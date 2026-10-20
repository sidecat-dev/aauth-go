package personserver

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/internal/httpapi"
	"gitlab.com/sidecat-dev/aauth-go/internal/interaction"
	"gitlab.com/sidecat-dev/aauth-go/r3"
)

// ErrMissionNotFound reports that an owner-scoped MissionStore lookup cannot
// see a mission. It covers both an absent identifier and a different owner.
var ErrMissionNotFound = errors.New("personserver: mission not found")

// ErrMissionConflict reports that a mission creation conflicts with retained
// state, or that a mission changed after policy read it and before the
// resulting transition could be retained.
var ErrMissionConflict = errors.New("personserver: mission conflicts with retained state")

// ErrMissionDenied distinguishes a host policy or person refusal from an
// operational callback failure. Mission callbacks wrap this error when a
// syntactically valid mission action is intentionally refused; other errors
// produce a server failure instead of being mislabeled as a refusal.
var ErrMissionDenied = errors.New("personserver: mission denied")

// MissionState is the durable state of an approved mission.
type MissionState string

const (
	MissionActive     MissionState = "active"
	MissionTerminated MissionState = "terminated"
)

// MissionRecord is the Person Server's retained approved mission. ExactJSON
// is the byte sequence named by S256 and returned to the Agent. Capabilities
// are the approval-time request fallback; they are retained state but are not
// part of the signed mission blob.
type MissionRecord struct {
	S256              string
	Agent             string
	ExactJSON         []byte
	ApprovedAt        time.Time
	ExpiresAt         time.Time
	Capabilities      []string
	State             MissionState
	TerminationReason string
	AcceptedUpdates   []MissionUpdateRecord
	Completion        *MissionCompletionRecord
}

// MissionUpdateRecord is one exact update accepted under the Person Server's
// update policy. Slice order is acceptance order.
type MissionUpdateRecord struct {
	Document   aauth.MissionUpdateDocument
	AcceptedAt time.Time
}

// MissionCompletionRecord is the exact completion statement accepted by the
// person responsible for a mission.
type MissionCompletionRecord struct {
	Document   aauth.MissionCompletionDocument
	AcceptedAt time.Time
}

// Equal reports whether two records describe the same retained mission and
// lifecycle state.
func (record MissionRecord) Equal(other MissionRecord) bool {
	if record.S256 != other.S256 || record.Agent != other.Agent ||
		!bytes.Equal(record.ExactJSON, other.ExactJSON) ||
		!record.ApprovedAt.Equal(other.ApprovedAt) || !record.ExpiresAt.Equal(other.ExpiresAt) ||
		!slices.Equal(record.Capabilities, other.Capabilities) ||
		record.State != other.State || record.TerminationReason != other.TerminationReason ||
		len(record.AcceptedUpdates) != len(other.AcceptedUpdates) ||
		(record.Completion == nil) != (other.Completion == nil) {
		return false
	}
	for index := range record.AcceptedUpdates {
		if !equalMissionUpdateRecord(record.AcceptedUpdates[index], other.AcceptedUpdates[index]) {
			return false
		}
	}
	return record.Completion == nil || equalMissionCompletionRecord(*record.Completion, *other.Completion)
}

// MissionContext is the verified, active mission content passed to Person
// Server policy. ExactJSON is an independent copy of the blob named by S256.
type MissionContext struct {
	S256            string
	ExactJSON       []byte
	Blob            aauth.MissionBlob
	AcceptedUpdates []MissionUpdateRecord
}

// MissionStore owns mission lifecycle and mission-bound token retention.
// CommitMission retains an approval and all Person tokens returned with it in
// one atomic operation. It returns ErrMissionConflict if the mission already
// exists, if any token identity already exists, or if a token identity is
// duplicated within the batch. LoadMissionForAgent uses a combined
// owner-and-mission lookup (or an
// observably equivalent design), returns ErrMissionNotFound with equivalent
// timing for both an absent mission and a different owner, and atomically
// turns an expired active mission into terminated/expired. It must not look up
// by digest and check ownership afterward.
//
// The two issuance commits compare every field of expected with the current
// mission, materialize expiry at the supplied commit time, require it to
// remain active, and retain the token record in the same atomic operation.
// Each token record must name expected.S256. They return
// *MissionTerminatedError for a terminal mission and ErrMissionConflict for
// any other changed state. AppendMissionUpdate and CompleteMission apply the
// same complete-record comparison: the former appends one exact accepted
// update in order; the latter retains one exact person-accepted completion and
// atomically terminates the mission with reason completed. Both require a
// nonzero acceptedAt and return an independent copy of the exact post-state.
// Implementations copy mutable values and never return a terminated mission to
// active.
type MissionStore interface {
	TokenStore
	CommitMission(ctx context.Context, mission MissionRecord, tokens []PersonTokenRecord) error
	LoadMissionForAgent(ctx context.Context, agent, s256 string, at time.Time) (MissionRecord, error)
	AppendMissionUpdate(ctx context.Context, expected MissionRecord, acceptedAt time.Time, document aauth.MissionUpdateDocument) (MissionRecord, error)
	CompleteMission(ctx context.Context, expected MissionRecord, acceptedAt time.Time, document aauth.MissionCompletionDocument) (MissionRecord, error)
	CommitMissionPersonToken(ctx context.Context, expected MissionRecord, decidedAt time.Time, token PersonTokenRecord) error
	CommitMissionAuthToken(ctx context.Context, expected MissionRecord, decidedAt time.Time, token IssuedAuthTokenRecord) error
}

// MissionR3IssuanceStore atomically compares one active mission and retains
// both the mission-bound Auth-token record and the mandatory R3 issuance audit
// facts before the token becomes observable. The token must name the expected
// mission. The issuance Auth-token reference, Resource, and issuance instant
// must equal the token record; its Person Server must equal the token issuer;
// and its Agent must equal the mission owner. A mismatch returns
// ErrMissionConflict without retaining either record.
type MissionR3IssuanceStore interface {
	MissionStore
	CommitMissionR3AuthToken(
		ctx context.Context,
		expected MissionRecord,
		decidedAt time.Time,
		token IssuedAuthTokenRecord,
		issuance r3.IssuanceRecord,
	) error
}

// MissionConfig enables the Agent-facing mission endpoint. Approve applies
// the deployment's person-facing approval policy to a verified proposal.
// AcceptUpdate applies the deployment's rule for immediate update acceptance;
// Core permits the Person Server to accept an update on its own. In contrast,
// ConfirmPersonAcceptedCompletion must return nil only after the host has
// obtained the responsible person's actual acceptance of the completion
// statement; it is not an autonomous reasonableness policy. An omitted action
// callback disables that action with a typed denial. Each configured callback
// wraps ErrMissionDenied for an intentional refusal and returns other errors
// only for operational failure.
type MissionConfig struct {
	Approve func(context.Context, MissionApprovalRequest) (MissionDecision, error)
	// DeferProposal optionally selects separately authenticated host review.
	// A true result retains the exact proposal and returns 202; false preserves
	// the immediate Approve path.
	DeferProposal                   func(context.Context, MissionApprovalRequest) (MissionProposalPendingPolicy, bool, error)
	AcceptUpdate                    func(context.Context, MissionUpdatePolicyRequest) error
	ConfirmPersonAcceptedCompletion func(context.Context, MissionCompletionPolicyRequest) error
}

// MissionApprovalRequest is the verified Agent context presented to mission
// approval policy.
type MissionApprovalRequest struct {
	Agent                 string
	Proposal              aauth.MissionProposal
	ExactJSON             []byte
	AgentAdditionalClaims map[string]json.RawMessage
}

// MissionUpdatePolicyRequest is the verified Agent request and the complete
// accepted mission state presented to the host's update policy.
type MissionUpdatePolicyRequest struct {
	Agent                 string
	Mission               MissionContext
	Document              aauth.MissionUpdateDocument
	AgentAdditionalClaims map[string]json.RawMessage
}

// MissionCompletionPolicyRequest is the verified Agent request presented to
// the host callback that obtains actual acceptance from the responsible
// person.
type MissionCompletionPolicyRequest struct {
	Agent                 string
	Mission               MissionContext
	Document              aauth.MissionCompletionDocument
	AgentAdditionalClaims map[string]json.RawMessage
}

// MissionDecision is the exact approved content and request capabilities
// selected by mission approval policy. Capabilities are retained for the
// Core-defined fallback when a later mission-bound request omits them.
type MissionDecision struct {
	Description       string
	ApprovedTools     []aauth.MissionTool
	ApprovedResources []string
	ExpiresAt         *time.Time
	Capabilities      []string
}

// MissionTerminatedError reports the permanent terminal state materialized by
// a MissionStore.
type MissionTerminatedError struct {
	TerminationReason string
}

func (failure *MissionTerminatedError) Error() string {
	if failure.TerminationReason == "" {
		return "personserver: mission is terminated"
	}
	return "personserver: mission is terminated: " + failure.TerminationReason
}

func (server *Server) handleMission(response http.ResponseWriter, request *http.Request) {
	_, agent, proof, err := server.verifyAgentProof(request, []string{"content-type", "content-digest"})
	if err != nil {
		writeAgentTokenProblem(response, err)
		return
	}
	if err := server.validateDirectAgentTopology(agent); err != nil {
		writeAgentTokenProblem(response, err)
		return
	}
	var proposal aauth.MissionProposal
	exactJSON, err := httpapi.DecodeExactJSON(request.Body, maxRequestBytes, &proposal)
	if err != nil {
		writeProblem(response, http.StatusBadRequest, "invalid_request", err)
		return
	}
	if err := proposal.Validate(); err != nil {
		writeProblem(response, http.StatusBadRequest, "invalid_request", err)
		return
	}
	policyRequest := MissionApprovalRequest{
		Agent: agent.Subject, Proposal: cloneMissionProposal(proposal),
		ExactJSON:             append([]byte(nil), exactJSON...),
		AgentAdditionalClaims: cloneClaims(agent.AdditionalClaims),
	}
	if server.missionDeferProposal != nil {
		pending, deferProposal, err := server.missionDeferProposal(request.Context(), cloneMissionApprovalRequest(policyRequest))
		if err != nil {
			writeProblem(response, http.StatusInternalServerError, "server_error", err)
			return
		}
		if deferProposal {
			if err := validateMissionProposalPendingPolicy(pending); err != nil {
				writeProblem(response, http.StatusInternalServerError, "server_error", err)
				return
			}
			createdAt := proof.VerifiedAt().UTC()
			agentExpiresAt := time.Unix(agent.ExpiresAt, 0).UTC()
			for attempt := 0; attempt < 3; attempt++ {
				reference, err := interaction.GeneratePendingReference(nil)
				if err != nil {
					writeProblem(response, http.StatusInternalServerError, "server_error", err)
					return
				}
				record := MissionProposalRecord{
					ID: reference, PersonServer: server.issuer, AgentProvider: agent.Issuer, Agent: agent.Subject,
					Confirmation: agent.Confirmation.JWK, AgentExpiresAt: agentExpiresAt,
					AgentAdditionalClaims: cloneClaims(agent.AdditionalClaims),
					ExactJSON:             append([]byte(nil), exactJSON...),
					CreatedAt:             createdAt, ExpiresAt: createdAt.Add(pending.Lifetime), RetryAfter: pending.RetryAfter,
				}
				if agentExpiresAt.Before(record.ExpiresAt) {
					record.ExpiresAt = agentExpiresAt
				}
				if !record.ExpiresAt.After(createdAt) {
					writeProblem(response, http.StatusRequestTimeout, "expired", ErrMissionProposalExpired)
					return
				}
				if err := validateMissionProposalRecord(record); err != nil {
					writeProblem(response, http.StatusInternalServerError, "server_error", err)
					return
				}
				if err := server.missionProposals.CreateMissionProposal(request.Context(), cloneMissionProposalRecord(record)); err != nil {
					if errors.Is(err, ErrMissionProposalConflict) {
						continue
					}
					writeProblem(response, http.StatusInternalServerError, "server_error", err)
					return
				}
				writePendingMissionProposal(response, "/mission/pending/"+reference, record.RetryAfter)
				return
			}
			writeProblem(response, http.StatusInternalServerError, "server_error", errors.New("personserver: could not allocate a unique mission proposal reference"))
			return
		}
	}
	if server.missionApprove == nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", errors.New("personserver: mission proposal was not deferred and no immediate approval policy is configured"))
		return
	}
	decision, err := server.missionApprove(request.Context(), policyRequest)
	if err != nil {
		writeMissionPolicyProblem(response, "mission_denied", err)
		return
	}
	approvedAt := server.clock.Now().UTC()
	if err := validateMissionDecision(decision, proposal, approvedAt); err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", err)
		return
	}
	approval, err := server.prepareMissionApproval(request.Context(), agent, decision, approvedAt)
	if err != nil {
		var binding *missionPersonBindingError
		if errors.As(err, &binding) {
			writeProblem(response, http.StatusForbidden, "person_token_denied", err)
		} else {
			writeProblem(response, http.StatusInternalServerError, "server_error", err)
		}
		return
	}
	if err := server.missions.CommitMission(request.Context(), approval.Mission, approval.PersonTokenRecords); err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", err)
		return
	}
	writePrivateJSON(response, http.StatusOK, missionApprovalResponse(approval))
}

func validateMissionProposalPendingPolicy(policy MissionProposalPendingPolicy) error {
	if policy.Lifetime <= 0 {
		return errors.New("personserver: deferred mission proposal lifetime must be positive")
	}
	if policy.RetryAfter < 0 || policy.RetryAfter%time.Second != 0 {
		return errors.New("personserver: deferred mission proposal retry interval must be whole nonnegative seconds")
	}
	return nil
}

func validateMissionProposalRecord(record MissionProposalRecord) error {
	if record.ID == "" || record.PersonServer == "" || record.AgentProvider == "" || record.Agent == "" ||
		record.AgentExpiresAt.IsZero() || record.CreatedAt.IsZero() || record.ExpiresAt.IsZero() ||
		!record.ExpiresAt.After(record.CreatedAt) || record.ExpiresAt.After(record.AgentExpiresAt) ||
		record.RetryAfter < 0 || record.RetryAfter%time.Second != 0 || len(record.ExactJSON) == 0 {
		return ErrMissionProposalConflict
	}
	if _, err := record.Confirmation.PublicKey(); err != nil {
		return ErrMissionProposalConflict
	}
	if _, err := missionProposalFromRecord(record); err != nil {
		return ErrMissionProposalConflict
	}
	return nil
}

func missionProposalFromRecord(record MissionProposalRecord) (aauth.MissionProposal, error) {
	var proposal aauth.MissionProposal
	exact, err := httpapi.DecodeExactJSON(bytes.NewReader(record.ExactJSON), maxRequestBytes, &proposal)
	if err != nil || !bytes.Equal(exact, record.ExactJSON) {
		return aauth.MissionProposal{}, ErrMissionProposalConflict
	}
	if err := proposal.Validate(); err != nil {
		return aauth.MissionProposal{}, ErrMissionProposalConflict
	}
	return cloneMissionProposal(proposal), nil
}

func cloneMissionApprovalRequest(request MissionApprovalRequest) MissionApprovalRequest {
	request.Proposal = cloneMissionProposal(request.Proposal)
	request.ExactJSON = append([]byte(nil), request.ExactJSON...)
	request.AgentAdditionalClaims = cloneClaims(request.AgentAdditionalClaims)
	return request
}

func writePendingMissionProposal(response http.ResponseWriter, location string, retryAfter time.Duration) {
	response.Header().Set("AAuth-Requirement", "requirement=approval")
	response.Header().Set("Location", location)
	response.Header().Set("Retry-After", strconv.FormatInt(int64(retryAfter/time.Second), 10))
	writePrivateJSON(response, http.StatusAccepted, map[string]string{"status": "pending"})
}

type missionPersonBindingError struct {
	cause error
}

func (failure *missionPersonBindingError) Error() string {
	return "personserver: mission person binding: " + failure.cause.Error()
}

func (failure *missionPersonBindingError) Unwrap() error { return failure.cause }

func (server *Server) prepareMissionApproval(
	ctx context.Context,
	agent aauth.AgentTokenClaims,
	decision MissionDecision,
	approvedAt time.Time,
) (MissionProposalApproval, error) {
	blob := aauth.MissionBlob{
		Approver: server.issuer, Agent: agent.Subject, ApprovedAt: approvedAt,
		ExpiresAt: decision.ExpiresAt, Description: decision.Description,
		ApprovedTools:     append([]aauth.MissionTool(nil), decision.ApprovedTools...),
		ApprovedResources: append([]string(nil), decision.ApprovedResources...),
	}
	mission, err := aauth.EncodeMission(blob)
	if err != nil {
		return MissionProposalApproval{}, err
	}
	record := MissionRecord{
		S256: mission.S256, Agent: agent.Subject, ExactJSON: append([]byte(nil), mission.ExactJSON...),
		ApprovedAt: approvedAt, Capabilities: append([]string(nil), decision.Capabilities...), State: MissionActive,
	}
	if decision.ExpiresAt != nil {
		record.ExpiresAt = decision.ExpiresAt.UTC()
	}
	personTokens := make(map[string]string, len(decision.ApprovedResources))
	personRecords := make([]PersonTokenRecord, 0, len(decision.ApprovedResources))
	identities := make(map[string]struct{}, len(decision.ApprovedResources))
	for _, resource := range decision.ApprovedResources {
		personRequest := PersonTokenRequest{
			Agent: agent.Subject, Resource: resource, Mission: missionPolicyContext(mission),
			AgentAdditionalClaims: cloneClaims(agent.AdditionalClaims),
		}
		person, err := server.bindPerson(ctx, clonePersonTokenRequest(personRequest))
		if err != nil {
			return MissionProposalApproval{}, &missionPersonBindingError{cause: fmt.Errorf("Resource %q: %w", resource, err)}
		}
		issuedAt := server.clock.Now().UTC()
		if !record.ExpiresAt.IsZero() && !issuedAt.Before(record.ExpiresAt) {
			return MissionProposalApproval{}, errors.New("personserver: mission expired before approval could be retained")
		}
		compact, tokenRecord, err := server.preparePersonToken(
			issuedAt, agent, agent, personRequest, person, &record, nil,
		)
		if err != nil {
			return MissionProposalApproval{}, err
		}
		identity := tokenRecord.PersonServer + "\x00" + tokenRecord.JTI
		if _, duplicate := identities[identity]; duplicate {
			return MissionProposalApproval{}, errors.New("personserver: mission approval produced duplicate person-token identities")
		}
		identities[identity] = struct{}{}
		personTokens[resource] = compact
		personRecords = append(personRecords, tokenRecord)
	}
	if !record.ExpiresAt.IsZero() && !server.clock.Now().UTC().Before(record.ExpiresAt) {
		return MissionProposalApproval{}, errors.New("personserver: mission expired before approval could be retained")
	}
	return MissionProposalApproval{
		Mission:      cloneMissionRecordForTransition(record),
		PersonTokens: personTokens, PersonTokenRecords: personRecords,
	}, nil
}

func (server *Server) handleMissionAction(response http.ResponseWriter, request *http.Request) {
	_, agent, _, err := server.verifyAgentProof(request, []string{"content-type", "content-digest"})
	if err != nil {
		writeAgentTokenProblem(response, err)
		return
	}
	if err := server.validateDirectAgentTopology(agent); err != nil {
		writeAgentTokenProblem(response, err)
		return
	}
	s256 := request.PathValue("s256")
	if err := aauth.ValidateMissionS256(s256); err != nil {
		writeProblem(response, http.StatusBadRequest, "invalid_request", errors.New("personserver: mission identifier is invalid"))
		return
	}
	var action struct {
		Action string `json:"action"`
	}
	exactJSON, err := httpapi.DecodeExactJSON(request.Body, maxRequestBytes, &action)
	if err != nil {
		writeProblem(response, http.StatusBadRequest, "invalid_request", err)
		return
	}
	var updateDocument aauth.MissionUpdateDocument
	var completionDocument aauth.MissionCompletionDocument
	switch action.Action {
	case "update":
		updateDocument, err = aauth.DecodeMissionUpdate(aauth.MissionS256(exactJSON), exactJSON)
	case "completion":
		completionDocument, err = aauth.DecodeMissionCompletion(exactJSON)
	default:
		writeProblem(response, http.StatusBadRequest, "invalid_request", errors.New("personserver: mission action must be update or completion"))
		return
	}
	if err != nil {
		writeProblem(response, http.StatusBadRequest, "invalid_request", err)
		return
	}
	expected, err := server.loadActiveMission(request.Context(), s256, agent.Subject, server.clock.Now().UTC())
	if err != nil {
		writeMissionActionProblem(response, err)
		return
	}
	expected = cloneMissionRecordForTransition(expected)
	mission, err := missionContextFromRecord(expected)
	if err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", err)
		return
	}

	switch action.Action {
	case "update":
		if server.missionAcceptUpdate == nil {
			writeMissionPolicyProblem(response, "mission_update_denied", fmt.Errorf("%w: mission updates are not enabled", ErrMissionDenied))
			return
		}
		policyRequest := MissionUpdatePolicyRequest{
			Agent: agent.Subject, Mission: *cloneMissionContext(mission),
			Document:              cloneMissionUpdateDocument(updateDocument),
			AgentAdditionalClaims: cloneClaims(agent.AdditionalClaims),
		}
		if err := server.missionAcceptUpdate(request.Context(), policyRequest); err != nil {
			writeMissionPolicyProblem(response, "mission_update_denied", err)
			return
		}
		acceptedAt := server.clock.Now().UTC()
		if err := validateMissionAcceptanceInstant(acceptedAt); err != nil {
			writeProblem(response, http.StatusInternalServerError, "server_error", err)
			return
		}
		retained, err := server.missions.AppendMissionUpdate(
			request.Context(), cloneMissionRecordForTransition(expected), acceptedAt,
			cloneMissionUpdateDocument(updateDocument),
		)
		if err != nil {
			writeMissionActionProblem(response, err)
			return
		}
		want := cloneMissionRecordForTransition(expected)
		want.AcceptedUpdates = append(cloneMissionUpdateRecords(expected.AcceptedUpdates), MissionUpdateRecord{
			Document: cloneMissionUpdateDocument(updateDocument), AcceptedAt: acceptedAt,
		})
		if _, err := validateMissionRecord(retained); err != nil || !retained.Equal(want) {
			writeProblem(response, http.StatusInternalServerError, "server_error", errors.New("personserver: mission store returned an invalid update transition"))
			return
		}
		writePrivateJSON(response, http.StatusOK, aauth.MissionUpdateResponse{S256: updateDocument.S256})
	case "completion":
		if server.missionConfirmPersonCompletion == nil {
			writeMissionPolicyProblem(response, "mission_completion_denied", fmt.Errorf("%w: mission completion is not enabled", ErrMissionDenied))
			return
		}
		policyRequest := MissionCompletionPolicyRequest{
			Agent: agent.Subject, Mission: *cloneMissionContext(mission),
			Document:              cloneMissionCompletionDocument(completionDocument),
			AgentAdditionalClaims: cloneClaims(agent.AdditionalClaims),
		}
		if err := server.missionConfirmPersonCompletion(request.Context(), policyRequest); err != nil {
			writeMissionPolicyProblem(response, "mission_completion_denied", err)
			return
		}
		acceptedAt := server.clock.Now().UTC()
		if err := validateMissionAcceptanceInstant(acceptedAt); err != nil {
			writeProblem(response, http.StatusInternalServerError, "server_error", err)
			return
		}
		retained, err := server.missions.CompleteMission(
			request.Context(), cloneMissionRecordForTransition(expected), acceptedAt,
			cloneMissionCompletionDocument(completionDocument),
		)
		if err != nil {
			writeMissionActionProblem(response, err)
			return
		}
		want := cloneMissionRecordForTransition(expected)
		want.State = MissionTerminated
		want.TerminationReason = "completed"
		want.Completion = &MissionCompletionRecord{
			Document: cloneMissionCompletionDocument(completionDocument), AcceptedAt: acceptedAt,
		}
		if _, err := validateMissionRecord(retained); err != nil || !retained.Equal(want) {
			writeProblem(response, http.StatusInternalServerError, "server_error", errors.New("personserver: mission store returned an invalid completion transition"))
			return
		}
		response.Header().Set("Cache-Control", "no-store")
		response.WriteHeader(http.StatusOK)
	}
}

func (server *Server) loadActiveMission(
	ctx context.Context,
	s256 string,
	agent string,
	now time.Time,
) (MissionRecord, error) {
	if server.missions == nil {
		return MissionRecord{}, ErrMissionNotFound
	}
	record, err := server.missions.LoadMissionForAgent(ctx, agent, s256, now)
	if err != nil {
		return MissionRecord{}, err
	}
	if record.Agent != agent || record.S256 != s256 {
		return MissionRecord{}, ErrMissionNotFound
	}
	mission, err := validateMissionRecord(record)
	if err != nil {
		return MissionRecord{}, err
	}
	if mission.Blob.Approver != server.issuer {
		return MissionRecord{}, errors.New("personserver: retained mission approver is not this Person Server")
	}
	if record.State == MissionTerminated {
		return MissionRecord{}, &MissionTerminatedError{TerminationReason: record.TerminationReason}
	}
	if !record.ExpiresAt.IsZero() && !now.Before(record.ExpiresAt) {
		return MissionRecord{}, errors.New("personserver: mission store returned an unmaterialized expiry")
	}
	return record, nil
}

func (server *Server) recheckActiveMission(
	ctx context.Context,
	expected MissionRecord,
	now time.Time,
) (MissionRecord, error) {
	current, err := server.loadActiveMission(ctx, expected.S256, expected.Agent, now)
	if err != nil {
		return MissionRecord{}, err
	}
	if !current.Equal(expected) {
		return MissionRecord{}, ErrMissionConflict
	}
	return current, nil
}

func (server *Server) preparePersonToken(
	issuedAt time.Time,
	requestingAgent aauth.AgentTokenClaims,
	credentialAgent aauth.AgentTokenClaims,
	request PersonTokenRequest,
	person Person,
	mission *MissionRecord,
	upstream *verifiedUpstreamToken,
) (string, PersonTokenRecord, error) {
	if person.Subject == "" || person.Lifetime <= 0 || person.Lifetime > maximumPersonLifetime {
		return "", PersonTokenRecord{}, errors.New("personserver: person binding returned an invalid person")
	}
	missionS256 := ""
	if request.Mission != nil {
		missionS256 = request.Mission.S256
		if mission == nil || mission.S256 != missionS256 {
			return "", PersonTokenRecord{}, errors.New("personserver: mission context does not match retained mission")
		}
	} else if mission != nil {
		return "", PersonTokenRecord{}, errors.New("personserver: retained mission has no policy context")
	}
	expiresAt := issuedAt.Add(person.Lifetime)
	if agentExpiry := time.Unix(requestingAgent.ExpiresAt, 0); agentExpiry.Before(expiresAt) {
		expiresAt = agentExpiry
	}
	if credentialExpiry := time.Unix(credentialAgent.ExpiresAt, 0); credentialExpiry.Before(expiresAt) {
		expiresAt = credentialExpiry
	}
	if mission != nil && !mission.ExpiresAt.IsZero() && mission.ExpiresAt.Before(expiresAt) {
		expiresAt = mission.ExpiresAt
	}
	// A person token issued with upstream_token expires no later than it.
	if upstream != nil {
		if upstreamExpiry := time.Unix(upstream.claims.ExpiresAt, 0); upstreamExpiry.Before(expiresAt) {
			expiresAt = upstreamExpiry
		}
	}
	if !expiresAt.After(issuedAt) {
		return "", PersonTokenRecord{}, errors.New("personserver: person binding has no usable lifetime")
	}
	claims := aauth.PersonTokenClaims{
		Issuer: server.issuer, DWK: aauth.PersonDiscoveryDocument,
		Audience: request.Resource, Subject: person.Subject,
		Confirmation: aauth.Confirmation{JWK: credentialAgent.Confirmation.JWK},
		JTI:          server.newID(), IssuedAt: issuedAt.Unix(), ExpiresAt: expiresAt.Unix(),
		MissionS256: missionS256, Tenant: person.Tenant,
	}
	compact, err := aauth.MintPersonToken(server.signingKey, claims)
	if err != nil {
		return "", PersonTokenRecord{}, err
	}
	canonicalExpiry := time.Unix(claims.ExpiresAt, 0).UTC()
	record := PersonTokenRecord{
		JTI: claims.JTI, PersonServer: claims.Issuer, Resource: claims.Audience,
		Subject: claims.Subject, MissionS256: claims.MissionS256, Tenant: claims.Tenant,
		AgentProvider: credentialAgent.Issuer, Agent: credentialAgent.Subject,
		ParentAgent: credentialAgent.ParentAgent, Confirmation: credentialAgent.Confirmation.JWK,
		ExpiresAt: canonicalExpiry,
		RetainUntil: canonicalExpiry.Add(
			server.maximumResourceTokenLifetime + aauth.MaximumAuthTokenLifetime,
		),
	}
	upstream.bindRecord(&record)
	return compact, record, nil
}

func validateMissionRecord(record MissionRecord) (aauth.ApprovedMission, error) {
	mission, err := aauth.DecodeMission(
		record.S256,
		base64.RawURLEncoding.EncodeToString(record.ExactJSON),
	)
	if err != nil {
		return aauth.ApprovedMission{}, fmt.Errorf("personserver: retained mission: %w", err)
	}
	if mission.Blob.Agent != record.Agent || !mission.Blob.ApprovedAt.Equal(record.ApprovedAt) {
		return aauth.ApprovedMission{}, errors.New("personserver: retained mission does not match its blob")
	}
	if mission.Blob.ExpiresAt == nil {
		if !record.ExpiresAt.IsZero() {
			return aauth.ApprovedMission{}, errors.New("personserver: retained mission expiry does not match its blob")
		}
	} else if !mission.Blob.ExpiresAt.Equal(record.ExpiresAt) {
		return aauth.ApprovedMission{}, errors.New("personserver: retained mission expiry does not match its blob")
	}
	if record.State != MissionActive && record.State != MissionTerminated {
		return aauth.ApprovedMission{}, errors.New("personserver: retained mission state is invalid")
	}
	if len(record.Capabilities) > 0 {
		if _, err := aauth.FormatCapabilities(record.Capabilities); err != nil {
			return aauth.ApprovedMission{}, fmt.Errorf("personserver: retained mission capabilities: %w", err)
		}
	}
	if record.State == MissionActive && record.TerminationReason != "" {
		return aauth.ApprovedMission{}, errors.New("personserver: active mission has a termination reason")
	}
	if record.State == MissionTerminated && record.TerminationReason == "" {
		return aauth.ApprovedMission{}, errors.New("personserver: terminated mission requires a termination reason")
	}
	for index, update := range record.AcceptedUpdates {
		decoded, err := aauth.DecodeMissionUpdate(update.Document.S256, update.Document.ExactJSON)
		if err != nil || !equalMissionUpdateDocument(update.Document, decoded) {
			return aauth.ApprovedMission{}, fmt.Errorf("personserver: retained mission update %d is invalid", index)
		}
		if update.AcceptedAt.IsZero() {
			return aauth.ApprovedMission{}, fmt.Errorf("personserver: retained mission update %d acceptance time is invalid", index)
		}
		if !record.ExpiresAt.IsZero() && !update.AcceptedAt.Before(record.ExpiresAt) {
			return aauth.ApprovedMission{}, fmt.Errorf("personserver: retained mission update %d was accepted after expiry", index)
		}
	}
	if record.Completion != nil {
		decoded, err := aauth.DecodeMissionCompletion(record.Completion.Document.ExactJSON)
		if err != nil || !equalMissionCompletionDocument(record.Completion.Document, decoded) {
			return aauth.ApprovedMission{}, errors.New("personserver: retained mission completion is invalid")
		}
		if record.Completion.AcceptedAt.IsZero() {
			return aauth.ApprovedMission{}, errors.New("personserver: retained mission completion acceptance time is invalid")
		}
		if !record.ExpiresAt.IsZero() && !record.Completion.AcceptedAt.Before(record.ExpiresAt) {
			return aauth.ApprovedMission{}, errors.New("personserver: retained mission completion was accepted after expiry")
		}
		if record.State != MissionTerminated || record.TerminationReason != "completed" {
			return aauth.ApprovedMission{}, errors.New("personserver: retained mission completion does not match lifecycle state")
		}
	} else if record.TerminationReason == "completed" {
		return aauth.ApprovedMission{}, errors.New("personserver: completed mission requires retained completion evidence")
	}
	return mission, nil
}

func validateMissionDecision(decision MissionDecision, proposal aauth.MissionProposal, approvedAt time.Time) error {
	if decision.Description == "" {
		return errors.New("personserver: mission decision description is required")
	}
	proposedResources := make(map[string]struct{}, len(proposal.Resources))
	for _, resource := range proposal.Resources {
		proposedResources[resource] = struct{}{}
	}
	seen := make(map[string]struct{}, len(decision.ApprovedResources))
	for _, resource := range decision.ApprovedResources {
		if _, proposed := proposedResources[resource]; !proposed {
			return fmt.Errorf("personserver: mission decision approved unproposed resource %q", resource)
		}
		if _, duplicate := seen[resource]; duplicate {
			return fmt.Errorf("personserver: mission decision repeats approved resource %q", resource)
		}
		seen[resource] = struct{}{}
	}
	if decision.ExpiresAt != nil && !decision.ExpiresAt.After(approvedAt) {
		return errors.New("personserver: mission decision expiry must follow approval")
	}
	if len(decision.Capabilities) > 0 {
		if _, err := aauth.FormatCapabilities(decision.Capabilities); err != nil {
			return fmt.Errorf("personserver: mission decision capabilities: %w", err)
		}
	}
	return nil
}

func cloneMissionProposal(proposal aauth.MissionProposal) aauth.MissionProposal {
	proposal.Tools = append([]aauth.MissionTool(nil), proposal.Tools...)
	proposal.Resources = append([]string(nil), proposal.Resources...)
	return proposal
}

func missionPolicyContext(mission aauth.ApprovedMission) *MissionContext {
	return &MissionContext{
		S256: mission.S256, ExactJSON: append([]byte(nil), mission.ExactJSON...), Blob: cloneMissionBlob(mission.Blob),
	}
}

func missionContextFromRecord(record MissionRecord) (*MissionContext, error) {
	mission, err := validateMissionRecord(record)
	if err != nil {
		return nil, err
	}
	context := missionPolicyContext(mission)
	context.AcceptedUpdates = cloneMissionUpdateRecords(record.AcceptedUpdates)
	return context, nil
}

func cloneMissionContext(mission *MissionContext) *MissionContext {
	if mission == nil {
		return nil
	}
	return &MissionContext{
		S256: mission.S256, ExactJSON: append([]byte(nil), mission.ExactJSON...), Blob: cloneMissionBlob(mission.Blob),
		AcceptedUpdates: cloneMissionUpdateRecords(mission.AcceptedUpdates),
	}
}

func cloneMissionUpdateDocument(document aauth.MissionUpdateDocument) aauth.MissionUpdateDocument {
	document.ExactJSON = append([]byte(nil), document.ExactJSON...)
	return document
}

func validateMissionAcceptanceInstant(acceptedAt time.Time) error {
	if acceptedAt.IsZero() {
		return errors.New("personserver: mission acceptance time is required")
	}
	return nil
}

func cloneMissionCompletionDocument(document aauth.MissionCompletionDocument) aauth.MissionCompletionDocument {
	document.ExactJSON = append([]byte(nil), document.ExactJSON...)
	return document
}

func cloneMissionUpdateRecords(records []MissionUpdateRecord) []MissionUpdateRecord {
	if records == nil {
		return nil
	}
	cloned := make([]MissionUpdateRecord, len(records))
	for index, record := range records {
		cloned[index] = MissionUpdateRecord{
			Document: cloneMissionUpdateDocument(record.Document), AcceptedAt: record.AcceptedAt,
		}
	}
	return cloned
}

func cloneMissionRecordForTransition(record MissionRecord) MissionRecord {
	record.ExactJSON = append([]byte(nil), record.ExactJSON...)
	record.Capabilities = append([]string(nil), record.Capabilities...)
	record.AcceptedUpdates = cloneMissionUpdateRecords(record.AcceptedUpdates)
	if record.Completion != nil {
		completion := *record.Completion
		completion.Document = cloneMissionCompletionDocument(completion.Document)
		record.Completion = &completion
	}
	return record
}

func equalMissionUpdateDocument(left, right aauth.MissionUpdateDocument) bool {
	return left.S256 == right.S256 && bytes.Equal(left.ExactJSON, right.ExactJSON) && left.Update == right.Update
}

func equalMissionCompletionDocument(left, right aauth.MissionCompletionDocument) bool {
	return bytes.Equal(left.ExactJSON, right.ExactJSON) && left.Completion == right.Completion
}

func equalMissionUpdateRecord(left, right MissionUpdateRecord) bool {
	return left.AcceptedAt.Equal(right.AcceptedAt) && equalMissionUpdateDocument(left.Document, right.Document)
}

func equalMissionCompletionRecord(left, right MissionCompletionRecord) bool {
	return left.AcceptedAt.Equal(right.AcceptedAt) && equalMissionCompletionDocument(left.Document, right.Document)
}

func cloneMissionBlob(blob aauth.MissionBlob) aauth.MissionBlob {
	blob.ApprovedTools = append([]aauth.MissionTool(nil), blob.ApprovedTools...)
	blob.ApprovedResources = append([]string(nil), blob.ApprovedResources...)
	if blob.ExpiresAt != nil {
		expiresAt := *blob.ExpiresAt
		blob.ExpiresAt = &expiresAt
	}
	return blob
}

func writeMissionReferenceProblem(response http.ResponseWriter, err error) {
	var terminated *MissionTerminatedError
	if errors.As(err, &terminated) {
		writeMissionTerminatedProblem(response, terminated.TerminationReason, err)
		return
	}
	if errors.Is(err, ErrMissionNotFound) {
		writeProblem(response, http.StatusBadRequest, "invalid_request", ErrMissionNotFound)
		return
	}
	writeProblem(response, http.StatusInternalServerError, "server_error", err)
}

func writeMissionPolicyProblem(response http.ResponseWriter, denialCode string, err error) {
	if errors.Is(err, ErrMissionDenied) {
		writeProblem(response, http.StatusForbidden, denialCode, err)
		return
	}
	writeProblem(response, http.StatusInternalServerError, "server_error", err)
}

func writeMissionActionProblem(response http.ResponseWriter, err error) {
	var terminated *MissionTerminatedError
	if errors.As(err, &terminated) {
		writeMissionTerminatedProblem(response, terminated.TerminationReason, err)
		return
	}
	if errors.Is(err, ErrMissionNotFound) {
		writeProblem(response, http.StatusNotFound, "mission_not_found", ErrMissionNotFound)
		return
	}
	writeProblem(response, http.StatusInternalServerError, "server_error", err)
}

func writeMissionTerminatedProblem(response http.ResponseWriter, reason string, cause error) {
	response.Header().Set("Cache-Control", "no-store")
	httpapi.WriteProblem(response, http.StatusForbidden, "mission_terminated", cause, httpapi.ProblemFields{
		MissionStatus: "terminated", TerminationReason: reason,
	})
}
