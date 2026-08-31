package personserver

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	aauth "aauth-go"
)

// ErrMissionNotFound reports that an owner-scoped MissionStore lookup cannot
// see a mission. It covers both an absent identifier and a different owner.
var ErrMissionNotFound = errors.New("personserver: mission not found")

// ErrMissionConflict reports that a mission changed after policy read it and
// before the resulting token could be retained.
var ErrMissionConflict = errors.New("personserver: mission conflicts with retained state")

// MissionState is the durable state of an approved mission.
type MissionState string

const (
	MissionActive     MissionState = "active"
	MissionTerminated MissionState = "terminated"
)

// MissionRecord is the Person Server's retained approved mission. ExactJSON
// is the byte sequence named by S256 and returned to the Agent.
type MissionRecord struct {
	S256              string
	Agent             string
	ExactJSON         []byte
	ApprovedAt        time.Time
	ExpiresAt         time.Time
	State             MissionState
	TerminationReason string
}

// Equal reports whether two records describe the same retained mission and
// lifecycle state.
func (record MissionRecord) Equal(other MissionRecord) bool {
	return record.S256 == other.S256 && record.Agent == other.Agent &&
		bytes.Equal(record.ExactJSON, other.ExactJSON) &&
		record.ApprovedAt.Equal(other.ApprovedAt) && record.ExpiresAt.Equal(other.ExpiresAt) &&
		record.State == other.State && record.TerminationReason == other.TerminationReason
}

// MissionContext is the verified, active mission content passed to Person
// Server policy. ExactJSON is an independent copy of the blob named by S256.
type MissionContext struct {
	S256      string
	ExactJSON []byte
	Blob      aauth.MissionBlob
}

// MissionStore owns mission lifecycle and mission-bound token retention.
// CommitMission retains an approval and all Person tokens returned with it in
// one atomic operation, rejecting duplicate token identities within the
// batch. LoadMissionForAgent uses an owner-scoped lookup, returns
// ErrMissionNotFound for both an absent mission and a different owner, and
// atomically turns an expired active mission into terminated/expired.
//
// The two issuance commits compare every field of expected with the current
// mission, materialize expiry at the supplied commit time, require it to
// remain active, and retain the token record in the same atomic operation.
// Each token record must name expected.S256. They return
// *MissionTerminatedError for a terminal mission and ErrMissionConflict for
// any other changed state. Implementations copy mutable values and never
// return a terminated mission to active.
type MissionStore interface {
	TokenStore
	CommitMission(context.Context, MissionRecord, []PersonTokenRecord) error
	LoadMissionForAgent(context.Context, string, string, time.Time) (MissionRecord, error)
	CommitMissionPersonToken(context.Context, MissionRecord, time.Time, PersonTokenRecord) error
	CommitMissionAuthToken(context.Context, MissionRecord, time.Time, IssuedAuthTokenRecord) error
}

// MissionConfig enables the Agent-facing mission endpoint. Approve applies
// the deployment's person-facing approval policy to a verified proposal.
type MissionConfig struct {
	Approve func(context.Context, MissionApprovalRequest) (MissionDecision, error)
}

// MissionApprovalRequest is the verified Agent context presented to mission
// approval policy.
type MissionApprovalRequest struct {
	Agent                 string
	Proposal              aauth.MissionProposal
	AgentAdditionalClaims map[string]json.RawMessage
}

// MissionDecision is the exact approved content and momentary capabilities
// selected by mission approval policy.
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
	_, agent, _, err := server.verifyAgentProof(request, []string{"content-type", "content-digest"})
	if err != nil {
		writeAgentTokenProblem(response, err)
		return
	}
	if err := server.validateDirectAgentTopology(agent); err != nil {
		writeAgentTokenProblem(response, err)
		return
	}
	var proposal aauth.MissionProposal
	if err := decodeJSON(request.Body, &proposal); err != nil {
		writeProblem(response, http.StatusBadRequest, "invalid_request", err)
		return
	}
	if err := proposal.Validate(); err != nil {
		writeProblem(response, http.StatusBadRequest, "invalid_request", err)
		return
	}
	policyRequest := MissionApprovalRequest{
		Agent: agent.Subject, Proposal: cloneMissionProposal(proposal),
		AgentAdditionalClaims: cloneClaims(agent.AdditionalClaims),
	}
	decision, err := server.missionApprove(request.Context(), policyRequest)
	if err != nil {
		writeProblem(response, http.StatusForbidden, "mission_denied", err)
		return
	}
	approvedAt := server.clock.Now().UTC()
	if err := validateMissionDecision(decision, proposal, approvedAt); err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", err)
		return
	}
	blob := aauth.MissionBlob{
		Approver: server.issuer, Agent: agent.Subject, ApprovedAt: approvedAt,
		ExpiresAt: decision.ExpiresAt, Description: decision.Description,
		ApprovedTools:     append([]aauth.MissionTool(nil), decision.ApprovedTools...),
		ApprovedResources: append([]string(nil), decision.ApprovedResources...),
	}
	mission, err := aauth.EncodeMission(blob)
	if err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", err)
		return
	}
	record := MissionRecord{
		S256: mission.S256, Agent: agent.Subject, ExactJSON: append([]byte(nil), mission.ExactJSON...),
		ApprovedAt: approvedAt, State: MissionActive,
	}
	if decision.ExpiresAt != nil {
		record.ExpiresAt = decision.ExpiresAt.UTC()
	}

	personTokens := make(map[string]string, len(decision.ApprovedResources))
	personRecords := make([]PersonTokenRecord, 0, len(decision.ApprovedResources))
	personIdentities := make(map[string]struct{}, len(decision.ApprovedResources))
	for _, resource := range decision.ApprovedResources {
		personRequest := PersonTokenRequest{
			Agent: agent.Subject, Resource: resource, Mission: missionPolicyContext(mission),
			AgentAdditionalClaims: cloneClaims(agent.AdditionalClaims),
		}
		person, err := server.bindPerson(request.Context(), clonePersonTokenRequest(personRequest))
		if err != nil {
			writeProblem(response, http.StatusForbidden, "person_token_denied", err)
			return
		}
		issuedAt := server.clock.Now().UTC()
		if !record.ExpiresAt.IsZero() && !issuedAt.Before(record.ExpiresAt) {
			writeProblem(response, http.StatusInternalServerError, "server_error", errors.New("personserver: mission expired before approval could be retained"))
			return
		}
		compact, tokenRecord, err := server.preparePersonToken(
			issuedAt, agent, agent, personRequest, person, &record, nil,
		)
		if err != nil {
			writeProblem(response, http.StatusInternalServerError, "server_error", err)
			return
		}
		identity := tokenRecord.PersonServer + "\x00" + tokenRecord.JTI
		if _, duplicate := personIdentities[identity]; duplicate {
			writeProblem(response, http.StatusInternalServerError, "server_error", errors.New("personserver: mission approval produced duplicate person-token identities"))
			return
		}
		personIdentities[identity] = struct{}{}
		personTokens[resource] = compact
		personRecords = append(personRecords, tokenRecord)
	}
	if !record.ExpiresAt.IsZero() && !server.clock.Now().UTC().Before(record.ExpiresAt) {
		writeProblem(response, http.StatusInternalServerError, "server_error", errors.New("personserver: mission expired before approval could be retained"))
		return
	}
	if err := server.missions.CommitMission(request.Context(), record, personRecords); err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", err)
		return
	}
	writePrivateJSON(response, http.StatusOK, aauth.MissionApproval{
		S256: mission.S256, Mission: mission.Encoded,
		Capabilities: append([]string(nil), decision.Capabilities...), PersonTokens: personTokens,
	})
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
		ExpiresAt: canonicalExpiry, RetainUntil: canonicalExpiry.Add(server.maximumResourceTokenLifetime),
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
	if record.State == MissionActive && record.TerminationReason != "" {
		return aauth.ApprovedMission{}, errors.New("personserver: active mission has a termination reason")
	}
	if record.State == MissionTerminated && record.TerminationReason == "" {
		return aauth.ApprovedMission{}, errors.New("personserver: terminated mission requires a termination reason")
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
	return missionPolicyContext(mission), nil
}

func cloneMissionContext(mission *MissionContext) *MissionContext {
	if mission == nil {
		return nil
	}
	return &MissionContext{
		S256: mission.S256, ExactJSON: append([]byte(nil), mission.ExactJSON...), Blob: cloneMissionBlob(mission.Blob),
	}
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
		writeMissionTerminatedProblem(response, terminated.TerminationReason)
		return
	}
	if errors.Is(err, ErrMissionNotFound) {
		writeProblem(response, http.StatusBadRequest, "invalid_request", ErrMissionNotFound)
		return
	}
	writeProblem(response, http.StatusInternalServerError, "server_error", err)
}

func writeMissionTerminatedProblem(response http.ResponseWriter, reason string) {
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("Content-Type", "application/problem+json")
	response.WriteHeader(http.StatusForbidden)
	_ = json.NewEncoder(response).Encode(struct {
		Status            int    `json:"status"`
		Code              string `json:"error"`
		Detail            string `json:"detail"`
		MissionStatus     string `json:"mission_status"`
		TerminationReason string `json:"termination_reason,omitempty"`
	}{
		Status: http.StatusForbidden, Code: "mission_terminated", Detail: http.StatusText(http.StatusForbidden),
		MissionStatus: "terminated", TerminationReason: reason,
	})
}
