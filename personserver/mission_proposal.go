package personserver

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/jose"
)

var (
	// ErrMissionProposalNotFound cloaks an absent proposal and a proposal owned
	// by another Agent identity or proof key.
	ErrMissionProposalNotFound = errors.New("personserver: mission proposal not found")
	// ErrMissionProposalConflict reports a transition that differs from the
	// retained proposal or its canonical decision.
	ErrMissionProposalConflict = errors.New("personserver: mission proposal conflicts with retained state")
	// ErrMissionProposalExpired reports a proposal whose decision deadline has
	// passed.
	ErrMissionProposalExpired = errors.New("personserver: mission proposal expired")
	// ErrMissionProposalGone reports a proposal whose terminal Agent response
	// has already been consumed.
	ErrMissionProposalGone = errors.New("personserver: mission proposal is gone")
)

// MissionProposalPendingPolicy asks the Person Server to retain a verified
// proposal for a separately authenticated host decision.
type MissionProposalPendingPolicy struct {
	Lifetime   time.Duration
	RetryAfter time.Duration
}

// MissionProposalState is the stable durable state of one deferred proposal.
type MissionProposalState string

const (
	MissionProposalPending  MissionProposalState = "pending"
	MissionProposalApproved MissionProposalState = "approved"
	MissionProposalDenied   MissionProposalState = "denied"
	MissionProposalExpired  MissionProposalState = "expired"
)

// MissionProposalRecord is the exact verified request retained before a 202
// response is exposed to the Agent.
type MissionProposalRecord struct {
	ID                    string
	PersonServer          string
	AgentProvider         string
	Agent                 string
	Confirmation          jose.JWK
	AgentExpiresAt        time.Time
	AgentAdditionalClaims map[string]json.RawMessage
	ExactJSON             []byte
	CreatedAt             time.Time
	ExpiresAt             time.Time
	RetryAfter            time.Duration
}

// Clone returns an independent copy suitable for a store boundary.
func (record MissionProposalRecord) Clone() MissionProposalRecord {
	return cloneMissionProposalRecord(record)
}

// Equal reports whether two records carry the same retained proposal state.
func (record MissionProposalRecord) Equal(other MissionProposalRecord) bool {
	return missionProposalRecordsEqual(record, other)
}

// MissionProposalPollIdentity is the verified Agent identity attached to one
// pending-URL GET.
type MissionProposalPollIdentity struct {
	PersonServer           string
	AgentProvider          string
	Agent                  string
	ConfirmationThumbprint string
}

// MissionProposalApproval is the complete canonical consequence of one host
// approval. Mission and PersonTokenRecords are committed atomically with the
// terminal response material. PersonTokens contains bearer credentials and
// must be protected from disclosure and logs.
type MissionProposalApproval struct {
	Mission            MissionRecord
	PersonTokens       map[string]string
	PersonTokenRecords []PersonTokenRecord
}

// Expired reports whether the approved Mission or any returned Person token
// is no longer usable at the supplied instant. Proposal stores use this before
// terminal delivery so an Agent never consumes an already-stale approval.
func (approval MissionProposalApproval) Expired(at time.Time) bool {
	if at.IsZero() {
		return true
	}
	if !approval.Mission.ExpiresAt.IsZero() && !at.Before(approval.Mission.ExpiresAt) {
		return true
	}
	for _, token := range approval.PersonTokenRecords {
		if token.ExpiresAt.IsZero() || !at.Before(token.ExpiresAt) {
			return true
		}
	}
	return false
}

// Clone returns an independent copy suitable for a store boundary.
func (approval MissionProposalApproval) Clone() MissionProposalApproval {
	return cloneMissionProposalApproval(approval)
}

// Equivalent reports whether two approvals represent the same host decision.
// Generated token identifiers and issuance instants do not affect equivalence;
// a store uses the first committed approval as the canonical result.
func (approval MissionProposalApproval) Equivalent(other MissionProposalApproval) bool {
	return missionApprovalsSemanticallyEqual(approval, other)
}

// MissionProposalSnapshot is the complete durable state used by host resume
// and one Agent poll. Approved snapshots contain bearer credentials and
// require confidentiality, integrity, and access control. DeliveredAt is
// nonzero after the terminal Agent response has been consumed.
type MissionProposalSnapshot struct {
	Record      MissionProposalRecord
	State       MissionProposalState
	Approval    MissionProposalApproval
	DecidedAt   time.Time
	DeliveredAt time.Time
}

// Clone returns an independent copy suitable for a store boundary.
func (snapshot MissionProposalSnapshot) Clone() MissionProposalSnapshot {
	return cloneMissionProposalSnapshot(snapshot)
}

// MissionProposalStore is the optional focused extension required by deferred
// mission proposal review. Approval commits the terminal proposal state, the
// Mission, and every Person-token record in one backend transaction.
type MissionProposalStore interface {
	MissionStore
	// CreateMissionProposal atomically creates one pending record and refuses a
	// duplicate identifier. The implementation retains an independent copy.
	CreateMissionProposal(context.Context, MissionProposalRecord) error
	// ListPendingMissionProposals is the durable host queue. It returns at most
	// limit currently pending records in stable creation order after atomically
	// materializing expiry at the supplied time.
	ListPendingMissionProposals(context.Context, time.Time, int) ([]MissionProposalRecord, error)
	// LoadMissionProposal materializes pending or approved expiry at the
	// supplied instant and returns an independent complete snapshot.
	LoadMissionProposal(context.Context, string, time.Time) (MissionProposalSnapshot, error)
	// ApproveMissionProposal compares the complete expected record and commits
	// the first canonical approval, Mission, and Person-token records in one
	// transaction. An equivalent retry returns the first canonical approval; a
	// different decision conflicts.
	ApproveMissionProposal(context.Context, MissionProposalRecord, MissionProposalApproval, time.Time) (MissionProposalApproval, error)
	// DenyMissionProposal compares the complete expected record and atomically
	// retains the first denial. Repeating that denial succeeds; approval or a
	// changed terminal state conflicts.
	DenyMissionProposal(context.Context, MissionProposalRecord, time.Time) error
	// PollMissionProposal leaves live pending state unchanged. Before delivery
	// it converts an expired pending record or approval into the terminal
	// expired state. Otherwise it atomically records terminal delivery and
	// returns the one winning snapshot; every later poll returns
	// ErrMissionProposalGone.
	PollMissionProposal(context.Context, string, MissionProposalPollIdentity, time.Time) (MissionProposalSnapshot, error)
}

// MissionProposalReview is the exact retained proposal presented to a host
// that has authenticated the responsible person or administrator separately.
// Possessing this value is not itself person authority. Proposal descriptions
// are untrusted Markdown and must be sanitized before rendering.
type MissionProposalReview struct {
	record MissionProposalRecord
}

// Reference returns the opaque proposal reference.
func (review MissionProposalReview) Reference() string { return review.record.ID }

// AgentProvider returns the Agent Provider that issued the proposal's Agent token.
func (review MissionProposalReview) AgentProvider() string { return review.record.AgentProvider }

// Agent returns the proposing Agent identifier.
func (review MissionProposalReview) Agent() string { return review.record.Agent }

// Proposal returns an independent copy of the parsed proposal. Its Markdown
// fields remain untrusted.
func (review MissionProposalReview) Proposal() aauth.MissionProposal {
	proposal, _ := missionProposalFromRecord(review.record)
	return proposal
}

// ExactJSON returns the exact signed proposal bytes retained by the Person Server.
func (review MissionProposalReview) ExactJSON() []byte {
	return append([]byte(nil), review.record.ExactJSON...)
}

// AgentAdditionalClaims returns independent copies of extension claims from
// the Agent token used for the proposal.
func (review MissionProposalReview) AgentAdditionalClaims() map[string]json.RawMessage {
	return cloneClaims(review.record.AgentAdditionalClaims)
}

// CreatedAt returns the request-proof instant attached to the retained proposal.
func (review MissionProposalReview) CreatedAt() time.Time { return review.record.CreatedAt }

// ExpiresAt returns the host-decision deadline.
func (review MissionProposalReview) ExpiresAt() time.Time { return review.record.ExpiresAt }

// ResumeMissionProposal reconstructs a host review from durable state. The
// application must authenticate the responsible person or administrator before
// exposing the returned proposal or calling a decision method.
func (server *Server) ResumeMissionProposal(ctx context.Context, reference string) (MissionProposalReview, error) {
	if server == nil || server.missionProposals == nil {
		return MissionProposalReview{}, errors.New("personserver: deferred mission proposals are not configured")
	}
	if ctx == nil {
		return MissionProposalReview{}, errors.New("personserver: context is required")
	}
	if reference == "" {
		return MissionProposalReview{}, errors.New("personserver: mission proposal reference is required")
	}
	snapshot, err := server.missionProposals.LoadMissionProposal(ctx, reference, server.clock.Now().UTC())
	if err != nil {
		return MissionProposalReview{}, err
	}
	if err := validateMissionProposalSnapshot(snapshot); err != nil || snapshot.Record.ID != reference ||
		snapshot.Record.PersonServer != server.issuer {
		return MissionProposalReview{}, ErrMissionProposalConflict
	}
	if snapshot.State == MissionProposalExpired {
		return MissionProposalReview{}, ErrMissionProposalExpired
	}
	return MissionProposalReview{
		record: cloneMissionProposalRecord(snapshot.Record),
	}, nil
}

// PendingMissionProposals returns the bounded durable host review queue. The
// application must authenticate the person or administrator before exposing
// these records or acting on them.
func (server *Server) PendingMissionProposals(ctx context.Context, limit int) ([]MissionProposalReview, error) {
	if server == nil || server.missionProposals == nil {
		return nil, errors.New("personserver: deferred mission proposals are not configured")
	}
	if ctx == nil {
		return nil, errors.New("personserver: context is required")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if limit < 1 || limit > 1000 {
		return nil, errors.New("personserver: mission proposal list limit must be between 1 and 1000")
	}
	records, err := server.missionProposals.ListPendingMissionProposals(ctx, server.clock.Now().UTC(), limit)
	if err != nil {
		return nil, err
	}
	reviews := make([]MissionProposalReview, len(records))
	for index, record := range records {
		if err := validateMissionProposalRecord(record); err != nil || record.PersonServer != server.issuer {
			return nil, ErrMissionProposalConflict
		}
		reviews[index] = MissionProposalReview{record: cloneMissionProposalRecord(record)}
	}
	return reviews, nil
}

// ApproveMissionProposal creates one canonical Mission and its approved
// Resource Person tokens, then asks the focused store to retain all of them in
// the same transaction as the terminal proposal decision.
func (server *Server) ApproveMissionProposal(ctx context.Context, review MissionProposalReview, decision MissionDecision) error {
	if err := server.validateMissionProposalReview(ctx, review); err != nil {
		return err
	}
	now := server.clock.Now().UTC()
	snapshot, err := server.missionProposals.LoadMissionProposal(ctx, review.record.ID, now)
	if err != nil {
		return err
	}
	if err := validateMissionProposalSnapshot(snapshot); err != nil || !missionProposalRecordsEqual(snapshot.Record, review.record) {
		return ErrMissionProposalConflict
	}
	switch snapshot.State {
	case MissionProposalApproved:
		if missionRecordMatchesDecision(snapshot.Approval.Mission, decision) {
			return nil
		}
		return ErrMissionProposalConflict
	case MissionProposalDenied:
		return ErrMissionProposalConflict
	case MissionProposalExpired:
		return ErrMissionProposalExpired
	case MissionProposalPending:
		// Continue below.
	default:
		return ErrMissionProposalConflict
	}
	if !now.Before(review.record.ExpiresAt) || !now.Before(review.record.AgentExpiresAt) {
		return ErrMissionProposalExpired
	}
	proposal, err := missionProposalFromRecord(review.record)
	if err != nil {
		return err
	}
	if err := validateMissionDecision(decision, proposal, now); err != nil {
		return err
	}
	agent := agentClaimsFromMissionProposalRecord(review.record)
	approval, err := server.prepareMissionApproval(ctx, agent, decision, now)
	if err != nil {
		return err
	}
	canonical, err := server.missionProposals.ApproveMissionProposal(
		ctx, cloneMissionProposalRecord(review.record), cloneMissionProposalApproval(approval), server.clock.Now().UTC(),
	)
	if err != nil {
		return err
	}
	return validateCanonicalMissionProposalApproval(review.record, decision, canonical)
}

func agentClaimsFromMissionProposalRecord(record MissionProposalRecord) aauth.AgentTokenClaims {
	return aauth.AgentTokenClaims{
		Issuer: record.AgentProvider, DWK: aauth.AgentDiscoveryDocument, Subject: record.Agent,
		PersonServer: record.PersonServer, Confirmation: aauth.Confirmation{JWK: record.Confirmation},
		ExpiresAt: record.AgentExpiresAt.Unix(), AdditionalClaims: cloneClaims(record.AgentAdditionalClaims),
	}
}

// DenyMissionProposal retains one host-authenticated denial. The application
// must authenticate the responsible person or administrator before calling it.
func (server *Server) DenyMissionProposal(ctx context.Context, review MissionProposalReview) error {
	if err := server.validateMissionProposalReview(ctx, review); err != nil {
		return err
	}
	now := server.clock.Now().UTC()
	snapshot, err := server.missionProposals.LoadMissionProposal(ctx, review.record.ID, now)
	if err != nil {
		return err
	}
	if err := validateMissionProposalSnapshot(snapshot); err != nil || !missionProposalRecordsEqual(snapshot.Record, review.record) {
		return ErrMissionProposalConflict
	}
	switch snapshot.State {
	case MissionProposalDenied:
		return nil
	case MissionProposalApproved:
		return ErrMissionProposalConflict
	case MissionProposalExpired:
		return ErrMissionProposalExpired
	case MissionProposalPending:
		if !now.Before(review.record.ExpiresAt) || !now.Before(review.record.AgentExpiresAt) {
			return ErrMissionProposalExpired
		}
		return server.missionProposals.DenyMissionProposal(ctx, cloneMissionProposalRecord(review.record), now)
	default:
		return ErrMissionProposalConflict
	}
}

func (server *Server) validateMissionProposalReview(ctx context.Context, review MissionProposalReview) error {
	if server == nil || server.missionProposals == nil {
		return errors.New("personserver: deferred mission proposals are not configured")
	}
	if ctx == nil {
		return errors.New("personserver: context is required")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if review.record.PersonServer != server.issuer || validateMissionProposalRecord(review.record) != nil {
		return ErrMissionProposalConflict
	}
	return nil
}

func validateMissionProposalSnapshot(snapshot MissionProposalSnapshot) error {
	if err := validateMissionProposalRecord(snapshot.Record); err != nil {
		return err
	}
	switch snapshot.State {
	case MissionProposalPending:
		if !snapshot.DecidedAt.IsZero() || !snapshot.DeliveredAt.IsZero() || snapshot.Approval.Mission.S256 != "" {
			return ErrMissionProposalConflict
		}
	case MissionProposalApproved:
		if snapshot.DecidedAt.IsZero() || snapshot.Approval.Mission.S256 == "" {
			return ErrMissionProposalConflict
		}
	case MissionProposalDenied, MissionProposalExpired:
		if snapshot.DecidedAt.IsZero() || snapshot.Approval.Mission.S256 != "" {
			return ErrMissionProposalConflict
		}
	default:
		return ErrMissionProposalConflict
	}
	return nil
}

func missionProposalRecordsEqual(left, right MissionProposalRecord) bool {
	return left.ID == right.ID && left.PersonServer == right.PersonServer &&
		left.AgentProvider == right.AgentProvider && left.Agent == right.Agent &&
		left.Confirmation.Equal(right.Confirmation) && left.AgentExpiresAt.Equal(right.AgentExpiresAt) &&
		claimsEqual(left.AgentAdditionalClaims, right.AgentAdditionalClaims) &&
		bytes.Equal(left.ExactJSON, right.ExactJSON) &&
		left.CreatedAt.Equal(right.CreatedAt) && left.ExpiresAt.Equal(right.ExpiresAt) && left.RetryAfter == right.RetryAfter
}

func claimsEqual(left, right map[string]json.RawMessage) bool {
	if len(left) != len(right) {
		return false
	}
	for name, value := range left {
		if other, ok := right[name]; !ok || !bytes.Equal(value, other) {
			return false
		}
	}
	return true
}

func validateCanonicalMissionProposalApproval(
	record MissionProposalRecord,
	decision MissionDecision,
	approval MissionProposalApproval,
) error {
	if !missionRecordMatchesDecision(approval.Mission, decision) || approval.Mission.Agent != record.Agent ||
		approval.Mission.State != MissionActive || approval.Mission.S256 == "" ||
		len(approval.PersonTokens) != len(approval.PersonTokenRecords) {
		return ErrMissionProposalConflict
	}
	if _, err := validateMissionRecord(approval.Mission); err != nil {
		return err
	}
	for _, token := range approval.PersonTokenRecords {
		if token.Agent != record.Agent || token.AgentProvider != record.AgentProvider ||
			token.MissionS256 != approval.Mission.S256 || !token.Confirmation.Equal(record.Confirmation) ||
			approval.PersonTokens[token.Resource] == "" {
			return ErrMissionProposalConflict
		}
	}
	return nil
}

func missionRecordMatchesDecision(record MissionRecord, decision MissionDecision) bool {
	mission, err := validateMissionRecord(record)
	if err != nil || mission.Blob.Description != decision.Description ||
		!slices.Equal(mission.Blob.ApprovedTools, decision.ApprovedTools) ||
		!slices.Equal(mission.Blob.ApprovedResources, decision.ApprovedResources) ||
		!slices.Equal(record.Capabilities, decision.Capabilities) ||
		(mission.Blob.ExpiresAt == nil) != (decision.ExpiresAt == nil) {
		return false
	}
	return mission.Blob.ExpiresAt == nil || mission.Blob.ExpiresAt.Equal(*decision.ExpiresAt)
}

func missionApprovalsSemanticallyEqual(left, right MissionProposalApproval) bool {
	leftMission, leftErr := validateMissionRecord(left.Mission)
	rightMission, rightErr := validateMissionRecord(right.Mission)
	if leftErr != nil || rightErr != nil {
		return false
	}
	return leftMission.Blob.Agent == rightMission.Blob.Agent &&
		leftMission.Blob.Approver == rightMission.Blob.Approver &&
		leftMission.Blob.Description == rightMission.Blob.Description &&
		slices.Equal(leftMission.Blob.ApprovedTools, rightMission.Blob.ApprovedTools) &&
		slices.Equal(leftMission.Blob.ApprovedResources, rightMission.Blob.ApprovedResources) &&
		slices.Equal(left.Mission.Capabilities, right.Mission.Capabilities) &&
		((leftMission.Blob.ExpiresAt == nil && rightMission.Blob.ExpiresAt == nil) ||
			(leftMission.Blob.ExpiresAt != nil && rightMission.Blob.ExpiresAt != nil && leftMission.Blob.ExpiresAt.Equal(*rightMission.Blob.ExpiresAt)))
}

func (server *Server) handlePendingMissionProposal(response http.ResponseWriter, request *http.Request) {
	if !requestBodyIsEmpty(request) {
		writeProblem(response, http.StatusBadRequest, "invalid_request", errors.New("mission proposal polling requires a bodyless GET"))
		return
	}
	_, agent, proof, err := server.verifyAgentRequest(request, nil)
	if err != nil {
		writeAgentTokenProblem(response, err)
		return
	}
	if err := server.validateDirectAgentTopology(agent); err != nil {
		writeAgentTokenProblem(response, err)
		return
	}
	thumbprint, err := agent.Confirmation.JWK.Thumbprint()
	if err != nil {
		writeAgentTokenProblem(response, err)
		return
	}
	id := request.PathValue("id")
	if id == "" {
		writeProblem(response, http.StatusGone, "invalid_code", ErrMissionProposalNotFound)
		return
	}
	now := proof.VerifiedAt().UTC()
	identity := MissionProposalPollIdentity{
		PersonServer: server.issuer, AgentProvider: agent.Issuer, Agent: agent.Subject,
		ConfirmationThumbprint: thumbprint,
	}
	snapshot, err := server.missionProposals.PollMissionProposal(request.Context(), id, identity, now)
	if err != nil {
		switch {
		case errors.Is(err, ErrMissionProposalNotFound), errors.Is(err, ErrMissionProposalGone):
			writeProblem(response, http.StatusGone, "invalid_code", err)
		case errors.Is(err, ErrMissionProposalExpired):
			writeProblem(response, http.StatusRequestTimeout, "expired", err)
		default:
			writeProblem(response, http.StatusInternalServerError, "server_error", err)
		}
		return
	}
	if err := validatePolledMissionProposal(id, identity, snapshot, now); err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", err)
		return
	}
	switch snapshot.State {
	case MissionProposalPending:
		writePendingMissionProposal(response, request.URL.Path, snapshot.Record.RetryAfter)
	case MissionProposalApproved:
		writePrivateJSON(response, http.StatusOK, missionApprovalResponse(snapshot.Approval))
	case MissionProposalDenied:
		writeProblem(response, http.StatusForbidden, "denied", ErrMissionDenied)
	case MissionProposalExpired:
		writeProblem(response, http.StatusRequestTimeout, "expired", ErrMissionProposalExpired)
	default:
		writeProblem(response, http.StatusInternalServerError, "server_error", ErrMissionProposalConflict)
	}
}

func missionApprovalResponse(approval MissionProposalApproval) aauth.MissionApproval {
	return aauth.MissionApproval{
		S256:         approval.Mission.S256,
		Mission:      base64.RawURLEncoding.EncodeToString(approval.Mission.ExactJSON),
		Capabilities: append([]string(nil), approval.Mission.Capabilities...),
		PersonTokens: cloneStringMap(approval.PersonTokens),
	}
}

func validatePolledMissionProposal(
	id string,
	identity MissionProposalPollIdentity,
	snapshot MissionProposalSnapshot,
	now time.Time,
) error {
	if err := validateMissionProposalSnapshot(snapshot); err != nil || snapshot.Record.ID != id ||
		snapshot.Record.PersonServer != identity.PersonServer || snapshot.Record.AgentProvider != identity.AgentProvider ||
		snapshot.Record.Agent != identity.Agent || snapshot.Record.CreatedAt.After(now) {
		return ErrMissionProposalConflict
	}
	thumbprint, err := snapshot.Record.Confirmation.Thumbprint()
	if err != nil || thumbprint != identity.ConfirmationThumbprint {
		return ErrMissionProposalConflict
	}
	if (snapshot.State == MissionProposalPending || snapshot.State == MissionProposalApproved) &&
		(!now.Before(snapshot.Record.ExpiresAt) || !now.Before(snapshot.Record.AgentExpiresAt)) {
		return ErrMissionProposalConflict
	}
	if snapshot.State == MissionProposalApproved && snapshot.Approval.Expired(now) {
		return ErrMissionProposalConflict
	}
	if snapshot.State == MissionProposalPending && !snapshot.DeliveredAt.IsZero() {
		return ErrMissionProposalConflict
	}
	if snapshot.State != MissionProposalPending && (snapshot.DeliveredAt.IsZero() || snapshot.DeliveredAt.After(now)) {
		return ErrMissionProposalConflict
	}
	return nil
}

func cloneStringMap(values map[string]string) map[string]string {
	if values == nil {
		return nil
	}
	cloned := make(map[string]string, len(values))
	for key, value := range values {
		cloned[key] = value
	}
	return cloned
}

func cloneMissionProposalRecord(record MissionProposalRecord) MissionProposalRecord {
	record.AgentAdditionalClaims = cloneClaims(record.AgentAdditionalClaims)
	record.ExactJSON = append([]byte(nil), record.ExactJSON...)
	return record
}

func cloneMissionProposalApproval(approval MissionProposalApproval) MissionProposalApproval {
	approval.Mission = cloneMissionRecordForTransition(approval.Mission)
	if approval.PersonTokens != nil {
		cloned := make(map[string]string, len(approval.PersonTokens))
		for resource, token := range approval.PersonTokens {
			cloned[resource] = token
		}
		approval.PersonTokens = cloned
	}
	approval.PersonTokenRecords = append([]PersonTokenRecord(nil), approval.PersonTokenRecords...)
	return approval
}

func cloneMissionProposalSnapshot(snapshot MissionProposalSnapshot) MissionProposalSnapshot {
	snapshot.Record = cloneMissionProposalRecord(snapshot.Record)
	snapshot.Approval = cloneMissionProposalApproval(snapshot.Approval)
	return snapshot
}
