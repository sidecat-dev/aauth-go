package personserver

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/internal/interaction"
)

var (
	// ErrInteractionRelayUnavailable tells the Agent to present the original
	// URL and code itself because the Person Server cannot relay them.
	ErrInteractionRelayUnavailable = errors.New("personserver: interaction relay is unavailable")
	ErrInteractionRelayNotFound    = errors.New("personserver: interaction relay not found")
	ErrInteractionRelayConflict    = errors.New("personserver: interaction relay conflicts with retained state")
	ErrInteractionRelayGone        = errors.New("personserver: interaction relay is gone")
)

// InteractionRelayConfig enables retained interaction and payment relays.
// With missions, Store must be nil and the server's Tokens must implement
// MissionInteractionRelayStore.
type InteractionRelayConfig struct {
	Policy func(context.Context, InteractionRelayPolicyRequest) (InteractionRelayPendingPolicy, error)
	Store  InteractionRelayStore
}

// InteractionRelayPolicyRequest supplies the verified Agent identity, exact
// untrusted relay document, and post-validation server instant.
type InteractionRelayPolicyRequest struct {
	Agent      string
	Document   aauth.InteractionRelayDocument
	ReceivedAt time.Time
	Mission    *MissionContext
}

// InteractionRelayPendingPolicy bounds one accepted relay. The request's
// max_wait, when present, can only shorten Lifetime.
type InteractionRelayPendingPolicy struct {
	Lifetime   time.Duration
	RetryAfter time.Duration
}

// InteractionRelayState is the retained relay lifecycle.
type InteractionRelayState uint8

const (
	InteractionRelayPending InteractionRelayState = iota + 1
	InteractionRelayResolved
	InteractionRelayGone
)

// InteractionRelayRecord is the complete purpose-specific retained relay
// state. A store must preserve every field exactly.
type InteractionRelayRecord struct {
	ID                     string
	PersonServer           string
	AgentProvider          string
	Agent                  string
	ConfirmationThumbprint string
	AgentExpiresAt         time.Time
	Document               aauth.InteractionRelayDocument
	State                  InteractionRelayState
	Completion             aauth.InteractionRelayCompletion
	CreatedAt              time.Time
	ExpiresAt              time.Time
	ResolvedAt             time.Time
	RetryAfter             time.Duration
}

// InteractionRelayPollIdentity binds polling to the original Agent and key.
type InteractionRelayPollIdentity struct {
	PersonServer           string
	AgentProvider          string
	Agent                  string
	ConfirmationThumbprint string
}

// InteractionRelayStore owns only deferred relay state. On or after ExpiresAt,
// a pending record becomes resolved with status pending before it is returned.
type InteractionRelayStore interface {
	CreateInteractionRelay(context.Context, InteractionRelayRecord) error
	LoadInteractionRelay(context.Context, string, time.Time) (InteractionRelayRecord, error)
	ResolveInteractionRelay(context.Context, string, aauth.InteractionRelayStatus, time.Time) (InteractionRelayRecord, error)
	PollInteractionRelay(context.Context, string, InteractionRelayPollIdentity, time.Time) (InteractionRelayRecord, error)
	ConsumeInteractionRelay(context.Context, string, InteractionRelayRecord) error
}

// MissionInteractionRelayStore keeps relay transitions in the same atomic
// boundary as mission lifecycle and mission-bound tokens.
type MissionInteractionRelayStore interface {
	MissionStore
	InteractionRelayStore
	CreateMissionInteractionRelay(context.Context, MissionRecord, InteractionRelayRecord, time.Time) error
	ResolveMissionInteractionRelay(context.Context, MissionRecord, string, aauth.InteractionRelayStatus, time.Time) (InteractionRelayRecord, error)
	PollMissionInteractionRelay(context.Context, MissionRecord, string, InteractionRelayPollIdentity, time.Time) (InteractionRelayRecord, error)
	ConsumeMissionInteractionRelay(context.Context, MissionRecord, string, InteractionRelayRecord, time.Time) error
}

type interactionRelayHandleKind uint8

const interactionRelayHandleVerified interactionRelayHandleKind = 1

// InteractionRelayHandle is a non-authoritative host handle reconstructed from
// retained state. The host authenticates the person separately.
type InteractionRelayHandle struct {
	kind          interactionRelayHandleKind
	record        InteractionRelayRecord
	mission       *MissionContext
	missionRecord *MissionRecord
}

// Reference returns the opaque relay reference.
func (handle InteractionRelayHandle) Reference() string {
	if handle.kind != interactionRelayHandleVerified {
		return ""
	}
	return handle.record.ID
}

// Agent returns the verified top-level Agent.
func (handle InteractionRelayHandle) Agent() string {
	if handle.kind != interactionRelayHandleVerified {
		return ""
	}
	return handle.record.Agent
}

// Relay returns a caller-owned copy of the untrusted exact relay.
func (handle InteractionRelayHandle) Relay() aauth.InteractionRelayDocument {
	if handle.kind != interactionRelayHandleVerified {
		return aauth.InteractionRelayDocument{}
	}
	return cloneInteractionRelayDocument(handle.record.Document)
}

// ExpiresAt returns the relay's wait deadline.
func (handle InteractionRelayHandle) ExpiresAt() time.Time {
	if handle.kind != interactionRelayHandleVerified {
		return time.Time{}
	}
	return handle.record.ExpiresAt
}

// Mission returns a caller-owned exact mission context for a mission-bound
// relay. The bool is false for a missionless relay.
func (handle InteractionRelayHandle) Mission() (MissionContext, bool) {
	if handle.kind != interactionRelayHandleVerified || handle.mission == nil {
		return MissionContext{}, false
	}
	return *cloneMissionContext(handle.mission), true
}

func interactionRelayPolicy(config *InteractionRelayConfig) func(
	context.Context,
	InteractionRelayPolicyRequest,
) (InteractionRelayPendingPolicy, error) {
	if config == nil {
		return nil
	}
	return config.Policy
}

func (server *Server) handleVerifiedInteractionRelay(
	response http.ResponseWriter,
	request *http.Request,
	agent aauth.AgentTokenClaims,
	exactJSON []byte,
) {
	document, err := aauth.DecodeInteractionRelay(exactJSON)
	if err != nil {
		writeProblem(response, http.StatusBadRequest, "invalid_request", err)
		return
	}
	if server.interactionRelayPolicy == nil {
		writeProblem(response, http.StatusFailedDependency, "interaction_unavailable", ErrInteractionRelayUnavailable)
		return
	}
	receivedAt := server.clock.Now().UTC()
	var missionRecord *MissionRecord
	var missionContext *MissionContext
	if document.Relay.MissionS256 != "" {
		if server.missionInteractionRelays == nil {
			writeProblem(response, http.StatusBadRequest, "invalid_request", errors.New("personserver: mission-bound interaction relay is not configured"))
			return
		}
		loaded, err := server.loadActiveMission(
			request.Context(), document.Relay.MissionS256, agent.Subject, receivedAt,
		)
		if err != nil {
			writeMissionReferenceProblem(response, err)
			return
		}
		missionRecord = &loaded
		missionContext, err = missionContextFromRecord(loaded)
		if err != nil {
			writeProblem(response, http.StatusInternalServerError, "server_error", err)
			return
		}
	}
	policy, err := server.interactionRelayPolicy(request.Context(), InteractionRelayPolicyRequest{
		Agent:      agent.Subject,
		Document:   cloneInteractionRelayDocument(document),
		ReceivedAt: receivedAt,
		Mission:    missionContext,
	})
	if err != nil {
		if errors.Is(err, ErrInteractionRelayUnavailable) {
			writeProblem(response, http.StatusFailedDependency, "interaction_unavailable", err)
			return
		}
		writeProblem(response, http.StatusInternalServerError, "server_error", err)
		return
	}
	if err := validateInteractionRelayPendingPolicy(policy); err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", err)
		return
	}
	thumbprint, err := agent.Confirmation.JWK.Thumbprint()
	if err != nil {
		writeAgentTokenProblem(response, err)
		return
	}
	agentExpiresAt := time.Unix(agent.ExpiresAt, 0).UTC()
	expiresAt := receivedAt.Add(policy.Lifetime)
	if document.Relay.MaxWait > 0 && receivedAt.Add(document.Relay.MaxWait).Before(expiresAt) {
		expiresAt = receivedAt.Add(document.Relay.MaxWait)
	}
	if agentExpiresAt.Before(expiresAt) {
		expiresAt = agentExpiresAt
	}
	if !expiresAt.After(receivedAt) {
		writeProblem(response, http.StatusRequestTimeout, "expired", errors.New("interaction relay already expired"))
		return
	}
	for attempt := 0; attempt < 3; attempt++ {
		id, err := interaction.GeneratePendingReference(nil)
		if err != nil {
			writeProblem(response, http.StatusInternalServerError, "server_error", err)
			return
		}
		record := InteractionRelayRecord{
			ID:                     id,
			PersonServer:           server.issuer,
			AgentProvider:          agent.Issuer,
			Agent:                  agent.Subject,
			ConfirmationThumbprint: thumbprint,
			AgentExpiresAt:         agentExpiresAt,
			Document:               cloneInteractionRelayDocument(document),
			State:                  InteractionRelayPending,
			CreatedAt:              receivedAt,
			ExpiresAt:              expiresAt,
			RetryAfter:             policy.RetryAfter,
		}
		if err := validateInteractionRelayRecord(record); err != nil {
			writeProblem(response, http.StatusInternalServerError, "server_error", err)
			return
		}
		var createErr error
		if missionRecord != nil {
			createErr = server.missionInteractionRelays.CreateMissionInteractionRelay(
				request.Context(), cloneMissionRecordForTransition(*missionRecord),
				cloneInteractionRelayRecord(record), server.clock.Now().UTC(),
			)
		} else {
			createErr = server.interactionRelayStore.CreateInteractionRelay(
				request.Context(), cloneInteractionRelayRecord(record),
			)
		}
		if createErr != nil {
			if errors.Is(createErr, ErrInteractionRelayConflict) {
				continue
			}
			if missionRecord != nil {
				writeMissionActionProblem(response, createErr)
				return
			}
			writeProblem(response, http.StatusInternalServerError, "server_error", createErr)
			return
		}
		server.writePendingInteractionQuestion(response, "/interaction/relay/"+id, record.RetryAfter)
		return
	}
	writeProblem(response, http.StatusInternalServerError, "server_error", errors.New("could not allocate interaction relay reference"))
}

// ResumeInteractionRelay reconstructs a non-authoritative host handle.
func (server *Server) ResumeInteractionRelay(ctx context.Context, reference string) (InteractionRelayHandle, error) {
	if server == nil || server.interactionRelayStore == nil {
		return InteractionRelayHandle{}, errors.New("personserver: interaction relays are not configured")
	}
	if ctx == nil {
		return InteractionRelayHandle{}, errors.New("personserver: context is required")
	}
	if reference == "" {
		return InteractionRelayHandle{}, errors.New("personserver: interaction relay reference is required")
	}
	now := server.clock.Now().UTC()
	record, err := server.interactionRelayStore.LoadInteractionRelay(ctx, reference, now)
	if err != nil {
		return InteractionRelayHandle{}, err
	}
	if validateInteractionRelayRecordAt(record, now) != nil || record.ID != reference ||
		record.PersonServer != server.issuer || record.State != InteractionRelayPending {
		return InteractionRelayHandle{}, ErrInteractionRelayConflict
	}
	var mission *MissionContext
	var missionRecord *MissionRecord
	if record.Document.Relay.MissionS256 != "" {
		if server.missionInteractionRelays == nil {
			return InteractionRelayHandle{}, ErrInteractionRelayConflict
		}
		loaded, err := server.loadActiveMission(
			ctx, record.Document.Relay.MissionS256, record.Agent, now,
		)
		if err != nil {
			return InteractionRelayHandle{}, err
		}
		mission, err = missionContextFromRecord(loaded)
		if err != nil {
			return InteractionRelayHandle{}, err
		}
		missionRecord = &loaded
	}
	var retainedMission *MissionRecord
	if missionRecord != nil {
		clone := cloneMissionRecordForTransition(*missionRecord)
		retainedMission = &clone
	}
	return InteractionRelayHandle{
		kind: interactionRelayHandleVerified, record: cloneInteractionRelayRecord(record),
		mission: cloneMissionContext(mission), missionRecord: retainedMission,
	}, nil
}

// MarkInteractionRelayEngaged records that the person reached the relayed URL.
func (server *Server) MarkInteractionRelayEngaged(ctx context.Context, handle InteractionRelayHandle) error {
	return server.resolveInteractionRelay(ctx, handle, aauth.InteractionRelayInteracting)
}

// FinishInteractionRelayNoProgress records that the Person Server can make no
// more progress. The Resource's pending URL remains authoritative.
func (server *Server) FinishInteractionRelayNoProgress(ctx context.Context, handle InteractionRelayHandle) error {
	return server.resolveInteractionRelay(ctx, handle, aauth.InteractionRelayPending)
}

func (server *Server) resolveInteractionRelay(
	ctx context.Context,
	handle InteractionRelayHandle,
	status aauth.InteractionRelayStatus,
) error {
	if server == nil || server.interactionRelayStore == nil {
		return errors.New("personserver: interaction relays are not configured")
	}
	if ctx == nil {
		return errors.New("personserver: context is required")
	}
	if handle.kind != interactionRelayHandleVerified ||
		validateInteractionRelayRecord(handle.record) != nil || handle.record.PersonServer != server.issuer {
		return ErrInteractionRelayConflict
	}
	now := server.clock.Now().UTC()
	if handle.record.Document.Relay.MissionS256 != "" {
		if server.missionInteractionRelays == nil || handle.mission == nil || handle.missionRecord == nil ||
			handle.mission.S256 != handle.record.Document.Relay.MissionS256 ||
			handle.missionRecord.S256 != handle.record.Document.Relay.MissionS256 ||
			handle.missionRecord.Agent != handle.record.Agent {
			return ErrInteractionRelayConflict
		}
		loaded, err := server.loadActiveMission(
			ctx, handle.missionRecord.S256, handle.missionRecord.Agent, now,
		)
		if err != nil {
			return err
		}
		if !handle.missionRecord.Equal(loaded) {
			return ErrMissionConflict
		}
		_, err = server.missionInteractionRelays.ResolveMissionInteractionRelay(
			ctx, cloneMissionRecordForTransition(*handle.missionRecord), handle.record.ID, status, now,
		)
		return err
	}
	if handle.mission != nil || handle.missionRecord != nil {
		return ErrInteractionRelayConflict
	}
	_, err := server.interactionRelayStore.ResolveInteractionRelay(ctx, handle.record.ID, status, now)
	return err
}

func (server *Server) handlePendingInteractionRelay(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		response.Header().Set("Allow", http.MethodGet)
		writeProblem(response, http.StatusMethodNotAllowed, "method_not_allowed", errors.New("interaction relay polling requires GET"))
		return
	}
	if !requestBodyIsEmpty(request) {
		writeProblem(response, http.StatusBadRequest, "invalid_request", errors.New("interaction relay polling requires a bodyless GET"))
		return
	}
	_, agent, _, err := server.verifyAgentProof(request, nil)
	if err != nil {
		writeAgentTokenProblem(response, err)
		return
	}
	if err := server.validateDirectAgentTopology(agent); err != nil {
		writeAgentTokenProblem(response, err)
		return
	}
	identity, err := interactionRelayPollIdentity(server.issuer, agent)
	if err != nil {
		writeAgentTokenProblem(response, err)
		return
	}
	id := request.PathValue("id")
	now := server.clock.Now().UTC()
	var mission *MissionRecord
	var record InteractionRelayRecord
	if server.missionInteractionRelays != nil {
		peek, peekErr := server.interactionRelayStore.LoadInteractionRelay(request.Context(), id, now)
		if peekErr == nil && peek.Document.Relay.MissionS256 != "" {
			if peek.PersonServer != identity.PersonServer || peek.AgentProvider != identity.AgentProvider ||
				peek.Agent != identity.Agent || peek.ConfirmationThumbprint != identity.ConfirmationThumbprint {
				writeProblem(response, http.StatusGone, "invalid_code", ErrInteractionRelayNotFound)
				return
			}
			if validateInteractionRelayRecordAt(peek, now) != nil || peek.ID != id {
				writeProblem(response, http.StatusInternalServerError, "server_error", ErrInteractionRelayConflict)
				return
			}
			loaded, loadErr := server.loadActiveMission(
				request.Context(), peek.Document.Relay.MissionS256, identity.Agent, now,
			)
			if loadErr != nil {
				writeMissionActionProblem(response, loadErr)
				return
			}
			mission = &loaded
			record, err = server.missionInteractionRelays.PollMissionInteractionRelay(
				request.Context(), cloneMissionRecordForTransition(loaded), id, identity, now,
			)
		} else if peekErr != nil {
			err = peekErr
		} else {
			record, err = server.interactionRelayStore.PollInteractionRelay(request.Context(), id, identity, now)
		}
	} else {
		record, err = server.interactionRelayStore.PollInteractionRelay(request.Context(), id, identity, now)
	}
	if err != nil {
		if mission != nil {
			writeMissionActionProblem(response, err)
			return
		}
		server.writeInteractionRelayStoreError(response, err)
		return
	}
	if validateInteractionRelayRecordAt(record, now) != nil || record.ID != id ||
		record.PersonServer != identity.PersonServer || record.AgentProvider != identity.AgentProvider ||
		record.Agent != identity.Agent || record.ConfirmationThumbprint != identity.ConfirmationThumbprint {
		writeProblem(response, http.StatusInternalServerError, "server_error", ErrInteractionRelayConflict)
		return
	}
	if record.State == InteractionRelayPending {
		server.writePendingInteractionQuestion(response, request.URL.Path, record.RetryAfter)
		return
	}
	if record.State != InteractionRelayResolved {
		server.writeInteractionRelayStoreError(response, ErrInteractionRelayConflict)
		return
	}
	completion, err := aauth.EncodeInteractionRelayCompletion(record.Completion)
	if err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", err)
		return
	}
	if mission != nil {
		err = server.missionInteractionRelays.ConsumeMissionInteractionRelay(
			request.Context(), cloneMissionRecordForTransition(*mission), record.ID,
			cloneInteractionRelayRecord(record), server.clock.Now().UTC(),
		)
	} else {
		err = server.interactionRelayStore.ConsumeInteractionRelay(
			request.Context(), record.ID, cloneInteractionRelayRecord(record),
		)
	}
	if err != nil {
		if mission != nil {
			writeMissionActionProblem(response, err)
			return
		}
		server.writeInteractionRelayStoreError(response, err)
		return
	}
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(http.StatusOK)
	_, _ = response.Write(completion.ExactJSON)
}

func validateInteractionRelayPendingPolicy(policy InteractionRelayPendingPolicy) error {
	if policy.Lifetime <= 0 || policy.Lifetime%time.Second != 0 ||
		policy.RetryAfter < 0 || policy.RetryAfter%time.Second != 0 {
		return errors.New("personserver: relay times must be whole seconds with positive lifetime")
	}
	return nil
}

func validateInteractionRelayRecord(record InteractionRelayRecord) error {
	if record.ID == "" || record.PersonServer == "" || record.AgentProvider == "" || record.Agent == "" ||
		record.ConfirmationThumbprint == "" || record.AgentExpiresAt.IsZero() || record.CreatedAt.IsZero() ||
		record.RetryAfter < 0 || record.RetryAfter%time.Second != 0 ||
		!record.ExpiresAt.After(record.CreatedAt) || record.AgentExpiresAt.Before(record.ExpiresAt) {
		return ErrInteractionRelayConflict
	}
	if aauth.ValidateServerIdentifier(record.PersonServer) != nil ||
		aauth.ValidateServerIdentifier(record.AgentProvider) != nil ||
		aauth.ValidateAgentIdentifier(record.Agent) != nil {
		return ErrInteractionRelayConflict
	}
	decoded, err := aauth.DecodeInteractionRelay(record.Document.ExactJSON)
	if err != nil || decoded.Relay != record.Document.Relay ||
		!bytes.Equal(decoded.ExactJSON, record.Document.ExactJSON) {
		return ErrInteractionRelayConflict
	}
	switch record.State {
	case InteractionRelayPending:
		if record.Completion.Status != "" || !record.ResolvedAt.IsZero() {
			return ErrInteractionRelayConflict
		}
	case InteractionRelayResolved, InteractionRelayGone:
		if record.Completion.Validate() != nil || record.ResolvedAt.Before(record.CreatedAt) ||
			record.ResolvedAt.After(record.ExpiresAt) {
			return ErrInteractionRelayConflict
		}
	default:
		return ErrInteractionRelayConflict
	}
	return nil
}

func validateInteractionRelayRecordAt(record InteractionRelayRecord, now time.Time) error {
	if validateInteractionRelayRecord(record) != nil || record.CreatedAt.After(now) {
		return ErrInteractionRelayConflict
	}
	if record.State == InteractionRelayPending && !now.Before(record.ExpiresAt) {
		return ErrInteractionRelayConflict
	}
	if record.State != InteractionRelayPending && record.ResolvedAt.After(now) {
		return ErrInteractionRelayConflict
	}
	return nil
}

func interactionRelayPollIdentity(personServer string, agent aauth.AgentTokenClaims) (InteractionRelayPollIdentity, error) {
	thumbprint, err := agent.Confirmation.JWK.Thumbprint()
	if err != nil {
		return InteractionRelayPollIdentity{}, err
	}
	return InteractionRelayPollIdentity{
		PersonServer:           personServer,
		AgentProvider:          agent.Issuer,
		Agent:                  agent.Subject,
		ConfirmationThumbprint: thumbprint,
	}, nil
}

func (server *Server) writeInteractionRelayStoreError(response http.ResponseWriter, err error) {
	if errors.Is(err, ErrInteractionRelayNotFound) || errors.Is(err, ErrInteractionRelayGone) {
		writeProblem(response, http.StatusGone, "invalid_code", err)
		return
	}
	writeProblem(response, http.StatusInternalServerError, "server_error", err)
}

func cloneInteractionRelayDocument(document aauth.InteractionRelayDocument) aauth.InteractionRelayDocument {
	document.ExactJSON = append([]byte(nil), document.ExactJSON...)
	return document
}

func cloneInteractionRelayRecord(record InteractionRelayRecord) InteractionRelayRecord {
	record.Document = cloneInteractionRelayDocument(record.Document)
	return record
}
