package reference

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"time"

	"gitlab.com/sidecat-dev/aauth-go/jose"

	aauth "gitlab.com/sidecat-dev/aauth-go"
)

type pendingPersonTokenAuthorization struct {
	pendingInteraction
	agent                  string
	pollingAgent           string
	pollingAgentThumbprint string
	parentAgent            string
	upstream               *aauth.AuthTokenClaims
	targetKey              jose.JWK
	agentExpiresAt         int64
	resource               string
	missionS256            string
	missionExpiresAt       *time.Time
	decision               aauth.PersonTokenDecision
	terminalCompact        string
	terminalClaims         aauth.PersonTokenClaims
	terminalRecord         PersonTokenRecord
}

type pendingPersonTokenRecord struct {
	Interaction            pendingInteractionRecord  `json:"interaction"`
	Agent                  string                    `json:"agent"`
	PollingAgent           string                    `json:"polling_agent"`
	PollingAgentThumbprint string                    `json:"polling_agent_thumbprint"`
	ParentAgent            string                    `json:"parent_agent,omitempty"`
	Upstream               *aauth.AuthTokenClaims    `json:"upstream,omitempty"`
	TargetKey              jose.JWK                  `json:"target_key"`
	AgentExpiresAt         int64                     `json:"agent_expires_at"`
	Resource               string                    `json:"resource"`
	MissionS256            string                    `json:"mission_s256,omitempty"`
	MissionExpiresAt       *time.Time                `json:"mission_expires_at,omitempty"`
	Decision               aauth.PersonTokenDecision `json:"decision"`
	TerminalCompact        string                    `json:"terminal_compact,omitempty"`
	TerminalClaims         aauth.PersonTokenClaims   `json:"terminal_claims"`
	TerminalRecord         PersonTokenRecord         `json:"terminal_record"`
}

func snapshotPendingPersonToken(value *pendingPersonTokenAuthorization) *pendingPersonTokenRecord {
	if value == nil {
		return nil
	}
	return &pendingPersonTokenRecord{
		Interaction: snapshotPendingInteraction(value.pendingInteraction), Agent: value.agent,
		PollingAgent: value.pollingAgent, PollingAgentThumbprint: value.pollingAgentThumbprint,
		ParentAgent: value.parentAgent, Upstream: copyAuthorizationRequest(aauth.AuthorizationRequest{Upstream: value.upstream}).Upstream,
		TargetKey:      value.targetKey,
		AgentExpiresAt: value.agentExpiresAt, Resource: value.resource, MissionS256: value.missionS256,
		MissionExpiresAt: copyTimePointer(value.missionExpiresAt), Decision: value.decision,
		TerminalCompact: value.terminalCompact, TerminalClaims: value.terminalClaims, TerminalRecord: value.terminalRecord,
	}
}

func restorePendingPersonToken(value pendingPersonTokenRecord) (*pendingPersonTokenAuthorization, error) {
	interaction, err := restorePendingInteraction(value.Interaction)
	if err != nil {
		return nil, err
	}
	if value.Agent == "" || value.PollingAgent == "" || value.PollingAgentThumbprint == "" || value.AgentExpiresAt <= 0 ||
		aauth.ValidateServerIdentifier(value.Resource) != nil {
		return nil, ErrAuthorizationStateIntegrity
	}
	if _, err := value.TargetKey.PublicKey(); err != nil {
		return nil, ErrAuthorizationStateIntegrity
	}
	approved := interaction.state == pendingAuthorizationApproved
	if approved != (value.Decision.Subject != "") ||
		value.Decision.Subject != "" && (value.Decision.Lifetime <= 0 || value.Decision.Lifetime > time.Hour) {
		return nil, ErrAuthorizationStateIntegrity
	}
	hasTerminal := value.TerminalCompact != ""
	if hasTerminal != (value.TerminalClaims.JTI != "") || hasTerminal != (value.TerminalRecord.JTI != "") ||
		hasTerminal && !approved {
		return nil, ErrAuthorizationStateIntegrity
	}
	if hasTerminal {
		claims, record := value.TerminalClaims, value.TerminalRecord
		if validatePersonTokenRecord(record) != nil || record.TokenSHA256 != aauth.S256([]byte(value.TerminalCompact)) ||
			record.JTI != claims.JTI || record.PersonServer != claims.Issuer || record.Resource != claims.Audience ||
			record.Subject != claims.Subject || record.MissionS256 != claims.MissionS256 || record.Tenant != claims.Tenant ||
			claims.JTI != interaction.id || claims.Audience != value.Resource || claims.Subject != value.Decision.Subject ||
			claims.MissionS256 != value.MissionS256 || claims.Tenant != value.Decision.Tenant ||
			!claims.Confirmation.JWK.Equal(value.TargetKey) ||
			!reflect.DeepEqual(record.ExpiresAt, time.Unix(claims.ExpiresAt, 0).UTC()) {
			return nil, ErrAuthorizationStateIntegrity
		}
	}
	return &pendingPersonTokenAuthorization{
		pendingInteraction: interaction, agent: value.Agent, pollingAgent: value.PollingAgent,
		pollingAgentThumbprint: value.PollingAgentThumbprint, parentAgent: value.ParentAgent,
		upstream:  copyAuthorizationRequest(aauth.AuthorizationRequest{Upstream: value.Upstream}).Upstream,
		targetKey: value.TargetKey, agentExpiresAt: value.AgentExpiresAt, resource: value.Resource,
		missionS256: value.MissionS256, missionExpiresAt: copyTimePointer(value.MissionExpiresAt), decision: value.Decision,
		terminalCompact: value.TerminalCompact, terminalClaims: value.TerminalClaims, terminalRecord: value.TerminalRecord,
	}, nil
}

func (server *PersonServer) beginPendingPersonToken(
	response http.ResponseWriter,
	request aauth.PersonTokenRequest,
	pollingAgent string,
	targetKey jose.JWK,
	pollingKey jose.JWK,
	agentExpiresAt int64,
	missionExpiresAt *time.Time,
) error {
	now := server.clock.Now()
	expiresAt := now.Add(server.pendingLifetime)
	if candidate := time.Unix(agentExpiresAt, 0); candidate.Before(expiresAt) {
		expiresAt = candidate
	}
	if missionExpiresAt != nil && missionExpiresAt.Before(expiresAt) {
		expiresAt = *missionExpiresAt
	}
	server.randomMu.Lock()
	interaction, err := newPendingInteraction(server.random, expiresAt)
	server.randomMu.Unlock()
	if err != nil {
		return err
	}
	thumbprint, err := pollingKey.Thumbprint()
	if err != nil {
		return err
	}
	pending := &pendingPersonTokenAuthorization{
		pendingInteraction: interaction, agent: request.Agent, pollingAgent: pollingAgent,
		pollingAgentThumbprint: thumbprint, parentAgent: request.ParentAgent,
		upstream:  copyAuthorizationRequest(aauth.AuthorizationRequest{Upstream: request.Upstream}).Upstream,
		targetKey: targetKey, agentExpiresAt: agentExpiresAt, resource: request.Resource,
		missionS256: request.MissionS256, missionExpiresAt: copyTimePointer(missionExpiresAt),
	}
	server.pendingMu.Lock()
	defer server.pendingMu.Unlock()
	if _, exists := server.pendingPersonTokens[interaction.id]; exists {
		return errors.New("reference: pending identifier source returned a duplicate value")
	}
	server.pendingPersonTokens[interaction.id] = pending
	if err := server.persistAuthorizationStateLocked(context.Background()); err != nil {
		return err
	}
	return server.writePendingAuthorization(response, interaction.id, pendingAuthorizationWaiting, interaction.code)
}

// ApprovePersonToken records a trusted person-token decision after interaction
// correlation. The browser code itself cannot call this method.
func (server *PersonServer) ApprovePersonToken(ctx context.Context, pendingID string) error {
	server.pendingMu.Lock()
	if err := server.settleAuthorizationStateLocked(ctx); err != nil {
		server.pendingMu.Unlock()
		return err
	}
	pending := server.pendingPersonTokens[pendingID]
	if pending == nil || pending.state != pendingAuthorizationInteracting {
		server.pendingMu.Unlock()
		return errors.New("reference: pending person-token authorization is not awaiting a trusted decision")
	}
	if !pending.expiresAt.After(server.clock.Now()) {
		pending.state = pendingAuthorizationExpired
		err := server.persistAuthorizationStateLocked(ctx)
		server.pendingMu.Unlock()
		if err != nil {
			return err
		}
		return errors.New("reference: pending person-token authorization expired")
	}
	request := aauth.PersonTokenRequest{
		Agent: pending.agent, ParentAgent: pending.parentAgent, Resource: pending.resource, MissionS256: pending.missionS256,
		Confirmation: pending.targetKey, AgentExpiresAt: time.Unix(pending.agentExpiresAt, 0).UTC(),
		Upstream: copyAuthorizationRequest(aauth.AuthorizationRequest{Upstream: pending.upstream}).Upstream,
	}
	server.pendingMu.Unlock()
	decision, err := server.personTokenPolicy(ctx, request)
	if err != nil {
		return &personTokenPolicyDenialError{cause: err}
	}
	if decision.Subject == "" || decision.Lifetime <= 0 || decision.Lifetime > time.Hour {
		return errors.New("reference: person-token policy returned an invalid decision")
	}
	server.pendingMu.Lock()
	defer server.pendingMu.Unlock()
	pending = server.pendingPersonTokens[pendingID]
	if pending == nil || pending.state != pendingAuthorizationInteracting {
		return errors.New("reference: pending person-token authorization changed while approval was evaluated")
	}
	if !pending.expiresAt.After(server.clock.Now()) {
		pending.state = pendingAuthorizationExpired
		if err := server.persistAuthorizationStateLocked(ctx); err != nil {
			return err
		}
		return errors.New("reference: pending person-token authorization expired")
	}
	pending.decision = decision
	pending.state = pendingAuthorizationApproved
	return server.persistAuthorizationStateLocked(ctx)
}

// RejectPersonToken records a trusted terminal denial or abandonment.
func (server *PersonServer) RejectPersonToken(ctx context.Context, pendingID string, code aauth.PollingErrorCode) error {
	if code != aauth.PollingDenied && code != aauth.PollingAbandoned && code != aauth.PollingServerError {
		return errors.New("reference: unsupported person-token rejection code")
	}
	server.pendingMu.Lock()
	defer server.pendingMu.Unlock()
	if err := server.settleAuthorizationStateLocked(ctx); err != nil {
		return err
	}
	pending := server.pendingPersonTokens[pendingID]
	if pending == nil || pending.state != pendingAuthorizationInteracting {
		return errors.New("reference: pending person-token authorization is not awaiting a trusted decision")
	}
	if !pending.expiresAt.After(server.clock.Now()) {
		pending.state = pendingAuthorizationExpired
		if err := server.persistAuthorizationStateLocked(ctx); err != nil {
			return err
		}
		return errors.New("reference: pending person-token authorization expired")
	}
	pending.pollingError = code
	pending.state = pendingAuthorizationRejected
	return server.persistAuthorizationStateLocked(ctx)
}

func (server *PersonServer) handlePersonTokenInteractionIfPresent(response http.ResponseWriter, request *http.Request) bool {
	server.pendingMu.Lock()
	pending := server.pendingPersonTokens[request.PathValue("id")]
	if pending == nil {
		server.pendingMu.Unlock()
		return false
	}
	status, code, err := pending.correlate(request.URL.Query()["code"], server.clock.Now())
	agent, resource := pending.agent, pending.resource
	persistErr := server.persistAuthorizationStateLocked(request.Context())
	server.pendingMu.Unlock()
	if persistErr != nil {
		writeProblem(response, http.StatusServiceUnavailable, "authorization_state_unavailable", persistErr)
		return true
	}
	if err != nil {
		writeProblem(response, status, code, err)
		return true
	}
	writeJSON(response, http.StatusOK, map[string]any{
		"status": "interacting", "agent": agent, "resource": resource,
	})
	return true
}

func (server *PersonServer) handlePendingPersonTokenIfPresent(
	response http.ResponseWriter,
	request *http.Request,
	agent string,
	thumbprint string,
) bool {
	server.pendingMu.Lock()
	pending := server.pendingPersonTokens[request.PathValue("id")]
	if pending == nil {
		server.pendingMu.Unlock()
		return false
	}
	if pending.pollingAgent != agent || pending.pollingAgentThumbprint != thumbprint {
		server.pendingMu.Unlock()
		writeProblem(response, http.StatusForbidden, "invalid_pending", errors.New("pending person-token authorization belongs to a different agent key"))
		return true
	}
	if (pending.state == pendingAuthorizationWaiting || pending.state == pendingAuthorizationInteracting) &&
		!pending.expiresAt.After(server.clock.Now()) {
		pending.state = pendingAuthorizationExpired
		if err := server.persistAuthorizationStateLocked(request.Context()); err != nil {
			server.pendingMu.Unlock()
			writeProblem(response, http.StatusServiceUnavailable, "authorization_state_unavailable", err)
			return true
		}
	}
	switch pending.state {
	case pendingAuthorizationWaiting, pendingAuthorizationInteracting:
		id, state, code := pending.id, pending.state, pending.code
		server.pendingMu.Unlock()
		if err := server.writePendingAuthorization(response, id, state, code); err != nil {
			writeProblem(response, http.StatusInternalServerError, "server_error", err)
		}
	case pendingAuthorizationApproved:
		if pending.terminalCompact == "" {
			compact, claims, record, err := server.prepareApprovedPendingPersonToken(pending)
			if err != nil {
				server.pendingMu.Unlock()
				writePersonTokenIssuanceFailure(response, err)
				return true
			}
			pending.terminalCompact, pending.terminalClaims, pending.terminalRecord = compact, claims, record
			if err := server.persistAuthorizationStateLocked(request.Context()); err != nil {
				server.pendingMu.Unlock()
				writeProblem(response, http.StatusServiceUnavailable, "authorization_state_unavailable", err)
				return true
			}
		}
		compact, claims, record := pending.terminalCompact, pending.terminalClaims, pending.terminalRecord
		server.pendingMu.Unlock()
		if err := server.personTokenStore.Commit(request.Context(), record); err != nil {
			writePersonTokenIssuanceFailure(response, &personTokenCustodyError{cause: err})
			return true
		}
		writeJSON(response, http.StatusOK, map[string]any{
			"person_token": compact, "expires_in": claims.ExpiresAt - server.clock.Now().Unix(),
		})
	case pendingAuthorizationExpired:
		server.pendingMu.Unlock()
		writeProblem(response, http.StatusRequestTimeout, "expired", errors.New("pending person-token authorization expired"))
	case pendingAuthorizationRejected:
		code := pending.pollingError
		server.pendingMu.Unlock()
		writeProblem(response, http.StatusForbidden, string(code), errors.New("pending person-token authorization was not approved"))
	default:
		server.pendingMu.Unlock()
		writeProblem(response, http.StatusGone, "gone", errors.New("pending person-token authorization has an invalid state"))
	}
	return true
}

func (server *PersonServer) prepareApprovedPendingPersonToken(
	pending *pendingPersonTokenAuthorization,
) (string, aauth.PersonTokenClaims, PersonTokenRecord, error) {
	now := server.clock.Now()
	expiresAt := now.Add(pending.decision.Lifetime)
	if candidate := time.Unix(pending.agentExpiresAt, 0); candidate.Before(expiresAt) {
		expiresAt = candidate
	}
	if pending.missionExpiresAt != nil && pending.missionExpiresAt.Before(expiresAt) {
		expiresAt = *pending.missionExpiresAt
	}
	if !expiresAt.After(now) {
		return "", aauth.PersonTokenClaims{}, PersonTokenRecord{}, errors.New("person-token inputs expire before issuance")
	}
	claims := aauth.PersonTokenClaims{
		Issuer: server.identifier, DWK: aauth.PersonDiscoveryDocument, Audience: pending.resource,
		Subject: pending.decision.Subject, Confirmation: aauth.Confirmation{JWK: pending.targetKey},
		JTI: pending.id, IssuedAt: now.Unix(), ExpiresAt: expiresAt.Unix(),
		MissionS256: pending.missionS256, Tenant: pending.decision.Tenant,
	}
	compact, err := aauth.MintPersonToken(server.signingKey, claims)
	if err != nil {
		return "", aauth.PersonTokenClaims{}, PersonTokenRecord{}, err
	}
	canonicalExpiry := time.Unix(claims.ExpiresAt, 0).UTC()
	record := PersonTokenRecord{
		JTI: claims.JTI, PersonServer: claims.Issuer, TokenSHA256: aauth.S256([]byte(compact)),
		Resource: claims.Audience, Subject: claims.Subject, MissionS256: claims.MissionS256,
		Tenant: claims.Tenant, ExpiresAt: canonicalExpiry, RetainUntil: canonicalExpiry.Add(currentResourceTokenLifetime),
	}
	if validatePersonTokenRecord(record) != nil {
		return "", aauth.PersonTokenClaims{}, PersonTokenRecord{}, fmt.Errorf("reference: prepared pending person token is invalid")
	}
	return compact, claims, record, nil
}
