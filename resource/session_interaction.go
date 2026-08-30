package resource

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	aauth "github.com/aauth-dev/auth-go"
	"github.com/aauth-dev/auth-go/internal/interaction"
)

const sessionInteractionCorrelated = 1

// SessionInteraction is one correlated Resource-owned interaction. Possession
// of this value does not authenticate the person or authorize the grant.
type SessionInteraction struct {
	kind      uint8
	resource  string
	reference string
	request   SessionAuthorizationRequest
	createdAt time.Time
	expiresAt time.Time
}

// AgentPrincipal returns the independently copied Agent that started the
// interaction.
func (value SessionInteraction) AgentPrincipal() AgentPrincipal {
	principal := value.request.AgentPrincipal
	principal.AdditionalClaims = cloneAdditionalClaims(principal.AdditionalClaims)
	return principal
}

// Reference returns the non-secret pending reference.
func (value SessionInteraction) Reference() string { return value.reference }

// Method returns the original request method used to select authorization.
func (value SessionInteraction) Method() string { return value.request.Method }

// Path returns the original request path used to select authorization.
func (value SessionInteraction) Path() string { return value.request.Path }

// RequiredScopes returns an independent copy of the requested Resource scopes.
func (value SessionInteraction) RequiredScopes() []string {
	return append([]string(nil), value.request.RequiredScopes...)
}

// ExpiresAt returns the pending interaction deadline.
func (value SessionInteraction) ExpiresAt() time.Time { return value.expiresAt }

func (server *ResourceManagedServer) beginSessionInteraction(
	response http.ResponseWriter,
	request *http.Request,
	authorization SessionAuthorizationRequest,
) {
	if server.deferredSessions == nil {
		writeProblem(response, http.StatusForbidden, "interaction_unavailable", errors.New("Resource interaction is not configured"))
		return
	}
	// RFC 8941 discards a malformed Structured Field. Treat it like an absent
	// capability declaration rather than turning it into a request error.
	capabilities, _ := aauth.ParseCapabilities(request.Header.Values("AAuth-Capabilities"))
	if !slices.Contains(capabilities, "interaction") {
		writeProblem(response, http.StatusForbidden, "interaction_unavailable", errors.New("Agent did not declare interaction capability"))
		return
	}
	createdAt := server.clock.Now().UTC()
	expiresAt := createdAt.Add(server.interaction.Lifetime)
	if !expiresAt.After(createdAt) {
		writeProblem(response, http.StatusInternalServerError, "server_error", errors.New("pending session lifetime overflows"))
		return
	}
	for attempt := 0; attempt < 3; attempt++ {
		reference, code, err := server.generateSessionInteractionIdentity()
		if err != nil {
			writeProblem(response, http.StatusInternalServerError, "server_error", err)
			return
		}
		interactionURL, err := appendSessionInteractionReference(server.interaction.URL, reference)
		if err != nil {
			writeProblem(response, http.StatusInternalServerError, "server_error", err)
			return
		}
		requirement, err := aauth.FormatInteractionRequirement(aauth.InteractionRequirement{
			URL: interactionURL, Code: code,
		})
		if err != nil {
			writeProblem(response, http.StatusInternalServerError, "server_error", err)
			return
		}
		digest, err := interaction.Digest(code)
		if err != nil {
			writeProblem(response, http.StatusInternalServerError, "server_error", err)
			return
		}
		record := PendingSessionRecord{
			ID: reference, CodeSHA256: digest, Resource: server.issuer,
			Request:   cloneSessionAuthorizationRequest(authorization),
			CreatedAt: createdAt, ExpiresAt: expiresAt, RetryAfter: server.interaction.RetryAfter,
			MaximumCodeAttempts: server.interaction.MaximumCodeAttempts,
		}
		if err := server.validatePendingSessionRecord(record); err != nil {
			writeProblem(response, http.StatusInternalServerError, "server_error", err)
			return
		}
		if err := server.deferredSessions.CreatePending(request.Context(), record); err != nil {
			if errors.Is(err, ErrPendingSessionConflict) {
				continue
			}
			writeProblem(response, http.StatusInternalServerError, "server_error", err)
			return
		}
		response.Header().Set("Location", "/session/pending/"+reference)
		response.Header().Set("Retry-After", strconv.FormatInt(int64(server.interaction.RetryAfter/time.Second), 10))
		response.Header().Set("Cache-Control", "no-store")
		response.Header().Set("AAuth-Requirement", requirement)
		writeJSON(response, http.StatusAccepted, struct {
			Status string `json:"status"`
		}{Status: "pending"})
		return
	}
	writeProblem(response, http.StatusInternalServerError, "server_error", errors.New("could not allocate a unique pending session"))
}

func (server *ResourceManagedServer) generateSessionInteractionIdentity() (string, string, error) {
	server.randomMu.Lock()
	defer server.randomMu.Unlock()
	reference, err := interaction.GeneratePendingReference(server.random)
	if err != nil {
		return "", "", fmt.Errorf("resource: generate pending session reference: %w", err)
	}
	code, err := interaction.GenerateCode(server.random)
	if err != nil {
		return "", "", fmt.Errorf("resource: generate session interaction code: %w", err)
	}
	return reference, code, nil
}

func appendSessionInteractionReference(base, reference string) (string, error) {
	parsed, err := url.Parse(base)
	if err != nil {
		return "", err
	}
	parsed.Path = strings.TrimRight(parsed.Path, "/") + "/" + reference
	parsed.RawPath = ""
	return parsed.String(), nil
}

// ConsumeSessionInteractionCode correlates human-entered code with one
// pending request. The host must authenticate the person separately.
func (server *ResourceManagedServer) ConsumeSessionInteractionCode(
	ctx context.Context,
	reference string,
	code string,
) (SessionInteraction, error) {
	if server == nil || server.deferredSessions == nil {
		return SessionInteraction{}, errors.New("resource: session interactions are not configured")
	}
	if ctx == nil {
		return SessionInteraction{}, errors.New("resource: context is required")
	}
	if reference == "" {
		return SessionInteraction{}, ErrSessionInteractionCodeInvalid
	}
	digest, err := interaction.Digest(code)
	if err != nil {
		return SessionInteraction{}, ErrSessionInteractionCodeInvalid
	}
	record, err := server.deferredSessions.ConsumeInteractionCode(ctx, server.issuer, reference, digest, server.clock.Now().UTC())
	if err != nil {
		return SessionInteraction{}, err
	}
	if record.ID != reference {
		return SessionInteraction{}, ErrPendingSessionConflict
	}
	if err := server.validatePendingSessionRecord(record); err != nil {
		return SessionInteraction{}, err
	}
	return sessionInteractionFromRecord(record), nil
}

// ResumeSessionInteraction reconstructs the host handle from retained state.
func (server *ResourceManagedServer) ResumeSessionInteraction(ctx context.Context, reference string) (SessionInteraction, error) {
	if server == nil || server.deferredSessions == nil {
		return SessionInteraction{}, errors.New("resource: session interactions are not configured")
	}
	if ctx == nil {
		return SessionInteraction{}, errors.New("resource: context is required")
	}
	if reference == "" {
		return SessionInteraction{}, errors.New("resource: interaction reference is required")
	}
	snapshot, err := server.deferredSessions.LoadPending(ctx, reference)
	if err != nil {
		return SessionInteraction{}, err
	}
	if snapshot.Record.ID != reference {
		return SessionInteraction{}, ErrPendingSessionConflict
	}
	if err := server.validatePendingSessionRecord(snapshot.Record); err != nil {
		return SessionInteraction{}, err
	}
	switch snapshot.State {
	case SessionPollPending, SessionPollInteracting, SessionPollApproved, SessionPollDenied:
		return sessionInteractionFromRecord(snapshot.Record), nil
	case SessionPollExpired:
		return SessionInteraction{}, ErrPendingSessionExpired
	case SessionPollGone:
		return SessionInteraction{}, ErrPendingSessionGone
	default:
		return SessionInteraction{}, ErrPendingSessionConflict
	}
}

// ApproveSessionInteraction retains the Resource-local person and session
// before the Agent can observe the session token. Calling it requires the
// host's separately authenticated person decision.
func (server *ResourceManagedServer) ApproveSessionInteraction(
	ctx context.Context,
	value SessionInteraction,
	grant SessionGrant,
) error {
	if err := server.validateSessionInteraction(ctx, value); err != nil {
		return err
	}
	now := server.clock.Now().UTC()
	if !now.Before(value.expiresAt) {
		return ErrPendingSessionExpired
	}
	if err := server.validateSessionGrant(grant, value.request.RequiredScopes); err != nil {
		return err
	}
	record, err := server.sessionRecord(value.request.AgentPrincipal, grant, now)
	if err != nil {
		return err
	}
	approval, err := server.deferredSessions.Approve(ctx, value.reference, record, now)
	if err != nil {
		return err
	}
	return server.validateCreatedSessionApproval(approval, record, now)
}

// DenySessionInteraction retains an authenticated denial.
func (server *ResourceManagedServer) DenySessionInteraction(ctx context.Context, value SessionInteraction) error {
	if err := server.validateSessionInteraction(ctx, value); err != nil {
		return err
	}
	return server.deferredSessions.Deny(ctx, value.reference, server.clock.Now().UTC())
}

// InvalidateSessionInteraction terminally closes a pending interaction after
// host-side abuse or callback failure.
func (server *ResourceManagedServer) InvalidateSessionInteraction(ctx context.Context, value SessionInteraction) error {
	if err := server.validateSessionInteraction(ctx, value); err != nil {
		return err
	}
	return server.deferredSessions.Invalidate(ctx, value.reference, server.clock.Now().UTC())
}

func (server *ResourceManagedServer) validateSessionInteraction(ctx context.Context, value SessionInteraction) error {
	if server == nil || server.deferredSessions == nil {
		return errors.New("resource: session interactions are not configured")
	}
	if ctx == nil {
		return errors.New("resource: context is required")
	}
	if value.kind != sessionInteractionCorrelated || value.resource != server.issuer || value.reference == "" {
		return errors.New("resource: correlated session interaction is required")
	}
	return nil
}

func sessionInteractionFromRecord(record PendingSessionRecord) SessionInteraction {
	return SessionInteraction{
		kind: sessionInteractionCorrelated, resource: record.Resource, reference: record.ID,
		request: cloneSessionAuthorizationRequest(record.Request), createdAt: record.CreatedAt, expiresAt: record.ExpiresAt,
	}
}

func (server *ResourceManagedServer) serveSessionPoll(response http.ResponseWriter, request *http.Request) {
	if server.deferredSessions == nil {
		writeProblem(response, http.StatusGone, "invalid_code", ErrPendingSessionNotFound)
		return
	}
	if request.Method != http.MethodGet {
		response.Header().Set("Allow", http.MethodGet)
		writeProblem(response, http.StatusMethodNotAllowed, "method_not_allowed", errors.New("session polling requires GET"))
		return
	}
	proof, claims, err := server.verifyResourceManagedAgentRequest(request, server.additionalSignatureComponents)
	if err != nil {
		writeCredentialProblem(response, "invalid_token", err)
		return
	}
	if !claims.Confirmation.JWK.Equal(proof.PublicKey()) {
		writeProblem(response, http.StatusUnauthorized, "invalid_signature", errors.New("request key does not match agent token"))
		return
	}
	identity := SessionPollIdentity{
		Resource: server.issuer, AgentProvider: claims.Issuer, Agent: claims.Subject, ParentAgent: claims.ParentAgent,
	}
	reference := request.PathValue("id")
	if reference == "" {
		writeProblem(response, http.StatusGone, "invalid_code", ErrPendingSessionNotFound)
		return
	}
	result, err := server.deferredSessions.Poll(request.Context(), reference, identity, proof.VerifiedAt())
	if err != nil {
		switch {
		case errors.Is(err, ErrPendingSessionNotFound), errors.Is(err, ErrPendingSessionGone):
			writeProblem(response, http.StatusGone, "invalid_code", err)
		default:
			writeProblem(response, http.StatusInternalServerError, "server_error", err)
		}
		return
	}
	response.Header().Set("Cache-Control", "no-store")
	switch result.State {
	case SessionPollPending, SessionPollInteracting:
		if result.RetryAfter < 0 || result.RetryAfter%time.Second != 0 {
			writeProblem(response, http.StatusInternalServerError, "server_error", ErrPendingSessionConflict)
			return
		}
		response.Header().Set("Location", "/session/pending/"+reference)
		response.Header().Set("Retry-After", strconv.FormatInt(int64(result.RetryAfter/time.Second), 10))
		status := "pending"
		if result.State == SessionPollInteracting {
			status = "interacting"
		}
		writeJSON(response, http.StatusAccepted, struct {
			Status string `json:"status"`
		}{Status: status})
	case SessionPollApproved:
		if err := server.validateSessionApproval(result.Approval, AgentPrincipal{
			AgentProvider: claims.Issuer, Agent: claims.Subject, ParentAgent: claims.ParentAgent,
		}, nil, proof.VerifiedAt()); err != nil {
			writeProblem(response, http.StatusInternalServerError, "server_error", err)
			return
		}
		if err := server.deferredSessions.ConsumeResult(request.Context(), reference, result); err != nil {
			writeProblem(response, http.StatusInternalServerError, "server_error", err)
			return
		}
		response.Header().Set("AAuth-Access", result.Approval.Token)
		writeJSON(response, http.StatusOK, struct {
			Status string `json:"status"`
			Scope  string `json:"scope"`
		}{Status: "authorized", Scope: strings.Join(result.Approval.Record.Scope, " ")})
	case SessionPollDenied:
		if err := server.deferredSessions.ConsumeResult(request.Context(), reference, result); err != nil {
			writeProblem(response, http.StatusInternalServerError, "server_error", err)
			return
		}
		writeProblem(response, http.StatusForbidden, "denied", errors.New("session authorization was denied"))
	case SessionPollExpired:
		if err := server.deferredSessions.ConsumeResult(request.Context(), reference, result); err != nil {
			writeProblem(response, http.StatusInternalServerError, "server_error", err)
			return
		}
		writeProblem(response, http.StatusRequestTimeout, "expired", ErrPendingSessionExpired)
	case SessionPollGone:
		writeProblem(response, http.StatusGone, "invalid_code", ErrPendingSessionGone)
	default:
		writeProblem(response, http.StatusInternalServerError, "server_error", ErrPendingSessionConflict)
	}
}

func (server *ResourceManagedServer) serveSessionPendingNamespace(response http.ResponseWriter, _ *http.Request) {
	writeProblem(response, http.StatusGone, "invalid_code", ErrPendingSessionNotFound)
}

func (server *ResourceManagedServer) validatePendingSessionRecord(record PendingSessionRecord) error {
	if record.ID == "" || record.CodeSHA256 == ([32]byte{}) || record.Resource != server.issuer ||
		record.CreatedAt.IsZero() || !record.ExpiresAt.After(record.CreatedAt) ||
		record.RetryAfter < 0 || record.RetryAfter%time.Second != 0 || record.MaximumCodeAttempts <= 0 {
		return ErrPendingSessionConflict
	}
	if record.Request.Method == "" || record.Request.Path == "" || !strings.HasPrefix(record.Request.Path, "/") {
		return ErrPendingSessionConflict
	}
	if err := validateStableAgent(record.Request.AgentPrincipal); err != nil {
		return ErrPendingSessionConflict
	}
	if _, err := server.validateManagedScopes(record.Request.RequiredScopes); err != nil {
		return ErrPendingSessionConflict
	}
	return nil
}

func (server *ResourceManagedServer) validateSessionGrant(grant SessionGrant, required []string) error {
	if grant.Subject == "" || strings.TrimSpace(grant.Subject) != grant.Subject {
		return errors.New("resource: session grant subject must be nonblank without surrounding whitespace")
	}
	if grant.Lifetime <= 0 {
		return errors.New("resource: session grant lifetime must be positive")
	}
	scopes, err := server.validateManagedScopes(grant.Scope)
	if err != nil {
		return err
	}
	if !scopeSetContains(scopes, required) {
		return errors.New("resource: session grant does not cover required scopes")
	}
	return nil
}

func (server *ResourceManagedServer) sessionRecord(
	principal AgentPrincipal,
	grant SessionGrant,
	createdAt time.Time,
) (SessionRecord, error) {
	expiresAt := createdAt.Add(grant.Lifetime)
	if !expiresAt.After(createdAt) {
		return SessionRecord{}, errors.New("resource: session lifetime overflows")
	}
	return SessionRecord{
		Resource: server.issuer, AgentProvider: principal.AgentProvider,
		Agent: principal.Agent, ParentAgent: principal.ParentAgent, Subject: grant.Subject,
		Scope: append([]string(nil), grant.Scope...), CreatedAt: createdAt, ExpiresAt: expiresAt,
	}, nil
}

func (server *ResourceManagedServer) validateSessionApproval(
	approval SessionApproval,
	principal AgentPrincipal,
	required []string,
	now time.Time,
) error {
	if _, err := aauth.FormatAAuthAccess(approval.Token); err != nil {
		return err
	}
	record := approval.Record
	if record.Resource != server.issuer || record.AgentProvider != principal.AgentProvider ||
		record.Agent != principal.Agent || record.ParentAgent != principal.ParentAgent ||
		record.Subject == "" || record.CreatedAt.IsZero() || !record.ExpiresAt.After(now) {
		return errors.New("resource: session store returned an invalid approval")
	}
	scopes, err := server.validateManagedScopes(record.Scope)
	if err != nil || !scopeSetContains(scopes, required) {
		return errors.New("resource: session store returned invalid approval scopes")
	}
	return nil
}

func (server *ResourceManagedServer) validateCreatedSessionApproval(
	approval SessionApproval,
	expected SessionRecord,
	now time.Time,
) error {
	record := approval.Record
	if record.Resource != expected.Resource || record.AgentProvider != expected.AgentProvider ||
		record.Agent != expected.Agent || record.ParentAgent != expected.ParentAgent ||
		record.Subject != expected.Subject || !slices.Equal(record.Scope, expected.Scope) ||
		!record.CreatedAt.Equal(expected.CreatedAt) || !record.ExpiresAt.Equal(expected.ExpiresAt) {
		return errors.New("resource: session store did not retain the proposed approval")
	}
	return server.validateSessionApproval(approval, AgentPrincipal{
		AgentProvider: expected.AgentProvider,
		Agent:         expected.Agent,
		ParentAgent:   expected.ParentAgent,
	}, expected.Scope, now)
}

func validateStableAgent(principal AgentPrincipal) error {
	if err := aauth.ValidateServerIdentifier(principal.AgentProvider); err != nil {
		return err
	}
	if err := aauth.ValidateAgentIdentifier(principal.Agent); err != nil {
		return err
	}
	if principal.ParentAgent != "" {
		if err := aauth.ValidateAgentIdentifier(principal.ParentAgent); err != nil {
			return err
		}
	}
	return nil
}

func (server *ResourceManagedServer) validateManagedScopes(values []string) ([]string, error) {
	if len(values) == 0 {
		return nil, errors.New("resource: session requires at least one scope")
	}
	validated := make([]string, len(values))
	seen := make(map[string]struct{}, len(values))
	for index, scope := range values {
		if err := aauth.ValidateScopeValue(scope); err != nil {
			return nil, err
		}
		if _, declared := server.scopeDescriptions[scope]; !declared {
			return nil, fmt.Errorf("resource: session scope %q is not declared", scope)
		}
		if _, duplicate := seen[scope]; duplicate {
			return nil, fmt.Errorf("resource: session scope %q is duplicated", scope)
		}
		seen[scope] = struct{}{}
		validated[index] = scope
	}
	return validated, nil
}

func scopeSetContains(granted, required []string) bool {
	for _, scope := range required {
		if !slices.Contains(granted, scope) {
			return false
		}
	}
	return true
}
