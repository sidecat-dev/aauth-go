package personserver

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/internal/httpapi"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

// ErrFederatedAuthorizationConflict reports a missing record or competing update.
var ErrFederatedAuthorizationConflict = errors.New("personserver: federated authorization conflict")

// DeferredCompositionError identifies a local PS configuration or request
// composition that cannot retain an AS continuation. It is available through
// diagnostics.Handler with errors.As; the wire response is 500 server_error
// with a public explanation, not a federation reachability error.
type DeferredCompositionError struct{ reason string }

// Reason returns not_configured, r3, budget, mission, claims, clarification,
// interaction or requirement (an unsupported extension). A mixed-capability
// PS may still defer a missionless Core request, top-level or parent-mediated.
func (e *DeferredCompositionError) Reason() string {
	if e == nil {
		return ""
	}
	return e.reason
}
func (e *DeferredCompositionError) Error() string {
	switch e.Reason() {
	case "not_configured":
		return "personserver: deferred AS authorization is not configured"
	case "r3":
		return "personserver: deferred AS authorization does not support R3 requests"
	case "budget":
		return "personserver: deferred AS authorization does not support Budget requests"
	case "mission":
		return "personserver: deferred AS authorization does not support mission-bound requests"
	case "claims", "clarification", "interaction":
		return "personserver: deferred AS authorization does not support " + e.Reason() + " requirements"
	case "requirement":
		return "personserver: deferred AS authorization supports only approval and payment requirements"
	default:
		return "personserver: unsupported deferred AS authorization composition"
	}
}

// ErrFederationNotReady means a poll is premature, already running, or terminal.
var ErrFederationNotReady = errors.New("personserver: federation cannot be advanced")

// FederatedDeferredConfig enables missionless Core AS approval and payment
// continuations, top-level or parent-mediated for a one-level sub-agent. Hosts
// settle payment and cache billing relationships per AS, then call
// AdvanceFederation explicitly. No payment is made by the library. R3, Budget,
// missions, claims and clarification are absent.
type FederatedDeferredConfig struct {
	Store    FederatedAuthorizationStore
	Lifetime time.Duration
}

// FederatedResponse is the bounded AS response for host inspection. Header and
// Body may contain untrusted payment-protocol data. A terminal 200 is retained
// only after normal Auth-token verification. Payment details never reach Agent.
type FederatedResponse struct {
	Status int
	Header http.Header
	Body   []byte
	// RefusalReason retains a local DeferredCompositionError reason for terminal
	// 500 responses. Adapters preserve it with the response; no Go error or
	// untrusted AS cause is serialized. Agent delivery reports the typed cause.
	RefusalReason string
}

// FederatedAuthorizationRecord keeps one exact request and its continuation
// in the PS boundary. The token bytes, IDs, Location, and ExpiresAt are immutable.
// Advancing fences an external AS poll: an uncertain poll is never reclaimed.
// Terminal stores the verified result or local problem; Gone prevents replay.
// AgentIssuer, Agent and AgentJKT name the Agent that signed the request and
// alone may poll; for a parent-mediated request that is the parent, and
// SubagentToken holds the exact sub-agent token the grant is bound to.
type FederatedAuthorizationRecord struct {
	ID             string
	PersonServer   string
	ResourceToken  string
	AgentToken     string
	AgentIssuer    string
	Agent          string
	AgentJKT       string
	PresentedToken string
	SubagentToken  string
	Location       string
	ExpiresAt      time.Time
	RetryAfter     time.Duration
	NextPollAt     time.Time
	Revision       uint64
	Advancing      bool
	Terminal       bool
	Gone           bool
	Response       FederatedResponse
}

// FederatedAuthorizationStore owns only PS-to-AS continuation state. Create
// rejects duplicate IDs. Load returns independent copies. Replace atomically
// compares the complete previous record, preserves immutable fields, increments
// Revision by one, and never reopens Gone or replaces a terminal response.
// Create, Load and Replace preserve the complete Response, including RefusalReason,
// so a persisted local refusal retains its typed diagnostic on Agent delivery.
// Missing IDs and failed comparisons return ErrFederatedAuthorizationConflict.
// The host authenticates operators before exposing records or invoking progress.
type FederatedAuthorizationStore interface {
	CreateFederatedAuthorization(context.Context, FederatedAuthorizationRecord) error
	LoadFederatedAuthorization(context.Context, string) (FederatedAuthorizationRecord, error)
	ReplaceFederatedAuthorization(context.Context, FederatedAuthorizationRecord, FederatedAuthorizationRecord) error
}

func writeFederatedContinuationProblem(w http.ResponseWriter, err error) {
	var refusal *DeferredCompositionError
	if errors.As(err, &refusal) {
		w.Header().Set("Cache-Control", "no-store")
		httpapi.WriteProblem(w, http.StatusInternalServerError, "server_error", refusal, httpapi.ProblemFields{Detail: refusal.Error()})
		return
	}
	writeAccessServerUnreachable(w, err)
}

func validateFederatedDeferredConfig(c *FederatedDeferredConfig) error {
	if c != nil && (c.Store == nil || c.Lifetime <= 0 || c.Lifetime > time.Hour) {
		return errors.New("personserver: federated store and lifetime in (0,1h] are required")
	}
	return nil
}

// FederatedAuthorization loads one host-side continuation. Its reference is
// the last segment of the Agent's PS pending URL. A reference is correlation,
// never host authentication or authority to settle a payment.
func (server *Server) FederatedAuthorization(ctx context.Context, reference string) (FederatedAuthorizationRecord, error) {
	if server.federatedDeferred == nil {
		return FederatedAuthorizationRecord{}, ErrFederationNotReady
	}
	record, err := server.federatedDeferred.Store.LoadFederatedAuthorization(ctx, reference)
	if err == nil && (record.ID != reference || record.PersonServer != server.issuer) {
		return FederatedAuthorizationRecord{}, ErrFederatedAuthorizationConflict
	}
	return record, err
}

// federatedContinuationInput is the verified request a PS continuation retains.
// agent signed the request; credentialAgent holds the credentials and equals
// agent unless subagentToken is set.
type federatedContinuationInput struct {
	resourceToken, agentToken, presentedToken, subagentToken string
	agent, credentialAgent                                   aauth.AgentTokenClaims
	resource                                                 aauth.ResourceTokenClaims
	presentedExpiresAt                                       time.Time
}

func (server *Server) beginFederatedAuthorization(w http.ResponseWriter, r *http.Request, as *http.Response, endpoint string, input federatedContinuationInput) {
	state, location, retry, err := readFederatedPending(as, endpoint, "")
	if err != nil {
		writeFederatedContinuationProblem(w, err)
		return
	}
	now := server.clock.Now().UTC()
	deadline := now.Add(server.federatedDeferred.Lifetime)
	for _, t := range []time.Time{
		time.Unix(input.resource.ExpiresAt, 0), time.Unix(input.agent.ExpiresAt, 0),
		time.Unix(input.credentialAgent.ExpiresAt, 0), input.presentedExpiresAt,
	} {
		if t.Before(deadline) {
			deadline = t
		}
	}
	if !now.Before(deadline) {
		writeProblem(w, 408, "expired", nil)
		return
	}
	id := make([]byte, 32)
	if _, err := rand.Read(id); err != nil {
		writeProblem(w, 500, "server_error", err)
		return
	}
	thumbprint, err := input.agent.Confirmation.JWK.Thumbprint()
	if err != nil {
		writeProblem(w, 500, "server_error", err)
		return
	}
	record := FederatedAuthorizationRecord{
		ID: base64.RawURLEncoding.EncodeToString(id), PersonServer: server.issuer, ResourceToken: input.resourceToken,
		AgentToken: input.agentToken, AgentIssuer: input.agent.Issuer, Agent: input.agent.Subject, AgentJKT: thumbprint,
		PresentedToken: input.presentedToken, SubagentToken: input.subagentToken, Location: location,
		ExpiresAt: deadline, NextPollAt: now.Add(retry), RetryAfter: retry, Revision: 1, Response: state,
	}
	if err := server.federatedDeferred.Store.CreateFederatedAuthorization(r.Context(), record); err != nil {
		writeProblem(w, 500, "server_error", err)
		return
	}
	server.writeFederatedWaiting(w, record)
}

func readFederatedPending(response *http.Response, endpoint, prior string) (FederatedResponse, string, time.Duration, error) {
	fail := func() (FederatedResponse, string, time.Duration, error) {
		return FederatedResponse{}, "", 0, errors.New("personserver: malformed AS continuation")
	}
	if response.StatusCode != 202 && response.StatusCode != 402 {
		return fail()
	}
	if len(response.Header.Values("Location")) != 1 {
		return fail()
	}
	base, err := url.Parse(endpoint)
	if err != nil || base.Scheme != "https" || base.Host == "" {
		return fail()
	}
	ref, err := url.Parse(response.Header.Get("Location"))
	if err != nil || ref.String() == "" {
		return fail()
	}
	location := base.ResolveReference(ref)
	if location.Scheme != base.Scheme || location.Host != base.Host || location.User != nil || location.Fragment != "" || prior != "" && location.String() != prior {
		return fail()
	}
	retry := 5 * time.Second
	if values := response.Header.Values("Retry-After"); len(values) > 0 {
		if len(values) != 1 {
			return fail()
		}
		n, err := strconv.ParseUint(values[0], 10, 32)
		if err != nil || n > 3600 {
			return fail()
		}
		retry = time.Duration(n) * time.Second
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxRequestBytes+1))
	if err != nil || len(body) > maxRequestBytes {
		return fail()
	}
	if response.StatusCode == 202 {
		noStore := false
		for _, v := range strings.Split(response.Header.Get("Cache-Control"), ",") {
			if strings.EqualFold(strings.TrimSpace(v), "no-store") {
				noStore = true
			}
		}
		media, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
		if err != nil || media != "application/json" || !noStore {
			return fail()
		}
		var input struct {
			Status string `json:"status"`
		}
		if decodeJSON(bytes.NewReader(body), &input) != nil || input.Status == "" {
			return fail()
		}
		if len(response.Header.Values("AAuth-Requirement")) != 0 {
			requirement, err := aauth.ParseRequirement(response.Header.Values("AAuth-Requirement"))
			if err != nil {
				return fail()
			}
			if requirement != aauth.RequirementApproval {
				reason := "requirement"
				switch requirement {
				case aauth.RequirementClaims, aauth.RequirementClarification, aauth.RequirementInteraction:
					reason = string(requirement)
				}
				return FederatedResponse{}, "", 0, &DeferredCompositionError{reason: reason}
			}
		}
	} else {
		if len(response.Header.Values("WWW-Authenticate")) != 1 || response.Header.Get("WWW-Authenticate") == "" {
			return fail()
		}
	}
	return FederatedResponse{Status: response.StatusCode, Header: response.Header.Clone(), Body: append([]byte(nil), body...)}, location.String(), retry, nil
}

// AdvanceFederation performs at most one bodyless PS-signed AS GET. The host
// calls it only after settling a payment, or when an approval wait is due.
// Retry-After is enforced. It never replays the original POST or follows a
// redirect. Agent polls observe retained state; they do not call the AS.
// A process loss or store failure during an AS call leaves Advancing fenced
// until expiry: the external result may have been consumed, so no retry is safe.
func (server *Server) AdvanceFederation(ctx context.Context, reference string) error {
	record, err := server.FederatedAuthorization(ctx, reference)
	if err != nil {
		return err
	}
	now := server.clock.Now().UTC()
	if record.Terminal || record.Gone || record.Advancing || now.Before(record.NextPollAt) {
		return ErrFederationNotReady
	}
	next := record
	next.Revision++
	next.Advancing = true
	if err := server.federatedDeferred.Store.ReplaceFederatedAuthorization(ctx, record, next); err != nil {
		return err
	}
	record = next
	buffer := newFederatedResponseBuffer()
	if !now.Before(record.ExpiresAt) {
		writeProblem(buffer, 408, "expired", nil)
	} else {
		server.advanceFederatedRequest(ctx, record, buffer)
	}
	next = record
	next.Revision++
	next.Advancing = false
	if buffer.pending != nil {
		next.Response = *buffer.pending
		next.RetryAfter = buffer.retry
		next.NextPollAt = server.clock.Now().UTC().Add(buffer.retry)
	} else {
		next.Terminal = true
		next.Response = FederatedResponse{Status: buffer.status, Header: buffer.header.Clone(), Body: append([]byte(nil), buffer.body.Bytes()...), RefusalReason: buffer.refusalReason}
	}
	return server.federatedDeferred.Store.ReplaceFederatedAuthorization(ctx, record, next)
}
func (server *Server) advanceFederatedRequest(ctx context.Context, record FederatedAuthorizationRecord, out *federatedResponseBuffer) {
	agent, credential, err := server.verifyFederatedAgents(ctx, record)
	if err != nil {
		writeProblem(out, 408, "expired", err)
		return
	}
	resource, err := aauth.VerifyResourceToken(ctx, record.ResourceToken, server.keyResolver, server.clock)
	if err != nil {
		writeProblem(out, 408, "expired", err)
		return
	}
	presented, err := aauth.VerifyPresentedToken(ctx, record.PresentedToken, resource, server.keyResolver, server.clock)
	if err != nil {
		writeProblem(out, 408, "expired", err)
		return
	}
	// A revoked token or binding ends the wait here, without presenting the
	// retained request to the AS again.
	if err := server.checkFederatedRevocations(ctx, agent, credential); err != nil {
		writeFederatedRevocationProblem(out, err)
		return
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, record.Location, nil)
	if err != nil {
		writeAccessServerUnreachable(out, err)
		return
	}
	if err := signaturekey.SignJWKSURIRequest(request, server.signingKey, server.issuer, aauth.PersonDiscoveryDocument, server.clock); err != nil {
		writeProblem(out, 500, "server_error", err)
		return
	}
	response, err := server.httpClient.Do(request)
	if err != nil {
		writeAccessServerUnreachable(out, err)
		return
	}
	defer response.Body.Close()
	if response.StatusCode == 429 || response.StatusCode == 503 {
		retry := 5 * time.Second
		if response.StatusCode == 429 {
			if record.RetryAfter < 0 || record.RetryAfter > time.Hour {
				writeAccessServerUnreachable(out, errors.New("invalid retained retry interval"))
				return
			}
			retry = record.RetryAfter + 5*time.Second
		}
		if values := response.Header.Values("Retry-After"); len(values) > 0 {
			delay, ok := httpapi.ParseRetryAfter(values, server.clock.Now())
			if !ok || delay > time.Hour {
				writeAccessServerUnreachable(out, errors.New("invalid Retry-After"))
				return
			}
			if delay > retry {
				retry = delay
			}
		}

		body, err := io.ReadAll(io.LimitReader(response.Body, maxRequestBytes+1))
		if err != nil || len(body) > maxRequestBytes {
			writeAccessServerUnreachable(out, errors.New("invalid temporary AS response"))
			return
		}
		header := response.Header.Clone()

		out.pending = &FederatedResponse{Status: response.StatusCode, Header: header, Body: body}
		out.retry = retry
		return
	}
	if response.StatusCode == 202 || response.StatusCode == 402 {
		pending, _, retry, err := readFederatedPending(response, record.Location, record.Location)
		if err != nil {
			writeFederatedContinuationProblem(out, err)
			return
		}
		out.pending = &pending
		out.retry = retry
		return
	}
	if response.StatusCode != 200 {
		if !relayAccessServerProblem(out, response) {
			writeAccessServerUnreachable(out, errors.New("access server returned no well-formed terminal error"))
		}
		return
	}
	scopes, err := aauth.ParseScope(resource.Scope)
	if err != nil {
		writeAccessServerUnreachable(out, err)
		return
	}
	server.deliverFederatedAuthorization(out, request, response, resource, agent, credential, presented.ExpiresAt, scopes, nil, nil, nil, nil, AuthorizationRequest{})
}

// verifyFederatedAgents reverifies the retained Agent tokens at the current
// instant. credential is the parent itself for a top-level request, or the
// sub-agent whose relationship to that parent is checked again.
func (server *Server) verifyFederatedAgents(ctx context.Context, record FederatedAuthorizationRecord) (aauth.AgentTokenClaims, aauth.AgentTokenClaims, error) {
	agent, err := aauth.VerifyAgentToken(ctx, record.AgentToken, server.keyResolver, server.clock)
	if err != nil {
		return aauth.AgentTokenClaims{}, aauth.AgentTokenClaims{}, err
	}
	if record.SubagentToken == "" {
		return agent, agent, nil
	}
	child, err := aauth.VerifySubagentToken(ctx, record.SubagentToken, agent, server.keyResolver, server.clock)
	if err != nil {
		return aauth.AgentTokenClaims{}, aauth.AgentTokenClaims{}, err
	}
	return agent, child, nil
}

// revokedPendingTokenError names which Agent token of a waiting request its
// Agent Provider revoked; Polling Error Codes asks detail to say which.
type revokedPendingTokenError struct{ detail string }

func (failure *revokedPendingTokenError) Error() string { return "personserver: " + failure.detail }

// checkFederatedRevocations applies the Agent Provider's revocations to the
// parent and any sub-agent token, then the parent's binding.
func (server *Server) checkFederatedRevocations(ctx context.Context, agent, credential aauth.AgentTokenClaims) error {
	if server.agentTokenRevocations != nil {
		for _, token := range []aauth.AgentTokenClaims{agent, credential} {
			revoked, err := server.agentTokenRevocations.IsRevoked(ctx, aauth.TokenReference{Issuer: token.Issuer, JTI: token.JTI})
			if err != nil {
				return &agentTokenRevocationStoreError{cause: err}
			}
			if revoked {
				if token.ParentAgent != "" {
					return &revokedPendingTokenError{detail: "The sub-agent token of this request was revoked."}
				}
				return &revokedPendingTokenError{detail: "The Agent token that started this request was revoked."}
			}
		}
	}
	return server.checkAgentBinding(ctx, agentBinding(agent))
}

// writeFederatedRevocationProblem answers a pending request whose Agent token
// was revoked with polling error revoked, and a revoked binding as the
// synchronous request would be answered, revoked_presented_token.
func writeFederatedRevocationProblem(w http.ResponseWriter, err error) {
	var revoked *revokedPendingTokenError
	switch {
	case errors.As(err, &revoked):
		w.Header().Set("Cache-Control", "no-store")
		httpapi.WriteProblem(w, http.StatusForbidden, "revoked", err, httpapi.ProblemFields{Detail: revoked.detail})
	case errors.Is(err, ErrAgentBindingRevoked):
		writeProblem(w, http.StatusBadRequest, "revoked_presented_token", err)
	default:
		writeProblem(w, http.StatusInternalServerError, "server_error", err)
	}
}
func (server *Server) writeFederatedWaiting(w http.ResponseWriter, record FederatedAuthorizationRecord) {
	w.Header().Set("Location", strings.TrimRight(server.issuer, "/")+"/token/federated/"+record.ID)
	remaining := record.NextPollAt.Sub(server.clock.Now())
	seconds := int64(0)
	if remaining > 0 {
		seconds = int64(remaining / time.Second)
		if remaining%time.Second != 0 {
			seconds++
		}
	}
	w.Header().Set("Retry-After", strconv.FormatInt(seconds, 10))
	w.Header().Set("AAuth-Requirement", "requirement=approval")
	body := map[string]string{"status": "pending"}
	switch record.Response.Status {
	case http.StatusPaymentRequired:
		body["pending_reason"] = "awaiting_payment"
	case http.StatusAccepted:
		body["pending_reason"] = "awaiting_approval"
	}
	writePrivateJSON(w, 202, body)
}
func (server *Server) handleFederatedPending(w http.ResponseWriter, r *http.Request) {
	_, agent, _, err := server.verifyAgentProof(r, nil)
	if err != nil {
		writeAgentTokenProblem(w, err)
		return
	}
	if !requestBodyIsEmpty(r) {
		writeProblem(w, 400, "invalid_request", errors.New("poll must be bodyless"))
		return
	}
	record, err := server.FederatedAuthorization(r.Context(), r.PathValue("id"))
	if err != nil {
		if errors.Is(err, ErrFederatedAuthorizationConflict) {
			writeProblem(w, 410, "unknown_request", err)
		} else {
			writeProblem(w, 500, "server_error", err)
		}
		return
	}
	thumbprint, err := agent.Confirmation.JWK.Thumbprint()
	if err != nil || agent.Issuer != record.AgentIssuer || agent.Subject != record.Agent || agent.PersonServer != server.issuer || thumbprint != record.AgentJKT {
		writeProblem(w, 403, "wrong_poller", errors.New("pending request belongs to another Agent or key"))
		return
	}

	if record.Gone {
		writeProblem(w, 410, "request_consumed", nil)
		return
	}
	if !server.clock.Now().Before(record.ExpiresAt) {
		// Even a retained grant is withheld after its original credential deadline.
		buffer := newFederatedResponseBuffer()
		writeProblem(buffer, 408, "expired", nil)
		next := record
		next.Revision++
		next.Gone = true
		if err := server.federatedDeferred.Store.ReplaceFederatedAuthorization(r.Context(), record, next); err != nil {
			if errors.Is(err, ErrFederatedAuthorizationConflict) {
				writeProblem(w, 410, "request_consumed", err)
			} else {
				writeProblem(w, 500, "server_error", err)
			}
			return
		}
		buffer.send(w)
		return
	}
	if err := server.checkAgentBinding(r.Context(), AgentBinding{AgentProvider: record.AgentIssuer, Agent: record.Agent}); err != nil {
		if !errors.Is(err, ErrAgentBindingRevoked) {
			writeProblem(w, http.StatusInternalServerError, "server_error", err)
			return
		}
		// The parent's binding authorized this wait and any retained grant.
		next := record
		next.Revision++
		next.Gone = true
		if replaceErr := server.federatedDeferred.Store.ReplaceFederatedAuthorization(r.Context(), record, next); replaceErr != nil {
			if errors.Is(replaceErr, ErrFederatedAuthorizationConflict) {
				writeProblem(w, 410, "request_consumed", replaceErr)
			} else {
				writeProblem(w, 500, "server_error", replaceErr)
			}
			return
		}
		writeProblem(w, http.StatusBadRequest, "revoked_presented_token", err)
		return
	}
	if !record.Terminal {
		server.writeFederatedWaiting(w, record)
		return
	}
	delivery := record.Response
	if delivery.Status == http.StatusOK {
		checked := newFederatedResponseBuffer()
		server.recheckFederatedDelivery(checked, r, record)
		delivery = FederatedResponse{Status: checked.status, Header: checked.header, Body: checked.body.Bytes()}
	}
	// Key resolution may outlast the continuation even when the grant is valid.
	if !server.clock.Now().Before(record.ExpiresAt) {
		expired := newFederatedResponseBuffer()
		writeProblem(expired, http.StatusRequestTimeout, "expired", nil)
		delivery = FederatedResponse{Status: expired.status, Header: expired.header, Body: expired.body.Bytes()}
	}
	next := record
	next.Revision++
	next.Gone = true
	if err := server.federatedDeferred.Store.ReplaceFederatedAuthorization(r.Context(), record, next); err != nil {
		if errors.Is(err, ErrFederatedAuthorizationConflict) {
			writeProblem(w, 410, "request_consumed", err)
		} else {
			writeProblem(w, 500, "server_error", err)
		}
		return
	}
	for k, v := range delivery.Header {
		w.Header()[k] = append([]string(nil), v...)
	}
	w.WriteHeader(delivery.Status)
	_, _ = w.Write(delivery.Body)
	if delivery.Status == http.StatusInternalServerError && delivery.RefusalReason != "" {
		httpapi.ReportProblem(w, delivery.Status, "server_error", &DeferredCompositionError{reason: delivery.RefusalReason})
	}
}

// An AS grant may expire or cease to verify between the host's AS poll and
// Agent delivery. Reuse the immediate delivery checks at the actual release.
func (server *Server) recheckFederatedDelivery(w http.ResponseWriter, r *http.Request, record FederatedAuthorizationRecord) {
	agent, credential, err := server.verifyFederatedAgents(r.Context(), record)
	if err != nil {
		writeAccessServerUnreachable(w, err)
		return
	}
	resource, err := aauth.VerifyResourceToken(r.Context(), record.ResourceToken, server.keyResolver, server.clock)
	if err != nil {
		writeAccessServerUnreachable(w, err)
		return
	}
	presented, err := aauth.VerifyPresentedToken(r.Context(), record.PresentedToken, resource, server.keyResolver, server.clock)
	if err != nil {
		writeAccessServerUnreachable(w, err)
		return
	}
	scopes, err := aauth.ParseScope(resource.Scope)
	if err != nil {
		writeAccessServerUnreachable(w, err)
		return
	}
	if err := server.checkFederatedRevocations(r.Context(), agent, credential); err != nil {
		writeFederatedRevocationProblem(w, err)
		return
	}
	response := &http.Response{StatusCode: 200, Header: record.Response.Header, Body: io.NopCloser(bytes.NewReader(record.Response.Body))}
	server.deliverFederatedAuthorization(w, r, response, resource, agent, credential, presented.ExpiresAt, scopes, nil, nil, nil, nil, AuthorizationRequest{})
}

// handleFederatedCancellation lets the Agent that started a federated wait
// withdraw it. The PS consumes its continuation first, so nothing retained
// can be delivered afterwards, then sends the AS one signed DELETE for a
// request still waiting there. The AS answer does not change the Agent's
// result: an AS that misses it retains the request only until its deadline.
func (server *Server) handleFederatedCancellation(w http.ResponseWriter, r *http.Request) {
	_, agent, _, err := server.verifyAgentProof(r, nil)
	if err != nil {
		writeAgentTokenProblem(w, err)
		return
	}
	if !requestBodyIsEmpty(r) {
		writeProblem(w, 400, "invalid_request", errors.New("cancellation must be bodyless"))
		return
	}
	record, err := server.FederatedAuthorization(r.Context(), r.PathValue("id"))
	if err != nil {
		if errors.Is(err, ErrFederatedAuthorizationConflict) {
			writeProblem(w, 410, "unknown_request", err)
		} else {
			writeProblem(w, 500, "server_error", err)
		}
		return
	}
	thumbprint, err := agent.Confirmation.JWK.Thumbprint()
	if err != nil || agent.Issuer != record.AgentIssuer || agent.Subject != record.Agent || agent.PersonServer != server.issuer || thumbprint != record.AgentJKT {
		writeProblem(w, 403, "wrong_poller", errors.New("pending request belongs to another Agent or key"))
		return
	}
	if record.Gone {
		writeProblem(w, 410, "request_consumed", nil)
		return
	}
	next := record
	next.Revision++
	next.Gone = true
	if err := server.federatedDeferred.Store.ReplaceFederatedAuthorization(r.Context(), record, next); err != nil {
		if errors.Is(err, ErrFederatedAuthorizationConflict) {
			writeProblem(w, 410, "request_consumed", err)
		} else {
			writeProblem(w, 500, "server_error", err)
		}
		return
	}
	if !record.Terminal {
		server.cancelAccessServerRequest(r.Context(), record)
	}
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
}

func (server *Server) cancelAccessServerRequest(ctx context.Context, record FederatedAuthorizationRecord) {
	request, err := http.NewRequestWithContext(ctx, http.MethodDelete, record.Location, nil)
	if err != nil {
		return
	}
	if err := signaturekey.SignJWKSURIRequest(request, server.signingKey, server.issuer, aauth.PersonDiscoveryDocument, server.clock); err != nil {
		return
	}
	response, err := server.httpClient.Do(request)
	if err != nil {
		return
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, maxRequestBytes))
	_ = response.Body.Close()
}

type federatedResponseBuffer struct {
	header        http.Header
	status        int
	body          bytes.Buffer
	pending       *FederatedResponse
	retry         time.Duration
	refusalReason string
}

func newFederatedResponseBuffer() *federatedResponseBuffer {
	return &federatedResponseBuffer{header: make(http.Header)}
}
func (b *federatedResponseBuffer) Header() http.Header { return b.header }
func (b *federatedResponseBuffer) WriteHeader(s int) {
	if b.status == 0 {
		b.status = s
	}
}
func (b *federatedResponseBuffer) Write(p []byte) (int, error) {
	if b.status == 0 {
		b.status = 200
	}
	return b.body.Write(p)
}

// Retain only the bounded local refusal, never arbitrary private causes.
func (b *federatedResponseBuffer) ReportAAuthProblem(status int, code string, cause error) {
	var refusal *DeferredCompositionError
	if status == http.StatusInternalServerError && code == "server_error" && errors.As(cause, &refusal) {
		b.refusalReason = refusal.Reason()
	}
}
func (b *federatedResponseBuffer) send(w http.ResponseWriter) {
	for k, v := range b.header {
		w.Header()[k] = append([]string(nil), v...)
	}
	w.WriteHeader(b.status)
	_, _ = w.Write(b.body.Bytes())
}
