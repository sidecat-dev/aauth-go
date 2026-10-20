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

// ErrFederationNotReady means a poll is premature, already running, or terminal.
var ErrFederationNotReady = errors.New("personserver: federation cannot be advanced")

// FederatedDeferredConfig enables top-level, missionless Core AS approval and
// payment continuations. Hosts settle payment and cache billing relationships
// per AS, then call AdvanceFederation explicitly. No payment is made by the
// library. R3, Budget, delegation, missions, claims and clarification are absent.
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
}

// FederatedAuthorizationRecord keeps one exact request and its continuation
// in the PS boundary. The token bytes, IDs, Location, and ExpiresAt are immutable.
// Advancing fences an external AS poll: an uncertain poll is never reclaimed.
// Terminal stores the verified result or local problem; Gone prevents replay.
type FederatedAuthorizationRecord struct {
	ID             string
	PersonServer   string
	ResourceToken  string
	AgentToken     string
	AgentIssuer    string
	Agent          string
	AgentJKT       string
	PresentedToken string
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
// Missing IDs and failed comparisons return ErrFederatedAuthorizationConflict.
// The host authenticates operators before exposing records or invoking progress.
type FederatedAuthorizationStore interface {
	CreateFederatedAuthorization(context.Context, FederatedAuthorizationRecord) error
	LoadFederatedAuthorization(context.Context, string) (FederatedAuthorizationRecord, error)
	ReplaceFederatedAuthorization(context.Context, FederatedAuthorizationRecord, FederatedAuthorizationRecord) error
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

func (server *Server) beginFederatedAuthorization(w http.ResponseWriter, r *http.Request, as *http.Response, endpoint, resourceCompact, agentCompact, presentedCompact string, agent aauth.AgentTokenClaims, resource aauth.ResourceTokenClaims, presentedExpiry time.Time) {
	state, location, retry, err := readFederatedPending(as, endpoint, "")
	if err != nil {
		writeAccessServerUnreachable(w, err)
		return
	}
	now := server.clock.Now().UTC()
	deadline := now.Add(server.federatedDeferred.Lifetime)
	for _, t := range []time.Time{time.Unix(resource.ExpiresAt, 0), time.Unix(agent.ExpiresAt, 0), presentedExpiry} {
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
	thumbprint, err := agent.Confirmation.JWK.Thumbprint()
	if err != nil {
		writeProblem(w, 500, "server_error", err)
		return
	}
	record := FederatedAuthorizationRecord{ID: base64.RawURLEncoding.EncodeToString(id), PersonServer: server.issuer, ResourceToken: resourceCompact, AgentToken: agentCompact, AgentIssuer: agent.Issuer, Agent: agent.Subject, AgentJKT: thumbprint, PresentedToken: presentedCompact, Location: location, ExpiresAt: deadline, NextPollAt: now.Add(retry), RetryAfter: retry, Revision: 1, Response: state}
	if err := server.federatedDeferred.Store.CreateFederatedAuthorization(r.Context(), record); err != nil {
		writeProblem(w, 500, "server_error", err)
		return
	}
	server.writeFederatedWaiting(w, record)
}

func readFederatedPending(response *http.Response, endpoint, prior string) (FederatedResponse, string, time.Duration, error) {
	fail := func() (FederatedResponse, string, time.Duration, error) {
		return FederatedResponse{}, "", 0, errors.New("personserver: malformed or unsupported AS continuation")
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
			if err != nil || requirement != aauth.RequirementApproval {
				return fail()
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
		next.Response = FederatedResponse{Status: buffer.status, Header: buffer.header.Clone(), Body: append([]byte(nil), buffer.body.Bytes()...)}
	}
	return server.federatedDeferred.Store.ReplaceFederatedAuthorization(ctx, record, next)
}
func (server *Server) advanceFederatedRequest(ctx context.Context, record FederatedAuthorizationRecord, out *federatedResponseBuffer) {
	agent, err := aauth.VerifyAgentToken(ctx, record.AgentToken, server.keyResolver, server.clock)
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
	if server.agentTokenRevocations != nil {
		revoked, err := server.agentTokenRevocations.IsRevoked(ctx, aauth.TokenReference{Issuer: agent.Issuer, JTI: agent.JTI})
		if err != nil {
			writeProblem(out, 500, "server_error", err)
			return
		}
		if revoked {
			writeProblem(out, 403, "revoked", nil)
			return
		}
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
			writeAccessServerUnreachable(out, err)
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
	server.deliverFederatedAuthorization(out, request, response, resource, agent, agent, presented.ExpiresAt, scopes, nil, nil, nil, nil, AuthorizationRequest{})
}
func (server *Server) writeFederatedWaiting(w http.ResponseWriter, record FederatedAuthorizationRecord) {
	w.Header().Set("Location", strings.TrimRight(server.issuer, "/")+"/token/federated/"+record.ID)
	w.Header().Set("Retry-After", "5")
	w.Header().Set("AAuth-Requirement", "requirement=approval")
	writePrivateJSON(w, 202, map[string]string{"status": "pending"})
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
			writeProblem(w, 410, "invalid_code", err)
		} else {
			writeProblem(w, 500, "server_error", err)
		}
		return
	}
	thumbprint, err := agent.Confirmation.JWK.Thumbprint()
	if err != nil || agent.Issuer != record.AgentIssuer || agent.Subject != record.Agent || agent.PersonServer != server.issuer || thumbprint != record.AgentJKT {
		writeProblem(w, 403, "denied", errors.New("pending request belongs to another Agent or key"))
		return
	}

	if record.Gone {
		writeProblem(w, 410, "invalid_code", nil)
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
			writeProblem(w, 500, "server_error", err)
			return
		}
		buffer.send(w)
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
			writeProblem(w, 410, "invalid_code", err)
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
}

// An AS grant may expire or cease to verify between the host's AS poll and
// Agent delivery. Reuse the immediate delivery checks at the actual release.
func (server *Server) recheckFederatedDelivery(w http.ResponseWriter, r *http.Request, record FederatedAuthorizationRecord) {
	agent, err := aauth.VerifyAgentToken(r.Context(), record.AgentToken, server.keyResolver, server.clock)
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
	if server.agentTokenRevocations != nil {
		revoked, err := server.agentTokenRevocations.IsRevoked(r.Context(), aauth.TokenReference{Issuer: agent.Issuer, JTI: agent.JTI})
		if err != nil {
			writeProblem(w, 500, "server_error", err)
			return
		}
		if revoked {
			writeProblem(w, 403, "revoked", nil)
			return
		}
	}
	response := &http.Response{StatusCode: 200, Header: record.Response.Header, Body: io.NopCloser(bytes.NewReader(record.Response.Body))}
	server.deliverFederatedAuthorization(w, r, response, resource, agent, agent, presented.ExpiresAt, scopes, nil, nil, nil, nil, AuthorizationRequest{})
}

type federatedResponseBuffer struct {
	header  http.Header
	status  int
	body    bytes.Buffer
	pending *FederatedResponse
	retry   time.Duration
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
func (b *federatedResponseBuffer) send(w http.ResponseWriter) {
	for k, v := range b.header {
		w.Header()[k] = append([]string(nil), v...)
	}
	w.WriteHeader(b.status)
	_, _ = w.Write(b.body.Bytes())
}
