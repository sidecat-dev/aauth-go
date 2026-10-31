package accessserver

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

// ErrPendingAuthorizationConflict reports a missing record or competing update.
var ErrPendingAuthorizationConflict = errors.New("accessserver: pending authorization conflict")

// DeferredConfig enables bounded approval, payment, and claims waits for Core
// requests, missionless or mission-bound, top-level, parent-mediated or
// chained. It does not forward interaction or clarification.
type DeferredConfig struct {
	Store    DeferredAuthorizationStore
	Lifetime time.Duration
}

// PaymentChallenge carries a host's WWW-Authenticate payment challenge. The
// host implements settlement and remembers billing relationships per PS;
// Authorize must only inspect that state, never charge a payment on a poll.
// Body is opaque payment-protocol content, paired with ContentType when present.
type PaymentChallenge struct {
	Authenticate string
	ContentType  string
	Body         []byte
}

// PendingDecision requests approval (Payment nil and no RequiredClaims), payment,
// or claims before issuance. RetryAfter is a whole nonnegative number of seconds.
// The host's next policy result may change payment or claims to approval at the
// same pending URL. RequiredClaims names the claims the Person Server must post.
// sub is never a legal name: the Access Server must not request it.
type PendingDecision struct {
	RetryAfter     time.Duration
	Payment        *PaymentChallenge
	RequiredClaims []string
}

// PendingAuthorizationRecord retains the exact token request and its verified
// PS identity. Deadline and request are immutable. Revision starts at one;
// replacement increments it. Gone is irreversible. Concurrent polls may each
// evaluate policy and sign a token before the replacement comparison. Only the
// winning replacement publishes its buffered response; losing tokens are not
// released. This is a publication fence, not exactly-once policy execution.
type PendingAuthorizationRecord struct {
	ID             string
	PersonServer   string
	Request        []byte
	ExpiresAt      time.Time
	NextPollAt     time.Time
	Revision       uint64
	Gone           bool
	RequiredClaims []string
	// Claims holds the values posted for RequiredClaims. A replacement may
	// change Claims and RequiredClaims. ID, PersonServer, Request, and
	// ExpiresAt stay immutable.
	Claims map[string]json.RawMessage
}

// DeferredAuthorizationStore is AS-owned pending token state. Create must
// reject duplicate IDs. Stored slices must not alias caller-owned memory. Load
// returns an independent copy. Replace
// atomically compares the complete previous record, preserves ID, PersonServer,
// Request and ExpiresAt, increments Revision, and never reopens Gone. Claims
// and RequiredClaims may change. A conflict
// or missing ID returns ErrPendingAuthorizationConflict. No HTTP response may
// be published until its corresponding replacement succeeds.
type DeferredAuthorizationStore interface {
	CreateAccessAuthorization(context.Context, PendingAuthorizationRecord) error
	LoadAccessAuthorization(context.Context, string) (PendingAuthorizationRecord, error)
	ReplaceAccessAuthorization(context.Context, PendingAuthorizationRecord, PendingAuthorizationRecord) error
}

func validateDeferredConfig(c *DeferredConfig) error {
	if c != nil && (c.Store == nil || c.Lifetime <= 0 || c.Lifetime > time.Hour) {
		return errors.New("accessserver: deferred store and lifetime in (0,1h] are required")
	}
	return nil
}
func cloneDeferredConfig(c *DeferredConfig) *DeferredConfig {
	if c == nil {
		return nil
	}
	v := *c
	return &v
}
func validPendingDecision(d Decision) bool {
	p := d.Pending
	if p == nil || len(d.Scopes) != 0 || d.Lifetime != 0 || d.Budget != nil || p.RetryAfter < 0 || p.RetryAfter > time.Hour || p.RetryAfter%time.Second != 0 {
		return false
	}
	if !validRequiredClaimNames(p.RequiredClaims) || (p.Payment != nil && len(p.RequiredClaims) > 0) {
		return false
	}
	if p.Payment == nil {
		return true
	}
	c := p.Payment
	return c.Authenticate != "" && len(c.Authenticate) <= 8192 && !strings.ContainsAny(c.Authenticate, "\r\n") && len(c.Body) <= maxRequestBytes && !strings.ContainsAny(c.ContentType, "\r\n") && (len(c.Body) == 0 || c.ContentType != "")
}

// deferAuthorization retains the exact verified request. credentialExpiresAt
// is the earlier of the parent and any sub-agent token expiry, so a wait never
// outlasts either Agent token.
func (server *Server) deferAuthorization(w http.ResponseWriter, r *http.Request, ps string, encoded []byte, resource aauth.ResourceTokenClaims, credentialExpiresAt time.Time, presented aauth.PresentedToken, decision Decision, prior *PendingAuthorizationRecord) {
	if server.deferred == nil || !validPendingDecision(decision) {
		writeProblem(w, 500, "server_error", errors.New("accessserver: invalid or unconfigured deferred decision"))
		return
	}
	now := server.clock.Now().UTC()
	var record PendingAuthorizationRecord
	if prior == nil {
		deadline := now.Add(server.deferred.Lifetime)
		for _, t := range []time.Time{time.Unix(resource.ExpiresAt, 0), credentialExpiresAt, presented.ExpiresAt} {
			if t.Before(deadline) {
				deadline = t
			}
		}
		id := make([]byte, 32)
		if _, err := rand.Read(id); err != nil {
			writeProblem(w, 500, "server_error", err)
			return
		}
		record = PendingAuthorizationRecord{ID: base64.RawURLEncoding.EncodeToString(id), PersonServer: ps, Request: append([]byte(nil), encoded...), ExpiresAt: deadline, NextPollAt: now.Add(decision.Pending.RetryAfter), Revision: 1, RequiredClaims: append([]string(nil), decision.Pending.RequiredClaims...)}
		if !now.Before(deadline) {
			writeProblem(w, 408, "expired", nil)
			return
		}
		if err := server.deferred.Store.CreateAccessAuthorization(r.Context(), record); err != nil {
			writeProblem(w, 500, "server_error", err)
			return
		}
	} else {
		prior.RequiredClaims = append([]string(nil), decision.Pending.RequiredClaims...)
		record = *prior
	}
	w.Header().Set("Location", strings.TrimRight(server.issuer, "/")+"/token/pending/"+record.ID)
	w.Header().Set("Retry-After", strconv.FormatInt(int64(decision.Pending.RetryAfter/time.Second), 10))
	w.Header().Set("Cache-Control", "no-store")
	if payment := decision.Pending.Payment; payment != nil {
		w.Header().Set("WWW-Authenticate", payment.Authenticate)
		if payment.ContentType != "" {
			w.Header().Set("Content-Type", payment.ContentType)
		}
		w.WriteHeader(http.StatusPaymentRequired)
		_, _ = w.Write(payment.Body)
		return
	}
	if len(decision.Pending.RequiredClaims) > 0 {
		w.Header().Set("AAuth-Requirement", "requirement=claims")
		writePrivateJSON(w, 202, map[string]any{"status": "pending", "required_claims": append([]string(nil), decision.Pending.RequiredClaims...)})
		return
	}
	w.Header().Set("AAuth-Requirement", "requirement=approval")
	writePrivateJSON(w, 202, map[string]string{"status": "pending"})
}

func validRequiredClaimNames(names []string) bool {
	seen := make(map[string]struct{}, len(names))
	for _, name := range names {
		if name == "" || name == "sub" || strings.ContainsAny(name, " \t\r\n") {
			return false
		}
		if _, ok := seen[name]; ok {
			return false
		}
		seen[name] = struct{}{}
	}
	return true
}

// verifyPendingPoller authenticates the Person Server that polls or cancels a
// pending URL with its own bodyless jwks_uri-signed request.
func (server *Server) verifyPendingPoller(w http.ResponseWriter, r *http.Request) (string, signaturekey.VerifiedRequest, bool) {
	ps, proof, _, ok := server.authenticatePending(w, r, false)
	return ps, proof, ok
}

// authenticatePending checks a jwks_uri signature from the Person Server.
// withBody requires content-type and content-digest and returns the exact body.
func (server *Server) authenticatePending(w http.ResponseWriter, r *http.Request, withBody bool) (string, signaturekey.VerifiedRequest, []byte, bool) {
	options := signaturekey.VerifyOptions{AcceptedSchemes: []signaturekey.Scheme{signaturekey.SchemeJWKSURI}, MaxBodyBytes: maxRequestBytes}
	if withBody {
		options.RequiredComponents = []string{"content-type", "content-digest"}
	}
	prepared, err := signaturekey.PrepareRequest(r, server.clock, options)
	if err != nil {
		writeProblem(w, 401, "invalid_request", err)
		return "", signaturekey.VerifiedRequest{}, nil, false
	}
	ps, dwk, _, ok := prepared.Credential().JWKSURI()
	if !ok || dwk != aauth.PersonDiscoveryDocument {
		writeProblem(w, 401, "invalid_request", errors.New("person server proof required"))
		return "", signaturekey.VerifiedRequest{}, nil, false
	}
	proof, err := prepared.VerifyJWKSURI(r.Context(), server.keyResolver)
	if err != nil || proof.Signer() != ps {
		writeProblem(w, 401, "invalid_request", err)
		return "", signaturekey.VerifiedRequest{}, nil, false
	}
	if err := server.trustPersonServer(r.Context(), ps); err != nil {
		writeAccessPolicyProblem(w, err)
		return "", signaturekey.VerifiedRequest{}, nil, false
	}
	if !withBody {
		if r.Body != nil {
			if body, err := io.ReadAll(io.LimitReader(r.Body, 1)); err != nil || len(body) != 0 {
				writeProblem(w, 400, "invalid_request", errors.New("pending request must be bodyless"))
				return "", signaturekey.VerifiedRequest{}, nil, false
			}
		}
		return ps, proof, nil, true
	}
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" {
		writeProblem(w, 400, "invalid_request", errors.New("claims body must be application/json"))
		return "", signaturekey.VerifiedRequest{}, nil, false
	}
	return ps, proof, proof.ExactBody(), true
}

func (server *Server) handlePendingToken(w http.ResponseWriter, r *http.Request) {
	ps, proof, ok := server.verifyPendingPoller(w, r)
	if !ok {
		return
	}

	record, err := server.deferred.Store.LoadAccessAuthorization(r.Context(), r.PathValue("id"))
	if err != nil {
		if errors.Is(err, ErrPendingAuthorizationConflict) {
			writeProblem(w, 410, "unknown_request", err)
		} else {
			writeProblem(w, 500, "server_error", err)
		}
		return
	}
	if record.PersonServer != ps {
		writeProblem(w, 403, "wrong_poller", errors.New("pending request belongs to another PS"))
		return
	}
	if record.Gone {
		writeProblem(w, 410, "request_consumed", nil)
		return
	}
	before := record
	now := server.clock.Now().UTC()
	buffer := newDeferredResponse()
	if !now.Before(record.ExpiresAt) {
		writeProblem(buffer, 408, "expired", nil)
	} else if now.Before(record.NextPollAt) {
		w.Header().Set("Retry-After", strconv.FormatInt(int64((record.NextPollAt.Sub(now)+time.Second-1)/time.Second), 10))
		writeProblem(w, 429, "slow_down", nil)
		return
	} else {
		nextRequest := r.Clone(r.Context())
		nextRequest.Body = io.NopCloser(bytes.NewReader(record.Request))
		server.authorizeToken(buffer, nextRequest, ps, proof, &record)
	}
	server.finishPending(w, r, before, record, buffer)
}

// handlePendingClaims accepts the Person Server's claims POST. The body is a
// JSON object whose keys are the requested claim names. sub is rejected. The
// full requested set is required in one POST; only requested names are stored.
// Policy runs again with those values. A wait that did not ask for claims is
// rejected rather than treated as a poll.
func (server *Server) handlePendingClaims(w http.ResponseWriter, r *http.Request) {
	ps, proof, body, ok := server.authenticatePending(w, r, true)
	if !ok {
		return
	}
	record, err := server.deferred.Store.LoadAccessAuthorization(r.Context(), r.PathValue("id"))
	if err != nil {
		if errors.Is(err, ErrPendingAuthorizationConflict) {
			writeProblem(w, 410, "unknown_request", err)
		} else {
			writeProblem(w, 500, "server_error", err)
		}
		return
	}
	if record.PersonServer != ps {
		writeProblem(w, 403, "wrong_poller", errors.New("pending request belongs to another PS"))
		return
	}
	if record.Gone {
		writeProblem(w, 410, "request_consumed", nil)
		return
	}
	if len(record.RequiredClaims) == 0 {
		writeProblem(w, 400, "invalid_request", errors.New("pending request is not waiting for claims"))
		return
	}
	claims, err := claimsForRequirement(body, record.RequiredClaims)
	if err != nil {
		writeProblem(w, 400, "invalid_request", err)
		return
	}
	before := record
	record.Claims = claims
	buffer := newDeferredResponse()
	if !server.clock.Now().UTC().Before(record.ExpiresAt) {
		writeProblem(buffer, 408, "expired", nil)
	} else {
		nextRequest := r.Clone(r.Context())
		nextRequest.Body = io.NopCloser(bytes.NewReader(record.Request))
		server.authorizeToken(buffer, nextRequest, ps, proof, &record)
	}
	server.finishPending(w, r, before, record, buffer)
}

func claimsForRequirement(body []byte, required []string) (map[string]json.RawMessage, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil || raw == nil {
		return nil, errors.New("accessserver: claims body must be a JSON object")
	}
	if _, present := raw["sub"]; present {
		return nil, errors.New("accessserver: claims response must not include sub")
	}
	copied := make(map[string]json.RawMessage, len(required))
	for _, name := range required {
		value, present := raw[name]
		if !present || len(bytes.TrimSpace(value)) == 0 || string(value) == "null" {
			return nil, errors.New("accessserver: claims response is incomplete")
		}
		copied[name] = append(json.RawMessage(nil), value...)
	}
	return copied, nil
}

func (server *Server) finishPending(w http.ResponseWriter, r *http.Request, before, record PendingAuthorizationRecord, buffer *deferredResponse) {
	// Policy or key resolution may outlast the retained request's deadline.
	// Check again at publication, not only when the poll arrived.
	now := server.clock.Now().UTC()
	if !now.Before(record.ExpiresAt) {
		buffer = newDeferredResponse()
		writeProblem(buffer, 408, "expired", nil)
	}
	next := record
	next.Revision++
	switch buffer.status {
	case 202, 402:
		seconds, _ := strconv.ParseInt(buffer.Header().Get("Retry-After"), 10, 64)
		next.NextPollAt = now.Add(time.Duration(seconds) * time.Second)
	default:
		next.Gone = true
	}
	if err := server.deferred.Store.ReplaceAccessAuthorization(r.Context(), before, next); err != nil {
		if errors.Is(err, ErrPendingAuthorizationConflict) {
			current, loadErr := server.deferred.Store.LoadAccessAuthorization(r.Context(), before.ID)
			switch {
			case errors.Is(loadErr, ErrPendingAuthorizationConflict):
				writeProblem(w, 410, "unknown_request", loadErr)
			case loadErr != nil:
				writeProblem(w, 500, "server_error", loadErr)
			case current.Gone:
				writeProblem(w, 410, "request_consumed", err)
			default:
				writeProblem(w, http.StatusConflict, "request_conflict", err)
			}
		} else {
			writeProblem(w, 500, "server_error", err)
		}
		return
	}
	buffer.send(w)
}

// handlePendingCancellation lets the owning Person Server withdraw a waiting
// request. The record is consumed and the answer is 200 {"status":"cancelled"},
// or 408 expired once its deadline passed; later polls are 410 request_consumed.
func (server *Server) handlePendingCancellation(w http.ResponseWriter, r *http.Request) {
	ps, _, ok := server.verifyPendingPoller(w, r)
	if !ok {
		return
	}
	record, err := server.deferred.Store.LoadAccessAuthorization(r.Context(), r.PathValue("id"))
	if err != nil {
		if errors.Is(err, ErrPendingAuthorizationConflict) {
			writeProblem(w, 410, "unknown_request", err)
		} else {
			writeProblem(w, 500, "server_error", err)
		}
		return
	}
	if record.PersonServer != ps {
		writeProblem(w, 403, "wrong_poller", errors.New("pending request belongs to another PS"))
		return
	}
	if record.Gone {
		writeProblem(w, 410, "request_consumed", nil)
		return
	}
	expired := !server.clock.Now().Before(record.ExpiresAt)
	next := record
	next.Revision++
	next.Gone = true
	if err := server.deferred.Store.ReplaceAccessAuthorization(r.Context(), record, next); err != nil {
		if errors.Is(err, ErrPendingAuthorizationConflict) {
			current, loadErr := server.deferred.Store.LoadAccessAuthorization(r.Context(), record.ID)
			if loadErr == nil && current.Gone {
				writeProblem(w, 410, "request_consumed", err)
			} else {
				writeProblem(w, http.StatusConflict, "request_conflict", err)
			}
		} else {
			writeProblem(w, 500, "server_error", err)
		}
		return
	}
	if expired {
		writeProblem(w, http.StatusRequestTimeout, "expired", nil)
		return
	}
	writePrivateJSON(w, http.StatusOK, map[string]string{"status": "cancelled"})
}

type deferredResponse struct {
	header http.Header
	status int
	body   bytes.Buffer
}

func newDeferredResponse() *deferredResponse    { return &deferredResponse{header: make(http.Header)} }
func (b *deferredResponse) Header() http.Header { return b.header }
func (b *deferredResponse) WriteHeader(s int) {
	if b.status == 0 {
		b.status = s
	}
}
func (b *deferredResponse) Write(p []byte) (int, error) {
	if b.status == 0 {
		b.status = 200
	}
	return b.body.Write(p)
}
func (b *deferredResponse) send(w http.ResponseWriter) {
	for k, v := range b.header {
		w.Header()[k] = append([]string(nil), v...)
	}
	w.WriteHeader(b.status)
	_, _ = w.Write(b.body.Bytes())
}
