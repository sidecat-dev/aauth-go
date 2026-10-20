package accessserver

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

// ErrPendingAuthorizationConflict reports a missing record or competing update.
var ErrPendingAuthorizationConflict = errors.New("accessserver: pending authorization conflict")

// DeferredConfig enables bounded approval and payment waits for top-level,
// missionless Core requests. It does not enable claims or interaction forwarding.
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

// PendingDecision requests approval (Payment nil) or payment before issuance.
// RetryAfter is a whole nonnegative number of seconds. The host's next policy
// result may change payment to approval at the same pending URL.
type PendingDecision struct {
	RetryAfter time.Duration
	Payment    *PaymentChallenge
}

// PendingAuthorizationRecord retains the exact token request and its verified
// PS identity. Deadline and request are immutable. Revision starts at one;
// replacement increments it. Gone is irreversible.
type PendingAuthorizationRecord struct {
	ID           string
	PersonServer string
	Request      []byte
	ExpiresAt    time.Time
	NextPollAt   time.Time
	Revision     uint64
	Gone         bool
}

// DeferredAuthorizationStore is AS-owned pending token state. Create must
// reject duplicate IDs. Stored slices must not alias caller-owned memory. Load
// returns an independent copy. Replace
// atomically compares the complete previous record, preserves ID, PersonServer,
// Request and ExpiresAt, increments Revision, and never reopens Gone. A conflict
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
	if p.Payment == nil {
		return true
	}
	c := p.Payment
	return c.Authenticate != "" && len(c.Authenticate) <= 8192 && !strings.ContainsAny(c.Authenticate, "\r\n") && len(c.Body) <= maxRequestBytes && !strings.ContainsAny(c.ContentType, "\r\n") && (len(c.Body) == 0 || c.ContentType != "")
}
func (server *Server) deferAuthorization(w http.ResponseWriter, r *http.Request, ps string, encoded []byte, resource aauth.ResourceTokenClaims, agent aauth.AgentTokenClaims, presented aauth.PresentedToken, decision Decision, prior *PendingAuthorizationRecord) {
	if server.deferred == nil || !validPendingDecision(decision) {
		writeProblem(w, 500, "server_error", errors.New("accessserver: invalid or unconfigured deferred decision"))
		return
	}
	now := server.clock.Now().UTC()
	var record PendingAuthorizationRecord
	if prior == nil {
		deadline := now.Add(server.deferred.Lifetime)
		for _, t := range []time.Time{time.Unix(resource.ExpiresAt, 0), time.Unix(agent.ExpiresAt, 0), presented.ExpiresAt} {
			if t.Before(deadline) {
				deadline = t
			}
		}
		id := make([]byte, 32)
		if _, err := rand.Read(id); err != nil {
			writeProblem(w, 500, "server_error", err)
			return
		}
		record = PendingAuthorizationRecord{ID: base64.RawURLEncoding.EncodeToString(id), PersonServer: ps, Request: append([]byte(nil), encoded...), ExpiresAt: deadline, NextPollAt: now.Add(decision.Pending.RetryAfter), Revision: 1}
		if !now.Before(deadline) {
			writeProblem(w, 408, "expired", nil)
			return
		}
		if err := server.deferred.Store.CreateAccessAuthorization(r.Context(), record); err != nil {
			writeProblem(w, 500, "server_error", err)
			return
		}
	} else {
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
	w.Header().Set("AAuth-Requirement", "requirement=approval")
	writePrivateJSON(w, 202, map[string]string{"status": "pending"})
}

func (server *Server) handlePendingToken(w http.ResponseWriter, r *http.Request) {
	prepared, err := signaturekey.PrepareRequest(r, server.clock, signaturekey.VerifyOptions{AcceptedSchemes: []signaturekey.Scheme{signaturekey.SchemeJWKSURI}, MaxBodyBytes: maxRequestBytes})
	if err != nil {
		writeProblem(w, 401, "invalid_request", err)
		return
	}
	ps, dwk, _, ok := prepared.Credential().JWKSURI()
	if !ok || dwk != aauth.PersonDiscoveryDocument {
		writeProblem(w, 401, "invalid_request", errors.New("person server proof required"))
		return
	}
	proof, err := prepared.VerifyJWKSURI(r.Context(), server.keyResolver)
	if err != nil || proof.Signer() != ps {
		writeProblem(w, 401, "invalid_request", err)
		return
	}
	if err := server.trustPersonServer(r.Context(), ps); err != nil {
		writeAccessPolicyProblem(w, err)
		return
	}
	if r.Body != nil {
		if body, err := io.ReadAll(io.LimitReader(r.Body, 1)); err != nil || len(body) != 0 {
			writeProblem(w, 400, "invalid_request", errors.New("poll must be bodyless"))
			return
		}
	}

	record, err := server.deferred.Store.LoadAccessAuthorization(r.Context(), r.PathValue("id"))
	if err != nil {
		if errors.Is(err, ErrPendingAuthorizationConflict) {
			writeProblem(w, 410, "invalid_code", err)
		} else {
			writeProblem(w, 500, "server_error", err)
		}
		return
	}
	if record.PersonServer != ps {
		writeProblem(w, 403, "denied", errors.New("pending request belongs to another PS"))
		return
	}
	if record.Gone {
		writeProblem(w, 410, "invalid_code", nil)
		return
	}
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
	// Policy or key resolution may outlast the retained request's deadline.
	// Check again at publication, not only when the poll arrived.
	now = server.clock.Now().UTC()
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
	if err := server.deferred.Store.ReplaceAccessAuthorization(r.Context(), record, next); err != nil {
		if errors.Is(err, ErrPendingAuthorizationConflict) {
			writeProblem(w, 410, "invalid_code", err)
		} else {
			writeProblem(w, 500, "server_error", err)
		}
		return
	}
	buffer.send(w)
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
