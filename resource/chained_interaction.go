package resource

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"mime"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/budgets"
	"gitlab.com/sidecat-dev/aauth-go/internal/interaction"
	"gitlab.com/sidecat-dev/aauth-go/internal/r3dispatch"
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

// MaximumChainedInteractionResultBytes bounds the retained body of a chained
// request's result.
const MaximumChainedInteractionResultBytes = 1 << 20

// MaximumChainedInteractionCodeAttempts is the failed-code bound for one
// chained interaction. The interaction is not ended by it: the caller still
// receives the downstream outcome at the pending URL, but no later code
// presentation correlates.
const MaximumChainedInteractionCodeAttempts = 3

const chainedInteractionPendingPath = "/chain/pending/"

var (
	// ErrChainedInteractionNotFound reports an unknown chained interaction.
	ErrChainedInteractionNotFound = errors.New("resource: chained interaction not found")
	// ErrChainedInteractionConflict reports a duplicate identifier, a
	// transition the retained state does not allow, or a store result that
	// does not match.
	ErrChainedInteractionConflict = errors.New("resource: chained interaction conflicts with retained state")
	// ErrChainedInteractionExpired reports a chained interaction at or after
	// its deadline.
	ErrChainedInteractionExpired = errors.New("resource: chained interaction expired")
	// ErrChainedInteractionGone reports a chained interaction whose terminal
	// response was delivered.
	ErrChainedInteractionGone = errors.New("resource: chained interaction is gone")
	// ErrChainedInteractionCodeInvalid reports a failed code correlation.
	ErrChainedInteractionCodeInvalid = errors.New("resource: chained interaction code is invalid")
	// ErrChainedInteractionCodeUsed reports a code already consumed.
	ErrChainedInteractionCodeUsed = errors.New("resource: chained interaction code was already used")
	// ErrChainedInteractionCallbackInvalid reports a callback whose per-flow
	// identifier is unknown or does not match.
	ErrChainedInteractionCallbackInvalid = errors.New("resource: chained interaction callback is invalid")
	// ErrChainedInteractionUndeclared reports a caller that did not declare
	// the interaction capability on the request being chained, so it cannot
	// be sent to an interaction URL.
	ErrChainedInteractionUndeclared = errors.New("resource: caller did not declare the interaction capability")
)

// ChainedInteractionConfig lets a Resource that calls a downstream server as
// an Agent propagate a downstream interaction to its own caller (Core,
// Interaction Chaining). The Resource answers the original request with its
// own 202, its own interaction code, and its own pending URL under
// /chain/pending/, and completes the original request there once it has the
// downstream result.
type ChainedInteractionConfig struct {
	// URL is the HTTPS base of this Resource's own interaction page for
	// chained interactions, without a query or fragment. Each chained
	// interaction uses {URL}/{reference}.
	URL string
	// CallbackURL is the HTTPS base the downstream interaction returns the
	// person to, without a query or fragment. Each flow uses
	// {CallbackURL}/{reference}/{flow} with a fresh flow value the caller
	// never sees.
	CallbackURL string
	// Lifetime bounds the wait, from one second to one hour. The deadline is
	// also capped by the expiry of the Auth token the caller presented.
	Lifetime time.Duration
	// RetryAfter is the caller's polling interval, in whole seconds.
	RetryAfter time.Duration
	// Store retains each chained interaction and its result.
	Store ChainedInteractionStore
}

// ChainedInteractionRecord is the immutable context retained before the
// Resource answers its caller with 202. AgentJKT is the thumbprint of the
// caller's signing key, which every poll must use. CodeSHA256 is the digest
// of this Resource's own normalized code.
type ChainedInteractionRecord struct {
	ID         string
	CodeSHA256 [32]byte
	Resource   string
	Person     PersonIdentity
	AgentJKT   string
	Downstream aauth.InteractionRequirement
	CreatedAt  time.Time
	ExpiresAt  time.Time
	RetryAfter time.Duration
}

// ChainedInteractionState is one chained interaction state.
type ChainedInteractionState uint8

const (
	// ChainedInteractionWaiting means the caller has not sent the person yet.
	ChainedInteractionWaiting ChainedInteractionState = iota + 1
	// ChainedInteractionInteracting means the person arrived and was sent on
	// to the downstream interaction.
	ChainedInteractionInteracting
	// ChainedInteractionCompleted holds the original request's result.
	ChainedInteractionCompleted
	// ChainedInteractionFailed holds the polling error the request ended with.
	ChainedInteractionFailed
	// ChainedInteractionExpired means the deadline passed first.
	ChainedInteractionExpired
	// ChainedInteractionGone means the terminal response was delivered.
	ChainedInteractionGone
)

// ChainedInteractionResult is the original request's response, delivered
// once at the pending URL. Status is a final status other than 202.
type ChainedInteractionResult struct {
	Status      int
	ContentType string
	Body        []byte
}

// ChainedInteractionOutcome ends a chained interaction with exactly one of
// Result or Failure. Failure is a polling error: denied, abandoned, expired,
// revoked or server_error.
type ChainedInteractionOutcome struct {
	Result  *ChainedInteractionResult
	Failure aauth.ErrorCode
}

// ChainedInteractionCodePresentation is one code attempt without its
// plaintext, together with what a correlated visit retains: the callback the
// caller sent and the digest of this Resource's per-flow callback identifier.
type ChainedInteractionCodePresentation struct {
	CodeSHA256         [32]byte
	SyntacticallyValid bool
	Callback           string
	CallbackSHA256     [32]byte
}

// ChainedInteractionSnapshot is the retained state of one chained
// interaction. Callback and CallbackSHA256 are set once the code is consumed.
type ChainedInteractionSnapshot struct {
	Record         ChainedInteractionRecord
	State          ChainedInteractionState
	Callback       string
	CallbackSHA256 [32]byte
	Result         ChainedInteractionResult
	Failure        aauth.ErrorCode
}

// ChainedInteractionStore retains chained interactions. Every method that
// accepts a time first changes a waiting or interacting record to expired at
// or after ExpiresAt. Values crossing the interface are independent copies.
//
// CreateChainedInteraction retains one waiting record and returns
// ErrChainedInteractionConflict for an ID already in use.
//
// ConsumeChainedInteractionCode correlates one visit to a waiting record. An
// unknown Resource and ID pair, a presentation that is not SyntacticallyValid,
// or one whose digest differs returns ErrChainedInteractionCodeInvalid and
// counts as a failed attempt; after MaximumChainedInteractionCodeAttempts
// failures no presentation correlates. A matching code moves the record to
// interacting, retains Callback and CallbackSHA256, and returns the record. A
// later presentation returns ErrChainedInteractionCodeUsed, and one after the
// deadline ErrChainedInteractionExpired.
//
// LoadChainedInteraction returns ErrChainedInteractionNotFound for an unknown
// pair.
//
// FinishChainedInteraction moves a waiting or interacting record to completed
// or failed. An exact repeat is idempotent; another transition conflicts, and
// one after the deadline returns ErrChainedInteractionExpired.
//
// ConsumeChainedInteractionResult moves a completed, failed or expired record
// to gone after its response is delivered; a gone record returns
// ErrChainedInteractionGone.
type ChainedInteractionStore interface {
	CreateChainedInteraction(context.Context, ChainedInteractionRecord) error
	ConsumeChainedInteractionCode(
		ctx context.Context,
		resource string,
		reference string,
		presentation ChainedInteractionCodePresentation,
		now time.Time,
	) (ChainedInteractionRecord, error)
	LoadChainedInteraction(ctx context.Context, resource, reference string, now time.Time) (ChainedInteractionSnapshot, error)
	FinishChainedInteraction(
		ctx context.Context,
		resource string,
		reference string,
		outcome ChainedInteractionOutcome,
		now time.Time,
	) error
	ConsumeChainedInteractionResult(ctx context.Context, resource, reference string, now time.Time) error
}

// ChainedInteraction identifies one chained interaction to the host. Keep the
// downstream pending request with Reference, and finish this interaction
// with CompleteChainedInteraction or FailChainedInteraction once the
// downstream request ends.
type ChainedInteraction struct {
	kind   uint8
	record ChainedInteractionRecord
}

const chainedInteractionIdentified uint8 = 1

// Reference returns the non-secret chained interaction reference.
func (value ChainedInteraction) Reference() string { return value.record.ID }

// Person returns the person of the request being chained.
func (value ChainedInteraction) Person() PersonIdentity { return value.record.Person }

// Downstream returns the downstream interaction this one propagates.
func (value ChainedInteraction) Downstream() aauth.InteractionRequirement {
	return value.record.Downstream
}

// ExpiresAt returns the deadline.
func (value ChainedInteraction) ExpiresAt() time.Time { return value.record.ExpiresAt }

// Location returns the absolute pending URL the caller polls.
func (value ChainedInteraction) Location() string {
	return value.record.Resource + chainedInteractionPendingPath + value.record.ID
}

type chainedInteractionConfig struct {
	url         string
	callbackURL string
	lifetime    time.Duration
	retryAfter  time.Duration
	store       ChainedInteractionStore
}

func newChainedInteractionConfig(config *ChainedInteractionConfig) (*chainedInteractionConfig, error) {
	if config == nil {
		return nil, nil
	}
	if config.Store == nil {
		return nil, errors.New("aauth: chained interaction store is required")
	}
	if err := aauth.ValidateEndpoint(config.URL); err != nil {
		return nil, fmt.Errorf("aauth: chained interaction URL: %w", err)
	}
	if err := aauth.ValidateEndpoint(config.CallbackURL); err != nil {
		return nil, fmt.Errorf("aauth: chained interaction callback URL: %w", err)
	}
	if config.Lifetime < time.Second || config.Lifetime > time.Hour {
		return nil, errors.New("aauth: chained interaction lifetime must be between one second and one hour")
	}
	if config.RetryAfter < 0 || config.RetryAfter%time.Second != 0 {
		return nil, errors.New("aauth: chained interaction retry interval must be nonnegative whole seconds")
	}
	return &chainedInteractionConfig{
		url: config.URL, callbackURL: strings.TrimRight(config.CallbackURL, "/"),
		lifetime: config.Lifetime, retryAfter: config.RetryAfter, store: config.Store,
	}, nil
}

// ChainInteraction answers the protected request in flight with this
// Resource's own interaction, propagating downstream: the interaction
// requirement a downstream server returned to this Resource acting as an
// Agent. Call it from the Protected handler of a request authorized by a Core
// Auth token, before writing anything else. It writes 202 with
// AAuth-Requirement naming {URL}/{reference} and a fresh code, Location
// naming this Resource's pending URL, and Retry-After. It writes nothing and
// returns an error when the caller did not declare the interaction
// capability in AAuth-Capabilities, or when the request is not one it can
// chain; the host then answers the request itself.
func (server *Server) ChainInteraction(
	response http.ResponseWriter,
	request *http.Request,
	downstream aauth.InteractionRequirement,
) (ChainedInteraction, error) {
	if server == nil || server.chainedInteractions == nil {
		return ChainedInteraction{}, errors.New("resource: chained interactions are not configured")
	}
	if response == nil || request == nil {
		return ChainedInteraction{}, errors.New("resource: response and request are required")
	}
	if _, err := aauth.FormatInteractionRequirement(downstream); err != nil {
		return ChainedInteraction{}, fmt.Errorf("resource: downstream interaction: %w", err)
	}
	// A malformed Structured Field is discarded like an absent declaration.
	capabilities, _ := aauth.ParseCapabilities(request.Header.Values("AAuth-Capabilities"))
	if !slices.Contains(capabilities, "interaction") {
		return ChainedInteraction{}, ErrChainedInteractionUndeclared
	}
	principal, ok := AuthPrincipalFromContext(request.Context())
	compact, hasToken := AuthTokenFromContext(request.Context())
	if !ok || !hasToken {
		return ChainedInteraction{}, errors.New("resource: chaining requires a request authorized by an Auth token")
	}
	authExpiresAt, err := plainAuthTokenExpiry(compact)
	if err != nil {
		return ChainedInteraction{}, err
	}
	agentJKT, err := principal.Confirmation.Thumbprint()
	if err != nil {
		return ChainedInteraction{}, err
	}
	config := server.chainedInteractions
	createdAt := server.clock.Now().UTC()
	expiresAt := createdAt.Add(config.lifetime)
	if authExpiresAt.Before(expiresAt) {
		expiresAt = authExpiresAt
	}
	if !expiresAt.After(createdAt) {
		return ChainedInteraction{}, ErrChainedInteractionExpired
	}
	for attempt := 0; attempt < 3; attempt++ {
		reference, err := interaction.GeneratePendingReference(nil)
		if err != nil {
			return ChainedInteraction{}, fmt.Errorf("resource: generate chained interaction reference: %w", err)
		}
		code, err := interaction.GenerateCode(nil)
		if err != nil {
			return ChainedInteraction{}, fmt.Errorf("resource: generate chained interaction code: %w", err)
		}
		digest, err := interaction.Digest(code)
		if err != nil {
			return ChainedInteraction{}, err
		}
		interactionURL, err := appendSessionInteractionReference(config.url, reference)
		if err != nil {
			return ChainedInteraction{}, err
		}
		requirement, err := aauth.FormatInteractionRequirement(aauth.InteractionRequirement{URL: interactionURL, Code: code})
		if err != nil {
			return ChainedInteraction{}, err
		}
		record := ChainedInteractionRecord{
			ID: reference, CodeSHA256: digest, Resource: server.issuer,
			Person:   PersonIdentity{Issuer: principal.PersonServer, Subject: principal.Subject},
			AgentJKT: agentJKT, Downstream: downstream,
			CreatedAt: createdAt, ExpiresAt: expiresAt, RetryAfter: config.retryAfter,
		}
		if err := validateChainedInteractionRecord(record); err != nil {
			return ChainedInteraction{}, err
		}
		if err := config.store.CreateChainedInteraction(request.Context(), record); err != nil {
			if errors.Is(err, ErrChainedInteractionConflict) {
				continue
			}
			return ChainedInteraction{}, err
		}
		value := ChainedInteraction{kind: chainedInteractionIdentified, record: record}
		response.Header().Set("AAuth-Requirement", requirement)
		server.writeChainedPending(response, value, "pending")
		return value, nil
	}
	return ChainedInteraction{}, errors.New("resource: could not allocate a unique chained interaction")
}

// VisitChainedInteraction correlates the person's visit to {URL}/{reference}
// and returns where to send them: the downstream interaction, with this
// Resource's own per-flow callback. visit comes from
// aauth.ParseInteractionVisit; its callback is retained for
// ChainedInteractionCallbackURL. A visit whose code does not correlate
// returns an error and no URL.
func (server *Server) VisitChainedInteraction(
	ctx context.Context,
	reference string,
	visit aauth.InteractionVisit,
) (string, error) {
	if err := server.requireChainedInteractions(ctx); err != nil {
		return "", err
	}
	if reference == "" {
		return "", ErrChainedInteractionCodeInvalid
	}
	if visit.Callback != "" {
		if err := aauth.ValidateInteractionCallback(visit.Callback, true); err != nil {
			return "", err
		}
	}
	flow, err := interaction.GeneratePendingReference(nil)
	if err != nil {
		return "", fmt.Errorf("resource: generate chained interaction flow: %w", err)
	}
	presentation := ChainedInteractionCodePresentation{
		Callback: visit.Callback, CallbackSHA256: sha256.Sum256([]byte(flow)),
	}
	if digest, err := interaction.Digest(visit.Code); err == nil {
		presentation.CodeSHA256 = digest
		presentation.SyntacticallyValid = true
	}
	record, err := server.chainedInteractions.store.ConsumeChainedInteractionCode(
		ctx, server.issuer, reference, presentation, server.clock.Now().UTC(),
	)
	if err != nil {
		return "", err
	}
	if !presentation.SyntacticallyValid || record.ID != reference || record.Resource != server.issuer ||
		record.CodeSHA256 != presentation.CodeSHA256 || validateChainedInteractionRecord(record) != nil {
		return "", ErrChainedInteractionConflict
	}
	callback := server.chainedInteractions.callbackURL + "/" + reference + "/" + flow
	return aauth.FormatInteractionVisitURL(record.Downstream.URL, record.Downstream.Code, callback)
}

// ReceiveChainedInteractionCallback reads the downstream interaction's return
// to {CallbackURL}/{reference}/{flow}; rawQuery is the query without its
// leading "?". Without an error parameter it returns the chained interaction
// so the host can poll its downstream pending request, which stays
// authoritative. With one, the chained interaction ends with the mapped
// polling error and the returned error is the aauth.InteractionCallbackError;
// the host then sends the browser to ChainedInteractionCallbackURL.
func (server *Server) ReceiveChainedInteractionCallback(
	ctx context.Context,
	reference string,
	flow string,
	rawQuery string,
) (ChainedInteraction, error) {
	if err := server.requireChainedInteractions(ctx); err != nil {
		return ChainedInteraction{}, err
	}
	if reference == "" || flow == "" {
		return ChainedInteraction{}, ErrChainedInteractionCallbackInvalid
	}
	now := server.clock.Now().UTC()
	snapshot, err := server.loadChainedInteraction(ctx, reference, now)
	if err != nil {
		return ChainedInteraction{}, err
	}
	digest := sha256.Sum256([]byte(flow))
	if snapshot.CallbackSHA256 == ([32]byte{}) ||
		subtle.ConstantTimeCompare(digest[:], snapshot.CallbackSHA256[:]) != 1 {
		return ChainedInteraction{}, ErrChainedInteractionCallbackInvalid
	}
	value := ChainedInteraction{kind: chainedInteractionIdentified, record: snapshot.Record}
	failure := aauth.ReadInteractionCallback(rawQuery)
	if failure == nil {
		switch snapshot.State {
		case ChainedInteractionInteracting, ChainedInteractionCompleted:
			return value, nil
		case ChainedInteractionExpired:
			return ChainedInteraction{}, ErrChainedInteractionExpired
		case ChainedInteractionGone:
			return ChainedInteraction{}, ErrChainedInteractionGone
		default:
			return ChainedInteraction{}, ErrChainedInteractionConflict
		}
	}
	callbackError, _ := failure.(aauth.InteractionCallbackError)
	if err := server.chainedInteractions.store.FinishChainedInteraction(
		ctx, server.issuer, reference, ChainedInteractionOutcome{Failure: callbackError.PollingError()}, now,
	); err != nil {
		return ChainedInteraction{}, err
	}
	return ChainedInteraction{}, callbackError
}

// ResumeChainedInteraction reconstructs the host handle from retained state.
func (server *Server) ResumeChainedInteraction(ctx context.Context, reference string) (ChainedInteraction, error) {
	if err := server.requireChainedInteractions(ctx); err != nil {
		return ChainedInteraction{}, err
	}
	snapshot, err := server.loadChainedInteraction(ctx, reference, server.clock.Now().UTC())
	if err != nil {
		return ChainedInteraction{}, err
	}
	return ChainedInteraction{kind: chainedInteractionIdentified, record: snapshot.Record}, nil
}

// CompleteChainedInteraction retains the original request's result, which
// the caller receives once at the pending URL. Call it after the downstream
// request completed and this Resource finished the original request.
func (server *Server) CompleteChainedInteraction(
	ctx context.Context,
	value ChainedInteraction,
	result ChainedInteractionResult,
) error {
	if err := server.validateChainedInteraction(ctx, value); err != nil {
		return err
	}
	if err := validateChainedInteractionResult(result); err != nil {
		return err
	}
	result.Body = append([]byte(nil), result.Body...)
	return server.chainedInteractions.store.FinishChainedInteraction(
		ctx, server.issuer, value.record.ID, ChainedInteractionOutcome{Result: &result}, server.clock.Now().UTC(),
	)
}

// FailChainedInteraction ends the chained interaction with a polling error
// the caller receives once at the pending URL: denied, abandoned, expired,
// revoked or server_error. Use the downstream request's own polling error
// when it ended with one.
func (server *Server) FailChainedInteraction(ctx context.Context, value ChainedInteraction, failure aauth.ErrorCode) error {
	if err := server.validateChainedInteraction(ctx, value); err != nil {
		return err
	}
	if _, ok := chainedFailureStatus(failure); !ok {
		return fmt.Errorf("resource: chained interaction failure %q is not a polling error", string(failure))
	}
	return server.chainedInteractions.store.FinishChainedInteraction(
		ctx, server.issuer, value.record.ID, ChainedInteractionOutcome{Failure: failure}, server.clock.Now().UTC(),
	)
}

// ChainedInteractionCallbackURL returns where to send the person's browser
// once the chained interaction has ended: the callback the caller sent, with
// an error unless the original request completed. It returns an empty string
// when the caller sent no callback; the host then shows its own completion
// page. While the interaction can still complete it returns
// ErrChainedInteractionConflict.
func (server *Server) ChainedInteractionCallbackURL(ctx context.Context, reference string) (string, error) {
	if err := server.requireChainedInteractions(ctx); err != nil {
		return "", err
	}
	snapshot, err := server.loadChainedInteraction(ctx, reference, server.clock.Now().UTC())
	if err != nil {
		return "", err
	}
	var failure aauth.InteractionCallbackError
	switch snapshot.State {
	case ChainedInteractionCompleted:
	case ChainedInteractionFailed:
		failure = aauth.InteractionCallbackErrorFor(snapshot.Failure)
	case ChainedInteractionExpired:
		failure = aauth.InteractionCallbackInteractionExpired
	default:
		return "", ErrChainedInteractionConflict
	}
	if snapshot.Callback == "" {
		return "", nil
	}
	return aauth.InteractionCallbackURL(snapshot.Callback, failure)
}

func (server *Server) serveChainedInteractionPoll(response http.ResponseWriter, request *http.Request) {
	response.Header().Set("Cache-Control", "no-store")
	if request.ContentLength != 0 {
		writeProblem(response, http.StatusBadRequest, "invalid_request", errors.New("chained interaction polling requires a bodyless GET"))
		return
	}
	prepared, compact, err := server.prepareJWTRequest(request, nil)
	if err != nil {
		writeCredentialProblem(response, "invalid_token", err)
		return
	}
	header, err := jose.PeekHeader(compact)
	if err != nil || header.Type != aauth.AuthTokenType {
		writeCredentialProblem(response, "invalid_token", &requestTokenError{cause: errors.New("aauth: chained interaction poll requires an Auth token")})
		return
	}
	proof, claims, err := server.verifyPreparedAuthRequest(request, prepared, compact)
	if err != nil {
		writeCredentialProblem(response, "invalid_token", err)
		return
	}
	expectedDocument, expectedIssuer := aauth.AccessDiscoveryDocument, server.accessServer
	if server.authorizationTopology == authorizationTopologyPersonServer {
		expectedDocument, expectedIssuer = aauth.PersonDiscoveryDocument, claims.PersonServer
	}
	if claims.DWK != expectedDocument || claims.Issuer != expectedIssuer || claims.Audience != server.issuer ||
		!claims.Confirmation.JWK.Equal(proof.PublicKey()) {
		writeProblem(response, http.StatusUnauthorized, "invalid_token", errors.New("auth token does not bind this request"))
		return
	}
	if err := server.observeAuthToken(request.Context(), compact, claims); err != nil {
		if errors.Is(err, ErrAuthTokenRevoked) {
			writeProblem(response, http.StatusUnauthorized, "invalid_token", signaturekey.NewError(signaturekey.ErrorRevokedJWT, err))
			return
		}
		writeProblem(response, http.StatusInternalServerError, "server_error", err)
		return
	}
	thumbprint, err := proof.PublicKey().Thumbprint()
	if err != nil {
		writeProblem(response, http.StatusUnauthorized, "invalid_token", err)
		return
	}
	reference := request.PathValue("id")
	snapshot, err := server.loadChainedInteraction(request.Context(), reference, proof.VerifiedAt())
	// Another caller learns nothing about the interaction, not even that it exists.
	if errors.Is(err, ErrChainedInteractionNotFound) || err == nil &&
		(subtle.ConstantTimeCompare([]byte(snapshot.Record.AgentJKT), []byte(thumbprint)) != 1 ||
			snapshot.Record.Person != (PersonIdentity{Issuer: claims.PersonServer, Subject: claims.Subject})) {
		response.WriteHeader(http.StatusNotFound)
		return
	}
	if err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", err)
		return
	}
	value := ChainedInteraction{kind: chainedInteractionIdentified, record: snapshot.Record}
	switch snapshot.State {
	case ChainedInteractionWaiting:
		// The code is not retained; the caller keeps the one it was given.
		server.writeChainedPending(response, value, "pending")
	case ChainedInteractionInteracting:
		server.writeChainedPending(response, value, "interacting")
	case ChainedInteractionCompleted, ChainedInteractionFailed, ChainedInteractionExpired:
		if err := server.chainedInteractions.store.ConsumeChainedInteractionResult(
			request.Context(), server.issuer, reference, proof.VerifiedAt(),
		); err != nil {
			if errors.Is(err, ErrChainedInteractionGone) {
				writeProblem(response, http.StatusGone, "invalid_code", err)
				return
			}
			writeProblem(response, http.StatusInternalServerError, "server_error", err)
			return
		}
		switch snapshot.State {
		case ChainedInteractionCompleted:
			if snapshot.Result.ContentType != "" {
				response.Header().Set("Content-Type", snapshot.Result.ContentType)
			}
			response.WriteHeader(snapshot.Result.Status)
			_, _ = response.Write(snapshot.Result.Body)
		case ChainedInteractionFailed:
			status, _ := chainedFailureStatus(snapshot.Failure)
			writeProblem(response, status, string(snapshot.Failure), errors.New("chained interaction did not complete"))
		default:
			writeProblem(response, http.StatusRequestTimeout, "expired", ErrChainedInteractionExpired)
		}
	case ChainedInteractionGone:
		writeProblem(response, http.StatusGone, "invalid_code", ErrChainedInteractionGone)
	default:
		writeProblem(response, http.StatusInternalServerError, "server_error", ErrChainedInteractionConflict)
	}
}

// serveChainedInteractionNamespace keeps every other request under the
// pending prefix away from the protected application.
func serveChainedInteractionNamespace(response http.ResponseWriter, _ *http.Request) {
	response.Header().Set("Allow", http.MethodGet)
	writeProblem(response, http.StatusMethodNotAllowed, "method_not_allowed", errors.New("chained interaction polling requires GET"))
}

func (server *Server) writeChainedPending(response http.ResponseWriter, value ChainedInteraction, status string) {
	response.Header().Set("Location", value.Location())
	response.Header().Set("Retry-After", strconv.FormatInt(int64(value.record.RetryAfter/time.Second), 10))
	response.Header().Set("Cache-Control", "no-store")
	writeJSON(response, http.StatusAccepted, struct {
		Status string `json:"status"`
	}{Status: status})
}

func (server *Server) requireChainedInteractions(ctx context.Context) error {
	if server == nil || server.chainedInteractions == nil {
		return errors.New("resource: chained interactions are not configured")
	}
	if ctx == nil {
		return errors.New("resource: context is required")
	}
	return nil
}

func (server *Server) validateChainedInteraction(ctx context.Context, value ChainedInteraction) error {
	if err := server.requireChainedInteractions(ctx); err != nil {
		return err
	}
	if value.kind != chainedInteractionIdentified || value.record.Resource != server.issuer || value.record.ID == "" {
		return errors.New("resource: identified chained interaction is required")
	}
	return nil
}

func (server *Server) loadChainedInteraction(ctx context.Context, reference string, now time.Time) (ChainedInteractionSnapshot, error) {
	if reference == "" {
		return ChainedInteractionSnapshot{}, ErrChainedInteractionNotFound
	}
	snapshot, err := server.chainedInteractions.store.LoadChainedInteraction(ctx, server.issuer, reference, now)
	if err != nil {
		return ChainedInteractionSnapshot{}, err
	}
	if snapshot.Record.ID != reference || snapshot.Record.Resource != server.issuer ||
		validateChainedInteractionRecord(snapshot.Record) != nil {
		return ChainedInteractionSnapshot{}, ErrChainedInteractionConflict
	}
	switch snapshot.State {
	case ChainedInteractionCompleted:
		if validateChainedInteractionResult(snapshot.Result) != nil || snapshot.Failure != "" {
			return ChainedInteractionSnapshot{}, ErrChainedInteractionConflict
		}
	case ChainedInteractionFailed:
		if _, ok := chainedFailureStatus(snapshot.Failure); !ok {
			return ChainedInteractionSnapshot{}, ErrChainedInteractionConflict
		}
	case ChainedInteractionWaiting, ChainedInteractionInteracting, ChainedInteractionExpired, ChainedInteractionGone:
	default:
		return ChainedInteractionSnapshot{}, ErrChainedInteractionConflict
	}
	if snapshot.Callback != "" && aauth.ValidateInteractionCallback(snapshot.Callback, true) != nil {
		return ChainedInteractionSnapshot{}, ErrChainedInteractionConflict
	}
	return snapshot, nil
}

func validateChainedInteractionRecord(record ChainedInteractionRecord) error {
	if record.ID == "" || record.CodeSHA256 == ([32]byte{}) || record.Resource == "" || record.AgentJKT == "" ||
		record.CreatedAt.IsZero() || !record.ExpiresAt.After(record.CreatedAt) ||
		record.RetryAfter < 0 || record.RetryAfter%time.Second != 0 {
		return errors.New("resource: chained interaction record is invalid")
	}
	if aauth.ValidateServerIdentifier(record.Person.Issuer) != nil || record.Person.Subject == "" {
		return errors.New("resource: chained interaction person is invalid")
	}
	if _, err := aauth.FormatInteractionRequirement(record.Downstream); err != nil {
		return fmt.Errorf("resource: chained interaction downstream: %w", err)
	}
	return nil
}

func validateChainedInteractionResult(result ChainedInteractionResult) error {
	if result.Status < 200 || result.Status > 599 || result.Status == http.StatusAccepted {
		return errors.New("resource: chained interaction result needs a final status other than 202")
	}
	if len(result.Body) > MaximumChainedInteractionResultBytes {
		return errors.New("resource: chained interaction result body is too large")
	}
	if result.ContentType != "" {
		if _, _, err := mime.ParseMediaType(result.ContentType); err != nil || len(result.ContentType) > 256 {
			return errors.New("resource: chained interaction result Content-Type is invalid")
		}
	}
	return nil
}

func chainedFailureStatus(failure aauth.ErrorCode) (int, bool) {
	switch failure {
	case "denied", "abandoned", "revoked":
		return http.StatusForbidden, true
	case "expired":
		return http.StatusRequestTimeout, true
	case "server_error":
		return http.StatusInternalServerError, true
	}
	return 0, false
}

// plainAuthTokenExpiry reads exp from a Core Auth token the protected route
// already verified. Companion tokens are not chained: their polls would need
// the companion's own verification.
func plainAuthTokenExpiry(compact string) (time.Time, error) {
	carriesR3, err := r3dispatch.TokenCarriesClaims(compact)
	if err != nil {
		return time.Time{}, err
	}
	carriesBudget, err := budgets.TokenCarriesClaims(compact)
	if err != nil {
		return time.Time{}, err
	}
	if carriesR3 || carriesBudget {
		return time.Time{}, errors.New("resource: chaining an R3 or Budget authorization is not implemented")
	}
	parsed, err := jose.ParseCompact(compact)
	if err != nil {
		return time.Time{}, err
	}
	var claims struct {
		ExpiresAt int64 `json:"exp"`
	}
	if err := json.Unmarshal(parsed.Payload(), &claims); err != nil || claims.ExpiresAt <= 0 {
		return time.Time{}, errors.New("resource: authorized Auth token has no expiry")
	}
	return time.Unix(claims.ExpiresAt, 0).UTC(), nil
}
