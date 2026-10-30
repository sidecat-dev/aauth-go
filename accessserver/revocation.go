package accessserver

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/internal/httpapi"
	"gitlab.com/sidecat-dev/aauth-go/internal/revocation"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

// maximumRevokedAuthTokens bounds how many issued auth tokens one person-token
// revocation walks, step-up tokens included.
const maximumRevokedAuthTokens = 1024

// TokenRevocationStore records revocations by (iss, jti): person tokens
// revoked by the Person Server that issued them, resource tokens withdrawn by
// their Resource, and auth tokens this Access Server revoked itself. Revoke
// must be idempotent, and IsRevoked and Revoke for one reference must be
// linearizable. A marker is retained at least through the request's
// ExpiresAt plus the recipient's clock skew; a repeat with a later ExpiresAt
// extends it and one with an earlier ExpiresAt does not shorten it. Revoke
// may return aauth.ErrRevocationLimitReached when the issuer already holds as
// many entries as the store allows.
type TokenRevocationStore interface {
	Revoke(context.Context, aauth.RevocationRequest) error
	IsRevoked(context.Context, aauth.TokenReference) (bool, error)
}

// IssuedAuthToken records one auth token this Access Server issued, the
// Resource it is for, and the token presented for it: a person token, or on a
// step-up an auth token this server issued earlier.
type IssuedAuthToken struct {
	Reference aauth.TokenReference
	Resource  string
	ExpiresAt time.Time
	Presented aauth.TokenReference
}

// IssuedAuthTokenStore retains the auth tokens this Access Server issued, so
// that revoking a person token reaches every auth token issued against it.
// CommitIssuedAuthToken is idempotent for an identical record and retains it
// at least through ExpiresAt. LoadIssuedAuthTokens returns the retained
// records whose Presented equals the reference, in any order, and none when
// there are none.
type IssuedAuthTokenStore interface {
	CommitIssuedAuthToken(context.Context, IssuedAuthToken) error
	LoadIssuedAuthTokens(ctx context.Context, presented aauth.TokenReference) ([]IssuedAuthToken, error)
}

// RevocationConfig enables the Access Server's revocation endpoint at
// /revoke. A Person Server it trusts revokes person tokens there, and a
// Resource withdraws resource tokens. The Access Server then refuses token
// requests naming a revoked token, and revokes at each Resource the auth
// tokens it issued against a revoked person token.
type RevocationConfig struct {
	Revocations  TokenRevocationStore
	IssuedTokens IssuedAuthTokenStore
	// HTTPClient carries revocations to Resources. The server uses a copy that
	// follows no redirects and sends no cookies.
	HTTPClient *http.Client
	// Admit decides whether each Resource metadata, revocation and pending URL
	// may be contacted.
	Admit signaturekey.EgressAdmitter
	// Limits bounds what one caller may send. Zero members select defaults.
	Limits aauth.RevocationLimits
	// Hold is the longest a revocation is held open while its cascade runs
	// before the endpoint answers 202. A caller's Prefer: wait may shorten
	// it. Zero selects 20 seconds.
	Hold time.Duration
}

type revocationState struct {
	store   TokenRevocationStore
	issued  IssuedAuthTokenStore
	sender  *revocation.Sender
	limiter *revocation.Limiter
	tracker *revocation.Tracker
	limits  aauth.RevocationLimits
	hold    time.Duration
}

func (server *Server) configureRevocation(config *RevocationConfig) error {
	if config == nil {
		return nil
	}
	if config.Revocations == nil || config.IssuedTokens == nil {
		return errors.New("accessserver: revocation requires revocation and issued auth-token stores")
	}
	if config.Hold < 0 {
		return errors.New("accessserver: revocation hold must not be negative")
	}
	if err := revocation.ValidateLimits(config.Limits); err != nil {
		return fmt.Errorf("accessserver: %w", err)
	}
	sender, err := revocation.NewSender(config.HTTPClient, config.Admit, server.signingKey, server.issuer, aauth.AccessDiscoveryDocument, server.clock)
	if err != nil {
		return fmt.Errorf("accessserver: %w", err)
	}
	server.revocation = &revocationState{
		store: config.Revocations, issued: config.IssuedTokens, sender: sender,
		limiter: revocation.NewLimiter(config.Limits), tracker: revocation.NewTracker(),
		limits: revocation.Limits(config.Limits), hold: config.Hold,
	}
	return nil
}

func (server *Server) handleRevocationRoutes(mux *http.ServeMux) {
	if server.revocation == nil {
		return
	}
	mux.HandleFunc("POST /revoke", server.handleRevocation)
	mux.HandleFunc("GET /revoke/pending/{id}", server.handleRevocationPoll)
}

func (server *Server) revocationEndpoint() string {
	if server.revocation == nil {
		return ""
	}
	return server.issuer + "/revoke"
}

func (server *Server) handleRevocation(response http.ResponseWriter, request *http.Request) {
	state := server.revocation
	ctx := request.Context()
	caller, err := revocation.VerifyCaller(request, server.clock, server.keyResolver, []string{"content-type", "content-digest"}, maxRequestBytes)
	if err != nil {
		writeProblem(response, http.StatusUnauthorized, "invalid_request", err)
		return
	}
	switch caller.Document {
	case aauth.PersonDiscoveryDocument:
		if err := server.trustPersonServer(ctx, caller.Issuer); err != nil {
			if errors.Is(err, ErrAccessDenied) {
				writeProblem(response, http.StatusForbidden, "unsupported_iss", err)
			} else {
				writeProblem(response, http.StatusInternalServerError, "server_error", err)
			}
			return
		}
	case aauth.ResourceDiscoveryDocument:
	default:
		writeProblem(response, http.StatusForbidden, "unsupported_iss", errors.New("accessserver: only a Person Server or a Resource revokes here"))
		return
	}
	now := server.clock.Now().UTC()
	if delay, ok := state.limiter.Allow(caller.Issuer, now); !ok {
		revocation.WriteRateLimited(response, delay, errors.New("accessserver: revocation rate exceeded"))
		return
	}
	input, err := revocation.DecodeRequest(request, caller.Issuer, maxRequestBytes, now, state.limits)
	if err != nil {
		writeProblem(response, http.StatusBadRequest, "invalid_request", err)
		return
	}
	// The revocation is recorded before anyone downstream is called.
	if !server.recordRevocation(response, ctx, input) {
		return
	}
	var targets []revocation.Target
	if caller.Document == aauth.PersonDiscoveryDocument {
		// A person token: revoke every auth token issued against it, here first
		// so that a step-up presenting one is refused, then at its Resource.
		issued, err := server.authTokensIssuedAgainst(ctx, input.Reference, now)
		if err != nil {
			writeProblem(response, http.StatusInternalServerError, "server_error", err)
			return
		}
		for _, token := range issued {
			if !server.recordRevocation(response, ctx, aauth.RevocationRequest{Reference: token.Reference, ExpiresAt: token.ExpiresAt}) {
				return
			}
			targets = append(targets, revocation.Target{
				Recipient: token.Resource, Metadata: aauth.ResourceDiscoveryDocument,
				JTI: token.Reference.JTI, ExpiresAt: token.ExpiresAt,
			})
		}
	}
	if len(targets) == 0 {
		// Nothing downstream: the answer is immediate and never 202.
		revocation.WriteReport(response, nil)
		return
	}
	result := state.tracker.Step(ctx, state.sender, revocation.Run{
		Key: input.Reference, Caller: caller.Issuer, Targets: targets, Retry: true,
		Hold: revocation.Hold(request, state.hold), RetainUntil: input.ExpiresAt.Add(revocation.Skew), Now: now,
	})
	server.writeRevocationResult(response, result)
}

func (server *Server) handleRevocationPoll(response http.ResponseWriter, request *http.Request) {
	state := server.revocation
	caller, err := revocation.VerifyCaller(request, server.clock, server.keyResolver, nil, maxRequestBytes)
	if err != nil {
		writeProblem(response, http.StatusUnauthorized, "invalid_request", err)
		return
	}
	key, delivered, ok := state.tracker.Pending(request.PathValue("id"), caller.Issuer)
	if !ok {
		revocation.WriteUnknownPending(response)
		return
	}
	if !revocation.RequireEmptyBody(request) {
		writeProblem(response, http.StatusBadRequest, "invalid_request", errors.New("accessserver: a revocation poll has no body"))
		return
	}
	if delivered {
		revocation.WriteGone(response)
		return
	}
	result := state.tracker.Step(request.Context(), state.sender, revocation.Run{
		Key: key, Caller: caller.Issuer, Hold: revocation.Hold(request, state.hold), Now: server.clock.Now().UTC(),
	})
	server.writeRevocationResult(response, result)
}

func (server *Server) writeRevocationResult(response http.ResponseWriter, result revocation.Result) {
	if result.Pending {
		revocation.WritePending(response, server.issuer+"/revoke/pending/"+result.PendingID, result.RetryAfter)
		return
	}
	// An Access Server reports to the Person Server each Resource it revoked at.
	revocation.WriteReport(response, revocation.Report(revocation.Aggregate(result)))
}

func (server *Server) recordRevocation(response http.ResponseWriter, ctx context.Context, input aauth.RevocationRequest) bool {
	err := server.revocation.store.Revoke(ctx, input)
	switch {
	case err == nil:
		return true
	case errors.Is(err, aauth.ErrRevocationLimitReached):
		revocation.WriteRateLimited(response, server.revocation.limits.Window, err)
	default:
		writeProblem(response, http.StatusInternalServerError, "server_error", err)
	}
	return false
}

// authTokensIssuedAgainst walks the auth tokens issued against a presented
// token, and against each of those on a step-up, that have not expired.
func (server *Server) authTokensIssuedAgainst(ctx context.Context, presented aauth.TokenReference, now time.Time) ([]IssuedAuthToken, error) {
	var issued []IssuedAuthToken
	seen := map[aauth.TokenReference]struct{}{presented: {}}
	queue := []aauth.TokenReference{presented}
	for len(queue) > 0 {
		next := queue[0]
		queue = queue[1:]
		records, err := server.revocation.issued.LoadIssuedAuthTokens(ctx, next)
		if err != nil {
			return nil, fmt.Errorf("accessserver: load auth tokens issued against %s: %w", next.JTI, err)
		}
		for _, record := range records {
			if record.Presented != next || record.Reference.Issuer != server.issuer {
				return nil, errors.New("accessserver: issued auth-token store returned a record for another token")
			}
			if _, duplicate := seen[record.Reference]; duplicate {
				continue
			}
			seen[record.Reference] = struct{}{}
			queue = append(queue, record.Reference)
			if !now.Before(record.ExpiresAt) {
				continue
			}
			if len(issued) == maximumRevokedAuthTokens {
				return nil, errors.New("accessserver: too many auth tokens issued against one token")
			}
			issued = append(issued, record)
		}
	}
	return issued, nil
}

// commitIssuedAuthToken retains an auth token before it is returned.
func (server *Server) commitIssuedAuthToken(ctx context.Context, claims aauth.AuthTokenClaims, presented aauth.PresentedToken) error {
	if server.revocation == nil {
		return nil
	}
	return server.revocation.issued.CommitIssuedAuthToken(ctx, IssuedAuthToken{
		Reference: aauth.TokenReference{Issuer: claims.Issuer, JTI: claims.JTI},
		Resource:  claims.Audience,
		ExpiresAt: time.Unix(claims.ExpiresAt, 0).UTC(),
		Presented: aauth.TokenReference{Issuer: presented.Issuer, JTI: presented.JTI},
	})
}

// refuseRevokedParameter answers a token request whose resource_token or
// presented_token is revoked, and reports whether it did. A token that also
// failed verification by expiry alone is still reported as revoked. On a
// pending request the answer is the polling error revoked.
func (server *Server) refuseRevokedParameter(
	response http.ResponseWriter,
	ctx context.Context,
	compact string,
	verified *aauth.TokenReference,
	verifyErr error,
	code string,
	pending bool,
) bool {
	if server.revocation == nil {
		return false
	}
	reference := aauth.TokenReference{}
	switch {
	case verified != nil:
		reference = *verified
	default:
		expired, ok := revocation.ExpiredTokenReference(compact, verifyErr)
		if !ok {
			return false
		}
		reference = expired
	}
	revoked, err := server.revocation.store.IsRevoked(ctx, reference)
	if err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", err)
		return true
	}
	if !revoked {
		return false
	}
	detail := "The resource token was withdrawn by the Resource that issued it."
	if code == "revoked_presented_token" {
		detail = "The presented token was revoked by the server that issued it."
	}
	response.Header().Set("Cache-Control", "no-store")
	if pending {
		httpapi.WriteProblem(response, http.StatusForbidden, "revoked", errors.New(detail), httpapi.ProblemFields{Detail: detail})
		return true
	}
	httpapi.WriteProblem(response, http.StatusBadRequest, code, errors.New(detail), httpapi.ProblemFields{Detail: detail})
	return true
}
