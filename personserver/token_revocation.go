package personserver

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

// ErrResourceTokenRevoked reports a resource token its Resource withdrew. A
// request waiting on it ends with the polling error revoked, and a host
// decision on it is refused.
var ErrResourceTokenRevoked = errors.New("personserver: resource token revoked")

// TokenRevocationStore records revocations by (iss, jti): person and auth
// tokens this Person Server revoked, and resource tokens withdrawn by the
// Resource that issued them. Revoke must be idempotent, and IsRevoked and
// Revoke for one reference must be linearizable. A marker is retained at
// least through the request's ExpiresAt plus the recipient's clock skew; a
// repeat with a later ExpiresAt extends it and one with an earlier ExpiresAt
// does not shorten it. Revoke may return aauth.ErrRevocationLimitReached when
// the issuer already holds as many entries as the store allows.
type TokenRevocationStore interface {
	Revoke(context.Context, aauth.RevocationRequest) error
	IsRevoked(context.Context, aauth.TokenReference) (bool, error)
}

// maximumRevokedPersonTokens bounds how many person tokens one revocation
// walks: those it revokes and those chained from them at any depth.
const maximumRevokedPersonTokens = 1024

// maximumRevokedAuthTokens bounds how many auth tokens obtained from those
// person tokens, step-ups included, one revocation walks.
const maximumRevokedAuthTokens = 4096

// ChainedPersonTokenStore is an optional TokenStore extension. It returns the
// retained records of the person tokens this Person Server issued with the
// given upstream token, in any order, and none when there are none. With it,
// RevokePersonToken also revokes, in the same cascade, the person tokens a
// call-chaining intermediary obtained by presenting a revoked person token, or
// an auth token obtained with it, as upstream_token, and those obtained from
// them in turn.
type ChainedPersonTokenStore interface {
	LoadChainedPersonTokens(ctx context.Context, upstream aauth.TokenReference) ([]PersonTokenRecord, error)
}

// AuthTokenLineageStore is an optional IssuedAuthTokenStore extension. It
// returns the retained records whose PresentedTokenReference is presented, in
// any order, and none when there are none. With it, revoking a person token
// reaches the auth tokens obtained with it, step-ups included: each enters the
// revocation store, so none is accepted again as a presented or upstream
// token, and each this Person Server issued is revoked at its Resource. An
// Access Server revokes the ones it issued itself. The call chains built on
// those auth tokens are then revoked too.
type AuthTokenLineageStore interface {
	LoadAuthTokensIssuedAgainst(ctx context.Context, presented aauth.TokenReference) ([]IssuedAuthTokenRecord, error)
}

// AgentPersonTokenStore is an optional TokenStore extension. It returns the
// retained records of the person tokens issued to the Agent that presented
// the Agent token agentToken names, under that or any other of its Agent
// tokens: every record whose AgentProvider is agentToken.Issuer and whose Agent
// is the Agent of a record with AgentTokenJTI agentToken.JTI. It returns none
// when no record names that Agent token. With it and TokenRevocation, an Agent
// Provider's revocation of an Agent token revokes each of those person tokens
// as RevokePersonToken does.
type AgentPersonTokenStore interface {
	LoadAgentPersonTokens(ctx context.Context, agentToken aauth.TokenReference) ([]PersonTokenRecord, error)
}

// TokenRevocationConfig enables RevokePersonToken and the resource-token half
// of the revocation endpoint. A revoked person token is refused as a
// presented_token and never presented to an Access Server; a resource token
// its Resource withdrew is refused with revoked_resource_token and ends a
// request waiting on it with revoked.
type TokenRevocationConfig struct {
	Revocations TokenRevocationStore
	// HTTPClient and Admit carry RevokePersonToken to Resources and Access
	// Servers. Leave both nil when this Person Server only receives
	// resource-token revocations. The server uses a copy of HTTPClient that
	// follows no redirects and sends no cookies.
	HTTPClient *http.Client
	// Admit decides whether each metadata, revocation and pending URL may be
	// contacted.
	Admit signaturekey.EgressAdmitter
	// Limits bounds what one caller may send the revocation endpoint. Zero
	// members select defaults.
	Limits aauth.RevocationLimits
	// Hold bounds how long RevokePersonToken waits for its recipients before
	// it reports them pending. Zero selects 20 seconds.
	Hold time.Duration
}

type tokenRevocationState struct {
	store   TokenRevocationStore
	sender  *revocation.Sender
	tracker *revocation.Tracker
	hold    time.Duration
}

func (server *Server) configureTokenRevocation(config *TokenRevocationConfig) error {
	limits := aauth.RevocationLimits{}
	if config != nil {
		limits = config.Limits
	}
	if err := revocation.ValidateLimits(limits); err != nil {
		return fmt.Errorf("personserver: %w", err)
	}
	server.revocationLimits = revocation.Limits(limits)
	server.revocationLimiter = revocation.NewLimiter(limits)
	if config == nil {
		return nil
	}
	if config.Revocations == nil {
		return errors.New("personserver: token revocation store is required")
	}
	if config.Hold < 0 {
		return errors.New("personserver: revocation hold must not be negative")
	}
	state := &tokenRevocationState{store: config.Revocations, tracker: revocation.NewTracker(), hold: config.Hold}
	if config.HTTPClient != nil || config.Admit != nil {
		sender, err := revocation.NewSender(config.HTTPClient, config.Admit, server.signingKey, server.issuer, aauth.PersonDiscoveryDocument, server.clock)
		if err != nil {
			return fmt.Errorf("personserver: %w", err)
		}
		state.sender = sender
	}
	server.tokenRevocation = state
	return nil
}

func (server *Server) handleRevocationRoutes(mux *http.ServeMux) {
	if server.agentTokenRevocations != nil || server.tokenRevocation != nil {
		mux.HandleFunc("POST /revoke", server.handleRevocation)
	}
	if server.cascadesAgentTokenRevocations() {
		mux.HandleFunc("GET /revoke/pending/{id}", server.handleRevocationPoll)
	}
}

// cascadesAgentTokenRevocations reports whether an Agent-token revocation
// revokes what this Person Server issued to that Agent.
func (server *Server) cascadesAgentTokenRevocations() bool {
	_, ok := server.tokens.(AgentPersonTokenStore)
	return ok && server.agentTokenRevocations != nil && server.tokenRevocation != nil && server.tokenRevocation.sender != nil
}

func (server *Server) revocationEndpoint() string {
	if server.agentTokenRevocations == nil && server.tokenRevocation == nil {
		return ""
	}
	return server.issuer + "/revoke"
}

// handleRevocation records an Agent Provider's Agent-token revocation or a
// Resource's resource-token revocation. A resource-token revocation has
// nothing downstream and is answered at once with an empty 200. So is an
// Agent-token revocation, unless this Person Server cascades it: it then
// revokes the person tokens it issued to that Agent, holds the request while
// that cascade runs, and answers the empty 200 once it is terminal, or 202 with
// a pending URL the Agent Provider polls.
func (server *Server) handleRevocation(response http.ResponseWriter, request *http.Request) {
	caller, err := revocation.VerifyCaller(request, server.clock, server.keyResolver, []string{"content-type", "content-digest"}, maxRequestBytes)
	if err != nil {
		writeProblem(response, http.StatusUnauthorized, "invalid_request", err)
		return
	}
	var record func(context.Context, aauth.RevocationRequest) error
	switch {
	case caller.Document == aauth.AgentDiscoveryDocument && server.agentTokenRevocations != nil:
		record = server.agentTokenRevocations.Revoke
	case caller.Document == aauth.ResourceDiscoveryDocument && server.tokenRevocation != nil:
		record = server.tokenRevocation.store.Revoke
	default:
		writeProblem(response, http.StatusForbidden, "unsupported_iss", errors.New("personserver: this Person Server accepts no revocations from this caller"))
		return
	}
	now := server.clock.Now().UTC()
	if delay, ok := server.revocationLimiter.Allow(caller.Issuer, now); !ok {
		revocation.WriteRateLimited(response, delay, errors.New("personserver: revocation rate exceeded"))
		return
	}
	input, err := revocation.DecodeRequest(request, caller.Issuer, maxRequestBytes, now, server.revocationLimits)
	if err != nil {
		writeProblem(response, http.StatusBadRequest, "invalid_request", err)
		return
	}
	if err := record(request.Context(), input); err != nil {
		if errors.Is(err, aauth.ErrRevocationLimitReached) {
			revocation.WriteRateLimited(response, server.revocationLimits.Window, err)
			return
		}
		writeProblem(response, http.StatusInternalServerError, "server_error", err)
		return
	}
	if caller.Document != aauth.AgentDiscoveryDocument || !server.cascadesAgentTokenRevocations() {
		revocation.WriteReport(response, nil)
		return
	}
	targets, retainUntil, err := server.agentTokenTargets(request.Context(), input.Reference)
	if err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", err)
		return
	}
	if len(targets) == 0 {
		// Nothing downstream: the answer is immediate and never 202.
		revocation.WriteReport(response, nil)
		return
	}
	if input.ExpiresAt.After(retainUntil) {
		retainUntil = input.ExpiresAt
	}
	state := server.tokenRevocation
	result := state.tracker.Step(request.Context(), state.sender, revocation.Run{
		Key: input.Reference, Caller: caller.Issuer, Targets: targets, Retry: true,
		Hold: revocation.Hold(request, state.hold), RetainUntil: retainUntil.Add(revocation.Skew), Now: now,
	})
	server.writeAgentTokenRevocationResult(response, result)
}

// handleRevocationPoll answers an Agent Provider polling the pending URL of
// an Agent-token revocation it made, with a signed bodyless GET.
func (server *Server) handleRevocationPoll(response http.ResponseWriter, request *http.Request) {
	state := server.tokenRevocation
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
		writeProblem(response, http.StatusBadRequest, "invalid_request", errors.New("personserver: a revocation poll has no body"))
		return
	}
	if delivered {
		revocation.WriteGone(response)
		return
	}
	result := state.tracker.Step(request.Context(), state.sender, revocation.Run{
		Key: key, Caller: caller.Issuer, Hold: revocation.Hold(request, state.hold), Now: server.clock.Now().UTC(),
	})
	server.writeAgentTokenRevocationResult(response, result)
}

// writeAgentTokenRevocationResult answers an Agent Provider. A Person Server
// reports nothing downstream to it, so a terminal cascade is an empty 200.
func (server *Server) writeAgentTokenRevocationResult(response http.ResponseWriter, result revocation.Result) {
	if result.Pending {
		revocation.WritePending(response, server.issuer+"/revoke/pending/"+result.PendingID, result.RetryAfter)
		return
	}
	revocation.WriteReport(response, nil)
}

// PersonTokenRevocation reports how far revoking one person token has
// reached: one attempt for the Resource named in its aud and one for each
// Access Server it was presented to.
type PersonTokenRevocation struct {
	Attempts []aauth.RevocationAttempt
}

// Pending reports whether any recipient has not reached a terminal outcome.
// Call RevokePersonToken again after RetryAfter to continue.
func (revoked PersonTokenRevocation) Pending() bool {
	for _, attempt := range revoked.Attempts {
		if attempt.Pending {
			return true
		}
	}
	return false
}

// RetryAfter is the longest delay a pending recipient asked for.
func (revoked PersonTokenRevocation) RetryAfter() time.Duration {
	var delay time.Duration
	for _, attempt := range revoked.Attempts {
		if attempt.Pending && attempt.RetryAfter > delay {
			delay = attempt.RetryAfter
		}
	}
	return delay
}

// RevokePersonToken revokes a person token this Person Server issued and
// retained. It records the revocation first, so the token is refused as a
// presented_token from then on, then revokes it at the Resource named in its
// aud and at every Access Server it was presented to. An Access Server revokes
// in turn the auth tokens it issued against it. When the issued auth-token
// store implements AuthTokenLineageStore, the auth tokens obtained with the
// person token, step-ups included, are recorded as revoked too, and those this
// Person Server issued are revoked at their Resources. When Tokens implements
// ChainedPersonTokenStore, the person tokens issued with any of these as
// upstream_token are revoked the same way in the same cascade, hop by hop.
//
// Each call makes one attempt at each recipient that has not recorded the
// revocation, waiting at most the configured hold. A recipient that answers
// 202 is reported pending and the next call polls its pending URL; one that
// failed is attempted again. Repeating the call is safe.
func (server *Server) RevokePersonToken(ctx context.Context, jti string) (PersonTokenRevocation, error) {
	if server == nil || server.tokenRevocation == nil || server.tokenRevocation.sender == nil {
		return PersonTokenRevocation{}, errors.New("personserver: person-token revocation is not configured")
	}
	if ctx == nil {
		return PersonTokenRevocation{}, errors.New("personserver: revocation context is required")
	}
	reference := aauth.TokenReference{Issuer: server.issuer, JTI: jti}
	if err := aauth.ValidateTokenReference(reference); err != nil {
		return PersonTokenRevocation{}, err
	}
	record, err := server.tokens.Load(ctx, server.issuer, jti)
	if err != nil {
		return PersonTokenRevocation{}, err
	}
	if err := validatePersonTokenRecord(record); err != nil || record.JTI != jti || record.PersonServer != server.issuer {
		return PersonTokenRevocation{}, errors.New("personserver: retained person-token record is invalid")
	}
	state := server.tokenRevocation
	targets, retainUntil, err := server.personTokenCascade(ctx, []PersonTokenRecord{record})
	if err != nil {
		return PersonTokenRevocation{}, err
	}
	now := server.clock.Now().UTC()
	hold := state.hold
	if hold <= 0 {
		hold = revocation.DefaultHold
	}
	result := state.tracker.Step(ctx, state.sender, revocation.Run{
		Key: reference, Caller: server.issuer, Targets: targets, Retry: true, Hold: hold,
		RetainUntil: retainUntil.Add(revocation.Skew), Now: now,
	})
	return PersonTokenRevocation{Attempts: revocation.Aggregate(result)}, nil
}

// revokePersonTokenRecord records one person token as revoked and returns the
// revocations it needs: at its Resource and at each Access Server it was
// presented to.
func (server *Server) revokePersonTokenRecord(ctx context.Context, record PersonTokenRecord) ([]revocation.Target, error) {
	reference := aauth.TokenReference{Issuer: server.issuer, JTI: record.JTI}
	if err := server.tokenRevocation.store.Revoke(ctx, aauth.RevocationRequest{Reference: reference, ExpiresAt: record.ExpiresAt}); err != nil {
		return nil, fmt.Errorf("personserver: record person-token revocation: %w", err)
	}
	targets := []revocation.Target{{
		Recipient: record.Resource, Metadata: aauth.ResourceDiscoveryDocument, JTI: record.JTI, ExpiresAt: record.ExpiresAt,
	}}
	if server.personTokenPresentations != nil {
		accessServers, err := server.personTokenPresentations.LoadPersonTokenPresentations(ctx, server.issuer, record.JTI)
		if err != nil {
			return nil, fmt.Errorf("personserver: load person-token presentations: %w", err)
		}
		for _, accessServer := range accessServers {
			targets = append(targets, revocation.Target{
				Recipient: accessServer, Metadata: aauth.AccessDiscoveryDocument, JTI: record.JTI, ExpiresAt: record.ExpiresAt,
			})
		}
	}
	return targets, nil
}

// personTokenCascade records each person token in roots as revoked, with
// every person token chained from it at any depth, and returns the
// revocations they need and the latest expiry among the tokens it revoked.
// Each person token is revoked at its Resource and at each Access Server it
// was presented to. Each auth token obtained with one, step-ups included, is
// recorded as revoked, and one this Person Server issued is revoked at its
// Resource; the Access Server that issued one revokes it itself. A person
// token issued with any of these tokens as upstream_token joins the cascade.
func (server *Server) personTokenCascade(ctx context.Context, roots []PersonTokenRecord) ([]revocation.Target, time.Time, error) {
	chained, _ := server.tokens.(ChainedPersonTokenStore)
	lineage, _ := server.issuedAuthTokens.(AuthTokenLineageStore)
	now := server.clock.Now()
	var targets []revocation.Target
	var retainUntil time.Time
	later := func(expiresAt time.Time) {
		if expiresAt.After(retainUntil) {
			retainUntil = expiresAt
		}
	}
	people := make([]PersonTokenRecord, 0, len(roots))
	seenPeople := make(map[string]struct{}, len(roots))
	for _, root := range roots {
		if _, duplicate := seenPeople[root.JTI]; !duplicate {
			seenPeople[root.JTI] = struct{}{}
			people = append(people, root)
		}
	}
	if len(people) > maximumRevokedPersonTokens {
		return nil, time.Time{}, errors.New("personserver: too many person tokens to revoke at once")
	}
	seenAuth := make(map[aauth.TokenReference]struct{})
	for next := 0; next < len(people); next++ {
		person := people[next]
		personTargets, err := server.revokePersonTokenRecord(ctx, person)
		if err != nil {
			return nil, time.Time{}, err
		}
		targets = append(targets, personTargets...)
		later(person.ExpiresAt)
		obtained := []aauth.TokenReference{{Issuer: server.issuer, JTI: person.JTI}}
		for walked := 0; lineage != nil && walked < len(obtained); walked++ {
			records, err := lineage.LoadAuthTokensIssuedAgainst(ctx, obtained[walked])
			if err != nil {
				return nil, time.Time{}, fmt.Errorf("personserver: load auth tokens issued against a revoked token: %w", err)
			}
			for _, record := range records {
				if validateIssuedAuthTokenRecord(record) != nil || record.PresentedTokenReference != obtained[walked] {
					return nil, time.Time{}, errors.New("personserver: issued auth-token store returned a record for another token")
				}
				if _, duplicate := seenAuth[record.Reference]; duplicate {
					continue
				}
				if len(seenAuth) == maximumRevokedAuthTokens {
					return nil, time.Time{}, errors.New("personserver: too many auth tokens issued against revoked person tokens")
				}
				seenAuth[record.Reference] = struct{}{}
				obtained = append(obtained, record.Reference)
				if !now.Before(record.ExpiresAt) {
					continue
				}
				if err := server.tokenRevocation.store.Revoke(ctx, aauth.RevocationRequest{Reference: record.Reference, ExpiresAt: record.ExpiresAt}); err != nil {
					return nil, time.Time{}, fmt.Errorf("personserver: record auth-token revocation: %w", err)
				}
				later(record.ExpiresAt)
				if record.Reference.Issuer == server.issuer {
					targets = append(targets, revocation.Target{
						Recipient: record.Resource, Metadata: aauth.ResourceDiscoveryDocument,
						JTI: record.Reference.JTI, ExpiresAt: record.ExpiresAt,
					})
				}
			}
		}
		if chained == nil {
			continue
		}
		// Revocation Cascade: the person tokens issued with one of these as
		// upstream_token are revoked in the same cascade.
		for _, upstream := range obtained {
			found, err := chained.LoadChainedPersonTokens(ctx, upstream)
			if err != nil {
				return nil, time.Time{}, fmt.Errorf("personserver: load chained person tokens: %w", err)
			}
			for _, record := range found {
				if validatePersonTokenRecord(record) != nil || record.PersonServer != server.issuer ||
					record.UpstreamTokenReference != upstream {
					return nil, time.Time{}, errors.New("personserver: chained person-token store returned a record for another token")
				}
				if _, duplicate := seenPeople[record.JTI]; duplicate || !now.Before(record.ExpiresAt) {
					continue
				}
				if len(people) == maximumRevokedPersonTokens {
					return nil, time.Time{}, errors.New("personserver: too many person tokens issued from one revoked token")
				}
				seenPeople[record.JTI] = struct{}{}
				people = append(people, record)
			}
		}
	}
	return targets, retainUntil, nil
}

// agentTokenTargets revokes, as RevokePersonToken does, every unexpired person
// token this Person Server issued to the Agent that presented agentToken, and
// returns the revocations they need. The cascade is by Agent identity: it
// includes person tokens requested with that Agent's other Agent tokens.
func (server *Server) agentTokenTargets(ctx context.Context, agentToken aauth.TokenReference) ([]revocation.Target, time.Time, error) {
	records, err := server.tokens.(AgentPersonTokenStore).LoadAgentPersonTokens(ctx, agentToken)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("personserver: load the Agent's person tokens: %w", err)
	}
	now := server.clock.Now()
	agent := ""
	roots := make([]PersonTokenRecord, 0, len(records))
	for _, record := range records {
		if validatePersonTokenRecord(record) != nil || record.PersonServer != server.issuer ||
			record.AgentProvider != agentToken.Issuer || agent != "" && record.Agent != agent {
			return nil, time.Time{}, errors.New("personserver: Agent person-token store returned a record for another Agent")
		}
		agent = record.Agent
		if now.Before(record.ExpiresAt) {
			roots = append(roots, record)
		}
	}
	return server.personTokenCascade(ctx, roots)
}

// recordUpstreamPresentation records that a person token this Person Server
// issued is passed to an Access Server as upstream_token. Revoking that
// person token then reaches the Access Server, which refuses it as an
// upstream_token from then on.
func (server *Server) recordUpstreamPresentation(ctx context.Context, upstream *verifiedUpstreamToken, accessServer string) error {
	if upstream == nil || upstream.person == nil || upstream.person.Issuer != server.issuer {
		return nil
	}
	err := server.personTokenPresentations.RecordPersonTokenPresentation(ctx, PersonTokenPresentation{
		PersonServer: server.issuer, JTI: upstream.person.JTI, AccessServer: accessServer,
		RetainUntil: time.Unix(upstream.person.ExpiresAt, 0).UTC().Add(server.maximumResourceTokenLifetime + aauth.MaximumAuthTokenLifetime),
	})
	if err != nil {
		return fmt.Errorf("personserver: record upstream person-token presentation: %w", err)
	}
	return nil
}

// recordIssuedAuthTokenRevocation retains a revocation of an auth token this
// Person Server issued, so it is refused as a presented_token too.
func (server *Server) recordIssuedAuthTokenRevocation(ctx context.Context, record IssuedAuthTokenRecord) error {
	if server.tokenRevocation == nil {
		return nil
	}
	return server.tokenRevocation.store.Revoke(ctx, aauth.RevocationRequest{Reference: record.Reference, ExpiresAt: record.ExpiresAt})
}

// refuseRevokedParameter answers a token request whose resource_token or
// presented_token is revoked, and reports whether it did. A token whose
// verification failed only by expiry is still reported as revoked.
func (server *Server) refuseRevokedParameter(
	response http.ResponseWriter,
	ctx context.Context,
	compact string,
	verified *aauth.TokenReference,
	verifyErr error,
	code string,
) bool {
	if server.tokenRevocation == nil {
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
	revoked, err := server.tokenRevocation.store.IsRevoked(ctx, reference)
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
	httpapi.WriteProblem(response, http.StatusBadRequest, code, errors.New(detail), httpapi.ProblemFields{Detail: detail})
	return true
}

// checkUpstreamRevoked refuses an upstream token this Person Server revoked.
func (server *Server) checkUpstreamRevoked(ctx context.Context, reference aauth.TokenReference) error {
	if server.tokenRevocation == nil {
		return nil
	}
	revoked, err := server.tokenRevocation.store.IsRevoked(ctx, reference)
	if err != nil {
		return &upstreamStoreError{cause: err}
	}
	if revoked {
		return fmt.Errorf("%w: the upstream token was revoked", errUpstreamCallerRevoked)
	}
	return nil
}

// revokedPendingResourceToken ends a request waiting on a resource token its
// Resource withdrew. A record retained without the resource token's jti is
// not checked.
func (server *Server) revokedPendingResourceToken(ctx context.Context, reference aauth.TokenReference) error {
	if server.tokenRevocation == nil || reference.JTI == "" {
		return nil
	}
	revoked, err := server.tokenRevocation.store.IsRevoked(ctx, reference)
	if err != nil {
		return &agentTokenRevocationStoreError{cause: err}
	}
	if revoked {
		return &revokedPendingTokenError{
			detail: "The resource token this request was started for was revoked.",
			reason: ErrResourceTokenRevoked,
		}
	}
	return nil
}
