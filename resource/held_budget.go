package resource

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/budgets"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

// HeldBudget marks a held invocation as a Budget refusal delivered under 202
// rather than 401 (Budgets Deferred Delivery). RefusedToken is the Auth token
// presented on the original request. Nothing was reserved against it or
// metered to it: for that token the 202 is a refusal like the 401. The held
// invocation is metered against the Auth token presented on the poll that
// completes it.
type HeldBudget struct {
	RefusedToken aauth.TokenReference
}

// HeldRechallenge replaces the Resource token of a held Budget invocation
// whose completing token did not fit. Previous is the Resource token being
// replaced. The other fields are as in HeldInvocation.
type HeldRechallenge struct {
	Previous              string
	ResourceToken         string
	ResourceTokenIssuedAt time.Time
	ExpiresAt             time.Time
	CompletionUntil       time.Time
}

// HeldBudgetStore is the HeldInvocationStore a Resource needs to hold Budget
// refusals. A Resource holds a Budget refusal only when its held store
// implements this interface and its Budget store implements BudgetReserver;
// otherwise it answers 401.
//
// Rechallenge atomically replaces the Resource token and completion horizon
// of a pending invocation whose current ResourceToken equals Previous. It
// returns ErrHeldInvocationNotFound for an unknown identifier,
// ErrHeldInvocationExpired for a pending invocation past CompletionUntil,
// ErrHeldAuthTokenMismatch for a completed invocation, which another token
// completed, and ErrHeldInvocationConflict while it is executing or when its
// Resource token is no longer Previous. Every other field is unchanged.
type HeldBudgetStore interface {
	HeldInvocationStore
	Rechallenge(context.Context, string, HeldRechallenge) error
}

// heldBudgetStore reports whether this Resource can hold a Budget refusal for
// request: a held store with Rechallenge, a reserving Budget store, no R3
// grant on the refused token, and the host's hold policy.
func (server *Server) heldBudgetStore(request *http.Request, r3Present bool) (HeldBudgetStore, bool, error) {
	store, ok := server.heldInvocations.(HeldBudgetStore)
	if !ok || server.budget == nil || server.budget.reserver == nil || r3Present {
		return nil, false, nil
	}
	hold, err := server.holdPolicy(request)
	if err != nil || !hold {
		return nil, false, err
	}
	return store, true, nil
}

// holdBudgetRefusal answers a Budget refusal with 202 and holds the
// invocation. The headers are those of the 401: AAuth-Requirement with its
// reason and fresh Resource token, and AAuth-Budget reporting the refused
// token's remaining and required, with no cost and no reserved.
func (server *Server) holdBudgetRefusal(
	response http.ResponseWriter,
	request *http.Request,
	store HeldBudgetStore,
	refused aauth.AuthTokenClaims,
	challengeToken string,
	requiredScopes []string,
	formattedRequirement string,
	formattedFeedback string,
) {
	claims, _, _, err := budgets.VerifyResourceToken(request.Context(), challengeToken, server.keyResolver, server.clock)
	if err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", fmt.Errorf("Resource Budget challenge: %w", err))
		return
	}
	snapshot, err := snapshotHeldRequest(request, server.maxRetainedRequestBodyBytes)
	if err == nil {
		err = validateHeldRequestHeaderLimit(snapshot.header, server.maxRetainedHeaderBytes)
	}
	if err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", err)
		return
	}
	invocation := snapshot.heldInvocation(
		challengeToken, requiredScopes, time.Unix(claims.IssuedAt, 0), time.Unix(claims.ExpiresAt, 0),
	)
	invocation.Budget = &HeldBudget{RefusedToken: aauth.TokenReference{Issuer: refused.Issuer, JTI: refused.JTI}}
	pendingID, err := store.Create(request.Context(), invocation)
	if err == nil {
		err = validateHeldPendingID(pendingID)
	}
	if err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", err)
		return
	}
	server.writeBudgetHold(response, pendingID, formattedRequirement, formattedFeedback)
}

func (server *Server) writeBudgetHold(response http.ResponseWriter, pendingID, requirement, feedback string) {
	response.Header().Set("Location", server.issuer+"/pending/"+pendingID)
	response.Header().Set("Retry-After", fmt.Sprintf("%.0f", heldPollRetryAfter.Seconds()))
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("AAuth-Requirement", requirement)
	response.Header().Set("AAuth-Budget", feedback)
	writeJSON(response, http.StatusAccepted, struct {
		Status string `json:"status"`
	}{Status: "pending"})
}

// serveHeldBudgetPoll completes a held Budget invocation, following the four
// rules of Budgets Deferred Delivery: it meters against the Auth token on
// the poll, never the refused one; it reserves the invocation's maximum cost
// against that token before running it and commits after; a token whose
// remainder is too small gets another 202 with insufficient-budget and a
// fresh Resource token while the invocation stays held; and a repeated
// presentation of the completing token is answered from the stored result
// without metering again.
func (server *Server) serveHeldBudgetPoll(
	response http.ResponseWriter,
	request *http.Request,
	pendingID string,
	invocation HeldInvocation,
	snapshot heldRequestSnapshot,
) {
	store, ok := server.heldInvocations.(HeldBudgetStore)
	if !ok || server.budget == nil || server.budget.reserver == nil || invocation.R3PerCall != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", retainedR3State(errors.New("held Budget invocation is not configured")))
		return
	}
	retained, err := server.verifyHeldBudgetResourceToken(request.Context(), invocation)
	if err != nil {
		writeR3ValidationFailure(response, err)
		return
	}
	prepared, compact, err := server.prepareJWTRequest(request, nil)
	if err != nil {
		writeCredentialProblem(response, "invalid_token", err)
		return
	}
	proof, claims, grant, err := server.verifyPreparedBudgetAuthRequest(request, prepared, compact)
	if err != nil {
		writeCredentialProblem(response, "invalid_token", err)
		return
	}
	scopes, err := server.verifyHeldBudgetCompletion(proof, claims, retained, invocation)
	if err != nil {
		writeProblem(response, http.StatusForbidden, "access_denied", err)
		return
	}
	if err := server.observeAuthToken(request.Context(), compact, claims); err != nil {
		switch {
		case errors.Is(err, ErrAuthTokenRevoked):
			response.Header().Set("AAuth-Requirement", aauth.FormatPersonTokenRequirement())
			writeProblem(response, http.StatusUnauthorized, "invalid_token", signaturekey.NewError(signaturekey.ErrorRevokedJWT, err))
		case errors.Is(err, ErrAuthTokenConflict):
			writeProblem(response, http.StatusForbidden, "access_denied", err)
		default:
			writeProblem(response, http.StatusInternalServerError, "server_error", err)
		}
		return
	}
	principal := AuthPrincipal{
		PersonServer: claims.PersonServer, Subject: claims.Subject, MissionS256: claims.MissionS256,
		Tenant: claims.Tenant, Account: cloneAuthorizationAccount(claims.Account), Scope: scopes,
		Confirmation: claims.Confirmation.JWK, AdditionalClaims: cloneAdditionalClaims(claims.AdditionalClaims),
	}
	meter := newBudgetResponseWriter(response, request.Context(), server.budget.store, claims, grant, server.clock.Now())
	hold, err := server.heldBudgetMaximum(request.Context(), snapshot, principal, grant)
	if err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", err)
		return
	}
	reservationID := server.newID()
	if reservationID == "" {
		writeProblem(response, http.StatusInternalServerError, "server_error", errors.New("Resource Budget reservation identifier is empty"))
		return
	}
	charge := meter.charge
	reserved, err := server.budget.reserver.Reserve(request.Context(), BudgetReserve{
		ID: reservationID, Token: charge.Token, PersonServer: charge.PersonServer, Subject: charge.Subject,
		Audience: charge.Audience, MissionS256: charge.MissionS256, Tenant: charge.Tenant,
		Account: cloneBudgetAccount(charge.Account), Grant: grant, Hold: hold,
		AgentJKT: charge.AgentJKT, ReservedAt: charge.ChargedAt,
	})
	if errors.Is(err, ErrBudgetInsufficient) || errors.Is(err, ErrBudgetExhausted) {
		server.rechallengeHeldBudget(response, request, store, pendingID, invocation, claims, principal, grant, hold, reserved)
		return
	}
	if err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", err)
		return
	}
	release := func() {
		_ = server.budget.reserver.Release(context.Background(), BudgetRelease{Token: charge.Token, ID: reservationID})
	}
	credential := HeldAuthToken{
		SHA256:      sha256.Sum256([]byte(compact)),
		PresentedAt: time.Unix(proof.VerifiedAt().Unix(), 0),
		RetainUntil: time.Unix(claims.ExpiresAt, 0),
	}
	claim, err := store.Claim(context.Background(), pendingID, credential)
	if err != nil {
		release()
		server.writeHeldStoreFailure(response, pendingID, err)
		return
	}
	if replay, ok := claim.Replay(); ok {
		release()
		server.writeHeldBudgetReplay(response, meter, replay)
		return
	}
	execution, ok := claim.Execution()
	if !ok || execution.InvocationID != pendingID || execution.Fence == "" {
		release()
		writeProblem(response, http.StatusInternalServerError, "server_error", errors.New("held invocation store returned an invalid execution claim"))
		return
	}
	settlement := &budgetSettlement{
		store: server.budget.reserver, id: reservationID, token: charge.Token, hold: hold, grant: grant,
		now: server.clock.Now,
	}
	result := server.executeHeldInvocationSettled(
		snapshot, compact, claims, proof.PublicKey(), proof.VerifiedAt(), scopes, settlement,
	)
	settlement.finish()
	if settlement.result == nil {
		result = server.heldInternalFailure()
	} else if feedback, err := budgets.NewSuccessFeedback(grant, settlement.result.Cost, settlement.result.Remaining); err != nil {
		result = server.heldInternalFailure()
	} else if formatted, err := budgets.FormatFeedback(feedback); err != nil {
		result = server.heldInternalFailure()
	} else {
		result.Header = result.Header.Clone()
		if result.Header == nil {
			result.Header = http.Header{}
		}
		result.Header.Set("AAuth-Budget", formatted)
	}
	stored, err := store.Retain(context.Background(), execution, result)
	if err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", err)
		return
	}
	if err := server.writeHeldResponse(response, stored); err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", err)
	}
}

func (server *Server) verifyHeldBudgetResourceToken(ctx context.Context, invocation HeldInvocation) (aauth.ResourceTokenClaims, error) {
	clock := aauth.ClockFunc(func() time.Time { return invocation.ResourceTokenIssuedAt })
	claims, _, _, err := budgets.VerifyResourceToken(ctx, invocation.ResourceToken, server.keyResolver, clock)
	if err != nil {
		return aauth.ResourceTokenClaims{}, retainedR3State(fmt.Errorf("verify held Budget Resource token: %w", err))
	}
	audience := server.accessServer
	if server.authorizationTopology == authorizationTopologyPersonServer {
		audience = claims.PersonServer
	}
	if claims.Issuer != server.issuer || claims.Audience != audience || claims.DWK != aauth.ResourceDiscoveryDocument ||
		claims.IssuedAt != invocation.ResourceTokenIssuedAt.Unix() || claims.ExpiresAt != invocation.ExpiresAt.Unix() ||
		!invocation.CompletionUntil.Equal(invocation.ExpiresAt.Add(maximumDerivativeAuthTokenLifetime)) {
		return aauth.ResourceTokenClaims{}, retainedR3State(errors.New("held Budget Resource token does not match its retained invocation"))
	}
	return claims, nil
}

// verifyHeldBudgetCompletion checks that the poll's Auth token was issued for
// the held Resource token: same issuer role, person, tenant, mission,
// account and key, issued during the Resource token's lifetime, and granting
// the route's required scopes. It returns the granted scopes.
func (server *Server) verifyHeldBudgetCompletion(
	proof signaturekey.VerifiedRequest,
	claims aauth.AuthTokenClaims,
	retained aauth.ResourceTokenClaims,
	invocation HeldInvocation,
) ([]string, error) {
	expectedDocument, expectedIssuer := aauth.AccessDiscoveryDocument, server.accessServer
	if server.authorizationTopology == authorizationTopologyPersonServer {
		expectedDocument, expectedIssuer = aauth.PersonDiscoveryDocument, retained.PersonServer
	}
	thumbprint, err := proof.PublicKey().Thumbprint()
	if err != nil {
		return nil, err
	}
	switch {
	case claims.DWK != expectedDocument || claims.Issuer != expectedIssuer || claims.Audience != server.issuer:
		return nil, errors.New("held Budget Auth token does not come from this Resource's issuer")
	case claims.PersonServer != retained.PersonServer || claims.Subject != retained.Subject ||
		claims.Tenant != retained.Tenant || claims.MissionS256 != retained.MissionS256 ||
		!sameBudgetAccount(claims.Account, retained.Account):
		return nil, errors.New("held Budget Auth token changed the retained person context")
	case !claims.Confirmation.JWK.Equal(proof.PublicKey()) || retained.AgentJKT != thumbprint:
		return nil, errors.New("held Budget Auth token does not match the poll signing key")
	case claims.IssuedAt < retained.IssuedAt || claims.IssuedAt >= retained.ExpiresAt:
		return nil, errors.New("held Budget Auth token was issued outside the Resource-token lifetime")
	}
	scopes, err := server.validateScopes(claims.Scope)
	if err != nil {
		return nil, err
	}
	for _, required := range invocation.RequiredScopes {
		if !slices.Contains(scopes, required) {
			return nil, errors.New("held Budget Auth token does not grant the route's required scopes")
		}
	}
	return scopes, nil
}

// heldBudgetMaximum is the amount reserved before the held invocation runs:
// the Maximum policy when one is configured, otherwise the fixed Cost.
func (server *Server) heldBudgetMaximum(
	ctx context.Context,
	snapshot heldRequestSnapshot,
	principal AuthPrincipal,
	grant budgets.Value,
) (int64, error) {
	policyRequest, err := snapshot.request(ctx, principal)
	if err != nil {
		return 0, err
	}
	policy := server.budget.cost
	if server.budget.maximum != nil {
		policy = server.budget.maximum
	}
	amount, err := policy(ctx, BudgetCostRequest{Request: policyRequest, Principal: cloneBudgetPrincipal(principal), Grant: grant})
	if err != nil {
		return 0, fmt.Errorf("Resource Budget cost policy: %w", err)
	}
	if amount <= 0 && server.budget.maximum != nil {
		return 0, errors.New("Resource Budget reserve must be positive")
	}
	if _, err := budgets.NewValue(amount, grant.Unit()); err != nil {
		return 0, fmt.Errorf("Resource Budget cost policy: %w", err)
	}
	return amount, nil
}

// rechallengeHeldBudget answers a completing token that does not fit: the
// invocation is not run and stays held under a fresh Resource token whose
// presented_jti names that token.
func (server *Server) rechallengeHeldBudget(
	response http.ResponseWriter,
	request *http.Request,
	store HeldBudgetStore,
	pendingID string,
	invocation HeldInvocation,
	claims aauth.AuthTokenClaims,
	principal AuthPrincipal,
	grant budgets.Value,
	hold int64,
	reserved BudgetReserveResult,
) {
	if reserved.Remaining < 0 || reserved.Remaining >= hold || reserved.Remaining > grant.Amount() {
		writeProblem(response, http.StatusInternalServerError, "server_error", errors.New("Resource Budget store returned an invalid refusal result"))
		return
	}
	required := hold
	feedback, err := budgets.NewRefusalFeedback(grant, reserved.Remaining, &required)
	if err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", err)
		return
	}
	formattedFeedback, err := budgets.FormatFeedback(feedback)
	if err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", err)
		return
	}
	challengeToken, err := server.budget.challenge(request.Context(), BudgetChallengeRequest{
		Token:     aauth.TokenReference{Issuer: claims.Issuer, JTI: claims.JTI},
		Principal: cloneBudgetPrincipal(principal), Grant: grant,
		Remaining: reserved.Remaining, Consumed: reserved.Consumed, Required: hold,
		Reason: budgets.ReasonInsufficientBudget,
	})
	if err == nil {
		err = server.validateBudgetChallenge(request.Context(), challengeToken, claims.JTI, principal, nil, reserved.Consumed, grant.Unit())
	}
	if err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", fmt.Errorf("Resource Budget challenge: %w", err))
		return
	}
	fresh, _, _, err := budgets.VerifyResourceToken(request.Context(), challengeToken, server.keyResolver, server.clock)
	if err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", fmt.Errorf("Resource Budget challenge: %w", err))
		return
	}
	expiresAt := time.Unix(fresh.ExpiresAt, 0)
	if err := store.Rechallenge(request.Context(), pendingID, HeldRechallenge{
		Previous: invocation.ResourceToken, ResourceToken: challengeToken,
		ResourceTokenIssuedAt: time.Unix(fresh.IssuedAt, 0), ExpiresAt: expiresAt,
		CompletionUntil: expiresAt.Add(maximumDerivativeAuthTokenLifetime),
	}); err != nil {
		server.writeHeldStoreFailure(response, pendingID, err)
		return
	}
	requirement, err := budgets.FormatAuthTokenRequirement(
		aauth.AuthTokenRequirement{ResourceToken: challengeToken}, budgets.ReasonInsufficientBudget,
	)
	if err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", err)
		return
	}
	server.writeBudgetHold(response, pendingID, requirement, formattedFeedback)
}

// writeHeldBudgetReplay answers a repeated presentation of the completing
// token from the stored result, metering nothing. Its AAuth-Budget reports
// the token's current remaining and the invocation's stored cost, with no
// reserved, so the figure is still a floor.
func (server *Server) writeHeldBudgetReplay(response http.ResponseWriter, meter *budgetResponseWriter, replay HeldResponse) {
	stored, err := budgets.ParseFeedback(replay.Header.Values("AAuth-Budget"))
	cost, hasCost := stored.Cost()
	if err != nil || !hasCost {
		writeProblem(response, http.StatusInternalServerError, "server_error", errors.New("held Budget result has no stored cost"))
		return
	}
	observed, err := server.budget.store.Charge(meter.ctx, meter.charge)
	if err != nil && !errors.Is(err, ErrBudgetExhausted) {
		writeProblem(response, http.StatusInternalServerError, "server_error", err)
		return
	}
	feedback, err := budgets.NewSuccessFeedback(meter.charge.Grant, cost, observed.Remaining)
	if err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", err)
		return
	}
	formatted, err := budgets.FormatFeedback(feedback)
	if err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", err)
		return
	}
	replay.Header = replay.Header.Clone()
	replay.Header.Set("AAuth-Budget", formatted)
	if err := server.writeHeldResponse(response, replay); err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", err)
	}
}
