package agent

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/budgets"
	"gitlab.com/sidecat-dev/aauth-go/internal/r3dispatch"
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

// ReauthorizationRequest names one auth token to replace and the person token
// the replacement is obtained with. Core Re-authorization: an agent that
// rotates its signing key, or whose auth token expired, obtains a fresh
// resource token from the Resource and submits it to its Person Server.
type ReauthorizationRequest struct {
	// PriorAuthToken is the auth token being replaced. It may be bound to the
	// Agent's previous signing key and may have expired.
	PriorAuthToken string
	// PersonToken is a person token for the same Resource and person, bound to
	// the client's current signing key. A person token bound to the previous
	// key cannot be presented after a rotation; obtain one with PersonToken.
	PersonToken string
	// Capabilities are the request-body capabilities sent with the exchange.
	Capabilities []string
}

// Reauthorize replaces one Core auth token. It verifies the prior token's
// signature as of its issuance, requests a fresh resource token from the
// Resource's authorization endpoint for the same scope and account with the
// current signing key, and submits that resource token to the Person Server
// the prior token named. The result is the immediate auth token, bound to the
// current key, or a pending exchange to continue with PollExchange.
//
// After a key rotation every auth token bound to the old key stops working:
// Do refuses one before sending the request. A Resource without an
// authorization endpoint issues the fresh resource token in its 401 challenge
// instead; Begin with the new person token obtains it there. Prior tokens
// that carry R3 or Budget claims are re-authorized through Authorize with
// their operations or Budget, then BeginExchange.
func (client *Client) Reauthorize(ctx context.Context, input ReauthorizationRequest) (ExchangeResult, error) {
	const operation = "reauthorize"
	if client == nil {
		return ExchangeResult{}, fail(operation, errors.New("client is required"))
	}
	if ctx == nil {
		return ExchangeResult{}, fail(operation, errors.New("context is required"))
	}
	if err := ctx.Err(); err != nil {
		return ExchangeResult{}, fail(operation, err)
	}
	if input.PriorAuthToken == "" {
		return ExchangeResult{}, fail(operation, errors.New("prior auth token is required"))
	}
	if input.PersonToken == "" {
		return ExchangeResult{}, fail(operation, errors.New("person token is required"))
	}
	prior, err := client.verifyPriorAuthToken(ctx, input.PriorAuthToken)
	if err != nil {
		return ExchangeResult{}, fail(operation, err)
	}
	person, err := aauth.VerifyPersonToken(ctx, input.PersonToken, client.keyResolver, client.clock)
	if err != nil {
		return ExchangeResult{}, fail(operation, err)
	}
	if person.Audience != prior.Audience || person.Issuer != prior.PersonServer ||
		person.Subject != prior.Subject || person.MissionS256 != prior.MissionS256 {
		return ExchangeResult{}, fail(operation, errors.New(
			"person token does not name the prior auth token's Resource, Person Server, person, and mission",
		))
	}
	resourceToken, err := client.Authorize(ctx, AuthorizeRequest{
		Resource: prior.Audience, PersonToken: input.PersonToken,
		Scopes: strings.Fields(prior.Scope), Account: prior.Account,
	})
	if err != nil {
		return ExchangeResult{}, fail(operation, err)
	}
	result, err := client.BeginExchange(ctx, ExchangeRequest{
		PersonServer: prior.PersonServer, ResourceToken: resourceToken,
		PresentedToken: input.PersonToken, Capabilities: input.Capabilities,
	})
	if err != nil {
		return ExchangeResult{}, fail(operation, err)
	}
	return result, nil
}

// verifyPriorAuthToken verifies a Core auth token as of its own iat, so an
// expired token or one bound to a previous key still proves which
// authorization it was.
func (client *Client) verifyPriorAuthToken(ctx context.Context, compact string) (aauth.AuthTokenClaims, error) {
	carriesR3, err := r3dispatch.TokenCarriesClaims(compact)
	if err != nil {
		return aauth.AuthTokenClaims{}, err
	}
	carriesBudget, err := budgets.TokenCarriesClaims(compact)
	if err != nil {
		return aauth.AuthTokenClaims{}, err
	}
	if carriesR3 || carriesBudget {
		return aauth.AuthTokenClaims{}, errors.New("prior auth token carries R3 or Budget claims; re-authorize it through Authorize and BeginExchange")
	}
	parsed, err := jose.ParseCompact(compact)
	if err != nil {
		return aauth.AuthTokenClaims{}, err
	}
	var issued struct {
		IssuedAt int64 `json:"iat"`
	}
	if err := json.Unmarshal(parsed.Payload(), &issued); err != nil || issued.IssuedAt <= 0 {
		return aauth.AuthTokenClaims{}, errors.New("prior auth token iat is required")
	}
	issuedAt := time.Unix(issued.IssuedAt, 0)
	claims, err := aauth.VerifyAuthToken(ctx, compact, client.keyResolver, aauth.ClockFunc(func() time.Time { return issuedAt }))
	if err != nil {
		return aauth.AuthTokenClaims{}, err
	}
	if claims.PersonServer == "" || claims.Subject == "" || claims.Scope == "" {
		return aauth.AuthTokenClaims{}, errors.New("prior auth token must name a Person Server, a person, and a scope")
	}
	return claims, nil
}

// PersonTokenRequiredError reports that a Resource refused an Auth token
// with revoked_jwt and requested a Person token. To satisfy the requirement,
// the caller obtains a Person token for that Resource and retries the original
// request with it. A Resource token naming the revoked Auth token cannot repair
// the failure and must not be used for an exchange.
//
// This error preserves the requirement; the client does not obtain a Person
// token or retry automatically. Re-authorization after expiry or key rotation
// is the separate Reauthorize procedure.
//
// Unwrap preserves the Signature-Key error for errors.As.
type PersonTokenRequiredError struct {
	Cause error
}

func (failure *PersonTokenRequiredError) Error() string {
	return "revoked_jwt: resource requires a person token"
}

// Requirement returns the Resource's validated person-token requirement.
func (failure *PersonTokenRequiredError) Requirement() aauth.Requirement {
	if failure == nil {
		return ""
	}
	return aauth.RequirementPersonToken
}

func (failure *PersonTokenRequiredError) Unwrap() error {
	if failure == nil {
		return nil
	}
	return failure.Cause
}

// authTokenResponseFailure is used only after presenting a verified Auth
// token. The same header cannot repair a revoked Agent or Person token.
func authTokenResponseFailure(response *http.Response) error {
	failure := responseFailure(response)
	var signatureFailure *signaturekey.Error
	if response.StatusCode == http.StatusUnauthorized &&
		errors.As(failure, &signatureFailure) && signatureFailure.Code == signaturekey.ErrorRevokedJWT &&
		aauth.ParsePersonTokenRequirement(response.Header.Values("AAuth-Requirement")) == nil {
		return &PersonTokenRequiredError{Cause: failure}
	}
	return failure
}
