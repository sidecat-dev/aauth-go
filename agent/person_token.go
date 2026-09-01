package agent

import (
	"context"
	"errors"
	"net/http"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

type personTokenResultKind uint8

const (
	personTokenResultToken personTokenResultKind = iota + 1
	personTokenResultPending
)

// PersonTokenResult is either one verified person token or one verified
// pending interaction. A 202 response is a protocol result, not an error.
type PersonTokenResult struct {
	kind    personTokenResultKind
	token   string
	pending PendingPersonToken
}

// Token returns the verified person token when issuance completed.
func (result PersonTokenResult) Token() (string, bool) {
	if result.kind != personTokenResultToken || result.token == "" {
		return "", false
	}
	return result.token, true
}

// Pending returns the verified interaction when issuance is pending.
func (result PersonTokenResult) Pending() (PendingPersonToken, bool) {
	if result.kind != personTokenResultPending || result.pending.kind != pendingPersonTokenVerified {
		return PendingPersonToken{}, false
	}
	return result.pending, true
}

type pendingPersonTokenKind uint8

const pendingPersonTokenVerified pendingPersonTokenKind = 1

// PendingPersonToken is a verified Person Server interaction. For a
// parent-mediated request, the parent retains and polls this handle while the
// verified result remains bound to the child key. Its fields are private so a
// caller cannot invent a polling target or credential binding.
type PendingPersonToken struct {
	kind              pendingPersonTokenKind
	personServer      string
	resource          string
	missionS256       string
	location          string
	retryAfter        time.Duration
	interactionURL    string
	interactionCode   string
	interacting       bool
	agent             string
	agentJKT          string
	tokenKey          jose.JWK
	tokenExpiresAt    int64
	tokenExpirySource string
}

// PersonServer returns the Person Server that accepted the original request.
func (pending PendingPersonToken) PersonServer() string { return pending.personServer }

// Resource returns the resource named by the original person-token request.
func (pending PendingPersonToken) Resource() string { return pending.resource }

// MissionS256 returns the mission named by the original request, or empty for
// a missionless interaction.
func (pending PendingPersonToken) MissionS256() string { return pending.missionS256 }

// Location returns the verified same-origin pending URL.
func (pending PendingPersonToken) Location() string { return pending.location }

// RetryAfter returns the server's current polling interval hint.
func (pending PendingPersonToken) RetryAfter() time.Duration { return pending.retryAfter }

// InteractionURL returns the HTTPS URL where the user can act.
func (pending PendingPersonToken) InteractionURL() string { return pending.interactionURL }

// InteractionCode returns the human-readable correlation code. It is not an
// authorization credential.
func (pending PendingPersonToken) InteractionCode() string { return pending.interactionCode }

// Interacting reports that the user reached the interaction endpoint. The
// caller should stop prompting the user while continuing explicit polling.
func (pending PendingPersonToken) Interacting() bool { return pending.interacting }

func (client *Client) personTokenResponse(
	ctx context.Context,
	response *http.Response,
	input PersonTokenRequest,
	credential personServerCredential,
) (PersonTokenResult, error) {
	if response.StatusCode == http.StatusAccepted {
		if input.UpstreamToken != "" {
			return PersonTokenResult{}, &CallChainingInteractionUnsupportedError{Operation: "person-token issuance"}
		}
		pending, err := client.pendingPersonToken(response, input, PendingPersonToken{}, credential)
		if err != nil {
			return PersonTokenResult{}, err
		}
		return PersonTokenResult{kind: personTokenResultPending, pending: pending}, nil
	}
	if response.StatusCode != http.StatusOK {
		return PersonTokenResult{}, responseFailure(response)
	}
	token, err := client.verifiedPersonToken(
		ctx, response, input.PersonServer, input.Resource, input.MissionS256, credential,
	)
	if err != nil {
		return PersonTokenResult{}, err
	}
	return PersonTokenResult{kind: personTokenResultToken, token: token}, nil
}

func (client *Client) pendingPersonToken(
	response *http.Response,
	input PersonTokenRequest,
	prior PendingPersonToken,
	credential personServerCredential,
) (PendingPersonToken, error) {
	if prior.kind != 0 && input.MissionS256 != prior.missionS256 {
		return PendingPersonToken{}, errors.New("pending person-token mission changed while polling")
	}
	location, err := parsePendingLocation(response)
	if err != nil {
		return PendingPersonToken{}, err
	}
	retryAfter, err := parseRetryAfter(response.Header.Values("Retry-After"))
	if err != nil {
		return PendingPersonToken{}, err
	}
	if !hasNoStore(response.Header.Values("Cache-Control")) {
		return PendingPersonToken{}, errors.New("pending response Cache-Control must contain no-store")
	}
	if len(response.Header.Values("Content-Type")) != 1 {
		return PendingPersonToken{}, errors.New("pending response requires exactly one Content-Type")
	}
	var body struct {
		Status string `json:"status"`
	}
	if err := decodeJSONResponse(response, &body); err != nil {
		return PendingPersonToken{}, err
	}
	if body.Status == "" {
		return PendingPersonToken{}, errors.New("pending response status is required")
	}

	requirementValues := response.Header.Values("AAuth-Requirement")
	interactionURL := prior.interactionURL
	interactionCode := prior.interactionCode
	if prior.kind == 0 && len(requirementValues) == 0 {
		return PendingPersonToken{}, errors.New("pending person-token response requires AAuth-Requirement")
	}
	if len(requirementValues) > 0 {
		requirement, err := aauth.ParseInteractionRequirement(requirementValues)
		if err != nil {
			return PendingPersonToken{}, err
		}
		if prior.kind != 0 && (requirement.URL != interactionURL || !aauth.MatchInteractionCode(interactionCode, requirement.Code)) {
			return PendingPersonToken{}, errors.New("pending person-token interaction changed while polling")
		}
		interactionURL = requirement.URL
		if prior.kind == 0 {
			interactionCode = requirement.Code
		}
	}
	thumbprint, err := client.signingKey.PublicJWK().Thumbprint()
	if err != nil {
		return PendingPersonToken{}, err
	}
	tokenKey := credential.requestKey
	tokenExpiresAt := credential.expiresAt
	tokenExpirySource := credential.expirySource
	if prior.kind != 0 {
		tokenKey = prior.tokenKey
		tokenExpiresAt = prior.tokenExpiresAt
		tokenExpirySource = prior.tokenExpirySource
	}
	if _, err := tokenKey.PublicKey(); err != nil || tokenExpiresAt <= 0 || tokenExpirySource == "" {
		return PendingPersonToken{}, errors.New("pending person-token credential binding is invalid")
	}
	return PendingPersonToken{
		kind: pendingPersonTokenVerified, personServer: input.PersonServer, resource: input.Resource,
		missionS256: input.MissionS256,
		location:    location, retryAfter: retryAfter, interactionURL: interactionURL,
		interactionCode: interactionCode, interacting: prior.interacting || body.Status == "interacting",
		agent: client.identifier, agentJKT: thumbprint,
		tokenKey: tokenKey, tokenExpiresAt: tokenExpiresAt, tokenExpirySource: tokenExpirySource,
	}, nil
}

func (client *Client) verifiedPersonToken(
	ctx context.Context,
	response *http.Response,
	personServer string,
	resource string,
	missionS256 string,
	credential personServerCredential,
) (string, error) {
	if len(response.Header.Values("Content-Type")) != 1 {
		return "", errors.New("person-token response requires exactly one Content-Type")
	}
	var output struct {
		PersonToken string `json:"person_token"`
		ExpiresIn   int64  `json:"expires_in"`
	}
	if err := decodeJSONResponse(response, &output); err != nil {
		return "", err
	}
	if output.PersonToken == "" || output.ExpiresIn <= 0 {
		return "", errors.New("response did not contain a valid person token result")
	}
	claims, err := aauth.VerifyPersonToken(ctx, output.PersonToken, client.keyResolver, client.clock)
	if err != nil {
		return "", err
	}
	if claims.Issuer != personServer {
		return "", errors.New("person-token issuer does not match person server")
	}
	if claims.MissionS256 != missionS256 {
		return "", errors.New("person-token mission_s256 does not match request")
	}
	if err := aauth.ValidatePersonTokenContext(claims, resource, credential.requestKey); err != nil {
		return "", err
	}
	if claims.ExpiresAt > credential.expiresAt {
		return "", errors.New("person-token lifetime exceeds " + credential.expirySource)
	}
	return output.PersonToken, nil
}

// PollPersonToken performs exactly one signed bodyless GET for a verified
// pending interaction. It never sleeps, loops, opens a browser, or resends the
// original request body.
func (client *Client) PollPersonToken(ctx context.Context, pending PendingPersonToken) (PersonTokenResult, error) {
	const operation = "poll person token"
	if client == nil {
		return PersonTokenResult{}, fail(operation, errors.New("client is required"))
	}
	if ctx == nil {
		return PersonTokenResult{}, fail(operation, errors.New("context is required"))
	}
	if err := ctx.Err(); err != nil {
		return PersonTokenResult{}, fail(operation, err)
	}
	if err := client.requireDirectPersonServerCaller(); err != nil {
		return PersonTokenResult{}, fail(operation, err)
	}
	if pending.kind != pendingPersonTokenVerified || pending.personServer == "" || pending.resource == "" ||
		pending.location == "" || pending.interactionURL == "" || pending.interactionCode == "" ||
		pending.agent == "" || pending.agentJKT == "" || pending.tokenExpiresAt <= 0 || pending.tokenExpirySource == "" {
		return PersonTokenResult{}, fail(operation, errors.New("verified pending person token is required"))
	}
	if pending.missionS256 != "" && aauth.ValidateMissionS256(pending.missionS256) != nil {
		return PersonTokenResult{}, fail(operation, errors.New("pending person token mission is invalid"))
	}
	if pending.personServer != client.agentClaims.PersonServer {
		return PersonTokenResult{}, fail(operation, errors.New("pending person server does not match client"))
	}
	if pending.agent != client.identifier {
		return PersonTokenResult{}, fail(operation, errors.New("pending person token belongs to another Agent"))
	}
	thumbprint, err := client.signingKey.PublicJWK().Thumbprint()
	if err != nil {
		return PersonTokenResult{}, fail(operation, err)
	}
	if thumbprint != pending.agentJKT {
		return PersonTokenResult{}, fail(operation, errors.New("pending person token belongs to another client key"))
	}
	if _, err := pending.tokenKey.PublicKey(); err != nil {
		return PersonTokenResult{}, fail(operation, errors.New("pending person-token credential key is invalid"))
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, pending.location, nil)
	if err != nil {
		return PersonTokenResult{}, fail(operation, err)
	}
	if err := signaturekey.SignJWTRequest(request, client.signingKey, client.agentToken, client.clock); err != nil {
		return PersonTokenResult{}, fail(operation, err)
	}
	response, err := client.httpClient.Do(request)
	if err != nil {
		return PersonTokenResult{}, fail(operation, err)
	}
	defer response.Body.Close()
	input := PersonTokenRequest{
		PersonServer: pending.personServer, Resource: pending.resource, MissionS256: pending.missionS256,
	}
	if response.StatusCode == http.StatusAccepted {
		next, err := client.pendingPersonToken(response, input, pending, personServerCredential{
			requestKey: pending.tokenKey, expiresAt: pending.tokenExpiresAt, expirySource: pending.tokenExpirySource,
		})
		if err != nil {
			return PersonTokenResult{}, fail(operation, err)
		}
		return PersonTokenResult{kind: personTokenResultPending, pending: next}, nil
	}
	if response.StatusCode != http.StatusOK {
		return PersonTokenResult{}, fail(operation, responseFailure(response))
	}
	token, err := client.verifiedPersonToken(
		ctx,
		response,
		pending.personServer,
		pending.resource,
		pending.missionS256,
		personServerCredential{
			requestKey: pending.tokenKey, expiresAt: pending.tokenExpiresAt,
			expirySource: pending.tokenExpirySource,
		},
	)
	if err != nil {
		return PersonTokenResult{}, fail(operation, err)
	}
	return PersonTokenResult{kind: personTokenResultToken, token: token}, nil
}
