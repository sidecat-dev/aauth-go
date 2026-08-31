// Package agent implements explicit calls for the bounded AAuth Core client
// paths, including direct identity access, Resource-managed sessions,
// immediate authorization, one immediate mission journey, parent-mediated
// sub-agents, one Resource call chain, and one-shot polling of supported
// interactions and held invocations.
package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	aauth "aauth-go"
	"aauth-go/internal/jsonstrict"
	"aauth-go/jose"
	"aauth-go/signaturekey"
)

const maxResponseBytes = 1 << 20

// Config supplies one agent's identity and protocol dependencies.
type Config struct {
	Identifier         string
	SigningKey         jose.SigningKey
	AgentToken         string
	KeyResolver        signaturekey.KeyResolver
	HTTPClient         *http.Client
	Clock              aauth.Clock
	MaxSignedBodyBytes int64
}

// Client performs explicit Core calls. It does not cache, sleep, retry, or
// automatically follow requirements or deferred responses.
type Client struct {
	identifier         string
	signingKey         jose.SigningKey
	agentToken         string
	agentClaims        aauth.AgentTokenClaims
	keyResolver        signaturekey.KeyResolver
	httpClient         *http.Client
	clock              aauth.Clock
	maxSignedBodyBytes int64
}

type personServerCredential struct {
	personServer string
	requestKey   jose.JWK
	expiresAt    int64
	expirySource string
}

// Error identifies the client operation that failed while preserving its
// underlying protocol, transport, verification, or remote AAuth problem.
type Error struct {
	Operation string
	Cause     error
}

func (failure *Error) Error() string {
	if failure == nil || failure.Cause == nil {
		return "aauth agent: operation failed"
	}
	return "aauth agent: " + failure.Operation + ": " + failure.Cause.Error()
}

func (failure *Error) Unwrap() error {
	if failure == nil {
		return nil
	}
	return failure.Cause
}

// SubagentInteractionUnsupportedError reports a parent-mediated request that
// reached a deferred response. This client path supports immediate sub-agent
// issuance only and never exposes a pending handle for delegated authority.
type SubagentInteractionUnsupportedError struct {
	Operation string
}

func (failure *SubagentInteractionUnsupportedError) Error() string {
	if failure == nil || failure.Operation == "" {
		return "aauth agent: parent-mediated sub-agent interaction is not supported"
	}
	return "aauth agent: parent-mediated sub-agent " + failure.Operation + " does not support interaction"
}

// CallChainingInteractionUnsupportedError reports a call-chain request that
// reached a deferred response. The current call-chain path is immediate and
// does not create or hide an interaction relay.
type CallChainingInteractionUnsupportedError struct {
	Operation string
}

func (failure *CallChainingInteractionUnsupportedError) Error() string {
	if failure == nil || failure.Operation == "" {
		return "aauth agent: call-chaining interaction is not supported"
	}
	return "aauth agent: call-chaining " + failure.Operation + " does not support interaction"
}

// PersonTokenRequest names the Person Server and Resource for one directed
// person token. A top-level parent sets SubagentToken to request a token bound
// to that one-level sub-agent's key. A Resource acting as an Agent instead sets
// UpstreamToken; that verified token selects the Person Server, so
// PersonServer may be empty or must name the same server.
type PersonTokenRequest struct {
	PersonServer  string
	Resource      string
	MissionS256   string
	SubagentToken string
	UpstreamToken string
}

// AuthorizeRequest asks a resource to issue one token for the exact directed
// person token and scopes. UpstreamToken is local call-chain context; it is
// verified but is not sent to the Resource.
type AuthorizeRequest struct {
	Resource      string
	PersonToken   string
	UpstreamToken string
	Scopes        []string
	Header        http.Header
}

// ExchangeRequest carries one exact resource token and optional request-body
// capabilities to its Person Server. A top-level parent sets SubagentToken
// when the resource token is bound to that child. A Resource acting as an
// Agent instead sets UpstreamToken; that verified token selects the Person
// Server, so PersonServer may be empty or must name the same server. Exchange
// remains immediate-only; BeginExchange exposes a verified pending
// continuation only for a direct top-level request.
type ExchangeRequest struct {
	PersonServer  string
	ResourceToken string
	SubagentToken string
	UpstreamToken string
	Capabilities  []string
}

// New constructs a bounded Core Agent and verifies that its configured token
// names the configured identifier and signing key. A Person Server is optional
// for direct Agent identity access. Discovery and key resolution use ctx.
func New(ctx context.Context, config Config) (*Client, error) {
	const operation = "new"
	if ctx == nil {
		return nil, fail(operation, errors.New("context is required"))
	}
	if err := aauth.ValidateAgentIdentifier(config.Identifier); err != nil {
		return nil, fail(operation, err)
	}
	if config.SigningKey.ID() == "" {
		return nil, fail(operation, errors.New("signing key is required"))
	}
	if _, err := config.SigningKey.PublicJWK().PublicKey(); err != nil {
		return nil, fail(operation, fmt.Errorf("signing key: %w", err))
	}
	if config.AgentToken == "" {
		return nil, fail(operation, errors.New("agent token is required"))
	}
	if config.KeyResolver == nil {
		return nil, fail(operation, errors.New("key resolver is required"))
	}
	if config.HTTPClient == nil {
		return nil, fail(operation, errors.New("HTTP client is required"))
	}
	if config.Clock == nil {
		return nil, fail(operation, errors.New("clock is required"))
	}
	if config.MaxSignedBodyBytes < 0 {
		return nil, fail(operation, errors.New("maximum signed body size must not be negative"))
	}
	httpClient := *config.HTTPClient
	httpClient.CheckRedirect = func(*http.Request, []*http.Request) error {
		return errors.New("aauth agent: HTTP redirects are not permitted")
	}
	claims, err := aauth.VerifyAgentToken(ctx, config.AgentToken, config.KeyResolver, config.Clock)
	if err != nil {
		return nil, fail(operation, fmt.Errorf("verify agent token: %w", err))
	}
	if claims.Subject != config.Identifier {
		return nil, fail(operation, errors.New("agent token subject does not match identifier"))
	}
	if !claims.Confirmation.JWK.Equal(config.SigningKey.PublicJWK()) {
		return nil, fail(operation, errors.New("agent token confirmation key does not match signing key"))
	}
	return &Client{
		identifier: config.Identifier, signingKey: config.SigningKey,
		agentToken: config.AgentToken, agentClaims: claims,
		keyResolver: config.KeyResolver, httpClient: &httpClient, clock: config.Clock,
		maxSignedBodyBytes: config.MaxSignedBodyBytes,
	}, nil
}

// PersonToken requests one resource-directed person token. It returns either a
// verified token or a verified interaction handle and never polls on its own.
func (client *Client) PersonToken(ctx context.Context, input PersonTokenRequest) (PersonTokenResult, error) {
	const operation = "person token"
	if client == nil {
		return PersonTokenResult{}, fail(operation, errors.New("client is required"))
	}
	if ctx == nil {
		return PersonTokenResult{}, fail(operation, errors.New("context is required"))
	}
	credential, err := client.personServerRequestBinding(
		ctx, input.PersonServer, input.SubagentToken, input.UpstreamToken,
	)
	if err != nil {
		return PersonTokenResult{}, fail(operation, err)
	}
	input.PersonServer = credential.personServer
	if err := aauth.ValidateServerIdentifier(input.Resource); err != nil {
		return PersonTokenResult{}, fail(operation, fmt.Errorf("resource: %w", err))
	}
	if input.MissionS256 != "" {
		if err := aauth.ValidateMissionS256(input.MissionS256); err != nil {
			return PersonTokenResult{}, fail(operation, err)
		}
		if input.SubagentToken != "" || input.UpstreamToken != "" {
			return PersonTokenResult{}, fail(operation, errors.New("mission-bound delegated or call-chain person-token issuance is not supported"))
		}
	}
	metadata, err := client.personServerMetadata(ctx, input.PersonServer)
	if err != nil {
		return PersonTokenResult{}, fail(operation, err)
	}
	body, err := json.Marshal(struct {
		Resource      string `json:"resource"`
		MissionS256   string `json:"mission_s256,omitempty"`
		SubagentToken string `json:"subagent_token,omitempty"`
		UpstreamToken string `json:"upstream_token,omitempty"`
	}{Resource: input.Resource, MissionS256: input.MissionS256, SubagentToken: input.SubagentToken, UpstreamToken: input.UpstreamToken})
	if err != nil {
		return PersonTokenResult{}, fail(operation, err)
	}
	request, err := newJSONRequest(ctx, metadata.PersonTokenEndpoint, body)
	if err != nil {
		return PersonTokenResult{}, fail(operation, err)
	}
	request.Header.Set("Prefer", "wait=0")
	if err := client.signJSONRequest(request, client.agentToken); err != nil {
		return PersonTokenResult{}, fail(operation, err)
	}
	response, err := client.httpClient.Do(request)
	if err != nil {
		return PersonTokenResult{}, fail(operation, err)
	}
	defer response.Body.Close()
	result, err := client.personTokenResponse(ctx, response, input, credential)
	if err != nil {
		return PersonTokenResult{}, fail(operation, err)
	}
	return result, nil
}

// Authorize requests and verifies one immediate resource token.
func (client *Client) Authorize(ctx context.Context, input AuthorizeRequest) (string, error) {
	const operation = "authorize"
	if client == nil {
		return "", fail(operation, errors.New("client is required"))
	}
	if err := aauth.ValidateServerIdentifier(input.Resource); err != nil {
		return "", fail(operation, fmt.Errorf("resource: %w", err))
	}
	if input.PersonToken == "" {
		return "", fail(operation, errors.New("person token is required"))
	}
	scopes, err := validateScopes(input.Scopes)
	if err != nil {
		return "", fail(operation, err)
	}
	person, err := aauth.VerifyPersonToken(ctx, input.PersonToken, client.keyResolver, client.clock)
	if err != nil {
		return "", fail(operation, err)
	}
	if err := client.acceptIssuedPersonServer(
		ctx, input.UpstreamToken, person.Issuer, time.Unix(person.IssuedAt, 0),
	); err != nil {
		return "", fail(operation, fmt.Errorf("person-token issuer: %w", err))
	}
	if person.MissionS256 != "" && input.UpstreamToken != "" {
		return "", fail(operation, errors.New("mission-bound call-chain authorization is not supported"))
	}
	if err := aauth.ValidatePersonTokenContext(person, input.Resource, client.signingKey.PublicJWK()); err != nil {
		return "", fail(operation, err)
	}
	metadata, err := client.resourceMetadata(ctx, input.Resource)
	if err != nil {
		return "", fail(operation, err)
	}
	if metadata.AuthorizationEndpoint == "" {
		return "", fail(operation, errors.New("resource metadata authorization_endpoint is required"))
	}
	body, err := json.Marshal(struct {
		Scope string `json:"scope"`
	}{Scope: strings.Join(scopes, " ")})
	if err != nil {
		return "", fail(operation, err)
	}
	request, err := newJSONRequest(ctx, metadata.AuthorizationEndpoint, body)
	if err != nil {
		return "", fail(operation, err)
	}
	for name, values := range input.Header {
		for _, value := range values {
			request.Header.Add(name, value)
		}
	}
	request.Header.Set("Content-Type", "application/json")
	if err := client.signResourceRequest(
		request,
		input.PersonToken,
		authorizationSignatureComponents(metadata.AdditionalSignatureComponents),
	); err != nil {
		return "", fail(operation, err)
	}
	response, err := client.httpClient.Do(request)
	if err != nil {
		return "", fail(operation, err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return "", fail(operation, responseFailure(response))
	}
	var output struct {
		ResourceToken string `json:"resource_token"`
	}
	if err := decodeJSONResponse(response, &output); err != nil {
		return "", fail(operation, err)
	}
	if output.ResourceToken == "" {
		return "", fail(operation, errors.New("response did not contain a resource token"))
	}
	if _, err := client.verifyResourceTokenContext(ctx, output.ResourceToken, input.Resource, person, scopes); err != nil {
		return "", fail(operation, err)
	}
	return output.ResourceToken, nil
}

// Exchange presents one resource token to its person server and verifies the
// immediate auth token against that exact resource-token context.
func (client *Client) Exchange(ctx context.Context, input ExchangeRequest) (string, error) {
	const operation = "exchange"
	if client == nil {
		return "", fail(operation, errors.New("client is required"))
	}
	response, resourceClaims, credential, err := client.exchangeRequest(ctx, input)
	if err != nil {
		return "", fail(operation, err)
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusAccepted && resourceClaims.MissionS256 != "" {
		return "", fail(operation, &MissionContinuationUnsupportedError{
			Phase: "auth-token exchange", Operation: "Exchange",
		})
	}
	if response.StatusCode == http.StatusAccepted && input.SubagentToken != "" {
		return "", fail(operation, &SubagentInteractionUnsupportedError{Operation: "auth-token exchange"})
	}
	if response.StatusCode == http.StatusAccepted && input.UpstreamToken != "" {
		return "", fail(operation, &CallChainingInteractionUnsupportedError{Operation: "auth-token exchange"})
	}
	if response.StatusCode != http.StatusOK {
		return "", fail(operation, responseFailure(response))
	}
	token, err := client.verifiedExchangeResponse(ctx, response, resourceClaims, credential)
	if err != nil {
		return "", fail(operation, err)
	}
	return token, nil
}

func (client *Client) requireDirectPersonServerCaller() error {
	if client.agentClaims.ParentAgent != "" {
		return errors.New("sub-agent must not call the Person Server directly")
	}
	if client.agentClaims.PersonServer == "" {
		return errors.New("agent token does not name a person server")
	}
	return nil
}

func (client *Client) personServerRequestBinding(
	ctx context.Context,
	personServer string,
	subagentToken string,
	upstreamToken string,
) (personServerCredential, error) {
	if subagentToken != "" && upstreamToken != "" {
		return personServerCredential{}, errors.New("subagent_token and upstream_token are mutually exclusive")
	}
	if client.agentClaims.ParentAgent != "" {
		return personServerCredential{}, errors.New("sub-agent must not call the Person Server directly")
	}
	if upstreamToken != "" {
		upstream, err := client.verifyCallChainUpstreamToken(ctx, upstreamToken)
		if err != nil {
			return personServerCredential{}, err
		}
		if personServer != "" {
			if err := aauth.ValidateServerIdentifier(personServer); err != nil {
				return personServerCredential{}, fmt.Errorf("person server: %w", err)
			}
			if personServer != upstream.PersonServer {
				return personServerCredential{}, errors.New("person server does not match upstream token")
			}
		}
		return personServerCredential{
			personServer: upstream.PersonServer,
			requestKey:   client.signingKey.PublicJWK(),
			expiresAt:    client.agentClaims.ExpiresAt,
			expirySource: "agent token",
		}, nil
	}
	if err := client.requireDirectPersonServerCaller(); err != nil {
		return personServerCredential{}, err
	}
	if err := aauth.ValidateServerIdentifier(personServer); err != nil {
		return personServerCredential{}, fmt.Errorf("person server: %w", err)
	}
	if personServer != client.agentClaims.PersonServer {
		return personServerCredential{}, errors.New("person server does not match agent token")
	}
	if subagentToken == "" {
		return personServerCredential{
			personServer: personServer,
			requestKey:   client.signingKey.PublicJWK(), expiresAt: client.agentClaims.ExpiresAt,
			expirySource: "agent token",
		}, nil
	}
	claims, err := aauth.VerifyAgentToken(ctx, subagentToken, client.keyResolver, client.clock)
	if err != nil {
		return personServerCredential{}, fmt.Errorf("verify subagent token: %w", err)
	}
	if claims.ParentAgent == "" {
		return personServerCredential{}, errors.New("subagent token does not identify a sub-agent")
	}
	if claims.ParentAgent != client.agentClaims.Subject {
		return personServerCredential{}, errors.New("subagent token parent_agent does not match parent")
	}
	if claims.Confirmation.JWK.Equal(client.agentClaims.Confirmation.JWK) {
		return personServerCredential{}, errors.New("subagent token must use a key distinct from the parent")
	}
	expiryCeiling := client.agentClaims.ExpiresAt
	expirySource := "agent token"
	if claims.ExpiresAt < expiryCeiling {
		expiryCeiling = claims.ExpiresAt
		expirySource = "sub-agent token"
	}
	return personServerCredential{
		personServer: personServer,
		requestKey:   claims.Confirmation.JWK, expiresAt: expiryCeiling, expirySource: expirySource,
	}, nil
}

func (client *Client) verifyCallChainUpstreamToken(ctx context.Context, compact string) (aauth.AuthTokenClaims, error) {
	return client.verifyCallChainUpstreamTokenAt(ctx, compact, client.clock.Now())
}

func (client *Client) verifyCallChainUpstreamTokenAt(
	ctx context.Context,
	compact string,
	verifiedAt time.Time,
) (aauth.AuthTokenClaims, error) {
	verificationClock := aauth.ClockFunc(func() time.Time { return verifiedAt })
	claims, err := aauth.VerifyAuthToken(ctx, compact, client.keyResolver, verificationClock)
	if err != nil {
		return aauth.AuthTokenClaims{}, fmt.Errorf("verify upstream token: %w", err)
	}
	if claims.DWK != aauth.PersonDiscoveryDocument || claims.Issuer != claims.PersonServer {
		return aauth.AuthTokenClaims{}, errors.New("upstream token was not issued by its Person Server")
	}
	if claims.Audience != client.agentClaims.Issuer {
		return aauth.AuthTokenClaims{}, errors.New("upstream token audience does not match intermediary Resource")
	}
	if claims.MissionS256 != "" || claims.Account != "" {
		return aauth.AuthTokenClaims{}, errors.New("mission- or account-bound call chaining is not supported")
	}
	return claims, nil
}

func (client *Client) acceptIssuedPersonServer(
	ctx context.Context,
	upstreamToken string,
	personServer string,
	issuedAt time.Time,
) error {
	if upstreamToken == "" {
		if !client.acceptsPersonServer(personServer) {
			return errors.New("does not match agent token")
		}
		return nil
	}
	upstream, err := client.verifyCallChainUpstreamTokenAt(ctx, upstreamToken, issuedAt)
	if err != nil {
		return err
	}
	if personServer != upstream.PersonServer {
		return errors.New("does not match upstream token")
	}
	return nil
}

func (client *Client) acceptsPersonServer(personServer string) bool {
	if client.agentClaims.ParentAgent != "" {
		return aauth.ValidateServerIdentifier(personServer) == nil
	}
	return personServer != "" && personServer == client.agentClaims.PersonServer
}

func (client *Client) verifyAuthTokenForResource(
	ctx context.Context,
	compact string,
	resource aauth.ResourceTokenClaims,
) (aauth.AuthTokenClaims, error) {
	return client.verifyAuthTokenForResourceBinding(
		ctx,
		compact,
		resource,
		personServerCredential{
			personServer: resource.PersonServer,
			requestKey:   client.signingKey.PublicJWK(), expiresAt: client.agentClaims.ExpiresAt,
			expirySource: "agent token",
		},
	)
}

func (client *Client) verifyAuthTokenForResourceBinding(
	ctx context.Context,
	compact string,
	resource aauth.ResourceTokenClaims,
	credential personServerCredential,
) (aauth.AuthTokenClaims, error) {
	claims, err := aauth.VerifyAuthToken(ctx, compact, client.keyResolver, client.clock)
	if err != nil {
		return aauth.AuthTokenClaims{}, err
	}
	// The verified auth token's dwk identifies the issuer role. Equality between
	// resource-token aud and ps cannot do so because a PS and AS may be
	// collocated at one origin.
	discoveryDocument := claims.DWK
	if err := aauth.ValidateCurrentAuthTokenContext(claims, aauth.AuthTokenContext{
		Issuer:            resource.Audience,
		DiscoveryDocument: discoveryDocument,
		Resource:          resource.Issuer,
		PersonServer:      resource.PersonServer,
		Subject:           resource.Subject,
		RequestKey:        credential.requestKey,
	}); err != nil {
		return aauth.AuthTokenClaims{}, err
	}
	if !scopeSubset(strings.Fields(claims.Scope), strings.Fields(resource.Scope)) {
		return aauth.AuthTokenClaims{}, errors.New("auth-token scope is outside resource token")
	}
	if claims.MissionS256 != resource.MissionS256 || claims.Tenant != resource.Tenant ||
		claims.Account != resource.Account {
		return aauth.AuthTokenClaims{}, errors.New("auth-token context does not match resource token")
	}
	if claims.ExpiresAt > credential.expiresAt {
		return aauth.AuthTokenClaims{}, errors.New("auth-token lifetime exceeds the " + credential.expirySource)
	}
	return claims, nil
}

func fail(operation string, cause error) error {
	return &Error{Operation: operation, Cause: cause}
}

type personServerMetadata struct {
	Issuer              string `json:"issuer"`
	PersonTokenEndpoint string `json:"person_token_endpoint"`
	AuthTokenEndpoint   string `json:"auth_token_endpoint"`
	MissionEndpoint     string `json:"mission_endpoint"`
	JWKSURI             string `json:"jwks_uri"`
}

type resourceMetadata struct {
	Issuer                        string            `json:"issuer"`
	AuthorizationEndpoint         string            `json:"authorization_endpoint"`
	JWKSURI                       string            `json:"jwks_uri"`
	AccessMode                    string            `json:"access_mode"`
	ScopeDescriptions             map[string]string `json:"scope_descriptions"`
	AdditionalSignatureComponents []string          `json:"additional_signature_components"`
}

func (client *Client) personServerMetadata(ctx context.Context, issuer string) (personServerMetadata, error) {
	var metadata personServerMetadata
	if err := client.fetchMetadata(ctx, issuer+"/.well-known/aauth-person.json", &metadata); err != nil {
		return personServerMetadata{}, fmt.Errorf("person-server metadata: %w", err)
	}
	if metadata.Issuer != issuer {
		return personServerMetadata{}, errors.New("person-server metadata issuer does not match requested issuer")
	}
	if err := aauth.ValidateEndpoint(metadata.PersonTokenEndpoint); err != nil {
		return personServerMetadata{}, fmt.Errorf("person-server metadata person_token_endpoint: %w", err)
	}
	if err := aauth.ValidateEndpoint(metadata.AuthTokenEndpoint); err != nil {
		return personServerMetadata{}, fmt.Errorf("person-server metadata auth_token_endpoint: %w", err)
	}
	return metadata, nil
}

func (client *Client) resourceMetadata(ctx context.Context, issuer string) (resourceMetadata, error) {
	var metadata resourceMetadata
	if err := client.fetchMetadata(ctx, issuer+"/.well-known/aauth-resource.json", &metadata); err != nil {
		return resourceMetadata{}, fmt.Errorf("resource metadata: %w", err)
	}
	if metadata.Issuer != issuer {
		return resourceMetadata{}, errors.New("resource metadata issuer does not match requested issuer")
	}
	if metadata.AuthorizationEndpoint != "" {
		if err := aauth.ValidateEndpoint(metadata.AuthorizationEndpoint); err != nil {
			return resourceMetadata{}, fmt.Errorf("resource metadata authorization_endpoint: %w", err)
		}
	}
	return metadata, nil
}

func (client *Client) fetchMetadata(ctx context.Context, endpoint string, destination any) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	request.Header.Set("Accept", "application/json")
	response, err := client.httpClient.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return responseFailure(response)
	}
	return decodeMetadataResponse(response, destination)
}

func (client *Client) signJSONRequest(request *http.Request, compact string) error {
	return signaturekey.SignJWTRequestWithOptions(
		request,
		client.signingKey,
		compact,
		client.clock,
		signaturekey.SignOptions{
			AdditionalComponents: []string{"content-type", "content-digest"},
			MaxBodyBytes:         client.maxSignedBodyBytes,
		},
	)
}

func (client *Client) signResourceRequest(request *http.Request, compact string, components []string) error {
	options := signaturekey.SignOptions{AdditionalComponents: append([]string(nil), components...)}
	if containsFold(components, "content-digest") {
		options.MaxBodyBytes = client.maxSignedBodyBytes
	}
	return signaturekey.SignJWTRequestWithOptions(request, client.signingKey, compact, client.clock, options)
}

func authorizationSignatureComponents(additional []string) []string {
	components := []string{"content-type", "content-digest"}
	for _, component := range additional {
		if !containsFold(components, component) {
			components = append(components, component)
		}
	}
	return components
}

func newJSONRequest(ctx context.Context, endpoint string, body []byte) (*http.Request, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Content-Type", "application/json")
	return request, nil
}

func decodeJSONResponse(response *http.Response, destination any) error {
	return decodeResponseJSON(response, destination)
}

func decodeMetadataResponse(response *http.Response, destination any) error {
	return decodeResponseJSON(response, destination)
}

func decodeResponseJSON(response *http.Response, destination any) error {
	if response == nil || response.Body == nil {
		return errors.New("response body is required")
	}
	mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return errors.New("response must use application/json")
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}
	if len(body) > maxResponseBytes {
		return errors.New("response is too large")
	}
	if err := jsonstrict.RejectAmbiguousNames(body); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	if err := jsonstrict.RejectCaseVariants(body, destination); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	if err := decoder.Decode(destination); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("response must contain one JSON value")
	}
	return nil
}

func inspectAAuthProblem(response *http.Response) (*aauth.ProblemError, bool, error) {
	original := response.Body
	body, err := io.ReadAll(io.LimitReader(original, maxResponseBytes+1))
	if err != nil {
		return nil, false, fmt.Errorf("read protected response: %w", err)
	}
	if len(body) > maxResponseBytes {
		response.Body = &restoredBody{
			Reader: io.MultiReader(bytes.NewReader(body), original),
			Closer: original,
		}
		return nil, false, nil
	}
	_ = original.Close()
	response.Body = io.NopCloser(bytes.NewReader(body))
	copy := *response
	copy.Body = io.NopCloser(bytes.NewReader(body))
	problem, err := aauth.DecodeProblemResponse(&copy)
	if err != nil {
		return nil, false, nil
	}
	return problem, true, nil
}

type restoredBody struct {
	io.Reader
	io.Closer
}

func responseFailure(response *http.Response) error {
	if response != nil && response.StatusCode == http.StatusUnauthorized {
		signatureError, err := signaturekey.DecodeErrorResponse(response)
		if err != nil {
			return err
		}
		return signatureError
	}
	if isProblemResponse(response) {
		problem, err := aauth.DecodeProblemResponse(response)
		if err != nil {
			return err
		}
		return problem
	}
	body, _ := io.ReadAll(io.LimitReader(response.Body, 8<<10))
	return fmt.Errorf("server returned HTTP %d: %s", response.StatusCode, strings.TrimSpace(string(body)))
}

func isProblemResponse(response *http.Response) bool {
	if response == nil {
		return false
	}
	mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	return err == nil && mediaType == "application/problem+json"
}

func validateScopes(scopes []string) ([]string, error) {
	if len(scopes) == 0 {
		return nil, errors.New("at least one scope is required")
	}
	result := make([]string, len(scopes))
	seen := make(map[string]struct{}, len(scopes))
	for index, scope := range scopes {
		if err := aauth.ValidateScopeValue(scope); err != nil {
			return nil, err
		}
		if _, duplicate := seen[scope]; duplicate {
			return nil, fmt.Errorf("duplicate scope %q", scope)
		}
		seen[scope] = struct{}{}
		result[index] = scope
	}
	return result, nil
}

func scopeSubset(granted, requested []string) bool {
	if len(granted) == 0 {
		return false
	}
	seen := make(map[string]struct{}, len(granted))
	for _, scope := range granted {
		if _, duplicate := seen[scope]; duplicate {
			return false
		}
		seen[scope] = struct{}{}
		if !slices.Contains(requested, scope) {
			return false
		}
	}
	return true
}

func sameScopeSet(first, second []string) bool {
	if len(first) != len(second) {
		return false
	}
	for _, scope := range first {
		if !slices.Contains(second, scope) {
			return false
		}
	}
	return true
}

func containsFold(values []string, target string) bool {
	for _, value := range values {
		if strings.EqualFold(value, target) {
			return true
		}
	}
	return false
}

func requestOrigin(target *url.URL) (string, error) {
	if target == nil || target.Scheme != "https" || target.Host == "" || target.User != nil ||
		target.Fragment != "" || target.Opaque != "" {
		return "", errors.New("request requires an absolute HTTPS URL without userinfo or fragment")
	}
	origin := target.Scheme + "://" + target.Host
	if err := aauth.ValidateServerIdentifier(origin); err != nil {
		return "", err
	}
	return origin, nil
}
