package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

// BootstrapConfig supplies the application-selected endpoints and
// dependencies for the repository's hosted Bootstrap profiles.
type BootstrapConfig struct {
	AgentProvider      string
	EnrollmentEndpoint string
	RefreshEndpoint    string
	DurableKey         jose.SigningKey
	KeyResolver        signaturekey.KeyResolver
	HTTPClient         *http.Client
	Clock              aauth.Clock
	MaxSignedBodyBytes int64
}

// BootstrapClient performs one enrollment or Agent-token refresh exchange.
// It does not discover endpoints, retry, poll, or mutate an authenticated
// Client.
type BootstrapClient struct {
	agentProvider      string
	enrollmentEndpoint string
	refreshEndpoint    string
	durableKey         jose.SigningKey
	keyResolver        signaturekey.KeyResolver
	httpClient         *http.Client
	clock              aauth.Clock
	maxSignedBodyBytes int64
}

// EnrollmentResult is the stable top-level Agent identity assigned by the
// Agent Provider.
type EnrollmentResult struct {
	Agent string
}

// RefreshAgentTokenInput requests one Agent token bound to SigningKey. A lost
// response is recovered by reusing every field, including the exact Evidence
// bytes, key, JTI, and delegation times. The client reconstructs the stable
// naming JWT and freshly signs the outer HTTP request.
type RefreshAgentTokenInput struct {
	Agent               string
	PersonServer        string
	Evidence            json.RawMessage
	SigningKey          jose.SigningKey
	DelegationJTI       string
	DelegationIssuedAt  time.Time
	DelegationExpiresAt time.Time
}

// SingleKeyRefreshAgentTokenInput requests one Agent token bound to the
// already-enrolled durable key. RefreshJTI and RefreshExpiresAt identify the
// exact replayable request in this repository profile.
type SingleKeyRefreshAgentTokenInput struct {
	Agent            string
	PersonServer     string
	Evidence         json.RawMessage
	RefreshJTI       string
	RefreshExpiresAt time.Time
}

// RefreshAgentTokenResult contains the exact token and its verified claims.
type RefreshAgentTokenResult struct {
	AgentToken string
	Claims     aauth.AgentTokenClaims
}

// NewBootstrapClient constructs the explicit hosted Bootstrap caller. The
// endpoint URLs are an AAuth Go profile choice because Bootstrap does not
// define portable endpoint discovery or request envelopes.
func NewBootstrapClient(config BootstrapConfig) (*BootstrapClient, error) {
	if err := aauth.ValidateServerIdentifier(config.AgentProvider); err != nil {
		return nil, fmt.Errorf("aauth agent: bootstrap Agent Provider: %w", err)
	}
	for name, endpoint := range map[string]string{
		"enrollment endpoint": config.EnrollmentEndpoint,
		"refresh endpoint":    config.RefreshEndpoint,
	} {
		if err := validateBootstrapEndpoint(endpoint, config.AgentProvider); err != nil {
			return nil, fmt.Errorf("aauth agent: bootstrap %s: %w", name, err)
		}
	}
	if config.DurableKey.ID() == "" {
		return nil, errors.New("aauth agent: bootstrap durable key is required")
	}
	if _, err := config.DurableKey.PublicJWK().PublicKey(); err != nil {
		return nil, fmt.Errorf("aauth agent: bootstrap durable key: %w", err)
	}
	if config.KeyResolver == nil || config.HTTPClient == nil || config.Clock == nil {
		return nil, errors.New("aauth agent: bootstrap key resolver, HTTP client, and clock are required")
	}
	if config.MaxSignedBodyBytes < 0 {
		return nil, errors.New("aauth agent: bootstrap maximum signed body size must not be negative")
	}
	httpClient := *config.HTTPClient
	httpClient.CheckRedirect = func(*http.Request, []*http.Request) error {
		return errors.New("aauth agent: HTTP redirects are not permitted")
	}
	return &BootstrapClient{
		agentProvider: config.AgentProvider, enrollmentEndpoint: config.EnrollmentEndpoint,
		refreshEndpoint: config.RefreshEndpoint, durableKey: config.DurableKey,
		keyResolver: config.KeyResolver, httpClient: &httpClient, clock: config.Clock,
		maxSignedBodyBytes: config.MaxSignedBodyBytes,
	}, nil
}

func validateBootstrapEndpoint(endpoint, agentProvider string) error {
	if err := aauth.ValidateEndpoint(endpoint); err != nil {
		return err
	}
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return err
	}
	if parsed.Scheme+"://"+parsed.Host != agentProvider {
		return errors.New("endpoint must use the Agent Provider origin")
	}
	return nil
}

// Enroll performs one hwk-signed enrollment request.
func (client *BootstrapClient) Enroll(ctx context.Context, evidence json.RawMessage) (EnrollmentResult, error) {
	const operation = "bootstrap enrollment"
	if client == nil {
		return EnrollmentResult{}, fail(operation, errors.New("bootstrap client is required"))
	}
	if ctx == nil {
		return EnrollmentResult{}, fail(operation, errors.New("context is required"))
	}
	if !json.Valid(evidence) {
		return EnrollmentResult{}, fail(operation, errors.New("enrollment evidence must be valid JSON"))
	}
	body, err := json.Marshal(struct {
		Evidence json.RawMessage `json:"evidence"`
	}{Evidence: evidence})
	if err != nil {
		return EnrollmentResult{}, fail(operation, err)
	}
	request, err := newJSONRequest(ctx, client.enrollmentEndpoint, body)
	if err != nil {
		return EnrollmentResult{}, fail(operation, err)
	}
	credential, err := signaturekey.NewHWKCredential(client.durableKey.PublicJWK())
	if err != nil {
		return EnrollmentResult{}, fail(operation, err)
	}
	if err := signaturekey.SignRequest(request, client.durableKey, credential, client.clock, signaturekey.SignOptions{
		AdditionalComponents: []string{"content-type", "content-digest"},
		MaxBodyBytes:         client.maxSignedBodyBytes,
	}); err != nil {
		return EnrollmentResult{}, fail(operation, err)
	}
	response, err := client.httpClient.Do(request)
	if err != nil {
		return EnrollmentResult{}, fail(operation, err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusCreated {
		return EnrollmentResult{}, fail(operation, responseFailure(response))
	}
	if err := requireNoStore(response); err != nil {
		return EnrollmentResult{}, fail(operation, err)
	}
	var output struct {
		Agent string `json:"agent"`
	}
	if err := decodeJSONResponse(response, &output); err != nil {
		return EnrollmentResult{}, fail(operation, err)
	}
	if err := validateBootstrapAgent(output.Agent, client.agentProvider); err != nil {
		return EnrollmentResult{}, fail(operation, err)
	}
	return EnrollmentResult{Agent: output.Agent}, nil
}

// Refresh performs one jkt-jwt-signed refresh request and verifies the exact
// returned Agent token before exposing it.
func (client *BootstrapClient) Refresh(
	ctx context.Context,
	input RefreshAgentTokenInput,
) (RefreshAgentTokenResult, error) {
	const operation = "bootstrap refresh"
	if client == nil {
		return RefreshAgentTokenResult{}, fail(operation, errors.New("bootstrap client is required"))
	}
	if ctx == nil {
		return RefreshAgentTokenResult{}, fail(operation, errors.New("context is required"))
	}
	if err := validateBootstrapAgent(input.Agent, client.agentProvider); err != nil {
		return RefreshAgentTokenResult{}, fail(operation, err)
	}
	if input.PersonServer != "" {
		if err := aauth.ValidateServerIdentifier(input.PersonServer); err != nil {
			return RefreshAgentTokenResult{}, fail(operation, fmt.Errorf("Person Server: %w", err))
		}
	}
	if input.SigningKey.ID() == "" {
		return RefreshAgentTokenResult{}, fail(operation, errors.New("delegated signing key is required"))
	}
	if _, err := input.SigningKey.PublicJWK().PublicKey(); err != nil {
		return RefreshAgentTokenResult{}, fail(operation, fmt.Errorf("delegated signing key: %w", err))
	}
	if input.SigningKey.PublicJWK().Equal(client.durableKey.PublicJWK()) {
		return RefreshAgentTokenResult{}, fail(operation, errors.New("delegated signing key must differ from durable key"))
	}
	if strings.TrimSpace(input.DelegationJTI) == "" || input.DelegationJTI != strings.TrimSpace(input.DelegationJTI) {
		return RefreshAgentTokenResult{}, fail(operation, errors.New("delegation JTI is required without surrounding whitespace"))
	}
	if !json.Valid(input.Evidence) {
		return RefreshAgentTokenResult{}, fail(operation, errors.New("refresh evidence must be valid JSON"))
	}
	now := client.clock.Now().UTC()
	if input.DelegationIssuedAt.IsZero() {
		return RefreshAgentTokenResult{}, fail(operation, errors.New("delegation issued time is required"))
	}
	issuedAt := input.DelegationIssuedAt.UTC().Truncate(time.Second)
	expiresAt := input.DelegationExpiresAt.UTC().Truncate(time.Second)
	if issuedAt.After(now) {
		return RefreshAgentTokenResult{}, fail(operation, errors.New("delegation issued time must not be in the future"))
	}
	if !expiresAt.After(issuedAt) {
		return RefreshAgentTokenResult{}, fail(operation, errors.New("delegation expiry must be after its issued time"))
	}
	if !expiresAt.After(now) {
		return RefreshAgentTokenResult{}, fail(operation, errors.New("delegation has expired"))
	}
	compact, err := signaturekey.MintJKTJWT(
		client.durableKey, input.SigningKey.PublicJWK(), issuedAt,
		expiresAt, input.DelegationJTI,
	)
	if err != nil {
		return RefreshAgentTokenResult{}, fail(operation, err)
	}
	return client.refreshAgentToken(ctx, input, compact)
}

// RefreshSingleKey performs one hwk-signed refresh with the enrolled durable
// key and verifies that the returned Agent token remains bound to that key.
func (client *BootstrapClient) RefreshSingleKey(
	ctx context.Context,
	input SingleKeyRefreshAgentTokenInput,
) (RefreshAgentTokenResult, error) {
	const operation = "bootstrap single-key refresh"
	if client == nil {
		return RefreshAgentTokenResult{}, fail(operation, errors.New("bootstrap client is required"))
	}
	if ctx == nil {
		return RefreshAgentTokenResult{}, fail(operation, errors.New("context is required"))
	}
	if err := validateBootstrapAgent(input.Agent, client.agentProvider); err != nil {
		return RefreshAgentTokenResult{}, fail(operation, err)
	}
	if input.PersonServer != "" {
		if err := aauth.ValidateServerIdentifier(input.PersonServer); err != nil {
			return RefreshAgentTokenResult{}, fail(operation, fmt.Errorf("Person Server: %w", err))
		}
	}
	if !json.Valid(input.Evidence) {
		return RefreshAgentTokenResult{}, fail(operation, errors.New("refresh evidence must be valid JSON"))
	}
	if strings.TrimSpace(input.RefreshJTI) == "" || input.RefreshJTI != strings.TrimSpace(input.RefreshJTI) {
		return RefreshAgentTokenResult{}, fail(operation, errors.New("refresh JTI is required without surrounding whitespace"))
	}
	now := client.clock.Now().UTC().Truncate(time.Second)
	expiresAt := input.RefreshExpiresAt.UTC().Truncate(time.Second)
	if !expiresAt.After(now) || expiresAt.After(now.Add(24*time.Hour)) {
		return RefreshAgentTokenResult{}, fail(operation, errors.New("refresh expiry must be within 24 hours"))
	}
	body, err := json.Marshal(struct {
		PersonServer     string          `json:"ps,omitempty"`
		Evidence         json.RawMessage `json:"evidence"`
		RefreshJTI       string          `json:"refresh_jti"`
		RefreshExpiresAt int64           `json:"refresh_expires_at"`
	}{
		PersonServer:     input.PersonServer,
		Evidence:         input.Evidence,
		RefreshJTI:       input.RefreshJTI,
		RefreshExpiresAt: expiresAt.Unix(),
	})
	if err != nil {
		return RefreshAgentTokenResult{}, fail(operation, err)
	}
	request, err := newJSONRequest(ctx, client.refreshEndpoint, body)
	if err != nil {
		return RefreshAgentTokenResult{}, fail(operation, err)
	}
	credential, err := signaturekey.NewHWKCredential(client.durableKey.PublicJWK())
	if err != nil {
		return RefreshAgentTokenResult{}, fail(operation, err)
	}
	if err := signaturekey.SignRequest(request, client.durableKey, credential, client.clock, signaturekey.SignOptions{
		AdditionalComponents: []string{"content-type", "content-digest"},
		MaxBodyBytes:         client.maxSignedBodyBytes,
	}); err != nil {
		return RefreshAgentTokenResult{}, fail(operation, err)
	}
	response, err := client.httpClient.Do(request)
	if err != nil {
		return RefreshAgentTokenResult{}, fail(operation, err)
	}
	result, err := client.readRefreshAgentTokenResponse(
		ctx,
		response,
		input.Agent,
		input.PersonServer,
		client.durableKey.PublicJWK(),
	)
	if err != nil {
		return RefreshAgentTokenResult{}, fail(operation, err)
	}
	return result, nil
}

func (client *BootstrapClient) refreshAgentToken(
	ctx context.Context,
	input RefreshAgentTokenInput,
	delegation string,
) (RefreshAgentTokenResult, error) {
	const operation = "bootstrap refresh"
	body, err := json.Marshal(struct {
		PersonServer string          `json:"ps,omitempty"`
		Evidence     json.RawMessage `json:"evidence"`
	}{PersonServer: input.PersonServer, Evidence: input.Evidence})
	if err != nil {
		return RefreshAgentTokenResult{}, fail(operation, err)
	}
	request, err := newJSONRequest(ctx, client.refreshEndpoint, body)
	if err != nil {
		return RefreshAgentTokenResult{}, fail(operation, err)
	}
	credential, err := signaturekey.NewJKTJWTCredential(delegation)
	if err != nil {
		return RefreshAgentTokenResult{}, fail(operation, err)
	}
	if err := signaturekey.SignRequest(request, input.SigningKey, credential, client.clock, signaturekey.SignOptions{
		AdditionalComponents: []string{"content-type", "content-digest"},
		MaxBodyBytes:         client.maxSignedBodyBytes,
	}); err != nil {
		return RefreshAgentTokenResult{}, fail(operation, err)
	}
	response, err := client.httpClient.Do(request)
	if err != nil {
		return RefreshAgentTokenResult{}, fail(operation, err)
	}
	result, err := client.readRefreshAgentTokenResponse(
		ctx,
		response,
		input.Agent,
		input.PersonServer,
		input.SigningKey.PublicJWK(),
	)
	if err != nil {
		return RefreshAgentTokenResult{}, fail(operation, err)
	}
	return result, nil
}

func (client *BootstrapClient) readRefreshAgentTokenResponse(
	ctx context.Context,
	response *http.Response,
	agent string,
	personServer string,
	confirmation jose.JWK,
) (RefreshAgentTokenResult, error) {
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return RefreshAgentTokenResult{}, responseFailure(response)
	}
	if err := requireNoStore(response); err != nil {
		return RefreshAgentTokenResult{}, err
	}
	var output struct {
		AgentToken string `json:"agent_token"`
	}
	if err := decodeJSONResponse(response, &output); err != nil {
		return RefreshAgentTokenResult{}, err
	}
	if output.AgentToken == "" {
		return RefreshAgentTokenResult{}, errors.New("response agent_token is required")
	}
	claims, err := aauth.VerifyAgentToken(
		ctx,
		output.AgentToken,
		bindResolverToIssuer(client.keyResolver, client.agentProvider),
		client.clock,
	)
	if err != nil {
		return RefreshAgentTokenResult{}, fmt.Errorf("verify Agent token: %w", err)
	}
	if claims.Issuer != client.agentProvider || claims.Subject != agent ||
		claims.PersonServer != personServer || claims.ParentAgent != "" ||
		!claims.Confirmation.JWK.Equal(confirmation) {
		return RefreshAgentTokenResult{}, errors.New("returned Agent token does not match the refresh request")
	}
	return RefreshAgentTokenResult{AgentToken: output.AgentToken, Claims: claims}, nil
}

type issuerBoundResolver struct {
	expected string
	resolver signaturekey.KeyResolver
}

func bindResolverToIssuer(resolver signaturekey.KeyResolver, expected string) signaturekey.KeyResolver {
	bound := issuerBoundResolver{expected: expected, resolver: resolver}
	if refresher, ok := resolver.(signaturekey.KeyRefresher); ok {
		return issuerBoundRefreshingResolver{issuerBoundResolver: bound, refresher: refresher}
	}
	return bound
}

func (resolver issuerBoundResolver) ResolveKey(
	ctx context.Context,
	issuer, discoveryDocument, keyID string,
) (jose.JWK, error) {
	if issuer != resolver.expected {
		return jose.JWK{}, resolver.issuerMismatch(issuer)
	}
	return resolver.resolver.ResolveKey(ctx, issuer, discoveryDocument, keyID)
}

func (resolver issuerBoundResolver) issuerMismatch(issuer string) error {
	return &signaturekey.ResolutionError{
		Code: signaturekey.ResolutionIssuerMismatch,
		Cause: fmt.Errorf(
			"aauth agent: Agent token issuer %q does not match Agent Provider %q",
			issuer,
			resolver.expected,
		),
	}
}

type issuerBoundRefreshingResolver struct {
	issuerBoundResolver
	refresher signaturekey.KeyRefresher
}

func (resolver issuerBoundRefreshingResolver) RefreshKey(
	ctx context.Context,
	issuer, discoveryDocument, keyID string,
) (jose.JWK, error) {
	if issuer != resolver.expected {
		return jose.JWK{}, resolver.issuerMismatch(issuer)
	}
	return resolver.refresher.RefreshKey(ctx, issuer, discoveryDocument, keyID)
}

func validateBootstrapAgent(identifier, agentProvider string) error {
	if err := aauth.ValidateAgentIdentifier(identifier); err != nil {
		return err
	}
	if err := aauth.ValidateAgentRelationship(identifier, ""); err != nil {
		return err
	}
	return aauth.ValidateAgentIssuer(identifier, agentProvider)
}

func requireNoStore(response *http.Response) error {
	for _, line := range response.Header.Values("Cache-Control") {
		for _, directive := range strings.Split(line, ",") {
			if strings.EqualFold(strings.TrimSpace(directive), "no-store") {
				return nil
			}
		}
	}
	return errors.New("credential response requires Cache-Control: no-store")
}
