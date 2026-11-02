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
// It does not discover endpoints, retry, or mutate an authenticated Client.
// The Begin methods return a Pending when the Agent Provider defers the
// exchange; the caller polls it. NeedsRefresh tells the caller when the Agent
// token it holds is due for refresh.
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
// already-enrolled durable key. RefreshJTI and RefreshExpiresAt are optional
// and set together: they identify the exact request so that a lost answer can
// be recovered with a freshly signed retry until RefreshExpiresAt. Without
// them the request is Bootstrap's bare single-key refresh, which the Agent
// Provider identifies by its signature, so a retry is a new refresh.
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

// RefreshMargin is the time before an Agent token's exp inside which the
// Agent refreshes it. AAuth Core, Expiry and the Refresh Margin, recommends
// five minutes, and Bootstrap's Refresh Patterns apply it to Agent tokens.
const RefreshMargin = 5 * time.Minute

// NeedsRefresh reports whether the Agent token with these claims is inside
// RefreshMargin at the client's clock: fewer than five minutes remain before
// its exp, so exactly five minutes left is outside the margin. A token past
// its exp, and claims without an exp, need a refresh too. The decision only
// reads the clock; the caller performs the refresh.
func (client *BootstrapClient) NeedsRefresh(claims aauth.AgentTokenClaims) bool {
	if client == nil || claims.ExpiresAt == 0 {
		return true
	}
	return time.Unix(claims.ExpiresAt, 0).Sub(client.clock.Now()) < RefreshMargin
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

// Enroll performs one hwk-signed enrollment request. When the Agent Provider
// defers enrollment, the error is a *PendingError[EnrollmentResult] that
// carries the pending enrollment; BeginEnroll returns it as a Result.
func (client *BootstrapClient) Enroll(ctx context.Context, evidence json.RawMessage) (EnrollmentResult, error) {
	const operation = "bootstrap enrollment"
	result, err := client.beginEnroll(ctx, evidence, operation)
	if err != nil {
		return EnrollmentResult{}, err
	}
	return completed(operation, result)
}

// BeginEnroll performs the same single enrollment request as Enroll and
// returns the enrollment, or the pending enrollment when the Agent Provider
// answers 202, for example while it reviews the evidence. Polls are signed
// with the durable key under hwk, as the request was.
func (client *BootstrapClient) BeginEnroll(ctx context.Context, evidence json.RawMessage) (Result[EnrollmentResult], error) {
	return client.beginEnroll(ctx, evidence, "begin bootstrap enrollment")
}

func (client *BootstrapClient) beginEnroll(
	ctx context.Context,
	evidence json.RawMessage,
	operation string,
) (Result[EnrollmentResult], error) {
	if client == nil {
		return Result[EnrollmentResult]{}, fail(operation, errors.New("bootstrap client is required"))
	}
	if ctx == nil {
		return Result[EnrollmentResult]{}, fail(operation, errors.New("context is required"))
	}
	if !json.Valid(evidence) {
		return Result[EnrollmentResult]{}, fail(operation, errors.New("enrollment evidence must be valid JSON"))
	}
	body, err := json.Marshal(struct {
		Evidence json.RawMessage `json:"evidence"`
	}{Evidence: evidence})
	if err != nil {
		return Result[EnrollmentResult]{}, fail(operation, err)
	}
	request, err := newJSONRequest(ctx, client.enrollmentEndpoint, body)
	if err != nil {
		return Result[EnrollmentResult]{}, fail(operation, err)
	}
	credential, err := signaturekey.NewHWKCredential(client.durableKey.PublicJWK())
	if err != nil {
		return Result[EnrollmentResult]{}, fail(operation, err)
	}
	if err := signaturekey.SignRequest(request, client.durableKey, credential, client.clock, signaturekey.SignOptions{
		AdditionalComponents: []string{"content-type", "content-digest"},
		MaxBodyBytes:         client.maxSignedBodyBytes,
	}); err != nil {
		return Result[EnrollmentResult]{}, fail(operation, err)
	}
	response, err := client.httpClient.Do(request)
	if err != nil {
		return Result[EnrollmentResult]{}, fail(operation, err)
	}
	flow := newBootstrapPendingFlow(client, "enrollment", client.durableKey, credential, client.readEnrollment)
	result, err := flow.begin(ctx, response)
	if err != nil {
		return Result[EnrollmentResult]{}, fail(operation, err)
	}
	return result, nil
}

func (client *BootstrapClient) readEnrollment(_ context.Context, response *http.Response) (EnrollmentResult, error) {
	if response.StatusCode != http.StatusCreated {
		return EnrollmentResult{}, responseFailure(response)
	}
	if err := requireNoStore(response); err != nil {
		return EnrollmentResult{}, err
	}
	var output struct {
		Agent string `json:"agent"`
	}
	if err := decodeJSONResponse(response, &output); err != nil {
		return EnrollmentResult{}, err
	}
	if err := validateBootstrapAgent(output.Agent, client.agentProvider); err != nil {
		return EnrollmentResult{}, err
	}
	return EnrollmentResult{Agent: output.Agent}, nil
}

// newBootstrapPendingFlow returns a flow whose polls are signed by key under
// credential, the same Signature-Key scheme as the original request.
func newBootstrapPendingFlow[T any](
	client *BootstrapClient,
	name string,
	key jose.SigningKey,
	credential signaturekey.Credential,
	complete func(context.Context, *http.Response) (T, error),
) *pendingFlow[T] {
	return &pendingFlow[T]{
		name: name, httpClient: client.httpClient, clock: client.clock,
		sign: func(request *http.Request) error {
			return signaturekey.SignRequest(request, key, credential, client.clock, signaturekey.SignOptions{
				MaxBodyBytes: client.maxSignedBodyBytes,
			})
		},
		complete: complete,
	}
}

// Refresh performs one jkt-jwt-signed refresh request and verifies the exact
// returned Agent token before exposing it. When the Agent Provider defers the
// refresh, the error is a *PendingError[RefreshAgentTokenResult] that carries
// the pending refresh; BeginRefresh returns it as a Result.
func (client *BootstrapClient) Refresh(
	ctx context.Context,
	input RefreshAgentTokenInput,
) (RefreshAgentTokenResult, error) {
	const operation = "bootstrap refresh"
	result, err := client.beginRefresh(ctx, input, operation)
	if err != nil {
		return RefreshAgentTokenResult{}, err
	}
	return completed(operation, result)
}

// BeginRefresh performs the same single refresh request as Refresh and
// returns the verified Agent token, or the pending refresh when the Agent
// Provider answers 202. Polls are signed with the delegated key under the same
// jkt-jwt delegation, so they must finish before it expires.
func (client *BootstrapClient) BeginRefresh(
	ctx context.Context,
	input RefreshAgentTokenInput,
) (Result[RefreshAgentTokenResult], error) {
	return client.beginRefresh(ctx, input, "begin bootstrap refresh")
}

func (client *BootstrapClient) beginRefresh(
	ctx context.Context,
	input RefreshAgentTokenInput,
	operation string,
) (Result[RefreshAgentTokenResult], error) {
	if client == nil {
		return Result[RefreshAgentTokenResult]{}, fail(operation, errors.New("bootstrap client is required"))
	}
	if ctx == nil {
		return Result[RefreshAgentTokenResult]{}, fail(operation, errors.New("context is required"))
	}
	if err := validateBootstrapAgent(input.Agent, client.agentProvider); err != nil {
		return Result[RefreshAgentTokenResult]{}, fail(operation, err)
	}
	if input.PersonServer != "" {
		if err := aauth.ValidateServerIdentifier(input.PersonServer); err != nil {
			return Result[RefreshAgentTokenResult]{}, fail(operation, fmt.Errorf("Person Server: %w", err))
		}
	}
	if input.SigningKey.ID() == "" {
		return Result[RefreshAgentTokenResult]{}, fail(operation, errors.New("delegated signing key is required"))
	}
	if _, err := input.SigningKey.PublicJWK().PublicKey(); err != nil {
		return Result[RefreshAgentTokenResult]{}, fail(operation, fmt.Errorf("delegated signing key: %w", err))
	}
	if input.SigningKey.PublicJWK().Equal(client.durableKey.PublicJWK()) {
		return Result[RefreshAgentTokenResult]{}, fail(operation, errors.New("delegated signing key must differ from durable key"))
	}
	if strings.TrimSpace(input.DelegationJTI) == "" || input.DelegationJTI != strings.TrimSpace(input.DelegationJTI) {
		return Result[RefreshAgentTokenResult]{}, fail(operation, errors.New("delegation JTI is required without surrounding whitespace"))
	}
	if !json.Valid(input.Evidence) {
		return Result[RefreshAgentTokenResult]{}, fail(operation, errors.New("refresh evidence must be valid JSON"))
	}
	now := client.clock.Now().UTC()
	if input.DelegationIssuedAt.IsZero() {
		return Result[RefreshAgentTokenResult]{}, fail(operation, errors.New("delegation issued time is required"))
	}
	issuedAt := input.DelegationIssuedAt.UTC().Truncate(time.Second)
	expiresAt := input.DelegationExpiresAt.UTC().Truncate(time.Second)
	if issuedAt.After(now) {
		return Result[RefreshAgentTokenResult]{}, fail(operation, errors.New("delegation issued time must not be in the future"))
	}
	if !expiresAt.After(issuedAt) {
		return Result[RefreshAgentTokenResult]{}, fail(operation, errors.New("delegation expiry must be after its issued time"))
	}
	if !expiresAt.After(now) {
		return Result[RefreshAgentTokenResult]{}, fail(operation, errors.New("delegation has expired"))
	}
	compact, err := signaturekey.MintJKTJWT(
		client.durableKey, input.SigningKey.PublicJWK(), issuedAt,
		expiresAt, input.DelegationJTI,
	)
	if err != nil {
		return Result[RefreshAgentTokenResult]{}, fail(operation, err)
	}
	return client.refreshAgentToken(ctx, input, compact, operation)
}

// RefreshSingleKey performs one hwk-signed refresh with the enrolled durable
// key and verifies that the returned Agent token remains bound to that key.
// A deferred refresh is a *PendingError[RefreshAgentTokenResult], as for
// Refresh.
func (client *BootstrapClient) RefreshSingleKey(
	ctx context.Context,
	input SingleKeyRefreshAgentTokenInput,
) (RefreshAgentTokenResult, error) {
	const operation = "bootstrap single-key refresh"
	result, err := client.beginRefreshSingleKey(ctx, input, operation)
	if err != nil {
		return RefreshAgentTokenResult{}, err
	}
	return completed(operation, result)
}

// BeginRefreshSingleKey performs the same single refresh request as
// RefreshSingleKey and returns the verified Agent token, or the pending
// refresh when the Agent Provider answers 202. Polls are signed with the
// durable key under hwk.
func (client *BootstrapClient) BeginRefreshSingleKey(
	ctx context.Context,
	input SingleKeyRefreshAgentTokenInput,
) (Result[RefreshAgentTokenResult], error) {
	return client.beginRefreshSingleKey(ctx, input, "begin bootstrap single-key refresh")
}

func (client *BootstrapClient) beginRefreshSingleKey(
	ctx context.Context,
	input SingleKeyRefreshAgentTokenInput,
	operation string,
) (Result[RefreshAgentTokenResult], error) {
	if client == nil {
		return Result[RefreshAgentTokenResult]{}, fail(operation, errors.New("bootstrap client is required"))
	}
	if ctx == nil {
		return Result[RefreshAgentTokenResult]{}, fail(operation, errors.New("context is required"))
	}
	if err := validateBootstrapAgent(input.Agent, client.agentProvider); err != nil {
		return Result[RefreshAgentTokenResult]{}, fail(operation, err)
	}
	if input.PersonServer != "" {
		if err := aauth.ValidateServerIdentifier(input.PersonServer); err != nil {
			return Result[RefreshAgentTokenResult]{}, fail(operation, fmt.Errorf("Person Server: %w", err))
		}
	}
	if !json.Valid(input.Evidence) {
		return Result[RefreshAgentTokenResult]{}, fail(operation, errors.New("refresh evidence must be valid JSON"))
	}
	var expiresAt int64
	if input.RefreshJTI != "" || !input.RefreshExpiresAt.IsZero() {
		if strings.TrimSpace(input.RefreshJTI) == "" || input.RefreshJTI != strings.TrimSpace(input.RefreshJTI) {
			return Result[RefreshAgentTokenResult]{}, fail(operation, errors.New("refresh JTI is required without surrounding whitespace when a refresh expiry is set"))
		}
		now := client.clock.Now().UTC().Truncate(time.Second)
		expiry := input.RefreshExpiresAt.UTC().Truncate(time.Second)
		if !expiry.After(now) || expiry.After(now.Add(24*time.Hour)) {
			return Result[RefreshAgentTokenResult]{}, fail(operation, errors.New("refresh expiry must be within 24 hours"))
		}
		expiresAt = expiry.Unix()
	}
	body, err := json.Marshal(struct {
		PersonServer     string          `json:"ps,omitempty"`
		Evidence         json.RawMessage `json:"evidence"`
		RefreshJTI       string          `json:"refresh_jti,omitempty"`
		RefreshExpiresAt int64           `json:"refresh_expires_at,omitempty"`
	}{
		PersonServer:     input.PersonServer,
		Evidence:         input.Evidence,
		RefreshJTI:       input.RefreshJTI,
		RefreshExpiresAt: expiresAt,
	})
	if err != nil {
		return Result[RefreshAgentTokenResult]{}, fail(operation, err)
	}
	request, err := newJSONRequest(ctx, client.refreshEndpoint, body)
	if err != nil {
		return Result[RefreshAgentTokenResult]{}, fail(operation, err)
	}
	credential, err := signaturekey.NewHWKCredential(client.durableKey.PublicJWK())
	if err != nil {
		return Result[RefreshAgentTokenResult]{}, fail(operation, err)
	}
	if err := signaturekey.SignRequest(request, client.durableKey, credential, client.clock, signaturekey.SignOptions{
		AdditionalComponents: []string{"content-type", "content-digest"},
		MaxBodyBytes:         client.maxSignedBodyBytes,
	}); err != nil {
		return Result[RefreshAgentTokenResult]{}, fail(operation, err)
	}
	response, err := client.httpClient.Do(request)
	if err != nil {
		return Result[RefreshAgentTokenResult]{}, fail(operation, err)
	}
	flow := newBootstrapPendingFlow(client, "Agent-token refresh", client.durableKey, credential,
		client.refreshAgentTokenReader(input.Agent, input.PersonServer, client.durableKey.PublicJWK()))
	result, err := flow.begin(ctx, response)
	if err != nil {
		return Result[RefreshAgentTokenResult]{}, fail(operation, err)
	}
	return result, nil
}

func (client *BootstrapClient) refreshAgentToken(
	ctx context.Context,
	input RefreshAgentTokenInput,
	delegation string,
	operation string,
) (Result[RefreshAgentTokenResult], error) {
	body, err := json.Marshal(struct {
		PersonServer string          `json:"ps,omitempty"`
		Evidence     json.RawMessage `json:"evidence"`
	}{PersonServer: input.PersonServer, Evidence: input.Evidence})
	if err != nil {
		return Result[RefreshAgentTokenResult]{}, fail(operation, err)
	}
	request, err := newJSONRequest(ctx, client.refreshEndpoint, body)
	if err != nil {
		return Result[RefreshAgentTokenResult]{}, fail(operation, err)
	}
	credential, err := signaturekey.NewJKTJWTCredential(delegation)
	if err != nil {
		return Result[RefreshAgentTokenResult]{}, fail(operation, err)
	}
	if err := signaturekey.SignRequest(request, input.SigningKey, credential, client.clock, signaturekey.SignOptions{
		AdditionalComponents: []string{"content-type", "content-digest"},
		MaxBodyBytes:         client.maxSignedBodyBytes,
	}); err != nil {
		return Result[RefreshAgentTokenResult]{}, fail(operation, err)
	}
	response, err := client.httpClient.Do(request)
	if err != nil {
		return Result[RefreshAgentTokenResult]{}, fail(operation, err)
	}
	flow := newBootstrapPendingFlow(client, "Agent-token refresh", input.SigningKey, credential,
		client.refreshAgentTokenReader(input.Agent, input.PersonServer, input.SigningKey.PublicJWK()))
	result, err := flow.begin(ctx, response)
	if err != nil {
		return Result[RefreshAgentTokenResult]{}, fail(operation, err)
	}
	return result, nil
}

// refreshAgentTokenReader checks a refresh answer for agent, personServer and
// the key the new Agent token must confirm.
func (client *BootstrapClient) refreshAgentTokenReader(
	agent string,
	personServer string,
	confirmation jose.JWK,
) func(context.Context, *http.Response) (RefreshAgentTokenResult, error) {
	return func(ctx context.Context, response *http.Response) (RefreshAgentTokenResult, error) {
		return client.readRefreshAgentTokenResponse(ctx, response, agent, personServer, confirmation)
	}
}

func (client *BootstrapClient) readRefreshAgentTokenResponse(
	ctx context.Context,
	response *http.Response,
	agent string,
	personServer string,
	confirmation jose.JWK,
) (RefreshAgentTokenResult, error) {
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
