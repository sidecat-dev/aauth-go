package reference

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"

	aauth "gitlab.com/sidecat-dev/aauth-go"
)

type BootstrapClientConfig struct {
	DurableKey         jose.SigningKey
	KeyResolver        signaturekey.KeyResolver
	HTTPClient         *http.Client
	Clock              aauth.Clock
	DelegationLifetime time.Duration
}

// BootstrapClient holds the durable installation identity and performs the
// AP's two-key refresh profile. The returned ephemeral key remains
// caller-owned and is never retained by the client.
type BootstrapClient struct {
	durableKey         jose.SigningKey
	keyResolver        signaturekey.KeyResolver
	httpClient         *http.Client
	clock              aauth.Clock
	delegationLifetime time.Duration
}

type BootstrapResult struct {
	Identifier string
	SigningKey jose.SigningKey
	AgentToken string
	Claims     aauth.AgentTokenClaims
}

func NewBootstrapClient(config BootstrapClientConfig) (*BootstrapClient, error) {
	if config.DurableKey.ID() == "" || config.KeyResolver == nil ||
		config.HTTPClient == nil || config.Clock == nil {
		return nil, errors.New("reference: bootstrap client requires durable key, resolver, HTTP client, and clock")
	}
	lifetime := config.DelegationLifetime
	if lifetime == 0 {
		lifetime = 5 * time.Minute
	}
	if lifetime <= 0 {
		return nil, errors.New("reference: bootstrap delegation lifetime must be positive")
	}
	return &BootstrapClient{
		durableKey:         config.DurableKey,
		keyResolver:        config.KeyResolver,
		httpClient:         config.HTTPClient,
		clock:              config.Clock,
		delegationLifetime: lifetime,
	}, nil
}

func (client *BootstrapClient) Refresh(
	ctx context.Context,
	endpoint string,
	personServer string,
	ephemeralKey jose.SigningKey,
) (BootstrapResult, error) {
	if err := validateBootstrapRefresh(endpoint, personServer); err != nil {
		return BootstrapResult{}, err
	}
	if ephemeralKey.ID() == "" {
		return BootstrapResult{}, errors.New("reference: bootstrap ephemeral key is required")
	}
	delegation, err := signaturekey.MintJKTJWT(
		client.durableKey,
		ephemeralKey.PublicJWK(),
		client.clock.Now(),
		client.delegationLifetime,
	)
	if err != nil {
		return BootstrapResult{}, err
	}
	return client.refresh(
		ctx,
		endpoint,
		personServer,
		ephemeralKey,
		func(request *http.Request) error {
			return signaturekey.SignJKTJWTRequest(request, ephemeralKey, delegation, client.clock)
		},
	)
}

// RefreshSingleKey performs the simpler bootstrap profile in which the
// durable installation key signs the request directly and remains the agent
// token confirmation key.
func (client *BootstrapClient) RefreshSingleKey(
	ctx context.Context,
	endpoint string,
	personServer string,
) (BootstrapResult, error) {
	if err := validateBootstrapRefresh(endpoint, personServer); err != nil {
		return BootstrapResult{}, err
	}
	return client.refresh(
		ctx,
		endpoint,
		personServer,
		client.durableKey,
		func(request *http.Request) error {
			return signaturekey.SignHWKRequest(request, client.durableKey, client.clock)
		},
	)
}

func (client *BootstrapClient) refresh(
	ctx context.Context,
	endpoint string,
	personServer string,
	requestKey jose.SigningKey,
	sign func(*http.Request) error,
) (BootstrapResult, error) {
	var result BootstrapResult
	nonceBytes := make([]byte, bootstrapNonceBytes)
	if _, err := io.ReadFull(rand.Reader, nonceBytes); err != nil {
		return result, errors.New("reference: generate bootstrap request nonce")
	}
	body, err := json.Marshal(BootstrapRefreshRequest{
		PersonServer: personServer,
		Nonce:        base64.RawURLEncoding.EncodeToString(nonceBytes),
	})
	if err != nil {
		return result, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return result, err
	}
	request.Header.Set("Content-Type", "application/json")
	if err := sign(request); err != nil {
		return result, err
	}
	response, err := client.httpClient.Do(request)
	if err != nil {
		return result, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return result, responseError(response)
	}
	responseBody, err := io.ReadAll(io.LimitReader(response.Body, maxJSONBody+1))
	if err != nil {
		return result, err
	}
	if len(responseBody) > maxJSONBody {
		return result, errors.New("reference: bootstrap response is too large")
	}
	var wire bootstrapRefreshResponse
	if err := decodeJSONBytes(bytes.NewReader(responseBody), &wire); err != nil {
		return result, err
	}
	if wire.Agent == "" || wire.AgentToken == "" {
		return result, errors.New("reference: bootstrap response is incomplete")
	}
	evidence, err := aauth.VerifyAgentToken(
		ctx,
		wire.AgentToken,
		client.keyResolver,
		client.clock,
	)
	if err != nil {
		return result, err
	}
	claims, err := claimsWithoutAuthorization(evidence)
	if err != nil {
		return result, err
	}
	providerIdentifier, err := endpointIdentifier(endpoint)
	if err != nil {
		return result, err
	}
	if claims.Issuer != providerIdentifier ||
		claims.Subject != wire.Agent ||
		claims.PersonServer != personServer ||
		!claims.Confirmation.JWK.Equal(requestKey.PublicJWK()) {
		return result, errors.New("reference: bootstrap agent token does not match the refresh context")
	}
	return BootstrapResult{
		Identifier: wire.Agent,
		SigningKey: requestKey,
		AgentToken: wire.AgentToken,
		Claims:     claims,
	}, nil
}

func validateBootstrapRefresh(endpoint string, personServer string) error {
	if err := aauth.ValidateEndpoint(endpoint); err != nil {
		return err
	}
	return aauth.ValidateServerIdentifier(personServer)
}
