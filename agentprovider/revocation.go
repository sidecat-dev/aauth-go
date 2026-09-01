package agentprovider

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/internal/jsonstrict"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

const maximumRevocationResponseBytes = 1 << 20

// RevocationClientConfig supplies transport and egress policy for Agent-token
// revocation at a Person Server.
type RevocationClientConfig struct {
	Provider   *Server
	HTTPClient *http.Client
	Admit      signaturekey.EgressAdmitter
}

// RevocationClient sends one signed Agent-token revocation request. It never
// retries internally; repeating an exact request is consequence-safe.
type RevocationClient struct {
	provider *Server
	client   *http.Client
	admit    signaturekey.EgressAdmitter
}

// NewRevocationClient constructs an Agent Provider revocation client.
func NewRevocationClient(config RevocationClientConfig) (*RevocationClient, error) {
	if config.Provider == nil || config.HTTPClient == nil || config.Admit == nil {
		return nil, errors.New("aauth: Agent-token revocation requires provider, HTTP client, and egress admitter")
	}
	client := *config.HTTPClient
	client.Jar = nil
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &RevocationClient{provider: config.Provider, client: &client, admit: config.Admit}, nil
}

// RevokeAgentToken asks the identified Person Server to refuse every later
// request authenticated by reference.
func (client *RevocationClient) RevokeAgentToken(ctx context.Context, personServer string, reference aauth.TokenReference) error {
	if client == nil || client.provider == nil {
		return errors.New("aauth: Agent-token revocation client is required")
	}
	if ctx == nil {
		return errors.New("aauth: Agent-token revocation context is required")
	}
	if err := aauth.ValidateServerIdentifier(personServer); err != nil {
		return fmt.Errorf("aauth: Person Server: %w", err)
	}
	if err := aauth.ValidateTokenReference(reference); err != nil {
		return err
	}
	if reference.Issuer != client.provider.issuer {
		return errors.New("aauth: Agent-token reference was not issued by this provider")
	}
	endpoint, err := client.revocationEndpoint(ctx, personServer)
	if err != nil {
		return err
	}
	body, err := json.Marshal(reference)
	if err != nil {
		return fmt.Errorf("aauth: encode Agent-token revocation: %w", err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("aauth: create Agent-token revocation request: %w", err)
	}
	request.Header.Set("Content-Type", "application/json")
	if err := signaturekey.SignJWKSURIRequestWithOptions(
		request,
		client.provider.signingKey,
		client.provider.issuer,
		aauth.AgentDiscoveryDocument,
		client.provider.clock,
		signaturekey.SignOptions{
			AdditionalComponents: []string{"content-type", "content-digest"},
			MaxBodyBytes:         maximumRevocationResponseBytes,
		},
	); err != nil {
		return fmt.Errorf("aauth: sign Agent-token revocation request: %w", err)
	}
	response, err := client.client.Do(request)
	if err != nil {
		return fmt.Errorf("aauth: revoke Agent token: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, maximumRevocationResponseBytes))
		return nil
	}
	if response.StatusCode == http.StatusUnauthorized && response.Header.Get("Signature-Error") != "" {
		if failure, decodeErr := signaturekey.DecodeErrorResponse(response); decodeErr == nil {
			return failure
		}
	}
	if mediaType, _, parseErr := mime.ParseMediaType(response.Header.Get("Content-Type")); parseErr == nil && mediaType == "application/problem+json" {
		if problem, decodeErr := aauth.DecodeProblemResponse(response); decodeErr == nil {
			return problem
		}
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, maximumRevocationResponseBytes))
	return fmt.Errorf("aauth: Person Server revocation endpoint returned %s", response.Status)
}

func (client *RevocationClient) revocationEndpoint(ctx context.Context, personServer string) (string, error) {
	metadataEndpoint := personServer + "/.well-known/aauth-person.json"
	if err := client.admit(ctx, metadataEndpoint); err != nil {
		return "", fmt.Errorf("aauth: Person Server metadata egress admission failed for %q: %w", metadataEndpoint, err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, metadataEndpoint, nil)
	if err != nil {
		return "", fmt.Errorf("aauth: create Person Server metadata request: %w", err)
	}
	response, err := client.client.Do(request)
	if err != nil {
		return "", fmt.Errorf("aauth: fetch Person Server metadata: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, maximumRevocationResponseBytes))
		return "", fmt.Errorf("aauth: Person Server metadata returned %s", response.Status)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maximumRevocationResponseBytes+1))
	if err != nil {
		return "", fmt.Errorf("aauth: read Person Server metadata: %w", err)
	}
	if len(body) > maximumRevocationResponseBytes {
		return "", errors.New("aauth: Person Server metadata is too large")
	}
	var metadata struct {
		Issuer             string `json:"issuer"`
		RevocationEndpoint string `json:"revocation_endpoint"`
	}
	if err := jsonstrict.RejectAmbiguousNames(body); err != nil {
		return "", fmt.Errorf("aauth: decode Person Server metadata: %w", err)
	}
	if err := jsonstrict.RejectCaseVariants(body, &metadata); err != nil {
		return "", fmt.Errorf("aauth: decode Person Server metadata: %w", err)
	}
	if err := json.Unmarshal(body, &metadata); err != nil {
		return "", fmt.Errorf("aauth: decode Person Server metadata: %w", err)
	}
	if metadata.Issuer != personServer {
		return "", errors.New("aauth: Person Server metadata issuer does not match requested server")
	}
	if err := aauth.ValidateEndpoint(metadata.RevocationEndpoint); err != nil {
		return "", fmt.Errorf("aauth: Person Server metadata revocation_endpoint: %w", err)
	}
	if err := client.admit(ctx, metadata.RevocationEndpoint); err != nil {
		return "", fmt.Errorf("aauth: Person Server revocation egress admission failed for %q: %w", metadata.RevocationEndpoint, err)
	}
	return metadata.RevocationEndpoint, nil
}
