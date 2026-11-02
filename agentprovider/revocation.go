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
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/internal/httpapi"
	"gitlab.com/sidecat-dev/aauth-go/internal/jsonstrict"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

const maximumRevocationResponseBytes = 1 << 20

// RevocationClientConfig supplies transport and egress policy for Agent-token
// revocation at Person Servers and direct Agent-identity Resources.
type RevocationClientConfig struct {
	Provider   *Server
	HTTPClient *http.Client
	Admit      signaturekey.EgressAdmitter
}

// RevocationPendingError reports that a Person Server recorded an Agent-token
// revocation and answered 202 because its cascade, revoking what it issued to
// that Agent, is not yet terminal. Repeat the same revocation after
// RetryAfter: the Person Server records nothing new and continues its cascade.
// Location is the pending URL it named.
type RevocationPendingError struct {
	Location   string
	RetryAfter time.Duration
}

func (failure *RevocationPendingError) Error() string {
	return "aauth: Agent-token revocation is recorded and its cascade is still pending"
}

// RevocationClient sends one signed Agent-token revocation request. It never
// retries internally; repeating an exact request is consequence-safe.
type RevocationClient struct {
	provider *Server
	client   *http.Client
	admit    signaturekey.EgressAdmitter
}

type revocationTarget struct {
	label        string
	metadataPath string
	// mayPublishNone marks a recipient whose metadata is optional: a Resource
	// MAY publish none (Core, Resource Metadata), and a 404 then means it has
	// no revocation_endpoint.
	mayPublishNone bool
}

type revocationProfile struct {
	endpoint             string
	additionalComponents []string
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
func (client *RevocationClient) RevokeAgentToken(ctx context.Context, personServer string, request aauth.RevocationRequest) error {
	return client.revokeAgentToken(ctx, personServer, request, nil, revocationTarget{
		label: "Person Server", metadataPath: "/.well-known/aauth-person.json",
	})
}

// RevokeAgentTokenAtResource asks a Resource that accepts direct Agent
// identity to refuse every later request authenticated by reference.
func (client *RevocationClient) RevokeAgentTokenAtResource(ctx context.Context, resource string, request aauth.RevocationRequest) error {
	return client.RevokeAgentTokenAtResourceWithHeaders(ctx, resource, request, nil)
}

// RevokeAgentTokenAtResourceWithHeaders supplies values for additional
// signature components advertised by the Resource.
func (client *RevocationClient) RevokeAgentTokenAtResourceWithHeaders(
	ctx context.Context,
	resource string,
	request aauth.RevocationRequest,
	header http.Header,
) error {
	return client.revokeAgentToken(ctx, resource, request, header, revocationTarget{
		label: "Resource", metadataPath: "/.well-known/aauth-resource.json", mayPublishNone: true,
	})
}

func (client *RevocationClient) revokeAgentToken(
	ctx context.Context,
	server string,
	revocation aauth.RevocationRequest,
	header http.Header,
	target revocationTarget,
) error {
	if client == nil || client.provider == nil {
		return errors.New("aauth: Agent-token revocation client is required")
	}
	if ctx == nil {
		return errors.New("aauth: Agent-token revocation context is required")
	}
	if err := aauth.ValidateServerIdentifier(server); err != nil {
		return fmt.Errorf("aauth: %s: %w", target.label, err)
	}
	if err := aauth.ValidateRevocationRequest(revocation); err != nil {
		return err
	}
	if revocation.Reference.Issuer != client.provider.issuer {
		return errors.New("aauth: Agent-token reference was not issued by this provider")
	}
	profile, err := client.revocationProfile(ctx, server, target)
	if err != nil {
		return err
	}
	body, err := aauth.EncodeRevocationRequest(revocation)
	if err != nil {
		return fmt.Errorf("aauth: encode Agent-token revocation: %w", err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, profile.endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("aauth: create Agent-token revocation request: %w", err)
	}
	request.Header.Set("Content-Type", "application/json")
	components, err := agentTokenRevocationComponents(target.label, profile.additionalComponents, header, request.Header)
	if err != nil {
		return err
	}
	if err := signaturekey.SignJWKSURIRequestWithOptions(
		request,
		client.provider.signingKey,
		client.provider.issuer,
		aauth.AgentDiscoveryDocument,
		client.provider.clock,
		signaturekey.SignOptions{
			AdditionalComponents: components,
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
		return aauth.ReadRevocationResponse(response, maximumRevocationResponseBytes)
	}
	if response.StatusCode == http.StatusAccepted {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, maximumRevocationResponseBytes))
		retryAfter, ok := httpapi.ParseRetryAfter(response.Header.Values("Retry-After"), client.provider.clock.Now())
		if !ok {
			retryAfter = 5 * time.Second
		}
		return &RevocationPendingError{Location: response.Header.Get("Location"), RetryAfter: retryAfter}
	}
	if response.StatusCode == http.StatusUnauthorized && response.Header.Get("Signature-Error") != "" {
		if failure, decodeErr := signaturekey.DecodeErrorResponse(response); decodeErr == nil {
			return failure
		}
	}
	if mediaType, _, parseErr := mime.ParseMediaType(response.Header.Get("Content-Type")); parseErr == nil && mediaType == "application/problem+json" {
		if problem, decodeErr := aauth.DecodeProblemResponse(response); decodeErr == nil {
			if problem.Status == http.StatusTooManyRequests && problem.Code == "rate_limited" {
				if delay, ok := httpapi.ParseRetryAfter(response.Header.Values("Retry-After"), client.provider.clock.Now()); ok {
					return &aauth.RateLimitedError{Problem: problem, RetryAfter: delay}
				}
			}
			return problem
		}
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, maximumRevocationResponseBytes))
	return fmt.Errorf("aauth: %s revocation endpoint returned %s", target.label, response.Status)
}

func (client *RevocationClient) revocationProfile(ctx context.Context, server string, target revocationTarget) (revocationProfile, error) {
	metadataEndpoint := server + target.metadataPath
	if err := client.admit(ctx, metadataEndpoint); err != nil {
		return revocationProfile{}, fmt.Errorf("aauth: %s metadata egress admission failed for %q: %w", target.label, metadataEndpoint, err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, metadataEndpoint, nil)
	if err != nil {
		return revocationProfile{}, fmt.Errorf("aauth: create %s metadata request: %w", target.label, err)
	}
	response, err := client.client.Do(request)
	if err != nil {
		return revocationProfile{}, fmt.Errorf("aauth: fetch %s metadata: %w", target.label, err)
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusNotFound && target.mayPublishNone {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, maximumRevocationResponseBytes))
		return revocationProfile{}, fmt.Errorf("aauth: %s publishes no metadata, so no revocation_endpoint", target.label)
	}
	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, maximumRevocationResponseBytes))
		return revocationProfile{}, fmt.Errorf("aauth: %s metadata returned %s", target.label, response.Status)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maximumRevocationResponseBytes+1))
	if err != nil {
		return revocationProfile{}, fmt.Errorf("aauth: read %s metadata: %w", target.label, err)
	}
	if len(body) > maximumRevocationResponseBytes {
		return revocationProfile{}, fmt.Errorf("aauth: %s metadata is too large", target.label)
	}
	var metadata struct {
		Issuer                        string   `json:"issuer"`
		RevocationEndpoint            string   `json:"revocation_endpoint"`
		AdditionalSignatureComponents []string `json:"additional_signature_components"`
	}
	if err := jsonstrict.RejectAmbiguousNames(body); err != nil {
		return revocationProfile{}, fmt.Errorf("aauth: decode %s metadata: %w", target.label, err)
	}
	if err := jsonstrict.RejectCaseVariants(body, &metadata); err != nil {
		return revocationProfile{}, fmt.Errorf("aauth: decode %s metadata: %w", target.label, err)
	}
	if err := json.Unmarshal(body, &metadata); err != nil {
		return revocationProfile{}, fmt.Errorf("aauth: decode %s metadata: %w", target.label, err)
	}
	if metadata.Issuer != server {
		return revocationProfile{}, fmt.Errorf("aauth: %s metadata issuer does not match requested server", target.label)
	}
	if metadata.RevocationEndpoint == "" {
		return revocationProfile{}, fmt.Errorf("aauth: %s publishes no revocation_endpoint", target.label)
	}
	if err := aauth.ValidateEndpoint(metadata.RevocationEndpoint); err != nil {
		return revocationProfile{}, fmt.Errorf("aauth: %s metadata revocation_endpoint: %w", target.label, err)
	}
	if err := client.admit(ctx, metadata.RevocationEndpoint); err != nil {
		return revocationProfile{}, fmt.Errorf("aauth: %s revocation egress admission failed for %q: %w", target.label, metadata.RevocationEndpoint, err)
	}
	return revocationProfile{
		endpoint:             metadata.RevocationEndpoint,
		additionalComponents: append([]string(nil), metadata.AdditionalSignatureComponents...),
	}, nil
}

func agentTokenRevocationComponents(label string, additional []string, provided, destination http.Header) ([]string, error) {
	components := []string{"content-type", "content-digest"}
	seen := map[string]struct{}{"content-type": {}, "content-digest": {}}
	var missing []string
	for _, component := range additional {
		if err := signaturekey.ValidateAdditionalComponent(component); err != nil {
			return nil, fmt.Errorf("aauth: %s revocation signature profile: %w", label, err)
		}
		if _, duplicate := seen[component]; duplicate {
			return nil, fmt.Errorf("aauth: %s revocation signature component %q is duplicated", label, component)
		}
		seen[component] = struct{}{}
		values := provided.Values(component)
		if len(values) == 0 {
			missing = append(missing, component)
			continue
		}
		for _, value := range values {
			destination.Add(component, value)
		}
		components = append(components, component)
	}
	if len(missing) > 0 {
		return nil, &signaturekey.Error{
			Code: signaturekey.ErrorInvalidInput, RequiredInput: missing,
			Cause: fmt.Errorf("aauth: %s revocation requires advertised headers", label),
		}
	}
	return components, nil
}
