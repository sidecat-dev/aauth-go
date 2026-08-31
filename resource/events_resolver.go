package resource

import (
	"context"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/events"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

const defaultEventMetadataTimeout = 10 * time.Second

// HTTPEventEndpointResolverConfig supplies network and egress policy for AP
// event_endpoint discovery.
type HTTPEventEndpointResolverConfig struct {
	Client   *http.Client
	Admit    signaturekey.EgressAdmitter
	MaxBytes int64
	Timeout  time.Duration
}

// HTTPEventEndpointResolver resolves the AP's current endpoint from its
// current /.well-known/aauth-agent.json document. It deliberately retains no
// endpoint across calls.
type HTTPEventEndpointResolver struct {
	client   *http.Client
	admit    signaturekey.EgressAdmitter
	maxBytes int64
	timeout  time.Duration
}

// NewHTTPEventEndpointResolver constructs a bounded AP metadata resolver.
func NewHTTPEventEndpointResolver(config HTTPEventEndpointResolverConfig) (*HTTPEventEndpointResolver, error) {
	if config.Client == nil || config.Admit == nil {
		return nil, errors.New("resource: event endpoint resolver requires HTTP client and egress admitter")
	}
	if config.MaxBytes < 0 || config.Timeout < 0 {
		return nil, errors.New("resource: event endpoint resolver limits must not be negative")
	}
	maxBytes := config.MaxBytes
	if maxBytes == 0 {
		maxBytes = defaultEventBodyBytes
	}
	timeout := config.Timeout
	if timeout == 0 {
		timeout = defaultEventMetadataTimeout
	}
	client := *config.Client
	client.Jar = nil
	client.CheckRedirect = func(*http.Request, []*http.Request) error {
		return errors.New("resource: event metadata redirects are not permitted")
	}
	return &HTTPEventEndpointResolver{client: &client, admit: config.Admit, maxBytes: maxBytes, timeout: timeout}, nil
}

// ResolveEventEndpoint fetches and validates one current AP metadata document.
func (resolver *HTTPEventEndpointResolver) ResolveEventEndpoint(ctx context.Context, provider string) (string, error) {
	if resolver == nil {
		return "", errors.New("resource: event endpoint resolver is required")
	}
	if ctx == nil {
		return "", errors.New("resource: event endpoint context is required")
	}
	if err := aauth.ValidateServerIdentifier(provider); err != nil {
		return "", fmt.Errorf("resource: Agent Provider identifier: %w", err)
	}
	endpoint := provider + "/.well-known/aauth-agent.json"
	if err := resolver.admit(ctx, endpoint); err != nil {
		return "", fmt.Errorf("resource: event metadata egress denied: %w", err)
	}
	requestContext, cancel := context.WithTimeout(ctx, resolver.timeout)
	defer cancel()
	request, err := http.NewRequestWithContext(requestContext, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", err
	}
	request.Header.Set("Accept", "application/json")
	response, err := resolver.client.Do(request)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("resource: Agent Provider metadata returned HTTP %d", response.StatusCode)
	}
	mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return "", errors.New("resource: Agent Provider metadata must use application/json")
	}
	exact, err := io.ReadAll(io.LimitReader(response.Body, resolver.maxBytes+1))
	if err != nil {
		return "", err
	}
	if int64(len(exact)) > resolver.maxBytes {
		return "", errors.New("resource: Agent Provider metadata is too large")
	}
	metadata, err := events.DecodeAgentProviderMetadata(exact, provider)
	if err != nil {
		return "", err
	}
	return metadata.EventEndpoint, nil
}
