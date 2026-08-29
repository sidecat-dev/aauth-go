package reference

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	aauth "gitlab.com/sidecat-dev/aauth-go"
)

// ResourceMetadataErrorCode classifies resource metadata failures without
// requiring callers to inspect transport or decoding diagnostics.
type ResourceMetadataErrorCode string

const (
	ResourceMetadataInvalid     ResourceMetadataErrorCode = "invalid"
	ResourceMetadataUnavailable ResourceMetadataErrorCode = "unavailable"
)

// ResourceMetadataError retains the local cause beside its stable class.
type ResourceMetadataError struct {
	Code  ResourceMetadataErrorCode
	Cause error
}

func (err *ResourceMetadataError) Error() string {
	if err == nil {
		return "reference: resource metadata error"
	}
	if err.Cause == nil {
		return "reference: resource metadata " + string(err.Code)
	}
	return "reference: resource metadata " + string(err.Code) + ": " + err.Cause.Error()
}

func (err *ResourceMetadataError) Unwrap() error {
	if err == nil {
		return nil
	}
	return err.Cause
}

// ResourceMetadataResolver returns the verified human-facing metadata a
// person server presents before issuing a person token.
type ResourceMetadataResolver interface {
	ResolveResourceMetadata(context.Context, string) (aauth.ResourcePresentation, error)
}

// HTTPResourceMetadataResolver fetches current resource metadata over the
// caller-supplied HTTP trust and transport boundary.
type HTTPResourceMetadataResolver struct {
	client *http.Client
}

func NewHTTPResourceMetadataResolver(client *http.Client) (*HTTPResourceMetadataResolver, error) {
	if client == nil {
		return nil, errors.New("reference: resource metadata resolver requires an HTTP client")
	}
	return &HTTPResourceMetadataResolver{client: client}, nil
}

func (resolver *HTTPResourceMetadataResolver) ResolveResourceMetadata(
	ctx context.Context,
	resource string,
) (aauth.ResourcePresentation, error) {
	var presentation aauth.ResourcePresentation
	if resolver == nil || resolver.client == nil {
		return presentation, &ResourceMetadataError{Code: ResourceMetadataUnavailable, Cause: errors.New("resolver is not initialized")}
	}
	if err := aauth.ValidateServerIdentifier(resource); err != nil {
		return presentation, &ResourceMetadataError{Code: ResourceMetadataInvalid, Cause: err}
	}
	endpoint := resource + "/.well-known/" + aauth.ResourceDiscoveryDocument
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return presentation, &ResourceMetadataError{Code: ResourceMetadataInvalid, Cause: err}
	}
	request.Header.Set("Accept", "application/json")
	response, err := resolver.client.Do(request)
	if err != nil {
		return presentation, &ResourceMetadataError{Code: ResourceMetadataUnavailable, Cause: err}
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return presentation, &ResourceMetadataError{
			Code:  ResourceMetadataUnavailable,
			Cause: fmt.Errorf("resource metadata endpoint returned HTTP %d", response.StatusCode),
		}
	}
	var metadata map[string]json.RawMessage
	if err := decodeJSONBytes(response.Body, &metadata); err != nil {
		return presentation, &ResourceMetadataError{Code: ResourceMetadataInvalid, Cause: err}
	}
	presentation.AccessMode = aauth.AccessModeAgentToken
	if err := requiredMetadataString(metadata, "issuer", &presentation.Issuer); err != nil {
		return aauth.ResourcePresentation{}, &ResourceMetadataError{Code: ResourceMetadataInvalid, Cause: err}
	}
	if presentation.Issuer != resource {
		return aauth.ResourcePresentation{}, &ResourceMetadataError{
			Code: ResourceMetadataInvalid, Cause: errors.New("issuer does not match the requested resource"),
		}
	}
	for name, destination := range map[string]*string{
		"name": &presentation.Name, "description": &presentation.Description,
	} {
		if err := optionalMetadataString(metadata, name, destination); err != nil {
			return aauth.ResourcePresentation{}, &ResourceMetadataError{Code: ResourceMetadataInvalid, Cause: err}
		}
	}
	var accessMode string
	if err := optionalMetadataString(metadata, "access_mode", &accessMode); err != nil {
		return aauth.ResourcePresentation{}, &ResourceMetadataError{Code: ResourceMetadataInvalid, Cause: err}
	}
	if accessMode != "" {
		presentation.AccessMode = aauth.AccessMode(accessMode)
	}
	return presentation, nil
}

func requiredMetadataString(metadata map[string]json.RawMessage, name string, destination *string) error {
	raw, ok := metadata[name]
	if !ok || json.Unmarshal(raw, destination) != nil || *destination == "" {
		return fmt.Errorf("%s is required", name)
	}
	return nil
}

func optionalMetadataString(metadata map[string]json.RawMessage, name string, destination *string) error {
	raw, ok := metadata[name]
	if !ok {
		return nil
	}
	if string(raw) == "null" {
		return fmt.Errorf("%s must be a string", name)
	}
	if err := json.Unmarshal(raw, destination); err != nil {
		return fmt.Errorf("%s must be a string", name)
	}
	return nil
}

func writeResourceMetadataFailure(response http.ResponseWriter, err error) {
	var metadataError *ResourceMetadataError
	if errors.As(err, &metadataError) && metadataError.Code == ResourceMetadataInvalid {
		writeProblem(response, http.StatusBadRequest, "invalid_request", errors.New("resource metadata is invalid"))
		return
	}
	writeProblem(response, http.StatusServiceUnavailable, "server_error", nil)
}

var _ ResourceMetadataResolver = (*HTTPResourceMetadataResolver)(nil)
