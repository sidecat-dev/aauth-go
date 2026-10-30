package events

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"gitlab.com/sidecat-dev/aauth-go/internal/jsonstrict"
)

const (
	// SubscribeSecuritySchemeName is the AsyncAPI security scheme name under
	// which a Resource declares the AAuth subscribe token.
	SubscribeSecuritySchemeName = "aauth_subscribe"
	// SubscribeSecuritySchemeType is the declared AsyncAPI security scheme
	// type.
	SubscribeSecuritySchemeType = "http"
	// SubscribeSecurityScheme is the declared HTTP authentication scheme.
	SubscribeSecurityScheme = "aauth-subscribe"
)

// ValidateAsyncAPIDocument checks that one exact AsyncAPI JSON document
// declares the AAuth subscribe-token security scheme as Events requires of
// every Resource: components.securitySchemes.aauth_subscribe with type "http"
// and scheme "aauth-subscribe". Other members, including the scheme's
// description and the document's channels, operations, and messages, remain
// the Resource's own. YAML documents must be converted to JSON first.
func ValidateAsyncAPIDocument(exact []byte) error {
	var document struct {
		AsyncAPI   *string `json:"asyncapi"`
		Components *struct {
			SecuritySchemes map[string]json.RawMessage `json:"securitySchemes"`
		} `json:"components"`
	}
	if err := jsonstrict.RejectCaseVariants(exact, &document); err != nil {
		return fmt.Errorf("aauth events: decode AsyncAPI document: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(exact))
	if err := decoder.Decode(&document); err != nil {
		return fmt.Errorf("aauth events: decode AsyncAPI document: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("aauth events: AsyncAPI document must contain one JSON value")
	}
	if document.AsyncAPI == nil || *document.AsyncAPI == "" {
		return errors.New("aauth events: AsyncAPI document requires an asyncapi version")
	}
	if document.Components == nil {
		return errors.New("aauth events: AsyncAPI document does not declare the aauth_subscribe security scheme")
	}
	raw, present := document.Components.SecuritySchemes[SubscribeSecuritySchemeName]
	if !present {
		return errors.New("aauth events: AsyncAPI document does not declare the aauth_subscribe security scheme")
	}
	var scheme struct {
		Type   *string `json:"type"`
		Scheme *string `json:"scheme"`
	}
	if err := jsonstrict.RejectCaseVariants(raw, &scheme); err != nil {
		return fmt.Errorf("aauth events: AsyncAPI aauth_subscribe security scheme: %w", err)
	}
	if err := json.Unmarshal(raw, &scheme); err != nil {
		return fmt.Errorf("aauth events: AsyncAPI aauth_subscribe security scheme: %w", err)
	}
	if scheme.Type == nil || *scheme.Type != SubscribeSecuritySchemeType ||
		scheme.Scheme == nil || *scheme.Scheme != SubscribeSecurityScheme {
		return fmt.Errorf(
			"aauth events: AsyncAPI aauth_subscribe security scheme must have type %q and scheme %q",
			SubscribeSecuritySchemeType, SubscribeSecurityScheme,
		)
	}
	return nil
}
