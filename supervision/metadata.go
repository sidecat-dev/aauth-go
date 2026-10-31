package supervision

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/internal/jsonstrict"
)

// DiscoveryDocument is the well-known metadata document of a supervision
// server, and the dwk a signed decision names in its Signature-Key.
const DiscoveryDocument = "aauth-supervisor.json"

// Metadata is a supervision server's metadata document (Supervisor Metadata).
// JWKSURI is optional: an SS that publishes one signs the terminal response to
// every supervision request, and one that does not is a plain JSON responder.
type Metadata struct {
	Issuer           string `json:"issuer"`
	Name             string `json:"name,omitempty"`
	ConnectEndpoint  string `json:"connect_endpoint"`
	MissionEndpoint  string `json:"mission_endpoint"`
	DecisionEndpoint string `json:"decision_endpoint"`
	EventEndpoint    string `json:"event_endpoint"`
	JWKSURI          string `json:"jwks_uri,omitempty"`
	Description      string `json:"description,omitempty"`
	LogoURI          string `json:"logo_uri,omitempty"`
	DocumentationURI string `json:"documentation_uri,omitempty"`
	TOSURI           string `json:"tos_uri,omitempty"`
	PolicyURI        string `json:"policy_uri,omitempty"`
}

// Signs reports whether the SS publishes a key set, and therefore signs its
// decisions.
func (metadata Metadata) Signs() bool { return metadata.JWKSURI != "" }

// Validate checks the required members and the endpoint rules: every endpoint
// and the key set are HTTPS URLs on the issuer's origin. The draft also admits
// an origin the SS controls, which a Person Server cannot establish from the
// document, so this implementation requires the issuer's own origin.
func (metadata Metadata) Validate() error {
	if err := aauth.ValidateServerIdentifier(metadata.Issuer); err != nil {
		return fmt.Errorf("supervision: metadata issuer: %w", err)
	}
	endpoints := []struct {
		name, value string
		required    bool
	}{
		{"connect_endpoint", metadata.ConnectEndpoint, true},
		{"mission_endpoint", metadata.MissionEndpoint, true},
		{"decision_endpoint", metadata.DecisionEndpoint, true},
		{"event_endpoint", metadata.EventEndpoint, true},
		{"jwks_uri", metadata.JWKSURI, false},
	}
	for _, endpoint := range endpoints {
		if endpoint.value == "" {
			if endpoint.required {
				return fmt.Errorf("supervision: metadata %s is required", endpoint.name)
			}
			continue
		}
		if err := aauth.ValidateEndpoint(endpoint.value); err != nil {
			return fmt.Errorf("supervision: metadata %s: %w", endpoint.name, err)
		}
		if !sameOrigin(metadata.Issuer, endpoint.value) {
			return fmt.Errorf("supervision: metadata %s is not on the issuer's origin", endpoint.name)
		}
	}
	for name, value := range map[string]string{
		"logo_uri": metadata.LogoURI, "documentation_uri": metadata.DocumentationURI,
		"tos_uri": metadata.TOSURI, "policy_uri": metadata.PolicyURI,
	} {
		if value != "" {
			if err := aauth.ValidateHTTPSURL(value); err != nil {
				return fmt.Errorf("supervision: metadata %s: %w", name, err)
			}
		}
	}
	return nil
}

// DecodeMetadata validates one exact metadata document fetched for
// expectedIssuer. The document must name that issuer exactly.
func DecodeMetadata(exact []byte, expectedIssuer string) (Metadata, error) {
	var metadata Metadata
	if err := decodeStrict(exact, &metadata); err != nil {
		return Metadata{}, fmt.Errorf("supervision: decode metadata: %w", err)
	}
	if metadata.Issuer != expectedIssuer {
		return Metadata{}, errors.New("supervision: metadata issuer does not match the supervision server")
	}
	if err := metadata.Validate(); err != nil {
		return Metadata{}, err
	}
	return metadata, nil
}

func sameOrigin(issuer, endpoint string) bool {
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return false
	}
	return parsed.Scheme+"://"+parsed.Host == issuer
}

// decodeStrict decodes one JSON value, rejecting ambiguous member names and
// case variants of known members, and trailing data. Unknown members are
// additive and ignored.
func decodeStrict(exact []byte, destination any) error {
	if err := jsonstrict.RejectAmbiguousNames(exact); err != nil {
		return err
	}
	if err := jsonstrict.RejectCaseVariants(exact, destination); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(exact))
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("body must contain exactly one JSON value")
	}
	return nil
}
