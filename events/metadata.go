package events

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/internal/jsonstrict"
)

// AgentProviderMetadata is the Events-relevant projection of
// /.well-known/aauth-agent.json. Other AP metadata members remain additive.
type AgentProviderMetadata struct {
	Issuer        string `json:"issuer"`
	JWKSURI       string `json:"jwks_uri"`
	EventEndpoint string `json:"event_endpoint"`
}

// DecodeAgentProviderMetadata validates one exact AP metadata document for
// Events endpoint discovery.
func DecodeAgentProviderMetadata(exact []byte, expectedIssuer string) (AgentProviderMetadata, error) {
	var metadata AgentProviderMetadata
	if err := jsonstrict.RejectAmbiguousNames(exact); err != nil {
		return metadata, fmt.Errorf("aauth events: decode Agent Provider metadata: %w", err)
	}
	if err := jsonstrict.RejectCaseVariants(exact, &metadata); err != nil {
		return metadata, fmt.Errorf("aauth events: decode Agent Provider metadata: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(exact))
	if err := decoder.Decode(&metadata); err != nil {
		return metadata, fmt.Errorf("aauth events: decode Agent Provider metadata: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return AgentProviderMetadata{}, errors.New("aauth events: Agent Provider metadata must contain one JSON value")
	}
	if metadata.Issuer != expectedIssuer {
		return AgentProviderMetadata{}, errors.New("aauth events: Agent Provider metadata issuer does not match requested issuer")
	}
	if err := aauth.ValidateServerIdentifier(metadata.Issuer); err != nil {
		return AgentProviderMetadata{}, fmt.Errorf("aauth events: Agent Provider metadata issuer: %w", err)
	}
	if err := aauth.ValidateEndpoint(metadata.JWKSURI); err != nil {
		return AgentProviderMetadata{}, fmt.Errorf("aauth events: Agent Provider metadata jwks_uri: %w", err)
	}
	if err := aauth.ValidateEndpoint(metadata.EventEndpoint); err != nil {
		return AgentProviderMetadata{}, fmt.Errorf("aauth events: Agent Provider metadata event_endpoint: %w", err)
	}
	return metadata, nil
}
