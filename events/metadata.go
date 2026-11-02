package events

import (
	"fmt"

	aauth "gitlab.com/sidecat-dev/aauth-go"
)

// AgentProviderMetadata is the Events-relevant projection of
// /.well-known/aauth-agent.json. aauth.DecodeAgentProviderMetadata decodes the
// whole document.
type AgentProviderMetadata struct {
	Issuer        string `json:"issuer"`
	JWKSURI       string `json:"jwks_uri"`
	EventEndpoint string `json:"event_endpoint"`
}

// DecodeAgentProviderMetadata verifies one exact AP metadata document as
// aauth.DecodeAgentProviderMetadata does, and requires the event_endpoint an
// AP that supports Events publishes (Events, Agent Provider Metadata), as an
// https URL without query or fragment.
func DecodeAgentProviderMetadata(exact []byte, expectedIssuer string) (AgentProviderMetadata, error) {
	metadata, err := aauth.DecodeAgentProviderMetadata(exact, expectedIssuer)
	if err != nil {
		return AgentProviderMetadata{}, fmt.Errorf("aauth events: Agent Provider metadata: %w", err)
	}
	if err := aauth.ValidateEndpoint(metadata.EventEndpoint); err != nil {
		return AgentProviderMetadata{}, fmt.Errorf("aauth events: Agent Provider metadata event_endpoint: %w", err)
	}
	return AgentProviderMetadata{
		Issuer: metadata.Issuer, JWKSURI: metadata.JWKSURI, EventEndpoint: metadata.EventEndpoint,
	}, nil
}
