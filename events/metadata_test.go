package events_test

import (
	"testing"

	"gitlab.com/sidecat-dev/aauth-go/events"
)

func TestDecodeAgentProviderMetadata(t *testing.T) {
	t.Parallel()

	metadata, err := events.DecodeAgentProviderMetadata([]byte(`{
		"issuer":"https://ap.example",
		"jwks_uri":"https://keys.example/ap.json",
		"event_endpoint":"https://inbox.example/events",
		"extension":true
	}`), "https://ap.example")
	if err != nil {
		t.Fatal(err)
	}
	if metadata.Issuer != "https://ap.example" || metadata.JWKSURI != "https://keys.example/ap.json" ||
		metadata.EventEndpoint != "https://inbox.example/events" {
		t.Fatalf("metadata = %#v", metadata)
	}
}

func TestDecodeAgentProviderMetadataRejectsIssuerMismatch(t *testing.T) {
	t.Parallel()

	_, err := events.DecodeAgentProviderMetadata([]byte(`{
		"issuer":"https://other.example",
		"jwks_uri":"https://other.example/jwks.json",
		"event_endpoint":"https://other.example/events"
	}`), "https://ap.example")
	if err == nil {
		t.Fatal("DecodeAgentProviderMetadata accepted another issuer")
	}
}
