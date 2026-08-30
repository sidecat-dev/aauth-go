package aauth_test

import (
	"testing"

	auth "aauth-go"
)

func TestServerIdentifierUsesOneCanonicalHTTPSOrigin(t *testing.T) {
	t.Parallel()

	if err := auth.ValidateServerIdentifier("https://xn--nxasmq6b.example"); err != nil {
		t.Fatal(err)
	}
	for _, identifier := range []string{
		"", "http://server.example", "https://Server.example", "https://server.example/",
		"https://server.example:8443", "https://user@server.example", "https://127.0.0.1",
		"https://server.example?", "https://server.example#",
	} {
		if err := auth.ValidateServerIdentifier(identifier); err == nil {
			t.Errorf("ValidateServerIdentifier(%q) succeeded", identifier)
		}
	}
}

func TestAgentIdentifierAndOneLevelRelationship(t *testing.T) {
	t.Parallel()

	if err := auth.ValidateAgentRelationship("aauth:planner@agents.example", ""); err != nil {
		t.Fatal(err)
	}
	if err := auth.ValidateAgentRelationship(
		"aauth:planner+research@agents.example", "aauth:planner@agents.example",
	); err != nil {
		t.Fatal(err)
	}
	for _, relation := range [][2]string{
		{"agent@agents.example", ""},
		{"aauth:Planner@agents.example", ""},
		{"aauth:planner+child@agents.example", ""},
		{"aauth:planner+child+grandchild@agents.example", "aauth:planner+child@agents.example"},
		{"aauth:planner+child@other.example", "aauth:planner@agents.example"},
	} {
		if err := auth.ValidateAgentRelationship(relation[0], relation[1]); err == nil {
			t.Errorf("ValidateAgentRelationship(%q, %q) succeeded", relation[0], relation[1])
		}
	}
}

func TestEndpointAllowsPathsButNotQueryOrFragment(t *testing.T) {
	t.Parallel()

	if err := auth.ValidateEndpoint("https://server.example/v1/tokens"); err != nil {
		t.Fatal(err)
	}
	for _, endpoint := range []string{
		"http://server.example/tokens", "https://server.example/tokens?mode=one",
		"https://server.example/tokens#result", "https://user@server.example/tokens",
		"https://server.example/tokens?", "https://server.example/tokens#",
	} {
		if err := auth.ValidateEndpoint(endpoint); err == nil {
			t.Errorf("ValidateEndpoint(%q) succeeded", endpoint)
		}
	}
}
