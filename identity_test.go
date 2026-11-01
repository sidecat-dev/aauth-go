package aauth_test

import (
	"testing"

	auth "gitlab.com/sidecat-dev/aauth-go"
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
		{"aauth:Plan ner@agents.example", ""},
		{"aauth:planner+child@agents.example", ""},
		{"aauth:planner+child+grandchild@agents.example", "aauth:planner+child@agents.example"},
		{"aauth:planner+child@other.example", "aauth:planner@agents.example"},
	} {
		if err := auth.ValidateAgentRelationship(relation[0], relation[1]); err == nil {
			t.Errorf("ValidateAgentRelationship(%q, %q) succeeded", relation[0], relation[1])
		}
	}
}

func TestAgentIdentifierLocalPartAcceptsUppercaseAndComparesExactly(t *testing.T) {
	t.Parallel()

	for _, identifier := range []string{
		"aauth:Planner@agents.example", "aauth:PLANNER.7f3C@agents.example",
	} {
		if err := auth.ValidateAgentIdentifier(identifier); err != nil {
			t.Errorf("ValidateAgentIdentifier(%q) = %v", identifier, err)
		}
	}
	if err := auth.ValidateAgentRelationship(
		"aauth:Planner+Search1@agents.example", "aauth:Planner@agents.example",
	); err != nil {
		t.Fatal(err)
	}
	// Parent and sub-agent local parts compare exactly; no case folding.
	if err := auth.ValidateAgentRelationship(
		"aauth:planner+search@agents.example", "aauth:Planner@agents.example",
	); err == nil {
		t.Fatal("sub-agent of a differently cased parent succeeded")
	}
}

// AAuth Core "Agent Identifiers": + is reserved as the sub-agent delimiter, so
// a local part with + is a non-empty parent local part, one +, and a
// non-empty discriminator.
func TestAgentIdentifierPlacesTheSubAgentDelimiterBetweenTwoParts(t *testing.T) {
	t.Parallel()

	if err := auth.ValidateAgentIdentifier("aauth:planner.7f3c+search1@vendor.example"); err != nil {
		t.Fatal(err)
	}
	for _, identifier := range []string{
		"aauth:+worker@agent.example",
		"aauth:assistant+@agent.example",
		"aauth:+@agent.example",
		"aauth:planner+child+grandchild@agent.example",
		"aauth:planner++child@agent.example",
	} {
		if err := auth.ValidateAgentIdentifier(identifier); err == nil {
			t.Errorf("ValidateAgentIdentifier(%q) succeeded", identifier)
		}
	}
}

func TestAgentIssuerBindsAgentDomainToProvider(t *testing.T) {
	t.Parallel()

	if err := auth.ValidateAgentIssuer("aauth:reader@agents.example", "https://agents.example"); err != nil {
		t.Fatal(err)
	}
	if err := auth.ValidateAgentIssuer("aauth:reader@other.example", "https://agents.example"); err == nil {
		t.Fatal("mismatched Agent issuer succeeded")
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

func TestHTTPSURLAllowsQueryAndFragment(t *testing.T) {
	t.Parallel()

	if err := auth.ValidateHTTPSURL("https://server.example/logo.svg?v=1#mark"); err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{"http://server.example/logo.svg", "https://", "https://user@server.example/logo.svg", "not a url"} {
		if err := auth.ValidateHTTPSURL(value); err == nil {
			t.Errorf("ValidateHTTPSURL(%q) succeeded", value)
		}
	}
}
