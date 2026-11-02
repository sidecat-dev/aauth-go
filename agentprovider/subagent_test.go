package agentprovider_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/agentprovider"
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

// Bootstrap 28e8258, Sub-Agent Tokens; Protocol 28e8258, Sub-Agent Identity
// and Single-Level Depth: only the parent's own provider issues a sub-agent
// token, from that parent's current top-level token.
type subagentProviderFixture struct {
	now      time.Time
	clock    aauth.Clock
	apKey    jose.SigningKey
	parent   jose.SigningKey
	child    jose.SigningKey
	provider *agentprovider.Server
	resolver signaturekey.StaticKeyResolver
	ids      []string
}

func newSubagentProviderFixture(t *testing.T) *subagentProviderFixture {
	t.Helper()
	f := &subagentProviderFixture{
		now:    time.Date(2026, 10, 20, 18, 0, 0, 0, time.UTC),
		apKey:  testSigningKey(t, "ap-key", 41),
		parent: testSigningKey(t, "parent-key", 42),
		child:  testSigningKey(t, "child-key", 43),
		ids:    []string{"parent-token", "child-token", "spare-token"},
	}
	f.clock = aauth.ClockFunc(func() time.Time { return f.now })
	provider, err := agentprovider.New(agentprovider.Config{
		Issuer: "https://ap.example", SigningKey: f.apKey, Clock: f.clock,
		NewID: func() string {
			id := f.ids[0]
			f.ids = f.ids[1:]
			return id
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	f.provider = provider
	f.resolver = signaturekey.StaticKeyResolver{
		{Issuer: "https://ap.example", DiscoveryDocument: aauth.AgentDiscoveryDocument, KeyID: f.apKey.ID()}: f.apKey.PublicJWK(),
	}
	return f
}

func (f *subagentProviderFixture) parentToken(t *testing.T, lifetime time.Duration) string {
	t.Helper()
	compact, err := f.provider.Issue(t.Context(), aauth.AgentTokenRequest{
		Agent: "aauth:planner@ap.example", PersonServer: "https://ps.example",
		PublicKey: f.parent.PublicJWK(), Lifetime: lifetime,
	})
	if err != nil {
		t.Fatal(err)
	}
	return compact
}

func TestIssueSubagentCreatesOneLevelChildOfTheVerifiedParent(t *testing.T) {
	t.Parallel()

	f := newSubagentProviderFixture(t)
	parentToken := f.parentToken(t, time.Hour)
	compact, err := f.provider.IssueSubagent(context.Background(), parentToken, agentprovider.SubagentTokenRequest{
		Discriminator: "search1", PublicKey: f.child.PublicJWK(), Lifetime: 10 * time.Minute,
		AdditionalClaims: map[string]json.RawMessage{"workload": json.RawMessage(`"search"`)},
	})
	if err != nil {
		t.Fatal(err)
	}
	parent, err := aauth.VerifyAgentToken(context.Background(), parentToken, f.resolver, f.clock)
	if err != nil {
		t.Fatal(err)
	}
	child, err := aauth.VerifySubagentToken(context.Background(), compact, parent, f.resolver, f.clock)
	if err != nil {
		t.Fatal(err)
	}
	if child.Issuer != "https://ap.example" || child.Subject != "aauth:planner+search1@ap.example" ||
		child.ParentAgent != "aauth:planner@ap.example" || child.PersonServer != "https://ps.example" ||
		!child.Confirmation.JWK.Equal(f.child.PublicJWK()) || child.JTI != "child-token" ||
		child.IssuedAt != f.now.Unix() || child.ExpiresAt != f.now.Add(10*time.Minute).Unix() ||
		string(child.AdditionalClaims["workload"]) != `"search"` {
		t.Fatalf("child = %#v", child)
	}
}

// Bootstrap 28e8258: the sub-agent token's exp is no later than the parent's.
func TestIssueSubagentCapsTheChildAtTheParentExpiry(t *testing.T) {
	t.Parallel()

	f := newSubagentProviderFixture(t)
	parentToken := f.parentToken(t, 5*time.Minute)
	compact, err := f.provider.IssueSubagent(context.Background(), parentToken, agentprovider.SubagentTokenRequest{
		Discriminator: "long", PublicKey: f.child.PublicJWK(), Lifetime: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	child, err := aauth.VerifyAgentToken(context.Background(), compact, f.resolver, f.clock)
	if err != nil {
		t.Fatal(err)
	}
	if child.ExpiresAt != f.now.Add(5*time.Minute).Unix() {
		t.Fatalf("child exp = %d, want parent exp %d", child.ExpiresAt, f.now.Add(5*time.Minute).Unix())
	}
}

func TestIssueSubagentRefusesAnUnverifiedOrIneligibleParent(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name   string
		parent func(*testing.T, *subagentProviderFixture) string
	}{
		{name: "another provider's key", parent: func(t *testing.T, f *subagentProviderFixture) string {
			compact, err := aauth.MintAgentToken("https://ap.example", testSigningKey(t, "ap-key", 44), aauth.AgentTokenRequest{
				Agent: "aauth:planner@ap.example", PublicKey: f.parent.PublicJWK(), Lifetime: time.Hour,
			}, f.now, "foreign")
			if err != nil {
				t.Fatal(err)
			}
			return compact
		}},
		{name: "another issuer", parent: func(t *testing.T, f *subagentProviderFixture) string {
			compact, err := aauth.MintAgentToken("https://other.example", f.apKey, aauth.AgentTokenRequest{
				Agent: "aauth:planner@other.example", PublicKey: f.parent.PublicJWK(), Lifetime: time.Hour,
			}, f.now, "other-issuer")
			if err != nil {
				t.Fatal(err)
			}
			return compact
		}},
		{name: "expired parent", parent: func(t *testing.T, f *subagentProviderFixture) string {
			compact, err := aauth.MintAgentToken("https://ap.example", f.apKey, aauth.AgentTokenRequest{
				Agent: "aauth:planner@ap.example", PublicKey: f.parent.PublicJWK(), Lifetime: time.Minute,
			}, f.now.Add(-2*time.Minute), "expired")
			if err != nil {
				t.Fatal(err)
			}
			return compact
		}},
		{name: "parent is a sub-agent", parent: func(t *testing.T, f *subagentProviderFixture) string {
			compact, err := aauth.MintAgentToken("https://ap.example", f.apKey, aauth.AgentTokenRequest{
				Agent: "aauth:planner+lane@ap.example", ParentAgent: "aauth:planner@ap.example",
				PublicKey: f.parent.PublicJWK(), Lifetime: time.Hour,
			}, f.now, "child-as-parent")
			if err != nil {
				t.Fatal(err)
			}
			return compact
		}},
		{name: "malformed", parent: func(*testing.T, *subagentProviderFixture) string { return "not-a-token" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			f := newSubagentProviderFixture(t)
			_, err := f.provider.IssueSubagent(context.Background(), test.parent(t, f), agentprovider.SubagentTokenRequest{
				Discriminator: "search", PublicKey: f.child.PublicJWK(), Lifetime: time.Minute,
			})
			if !errors.Is(err, agentprovider.ErrInvalidSubagentParent) {
				t.Fatalf("error = %v, want ErrInvalidSubagentParent", err)
			}
		})
	}
}

func TestIssueSubagentRefusesInvalidChildRequests(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name    string
		request func(*subagentProviderFixture) agentprovider.SubagentTokenRequest
	}{
		{name: "empty discriminator", request: func(f *subagentProviderFixture) agentprovider.SubagentTokenRequest {
			return agentprovider.SubagentTokenRequest{PublicKey: f.child.PublicJWK(), Lifetime: time.Minute}
		}},
		{name: "nested discriminator", request: func(f *subagentProviderFixture) agentprovider.SubagentTokenRequest {
			return agentprovider.SubagentTokenRequest{Discriminator: "a+b", PublicKey: f.child.PublicJWK(), Lifetime: time.Minute}
		}},
		{name: "discriminator outside the local-part grammar", request: func(f *subagentProviderFixture) agentprovider.SubagentTokenRequest {
			return agentprovider.SubagentTokenRequest{Discriminator: "a@b", PublicKey: f.child.PublicJWK(), Lifetime: time.Minute}
		}},
		{name: "parent key reused", request: func(f *subagentProviderFixture) agentprovider.SubagentTokenRequest {
			return agentprovider.SubagentTokenRequest{Discriminator: "search", PublicKey: f.parent.PublicJWK(), Lifetime: time.Minute}
		}},
		{name: "missing key", request: func(*subagentProviderFixture) agentprovider.SubagentTokenRequest {
			return agentprovider.SubagentTokenRequest{Discriminator: "search", Lifetime: time.Minute}
		}},
		{name: "no lifetime", request: func(f *subagentProviderFixture) agentprovider.SubagentTokenRequest {
			return agentprovider.SubagentTokenRequest{Discriminator: "search", PublicKey: f.child.PublicJWK()}
		}},
		{name: "reserved claim", request: func(f *subagentProviderFixture) agentprovider.SubagentTokenRequest {
			return agentprovider.SubagentTokenRequest{
				Discriminator: "search", PublicKey: f.child.PublicJWK(), Lifetime: time.Minute,
				AdditionalClaims: map[string]json.RawMessage{"parent_agent": json.RawMessage(`"aauth:other@ap.example"`)},
			}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			f := newSubagentProviderFixture(t)
			if _, err := f.provider.IssueSubagent(context.Background(), f.parentToken(t, time.Hour), test.request(f)); err == nil {
				t.Fatal("IssueSubagent accepted an invalid child request")
			}
		})
	}
}
