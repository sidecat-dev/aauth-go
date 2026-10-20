package aauth_test

import (
	"context"
	"errors"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

// Protocol 28e8258, Sub-Agent Identity, Single-Level Depth and
// Parent-Mediated Authorization: the child token is verified on its own, then
// bound to the verified parent through parent_agent, one issuer and its own key.
type subagentCoreFixture struct {
	now      time.Time
	clock    aauth.Clock
	provider jose.SigningKey
	foreign  jose.SigningKey
	parent   jose.SigningKey
	child    jose.SigningKey
	resolver signaturekey.StaticKeyResolver
}

func newSubagentCoreFixture(t *testing.T) *subagentCoreFixture {
	t.Helper()
	f := &subagentCoreFixture{
		now:      time.Date(2026, 10, 20, 18, 0, 0, 0, time.UTC),
		provider: coreTokenKey(t, "provider-key"),
		foreign:  coreTokenKey(t, "foreign-provider-key"),
		parent:   coreTokenKey(t, "parent-key"),
		child:    coreTokenKey(t, "child-key"),
	}
	f.clock = aauth.ClockFunc(func() time.Time { return f.now })
	f.resolver = signaturekey.StaticKeyResolver{
		{Issuer: "https://agents.example", DiscoveryDocument: aauth.AgentDiscoveryDocument, KeyID: f.provider.ID()}: f.provider.PublicJWK(),
		{Issuer: "https://other.example", DiscoveryDocument: aauth.AgentDiscoveryDocument, KeyID: f.foreign.ID()}:   f.foreign.PublicJWK(),
	}
	return f
}

func (f *subagentCoreFixture) mint(t *testing.T, issuer string, key jose.SigningKey, request aauth.AgentTokenRequest, issuedAt time.Time, jti string) string {
	t.Helper()
	compact, err := aauth.MintAgentToken(issuer, key, request, issuedAt, jti)
	if err != nil {
		t.Fatal(err)
	}
	return compact
}

func (f *subagentCoreFixture) parentClaims(t *testing.T) aauth.AgentTokenClaims {
	t.Helper()
	compact := f.mint(t, "https://agents.example", f.provider, aauth.AgentTokenRequest{
		Agent: "aauth:planner@agents.example", PersonServer: "https://person.example",
		PublicKey: f.parent.PublicJWK(), Lifetime: time.Hour,
	}, f.now, "parent")
	claims, err := aauth.VerifyAgentToken(context.Background(), compact, f.resolver, f.clock)
	if err != nil {
		t.Fatal(err)
	}
	return claims
}

func (f *subagentCoreFixture) childRequest() aauth.AgentTokenRequest {
	return aauth.AgentTokenRequest{
		Agent: "aauth:planner+search@agents.example", ParentAgent: "aauth:planner@agents.example",
		PublicKey: f.child.PublicJWK(), Lifetime: 10 * time.Minute,
	}
}

func TestVerifySubagentTokenReturnsTheVerifiedChild(t *testing.T) {
	t.Parallel()

	f := newSubagentCoreFixture(t)
	parent := f.parentClaims(t)
	compact := f.mint(t, "https://agents.example", f.provider, f.childRequest(), f.now, "child")
	child, err := aauth.VerifySubagentToken(context.Background(), compact, parent, f.resolver, f.clock)
	if err != nil {
		t.Fatal(err)
	}
	if child.Subject != "aauth:planner+search@agents.example" || child.ParentAgent != parent.Subject ||
		child.Issuer != parent.Issuer || !child.Confirmation.JWK.Equal(f.child.PublicJWK()) {
		t.Fatalf("child = %#v", child)
	}
}

func TestVerifySubagentTokenRefusesEachBrokenRelationship(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name   string
		child  func(*testing.T, *subagentCoreFixture) string
		parent func(*testing.T, *subagentCoreFixture) aauth.AgentTokenClaims
		want   error
	}{
		{name: "malformed", want: aauth.ErrInvalidSubagentToken, child: func(*testing.T, *subagentCoreFixture) string {
			return "not-a-token"
		}},
		{name: "untrusted signature", want: aauth.ErrInvalidSubagentToken, child: func(t *testing.T, f *subagentCoreFixture) string {
			return f.mint(t, "https://agents.example", f.foreign, f.childRequest(), f.now, "forged")
		}},
		{name: "expired", want: aauth.ErrExpiredSubagentToken, child: func(t *testing.T, f *subagentCoreFixture) string {
			request := f.childRequest()
			request.Lifetime = time.Minute
			return f.mint(t, "https://agents.example", f.provider, request, f.now.Add(-2*time.Minute), "expired")
		}},
		{name: "top-level token", want: aauth.ErrInvalidSubagentToken, child: func(t *testing.T, f *subagentCoreFixture) string {
			return f.mint(t, "https://agents.example", f.provider, aauth.AgentTokenRequest{
				Agent: "aauth:worker@agents.example", PublicKey: f.child.PublicJWK(), Lifetime: time.Hour,
			}, f.now, "top-level")
		}},
		{name: "another parent", want: aauth.ErrInvalidSubagentToken, child: func(t *testing.T, f *subagentCoreFixture) string {
			return f.mint(t, "https://agents.example", f.provider, aauth.AgentTokenRequest{
				Agent: "aauth:other+search@agents.example", ParentAgent: "aauth:other@agents.example",
				PublicKey: f.child.PublicJWK(), Lifetime: time.Hour,
			}, f.now, "other-parent")
		}},
		{name: "foreign provider", want: aauth.ErrInvalidSubagentToken, child: func(t *testing.T, f *subagentCoreFixture) string {
			return f.mint(t, "https://other.example", f.foreign, aauth.AgentTokenRequest{
				Agent: "aauth:planner+search@other.example", ParentAgent: "aauth:planner@other.example",
				PublicKey: f.child.PublicJWK(), Lifetime: time.Hour,
			}, f.now, "foreign")
		}},
		{name: "parent key reused", want: aauth.ErrInvalidSubagentToken, child: func(t *testing.T, f *subagentCoreFixture) string {
			request := f.childRequest()
			request.PublicKey = f.parent.PublicJWK()
			return f.mint(t, "https://agents.example", f.provider, request, f.now, "shared-key")
		}},
		// A caller passes the verified claims of the request signer. Claims that
		// name the child's parent under another issuer are still refused, so the
		// one-issuer rule does not depend on identifier naming.
		{name: "parent issued elsewhere", want: aauth.ErrInvalidSubagentToken,
			child: func(t *testing.T, f *subagentCoreFixture) string {
				return f.mint(t, "https://agents.example", f.provider, f.childRequest(), f.now, "child")
			},
			parent: func(t *testing.T, f *subagentCoreFixture) aauth.AgentTokenClaims {
				parent := f.parentClaims(t)
				parent.Issuer = "https://other.example"
				return parent
			}},
		{name: "parent is a sub-agent", want: aauth.ErrInvalidSubagentToken,
			child: func(t *testing.T, f *subagentCoreFixture) string {
				return f.mint(t, "https://agents.example", f.provider, f.childRequest(), f.now, "child")
			},
			parent: func(t *testing.T, f *subagentCoreFixture) aauth.AgentTokenClaims {
				parent := f.parentClaims(t)
				parent.ParentAgent = "aauth:root@agents.example"
				return parent
			}},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			f := newSubagentCoreFixture(t)
			parent := f.parentClaims(t)
			if test.parent != nil {
				parent = test.parent(t, f)
			}
			_, err := aauth.VerifySubagentToken(context.Background(), test.child(t, f), parent, f.resolver, f.clock)
			if !errors.Is(err, test.want) {
				t.Fatalf("error = %v, want %v", err, test.want)
			}
			other := aauth.ErrExpiredSubagentToken
			if test.want == aauth.ErrExpiredSubagentToken {
				other = aauth.ErrInvalidSubagentToken
			}
			if errors.Is(err, other) {
				t.Fatalf("error %v matches both sub-agent classes", err)
			}
		})
	}
}

// A grandchild names an intervening sub-agent as its parent. Minting refuses
// it, so the provider key signs the claims directly; verification refuses the
// second level even when the top-level Agent presents it.
func TestVerifySubagentTokenRefusesAGrandchild(t *testing.T) {
	t.Parallel()

	f := newSubagentCoreFixture(t)
	parent := f.parentClaims(t)
	if _, err := aauth.MintAgentToken("https://agents.example", f.provider, aauth.AgentTokenRequest{
		Agent: "aauth:planner+search+deep@agents.example", ParentAgent: "aauth:planner+search@agents.example",
		PublicKey: coreTokenKey(t, "grandchild-key").PublicJWK(), Lifetime: time.Hour,
	}, f.now, "grandchild"); err == nil {
		t.Fatal("grandchild token was minted")
	}
	forged := signCoreTokenPayload(t, f.provider, aauth.AgentTokenType, map[string]any{
		"iss": "https://agents.example", "dwk": aauth.AgentDiscoveryDocument,
		"sub": "aauth:planner+search+deep@agents.example", "parent_agent": "aauth:planner+search@agents.example",
		"jti": "grandchild", "iat": f.now.Unix(), "exp": f.now.Add(time.Hour).Unix(),
		"cnf": map[string]any{"jwk": coreTokenKey(t, "grandchild-key").PublicJWK()},
	})
	if _, err := aauth.VerifySubagentToken(context.Background(), forged, parent, f.resolver, f.clock); !errors.Is(err, aauth.ErrInvalidSubagentToken) {
		t.Fatalf("grandchild verification = %v", err)
	}
}
