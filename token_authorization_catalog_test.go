package aauth

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"gitlab.com/sidecat-dev/aauth-go/jose"
)

func TestCoreAuthorizationMemberCatalogIsCompleteUniqueAndApplicable(t *testing.T) {
	want := map[string]struct {
		profiles         tokenProfileSet
		resourceRequires []string
		authRequires     []string
	}{
		"r3_uri": {
			profiles:         resourceTokenProfile | authTokenProfile,
			resourceRequires: []string{"r3_s256"},
			authRequires:     []string{"r3_s256", "r3_granted"},
		},
		"r3_s256": {
			profiles:         resourceTokenProfile | authTokenProfile,
			resourceRequires: []string{"r3_uri"},
			authRequires:     []string{"r3_uri", "r3_granted"},
		},
		"r3_granted":      {profiles: authTokenProfile, authRequires: []string{"r3_uri", "r3_s256"}},
		"r3_per_call":     {profiles: authTokenProfile, authRequires: []string{"r3_uri", "r3_s256", "r3_granted"}},
		"budget":          {profiles: resourceTokenProfile | authTokenProfile},
		"budget_consumed": {profiles: resourceTokenProfile, resourceRequires: []string{"budget"}},
	}
	seen := make(map[string]bool, len(coreAuthorizationMemberCatalog))
	for _, rule := range coreAuthorizationMemberCatalog {
		if seen[rule.name] {
			t.Fatalf("authorization member %q appears more than once", rule.name)
		}
		seen[rule.name] = true
		expected, ok := want[rule.name]
		if !ok {
			t.Fatalf("unexpected authorization member %q", rule.name)
		}
		if rule.profiles != expected.profiles ||
			!reflect.DeepEqual(rule.resourceRequires, expected.resourceRequires) ||
			!reflect.DeepEqual(rule.authRequires, expected.authRequires) {
			t.Fatalf("authorization member %q = %#v, want %#v", rule.name, rule, expected)
		}
	}
	if len(seen) != len(want) {
		t.Fatalf("authorization member catalog = %#v, want %#v", seen, want)
	}
	if seen["r3_conditional"] {
		t.Fatal("removed r3_conditional is a current catalog member")
	}
}

func TestCoreAuthorizationMemberCatalogEnforcesApplicabilityAndCoPresence(t *testing.T) {
	for _, test := range []struct {
		name      string
		tokenType string
		members   map[string]json.RawMessage
		want      []string
	}{
		{
			name:      "resource R3 pair",
			tokenType: ResourceTokenType,
			members:   map[string]json.RawMessage{"r3_uri": json.RawMessage(`"https://resource.example/r3"`), "r3_s256": json.RawMessage(`"digest"`)},
		},
		{
			name:      "auth complete R3 set",
			tokenType: AuthTokenType,
			members: map[string]json.RawMessage{
				"r3_uri":      json.RawMessage(`"https://resource.example/r3"`),
				"r3_s256":     json.RawMessage(`"digest"`),
				"r3_granted":  json.RawMessage(`{}`),
				"r3_per_call": json.RawMessage(`{}`),
			},
		},
		{
			name:      "resource budget history",
			tokenType: ResourceTokenType,
			members:   map[string]json.RawMessage{"budget": json.RawMessage(`{}`), "budget_consumed": json.RawMessage(`[]`)},
		},
		{
			name:      "resource R3 pair incomplete",
			tokenType: ResourceTokenType,
			members:   map[string]json.RawMessage{"r3_uri": json.RawMessage(`"https://resource.example/r3"`)},
			want:      []string{"r3_uri", "r3_s256"},
		},
		{
			name:      "auth R3 grant missing",
			tokenType: AuthTokenType,
			members:   map[string]json.RawMessage{"r3_uri": json.RawMessage(`"https://resource.example/r3"`), "r3_s256": json.RawMessage(`"digest"`)},
			want:      []string{"r3_granted"},
		},
		{
			name:      "budget history without budget",
			tokenType: ResourceTokenType,
			members:   map[string]json.RawMessage{"budget_consumed": json.RawMessage(`[]`)},
			want:      []string{"budget_consumed", "budget"},
		},
		{
			name:      "auth cannot report budget history",
			tokenType: AuthTokenType,
			members:   map[string]json.RawMessage{"budget_consumed": json.RawMessage(`[]`)},
			want:      []string{"budget_consumed", "aa-auth+jwt"},
		},
		{
			name:      "person cannot carry R3",
			tokenType: PersonTokenType,
			members:   map[string]json.RawMessage{"r3_uri": json.RawMessage(`"https://resource.example/r3"`), "r3_s256": json.RawMessage(`"digest"`)},
			want:      []string{"r3_uri", "aa-person+jwt"},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := inspectCoreAuthorizationMembers(test.members, test.tokenType)
			if len(test.want) == 0 {
				if err != nil || len(got) != len(test.members) {
					t.Fatalf("inspection = %#v, %v", got, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("inspection accepted %#v", test.members)
			}
			for _, text := range test.want {
				if !strings.Contains(err.Error(), text) {
					t.Fatalf("error = %v, want %q", err, text)
				}
			}
		})
	}
}

func TestRecognizedAndRemovedAuthorizationMembersFailBeforeKeyResolution(t *testing.T) {
	now := time.Date(2026, 8, 29, 4, 0, 0, 0, time.UTC)
	issuerKey := internalTestSigningKey(t, "issuer-key")
	requestKey := internalTestSigningKey(t, "request-key")
	thumbprint, err := requestKey.PublicJWK().Thumbprint()
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name      string
		tokenType string
		claims    any
		members   map[string]json.RawMessage
		verify    func(string, *catalogKeyResolver) error
	}{
		{
			name:      "agent budget",
			tokenType: AgentTokenType,
			claims: AgentTokenClaims{
				Issuer: "https://provider.example", DWK: AgentDiscoveryDocument,
				Subject: "aauth:worker@provider.example", JTI: "agent-catalog",
				Confirmation: Confirmation{JWK: requestKey.PublicJWK()},
				IssuedAt:     now.Unix(), ExpiresAt: now.Add(time.Hour).Unix(),
			},
			members: map[string]json.RawMessage{"budget": json.RawMessage(`{}`)},
			verify: func(compact string, resolver *catalogKeyResolver) error {
				_, err := VerifyAgentToken(context.Background(), compact, resolver, ClockFunc(func() time.Time { return now }))
				return err
			},
		},
		{
			name:      "person R3",
			tokenType: PersonTokenType,
			claims: PersonTokenClaims{
				Issuer: "https://person.example", DWK: PersonDiscoveryDocument,
				Audience: "https://resource.example", Subject: "directed-person",
				Confirmation: Confirmation{JWK: requestKey.PublicJWK()}, JTI: "person-catalog",
				IssuedAt: now.Unix(), ExpiresAt: now.Add(time.Hour).Unix(),
			},
			members: map[string]json.RawMessage{
				"r3_uri":  json.RawMessage(`"https://resource.example/r3"`),
				"r3_s256": json.RawMessage(`"digest"`),
			},
			verify: func(compact string, resolver *catalogKeyResolver) error {
				_, err := VerifyPersonToken(context.Background(), compact, resolver, ClockFunc(func() time.Time { return now }))
				return err
			},
		},
		{
			name:      "resource complete budget",
			tokenType: ResourceTokenType,
			claims: ResourceTokenClaims{
				Issuer: "https://resource.example", DWK: ResourceDiscoveryDocument,
				Audience: "https://person.example", JTI: "resource-catalog", AgentJKT: thumbprint,
				IssuedAt: now.Unix(), ExpiresAt: now.Add(time.Minute).Unix(), Scope: "documents.read",
				PersonServer: "https://person.example", Subject: "directed-person", PresentedJTI: "person-catalog",
			},
			members: map[string]json.RawMessage{"budget": json.RawMessage(`{}`)},
			verify: func(compact string, resolver *catalogKeyResolver) error {
				_, err := VerifyResourceToken(context.Background(), compact, resolver, ClockFunc(func() time.Time { return now }))
				return err
			},
		},
		{
			name:      "auth complete R3",
			tokenType: AuthTokenType,
			claims: AuthTokenClaims{
				Issuer: "https://person.example", DWK: PersonDiscoveryDocument,
				Audience: "https://resource.example", JTI: "auth-catalog",
				Confirmation: Confirmation{JWK: requestKey.PublicJWK()},
				IssuedAt:     now.Unix(), ExpiresAt: now.Add(time.Minute).Unix(),
				Subject: "directed-person", Scope: "documents.read", PersonServer: "https://person.example",
			},
			members: map[string]json.RawMessage{
				"r3_uri":     json.RawMessage(`"https://resource.example/r3"`),
				"r3_s256":    json.RawMessage(`"digest"`),
				"r3_granted": json.RawMessage(`{}`),
			},
			verify: func(compact string, resolver *catalogKeyResolver) error {
				_, err := VerifyAuthToken(context.Background(), compact, resolver, ClockFunc(func() time.Time { return now }))
				return err
			},
		},
		{
			name:      "removed conditional",
			tokenType: AuthTokenType,
			claims: AuthTokenClaims{
				Issuer: "https://person.example", DWK: PersonDiscoveryDocument,
				Audience: "https://resource.example", JTI: "auth-obsolete",
				Confirmation: Confirmation{JWK: requestKey.PublicJWK()},
				IssuedAt:     now.Unix(), ExpiresAt: now.Add(time.Minute).Unix(),
				Subject: "directed-person", Scope: "documents.read", PersonServer: "https://person.example",
			},
			members: map[string]json.RawMessage{"r3_conditional": json.RawMessage(`{}`)},
			verify: func(compact string, resolver *catalogKeyResolver) error {
				_, err := VerifyAuthToken(context.Background(), compact, resolver, ClockFunc(func() time.Time { return now }))
				return err
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			payload, err := json.Marshal(test.claims)
			if err != nil {
				t.Fatal(err)
			}
			var object map[string]json.RawMessage
			if err := json.Unmarshal(payload, &object); err != nil {
				t.Fatal(err)
			}
			for name, raw := range test.members {
				object[name] = raw
			}
			payload, err = json.Marshal(object)
			if err != nil {
				t.Fatal(err)
			}
			compact := signRawTestToken(t, issuerKey, test.tokenType, payload)
			resolver := &catalogKeyResolver{key: issuerKey.PublicJWK()}
			err = test.verify(compact, resolver)
			if err == nil || !strings.Contains(err.Error(), "unsupported") {
				t.Fatalf("error = %v", err)
			}
			if resolver.calls != 0 {
				t.Fatalf("key resolver calls = %d, want 0", resolver.calls)
			}
		})
	}
}

type catalogKeyResolver struct {
	key   jose.JWK
	calls int
}

func (resolver *catalogKeyResolver) ResolveKey(context.Context, string, string, string) (jose.JWK, error) {
	resolver.calls++
	return resolver.key, nil
}
