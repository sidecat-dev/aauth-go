package accessserver

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

// TestServerAppliesThePersonServersNarrowing checks the scope and exp members
// a Person Server sends for its supervisor's narrowing: the grant stays
// within the scope and the token ends by exp, and a scope outside the
// resource token's or an exp already past is refused before policy runs.
func TestServerAppliesThePersonServersNarrowing(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 11, 1, 9, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	apKey := accessServerTestKey(t, "ap-key")
	psKey := accessServerTestKey(t, "ps-key")
	resourceKey := accessServerTestKey(t, "resource-key")
	accessKey := accessServerTestKey(t, "access-key")
	agentKey := accessServerTestKey(t, "agent-key")
	resolver := signaturekey.StaticKeyResolver{
		{Issuer: "https://ap.example", DiscoveryDocument: aauth.AgentDiscoveryDocument, KeyID: apKey.ID()}:                apKey.PublicJWK(),
		{Issuer: "https://ps.example", DiscoveryDocument: aauth.PersonDiscoveryDocument, KeyID: psKey.ID()}:               psKey.PublicJWK(),
		{Issuer: "https://resource.example", DiscoveryDocument: aauth.ResourceDiscoveryDocument, KeyID: resourceKey.ID()}: resourceKey.PublicJWK(),
		{Issuer: "https://as.example", DiscoveryDocument: aauth.AccessDiscoveryDocument, KeyID: accessKey.ID()}:           accessKey.PublicJWK(),
	}
	agentToken, err := aauth.MintAgentToken("https://ap.example", apKey, aauth.AgentTokenRequest{
		Agent: "aauth:planner@ap.example", PersonServer: "https://ps.example", PublicKey: agentKey.PublicJWK(), Lifetime: time.Hour,
	}, now, "agent-token-1")
	if err != nil {
		t.Fatal(err)
	}
	agentJKT, err := agentKey.PublicJWK().Thumbprint()
	if err != nil {
		t.Fatal(err)
	}
	resourceToken, err := aauth.MintResourceToken(resourceKey, aauth.ResourceTokenClaims{
		Issuer: "https://resource.example", DWK: aauth.ResourceDiscoveryDocument, Audience: "https://as.example",
		JTI: "resource-token-1", AgentJKT: agentJKT, IssuedAt: now.Unix(), ExpiresAt: now.Add(5 * time.Minute).Unix(),
		Scope: "records.read records.write", PersonServer: "https://ps.example", Subject: "directed-person-1",
		PresentedJTI: "person-token-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	presentedToken := accessServerPresentedToken(t, psKey, now, resourceToken, agentKey)
	var evaluated []AuthorizationRequest
	server, err := New(Config{
		Issuer: "https://as.example", SigningKey: accessKey, KeyResolver: resolver, Clock: clock,
		NewID:             func() string { return "auth-token-1" },
		TrustPersonServer: func(context.Context, string) error { return nil },
		Authorize: func(_ context.Context, request AuthorizationRequest) (Decision, error) {
			evaluated = append(evaluated, request)
			return Decision{Scopes: append([]string(nil), request.Scopes...), Lifetime: 30 * time.Minute}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	call := func(narrowing map[string]any) *httptest.ResponseRecorder {
		t.Helper()
		input := map[string]any{"resource_token": resourceToken, "agent_token": agentToken, "presented_token": presentedToken}
		for name, value := range narrowing {
			input[name] = value
		}
		body, err := json.Marshal(input)
		if err != nil {
			t.Fatal(err)
		}
		request := httptest.NewRequest(http.MethodPost, "https://as.example/token", bytes.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		if err := signaturekey.SignJWKSURIRequestWithOptions(
			request, psKey, "https://ps.example", aauth.PersonDiscoveryDocument, clock,
			signaturekey.SignOptions{AdditionalComponents: []string{"content-type", "content-digest"}, MaxBodyBytes: int64(len(body))},
		); err != nil {
			t.Fatal(err)
		}
		response := httptest.NewRecorder()
		server.Handler().ServeHTTP(response, request)
		return response
	}

	bound := now.Add(10 * time.Minute).Unix()
	response := call(map[string]any{"scope": "records.read", "exp": bound})
	if response.Code != http.StatusOK {
		t.Fatalf("narrowed request = %d %s", response.Code, response.Body.String())
	}
	var output struct {
		AuthToken string `json:"auth_token"`
	}
	if err := json.NewDecoder(response.Body).Decode(&output); err != nil {
		t.Fatal(err)
	}
	claims, err := aauth.VerifyAuthToken(context.Background(), output.AuthToken, resolver, clock)
	if err != nil {
		t.Fatal(err)
	}
	if claims.Scope != "records.read" || claims.ExpiresAt != bound ||
		len(evaluated) != 1 || !slices.Equal(evaluated[0].Scopes, []string{"records.read"}) {
		t.Fatalf("narrowed token scope %q exp %d, policy saw %#v", claims.Scope, claims.ExpiresAt, evaluated)
	}

	for name, narrowing := range map[string]map[string]any{
		"scope outside the resource token": {"scope": "records.delete"},
		"empty scope":                      {"scope": ""},
		"scope not a string":               {"scope": []string{"records.read"}},
		"exp already past":                 {"exp": now.Unix()},
		"exp not a NumericDate":            {"exp": "soon"},
	} {
		response := call(narrowing)
		if response.Code != http.StatusBadRequest {
			t.Fatalf("%s = %d, want 400", name, response.Code)
		}
		assertAccessProblem(t, response, "invalid_request")
	}
	if len(evaluated) != 1 {
		t.Fatalf("policy ran %d times, want only for the valid narrowing", len(evaluated))
	}
}
