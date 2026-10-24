package resource

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

func TestResourceChecksAuthTokenAgainstTheAskAndNotTheLoginHint(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 10, 24, 22, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	personKey := testSigningKey(t, "ask-person", 71)
	resourceKey := testSigningKey(t, "ask-resource", 72)
	agentKey := testSigningKey(t, "ask-agent", 73)
	otherPersonKey := testSigningKey(t, "ask-other-person", 74)
	resolver := signaturekey.StaticKeyResolver{
		{Issuer: personIssuer, DiscoveryDocument: aauth.PersonDiscoveryDocument, KeyID: personKey.ID()}:                    personKey.PublicJWK(),
		{Issuer: "https://other-ps.example", DiscoveryDocument: aauth.PersonDiscoveryDocument, KeyID: otherPersonKey.ID()}: otherPersonKey.PublicJWK(),
		{Issuer: resourceIssuer, DiscoveryDocument: aauth.ResourceDiscoveryDocument, KeyID: resourceKey.ID()}:              resourceKey.PublicJWK(),
	}
	const hint = "not-the-subject"
	ask := func(subject string) func(context.Context, *http.Request) (*AuthorizationAsk, error) {
		return func(context.Context, *http.Request) (*AuthorizationAsk, error) {
			return &AuthorizationAsk{
				PersonServer: personIssuer, LoginHint: hint, Subject: subject, Tenant: "tenant-1",
			}, nil
		}
	}
	newServer := func(callback func(context.Context, *http.Request) (*AuthorizationAsk, error)) *Server {
		t.Helper()
		server, err := NewPSAuthorization(PSAuthorizationConfig{
			Issuer: resourceIssuer, SigningKey: resourceKey, KeyResolver: resolver,
			Clock: clock, NewID: func() string { return "ask-resource-token" },
			ScopeDescriptions: map[string]string{"records.read": "Read records"},
			RequiredScopes:    func(*http.Request) []string { return []string{"records.read"} },
			ResolvePerson:     func(context.Context, PersonIdentity, PersonContext) error { return nil },
			AuthorizationAsk:  callback,
			Protected:         http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}),
		})
		if err != nil {
			t.Fatal(err)
		}
		return server
	}
	server := newServer(ask("person-1"))
	personToken := mintPersonToken(t, personKey, agentKey.PublicJWK(), now, resourceIssuer, "ask-person-token")
	challenge := signedRequest(t, clock, agentKey, personToken, http.MethodGet, resourceIssuer+"/records", "")
	challengeResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(challengeResponse, challenge)
	requirement := parseAuthTokenRequirement(t, challengeResponse)
	claims, err := aauth.VerifyResourceToken(context.Background(), requirement.ResourceToken, resolver, clock)
	if err != nil {
		t.Fatal(err)
	}
	if claims.LoginHint != hint || claims.Subject != "person-1" {
		t.Fatalf("resource token hint = %q subject = %q", claims.LoginHint, claims.Subject)
	}

	admit := func(token string) *httptest.ResponseRecorder {
		t.Helper()
		response := httptest.NewRecorder()
		server.Handler().ServeHTTP(response, signedRequest(t, clock, agentKey, token, http.MethodGet, resourceIssuer+"/records", ""))
		return response
	}
	matching := mintAuthToken(t, personKey, agentKey.PublicJWK(), now, aauth.AuthTokenClaims{
		Issuer: personIssuer, DWK: aauth.PersonDiscoveryDocument, Audience: resourceIssuer,
		JTI: "ask-auth", PersonServer: personIssuer, Subject: "person-1", Scope: "records.read", Tenant: "tenant-1",
	})
	if response := admit(matching); response.Code != http.StatusOK {
		t.Fatalf("matching auth = %d %s", response.Code, response.Body.String())
	}
	otherSubject := mintAuthToken(t, personKey, agentKey.PublicJWK(), now, aauth.AuthTokenClaims{
		Issuer: personIssuer, DWK: aauth.PersonDiscoveryDocument, Audience: resourceIssuer,
		JTI: "ask-other-sub", PersonServer: personIssuer, Subject: hint, Scope: "records.read", Tenant: "tenant-1",
	})
	mismatch := admit(otherSubject)
	if mismatch.Code != http.StatusForbidden || mismatch.Header().Get("Signature-Error") != "" || mismatch.Header().Get("AAuth-Requirement") != "" {
		t.Fatalf("hint-as-subject = %d signature-error=%q requirement=%q body=%s", mismatch.Code, mismatch.Header().Get("Signature-Error"), mismatch.Header().Get("AAuth-Requirement"), mismatch.Body.String())
	}
	var problem struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(mismatch.Body.Bytes(), &problem); err != nil || problem.Error != "access_denied" {
		t.Fatalf("mismatch problem = %#v %v", problem, err)
	}
	otherPS := mintAuthToken(t, otherPersonKey, agentKey.PublicJWK(), now, aauth.AuthTokenClaims{
		Issuer: "https://other-ps.example", DWK: aauth.PersonDiscoveryDocument, Audience: resourceIssuer,
		JTI: "ask-other-ps", PersonServer: "https://other-ps.example", Subject: "person-1", Scope: "records.read", Tenant: "tenant-1",
	})
	if response := admit(otherPS); response.Code != http.StatusForbidden {
		t.Fatalf("other person server = %d %s", response.Code, response.Body.String())
	}

	broken := newServer(ask(""))
	brokenResponse := httptest.NewRecorder()
	broken.Handler().ServeHTTP(brokenResponse, signedRequest(t, clock, agentKey, matching, http.MethodGet, resourceIssuer+"/records", ""))
	if brokenResponse.Code != http.StatusInternalServerError {
		t.Fatalf("empty ask subject = %d %s", brokenResponse.Code, brokenResponse.Body.String())
	}
}
