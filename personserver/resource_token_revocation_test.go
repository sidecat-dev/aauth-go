package personserver

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

// Protocol 70d6737, Revocation Cascade: the recipient of a resource-token
// revocation issues no auth token against it, refuses a token request naming
// it with revoked_resource_token, and ends a pending request it started for it,
// which the Agent reads as revoked.
func TestWithdrawnResourceTokenEndsPSHostedConsent(t *testing.T) {
	t.Parallel()
	const withdrawnDetail = "The resource token this request was started for was revoked."
	p := newSubagentPersonServerProtocol(t)
	if err := p.store.Commit(context.Background(), PersonTokenRecord{
		JTI: "person-token", PersonServer: "https://ps.example", Resource: "https://resource.example",
		Subject: "person-123", Tenant: "tenant-1", ExpiresAt: p.now.Add(10 * time.Minute),
		RetainUntil: p.now.Add(15 * time.Minute), AgentProvider: "https://ap.example",
		Agent: "aauth:planner@ap.example", Confirmation: p.parentKey.PublicJWK(),
	}); err != nil {
		t.Fatal(err)
	}
	revocations := newReferenceAgentTokenRevocationStore()
	server, err := NewPSAuthorization(PSAuthorizationConfig{
		Issuer: "https://ps.example", SigningKey: p.personKey, KeyResolver: p.resolver,
		Clock: p.clock, NewID: func() string { return "auth-token" }, Tokens: p.store,
		BindPerson: p.policyPerson, Authorize: p.policyAuthorization,
		AuthorizationInteractions: newMemoryDeferredAuthorizationStore(),
		RequireAuthorizationInteraction: func(context.Context, AuthorizationRequest) (AuthorizationInteractionPolicy, bool, error) {
			return AuthorizationInteractionPolicy{URL: "https://ps.example/interact", Lifetime: time.Minute, RetryAfter: time.Second}, true, nil
		},
		TokenRevocation: &TokenRevocationConfig{Revocations: revocations},
	})
	if err != nil {
		t.Fatal(err)
	}
	resourceToken := p.resourceToken(t, "https://ps.example", "person-token", p.parentKey.PublicJWK())
	started := p.tokenRequestWithCapabilities(t, server, p.parentKey, p.parentToken, "", resourceToken, []string{"interaction"})
	if started.Code != http.StatusAccepted {
		t.Fatalf("consent = %d %s", started.Code, started.Body.String())
	}
	location := started.Header().Get("Location")
	requirement, err := aauth.ParseInteractionRequirement(started.Header().Values("AAuth-Requirement"))
	if err != nil {
		t.Fatal(err)
	}
	value, err := server.ConsumeAuthorizationInteractionCode(context.Background(), strings.TrimPrefix(requirement.URL, "https://ps.example/interact/"), requirement.Code)
	if err != nil {
		t.Fatal(err)
	}

	revocations.revoked[aauth.TokenReference{Issuer: "https://resource.example", JTI: "subagent-resource-token"}] = true
	decision := AuthorizationDecision{Scopes: []string{"records.read"}, Lifetime: time.Minute}
	if err := server.ApproveAuthorizationInteraction(context.Background(), value, decision); !errors.Is(err, ErrResourceTokenRevoked) {
		t.Fatalf("approval for a withdrawn resource token = %v", err)
	}
	poll := func() *httptest.ResponseRecorder {
		request := httptest.NewRequest(http.MethodGet, "https://ps.example"+location, nil)
		if err := signaturekey.SignJWTRequest(request, p.parentKey, p.parentToken, p.clock); err != nil {
			t.Fatal(err)
		}
		response := httptest.NewRecorder()
		server.Handler().ServeHTTP(response, request)
		return response
	}
	assertRevokedPendingProblem(t, poll(), withdrawnDetail)
	assertAuthorizationInteractionProblem(t, poll(), http.StatusGone, "invalid_code")

	again := p.tokenRequestWithCapabilities(t, server, p.parentKey, p.parentToken, "", resourceToken, []string{"interaction"})
	assertAuthorizationInteractionProblem(t, again, http.StatusBadRequest, "revoked_resource_token")
}
