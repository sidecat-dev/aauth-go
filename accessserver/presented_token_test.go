package accessserver

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

const (
	presentedProviderID = "https://ap.example"
	presentedPersonID   = "https://ps.example"
	presentedResourceID = "https://resource.example"
	presentedAccessID   = "https://as.example"
)

// presentedTokenProtocol holds the parties of one token request whose
// presented_token the Access Server has to verify for itself.
type presentedTokenProtocol struct {
	now         time.Time
	clock       aauth.Clock
	providerKey jose.SigningKey
	personKey   jose.SigningKey
	resourceKey jose.SigningKey
	accessKey   jose.SigningKey
	agentKey    jose.SigningKey
	resolver    signaturekey.StaticKeyResolver
	agentToken  string
	agentJKT    string
	lifetime    time.Duration
	server      *Server
}

func newPresentedTokenProtocol(t *testing.T) *presentedTokenProtocol {
	t.Helper()
	protocol := &presentedTokenProtocol{
		now:         time.Date(2026, 10, 3, 18, 0, 0, 0, time.UTC),
		providerKey: accessServerTestKey(t, "presented-provider"),
		personKey:   accessServerTestKey(t, "presented-person"),
		resourceKey: accessServerTestKey(t, "presented-resource"),
		accessKey:   accessServerTestKey(t, "presented-access"),
		agentKey:    accessServerTestKey(t, "presented-agent"),
		lifetime:    time.Hour,
	}
	protocol.clock = aauth.ClockFunc(func() time.Time { return protocol.now })
	protocol.resolver = signaturekey.StaticKeyResolver{
		{Issuer: presentedProviderID, DiscoveryDocument: aauth.AgentDiscoveryDocument, KeyID: protocol.providerKey.ID()}:    protocol.providerKey.PublicJWK(),
		{Issuer: presentedPersonID, DiscoveryDocument: aauth.PersonDiscoveryDocument, KeyID: protocol.personKey.ID()}:       protocol.personKey.PublicJWK(),
		{Issuer: presentedResourceID, DiscoveryDocument: aauth.ResourceDiscoveryDocument, KeyID: protocol.resourceKey.ID()}: protocol.resourceKey.PublicJWK(),
		{Issuer: presentedAccessID, DiscoveryDocument: aauth.AccessDiscoveryDocument, KeyID: protocol.accessKey.ID()}:       protocol.accessKey.PublicJWK(),
	}
	var err error
	protocol.agentToken, err = aauth.MintAgentToken(presentedProviderID, protocol.providerKey, aauth.AgentTokenRequest{
		Agent: "aauth:planner@ap.example", PersonServer: presentedPersonID,
		PublicKey: protocol.agentKey.PublicJWK(), Lifetime: 2 * time.Hour,
	}, protocol.now, "presented-agent-token")
	if err != nil {
		t.Fatal(err)
	}
	protocol.agentJKT, err = protocol.agentKey.PublicJWK().Thumbprint()
	if err != nil {
		t.Fatal(err)
	}
	protocol.server, err = New(Config{
		Issuer: presentedAccessID, SigningKey: protocol.accessKey, KeyResolver: protocol.resolver,
		Clock: protocol.clock, NewID: func() string { return "issued-auth-token" },
		TrustPersonServer: func(context.Context, string) error { return nil },
		Authorize: func(context.Context, AuthorizationRequest) (Decision, error) {
			return Decision{Scopes: []string{"records.read"}, Lifetime: protocol.lifetime}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return protocol
}

func (protocol *presentedTokenProtocol) personToken(
	t *testing.T, key jose.SigningKey, confirmation jose.JWK, jti string, expiresAt time.Time,
) string {
	t.Helper()
	compact, err := aauth.MintPersonToken(key, aauth.PersonTokenClaims{
		Issuer: presentedPersonID, DWK: aauth.PersonDiscoveryDocument, Audience: presentedResourceID,
		Subject: "person-123", Confirmation: aauth.Confirmation{JWK: confirmation},
		JTI: jti, IssuedAt: protocol.now.Add(-time.Minute).Unix(), ExpiresAt: expiresAt.Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return compact
}

// authToken mints the auth token this Access Server issued earlier and the
// agent now presents on step-up.
func (protocol *presentedTokenProtocol) authToken(t *testing.T, jti string, expiresAt time.Time) string {
	t.Helper()
	compact, err := aauth.MintAuthToken(protocol.accessKey, aauth.AuthTokenClaims{
		Issuer: presentedAccessID, DWK: aauth.AccessDiscoveryDocument, Audience: presentedResourceID, JTI: jti,
		Confirmation: aauth.Confirmation{JWK: protocol.agentKey.PublicJWK()},
		IssuedAt:     protocol.now.Add(-time.Minute).Unix(), ExpiresAt: expiresAt.Unix(),
		Subject: "person-123", Scope: "records.read", PersonServer: presentedPersonID,
	})
	if err != nil {
		t.Fatal(err)
	}
	return compact
}

func (protocol *presentedTokenProtocol) resourceToken(t *testing.T, presentedJTI string) string {
	t.Helper()
	compact, err := aauth.MintResourceToken(protocol.resourceKey, aauth.ResourceTokenClaims{
		Issuer: presentedResourceID, DWK: aauth.ResourceDiscoveryDocument, Audience: presentedAccessID,
		JTI: "presented-resource-token", AgentJKT: protocol.agentJKT,
		IssuedAt: protocol.now.Unix(), ExpiresAt: protocol.now.Add(5 * time.Minute).Unix(),
		Scope: "records.read records.write", PersonServer: presentedPersonID,
		Subject: "person-123", PresentedJTI: presentedJTI,
	})
	if err != nil {
		t.Fatal(err)
	}
	return compact
}

// exchange sends the Person Server's signed token request. An empty
// presented token leaves the member out.
func (protocol *presentedTokenProtocol) exchange(t *testing.T, resourceToken, presented string) *httptest.ResponseRecorder {
	t.Helper()
	input := map[string]any{"resource_token": resourceToken, "agent_token": protocol.agentToken}
	if presented != "" {
		input["presented_token"] = presented
	}
	body, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, presentedAccessID+"/token", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	if err := signaturekey.SignJWKSURIRequestWithOptions(
		request, protocol.personKey, presentedPersonID, aauth.PersonDiscoveryDocument, protocol.clock,
		signaturekey.SignOptions{
			AdditionalComponents: []string{"content-type", "content-digest"},
			MaxBodyBytes:         int64(len(body)),
		},
	); err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	protocol.server.Handler().ServeHTTP(response, request)
	return response
}

func (protocol *presentedTokenProtocol) issuedAuthToken(t *testing.T, response *httptest.ResponseRecorder) aauth.AuthTokenClaims {
	t.Helper()
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	var output struct {
		AuthToken string `json:"auth_token"`
		ExpiresIn int64  `json:"expires_in"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &output); err != nil {
		t.Fatal(err)
	}
	claims, err := aauth.VerifyAuthToken(context.Background(), output.AuthToken, protocol.resolver, protocol.clock)
	if err != nil {
		t.Fatal(err)
	}
	if output.ExpiresIn != claims.ExpiresAt-claims.IssuedAt {
		t.Fatalf("expires_in = %d, token lifetime = %d", output.ExpiresIn, claims.ExpiresAt-claims.IssuedAt)
	}
	return claims
}

func TestTokenEndpointVerifiesPersonTypedPresentedToken(t *testing.T) {
	t.Parallel()
	protocol := newPresentedTokenProtocol(t)
	protocol.lifetime = 20 * time.Minute
	presented := protocol.personToken(
		t, protocol.personKey, protocol.agentKey.PublicJWK(), "person-token-1", protocol.now.Add(45*time.Minute),
	)

	claims := protocol.issuedAuthToken(t, protocol.exchange(t, protocol.resourceToken(t, "person-token-1"), presented))

	if claims.Subject != "person-123" || claims.Scope != "records.read" {
		t.Fatalf("issued claims = %#v", claims)
	}
	if want := protocol.now.Add(20 * time.Minute).Unix(); claims.ExpiresAt != want {
		t.Fatalf("exp = %d, want the policy lifetime %d", claims.ExpiresAt, want)
	}
}

func TestTokenEndpointCapsExpiryAtThePresentedToken(t *testing.T) {
	t.Parallel()
	protocol := newPresentedTokenProtocol(t)
	ceiling := protocol.now.Add(10 * time.Minute)
	presented := protocol.personToken(t, protocol.personKey, protocol.agentKey.PublicJWK(), "person-token-1", ceiling)

	claims := protocol.issuedAuthToken(t, protocol.exchange(t, protocol.resourceToken(t, "person-token-1"), presented))

	if claims.ExpiresAt != ceiling.Unix() {
		t.Fatalf("exp = %d, want the presented token's exp %d", claims.ExpiresAt, ceiling.Unix())
	}
}

// On step-up the agent presents the auth token this Access Server issued
// earlier, so the Access Server resolves its own published key to verify it.
func TestTokenEndpointVerifiesAuthTypedPresentedTokenOnStepUp(t *testing.T) {
	t.Parallel()
	protocol := newPresentedTokenProtocol(t)
	ceiling := protocol.now.Add(20 * time.Minute)
	presented := protocol.authToken(t, "auth-token-0", ceiling)

	claims := protocol.issuedAuthToken(t, protocol.exchange(t, protocol.resourceToken(t, "auth-token-0"), presented))

	if claims.JTI != "issued-auth-token" || claims.ExpiresAt != ceiling.Unix() {
		t.Fatalf("issued jti = %q exp = %d, want a new token capped at %d", claims.JTI, claims.ExpiresAt, ceiling.Unix())
	}
}

func TestTokenEndpointRefusesUnusablePresentedToken(t *testing.T) {
	t.Parallel()
	protocol := newPresentedTokenProtocol(t)
	live := protocol.now.Add(30 * time.Minute)
	agent := protocol.agentKey.PublicJWK()
	resourceToken := protocol.resourceToken(t, "person-token-1")
	otherAgent := accessServerTestKey(t, "presented-other-agent").PublicJWK()
	unknownKey := accessServerTestKey(t, "presented-unknown-person")

	for _, test := range []struct {
		name      string
		presented string
		status    int
		code      string
	}{
		{"missing", "", http.StatusBadRequest, "invalid_request"},
		{"not a token", "not-a-token", http.StatusBadRequest, "invalid_presented_token"},
		{"resource token", resourceToken, http.StatusBadRequest, "invalid_presented_token"},
		{
			"signature the resolver cannot verify",
			protocol.personToken(t, unknownKey, agent, "person-token-1", live),
			http.StatusBadRequest, "invalid_presented_token",
		},
		{
			"expired person token",
			protocol.personToken(t, protocol.personKey, agent, "person-token-1", protocol.now.Add(-time.Second)),
			http.StatusBadRequest, "expired_presented_token",
		},
		{
			"expired auth token",
			protocol.authToken(t, "person-token-1", protocol.now.Add(-time.Second)),
			http.StatusBadRequest, "expired_presented_token",
		},
		{
			"another jti",
			protocol.personToken(t, protocol.personKey, agent, "person-token-2", live),
			http.StatusBadRequest, "invalid_resource_token",
		},
		{
			"another agent key",
			protocol.personToken(t, protocol.personKey, otherAgent, "person-token-1", live),
			http.StatusBadRequest, "invalid_presented_token",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			assertAccessProblemStatus(t, protocol.exchange(t, resourceToken, test.presented), test.status, test.code)
		})
	}
}
