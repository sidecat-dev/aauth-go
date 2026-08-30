package personserver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	aauth "github.com/aauth-dev/auth-go"
	"github.com/aauth-dev/auth-go/jose"
	"github.com/aauth-dev/auth-go/signaturekey"
)

func TestNewPSAuthorizationRequiresOnlyThreePartyDependencies(t *testing.T) {
	t.Parallel()

	valid := PSAuthorizationConfig{
		Issuer: "https://person.example", SigningKey: personServerTestKey(t, "three-party-config"),
		KeyResolver: signaturekey.StaticKeyResolver{}, Clock: aauth.SystemClock{},
		NewID: func() string { return "token" }, Tokens: newMemoryTokenStore(),
		BindPerson: func(context.Context, PersonTokenRequest) (Person, error) { return Person{}, nil },
		Authorize: func(context.Context, AuthorizationRequest) (AuthorizationDecision, error) {
			return AuthorizationDecision{Scopes: []string{"records.read"}, Lifetime: time.Minute}, nil
		},
	}
	if _, err := NewPSAuthorization(valid); err != nil {
		t.Fatalf("complete three-party configuration: %v", err)
	}
	for _, test := range []struct {
		name   string
		change func(*PSAuthorizationConfig)
	}{
		{name: "issuer", change: func(config *PSAuthorizationConfig) { config.Issuer = "" }},
		{name: "signing key", change: func(config *PSAuthorizationConfig) { config.SigningKey = jose.SigningKey{} }},
		{name: "key resolver", change: func(config *PSAuthorizationConfig) { config.KeyResolver = nil }},
		{name: "clock", change: func(config *PSAuthorizationConfig) { config.Clock = nil }},
		{name: "id source", change: func(config *PSAuthorizationConfig) { config.NewID = nil }},
		{name: "token store", change: func(config *PSAuthorizationConfig) { config.Tokens = nil }},
		{name: "person binding", change: func(config *PSAuthorizationConfig) { config.BindPerson = nil }},
		{name: "authorization policy", change: func(config *PSAuthorizationConfig) { config.Authorize = nil }},
		{name: "interaction without deferred store", change: func(config *PSAuthorizationConfig) {
			config.RequirePersonTokenInteraction = func(context.Context, PersonTokenRequest) (PersonTokenInteractionPolicy, bool, error) {
				return PersonTokenInteractionPolicy{}, true, nil
			}
		}},
		{name: "negative retention bound", change: func(config *PSAuthorizationConfig) { config.MaximumResourceTokenLifetime = -1 }},
		{name: "revocation without issued-token store", change: func(config *PSAuthorizationConfig) {
			config.Revocation = &AuthTokenRevocationConfig{HTTPClient: http.DefaultClient, Admit: allowRevocationEgress}
		}},
		{name: "revocation without HTTP client", change: func(config *PSAuthorizationConfig) {
			config.Revocation = &AuthTokenRevocationConfig{IssuedTokens: newTestIssuedAuthTokenStore(), Admit: allowRevocationEgress}
		}},
		{name: "revocation without egress admission", change: func(config *PSAuthorizationConfig) {
			config.Revocation = &AuthTokenRevocationConfig{IssuedTokens: newTestIssuedAuthTokenStore(), HTTPClient: http.DefaultClient}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			config := valid
			test.change(&config)
			if _, err := NewPSAuthorization(config); err == nil {
				t.Fatal("incomplete three-party configuration was accepted")
			}
		})
	}
}

func TestServerIssuesThreePartyAuthTokenWithoutAccessServer(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 30, 20, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	providerKey := personServerTestKey(t, "three-party-provider")
	personKey := personServerTestKey(t, "three-party-person")
	resourceKey := personServerTestKey(t, "three-party-resource")
	agentKey := personServerTestKey(t, "three-party-agent")
	const (
		providerID = "https://provider.example"
		personID   = "https://person.example"
		resourceID = "https://resource.example"
		agentID    = "aauth:planner@provider.example"
	)
	resolver := signaturekey.StaticKeyResolver{
		{Issuer: providerID, DiscoveryDocument: aauth.AgentDiscoveryDocument, KeyID: providerKey.ID()}:    providerKey.PublicJWK(),
		{Issuer: personID, DiscoveryDocument: aauth.PersonDiscoveryDocument, KeyID: personKey.ID()}:       personKey.PublicJWK(),
		{Issuer: resourceID, DiscoveryDocument: aauth.ResourceDiscoveryDocument, KeyID: resourceKey.ID()}: resourceKey.PublicJWK(),
	}
	agentToken, err := aauth.MintAgentToken(providerID, providerKey, aauth.AgentTokenRequest{
		Agent: agentID, PersonServer: personID, PublicKey: agentKey.PublicJWK(),
		Lifetime: 30 * time.Minute,
		AdditionalClaims: map[string]json.RawMessage{
			"platform_attestation": json.RawMessage(`{"level":"example"}`),
		},
	}, now, "three-party-agent-token")
	if err != nil {
		t.Fatal(err)
	}
	agentJKT, err := agentKey.PublicJWK().Thumbprint()
	if err != nil {
		t.Fatal(err)
	}
	resourceToken := func(audience, jti, scope string) string {
		t.Helper()
		compact, err := aauth.MintResourceToken(resourceKey, aauth.ResourceTokenClaims{
			Issuer: resourceID, DWK: aauth.ResourceDiscoveryDocument, Audience: audience,
			JTI: jti, AgentJKT: agentJKT, IssuedAt: now.Unix(), ExpiresAt: now.Add(5 * time.Minute).Unix(),
			Scope: scope, PersonServer: personID, Subject: "person-123",
			PresentedJTI: "three-party-person-token", Tenant: "tenant-1",
		})
		if err != nil {
			t.Fatal(err)
		}
		return compact
	}
	store := newMemoryTokenStore()
	if err := store.Commit(context.Background(), directPersonTokenRecord(
		"three-party-person-token", personID, resourceID, "person-123", "tenant-1",
		providerID, "aauth:planner@provider.example", agentKey.PublicJWK(),
		now.Add(20*time.Minute), now.Add(25*time.Minute),
	)); err != nil {
		t.Fatal(err)
	}
	var consentRequests []AuthorizationRequest
	decision := AuthorizationDecision{Scopes: []string{"records.read"}, Lifetime: time.Hour}
	var authorizationErr error
	issuedAuthTokens := newTestIssuedAuthTokenStore()
	server, err := NewPSAuthorization(PSAuthorizationConfig{
		Issuer: personID, SigningKey: personKey, KeyResolver: resolver, Clock: clock,
		NewID: func() string { return "three-party-auth-token" }, Tokens: store,
		BindPerson: func(context.Context, PersonTokenRequest) (Person, error) { return Person{}, nil },
		Authorize: func(_ context.Context, request AuthorizationRequest) (AuthorizationDecision, error) {
			consentRequests = append(consentRequests, request)
			return decision, authorizationErr
		},
		Revocation: &AuthTokenRevocationConfig{
			IssuedTokens: issuedAuthTokens,
			Admit:        allowRevocationEgress,
			HTTPClient: &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
				return nil, errors.New("unexpected revocation request: " + request.URL.String())
			})},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	callTokenEndpoint := func(compact string) *httptest.ResponseRecorder {
		t.Helper()
		body, err := json.Marshal(struct {
			ResourceToken string `json:"resource_token"`
		}{ResourceToken: compact})
		if err != nil {
			t.Fatal(err)
		}
		request := httptest.NewRequest(http.MethodPost, personID+"/token", bytes.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		if err := signPersonServerTestRequest(request, agentKey, agentToken, clock); err != nil {
			t.Fatal(err)
		}
		response := httptest.NewRecorder()
		server.Handler().ServeHTTP(response, request)
		return response
	}
	response := callTokenEndpoint(resourceToken(personID, "three-party-resource-token", "records.read records.write"))
	if response.Code != http.StatusOK {
		t.Fatalf("direct exchange = %d %s", response.Code, response.Body.String())
	}
	if response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("Cache-Control = %q", response.Header().Get("Cache-Control"))
	}
	var output struct {
		AuthToken string `json:"auth_token"`
		ExpiresIn int64  `json:"expires_in"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &output); err != nil {
		t.Fatal(err)
	}
	claims, err := aauth.VerifyAuthToken(context.Background(), output.AuthToken, resolver, clock)
	if err != nil {
		t.Fatal(err)
	}
	if claims.Issuer != personID || claims.DWK != aauth.PersonDiscoveryDocument ||
		claims.Audience != resourceID || claims.JTI != "three-party-auth-token" ||
		claims.PersonServer != personID || claims.Subject != "person-123" ||
		!claims.Confirmation.JWK.Equal(agentKey.PublicJWK()) || claims.Scope != "records.read" ||
		claims.Tenant != "tenant-1" || claims.IssuedAt != now.Unix() ||
		claims.ExpiresAt != now.Add(30*time.Minute).Unix() || output.ExpiresIn != int64((30*time.Minute)/time.Second) {
		t.Fatalf("three-party auth token = %#v; expires_in=%d", claims, output.ExpiresIn)
	}
	issued, err := issuedAuthTokens.LoadIssuedAuthToken(context.Background(), aauth.TokenReference{Issuer: personID, JTI: claims.JTI})
	if err != nil || issued.Reference != (aauth.TokenReference{Issuer: personID, JTI: claims.JTI}) ||
		issued.Resource != resourceID ||
		issued.CompactSHA256 != sha256.Sum256([]byte(output.AuthToken)) ||
		issued.IssuedAt != time.Unix(claims.IssuedAt, 0).UTC() || issued.ExpiresAt != time.Unix(claims.ExpiresAt, 0).UTC() {
		t.Fatalf("issued auth-token record = %#v, %v", issued, err)
	}
	wantConsent := AuthorizationRequest{
		Agent: agentID, Resource: resourceID, Subject: "person-123", Tenant: "tenant-1",
		Scopes: []string{"records.read", "records.write"},
		AgentAdditionalClaims: map[string]json.RawMessage{
			"platform_attestation": json.RawMessage(`{"level":"example"}`),
		},
	}
	if !reflect.DeepEqual(consentRequests, []AuthorizationRequest{wantConsent}) {
		t.Fatalf("consent requests = %#v", consentRequests)
	}
	issuedAuthTokens.commitError = errors.New("issued auth-token retention unavailable")
	retentionFailure := callTokenEndpoint(resourceToken(personID, "retention-failure-resource-token", "records.read"))
	if retentionFailure.Code != http.StatusInternalServerError || bytes.Contains(retentionFailure.Body.Bytes(), []byte(`"auth_token"`)) {
		t.Fatalf("retention failure = %d %s", retentionFailure.Code, retentionFailure.Body.String())
	}
	issuedAuthTokens.commitError = nil

	wrongTopology := callTokenEndpoint(resourceToken("https://access.example", "federated-resource-token", "records.read"))
	if wrongTopology.Code == http.StatusOK || len(consentRequests) != 2 {
		t.Fatalf("federated token = %d %s; consent=%d", wrongTopology.Code, wrongTopology.Body.String(), len(consentRequests))
	}

	for _, test := range []struct {
		name     string
		decision AuthorizationDecision
		policy   error
		status   int
	}{
		{name: "empty scope", decision: AuthorizationDecision{Lifetime: time.Minute}, status: http.StatusInternalServerError},
		{name: "duplicate scope", decision: AuthorizationDecision{Scopes: []string{"records.read", "records.read"}, Lifetime: time.Minute}, status: http.StatusInternalServerError},
		{name: "broader scope", decision: AuthorizationDecision{Scopes: []string{"records.write"}, Lifetime: time.Minute}, status: http.StatusInternalServerError},
		{name: "zero lifetime", decision: AuthorizationDecision{Scopes: []string{"records.read"}}, status: http.StatusInternalServerError},
		{name: "excess lifetime", decision: AuthorizationDecision{Scopes: []string{"records.read"}, Lifetime: time.Hour + time.Second}, status: http.StatusInternalServerError},
		{name: "policy denial", policy: errors.New("person refused"), status: http.StatusForbidden},
	} {
		t.Run(test.name, func(t *testing.T) {
			decision = test.decision
			authorizationErr = test.policy
			response := callTokenEndpoint(resourceToken(personID, "invalid-decision-resource-token", "records.read"))
			if response.Code != test.status {
				t.Fatalf("status = %d, want %d; body=%s", response.Code, test.status, response.Body.String())
			}
			var output map[string]json.RawMessage
			if err := json.Unmarshal(response.Body.Bytes(), &output); err != nil {
				t.Fatal(err)
			}
			if output["auth_token"] != nil {
				t.Fatalf("failure released auth token: %s", response.Body.String())
			}
		})
	}
}

func TestFederatedServerUsesAccessRoleWhenAudienceEqualsIssuer(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 30, 20, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	providerKey := personServerTestKey(t, "collapsed-provider")
	personKey := personServerTestKey(t, "collapsed-person")
	accessKey := personServerTestKey(t, "collapsed-access")
	resourceKey := personServerTestKey(t, "collapsed-resource")
	agentKey := personServerTestKey(t, "collapsed-agent")
	const (
		providerID = "https://provider.example"
		personID   = "https://person.example"
		resourceID = "https://resource.example"
		agentID    = "aauth:planner@provider.example"
	)
	resolver := signaturekey.StaticKeyResolver{
		{Issuer: providerID, DiscoveryDocument: aauth.AgentDiscoveryDocument, KeyID: providerKey.ID()}:    providerKey.PublicJWK(),
		{Issuer: personID, DiscoveryDocument: aauth.PersonDiscoveryDocument, KeyID: personKey.ID()}:       personKey.PublicJWK(),
		{Issuer: personID, DiscoveryDocument: aauth.AccessDiscoveryDocument, KeyID: accessKey.ID()}:       accessKey.PublicJWK(),
		{Issuer: resourceID, DiscoveryDocument: aauth.ResourceDiscoveryDocument, KeyID: resourceKey.ID()}: resourceKey.PublicJWK(),
	}
	agentToken, err := aauth.MintAgentToken(providerID, providerKey, aauth.AgentTokenRequest{
		Agent: agentID, PersonServer: personID, PublicKey: agentKey.PublicJWK(), Lifetime: time.Hour,
	}, now, "collapsed-agent-token")
	if err != nil {
		t.Fatal(err)
	}
	agentJKT, _ := agentKey.PublicJWK().Thumbprint()
	resourceToken, err := aauth.MintResourceToken(resourceKey, aauth.ResourceTokenClaims{
		Issuer: resourceID, DWK: aauth.ResourceDiscoveryDocument, Audience: personID,
		JTI: "collapsed-resource-token", AgentJKT: agentJKT,
		IssuedAt: now.Unix(), ExpiresAt: now.Add(5 * time.Minute).Unix(), Scope: "records.read",
		PersonServer: personID, Subject: "person-123", PresentedJTI: "collapsed-person-token",
	})
	if err != nil {
		t.Fatal(err)
	}
	store := newMemoryTokenStore()
	if err := store.Commit(context.Background(), directPersonTokenRecord(
		"collapsed-person-token", personID, resourceID, "person-123", "",
		providerID, agentID, agentKey.PublicJWK(), now.Add(20*time.Minute), now.Add(25*time.Minute),
	)); err != nil {
		t.Fatal(err)
	}
	authToken, err := aauth.MintAuthToken(accessKey, aauth.AuthTokenClaims{
		Issuer: personID, DWK: aauth.AccessDiscoveryDocument, Audience: resourceID,
		JTI: "collapsed-auth-token", PersonServer: personID, Subject: "person-123",
		Confirmation: aauth.Confirmation{JWK: agentKey.PublicJWK()},
		IssuedAt:     now.Unix(), ExpiresAt: now.Add(30 * time.Minute).Unix(), Scope: "records.read",
	})
	if err != nil {
		t.Fatal(err)
	}
	accessCalls := 0
	httpClient := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		accessCalls++
		body, _ := json.Marshal(map[string]any{"auth_token": authToken, "expires_in": 1800})
		return &http.Response{
			StatusCode: http.StatusOK, Status: "200 OK", Request: request,
			Header: http.Header{"Content-Type": []string{"application/json"}},
			Body:   io.NopCloser(bytes.NewReader(body)),
		}, nil
	})}
	server, err := NewFederatedAuthorization(FederatedAuthorizationConfig{
		Issuer: personID, SigningKey: personKey, KeyResolver: resolver, Clock: clock,
		NewID: func() string { return "unused" }, HTTPClient: httpClient, Tokens: store,
		AccessServerEndpoint: func(context.Context, string) (string, error) {
			return personID + "/access/token", nil
		},
		BindPerson: func(context.Context, PersonTokenRequest) (Person, error) { return Person{}, nil },
		Consent:    func(context.Context, AuthorizationRequest) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]string{"resource_token": resourceToken})
	request := httptest.NewRequest(http.MethodPost, personID+"/token", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	if err := signPersonServerTestRequest(request, agentKey, agentToken, clock); err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusOK || accessCalls != 1 {
		t.Fatalf("collapsed federation = %d %s; access=%d", response.Code, response.Body.String(), accessCalls)
	}
}
