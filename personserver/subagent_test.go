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
	"strings"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

type subagentPersonServerProtocol struct {
	now                           time.Time
	clock                         aauth.Clock
	providerKey                   jose.SigningKey
	personKey                     jose.SigningKey
	resourceKey                   jose.SigningKey
	accessKey                     jose.SigningKey
	parentKey                     jose.SigningKey
	childKey                      jose.SigningKey
	resolver                      signaturekey.StaticKeyResolver
	parentToken                   string
	childToken                    string
	parentAdditionalClaims        map[string]json.RawMessage
	childAdditionalClaims         map[string]json.RawMessage
	store                         *memoryTokenStore
	bindCalls                     int
	authorizationCalls            int
	requirePersonInteractionCalls int
	requireAuthInteractionCalls   int
}

func newSubagentPersonServerProtocol(t *testing.T) *subagentPersonServerProtocol {
	t.Helper()
	p := &subagentPersonServerProtocol{
		now:         time.Date(2026, 8, 30, 22, 0, 0, 0, time.UTC),
		providerKey: personServerTestKey(t, "subagent-provider"),
		personKey:   personServerTestKey(t, "subagent-person"),
		resourceKey: personServerTestKey(t, "subagent-resource"),
		accessKey:   personServerTestKey(t, "subagent-access"),
		parentKey:   personServerTestKey(t, "subagent-parent"),
		childKey:    personServerTestKey(t, "subagent-child"),
		parentAdditionalClaims: map[string]json.RawMessage{
			"platform": json.RawMessage(`"orchestrator"`),
		},
		childAdditionalClaims: map[string]json.RawMessage{
			"workload": json.RawMessage(`"search-worker"`),
		},
		store: newMemoryTokenStore(),
	}
	p.clock = aauth.ClockFunc(func() time.Time { return p.now })
	p.resolver = signaturekey.StaticKeyResolver{
		{Issuer: "https://ap.example", DiscoveryDocument: aauth.AgentDiscoveryDocument, KeyID: p.providerKey.ID()}:          p.providerKey.PublicJWK(),
		{Issuer: "https://ps.example", DiscoveryDocument: aauth.PersonDiscoveryDocument, KeyID: p.personKey.ID()}:           p.personKey.PublicJWK(),
		{Issuer: "https://resource.example", DiscoveryDocument: aauth.ResourceDiscoveryDocument, KeyID: p.resourceKey.ID()}: p.resourceKey.PublicJWK(),
		{Issuer: "https://as.example", DiscoveryDocument: aauth.AccessDiscoveryDocument, KeyID: p.accessKey.ID()}:           p.accessKey.PublicJWK(),
	}
	p.parentToken = p.mintAgentToken(t, "aauth:planner@ap.example", "", p.parentKey.PublicJWK(), 40*time.Minute, "parent-token", p.parentAdditionalClaims)
	p.childToken = p.mintAgentToken(t, "aauth:planner+search@ap.example", "aauth:planner@ap.example", p.childKey.PublicJWK(), 10*time.Minute, "child-token", p.childAdditionalClaims)
	return p
}

func (p *subagentPersonServerProtocol) mintAgentToken(
	t *testing.T,
	agent string,
	parent string,
	key jose.JWK,
	lifetime time.Duration,
	jti string,
	additional map[string]json.RawMessage,
) string {
	t.Helper()
	compact, err := aauth.MintAgentToken("https://ap.example", p.providerKey, aauth.AgentTokenRequest{
		Agent: agent, PersonServer: "https://ps.example", ParentAgent: parent,
		PublicKey: key, Lifetime: lifetime, AdditionalClaims: additional,
	}, p.now, jti)
	if err != nil {
		t.Fatal(err)
	}
	return compact
}

func (p *subagentPersonServerProtocol) personRequest(t *testing.T, server *Server, childToken string) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"resource":       "https://resource.example",
		"subagent_token": childToken,
	})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "https://ps.example/person", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	if err := signPersonServerTestRequest(request, p.parentKey, p.parentToken, p.clock); err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	return response
}

func (p *subagentPersonServerProtocol) tokenRequest(
	t *testing.T,
	server *Server,
	parentKey jose.SigningKey,
	parentToken, childToken, resourceToken string,
) *httptest.ResponseRecorder {
	return p.tokenRequestWithCapabilities(t, server, parentKey, parentToken, childToken, resourceToken, nil)
}

func (p *subagentPersonServerProtocol) tokenRequestWithCapabilities(
	t *testing.T,
	server *Server,
	parentKey jose.SigningKey,
	parentToken, childToken, resourceToken string,
	capabilities []string,
) *httptest.ResponseRecorder {
	t.Helper()
	requestBody := map[string]any{
		"resource_token": resourceToken,
		"subagent_token": childToken,
	}
	if len(capabilities) > 0 {
		requestBody["capabilities"] = capabilities
	}
	body, err := json.Marshal(requestBody)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "https://ps.example/token", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	if err := signPersonServerTestRequest(request, parentKey, parentToken, p.clock); err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	return response
}

func (p *subagentPersonServerProtocol) resourceToken(t *testing.T, audience, presentedJTI string, key jose.JWK) string {
	t.Helper()
	jkt, err := key.Thumbprint()
	if err != nil {
		t.Fatal(err)
	}
	compact, err := aauth.MintResourceToken(p.resourceKey, aauth.ResourceTokenClaims{
		Issuer: "https://resource.example", DWK: aauth.ResourceDiscoveryDocument,
		Audience: audience, JTI: "subagent-resource-token", AgentJKT: jkt,
		IssuedAt: p.now.Unix(), ExpiresAt: p.now.Add(5 * time.Minute).Unix(), Scope: "records.read",
		PersonServer: "https://ps.example", Subject: "person-123", PresentedJTI: presentedJTI,
		Tenant: "tenant-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	return compact
}

func (p *subagentPersonServerProtocol) policyPerson(_ context.Context, request PersonTokenRequest) (Person, error) {
	p.bindCalls++
	if request.Agent != "aauth:planner@ap.example" || request.Subagent != "aauth:planner+search@ap.example" || request.Resource != "https://resource.example" {
		return Person{}, errors.New("unexpected parent, sub-agent, or resource")
	}
	if !reflect.DeepEqual(request.AgentAdditionalClaims, p.parentAdditionalClaims) ||
		!reflect.DeepEqual(request.SubagentAdditionalClaims, p.childAdditionalClaims) {
		return Person{}, errors.New("unexpected parent or sub-agent claims")
	}
	return Person{Subject: "person-123", Tenant: "tenant-1", Lifetime: 30 * time.Minute}, nil
}

func (p *subagentPersonServerProtocol) policyAuthorization(_ context.Context, request AuthorizationRequest) (AuthorizationDecision, error) {
	p.authorizationCalls++
	if request.Agent != "aauth:planner@ap.example" || request.Subagent != "aauth:planner+search@ap.example" ||
		request.Resource != "https://resource.example" || request.Subject != "person-123" || request.Tenant != "tenant-1" ||
		!reflect.DeepEqual(request.Scopes, []string{"records.read"}) {
		return AuthorizationDecision{}, errors.New("unexpected authorization context")
	}
	if !reflect.DeepEqual(request.AgentAdditionalClaims, p.parentAdditionalClaims) ||
		!reflect.DeepEqual(request.SubagentAdditionalClaims, p.childAdditionalClaims) {
		return AuthorizationDecision{}, errors.New("unexpected parent or sub-agent claims")
	}
	return AuthorizationDecision{Scopes: []string{"records.read"}, Lifetime: 30 * time.Minute}, nil
}

func TestServerIssuesImmediatePersonAndAuthTokensForSubagent(t *testing.T) {
	t.Parallel()

	p := newSubagentPersonServerProtocol(t)
	ids := []string{"subagent-person-token", "subagent-auth-token"}
	server, err := NewPSAuthorization(PSAuthorizationConfig{
		Issuer: "https://ps.example", SigningKey: p.personKey, KeyResolver: p.resolver,
		Clock: p.clock, Tokens: p.store,
		NewID: func() string {
			id := ids[0]
			ids = ids[1:]
			return id
		},
		BindPerson: p.policyPerson,
		Authorize:  p.policyAuthorization,
	})
	if err != nil {
		t.Fatal(err)
	}

	personResponse := p.personRequest(t, server, p.childToken)
	if personResponse.Code != http.StatusOK {
		t.Fatalf("person-token response = %d %s", personResponse.Code, personResponse.Body.String())
	}
	var personOutput struct {
		PersonToken string `json:"person_token"`
		ExpiresIn   int64  `json:"expires_in"`
	}
	if err := json.Unmarshal(personResponse.Body.Bytes(), &personOutput); err != nil {
		t.Fatal(err)
	}
	personClaims, err := aauth.VerifyPersonToken(context.Background(), personOutput.PersonToken, p.resolver, p.clock)
	if err != nil {
		t.Fatal(err)
	}
	if !personClaims.Confirmation.JWK.Equal(p.childKey.PublicJWK()) || personClaims.ExpiresAt != p.now.Add(10*time.Minute).Unix() ||
		personOutput.ExpiresIn != int64((10*time.Minute)/time.Second) {
		t.Fatalf("delegated person token = %#v; expires_in=%d", personClaims, personOutput.ExpiresIn)
	}
	record, commits, _ := p.store.observation()
	if commits != 1 || record.AgentProvider != "https://ap.example" || record.Agent != "aauth:planner+search@ap.example" ||
		record.ParentAgent != "aauth:planner@ap.example" || !record.Confirmation.Equal(p.childKey.PublicJWK()) {
		t.Fatalf("retained delegated person token = %#v; commits=%d", record, commits)
	}

	resourceToken := p.resourceToken(t, "https://ps.example", personClaims.JTI, p.childKey.PublicJWK())
	authResponse := p.tokenRequest(t, server, p.parentKey, p.parentToken, p.childToken, resourceToken)
	if authResponse.Code != http.StatusOK {
		t.Fatalf("auth-token response = %d %s", authResponse.Code, authResponse.Body.String())
	}
	var authOutput struct {
		AuthToken string `json:"auth_token"`
		ExpiresIn int64  `json:"expires_in"`
	}
	if err := json.Unmarshal(authResponse.Body.Bytes(), &authOutput); err != nil {
		t.Fatal(err)
	}
	authClaims, err := aauth.VerifyAuthToken(context.Background(), authOutput.AuthToken, p.resolver, p.clock)
	if err != nil {
		t.Fatal(err)
	}
	if !authClaims.Confirmation.JWK.Equal(p.childKey.PublicJWK()) || authClaims.ExpiresAt != p.now.Add(10*time.Minute).Unix() ||
		authOutput.ExpiresIn != int64((10*time.Minute)/time.Second) {
		t.Fatalf("delegated auth token = %#v; expires_in=%d", authClaims, authOutput.ExpiresIn)
	}
	if p.bindCalls != 1 || p.authorizationCalls != 1 {
		t.Fatalf("policy calls = bind %d authorize %d, want 1/1", p.bindCalls, p.authorizationCalls)
	}
}

func TestServerCapsSubagentPersonAndAuthTokensAtParentExpiry(t *testing.T) {
	t.Parallel()

	p := newSubagentPersonServerProtocol(t)
	p.parentToken = p.mintAgentToken(
		t,
		"aauth:planner@ap.example",
		"",
		p.parentKey.PublicJWK(),
		5*time.Minute,
		"short-parent-token",
		p.parentAdditionalClaims,
	)
	ids := []string{"parent-capped-person-token", "parent-capped-auth-token"}
	server, err := NewPSAuthorization(PSAuthorizationConfig{
		Issuer: "https://ps.example", SigningKey: p.personKey, KeyResolver: p.resolver,
		Clock: p.clock, Tokens: p.store,
		NewID: func() string {
			id := ids[0]
			ids = ids[1:]
			return id
		},
		BindPerson: p.policyPerson,
		Authorize:  p.policyAuthorization,
	})
	if err != nil {
		t.Fatal(err)
	}

	personResponse := p.personRequest(t, server, p.childToken)
	if personResponse.Code != http.StatusOK {
		t.Fatalf("person-token response = %d %s", personResponse.Code, personResponse.Body.String())
	}
	var personOutput struct {
		PersonToken string `json:"person_token"`
		ExpiresIn   int64  `json:"expires_in"`
	}
	if err := json.Unmarshal(personResponse.Body.Bytes(), &personOutput); err != nil {
		t.Fatal(err)
	}
	personClaims, err := aauth.VerifyPersonToken(context.Background(), personOutput.PersonToken, p.resolver, p.clock)
	if err != nil {
		t.Fatal(err)
	}
	if personClaims.ExpiresAt != p.now.Add(5*time.Minute).Unix() || personOutput.ExpiresIn != 300 {
		t.Fatalf("parent-capped person token = %#v; expires_in=%d", personClaims, personOutput.ExpiresIn)
	}

	resourceToken := p.resourceToken(t, "https://ps.example", personClaims.JTI, p.childKey.PublicJWK())
	authResponse := p.tokenRequest(t, server, p.parentKey, p.parentToken, p.childToken, resourceToken)
	if authResponse.Code != http.StatusOK {
		t.Fatalf("auth-token response = %d %s", authResponse.Code, authResponse.Body.String())
	}
	var authOutput struct {
		AuthToken string `json:"auth_token"`
		ExpiresIn int64  `json:"expires_in"`
	}
	if err := json.Unmarshal(authResponse.Body.Bytes(), &authOutput); err != nil {
		t.Fatal(err)
	}
	authClaims, err := aauth.VerifyAuthToken(context.Background(), authOutput.AuthToken, p.resolver, p.clock)
	if err != nil {
		t.Fatal(err)
	}
	if authClaims.ExpiresAt != p.now.Add(5*time.Minute).Unix() || authOutput.ExpiresIn != 300 {
		t.Fatalf("parent-capped auth token = %#v; expires_in=%d", authClaims, authOutput.ExpiresIn)
	}
}

func TestServerAcceptsCurrentChildTokenForRetainedRelationship(t *testing.T) {
	t.Parallel()

	p := newSubagentPersonServerProtocol(t)
	ids := []string{"relationship-person-token", "relationship-auth-token"}
	server, err := NewPSAuthorization(PSAuthorizationConfig{
		Issuer: "https://ps.example", SigningKey: p.personKey, KeyResolver: p.resolver,
		Clock: p.clock, Tokens: p.store,
		NewID: func() string {
			id := ids[0]
			ids = ids[1:]
			return id
		},
		BindPerson: p.policyPerson,
		Authorize:  p.policyAuthorization,
	})
	if err != nil {
		t.Fatal(err)
	}

	personResponse := p.personRequest(t, server, p.childToken)
	if personResponse.Code != http.StatusOK {
		t.Fatalf("person-token response = %d %s", personResponse.Code, personResponse.Body.String())
	}
	var personOutput struct {
		PersonToken string `json:"person_token"`
	}
	if err := json.Unmarshal(personResponse.Body.Bytes(), &personOutput); err != nil {
		t.Fatal(err)
	}
	personClaims, err := aauth.VerifyPersonToken(context.Background(), personOutput.PersonToken, p.resolver, p.clock)
	if err != nil {
		t.Fatal(err)
	}

	currentClaims := map[string]json.RawMessage{"workload": json.RawMessage(`"current-worker"`)}
	currentChildToken := p.mintAgentToken(
		t,
		"aauth:planner+search@ap.example",
		"aauth:planner@ap.example",
		p.childKey.PublicJWK(),
		8*time.Minute,
		"current-child-token",
		currentClaims,
	)
	p.childAdditionalClaims = currentClaims
	resourceToken := p.resourceToken(t, "https://ps.example", personClaims.JTI, p.childKey.PublicJWK())
	authResponse := p.tokenRequest(t, server, p.parentKey, p.parentToken, currentChildToken, resourceToken)
	if authResponse.Code != http.StatusOK {
		t.Fatalf("auth-token response = %d %s", authResponse.Code, authResponse.Body.String())
	}
	if p.authorizationCalls != 1 {
		t.Fatalf("authorization policy calls = %d, want 1", p.authorizationCalls)
	}
	record, commits, loads := p.store.observation()
	if commits != 1 || loads != 1 || record.Agent != "aauth:planner+search@ap.example" ||
		record.ParentAgent != "aauth:planner@ap.example" || !record.Confirmation.Equal(p.childKey.PublicJWK()) {
		t.Fatalf("retained relationship = %#v; commits=%d loads=%d", record, commits, loads)
	}
}

func TestServerRejectsInvalidSubagentBeforePersonPolicyOrRetention(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name  string
		child func(*testing.T, *subagentPersonServerProtocol) string
	}{
		{name: "wrong parent", child: func(t *testing.T, p *subagentPersonServerProtocol) string {
			return p.mintAgentToken(t, "aauth:other+search@ap.example", "aauth:other@ap.example", p.childKey.PublicJWK(), time.Hour, "wrong-parent", nil)
		}},
		{name: "top-level token", child: func(t *testing.T, p *subagentPersonServerProtocol) string {
			return p.mintAgentToken(t, "aauth:other@ap.example", "", p.childKey.PublicJWK(), time.Hour, "not-a-child", nil)
		}},
		{name: "parent and child share one key", child: func(t *testing.T, p *subagentPersonServerProtocol) string {
			return p.mintAgentToken(t, "aauth:planner+search@ap.example", "aauth:planner@ap.example", p.parentKey.PublicJWK(), time.Hour, "shared-key", nil)
		}},
		{name: "expired token", child: func(t *testing.T, p *subagentPersonServerProtocol) string {
			compact, err := aauth.MintAgentToken("https://ap.example", p.providerKey, aauth.AgentTokenRequest{
				Agent: "aauth:planner+search@ap.example", ParentAgent: "aauth:planner@ap.example",
				PersonServer: "https://ps.example", PublicKey: p.childKey.PublicJWK(), Lifetime: time.Minute,
			}, p.now.Add(-2*time.Minute), "expired-child")
			if err != nil {
				t.Fatal(err)
			}
			return compact
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			p := newSubagentPersonServerProtocol(t)
			server, err := NewPSAuthorization(PSAuthorizationConfig{
				Issuer: "https://ps.example", SigningKey: p.personKey, KeyResolver: p.resolver,
				Clock: p.clock, NewID: func() string { return "unused" }, Tokens: p.store,
				BindPerson: p.policyPerson,
				Authorize:  p.policyAuthorization,
			})
			if err != nil {
				t.Fatal(err)
			}
			response := p.personRequest(t, server, test.child(t, p))
			if response.Code != http.StatusBadRequest || p.bindCalls != 0 {
				t.Fatalf("response=%d %s; bind=%d", response.Code, response.Body.String(), p.bindCalls)
			}
			_, commits, loads := p.store.observation()
			if commits != 0 || loads != 0 {
				t.Fatalf("invalid sub-agent reached store: commits=%d loads=%d", commits, loads)
			}
		})
	}
}

func TestServerRefusesFutureSubagentTokenAsParameterClockSkew(t *testing.T) {
	t.Parallel()

	p := newSubagentPersonServerProtocol(t)
	server, err := NewPSAuthorization(PSAuthorizationConfig{
		Issuer: "https://ps.example", SigningKey: p.personKey, KeyResolver: p.resolver,
		Clock: p.clock, NewID: func() string { return "unused" }, Tokens: p.store,
		BindPerson: p.policyPerson,
		Authorize:  p.policyAuthorization,
	})
	if err != nil {
		t.Fatal(err)
	}
	futureChild, err := aauth.MintAgentToken("https://ap.example", p.providerKey, aauth.AgentTokenRequest{
		Agent: "aauth:planner+search@ap.example", ParentAgent: "aauth:planner@ap.example",
		PersonServer: "https://ps.example", PublicKey: p.childKey.PublicJWK(), Lifetime: 10 * time.Minute,
	}, p.now.Add(90*time.Second), "future-child")
	if err != nil {
		t.Fatal(err)
	}
	response := p.personRequest(t, server, futureChild)
	if got := response.Header().Get("Signature-Error"); got != "" {
		t.Fatalf("parameter token skew Signature-Error = %q", got)
	}
	assertSubagentProblem(t, response, http.StatusBadRequest, "clock_skew")
	_, commits, loads := p.store.observation()
	if p.bindCalls != 0 || commits != 0 || loads != 0 {
		t.Fatalf("future sub-agent token reached policy or store: bind=%d commits=%d loads=%d", p.bindCalls, commits, loads)
	}
}

func TestServerVerifiesDirectSubagentProofBeforeTopologyRefusal(t *testing.T) {
	t.Parallel()

	p := newSubagentPersonServerProtocol(t)
	server, err := NewPSAuthorization(PSAuthorizationConfig{
		Issuer: "https://ps.example", SigningKey: p.personKey, KeyResolver: p.resolver,
		Clock: p.clock, NewID: func() string { return "unused" }, Tokens: p.store,
		BindPerson: p.policyPerson, Authorize: p.policyAuthorization,
	})
	if err != nil {
		t.Fatal(err)
	}
	request := func(signingKey jose.SigningKey) *httptest.ResponseRecorder {
		body := strings.NewReader(`{"resource":"https://resource.example"}`)
		req := httptest.NewRequest(http.MethodPost, "https://ps.example/person", body)
		req.Header.Set("Content-Type", "application/json")
		if err := signPersonServerTestRequest(req, signingKey, p.childToken, p.clock); err != nil {
			t.Fatal(err)
		}
		response := httptest.NewRecorder()
		server.Handler().ServeHTTP(response, req)
		return response
	}

	forged := request(p.parentKey)
	if forged.Code != http.StatusUnauthorized || forged.Header().Get("Signature-Error") == "" {
		t.Fatalf("forged child proof = %d headers=%v body=%s", forged.Code, forged.Header(), forged.Body.String())
	}
	signatureFailure, err := signaturekey.ParseError(forged.Header().Get("Signature-Error"))
	if err != nil || signatureFailure.Code != signaturekey.ErrorInvalidSignature {
		t.Fatalf("forged child Signature-Error = %#v, error=%v", signatureFailure, err)
	}
	var forgedProblem struct {
		Code string `json:"error"`
	}
	if err := json.Unmarshal(forged.Body.Bytes(), &forgedProblem); err != nil || forgedProblem.Code != "invalid_agent_token" {
		t.Fatalf("forged child problem = %#v, error=%v", forgedProblem, err)
	}

	signed := request(p.childKey)
	if signed.Code != http.StatusBadRequest || signed.Header().Get("Signature-Error") != "" {
		t.Fatalf("signed child refusal = %d headers=%v body=%s", signed.Code, signed.Header(), signed.Body.String())
	}
	var signedProblem struct {
		Code string `json:"error"`
	}
	if err := json.Unmarshal(signed.Body.Bytes(), &signedProblem); err != nil || signedProblem.Code != "invalid_agent_token" {
		t.Fatalf("signed child problem = %#v, error=%v", signedProblem, err)
	}
	if p.bindCalls != 0 || p.authorizationCalls != 0 {
		t.Fatalf("direct child reached policy: bind=%d authorization=%d", p.bindCalls, p.authorizationCalls)
	}
	_, commits, loads := p.store.observation()
	if commits != 0 || loads != 0 {
		t.Fatalf("direct child reached store: commits=%d loads=%d", commits, loads)
	}
}

func TestServerRetainsParentPollAndChildCredentialForDelegatedInteraction(t *testing.T) {
	t.Parallel()

	p := newSubagentPersonServerProtocol(t)
	store := newMemoryDeferredTokenStore()
	server, err := NewPSAuthorization(PSAuthorizationConfig{
		Issuer: "https://ps.example", SigningKey: p.personKey, KeyResolver: p.resolver,
		Clock: p.clock, NewID: func() string { return "unused" }, Tokens: store,
		BindPerson: p.policyPerson,
		RequirePersonTokenInteraction: func(context.Context, PersonTokenRequest) (PersonTokenInteractionPolicy, bool, error) {
			return PersonTokenInteractionPolicy{URL: "https://ps.example/interact", Lifetime: time.Minute, RetryAfter: time.Second}, true, nil
		},
		Authorize: p.policyAuthorization,
	})
	if err != nil {
		t.Fatal(err)
	}
	response := p.personRequest(t, server, p.childToken)
	if response.Code != http.StatusAccepted {
		t.Fatalf("delegated person interaction = %d %s", response.Code, response.Body.String())
	}
	pending := store.onlyPending(t)
	if pending.RequestingAgent != "aauth:planner@ap.example" || pending.Agent != "aauth:planner+search@ap.example" ||
		pending.ParentAgent != "aauth:planner@ap.example" ||
		!pending.RequestingConfirmation.Equal(p.parentKey.PublicJWK()) ||
		!pending.Confirmation.Equal(p.childKey.PublicJWK()) || p.bindCalls != 0 {
		t.Fatalf("delegated pending record = %#v, bind=%d", pending, p.bindCalls)
	}
}

func TestServerMatchesSubagentAndRetainedCredentialBeforeAuthorizationPolicy(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name            string
		childToken      func(*testing.T, *subagentPersonServerProtocol) string
		resourceKey     func(*subagentPersonServerProtocol) jose.JWK
		recordChange    func(*subagentPersonServerProtocol, *PersonTokenRecord)
		wantLoads       int
		useNestedParent bool
	}{
		{
			name: "same key different child",
			childToken: func(t *testing.T, p *subagentPersonServerProtocol) string {
				return p.mintAgentToken(t, "aauth:planner+other@ap.example", "aauth:planner@ap.example", p.childKey.PublicJWK(), time.Hour, "other-child", nil)
			},
			resourceKey: func(p *subagentPersonServerProtocol) jose.JWK { return p.childKey.PublicJWK() },
			wantLoads:   1,
		},
		{
			name: "wrong parent",
			childToken: func(t *testing.T, p *subagentPersonServerProtocol) string {
				return p.mintAgentToken(t, "aauth:other+search@ap.example", "aauth:other@ap.example", p.childKey.PublicJWK(), time.Hour, "wrong-parent", nil)
			},
			resourceKey: func(p *subagentPersonServerProtocol) jose.JWK { return p.childKey.PublicJWK() },
		},
		{
			name:            "nested requesting agent",
			childToken:      func(_ *testing.T, p *subagentPersonServerProtocol) string { return p.childToken },
			resourceKey:     func(p *subagentPersonServerProtocol) jose.JWK { return p.childKey.PublicJWK() },
			useNestedParent: true,
		},
		{
			name:        "resource bound to parent key",
			childToken:  func(_ *testing.T, p *subagentPersonServerProtocol) string { return p.childToken },
			resourceKey: func(p *subagentPersonServerProtocol) jose.JWK { return p.parentKey.PublicJWK() },
		},
		{
			name:        "retained child key differs",
			childToken:  func(_ *testing.T, p *subagentPersonServerProtocol) string { return p.childToken },
			resourceKey: func(p *subagentPersonServerProtocol) jose.JWK { return p.childKey.PublicJWK() },
			recordChange: func(p *subagentPersonServerProtocol, record *PersonTokenRecord) {
				record.Confirmation = p.resourceKey.PublicJWK()
			},
			wantLoads: 1,
		},
		{
			name:        "retained Agent Provider differs",
			childToken:  func(_ *testing.T, p *subagentPersonServerProtocol) string { return p.childToken },
			resourceKey: func(p *subagentPersonServerProtocol) jose.JWK { return p.childKey.PublicJWK() },
			recordChange: func(_ *subagentPersonServerProtocol, record *PersonTokenRecord) {
				record.AgentProvider = "https://other-ap.example"
			},
			wantLoads: 1,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			p := newSubagentPersonServerProtocol(t)
			record := PersonTokenRecord{
				JTI: "person-token", PersonServer: "https://ps.example", Resource: "https://resource.example",
				Subject: "person-123", Tenant: "tenant-1", ExpiresAt: p.now.Add(10 * time.Minute),
				RetainUntil: p.now.Add(15 * time.Minute), AgentProvider: "https://ap.example",
				Agent: "aauth:planner+search@ap.example", ParentAgent: "aauth:planner@ap.example",
				Confirmation: p.childKey.PublicJWK(),
			}
			if test.recordChange != nil {
				test.recordChange(p, &record)
			}
			if err := p.store.Commit(context.Background(), record); err != nil {
				t.Fatal(err)
			}
			p.store.mu.Lock()
			p.store.commits = 0
			p.store.mu.Unlock()
			downstreamCalls := 0
			server, err := NewFederatedAuthorization(FederatedAuthorizationConfig{
				Issuer: "https://ps.example", SigningKey: p.personKey, KeyResolver: p.resolver,
				Clock: p.clock, NewID: func() string { return "unused" }, Tokens: p.store,
				HTTPClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
					downstreamCalls++
					return nil, errors.New("must not call downstream")
				})},
				AccessServerEndpoint: func(context.Context, string) (string, error) {
					downstreamCalls++
					return "https://as.example/token", nil
				},
				BindPerson: p.policyPerson,
				Consent: func(context.Context, AuthorizationRequest) error {
					p.authorizationCalls++
					return nil
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			parentKey, parentToken := p.parentKey, p.parentToken
			if test.useNestedParent {
				parentKey, parentToken = p.childKey, p.childToken
			}
			resourceToken := p.resourceToken(t, "https://as.example", "person-token", test.resourceKey(p))
			response := p.tokenRequest(t, server, parentKey, parentToken, test.childToken(t, p), resourceToken)
			if response.Code == http.StatusOK || p.authorizationCalls != 0 || downstreamCalls != 0 {
				t.Fatalf("response=%d %s policy=%d downstream=%d", response.Code, response.Body.String(), p.authorizationCalls, downstreamCalls)
			}
			_, _, loads := p.store.observation()
			if loads != test.wantLoads {
				t.Fatalf("store loads=%d, want %d", loads, test.wantLoads)
			}
		})
	}
}

func TestFederatedServerForwardsExactSubagentAndValidatesChildBoundResult(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name       string
		resultKey  func(*subagentPersonServerProtocol) jose.JWK
		wantStatus int
	}{
		{name: "child-bound result", resultKey: func(p *subagentPersonServerProtocol) jose.JWK { return p.childKey.PublicJWK() }, wantStatus: http.StatusOK},
		{name: "parent-bound result", resultKey: func(p *subagentPersonServerProtocol) jose.JWK { return p.parentKey.PublicJWK() }, wantStatus: http.StatusInternalServerError},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			p := newSubagentPersonServerProtocol(t)
			if err := p.store.Commit(context.Background(), PersonTokenRecord{
				JTI: "person-token", PersonServer: "https://ps.example", Resource: "https://resource.example",
				Subject: "person-123", Tenant: "tenant-1", ExpiresAt: p.now.Add(10 * time.Minute),
				RetainUntil: p.now.Add(15 * time.Minute), AgentProvider: "https://ap.example",
				Agent: "aauth:planner+search@ap.example", ParentAgent: "aauth:planner@ap.example",
				Confirmation: p.childKey.PublicJWK(),
			}); err != nil {
				t.Fatal(err)
			}
			resourceToken := p.resourceToken(t, "https://as.example", "person-token", p.childKey.PublicJWK())
			forwarded := 0
			client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
				forwarded++
				var input struct {
					ResourceToken string `json:"resource_token"`
					AgentToken    string `json:"agent_token"`
					SubagentToken string `json:"subagent_token"`
				}
				if err := json.NewDecoder(request.Body).Decode(&input); err != nil {
					t.Fatal(err)
				}
				if input.ResourceToken != resourceToken || input.AgentToken != p.parentToken || input.SubagentToken != p.childToken {
					t.Fatalf("federated input = %#v", input)
				}
				authToken, err := aauth.MintAuthToken(p.accessKey, aauth.AuthTokenClaims{
					Issuer: "https://as.example", DWK: aauth.AccessDiscoveryDocument,
					Audience: "https://resource.example", JTI: "as-auth-token",
					PersonServer: "https://ps.example", Subject: "person-123", Tenant: "tenant-1",
					Confirmation: aauth.Confirmation{JWK: test.resultKey(p)}, Scope: "records.read",
					IssuedAt: p.now.Unix(), ExpiresAt: p.now.Add(10 * time.Minute).Unix(),
				})
				if err != nil {
					t.Fatal(err)
				}
				body, _ := json.Marshal(map[string]any{"auth_token": authToken, "expires_in": 600})
				return &http.Response{
					StatusCode: http.StatusOK, Status: "200 OK", Request: request,
					Header: http.Header{"Content-Type": []string{"application/json"}},
					Body:   io.NopCloser(bytes.NewReader(body)),
				}, nil
			})}
			server, err := NewFederatedAuthorization(FederatedAuthorizationConfig{
				Issuer: "https://ps.example", SigningKey: p.personKey, KeyResolver: p.resolver,
				Clock: p.clock, NewID: func() string { return "unused" }, Tokens: p.store,
				HTTPClient:           client,
				AccessServerEndpoint: func(context.Context, string) (string, error) { return "https://as.example/token", nil },
				BindPerson:           p.policyPerson,
				Consent: func(_ context.Context, request AuthorizationRequest) error {
					p.authorizationCalls++
					if request.Subagent != "aauth:planner+search@ap.example" {
						return errors.New("missing sub-agent")
					}
					return nil
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			response := p.tokenRequest(t, server, p.parentKey, p.parentToken, p.childToken, resourceToken)
			if response.Code != test.wantStatus || forwarded != 1 || p.authorizationCalls != 1 {
				t.Fatalf("response=%d %s forwarded=%d policy=%d", response.Code, response.Body.String(), forwarded, p.authorizationCalls)
			}
		})
	}
}

func TestValidatePersonTokenRecordRequiresCredentialRecipient(t *testing.T) {
	t.Parallel()

	p := newSubagentPersonServerProtocol(t)
	valid := PersonTokenRecord{
		JTI: "person-token", PersonServer: "https://ps.example", Resource: "https://resource.example",
		Subject: "person-123", ExpiresAt: p.now.Add(time.Minute), RetainUntil: p.now.Add(6 * time.Minute),
		AgentProvider: "https://ap.example", Agent: "aauth:planner+search@ap.example",
		ParentAgent: "aauth:planner@ap.example", Confirmation: p.childKey.PublicJWK(),
	}
	if err := validatePersonTokenRecord(valid); err != nil {
		t.Fatalf("valid record: %v", err)
	}
	for _, change := range []func(*PersonTokenRecord){
		func(record *PersonTokenRecord) { record.AgentProvider = "" },
		func(record *PersonTokenRecord) { record.Agent = "" },
		func(record *PersonTokenRecord) { record.ParentAgent = "aauth:other@ap.example" },
		func(record *PersonTokenRecord) { record.Confirmation = jose.JWK{} },
		func(record *PersonTokenRecord) { record.Resource = "not-a-server" },
	} {
		record := valid
		change(&record)
		if err := validatePersonTokenRecord(record); err == nil {
			t.Fatalf("invalid record accepted: %#v", record)
		}
	}
}

func TestServerRetainsDelegatedAuthorizationInteractionForParentPolling(t *testing.T) {
	t.Parallel()

	p := newSubagentPersonServerProtocol(t)
	if err := p.store.Commit(context.Background(), PersonTokenRecord{
		JTI: "person-token", PersonServer: "https://ps.example", Resource: "https://resource.example",
		Subject: "person-123", Tenant: "tenant-1", ExpiresAt: p.now.Add(10 * time.Minute),
		RetainUntil: p.now.Add(15 * time.Minute), AgentProvider: "https://ap.example",
		Agent: "aauth:planner+search@ap.example", ParentAgent: "aauth:planner@ap.example",
		Confirmation: p.childKey.PublicJWK(),
	}); err != nil {
		t.Fatal(err)
	}
	authorizationStore := newMemoryDeferredAuthorizationStore()
	server, err := NewPSAuthorization(PSAuthorizationConfig{
		Issuer: "https://ps.example", SigningKey: p.personKey, KeyResolver: p.resolver,
		Clock: p.clock, NewID: func() string { return "unused" }, Tokens: p.store,
		BindPerson: p.policyPerson, Authorize: p.policyAuthorization,
		AuthorizationInteractions: authorizationStore,
		RequireAuthorizationInteraction: func(context.Context, AuthorizationRequest) (AuthorizationInteractionPolicy, bool, error) {
			p.requireAuthInteractionCalls++
			return AuthorizationInteractionPolicy{URL: "https://ps.example/interact", Lifetime: time.Minute, RetryAfter: time.Second}, true, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	resourceToken := p.resourceToken(t, "https://ps.example", "person-token", p.childKey.PublicJWK())
	response := p.tokenRequestWithCapabilities(
		t, server, p.parentKey, p.parentToken, p.childToken, resourceToken, []string{"interaction"},
	)
	if response.Code != http.StatusAccepted || p.requireAuthInteractionCalls != 1 || p.authorizationCalls != 0 {
		t.Fatalf("delegated authorization interaction = %d %s interaction=%d authorize=%d", response.Code, response.Body.String(), p.requireAuthInteractionCalls, p.authorizationCalls)
	}
	authorizationStore.mu.Lock()
	defer authorizationStore.mu.Unlock()
	if len(authorizationStore.pending) != 1 {
		t.Fatalf("delegated authorization interaction created %d pending records, want 1", len(authorizationStore.pending))
	}
	var pending PendingAuthorizationRecord
	for _, retained := range authorizationStore.pending {
		pending = retained.record
	}
	if pending.Agent != "aauth:planner@ap.example" || pending.Subagent != "aauth:planner+search@ap.example" ||
		!pending.Confirmation.Equal(p.parentKey.PublicJWK()) ||
		!pending.SubagentConfirmation.Equal(p.childKey.PublicJWK()) ||
		!pending.AgentExpiresAt.Equal(p.now.Add(40*time.Minute)) ||
		!pending.SubagentExpiresAt.Equal(p.now.Add(10*time.Minute)) ||
		!pending.ExpiresAt.Equal(p.now.Add(time.Minute)) ||
		!reflect.DeepEqual(pending.AgentAdditionalClaims, p.parentAdditionalClaims) ||
		!reflect.DeepEqual(pending.SubagentAdditionalClaims, p.childAdditionalClaims) {
		t.Fatalf("delegated pending authorization = %#v", pending)
	}
}

func TestValidatePendingAuthorizationRecordRequiresSeparateParentAndChildBindings(t *testing.T) {
	t.Parallel()

	p := newSubagentPersonServerProtocol(t)
	valid := PendingAuthorizationRecord{
		ID: "pending-subagent", CodeSHA256: sha256.Sum256([]byte("pending-subagent-code")),
		PersonServer: "https://ps.example", AgentProvider: "https://ap.example",
		Agent: "aauth:planner@ap.example", Subagent: "aauth:planner+search@ap.example",
		Resource: "https://resource.example", Subject: "person-123", Scopes: []string{"records.read"},
		Confirmation: p.parentKey.PublicJWK(), AgentExpiresAt: p.now.Add(40 * time.Minute),
		SubagentConfirmation: p.childKey.PublicJWK(), SubagentExpiresAt: p.now.Add(10 * time.Minute),
		ResourceTokenExpiresAt:   p.now.Add(5 * time.Minute),
		PersonTokenExpiresAt:     p.now.Add(5 * time.Minute),
		SubagentAdditionalClaims: cloneClaims(p.childAdditionalClaims),
		CreatedAt:                p.now, ExpiresAt: p.now.Add(time.Minute),
	}
	if err := validatePendingAuthorizationRecord(valid); err != nil {
		t.Fatalf("valid delegated record: %v", err)
	}
	for _, change := range []func(*PendingAuthorizationRecord){
		func(record *PendingAuthorizationRecord) { record.Subagent = "aauth:other+search@ap.example" },
		func(record *PendingAuthorizationRecord) { record.SubagentConfirmation = record.Confirmation },
		func(record *PendingAuthorizationRecord) { record.SubagentExpiresAt = time.Time{} },
		func(record *PendingAuthorizationRecord) { record.SubagentExpiresAt = record.CreatedAt },
		func(record *PendingAuthorizationRecord) { record.Subagent = "" },
	} {
		record := clonePendingAuthorizationRecord(valid)
		change(&record)
		if err := validatePendingAuthorizationRecord(record); err == nil {
			t.Fatalf("invalid delegated record accepted: %#v", record)
		}
	}
}

func TestServerRejectsMalformedSubagentMember(t *testing.T) {
	t.Parallel()

	p := newSubagentPersonServerProtocol(t)
	server, err := NewPSAuthorization(PSAuthorizationConfig{
		Issuer: "https://ps.example", SigningKey: p.personKey, KeyResolver: p.resolver,
		Clock: p.clock, NewID: func() string { return "unused" }, Tokens: p.store,
		BindPerson: p.policyPerson, Authorize: p.policyAuthorization,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, body := range []string{
		`{"resource":"https://resource.example","subagent_token":null}`,
		`{"resource":"https://resource.example","subagent_token":{}}`,
		`{"resource":"https://resource.example","subagent_token":""}`,
	} {
		request := httptest.NewRequest(http.MethodPost, "https://ps.example/person", strings.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		if err := signPersonServerTestRequest(request, p.parentKey, p.parentToken, p.clock); err != nil {
			t.Fatal(err)
		}
		response := httptest.NewRecorder()
		server.Handler().ServeHTTP(response, request)
		if response.Code != http.StatusBadRequest || p.bindCalls != 0 {
			t.Fatalf("malformed subagent_token %s = %d %s", body, response.Code, response.Body.String())
		}
	}
}

func assertSubagentProblem(t *testing.T, response *httptest.ResponseRecorder, status int, code string) {
	t.Helper()
	if response.Code != status {
		t.Fatalf("problem status = %d, want %d; body=%s", response.Code, status, response.Body.String())
	}
	var problem struct {
		Code string `json:"error"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &problem); err != nil {
		t.Fatal(err)
	}
	if problem.Code != code {
		t.Fatalf("problem code = %q, want %q; body=%s", problem.Code, code, response.Body.String())
	}
}
