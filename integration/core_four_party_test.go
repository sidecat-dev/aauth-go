package integration_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/accessserver"
	clientagent "gitlab.com/sidecat-dev/aauth-go/agent"
	"gitlab.com/sidecat-dev/aauth-go/agentprovider"
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/personserver"
	"gitlab.com/sidecat-dev/aauth-go/resource"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

// TestCurrentCoreFourParty is this implementation's smallest current Core
// journey: AP -> Agent -> PS -> Resource -> PS -> AS -> Resource. It covers
// both baseline retry delivery and Resource-held delivery of the auth-token
// requirement.
func TestCurrentCoreFourParty(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	now := time.Date(2026, 8, 29, 18, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	scope := []string{"records.read"}
	account := "primary"

	const (
		agentProviderID = "https://ap.example"
		agentID         = "aauth:reader@ap.example"
		personServerID  = "https://ps.example"
		accessServerID  = "https://as.example"
		resourceID      = "https://resource.example"
	)

	agentProviderKey := newSigningKey(t, "ap-key")
	agentKey := newSigningKey(t, "agent-key")
	personServerKey := newSigningKey(t, "ps-key")
	accessServerKey := newSigningKey(t, "as-key")
	resourceKey := newSigningKey(t, "resource-key")
	agentJKT, err := agentKey.PublicJWK().Thumbprint()
	if err != nil {
		t.Fatal(err)
	}

	network := newLogicalTransport()
	httpClient := &http.Client{Transport: network}
	personTokens := newMemoryPersonTokenStore()

	provider, err := agentprovider.New(agentprovider.Config{
		Issuer:     agentProviderID,
		SigningKey: agentProviderKey,
		Clock:      clock,
		NewID:      func() string { return "agent-token-1" },
	})
	if err != nil {
		t.Fatal(err)
	}
	agentToken, err := provider.Issue(aauth.AgentTokenRequest{
		Agent:        agentID,
		PersonServer: personServerID,
		PublicKey:    agentKey.PublicJWK(),
		Lifetime:     time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}

	keyResolver, err := signaturekey.NewHTTPKeyResolver(signaturekey.HTTPKeyResolverConfig{
		Client: httpClient,
		Clock:  clock,
		Admit: func(_ context.Context, endpoint string) error {
			if strings.HasSuffix(endpoint, ".example/.well-known/aauth-agent.json") ||
				strings.HasSuffix(endpoint, ".example/.well-known/aauth-person.json") ||
				strings.HasSuffix(endpoint, ".example/.well-known/aauth-access.json") ||
				strings.HasSuffix(endpoint, ".example/.well-known/aauth-resource.json") ||
				strings.HasSuffix(endpoint, ".example/.well-known/jwks.json") {
				return nil
			}
			return errors.New("unexpected discovery endpoint: " + endpoint)
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	var accessRequest accessserver.AuthorizationRequest
	access, err := accessserver.New(accessserver.Config{
		Issuer:      accessServerID,
		SigningKey:  accessServerKey,
		KeyResolver: keyResolver,
		Clock:       clock,
		NewID:       func() string { return "auth-token-1" },
		TrustPersonServer: func(_ context.Context, issuer string) error {
			if issuer != personServerID {
				return errors.New("untrusted person server")
			}
			return nil
		},
		Authorize: func(_ context.Context, request accessserver.AuthorizationRequest) (accessserver.Decision, error) {
			accessRequest = request
			return accessserver.Decision{Scopes: append([]string(nil), request.Scopes...), Lifetime: 30 * time.Minute}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	protectedCalls := 0
	var protectedAccount *string
	protected := http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		protectedCalls++
		principal, ok := resource.AuthPrincipalFromContext(request.Context())
		if !ok {
			t.Error("protected handler received no AAuth principal")
			http.Error(w, "missing principal", http.StatusInternalServerError)
			return
		}
		if principal.PersonServer != personServerID || principal.Subject != "person-123" ||
			!slices.Equal(principal.Scope, scope) ||
			!principal.Confirmation.Equal(agentKey.PublicJWK()) {
			t.Errorf("protected principal = %#v", principal)
		}
		if principal.Account != nil {
			value := *principal.Account
			protectedAccount = &value
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"ok":true}`)
	})

	protectedResource, err := resource.NewFederatedAuthorization(resource.FederatedAuthorizationConfig{
		Issuer:       resourceID,
		AccessServer: accessServerID,
		SigningKey:   resourceKey,
		KeyResolver:  keyResolver,
		Clock:        clock,
		NewID:        func() string { return "resource-token-1" },
		ScopeDescriptions: map[string]string{
			"records.read":  "Read records",
			"records.write": "Write records",
		},
		RequiredScopes: func(request *http.Request) []string {
			if request.Method == http.MethodGet {
				return []string{"records.read"}
			}
			return []string{"records.write"}
		},
		ValidateAccount: func(_ context.Context, identity resource.PersonIdentity, got string) error {
			if identity != (resource.PersonIdentity{Issuer: personServerID, Subject: "person-123"}) || got != account {
				return errors.Join(resource.ErrInvalidAccount, errors.New("unknown account"))
			}
			return nil
		},
		ResolvePerson: func(_ context.Context, identity resource.PersonIdentity, _ resource.PersonContext) error {
			if identity.Issuer != personServerID || identity.Subject != "person-123" {
				return errors.New("unrecognized person identity")
			}
			return nil
		},
		Protected: protected,
	})
	if err != nil {
		t.Fatal(err)
	}

	var consentAccount *string
	people, err := personserver.NewFederatedAuthorization(personserver.FederatedAuthorizationConfig{
		Issuer:      personServerID,
		SigningKey:  personServerKey,
		KeyResolver: keyResolver,
		Clock:       clock,
		NewID:       func() string { return "person-token-1" },
		HTTPClient:  httpClient,
		Tokens:      personTokens,
		AccessServerEndpoint: func(_ context.Context, issuer string) (string, error) {
			if issuer != accessServerID {
				return "", errors.New("unknown access server")
			}
			return accessServerID + "/token", nil
		},
		BindPerson: func(_ context.Context, request personserver.PersonTokenRequest) (personserver.Person, error) {
			if request.Agent != agentID || request.Resource != resourceID {
				return personserver.Person{}, errors.New("unexpected person-token request")
			}
			return personserver.Person{Subject: "person-123", Lifetime: time.Hour}, nil
		},
		Consent: func(_ context.Context, request personserver.AuthorizationRequest) error {
			if request.Account != nil {
				value := *request.Account
				consentAccount = &value
			}
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	var accessProofHeaders http.Header
	var authorizationProofHeaders http.Header
	tamperAuthorizationBody := false
	network.Handle(agentProviderID, provider.Handler())
	network.Handle(personServerID, people.Handler())
	network.Handle(resourceID, http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.Method == http.MethodPost && request.URL.Path == "/authorize" {
			authorizationProofHeaders = request.Header.Clone()
			if tamperAuthorizationBody {
				body, err := io.ReadAll(request.Body)
				if err != nil {
					t.Fatal(err)
				}
				body = []byte(strings.Replace(string(body), "records.read", "records.write", 1))
				request.Body = io.NopCloser(strings.NewReader(string(body)))
				request.ContentLength = int64(len(body))
			}
		}
		protectedResource.Handler().ServeHTTP(w, request)
	}))
	network.Handle(accessServerID, http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.Method == http.MethodPost && request.URL.Path == "/token" {
			accessProofHeaders = request.Header.Clone()
		}
		access.Handler().ServeHTTP(w, request)
	}))

	reader, err := clientagent.New(context.Background(), clientagent.Config{
		Identifier:  agentID,
		SigningKey:  agentKey,
		AgentToken:  agentToken,
		KeyResolver: keyResolver,
		HTTPClient:  httpClient,
		Clock:       clock,
	})
	if err != nil {
		t.Fatal(err)
	}

	personTokenResult, err := reader.PersonToken(ctx, clientagent.PersonTokenRequest{
		PersonServer: personServerID,
		Resource:     resourceID,
	})
	if err != nil {
		t.Fatal(err)
	}
	personToken, ok := personTokenResult.Token()
	if !ok {
		t.Fatalf("immediate person-token result = %#v", personTokenResult)
	}
	personClaims := tokenClaims(t, personToken)

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, resourceID+"/records/42", nil)
	if err != nil {
		t.Fatal(err)
	}
	initialResult, err := reader.Begin(ctx, clientagent.InitialCall{Request: request, PersonToken: personToken})
	if err != nil {
		t.Fatal(err)
	}
	if response, ok := initialResult.Response(); ok || response != nil {
		t.Fatalf("initial call returned ordinary response = %#v, %t", response, ok)
	}
	requirement, ok := initialResult.AuthorizationRequired()
	if !ok {
		t.Fatal("initial call did not return a verified auth-token requirement")
	}
	resourceToken := requirement.ResourceToken
	resourceClaims := tokenClaims(t, resourceToken)
	if protectedCalls != 0 {
		t.Fatalf("initial challenge reached protected handler; calls = %d", protectedCalls)
	}

	authToken, err := reader.Exchange(ctx, clientagent.ExchangeRequest{
		PersonServer:  personServerID,
		ResourceToken: resourceToken,
	})
	if err != nil {
		t.Fatal(err)
	}
	authClaims := tokenClaims(t, authToken)

	response, err := reader.Do(ctx, clientagent.Call{
		Request:   request,
		AuthToken: authToken,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(response.Body)
		t.Fatalf("protected response = %d %s", response.StatusCode, body)
	}
	responseBody, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(responseBody) != `{"ok":true}` {
		t.Fatalf("protected response body = %s, want exact {\"ok\":true}", responseBody)
	}
	if protectedCalls != 1 {
		t.Fatalf("protected handler calls = %d, want 1", protectedCalls)
	}

	writeRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, resourceID+"/records/42", strings.NewReader(`{"value":"changed"}`))
	if err != nil {
		t.Fatal(err)
	}
	writeRequest.Header.Set("Content-Type", "application/json")
	_, err = reader.Do(ctx, clientagent.Call{Request: writeRequest, AuthToken: authToken})
	var denial *aauth.ProblemError
	if !errors.As(err, &denial) || denial.Status != http.StatusForbidden || denial.Code != "access_denied" {
		t.Fatalf("write with read scope error = %v, problem = %#v", err, denial)
	}
	if protectedCalls != 1 {
		t.Fatalf("denied write reached protected handler; calls = %d", protectedCalls)
	}

	record, commits, loads := personTokens.observation()
	if commits != 1 {
		t.Fatalf("person-token record commits = %d, want 1", commits)
	}
	if loads == 0 {
		t.Fatal("person server did not cross-check the retained person-token record")
	}
	if record.PersonServer != personServerID || record.JTI != claimString(t, personClaims, "jti") ||
		record.Resource != resourceID || record.Subject != "person-123" {
		t.Fatalf("retained person-token record = %#v", record)
	}

	if accessProofHeaders.Get("Signature") == "" || accessProofHeaders.Get("Signature-Input") == "" ||
		accessProofHeaders.Get("Signature-Key") == "" || accessRequest.PersonServer != personServerID {
		t.Fatalf("access-server request was not authenticated as the person server: headers=%v request=%#v", accessProofHeaders, accessRequest)
	}

	tamperAuthorizationBody = true
	if _, err := reader.Authorize(ctx, clientagent.AuthorizeRequest{
		Resource: resourceID, PersonToken: personToken, Scopes: scope,
	}); err == nil {
		t.Fatal("resource accepted an authorization request whose signed scope body was changed in transit")
	}
	if signatureInput := authorizationProofHeaders.Get("Signature-Input"); !strings.Contains(signatureInput, `"content-type"`) || !strings.Contains(signatureInput, `"content-digest"`) {
		t.Fatalf("authorization request did not bind its JSON body: %s", signatureInput)
	}

	requireTokenBindings(t, personClaims, tokenBinding{
		Issuer: personServerID, Audience: resourceID, PersonServer: "",
		Subject: "person-123", Confirmation: agentKey.PublicJWK(),
	})
	requireTokenBindings(t, resourceClaims, tokenBinding{
		Issuer: resourceID, Audience: accessServerID, PersonServer: personServerID,
		Subject: "person-123", AgentJKT: agentJKT, Scope: scope,
	})
	requireTokenBindings(t, authClaims, tokenBinding{
		Issuer: accessServerID, Audience: resourceID, PersonServer: personServerID,
		Subject: "person-123", Confirmation: agentKey.PublicJWK(), Scope: scope,
	})

	// Core account binding is independent of R3 and Budget. Every role sees the
	// same Resource-validated selector, and the protected principal retains it.
	tamperAuthorizationBody = false
	accountResourceToken, err := reader.Authorize(ctx, clientagent.AuthorizeRequest{
		Resource: resourceID, PersonToken: personToken, Scopes: scope, Account: &account,
	})
	if err != nil {
		t.Fatal(err)
	}
	accountAuthToken, err := reader.Exchange(ctx, clientagent.ExchangeRequest{
		PersonServer: personServerID, ResourceToken: accountResourceToken,
	})
	if err != nil {
		t.Fatal(err)
	}
	accountResponse, err := reader.Do(ctx, clientagent.Call{Request: request, AuthToken: accountAuthToken})
	if err != nil {
		t.Fatal(err)
	}
	accountResponse.Body.Close()
	resourceAccountClaims, err := aauth.VerifyResourceToken(ctx, accountResourceToken, keyResolver, clock)
	if err != nil {
		t.Fatal(err)
	}
	authAccountClaims, err := aauth.VerifyAuthToken(ctx, accountAuthToken, keyResolver, clock)
	if err != nil {
		t.Fatal(err)
	}
	if resourceAccountClaims.Account == nil || *resourceAccountClaims.Account != account ||
		consentAccount == nil || *consentAccount != account ||
		accessRequest.Account == nil || *accessRequest.Account != account ||
		authAccountClaims.Account == nil || *authAccountClaims.Account != account ||
		protectedAccount == nil || *protectedAccount != account || protectedCalls != 2 {
		t.Fatalf("Core account path = resource=%#v consent=%#v access=%#v auth=%#v protected=%#v calls=%d",
			resourceAccountClaims.Account, consentAccount, accessRequest.Account,
			authAccountClaims.Account, protectedAccount, protectedCalls)
	}

	heldStore := newMemoryHeldInvocationStore()
	heldCalls := 0
	newHeldResource := func() *resource.Server {
		server, err := resource.NewFederatedAuthorization(resource.FederatedAuthorizationConfig{
			Issuer:                        resourceID,
			AccessServer:                  accessServerID,
			SigningKey:                    resourceKey,
			KeyResolver:                   keyResolver,
			Clock:                         clock,
			NewID:                         func() string { return "held-resource-token-1" },
			ScopeDescriptions:             map[string]string{"records.read": "Read records", "records.write": "Write records"},
			AdditionalSignatureComponents: []string{"content-type", "content-digest"},
			RequiredScopes: func(request *http.Request) []string {
				if request.Method == http.MethodPost {
					return []string{"records.write"}
				}
				return []string{"records.read"}
			},
			ResolvePerson: func(_ context.Context, identity resource.PersonIdentity, _ resource.PersonContext) error {
				if identity != (resource.PersonIdentity{Issuer: personServerID, Subject: "person-123"}) {
					return errors.New("unrecognized held person identity")
				}
				return nil
			},
			Protected: http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
				heldCalls++
				principal, ok := resource.AuthPrincipalFromContext(request.Context())
				body, readErr := io.ReadAll(request.Body)
				if readErr != nil {
					t.Error(readErr)
				}
				if !ok || principal.PersonServer != personServerID || principal.Subject != "person-123" ||
					!principal.Confirmation.Equal(agentKey.PublicJWK()) || !slices.Equal(principal.Scope, []string{"records.write"}) {
					t.Errorf("held principal = %#v, present = %t", principal, ok)
				}
				if request.Method != http.MethodPost || request.URL.EscapedPath() != "/records/held" ||
					request.URL.RawQuery != "view=full" || request.Header.Get("X-Trace") != "held-42" ||
					string(body) != `{"value":"held"}` {
					t.Errorf("held application request = %s %s, headers=%v, body=%q", request.Method, request.URL, request.Header, body)
				}
				response.Header().Set("Content-Type", "application/json")
				response.WriteHeader(http.StatusCreated)
				_, _ = io.WriteString(response, `{"held":true}`)
			}),
			HeldInvocations:              heldStore,
			MaxRetainedRequestBodyBytes:  64 << 10,
			MaxRetainedResponseBodyBytes: 64 << 10,
			MaxRetainedHeaderBytes:       16 << 10,
		})
		if err != nil {
			t.Fatal(err)
		}
		return server
	}
	network.Handle(resourceID, newHeldResource().Handler())
	heldRequest, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		resourceID+"/records/held?view=full",
		strings.NewReader(`{"value":"held"}`),
	)
	if err != nil {
		t.Fatal(err)
	}
	heldRequest.Header.Set("Content-Type", "application/json")
	heldRequest.Header.Set("X-Trace", "held-42")
	heldResult, err := reader.Begin(ctx, clientagent.InitialCall{Request: heldRequest, PersonToken: personToken})
	if err != nil {
		t.Fatal(err)
	}
	pending, ok := heldResult.PendingAuthToken()
	if !ok || pending.Location() == "" || pending.ResourceToken() == "" || pending.RetryAfter() != 5*time.Second {
		t.Fatalf("held Begin result = %#v, present = %t", pending, ok)
	}
	if heldCalls != 0 {
		t.Fatalf("held invocation executed before authorization; calls = %d", heldCalls)
	}
	heldAuthToken, err := reader.Exchange(ctx, clientagent.ExchangeRequest{
		PersonServer: personServerID, ResourceToken: pending.ResourceToken(),
	})
	if err != nil {
		t.Fatal(err)
	}

	// Recompose the Resource around the same store before execution and again
	// before replay. The invocation and its result belong to the host store,
	// not one in-process Server value.
	network.Handle(resourceID, newHeldResource().Handler())
	heldResponse, err := reader.PollAuthToken(ctx, clientagent.AuthTokenPoll{Pending: pending, AuthToken: heldAuthToken})
	if err != nil {
		t.Fatal(err)
	}
	heldBody, err := io.ReadAll(heldResponse.Body)
	heldResponse.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if heldResponse.StatusCode != http.StatusCreated || string(heldBody) != `{"held":true}` || heldCalls != 1 {
		t.Fatalf("held completion = %d %q; application calls=%d", heldResponse.StatusCode, heldBody, heldCalls)
	}

	network.Handle(resourceID, newHeldResource().Handler())
	replayed, err := reader.PollAuthToken(ctx, clientagent.AuthTokenPoll{Pending: pending, AuthToken: heldAuthToken})
	if err != nil {
		t.Fatal(err)
	}
	replayedBody, err := io.ReadAll(replayed.Body)
	replayed.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if replayed.StatusCode != http.StatusCreated || string(replayedBody) != `{"held":true}` || heldCalls != 1 {
		t.Fatalf("held replay = %d %q; application calls=%d", replayed.StatusCode, replayedBody, heldCalls)
	}
	if claims, retains := heldStore.observation(); claims != 2 || retains != 1 {
		t.Fatalf("held store transitions = claims %d, retains %d; want 2/1", claims, retains)
	}
}

type tokenBinding struct {
	Issuer       string
	Audience     string
	PersonServer string
	Subject      string
	Confirmation jose.JWK
	AgentJKT     string
	Scope        []string
}

func requireTokenBindings(t *testing.T, claims map[string]any, want tokenBinding) {
	t.Helper()
	if got := claimString(t, claims, "iss"); got != want.Issuer {
		t.Errorf("token iss = %q, want %q", got, want.Issuer)
	}
	if got := claimString(t, claims, "aud"); got != want.Audience {
		t.Errorf("token aud = %q, want %q", got, want.Audience)
	}
	if want.PersonServer != "" {
		if got := claimString(t, claims, "ps"); got != want.PersonServer {
			t.Errorf("token ps = %q, want %q", got, want.PersonServer)
		}
	}
	if got := claimString(t, claims, "sub"); got != want.Subject {
		t.Errorf("token sub = %q, want %q", got, want.Subject)
	}
	if want.Confirmation.Kty != "" {
		confirmation, ok := claims["cnf"].(map[string]any)
		if !ok {
			t.Fatalf("token cnf = %#v, want object", claims["cnf"])
		}
		encodedKey, err := json.Marshal(confirmation["jwk"])
		if err != nil {
			t.Fatal(err)
		}
		var key jose.JWK
		if err := json.Unmarshal(encodedKey, &key); err != nil {
			t.Fatal(err)
		}
		if !key.Equal(want.Confirmation) {
			t.Errorf("token cnf.jwk = %#v, want %#v", key, want.Confirmation)
		}
	}
	if want.AgentJKT != "" {
		if got := claimString(t, claims, "agent_jkt"); got != want.AgentJKT {
			t.Errorf("token agent_jkt = %q, want %q", got, want.AgentJKT)
		}
	}
	if want.Scope != nil {
		gotScope := claimStrings(t, claims, "scope")
		if !slices.Equal(gotScope, want.Scope) {
			t.Errorf("token scope = %v, want %v", gotScope, want.Scope)
		}
	}
}

func tokenClaims(t *testing.T, compact string) map[string]any {
	t.Helper()
	parsed, err := jose.ParseCompact(compact)
	if err != nil {
		t.Fatal(err)
	}
	var claims map[string]any
	if err := json.Unmarshal(parsed.Payload(), &claims); err != nil {
		t.Fatal(err)
	}
	return claims
}

func claimString(t *testing.T, claims map[string]any, name string) string {
	t.Helper()
	value, ok := claims[name].(string)
	if !ok || value == "" {
		t.Fatalf("token %s = %#v, want nonempty string", name, claims[name])
	}
	return value
}

func claimStrings(t *testing.T, claims map[string]any, name string) []string {
	t.Helper()
	switch value := claims[name].(type) {
	case string:
		return strings.Fields(value)
	case []any:
		result := make([]string, 0, len(value))
		for _, member := range value {
			text, ok := member.(string)
			if !ok {
				t.Fatalf("token %s member = %#v, want string", name, member)
			}
			result = append(result, text)
		}
		return result
	default:
		t.Fatalf("token %s = %#v, want string or array", name, claims[name])
		return nil
	}
}

func newSigningKey(t *testing.T, id string) jose.SigningKey {
	t.Helper()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := jose.NewEd25519SigningKey(id, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

type memoryPersonTokenStore struct {
	mu       sync.Mutex
	records  map[string]personserver.PersonTokenRecord
	missions map[string]personserver.MissionRecord
	auth     map[string]personserver.IssuedAuthTokenRecord
	pending  map[string]*memoryPendingPersonToken
	byCode   map[[32]byte]string
	last     personserver.PersonTokenRecord
	commits  int
	loads    int
}

func newMemoryPersonTokenStore() *memoryPersonTokenStore {
	return &memoryPersonTokenStore{
		records: make(map[string]personserver.PersonTokenRecord), missions: make(map[string]personserver.MissionRecord),
		auth:    make(map[string]personserver.IssuedAuthTokenRecord),
		pending: make(map[string]*memoryPendingPersonToken), byCode: make(map[[32]byte]string),
	}
}

func (store *memoryPersonTokenStore) CommitMission(
	_ context.Context,
	mission personserver.MissionRecord,
	tokens []personserver.PersonTokenRecord,
) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	missionKey := mission.Agent + "\x00" + mission.S256
	if _, exists := store.missions[missionKey]; exists {
		return errors.New("mission record conflicts with retained value")
	}
	batch := make(map[string]struct{}, len(tokens))
	for _, token := range tokens {
		key := token.PersonServer + "\x00" + token.JTI
		if _, exists := store.records[key]; exists {
			return errors.New("person-token record conflicts with retained value")
		}
		if _, duplicate := batch[key]; duplicate {
			return errors.New("person-token identity is duplicated within mission approval")
		}
		batch[key] = struct{}{}
	}
	store.missions[missionKey] = cloneIntegrationMissionRecord(mission)
	for _, token := range tokens {
		store.records[token.PersonServer+"\x00"+token.JTI] = token
		store.last = token
		store.commits++
	}
	return nil
}

func (store *memoryPersonTokenStore) LoadMissionForAgent(
	_ context.Context, agent, s256 string, at time.Time,
) (personserver.MissionRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	key := agent + "\x00" + s256
	record, exists := store.missions[key]
	if !exists {
		return personserver.MissionRecord{}, personserver.ErrMissionNotFound
	}
	if record.State == personserver.MissionActive && !record.ExpiresAt.IsZero() && !at.Before(record.ExpiresAt) {
		record.State = personserver.MissionTerminated
		record.TerminationReason = "expired"
		store.missions[key] = cloneIntegrationMissionRecord(record)
	}
	return cloneIntegrationMissionRecord(record), nil
}

func (store *memoryPersonTokenStore) AppendMissionUpdate(
	_ context.Context,
	expected personserver.MissionRecord,
	acceptedAt time.Time,
	document aauth.MissionUpdateDocument,
) (personserver.MissionRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if acceptedAt.IsZero() {
		return personserver.MissionRecord{}, errors.New("mission acceptance time is required")
	}
	if err := store.requireActiveMissionLocked(expected, acceptedAt); err != nil {
		return personserver.MissionRecord{}, err
	}
	key := expected.Agent + "\x00" + expected.S256
	current := store.missions[key]
	current.AcceptedUpdates = append(current.AcceptedUpdates, personserver.MissionUpdateRecord{
		Document: cloneIntegrationMissionUpdateDocument(document), AcceptedAt: acceptedAt,
	})
	store.missions[key] = cloneIntegrationMissionRecord(current)
	return cloneIntegrationMissionRecord(current), nil
}

func (store *memoryPersonTokenStore) CompleteMission(
	_ context.Context,
	expected personserver.MissionRecord,
	acceptedAt time.Time,
	document aauth.MissionCompletionDocument,
) (personserver.MissionRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if acceptedAt.IsZero() {
		return personserver.MissionRecord{}, errors.New("mission acceptance time is required")
	}
	if err := store.requireActiveMissionLocked(expected, acceptedAt); err != nil {
		return personserver.MissionRecord{}, err
	}
	key := expected.Agent + "\x00" + expected.S256
	current := store.missions[key]
	current.State = personserver.MissionTerminated
	current.TerminationReason = "completed"
	current.Completion = &personserver.MissionCompletionRecord{
		Document: cloneIntegrationMissionCompletionDocument(document), AcceptedAt: acceptedAt,
	}
	store.missions[key] = cloneIntegrationMissionRecord(current)
	return cloneIntegrationMissionRecord(current), nil
}

func (store *memoryPersonTokenStore) CommitMissionPersonToken(
	_ context.Context, expected personserver.MissionRecord, at time.Time, token personserver.PersonTokenRecord,
) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.requireActiveMissionLocked(expected, at); err != nil {
		return err
	}
	if token.MissionS256 != expected.S256 || token.Agent != expected.Agent {
		return personserver.ErrMissionConflict
	}
	key := token.PersonServer + "\x00" + token.JTI
	if _, exists := store.records[key]; exists {
		return errors.New("person-token record conflicts with retained value")
	}
	store.records[key] = token
	store.last = token
	store.commits++
	return nil
}

func (store *memoryPersonTokenStore) CommitMissionAuthToken(
	_ context.Context, expected personserver.MissionRecord, at time.Time, token personserver.IssuedAuthTokenRecord,
) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.requireActiveMissionLocked(expected, at); err != nil {
		return err
	}
	if token.MissionS256 != expected.S256 {
		return personserver.ErrMissionConflict
	}
	key := token.Reference.Issuer + "\x00" + token.Reference.JTI
	if _, exists := store.auth[key]; exists {
		return errors.New("auth-token record conflicts with retained value")
	}
	store.auth[key] = token
	return nil
}

func (store *memoryPersonTokenStore) terminateMission(agent, s256, reason string) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	key := agent + "\x00" + s256
	record, exists := store.missions[key]
	if !exists {
		return personserver.ErrMissionNotFound
	}
	record.State = personserver.MissionTerminated
	record.TerminationReason = reason
	store.missions[key] = cloneIntegrationMissionRecord(record)
	return nil
}

func (store *memoryPersonTokenStore) requireActiveMissionLocked(expected personserver.MissionRecord, at time.Time) error {
	key := expected.Agent + "\x00" + expected.S256
	current, exists := store.missions[key]
	if !exists {
		return personserver.ErrMissionNotFound
	}
	if current.State == personserver.MissionActive && !current.ExpiresAt.IsZero() && !at.Before(current.ExpiresAt) {
		current.State = personserver.MissionTerminated
		current.TerminationReason = "expired"
		store.missions[key] = cloneIntegrationMissionRecord(current)
	}
	if current.State == personserver.MissionTerminated {
		return &personserver.MissionTerminatedError{TerminationReason: current.TerminationReason}
	}
	if !current.Equal(expected) {
		return personserver.ErrMissionConflict
	}
	return nil
}

func cloneIntegrationMissionRecord(record personserver.MissionRecord) personserver.MissionRecord {
	record.ExactJSON = append([]byte(nil), record.ExactJSON...)
	record.AcceptedUpdates = append([]personserver.MissionUpdateRecord(nil), record.AcceptedUpdates...)
	for index := range record.AcceptedUpdates {
		record.AcceptedUpdates[index].Document = cloneIntegrationMissionUpdateDocument(record.AcceptedUpdates[index].Document)
	}
	if record.Completion != nil {
		completion := *record.Completion
		completion.Document = cloneIntegrationMissionCompletionDocument(completion.Document)
		record.Completion = &completion
	}
	return record
}

func cloneIntegrationMissionUpdateDocument(document aauth.MissionUpdateDocument) aauth.MissionUpdateDocument {
	document.ExactJSON = append([]byte(nil), document.ExactJSON...)
	return document
}

func cloneIntegrationMissionCompletionDocument(document aauth.MissionCompletionDocument) aauth.MissionCompletionDocument {
	document.ExactJSON = append([]byte(nil), document.ExactJSON...)
	return document
}

type memoryPendingPersonToken struct {
	record   personserver.PendingPersonTokenRecord
	state    personserver.PersonTokenPollState
	approval personserver.PersonTokenApproval
	denied   bool
}

func (store *memoryPersonTokenStore) Commit(_ context.Context, record personserver.PersonTokenRecord) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	key := record.PersonServer + "\x00" + record.JTI
	if existing, ok := store.records[key]; ok && !reflect.DeepEqual(existing, record) {
		return errors.New("person-token record conflicts with retained value")
	}
	store.records[key] = record
	store.last = record
	store.commits++
	return nil
}

func (store *memoryPersonTokenStore) Load(_ context.Context, issuer, jti string) (personserver.PersonTokenRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.loads++
	record, ok := store.records[issuer+"\x00"+jti]
	if !ok {
		return personserver.PersonTokenRecord{}, personserver.ErrPersonTokenNotFound
	}
	return record, nil
}

func (store *memoryPersonTokenStore) observation() (personserver.PersonTokenRecord, int, int) {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.last, store.commits, store.loads
}

func (store *memoryPersonTokenStore) CreatePendingPersonToken(_ context.Context, record personserver.PendingPersonTokenRecord) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if _, ok := store.pending[record.ID]; ok {
		return personserver.ErrPendingPersonTokenConflict
	}
	if _, ok := store.byCode[record.CodeSHA256]; ok {
		return personserver.ErrPendingPersonTokenConflict
	}
	store.pending[record.ID] = &memoryPendingPersonToken{
		record: clonePendingPersonToken(record), state: personserver.PersonTokenPollWaiting,
	}
	store.byCode[record.CodeSHA256] = record.ID
	return nil
}

func (store *memoryPersonTokenStore) ConsumePersonTokenInteractionCode(_ context.Context, personServer, reference string, code [32]byte, now time.Time) (personserver.PendingPersonTokenRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	pending, ok := store.pending[reference]
	if !ok {
		return personserver.PendingPersonTokenRecord{}, personserver.ErrInteractionCodeInvalid
	}
	if pending.record.PersonServer != personServer || pending.record.CodeSHA256 != code {
		return personserver.PendingPersonTokenRecord{}, personserver.ErrInteractionCodeInvalid
	}
	if pending.state != personserver.PersonTokenPollWaiting {
		return personserver.PendingPersonTokenRecord{}, personserver.ErrInteractionCodeUsed
	}
	if !now.Before(pending.record.ExpiresAt) {
		pending.state = personserver.PersonTokenPollExpired
		return personserver.PendingPersonTokenRecord{}, personserver.ErrPendingPersonTokenExpired
	}
	pending.state = personserver.PersonTokenPollInteracting
	return clonePendingPersonToken(pending.record), nil
}

func (store *memoryPersonTokenStore) LoadPendingPersonToken(_ context.Context, id string) (personserver.PendingPersonTokenSnapshot, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	pending, ok := store.pending[id]
	if !ok {
		return personserver.PendingPersonTokenSnapshot{}, personserver.ErrPendingPersonTokenNotFound
	}
	snapshot := personserver.PendingPersonTokenSnapshot{Record: clonePendingPersonToken(pending.record), State: pending.state}
	if pending.state == personserver.PersonTokenPollApproved {
		snapshot.ApprovedPerson = pending.approval.Person
	}
	return snapshot, nil
}

func (store *memoryPersonTokenStore) ApprovePendingPersonToken(_ context.Context, id string, approval personserver.PersonTokenApproval) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	pending, ok := store.pending[id]
	if !ok {
		return personserver.ErrPendingPersonTokenNotFound
	}
	if pending.state == personserver.PersonTokenPollApproved && reflect.DeepEqual(pending.approval.Person, approval.Person) {
		return nil
	}
	if pending.state != personserver.PersonTokenPollInteracting {
		return personserver.ErrPendingPersonTokenConflict
	}
	key := approval.Record.PersonServer + "\x00" + approval.Record.JTI
	if existing, ok := store.records[key]; ok && !reflect.DeepEqual(existing, approval.Record) {
		return personserver.ErrPendingPersonTokenConflict
	}
	store.records[key] = approval.Record
	store.last = approval.Record
	store.commits++
	pending.approval = approval
	pending.state = personserver.PersonTokenPollApproved
	return nil
}

func (store *memoryPersonTokenStore) DenyPendingPersonToken(_ context.Context, id string, _ time.Time) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	pending, ok := store.pending[id]
	if !ok {
		return personserver.ErrPendingPersonTokenNotFound
	}
	if pending.state == personserver.PersonTokenPollDenied && pending.denied {
		return nil
	}
	if pending.state != personserver.PersonTokenPollInteracting {
		return personserver.ErrPendingPersonTokenConflict
	}
	pending.denied = true
	pending.state = personserver.PersonTokenPollDenied
	return nil
}

func (store *memoryPersonTokenStore) InvalidatePendingPersonToken(_ context.Context, id string, _ time.Time) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	pending, ok := store.pending[id]
	if !ok {
		return personserver.ErrPendingPersonTokenNotFound
	}
	if pending.state == personserver.PersonTokenPollGone {
		return nil
	}
	if pending.state != personserver.PersonTokenPollWaiting && pending.state != personserver.PersonTokenPollInteracting {
		return personserver.ErrPendingPersonTokenConflict
	}
	pending.state = personserver.PersonTokenPollGone
	return nil
}

func (store *memoryPersonTokenStore) PollPendingPersonToken(
	_ context.Context,
	id string,
	identity personserver.PersonTokenPollIdentity,
	now time.Time,
) (personserver.PersonTokenPollRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	pending, ok := store.pending[id]
	if !ok {
		return personserver.PersonTokenPollRecord{}, personserver.ErrPendingPersonTokenNotFound
	}
	wantJKT, _ := pending.record.RequestingConfirmation.Thumbprint()
	if identity.PersonServer != pending.record.PersonServer || identity.Agent != pending.record.RequestingAgent || identity.ConfirmationThumbprint != wantJKT {
		return personserver.PersonTokenPollRecord{}, personserver.ErrPendingPersonTokenNotFound
	}
	if pending.state == personserver.PersonTokenPollGone {
		return personserver.PersonTokenPollRecord{}, personserver.ErrPendingPersonTokenGone
	}
	if !now.Before(pending.record.ExpiresAt) &&
		(pending.state == personserver.PersonTokenPollWaiting || pending.state == personserver.PersonTokenPollInteracting) {
		pending.state = personserver.PersonTokenPollExpired
	}
	result := personserver.PersonTokenPollRecord{State: pending.state, RetryAfter: pending.record.RetryAfter}
	switch pending.state {
	case personserver.PersonTokenPollApproved:
		result.Token = pending.approval.Token
		result.Record = pending.approval.Record
		result.ExpiresIn = pending.approval.ExpiresIn
	}
	return result, nil
}

func (store *memoryPersonTokenStore) ConsumePendingPersonTokenResult(_ context.Context, id string, result personserver.PersonTokenPollRecord) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	pending, ok := store.pending[id]
	if !ok {
		return personserver.ErrPendingPersonTokenNotFound
	}
	if pending.state == personserver.PersonTokenPollGone {
		return personserver.ErrPendingPersonTokenGone
	}
	if result.State != pending.state {
		return personserver.ErrPendingPersonTokenConflict
	}
	switch pending.state {
	case personserver.PersonTokenPollApproved:
		want := personserver.PersonTokenPollRecord{
			State: personserver.PersonTokenPollApproved, Token: pending.approval.Token,
			Record: pending.approval.Record, ExpiresIn: pending.approval.ExpiresIn,
			RetryAfter: pending.record.RetryAfter,
		}
		if !reflect.DeepEqual(result, want) {
			return personserver.ErrPendingPersonTokenConflict
		}
	case personserver.PersonTokenPollDenied, personserver.PersonTokenPollExpired:
		if result.Token != "" || result.Record != (personserver.PersonTokenRecord{}) || result.ExpiresIn != 0 ||
			result.RetryAfter != pending.record.RetryAfter {
			return personserver.ErrPendingPersonTokenConflict
		}
	default:
		return personserver.ErrPendingPersonTokenConflict
	}
	pending.state = personserver.PersonTokenPollGone
	return nil
}

func (store *memoryPersonTokenStore) CreateMissionPendingPersonToken(
	_ context.Context,
	expected personserver.MissionRecord,
	record personserver.PendingPersonTokenRecord,
	at time.Time,
) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.requireActiveMissionLocked(expected, at); err != nil {
		return err
	}
	if record.Agent != expected.Agent || record.MissionS256 != expected.S256 {
		return personserver.ErrMissionConflict
	}
	if _, ok := store.pending[record.ID]; ok {
		return personserver.ErrPendingPersonTokenConflict
	}
	if _, ok := store.byCode[record.CodeSHA256]; ok {
		return personserver.ErrPendingPersonTokenConflict
	}
	store.pending[record.ID] = &memoryPendingPersonToken{
		record: clonePendingPersonToken(record), state: personserver.PersonTokenPollWaiting,
	}
	store.byCode[record.CodeSHA256] = record.ID
	return nil
}

func (store *memoryPersonTokenStore) ApproveMissionPendingPersonToken(
	_ context.Context,
	expected personserver.MissionRecord,
	id string,
	approval personserver.PersonTokenApproval,
	at time.Time,
) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.requireActiveMissionLocked(expected, at); err != nil {
		return err
	}
	pending, ok := store.pending[id]
	if !ok {
		return personserver.ErrPendingPersonTokenNotFound
	}
	if pending.record.Agent != expected.Agent || pending.record.MissionS256 != expected.S256 ||
		approval.Record.Agent != expected.Agent || approval.Record.MissionS256 != expected.S256 {
		return personserver.ErrMissionConflict
	}
	if pending.state == personserver.PersonTokenPollApproved && reflect.DeepEqual(pending.approval.Person, approval.Person) {
		return nil
	}
	if pending.state != personserver.PersonTokenPollInteracting {
		return personserver.ErrPendingPersonTokenConflict
	}
	key := approval.Record.PersonServer + "\x00" + approval.Record.JTI
	if existing, ok := store.records[key]; ok && !reflect.DeepEqual(existing, approval.Record) {
		return personserver.ErrPendingPersonTokenConflict
	}
	store.records[key] = approval.Record
	store.last, store.commits = approval.Record, store.commits+1
	pending.approval, pending.state = approval, personserver.PersonTokenPollApproved
	return nil
}

func (store *memoryPersonTokenStore) DenyMissionPendingPersonToken(
	_ context.Context,
	expected personserver.MissionRecord,
	id string,
	at time.Time,
) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.requireActiveMissionLocked(expected, at); err != nil {
		return err
	}
	pending, ok := store.pending[id]
	if !ok {
		return personserver.ErrPendingPersonTokenNotFound
	}
	if pending.record.Agent != expected.Agent || pending.record.MissionS256 != expected.S256 {
		return personserver.ErrMissionConflict
	}
	if pending.state == personserver.PersonTokenPollDenied && pending.denied {
		return nil
	}
	if pending.state != personserver.PersonTokenPollInteracting {
		return personserver.ErrPendingPersonTokenConflict
	}
	pending.denied, pending.state = true, personserver.PersonTokenPollDenied
	return nil
}

func (store *memoryPersonTokenStore) PollMissionPendingPersonToken(
	_ context.Context,
	expected personserver.MissionRecord,
	id string,
	identity personserver.PersonTokenPollIdentity,
	at time.Time,
) (personserver.PersonTokenPollRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.requireActiveMissionLocked(expected, at); err != nil {
		return personserver.PersonTokenPollRecord{}, err
	}
	pending, ok := store.pending[id]
	if !ok || pending.record.Agent != expected.Agent || pending.record.MissionS256 != expected.S256 {
		return personserver.PersonTokenPollRecord{}, personserver.ErrPendingPersonTokenNotFound
	}
	wantJKT, _ := pending.record.RequestingConfirmation.Thumbprint()
	if identity.PersonServer != pending.record.PersonServer || identity.Agent != pending.record.RequestingAgent ||
		identity.ConfirmationThumbprint != wantJKT {
		return personserver.PersonTokenPollRecord{}, personserver.ErrPendingPersonTokenNotFound
	}
	if pending.state == personserver.PersonTokenPollGone {
		return personserver.PersonTokenPollRecord{}, personserver.ErrPendingPersonTokenGone
	}
	if !at.Before(pending.record.ExpiresAt) &&
		(pending.state == personserver.PersonTokenPollWaiting || pending.state == personserver.PersonTokenPollInteracting) {
		pending.state = personserver.PersonTokenPollExpired
	}
	result := personserver.PersonTokenPollRecord{State: pending.state, RetryAfter: pending.record.RetryAfter}
	if pending.state == personserver.PersonTokenPollApproved {
		result.Token, result.Record = pending.approval.Token, pending.approval.Record
		result.ExpiresIn = pending.approval.ExpiresIn
	}
	return result, nil
}

func (store *memoryPersonTokenStore) ConsumeMissionPendingPersonTokenResult(
	_ context.Context,
	expected personserver.MissionRecord,
	id string,
	result personserver.PersonTokenPollRecord,
	at time.Time,
) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.requireActiveMissionLocked(expected, at); err != nil {
		return err
	}
	pending, ok := store.pending[id]
	if !ok || pending.record.Agent != expected.Agent || pending.record.MissionS256 != expected.S256 {
		return personserver.ErrPendingPersonTokenNotFound
	}
	if pending.state == personserver.PersonTokenPollGone {
		return personserver.ErrPendingPersonTokenGone
	}
	if result.State != pending.state {
		return personserver.ErrPendingPersonTokenConflict
	}
	switch pending.state {
	case personserver.PersonTokenPollApproved:
		want := personserver.PersonTokenPollRecord{
			State: personserver.PersonTokenPollApproved, Token: pending.approval.Token,
			Record: pending.approval.Record, ExpiresIn: pending.approval.ExpiresIn,
			RetryAfter: pending.record.RetryAfter,
		}
		if !reflect.DeepEqual(result, want) {
			return personserver.ErrPendingPersonTokenConflict
		}
	case personserver.PersonTokenPollDenied, personserver.PersonTokenPollExpired:
		if result.Token != "" || result.Record != (personserver.PersonTokenRecord{}) || result.ExpiresIn != 0 ||
			result.RetryAfter != pending.record.RetryAfter {
			return personserver.ErrPendingPersonTokenConflict
		}
	default:
		return personserver.ErrPendingPersonTokenConflict
	}
	pending.state = personserver.PersonTokenPollGone
	return nil
}

func clonePendingPersonToken(record personserver.PendingPersonTokenRecord) personserver.PendingPersonTokenRecord {
	if len(record.AgentAdditionalClaims) > 0 {
		claims := make(map[string]json.RawMessage, len(record.AgentAdditionalClaims))
		for name, value := range record.AgentAdditionalClaims {
			claims[name] = append(json.RawMessage(nil), value...)
		}
		record.AgentAdditionalClaims = claims
	}
	if len(record.RequestingAgentAdditionalClaims) > 0 {
		claims := make(map[string]json.RawMessage, len(record.RequestingAgentAdditionalClaims))
		for name, value := range record.RequestingAgentAdditionalClaims {
			claims[name] = append(json.RawMessage(nil), value...)
		}
		record.RequestingAgentAdditionalClaims = claims
	}
	return record
}

var _ personserver.DeferredTokenStore = (*memoryPersonTokenStore)(nil)
var _ personserver.MissionDeferredTokenStore = (*memoryPersonTokenStore)(nil)

type memoryHeldInvocationStore struct {
	mu         sync.Mutex
	invocation resource.HeldInvocation
	response   resource.HeldResponse
	token      resource.HeldAuthToken
	state      string
	claims     int
	retains    int
}

func newMemoryHeldInvocationStore() *memoryHeldInvocationStore {
	return &memoryHeldInvocationStore{}
}

func (store *memoryHeldInvocationStore) Create(_ context.Context, invocation resource.HeldInvocation) (string, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.state != "" {
		return "", resource.ErrHeldInvocationConflict
	}
	store.invocation = cloneHeldInvocation(invocation)
	store.state = "pending"
	return "held-four-party-0123456789abcdef", nil
}

func (store *memoryHeldInvocationStore) Load(_ context.Context, id string) (resource.HeldInvocation, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if id != "held-four-party-0123456789abcdef" || store.state == "" {
		return resource.HeldInvocation{}, resource.ErrHeldInvocationNotFound
	}
	return cloneHeldInvocation(store.invocation), nil
}

func (store *memoryHeldInvocationStore) Claim(_ context.Context, id string, token resource.HeldAuthToken) (resource.HeldClaim, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if id != "held-four-party-0123456789abcdef" || store.state == "" {
		return resource.HeldClaim{}, resource.ErrHeldInvocationNotFound
	}
	store.claims++
	switch store.state {
	case "pending":
		if !token.PresentedAt.Before(store.invocation.CompletionUntil) {
			store.state = "expired"
			return resource.HeldClaim{}, resource.ErrHeldInvocationExpired
		}
		store.state = "executing"
		store.token = token
		return resource.NewHeldExecution(resource.HeldExecution{InvocationID: id, Fence: "held-four-party-fence"}), nil
	case "executing":
		return resource.HeldClaim{}, resource.ErrHeldInvocationConflict
	case "complete":
		if store.token.SHA256 != token.SHA256 {
			return resource.HeldClaim{}, resource.ErrHeldAuthTokenMismatch
		}
		return resource.NewHeldReplay(store.response), nil
	case "expired":
		return resource.HeldClaim{}, resource.ErrHeldInvocationExpired
	default:
		return resource.HeldClaim{}, resource.ErrHeldExecutionUnresolved
	}
}

func (store *memoryHeldInvocationStore) Retain(_ context.Context, execution resource.HeldExecution, response resource.HeldResponse) (resource.HeldResponse, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.state != "executing" || execution != (resource.HeldExecution{
		InvocationID: "held-four-party-0123456789abcdef",
		Fence:        "held-four-party-fence",
	}) {
		return resource.HeldResponse{}, resource.ErrHeldCompletionStale
	}
	store.response = cloneHeldResponse(response)
	store.state = "complete"
	store.retains++
	return cloneHeldResponse(store.response), nil
}

func (store *memoryHeldInvocationStore) observation() (claims, retains int) {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.claims, store.retains
}

func cloneHeldInvocation(invocation resource.HeldInvocation) resource.HeldInvocation {
	invocation.Header = invocation.Header.Clone()
	invocation.Body = append([]byte(nil), invocation.Body...)
	invocation.RequiredScopes = append([]string(nil), invocation.RequiredScopes...)
	if invocation.R3PerCall != nil {
		cloned := *invocation.R3PerCall
		cloned.ExactProposal = append([]byte(nil), invocation.R3PerCall.ExactProposal...)
		invocation.R3PerCall = &cloned
	}
	return invocation
}

func cloneHeldResponse(response resource.HeldResponse) resource.HeldResponse {
	response.Header = response.Header.Clone()
	response.Body = append([]byte(nil), response.Body...)
	response.Trailer = response.Trailer.Clone()
	return response
}

var _ resource.HeldInvocationStore = (*memoryHeldInvocationStore)(nil)

type logicalTransport struct {
	mu     sync.RWMutex
	routes map[string]http.Handler
}

func newLogicalTransport() *logicalTransport {
	return &logicalTransport{routes: make(map[string]http.Handler)}
}

func (transport *logicalTransport) Handle(origin string, handler http.Handler) {
	transport.mu.Lock()
	defer transport.mu.Unlock()
	transport.routes[origin] = handler
}

func (transport *logicalTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if request.Body != nil {
		defer request.Body.Close()
	}
	origin := request.URL.Scheme + "://" + request.URL.Host
	transport.mu.RLock()
	handler := transport.routes[origin]
	transport.mu.RUnlock()
	if handler == nil {
		return nil, errors.New("logical transport has no handler for " + origin)
	}
	if _, err := url.ParseRequestURI(request.URL.RequestURI()); err != nil {
		return nil, err
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	response := recorder.Result()
	response.Request = request
	return response, nil
}
