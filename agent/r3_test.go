package agent_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/agent"
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/r3"
	"gitlab.com/sidecat-dev/aauth-go/r3/vocab/mcp"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

func TestClientR3AuthorizesAndExchangesScopelessClassAuthorization(t *testing.T) {
	t.Parallel()

	fixture := newR3ExchangeFixture(t)
	gotResourceToken, err := fixture.client.Authorize(context.Background(), agent.AuthorizeRequest{
		Resource: "https://resource.example", PersonToken: fixture.personToken,
		Account: &fixture.account, R3Operations: &fixture.operations,
	})
	if err != nil {
		t.Fatal(err)
	}
	authorizeInput := fixture.authorizeInput
	parsedOperations, parseErr := fixture.registry.ParseOperationSet(authorizeInput.R3Operations)
	operationsEqual, equalErr := parsedOperations.Equal(fixture.operations)
	if gotResourceToken != fixture.resourceToken || authorizeInput.Scope != nil || authorizeInput.Account == nil ||
		*authorizeInput.Account != fixture.account || len(authorizeInput.R3Operations) == 0 ||
		parseErr != nil || equalErr != nil || !operationsEqual {
		t.Fatalf("authorize input/output = %#v / %t", authorizeInput, gotResourceToken == fixture.resourceToken)
	}
	gotAuthToken, err := fixture.client.Exchange(context.Background(), agent.ExchangeRequest{
		PersonServer: "https://person.example", ResourceToken: gotResourceToken, PresentedToken: fixture.personToken,
	})
	if err != nil {
		t.Fatal(err)
	}
	if gotAuthToken != fixture.authToken {
		t.Fatalf("auth token changed")
	}
	claims, gotReference, gotAuthorization, err := r3.VerifyAuthTokenClaims(
		context.Background(), fixture.registry, gotAuthToken, fixture.resolver, fixture.clock,
	)
	grantedEqual, grantedErr := gotAuthorization.GrantedOperations().Equal(fixture.granted)
	perCallEqual, perCallErr := gotAuthorization.PerCallOperations().Equal(fixture.perCall)
	if err != nil || claims.Scope != "" || gotReference != fixture.reference ||
		grantedErr != nil || !grantedEqual || perCallErr != nil || !perCallEqual {
		t.Fatalf("verified auth = %#v %#v %#v, %v", claims, gotReference, gotAuthorization, err)
	}
}

// A Person Server may defer an R3 exchange like any other. The pending
// exchange keeps the R3 document reference, and the auth token its poll
// delivers is verified against it.
func TestClientR3PendingExchangePollsForTheR3AuthToken(t *testing.T) {
	t.Parallel()

	fixture := newR3ExchangeFixture(t)
	polls := 0
	fixture.token = func(request *http.Request) *http.Response {
		response := &http.Response{
			StatusCode: http.StatusAccepted, Request: request,
			Header: http.Header{
				"Content-Type": []string{"application/json"}, "Location": []string{"/pending/r3"},
				"Retry-After": []string{"0"}, "Cache-Control": []string{"no-store"},
			},
			Body: io.NopCloser(strings.NewReader(`{"status":"pending"}`)),
		}
		return response
	}
	fixture.pending = func(request *http.Request) *http.Response {
		polls++
		body, _ := json.Marshal(map[string]any{"auth_token": fixture.authToken, "expires_in": 1800})
		return &http.Response{
			StatusCode: http.StatusOK, Request: request,
			Header: http.Header{"Content-Type": []string{"application/json"}},
			Body:   io.NopCloser(bytes.NewReader(body)),
		}
	}
	result, err := fixture.client.BeginExchange(context.Background(), agent.ExchangeRequest{
		PersonServer: "https://person.example", ResourceToken: fixture.resourceToken, PresentedToken: fixture.personToken,
	})
	if err != nil {
		t.Fatal(err)
	}
	pending, ok := result.Pending()
	if !ok || pending.Location() != "https://person.example/pending/r3" {
		t.Fatalf("R3 exchange = %#v", result)
	}
	if _, err := pending.Snapshot(); err == nil {
		t.Fatal("an R3 pending exchange was snapshotted without its document reference")
	}
	polled, err := fixture.client.PollExchange(context.Background(), pending)
	if err != nil {
		t.Fatal(err)
	}
	if token, ok := polled.Token(); !ok || token != fixture.authToken || polls != 1 {
		t.Fatalf("R3 poll = %#v, polls = %d", polled, polls)
	}

	_, err = fixture.client.Exchange(context.Background(), agent.ExchangeRequest{
		PersonServer: "https://person.example", ResourceToken: fixture.resourceToken, PresentedToken: fixture.personToken,
	})
	var deferred *agent.PendingExchangeError
	if !errors.As(err, &deferred) || deferred.Pending().Location() != pending.Location() {
		t.Fatalf("immediate R3 exchange error = %v", err)
	}
}

type r3ExchangeFixture struct {
	now            time.Time
	clock          aauth.Clock
	registry       r3.Registry
	resolver       signaturekey.StaticKeyResolver
	client         *agent.Client
	personToken    string
	resourceToken  string
	authToken      string
	account        string
	operations     r3.OperationSet
	reference      r3.Reference
	granted        r3.GrantedOperations
	perCall        r3.GrantedOperations
	authorizeInput struct {
		Scope        *string         `json:"scope"`
		Account      *string         `json:"account"`
		R3Operations json.RawMessage `json:"r3_operations"`
	}
	// token answers the PS token request; nil answers the auth token.
	token func(*http.Request) *http.Response
	// pending answers requests to the PS pending URL.
	pending func(*http.Request) *http.Response
}

func newR3ExchangeFixture(t *testing.T) *r3ExchangeFixture {
	t.Helper()
	fixture := &r3ExchangeFixture{now: time.Date(2026, 8, 31, 11, 0, 0, 0, time.UTC)}
	fixture.clock = aauth.ClockFunc(func() time.Time { return fixture.now })
	now := fixture.now
	fixture.registry = newAgentR3Registry(t)
	providerKey := agentR3Key(t, "provider-key", 1)
	personKey := agentR3Key(t, "person-key", 2)
	resourceKey := agentR3Key(t, "resource-key", 3)
	accessKey := agentR3Key(t, "access-key", 4)
	agentKey := agentR3Key(t, "agent-key", 5)
	fixture.resolver = signaturekey.StaticKeyResolver{
		{Issuer: "https://provider.example", DiscoveryDocument: aauth.AgentDiscoveryDocument, KeyID: providerKey.ID()}:    providerKey.PublicJWK(),
		{Issuer: "https://person.example", DiscoveryDocument: aauth.PersonDiscoveryDocument, KeyID: personKey.ID()}:       personKey.PublicJWK(),
		{Issuer: "https://resource.example", DiscoveryDocument: aauth.ResourceDiscoveryDocument, KeyID: resourceKey.ID()}: resourceKey.PublicJWK(),
		{Issuer: "https://access.example", DiscoveryDocument: aauth.AccessDiscoveryDocument, KeyID: accessKey.ID()}:       accessKey.PublicJWK(),
	}
	agentToken, err := aauth.MintAgentToken(
		"https://provider.example", providerKey,
		aauth.AgentTokenRequest{
			Agent: "aauth:planner@provider.example", PersonServer: "https://person.example",
			PublicKey: agentKey.PublicJWK(), Lifetime: time.Hour,
		}, now, "agent-token-1",
	)
	if err != nil {
		t.Fatal(err)
	}
	fixture.personToken, err = aauth.MintPersonToken(personKey, aauth.PersonTokenClaims{
		Issuer: "https://person.example", DWK: aauth.PersonDiscoveryDocument,
		Audience: "https://resource.example", Subject: "person-123", JTI: "person-token-1",
		Confirmation: aauth.Confirmation{JWK: agentKey.PublicJWK()},
		IssuedAt:     now.Unix(), ExpiresAt: now.Add(time.Hour).Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	agentJKT, _ := agentKey.PublicJWK().Thumbprint()
	fixture.account = "work-account"
	read := newAgentMCPOperation(t, "records.read")
	export := newAgentMCPOperation(t, "records.export")
	fixture.operations = newAgentMCPOperationSet(t, read, export)
	document, _ := r3.NewDocument(fixture.operations, r3.DocumentOptions{Account: &fixture.account})
	exactDocument, _ := json.Marshal(document)
	fixture.reference, _ = r3.NewReference("https://resource.example/r3/document", r3.Digest(exactDocument))
	fixture.resourceToken, _, err = r3.MintResourceToken(fixture.registry, resourceKey, aauth.ResourceTokenClaims{
		Issuer: "https://resource.example", DWK: aauth.ResourceDiscoveryDocument,
		Audience: "https://access.example", JTI: "resource-token-1", AgentJKT: agentJKT,
		IssuedAt: now.Unix(), ExpiresAt: now.Add(5 * time.Minute).Unix(),
		PersonServer: "https://person.example", Subject: "person-123", PresentedJTI: "person-token-1",
		Account: &fixture.account,
	}, fixture.reference.URI(), exactDocument)
	if err != nil {
		t.Fatal(err)
	}
	fixture.granted, _ = r3.NewGrantedOperations(mcp.Vocabulary(), read)
	fixture.perCall, _ = r3.NewGrantedOperations(mcp.Vocabulary(), export)
	authorization, _ := r3.NewAuthorization(fixture.granted, fixture.perCall, document)
	fixture.authToken, err = r3.MintAuthToken(fixture.registry, accessKey, aauth.AuthTokenClaims{
		Issuer: "https://access.example", DWK: aauth.AccessDiscoveryDocument,
		Audience: "https://resource.example", JTI: "auth-token-1",
		PersonServer: "https://person.example", Subject: "person-123", Account: &fixture.account,
		Confirmation: aauth.Confirmation{JWK: agentKey.PublicJWK()},
		IssuedAt:     now.Unix(), ExpiresAt: now.Add(30 * time.Minute).Unix(),
	}, fixture.reference, exactDocument, authorization)
	if err != nil {
		t.Fatal(err)
	}
	transport := agentR3RoundTripper(func(request *http.Request) (*http.Response, error) {
		var responseBody []byte
		switch request.URL.String() {
		case "https://resource.example/.well-known/aauth-resource.json":
			responseBody = []byte(`{"issuer":"https://resource.example","authorization_endpoint":"https://resource.example/authorize","r3_vocabularies":{"urn:aauth:vocabulary:mcp":"https://resource.example/mcp"}}`)
		case "https://resource.example/authorize":
			if err := json.NewDecoder(request.Body).Decode(&fixture.authorizeInput); err != nil {
				t.Fatal(err)
			}
			responseBody, _ = json.Marshal(map[string]string{"resource_token": fixture.resourceToken})
		case "https://person.example/.well-known/aauth-person.json":
			responseBody = []byte(`{"issuer":"https://person.example","person_token_endpoint":"https://person.example/person","auth_token_endpoint":"https://person.example/token","jwks_uri":"https://person.example/jwks"}`)
		case "https://person.example/token":
			var input struct {
				ResourceToken string `json:"resource_token"`
			}
			if err := json.NewDecoder(request.Body).Decode(&input); err != nil {
				t.Fatal(err)
			}
			if input.ResourceToken != fixture.resourceToken {
				t.Fatalf("exchange resource token changed")
			}
			if fixture.token != nil {
				return fixture.token(request), nil
			}
			responseBody, _ = json.Marshal(map[string]any{"auth_token": fixture.authToken, "expires_in": 1800})
		case "https://person.example/pending/r3":
			if fixture.pending == nil {
				t.Fatalf("unexpected poll %s", request.URL)
			}
			return fixture.pending(request), nil
		default:
			t.Fatalf("unexpected request %s", request.URL)
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body:       io.NopCloser(bytes.NewReader(responseBody)), Request: request,
		}, nil
	})
	fixture.client, err = agent.New(context.Background(), agent.Config{
		Identifier: "aauth:planner@provider.example", SigningKey: agentKey,
		AgentToken: agentToken, KeyResolver: fixture.resolver,
		HTTPClient: &http.Client{Transport: transport}, Clock: fixture.clock,
		R3: &agent.R3Config{Registry: fixture.registry},
	})
	if err != nil {
		t.Fatal(err)
	}
	return fixture
}

func TestClientUsesTheRegisteredVocabularyDiscoveryEndpointRule(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 31, 15, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	providerKey := agentR3Key(t, "provider-key", 11)
	personKey := agentR3Key(t, "person-key", 12)
	agentKey := agentR3Key(t, "agent-key", 13)
	resolver := signaturekey.StaticKeyResolver{
		{Issuer: "https://provider.example", DiscoveryDocument: aauth.AgentDiscoveryDocument, KeyID: providerKey.ID()}: providerKey.PublicJWK(),
		{Issuer: "https://person.example", DiscoveryDocument: aauth.PersonDiscoveryDocument, KeyID: personKey.ID()}:    personKey.PublicJWK(),
	}
	agentToken, err := aauth.MintAgentToken(
		"https://provider.example", providerKey,
		aauth.AgentTokenRequest{
			Agent: "aauth:planner@provider.example", PersonServer: "https://person.example",
			PublicKey: agentKey.PublicJWK(), Lifetime: time.Hour,
		}, now, "agent-token-discovery",
	)
	if err != nil {
		t.Fatal(err)
	}
	personToken, err := aauth.MintPersonToken(personKey, aauth.PersonTokenClaims{
		Issuer: "https://person.example", DWK: aauth.PersonDiscoveryDocument,
		Audience: "https://resource.example", Subject: "person-123", JTI: "person-token-discovery",
		Confirmation: aauth.Confirmation{JWK: agentKey.PublicJWK()},
		IssuedAt:     now.Unix(), ExpiresAt: now.Add(time.Hour).Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	var validatedEndpoint string
	vocabulary, err := r3.NewVocabulary(agentDiscoveryCodec{seen: &validatedEndpoint})
	if err != nil {
		t.Fatal(err)
	}
	registry, err := r3.NewRegistry(vocabulary)
	if err != nil {
		t.Fatal(err)
	}
	operation, err := r3.NewOperation(vocabulary, json.RawMessage(`{"name":"records.read"}`))
	if err != nil {
		t.Fatal(err)
	}
	operations, err := r3.NewOperationSet(operation)
	if err != nil {
		t.Fatal(err)
	}

	const discoveryEndpoint = "custom+unix:///run/resource.sock?definition=current"
	authorizeCalls := 0
	transportCalls := 0
	transport := agentR3RoundTripper(func(request *http.Request) (*http.Response, error) {
		transportCalls++
		var status = http.StatusOK
		var responseBody []byte
		switch request.URL.String() {
		case "https://resource.example/.well-known/aauth-resource.json":
			responseBody = []byte(`{"issuer":"https://resource.example","authorization_endpoint":"https://resource.example/authorize","r3_vocabularies":{"urn:example:vocabulary:custom-discovery":"` + discoveryEndpoint + `"}}`)
		case "https://resource.example/authorize":
			authorizeCalls++
			status = http.StatusInternalServerError
			responseBody = []byte(`{"type":"about:blank","title":"expected test stop","status":500}`)
		default:
			t.Fatalf("unexpected request %s", request.URL)
		}
		return &http.Response{
			StatusCode: status,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body:       io.NopCloser(bytes.NewReader(responseBody)), Request: request,
		}, nil
	})
	client, err := agent.New(context.Background(), agent.Config{
		Identifier: "aauth:planner@provider.example", SigningKey: agentKey,
		AgentToken: agentToken, KeyResolver: resolver,
		HTTPClient: &http.Client{Transport: transport}, Clock: clock,
		R3: &agent.R3Config{Registry: registry},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Authorize(context.Background(), agent.AuthorizeRequest{
		Resource: "https://resource.example", PersonToken: personToken, R3Operations: &operations,
	}); err == nil {
		t.Fatal("authorization unexpectedly succeeded at the deliberate test stop")
	}
	if validatedEndpoint != discoveryEndpoint {
		t.Fatalf("codec validated endpoint %q, want %q", validatedEndpoint, discoveryEndpoint)
	}
	if authorizeCalls != 1 {
		t.Fatalf("authorization endpoint calls = %d, want 1 after custom discovery validation", authorizeCalls)
	}

	foreignVocabulary, err := r3.NewVocabulary(agentDiscoveryCodec{})
	if err != nil {
		t.Fatal(err)
	}
	foreignOperation, err := r3.NewOperation(foreignVocabulary, json.RawMessage(`{"name":"records.read"}`))
	if err != nil {
		t.Fatal(err)
	}
	foreignOperations, err := r3.NewOperationSet(foreignOperation)
	if err != nil {
		t.Fatal(err)
	}
	callsBeforeForeign := transportCalls
	if _, err := client.Authorize(context.Background(), agent.AuthorizeRequest{
		Resource: "https://resource.example", PersonToken: personToken, R3Operations: &foreignOperations,
	}); err == nil || !strings.Contains(err.Error(), "different registration") {
		t.Fatalf("foreign same-URI registration error = %v", err)
	}
	if transportCalls != callsBeforeForeign {
		t.Fatalf("foreign registration performed %d network calls", transportCalls-callsBeforeForeign)
	}
}

type agentDiscoveryCodec struct{ seen *string }

type agentDiscoverySet []string

func (agentDiscoveryCodec) URI() r3.VocabularyURI {
	return "urn:example:vocabulary:custom-discovery"
}

func (agentDiscoveryCodec) AnnotationEncoding() r3.AnnotationEncoding {
	return r3.AnnotationUnavailable
}

func (codec agentDiscoveryCodec) ValidateDiscoveryEndpoint(endpoint string) error {
	if codec.seen != nil {
		*codec.seen = endpoint
	}
	if !strings.HasPrefix(endpoint, "custom+unix:///") {
		return errors.New("custom discovery endpoint must use custom+unix")
	}
	return nil
}

func (agentDiscoveryCodec) ParseSet(raw []json.RawMessage) (agentDiscoverySet, error) {
	set := make(agentDiscoverySet, 0, len(raw))
	for _, encoded := range raw {
		var operation struct {
			Name string `json:"name"`
		}
		if err := json.Unmarshal(encoded, &operation); err != nil || operation.Name == "" || slices.Contains(set, operation.Name) {
			return nil, errors.New("invalid custom operation")
		}
		set = append(set, operation.Name)
	}
	return set, nil
}

func (agentDiscoveryCodec) MarshalSet(set agentDiscoverySet) ([]json.RawMessage, error) {
	raw := make([]json.RawMessage, len(set))
	for index, name := range set {
		encoded, err := json.Marshal(struct {
			Name string `json:"name"`
		}{Name: name})
		if err != nil {
			return nil, err
		}
		raw[index] = encoded
	}
	return raw, nil
}

func (agentDiscoveryCodec) Union(sets ...agentDiscoverySet) (agentDiscoverySet, error) {
	var union agentDiscoverySet
	for _, set := range sets {
		for _, name := range set {
			if !slices.Contains(union, name) {
				union = append(union, name)
			}
		}
	}
	return union, nil
}

func (agentDiscoveryCodec) Equal(left, right agentDiscoverySet) bool {
	return len(left) == len(right) && agentDiscoverySubset(left, right)
}

func (agentDiscoveryCodec) Subset(subset, superset agentDiscoverySet) bool {
	return agentDiscoverySubset(subset, superset)
}

func (agentDiscoveryCodec) Disjoint(left, right agentDiscoverySet) bool {
	for _, name := range left {
		if slices.Contains(right, name) {
			return false
		}
	}
	return true
}

func agentDiscoverySubset(subset, superset agentDiscoverySet) bool {
	for _, name := range subset {
		if !slices.Contains(superset, name) {
			return false
		}
	}
	return true
}

func newAgentR3Registry(t *testing.T) r3.Registry {
	t.Helper()
	registry, err := r3.NewRegistry(mcp.Vocabulary())
	if err != nil {
		t.Fatal(err)
	}
	return registry
}

func newAgentMCPOperation(t *testing.T, tool string) r3.Operation {
	t.Helper()
	typed, err := mcp.NewOperation(tool)
	if err != nil {
		t.Fatal(err)
	}
	operation, err := typed.ToR3()
	if err != nil {
		t.Fatal(err)
	}
	return operation
}

func newAgentMCPOperationSet(t *testing.T, operations ...r3.Operation) r3.OperationSet {
	t.Helper()
	set, err := r3.NewOperationSet(operations...)
	if err != nil {
		t.Fatal(err)
	}
	return set
}

func agentR3Key(t *testing.T, id string, fill byte) jose.SigningKey {
	t.Helper()
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{fill}, ed25519.SeedSize))
	key, err := jose.NewEd25519SigningKey(id, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

type agentR3RoundTripper func(*http.Request) (*http.Response, error)

func (roundTrip agentR3RoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	return roundTrip(request)
}
