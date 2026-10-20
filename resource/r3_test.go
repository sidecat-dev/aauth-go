package resource

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/r3"
	"gitlab.com/sidecat-dev/aauth-go/r3/vocab/mcp"
	"gitlab.com/sidecat-dev/aauth-go/r3/vocab/openapi"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

func newResourceR3Registry(t *testing.T) r3.Registry {
	t.Helper()
	registry, err := resourceMCPRegistry()
	if err != nil {
		t.Fatal(err)
	}
	return registry
}

func newResourceR3DefinitionRegistry(t *testing.T) r3.DefinitionRegistry {
	t.Helper()
	registry, err := r3.NewDefinitionRegistry(mcp.DefinitionRegistration())
	if err != nil {
		t.Fatal(err)
	}
	return registry
}

func resourceMCPRegistry() (r3.Registry, error) {
	return r3.NewRegistry(mcp.Vocabulary())
}

func newResourceMCPOperation(t *testing.T, tool string) r3.Operation {
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

func newResourceMCPOperationSet(t *testing.T, tools ...string) r3.OperationSet {
	t.Helper()
	typed := make([]mcp.Operation, len(tools))
	for index, tool := range tools {
		operation, err := mcp.NewOperation(tool)
		if err != nil {
			t.Fatal(err)
		}
		typed[index] = operation
	}
	set, err := mcp.NewOperationSet(typed...)
	if err != nil {
		t.Fatal(err)
	}
	return set
}

func newResourceMCPDefinition(t *testing.T, tools ...string) r3.AuthoritativeSnapshot {
	t.Helper()
	defined := make([]map[string]any, len(tools))
	for index, tool := range tools {
		defined[index] = map[string]any{"name": tool, "inputSchema": map[string]any{"type": "object"}}
	}
	body, err := json.Marshal(map[string]any{"tools": defined})
	if err != nil {
		t.Fatal(err)
	}
	return newResourceMCPDefinitionFromBody(t, body)
}

func newResourceMCPDefinitionFromBody(t *testing.T, body []byte) r3.AuthoritativeSnapshot {
	t.Helper()
	source := mcp.NewToolsListSnapshot(mcp.NewInitialToolsListPage(body))
	snapshot, err := mcp.ParseDefinition("https://resource.example/mcp", source)
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func newResourceOpenAPIDefinition(t *testing.T) r3.AuthoritativeSnapshot {
	t.Helper()
	snapshot, err := openapi.ParseDefinition(
		"https://resource.example/openapi.json",
		openapi.NewDocumentSource([]byte(`{"openapi":"3.1.0","info":{"title":"records","version":"1"},"paths":{"/read":{"get":{"operationId":"records.read","responses":{"204":{"description":"ok"}}}}}}`)),
	)
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}

type resourceMCPRequestMapper func(*http.Request) (string, bool, error)

func newResourceMCPConfig(
	t *testing.T,
	documents R3DocumentStore,
	knownTools []string,
	mapper resourceMCPRequestMapper,
) *R3Config {
	t.Helper()
	config := &R3Config{
		Registry:    newResourceR3Registry(t),
		Definitions: newResourceR3DefinitionRegistry(t),
		Vocabularies: []R3VocabularyConfig{{
			Definition: newResourceMCPDefinition(t, knownTools...),
		}},
		Documents: documents,
	}
	if mapper != nil {
		config.HTTP.OperationForRequest = func(request *http.Request) (r3.Operation, bool, error) {
			tool, ok, err := mapper(request)
			if err != nil || !ok {
				return r3.Operation{}, ok, err
			}
			typed, err := mcp.NewOperation(tool)
			if err != nil {
				return r3.Operation{}, false, err
			}
			operation, err := typed.ToR3()
			return operation, err == nil, err
		}
	}
	return config
}

func resourceMCPTool(t *testing.T, operation r3.Operation) string {
	t.Helper()
	typed, err := mcp.FromR3(operation)
	if err != nil {
		t.Fatal(err)
	}
	return typed.Tool()
}

func equalResourceR3Operations(t *testing.T, first, second r3.Operation) bool {
	t.Helper()
	equal, err := first.Equal(second)
	if err != nil {
		t.Fatal(err)
	}
	return equal
}

func TestR3ResourceMetadataAdvertisesVocabularyAndValidatesConfiguration(t *testing.T) {
	t.Parallel()

	validR3 := func(t *testing.T) *R3Config {
		t.Helper()
		return newResourceMCPConfig(
			t,
			&r3TestDocumentStore{},
			[]string{"records.read", "records.export"},
			func(*http.Request) (string, bool, error) {
				return "records.read", true, nil
			},
		)
	}
	foreignDefinition := newResourceOpenAPIDefinition(t)
	conflictingHints := newResourceMCPDefinitionFromBody(t, []byte(
		`{"tools":[{"name":"records.read","inputSchema":{"type":"object"},"_meta":{"aauth.dev/access-mode":"person-token","aauth.dev/budget":true}}]}`,
	))

	for _, test := range []struct {
		name   string
		change func(*R3Config)
	}{
		{name: "missing registry", change: func(config *R3Config) { config.Registry = r3.Registry{} }},
		{name: "missing definition registry", change: func(config *R3Config) { config.Definitions = r3.DefinitionRegistry{} }},
		{name: "missing vocabularies", change: func(config *R3Config) { config.Vocabularies = nil }},
		{name: "missing definition", change: func(config *R3Config) {
			config.Vocabularies[0].Definition = r3.AuthoritativeSnapshot{}
		}},
		{name: "unregistered vocabulary", change: func(config *R3Config) {
			config.Vocabularies[0].Definition = foreignDefinition
		}},
		{name: "duplicate vocabulary", change: func(config *R3Config) {
			config.Vocabularies = append(config.Vocabularies, config.Vocabularies[0])
		}},
		{name: "publisher-conflicting hints", change: func(config *R3Config) {
			config.Vocabularies[0].Definition = conflictingHints
		}},
		{name: "missing document store", change: func(config *R3Config) { config.Documents = nil }},
		{name: "missing invocation adapter", change: func(config *R3Config) { config.HTTP = R3HTTPAdapter{} }},
	} {
		t.Run(test.name, func(t *testing.T) {
			config := validConfig(t, http.NotFoundHandler())
			config.R3 = validR3(t)
			test.change(config.R3)
			if _, err := NewFederatedAuthorization(config); err == nil {
				t.Fatal("NewFederatedAuthorization accepted incomplete R3 configuration")
			}
		})
	}
	if _, err := mcp.NewOperation(" records.read"); err == nil {
		t.Fatal("MCP operation constructor accepted an untrimmed tool")
	}
	duplicate := newResourceMCPOperation(t, "records.read")
	if _, err := r3.NewOperationSet(duplicate, duplicate); err == nil {
		t.Fatal("MCP operation set accepted a duplicate tool")
	}

	config := validConfig(t, http.NotFoundHandler())
	config.R3 = validR3(t)
	server, err := NewFederatedAuthorization(config)
	if err != nil {
		t.Fatal(err)
	}
	originalOperations := newResourceMCPOperationSet(t, "records.read", "records.export")
	config.R3.Vocabularies[0].Definition = newResourceMCPDefinition(t, "records.delete")
	got := server.r3.vocabularies[mcp.URI].definition.Operations()
	equal, equalErr := got.Equal(originalOperations)
	if equalErr != nil || !equal {
		t.Fatalf("retained authoritative operations = %#v, error = %v", got.Operations(), equalErr)
	}

	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, resourceIssuer+"/.well-known/aauth-resource.json", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("metadata status = %d, body = %s", response.Code, response.Body.String())
	}
	var metadata struct {
		R3Vocabularies map[string]string `json:"r3_vocabularies"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &metadata); err != nil {
		t.Fatal(err)
	}
	if len(metadata.R3Vocabularies) != 1 || metadata.R3Vocabularies[string(mcp.URI)] != "https://resource.example/mcp" {
		t.Fatalf("r3_vocabularies = %#v", metadata.R3Vocabularies)
	}
}

func TestPSAuthorizationWithoutR3RemainsCoreOnly(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	personKey := testSigningKey(t, "PS-core-only-person", 151)
	resourceKey := testSigningKey(t, "PS-core-only-resource", 152)
	agentKey := testSigningKey(t, "PS-core-only-agent", 153)
	resolver := signaturekey.StaticKeyResolver{
		{Issuer: personIssuer, DiscoveryDocument: aauth.PersonDiscoveryDocument, KeyID: personKey.ID()}:       personKey.PublicJWK(),
		{Issuer: resourceIssuer, DiscoveryDocument: aauth.ResourceDiscoveryDocument, KeyID: resourceKey.ID()}: resourceKey.PublicJWK(),
	}
	server, err := NewPSAuthorization(PSAuthorizationConfig{
		Issuer: resourceIssuer, SigningKey: resourceKey, KeyResolver: resolver, Clock: clock,
		NewID:             func() string { return "PS-core-only-resource-token" },
		ScopeDescriptions: map[string]string{"records.read": "Read records"},
		RequiredScopes:    func(*http.Request) []string { return []string{"records.read"} },
		ResolvePerson:     func(context.Context, PersonIdentity, PersonContext) error { return nil },
		Protected:         http.NotFoundHandler(),
	})
	if err != nil {
		t.Fatal(err)
	}

	metadataResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(
		metadataResponse,
		httptest.NewRequest(http.MethodGet, resourceIssuer+"/.well-known/aauth-resource.json", nil),
	)
	var metadata map[string]json.RawMessage
	if metadataResponse.Code != http.StatusOK || json.Unmarshal(metadataResponse.Body.Bytes(), &metadata) != nil {
		t.Fatalf("Core-only metadata = %d %s", metadataResponse.Code, metadataResponse.Body.String())
	}
	if _, present := metadata["r3_vocabularies"]; present {
		t.Fatalf("Core-only metadata advertised R3: %s", metadataResponse.Body.String())
	}

	personToken := mintPersonToken(t, personKey, agentKey.PublicJWK(), now, resourceIssuer, "PS-core-only-person-token")
	coreResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(
		coreResponse,
		signedRequest(
			t, clock, agentKey, personToken, http.MethodPost, resourceIssuer+"/authorize",
			`{"scope":"records.read"}`,
		),
	)
	var authorization struct {
		ResourceToken string `json:"resource_token"`
	}
	if coreResponse.Code != http.StatusOK || json.Unmarshal(coreResponse.Body.Bytes(), &authorization) != nil || authorization.ResourceToken == "" {
		t.Fatalf("Core-only authorization = %d %s", coreResponse.Code, coreResponse.Body.String())
	}
	claims, err := aauth.VerifyResourceToken(context.Background(), authorization.ResourceToken, resolver, clock)
	if err != nil {
		t.Fatal(err)
	}
	if claims.Audience != personIssuer || claims.Scope != "records.read" || len(claims.AdditionalClaims) != 0 {
		t.Fatalf("Core-only Resource token = %#v", claims)
	}

	r3Response := httptest.NewRecorder()
	server.Handler().ServeHTTP(
		r3Response,
		signedRequest(
			t, clock, agentKey, personToken, http.MethodPost, resourceIssuer+"/authorize",
			`{"r3_operations":{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"records.read"}]}}`,
		),
	)
	if r3Response.Code != http.StatusBadRequest || !strings.Contains(r3Response.Body.String(), `"error":"invalid_request"`) {
		t.Fatalf("Core-only R3 request = %d %s", r3Response.Code, r3Response.Body.String())
	}
}

func TestPSAuthorizationAcceptsClassR3AndEnforcesPersonServerGrant(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 31, 12, 30, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	personKey := testSigningKey(t, "PS-class-R3-person", 154)
	resourceKey := testSigningKey(t, "PS-class-R3-resource", 155)
	agentKey := testSigningKey(t, "PS-class-R3-agent", 156)
	resolver := signaturekey.StaticKeyResolver{
		{Issuer: personIssuer, DiscoveryDocument: aauth.PersonDiscoveryDocument, KeyID: personKey.ID()}:       personKey.PublicJWK(),
		{Issuer: resourceIssuer, DiscoveryDocument: aauth.ResourceDiscoveryDocument, KeyID: resourceKey.ID()}: resourceKey.PublicJWK(),
	}
	documents := &r3TestDocumentStore{}
	classR3 := newResourceMCPConfig(
		t,
		documents,
		[]string{"records.read", "records.export"},
		func(request *http.Request) (string, bool, error) {
			switch request.URL.Path {
			case "/records":
				return "records.read", true, nil
			case "/exports":
				return "records.export", true, nil
			default:
				return "", false, nil
			}
		},
	)
	registry := classR3.Registry
	resolveCalls := 0
	protectedCalls := 0
	server, err := NewPSAuthorization(PSAuthorizationConfig{
		Issuer: resourceIssuer, SigningKey: resourceKey, KeyResolver: resolver, Clock: clock,
		NewID:             func() string { return "PS-class-R3-resource-token" },
		ScopeDescriptions: map[string]string{"records.read": "Read records"},
		RequiredScopes:    func(*http.Request) []string { return []string{"records.read"} },
		ResolvePerson: func(_ context.Context, identity PersonIdentity, personContext PersonContext) error {
			resolveCalls++
			if identity != (PersonIdentity{Issuer: personIssuer, Subject: "person-1"}) || personContext.Tenant != "tenant-1" {
				return errors.New("unexpected PS-class R3 person context")
			}
			return nil
		},
		Protected: http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
			protectedCalls++
			response.WriteHeader(http.StatusNoContent)
		}),
		R3: classR3,
	})
	if err != nil {
		t.Fatal(err)
	}

	metadataResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(
		metadataResponse,
		httptest.NewRequest(http.MethodGet, resourceIssuer+"/.well-known/aauth-resource.json", nil),
	)
	var metadata struct {
		R3Vocabularies map[string]string `json:"r3_vocabularies"`
	}
	if metadataResponse.Code != http.StatusOK || json.Unmarshal(metadataResponse.Body.Bytes(), &metadata) != nil ||
		metadata.R3Vocabularies[string(mcp.URI)] != "https://resource.example/mcp" {
		t.Fatalf("PS-class R3 metadata = %d %s", metadataResponse.Code, metadataResponse.Body.String())
	}

	personToken := mintPersonToken(t, personKey, agentKey.PublicJWK(), now, resourceIssuer, "PS-class-R3-person-token")
	authorizeResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(
		authorizeResponse,
		signedRequest(
			t, clock, agentKey, personToken, http.MethodPost, resourceIssuer+"/authorize",
			`{"scope":"records.read","r3_operations":{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"records.read"}]}}`,
		),
	)
	var authorization struct {
		ResourceToken string `json:"resource_token"`
	}
	if authorizeResponse.Code != http.StatusOK || json.Unmarshal(authorizeResponse.Body.Bytes(), &authorization) != nil || authorization.ResourceToken == "" {
		t.Fatalf("PS-class R3 authorization = %d %s", authorizeResponse.Code, authorizeResponse.Body.String())
	}
	resourceClaims, reference, err := r3.VerifyResourceToken(
		context.Background(), authorization.ResourceToken, resolver, clock,
	)
	if err != nil {
		t.Fatal(err)
	}
	if resourceClaims.Audience != personIssuer || resourceClaims.PersonServer != personIssuer || resourceClaims.Scope != "records.read" {
		t.Fatalf("PS-class R3 Resource token = %#v", resourceClaims)
	}
	record, err := documents.Load(context.Background(), reference.URI())
	if err != nil {
		t.Fatal(err)
	}
	if record.PersonServer != personIssuer || record.AuthTokenIssuer != personIssuer ||
		record.AuthTokenIssuerDocument != aauth.PersonDiscoveryDocument ||
		record.ClassContext.ResourceToken.JTI != resourceClaims.JTI || r3.Digest(record.ExactJSON) != reference.Digest() {
		t.Fatalf("PS-class R3 retained document = %#v", record)
	}
	document, err := registry.ParseReferencedDocument(reference, record.ExactJSON)
	if err != nil {
		t.Fatal(err)
	}
	wantOperations := newResourceMCPOperationSet(t, "records.read")
	equal, err := document.OperationSet().Equal(wantOperations)
	if err != nil || !equal {
		t.Fatalf("PS-class R3 document operations = %#v, %v", document.OperationSet().Operations(), err)
	}

	fetchRequest := httptest.NewRequest(http.MethodGet, reference.URI(), nil)
	if err := signaturekey.SignJWKSURIRequest(
		fetchRequest, personKey, personIssuer, aauth.PersonDiscoveryDocument, clock,
	); err != nil {
		t.Fatal(err)
	}
	fetchResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(fetchResponse, fetchRequest)
	if fetchResponse.Code != http.StatusOK || !bytes.Equal(fetchResponse.Body.Bytes(), record.ExactJSON) {
		t.Fatalf("PS-class R3 document fetch = %d %s", fetchResponse.Code, fetchResponse.Body.String())
	}

	read := newResourceMCPOperation(t, "records.read")
	granted, err := r3.NewGrantedOperations(mcp.Vocabulary(), read)
	if err != nil {
		t.Fatal(err)
	}
	grant, err := r3.NewGrant(granted, document)
	if err != nil {
		t.Fatal(err)
	}
	authToken, err := r3.MintDirectAuthToken(registry, personKey, aauth.AuthTokenClaims{
		Issuer: personIssuer, DWK: aauth.PersonDiscoveryDocument,
		Audience: resourceIssuer, JTI: "PS-class-R3-auth-token",
		PersonServer: personIssuer, Subject: "person-1", Scope: "records.read", Tenant: "tenant-1",
		Confirmation: aauth.Confirmation{JWK: agentKey.PublicJWK()},
		IssuedAt:     now.Unix(), ExpiresAt: now.Add(time.Hour).Unix(),
	}, reference, record.ExactJSON, grant)
	if err != nil {
		t.Fatal(err)
	}
	loadsBeforeProtectedUse := documents.loadCount()
	readResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(
		readResponse,
		signedRequest(t, clock, agentKey, authToken, http.MethodGet, resourceIssuer+"/records", ""),
	)
	if readResponse.Code != http.StatusNoContent || resolveCalls != 1 || protectedCalls != 1 {
		t.Fatalf(
			"PS-class R3 granted use = %d %s; resolve=%d protected=%d",
			readResponse.Code, readResponse.Body.String(), resolveCalls, protectedCalls,
		)
	}
	exportResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(
		exportResponse,
		signedRequest(t, clock, agentKey, authToken, http.MethodGet, resourceIssuer+"/exports", ""),
	)
	if exportResponse.Code != http.StatusForbidden || resolveCalls != 1 || protectedCalls != 1 {
		t.Fatalf(
			"PS-class R3 ungranted use = %d %s; resolve=%d protected=%d",
			exportResponse.Code, exportResponse.Body.String(), resolveCalls, protectedCalls,
		)
	}
	if documents.loadCount() != loadsBeforeProtectedUse {
		t.Fatalf("PS-class R3 protected use loaded the document store")
	}
}

func TestPSAuthorizationRejectsPerCallR3Configuration(t *testing.T) {
	t.Parallel()

	classR3 := newResourceMCPConfig(
		t,
		&r3TestDocumentStore{},
		[]string{"records.delete"},
		func(*http.Request) (string, bool, error) { return "records.delete", true, nil },
	)
	classR3.HTTP.PresentParameters = func(*http.Request, r3.Operation) (map[string]r3.PresentedParameter, error) {
		return nil, nil
	}
	classR3.PerCall = &R3PerCallConfig{
		DescribeCall: func(context.Context, r3.Invocation, *string) (R3CallDescription, error) {
			return R3CallDescription{}, nil
		},
		Proposals: &r3ProposalTestStore{},
		Retries:   &r3RetryTestStore{},
	}
	_, err := NewPSAuthorization(PSAuthorizationConfig{
		Issuer: resourceIssuer, SigningKey: testSigningKey(t, "PS-per-call-resource", 157),
		KeyResolver: signaturekey.StaticKeyResolver{}, Clock: aauth.SystemClock{},
		NewID:             func() string { return "PS-per-call-resource-token" },
		ScopeDescriptions: map[string]string{"records.read": "Read records"},
		RequiredScopes:    func(*http.Request) []string { return []string{"records.read"} },
		ResolvePerson:     func(context.Context, PersonIdentity, PersonContext) error { return nil },
		Protected:         http.NotFoundHandler(),
		R3:                classR3,
	})
	if err == nil || !strings.Contains(err.Error(), "per-call") || !strings.Contains(err.Error(), "federated") {
		t.Fatalf("PS per-call R3 configuration error = %v", err)
	}
}

func TestMCPDirectAuthorizationRetainsExactRequestedDocumentBeforeToken(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 31, 1, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	resourceKey := testSigningKey(t, "resource-key", 31)
	personKey := testSigningKey(t, "person-key", 32)
	agentKey := testSigningKey(t, "agent-key", 33)
	resolver := signaturekey.StaticKeyResolver{
		{Issuer: personIssuer, DiscoveryDocument: aauth.PersonDiscoveryDocument, KeyID: personKey.ID()}:       personKey.PublicJWK(),
		{Issuer: resourceIssuer, DiscoveryDocument: aauth.ResourceDiscoveryDocument, KeyID: resourceKey.ID()}: resourceKey.PublicJWK(),
	}
	personToken := mintPersonToken(t, personKey, agentKey.PublicJWK(), now, resourceIssuer, "person-token-1")
	display, err := r3.NewDisplay(
		"Read and export records",
		"Exported records may leave the system",
		"Record contents",
		"Exported copies cannot be recalled",
	)
	if err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		name    string
		account *string
		scope   string
	}{
		{name: "account absent", scope: "records.read"},
		{name: "account present", account: testStringPointer("work-account"), scope: "records.read"},
		{name: "R3 operations replace Core scope"},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := &r3TestDocumentStore{}
			accountCalls := 0
			displayCalls := 0
			config := validConfigWithKey(resourceKey, http.NotFoundHandler())
			config.Clock = clock
			config.KeyResolver = resolver
			config.ValidateAccount = func(_ context.Context, identity PersonIdentity, account string) error {
				accountCalls++
				if identity != (PersonIdentity{Issuer: personIssuer, Subject: "person-1"}) || account != "work-account" {
					t.Fatalf("account validation = (%#v, %q)", identity, account)
				}
				return nil
			}
			config.R3 = newResourceMCPConfig(
				t,
				store,
				[]string{"records.read", "records.export", "records.delete"},
				func(*http.Request) (string, bool, error) {
					return "records.read", true, nil
				},
			)
			registry := config.R3.Registry
			config.R3.Vocabularies[0].DisplayForOperations = func(_ context.Context, operations r3.OperationSet, account *string) (*r3.Display, error) {
				displayCalls++
				wantOperations := newResourceMCPOperationSet(t, "records.read", "records.export")
				equal, equalErr := operations.Equal(wantOperations)
				if equalErr != nil || !equal || !equalR3TestStringPointers(account, test.account) {
					t.Fatalf("display input = %#v, %v", operations.Operations(), account)
				}
				return &display, nil
			}
			server, err := NewFederatedAuthorization(config)
			if err != nil {
				t.Fatal(err)
			}

			input := map[string]any{
				"r3_operations": map[string]any{
					"vocabulary": string(mcp.URI),
					"operations": []any{
						map[string]any{"tool": "records.read"},
						map[string]any{"tool": "records.export"},
					},
				},
			}
			if test.scope != "" {
				input["scope"] = test.scope
			}
			if test.account != nil {
				input["account"] = *test.account
			}
			body, err := json.Marshal(input)
			if err != nil {
				t.Fatal(err)
			}
			request := signedRequest(t, clock, agentKey, personToken, http.MethodPost, resourceIssuer+"/authorize", string(body))
			response := httptest.NewRecorder()
			server.Handler().ServeHTTP(response, request)
			if response.Code != http.StatusOK {
				t.Fatalf("authorize = %d %s", response.Code, response.Body.String())
			}
			var output struct {
				ResourceToken string `json:"resource_token"`
			}
			if err := json.Unmarshal(response.Body.Bytes(), &output); err != nil || output.ResourceToken == "" {
				t.Fatalf("authorization output = %#v, error = %v", output, err)
			}
			claims, reference, err := r3.VerifyResourceToken(context.Background(), output.ResourceToken, resolver, clock)
			if err != nil {
				t.Fatal(err)
			}
			if claims.Scope != test.scope || claims.PersonServer != personIssuer || claims.Audience != accessIssuer || !equalR3TestStringPointers(claims.Account, test.account) {
				t.Fatalf("R3 Resource claims = %#v", claims)
			}
			if got := accountCalls; got != boolInt(test.account != nil) {
				t.Fatalf("account validation calls = %d", got)
			}
			if displayCalls != 1 {
				t.Fatalf("display calls = %d", displayCalls)
			}

			record, err := store.Load(context.Background(), reference.URI())
			if err != nil {
				t.Fatal(err)
			}
			if record.Reference != reference || record.PersonServer != personIssuer || record.AuthTokenIssuer != accessIssuer ||
				record.AuthTokenIssuerDocument != aauth.AccessDiscoveryDocument ||
				record.ClassContext.ResourceToken.JTI != claims.JTI ||
				record.ClassContext.ResourceToken.PresentedJTI != claims.PresentedJTI ||
				r3.Digest(record.ExactJSON) != reference.Digest() {
				t.Fatalf("retained R3 record = %#v", record)
			}
			document, err := registry.ParseReferencedDocument(reference, record.ExactJSON)
			if err != nil {
				t.Fatal(err)
			}
			wantOperations := newResourceMCPOperationSet(t, "records.read", "records.export")
			equal, equalErr := document.OperationSet().Equal(wantOperations)
			if equalErr != nil || !equal {
				t.Fatalf("document operations = %#v", document.OperationSet().Operations())
			}
			if err := r3.ValidateDocumentAccount(document, test.account); err != nil {
				t.Fatalf("document account = %v", err)
			}
			gotDisplay, ok := document.Display()
			if !ok || gotDisplay.Summary() != display.Summary() {
				t.Fatalf("document display = %#v, %t", gotDisplay, ok)
			}
		})
	}
}

func TestMCPClassReferencesSeparateIdenticalDocumentsByPersonTokenLineage(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 31, 1, 15, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	resourceKey := testSigningKey(t, "resource-key", 131)
	personKey := testSigningKey(t, "person-key", 132)
	agentKey := testSigningKey(t, "agent-key", 133)
	resolver := signaturekey.StaticKeyResolver{
		{Issuer: personIssuer, DiscoveryDocument: aauth.PersonDiscoveryDocument, KeyID: personKey.ID()}:       personKey.PublicJWK(),
		{Issuer: resourceIssuer, DiscoveryDocument: aauth.ResourceDiscoveryDocument, KeyID: resourceKey.ID()}: resourceKey.PublicJWK(),
	}
	store := &r3TestDocumentStore{}
	ids := []string{"class-resource-token-1", "class-resource-token-2"}
	config := validConfigWithKey(resourceKey, http.NotFoundHandler())
	config.Clock = clock
	config.KeyResolver = resolver
	config.NewID = func() string {
		id := ids[0]
		ids = ids[1:]
		return id
	}
	config.R3 = newResourceMCPConfig(t, store, []string{"records.read"}, func(*http.Request) (string, bool, error) {
		return "records.read", true, nil
	})
	server, err := NewFederatedAuthorization(config)
	if err != nil {
		t.Fatal(err)
	}
	body := `{"r3_operations":{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"records.read"}]}}`

	type issued struct {
		compact   string
		claims    aauth.ResourceTokenClaims
		reference r3.Reference
	}
	issue := func(personJTI string) issued {
		personToken := mintPersonToken(t, personKey, agentKey.PublicJWK(), now, resourceIssuer, personJTI)
		request := signedRequest(t, clock, agentKey, personToken, http.MethodPost, resourceIssuer+"/authorize", body)
		response := httptest.NewRecorder()
		server.Handler().ServeHTTP(response, request)
		if response.Code != http.StatusOK {
			t.Fatalf("authorize %s = %d %s", personJTI, response.Code, response.Body.String())
		}
		var output struct {
			ResourceToken string `json:"resource_token"`
		}
		if err := json.Unmarshal(response.Body.Bytes(), &output); err != nil {
			t.Fatal(err)
		}
		claims, reference, err := r3.VerifyResourceToken(context.Background(), output.ResourceToken, resolver, clock)
		if err != nil {
			t.Fatal(err)
		}
		return issued{compact: output.ResourceToken, claims: claims, reference: reference}
	}

	first := issue("person-token-1")
	second := issue("person-token-2")
	if first.reference.URI() == second.reference.URI() {
		t.Fatalf("distinct Person-token lineages shared class URI %q", first.reference.URI())
	}
	if first.reference.Digest() != second.reference.Digest() {
		t.Fatalf("identical class bytes have digests %q and %q", first.reference.Digest(), second.reference.Digest())
	}
	if store.count() != 2 {
		t.Fatalf("retained class records = %d", store.count())
	}
	for _, want := range []issued{first, second} {
		record, err := store.Load(context.Background(), want.reference.URI())
		if err != nil {
			t.Fatal(err)
		}
		if record.ClassContext.ResourceToken.JTI != want.claims.JTI ||
			record.ClassContext.ResourceToken.PresentedJTI != want.claims.PresentedJTI {
			t.Fatalf("record %s retained wrong lineage: %#v", want.reference.URI(), record.ClassContext)
		}
	}
}

func TestMCPDirectAuthorizationRejectsInvalidOperationsBeforePublishing(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 31, 1, 30, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	resourceKey := testSigningKey(t, "resource-key", 34)
	personKey := testSigningKey(t, "person-key", 35)
	agentKey := testSigningKey(t, "agent-key", 36)
	resolver := signaturekey.StaticKeyResolver{
		{Issuer: personIssuer, DiscoveryDocument: aauth.PersonDiscoveryDocument, KeyID: personKey.ID()}: personKey.PublicJWK(),
	}
	personToken := mintPersonToken(t, personKey, agentKey.PublicJWK(), now, resourceIssuer, "person-token-1")

	for _, test := range []struct {
		name      string
		body      string
		wantError string
	}{
		{name: "unsupported vocabulary", body: `{"scope":"records.read","r3_operations":{"vocabulary":"urn:example:other","operations":[{"tool":"records.read"}]}}`},
		{name: "unknown tool", body: `{"scope":"records.read","r3_operations":{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"records.delete"}]}}`},
		{name: "missing operations", body: `{"scope":"records.read","r3_operations":{"vocabulary":"urn:aauth:vocabulary:mcp"}}`},
		{name: "null operations", body: `{"scope":"records.read","r3_operations":null}`},
		{name: "present empty scope", body: `{"scope":"","r3_operations":{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"records.read"}]}}`, wantError: "invalid_scope"},
		{name: "present null scope", body: `{"scope":null,"r3_operations":{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"records.read"}]}}`, wantError: "invalid_scope"},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := &r3TestDocumentStore{}
			idCalls := 0
			config := validConfigWithKey(resourceKey, http.NotFoundHandler())
			config.Clock = clock
			config.KeyResolver = resolver
			config.NewID = func() string {
				idCalls++
				return "resource-token-1"
			}
			config.R3 = newResourceMCPConfig(t, store, []string{"records.read"}, func(*http.Request) (string, bool, error) {
				return "records.read", true, nil
			})
			server, err := NewFederatedAuthorization(config)
			if err != nil {
				t.Fatal(err)
			}
			request := signedRequest(t, clock, agentKey, personToken, http.MethodPost, resourceIssuer+"/authorize", test.body)
			response := httptest.NewRecorder()
			server.Handler().ServeHTTP(response, request)
			wantError := test.wantError
			if wantError == "" {
				wantError = "invalid_request"
			}
			if response.Code != http.StatusBadRequest || !bytes.Contains(response.Body.Bytes(), []byte(`"error":"`+wantError+`"`)) {
				t.Fatalf("authorize = %d %s", response.Code, response.Body.String())
			}
			if idCalls != 0 || store.count() != 0 || bytes.Contains(response.Body.Bytes(), []byte("resource_token")) {
				t.Fatalf("invalid request published state: id calls=%d records=%d body=%s", idCalls, store.count(), response.Body.String())
			}
		})
	}
}

func TestMCPDirectAuthorizationWithholdsTokenAndRecoversUncertainDocumentCommit(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 31, 2, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	resourceKey := testSigningKey(t, "resource-key", 37)
	personKey := testSigningKey(t, "person-key", 38)
	agentKey := testSigningKey(t, "agent-key", 39)
	resolver := signaturekey.StaticKeyResolver{
		{Issuer: personIssuer, DiscoveryDocument: aauth.PersonDiscoveryDocument, KeyID: personKey.ID()}:       personKey.PublicJWK(),
		{Issuer: resourceIssuer, DiscoveryDocument: aauth.ResourceDiscoveryDocument, KeyID: resourceKey.ID()}: resourceKey.PublicJWK(),
	}
	personToken := mintPersonToken(t, personKey, agentKey.PublicJWK(), now, resourceIssuer, "person-token-1")
	body := `{"scope":"records.read","r3_operations":{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"records.read"}]}}`

	newServer := func(store R3DocumentStore, newID func() string) *Server {
		config := validConfigWithKey(resourceKey, http.NotFoundHandler())
		config.Clock = clock
		config.KeyResolver = resolver
		config.NewID = newID
		config.R3 = newResourceMCPConfig(t, store, []string{"records.read"}, func(*http.Request) (string, bool, error) {
			return "records.read", true, nil
		})
		server, err := NewFederatedAuthorization(config)
		if err != nil {
			t.Fatal(err)
		}
		return server
	}
	call := func(server *Server) *httptest.ResponseRecorder {
		request := signedRequest(t, clock, agentKey, personToken, http.MethodPost, resourceIssuer+"/authorize", body)
		response := httptest.NewRecorder()
		server.Handler().ServeHTTP(response, request)
		return response
	}

	t.Run("definite failure", func(t *testing.T) {
		inner := &r3TestDocumentStore{}
		store := &failingR3DocumentStore{inner: inner, failBeforeCommit: true}
		response := call(newServer(store, func() string { return "resource-token-1" }))
		if response.Code != http.StatusInternalServerError || bytes.Contains(response.Body.Bytes(), []byte("resource_token")) || inner.count() != 0 {
			t.Fatalf("definite failure = %d %s, records=%d", response.Code, response.Body.String(), inner.count())
		}
	})

	t.Run("commit then error leaves a private orphan and a later request gets new lineage", func(t *testing.T) {
		inner := &r3TestDocumentStore{}
		store := &failingR3DocumentStore{inner: inner, failAfterFirstCommit: true}
		ids := []string{"resource-token-1", "resource-token-2"}
		server := newServer(store, func() string {
			id := ids[0]
			ids = ids[1:]
			return id
		})
		first := call(server)
		if first.Code != http.StatusInternalServerError || bytes.Contains(first.Body.Bytes(), []byte("resource_token")) || inner.count() != 1 {
			t.Fatalf("first uncertain response = %d %s, records=%d", first.Code, first.Body.String(), inner.count())
		}
		second := call(server)
		if second.Code != http.StatusOK || inner.count() != 2 {
			t.Fatalf("retry = %d %s, records=%d", second.Code, second.Body.String(), inner.count())
		}
		var output struct {
			ResourceToken string `json:"resource_token"`
		}
		if err := json.Unmarshal(second.Body.Bytes(), &output); err != nil || output.ResourceToken == "" {
			t.Fatalf("retry output = %#v, error=%v", output, err)
		}
		if claims, _, err := r3.VerifyResourceToken(context.Background(), output.ResourceToken, resolver, clock); err != nil || claims.JTI != "resource-token-2" {
			t.Fatalf("retry token claims = %#v, error=%v", claims, err)
		}
	})

	t.Run("mint failure publishes nothing", func(t *testing.T) {
		inner := &r3TestDocumentStore{}
		response := call(newServer(inner, func() string { return "" }))
		if response.Code != http.StatusInternalServerError || bytes.Contains(response.Body.Bytes(), []byte("resource_token")) || inner.count() != 0 {
			t.Fatalf("mint failure = %d %s, records=%d", response.Code, response.Body.String(), inner.count())
		}
	})
}

func TestMCPDirectDocumentFetchAllowsOnlyEntitledSignedPersonAndAccessServers(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 31, 2, 30, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	resourceKey := testSigningKey(t, "resource-key", 40)
	personKey := testSigningKey(t, "person-key", 41)
	accessKey := testSigningKey(t, "access-key", 42)
	agentKey := testSigningKey(t, "agent-key", 43)
	otherKey := testSigningKey(t, "other-key", 44)
	forgedAccessKey := testSigningKey(t, accessKey.ID(), 54)
	unknownAccessKey := testSigningKey(t, "unknown-access-key", 55)
	otherIssuer := "https://other.example"
	resolver := &countingR3KeyResolver{inner: signaturekey.StaticKeyResolver{
		{Issuer: personIssuer, DiscoveryDocument: aauth.PersonDiscoveryDocument, KeyID: personKey.ID()}:       personKey.PublicJWK(),
		{Issuer: accessIssuer, DiscoveryDocument: aauth.AccessDiscoveryDocument, KeyID: accessKey.ID()}:       accessKey.PublicJWK(),
		{Issuer: otherIssuer, DiscoveryDocument: aauth.PersonDiscoveryDocument, KeyID: otherKey.ID()}:         otherKey.PublicJWK(),
		{Issuer: otherIssuer, DiscoveryDocument: aauth.AccessDiscoveryDocument, KeyID: otherKey.ID()}:         otherKey.PublicJWK(),
		{Issuer: resourceIssuer, DiscoveryDocument: aauth.ResourceDiscoveryDocument, KeyID: resourceKey.ID()}: resourceKey.PublicJWK(),
	}}
	store := &r3TestDocumentStore{}
	protectedCalls := 0
	config := validConfigWithKey(resourceKey, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { protectedCalls++ }))
	config.Clock = clock
	config.KeyResolver = resolver
	config.R3 = newResourceMCPConfig(t, store, []string{"records.read"}, func(*http.Request) (string, bool, error) {
		return "records.read", true, nil
	})
	server, err := NewFederatedAuthorization(config)
	if err != nil {
		t.Fatal(err)
	}
	personToken := mintPersonToken(t, personKey, agentKey.PublicJWK(), now, resourceIssuer, "person-token-1")
	authorizeBody := `{"scope":"records.read","r3_operations":{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"records.read"}]}}`
	authorizeResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(authorizeResponse, signedRequest(t, clock, agentKey, personToken, http.MethodPost, resourceIssuer+"/authorize", authorizeBody))
	if authorizeResponse.Code != http.StatusOK {
		t.Fatalf("authorize = %d %s", authorizeResponse.Code, authorizeResponse.Body.String())
	}
	var authorization struct {
		ResourceToken string `json:"resource_token"`
	}
	if err := json.Unmarshal(authorizeResponse.Body.Bytes(), &authorization); err != nil {
		t.Fatal(err)
	}
	_, reference, err := r3.VerifyResourceToken(context.Background(), authorization.ResourceToken, resolver, clock)
	if err != nil {
		t.Fatal(err)
	}
	record, err := store.Load(context.Background(), reference.URI())
	if err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		name        string
		key         jose.SigningKey
		issuer      string
		document    string
		method      string
		target      string
		wantStatus  int
		wantBody    bool
		unsigned    bool
		wantResolve bool
		wantLoad    bool
	}{
		{name: "entitled Person Server", key: personKey, issuer: personIssuer, document: aauth.PersonDiscoveryDocument, wantStatus: http.StatusOK, wantBody: true, wantResolve: true, wantLoad: true},
		{name: "entitled Access Server", key: accessKey, issuer: accessIssuer, document: aauth.AccessDiscoveryDocument, wantStatus: http.StatusOK, wantBody: true, wantResolve: true, wantLoad: true},
		{name: "unsigned", wantStatus: http.StatusUnauthorized, unsigned: true},
		{name: "unrelated Access Server", key: otherKey, issuer: otherIssuer, document: aauth.AccessDiscoveryDocument, wantStatus: http.StatusNotFound, wantLoad: true},
		{name: "right Person Server wrong role", key: personKey, issuer: personIssuer, document: aauth.AccessDiscoveryDocument, wantStatus: http.StatusNotFound, wantLoad: true},
		{name: "alternate authority", key: accessKey, issuer: accessIssuer, document: aauth.AccessDiscoveryDocument, target: strings.Replace(reference.URI(), "resource.example", "alternate.example", 1), wantStatus: http.StatusMisdirectedRequest},
		{name: "query-bearing target", key: accessKey, issuer: accessIssuer, document: aauth.AccessDiscoveryDocument, target: reference.URI() + "?probe=1", wantStatus: http.StatusNotFound},
		{name: "HEAD target", key: accessKey, issuer: accessIssuer, document: aauth.AccessDiscoveryDocument, method: http.MethodHead, wantStatus: http.StatusNotFound},
		{name: "POST target", key: accessKey, issuer: accessIssuer, document: aauth.AccessDiscoveryDocument, method: http.MethodPost, wantStatus: http.StatusNotFound},
		{name: "entitled issuer invalid signature", key: forgedAccessKey, issuer: accessIssuer, document: aauth.AccessDiscoveryDocument, wantStatus: http.StatusUnauthorized, wantResolve: true, wantLoad: true},
		{name: "entitled issuer unknown key", key: unknownAccessKey, issuer: accessIssuer, document: aauth.AccessDiscoveryDocument, wantStatus: http.StatusUnauthorized, wantResolve: true, wantLoad: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			target := test.target
			if target == "" {
				target = reference.URI()
			}
			method := test.method
			if method == "" {
				method = http.MethodGet
			}
			request := httptest.NewRequest(method, target, nil)
			if !test.unsigned {
				if err := signaturekey.SignJWKSURIRequest(request, test.key, test.issuer, test.document, clock); err != nil {
					t.Fatal(err)
				}
			}
			beforeResolve := resolver.callCount()
			beforeLoad := store.loadCount()
			response := httptest.NewRecorder()
			server.Handler().ServeHTTP(response, request)
			if got := response.Header().Get("Cache-Control"); got != "private, no-store, no-transform" {
				t.Fatalf("Cache-Control = %q", got)
			}
			if response.Code != test.wantStatus {
				t.Fatalf("fetch = %d %s", response.Code, response.Body.String())
			}
			if got := resolver.callCount() - beforeResolve; got != boolInt(test.wantResolve) {
				t.Fatalf("key-resolution calls = %d", got)
			}
			if got := store.loadCount() - beforeLoad; got != boolInt(test.wantLoad) {
				t.Fatalf("document-store loads = %d", got)
			}
			if test.wantBody {
				if !bytes.Equal(response.Body.Bytes(), record.ExactJSON) ||
					response.Header().Get("Content-Type") != "application/json" ||
					response.Header().Get("Cache-Control") != "private, no-store, no-transform" {
					t.Fatalf("fetch body/header = %q / %q", response.Body.Bytes(), response.Header().Get("Content-Type"))
				}
			} else if response.Body.Len() != 0 && response.Code == http.StatusNotFound {
				t.Fatalf("unentitled fetch exposed body %q", response.Body.Bytes())
			}
		})
	}

	for _, corruption := range []struct {
		name               string
		document           string
		originalKey        jose.SigningKey
		originalIssuer     string
		corruptEntitlement func(*R3DocumentRecord)
	}{
		{
			name: "Person Server entitlement", document: aauth.PersonDiscoveryDocument,
			originalKey: personKey, originalIssuer: personIssuer,
			corruptEntitlement: func(record *R3DocumentRecord) { record.PersonServer = otherIssuer },
		},
		{
			name: "Access Server entitlement", document: aauth.AccessDiscoveryDocument,
			originalKey: accessKey, originalIssuer: accessIssuer,
			corruptEntitlement: func(record *R3DocumentRecord) { record.AuthTokenIssuer = otherIssuer },
		},
	} {
		t.Run("corrupt retained "+corruption.name, func(t *testing.T) {
			store.mutate(reference.URI(), corruption.corruptEntitlement)
			for _, signer := range []struct {
				name       string
				key        jose.SigningKey
				issuer     string
				wantStatus int
			}{
				{name: "original signer", key: corruption.originalKey, issuer: corruption.originalIssuer, wantStatus: http.StatusNotFound},
				{name: "corrupted signer", key: otherKey, issuer: otherIssuer, wantStatus: http.StatusInternalServerError},
			} {
				t.Run(signer.name, func(t *testing.T) {
					request := httptest.NewRequest(http.MethodGet, reference.URI(), nil)
					if err := signaturekey.SignJWKSURIRequest(request, signer.key, signer.issuer, corruption.document, clock); err != nil {
						t.Fatal(err)
					}
					response := httptest.NewRecorder()
					server.Handler().ServeHTTP(response, request)
					if response.Code != signer.wantStatus || bytes.Equal(response.Body.Bytes(), record.ExactJSON) {
						t.Fatalf("corrupt entitlement fetch = %d %q", response.Code, response.Body.Bytes())
					}
					if got := response.Header().Get("Cache-Control"); got != "private, no-store, no-transform" {
						t.Fatalf("Cache-Control = %q", got)
					}
				})
			}
			store.mutate(reference.URI(), func(current *R3DocumentRecord) { *current = cloneR3TestRecord(record) })
		})
	}
	store.mutate(reference.URI(), func(record *R3DocumentRecord) {
		record.ExactJSON = append(record.ExactJSON, ' ')
	})
	corruptRequest := httptest.NewRequest(http.MethodGet, reference.URI(), nil)
	if err := signaturekey.SignJWKSURIRequest(corruptRequest, accessKey, accessIssuer, aauth.AccessDiscoveryDocument, clock); err != nil {
		t.Fatal(err)
	}
	corruptResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(corruptResponse, corruptRequest)
	if got := corruptResponse.Header().Get("Cache-Control"); got != "private, no-store, no-transform" {
		t.Fatalf("corrupt Cache-Control = %q", got)
	}
	if corruptResponse.Code != http.StatusInternalServerError || bytes.Equal(corruptResponse.Body.Bytes(), record.ExactJSON) {
		t.Fatalf("corrupt retained document = %d %q", corruptResponse.Code, corruptResponse.Body.Bytes())
	}
	if protectedCalls != 0 {
		t.Fatalf("document fetch invoked application %d times", protectedCalls)
	}
}

func TestMCPDirectDocumentFetchDistinguishesCollocatedServerRoles(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 31, 2, 45, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	resourceKey := testSigningKey(t, "resource-key", 56)
	collocatedKey := testSigningKey(t, "collocated-key", 57)
	collocatedIssuer := "https://person-and-access.example"
	resolver := signaturekey.StaticKeyResolver{
		{Issuer: collocatedIssuer, DiscoveryDocument: aauth.PersonDiscoveryDocument, KeyID: collocatedKey.ID()}: collocatedKey.PublicJWK(),
		{Issuer: collocatedIssuer, DiscoveryDocument: aauth.AccessDiscoveryDocument, KeyID: collocatedKey.ID()}: collocatedKey.PublicJWK(),
	}
	operations := newResourceMCPOperationSet(t, "records.read")
	document, _ := r3.NewDocument(operations, r3.DocumentOptions{})
	exactDocument, _ := json.Marshal(document)
	reference, _ := r3.NewReference(
		r3DocumentURI(resourceIssuer, exactDocument, collocatedIssuer, collocatedIssuer, "collocated-resource-token"),
		r3.Digest(exactDocument),
	)
	store := &r3TestDocumentStore{}
	if err := store.Commit(context.Background(), R3DocumentRecord{
		Reference: reference, ExactJSON: exactDocument,
		PersonServer: collocatedIssuer, AuthTokenIssuer: collocatedIssuer,
		AuthTokenIssuerDocument: aauth.AccessDiscoveryDocument,
		ClassContext:            r3TestClassContext(resourceIssuer, collocatedIssuer, collocatedIssuer, "collocated-resource-token", "person-token"),
	}); err != nil {
		t.Fatal(err)
	}
	config := validConfigWithKey(resourceKey, http.NotFoundHandler())
	config.Clock = clock
	config.KeyResolver = resolver
	config.AccessServer = collocatedIssuer
	config.R3 = newResourceMCPConfig(t, store, []string{"records.read"}, func(*http.Request) (string, bool, error) {
		return "records.read", true, nil
	})
	server, err := NewFederatedAuthorization(config)
	if err != nil {
		t.Fatal(err)
	}
	for _, discoveryDocument := range []string{aauth.PersonDiscoveryDocument, aauth.AccessDiscoveryDocument} {
		t.Run(discoveryDocument, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, reference.URI(), nil)
			if err := signaturekey.SignJWKSURIRequest(request, collocatedKey, collocatedIssuer, discoveryDocument, clock); err != nil {
				t.Fatal(err)
			}
			response := httptest.NewRecorder()
			server.Handler().ServeHTTP(response, request)
			if response.Code != http.StatusOK || !bytes.Equal(response.Body.Bytes(), exactDocument) {
				t.Fatalf("fetch = %d %q", response.Code, response.Body.Bytes())
			}
		})
	}
}

func TestMCPDirectProtectedCallRequiresIndependentScopeAndGrantedTool(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 31, 3, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	resourceKey := testSigningKey(t, "resource-key", 45)
	accessKey := testSigningKey(t, "access-key", 46)
	agentKey := testSigningKey(t, "agent-key", 47)
	resolver := signaturekey.StaticKeyResolver{
		{Issuer: accessIssuer, DiscoveryDocument: aauth.AccessDiscoveryDocument, KeyID: accessKey.ID()}: accessKey.PublicJWK(),
	}
	registry := newResourceR3Registry(t)
	read := newResourceMCPOperation(t, "records.read")
	export := newResourceMCPOperation(t, "records.export")
	documentOperations := newResourceMCPOperationSet(t, "records.read", "records.export")
	document, _ := r3.NewDocument(documentOperations, r3.DocumentOptions{})
	exactDocument, _ := json.Marshal(document)
	reference, _ := r3.NewReference(
		r3DocumentURI(resourceIssuer, exactDocument, personIssuer, accessIssuer, "class-resource-token"),
		r3.Digest(exactDocument),
	)

	mintR3 := func(t *testing.T, scope string, operations ...r3.Operation) string {
		t.Helper()
		granted, err := r3.NewGrantedOperations(mcp.Vocabulary(), operations...)
		if err != nil {
			t.Fatal(err)
		}
		grant, err := r3.NewGrant(granted, document)
		if err != nil {
			t.Fatal(err)
		}
		compact, err := r3.MintDirectAuthToken(registry, accessKey, aauth.AuthTokenClaims{
			Issuer: accessIssuer, DWK: aauth.AccessDiscoveryDocument,
			Audience: resourceIssuer, JTI: "auth-token-1",
			PersonServer: personIssuer, Subject: "person-1", Scope: scope,
			Confirmation: aauth.Confirmation{JWK: agentKey.PublicJWK()},
			IssuedAt:     now.Unix(), ExpiresAt: now.Add(time.Hour).Unix(), Tenant: "tenant-1",
		}, reference, exactDocument, grant)
		if err != nil {
			t.Fatal(err)
		}
		return compact
	}
	coreToken, err := aauth.MintAuthToken(accessKey, aauth.AuthTokenClaims{
		Issuer: accessIssuer, DWK: aauth.AccessDiscoveryDocument,
		Audience: resourceIssuer, JTI: "core-auth-token",
		PersonServer: personIssuer, Subject: "person-1", Scope: "records.read",
		Confirmation: aauth.Confirmation{JWK: agentKey.PublicJWK()},
		IssuedAt:     now.Unix(), ExpiresAt: now.Add(time.Hour).Unix(), Tenant: "tenant-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	account := "work-account"
	accountDocument, _ := r3.NewDocument(documentOperations, r3.DocumentOptions{Account: &account})
	accountDocumentBytes, _ := json.Marshal(accountDocument)
	accountReference, _ := r3.NewReference(
		r3DocumentURI(resourceIssuer, accountDocumentBytes, personIssuer, accessIssuer, "account-resource-token"),
		r3.Digest(accountDocumentBytes),
	)
	accountGranted, _ := r3.NewGrantedOperations(mcp.Vocabulary(), read)
	accountGrant, _ := r3.NewGrant(accountGranted, accountDocument)
	accountToken, err := r3.MintDirectAuthToken(registry, accessKey, aauth.AuthTokenClaims{
		Issuer: accessIssuer, DWK: aauth.AccessDiscoveryDocument,
		Audience: resourceIssuer, JTI: "account-auth-token",
		PersonServer: personIssuer, Subject: "person-1", Scope: "records.read", Account: &account,
		Confirmation: aauth.Confirmation{JWK: agentKey.PublicJWK()},
		IssuedAt:     now.Unix(), ExpiresAt: now.Add(time.Hour).Unix(), Tenant: "tenant-1",
	}, accountReference, accountDocumentBytes, accountGrant)
	if err != nil {
		t.Fatal(err)
	}
	wrongEntitlementReference, _ := r3.NewReference(
		r3DocumentURI(resourceIssuer, exactDocument, personIssuer, "https://other-access.example", "other-access-resource-token"),
		r3.Digest(exactDocument),
	)
	readGranted, _ := r3.NewGrantedOperations(mcp.Vocabulary(), read)
	wrongEntitlementToken := mintRawR3AuthToken(t, accessKey, agentKey, now, wrongEntitlementReference, readGranted, nil)

	for _, test := range []struct {
		name        string
		compact     string
		account     *string
		noCoreScope bool
		wantStatus  int
	}{
		{name: "scope and tool granted", compact: mintR3(t, "records.read", read), wantStatus: http.StatusNoContent},
		{name: "R3 grant replaces Core scope", compact: mintR3(t, "", read), noCoreScope: true, wantStatus: http.StatusNoContent},
		{name: "account and tool granted", compact: accountToken, account: &account, wantStatus: http.StatusNoContent},
		{name: "wrong ordinary scope", compact: mintR3(t, "records.write", read), wantStatus: http.StatusForbidden},
		{name: "empty R3 grant", compact: mintR3(t, "records.read"), wantStatus: http.StatusForbidden},
		{name: "different R3 tool", compact: mintR3(t, "records.read", export), wantStatus: http.StatusForbidden},
		{name: "reference entitlement differs from auth token", compact: wrongEntitlementToken, wantStatus: http.StatusForbidden},
		{name: "Core token on R3 route", compact: coreToken, wantStatus: http.StatusForbidden},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := &r3TestDocumentStore{}
			resolveCalls, protectedCalls := 0, 0
			config := validConfigWithKey(resourceKey, http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
				protectedCalls++
				principal, ok := AuthPrincipalFromContext(request.Context())
				if !ok || !equalR3TestStringPointers(principal.Account, test.account) {
					t.Fatalf("AuthPrincipal = %#v", principal)
				}
				response.WriteHeader(http.StatusNoContent)
			}))
			config.Clock = clock
			config.KeyResolver = resolver
			config.AdditionalSignatureComponents = nil
			config.ScopeDescriptions["records.write"] = "Write records"
			if test.noCoreScope {
				config.RequiredScopes = func(*http.Request) []string { return nil }
			}
			config.ResolvePerson = func(context.Context, PersonIdentity, PersonContext) error {
				resolveCalls++
				return nil
			}
			if test.account != nil {
				config.ValidateAccount = func(context.Context, PersonIdentity, string) error { return nil }
			}
			config.R3 = newResourceMCPConfig(t, store, []string{"records.read", "records.export"}, func(*http.Request) (string, bool, error) {
				return "records.read", true, nil
			})
			server, err := NewFederatedAuthorization(config)
			if err != nil {
				t.Fatal(err)
			}
			request := signedRequest(t, clock, agentKey, test.compact, http.MethodGet, resourceIssuer+"/records", "")
			response := httptest.NewRecorder()
			server.Handler().ServeHTTP(response, request)
			if response.Code != test.wantStatus {
				t.Fatalf("protected = %d %s", response.Code, response.Body.String())
			}
			wantCalls := boolInt(test.wantStatus == http.StatusNoContent)
			if resolveCalls != wantCalls || protectedCalls != wantCalls || store.loadCount() != 0 {
				t.Fatalf("calls resolve/protected/load = %d/%d/%d", resolveCalls, protectedCalls, store.loadCount())
			}
		})
	}
}

func TestMCPDirectConfigurationPreservesCoreOnlyRoutes(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 31, 3, 30, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	resourceKey := testSigningKey(t, "resource-key", 48)
	accessKey := testSigningKey(t, "access-key", 49)
	agentKey := testSigningKey(t, "agent-key", 50)
	resolver := signaturekey.StaticKeyResolver{
		{Issuer: accessIssuer, DiscoveryDocument: aauth.AccessDiscoveryDocument, KeyID: accessKey.ID()}: accessKey.PublicJWK(),
	}
	registry := newResourceR3Registry(t)
	read := newResourceMCPOperation(t, "records.read")
	operations := newResourceMCPOperationSet(t, "records.read")
	document, _ := r3.NewDocument(operations, r3.DocumentOptions{})
	exactDocument, _ := json.Marshal(document)
	reference, _ := r3.NewReference(
		r3DocumentURI(resourceIssuer, exactDocument, personIssuer, accessIssuer, "class-resource-token"),
		r3.Digest(exactDocument),
	)
	granted, _ := r3.NewGrantedOperations(mcp.Vocabulary(), read)
	grant, _ := r3.NewGrant(granted, document)
	r3Token, err := r3.MintDirectAuthToken(registry, accessKey, aauth.AuthTokenClaims{
		Issuer: accessIssuer, DWK: aauth.AccessDiscoveryDocument,
		Audience: resourceIssuer, JTI: "r3-auth-token",
		PersonServer: personIssuer, Subject: "person-1", Scope: "records.read",
		Confirmation: aauth.Confirmation{JWK: agentKey.PublicJWK()},
		IssuedAt:     now.Unix(), ExpiresAt: now.Add(time.Hour).Unix(),
	}, reference, exactDocument, grant)
	if err != nil {
		t.Fatal(err)
	}
	coreToken, err := aauth.MintAuthToken(accessKey, aauth.AuthTokenClaims{
		Issuer: accessIssuer, DWK: aauth.AccessDiscoveryDocument,
		Audience: resourceIssuer, JTI: "core-auth-token",
		PersonServer: personIssuer, Subject: "person-1", Scope: "records.read",
		Confirmation: aauth.Confirmation{JWK: agentKey.PublicJWK()},
		IssuedAt:     now.Unix(), ExpiresAt: now.Add(time.Hour).Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	coreAccount := "core-account"
	coreAccountToken, err := aauth.MintAuthToken(accessKey, aauth.AuthTokenClaims{
		Issuer: accessIssuer, DWK: aauth.AccessDiscoveryDocument,
		Audience: resourceIssuer, JTI: "core-account-auth-token",
		PersonServer: personIssuer, Subject: "person-1", Scope: "records.read", Account: &coreAccount,
		Confirmation: aauth.Confirmation{JWK: agentKey.PublicJWK()},
		IssuedAt:     now.Unix(), ExpiresAt: now.Add(time.Hour).Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}

	store := &r3TestDocumentStore{}
	protectedCalls := 0
	config := validConfigWithKey(resourceKey, http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		protectedCalls++
		response.WriteHeader(http.StatusNoContent)
	}))
	config.Clock = clock
	config.KeyResolver = resolver
	config.AdditionalSignatureComponents = nil
	config.ValidateAccount = func(context.Context, PersonIdentity, string) error { return nil }
	config.R3 = newResourceMCPConfig(t, store, []string{"records.read"}, func(request *http.Request) (string, bool, error) {
		if request.URL.Path == "/records" {
			return "records.read", true, nil
		}
		return "", false, nil
	})
	server, err := NewFederatedAuthorization(config)
	if err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		name       string
		path       string
		compact    string
		wantLoads  int
		wantStatus int
	}{
		{name: "Core token on Core route", path: "/legacy", compact: coreToken, wantStatus: http.StatusNoContent},
		{name: "Core account token on Core route", path: "/legacy", compact: coreAccountToken, wantStatus: http.StatusNoContent},
		{name: "R3 token on Core route", path: "/legacy", compact: r3Token, wantStatus: http.StatusForbidden},
		{name: "Core token on R3 route", path: "/records", compact: coreToken, wantStatus: http.StatusForbidden},
		{name: "R3 token on R3 route", path: "/records", compact: r3Token, wantStatus: http.StatusNoContent},
	} {
		t.Run(test.name, func(t *testing.T) {
			before := protectedCalls
			beforeLoads := store.loadCount()
			request := signedRequest(t, clock, agentKey, test.compact, http.MethodGet, resourceIssuer+test.path, "")
			response := httptest.NewRecorder()
			server.Handler().ServeHTTP(response, request)
			if response.Code != test.wantStatus {
				t.Fatalf("protected = %d %s", response.Code, response.Body.String())
			}
			wantDelta := boolInt(test.wantStatus == http.StatusNoContent)
			if protectedCalls-before != wantDelta || store.loadCount()-beforeLoads != test.wantLoads {
				t.Fatalf("protected/load calls = %d/%d", protectedCalls-before, store.loadCount()-beforeLoads)
			}
		})
	}
}

func TestMCPDirectRoutePoliciesPreserveTheApplicationBody(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 31, 4, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	resourceKey := testSigningKey(t, "resource-key", 51)
	accessKey := testSigningKey(t, "access-key", 52)
	agentKey := testSigningKey(t, "agent-key", 53)
	resolver := signaturekey.StaticKeyResolver{
		{Issuer: accessIssuer, DiscoveryDocument: aauth.AccessDiscoveryDocument, KeyID: accessKey.ID()}: accessKey.PublicJWK(),
	}
	registry := newResourceR3Registry(t)
	read := newResourceMCPOperation(t, "records.read")
	operations := newResourceMCPOperationSet(t, "records.read")
	document, _ := r3.NewDocument(operations, r3.DocumentOptions{})
	exactDocument, _ := json.Marshal(document)
	reference, _ := r3.NewReference(
		r3DocumentURI(resourceIssuer, exactDocument, personIssuer, accessIssuer, "class-resource-token"),
		r3.Digest(exactDocument),
	)
	granted, _ := r3.NewGrantedOperations(mcp.Vocabulary(), read)
	grant, _ := r3.NewGrant(granted, document)
	compact, err := r3.MintDirectAuthToken(registry, accessKey, aauth.AuthTokenClaims{
		Issuer: accessIssuer, DWK: aauth.AccessDiscoveryDocument,
		Audience: resourceIssuer, JTI: "auth-token-1",
		PersonServer: personIssuer, Subject: "person-1", Scope: "records.read",
		Confirmation: aauth.Confirmation{JWK: agentKey.PublicJWK()},
		IssuedAt:     now.Unix(), ExpiresAt: now.Add(time.Hour).Unix(),
	}, reference, exactDocument, grant)
	if err != nil {
		t.Fatal(err)
	}

	wantBody := `{"record":"42"}`
	var scopeBody, operationBody, applicationBody string
	config := validConfigWithKey(resourceKey, http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		body, err := io.ReadAll(request.Body)
		if err != nil {
			t.Fatal(err)
		}
		applicationBody = string(body)
		response.WriteHeader(http.StatusNoContent)
	}))
	config.Clock = clock
	config.KeyResolver = resolver
	config.RequiredScopes = func(request *http.Request) []string {
		body, _ := io.ReadAll(request.Body)
		scopeBody = string(body)
		return []string{"records.read"}
	}
	store := &r3TestDocumentStore{}
	config.R3 = newResourceMCPConfig(t, store, []string{"records.read"}, func(request *http.Request) (string, bool, error) {
		body, err := io.ReadAll(request.Body)
		operationBody = string(body)
		return "records.read", true, err
	})
	server, err := NewFederatedAuthorization(config)
	if err != nil {
		t.Fatal(err)
	}
	request := signedRequest(t, clock, agentKey, compact, http.MethodPost, resourceIssuer+"/records", wantBody)
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusNoContent {
		t.Fatalf("protected = %d %s", response.Code, response.Body.String())
	}
	if scopeBody != wantBody || operationBody != wantBody || applicationBody != wantBody {
		t.Fatalf("body views = scope %q, operation %q, application %q", scopeBody, operationBody, applicationBody)
	}
	if store.loadCount() != 0 {
		t.Fatalf("document loads = %d", store.loadCount())
	}
}

func TestR3DocumentStoreContractIsExactIdempotentConflictSafeAndCopySafe(t *testing.T) {
	t.Parallel()

	operations := newResourceMCPOperationSet(t, "records.read")
	document, _ := r3.NewDocument(operations, r3.DocumentOptions{})
	exactDocument, _ := json.Marshal(document)
	reference, _ := r3.NewReference(
		r3DocumentURI(resourceIssuer, exactDocument, personIssuer, accessIssuer, "class-resource-token"),
		r3.Digest(exactDocument),
	)
	record := R3DocumentRecord{
		Reference: reference, ExactJSON: exactDocument,
		PersonServer: personIssuer, AuthTokenIssuer: accessIssuer,
		AuthTokenIssuerDocument: aauth.AccessDiscoveryDocument,
		ClassContext:            r3TestClassContext(resourceIssuer, personIssuer, accessIssuer, "class-resource-token", "person-token"),
	}
	account := "account-1"
	record.ClassContext.ResourceToken.Account = &account
	record.ClassContext.ResourceToken.Interaction = &aauth.ResourceInteraction{URL: resourceIssuer + "/interact", Code: "code-1"}
	record.ClassContext.ResourceToken.AdditionalClaims = map[string]json.RawMessage{"urn:example:claim": json.RawMessage(`{"value":1}`)}
	emptyMapRecord := record
	emptyMapRecord.ClassContext.ResourceToken.AdditionalClaims = make(map[string]json.RawMessage)
	emptyMapClone := emptyMapRecord.Clone()
	emptyMapRecord.ClassContext.ResourceToken.AdditionalClaims["urn:example:later"] = json.RawMessage(`true`)
	if len(emptyMapClone.ClassContext.ResourceToken.AdditionalClaims) != 0 {
		t.Fatal("clone aliases an initially empty additional-claims map")
	}
	store := &r3TestDocumentStore{}
	input := cloneR3TestRecord(record)
	if err := store.Commit(context.Background(), input); err != nil {
		t.Fatal(err)
	}
	input.ExactJSON[0] ^= 0xff
	*input.ClassContext.ResourceToken.Account = "mutated-account"
	input.ClassContext.ResourceToken.Interaction.Code = "mutated-code"
	input.ClassContext.ResourceToken.AdditionalClaims["urn:example:claim"][0] ^= 0xff
	loaded, err := store.Load(context.Background(), reference.URI())
	if err != nil {
		t.Fatal(err)
	}
	if !equalR3TestRecords(loaded, record) {
		t.Fatalf("caller mutation changed retained record: %#v", loaded)
	}
	loaded.ExactJSON[0] ^= 0xff
	*loaded.ClassContext.ResourceToken.Account = "mutated-loaded-account"
	loaded.ClassContext.ResourceToken.Interaction.Code = "mutated-loaded-code"
	loaded.ClassContext.ResourceToken.AdditionalClaims["urn:example:claim"][0] ^= 0xff
	loadedAgain, err := store.Load(context.Background(), reference.URI())
	if err != nil {
		t.Fatal(err)
	}
	if !equalR3TestRecords(loadedAgain, record) {
		t.Fatalf("loaded-copy mutation changed retained record: %#v", loadedAgain)
	}
	if err := store.Commit(context.Background(), cloneR3TestRecord(record)); err != nil {
		t.Fatalf("exact repeat: %v", err)
	}
	if store.count() != 1 {
		t.Fatalf("exact repeat retained %d records", store.count())
	}

	differentReference, _ := r3.NewReference(reference.URI(), r3.Digest([]byte(`{"vocabulary":"different","operations":[]}`)))
	conflicts := []R3DocumentRecord{
		{Reference: reference, ExactJSON: append(append([]byte(nil), exactDocument...), ' '), PersonServer: personIssuer, AuthTokenIssuer: accessIssuer, AuthTokenIssuerDocument: aauth.AccessDiscoveryDocument, ClassContext: record.ClassContext},
		{Reference: differentReference, ExactJSON: exactDocument, PersonServer: personIssuer, AuthTokenIssuer: accessIssuer, AuthTokenIssuerDocument: aauth.AccessDiscoveryDocument, ClassContext: record.ClassContext},
		{Reference: reference, ExactJSON: exactDocument, PersonServer: "https://other-person.example", AuthTokenIssuer: accessIssuer, AuthTokenIssuerDocument: aauth.AccessDiscoveryDocument, ClassContext: record.ClassContext},
		{Reference: reference, ExactJSON: exactDocument, PersonServer: personIssuer, AuthTokenIssuer: "https://other-access.example", AuthTokenIssuerDocument: aauth.AccessDiscoveryDocument, ClassContext: record.ClassContext},
	}
	changedJTI := cloneR3TestRecord(record)
	changedJTI.ClassContext.ResourceToken.JTI = "different-resource-token"
	conflicts = append(conflicts, changedJTI)
	changedPresented := cloneR3TestRecord(record)
	changedPresented.ClassContext.ResourceToken.PresentedJTI = "different-person-token"
	conflicts = append(conflicts, changedPresented)
	changedIssuerRole := cloneR3TestRecord(record)
	changedIssuerRole.AuthTokenIssuerDocument = aauth.PersonDiscoveryDocument
	conflicts = append(conflicts, changedIssuerRole)
	for index, conflicting := range conflicts {
		if err := store.Commit(context.Background(), conflicting); !errors.Is(err, ErrR3DocumentConflict) {
			t.Fatalf("conflict %d = %v", index, err)
		}
		retained, err := store.Load(context.Background(), reference.URI())
		if err != nil {
			t.Fatal(err)
		}
		if !equalR3TestRecords(retained, record) {
			t.Fatalf("conflict %d changed retained record: %#v", index, retained)
		}
	}
	if _, err := store.Load(context.Background(), resourceIssuer+"/r3/missing"); !errors.Is(err, ErrR3DocumentNotFound) {
		t.Fatalf("missing load = %v", err)
	}

	concurrent := &r3TestDocumentStore{}
	const writers = 16
	errorsOut := make(chan error, writers)
	var wait sync.WaitGroup
	for range writers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			errorsOut <- concurrent.Commit(context.Background(), cloneR3TestRecord(record))
		}()
	}
	wait.Wait()
	close(errorsOut)
	for err := range errorsOut {
		if err != nil {
			t.Fatalf("concurrent exact commit: %v", err)
		}
	}
	if concurrent.count() != 1 {
		t.Fatalf("concurrent exact commits retained %d records", concurrent.count())
	}
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

func equalR3TestStringPointers(first, second *string) bool {
	if first == nil || second == nil {
		return first == nil && second == nil
	}
	return *first == *second
}

func mintRawR3AuthToken(
	t *testing.T,
	issuerKey, requestKey jose.SigningKey,
	now time.Time,
	reference r3.Reference,
	granted r3.GrantedOperations,
	account *string,
) string {
	t.Helper()
	uriJSON, _ := json.Marshal(reference.URI())
	digestJSON, _ := json.Marshal(reference.Digest())
	grantedJSON, err := json.Marshal(granted)
	if err != nil {
		t.Fatal(err)
	}
	compact, err := aauth.MintAuthTokenCore(issuerKey, aauth.AuthTokenClaims{
		Issuer: accessIssuer, DWK: aauth.AccessDiscoveryDocument,
		Audience: resourceIssuer, JTI: "raw-r3-auth-token",
		PersonServer: personIssuer, Subject: "person-1", Scope: "records.read", Account: cloneAuthorizationAccount(account),
		Confirmation: aauth.Confirmation{JWK: requestKey.PublicJWK()},
		IssuedAt:     now.Unix(), ExpiresAt: now.Add(time.Hour).Unix(), Tenant: "tenant-1",
		AdditionalClaims: map[string]json.RawMessage{
			"r3_uri": uriJSON, "r3_s256": digestJSON, "r3_granted": grantedJSON,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return compact
}

type r3TestDocumentStore struct {
	mu      sync.Mutex
	records map[string]R3DocumentRecord
	loads   int
}

type countingR3KeyResolver struct {
	mu    sync.Mutex
	inner signaturekey.KeyResolver
	calls int
}

func (resolver *countingR3KeyResolver) ResolveKey(
	ctx context.Context,
	issuer, discoveryDocument, keyID string,
) (jose.JWK, error) {
	resolver.mu.Lock()
	resolver.calls++
	resolver.mu.Unlock()
	return resolver.inner.ResolveKey(ctx, issuer, discoveryDocument, keyID)
}

func (resolver *countingR3KeyResolver) callCount() int {
	resolver.mu.Lock()
	defer resolver.mu.Unlock()
	return resolver.calls
}

type failingR3DocumentStore struct {
	inner                *r3TestDocumentStore
	failBeforeCommit     bool
	failAfterFirstCommit bool
	calls                int
}

func (store *failingR3DocumentStore) Commit(ctx context.Context, record R3DocumentRecord) error {
	store.calls++
	if store.failBeforeCommit {
		return errors.New("definite document commit failure")
	}
	if err := store.inner.Commit(ctx, record); err != nil {
		return err
	}
	if store.failAfterFirstCommit && store.calls == 1 {
		return errors.New("document commit result was lost")
	}
	return nil
}

func (store *failingR3DocumentStore) Load(ctx context.Context, uri string) (R3DocumentRecord, error) {
	return store.inner.Load(ctx, uri)
}

func (store *r3TestDocumentStore) Commit(_ context.Context, record R3DocumentRecord) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.records == nil {
		store.records = make(map[string]R3DocumentRecord)
	}
	if existing, ok := store.records[record.Reference.URI()]; ok {
		if !equalR3TestRecords(existing, record) {
			return ErrR3DocumentConflict
		}
		return nil
	}
	registry, err := resourceMCPRegistry()
	if err != nil {
		return err
	}
	if _, err := registry.ParseReferencedDocument(record.Reference, record.ExactJSON); err != nil {
		return err
	}
	store.records[record.Reference.URI()] = cloneR3TestRecord(record)
	return nil
}

func (store *r3TestDocumentStore) Load(_ context.Context, uri string) (R3DocumentRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.loads++
	record, ok := store.records[uri]
	if !ok {
		return R3DocumentRecord{}, ErrR3DocumentNotFound
	}
	return cloneR3TestRecord(record), nil
}

func (store *r3TestDocumentStore) loadCount() int {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.loads
}

func (store *r3TestDocumentStore) count() int {
	store.mu.Lock()
	defer store.mu.Unlock()
	return len(store.records)
}

func (store *r3TestDocumentStore) mutate(uri string, change func(*R3DocumentRecord)) {
	store.mu.Lock()
	defer store.mu.Unlock()
	record := store.records[uri]
	change(&record)
	store.records[uri] = record
}

func cloneR3TestRecord(record R3DocumentRecord) R3DocumentRecord {
	return record.Clone()
}

func equalR3TestRecords(first, second R3DocumentRecord) bool {
	return first.Reference == second.Reference &&
		first.PersonServer == second.PersonServer &&
		first.AuthTokenIssuer == second.AuthTokenIssuer &&
		first.AuthTokenIssuerDocument == second.AuthTokenIssuerDocument &&
		reflect.DeepEqual(first.ClassContext, second.ClassContext) &&
		bytes.Equal(first.ExactJSON, second.ExactJSON)
}

func r3TestClassContext(resource, person, access, resourceJTI, presentedJTI string) R3ClassAuthorizationContext {
	return R3ClassAuthorizationContext{
		ResourceToken: aauth.ResourceTokenClaims{
			Issuer: resource, Audience: access, JTI: resourceJTI,
			PersonServer: person, Subject: "person-1", PresentedJTI: presentedJTI,
			AgentJKT: "agent-jkt", IssuedAt: 1_777_000_000, ExpiresAt: 1_777_000_300,
		},
		PersonTokenIssuedAt: 1_777_000_000, PersonTokenExpiresAt: 1_777_003_600,
	}
}

var _ R3DocumentStore = (*r3TestDocumentStore)(nil)
