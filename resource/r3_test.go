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

	aauth "aauth-go"
	"aauth-go/jose"
	"aauth-go/r3"
	"aauth-go/signaturekey"
)

func TestMCPDirectResourceMetadataAdvertisesVocabularyAndValidatesConfiguration(t *testing.T) {
	t.Parallel()

	validR3 := func() *MCPR3Config {
		return &MCPR3Config{
			DiscoveryEndpoint: "https://resource.example/mcp",
			KnownTools:        []string{"records.read", "records.export"},
			Documents:         &r3TestDocumentStore{},
			OperationForRequest: func(*http.Request) (string, bool, error) {
				return "records.read", true, nil
			},
		}
	}

	for _, test := range []struct {
		name   string
		change func(*MCPR3Config)
	}{
		{name: "missing endpoint", change: func(config *MCPR3Config) { config.DiscoveryEndpoint = "" }},
		{name: "non-HTTPS endpoint", change: func(config *MCPR3Config) { config.DiscoveryEndpoint = "http://resource.example/mcp" }},
		{name: "missing known tools", change: func(config *MCPR3Config) { config.KnownTools = nil }},
		{name: "invalid known tool", change: func(config *MCPR3Config) { config.KnownTools = []string{" records.read"} }},
		{name: "duplicate known tool", change: func(config *MCPR3Config) { config.KnownTools = []string{"records.read", "records.read"} }},
		{name: "missing document store", change: func(config *MCPR3Config) { config.Documents = nil }},
		{name: "missing operation mapper", change: func(config *MCPR3Config) { config.OperationForRequest = nil }},
	} {
		t.Run(test.name, func(t *testing.T) {
			config := validConfig(t, http.NotFoundHandler())
			config.MCPR3 = validR3()
			test.change(config.MCPR3)
			if _, err := NewFederatedAuthorization(config); err == nil {
				t.Fatal("NewFederatedAuthorization accepted incomplete MCP R3 configuration")
			}
		})
	}

	config := validConfig(t, http.NotFoundHandler())
	config.MCPR3 = validR3()
	server, err := NewFederatedAuthorization(config)
	if err != nil {
		t.Fatal(err)
	}
	config.MCPR3.DiscoveryEndpoint = "https://changed.example/mcp"
	config.MCPR3.KnownTools[0] = "records.delete"
	if got := server.mcpR3.knownTools; len(got) != 2 || got[0] != "records.read" || got[1] != "records.export" {
		t.Fatalf("retained authoritative tools = %q", got)
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
	if len(metadata.R3Vocabularies) != 1 || metadata.R3Vocabularies[r3.MCPVocabulary] != "https://resource.example/mcp" {
		t.Fatalf("r3_vocabularies = %#v", metadata.R3Vocabularies)
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
			config.MCPR3 = &MCPR3Config{
				DiscoveryEndpoint: "https://resource.example/mcp",
				KnownTools:        []string{"records.read", "records.export", "records.delete"},
				Documents:         store,
				DisplayForOperations: func(_ context.Context, operations r3.MCPOperationSet, account *string) (*r3.Display, error) {
					displayCalls++
					wantRead, _ := r3.NewMCPOperation("records.read")
					wantExport, _ := r3.NewMCPOperation("records.export")
					wantOperations, _ := r3.NewMCPOperationSet(wantRead, wantExport)
					if !operations.Equal(wantOperations) || !equalR3TestStringPointers(account, test.account) {
						t.Fatalf("display input = %#v, %v", operations.Operations(), account)
					}
					return &display, nil
				},
				OperationForRequest: func(*http.Request) (string, bool, error) {
					return "records.read", true, nil
				},
			}
			server, err := NewFederatedAuthorization(config)
			if err != nil {
				t.Fatal(err)
			}

			input := map[string]any{
				"r3_operations": map[string]any{
					"vocabulary": r3.MCPVocabulary,
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
			claims, reference, err := r3.VerifyMCPResourceToken(context.Background(), output.ResourceToken, resolver, clock)
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
			if record.Reference != reference || record.PersonServer != personIssuer || record.AccessServer != accessIssuer ||
				record.ClassContext.ResourceToken.JTI != claims.JTI ||
				record.ClassContext.ResourceToken.PresentedJTI != claims.PresentedJTI ||
				r3.Digest(record.ExactJSON) != reference.Digest() {
				t.Fatalf("retained R3 record = %#v", record)
			}
			document, err := r3.ParseReferencedDocument(reference, record.ExactJSON)
			if err != nil {
				t.Fatal(err)
			}
			wantRead, _ := r3.NewMCPOperation("records.read")
			wantExport, _ := r3.NewMCPOperation("records.export")
			wantOperations, _ := r3.NewMCPOperationSet(wantRead, wantExport)
			if !document.OperationSet().Equal(wantOperations) {
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
	config.MCPR3 = &MCPR3Config{
		DiscoveryEndpoint: "https://resource.example/mcp",
		KnownTools:        []string{"records.read"},
		Documents:         store,
		OperationForRequest: func(*http.Request) (string, bool, error) {
			return "records.read", true, nil
		},
	}
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
		claims, reference, err := r3.VerifyMCPResourceToken(context.Background(), output.ResourceToken, resolver, clock)
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
			config.MCPR3 = &MCPR3Config{
				DiscoveryEndpoint: "https://resource.example/mcp",
				KnownTools:        []string{"records.read"},
				Documents:         store,
				OperationForRequest: func(*http.Request) (string, bool, error) {
					return "records.read", true, nil
				},
			}
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
		config.MCPR3 = &MCPR3Config{
			DiscoveryEndpoint: "https://resource.example/mcp",
			KnownTools:        []string{"records.read"},
			Documents:         store,
			OperationForRequest: func(*http.Request) (string, bool, error) {
				return "records.read", true, nil
			},
		}
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
		if claims, _, err := r3.VerifyMCPResourceToken(context.Background(), output.ResourceToken, resolver, clock); err != nil || claims.JTI != "resource-token-2" {
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
	config.MCPR3 = &MCPR3Config{
		DiscoveryEndpoint: "https://resource.example/mcp",
		KnownTools:        []string{"records.read"},
		Documents:         store,
		OperationForRequest: func(*http.Request) (string, bool, error) {
			return "records.read", true, nil
		},
	}
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
	_, reference, err := r3.VerifyMCPResourceToken(context.Background(), authorization.ResourceToken, resolver, clock)
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
		{name: "alternate authority", key: accessKey, issuer: accessIssuer, document: aauth.AccessDiscoveryDocument, target: strings.Replace(reference.URI(), "resource.example", "alternate.example", 1), wantStatus: http.StatusNotFound},
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
			corruptEntitlement: func(record *R3DocumentRecord) { record.AccessServer = otherIssuer },
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
	read, _ := r3.NewMCPOperation("records.read")
	operations, _ := r3.NewMCPOperationSet(read)
	document, _ := r3.NewDocument(operations, r3.DocumentOptions{})
	exactDocument, _ := json.Marshal(document)
	reference, _ := r3.NewReference(
		mcpR3DocumentURI(resourceIssuer, exactDocument, collocatedIssuer, collocatedIssuer, "collocated-resource-token"),
		r3.Digest(exactDocument),
	)
	store := &r3TestDocumentStore{}
	if err := store.Commit(context.Background(), R3DocumentRecord{
		Reference: reference, ExactJSON: exactDocument,
		PersonServer: collocatedIssuer, AccessServer: collocatedIssuer,
		ClassContext: r3TestClassContext(resourceIssuer, collocatedIssuer, collocatedIssuer, "collocated-resource-token", "person-token"),
	}); err != nil {
		t.Fatal(err)
	}
	config := validConfigWithKey(resourceKey, http.NotFoundHandler())
	config.Clock = clock
	config.KeyResolver = resolver
	config.AccessServer = collocatedIssuer
	config.MCPR3 = &MCPR3Config{
		DiscoveryEndpoint: "https://resource.example/mcp",
		KnownTools:        []string{"records.read"},
		Documents:         store,
		OperationForRequest: func(*http.Request) (string, bool, error) {
			return "records.read", true, nil
		},
	}
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
	read, _ := r3.NewMCPOperation("records.read")
	export, _ := r3.NewMCPOperation("records.export")
	documentOperations, _ := r3.NewMCPOperationSet(read, export)
	document, _ := r3.NewDocument(documentOperations, r3.DocumentOptions{})
	exactDocument, _ := json.Marshal(document)
	reference, _ := r3.NewReference(
		mcpR3DocumentURI(resourceIssuer, exactDocument, personIssuer, accessIssuer, "class-resource-token"),
		r3.Digest(exactDocument),
	)

	mintR3 := func(t *testing.T, scope string, operations ...r3.MCPOperation) string {
		t.Helper()
		granted, err := r3.NewGrantedOperations(operations...)
		if err != nil {
			t.Fatal(err)
		}
		grant, err := r3.NewGrant(granted, document)
		if err != nil {
			t.Fatal(err)
		}
		compact, err := r3.MintMCPDirectAuthToken(accessKey, aauth.AuthTokenClaims{
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
		mcpR3DocumentURI(resourceIssuer, accountDocumentBytes, personIssuer, accessIssuer, "account-resource-token"),
		r3.Digest(accountDocumentBytes),
	)
	accountGranted, _ := r3.NewGrantedOperations(read)
	accountGrant, _ := r3.NewGrant(accountGranted, accountDocument)
	accountToken, err := r3.MintMCPDirectAuthToken(accessKey, aauth.AuthTokenClaims{
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
		mcpR3DocumentURI(resourceIssuer, exactDocument, personIssuer, "https://other-access.example", "other-access-resource-token"),
		r3.Digest(exactDocument),
	)
	readGranted, _ := r3.NewGrantedOperations(read)
	wrongEntitlementToken := mintRawMCPR3AuthToken(t, accessKey, agentKey, now, wrongEntitlementReference, readGranted, nil)

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
			config.MCPR3 = &MCPR3Config{
				DiscoveryEndpoint: "https://resource.example/mcp",
				KnownTools:        []string{"records.read", "records.export"},
				Documents:         store,
				OperationForRequest: func(*http.Request) (string, bool, error) {
					return "records.read", true, nil
				},
			}
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
	read, _ := r3.NewMCPOperation("records.read")
	operations, _ := r3.NewMCPOperationSet(read)
	document, _ := r3.NewDocument(operations, r3.DocumentOptions{})
	exactDocument, _ := json.Marshal(document)
	reference, _ := r3.NewReference(
		mcpR3DocumentURI(resourceIssuer, exactDocument, personIssuer, accessIssuer, "class-resource-token"),
		r3.Digest(exactDocument),
	)
	granted, _ := r3.NewGrantedOperations(read)
	grant, _ := r3.NewGrant(granted, document)
	r3Token, err := r3.MintMCPDirectAuthToken(accessKey, aauth.AuthTokenClaims{
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
	config.MCPR3 = &MCPR3Config{
		DiscoveryEndpoint: "https://resource.example/mcp",
		KnownTools:        []string{"records.read"},
		Documents:         store,
		OperationForRequest: func(request *http.Request) (string, bool, error) {
			if request.URL.Path == "/records" {
				return "records.read", true, nil
			}
			return "", false, nil
		},
	}
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
		{name: "Core account token remains unsupported", path: "/legacy", compact: coreAccountToken, wantStatus: http.StatusForbidden},
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
	read, _ := r3.NewMCPOperation("records.read")
	operations, _ := r3.NewMCPOperationSet(read)
	document, _ := r3.NewDocument(operations, r3.DocumentOptions{})
	exactDocument, _ := json.Marshal(document)
	reference, _ := r3.NewReference(
		mcpR3DocumentURI(resourceIssuer, exactDocument, personIssuer, accessIssuer, "class-resource-token"),
		r3.Digest(exactDocument),
	)
	granted, _ := r3.NewGrantedOperations(read)
	grant, _ := r3.NewGrant(granted, document)
	compact, err := r3.MintMCPDirectAuthToken(accessKey, aauth.AuthTokenClaims{
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
	config.MCPR3 = &MCPR3Config{
		DiscoveryEndpoint: "https://resource.example/mcp",
		KnownTools:        []string{"records.read"},
		Documents:         store,
		OperationForRequest: func(request *http.Request) (string, bool, error) {
			body, err := io.ReadAll(request.Body)
			operationBody = string(body)
			return "records.read", true, err
		},
	}
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

	read, _ := r3.NewMCPOperation("records.read")
	operations, _ := r3.NewMCPOperationSet(read)
	document, _ := r3.NewDocument(operations, r3.DocumentOptions{})
	exactDocument, _ := json.Marshal(document)
	reference, _ := r3.NewReference(
		mcpR3DocumentURI(resourceIssuer, exactDocument, personIssuer, accessIssuer, "class-resource-token"),
		r3.Digest(exactDocument),
	)
	record := R3DocumentRecord{
		Reference: reference, ExactJSON: exactDocument,
		PersonServer: personIssuer, AccessServer: accessIssuer,
		ClassContext: r3TestClassContext(resourceIssuer, personIssuer, accessIssuer, "class-resource-token", "person-token"),
	}
	store := &r3TestDocumentStore{}
	input := cloneR3TestRecord(record)
	if err := store.Commit(context.Background(), input); err != nil {
		t.Fatal(err)
	}
	input.ExactJSON[0] ^= 0xff
	loaded, err := store.Load(context.Background(), reference.URI())
	if err != nil {
		t.Fatal(err)
	}
	if !equalR3TestRecords(loaded, record) {
		t.Fatalf("caller mutation changed retained record: %#v", loaded)
	}
	loaded.ExactJSON[0] ^= 0xff
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
		{Reference: reference, ExactJSON: append(append([]byte(nil), exactDocument...), ' '), PersonServer: personIssuer, AccessServer: accessIssuer, ClassContext: record.ClassContext},
		{Reference: differentReference, ExactJSON: exactDocument, PersonServer: personIssuer, AccessServer: accessIssuer, ClassContext: record.ClassContext},
		{Reference: reference, ExactJSON: exactDocument, PersonServer: "https://other-person.example", AccessServer: accessIssuer, ClassContext: record.ClassContext},
		{Reference: reference, ExactJSON: exactDocument, PersonServer: personIssuer, AccessServer: "https://other-access.example", ClassContext: record.ClassContext},
	}
	changedJTI := cloneR3TestRecord(record)
	changedJTI.ClassContext.ResourceToken.JTI = "different-resource-token"
	conflicts = append(conflicts, changedJTI)
	changedPresented := cloneR3TestRecord(record)
	changedPresented.ClassContext.ResourceToken.PresentedJTI = "different-person-token"
	conflicts = append(conflicts, changedPresented)
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

func mintRawMCPR3AuthToken(
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
	if _, err := r3.ParseReferencedDocument(record.Reference, record.ExactJSON); err != nil {
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
	record.ExactJSON = append([]byte(nil), record.ExactJSON...)
	record.ClassContext.ResourceToken.Account = cloneAuthorizationAccount(record.ClassContext.ResourceToken.Account)
	record.ClassContext.ResourceToken.AdditionalClaims = cloneAdditionalClaims(record.ClassContext.ResourceToken.AdditionalClaims)
	return record
}

func equalR3TestRecords(first, second R3DocumentRecord) bool {
	return first.Reference == second.Reference &&
		first.PersonServer == second.PersonServer &&
		first.AccessServer == second.AccessServer &&
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
