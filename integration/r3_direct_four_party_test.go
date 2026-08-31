package integration_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	aauth "aauth-go"
	"aauth-go/accessserver"
	clientagent "aauth-go/agent"
	"aauth-go/agentprovider"
	"aauth-go/personserver"
	"aauth-go/r3"
	"aauth-go/resource"
	"aauth-go/signaturekey"
)

func TestMCPR3DirectFourPartyJourney(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	const (
		agentProviderID = "https://ap.example"
		agentID         = "aauth:planner@ap.example"
		personServerID  = "https://ps.example"
		accessServerID  = "https://as.example"
		resourceID      = "https://resource.example"
	)
	providerKey := newSigningKey(t, "r3-ap-key")
	agentKey := newSigningKey(t, "r3-agent-key")
	personKey := newSigningKey(t, "r3-ps-key")
	accessKey := newSigningKey(t, "r3-as-key")
	resourceKey := newSigningKey(t, "r3-resource-key")
	network := newLogicalTransport()
	httpClient := &http.Client{Transport: network}
	resolver, err := signaturekey.NewHTTPKeyResolver(signaturekey.HTTPKeyResolverConfig{
		Client: httpClient, Clock: clock,
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
	provider, err := agentprovider.New(agentprovider.Config{
		Issuer: agentProviderID, SigningKey: providerKey, Clock: clock,
		NewID: func() string { return "r3-agent-token" },
	})
	if err != nil {
		t.Fatal(err)
	}
	agentToken, err := provider.Issue(aauth.AgentTokenRequest{
		Agent: agentID, PersonServer: personServerID,
		PublicKey: agentKey.PublicJWK(), Lifetime: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}

	documents := newIntegrationR3DocumentStore()
	account := "work-account"
	var requiredScopes []string
	var expectedPrincipalScopes []string
	resourceTokenIDs := 0
	read, _ := r3.NewMCPOperation("records.read")
	export, _ := r3.NewMCPOperation("records.export")
	requestedOperations, _ := r3.NewMCPOperationSet(read, export)
	display, _ := r3.NewDisplay(
		"Read and export records",
		"Exported records may leave the system",
		"Record contents",
		"Exported copies cannot be recalled",
	)
	protectedCalls := 0
	protectedResource, err := resource.NewFederatedAuthorization(resource.FederatedAuthorizationConfig{
		Issuer: resourceID, AccessServer: accessServerID,
		SigningKey: resourceKey, KeyResolver: resolver, Clock: clock,
		NewID: func() string {
			resourceTokenIDs++
			return "r3-resource-token-" + string(rune('0'+resourceTokenIDs))
		},
		ScopeDescriptions: map[string]string{
			"records.read":  "Read records",
			"records.write": "Write records",
		},
		RequiredScopes: func(*http.Request) []string { return append([]string(nil), requiredScopes...) },
		ResolvePerson: func(_ context.Context, identity resource.PersonIdentity, _ resource.PersonContext) error {
			if identity != (resource.PersonIdentity{Issuer: personServerID, Subject: "person-123"}) {
				return errors.New("unexpected person")
			}
			return nil
		},
		ValidateAccount: func(_ context.Context, identity resource.PersonIdentity, got string) error {
			if identity.Subject != "person-123" || got != account {
				return errors.New("unexpected account")
			}
			return nil
		},
		MCPR3: &resource.MCPR3Config{
			DiscoveryEndpoint: resourceID + "/mcp",
			KnownTools:        []string{"records.read", "records.export"},
			Documents:         documents,
			DisplayForOperations: func(_ context.Context, operations r3.MCPOperationSet, gotAccount *string) (*r3.Display, error) {
				if !operations.Equal(requestedOperations) || gotAccount == nil || *gotAccount != account {
					return nil, errors.New("unexpected display input")
				}
				return &display, nil
			},
			OperationForRequest: func(request *http.Request) (string, bool, error) {
				switch request.URL.Path {
				case "/records/read":
					return "records.read", true, nil
				case "/records/export":
					return "records.export", true, nil
				default:
					return "", false, nil
				}
			},
		},
		Protected: http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			protectedCalls++
			principal, ok := resource.AuthPrincipalFromContext(request.Context())
			if !ok || principal.Account == nil || *principal.Account != account || !slices.Equal(principal.Scope, expectedPrincipalScopes) {
				t.Fatalf("R3 principal = %#v, %t", principal, ok)
			}
			response.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(response, `{"ok":true}`)
		}),
	})
	if err != nil {
		t.Fatal(err)
	}

	issuances := &integrationR3IssuanceStore{}
	authTokenIDs := 0
	access, err := accessserver.New(accessserver.Config{
		Issuer: accessServerID, SigningKey: accessKey, KeyResolver: resolver,
		Clock: clock, NewID: func() string {
			authTokenIDs++
			return "r3-auth-token-" + string(rune('0'+authTokenIDs))
		},
		TrustPersonServer: func(_ context.Context, issuer string) error {
			if issuer != personServerID {
				return errors.New("untrusted Person Server")
			}
			return nil
		},
		Authorize: func(_ context.Context, request accessserver.AuthorizationRequest) (accessserver.Decision, error) {
			if request.MCPR3 == nil || !request.MCPR3.Document.OperationSet().Equal(requestedOperations) ||
				!slices.Equal(request.Scopes, requiredScopes) {
				return accessserver.Decision{}, errors.New("unexpected R3 policy input")
			}
			granted, err := r3.NewGrantedOperations(read)
			if err != nil {
				return accessserver.Decision{}, err
			}
			emptyPerCall, err := r3.NewGrantedOperations()
			if err != nil {
				return accessserver.Decision{}, err
			}
			authorization, err := r3.NewAuthorization(granted, emptyPerCall, request.MCPR3.Document)
			if err != nil {
				return accessserver.Decision{}, err
			}
			return accessserver.Decision{Scopes: append([]string(nil), request.Scopes...), Lifetime: 30 * time.Minute, MCPR3Authorization: &authorization}, nil
		},
		MCPR3: &accessserver.MCPR3Config{
			HTTPClient: httpClient,
			Admit: func(_ context.Context, endpoint string) error {
				if !strings.HasPrefix(endpoint, resourceID+"/r3/") {
					return errors.New("unexpected R3 document endpoint")
				}
				return nil
			},
			Issuances: issuances,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	personTokens := newMemoryPersonTokenStore()
	consentCalls := 0
	people, err := personserver.NewFederatedAuthorization(personserver.FederatedAuthorizationConfig{
		Issuer: personServerID, SigningKey: personKey, KeyResolver: resolver,
		Clock: clock, NewID: func() string { return "r3-person-token" },
		HTTPClient: httpClient, Tokens: personTokens,
		AccessServerEndpoint: func(_ context.Context, issuer string) (string, error) {
			if issuer != accessServerID {
				return "", errors.New("unknown Access Server")
			}
			return accessServerID + "/token", nil
		},
		BindPerson: func(_ context.Context, request personserver.PersonTokenRequest) (personserver.Person, error) {
			if request.Agent != agentID || request.Resource != resourceID {
				return personserver.Person{}, errors.New("unexpected person-token request")
			}
			return personserver.Person{Subject: "person-123", Lifetime: time.Hour}, nil
		},
		Consent: func(context.Context, personserver.AuthorizationRequest) error {
			return errors.New("Core consent must not receive an R3 request")
		},
		MCPR3: &personserver.MCPR3Config{
			Admit: func(_ context.Context, endpoint string) error {
				if !strings.HasPrefix(endpoint, resourceID+"/r3/") {
					return errors.New("unexpected R3 document endpoint")
				}
				return nil
			},
			Consent: func(_ context.Context, request personserver.AuthorizationRequest, _ r3.Reference, document r3.Document) error {
				consentCalls++
				gotDisplay, hasDisplay := document.Display()
				if request.Account == nil || *request.Account != account || !slices.Equal(request.Scopes, requiredScopes) ||
					!document.OperationSet().Equal(requestedOperations) || !hasDisplay || gotDisplay.Summary() != display.Summary() {
					return errors.New("unexpected R3 consent input")
				}
				return nil
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	personFetches, accessFetches := 0, 0
	network.Handle(agentProviderID, provider.Handler())
	network.Handle(personServerID, people.Handler())
	network.Handle(accessServerID, access.Handler())
	network.Handle(resourceID, http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if strings.HasPrefix(request.URL.Path, "/r3/") {
			signature := request.Header.Get("Signature-Key")
			switch {
			case strings.Contains(signature, aauth.PersonDiscoveryDocument):
				personFetches++
			case strings.Contains(signature, aauth.AccessDiscoveryDocument):
				accessFetches++
			}
		}
		protectedResource.Handler().ServeHTTP(response, request)
	}))
	agent, err := clientagent.New(ctx, clientagent.Config{
		Identifier: agentID, SigningKey: agentKey, AgentToken: agentToken,
		KeyResolver: resolver, HTTPClient: httpClient, Clock: clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	personResult, err := agent.PersonToken(ctx, clientagent.PersonTokenRequest{
		PersonServer: personServerID, Resource: resourceID,
	})
	if err != nil {
		t.Fatal(err)
	}
	personToken, ok := personResult.Token()
	if !ok {
		t.Fatalf("person-token result = %#v", personResult)
	}
	resourceToken, err := agent.Authorize(ctx, clientagent.AuthorizeRequest{
		Resource: resourceID, PersonToken: personToken,
		Account: &account, MCPR3Operations: &requestedOperations,
	})
	if err != nil {
		t.Fatal(err)
	}
	authToken, err := agent.Exchange(ctx, clientagent.ExchangeRequest{
		PersonServer: personServerID, ResourceToken: resourceToken,
	})
	if err != nil {
		t.Fatal(err)
	}
	request, _ := http.NewRequestWithContext(ctx, http.MethodGet, resourceID+"/records/read", nil)
	response, err := agent.Do(ctx, clientagent.Call{Request: request, AuthToken: authToken})
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusOK || protectedCalls != 1 {
		t.Fatalf("granted call = %d, protected calls %d", response.StatusCode, protectedCalls)
	}
	request, _ = http.NewRequestWithContext(ctx, http.MethodGet, resourceID+"/records/export", nil)
	if _, err := agent.Do(ctx, clientagent.Call{Request: request, AuthToken: authToken}); err == nil {
		t.Fatal("ungranted MCP tool reached the application")
	}

	requiredScopes = []string{"records.read"}
	expectedPrincipalScopes = []string{"records.read"}
	mixedResourceToken, err := agent.Authorize(ctx, clientagent.AuthorizeRequest{
		Resource: resourceID, PersonToken: personToken, Scopes: []string{"records.read"},
		Account: &account, MCPR3Operations: &requestedOperations,
	})
	if err != nil {
		t.Fatal(err)
	}
	mixedAuthToken, err := agent.Exchange(ctx, clientagent.ExchangeRequest{
		PersonServer: personServerID, ResourceToken: mixedResourceToken,
	})
	if err != nil {
		t.Fatal(err)
	}
	mixedClaims, _, _, err := r3.VerifyMCPDirectAuthToken(ctx, mixedAuthToken, resolver, clock)
	if err != nil || mixedClaims.Scope != "records.read" {
		t.Fatalf("mixed R3 Auth token = %#v, %v", mixedClaims, err)
	}
	request, _ = http.NewRequestWithContext(ctx, http.MethodGet, resourceID+"/records/read", nil)
	response, err = agent.Do(ctx, clientagent.Call{Request: request, AuthToken: mixedAuthToken})
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusOK || protectedCalls != 2 {
		t.Fatalf("mixed granted call = %d, protected calls %d", response.StatusCode, protectedCalls)
	}
	requiredScopes = []string{"records.write"}
	request, _ = http.NewRequestWithContext(ctx, http.MethodGet, resourceID+"/records/read", nil)
	if _, err := agent.Do(ctx, clientagent.Call{Request: request, AuthToken: mixedAuthToken}); err == nil {
		t.Fatal("MCP grant bypassed the independently required Core scope")
	}
	if protectedCalls != 2 || consentCalls != 2 || personFetches != 2 || accessFetches != 2 || documents.loadCount() != 4 {
		t.Fatalf("calls protected/consent/PS-fetch/AS-fetch/document-load = %d/%d/%d/%d/%d", protectedCalls, consentCalls, personFetches, accessFetches, documents.loadCount())
	}
	records := issuances.recordsCopy()
	if len(records) != 2 || records[0].ExactAuthToken != authToken || records[1].ExactAuthToken != mixedAuthToken {
		t.Fatalf("R3 issuance audit = %#v", records)
	}
	if err := issuances.Commit(ctx, records[0]); err != nil || len(issuances.recordsCopy()) != 2 {
		t.Fatalf("exact issuance repeat = %v, %#v", err, issuances.recordsCopy())
	}
	changedIssuance := records[0]
	changedIssuance.Resource = "https://other-resource.example"
	if err := issuances.Commit(ctx, changedIssuance); !errors.Is(err, accessserver.ErrR3IssuanceConflict) {
		t.Fatalf("changed issuance repeat = %v", err)
	}
}

type integrationR3DocumentStore struct {
	mu      sync.Mutex
	records map[string]resource.R3DocumentRecord
	loads   int
}

func newIntegrationR3DocumentStore() *integrationR3DocumentStore {
	return &integrationR3DocumentStore{records: make(map[string]resource.R3DocumentRecord)}
}

func (store *integrationR3DocumentStore) Commit(_ context.Context, record resource.R3DocumentRecord) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if existing, ok := store.records[record.Reference.URI()]; ok {
		if existing.Reference != record.Reference || existing.PersonServer != record.PersonServer ||
			existing.AccessServer != record.AccessServer || !bytes.Equal(existing.ExactJSON, record.ExactJSON) {
			return resource.ErrR3DocumentConflict
		}
		return nil
	}
	record.ExactJSON = append([]byte(nil), record.ExactJSON...)
	store.records[record.Reference.URI()] = record
	return nil
}

func (store *integrationR3DocumentStore) Load(_ context.Context, uri string) (resource.R3DocumentRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.loads++
	record, ok := store.records[uri]
	if !ok {
		return resource.R3DocumentRecord{}, resource.ErrR3DocumentNotFound
	}
	record.ExactJSON = append([]byte(nil), record.ExactJSON...)
	return record, nil
}

func (store *integrationR3DocumentStore) loadCount() int {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.loads
}

type integrationR3IssuanceStore struct {
	mu      sync.Mutex
	records []accessserver.R3IssuanceRecord
}

func (store *integrationR3IssuanceStore) Commit(_ context.Context, record accessserver.R3IssuanceRecord) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	record = cloneIntegrationR3Issuance(record)
	for _, retained := range store.records {
		if retained.AuthTokenReference != record.AuthTokenReference {
			continue
		}
		if !reflect.DeepEqual(retained, record) {
			return accessserver.ErrR3IssuanceConflict
		}
		return nil
	}
	store.records = append(store.records, record)
	return nil
}

func (store *integrationR3IssuanceStore) recordsCopy() []accessserver.R3IssuanceRecord {
	store.mu.Lock()
	defer store.mu.Unlock()
	records := make([]accessserver.R3IssuanceRecord, len(store.records))
	for index, record := range store.records {
		records[index] = cloneIntegrationR3Issuance(record)
	}
	return records
}

func cloneIntegrationR3Issuance(record accessserver.R3IssuanceRecord) accessserver.R3IssuanceRecord {
	record.ExactAuthToken = strings.Clone(record.ExactAuthToken)
	if record.Account != nil {
		account := *record.Account
		record.Account = &account
	}
	return record
}
