package integration_test

import (
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

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/accessserver"
	clientagent "gitlab.com/sidecat-dev/aauth-go/agent"
	"gitlab.com/sidecat-dev/aauth-go/agentprovider"
	"gitlab.com/sidecat-dev/aauth-go/budgets"
	"gitlab.com/sidecat-dev/aauth-go/personserver"
	"gitlab.com/sidecat-dev/aauth-go/r3"
	"gitlab.com/sidecat-dev/aauth-go/resource"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

func TestR3DirectFourPartyJourney(t *testing.T) {
	t.Parallel()
	for _, vocabulary := range integrationR3Vocabularies() {
		vocabulary := vocabulary
		t.Run(vocabulary.name, func(t *testing.T) {
			t.Parallel()
			testR3DirectFourPartyJourney(t, vocabulary, false)
		})
	}
}

func TestR3BudgetFourPartyJourney(t *testing.T) {
	t.Parallel()
	testR3DirectFourPartyJourney(t, integrationR3Vocabularies()[0], true)
}

func testR3DirectFourPartyJourney(t *testing.T, vocabulary integrationR3Vocabulary, withBudget bool) {
	ctx := context.Background()
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	registry := newIntegrationR3Registry(t)
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
	read := vocabulary.newOperation(t, "records.read")
	export := vocabulary.newOperation(t, "records.export")
	requestedOperations, _ := r3.NewOperationSet(read, export)
	display, _ := r3.NewDisplay(
		"Read and export records",
		"Exported records may leave the system",
		"Record contents",
		"Exported copies cannot be recalled",
	)
	var accountInput *string
	if !withBudget {
		accountInput = &account
	}
	var requestedBudget, resourceOffer, personCeiling, accessGrant budgets.Value
	var budgetDeclaration budgets.UnitDeclaration
	var budgetLedger *integrationBudgetStore
	var resourceBudget *resource.BudgetConfig
	if withBudget {
		unit, err := budgets.NewUnit("USD", 6)
		if err != nil {
			t.Fatal(err)
		}
		requestedBudget = integrationBudgetValue(t, 800_000, unit)
		resourceOffer = integrationBudgetValue(t, 600_000, unit)
		personCeiling = integrationBudgetValue(t, 450_000, unit)
		accessGrant = integrationBudgetValue(t, 300_000, unit)
		budgetDeclaration, err = budgets.NewBoundedUnitDeclaration(unit, 1_000_000, "US dollars at micro-dollar precision")
		if err != nil {
			t.Fatal(err)
		}
		budgetLedger = newIntegrationBudgetStore()
		resourceBudget = &resource.BudgetConfig{
			Units: []budgets.UnitDeclaration{budgetDeclaration},
			Offer: func(_ context.Context, request resource.BudgetOfferRequest) (budgets.Value, error) {
				if !integrationSameBudget(request.Requested, requestedBudget) {
					return budgets.Value{}, errors.New("unexpected R3 Budget request")
				}
				return resourceOffer, nil
			},
			RetainLineage: func(context.Context, resource.BudgetLineage) error { return nil },
			Cost: func(_ context.Context, request resource.BudgetCostRequest) (int64, error) {
				if !integrationSameBudget(request.Grant, accessGrant) {
					return 0, errors.New("unexpected R3 Budget grant")
				}
				return 125_000, nil
			},
			Store: budgetLedger,
			Challenge: func(context.Context, resource.BudgetChallengeRequest) (string, error) {
				return "", errors.New("R3 Budget step-up is outside this journey")
			},
		}
	}
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
		R3: &resource.R3Config{
			Registry:    registry,
			Definitions: newIntegrationR3DefinitionRegistry(t),
			Vocabularies: integrationR3ResourceVocabularies(
				t, resourceID, []string{"records.read", "records.export"}, accountInput, &display,
			),
			Documents: documents,
			HTTP: resource.R3HTTPAdapter{OperationForRequest: func(request *http.Request) (r3.Operation, bool, error) {
				switch request.URL.Path {
				case "/records/read":
					return read, true, nil
				case "/records/export":
					return export, true, nil
				default:
					return r3.Operation{}, false, nil
				}
			}},
		},
		Protected: http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			protectedCalls++
			principal, ok := resource.AuthPrincipalFromContext(request.Context())
			accountMatches := withBudget && principal.Account == nil ||
				!withBudget && principal.Account != nil && *principal.Account == account
			if !ok || !accountMatches || !slices.Equal(principal.Scope, expectedPrincipalScopes) {
				t.Fatalf("R3 principal = %#v, %t", principal, ok)
			}
			response.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(response, `{"ok":true}`)
		}),
		Budget: resourceBudget,
	})
	if err != nil {
		t.Fatal(err)
	}
	requireIntegrationR3ResourceMetadata(t, protectedResource.Handler(), resourceID)

	issuances := &integrationR3IssuanceStore{}
	authTokenIDs := 0
	var accessBudget *accessserver.BudgetConfig
	if withBudget {
		accessBudget = &accessserver.BudgetConfig{ResolveResourceUnits: func(_ context.Context, resource string) ([]budgets.UnitDeclaration, error) {
			if resource != resourceID {
				return nil, errors.New("unexpected Resource metadata request")
			}
			return []budgets.UnitDeclaration{budgetDeclaration}, nil
		}}
	}
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
			return accessserver.Decision{}, errors.New("Core policy must not receive an R3 request")
		},
		R3: &accessserver.R3Config{
			Registry:   registry,
			HTTPClient: httpClient,
			Admit: func(_ context.Context, endpoint string) error {
				if !strings.HasPrefix(endpoint, resourceID+"/r3/") {
					return errors.New("unexpected R3 document endpoint")
				}
				return nil
			},
			AuthorizeDocument: func(_ context.Context, request accessserver.AuthorizationRequest, _ r3.Reference, document r3.Document) (accessserver.R3DocumentDecision, error) {
				if !vocabulary.operationSetsEqual(t, document.OperationSet(), requestedOperations) ||
					!slices.Equal(request.Scopes, requiredScopes) || withBudget &&
					(request.Budget == nil || !integrationSameBudget(*request.Budget, personCeiling)) {
					return accessserver.R3DocumentDecision{}, errors.New("unexpected R3 policy input")
				}
				granted, err := r3.NewGrantedOperations(vocabulary.registration, read)
				if err != nil {
					return accessserver.R3DocumentDecision{}, err
				}
				emptyPerCall, err := r3.NewGrantedOperations(vocabulary.registration)
				if err != nil {
					return accessserver.R3DocumentDecision{}, err
				}
				authorization, err := r3.NewAuthorization(granted, emptyPerCall, document)
				if err != nil {
					return accessserver.R3DocumentDecision{}, err
				}
				return accessserver.R3DocumentDecision{
					Scopes:        append([]string(nil), request.Scopes...),
					Lifetime:      30 * time.Minute,
					Authorization: &authorization,
					Budget:        cloneIntegrationBudget(withBudget, accessGrant),
				}, nil
			},
			Issuances: issuances,
		},
		Budget: accessBudget,
	})
	if err != nil {
		t.Fatal(err)
	}
	personTokens := newMemoryPersonTokenStore()
	consentCalls := 0
	var personBudget *personserver.FederatedBudgetConfig
	if withBudget {
		personBudget = &personserver.FederatedBudgetConfig{
			ResolveResourceUnits: func(_ context.Context, resource string) ([]budgets.UnitDeclaration, error) {
				if resource != resourceID {
					return nil, errors.New("unexpected Resource metadata request")
				}
				return []budgets.UnitDeclaration{budgetDeclaration}, nil
			},
			Ceiling: func(_ context.Context, request personserver.AuthorizationRequest) (*budgets.Value, error) {
				if request.Budget == nil || !integrationSameBudget(*request.Budget, resourceOffer) {
					return nil, errors.New("unexpected R3 Budget offer")
				}
				return &personCeiling, nil
			},
		}
	}
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
		R3: &personserver.R3Config{
			Registry: registry,
			Admit: func(_ context.Context, endpoint string) error {
				if !strings.HasPrefix(endpoint, resourceID+"/r3/") {
					return errors.New("unexpected R3 document endpoint")
				}
				return nil
			},
			ConsentDocument: func(_ context.Context, request personserver.AuthorizationRequest, _ r3.Reference, document r3.Document) error {
				consentCalls++
				gotDisplay, hasDisplay := document.Display()
				if !equalIntegrationStringPointers(request.Account, accountInput) || !slices.Equal(request.Scopes, requiredScopes) ||
					withBudget && (request.Budget == nil || !integrationSameBudget(*request.Budget, resourceOffer)) ||
					!vocabulary.operationSetsEqual(t, document.OperationSet(), requestedOperations) || !hasDisplay || gotDisplay.Summary() != display.Summary() {
					return errors.New("unexpected R3 consent input")
				}
				return nil
			},
		},
		Budget: personBudget,
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
		R3: &clientagent.R3Config{Registry: registry},
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
		Account: accountInput, R3Operations: &requestedOperations,
		Budget: cloneIntegrationBudget(withBudget, requestedBudget),
	})
	if err != nil {
		t.Fatal(err)
	}
	authToken, err := agent.Exchange(ctx, clientagent.ExchangeRequest{
		PersonServer: personServerID, ResourceToken: resourceToken, PresentedToken: personToken,
	})
	if err != nil {
		t.Fatal(err)
	}
	var authClaims aauth.AuthTokenClaims
	if withBudget {
		var grant budgets.Value
		authClaims, _, _, grant, err = r3.VerifyBudgetAuthToken(ctx, registry, authToken, resolver, clock)
		if err == nil && !integrationSameBudget(grant, accessGrant) {
			err = errors.New("unexpected Access Server R3 Budget grant")
		}
	} else {
		authClaims, _, _, err = r3.VerifyDirectAuthToken(ctx, registry, authToken, resolver, clock)
	}
	if err != nil {
		t.Fatal(err)
	}
	if withBudget {
		ungranted, _ := http.NewRequestWithContext(ctx, http.MethodGet, resourceID+"/records/export", nil)
		refused, err := agent.BeginBudgetCall(ctx, clientagent.BudgetCall{Request: ungranted, AuthToken: authToken})
		if err != nil {
			t.Fatal(err)
		}
		if response, ok := refused.Response(); !ok || response.StatusCode != http.StatusForbidden {
			t.Fatalf("ungranted operation=%#v", refused)
		} else {
			response.Body.Close()
		}
		feedback := integrationBudgetFeedback(t, refused)
		if cost, ok := feedback.Cost(); !ok || cost != 0 || feedback.Remaining() != accessGrant.Amount() {
			t.Fatalf("ungranted operation feedback=%#v", feedback)
		}
		if total := budgetLedger.personTotal(personServerID, "person-123", resourceID); total != 0 || protectedCalls != 0 {
			t.Fatalf("ungranted R3 Budget operation charged/dispatched = %d/%d", total, protectedCalls)
		}
	}
	request, _ := http.NewRequestWithContext(ctx, http.MethodGet, resourceID+"/records/read", nil)
	var response *http.Response
	if withBudget {
		result, callErr := agent.BeginBudgetCall(ctx, clientagent.BudgetCall{Request: request, AuthToken: authToken})
		err = callErr
		response, _ = result.Response()
		if feedback, ok := result.Feedback(); callErr == nil && (!ok || feedback.Remaining() != 175_000) {
			err = errors.New("unexpected R3 Budget feedback")
		}
	} else {
		response, err = agent.Do(ctx, clientagent.Call{Request: request, AuthToken: authToken})
	}
	if err != nil {
		t.Fatal(err)
	}
	if response == nil {
		t.Fatal("granted R3 call returned no response")
	}
	response.Body.Close()
	if response.StatusCode != http.StatusOK || protectedCalls != 1 {
		t.Fatalf("granted call = %d, protected calls %d", response.StatusCode, protectedCalls)
	}
	if withBudget {
		if total := budgetLedger.personTotal(personServerID, "person-123", resourceID); total != 125_000 {
			t.Fatalf("R3 Budget charge = %d, want 125000", total)
		}
		records := issuances.recordsCopy()
		if len(records) != 1 || records[0].AuthTokenReference != (aauth.TokenReference{Issuer: authClaims.Issuer, JTI: authClaims.JTI}) {
			t.Fatalf("R3 Budget issuance audit = %#v", records)
		}
		return
	}
	request, _ = http.NewRequestWithContext(ctx, http.MethodGet, resourceID+"/records/export", nil)
	if _, err := agent.Do(ctx, clientagent.Call{Request: request, AuthToken: authToken}); err == nil {
		t.Fatal("ungranted R3 operation reached the application")
	}

	requiredScopes = []string{"records.read"}
	expectedPrincipalScopes = []string{"records.read"}
	mixedResourceToken, err := agent.Authorize(ctx, clientagent.AuthorizeRequest{
		Resource: resourceID, PersonToken: personToken, Scopes: []string{"records.read"},
		Account: &account, R3Operations: &requestedOperations,
	})
	if err != nil {
		t.Fatal(err)
	}
	mixedAuthToken, err := agent.Exchange(ctx, clientagent.ExchangeRequest{
		PersonServer: personServerID, ResourceToken: mixedResourceToken, PresentedToken: personToken,
	})
	if err != nil {
		t.Fatal(err)
	}
	mixedClaims, _, _, err := r3.VerifyDirectAuthToken(ctx, registry, mixedAuthToken, resolver, clock)
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
		t.Fatal("R3 grant bypassed the independently required Core scope")
	}
	if protectedCalls != 2 || consentCalls != 2 || personFetches != 2 || accessFetches != 2 || documents.loadCount() != 4 {
		t.Fatalf("calls protected/consent/PS-fetch/AS-fetch/document-load = %d/%d/%d/%d/%d", protectedCalls, consentCalls, personFetches, accessFetches, documents.loadCount())
	}
	records := issuances.recordsCopy()
	if len(records) != 2 ||
		records[0].AuthTokenReference != (aauth.TokenReference{Issuer: authClaims.Issuer, JTI: authClaims.JTI}) ||
		records[1].AuthTokenReference != (aauth.TokenReference{Issuer: mixedClaims.Issuer, JTI: mixedClaims.JTI}) {
		t.Fatalf("R3 issuance audit = %#v", records)
	}
	if err := issuances.Commit(ctx, records[0]); err != nil || len(issuances.recordsCopy()) != 2 {
		t.Fatalf("exact issuance repeat = %v, %#v", err, issuances.recordsCopy())
	}
	changedIssuance := records[0]
	changedIssuance.Resource = "https://other-resource.example"
	if err := issuances.Commit(ctx, changedIssuance); !errors.Is(err, r3.ErrIssuanceConflict) {
		t.Fatalf("changed issuance repeat = %v", err)
	}
}

func cloneIntegrationBudget(enabled bool, value budgets.Value) *budgets.Value {
	if !enabled {
		return nil
	}
	return &value
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
	owned := record.Clone()
	if existing, ok := store.records[record.Reference.URI()]; ok {
		if !reflect.DeepEqual(existing, owned) {
			return resource.ErrR3DocumentConflict
		}
		return nil
	}
	store.records[record.Reference.URI()] = owned
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
	return record.Clone(), nil
}

func (store *integrationR3DocumentStore) loadCount() int {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.loads
}

type integrationR3IssuanceStore struct {
	mu      sync.Mutex
	records []r3.IssuanceRecord
}

func (store *integrationR3IssuanceStore) Commit(_ context.Context, record r3.IssuanceRecord) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	record = cloneIntegrationR3Issuance(record)
	for _, retained := range store.records {
		if retained.AuthTokenReference != record.AuthTokenReference {
			continue
		}
		if !reflect.DeepEqual(retained, record) {
			return r3.ErrIssuanceConflict
		}
		return nil
	}
	store.records = append(store.records, record)
	return nil
}

func (store *integrationR3IssuanceStore) recordsCopy() []r3.IssuanceRecord {
	store.mu.Lock()
	defer store.mu.Unlock()
	records := make([]r3.IssuanceRecord, len(store.records))
	for index, record := range store.records {
		records[index] = cloneIntegrationR3Issuance(record)
	}
	return records
}

func cloneIntegrationR3Issuance(record r3.IssuanceRecord) r3.IssuanceRecord {
	if record.Account != nil {
		account := *record.Account
		record.Account = &account
	}
	return record
}
