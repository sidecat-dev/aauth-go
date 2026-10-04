package integration_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	clientagent "gitlab.com/sidecat-dev/aauth-go/agent"
	"gitlab.com/sidecat-dev/aauth-go/agentprovider"
	"gitlab.com/sidecat-dev/aauth-go/personserver"
	"gitlab.com/sidecat-dev/aauth-go/r3"
	"gitlab.com/sidecat-dev/aauth-go/r3/vocab/mcp"
	"gitlab.com/sidecat-dev/aauth-go/resource"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

func TestR3DirectThreePartyClassAuthorization(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 8, 31, 18, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	const (
		agentProviderID = "https://ap.example"
		agentID         = "aauth:planner@ap.example"
		personServerID  = "https://ps.example"
		resourceID      = "https://resource.example"
		unusedASID      = "https://as.example"
	)

	providerKey := newSigningKey(t, "r3-three-party-provider")
	agentKey := newSigningKey(t, "r3-three-party-agent")
	personKey := newSigningKey(t, "r3-three-party-person")
	resourceKey := newSigningKey(t, "r3-three-party-resource")
	baseNetwork := newLogicalTransport()
	transport := &oneShotR3DigestSubstitutionTransport{base: baseNetwork}
	httpClient := &http.Client{Transport: transport}
	resolver, err := signaturekey.NewHTTPKeyResolver(signaturekey.HTTPKeyResolverConfig{
		Client: httpClient, Clock: clock,
		Admit: func(_ context.Context, endpoint string) error {
			if strings.HasSuffix(endpoint, ".example/.well-known/aauth-agent.json") ||
				strings.HasSuffix(endpoint, ".example/.well-known/aauth-person.json") ||
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
		NewID: func() string { return "r3-three-party-agent-token" },
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

	registry, err := r3.NewRegistry(mcp.Vocabulary())
	if err != nil {
		t.Fatal(err)
	}
	definitions, err := r3.NewDefinitionRegistry(mcp.DefinitionRegistration())
	if err != nil {
		t.Fatal(err)
	}
	readMCP, err := mcp.NewOperation("records.read")
	if err != nil {
		t.Fatal(err)
	}
	exportMCP, err := mcp.NewOperation("records.export")
	if err != nil {
		t.Fatal(err)
	}
	read, err := readMCP.ToR3()
	if err != nil {
		t.Fatal(err)
	}
	export, err := exportMCP.ToR3()
	if err != nil {
		t.Fatal(err)
	}
	requested, err := mcp.NewOperationSet(readMCP, exportMCP)
	if err != nil {
		t.Fatal(err)
	}
	display, err := r3.NewDisplay(
		"Read and export records",
		"Exports may leave the system",
		"Record contents",
		"Exported copies cannot be recalled",
	)
	if err != nil {
		t.Fatal(err)
	}
	definitionSource := mcp.NewToolsListSnapshot(mcp.NewInitialToolsListPage([]byte(`{
		"tools":[
			{"name":"records.read","inputSchema":{"type":"object"}},
			{"name":"records.export","inputSchema":{"type":"object"}}
		]
	}`)))
	definition, err := mcp.ParseDefinition(resourceID+"/mcp", definitionSource)
	if err != nil {
		t.Fatal(err)
	}
	documents := newDirectR3DocumentStore()
	personTokens := newMemoryPersonTokenStore()
	issuances := &integrationR3IssuanceStore{}
	personIDs := []string{"r3-three-party-person-token", "r3-three-party-auth-token"}
	resourceTokenIDs := 0
	policyCalls := 0
	protectedCalls := 0
	accessCalls := 0

	newResource := func() *resource.Server {
		server, err := resource.NewPSAuthorization(resource.PSAuthorizationConfig{
			Issuer: resourceID, SigningKey: resourceKey, KeyResolver: resolver, Clock: clock,
			NewID: func() string {
				resourceTokenIDs++
				return "r3-three-party-resource-token-" + strconv.Itoa(resourceTokenIDs)
			},
			ResolvePerson: func(_ context.Context, identity resource.PersonIdentity, _ resource.PersonContext) error {
				if identity != (resource.PersonIdentity{Issuer: personServerID, Subject: "person-123"}) {
					return errors.New("unexpected Resource person")
				}
				return nil
			},
			R3: &resource.R3Config{
				Registry: registry, Definitions: definitions,
				Vocabularies: []resource.R3VocabularyConfig{{
					Definition: definition,
					DisplayForOperations: func(_ context.Context, operations r3.OperationSet, account *string) (*r3.Display, error) {
						equal, equalErr := operations.Equal(requested)
						if equalErr != nil || !equal || account != nil {
							return nil, errors.New("unexpected direct R3 document input")
						}
						return &display, nil
					},
				}},
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
				if !ok || principal.PersonServer != personServerID || principal.Subject != "person-123" ||
					!principal.Confirmation.Equal(agentKey.PublicJWK()) {
					t.Errorf("direct R3 principal = %#v, present=%t", principal, ok)
				}
				response.WriteHeader(http.StatusNoContent)
			}),
		})
		if err != nil {
			t.Fatal(err)
		}
		return server
	}

	newPersonServer := func() *personserver.Server {
		server, err := personserver.NewPSAuthorization(personserver.PSAuthorizationConfig{
			Issuer: personServerID, SigningKey: personKey, KeyResolver: resolver, Clock: clock,
			Tokens: personTokens,
			NewID: func() string {
				id := personIDs[0]
				personIDs = personIDs[1:]
				return id
			},
			BindPerson: func(_ context.Context, request personserver.PersonTokenRequest) (personserver.Person, error) {
				if request.Agent != agentID || request.Resource != resourceID {
					return personserver.Person{}, errors.New("unexpected person binding")
				}
				return personserver.Person{Subject: "person-123", Lifetime: time.Hour}, nil
			},
			R3: &personserver.DirectR3Config{
				Registry: registry, HTTPClient: httpClient,
				Admit: func(_ context.Context, endpoint string) error {
					if !strings.HasPrefix(endpoint, resourceID+"/r3/") {
						return errors.New("unexpected R3 document endpoint")
					}
					return nil
				},
				AuthorizeDocument: func(_ context.Context, request personserver.AuthorizationRequest, reference r3.Reference, document r3.Document) (personserver.DirectR3Decision, error) {
					policyCalls++
					equal, equalErr := document.OperationSet().Equal(requested)
					shown, shownOK := document.Display()
					if equalErr != nil || !equal || !shownOK || shown.Summary() != display.Summary() ||
						request.Agent != agentID || request.Resource != resourceID || request.Subject != "person-123" ||
						!strings.HasPrefix(reference.URI(), resourceID+"/r3/") {
						return personserver.DirectR3Decision{}, errors.New("unexpected direct R3 policy input")
					}
					granted, err := r3.NewGrantedOperations(mcp.Vocabulary(), read)
					if err != nil {
						return personserver.DirectR3Decision{}, err
					}
					grant, err := r3.NewGrant(granted, document)
					if err != nil {
						return personserver.DirectR3Decision{}, err
					}
					return personserver.DirectR3Decision{
						Lifetime: 30 * time.Minute, Grant: grant,
					}, nil
				},
				Issuances: issuances,
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		return server
	}

	resourceServer := newResource()
	personServer := newPersonServer()
	baseNetwork.Handle(agentProviderID, provider.Handler())
	baseNetwork.Handle(resourceID, resourceServer.Handler())
	baseNetwork.Handle(personServerID, personServer.Handler())
	baseNetwork.Handle(unusedASID, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { accessCalls++ }))

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
		t.Fatal("direct R3 person-token request did not complete")
	}
	resourceToken, err := agent.Authorize(ctx, clientagent.AuthorizeRequest{
		Resource: resourceID, PersonToken: personToken, R3Operations: &requested,
	})
	if err != nil {
		t.Fatal(err)
	}

	transport.SubstituteNextR3DocumentDigest()
	if _, err := agent.Exchange(ctx, clientagent.ExchangeRequest{
		PersonServer: personServerID, ResourceToken: resourceToken, PresentedToken: personToken,
	}); err == nil {
		t.Fatal("direct Person Server accepted a substituted R3 document")
	}
	if policyCalls != 0 || len(issuances.recordsCopy()) != 0 {
		t.Fatalf("substituted document reached policy/issuance: %d/%d", policyCalls, len(issuances.recordsCopy()))
	}

	authToken, err := agent.Exchange(ctx, clientagent.ExchangeRequest{
		PersonServer: personServerID, ResourceToken: resourceToken, PresentedToken: personToken,
	})
	if err != nil {
		t.Fatal(err)
	}
	claims, reference, granted, err := r3.VerifyDirectAuthToken(ctx, registry, authToken, resolver, clock)
	if err != nil {
		t.Fatal(err)
	}
	grantedOperations := granted.Operations()
	resourceClaims, resourceReference, err := r3.VerifyResourceToken(ctx, resourceToken, resolver, clock)
	if err != nil {
		t.Fatal(err)
	}
	if claims.Issuer != personServerID || claims.DWK != aauth.PersonDiscoveryDocument ||
		claims.Audience != resourceID || reference != resourceReference || len(grantedOperations) != 1 ||
		claims.Scope != "" || resourceClaims.Scope != "" ||
		claims.ExpiresAt != now.Add(30*time.Minute).Unix() || claims.ExpiresAt <= resourceClaims.ExpiresAt {
		t.Fatalf("direct R3 Auth token = %#v, %#v, %#v", claims, reference, grantedOperations)
	}
	equal, err := grantedOperations[0].Equal(read)
	records := issuances.recordsCopy()
	agentJKT, _ := agentKey.PublicJWK().Thumbprint()
	wantRecord := r3.IssuanceRecord{
		AuthTokenReference: aauth.TokenReference{Issuer: personServerID, JTI: claims.JTI},
		Resource:           resourceID, R3Reference: reference,
		Vocabulary: mcp.URI, IssuedAt: now, PersonServer: personServerID,
		Subject: "person-123", PresentedJTI: resourceClaims.PresentedJTI,
		AgentJKT: agentJKT, Agent: agentID,
	}
	if err != nil || !equal || policyCalls != 1 || len(records) != 1 ||
		!reflect.DeepEqual(records[0], wantRecord) || accessCalls != 0 {
		t.Fatalf("direct grant/policy/issuance/AS = %t/%v/%d/%#v/%d", equal, err, policyCalls, records, accessCalls)
	}

	// Recomposition must not disturb use of the self-contained issued token or
	// introduce an Access Server. Protected use does not consult the PS or fetch
	// the class document again.
	baseNetwork.Handle(resourceID, newResource().Handler())
	request, _ := http.NewRequestWithContext(ctx, http.MethodGet, resourceID+"/records/read", nil)
	response, err := agent.Do(ctx, clientagent.Call{Request: request, AuthToken: authToken})
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusNoContent || protectedCalls != 1 {
		t.Fatalf("granted direct R3 call = %d, protected=%d", response.StatusCode, protectedCalls)
	}
	request, _ = http.NewRequestWithContext(ctx, http.MethodGet, resourceID+"/records/export", nil)
	if _, err := agent.Do(ctx, clientagent.Call{Request: request, AuthToken: authToken}); err == nil {
		t.Fatal("defined but ungranted direct R3 operation reached the application")
	}
	if protectedCalls != 1 || policyCalls != 1 || len(issuances.recordsCopy()) != 1 || accessCalls != 0 {
		t.Fatalf("final calls protected/policy/issuance/AS = %d/%d/%d/%d", protectedCalls, policyCalls, len(issuances.recordsCopy()), accessCalls)
	}
}

type directR3DocumentStore struct {
	mu      sync.Mutex
	records map[string]resource.R3DocumentRecord
}

func newDirectR3DocumentStore() *directR3DocumentStore {
	return &directR3DocumentStore{records: make(map[string]resource.R3DocumentRecord)}
}

func (store *directR3DocumentStore) Commit(_ context.Context, record resource.R3DocumentRecord) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	owned := record.Clone()
	if retained, ok := store.records[record.Reference.URI()]; ok {
		if !equalDirectR3DocumentRecords(retained, owned) {
			return resource.ErrR3DocumentConflict
		}
		return nil
	}
	store.records[record.Reference.URI()] = owned
	return nil
}

func (store *directR3DocumentStore) Load(_ context.Context, uri string) (resource.R3DocumentRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	record, ok := store.records[uri]
	if !ok {
		return resource.R3DocumentRecord{}, resource.ErrR3DocumentNotFound
	}
	return record.Clone(), nil
}

func equalDirectR3DocumentRecords(left, right resource.R3DocumentRecord) bool {
	return reflect.DeepEqual(left, right)
}

type oneShotR3DigestSubstitutionTransport struct {
	mu    sync.Mutex
	base  http.RoundTripper
	armed bool
}

func (transport *oneShotR3DigestSubstitutionTransport) SubstituteNextR3DocumentDigest() {
	transport.mu.Lock()
	defer transport.mu.Unlock()
	transport.armed = true
}

func (transport *oneShotR3DigestSubstitutionTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	response, err := transport.base.RoundTrip(request)
	if err != nil {
		return nil, err
	}
	transport.mu.Lock()
	substitute := transport.armed && request.Method == http.MethodGet && strings.HasPrefix(request.URL.Path, "/r3/")
	if substitute {
		transport.armed = false
	}
	transport.mu.Unlock()
	if !substitute || response.StatusCode != http.StatusOK {
		return response, nil
	}
	body, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil {
		return nil, err
	}
	body = append(bytes.TrimSpace(body), ' ')
	response.Body = io.NopCloser(bytes.NewReader(body))
	response.ContentLength = int64(len(body))
	response.Header.Set("Content-Length", strconv.Itoa(len(body)))
	return response, nil
}

var _ resource.R3DocumentStore = (*directR3DocumentStore)(nil)
var _ http.RoundTripper = (*oneShotR3DigestSubstitutionTransport)(nil)
