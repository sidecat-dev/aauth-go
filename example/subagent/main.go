// The subagent example runs immediate parent-mediated authorization entirely
// in process. The parent calls the Person Server; the child calls the Resource.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"time"

	aauth "aauth-go"
	clientagent "aauth-go/agent"
	"aauth-go/agentprovider"
	"aauth-go/jose"
	"aauth-go/personserver"
	"aauth-go/resource"
	"aauth-go/signaturekey"
)

const (
	agentProviderID = "https://agents.example"
	parentAgentID   = "aauth:planner@agents.example"
	childAgentID    = "aauth:planner+search@agents.example"
	personServerID  = "https://person.example"
	resourceID      = "https://resource.example"
	scope           = "records.read"
)

func main() {
	now := time.Date(2026, 8, 30, 20, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	providerKey := newSigningKey("agent-provider-key")
	parentKey := newSigningKey("parent-key")
	childKey := newSigningKey("child-key")
	personKey := newSigningKey("person-server-key")
	resourceKey := newSigningKey("resource-key")
	network := newLogicalTransport()
	httpClient := &http.Client{Transport: network}
	resolver := must(signaturekey.NewHTTPKeyResolver(signaturekey.HTTPKeyResolverConfig{
		Client: httpClient, Clock: clock, Admit: network.Admit,
	}))

	provider := must(agentprovider.New(agentprovider.Config{
		Issuer: agentProviderID, SigningKey: providerKey, Clock: clock,
		NewID: func() string { return "parent-token" },
	}))
	parentToken := must(provider.Issue(aauth.AgentTokenRequest{
		Agent: parentAgentID, PersonServer: personServerID,
		PublicKey: parentKey.PublicJWK(), Lifetime: time.Hour,
	}))
	// How a platform acquires the child's agent token belongs to Bootstrap.
	// This Core example starts with the exact one-level credential it needs.
	childToken := must(aauth.MintAgentToken(agentProviderID, providerKey, aauth.AgentTokenRequest{
		Agent: childAgentID, ParentAgent: parentAgentID,
		PublicKey: childKey.PublicJWK(), Lifetime: 30 * time.Minute,
	}, now, "child-token"))

	ids := []string{"person-token", "auth-token"}
	people := must(personserver.NewPSAuthorization(personserver.PSAuthorizationConfig{
		Issuer: personServerID, SigningKey: personKey, KeyResolver: resolver,
		Clock: clock, Tokens: newMemoryTokenStore(),
		NewID: func() string {
			id := ids[0]
			ids = ids[1:]
			return id
		},
		BindPerson: func(_ context.Context, request personserver.PersonTokenRequest) (personserver.Person, error) {
			if request.Agent != parentAgentID || request.Subagent != childAgentID || request.Resource != resourceID {
				return personserver.Person{}, errors.New("unexpected parent-mediated person-token request")
			}
			return personserver.Person{Subject: "person-123", Lifetime: 20 * time.Minute}, nil
		},
		Authorize: func(_ context.Context, request personserver.AuthorizationRequest) (personserver.AuthorizationDecision, error) {
			if request.Agent != parentAgentID || request.Subagent != childAgentID {
				return personserver.AuthorizationDecision{}, errors.New("unexpected parent-mediated authorization request")
			}
			return personserver.AuthorizationDecision{Scopes: request.Scopes, Lifetime: 15 * time.Minute}, nil
		},
	}))
	protected := http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		principal, ok := resource.AuthPrincipalFromContext(request.Context())
		if !ok || !principal.Confirmation.Equal(childKey.PublicJWK()) {
			http.Error(response, "missing child-bound principal", http.StatusInternalServerError)
			return
		}
		fmt.Fprintf(response, "AAuth parent-mediated sub-agent flow complete: %s has %s\n", principal.Subject, principal.Scope[0])
	})
	protectedResource := must(resource.NewPSAuthorization(resource.PSAuthorizationConfig{
		Issuer: resourceID, SigningKey: resourceKey, KeyResolver: resolver, Clock: clock,
		NewID:             func() string { return "resource-token" },
		ScopeDescriptions: map[string]string{scope: "Read records"},
		RequiredScopes:    func(*http.Request) []string { return []string{scope} },
		ResolvePerson: func(_ context.Context, identity resource.PersonIdentity, _ resource.PersonContext) error {
			if identity.Issuer != personServerID || identity.Subject == "" {
				return errors.New("unrecognized person identity")
			}
			return nil
		},
		Protected: protected,
	}))
	network.Handle(agentProviderID, provider.Handler())
	network.Handle(personServerID, people.Handler())
	network.Handle(resourceID, protectedResource.Handler())

	parent := must(clientagent.New(context.Background(), clientagent.Config{
		Identifier: parentAgentID, SigningKey: parentKey, AgentToken: parentToken,
		KeyResolver: resolver, HTTPClient: httpClient, Clock: clock,
	}))
	child := must(clientagent.New(context.Background(), clientagent.Config{
		Identifier: childAgentID, SigningKey: childKey, AgentToken: childToken,
		KeyResolver: resolver, HTTPClient: httpClient, Clock: clock,
	}))
	ctx := context.Background()
	personResult := must(parent.PersonToken(ctx, clientagent.PersonTokenRequest{
		PersonServer: personServerID, Resource: resourceID, SubagentToken: childToken,
	}))
	personToken, ok := personResult.Token()
	if !ok {
		log.Fatal("example Person Server unexpectedly required interaction")
	}
	resourceToken := must(child.Authorize(ctx, clientagent.AuthorizeRequest{
		Resource: resourceID, PersonToken: personToken, Scopes: []string{scope},
	}))
	authToken := must(parent.Exchange(ctx, clientagent.ExchangeRequest{
		PersonServer: personServerID, ResourceToken: resourceToken, SubagentToken: childToken,
	}))
	request := must(http.NewRequestWithContext(ctx, http.MethodGet, resourceID+"/records/42", nil))
	response := must(child.Do(ctx, clientagent.Call{Request: request, AuthToken: authToken}))
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		log.Fatalf("protected call returned %s", response.Status)
	}
	_, _ = io.Copy(os.Stdout, response.Body)
}

func newSigningKey(id string) jose.SigningKey {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	return must(jose.NewEd25519SigningKey(id, privateKey))
}

func must[T any](value T, err error) T {
	if err != nil {
		log.Fatal(err)
	}
	return value
}

type memoryTokenStore struct {
	mu      sync.Mutex
	records map[string]personserver.PersonTokenRecord
}

func newMemoryTokenStore() *memoryTokenStore {
	return &memoryTokenStore{records: make(map[string]personserver.PersonTokenRecord)}
}

func (store *memoryTokenStore) Commit(_ context.Context, record personserver.PersonTokenRecord) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	key := record.PersonServer + "\x00" + record.JTI
	if _, exists := store.records[key]; exists {
		return errors.New("person-token record already exists")
	}
	store.records[key] = record
	return nil
}

func (store *memoryTokenStore) Load(_ context.Context, issuer, tokenID string) (personserver.PersonTokenRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	record, ok := store.records[issuer+"\x00"+tokenID]
	if !ok {
		return personserver.PersonTokenRecord{}, personserver.ErrPersonTokenNotFound
	}
	return record, nil
}

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

func (transport *logicalTransport) Admit(_ context.Context, endpoint string) error {
	request, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	origin := request.URL.Scheme + "://" + request.URL.Host
	transport.mu.RLock()
	_, ok := transport.routes[origin]
	transport.mu.RUnlock()
	if !ok {
		return fmt.Errorf("discovery is not admitted for %s", origin)
	}
	return nil
}

func (transport *logicalTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	origin := request.URL.Scheme + "://" + request.URL.Host
	transport.mu.RLock()
	handler := transport.routes[origin]
	transport.mu.RUnlock()
	if handler == nil {
		return nil, fmt.Errorf("no handler for %s", origin)
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	response := recorder.Result()
	response.Request = request
	return response, nil
}
