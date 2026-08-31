// The callchaining example runs one immediate two-resource call chain entirely
// in process. Resource 1 receives the original Agent's authorized call, then
// acts as its own Agent to call Resource 2 with the same Person Server.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	clientagent "gitlab.com/sidecat-dev/aauth-go/agent"
	"gitlab.com/sidecat-dev/aauth-go/agentprovider"
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/personserver"
	"gitlab.com/sidecat-dev/aauth-go/resource"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

const (
	originalAgentProviderID = "https://agents.example"
	originalAgentID         = "aauth:reader@agents.example"
	personServerID          = "https://person.example"
	resourceOneID           = "https://orders.example"
	resourceOneAgentID      = "aauth:fulfillment@orders.example"
	resourceOneOwnPS        = "https://orders-person.example"
	resourceTwoID           = "https://inventory.example"
	resourceOneSubject      = "person-at-orders"
	resourceTwoSubject      = "person-at-inventory"
	resourceOneScope        = "orders.fulfill"
	resourceTwoScope        = "inventory.reserve"
)

func main() {
	ctx := context.Background()
	now := time.Date(2026, 8, 30, 22, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	originalProviderKey := newSigningKey("original-agent-provider-key")
	originalAgentKey := newSigningKey("original-agent-key")
	personServerKey := newSigningKey("person-server-key")
	resourceOneProviderKey := newSigningKey("resource-one-provider-key")
	resourceOneResourceKey := newSigningKey("resource-one-resource-key")
	resourceOneAgentKey := newSigningKey("resource-one-agent-key")
	resourceTwoKey := newSigningKey("resource-two-key")

	network := newLogicalTransport()
	httpClient := &http.Client{Transport: network}
	resolver := must(signaturekey.NewHTTPKeyResolver(signaturekey.HTTPKeyResolverConfig{
		Client: httpClient, Clock: clock, Admit: network.Admit,
	}))

	originalProvider := must(agentprovider.New(agentprovider.Config{
		Issuer: originalAgentProviderID, SigningKey: originalProviderKey, Clock: clock,
		NewID: func() string { return "original-agent-token" },
	}))
	originalAgentToken := must(originalProvider.Issue(aauth.AgentTokenRequest{
		Agent: originalAgentID, PersonServer: personServerID,
		PublicKey: originalAgentKey.PublicJWK(), Lifetime: time.Hour,
	}))

	// Resource 1 publishes Agent Provider metadata at its Resource origin. Its
	// Agent Provider and Resource issuer keys remain distinct; the Agent proof
	// key is a third key that signs every downstream protocol request.
	resourceOneProvider := must(agentprovider.New(agentprovider.Config{
		Issuer: resourceOneID, SigningKey: resourceOneProviderKey, Clock: clock,
		NewID: func() string { return "resource-one-agent-token" },
	}))
	resourceOneAgentToken := must(resourceOneProvider.Issue(aauth.AgentTokenRequest{
		Agent: resourceOneAgentID, PersonServer: resourceOneOwnPS,
		PublicKey: resourceOneAgentKey.PublicJWK(), Lifetime: time.Hour,
	}))

	personTokens := newMemoryTokenStore()
	personServerTokenID := 0
	people := must(personserver.NewPSAuthorization(personserver.PSAuthorizationConfig{
		Issuer: personServerID, SigningKey: personServerKey, KeyResolver: resolver,
		Clock: clock, Tokens: personTokens,
		NewID: func() string {
			personServerTokenID++
			return fmt.Sprintf("person-server-token-%d", personServerTokenID)
		},
		BindPerson: func(_ context.Context, request personserver.PersonTokenRequest) (personserver.Person, error) {
			if request.Agent != originalAgentID || request.Resource != resourceOneID || request.Upstream != nil {
				return personserver.Person{}, errors.New("unexpected original person-token request")
			}
			return personserver.Person{Subject: resourceOneSubject, Lifetime: 30 * time.Minute}, nil
		},
		Authorize: func(_ context.Context, request personserver.AuthorizationRequest) (personserver.AuthorizationDecision, error) {
			if request.Agent != originalAgentID || request.Resource != resourceOneID ||
				request.Subject != resourceOneSubject || request.Upstream != nil {
				return personserver.AuthorizationDecision{}, errors.New("unexpected original authorization request")
			}
			return personserver.AuthorizationDecision{Scopes: request.Scopes, Lifetime: 20 * time.Minute}, nil
		},
		CallChaining: &personserver.CallChainingConfig{
			BindPerson: func(_ context.Context, request personserver.PersonTokenRequest) (personserver.Person, error) {
				if request.Agent != resourceOneAgentID || request.Resource != resourceTwoID ||
					!validUpstream(request.Upstream, originalAgentKey.PublicJWK()) {
					return personserver.Person{}, errors.New("unexpected call-chaining person-token request")
				}
				return personserver.Person{Subject: resourceTwoSubject, Lifetime: 25 * time.Minute}, nil
			},
			Authorize: func(_ context.Context, request personserver.AuthorizationRequest) (personserver.AuthorizationDecision, error) {
				if request.Agent != resourceOneAgentID || request.Resource != resourceTwoID ||
					request.Subject != resourceTwoSubject ||
					!slices.Equal(request.Scopes, []string{resourceTwoScope}) ||
					!validUpstream(request.Upstream, originalAgentKey.PublicJWK()) {
					return personserver.AuthorizationDecision{}, errors.New("unexpected call-chaining authorization request")
				}
				return personserver.AuthorizationDecision{Scopes: request.Scopes, Lifetime: 15 * time.Minute}, nil
			},
		},
	}))

	resourceTwo := must(resource.NewPSAuthorization(resource.PSAuthorizationConfig{
		Issuer: resourceTwoID, SigningKey: resourceTwoKey, KeyResolver: resolver, Clock: clock,
		NewID:             func() string { return "resource-two-token" },
		ScopeDescriptions: map[string]string{resourceTwoScope: "Reserve inventory"},
		RequiredScopes:    func(*http.Request) []string { return []string{resourceTwoScope} },
		ResolvePerson: func(_ context.Context, identity resource.PersonIdentity, _ resource.PersonContext) error {
			if identity != (resource.PersonIdentity{Issuer: personServerID, Subject: resourceTwoSubject}) {
				return errors.New("unrecognized inventory person")
			}
			return nil
		},
		Protected: http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			principal, ok := resource.AuthPrincipalFromContext(request.Context())
			if !ok || principal.Subject != resourceTwoSubject ||
				!principal.Confirmation.Equal(resourceOneAgentKey.PublicJWK()) ||
				!slices.Equal(principal.Scope, []string{resourceTwoScope}) {
				http.Error(response, "invalid inventory authorization", http.StatusInternalServerError)
				return
			}
			_, _ = io.WriteString(response, resourceTwoScope)
		}),
	}))

	// The relay client must first resolve Resource 1 as an Agent Provider. Once
	// constructed, the same origin is replaced with the collocated Agent and
	// Resource handler below.
	network.Handle(originalAgentProviderID, originalProvider.Handler())
	network.Handle(personServerID, people.Handler())
	network.Handle(resourceTwoID, resourceTwo.Handler())
	network.Handle(resourceOneID, resourceOneProvider.Handler())
	relay := must(clientagent.New(ctx, clientagent.Config{
		Identifier: resourceOneAgentID, SigningKey: resourceOneAgentKey,
		AgentToken: resourceOneAgentToken, KeyResolver: resolver,
		HTTPClient: httpClient, Clock: clock,
	}))

	resourceOne := must(resource.NewPSAuthorization(resource.PSAuthorizationConfig{
		Issuer: resourceOneID, SigningKey: resourceOneResourceKey, KeyResolver: resolver, Clock: clock,
		NewID:             func() string { return "resource-one-token" },
		ScopeDescriptions: map[string]string{resourceOneScope: "Fulfill orders"},
		RequiredScopes:    func(*http.Request) []string { return []string{resourceOneScope} },
		ResolvePerson: func(_ context.Context, identity resource.PersonIdentity, _ resource.PersonContext) error {
			if identity != (resource.PersonIdentity{Issuer: personServerID, Subject: resourceOneSubject}) {
				return errors.New("unrecognized orders person")
			}
			return nil
		},
		Protected: http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			upstreamToken, ok := resource.AuthTokenFromContext(request.Context())
			if !ok {
				http.Error(response, "missing upstream authorization", http.StatusInternalServerError)
				return
			}
			result, err := callInventory(request.Context(), relay, upstreamToken)
			if err != nil {
				http.Error(response, err.Error(), http.StatusBadGateway)
				return
			}
			fmt.Fprintf(
				response,
				"AAuth two-resource call chain complete: %s used %s.\n",
				resourceOneScope,
				result,
			)
		}),
	}))
	providerHandler := resourceOneProvider.Handler()
	resourceHandler := resourceOne.Handler()
	network.Handle(resourceOneID, http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Method == http.MethodGet {
			switch request.URL.Path {
			case "/.well-known/aauth-agent.json":
				providerHandler.ServeHTTP(response, request)
				return
			case "/.well-known/jwks.json":
				response.Header().Set("Content-Type", "application/json")
				if err := json.NewEncoder(response).Encode(map[string]any{
					"keys": []jose.JWK{resourceOneProviderKey.PublicJWK(), resourceOneResourceKey.PublicJWK()},
				}); err != nil {
					http.Error(response, "encode collocated JWKS", http.StatusInternalServerError)
				}
				return
			}
		}
		resourceHandler.ServeHTTP(response, request)
	}))

	originalAgent := must(clientagent.New(ctx, clientagent.Config{
		Identifier: originalAgentID, SigningKey: originalAgentKey,
		AgentToken: originalAgentToken, KeyResolver: resolver,
		HTTPClient: httpClient, Clock: clock,
	}))
	personResult := must(originalAgent.PersonToken(ctx, clientagent.PersonTokenRequest{
		PersonServer: personServerID, Resource: resourceOneID,
	}))
	personToken, ok := personResult.Token()
	if !ok {
		log.Fatal("example Person Server unexpectedly required interaction")
	}
	resourceToken := must(originalAgent.Authorize(ctx, clientagent.AuthorizeRequest{
		Resource: resourceOneID, PersonToken: personToken, Scopes: []string{resourceOneScope},
	}))
	authToken := must(originalAgent.Exchange(ctx, clientagent.ExchangeRequest{
		PersonServer: personServerID, ResourceToken: resourceToken,
	}))
	request := must(http.NewRequestWithContext(ctx, http.MethodPost, resourceOneID+"/orders/42/fulfill", nil))
	response := must(originalAgent.Do(ctx, clientagent.Call{Request: request, AuthToken: authToken}))
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(response.Body)
		log.Fatalf("orders call returned %s: %s", response.Status, body)
	}
	_, _ = io.Copy(os.Stdout, response.Body)
}

func callInventory(ctx context.Context, relay *clientagent.Client, upstreamToken string) (string, error) {
	personResult, err := relay.PersonToken(ctx, clientagent.PersonTokenRequest{
		Resource: resourceTwoID, UpstreamToken: upstreamToken,
	})
	if err != nil {
		return "", err
	}
	personToken, ok := personResult.Token()
	if !ok {
		return "", errors.New("Person Server unexpectedly required interaction")
	}
	resourceToken, err := relay.Authorize(ctx, clientagent.AuthorizeRequest{
		Resource: resourceTwoID, PersonToken: personToken,
		Scopes: []string{resourceTwoScope}, UpstreamToken: upstreamToken,
	})
	if err != nil {
		return "", err
	}
	authToken, err := relay.Exchange(ctx, clientagent.ExchangeRequest{
		ResourceToken: resourceToken, UpstreamToken: upstreamToken,
	})
	if err != nil {
		return "", err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, resourceTwoID+"/inventory/42/reserve", nil)
	if err != nil {
		return "", err
	}
	response, err := relay.Do(ctx, clientagent.Call{
		Request: request, AuthToken: authToken, UpstreamToken: upstreamToken,
	})
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return "", err
	}
	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("inventory call returned %s: %s", response.Status, body)
	}
	return string(body), nil
}

func validUpstream(claims *aauth.AuthTokenClaims, originalAgentKey jose.JWK) bool {
	return claims != nil &&
		claims.Issuer == personServerID &&
		claims.Audience == resourceOneID &&
		claims.PersonServer == personServerID &&
		claims.Subject == resourceOneSubject &&
		slices.Equal(strings.Fields(claims.Scope), []string{resourceOneScope}) &&
		claims.Confirmation.JWK.Equal(originalAgentKey)
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
