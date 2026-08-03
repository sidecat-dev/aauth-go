package eventsjourney_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/reference"
)

func TestPublicSubscriptionEventSurvivesHostReconstruction(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 8, 3, 3, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	ids := sequentialIDs("agent-token", "event-1", "delivery-1")

	apKey := testSigningKey(t, "ap-key")
	resourceKey := testSigningKey(t, "resource-key")
	agentKey := testSigningKey(t, "agent-key")
	agentID := "aauth:subscriber@ap.example"
	apID := "https://ap.example"
	resourceID := "https://resource.example"

	apStore := reference.NewMemoryAPEventStore(apID)
	resourceStore := reference.NewMemoryResourceEventStore()
	agentStore := reference.NewMemoryAgentEventStore()
	action := &recoverableAction{}

	protocolClient := &http.Client{}
	resolver, err := aauth.NewHTTPKeyResolver(aauth.HTTPKeyResolverConfig{
		Client: protocolClient,
		Clock:  clock,
		Admit: func(_ context.Context, endpoint string) error {
			if strings.HasPrefix(endpoint, apID+"/") || strings.HasPrefix(endpoint, resourceID+"/") {
				return nil
			}
			return fmt.Errorf("journey discovery endpoint is outside the admitted hosts: %s", endpoint)
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	activeUntil := now.Add(2 * time.Hour)
	ap := newEventProvider(t, eventProviderInput{
		identifier:  apID,
		endpoint:    apID + "/events-v1",
		signingKey:  apKey,
		clock:       clock,
		newID:       ids,
		store:       apStore,
		activeUntil: activeUntil,
	})
	resource := newEventResource(t, eventResourceInput{
		identifier:  resourceID,
		signingKey:  resourceKey,
		resolver:    resolver,
		client:      protocolClient,
		clock:       clock,
		store:       resourceStore,
		activeUntil: activeUntil,
	})

	agentToken, err := ap.IssueAgentToken(aauth.AgentTokenRequest{
		Agent:     agentID,
		PublicKey: agentKey.PublicJWK(),
		Lifetime:  time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	agent := newEventAgent(t, eventAgentInput{
		identifier: agentID,
		signingKey: agentKey,
		agentToken: agentToken,
		resolver:   resolver,
		client:     protocolClient,
		clock:      clock,
		store:      agentStore,
		action:     action,
	})

	handlers := &logicalHandlers{byHost: map[string]http.Handler{
		"ap.example":       ap.Handler(),
		"resource.example": resource.Handler(),
	}}
	gateway := newLogicalGateway(t, handlers)
	defer gateway.Close()
	lostResponses := &loseAcceptedResponseTransport{base: gateway.Client().Transport}
	protocolClient.Transport = lostResponses

	subscribeToken, err := ap.IssueEventSubscription(ctx, reference.EventSubscriptionRequest{
		Resource: resourceID,
		Agent:    agentID,
		AgentKey: agentKey.PublicJWK(),
	})
	if err != nil {
		t.Fatal(err)
	}
	subscribeClaims, err := aauth.VerifySubscribeToken(ctx, subscribeToken, resolver, clock)
	if err != nil {
		t.Fatal(err)
	}
	if subscribeClaims.MaxUses == nil || *subscribeClaims.MaxUses != 1 {
		t.Fatalf("subscribe max_uses = %v, want 1", subscribeClaims.MaxUses)
	}
	if subscribeClaims.EventID == "" {
		t.Fatal("subscribe token has empty eid")
	}

	localContext := reference.AgentEventContext{
		APIssuer: apID,
		EventID:  subscribeClaims.EventID,
		Value:    json.RawMessage(`{"purpose":"public single-shot qualification"}`),
	}
	if err := agent.RegisterPublicEventSubscription(
		ctx,
		resourceID+"/events/subscriptions",
		subscribeToken,
		localContext,
	); err != nil {
		t.Fatal(err)
	}

	// The registration credential expires while both independently selected
	// host subscription lifetimes remain active. Metadata freshness also ends.
	now = now.Add(10 * time.Minute)
	ap = newEventProvider(t, eventProviderInput{
		identifier:  apID,
		endpoint:    apID + "/events-v2",
		signingKey:  apKey,
		clock:       clock,
		newID:       ids,
		store:       apStore,
		activeUntil: activeUntil,
	})
	handlers.set("ap.example", ap.Handler())

	// Reconstruct the resource from its durable authority before delivery.
	resource = newEventResource(t, eventResourceInput{
		identifier:  resourceID,
		signingKey:  resourceKey,
		resolver:    resolver,
		client:      protocolClient,
		clock:       clock,
		store:       resourceStore,
		activeUntil: activeUntil,
	})
	handlers.set("resource.example", resource.Handler())

	lostResponses.arm(apID + "/events-v2")
	firstErr := resource.DeliverEvent(ctx, apID, subscribeClaims.EventID)
	if firstErr == nil {
		t.Fatal("first delivery unexpectedly observed the AP acceptance response")
	}
	acceptedAfterLostResponse, err := apStore.NextDelivery(ctx)
	if err != nil {
		t.Fatalf("AP inbox after lost acceptance response: %v", err)
	}
	if acceptedAfterLostResponse.Token != lostResponses.tokens()[0] {
		t.Fatal("AP did not commit the exact event JWT before its 202 response was lost")
	}
	now = now.Add(time.Second)

	// Reconstruct both protocol hosts and retry. The resource must send the
	// exact retained JWT with a fresh HTTP proof; the AP returns exhausted 429,
	// which settles the lost 202 without another use or inbox record.
	ap = newEventProvider(t, eventProviderInput{
		identifier:  apID,
		endpoint:    apID + "/events-v2",
		signingKey:  apKey,
		clock:       clock,
		newID:       ids,
		store:       apStore,
		activeUntil: activeUntil,
	})
	resource = newEventResource(t, eventResourceInput{
		identifier:  resourceID,
		signingKey:  resourceKey,
		resolver:    resolver,
		client:      protocolClient,
		clock:       clock,
		store:       resourceStore,
		activeUntil: activeUntil,
	})
	handlers.set("ap.example", ap.Handler())
	handlers.set("resource.example", resource.Handler())
	if err := resource.DeliverEvent(ctx, apID, subscribeClaims.EventID); err != nil {
		t.Fatal(err)
	}
	if got := lostResponses.attemptCount(); got != 2 {
		t.Fatalf("event delivery attempts = %d, want 2", got)
	}
	if got := lostResponses.statuses(); len(got) != 2 || got[0] != http.StatusAccepted || got[1] != http.StatusTooManyRequests {
		t.Fatalf("event response statuses = %v, want [202 429]", got)
	}
	tokens := lostResponses.tokens()
	if len(tokens) != 2 || tokens[0] == "" || tokens[0] != tokens[1] {
		t.Fatalf("event retry JWTs differ: %q", tokens)
	}
	proofs := lostResponses.proofs()
	if len(proofs) != 2 || proofs[0] == "" || proofs[1] == "" || proofs[0] == proofs[1] {
		t.Fatalf("event retry HTTP proofs were not fresh: %q", proofs)
	}
	if got := lostResponses.bodyBytes(); got != 0 {
		t.Fatalf("event request body bytes = %d, want 0", got)
	}
	if _, err := resourceStore.Load(ctx, apID, subscribeClaims.EventID); !errors.Is(err, reference.ErrEventSubscriptionNotFound) {
		t.Fatalf("resource subscription after exhaustion error = %v, want not found", err)
	}

	accepted, err := apStore.NextDelivery(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if accepted.Token != lostResponses.tokens()[0] {
		t.Fatal("AP inbox did not preserve the exact accepted event JWT")
	}

	// The first adapter process loses the result after the deployment action
	// commits. Reconstructed agent and adapter state reconcile the stable action
	// key, mark completion, and only then acknowledge the AP inbox record.
	adapter, err := reference.NewEventAdapter(apStore, agent)
	if err != nil {
		t.Fatal(err)
	}
	if err := adapter.Continue(ctx); err == nil {
		t.Fatal("first adapter continuation unexpectedly observed action completion")
	}
	pendingAfterUnknown, err := apStore.NextDelivery(ctx)
	if err != nil {
		t.Fatalf("AP inbox after unknown action outcome: %v", err)
	}
	if pendingAfterUnknown.Token != accepted.Token {
		t.Fatal("adapter acknowledged the AP inbox before a durable terminal disposition")
	}
	actionKey := reference.EventActionKey{
		ResourceIssuer: resourceID,
		APIssuer:       apID,
		EventID:        subscribeClaims.EventID,
	}
	processing, err := agentStore.LoadProcessing(ctx, actionKey)
	if err != nil {
		t.Fatalf("load processing after unknown action outcome: %v", err)
	}
	if processing.State != reference.EventDispatched {
		t.Fatalf("processing after unknown action outcome = %q, want dispatched", processing.State)
	}
	agent = newEventAgent(t, eventAgentInput{
		identifier: agentID,
		signingKey: agentKey,
		agentToken: agentToken,
		resolver:   resolver,
		client:     protocolClient,
		clock:      clock,
		store:      agentStore,
		action:     action,
	})
	adapter, err = reference.NewEventAdapter(apStore, agent)
	if err != nil {
		t.Fatal(err)
	}
	if err := adapter.Continue(ctx); err != nil {
		t.Fatal(err)
	}
	if got := action.dispatchCount(); got != 1 {
		t.Fatalf("agent action dispatches = %d, want 1", got)
	}
	if got := action.reconciliationCount(); got != 1 {
		t.Fatalf("agent action reconciliations = %d, want 1", got)
	}
	processing, err = agentStore.LoadProcessing(ctx, actionKey)
	if err != nil {
		t.Fatalf("load processing after reconciliation: %v", err)
	}
	if processing.State != reference.EventCompleted {
		t.Fatalf("processing after reconciliation = %q, want completed", processing.State)
	}
	if _, err := apStore.NextDelivery(ctx); !errors.Is(err, reference.ErrNoPendingEventDelivery) {
		t.Fatalf("AP inbox after terminal agent completion error = %v, want no pending delivery", err)
	}
}

type eventProviderInput struct {
	identifier  string
	endpoint    string
	signingKey  aauth.SigningKey
	clock       aauth.Clock
	newID       func() string
	store       reference.APEventStore
	activeUntil time.Time
}

func newEventProvider(t *testing.T, input eventProviderInput) *reference.AgentProvider {
	t.Helper()
	provider, err := reference.NewAgentProvider(reference.AgentProviderConfig{
		Identifier: input.identifier,
		SigningKey: input.signingKey,
		Clock:      input.clock,
		NewID:      input.newID,
		Events: &reference.AgentProviderEventsConfig{
			EventEndpoint: input.endpoint,
			Store:         input.store,
			SubscriptionActiveUntil: func(context.Context, string, string) (time.Time, error) {
				return input.activeUntil, nil
			},
			TokenLifetime: time.Minute,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return provider
}

type eventResourceInput struct {
	identifier  string
	signingKey  aauth.SigningKey
	resolver    aauth.KeyResolver
	client      *http.Client
	clock       aauth.Clock
	store       reference.ResourceEventStore
	activeUntil time.Time
}

func newEventResource(t *testing.T, input eventResourceInput) *reference.Resource {
	t.Helper()
	resource, err := reference.NewResource(reference.ResourceConfig{
		Identifier:  input.identifier,
		SigningKey:  input.signingKey,
		KeyResolver: input.resolver,
		Clock:       input.clock,
		NewID:       sequentialIDs("unused-resource-id"),
		Scopes:      []string{"qualification.read"},
		AuthorizationPolicy: func(context.Context, aauth.AuthorizationRequest) (aauth.AuthorizationDecision, error) {
			return aauth.AuthorizationDecision{}, errors.New("ordinary authorization is outside this Events journey")
		},
		Operation: func(context.Context, aauth.AuthorizedRequest) (any, error) {
			return nil, errors.New("ordinary protected operation is outside this Events journey")
		},
		Events: &reference.ResourceEventsConfig{
			PublicSubscriptionPath: "/events/subscriptions",
			Store:                  input.store,
			HTTPClient:             input.client,
			ActiveUntil: func(context.Context, aauth.SubscribeTokenClaims) (time.Time, error) {
				return input.activeUntil, nil
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return resource
}

type eventAgentInput struct {
	identifier string
	signingKey aauth.SigningKey
	agentToken string
	resolver   aauth.KeyResolver
	client     *http.Client
	clock      aauth.Clock
	store      reference.AgentEventStore
	action     reference.EventAction
}

func newEventAgent(t *testing.T, input eventAgentInput) *reference.Agent {
	t.Helper()
	agent, err := reference.NewAgent(reference.AgentConfig{
		Identifier:  input.identifier,
		SigningKey:  input.signingKey,
		AgentToken:  input.agentToken,
		KeyResolver: input.resolver,
		HTTPClient:  input.client,
		Clock:       input.clock,
		Events: &reference.AgentEventsConfig{
			Store:  input.store,
			Action: input.action,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return agent
}

type recoverableAction struct {
	mu              sync.Mutex
	dispatches      int
	reconciliations int
	completed       map[reference.EventActionKey]bool
}

func (action *recoverableAction) Dispatch(_ context.Context, input reference.EventActionInput) (reference.EventActionOutcome, error) {
	action.mu.Lock()
	defer action.mu.Unlock()
	if action.completed == nil {
		action.completed = make(map[reference.EventActionKey]bool)
	}
	action.dispatches++
	if action.completed[input.Key] {
		return reference.EventActionUnknown, errors.New("journey: duplicate action dispatch")
	}
	action.completed[input.Key] = true
	return reference.EventActionUnknown, errors.New("journey: action completion response was lost")
}

func (action *recoverableAction) Reconcile(_ context.Context, key reference.EventActionKey) (reference.EventActionOutcome, error) {
	action.mu.Lock()
	defer action.mu.Unlock()
	action.reconciliations++
	if action.completed[key] {
		return reference.EventActionCompleted, nil
	}
	return reference.EventActionNotApplied, nil
}

func (action *recoverableAction) dispatchCount() int {
	action.mu.Lock()
	defer action.mu.Unlock()
	return action.dispatches
}

func (action *recoverableAction) reconciliationCount() int {
	action.mu.Lock()
	defer action.mu.Unlock()
	return action.reconciliations
}

type logicalHandlers struct {
	mu     sync.RWMutex
	byHost map[string]http.Handler
}

func (handlers *logicalHandlers) set(host string, handler http.Handler) {
	handlers.mu.Lock()
	defer handlers.mu.Unlock()
	handlers.byHost[host] = handler
}

func (handlers *logicalHandlers) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	handlers.mu.RLock()
	handler := handlers.byHost[request.Host]
	handlers.mu.RUnlock()
	if handler == nil {
		http.Error(response, "unknown logical host", http.StatusBadGateway)
		return
	}
	handler.ServeHTTP(response, request)
}

func newLogicalGateway(t *testing.T, handler http.Handler) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(handler)
	target, err := url.Parse(server.URL)
	if err != nil {
		server.Close()
		t.Fatal(err)
	}
	server.Client().Transport = &logicalTransport{target: target, base: server.Client().Transport}
	return server
}

type logicalTransport struct {
	target *url.URL
	base   http.RoundTripper
}

func (transport *logicalTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	cloned := request.Clone(request.Context())
	cloned.URL.Scheme = transport.target.Scheme
	cloned.URL.Host = transport.target.Host
	cloned.Host = request.URL.Host
	response, err := transport.base.RoundTrip(cloned)
	if response != nil {
		response.Request = request
	}
	return response, err
}

type loseAcceptedResponseTransport struct {
	mu           sync.Mutex
	base         http.RoundTripper
	armedURL     string
	lost         bool
	attempts     int
	tokensSeen   []string
	proofsSeen   []string
	statusesSeen []int
	bodySeen     int
}

func (transport *loseAcceptedResponseTransport) arm(endpoint string) {
	transport.mu.Lock()
	defer transport.mu.Unlock()
	transport.armedURL = endpoint
	transport.lost = false
}

func (transport *loseAcceptedResponseTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	isEvent := request.Method == http.MethodPost && request.URL.String() == transport.armedURL
	if isEvent {
		var body []byte
		if request.Body != nil {
			var err error
			body, err = io.ReadAll(request.Body)
			if err != nil {
				return nil, err
			}
			request.Body = io.NopCloser(strings.NewReader(string(body)))
		}
		transport.mu.Lock()
		transport.attempts++
		transport.bodySeen += len(body)
		transport.tokensSeen = append(transport.tokensSeen, signatureKeyJWT(request.Header.Get("Signature-Key")))
		transport.proofsSeen = append(transport.proofsSeen, request.Header.Get("Signature-Input")+"\n"+request.Header.Get("Signature"))
		transport.mu.Unlock()
	}
	response, err := transport.base.RoundTrip(request)
	if err != nil || !isEvent {
		return response, err
	}
	transport.mu.Lock()
	if response != nil {
		transport.statusesSeen = append(transport.statusesSeen, response.StatusCode)
	}
	lose := !transport.lost
	if lose {
		transport.lost = true
	}
	transport.mu.Unlock()
	if lose {
		if response != nil && response.Body != nil {
			_ = response.Body.Close()
		}
		return nil, errors.New("journey: AP acceptance response was lost")
	}
	return response, nil
}

func (transport *loseAcceptedResponseTransport) attemptCount() int {
	transport.mu.Lock()
	defer transport.mu.Unlock()
	return transport.attempts
}

func (transport *loseAcceptedResponseTransport) tokens() []string {
	transport.mu.Lock()
	defer transport.mu.Unlock()
	return append([]string(nil), transport.tokensSeen...)
}

func (transport *loseAcceptedResponseTransport) proofs() []string {
	transport.mu.Lock()
	defer transport.mu.Unlock()
	return append([]string(nil), transport.proofsSeen...)
}

func (transport *loseAcceptedResponseTransport) statuses() []int {
	transport.mu.Lock()
	defer transport.mu.Unlock()
	return append([]int(nil), transport.statusesSeen...)
}

func (transport *loseAcceptedResponseTransport) bodyBytes() int {
	transport.mu.Lock()
	defer transport.mu.Unlock()
	return transport.bodySeen
}

func signatureKeyJWT(header string) string {
	marker := `jwt="`
	start := strings.Index(header, marker)
	if start < 0 {
		return ""
	}
	value := header[start+len(marker):]
	end := strings.IndexByte(value, '"')
	if end < 0 {
		return ""
	}
	return value[:end]
}

func testSigningKey(t *testing.T, id string) aauth.SigningKey {
	t.Helper()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := aauth.NewEd25519SigningKey(id, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func sequentialIDs(values ...string) func() string {
	next := 0
	return func() string {
		if next >= len(values) {
			panic("journey requested more identifiers than configured")
		}
		value := values[next]
		next++
		return value
	}
}
