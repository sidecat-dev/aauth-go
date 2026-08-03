package reference

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
)

func TestAPEventEndpointCommitsInboxBefore202(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	now := time.Date(2026, 8, 3, 8, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	apKey := eventsProviderTestSigningKey(t, "ap-events-key")
	resourceKey := eventsProviderTestSigningKey(t, "resource-events-key")
	store := NewMemoryAPEventStore("https://ap.example")
	if err := store.CreateSubscription(ctx, APEventSubscription{
		APIssuer:    "https://ap.example",
		EventID:     "event-one",
		Resource:    "https://resource.example",
		Agent:       "aauth:subscriber@ap.example",
		ActiveUntil: now.Add(time.Hour),
		MaxUses:     1,
	}); err != nil {
		t.Fatal(err)
	}
	provider := newDeliveryTestProvider(t, apKey, store, aauth.StaticKeyResolver{
		"https://resource.example": {resourceKey.ID(): resourceKey.PublicJWK()},
	}, clock)
	compact := mintDeliveryTestEvent(t, resourceKey, now, "aauth:subscriber@ap.example", "event-one")

	request, err := http.NewRequest(http.MethodPost, "https://ap.example/events", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := aauth.SignRequestWithSelfJWT(request, resourceKey, compact, clock); err != nil {
		t.Fatal(err)
	}
	response := eventRegistrationHTTPResponse(provider.Handler(), request)
	defer response.Body.Close()
	if response.StatusCode != http.StatusAccepted {
		body, _ := io.ReadAll(response.Body)
		t.Fatalf("event status = %d: %s", response.StatusCode, body)
	}
	accepted, err := store.NextDelivery(ctx)
	if err != nil {
		t.Fatalf("202 preceded inbox commit: %v", err)
	}
	if accepted.Token != compact {
		t.Fatal("AP inbox did not retain the exact accepted token")
	}

	retry, err := http.NewRequest(http.MethodPost, "https://ap.example/events", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := aauth.SignRequestWithSelfJWT(retry, resourceKey, compact, clock); err != nil {
		t.Fatal(err)
	}
	retryResponse := eventRegistrationHTTPResponse(provider.Handler(), retry)
	defer retryResponse.Body.Close()
	if retryResponse.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("exhausted retry status = %d, want 429", retryResponse.StatusCode)
	}

	failedAuthority := NewMemoryAPEventStore("https://ap.example")
	if err := failedAuthority.CreateSubscription(ctx, APEventSubscription{
		APIssuer: "https://ap.example", EventID: "event-failure",
		Resource: "https://resource.example", Agent: "aauth:subscriber@ap.example",
		ActiveUntil: now.Add(time.Hour), MaxUses: 1,
	}); err != nil {
		t.Fatal(err)
	}
	commitFailure := errors.Join(ErrEventRecordInvalid, errors.New("test: atomic event commit failed"))
	failingStore := &failingAcceptAPEventStore{APEventStore: failedAuthority, err: commitFailure}
	failingProvider := newDeliveryTestProvider(t, apKey, failingStore, aauth.StaticKeyResolver{
		"https://resource.example": {resourceKey.ID(): resourceKey.PublicJWK()},
	}, clock)
	failingToken := mintDeliveryTestEvent(t, resourceKey, now, "aauth:subscriber@ap.example", "event-failure")
	failingRequest, err := http.NewRequest(http.MethodPost, "https://ap.example/events", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := aauth.SignRequestWithSelfJWT(failingRequest, resourceKey, failingToken, clock); err != nil {
		t.Fatal(err)
	}
	failingResponse := eventRegistrationHTTPResponse(failingProvider.Handler(), failingRequest)
	defer failingResponse.Body.Close()
	if failingResponse.StatusCode != http.StatusInternalServerError {
		t.Fatalf("invalid store record status = %d, want 500", failingResponse.StatusCode)
	}
	if _, err := failedAuthority.NextDelivery(ctx); !errors.Is(err, ErrNoPendingEventDelivery) {
		t.Fatalf("failed atomic event commit queued work: %v", err)
	}
}

func TestEventDeliveryRetainsExactJWTAndReconcilesLost202With429(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	now := time.Date(2026, 8, 3, 8, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	apKey := eventsProviderTestSigningKey(t, "ap-events-key")
	resourceKey := eventsProviderTestSigningKey(t, "resource-events-key")
	apStore := NewMemoryAPEventStore("https://ap.example")
	resourceStore := NewMemoryResourceEventStore()
	subscription := ResourceEventSubscription{
		APIssuer:    "https://ap.example",
		EventID:     "event-one",
		Resource:    "https://resource.example",
		Agent:       "aauth:subscriber@ap.example",
		ActiveUntil: now.Add(time.Hour),
	}
	if err := resourceStore.Register(ctx, subscription); err != nil {
		t.Fatal(err)
	}
	if err := apStore.CreateSubscription(ctx, APEventSubscription{
		APIssuer: subscription.APIssuer, EventID: subscription.EventID,
		Resource: subscription.Resource, Agent: subscription.Agent,
		ActiveUntil: subscription.ActiveUntil, MaxUses: 1,
	}); err != nil {
		t.Fatal(err)
	}

	provider := newDeliveryTestProvider(t, apKey, apStore, aauth.StaticKeyResolver{
		subscription.Resource: {resourceKey.ID(): resourceKey.PublicJWK()},
	}, clock)
	client := &http.Client{}
	resolver, err := aauth.NewHTTPKeyResolver(aauth.HTTPKeyResolverConfig{
		Client: client,
		Clock:  clock,
		Admit: func(_ context.Context, endpoint string) error {
			if !strings.HasPrefix(endpoint, subscription.APIssuer+"/") {
				return errors.New("unadmitted event discovery endpoint")
			}
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	transport := &lostAcceptedEventTransport{base: registrationRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		return eventRegistrationHTTPResponse(provider.Handler(), request), nil
	})}
	client.Transport = transport

	resource := newDeliveryTestResource(t, resourceKey, resolver, client, clock, resourceStore)
	if err := resource.DeliverEvent(ctx, subscription.APIssuer, subscription.EventID); err == nil {
		t.Fatal("lost 202 was reported as observed delivery")
	}
	pending, err := resourceStore.LoadPending(ctx, subscription.APIssuer, subscription.EventID)
	if err != nil || pending.Token == "" {
		t.Fatalf("pending exact token after lost 202 = %#v, %v", pending, err)
	}
	accepted, err := apStore.NextDelivery(ctx)
	if err != nil || accepted.Token != pending.Token {
		t.Fatalf("AP inbox/pending token mismatch = %#v / %#v / %v", accepted, pending, err)
	}

	now = now.Add(time.Second)
	resource = newDeliveryTestResource(t, resourceKey, resolver, client, clock, resourceStore)
	if err := resource.DeliverEvent(ctx, subscription.APIssuer, subscription.EventID); err != nil {
		t.Fatal(err)
	}
	if transport.attemptCount() != 2 {
		t.Fatalf("event attempts = %d, want 2", transport.attemptCount())
	}
	tokens, proofs := transport.observed()
	if len(tokens) != 2 || tokens[0] == "" || tokens[0] != tokens[1] {
		t.Fatalf("event retry tokens = %#v", tokens)
	}
	if len(proofs) != 2 || proofs[0] == "" || proofs[0] == proofs[1] {
		t.Fatalf("event retry proofs = %#v", proofs)
	}
	if _, err := resourceStore.Load(ctx, subscription.APIssuer, subscription.EventID); !errors.Is(err, ErrEventSubscriptionNotFound) {
		t.Fatalf("settled subscription error = %v, want not found", err)
	}
}

func TestEventDeliveryRejectsUnsafeResolvedEndpointBeforeSend(t *testing.T) {
	t.Parallel()

	for _, endpoint := range []string{
		"http://ap.example/events",
		"https://ap.example/events?tenant=other",
		"https://user@ap.example/events",
		"https://ap.example/events#fragment",
	} {
		endpoint := endpoint
		t.Run(endpoint, func(t *testing.T) {
			t.Parallel()

			ctx := context.Background()
			now := time.Date(2026, 8, 3, 8, 0, 0, 0, time.UTC)
			clock := aauth.ClockFunc(func() time.Time { return now })
			resourceKey := eventsProviderTestSigningKey(t, "resource-events-key")
			store := NewMemoryResourceEventStore()
			subscription := ResourceEventSubscription{
				APIssuer: "https://ap.example", EventID: "event-one",
				Resource: "https://resource.example", Agent: "aauth:subscriber@ap.example",
				ActiveUntil: now.Add(time.Hour),
			}
			if err := store.Register(ctx, subscription); err != nil {
				t.Fatal(err)
			}
			resolver := hostileEventMetadataResolver{
				StaticKeyResolver: aauth.StaticKeyResolver{},
				metadata: aauth.AgentEventMetadata{
					Issuer: subscription.APIssuer, EventEndpoint: endpoint,
				},
			}
			sent := false
			client := &http.Client{Transport: registrationRoundTripFunc(func(*http.Request) (*http.Response, error) {
				sent = true
				return nil, errors.New("test: unsafe endpoint was sent")
			})}
			resource := newDeliveryTestResource(t, resourceKey, resolver, client, clock, store)
			if err := resource.DeliverEvent(ctx, subscription.APIssuer, subscription.EventID); err == nil {
				t.Fatal("unsafe resolved endpoint was accepted")
			}
			if sent {
				t.Fatal("unsafe resolved endpoint reached the HTTP transport")
			}
		})
	}
}

func newDeliveryTestProvider(t *testing.T, key aauth.SigningKey, store APEventStore, resolver aauth.KeyResolver, clock aauth.Clock) *AgentProvider {
	t.Helper()
	provider, err := NewAgentProvider(AgentProviderConfig{
		Identifier: "https://ap.example",
		SigningKey: key,
		Clock:      clock,
		NewID:      func() string { return "unused" },
		Events: &AgentProviderEventsConfig{
			EventEndpoint: "https://ap.example/events",
			Store:         store,
			KeyResolver:   resolver,
			SubscriptionActiveUntil: func(context.Context, string, string) (time.Time, error) {
				return clock.Now().Add(time.Hour), nil
			},
			TokenLifetime: time.Minute,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return provider
}

func newDeliveryTestResource(t *testing.T, key aauth.SigningKey, resolver aauth.KeyResolver, client *http.Client, clock aauth.Clock, store ResourceEventStore) *Resource {
	t.Helper()
	resource, err := NewResource(ResourceConfig{
		Identifier:  "https://resource.example",
		SigningKey:  key,
		KeyResolver: resolver,
		Clock:       clock,
		NewID:       func() string { return "unused" },
		Scopes:      []string{"qualification.read"},
		AuthorizationPolicy: func(context.Context, aauth.AuthorizationRequest) (aauth.AuthorizationDecision, error) {
			return aauth.AuthorizationDecision{}, errors.New("unused")
		},
		Operation: func(context.Context, aauth.AuthorizedRequest) (any, error) { return nil, errors.New("unused") },
		Events: &ResourceEventsConfig{
			PublicSubscriptionPath: "/events/subscriptions",
			Store:                  store,
			HTTPClient:             client,
			ActiveUntil: func(context.Context, aauth.SubscribeTokenClaims) (time.Time, error) {
				return clock.Now().Add(time.Hour), nil
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return resource
}

func mintDeliveryTestEvent(t *testing.T, key aauth.SigningKey, now time.Time, agent, eventID string) string {
	t.Helper()
	compact, err := aauth.MintEventToken(key, aauth.EventTokenClaims{
		Issuer: "https://resource.example", DWK: aauth.ResourceDiscoveryDocument,
		Audience: agent, EventID: eventID, IssuedAt: now.Unix(), ExpiresAt: now.Add(5 * time.Minute).Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return compact
}

type lostAcceptedEventTransport struct {
	mu     sync.Mutex
	base   http.RoundTripper
	lost   bool
	tokens []string
	proofs []string
}

func (transport *lostAcceptedEventTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	isEvent := request.Method == http.MethodPost && request.URL.Path == "/events"
	if isEvent {
		transport.mu.Lock()
		transport.tokens = append(transport.tokens, selfJWTFromSignatureKey(request.Header.Get("Signature-Key")))
		transport.proofs = append(transport.proofs, request.Header.Get("Signature-Input")+"\n"+request.Header.Get("Signature"))
		transport.mu.Unlock()
	}
	response, err := transport.base.RoundTrip(request)
	if err != nil || !isEvent {
		return response, err
	}
	transport.mu.Lock()
	lose := !transport.lost
	if lose {
		transport.lost = true
	}
	transport.mu.Unlock()
	if lose {
		if response != nil && response.Body != nil {
			_ = response.Body.Close()
		}
		return nil, errors.New("test: accepted response was lost")
	}
	return response, nil
}

func (transport *lostAcceptedEventTransport) attemptCount() int {
	transport.mu.Lock()
	defer transport.mu.Unlock()
	return len(transport.tokens)
}

func (transport *lostAcceptedEventTransport) observed() ([]string, []string) {
	transport.mu.Lock()
	defer transport.mu.Unlock()
	return append([]string(nil), transport.tokens...), append([]string(nil), transport.proofs...)
}

func selfJWTFromSignatureKey(value string) string {
	const prefix = `sig=self-jwt;jwt=`
	if !strings.HasPrefix(value, prefix) {
		return ""
	}
	compact, err := strconv.Unquote(strings.TrimPrefix(value, prefix))
	if err != nil {
		return ""
	}
	return compact
}

type failingAcceptAPEventStore struct {
	APEventStore
	err error
}

type hostileEventMetadataResolver struct {
	aauth.StaticKeyResolver
	metadata aauth.AgentEventMetadata
}

func (resolver hostileEventMetadataResolver) ResolveAgentEventMetadata(context.Context, string) (aauth.AgentEventMetadata, error) {
	return resolver.metadata, nil
}

func (store *failingAcceptAPEventStore) AcceptEvent(context.Context, AcceptedEventInput) (AcceptedEvent, int, error) {
	return AcceptedEvent{}, 0, store.err
}
