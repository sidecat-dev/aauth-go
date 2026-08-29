package reference

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
)

func TestProtectedPayloadEventSurvivesHostReconstruction(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	root := t.TempDir()
	resourceDirectory := filepath.Join(root, "resource")
	apDirectory := filepath.Join(root, "ap")
	agentDirectory := filepath.Join(root, "agent")
	contractDirectory := filepath.Join(root, "contracts")
	document := protectedEventsTestDocument()
	activeUntil := now.Add(time.Hour)
	resourceKey := eventsProviderTestSigningKey(t, "journey-resource-key")
	accessKey := eventsProviderTestSigningKey(t, "journey-access-key")
	apKey := eventsProviderTestSigningKey(t, "journey-ap-key")
	agentKey := eventsProviderTestSigningKey(t, "journey-agent-key")

	resourceStore, err := OpenFileResourceEventStore(FileResourceEventStoreConfig{Directory: resourceDirectory})
	if err != nil {
		t.Fatal(err)
	}
	contractStore, err := OpenFileR3DocumentStore(FileR3DocumentStoreConfig{Directory: contractDirectory, Clock: clock})
	if err != nil {
		t.Fatal(err)
	}
	transport := &journeyPayloadTransport{}
	resourceResolver := hostileEventMetadataResolver{
		StaticKeyResolver: aauth.StaticKeyResolver{
			"https://as.example": {accessKey.ID(): accessKey.PublicJWK()},
			"https://ap.example": {apKey.ID(): apKey.PublicJWK()},
		},
		metadata: aauth.AgentEventMetadata{Issuer: "https://ap.example", EventEndpoint: "https://ap.example/events"},
	}
	resource := newProtectedJourneyResource(t, resourceKey, resourceResolver, clock, resourceStore, contractStore, document, transport, func(_ context.Context, authorized aauth.AuthorizedRequest) (any, error) {
		if authorized.Agent != "" || authorized.PersonServer != "https://ps.example" ||
			authorized.Subject != "pairwise-user" || authorized.ConfirmationKey != agentKey.PublicJWK() ||
			authorized.Method != http.MethodPost || authorized.Path != "/appointments/search" {
			t.Fatalf("authorized ticket operation = %#v", authorized)
		}
		return ProtectedEventOperationResult{
			Ticket: ProtectedEventTicketRequest{
				Agent: "aauth:subscriber@ap.example", ResourceRevision: "appointments-r17", ActiveUntil: activeUntil,
			},
			Response: func(grant ProtectedEventTicketGrant) (any, error) { return grant, nil },
		}, nil
	})
	authToken := protectedEventsTestAuthToken(t, accessKey, agentKey, now)
	authenticated := httptest.NewRequest(http.MethodPost, "https://resource.example/appointments/search", nil)
	if err := aauth.SignRequest(authenticated, agentKey, authToken, clock); err != nil {
		t.Fatal(err)
	}
	authenticatedResponse := httptest.NewRecorder()
	resource.Handler().ServeHTTP(authenticatedResponse, authenticated)
	if authenticatedResponse.Code != http.StatusOK {
		t.Fatalf("protected operation = %d: %s", authenticatedResponse.Code, authenticatedResponse.Body.Bytes())
	}
	var grant ProtectedEventTicketGrant
	if err := json.Unmarshal(authenticatedResponse.Body.Bytes(), &grant); err != nil {
		t.Fatal(err)
	}
	parsedTicketURL, err := url.Parse(grant.URL)
	if err != nil || parsedTicketURL.Scheme != "https" || parsedTicketURL.Host != "resource.example" {
		t.Fatalf("ticket grant = %#v, %v", grant, err)
	}
	rawTicket := strings.TrimPrefix(parsedTicketURL.Path, "/appointments/waitlist/")
	rawBytes, err := base64.RawURLEncoding.DecodeString(rawTicket)
	if err != nil || len(rawBytes) != 32 {
		t.Fatalf("ticket capability bytes/error = %d/%v", len(rawBytes), err)
	}
	ticket, err := resourceStore.LoadTicket(ctx, protectedEventTicketDigest(rawTicket))
	if err != nil || ticket.ContractDigest != grant.ContractDigest || ticket.OperationID != grant.OperationID || ticket.MessageID != grant.MessageID {
		t.Fatalf("committed ticket before URL = %#v, %v", ticket, err)
	}

	discoveryClient := &http.Client{Transport: registrationRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		return eventRegistrationHTTPResponse(resource.Handler(), request), nil
	})}
	contractResolver, err := aauth.NewHTTPEventsContractResolver(aauth.HTTPEventsContractResolverConfig{
		Client: discoveryClient, Clock: clock,
		Admit: func(_ context.Context, endpoint string) error {
			if !strings.HasPrefix(endpoint, "https://resource.example/") {
				return errors.New("test: discovery left resource origin")
			}
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	discovered, err := contractResolver.Resolve(ctx, "https://resource.example")
	if err != nil || discovered.Digest() != grant.ContractDigest || !bytes.Equal(discovered.ExactBytes(), document) {
		t.Fatalf("discovered contract = %q, %v", discovered.Digest(), err)
	}
	if _, err := discovered.ProtectedMessage(grant.OperationID, grant.MessageID); err != nil {
		t.Fatal(err)
	}

	apStore, err := OpenFileAPEventStore(FileAPEventStoreConfig{Directory: apDirectory, Issuer: "https://ap.example"})
	if err != nil {
		t.Fatal(err)
	}
	provider := newDeliveryTestProvider(t, apKey, apStore, aauth.StaticKeyResolver{
		"https://resource.example": {resourceKey.ID(): resourceKey.PublicJWK()},
	}, clock)
	subscribeToken, err := provider.IssueEventSubscription(ctx, EventSubscriptionRequest{
		Resource: "https://resource.example", Agent: "aauth:subscriber@ap.example",
		AgentKey: agentKey.PublicJWK(), ContractDigest: grant.ContractDigest,
		OperationID: grant.OperationID, MessageID: grant.MessageID,
	})
	if err != nil {
		t.Fatal(err)
	}
	subscribeClaims, err := aauth.VerifySubscribeToken(ctx, subscribeToken, aauth.StaticKeyResolver{
		"https://ap.example": {apKey.ID(): apKey.PublicJWK()},
	}, clock)
	if err != nil || subscribeClaims.MaxUses == nil || *subscribeClaims.MaxUses != 1 {
		t.Fatalf("one-use subscribe token = %#v, %v", subscribeClaims, err)
	}
	agentStore, err := OpenFileAgentEventStore(FileAgentEventStoreConfig{Directory: agentDirectory})
	if err != nil {
		t.Fatal(err)
	}
	registrationAgent := newJourneyAgent(t, agentKey, aauth.StaticKeyResolver{
		"https://ap.example": {apKey.ID(): apKey.PublicJWK()},
	}, clock, agentStore, unusedEventAction{}, registrationRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		return eventRegistrationHTTPResponse(resource.Handler(), request), nil
	}))
	localContext := protectedAgentPayloadContext(subscribeClaims.EventID, discovered.ExactBytes())
	if err := registrationAgent.RegisterProtectedEventSubscription(ctx, grant, subscribeToken, localContext); err != nil {
		t.Fatal(err)
	}
	if _, err := resourceStore.LoadTicket(ctx, ticket.TicketDigest); !errors.Is(err, ErrProtectedEventTicketNotFound) {
		t.Fatalf("registered ticket remains = %v", err)
	}
	subscription, err := resourceStore.Load(ctx, subscribeClaims.Issuer, subscribeClaims.EventID)
	if err != nil || subscription.ContractDigest != grant.ContractDigest {
		t.Fatalf("protected resource subscription = %#v, %v", subscription, err)
	}

	if err := resourceStore.Close(); err != nil {
		t.Fatal(err)
	}
	resourceStore, err = OpenFileResourceEventStore(FileResourceEventStoreConfig{Directory: resourceDirectory})
	if err != nil {
		t.Fatal(err)
	}
	contractStore, err = OpenFileR3DocumentStore(FileR3DocumentStoreConfig{Directory: contractDirectory, Clock: clock})
	if err != nil {
		t.Fatal(err)
	}
	transport.setHandler(provider.Handler())
	resource = newProtectedJourneyResource(t, resourceKey, resourceResolver, clock, resourceStore, contractStore, document, transport, func(context.Context, aauth.AuthorizedRequest) (any, error) {
		return map[string]string{"status": "unused"}, nil
	})
	payload := EventPayload{
		OperationID: grant.OperationID, MessageID: grant.MessageID, ContentType: "application/json",
		Body: []byte(" \n" + `{"event_type":"slot.available","slot_time":"2026-08-04T12:30:00Z"}` + "\n "),
	}
	if err := resource.DeliverEventPayload(ctx, subscription.APIssuer, subscription.EventID, payload); err == nil {
		t.Fatal("lost 202 was reported as observed")
	}
	pending, err := resourceStore.LoadPending(ctx, subscription.APIssuer, subscription.EventID)
	if err != nil || !bytes.Equal(pending.Payload, payload.Body) {
		t.Fatalf("resource pending payload = %#v, %v", pending, err)
	}
	accepted, err := apStore.NextDelivery(ctx)
	if err != nil || accepted.Token != pending.Token || accepted.PayloadDigest != pending.PayloadDigest || !bytes.Equal(accepted.Payload, pending.Payload) {
		t.Fatalf("AP accepted payload = %#v, %v", accepted, err)
	}

	if err := resourceStore.Close(); err != nil {
		t.Fatal(err)
	}
	if err := apStore.Close(); err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Second)
	resourceStore, err = OpenFileResourceEventStore(FileResourceEventStoreConfig{Directory: resourceDirectory})
	if err != nil {
		t.Fatal(err)
	}
	apStore, err = OpenFileAPEventStore(FileAPEventStoreConfig{Directory: apDirectory, Issuer: "https://ap.example"})
	if err != nil {
		t.Fatal(err)
	}
	provider = newDeliveryTestProvider(t, apKey, apStore, aauth.StaticKeyResolver{
		"https://resource.example": {resourceKey.ID(): resourceKey.PublicJWK()},
	}, clock)
	transport.setHandler(provider.Handler())
	contractStore, err = OpenFileR3DocumentStore(FileR3DocumentStoreConfig{Directory: contractDirectory, Clock: clock})
	if err != nil {
		t.Fatal(err)
	}
	resource = newProtectedJourneyResource(t, resourceKey, resourceResolver, clock, resourceStore, contractStore, document, transport, func(context.Context, aauth.AuthorizedRequest) (any, error) {
		return nil, errors.New("unused")
	})
	if err := resource.DeliverEventPayload(ctx, subscription.APIssuer, subscription.EventID, payload); err != nil {
		t.Fatal(err)
	}
	if _, err := resourceStore.LoadPending(ctx, subscription.APIssuer, subscription.EventID); !errors.Is(err, ErrEventPendingNotFound) {
		t.Fatalf("settled pending = %v", err)
	}
	if _, err := resourceStore.Load(ctx, subscription.APIssuer, subscription.EventID); !errors.Is(err, ErrEventSubscriptionNotFound) {
		t.Fatalf("settled subscription = %v", err)
	}
	bodies, proofs := transport.observed()
	if len(bodies) != 2 || !bytes.Equal(bodies[0], payload.Body) || !bytes.Equal(bodies[0], bodies[1]) ||
		len(proofs) != 2 || proofs[0] == proofs[1] {
		t.Fatalf("lost-response retry bodies/proofs = %#v / %#v", bodies, proofs)
	}

	if err := agentStore.Close(); err != nil {
		t.Fatal(err)
	}
	agentStore, err = OpenFileAgentEventStore(FileAgentEventStoreConfig{Directory: agentDirectory})
	if err != nil {
		t.Fatal(err)
	}
	action := &journeyPayloadAction{}
	agent := newJourneyAgent(t, agentKey, aauth.StaticKeyResolver{
		"https://resource.example": {resourceKey.ID(): resourceKey.PublicJWK()},
	}, clock, agentStore, action, &http.Transport{})
	adapter, err := NewEventAdapter(apStore, agent)
	if err != nil {
		t.Fatal(err)
	}
	if err := adapter.Continue(ctx); !errors.Is(err, ErrEventProcessingIncomplete) {
		t.Fatalf("unknown action result = %v", err)
	}
	if err := agentStore.Close(); err != nil {
		t.Fatal(err)
	}
	agentStore, err = OpenFileAgentEventStore(FileAgentEventStoreConfig{Directory: agentDirectory})
	if err != nil {
		t.Fatal(err)
	}
	agent = newJourneyAgent(t, agentKey, aauth.StaticKeyResolver{
		"https://resource.example": {resourceKey.ID(): resourceKey.PublicJWK()},
	}, clock, agentStore, action, &http.Transport{})
	adapter, err = NewEventAdapter(apStore, agent)
	if err != nil {
		t.Fatal(err)
	}
	if err := adapter.Continue(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := apStore.NextDelivery(ctx); !errors.Is(err, ErrNoPendingEventDelivery) {
		t.Fatalf("terminal adapter did not acknowledge = %v", err)
	}
	if state, err := agent.AcceptEvent(ctx, accepted); err != nil || state != EventCompleted {
		t.Fatalf("terminal duplicate = %q, %v", state, err)
	}
	dispatches, reconciliations, actedPayload := action.snapshot()
	if dispatches != 1 || reconciliations != 1 || !bytes.Equal(actedPayload, payload.Body) {
		t.Fatalf("journey action counts/payload = %d/%d/%q", dispatches, reconciliations, actedPayload)
	}
	if err := agentStore.Close(); err != nil {
		t.Fatal(err)
	}
	if err := apStore.Close(); err != nil {
		t.Fatal(err)
	}
	if err := resourceStore.Close(); err != nil {
		t.Fatal(err)
	}
}

func newProtectedJourneyResource(
	t *testing.T,
	key jose.SigningKey,
	resolver aauth.KeyResolver,
	clock aauth.Clock,
	store ResourceEventStore,
	contracts EventContractStore,
	document []byte,
	client http.RoundTripper,
	operation func(context.Context, aauth.AuthorizedRequest) (any, error),
) *Resource {
	t.Helper()
	resource, err := NewResource(ResourceConfig{
		Identifier: "https://resource.example", AccessMode: aauth.AccessModeAuthToken,
		AccessServer: "https://as.example",
		SigningKey:   key, KeyResolver: resolver, Clock: clock, NewID: func() string { return "unused" },
		Scopes: []string{"events.read"}, ScopeDescriptions: map[string]string{"events.read": "Read protected appointment events"},
		RequiredScopesForRequest:     testRequiredResourceScopes("events.read"),
		ReplayStore:                  testResourceReplayStore(t, clock),
		ProtectedAuthorizationPolicy: testProtectedAuthorizationPolicy,
		Operation:                    operation,
		Events: &ResourceEventsConfig{
			PublicSubscriptionPath: "/events/subscriptions", Store: store,
			HTTPClient: &http.Client{Transport: client},
			ActiveUntil: func(context.Context, aauth.SubscribeTokenClaims) (time.Time, error) {
				return clock.Now().Add(time.Hour), nil
			},
			AsyncAPIPath: "/asyncapi.json", AsyncAPIDocument: document,
			ProtectedOperationID: "subscribeProtectedWaitlist", ProtectedMessageID: "slotAvailable",
			ContractStore: contracts, TicketLifetime: time.Minute,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return resource
}

func newJourneyAgent(
	t *testing.T,
	key jose.SigningKey,
	resolver aauth.KeyResolver,
	clock aauth.Clock,
	store AgentEventStore,
	action EventAction,
	transport http.RoundTripper,
) *Agent {
	t.Helper()
	agent, err := NewAgent(AgentConfig{
		AuthorizationStore: testAuthorizationStateStore(t),
		Identifier:         "aauth:subscriber@ap.example", SigningKey: key,
		AgentToken: "unused-agent-token", KeyResolver: resolver,
		HTTPClient: &http.Client{Transport: transport}, Clock: clock,
		Events: &AgentEventsConfig{Store: store, Action: action},
	})
	if err != nil {
		t.Fatal(err)
	}
	return agent
}

type journeyPayloadTransport struct {
	mu      sync.Mutex
	handler http.Handler
	lost    bool
	bodies  [][]byte
	proofs  []string
}

func (transport *journeyPayloadTransport) setHandler(handler http.Handler) {
	transport.mu.Lock()
	defer transport.mu.Unlock()
	transport.handler = handler
}

func (transport *journeyPayloadTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	body, err := io.ReadAll(request.Body)
	if err != nil {
		return nil, err
	}
	request.Body = io.NopCloser(bytes.NewReader(body))
	request.ContentLength = int64(len(body))
	transport.mu.Lock()
	handler := transport.handler
	transport.bodies = append(transport.bodies, append([]byte(nil), body...))
	transport.proofs = append(transport.proofs, request.Header.Get("Signature-Input")+"\n"+request.Header.Get("Signature"))
	lose := !transport.lost
	if lose {
		transport.lost = true
	}
	transport.mu.Unlock()
	if handler == nil {
		return nil, errors.New("test: journey AP handler is unavailable")
	}
	response := eventRegistrationHTTPResponse(handler, request)
	if lose && response.StatusCode == http.StatusAccepted {
		_ = response.Body.Close()
		return nil, errors.New("test: journey accepted response was lost")
	}
	return response, nil
}

func (transport *journeyPayloadTransport) observed() ([][]byte, []string) {
	transport.mu.Lock()
	defer transport.mu.Unlock()
	bodies := make([][]byte, len(transport.bodies))
	for index := range transport.bodies {
		bodies[index] = append([]byte(nil), transport.bodies[index]...)
	}
	return bodies, append([]string(nil), transport.proofs...)
}

type journeyPayloadAction struct {
	mu              sync.Mutex
	dispatches      int
	reconciliations int
	payload         []byte
}

func (action *journeyPayloadAction) Dispatch(_ context.Context, input EventActionInput) (EventActionOutcome, error) {
	action.mu.Lock()
	defer action.mu.Unlock()
	action.dispatches++
	action.payload = append([]byte(nil), input.Payload...)
	return EventActionUnknown, nil
}

func (action *journeyPayloadAction) Reconcile(context.Context, EventActionKey) (EventActionOutcome, error) {
	action.mu.Lock()
	defer action.mu.Unlock()
	action.reconciliations++
	return EventActionCompleted, nil
}

func (action *journeyPayloadAction) snapshot() (int, int, []byte) {
	action.mu.Lock()
	defer action.mu.Unlock()
	return action.dispatches, action.reconciliations, append([]byte(nil), action.payload...)
}
