package reference

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"path/filepath"
	"sync"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
)

func TestEventPayloadDeliveryRetainsExactPairAndReconcilesLost202(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 8, 3, 10, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	resourceKey := eventsProviderTestSigningKey(t, "resource-payload-key")
	apKey := eventsProviderTestSigningKey(t, "ap-payload-key")
	document := protectedEventsTestDocument()
	contractStore := NewMemoryEventContractStore(clock)
	activeUntil := now.Add(time.Hour)
	if err := contractStore.Retain(ctx, aauth.R3S256(document), document, activeUntil); err != nil {
		t.Fatal(err)
	}
	resourceStore := NewMemoryResourceEventStore()
	subscription := ResourceEventSubscription{
		APIssuer: "https://ap.example", EventID: "event-payload",
		Resource: "https://resource.example", Agent: "aauth:subscriber@ap.example",
		ActiveUntil: activeUntil, ContractDigest: aauth.R3S256(document),
		OperationID: "subscribeProtectedWaitlist", MessageID: "slotAvailable",
	}
	if err := resourceStore.Register(ctx, subscription); err != nil {
		t.Fatal(err)
	}
	apStore := NewMemoryAPEventStore("https://ap.example")
	if err := apStore.CreateSubscription(ctx, APEventSubscription{
		APIssuer: subscription.APIssuer, EventID: subscription.EventID,
		Resource: subscription.Resource, Agent: subscription.Agent,
		ActiveUntil: subscription.ActiveUntil, MaxUses: 1,
		ContractDigest: subscription.ContractDigest,
		OperationID:    subscription.OperationID, MessageID: subscription.MessageID,
	}); err != nil {
		t.Fatal(err)
	}
	provider := newDeliveryTestProvider(t, apKey, apStore, aauth.StaticKeyResolver{
		subscription.Resource: {resourceKey.ID(): resourceKey.PublicJWK()},
	}, clock)
	transport := &lostAcceptedPayloadTransport{handler: provider.Handler()}
	resolver := hostileEventMetadataResolver{
		StaticKeyResolver: aauth.StaticKeyResolver{},
		metadata:          aauth.AgentEventMetadata{Issuer: subscription.APIssuer, EventEndpoint: "https://ap.example/events"},
	}
	resource := newPayloadDeliveryTestResource(t, resourceKey, resolver, &http.Client{Transport: transport}, clock, resourceStore, contractStore, document)
	if err := resource.DeliverEvent(ctx, subscription.APIssuer, subscription.EventID); !errors.Is(err, ErrEventPayloadNotAllowed) {
		t.Fatalf("legacy bodyless protected delivery error = %v", err)
	}
	if _, err := resourceStore.LoadPending(ctx, subscription.APIssuer, subscription.EventID); !errors.Is(err, ErrEventPendingNotFound) {
		t.Fatalf("legacy bodyless protected delivery retained pending custody: %v", err)
	}
	if bodies, _, _, _ := transport.observed(); len(bodies) != 0 {
		t.Fatalf("legacy bodyless protected delivery sent %d HTTP attempts", len(bodies))
	}
	payload := EventPayload{
		OperationID: subscription.OperationID, MessageID: subscription.MessageID,
		ContentType: "application/json",
		Body:        []byte(`{"event_type":"slot.available","slot_time":"2026-08-04T12:30:00Z"}`),
	}
	if err := resource.DeliverEventPayload(ctx, subscription.APIssuer, subscription.EventID, payload); err == nil {
		t.Fatal("lost 202 was reported as observed payload delivery")
	}
	pending, err := resourceStore.LoadPending(ctx, subscription.APIssuer, subscription.EventID)
	if err != nil {
		t.Fatal(err)
	}
	if pending.Token == "" || pending.ContentType != payload.ContentType ||
		!bytes.Equal(pending.Payload, payload.Body) || pending.PayloadDigest != eventPayloadDigest(payload.Body) {
		t.Fatalf("pending payload attempt = %#v", pending)
	}
	accepted, err := apStore.NextDelivery(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if accepted.Token != pending.Token || accepted.ContentType != pending.ContentType ||
		accepted.PayloadDigest != pending.PayloadDigest || !bytes.Equal(accepted.Payload, pending.Payload) {
		t.Fatalf("AP accepted pair = %#v, pending %#v", accepted, pending)
	}
	changed := payload
	changed.Body = []byte(`{"event_type":"slot.available","slot_time":"2026-08-04T12:45:00Z"}`)
	if err := resource.DeliverEventPayload(ctx, subscription.APIssuer, subscription.EventID, changed); !errors.Is(err, ErrEventPendingConflict) {
		t.Fatalf("changed retry error = %v, want pending conflict", err)
	}
	if bodies, _, _, _ := transport.observed(); len(bodies) != 1 {
		t.Fatalf("changed retry sent %d HTTP attempts", len(bodies))
	}

	now = now.Add(time.Second)
	rotatedDocument := bytes.Replace(document,
		[]byte(`"required":["event_type","slot_time"]`),
		[]byte(`"required":["event_type","slot_time","rotation_marker"]`), 1)
	resource = newPayloadDeliveryTestResource(t, resourceKey, resolver, &http.Client{Transport: transport}, clock, resourceStore, contractStore, rotatedDocument)
	if err := resource.DeliverEventPayload(ctx, subscription.APIssuer, subscription.EventID, payload); err != nil {
		t.Fatal(err)
	}
	bodies, mediaTypes, digests, proofs := transport.observed()
	if len(bodies) != 2 || !bytes.Equal(bodies[0], payload.Body) || !bytes.Equal(bodies[0], bodies[1]) {
		t.Fatalf("payload retry bodies = %#v", bodies)
	}
	if len(mediaTypes) != 2 || mediaTypes[0] != payload.ContentType || mediaTypes[1] != mediaTypes[0] ||
		len(digests) != 2 || digests[0] == "" || digests[0] != digests[1] {
		t.Fatalf("payload retry media/digests = %#v / %#v", mediaTypes, digests)
	}
	if len(proofs) != 2 || proofs[0] == "" || proofs[0] == proofs[1] {
		t.Fatalf("payload retry proofs = %#v", proofs)
	}
	if _, err := resourceStore.LoadPending(ctx, subscription.APIssuer, subscription.EventID); !errors.Is(err, ErrEventPendingNotFound) {
		t.Fatalf("settled pending error = %v", err)
	}
	if next, err := apStore.NextDelivery(ctx); err != nil || next.Delivery != accepted.Delivery {
		t.Fatalf("retry changed AP inbox = %#v, %v", next, err)
	}
}

func TestEventPayloadDeliveryRefusalsPrecedePendingCustodyAndTransport(t *testing.T) {
	base := time.Date(2026, 8, 3, 10, 0, 0, 0, time.UTC)
	resourceKey := eventsProviderTestSigningKey(t, "resource-payload-key")
	document := protectedEventsTestDocument()
	valid := EventPayload{
		OperationID: "subscribeProtectedWaitlist", MessageID: "slotAvailable",
		ContentType: "application/json",
		Body:        []byte(`{"event_type":"slot.available","slot_time":"2026-08-04T12:30:00Z"}`),
	}
	for _, test := range []struct {
		name           string
		mutate         func(*EventPayload)
		retainContract bool
	}{
		{name: "malformed JSON", retainContract: true, mutate: func(payload *EventPayload) { payload.Body = []byte(`{"event_type":`) }},
		{name: "schema mismatch", retainContract: true, mutate: func(payload *EventPayload) {
			payload.Body = []byte(`{"event_type":"different","slot_time":"2026-08-04T12:30:00Z"}`)
		}},
		{name: "wrong media type", retainContract: true, mutate: func(payload *EventPayload) { payload.ContentType = "application/problem+json" }},
		{name: "wrong operation", retainContract: true, mutate: func(payload *EventPayload) { payload.OperationID = "otherOperation" }},
		{name: "oversize", retainContract: true, mutate: func(payload *EventPayload) {
			payload.Body = append(bytes.Repeat([]byte(" "), maxEventPayloadBody), payload.Body...)
		}},
		{name: "missing retained contract", mutate: func(*EventPayload) {}},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			now := base
			clock := aauth.ClockFunc(func() time.Time { return now })
			contracts := NewMemoryEventContractStore(clock)
			if test.retainContract {
				if err := contracts.Retain(ctx, aauth.R3S256(document), document, now.Add(time.Hour)); err != nil {
					t.Fatal(err)
				}
			}
			store := NewMemoryResourceEventStore()
			subscription := ResourceEventSubscription{
				APIssuer: "https://ap.example", EventID: "event-refusal",
				Resource: "https://resource.example", Agent: "aauth:subscriber@ap.example",
				ActiveUntil: now.Add(time.Hour), ContractDigest: aauth.R3S256(document),
				OperationID: valid.OperationID, MessageID: valid.MessageID,
			}
			if err := store.Register(ctx, subscription); err != nil {
				t.Fatal(err)
			}
			sent := 0
			client := &http.Client{Transport: registrationRoundTripFunc(func(*http.Request) (*http.Response, error) {
				sent++
				return nil, errors.New("test: invalid payload reached transport")
			})}
			resolver := hostileEventMetadataResolver{
				metadata: aauth.AgentEventMetadata{Issuer: subscription.APIssuer, EventEndpoint: "https://ap.example/events"},
			}
			resource := newPayloadDeliveryTestResource(t, resourceKey, resolver, client, clock, store, contracts, document)
			payload := valid
			payload.Body = append([]byte(nil), valid.Body...)
			test.mutate(&payload)
			if err := resource.DeliverEventPayload(ctx, subscription.APIssuer, subscription.EventID, payload); err == nil {
				t.Fatal("invalid payload delivery succeeded")
			}
			if sent != 0 {
				t.Fatalf("invalid payload sent %d requests", sent)
			}
			if _, err := store.LoadPending(ctx, subscription.APIssuer, subscription.EventID); !errors.Is(err, ErrEventPendingNotFound) {
				t.Fatalf("invalid payload retained pending authority: %v", err)
			}
		})
	}

	t.Run("pending store failure", func(t *testing.T) {
		ctx := context.Background()
		now := base
		clock := aauth.ClockFunc(func() time.Time { return now })
		contracts := NewMemoryEventContractStore(clock)
		if err := contracts.Retain(ctx, aauth.R3S256(document), document, now.Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
		baseStore := NewMemoryResourceEventStore()
		subscription := ResourceEventSubscription{
			APIssuer: "https://ap.example", EventID: "event-store-failure",
			Resource: "https://resource.example", Agent: "aauth:subscriber@ap.example",
			ActiveUntil: now.Add(time.Hour), ContractDigest: aauth.R3S256(document),
			OperationID: valid.OperationID, MessageID: valid.MessageID,
		}
		if err := baseStore.Register(ctx, subscription); err != nil {
			t.Fatal(err)
		}
		commitFailure := errors.New("test: payload pending commit failed")
		store := &failingPayloadPendingStore{
			ResourceEventStore: baseStore, ProtectedEventTicketStore: baseStore, err: commitFailure,
		}
		sent := 0
		client := &http.Client{Transport: registrationRoundTripFunc(func(*http.Request) (*http.Response, error) {
			sent++
			return nil, errors.New("test: failed custody reached transport")
		})}
		resolver := hostileEventMetadataResolver{
			metadata: aauth.AgentEventMetadata{Issuer: subscription.APIssuer, EventEndpoint: "https://ap.example/events"},
		}
		resource := newPayloadDeliveryTestResource(t, resourceKey, resolver, client, clock, store, contracts, document)
		if err := resource.DeliverEventPayload(ctx, subscription.APIssuer, subscription.EventID, valid); !errors.Is(err, commitFailure) {
			t.Fatalf("pending failure = %v", err)
		}
		if sent != 0 {
			t.Fatalf("pending failure sent %d requests", sent)
		}
		if _, err := baseStore.LoadPending(ctx, subscription.APIssuer, subscription.EventID); !errors.Is(err, ErrEventPendingNotFound) {
			t.Fatalf("failed custody retained pending authority: %v", err)
		}
	})
}

func TestEventPayloadDeliveryAPProofRefusalsLeaveUseAndInboxUnchanged(t *testing.T) {
	base := time.Date(2026, 8, 3, 10, 0, 0, 0, time.UTC)
	apKey := eventsProviderTestSigningKey(t, "ap-payload-key")
	resourceKey := eventsProviderTestSigningKey(t, "resource-payload-key")
	document := protectedEventsTestDocument()
	validBody := []byte(`{"event_type":"slot.available","slot_time":"2026-08-04T12:30:00Z"}`)
	for _, test := range []struct {
		name       string
		body       []byte
		mediaType  string
		afterSign  func(*http.Request)
		wantStatus int
	}{
		{name: "body mutation", body: validBody, mediaType: "application/json", wantStatus: http.StatusUnauthorized, afterSign: func(request *http.Request) {
			changed := []byte(`{"event_type":"slot.available","slot_time":"2026-08-04T12:31:00Z"}`)
			request.Body = io.NopCloser(bytes.NewReader(changed))
			request.ContentLength = int64(len(changed))
		}},
		{name: "missing content digest", body: validBody, mediaType: "application/json", wantStatus: http.StatusUnauthorized, afterSign: func(request *http.Request) {
			request.Header.Del("Content-Digest")
		}},
		{name: "missing content type", body: validBody, mediaType: "application/json", wantStatus: http.StatusUnauthorized, afterSign: func(request *http.Request) {
			request.Header.Del("Content-Type")
		}},
		{name: "wrong signed media type", body: validBody, mediaType: "application/problem+json", wantStatus: http.StatusBadRequest},
		{name: "malformed JSON", body: []byte(`{"event_type":`), mediaType: "application/json", wantStatus: http.StatusBadRequest},
		{name: "duplicate JSON name", body: []byte(`{"event_type":"slot.available","event_type":"other","slot_time":"2026-08-04T12:30:00Z"}`), mediaType: "application/json", wantStatus: http.StatusBadRequest},
		{name: "oversize", body: bytes.Repeat([]byte(" "), maxEventPayloadBody+1), mediaType: "application/json", wantStatus: http.StatusRequestEntityTooLarge},
		{name: "bodyless protected delivery", wantStatus: http.StatusBadRequest},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			now := base
			clock := aauth.ClockFunc(func() time.Time { return now })
			store := NewMemoryAPEventStore("https://ap.example")
			subscription := APEventSubscription{
				APIssuer: "https://ap.example", EventID: "event-payload-refusal",
				Resource: "https://resource.example", Agent: "aauth:subscriber@ap.example",
				ActiveUntil: now.Add(time.Hour), MaxUses: 1,
				ContractDigest: aauth.R3S256(document),
				OperationID:    "subscribeProtectedWaitlist", MessageID: "slotAvailable",
			}
			if err := store.CreateSubscription(ctx, subscription); err != nil {
				t.Fatal(err)
			}
			provider := newDeliveryTestProvider(t, apKey, store, aauth.StaticKeyResolver{
				subscription.Resource: {resourceKey.ID(): resourceKey.PublicJWK()},
			}, clock)
			compact := mintDeliveryTestEvent(t, resourceKey, now, subscription.Agent, subscription.EventID)
			var body io.Reader
			if test.body != nil {
				body = bytes.NewReader(test.body)
			}
			request, err := http.NewRequest(http.MethodPost, "https://ap.example/events", body)
			if err != nil {
				t.Fatal(err)
			}
			if test.mediaType != "" {
				request.Header.Set("Content-Type", test.mediaType)
			}
			if err := aauth.SignRequestWithSelfJWT(request, resourceKey, compact, clock); err != nil {
				t.Fatal(err)
			}
			if test.afterSign != nil {
				test.afterSign(request)
			}
			before := snapshotMemoryAPEventStore(t, store)
			response := eventRegistrationHTTPResponse(provider.Handler(), request)
			defer response.Body.Close()
			if response.StatusCode != test.wantStatus {
				body, _ := io.ReadAll(response.Body)
				t.Fatalf("status = %d, want %d: %s", response.StatusCode, test.wantStatus, body)
			}
			after := snapshotMemoryAPEventStore(t, store)
			if !bytes.Equal(before, after) {
				t.Fatalf("refusal changed AP authority\nbefore: %s\nafter: %s", before, after)
			}
			if _, err := store.NextDelivery(ctx); !errors.Is(err, ErrNoPendingEventDelivery) {
				t.Fatalf("refusal queued AP inbox work: %v", err)
			}
		})
	}
}

func TestEventPayloadCustodyDefensivelyCopiesMemoryBoundaries(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 8, 3, 10, 0, 0, 0, time.UTC)
	document := protectedEventsTestDocument()
	payload := []byte(` {"event_type":"slot.available","slot_time":"2026-08-04T12:30:00Z"} `)
	want := append([]byte(nil), payload...)

	resourceStore := NewMemoryResourceEventStore()
	resourceSubscription := ResourceEventSubscription{
		APIssuer: "https://ap.example", EventID: "event-copy-resource",
		Resource: "https://resource.example", Agent: "aauth:subscriber@ap.example",
		ActiveUntil: now.Add(time.Hour), ContractDigest: aauth.R3S256(document),
		OperationID: "subscribeProtectedWaitlist", MessageID: "slotAvailable",
	}
	if err := resourceStore.Register(ctx, resourceSubscription); err != nil {
		t.Fatal(err)
	}
	pending := PendingEventDelivery{
		APIssuer: resourceSubscription.APIssuer, EventID: resourceSubscription.EventID,
		Token: "exact-event-token", ContentType: "application/json",
		Payload: payload, PayloadDigest: eventPayloadDigest(payload), CreatedAt: now,
	}
	if err := resourceStore.RetainPending(ctx, pending); err != nil {
		t.Fatal(err)
	}
	payload[1] = 'X'
	loaded, err := resourceStore.LoadPending(ctx, pending.APIssuer, pending.EventID)
	if err != nil || !bytes.Equal(loaded.Payload, want) {
		t.Fatalf("resource retained payload = %q, %v", loaded.Payload, err)
	}
	loaded.Payload[1] = 'Y'
	reloaded, err := resourceStore.LoadPending(ctx, pending.APIssuer, pending.EventID)
	if err != nil || !bytes.Equal(reloaded.Payload, want) {
		t.Fatalf("resource returned mutable payload = %q, %v", reloaded.Payload, err)
	}

	apStore := NewMemoryAPEventStore("https://ap.example")
	if err := apStore.CreateSubscription(ctx, APEventSubscription{
		APIssuer: "https://ap.example", EventID: "event-copy-ap",
		Resource: "https://resource.example", Agent: "aauth:subscriber@ap.example",
		ActiveUntil: now.Add(time.Hour), MaxUses: 1, ContractDigest: aauth.R3S256(document),
		OperationID: "subscribeProtectedWaitlist", MessageID: "slotAvailable",
	}); err != nil {
		t.Fatal(err)
	}
	apPayload := append([]byte(nil), want...)
	if _, _, err := apStore.AcceptEvent(ctx, AcceptedEventInput{
		Resource: "https://resource.example", Agent: "aauth:subscriber@ap.example",
		EventID: "event-copy-ap", Token: "exact-event-token", ContentType: "application/json",
		Payload: apPayload, PayloadDigest: eventPayloadDigest(apPayload), AcceptedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	apPayload[1] = 'Z'
	accepted, err := apStore.NextDelivery(ctx)
	if err != nil || !bytes.Equal(accepted.Payload, want) {
		t.Fatalf("AP retained payload = %q, %v", accepted.Payload, err)
	}
	accepted.Payload[1] = 'Q'
	again, err := apStore.NextDelivery(ctx)
	if err != nil || !bytes.Equal(again.Payload, want) {
		t.Fatalf("AP returned mutable payload = %q, %v", again.Payload, err)
	}
}

func TestEventPayloadFileStoresReopenExactCustody(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 8, 3, 10, 0, 0, 0, time.UTC)
	document := protectedEventsTestDocument()
	payload := []byte(" \n" + `{"event_type":"slot.available","slot_time":"2026-08-04T12:30:00Z"}` + "\n ")
	digest := eventPayloadDigest(payload)

	resourceConfig := FileResourceEventStoreConfig{Directory: filepath.Join(t.TempDir(), "resource")}
	resourceStore, err := OpenFileResourceEventStore(resourceConfig)
	if err != nil {
		t.Fatal(err)
	}
	resourceSubscription := ResourceEventSubscription{
		APIssuer: "https://ap.example", EventID: "event-file-payload",
		Resource: "https://resource.example", Agent: "aauth:subscriber@ap.example",
		ActiveUntil: now.Add(time.Hour), ContractDigest: aauth.R3S256(document),
		OperationID: "subscribeProtectedWaitlist", MessageID: "slotAvailable",
	}
	if err := resourceStore.Register(ctx, resourceSubscription); err != nil {
		t.Fatal(err)
	}
	pending := PendingEventDelivery{
		APIssuer: resourceSubscription.APIssuer, EventID: resourceSubscription.EventID,
		Token: "exact-file-event-token", ContentType: "application/json",
		Payload: payload, PayloadDigest: digest, CreatedAt: now,
	}
	if err := resourceStore.RetainPending(ctx, pending); err != nil {
		t.Fatal(err)
	}
	if err := resourceStore.Close(); err != nil {
		t.Fatal(err)
	}
	resourceStore, err = OpenFileResourceEventStore(resourceConfig)
	if err != nil {
		t.Fatal(err)
	}
	reopenedPending, err := resourceStore.LoadPending(ctx, pending.APIssuer, pending.EventID)
	if err != nil || reopenedPending.Token != pending.Token || reopenedPending.ContentType != pending.ContentType ||
		reopenedPending.PayloadDigest != digest || !bytes.Equal(reopenedPending.Payload, payload) {
		t.Fatalf("reopened resource payload = %#v, %v", reopenedPending, err)
	}
	if err := resourceStore.Close(); err != nil {
		t.Fatal(err)
	}

	apConfig := FileAPEventStoreConfig{Directory: filepath.Join(t.TempDir(), "ap"), Issuer: "https://ap.example"}
	apStore, err := OpenFileAPEventStore(apConfig)
	if err != nil {
		t.Fatal(err)
	}
	if err := apStore.CreateSubscription(ctx, APEventSubscription{
		APIssuer: "https://ap.example", EventID: "event-file-payload",
		Resource: "https://resource.example", Agent: "aauth:subscriber@ap.example",
		ActiveUntil: now.Add(time.Hour), MaxUses: 1, ContractDigest: aauth.R3S256(document),
		OperationID: "subscribeProtectedWaitlist", MessageID: "slotAvailable",
	}); err != nil {
		t.Fatal(err)
	}
	accepted, _, err := apStore.AcceptEvent(ctx, AcceptedEventInput{
		Resource: "https://resource.example", Agent: "aauth:subscriber@ap.example",
		EventID: "event-file-payload", Token: "exact-file-event-token",
		ContentType: "application/json", Payload: payload, PayloadDigest: digest, AcceptedAt: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := apStore.Close(); err != nil {
		t.Fatal(err)
	}
	apStore, err = OpenFileAPEventStore(apConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer apStore.Close()
	reopenedAccepted, err := apStore.NextDelivery(ctx)
	if err != nil || reopenedAccepted.Delivery != accepted.Delivery || reopenedAccepted.Token != accepted.Token ||
		reopenedAccepted.ContentType != accepted.ContentType || reopenedAccepted.PayloadDigest != digest ||
		!bytes.Equal(reopenedAccepted.Payload, payload) {
		t.Fatalf("reopened AP payload = %#v, %v", reopenedAccepted, err)
	}
}

func newPayloadDeliveryTestResource(
	t *testing.T,
	key aauth.SigningKey,
	resolver aauth.KeyResolver,
	client *http.Client,
	clock aauth.Clock,
	store ResourceEventStore,
	contracts EventContractStore,
	document []byte,
) *Resource {
	t.Helper()
	resource, err := NewResource(ResourceConfig{
		Identifier: "https://resource.example", AccessMode: aauth.AccessModeSessionToken,
		SigningKey: key, KeyResolver: resolver,
		Clock: clock, NewID: func() string { return "unused" }, Scopes: []string{"qualification.read"},
		RequiredScopesForRequest: testRequiredResourceScopes("qualification.read"),
		ReplayStore:              testResourceReplayStore(t, clock),
		AuthorizationStore:       testAuthorizationStateStore(t),
		AuthorizationPolicy: func(context.Context, aauth.AuthorizationRequest) (aauth.AuthorizationDecision, error) {
			return aauth.AuthorizationDecision{}, errors.New("unused")
		},
		Operation: func(context.Context, aauth.AuthorizedRequest) (any, error) { return nil, errors.New("unused") },
		Events: &ResourceEventsConfig{
			PublicSubscriptionPath: "/events/subscriptions", Store: store, HTTPClient: client,
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

type lostAcceptedPayloadTransport struct {
	mu           sync.Mutex
	handler      http.Handler
	bodies       [][]byte
	mediaTypes   []string
	digests      []string
	proofs       []string
	lostResponse bool
}

type failingPayloadPendingStore struct {
	ResourceEventStore
	ProtectedEventTicketStore
	err error
}

func (store *failingPayloadPendingStore) RetainPending(context.Context, PendingEventDelivery) error {
	return store.err
}

func (transport *lostAcceptedPayloadTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	body, err := io.ReadAll(request.Body)
	if err != nil {
		return nil, err
	}
	request.Body = io.NopCloser(bytes.NewReader(body))
	request.ContentLength = int64(len(body))
	transport.mu.Lock()
	transport.bodies = append(transport.bodies, append([]byte(nil), body...))
	transport.mediaTypes = append(transport.mediaTypes, request.Header.Get("Content-Type"))
	transport.digests = append(transport.digests, request.Header.Get("Content-Digest"))
	transport.proofs = append(transport.proofs, request.Header.Get("Signature"))
	lose := !transport.lostResponse
	if lose {
		transport.lostResponse = true
	}
	transport.mu.Unlock()
	response := eventRegistrationHTTPResponse(transport.handler, request)
	if lose && response.StatusCode == http.StatusAccepted {
		_ = response.Body.Close()
		return nil, errors.New("test: accepted payload response lost")
	}
	return response, nil
}

func (transport *lostAcceptedPayloadTransport) observed() ([][]byte, []string, []string, []string) {
	transport.mu.Lock()
	defer transport.mu.Unlock()
	bodies := make([][]byte, len(transport.bodies))
	for index := range transport.bodies {
		bodies[index] = append([]byte(nil), transport.bodies[index]...)
	}
	return bodies, append([]string(nil), transport.mediaTypes...), append([]string(nil), transport.digests...), append([]string(nil), transport.proofs...)
}
