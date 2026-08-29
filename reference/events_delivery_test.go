package reference

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"io"
	"net/http"
	"path/filepath"
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
	if got := failedAuthority.subscriptions["event-failure"].UseCount; got != 0 || failedAuthority.nextDelivery != 0 || len(failedAuthority.inbox) != 0 {
		t.Fatalf("failed atomic event commit state = uses %d, sequence %d, inbox %d", got, failedAuthority.nextDelivery, len(failedAuthority.inbox))
	}

	now = now.Add(time.Second)
	recoveredProvider := newDeliveryTestProvider(t, apKey, failedAuthority, aauth.StaticKeyResolver{
		"https://resource.example": {resourceKey.ID(): resourceKey.PublicJWK()},
	}, clock)
	recoveredRequest, err := http.NewRequest(http.MethodPost, "https://ap.example/events", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := aauth.SignRequestWithSelfJWT(recoveredRequest, resourceKey, failingToken, clock); err != nil {
		t.Fatal(err)
	}
	recoveredResponse := eventRegistrationHTTPResponse(recoveredProvider.Handler(), recoveredRequest)
	defer recoveredResponse.Body.Close()
	if recoveredResponse.StatusCode != http.StatusAccepted {
		body, _ := io.ReadAll(recoveredResponse.Body)
		t.Fatalf("healthy retry status = %d: %s", recoveredResponse.StatusCode, body)
	}
	var recoveredBody struct {
		RemainingUses int `json:"remaining_uses"`
	}
	decoder := json.NewDecoder(recoveredResponse.Body)
	if err := decoder.Decode(&recoveredBody); err != nil || recoveredBody.RemainingUses != 0 {
		t.Fatalf("healthy retry body = %#v, %v", recoveredBody, err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		t.Fatalf("healthy retry body has trailing data: %v", err)
	}
	recoveredAccepted, err := failedAuthority.NextDelivery(ctx)
	if err != nil || recoveredAccepted.Token != failingToken {
		t.Fatalf("healthy retry inbox = %#v, %v", recoveredAccepted, err)
	}
	if got := failedAuthority.subscriptions["event-failure"].UseCount; got != 1 || failedAuthority.nextDelivery != 1 || len(failedAuthority.inbox) != 1 {
		t.Fatalf("healthy retry state = uses %d, sequence %d, inbox %d", got, failedAuthority.nextDelivery, len(failedAuthority.inbox))
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
	differentToken := mintDeliveryTestEvent(t, resourceKey, now, subscription.Agent, subscription.EventID)
	if differentToken == pending.Token {
		t.Fatal("different exhausted event token matched the retained token")
	}
	differentRequest, err := http.NewRequest(http.MethodPost, "https://ap.example/events", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := aauth.SignRequestWithSelfJWT(differentRequest, resourceKey, differentToken, clock); err != nil {
		t.Fatal(err)
	}
	differentResponse := eventRegistrationHTTPResponse(provider.Handler(), differentRequest)
	defer differentResponse.Body.Close()
	if differentResponse.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("different exhausted token status = %d, want 429", differentResponse.StatusCode)
	}
	unchangedAccepted, err := apStore.NextDelivery(ctx)
	if err != nil || unchangedAccepted.Token != pending.Token {
		t.Fatalf("different exhausted token changed inbox = %#v, %v", unchangedAccepted, err)
	}
}

func TestAPEventEndpointRefusalMatrixLeavesAuthorityUnchanged(t *testing.T) {
	t.Parallel()

	base := time.Date(2026, 8, 3, 8, 0, 0, 0, time.UTC)
	apKey := eventsProviderTestSigningKey(t, "ap-events-key")
	resourceKey := eventsProviderTestSigningKey(t, "resource-events-key")
	otherResourceKey := eventsProviderTestSigningKey(t, "other-resource-key")

	for _, test := range []struct {
		name          string
		wantStatus    int
		wantCode      string
		wantSignature aauth.SignatureErrorCode
	}{
		{name: "malformed body", wantStatus: http.StatusBadRequest, wantCode: "invalid_request"},
		{name: "invalid resource proof", wantStatus: http.StatusUnauthorized, wantCode: string(aauth.SignatureErrorInvalidSignature), wantSignature: aauth.SignatureErrorInvalidSignature},
		{name: "wrong resource", wantStatus: http.StatusForbidden, wantCode: "subscription_mismatch"},
		{name: "wrong agent", wantStatus: http.StatusForbidden, wantCode: "subscription_mismatch"},
		{name: "unknown event id", wantStatus: http.StatusNotFound, wantCode: "subscription_not_found"},
		{name: "expired event id", wantStatus: http.StatusNotFound, wantCode: "subscription_not_found"},
		{name: "expired token", wantStatus: http.StatusUnauthorized, wantCode: string(aauth.SignatureErrorExpiredJWT), wantSignature: aauth.SignatureErrorExpiredJWT},
		{name: "exhausted", wantStatus: http.StatusTooManyRequests, wantCode: "subscription_exhausted"},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			now := base
			clock := aauth.ClockFunc(func() time.Time { return now })
			store := NewMemoryAPEventStore("https://ap.example")
			subscription := APEventSubscription{
				APIssuer: "https://ap.example", EventID: "event-one",
				Resource: "https://resource.example", Agent: "aauth:subscriber@ap.example",
				ActiveUntil: now.Add(time.Hour), MaxUses: 1,
			}
			if test.name == "expired event id" {
				subscription.ActiveUntil = now
			}
			if err := store.CreateSubscription(ctx, subscription); err != nil {
				t.Fatal(err)
			}
			resolver := aauth.StaticKeyResolver{
				"https://resource.example":       {resourceKey.ID(): resourceKey.PublicJWK()},
				"https://other-resource.example": {otherResourceKey.ID(): otherResourceKey.PublicJWK()},
			}
			provider := newDeliveryTestProvider(t, apKey, store, resolver, clock)
			claims := aauth.EventTokenClaims{
				Issuer: "https://resource.example", DWK: aauth.ResourceDiscoveryDocument,
				Audience: "aauth:subscriber@ap.example", EventID: "event-one",
				IssuedAt: now.Unix(), ExpiresAt: now.Add(5 * time.Minute).Unix(),
			}
			proofKey := resourceKey
			var body io.Reader
			switch test.name {
			case "malformed body":
				body = strings.NewReader(`{"unexpected":true}`)
			case "wrong resource":
				claims.Issuer = "https://other-resource.example"
				proofKey = otherResourceKey
			case "wrong agent":
				claims.Audience = "aauth:other@ap.example"
			case "unknown event id":
				claims.EventID = "event-unknown"
			case "expired token":
				claims.IssuedAt = now.Add(-2 * time.Minute).Unix()
				claims.ExpiresAt = now.Add(-time.Minute).Unix()
			case "exhausted":
				seedToken := mintDeliveryTestEvent(t, resourceKey, now, claims.Audience, claims.EventID)
				accepted, _, err := store.AcceptEvent(ctx, AcceptedEventInput{
					Resource: claims.Issuer, Agent: claims.Audience, EventID: claims.EventID,
					Token: seedToken, AcceptedAt: now,
				})
				if err != nil {
					t.Fatal(err)
				}
				if err := store.AcknowledgeDelivery(ctx, accepted.Delivery.DeliveryID); err != nil {
					t.Fatal(err)
				}
			}
			compact, err := aauth.MintEventToken(proofTokenKey(test.name, resourceKey, otherResourceKey), claims)
			if err != nil {
				t.Fatal(err)
			}
			request, err := http.NewRequest(http.MethodPost, "https://ap.example/events", body)
			if err != nil {
				t.Fatal(err)
			}
			if body != nil {
				request.Header.Set("Content-Type", "application/json")
			}
			if err := aauth.SignRequestWithSelfJWT(request, proofKey, compact, clock); err != nil {
				t.Fatal(err)
			}
			if test.name == "invalid resource proof" {
				request.Header.Set("Signature", corruptDeliveryTestHTTPSignature(request.Header.Get("Signature")))
			}
			before := snapshotMemoryAPEventStore(t, store)
			response := eventRegistrationHTTPResponse(provider.Handler(), request)
			defer response.Body.Close()
			if response.StatusCode != test.wantStatus {
				responseBody, _ := io.ReadAll(response.Body)
				t.Fatalf("status = %d, want %d: %s", response.StatusCode, test.wantStatus, responseBody)
			}
			if got := response.Header.Get("Content-Type"); !strings.HasPrefix(got, "application/problem+json") {
				t.Fatalf("Content-Type = %q", got)
			}
			if got := response.Header.Get("Cache-Control"); got != "no-store" {
				t.Fatalf("Cache-Control = %q, want no-store", got)
			}
			var problem struct {
				Status int    `json:"status"`
				Error  string `json:"error"`
			}
			if err := json.NewDecoder(response.Body).Decode(&problem); err != nil || problem.Status != test.wantStatus || problem.Error != test.wantCode {
				t.Fatalf("problem = %#v, %v", problem, err)
			}
			signatureHeader := response.Header.Get("Signature-Error")
			if test.wantSignature != "" {
				parsed, err := aauth.ParseSignatureError(signatureHeader)
				if err != nil || parsed.Code != test.wantSignature {
					t.Fatalf("Signature-Error = %q, %#v, %v", signatureHeader, parsed, err)
				}
			} else if signatureHeader != "" {
				t.Fatalf("non-authentication refusal emitted Signature-Error %q", signatureHeader)
			}
			after := snapshotMemoryAPEventStore(t, store)
			if !bytes.Equal(before, after) {
				t.Fatalf("refusal changed AP snapshot\nbefore: %s\nafter:  %s", before, after)
			}
			if _, err := store.NextDelivery(ctx); !errors.Is(err, ErrNoPendingEventDelivery) {
				t.Fatalf("refusal queued adapter work: %v", err)
			}
		})
	}
}

func TestAPEventEndpointSerializesConcurrentFinalUseAcrossReconstruction(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	now := time.Date(2026, 8, 3, 8, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	apKey := eventsProviderTestSigningKey(t, "ap-events-key")
	resourceKeyA := eventsProviderTestSigningKey(t, "resource-events-a")
	resourceKeyB := eventsProviderTestSigningKey(t, "resource-events-b")
	resolver := aauth.StaticKeyResolver{
		"https://resource.example": {
			resourceKeyA.ID(): resourceKeyA.PublicJWK(),
			resourceKeyB.ID(): resourceKeyB.PublicJWK(),
		},
	}
	root := t.TempDir()
	apDirectory := filepath.Join(root, "ap-store")
	resourceDirectory := filepath.Join(root, "resource-store")
	store, err := OpenFileAPEventStore(FileAPEventStoreConfig{Directory: apDirectory, Issuer: "https://ap.example"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if store != nil {
			_ = store.Close()
		}
	})
	resourceStore, err := OpenFileResourceEventStore(FileResourceEventStoreConfig{Directory: resourceDirectory})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if resourceStore != nil {
			_ = resourceStore.Close()
		}
	})
	subscription := ResourceEventSubscription{
		APIssuer: "https://ap.example", EventID: "event-concurrent",
		Resource: "https://resource.example", Agent: "aauth:subscriber@ap.example",
		ActiveUntil: now.Add(time.Hour),
	}
	if err := resourceStore.Register(ctx, subscription); err != nil {
		t.Fatal(err)
	}
	if err := store.CreateSubscription(ctx, APEventSubscription{
		APIssuer: subscription.APIssuer, EventID: subscription.EventID,
		Resource: subscription.Resource, Agent: subscription.Agent,
		ActiveUntil: subscription.ActiveUntil, MaxUses: 1,
	}); err != nil {
		t.Fatal(err)
	}
	retainedToken := mintDeliveryTestEvent(t, resourceKeyA, now, subscription.Agent, subscription.EventID)
	if err := resourceStore.RetainPending(ctx, PendingEventDelivery{
		APIssuer: subscription.APIssuer, EventID: subscription.EventID,
		Token: retainedToken, CreatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	barrier := &twoArrivalAPEventStore{APEventStore: store, release: make(chan struct{})}
	provider := newDeliveryTestProvider(t, apKey, barrier, resolver, clock)
	directToken := mintDeliveryTestEvent(t, resourceKeyB, now, subscription.Agent, subscription.EventID)
	tokens := map[string]jose.SigningKey{
		retainedToken: resourceKeyA,
		directToken:   resourceKeyB,
	}
	metadataResolver := hostileEventMetadataResolver{
		StaticKeyResolver: resolver,
		metadata: aauth.AgentEventMetadata{
			Issuer: subscription.APIssuer, EventEndpoint: "https://ap.example/events",
		},
	}
	client := &http.Client{Transport: registrationRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		return eventRegistrationHTTPResponse(provider.Handler(), request), nil
	})}
	resource := newDeliveryTestResource(t, resourceKeyA, metadataResolver, client, clock, resourceStore)
	resourceResult := make(chan error, 1)
	directResult := make(chan struct {
		status int
		body   []byte
	}, 1)
	go func() {
		resourceResult <- resource.DeliverEvent(ctx, subscription.APIssuer, subscription.EventID)
	}()
	go func() {
		request, requestErr := http.NewRequestWithContext(ctx, http.MethodPost, "https://ap.example/events", nil)
		if requestErr != nil {
			directResult <- struct {
				status int
				body   []byte
			}{body: []byte(requestErr.Error())}
			return
		}
		if signErr := aauth.SignRequestWithSelfJWT(request, resourceKeyB, directToken, clock); signErr != nil {
			directResult <- struct {
				status int
				body   []byte
			}{body: []byte(signErr.Error())}
			return
		}
		response := eventRegistrationHTTPResponse(provider.Handler(), request)
		body, _ := io.ReadAll(response.Body)
		_ = response.Body.Close()
		directResult <- struct {
			status int
			body   []byte
		}{status: response.StatusCode, body: body}
	}()
	var directOutcome struct {
		status int
		body   []byte
	}
	select {
	case err := <-resourceResult:
		if err != nil {
			t.Fatalf("resource contender failed: %v", err)
		}
	case <-ctx.Done():
		t.Fatalf("resource contender did not finish: %v", ctx.Err())
	}
	select {
	case directOutcome = <-directResult:
	case <-ctx.Done():
		t.Fatalf("direct contender did not finish: %v", ctx.Err())
	}
	if directOutcome.status != http.StatusAccepted && directOutcome.status != http.StatusTooManyRequests {
		t.Fatalf("direct contender status = %d: %s", directOutcome.status, directOutcome.body)
	}
	winner := retainedToken
	if directOutcome.status == http.StatusAccepted {
		winner = directToken
		var body struct {
			RemainingUses int `json:"remaining_uses"`
		}
		decoder := json.NewDecoder(bytes.NewReader(directOutcome.body))
		if err := decoder.Decode(&body); err != nil || body.RemainingUses != 0 {
			t.Fatalf("direct winner body = %#v, %v: %s", body, err, directOutcome.body)
		}
		if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
			t.Fatalf("direct winner body has trailing data: %v", err)
		}
	}
	accepted, err := store.NextDelivery(ctx)
	if err != nil || accepted.Token != winner {
		t.Fatalf("winner inbox = %#v, %v; want token %q", accepted, err, winner)
	}
	if _, err := resourceStore.Load(ctx, subscription.APIssuer, subscription.EventID); !errors.Is(err, ErrEventSubscriptionNotFound) {
		t.Fatalf("settled resource subscription error = %v, want not found", err)
	}
	if _, err := resourceStore.LoadPending(ctx, subscription.APIssuer, subscription.EventID); !errors.Is(err, ErrEventPendingNotFound) {
		t.Fatalf("settled resource pending error = %v, want not found", err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store = nil
	if err := resourceStore.Close(); err != nil {
		t.Fatal(err)
	}
	resourceStore = nil

	store, err = OpenFileAPEventStore(FileAPEventStoreConfig{Directory: apDirectory, Issuer: "https://ap.example"})
	if err != nil {
		t.Fatal(err)
	}
	resourceStore, err = OpenFileResourceEventStore(FileResourceEventStoreConfig{Directory: resourceDirectory})
	if err != nil {
		t.Fatal(err)
	}
	provider = newDeliveryTestProvider(t, apKey, store, resolver, clock)
	accepted, err = store.NextDelivery(ctx)
	if err != nil || accepted.Token != winner {
		t.Fatalf("reopened winner inbox = %#v, %v; want token %q", accepted, err, winner)
	}
	if got := store.memory.subscriptions["event-concurrent"].UseCount; got != 1 || store.memory.nextDelivery != 1 || len(store.memory.inbox) != 1 {
		t.Fatalf("reopened final-use state = uses %d, sequence %d, inbox %d", got, store.memory.nextDelivery, len(store.memory.inbox))
	}
	if _, err := resourceStore.Load(ctx, subscription.APIssuer, subscription.EventID); !errors.Is(err, ErrEventSubscriptionNotFound) {
		t.Fatalf("reopened settled resource subscription error = %v, want not found", err)
	}
	if _, err := resourceStore.LoadPending(ctx, subscription.APIssuer, subscription.EventID); !errors.Is(err, ErrEventPendingNotFound) {
		t.Fatalf("reopened settled resource pending error = %v, want not found", err)
	}
	before := snapshotMemoryAPEventStore(t, store.memory)
	now = now.Add(time.Second)
	for name, attempt := range map[string]struct {
		token string
		key   jose.SigningKey
	}{
		"winning exact token": {token: winner, key: tokens[winner]},
		"different valid token": {
			token: mintDeliveryTestEvent(t, resourceKeyA, now, "aauth:subscriber@ap.example", "event-concurrent"),
			key:   resourceKeyA,
		},
	} {
		attempt := attempt
		t.Run(name, func(t *testing.T) {
			request, err := http.NewRequest(http.MethodPost, "https://ap.example/events", nil)
			if err != nil {
				t.Fatal(err)
			}
			if err := aauth.SignRequestWithSelfJWT(request, attempt.key, attempt.token, clock); err != nil {
				t.Fatal(err)
			}
			response := eventRegistrationHTTPResponse(provider.Handler(), request)
			defer response.Body.Close()
			if response.StatusCode != http.StatusTooManyRequests {
				body, _ := io.ReadAll(response.Body)
				t.Fatalf("exhausted status = %d: %s", response.StatusCode, body)
			}
			if after := snapshotMemoryAPEventStore(t, store.memory); !bytes.Equal(before, after) {
				t.Fatalf("exhausted request changed reopened AP state\nbefore: %s\nafter:  %s", before, after)
			}
		})
	}
}

func proofTokenKey(name string, resourceKey, otherResourceKey jose.SigningKey) jose.SigningKey {
	if name == "wrong resource" {
		return otherResourceKey
	}
	return resourceKey
}

func snapshotMemoryAPEventStore(t *testing.T, store *MemoryAPEventStore) []byte {
	t.Helper()
	body, _, err := encodeFileAPSnapshot(store)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func corruptDeliveryTestHTTPSignature(value string) string {
	start := strings.IndexByte(value, ':') + 1
	if start <= 0 || start >= len(value) {
		return value + "A"
	}
	replacement := byte('A')
	if value[start] == replacement {
		replacement = 'B'
	}
	return value[:start] + string(replacement) + value[start+1:]
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

func newDeliveryTestProvider(t *testing.T, key jose.SigningKey, store APEventStore, resolver aauth.KeyResolver, clock aauth.Clock) *AgentProvider {
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

func newDeliveryTestResource(t *testing.T, key jose.SigningKey, resolver aauth.KeyResolver, client *http.Client, clock aauth.Clock, store ResourceEventStore) *Resource {
	t.Helper()
	resource, err := NewResource(ResourceConfig{
		Identifier:               "https://resource.example",
		AccessMode:               aauth.AccessModeSessionToken,
		SigningKey:               key,
		KeyResolver:              resolver,
		Clock:                    clock,
		NewID:                    func() string { return "unused" },
		Scopes:                   []string{"qualification.read"},
		RequiredScopesForRequest: testRequiredResourceScopes("qualification.read"),
		ReplayStore:              testResourceReplayStore(t, clock),
		AuthorizationStore:       testAuthorizationStateStore(t),
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

func mintDeliveryTestEvent(t *testing.T, key jose.SigningKey, now time.Time, agent, eventID string) string {
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

type twoArrivalAPEventStore struct {
	APEventStore
	mu       sync.Mutex
	arrivals int
	release  chan struct{}
}

func (store *twoArrivalAPEventStore) AcceptEvent(ctx context.Context, input AcceptedEventInput) (AcceptedEvent, int, error) {
	store.mu.Lock()
	store.arrivals++
	arrival := store.arrivals
	if arrival == 2 {
		close(store.release)
	}
	release := store.release
	store.mu.Unlock()
	if arrival <= 2 {
		select {
		case <-ctx.Done():
			return AcceptedEvent{}, 0, ctx.Err()
		case <-release:
		}
	}
	return store.APEventStore.AcceptEvent(ctx, input)
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
