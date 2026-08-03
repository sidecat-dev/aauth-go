package reference

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
)

func TestProtectedEventTicketIssueFollowsAuthenticatedOperationCommit(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 8, 3, 9, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	resourceKey := eventsProviderTestSigningKey(t, "resource-key")
	accessKey := eventsProviderTestSigningKey(t, "access-key")
	agentKey := eventsProviderTestSigningKey(t, "agent-key")
	store := NewMemoryResourceEventStore()
	contracts := NewMemoryEventContractStore(clock)
	document := protectedEventsTestDocument()
	activeUntil := now.Add(2 * time.Hour)

	resource := newProtectedEventsTestResource(t, protectedEventsTestResourceInput{
		clock: clock, resourceKey: resourceKey,
		resolver: aauth.StaticKeyResolver{"https://as.example": {accessKey.ID(): accessKey.PublicJWK()}},
		store:    store, contracts: contracts, document: document,
		operation: func(_ context.Context, authorized aauth.AuthorizedRequest) (any, error) {
			return ProtectedEventOperationResult{
				Ticket: ProtectedEventTicketRequest{
					ResourceRevision: "appointment-state-17", ActiveUntil: activeUntil,
				},
				Response: func(grant ProtectedEventTicketGrant) (any, error) {
					return map[string]any{
						"status": "unavailable",
						"waitlist": map[string]any{
							"subscribe_url": grant.URL,
							"contract_s256": grant.ContractDigest,
							"operation_id":  grant.OperationID,
							"message_id":    grant.MessageID,
						},
					}, nil
				},
			}, nil
		},
	})
	compact := protectedEventsTestAuthToken(t, accessKey, agentKey, now)
	request := httptest.NewRequest(http.MethodPost, "https://resource.example/appointments/search", nil)
	if err := aauth.SignRequest(request, agentKey, compact, clock); err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	resource.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("protected operation status = %d: %s", response.Code, response.Body.Bytes())
	}
	var result struct {
		Waitlist struct {
			SubscribeURL   string `json:"subscribe_url"`
			ContractDigest string `json:"contract_s256"`
			OperationID    string `json:"operation_id"`
			MessageID      string `json:"message_id"`
		} `json:"waitlist"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(result.Waitlist.SubscribeURL)
	if err != nil || parsed.Scheme != "https" || parsed.Host != "resource.example" {
		t.Fatalf("subscribe URL = %q, %v", result.Waitlist.SubscribeURL, err)
	}
	rawTicket := strings.TrimPrefix(parsed.Path, "/appointments/waitlist/")
	decoded, err := base64.RawURLEncoding.DecodeString(rawTicket)
	if err != nil || len(decoded) != 32 {
		t.Fatalf("ticket capability = %q, bytes/error = %d/%v", rawTicket, len(decoded), err)
	}
	digest := protectedEventTicketDigest(rawTicket)
	ticket, err := store.LoadTicket(ctx, digest)
	if err != nil {
		t.Fatal(err)
	}
	if ticket.TicketDigest != digest || ticket.Agent != "aauth:subscriber@ap.example" ||
		ticket.Resource != "https://resource.example" || ticket.AuthorizedMethod != http.MethodPost ||
		ticket.AuthorizedPath != "/appointments/search" || ticket.ResourceRevision != "appointment-state-17" ||
		ticket.ContractDigest != aauth.R3S256(document) ||
		ticket.OperationID != "subscribeProtectedWaitlist" || ticket.MessageID != "slotAvailable" ||
		!ticket.ExpiresAt.Equal(now.Add(time.Minute)) || !ticket.ActiveUntil.Equal(activeUntil) {
		t.Fatalf("retained ticket = %#v", ticket)
	}
	if strings.Contains(string(mustJSONMarshalProtectedTicket(t, ticket)), rawTicket) {
		t.Fatal("ticket authority retained the raw URL capability")
	}
	retainedDocument, err := contracts.Load(ctx, ticket.ContractDigest)
	if err != nil || !bytes.Equal(retainedDocument, document) {
		t.Fatalf("retained contract = %q, %v", retainedDocument, err)
	}
	if result.Waitlist.ContractDigest != ticket.ContractDigest ||
		result.Waitlist.OperationID != ticket.OperationID || result.Waitlist.MessageID != ticket.MessageID {
		t.Fatalf("outward ticket selection = %#v", result.Waitlist)
	}

	// An unauthenticated request cannot invoke the operation or mint another
	// ticket. The already committed record remains the only authority.
	unauthenticated := httptest.NewRecorder()
	resource.Handler().ServeHTTP(unauthenticated, httptest.NewRequest(http.MethodPost, "https://resource.example/appointments/search", nil))
	if unauthenticated.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated status = %d", unauthenticated.Code)
	}
	if got := store.ticketCount(); got != 1 {
		t.Fatalf("ticket count after unauthenticated call = %d, want 1", got)
	}
}

func TestProtectedEventsConfigurationRejectsWildcardPublicRouteConflict(t *testing.T) {
	now := time.Date(2026, 8, 3, 9, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	resourceKey := eventsProviderTestSigningKey(t, "resource-key")
	store := NewMemoryResourceEventStore()
	_, err := NewResource(ResourceConfig{
		Identifier: "https://resource.example", AccessServer: "https://as.example",
		SigningKey: resourceKey, KeyResolver: aauth.StaticKeyResolver{}, Clock: clock,
		NewID: func() string { return "unused" }, Scopes: []string{"events.read"},
		Operation: func(context.Context, aauth.AuthorizedRequest) (any, error) { return nil, nil },
		Events: &ResourceEventsConfig{
			PublicSubscriptionPath: "/appointments/waitlist/{subscriptionTicket}",
			Store:                  store, HTTPClient: &http.Client{},
			ActiveUntil: func(context.Context, aauth.SubscribeTokenClaims) (time.Time, error) {
				return now.Add(time.Hour), nil
			},
			AsyncAPIPath: "/asyncapi.json", AsyncAPIDocument: protectedEventsTestDocument(),
			ProtectedOperationID: "subscribeProtectedWaitlist", ProtectedMessageID: "slotAvailable",
			ContractStore: NewMemoryEventContractStore(clock), TicketLifetime: time.Minute,
		},
	})
	if err == nil {
		t.Fatal("resource accepted a wildcard public route that conflicts with protected registration")
	}
}

func TestEventsConfigurationRejectsReservedOrTemplatedRoutes(t *testing.T) {
	now := time.Date(2026, 8, 3, 9, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	resourceKey := eventsProviderTestSigningKey(t, "resource-key")
	for _, test := range []struct {
		name       string
		publicPath string
		asyncPath  string
	}{
		{name: "built-in POST", publicPath: "/authorize", asyncPath: "/asyncapi.json"},
		{name: "built-in GET", publicPath: "/events/subscriptions", asyncPath: "/jwks"},
		{name: "templated discovery", publicPath: "/events/subscriptions", asyncPath: "/contracts/{version}"},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := NewMemoryResourceEventStore()
			_, err := NewResource(ResourceConfig{
				Identifier: "https://resource.example", AccessServer: "https://as.example",
				SigningKey: resourceKey, KeyResolver: aauth.StaticKeyResolver{}, Clock: clock,
				NewID: func() string { return "unused" }, Scopes: []string{"events.read"},
				Operation: func(context.Context, aauth.AuthorizedRequest) (any, error) { return nil, nil },
				Events: &ResourceEventsConfig{
					PublicSubscriptionPath: test.publicPath, Store: store, HTTPClient: &http.Client{},
					ActiveUntil: func(context.Context, aauth.SubscribeTokenClaims) (time.Time, error) {
						return now.Add(time.Hour), nil
					},
					AsyncAPIPath: test.asyncPath, AsyncAPIDocument: protectedEventsTestDocument(),
					ProtectedOperationID: "subscribeProtectedWaitlist", ProtectedMessageID: "slotAvailable",
					ContractStore: NewMemoryEventContractStore(clock), TicketLifetime: time.Minute,
				},
			})
			if err == nil {
				t.Fatal("resource accepted conflicting or templated route configuration")
			}
		})
	}
}

func TestProtectedEventTicketIssueFailureReleasesNoURL(t *testing.T) {
	now := time.Date(2026, 8, 3, 9, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	resourceKey := eventsProviderTestSigningKey(t, "resource-key")
	accessKey := eventsProviderTestSigningKey(t, "access-key")
	agentKey := eventsProviderTestSigningKey(t, "agent-key")
	commitFailure := errors.New("test: ticket commit failed")
	baseStore := NewMemoryResourceEventStore()
	store := &failingProtectedEventTicketStore{
		ResourceEventStore: baseStore, ProtectedEventTicketStore: baseStore, createErr: commitFailure,
	}
	var rendered bool
	resource := newProtectedEventsTestResource(t, protectedEventsTestResourceInput{
		clock: clock, resourceKey: resourceKey,
		resolver: aauth.StaticKeyResolver{"https://as.example": {accessKey.ID(): accessKey.PublicJWK()}},
		store:    store, contracts: NewMemoryEventContractStore(clock), document: protectedEventsTestDocument(),
		operation: func(context.Context, aauth.AuthorizedRequest) (any, error) {
			return ProtectedEventOperationResult{
				Ticket: ProtectedEventTicketRequest{ResourceRevision: "state-1", ActiveUntil: now.Add(time.Hour)},
				Response: func(ProtectedEventTicketGrant) (any, error) {
					rendered = true
					return map[string]string{"unexpected": "ticket"}, nil
				},
			}, nil
		},
	})
	compact := protectedEventsTestAuthToken(t, accessKey, agentKey, now)
	request := httptest.NewRequest(http.MethodPost, "https://resource.example/appointments/search", nil)
	if err := aauth.SignRequest(request, agentKey, compact, clock); err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	resource.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable || rendered || strings.Contains(response.Body.String(), "subscribe") {
		t.Fatalf("failed issue response/rendered = %d %q/%t", response.Code, response.Body.String(), rendered)
	}
}

func TestProtectedEventTicketIssueRejectsIncompleteOrCollidingAuthority(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 8, 3, 9, 0, 0, 0, time.UTC)
	document := protectedEventsTestDocument()
	valid := protectedEventsTestTicket("collision-resistant-capability", now, document)
	store := NewMemoryResourceEventStore()
	if err := store.CreateTicket(ctx, valid); err != nil {
		t.Fatal(err)
	}

	replacement := valid
	replacement.ResourceRevision = "replacement-state"
	if err := store.CreateTicket(ctx, replacement); !errors.Is(err, ErrProtectedEventTicketConflict) {
		t.Fatalf("colliding ticket error = %v", err)
	}
	retained, err := store.LoadTicket(ctx, valid.TicketDigest)
	if err != nil || retained != valid {
		t.Fatalf("colliding ticket replaced retained authority: %#v, %v", retained, err)
	}

	for name, mutate := range map[string]func(*ProtectedEventTicket){
		"digest":            func(ticket *ProtectedEventTicket) { ticket.TicketDigest = "short" },
		"resource":          func(ticket *ProtectedEventTicket) { ticket.Resource = "http://resource.example" },
		"agent":             func(ticket *ProtectedEventTicket) { ticket.Agent = "not-an-agent" },
		"method":            func(ticket *ProtectedEventTicket) { ticket.AuthorizedMethod = "" },
		"path":              func(ticket *ProtectedEventTicket) { ticket.AuthorizedPath = "" },
		"resource revision": func(ticket *ProtectedEventTicket) { ticket.ResourceRevision = "" },
		"contract digest":   func(ticket *ProtectedEventTicket) { ticket.ContractDigest = "" },
		"operation":         func(ticket *ProtectedEventTicket) { ticket.OperationID = "" },
		"message":           func(ticket *ProtectedEventTicket) { ticket.MessageID = "" },
		"expiry":            func(ticket *ProtectedEventTicket) { ticket.ExpiresAt = time.Time{} },
		"active lifetime":   func(ticket *ProtectedEventTicket) { ticket.ActiveUntil = ticket.ExpiresAt },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := protectedEventsTestTicket("invalid-"+name, now, document)
			mutate(&candidate)
			if err := store.CreateTicket(ctx, candidate); !errors.Is(err, ErrEventRecordInvalid) {
				t.Fatalf("incomplete ticket error = %v", err)
			}
		})
	}
	if got := store.ticketCount(); got != 1 {
		t.Fatalf("ticket count after refusals = %d, want 1", got)
	}
}

func TestProtectedEventRegistrationConsumesTicketAndCreatesSubscriptionAtomically(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 8, 3, 9, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	resourceKey := eventsProviderTestSigningKey(t, "resource-key")
	apKey := eventsProviderTestSigningKey(t, "ap-key")
	agentKey := eventsProviderTestSigningKey(t, "agent-key")
	store := NewMemoryResourceEventStore()
	document := protectedEventsTestDocument()
	resource := newProtectedEventsTestResource(t, protectedEventsTestResourceInput{
		clock: clock, resourceKey: resourceKey,
		resolver: aauth.StaticKeyResolver{"https://ap.example": {apKey.ID(): apKey.PublicJWK()}},
		store:    store, contracts: NewMemoryEventContractStore(clock), document: document,
		operation: func(context.Context, aauth.AuthorizedRequest) (any, error) {
			return map[string]string{"status": "ok"}, nil
		},
	})
	rawTicket := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, 32))
	ticket := protectedEventsTestTicket(rawTicket, now, document)
	if err := store.CreateTicket(ctx, ticket); err != nil {
		t.Fatal(err)
	}
	compact := protectedEventsTestSubscribeToken(t, apKey, agentKey, now, "event-protected")
	request := httptest.NewRequest(http.MethodPost, "https://resource.example/appointments/waitlist/"+rawTicket, nil)
	if err := aauth.SignRequest(request, agentKey, compact, clock); err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	resource.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusCreated {
		t.Fatalf("registration status = %d: %s", response.Code, response.Body.Bytes())
	}
	if _, err := store.LoadTicket(ctx, ticket.TicketDigest); !errors.Is(err, ErrProtectedEventTicketNotFound) {
		t.Fatalf("consumed ticket load error = %v", err)
	}
	subscription, err := store.Load(ctx, "https://ap.example", "event-protected")
	if err != nil {
		t.Fatal(err)
	}
	if subscription.Agent != ticket.Agent || subscription.Resource != ticket.Resource ||
		subscription.ContractDigest != ticket.ContractDigest || subscription.OperationID != ticket.OperationID ||
		subscription.MessageID != ticket.MessageID || !subscription.ActiveUntil.Equal(ticket.ActiveUntil) {
		t.Fatalf("protected subscription = %#v", subscription)
	}

	replay := httptest.NewRecorder()
	replayRequest := httptest.NewRequest(http.MethodPost, "https://resource.example/appointments/waitlist/"+rawTicket, nil)
	if err := aauth.SignRequest(replayRequest, agentKey, compact, clock); err != nil {
		t.Fatal(err)
	}
	resource.Handler().ServeHTTP(replay, replayRequest)
	if replay.Code != http.StatusNotFound {
		t.Fatalf("used ticket replay status = %d", replay.Code)
	}
}

func TestProtectedEventRegistrationRejectsTicketFromAnotherResourceAuthority(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 8, 3, 9, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	resourceKey := eventsProviderTestSigningKey(t, "resource-key")
	apKey := eventsProviderTestSigningKey(t, "ap-key")
	agentKey := eventsProviderTestSigningKey(t, "agent-key")
	store := NewMemoryResourceEventStore()
	document := protectedEventsTestDocument()
	resource := newProtectedEventsTestResource(t, protectedEventsTestResourceInput{
		clock: clock, resourceKey: resourceKey,
		resolver: aauth.StaticKeyResolver{"https://ap.example": {apKey.ID(): apKey.PublicJWK()}},
		store:    store, contracts: NewMemoryEventContractStore(clock), document: document,
		operation: func(context.Context, aauth.AuthorizedRequest) (any, error) { return nil, nil },
	})
	rawTicket := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x62}, 32))
	ticket := protectedEventsTestTicket(rawTicket, now, document)
	ticket.Resource = "https://other-resource.example"
	if err := store.CreateTicket(ctx, ticket); err != nil {
		t.Fatal(err)
	}
	compact := protectedEventsTestSubscribeToken(t, apKey, agentKey, now, "event-cross-resource")
	request := httptest.NewRequest(http.MethodPost, "https://resource.example/appointments/waitlist/"+rawTicket, nil)
	if err := aauth.SignRequest(request, agentKey, compact, clock); err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	resource.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("cross-resource ticket status = %d: %s", response.Code, response.Body.Bytes())
	}
	if _, err := store.LoadTicket(ctx, ticket.TicketDigest); err != nil {
		t.Fatalf("cross-resource refusal consumed ticket: %v", err)
	}
	if got := store.subscriptionCount(); got != 0 {
		t.Fatalf("cross-resource refusal created %d subscriptions", got)
	}
}

func TestProtectedEventRegistrationRetainsExactAgentContractContextBeforeSend(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 8, 3, 9, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	resourceKey := eventsProviderTestSigningKey(t, "resource-key")
	apKey := eventsProviderTestSigningKey(t, "ap-key")
	agentKey := eventsProviderTestSigningKey(t, "agent-key")
	resolver := aauth.StaticKeyResolver{"https://ap.example": {apKey.ID(): apKey.PublicJWK()}}
	resourceStore := NewMemoryResourceEventStore()
	document := protectedEventsTestDocument()
	resource := newProtectedEventsTestResource(t, protectedEventsTestResourceInput{
		clock: clock, resourceKey: resourceKey, resolver: resolver,
		store: resourceStore, contracts: NewMemoryEventContractStore(clock), document: document,
		operation: func(context.Context, aauth.AuthorizedRequest) (any, error) { return nil, nil },
	})
	rawTicket := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x24}, 32))
	ticket := protectedEventsTestTicket(rawTicket, now, document)
	if err := resourceStore.CreateTicket(ctx, ticket); err != nil {
		t.Fatal(err)
	}
	compact := protectedEventsTestSubscribeToken(t, apKey, agentKey, now, "event-protected-context")
	grant := ProtectedEventTicketGrant{
		URL:            "https://resource.example/appointments/waitlist/" + rawTicket,
		ContractDigest: ticket.ContractDigest, OperationID: ticket.OperationID, MessageID: ticket.MessageID,
	}
	localContext := AgentEventContext{
		APIssuer: "https://ap.example", EventID: "event-protected-context",
		Value:    json.RawMessage(`{"appointment":"local-42"}`),
		Contract: append([]byte(nil), document...), ContractDigest: ticket.ContractDigest,
		OperationID: ticket.OperationID, MessageID: ticket.MessageID,
	}
	agentStore := NewMemoryAgentEventStore()
	transportCalls := 0
	agent := newRegistrationTestAgent(t, resolver, clock, agentKey, agentStore, registrationRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		transportCalls++
		retained, err := agentStore.LookupContext(ctx, localContext.APIssuer, localContext.EventID)
		if err != nil || !bytes.Equal(retained.Contract, document) || retained.ContractDigest != grant.ContractDigest ||
			retained.OperationID != grant.OperationID || retained.MessageID != grant.MessageID {
			t.Fatalf("agent context before send = %#v, %v", retained, err)
		}
		return eventRegistrationHTTPResponse(resource.Handler(), request), nil
	}))
	if err := agent.RegisterProtectedEventSubscription(ctx, grant, compact, localContext); err != nil {
		t.Fatal(err)
	}
	if transportCalls != 1 {
		t.Fatalf("transport calls = %d, want 1", transportCalls)
	}
	if _, err := resourceStore.Load(ctx, "https://ap.example", localContext.EventID); err != nil {
		t.Fatal(err)
	}

	drifted := localContext
	drifted.ContractDigest = protectedEventTicketDigest("other-contract")
	if err := agent.RegisterProtectedEventSubscription(ctx, grant, compact, drifted); err == nil {
		t.Fatal("agent accepted a contract digest different from the ticket grant")
	}
	if transportCalls != 1 {
		t.Fatalf("contract mismatch sent a request; calls = %d", transportCalls)
	}
}

func TestProtectedEventRegistrationValidatorRunsAfterCoveredBodyProofAndBeforeConsumption(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 8, 3, 9, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	resourceKey := eventsProviderTestSigningKey(t, "resource-key")
	apKey := eventsProviderTestSigningKey(t, "ap-key")
	agentKey := eventsProviderTestSigningKey(t, "agent-key")
	store := NewMemoryResourceEventStore()
	document := protectedEventsTestDocument()
	validatorCalls := 0
	resource := newProtectedEventsTestResource(t, protectedEventsTestResourceInput{
		clock: clock, resourceKey: resourceKey,
		resolver: aauth.StaticKeyResolver{"https://ap.example": {apKey.ID(): apKey.PublicJWK()}},
		store:    store, contracts: NewMemoryEventContractStore(clock), document: document,
		operation: func(context.Context, aauth.AuthorizedRequest) (any, error) { return nil, nil },
		registrationValidator: func(_ context.Context, registration ProtectedEventRegistration) error {
			validatorCalls++
			if registration.Agent != "aauth:subscriber@ap.example" || registration.APIssuer != "https://ap.example" ||
				registration.EventID == "" || registration.ContentType != "application/json" {
				t.Fatalf("validated registration = %#v", registration)
			}
			if bytes.Equal(registration.Body, []byte(`{"event_types":[]}`)) {
				return errors.New("test: registration selection required")
			}
			if !bytes.Equal(registration.Body, []byte(`{"event_types":["slot.available"]}`)) {
				t.Fatalf("validated registration body = %q", registration.Body)
			}
			return nil
		},
	})
	rawTicket := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x51}, 32))
	ticket := protectedEventsTestTicket(rawTicket, now, document)
	if err := store.CreateTicket(ctx, ticket); err != nil {
		t.Fatal(err)
	}
	compact := protectedEventsTestSubscribeToken(t, apKey, agentKey, now, "event-body-registration")
	body := []byte(`{"event_types":["slot.available"]}`)
	request := httptest.NewRequest(http.MethodPost, "https://resource.example/appointments/waitlist/"+rawTicket, bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	if err := aauth.SignRequest(request, agentKey, compact, clock); err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	resource.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusCreated || validatorCalls != 1 {
		t.Fatalf("validated registration = %d %q, calls %d", response.Code, response.Body.Bytes(), validatorCalls)
	}

	invalidRaw := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x53}, 32))
	invalidTicket := protectedEventsTestTicket(invalidRaw, now, document)
	if err := store.CreateTicket(ctx, invalidTicket); err != nil {
		t.Fatal(err)
	}
	invalidCompact := protectedEventsTestSubscribeToken(t, apKey, agentKey, now, "event-invalid-registration")
	invalidBody := []byte(`{"event_types":[]}`)
	invalid := httptest.NewRequest(http.MethodPost, "https://resource.example/appointments/waitlist/"+invalidRaw, bytes.NewReader(invalidBody))
	invalid.Header.Set("Content-Type", "application/json")
	if err := aauth.SignRequest(invalid, agentKey, invalidCompact, clock); err != nil {
		t.Fatal(err)
	}
	invalidResponse := httptest.NewRecorder()
	resource.Handler().ServeHTTP(invalidResponse, invalid)
	if invalidResponse.Code != http.StatusBadRequest || validatorCalls != 2 {
		t.Fatalf("invalid registration = %d %q, validator calls %d", invalidResponse.Code, invalidResponse.Body.Bytes(), validatorCalls)
	}
	if _, err := store.LoadTicket(ctx, invalidTicket.TicketDigest); err != nil {
		t.Fatalf("validator refusal consumed ticket: %v", err)
	}

	rejectedRaw := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x52}, 32))
	rejectedTicket := protectedEventsTestTicket(rejectedRaw, now, document)
	if err := store.CreateTicket(ctx, rejectedTicket); err != nil {
		t.Fatal(err)
	}
	rejectedCompact := protectedEventsTestSubscribeToken(t, apKey, agentKey, now, "event-tampered-registration")
	rejected := httptest.NewRequest(http.MethodPost, "https://resource.example/appointments/waitlist/"+rejectedRaw, bytes.NewReader(body))
	rejected.Header.Set("Content-Type", "application/json")
	if err := aauth.SignRequest(rejected, agentKey, rejectedCompact, clock); err != nil {
		t.Fatal(err)
	}
	rejected.Body = io.NopCloser(strings.NewReader(`{"event_types":["changed"]}`))
	rejected.ContentLength = int64(len(`{"event_types":["changed"]}`))
	rejectedResponse := httptest.NewRecorder()
	resource.Handler().ServeHTTP(rejectedResponse, rejected)
	if rejectedResponse.Code != http.StatusUnauthorized || validatorCalls != 2 {
		t.Fatalf("tampered registration = %d %q, validator calls %d", rejectedResponse.Code, rejectedResponse.Body.Bytes(), validatorCalls)
	}
	if _, err := store.LoadTicket(ctx, rejectedTicket.TicketDigest); err != nil {
		t.Fatalf("tampered proof consumed ticket: %v", err)
	}
}

func TestProtectedEventRegistrationRefusalsLeaveTicketUsable(t *testing.T) {
	now := time.Date(2026, 8, 3, 9, 0, 0, 0, time.UTC)
	resourceKey := eventsProviderTestSigningKey(t, "resource-key")
	apKey := eventsProviderTestSigningKey(t, "ap-key")
	agentKey := eventsProviderTestSigningKey(t, "agent-key")
	otherAgentKey := eventsProviderTestSigningKey(t, "other-agent-key")
	document := protectedEventsTestDocument()
	for _, test := range []struct {
		name        string
		body        string
		claimsAgent string
		requestKey  aauth.SigningKey
		tokenKey    aauth.SigningKey
		advance     time.Duration
		wantStatus  int
	}{
		{name: "wrong agent", claimsAgent: "aauth:other@ap.example", requestKey: otherAgentKey, tokenKey: otherAgentKey, wantStatus: http.StatusForbidden},
		{name: "wrong confirmation key", claimsAgent: "aauth:subscriber@ap.example", requestKey: otherAgentKey, tokenKey: agentKey, wantStatus: http.StatusUnauthorized},
		{name: "unconfigured body", claimsAgent: "aauth:subscriber@ap.example", requestKey: agentKey, tokenKey: agentKey, body: `{"event_types":["slot.available"]}`, wantStatus: http.StatusBadRequest},
		{name: "expired ticket", claimsAgent: "aauth:subscriber@ap.example", requestKey: agentKey, tokenKey: agentKey, advance: 2 * time.Minute, wantStatus: http.StatusNotFound},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			currentNow := now
			testClock := aauth.ClockFunc(func() time.Time { return currentNow })
			store := NewMemoryResourceEventStore()
			resource := newProtectedEventsTestResource(t, protectedEventsTestResourceInput{
				clock: testClock, resourceKey: resourceKey,
				resolver: aauth.StaticKeyResolver{"https://ap.example": {apKey.ID(): apKey.PublicJWK()}},
				store:    store, contracts: NewMemoryEventContractStore(testClock), document: document,
				operation: func(context.Context, aauth.AuthorizedRequest) (any, error) { return nil, nil },
			})
			rawTicket := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte(test.name), 32)[:32])
			ticket := protectedEventsTestTicket(rawTicket, now, document)
			if err := store.CreateTicket(context.Background(), ticket); err != nil {
				t.Fatal(err)
			}
			currentNow = now.Add(test.advance)
			compact := protectedEventsTestSubscribeTokenForAgent(t, apKey, test.tokenKey.PublicJWK(), currentNow, "event-"+strings.ReplaceAll(test.name, " ", "-"), test.claimsAgent)
			var body *strings.Reader
			if test.body != "" {
				body = strings.NewReader(test.body)
			} else {
				body = strings.NewReader("")
			}
			request := httptest.NewRequest(http.MethodPost, "https://resource.example/appointments/waitlist/"+rawTicket, body)
			if test.body == "" {
				request.Body = http.NoBody
				request.ContentLength = 0
			} else {
				request.Header.Set("Content-Type", "application/json")
			}
			if err := aauth.SignRequest(request, test.requestKey, compact, testClock); err != nil {
				t.Fatal(err)
			}
			response := httptest.NewRecorder()
			resource.Handler().ServeHTTP(response, request)
			if response.Code != test.wantStatus {
				t.Fatalf("status = %d, want %d: %s", response.Code, test.wantStatus, response.Body.Bytes())
			}
			if test.name != "expired ticket" {
				if _, err := store.LoadTicket(context.Background(), ticket.TicketDigest); err != nil {
					t.Fatalf("refusal consumed ticket: %v", err)
				}
			}
			if got := store.subscriptionCount(); got != 0 {
				t.Fatalf("refusal created %d subscriptions", got)
			}
		})
	}
}

func TestProtectedEventTicketConcurrentConsumptionHasOneWinner(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 8, 3, 9, 0, 0, 0, time.UTC)
	store := NewMemoryResourceEventStore()
	ticket := protectedEventsTestTicket("concurrent-ticket", now, protectedEventsTestDocument())
	if err := store.CreateTicket(ctx, ticket); err != nil {
		t.Fatal(err)
	}
	var wait sync.WaitGroup
	results := make(chan error, 2)
	for _, eventID := range []string{"event-one", "event-two"} {
		eventID := eventID
		wait.Add(1)
		go func() {
			defer wait.Done()
			_, err := store.ConsumeTicket(ctx, ProtectedEventTicketConsumption{
				TicketDigest: ticket.TicketDigest, Resource: ticket.Resource, APIssuer: "https://ap.example",
				EventID: eventID, Agent: ticket.Agent, RegisteredAt: now,
			})
			results <- err
		}()
	}
	wait.Wait()
	close(results)
	var successes int
	for err := range results {
		if err == nil {
			successes++
		} else if !errors.Is(err, ErrProtectedEventTicketNotFound) {
			t.Fatalf("concurrent consume error = %v", err)
		}
	}
	if successes != 1 || store.subscriptionCount() != 1 {
		t.Fatalf("concurrent successes/subscriptions = %d/%d, want 1/1", successes, store.subscriptionCount())
	}
}

type protectedEventsTestResourceInput struct {
	clock                 aauth.Clock
	resourceKey           aauth.SigningKey
	resolver              aauth.KeyResolver
	store                 ResourceEventStore
	contracts             EventContractStore
	document              []byte
	operation             func(context.Context, aauth.AuthorizedRequest) (any, error)
	registrationValidator func(context.Context, ProtectedEventRegistration) error
}

func newProtectedEventsTestResource(t *testing.T, input protectedEventsTestResourceInput) *Resource {
	t.Helper()
	resource, err := NewResource(ResourceConfig{
		Identifier: "https://resource.example", AccessServer: "https://as.example",
		SigningKey: input.resourceKey, KeyResolver: input.resolver, Clock: input.clock,
		NewID: func() string { return "unused" }, Scopes: []string{"events.read"}, Operation: input.operation,
		Events: &ResourceEventsConfig{
			PublicSubscriptionPath: "/events/subscriptions", Store: input.store,
			HTTPClient: &http.Client{}, ActiveUntil: func(context.Context, aauth.SubscribeTokenClaims) (time.Time, error) {
				return input.clock.Now().Add(time.Hour), nil
			},
			AsyncAPIPath: "/asyncapi.json", AsyncAPIDocument: input.document,
			ProtectedOperationID: "subscribeProtectedWaitlist", ProtectedMessageID: "slotAvailable",
			ContractStore: input.contracts, TicketLifetime: time.Minute,
			ProtectedRegistrationValidator: input.registrationValidator,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return resource
}

func protectedEventsTestAuthToken(t *testing.T, accessKey, agentKey aauth.SigningKey, now time.Time) string {
	t.Helper()
	compact, err := aauth.MintAuthToken(accessKey, aauth.AuthTokenClaims{
		Issuer: "https://as.example", DWK: aauth.AccessDiscoveryDocument,
		Audience: "https://resource.example", JTI: "auth-protected-events",
		Agent: "aauth:subscriber@ap.example", Confirmation: aauth.Confirmation{JWK: agentKey.PublicJWK()},
		IssuedAt: now.Unix(), ExpiresAt: now.Add(5 * time.Minute).Unix(),
		Subject: "pairwise-user", Scope: "events.read",
	})
	if err != nil {
		t.Fatal(err)
	}
	return compact
}

func protectedEventsTestSubscribeToken(t *testing.T, apKey, agentKey aauth.SigningKey, now time.Time, eventID string) string {
	t.Helper()
	return protectedEventsTestSubscribeTokenForAgent(t, apKey, agentKey.PublicJWK(), now, eventID, "aauth:subscriber@ap.example")
}

func protectedEventsTestSubscribeTokenForAgent(t *testing.T, apKey aauth.SigningKey, agentKey aauth.JWK, now time.Time, eventID, agent string) string {
	t.Helper()
	maxUses := 1
	compact, err := aauth.MintSubscribeToken(apKey, aauth.SubscribeTokenClaims{
		Issuer: "https://ap.example", DWK: aauth.AgentDiscoveryDocument, Subject: agent,
		Audience: "https://resource.example", Confirmation: aauth.Confirmation{JWK: agentKey},
		EventID: eventID, IssuedAt: now.Unix(), ExpiresAt: now.Add(time.Minute).Unix(), MaxUses: &maxUses,
	})
	if err != nil {
		t.Fatal(err)
	}
	return compact
}

func protectedEventsTestTicket(raw string, now time.Time, document []byte) ProtectedEventTicket {
	return ProtectedEventTicket{
		TicketDigest: protectedEventTicketDigest(raw), Resource: "https://resource.example",
		Agent: "aauth:subscriber@ap.example", AuthorizedMethod: http.MethodPost,
		AuthorizedPath: "/appointments/search", ResourceRevision: "appointment-state-17",
		ContractDigest: aauth.R3S256(document), OperationID: "subscribeProtectedWaitlist",
		MessageID: "slotAvailable", ExpiresAt: now.Add(time.Minute), ActiveUntil: now.Add(time.Hour),
	}
}

func protectedEventsTestDocument() []byte {
	return []byte(`{"asyncapi":"3.0.0","info":{"title":"Appointments Events","version":"1.0.0"},"channels":{"waitlistProtected":{"address":"/appointments/waitlist/{subscriptionTicket}","description":"Ticket URL from prior authenticated operation.","parameters":{"subscriptionTicket":{"description":"Single-use ticket."}},"messages":{"slotAvailable":{"$ref":"#/components/messages/SlotAvailable"}}}},"operations":{"subscribeProtectedWaitlist":{"action":"receive","channel":{"$ref":"#/channels/waitlistProtected"}}},"components":{"messages":{"SlotAvailable":{"contentType":"application/json","payload":{"type":"object","additionalProperties":false,"properties":{"event_type":{"type":"string","const":"slot.available"},"slot_time":{"type":"string","format":"date-time"}},"required":["event_type","slot_time"]}}},"securitySchemes":{"aauth_subscribe":{"type":"http","scheme":"aauth-subscribe"}}}}`)
}

func mustJSONMarshalProtectedTicket(t *testing.T, ticket ProtectedEventTicket) []byte {
	t.Helper()
	encoded, err := json.Marshal(ticket)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

type failingProtectedEventTicketStore struct {
	ResourceEventStore
	ProtectedEventTicketStore
	createErr error
}

func (store *failingProtectedEventTicketStore) CreateTicket(context.Context, ProtectedEventTicket) error {
	return store.createErr
}

func (store *MemoryResourceEventStore) ticketCount() int {
	store.mu.Lock()
	defer store.mu.Unlock()
	return len(store.tickets)
}

func (store *MemoryResourceEventStore) subscriptionCount() int {
	store.mu.Lock()
	defer store.mu.Unlock()
	return len(store.subscriptions)
}
