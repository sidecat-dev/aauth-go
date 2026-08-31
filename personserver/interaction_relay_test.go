package personserver

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

func TestInteractionRelayRetainsBeforeDeferredResponseInBothPersonServerModes(t *testing.T) {
	for _, mode := range []string{"direct", "federated"} {
		t.Run(mode, func(t *testing.T) {
			protocol := newInteractionQuestionProtocol(t)
			store := newRelayTestStore()
			var policyRequest InteractionRelayPolicyRequest
			server := newInteractionRelayServer(t, protocol, mode, &InteractionRelayConfig{
				Policy: func(_ context.Context, request InteractionRelayPolicyRequest) (InteractionRelayPendingPolicy, error) {
					policyRequest = request
					return InteractionRelayPendingPolicy{Lifetime: time.Minute, RetryAfter: 2 * time.Second}, nil
				},
				Store: store,
			})
			if metadata := interactionQuestionMetadata(t, server); metadata["interaction_endpoint"] != protocol.personServerID+"/interaction" {
				t.Fatalf("interaction endpoint = %q", metadata["interaction_endpoint"])
			}
			body := []byte("{\n" +
				`  "type":"payment",` + "\n" +
				`  "description":"Approve the **payment**.",` + "\n" +
				`  "url":"https://merchant.example/pay",` + "\n" +
				`  "code":"X7K2-M9P4",` + "\n" +
				`  "max_wait":10,` + "\n" +
				`  "extension":true` + "\n" +
				"}")
			response := interactionQuestionRequest(t, protocol, server, protocol.agentKey, protocol.agentToken, string(body))
			if response.Code != http.StatusAccepted || response.Header().Get("Location") == "" ||
				response.Header().Get("Retry-After") != "2" || response.Body.String() != "{\"status\":\"pending\"}\n" {
				t.Fatalf("relay response = %d headers=%#v body=%q", response.Code, response.Header(), response.Body.String())
			}
			if policyRequest.Agent != protocol.agentID || policyRequest.Document.Relay.Type != aauth.InteractionRelayPayment ||
				!reflect.DeepEqual(policyRequest.Document.ExactJSON, body) || !policyRequest.ReceivedAt.Equal(protocol.now) {
				t.Fatalf("policy request = %#v", policyRequest)
			}
			if store.createCalls != 1 || len(store.records) != 1 {
				t.Fatalf("retained records = %d create calls=%d", len(store.records), store.createCalls)
			}
		})
	}
}

func TestInteractionRelayHostEngagementResolvesOnce(t *testing.T) {
	protocol := newInteractionQuestionProtocol(t)
	store := newRelayTestStore()
	server := newInteractionRelayServer(t, protocol, "direct", relayTestConfig(store, time.Minute))
	response := interactionQuestionRequest(t, protocol, server, protocol.agentKey, protocol.agentToken,
		`{"type":"interaction","url":"https://resource.example/confirm","code":"ABCD-EFGH"}`)
	location := response.Header().Get("Location")
	if response.Code != http.StatusAccepted || location == "" {
		t.Fatalf("relay response = %d headers=%#v body=%q", response.Code, response.Header(), response.Body.String())
	}
	reference := strings.TrimPrefix(location, "/interaction/relay/")
	handle, err := server.ResumeInteractionRelay(context.Background(), reference)
	if err != nil {
		t.Fatal(err)
	}
	if handle.Agent() != protocol.agentID || handle.Reference() != reference ||
		handle.Relay().Relay.URL != "https://resource.example/confirm" {
		t.Fatalf("handle = %#v", handle)
	}
	if err := server.MarkInteractionRelayEngaged(context.Background(), handle); err != nil {
		t.Fatal(err)
	}
	poll := pollInteractionRelay(t, protocol, server, location)
	if poll.Code != http.StatusOK || poll.Body.String() != `{"status":"interacting"}` {
		t.Fatalf("terminal poll = %d %q", poll.Code, poll.Body.String())
	}
	again := pollInteractionRelay(t, protocol, server, location)
	assertAuditProblem(t, again, http.StatusGone, "invalid_code", "", "")
	if err := server.MarkInteractionRelayEngaged(context.Background(), handle); !errors.Is(err, ErrInteractionRelayGone) {
		t.Fatalf("second resolution = %v", err)
	}
}

func TestInteractionRelayMaxWaitAndNoProgressResolvePending(t *testing.T) {
	for _, test := range []struct {
		name    string
		resolve func(*testing.T, *Server, InteractionRelayHandle)
	}{
		{
			name:    "max wait",
			resolve: func(_ *testing.T, _ *Server, _ InteractionRelayHandle) {},
		},
		{
			name: "no progress",
			resolve: func(t *testing.T, server *Server, handle InteractionRelayHandle) {
				t.Helper()
				if err := server.FinishInteractionRelayNoProgress(context.Background(), handle); err != nil {
					t.Fatal(err)
				}
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			protocol := newInteractionQuestionProtocol(t)
			store := newRelayTestStore()
			server := newInteractionRelayServer(t, protocol, "direct", relayTestConfig(store, time.Minute))
			body := `{"type":"payment","url":"https://merchant.example/pay","code":"X7K2-M9P4","max_wait":2}`
			response := interactionQuestionRequest(t, protocol, server, protocol.agentKey, protocol.agentToken, body)
			location := response.Header().Get("Location")
			if response.Code != http.StatusAccepted || location == "" {
				t.Fatalf("relay response = %d headers=%#v body=%q", response.Code, response.Header(), response.Body.String())
			}
			reference := strings.TrimPrefix(location, "/interaction/relay/")
			handle, err := server.ResumeInteractionRelay(context.Background(), reference)
			if err != nil {
				t.Fatal(err)
			}
			if test.name == "max wait" && !handle.ExpiresAt().Equal(protocol.now.Add(2*time.Second)) {
				t.Fatalf("max_wait deadline = %s", handle.ExpiresAt())
			}
			test.resolve(t, server, handle)
			if test.name == "max wait" {
				protocol.now = protocol.now.Add(2 * time.Second)
			}
			poll := pollInteractionRelay(t, protocol, server, location)
			if poll.Code != http.StatusOK || poll.Body.String() != `{"status":"pending"}` {
				t.Fatalf("terminal poll = %d %q", poll.Code, poll.Body.String())
			}
		})
	}
}

func TestInteractionRelayUnavailableIsTypedAndNotRetained(t *testing.T) {
	protocol := newInteractionQuestionProtocol(t)
	store := newRelayTestStore()
	server := newInteractionRelayServer(t, protocol, "federated", &InteractionRelayConfig{
		Policy: func(context.Context, InteractionRelayPolicyRequest) (InteractionRelayPendingPolicy, error) {
			return InteractionRelayPendingPolicy{}, ErrInteractionRelayUnavailable
		},
		Store: store,
	})
	response := interactionQuestionRequest(t, protocol, server, protocol.agentKey, protocol.agentToken,
		`{"type":"interaction","url":"https://resource.example/confirm","code":"ABCD-EFGH"}`)
	assertAuditProblem(t, response, http.StatusFailedDependency, "interaction_unavailable", "", "")
	if store.createCalls != 0 {
		t.Fatalf("unavailable relay was retained %d times", store.createCalls)
	}
}

func relayTestConfig(store InteractionRelayStore, lifetime time.Duration) *InteractionRelayConfig {
	return &InteractionRelayConfig{
		Policy: func(context.Context, InteractionRelayPolicyRequest) (InteractionRelayPendingPolicy, error) {
			return InteractionRelayPendingPolicy{Lifetime: lifetime, RetryAfter: time.Second}, nil
		},
		Store: store,
	}
}

func newInteractionRelayServer(t *testing.T, protocol *interactionQuestionProtocol, mode string, relays *InteractionRelayConfig) *Server {
	t.Helper()
	if mode == "federated" {
		server, err := NewFederatedAuthorization(FederatedAuthorizationConfig{
			Issuer: protocol.personServerID, SigningKey: protocol.personKey, KeyResolver: protocol.resolver,
			Clock: protocol.clock, NewID: func() string { return "relay-1" }, Tokens: protocol.tokens,
			HTTPClient: &http.Client{}, AccessServerEndpoint: func(context.Context, string) (string, error) {
				return "https://access.example/token", nil
			},
			BindPerson: func(context.Context, PersonTokenRequest) (Person, error) {
				return Person{Subject: "person", Lifetime: time.Minute}, nil
			},
			Consent: func(context.Context, AuthorizationRequest) error { return nil }, InteractionRelay: relays,
		})
		if err != nil {
			t.Fatal(err)
		}
		return server
	}
	server, err := NewPSAuthorization(PSAuthorizationConfig{
		Issuer: protocol.personServerID, SigningKey: protocol.personKey, KeyResolver: protocol.resolver,
		Clock: protocol.clock, NewID: func() string { return "relay-1" }, Tokens: protocol.tokens,
		BindPerson: func(context.Context, PersonTokenRequest) (Person, error) {
			return Person{Subject: "person", Lifetime: time.Minute}, nil
		},
		Authorize: func(context.Context, AuthorizationRequest) (AuthorizationDecision, error) {
			return AuthorizationDecision{Scopes: []string{"read"}, Lifetime: time.Minute}, nil
		},
		InteractionRelay: relays,
	})
	if err != nil {
		t.Fatal(err)
	}
	return server
}

func pollInteractionRelay(t *testing.T, protocol *interactionQuestionProtocol, server *Server, location string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodGet, protocol.personServerID+location, nil)
	if err := signaturekey.SignJWTRequest(request, protocol.agentKey, protocol.agentToken, protocol.clock); err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	return response
}

type relayTestStore struct {
	mu          sync.Mutex
	records     map[string]InteractionRelayRecord
	createCalls int
}

func newRelayTestStore() *relayTestStore {
	return &relayTestStore{records: make(map[string]InteractionRelayRecord)}
}

func (store *relayTestStore) CreateInteractionRelay(_ context.Context, record InteractionRelayRecord) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.createCalls++
	if _, exists := store.records[record.ID]; exists {
		return ErrInteractionRelayConflict
	}
	store.records[record.ID] = cloneRelayTestRecord(record)
	return nil
}

func (store *relayTestStore) LoadInteractionRelay(_ context.Context, id string, at time.Time) (InteractionRelayRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.load(id, at)
}

func (store *relayTestStore) ResolveInteractionRelay(_ context.Context, id string, status aauth.InteractionRelayStatus, at time.Time) (InteractionRelayRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	record, err := store.load(id, at)
	if err != nil {
		return InteractionRelayRecord{}, err
	}
	if record.State == InteractionRelayResolved {
		if record.Completion.Status == status {
			return cloneRelayTestRecord(record), nil
		}
		return InteractionRelayRecord{}, ErrInteractionRelayConflict
	}
	if record.State != InteractionRelayPending {
		return InteractionRelayRecord{}, ErrInteractionRelayConflict
	}
	record.State = InteractionRelayResolved
	record.Completion = aauth.InteractionRelayCompletion{Status: status}
	record.ResolvedAt = at
	store.records[id] = cloneRelayTestRecord(record)
	return cloneRelayTestRecord(record), nil
}

func (store *relayTestStore) PollInteractionRelay(_ context.Context, id string, identity InteractionRelayPollIdentity, at time.Time) (InteractionRelayRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	record, err := store.load(id, at)
	if err != nil {
		return InteractionRelayRecord{}, err
	}
	if record.PersonServer != identity.PersonServer || record.AgentProvider != identity.AgentProvider ||
		record.Agent != identity.Agent || record.ConfirmationThumbprint != identity.ConfirmationThumbprint {
		return InteractionRelayRecord{}, ErrInteractionRelayNotFound
	}
	return cloneRelayTestRecord(record), nil
}

func (store *relayTestStore) ConsumeInteractionRelay(_ context.Context, id string, expected InteractionRelayRecord) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	record, exists := store.records[id]
	if !exists {
		return ErrInteractionRelayNotFound
	}
	if record.State == InteractionRelayGone {
		return ErrInteractionRelayGone
	}
	if !reflect.DeepEqual(record, expected) || record.State != InteractionRelayResolved {
		return ErrInteractionRelayConflict
	}
	record.State = InteractionRelayGone
	store.records[id] = cloneRelayTestRecord(record)
	return nil
}

func (store *relayTestStore) load(id string, at time.Time) (InteractionRelayRecord, error) {
	record, exists := store.records[id]
	if !exists {
		return InteractionRelayRecord{}, ErrInteractionRelayNotFound
	}
	if record.State == InteractionRelayGone {
		return InteractionRelayRecord{}, ErrInteractionRelayGone
	}
	if record.State == InteractionRelayPending && !at.Before(record.ExpiresAt) {
		record.State = InteractionRelayResolved
		record.Completion = aauth.InteractionRelayCompletion{Status: aauth.InteractionRelayPending}
		record.ResolvedAt = record.ExpiresAt
		store.records[id] = cloneRelayTestRecord(record)
	}
	return cloneRelayTestRecord(record), nil
}

func cloneRelayTestRecord(record InteractionRelayRecord) InteractionRelayRecord {
	record.Document.ExactJSON = append([]byte(nil), record.Document.ExactJSON...)
	return record
}

var _ InteractionRelayStore = (*relayTestStore)(nil)
