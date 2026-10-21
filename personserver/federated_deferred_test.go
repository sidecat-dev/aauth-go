package personserver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/budgets"
	"gitlab.com/sidecat-dev/aauth-go/diagnostics"
	"gitlab.com/sidecat-dev/aauth-go/r3"
	"gitlab.com/sidecat-dev/aauth-go/r3/vocab/mcp"
)

// Protocol 28e8258, Error Response Format and Token Endpoint Error Codes:
// a local unsupported composition is not an unreachable or invalid AS result.
func TestDeferredCompositionRefusalHasLocalReason(t *testing.T) {
	for _, configured := range []bool{false, true} {
		t.Run(map[bool]string{false: "not configured", true: "mission"}[configured], func(t *testing.T) {
			now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
			f := newMissionFederationFixture(t, missionFederationTimes{now: now, resourceExpiresAt: now.Add(time.Minute), missionExpiresAt: now.Add(5 * time.Minute), authExpiresAt: now.Add(time.Minute)})
			if configured {
				f.server.federatedDeferred = &FederatedDeferredConfig{}
			}
			f.server.httpClient = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: 402, Header: http.Header{"Location": {"https://access.example/pending/test"}, "Www-Authenticate": {`Payment secret="private-invoice"`}}, Body: io.NopCloser(strings.NewReader("private-invoice")), Request: r}, nil
			})}
			body := testTokenRequestBody(t, f.resourceToken, f.presentedToken)
			request := httptest.NewRequest("POST", f.protocol.personServerID+"/token", bytes.NewReader(body))
			request.Header.Set("Content-Type", "application/json")
			if err := signPersonServerTestRequest(request, f.protocol.agentKey, f.protocol.agentToken, f.protocol.clock); err != nil {
				t.Fatal(err)
			}
			var observed diagnostics.Problem
			recorder := httptest.NewRecorder()
			diagnostics.Handler(f.server.Handler(), func(_ context.Context, p diagnostics.Problem) { observed = p }).ServeHTTP(recorder, request)
			problem, err := aauth.DecodeProblemResponse(recorder.Result())
			if err != nil {
				t.Fatal(err)
			}
			if problem.Status != 500 || problem.Code != "server_error" {
				t.Fatalf("local refusal = %v", problem)
			}
			var reason *DeferredCompositionError
			if !errors.As(observed.Cause, &reason) {
				t.Fatalf("untyped composition cause: %T %v", observed.Cause, observed.Cause)
			}
			want := "not_configured"
			if configured {
				want = "mission"
			}
			if reason.Reason() != want || !strings.Contains(problem.Detail, "deferred") || strings.Contains(problem.Detail, "private-invoice") {
				t.Fatalf("reason=%q detail=%q", reason.Reason(), problem.Detail)
			}
			if attempts, _, _ := f.store.observation(); attempts != 0 {
				t.Fatal("unsupported continuation retained a token")
			}
		})
	}
}

func TestPendingFederatedReferencesValidateStoreResults(t *testing.T) {
	now := time.Unix(100, 0)
	valid := FederatedAuthorizationRecord{ID: "request", PersonServer: "https://ps.example", ExpiresAt: now.Add(time.Minute)}
	for _, tc := range []struct {
		name  string
		alter func(*FederatedAuthorizationRecord)
	}{
		{"valid", nil},
		{"foreign", func(r *FederatedAuthorizationRecord) { r.PersonServer = "https://other.example" }},
		{"expired", func(r *FederatedAuthorizationRecord) { r.ExpiresAt = now }},
		{"terminal", func(r *FederatedAuthorizationRecord) { r.Terminal = true }},
		{"gone", func(r *FederatedAuthorizationRecord) { r.Gone = true }},
		{"missing id", func(r *FederatedAuthorizationRecord) { r.ID = "" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := valid
			if tc.alter != nil {
				tc.alter(&r)
			}
			store := &federatedQueueProbe{records: []FederatedAuthorizationRecord{r}}
			server := &Server{issuer: valid.PersonServer, clock: aauth.ClockFunc(func() time.Time { return now }), federatedDeferred: &FederatedDeferredConfig{Store: store}}
			queue := server
			refs, err := queue.PendingFederatedAuthorizationReferences(context.Background(), 1)
			if tc.alter != nil {
				if !errors.Is(err, ErrFederatedAuthorizationConflict) || len(refs) != 0 {
					t.Fatalf("corrupt queue = %v %v", refs, err)
				}
				return
			}
			if err != nil || len(refs) != 1 || refs[0] != valid.ID || store.issuer != valid.PersonServer || !store.now.Equal(now) || store.limit != 1 {
				t.Fatalf("queue = %v %v", refs, err)
			}
			store.records = append(store.records, r)
			for _, limit := range []int{1, 2} {
				if refs, err := queue.PendingFederatedAuthorizationReferences(context.Background(), limit); !errors.Is(err, ErrFederatedAuthorizationConflict) || len(refs) != 0 {
					t.Fatalf("excess or duplicate records = %v %v", refs, err)
				}
			}
		})
	}
}

type federatedQueueProbe struct {
	FederatedAuthorizationStore
	records []FederatedAuthorizationRecord
	issuer  string
	now     time.Time
	limit   int
	err     error
	calls   int
}

func (s *federatedQueueProbe) ListPendingFederatedAuthorizations(_ context.Context, issuer string, now time.Time, limit int) ([]FederatedAuthorizationRecord, error) {
	s.issuer, s.now, s.limit = issuer, now, limit
	s.calls++
	return s.records, s.err
}

// Agent polls never advance the AS exchange, so a poll that is already due
// waits on the host: answering Retry-After: 0 would invite a busy loop.
func TestFederatedWaitingRoundsUpRemainingRetryAfter(t *testing.T) {
	now := time.Unix(100, 0)
	server := &Server{issuer: "https://ps.example", clock: aauth.ClockFunc(func() time.Time { return now })}
	for _, tc := range []struct {
		remaining time.Duration
		want      string
	}{{time.Millisecond, "1"}, {time.Second, "1"}, {time.Second + time.Nanosecond, "2"}, {0, "1"}, {-time.Second, "1"}} {
		w := httptest.NewRecorder()
		server.writeFederatedWaiting(w, FederatedAuthorizationRecord{ID: "request", NextPollAt: now.Add(tc.remaining)})
		if got := w.Header().Get("Retry-After"); got != tc.want {
			t.Fatalf("remaining %v: Retry-After=%q, want %q", tc.remaining, got, tc.want)
		}
	}
}

func TestFederatedWaitingExposesOnlySafeHint(t *testing.T) {
	now := time.Unix(100, 0)
	server := &Server{issuer: "https://ps.example", clock: aauth.ClockFunc(func() time.Time { return now })}
	for _, tc := range []struct {
		status int
		reason string
	}{{402, "awaiting_payment"}, {202, "awaiting_approval"}, {503, ""}} {
		w := httptest.NewRecorder()
		server.writeFederatedWaiting(w, FederatedAuthorizationRecord{ID: "request", NextPollAt: now, Response: FederatedResponse{Status: tc.status, Body: []byte("private-invoice"), Header: http.Header{"Www-Authenticate": {"private-payment"}}}})
		var body map[string]string
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		if body["status"] != "pending" || body["pending_reason"] != tc.reason {
			t.Fatalf("pending response = %v", body)
		}
		if strings.Contains(w.Body.String(), "private-") || w.Header().Get("WWW-Authenticate") != "" {
			t.Fatal("payment details exposed to Agent")
		}
	}
}

// Deferred federation supports missionless Core requests, top-level or
// parent-mediated. Each companion request reaches consent and the AS before a
// local typed refusal; it must neither issue a token nor retain an unsupported
// continuation. integration/subagent_federated_deferred_test.go covers the
// parent-mediated continuation that is now retained.
func TestDeferredCompositionRefusesR3AndBudget(t *testing.T) {
	for _, reason := range []string{"r3", "budget"} {
		for _, status := range []int{202, 402} {
			t.Run(reason+"/"+http.StatusText(status), func(t *testing.T) {
				p := newSubagentPersonServerProtocol(t)
				key, agent, parent := p.parentKey.PublicJWK(), "aauth:planner@ap.example", ""
				if err := p.store.Commit(context.Background(), PersonTokenRecord{
					JTI: "person-token", PersonServer: "https://ps.example", Resource: "https://resource.example",
					Subject: "person-123", Tenant: "tenant-1", ExpiresAt: p.now.Add(10 * time.Minute),
					RetainUntil: p.now.Add(15 * time.Minute), AgentProvider: "https://ap.example",
					Agent: agent, ParentAgent: parent, Confirmation: key,
				}); err != nil {
					t.Fatal(err)
				}
				resourceToken := p.resourceToken(t, "https://as.example", "person-token", key)
				claims, err := aauth.VerifyResourceToken(context.Background(), resourceToken, p.resolver, p.clock)
				if err != nil {
					t.Fatal(err)
				}
				var document []byte
				consents, asCalls := 0, 0
				continuations := &refusedFederationStore{}
				config := FederatedAuthorizationConfig{
					Issuer: "https://ps.example", SigningKey: p.personKey, KeyResolver: p.resolver,
					Clock: p.clock, NewID: func() string { return "unused" }, Tokens: p.store,
					AccessServerEndpoint: func(context.Context, string) (string, error) { return "https://as.example/token", nil },
					BindPerson:           p.policyPerson,
					Consent:              func(context.Context, AuthorizationRequest) error { consents++; return nil },
					Deferred:             &FederatedDeferredConfig{Store: continuations, Lifetime: time.Minute},
				}
				config.HTTPClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
					if req.URL.String() == "https://resource.example/r3/document" {
						return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(bytes.NewReader(document)), Request: req}, nil
					}
					if req.URL.String() != "https://as.example/token" || req.Method != http.MethodPost {
						t.Fatal("unexpected AS request")
					}
					asCalls++
					return &http.Response{StatusCode: status, Header: http.Header{
						"Location": {"https://as.example/pending/test"}, "Www-Authenticate": {`Payment id="private-invoice"`},
						"Cache-Control": {"no-store"}, "Content-Type": {"application/json"},
					}, Body: io.NopCloser(strings.NewReader(`{"status":"pending"}`)), Request: req}, nil
				})}
				switch reason {
				case "r3":
					registry := newPersonServerR3Registry(t)
					op, err := mcp.NewOperation("records.read")
					if err != nil {
						t.Fatal(err)
					}
					operations, err := mcp.NewOperationSet(op)
					if err != nil {
						t.Fatal(err)
					}
					doc, err := r3.NewDocument(operations, r3.DocumentOptions{})
					if err != nil {
						t.Fatal(err)
					}
					document, err = json.Marshal(doc)
					if err != nil {
						t.Fatal(err)
					}
					resourceToken, _, err = r3.MintResourceToken(registry, p.resourceKey, claims, "https://resource.example/r3/document", document)
					if err != nil {
						t.Fatal(err)
					}
					config.R3 = &R3Config{Registry: registry, Admit: func(context.Context, string) error { return nil },
						ConsentDocument: func(context.Context, AuthorizationRequest, r3.Reference, r3.Document) error { consents++; return nil },
					}
				case "budget":
					unit, err := budgets.NewUnit("credits", 0)
					if err != nil {
						t.Fatal(err)
					}
					offer, err := budgets.NewValue(100, unit)
					if err != nil {
						t.Fatal(err)
					}
					declaration, err := budgets.NewUnitDeclaration(unit, "Service credits")
					if err != nil {
						t.Fatal(err)
					}
					resourceToken, err = budgets.MintResourceToken(p.resourceKey, claims, offer, nil)
					if err != nil {
						t.Fatal(err)
					}
					config.Budget = &FederatedBudgetConfig{
						ResolveResourceUnits: func(context.Context, string) ([]budgets.UnitDeclaration, error) {
							return []budgets.UnitDeclaration{declaration}, nil
						},
						Ceiling: func(context.Context, AuthorizationRequest) (*budgets.Value, error) { return nil, nil },
					}
				}
				server, err := NewFederatedAuthorization(config)
				if err != nil {
					t.Fatal(err)
				}
				input := map[string]string{"resource_token": resourceToken, "presented_token": p.presentedToken(t, resourceToken)}
				body, err := json.Marshal(input)
				if err != nil {
					t.Fatal(err)
				}
				request := httptest.NewRequest(http.MethodPost, "https://ps.example/token", bytes.NewReader(body))
				request.Header.Set("Content-Type", "application/json")
				if err := signPersonServerTestRequest(request, p.parentKey, p.parentToken, p.clock); err != nil {
					t.Fatal(err)
				}
				var observed diagnostics.Problem
				response := httptest.NewRecorder()
				diagnostics.Handler(server.Handler(), func(_ context.Context, problem diagnostics.Problem) { observed = problem }).ServeHTTP(response, request)
				problem, err := aauth.DecodeProblemResponse(response.Result())
				if err != nil {
					t.Fatal(err)
				}
				var refusal *DeferredCompositionError
				if problem.Status != 500 || problem.Code != "server_error" || !errors.As(observed.Cause, &refusal) || refusal.Reason() != reason {
					t.Fatalf("refusal = %v, cause=%T %v", problem, observed.Cause, observed.Cause)
				}
				if consents != 1 || asCalls != 1 || continuations.creates != 0 {
					t.Fatalf("consent=%d AS=%d continuation writes=%d", consents, asCalls, continuations.creates)
				}
				if strings.Contains(response.Body.String(), "private-invoice") || strings.Contains(response.Body.String(), "auth_token") {
					t.Fatal("refusal exposed AS data or authorization")
				}
			})
		}
	}
}

type refusedFederationStore struct {
	FederatedAuthorizationStore
	creates int
}

func (s *refusedFederationStore) CreateFederatedAuthorization(context.Context, FederatedAuthorizationRecord) error {
	s.creates++
	return errors.New("unsupported request reached continuation store")
}
