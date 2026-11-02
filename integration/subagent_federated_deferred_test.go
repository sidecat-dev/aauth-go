package integration_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/accessserver"
	"gitlab.com/sidecat-dev/aauth-go/agent"
	"gitlab.com/sidecat-dev/aauth-go/agentprovider"
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/personserver"
	"gitlab.com/sidecat-dev/aauth-go/resource"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
	"gitlab.com/sidecat-dev/aauth-go/testutil"
)

// Protocol 28e8258, Sub-Agents (Parent-Mediated Authorization), AS Response,
// Auth Token Delivery, Deferred Responses and Pending URL Security; Bootstrap
// 28e8258, Sub-Agent Tokens. The parent owns consent, the binding and every
// PS poll; the PS owns AS polls; the child holds the credentials.
type subagentFederation struct {
	now                        atomic.Int64
	clock                      aauth.Clock
	network                    *logicalTransport
	ap                         *agentprovider.Server
	parentKey, childKey, psKey jose.SigningKey
	parentToken, childToken    string
	childExpiresAt             time.Time
	psStore                    personserver.FederatedAuthorizationQueueStore
	asStore                    accessserver.DeferredAuthorizationStore
	bindings                   personserver.AgentBindingRevocationStore
	revocations                resource.AgentTokenRevocationStore
	ps                         *personserver.Server
	parent, child              *agent.Client
	stage                      atomic.Int32
	asPolls, asCancels         atomic.Int32
	protected                  atomic.Int32
	mu                         sync.Mutex
	asPolicy                   []string
	recompose                  func(*testing.T)
	// afterAS, when set, runs once after the AS answers a token request.
	afterAS atomic.Pointer[func()]
}

const (
	subagentParentID = "aauth:planner@ap.example"
	subagentChildID  = "aauth:planner+search@ap.example"
)

func newSubagentFederation(t *testing.T, childLifetime time.Duration) *subagentFederation {
	t.Helper()
	f := &subagentFederation{}
	f.now.Store(1792512000)
	f.clock = aauth.ClockFunc(func() time.Time { return time.Unix(f.now.Load(), 0).UTC() })
	f.network = newLogicalTransport()
	httpClient := &http.Client{Transport: f.network}
	apKey, asKey, resourceKey := newSigningKey(t, "ap"), newSigningKey(t, "as"), newSigningKey(t, "resource")
	f.parentKey, f.childKey, f.psKey = newSigningKey(t, "parent"), newSigningKey(t, "child"), newSigningKey(t, "ps")
	resolver, err := signaturekey.NewHTTPKeyResolver(signaturekey.HTTPKeyResolverConfig{
		Client: httpClient, TransportEnforcesEgress: true, Clock: f.clock, Admit: func(context.Context, string) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	var ids atomic.Int64
	newID := func() string { return fmt.Sprintf("subagent-%d", ids.Add(1)) }
	ap, err := agentprovider.New(agentprovider.Config{Issuer: "https://ap.example", SigningKey: apKey, Clock: f.clock, NewID: newID})
	if err != nil {
		t.Fatal(err)
	}
	f.ap = ap
	f.network.Handle("https://ap.example", ap.Handler())
	f.parentToken, err = ap.Issue(t.Context(), aauth.AgentTokenRequest{
		Agent: subagentParentID, PersonServer: "https://ps.example", PublicKey: f.parentKey.PublicJWK(), Lifetime: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	f.childToken, err = ap.IssueSubagent(context.Background(), f.parentToken, agentprovider.SubagentTokenRequest{
		Discriminator: "search", PublicKey: f.childKey.PublicJWK(), Lifetime: childLifetime,
	})
	if err != nil {
		t.Fatal(err)
	}
	f.childExpiresAt = f.clock.Now().Add(childLifetime)
	f.asStore = testutil.NewAccessAuthorizationStore()
	f.psStore = testutil.NewFederatedAuthorizationStore()
	f.bindings = testutil.NewAgentBindingRevocationStore()
	f.revocations = testutil.NewAgentTokenRevocationStore()
	personTokens := newMemoryPersonTokenStore()
	f.recompose = func(t *testing.T) {
		t.Helper()
		as, err := accessserver.New(accessserver.Config{
			Issuer: "https://as.example", SigningKey: asKey, KeyResolver: resolver, Clock: f.clock, NewID: newID,
			TrustPersonServer: func(context.Context, string) error { return nil },
			Deferred:          &accessserver.DeferredConfig{Store: f.asStore, Lifetime: time.Minute},
			Authorize: func(_ context.Context, r accessserver.AuthorizationRequest) (accessserver.Decision, error) {
				child := ""
				if r.Subagent != nil {
					child = r.Subagent.Identifier
				}
				f.mu.Lock()
				f.asPolicy = append(f.asPolicy, r.Agent.Identifier+"|"+child)
				f.mu.Unlock()
				switch f.stage.Load() {
				case -1:
					return accessserver.Decision{}, accessserver.ErrAccessDenied
				case 0:
					return accessserver.Decision{Pending: &accessserver.PendingDecision{Payment: &accessserver.PaymentChallenge{Authenticate: `Payment id="bill-1", method="example"`}}}, nil
				case 1:
					return accessserver.Decision{Pending: &accessserver.PendingDecision{}}, nil
				default:
					return accessserver.Decision{Scopes: r.Scopes, Lifetime: time.Minute}, nil
				}
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		f.network.Handle("https://as.example", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasPrefix(r.URL.Path, "/token/pending/") {
				switch r.Method {
				case http.MethodGet:
					f.asPolls.Add(1)
				case http.MethodDelete:
					f.asCancels.Add(1)
				}
			}
			as.Handler().ServeHTTP(w, r)
			if r.URL.Path == "/token" {
				if hook := f.afterAS.Swap(nil); hook != nil {
					(*hook)()
				}
			}
		}))
		f.ps, err = personserver.NewFederatedAuthorization(personserver.FederatedAuthorizationConfig{
			Issuer: "https://ps.example", SigningKey: f.psKey, KeyResolver: resolver, Clock: f.clock, NewID: newID,
			HTTPClient: httpClient, Tokens: personTokens,
			AccessServerEndpoint: func(context.Context, string) (string, error) { return "https://as.example/token", nil },
			BindPerson: func(_ context.Context, r personserver.PersonTokenRequest) (personserver.Person, error) {
				if r.Agent != subagentParentID || r.Subagent != subagentChildID {
					return personserver.Person{}, errors.New("unexpected parent-mediated person request")
				}
				return personserver.Person{Subject: "reader", Lifetime: 5 * time.Minute}, nil
			},
			Consent: func(_ context.Context, r personserver.AuthorizationRequest) error {
				if r.Agent != subagentParentID || r.Subagent != subagentChildID {
					return errors.New("unexpected parent-mediated consent request")
				}
				return nil
			},
			Deferred:                &personserver.FederatedDeferredConfig{Store: f.psStore, Lifetime: time.Minute},
			AgentBindingRevocations: f.bindings,
			AgentTokenRevocations:   f.revocations,
		})
		if err != nil {
			t.Fatal(err)
		}
		f.network.Handle("https://ps.example", f.ps.Handler())
	}
	f.recompose(t)
	protected, err := resource.NewFederatedAuthorization(resource.FederatedAuthorizationConfig{
		Issuer: "https://resource.example", AccessServer: "https://as.example", SigningKey: resourceKey,
		KeyResolver: resolver, Clock: f.clock, NewID: newID,
		ScopeDescriptions: map[string]string{"records.read": "Read records"},
		RequiredScopes:    func(*http.Request) []string { return []string{"records.read"} },
		ResolvePerson:     func(context.Context, resource.PersonIdentity, resource.PersonContext) error { return nil },
		Protected: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			principal, ok := resource.AuthPrincipalFromContext(r.Context())
			if !ok || !principal.Confirmation.Equal(f.childKey.PublicJWK()) {
				http.Error(w, "credential is not child-bound", http.StatusInternalServerError)
				return
			}
			f.protected.Add(1)
			w.WriteHeader(http.StatusOK)
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	f.network.Handle("https://resource.example", protected.Handler())
	f.parent, err = agent.New(context.Background(), agent.Config{
		Identifier: subagentParentID, AgentToken: f.parentToken, SigningKey: f.parentKey,
		KeyResolver: resolver, Clock: f.clock, HTTPClient: httpClient,
	})
	if err != nil {
		t.Fatal(err)
	}
	f.child, err = agent.New(context.Background(), agent.Config{
		Identifier: subagentChildID, AgentToken: f.childToken, SigningKey: f.childKey,
		KeyResolver: resolver, Clock: f.clock, HTTPClient: httpClient,
	})
	if err != nil {
		t.Fatal(err)
	}
	return f
}

// begin obtains the child's Person token through the parent, lets the child
// receive the Resource's challenge, and has the parent start the exchange.
func (f *subagentFederation) begin(t *testing.T) agent.PendingExchange {
	t.Helper()
	return f.beginWith(t, f.childToken)
}

// beginWith presents exchangeChild, a current token for the same child, in
// the parent's exchange.
func (f *subagentFederation) beginWith(t *testing.T, exchangeChild string) agent.PendingExchange {
	t.Helper()
	ctx := context.Background()
	person, err := f.parent.PersonToken(ctx, agent.PersonTokenRequest{
		PersonServer: "https://ps.example", Resource: "https://resource.example", SubagentToken: f.childToken,
	})
	if err != nil {
		t.Fatal(err)
	}
	personToken, ok := person.Token()
	if !ok {
		t.Fatal("missing child Person token")
	}
	request, _ := http.NewRequest(http.MethodGet, "https://resource.example/records", nil)
	call, err := f.child.Begin(ctx, agent.InitialCall{Request: request, PersonToken: personToken})
	if err != nil {
		t.Fatal(err)
	}
	required, ok := call.AuthorizationRequired()
	if !ok {
		t.Fatal("missing child-bound Resource token")
	}
	exchange, err := f.parent.BeginExchange(ctx, agent.ExchangeRequest{
		PersonServer: "https://ps.example", ResourceToken: required.ResourceToken,
		PresentedToken: personToken, SubagentToken: exchangeChild,
	})
	if err != nil {
		t.Fatal(err)
	}
	pending, ok := exchange.Pending()
	if !ok {
		t.Fatal("missing parent-owned pending exchange")
	}
	return pending
}

// signedPending sends one bodyless request to a pending URL, signed by the
// given Agent key and token.
func (f *subagentFederation) signedPending(t *testing.T, method, location string, key jose.SigningKey, token string) *http.Response {
	t.Helper()
	request, _ := http.NewRequest(method, location, nil)
	if err := signaturekey.SignJWTRequest(request, key, token, f.clock); err != nil {
		t.Fatal(err)
	}
	response, err := f.network.RoundTrip(request)
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func requirePendingProblem(t *testing.T, response *http.Response, status int, code string) {
	t.Helper()
	defer response.Body.Close()
	problem, err := aauth.DecodeProblemResponse(response)
	if err != nil || problem.Status != status || string(problem.Code) != code {
		t.Fatalf("problem = %#v %v; want %d %s", problem, err, status, code)
	}
}

func TestSubagentFederatedPaymentThenApprovalDeliversChildBoundGrant(t *testing.T) {
	f := newSubagentFederation(t, 10*time.Minute)
	pending := f.begin(t)
	reference := deferredReference(pending)
	record, err := f.ps.FederatedAuthorization(context.Background(), reference)
	if err != nil {
		t.Fatal(err)
	}
	if record.Response.Status != http.StatusPaymentRequired || record.Agent != subagentParentID ||
		record.AgentToken != f.parentToken || record.SubagentToken != f.childToken {
		t.Fatalf("retained continuation = %#v", record)
	}
	// The child holds credentials but never calls the PS, so it cannot poll.
	requirePendingProblem(t, f.signedPending(t, http.MethodGet, pending.Location(), f.childKey, f.childToken), http.StatusForbidden, "wrong_poller")
	result, err := f.parent.PollExchange(context.Background(), pending)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := result.Pending(); !ok || f.asPolls.Load() != 0 {
		t.Fatalf("parent poll = %#v; AS polls = %d", result, f.asPolls.Load())
	}
	f.recompose(t)
	f.stage.Store(1)
	if err := f.ps.AdvanceFederation(context.Background(), reference); err != nil {
		t.Fatal(err)
	}
	if record, err = f.ps.FederatedAuthorization(context.Background(), reference); err != nil || record.Response.Status != http.StatusAccepted {
		t.Fatalf("approval wait = %#v %v", record.Response, err)
	}
	f.stage.Store(2)
	if err := f.ps.AdvanceFederation(context.Background(), reference); err != nil {
		t.Fatal(err)
	}
	// A child poll after completion is refused and does not consume the grant.
	requirePendingProblem(t, f.signedPending(t, http.MethodGet, pending.Location(), f.childKey, f.childToken), http.StatusForbidden, "wrong_poller")
	result, err = f.parent.PollExchange(context.Background(), pending)
	if err != nil {
		t.Fatal(err)
	}
	token, ok := result.Token()
	if !ok {
		t.Fatal("missing child-bound Auth token")
	}
	claims, err := aauth.VerifyAuthToken(context.Background(), token, f.parentResolver(t), f.clock)
	if err != nil {
		t.Fatal(err)
	}
	if !claims.Confirmation.JWK.Equal(f.childKey.PublicJWK()) || claims.ExpiresAt > f.childExpiresAt.Unix() || claims.Issuer != "https://as.example" {
		t.Fatalf("delivered Auth token = %#v", claims)
	}
	request, _ := http.NewRequest(http.MethodGet, "https://resource.example/records", nil)
	response, err := f.child.Do(context.Background(), agent.Call{Request: request, AuthToken: token})
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusOK || f.protected.Load() != 1 {
		t.Fatalf("child Resource call = %d, protected calls = %d", response.StatusCode, f.protected.Load())
	}
	// The parent cannot use the child's credential: it lacks the child's key.
	parentUse := f.signedPending(t, http.MethodGet, "https://resource.example/records", f.parentKey, token)
	parentUse.Body.Close()
	if parentUse.StatusCode != http.StatusUnauthorized || f.protected.Load() != 1 {
		t.Fatalf("parent use of child credential = %d", parentUse.StatusCode)
	}
	_, err = f.parent.PollExchange(context.Background(), pending)
	requireDeferredProblem(t, err, http.StatusGone, "request_consumed")
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.asPolicy) != 3 {
		t.Fatalf("AS policy evaluations = %v", f.asPolicy)
	}
	for _, seen := range f.asPolicy {
		if seen != subagentParentID+"|"+subagentChildID {
			t.Fatalf("AS policy saw %q", seen)
		}
	}
}

func TestSubagentFederatedDenialIsTerminal(t *testing.T) {
	f := newSubagentFederation(t, 10*time.Minute)
	f.stage.Store(1)
	pending := f.begin(t)
	f.stage.Store(-1)
	if err := f.ps.AdvanceFederation(context.Background(), deferredReference(pending)); err != nil {
		t.Fatal(err)
	}
	_, err := f.parent.PollExchange(context.Background(), pending)
	requireDeferredProblem(t, err, http.StatusForbidden, "denied")
	_, err = f.parent.PollExchange(context.Background(), pending)
	requireDeferredProblem(t, err, http.StatusGone, "request_consumed")
}

// The continuation cannot outlive the sub-agent token that justified it, even
// when the configured pending lifetime is longer.
func TestSubagentFederatedContinuationExpiresWithTheChildToken(t *testing.T) {
	f := newSubagentFederation(t, 30*time.Second)
	f.stage.Store(1)
	pending := f.begin(t)
	record, err := f.ps.FederatedAuthorization(context.Background(), deferredReference(pending))
	if err != nil {
		t.Fatal(err)
	}
	if !record.ExpiresAt.Equal(f.childExpiresAt) {
		t.Fatalf("continuation deadline = %s, want child expiry %s", record.ExpiresAt, f.childExpiresAt)
	}
	f.now.Add(31)
	_, err = f.parent.PollExchange(context.Background(), pending)
	requireDeferredProblem(t, err, http.StatusRequestTimeout, "expired")
	_, err = f.parent.PollExchange(context.Background(), pending)
	requireDeferredProblem(t, err, http.StatusGone, "request_consumed")
	if f.asCancels.Load() != 1 {
		t.Fatalf("AS withdrawals after the PS ended the wait = %d, want 1", f.asCancels.Load())
	}
}

// Protocol 28e8258, Agent Response to Clarification (Cancel Request) and
// Pending URL Security: only the parent cancels; the PS closes its custody and
// tells the AS once.
func TestSubagentFederatedCancellationClosesBothContinuations(t *testing.T) {
	f := newSubagentFederation(t, 10*time.Minute)
	f.stage.Store(1)
	pending := f.begin(t)
	requirePendingProblem(t, f.signedPending(t, http.MethodDelete, pending.Location(), f.childKey, f.childToken), http.StatusForbidden, "wrong_poller")
	requireCancelled(t, f.signedPending(t, http.MethodDelete, pending.Location(), f.parentKey, f.parentToken))
	if f.asCancels.Load() != 1 || f.asPolls.Load() != 0 {
		t.Fatalf("AS cancels = %d polls = %d", f.asCancels.Load(), f.asPolls.Load())
	}
	_, err := f.parent.PollExchange(context.Background(), pending)
	requireDeferredProblem(t, err, http.StatusGone, "request_consumed")
	if err := f.ps.AdvanceFederation(context.Background(), deferredReference(pending)); !errors.Is(err, personserver.ErrFederationNotReady) {
		t.Fatalf("advance after cancellation = %v", err)
	}
	if err := f.parent.CancelExchange(context.Background(), pending); err == nil {
		t.Fatal("second cancellation succeeded")
	}
}

// Protocol 28e8258, Sub-Agents and Agent-Person Binding: revoking the parent's
// binding makes the next sub-agent authorization fail. A waiting request is
// answered revoked_presented_token once and then consumed; no further AS poll
// occurs, and the PS withdraws the request at the AS. A replacement binding
// does not adopt the wait.
func TestSubagentFederatedBindingRevocationEndsTheWait(t *testing.T) {
	for _, mode := range []string{"agent poll", "host advance", "replacement binding"} {
		t.Run(mode, func(t *testing.T) {
			f := newSubagentFederation(t, 10*time.Minute)
			f.stage.Store(1)
			pending := f.begin(t)
			binding := personserver.AgentBinding{AgentProvider: "https://ap.example", Agent: subagentParentID}
			f.now.Add(1)
			if err := f.ps.RevokeAgentBinding(context.Background(), binding); err != nil {
				t.Fatal(err)
			}
			f.stage.Store(2)
			switch mode {
			case "host advance":
				if err := f.ps.AdvanceFederation(context.Background(), deferredReference(pending)); err != nil {
					t.Fatal(err)
				}
			case "replacement binding":
				f.now.Add(1)
				if err := f.ps.ReestablishAgentBinding(context.Background(), binding); err != nil {
					t.Fatal(err)
				}
				f.now.Add(1)
			}
			_, err := f.parent.PollExchange(context.Background(), pending)
			requireDeferredProblem(t, err, http.StatusBadRequest, "revoked_presented_token")
			_, err = f.parent.PollExchange(context.Background(), pending)
			requireDeferredProblem(t, err, http.StatusGone, "request_consumed")
			if f.asPolls.Load() != 0 || f.asCancels.Load() != 1 {
				t.Fatalf("revoked binding: AS polls %d, withdrawals %d", f.asPolls.Load(), f.asCancels.Load())
			}
		})
	}
}

// Protocol 28e8258, Presenting a Revoked Token: a pending request whose Agent
// token is revoked while it waits terminates with revoked. The sub-agent token
// is held to the same rule, and the PS does not present it to the AS again.
func TestSubagentFederatedRevokedChildTokenEndsTheWait(t *testing.T) {
	for _, advance := range []bool{false, true} {
		t.Run(fmt.Sprintf("advance=%t", advance), func(t *testing.T) {
			testSubagentFederatedRevokedChildTokenEndsTheWait(t, advance)
		})
	}
}

func testSubagentFederatedRevokedChildTokenEndsTheWait(t *testing.T, advance bool) {
	f := newSubagentFederation(t, 10*time.Minute)
	f.stage.Store(1)
	pending := f.begin(t)
	child, err := aauth.VerifyAgentToken(context.Background(), f.childToken, f.parentResolver(t), f.clock)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.revocations.Revoke(context.Background(), aauth.RevocationRequest{
		Reference: aauth.TokenReference{Issuer: child.Issuer, JTI: child.JTI}, ExpiresAt: time.Unix(child.ExpiresAt, 0),
	}); err != nil {
		t.Fatal(err)
	}
	f.stage.Store(2)
	if advance {
		if err := f.ps.AdvanceFederation(context.Background(), deferredReference(pending)); err != nil {
			t.Fatal(err)
		}
	}
	_, err = f.parent.PollExchange(context.Background(), pending)
	requireDeferredProblem(t, err, http.StatusForbidden, "revoked")
	var problem *aauth.ProblemError
	if !errors.As(err, &problem) || !strings.Contains(problem.Detail, "sub-agent token") {
		t.Fatalf("revoked detail = %#v", problem)
	}
	if f.asPolls.Load() != 0 || f.asCancels.Load() != 1 {
		t.Fatalf("revoked child token: AS polls %d, withdrawals %d", f.asPolls.Load(), f.asCancels.Load())
	}
	_, err = f.parent.PollExchange(context.Background(), pending)
	requireDeferredProblem(t, err, http.StatusGone, "request_consumed")
}

// hookedFederatedStore runs afterLoad once, after a Load returns, so a test
// can place a host advance between a handler's Load and its Replace.
type hookedFederatedStore struct {
	personserver.FederatedAuthorizationQueueStore
	afterLoad atomic.Pointer[func()]
}

func (store *hookedFederatedStore) LoadFederatedAuthorization(ctx context.Context, id string) (personserver.FederatedAuthorizationRecord, error) {
	record, err := store.FederatedAuthorizationQueueStore.LoadFederatedAuthorization(ctx, id)
	if hook := store.afterLoad.Swap(nil); hook != nil {
		(*hook)()
	}
	return record, err
}

// A parent's withdrawal that loses its compare-and-swap to a host advance
// still withdraws: the PS reloads and consumes the grant the advance retained,
// so nothing is delivered after the cancellation is answered.
func TestSubagentFederatedCancellationWinsAConcurrentAdvance(t *testing.T) {
	f := newSubagentFederation(t, 10*time.Minute)
	hooked := &hookedFederatedStore{FederatedAuthorizationQueueStore: f.psStore}
	f.psStore = hooked
	f.recompose(t)
	f.stage.Store(1)
	pending := f.begin(t)
	f.stage.Store(2)
	advance := func() {
		if err := f.ps.AdvanceFederation(context.Background(), deferredReference(pending)); err != nil {
			t.Errorf("concurrent advance: %v", err)
		}
	}
	hooked.afterLoad.Store(&advance)
	requireCancelled(t, f.signedPending(t, http.MethodDelete, pending.Location(), f.parentKey, f.parentToken))
	if f.asPolls.Load() != 1 {
		t.Fatalf("the advance did not reach the AS: polls %d", f.asPolls.Load())
	}
	_, err := f.parent.PollExchange(context.Background(), pending)
	requireDeferredProblem(t, err, http.StatusGone, "request_consumed")
	record, err := f.ps.FederatedAuthorization(context.Background(), deferredReference(pending))
	if err != nil || !record.Gone {
		t.Fatalf("cancelled continuation = %#v %v", record, err)
	}
}

// The AS keeps its own deadline, so a wait the PS ends at creation, because
// the AS answered after the PS deadline, is withdrawn at the AS too.
func TestSubagentFederatedLateASAnswerIsWithdrawn(t *testing.T) {
	f := newSubagentFederation(t, 10*time.Minute)
	f.stage.Store(1)
	late := func() { f.now.Add(6 * 60) }
	f.afterAS.Store(&late)
	ctx := context.Background()
	person, err := f.parent.PersonToken(ctx, agent.PersonTokenRequest{
		PersonServer: "https://ps.example", Resource: "https://resource.example", SubagentToken: f.childToken,
	})
	if err != nil {
		t.Fatal(err)
	}
	personToken, _ := person.Token()
	request, _ := http.NewRequest(http.MethodGet, "https://resource.example/records", nil)
	call, err := f.child.Begin(ctx, agent.InitialCall{Request: request, PersonToken: personToken})
	if err != nil {
		t.Fatal(err)
	}
	required, ok := call.AuthorizationRequired()
	if !ok {
		t.Fatal("missing child-bound Resource token")
	}
	_, err = f.parent.BeginExchange(ctx, agent.ExchangeRequest{
		PersonServer: "https://ps.example", ResourceToken: required.ResourceToken,
		PresentedToken: personToken, SubagentToken: f.childToken,
	})
	requireDeferredProblem(t, err, http.StatusRequestTimeout, "expired")
	if f.asCancels.Load() != 1 {
		t.Fatalf("AS withdrawals of a late answer = %d, want 1", f.asCancels.Load())
	}
}

func (f *subagentFederation) parentResolver(t *testing.T) signaturekey.KeyResolver {
	t.Helper()
	resolver, err := signaturekey.NewHTTPKeyResolver(signaturekey.HTTPKeyResolverConfig{
		Client: &http.Client{Transport: f.network}, TransportEnforcesEgress: true, Clock: f.clock, Admit: func(context.Context, string) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	return resolver
}

// Both waits are bounded by the sub-agent token actually presented. A child
// reissued with a shorter lifetime after its Person token was obtained makes
// that bound decisive at the PS and at the AS.
func TestSubagentFederatedWaitsEndWithThePresentedChildToken(t *testing.T) {
	f := newSubagentFederation(t, 10*time.Minute)
	f.stage.Store(1)
	shorter, err := f.ap.IssueSubagent(context.Background(), f.parentToken, agentprovider.SubagentTokenRequest{
		Discriminator: "search", PublicKey: f.childKey.PublicJWK(), Lifetime: 20 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	pending := f.beginWith(t, shorter)
	deadline := f.clock.Now().Add(20 * time.Second)
	record, err := f.ps.FederatedAuthorization(context.Background(), deferredReference(pending))
	if err != nil {
		t.Fatal(err)
	}
	if !record.ExpiresAt.Equal(deadline) || record.SubagentToken != shorter {
		t.Fatalf("PS wait deadline = %s token=%t, want %s", record.ExpiresAt, record.SubagentToken == shorter, deadline)
	}
	retained, err := f.asStore.LoadAccessAuthorization(context.Background(), record.Location[strings.LastIndex(record.Location, "/")+1:])
	if err != nil {
		t.Fatal(err)
	}
	if !retained.ExpiresAt.Equal(deadline) {
		t.Fatalf("AS wait deadline = %s, want %s", retained.ExpiresAt, deadline)
	}
}

// Only the Person Server that started an AS wait can withdraw it, once.
func TestAccessServerCancellationBelongsToTheRequestingPersonServer(t *testing.T) {
	f := newSubagentFederation(t, 10*time.Minute)
	f.stage.Store(1)
	pending := f.begin(t)
	record, err := f.ps.FederatedAuthorization(context.Background(), deferredReference(pending))
	if err != nil {
		t.Fatal(err)
	}
	otherKey := newSigningKey(t, "other-ps")
	f.network.Handle("https://other-ps.example", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/aauth-person.json":
			fmt.Fprint(w, `{"issuer":"https://other-ps.example","jwks_uri":"https://other-ps.example/.well-known/jwks.json"}`)
		case "/.well-known/jwks.json":
			_ = json.NewEncoder(w).Encode(map[string]any{"keys": []jose.JWK{otherKey.PublicJWK()}})
		default:
			http.NotFound(w, r)
		}
	}))
	cancel := func(location string, key jose.SigningKey, issuer string) *http.Response {
		request, _ := http.NewRequest(http.MethodDelete, location, nil)
		if err := signaturekey.SignJWKSURIRequest(request, key, issuer, aauth.PersonDiscoveryDocument, f.clock); err != nil {
			t.Fatal(err)
		}
		response, err := f.network.RoundTrip(request)
		if err != nil {
			t.Fatal(err)
		}
		return response
	}
	requirePendingProblem(t, cancel(record.Location, otherKey, "https://other-ps.example"), http.StatusForbidden, "wrong_poller")
	requirePendingProblem(t, cancel("https://as.example/token/pending/unknown", f.psKey, "https://ps.example"), http.StatusGone, "unknown_request")
	response := cancel(record.Location, f.psKey, "https://ps.example")
	requireCancelled(t, response)
	requirePendingProblem(t, cancel(record.Location, f.psKey, "https://ps.example"), http.StatusGone, "request_consumed")
	poll, _ := http.NewRequest(http.MethodGet, record.Location, nil)
	if err := signaturekey.SignJWKSURIRequest(poll, f.psKey, "https://ps.example", aauth.PersonDiscoveryDocument, f.clock); err != nil {
		t.Fatal(err)
	}
	polled, err := f.network.RoundTrip(poll)
	if err != nil {
		t.Fatal(err)
	}
	requirePendingProblem(t, polled, http.StatusGone, "request_consumed")
}

// Both implementations answer a successful withdrawal the same way, so a PS
// of either one can cancel at an AS of the other.
func requireCancelled(t *testing.T, response *http.Response) {
	t.Helper()
	defer response.Body.Close()
	var body struct {
		Status string `json:"status"`
	}
	if response.StatusCode != http.StatusOK || response.Header.Get("Cache-Control") != "no-store" ||
		json.NewDecoder(response.Body).Decode(&body) != nil || body.Status != "cancelled" {
		t.Fatalf("cancellation = %d %v %#v", response.StatusCode, response.Header, body)
	}
}

// A withdrawal that arrives after the wait expired closes it with expired.
// The AS deadline is its own, so the PS still withdraws the request there.
func TestSubagentFederatedCancellationAfterExpiryIsExpired(t *testing.T) {
	f := newSubagentFederation(t, 10*time.Minute)
	f.stage.Store(1)
	pending := f.begin(t)
	f.now.Add(61)
	err := f.parent.CancelExchange(context.Background(), pending)
	requireDeferredProblem(t, err, http.StatusRequestTimeout, "expired")
	_, err = f.parent.PollExchange(context.Background(), pending)
	requireDeferredProblem(t, err, http.StatusGone, "request_consumed")
	if f.asCancels.Load() != 1 {
		t.Fatalf("AS withdrawals after the PS deadline = %d, want 1", f.asCancels.Load())
	}
}

// An AS wait withdrawn after its deadline is consumed with expired.
func TestAccessServerCancellationAfterItsDeadlineIsExpired(t *testing.T) {
	f := newSubagentFederation(t, 10*time.Minute)
	f.stage.Store(1)
	pending := f.begin(t)
	record, err := f.ps.FederatedAuthorization(context.Background(), deferredReference(pending))
	if err != nil {
		t.Fatal(err)
	}
	f.now.Add(61)
	cancel := func() *http.Response {
		request, _ := http.NewRequest(http.MethodDelete, record.Location, nil)
		if err := signaturekey.SignJWKSURIRequest(request, f.psKey, "https://ps.example", aauth.PersonDiscoveryDocument, f.clock); err != nil {
			t.Fatal(err)
		}
		response, err := f.network.RoundTrip(request)
		if err != nil {
			t.Fatal(err)
		}
		return response
	}
	requirePendingProblem(t, cancel(), http.StatusRequestTimeout, "expired")
	requirePendingProblem(t, cancel(), http.StatusGone, "request_consumed")
}
