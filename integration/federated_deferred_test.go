package integration_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/accessserver"
	"gitlab.com/sidecat-dev/aauth-go/agent"
	"gitlab.com/sidecat-dev/aauth-go/agentprovider"
	"gitlab.com/sidecat-dev/aauth-go/diagnostics"
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/personserver"
	"gitlab.com/sidecat-dev/aauth-go/resource"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
	"gitlab.com/sidecat-dev/aauth-go/testutil"
)

// Protocol 28e8258: AS Response, Auth Token Delivery, PS-AS Trust
// Establishment, Deferred Responses and Pending URL Security.
func TestFederatedPaymentApprovalAndDeliveryAcrossRecomposition(t *testing.T) {
	f := newDeferredFederation(t)
	pending := f.begin(t)
	reference := pending.Location()[strings.LastIndex(pending.Location(), "/")+1:]
	payment, err := f.ps.FederatedAuthorization(context.Background(), reference)
	if err != nil {
		t.Fatal(err)
	}
	if payment.Response.Status != 402 || payment.Response.Header.Get("WWW-Authenticate") != `Payment id="bill-1", method="example"` {
		t.Fatalf("host payment challenge = %#v", payment.Response)
	}
	asLocation := payment.Location
	if strings.HasPrefix(pending.Location(), "https://as.example/") {
		t.Fatal("Agent was sent to AS")
	}
	f.recompose(t)
	// Agent polling does not settle a payment or make an implicit AS request.
	result, err := f.client.PollExchange(context.Background(), pending)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := result.Pending(); !ok {
		t.Fatal("expected retained PS pending response")
	}
	if f.asPolls.Load() != 0 {
		t.Fatal("Agent poll advanced federation")
	}
	f.stage.Store(1) // host confirms billing; the AS still awaits approval
	if err := f.ps.AdvanceFederation(context.Background(), reference); err != nil {
		t.Fatal(err)
	}
	approval, err := f.ps.FederatedAuthorization(context.Background(), reference)
	if err != nil {
		t.Fatal(err)
	}
	if approval.Response.Status != 202 || approval.Location != asLocation {
		t.Fatalf("approval = %#v", approval)
	}
	f.stage.Store(2)
	if err := f.ps.AdvanceFederation(context.Background(), reference); err != nil {
		t.Fatal(err)
	}
	result, err = f.client.PollExchange(context.Background(), pending)
	if err != nil {
		t.Fatal(err)
	}
	token, ok := result.Token()
	if !ok {
		t.Fatal("missing verified Auth token")
	}
	req, _ := http.NewRequest("GET", "https://resource.example/records", nil)
	response, err := f.client.Do(context.Background(), agent.Call{Request: req, AuthToken: token})
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != 200 || f.protected.Load() != 1 {
		t.Fatalf("Resource: %d, calls %d", response.StatusCode, f.protected.Load())
	}
	if _, err := f.client.PollExchange(context.Background(), pending); err == nil {
		t.Fatal("terminal PS result was delivered twice")
	}
	// A billing relationship is host-owned and survives server recomposition.
	f.recompose(t)
	next := f.exchange(t)
	if _, ok := next.Token(); !ok {
		t.Fatal("established billing relationship did not skip payment")
	}
}

// A host can recover outstanding work after recomposition without observing
// Create or borrowing the Agent's pending URL. Listing does not advance the AS.
func TestFederatedPendingReferencesAcrossRecomposition(t *testing.T) {
	f := newDeferredFederation(t)
	pending := f.begin(t)
	f.recompose(t)
	queue := f.ps
	refs, err := queue.PendingFederatedAuthorizationReferences(context.Background(), 10)
	if err != nil || len(refs) != 1 || refs[0] != deferredReference(pending) {
		t.Fatalf("references = %v %v", refs, err)
	}
	if f.asPolls.Load() != 0 {
		t.Fatal("listing advanced federation")
	}
	f.stage.Store(2)
	if err := f.ps.AdvanceFederation(context.Background(), refs[0]); err != nil {
		t.Fatal(err)
	}
	refs, err = queue.PendingFederatedAuthorizationReferences(context.Background(), 10)
	if err != nil || len(refs) != 0 {
		t.Fatalf("completed references = %v %v", refs, err)
	}
	result, err := f.client.PollExchange(context.Background(), pending)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := result.Token(); !ok {
		t.Fatal("listing consumed the retained grant")
	}
}

type deferredFederation struct {
	asLifetime             atomic.Int64
	policyDelay            atomic.Int64
	grantLifetime          atomic.Int64
	now                    atomic.Int64
	network                *logicalTransport
	ap                     *agentprovider.Server
	agentKey, psKey, asKey jose.SigningKey
	clock                  aauth.Clock
	asMutation             func(*http.Request, *httptest.ResponseRecorder)
	psStore                personserver.FederatedAuthorizationStore
	asStore                accessserver.DeferredAuthorizationStore
	retry                  atomic.Int64
	ps                     *personserver.Server
	client                 *agent.Client
	stage                  atomic.Int32
	asPolls                atomic.Int32
	protected              atomic.Int32
	recompose              func(*testing.T)
	exchange               func(*testing.T) agent.ExchangeResult
}

func (f *deferredFederation) begin(t *testing.T) agent.PendingExchange {
	t.Helper()
	result := f.exchange(t)
	pending, ok := result.Pending()
	if !ok {
		t.Fatal("missing pending exchange")
	}
	return pending
}
func newDeferredFederation(t *testing.T) *deferredFederation {
	t.Helper()
	f := &deferredFederation{}
	f.now.Store(1792512000)
	f.grantLifetime.Store(60)
	f.asLifetime.Store(60)
	clock := aauth.ClockFunc(func() time.Time { return time.Unix(f.now.Load(), 0).UTC() })
	f.clock = clock
	network := newLogicalTransport()
	f.network = network
	httpClient := &http.Client{Transport: network}
	apKey, agentKey, psKey, asKey, resourceKey := newSigningKey(t, "ap"), newSigningKey(t, "agent"), newSigningKey(t, "ps"), newSigningKey(t, "as"), newSigningKey(t, "resource")
	f.agentKey, f.psKey, f.asKey = agentKey, psKey, asKey
	// Discovery runs through each role's public HTTP handler.
	resolver, err := signaturekey.NewHTTPKeyResolver(signaturekey.HTTPKeyResolverConfig{Client: httpClient, Clock: clock, Admit: func(context.Context, string) error { return nil }})
	if err != nil {
		t.Fatal(err)
	}
	var ids atomic.Int64
	newID := func() string { return fmt.Sprintf("deferred-%d", ids.Add(1)) }
	ap, err := agentprovider.New(agentprovider.Config{Issuer: "https://ap.example", SigningKey: apKey, Clock: clock, NewID: newID})
	if err != nil {
		t.Fatal(err)
	}
	compact, err := ap.Issue(aauth.AgentTokenRequest{Agent: "aauth:reader@ap.example", PersonServer: "https://ps.example", PublicKey: agentKey.PublicJWK(), Lifetime: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	f.ap = ap
	network.Handle("https://ap.example", ap.Handler())
	f.asStore = testutil.NewAccessAuthorizationStore()
	f.psStore = testutil.NewFederatedAuthorizationStore()
	personTokens := newMemoryPersonTokenStore()
	f.recompose = func(t *testing.T) {
		t.Helper()
		as, err := accessserver.New(accessserver.Config{Issuer: "https://as.example", SigningKey: asKey, KeyResolver: resolver, Clock: clock, NewID: newID,
			TrustPersonServer: func(context.Context, string) error { return nil },
			Deferred:          &accessserver.DeferredConfig{Store: f.asStore, Lifetime: time.Duration(f.asLifetime.Load()) * time.Second},
			Authorize: func(_ context.Context, r accessserver.AuthorizationRequest) (accessserver.Decision, error) {
				f.now.Add(f.policyDelay.Load())
				switch f.stage.Load() {
				case -1:
					return accessserver.Decision{}, accessserver.ErrAccessDenied
				case 0:
					return accessserver.Decision{Pending: &accessserver.PendingDecision{RetryAfter: time.Duration(f.retry.Load()) * time.Second, Payment: &accessserver.PaymentChallenge{Authenticate: `Payment id="bill-1", method="example"`}}}, nil
				case 1:
					return accessserver.Decision{Pending: &accessserver.PendingDecision{}}, nil
				case 3:
					if _, ok := r.Claims["email"]; ok {
						return accessserver.Decision{Scopes: r.Scopes, Lifetime: time.Duration(f.grantLifetime.Load()) * time.Second}, nil
					}
					return accessserver.Decision{Pending: &accessserver.PendingDecision{RequiredClaims: []string{"email"}}}, nil
				default:
					return accessserver.Decision{Scopes: r.Scopes, Lifetime: time.Duration(f.grantLifetime.Load()) * time.Second}, nil
				}
			}})
		if err != nil {
			t.Fatal(err)
		}
		network.Handle("https://as.example", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/token/pending/") {
				f.asPolls.Add(1)
			}
			if f.asMutation == nil {
				as.Handler().ServeHTTP(w, r)
				return
			}
			recorder := httptest.NewRecorder()
			as.Handler().ServeHTTP(recorder, r)
			f.asMutation(r, recorder)
			for k, v := range recorder.Header() {
				w.Header()[k] = v
			}
			w.WriteHeader(recorder.Code)
			_, _ = w.Write(recorder.Body.Bytes())
		}))
		f.ps, err = personserver.NewFederatedAuthorization(personserver.FederatedAuthorizationConfig{Issuer: "https://ps.example", SigningKey: psKey, KeyResolver: resolver, Clock: clock, NewID: newID, HTTPClient: httpClient, Tokens: personTokens,
			AccessServerEndpoint: func(context.Context, string) (string, error) { return "https://as.example/token", nil },
			BindPerson: func(context.Context, personserver.PersonTokenRequest) (personserver.Person, error) {
				return personserver.Person{Subject: "reader", Lifetime: 5 * time.Minute}, nil
			},
			Consent:  func(context.Context, personserver.AuthorizationRequest) error { return nil },
			Deferred: &personserver.FederatedDeferredConfig{Store: f.psStore, Lifetime: time.Minute},
		})
		if err != nil {
			t.Fatal(err)
		}
		network.Handle("https://ps.example", f.ps.Handler())
	}
	f.recompose(t)
	res, err := resource.NewFederatedAuthorization(resource.FederatedAuthorizationConfig{Issuer: "https://resource.example", AccessServer: "https://as.example", SigningKey: resourceKey, KeyResolver: resolver, Clock: clock, NewID: newID,
		ScopeDescriptions: map[string]string{"records.read": "Read records"}, RequiredScopes: func(*http.Request) []string { return []string{"records.read"} },
		ResolvePerson: func(context.Context, resource.PersonIdentity, resource.PersonContext) error { return nil },
		Protected:     http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { f.protected.Add(1); w.WriteHeader(200) }),
	})
	if err != nil {
		t.Fatal(err)
	}
	network.Handle("https://resource.example", res.Handler())
	f.client, err = agent.New(context.Background(), agent.Config{Identifier: "aauth:reader@ap.example", AgentToken: compact, SigningKey: agentKey, KeyResolver: resolver, Clock: clock, HTTPClient: httpClient})
	if err != nil {
		t.Fatal(err)
	}
	f.exchange = func(t *testing.T) agent.ExchangeResult {
		t.Helper()
		ctx := context.Background()
		result, err := f.client.PersonToken(ctx, agent.PersonTokenRequest{PersonServer: "https://ps.example", Resource: "https://resource.example"})
		if err != nil {
			t.Fatal(err)
		}
		person, ok := result.Token()
		if !ok {
			t.Fatal("missing Person token")
		}
		req, _ := http.NewRequest("GET", "https://resource.example/records", nil)
		call, err := f.client.Begin(ctx, agent.InitialCall{Request: req, PersonToken: person})
		if err != nil {
			t.Fatal(err)
		}
		required, ok := call.AuthorizationRequired()
		if !ok {
			t.Fatal("missing Resource token")
		}
		exchange, err := f.client.BeginExchange(ctx, agent.ExchangeRequest{PersonServer: "https://ps.example", ResourceToken: required.ResourceToken, PresentedToken: person})
		if err != nil {
			t.Fatal(err)
		}
		return exchange
	}
	return f
}

func TestFederatedDeferredDenialRetainsPollingError(t *testing.T) {
	f := newDeferredFederation(t)
	pending := f.begin(t)
	id := pending.Location()[strings.LastIndex(pending.Location(), "/")+1:]
	f.stage.Store(-1)
	if err := f.ps.AdvanceFederation(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	_, err := f.client.PollExchange(context.Background(), pending)
	requireDeferredProblem(t, err, 403, "denied")
	_, err = f.client.PollExchange(context.Background(), pending)
	requireDeferredProblem(t, err, 410, "request_consumed")
}
func requireDeferredProblem(t *testing.T, err error, status int, code string) {
	t.Helper()
	var problem *aauth.ProblemError
	if !errors.As(err, &problem) || problem.Status != status || string(problem.Code) != code {
		t.Fatalf("problem = %v; want %d %s", err, status, code)
	}
}

func deferredReference(p agent.PendingExchange) string {
	return p.Location()[strings.LastIndex(p.Location(), "/")+1:]
}
func deferredGET(t *testing.T, f *deferredFederation, location string, key jose.SigningKey, token, ps string) *http.Response {
	t.Helper()
	request, _ := http.NewRequest("GET", location, nil)
	var err error
	if ps != "" {
		err = signaturekey.SignJWKSURIRequest(request, key, ps, aauth.PersonDiscoveryDocument, f.clock)
	} else {
		err = signaturekey.SignJWTRequest(request, key, token, f.clock)
	}
	if err != nil {
		t.Fatal(err)
	}
	response, err := f.network.RoundTrip(request)
	if err != nil {
		t.Fatal(err)
	}
	return response
}
func TestFederatedDeferredPollIdentityAndSingleDelivery(t *testing.T) {
	f := newDeferredFederation(t)
	pending := f.begin(t)
	id := deferredReference(pending)
	record, err := f.ps.FederatedAuthorization(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"agent", "key"} {
		t.Run(kind, func(t *testing.T) {
			key := f.agentKey
			subject := "aauth:other@ap.example"
			if kind == "key" {
				key = newSigningKey(t, "other")
				subject = "aauth:reader@ap.example"
			}
			token, err := f.ap.Issue(aauth.AgentTokenRequest{Agent: subject, PersonServer: "https://ps.example", PublicKey: key.PublicJWK(), Lifetime: time.Hour})
			if err != nil {
				t.Fatal(err)
			}
			response := deferredGET(t, f, pending.Location(), key, token, "")
			defer response.Body.Close()
			problem, err := aauth.DecodeProblemResponse(response)
			if err != nil || problem.Status != 403 || problem.Code != "wrong_poller" {
				t.Fatalf("foreign %s: %v %v", kind, problem, err)
			}
		})
	}
	// A valid proof by another PS cannot obtain the original PS's pending grant.
	f.network.Handle("https://other-ps.example", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/.well-known/aauth-person.json" {
			json.NewEncoder(w).Encode(map[string]string{"issuer": "https://other-ps.example", "jwks_uri": "https://other-ps.example/keys"})
		} else {
			json.NewEncoder(w).Encode(map[string]any{"keys": []jose.JWK{f.psKey.PublicJWK()}})
		}
	}))
	response := deferredGET(t, f, record.Location, f.psKey, "", "https://other-ps.example")
	problem, err := aauth.DecodeProblemResponse(response)
	response.Body.Close()
	if err != nil || problem.Status != 403 || problem.Code != "wrong_poller" {
		t.Fatalf("foreign PS: %v %v", problem, err)
	}
	f.stage.Store(2)
	// Only one worker may cross the AS boundary; others see a fence or terminal state.
	var successes atomic.Int32
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			err := f.ps.AdvanceFederation(context.Background(), id)
			if err == nil {
				successes.Add(1)
			} else if !errors.Is(err, personserver.ErrFederationNotReady) && !errors.Is(err, personserver.ErrFederatedAuthorizationConflict) {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	if successes.Load() != 1 || f.asPolls.Load() != 2 {
		t.Fatalf("advances %d, AS polls %d (including foreign PS)", successes.Load(), f.asPolls.Load())
	}
	response = deferredGET(t, f, record.Location, f.psKey, "", "https://ps.example")
	response.Body.Close()
	if response.StatusCode != 410 {
		t.Fatalf("AS result replay: %d", response.StatusCode)
	}
	var grants atomic.Int32
	for range 8 {
		wg.Go(func() {
			result, err := f.client.PollExchange(context.Background(), pending)
			if err == nil {
				if _, ok := result.Token(); ok {
					grants.Add(1)
				}
			}
		})
	}
	wg.Wait()
	if grants.Load() != 1 {
		t.Fatalf("delivered %d grants", grants.Load())
	}
}
func TestFederatedDeferredExpiryAndRetryAfter(t *testing.T) {
	t.Run("expiry", func(t *testing.T) {
		f := newDeferredFederation(t)
		p := f.begin(t)
		record, _ := f.ps.FederatedAuthorization(context.Background(), deferredReference(p))
		f.now.Add(60)
		response := deferredGET(t, f, record.Location, f.psKey, "", "https://ps.example")
		response.Body.Close()
		if response.StatusCode != 408 {
			t.Fatalf("AS expiry = %d", response.StatusCode)
		}
		response = deferredGET(t, f, record.Location, f.psKey, "", "https://ps.example")
		response.Body.Close()
		if response.StatusCode != 410 {
			t.Fatalf("AS expiry replay = %d", response.StatusCode)
		}
		_, err := f.client.PollExchange(context.Background(), p)
		requireDeferredProblem(t, err, 408, "expired")
		_, err = f.client.PollExchange(context.Background(), p)
		requireDeferredProblem(t, err, 410, "request_consumed")
	})
	t.Run("retry-after", func(t *testing.T) {
		f := newDeferredFederation(t)
		f.retry.Store(7)
		p := f.begin(t)
		id := deferredReference(p)
		record, _ := f.ps.FederatedAuthorization(context.Background(), id)
		if err := f.ps.AdvanceFederation(context.Background(), id); !errors.Is(err, personserver.ErrFederationNotReady) {
			t.Fatalf("early poll = %v", err)
		}
		response := deferredGET(t, f, record.Location, f.psKey, "", "https://ps.example")
		response.Body.Close()
		if response.StatusCode != 429 {
			t.Fatalf("early AS poll = %d", response.StatusCode)
		}
		f.now.Add(7)
		f.stage.Store(2)
		if err := f.ps.AdvanceFederation(context.Background(), id); err != nil {
			t.Fatal(err)
		}
		result, err := f.client.PollExchange(context.Background(), p)
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := result.Token(); !ok {
			t.Fatal("missing grant after interval")
		}
	})
}
func TestFederatedDeferredRefusesChangedLocationAndInvalidGrant(t *testing.T) {
	for _, kind := range []string{"foreign-location", "changed-location", "missing-no-store", "missing-status", "invalid-signature", "broader-scope"} {
		t.Run(kind, func(t *testing.T) {
			f := newDeferredFederation(t)
			p := f.begin(t)
			id := deferredReference(p)
			f.stage.Store(1)
			if kind == "invalid-signature" || kind == "broader-scope" {
				f.stage.Store(2)
			}
			f.asMutation = func(r *http.Request, w *httptest.ResponseRecorder) {
				if r.Method != "GET" || !strings.HasPrefix(r.URL.Path, "/token/pending/") {
					return
				}
				switch kind {
				case "foreign-location":
					w.Header().Set("Location", "https://attacker.example/collect")
				case "changed-location":
					w.Header().Set("Location", "https://as.example/another")
				case "missing-no-store":
					w.Header().Del("Cache-Control")
				case "missing-status":
					w.Body.Reset()
					w.Body.WriteString(`{}`)
				case "invalid-signature", "broader-scope":
					var value struct {
						Token string `json:"auth_token"`
					}
					if err := json.Unmarshal(w.Body.Bytes(), &value); err != nil {
						t.Fatal(err)
					}
					if kind == "invalid-signature" {
						parts := strings.Split(value.Token, ".")
						parts[2] = "invalid"
						value.Token = strings.Join(parts, ".")
					} else {
						claims, err := aauth.VerifyAuthToken(context.Background(), value.Token, signaturekey.StaticKeyResolver{signaturekey.StaticKeyReference{Issuer: "https://as.example", DiscoveryDocument: aauth.AccessDiscoveryDocument, KeyID: f.asKey.PublicJWK().Kid}: f.asKey.PublicJWK()}, f.clock)
						if err != nil {
							t.Fatal(err)
						}
						claims.Scope = "records.write"
						value.Token, err = aauth.MintAuthToken(f.asKey, claims)
						if err != nil {
							t.Fatal(err)
						}
					}
					w.Body.Reset()
					json.NewEncoder(w.Body).Encode(map[string]any{"auth_token": value.Token, "expires_in": 60})
				}
			}
			if err := f.ps.AdvanceFederation(context.Background(), id); err != nil {
				t.Fatal(err)
			}
			_, err := f.client.PollExchange(context.Background(), p)
			requireDeferredProblem(t, err, 502, "as_unreachable")
			if f.protected.Load() != 0 {
				t.Fatal("bad continuation reached protected service")
			}
		})
	}
}
func TestFederatedDeferredTransientPollRemainsPending(t *testing.T) {
	for _, status := range []int{429, 503} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			f := newDeferredFederation(t)
			p := f.begin(t)
			id := deferredReference(p)
			// Simulate a transient AS front-end refusal before the native pending handler.
			network := f.network
			network.mu.RLock()
			native := network.routes["https://as.example"]
			network.mu.RUnlock()
			transient := true
			network.Handle("https://as.example", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if transient && strings.HasPrefix(r.URL.Path, "/token/pending/") {
					w.Header().Set("Retry-After", "7")
					w.Header().Set("Content-Type", "application/problem+json")
					w.WriteHeader(status)
					io.WriteString(w, `{"error":"slow_down"}`)
					return
				}
				native.ServeHTTP(w, r)
			}))
			if err := f.ps.AdvanceFederation(context.Background(), id); err != nil {
				t.Fatal(err)
			}
			state, err := f.ps.FederatedAuthorization(context.Background(), id)
			if err != nil {
				t.Fatal(err)
			}
			if state.Terminal {
				t.Fatalf("%d consumed pending federation", status)
			}
			if state.NextPollAt.Before(f.clock.Now().Add(7 * time.Second)) {
				t.Fatal("ignored Retry-After")
			}
			if err := f.ps.AdvanceFederation(context.Background(), id); !errors.Is(err, personserver.ErrFederationNotReady) {
				t.Fatalf("premature retry = %v", err)
			}
			transient = false
			f.now.Add(7)
			f.stage.Store(2)
			if err := f.ps.AdvanceFederation(context.Background(), id); err != nil {
				t.Fatal(err)
			}
			result, err := f.client.PollExchange(context.Background(), p)
			if err != nil {
				t.Fatal(err)
			}
			if _, ok := result.Token(); !ok {
				t.Fatal("no grant after temporary refusal")
			}
		})
	}
}

func TestFederatedDeferredDoesNotDeliverExpiredRetainedGrant(t *testing.T) {
	f := newDeferredFederation(t)
	p := f.begin(t)
	f.stage.Store(2)
	f.grantLifetime.Store(1)
	if err := f.ps.AdvanceFederation(context.Background(), deferredReference(p)); err != nil {
		t.Fatal(err)
	}
	f.now.Add(2)
	request, _ := http.NewRequest("GET", p.Location(), nil)
	// A raw client sees the PS refusal, not just the Agent's independent check.
	original, _ := f.ps.FederatedAuthorization(context.Background(), deferredReference(p))
	if err := signaturekey.SignJWTRequest(request, f.agentKey, original.AgentToken, f.clock); err != nil {
		t.Fatal(err)
	}
	response, err := f.network.RoundTrip(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(response.Body)
	if response.StatusCode != 502 || strings.Contains(string(body), "auth_token") {
		t.Fatalf("expired grant delivered: %d %s", response.StatusCode, body)
	}
}

// A store cannot atomically commit an external HTTP exchange. Losing that
// commit must fence the uncertain poll rather than silently repeat it.
func TestFederatedDeferredStoreFailureWithholdsResultAndFencesRetry(t *testing.T) {
	f := newDeferredFederation(t)
	p := f.begin(t)
	id := deferredReference(p)
	f.psStore = failFederatedCompletion{f.psStore}
	f.recompose(t)
	f.stage.Store(2)
	if err := f.ps.AdvanceFederation(context.Background(), id); err == nil {
		t.Fatal("lost completion was ignored")
	}
	if err := f.ps.AdvanceFederation(context.Background(), id); !errors.Is(err, personserver.ErrFederationNotReady) {
		t.Fatalf("uncertain poll retried: %v", err)
	}
	result, err := f.client.PollExchange(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := result.Pending(); !ok {
		t.Fatal("uncommitted token was released")
	}
	if f.asPolls.Load() != 1 {
		t.Fatal("AS consequence repeated")
	}
	f.now.Add(60)
	_, err = f.client.PollExchange(context.Background(), p)
	requireDeferredProblem(t, err, 408, "expired")
}

type failFederatedCompletion struct {
	personserver.FederatedAuthorizationStore
}

func (s failFederatedCompletion) ReplaceFederatedAuthorization(ctx context.Context, before, after personserver.FederatedAuthorizationRecord) error {
	if before.Advancing && !after.Advancing {
		return errors.New("injected persistence failure")
	}
	return s.FederatedAuthorizationStore.ReplaceFederatedAuthorization(ctx, before, after)
}

func TestFederatedDeferredRetryStartsAtResponseReceipt(t *testing.T) {
	f := newDeferredFederation(t)
	p := f.begin(t)
	id := deferredReference(p)
	f.asMutation = func(r *http.Request, w *httptest.ResponseRecorder) {
		if r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/token/pending/") {
			f.now.Add(3)
			w.Header().Set("Retry-After", "7")
		}
	}
	if err := f.ps.AdvanceFederation(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	record, err := f.ps.FederatedAuthorization(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	if record.NextPollAt.Before(f.clock.Now().Add(7 * time.Second)) {
		t.Fatal("network time was deducted from Retry-After")
	}
}

func TestFederatedDeferredDefaultIntervalBackoffAndHTTPDate(t *testing.T) {
	for _, kind := range []string{"default-backoff", "http-date"} {
		t.Run(kind, func(t *testing.T) {
			f := newDeferredFederation(t)
			f.asMutation = func(r *http.Request, w *httptest.ResponseRecorder) {
				if r.Method == "POST" && r.URL.Path == "/token" {
					w.Header().Del("Retry-After")
				}
				if r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/token/pending/") {
					w.Code = 429
					w.Header().Del("Retry-After")
					if kind == "http-date" {
						w.Code = 503
						w.Header().Set("Retry-After", f.clock.Now().Add(12*time.Second).Format(http.TimeFormat))
					}
					w.Header().Set("Content-Type", "application/problem+json")
					w.Body.Reset()
					w.Body.WriteString(`{"error":"slow_down"}`)
				}
			}
			p := f.begin(t)
			id := deferredReference(p)
			f.now.Add(5)
			if err := f.ps.AdvanceFederation(context.Background(), id); err != nil {
				t.Fatal(err)
			}
			record, err := f.ps.FederatedAuthorization(context.Background(), id)
			if err != nil {
				t.Fatal(err)
			}
			seconds := 10
			if kind == "http-date" {
				seconds = 12
			}
			if record.Terminal || !record.NextPollAt.Equal(f.clock.Now().Add(time.Duration(seconds)*time.Second)) {
				t.Fatalf("next poll %s terminal %t", record.NextPollAt, record.Terminal)
			}
		})
	}
}

func TestFederatedDeferredASDeadlineAfterPolicy(t *testing.T) {
	for _, stage := range []int32{1, 2} {
		t.Run(fmt.Sprint(stage), func(t *testing.T) {
			f := newDeferredFederation(t)
			f.asLifetime.Store(10)
			f.recompose(t)
			p := f.begin(t)
			f.stage.Store(stage)
			f.policyDelay.Store(11)
			if err := f.ps.AdvanceFederation(context.Background(), deferredReference(p)); err != nil {
				t.Fatal(err)
			}
			_, err := f.client.PollExchange(context.Background(), p)
			requireDeferredProblem(t, err, 408, "expired")
		})
	}
}

type delayedDeliveryResolver struct {
	signaturekey.KeyResolver
	f     *deferredFederation
	armed bool
}

func (r *delayedDeliveryResolver) ResolveKey(ctx context.Context, issuer, dwk, kid string) (jose.JWK, error) {
	if r.armed && issuer == "https://as.example" {
		r.f.now.Add(11)
		r.armed = false
	}
	return r.KeyResolver.ResolveKey(ctx, issuer, dwk, kid)
}
func TestFederatedDeferredPSDeadlineAfterDeliveryVerification(t *testing.T) {
	f := newDeferredFederation(t)
	base, err := signaturekey.NewHTTPKeyResolver(signaturekey.HTTPKeyResolverConfig{Client: &http.Client{Transport: f.network}, Clock: f.clock, Admit: func(context.Context, string) error { return nil }})
	if err != nil {
		t.Fatal(err)
	}
	resolver := &delayedDeliveryResolver{KeyResolver: base, f: f}
	f.ps, err = personserver.NewFederatedAuthorization(personserver.FederatedAuthorizationConfig{
		Issuer: "https://ps.example", SigningKey: f.psKey, KeyResolver: resolver, Clock: f.clock, NewID: func() string { return "deadline-person-token" }, HTTPClient: &http.Client{Transport: f.network}, Tokens: testutil.NewMissionStore(),
		AccessServerEndpoint: func(context.Context, string) (string, error) { return "https://as.example/token", nil },
		BindPerson: func(context.Context, personserver.PersonTokenRequest) (personserver.Person, error) {
			return personserver.Person{Subject: "reader", Lifetime: 5 * time.Minute}, nil
		},
		Consent:  func(context.Context, personserver.AuthorizationRequest) error { return nil },
		Deferred: &personserver.FederatedDeferredConfig{Store: f.psStore, Lifetime: 10 * time.Second},
	})
	if err != nil {
		t.Fatal(err)
	}
	f.network.Handle("https://ps.example", f.ps.Handler())
	p := f.begin(t)
	f.stage.Store(2)
	if err = f.ps.AdvanceFederation(context.Background(), deferredReference(p)); err != nil {
		t.Fatal(err)
	}
	resolver.armed = true
	result, err := f.client.PollExchange(context.Background(), p)
	if _, ok := result.Token(); ok {
		t.Fatal("PS delivered grant after PS 10s pending deadline; release verification completed at 11s")
	}
	requireDeferredProblem(t, err, 408, "expired")
}

// Protocol 28e8258, Deferred Responses / Polling with GET: Agent polling
// follows Retry-After. A PS continuation reflects the retained AS schedule;
// once the AS poll is due it waits on the host, so it advertises one second.
func TestFederatedAgentRetryAfterTracksASSchedule(t *testing.T) {
	f := newDeferredFederation(t)
	f.retry.Store(7)
	pending := f.begin(t)
	if pending.RetryAfter() != 7*time.Second {
		t.Fatalf("initial Retry-After = %v", pending.RetryAfter())
	}
	for _, tc := range []struct {
		advance int64
		want    time.Duration
	}{{2, 5 * time.Second}, {5, time.Second}} {
		f.now.Add(tc.advance)
		result, err := f.client.PollExchange(context.Background(), pending)
		if err != nil {
			t.Fatal(err)
		}
		var ok bool
		pending, ok = result.Pending()
		if !ok || pending.RetryAfter() != tc.want {
			t.Fatalf("pending=%v Retry-After=%v, want %v", ok, pending.RetryAfter(), tc.want)
		}
	}
	f.asMutation = func(r *http.Request, w *httptest.ResponseRecorder) {
		if r.Method == http.MethodGet {
			w.Code = http.StatusServiceUnavailable
			w.Header().Set("Retry-After", "11")
			w.Body.Reset()
		}
	}
	if err := f.ps.AdvanceFederation(context.Background(), deferredReference(pending)); err != nil {
		t.Fatal(err)
	}
	result, err := f.client.PollExchange(context.Background(), pending)
	if err != nil {
		t.Fatal(err)
	}
	pending, ok := result.Pending()
	if !ok || pending.RetryAfter() != 11*time.Second {
		t.Fatalf("backoff Retry-After = %v", pending.RetryAfter())
	}
}

// The optional pending_reason extension is a display hint only. AS payment
// details stay with the PS; the Agent continues to use the PS pending URL.
func TestFederatedAgentWaitReasonPaymentThenApproval(t *testing.T) {
	f := newDeferredFederation(t)
	pending := f.begin(t)
	check := func(p agent.PendingExchange, want string) {
		t.Helper()
		if p.WaitReason() != want {
			t.Fatalf("wait reason = %q, want %q", p.WaitReason(), want)
		}
		if p.Requirement() != aauth.RequirementApproval || !strings.HasPrefix(p.Location(), "https://ps.example/") {
			t.Fatal("hint changed the polling contract")
		}
	}
	check(pending, "awaiting_payment")
	f.stage.Store(1)
	if err := f.ps.AdvanceFederation(context.Background(), deferredReference(pending)); err != nil {
		t.Fatal(err)
	}
	result, err := f.client.PollExchange(context.Background(), pending)
	if err != nil {
		t.Fatal(err)
	}
	pending, ok := result.Pending()
	if !ok {
		t.Fatal("missing approval continuation")
	}
	check(pending, "awaiting_approval")
}

// Protocol 28e8258, Auth Token Delivery, Auth Token Structure and Common JWT
// Claims: jti identifies the token, not the exchange. No grant claim binds it
// to a Resource-token ID or pending URL. Equivalent, still-valid grants can be
// delivered for distinct exchanges; single delivery applies to each PS record.
func TestFederatedEquivalentGrantHasNoCrossExchangeBinding(t *testing.T) {
	f := newDeferredFederation(t)
	ctx := context.Background()
	first := f.begin(t)
	firstRecord, err := f.ps.FederatedAuthorization(ctx, deferredReference(first))
	if err != nil {
		t.Fatal(err)
	}
	var grantBody []byte
	f.asMutation = func(r *http.Request, w *httptest.ResponseRecorder) {
		if r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/token/pending/") && w.Code == http.StatusOK {
			if grantBody == nil {
				grantBody = append([]byte(nil), w.Body.Bytes()...)
			} else {
				w.Body.Reset()
				_, _ = w.Body.Write(grantBody)
			}
		}
	}
	f.stage.Store(2)
	if err := f.ps.AdvanceFederation(ctx, firstRecord.ID); err != nil {
		t.Fatal(err)
	}
	result, err := f.client.PollExchange(ctx, first)
	if err != nil {
		t.Fatal(err)
	}
	firstToken, ok := result.Token()
	if !ok {
		t.Fatal("missing first grant")
	}
	f.stage.Store(0)
	second := f.begin(t)
	secondRecord, err := f.ps.FederatedAuthorization(ctx, deferredReference(second))
	if err != nil {
		t.Fatal(err)
	}
	if firstRecord.ID == secondRecord.ID || firstRecord.ResourceToken == secondRecord.ResourceToken || firstRecord.PresentedToken == secondRecord.PresentedToken {
		t.Fatal("fixture did not create a distinct exchange")
	}
	f.stage.Store(2)
	if err := f.ps.AdvanceFederation(ctx, secondRecord.ID); err != nil {
		t.Fatal(err)
	}
	result, err = f.client.PollExchange(ctx, second)
	if err != nil {
		t.Fatal(err)
	}
	secondToken, ok := result.Token()
	if !ok || secondToken != firstToken {
		t.Fatal("equivalent grant was not delivered unchanged")
	}
	for _, pending := range []agent.PendingExchange{first, second} {
		_, err := f.client.PollExchange(ctx, pending)
		var problem *aauth.ProblemError
		if !errors.As(err, &problem) || problem.Status != 410 {
			t.Fatalf("consumed continuation replay = %v", err)
		}
	}
}

func TestFederatedClaimsStayWithThePersonServer(t *testing.T) {
	f := newDeferredFederation(t)
	f.stage.Store(3)
	pending := f.begin(t)
	if pending.Requirement() != aauth.RequirementApproval {
		t.Fatalf("agent requirement = %q", pending.Requirement())
	}
	if strings.HasPrefix(pending.Location(), "https://as.example/") {
		t.Fatal("agent was sent to the access server")
	}
	reference := deferredReference(pending)
	record, err := f.ps.FederatedAuthorization(context.Background(), reference)
	if err != nil {
		t.Fatal(err)
	}
	if record.Response.Header.Get("AAuth-Requirement") != "requirement=claims" || !strings.Contains(string(record.Response.Body), `"email"`) {
		t.Fatalf("host claims challenge = %#v", record.Response)
	}
	if err := f.ps.SubmitFederatedClaims(context.Background(), reference, map[string]json.RawMessage{"sub": json.RawMessage(`"person"`), "email": json.RawMessage(`"a@example.com"`)}); err == nil {
		t.Fatal("claims response containing sub was accepted")
	}
	if err := f.ps.SubmitFederatedClaims(context.Background(), reference, map[string]json.RawMessage{"email": json.RawMessage(`"a@example.com"`)}); err != nil {
		t.Fatal(err)
	}
	result, err := f.client.PollExchange(context.Background(), pending)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := result.Token(); !ok {
		t.Fatal("claims delivery did not produce an auth token")
	}
}

func TestFederatedUnsupportedRequirementIsLocalRefusal(t *testing.T) {
	for _, requirement := range []string{"interaction", "clarification"} {
		for _, phase := range []string{"initial", "poll"} {
			t.Run(requirement+"/"+phase, func(t *testing.T) {
				f := newDeferredFederation(t)
				pending := f.begin(t)
				record, err := f.ps.FederatedAuthorization(context.Background(), deferredReference(pending))
				if err != nil {
					t.Fatal(err)
				}
				f.stage.Store(1)
				f.asMutation = func(r *http.Request, w *httptest.ResponseRecorder) {
					if r.URL.Path != "/token" && !strings.HasPrefix(r.URL.Path, "/token/pending/") {
						return
					}
					header := "requirement=" + requirement
					body := map[string]any{"status": "pending"}
					switch requirement {
					case "claims":
						body["required_claims"] = []string{"email"}
					case "clarification":
						body["clarification"], body["timeout"] = "Proceed?", 30
					case "interaction":
						header += `;url="https://as.example/interaction";code="ABCD"`
					}
					w.Header().Set("AAuth-Requirement", header)
					w.Body.Reset()
					if err := json.NewEncoder(w.Body).Encode(body); err != nil {
						t.Fatal(err)
					}
				}
				var cause error
				f.network.Handle("https://ps.example", diagnostics.Handler(f.ps.Handler(), func(_ context.Context, p diagnostics.Problem) { cause = p.Cause }))
				if phase == "initial" {
					_, err = f.client.BeginExchange(context.Background(), agent.ExchangeRequest{PersonServer: "https://ps.example", ResourceToken: record.ResourceToken, PresentedToken: record.PresentedToken})
				} else {
					if err := f.ps.AdvanceFederation(context.Background(), record.ID); err != nil {
						t.Fatal(err)
					}
					// Retention must survive serialization and server recomposition.
					f.psStore = &serializedFederatedStore{FederatedAuthorizationStore: f.psStore}
					f.recompose(t)
					f.network.Handle("https://ps.example", diagnostics.Handler(f.ps.Handler(), func(_ context.Context, p diagnostics.Problem) { cause = p.Cause }))
					_, err = f.client.PollExchange(context.Background(), pending)
				}
				requireDeferredProblem(t, err, 500, "server_error")
				var problem *aauth.ProblemError
				if !errors.As(err, &problem) || !strings.Contains(problem.Detail, requirement) {
					t.Fatalf("missing refusal reason: %v", err)
				}
				var refusal *personserver.DeferredCompositionError
				if !errors.As(cause, &refusal) || refusal.Reason() != requirement {
					t.Fatalf("local cause = %T %v", cause, cause)
				}
				if phase == "poll" {
					_, err = f.client.PollExchange(context.Background(), pending)
					requireDeferredProblem(t, err, 410, "request_consumed")
				}
				if f.protected.Load() != 0 {
					t.Fatal("unsupported requirement released authorization")
				}
			})
		}
	}
}

func TestFederatedPendingErrorsDistinguishUnknownAndConsumed(t *testing.T) {
	f := newDeferredFederation(t)
	pending := f.begin(t)
	record, err := f.ps.FederatedAuthorization(context.Background(), deferredReference(pending))
	if err != nil {
		t.Fatal(err)
	}
	for _, phase := range []string{"unknown", "consumed"} {
		want := "unknown_request"
		if phase == "consumed" {
			f.stage.Store(2)
			if err := f.ps.AdvanceFederation(context.Background(), record.ID); err != nil {
				t.Fatal(err)
			}
			if _, err := f.client.PollExchange(context.Background(), pending); err != nil {
				t.Fatal(err)
			}
			want = "request_consumed"
		}
		for _, role := range []string{"AS", "PS"} {
			location, key, token, ps := record.Location, f.psKey, "", "https://ps.example"
			if role == "PS" {
				location, key, token, ps = pending.Location(), f.agentKey, record.AgentToken, ""
			}
			if phase == "unknown" {
				location = location[:strings.LastIndex(location, "/")+1] + "unknown-reference"
			}
			response := deferredGET(t, f, location, key, token, ps)
			problem, err := aauth.DecodeProblemResponse(response)
			response.Body.Close()
			if err != nil || problem.Status != 410 || string(problem.Code) != want {
				t.Fatalf("%s %s = %v %v", role, phase, problem, err)
			}
		}
	}
}

// Two authenticated callers may reach AS policy before either replacement.
// The store winner alone publishes its result. A losing wait is a conflict,
// while a losing terminal delivery reports that the request was consumed.
func TestFederatedASConcurrentPollsPublishOneResult(t *testing.T) {
	for _, stage := range []int32{1, 2} {
		t.Run(fmt.Sprint(stage), func(t *testing.T) {
			f := newDeferredFederation(t)
			pending := f.begin(t)
			record, err := f.ps.FederatedAuthorization(context.Background(), deferredReference(pending))
			if err != nil {
				t.Fatal(err)
			}
			gate := &overlappingAccessStore{DeferredAuthorizationStore: f.asStore, arrived: make(chan struct{}, 2), release: make(chan struct{})}
			f.asStore = gate
			f.recompose(t)
			f.stage.Store(stage)
			results := make(chan *http.Response, 2)
			var wg sync.WaitGroup
			for range 2 {
				wg.Go(func() { results <- deferredGET(t, f, record.Location, f.psKey, "", "https://ps.example") })
			}
			for range 2 {
				select {
				case <-gate.arrived:
				case <-time.After(10 * time.Second):
					close(gate.release)
					wg.Wait()
					t.Fatal("AS polls did not overlap at publication")
				}
			}
			close(gate.release)
			wg.Wait()
			close(results)
			wins, losses := 0, 0
			for response := range results {
				wantStatus, loseStatus, loseCode := 202, 409, "request_conflict"
				if stage == 2 {
					wantStatus, loseStatus, loseCode = 200, 410, "request_consumed"
				}
				if response.StatusCode == wantStatus {
					wins++
				} else {
					problem, err := aauth.DecodeProblemResponse(response)
					if err != nil || problem.Status != loseStatus || string(problem.Code) != loseCode {
						t.Errorf("losing poll = %v %v", problem, err)
					}
					losses++
				}
				response.Body.Close()
			}
			if wins != 1 || losses != 1 {
				t.Fatalf("published %d results, %d refusals", wins, losses)
			}
		})
	}
}

type overlappingAccessStore struct {
	accessserver.DeferredAuthorizationStore
	arrived chan struct{}
	release chan struct{}
}

func (s *overlappingAccessStore) ReplaceAccessAuthorization(ctx context.Context, before, after accessserver.PendingAuthorizationRecord) error {
	s.arrived <- struct{}{}
	<-s.release
	return s.DeferredAuthorizationStore.ReplaceAccessAuthorization(ctx, before, after)
}

// A persistence adapter round trip must retain the bounded diagnostic reason,
// without serializing Go errors or relying on a live server's in-memory state.
type serializedFederatedStore struct {
	personserver.FederatedAuthorizationStore
}

func (s *serializedFederatedStore) LoadFederatedAuthorization(ctx context.Context, id string) (personserver.FederatedAuthorizationRecord, error) {
	r, err := s.FederatedAuthorizationStore.LoadFederatedAuthorization(ctx, id)
	if err != nil {
		return r, err
	}
	data, err := json.Marshal(r)
	if err != nil {
		return r, err
	}
	var loaded personserver.FederatedAuthorizationRecord
	err = json.Unmarshal(data, &loaded)
	return loaded, err
}

// Protocol 28e8258, Pending URL Security: after one terminal expiry response,
// every competing Agent poll receives Gone, including a losing store CAS.
func TestFederatedConcurrentExpiredAgentPollsConsumeOnce(t *testing.T) {
	f := newDeferredFederation(t)
	pending := f.begin(t)
	record, err := f.ps.FederatedAuthorization(context.Background(), deferredReference(pending))
	if err != nil {
		t.Fatal(err)
	}
	gate := &overlappingFederatedStore{FederatedAuthorizationStore: f.psStore, arrived: make(chan struct{}, 2), release: make(chan struct{})}
	f.psStore = gate
	f.recompose(t)
	f.now.Store(record.ExpiresAt.Unix())
	results := make(chan *http.Response, 2)
	var wg sync.WaitGroup
	for range 2 {
		wg.Go(func() { results <- deferredGET(t, f, pending.Location(), f.agentKey, record.AgentToken, "") })
	}
	for range 2 {
		select {
		case <-gate.arrived:
		case <-time.After(10 * time.Second):
			close(gate.release)
			wg.Wait()
			t.Fatal("Agent polls did not overlap at expiry consumption")
		}
	}
	close(gate.release)
	wg.Wait()
	close(results)
	counts := map[string]int{}
	for response := range results {
		problem, err := aauth.DecodeProblemResponse(response)
		response.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
		counts[fmt.Sprintf("%d %s", problem.Status, problem.Code)]++
	}
	if len(counts) != 2 || counts["408 expired"] != 1 || counts["410 request_consumed"] != 1 {
		t.Fatalf("concurrent expired polls = %v", counts)
	}
	if f.asPolls.Load() != 0 || f.protected.Load() != 0 {
		t.Fatal("expired polls advanced authorization")
	}
}

type overlappingFederatedStore struct {
	personserver.FederatedAuthorizationStore
	arrived chan struct{}
	release chan struct{}
}

func (s *overlappingFederatedStore) ReplaceFederatedAuthorization(ctx context.Context, before, after personserver.FederatedAuthorizationRecord) error {
	s.arrived <- struct{}{}
	<-s.release
	return s.FederatedAuthorizationStore.ReplaceFederatedAuthorization(ctx, before, after)
}

// Listing is an optional host capability. An adapter implementing only the
// original continuation transitions still completes a deferred exchange.
func TestFederatedStoreWithoutQueueStillDelivers(t *testing.T) {
	f := newDeferredFederation(t)
	f.psStore = &federatedStoreWithoutQueue{store: f.psStore}
	f.recompose(t)
	pending := f.begin(t)
	if refs, err := f.ps.PendingFederatedAuthorizationReferences(context.Background(), 1); err == nil || len(refs) != 0 || !strings.Contains(err.Error(), "does not support pending listing") {
		t.Fatalf("optional queue = %v %v", refs, err)
	}
	f.stage.Store(2)
	if err := f.ps.AdvanceFederation(context.Background(), deferredReference(pending)); err != nil {
		t.Fatal(err)
	}
	result, err := f.client.PollExchange(context.Background(), pending)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := result.Token(); !ok {
		t.Fatal("base store did not deliver authorization")
	}
}

type federatedStoreWithoutQueue struct {
	store personserver.FederatedAuthorizationStore
}

func (s *federatedStoreWithoutQueue) CreateFederatedAuthorization(ctx context.Context, r personserver.FederatedAuthorizationRecord) error {
	return s.store.CreateFederatedAuthorization(ctx, r)
}
func (s *federatedStoreWithoutQueue) LoadFederatedAuthorization(ctx context.Context, id string) (personserver.FederatedAuthorizationRecord, error) {
	return s.store.LoadFederatedAuthorization(ctx, id)
}
func (s *federatedStoreWithoutQueue) ReplaceFederatedAuthorization(ctx context.Context, before, after personserver.FederatedAuthorizationRecord) error {
	return s.store.ReplaceFederatedAuthorization(ctx, before, after)
}
