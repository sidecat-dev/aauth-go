package supervisionserver_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
	"gitlab.com/sidecat-dev/aauth-go/supervision"
	"gitlab.com/sidecat-dev/aauth-go/supervisionserver"
	"gitlab.com/sidecat-dev/aauth-go/testutil"
)

// AAuth Supervision (draft-hardt-aauth-supervision, pinned 70d6737). Each
// test drives the SS over HTTP with the Person Server's own client, so the
// wire contract is exercised end to end.

const (
	supervisor     = "https://ss.example"
	personServer   = "https://ps.example"
	otherServer    = "https://other.example"
	subject        = "8f14e45fceea167a5a36dedd4bea2543"
	agentID        = "aauth:assistant@agent.example"
	forwardedToken = "eyJhbGciOiJFZERTQSJ9.eyJzdWIiOiJhYXV0aDphc3Npc3RhbnRAYWdlbnQuZXhhbXBsZSJ9.c2lnbmF0dXJl"
)

var missionBlob = []byte(`{"agent":"aauth:assistant@agent.example","approver":"https://ps.example","description":"# Plan a trip"}`)

type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func (clock *testClock) Now() time.Time {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	return clock.now
}

func (clock *testClock) advance(by time.Duration) {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	clock.now = clock.now.Add(by)
}

type fixture struct {
	clock    *testClock
	store    supervisionserver.Store
	server   *supervisionserver.Server
	handler  http.Handler
	resolver signaturekey.StaticKeyResolver
	psKey    jose.SigningKey
	ps       *supervision.Client
	other    *supervision.Client

	mu        sync.Mutex
	connect   func(supervisionserver.ConnectRequest) supervisionserver.ConnectResult
	decide    func(supervisionserver.DecisionRequest) supervisionserver.DecisionResult
	observe   func(supervisionserver.Observation) error
	connects  int
	decisions []supervisionserver.DecisionRequest
	observed  []supervisionserver.Observation
}

func signingKey(t *testing.T, id string, seed byte) jose.SigningKey {
	t.Helper()
	key, err := jose.NewEd25519SigningKey(id, ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, ed25519.SeedSize)))
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func newFixture(t *testing.T, configure ...func(*supervisionserver.Config)) *fixture {
	t.Helper()
	f := &fixture{
		clock: &testClock{now: time.Unix(1790600000, 0).UTC()},
		store: testutil.NewSupervisorStore(),
		psKey: signingKey(t, "ps-key", 1),
		connect: func(supervisionserver.ConnectRequest) supervisionserver.ConnectResult {
			return supervisionserver.ConnectResult{Accept: true, Account: "account-1"}
		},
		decide: allow,
	}
	otherKey := signingKey(t, "other-key", 2)
	ssKey := signingKey(t, "ss-key", 3)
	f.resolver = signaturekey.StaticKeyResolver{
		{Issuer: personServer, DiscoveryDocument: aauth.PersonDiscoveryDocument, KeyID: f.psKey.ID()}: f.psKey.PublicJWK(),
		{Issuer: otherServer, DiscoveryDocument: aauth.PersonDiscoveryDocument, KeyID: otherKey.ID()}: otherKey.PublicJWK(),
		{Issuer: supervisor, DiscoveryDocument: supervision.DiscoveryDocument, KeyID: ssKey.ID()}:     ssKey.PublicJWK(),
	}
	config := supervisionserver.Config{
		Issuer: supervisor, Name: "Example Supervisor", SigningKey: &ssKey,
		KeyResolver: f.resolver, Clock: f.clock, Store: f.store,
		Connect: func(_ context.Context, request supervisionserver.ConnectRequest) (supervisionserver.ConnectResult, error) {
			f.mu.Lock()
			f.connects++
			policy := f.connect
			f.mu.Unlock()
			return policy(request), nil
		},
		Decide: func(_ context.Context, request supervisionserver.DecisionRequest) (supervisionserver.DecisionResult, error) {
			f.mu.Lock()
			f.decisions = append(f.decisions, request)
			policy := f.decide
			f.mu.Unlock()
			return policy(request), nil
		},
		Observe: func(_ context.Context, observation supervisionserver.Observation) error {
			f.mu.Lock()
			defer f.mu.Unlock()
			f.observed = append(f.observed, observation)
			if f.observe != nil {
				return f.observe(observation)
			}
			return nil
		},
	}
	for _, change := range configure {
		change(&config)
	}
	server, err := supervisionserver.New(config)
	if err != nil {
		t.Fatal(err)
	}
	f.server = server
	f.handler = server.Handler()
	httpClient := &http.Client{Transport: f}
	newClient := func(issuer string, key jose.SigningKey) *supervision.Client {
		client, err := supervision.NewClient(supervision.ClientConfig{
			PersonServer: issuer, SigningKey: key, KeyResolver: f.resolver, HTTPClient: httpClient,
			Admit: func(context.Context, string) error { return nil }, Clock: f.clock,
		})
		if err != nil {
			t.Fatal(err)
		}
		return client
	}
	f.ps = newClient(personServer, f.psKey)
	f.other = newClient(otherServer, otherKey)
	return f
}

func unsigned(config *supervisionserver.Config) { config.SigningKey = nil }

// RoundTrip routes the supervisor's origin to the server under test.
func (f *fixture) RoundTrip(request *http.Request) (*http.Response, error) {
	if request.URL.Scheme+"://"+request.URL.Host != supervisor {
		return nil, errors.New("no route to " + request.URL.Host)
	}
	recorder := httptest.NewRecorder()
	f.handler.ServeHTTP(recorder, request)
	response := recorder.Result()
	response.Request = request
	return response, nil
}

func (f *fixture) setDecide(policy func(supervisionserver.DecisionRequest) supervisionserver.DecisionResult) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.decide = policy
}

func (f *fixture) setConnect(policy func(supervisionserver.ConnectRequest) supervisionserver.ConnectResult) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.connect = policy
}

func (f *fixture) decisionRequests() []supervisionserver.DecisionRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]supervisionserver.DecisionRequest(nil), f.decisions...)
}

func (f *fixture) observations() []supervisionserver.Observation {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]supervisionserver.Observation(nil), f.observed...)
}

func allow(request supervisionserver.DecisionRequest) supervisionserver.DecisionResult {
	decision := supervision.Decision{Verdict: supervision.VerdictAllow}
	if request.Request.Kind == supervision.KindMissionProposal {
		decision.Mission = &supervision.MissionTerms{Description: request.Request.Description}
	}
	return supervisionserver.DecisionResult{Decision: &decision}
}

func decided(decision supervision.Decision) func(supervisionserver.DecisionRequest) supervisionserver.DecisionResult {
	return func(supervisionserver.DecisionRequest) supervisionserver.DecisionResult {
		copied := decision
		return supervisionserver.DecisionResult{Decision: &copied}
	}
}

func deferred(supervisionserver.DecisionRequest) supervisionserver.DecisionResult {
	return supervisionserver.DecisionResult{Defer: &supervisionserver.Deferral{Lifetime: 10 * time.Minute, RetryAfter: 2 * time.Second}}
}

func (f *fixture) request(kind supervision.Kind, sdi, missionS256 string) supervision.Request {
	request := supervision.Request{
		Kind: kind, SDI: sdi, IssuedAt: f.clock.Now().Unix(), Subject: subject, Agent: agentID, MissionS256: missionS256,
	}
	switch kind {
	case supervision.KindMissionProposal:
		request.AgentToken = forwardedToken
		request.Description = "# Plan a trip"
		request.Tools = []aauth.MissionTool{{Name: "WebSearch", Description: "Search the web"}}
		request.Resources = []string{"https://flights.example"}
	case supervision.KindMissionUpdate:
		request.Description = "Also book a hotel"
	case supervision.KindMissionCompletion:
		request.Summary = "The trip is booked."
	case supervision.KindPersonToken:
		request.AgentToken = forwardedToken
		request.Resource = "https://calendar.example"
	case supervision.KindAuthToken:
		request.AgentToken, request.ResourceToken, request.PresentedToken = forwardedToken, forwardedToken, forwardedToken
		request.Justification = "I need to read your calendar."
	case supervision.KindPermission:
		request.Action = "SendEmail"
		request.Description = "Send the itinerary"
		request.Parameters = json.RawMessage(`{"to":"user@example.com"}`)
	}
	return request
}

func (f *fixture) connectSubject(t *testing.T, client *supervision.Client, sub string) {
	t.Helper()
	outcome, err := client.Connect(context.Background(), supervisor, supervision.ConnectRequest{
		Action: supervision.ActionConnect, ID: "c-" + sub, IssuedAt: f.clock.Now().Unix(), Subject: sub,
	})
	if err != nil || !outcome.Connected {
		t.Fatalf("connect = %#v, %v", outcome, err)
	}
}

func (f *fixture) approve(t *testing.T, blob []byte) string {
	t.Helper()
	s256 := aauth.MissionS256(blob)
	outcome, err := f.ps.PostReport(context.Background(), supervisor, supervision.Report{
		Action: supervision.ReportApproved, ID: "e-approved-" + s256[:8], SDI: "d-proposal",
		IssuedAt: f.clock.Now().Unix(), Subject: subject, Agent: agentID, MissionS256: s256, Mission: blob,
	})
	if err != nil || !outcome.Accepted {
		t.Fatalf("approved report = %#v, %v", outcome, err)
	}
	return s256
}

func supervise(t *testing.T, client *supervision.Client, request supervision.Request) supervision.Outcome {
	t.Helper()
	outcome, err := client.Supervise(context.Background(), supervisor, request)
	if err != nil {
		t.Fatalf("supervise %s: %v", request.SDI, err)
	}
	return outcome
}

func requireProblem(t *testing.T, outcome supervision.Outcome, status int, code supervision.ErrorCode) {
	t.Helper()
	if outcome.Problem == nil || outcome.Problem.Status != status || outcome.Problem.Code != code {
		t.Fatalf("problem = %#v, want %d %s (outcome %#v)", outcome.Problem, status, code, outcome)
	}
}

func requireVerdict(t *testing.T, outcome supervision.Outcome, verdict supervision.Verdict) supervision.Decision {
	t.Helper()
	if outcome.Decision == nil || outcome.Decision.Verdict != verdict {
		t.Fatalf("decision = %#v, want %s (outcome %#v)", outcome.Decision, verdict, outcome)
	}
	return *outcome.Decision
}

func requireSameResponse(t *testing.T, first, second supervision.Outcome) {
	t.Helper()
	left, right := first.Exchange.Response, second.Exchange.Response
	if left == nil || right == nil || left.Status != right.Status || !bytes.Equal(left.Body, right.Body) {
		t.Fatalf("responses differ: %#v and %#v", left, right)
	}
	for _, name := range []string{"Content-Type", "Content-Digest", "Signature-Key", "Signature-Input", "Signature"} {
		if left.Header.Get(name) == "" || left.Header.Get(name) != right.Header.Get(name) {
			t.Fatalf("%s differs: %q and %q", name, left.Header.Get(name), right.Header.Get(name))
		}
	}
	// The decision names its key in keyid as Signature-Key does, as the
	// draft's example writes it.
	keyID := regexp.MustCompile(`kid="([^"]+)"`).FindStringSubmatch(left.Header.Get("Signature-Key"))
	if keyID == nil || !strings.Contains(left.Header.Get("Signature-Input"), `;keyid="`+keyID[1]+`"`) {
		t.Fatalf("signed decision Signature-Input = %q, want the Signature-Key kid as keyid", left.Header.Get("Signature-Input"))
	}
}

// raw sends one request signed as issuer with key; body nil sends none.
func (f *fixture) raw(t *testing.T, key jose.SigningKey, issuer, method, target string, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(method, target, bytes.NewReader(body))
	var err error
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
		err = signaturekey.SignJWKSURIRequestWithOptions(request, key, issuer, aauth.PersonDiscoveryDocument, f.clock,
			signaturekey.SignOptions{AdditionalComponents: []string{"content-type", "content-digest"}})
	} else {
		err = signaturekey.SignJWKSURIRequest(request, key, issuer, aauth.PersonDiscoveryDocument, f.clock)
	}
	if err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	f.handler.ServeHTTP(recorder, request)
	return recorder
}

func problemCode(t *testing.T, recorder *httptest.ResponseRecorder) string {
	t.Helper()
	var problem struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &problem); err != nil {
		t.Fatalf("problem body %q: %v", recorder.Body.String(), err)
	}
	return problem.Error
}

// Supervisor Metadata: endpoints on the issuer's origin, and jwks_uri only
// for an SS that signs.
func TestMetadataPublishesEndpointsAndKeysOnlyWhenSigning(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	metadata, err := f.ps.Metadata(context.Background(), supervisor)
	if err != nil {
		t.Fatal(err)
	}
	if metadata.Name != "Example Supervisor" || metadata.ConnectEndpoint != supervisor+"/connect" ||
		metadata.MissionEndpoint != supervisor+"/mission" || metadata.DecisionEndpoint != supervisor+"/decision" ||
		metadata.EventEndpoint != supervisor+"/event" || metadata.JWKSURI != supervisor+"/.well-known/jwks.json" {
		t.Fatalf("metadata = %#v", metadata)
	}
	keys := httptest.NewRecorder()
	f.handler.ServeHTTP(keys, httptest.NewRequest(http.MethodGet, metadata.JWKSURI, nil))
	if keys.Code != http.StatusOK || !strings.Contains(keys.Body.String(), `"kid":"ss-key"`) {
		t.Fatalf("jwks = %d %s", keys.Code, keys.Body.String())
	}

	plain := newFixture(t, unsigned)
	metadata, err = plain.ps.Metadata(context.Background(), supervisor)
	if err != nil || metadata.JWKSURI != "" || metadata.Signs() {
		t.Fatalf("unsigned metadata = %#v, %v", metadata, err)
	}
	keys = httptest.NewRecorder()
	plain.handler.ServeHTTP(keys, httptest.NewRequest(http.MethodGet, supervisor+"/.well-known/jwks.json", nil))
	if keys.Code != http.StatusNotFound {
		t.Fatalf("unsigned jwks = %d", keys.Code)
	}
	plain.connectSubject(t, plain.ps, subject)
	outcome := supervise(t, plain.ps, plain.request(supervision.KindPersonToken, "d-plain", ""))
	requireVerdict(t, outcome, supervision.VerdictAllow)
	if outcome.Exchange.Signed || outcome.Exchange.Response.Header.Get("Signature") != "" {
		t.Fatalf("an SS without a key signed: %#v", outcome.Exchange.Response.Header)
	}
}

// PS Authentication: a request whose signature does not verify as the
// Person Server's jwks_uri signature is 401 with Signature-Error, before any
// state is read.
func TestRequestsWithoutAValidPersonServerSignatureAreRefused(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	f.connectSubject(t, f.ps, subject)
	body, err := f.request(supervision.KindPersonToken, "d-signature", "").Encode()
	if err != nil {
		t.Fatal(err)
	}
	stranger := signingKey(t, "ps-key", 9)
	for _, test := range []struct {
		name    string
		request func() *http.Request
	}{
		{"missing signature", func() *http.Request {
			request := httptest.NewRequest(http.MethodPost, supervisor+"/decision", bytes.NewReader(body))
			request.Header.Set("Content-Type", "application/json")
			return request
		}},
		{"key the person server does not publish", func() *http.Request {
			request := httptest.NewRequest(http.MethodPost, supervisor+"/decision", bytes.NewReader(body))
			request.Header.Set("Content-Type", "application/json")
			if err := signaturekey.SignJWKSURIRequestWithOptions(request, stranger, personServer, aauth.PersonDiscoveryDocument, f.clock,
				signaturekey.SignOptions{AdditionalComponents: []string{"content-type", "content-digest"}}); err != nil {
				t.Fatal(err)
			}
			return request
		}},
		{"body changed after signing", func() *http.Request {
			request := httptest.NewRequest(http.MethodPost, supervisor+"/decision", bytes.NewReader(body))
			request.Header.Set("Content-Type", "application/json")
			if err := signaturekey.SignJWKSURIRequestWithOptions(request, f.psKey, personServer, aauth.PersonDiscoveryDocument, f.clock,
				signaturekey.SignOptions{AdditionalComponents: []string{"content-type", "content-digest"}}); err != nil {
				t.Fatal(err)
			}
			changed := bytes.Replace(body, []byte("calendar"), []byte("contacts"), 1)
			request.Body = io.NopCloser(bytes.NewReader(changed))
			request.ContentLength = int64(len(changed))
			return request
		}},
		{"not a person server document", func() *http.Request {
			request := httptest.NewRequest(http.MethodPost, supervisor+"/decision", bytes.NewReader(body))
			request.Header.Set("Content-Type", "application/json")
			if err := signaturekey.SignJWKSURIRequestWithOptions(request, f.psKey, personServer, "aauth-access.json", f.clock,
				signaturekey.SignOptions{AdditionalComponents: []string{"content-type", "content-digest"}}); err != nil {
				t.Fatal(err)
			}
			return request
		}},
		{"agent key scheme", func() *http.Request {
			request := httptest.NewRequest(http.MethodPost, supervisor+"/decision", bytes.NewReader(body))
			request.Header.Set("Content-Type", "application/json")
			if err := signaturekey.SignHWKRequest(request, f.psKey, f.clock); err != nil {
				t.Fatal(err)
			}
			return request
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			f.handler.ServeHTTP(recorder, test.request())
			if recorder.Code != http.StatusUnauthorized || recorder.Header().Get("Signature-Error") == "" {
				t.Fatalf("response = %d %v %s", recorder.Code, recorder.Header(), recorder.Body.String())
			}
		})
	}
	if requests := f.decisionRequests(); len(requests) != 0 {
		t.Fatalf("policy saw %d unauthenticated requests", len(requests))
	}
}

// PS Authentication and Connect: nothing is accepted for a sub the Person
// Server has not connected, and after disconnect the pair is unknown again.
func TestRequestsNeedAConnectedSubject(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	ctx := context.Background()
	requireProblem(t, supervise(t, f.ps, f.request(supervision.KindPersonToken, "d-early", "")), 404, supervision.ErrorUnknownSub)
	event := supervision.Event{
		Name: supervision.EventAgentBound, ID: "e-bound", IssuedAt: f.clock.Now().Unix(), Subject: subject, Agent: agentID,
		AgentIssuer: "https://agent.example", AgentSubject: agentID,
	}
	outcome, err := f.ps.PostEvent(ctx, supervisor, event)
	if err != nil {
		t.Fatal(err)
	}
	requireProblem(t, outcome, 404, supervision.ErrorUnknownSub)

	f.connectSubject(t, f.ps, subject)
	requireVerdict(t, supervise(t, f.ps, f.request(supervision.KindPersonToken, "d-early", "")), supervision.VerdictAllow)
	if requests := f.decisionRequests(); len(requests) != 1 || requests[0].Connection.Account != "account-1" ||
		requests[0].PersonServer != personServer {
		t.Fatalf("policy saw %#v", requests)
	}
	// A connected pair is answered without consulting the policy again.
	f.connectSubject(t, f.ps, subject)
	f.mu.Lock()
	connects := f.connects
	f.mu.Unlock()
	if connects != 1 {
		t.Fatalf("connect policy ran %d times", connects)
	}

	outcome, err = f.ps.Connect(ctx, supervisor, supervision.ConnectRequest{
		Action: supervision.ActionDisconnect, ID: "c-gone", IssuedAt: f.clock.Now().Unix(), Subject: subject,
	})
	if err != nil || !outcome.Connected {
		t.Fatalf("disconnect = %#v, %v", outcome, err)
	}
	requireProblem(t, supervise(t, f.ps, f.request(supervision.KindPermission, "d-late", "")), 404, supervision.ErrorUnknownSub)
}

// Connect, interaction required: the person confirms at the SS's page with
// the code, and the Person Server's polls answer 200 only then. Only the
// connecting Person Server may poll.
func TestConnectWaitsForThePersonToConfirm(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	ctx := context.Background()
	f.setConnect(func(request supervisionserver.ConnectRequest) supervisionserver.ConnectResult {
		if request.PersonServer != personServer || request.Subject != subject || request.Tenant != "acme.example" {
			t.Errorf("connect policy saw %#v", request)
		}
		return supervisionserver.ConnectResult{Interaction: &supervisionserver.ConnectInteraction{URL: supervisor + "/confirm"}}
	})
	connect := supervision.ConnectRequest{
		Action: supervision.ActionConnect, ID: "c-1", IssuedAt: f.clock.Now().Unix(), Subject: subject, Tenant: "acme.example",
	}
	first, err := f.ps.Connect(ctx, supervisor, connect)
	if err != nil || first.Interaction == nil {
		t.Fatalf("connect = %#v, %v", first, err)
	}
	interaction := *first.Interaction
	reference := strings.TrimPrefix(interaction.URL, supervisor+"/confirm/")
	if reference == interaction.URL || reference == "" || !strings.HasPrefix(interaction.Location, supervisor+"/connect/pending/") {
		t.Fatalf("interaction = %#v", interaction)
	}
	again, err := f.ps.Connect(ctx, supervisor, connect)
	if err != nil || again.Interaction == nil || *again.Interaction != interaction {
		t.Fatalf("repeated connect = %#v, %v", again, err)
	}
	polled, err := f.ps.PollConnect(ctx, supervisor, interaction.Location)
	if err != nil || polled.Interaction == nil || polled.Interaction.Code != interaction.Code {
		t.Fatalf("poll before the visit = %#v, %v", polled, err)
	}
	foreign, err := f.other.PollConnect(ctx, supervisor, interaction.Location)
	if err != nil {
		t.Fatal(err)
	}
	requireProblem(t, foreign, 404, supervision.ErrorUnknownPending)
	requireProblem(t, supervise(t, f.ps, f.request(supervision.KindPersonToken, "d-waiting", "")), 404, supervision.ErrorUnknownSub)

	if _, err := f.server.ConsumeConnectCode(ctx, reference, "0000-0000"); !errors.Is(err, supervisionserver.ErrInvalidCode) {
		t.Fatalf("wrong code = %v", err)
	}
	confirmation, err := f.server.ConsumeConnectCode(ctx, reference, strings.ToLower(interaction.Code))
	if err != nil {
		t.Fatal(err)
	}
	if confirmation.PersonServer != personServer || confirmation.Code != interaction.Code ||
		confirmation.Subject != subject || confirmation.Tenant != "acme.example" {
		t.Fatalf("confirmation = %#v", confirmation)
	}
	if _, err := f.server.ConsumeConnectCode(ctx, reference, interaction.Code); !errors.Is(err, supervisionserver.ErrInvalidCode) {
		t.Fatalf("consumed code = %v", err)
	}
	// While the person decides, polls repeat the interaction and report the
	// person interacting.
	polled, err = f.ps.PollConnect(ctx, supervisor, interaction.Location)
	if err != nil || polled.Interaction == nil || polled.Interaction.Location != interaction.Location || polled.Connected ||
		!strings.Contains(string(polled.Exchange.Response.Body), `"interacting"`) {
		t.Fatalf("poll while the person decides = %#v, %v", polled, err)
	}
	if err := f.server.ConfirmConnect(ctx, reference, "account-7"); err != nil {
		t.Fatal(err)
	}
	polled, err = f.ps.PollConnect(ctx, supervisor, interaction.Location)
	if err != nil || !polled.Connected {
		t.Fatalf("poll after confirmation = %#v, %v", polled, err)
	}
	requireVerdict(t, supervise(t, f.ps, f.request(supervision.KindPersonToken, "d-waiting", "")), supervision.VerdictAllow)
	if requests := f.decisionRequests(); len(requests) != 1 || requests[0].Connection.Account != "account-7" ||
		requests[0].Connection.Tenant != "acme.example" {
		t.Fatalf("policy saw %#v", requests)
	}
}

// Connect: a declined confirmation and a code guessed too often both end
// the interaction, and the Person Server's poll says so.
func TestConnectEndsWhenThePersonDeclinesOrTheCodeFails(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	ctx := context.Background()
	f.setConnect(func(supervisionserver.ConnectRequest) supervisionserver.ConnectResult {
		return supervisionserver.ConnectResult{Interaction: &supervisionserver.ConnectInteraction{URL: supervisor + "/confirm"}}
	})
	start := func(sub string) supervision.ConnectInteraction {
		t.Helper()
		outcome, err := f.ps.Connect(ctx, supervisor, supervision.ConnectRequest{
			Action: supervision.ActionConnect, ID: "c-" + sub, IssuedAt: f.clock.Now().Unix(), Subject: sub,
		})
		if err != nil || outcome.Interaction == nil {
			t.Fatalf("connect = %#v, %v", outcome, err)
		}
		return *outcome.Interaction
	}
	declined := start("declining")
	reference := strings.TrimPrefix(declined.URL, supervisor+"/confirm/")
	if _, err := f.server.ConsumeConnectCode(ctx, reference, declined.Code); err != nil {
		t.Fatal(err)
	}
	if err := f.server.DeclineConnect(ctx, reference); err != nil {
		t.Fatal(err)
	}
	if err := f.server.ConfirmConnect(ctx, reference, "late"); !errors.Is(err, supervisionserver.ErrConflict) {
		t.Fatalf("confirm after decline = %v", err)
	}
	outcome, err := f.ps.PollConnect(ctx, supervisor, declined.Location)
	if err != nil || outcome.Problem == nil || outcome.Problem.Status != http.StatusForbidden {
		t.Fatalf("poll after decline = %#v, %v", outcome, err)
	}

	guessed := start("guessed")
	reference = strings.TrimPrefix(guessed.URL, supervisor+"/confirm/")
	for attempt := 0; attempt < supervisionserver.MaximumConnectCodeAttempts; attempt++ {
		if _, err := f.server.ConsumeConnectCode(ctx, reference, "0000-0000"); !errors.Is(err, supervisionserver.ErrInvalidCode) {
			t.Fatalf("guess %d = %v", attempt, err)
		}
	}
	if _, err := f.server.ConsumeConnectCode(ctx, reference, guessed.Code); !errors.Is(err, supervisionserver.ErrInvalidCode) {
		t.Fatalf("right code after failure = %v", err)
	}
	outcome, err = f.ps.PollConnect(ctx, supervisor, guessed.Location)
	if err != nil || outcome.Problem == nil || outcome.Problem.Status != http.StatusGone {
		t.Fatalf("poll after failure = %#v, %v", outcome, err)
	}
}

// Connect refused, and a Person Server the host refuses entirely:
// unsupported_iss. A person the policy refused stays unknown_sub.
func TestRefusedPersonServers(t *testing.T) {
	t.Parallel()
	f := newFixture(t, func(config *supervisionserver.Config) {
		config.TrustPersonServer = func(_ context.Context, issuer string) error {
			if issuer == otherServer {
				return supervisionserver.ErrUnsupportedIss
			}
			return nil
		}
	})
	ctx := context.Background()
	outcome, err := f.other.Connect(ctx, supervisor, supervision.ConnectRequest{
		Action: supervision.ActionConnect, ID: "c-other", IssuedAt: f.clock.Now().Unix(), Subject: subject,
	})
	if err != nil {
		t.Fatal(err)
	}
	requireProblem(t, outcome, 403, supervision.ErrorUnsupportedIss)
	requireProblem(t, supervise(t, f.other, f.request(supervision.KindPermission, "d-other", "")), 403, supervision.ErrorUnsupportedIss)

	f.setConnect(func(supervisionserver.ConnectRequest) supervisionserver.ConnectResult {
		return supervisionserver.ConnectResult{}
	})
	outcome, err = f.ps.Connect(ctx, supervisor, supervision.ConnectRequest{
		Action: supervision.ActionConnect, ID: "c-refused", IssuedAt: f.clock.Now().Unix(), Subject: subject,
	})
	if err != nil {
		t.Fatal(err)
	}
	requireProblem(t, outcome, 403, supervision.ErrorUnsupportedIss)
	requireProblem(t, supervise(t, f.ps, f.request(supervision.KindPermission, "d-refused", "")), 404, supervision.ErrorUnknownSub)
}

// Errors: an SS that will not take more from a Person Server for now answers
// 429 rate_limited with its REQUIRED Retry-After, and handles nothing, so the
// Person Server can send the request again unchanged. A wait the draft cannot
// carry is a host defect, answered server_error.
func TestRateLimitAnswersRateLimitedWithRetryAfter(t *testing.T) {
	t.Parallel()
	var wait time.Duration
	var asked []string
	var mu sync.Mutex
	f := newFixture(t, func(config *supervisionserver.Config) {
		config.RateLimit = func(_ context.Context, issuer string) (time.Duration, error) {
			mu.Lock()
			defer mu.Unlock()
			asked = append(asked, issuer)
			return wait, nil
		}
	})
	setWait := func(value time.Duration) {
		mu.Lock()
		defer mu.Unlock()
		wait = value
	}
	f.connectSubject(t, f.ps, subject)

	setWait(30 * time.Second)
	request := f.request(supervision.KindPermission, "d-limited", "")
	limited := supervise(t, f.ps, request)
	requireProblem(t, limited, 429, supervision.ErrorRateLimited)
	if limited.Problem.RetryAfter != 30*time.Second || limited.Exchange.Response.Header.Get("Retry-After") != "30" {
		t.Fatalf("Retry-After = %v, header %q", limited.Problem.RetryAfter, limited.Exchange.Response.Header.Get("Retry-After"))
	}
	event := supervision.Event{
		Name: supervision.EventAgentBound, ID: "e-limited", IssuedAt: f.clock.Now().Unix(), Subject: subject, Agent: agentID,
		AgentIssuer: "https://agent.example", AgentSubject: agentID,
	}
	if outcome, err := f.ps.PostEvent(context.Background(), supervisor, event); err != nil {
		t.Fatal(err)
	} else {
		requireProblem(t, outcome, 429, supervision.ErrorRateLimited)
	}
	if len(f.decisionRequests()) != 0 || len(f.observations()) != 0 {
		t.Fatal("a rate-limited request reached host policy")
	}

	for _, invalid := range []time.Duration{-time.Second, 500 * time.Millisecond, 1500 * time.Millisecond, 2 * time.Hour} {
		setWait(invalid)
		requireProblem(t, supervise(t, f.ps, request), 500, supervision.ErrorServerError)
	}

	setWait(0)
	requireVerdict(t, supervise(t, f.ps, request), supervision.VerdictAllow)
	mu.Lock()
	defer mu.Unlock()
	for _, issuer := range asked {
		if issuer != personServer {
			t.Fatalf("RateLimit asked about %q", issuer)
		}
	}
}

// Mission and Decision Endpoints: an immediate allow, deny or ask on each
// act, signed, with the policy seeing the exact forwarded body.
func TestImmediateDecisionsOnEveryEndpoint(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	f.connectSubject(t, f.ps, subject)
	s256 := f.approve(t, missionBlob)
	expires := time.Unix(1790700000, 0).UTC()
	for _, test := range []struct {
		kind     supervision.Kind
		mission  string
		decision supervision.Decision
	}{
		{supervision.KindMissionProposal, "", supervision.Decision{
			Verdict: supervision.VerdictAllow,
			Mission: &supervision.MissionTerms{
				Description: "# Plan a trip\n\nDo not book non-refundable fares.", ExpiresAt: &expires,
				ApprovedTools: []aauth.MissionTool{{Name: "WebSearch", Description: "Search the web"}},
			},
		}},
		{supervision.KindMissionUpdate, s256, supervision.Decision{Verdict: supervision.VerdictDeny, Reason: "Hotels are out of scope."}},
		{supervision.KindMissionCompletion, s256, supervision.Decision{
			Verdict: supervision.VerdictAsk, Summary: "The agent reports the trip booked.", Recommendation: supervision.VerdictAllow,
		}},
		{supervision.KindPersonToken, s256, supervision.Decision{Verdict: supervision.VerdictAllow, ExpiresAt: 1790603600}},
		{supervision.KindAuthToken, "", supervision.Decision{Verdict: supervision.VerdictAllow, Scope: "calendar.read"}},
		{supervision.KindPermission, s256, supervision.Decision{
			Verdict: supervision.VerdictAsk, Summary: "Send an email?",
			ApplyOptions: []supervision.ApplyOption{{Value: "once", Label: "This email only"}},
		}},
	} {
		t.Run(string(test.kind), func(t *testing.T) {
			f.setDecide(decided(test.decision))
			request := f.request(test.kind, "d-"+string(test.kind), test.mission)
			outcome := supervise(t, f.ps, request)
			got := requireVerdict(t, outcome, test.decision.Verdict)
			if got.SDI != request.SDI || got.Reason != test.decision.Reason || got.Summary != test.decision.Summary ||
				got.Scope != test.decision.Scope || got.ExpiresAt != test.decision.ExpiresAt ||
				got.Recommendation != test.decision.Recommendation || len(got.ApplyOptions) != len(test.decision.ApplyOptions) {
				t.Fatalf("decision = %#v", got)
			}
			if test.decision.Mission != nil && (got.Mission == nil || got.Mission.Description != test.decision.Mission.Description ||
				got.Mission.ExpiresAt == nil || !got.Mission.ExpiresAt.Equal(expires) || len(got.Mission.ApprovedTools) != 1) {
				t.Fatalf("approved mission = %#v", got.Mission)
			}
			if !outcome.Exchange.Signed {
				t.Fatal("decision was not signed")
			}
			requests := f.decisionRequests()
			seen := requests[len(requests)-1]
			if seen.Request.Kind != test.kind || !bytes.Equal(seen.Body, outcome.Exchange.Request.Body) {
				t.Fatalf("policy saw %#v", seen)
			}
			if (test.mission != "") != (seen.Mission != nil) || (seen.Mission != nil && !bytes.Equal(seen.Mission.Blob, missionBlob)) {
				t.Fatalf("policy saw mission %#v", seen.Mission)
			}
		})
	}
}

// Deferred Decisions and Idempotence: a deferral answers 202 at once; a
// repeat while deciding gets the same Location; the host resolves; the
// decision is answered signed at the poll, and each request shape gets its
// own signed bytes, repeated exactly.
func TestDeferredDecisionResolvedByTheHost(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	ctx := context.Background()
	f.connectSubject(t, f.ps, subject)
	f.setDecide(deferred)
	request := f.request(supervision.KindAuthToken, "d-deferred", "")
	first := supervise(t, f.ps, request)
	if first.Pending == nil || first.Pending.Clarification != nil || first.Pending.RetryAfter != 2*time.Second ||
		!strings.HasPrefix(first.Pending.Location, supervisor+"/pending/") {
		t.Fatalf("deferral = %#v", first)
	}
	location := first.Pending.Location
	polled, err := f.ps.Poll(ctx, supervisor, request, location)
	if err != nil || polled.Pending == nil || polled.Pending.Location != location {
		t.Fatalf("poll while deciding = %#v, %v", polled, err)
	}
	again := supervise(t, f.ps, request)
	if again.Pending == nil || again.Pending.Location != location {
		t.Fatalf("repeat while deciding = %#v", again)
	}
	resumed, err := f.server.ResumeDecision(ctx, personServer, request.SDI)
	if err != nil || resumed.Request.Justification != request.Justification || resumed.Connection.Subject != subject {
		t.Fatalf("resumed = %#v, %v", resumed, err)
	}
	narrowed := supervision.Decision{Verdict: supervision.VerdictAllow, Scope: "calendar.read"}
	if err := f.server.ResolveDecision(ctx, personServer, request.SDI, supervisionserver.DecisionResult{Decision: &narrowed}); err != nil {
		t.Fatal(err)
	}
	if err := f.server.ResolveDecision(ctx, personServer, request.SDI, supervisionserver.DecisionResult{Decision: &narrowed}); err != nil {
		t.Fatalf("same resolution again = %v", err)
	}
	denied := supervision.Decision{Verdict: supervision.VerdictDeny}
	if err := f.server.ResolveDecision(ctx, personServer, request.SDI, supervisionserver.DecisionResult{Decision: &denied}); !errors.Is(err, supervisionserver.ErrConflict) {
		t.Fatalf("different resolution = %v", err)
	}

	f.clock.advance(3 * time.Second)
	polledDecision, err := f.ps.Poll(ctx, supervisor, request, location)
	if err != nil {
		t.Fatal(err)
	}
	if requireVerdict(t, polledDecision, supervision.VerdictAllow).Scope != "calendar.read" || !polledDecision.Exchange.Signed {
		t.Fatalf("polled decision = %#v", polledDecision)
	}
	f.clock.advance(3 * time.Second)
	repolled, err := f.ps.Poll(ctx, supervisor, request, location)
	if err != nil {
		t.Fatal(err)
	}
	requireSameResponse(t, polledDecision, repolled)

	// The first terminal answer went out on a poll; the original POST is now
	// signed once as a response to itself and repeated thereafter.
	f.clock.advance(3 * time.Second)
	posted := supervise(t, f.ps, request)
	requireVerdict(t, posted, supervision.VerdictAllow)
	if !bytes.Equal(posted.Exchange.Response.Body, polledDecision.Exchange.Response.Body) ||
		posted.Exchange.Response.Header.Get("Signature") == polledDecision.Exchange.Response.Header.Get("Signature") {
		t.Fatal("the POST did not get the same decision under its own signature")
	}
	f.clock.advance(3 * time.Second)
	requireSameResponse(t, posted, supervise(t, f.ps, request))
	if requests := f.decisionRequests(); len(requests) != 1 {
		t.Fatalf("policy ran %d times", len(requests))
	}
}

// Deferred Decisions: a poll from any identity other than the requester, or
// of a URL the SS does not hold, is unknown_pending.
func TestPendingURLsAnswerOnlyTheRequester(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	ctx := context.Background()
	f.connectSubject(t, f.ps, subject)
	f.connectSubject(t, f.other, subject)
	f.setDecide(deferred)
	request := f.request(supervision.KindPersonToken, "d-mine", "")
	location := supervise(t, f.ps, request).Pending.Location
	for name, send := range map[string]func() (supervision.Outcome, error){
		"poll": func() (supervision.Outcome, error) { return f.other.Poll(ctx, supervisor, request, location) },
		"answer": func() (supervision.Outcome, error) {
			return f.other.AnswerClarification(ctx, supervisor, request, location, supervision.ClarificationResponse{Answer: "yes"})
		},
		"cancel": func() (supervision.Outcome, error) { return f.other.Cancel(ctx, supervisor, location) },
		"unknown url": func() (supervision.Outcome, error) {
			return f.ps.Poll(ctx, supervisor, request, supervisor+"/pending/not-a-pending-url")
		},
	} {
		outcome, err := send()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		requireProblem(t, outcome, 404, supervision.ErrorUnknownPending)
	}
	if polled, err := f.ps.Poll(ctx, supervisor, request, location); err != nil || polled.Pending == nil {
		t.Fatalf("the requester's poll = %#v, %v", polled, err)
	}
}

// Clarification: the SS asks the Agent through the Person Server, decides on
// the relayed answer with the round recorded, and a cancelled request's
// pending URL is gone.
func TestClarificationRoundTripAndCancellation(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	ctx := context.Background()
	f.connectSubject(t, f.ps, subject)
	f.setDecide(func(request supervisionserver.DecisionRequest) supervisionserver.DecisionResult {
		if len(request.Rounds) == 0 {
			return supervisionserver.DecisionResult{Clarify: &supervision.Clarification{
				Question: "Is the fare refundable?", Timeout: 120 * time.Second, Options: []string{"yes", "no"},
			}}
		}
		return allow(request)
	})
	request := f.request(supervision.KindPermission, "d-clarify", "")
	asked := supervise(t, f.ps, request)
	if asked.Pending == nil || asked.Pending.Clarification == nil ||
		asked.Pending.Clarification.Question != "Is the fare refundable?" || asked.Pending.Clarification.Timeout != 120*time.Second {
		t.Fatalf("clarification = %#v", asked)
	}
	location := asked.Pending.Location
	repeated := supervise(t, f.ps, request)
	if repeated.Pending == nil || repeated.Pending.Location != location || repeated.Pending.Clarification == nil {
		t.Fatalf("repeat while clarifying = %#v", repeated)
	}
	answered, err := f.ps.AnswerClarification(ctx, supervisor, request, location, supervision.ClarificationResponse{Answer: "Yes, until 48 hours before departure."})
	if err != nil {
		t.Fatal(err)
	}
	requireVerdict(t, answered, supervision.VerdictAllow)
	requests := f.decisionRequests()
	if len(requests) != 2 || len(requests[1].Rounds) != 1 || requests[1].Rounds[0].Question.Question != "Is the fare refundable?" ||
		requests[1].Rounds[0].Answer != "Yes, until 48 hours before departure." || !bytes.Equal(requests[1].Body, requests[0].Body) {
		t.Fatalf("policy saw %#v", requests)
	}
	// A retried answer whose response was lost gets the same bytes.
	retried, err := f.ps.AnswerClarification(ctx, supervisor, request, location, supervision.ClarificationResponse{Answer: "Yes, until 48 hours before departure."})
	if err != nil {
		t.Fatal(err)
	}
	requireSameResponse(t, answered, retried)

	cancelled := f.request(supervision.KindPermission, "d-cancelled", "")
	location = supervise(t, f.ps, cancelled).Pending.Location
	withdrawn, err := f.ps.Cancel(ctx, supervisor, location)
	if err != nil || !withdrawn.Accepted || withdrawn.Exchange.Response.Status != http.StatusOK ||
		string(withdrawn.Exchange.Response.Body) != `{"status":"cancelled"}` {
		t.Fatalf("cancel = %#v, %v", withdrawn, err)
	}
	for name, send := range map[string]func() (supervision.Outcome, error){
		"poll": func() (supervision.Outcome, error) { return f.ps.Poll(ctx, supervisor, cancelled, location) },
		"answer": func() (supervision.Outcome, error) {
			return f.ps.AnswerClarification(ctx, supervisor, cancelled, location, supervision.ClarificationResponse{Answer: "no"})
		},
		"cancel": func() (supervision.Outcome, error) { return f.ps.Cancel(ctx, supervisor, location) },
	} {
		outcome, err := send()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if outcome.Exchange.Response.Status != http.StatusGone {
			t.Fatalf("%s after cancel = %#v", name, outcome)
		}
	}
	requireProblem(t, supervise(t, f.ps, cancelled), 400, supervision.ErrorInvalidRequest)
}

// Idempotence: a repeated request under an answered sdi gets the same
// signed response, byte for byte, without consulting the policy again. The
// same sdi naming a different request is refused.
func TestRepeatedRequestGetsTheSameSignedBytes(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	f.connectSubject(t, f.ps, subject)
	f.setDecide(decided(supervision.Decision{Verdict: supervision.VerdictAllow, ExpiresAt: 1790603600}))
	request := f.request(supervision.KindPersonToken, "d-repeat", "")
	first := supervise(t, f.ps, request)
	requireVerdict(t, first, supervision.VerdictAllow)
	f.clock.advance(10 * time.Second)
	second := supervise(t, f.ps, request)
	requireSameResponse(t, first, second)
	if !second.Exchange.Signed {
		t.Fatal("the repeat was not verified as signed")
	}
	if requests := f.decisionRequests(); len(requests) != 1 {
		t.Fatalf("policy ran %d times", len(requests))
	}
	changed := request
	changed.Resource = "https://contacts.example"
	requireProblem(t, supervise(t, f.ps, changed), 400, supervision.ErrorInvalidRequest)
	record, err := f.store.LoadDecision(context.Background(), personServer, request.SDI)
	if err != nil || len(record.Responses) != 1 || record.RetainUntil.Before(time.Unix(1790603600, 0)) {
		t.Fatalf("retained record = %#v, %v", record, err)
	}
}

// Replay and Recovery: a request naming a mission the SS holds no blob for is
// unknown_mission; after the approved report the same request is decided
// against the exact blob.
func TestUnknownMissionUntilTheApprovedReport(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	ctx := context.Background()
	f.connectSubject(t, f.ps, subject)
	s256 := aauth.MissionS256(missionBlob)
	update := f.request(supervision.KindMissionUpdate, "d-update", s256)
	requireProblem(t, supervise(t, f.ps, update), 404, supervision.ErrorUnknownMission)
	requireProblem(t, supervise(t, f.ps, f.request(supervision.KindPersonToken, "d-token", s256)), 404, supervision.ErrorUnknownMission)
	if requests := f.decisionRequests(); len(requests) != 0 {
		t.Fatalf("policy saw %d requests for an unknown mission", len(requests))
	}
	audit := supervision.Event{
		Name: supervision.EventAuditRecorded, ID: "e-audit", IssuedAt: f.clock.Now().Unix(),
		Subject: subject, Agent: agentID, MissionS256: s256, Action: "WebSearch",
	}
	outcome, err := f.ps.PostEvent(ctx, supervisor, audit)
	if err != nil {
		t.Fatal(err)
	}
	requireProblem(t, outcome, 404, supervision.ErrorUnknownMission)

	f.approve(t, missionBlob)
	if outcome, err := f.ps.PostEvent(ctx, supervisor, audit); err != nil || !outcome.Accepted {
		t.Fatalf("event after the approved report = %#v, %v", outcome, err)
	}
	requireVerdict(t, supervise(t, f.ps, update), supervision.VerdictAllow)
	requests := f.decisionRequests()
	if len(requests) != 1 || requests[0].Mission == nil || !bytes.Equal(requests[0].Mission.Blob, missionBlob) ||
		requests[0].Mission.S256 != s256 || requests[0].Mission.SDI != "d-proposal" {
		t.Fatalf("policy saw %#v", requests)
	}

	terminated, err := f.ps.PostReport(ctx, supervisor, supervision.Report{
		Action: supervision.ReportTerminated, ID: "e-terminated", IssuedAt: f.clock.Now().Unix(),
		Subject: subject, Agent: agentID, MissionS256: s256, Reason: "completed",
	})
	if err != nil || !terminated.Accepted {
		t.Fatalf("terminated report = %#v, %v", terminated, err)
	}
	mission, err := f.store.LoadMission(ctx, personServer, subject, s256)
	if err != nil || !mission.Terminated || mission.Reason != "completed" {
		t.Fatalf("mission = %#v, %v", mission, err)
	}

	missing := f.raw(t, f.psKey, personServer, http.MethodPost, supervisor+"/mission/"+s256, []byte(
		`{"id":"e-x","iat":1790600000,"sub":"`+subject+`","agent":"`+agentID+`"}`))
	if missing.Code != http.StatusBadRequest || problemCode(t, missing) != string(supervision.ErrorInvalidRequest) {
		t.Fatalf("missing action = %d %s", missing.Code, missing.Body.String())
	}
}

// Event Endpoint and Delivery: events are recorded and acknowledged with 201
// and no body, once per (iss, id); the observer sees decision.resolved with
// its reach, and a delivery it fails is delivered again.
func TestEventsAreRecordedOncePerID(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	ctx := context.Background()
	f.connectSubject(t, f.ps, subject)
	resolved := supervision.Event{
		Name: supervision.EventDecisionResolved, ID: "e-resolved", SDI: "d-ask", IssuedAt: f.clock.Now().Unix(),
		Subject: subject, Agent: agentID, Answer: supervision.AnswerAllow, Apply: "mission",
		Recommendation: supervision.VerdictDeny,
	}
	for attempt := 0; attempt < 2; attempt++ {
		outcome, err := f.ps.PostEvent(ctx, supervisor, resolved)
		if err != nil || !outcome.Accepted || outcome.Exchange.Response.Status != http.StatusCreated ||
			len(outcome.Exchange.Response.Body) != 0 {
			t.Fatalf("event delivery %d = %#v, %v", attempt, outcome, err)
		}
	}
	observed := f.observations()
	if len(observed) != 1 || observed[0].Event == nil || observed[0].Event.Apply != "mission" ||
		observed[0].Event.Answer != supervision.AnswerAllow || observed[0].Connection.PersonServer != personServer {
		t.Fatalf("observed %#v", observed)
	}

	f.mu.Lock()
	failures := 1
	f.observe = func(supervisionserver.Observation) error {
		if failures > 0 {
			failures--
			return errors.New("observer unavailable")
		}
		return nil
	}
	f.mu.Unlock()
	issued := supervision.Event{
		Name: supervision.EventPersonTokenIssued, ID: "e-issued", SDI: "d-ask", IssuedAt: f.clock.Now().Unix(),
		Subject: subject, Agent: agentID, JTI: "jti-1", Audience: "https://calendar.example", ExpiresAt: 1790603600,
	}
	outcome, err := f.ps.PostEvent(ctx, supervisor, issued)
	if err != nil {
		t.Fatal(err)
	}
	requireProblem(t, outcome, 500, supervision.ErrorServerError)
	for attempt := 0; attempt < 2; attempt++ {
		if outcome, err := f.ps.PostEvent(ctx, supervisor, issued); err != nil || !outcome.Accepted {
			t.Fatalf("redelivery %d = %#v, %v", attempt, outcome, err)
		}
	}
	if observed := f.observations(); len(observed) != 3 {
		t.Fatalf("observer saw %d deliveries, want the failed one, its redelivery, and nothing for the repeat", len(observed))
	}
	unknown := f.raw(t, f.psKey, personServer, http.MethodPost, supervisor+"/event", []byte(
		`{"event":"mission.renamed","id":"e-y","iat":1790600000,"sub":"`+subject+`","agent":"`+agentID+`"}`))
	if unknown.Code != http.StatusBadRequest || problemCode(t, unknown) != string(supervision.ErrorInvalidRequest) {
		t.Fatalf("unknown event = %d %s", unknown.Code, unknown.Body.String())
	}
}

// Signed Decisions: the recorded exchange verifies later, by a reader who
// was not on the connection, from the record alone.
func TestSignedDecisionVerifiesLaterFromTheRecord(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	f.connectSubject(t, f.ps, subject)
	f.setDecide(decided(supervision.Decision{Verdict: supervision.VerdictDeny, Reason: "Not on this mission."}))
	outcome := supervise(t, f.ps, f.request(supervision.KindPermission, "d-audit", ""))
	requireVerdict(t, outcome, supervision.VerdictDeny)
	record := outcome.Exchange.Clone()
	f.clock.advance(30 * 24 * time.Hour)

	verified, err := supervision.VerifyExchange(context.Background(), record, f.resolver)
	if err != nil {
		t.Fatal(err)
	}
	if verified.Signer() != supervisor {
		t.Fatalf("signer = %q", verified.Signer())
	}
	covered := strings.Join(verified.CoveredComponents(), " ")
	for _, component := range []string{"@status", "content-type", "content-digest", "content-digest;req", "@authority;req", "@path;req"} {
		if !strings.Contains(" "+covered+" ", " "+component+" ") {
			t.Fatalf("signature covers %q, missing %s", covered, component)
		}
	}

	tampered := record.Clone()
	tampered.Response.Body = bytes.Replace(tampered.Response.Body, []byte("deny"), []byte("allow"), 1)
	if _, err := supervision.VerifyExchange(context.Background(), tampered, f.resolver); err == nil {
		t.Fatal("a changed decision verified")
	}
	misattributed := record.Clone()
	misattributed.Supervisor = otherServer
	if _, err := supervision.VerifyExchange(context.Background(), misattributed, f.resolver); err == nil {
		t.Fatal("a decision verified as another supervisor's")
	}
	rebound := record.Clone()
	rebound.Request.URL = supervisor + "/mission"
	if _, err := supervision.VerifyExchange(context.Background(), rebound, f.resolver); err == nil {
		t.Fatal("a decision verified against another request")
	}
}

// Idempotence under concurrency: polls racing to the first terminal answer
// all receive the one signed response the store retained.
func TestConcurrentPollsShareOneSignedResponse(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	ctx := context.Background()
	f.connectSubject(t, f.ps, subject)
	f.setDecide(deferred)
	request := f.request(supervision.KindPersonToken, "d-race", "")
	location := supervise(t, f.ps, request).Pending.Location
	allowed := supervision.Decision{Verdict: supervision.VerdictAllow}
	if err := f.server.ResolveDecision(ctx, personServer, request.SDI, supervisionserver.DecisionResult{Decision: &allowed}); err != nil {
		t.Fatal(err)
	}
	outcomes := make([]supervision.Outcome, 8)
	var group sync.WaitGroup
	for index := range outcomes {
		group.Add(1)
		go func() {
			defer group.Done()
			outcome, err := f.ps.Poll(ctx, supervisor, request, location)
			if err != nil {
				t.Error(err)
			}
			outcomes[index] = outcome
		}()
		f.clock.advance(time.Second)
	}
	group.Wait()
	for _, outcome := range outcomes[1:] {
		requireSameResponse(t, outcomes[0], outcome)
	}
	record, err := f.store.LoadDecision(ctx, personServer, request.SDI)
	if err != nil || len(record.Responses) != 1 {
		t.Fatalf("retained %d responses, %v", len(record.Responses), err)
	}
}

// Clarification: a Person Server may relay an Agent's updated auth-token
// request; the policy decides again on the replacement tokens.
func TestUpdatedRequestReplacesTheTokensThePolicySees(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	f.connectSubject(t, f.ps, subject)
	f.setDecide(func(request supervisionserver.DecisionRequest) supervisionserver.DecisionResult {
		if len(request.Rounds) == 0 {
			return supervisionserver.DecisionResult{Clarify: &supervision.Clarification{Question: "Can you ask for less?"}}
		}
		return allow(request)
	})
	request := f.request(supervision.KindAuthToken, "d-update-request", "")
	asked := supervise(t, f.ps, request)
	if asked.Pending == nil || asked.Pending.Clarification == nil {
		t.Fatalf("clarification = %#v", asked)
	}
	replacement := "eyJhbGciOiJFZERTQSJ9.eyJzY29wZSI6ImNhbGVuZGFyLnJlYWQifQ.bmFycm93ZXI"
	body, err := supervision.ClarificationResponse{Updated: &supervision.UpdatedRequest{
		ResourceToken: replacement, PresentedToken: forwardedToken, Justification: "Read only.",
	}}.Encode()
	if err != nil {
		t.Fatal(err)
	}
	answered := f.raw(t, f.psKey, personServer, http.MethodPost, asked.Pending.Location, body)
	if answered.Code != http.StatusOK {
		t.Fatalf("updated request = %d %s", answered.Code, answered.Body.String())
	}
	requests := f.decisionRequests()
	last := requests[len(requests)-1]
	if last.Request.ResourceToken != replacement || last.Request.Justification != "Read only." ||
		len(last.Rounds) != 1 || last.Rounds[0].Updated == nil {
		t.Fatalf("policy saw %#v", last)
	}
	permission := f.request(supervision.KindPermission, "d-permission-update", "")
	location := supervise(t, f.ps, permission).Pending.Location
	if refused := f.raw(t, f.psKey, personServer, http.MethodPost, location, body); refused.Code != http.StatusBadRequest {
		t.Fatalf("an updated permission request = %d", refused.Code)
	}
}
