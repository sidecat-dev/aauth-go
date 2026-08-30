package personserver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	aauth "aauth-go"
	"aauth-go/jose"
	"aauth-go/signaturekey"
)

func TestDeferredPersonTokenInteractionApprovesOnceAcrossServerRecomposition(t *testing.T) {
	t.Parallel()

	protocol := newPersonInteractionProtocol(t)
	store := newMemoryDeferredTokenStore()
	server := protocol.newServer(t, store, true)

	initial := protocol.personTokenRequest(t)
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, initial)
	if response.Code != http.StatusAccepted {
		t.Fatalf("initial status = %d, headers = %v, body = %s", response.Code, response.Header(), response.Body.String())
	}
	if response.Header().Get("Cache-Control") != "no-store" || response.Header().Get("Retry-After") != "3" {
		t.Fatalf("initial headers = %v", response.Header())
	}
	requirement, err := aauth.ParseInteractionRequirement(response.Header().Values("AAuth-Requirement"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(requirement.URL, "https://person.example/interaction/") {
		t.Fatalf("interaction requirement = %#v", requirement)
	}
	location := response.Header().Get("Location")
	if !strings.HasPrefix(location, "/person/pending/") {
		t.Fatalf("Location = %q", location)
	}
	pendingID, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(location, "/person/pending/"))
	if err != nil || len(pendingID) != 16 {
		t.Fatalf("pending identifier = %q, bytes = %d, error = %v", location, len(pendingID), err)
	}
	if requirement.URL != "https://person.example/interaction/"+strings.TrimPrefix(location, "/person/pending/") {
		t.Fatalf("interaction URL %q does not identify pending Location %q", requirement.URL, location)
	}
	if got := response.Body.String(); got != "{\"status\":\"pending\"}\n" {
		t.Fatalf("initial body = %q", got)
	}
	if store.tokenCommitCount() != 0 || protocol.bindCalls != 0 {
		t.Fatalf("before approval: token commits = %d, BindPerson calls = %d", store.tokenCommitCount(), protocol.bindCalls)
	}
	pending := store.onlyPending(t)
	if pending.PersonServer != protocol.personServerID || pending.Agent != protocol.agentID || pending.Resource != protocol.resourceID ||
		pending.CodeSHA256 == ([32]byte{}) || pending.Confirmation.Equal(jose.JWK{}) ||
		!pending.Confirmation.Equal(protocol.agentKey.PublicJWK()) ||
		pending.AgentAdditionalClaims == nil {
		t.Fatalf("pending record = %#v", pending)
	}

	poll := protocol.pollRequest(t, location, protocol.agentKey, protocol.agentToken)
	pollResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(pollResponse, poll)
	if pollResponse.Code != http.StatusAccepted || pollResponse.Body.String() != "{\"status\":\"pending\"}\n" {
		t.Fatalf("pending poll = %d %s", pollResponse.Code, pollResponse.Body.String())
	}

	reference := personInteractionReference(t, requirement.URL)
	interaction, err := server.ConsumePersonTokenInteractionCode(context.Background(), reference, strings.ToLower(strings.ReplaceAll(requirement.Code, "-", "")))
	if err != nil {
		t.Fatal(err)
	}
	if interaction.Agent() != protocol.agentID || interaction.Resource() != protocol.resourceID ||
		!interaction.ExpiresAt().Equal(protocol.now.Add(5*time.Minute)) ||
		string(interaction.AgentAdditionalClaims()["platform_attestation"]) != `{"level":"example"}` {
		t.Fatalf("interaction = %#v", interaction)
	}
	if _, err := server.ConsumePersonTokenInteractionCode(context.Background(), reference, requirement.Code); !errors.Is(err, ErrInteractionCodeUsed) {
		t.Fatalf("second code use error = %v", err)
	}

	poll = protocol.pollRequest(t, location, protocol.agentKey, protocol.agentToken)
	pollResponse = httptest.NewRecorder()
	server.Handler().ServeHTTP(pollResponse, poll)
	if pollResponse.Code != http.StatusAccepted || pollResponse.Body.String() != "{\"status\":\"interacting\"}\n" {
		t.Fatalf("interacting poll = %d %s", pollResponse.Code, pollResponse.Body.String())
	}

	if err := server.ApprovePersonTokenInteraction(context.Background(), interaction, Person{
		Subject: "person-123", Tenant: "tenant-1", Lifetime: 20 * time.Minute,
	}); err != nil {
		t.Fatal(err)
	}
	protocol.now = protocol.now.Add(time.Second)
	if err := server.ApprovePersonTokenInteraction(context.Background(), interaction, Person{
		Subject: "person-123", Tenant: "tenant-1", Lifetime: 20 * time.Minute,
	}); err != nil {
		t.Fatalf("same approval retry = %v", err)
	}
	if store.tokenCommitCount() != 1 {
		t.Fatalf("token commits after approval = %d", store.tokenCommitCount())
	}

	recomposed := protocol.newServer(t, store, true)
	head := httptest.NewRequest(http.MethodHead, protocol.personServerID+location, nil)
	if err := signaturekey.SignJWTRequest(head, protocol.agentKey, protocol.agentToken, protocol.clock); err != nil {
		t.Fatal(err)
	}
	headResponse := httptest.NewRecorder()
	recomposed.Handler().ServeHTTP(headResponse, head)
	if headResponse.Code != http.StatusMethodNotAllowed || headResponse.Header().Get("Allow") != http.MethodGet {
		t.Fatalf("HEAD poll = %d Allow %q", headResponse.Code, headResponse.Header().Get("Allow"))
	}
	poll = protocol.pollRequest(t, location, protocol.agentKey, protocol.agentToken)
	pollResponse = httptest.NewRecorder()
	recomposed.Handler().ServeHTTP(pollResponse, poll)
	if pollResponse.Code != http.StatusOK || pollResponse.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("approved poll = %d %v %s", pollResponse.Code, pollResponse.Header(), pollResponse.Body.String())
	}
	var output struct {
		PersonToken string `json:"person_token"`
		ExpiresIn   int64  `json:"expires_in"`
	}
	if err := json.NewDecoder(pollResponse.Body).Decode(&output); err != nil {
		t.Fatal(err)
	}
	claims, err := aauth.VerifyPersonToken(context.Background(), output.PersonToken, protocol.resolver, protocol.clock)
	if err != nil {
		t.Fatal(err)
	}
	if claims.Subject != "person-123" || claims.Audience != protocol.resourceID ||
		claims.Issuer != protocol.personServerID || claims.Tenant != "tenant-1" ||
		!claims.Confirmation.JWK.Equal(protocol.agentKey.PublicJWK()) || output.ExpiresIn != int64((20*time.Minute)/time.Second) {
		t.Fatalf("approved person token = %#v, expires_in = %d", claims, output.ExpiresIn)
	}
	if _, err := store.Load(context.Background(), claims.Issuer, claims.JTI); err != nil {
		t.Fatalf("retained person-token record: %v", err)
	}

	poll = protocol.pollRequest(t, location, protocol.agentKey, protocol.agentToken)
	pollResponse = httptest.NewRecorder()
	recomposed.Handler().ServeHTTP(pollResponse, poll)
	assertPersonInteractionProblem(t, pollResponse, http.StatusGone, "invalid_code")
	protocol.now = protocol.now.Add(10 * time.Minute)
	if _, err := recomposed.ConsumePersonTokenInteractionCode(context.Background(), reference, requirement.Code); !errors.Is(err, ErrInteractionCodeUsed) {
		t.Fatalf("terminal code replay error = %v", err)
	}
}

func TestDeferredPersonTokenInteractionCodeIsBoundToURLReference(t *testing.T) {
	t.Parallel()

	protocol := newPersonInteractionProtocol(t)
	store := newMemoryDeferredTokenStore()
	server := protocol.newServer(t, store, true)
	issue := func() (string, string) {
		t.Helper()
		response := httptest.NewRecorder()
		server.Handler().ServeHTTP(response, protocol.personTokenRequest(t))
		if response.Code != http.StatusAccepted {
			t.Fatalf("initial status = %d, body = %s", response.Code, response.Body.String())
		}
		requirement, err := aauth.ParseInteractionRequirement(response.Header().Values("AAuth-Requirement"))
		if err != nil {
			t.Fatal(err)
		}
		reference := strings.TrimPrefix(requirement.URL, "https://person.example/interaction/")
		if reference == requirement.URL || reference == "" {
			t.Fatalf("interaction URL = %q", requirement.URL)
		}
		return reference, requirement.Code
	}

	referenceA, codeA := issue()
	referenceB, codeB := issue()
	if _, err := server.ConsumePersonTokenInteractionCode(context.Background(), referenceA, codeB); !errors.Is(err, ErrInteractionCodeInvalid) {
		t.Fatalf("reference A with code B error = %v", err)
	}
	for _, reference := range []string{referenceA, referenceB} {
		snapshot, err := store.LoadPendingPersonToken(context.Background(), reference)
		if err != nil {
			t.Fatal(err)
		}
		if snapshot.State != PersonTokenPollWaiting {
			t.Fatalf("pending %q state after mismatched code = %v", reference, snapshot.State)
		}
	}
	if interaction, err := server.ConsumePersonTokenInteractionCode(context.Background(), referenceB, codeB); err != nil || interaction.Reference() != referenceB {
		t.Fatalf("reference B with code B = %#v, %v", interaction, err)
	}
	if interaction, err := server.ConsumePersonTokenInteractionCode(context.Background(), referenceA, codeA); err != nil || interaction.Reference() != referenceA {
		t.Fatalf("reference A with code A = %#v, %v", interaction, err)
	}
}

func TestDeferredPersonTokenApprovalFailureDoesNotExposePartialState(t *testing.T) {
	t.Parallel()

	protocol := newPersonInteractionProtocol(t)
	store := newMemoryDeferredTokenStore()
	server := protocol.newServer(t, store, true)
	initial := httptest.NewRecorder()
	server.Handler().ServeHTTP(initial, protocol.personTokenRequest(t))
	requirement, err := aauth.ParseInteractionRequirement(initial.Header().Values("AAuth-Requirement"))
	if err != nil {
		t.Fatal(err)
	}
	interaction, err := server.ConsumePersonTokenInteractionCode(context.Background(), personInteractionReference(t, requirement.URL), requirement.Code)
	if err != nil {
		t.Fatal(err)
	}
	store.approveErr = errors.New("transaction unavailable")
	person := Person{Subject: "person-123", Lifetime: time.Minute}
	if err := server.ApprovePersonTokenInteraction(context.Background(), interaction, person); !errors.Is(err, store.approveErr) {
		t.Fatalf("approval error = %v", err)
	}
	if store.tokenCommitCount() != 0 {
		t.Fatalf("failed approval exposed %d person-token records", store.tokenCommitCount())
	}
	store.approveErr = nil
	if err := server.ApprovePersonTokenInteraction(context.Background(), interaction, person); err != nil {
		t.Fatal(err)
	}
	poll := httptest.NewRecorder()
	server.Handler().ServeHTTP(poll, protocol.pollRequest(t, initial.Header().Get("Location"), protocol.agentKey, protocol.agentToken))
	if poll.Code != http.StatusOK {
		t.Fatalf("recovered approval poll = %d %s", poll.Code, poll.Body.String())
	}
}

func TestDeferredPersonTokenCreationFailureReturnsNoPendingHandle(t *testing.T) {
	t.Parallel()

	protocol := newPersonInteractionProtocol(t)
	store := newMemoryDeferredTokenStore()
	store.createErr = errors.New("pending store unavailable")
	server := protocol.newServer(t, store, true)
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, protocol.personTokenRequest(t))
	assertPersonInteractionProblem(t, response, http.StatusInternalServerError, "server_error")
	if response.Header().Get("Location") != "" || response.Header().Get("AAuth-Requirement") != "" ||
		store.pendingCount() != 0 || store.tokenCommitCount() != 0 {
		t.Fatalf("failed creation exposed state: headers=%v pending=%d tokens=%d",
			response.Header(), store.pendingCount(), store.tokenCommitCount())
	}
}

func TestDeferredPersonTokenRefusesPolicyThatOutlivesAgentToken(t *testing.T) {
	t.Parallel()

	protocol := newPersonInteractionProtocol(t)
	protocol.policyDelay = 2 * time.Hour
	store := newMemoryDeferredTokenStore()
	server := protocol.newServer(t, store, true)
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, protocol.personTokenRequest(t))
	assertPersonInteractionProblem(t, response, http.StatusInternalServerError, "server_error")
	if store.pendingCount() != 0 {
		t.Fatalf("slow policy created %d pending records", store.pendingCount())
	}
}

func TestDeferredPersonTokenUncertainDecisionRetriesRecoverRetainedOutcome(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name   string
		decide func(*Server, PersonTokenInteraction, Person) error
		inject func(*memoryDeferredTokenStore, error)
		status int
	}{
		{
			name: "approve",
			decide: func(server *Server, interaction PersonTokenInteraction, person Person) error {
				return server.ApprovePersonTokenInteraction(context.Background(), interaction, person)
			},
			inject: func(store *memoryDeferredTokenStore, err error) { store.approveCommitErr = err },
			status: http.StatusOK,
		},
		{
			name: "deny",
			decide: func(server *Server, interaction PersonTokenInteraction, _ Person) error {
				return server.DenyPersonTokenInteraction(context.Background(), interaction)
			},
			inject: func(store *memoryDeferredTokenStore, err error) { store.denyCommitErr = err },
			status: http.StatusForbidden,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			protocol := newPersonInteractionProtocol(t)
			store := newMemoryDeferredTokenStore()
			server := protocol.newServer(t, store, true)
			initial := httptest.NewRecorder()
			server.Handler().ServeHTTP(initial, protocol.personTokenRequest(t))
			requirement, err := aauth.ParseInteractionRequirement(initial.Header().Values("AAuth-Requirement"))
			if err != nil {
				t.Fatal(err)
			}
			interaction, err := server.ConsumePersonTokenInteractionCode(context.Background(), personInteractionReference(t, requirement.URL), requirement.Code)
			if err != nil {
				t.Fatal(err)
			}
			reference := interaction.Reference()
			commitErr := errors.New("decision committed but reply was lost")
			test.inject(store, commitErr)
			person := Person{Subject: "person-123", Lifetime: 20 * time.Minute}
			if err := test.decide(server, interaction, person); !errors.Is(err, commitErr) {
				t.Fatalf("first decision error = %v", err)
			}
			protocol.now = protocol.now.Add(10 * time.Minute)
			server = protocol.newServer(t, store, true)
			interaction, err = server.ResumePersonTokenInteraction(context.Background(), reference)
			if err != nil {
				t.Fatal(err)
			}
			if err := test.decide(server, interaction, person); err != nil {
				t.Fatalf("decision recovery = %v", err)
			}
			poll := httptest.NewRecorder()
			server.Handler().ServeHTTP(poll, protocol.pollRequest(t, initial.Header().Get("Location"), protocol.agentKey, protocol.agentToken))
			if poll.Code != test.status {
				t.Fatalf("recovered decision poll = %d %s", poll.Code, poll.Body.String())
			}
		})
	}
}

func TestDeferredPersonTokenHostCanInvalidateAfterFailedCodeAttemptBound(t *testing.T) {
	t.Parallel()

	protocol := newPersonInteractionProtocol(t)
	store := newMemoryDeferredTokenStore()
	server := protocol.newServer(t, store, true)
	initial := httptest.NewRecorder()
	server.Handler().ServeHTTP(initial, protocol.personTokenRequest(t))
	requirement, err := aauth.ParseInteractionRequirement(initial.Header().Values("AAuth-Requirement"))
	if err != nil {
		t.Fatal(err)
	}
	reference := personInteractionReference(t, requirement.URL)
	if _, err := server.ConsumePersonTokenInteractionCode(context.Background(), reference, "ZZZZ-ZZZZ"); !errors.Is(err, ErrInteractionCodeInvalid) {
		t.Fatalf("failed code attempt = %v", err)
	}
	interaction, err := server.ResumePersonTokenInteraction(context.Background(), reference)
	if err != nil {
		t.Fatal(err)
	}
	if err := server.InvalidatePersonTokenInteraction(context.Background(), interaction); err != nil {
		t.Fatal(err)
	}
	poll := httptest.NewRecorder()
	server.Handler().ServeHTTP(poll, protocol.pollRequest(t, initial.Header().Get("Location"), protocol.agentKey, protocol.agentToken))
	assertPersonInteractionProblem(t, poll, http.StatusGone, "invalid_code")
}

func TestDeferredPersonTokenRejectsMisdirectedCodeLookup(t *testing.T) {
	t.Parallel()

	for _, change := range []func(*PendingPersonTokenRecord){
		func(record *PendingPersonTokenRecord) { record.PersonServer = "https://other-person.example" },
		func(record *PendingPersonTokenRecord) { record.CodeSHA256 = sha256.Sum256([]byte("different-code")) },
		func(record *PendingPersonTokenRecord) { record.ExpiresAt = record.AgentExpiresAt.Add(time.Second) },
	} {
		protocol := newPersonInteractionProtocol(t)
		store := newMemoryDeferredTokenStore()
		server := protocol.newServer(t, store, true)
		initial := httptest.NewRecorder()
		server.Handler().ServeHTTP(initial, protocol.personTokenRequest(t))
		requirement, err := aauth.ParseInteractionRequirement(initial.Header().Values("AAuth-Requirement"))
		if err != nil {
			t.Fatal(err)
		}
		store.consumeChange = change
		if interaction, err := server.ConsumePersonTokenInteractionCode(context.Background(), personInteractionReference(t, requirement.URL), requirement.Code); err == nil {
			t.Fatalf("misdirected code lookup returned interaction %#v", interaction)
		}
	}
}

func TestDeferredPersonTokenDoesNotTrustStoreSuppliedTokenKey(t *testing.T) {
	t.Parallel()

	protocol := newPersonInteractionProtocol(t)
	store := newMemoryDeferredTokenStore()
	server := protocol.newServer(t, store, true)
	initial := httptest.NewRecorder()
	server.Handler().ServeHTTP(initial, protocol.personTokenRequest(t))
	requirement, err := aauth.ParseInteractionRequirement(initial.Header().Values("AAuth-Requirement"))
	if err != nil {
		t.Fatal(err)
	}
	interaction, err := server.ConsumePersonTokenInteractionCode(context.Background(), personInteractionReference(t, requirement.URL), requirement.Code)
	if err != nil {
		t.Fatal(err)
	}
	if err := server.ApprovePersonTokenInteraction(context.Background(), interaction, Person{
		Subject: "person-123", Lifetime: time.Minute,
	}); err != nil {
		t.Fatal(err)
	}
	attackerKey := personServerTestKey(t, "attacker-key")
	claims := aauth.PersonTokenClaims{
		Issuer: protocol.personServerID, DWK: aauth.PersonDiscoveryDocument,
		Audience: protocol.resourceID, Subject: "attacker-person",
		Confirmation: aauth.Confirmation{JWK: protocol.agentKey.PublicJWK()},
		JTI:          "attacker-token", IssuedAt: protocol.now.Unix(), ExpiresAt: protocol.now.Add(time.Minute).Unix(),
	}
	compact, err := aauth.MintPersonToken(attackerKey, claims)
	if err != nil {
		t.Fatal(err)
	}
	expiresAt := time.Unix(claims.ExpiresAt, 0).UTC()
	store.pollOverride = &PersonTokenPollRecord{
		State: PersonTokenPollApproved, Token: compact, ExpiresIn: int64(time.Minute / time.Second),
		Record: PersonTokenRecord{
			JTI: claims.JTI, PersonServer: claims.Issuer, Resource: claims.Audience,
			Subject: claims.Subject, AgentProvider: "https://provider.example",
			Agent: protocol.agentID, Confirmation: protocol.agentKey.PublicJWK(),
			ExpiresAt: expiresAt, RetainUntil: expiresAt.Add(5 * time.Minute),
		},
	}
	poll := httptest.NewRecorder()
	server.Handler().ServeHTTP(poll, protocol.pollRequest(t, initial.Header().Get("Location"), protocol.agentKey, protocol.agentToken))
	assertPersonInteractionProblem(t, poll, http.StatusInternalServerError, "server_error")
}

func TestDeferredPersonTokenResolverFailureDoesNotConsumeApprovedResult(t *testing.T) {
	t.Parallel()

	protocol := newPersonInteractionProtocol(t)
	store := newMemoryDeferredTokenStore()
	server := protocol.newServer(t, store, true)
	initial := httptest.NewRecorder()
	server.Handler().ServeHTTP(initial, protocol.personTokenRequest(t))
	requirement, err := aauth.ParseInteractionRequirement(initial.Header().Values("AAuth-Requirement"))
	if err != nil {
		t.Fatal(err)
	}
	interaction, err := server.ConsumePersonTokenInteractionCode(context.Background(), personInteractionReference(t, requirement.URL), requirement.Code)
	if err != nil {
		t.Fatal(err)
	}
	if err := server.ApprovePersonTokenInteraction(context.Background(), interaction, Person{
		Subject: "person-123", Lifetime: time.Minute,
	}); err != nil {
		t.Fatal(err)
	}
	trusted := protocol.resolver
	failures := 1
	protocol.resolver = personKeyResolverFunc(func(ctx context.Context, issuer, document, keyID string) (jose.JWK, error) {
		if issuer == protocol.personServerID && failures > 0 {
			failures--
			return jose.JWK{}, errors.New("temporary trusted-key lookup failure")
		}
		return trusted.ResolveKey(ctx, issuer, document, keyID)
	})
	server = protocol.newServer(t, store, true)

	first := httptest.NewRecorder()
	server.Handler().ServeHTTP(first, protocol.pollRequest(t, initial.Header().Get("Location"), protocol.agentKey, protocol.agentToken))
	assertPersonInteractionProblem(t, first, http.StatusInternalServerError, "server_error")
	second := httptest.NewRecorder()
	server.Handler().ServeHTTP(second, protocol.pollRequest(t, initial.Header().Get("Location"), protocol.agentKey, protocol.agentToken))
	if second.Code != http.StatusOK {
		t.Fatalf("second poll = %d %s", second.Code, second.Body.String())
	}
	third := httptest.NewRecorder()
	server.Handler().ServeHTTP(third, protocol.pollRequest(t, initial.Header().Get("Location"), protocol.agentKey, protocol.agentToken))
	assertPersonInteractionProblem(t, third, http.StatusGone, "invalid_code")
}

func TestDeferredPersonTokenInternalPollFailuresUseCoreServerError(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name      string
		configure func(*memoryDeferredTokenStore)
	}{
		{
			name: "store failure",
			configure: func(store *memoryDeferredTokenStore) {
				store.pollErr = errors.New("pending store failed")
			},
		},
		{
			name: "invalid state",
			configure: func(store *memoryDeferredTokenStore) {
				store.pollOverride = &PersonTokenPollRecord{State: PersonTokenPollState(255)}
			},
		},
		{
			name: "invalid pending result",
			configure: func(store *memoryDeferredTokenStore) {
				store.pollOverride = &PersonTokenPollRecord{State: PersonTokenPollWaiting, RetryAfter: -time.Second}
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			protocol := newPersonInteractionProtocol(t)
			store := newMemoryDeferredTokenStore()
			server := protocol.newServer(t, store, true)
			initial := httptest.NewRecorder()
			server.Handler().ServeHTTP(initial, protocol.personTokenRequest(t))
			if initial.Code != http.StatusAccepted {
				t.Fatalf("initial response = %d %s", initial.Code, initial.Body.String())
			}
			test.configure(store)

			poll := httptest.NewRecorder()
			server.Handler().ServeHTTP(poll, protocol.pollRequest(t, initial.Header().Get("Location"), protocol.agentKey, protocol.agentToken))
			assertPersonInteractionProblem(t, poll, http.StatusInternalServerError, "server_error")
			if retryAfter := poll.Header().Get("Retry-After"); retryAfter != "" {
				t.Fatalf("internal failure Retry-After = %q", retryAfter)
			}
		})
	}
}

func TestDeferredPersonTokenExpiredBeforeTerminalPollDoesNotReleaseToken(t *testing.T) {
	t.Parallel()

	protocol := newPersonInteractionProtocol(t)
	store := newMemoryDeferredTokenStore()
	server := protocol.newServer(t, store, true)
	initial := httptest.NewRecorder()
	server.Handler().ServeHTTP(initial, protocol.personTokenRequest(t))
	requirement, err := aauth.ParseInteractionRequirement(initial.Header().Values("AAuth-Requirement"))
	if err != nil {
		t.Fatal(err)
	}
	interaction, err := server.ConsumePersonTokenInteractionCode(context.Background(), personInteractionReference(t, requirement.URL), requirement.Code)
	if err != nil {
		t.Fatal(err)
	}
	if err := server.ApprovePersonTokenInteraction(context.Background(), interaction, Person{
		Subject: "person-123", Lifetime: time.Minute,
	}); err != nil {
		t.Fatal(err)
	}
	protocol.now = protocol.now.Add(2 * time.Minute)
	poll := httptest.NewRecorder()
	server.Handler().ServeHTTP(poll, protocol.pollRequest(t, initial.Header().Get("Location"), protocol.agentKey, protocol.agentToken))
	assertPersonInteractionProblem(t, poll, http.StatusRequestTimeout, "expired")
	gone := httptest.NewRecorder()
	server.Handler().ServeHTTP(gone, protocol.pollRequest(t, initial.Header().Get("Location"), protocol.agentKey, protocol.agentToken))
	assertPersonInteractionProblem(t, gone, http.StatusGone, "invalid_code")
}

func TestDeferredPersonTokenDecisionRaceHasOneWinner(t *testing.T) {
	t.Parallel()

	protocol := newPersonInteractionProtocol(t)
	store := newMemoryDeferredTokenStore()
	server := protocol.newServer(t, store, true)
	initial := httptest.NewRecorder()
	server.Handler().ServeHTTP(initial, protocol.personTokenRequest(t))
	requirement, err := aauth.ParseInteractionRequirement(initial.Header().Values("AAuth-Requirement"))
	if err != nil {
		t.Fatal(err)
	}
	interaction, err := server.ConsumePersonTokenInteractionCode(context.Background(), personInteractionReference(t, requirement.URL), requirement.Code)
	if err != nil {
		t.Fatal(err)
	}
	errorsByDecision := make(chan error, 2)
	go func() {
		errorsByDecision <- server.ApprovePersonTokenInteraction(context.Background(), interaction, Person{
			Subject: "person-123", Lifetime: time.Minute,
		})
	}()
	go func() { errorsByDecision <- server.DenyPersonTokenInteraction(context.Background(), interaction) }()
	first, second := <-errorsByDecision, <-errorsByDecision
	successes := 0
	conflicts := 0
	for _, err := range []error{first, second} {
		switch {
		case err == nil:
			successes++
		case errors.Is(err, ErrPendingPersonTokenConflict):
			conflicts++
		default:
			t.Fatalf("decision error = %v", err)
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("decision outcomes = success %d, conflict %d", successes, conflicts)
	}
}

func TestDeferredPersonTokenConcurrentTerminalPollIsDeliveredOnce(t *testing.T) {
	t.Parallel()

	protocol := newPersonInteractionProtocol(t)
	store := newMemoryDeferredTokenStore()
	server := protocol.newServer(t, store, true)
	initial := httptest.NewRecorder()
	server.Handler().ServeHTTP(initial, protocol.personTokenRequest(t))
	requirement, err := aauth.ParseInteractionRequirement(initial.Header().Values("AAuth-Requirement"))
	if err != nil {
		t.Fatal(err)
	}
	interaction, err := server.ConsumePersonTokenInteractionCode(context.Background(), personInteractionReference(t, requirement.URL), requirement.Code)
	if err != nil {
		t.Fatal(err)
	}
	if err := server.ApprovePersonTokenInteraction(context.Background(), interaction, Person{
		Subject: "person-123", Lifetime: time.Minute,
	}); err != nil {
		t.Fatal(err)
	}

	const polls = 24
	statuses := make(chan int, polls)
	var wait sync.WaitGroup
	wait.Add(polls)
	for index := 0; index < polls; index++ {
		go func() {
			defer wait.Done()
			response := httptest.NewRecorder()
			server.Handler().ServeHTTP(response, protocol.pollRequest(t, initial.Header().Get("Location"), protocol.agentKey, protocol.agentToken))
			statuses <- response.Code
		}()
	}
	wait.Wait()
	close(statuses)
	succeeded, gone := 0, 0
	for status := range statuses {
		switch status {
		case http.StatusOK:
			succeeded++
		case http.StatusGone:
			gone++
		default:
			t.Fatalf("concurrent poll status = %d", status)
		}
	}
	if succeeded != 1 || gone != polls-1 {
		t.Fatalf("concurrent terminal polls = %d succeeded, %d gone", succeeded, gone)
	}
}

func TestDeferredPersonTokenInteractionDenialAndExpiryAreTerminal(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name    string
		decide  func(*Server, PersonTokenInteraction) error
		advance time.Duration
		status  int
		code    string
	}{
		{
			name: "denied",
			decide: func(server *Server, interaction PersonTokenInteraction) error {
				return server.DenyPersonTokenInteraction(context.Background(), interaction)
			},
			status: http.StatusForbidden, code: "denied",
		},
		{name: "expired", advance: 6 * time.Minute, status: http.StatusRequestTimeout, code: "expired"},
	} {
		t.Run(test.name, func(t *testing.T) {
			protocol := newPersonInteractionProtocol(t)
			store := newMemoryDeferredTokenStore()
			server := protocol.newServer(t, store, true)
			initial := httptest.NewRecorder()
			server.Handler().ServeHTTP(initial, protocol.personTokenRequest(t))
			requirement, err := aauth.ParseInteractionRequirement(initial.Header().Values("AAuth-Requirement"))
			if err != nil {
				t.Fatal(err)
			}
			interaction, err := server.ConsumePersonTokenInteractionCode(context.Background(), personInteractionReference(t, requirement.URL), requirement.Code)
			if err != nil {
				t.Fatal(err)
			}
			if test.decide != nil {
				if err := test.decide(server, interaction); err != nil {
					t.Fatal(err)
				}
			}
			protocol.now = protocol.now.Add(test.advance)
			poll := httptest.NewRecorder()
			server.Handler().ServeHTTP(poll, protocol.pollRequest(t, initial.Header().Get("Location"), protocol.agentKey, protocol.agentToken))
			assertPersonInteractionProblem(t, poll, test.status, test.code)
			if store.tokenCommitCount() != 0 {
				t.Fatalf("token commits = %d", store.tokenCommitCount())
			}
			gone := httptest.NewRecorder()
			server.Handler().ServeHTTP(gone, protocol.pollRequest(t, initial.Header().Get("Location"), protocol.agentKey, protocol.agentToken))
			assertPersonInteractionProblem(t, gone, http.StatusGone, "invalid_code")
		})
	}
}

func TestDeferredPersonTokenPollIsBoundToOriginalAgent(t *testing.T) {
	t.Parallel()

	protocol := newPersonInteractionProtocol(t)
	store := newMemoryDeferredTokenStore()
	server := protocol.newServer(t, store, true)
	initial := httptest.NewRecorder()
	server.Handler().ServeHTTP(initial, protocol.personTokenRequest(t))

	otherKey := personServerTestKey(t, "other-agent-key")
	otherToken, err := aauth.MintAgentToken(
		"https://provider.example", protocol.providerKey,
		aauth.AgentTokenRequest{
			Agent: "aauth:other@provider.example", PersonServer: protocol.personServerID,
			PublicKey: otherKey.PublicJWK(), Lifetime: time.Hour,
		},
		protocol.now, "other-agent-token",
	)
	if err != nil {
		t.Fatal(err)
	}
	wrongPoll := httptest.NewRecorder()
	server.Handler().ServeHTTP(wrongPoll, protocol.pollRequest(t, initial.Header().Get("Location"), otherKey, otherToken))
	if wrongPoll.Code == http.StatusOK || wrongPoll.Code == http.StatusAccepted {
		t.Fatalf("wrong-agent poll = %d %s", wrongPoll.Code, wrongPoll.Body.String())
	}

	rightPoll := httptest.NewRecorder()
	server.Handler().ServeHTTP(rightPoll, protocol.pollRequest(t, initial.Header().Get("Location"), protocol.agentKey, protocol.agentToken))
	if rightPoll.Code != http.StatusAccepted {
		t.Fatalf("right-agent poll = %d %s", rightPoll.Code, rightPoll.Body.String())
	}
}

type personInteractionProtocol struct {
	t               *testing.T
	now             time.Time
	clock           aauth.Clock
	providerKey     jose.SigningKey
	personServerKey jose.SigningKey
	agentKey        jose.SigningKey
	resolver        signaturekey.KeyResolver
	agentToken      string
	agentID         string
	personServerID  string
	resourceID      string
	bindCalls       int
	policyDelay     time.Duration
}

func newPersonInteractionProtocol(t *testing.T) *personInteractionProtocol {
	t.Helper()
	protocol := &personInteractionProtocol{
		t: t, now: time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC),
		agentID: "aauth:planner@provider.example", personServerID: "https://person.example",
		resourceID: "https://resource.example",
	}
	protocol.clock = aauth.ClockFunc(func() time.Time { return protocol.now })
	protocol.providerKey = personServerTestKey(t, "provider-key")
	protocol.personServerKey = personServerTestKey(t, "person-server-key")
	protocol.agentKey = personServerTestKey(t, "agent-key")
	protocol.resolver = signaturekey.StaticKeyResolver{
		{Issuer: "https://provider.example", DiscoveryDocument: aauth.AgentDiscoveryDocument, KeyID: protocol.providerKey.ID()}:   protocol.providerKey.PublicJWK(),
		{Issuer: protocol.personServerID, DiscoveryDocument: aauth.PersonDiscoveryDocument, KeyID: protocol.personServerKey.ID()}: protocol.personServerKey.PublicJWK(),
	}
	var err error
	protocol.agentToken, err = aauth.MintAgentToken(
		"https://provider.example", protocol.providerKey,
		aauth.AgentTokenRequest{
			Agent: protocol.agentID, PersonServer: protocol.personServerID,
			PublicKey: protocol.agentKey.PublicJWK(), Lifetime: time.Hour,
			AdditionalClaims: map[string]json.RawMessage{
				"platform_attestation": json.RawMessage(`{"level":"example"}`),
			},
		},
		protocol.now, "agent-token-1",
	)
	if err != nil {
		t.Fatal(err)
	}
	return protocol
}

func (protocol *personInteractionProtocol) newServer(t *testing.T, store *memoryDeferredTokenStore, deferred bool) *Server {
	t.Helper()
	config := FederatedAuthorizationConfig{
		Issuer: protocol.personServerID, SigningKey: protocol.personServerKey,
		KeyResolver: protocol.resolver, Clock: protocol.clock,
		NewID: func() string { return "person-token-1" }, HTTPClient: http.DefaultClient,
		AccessServerEndpoint: func(context.Context, string) (string, error) {
			return "https://access.example/token", nil
		},
		Tokens: store,
		BindPerson: func(context.Context, PersonTokenRequest) (Person, error) {
			protocol.bindCalls++
			return Person{Subject: "immediate-person", Lifetime: time.Minute}, nil
		},
		Consent: func(context.Context, AuthorizationRequest) error { return nil },
	}
	if deferred {
		config.RequirePersonTokenInteraction = func(_ context.Context, request PersonTokenRequest) (PersonTokenInteractionPolicy, bool, error) {
			if request.Agent != protocol.agentID || request.Resource != protocol.resourceID {
				t.Fatalf("interaction policy request = %#v", request)
			}
			protocol.now = protocol.now.Add(protocol.policyDelay)
			return PersonTokenInteractionPolicy{
				URL: "https://person.example/interaction", Lifetime: 5 * time.Minute, RetryAfter: 3 * time.Second,
			}, true, nil
		}
	}
	server, err := NewFederatedAuthorization(config)
	if err != nil {
		t.Fatal(err)
	}
	return server
}

func (protocol *personInteractionProtocol) personTokenRequest(t *testing.T) *http.Request {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, protocol.personServerID+"/person", bytes.NewBufferString(`{"resource":"https://resource.example"}`))
	request.Header.Set("Content-Type", "application/json")
	if err := signPersonServerTestRequest(request, protocol.agentKey, protocol.agentToken, protocol.clock); err != nil {
		t.Fatal(err)
	}
	return request
}

func (protocol *personInteractionProtocol) pollRequest(t *testing.T, location string, key jose.SigningKey, token string) *http.Request {
	t.Helper()
	request := httptest.NewRequest(http.MethodGet, protocol.personServerID+location, nil)
	if err := signaturekey.SignJWTRequest(request, key, token, protocol.clock); err != nil {
		t.Fatal(err)
	}
	return request
}

func personInteractionReference(t *testing.T, interactionURL string) string {
	t.Helper()
	const prefix = "https://person.example/interaction/"
	reference := strings.TrimPrefix(interactionURL, prefix)
	if reference == interactionURL || reference == "" {
		t.Fatalf("interaction URL = %q", interactionURL)
	}
	return reference
}

func assertPersonInteractionProblem(t *testing.T, response *httptest.ResponseRecorder, status int, code string) {
	t.Helper()
	var problem struct {
		Code string `json:"error"`
	}
	if err := json.NewDecoder(response.Body).Decode(&problem); err != nil {
		t.Fatal(err)
	}
	if response.Code != status || problem.Code != code {
		t.Fatalf("problem = %d %#v", response.Code, problem)
	}
}

type memoryDeferredTokenStore struct {
	mu               sync.Mutex
	records          map[string]PersonTokenRecord
	pending          map[string]*memoryPendingPersonToken
	byCode           map[[32]byte]string
	createErr        error
	approveErr       error
	approveCommitErr error
	denyCommitErr    error
	consumeChange    func(*PendingPersonTokenRecord)
	pollErr          error
	pollOverride     *PersonTokenPollRecord
}

type memoryPendingPersonToken struct {
	record   PendingPersonTokenRecord
	state    PersonTokenPollState
	approval PersonTokenApproval
	deniedAt time.Time
}

func newMemoryDeferredTokenStore() *memoryDeferredTokenStore {
	return &memoryDeferredTokenStore{
		records: make(map[string]PersonTokenRecord), pending: make(map[string]*memoryPendingPersonToken),
		byCode: make(map[[32]byte]string),
	}
}

func (store *memoryDeferredTokenStore) Commit(_ context.Context, record PersonTokenRecord) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.records[record.PersonServer+"\x00"+record.JTI] = record
	return nil
}

func (store *memoryDeferredTokenStore) Load(_ context.Context, issuer, jti string) (PersonTokenRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	record, ok := store.records[issuer+"\x00"+jti]
	if !ok {
		return PersonTokenRecord{}, ErrPersonTokenNotFound
	}
	return record, nil
}

func (store *memoryDeferredTokenStore) CreatePendingPersonToken(_ context.Context, record PendingPersonTokenRecord) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.createErr != nil {
		return store.createErr
	}
	if _, exists := store.pending[record.ID]; exists {
		return ErrPendingPersonTokenConflict
	}
	if _, exists := store.byCode[record.CodeSHA256]; exists {
		return ErrPendingPersonTokenConflict
	}
	store.pending[record.ID] = &memoryPendingPersonToken{record: clonePendingPersonTokenRecord(record), state: PersonTokenPollWaiting}
	store.byCode[record.CodeSHA256] = record.ID
	return nil
}

func (store *memoryDeferredTokenStore) ConsumePersonTokenInteractionCode(_ context.Context, personServer, reference string, code [32]byte, now time.Time) (PendingPersonTokenRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	pending, ok := store.pending[reference]
	if !ok {
		return PendingPersonTokenRecord{}, ErrInteractionCodeInvalid
	}
	if pending.record.PersonServer != personServer || pending.record.CodeSHA256 != code {
		return PendingPersonTokenRecord{}, ErrInteractionCodeInvalid
	}
	if pending.state != PersonTokenPollWaiting {
		return PendingPersonTokenRecord{}, ErrInteractionCodeUsed
	}
	if !now.Before(pending.record.ExpiresAt) {
		pending.state = PersonTokenPollExpired
		return PendingPersonTokenRecord{}, ErrPendingPersonTokenExpired
	}
	pending.state = PersonTokenPollInteracting
	record := clonePendingPersonTokenRecord(pending.record)
	if store.consumeChange != nil {
		store.consumeChange(&record)
	}
	return record, nil
}

func (store *memoryDeferredTokenStore) LoadPendingPersonToken(_ context.Context, id string) (PendingPersonTokenSnapshot, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	pending, ok := store.pending[id]
	if !ok {
		return PendingPersonTokenSnapshot{}, ErrPendingPersonTokenNotFound
	}
	snapshot := PendingPersonTokenSnapshot{Record: clonePendingPersonTokenRecord(pending.record), State: pending.state}
	if pending.state == PersonTokenPollApproved {
		snapshot.ApprovedPerson = pending.approval.Person
	}
	return snapshot, nil
}

func (store *memoryDeferredTokenStore) ApprovePendingPersonToken(_ context.Context, id string, approval PersonTokenApproval) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.approveErr != nil {
		return store.approveErr
	}
	pending, ok := store.pending[id]
	if !ok {
		return ErrPendingPersonTokenNotFound
	}
	if pending.state == PersonTokenPollApproved && reflect.DeepEqual(pending.approval.Person, approval.Person) {
		return nil
	}
	if pending.state != PersonTokenPollInteracting {
		return ErrPendingPersonTokenConflict
	}
	store.records[approval.Record.PersonServer+"\x00"+approval.Record.JTI] = approval.Record
	pending.approval = approval
	pending.state = PersonTokenPollApproved
	if store.approveCommitErr != nil {
		err := store.approveCommitErr
		store.approveCommitErr = nil
		return err
	}
	return nil
}

func (store *memoryDeferredTokenStore) DenyPendingPersonToken(_ context.Context, id string, decidedAt time.Time) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	pending, ok := store.pending[id]
	if !ok {
		return ErrPendingPersonTokenNotFound
	}
	if pending.state == PersonTokenPollDenied {
		return nil
	}
	if pending.state != PersonTokenPollInteracting {
		return ErrPendingPersonTokenConflict
	}
	pending.deniedAt = decidedAt
	pending.state = PersonTokenPollDenied
	if store.denyCommitErr != nil {
		err := store.denyCommitErr
		store.denyCommitErr = nil
		return err
	}
	return nil
}

func (store *memoryDeferredTokenStore) InvalidatePendingPersonToken(_ context.Context, id string, _ time.Time) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	pending, ok := store.pending[id]
	if !ok {
		return ErrPendingPersonTokenNotFound
	}
	if pending.state == PersonTokenPollGone {
		return nil
	}
	if pending.state != PersonTokenPollWaiting && pending.state != PersonTokenPollInteracting {
		return ErrPendingPersonTokenConflict
	}
	pending.state = PersonTokenPollGone
	return nil
}

func (store *memoryDeferredTokenStore) PollPendingPersonToken(_ context.Context, id string, identity PersonTokenPollIdentity, now time.Time) (PersonTokenPollRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.pollErr != nil {
		return PersonTokenPollRecord{}, store.pollErr
	}
	pending, ok := store.pending[id]
	if !ok {
		return PersonTokenPollRecord{}, ErrPendingPersonTokenNotFound
	}
	wantJKT, _ := pending.record.Confirmation.Thumbprint()
	if identity.PersonServer != pending.record.PersonServer || identity.Agent != pending.record.Agent || identity.ConfirmationThumbprint != wantJKT {
		return PersonTokenPollRecord{}, ErrPendingPersonTokenNotFound
	}
	if store.pollOverride != nil {
		result := *store.pollOverride
		store.pollOverride = nil
		return result, nil
	}
	if pending.state == PersonTokenPollGone {
		return PersonTokenPollRecord{}, ErrPendingPersonTokenGone
	}
	if !now.Before(pending.record.ExpiresAt) && (pending.state == PersonTokenPollWaiting || pending.state == PersonTokenPollInteracting) {
		pending.state = PersonTokenPollExpired
	}
	result := PersonTokenPollRecord{State: pending.state, RetryAfter: pending.record.RetryAfter}
	switch pending.state {
	case PersonTokenPollApproved:
		result.Token = pending.approval.Token
		result.Record = pending.approval.Record
		result.ExpiresIn = pending.approval.ExpiresIn
	}
	return result, nil
}

func (store *memoryDeferredTokenStore) ConsumePendingPersonTokenResult(_ context.Context, id string, result PersonTokenPollRecord) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	pending, ok := store.pending[id]
	if !ok {
		return ErrPendingPersonTokenNotFound
	}
	if pending.state == PersonTokenPollGone {
		return ErrPendingPersonTokenGone
	}
	if result.State != pending.state {
		return ErrPendingPersonTokenConflict
	}
	switch pending.state {
	case PersonTokenPollApproved:
		want := PersonTokenPollRecord{
			State: PersonTokenPollApproved, Token: pending.approval.Token,
			Record: pending.approval.Record, ExpiresIn: pending.approval.ExpiresIn,
			RetryAfter: pending.record.RetryAfter,
		}
		if !reflect.DeepEqual(result, want) {
			return ErrPendingPersonTokenConflict
		}
	case PersonTokenPollDenied, PersonTokenPollExpired:
		if result.Token != "" || result.Record != (PersonTokenRecord{}) || result.ExpiresIn != 0 ||
			result.RetryAfter != pending.record.RetryAfter {
			return ErrPendingPersonTokenConflict
		}
	default:
		return ErrPendingPersonTokenConflict
	}
	pending.state = PersonTokenPollGone
	return nil
}

func (store *memoryDeferredTokenStore) tokenCommitCount() int {
	store.mu.Lock()
	defer store.mu.Unlock()
	return len(store.records)
}

func (store *memoryDeferredTokenStore) pendingCount() int {
	store.mu.Lock()
	defer store.mu.Unlock()
	return len(store.pending)
}

func (store *memoryDeferredTokenStore) onlyPending(t *testing.T) PendingPersonTokenRecord {
	t.Helper()
	store.mu.Lock()
	defer store.mu.Unlock()
	if len(store.pending) != 1 {
		t.Fatalf("pending records = %d", len(store.pending))
	}
	for _, pending := range store.pending {
		return clonePendingPersonTokenRecord(pending.record)
	}
	panic("unreachable")
}

func clonePendingPersonTokenRecord(record PendingPersonTokenRecord) PendingPersonTokenRecord {
	record.AgentAdditionalClaims = cloneClaims(record.AgentAdditionalClaims)
	return record
}

func normalizedCodeDigest(code string) [32]byte {
	code = strings.ToUpper(strings.ReplaceAll(code, "-", ""))
	code = strings.NewReplacer("I", "1", "L", "1", "O", "0").Replace(code)
	return sha256.Sum256([]byte(code))
}

type personKeyResolverFunc func(context.Context, string, string, string) (jose.JWK, error)

func (resolve personKeyResolverFunc) ResolveKey(ctx context.Context, issuer, document, keyID string) (jose.JWK, error) {
	return resolve(ctx, issuer, document, keyID)
}
