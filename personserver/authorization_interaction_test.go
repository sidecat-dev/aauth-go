package personserver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	aauth "aauth-go"
	"aauth-go/internal/interaction"
	"aauth-go/jose"
	"aauth-go/signaturekey"
)

func TestDeferredAuthorizationConfigurationAndImmediateCompatibility(t *testing.T) {
	protocol := newAuthorizationInteractionProtocol(t)
	valid := protocol.config(newMemoryDeferredAuthorizationStore())

	if _, err := NewPSAuthorization(valid); err != nil {
		t.Fatalf("paired authorization interaction configuration: %v", err)
	}
	for _, test := range []struct {
		name   string
		change func(*PSAuthorizationConfig)
	}{
		{name: "policy only", change: func(config *PSAuthorizationConfig) { config.AuthorizationInteractions = nil }},
		{name: "store only", change: func(config *PSAuthorizationConfig) { config.RequireAuthorizationInteraction = nil }},
	} {
		t.Run(test.name, func(t *testing.T) {
			config := valid
			test.change(&config)
			if _, err := NewPSAuthorization(config); err == nil {
				t.Fatal("unpaired authorization interaction configuration was accepted")
			}
		})
	}

	protocol.requireInteraction = false
	server := protocol.newServer(t, newMemoryDeferredAuthorizationStore())
	response := protocol.exchange(t, server, []string{"future-extension", "interaction"})
	if response.Code != http.StatusOK {
		t.Fatalf("immediate response = %d %s", response.Code, response.Body.String())
	}
	if protocol.policyCalls != 1 || protocol.authorizeCalls != 1 {
		t.Fatalf("immediate calls: interaction policy=%d authorize=%d", protocol.policyCalls, protocol.authorizeCalls)
	}
	if !reflect.DeepEqual(protocol.lastAuthorization.Capabilities, []string{"future-extension", "interaction"}) {
		t.Fatalf("immediate capabilities = %#v", protocol.lastAuthorization.Capabilities)
	}
	protocol.lastAuthorization.Capabilities[0] = "mutated"
	if protocol.requestCapabilities[0] != "future-extension" {
		t.Fatalf("authorization policy mutated request capabilities = %#v", protocol.requestCapabilities)
	}
}

func TestDeferredAuthorizationDoesNotRequireDeadImmediatePolicy(t *testing.T) {
	t.Run("interaction selected", func(t *testing.T) {
		protocol := newAuthorizationInteractionProtocol(t)
		store := newMemoryDeferredAuthorizationStore()
		config := protocol.config(store)
		config.Authorize = nil
		server, err := NewPSAuthorization(config)
		if err != nil {
			t.Fatalf("construct deferred-only Person Server: %v", err)
		}
		response := protocol.exchange(t, server, []string{"interaction"})
		if response.Code != http.StatusAccepted || store.pendingCount() != 1 || protocol.authorizeCalls != 0 {
			t.Fatalf("deferred-only response=%d body=%s pending=%d immediate=%d",
				response.Code, response.Body.String(), store.pendingCount(), protocol.authorizeCalls)
		}
	})

	t.Run("interaction not selected", func(t *testing.T) {
		protocol := newAuthorizationInteractionProtocol(t)
		protocol.requireInteraction = false
		store := newMemoryDeferredAuthorizationStore()
		config := protocol.config(store)
		config.Authorize = nil
		server, err := NewPSAuthorization(config)
		if err != nil {
			t.Fatalf("construct deferred-only Person Server: %v", err)
		}
		response := protocol.exchange(t, server, []string{"interaction"})
		assertAuthorizationInteractionProblem(t, response, http.StatusInternalServerError, "server_error")
		if store.pendingCount() != 0 || protocol.tokenIDCalls() != 0 {
			t.Fatalf("missing deferred decision changed state: pending=%d tokens=%d", store.pendingCount(), protocol.tokenIDCalls())
		}
	})

	t.Run("no authorization policy", func(t *testing.T) {
		protocol := newAuthorizationInteractionProtocol(t)
		config := protocol.config(nil)
		config.Authorize = nil
		if _, err := NewPSAuthorization(config); err == nil {
			t.Fatal("Person Server without immediate or deferred authorization policy was accepted")
		}
	})
}

func TestDeferredAuthorizationCodeAttemptBoundIsFixed(t *testing.T) {
	if _, configurable := reflect.TypeOf(AuthorizationInteractionPolicy{}).FieldByName("MaximumCodeAttempts"); configurable {
		t.Fatal("authorization interaction policy exposes a configurable code-attempt bound")
	}
	if _, configurable := reflect.TypeOf(PendingAuthorizationRecord{}).FieldByName("MaximumCodeAttempts"); configurable {
		t.Fatal("pending authorization record exposes a configurable code-attempt bound")
	}
}

func TestDeferredAuthorizationCodeAttemptsCannotDestroyCorrelatedInteraction(t *testing.T) {
	protocol := newAuthorizationInteractionProtocol(t)
	store := newMemoryDeferredAuthorizationStore()
	server := protocol.newServer(t, store)
	response := protocol.exchange(t, server, []string{"interaction"})
	requirement, err := aauth.ParseInteractionRequirement(response.Header().Values("AAuth-Requirement"))
	if err != nil {
		t.Fatal(err)
	}
	reference := strings.TrimPrefix(requirement.URL, protocol.interactionURL+"/")
	value, err := server.ConsumeAuthorizationInteractionCode(context.Background(), reference, requirement.Code)
	if err != nil {
		t.Fatal(err)
	}

	for _, code := range []string{"***", differentValidAuthorizationCode(t, requirement.Code), requirement.Code} {
		if _, err := server.ConsumeAuthorizationInteractionCode(context.Background(), reference, code); !errors.Is(err, ErrAuthorizationInteractionCodeUsed) {
			t.Fatalf("code presentation after correlation = %q: %v", code, err)
		}
	}
	state, attempts := store.codeAttemptObservation(t, reference)
	if state != AuthorizationPollInteracting || attempts != 0 {
		t.Fatalf("correlated interaction changed by later code presentations: state=%v attempts=%d", state, attempts)
	}
	if err := server.ApproveAuthorizationInteraction(context.Background(), value, AuthorizationDecision{
		Scopes: []string{"records.read"}, Lifetime: time.Minute,
	}); err != nil {
		t.Fatalf("approve correlated interaction: %v", err)
	}
}

func TestDeferredAuthorizationInteractionLifecycleAcrossRecomposition(t *testing.T) {
	protocol := newAuthorizationInteractionProtocol(t)
	store := newMemoryDeferredAuthorizationStore()
	server := protocol.newServer(t, store)

	response := protocol.exchange(t, server, []string{"future-extension", "interaction"})
	if response.Code != http.StatusAccepted {
		t.Fatalf("initial response = %d %s", response.Code, response.Body.String())
	}
	if response.Header().Get("Cache-Control") != "no-store" || response.Header().Get("Retry-After") != "3" {
		t.Fatalf("pending headers = %#v", response.Header())
	}
	location := response.Header().Get("Location")
	if !strings.HasPrefix(location, "/token/pending/") {
		t.Fatalf("Location = %q", location)
	}
	requirement, err := aauth.ParseInteractionRequirement(response.Header().Values("AAuth-Requirement"))
	if err != nil {
		t.Fatal(err)
	}
	var pendingBody struct {
		Status string `json:"status"`
	}
	if err := json.NewDecoder(response.Body).Decode(&pendingBody); err != nil || pendingBody.Status != "pending" {
		t.Fatalf("pending body = %#v, %v", pendingBody, err)
	}
	if protocol.policyCalls != 1 || protocol.authorizeCalls != 0 || protocol.tokenIDCalls() != 0 || store.pendingCount() != 1 {
		t.Fatalf("initial effects: policy=%d authorize=%d mint=%d pending=%d", protocol.policyCalls, protocol.authorizeCalls, protocol.tokenIDCalls(), store.pendingCount())
	}
	pending := store.onlyPending(t)
	if pending.ID == "" || pending.CodeSHA256 == ([32]byte{}) || pending.PersonServer != protocol.personServerID ||
		pending.AgentProvider != protocol.providerID || pending.Agent != protocol.agentID || pending.Resource != protocol.resourceID ||
		pending.Subject != protocol.subject || pending.Tenant != protocol.tenant ||
		!reflect.DeepEqual(pending.Scopes, []string{"records.read", "records.write"}) ||
		!reflect.DeepEqual(pending.Capabilities, []string{"future-extension", "interaction"}) ||
		!pending.Confirmation.Equal(protocol.agentKey.PublicJWK()) ||
		!pending.AgentExpiresAt.Equal(protocol.now.Add(30*time.Minute)) ||
		!pending.ResourceTokenExpiresAt.Equal(protocol.now.Add(5*time.Minute)) ||
		!pending.CreatedAt.Equal(protocol.now) || !pending.ExpiresAt.Equal(protocol.now.Add(4*time.Minute)) ||
		pending.RetryAfter != 3*time.Second ||
		string(pending.AgentAdditionalClaims["platform_attestation"]) != `{"level":"example"}` {
		t.Fatalf("pending record = %#v", pending)
	}
	if normalized, err := interaction.Digest(requirement.Code); err != nil || normalized != pending.CodeSHA256 {
		t.Fatalf("code digest = %x, %v; pending=%x", normalized, err, pending.CodeSHA256)
	}
	pending.Scopes[0] = "mutated"
	pending.Capabilities[0] = "mutated"
	pending.AgentAdditionalClaims["platform_attestation"][0] = 'x'
	if got := store.onlyPending(t); got.Scopes[0] != "records.read" || got.Capabilities[0] != "future-extension" ||
		string(got.AgentAdditionalClaims["platform_attestation"]) != `{"level":"example"}` {
		t.Fatalf("pending record was not copy isolated = %#v", got)
	}

	waiting := protocol.poll(t, server, location, protocol.agentKey, protocol.agentToken)
	if waiting.Code != http.StatusAccepted || !strings.Contains(waiting.Body.String(), `"status":"pending"`) {
		t.Fatalf("waiting poll = %d %s", waiting.Code, waiting.Body.String())
	}
	reference := strings.TrimPrefix(requirement.URL, protocol.interactionURL+"/")
	if reference == "" || reference == requirement.URL {
		t.Fatalf("interaction URL = %q", requirement.URL)
	}
	interactionValue, err := server.ConsumeAuthorizationInteractionCode(context.Background(), reference, strings.ToLower(requirement.Code))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := server.ConsumeAuthorizationInteractionCode(context.Background(), reference, requirement.Code); !errors.Is(err, ErrAuthorizationInteractionCodeUsed) {
		t.Fatalf("second code use = %v", err)
	}
	if interactionValue.AgentProvider() != protocol.providerID || interactionValue.Agent() != protocol.agentID ||
		interactionValue.Resource() != protocol.resourceID || interactionValue.Subject() != protocol.subject ||
		interactionValue.Tenant() != protocol.tenant || interactionValue.Reference() != reference ||
		!reflect.DeepEqual(interactionValue.RequestedScopes(), []string{"records.read", "records.write"}) ||
		!reflect.DeepEqual(interactionValue.Capabilities(), []string{"future-extension", "interaction"}) {
		t.Fatalf("interaction handle = %#v", interactionValue)
	}
	interacting := protocol.poll(t, server, location, protocol.agentKey, protocol.agentToken)
	if interacting.Code != http.StatusAccepted || !strings.Contains(interacting.Body.String(), `"status":"interacting"`) {
		t.Fatalf("interacting poll = %d %s", interacting.Code, interacting.Body.String())
	}

	recomposed := protocol.newServer(t, store)
	resumed, err := recomposed.ResumeAuthorizationInteraction(context.Background(), reference)
	if err != nil || resumed.Reference() != reference {
		t.Fatalf("resume = %#v, %v", resumed, err)
	}
	decision := AuthorizationDecision{Scopes: []string{"records.read"}, Lifetime: 10 * time.Minute}
	if err := recomposed.ApproveAuthorizationInteraction(context.Background(), resumed, decision); err != nil {
		t.Fatal(err)
	}
	if err := recomposed.ApproveAuthorizationInteraction(context.Background(), resumed, decision); err != nil {
		t.Fatalf("exact repeated approval: %v", err)
	}
	if protocol.tokenIDCalls() != 1 {
		t.Fatalf("token mint calls = %d", protocol.tokenIDCalls())
	}
	approved := protocol.poll(t, recomposed, location, protocol.agentKey, protocol.agentToken)
	if approved.Code != http.StatusOK {
		t.Fatalf("approved poll = %d %s", approved.Code, approved.Body.String())
	}
	var output struct {
		AuthToken string `json:"auth_token"`
		ExpiresIn int64  `json:"expires_in"`
	}
	if err := json.NewDecoder(approved.Body).Decode(&output); err != nil {
		t.Fatal(err)
	}
	claims, err := aauth.VerifyAuthToken(context.Background(), output.AuthToken, protocol.resolver, protocol.clock)
	if err != nil {
		t.Fatal(err)
	}
	if claims.Issuer != protocol.personServerID || claims.DWK != aauth.PersonDiscoveryDocument || claims.Audience != protocol.resourceID ||
		claims.PersonServer != protocol.personServerID || claims.Subject != protocol.subject || claims.Tenant != protocol.tenant ||
		claims.Scope != "records.read" || !claims.Confirmation.JWK.Equal(protocol.agentKey.PublicJWK()) ||
		claims.ExpiresAt != protocol.now.Add(10*time.Minute).Unix() || output.ExpiresIn != int64((10*time.Minute)/time.Second) {
		t.Fatalf("approved auth token = %#v; expires_in=%d", claims, output.ExpiresIn)
	}
	gone := protocol.poll(t, recomposed, location, protocol.agentKey, protocol.agentToken)
	assertAuthorizationInteractionProblem(t, gone, http.StatusGone, "invalid_code")
	if protocol.policyCalls != 1 || protocol.authorizeCalls != 0 || protocol.tokenIDCalls() != 1 {
		t.Fatalf("lifecycle effects: policy=%d authorize=%d mint=%d", protocol.policyCalls, protocol.authorizeCalls, protocol.tokenIDCalls())
	}
}

func TestDeferredAuthorizationBoundsWrongCodeAttemptsByReference(t *testing.T) {
	t.Run("below at and above bound", func(t *testing.T) {
		protocol := newAuthorizationInteractionProtocol(t)
		store := newMemoryDeferredAuthorizationStore()
		server := protocol.newServer(t, store)
		response := protocol.exchange(t, server, []string{"interaction"})
		requirement, _ := aauth.ParseInteractionRequirement(response.Header().Values("AAuth-Requirement"))
		reference := strings.TrimPrefix(requirement.URL, protocol.interactionURL+"/")

		for attempt := 1; attempt < MaximumAuthorizationCodeAttempts; attempt++ {
			if _, err := server.ConsumeAuthorizationInteractionCode(context.Background(), reference, "0000-0000"); !errors.Is(err, ErrAuthorizationInteractionCodeInvalid) {
				t.Fatalf("wrong attempt %d = %v", attempt, err)
			}
		}
		if _, err := server.ConsumeAuthorizationInteractionCode(context.Background(), reference, "0000-0000"); !errors.Is(err, ErrPendingAuthorizationGone) {
			t.Fatalf("wrong attempt at bound = %v", err)
		}
		if _, err := server.ConsumeAuthorizationInteractionCode(context.Background(), reference, "0000-0000"); !errors.Is(err, ErrPendingAuthorizationGone) {
			t.Fatalf("wrong attempt above bound = %v", err)
		}
		if _, err := server.ConsumeAuthorizationInteractionCode(context.Background(), reference, requirement.Code); !errors.Is(err, ErrPendingAuthorizationGone) {
			t.Fatalf("correct code after exhaustion = %v", err)
		}
		state, attempts := store.codeAttemptObservation(t, reference)
		if state != AuthorizationPollGone || attempts != MaximumAuthorizationCodeAttempts {
			t.Fatalf("exhausted state = %v, attempts = %d", state, attempts)
		}
	})

	t.Run("concurrent wrong attempts converge", func(t *testing.T) {
		protocol := newAuthorizationInteractionProtocol(t)
		store := newMemoryDeferredAuthorizationStore()
		server := protocol.newServer(t, store)
		response := protocol.exchange(t, server, []string{"interaction"})
		requirement, _ := aauth.ParseInteractionRequirement(response.Header().Values("AAuth-Requirement"))
		reference := strings.TrimPrefix(requirement.URL, protocol.interactionURL+"/")

		const attempts = 12
		start := make(chan struct{})
		results := make(chan error, attempts)
		for index := 0; index < attempts; index++ {
			go func() {
				<-start
				_, err := server.ConsumeAuthorizationInteractionCode(context.Background(), reference, "0000-0000")
				results <- err
			}()
		}
		close(start)
		invalid, gone := 0, 0
		for index := 0; index < attempts; index++ {
			switch err := <-results; {
			case errors.Is(err, ErrAuthorizationInteractionCodeInvalid):
				invalid++
			case errors.Is(err, ErrPendingAuthorizationGone):
				gone++
			default:
				t.Fatalf("concurrent wrong attempt = %v", err)
			}
		}
		if invalid != MaximumAuthorizationCodeAttempts-1 || gone != attempts-invalid {
			t.Fatalf("concurrent outcomes: invalid=%d gone=%d", invalid, gone)
		}
		state, retainedAttempts := store.codeAttemptObservation(t, reference)
		if state != AuthorizationPollGone || retainedAttempts != MaximumAuthorizationCodeAttempts {
			t.Fatalf("concurrent exhausted state = %v, attempts = %d", state, retainedAttempts)
		}
	})
}

func TestDeferredAuthorizationMalformedCodePresentationsUseAtomicAttemptPath(t *testing.T) {
	start := func(t *testing.T) (*authorizationInteractionProtocol, *memoryDeferredAuthorizationStore, *Server, aauth.InteractionRequirement, string) {
		t.Helper()
		protocol := newAuthorizationInteractionProtocol(t)
		store := newMemoryDeferredAuthorizationStore()
		server := protocol.newServer(t, store)
		response := protocol.exchange(t, server, []string{"interaction"})
		requirement, err := aauth.ParseInteractionRequirement(response.Header().Values("AAuth-Requirement"))
		if err != nil {
			t.Fatal(err)
		}
		reference := strings.TrimPrefix(requirement.URL, protocol.interactionURL+"/")
		return protocol, store, server, requirement, reference
	}

	t.Run("sequential malformed attempts exhaust and refuse correct code", func(t *testing.T) {
		_, store, server, requirement, reference := start(t)
		for attempt := 1; attempt < MaximumAuthorizationCodeAttempts; attempt++ {
			if _, err := server.ConsumeAuthorizationInteractionCode(context.Background(), reference, "***"); !errors.Is(err, ErrAuthorizationInteractionCodeInvalid) {
				t.Fatalf("malformed attempt %d = %v", attempt, err)
			}
		}
		if _, err := server.ConsumeAuthorizationInteractionCode(context.Background(), reference, "***"); !errors.Is(err, ErrPendingAuthorizationGone) {
			t.Fatalf("malformed attempt at bound = %v", err)
		}
		if _, err := server.ConsumeAuthorizationInteractionCode(context.Background(), reference, requirement.Code); !errors.Is(err, ErrPendingAuthorizationGone) {
			t.Fatalf("correct code after malformed exhaustion = %v", err)
		}
		state, attempts := store.codeAttemptObservation(t, reference)
		if state != AuthorizationPollGone || attempts != MaximumAuthorizationCodeAttempts {
			t.Fatalf("malformed exhausted state = %v, attempts = %d", state, attempts)
		}
	})

	t.Run("mixed malformed and well-formed wrong attempts share one bound", func(t *testing.T) {
		_, store, server, requirement, reference := start(t)
		wrong := differentValidAuthorizationCode(t, requirement.Code)
		for index, code := range []string{"***", wrong} {
			if _, err := server.ConsumeAuthorizationInteractionCode(context.Background(), reference, code); !errors.Is(err, ErrAuthorizationInteractionCodeInvalid) {
				t.Fatalf("mixed attempt %d = %v", index+1, err)
			}
		}
		if _, err := server.ConsumeAuthorizationInteractionCode(context.Background(), reference, "not/crockford"); !errors.Is(err, ErrPendingAuthorizationGone) {
			t.Fatalf("mixed attempt at bound = %v", err)
		}
		if _, err := server.ConsumeAuthorizationInteractionCode(context.Background(), reference, requirement.Code); !errors.Is(err, ErrPendingAuthorizationGone) {
			t.Fatalf("correct code after mixed exhaustion = %v", err)
		}
		state, attempts := store.codeAttemptObservation(t, reference)
		if state != AuthorizationPollGone || attempts != MaximumAuthorizationCodeAttempts {
			t.Fatalf("mixed exhausted state = %v, attempts = %d", state, attempts)
		}
	})

	t.Run("concurrent malformed attempts converge", func(t *testing.T) {
		_, store, server, _, reference := start(t)
		const attempts = 12
		startTogether := make(chan struct{})
		results := make(chan error, attempts)
		for index := 0; index < attempts; index++ {
			go func() {
				<-startTogether
				_, err := server.ConsumeAuthorizationInteractionCode(context.Background(), reference, "!")
				results <- err
			}()
		}
		close(startTogether)
		invalid, gone := 0, 0
		for index := 0; index < attempts; index++ {
			switch err := <-results; {
			case errors.Is(err, ErrAuthorizationInteractionCodeInvalid):
				invalid++
			case errors.Is(err, ErrPendingAuthorizationGone):
				gone++
			default:
				t.Fatalf("concurrent malformed attempt = %v", err)
			}
		}
		if invalid != MaximumAuthorizationCodeAttempts-1 || gone != attempts-invalid {
			t.Fatalf("concurrent malformed outcomes: invalid=%d gone=%d", invalid, gone)
		}
		state, retainedAttempts := store.codeAttemptObservation(t, reference)
		if state != AuthorizationPollGone || retainedAttempts != MaximumAuthorizationCodeAttempts {
			t.Fatalf("concurrent malformed state = %v, attempts = %d", state, retainedAttempts)
		}
	})

	t.Run("malformed presentation at exact deadline is expired before counting", func(t *testing.T) {
		protocol, store, server, _, reference := start(t)
		protocol.now = store.onlyPending(t).ExpiresAt
		if _, err := server.ConsumeAuthorizationInteractionCode(context.Background(), reference, "***"); !errors.Is(err, ErrPendingAuthorizationExpired) {
			t.Fatalf("malformed presentation at deadline = %v", err)
		}
		state, attempts := store.codeAttemptObservation(t, reference)
		if state != AuthorizationPollExpired || attempts != 0 {
			t.Fatalf("deadline malformed state = %v, attempts = %d", state, attempts)
		}
	})

	t.Run("server rejects store success for an invalid presentation", func(t *testing.T) {
		_, store, server, _, reference := start(t)
		store.invalidPresentationSuccess = true
		if _, err := server.ConsumeAuthorizationInteractionCode(context.Background(), reference, "***"); !errors.Is(err, ErrPendingAuthorizationConflict) {
			t.Fatalf("invalid-presentation store success = %v", err)
		}
	})
}

func TestDeferredAuthorizationRequiresInteractionCapabilityBeforeCreatingState(t *testing.T) {
	protocol := newAuthorizationInteractionProtocol(t)
	store := newMemoryDeferredAuthorizationStore()
	server := protocol.newServer(t, store)

	for _, capabilities := range [][]string{nil, {"future-extension"}} {
		response := protocol.exchange(t, server, capabilities)
		assertAuthorizationInteractionProblem(t, response, http.StatusForbidden, "user_unreachable")
	}
	if store.pendingCount() != 0 || protocol.authorizeCalls != 0 || protocol.tokenIDCalls() != 0 {
		t.Fatalf("unreachable request changed state: pending=%d authorize=%d mint=%d", store.pendingCount(), protocol.authorizeCalls, protocol.tokenIDCalls())
	}

	for _, body := range []string{
		`{"resource_token":"TOKEN","capabilities":null}`,
		`{"resource_token":"TOKEN","capabilities":["interaction","interaction"]}`,
		`{"resource_token":"TOKEN","capabilities":["not a token"]}`,
	} {
		response := protocol.exchangeBody(t, server, strings.Replace(body, "TOKEN", protocol.resourceToken, 1))
		assertAuthorizationInteractionProblem(t, response, http.StatusBadRequest, "invalid_request")
	}
}

func TestDeferredAuthorizationExactDeadlineClassifiesEveryTransitionAsExpired(t *testing.T) {
	type started struct {
		protocol    *authorizationInteractionProtocol
		store       *memoryDeferredAuthorizationStore
		server      *Server
		response    *httptest.ResponseRecorder
		requirement aauth.InteractionRequirement
		reference   string
	}
	start := func(t *testing.T) started {
		t.Helper()
		protocol := newAuthorizationInteractionProtocol(t)
		store := newMemoryDeferredAuthorizationStore()
		server := protocol.newServer(t, store)
		response := protocol.exchange(t, server, []string{"interaction"})
		requirement, err := aauth.ParseInteractionRequirement(response.Header().Values("AAuth-Requirement"))
		if err != nil {
			t.Fatal(err)
		}
		return started{
			protocol: protocol, store: store, server: server, response: response, requirement: requirement,
			reference: strings.TrimPrefix(requirement.URL, protocol.interactionURL+"/"),
		}
	}
	correlate := func(t *testing.T, value started) AuthorizationInteraction {
		t.Helper()
		interaction, err := value.server.ConsumeAuthorizationInteractionCode(context.Background(), value.reference, value.requirement.Code)
		if err != nil {
			t.Fatal(err)
		}
		return interaction
	}
	advance := func(t *testing.T, value started) {
		t.Helper()
		value.protocol.now = value.store.onlyPending(t).ExpiresAt
	}
	assertExpiredState := func(t *testing.T, value started) {
		t.Helper()
		state, _ := value.store.codeAttemptObservation(t, value.reference)
		if state != AuthorizationPollExpired {
			t.Fatalf("state = %v, want expired", state)
		}
	}

	t.Run("resume", func(t *testing.T) {
		value := start(t)
		advance(t, value)
		if _, err := value.server.ResumeAuthorizationInteraction(context.Background(), value.reference); !errors.Is(err, ErrPendingAuthorizationExpired) {
			t.Fatalf("resume at deadline = %v", err)
		}
		assertExpiredState(t, value)
	})
	t.Run("abandon", func(t *testing.T) {
		value := start(t)
		interaction := correlate(t, value)
		advance(t, value)
		if err := value.server.AbandonAuthorizationInteraction(context.Background(), interaction); !errors.Is(err, ErrPendingAuthorizationExpired) {
			t.Fatalf("abandon at deadline = %v", err)
		}
		assertExpiredState(t, value)
	})
	t.Run("code", func(t *testing.T) {
		value := start(t)
		advance(t, value)
		if _, err := value.server.ConsumeAuthorizationInteractionCode(context.Background(), value.reference, value.requirement.Code); !errors.Is(err, ErrPendingAuthorizationExpired) {
			t.Fatalf("code at deadline = %v", err)
		}
		assertExpiredState(t, value)
	})
	t.Run("approval", func(t *testing.T) {
		value := start(t)
		interaction := correlate(t, value)
		advance(t, value)
		if err := value.server.ApproveAuthorizationInteraction(context.Background(), interaction, AuthorizationDecision{
			Scopes: []string{"records.read"}, Lifetime: time.Minute,
		}); !errors.Is(err, ErrPendingAuthorizationExpired) {
			t.Fatalf("approval at deadline = %v", err)
		}
		if value.protocol.tokenIDCalls() != 0 {
			t.Fatalf("approval at deadline allocated a token ID")
		}
		assertExpiredState(t, value)
	})
	t.Run("denial", func(t *testing.T) {
		value := start(t)
		interaction := correlate(t, value)
		advance(t, value)
		if err := value.server.DenyAuthorizationInteraction(context.Background(), interaction); !errors.Is(err, ErrPendingAuthorizationExpired) {
			t.Fatalf("denial at deadline = %v", err)
		}
		assertExpiredState(t, value)
	})
	t.Run("poll is one canonical terminal delivery", func(t *testing.T) {
		value := start(t)
		advance(t, value)
		first := value.protocol.poll(t, value.server, value.response.Header().Get("Location"), value.protocol.agentKey, value.protocol.agentToken)
		assertAuthorizationInteractionProblem(t, first, http.StatusRequestTimeout, "expired")
		second := value.protocol.poll(t, value.server, value.response.Header().Get("Location"), value.protocol.agentKey, value.protocol.agentToken)
		assertAuthorizationInteractionProblem(t, second, http.StatusGone, "invalid_code")
	})
}

func TestDeferredAuthorizationTerminalStateCommittedBeforeDeadlineHasPrecedence(t *testing.T) {
	for _, terminal := range []string{"approved", "denied", "abandoned", "server error"} {
		t.Run(terminal, func(t *testing.T) {
			protocol := newAuthorizationInteractionProtocol(t)
			store := newMemoryDeferredAuthorizationStore()
			server := protocol.newServer(t, store)
			response := protocol.exchange(t, server, []string{"interaction"})
			requirement, _ := aauth.ParseInteractionRequirement(response.Header().Values("AAuth-Requirement"))
			reference := strings.TrimPrefix(requirement.URL, protocol.interactionURL+"/")
			interaction, err := server.ConsumeAuthorizationInteractionCode(context.Background(), reference, requirement.Code)
			if err != nil {
				t.Fatal(err)
			}
			switch terminal {
			case "approved":
				err = server.ApproveAuthorizationInteraction(context.Background(), interaction, AuthorizationDecision{
					Scopes: []string{"records.read"}, Lifetime: 10 * time.Minute,
				})
			case "denied":
				err = server.DenyAuthorizationInteraction(context.Background(), interaction)
			case "abandoned":
				err = server.AbandonAuthorizationInteraction(context.Background(), interaction)
			case "server error":
				err = server.FailAuthorizationInteraction(context.Background(), interaction)
			}
			if err != nil {
				t.Fatal(err)
			}
			protocol.now = store.onlyPending(t).ExpiresAt
			resumed, resumeErr := server.ResumeAuthorizationInteraction(context.Background(), reference)
			if resumeErr != nil || resumed.Reference() != reference {
				t.Fatalf("%s resume after deadline = %#v, %v", terminal, resumed, resumeErr)
			}
			poll := protocol.poll(t, server, response.Header().Get("Location"), protocol.agentKey, protocol.agentToken)
			switch terminal {
			case "approved":
				if poll.Code != http.StatusOK {
					t.Fatalf("approved terminal changed after deadline = %d %s", poll.Code, poll.Body.String())
				}
			case "denied":
				assertAuthorizationInteractionProblem(t, poll, http.StatusForbidden, "denied")
			case "abandoned":
				assertAuthorizationInteractionProblem(t, poll, http.StatusForbidden, "abandoned")
			case "server error":
				assertAuthorizationInteractionProblem(t, poll, http.StatusInternalServerError, "server_error")
			}
		})
	}
}

func TestDeferredAuthorizationDecisionRacesAndDeadlineAreTerminal(t *testing.T) {
	protocol := newAuthorizationInteractionProtocol(t)
	store := newMemoryDeferredAuthorizationStore()
	server := protocol.newServer(t, store)
	response := protocol.exchange(t, server, []string{"interaction"})
	requirement, _ := aauth.ParseInteractionRequirement(response.Header().Values("AAuth-Requirement"))
	reference := strings.TrimPrefix(requirement.URL, protocol.interactionURL+"/")
	value, err := server.ConsumeAuthorizationInteractionCode(context.Background(), reference, requirement.Code)
	if err != nil {
		t.Fatal(err)
	}
	decision := AuthorizationDecision{Scopes: []string{"records.read"}, Lifetime: time.Minute}
	var approvals, denials atomic.Int32
	start := make(chan struct{})
	var wait sync.WaitGroup
	for _, approve := range []bool{true, false} {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			var err error
			if approve {
				err = server.ApproveAuthorizationInteraction(context.Background(), value, decision)
				if err == nil {
					approvals.Add(1)
				}
			} else {
				err = server.DenyAuthorizationInteraction(context.Background(), value)
				if err == nil {
					denials.Add(1)
				}
			}
			if err != nil && !errors.Is(err, ErrPendingAuthorizationConflict) {
				t.Errorf("competing decision = %v", err)
			}
		}()
	}
	close(start)
	wait.Wait()
	if approvals.Load()+denials.Load() != 1 {
		t.Fatalf("decision winners: approvals=%d denials=%d", approvals.Load(), denials.Load())
	}
	if snapshot, err := store.LoadPendingAuthorization(context.Background(), reference, protocol.now); err != nil ||
		(snapshot.State != AuthorizationPollApproved && snapshot.State != AuthorizationPollDenied) {
		t.Fatalf("retained race result = %#v, %v", snapshot, err)
	}

	protocol = newAuthorizationInteractionProtocol(t)
	store = newMemoryDeferredAuthorizationStore()
	server = protocol.newServer(t, store)
	response = protocol.exchange(t, server, []string{"interaction"})
	requirement, _ = aauth.ParseInteractionRequirement(response.Header().Values("AAuth-Requirement"))
	reference = strings.TrimPrefix(requirement.URL, protocol.interactionURL+"/")
	value, err = server.ConsumeAuthorizationInteractionCode(context.Background(), reference, requirement.Code)
	if err != nil {
		t.Fatal(err)
	}
	protocol.now = value.ExpiresAt()
	if err := server.ApproveAuthorizationInteraction(context.Background(), value, decision); !errors.Is(err, ErrPendingAuthorizationExpired) {
		t.Fatalf("approval at deadline = %v", err)
	}
	if protocol.tokenIDCalls() != 0 {
		t.Fatalf("deadline minted %d tokens", protocol.tokenIDCalls())
	}
	location := response.Header().Get("Location")
	expired := protocol.poll(t, server, location, protocol.agentKey, protocol.agentTokenAt(t, protocol.now.Add(time.Minute), "deadline-agent"))
	assertAuthorizationInteractionProblem(t, expired, http.StatusRequestTimeout, "expired")
	if err := server.ApproveAuthorizationInteraction(context.Background(), value, decision); !errors.Is(err, ErrPendingAuthorizationGone) && !errors.Is(err, ErrPendingAuthorizationExpired) && !errors.Is(err, ErrPendingAuthorizationConflict) {
		t.Fatalf("late approval rewrote terminal state: %v", err)
	}
}

func TestDeferredAuthorizationExplicitHostTerminalOutcomes(t *testing.T) {
	for _, test := range []struct {
		name       string
		status     int
		problem    string
		transition func(*Server, context.Context, AuthorizationInteraction) error
	}{
		{
			name: "abandoned", status: http.StatusForbidden, problem: "abandoned",
			transition: func(server *Server, ctx context.Context, value AuthorizationInteraction) error {
				host, ok := any(server).(interface {
					AbandonAuthorizationInteraction(context.Context, AuthorizationInteraction) error
				})
				if !ok {
					return errors.New("Person Server does not expose an abandoned transition")
				}
				return host.AbandonAuthorizationInteraction(ctx, value)
			},
		},
		{
			name: "server error", status: http.StatusInternalServerError, problem: "server_error",
			transition: func(server *Server, ctx context.Context, value AuthorizationInteraction) error {
				host, ok := any(server).(interface {
					FailAuthorizationInteraction(context.Context, AuthorizationInteraction) error
				})
				if !ok {
					return errors.New("Person Server does not expose a server-error transition")
				}
				return host.FailAuthorizationInteraction(ctx, value)
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			protocol := newAuthorizationInteractionProtocol(t)
			store := newMemoryDeferredAuthorizationStore()
			server := protocol.newServer(t, store)
			response := protocol.exchange(t, server, []string{"interaction"})
			requirement, err := aauth.ParseInteractionRequirement(response.Header().Values("AAuth-Requirement"))
			if err != nil {
				t.Fatal(err)
			}
			reference := strings.TrimPrefix(requirement.URL, protocol.interactionURL+"/")
			value, err := server.ConsumeAuthorizationInteractionCode(context.Background(), reference, requirement.Code)
			if err != nil {
				t.Fatal(err)
			}
			if err := test.transition(server, context.Background(), value); err != nil {
				t.Fatalf("record %s: %v", test.name, err)
			}
			resumed, err := server.ResumeAuthorizationInteraction(context.Background(), reference)
			if err != nil {
				t.Fatalf("resume retained %s: %v", test.name, err)
			}
			if err := test.transition(server, context.Background(), resumed); err != nil {
				t.Fatalf("repeat retained %s: %v", test.name, err)
			}

			first := protocol.poll(t, server, response.Header().Get("Location"), protocol.agentKey, protocol.agentToken)
			assertAuthorizationInteractionProblem(t, first, test.status, test.problem)
			second := protocol.poll(t, server, response.Header().Get("Location"), protocol.agentKey, protocol.agentToken)
			assertAuthorizationInteractionProblem(t, second, http.StatusGone, "invalid_code")
		})
	}
}

func TestDeferredAuthorizationPollRejectsIdentityTheftAndMalformedResults(t *testing.T) {
	protocol := newAuthorizationInteractionProtocol(t)
	store := newMemoryDeferredAuthorizationStore()
	server := protocol.newServer(t, store)
	response := protocol.exchange(t, server, []string{"interaction"})
	location := response.Header().Get("Location")
	requirement, _ := aauth.ParseInteractionRequirement(response.Header().Values("AAuth-Requirement"))
	reference := strings.TrimPrefix(requirement.URL, protocol.interactionURL+"/")
	value, err := server.ConsumeAuthorizationInteractionCode(context.Background(), reference, requirement.Code)
	if err != nil {
		t.Fatal(err)
	}
	if err := server.ApproveAuthorizationInteraction(context.Background(), value, AuthorizationDecision{Scopes: []string{"records.read"}, Lifetime: time.Minute}); err != nil {
		t.Fatal(err)
	}

	thiefKey := personServerTestKey(t, "authorization-thief")
	thiefToken := protocol.agentTokenWith(t, protocol.agentID, thiefKey, protocol.now.Add(30*time.Minute), "thief-token")
	stolen := protocol.poll(t, server, location, thiefKey, thiefToken)
	assertAuthorizationInteractionProblem(t, stolen, http.StatusGone, "invalid_code")
	store.pollError = errors.New("retained authorization unavailable")
	storeFailure := protocol.poll(t, server, location, protocol.agentKey, protocol.agentToken)
	assertAuthorizationInteractionProblem(t, storeFailure, http.StatusInternalServerError, "server_error")
	if store.consumeCalls != 0 {
		t.Fatalf("store read failure was consumed %d times", store.consumeCalls)
	}

	store.pollOverride = &AuthorizationPollRecord{State: AuthorizationPollApproved, RetryAfter: 3 * time.Second}
	malformed := protocol.poll(t, server, location, protocol.agentKey, protocol.agentToken)
	assertAuthorizationInteractionProblem(t, malformed, http.StatusInternalServerError, "server_error")
	if store.consumeCalls != 0 {
		t.Fatalf("malformed result was consumed %d times", store.consumeCalls)
	}
	canonical := store.approvedPoll(t)
	substituted, err := aauth.MintAuthToken(protocol.personKey, aauth.AuthTokenClaims{
		Issuer: protocol.personServerID, DWK: aauth.PersonDiscoveryDocument,
		Audience: "https://other-resource.example", JTI: "substituted-auth-token",
		PersonServer: protocol.personServerID, Subject: protocol.subject,
		Confirmation: aauth.Confirmation{JWK: protocol.agentKey.PublicJWK()},
		IssuedAt:     canonical.DecidedAt.Unix(), ExpiresAt: canonical.DecidedAt.Add(time.Minute).Unix(),
		Scope: "records.read", Tenant: protocol.tenant,
	})
	if err != nil {
		t.Fatal(err)
	}
	canonical.Token = substituted
	store.pollOverride = &canonical
	tokenSubstitution := protocol.poll(t, server, location, protocol.agentKey, protocol.agentToken)
	assertAuthorizationInteractionProblem(t, tokenSubstitution, http.StatusInternalServerError, "server_error")
	if store.consumeCalls != 0 {
		t.Fatalf("substituted token was consumed %d times", store.consumeCalls)
	}
	mutated := store.approvedPoll(t)
	mutated.Pending.Subject = "another-person"
	store.pollOverride = &mutated
	contextMutation := protocol.poll(t, server, location, protocol.agentKey, protocol.agentToken)
	assertAuthorizationInteractionProblem(t, contextMutation, http.StatusInternalServerError, "server_error")
	if store.consumeCalls != 0 {
		t.Fatalf("mutated context was consumed %d times", store.consumeCalls)
	}
	store.consumeError = errors.New("terminal compare unavailable")
	consumeFailure := protocol.poll(t, server, location, protocol.agentKey, protocol.agentToken)
	assertAuthorizationInteractionProblem(t, consumeFailure, http.StatusInternalServerError, "server_error")
	if store.consumeCalls != 0 {
		t.Fatalf("store consume failure changed consume count to %d", store.consumeCalls)
	}
	valid := protocol.poll(t, server, location, protocol.agentKey, protocol.agentToken)
	if valid.Code != http.StatusOK {
		t.Fatalf("valid result after malformed store output = %d %s", valid.Code, valid.Body.String())
	}
}

func TestDeferredAuthorizationNonApprovalTerminalStatesCannotBeApproved(t *testing.T) {
	for _, terminal := range []string{"denied", "abandoned", "server error"} {
		t.Run(terminal, func(t *testing.T) {
			protocol := newAuthorizationInteractionProtocol(t)
			store := newMemoryDeferredAuthorizationStore()
			server := protocol.newServer(t, store)
			response := protocol.exchange(t, server, []string{"interaction"})
			requirement, _ := aauth.ParseInteractionRequirement(response.Header().Values("AAuth-Requirement"))
			reference := strings.TrimPrefix(requirement.URL, protocol.interactionURL+"/")
			value, err := server.ConsumeAuthorizationInteractionCode(context.Background(), reference, requirement.Code)
			if err != nil {
				t.Fatal(err)
			}
			switch terminal {
			case "denied":
				err = server.DenyAuthorizationInteraction(context.Background(), value)
			case "abandoned":
				err = server.AbandonAuthorizationInteraction(context.Background(), value)
			case "server error":
				err = server.FailAuthorizationInteraction(context.Background(), value)
			}
			if err != nil {
				t.Fatal(err)
			}
			decision := AuthorizationDecision{Scopes: []string{"records.read"}, Lifetime: time.Minute}
			if err := server.ApproveAuthorizationInteraction(context.Background(), value, decision); err == nil {
				t.Fatal("terminal state accepted a late approval")
			}
			if protocol.tokenIDCalls() != 0 {
				t.Fatalf("late approval minted %d tokens", protocol.tokenIDCalls())
			}
			poll := protocol.poll(t, server, response.Header().Get("Location"), protocol.agentKey, protocol.agentToken)
			switch terminal {
			case "denied":
				assertAuthorizationInteractionProblem(t, poll, http.StatusForbidden, "denied")
			case "abandoned":
				assertAuthorizationInteractionProblem(t, poll, http.StatusForbidden, "abandoned")
			case "server error":
				assertAuthorizationInteractionProblem(t, poll, http.StatusInternalServerError, "server_error")
			}
			gone := protocol.poll(t, server, response.Header().Get("Location"), protocol.agentKey, protocol.agentToken)
			assertAuthorizationInteractionProblem(t, gone, http.StatusGone, "invalid_code")
		})
	}
}

func TestDeferredAuthorizationCodeAndReferenceArePersonServerBound(t *testing.T) {
	protocol := newAuthorizationInteractionProtocol(t)
	store := newMemoryDeferredAuthorizationStore()
	server := protocol.newServer(t, store)
	response := protocol.exchange(t, server, []string{"interaction"})
	requirement, _ := aauth.ParseInteractionRequirement(response.Header().Values("AAuth-Requirement"))
	reference := strings.TrimPrefix(requirement.URL, protocol.interactionURL+"/")
	if _, err := server.ConsumeAuthorizationInteractionCode(context.Background(), "wrong-reference", requirement.Code); !errors.Is(err, ErrAuthorizationInteractionCodeInvalid) {
		t.Fatalf("wrong reference = %v", err)
	}
	if _, err := server.ConsumeAuthorizationInteractionCode(context.Background(), reference, "0000-0000"); !errors.Is(err, ErrAuthorizationInteractionCodeInvalid) {
		t.Fatalf("wrong code = %v", err)
	}
	config := protocol.config(store)
	config.Issuer = "https://other-person.example"
	otherServer, err := NewPSAuthorization(config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := otherServer.ConsumeAuthorizationInteractionCode(context.Background(), reference, requirement.Code); !errors.Is(err, ErrAuthorizationInteractionCodeInvalid) {
		t.Fatalf("wrong Person Server code use = %v", err)
	}
	if _, err := otherServer.ResumeAuthorizationInteraction(context.Background(), reference); err == nil {
		t.Fatal("another Person Server resumed the pending authorization")
	}
}

func TestDeferredAuthorizationStoreConcurrentExactApprovalConverges(t *testing.T) {
	protocol := newAuthorizationInteractionProtocol(t)
	store := newMemoryDeferredAuthorizationStore()
	server := protocol.newServer(t, store)
	response := protocol.exchange(t, server, []string{"interaction"})
	requirement, _ := aauth.ParseInteractionRequirement(response.Header().Values("AAuth-Requirement"))
	reference := strings.TrimPrefix(requirement.URL, protocol.interactionURL+"/")
	if _, err := server.ConsumeAuthorizationInteractionCode(context.Background(), reference, requirement.Code); err != nil {
		t.Fatal(err)
	}
	decision := AuthorizationDecision{Scopes: []string{"records.read"}, Lifetime: time.Minute}
	if _, err := store.ApprovePendingAuthorization(context.Background(), reference, AuthorizationApproval{
		Decision: decision,
	}); err == nil {
		t.Fatal("store accepted an incomplete first approval proposal")
	}
	approvals := []AuthorizationApproval{
		{Decision: decision, Token: "first-token", ExpiresIn: 60, DecidedAt: protocol.now},
		{Decision: decision, Token: "second-token", ExpiresIn: 60, DecidedAt: protocol.now},
	}
	start := make(chan struct{})
	errorsOut := make(chan error, len(approvals))
	for _, approval := range approvals {
		approval := approval
		go func() {
			<-start
			_, err := store.ApprovePendingAuthorization(context.Background(), reference, approval)
			errorsOut <- err
		}()
	}
	close(start)
	for range approvals {
		if err := <-errorsOut; err != nil {
			t.Fatalf("exact concurrent approval = %v", err)
		}
	}
	result := store.approvedPoll(t)
	if result.Token != "first-token" && result.Token != "second-token" {
		t.Fatalf("retained token = %q", result.Token)
	}
	first := result.Token
	canonical, err := store.ApprovePendingAuthorization(context.Background(), reference, AuthorizationApproval{
		Decision: decision, Token: "third-token", ExpiresIn: 60, DecidedAt: protocol.now,
	})
	if err != nil {
		t.Fatal(err)
	}
	if canonical.Token != first {
		t.Fatalf("canonical retry token = %q, want %q", canonical.Token, first)
	}
	if result := store.approvedPoll(t); result.Token != first {
		t.Fatalf("exact retry replaced %q with %q", first, result.Token)
	}
}

func TestDeferredAuthorizationServerConcurrentSemanticApprovalDeliversOneCanonicalToken(t *testing.T) {
	protocol := newAuthorizationInteractionProtocol(t)
	store := newMemoryDeferredAuthorizationStore()
	server := protocol.newServer(t, store)
	response := protocol.exchange(t, server, []string{"interaction"})
	requirement, _ := aauth.ParseInteractionRequirement(response.Header().Values("AAuth-Requirement"))
	reference := strings.TrimPrefix(requirement.URL, protocol.interactionURL+"/")
	value, err := server.ConsumeAuthorizationInteractionCode(context.Background(), reference, requirement.Code)
	if err != nil {
		t.Fatal(err)
	}
	decisions := []AuthorizationDecision{
		{Scopes: []string{"records.read", "records.write"}, Lifetime: time.Minute},
		{Scopes: []string{"records.write", "records.read"}, Lifetime: time.Minute},
	}
	start := make(chan struct{})
	results := make(chan error, len(decisions))
	for _, decision := range decisions {
		decision := decision
		go func() {
			<-start
			results <- server.ApproveAuthorizationInteraction(context.Background(), value, decision)
		}()
	}
	close(start)
	for range decisions {
		if err := <-results; err != nil {
			t.Fatalf("semantic concurrent approval = %v", err)
		}
	}
	if calls := protocol.tokenIDCalls(); calls < 1 || calls > len(decisions) {
		t.Fatalf("token ID allocations = %d", calls)
	}
	canonical := store.approvedPoll(t)
	poll := protocol.poll(t, server, response.Header().Get("Location"), protocol.agentKey, protocol.agentToken)
	if poll.Code != http.StatusOK {
		t.Fatalf("canonical poll = %d %s", poll.Code, poll.Body.String())
	}
	var output struct {
		AuthToken string `json:"auth_token"`
	}
	if err := json.NewDecoder(poll.Body).Decode(&output); err != nil {
		t.Fatal(err)
	}
	if output.AuthToken != canonical.Token {
		t.Fatalf("delivered token differs from canonical winner")
	}
	claims, err := aauth.VerifyAuthToken(context.Background(), output.AuthToken, protocol.resolver, protocol.clock)
	if err != nil {
		t.Fatal(err)
	}
	if claims.Scope != strings.Join(canonical.Decision.Scopes, " ") {
		t.Fatalf("delivered scope = %q, canonical decision = %#v", claims.Scope, canonical.Decision)
	}
	gone := protocol.poll(t, server, response.Header().Get("Location"), protocol.agentKey, protocol.agentToken)
	assertAuthorizationInteractionProblem(t, gone, http.StatusGone, "invalid_code")
}

func TestDeferredAuthorizationServerValidatesCanonicalApprovalBeforeSuccess(t *testing.T) {
	protocol := newAuthorizationInteractionProtocol(t)
	store := newMemoryDeferredAuthorizationStore()
	server := protocol.newServer(t, store)
	response := protocol.exchange(t, server, []string{"interaction"})
	requirement, _ := aauth.ParseInteractionRequirement(response.Header().Values("AAuth-Requirement"))
	reference := strings.TrimPrefix(requirement.URL, protocol.interactionURL+"/")
	value, err := server.ConsumeAuthorizationInteractionCode(context.Background(), reference, requirement.Code)
	if err != nil {
		t.Fatal(err)
	}
	decision := AuthorizationDecision{Scopes: []string{"records.read"}, Lifetime: time.Minute}
	store.approveReturnChange = func(canonical *AuthorizationApproval) { canonical.Token = "" }
	if err := server.ApproveAuthorizationInteraction(context.Background(), value, decision); err == nil {
		t.Fatal("server accepted malformed canonical approval")
	}
	if calls := protocol.tokenIDCalls(); calls != 1 {
		t.Fatalf("first approval token ID allocations = %d", calls)
	}
	store.approveReturnChange = nil
	if err := server.ApproveAuthorizationInteraction(context.Background(), value, decision); err != nil {
		t.Fatalf("canonical approval recovery = %v", err)
	}
	if calls := protocol.tokenIDCalls(); calls != 1 {
		t.Fatalf("canonical recovery allocated another token ID: %d", calls)
	}
	poll := protocol.poll(t, server, response.Header().Get("Location"), protocol.agentKey, protocol.agentToken)
	if poll.Code != http.StatusOK {
		t.Fatalf("retained canonical poll = %d %s", poll.Code, poll.Body.String())
	}
}

type authorizationInteractionProtocol struct {
	t                   *testing.T
	now                 time.Time
	clock               aauth.Clock
	providerKey         jose.SigningKey
	personKey           jose.SigningKey
	resourceKey         jose.SigningKey
	agentKey            jose.SigningKey
	resolver            signaturekey.KeyResolver
	agentToken          string
	resourceToken       string
	providerID          string
	personServerID      string
	resourceID          string
	agentID             string
	subject             string
	tenant              string
	interactionURL      string
	requireInteraction  bool
	policyCalls         int
	authorizeCalls      int
	newIDMu             sync.Mutex
	newIDCalls          int
	lastAuthorization   AuthorizationRequest
	requestCapabilities []string
}

func newAuthorizationInteractionProtocol(t *testing.T) *authorizationInteractionProtocol {
	t.Helper()
	p := &authorizationInteractionProtocol{
		t: t, now: time.Date(2026, 8, 30, 21, 0, 0, 0, time.UTC),
		providerID: "https://provider.example", personServerID: "https://person.example",
		resourceID: "https://resource.example", agentID: "aauth:planner@provider.example",
		subject: "person-123", tenant: "tenant-1", interactionURL: "https://person.example/authorize",
		requireInteraction: true,
	}
	p.clock = aauth.ClockFunc(func() time.Time { return p.now })
	p.providerKey = personServerTestKey(t, "authorization-provider")
	p.personKey = personServerTestKey(t, "authorization-person")
	p.resourceKey = personServerTestKey(t, "authorization-resource")
	p.agentKey = personServerTestKey(t, "authorization-agent")
	p.resolver = signaturekey.StaticKeyResolver{
		{Issuer: p.providerID, DiscoveryDocument: aauth.AgentDiscoveryDocument, KeyID: p.providerKey.ID()}:    p.providerKey.PublicJWK(),
		{Issuer: p.personServerID, DiscoveryDocument: aauth.PersonDiscoveryDocument, KeyID: p.personKey.ID()}: p.personKey.PublicJWK(),
		{Issuer: p.resourceID, DiscoveryDocument: aauth.ResourceDiscoveryDocument, KeyID: p.resourceKey.ID()}: p.resourceKey.PublicJWK(),
	}
	p.agentToken = p.agentTokenAt(t, p.now.Add(30*time.Minute), "authorization-agent-token")
	thumbprint, err := p.agentKey.PublicJWK().Thumbprint()
	if err != nil {
		t.Fatal(err)
	}
	p.resourceToken, err = aauth.MintResourceToken(p.resourceKey, aauth.ResourceTokenClaims{
		Issuer: p.resourceID, DWK: aauth.ResourceDiscoveryDocument, Audience: p.personServerID,
		JTI: "authorization-resource-token", PersonServer: p.personServerID, Subject: p.subject,
		PresentedJTI: "authorization-person-token", AgentJKT: thumbprint,
		IssuedAt: p.now.Unix(), ExpiresAt: p.now.Add(5 * time.Minute).Unix(),
		Scope: "records.read records.write", Tenant: p.tenant,
	})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func (p *authorizationInteractionProtocol) agentTokenAt(t *testing.T, expiry time.Time, id string) string {
	t.Helper()
	return p.agentTokenWith(t, p.agentID, p.agentKey, expiry, id)
}

func (p *authorizationInteractionProtocol) agentTokenWith(t *testing.T, agent string, key jose.SigningKey, expiry time.Time, id string) string {
	t.Helper()
	token, err := aauth.MintAgentToken(p.providerID, p.providerKey, aauth.AgentTokenRequest{
		Agent: agent, PersonServer: p.personServerID, PublicKey: key.PublicJWK(), Lifetime: expiry.Sub(p.now),
		AdditionalClaims: map[string]json.RawMessage{"platform_attestation": json.RawMessage(`{"level":"example"}`)},
	}, p.now, id)
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func (p *authorizationInteractionProtocol) nextTokenID() string {
	p.newIDMu.Lock()
	defer p.newIDMu.Unlock()
	p.newIDCalls++
	return fmt.Sprintf("authorization-auth-token-%d", p.newIDCalls)
}

func (p *authorizationInteractionProtocol) tokenIDCalls() int {
	p.newIDMu.Lock()
	defer p.newIDMu.Unlock()
	return p.newIDCalls
}

func (p *authorizationInteractionProtocol) config(store DeferredAuthorizationStore) PSAuthorizationConfig {
	tokens := newMemoryTokenStore()
	if err := tokens.Commit(context.Background(), directPersonTokenRecord(
		"authorization-person-token", p.personServerID, p.resourceID, p.subject, p.tenant,
		p.providerID, p.agentID, p.agentKey.PublicJWK(), p.now.Add(20*time.Minute), p.now.Add(25*time.Minute),
	)); err != nil {
		p.t.Fatal(err)
	}
	config := PSAuthorizationConfig{
		Issuer: p.personServerID, SigningKey: p.personKey, KeyResolver: p.resolver, Clock: p.clock,
		NewID: p.nextTokenID, Tokens: tokens,
		BindPerson: func(context.Context, PersonTokenRequest) (Person, error) { return Person{}, nil },
		Authorize: func(_ context.Context, request AuthorizationRequest) (AuthorizationDecision, error) {
			p.authorizeCalls++
			p.lastAuthorization = request
			p.requestCapabilities = append([]string(nil), request.Capabilities...)
			return AuthorizationDecision{Scopes: []string{"records.read"}, Lifetime: 10 * time.Minute}, nil
		},
	}
	if store != nil {
		config.AuthorizationInteractions = store
		config.RequireAuthorizationInteraction = func(_ context.Context, request AuthorizationRequest) (AuthorizationInteractionPolicy, bool, error) {
			p.policyCalls++
			p.lastAuthorization = request
			p.requestCapabilities = append([]string(nil), request.Capabilities...)
			return AuthorizationInteractionPolicy{
				URL: p.interactionURL, Lifetime: 4 * time.Minute, RetryAfter: 3 * time.Second,
			}, p.requireInteraction, nil
		}
	}
	return config
}

func (p *authorizationInteractionProtocol) newServer(t *testing.T, store DeferredAuthorizationStore) *Server {
	t.Helper()
	server, err := NewPSAuthorization(p.config(store))
	if err != nil {
		t.Fatal(err)
	}
	return server
}

func (p *authorizationInteractionProtocol) exchange(t *testing.T, server *Server, capabilities []string) *httptest.ResponseRecorder {
	t.Helper()
	body := map[string]any{"resource_token": p.resourceToken}
	if capabilities != nil {
		body["capabilities"] = capabilities
	}
	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	return p.exchangeBody(t, server, string(encoded))
}

func (p *authorizationInteractionProtocol) exchangeBody(t *testing.T, server *Server, body string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, p.personServerID+"/token", bytes.NewBufferString(body))
	request.Header.Set("Content-Type", "application/json")
	if err := signPersonServerTestRequest(request, p.agentKey, p.agentToken, p.clock); err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	return response
}

func (p *authorizationInteractionProtocol) poll(t *testing.T, server *Server, location string, key jose.SigningKey, token string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodGet, p.personServerID+location, nil)
	if err := signaturekey.SignJWTRequest(request, key, token, p.clock); err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	return response
}

func assertAuthorizationInteractionProblem(t *testing.T, response *httptest.ResponseRecorder, status int, code string) {
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

func differentValidAuthorizationCode(t *testing.T, code string) string {
	t.Helper()
	for index := range code {
		if code[index] == '-' {
			continue
		}
		replacement := byte('0')
		if code[index] == replacement {
			replacement = '1'
		}
		changed := []byte(code)
		changed[index] = replacement
		if _, err := interaction.Digest(string(changed)); err != nil {
			t.Fatal(err)
		}
		return string(changed)
	}
	t.Fatal("interaction code has no symbols")
	return ""
}

type memoryDeferredAuthorizationStore struct {
	mu                         sync.Mutex
	pending                    map[string]*memoryPendingAuthorization
	byCode                     map[[32]byte]string
	pollOverride               *AuthorizationPollRecord
	pollError                  error
	consumeError               error
	approveReturnChange        func(*AuthorizationApproval)
	invalidPresentationSuccess bool
	consumeCalls               int
}

type memoryPendingAuthorization struct {
	record             PendingAuthorizationRecord
	state              AuthorizationPollState
	approval           AuthorizationApproval
	deniedAt           time.Time
	failedCodeAttempts int
}

func newMemoryDeferredAuthorizationStore() *memoryDeferredAuthorizationStore {
	return &memoryDeferredAuthorizationStore{pending: make(map[string]*memoryPendingAuthorization), byCode: make(map[[32]byte]string)}
}

func (store *memoryDeferredAuthorizationStore) CreatePendingAuthorization(_ context.Context, record PendingAuthorizationRecord) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if _, exists := store.pending[record.ID]; exists {
		return ErrPendingAuthorizationConflict
	}
	if _, exists := store.byCode[record.CodeSHA256]; exists {
		return ErrPendingAuthorizationConflict
	}
	store.pending[record.ID] = &memoryPendingAuthorization{record: clonePendingAuthorizationRecord(record), state: AuthorizationPollWaiting}
	store.byCode[record.CodeSHA256] = record.ID
	return nil
}

func (store *memoryDeferredAuthorizationStore) ConsumeAuthorizationInteractionCode(_ context.Context, personServer, reference string, presentation AuthorizationCodePresentation, now time.Time) (PendingAuthorizationRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	pending, ok := store.pending[reference]
	if !ok || pending.record.PersonServer != personServer {
		return PendingAuthorizationRecord{}, ErrAuthorizationInteractionCodeInvalid
	}
	materializeMemoryAuthorizationExpiry(pending, now)
	switch pending.state {
	case AuthorizationPollGone:
		return PendingAuthorizationRecord{}, ErrPendingAuthorizationGone
	case AuthorizationPollExpired:
		return PendingAuthorizationRecord{}, ErrPendingAuthorizationExpired
	case AuthorizationPollInteracting:
		return PendingAuthorizationRecord{}, ErrAuthorizationInteractionCodeUsed
	case AuthorizationPollApproved, AuthorizationPollDenied, AuthorizationPollAbandoned, AuthorizationPollServerError:
		return PendingAuthorizationRecord{}, ErrAuthorizationInteractionCodeUsed
	}
	if !presentation.SyntacticallyValid && store.invalidPresentationSuccess {
		return clonePendingAuthorizationRecord(pending.record), nil
	}
	if !presentation.SyntacticallyValid || pending.record.CodeSHA256 != presentation.CodeSHA256 {
		pending.failedCodeAttempts++
		if pending.failedCodeAttempts >= MaximumAuthorizationCodeAttempts {
			pending.failedCodeAttempts = MaximumAuthorizationCodeAttempts
			pending.state = AuthorizationPollGone
			return PendingAuthorizationRecord{}, ErrPendingAuthorizationGone
		}
		return PendingAuthorizationRecord{}, ErrAuthorizationInteractionCodeInvalid
	}
	if pending.state != AuthorizationPollWaiting {
		return PendingAuthorizationRecord{}, ErrAuthorizationInteractionCodeUsed
	}
	pending.state = AuthorizationPollInteracting
	return clonePendingAuthorizationRecord(pending.record), nil
}

func (store *memoryDeferredAuthorizationStore) LoadPendingAuthorization(_ context.Context, id string, now time.Time) (PendingAuthorizationSnapshot, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	pending, ok := store.pending[id]
	if !ok {
		return PendingAuthorizationSnapshot{}, ErrPendingAuthorizationNotFound
	}
	materializeMemoryAuthorizationExpiry(pending, now)
	snapshot := PendingAuthorizationSnapshot{Record: clonePendingAuthorizationRecord(pending.record), State: pending.state}
	if pending.state == AuthorizationPollApproved {
		snapshot.Approval = cloneAuthorizationApproval(pending.approval)
	}
	return snapshot, nil
}

func (store *memoryDeferredAuthorizationStore) ApprovePendingAuthorization(_ context.Context, id string, approval AuthorizationApproval) (AuthorizationApproval, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	pending, ok := store.pending[id]
	if !ok {
		return AuthorizationApproval{}, ErrPendingAuthorizationNotFound
	}
	materializeMemoryAuthorizationExpiry(pending, approval.DecidedAt)
	if pending.state == AuthorizationPollApproved {
		if !authorizationDecisionsSemanticallyEqual(pending.approval.Decision, approval.Decision) {
			return AuthorizationApproval{}, ErrPendingAuthorizationConflict
		}
		canonical := cloneAuthorizationApproval(pending.approval)
		if store.approveReturnChange != nil {
			store.approveReturnChange(&canonical)
		}
		return canonical, nil
	}
	if pending.state == AuthorizationPollExpired {
		return AuthorizationApproval{}, ErrPendingAuthorizationExpired
	}
	if pending.state != AuthorizationPollInteracting {
		return AuthorizationApproval{}, ErrPendingAuthorizationConflict
	}
	if err := validateAuthorizationApprovalShape(pending.record, approval); err != nil {
		return AuthorizationApproval{}, ErrPendingAuthorizationConflict
	}
	pending.approval = cloneAuthorizationApproval(approval)
	pending.state = AuthorizationPollApproved
	canonical := cloneAuthorizationApproval(pending.approval)
	if store.approveReturnChange != nil {
		store.approveReturnChange(&canonical)
	}
	return canonical, nil
}

func (store *memoryDeferredAuthorizationStore) DenyPendingAuthorization(_ context.Context, id string, decidedAt time.Time) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	pending, ok := store.pending[id]
	if !ok {
		return ErrPendingAuthorizationNotFound
	}
	materializeMemoryAuthorizationExpiry(pending, decidedAt)
	if pending.state == AuthorizationPollDenied {
		return nil
	}
	if pending.state == AuthorizationPollExpired {
		return ErrPendingAuthorizationExpired
	}
	if pending.state != AuthorizationPollInteracting {
		return ErrPendingAuthorizationConflict
	}
	pending.deniedAt = decidedAt
	pending.state = AuthorizationPollDenied
	return nil
}

func (store *memoryDeferredAuthorizationStore) AbandonPendingAuthorization(_ context.Context, id string, now time.Time) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	pending, ok := store.pending[id]
	if !ok {
		return ErrPendingAuthorizationNotFound
	}
	materializeMemoryAuthorizationExpiry(pending, now)
	if pending.state == AuthorizationPollAbandoned {
		return nil
	}
	if pending.state == AuthorizationPollExpired {
		return ErrPendingAuthorizationExpired
	}
	if pending.state != AuthorizationPollInteracting {
		return ErrPendingAuthorizationConflict
	}
	pending.state = AuthorizationPollAbandoned
	return nil
}

func (store *memoryDeferredAuthorizationStore) FailPendingAuthorization(_ context.Context, id string, now time.Time) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	pending, ok := store.pending[id]
	if !ok {
		return ErrPendingAuthorizationNotFound
	}
	materializeMemoryAuthorizationExpiry(pending, now)
	if pending.state == AuthorizationPollServerError {
		return nil
	}
	if pending.state == AuthorizationPollExpired {
		return ErrPendingAuthorizationExpired
	}
	if pending.state != AuthorizationPollWaiting && pending.state != AuthorizationPollInteracting {
		return ErrPendingAuthorizationConflict
	}
	pending.state = AuthorizationPollServerError
	return nil
}

func (store *memoryDeferredAuthorizationStore) PollPendingAuthorization(_ context.Context, id string, identity AuthorizationPollIdentity, now time.Time) (AuthorizationPollRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	pending, ok := store.pending[id]
	if !ok {
		return AuthorizationPollRecord{}, ErrPendingAuthorizationNotFound
	}
	materializeMemoryAuthorizationExpiry(pending, now)
	wantThumbprint, _ := pending.record.Confirmation.Thumbprint()
	if identity.PersonServer != pending.record.PersonServer || identity.AgentProvider != pending.record.AgentProvider ||
		identity.Agent != pending.record.Agent || identity.ConfirmationThumbprint != wantThumbprint {
		return AuthorizationPollRecord{}, ErrPendingAuthorizationNotFound
	}
	if store.pollOverride != nil {
		result := cloneAuthorizationPollRecord(*store.pollOverride)
		store.pollOverride = nil
		return result, nil
	}
	if store.pollError != nil {
		err := store.pollError
		store.pollError = nil
		return AuthorizationPollRecord{}, err
	}
	if pending.state == AuthorizationPollGone {
		return AuthorizationPollRecord{}, ErrPendingAuthorizationGone
	}
	result := AuthorizationPollRecord{
		State: pending.state, Pending: clonePendingAuthorizationRecord(pending.record), RetryAfter: pending.record.RetryAfter,
	}
	if pending.state == AuthorizationPollApproved {
		result.Token = pending.approval.Token
		result.Decision = cloneAuthorizationDecision(pending.approval.Decision)
		result.ExpiresIn = pending.approval.ExpiresIn
		result.DecidedAt = pending.approval.DecidedAt
	}
	return result, nil
}

func (store *memoryDeferredAuthorizationStore) ConsumePendingAuthorizationResult(_ context.Context, id string, result AuthorizationPollRecord) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	pending, ok := store.pending[id]
	if !ok {
		return ErrPendingAuthorizationNotFound
	}
	if pending.state == AuthorizationPollGone {
		return ErrPendingAuthorizationGone
	}
	if store.consumeError != nil {
		err := store.consumeError
		store.consumeError = nil
		return err
	}
	want := AuthorizationPollRecord{
		State: pending.state, Pending: clonePendingAuthorizationRecord(pending.record), RetryAfter: pending.record.RetryAfter,
	}
	if pending.state == AuthorizationPollApproved {
		want.Token = pending.approval.Token
		want.Decision = cloneAuthorizationDecision(pending.approval.Decision)
		want.ExpiresIn = pending.approval.ExpiresIn
		want.DecidedAt = pending.approval.DecidedAt
	} else if pending.state != AuthorizationPollDenied && pending.state != AuthorizationPollAbandoned &&
		pending.state != AuthorizationPollServerError && pending.state != AuthorizationPollExpired {
		return ErrPendingAuthorizationConflict
	}
	if !reflect.DeepEqual(result, want) {
		return ErrPendingAuthorizationConflict
	}
	store.consumeCalls++
	pending.state = AuthorizationPollGone
	return nil
}

func (store *memoryDeferredAuthorizationStore) pendingCount() int {
	store.mu.Lock()
	defer store.mu.Unlock()
	return len(store.pending)
}

func (store *memoryDeferredAuthorizationStore) onlyPending(t *testing.T) PendingAuthorizationRecord {
	t.Helper()
	store.mu.Lock()
	defer store.mu.Unlock()
	if len(store.pending) != 1 {
		t.Fatalf("pending records = %d", len(store.pending))
	}
	for _, pending := range store.pending {
		return clonePendingAuthorizationRecord(pending.record)
	}
	panic("unreachable")
}

func (store *memoryDeferredAuthorizationStore) approvedPoll(t *testing.T) AuthorizationPollRecord {
	t.Helper()
	store.mu.Lock()
	defer store.mu.Unlock()
	if len(store.pending) != 1 {
		t.Fatalf("pending records = %d", len(store.pending))
	}
	for _, pending := range store.pending {
		if pending.state != AuthorizationPollApproved {
			t.Fatalf("pending state = %v", pending.state)
		}
		return AuthorizationPollRecord{
			State: AuthorizationPollApproved, Pending: clonePendingAuthorizationRecord(pending.record),
			Token: pending.approval.Token, Decision: cloneAuthorizationDecision(pending.approval.Decision),
			ExpiresIn: pending.approval.ExpiresIn, DecidedAt: pending.approval.DecidedAt,
			RetryAfter: pending.record.RetryAfter,
		}
	}
	panic("unreachable")
}

func (store *memoryDeferredAuthorizationStore) codeAttemptObservation(t *testing.T, id string) (AuthorizationPollState, int) {
	t.Helper()
	store.mu.Lock()
	defer store.mu.Unlock()
	pending, ok := store.pending[id]
	if !ok {
		t.Fatalf("pending %q not found", id)
	}
	return pending.state, pending.failedCodeAttempts
}

func materializeMemoryAuthorizationExpiry(pending *memoryPendingAuthorization, now time.Time) {
	if (pending.state == AuthorizationPollWaiting || pending.state == AuthorizationPollInteracting) &&
		!now.Before(pending.record.ExpiresAt) {
		pending.state = AuthorizationPollExpired
	}
}
