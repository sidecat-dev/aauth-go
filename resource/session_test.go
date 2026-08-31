package resource

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

func TestResourceManagedConstructorAndMetadataAreSessionOnly(t *testing.T) {
	t.Parallel()

	protocol := newResourceSessionProtocol(t)
	valid := protocol.config(newMemorySessionStore(), http.NotFoundHandler())
	for _, test := range []struct {
		name   string
		change func(*ResourceManagedConfig)
	}{
		{name: "issuer", change: func(config *ResourceManagedConfig) { config.Issuer = "" }},
		{name: "resolver", change: func(config *ResourceManagedConfig) { config.KeyResolver = nil }},
		{name: "clock", change: func(config *ResourceManagedConfig) { config.Clock = nil }},
		{name: "scope descriptions", change: func(config *ResourceManagedConfig) { config.ScopeDescriptions = nil }},
		{name: "invalid scope", change: func(config *ResourceManagedConfig) {
			config.ScopeDescriptions = map[string]string{"records read": "Read records"}
		}},
		{name: "blank description", change: func(config *ResourceManagedConfig) {
			config.ScopeDescriptions = map[string]string{"records.read": " \t"}
		}},
		{name: "invalid signature component", change: func(config *ResourceManagedConfig) {
			config.AdditionalSignatureComponents = []string{"X-Route-Proof"}
		}},
		{name: "duplicate signature component", change: func(config *ResourceManagedConfig) {
			config.AdditionalSignatureComponents = []string{"x-route-proof", "x-route-proof"}
		}},
		{name: "negative body limit", change: func(config *ResourceManagedConfig) { config.MaxSignedBodyBytes = -1 }},
		{name: "required scopes", change: func(config *ResourceManagedConfig) { config.RequiredScopes = nil }},
		{name: "interaction URL", change: func(config *ResourceManagedConfig) { config.Interaction.URL = "http://resource.example/interaction" }},
		{name: "interaction lifetime", change: func(config *ResourceManagedConfig) { config.Interaction.Lifetime = 0 }},
		{name: "interaction retry", change: func(config *ResourceManagedConfig) { config.Interaction.RetryAfter = -time.Second }},
		{name: "interaction retry fractional", change: func(config *ResourceManagedConfig) { config.Interaction.RetryAfter = time.Millisecond }},
		{name: "interaction attempt bound", change: func(config *ResourceManagedConfig) { config.Interaction.MaximumCodeAttempts = 0 }},
		{name: "sessions", change: func(config *ResourceManagedConfig) { config.Sessions = nil }},
		{name: "protected", change: func(config *ResourceManagedConfig) { config.Protected = nil }},
	} {
		t.Run(test.name, func(t *testing.T) {
			config := valid
			test.change(&config)
			if _, err := NewResourceManaged(config); err == nil {
				t.Fatal("NewResourceManaged accepted an invalid configuration")
			}
		})
	}
	valid.Random = nil // nil deliberately selects crypto/rand.
	server, err := NewResourceManaged(valid)
	if err != nil {
		t.Fatalf("nil Random: %v", err)
	}

	metadataResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(metadataResponse, httptest.NewRequest(
		http.MethodGet, protocol.resource+"/.well-known/aauth-resource.json", nil,
	))
	var metadata map[string]json.RawMessage
	if err := json.Unmarshal(metadataResponse.Body.Bytes(), &metadata); err != nil {
		t.Fatal(err)
	}
	if metadataResponse.Code != http.StatusOK || len(metadata) != 4 ||
		string(metadata["issuer"]) != `"https://resource.example"` ||
		string(metadata["access_mode"]) != `"session-token"` ||
		string(metadata["scope_descriptions"]) != `{"records.read":"Read records","records.write":"Write records"}` ||
		string(metadata["additional_signature_components"]) != `["x-route-proof"]` {
		t.Fatalf("metadata = %d %s", metadataResponse.Code, metadataResponse.Body.String())
	}
	for _, absent := range []string{"jwks_uri", "authorization_endpoint"} {
		if _, ok := metadata[absent]; ok {
			t.Fatalf("session-only metadata advertised %q: %s", absent, metadataResponse.Body.String())
		}
	}

	called := 0
	challengeServer, err := NewResourceManaged(protocol.config(newMemorySessionStore(), http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		called++
	})))
	if err != nil {
		t.Fatal(err)
	}
	challenge := httptest.NewRecorder()
	challengeServer.Handler().ServeHTTP(challenge, httptest.NewRequest(http.MethodGet, protocol.resource+"/records", nil))
	if challenge.Code != http.StatusUnauthorized || challenge.Header().Get("Signature-Error") != "" ||
		aauth.ParseAgentTokenRequirement(challenge.Header().Values("AAuth-Requirement")) != nil || called != 0 {
		t.Fatalf("missing-proof challenge = %d headers=%v body=%s called=%d", challenge.Code, challenge.Header(), challenge.Body.String(), called)
	}
}

func TestResourceManagedConfigAcceptsTheMinimalSessionStoreContract(t *testing.T) {
	t.Parallel()

	field, ok := reflect.TypeOf(ResourceManagedConfig{}).FieldByName("Sessions")
	if !ok {
		t.Fatal("ResourceManagedConfig has no Sessions field")
	}
	want := reflect.TypeOf((*SessionStore)(nil)).Elem()
	if field.Type != want {
		t.Fatalf("ResourceManagedConfig.Sessions type = %v, want %v", field.Type, want)
	}
}

func TestResourceManagedImmediateOnlyCompositionNeedsNoDeferredStore(t *testing.T) {
	t.Parallel()

	protocol := newResourceSessionProtocol(t)
	store := &minimalSessionStore{inner: newMemorySessionStore()}
	protected := 0
	config := protocol.config(newMemorySessionStore(), http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		protected++
		response.WriteHeader(http.StatusNoContent)
	}))
	config.Interaction = SessionInteractionPolicy{}
	config.Sessions = store
	config.AuthorizeImmediately = func(context.Context, SessionAuthorizationRequest) (SessionGrant, bool, error) {
		return SessionGrant{
			Subject: "person-123", Scope: []string{"records.read"}, Lifetime: 30 * time.Minute,
		}, true, nil
	}

	server, err := NewResourceManaged(config)
	if err != nil {
		t.Fatalf("NewResourceManaged immediate-only: %v", err)
	}
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, protocol.signedAgentRequest(
		t, protocol.agentKey, protocol.agentToken, http.MethodGet, "/records", false,
	))
	if response.Code != http.StatusNoContent || response.Header().Get("AAuth-Access") == "" || protected != 1 {
		t.Fatalf("immediate-only response = %d headers=%v body=%s protected=%d",
			response.Code, response.Header(), response.Body.String(), protected)
	}
}

func TestResourceManagedConfigurationSeparatesImmediateAndInteractiveDependencies(t *testing.T) {
	t.Parallel()

	protocol := newResourceSessionProtocol(t)
	minimal := &minimalSessionStore{inner: newMemorySessionStore()}

	t.Run("immediate policy required when interaction is disabled", func(t *testing.T) {
		config := protocol.config(newMemorySessionStore(), http.NotFoundHandler())
		config.Interaction = SessionInteractionPolicy{}
		config.Sessions = minimal
		config.AuthorizeImmediately = nil
		if _, err := NewResourceManaged(config); err == nil || !strings.Contains(err.Error(), "immediate authorization policy") {
			t.Fatalf("NewResourceManaged error = %v", err)
		}
	})

	t.Run("interaction requires deferred store", func(t *testing.T) {
		config := protocol.config(newMemorySessionStore(), http.NotFoundHandler())
		config.Sessions = minimal
		if _, err := NewResourceManaged(config); err == nil || !strings.Contains(err.Error(), "deferred session store") {
			t.Fatalf("NewResourceManaged error = %v", err)
		}
	})
}

func TestResourceManagedImmediateRefusalWithoutInteractionIsExplicit(t *testing.T) {
	t.Parallel()

	protocol := newResourceSessionProtocol(t)
	store := &minimalSessionStore{inner: newMemorySessionStore()}
	protected := 0
	config := protocol.config(newMemorySessionStore(), http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		protected++
	}))
	config.Interaction = SessionInteractionPolicy{}
	config.Sessions = store
	config.AuthorizeImmediately = func(context.Context, SessionAuthorizationRequest) (SessionGrant, bool, error) {
		return SessionGrant{}, false, nil
	}
	server, err := NewResourceManaged(config)
	if err != nil {
		t.Fatal(err)
	}

	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, protocol.signedAgentRequest(
		t, protocol.agentKey, protocol.agentToken, http.MethodGet, "/records", true,
	))
	var problem struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &problem); err != nil {
		t.Fatal(err)
	}
	if response.Code != http.StatusForbidden || problem.Error != "interaction_unavailable" ||
		response.Header().Get("Location") != "" || response.Header().Get("AAuth-Access") != "" || protected != 0 {
		t.Fatalf("immediate refusal = %d headers=%v body=%s protected=%d",
			response.Code, response.Header(), response.Body.String(), protected)
	}
}

func TestResourceManagedImmediateOnlyCompositionClosesInteractionSurfaces(t *testing.T) {
	t.Parallel()

	protocol := newResourceSessionProtocol(t)
	config := protocol.config(newMemorySessionStore(), http.NotFoundHandler())
	config.Interaction = SessionInteractionPolicy{}
	config.Sessions = &minimalSessionStore{inner: newMemorySessionStore()}
	config.AuthorizeImmediately = func(context.Context, SessionAuthorizationRequest) (SessionGrant, bool, error) {
		return SessionGrant{
			Subject: "person-123", Scope: []string{"records.read"}, Lifetime: 30 * time.Minute,
		}, true, nil
	}
	server, err := NewResourceManaged(config)
	if err != nil {
		t.Fatal(err)
	}

	poll := httptest.NewRecorder()
	server.Handler().ServeHTTP(poll, httptest.NewRequest(http.MethodGet, protocol.resource+"/session/pending/missing", nil))
	var problem struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(poll.Body.Bytes(), &problem); err != nil {
		t.Fatal(err)
	}
	if poll.Code != http.StatusGone || problem.Error != "invalid_code" {
		t.Fatalf("disabled pending route = %d headers=%v body=%s", poll.Code, poll.Header(), poll.Body.String())
	}

	const want = "resource: session interactions are not configured"
	checks := []struct {
		name string
		call func() error
	}{
		{name: "consume", call: func() error {
			_, err := server.ConsumeSessionInteractionCode(context.Background(), "missing", "0000-0000")
			return err
		}},
		{name: "resume", call: func() error {
			_, err := server.ResumeSessionInteraction(context.Background(), "missing")
			return err
		}},
		{name: "approve", call: func() error {
			return server.ApproveSessionInteraction(context.Background(), SessionInteraction{}, SessionGrant{})
		}},
		{name: "deny", call: func() error {
			return server.DenySessionInteraction(context.Background(), SessionInteraction{})
		}},
		{name: "invalidate", call: func() error {
			return server.InvalidateSessionInteraction(context.Background(), SessionInteraction{})
		}},
	}
	for _, check := range checks {
		check := check
		t.Run(check.name, func(t *testing.T) {
			if err := check.call(); err == nil || err.Error() != want {
				t.Fatalf("error = %v, want %q", err, want)
			}
		})
	}
}

func TestResourceManagedInteractionApprovesAcrossRecompositionAndBindsStableAgent(t *testing.T) {
	t.Parallel()

	protocol := newResourceSessionProtocol(t)
	store := newMemorySessionStore()
	protectedCalls := 0
	var protectedPrincipal SessionPrincipal
	protected := http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		protectedCalls++
		principal, ok := SessionPrincipalFromContext(request.Context())
		if !ok {
			t.Fatal("protected request has no SessionPrincipal")
		}
		principal.Scope[0] = "mutated"
		again, _ := SessionPrincipalFromContext(request.Context())
		if !reflect.DeepEqual(again.Scope, []string{"records.read"}) {
			t.Fatalf("SessionPrincipal aliases context state: %q", again.Scope)
		}
		protectedPrincipal = again
		response.WriteHeader(http.StatusNoContent)
	})
	server, err := NewResourceManaged(protocol.config(store, protected))
	if err != nil {
		t.Fatal(err)
	}

	initial := protocol.signedAgentRequest(t, protocol.agentKey, protocol.agentToken, http.MethodGet, "/records", true)
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, initial)
	if response.Code != http.StatusAccepted || response.Header().Get("Cache-Control") != "no-store" ||
		response.Header().Get("Retry-After") != "3" || response.Body.String() != "{\"status\":\"pending\"}\n" || protectedCalls != 0 {
		t.Fatalf("initial = %d headers=%v body=%s protected=%d", response.Code, response.Header(), response.Body.String(), protectedCalls)
	}
	requirement, err := aauth.ParseInteractionRequirement(response.Header().Values("AAuth-Requirement"))
	if err != nil {
		t.Fatal(err)
	}
	location := response.Header().Get("Location")
	locationURL, err := url.Parse(location)
	if err != nil {
		t.Fatal(err)
	}
	resolved := (&url.URL{Scheme: "https", Host: "resource.example"}).ResolveReference(locationURL)
	if resolved.Scheme != "https" || resolved.Host != "resource.example" || !strings.HasPrefix(resolved.Path, "/session/pending/") {
		t.Fatalf("Location = %q", location)
	}
	reference := strings.TrimPrefix(resolved.Path, "/session/pending/")
	if reference == resolved.Path || requirement.URL != protocol.resource+"/interaction/"+reference || requirement.Code == "" {
		t.Fatalf("Location = %q requirement = %#v", location, requirement)
	}
	pending := store.onlyPending(t)
	if pending.Resource != protocol.resource || pending.Request.AgentPrincipal.AgentProvider != protocol.provider ||
		pending.Request.AgentPrincipal.Agent != protocol.agent || pending.Request.Method != http.MethodGet ||
		pending.Request.Path != "/records" || !reflect.DeepEqual(pending.Request.RequiredScopes, []string{"records.read"}) {
		t.Fatalf("pending = %#v", pending)
	}

	ownerPoll := protocol.signedAgentRequest(t, protocol.agentKey, protocol.agentToken, http.MethodGet, resolved.Path, false)
	pollResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(pollResponse, ownerPoll)
	if pollResponse.Code != http.StatusAccepted || pollResponse.Body.String() != "{\"status\":\"pending\"}\n" {
		t.Fatalf("pending poll = %d %s", pollResponse.Code, pollResponse.Body.String())
	}
	otherPoll := protocol.signedAgentRequest(t, protocol.otherKey, protocol.otherToken, http.MethodGet, resolved.Path, false)
	otherResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(otherResponse, otherPoll)
	if otherResponse.Code == http.StatusAccepted || otherResponse.Code == http.StatusOK {
		t.Fatalf("another Agent polled stolen URL: %d %s", otherResponse.Code, otherResponse.Body.String())
	}

	interaction, err := server.ConsumeSessionInteractionCode(
		context.Background(), reference, strings.ToLower(strings.ReplaceAll(requirement.Code, "0", "o")),
	)
	if err != nil {
		t.Fatal(err)
	}
	if interaction.AgentPrincipal().Agent != protocol.agent || interaction.Method() != http.MethodGet ||
		interaction.Path() != "/records" || !reflect.DeepEqual(interaction.RequiredScopes(), []string{"records.read"}) {
		t.Fatalf("interaction = %#v", interaction)
	}
	if _, err := server.ConsumeSessionInteractionCode(context.Background(), reference, requirement.Code); !errors.Is(err, ErrSessionInteractionCodeUsed) {
		t.Fatalf("reused code error = %v", err)
	}
	pollResponse = httptest.NewRecorder()
	server.Handler().ServeHTTP(pollResponse, protocol.signedAgentRequest(t, protocol.agentKey, protocol.agentToken, http.MethodGet, resolved.Path, false))
	if pollResponse.Code != http.StatusAccepted || pollResponse.Body.String() != "{\"status\":\"interacting\"}\n" || protectedCalls != 0 {
		t.Fatalf("code conferred authority: poll=%d %s protected=%d", pollResponse.Code, pollResponse.Body.String(), protectedCalls)
	}

	recomposed, err := NewResourceManaged(protocol.config(store, protected))
	if err != nil {
		t.Fatal(err)
	}
	resumed, err := recomposed.ResumeSessionInteraction(context.Background(), reference)
	if err != nil {
		t.Fatal(err)
	}
	if err := recomposed.ApproveSessionInteraction(context.Background(), resumed, SessionGrant{
		Subject: "person-123", Scope: []string{"records.read"}, Lifetime: 30 * time.Minute,
	}); err != nil {
		t.Fatal(err)
	}

	// The terminal poll uses a fresh valid token and proof key for the same
	// stable Agent identity. The session is deliberately not bound to the old cnf.
	terminal := protocol.signedAgentRequest(t, protocol.rotatedKey, protocol.rotatedToken, http.MethodGet, resolved.Path, false)
	terminalResponse := httptest.NewRecorder()
	recomposed.Handler().ServeHTTP(terminalResponse, terminal)
	access, err := aauth.ParseAAuthAccess(terminalResponse.Header().Values("AAuth-Access"))
	if err != nil {
		t.Fatalf("terminal AAuth-Access: %v; response=%d %v %s", err, terminalResponse.Code, terminalResponse.Header(), terminalResponse.Body.String())
	}
	if terminalResponse.Code != http.StatusOK || terminalResponse.Header().Get("Cache-Control") != "no-store" || access == "" ||
		terminalResponse.Body.String() != "{\"status\":\"authorized\",\"scope\":\"records.read\"}\n" {
		t.Fatalf("terminal = %d headers=%v body=%s", terminalResponse.Code, terminalResponse.Header(), terminalResponse.Body.String())
	}
	laterResponse := httptest.NewRecorder()
	recomposed.Handler().ServeHTTP(laterResponse, protocol.signedAgentRequest(t, protocol.rotatedKey, protocol.rotatedToken, http.MethodGet, resolved.Path, false))
	if laterResponse.Code != http.StatusGone {
		t.Fatalf("later terminal poll = %d %s", laterResponse.Code, laterResponse.Body.String())
	}

	use := protocol.signedSessionRequest(t, protocol.rotatedKey, protocol.rotatedToken, access, http.MethodGet, "/records")
	useResponse := httptest.NewRecorder()
	recomposed.Handler().ServeHTTP(useResponse, use)
	if useResponse.Code != http.StatusNoContent || protectedCalls != 1 {
		t.Fatalf("session use = %d %s protected=%d", useResponse.Code, useResponse.Body.String(), protectedCalls)
	}
	if protectedPrincipal.Resource != protocol.resource || protectedPrincipal.AgentProvider != protocol.provider ||
		protectedPrincipal.Agent != protocol.agent || protectedPrincipal.Subject != "person-123" ||
		!reflect.DeepEqual(protectedPrincipal.Scope, []string{"records.read"}) {
		t.Fatalf("SessionPrincipal = %#v", protectedPrincipal)
	}
}

func TestResourceManagedInteractionRequiresCapabilityAndHostDecision(t *testing.T) {
	t.Parallel()

	protocol := newResourceSessionProtocol(t)
	store := newMemorySessionStore()
	protected := 0
	server, err := NewResourceManaged(protocol.config(store, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { protected++ })))
	if err != nil {
		t.Fatal(err)
	}
	withoutCapability := httptest.NewRecorder()
	server.Handler().ServeHTTP(withoutCapability, protocol.signedAgentRequest(
		t, protocol.agentKey, protocol.agentToken, http.MethodGet, "/records", false,
	))
	if withoutCapability.Code == http.StatusAccepted || withoutCapability.Header().Get("Location") != "" ||
		withoutCapability.Header().Get("AAuth-Requirement") != "" || protected != 0 {
		t.Fatalf("absent interaction capability = %d headers=%v protected=%d", withoutCapability.Code, withoutCapability.Header(), protected)
	}
	malformedRequest := protocol.signedAgentRequest(
		t, protocol.agentKey, protocol.agentToken, http.MethodGet, "/records", false,
	)
	malformedRequest.Header.Set("AAuth-Capabilities", `"interaction"`)
	malformedCapability := httptest.NewRecorder()
	server.Handler().ServeHTTP(malformedCapability, malformedRequest)
	var malformedProblem struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(malformedCapability.Body.Bytes(), &malformedProblem); err != nil {
		t.Fatal(err)
	}
	if malformedCapability.Code != http.StatusForbidden || malformedProblem.Error != "interaction_unavailable" ||
		malformedCapability.Header().Get("Location") != "" || protected != 0 {
		t.Fatalf("malformed capability = %d error=%q headers=%v protected=%d",
			malformedCapability.Code, malformedProblem.Error, malformedCapability.Header(), protected)
	}

	start := httptest.NewRecorder()
	server.Handler().ServeHTTP(start, protocol.signedAgentRequest(t, protocol.agentKey, protocol.agentToken, http.MethodGet, "/records", true))
	requirement, err := aauth.ParseInteractionRequirement(start.Header().Values("AAuth-Requirement"))
	if err != nil {
		t.Fatal(err)
	}
	reference := strings.TrimPrefix(requirement.URL, protocol.resource+"/interaction/")
	interaction, err := server.ConsumeSessionInteractionCode(context.Background(), reference, requirement.Code)
	if err != nil {
		t.Fatal(err)
	}
	if err := server.DenySessionInteraction(context.Background(), interaction); err != nil {
		t.Fatal(err)
	}
	location := start.Header().Get("Location")
	denied := httptest.NewRecorder()
	server.Handler().ServeHTTP(denied, protocol.signedAgentRequest(t, protocol.agentKey, protocol.agentToken, http.MethodGet, location, false))
	if denied.Code != http.StatusForbidden || denied.Header().Get("AAuth-Access") != "" || protected != 0 {
		t.Fatalf("denied poll = %d headers=%v body=%s protected=%d", denied.Code, denied.Header(), denied.Body.String(), protected)
	}
	later := httptest.NewRecorder()
	server.Handler().ServeHTTP(later, protocol.signedAgentRequest(t, protocol.agentKey, protocol.agentToken, http.MethodGet, location, false))
	if later.Code != http.StatusGone {
		t.Fatalf("later denied poll = %d %s", later.Code, later.Body.String())
	}
}

func TestResourceManagedInteractionRefusesApprovalAtOrAfterExpiry(t *testing.T) {
	t.Parallel()

	protocol := newResourceSessionProtocol(t)
	store := newMemorySessionStore()
	server, err := NewResourceManaged(protocol.config(store, http.NotFoundHandler()))
	if err != nil {
		t.Fatal(err)
	}
	started := httptest.NewRecorder()
	server.Handler().ServeHTTP(started, protocol.signedAgentRequest(
		t, protocol.agentKey, protocol.agentToken, http.MethodGet, "/records", true,
	))
	requirement, err := aauth.ParseInteractionRequirement(started.Header().Values("AAuth-Requirement"))
	if err != nil {
		t.Fatal(err)
	}
	reference := strings.TrimPrefix(requirement.URL, protocol.resource+"/interaction/")
	interaction, err := server.ConsumeSessionInteractionCode(context.Background(), reference, requirement.Code)
	if err != nil {
		t.Fatal(err)
	}
	protocol.now = interaction.ExpiresAt()
	err = server.ApproveSessionInteraction(context.Background(), interaction, SessionGrant{
		Subject: "person-123", Scope: []string{"records.read"}, Lifetime: 30 * time.Minute,
	})
	if !errors.Is(err, ErrPendingSessionExpired) {
		t.Fatalf("approval at expiry error = %v, want ErrPendingSessionExpired", err)
	}
	if store.sessionCount() != 0 {
		t.Fatalf("approval at expiry retained %d sessions", store.sessionCount())
	}
	poll := httptest.NewRecorder()
	server.Handler().ServeHTTP(poll, protocol.signedAgentRequest(
		t, protocol.agentKey, protocol.agentToken, http.MethodGet, started.Header().Get("Location"), false,
	))
	var expiredProblem struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(poll.Body.Bytes(), &expiredProblem); err != nil {
		t.Fatal(err)
	}
	if poll.Code != http.StatusRequestTimeout || expiredProblem.Error != "expired" || poll.Header().Get("AAuth-Access") != "" {
		t.Fatalf("approval at expiry escaped: status=%d access=%q body=%s",
			poll.Code, poll.Header().Get("AAuth-Access"), poll.Body.String())
	}
	consumed := httptest.NewRecorder()
	server.Handler().ServeHTTP(consumed, protocol.signedAgentRequest(
		t, protocol.agentKey, protocol.agentToken, http.MethodGet, started.Header().Get("Location"), false,
	))
	assertSessionInvalidCodeProblem(t, consumed)
}

func TestSessionUseVerifiesProofBeforeLoadAndRejectsEveryBindingFailure(t *testing.T) {
	t.Parallel()

	protocol := newResourceSessionProtocol(t)
	store := newMemorySessionStore()
	protected := 0
	config := protocol.config(store, http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		protected++
		response.WriteHeader(http.StatusNoContent)
	}))
	config.AuthorizeImmediately = func(_ context.Context, request SessionAuthorizationRequest) (SessionGrant, bool, error) {
		if request.AgentPrincipal.AgentProvider != protocol.provider || request.AgentPrincipal.Agent != protocol.agent ||
			request.Method != http.MethodGet || request.Path != "/records" ||
			!reflect.DeepEqual(request.RequiredScopes, []string{"records.read"}) {
			t.Fatalf("immediate request = %#v", request)
		}
		return SessionGrant{Subject: "person-123", Scope: []string{"records.read"}, Lifetime: 30 * time.Minute}, true, nil
	}
	server, err := NewResourceManaged(config)
	if err != nil {
		t.Fatal(err)
	}
	immediate := httptest.NewRecorder()
	server.Handler().ServeHTTP(immediate, protocol.signedAgentRequest(t, protocol.agentKey, protocol.agentToken, http.MethodGet, "/records", false))
	token, err := aauth.ParseAAuthAccess(immediate.Header().Values("AAuth-Access"))
	if err != nil {
		t.Fatal(err)
	}
	if immediate.Code != http.StatusNoContent || token == "" || protected != 1 {
		t.Fatalf("immediate = %d headers=%v body=%s protected=%d", immediate.Code, immediate.Header(), immediate.Body.String(), protected)
	}
	protected = 0

	unsigned := httptest.NewRequest(http.MethodGet, protocol.resource+"/records", nil)
	unsigned.Header.Set("Authorization", "AAuth "+token)
	unsigned.Header.Set("X-Route-Proof", "route-1")
	loadsBefore := store.loadCount()
	unsignedResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(unsignedResponse, unsigned)
	if store.loadCount() != loadsBefore || protected != 0 {
		t.Fatalf("unsigned session loaded state or called Protected: loads=%d->%d protected=%d", loadsBefore, store.loadCount(), protected)
	}

	wrongResource, err := store.Create(context.Background(), SessionRecord{
		Resource: "https://other-resource.example", AgentProvider: protocol.provider, Agent: protocol.agent,
		Subject: "person-123", Scope: []string{"records.read"}, CreatedAt: protocol.now, ExpiresAt: protocol.now.Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	wrongAgent, err := store.Create(context.Background(), SessionRecord{
		Resource: protocol.resource, AgentProvider: protocol.provider, Agent: protocol.otherAgent,
		Subject: "person-123", Scope: []string{"records.read"}, CreatedAt: protocol.now, ExpiresAt: protocol.now.Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	insufficient, err := store.Create(context.Background(), SessionRecord{
		Resource: protocol.resource, AgentProvider: protocol.provider, Agent: protocol.agent,
		Subject: "person-123", Scope: []string{"records.read"}, CreatedAt: protocol.now, ExpiresAt: protocol.now.Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	expired, err := store.Create(context.Background(), SessionRecord{
		Resource: protocol.resource, AgentProvider: protocol.provider, Agent: protocol.agent,
		Subject: "person-123", Scope: []string{"records.read"}, CreatedAt: protocol.now.Add(-time.Hour), ExpiresAt: protocol.now,
	})
	if err != nil {
		t.Fatal(err)
	}

	mutated := protocol.signedSessionRequest(t, protocol.agentKey, protocol.agentToken, token, http.MethodGet, "/records")
	mutated.Header.Set("Authorization", "AAuth "+wrongResource.Token)
	malformed := protocol.signedAgentRequest(t, protocol.agentKey, protocol.agentToken, http.MethodGet, "/records", false)
	malformed.Header.Set("Authorization", "AAuth bad token")
	if err := signaturekey.SignJWTRequestWithOptions(malformed, protocol.agentKey, protocol.agentToken, protocol.clock, signaturekey.SignOptions{
		AdditionalComponents: []string{"x-route-proof"},
	}); err != nil {
		t.Fatal(err)
	}
	multiple := protocol.signedSessionRequest(t, protocol.agentKey, protocol.agentToken, token, http.MethodGet, "/records")
	multiple.Header.Add("Authorization", "AAuth "+wrongResource.Token)

	for _, scenario := range []struct {
		name    string
		request *http.Request
	}{
		{name: "stolen by another Agent", request: protocol.signedSessionRequest(t, protocol.otherKey, protocol.otherToken, token, http.MethodGet, "/records")},
		{name: "wrong Resource", request: protocol.signedSessionRequest(t, protocol.agentKey, protocol.agentToken, wrongResource.Token, http.MethodGet, "/records")},
		{name: "wrong Agent", request: protocol.signedSessionRequest(t, protocol.agentKey, protocol.agentToken, wrongAgent.Token, http.MethodGet, "/records")},
		{name: "malformed Authorization", request: malformed},
		{name: "multiple Authorization", request: multiple},
		{name: "mutated Authorization", request: mutated},
		{name: "expired", request: protocol.signedSessionRequest(t, protocol.agentKey, protocol.agentToken, expired.Token, http.MethodGet, "/records")},
		{name: "insufficient scope", request: protocol.signedSessionRequest(t, protocol.agentKey, protocol.agentToken, insufficient.Token, http.MethodPost, "/records")},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			before := protected
			response := httptest.NewRecorder()
			server.Handler().ServeHTTP(response, scenario.request)
			if response.Code >= 200 && response.Code < 300 {
				t.Fatalf("binding failure succeeded: %d %s", response.Code, response.Body.String())
			}
			if protected != before {
				t.Fatalf("binding failure called Protected: before=%d after=%d", before, protected)
			}
		})
	}

	rotated := protocol.signedSessionRequest(t, protocol.rotatedKey, protocol.rotatedToken, token, http.MethodGet, "/records")
	rotatedResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(rotatedResponse, rotated)
	if rotatedResponse.Code != http.StatusNoContent || protected != 1 {
		t.Fatalf("same Agent after key rotation = %d %s protected=%d", rotatedResponse.Code, rotatedResponse.Body.String(), protected)
	}
}

func TestResourceManagedPendingURLRequiresSignedGET(t *testing.T) {
	t.Parallel()

	protocol := newResourceSessionProtocol(t)
	store := newMemorySessionStore()
	server, err := NewResourceManaged(protocol.config(store, http.NotFoundHandler()))
	if err != nil {
		t.Fatal(err)
	}
	start := httptest.NewRecorder()
	server.Handler().ServeHTTP(start, protocol.signedAgentRequest(
		t, protocol.agentKey, protocol.agentToken, http.MethodGet, "/records", true,
	))
	location := start.Header().Get("Location")
	if location == "" {
		t.Fatalf("start = %d headers=%v body=%s", start.Code, start.Header(), start.Body.String())
	}
	post := protocol.signedAgentRequest(t, protocol.agentKey, protocol.agentToken, http.MethodPost, location, false)
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, post)
	if response.Code != http.StatusMethodNotAllowed || response.Header().Get("Allow") != http.MethodGet {
		t.Fatalf("POST pending = %d headers=%v body=%s", response.Code, response.Header(), response.Body.String())
	}
}

func TestResourceManagedPendingURLRequiresAdvertisedSignatureComponents(t *testing.T) {
	t.Parallel()

	protocol := newResourceSessionProtocol(t)
	store := newMemorySessionStore()
	server, err := NewResourceManaged(protocol.config(store, http.NotFoundHandler()))
	if err != nil {
		t.Fatal(err)
	}
	metadata := httptest.NewRecorder()
	server.Handler().ServeHTTP(metadata, httptest.NewRequest(http.MethodGet, protocol.resource+"/.well-known/aauth-resource.json", nil))
	if metadata.Code != http.StatusOK {
		t.Fatalf("metadata = %d %s", metadata.Code, metadata.Body.String())
	}
	var document struct {
		AdditionalSignatureComponents []string `json:"additional_signature_components"`
	}
	if err := json.Unmarshal(metadata.Body.Bytes(), &document); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(document.AdditionalSignatureComponents, []string{"x-route-proof"}) {
		t.Fatalf("advertised components = %v", document.AdditionalSignatureComponents)
	}

	start := httptest.NewRecorder()
	server.Handler().ServeHTTP(start, protocol.signedAgentRequest(
		t, protocol.agentKey, protocol.agentToken, http.MethodGet, "/records", true,
	))
	location := start.Header().Get("Location")
	if location == "" {
		t.Fatalf("start = %d headers=%v body=%s", start.Code, start.Header(), start.Body.String())
	}
	poll := httptest.NewRequest(http.MethodGet, protocol.resource+location, nil)
	poll.Header.Set("X-Route-Proof", "fresh-poll-value")
	if err := signaturekey.SignJWTRequest(poll, protocol.agentKey, protocol.agentToken, protocol.clock); err != nil {
		t.Fatal(err)
	}
	rejected := httptest.NewRecorder()
	server.Handler().ServeHTTP(rejected, poll)
	assertSignatureError(t, rejected, signaturekey.ErrorInvalidInput)
	decoded, err := signaturekey.DecodeErrorResponse(rejected.Result())
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(decoded.RequiredInput, []string{
		"@method", "@authority", "@path", "signature-key", "x-route-proof",
	}) {
		t.Fatalf("required signature input = %v", decoded.RequiredInput)
	}

	valid := httptest.NewRecorder()
	server.Handler().ServeHTTP(valid, protocol.signedAgentRequest(
		t, protocol.agentKey, protocol.agentToken, http.MethodGet, location, false,
	))
	if valid.Code != http.StatusAccepted {
		t.Fatalf("fully covered pending poll = %d headers=%v body=%s", valid.Code, valid.Header(), valid.Body.String())
	}
}

func TestResourceManagedSessionWithoutProofIsSignatureFailureBeforeStoreLookup(t *testing.T) {
	t.Parallel()

	protocol := newResourceSessionProtocol(t)
	store := newMemorySessionStore()
	approval, err := store.Create(context.Background(), SessionRecord{
		Resource: protocol.resource, AgentProvider: protocol.provider, Agent: protocol.agent,
		Subject: "person-123", Scope: []string{"records.read"},
		CreatedAt: protocol.now, ExpiresAt: protocol.now.Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewResourceManaged(protocol.config(store, http.NotFoundHandler()))
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, protocol.resource+"/records", nil)
	request.Header.Set("Authorization", "AAuth "+approval.Token)
	before := store.loadCount()
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized || response.Header().Get("Signature-Error") == "" ||
		response.Header().Get("AAuth-Requirement") != "" || store.loadCount() != before {
		t.Fatalf("unsigned session = %d headers=%v loads=%d->%d body=%s", response.Code, response.Header(), before, store.loadCount(), response.Body.String())
	}
}

func TestResourceManagedRejectsStoreApprovalThatDiffersFromProposedRecord(t *testing.T) {
	t.Parallel()

	mutations := []struct {
		name   string
		change func(*SessionRecord)
	}{
		{name: "resource", change: func(record *SessionRecord) { record.Resource = "https://other-resource.example" }},
		{name: "agent provider and agent", change: func(record *SessionRecord) {
			record.AgentProvider = "https://other-provider.example"
			record.Agent = "aauth:reader@other-provider.example"
		}},
		{name: "parent and sub-agent", change: func(record *SessionRecord) {
			record.Agent = "aauth:reader+worker@provider.example"
			record.ParentAgent = "aauth:reader@provider.example"
		}},
		{name: "subject", change: func(record *SessionRecord) { record.Subject = "person-substituted" }},
		{name: "scope", change: func(record *SessionRecord) {
			record.Scope = []string{"records.read", "records.write"}
		}},
		{name: "created at", change: func(record *SessionRecord) { record.CreatedAt = record.CreatedAt.Add(-time.Second) }},
		{name: "expires at", change: func(record *SessionRecord) { record.ExpiresAt = record.ExpiresAt.Add(time.Minute) }},
	}
	for _, transition := range []string{"immediate Create", "interactive Approve"} {
		transition := transition
		for _, mutation := range mutations {
			mutation := mutation
			t.Run(transition+"/"+mutation.name, func(t *testing.T) {
				t.Parallel()

				protocol := newResourceSessionProtocol(t)
				base := newMemorySessionStore()
				store := &approvalMutatingSessionStore{memorySessionStore: base}
				protected := 0
				config := protocol.config(store, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
					protected++
				}))
				grant := SessionGrant{
					Subject: "person-123", Scope: []string{"records.read"}, Lifetime: 30 * time.Minute,
				}
				if transition == "immediate Create" {
					store.changeCreate = mutation.change
					config.AuthorizeImmediately = func(context.Context, SessionAuthorizationRequest) (SessionGrant, bool, error) {
						return grant, true, nil
					}
				} else {
					store.changeApprove = mutation.change
				}
				server, err := NewResourceManaged(config)
				if err != nil {
					t.Fatal(err)
				}

				initial := httptest.NewRecorder()
				server.Handler().ServeHTTP(initial, protocol.signedAgentRequest(
					t, protocol.agentKey, protocol.agentToken, http.MethodGet, "/records", transition != "immediate Create",
				))
				if transition == "immediate Create" {
					assertResourceSessionServerError(t, initial)
					if initial.Header().Get("AAuth-Access") != "" || protected != 0 {
						t.Fatalf("mismatched Create approval escaped: access=%q protected=%d", initial.Header().Get("AAuth-Access"), protected)
					}
					return
				}

				requirement, err := aauth.ParseInteractionRequirement(initial.Header().Values("AAuth-Requirement"))
				if err != nil {
					t.Fatal(err)
				}
				reference := strings.TrimPrefix(requirement.URL, protocol.resource+"/interaction/")
				interaction, err := server.ConsumeSessionInteractionCode(context.Background(), reference, requirement.Code)
				if err != nil {
					t.Fatal(err)
				}
				if err := server.ApproveSessionInteraction(context.Background(), interaction, grant); err == nil {
					t.Fatal("mismatched Approve approval was accepted")
				}
				poll := httptest.NewRecorder()
				server.Handler().ServeHTTP(poll, protocol.signedAgentRequest(
					t, protocol.agentKey, protocol.agentToken, http.MethodGet, initial.Header().Get("Location"), false,
				))
				if poll.Code != http.StatusAccepted || poll.Header().Get("AAuth-Access") != "" || protected != 0 {
					t.Fatalf("mismatched Approve approval escaped: status=%d access=%q protected=%d body=%s",
						poll.Code, poll.Header().Get("AAuth-Access"), protected, poll.Body.String())
				}
			})
		}
	}
}

func TestResourceManagedSessionInternalFailuresUseCoreServerError(t *testing.T) {
	t.Run("immediate store failure", func(t *testing.T) {
		protocol := newResourceSessionProtocol(t)
		store := newMemorySessionStore()
		store.createErr = errors.New("session store failed")
		config := protocol.config(store, http.NotFoundHandler())
		config.AuthorizeImmediately = func(context.Context, SessionAuthorizationRequest) (SessionGrant, bool, error) {
			return SessionGrant{Subject: "person-123", Scope: []string{"records.read"}, Lifetime: time.Minute}, true, nil
		}
		server, err := NewResourceManaged(config)
		if err != nil {
			t.Fatal(err)
		}
		response := httptest.NewRecorder()
		server.Handler().ServeHTTP(response, protocol.signedAgentRequest(
			t, protocol.agentKey, protocol.agentToken, http.MethodGet, "/records", false,
		))
		assertResourceSessionServerError(t, response)
	})

	t.Run("session load failure", func(t *testing.T) {
		protocol := newResourceSessionProtocol(t)
		store := newMemorySessionStore()
		approval, err := store.Create(context.Background(), SessionRecord{
			Resource: protocol.resource, AgentProvider: protocol.provider, Agent: protocol.agent,
			Subject: "person-123", Scope: []string{"records.read"}, CreatedAt: protocol.now, ExpiresAt: protocol.now.Add(time.Minute),
		})
		if err != nil {
			t.Fatal(err)
		}
		store.loadErr = errors.New("session load failed")
		server, err := NewResourceManaged(protocol.config(store, http.NotFoundHandler()))
		if err != nil {
			t.Fatal(err)
		}
		response := httptest.NewRecorder()
		server.Handler().ServeHTTP(response, protocol.signedSessionRequest(
			t, protocol.agentKey, protocol.agentToken, approval.Token, http.MethodGet, "/records",
		))
		assertResourceSessionServerError(t, response)
	})

	t.Run("pending creation failure", func(t *testing.T) {
		protocol := newResourceSessionProtocol(t)
		store := newMemorySessionStore()
		store.createPendingErr = errors.New("pending store failed")
		server, err := NewResourceManaged(protocol.config(store, http.NotFoundHandler()))
		if err != nil {
			t.Fatal(err)
		}
		response := httptest.NewRecorder()
		server.Handler().ServeHTTP(response, protocol.signedAgentRequest(
			t, protocol.agentKey, protocol.agentToken, http.MethodGet, "/records", true,
		))
		assertResourceSessionServerError(t, response)
	})

	for _, test := range []struct {
		name      string
		configure func(*memorySessionStore)
	}{
		{
			name: "poll store failure",
			configure: func(store *memorySessionStore) {
				store.pollErr = errors.New("pending poll failed")
			},
		},
		{
			name: "invalid poll state",
			configure: func(store *memorySessionStore) {
				store.pollOverride = &SessionPollRecord{State: SessionPollState(255)}
			},
		},
		{
			name: "invalid approval",
			configure: func(store *memorySessionStore) {
				store.pollOverride = &SessionPollRecord{State: SessionPollApproved}
			},
		},
		{
			name: "terminal consume failure",
			configure: func(store *memorySessionStore) {
				store.pollOverride = &SessionPollRecord{State: SessionPollDenied}
				store.consumeResultErr = errors.New("pending consume failed")
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			protocol := newResourceSessionProtocol(t)
			store := newMemorySessionStore()
			server, err := NewResourceManaged(protocol.config(store, http.NotFoundHandler()))
			if err != nil {
				t.Fatal(err)
			}
			initial := httptest.NewRecorder()
			server.Handler().ServeHTTP(initial, protocol.signedAgentRequest(
				t, protocol.agentKey, protocol.agentToken, http.MethodGet, "/records", true,
			))
			if initial.Code != http.StatusAccepted {
				t.Fatalf("initial response = %d %s", initial.Code, initial.Body.String())
			}
			test.configure(store)
			poll := httptest.NewRecorder()
			server.Handler().ServeHTTP(poll, protocol.signedAgentRequest(
				t, protocol.agentKey, protocol.agentToken, http.MethodGet, initial.Header().Get("Location"), false,
			))
			assertResourceSessionServerError(t, poll)
		})
	}
}

func TestResourceManagedUnknownAndConsumedPendingURLsUseInvalidCode(t *testing.T) {
	t.Parallel()

	protocol := newResourceSessionProtocol(t)
	store := newMemorySessionStore()
	server, err := NewResourceManaged(protocol.config(store, http.NotFoundHandler()))
	if err != nil {
		t.Fatal(err)
	}

	t.Run("unknown", func(t *testing.T) {
		unknown := httptest.NewRecorder()
		server.Handler().ServeHTTP(unknown, protocol.signedAgentRequest(
			t, protocol.agentKey, protocol.agentToken, http.MethodGet, "/session/pending/unknown", false,
		))
		assertSessionInvalidCodeProblem(t, unknown)
	})

	t.Run("post-terminal", func(t *testing.T) {
		initial := httptest.NewRecorder()
		server.Handler().ServeHTTP(initial, protocol.signedAgentRequest(
			t, protocol.agentKey, protocol.agentToken, http.MethodGet, "/records", true,
		))
		requirement, err := aauth.ParseInteractionRequirement(initial.Header().Values("AAuth-Requirement"))
		if err != nil {
			t.Fatal(err)
		}
		reference := strings.TrimPrefix(requirement.URL, protocol.resource+"/interaction/")
		interaction, err := server.ConsumeSessionInteractionCode(context.Background(), reference, requirement.Code)
		if err != nil {
			t.Fatal(err)
		}
		if err := server.ApproveSessionInteraction(context.Background(), interaction, SessionGrant{
			Subject: "person-123", Scope: []string{"records.read"}, Lifetime: 30 * time.Minute,
		}); err != nil {
			t.Fatal(err)
		}
		location := initial.Header().Get("Location")
		terminal := httptest.NewRecorder()
		server.Handler().ServeHTTP(terminal, protocol.signedAgentRequest(
			t, protocol.agentKey, protocol.agentToken, http.MethodGet, location, false,
		))
		if terminal.Code != http.StatusOK || terminal.Header().Get("AAuth-Access") == "" {
			t.Fatalf("terminal response = %d headers=%v body=%s", terminal.Code, terminal.Header(), terminal.Body.String())
		}
		consumed := httptest.NewRecorder()
		server.Handler().ServeHTTP(consumed, protocol.signedAgentRequest(
			t, protocol.agentKey, protocol.agentToken, http.MethodGet, location, false,
		))
		assertSessionInvalidCodeProblem(t, consumed)
	})
}

type approvalMutatingSessionStore struct {
	*memorySessionStore
	changeCreate  func(*SessionRecord)
	changeApprove func(*SessionRecord)
}

type minimalSessionStore struct {
	inner *memorySessionStore
}

func (store *minimalSessionStore) Create(ctx context.Context, record SessionRecord) (SessionApproval, error) {
	return store.inner.Create(ctx, record)
}

func (store *minimalSessionStore) Load(ctx context.Context, token string, now time.Time) (SessionRecord, error) {
	return store.inner.Load(ctx, token, now)
}

func (store *approvalMutatingSessionStore) Create(ctx context.Context, proposed SessionRecord) (SessionApproval, error) {
	approval, err := store.memorySessionStore.Create(ctx, proposed)
	if err == nil && store.changeCreate != nil {
		store.changeCreate(&approval.Record)
	}
	return approval, err
}

func (store *approvalMutatingSessionStore) Approve(
	_ context.Context,
	_ string,
	proposed SessionRecord,
	_ time.Time,
) (SessionApproval, error) {
	approval := SessionApproval{Token: "interactive-store-token", Record: cloneSessionRecordForTest(proposed)}
	if store.changeApprove != nil {
		store.changeApprove(&approval.Record)
	}
	return approval, nil
}

func assertSessionInvalidCodeProblem(t *testing.T, response *httptest.ResponseRecorder) {
	t.Helper()
	var problem struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &problem); err != nil {
		t.Fatalf("decode pending problem: %v; status=%d body=%s", err, response.Code, response.Body.String())
	}
	if response.Code != http.StatusGone || problem.Error != "invalid_code" {
		t.Fatalf("pending problem = %d error=%q body=%s", response.Code, problem.Error, response.Body.String())
	}
}

func assertResourceSessionServerError(t *testing.T, response *httptest.ResponseRecorder) {
	t.Helper()
	var problem struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &problem); err != nil {
		t.Fatalf("decode server problem: %v; status=%d body=%s", err, response.Code, response.Body.String())
	}
	if response.Code != http.StatusInternalServerError || problem.Error != "server_error" || response.Header().Get("Retry-After") != "" {
		t.Fatalf("server problem = %d error=%q Retry-After=%q body=%s",
			response.Code, problem.Error, response.Header().Get("Retry-After"), response.Body.String())
	}
}

type resourceSessionProtocol struct {
	t            *testing.T
	now          time.Time
	clock        aauth.Clock
	resource     string
	provider     string
	agent        string
	otherAgent   string
	providerKey  jose.SigningKey
	agentKey     jose.SigningKey
	rotatedKey   jose.SigningKey
	otherKey     jose.SigningKey
	agentToken   string
	rotatedToken string
	otherToken   string
	resolver     signaturekey.StaticKeyResolver
}

func newResourceSessionProtocol(t *testing.T) *resourceSessionProtocol {
	t.Helper()
	protocol := &resourceSessionProtocol{
		t: t, now: time.Date(2026, 8, 30, 22, 0, 0, 0, time.UTC),
		resource: "https://resource.example", provider: "https://provider.example",
		agent: "aauth:reader@provider.example", otherAgent: "aauth:other@provider.example",
	}
	protocol.clock = aauth.ClockFunc(func() time.Time { return protocol.now })
	protocol.providerKey = testSigningKey(t, "session-provider", 71)
	protocol.agentKey = testSigningKey(t, "session-agent", 72)
	protocol.rotatedKey = testSigningKey(t, "session-agent-rotated", 73)
	protocol.otherKey = testSigningKey(t, "session-agent-other", 74)
	protocol.resolver = signaturekey.StaticKeyResolver{
		{Issuer: protocol.provider, DiscoveryDocument: aauth.AgentDiscoveryDocument, KeyID: protocol.providerKey.ID()}: protocol.providerKey.PublicJWK(),
	}
	var err error
	protocol.agentToken, err = aauth.MintAgentToken(protocol.provider, protocol.providerKey, aauth.AgentTokenRequest{
		Agent: protocol.agent, PublicKey: protocol.agentKey.PublicJWK(), Lifetime: time.Hour,
		AdditionalClaims: map[string]json.RawMessage{"platform": json.RawMessage(`{"level":"example"}`)},
	}, protocol.now, "session-agent-token")
	if err != nil {
		t.Fatal(err)
	}
	protocol.rotatedToken, err = aauth.MintAgentToken(protocol.provider, protocol.providerKey, aauth.AgentTokenRequest{
		Agent: protocol.agent, PublicKey: protocol.rotatedKey.PublicJWK(), Lifetime: time.Hour,
	}, protocol.now, "session-agent-token-rotated")
	if err != nil {
		t.Fatal(err)
	}
	protocol.otherToken, err = aauth.MintAgentToken(protocol.provider, protocol.providerKey, aauth.AgentTokenRequest{
		Agent: protocol.otherAgent, PublicKey: protocol.otherKey.PublicJWK(), Lifetime: time.Hour,
	}, protocol.now, "session-other-agent-token")
	if err != nil {
		t.Fatal(err)
	}
	return protocol
}

func (protocol *resourceSessionProtocol) config(store DeferredSessionStore, protected http.Handler) ResourceManagedConfig {
	return ResourceManagedConfig{
		Issuer: protocol.resource, KeyResolver: protocol.resolver, Clock: protocol.clock,
		Random:                        bytes.NewReader(bytes.Repeat([]byte{0x5a}, 256)),
		ScopeDescriptions:             map[string]string{"records.read": "Read records", "records.write": "Write records"},
		AdditionalSignatureComponents: []string{"x-route-proof"}, MaxSignedBodyBytes: 64 << 10,
		RequiredScopes: func(request *http.Request) []string {
			if request.Method == http.MethodPost {
				return []string{"records.write"}
			}
			return []string{"records.read"}
		},
		Interaction: SessionInteractionPolicy{
			URL: protocol.resource + "/interaction", Lifetime: 5 * time.Minute,
			RetryAfter: 3 * time.Second, MaximumCodeAttempts: 3,
		},
		Sessions: store, Protected: protected,
	}
}

func (protocol *resourceSessionProtocol) signedAgentRequest(
	t *testing.T, key jose.SigningKey, token, method, path string, interaction bool,
) *http.Request {
	t.Helper()
	request := httptest.NewRequest(method, protocol.resource+path, nil)
	request.Header.Set("X-Route-Proof", "route-1")
	if interaction {
		request.Header.Set("AAuth-Capabilities", "interaction")
	}
	if err := signaturekey.SignJWTRequestWithOptions(request, key, token, protocol.clock, signaturekey.SignOptions{
		AdditionalComponents: []string{"x-route-proof"},
	}); err != nil {
		t.Fatal(err)
	}
	return request
}

func (protocol *resourceSessionProtocol) signedSessionRequest(
	t *testing.T, key jose.SigningKey, agentToken, sessionToken, method, path string,
) *http.Request {
	t.Helper()
	request := httptest.NewRequest(method, protocol.resource+path, nil)
	request.Header.Set("Authorization", "AAuth "+sessionToken)
	request.Header.Set("X-Route-Proof", "route-1")
	if err := signaturekey.SignJWTRequestWithOptions(request, key, agentToken, protocol.clock, signaturekey.SignOptions{
		AdditionalComponents: []string{"x-route-proof"},
	}); err != nil {
		t.Fatal(err)
	}
	return request
}
