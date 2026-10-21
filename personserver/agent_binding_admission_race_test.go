package personserver

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
)

// Protocol 28e8258, Agent-Person Binding: a replacement binding must not
// adopt a request authenticated under the old binding merely because a host
// policy returned after replacement. The request's retained admission time
// must predate the replacement even when its pending record is created later.
func TestReplacementDuringAuthorizationInteractionPolicyDoesNotAdoptOldRequest(t *testing.T) {
	t.Parallel()
	protocol := newAuthorizationInteractionProtocol(t)
	config := protocol.config(newMemoryDeferredAuthorizationStore())
	config.AgentBindingRevocations = newMemoryAgentBindingRevocations()
	policy := config.RequireAuthorizationInteraction
	var server *Server
	config.RequireAuthorizationInteraction = func(ctx context.Context, request AuthorizationRequest) (AuthorizationInteractionPolicy, bool, error) {
		binding := AgentBinding{AgentProvider: protocol.providerID, Agent: protocol.agentID}
		protocol.now = protocol.now.Add(time.Second)
		if err := server.RevokeAgentBinding(ctx, binding); err != nil {
			return AuthorizationInteractionPolicy{}, false, err
		}
		protocol.now = protocol.now.Add(time.Second)
		if err := server.ReestablishAgentBinding(ctx, binding); err != nil {
			return AuthorizationInteractionPolicy{}, false, err
		}
		protocol.now = protocol.now.Add(time.Second)
		return policy(ctx, request)
	}
	var err error
	server, err = NewPSAuthorization(config)
	if err != nil {
		t.Fatal(err)
	}
	started := protocol.exchange(t, server, []string{"interaction"})
	if started.Code == http.StatusBadRequest {
		assertBindingRevokedProblem(t, started, http.StatusBadRequest, "revoked_presented_token")
		return
	}
	if started.Code != http.StatusAccepted {
		t.Fatalf("authorization request = %d %s", started.Code, started.Body.String())
	}
	requirement, err := aauth.ParseInteractionRequirement(started.Header().Values("AAuth-Requirement"))
	if err != nil {
		t.Fatal(err)
	}
	value, err := server.ConsumeAuthorizationInteractionCode(context.Background(), strings.TrimPrefix(requirement.URL, protocol.interactionURL+"/"), requirement.Code)
	if err != nil {
		t.Fatal(err)
	}
	if err := server.ApproveAuthorizationInteraction(context.Background(), value, AuthorizationDecision{
		Scopes: []string{"records.read"}, Lifetime: time.Minute,
	}); !errors.Is(err, ErrAgentBindingRevoked) {
		t.Errorf("approval of pre-replacement request = %v; want ErrAgentBindingRevoked", err)
	}
	if protocol.tokenIDCalls() != 0 {
		t.Errorf("pre-replacement request minted %d Auth tokens", protocol.tokenIDCalls())
	}
	location := started.Header().Get("Location")
	assertBindingRevokedProblem(t, protocol.poll(t, server, location, protocol.agentKey, protocol.agentToken), http.StatusBadRequest, "revoked_presented_token")
	assertAuthorizationInteractionProblem(t, protocol.poll(t, server, location, protocol.agentKey, protocol.agentToken), http.StatusGone, "invalid_code")
}

func TestReplacementDuringPersonInteractionPolicyDoesNotAdoptOldRequest(t *testing.T) {
	t.Parallel()
	protocol := newPersonInteractionProtocol(t)
	protocol.bindings = newMemoryAgentBindingRevocations()
	store := newMemoryDeferredTokenStore()
	server := protocol.newServer(t, store, true)
	policy := server.requirePersonTokenInteraction
	server.requirePersonTokenInteraction = func(ctx context.Context, request PersonTokenRequest) (PersonTokenInteractionPolicy, bool, error) {
		binding := AgentBinding{AgentProvider: "https://provider.example", Agent: protocol.agentID}
		protocol.now = protocol.now.Add(time.Second)
		if err := server.RevokeAgentBinding(ctx, binding); err != nil {
			return PersonTokenInteractionPolicy{}, false, err
		}
		protocol.now = protocol.now.Add(time.Second)
		if err := server.ReestablishAgentBinding(ctx, binding); err != nil {
			return PersonTokenInteractionPolicy{}, false, err
		}
		protocol.now = protocol.now.Add(time.Second)
		return policy(ctx, request)
	}
	started := httptest.NewRecorder()
	server.Handler().ServeHTTP(started, protocol.personTokenRequest(t))
	if started.Code == http.StatusForbidden {
		assertBindingRevokedProblem(t, started, http.StatusForbidden, "person_token_denied")
		return
	}
	if started.Code != http.StatusAccepted {
		t.Fatalf("Person-token request = %d %s", started.Code, started.Body.String())
	}
	requirement, err := aauth.ParseInteractionRequirement(started.Header().Values("AAuth-Requirement"))
	if err != nil {
		t.Fatal(err)
	}
	value, err := server.ConsumePersonTokenInteractionCode(context.Background(), personInteractionReference(t, requirement.URL), requirement.Code)
	if err != nil {
		t.Fatal(err)
	}
	if err := server.ApprovePersonTokenInteraction(context.Background(), value, Person{
		Subject: "old-person", Lifetime: time.Minute,
	}); !errors.Is(err, ErrAgentBindingRevoked) {
		t.Errorf("approval of pre-replacement request = %v; want ErrAgentBindingRevoked", err)
	}
	if store.tokenCommitCount() != 0 {
		t.Errorf("pre-replacement request committed %d Person tokens", store.tokenCommitCount())
	}
	location := started.Header().Get("Location")
	poll := httptest.NewRecorder()
	server.Handler().ServeHTTP(poll, protocol.pollRequest(t, location, protocol.agentKey, protocol.agentToken))
	assertBindingRevokedProblem(t, poll, http.StatusForbidden, "person_token_denied")
	secondPoll := httptest.NewRecorder()
	server.Handler().ServeHTTP(secondPoll, protocol.pollRequest(t, location, protocol.agentKey, protocol.agentToken))
	assertPersonInteractionProblem(t, secondPoll, http.StatusGone, "invalid_code")
}

func TestReplacementDuringImmediateAuthorizationPolicyDoesNotIssueOldSubjectGrant(t *testing.T) {
	t.Parallel()
	protocol := newAuthorizationInteractionProtocol(t)
	config := protocol.config(nil)
	config.AgentBindingRevocations = newMemoryAgentBindingRevocations()
	authorize := config.Authorize
	var server *Server
	config.Authorize = func(ctx context.Context, request AuthorizationRequest) (AuthorizationDecision, error) {
		replaceBindingDuringPolicy(t, server, &protocol.now, AgentBinding{AgentProvider: protocol.providerID, Agent: protocol.agentID})
		return authorize(ctx, request)
	}
	var err error
	server, err = NewPSAuthorization(config)
	if err != nil {
		t.Fatal(err)
	}
	response := protocol.exchange(t, server, nil)
	if protocol.tokenIDCalls() != 0 {
		t.Errorf("old-subject authorization minted %d Auth tokens after binding replacement", protocol.tokenIDCalls())
	}
	assertBindingRevokedProblem(t, response, http.StatusBadRequest, "revoked_presented_token")
}

func TestReplacementDuringImmediatePersonPolicyDoesNotIssueOldSubjectToken(t *testing.T) {
	t.Parallel()
	protocol := newPersonInteractionProtocol(t)
	protocol.bindings = newMemoryAgentBindingRevocations()
	store := newMemoryDeferredTokenStore()
	server := protocol.newServer(t, store, false)
	server.bindPerson = func(context.Context, PersonTokenRequest) (Person, error) {
		replaceBindingDuringPolicy(t, server, &protocol.now, AgentBinding{AgentProvider: "https://provider.example", Agent: protocol.agentID})
		return Person{Subject: "old-person", Lifetime: time.Minute}, nil
	}
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, protocol.personTokenRequest(t))
	if store.tokenCommitCount() != 0 {
		t.Errorf("old-subject request committed %d Person tokens after binding replacement", store.tokenCommitCount())
	}
	assertBindingRevokedProblem(t, response, http.StatusForbidden, "person_token_denied")
}

func TestReplacementDuringMissionPersonPolicyDoesNotIssueOldSubjectTokens(t *testing.T) {
	t.Parallel()
	protocol := newMissionProtocol(t)
	server := protocol.server
	server.agentBindingRevocations = newMemoryAgentBindingRevocations()
	server.bindPerson = func(context.Context, PersonTokenRequest) (Person, error) {
		replaceBindingDuringPolicy(t, server, &protocol.now, AgentBinding{AgentProvider: protocol.agentProviderID, Agent: protocol.agentID})
		return Person{Subject: "old-person", Lifetime: time.Minute}, nil
	}
	request := httptest.NewRequest(http.MethodPost, protocol.personServerID+"/mission", strings.NewReader(
		`{"description":"# Report","tools":[{"name":"Publish","description":"Publish"}],"resources":["https://resource.example"]}`,
	))
	request.Header.Set("Content-Type", "application/json")
	if err := signPersonServerTestRequest(request, protocol.agentKey, protocol.agentToken, protocol.clock); err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	protocol.store.mu.Lock()
	missions, tokens := len(protocol.store.missions), len(protocol.store.records)
	protocol.store.mu.Unlock()
	if missions != 0 || tokens != 0 {
		t.Errorf("old-subject mission committed %d missions and %d Person tokens after binding replacement", missions, tokens)
	}
	assertBindingRevokedProblem(t, response, http.StatusForbidden, "person_token_denied")
}

func replaceBindingDuringPolicy(t *testing.T, server *Server, now *time.Time, binding AgentBinding) {
	t.Helper()
	*now = now.Add(time.Second)
	if err := server.RevokeAgentBinding(context.Background(), binding); err != nil {
		t.Fatal(err)
	}
	*now = now.Add(time.Second)
	if err := server.ReestablishAgentBinding(context.Background(), binding); err != nil {
		t.Fatal(err)
	}
	*now = now.Add(time.Second)
}

// Protocol 28e8258, Agent-Person Binding: a replacement must not readmit an
// old binding's credential because its Access Server's clock was ahead. The
// accepted request-signature window allows this otherwise valid future iat;
// only the Person Server knows when its binding was replaced.
func TestReplacementDoesNotAdmitOldASAuthTokenWithAheadClock(t *testing.T) {
	t.Parallel()
	protocol := newPresentedTokenProtocol(t)
	expiresAt := protocol.now.Add(10 * time.Minute)
	presented, err := aauth.MintAuthToken(protocol.accessKey, aauth.AuthTokenClaims{
		Issuer: presentedAccessID, DWK: aauth.AccessDiscoveryDocument, Audience: presentedResourceID,
		JTI: "old-binding-ahead-clock", Confirmation: aauth.Confirmation{JWK: protocol.agentKey.PublicJWK()},
		IssuedAt: protocol.now.Add(30 * time.Second).Unix(), ExpiresAt: expiresAt.Unix(),
		Subject: "person-123", Scope: "records.read", PersonServer: presentedPersonID,
	})
	if err != nil {
		t.Fatal(err)
	}
	reply := &accessServerReply{
		status: http.StatusOK, contentType: "application/json",
		body: protocol.accessServerAuthToken(t, expiresAt),
	}
	var forwarded string
	access := protocol.accessServer(t, reply, &forwarded)
	accessCalls := 0
	server := protocol.federatedServer(t, func(request *http.Request) (*http.Response, error) {
		accessCalls++
		return access(request)
	})
	server.agentBindingRevocations = newMemoryAgentBindingRevocations()
	control := protocol.exchange(t, server,
		protocol.resourceToken(t, presentedAccessID, "old-binding-ahead-clock"), presented)
	if control.Code != http.StatusOK || accessCalls != 1 || forwarded != presented {
		t.Fatalf("never-revoked control = %d %s; AS calls=%d", control.Code, control.Body.String(), accessCalls)
	}
	replaceBindingDuringPolicy(t, server, &protocol.now, AgentBinding{AgentProvider: presentedProviderID, Agent: presentedAgentID})
	response := protocol.exchange(t, server,
		protocol.resourceToken(t, presentedAccessID, "old-binding-ahead-clock"), presented)
	if accessCalls != 1 {
		t.Errorf("old-binding Auth token reached AS after replacement: calls=%d; want 1 control call", accessCalls)
	}
	assertBindingRevokedProblem(t, response, http.StatusBadRequest, "revoked_presented_token")
}
