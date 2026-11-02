package integration_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	clientagent "gitlab.com/sidecat-dev/aauth-go/agent"
	"gitlab.com/sidecat-dev/aauth-go/agentprovider"
	"gitlab.com/sidecat-dev/aauth-go/resource"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

func TestCurrentCoreResourceManagedSessionAcrossResourceRecomposition(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	now := time.Date(2026, 8, 30, 23, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	const (
		agentProviderID = "https://ap.example"
		agentID         = "aauth:reader@ap.example"
		otherAgentID    = "aauth:other@ap.example"
		resourceID      = "https://resource.example"
	)

	providerKey := newSigningKey(t, "session-ap-key")
	agentKey := newSigningKey(t, "session-agent-key")
	rotatedAgentKey := newSigningKey(t, "session-agent-key-rotated")
	otherAgentKey := newSigningKey(t, "session-other-agent-key")
	issuedAgentTokens := 0
	provider, err := agentprovider.New(agentprovider.Config{
		Issuer: agentProviderID, SigningKey: providerKey, Clock: clock,
		NewID: func() string {
			issuedAgentTokens++
			return fmt.Sprintf("session-agent-token-%d", issuedAgentTokens)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	agentToken, err := provider.Issue(ctx, aauth.AgentTokenRequest{
		Agent: agentID, PublicKey: agentKey.PublicJWK(), Lifetime: time.Hour,
		AdditionalClaims: map[string]json.RawMessage{"platform": json.RawMessage(`{"level":"initial"}`)},
	})
	if err != nil {
		t.Fatal(err)
	}
	rotatedAgentToken, err := provider.Issue(ctx, aauth.AgentTokenRequest{
		Agent: agentID, PublicKey: rotatedAgentKey.PublicJWK(), Lifetime: time.Hour,
		AdditionalClaims: map[string]json.RawMessage{"platform": json.RawMessage(`{"level":"rotated"}`)},
	})
	if err != nil {
		t.Fatal(err)
	}
	otherAgentToken, err := provider.Issue(ctx, aauth.AgentTokenRequest{
		Agent: otherAgentID, PublicKey: otherAgentKey.PublicJWK(), Lifetime: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	claims, err := aauth.VerifyAgentToken(ctx, agentToken, signaturekey.StaticKeyResolver{
		{Issuer: agentProviderID, DiscoveryDocument: aauth.AgentDiscoveryDocument, KeyID: providerKey.ID()}: providerKey.PublicJWK(),
	}, clock)
	if err != nil {
		t.Fatal(err)
	}
	if claims.PersonServer != "" {
		t.Fatalf("resource-managed Agent unexpectedly names a Person Server: %#v", claims)
	}

	resolver := signaturekey.StaticKeyResolver{
		{Issuer: agentProviderID, DiscoveryDocument: aauth.AgentDiscoveryDocument, KeyID: providerKey.ID()}: providerKey.PublicJWK(),
	}
	store := newIntegrationSessionStore()
	network := newLogicalTransport()
	httpClient := &http.Client{Transport: network}

	var captureMu sync.Mutex
	var captured []capturedSessionRequest
	tamperNextAuthorization := false
	protectedCalls := 0
	var protectedPrincipal resource.SessionPrincipal
	protected := http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		protectedCalls++
		principal, ok := resource.SessionPrincipalFromContext(request.Context())
		if !ok {
			t.Fatal("protected request has no Resource-managed SessionPrincipal")
		}
		protectedPrincipal = principal
		_, _ = io.WriteString(response, `{"ok":true}`)
	})

	newResource := func() *resource.ResourceManagedServer {
		server, err := resource.NewResourceManaged(resource.ResourceManagedConfig{
			Issuer: resourceID, KeyResolver: resolver, Clock: clock,
			ScopeDescriptions:             map[string]string{"records.read": "Read records"},
			AdditionalSignatureComponents: []string{"x-request-id", "content-type", "content-digest"},
			RequiredScopes:                func(*http.Request) []string { return []string{"records.read"} },
			Interaction: resource.SessionInteractionPolicy{
				URL: resourceID + "/interaction", Lifetime: 5 * time.Minute,
				RetryAfter: 2 * time.Second, MaximumCodeAttempts: 3,
			},
			Sessions: store, Protected: protected,
		})
		if err != nil {
			t.Fatal(err)
		}
		return server
	}
	currentResource := newResource()
	network.Handle(agentProviderID, provider.Handler())
	network.Handle(resourceID, http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		captureMu.Lock()
		captured = append(captured, capturedSessionRequest{
			Method: request.Method, Path: request.URL.Path,
			SignatureInput: request.Header.Get("Signature-Input"),
			SignatureKey:   request.Header.Get("Signature-Key"),
			Authorization:  request.Header.Get("Authorization"),
			ContentDigest:  request.Header.Get("Content-Digest"),
		})
		if tamperNextAuthorization && request.Header.Get("Authorization") != "" {
			tamperNextAuthorization = false
			request.Header.Set("Authorization", request.Header.Get("Authorization")+"x")
		}
		captureMu.Unlock()
		currentResource.Handler().ServeHTTP(response, request)
	}))

	reader, err := clientagent.New(ctx, clientagent.Config{
		Identifier: agentID, SigningKey: agentKey, AgentToken: agentToken,
		KeyResolver: resolver, HTTPClient: httpClient, Clock: clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	initialRequest, err := http.NewRequestWithContext(ctx, http.MethodGet, resourceID+"/records", nil)
	if err != nil {
		t.Fatal(err)
	}
	initialRequest.Header.Set("X-Request-ID", "resource-session-initial")
	initialRequest.Header.Set("Content-Type", "application/json")
	initialRequest.Header.Set("AAuth-Capabilities", "interaction")
	begin, err := reader.BeginResourceSession(ctx, initialRequest)
	if err != nil {
		t.Fatal(err)
	}
	pending, ok := begin.Pending()
	if !ok || pending.Resource() != resourceID || pending.RetryAfter() != 2*time.Second ||
		!strings.HasPrefix(pending.InteractionURL(), resourceID+"/interaction/") || pending.InteractionCode() == "" {
		t.Fatalf("initial Resource session = %#v, pending = %#v", begin, pending)
	}
	if protectedCalls != 0 || store.sessionCount() != 0 {
		t.Fatalf("initial request executed or issued a session: protected=%d sessions=%d", protectedCalls, store.sessionCount())
	}
	poll := func(client *clientagent.Client, pending clientagent.PendingResourceSession, requestID string) (clientagent.ResourceSessionResult, error) {
		header := make(http.Header)
		header.Set("X-Request-ID", requestID)
		header.Set("Content-Type", "application/json")
		return client.PollResourceSessionWithComponents(
			ctx, pending, header, []string{"x-request-id", "content-type", "content-digest"},
		)
	}

	// The code correlates the browser visit. It cannot authorize or create a
	// session without the host's separate authenticated decision below.
	reference := strings.TrimPrefix(pending.InteractionURL(), resourceID+"/interaction/")
	const agentCallback = "https://agent.example/callback"
	interaction, err := currentResource.ConsumeSessionInteractionVisit(ctx, reference, aauth.InteractionVisit{
		Code: pending.InteractionCode(), Callback: agentCallback,
	})
	if err != nil {
		t.Fatal(err)
	}
	interacting, err := poll(reader, pending, "resource-session-poll-interacting")
	if err != nil {
		t.Fatal(err)
	}
	updatedPending, ok := interacting.Pending()
	if !ok || !updatedPending.Interacting() || updatedPending.Location() != pending.Location() {
		t.Fatalf("interacting poll = %#v", interacting)
	}
	if protectedCalls != 0 || store.sessionCount() != 0 {
		t.Fatalf("interaction code conferred authority: protected=%d sessions=%d", protectedCalls, store.sessionCount())
	}

	// Recompose the Resource around the same host store, recover the correlated
	// interaction from authenticated host state, and then make the decision.
	currentResource = newResource()
	interaction, err = currentResource.ResumeSessionInteraction(ctx, interaction.Reference())
	if err != nil {
		t.Fatal(err)
	}
	if interaction.Callback() != agentCallback {
		t.Fatalf("resumed callback = %q", interaction.Callback())
	}
	grant := resource.SessionGrant{
		Subject: "person-123", Scope: []string{"records.read"}, Lifetime: 30 * time.Minute,
	}
	approveAsHost := func(authenticated bool) error {
		if !authenticated {
			return errors.New("host authentication is required before approval")
		}
		return currentResource.ApproveSessionInteraction(ctx, interaction, grant)
	}
	if err := approveAsHost(false); err == nil || store.sessionCount() != 0 {
		t.Fatalf("unauthenticated host approval = %v, sessions=%d", err, store.sessionCount())
	}
	if err := approveAsHost(true); err != nil {
		t.Fatal(err)
	}
	completion, completionErr := interaction.CompletionURL()
	back, backErr := currentResource.SessionCallbackURL(ctx, reference)
	if completion != agentCallback || completionErr != nil || back != agentCallback || backErr != nil {
		t.Fatalf("approved callback = %q, %v; from state %q, %v", completion, completionErr, back, backErr)
	}

	approved, err := poll(reader, updatedPending, "resource-session-poll-approved")
	if err != nil {
		t.Fatal(err)
	}
	terminalResponse, ok := approved.Response()
	if !ok {
		t.Fatalf("approved poll has no terminal response: %#v", approved)
	}
	terminalResponse.Body.Close()
	session, ok := approved.Session()
	if !ok || terminalResponse.StatusCode != http.StatusOK || session.Resource() != resourceID || session.Token() == "" {
		t.Fatalf("approved terminal = %d session=%#v present=%v", terminalResponse.StatusCode, session, ok)
	}
	if strings.Count(session.Token(), ".") == 2 {
		t.Fatalf("Resource session looks like a JWT instead of an opaque token: %q", session.Token())
	}
	state := session.State()
	consumed, err := poll(reader, updatedPending, "resource-session-poll-consumed")
	if err != nil {
		t.Fatalf("second terminal poll returned Go error: %v", err)
	}
	var gone *aauth.ProblemError
	if failure := consumed.Failure(); !errors.As(failure, &gone) || gone.Status != http.StatusGone {
		t.Fatalf("second terminal poll failure = %v, problem = %#v", failure, gone)
	}
	if response, ok := consumed.Response(); ok {
		response.Body.Close()
	}

	otherReader, err := clientagent.New(ctx, clientagent.Config{
		Identifier: otherAgentID, SigningKey: otherAgentKey, AgentToken: otherAgentToken,
		KeyResolver: resolver, HTTPClient: httpClient, Clock: clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := otherReader.RestoreResourceSession(state); err == nil {
		t.Fatal("another Agent restored the stolen ResourceSession state")
	}
	stolenRequest, err := http.NewRequestWithContext(ctx, http.MethodGet, resourceID+"/records", nil)
	if err != nil {
		t.Fatal(err)
	}
	stolenRequest.Header.Set("X-Request-ID", "resource-session-stolen")
	if _, err := otherReader.DoWithResourceSession(ctx, stolenRequest, session); err == nil {
		t.Fatal("another Agent accepted the stolen ResourceSession value")
	}
	// Bypass the Agent's local custody check and prove that the Resource also
	// rejects the stolen opaque token under another Agent's valid proof.
	rawStolen, err := http.NewRequestWithContext(ctx, http.MethodGet, resourceID+"/records", nil)
	if err != nil {
		t.Fatal(err)
	}
	rawStolen.Header.Set("X-Request-ID", "resource-session-stolen-wire")
	rawStolen.Header.Set("Content-Type", "application/json")
	rawStolen.Header.Set("Authorization", "AAuth "+session.Token())
	if err := signaturekey.SignJWTRequestWithOptions(rawStolen, otherAgentKey, otherAgentToken, clock, signaturekey.SignOptions{
		AdditionalComponents: []string{"x-request-id", "content-type", "content-digest"},
	}); err != nil {
		t.Fatal(err)
	}
	stolenResponse, err := httpClient.Do(rawStolen)
	if err != nil {
		t.Fatal(err)
	}
	stolenResponse.Body.Close()
	if stolenResponse.StatusCode != http.StatusForbidden || protectedCalls != 0 {
		t.Fatalf("stolen wire session = %d protected=%d", stolenResponse.StatusCode, protectedCalls)
	}

	rotatedReader, err := clientagent.New(ctx, clientagent.Config{
		Identifier: agentID, SigningKey: rotatedAgentKey, AgentToken: rotatedAgentToken,
		KeyResolver: resolver, HTTPClient: httpClient, Clock: clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	restored, err := rotatedReader.RestoreResourceSession(state)
	if err != nil {
		t.Fatal(err)
	}
	tamperNextAuthorization = true
	tamperedRequest, err := http.NewRequestWithContext(ctx, http.MethodGet, resourceID+"/records", nil)
	if err != nil {
		t.Fatal(err)
	}
	tamperedRequest.Header.Set("X-Request-ID", "resource-session-tampered")
	tamperedRequest.Header.Set("Content-Type", "application/json")
	tampered, err := rotatedReader.DoWithResourceSession(ctx, tamperedRequest, restored)
	if err != nil {
		t.Fatalf("mutated Authorization response was malformed: %v", err)
	}
	if tampered.Failure() == nil {
		t.Fatal("mutated Authorization remained valid after signing")
	}
	if response, ok := tampered.Response(); ok {
		response.Body.Close()
	}
	if protectedCalls != 0 {
		t.Fatalf("mutated Authorization reached Protected: %d", protectedCalls)
	}

	protectedRequest, err := http.NewRequestWithContext(ctx, http.MethodGet, resourceID+"/records", nil)
	if err != nil {
		t.Fatal(err)
	}
	protectedRequest.Header.Set("X-Request-ID", "resource-session-rotated")
	protectedRequest.Header.Set("Content-Type", "application/json")
	protectedResult, err := rotatedReader.DoWithResourceSession(ctx, protectedRequest, restored)
	if err != nil {
		t.Fatal(err)
	}
	if failure := protectedResult.Failure(); failure != nil {
		t.Fatalf("protected Resource protocol failure: %v", failure)
	}
	protectedResponse, ok := protectedResult.Response()
	if !ok {
		t.Fatal("protected Resource result has no response")
	}
	nextSession, ok := protectedResult.Session()
	if !ok {
		protectedResponse.Body.Close()
		t.Fatal("protected Resource result has no session")
	}
	protectedBody, _ := io.ReadAll(protectedResponse.Body)
	protectedResponse.Body.Close()
	if protectedResponse.StatusCode != http.StatusOK || string(protectedBody) != `{"ok":true}` ||
		nextSession.Token() != session.Token() || protectedCalls != 1 {
		t.Fatalf("protected response = %d %s next=%q protected=%d", protectedResponse.StatusCode, protectedBody, nextSession.Token(), protectedCalls)
	}
	if protectedPrincipal.Resource != resourceID || protectedPrincipal.AgentProvider != agentProviderID ||
		protectedPrincipal.Agent != agentID || protectedPrincipal.Subject != "person-123" ||
		!reflect.DeepEqual(protectedPrincipal.Scope, []string{"records.read"}) ||
		!protectedPrincipal.Confirmation.Equal(rotatedAgentKey.PublicJWK()) ||
		string(protectedPrincipal.AdditionalClaims["platform"]) != `{"level":"rotated"}` {
		t.Fatalf("Resource-managed principal = %#v", protectedPrincipal)
	}

	captureMu.Lock()
	observed := append([]capturedSessionRequest(nil), captured...)
	captureMu.Unlock()
	foundSignedPoll := false
	foundSignedAuthorization := false
	for _, request := range observed {
		if request.Path == "/authorize" || request.Path == "/token" || request.Path == "/person" {
			t.Fatalf("two-party journey entered a PS/AS/token endpoint: %#v", request)
		}
		if request.Path == strings.TrimPrefix(pending.Location(), resourceID) && request.Method == http.MethodGet &&
			request.SignatureInput != "" && request.SignatureKey != "" {
			const emptySHA256 = "sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:"
			for _, component := range []string{`"x-request-id"`, `"content-type"`, `"content-digest"`} {
				if !strings.Contains(request.SignatureInput, component) {
					t.Fatalf("pending poll omitted %s: %s", component, request.SignatureInput)
				}
			}
			if request.ContentDigest != emptySHA256 {
				t.Fatalf("pending poll Content-Digest = %q, want empty-content digest", request.ContentDigest)
			}
			foundSignedPoll = true
		}
		if request.Authorization != "" && strings.Contains(request.SignatureInput, `"authorization"`) {
			foundSignedAuthorization = true
		}
		if request.SignatureKey != "" && !strings.Contains(request.SignatureKey, agentToken) &&
			!strings.Contains(request.SignatureKey, rotatedAgentToken) && !strings.Contains(request.SignatureKey, otherAgentToken) {
			t.Fatalf("Resource request used a credential other than the three Agent tokens: %q", request.SignatureKey)
		}
	}
	if !foundSignedPoll || !foundSignedAuthorization {
		t.Fatalf("signed poll=%v signed Authorization=%v requests=%#v", foundSignedPoll, foundSignedAuthorization, observed)
	}
	if issuedAgentTokens != 3 || store.sessionCount() != 1 {
		t.Fatalf("token custody: agent tokens=%d Resource sessions=%d", issuedAgentTokens, store.sessionCount())
	}
}

func TestResourceManagedIntegrationStorePreservesTerminalStateAgainstLateApproval(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 30, 23, 30, 0, 0, time.UTC)
	store := newIntegrationSessionStore()
	pending := resource.PendingSessionRecord{
		ID: "pending-terminal", CodeSHA256: [32]byte{1}, Resource: "https://resource.example",
		Request: resource.SessionAuthorizationRequest{AgentPrincipal: resource.AgentPrincipal{
			AgentProvider: "https://ap.example", Agent: "aauth:reader@ap.example",
		}},
		CreatedAt: now, ExpiresAt: now.Add(time.Minute), RetryAfter: time.Second, MaximumCodeAttempts: 2,
	}
	if err := store.CreatePending(context.Background(), pending); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ConsumeInteractionCode(
		context.Background(), pending.Resource, pending.ID, resource.SessionCodePresentation{CodeSHA256: pending.CodeSHA256}, now,
	); err != nil {
		t.Fatal(err)
	}
	if err := store.Deny(context.Background(), pending.ID, now); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Approve(
		context.Background(), pending.ID, resource.SessionRecord{}, pending.ExpiresAt,
	); !errors.Is(err, resource.ErrPendingSessionConflict) {
		t.Fatalf("late approval after denial error = %v", err)
	}
	identity := resource.SessionPollIdentity{
		Resource: pending.Resource, AgentProvider: "https://ap.example", Agent: "aauth:reader@ap.example",
	}
	result, err := store.Poll(context.Background(), pending.ID, identity, pending.ExpiresAt)
	if err != nil {
		t.Fatal(err)
	}
	if result.State != resource.SessionPollDenied {
		t.Fatalf("late approval changed denied state to %v", result.State)
	}
	if err := store.ConsumeResult(context.Background(), pending.ID, result); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Approve(
		context.Background(), pending.ID, resource.SessionRecord{}, pending.ExpiresAt,
	); !errors.Is(err, resource.ErrPendingSessionConflict) {
		t.Fatalf("late approval after terminal consumption error = %v", err)
	}
	if _, err := store.Poll(context.Background(), pending.ID, identity, pending.ExpiresAt); !errors.Is(err, resource.ErrPendingSessionGone) {
		t.Fatalf("late approval resurrected consumed result: %v", err)
	}
}

type capturedSessionRequest struct {
	Method         string
	Path           string
	SignatureInput string
	SignatureKey   string
	Authorization  string
	ContentDigest  string
}

// integrationSessionStore is test-only evidence for the public durable-store
// contract. Every mutable value is copied while the mutex owns its transition.
type integrationSessionStore struct {
	mu       sync.Mutex
	next     int
	sessions map[string]resource.SessionRecord
	pending  map[string]*integrationPendingSession
}

type integrationPendingSession struct {
	record   resource.PendingSessionRecord
	state    resource.SessionPollState
	approval resource.SessionApproval
	callback string
}

func newIntegrationSessionStore() *integrationSessionStore {
	return &integrationSessionStore{
		sessions: make(map[string]resource.SessionRecord),
		pending:  make(map[string]*integrationPendingSession),
	}
}

func (store *integrationSessionStore) Create(_ context.Context, record resource.SessionRecord) (resource.SessionApproval, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.createLocked(record), nil
}

func (store *integrationSessionStore) createLocked(record resource.SessionRecord) resource.SessionApproval {
	store.next++
	token := fmt.Sprintf("opaque-session-%d", store.next)
	record = cloneIntegrationSessionRecord(record)
	store.sessions[token] = record
	return resource.SessionApproval{Token: token, Record: cloneIntegrationSessionRecord(record)}
}

func (store *integrationSessionStore) Load(_ context.Context, token string, now time.Time) (resource.SessionRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	record, ok := store.sessions[token]
	if !ok {
		return resource.SessionRecord{}, resource.ErrSessionNotFound
	}
	if !now.Before(record.ExpiresAt) {
		return resource.SessionRecord{}, resource.ErrSessionExpired
	}
	return cloneIntegrationSessionRecord(record), nil
}

func (store *integrationSessionStore) CreatePending(_ context.Context, record resource.PendingSessionRecord) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if _, exists := store.pending[record.ID]; exists {
		return resource.ErrPendingSessionConflict
	}
	store.pending[record.ID] = &integrationPendingSession{
		record: cloneIntegrationPendingRecord(record), state: resource.SessionPollPending,
	}
	return nil
}

func (store *integrationSessionStore) ConsumeInteractionCode(
	_ context.Context, issuer, reference string, presentation resource.SessionCodePresentation, now time.Time,
) (resource.PendingSessionRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	pending, ok := store.pending[reference]
	if !ok || pending.record.Resource != issuer || pending.record.CodeSHA256 != presentation.CodeSHA256 {
		return resource.PendingSessionRecord{}, resource.ErrSessionInteractionCodeInvalid
	}
	if pending.state != resource.SessionPollPending {
		return resource.PendingSessionRecord{}, resource.ErrSessionInteractionCodeUsed
	}
	if !now.Before(pending.record.ExpiresAt) {
		pending.state = resource.SessionPollExpired
		return resource.PendingSessionRecord{}, resource.ErrPendingSessionExpired
	}
	pending.state = resource.SessionPollInteracting
	pending.callback = presentation.Callback
	return cloneIntegrationPendingRecord(pending.record), nil
}

func (store *integrationSessionStore) LoadPending(_ context.Context, reference string) (resource.PendingSessionSnapshot, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	pending, ok := store.pending[reference]
	if !ok {
		return resource.PendingSessionSnapshot{}, resource.ErrPendingSessionNotFound
	}
	return resource.PendingSessionSnapshot{
		Record: cloneIntegrationPendingRecord(pending.record), State: pending.state,
		Approval: cloneIntegrationSessionApproval(pending.approval), Callback: pending.callback,
	}, nil
}

func (store *integrationSessionStore) Approve(
	_ context.Context, reference string, record resource.SessionRecord, now time.Time,
) (resource.SessionApproval, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	pending, ok := store.pending[reference]
	if !ok {
		return resource.SessionApproval{}, resource.ErrPendingSessionNotFound
	}
	if pending.state == resource.SessionPollApproved {
		if reflect.DeepEqual(pending.approval.Record, record) {
			return cloneIntegrationSessionApproval(pending.approval), nil
		}
		return resource.SessionApproval{}, resource.ErrPendingSessionConflict
	}
	if pending.state != resource.SessionPollInteracting {
		return resource.SessionApproval{}, resource.ErrPendingSessionConflict
	}
	if !now.Before(pending.record.ExpiresAt) {
		pending.state = resource.SessionPollExpired
		return resource.SessionApproval{}, resource.ErrPendingSessionExpired
	}
	pending.approval = store.createLocked(record)
	pending.state = resource.SessionPollApproved
	return cloneIntegrationSessionApproval(pending.approval), nil
}

func (store *integrationSessionStore) Deny(_ context.Context, reference string, _ time.Time) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	pending, ok := store.pending[reference]
	if !ok {
		return resource.ErrPendingSessionNotFound
	}
	if pending.state != resource.SessionPollInteracting {
		return resource.ErrPendingSessionConflict
	}
	pending.state = resource.SessionPollDenied
	return nil
}

func (store *integrationSessionStore) Invalidate(_ context.Context, reference string, _ time.Time) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	pending, ok := store.pending[reference]
	if !ok {
		return resource.ErrPendingSessionNotFound
	}
	pending.state = resource.SessionPollGone
	return nil
}

func (store *integrationSessionStore) Poll(
	_ context.Context, reference string, identity resource.SessionPollIdentity, now time.Time,
) (resource.SessionPollRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	pending, ok := store.pending[reference]
	if !ok {
		return resource.SessionPollRecord{}, resource.ErrPendingSessionNotFound
	}
	principal := pending.record.Request.AgentPrincipal
	if identity.Resource != pending.record.Resource || identity.AgentProvider != principal.AgentProvider ||
		identity.Agent != principal.Agent || identity.ParentAgent != principal.ParentAgent {
		return resource.SessionPollRecord{}, resource.ErrPendingSessionNotFound
	}
	if pending.state == resource.SessionPollGone {
		return resource.SessionPollRecord{}, resource.ErrPendingSessionGone
	}
	if !now.Before(pending.record.ExpiresAt) &&
		(pending.state == resource.SessionPollPending || pending.state == resource.SessionPollInteracting) {
		pending.state = resource.SessionPollExpired
	}
	return resource.SessionPollRecord{
		State: pending.state, Approval: cloneIntegrationSessionApproval(pending.approval),
		RetryAfter: pending.record.RetryAfter,
	}, nil
}

func (store *integrationSessionStore) ConsumeResult(_ context.Context, reference string, result resource.SessionPollRecord) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	pending, ok := store.pending[reference]
	if !ok {
		return resource.ErrPendingSessionNotFound
	}
	want := resource.SessionPollRecord{
		State: pending.state, Approval: cloneIntegrationSessionApproval(pending.approval),
		RetryAfter: pending.record.RetryAfter,
	}
	if !reflect.DeepEqual(result, want) ||
		(result.State != resource.SessionPollApproved && result.State != resource.SessionPollDenied && result.State != resource.SessionPollExpired) {
		return resource.ErrPendingSessionConflict
	}
	pending.state = resource.SessionPollGone
	return nil
}

func (store *integrationSessionStore) sessionCount() int {
	store.mu.Lock()
	defer store.mu.Unlock()
	return len(store.sessions)
}

func cloneIntegrationSessionRecord(record resource.SessionRecord) resource.SessionRecord {
	record.Scope = append([]string(nil), record.Scope...)
	return record
}

func cloneIntegrationSessionApproval(approval resource.SessionApproval) resource.SessionApproval {
	approval.Record = cloneIntegrationSessionRecord(approval.Record)
	return approval
}

func cloneIntegrationPendingRecord(record resource.PendingSessionRecord) resource.PendingSessionRecord {
	record.Request.RequiredScopes = append([]string(nil), record.Request.RequiredScopes...)
	claims := record.Request.AgentPrincipal.AdditionalClaims
	if claims != nil {
		record.Request.AgentPrincipal.AdditionalClaims = make(map[string]json.RawMessage, len(claims))
		for name, value := range claims {
			record.Request.AgentPrincipal.AdditionalClaims[name] = append(json.RawMessage(nil), value...)
		}
	}
	return record
}

var _ resource.DeferredSessionStore = (*integrationSessionStore)(nil)
