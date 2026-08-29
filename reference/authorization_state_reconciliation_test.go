package reference

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/internal/snapshotfile"
)

func TestAgentReconcilesPublishedUncertainAuthorizationStateBeforeNextMutation(t *testing.T) {
	store, config := openRoleAuthorizationStateStore(t)
	agent := &Agent{
		authorizationStore: store,
		pendingTokens:      make(map[string]agentPendingTokenRecord),
		pendingAccess:      make(map[string]agentPendingAccessRecord),
	}
	if err := agent.persistAuthorizationStateLocked(context.Background()); err != nil {
		t.Fatal(err)
	}

	injectPublishedUncertainAuthorizationStateCommit(store)
	first := PendingAccessAuthorization{
		ID: "pending-first", Resource: "https://resource.example",
		Location:  "https://resource.example/pending/pending-first",
		NotBefore: time.Unix(1_750_000_000, 0), Status: "pending",
		requestedScope: []string{"records.read"},
	}
	if err := agent.retainPendingAccessAuthorization(context.Background(), first, nil); !errors.Is(err, ErrAuthorizationStateUncertain) {
		t.Fatalf("first retention error = %v, want uncertain commit", err)
	}
	if _, exists := agent.pendingAccess[first.ID]; !exists {
		t.Fatal("published first agent continuation was rolled back in memory")
	}
	if len(agent.authorizationRecovery) == 0 {
		t.Fatal("published uncertain agent continuation was treated as settled authority")
	}

	second := first
	second.ID = "pending-second"
	second.Location = "https://resource.example/pending/pending-second"
	if _, err := agent.restorePendingAccessAuthorization(context.Background(), &first); !errors.Is(err, ErrAuthorizationStateUncertain) {
		t.Fatalf("uncertain agent continuation read error = %v", err)
	}
	if err := agent.retainPendingAccessAuthorization(context.Background(), second, nil); !errors.Is(err, ErrAuthorizationStateUncertain) {
		t.Fatalf("unrelated agent retention during uncertainty = %v", err)
	}
	if _, exists := agent.pendingAccess[second.ID]; exists {
		t.Fatal("unrelated agent continuation entered uncertain state")
	}

	store.file.SetFailureInjectorForTesting(nil)
	agent.authorizationMu.Lock()
	settleErr := agent.settleAuthorizationStateLocked(context.Background())
	agent.authorizationMu.Unlock()
	if settleErr != nil || len(agent.authorizationRecovery) != 0 {
		t.Fatalf("settle exact agent snapshot = %v, recovery bytes = %d", settleErr, len(agent.authorizationRecovery))
	}
	if err := agent.retainPendingAccessAuthorization(context.Background(), second, nil); err != nil {
		t.Fatalf("second retention: %v", err)
	}

	reopened := reopenRoleAuthorizationStateStore(t, store, config)
	reconstructed := &Agent{
		authorizationStore: reopened,
		pendingTokens:      make(map[string]agentPendingTokenRecord),
		pendingAccess:      make(map[string]agentPendingAccessRecord),
	}
	if err := reconstructed.loadAuthorizationState(context.Background()); err != nil {
		t.Fatalf("reconstruct agent: %v", err)
	}
	for _, id := range []string{first.ID, second.ID} {
		if _, exists := reconstructed.pendingAccess[id]; !exists {
			t.Fatalf("reconstructed agent is missing %q", id)
		}
	}
}

func TestResourceReconcilesPublishedUncertainAuthorizationStateBeforeNextMutation(t *testing.T) {
	store, config := openRoleAuthorizationStateStore(t)
	ids := []string{"access-first", "access-blocked", "access-second"}
	resource := &Resource{
		authorizationStore: store,
		pending:            make(map[string]*pendingAuthorization),
		access:             make(map[string]localAccessGrant),
		newID: func() string {
			id := ids[0]
			ids = ids[1:]
			return id
		},
	}
	if err := resource.persistAuthorizationStateLocked(context.Background()); err != nil {
		t.Fatal(err)
	}

	injectPublishedUncertainAuthorizationStateCommit(store)
	request := aauth.AuthorizationRequest{Agent: "aauth:first@ap.example", Resource: "https://resource.example", Scope: []string{"records.read"}}
	decision := aauth.AuthorizationDecision{Subject: "person:first", Scope: []string{"records.read"}}
	if _, err := resource.storeAccessGrant(request, decision, strings.Repeat("A", 43), time.Unix(1_750_003_600, 0)); !errors.Is(err, ErrAuthorizationStateUncertain) {
		t.Fatalf("first grant error = %v, want uncertain commit", err)
	}
	if _, exists := resource.access["access-first"]; !exists {
		t.Fatal("published first resource grant was rolled back in memory")
	}
	if len(resource.authorizationRecovery) == 0 {
		t.Fatal("published uncertain resource grant was treated as settled authority")
	}
	blocked := httptest.NewRecorder()
	resource.handleAccessProtected(blocked, httptest.NewRequest("POST", "https://resource.example/protected", nil))
	if blocked.Code != 503 {
		t.Fatalf("uncertain resource authority response = %d, want 503", blocked.Code)
	}

	request.Agent = "aauth:second@ap.example"
	decision.Subject = "person:second"
	if _, err := resource.storeAccessGrant(request, decision, strings.Repeat("B", 43), time.Unix(1_750_007_200, 0)); !errors.Is(err, ErrAuthorizationStateUncertain) {
		t.Fatalf("unrelated resource grant during uncertainty = %v", err)
	}
	if _, exists := resource.access["access-blocked"]; exists {
		t.Fatal("unrelated resource grant entered uncertain state")
	}

	store.file.SetFailureInjectorForTesting(nil)
	resource.pendingMu.Lock()
	settleErr := resource.settleAuthorizationStateLocked(context.Background())
	resource.pendingMu.Unlock()
	if settleErr != nil || len(resource.authorizationRecovery) != 0 {
		t.Fatalf("settle exact resource snapshot = %v, recovery bytes = %d", settleErr, len(resource.authorizationRecovery))
	}
	if _, err := resource.storeAccessGrant(request, decision, strings.Repeat("C", 43), time.Unix(1_750_007_200, 0)); err != nil {
		t.Fatalf("second grant: %v", err)
	}

	reopened := reopenRoleAuthorizationStateStore(t, store, config)
	reconstructed := &Resource{
		authorizationStore: reopened,
		pending:            make(map[string]*pendingAuthorization),
		access:             make(map[string]localAccessGrant),
	}
	if err := reconstructed.loadAuthorizationState(context.Background()); err != nil {
		t.Fatalf("reconstruct resource: %v", err)
	}
	for _, id := range []string{"access-first", "access-second"} {
		if _, exists := reconstructed.access[id]; !exists {
			t.Fatalf("reconstructed resource is missing %q", id)
		}
	}
}

func TestResourceInitialSessionRequestSettlesPublishedUncertainStateBeforeFreshWork(t *testing.T) {
	store, _ := openRoleAuthorizationStateStore(t)
	now := time.Date(2026, 8, 28, 22, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	issuerKey := referenceTestSigningKey(t, "issuer-key")
	agentKey := referenceTestSigningKey(t, "agent-key")
	agentToken, err := aauth.MintAgentToken(
		"https://ap.example",
		issuerKey,
		aauth.AgentTokenRequest{
			Agent:     "aauth:agent@ap.example",
			PublicKey: agentKey.PublicJWK(),
			Lifetime:  time.Hour,
		},
		now,
		"agent-token",
	)
	if err != nil {
		t.Fatal(err)
	}

	replayStore := &countingProofReplayStore{}
	scopeCalls := 0
	interactionCalls := 0
	policyCalls := 0
	operationCalls := 0
	ids := []string{"uncertain-access", "unexpected-access"}
	resource, err := NewResource(ResourceConfig{
		Identifier: "https://resource.example",
		AccessMode: aauth.AccessModeSessionToken,
		KeyResolver: aauth.StaticKeyResolver{
			"https://ap.example": {issuerKey.ID(): issuerKey.PublicJWK()},
		},
		Clock: clock,
		NewID: func() string {
			id := ids[0]
			ids = ids[1:]
			return id
		},
		Scopes: []string{"records.read"},
		RequiredScopesForRequest: func(context.Context, *http.Request) ([]string, error) {
			scopeCalls++
			return []string{"records.read"}, nil
		},
		ReplayStore:        replayStore,
		AuthorizationStore: store,
		InteractionRequired: func(context.Context, aauth.AuthorizationRequest) (bool, error) {
			interactionCalls++
			return false, nil
		},
		AuthorizationPolicy: func(context.Context, aauth.AuthorizationRequest) (aauth.AuthorizationDecision, error) {
			policyCalls++
			return aauth.AuthorizationDecision{Subject: "person-1", Scope: []string{"records.read"}}, nil
		},
		Operation: func(context.Context, aauth.AuthorizedRequest) (any, error) {
			operationCalls++
			return map[string]bool{"ok": true}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	injectPublishedUncertainAuthorizationStateCommit(store)
	_, err = resource.storeAccessGrant(
		aauth.AuthorizationRequest{
			Agent: "aauth:agent@ap.example", Resource: "https://resource.example",
			Scope: []string{"records.read"},
		},
		aauth.AuthorizationDecision{Subject: "person-1", Scope: []string{"records.read"}},
		strings.Repeat("A", 43),
		now.Add(time.Hour),
	)
	if !errors.Is(err, ErrAuthorizationStateUncertain) || len(resource.authorizationRecovery) == 0 {
		t.Fatalf("published uncertain setup = %v, recovery bytes = %d", err, len(resource.authorizationRecovery))
	}

	request := httptest.NewRequest(http.MethodGet, "https://resource.example/records", nil)
	if err := aauth.SignRequest(request, agentKey, agentToken, clock); err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	resource.Handler().ServeHTTP(response, request)

	if response.Code != http.StatusServiceUnavailable ||
		!bytes.Contains(response.Body.Bytes(), []byte(`"error":"authorization_state_unavailable"`)) {
		t.Fatalf("uncertain initial request = %d: %s", response.Code, response.Body.String())
	}
	if replayStore.calls != 0 || scopeCalls != 0 || interactionCalls != 0 || policyCalls != 0 || operationCalls != 0 {
		t.Fatalf(
			"uncertain initial request reached replay/scope/interaction/policy/operation = %d/%d/%d/%d/%d",
			replayStore.calls,
			scopeCalls,
			interactionCalls,
			policyCalls,
			operationCalls,
		)
	}
}

func TestResourceRestoresPreviousSnapshotAfterUnpublishedAuthorizationStateFailure(t *testing.T) {
	store, config := openRoleAuthorizationStateStore(t)
	ids := []string{"unpublished-access", "durable-access"}
	resource := &Resource{
		authorizationStore: store,
		pending:            make(map[string]*pendingAuthorization),
		access:             make(map[string]localAccessGrant),
		newID: func() string {
			id := ids[0]
			ids = ids[1:]
			return id
		},
	}
	if err := resource.persistAuthorizationStateLocked(context.Background()); err != nil {
		t.Fatal(err)
	}
	store.file.SetFailureInjectorForTesting(func(phase snapshotfile.CommitPhase) error {
		if phase == snapshotfile.CommitAfterFileSync {
			return errors.New("injected failure before rename")
		}
		return nil
	})
	request := aauth.AuthorizationRequest{Agent: "aauth:first@ap.example", Resource: "https://resource.example", Scope: []string{"records.read"}}
	decision := aauth.AuthorizationDecision{Subject: "person:first", Scope: []string{"records.read"}}
	if _, err := resource.storeAccessGrant(request, decision, strings.Repeat("A", 43), time.Unix(1_750_003_600, 0)); err == nil {
		t.Fatal("unpublished replacement unexpectedly succeeded")
	}
	if _, exists := resource.access["unpublished-access"]; exists {
		t.Fatal("unpublished candidate remained in resource memory")
	}
	store.file.SetFailureInjectorForTesting(nil)
	if _, err := resource.storeAccessGrant(request, decision, strings.Repeat("B", 43), time.Unix(1_750_007_200, 0)); err != nil {
		t.Fatal(err)
	}
	reopened := reopenRoleAuthorizationStateStore(t, store, config)
	reconstructed := &Resource{
		authorizationStore: reopened,
		pending:            make(map[string]*pendingAuthorization),
		access:             make(map[string]localAccessGrant),
	}
	if err := reconstructed.loadAuthorizationState(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, exists := reconstructed.access["unpublished-access"]; exists {
		t.Fatal("unpublished candidate reached reconstructed resource")
	}
	if _, exists := reconstructed.access["durable-access"]; !exists {
		t.Fatal("durable successor was not reconstructed")
	}
}

func TestPersonServerReconcilesPublishedUncertainAuthorizationStateBeforeNextMutation(t *testing.T) {
	store, config := openRoleAuthorizationStateStore(t)
	fixture := newAuthorizationStateSemanticFixture(t)
	now := fixture.now
	server := &PersonServer{
		identifier:         "https://ps.example",
		signingKey:         fixture.personKey,
		clock:              aauth.ClockFunc(func() time.Time { return now }),
		random:             distinctPendingRandomness(),
		pendingLifetime:    time.Hour,
		authorizationStore: store,
		pending:            make(map[string]*pendingPersonAuthorization),
	}
	if err := server.persistAuthorizationStateLocked(context.Background()); err != nil {
		t.Fatal(err)
	}

	firstID, blockedID, secondID := deterministicThreePendingIDs(t)
	injectPublishedUncertainAuthorizationStateCommit(store)
	first := restorePersonAuthorizationContext(fixture.personRecord(t, 1, false).Context)
	if err := server.beginPendingAuthorization(httptest.NewRecorder(), first); !errors.Is(err, ErrAuthorizationStateUncertain) {
		t.Fatalf("first pending error = %v, want uncertain commit", err)
	}
	if _, exists := server.pending[firstID]; !exists {
		t.Fatal("published first person-server continuation was rolled back in memory")
	}
	if len(server.authorizationRecovery) == 0 {
		t.Fatal("published uncertain person-server continuation was treated as settled authority")
	}
	if err := server.ApproveAuthorization(context.Background(), firstID); !errors.Is(err, ErrAuthorizationStateUncertain) {
		t.Fatalf("uncertain person-server authority error = %v", err)
	}

	second := restorePersonAuthorizationContext(fixture.personRecord(t, 2, false).Context)
	if err := server.beginPendingAuthorization(httptest.NewRecorder(), second); !errors.Is(err, ErrAuthorizationStateUncertain) {
		t.Fatalf("unrelated person-server pending during uncertainty = %v", err)
	}
	if _, exists := server.pending[blockedID]; exists {
		t.Fatal("unrelated person-server continuation entered uncertain state")
	}

	store.file.SetFailureInjectorForTesting(nil)
	server.pendingMu.Lock()
	settleErr := server.settleAuthorizationStateLocked(context.Background())
	server.pendingMu.Unlock()
	if settleErr != nil || len(server.authorizationRecovery) != 0 {
		t.Fatalf("settle exact person-server snapshot = %v, recovery bytes = %d", settleErr, len(server.authorizationRecovery))
	}
	if err := server.beginPendingAuthorization(httptest.NewRecorder(), second); err != nil {
		t.Fatalf("second pending authorization: %v", err)
	}

	reopened := reopenRoleAuthorizationStateStore(t, store, config)
	reconstructed := &PersonServer{
		identifier:         "https://ps.example",
		signingKey:         fixture.personKey,
		authorizationStore: reopened,
		pending:            make(map[string]*pendingPersonAuthorization),
	}
	if err := reconstructed.loadAuthorizationState(context.Background()); err != nil {
		t.Fatalf("reconstruct person server: %v", err)
	}
	for _, id := range []string{firstID, secondID} {
		if _, exists := reconstructed.pending[id]; !exists {
			t.Fatalf("reconstructed person server is missing %q", id)
		}
	}
}

func TestAccessServerReconcilesPublishedUncertainAuthorizationStateBeforeNextMutation(t *testing.T) {
	store, config := openRoleAuthorizationStateStore(t)
	fixture := newAuthorizationStateSemanticFixture(t)
	now := fixture.now
	server := &AccessServer{
		identifier:         "https://as.example",
		signingKey:         fixture.accessKey,
		clock:              aauth.ClockFunc(func() time.Time { return now }),
		random:             distinctPendingRandomness(),
		pendingLifetime:    time.Hour,
		authorizationStore: store,
		pending:            make(map[string]*pendingAccessServerAuthorization),
	}
	if err := server.persistAuthorizationStateLocked(context.Background()); err != nil {
		t.Fatal(err)
	}

	firstID, blockedID, secondID := deterministicThreePendingIDs(t)
	injectPublishedUncertainAuthorizationStateCommit(store)
	first := restoreAccessAuthorizationContext(fixture.accessRecord(t, 1, false).Context)
	if err := server.beginPendingAuthorization(httptest.NewRecorder(), first); !errors.Is(err, ErrAuthorizationStateUncertain) {
		t.Fatalf("first pending error = %v, want uncertain commit", err)
	}
	if _, exists := server.pending[firstID]; !exists {
		t.Fatal("published first access-server continuation was rolled back in memory")
	}
	if len(server.authorizationRecovery) == 0 {
		t.Fatal("published uncertain access-server continuation was treated as settled authority")
	}
	if err := server.ApproveAuthorization(context.Background(), firstID); !errors.Is(err, ErrAuthorizationStateUncertain) {
		t.Fatalf("uncertain access-server authority error = %v", err)
	}

	second := restoreAccessAuthorizationContext(fixture.accessRecord(t, 2, false).Context)
	if err := server.beginPendingAuthorization(httptest.NewRecorder(), second); !errors.Is(err, ErrAuthorizationStateUncertain) {
		t.Fatalf("unrelated access-server pending during uncertainty = %v", err)
	}
	if _, exists := server.pending[blockedID]; exists {
		t.Fatal("unrelated access-server continuation entered uncertain state")
	}

	store.file.SetFailureInjectorForTesting(nil)
	server.pendingMu.Lock()
	settleErr := server.settleAuthorizationStateLocked(context.Background())
	server.pendingMu.Unlock()
	if settleErr != nil || len(server.authorizationRecovery) != 0 {
		t.Fatalf("settle exact access-server snapshot = %v, recovery bytes = %d", settleErr, len(server.authorizationRecovery))
	}
	if err := server.beginPendingAuthorization(httptest.NewRecorder(), second); err != nil {
		t.Fatalf("second pending authorization: %v", err)
	}

	reopened := reopenRoleAuthorizationStateStore(t, store, config)
	reconstructed := &AccessServer{
		identifier:         "https://as.example",
		signingKey:         fixture.accessKey,
		authorizationStore: reopened,
		pending:            make(map[string]*pendingAccessServerAuthorization),
	}
	if err := reconstructed.loadAuthorizationState(context.Background()); err != nil {
		t.Fatalf("reconstruct access server: %v", err)
	}
	for _, id := range []string{firstID, secondID} {
		if _, exists := reconstructed.pending[id]; !exists {
			t.Fatalf("reconstructed access server is missing %q", id)
		}
	}
}

func TestAuthorizationRolesRejectImpossibleDecodedState(t *testing.T) {
	expiresAt := time.Unix(1_750_003_600, 0).UTC()

	t.Run("agent unknown continuation status", func(t *testing.T) {
		record := agentAuthorizationStateRecord{
			Kind: "access", Key: "pending-agent",
			Access: &agentPendingAccessRecord{
				ID: "pending-agent", Resource: "https://resource.example",
				Location:  "https://resource.example/pending/pending-agent",
				NotBefore: expiresAt, Status: "invented", RequestedScope: []string{"records.read"},
			},
		}
		agent := &Agent{}
		err := agent.restoreAuthorizationStateLocked(roleAuthorizationSnapshot(t, agentAuthorizationStateSchema, record))
		if !errors.Is(err, ErrAuthorizationStateIntegrity) {
			t.Fatalf("agent impossible state error = %v", err)
		}
	})

	t.Run("resource terminal grant on waiting continuation", func(t *testing.T) {
		record := resourceAuthorizationStateRecord{
			Kind: "pending", Key: "pending-resource",
			Pending: &resourcePendingAuthorizationRecord{
				ID: "pending-resource", Code: "0000-0000", NormalizedCode: "00000000",
				State: pendingAuthorizationWaiting, ExpiresAt: expiresAt,
				Request: aauth.AuthorizationRequest{
					Agent: "aauth:agent@ap.example", Resource: "https://resource.example", Scope: []string{"records.read"},
				},
				AgentThumbprint: "thumbprint", AgentExpiresAt: expiresAt,
				TerminalAccessToken: "access-token",
			},
		}
		resource := &Resource{}
		err := resource.restoreAuthorizationStateLocked(roleAuthorizationSnapshot(t, resourceAuthorizationStateSchema, record))
		if !errors.Is(err, ErrAuthorizationStateIntegrity) {
			t.Fatalf("resource impossible state error = %v", err)
		}
	})

	t.Run("person server terminal token on waiting continuation", func(t *testing.T) {
		record := personAuthorizationStateRecord{
			Key: "pending-person",
			Interaction: pendingInteractionRecord{
				ID: "pending-person", Code: "0000-0000", NormalizedCode: "00000000",
				State: pendingAuthorizationWaiting, ExpiresAt: expiresAt,
			},
			TerminalAuthToken: "auth-token", TerminalExpiresAt: expiresAt.Unix(),
		}
		server := &PersonServer{}
		err := server.restoreAuthorizationStateLocked(roleAuthorizationSnapshot(t, personAuthorizationStateSchema, record))
		if !errors.Is(err, ErrAuthorizationStateIntegrity) {
			t.Fatalf("person-server impossible state error = %v", err)
		}
	})

	t.Run("access server unknown continuation state", func(t *testing.T) {
		record := accessAuthorizationStateRecord{
			Key: "pending-access",
			Interaction: pendingInteractionRecord{
				ID: "pending-access", State: pendingAuthorizationState("invented"), ExpiresAt: expiresAt,
			},
		}
		server := &AccessServer{}
		err := server.restoreAuthorizationStateLocked(roleAuthorizationSnapshot(t, accessAuthorizationStateSchema, record))
		if !errors.Is(err, ErrAuthorizationStateIntegrity) {
			t.Fatalf("access-server impossible state error = %v", err)
		}
	})
}

func TestPersonAndAccessServersRejectSemanticallyCorruptCanonicalStateAfterReopen(t *testing.T) {
	fixture := newAuthorizationStateSemanticFixture(t)

	t.Run("valid person-server state", func(t *testing.T) {
		record := fixture.personRecord(t, 1, true)
		fixture.loadPersonRecordsAfterReopen(t, false, record)
	})

	t.Run("person-server decision expands requested scope", func(t *testing.T) {
		record := fixture.personRecord(t, 1, false)
		record.Decision.Scope = append(record.Decision.Scope, "records.write")
		fixture.loadPersonRecordsAfterReopen(t, true, record)
	})

	t.Run("person-server compact resource token differs from retained claims", func(t *testing.T) {
		record := fixture.personRecord(t, 1, false)
		other := fixture.personRecord(t, 2, false)
		record.Context.ResourceTokenCompact = other.Context.ResourceTokenCompact
		fixture.loadPersonRecordsAfterReopen(t, true, record)
	})

	t.Run("person-server target key differs from resource token", func(t *testing.T) {
		record := fixture.personRecord(t, 1, false)
		record.Context.TargetKey = fixture.agentKeys[1].PublicJWK()
		fixture.loadPersonRecordsAfterReopen(t, true, record)
	})

	t.Run("person-server polling identity differs from retained agent token", func(t *testing.T) {
		record := fixture.personRecord(t, 1, false)
		record.Context.PollingAgent = "aauth:other@ap.example"
		fixture.loadPersonRecordsAfterReopen(t, true, record)
	})

	t.Run("person-server rejects noncanonical emitted interaction code", func(t *testing.T) {
		record := fixture.personRecord(t, 1, false)
		record.Interaction.Code = "oooo-oooo"
		record.Interaction.NormalizedCode = "00000000"
		fixture.loadPersonRecordsAfterReopen(t, true, record)
	})

	t.Run("person-server rejects noncanonical pending identifier", func(t *testing.T) {
		record := fixture.personRecord(t, 1, false)
		record.Key = "short"
		record.Interaction.ID = record.Key
		fixture.loadPersonRecordsAfterReopen(t, true, record)
	})

	t.Run("person-server retained person-token receipt must bind presented jti", func(t *testing.T) {
		record := fixture.personRecord(t, 1, false)
		record.Context.PersonTokenRecord.JTI = "different-person-token"
		fixture.loadPersonRecordsAfterReopen(t, true, record)
	})

	t.Run("person-server retained input verification key must verify compact token", func(t *testing.T) {
		record := fixture.personRecord(t, 1, false)
		record.Context.TokenVerificationKeys.Resource = fixture.providerKey.PublicJWK()
		fixture.loadPersonRecordsAfterReopen(t, true, record)
	})

	t.Run("person-server signed justification cannot be mutated", func(t *testing.T) {
		record := fixture.personRecord(t, 1, false)
		record.Context.Request.Justification = "mutated after admission"
		fixture.loadPersonRecordsAfterReopen(t, true, record)
	})

	t.Run("person-server request proof binds credential issuer", func(t *testing.T) {
		record := fixture.personRecord(t, 1, false)
		record.Context.RequestProof.CredentialIssuer = "https://other-ap.example"
		fixture.loadPersonRecordsAfterReopen(t, true, record)
	})

	t.Run("person-server request proof verified_at is canonical UTC", func(t *testing.T) {
		record := fixture.personRecord(t, 1, false)
		record.Context.RequestProof.VerifiedAt = record.Context.RequestProof.VerifiedAt.In(
			time.FixedZone("noncanonical-offset", -7*60*60),
		)
		fixture.loadPersonRecordsAfterReopen(t, true, record)
	})

	t.Run("person-server exact signed request body cannot be mutated", func(t *testing.T) {
		record := fixture.personRecord(t, 1, false)
		record.Context.RequestBody = append(record.Context.RequestBody, ' ')
		fixture.loadPersonRecordsAfterReopen(t, true, record)
	})

	t.Run("person-server retained signed request body stays bounded", func(t *testing.T) {
		record := fixture.personRecord(t, 1, false)
		record.Context.RequestBody = make([]byte, maxJSONBody+1)
		server := &PersonServer{identifier: "https://ps.example", signingKey: fixture.personKey}
		if err := server.validatePersonAuthorizationStateRecord(record); !errors.Is(err, ErrAuthorizationStateIntegrity) {
			t.Fatalf("person-server oversized retained body error = %v", err)
		}
	})

	t.Run("person-server retained request issuer key cannot be swapped", func(t *testing.T) {
		record := fixture.personRecord(t, 1, false)
		record.Context.TokenVerificationKeys.Agent = fixture.resourceKey.PublicJWK()
		fixture.loadPersonRecordsAfterReopen(t, true, record)
	})

	t.Run("person-server optional compact and verification key must have matching presence", func(t *testing.T) {
		record := fixture.personRecord(t, 1, false)
		key := fixture.providerKey.PublicJWK()
		record.Context.TokenVerificationKeys.Subagent = &key
		fixture.loadPersonRecordsAfterReopen(t, true, record)
	})

	t.Run("person-server rejects subsecond interaction lifetime expansion", func(t *testing.T) {
		record := fixture.personRecord(t, 1, false)
		record.Interaction.ExpiresAt = time.Unix(record.Context.ResourceToken.ExpiresAt, 1).UTC()
		fixture.loadPersonRecordsAfterReopen(t, true, record)
	})

	t.Run("person-server rejects interaction deadline before retained inputs", func(t *testing.T) {
		record := fixture.personRecord(t, 1, false)
		record.Interaction.ExpiresAt = time.Unix(record.Context.ResourceToken.IssuedAt, 0).UTC()
		fixture.loadPersonRecordsAfterReopen(t, true, record)
	})

	t.Run("person-server accepts reachable expiry after third failed code", func(t *testing.T) {
		record := fixture.personRecord(t, 1, false)
		record.Interaction.State = pendingAuthorizationExpired
		record.Interaction.CodeConsumed = false
		record.Interaction.FailedCodeAttempts = maxInteractionCodeAttempts
		record.Decision = aauth.AuthorizationDecision{}
		fixture.loadPersonRecordsAfterReopen(t, false, record)
	})

	t.Run("person-server local rejection uses polling error only", func(t *testing.T) {
		record := fixture.personRecord(t, 1, false)
		record.Interaction.State = pendingAuthorizationRejected
		record.Interaction.PollingError = aauth.PollingDenied
		record.Decision = aauth.AuthorizationDecision{}
		fixture.loadPersonRecordsAfterReopen(t, false, record)
		record.TerminalStatus = http.StatusForbidden
		record.TerminalCode = "denied"
		record.TerminalDetail = "denied"
		fixture.loadPersonRecordsAfterReopen(t, true, record)
	})

	t.Run("person-server terminal token is transplanted from another record", func(t *testing.T) {
		first := fixture.personRecord(t, 1, true)
		second := fixture.personRecord(t, 2, true)
		first.TerminalAuthToken, second.TerminalAuthToken = second.TerminalAuthToken, first.TerminalAuthToken
		fixture.loadPersonRecordsAfterReopen(t, true, first, second)
	})

	t.Run("person-server terminal token signature is corrupt", func(t *testing.T) {
		record := fixture.personRecord(t, 1, true)
		record.TerminalAuthToken = corruptRetainedTokenSignature(t, record.TerminalAuthToken)
		fixture.loadPersonRecordsAfterReopen(t, true, record)
	})

	t.Run("person-server terminal token cannot predate retained inputs", func(t *testing.T) {
		record := fixture.personRecord(t, 1, true)
		claims := fixture.terminalClaims(
			1, record.Key, "https://ps.example", aauth.PersonDiscoveryDocument,
			record.Context.ResourceToken, record.Context.TargetKey, record.Decision,
		)
		claims.IssuedAt = record.Context.ResourceToken.IssuedAt - 1
		var err error
		record.TerminalAuthToken, err = aauth.MintAuthToken(fixture.personKey, claims)
		if err != nil {
			t.Fatal(err)
		}
		record.TerminalExpiresAt = claims.ExpiresAt
		fixture.loadPersonRecordsAfterReopen(t, true, record)
	})

	t.Run("person-server terminal token remains verifiable after local signing-key rotation", func(t *testing.T) {
		record := fixture.personRecord(t, 1, true)
		store := reopenedAuthorizationStateWithRecords(t, personAuthorizationStateSchema, record)
		server := &PersonServer{
			identifier: "https://ps.example", signingKey: fixture.accessKey,
			authorizationStore: store, pending: make(map[string]*pendingPersonAuthorization),
		}
		if err := server.loadAuthorizationState(context.Background()); err != nil {
			t.Fatalf("person-server rotated signing-key recovery = %v", err)
		}
	})

	t.Run("person-server same-context terminal-token swap is rejected", func(t *testing.T) {
		first := fixture.personRecord(t, 1, true)
		second := first
		second.Key = semanticPendingID(t, 2)
		second.Interaction.ID = second.Key
		claims := fixture.terminalClaims(
			2, second.Key, "https://ps.example", aauth.PersonDiscoveryDocument,
			second.Context.ResourceToken, second.Context.TargetKey, second.Decision,
		)
		var err error
		second.TerminalAuthToken, err = aauth.MintAuthToken(fixture.personKey, claims)
		if err != nil {
			t.Fatal(err)
		}
		second.TerminalExpiresAt = claims.ExpiresAt
		first.TerminalAuthToken, second.TerminalAuthToken = second.TerminalAuthToken, first.TerminalAuthToken
		fixture.loadPersonRecordsAfterReopen(t, true, first, second)
	})

	t.Run("person-server federated terminal uses retained verification key offline", func(t *testing.T) {
		record := fixture.federatedPersonRecord(t, 1, true)
		fixture.loadPersonRecordsAfterReopen(t, false, record)
	})

	t.Run("person-server federated terminal verification key is corrupt", func(t *testing.T) {
		record := fixture.federatedPersonRecord(t, 1, true)
		wrong := fixture.personKey.PublicJWK()
		record.TerminalVerificationKey = &wrong
		fixture.loadPersonRecordsAfterReopen(t, true, record)
	})

	t.Run("person-server federated terminal may use a shorter bounded lifetime", func(t *testing.T) {
		record := fixture.federatedPersonRecord(t, 1, true)
		claims := fixture.terminalClaims(
			1, record.Key, "https://as.example", aauth.AccessDiscoveryDocument,
			record.Context.ResourceToken, record.Context.TargetKey, record.Decision,
		)
		claims.ExpiresAt--
		var err error
		record.TerminalAuthToken, err = aauth.MintAuthToken(fixture.accessKey, claims)
		if err != nil {
			t.Fatal(err)
		}
		record.TerminalExpiresAt = claims.ExpiresAt
		fixture.loadPersonRecordsAfterReopen(t, false, record)
	})

	t.Run("person-server federated terminal remains bounded by original person grant", func(t *testing.T) {
		record := fixture.federatedPersonRecord(t, 1, true)
		requested := []string{"records.1.read", "records.extra.read"}
		resource := record.Context.ResourceToken
		resource.Scope = strings.Join(requested, " ")
		compact, err := aauth.MintResourceToken(fixture.resourceKey, resource)
		if err != nil {
			t.Fatal(err)
		}
		record.Context.ResourceToken = resource
		record.Context.ResourceTokenCompact = compact
		record.Context.Request.Scope = append([]string(nil), requested...)
		record.Decision.Scope = append([]string(nil), requested...)
		fixture.bindPersonRequestEvidence(t, &record, fixture.agentKeys[0])
		claims := fixture.terminalClaims(
			1, record.Key, "https://as.example", aauth.AccessDiscoveryDocument,
			resource, record.Context.TargetKey,
			aauth.AuthorizationDecision{Subject: record.Decision.Subject, Scope: requested[:1]},
		)
		record.TerminalAuthToken, err = aauth.MintAuthToken(fixture.accessKey, claims)
		if err != nil {
			t.Fatal(err)
		}
		record.TerminalExpiresAt = claims.ExpiresAt
		fixture.loadPersonRecordsAfterReopen(t, false, record)
	})

	t.Run("person-server federated whole-bundle swap is rejected", func(t *testing.T) {
		first := fixture.federatedPersonRecord(t, 1, true)
		second := first
		second.Key = semanticPendingID(t, 2)
		second.Interaction.ID = second.Key
		fixture.loadPersonRecordsAfterReopen(t, true, first, second)
	})

	t.Run("person-server federated rejection uses terminal problem only", func(t *testing.T) {
		record := fixture.federatedPersonRecord(t, 1, false)
		record.Interaction.State = pendingAuthorizationRejected
		record.TerminalStatus = http.StatusBadGateway
		record.TerminalCode = "federation_failed"
		record.TerminalDetail = "authorization federation failed"
		fixture.loadPersonRecordsAfterReopen(t, false, record)
		record.Interaction.PollingError = aauth.PollingDenied
		fixture.loadPersonRecordsAfterReopen(t, true, record)
	})

	t.Run("valid access-server state", func(t *testing.T) {
		record := fixture.accessRecord(t, 1, true)
		fixture.loadAccessRecordsAfterReopen(t, false, record)
	})

	t.Run("access-server decision expands requested scope", func(t *testing.T) {
		record := fixture.accessRecord(t, 1, false)
		record.Decision.Scope = append(record.Decision.Scope, "records.write")
		fixture.loadAccessRecordsAfterReopen(t, true, record)
	})

	t.Run("access-server compact resource token differs from retained claims", func(t *testing.T) {
		record := fixture.accessRecord(t, 1, false)
		other := fixture.accessRecord(t, 2, false)
		record.Context.ResourceTokenCompact = other.Context.ResourceTokenCompact
		fixture.loadAccessRecordsAfterReopen(t, true, record)
	})

	t.Run("access-server target key differs from resource token", func(t *testing.T) {
		record := fixture.accessRecord(t, 1, false)
		record.Context.TargetKey = fixture.agentKeys[1].PublicJWK()
		fixture.loadAccessRecordsAfterReopen(t, true, record)
	})

	t.Run("access-server retained agent token differs from target context", func(t *testing.T) {
		record := fixture.accessRecord(t, 1, false)
		other := fixture.accessRecord(t, 2, false)
		record.Context.AgentTokenCompact = other.Context.AgentTokenCompact
		fixture.loadAccessRecordsAfterReopen(t, true, record)
	})

	t.Run("access-server retained input verification key must verify compact token", func(t *testing.T) {
		record := fixture.accessRecord(t, 1, false)
		record.Context.TokenVerificationKeys.Agent = fixture.resourceKey.PublicJWK()
		fixture.loadAccessRecordsAfterReopen(t, true, record)
	})

	t.Run("access-server optional compact and verification key must have matching presence", func(t *testing.T) {
		record := fixture.accessRecord(t, 1, false)
		key := fixture.providerKey.PublicJWK()
		record.Context.TokenVerificationKeys.Upstream = &key
		fixture.loadAccessRecordsAfterReopen(t, true, record)
	})

	t.Run("access-server rejects subsecond interaction lifetime expansion", func(t *testing.T) {
		record := fixture.accessRecord(t, 1, false)
		record.Interaction.ExpiresAt = time.Unix(record.Context.ResourceToken.ExpiresAt, 1).UTC()
		fixture.loadAccessRecordsAfterReopen(t, true, record)
	})

	t.Run("access-server rejects interaction deadline before retained inputs", func(t *testing.T) {
		record := fixture.accessRecord(t, 1, false)
		record.Interaction.ExpiresAt = time.Unix(record.Context.ResourceToken.IssuedAt, 0).UTC()
		fixture.loadAccessRecordsAfterReopen(t, true, record)
	})

	t.Run("access-server accepts reachable expiry after third failed code", func(t *testing.T) {
		record := fixture.accessRecord(t, 1, false)
		record.Interaction.State = pendingAuthorizationExpired
		record.Interaction.CodeConsumed = true
		record.Interaction.FailedCodeAttempts = maxInteractionCodeAttempts
		record.Decision = aauth.AuthorizationDecision{}
		fixture.loadAccessRecordsAfterReopen(t, false, record)
	})

	t.Run("access-server rejection uses polling error only", func(t *testing.T) {
		record := fixture.accessRecord(t, 1, false)
		record.Interaction.State = pendingAuthorizationRejected
		record.Interaction.PollingError = aauth.PollingDenied
		record.Decision = aauth.AuthorizationDecision{}
		fixture.loadAccessRecordsAfterReopen(t, false, record)
		record.TerminalStatus = http.StatusForbidden
		record.TerminalCode = "denied"
		record.TerminalDetail = "denied"
		fixture.loadAccessRecordsAfterReopen(t, true, record)
	})

	t.Run("access-server polling server differs from retained person server", func(t *testing.T) {
		record := fixture.accessRecord(t, 1, false)
		record.Context.PollingServer = "https://other-ps.example"
		fixture.loadAccessRecordsAfterReopen(t, true, record)
	})

	t.Run("access-server polling key differs from retained thumbprint", func(t *testing.T) {
		record := fixture.accessRecord(t, 1, false)
		record.Context.PollingKey = fixture.accessKey.PublicJWK()
		fixture.loadAccessRecordsAfterReopen(t, true, record)
	})

	t.Run("access-server signed request prevents polling authority replacement", func(t *testing.T) {
		record := fixture.accessRecord(t, 1, false)
		replacement := fixture.accessKey.PublicJWK()
		thumbprint, err := replacement.Thumbprint()
		if err != nil {
			t.Fatal(err)
		}
		record.Context.PollingKey = replacement
		record.Context.PollingKeyThumbprint = thumbprint
		fixture.loadAccessRecordsAfterReopen(t, true, record)
	})

	t.Run("access-server jwks request proof has no credential issuer", func(t *testing.T) {
		record := fixture.accessRecord(t, 1, false)
		record.Context.RequestProof.CredentialIssuer = "https://ps.example"
		fixture.loadAccessRecordsAfterReopen(t, true, record)
	})

	t.Run("access-server request proof verified_at is canonical UTC", func(t *testing.T) {
		record := fixture.accessRecord(t, 1, false)
		record.Context.RequestProof.VerifiedAt = record.Context.RequestProof.VerifiedAt.In(
			time.FixedZone("noncanonical-offset", -7*60*60),
		)
		fixture.loadAccessRecordsAfterReopen(t, true, record)
	})

	t.Run("access-server terminal token is transplanted from another record", func(t *testing.T) {
		first := fixture.accessRecord(t, 1, true)
		second := fixture.accessRecord(t, 2, true)
		first.TerminalAuthToken, second.TerminalAuthToken = second.TerminalAuthToken, first.TerminalAuthToken
		fixture.loadAccessRecordsAfterReopen(t, true, first, second)
	})

	t.Run("access-server terminal token signature is corrupt", func(t *testing.T) {
		record := fixture.accessRecord(t, 1, true)
		record.TerminalAuthToken = corruptRetainedTokenSignature(t, record.TerminalAuthToken)
		fixture.loadAccessRecordsAfterReopen(t, true, record)
	})

	t.Run("access-server terminal token cannot predate retained inputs", func(t *testing.T) {
		record := fixture.accessRecord(t, 1, true)
		claims := fixture.terminalClaims(
			1, record.Key, "https://as.example", aauth.AccessDiscoveryDocument,
			record.Context.ResourceToken, record.Context.TargetKey, record.Decision,
		)
		claims.IssuedAt = record.Context.ResourceToken.IssuedAt - 1
		var err error
		record.TerminalAuthToken, err = aauth.MintAuthToken(fixture.accessKey, claims)
		if err != nil {
			t.Fatal(err)
		}
		record.TerminalExpiresAt = claims.ExpiresAt
		fixture.loadAccessRecordsAfterReopen(t, true, record)
	})

	t.Run("access-server terminal token remains verifiable after local signing-key rotation", func(t *testing.T) {
		record := fixture.accessRecord(t, 1, true)
		store := reopenedAuthorizationStateWithRecords(t, accessAuthorizationStateSchema, record)
		server := &AccessServer{
			identifier: "https://as.example", signingKey: fixture.personKey,
			authorizationStore: store, pending: make(map[string]*pendingAccessServerAuthorization),
		}
		if err := server.loadAuthorizationState(context.Background()); err != nil {
			t.Fatalf("access-server rotated signing-key recovery = %v", err)
		}
	})

	t.Run("access-server same-context terminal-token swap is rejected", func(t *testing.T) {
		first := fixture.accessRecord(t, 1, true)
		second := first
		second.Key = semanticPendingID(t, 2)
		second.Interaction.ID = second.Key
		claims := fixture.terminalClaims(
			2, second.Key, "https://as.example", aauth.AccessDiscoveryDocument,
			second.Context.ResourceToken, second.Context.TargetKey, second.Decision,
		)
		var err error
		second.TerminalAuthToken, err = aauth.MintAuthToken(fixture.accessKey, claims)
		if err != nil {
			t.Fatal(err)
		}
		second.TerminalExpiresAt = claims.ExpiresAt
		first.TerminalAuthToken, second.TerminalAuthToken = second.TerminalAuthToken, first.TerminalAuthToken
		fixture.loadAccessRecordsAfterReopen(t, true, first, second)
	})

	t.Run("person-server rejects corruption before persistence", func(t *testing.T) {
		record := fixture.personRecord(t, 1, false)
		record.Decision.Scope = append(record.Decision.Scope, "records.write")
		fixture.rejectPersonRecordBeforePersistence(t, record)
	})

	t.Run("access-server rejects corruption before persistence", func(t *testing.T) {
		record := fixture.accessRecord(t, 1, false)
		record.Decision.Scope = append(record.Decision.Scope, "records.write")
		fixture.rejectAccessRecordBeforePersistence(t, record)
	})
}

func TestPersonAndAccessServerTokenEndpointsUseRequestVerificationInstant(t *testing.T) {
	fixture := newAuthorizationStateSemanticFixture(t)

	t.Run("person server", func(t *testing.T) {
		record := fixture.personRecord(t, 1, false)
		record.Context.PersonTokenRecord.RetainUntil = fixture.now.Add(3 * time.Hour)
		personTokens, err := NewFilePersonTokenStore(t.TempDir() + "/person-tokens.json")
		if err != nil {
			t.Fatal(err)
		}
		if err := personTokens.Commit(context.Background(), record.Context.PersonTokenRecord); err != nil {
			t.Fatal(err)
		}
		missionIssuance, err := NewFileMissionIssuanceStore(t.TempDir() + "/mission-issuance.json")
		if err != nil {
			t.Fatal(err)
		}
		authorizationStore, err := NewMemoryAuthorizationStateStore(16, 1<<20)
		if err != nil {
			t.Fatal(err)
		}
		policyCalls := 0
		fixedClock := aauth.ClockFunc(func() time.Time { return fixture.now })
		server, err := NewPersonServer(PersonServerConfig{
			Identifier: "https://ps.example",
			SigningKey: fixture.personKey,
			KeyResolver: aauth.StaticKeyResolver{
				"https://ap.example":       {fixture.providerKey.ID(): fixture.providerKey.PublicJWK()},
				"https://resource.example": {fixture.resourceKey.ID(): fixture.resourceKey.PublicJWK()},
			},
			Clock:                fixedClock,
			NewID:                func() string { return "unused" },
			AuthorizationStore:   authorizationStore,
			PersonTokenStore:     personTokens,
			MissionIssuanceStore: missionIssuance,
			PersonTokenPolicy: func(context.Context, aauth.PersonTokenRequest) (aauth.PersonTokenDecision, error) {
				return aauth.PersonTokenDecision{}, errors.New("unused")
			},
			CurrentMissionPolicy: func(context.Context, aauth.MissionEvaluation) (aauth.MissionDecision, error) {
				return aauth.MissionDecision{}, errors.New("unused")
			},
			AuthorizationPolicy: func(context.Context, aauth.AuthorizationRequest) (aauth.AuthorizationDecision, error) {
				policyCalls++
				return aauth.AuthorizationDecision{}, errors.New("policy reached")
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		clockCalls := 0
		server.clock = aauth.ClockFunc(func() time.Time {
			clockCalls++
			if clockCalls == 1 {
				return fixture.now
			}
			return fixture.now.Add(2 * time.Hour)
		})
		request := func() *http.Request {
			body, err := json.Marshal(personAuthorizationTokenInput{ResourceToken: record.Context.ResourceTokenCompact})
			if err != nil {
				t.Fatal(err)
			}
			value := httptest.NewRequest(http.MethodPost, "https://ps.example/token", bytes.NewReader(body))
			value.Header.Set("Content-Type", "application/json")
			if err := aauth.SignRequest(value, fixture.agentKeys[0], record.Context.AgentTokenCompact, fixedClock); err != nil {
				t.Fatal(err)
			}
			return value
		}
		first := httptest.NewRecorder()
		server.Handler().ServeHTTP(first, request())
		if policyCalls != 1 || strings.Contains(first.Body.String(), "policy reached") ||
			!strings.Contains(first.Body.String(), `"detail":"authorization policy denied the request"`) {
			t.Fatalf("person-server policy calls = %d, response = %d %s", policyCalls, first.Code, first.Body.String())
		}
		clockCalls = 0
		second := httptest.NewRecorder()
		server.Handler().ServeHTTP(second, request())
		if second.Code != http.StatusUnauthorized || policyCalls != 1 {
			t.Fatalf("person-server replay = %d %s, policy calls = %d", second.Code, second.Body.String(), policyCalls)
		}
	})

	t.Run("access server", func(t *testing.T) {
		record := fixture.accessRecord(t, 1, false)
		authorizationStore, err := NewMemoryAuthorizationStateStore(16, 1<<20)
		if err != nil {
			t.Fatal(err)
		}
		policyCalls := 0
		fixedClock := aauth.ClockFunc(func() time.Time { return fixture.now })
		server, err := NewAccessServer(AccessServerConfig{
			Identifier: "https://as.example",
			SigningKey: fixture.accessKey,
			KeyResolver: aauth.StaticKeyResolver{
				"https://ps.example":       {fixture.personKey.ID(): fixture.personKey.PublicJWK()},
				"https://ap.example":       {fixture.providerKey.ID(): fixture.providerKey.PublicJWK()},
				"https://resource.example": {fixture.resourceKey.ID(): fixture.resourceKey.PublicJWK()},
			},
			Clock:              fixedClock,
			NewID:              func() string { return "unused" },
			AuthorizationStore: authorizationStore,
			TrustedPersonServer: func(context.Context, string) error {
				return nil
			},
			AuthorizationPolicy: func(context.Context, aauth.AuthorizationRequest) (aauth.AuthorizationDecision, error) {
				policyCalls++
				return aauth.AuthorizationDecision{}, errors.New("policy reached")
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		clockCalls := 0
		server.clock = aauth.ClockFunc(func() time.Time {
			clockCalls++
			if clockCalls == 1 {
				return fixture.now
			}
			return fixture.now.Add(2 * time.Hour)
		})
		request := func() *http.Request {
			body, err := json.Marshal(accessAuthorizationTokenInput{
				ResourceToken: record.Context.ResourceTokenCompact,
				AgentToken:    record.Context.AgentTokenCompact,
			})
			if err != nil {
				t.Fatal(err)
			}
			value := httptest.NewRequest(http.MethodPost, "https://as.example/token", bytes.NewReader(body))
			value.Header.Set("Content-Type", "application/json")
			if err := aauth.SignRequestWithJWKSURI(
				value,
				fixture.personKey,
				"https://ps.example",
				aauth.PersonDiscoveryDocument,
				fixedClock,
			); err != nil {
				t.Fatal(err)
			}
			return value
		}
		first := httptest.NewRecorder()
		server.Handler().ServeHTTP(first, request())
		if policyCalls != 1 || strings.Contains(first.Body.String(), "policy reached") ||
			!strings.Contains(first.Body.String(), `"detail":"authorization policy denied the request"`) {
			t.Fatalf("access-server policy calls = %d, response = %d %s", policyCalls, first.Code, first.Body.String())
		}
		clockCalls = 0
		second := httptest.NewRecorder()
		server.Handler().ServeHTTP(second, request())
		if second.Code != http.StatusUnauthorized || policyCalls != 1 {
			t.Fatalf("access-server replay = %d %s, policy calls = %d", second.Code, second.Body.String(), policyCalls)
		}
	})
}

func TestPersonAndAccessAuthorizationStateRejectsInputTokenExpiredAtVerifiedAt(t *testing.T) {
	fixture := newAuthorizationStateSemanticFixture(t)
	verifiedAt := fixture.now.Add(30 * time.Second).UTC()
	shortUpstream := func(t *testing.T, agentKey aauth.SigningKey, jti string) (string, aauth.AuthTokenClaims) {
		t.Helper()
		claims := aauth.AuthTokenClaims{
			Issuer:       "https://ps.example",
			DWK:          aauth.PersonDiscoveryDocument,
			Audience:     "https://ap.example",
			JTI:          jti,
			PersonServer: "https://ps.example",
			Subject:      "upstream-directed-person",
			Confirmation: aauth.Confirmation{JWK: agentKey.PublicJWK()},
			IssuedAt:     fixture.now.Unix(),
			ExpiresAt:    fixture.now.Add(20 * time.Second).Unix(),
			Scope:        "upstream.read",
		}
		compact, err := aauth.MintAuthToken(fixture.personKey, claims)
		if err != nil {
			t.Fatal(err)
		}
		return compact, claims
	}
	shortSubagent := func(t *testing.T, parent string) (string, aauth.AgentTokenClaims) {
		t.Helper()
		compact, err := aauth.MintAgentToken(
			"https://ap.example",
			fixture.providerKey,
			aauth.AgentTokenRequest{
				Agent:        "aauth:agent-1+worker@ap.example",
				PersonServer: "https://ps.example",
				ParentAgent:  parent,
				PublicKey:    fixture.agentKeys[1].PublicJWK(),
				Lifetime:     20 * time.Second,
			},
			fixture.now,
			"short-subagent-token",
		)
		if err != nil {
			t.Fatal(err)
		}
		claims, err := aauth.VerifyAgentToken(
			context.Background(),
			compact,
			aauth.StaticKeyResolver{
				"https://ap.example": {fixture.providerKey.ID(): fixture.providerKey.PublicJWK()},
			},
			aauth.ClockFunc(func() time.Time { return fixture.now }),
		)
		if err != nil {
			t.Fatal(err)
		}
		return compact, claims
	}
	bindSubagent := func(t *testing.T, resource *aauth.ResourceTokenClaims) string {
		t.Helper()
		thumbprint, err := fixture.agentKeys[1].PublicJWK().Thumbprint()
		if err != nil {
			t.Fatal(err)
		}
		resource.AgentJKT = thumbprint
		compact, err := aauth.MintResourceToken(fixture.resourceKey, *resource)
		if err != nil {
			t.Fatal(err)
		}
		return compact
	}

	t.Run("person-server resource token", func(t *testing.T) {
		record := fixture.personRecord(t, 1, false)
		claims := record.Context.ResourceToken
		claims.ExpiresAt = fixture.now.Add(20 * time.Second).Unix()
		compact, err := aauth.MintResourceToken(fixture.resourceKey, claims)
		if err != nil {
			t.Fatal(err)
		}
		record.Context.ResourceToken = claims
		record.Context.ResourceTokenCompact = compact
		record.Interaction.ExpiresAt = fixture.now.Add(10 * time.Second).UTC()
		fixture.bindPersonRequestEvidence(t, &record, fixture.agentKeys[0])
		record.Context.RequestProof.VerifiedAt = verifiedAt
		fixture.loadPersonRecordsAfterReopen(t, true, record)
	})

	t.Run("person-server signing agent token", func(t *testing.T) {
		record := fixture.personRecord(t, 1, false)
		agentToken, err := aauth.MintAgentToken(
			"https://ap.example",
			fixture.providerKey,
			aauth.AgentTokenRequest{
				Agent:        record.Context.PollingAgent,
				PersonServer: "https://ps.example",
				PublicKey:    fixture.agentKeys[0].PublicJWK(),
				Lifetime:     20 * time.Second,
			},
			fixture.now,
			"short-person-server-agent-token",
		)
		if err != nil {
			t.Fatal(err)
		}
		record.Context.AgentTokenCompact = agentToken
		record.Context.TargetTokenExpiresAt = fixture.now.Add(20 * time.Second).Unix()
		record.Interaction.ExpiresAt = fixture.now.Add(10 * time.Second).UTC()
		fixture.bindPersonRequestEvidence(t, &record, fixture.agentKeys[0])
		record.Context.RequestProof.VerifiedAt = verifiedAt
		fixture.loadPersonRecordsAfterReopen(t, true, record)
	})

	t.Run("person-server subagent token", func(t *testing.T) {
		record := fixture.personRecord(t, 1, false)
		parent := record.Context.TargetAgent
		subagentToken, subagent := shortSubagent(t, parent)
		record.Context.SubagentTokenCompact = subagentToken
		record.Context.TokenVerificationKeys.Subagent = pointerToJWK(fixture.providerKey.PublicJWK())
		record.Context.TargetAgent = subagent.Subject
		record.Context.TargetKey = subagent.Confirmation.JWK
		record.Context.ParentAgent = parent
		record.Context.TargetTokenExpiresAt = subagent.ExpiresAt
		record.Context.Request.Agent = subagent.Subject
		record.Context.Request.ParentAgent = parent
		record.Context.ResourceTokenCompact = bindSubagent(t, &record.Context.ResourceToken)
		record.Interaction.ExpiresAt = fixture.now.Add(10 * time.Second).UTC()
		fixture.bindPersonRequestEvidence(t, &record, fixture.agentKeys[0])
		record.Context.RequestProof.VerifiedAt = verifiedAt
		fixture.loadPersonRecordsAfterReopen(t, true, record)
	})

	t.Run("person-server upstream token", func(t *testing.T) {
		record := fixture.personRecord(t, 1, false)
		upstreamToken, upstream := shortUpstream(t, fixture.agentKeys[0], "short-upstream-token-ps")
		record.Context.UpstreamTokenCompact = upstreamToken
		record.Context.TokenVerificationKeys.Upstream = pointerToJWK(fixture.personKey.PublicJWK())
		record.Context.Request.Upstream = &upstream
		record.Context.TargetTokenExpiresAt = upstream.ExpiresAt
		record.Interaction.ExpiresAt = fixture.now.Add(10 * time.Second).UTC()
		fixture.bindPersonRequestEvidence(t, &record, fixture.agentKeys[0])
		record.Context.RequestProof.VerifiedAt = verifiedAt
		fixture.loadPersonRecordsAfterReopen(t, true, record)
	})

	t.Run("access-server resource token", func(t *testing.T) {
		record := fixture.accessRecord(t, 1, false)
		claims := record.Context.ResourceToken
		claims.ExpiresAt = fixture.now.Add(20 * time.Second).Unix()
		compact, err := aauth.MintResourceToken(fixture.resourceKey, claims)
		if err != nil {
			t.Fatal(err)
		}
		record.Context.ResourceToken = claims
		record.Context.ResourceTokenCompact = compact
		record.Interaction.ExpiresAt = fixture.now.Add(10 * time.Second).UTC()
		fixture.bindAccessRequestEvidence(t, &record)
		record.Context.RequestProof.VerifiedAt = verifiedAt
		fixture.loadAccessRecordsAfterReopen(t, true, record)
	})

	t.Run("access-server agent token", func(t *testing.T) {
		record := fixture.accessRecord(t, 1, false)
		agentToken, err := aauth.MintAgentToken(
			"https://ap.example",
			fixture.providerKey,
			aauth.AgentTokenRequest{
				Agent:        record.Context.TargetAgent,
				PersonServer: record.Context.PollingServer,
				PublicKey:    record.Context.TargetKey,
				Lifetime:     20 * time.Second,
			},
			fixture.now,
			"short-agent-token",
		)
		if err != nil {
			t.Fatal(err)
		}
		record.Context.AgentTokenCompact = agentToken
		record.Context.TargetTokenExpiresAt = fixture.now.Add(20 * time.Second).Unix()
		record.Interaction.ExpiresAt = fixture.now.Add(10 * time.Second).UTC()
		fixture.bindAccessRequestEvidence(t, &record)
		record.Context.RequestProof.VerifiedAt = verifiedAt
		fixture.loadAccessRecordsAfterReopen(t, true, record)
	})

	t.Run("access-server subagent token", func(t *testing.T) {
		record := fixture.accessRecord(t, 1, false)
		parent := record.Context.TargetAgent
		subagentToken, subagent := shortSubagent(t, parent)
		record.Context.SubagentTokenCompact = subagentToken
		record.Context.TokenVerificationKeys.Subagent = pointerToJWK(fixture.providerKey.PublicJWK())
		record.Context.TargetAgent = subagent.Subject
		record.Context.TargetKey = subagent.Confirmation.JWK
		record.Context.ParentAgent = parent
		record.Context.TargetTokenExpiresAt = subagent.ExpiresAt
		record.Context.Request.Agent = subagent.Subject
		record.Context.Request.ParentAgent = parent
		record.Context.ResourceTokenCompact = bindSubagent(t, &record.Context.ResourceToken)
		record.Interaction.ExpiresAt = fixture.now.Add(10 * time.Second).UTC()
		fixture.bindAccessRequestEvidence(t, &record)
		record.Context.RequestProof.VerifiedAt = verifiedAt
		fixture.loadAccessRecordsAfterReopen(t, true, record)
	})

	t.Run("access-server upstream token", func(t *testing.T) {
		record := fixture.accessRecord(t, 1, false)
		upstreamToken, upstream := shortUpstream(t, fixture.agentKeys[0], "short-upstream-token-as")
		record.Context.UpstreamTokenCompact = upstreamToken
		record.Context.TokenVerificationKeys.Upstream = pointerToJWK(fixture.personKey.PublicJWK())
		record.Context.Request.Upstream = &upstream
		record.Context.TargetTokenExpiresAt = upstream.ExpiresAt
		record.Interaction.ExpiresAt = fixture.now.Add(10 * time.Second).UTC()
		fixture.bindAccessRequestEvidence(t, &record)
		record.Context.RequestProof.VerifiedAt = verifiedAt
		fixture.loadAccessRecordsAfterReopen(t, true, record)
	})
}

func TestPersonAndAccessAuthorizationStateRejectDirectSubagentWithoutPersonServerAfterReopen(t *testing.T) {
	fixture := newAuthorizationStateSemanticFixture(t)
	emptyPersonServerSubagent := func(t *testing.T, parent string) (string, aauth.AgentTokenClaims) {
		t.Helper()
		compact, err := aauth.MintAgentToken(
			"https://ap.example",
			fixture.providerKey,
			aauth.AgentTokenRequest{
				Agent:       "aauth:agent-1+worker@ap.example",
				ParentAgent: parent,
				PublicKey:   fixture.agentKeys[1].PublicJWK(),
				Lifetime:    time.Hour,
			},
			fixture.now,
			"empty-ps-subagent-token",
		)
		if err != nil {
			t.Fatal(err)
		}
		claims, err := aauth.VerifyAgentToken(
			context.Background(),
			compact,
			aauth.StaticKeyResolver{
				"https://ap.example": {fixture.providerKey.ID(): fixture.providerKey.PublicJWK()},
			},
			aauth.ClockFunc(func() time.Time { return fixture.now }),
		)
		if err != nil {
			t.Fatal(err)
		}
		return compact, claims
	}
	bindSubagent := func(t *testing.T, resource *aauth.ResourceTokenClaims) string {
		t.Helper()
		thumbprint, err := fixture.agentKeys[1].PublicJWK().Thumbprint()
		if err != nil {
			t.Fatal(err)
		}
		resource.AgentJKT = thumbprint
		compact, err := aauth.MintResourceToken(fixture.resourceKey, *resource)
		if err != nil {
			t.Fatal(err)
		}
		return compact
	}

	t.Run("person server", func(t *testing.T) {
		record := fixture.personRecord(t, 1, false)
		parent := record.Context.TargetAgent
		subagentToken, subagent := emptyPersonServerSubagent(t, parent)
		record.Context.SubagentTokenCompact = subagentToken
		record.Context.TokenVerificationKeys.Subagent = pointerToJWK(fixture.providerKey.PublicJWK())
		record.Context.TargetAgent = subagent.Subject
		record.Context.TargetKey = subagent.Confirmation.JWK
		record.Context.ParentAgent = parent
		record.Context.TargetTokenExpiresAt = subagent.ExpiresAt
		record.Context.Request.Agent = subagent.Subject
		record.Context.Request.ParentAgent = parent
		record.Context.ResourceTokenCompact = bindSubagent(t, &record.Context.ResourceToken)
		fixture.bindPersonRequestEvidence(t, &record, fixture.agentKeys[0])
		fixture.loadPersonRecordsAfterReopen(t, true, record)
	})

	t.Run("access server", func(t *testing.T) {
		record := fixture.accessRecord(t, 1, false)
		parent := record.Context.TargetAgent
		subagentToken, subagent := emptyPersonServerSubagent(t, parent)
		record.Context.SubagentTokenCompact = subagentToken
		record.Context.TokenVerificationKeys.Subagent = pointerToJWK(fixture.providerKey.PublicJWK())
		record.Context.TargetAgent = subagent.Subject
		record.Context.TargetKey = subagent.Confirmation.JWK
		record.Context.ParentAgent = parent
		record.Context.TargetTokenExpiresAt = subagent.ExpiresAt
		record.Context.Request.Agent = subagent.Subject
		record.Context.Request.ParentAgent = parent
		record.Context.ResourceTokenCompact = bindSubagent(t, &record.Context.ResourceToken)
		fixture.bindAccessRequestEvidence(t, &record)
		fixture.loadAccessRecordsAfterReopen(t, true, record)
	})
}

func TestPersonAndAccessServerLiveRejectDirectSubagentWithoutPersonServer(t *testing.T) {
	fixture := newAuthorizationStateSemanticFixture(t)
	clock := aauth.ClockFunc(func() time.Time { return fixture.now })
	emptyPersonServerSubagent := func(t *testing.T, parent, tokenID string) string {
		t.Helper()
		compact, err := aauth.MintAgentToken(
			"https://ap.example",
			fixture.providerKey,
			aauth.AgentTokenRequest{
				Agent:       "aauth:agent-1+worker@ap.example",
				ParentAgent: parent,
				PublicKey:   fixture.agentKeys[1].PublicJWK(),
				Lifetime:    time.Hour,
			},
			fixture.now,
			tokenID,
		)
		if err != nil {
			t.Fatal(err)
		}
		return compact
	}
	bindSubagent := func(t *testing.T, claims aauth.ResourceTokenClaims) string {
		t.Helper()
		thumbprint, err := fixture.agentKeys[1].PublicJWK().Thumbprint()
		if err != nil {
			t.Fatal(err)
		}
		claims.AgentJKT = thumbprint
		compact, err := aauth.MintResourceToken(fixture.resourceKey, claims)
		if err != nil {
			t.Fatal(err)
		}
		return compact
	}
	assertInvalidSubagent := func(t *testing.T, response *httptest.ResponseRecorder) {
		t.Helper()
		if response.Code != http.StatusForbidden {
			t.Fatalf("empty-ps direct subagent response = %d %s", response.Code, response.Body.String())
		}
		problem, err := aauth.DecodeProblemResponse(response.Result())
		if err != nil {
			t.Fatal(err)
		}
		if problem.Code != "invalid_subagent_token" || !strings.Contains(problem.Detail, "person server") {
			t.Fatalf("empty-ps direct subagent problem = %#v", problem)
		}
	}

	t.Run("person server", func(t *testing.T) {
		record := fixture.personRecord(t, 1, false)
		personTokens, err := NewFilePersonTokenStore(t.TempDir() + "/person-tokens.json")
		if err != nil {
			t.Fatal(err)
		}
		if err := personTokens.Commit(context.Background(), record.Context.PersonTokenRecord); err != nil {
			t.Fatal(err)
		}
		missionIssuance, err := NewFileMissionIssuanceStore(t.TempDir() + "/mission-issuance.json")
		if err != nil {
			t.Fatal(err)
		}
		authorizationStore, err := NewMemoryAuthorizationStateStore(16, 1<<20)
		if err != nil {
			t.Fatal(err)
		}
		server, err := NewPersonServer(PersonServerConfig{
			Identifier: "https://ps.example",
			SigningKey: fixture.personKey,
			KeyResolver: aauth.StaticKeyResolver{
				"https://ap.example":       {fixture.providerKey.ID(): fixture.providerKey.PublicJWK()},
				"https://resource.example": {fixture.resourceKey.ID(): fixture.resourceKey.PublicJWK()},
			},
			Clock:                clock,
			NewID:                func() string { return "must-not-issue" },
			AuthorizationStore:   authorizationStore,
			PersonTokenStore:     personTokens,
			MissionIssuanceStore: missionIssuance,
			PersonTokenPolicy: func(context.Context, aauth.PersonTokenRequest) (aauth.PersonTokenDecision, error) {
				return aauth.PersonTokenDecision{}, errors.New("unused")
			},
			CurrentMissionPolicy: func(context.Context, aauth.MissionEvaluation) (aauth.MissionDecision, error) {
				return aauth.MissionDecision{}, errors.New("unused")
			},
			AuthorizationPolicy: func(_ context.Context, request aauth.AuthorizationRequest) (aauth.AuthorizationDecision, error) {
				return aauth.AuthorizationDecision{Subject: request.Subject, Scope: request.Scope}, nil
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		subagentToken := emptyPersonServerSubagent(t, record.Context.PollingAgent, "empty-ps-live-subagent-ps")
		body, err := json.Marshal(personAuthorizationTokenInput{
			ResourceToken: bindSubagent(t, record.Context.ResourceToken),
			SubagentToken: subagentToken,
		})
		if err != nil {
			t.Fatal(err)
		}
		request := httptest.NewRequest(http.MethodPost, "https://ps.example/token", bytes.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		if err := aauth.SignRequest(request, fixture.agentKeys[0], record.Context.AgentTokenCompact, clock); err != nil {
			t.Fatal(err)
		}
		response := httptest.NewRecorder()
		server.Handler().ServeHTTP(response, request)
		assertInvalidSubagent(t, response)
	})

	t.Run("access server", func(t *testing.T) {
		record := fixture.accessRecord(t, 1, false)
		authorizationStore, err := NewMemoryAuthorizationStateStore(16, 1<<20)
		if err != nil {
			t.Fatal(err)
		}
		server, err := NewAccessServer(AccessServerConfig{
			Identifier: "https://as.example",
			SigningKey: fixture.accessKey,
			KeyResolver: aauth.StaticKeyResolver{
				"https://ps.example":       {fixture.personKey.ID(): fixture.personKey.PublicJWK()},
				"https://ap.example":       {fixture.providerKey.ID(): fixture.providerKey.PublicJWK()},
				"https://resource.example": {fixture.resourceKey.ID(): fixture.resourceKey.PublicJWK()},
			},
			Clock:              clock,
			NewID:              func() string { return "must-not-issue" },
			AuthorizationStore: authorizationStore,
			TrustedPersonServer: func(context.Context, string) error {
				return nil
			},
			AuthorizationPolicy: func(_ context.Context, request aauth.AuthorizationRequest) (aauth.AuthorizationDecision, error) {
				return aauth.AuthorizationDecision{Subject: request.Subject, Scope: request.Scope}, nil
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		subagentToken := emptyPersonServerSubagent(t, record.Context.TargetAgent, "empty-ps-live-subagent-as")
		body, err := json.Marshal(accessAuthorizationTokenInput{
			ResourceToken: bindSubagent(t, record.Context.ResourceToken),
			AgentToken:    record.Context.AgentTokenCompact,
			SubagentToken: subagentToken,
		})
		if err != nil {
			t.Fatal(err)
		}
		request := httptest.NewRequest(http.MethodPost, "https://as.example/token", bytes.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		if err := aauth.SignRequestWithJWKSURI(
			request,
			fixture.personKey,
			"https://ps.example",
			aauth.PersonDiscoveryDocument,
			clock,
		); err != nil {
			t.Fatal(err)
		}
		response := httptest.NewRecorder()
		server.Handler().ServeHTTP(response, request)
		assertInvalidSubagent(t, response)
	})
}

func TestPersonAndAccessAuthorizationStateAcceptsUpstreamSelectedPSAfterReopen(t *testing.T) {
	fixture := newAuthorizationStateSemanticFixture(t)

	upstreamContext := func(t *testing.T, agentKey aauth.SigningKey, jti string) (string, aauth.AuthTokenClaims) {
		t.Helper()
		claims := aauth.AuthTokenClaims{
			Issuer:       "https://ps.example",
			DWK:          aauth.PersonDiscoveryDocument,
			Audience:     "https://ap.example",
			JTI:          jti,
			PersonServer: "https://ps.example",
			Subject:      "upstream-directed-person",
			Confirmation: aauth.Confirmation{JWK: agentKey.PublicJWK()},
			IssuedAt:     fixture.now.Unix(),
			ExpiresAt:    fixture.now.Add(time.Hour).Unix(),
			Scope:        "upstream.read",
		}
		compact, err := aauth.MintAuthToken(fixture.personKey, claims)
		if err != nil {
			t.Fatal(err)
		}
		return compact, claims
	}
	intermediaryToken := func(t *testing.T, agent string, key aauth.SigningKey, jti string) string {
		t.Helper()
		compact, err := aauth.MintAgentToken(
			"https://ap.example",
			fixture.providerKey,
			aauth.AgentTokenRequest{
				Agent:        agent,
				PersonServer: "https://intermediary-ps.example",
				PublicKey:    key.PublicJWK(),
				Lifetime:     time.Hour,
			},
			fixture.now,
			jti,
		)
		if err != nil {
			t.Fatal(err)
		}
		return compact
	}

	t.Run("person server", func(t *testing.T) {
		record := fixture.personRecord(t, 1, false)
		agent := record.Context.TargetAgent
		record.Context.AgentTokenCompact = intermediaryToken(t, agent, fixture.agentKeys[0], "intermediary-agent-token-ps")
		upstreamToken, upstream := upstreamContext(t, fixture.agentKeys[0], "upstream-auth-token-ps")
		record.Context.UpstreamTokenCompact = upstreamToken
		record.Context.TokenVerificationKeys.Upstream = pointerToJWK(fixture.personKey.PublicJWK())
		record.Context.Request.Upstream = &upstream
		fixture.bindPersonRequestEvidence(t, &record, fixture.agentKeys[0])
		fixture.loadPersonRecordsAfterReopen(t, false, record)
	})

	t.Run("access server", func(t *testing.T) {
		record := fixture.accessRecord(t, 1, false)
		agent := record.Context.TargetAgent
		record.Context.AgentTokenCompact = intermediaryToken(t, agent, fixture.agentKeys[0], "intermediary-agent-token-as")
		upstreamToken, upstream := upstreamContext(t, fixture.agentKeys[0], "upstream-auth-token-as")
		record.Context.UpstreamTokenCompact = upstreamToken
		record.Context.TokenVerificationKeys.Upstream = pointerToJWK(fixture.personKey.PublicJWK())
		record.Context.Request.Upstream = &upstream
		fixture.bindAccessRequestEvidence(t, &record)
		fixture.loadAccessRecordsAfterReopen(t, false, record)
	})
}

func pointerToJWK(value aauth.JWK) *aauth.JWK {
	return &value
}

func TestAgentRejectsSemanticallyCorruptTerminalTokenStateAfterReopen(t *testing.T) {
	fixture := newAuthorizationStateSemanticFixture(t)

	t.Run("valid terminal token state", func(t *testing.T) {
		fixture.loadAgentRecordsAfterReopen(t, false, fixture.agentTokenRecord(t, 1, true))
	})

	t.Run("terminal token signature is corrupt", func(t *testing.T) {
		record := fixture.agentTokenRecord(t, 1, true)
		record.Token.TerminalGrant.AuthToken = corruptRetainedTokenSignature(t, record.Token.TerminalGrant.AuthToken)
		fixture.loadAgentRecordsAfterReopen(t, true, record)
	})

	t.Run("resource token signature is corrupt", func(t *testing.T) {
		record := fixture.agentTokenRecord(t, 1, true)
		record.Token.ResourceGrant.ResourceToken = corruptRetainedTokenSignature(t, record.Token.ResourceGrant.ResourceToken)
		fixture.loadAgentRecordsAfterReopen(t, true, record)
	})

	t.Run("resource compact and retained claims differ", func(t *testing.T) {
		record := fixture.agentTokenRecord(t, 1, true)
		record.Token.ResourceGrant.Claims.Subject = "rewritten-person"
		fixture.loadAgentRecordsAfterReopen(t, true, record)
	})

	t.Run("resource verification key is wrong", func(t *testing.T) {
		record := fixture.agentTokenRecord(t, 1, true)
		record.Token.ResourceVerificationKey = fixture.accessKey.PublicJWK()
		fixture.loadAgentRecordsAfterReopen(t, true, record)
	})

	t.Run("terminal verification key is wrong", func(t *testing.T) {
		record := fixture.agentTokenRecord(t, 1, true)
		wrong := fixture.accessKey.PublicJWK()
		record.Token.TerminalVerificationKey = &wrong
		fixture.loadAgentRecordsAfterReopen(t, true, record)
	})

	t.Run("terminal compact and retained claims differ", func(t *testing.T) {
		record := fixture.agentTokenRecord(t, 1, true)
		record.Token.TerminalGrant.Claims.Subject = "rewritten-person"
		fixture.loadAgentRecordsAfterReopen(t, true, record)
	})

	t.Run("terminal token jti differs from pending id", func(t *testing.T) {
		record := fixture.agentTokenRecord(t, 1, true)
		claims := record.Token.TerminalGrant.Claims
		claims.JTI = "other-pending-id"
		compact, err := aauth.MintAuthToken(fixture.personKey, claims)
		if err != nil {
			t.Fatal(err)
		}
		record.Token.TerminalGrant.AuthToken = compact
		record.Token.TerminalGrant.Claims = claims
		fixture.loadAgentRecordsAfterReopen(t, true, record)
	})

	t.Run("same-context terminal tokens cannot be swapped", func(t *testing.T) {
		first := fixture.agentTokenRecord(t, 1, true)
		second := first
		cloned := cloneAgentPendingTokenRecord(*first.Token)
		second.Token = &cloned
		second.Key = semanticPendingID(t, 2)
		second.Token.ID = second.Key
		second.Token.Location = "https://ps.example/pending/" + second.Key
		claims := second.Token.TerminalGrant.Claims
		claims.JTI = second.Key
		compact, err := aauth.MintAuthToken(fixture.personKey, claims)
		if err != nil {
			t.Fatal(err)
		}
		second.Token.TerminalGrant.AuthToken = compact
		second.Token.TerminalGrant.Claims = claims
		first.Token.TerminalGrant, second.Token.TerminalGrant = second.Token.TerminalGrant, first.Token.TerminalGrant
		fixture.loadAgentRecordsAfterReopen(t, true, first, second)
	})

	t.Run("terminal grant and verification key presence must match", func(t *testing.T) {
		record := fixture.agentTokenRecord(t, 1, true)
		record.Token.TerminalVerificationKey = nil
		fixture.loadAgentRecordsAfterReopen(t, true, record)
	})

	t.Run("semantic corruption is refused before persistence", func(t *testing.T) {
		record := fixture.agentTokenRecord(t, 1, true)
		store, err := NewMemoryAuthorizationStateStore(16, 1<<20)
		if err != nil {
			t.Fatal(err)
		}
		agent := &Agent{
			authorizationStore: store,
			pendingTokens: map[string]agentPendingTokenRecord{
				record.Key: cloneAgentPendingTokenRecord(*record.Token),
			},
			pendingAccess: make(map[string]agentPendingAccessRecord),
		}
		if err := agent.persistAuthorizationStateLocked(context.Background()); err != nil {
			t.Fatal(err)
		}
		before, err := store.Load(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		corrupt := agent.pendingTokens[record.Key]
		corrupt.TerminalGrant.Claims.Subject = "rewritten-person"
		agent.pendingTokens[record.Key] = corrupt
		if err := agent.persistAuthorizationStateLocked(context.Background()); !errors.Is(err, ErrAuthorizationStateIntegrity) {
			t.Fatalf("agent pre-persistence corruption error = %v", err)
		}
		after, err := store.Load(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(after, before) {
			t.Fatal("agent semantic corruption reached durable state")
		}
	})
}

func TestResourceRejectsSemanticallyCorruptAuthorizationStateAfterReopen(t *testing.T) {
	fixture := newAuthorizationStateSemanticFixture(t)

	t.Run("valid terminal access grant", func(t *testing.T) {
		pending, grant := fixture.resourceAuthorizationRecords(t, 1, true)
		fixture.loadResourceRecordsAfterReopen(t, false, pending, grant)
	})

	t.Run("exact signed request body cannot be mutated", func(t *testing.T) {
		pending, grant := fixture.resourceAuthorizationRecords(t, 1, true)
		pending.Pending.RequestBody = append(pending.Pending.RequestBody, ' ')
		fixture.loadResourceRecordsAfterReopen(t, true, pending, grant)
	})

	t.Run("request issuer verification key cannot be replaced", func(t *testing.T) {
		pending, grant := fixture.resourceAuthorizationRecords(t, 1, true)
		pending.Pending.RequestVerificationKey = fixture.accessKey.PublicJWK()
		fixture.loadResourceRecordsAfterReopen(t, true, pending, grant)
	})

	t.Run("decision cannot expand requested scope", func(t *testing.T) {
		pending, grant := fixture.resourceAuthorizationRecords(t, 1, true)
		pending.Pending.Decision.Scope = append(pending.Pending.Decision.Scope, "records.write")
		fixture.loadResourceRecordsAfterReopen(t, true, pending, grant)
	})

	t.Run("terminal grant must bind the exact pending request and decision", func(t *testing.T) {
		pending, grant := fixture.resourceAuthorizationRecords(t, 1, true)
		grant.Grant.Subject = "different-person"
		fixture.loadResourceRecordsAfterReopen(t, true, pending, grant)
	})

	t.Run("terminal token cannot name another pending grant", func(t *testing.T) {
		firstPending, firstGrant := fixture.resourceAuthorizationRecords(t, 1, true)
		secondPending, secondGrant := fixture.resourceAuthorizationRecords(t, 2, true)
		firstPending.Pending.TerminalAccessToken, secondPending.Pending.TerminalAccessToken =
			secondPending.Pending.TerminalAccessToken, firstPending.Pending.TerminalAccessToken
		fixture.loadResourceRecordsAfterReopen(t, true, firstGrant, firstPending, secondGrant, secondPending)
	})

	t.Run("one terminal grant cannot satisfy two pending records", func(t *testing.T) {
		firstPending, firstGrant := fixture.resourceAuthorizationRecords(t, 1, true)
		secondPending, _ := fixture.resourceAuthorizationRecords(t, 2, true)
		secondPending.Pending.TerminalAccessToken = firstPending.Pending.TerminalAccessToken
		fixture.loadResourceRecordsAfterReopen(t, true, firstGrant, firstPending, secondPending)
	})

	t.Run("orphan grant is rejected", func(t *testing.T) {
		_, grant := fixture.resourceAuthorizationRecords(t, 1, true)
		fixture.loadResourceRecordsAfterReopen(t, true, grant)
	})

	t.Run("semantic corruption is refused before persistence", func(t *testing.T) {
		pending, grant := fixture.resourceAuthorizationRecords(t, 1, true)
		resource := &Resource{
			identifier: "https://resource.example",
			pending:    make(map[string]*pendingAuthorization), access: make(map[string]localAccessGrant),
		}
		if err := resource.restoreAuthorizationStateLocked(
			roleAuthorizationSnapshot(t, resourceAuthorizationStateSchema, grant, pending),
		); err != nil {
			t.Fatal(err)
		}
		store, err := NewMemoryAuthorizationStateStore(16, 1<<20)
		if err != nil {
			t.Fatal(err)
		}
		resource.authorizationStore = store
		if err := resource.persistAuthorizationStateLocked(context.Background()); err != nil {
			t.Fatal(err)
		}
		before, err := store.Load(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		corrupt := resource.access[grant.Key]
		corrupt.subject = "rewritten-person"
		resource.access[grant.Key] = corrupt
		if err := resource.persistAuthorizationStateLocked(context.Background()); !errors.Is(err, ErrAuthorizationStateIntegrity) {
			t.Fatalf("resource pre-persistence corruption error = %v", err)
		}
		after, err := store.Load(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(after, before) {
			t.Fatal("resource semantic corruption reached durable state")
		}
	})
}

func TestPersonServerRetainsRefreshedAccessServerKeyForOfflineTerminalRecovery(t *testing.T) {
	fixture := newAuthorizationStateSemanticFixture(t)
	stale := referenceTestSigningKey(t, "rotating-access-key")
	fresh := referenceTestSigningKey(t, "rotating-access-key")
	resolver := &staleThenFreshAuthorizationResolver{
		stale: stale.PublicJWK(),
		fresh: fresh.PublicJWK(),
	}
	now := fixture.now.Add(2 * time.Second)
	clock := aauth.ClockFunc(func() time.Time { return now })
	store, err := NewMemoryAuthorizationStateStore(16, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	record := fixture.federatedPersonRecord(t, 1, false)
	record.Interaction.State = pendingAuthorizationWaiting
	interaction, err := restorePendingInteraction(record.Interaction)
	if err != nil {
		t.Fatal(err)
	}
	server := &PersonServer{
		identifier: "https://ps.example", signingKey: fixture.personKey,
		keyResolver: resolver, clock: clock, authorizationStore: store,
		pending: map[string]*pendingPersonAuthorization{
			record.Key: {
				pendingInteraction: interaction,
				context:            restorePersonAuthorizationContext(record.Context),
				decision:           record.Decision,
				federated: &pendingFederatedAuthorization{
					accessServer: record.Federated.AccessServer,
					location:     record.Federated.Location,
					notBefore:    record.Federated.NotBefore,
					status:       record.Federated.Status,
				},
				pollingFederation: true,
			},
		},
	}
	if err := server.persistAuthorizationStateLocked(context.Background()); err != nil {
		t.Fatal(err)
	}
	claims := fixture.terminalClaims(
		1, record.Key, "https://as.example", aauth.AccessDiscoveryDocument,
		record.Context.ResourceToken, record.Context.TargetKey, record.Decision,
	)
	claims.IssuedAt = fixture.now.Unix()
	compact, err := aauth.MintAuthToken(fresh, claims)
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(map[string]string{"auth_token": compact})
	if err != nil {
		t.Fatal(err)
	}
	exchange, err := server.parseAccessServerGrant(
		context.Background(),
		&http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(body))},
		"https://as.example",
		record.Context.TargetKey,
		record.Context.TargetTokenExpiresAt,
		record.Context.ResourceToken,
		record.Decision,
	)
	if err != nil {
		t.Fatal(err)
	}
	if resolver.resolveCalls != 1 || resolver.refreshCalls != 1 ||
		exchange.verificationKey == nil || !exchange.verificationKey.Equal(fresh.PublicJWK()) {
		t.Fatalf(
			"same-kid key capture resolve/refresh/key = %d/%d/%v",
			resolver.resolveCalls,
			resolver.refreshCalls,
			exchange.verificationKey,
		)
	}
	retained, err := server.retainFederatedAuthorization(record.Key, exchange)
	if err != nil || !retained {
		t.Fatalf("retain refreshed-key terminal = %v, %v", retained, err)
	}
	resolutionCalls := resolver.resolveCalls + resolver.refreshCalls
	reconstructed := &PersonServer{
		identifier: "https://ps.example", signingKey: fixture.accessKey,
		authorizationStore: store, pending: make(map[string]*pendingPersonAuthorization),
	}
	if err := reconstructed.loadAuthorizationState(context.Background()); err != nil {
		t.Fatalf("offline terminal recovery after same-kid refresh = %v", err)
	}
	if resolver.resolveCalls+resolver.refreshCalls != resolutionCalls {
		t.Fatal("offline recovery consulted the live key resolver")
	}
}

func TestAgentCapturesSuccessfulSameKidKeysForDeferredRecovery(t *testing.T) {
	fixture := newAuthorizationStateSemanticFixture(t)
	record := fixture.agentTokenRecord(t, 1, true)
	staleResourceKey := referenceTestSigningKey(t, fixture.resourceKey.ID())
	resourceResolver := &staleThenFreshAuthorizationResolver{
		stale: staleResourceKey.PublicJWK(),
		fresh: fixture.resourceKey.PublicJWK(),
	}
	agent := &Agent{
		keyResolver: resourceResolver,
		clock:       aauth.ClockFunc(func() time.Time { return fixture.now.Add(2 * time.Second) }),
	}
	resourceKey, err := agent.verifyResourceGrantForContinuation(
		context.Background(),
		record.Token.ResourceGrant,
	)
	if err != nil {
		t.Fatal(err)
	}
	if resourceResolver.resolveCalls != 1 || resourceResolver.refreshCalls != 1 ||
		!resourceKey.Equal(fixture.resourceKey.PublicJWK()) {
		t.Fatalf(
			"resource same-kid key capture resolve/refresh/key = %d/%d/%v",
			resourceResolver.resolveCalls,
			resourceResolver.refreshCalls,
			resourceKey,
		)
	}

	staleTerminalKey := referenceTestSigningKey(t, fixture.personKey.ID())
	terminalResolver := &staleThenFreshAuthorizationResolver{
		stale: staleTerminalKey.PublicJWK(),
		fresh: fixture.personKey.PublicJWK(),
	}
	agent.keyResolver = terminalResolver
	body, err := json.Marshal(map[string]string{"auth_token": record.Token.TerminalGrant.AuthToken})
	if err != nil {
		t.Fatal(err)
	}
	grant, terminalKey, err := agent.parseTokenGrantResponse(
		context.Background(),
		&http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(body))},
		record.Token.ResourceGrant,
		record.Token.ExpectedIssuer,
		record.Token.ExpectedKey,
		record.Token.ID,
	)
	if err != nil {
		t.Fatal(err)
	}
	if terminalResolver.resolveCalls != 1 || terminalResolver.refreshCalls != 1 ||
		!terminalKey.Equal(fixture.personKey.PublicJWK()) {
		t.Fatalf(
			"terminal same-kid key capture resolve/refresh/key = %d/%d/%v",
			terminalResolver.resolveCalls,
			terminalResolver.refreshCalls,
			terminalKey,
		)
	}

	store, err := NewMemoryAuthorizationStateStore(16, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	agent.authorizationStore = store
	agent.pendingTokens = make(map[string]agentPendingTokenRecord)
	agent.pendingAccess = make(map[string]agentPendingAccessRecord)
	pending := PendingTokenAuthorization{
		ID: record.Token.ID, PersonServer: record.Token.PersonServer, Location: record.Token.Location,
		NotBefore: record.Token.NotBefore, Status: record.Token.Status,
		resourceGrant: record.Token.ResourceGrant, resourceVerificationKey: resourceKey,
		expectedIssuer: record.Token.ExpectedIssuer, expectedKey: record.Token.ExpectedKey,
	}
	if err := agent.retainPendingTokenAuthorization(context.Background(), pending, &grant, &terminalKey); err != nil {
		t.Fatal(err)
	}
	resolutionCalls := resourceResolver.resolveCalls + resourceResolver.refreshCalls +
		terminalResolver.resolveCalls + terminalResolver.refreshCalls
	reconstructed := &Agent{
		authorizationStore: store,
		pendingTokens:      make(map[string]agentPendingTokenRecord),
		pendingAccess:      make(map[string]agentPendingAccessRecord),
	}
	if err := reconstructed.loadAuthorizationState(context.Background()); err != nil {
		t.Fatalf("offline agent terminal recovery = %v", err)
	}
	if resourceResolver.resolveCalls+resourceResolver.refreshCalls+
		terminalResolver.resolveCalls+terminalResolver.refreshCalls != resolutionCalls {
		t.Fatal("offline agent recovery consulted a live key resolver")
	}
}

func TestAgentTerminalTokenRetentionCannotBeReplacedByAStalePoll(t *testing.T) {
	fixture := newAuthorizationStateSemanticFixture(t)
	record := fixture.agentTokenRecord(t, 1, true)
	store, err := NewMemoryAuthorizationStateStore(16, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	agent := &Agent{
		authorizationStore: store,
		pendingTokens:      make(map[string]agentPendingTokenRecord),
		pendingAccess:      make(map[string]agentPendingAccessRecord),
	}
	pending := PendingTokenAuthorization{
		ID: record.Token.ID, PersonServer: record.Token.PersonServer, Location: record.Token.Location,
		NotBefore: record.Token.NotBefore, Status: record.Token.Status,
		resourceGrant: record.Token.ResourceGrant, resourceVerificationKey: record.Token.ResourceVerificationKey,
		expectedIssuer: record.Token.ExpectedIssuer, expectedKey: record.Token.ExpectedKey,
	}
	if err := agent.retainPendingTokenAuthorization(context.Background(), pending, nil, nil); err != nil {
		t.Fatal(err)
	}
	if err := agent.retainPendingTokenAuthorization(
		context.Background(), pending, record.Token.TerminalGrant, record.Token.TerminalVerificationKey,
	); err != nil {
		t.Fatal(err)
	}
	if err := agent.retainPendingTokenAuthorization(context.Background(), pending, nil, nil); !errors.Is(err, ErrAuthorizationStateIntegrity) {
		t.Fatalf("stale nonterminal retention after terminal = %v", err)
	}
	terminal, err := agent.restorePendingTokenAuthorization(context.Background(), &pending)
	if err != nil {
		t.Fatal(err)
	}
	if terminal == nil || terminal.AuthToken != record.Token.TerminalGrant.AuthToken {
		t.Fatalf("terminal grant after stale poll = %#v", terminal)
	}
}

func TestAgentResourceManagedTerminalGrantKeepsExactCustody(t *testing.T) {
	now := time.Date(2026, 8, 28, 20, 0, 0, 0, time.UTC)
	record := func(id, token string) agentAuthorizationStateRecord {
		return agentAuthorizationStateRecord{
			Kind: "access", Key: id,
			Access: &agentPendingAccessRecord{
				ID: id, Resource: "https://resource.example",
				Location:  "https://resource.example/pending/" + id,
				NotBefore: now, Status: "pending", RequestedScope: []string{"records.read"},
				TerminalGrant: &AccessGrant{
					Resource: "https://resource.example", Token: token, Scope: []string{"records.read"},
				},
			},
		}
	}

	t.Run("terminal scope stays within the retained request", func(t *testing.T) {
		corrupt := record("pending-access", "access-token")
		corrupt.Access.TerminalGrant.Scope = []string{"records.write"}
		agent := &Agent{}
		err := agent.restoreAuthorizationStateLocked(
			roleAuthorizationSnapshot(t, agentAuthorizationStateSchema, corrupt),
		)
		if !errors.Is(err, ErrAuthorizationStateIntegrity) {
			t.Fatalf("outside-scope terminal access grant error = %v", err)
		}
	})

	t.Run("one opaque token cannot terminate two continuations", func(t *testing.T) {
		first := record("pending-first", "shared-access-token")
		second := record("pending-second", "shared-access-token")
		agent := &Agent{}
		err := agent.restoreAuthorizationStateLocked(
			roleAuthorizationSnapshot(t, agentAuthorizationStateSchema, first, second),
		)
		if !errors.Is(err, ErrAuthorizationStateIntegrity) {
			t.Fatalf("duplicate terminal access token error = %v", err)
		}
	})

	t.Run("stale poll cannot erase terminal access grant", func(t *testing.T) {
		store, err := NewMemoryAuthorizationStateStore(16, 1<<20)
		if err != nil {
			t.Fatal(err)
		}
		agent := &Agent{
			authorizationStore: store,
			pendingTokens:      make(map[string]agentPendingTokenRecord),
			pendingAccess:      make(map[string]agentPendingAccessRecord),
		}
		pending := PendingAccessAuthorization{
			ID: "pending-access", Resource: "https://resource.example",
			Location:  "https://resource.example/pending/pending-access",
			NotBefore: now, Status: "pending", requestedScope: []string{"records.read"},
		}
		terminal := AccessGrant{
			Resource: pending.Resource, Token: "access-token", Scope: []string{"records.read"},
		}
		if err := agent.retainPendingAccessAuthorization(context.Background(), pending, nil); err != nil {
			t.Fatal(err)
		}
		if err := agent.retainPendingAccessAuthorization(context.Background(), pending, &terminal); err != nil {
			t.Fatal(err)
		}
		if err := agent.retainPendingAccessAuthorization(context.Background(), pending, nil); !errors.Is(err, ErrAuthorizationStateIntegrity) {
			t.Fatalf("stale access continuation after terminal = %v", err)
		}
		grant, err := agent.restorePendingAccessAuthorization(context.Background(), &pending)
		if err != nil || grant == nil || grant.Token != terminal.Token {
			t.Fatalf("terminal access grant after stale poll = %#v, %v", grant, err)
		}
	})
}

func TestAuthorizationExpiryPersistenceFailuresAreNeverReportedAsOrdinaryExpiry(t *testing.T) {
	fixture := newAuthorizationStateSemanticFixture(t)

	t.Run("person approve before policy", func(t *testing.T) {
		now := fixture.now.Add(time.Hour)
		server, store, id := expiryPersonServer(t, fixture, &now, nil)
		store.fail = true
		if err := server.ApproveAuthorization(context.Background(), id); !errors.Is(err, ErrAuthorizationStateUncertain) {
			t.Fatalf("person early-expiry persistence error = %v", err)
		}
	})

	t.Run("person approve after policy", func(t *testing.T) {
		now := fixture.now
		policy := func(_ context.Context, request aauth.AuthorizationRequest) (aauth.AuthorizationDecision, error) {
			now = fixture.now.Add(time.Hour)
			return aauth.AuthorizationDecision{Subject: request.Subject, Scope: request.Scope}, nil
		}
		server, store, id := expiryPersonServer(t, fixture, &now, policy)
		store.fail = true
		if err := server.ApproveAuthorization(context.Background(), id); !errors.Is(err, ErrAuthorizationStateUncertain) {
			t.Fatalf("person post-policy expiry persistence error = %v", err)
		}
	})

	t.Run("person reject", func(t *testing.T) {
		now := fixture.now.Add(time.Hour)
		server, store, id := expiryPersonServer(t, fixture, &now, nil)
		store.fail = true
		if err := server.RejectAuthorization(id, aauth.PollingDenied); !errors.Is(err, ErrAuthorizationStateUncertain) {
			t.Fatalf("person rejection expiry persistence error = %v", err)
		}
	})

	t.Run("person interaction HTTP", func(t *testing.T) {
		now := fixture.now.Add(time.Hour)
		server, store, id := expiryPersonServer(t, fixture, &now, nil)
		server.pending[id].state = pendingAuthorizationWaiting
		server.pending[id].codeConsumed = false
		store.fail = true
		request := httptest.NewRequest(http.MethodGet, "https://ps.example/interaction/"+id, nil)
		request.SetPathValue("id", id)
		response := httptest.NewRecorder()
		server.handleAuthorizationInteraction(response, request)
		if response.Code != http.StatusServiceUnavailable ||
			!bytes.Contains(response.Body.Bytes(), []byte(`"error":"authorization_state_unavailable"`)) ||
			bytes.Contains(response.Body.Bytes(), []byte(`"error":"expired"`)) {
			t.Fatalf("person interaction expiry persistence response = %d: %s", response.Code, response.Body.String())
		}
	})

	t.Run("access approve before policy", func(t *testing.T) {
		now := fixture.now.Add(time.Hour)
		server, store, id := expiryAccessServer(t, fixture, &now, nil)
		store.fail = true
		if err := server.ApproveAuthorization(context.Background(), id); !errors.Is(err, ErrAuthorizationStateUncertain) {
			t.Fatalf("access early-expiry persistence error = %v", err)
		}
	})

	t.Run("access approve after policy", func(t *testing.T) {
		now := fixture.now
		policy := func(_ context.Context, request aauth.AuthorizationRequest) (aauth.AuthorizationDecision, error) {
			now = fixture.now.Add(time.Hour)
			return aauth.AuthorizationDecision{Subject: request.Subject, Scope: request.Scope}, nil
		}
		server, store, id := expiryAccessServer(t, fixture, &now, policy)
		store.fail = true
		if err := server.ApproveAuthorization(context.Background(), id); !errors.Is(err, ErrAuthorizationStateUncertain) {
			t.Fatalf("access post-policy expiry persistence error = %v", err)
		}
	})

	t.Run("access reject", func(t *testing.T) {
		now := fixture.now.Add(time.Hour)
		server, store, id := expiryAccessServer(t, fixture, &now, nil)
		store.fail = true
		if err := server.RejectAuthorization(id, aauth.PollingDenied); !errors.Is(err, ErrAuthorizationStateUncertain) {
			t.Fatalf("access rejection expiry persistence error = %v", err)
		}
	})

	t.Run("resource approve before policy", func(t *testing.T) {
		now := fixture.now.Add(time.Hour)
		resource, store, id := expiryResource(t, fixture, &now, nil)
		store.fail = true
		if err := resource.ApproveAuthorization(context.Background(), id); !errors.Is(err, ErrAuthorizationStateUncertain) {
			t.Fatalf("resource early-expiry persistence error = %v", err)
		}
	})

	t.Run("resource approve after policy", func(t *testing.T) {
		now := fixture.now
		policy := func(_ context.Context, request aauth.AuthorizationRequest) (aauth.AuthorizationDecision, error) {
			now = fixture.now.Add(time.Hour)
			return aauth.AuthorizationDecision{Subject: request.Subject, Scope: request.Scope}, nil
		}
		resource, store, id := expiryResource(t, fixture, &now, policy)
		store.fail = true
		if err := resource.ApproveAuthorization(context.Background(), id); !errors.Is(err, ErrAuthorizationStateUncertain) {
			t.Fatalf("resource post-policy expiry persistence error = %v", err)
		}
	})

	t.Run("resource reject", func(t *testing.T) {
		now := fixture.now.Add(time.Hour)
		resource, store, id := expiryResource(t, fixture, &now, nil)
		store.fail = true
		if err := resource.RejectAuthorization(id, aauth.PollingDenied); !errors.Is(err, ErrAuthorizationStateUncertain) {
			t.Fatalf("resource rejection expiry persistence error = %v", err)
		}
	})
}

func TestResourceApprovedAuthorizationCannotReleaseAfterCredentialExpiry(t *testing.T) {
	fixture := newAuthorizationStateSemanticFixture(t)
	pendingRecord, _ := fixture.resourceAuthorizationRecords(t, 1, true)
	pendingRecord.Pending.TerminalAccessToken = ""
	body := roleAuthorizationSnapshot(t, resourceAuthorizationStateSchema, pendingRecord)
	store, err := NewMemoryAuthorizationStateStore(16, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Replace(context.Background(), body); err != nil {
		t.Fatal(err)
	}
	now := pendingRecord.Pending.AgentExpiresAt.Add(time.Second)
	agentToken, err := aauth.MintAgentToken(
		"https://ap.example",
		fixture.providerKey,
		aauth.AgentTokenRequest{
			Agent: "aauth:agent@ap.example", PublicKey: fixture.agentKeys[0].PublicJWK(), Lifetime: time.Hour,
		},
		now,
		"polling-agent-token",
	)
	if err != nil {
		t.Fatal(err)
	}
	resource := &Resource{
		identifier: "https://resource.example", clock: aauth.ClockFunc(func() time.Time { return now }),
		keyResolver: aauth.StaticKeyResolver{
			"https://ap.example": {fixture.providerKey.ID(): fixture.providerKey.PublicJWK()},
		},
		authorizationStore: store, authorizationBody: append([]byte(nil), body...),
		pending: make(map[string]*pendingAuthorization), access: make(map[string]localAccessGrant),
		newID: func() string { return "must-not-be-minted" },
	}
	if err := resource.restoreAuthorizationStateLocked(body); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(
		http.MethodGet,
		"https://resource.example/pending/"+pendingRecord.Key,
		nil,
	)
	request.SetPathValue("id", pendingRecord.Key)
	if err := aauth.SignRequest(request, fixture.agentKeys[0], agentToken, resource.clock); err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	resource.handlePendingAuthorization(response, request)
	if response.Code != http.StatusRequestTimeout || response.Header().Get("AAuth-Access") != "" ||
		resource.pending[pendingRecord.Key].state != pendingAuthorizationExpired || len(resource.access) != 0 {
		t.Fatalf(
			"approved authorization after credential expiry = %d state=%s grants=%d: %s",
			response.Code,
			resource.pending[pendingRecord.Key].state,
			len(resource.access),
			response.Body.String(),
		)
	}
}

func TestAuthorizationApprovalRejectsAReconciledReplacementWhilePolicyRuns(t *testing.T) {
	fixture := newAuthorizationStateSemanticFixture(t)

	t.Run("person server", func(t *testing.T) {
		record := fixture.personRecord(t, 1, false)
		record.Interaction.State = pendingAuthorizationInteracting
		record.Decision = aauth.AuthorizationDecision{}
		interaction, err := restorePendingInteraction(record.Interaction)
		if err != nil {
			t.Fatal(err)
		}
		server := &PersonServer{
			identifier: "https://ps.example", clock: aauth.ClockFunc(func() time.Time { return fixture.now }),
			pending: map[string]*pendingPersonAuthorization{
				record.Key: {
					pendingInteraction: interaction,
					context:            restorePersonAuthorizationContext(record.Context),
				},
			},
		}
		server.authorizationPolicy = func(_ context.Context, request aauth.AuthorizationRequest) (aauth.AuthorizationDecision, error) {
			server.pendingMu.Lock()
			replacement := *server.pending[record.Key]
			server.pending[record.Key] = &replacement
			server.pendingMu.Unlock()
			return aauth.AuthorizationDecision{Subject: request.Subject, Scope: request.Scope}, nil
		}
		err = server.ApproveAuthorization(context.Background(), record.Key)
		if err == nil || !strings.Contains(err.Error(), "changed while approval was evaluated") {
			t.Fatalf("person reconciled-pointer approval error = %v", err)
		}
		if current := server.pending[record.Key]; current.state != pendingAuthorizationInteracting || current.decision.Subject != "" {
			t.Fatalf("person replacement was mutated: state=%s decision=%+v", current.state, current.decision)
		}
	})

	t.Run("access server", func(t *testing.T) {
		record := fixture.accessRecord(t, 1, false)
		record.Interaction.State = pendingAuthorizationInteracting
		record.Decision = aauth.AuthorizationDecision{}
		interaction, err := restorePendingInteraction(record.Interaction)
		if err != nil {
			t.Fatal(err)
		}
		server := &AccessServer{
			identifier: "https://as.example", clock: aauth.ClockFunc(func() time.Time { return fixture.now }),
			pending: map[string]*pendingAccessServerAuthorization{
				record.Key: {
					pendingInteraction: interaction,
					context:            restoreAccessAuthorizationContext(record.Context),
				},
			},
		}
		server.authorizationPolicy = func(_ context.Context, request aauth.AuthorizationRequest) (aauth.AuthorizationDecision, error) {
			server.pendingMu.Lock()
			replacement := *server.pending[record.Key]
			server.pending[record.Key] = &replacement
			server.pendingMu.Unlock()
			return aauth.AuthorizationDecision{Subject: request.Subject, Scope: request.Scope}, nil
		}
		err = server.ApproveAuthorization(context.Background(), record.Key)
		if err == nil || !strings.Contains(err.Error(), "changed while approval was evaluated") {
			t.Fatalf("access reconciled-pointer approval error = %v", err)
		}
		if current := server.pending[record.Key]; current.state != pendingAuthorizationInteracting || current.decision.Subject != "" {
			t.Fatalf("access replacement was mutated: state=%s decision=%+v", current.state, current.decision)
		}
	})

	t.Run("resource", func(t *testing.T) {
		record, _ := fixture.resourceAuthorizationRecords(t, 1, false)
		stored := record.Pending
		interaction, err := restorePendingInteraction(pendingInteractionRecord{
			ID: stored.ID, Code: stored.Code, NormalizedCode: stored.NormalizedCode,
			CodeConsumed: stored.CodeConsumed, FailedCodeAttempts: stored.FailedCodeAttempts,
			State: stored.State, PollingError: stored.PollingError, ExpiresAt: stored.ExpiresAt,
		})
		if err != nil {
			t.Fatal(err)
		}
		pending := &pendingAuthorization{
			pendingInteraction: interaction,
			request:            copyAuthorizationRequest(stored.Request), requestBody: append([]byte(nil), stored.RequestBody...),
			requestProof: copyRequestProof(stored.RequestProof), requestVerificationKey: stored.RequestVerificationKey,
			agentThumbprint: stored.AgentThumbprint, agentExpiresAt: stored.AgentExpiresAt,
		}
		resource := &Resource{
			identifier: "https://resource.example",
			clock:      aauth.ClockFunc(func() time.Time { return fixture.now }),
			pending:    map[string]*pendingAuthorization{record.Key: pending},
			access:     make(map[string]localAccessGrant),
		}
		resource.authorizationPolicy = func(_ context.Context, request aauth.AuthorizationRequest) (aauth.AuthorizationDecision, error) {
			resource.pendingMu.Lock()
			replacement := *resource.pending[record.Key]
			resource.pending[record.Key] = &replacement
			resource.pendingMu.Unlock()
			return aauth.AuthorizationDecision{Subject: request.Subject, Scope: request.Scope}, nil
		}
		err = resource.ApproveAuthorization(context.Background(), record.Key)
		if err == nil || !strings.Contains(err.Error(), "changed while approval was evaluated") {
			t.Fatalf("resource reconciled-pointer approval error = %v", err)
		}
		if current := resource.pending[record.Key]; current.state != pendingAuthorizationInteracting || current.decision.Subject != "" {
			t.Fatalf("resource replacement was mutated: state=%s decision=%+v", current.state, current.decision)
		}
	})
}

func TestStaleInteractionCannotRewriteTerminalAuthorizationStateAfterExpiry(t *testing.T) {
	fixture := newAuthorizationStateSemanticFixture(t)

	exercisePerson := func(t *testing.T, record personAuthorizationStateRecord) {
		t.Helper()
		interaction, err := restorePendingInteraction(record.Interaction)
		if err != nil {
			t.Fatal(err)
		}
		now := fixture.now
		store, err := NewMemoryAuthorizationStateStore(16, 1<<20)
		if err != nil {
			t.Fatal(err)
		}
		pending := &pendingPersonAuthorization{
			pendingInteraction:      interaction,
			context:                 restorePersonAuthorizationContext(record.Context),
			decision:                record.Decision,
			terminalAuthToken:       record.TerminalAuthToken,
			terminalVerificationKey: copyJWK(record.TerminalVerificationKey),
			terminalExpiresAt:       record.TerminalExpiresAt,
			terminalStatus:          record.TerminalStatus,
			terminalCode:            record.TerminalCode,
			terminalDetail:          record.TerminalDetail,
		}
		server := &PersonServer{
			identifier: "https://ps.example", signingKey: fixture.personKey,
			clock: aauth.ClockFunc(func() time.Time { return now }), authorizationStore: store,
			pending: map[string]*pendingPersonAuthorization{record.Key: pending},
		}
		if err := server.persistAuthorizationStateLocked(context.Background()); err != nil {
			t.Fatal(err)
		}
		now = fixture.now.Add(time.Hour)
		request := httptest.NewRequest(http.MethodGet, "https://ps.example/interaction/"+record.Key, nil)
		request.SetPathValue("id", record.Key)
		response := httptest.NewRecorder()
		server.handleAuthorizationInteraction(response, request)
		if response.Code != http.StatusGone || pending.state != record.Interaction.State ||
			pending.terminalAuthToken != record.TerminalAuthToken || pending.pollingError != record.Interaction.PollingError {
			t.Fatalf("person stale interaction = %d state=%s token=%t polling=%s body=%s", response.Code, pending.state, pending.terminalAuthToken != "", pending.pollingError, response.Body.String())
		}
	}

	exerciseAccess := func(t *testing.T, record accessAuthorizationStateRecord) {
		t.Helper()
		interaction, err := restorePendingInteraction(record.Interaction)
		if err != nil {
			t.Fatal(err)
		}
		now := fixture.now
		store, err := NewMemoryAuthorizationStateStore(16, 1<<20)
		if err != nil {
			t.Fatal(err)
		}
		pending := &pendingAccessServerAuthorization{
			pendingInteraction:      interaction,
			context:                 restoreAccessAuthorizationContext(record.Context),
			decision:                record.Decision,
			terminalAuthToken:       record.TerminalAuthToken,
			terminalVerificationKey: copyJWK(record.TerminalVerificationKey),
			terminalExpiresAt:       record.TerminalExpiresAt,
			terminalStatus:          record.TerminalStatus,
			terminalCode:            record.TerminalCode,
			terminalDetail:          record.TerminalDetail,
		}
		server := &AccessServer{
			identifier: "https://as.example", signingKey: fixture.accessKey,
			clock: aauth.ClockFunc(func() time.Time { return now }), authorizationStore: store,
			pending: map[string]*pendingAccessServerAuthorization{record.Key: pending},
		}
		if err := server.persistAuthorizationStateLocked(context.Background()); err != nil {
			t.Fatal(err)
		}
		now = fixture.now.Add(time.Hour)
		request := httptest.NewRequest(http.MethodGet, "https://as.example/interaction/"+record.Key, nil)
		request.SetPathValue("id", record.Key)
		response := httptest.NewRecorder()
		server.handleInteraction(response, request)
		if response.Code != http.StatusGone || pending.state != record.Interaction.State ||
			pending.terminalAuthToken != record.TerminalAuthToken || pending.pollingError != record.Interaction.PollingError {
			t.Fatalf("access stale interaction = %d state=%s token=%t polling=%s body=%s", response.Code, pending.state, pending.terminalAuthToken != "", pending.pollingError, response.Body.String())
		}
	}

	t.Run("person approved", func(t *testing.T) {
		exercisePerson(t, fixture.personRecord(t, 1, true))
	})
	t.Run("person rejected", func(t *testing.T) {
		record := fixture.personRecord(t, 1, false)
		record.Interaction.State = pendingAuthorizationRejected
		record.Interaction.PollingError = aauth.PollingDenied
		record.Decision = aauth.AuthorizationDecision{}
		exercisePerson(t, record)
	})
	t.Run("access approved", func(t *testing.T) {
		exerciseAccess(t, fixture.accessRecord(t, 1, true))
	})
	t.Run("access rejected", func(t *testing.T) {
		record := fixture.accessRecord(t, 1, false)
		record.Interaction.State = pendingAuthorizationRejected
		record.Interaction.PollingError = aauth.PollingDenied
		record.Decision = aauth.AuthorizationDecision{}
		exerciseAccess(t, record)
	})
}

func TestFederatedTerminalTransitionsRemainDurableAndSemanticallyBound(t *testing.T) {
	fixture := newAuthorizationStateSemanticFixture(t)

	newServer := func(t *testing.T, transport http.RoundTripper) (*PersonServer, string) {
		t.Helper()
		record := fixture.federatedPersonRecord(t, 1, false)
		record.Interaction.State = pendingAuthorizationWaiting
		interaction, err := restorePendingInteraction(record.Interaction)
		if err != nil {
			t.Fatal(err)
		}
		store, err := NewMemoryAuthorizationStateStore(16, 1<<20)
		if err != nil {
			t.Fatal(err)
		}
		server := &PersonServer{
			identifier: "https://ps.example", signingKey: fixture.personKey,
			clock:              aauth.ClockFunc(func() time.Time { return fixture.now }),
			authorizationStore: store, federationClient: &http.Client{Transport: transport},
			pending: map[string]*pendingPersonAuthorization{
				record.Key: {
					pendingInteraction: interaction,
					context:            restorePersonAuthorizationContext(record.Context),
					decision:           record.Decision,
					federated: &pendingFederatedAuthorization{
						accessServer: record.Federated.AccessServer,
						location:     record.Federated.Location,
						notBefore:    record.Federated.NotBefore,
						status:       record.Federated.Status,
					},
					pollingFederation: true,
				},
			},
		}
		if err := server.persistAuthorizationStateLocked(context.Background()); err != nil {
			t.Fatal(err)
		}
		return server, record.Key
	}

	for _, status := range []int{http.StatusNoContent, http.StatusFound} {
		status := status
		t.Run(fmt.Sprintf("non-error terminal status %d maps to bad gateway", status), func(t *testing.T) {
			server, id := newServer(t, authorizationRoundTripFunc(func(request *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: status,
					Header:     make(http.Header),
					Body:       io.NopCloser(strings.NewReader("")),
					Request:    request,
				}, nil
			}))
			pending := server.pending[id]
			response := httptest.NewRecorder()
			server.pollFederatedAuthorization(
				response, context.Background(), id, copyPendingFederation(pending.federated),
				copyPersonAuthorizationContext(pending.context), pending.decision,
			)
			if response.Code != http.StatusBadGateway || pending.state != pendingAuthorizationRejected ||
				pending.terminalStatus != http.StatusBadGateway || pending.terminalDetail == "" {
				t.Fatalf("federated status %d transition = %d state=%s terminal=%d/%q: %s", status, response.Code, pending.state, pending.terminalStatus, pending.terminalDetail, response.Body.String())
			}
		})
	}

	t.Run("empty problem detail gets deterministic retained explanation", func(t *testing.T) {
		server, id := newServer(t, authorizationRoundTripFunc(func(request *http.Request) (*http.Response, error) {
			header := make(http.Header)
			header.Set("Content-Type", "application/problem+json")
			return &http.Response{
				StatusCode: http.StatusForbidden,
				Header:     header,
				Body: io.NopCloser(strings.NewReader(
					`{"type":"about:blank","title":"Forbidden","status":403,"error":"denied"}`,
				)),
				Request: request,
			}, nil
		}))
		pending := server.pending[id]
		response := httptest.NewRecorder()
		server.pollFederatedAuthorization(
			response, context.Background(), id, copyPendingFederation(pending.federated),
			copyPersonAuthorizationContext(pending.context), pending.decision,
		)
		if response.Code != http.StatusForbidden || pending.state != pendingAuthorizationRejected ||
			pending.terminalDetail == "" {
			t.Fatalf("empty-detail terminal = %d state=%s detail=%q: %s", response.Code, pending.state, pending.terminalDetail, response.Body.String())
		}
	})

	t.Run("continuation cannot move to another pending identifier", func(t *testing.T) {
		otherID := semanticPendingID(t, 2)
		server, id := newServer(t, authorizationRoundTripFunc(func(request *http.Request) (*http.Response, error) {
			header := make(http.Header)
			header.Set("Location", "https://as.example/pending/"+otherID)
			header.Set("Retry-After", "0")
			return &http.Response{
				StatusCode: http.StatusAccepted,
				Header:     header,
				Body:       io.NopCloser(strings.NewReader(`{"status":"pending"}`)),
				Request:    request,
			}, nil
		}))
		pending := server.pending[id]
		response := httptest.NewRecorder()
		server.pollFederatedAuthorization(
			response, context.Background(), id, copyPendingFederation(pending.federated),
			copyPersonAuthorizationContext(pending.context), pending.decision,
		)
		if response.Code != http.StatusBadGateway || pending.state != pendingAuthorizationRejected ||
			pending.federated.location != "https://as.example/pending/"+id {
			t.Fatalf("moved continuation = %d state=%s location=%s: %s", response.Code, pending.state, pending.federated.location, response.Body.String())
		}
	})

	t.Run("failed terminal persistence returns custody refusal", func(t *testing.T) {
		record := fixture.federatedPersonRecord(t, 1, false)
		record.Interaction.State = pendingAuthorizationWaiting
		interaction, err := restorePendingInteraction(record.Interaction)
		if err != nil {
			t.Fatal(err)
		}
		store := newUnreconcilableAuthorizationStateStore(t)
		store.fail = true
		server := &PersonServer{
			identifier: "https://ps.example", signingKey: fixture.personKey,
			clock: aauth.ClockFunc(func() time.Time { return fixture.now }), authorizationStore: store,
			pending: map[string]*pendingPersonAuthorization{
				record.Key: {
					pendingInteraction: interaction,
					context:            restorePersonAuthorizationContext(record.Context),
					decision:           record.Decision,
					federated: &pendingFederatedAuthorization{
						accessServer: record.Federated.AccessServer,
						location:     record.Federated.Location,
						notBefore:    record.Federated.NotBefore,
						status:       record.Federated.Status,
					},
					pollingFederation: true,
				},
			},
		}
		response := httptest.NewRecorder()
		server.failFederatedAuthorization(response, record.Key, http.StatusBadGateway, "federation_failed", errors.New("upstream failed"))
		if response.Code != http.StatusServiceUnavailable ||
			!bytes.Contains(response.Body.Bytes(), []byte(`"error":"authorization_state_unavailable"`)) {
			t.Fatalf("failed terminal persistence = %d: %s", response.Code, response.Body.String())
		}
	})

	t.Run("late poll failure cannot revive expired state", func(t *testing.T) {
		server, id := newServer(t, authorizationRoundTripFunc(func(*http.Request) (*http.Response, error) {
			return nil, errors.New("unused")
		}))
		pending := server.pending[id]
		pending.state = pendingAuthorizationExpired
		response := httptest.NewRecorder()
		server.failFederatedAuthorization(response, id, http.StatusBadGateway, "federation_failed", errors.New("late failure"))
		if response.Code != http.StatusRequestTimeout || pending.state != pendingAuthorizationExpired ||
			pending.terminalStatus != 0 {
			t.Fatalf("late federated failure = %d state=%s terminal=%d: %s", response.Code, pending.state, pending.terminalStatus, response.Body.String())
		}
	})
}

func expiryPersonServer(
	t *testing.T,
	fixture authorizationStateSemanticFixture,
	now *time.Time,
	policy aauth.AuthorizationPolicy,
) (*PersonServer, *unreconcilableAuthorizationStateStore, string) {
	t.Helper()
	record := fixture.personRecord(t, 1, false)
	record.Interaction.State = pendingAuthorizationInteracting
	record.Decision = aauth.AuthorizationDecision{}
	interaction, err := restorePendingInteraction(record.Interaction)
	if err != nil {
		t.Fatal(err)
	}
	store := newUnreconcilableAuthorizationStateStore(t)
	return &PersonServer{
		identifier: "https://ps.example", signingKey: fixture.personKey,
		clock: aauth.ClockFunc(func() time.Time { return *now }), authorizationPolicy: policy,
		authorizationStore: store,
		pending: map[string]*pendingPersonAuthorization{
			record.Key: {
				pendingInteraction: interaction,
				context:            restorePersonAuthorizationContext(record.Context),
			},
		},
	}, store, record.Key
}

func expiryAccessServer(
	t *testing.T,
	fixture authorizationStateSemanticFixture,
	now *time.Time,
	policy aauth.AuthorizationPolicy,
) (*AccessServer, *unreconcilableAuthorizationStateStore, string) {
	t.Helper()
	record := fixture.accessRecord(t, 1, false)
	record.Interaction.State = pendingAuthorizationInteracting
	record.Decision = aauth.AuthorizationDecision{}
	interaction, err := restorePendingInteraction(record.Interaction)
	if err != nil {
		t.Fatal(err)
	}
	store := newUnreconcilableAuthorizationStateStore(t)
	return &AccessServer{
		identifier: "https://as.example", signingKey: fixture.accessKey,
		clock: aauth.ClockFunc(func() time.Time { return *now }), authorizationPolicy: policy,
		authorizationStore: store,
		pending: map[string]*pendingAccessServerAuthorization{
			record.Key: {
				pendingInteraction: interaction,
				context:            restoreAccessAuthorizationContext(record.Context),
			},
		},
	}, store, record.Key
}

func expiryResource(
	t *testing.T,
	fixture authorizationStateSemanticFixture,
	now *time.Time,
	policy aauth.AuthorizationPolicy,
) (*Resource, *unreconcilableAuthorizationStateStore, string) {
	t.Helper()
	record, _ := fixture.resourceAuthorizationRecords(t, 1, false)
	stored := record.Pending
	interaction, err := restorePendingInteraction(pendingInteractionRecord{
		ID: stored.ID, Code: stored.Code, NormalizedCode: stored.NormalizedCode,
		CodeConsumed: stored.CodeConsumed, FailedCodeAttempts: stored.FailedCodeAttempts,
		State: stored.State, PollingError: stored.PollingError, ExpiresAt: stored.ExpiresAt,
	})
	if err != nil {
		t.Fatal(err)
	}
	store := newUnreconcilableAuthorizationStateStore(t)
	return &Resource{
		identifier: "https://resource.example",
		clock:      aauth.ClockFunc(func() time.Time { return *now }), authorizationPolicy: policy,
		authorizationStore: store,
		pending: map[string]*pendingAuthorization{
			record.Key: {
				pendingInteraction:     interaction,
				request:                copyAuthorizationRequest(stored.Request),
				requestBody:            append([]byte(nil), stored.RequestBody...),
				requestProof:           copyRequestProof(stored.RequestProof),
				requestVerificationKey: stored.RequestVerificationKey,
				agentThumbprint:        stored.AgentThumbprint,
				agentExpiresAt:         stored.AgentExpiresAt,
			},
		},
		access: make(map[string]localAccessGrant),
	}, store, record.Key
}

func TestAuthorizationRolesPoisonStateWhenFailedCommitCannotBeReconciled(t *testing.T) {
	t.Run("agent", func(t *testing.T) {
		store := newUnreconcilableAuthorizationStateStore(t)
		role := &Agent{
			authorizationStore: store,
			pendingTokens:      make(map[string]agentPendingTokenRecord),
			pendingAccess:      make(map[string]agentPendingAccessRecord),
		}
		if err := role.persistAuthorizationStateLocked(context.Background()); err != nil {
			t.Fatal(err)
		}
		store.fail = true
		role.pendingAccess["first"] = agentPendingAccessRecord{
			ID: "first", Resource: "https://resource.example",
			Location: "https://resource.example/pending/first", NotBefore: time.Unix(1_750_000_000, 0),
			Status: "pending", RequestedScope: []string{"records.read"},
		}
		assertAuthorizationRolePoisoned(t, store, role.persistAuthorizationStateLocked, func() int {
			return len(role.pendingAccess) + len(role.pendingTokens)
		})
	})

	t.Run("resource", func(t *testing.T) {
		store := newUnreconcilableAuthorizationStateStore(t)
		role := &Resource{
			authorizationStore: store,
			pending:            make(map[string]*pendingAuthorization),
			access:             make(map[string]localAccessGrant),
		}
		if err := role.persistAuthorizationStateLocked(context.Background()); err != nil {
			t.Fatal(err)
		}
		store.fail = true
		role.access["first"] = localAccessGrant{
			agent: "aauth:agent@ap.example", subject: "person",
			thumbprint: strings.Repeat("A", 43), scope: []string{"records.read"},
			expiresAt: time.Unix(1_750_003_600, 0),
		}
		assertAuthorizationRolePoisoned(t, store, role.persistAuthorizationStateLocked, func() int {
			return len(role.pending) + len(role.access)
		})
	})

	t.Run("person server", func(t *testing.T) {
		fixture := newAuthorizationStateSemanticFixture(t)
		store := newUnreconcilableAuthorizationStateStore(t)
		role := &PersonServer{
			identifier:         "https://ps.example",
			signingKey:         fixture.personKey,
			authorizationStore: store,
			pending:            make(map[string]*pendingPersonAuthorization),
		}
		if err := role.persistAuthorizationStateLocked(context.Background()); err != nil {
			t.Fatal(err)
		}
		store.fail = true
		record := fixture.personRecord(t, 1, false)
		interaction, err := restorePendingInteraction(record.Interaction)
		if err != nil {
			t.Fatal(err)
		}
		role.pending[record.Key] = &pendingPersonAuthorization{
			pendingInteraction: interaction,
			context:            restorePersonAuthorizationContext(record.Context),
			decision:           record.Decision,
		}
		assertAuthorizationRolePoisoned(t, store, role.persistAuthorizationStateLocked, func() int {
			return len(role.pending)
		})
	})

	t.Run("access server", func(t *testing.T) {
		fixture := newAuthorizationStateSemanticFixture(t)
		store := newUnreconcilableAuthorizationStateStore(t)
		role := &AccessServer{
			identifier:         "https://as.example",
			signingKey:         fixture.accessKey,
			authorizationStore: store,
			pending:            make(map[string]*pendingAccessServerAuthorization),
		}
		if err := role.persistAuthorizationStateLocked(context.Background()); err != nil {
			t.Fatal(err)
		}
		store.fail = true
		record := fixture.accessRecord(t, 1, false)
		interaction, err := restorePendingInteraction(record.Interaction)
		if err != nil {
			t.Fatal(err)
		}
		role.pending[record.Key] = &pendingAccessServerAuthorization{
			pendingInteraction: interaction,
			context:            restoreAccessAuthorizationContext(record.Context),
			decision:           record.Decision,
		}
		assertAuthorizationRolePoisoned(t, store, role.persistAuthorizationStateLocked, func() int {
			return len(role.pending)
		})
	})
}

func openRoleAuthorizationStateStore(t *testing.T) (*FileAuthorizationStateStore, FileAuthorizationStateStoreConfig) {
	t.Helper()
	config := FileAuthorizationStateStoreConfig{
		Directory:  filepath.Join(t.TempDir(), "authorization"),
		MaxEntries: 16,
		MaxBytes:   1 << 20,
	}
	store, err := OpenFileAuthorizationStateStore(config)
	if err != nil {
		t.Fatal(err)
	}
	return store, config
}

func reopenRoleAuthorizationStateStore(
	t *testing.T,
	store *FileAuthorizationStateStore,
	config FileAuthorizationStateStoreConfig,
) *FileAuthorizationStateStore {
	t.Helper()
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenFileAuthorizationStateStore(config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	return reopened
}

func injectPublishedUncertainAuthorizationStateCommit(store *FileAuthorizationStateStore) {
	store.file.SetFailureInjectorForTesting(func(phase snapshotfile.CommitPhase) error {
		if phase == snapshotfile.CommitAfterRename {
			return errors.New("injected directory-sync loss")
		}
		return nil
	})
}

func distinctPendingRandomness() *bytes.Reader {
	return bytes.NewReader(append(append(make([]byte, 21), bytes.Repeat([]byte{1}, 21)...), bytes.Repeat([]byte{2}, 21)...))
}

func deterministicPendingIDs(t *testing.T) (string, string) {
	t.Helper()
	first, err := aauth.GeneratePendingID(bytes.NewReader(make([]byte, 16)))
	if err != nil {
		t.Fatal(err)
	}
	second, err := aauth.GeneratePendingID(bytes.NewReader(bytes.Repeat([]byte{1}, 16)))
	if err != nil {
		t.Fatal(err)
	}
	return first, second
}

func deterministicThreePendingIDs(t *testing.T) (string, string, string) {
	t.Helper()
	first, second := deterministicPendingIDs(t)
	third, err := aauth.GeneratePendingID(bytes.NewReader(bytes.Repeat([]byte{2}, 16)))
	if err != nil {
		t.Fatal(err)
	}
	return first, second, third
}

func roleAuthorizationSnapshot(t *testing.T, schema string, records ...any) []byte {
	t.Helper()
	raw := make([]json.RawMessage, 0, len(records))
	for _, record := range records {
		encoded, err := json.Marshal(record)
		if err != nil {
			t.Fatal(err)
		}
		raw = append(raw, encoded)
	}
	body, err := marshalAuthorizationStateRecords(schema, raw)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

type authorizationStateSemanticFixture struct {
	now         time.Time
	personKey   aauth.SigningKey
	accessKey   aauth.SigningKey
	resourceKey aauth.SigningKey
	providerKey aauth.SigningKey
	agentKeys   []aauth.SigningKey
}

func newAuthorizationStateSemanticFixture(t *testing.T) authorizationStateSemanticFixture {
	t.Helper()
	return authorizationStateSemanticFixture{
		now:         time.Date(2026, 8, 28, 20, 0, 0, 0, time.UTC),
		personKey:   referenceTestSigningKey(t, "person-key"),
		accessKey:   referenceTestSigningKey(t, "access-key"),
		resourceKey: referenceTestSigningKey(t, "resource-key"),
		providerKey: referenceTestSigningKey(t, "provider-key"),
		agentKeys: []aauth.SigningKey{
			referenceTestSigningKey(t, "agent-key-1"),
			referenceTestSigningKey(t, "agent-key-2"),
		},
	}
}

func (fixture authorizationStateSemanticFixture) personRecord(
	t *testing.T,
	ordinal int,
	withTerminal bool,
) personAuthorizationStateRecord {
	t.Helper()
	resourceToken, compact := fixture.resourceToken(t, ordinal, "https://ps.example")
	agentKey := fixture.agentKeys[ordinal-1]
	agent := fmt.Sprintf("aauth:agent-%d@ap.example", ordinal)
	agentToken, err := aauth.MintAgentToken(
		"https://ap.example",
		fixture.providerKey,
		aauth.AgentTokenRequest{
			Agent: agent, PersonServer: "https://ps.example", PublicKey: agentKey.PublicJWK(), Lifetime: time.Hour,
		},
		fixture.now,
		fmt.Sprintf("agent-token-%d", ordinal),
	)
	if err != nil {
		t.Fatal(err)
	}
	agentThumbprint, err := agentKey.PublicJWK().Thumbprint()
	if err != nil {
		t.Fatal(err)
	}
	scope := []string{fmt.Sprintf("records.%d.read", ordinal)}
	pendingID := semanticPendingID(t, ordinal)
	record := personAuthorizationStateRecord{
		Key: pendingID,
		Interaction: pendingInteractionRecord{
			ID: pendingID, Code: "0000-0000", NormalizedCode: "00000000",
			CodeConsumed: true, State: pendingAuthorizationApproved, ExpiresAt: fixture.now.Add(4 * time.Minute),
		},
		Context: personAuthorizationContextRecord{
			Request: aauth.AuthorizationRequest{
				Agent: agent, PersonServer: resourceToken.PersonServer, Subject: resourceToken.Subject,
				Resource: resourceToken.Issuer, Scope: scope, MissionS256: resourceToken.MissionS256,
				Tenant: resourceToken.Tenant, Account: resourceToken.Account,
			},
			ResourceTokenCompact: compact,
			AgentTokenCompact:    agentToken,
			TokenVerificationKeys: retainedAuthorizationTokenKeys{
				Resource: fixture.resourceKey.PublicJWK(),
				Agent:    fixture.providerKey.PublicJWK(),
			},
			TargetAgent:            agent,
			TargetKey:              agentKey.PublicJWK(),
			PollingAgent:           agent,
			PollingAgentThumbprint: agentThumbprint,
			TargetTokenExpiresAt:   fixture.now.Add(time.Hour).Unix(),
			ResourceToken:          resourceToken,
			PersonTokenRecord: PersonTokenRecord{
				JTI: resourceToken.PresentedJTI, PersonServer: resourceToken.PersonServer,
				TokenSHA256: strings.Repeat("a", 64), Resource: resourceToken.Issuer,
				Subject: resourceToken.Subject, MissionS256: resourceToken.MissionS256,
				Tenant: resourceToken.Tenant, ExpiresAt: fixture.now.Add(time.Hour),
				RetainUntil: fixture.now.Add(time.Hour + currentResourceTokenLifetime),
			},
		},
		Decision: aauth.AuthorizationDecision{Subject: resourceToken.Subject, Scope: scope},
	}
	fixture.bindPersonRequestEvidence(t, &record, agentKey)
	if !withTerminal {
		return record
	}
	claims := fixture.terminalClaims(
		ordinal,
		record.Key,
		"https://ps.example",
		aauth.PersonDiscoveryDocument,
		resourceToken,
		agentKey.PublicJWK(),
		record.Decision,
	)
	record.TerminalAuthToken, err = aauth.MintAuthToken(fixture.personKey, claims)
	if err != nil {
		t.Fatal(err)
	}
	record.TerminalExpiresAt = claims.ExpiresAt
	verificationKey := fixture.personKey.PublicJWK()
	record.TerminalVerificationKey = &verificationKey
	return record
}

func (fixture authorizationStateSemanticFixture) accessRecord(
	t *testing.T,
	ordinal int,
	withTerminal bool,
) accessAuthorizationStateRecord {
	t.Helper()
	resourceToken, compact := fixture.resourceToken(t, ordinal, "https://as.example")
	agentKey := fixture.agentKeys[ordinal-1]
	agent := fmt.Sprintf("aauth:agent-%d@ap.example", ordinal)
	agentToken, err := aauth.MintAgentToken(
		"https://ap.example",
		fixture.providerKey,
		aauth.AgentTokenRequest{
			Agent: agent, PersonServer: "https://ps.example", PublicKey: agentKey.PublicJWK(), Lifetime: time.Hour,
		},
		fixture.now,
		fmt.Sprintf("agent-token-%d", ordinal),
	)
	if err != nil {
		t.Fatal(err)
	}
	targetThumbprint, err := agentKey.PublicJWK().Thumbprint()
	if err != nil {
		t.Fatal(err)
	}
	if targetThumbprint != resourceToken.AgentJKT {
		t.Fatal("semantic fixture target key does not match resource token")
	}
	pollingThumbprint, err := fixture.personKey.PublicJWK().Thumbprint()
	if err != nil {
		t.Fatal(err)
	}
	scope := []string{fmt.Sprintf("records.%d.read", ordinal)}
	pendingID := semanticPendingID(t, ordinal)
	record := accessAuthorizationStateRecord{
		Key: pendingID,
		Interaction: pendingInteractionRecord{
			ID: pendingID, Code: "0000-0000", NormalizedCode: "00000000",
			CodeConsumed: true, State: pendingAuthorizationApproved, ExpiresAt: fixture.now.Add(4 * time.Minute),
		},
		Context: accessAuthorizationContextRecord{
			Request: aauth.AuthorizationRequest{
				Agent: agent, PersonServer: resourceToken.PersonServer, Subject: resourceToken.Subject,
				Resource: resourceToken.Issuer, Scope: scope, MissionS256: resourceToken.MissionS256,
				Tenant: resourceToken.Tenant, Account: resourceToken.Account,
			},
			ResourceToken:        resourceToken,
			ResourceTokenCompact: compact,
			AgentTokenCompact:    agentToken,
			TokenVerificationKeys: retainedAuthorizationTokenKeys{
				Resource: fixture.resourceKey.PublicJWK(),
				Agent:    fixture.providerKey.PublicJWK(),
			},
			TargetAgent:          agent,
			TargetKey:            agentKey.PublicJWK(),
			TargetTokenExpiresAt: fixture.now.Add(time.Hour).Unix(),
			PollingServer:        "https://ps.example",
			PollingKey:           fixture.personKey.PublicJWK(),
			PollingKeyThumbprint: pollingThumbprint,
		},
		Decision: aauth.AuthorizationDecision{Subject: resourceToken.Subject, Scope: scope},
	}
	fixture.bindAccessRequestEvidence(t, &record)
	if !withTerminal {
		return record
	}
	claims := fixture.terminalClaims(
		ordinal,
		record.Key,
		"https://as.example",
		aauth.AccessDiscoveryDocument,
		resourceToken,
		agentKey.PublicJWK(),
		record.Decision,
	)
	record.TerminalAuthToken, err = aauth.MintAuthToken(fixture.accessKey, claims)
	if err != nil {
		t.Fatal(err)
	}
	record.TerminalExpiresAt = claims.ExpiresAt
	verificationKey := fixture.accessKey.PublicJWK()
	record.TerminalVerificationKey = &verificationKey
	return record
}

func (fixture authorizationStateSemanticFixture) bindAccessRequestEvidence(
	t *testing.T,
	record *accessAuthorizationStateRecord,
) {
	t.Helper()
	body, err := json.Marshal(accessAuthorizationTokenInput{
		ResourceToken: record.Context.ResourceTokenCompact,
		AgentToken:    record.Context.AgentTokenCompact,
		SubagentToken: record.Context.SubagentTokenCompact,
		UpstreamToken: record.Context.UpstreamTokenCompact,
	})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "https://as.example/token", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	clock := aauth.ClockFunc(func() time.Time { return fixture.now })
	if err := aauth.SignRequestWithJWKSURI(
		request,
		fixture.personKey,
		"https://ps.example",
		aauth.PersonDiscoveryDocument,
		clock,
	); err != nil {
		t.Fatal(err)
	}
	verified, err := aauth.VerifyRequest(
		context.Background(),
		request,
		aauth.StaticKeyResolver{
			"https://ps.example": {fixture.personKey.ID(): fixture.personKey.PublicJWK()},
		},
		clock,
		aauth.VerifyRequestOptions{
			RequiredComponents:       []string{"content-type"},
			RequireExactComponents:   true,
			AllowedSignatureKeyTypes: []string{aauth.SignatureKeyJWKSURI},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	record.Context.RequestBody = append([]byte(nil), body...)
	record.Context.RequestProof = requestProof(request, verified)
}

func (fixture authorizationStateSemanticFixture) federatedPersonRecord(
	t *testing.T,
	ordinal int,
	withTerminal bool,
) personAuthorizationStateRecord {
	t.Helper()
	record := fixture.personRecord(t, ordinal, false)
	resourceToken, compact := fixture.resourceToken(t, ordinal, "https://as.example")
	record.Context.ResourceToken = resourceToken
	record.Context.ResourceTokenCompact = compact
	record.Context.Request.PersonServer = resourceToken.PersonServer
	record.Context.Request.Subject = resourceToken.Subject
	record.Context.Request.Resource = resourceToken.Issuer
	record.Context.Request.MissionS256 = resourceToken.MissionS256
	record.Context.Request.Tenant = resourceToken.Tenant
	record.Context.Request.Account = resourceToken.Account
	fixture.bindPersonRequestEvidence(t, &record, fixture.agentKeys[ordinal-1])
	record.Interaction.Code = ""
	record.Interaction.NormalizedCode = ""
	record.Interaction.CodeConsumed = false
	record.Federated = &pendingFederatedRecord{
		AccessServer: "https://as.example",
		Location:     "https://as.example/pending/" + record.Key,
		NotBefore:    fixture.now,
		Status:       "pending",
	}
	if !withTerminal {
		return record
	}
	claims := fixture.terminalClaims(
		ordinal,
		record.Key,
		"https://as.example",
		aauth.AccessDiscoveryDocument,
		resourceToken,
		record.Context.TargetKey,
		record.Decision,
	)
	var err error
	record.TerminalAuthToken, err = aauth.MintAuthToken(fixture.accessKey, claims)
	if err != nil {
		t.Fatal(err)
	}
	verificationKey := fixture.accessKey.PublicJWK()
	record.TerminalVerificationKey = &verificationKey
	record.TerminalExpiresAt = claims.ExpiresAt
	return record
}

func (fixture authorizationStateSemanticFixture) resourceToken(
	t *testing.T,
	ordinal int,
	audience string,
) (aauth.ResourceTokenClaims, string) {
	t.Helper()
	agentKey := fixture.agentKeys[ordinal-1]
	thumbprint, err := agentKey.PublicJWK().Thumbprint()
	if err != nil {
		t.Fatal(err)
	}
	claims := aauth.ResourceTokenClaims{
		Issuer:       "https://resource.example",
		DWK:          aauth.ResourceDiscoveryDocument,
		Audience:     audience,
		JTI:          fmt.Sprintf("resource-token-%d", ordinal),
		AgentJKT:     thumbprint,
		IssuedAt:     fixture.now.Unix(),
		ExpiresAt:    fixture.now.Add(5 * time.Minute).Unix(),
		Scope:        fmt.Sprintf("records.%d.read", ordinal),
		PersonServer: "https://ps.example",
		Subject:      fmt.Sprintf("person-%d", ordinal),
		PresentedJTI: fmt.Sprintf("person-token-%d", ordinal),
		Account:      fmt.Sprintf("account-%d", ordinal),
		Tenant:       fmt.Sprintf("tenant-%d", ordinal),
	}
	compact, err := aauth.MintResourceToken(fixture.resourceKey, claims)
	if err != nil {
		t.Fatal(err)
	}
	return claims, compact
}

func (fixture authorizationStateSemanticFixture) terminalClaims(
	ordinal int,
	tokenID string,
	issuer string,
	discoveryDocument string,
	resourceToken aauth.ResourceTokenClaims,
	targetKey aauth.JWK,
	decision aauth.AuthorizationDecision,
) aauth.AuthTokenClaims {
	return aauth.AuthTokenClaims{
		Issuer: issuer, DWK: discoveryDocument, Audience: resourceToken.Issuer,
		JTI: tokenID, Confirmation: aauth.Confirmation{JWK: targetKey},
		IssuedAt: fixture.now.Add(time.Duration(ordinal) * time.Second).Unix(), ExpiresAt: resourceToken.ExpiresAt,
		Subject: resourceToken.Subject, Scope: fmt.Sprintf("%s", decision.Scope[0]),
		PersonServer: resourceToken.PersonServer, Account: resourceToken.Account,
		MissionS256: resourceToken.MissionS256, Tenant: resourceToken.Tenant,
	}
}

func (fixture authorizationStateSemanticFixture) agentTokenRecord(
	t *testing.T,
	ordinal int,
	withTerminal bool,
) agentAuthorizationStateRecord {
	t.Helper()
	resourceToken, compact := fixture.resourceToken(t, ordinal, "https://ps.example")
	pendingID := semanticPendingID(t, ordinal)
	record := agentAuthorizationStateRecord{
		Kind: "token",
		Key:  pendingID,
		Token: &agentPendingTokenRecord{
			ID: pendingID, PersonServer: "https://ps.example",
			Location:  "https://ps.example/pending/" + pendingID,
			NotBefore: fixture.now,
			Status:    "pending",
			ResourceGrant: ResourceGrant{
				Resource: "https://resource.example", ResourceToken: compact, Claims: resourceToken,
			},
			ExpectedIssuer:          "https://ps.example",
			ExpectedKey:             fixture.agentKeys[ordinal-1].PublicJWK(),
			ResourceVerificationKey: fixture.resourceKey.PublicJWK(),
		},
	}
	if !withTerminal {
		return record
	}
	decision := aauth.AuthorizationDecision{
		Subject: resourceToken.Subject,
		Scope:   strings.Fields(resourceToken.Scope),
	}
	claims := fixture.terminalClaims(
		ordinal,
		pendingID,
		"https://ps.example",
		aauth.PersonDiscoveryDocument,
		resourceToken,
		record.Token.ExpectedKey,
		decision,
	)
	authToken, err := aauth.MintAuthToken(fixture.personKey, claims)
	if err != nil {
		t.Fatal(err)
	}
	record.Token.TerminalGrant = &Grant{
		Resource:  record.Token.ResourceGrant.Resource,
		AuthToken: authToken,
		Claims:    claims,
	}
	verificationKey := fixture.personKey.PublicJWK()
	record.Token.TerminalVerificationKey = &verificationKey
	return record
}

func (fixture authorizationStateSemanticFixture) resourceAuthorizationRecords(
	t *testing.T,
	ordinal int,
	withTerminal bool,
) (resourceAuthorizationStateRecord, resourceAuthorizationStateRecord) {
	t.Helper()
	agentKey := fixture.agentKeys[ordinal-1]
	personClaims := aauth.PersonTokenClaims{
		Issuer: "https://ps.example", DWK: aauth.PersonDiscoveryDocument,
		Audience: "https://resource.example", Subject: fmt.Sprintf("person-%d", ordinal),
		Confirmation: aauth.Confirmation{JWK: agentKey.PublicJWK()},
		JTI:          fmt.Sprintf("person-token-%d", ordinal), IssuedAt: fixture.now.Unix(),
		ExpiresAt: fixture.now.Add(time.Hour).Unix(), Tenant: fmt.Sprintf("tenant-%d", ordinal),
	}
	personToken, err := aauth.MintPersonToken(fixture.personKey, personClaims)
	if err != nil {
		t.Fatal(err)
	}
	scope := fmt.Sprintf("records.%d.read", ordinal)
	body, err := json.Marshal(resourceAuthorizationInput{Scope: scope, Account: fmt.Sprintf("account-%d", ordinal)})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "https://resource.example/authorize", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	clock := aauth.ClockFunc(func() time.Time { return fixture.now })
	if err := aauth.SignRequest(request, agentKey, personToken, clock); err != nil {
		t.Fatal(err)
	}
	verified, err := aauth.VerifyRequest(
		context.Background(),
		request,
		aauth.StaticKeyResolver{"https://ps.example": {fixture.personKey.ID(): fixture.personKey.PublicJWK()}},
		clock,
		aauth.VerifyRequestOptions{
			RequiredComponents:     []string{"content-type"},
			RequireExactComponents: true,
			AllowedCredentialTypes: []string{aauth.PersonTokenType},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	pendingID := semanticPendingID(t, ordinal)
	interaction := pendingInteractionRecord{
		ID: pendingID, Code: "0000-0000", NormalizedCode: "00000000",
		CodeConsumed: true, State: pendingAuthorizationInteracting,
		ExpiresAt: fixture.now.Add(4 * time.Minute),
	}
	thumbprint, err := agentKey.PublicJWK().Thumbprint()
	if err != nil {
		t.Fatal(err)
	}
	pending := resourceAuthorizationStateRecord{
		Kind: "pending", Key: pendingID,
		Pending: &resourcePendingAuthorizationRecord{
			ID: pendingID, Code: interaction.Code, NormalizedCode: interaction.NormalizedCode,
			CodeConsumed: interaction.CodeConsumed, State: interaction.State, ExpiresAt: interaction.ExpiresAt,
			Request: aauth.AuthorizationRequest{
				PersonServer: personClaims.Issuer, Subject: personClaims.Subject,
				Resource: "https://resource.example", Scope: []string{scope},
				Account: fmt.Sprintf("account-%d", ordinal), Tenant: personClaims.Tenant,
			},
			RequestBody: append([]byte(nil), body...), RequestProof: requestProof(request, verified),
			RequestVerificationKey: fixture.personKey.PublicJWK(),
			AgentThumbprint:        thumbprint, AgentExpiresAt: time.Unix(personClaims.ExpiresAt, 0).UTC(),
		},
	}
	if !withTerminal {
		return pending, resourceAuthorizationStateRecord{}
	}
	accessToken := fmt.Sprintf("access-token-%d", ordinal)
	pending.Pending.State = pendingAuthorizationApproved
	pending.Pending.Decision = aauth.AuthorizationDecision{Subject: personClaims.Subject, Scope: []string{scope}}
	pending.Pending.TerminalAccessToken = accessToken
	grant := resourceAuthorizationStateRecord{
		Kind: "grant", Key: accessToken,
		Grant: &resourceAccessGrantRecord{
			Subject: personClaims.Subject, Thumbprint: thumbprint, Scope: []string{scope},
			ExpiresAt: fixture.now.Add(30 * time.Minute), SourcePendingID: pendingID,
		},
	}
	return pending, grant
}

func (fixture authorizationStateSemanticFixture) loadResourceRecordsAfterReopen(
	t *testing.T,
	wantError bool,
	records ...resourceAuthorizationStateRecord,
) {
	t.Helper()
	values := make([]any, 0, len(records))
	for _, record := range records {
		if record.Kind != "" {
			values = append(values, record)
		}
	}
	sort.Slice(values, func(i, j int) bool {
		first := values[i].(resourceAuthorizationStateRecord)
		second := values[j].(resourceAuthorizationStateRecord)
		return first.Kind+"\x00"+first.Key < second.Kind+"\x00"+second.Key
	})
	store := reopenedAuthorizationStateWithRecords(t, resourceAuthorizationStateSchema, values...)
	resource := &Resource{
		identifier: "https://resource.example", authorizationStore: store,
		pending: make(map[string]*pendingAuthorization), access: make(map[string]localAccessGrant),
	}
	err := resource.loadAuthorizationState(context.Background())
	if wantError && !errors.Is(err, ErrAuthorizationStateIntegrity) {
		t.Fatalf("resource semantic corruption error = %v", err)
	}
	if !wantError && err != nil {
		t.Fatalf("load valid resource state = %v", err)
	}
}

func (fixture authorizationStateSemanticFixture) loadAgentRecordsAfterReopen(
	t *testing.T,
	wantError bool,
	records ...agentAuthorizationStateRecord,
) {
	t.Helper()
	values := make([]any, len(records))
	for index := range records {
		values[index] = records[index]
	}
	store := reopenedAuthorizationStateWithRecords(t, agentAuthorizationStateSchema, values...)
	agent := &Agent{
		authorizationStore: store,
		pendingTokens:      make(map[string]agentPendingTokenRecord),
		pendingAccess:      make(map[string]agentPendingAccessRecord),
	}
	err := agent.loadAuthorizationState(context.Background())
	if wantError && !errors.Is(err, ErrAuthorizationStateIntegrity) {
		t.Fatalf("agent semantic corruption error = %v", err)
	}
	if !wantError && err != nil {
		t.Fatalf("load valid agent state = %v", err)
	}
}

func (fixture authorizationStateSemanticFixture) bindPersonRequestEvidence(
	t *testing.T,
	record *personAuthorizationStateRecord,
	agentKey aauth.SigningKey,
) {
	t.Helper()
	body, err := json.Marshal(personAuthorizationTokenInput{
		ResourceToken: record.Context.ResourceTokenCompact,
		SubagentToken: record.Context.SubagentTokenCompact,
		UpstreamToken: record.Context.UpstreamTokenCompact,
		Justification: record.Context.Request.Justification,
	})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "https://ps.example/token", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	clock := aauth.ClockFunc(func() time.Time { return fixture.now })
	if err := aauth.SignRequest(request, agentKey, record.Context.AgentTokenCompact, clock); err != nil {
		t.Fatal(err)
	}
	verified, err := aauth.VerifyRequest(
		context.Background(),
		request,
		aauth.StaticKeyResolver{
			"https://ap.example": {fixture.providerKey.ID(): fixture.providerKey.PublicJWK()},
		},
		clock,
		aauth.VerifyRequestOptions{
			RequiredComponents:     []string{"content-digest"},
			AllowedCredentialTypes: []string{aauth.AgentTokenType},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	record.Context.RequestBody = append([]byte(nil), body...)
	record.Context.RequestProof = requestProof(request, verified)
}

func semanticPendingID(t *testing.T, ordinal int) string {
	t.Helper()
	pendingID, err := aauth.GeneratePendingID(bytes.NewReader(bytes.Repeat([]byte{byte(ordinal)}, 16)))
	if err != nil {
		t.Fatal(err)
	}
	return pendingID
}

func (fixture authorizationStateSemanticFixture) loadPersonRecordsAfterReopen(
	t *testing.T,
	wantIntegrityError bool,
	records ...personAuthorizationStateRecord,
) {
	t.Helper()
	values := make([]any, len(records))
	for index := range records {
		values[index] = records[index]
	}
	store := reopenedAuthorizationStateWithRecords(t, personAuthorizationStateSchema, values...)
	server := &PersonServer{
		identifier: "https://ps.example", signingKey: fixture.personKey,
		authorizationStore: store, pending: make(map[string]*pendingPersonAuthorization),
	}
	err := server.loadAuthorizationState(context.Background())
	if wantIntegrityError {
		if !errors.Is(err, ErrAuthorizationStateIntegrity) {
			t.Fatalf("person-server corrupt reopened state error = %v", err)
		}
		return
	}
	if err != nil {
		t.Fatalf("person-server valid reopened state error = %v", err)
	}
}

func (fixture authorizationStateSemanticFixture) loadAccessRecordsAfterReopen(
	t *testing.T,
	wantIntegrityError bool,
	records ...accessAuthorizationStateRecord,
) {
	t.Helper()
	values := make([]any, len(records))
	for index := range records {
		values[index] = records[index]
	}
	store := reopenedAuthorizationStateWithRecords(t, accessAuthorizationStateSchema, values...)
	server := &AccessServer{
		identifier: "https://as.example", signingKey: fixture.accessKey,
		authorizationStore: store, pending: make(map[string]*pendingAccessServerAuthorization),
	}
	err := server.loadAuthorizationState(context.Background())
	if wantIntegrityError {
		if !errors.Is(err, ErrAuthorizationStateIntegrity) {
			t.Fatalf("access-server corrupt reopened state error = %v", err)
		}
		return
	}
	if err != nil {
		t.Fatalf("access-server valid reopened state error = %v", err)
	}
}

func (fixture authorizationStateSemanticFixture) rejectPersonRecordBeforePersistence(
	t *testing.T,
	record personAuthorizationStateRecord,
) {
	t.Helper()
	store, err := NewMemoryAuthorizationStateStore(16, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	server := &PersonServer{
		identifier: "https://ps.example", signingKey: fixture.personKey,
		authorizationStore: store, pending: make(map[string]*pendingPersonAuthorization),
	}
	if err := server.persistAuthorizationStateLocked(context.Background()); err != nil {
		t.Fatal(err)
	}
	before, err := store.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	interaction, err := restorePendingInteraction(record.Interaction)
	if err != nil {
		t.Fatal(err)
	}
	server.pending[record.Key] = &pendingPersonAuthorization{
		pendingInteraction: interaction,
		context:            restorePersonAuthorizationContext(record.Context),
		decision:           record.Decision,
	}
	if err := server.persistAuthorizationStateLocked(context.Background()); !errors.Is(err, ErrAuthorizationStateIntegrity) {
		t.Fatalf("person-server pre-persistence corruption error = %v", err)
	}
	after, err := store.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after, before) {
		t.Fatal("person-server corruption reached durable state")
	}
}

func (fixture authorizationStateSemanticFixture) rejectAccessRecordBeforePersistence(
	t *testing.T,
	record accessAuthorizationStateRecord,
) {
	t.Helper()
	store, err := NewMemoryAuthorizationStateStore(16, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	server := &AccessServer{
		identifier: "https://as.example", signingKey: fixture.accessKey,
		authorizationStore: store, pending: make(map[string]*pendingAccessServerAuthorization),
	}
	if err := server.persistAuthorizationStateLocked(context.Background()); err != nil {
		t.Fatal(err)
	}
	before, err := store.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	interaction, err := restorePendingInteraction(record.Interaction)
	if err != nil {
		t.Fatal(err)
	}
	server.pending[record.Key] = &pendingAccessServerAuthorization{
		pendingInteraction: interaction,
		context:            restoreAccessAuthorizationContext(record.Context),
		decision:           record.Decision,
	}
	if err := server.persistAuthorizationStateLocked(context.Background()); !errors.Is(err, ErrAuthorizationStateIntegrity) {
		t.Fatalf("access-server pre-persistence corruption error = %v", err)
	}
	after, err := store.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after, before) {
		t.Fatal("access-server corruption reached durable state")
	}
}

func reopenedAuthorizationStateWithRecords(
	t *testing.T,
	schema string,
	records ...any,
) *FileAuthorizationStateStore {
	t.Helper()
	store, config := openRoleAuthorizationStateStore(t)
	if err := store.Replace(context.Background(), roleAuthorizationSnapshot(t, schema, records...)); err != nil {
		t.Fatal(err)
	}
	return reopenRoleAuthorizationStateStore(t, store, config)
}

func corruptRetainedTokenSignature(t *testing.T, compact string) string {
	t.Helper()
	parts := bytes.Split([]byte(compact), []byte("."))
	if len(parts) != 3 {
		t.Fatalf("compact token parts = %d", len(parts))
	}
	signature, err := base64.RawURLEncoding.DecodeString(string(parts[2]))
	if err != nil || len(signature) == 0 {
		t.Fatalf("decode compact signature = %d bytes, %v", len(signature), err)
	}
	signature[0] ^= 0xff
	parts[2] = []byte(base64.RawURLEncoding.EncodeToString(signature))
	return string(bytes.Join(parts, []byte(".")))
}

type unreconcilableAuthorizationStateStore struct {
	AuthorizationStateStore
	fail         bool
	replaceCalls int
}

type countingProofReplayStore struct {
	calls int
}

type staleThenFreshAuthorizationResolver struct {
	stale        aauth.JWK
	fresh        aauth.JWK
	resolveCalls int
	refreshCalls int
}

type authorizationRoundTripFunc func(*http.Request) (*http.Response, error)

func (function authorizationRoundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func (resolver *staleThenFreshAuthorizationResolver) ResolveKey(
	context.Context,
	string,
	string,
	string,
) (aauth.JWK, error) {
	resolver.resolveCalls++
	return resolver.stale, nil
}

func (resolver *staleThenFreshAuthorizationResolver) RefreshKey(
	context.Context,
	string,
	string,
	string,
) (aauth.JWK, error) {
	resolver.refreshCalls++
	return resolver.fresh, nil
}

func (store *countingProofReplayStore) Consume(context.Context, string, time.Time) error {
	store.calls++
	return nil
}

func newUnreconcilableAuthorizationStateStore(t *testing.T) *unreconcilableAuthorizationStateStore {
	t.Helper()
	memory, err := NewMemoryAuthorizationStateStore(16, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	return &unreconcilableAuthorizationStateStore{AuthorizationStateStore: memory}
}

func (store *unreconcilableAuthorizationStateStore) Load(ctx context.Context) ([]byte, error) {
	if store.fail {
		return nil, errors.New("injected authorization-state load failure")
	}
	return store.AuthorizationStateStore.Load(ctx)
}

func (store *unreconcilableAuthorizationStateStore) Replace(ctx context.Context, body []byte) error {
	store.replaceCalls++
	if store.fail {
		return errors.New("injected authorization-state replace failure")
	}
	return store.AuthorizationStateStore.Replace(ctx, body)
}

func assertAuthorizationRolePoisoned(
	t *testing.T,
	store *unreconcilableAuthorizationStateStore,
	persist func(context.Context) error,
	entryCount func() int,
) {
	t.Helper()
	if err := persist(context.Background()); !errors.Is(err, ErrAuthorizationStateUncertain) {
		t.Fatalf("unreconciled commit error = %v", err)
	}
	if count := entryCount(); count != 0 {
		t.Fatalf("unreconciled role retained %d uncertain entries", count)
	}
	failedCalls := store.replaceCalls
	store.fail = false
	if err := persist(context.Background()); !errors.Is(err, ErrAuthorizationStateUncertain) {
		t.Fatalf("poisoned role retry error = %v", err)
	}
	if store.replaceCalls != failedCalls {
		t.Fatalf("poisoned role attempted another replacement: calls = %d, want %d", store.replaceCalls, failedCalls)
	}
}
