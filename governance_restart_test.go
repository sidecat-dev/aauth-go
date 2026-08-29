package aauth_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/reference"
)

func TestPersonServerGovernanceSurvivesRestart(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 27, 18, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	apKey := testSigningKey(t, "ap-key")
	psKey := testSigningKey(t, "ps-key")
	agentKey := testSigningKey(t, "agent-key")
	ap, err := reference.NewAgentProvider(reference.AgentProviderConfig{
		Identifier: "https://ap.example",
		SigningKey: apKey,
		Clock:      clock,
		NewID:      sequentialIDs("agent-token"),
	})
	if err != nil {
		t.Fatal(err)
	}
	agentToken, err := ap.IssueAgentToken(aauth.AgentTokenRequest{
		Agent:        "aauth:operator@ap.example",
		PersonServer: "https://ps.example",
		PublicKey:    agentKey.PublicJWK(),
		Lifetime:     2 * time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}

	client := &http.Client{}
	resolver, err := signaturekey.NewHTTPKeyResolver(signaturekey.HTTPKeyResolverConfig{
		Client: client,
		Clock:  clock,
		Admit: func(_ context.Context, endpoint string) error {
			for _, allowed := range []string{
				"https://ap.example/",
				"https://ps.example/",
			} {
				if strings.HasPrefix(endpoint, allowed) {
					return nil
				}
			}
			return fmt.Errorf("endpoint outside trust boundary: %s", endpoint)
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	statePath := filepath.Join(t.TempDir(), "person-governance.json")
	fileStore, err := reference.NewFileGovernanceStore(statePath)
	if err != nil {
		t.Fatal(err)
	}
	store := &toggleGovernanceStore{inner: fileStore}
	config := reference.PersonServerConfig{
		AuthorizationStore:   testAuthorizationStateStore(t),
		Identifier:           "https://ps.example",
		SigningKey:           psKey,
		KeyResolver:          resolver,
		Clock:                clock,
		NewID:                sequentialIDs(),
		GovernanceStore:      store,
		PersonTokenStore:     testPersonTokenStore(t),
		MissionIssuanceStore: testMissionIssuanceStore(t),
		PersonTokenPolicy:    testPersonTokenPolicy,
		CurrentMissionPolicy: func(_ context.Context, evaluation aauth.MissionEvaluation) (aauth.MissionDecision, error) {
			proposal := evaluation.Proposal
			return aauth.MissionDecision{
				Description: proposal.Description,
				Tools:       proposal.Tools,
			}, nil
		},
		AuthorizationPolicy: func(_ context.Context, request aauth.AuthorizationRequest) (aauth.AuthorizationDecision, error) {
			return aauth.AuthorizationDecision{Subject: "unused", Scope: request.Scope}, nil
		},
		PermissionPolicy: func(_ context.Context, _ aauth.PermissionEvaluation) (aauth.PermissionDecision, error) {
			return aauth.PermissionDecision{
				Permission: aauth.PermissionGranted,
				DecidedBy:  "operator",
			}, nil
		},
		PermissionInteractionRequired: func(_ context.Context, input aauth.PermissionEvaluation) (bool, error) {
			return input.Request.Action == "message.send", nil
		},
	}
	newPersonServer := func() *reference.PersonServer {
		t.Helper()
		server, err := reference.NewPersonServer(config)
		if err != nil {
			t.Fatal(err)
		}
		return server
	}

	personServer := newPersonServer()
	var personHandler http.Handler = personServer.Handler()
	gateway := newLogicalGateway(t, map[string]http.Handler{
		"ap.example": ap.Handler(),
		"ps.example": http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			personHandler.ServeHTTP(response, request)
		}),
	})
	defer gateway.Close()
	client.Transport = gateway.Client().Transport
	agent, err := reference.NewAgent(reference.AgentConfig{
		AuthorizationStore: testAuthorizationStateStore(t),
		Identifier:         "aauth:operator@ap.example",
		SigningKey:         agentKey,
		AgentToken:         agentToken,
		KeyResolver:        resolver,
		HTTPClient:         client,
		Clock:              clock,
	})
	if err != nil {
		t.Fatal(err)
	}

	mission, err := agent.CreateMission(
		context.Background(),
		"https://ps.example/mission",
		aauth.MissionProposal{
			Description: "Prepare and report a recoverable change.",
			Tools: []aauth.Tool{{
				Name:        "filesystem.read",
				Description: "Read source files.",
			}},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	permissionRequest := aauth.PermissionRequest{
		Action:      "message.send",
		Description: "Report the completed change.",
		Mission:     &mission.Reference,
	}
	pendingResult, err := agent.RequestPermission(
		context.Background(),
		"https://ps.example/permission",
		permissionRequest,
	)
	if err != nil {
		t.Fatal(err)
	}
	if pendingResult.Pending == nil {
		t.Fatalf("permission = %#v, want pending", pendingResult)
	}
	pending := pendingResult.Pending
	history := personServer.PermissionHistory()
	if len(history) != 1 ||
		history[0].Sequence != 1 ||
		history[0].PendingID != pending.ID ||
		history[0].Proof == nil ||
		len(history[0].Response) != 0 {
		t.Fatalf("initial permission history = %#v", history)
	}
	history[0].Request[0] ^= 1
	history[0].Proof.Signature = "mutated"
	history = personServer.PermissionHistory()
	if history[0].Proof.Signature == "mutated" || history[0].Request[0] != '{' {
		t.Fatal("permission history exposed mutable custody")
	}

	info, err := os.Stat(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("governance state mode = %o, want 600", info.Mode().Perm())
	}

	personServer = newPersonServer()
	personHandler = personServer.Handler()
	restored, err := personServer.MissionSnapshot(mission.Reference)
	if err != nil {
		t.Fatal(err)
	}
	if restored.Status != aauth.MissionActive ||
		len(restored.Log) != 1 ||
		restored.Log[0].Kind != aauth.MissionLogPermissionRequest ||
		restored.Log[0].Proof == nil {
		t.Fatalf("restored mission = %#v", restored)
	}
	history = personServer.PermissionHistory()
	if len(history) != 1 ||
		history[0].PendingID != pending.ID ||
		history[0].Proof == nil {
		t.Fatalf("restored permission history = %#v", history)
	}
	waiting, err := agent.PollPermission(context.Background(), pending)
	if err != nil {
		t.Fatal(err)
	}
	if waiting.Pending == nil || waiting.Pending.ID != pending.ID {
		t.Fatalf("restored pending permission = %#v", waiting)
	}

	interaction, err := client.Get(
		pending.Requirement.InteractionURL +
			"?code=" + pending.Requirement.InteractionCode,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer interaction.Body.Close()
	if interaction.StatusCode != http.StatusOK {
		t.Fatalf("restored interaction status = %d", interaction.StatusCode)
	}
	if err := personServer.ApprovePermission(context.Background(), pending.ID); err != nil {
		t.Fatal(err)
	}
	approved, err := agent.PollPermission(context.Background(), pending)
	if err != nil {
		t.Fatal(err)
	}
	if approved.Decision == nil ||
		approved.Decision.Permission != aauth.PermissionGranted {
		t.Fatalf("restored permission decision = %#v", approved)
	}
	history = personServer.PermissionHistory()
	if len(history) != 1 ||
		history[0].DecidedBy != "operator" ||
		len(history[0].Response) == 0 {
		t.Fatalf("terminal permission history = %#v", history)
	}

	now = now.Add(time.Second)
	if err := agent.RecordAudit(
		context.Background(),
		"https://ps.example/audit",
		aauth.AuditRequest{
			Mission: mission.Reference,
			Action:  "message.send",
			Result:  map[string]any{"status": "completed"},
		},
	); err != nil {
		t.Fatal(err)
	}

	personServer = newPersonServer()
	personHandler = personServer.Handler()
	restored, err = personServer.MissionSnapshot(mission.Reference)
	if err != nil {
		t.Fatal(err)
	}
	if len(restored.Log) != 3 ||
		restored.Log[1].Kind != aauth.MissionLogPermissionDecision ||
		restored.Log[2].Kind != aauth.MissionLogAudit ||
		restored.Log[2].Proof == nil {
		t.Fatalf("mission after second restart = %#v", restored)
	}
	if _, err := agent.PollPermission(context.Background(), pending); err == nil {
		t.Fatal("served permission continuation revived after restart")
	} else {
		assertProblemCode(t, err, http.StatusGone, "gone")
	}

	const concurrentAuditCount = 8
	auditErrors := make(chan error, concurrentAuditCount)
	var audits sync.WaitGroup
	for index := 0; index < concurrentAuditCount; index++ {
		index := index
		audits.Add(1)
		go func() {
			defer audits.Done()
			auditErrors <- agent.RecordAudit(
				context.Background(),
				"https://ps.example/audit",
				aauth.AuditRequest{
					Mission: mission.Reference,
					Action:  fmt.Sprintf("concurrent.audit.%d", index),
					Result:  map[string]any{"index": index},
				},
			)
		}()
	}
	audits.Wait()
	close(auditErrors)
	for err := range auditErrors {
		if err != nil {
			t.Fatal(err)
		}
	}
	personServer = newPersonServer()
	personHandler = personServer.Handler()
	afterConcurrentAudit, err := personServer.MissionSnapshot(mission.Reference)
	if err != nil {
		t.Fatal(err)
	}
	expectedMissionLogLength := 3 + concurrentAuditCount
	if len(afterConcurrentAudit.Log) != expectedMissionLogLength {
		t.Fatalf("concurrent durable log length = %d", len(afterConcurrentAudit.Log))
	}
	for index, entry := range afterConcurrentAudit.Log {
		if entry.Sequence != uint64(index+1) {
			t.Fatalf("concurrent durable log sequence %d = %d", index, entry.Sequence)
		}
	}

	// The core draft gives audit requests no stable request identifier. If the
	// server commits an audit but its 201 is lost, a freshly signed retry is
	// indistinguishable from a second legitimate occurrence of the same action.
	ambiguousAudit := aauth.AuditRequest{
		Mission: mission.Reference,
		Action:  "external.notify",
		Result:  map[string]any{"status": "completed"},
	}
	baseTransport := client.Transport
	client.Transport = &dropFirstResponseTransport{
		base:   baseTransport,
		target: "/audit",
	}
	if err := agent.RecordAudit(
		context.Background(),
		"https://ps.example/audit",
		ambiguousAudit,
	); err == nil {
		t.Fatal("lost audit acknowledgment was reported as success")
	}
	expectedMissionLogLength++
	client.Transport = baseTransport
	now = now.Add(time.Second)
	if err := agent.RecordAudit(
		context.Background(),
		"https://ps.example/audit",
		ambiguousAudit,
	); err != nil {
		t.Fatal(err)
	}
	expectedMissionLogLength++
	ambiguousSnapshot, err := personServer.MissionSnapshot(mission.Reference)
	if err != nil {
		t.Fatal(err)
	}
	firstAmbiguous := ambiguousSnapshot.Log[len(ambiguousSnapshot.Log)-2]
	secondAmbiguous := ambiguousSnapshot.Log[len(ambiguousSnapshot.Log)-1]
	if firstAmbiguous.Kind != aauth.MissionLogAudit ||
		secondAmbiguous.Kind != aauth.MissionLogAudit ||
		!strings.Contains(string(firstAmbiguous.Request), `"action":"external.notify"`) ||
		!strings.Contains(string(secondAmbiguous.Request), `"action":"external.notify"`) ||
		firstAmbiguous.Proof == nil ||
		secondAmbiguous.Proof == nil ||
		firstAmbiguous.Proof.ReplayKey == secondAmbiguous.Proof.ReplayKey {
		t.Fatalf(
			"ambiguous audit retry evidence = %#v / %#v",
			firstAmbiguous,
			secondAmbiguous,
		)
	}

	now = now.Add(time.Second)
	failedAudit := aauth.AuditRequest{
		Mission: mission.Reference,
		Action:  "filesystem.checkpoint",
		Result:  map[string]any{"status": "completed"},
	}
	store.setFail(true)
	if err := agent.RecordAudit(
		context.Background(),
		"https://ps.example/audit",
		failedAudit,
	); err == nil {
		t.Fatal("audit succeeded without durable custody")
	} else {
		assertProblemCode(t, err, http.StatusInternalServerError, "server_error")
	}
	afterFailedAudit, err := personServer.MissionSnapshot(mission.Reference)
	if err != nil {
		t.Fatal(err)
	}
	if len(afterFailedAudit.Log) != expectedMissionLogLength {
		t.Fatal("failed audit changed the mission log or consumed its replay proof")
	}
	store.setFail(false)
	if err := agent.RecordAudit(
		context.Background(),
		"https://ps.example/audit",
		failedAudit,
	); err != nil {
		t.Fatalf("retry audit after definite save failure: %v", err)
	}
	expectedMissionLogLength++

	failedRequest := aauth.PermissionRequest{Action: "filesystem.write"}
	store.setFail(true)
	if _, err := agent.RequestPermission(
		context.Background(),
		"https://ps.example/permission",
		failedRequest,
	); err == nil {
		t.Fatal("permission succeeded without durable custody")
	} else {
		assertProblemCode(t, err, http.StatusInternalServerError, "server_error")
	}
	if got := len(personServer.PermissionHistory()); got != 1 {
		t.Fatalf("failed permission changed in-memory history length to %d", got)
	}
	store.setFail(false)
	if authorization, err := agent.RequestPermission(
		context.Background(),
		"https://ps.example/permission",
		failedRequest,
	); err != nil {
		t.Fatalf("retry after definite save failure: %v", err)
	} else if authorization.Decision == nil ||
		authorization.Decision.Permission != aauth.PermissionGranted {
		t.Fatalf("retry permission = %#v", authorization)
	}
	history = personServer.PermissionHistory()
	if len(history) != 2 ||
		history[1].PendingID != "" ||
		len(history[1].Response) == 0 {
		t.Fatalf("missionless permission history = %#v", history)
	}
	now = now.Add(2 * signaturekey.DefaultSignatureWindow)
	if _, err := agent.RequestPermission(
		context.Background(),
		"https://ps.example/permission",
		aauth.PermissionRequest{Action: "governance.replay-prune"},
	); err != nil {
		t.Fatal(err)
	}
	personServer = newPersonServer()
	personHandler = personServer.Handler()
	if got := len(personServer.PermissionHistory()); got != 3 {
		t.Fatalf("permission history after replay expiry and restart = %d", got)
	}

	store.setFail(true)
	if err := personServer.TerminateMission(mission.Reference); err == nil {
		t.Fatal("mission termination succeeded without durable custody")
	}
	afterFailedSave, err := personServer.MissionSnapshot(mission.Reference)
	if err != nil {
		t.Fatal(err)
	}
	if afterFailedSave.Status != aauth.MissionActive ||
		len(afterFailedSave.Log) != expectedMissionLogLength {
		t.Fatalf("failed persistence changed in-memory mission = %#v", afterFailedSave)
	}
	store.setFail(false)
	personServer = newPersonServer()
	personHandler = personServer.Handler()
	afterFailedSave, err = personServer.MissionSnapshot(mission.Reference)
	if err != nil {
		t.Fatal(err)
	}
	if afterFailedSave.Status != aauth.MissionActive ||
		len(afterFailedSave.Log) != expectedMissionLogLength {
		t.Fatalf("failed persistence changed durable mission = %#v", afterFailedSave)
	}
	store.setUncertain(true)
	if err := personServer.TerminateMission(mission.Reference); !errors.Is(
		err,
		reference.ErrGovernanceStateUncertain,
	) {
		t.Fatalf("uncertain termination error = %v", err)
	}
	afterUncertainSave, err := personServer.MissionSnapshot(mission.Reference)
	if err != nil {
		t.Fatal(err)
	}
	if afterUncertainSave.Status != aauth.MissionTerminated ||
		len(afterUncertainSave.Log) != expectedMissionLogLength+1 {
		t.Fatalf("uncertain published state was rolled back = %#v", afterUncertainSave)
	}
	store.setUncertain(false)

	personServer = newPersonServer()
	personHandler = personServer.Handler()
	restored, err = personServer.MissionSnapshot(mission.Reference)
	if err != nil {
		t.Fatal(err)
	}
	if restored.Status != aauth.MissionTerminated ||
		len(restored.Log) != expectedMissionLogLength+1 ||
		restored.Log[len(restored.Log)-1].Kind != aauth.MissionLogTermination {
		t.Fatalf("terminated mission after restart = %#v", restored)
	}
	now = now.Add(time.Second)
	_, err = agent.RequestPermission(
		context.Background(),
		"https://ps.example/permission",
		aauth.PermissionRequest{
			Action:  "message.send",
			Mission: &mission.Reference,
		},
	)
	assertMissionTerminated(t, err)

	wrongServerConfig := config
	wrongServerConfig.Identifier = "https://other-ps.example"
	if _, err := reference.NewPersonServer(wrongServerConfig); err == nil {
		t.Fatal("person server loaded governance state owned by another server")
	}

	stateBody, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	semanticallyCorruptGovernancePermissionLink(t, statePath, stateBody)
	if _, err := reference.NewPersonServer(config); err == nil {
		t.Fatal("person server accepted semantically inconsistent governance custody")
	}
	if err := os.WriteFile(statePath, stateBody, 0o600); err != nil {
		t.Fatal(err)
	}
	stateBody[len(stateBody)/2] ^= 1
	if err := os.WriteFile(statePath, stateBody, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := reference.NewPersonServer(config); err == nil {
		t.Fatal("person server accepted a corrupted valid governance snapshot")
	}
}

func semanticallyCorruptGovernancePermissionLink(
	t *testing.T,
	path string,
	envelopeBody []byte,
) {
	t.Helper()
	var envelope struct {
		Schema      string          `json:"schema"`
		StateSHA256 string          `json:"state_sha256"`
		State       json.RawMessage `json:"state"`
	}
	if err := json.Unmarshal(envelopeBody, &envelope); err != nil {
		t.Fatal(err)
	}
	var state map[string]any
	if err := json.Unmarshal(envelope.State, &state); err != nil {
		t.Fatal(err)
	}
	permissions, ok := state["permissions"].([]any)
	if !ok || len(permissions) == 0 {
		t.Fatal("valid governance fixture has no permission records")
	}
	first, ok := permissions[0].(map[string]any)
	if !ok {
		t.Fatal("valid governance permission record has the wrong shape")
	}
	first["pending_id"] = "AAAAAAAAAAAAAAAAAAAAAA"
	stateBody, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(stateBody)
	envelope.State = stateBody
	envelope.StateSHA256 = hex.EncodeToString(digest[:])
	corruptBody, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, corruptBody, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestPersonServerRejectsCorruptGovernanceState(t *testing.T) {
	t.Parallel()

	for name, body := range map[string][]byte{
		"empty":  {},
		"schema": []byte(`{"schema":"broken"}`),
	} {
		t.Run(name, func(t *testing.T) {
			statePath := filepath.Join(t.TempDir(), "person-governance.json")
			if err := os.WriteFile(statePath, body, 0o600); err != nil {
				t.Fatal(err)
			}
			store, err := reference.NewFileGovernanceStore(statePath)
			if err != nil {
				t.Fatal(err)
			}
			_, err = reference.NewPersonServer(reference.PersonServerConfig{
				AuthorizationStore:   testAuthorizationStateStore(t),
				Identifier:           "https://ps.example",
				SigningKey:           testSigningKey(t, "ps-key"),
				KeyResolver:          rejectingKeyResolver{},
				Clock:                aauth.ClockFunc(time.Now),
				NewID:                sequentialIDs(),
				GovernanceStore:      store,
				PersonTokenStore:     testPersonTokenStore(t),
				MissionIssuanceStore: testMissionIssuanceStore(t),
				PersonTokenPolicy:    testPersonTokenPolicy,
				CurrentMissionPolicy: func(context.Context, aauth.MissionEvaluation) (aauth.MissionDecision, error) {
					return aauth.MissionDecision{}, nil
				},
				AuthorizationPolicy: func(context.Context, aauth.AuthorizationRequest) (aauth.AuthorizationDecision, error) {
					return aauth.AuthorizationDecision{}, nil
				},
			})
			if err == nil {
				t.Fatal("person server accepted corrupt governance custody")
			}
		})
	}
}

func TestFileGovernanceStoreRejectsLoosePermissions(t *testing.T) {
	t.Parallel()

	statePath := filepath.Join(t.TempDir(), "person-governance.json")
	if err := os.WriteFile(statePath, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(statePath, 0o644); err != nil {
		t.Fatal(err)
	}
	store, err := reference.NewFileGovernanceStore(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(); err == nil {
		t.Fatal("governance store loaded a group/world-readable state file")
	}
}

type rejectingKeyResolver struct{}

func (rejectingKeyResolver) ResolveKey(
	context.Context,
	string,
	string,
	string,
) (jose.JWK, error) {
	return jose.JWK{}, fmt.Errorf("unexpected key resolution")
}

type toggleGovernanceStore struct {
	inner     reference.GovernanceStore
	mu        sync.Mutex
	fail      bool
	uncertain bool
}

type dropFirstResponseTransport struct {
	base    http.RoundTripper
	target  string
	mu      sync.Mutex
	dropped bool
}

func (transport *dropFirstResponseTransport) RoundTrip(
	request *http.Request,
) (*http.Response, error) {
	response, err := transport.base.RoundTrip(request)
	if err != nil {
		return response, err
	}
	transport.mu.Lock()
	drop := !transport.dropped && request.URL.Path == transport.target
	if drop {
		transport.dropped = true
	}
	transport.mu.Unlock()
	if !drop {
		return response, nil
	}
	_, _ = io.Copy(io.Discard, response.Body)
	_ = response.Body.Close()
	return nil, errors.New("injected response loss after server commit")
}

func (store *toggleGovernanceStore) Load() ([]byte, error) {
	return store.inner.Load()
}

func (store *toggleGovernanceStore) Save(body []byte) error {
	store.mu.Lock()
	fail := store.fail
	uncertain := store.uncertain
	store.mu.Unlock()
	if fail {
		return fmt.Errorf("injected governance save failure")
	}
	if err := store.inner.Save(body); err != nil {
		return err
	}
	if uncertain {
		return fmt.Errorf("%w: injected directory sync uncertainty", reference.ErrGovernanceStateUncertain)
	}
	return nil
}

func (store *toggleGovernanceStore) setUncertain(uncertain bool) {
	store.mu.Lock()
	store.uncertain = uncertain
	store.mu.Unlock()
}

func (store *toggleGovernanceStore) setFail(fail bool) {
	store.mu.Lock()
	store.fail = fail
	store.mu.Unlock()
}
