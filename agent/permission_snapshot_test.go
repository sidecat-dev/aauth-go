package agent_test

import (
	"context"
	"encoding/json"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/agent"
)

func TestPendingPermissionSnapshotRestoresWithRenewedClient(t *testing.T) {
	fixture := newPermissionFixture(t)
	var initialJTI string
	fixture.initial = func(request *http.Request) (*http.Response, error) {
		verified := verifyProof(t, request, fixture.protocol.resolver, fixture.protocol.clock, aauth.AgentTokenType)
		claims, err := verified.AgentClaims()
		if err != nil {
			t.Fatal(err)
		}
		initialJTI = claims.JTI
		return permissionPendingResponse(request, "7", "pending"), nil
	}
	fixture.poll = func(request *http.Request) (*http.Response, error) {
		verified := verifyProof(t, request, fixture.protocol.resolver, fixture.protocol.clock, aauth.AgentTokenType)
		claims, err := verified.AgentClaims()
		if err != nil {
			t.Fatal(err)
		}
		if initialJTI == "" || claims.JTI == initialJTI || claims.JTI != "renewed-permission-token" {
			t.Fatalf("poll did not use renewed credential: initial=%q poll=%q", initialJTI, claims.JTI)
		}
		if request.Method != http.MethodGet || request.ContentLength != 0 {
			t.Fatalf("poll = %s, body length %d", request.Method, request.ContentLength)
		}
		return jsonResponse(request, http.StatusOK, map[string]any{"permission": "granted"}), nil
	}
	pending := requestPendingPermission(t, fixture)
	snapshot, err := pending.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "permission.json")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	pending = agent.PendingPermission{}
	data, err = os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var stored agent.PendingPermissionSnapshot
	if err := json.Unmarshal(data, &stored); err != nil {
		t.Fatal(err)
	}
	renewed, err := aauth.MintAgentToken(fixture.protocol.agentProviderID, fixture.protocol.agentProviderKey,
		aauth.AgentTokenRequest{Agent: fixture.protocol.agentID, PersonServer: fixture.protocol.personServerID,
			PublicKey: fixture.protocol.agentKey.PublicJWK(), Lifetime: time.Hour}, fixture.protocol.now, "renewed-permission-token")
	if err != nil {
		t.Fatal(err)
	}
	if renewed == fixture.protocol.agentToken {
		t.Fatal("renewal reused the original token")
	}
	client, err := agent.New(context.Background(), agent.Config{Identifier: fixture.protocol.agentID, SigningKey: fixture.protocol.agentKey,
		AgentToken: renewed, KeyResolver: fixture.protocol.resolver, Clock: fixture.protocol.clock,
		HTTPClient: &http.Client{Transport: roundTripperFunc(fixture.roundTrip)}})
	if err != nil {
		t.Fatal(err)
	}
	pending, err = client.RestorePendingPermission(context.Background(), stored)
	if err != nil {
		t.Fatal(err)
	}
	if pending.RetryAfter() != 7*time.Second || fixture.initialCalls != 1 || fixture.pollCalls != 0 {
		t.Fatalf("restore: retry=%s, posts=%d polls=%d", pending.RetryAfter(), fixture.initialCalls, fixture.pollCalls)
	}
	result, err := client.PollPermission(context.Background(), pending)
	if err != nil {
		t.Fatal(err)
	}
	decision, ok := result.Decision()
	if !ok || decision.Permission() != aauth.PermissionGranted || fixture.initialCalls != 1 || fixture.pollCalls != 1 {
		t.Fatalf("resume: decision=%v posts=%d polls=%d", decision.Permission(), fixture.initialCalls, fixture.pollCalls)
	}
}

func TestRestorePendingPermissionRejectsInvalidStateBeforePoll(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*agent.PendingPermissionSnapshot)
	}{
		{"zero", func(s *agent.PendingPermissionSnapshot) { *s = agent.PendingPermissionSnapshot{} }},
		{"person server", func(s *agent.PendingPermissionSnapshot) { s.PersonServer = "https://other.example" }},
		{"provider", func(s *agent.PendingPermissionSnapshot) { s.AgentProvider = "https://other.example" }},
		{"agent", func(s *agent.PendingPermissionSnapshot) { s.Agent = "aauth:other@ap.example" }},
		{"key", func(s *agent.PendingPermissionSnapshot) { s.AgentJKT = "other" }},
		{"location origin", func(s *agent.PendingPermissionSnapshot) { s.Location = "https://other.example/pending" }},
		{"relative location", func(s *agent.PendingPermissionSnapshot) { s.Location = "/pending" }},
		{"negative retry", func(s *agent.PendingPermissionSnapshot) { s.RetryAfter = -1 }},
		{"overflow retry", func(s *agent.PendingPermissionSnapshot) { s.RetryAfter = math.MaxInt64 }},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newPermissionFixture(t)
			fixture.initial = func(request *http.Request) (*http.Response, error) {
				return permissionPendingResponse(request, "1", "pending"), nil
			}
			snapshot, err := requestPendingPermission(t, fixture).Snapshot()
			if err != nil {
				t.Fatal(err)
			}
			test.change(&snapshot)
			if _, err := fixture.client.RestorePendingPermission(context.Background(), snapshot); err == nil {
				t.Fatal("invalid continuation restored")
			}
			if fixture.initialCalls != 1 || fixture.pollCalls != 0 {
				t.Fatal("restoration dispatched a permission request")
			}
		})
	}
	t.Run("metadata changed", func(t *testing.T) {
		fixture := newPermissionFixture(t)
		fixture.initial = func(request *http.Request) (*http.Response, error) {
			return permissionPendingResponse(request, "1", "pending"), nil
		}
		snapshot, err := requestPendingPermission(t, fixture).Snapshot()
		if err != nil {
			t.Fatal(err)
		}
		fixture.permissionEndpoint = "https://other.example/permission"
		if _, err := fixture.client.RestorePendingPermission(context.Background(), snapshot); err == nil {
			t.Fatal("changed metadata accepted")
		}
		if fixture.pollCalls != 0 {
			t.Fatal("restoration polled")
		}
	})
}
