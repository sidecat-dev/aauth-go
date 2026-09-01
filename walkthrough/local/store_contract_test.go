package main

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/personserver"
	personstoretest "gitlab.com/sidecat-dev/aauth-go/personserver/storetest"
	"gitlab.com/sidecat-dev/aauth-go/resource"
	resourcestoretest "gitlab.com/sidecat-dev/aauth-go/resource/storetest"
)

func TestPermissionStoreContract(t *testing.T) {
	personstoretest.RunPermission(t, personstoretest.PermissionContract{
		New: func(t testing.TB) personserver.PermissionStore {
			return newPermissionStore(filepath.Join(t.TempDir(), "permissions.json"))
		},
	})
}

func TestAgentTokenRevocationStoreContract(t *testing.T) {
	resourcestoretest.RunAgentTokenRevocation(t, resourcestoretest.AgentTokenRevocationContract{
		New: func(t testing.TB) resource.AgentTokenRevocationStore {
			return newRevocationStore(filepath.Join(t.TempDir(), "revocations.json"))
		},
	})
}

func TestWalkthroughStoresSurviveReopen(t *testing.T) {
	stateDir := t.TempDir()
	created := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	permission := personserver.PermissionRecord{
		ID: "permission-1", PersonServer: personOrigin, AgentProvider: agentOrigin,
		Agent: agentID, ConfirmationThumbprint: "thumbprint", AgentExpiresAt: created.Add(time.Hour),
		Action: "notes.create", Description: "Create one note", State: personserver.PermissionStateGranted,
		Decision:  personserver.PermissionDecision{Permission: aauth.PermissionGranted},
		CreatedAt: created, DecidedAt: created,
	}
	permissionsPath := filepath.Join(stateDir, "permissions.json")
	if err := newPermissionStore(permissionsPath).CreatePermission(context.Background(), permission); err != nil {
		t.Fatal(err)
	}
	loaded, err := newPermissionStore(permissionsPath).LoadPermission(context.Background(), permission.ID, created)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.ID != permission.ID || loaded.Decision.Permission != aauth.PermissionGranted {
		t.Fatalf("reopened permission = %#v", loaded)
	}

	reference := aauth.TokenReference{Issuer: agentOrigin, JTI: "agent-token-1"}
	revocationsPath := filepath.Join(stateDir, "revocations.json")
	if err := newRevocationStore(revocationsPath).Revoke(context.Background(), reference); err != nil {
		t.Fatal(err)
	}
	if revoked, err := newRevocationStore(revocationsPath).IsRevoked(context.Background(), reference); err != nil || !revoked {
		t.Fatalf("reopened revocation = %t, %v", revoked, err)
	}

	consequencesPath := filepath.Join(stateDir, "consequences.json")
	result, replayed, count, err := newConsequenceStore(consequencesPath).apply("request-1")
	if err != nil || result != "note-1" || replayed || count != 1 {
		t.Fatalf("first consequence = %q, %t, %d, %v", result, replayed, count, err)
	}
	result, replayed, count, err = newConsequenceStore(consequencesPath).apply("request-1")
	if err != nil || result != "note-1" || !replayed || count != 1 {
		t.Fatalf("reopened consequence = %q, %t, %d, %v", result, replayed, count, err)
	}
}
