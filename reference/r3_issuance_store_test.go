package reference

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
)

func TestFileR3PerCallIssuanceStoreRejectsUnsafeDirectoryPermissions(t *testing.T) {
	t.Parallel()

	directory := filepath.Join(t.TempDir(), "r3-issuances")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(directory, 0o707); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenFileR3PerCallIssuanceStore(FileR3PerCallIssuanceStoreConfig{
		Directory: directory,
		Clock:     aauth.ClockFunc(time.Now),
	}); err == nil {
		t.Fatal("R3 issuance store accepted a world-writable custody directory")
	}
}

func TestFileR3PerCallIssuanceStoreCommitsOneExactTokenAcrossRestart(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 2, 20, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	config := FileR3PerCallIssuanceStoreConfig{
		Directory:  privateR3TestDirectory(t),
		Clock:      clock,
		MaxRecords: 4,
	}
	store, err := OpenFileR3PerCallIssuanceStore(config)
	if err != nil {
		t.Fatal(err)
	}
	approvedOperation := aauth.R3OperationSet{
		Vocabulary: aauth.R3VocabularyMCP,
		Operations: []json.RawMessage{json.RawMessage(`{"tool":"send_message"}`)},
	}
	mission := aauth.MissionReference{
		Approver: "https://ps.example",
		S256:     aauth.R3S256([]byte("approved mission")),
	}
	candidates := []R3PerCallIssuance{
		{
			Resource:                 "https://resource.example",
			ResourceTokenID:          "proposal-resource-token",
			ResourceTokenFingerprint: "fingerprint-one",
			AuthToken:                "compact-auth-token-one",
			ExpiresAt:                now.Add(5 * time.Minute),
			Audit: aauth.R3AuditRecord{
				R3URI:           "https://resource.example/r3/proposals/proposal-hash",
				R3S256:          "proposal-hash",
				Agent:           "aauth:messenger@ap.example",
				Resource:        "https://resource.example",
				ResourceTokenID: "proposal-resource-token",
				TokenID:         "per-call-auth-token-one",
				Mission:         &mission,
				R3Granted:       &approvedOperation,
				IssuedAt:        now,
			},
		},
		{
			Resource:                 "https://resource.example",
			ResourceTokenID:          "proposal-resource-token",
			ResourceTokenFingerprint: "fingerprint-one",
			AuthToken:                "compact-auth-token-two",
			ExpiresAt:                now.Add(5 * time.Minute),
			Audit: aauth.R3AuditRecord{
				R3URI:           "https://resource.example/r3/proposals/proposal-hash",
				R3S256:          "proposal-hash",
				Agent:           "aauth:messenger@ap.example",
				Resource:        "https://resource.example",
				ResourceTokenID: "proposal-resource-token",
				TokenID:         "per-call-auth-token-two",
				Mission:         &mission,
				R3Granted:       &approvedOperation,
				IssuedAt:        now,
			},
		},
	}

	results := make(chan R3PerCallIssuance, 2)
	errorsSeen := make(chan error, 2)
	start := make(chan struct{})
	var group sync.WaitGroup
	for _, candidate := range candidates {
		candidate := candidate
		group.Add(1)
		go func() {
			defer group.Done()
			<-start
			committed, commitErr := store.Commit(context.Background(), candidate)
			results <- committed
			errorsSeen <- commitErr
		}()
	}
	close(start)
	group.Wait()
	close(results)
	close(errorsSeen)
	for err := range errorsSeen {
		if err != nil {
			t.Fatal(err)
		}
	}
	var exactToken string
	var exactTokenID string
	for result := range results {
		if exactToken == "" {
			exactToken = result.AuthToken
			exactTokenID = result.Audit.TokenID
		}
		if result.AuthToken != exactToken || result.Audit.TokenID != exactTokenID {
			t.Fatalf("concurrent commits returned different issuances: %#v", result)
		}
	}

	restarted, err := OpenFileR3PerCallIssuanceStore(config)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := restarted.Load(
		context.Background(),
		"https://resource.example",
		"proposal-resource-token",
		"fingerprint-one",
	)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.AuthToken != exactToken || loaded.Audit.TokenID != exactTokenID {
		t.Fatalf("restarted issuance = %#v", loaded)
	}
	if loaded.Audit.Mission == nil || *loaded.Audit.Mission != mission ||
		loaded.Audit.R3Granted == nil || !loaded.Audit.R3Granted.Equal(approvedOperation) ||
		loaded.Audit.R3Conditional != nil {
		t.Fatalf("restarted issuance lost approved semantics: %#v", loaded.Audit)
	}
	if _, err := restarted.Load(
		context.Background(),
		"https://resource.example",
		"proposal-resource-token",
		"different-fingerprint",
	); !errors.Is(err, ErrR3IssuanceCollision) {
		t.Fatalf("resource-token fingerprint collision error = %v", err)
	}
}
