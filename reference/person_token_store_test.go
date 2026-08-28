package reference

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
)

func TestFilePersonTokenStoreReloadsAndRefusesConflictingJTI(t *testing.T) {
	t.Parallel()

	path := t.TempDir() + "/person-tokens.json"
	store, err := NewFilePersonTokenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	record := PersonTokenRecord{
		JTI:          "person-token-1",
		PersonServer: "https://ps.example",
		TokenSHA256:  "first-token-digest",
		Resource:     "https://resource.example",
		Subject:      "directed-person",
		MissionS256:  "mission-digest",
		Tenant:       "example-org",
		ExpiresAt:    time.Date(2026, 8, 28, 16, 0, 0, 0, time.UTC),
		RetainUntil:  time.Date(2026, 8, 28, 16, 5, 0, 0, time.UTC),
	}
	if err := store.Commit(context.Background(), record); err != nil {
		t.Fatal(err)
	}

	reloaded, err := NewFilePersonTokenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	got, err := reloaded.Load(context.Background(), record.PersonServer, record.JTI)
	if err != nil {
		t.Fatal(err)
	}
	if got != record {
		t.Fatalf("reloaded record = %#v, want %#v", got, record)
	}
	if err := reloaded.Commit(context.Background(), record); err != nil {
		t.Fatalf("idempotent commit: %v", err)
	}
	conflict := record
	conflict.TokenSHA256 = "different-token-digest"
	if err := reloaded.Commit(context.Background(), conflict); !errors.Is(err, ErrPersonTokenConflict) {
		t.Fatalf("conflicting commit error = %v", err)
	}
}

func TestFilePersonTokenStoreReloadsAnAdmittedLargeSnapshot(t *testing.T) {
	t.Parallel()

	path := t.TempDir() + "/person-tokens.json"
	records := make(map[string]PersonTokenRecord)
	for index := 0; index < 5_000; index++ {
		record := PersonTokenRecord{
			JTI:          fmt.Sprintf("person-token-%04d", index),
			PersonServer: "https://ps.example",
			TokenSHA256:  "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			Resource:     "https://resource.example",
			Subject:      "directed-person",
			MissionS256:  "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
			Tenant:       "example-org",
			ExpiresAt:    time.Date(2026, 8, 28, 16, 0, 0, 0, time.UTC),
			RetainUntil:  time.Date(2026, 8, 28, 16, 5, 0, 0, time.UTC),
		}
		records[personTokenRecordKey(record.PersonServer, record.JTI)] = record
	}
	body, err := encodePersonTokenState(records)
	if err != nil {
		t.Fatal(err)
	}
	if len(body) <= maxJSONBody || len(body) > maxGovernanceStateBytes {
		t.Fatalf("snapshot bytes = %d, want (%d, %d]", len(body), maxJSONBody, maxGovernanceStateBytes)
	}
	file, err := NewFileGovernanceStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Save(body); err != nil {
		t.Fatal(err)
	}

	store, err := NewFilePersonTokenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	got, err := store.Load(context.Background(), "https://ps.example", "person-token-4999")
	if err != nil {
		t.Fatal(err)
	}
	if got.JTI != "person-token-4999" {
		t.Fatalf("reloaded JTI = %q", got.JTI)
	}
}

func TestPersonTokenIssuanceRefusesSameJTIForDifferentToken(t *testing.T) {
	t.Parallel()

	store, err := NewFilePersonTokenStore(t.TempDir() + "/person-tokens.json")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 28, 18, 0, 0, 0, time.UTC)
	server := &PersonServer{
		identifier:       "https://ps.example",
		signingKey:       newPersonTokenTestKey(t, "ps-key"),
		clock:            aauth.ClockFunc(func() time.Time { return now }),
		newID:            func() string { return "reused-person-token-jti" },
		personTokenStore: store,
		personTokenPolicy: func(context.Context, aauth.PersonTokenRequest) (aauth.PersonTokenDecision, error) {
			return aauth.PersonTokenDecision{
				Subject:  "directed-person",
				Lifetime: time.Hour,
			}, nil
		},
	}
	firstAgentKey := newPersonTokenTestKey(t, "first-agent-key")
	secondAgentKey := newPersonTokenTestKey(t, "second-agent-key")
	if _, _, err := server.issuePersonToken(
		context.Background(),
		"aauth:planner@ap.example",
		firstAgentKey.PublicJWK(),
		now.Add(2*time.Hour).Unix(),
		"https://resource.example",
		"",
		nil,
	); err != nil {
		t.Fatal(err)
	}
	if _, _, err := server.issuePersonToken(
		context.Background(),
		"aauth:planner@ap.example",
		secondAgentKey.PublicJWK(),
		now.Add(2*time.Hour).Unix(),
		"https://resource.example",
		"",
		nil,
	); !errors.Is(err, ErrPersonTokenConflict) {
		t.Fatalf("second issuance error = %v", err)
	}
}

func newPersonTokenTestKey(t *testing.T, id string) aauth.SigningKey {
	t.Helper()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := aauth.NewEd25519SigningKey(id, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return key
}
