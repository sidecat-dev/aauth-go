package reference

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"testing"
)

func TestFileR3PerCallStoreRecoversPendingAndCompleteExecution(t *testing.T) {
	path := t.TempDir() + "/r3-per-call.json"
	operation := json.RawMessage(`{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"delete_record"}]}`)
	execution, err := NewR3PerCallExecution(
		"https://as.example", "auth-token-7",
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", operation, 1_800_000_000,
	)
	if err != nil {
		t.Fatal(err)
	}
	store, err := NewFileR3PerCallStore(path)
	if err != nil {
		t.Fatal(err)
	}
	pending, acquired, err := store.Claim(context.Background(), execution)
	if err != nil || !acquired || pending.State != "pending" || pending.Result != nil {
		t.Fatalf("pending = %#v, acquired=%t, %v", pending, acquired, err)
	}
	if replay, acquired, err := store.Claim(context.Background(), execution); err != nil || acquired || replay.State != "pending" {
		t.Fatalf("concurrent pending replay = %#v, acquired=%t, %v", replay, acquired, err)
	}

	reopened, err := NewFileR3PerCallStore(path)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := reopened.Load(context.Background(), execution.Key)
	if err != nil || loaded.State != "pending" {
		t.Fatalf("reopened pending = %#v, %v", loaded, err)
	}
	if replay, acquired, err := reopened.Claim(context.Background(), execution); err != nil || !acquired || replay.State != "pending" {
		t.Fatalf("reopened pending recovery = %#v, acquired=%t, %v", replay, acquired, err)
	}
	result := R3PerCallResult{Status: 200, ContentType: "application/json", Body: []byte(`{"deleted":"record-7"}`)}
	complete, err := reopened.Complete(context.Background(), execution.Key, result)
	if err != nil || complete.State != "complete" || complete.Result == nil {
		t.Fatalf("complete = %#v, %v", complete, err)
	}
	if replay, err := reopened.Complete(context.Background(), execution.Key, result); err != nil || replay.State != "complete" {
		t.Fatalf("exact complete replay = %#v, %v", replay, err)
	}
	if replay, acquired, err := reopened.Claim(context.Background(), execution); err != nil || acquired || replay.State != "complete" {
		t.Fatalf("complete result claim = %#v, acquired=%t, %v", replay, acquired, err)
	}

	reopened, err = NewFileR3PerCallStore(path)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err = reopened.Load(context.Background(), execution.Key)
	if err != nil || loaded.Result == nil || string(loaded.Result.Body) != string(result.Body) {
		t.Fatalf("reopened complete = %#v, %v", loaded, err)
	}

	changed := execution
	changed.AuthTokenID = "substituted-token"
	if _, _, err := reopened.Claim(context.Background(), changed); err == nil {
		t.Fatal("execution with a substituted identity and stale key was accepted")
	}
	if _, err := reopened.Complete(context.Background(), execution.Key, R3PerCallResult{
		Status: 200, ContentType: "application/json", Body: []byte(`{"deleted":"other"}`),
	}); !errors.Is(err, ErrR3PerCallConflict) {
		t.Fatalf("changed result = %v", err)
	}
}

func TestFileR3PerCallStoreRefusesCorruptCustody(t *testing.T) {
	path := t.TempDir() + "/r3-per-call.json"
	store, err := NewFileR3PerCallStore(path)
	if err != nil {
		t.Fatal(err)
	}
	operation := json.RawMessage(`{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"delete_record"}]}`)
	execution, err := NewR3PerCallExecution(
		"https://as.example", "auth-token-7",
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", operation, 1_800_000_000,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, acquired, err := store.Claim(context.Background(), execution); err != nil || !acquired {
		t.Fatal(err)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	body[len(body)/2] ^= 1
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	if reopened, err := NewFileR3PerCallStore(path); err == nil || reopened != nil {
		t.Fatalf("corrupt custody reopened: %#v, %v", reopened, err)
	}
}
