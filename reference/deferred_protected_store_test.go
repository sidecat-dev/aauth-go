package reference

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"os"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

func TestFileDeferredProtectedCallStoreRetainsOneExactTerminalResponse(t *testing.T) {
	path := t.TempDir() + "/deferred-protected.json"
	store, err := NewFileDeferredProtectedCallStore(path)
	if err != nil {
		t.Fatal(err)
	}
	record := deferredProtectedStoreRecord(t)
	if err := store.Create(context.Background(), record); err != nil {
		t.Fatal(err)
	}
	if err := store.Create(context.Background(), record); err != nil {
		t.Fatalf("exact create replay = %v", err)
	}
	claimed, acquired, err := store.Claim(context.Background(), record.ID, "https://as.example", "auth-token")
	if err != nil || !acquired || claimed.State != DeferredProtectedClaimed {
		t.Fatalf("claim = %#v acquired=%t err=%v", claimed, acquired, err)
	}
	if _, acquired, err := store.Claim(context.Background(), record.ID, "https://as.example", "auth-token"); err != nil || acquired {
		t.Fatalf("concurrent claim acquired=%t err=%v", acquired, err)
	}
	if _, _, err := store.Claim(context.Background(), record.ID, "https://as.example", "other-token"); !errors.Is(err, ErrDeferredProtectedConflict) {
		t.Fatalf("token substitution = %v", err)
	}
	result := DeferredProtectedResult{Status: 200, ContentType: "application/json", Body: []byte(`{"status":"stored"}`)}
	complete, err := store.Complete(context.Background(), record.ID, result)
	if err != nil || complete.State != DeferredProtectedComplete || complete.Result == nil {
		t.Fatalf("complete = %#v, %v", complete, err)
	}

	reopened, err := NewFileDeferredProtectedCallStore(path)
	if err != nil {
		t.Fatal(err)
	}
	replayed, acquired, err := reopened.Claim(context.Background(), record.ID, "https://as.example", "auth-token")
	if err != nil || acquired || replayed.Result == nil || string(replayed.Result.Body) != string(result.Body) {
		t.Fatalf("reopened = %#v acquired=%t err=%v", replayed, acquired, err)
	}
	replayed.Body[0] = 'x'
	again, _, _ := reopened.Claim(context.Background(), record.ID, "https://as.example", "auth-token")
	if string(again.Body) != string(record.Body) {
		t.Fatal("loaded record aliases retained request body")
	}
}

func TestFileDeferredProtectedCallStoreRefusesCorruptCustody(t *testing.T) {
	path := t.TempDir() + "/deferred-protected.json"
	store, err := NewFileDeferredProtectedCallStore(path)
	if err != nil {
		t.Fatal(err)
	}
	record := deferredProtectedStoreRecord(t)
	if err := store.Create(context.Background(), record); err != nil {
		t.Fatal(err)
	}
	body, _ := os.ReadFile(path)
	body[len(body)/2] ^= 1
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	if reopened, err := NewFileDeferredProtectedCallStore(path); err == nil || reopened != nil {
		t.Fatalf("corrupt store reopened: %#v, %v", reopened, err)
	}
}

func TestFileDeferredProtectedCallStoreRefusesCanonicalRequestRewrite(t *testing.T) {
	path := t.TempDir() + "/deferred-protected.json"
	store, err := NewFileDeferredProtectedCallStore(path)
	if err != nil {
		t.Fatal(err)
	}
	record := deferredProtectedStoreRecord(t)
	if err := store.Create(context.Background(), record); err != nil {
		t.Fatal(err)
	}
	forged := copyDeferredProtectedRecord(record)
	forged.Body = []byte(`{"name":"forged"}`)
	body, err := encodeDeferredProtectedState(map[string]DeferredProtectedCallRecord{forged.ID: forged})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	if reopened, err := NewFileDeferredProtectedCallStore(path); err == nil || reopened != nil {
		t.Fatalf("canonical request rewrite reopened: %#v, %v", reopened, err)
	}
}

func deferredProtectedStoreRecord(t *testing.T) DeferredProtectedCallRecord {
	t.Helper()
	now := time.Date(2026, 8, 29, 17, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	personKey := referenceTestSigningKey(t, "deferred-store-person")
	agentKey := referenceTestSigningKey(t, "deferred-store-agent")
	personToken, err := aauth.MintPersonToken(personKey, aauth.PersonTokenClaims{
		Issuer: "https://ps.example", DWK: aauth.PersonDiscoveryDocument,
		Audience: "https://resource.example", Subject: "person",
		Confirmation: aauth.Confirmation{JWK: agentKey.PublicJWK()}, JTI: "person-token",
		IssuedAt: now.Unix(), ExpiresAt: now.Add(time.Hour).Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"name":"current"}`)
	request, _ := http.NewRequest(http.MethodPost, "https://resource.example/records?mode=current", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	if err := signaturekey.SignJWTRequest(request, agentKey, personToken, clock); err != nil {
		t.Fatal(err)
	}
	verified, err := aauth.VerifyRequest(
		context.Background(), request,
		signaturekey.StaticKeyResolver{"https://ps.example": {personKey.ID(): personKey.PublicJWK()}},
		clock,
		aauth.VerifyRequestOptions{
			RequiredComponents: []string{"content-type"}, RequireExactComponents: true,
			AllowedCredentialTypes: []string{aauth.PersonTokenType},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	return DeferredProtectedCallRecord{
		ID: "pending-call", Resource: "https://resource.example", ResourceToken: "resource-token",
		RequestProofKey: verified.ReplayKey, RequestProof: requestProof(request, verified), PersonIssuerKey: personKey.PublicJWK(),
		Method: request.Method, Target: request.URL.RequestURI(), Body: body, ContentType: "application/json",
		RequiredScopes: []string{"records.write"}, ExpiresAt: now.Add(time.Hour), State: DeferredProtectedPending,
	}
}
