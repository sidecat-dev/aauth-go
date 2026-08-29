package reference

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/r3"
)

func TestFileR3ResourceTokenStoreRecoversOneExactAuthorizationLineage(t *testing.T) {
	now := time.Date(2026, 8, 29, 17, 0, 0, 0, time.UTC)
	resourceKey := referenceTestSigningKey(t, "resource-r3-lineage")
	agentKey := referenceTestSigningKey(t, "agent-r3-lineage")
	document, err := r3.NewDocumentReference(
		"https://resource.example/r3/records",
		[]byte(`{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"delete_record"}],"display":{"summary":"Delete records"}}`),
	)
	if err != nil {
		t.Fatal(err)
	}
	thumbprint, err := agentKey.PublicJWK().Thumbprint()
	if err != nil {
		t.Fatal(err)
	}
	claims := aauth.ResourceTokenClaims{
		Issuer: "https://resource.example", DWK: aauth.ResourceDiscoveryDocument,
		Audience: "https://as.example", JTI: "resource-token-1", AgentJKT: thumbprint,
		IssuedAt: now.Unix(), ExpiresAt: now.Add(5 * time.Minute).Unix(), Scope: "records.write",
		PersonServer: "https://ps.example", Subject: "directed-person", PresentedJTI: "person-token-1",
		MissionS256: r3.S256([]byte("mission")), Tenant: "tenant-a", Account: "account-a",
	}
	token, err := r3.MintResourceToken(resourceKey, claims, document)
	if err != nil {
		t.Fatal(err)
	}
	record, err := NewR3ResourceTokenRecord(token, claims, document)
	if err != nil {
		t.Fatal(err)
	}
	if record.LineageKey == "" || record.ContextKey == "" || record.PresentedJTI != claims.PresentedJTI {
		t.Fatalf("record = %#v", record)
	}

	path := filepath.Join(t.TempDir(), "resource-token-lineage.json")
	store, err := NewFileR3ResourceTokenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Commit(context.Background(), record); err != nil {
		t.Fatal(err)
	}
	if err := store.Commit(context.Background(), record); err != nil {
		t.Fatalf("exact replay = %v", err)
	}

	reopened, err := NewFileR3ResourceTokenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := reopened.Load(context.Background(), record.ContextKey)
	if err != nil || loaded.ResourceToken != token || loaded.PresentedJTI != "person-token-1" {
		t.Fatalf("loaded = %#v, %v", loaded, err)
	}
	loaded.Scope = "changed"
	again, _ := reopened.Load(context.Background(), record.ContextKey)
	if again.Scope != "records.write" {
		t.Fatal("loaded record aliases retained state")
	}
	resolved, err := reopened.Resolve(context.Background(), record.LineageKey, now.Add(time.Minute).Unix())
	if err != nil || resolved.ContextKey != record.ContextKey {
		t.Fatalf("resolved = %#v, %v", resolved, err)
	}

	changedClaims := claims
	changedClaims.JTI = "resource-token-other"
	changedToken, err := r3.MintResourceToken(resourceKey, changedClaims, document)
	if err != nil {
		t.Fatal(err)
	}
	conflict, err := NewR3ResourceTokenRecord(changedToken, changedClaims, document)
	if err != nil {
		t.Fatal(err)
	}
	if err := reopened.Commit(context.Background(), conflict); !errors.Is(err, ErrR3ResourceTokenConflict) {
		t.Fatalf("changed replay = %v", err)
	}
	scopedClaims := claims
	scopedClaims.JTI = "resource-token-scoped"
	scopedClaims.Scope = "records.read"
	scopedToken, err := r3.MintResourceToken(resourceKey, scopedClaims, document)
	if err != nil {
		t.Fatal(err)
	}
	scoped, err := NewR3ResourceTokenRecord(scopedToken, scopedClaims, document)
	if err != nil {
		t.Fatal(err)
	}
	if scoped.ContextKey == record.ContextKey {
		t.Fatal("distinct resource-token scopes converged on one retained context")
	}
	ambiguousClaims := claims
	ambiguousClaims.JTI = "resource-token-ambiguous"
	ambiguousClaims.PresentedJTI = "person-token-ambiguous"
	ambiguousToken, err := r3.MintResourceToken(resourceKey, ambiguousClaims, document)
	if err != nil {
		t.Fatal(err)
	}
	ambiguous, err := NewR3ResourceTokenRecord(ambiguousToken, ambiguousClaims, document)
	if err != nil {
		t.Fatal(err)
	}
	if ambiguous.ContextKey == record.ContextKey {
		t.Fatal("distinct person-token bindings converged on one retained context")
	}
	if err := reopened.Commit(context.Background(), ambiguous); err != nil {
		t.Fatal(err)
	}
	if _, err := reopened.Resolve(context.Background(), record.LineageKey, now.Add(time.Minute).Unix()); !errors.Is(err, ErrR3ResourceTokenConflict) {
		t.Fatalf("ambiguous lineage resolution = %v", err)
	}
	if _, err := reopened.Load(context.Background(), "missing"); !errors.Is(err, ErrR3ResourceTokenNotFound) {
		t.Fatalf("missing = %v", err)
	}
}

func TestR3ResourceTokenRecordRejectsContextOrTokenSubstitution(t *testing.T) {
	now := time.Date(2026, 8, 29, 17, 30, 0, 0, time.UTC)
	resourceKey := referenceTestSigningKey(t, "resource-r3-lineage-negative")
	agentKey := referenceTestSigningKey(t, "agent-r3-lineage-negative")
	document, err := r3.NewDocumentReference(
		"https://resource.example/r3/records",
		[]byte(`{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"delete_record"}],"parameters":{},"display":{"summary":"Delete records"}}`),
	)
	if err != nil {
		t.Fatal(err)
	}
	thumbprint, _ := agentKey.PublicJWK().Thumbprint()
	claims := aauth.ResourceTokenClaims{
		Issuer: "https://resource.example", DWK: aauth.ResourceDiscoveryDocument,
		Audience: "https://as.example", JTI: "resource-token-2", AgentJKT: thumbprint,
		IssuedAt: now.Unix(), ExpiresAt: now.Add(5 * time.Minute).Unix(), Scope: "records.write",
		PersonServer: "https://ps.example", Subject: "directed-person", PresentedJTI: "person-token-2",
	}
	token, err := r3.MintResourceToken(resourceKey, claims, document)
	if err != nil {
		t.Fatal(err)
	}
	changed := claims
	changed.PresentedJTI = "person-token-other"
	if _, err := NewR3ResourceTokenRecord(token, changed, document); err == nil {
		t.Fatal("changed presented_jti was accepted against the compact token")
	}
	changed = claims
	changed.Scope = "records.read"
	if _, err := NewR3ResourceTokenRecord(token, changed, document); err == nil {
		t.Fatal("changed scope was accepted against the compact token")
	}
	otherDocument, err := r3.NewDocumentReference(
		"https://resource.example/r3/other",
		[]byte(`{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"read_record"}],"display":{"summary":"Read records"}}`),
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewR3ResourceTokenRecord(token, claims, otherDocument); err == nil {
		t.Fatal("changed R3 reference was accepted against the compact token")
	}

	if _, err := NewR3ResourceTokenRecord("not-a-token", claims, document); err == nil {
		t.Fatal("malformed compact token was accepted")
	}
}
