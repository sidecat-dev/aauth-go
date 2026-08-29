package aauth_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/budgets"
	"gitlab.com/sidecat-dev/aauth-go/r3"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

func TestTokenDraftComposesOnlyCompleteKnownAuthorizationMembers(t *testing.T) {
	now := time.Date(2026, 8, 29, 9, 0, 0, 0, time.UTC)
	issuer := testSigningKey(t, "draft-resource")
	agent := testSigningKey(t, "draft-agent")
	thumbprint, err := agent.PublicJWK().Thumbprint()
	if err != nil {
		t.Fatal(err)
	}
	draft, err := aauth.NewResourceTokenDraft(aauth.ResourceTokenClaims{
		Issuer: "https://resource.example", DWK: aauth.ResourceDiscoveryDocument,
		Audience: "https://as.example", JTI: "resource-draft", AgentJKT: thumbprint,
		IssuedAt: now.Unix(), ExpiresAt: now.Add(time.Minute).Unix(), Scope: "records.read",
		PersonServer: "https://ps.example", Subject: "directed-person", PresentedJTI: "person-token-1",
	})
	if err != nil || !draft.Valid() {
		t.Fatalf("draft = %#v, %v", draft, err)
	}
	if _, err := draft.WithAuthorizationMembers(map[string]json.RawMessage{
		"unknown_extension": json.RawMessage(`true`),
	}); err == nil {
		t.Fatal("unknown authorization member was admitted")
	}
	if _, err := draft.WithAuthorizationMembers(map[string]json.RawMessage{
		"r3_uri": json.RawMessage(`"https://resource.example/r3/current"`),
	}); err == nil {
		t.Fatal("incomplete R3 member set was admitted")
	}
	if _, err := draft.WithAuthorizationMembers(map[string]json.RawMessage{
		"scope": json.RawMessage(`"changed"`),
	}); err == nil {
		t.Fatal("base claim was replaced as an authorization member")
	}

	budget := json.RawMessage(`{"amount":5000000,"unit":"USD","decimals":6}`)
	composed, err := draft.WithAuthorizationMembers(map[string]json.RawMessage{"budget": budget})
	if err != nil || !composed.Valid() {
		t.Fatalf("budget composition = %#v, %v", composed, err)
	}
	budget[10] = '9'
	reference, err := r3.NewDocumentReference(
		"https://resource.example/r3/current",
		[]byte(`{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"read"}]}`),
	)
	if err != nil {
		t.Fatal(err)
	}
	composed, err = r3.BindResourceToken(composed, reference)
	if err != nil {
		t.Fatal(err)
	}
	compact, err := composed.Mint(issuer)
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := aauth.VerifyResourceToken(
		context.Background(), compact,
		signaturekey.StaticKeyResolver{"https://resource.example": {issuer.ID(): issuer.PublicJWK()}},
		aauth.ClockFunc(func() time.Time { return now }),
	)
	if err != nil {
		t.Fatal(err)
	}
	members, err := evidence.AuthorizationMembers()
	if err != nil || string(members["budget"]) != `{"amount":5000000,"unit":"USD","decimals":6}` {
		t.Fatalf("authorization members = %s, %v", members["budget"], err)
	}
	if members["r3_uri"] == nil || members["r3_s256"] == nil {
		t.Fatalf("R3 members were not composed: %#v", members)
	}
	if budgetResult, err := budgets.ValidateResourceToken(evidence); err != nil || !budgetResult.Valid() {
		t.Fatalf("Budget companion = %#v, %v", budgetResult, err)
	}
	if r3Result, err := r3.ValidateResourceToken(evidence); err != nil || !r3Result.Valid() {
		t.Fatalf("R3 companion = %#v, %v", r3Result, err)
	}
	if _, err := composed.WithAuthorizationMembers(map[string]json.RawMessage{"budget": json.RawMessage(`{}`)}); err == nil {
		t.Fatal("duplicate companion member was admitted")
	}

	var zero aauth.TokenDraft[aauth.ResourceTokenClaims]
	if zero.Valid() {
		t.Fatal("zero token draft is valid")
	}
	if _, err := zero.Mint(issuer); err == nil {
		t.Fatal("zero token draft minted a token")
	}
}
