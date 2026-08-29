package aauth_test

import (
	"context"
	"net/http"
	"testing"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

func TestAAuthVerificationComposesTheGenericRequestProof(t *testing.T) {
	fixture := newAuthRequestFixture(t)
	request := fixture.request(t, http.MethodGet, nil)
	credential, err := signaturekey.NewJWTCredential(fixture.authToken)
	if err != nil {
		t.Fatal(err)
	}
	if err := signaturekey.SignRequest(
		request,
		fixture.agentKey,
		credential,
		fixture.clock,
		signaturekey.SignOptions{},
	); err != nil {
		t.Fatal(err)
	}

	verified, err := aauth.VerifyRequest(
		context.Background(),
		request,
		fixture.keys,
		fixture.clock,
		aauth.VerifyRequestOptions{AllowedCredentialTypes: []string{aauth.AuthTokenType}},
	)
	if err != nil {
		t.Fatal(err)
	}
	if verified.Proof.Scheme() != signaturekey.SchemeJWT ||
		verified.Proof.ReplayKey() == "" ||
		verified.Proof.ReplayKey() != verified.ReplayKey ||
		!verified.Proof.PublicKey().Equal(verified.PublicKey) {
		t.Fatalf("AAuth request did not retain its generic proof: %#v", verified)
	}
	if verified.AuthToken == nil || !verified.AuthToken.Valid() {
		t.Fatal("AAuth request did not retain sealed Core token evidence")
	}
	claims, err := verified.AuthClaims()
	if err != nil || claims.JTI == "" {
		t.Fatalf("verified auth claims = %#v, %v", claims, err)
	}
	direct, err := aauth.VerifyAuthToken(context.Background(), fixture.authToken, fixture.keys, fixture.clock)
	if err != nil {
		t.Fatal(err)
	}
	requestEvidenceID, err := verified.AuthToken.EvidenceID()
	if err != nil {
		t.Fatal(err)
	}
	directEvidenceID, err := direct.EvidenceID()
	if err != nil {
		t.Fatal(err)
	}
	if requestEvidenceID != directEvidenceID {
		t.Fatalf("request token evidence = %q, direct evidence = %q", requestEvidenceID, directEvidenceID)
	}
}
