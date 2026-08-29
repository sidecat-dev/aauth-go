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
}
