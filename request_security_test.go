package aauth_test

import (
	"bytes"
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
)

func TestSignedRequestRejectsBodyMutation(t *testing.T) {
	t.Parallel()

	fixture := newAuthRequestFixture(t)
	request := fixture.request(t, http.MethodPost, []byte(`{"action":"read"}`))
	if err := aauth.SignRequest(request, fixture.agentKey, fixture.authToken, fixture.clock); err != nil {
		t.Fatal(err)
	}
	request.Body = ioBody(`{"action":"delete"}`)
	request.ContentLength = int64(len(`{"action":"delete"}`))

	_, err := aauth.VerifyRequest(context.Background(), request, fixture.keys, fixture.clock, aauth.VerifyRequestOptions{
		AllowedCredentialTypes: []string{aauth.AuthTokenType},
	})
	if err == nil || !strings.Contains(err.Error(), "Content-Digest does not match") {
		t.Fatalf("body mutation error = %v", err)
	}
}

func TestSignedRequestRejectsConfirmationKeySubstitution(t *testing.T) {
	t.Parallel()

	fixture := newAuthRequestFixture(t)
	attackerKey := testSigningKey(t, "attacker-key")
	request := fixture.request(t, http.MethodGet, nil)
	if err := aauth.SignRequest(request, attackerKey, fixture.authToken, fixture.clock); err != nil {
		t.Fatal(err)
	}

	_, err := aauth.VerifyRequest(context.Background(), request, fixture.keys, fixture.clock, aauth.VerifyRequestOptions{
		AllowedCredentialTypes: []string{aauth.AuthTokenType},
	})
	if err == nil || !strings.Contains(err.Error(), "HTTP message signature is invalid") {
		t.Fatalf("key-substitution error = %v", err)
	}
}

func TestSignedRequestRejectsMissionAddedOutsideCoveredComponents(t *testing.T) {
	t.Parallel()

	fixture := newAuthRequestFixture(t)
	request := fixture.request(t, http.MethodGet, nil)
	if err := aauth.SignRequest(request, fixture.agentKey, fixture.authToken, fixture.clock); err != nil {
		t.Fatal(err)
	}
	request.Header.Set(
		"AAuth-Mission",
		`approver="https://ps.example"; s256="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"`,
	)

	_, err := aauth.VerifyRequest(context.Background(), request, fixture.keys, fixture.clock, aauth.VerifyRequestOptions{
		RequiredComponents:     []string{"aauth-mission"},
		AllowedCredentialTypes: []string{aauth.AuthTokenType},
	})
	if err == nil || !strings.Contains(err.Error(), `does not cover required component "aauth-mission"`) {
		t.Fatalf("uncovered mission error = %v", err)
	}
}

func TestSignRequestDoesNotCoverObsoleteMissionHeader(t *testing.T) {
	t.Parallel()

	fixture := newAuthRequestFixture(t)
	request := fixture.request(t, http.MethodGet, nil)
	request.Header.Set("AAuth-Mission", "obsolete-wire-value")
	if err := aauth.SignRequest(request, fixture.agentKey, fixture.authToken, fixture.clock); err != nil {
		t.Fatal(err)
	}
	if got := strings.ToLower(request.Header.Get("Signature-Input")); strings.Contains(got, "aauth-mission") {
		t.Fatalf("Signature-Input covers obsolete AAuth-Mission header: %s", got)
	}
}

func TestSignedRequestRejectsAdditionalCoveredFieldValue(t *testing.T) {
	t.Parallel()

	fixture := newAuthRequestFixture(t)
	request := fixture.request(t, http.MethodGet, nil)
	request.Header.Set("Authorization", "Bearer signed-value")
	if err := aauth.SignRequest(request, fixture.agentKey, fixture.authToken, fixture.clock); err != nil {
		t.Fatal(err)
	}
	request.Header.Add("Authorization", "Bearer appended-value")

	_, err := aauth.VerifyRequest(
		context.Background(),
		request,
		fixture.keys,
		fixture.clock,
		aauth.VerifyRequestOptions{AllowedCredentialTypes: []string{aauth.AuthTokenType}},
	)
	if err == nil || !strings.Contains(err.Error(), "HTTP message signature is invalid") {
		t.Fatalf("additional covered field value error = %v", err)
	}
}

func TestAuthTokenRejectsWrongAudienceAtResourceBoundary(t *testing.T) {
	t.Parallel()

	fixture := newAuthRequestFixture(t)
	claims, err := aauth.VerifyAuthToken(context.Background(), fixture.authToken, fixture.keys, fixture.clock)
	if err != nil {
		t.Fatal(err)
	}
	err = aauth.ValidateCurrentAuthTokenContext(
		claims,
		"https://other-resource.example",
		"https://ps.example",
		"pairwise-subject",
		fixture.agentKey.PublicJWK(),
		[]string{"documents.read"},
	)
	if err == nil || !strings.Contains(err.Error(), "audience") {
		t.Fatalf("wrong-audience error = %v", err)
	}
}

type authRequestFixture struct {
	clock     aauth.Clock
	agentKey  aauth.SigningKey
	authToken string
	keys      aauth.StaticKeyResolver
}

func newAuthRequestFixture(t *testing.T) authRequestFixture {
	t.Helper()

	now := time.Date(2026, 7, 27, 6, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	issuerKey := testSigningKey(t, "ps-key")
	agentKey := testSigningKey(t, "agent-key")
	token, err := aauth.MintAuthToken(issuerKey, aauth.AuthTokenClaims{
		Issuer:       "https://ps.example",
		DWK:          aauth.PersonDiscoveryDocument,
		Audience:     "https://resource.example",
		JTI:          "auth-token-1",
		PersonServer: "https://ps.example",
		Confirmation: aauth.Confirmation{JWK: agentKey.PublicJWK()},
		IssuedAt:     now.Unix(),
		ExpiresAt:    now.Add(time.Hour).Unix(),
		Subject:      "pairwise-subject",
		Scope:        "documents.read",
	})
	if err != nil {
		t.Fatal(err)
	}
	return authRequestFixture{
		clock:     clock,
		agentKey:  agentKey,
		authToken: token,
		keys: aauth.StaticKeyResolver{
			"https://ps.example": {"ps-key": issuerKey.PublicJWK()},
		},
	}
}

func (fixture authRequestFixture) request(t *testing.T, method string, body []byte) *http.Request {
	t.Helper()
	var reader *bytes.Reader
	if body == nil {
		reader = bytes.NewReader(nil)
	} else {
		reader = bytes.NewReader(body)
	}
	request, err := http.NewRequest(method, "https://resource.example/documents", reader)
	if err != nil {
		t.Fatal(err)
	}
	return request
}

func ioBody(value string) *readCloser {
	return &readCloser{Reader: strings.NewReader(value)}
}

type readCloser struct {
	*strings.Reader
}

func (closer *readCloser) Close() error {
	return nil
}
