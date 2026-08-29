package aauth_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"

	aauth "gitlab.com/sidecat-dev/aauth-go"
)

const elixirAgentRequestVector = "interop/elixir-agent-request.json"
const elixirJKTJWTRequestVector = "interop/elixir-jkt-jwt-request.json"

type elixirRequestFixture struct {
	Schema    string `json:"schema"`
	Generator struct {
		Repository string `json:"repository"`
		Commit     string `json:"commit"`
	} `json:"generator"`
	Now       int64    `json:"now"`
	Issuer    string   `json:"issuer"`
	IssuerKey jose.JWK `json:"issuer_key"`
	Expected  struct {
		Agent        string                 `json:"agent"`
		PersonServer string                 `json:"person_server"`
		AgentKey     jose.JWK               `json:"agent_key"`
		Mission      aauth.MissionReference `json:"mission"`
	} `json:"expected"`
	Request struct {
		Method  string            `json:"method"`
		URL     string            `json:"url"`
		Headers map[string]string `json:"headers"`
	} `json:"request"`
}

type elixirJKTJWTRequestFixture struct {
	Schema    string `json:"schema"`
	Generator struct {
		Repository string `json:"repository"`
		Commit     string `json:"commit"`
	} `json:"generator"`
	Now      int64 `json:"now"`
	Expected struct {
		Identity    string   `json:"identity"`
		IdentityKey jose.JWK `json:"identity_key"`
		RequestKey  jose.JWK `json:"request_key"`
	} `json:"expected"`
	Request struct {
		Method  string            `json:"method"`
		URL     string            `json:"url"`
		Headers map[string]string `json:"headers"`
	} `json:"request"`
}

func TestLegacyDraft06ElixirAgentRequestIsRetainedButRejected(t *testing.T) {
	fixture := loadElixirRequestFixture(t)
	request := elixirFixtureRequest(t, fixture)
	resolver := signaturekey.StaticKeyResolver{
		fixture.Issuer: {
			fixture.IssuerKey.Kid: fixture.IssuerKey,
		},
	}
	clock := aauth.ClockFunc(func() time.Time {
		return time.Unix(fixture.Now, 0)
	})

	_, err := aauth.VerifyRequest(
		context.Background(),
		request,
		resolver,
		clock,
		aauth.VerifyRequestOptions{
			RequiredComponents:     []string{"aauth-mission"},
			AllowedCredentialTypes: []string{aauth.AgentTokenType},
		},
	)
	var signatureError *signaturekey.Error
	if !errors.As(err, &signatureError) ||
		signatureError.Code != signaturekey.ErrorUnsupportedAlgorithm {
		t.Fatalf("legacy draft-06 fixture error = %v, want unsupported_algorithm", err)
	}
}

func TestLegacyDraft06ElixirJKTJWTRequestIsRetainedButRejected(t *testing.T) {
	body, err := os.ReadFile(elixirJKTJWTRequestVector)
	if err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	var fixture elixirJKTJWTRequestFixture
	if err := decoder.Decode(&fixture); err != nil {
		t.Fatal(err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		t.Fatal("Elixir jkt-jwt fixture has trailing JSON")
	}
	commitBytes, commitErr := hex.DecodeString(fixture.Generator.Commit)
	if fixture.Schema != "aauth.interop.elixir-jkt-jwt-request.v0" ||
		fixture.Generator.Repository != "https://gitlab.com/sidecat-dev/sidecat-beam" ||
		commitErr != nil ||
		len(commitBytes) != 20 ||
		fixture.Request.Method != http.MethodPost ||
		fixture.Request.URL == "" {
		t.Fatalf("Elixir jkt-jwt fixture metadata is invalid: %#v", fixture)
	}
	request, err := http.NewRequest(fixture.Request.Method, fixture.Request.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	for name, value := range fixture.Request.Headers {
		request.Header.Set(name, value)
	}
	clock := aauth.ClockFunc(func() time.Time {
		return time.Unix(fixture.Now, 0)
	})
	_, err = aauth.VerifyRequest(
		context.Background(),
		request,
		nil,
		clock,
		aauth.VerifyRequestOptions{
			AllowedSignatureKeyTypes: []signaturekey.Scheme{signaturekey.SchemeJKTJWT},
		},
	)
	var signatureError *signaturekey.Error
	if !errors.As(err, &signatureError) ||
		signatureError.Code != signaturekey.ErrorUnsupportedAlgorithm {
		t.Fatalf("legacy draft-06 jkt-jwt error = %v, want unsupported_algorithm", err)
	}
}

func loadElixirRequestFixture(t *testing.T) elixirRequestFixture {
	t.Helper()
	body, err := os.ReadFile(elixirAgentRequestVector)
	if err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	var fixture elixirRequestFixture
	if err := decoder.Decode(&fixture); err != nil {
		t.Fatal(err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		t.Fatal("Elixir interop fixture has trailing JSON")
	}
	commitBytes, commitErr := hex.DecodeString(fixture.Generator.Commit)
	if fixture.Schema != "aauth.interop.elixir-agent-request.v0" ||
		fixture.Generator.Repository !=
			"https://gitlab.com/sidecat-dev/sidecat-beam" ||
		commitErr != nil ||
		len(commitBytes) != 20 ||
		strings.ToLower(fixture.Generator.Commit) != fixture.Generator.Commit ||
		fixture.Request.Method != http.MethodGet ||
		fixture.Request.URL == "" ||
		len(fixture.Request.Headers) == 0 {
		t.Fatalf("Elixir interop fixture metadata is invalid: %#v", fixture)
	}
	return fixture
}

func elixirFixtureRequest(
	t *testing.T,
	fixture elixirRequestFixture,
) *http.Request {
	t.Helper()
	request, err := http.NewRequest(
		fixture.Request.Method,
		fixture.Request.URL,
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	for name, value := range fixture.Request.Headers {
		request.Header.Set(name, value)
	}
	return request
}
