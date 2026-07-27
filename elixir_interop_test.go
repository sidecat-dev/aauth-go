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
	Now       int64     `json:"now"`
	Issuer    string    `json:"issuer"`
	IssuerKey aauth.JWK `json:"issuer_key"`
	Expected  struct {
		Agent        string                 `json:"agent"`
		PersonServer string                 `json:"person_server"`
		AgentKey     aauth.JWK              `json:"agent_key"`
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
		Identity    string    `json:"identity"`
		IdentityKey aauth.JWK `json:"identity_key"`
		RequestKey  aauth.JWK `json:"request_key"`
	} `json:"expected"`
	Request struct {
		Method  string            `json:"method"`
		URL     string            `json:"url"`
		Headers map[string]string `json:"headers"`
	} `json:"request"`
}

func TestElixirSignedAgentRequestVerifiesInGo(t *testing.T) {
	fixture := loadElixirRequestFixture(t)
	request := elixirFixtureRequest(t, fixture)
	resolver := aauth.StaticKeyResolver{
		fixture.Issuer: {
			fixture.IssuerKey.Kid: fixture.IssuerKey,
		},
	}
	clock := aauth.ClockFunc(func() time.Time {
		return time.Unix(fixture.Now, 0)
	})

	verified, err := aauth.VerifyRequest(
		context.Background(),
		request,
		resolver,
		clock,
		aauth.VerifyRequestOptions{
			RequiredComponents:     []string{"aauth-mission"},
			AllowedCredentialTypes: []string{aauth.AgentTokenType},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if verified.SignatureKeyType != aauth.SignatureKeyJWT ||
		verified.Agent != fixture.Expected.Agent ||
		verified.AgentToken == nil ||
		verified.AgentToken.Issuer != fixture.Issuer ||
		verified.AgentToken.PersonServer != fixture.Expected.PersonServer ||
		!verified.PublicKey.Equal(fixture.Expected.AgentKey) {
		t.Fatalf("verified Elixir request = %#v", verified)
	}
	mission, err := aauth.ParseMissionHeader(request.Header.Get("AAuth-Mission"))
	if err != nil {
		t.Fatal(err)
	}
	if mission != fixture.Expected.Mission {
		t.Fatalf("mission = %#v, want %#v", mission, fixture.Expected.Mission)
	}
}

func TestElixirSignedAgentRequestRefusesWireMutation(t *testing.T) {
	fixture := loadElixirRequestFixture(t)
	resolver := aauth.StaticKeyResolver{
		fixture.Issuer: {
			fixture.IssuerKey.Kid: fixture.IssuerKey,
		},
	}
	clock := aauth.ClockFunc(func() time.Time {
		return time.Unix(fixture.Now, 0)
	})
	verify := func(request *http.Request) error {
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
		return err
	}

	t.Run("mission", func(t *testing.T) {
		request := elixirFixtureRequest(t, fixture)
		value := request.Header.Get("AAuth-Mission")
		request.Header.Set(
			"AAuth-Mission",
			strings.Replace(value, "s256=\"", "s256=\"A", 1),
		)
		if err := verify(request); err == nil {
			t.Fatal("mutated Elixir mission header was accepted")
		}
	})

	t.Run("signature key", func(t *testing.T) {
		request := elixirFixtureRequest(t, fixture)
		value := request.Header.Get("Signature-Key")
		request.Header.Set(
			"Signature-Key",
			strings.Replace(value, "sig=jwt;jwt=\"", "sig=jwt;jwt=\"A", 1),
		)
		if err := verify(request); err == nil {
			t.Fatal("mutated Elixir Signature-Key was accepted")
		}
	})
}

func TestElixirJKTJWTRequestVerifiesInGo(t *testing.T) {
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
	verified, err := aauth.VerifyRequest(
		context.Background(),
		request,
		nil,
		clock,
		aauth.VerifyRequestOptions{
			AllowedSignatureKeyTypes: []string{aauth.SignatureKeyJKTJWT},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if verified.Signer != fixture.Expected.Identity ||
		!verified.IdentityKey.Equal(fixture.Expected.IdentityKey) ||
		!verified.PublicKey.Equal(fixture.Expected.RequestKey) {
		t.Fatalf("verified Elixir jkt-jwt request = %#v", verified)
	}

	mutated := request.Clone(context.Background())
	mutated.Header.Set(
		"Signature-Key",
		strings.Replace(
			request.Header.Get("Signature-Key"),
			`sig=jkt-jwt;jwt="`,
			`sig=jkt-jwt;jwt="A`,
			1,
		),
	)
	if _, err := aauth.VerifyRequest(
		context.Background(),
		mutated,
		nil,
		clock,
		aauth.VerifyRequestOptions{
			AllowedSignatureKeyTypes: []string{aauth.SignatureKeyJKTJWT},
		},
	); err == nil {
		t.Fatal("mutated Elixir jkt-jwt Signature-Key was accepted")
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
