package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
)

const goAgentRequestSchema = "aauth.interop.go-agent-request.v0"
const goJKTJWTRequestSchema = "aauth.interop.go-jkt-jwt-request.v0"

type goRequestFixture struct {
	Schema    string `json:"schema"`
	Generator struct {
		Repository string `json:"repository"`
		Path       string `json:"path"`
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
		Method     string            `json:"method"`
		URL        string            `json:"url"`
		AgentToken string            `json:"agent_token"`
		Headers    map[string]string `json:"headers"`
	} `json:"request"`
}

type goJKTJWTRequestFixture struct {
	Schema    string `json:"schema"`
	Generator struct {
		Repository string `json:"repository"`
		Path       string `json:"path"`
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

func main() {
	if len(os.Args) == 2 {
		if err := generate(os.Args[1]); err != nil {
			fmt.Fprintln(os.Stderr, "generate Go interoperability vector:", err)
			os.Exit(1)
		}
		return
	}
	if len(os.Args) == 4 && os.Args[1] == "--profile" &&
		os.Args[2] == "jkt-jwt-request" {
		if err := generateJKTJWTRequest(os.Args[3]); err != nil {
			fmt.Fprintln(os.Stderr, "generate Go interoperability vector:", err)
			os.Exit(1)
		}
		return
	}
	fmt.Fprintln(
		os.Stderr,
		"usage: go run ./internal/interop/cmd/generate [--profile jkt-jwt-request] OUTPUT",
	)
	os.Exit(2)
}

func generate(output string) error {
	providerPrivate := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{41}, 32))
	agentPrivate := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{53}, 32))
	providerKey, err := aauth.NewEd25519SigningKey(
		"go-provider-key",
		providerPrivate,
	)
	if err != nil {
		return err
	}
	agentKey, err := aauth.NewEd25519SigningKey("go-agent-key", agentPrivate)
	if err != nil {
		return err
	}
	now := time.Unix(2_000_000_100, 0)
	issuer := "https://provider.example"
	personServer := "https://person.example"
	agentIdentifier := "aauth:interop@provider.example"
	agentToken, err := aauth.MintAgentToken(
		issuer,
		providerKey,
		aauth.AgentTokenRequest{
			Agent:        agentIdentifier,
			PersonServer: personServer,
			PublicKey:    agentKey.PublicJWK(),
			Lifetime:     time.Hour,
		},
		time.Unix(2_000_000_000, 0),
		"go-elixir-agent-token",
	)
	if err != nil {
		return err
	}
	missionBytes := []byte(
		`{"description":"Exercise an independent Go peer.",` +
			`"tools":[{"name":"records.read",` +
			`"description":"Read one admitted record."}]}`,
	)
	mission := aauth.MissionReference{
		Approver: personServer,
		S256:     aauth.S256(missionBytes),
	}
	missionHeader, err := mission.Header()
	if err != nil {
		return err
	}
	request, err := http.NewRequest(
		http.MethodGet,
		"https://resource.example/authorize",
		nil,
	)
	if err != nil {
		return err
	}
	request.Header.Set("AAuth-Mission", missionHeader)
	if err := aauth.SignRequest(
		request,
		agentKey,
		agentToken,
		aauth.ClockFunc(func() time.Time { return now }),
	); err != nil {
		return err
	}

	var fixture goRequestFixture
	fixture.Schema = goAgentRequestSchema
	fixture.Generator.Repository =
		"https://gitlab.com/sidecat-dev/aauth-go"
	fixture.Generator.Path = "internal/interop/cmd/generate"
	fixture.Now = now.Unix()
	fixture.Issuer = issuer
	fixture.IssuerKey = providerKey.PublicJWK()
	fixture.Expected.Agent = agentIdentifier
	fixture.Expected.PersonServer = personServer
	fixture.Expected.AgentKey = agentKey.PublicJWK()
	fixture.Expected.Mission = mission
	fixture.Request.Method = request.Method
	fixture.Request.URL = request.URL.String()
	fixture.Request.AgentToken = agentToken
	fixture.Request.Headers = map[string]string{
		"AAuth-Mission":   request.Header.Get("AAuth-Mission"),
		"Signature-Input": request.Header.Get("Signature-Input"),
		"Signature":       request.Header.Get("Signature"),
		"Signature-Key":   request.Header.Get("Signature-Key"),
	}
	body, err := json.MarshalIndent(fixture, "", "  ")
	if err != nil {
		return err
	}
	return replaceFile(output, append(body, '\n'))
}

func generateJKTJWTRequest(output string) error {
	durablePrivate := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{97}, 32))
	ephemeralPrivate := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{109}, 32))
	durableKey, err := aauth.NewEd25519SigningKey("go-durable-key", durablePrivate)
	if err != nil {
		return err
	}
	ephemeralKey, err := aauth.NewEd25519SigningKey("go-ephemeral-key", ephemeralPrivate)
	if err != nil {
		return err
	}
	now := time.Unix(2_000_000_100, 0)
	clock := aauth.ClockFunc(func() time.Time { return now })
	delegation, err := aauth.MintJKTJWT(
		durableKey,
		ephemeralKey.PublicJWK(),
		now,
		5*time.Minute,
	)
	if err != nil {
		return err
	}
	request, err := http.NewRequest(
		http.MethodPost,
		"https://provider.example/refresh",
		nil,
	)
	if err != nil {
		return err
	}
	if err := aauth.SignRequestWithJKTJWT(
		request,
		ephemeralKey,
		delegation,
		clock,
	); err != nil {
		return err
	}
	identity, err := durableKey.PublicJWK().ThumbprintURI()
	if err != nil {
		return err
	}

	var fixture goJKTJWTRequestFixture
	fixture.Schema = goJKTJWTRequestSchema
	fixture.Generator.Repository = "https://gitlab.com/sidecat-dev/aauth-go"
	fixture.Generator.Path = "internal/interop/cmd/generate"
	fixture.Now = now.Unix()
	fixture.Expected.Identity = identity
	fixture.Expected.IdentityKey = durableKey.PublicJWK()
	fixture.Expected.RequestKey = ephemeralKey.PublicJWK()
	fixture.Request.Method = request.Method
	fixture.Request.URL = request.URL.String()
	fixture.Request.Headers = map[string]string{
		"Signature-Input": request.Header.Get("Signature-Input"),
		"Signature":       request.Header.Get("Signature"),
		"Signature-Key":   request.Header.Get("Signature-Key"),
	}
	body, err := json.MarshalIndent(fixture, "", "  ")
	if err != nil {
		return err
	}
	return replaceFile(output, append(body, '\n'))
}

func replaceFile(path string, body []byte) error {
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, ".go-agent-request-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(0o644); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(body); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return err
	}
	cleanup = false
	return nil
}
