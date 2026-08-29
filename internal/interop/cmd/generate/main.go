package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"net/http"
	"os"
	"path/filepath"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
)

const goJKTJWTRequestSchema = "aauth.interop.go-jkt-jwt-request.v0"

type goJKTJWTRequestFixture struct {
	Schema    string `json:"schema"`
	Generator struct {
		Repository string `json:"repository"`
		Path       string `json:"path"`
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

func main() {
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
		"usage: go run ./internal/interop/cmd/generate --profile jkt-jwt-request OUTPUT",
	)
	os.Exit(2)
}

func generateJKTJWTRequest(output string) error {
	durablePrivate := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{97}, 32))
	ephemeralPrivate := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{109}, 32))
	durableKey, err := jose.NewEd25519SigningKey("go-durable-key", durablePrivate)
	if err != nil {
		return err
	}
	ephemeralKey, err := jose.NewEd25519SigningKey("go-ephemeral-key", ephemeralPrivate)
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
	temporary, err := os.CreateTemp(directory, ".go-jkt-jwt-request-*")
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
