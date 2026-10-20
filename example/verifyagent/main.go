// The verifyagent example checks an Agent token, then verifies a signed
// request at a Resource. It uses synthetic keys and an in-process handler.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/resource"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

func providerKeys(key jose.JWK) signaturekey.StaticKeyResolver {
	return signaturekey.StaticKeyResolver{
		{Issuer: "https://agents.example", DiscoveryDocument: aauth.AgentDiscoveryDocument, KeyID: key.Kid}: key,
	}
}

func agentResource(keys signaturekey.KeyResolver, clock aauth.Clock, app http.Handler) (http.Handler, error) {
	server, err := resource.NewAgentIdentity(resource.AgentIdentityConfig{
		Issuer: "https://resource.example", KeyResolver: keys, Clock: clock,
		AdditionalSignatureComponents: []string{"content-digest"},
		Protected:                     app,
	})
	if err != nil {
		return nil, err
	}
	return server.Handler(), nil
}

func signAgentRequest(request *http.Request, key jose.SigningKey, token string, clock aauth.Clock) error {
	return signaturekey.SignJWTRequestWithOptions(request, key, token, clock, signaturekey.SignOptions{
		AdditionalComponents: []string{"content-digest"},
	})
}

func main() {
	if err := run(os.Stdout); err != nil {
		log.Fatal(err)
	}
}

func run(output io.Writer) error {
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	providerKey, agentKey := signingKey("provider-key"), signingKey("agent-key")
	token, err := aauth.MintAgentToken("https://agents.example", providerKey,
		aauth.AgentTokenRequest{
			Agent: "aauth:reader@agents.example", PublicKey: agentKey.PublicJWK(),
			Lifetime: time.Hour,
		}, now, "example-agent-token")
	if err != nil {
		return err
	}
	keys := providerKeys(providerKey.PublicJWK())

	claims, err := aauth.VerifyAgentToken(context.Background(), token, keys, clock)
	if err != nil {
		return err
	}
	fmt.Fprintln(output, "Token verified:", claims.Subject)

	app := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		principal, ok := resource.AgentPrincipalFromContext(r.Context())
		if !ok || principal.Agent != "aauth:reader@agents.example" {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		fmt.Fprint(w, principal.Agent)
	})
	handler, err := agentResource(keys, clock, app)
	if err != nil {
		return err
	}
	request, err := http.NewRequest(http.MethodGet, "https://resource.example/records", nil)
	if err != nil {
		return err
	}
	if err := signAgentRequest(request, agentKey, token, clock); err != nil {
		return err
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		return fmt.Errorf("Resource refused request: HTTP %d", response.Code)
	}
	fmt.Fprintln(output, "Request verified:", response.Body.String())
	return nil
}

func signingKey(id string) jose.SigningKey {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	key, err := jose.NewEd25519SigningKey(id, privateKey)
	if err != nil {
		panic(err)
	}
	return key
}
