// The agentidentity example runs direct Agent identity access with no Person
// Server, Access Server, person token, resource token, or auth token.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"time"

	aauth "github.com/aauth-dev/auth-go"
	"github.com/aauth-dev/auth-go/agent"
	"github.com/aauth-dev/auth-go/agentprovider"
	"github.com/aauth-dev/auth-go/jose"
	"github.com/aauth-dev/auth-go/resource"
	"github.com/aauth-dev/auth-go/signaturekey"
)

func main() {
	ctx := context.Background()
	now := time.Date(2026, 8, 30, 18, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	const (
		providerID = "https://agents.example"
		agentID    = "aauth:reader@agents.example"
		resourceID = "https://resource.example"
	)

	providerKey := signingKey("provider-key")
	agentKey := signingKey("agent-key")
	provider := must(agentprovider.New(agentprovider.Config{
		Issuer: providerID, SigningKey: providerKey, Clock: clock,
		NewID: func() string { return "example-agent-token" },
	}))
	agentToken := must(provider.Issue(aauth.AgentTokenRequest{
		Agent: agentID, PublicKey: agentKey.PublicJWK(), Lifetime: time.Hour,
	}))
	resolver := signaturekey.StaticKeyResolver{
		{Issuer: providerID, DiscoveryDocument: aauth.AgentDiscoveryDocument, KeyID: providerKey.ID()}: providerKey.PublicJWK(),
	}

	protected := must(resource.NewAgentIdentity(resource.AgentIdentityConfig{
		Issuer: resourceID, KeyResolver: resolver, Clock: clock,
		Protected: http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			principal, ok := resource.AgentPrincipalFromContext(request.Context())
			if !ok {
				http.Error(response, "missing Agent principal", http.StatusInternalServerError)
				return
			}
			_, _ = io.WriteString(response, principal.Agent)
		}),
	}))
	client := must(agent.New(ctx, agent.Config{
		Identifier: agentID, SigningKey: agentKey, AgentToken: agentToken,
		KeyResolver: resolver,
		HTTPClient:  &http.Client{Transport: localTransport{origin: resourceID, handler: protected.Handler()}},
		Clock:       clock,
	}))
	request := must(http.NewRequest(http.MethodGet, resourceID+"/records", nil))
	response := must(client.CallAsAgent(ctx, request))
	defer response.Body.Close()
	body := must(io.ReadAll(response.Body))
	if response.StatusCode != http.StatusOK {
		panic(fmt.Sprintf("Resource returned %s: %s", response.Status, body))
	}
	fmt.Printf("AAuth agent identity flow complete: %s\n", body)
}

type localTransport struct {
	origin  string
	handler http.Handler
}

func (transport localTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if request.URL.Scheme+"://"+request.URL.Host != transport.origin {
		return nil, fmt.Errorf("unexpected origin %s://%s", request.URL.Scheme, request.URL.Host)
	}
	recorder := httptest.NewRecorder()
	transport.handler.ServeHTTP(recorder, request)
	response := recorder.Result()
	response.Request = request
	return response, nil
}

func signingKey(id string) jose.SigningKey {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	return must(jose.NewEd25519SigningKey(id, privateKey))
}

func must[T any](value T, err error) T {
	if err != nil {
		panic(err)
	}
	return value
}
