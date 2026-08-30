// The resourcesession example runs the direct Resource-managed interaction
// path. It uses an Agent Provider and Resource, but no Person Server or Access
// Server.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"time"

	aauth "github.com/aauth-dev/auth-go"
	clientagent "github.com/aauth-dev/auth-go/agent"
	"github.com/aauth-dev/auth-go/agentprovider"
	"github.com/aauth-dev/auth-go/jose"
	"github.com/aauth-dev/auth-go/resource"
	"github.com/aauth-dev/auth-go/signaturekey"
)

const (
	agentProviderID = "https://agents.example"
	agentID         = "aauth:reader@agents.example"
	resourceID      = "https://resource.example"
	readScope       = "records.read"
)

func main() {
	if err := run(os.Stdout); err != nil {
		panic(err)
	}
}

func run(output io.Writer) error {
	ctx := context.Background()
	now := time.Date(2026, 8, 30, 23, 30, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	providerKey, err := newSigningKey("provider-key")
	if err != nil {
		return err
	}
	agentKey, err := newSigningKey("agent-key")
	if err != nil {
		return err
	}
	provider, err := agentprovider.New(agentprovider.Config{
		Issuer: agentProviderID, SigningKey: providerKey, Clock: clock,
		NewID: func() string { return "example-agent-token" },
	})
	if err != nil {
		return err
	}
	agentToken, err := provider.Issue(aauth.AgentTokenRequest{
		Agent: agentID, PublicKey: agentKey.PublicJWK(), Lifetime: time.Hour,
	})
	if err != nil {
		return err
	}
	resolver := signaturekey.StaticKeyResolver{
		{Issuer: agentProviderID, DiscoveryDocument: aauth.AgentDiscoveryDocument, KeyID: providerKey.ID()}: providerKey.PublicJWK(),
	}

	protected := http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		principal, ok := resource.SessionPrincipalFromContext(request.Context())
		if !ok {
			http.Error(response, "missing Resource session principal", http.StatusInternalServerError)
			return
		}
		fmt.Fprintf(response, "AAuth Resource-managed session complete: %s has %s\n", principal.Subject, principal.Scope[0])
	})
	store := newMemorySessionStore()
	resourceServer, err := resource.NewResourceManaged(resource.ResourceManagedConfig{
		Issuer: resourceID, KeyResolver: resolver, Clock: clock,
		ScopeDescriptions: map[string]string{readScope: "Read records"},
		RequiredScopes:    func(*http.Request) []string { return []string{readScope} },
		Interaction: resource.SessionInteractionPolicy{
			URL: resourceID + "/interaction", Lifetime: 5 * time.Minute,
			RetryAfter: 0, MaximumCodeAttempts: 3,
		},
		Sessions: store, Protected: protected,
	})
	if err != nil {
		return err
	}
	httpClient := &http.Client{Transport: localTransport{origin: resourceID, handler: resourceServer.Handler()}}
	reader, err := clientagent.New(ctx, clientagent.Config{
		Identifier: agentID, SigningKey: agentKey, AgentToken: agentToken,
		KeyResolver: resolver, HTTPClient: httpClient, Clock: clock,
	})
	if err != nil {
		return err
	}

	initial, err := http.NewRequestWithContext(ctx, http.MethodGet, resourceID+"/records", nil)
	if err != nil {
		return err
	}
	initial.Header.Set("AAuth-Capabilities", "interaction")
	started, err := reader.BeginResourceSession(ctx, initial)
	if err != nil {
		return err
	}
	pending, ok := started.Pending()
	if !ok {
		return fmt.Errorf("Resource did not request interaction")
	}
	interactionURL, err := url.Parse(pending.InteractionURL())
	if err != nil {
		return err
	}
	reference := strings.TrimPrefix(interactionURL.Path, "/interaction/")
	interaction, err := resourceServer.ConsumeSessionInteractionCode(ctx, reference, pending.InteractionCode())
	if err != nil {
		return err
	}
	if err := resourceServer.ApproveSessionInteraction(ctx, interaction, resource.SessionGrant{
		Subject: "person-123", Scope: []string{readScope}, Lifetime: 30 * time.Minute,
	}); err != nil {
		return err
	}
	completed, err := reader.PollResourceSession(ctx, pending)
	if err != nil {
		return err
	}
	terminal, hasTerminal := completed.Response()
	if failure := completed.Failure(); failure != nil {
		if hasTerminal {
			terminal.Body.Close()
		}
		return failure
	}
	session, hasSession := completed.Session()
	if !hasTerminal || !hasSession {
		if hasTerminal {
			terminal.Body.Close()
		}
		return fmt.Errorf("Resource did not issue a session")
	}
	terminal.Body.Close()

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, resourceID+"/records", nil)
	if err != nil {
		return err
	}
	result, err := reader.DoWithResourceSession(ctx, request, session)
	if err != nil {
		return err
	}
	response, hasResponse := result.Response()
	if failure := result.Failure(); failure != nil {
		if hasResponse {
			response.Body.Close()
		}
		return failure
	}
	if !hasResponse {
		return fmt.Errorf("protected Resource returned no response")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("protected Resource returned %s", response.Status)
	}
	_, err = io.Copy(output, response.Body)
	return err
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

func newSigningKey(id string) (jose.SigningKey, error) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return jose.SigningKey{}, err
	}
	return jose.NewEd25519SigningKey(id, privateKey)
}
