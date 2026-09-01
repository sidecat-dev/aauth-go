// The self-hosted example publishes ordinary Agent Provider metadata and JWKS,
// self-issues a short-lived Agent token, obtains one local-action permission
// from the token's Person Server, and uses the same key for one signed Resource
// call. Bootstrap defines no separate refresh ceremony for this profile; the
// Agent self-issues another token when needed.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	clientagent "gitlab.com/sidecat-dev/aauth-go/agent"
	"gitlab.com/sidecat-dev/aauth-go/agentprovider"
	"gitlab.com/sidecat-dev/aauth-go/internal/exampleutil"
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/personserver"
	"gitlab.com/sidecat-dev/aauth-go/resource"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

const (
	agentOrigin    = "https://agent.example"
	agentID        = "aauth:local@agent.example"
	personServerID = "https://person.example"
	resourceID     = "https://resource.example"
)

func main() {
	if err := run(os.Stdout); err != nil {
		log.Fatal(err)
	}
}

func run(output io.Writer) error {
	if output == nil {
		return errors.New("output is required")
	}
	ctx := context.Background()
	now := time.Date(2026, 8, 31, 9, 15, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	key, err := newSigningKey("self-hosted-key")
	if err != nil {
		return err
	}
	personKey, err := newSigningKey("local-person-server-key")
	if err != nil {
		return err
	}
	selfHosted, err := agentprovider.NewSelfHostedAgent(agentprovider.SelfHostedAgentConfig{
		Issuer: agentOrigin, Agent: agentID, SigningKey: key, Clock: clock,
		NewID: func() string { return "self-hosted-agent-token" },
	})
	if err != nil {
		return err
	}
	network := newLogicalTransport()
	network.Handle(agentOrigin, selfHosted.Handler())
	httpClient := &http.Client{Transport: network}
	resolver, err := signaturekey.NewHTTPKeyResolver(signaturekey.HTTPKeyResolverConfig{
		Client: httpClient, Clock: clock, Admit: network.Admit,
	})
	if err != nil {
		return err
	}
	compact, err := selfHosted.Issue(agentprovider.SelfHostedAgentTokenRequest{
		PersonServer: personServerID, Lifetime: time.Hour,
	})
	if err != nil {
		return err
	}
	localStore := exampleutil.NewMissionPermissionStore()
	people, err := personserver.NewPSAuthorization(personserver.PSAuthorizationConfig{
		Issuer: personServerID, SigningKey: personKey, KeyResolver: resolver, Clock: clock,
		NewID: func() string { return "unused-local-token" }, Tokens: localStore,
		BindPerson: func(context.Context, personserver.PersonTokenRequest) (personserver.Person, error) {
			return personserver.Person{Subject: "local-person", Lifetime: time.Minute}, nil
		},
		Authorize: func(context.Context, personserver.AuthorizationRequest) (personserver.AuthorizationDecision, error) {
			return personserver.AuthorizationDecision{Scopes: []string{"unused"}, Lifetime: time.Minute}, nil
		},
		Permission: &personserver.PermissionConfig{
			Store: localStore,
			Policy: func(_ context.Context, request personserver.PermissionPolicyRequest) (personserver.PermissionPolicyResult, error) {
				if request.Agent != agentID || request.Mission != nil || request.Action != "workspace.inspect" {
					return personserver.PermissionPolicyResult{}, errors.New("self-hosted example: unexpected local permission")
				}
				return personserver.PermissionPolicyResult{Immediate: &personserver.PermissionDecision{
					Permission: aauth.PermissionGranted,
				}}, nil
			},
		},
	})
	if err != nil {
		return err
	}
	network.Handle(personServerID, people.Handler())
	protected, err := resource.NewAgentIdentity(resource.AgentIdentityConfig{
		Issuer: resourceID, KeyResolver: resolver, Clock: clock,
		Protected: http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			principal, ok := resource.AgentPrincipalFromContext(request.Context())
			if !ok {
				http.Error(response, "missing Agent principal", http.StatusInternalServerError)
				return
			}
			_, _ = io.WriteString(response, principal.Agent)
		}),
	})
	if err != nil {
		return err
	}
	network.Handle(resourceID, protected.Handler())
	client, err := clientagent.New(ctx, clientagent.Config{
		Identifier: agentID, SigningKey: key, AgentToken: compact,
		KeyResolver: resolver, HTTPClient: httpClient, Clock: clock,
	})
	if err != nil {
		return err
	}
	permission, err := client.RequestPermission(ctx, clientagent.PermissionRequest{
		PersonServer: personServerID, Action: "workspace.inspect",
		Description: "Inspect the local workspace without changing it.",
	})
	if err != nil {
		return err
	}
	decision, ok := permission.Decision()
	if !ok || decision.Permission() != aauth.PermissionGranted {
		return errors.New("self-hosted example: local permission was not granted")
	}
	if _, err := fmt.Fprintln(output, "AAuth local permission granted: workspace.inspect"); err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, resourceID+"/records", nil)
	if err != nil {
		return err
	}
	response, err := client.CallAsAgent(ctx, request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return err
	}
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("Resource returned %s: %s", response.Status, body)
	}
	_, err = fmt.Fprintf(output, "AAuth self-hosted Agent accepted: %s\n", body)
	return err
}

func newSigningKey(id string) (jose.SigningKey, error) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return jose.SigningKey{}, err
	}
	return jose.NewEd25519SigningKey(id, privateKey)
}

type logicalTransport struct {
	mu     sync.RWMutex
	routes map[string]http.Handler
}

func newLogicalTransport() *logicalTransport {
	return &logicalTransport{routes: make(map[string]http.Handler)}
}

func (transport *logicalTransport) Handle(origin string, handler http.Handler) {
	transport.mu.Lock()
	defer transport.mu.Unlock()
	transport.routes[origin] = handler
}

func (transport *logicalTransport) Admit(_ context.Context, endpoint string) error {
	request, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	origin := request.URL.Scheme + "://" + request.URL.Host
	transport.mu.RLock()
	_, ok := transport.routes[origin]
	transport.mu.RUnlock()
	if !ok {
		return errors.New("self-hosted example: endpoint origin is not admitted")
	}
	return nil
}

func (transport *logicalTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if request.Body != nil {
		defer request.Body.Close()
	}
	origin := request.URL.Scheme + "://" + request.URL.Host
	transport.mu.RLock()
	handler := transport.routes[origin]
	transport.mu.RUnlock()
	if handler == nil {
		return nil, fmt.Errorf("self-hosted example: no handler for %s", origin)
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	response := recorder.Result()
	response.Request = request
	return response, nil
}
