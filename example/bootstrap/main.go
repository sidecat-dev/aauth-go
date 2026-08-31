// The bootstrap example runs the repository's explicit two-key Agent
// enrollment profile. Bootstrap leaves endpoint discovery and JSON envelopes
// to each Agent Provider, so the host selects and mounts both routes here.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"time"

	aauth "aauth-go"
	clientagent "aauth-go/agent"
	"aauth-go/agentprovider"
	"aauth-go/internal/exampleutil"
	"aauth-go/jose"
	"aauth-go/resource"
	"aauth-go/signaturekey"
)

const (
	agentProviderID = "https://agents.example"
	agentID         = "aauth:reference@agents.example"
	personServerID  = "https://person.example"
	resourceID      = "https://resource.example"
)

func main() {
	if err := run(os.Stdout); err != nil {
		log.Fatal(err)
	}
}

func run(output io.Writer) error {
	ctx := context.Background()
	now := time.Date(2026, 8, 31, 5, 30, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	providerKey, err := newSigningKey("agent-provider-key")
	if err != nil {
		return err
	}
	durableKey, err := newSigningKey("durable-enrollment-key")
	if err != nil {
		return err
	}
	ephemeralKey, err := newSigningKey("current-agent-key")
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
	// These literal checks demonstrate host policy injection, not platform or
	// account attestation. A deployment validates its own trusted evidence.
	service, err := agentprovider.NewEnrollmentService(agentprovider.EnrollmentServiceConfig{
		Provider: provider, Store: exampleutil.NewEnrollmentStore(clock),
		Enroll: func(_ context.Context, request agentprovider.EnrollmentRequest) (agentprovider.EnrollmentDecision, error) {
			if string(request.Evidence) != `{"account":"person-1"}` {
				return agentprovider.EnrollmentDecision{}, agentprovider.ErrEnrollmentDenied
			}
			return agentprovider.EnrollmentDecision{Agent: agentID}, nil
		},
		Refresh: func(_ context.Context, request agentprovider.RefreshRequest) (agentprovider.RefreshDecision, error) {
			if request.RequestedPersonServer != personServerID || string(request.Evidence) != `{"posture":"current"}` {
				return agentprovider.RefreshDecision{}, agentprovider.ErrRefreshDenied
			}
			return agentprovider.RefreshDecision{
				PersonServer: personServerID, Lifetime: 30 * time.Minute,
				AdditionalClaims: map[string]json.RawMessage{"profile": json.RawMessage(`"two-key"`)},
			}, nil
		},
	})
	if err != nil {
		return err
	}
	network := newLogicalTransport()
	httpClient := &http.Client{Transport: network}
	resolver, err := signaturekey.NewHTTPKeyResolver(signaturekey.HTTPKeyResolverConfig{
		Client: httpClient, Clock: clock, Admit: network.Admit,
	})
	if err != nil {
		return err
	}
	network.Handle(agentProviderID, providerWithBootstrap(provider, service))
	bootstrap, err := clientagent.NewBootstrapClient(clientagent.BootstrapConfig{
		AgentProvider:      agentProviderID,
		EnrollmentEndpoint: agentProviderID + "/internal/enrollment",
		RefreshEndpoint:    agentProviderID + "/internal/refresh",
		DurableKey:         durableKey, KeyResolver: resolver, HTTPClient: httpClient, Clock: clock,
	})
	if err != nil {
		return err
	}
	enrollment, err := bootstrap.Enroll(ctx, json.RawMessage(`{"account":"person-1"}`))
	if err != nil {
		return err
	}
	refreshed, err := bootstrap.Refresh(ctx, clientagent.RefreshAgentTokenInput{
		Agent: enrollment.Agent, PersonServer: personServerID,
		Evidence: json.RawMessage(`{"posture":"current"}`), SigningKey: ephemeralKey,
		DelegationJTI: "example-refresh-1", DelegationIssuedAt: now,
		DelegationExpiresAt: now.Add(10 * time.Minute),
	})
	if err != nil {
		return err
	}
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
	authenticated, err := clientagent.New(ctx, clientagent.Config{
		Identifier: enrollment.Agent, SigningKey: ephemeralKey,
		AgentToken: refreshed.AgentToken, KeyResolver: resolver,
		HTTPClient: httpClient, Clock: clock,
	})
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, resourceID+"/records", nil)
	if err != nil {
		return err
	}
	response, err := authenticated.CallAsAgent(ctx, request)
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
	_, err = fmt.Fprintf(output, "AAuth two-key bootstrap complete: %s\n", body)
	return err
}

func providerWithBootstrap(provider *agentprovider.Server, service *agentprovider.EnrollmentService) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/internal/enrollment":
			service.EnrollmentHandler().ServeHTTP(response, request)
		case "/internal/refresh":
			service.RefreshHandler().ServeHTTP(response, request)
		default:
			provider.Handler().ServeHTTP(response, request)
		}
	})
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
		return errors.New("example bootstrap: discovery origin is not admitted")
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
		return nil, fmt.Errorf("example bootstrap: no handler for %s", origin)
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	response := recorder.Result()
	response.Request = request
	return response, nil
}
