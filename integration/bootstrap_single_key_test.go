package integration_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	clientagent "gitlab.com/sidecat-dev/aauth-go/agent"
	"gitlab.com/sidecat-dev/aauth-go/agentprovider"
	"gitlab.com/sidecat-dev/aauth-go/resource"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

func TestSingleKeyBootstrapRefreshPerformsDirectAgentCallAcrossRecomposition(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	now := time.Date(2026, 8, 31, 7, 40, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	const (
		agentProviderID = "https://ap.example"
		agentID         = "aauth:single@ap.example"
		personServerID  = "https://ps.example"
		resourceID      = "https://resource.example"
	)
	providerKey := newSigningKey(t, "single-bootstrap-ap")
	durable := newSigningKey(t, "single-bootstrap-durable")
	issuedIDs := 0
	provider, err := agentprovider.New(agentprovider.Config{
		Issuer: agentProviderID, SigningKey: providerKey, Clock: clock,
		NewID: func() string {
			issuedIDs++
			return fmt.Sprintf("single-bootstrap-agent-token-%d", issuedIDs)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	durableIdentity, err := durable.PublicJWK().ThumbprintURI()
	if err != nil {
		t.Fatal(err)
	}
	store := newIntegrationEnrollmentStore(clock)
	policyCalls := 0
	newService := func() *agentprovider.EnrollmentService {
		service, err := agentprovider.NewEnrollmentService(agentprovider.EnrollmentServiceConfig{
			Provider: provider,
			Store:    store,
			Enroll: func(_ context.Context, request agentprovider.EnrollmentRequest) (agentprovider.EnrollmentDecision, error) {
				if request.Identity != durableIdentity {
					t.Fatalf("enrollment request = %#v", request)
				}
				return agentprovider.EnrollmentDecision{Agent: agentID}, nil
			},
			Refresh: func(_ context.Context, request agentprovider.RefreshRequest) (agentprovider.RefreshDecision, error) {
				policyCalls++
				if request.Profile != agentprovider.RefreshProfileSingleKey || request.Delegation.JTI() != "" ||
					request.Enrollment.Agent != agentID || request.RequestedPersonServer != personServerID ||
					string(request.Evidence) != `{"posture":"current"}` {
					t.Fatalf("single-key refresh request = %#v", request)
				}
				return agentprovider.RefreshDecision{PersonServer: personServerID, Lifetime: 30 * time.Minute}, nil
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		return service
	}
	composeProvider := func(service *agentprovider.EnrollmentService) http.Handler {
		return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			switch request.URL.Path {
			case "/internal/enrollment":
				service.EnrollmentHandler().ServeHTTP(response, request)
			case "/internal/refresh":
				service.SingleKeyRefreshHandler().ServeHTTP(response, request)
			default:
				provider.Handler().ServeHTTP(response, request)
			}
		})
	}

	network := newLogicalTransport()
	network.Handle(agentProviderID, composeProvider(newService()))
	httpClient := &http.Client{Transport: network}
	resolver, err := signaturekey.NewHTTPKeyResolver(signaturekey.HTTPKeyResolverConfig{
		Client: httpClient,
		Clock:  clock,
		Admit: func(_ context.Context, endpoint string) error {
			if endpoint != agentProviderID+"/.well-known/aauth-agent.json" &&
				endpoint != agentProviderID+"/.well-known/jwks.json" {
				return fmt.Errorf("unexpected discovery endpoint %s", endpoint)
			}
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	bootstrap, err := clientagent.NewBootstrapClient(clientagent.BootstrapConfig{
		AgentProvider:      agentProviderID,
		EnrollmentEndpoint: agentProviderID + "/internal/enrollment",
		RefreshEndpoint:    agentProviderID + "/internal/refresh",
		DurableKey:         durable, KeyResolver: resolver, HTTPClient: httpClient, Clock: clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	enrollment, err := bootstrap.Enroll(ctx, json.RawMessage(`{"account":"person-1"}`))
	if err != nil {
		t.Fatal(err)
	}
	input := clientagent.SingleKeyRefreshAgentTokenInput{
		Agent: enrollment.Agent, PersonServer: personServerID,
		Evidence:   json.RawMessage(`{"posture":"current"}`),
		RefreshJTI: "single-bootstrap-refresh-1", RefreshExpiresAt: now.Add(10 * time.Minute),
	}
	first, err := bootstrap.RefreshSingleKey(ctx, input)
	if err != nil {
		t.Fatal(err)
	}
	network.Handle(agentProviderID, composeProvider(newService()))
	replayed, err := bootstrap.RefreshSingleKey(ctx, input)
	if err != nil {
		t.Fatal(err)
	}
	if replayed.AgentToken != first.AgentToken || issuedIDs != 1 || policyCalls != 1 {
		t.Fatalf("replay token match=%v, issued=%d, policy calls=%d", replayed.AgentToken == first.AgentToken, issuedIDs, policyCalls)
	}

	protected, err := resource.NewAgentIdentity(resource.AgentIdentityConfig{
		Issuer: resourceID, KeyResolver: resolver, Clock: clock,
		Protected: http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			principal, ok := resource.AgentPrincipalFromContext(request.Context())
			if !ok || principal.Agent != agentID || !principal.Confirmation.Equal(durable.PublicJWK()) {
				t.Fatalf("protected principal = %#v, present=%v", principal, ok)
			}
			_, _ = io.WriteString(response, "single-key identity accepted")
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	network.Handle(resourceID, protected.Handler())
	authenticated, err := clientagent.New(ctx, clientagent.Config{
		Identifier: agentID, SigningKey: durable, AgentToken: first.AgentToken,
		KeyResolver: resolver, HTTPClient: httpClient, Clock: clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	request, _ := http.NewRequestWithContext(ctx, http.MethodGet, resourceID+"/records", nil)
	response, err := authenticated.CallAsAgent(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode != http.StatusOK || string(body) != "single-key identity accepted" {
		t.Fatalf("protected response = %d %q", response.StatusCode, body)
	}
}
