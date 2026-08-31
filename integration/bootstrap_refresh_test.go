package integration_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	aauth "aauth-go"
	clientagent "aauth-go/agent"
	"aauth-go/agentprovider"
	"aauth-go/resource"
	"aauth-go/signaturekey"
)

func TestTwoKeyBootstrapRefreshPerformsDirectAgentCallAcrossRecomposition(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	now := time.Date(2026, 8, 31, 5, 20, 0, 0, time.UTC)
	current := now
	clock := aauth.ClockFunc(func() time.Time { return current })
	const (
		agentProviderID = "https://ap.example"
		agentID         = "aauth:reference@ap.example"
		personServerID  = "https://ps.example"
		resourceID      = "https://resource.example"
	)
	providerKey := newSigningKey(t, "bootstrap-ap-key")
	durable := newSigningKey(t, "bootstrap-durable-key")
	ephemeral := newSigningKey(t, "bootstrap-ephemeral-key")
	issuedIDs := 0
	provider, err := agentprovider.New(agentprovider.Config{
		Issuer: agentProviderID, SigningKey: providerKey, Clock: clock,
		NewID: func() string {
			issuedIDs++
			return fmt.Sprintf("bootstrap-agent-token-%d", issuedIDs)
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
	refreshPolicyCalls := 0
	newService := func() *agentprovider.EnrollmentService {
		service, err := agentprovider.NewEnrollmentService(agentprovider.EnrollmentServiceConfig{
			Provider: provider, Store: store,
			Enroll: func(_ context.Context, request agentprovider.EnrollmentRequest) (agentprovider.EnrollmentDecision, error) {
				if request.Identity != durableIdentity || string(request.Evidence) != `{"account":"person-1"}` {
					t.Fatalf("enrollment request = %#v", request)
				}
				return agentprovider.EnrollmentDecision{Agent: agentID}, nil
			},
			Refresh: func(_ context.Context, request agentprovider.RefreshRequest) (agentprovider.RefreshDecision, error) {
				refreshPolicyCalls++
				if request.Enrollment.Agent != agentID || request.RequestedPersonServer != personServerID ||
					!request.Delegation.ConfirmationKey().Equal(ephemeral.PublicJWK()) ||
					string(request.Evidence) != `{"posture":"current"}` {
					t.Fatalf("refresh request = %#v", request)
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
				service.RefreshHandler().ServeHTTP(response, request)
			default:
				provider.Handler().ServeHTTP(response, request)
			}
		})
	}

	network := newLogicalTransport()
	network.Handle(agentProviderID, composeProvider(newService()))
	httpClient := &http.Client{Transport: network}
	resolver, err := signaturekey.NewHTTPKeyResolver(signaturekey.HTTPKeyResolverConfig{
		Client: httpClient, Clock: clock,
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
	refreshInput := clientagent.RefreshAgentTokenInput{
		Agent: enrollment.Agent, PersonServer: personServerID,
		Evidence: json.RawMessage(`{"posture":"current"}`), SigningKey: ephemeral,
		DelegationJTI: "bootstrap-refresh-1", DelegationIssuedAt: now,
		DelegationExpiresAt: now.Add(10 * time.Minute),
	}
	first, err := bootstrap.Refresh(ctx, refreshInput)
	if err != nil {
		t.Fatal(err)
	}
	current = now.Add(2 * time.Minute)
	network.Handle(agentProviderID, composeProvider(newService()))
	replayed, err := bootstrap.Refresh(ctx, refreshInput)
	if err != nil {
		t.Fatal(err)
	}
	if replayed.AgentToken != first.AgentToken || issuedIDs != 1 || refreshPolicyCalls != 1 {
		t.Fatalf("replay token match=%v, issued=%d, policy calls=%d", replayed.AgentToken == first.AgentToken, issuedIDs, refreshPolicyCalls)
	}

	protectedCalls := 0
	protected, err := resource.NewAgentIdentity(resource.AgentIdentityConfig{
		Issuer: resourceID, KeyResolver: resolver, Clock: clock,
		Protected: http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			protectedCalls++
			principal, ok := resource.AgentPrincipalFromContext(request.Context())
			if !ok || principal.AgentProvider != agentProviderID || principal.Agent != agentID ||
				!principal.Confirmation.Equal(ephemeral.PublicJWK()) {
				t.Fatalf("protected principal = %#v, present=%v", principal, ok)
			}
			_, _ = io.WriteString(response, "bootstrap identity accepted")
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	network.Handle(resourceID, protected.Handler())
	authenticated, err := clientagent.New(ctx, clientagent.Config{
		Identifier: agentID, SigningKey: ephemeral, AgentToken: first.AgentToken,
		KeyResolver: resolver, HTTPClient: httpClient, Clock: clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, resourceID+"/records", nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := authenticated.CallAsAgent(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode != http.StatusOK || string(body) != "bootstrap identity accepted" || protectedCalls != 1 {
		t.Fatalf("protected response = %d %q, calls=%d", response.StatusCode, body, protectedCalls)
	}
}
