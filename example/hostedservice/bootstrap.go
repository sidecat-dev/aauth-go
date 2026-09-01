package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"sync/atomic"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	clientagent "gitlab.com/sidecat-dev/aauth-go/agent"
	"gitlab.com/sidecat-dev/aauth-go/agentprovider"
	"gitlab.com/sidecat-dev/aauth-go/internal/exampleutil"
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/r3"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

type bootstrappedAgent struct {
	provider   *agentprovider.Server
	client     *clientagent.Client
	agentToken string
}

func bootstrapHostedAgent(
	ctx context.Context,
	now time.Time,
	clock aauth.Clock,
	network *logicalTransport,
	httpClient *http.Client,
	resolver signaturekey.KeyResolver,
	registry r3.Registry,
	providerKey, durableKey, agentKey jose.SigningKey,
) (bootstrappedAgent, error) {
	var agentTokenIDs atomic.Int64
	provider, err := agentprovider.New(agentprovider.Config{
		Issuer: agentProviderID, SigningKey: providerKey, Clock: clock,
		NewID: func() string { return fmt.Sprintf("agent-token-%d", agentTokenIDs.Add(1)) },
	})
	if err != nil {
		return bootstrappedAgent{}, err
	}
	enrollmentService, err := agentprovider.NewEnrollmentService(agentprovider.EnrollmentServiceConfig{
		Provider: provider, Store: exampleutil.NewEnrollmentStore(clock),
		Enroll: func(_ context.Context, request agentprovider.EnrollmentRequest) (agentprovider.EnrollmentDecision, error) {
			if string(request.Evidence) != `{"account":"person-123"}` {
				return agentprovider.EnrollmentDecision{}, agentprovider.ErrEnrollmentDenied
			}
			return agentprovider.EnrollmentDecision{Agent: agentID}, nil
		},
		Refresh: func(_ context.Context, request agentprovider.RefreshRequest) (agentprovider.RefreshDecision, error) {
			if request.RequestedPersonServer != personServerID || string(request.Evidence) != `{"posture":"current"}` {
				return agentprovider.RefreshDecision{}, agentprovider.ErrRefreshDenied
			}
			return agentprovider.RefreshDecision{PersonServer: personServerID, Lifetime: 30 * time.Minute}, nil
		},
	})
	if err != nil {
		return bootstrappedAgent{}, err
	}
	network.Handle(agentProviderID, providerWithBootstrap(provider, enrollmentService))
	bootstrap, err := clientagent.NewBootstrapClient(clientagent.BootstrapConfig{
		AgentProvider: agentProviderID, EnrollmentEndpoint: agentProviderID + "/internal/enrollment",
		RefreshEndpoint: agentProviderID + "/internal/refresh", DurableKey: durableKey,
		KeyResolver: resolver, HTTPClient: httpClient, Clock: clock,
	})
	if err != nil {
		return bootstrappedAgent{}, err
	}
	enrollment, err := bootstrap.Enroll(ctx, json.RawMessage(`{"account":"person-123"}`))
	if err != nil {
		return bootstrappedAgent{}, err
	}
	refreshed, err := bootstrap.Refresh(ctx, clientagent.RefreshAgentTokenInput{
		Agent: enrollment.Agent, PersonServer: personServerID,
		Evidence: json.RawMessage(`{"posture":"current"}`), SigningKey: agentKey,
		DelegationJTI: "hosted-refresh-1", DelegationIssuedAt: now,
		DelegationExpiresAt: now.Add(10 * time.Minute),
	})
	if err != nil {
		return bootstrappedAgent{}, err
	}
	client, err := clientagent.New(ctx, clientagent.Config{
		Identifier: enrollment.Agent, SigningKey: agentKey, AgentToken: refreshed.AgentToken,
		KeyResolver: resolver, HTTPClient: httpClient, Clock: clock,
		R3: &clientagent.R3Config{Registry: registry},
	})
	if err != nil {
		return bootstrappedAgent{}, err
	}
	return bootstrappedAgent{provider: provider, client: client, agentToken: refreshed.AgentToken}, nil
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
