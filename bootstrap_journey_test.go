package aauth_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/reference"
)

func TestTwoKeyBootstrapIssuesAUsableAgentTokenWithStableInstallIdentity(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 27, 12, 30, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	apKey := testSigningKey(t, "ap-key")
	psKey := testSigningKey(t, "ps-key")
	durable := testSigningKey(t, "install-key")
	firstEphemeral := testSigningKey(t, "ephemeral-1")
	secondEphemeral := testSigningKey(t, "ephemeral-2")
	durableThumbprint, err := durable.PublicJWK().Thumbprint()
	if err != nil {
		t.Fatal(err)
	}
	ids := sequentialIDs("agent-token-1", "agent-token-2", "mission-1")

	provider, err := reference.NewAgentProvider(reference.AgentProviderConfig{
		Identifier: "https://ap.example",
		SigningKey: apKey,
		Clock:      clock,
		NewID:      ids,
		Enrollments: reference.StaticEnrollmentStore{
			durableThumbprint: {
				Agent:        "aauth:install-01@ap.example",
				PersonServer: "https://ps.example",
			},
		},
		AgentTokenLifetime: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	person, err := reference.NewPersonServer(reference.PersonServerConfig{
		Identifier: "https://ps.example",
		SigningKey: psKey,
		KeyResolver: aauth.StaticKeyResolver{
			"https://ap.example": {"ap-key": apKey.PublicJWK()},
		},
		Clock: clock,
		NewID: ids,
		MissionPolicy: func(_ context.Context, proposal aauth.MissionProposal) (aauth.MissionDecision, error) {
			return aauth.MissionDecision{
				Description: proposal.Description,
				Tools:       proposal.Tools,
			}, nil
		},
		AuthorizationPolicy: func(_ context.Context, request aauth.AuthorizationRequest) (aauth.AuthorizationDecision, error) {
			return aauth.AuthorizationDecision{Subject: "subject", Scope: request.Scope}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	gateway := newLogicalGateway(t, map[string]http.Handler{
		"ap.example": provider.Handler(),
		"ps.example": person.Handler(),
	})
	defer gateway.Close()

	resolver, err := aauth.NewHTTPKeyResolver(aauth.HTTPKeyResolverConfig{
		Client: gateway.Client(),
		Clock:  clock,
		Admit: func(_ context.Context, endpoint string) error {
			if strings.HasPrefix(endpoint, "https://ap.example/") {
				return nil
			}
			return io.ErrUnexpectedEOF
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	client, err := reference.NewBootstrapClient(reference.BootstrapClientConfig{
		DurableKey:         durable,
		KeyResolver:        resolver,
		HTTPClient:         gateway.Client(),
		Clock:              clock,
		DelegationLifetime: 5 * time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}

	first, err := client.Refresh(
		context.Background(),
		"https://ap.example/refresh",
		"https://ps.example",
		firstEphemeral,
	)
	if err != nil {
		t.Fatal(err)
	}
	second, err := client.Refresh(
		context.Background(),
		"https://ap.example/refresh",
		"https://ps.example",
		secondEphemeral,
	)
	if err != nil {
		t.Fatal(err)
	}
	if first.Identifier != "aauth:install-01@ap.example" ||
		second.Identifier != first.Identifier {
		t.Fatalf("bootstrap identifiers = %q, %q", first.Identifier, second.Identifier)
	}
	if first.Claims.Confirmation.JWK.Equal(second.Claims.Confirmation.JWK) ||
		!first.Claims.Confirmation.JWK.Equal(firstEphemeral.PublicJWK()) ||
		!second.Claims.Confirmation.JWK.Equal(secondEphemeral.PublicJWK()) {
		t.Fatal("ephemeral confirmation keys did not rotate with stable install identity")
	}

	agent, err := reference.NewAgent(reference.AgentConfig{
		Identifier:  second.Identifier,
		SigningKey:  secondEphemeral,
		AgentToken:  second.AgentToken,
		KeyResolver: resolver,
		HTTPClient:  gateway.Client(),
		Clock:       clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	mission, err := agent.CreateMission(
		context.Background(),
		"https://ps.example/mission",
		aauth.MissionProposal{Description: "Prove the bootstrapped agent is usable."},
	)
	if err != nil {
		t.Fatal(err)
	}
	if mission.Reference.Approver != "https://ps.example" {
		t.Fatalf("mission approver = %q", mission.Reference.Approver)
	}
}

func TestBootstrapRefusesUnknownInstallAndExactRequestReplay(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 27, 12, 30, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	apKey := testSigningKey(t, "ap-key")
	enrolledDurable := testSigningKey(t, "known-install")
	unknownDurable := testSigningKey(t, "unknown-install")
	ephemeral := testSigningKey(t, "ephemeral")
	thumbprint, err := enrolledDurable.PublicJWK().Thumbprint()
	if err != nil {
		t.Fatal(err)
	}
	provider, err := reference.NewAgentProvider(reference.AgentProviderConfig{
		Identifier: "https://ap.example",
		SigningKey: apKey,
		Clock:      clock,
		NewID:      sequentialIDs("agent-token-1", "agent-token-2"),
		Enrollments: reference.StaticEnrollmentStore{
			thumbprint: {
				Agent:        "aauth:known-install@ap.example",
				PersonServer: "https://ps.example",
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	server := newLogicalGateway(t, map[string]http.Handler{
		"ap.example": provider.Handler(),
	})
	defer server.Close()

	unknownClient, err := reference.NewBootstrapClient(reference.BootstrapClientConfig{
		DurableKey: unknownDurable,
		KeyResolver: aauth.StaticKeyResolver{
			"https://ap.example": {"ap-key": apKey.PublicJWK()},
		},
		HTTPClient: server.Client(),
		Clock:      clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := unknownClient.Refresh(
		context.Background(),
		"https://ap.example/refresh",
		"https://ps.example",
		ephemeral,
	); err == nil || !strings.Contains(err.Error(), "unknown_enrollment") {
		t.Fatalf("unknown enrollment error = %v", err)
	}

	knownClient, err := reference.NewBootstrapClient(reference.BootstrapClientConfig{
		DurableKey: enrolledDurable,
		KeyResolver: aauth.StaticKeyResolver{
			"https://ap.example": {"ap-key": apKey.PublicJWK()},
		},
		HTTPClient: server.Client(),
		Clock:      clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := knownClient.Refresh(
		context.Background(),
		"https://ap.example/refresh",
		"https://other-person.example",
		testSigningKey(t, "other-person-ephemeral"),
	); err == nil || !strings.Contains(err.Error(), "person_server_not_allowed") {
		t.Fatalf("unenrolled person-server error = %v", err)
	}

	overlongClient, err := reference.NewBootstrapClient(reference.BootstrapClientConfig{
		DurableKey: enrolledDurable,
		KeyResolver: aauth.StaticKeyResolver{
			"https://ap.example": {"ap-key": apKey.PublicJWK()},
		},
		HTTPClient:         server.Client(),
		Clock:              clock,
		DelegationLifetime: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := overlongClient.Refresh(
		context.Background(),
		"https://ap.example/refresh",
		"https://ps.example",
		testSigningKey(t, "overlong-ephemeral"),
	); err == nil || !strings.Contains(err.Error(), "delegation_too_long") {
		t.Fatalf("overlong delegation error = %v", err)
	}

	body, err := json.Marshal(reference.BootstrapRefreshRequest{
		PersonServer: "https://ps.example",
	})
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest(
		http.MethodPost,
		"https://ap.example/refresh",
		bytes.NewReader(body),
	)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	delegation, err := aauth.MintJKTJWT(
		enrolledDurable,
		ephemeral.PublicJWK(),
		now,
		5*time.Minute,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := aauth.SignRequestWithJKTJWT(request, ephemeral, delegation, clock); err != nil {
		t.Fatal(err)
	}

	first, err := server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	first.Body.Close()
	if first.StatusCode != http.StatusOK {
		t.Fatalf("first refresh status = %d", first.StatusCode)
	}
	replay := request.Clone(context.Background())
	replay.Body, err = request.GetBody()
	if err != nil {
		t.Fatal(err)
	}
	second, err := server.Client().Do(replay)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Body.Close()
	if second.StatusCode != http.StatusUnauthorized {
		body, _ := io.ReadAll(second.Body)
		t.Fatalf("replayed refresh status = %d, body = %s", second.StatusCode, body)
	}
}

func TestSingleKeyBootstrapCarriesTheDurableKeyIntoTheAgentToken(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 27, 12, 45, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	apKey := testSigningKey(t, "ap-key")
	durable := testSigningKey(t, "install-key")
	thumbprint, err := durable.PublicJWK().Thumbprint()
	if err != nil {
		t.Fatal(err)
	}
	provider, err := reference.NewAgentProvider(reference.AgentProviderConfig{
		Identifier: "https://ap.example",
		SigningKey: apKey,
		Clock:      clock,
		NewID:      sequentialIDs("agent-token-1"),
		Enrollments: reference.StaticEnrollmentStore{
			thumbprint: {
				Agent:        "aauth:single-key@ap.example",
				PersonServer: "https://ps.example",
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	server := newLogicalGateway(t, map[string]http.Handler{
		"ap.example": provider.Handler(),
	})
	defer server.Close()

	client, err := reference.NewBootstrapClient(reference.BootstrapClientConfig{
		DurableKey: durable,
		KeyResolver: aauth.StaticKeyResolver{
			"https://ap.example": {"ap-key": apKey.PublicJWK()},
		},
		HTTPClient: server.Client(),
		Clock:      clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := client.RefreshSingleKey(
		context.Background(),
		"https://ap.example/refresh",
		"https://ps.example",
	)
	if err != nil {
		t.Fatal(err)
	}
	if result.Identifier != "aauth:single-key@ap.example" ||
		!result.Claims.Confirmation.JWK.Equal(durable.PublicJWK()) ||
		!result.SigningKey.PublicJWK().Equal(durable.PublicJWK()) {
		t.Fatalf("single-key bootstrap result = %#v", result)
	}
}
