package agentprovider_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/agentprovider"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

func TestSelfHostedAgentPublishesAndSelfIssuesWithOneKey(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 31, 8, 30, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	key := testSigningKey(t, "self-hosted-key", 0xc1)
	ids := []string{"self-hosted-token-1", "self-hosted-token-2"}
	selfHosted, err := agentprovider.NewSelfHostedAgent(agentprovider.SelfHostedAgentConfig{
		Issuer: "https://agent.example", Agent: "aauth:local@agent.example",
		SigningKey: key, Clock: clock,
		NewID: func() string { id := ids[0]; ids = ids[1:]; return id },
	})
	if err != nil {
		t.Fatal(err)
	}
	metadataResponse := httptest.NewRecorder()
	selfHosted.Handler().ServeHTTP(metadataResponse, httptest.NewRequest(
		http.MethodGet, "https://agent.example/.well-known/aauth-agent.json", nil,
	))
	var metadata map[string]string
	if metadataResponse.Code != http.StatusOK || json.Unmarshal(metadataResponse.Body.Bytes(), &metadata) != nil ||
		metadata["issuer"] != "https://agent.example" || metadata["jwks_uri"] != "https://agent.example/.well-known/jwks.json" {
		t.Fatalf("metadata = %d %s", metadataResponse.Code, metadataResponse.Body.String())
	}
	compact, err := selfHosted.Issue(agentprovider.SelfHostedAgentTokenRequest{
		PersonServer: "https://ps.example", Lifetime: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	claims, err := aauth.VerifyAgentToken(context.Background(), compact, signaturekey.StaticKeyResolver{
		{Issuer: "https://agent.example", DiscoveryDocument: aauth.AgentDiscoveryDocument, KeyID: key.ID()}: key.PublicJWK(),
	}, clock)
	if err != nil {
		t.Fatal(err)
	}
	if claims.Subject != "aauth:local@agent.example" || claims.PersonServer != "https://ps.example" ||
		claims.JTI != "self-hosted-token-1" || !claims.Confirmation.JWK.Equal(key.PublicJWK()) {
		t.Fatalf("claims = %#v", claims)
	}
	now = now.Add(time.Minute)
	next, err := selfHosted.Issue(agentprovider.SelfHostedAgentTokenRequest{Lifetime: time.Hour})
	if err != nil || next == compact || len(ids) != 0 {
		t.Fatalf("reissue = equal %v, remaining IDs=%v, error=%v", next == compact, ids, err)
	}
}

func TestSelfHostedAgentRejectsIdentityOutsideItsIssuer(t *testing.T) {
	t.Parallel()
	key := testSigningKey(t, "self-hosted-invalid-key", 0xc2)
	_, err := agentprovider.NewSelfHostedAgent(agentprovider.SelfHostedAgentConfig{
		Issuer: "https://agent.example", Agent: "aauth:local@other.example",
		SigningKey: key, Clock: aauth.ClockFunc(time.Now), NewID: func() string { return "unused" },
	})
	if err == nil {
		t.Fatal("self-hosted Agent accepted an identity outside its issuer")
	}
}
