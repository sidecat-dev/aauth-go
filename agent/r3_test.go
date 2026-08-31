package agent_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"io"
	"net/http"
	"reflect"
	"testing"
	"time"

	aauth "aauth-go"
	"aauth-go/agent"
	"aauth-go/jose"
	"aauth-go/r3"
	"aauth-go/signaturekey"
)

func TestClientMCPR3AuthorizesAndExchangesScopelessDirectGrant(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 31, 11, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	providerKey := agentR3Key(t, "provider-key", 1)
	personKey := agentR3Key(t, "person-key", 2)
	resourceKey := agentR3Key(t, "resource-key", 3)
	accessKey := agentR3Key(t, "access-key", 4)
	agentKey := agentR3Key(t, "agent-key", 5)
	resolver := signaturekey.StaticKeyResolver{
		{Issuer: "https://provider.example", DiscoveryDocument: aauth.AgentDiscoveryDocument, KeyID: providerKey.ID()}:    providerKey.PublicJWK(),
		{Issuer: "https://person.example", DiscoveryDocument: aauth.PersonDiscoveryDocument, KeyID: personKey.ID()}:       personKey.PublicJWK(),
		{Issuer: "https://resource.example", DiscoveryDocument: aauth.ResourceDiscoveryDocument, KeyID: resourceKey.ID()}: resourceKey.PublicJWK(),
		{Issuer: "https://access.example", DiscoveryDocument: aauth.AccessDiscoveryDocument, KeyID: accessKey.ID()}:       accessKey.PublicJWK(),
	}
	agentToken, err := aauth.MintAgentToken(
		"https://provider.example", providerKey,
		aauth.AgentTokenRequest{
			Agent: "aauth:planner@provider.example", PersonServer: "https://person.example",
			PublicKey: agentKey.PublicJWK(), Lifetime: time.Hour,
		}, now, "agent-token-1",
	)
	if err != nil {
		t.Fatal(err)
	}
	personToken, err := aauth.MintPersonToken(personKey, aauth.PersonTokenClaims{
		Issuer: "https://person.example", DWK: aauth.PersonDiscoveryDocument,
		Audience: "https://resource.example", Subject: "person-123", JTI: "person-token-1",
		Confirmation: aauth.Confirmation{JWK: agentKey.PublicJWK()},
		IssuedAt:     now.Unix(), ExpiresAt: now.Add(time.Hour).Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	agentJKT, _ := agentKey.PublicJWK().Thumbprint()
	account := "work-account"
	read, _ := r3.NewMCPOperation("records.read")
	operations, _ := r3.NewMCPOperationSet(read)
	document, _ := r3.NewDocument(operations, r3.DocumentOptions{Account: &account})
	exactDocument, _ := json.Marshal(document)
	reference, _ := r3.NewReference("https://resource.example/r3/document", r3.Digest(exactDocument))
	resourceToken, _, err := r3.MintMCPResourceToken(resourceKey, aauth.ResourceTokenClaims{
		Issuer: "https://resource.example", DWK: aauth.ResourceDiscoveryDocument,
		Audience: "https://access.example", JTI: "resource-token-1", AgentJKT: agentJKT,
		IssuedAt: now.Unix(), ExpiresAt: now.Add(5 * time.Minute).Unix(),
		PersonServer: "https://person.example", Subject: "person-123", PresentedJTI: "person-token-1",
		Account: &account,
	}, reference.URI(), exactDocument)
	if err != nil {
		t.Fatal(err)
	}
	granted, _ := r3.NewGrantedOperations(read)
	grant, _ := r3.NewGrant(granted, document)
	authToken, err := r3.MintMCPDirectAuthToken(accessKey, aauth.AuthTokenClaims{
		Issuer: "https://access.example", DWK: aauth.AccessDiscoveryDocument,
		Audience: "https://resource.example", JTI: "auth-token-1",
		PersonServer: "https://person.example", Subject: "person-123", Account: &account,
		Confirmation: aauth.Confirmation{JWK: agentKey.PublicJWK()},
		IssuedAt:     now.Unix(), ExpiresAt: now.Add(30 * time.Minute).Unix(),
	}, reference, exactDocument, grant)
	if err != nil {
		t.Fatal(err)
	}
	var authorizeInput struct {
		Scope        *string             `json:"scope"`
		Account      *string             `json:"account"`
		R3Operations *r3.MCPOperationSet `json:"r3_operations"`
	}
	transport := agentR3RoundTripper(func(request *http.Request) (*http.Response, error) {
		var responseBody []byte
		switch request.URL.String() {
		case "https://resource.example/.well-known/aauth-resource.json":
			responseBody = []byte(`{"issuer":"https://resource.example","authorization_endpoint":"https://resource.example/authorize","r3_vocabularies":{"urn:aauth:vocabulary:mcp":"https://resource.example/mcp"}}`)
		case "https://resource.example/authorize":
			if err := json.NewDecoder(request.Body).Decode(&authorizeInput); err != nil {
				t.Fatal(err)
			}
			responseBody, _ = json.Marshal(map[string]string{"resource_token": resourceToken})
		case "https://person.example/.well-known/aauth-person.json":
			responseBody = []byte(`{"issuer":"https://person.example","person_token_endpoint":"https://person.example/person","auth_token_endpoint":"https://person.example/token","jwks_uri":"https://person.example/jwks"}`)
		case "https://person.example/token":
			var input struct {
				ResourceToken string `json:"resource_token"`
			}
			if err := json.NewDecoder(request.Body).Decode(&input); err != nil {
				t.Fatal(err)
			}
			if input.ResourceToken != resourceToken {
				t.Fatalf("exchange resource token changed")
			}
			responseBody, _ = json.Marshal(map[string]any{"auth_token": authToken, "expires_in": 1800})
		default:
			t.Fatalf("unexpected request %s", request.URL)
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body:       io.NopCloser(bytes.NewReader(responseBody)), Request: request,
		}, nil
	})
	client, err := agent.New(context.Background(), agent.Config{
		Identifier: "aauth:planner@provider.example", SigningKey: agentKey,
		AgentToken: agentToken, KeyResolver: resolver,
		HTTPClient: &http.Client{Transport: transport}, Clock: clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	gotResourceToken, err := client.Authorize(context.Background(), agent.AuthorizeRequest{
		Resource: "https://resource.example", PersonToken: personToken,
		Account: &account, MCPR3Operations: &operations,
	})
	if err != nil {
		t.Fatal(err)
	}
	if gotResourceToken != resourceToken || authorizeInput.Scope != nil || authorizeInput.Account == nil ||
		*authorizeInput.Account != account || authorizeInput.R3Operations == nil ||
		!authorizeInput.R3Operations.Equal(operations) {
		t.Fatalf("authorize input/output = %#v / %t", authorizeInput, gotResourceToken == resourceToken)
	}
	gotAuthToken, err := client.Exchange(context.Background(), agent.ExchangeRequest{
		PersonServer: "https://person.example", ResourceToken: gotResourceToken,
	})
	if err != nil {
		t.Fatal(err)
	}
	if gotAuthToken != authToken {
		t.Fatalf("auth token changed")
	}
	claims, gotReference, gotGranted, err := r3.VerifyMCPDirectAuthToken(context.Background(), gotAuthToken, resolver, clock)
	if err != nil || claims.Scope != "" || gotReference != reference || !reflect.DeepEqual(gotGranted.Operations(), granted.Operations()) {
		t.Fatalf("verified auth = %#v %#v %#v, %v", claims, gotReference, gotGranted, err)
	}
}

func agentR3Key(t *testing.T, id string, fill byte) jose.SigningKey {
	t.Helper()
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{fill}, ed25519.SeedSize))
	key, err := jose.NewEd25519SigningKey(id, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

type agentR3RoundTripper func(*http.Request) (*http.Response, error)

func (roundTrip agentR3RoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	return roundTrip(request)
}
