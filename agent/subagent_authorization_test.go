package agent_test

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/agent"
	"gitlab.com/sidecat-dev/aauth-go/jose"
)

func TestParentMediatedSubagentUsesExactChildTokenAndVerifiesChildBoundResults(t *testing.T) {
	t.Parallel()

	harness := newSubagentClientHarness(t)
	client := harness.client(t)

	personResult, err := client.PersonToken(context.Background(), agent.PersonTokenRequest{
		PersonServer:  harness.protocol.personServerID,
		Resource:      harness.protocol.resourceID,
		SubagentToken: harness.childToken,
	})
	if err != nil {
		t.Fatal(err)
	}
	personToken, ok := personResult.Token()
	if !ok || personToken == "" {
		t.Fatalf("PersonToken result = %#v", personResult)
	}
	personClaims, err := aauth.VerifyPersonToken(context.Background(), personToken, harness.protocol.resolver, harness.protocol.clock)
	if err != nil {
		t.Fatal(err)
	}
	if !personClaims.Confirmation.JWK.Equal(harness.childKey.PublicJWK()) {
		t.Fatalf("person-token key = %#v, want child key", personClaims.Confirmation.JWK)
	}
	if harness.personBody.Resource != harness.protocol.resourceID || harness.personBody.SubagentToken != harness.childToken {
		t.Fatalf("person-token body = %#v", harness.personBody)
	}

	resourceToken := harness.resourceToken(t, harness.childKey.PublicJWK())
	authToken, err := client.Exchange(context.Background(), agent.ExchangeRequest{
		PersonServer:   harness.protocol.personServerID,
		ResourceToken:  resourceToken,
		PresentedToken: personToken,
		SubagentToken:  harness.childToken,
	})
	if err != nil {
		t.Fatal(err)
	}
	authClaims, err := aauth.VerifyAuthToken(context.Background(), authToken, harness.protocol.resolver, harness.protocol.clock)
	if err != nil {
		t.Fatal(err)
	}
	if !authClaims.Confirmation.JWK.Equal(harness.childKey.PublicJWK()) {
		t.Fatalf("auth-token key = %#v, want child key", authClaims.Confirmation.JWK)
	}
	if harness.exchangeBody.ResourceToken != resourceToken || harness.exchangeBody.SubagentToken != harness.childToken ||
		harness.exchangeBody.PresentedToken != personToken {
		t.Fatalf("auth-token body = %#v", harness.exchangeBody)
	}
	if harness.parentProofs != 2 {
		t.Fatalf("parent-signed PS requests = %d, want 2", harness.parentProofs)
	}
}

func TestParentMediatedSubagentRefusesInvalidRelationshipsBeforeNetwork(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name  string
		token func(*subagentClientHarness) string
		want  string
	}{
		{
			name: "top-level token is not a child",
			token: func(h *subagentClientHarness) string {
				return h.mintAgentToken(t, "aauth:other@ap.example", "", h.protocol.personServerID, h.childKey, time.Hour)
			},
			want: "does not identify a sub-agent",
		},
		{
			name: "wrong parent",
			token: func(h *subagentClientHarness) string {
				return h.mintAgentToken(t, "aauth:other+child@ap.example", "aauth:other@ap.example", h.protocol.personServerID, h.childKey, time.Hour)
			},
			want: "parent_agent does not name the requesting Agent",
		},
		{
			name: "child names another person server",
			token: func(h *subagentClientHarness) string {
				return h.mintAgentToken(t, harnessChildID, harnessParentID, "https://other-ps.example", h.childKey, time.Hour)
			},
			want: "names another Person Server",
		},
		{
			name: "parent and child share one key",
			token: func(h *subagentClientHarness) string {
				return h.mintAgentToken(t, harnessChildID, harnessParentID, "", h.protocol.agentKey, time.Hour)
			},
			want: "key distinct from its parent",
		},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			for _, operation := range []string{"person token", "exchange"} {
				operation := operation
				t.Run(operation, func(t *testing.T) {
					harness := newSubagentClientHarness(t)
					token := test.token(harness)
					client := harness.client(t)
					var err error
					if operation == "person token" {
						_, err = client.PersonToken(context.Background(), agent.PersonTokenRequest{
							PersonServer:  harness.protocol.personServerID,
							Resource:      harness.protocol.resourceID,
							SubagentToken: token,
						})
					} else {
						_, err = client.Exchange(context.Background(), agent.ExchangeRequest{
							PersonServer:   harness.protocol.personServerID,
							ResourceToken:  harness.resourceToken(t, harness.childKey.PublicJWK()),
							PresentedToken: harness.presentedToken(t),
							SubagentToken:  token,
						})
					}
					if !errors.Is(err, aauth.ErrInvalidSubagentToken) || !strings.Contains(err.Error(), test.want) {
						t.Fatalf("error = %v, want %q", err, test.want)
					}
					if harness.networkCalls != 0 {
						t.Fatalf("invalid relationship used network: %d calls", harness.networkCalls)
					}
				})
			}
		})
	}
}

func TestSubagentCannotMediateAnotherSubagent(t *testing.T) {
	t.Parallel()

	harness := newSubagentClientHarness(t)
	nestedParentKey := testSigningKey(t, "nested-parent-key", 72)
	nestedParentToken := harness.mintAgentToken(
		t,
		"aauth:root+parent@ap.example",
		"aauth:root@ap.example",
		harness.protocol.personServerID,
		nestedParentKey,
		time.Hour,
	)
	client, err := agent.New(context.Background(), agent.Config{
		Identifier:  "aauth:root+parent@ap.example",
		SigningKey:  nestedParentKey,
		AgentToken:  nestedParentToken,
		KeyResolver: harness.protocol.resolver,
		HTTPClient:  &http.Client{Transport: roundTripperFunc(harness.roundTrip)},
		Clock:       harness.protocol.clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.PersonToken(context.Background(), agent.PersonTokenRequest{
		PersonServer:  harness.protocol.personServerID,
		Resource:      harness.protocol.resourceID,
		SubagentToken: harness.childToken,
	})
	if !errors.Is(err, agent.ErrSubagentPersonServerCall) {
		t.Fatalf("nested mediation error = %v", err)
	}
	if harness.networkCalls != 0 {
		t.Fatalf("nested mediation used network: %d calls", harness.networkCalls)
	}
}

func TestParentMediatedSubagentRejectsWrongTokenBindings(t *testing.T) {
	t.Parallel()

	t.Run("person-token result uses parent key", func(t *testing.T) {
		harness := newSubagentClientHarness(t)
		harness.personConfirmation = harness.protocol.agentKey.PublicJWK()
		_, err := harness.client(t).PersonToken(context.Background(), agent.PersonTokenRequest{
			PersonServer:  harness.protocol.personServerID,
			Resource:      harness.protocol.resourceID,
			SubagentToken: harness.childToken,
		})
		if err == nil || !strings.Contains(err.Error(), "confirmation") {
			t.Fatalf("PersonToken error = %v", err)
		}
	})

	t.Run("resource token uses parent key", func(t *testing.T) {
		harness := newSubagentClientHarness(t)
		_, err := harness.client(t).Exchange(context.Background(), agent.ExchangeRequest{
			PersonServer:  harness.protocol.personServerID,
			ResourceToken: harness.resourceToken(t, harness.protocol.agentKey.PublicJWK()),
			SubagentToken: harness.childToken,
		})
		if err == nil || !strings.Contains(err.Error(), "resource token does not match person server and sub-agent key") {
			t.Fatalf("Exchange error = %v", err)
		}
		if harness.networkCalls != 0 {
			t.Fatalf("wrong resource-token key used network: %d calls", harness.networkCalls)
		}
	})

	t.Run("auth-token result uses parent key", func(t *testing.T) {
		harness := newSubagentClientHarness(t)
		harness.authConfirmation = harness.protocol.agentKey.PublicJWK()
		_, err := harness.client(t).Exchange(context.Background(), agent.ExchangeRequest{
			PersonServer:   harness.protocol.personServerID,
			ResourceToken:  harness.resourceToken(t, harness.childKey.PublicJWK()),
			PresentedToken: harness.presentedToken(t),
			SubagentToken:  harness.childToken,
		})
		if err == nil || !strings.Contains(err.Error(), "confirmation") {
			t.Fatalf("Exchange error = %v", err)
		}
	})
}

func TestParentMediatedSubagentUsesEarlierAgentExpiryCeiling(t *testing.T) {
	t.Parallel()

	for _, ceiling := range []string{"child", "parent"} {
		ceiling := ceiling
		for _, operation := range []string{"person token", "exchange"} {
			operation := operation
			t.Run(ceiling+"/"+operation, func(t *testing.T) {
				harness := newSubagentClientHarness(t)
				wantSource := "sub-agent token"
				if ceiling == "child" {
					harness.childToken = harness.mintAgentToken(
						t, harnessChildID, harnessParentID, harness.protocol.personServerID,
						harness.childKey, 5*time.Minute,
					)
				} else {
					parentToken, err := aauth.MintAgentToken(
						harness.protocol.agentProviderID, harness.protocol.agentProviderKey,
						aauth.AgentTokenRequest{
							Agent: harness.protocol.agentID, PersonServer: harness.protocol.personServerID,
							PublicKey: harness.protocol.agentKey.PublicJWK(), Lifetime: 5 * time.Minute,
						}, harness.protocol.now, "short-parent-token",
					)
					if err != nil {
						t.Fatal(err)
					}
					harness.protocol.agentToken = parentToken
					wantSource = "agent token"
				}
				harness.personExpiresAt = harness.protocol.now.Add(6 * time.Minute).Unix()
				harness.authExpiresAt = harness.protocol.now.Add(6 * time.Minute).Unix()
				client := harness.client(t)
				var err error
				if operation == "person token" {
					_, err = client.PersonToken(context.Background(), agent.PersonTokenRequest{
						PersonServer:  harness.protocol.personServerID,
						Resource:      harness.protocol.resourceID,
						SubagentToken: harness.childToken,
					})
				} else {
					_, err = client.Exchange(context.Background(), agent.ExchangeRequest{
						PersonServer:   harness.protocol.personServerID,
						ResourceToken:  harness.resourceToken(t, harness.childKey.PublicJWK()),
						PresentedToken: harness.presentedToken(t),
						SubagentToken:  harness.childToken,
					})
				}
				if err == nil || !strings.Contains(err.Error(), "lifetime exceeds") || !strings.Contains(err.Error(), wantSource) {
					t.Fatalf("error = %v", err)
				}
			})
		}
	}
}

func TestParentMediatedSubagentPersonTokenReturnsPendingInteraction(t *testing.T) {
	t.Parallel()
	harness := newSubagentClientHarness(t)
	harness.personPending = true
	result, err := harness.client(t).PersonToken(context.Background(), agent.PersonTokenRequest{
		PersonServer:  harness.protocol.personServerID,
		Resource:      harness.protocol.resourceID,
		SubagentToken: harness.childToken,
	})
	if err != nil {
		t.Fatal(err)
	}
	pending, ok := result.Pending()
	if !ok || pending.PersonServer() != harness.protocol.personServerID ||
		pending.Resource() != harness.protocol.resourceID {
		t.Fatalf("pending result = %#v, pending=%#v", result, pending)
	}
}

func TestParentMediatedSubagentExchangeReturnsPendingInteraction(t *testing.T) {
	t.Parallel()
	harness := newSubagentClientHarness(t)
	harness.exchangePending = true
	result, err := harness.client(t).BeginExchange(context.Background(), agent.ExchangeRequest{
		PersonServer:   harness.protocol.personServerID,
		ResourceToken:  harness.resourceToken(t, harness.childKey.PublicJWK()),
		PresentedToken: harness.presentedToken(t),
		SubagentToken:  harness.childToken,
		Capabilities:   []string{"interaction"},
	})
	if err != nil {
		t.Fatal(err)
	}
	pending, ok := result.Pending()
	if !ok || pending.PersonServer() != harness.protocol.personServerID ||
		pending.Location() != harness.protocol.personServerID+"/pending/exchange-1" {
		t.Fatalf("pending result = %#v, pending=%#v", result, pending)
	}
}

func TestParentMediatedSubagentExchangeConvenienceNamesPendingAPI(t *testing.T) {
	t.Parallel()
	harness := newSubagentClientHarness(t)
	harness.exchangePending = true
	_, err := harness.client(t).Exchange(context.Background(), agent.ExchangeRequest{
		PersonServer:   harness.protocol.personServerID,
		ResourceToken:  harness.resourceToken(t, harness.childKey.PublicJWK()),
		PresentedToken: harness.presentedToken(t),
		SubagentToken:  harness.childToken,
		Capabilities:   []string{"interaction"},
	})
	var pendingRequired *agent.SubagentPendingExchangeRequiredError
	if !errors.As(err, &pendingRequired) || pendingRequired.Operation != "Exchange" ||
		!strings.Contains(err.Error(), "use BeginExchange and PollExchange") {
		t.Fatalf("error = %v, want typed pending-exchange direction", err)
	}
}

const (
	harnessParentID = "aauth:reader@ap.example"
	harnessChildID  = "aauth:reader+search@ap.example"
)

type subagentClientHarness struct {
	t                  *testing.T
	protocol           *testProtocol
	childKey           jose.SigningKey
	childToken         string
	personConfirmation jose.JWK
	authConfirmation   jose.JWK
	personExpiresAt    int64
	authExpiresAt      int64
	personPending      bool
	exchangePending    bool
	networkCalls       int
	parentProofs       int
	personBody         struct {
		Resource      string `json:"resource"`
		SubagentToken string `json:"subagent_token"`
	}
	exchangeBody struct {
		ResourceToken  string   `json:"resource_token"`
		PresentedToken string   `json:"presented_token"`
		SubagentToken  string   `json:"subagent_token"`
		Capabilities   []string `json:"capabilities,omitempty"`
	}
}

func newSubagentClientHarness(t *testing.T) *subagentClientHarness {
	t.Helper()
	protocol := newTestProtocol(t)
	harness := &subagentClientHarness{
		t:               t,
		protocol:        protocol,
		childKey:        testSigningKey(t, "subagent-key", 71),
		personExpiresAt: protocol.now.Add(20 * time.Minute).Unix(),
		authExpiresAt:   protocol.now.Add(15 * time.Minute).Unix(),
	}
	harness.childToken = harness.mintAgentToken(
		t, harnessChildID, harnessParentID, "",
		harness.childKey, 30*time.Minute,
	)
	harness.personConfirmation = harness.childKey.PublicJWK()
	harness.authConfirmation = harness.childKey.PublicJWK()
	return harness
}

func (harness *subagentClientHarness) client(t *testing.T) *agent.Client {
	t.Helper()
	client, err := agent.New(context.Background(), agent.Config{
		Identifier:  harness.protocol.agentID,
		SigningKey:  harness.protocol.agentKey,
		AgentToken:  harness.protocol.agentToken,
		KeyResolver: harness.protocol.resolver,
		HTTPClient:  &http.Client{Transport: roundTripperFunc(harness.roundTrip)},
		Clock:       harness.protocol.clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func (harness *subagentClientHarness) mintAgentToken(
	t *testing.T,
	agentID string,
	parentID string,
	personServer string,
	key jose.SigningKey,
	lifetime time.Duration,
) string {
	t.Helper()
	compact, err := aauth.MintAgentToken(
		harness.protocol.agentProviderID,
		harness.protocol.agentProviderKey,
		aauth.AgentTokenRequest{
			Agent: agentID, ParentAgent: parentID, PersonServer: personServer,
			PublicKey: key.PublicJWK(), Lifetime: lifetime,
		},
		harness.protocol.now,
		"agent-token-"+strings.ReplaceAll(agentID, ":", "-"),
	)
	if err != nil {
		t.Fatal(err)
	}
	return compact
}

func (harness *subagentClientHarness) resourceToken(t *testing.T, confirmation jose.JWK) string {
	t.Helper()
	thumbprint, err := confirmation.Thumbprint()
	if err != nil {
		t.Fatal(err)
	}
	compact, err := aauth.MintResourceToken(harness.protocol.resourceKey, aauth.ResourceTokenClaims{
		Issuer:       harness.protocol.resourceID,
		DWK:          aauth.ResourceDiscoveryDocument,
		Audience:     harness.protocol.accessServerID,
		JTI:          "subagent-resource-token",
		AgentJKT:     thumbprint,
		IssuedAt:     harness.protocol.now.Unix(),
		ExpiresAt:    harness.protocol.now.Add(10 * time.Minute).Unix(),
		Scope:        "records.read",
		PersonServer: harness.protocol.personServerID,
		Subject:      "person-123",
		PresentedJTI: "subagent-person-token",
	})
	if err != nil {
		t.Fatal(err)
	}
	return compact
}

// presentedToken mints the person token the harness resource token names.
func (harness *subagentClientHarness) presentedToken(t *testing.T) string {
	t.Helper()
	return harness.protocol.presentedPersonToken(t, aauth.ResourceTokenClaims{
		Issuer: harness.protocol.resourceID, Subject: "person-123", PresentedJTI: "subagent-person-token",
	}, harness.childKey.PublicJWK())
}

func (harness *subagentClientHarness) roundTrip(request *http.Request) (*http.Response, error) {
	harness.networkCalls++
	switch {
	case request.Method == http.MethodGet && request.URL.String() == harness.protocol.personServerID+"/.well-known/aauth-person.json":
		return jsonResponse(request, http.StatusOK, map[string]any{
			"issuer":                harness.protocol.personServerID,
			"person_token_endpoint": harness.protocol.personTokenEndpoint,
			"auth_token_endpoint":   harness.protocol.authTokenEndpoint,
		}), nil
	case request.Method == http.MethodPost && request.URL.String() == harness.protocol.personTokenEndpoint:
		verified := verifyProof(harness.t, request, harness.protocol.resolver, harness.protocol.clock, aauth.AgentTokenType)
		claims, err := verified.AgentClaims()
		if err != nil || claims.Subject != harness.protocol.agentID {
			harness.t.Fatalf("person request proof = %#v, error = %v", claims, err)
		}
		harness.parentProofs++
		decodeRequest(harness.t, request, &harness.personBody)
		if harness.personPending {
			response := jsonResponse(request, http.StatusAccepted, map[string]string{"status": "pending"})
			response.Header.Set("Cache-Control", "no-store")
			response.Header.Set("Location", "/pending/person-1")
			response.Header.Set("Retry-After", "0")
			response.Header.Set("AAuth-Requirement", `requirement=interaction; url="https://ps.example/interaction"; code="ABCD-EFGH"`)
			return response, nil
		}
		compact, err := aauth.MintPersonToken(harness.protocol.personServerKey, aauth.PersonTokenClaims{
			Issuer:       harness.protocol.personServerID,
			DWK:          aauth.PersonDiscoveryDocument,
			Audience:     harness.protocol.resourceID,
			Subject:      "person-123",
			Confirmation: aauth.Confirmation{JWK: harness.personConfirmation},
			JTI:          "subagent-person-token",
			IssuedAt:     harness.protocol.now.Unix(),
			ExpiresAt:    harness.personExpiresAt,
		})
		if err != nil {
			harness.t.Fatal(err)
		}
		return jsonResponse(request, http.StatusOK, map[string]any{
			"person_token": compact,
			"expires_in":   harness.personExpiresAt - harness.protocol.now.Unix(),
		}), nil
	case request.Method == http.MethodPost && request.URL.String() == harness.protocol.authTokenEndpoint:
		verified := verifyProof(harness.t, request, harness.protocol.resolver, harness.protocol.clock, aauth.AgentTokenType)
		claims, err := verified.AgentClaims()
		if err != nil || claims.Subject != harness.protocol.agentID {
			harness.t.Fatalf("exchange request proof = %#v, error = %v", claims, err)
		}
		harness.parentProofs++
		decodeRequest(harness.t, request, &harness.exchangeBody)
		if harness.exchangePending {
			response := jsonResponse(request, http.StatusAccepted, map[string]string{"status": "pending"})
			response.Header.Set("Cache-Control", "no-store")
			response.Header.Set("Location", "/pending/exchange-1")
			response.Header.Set("Retry-After", "0")
			response.Header.Set("AAuth-Requirement", `requirement=interaction; url="https://ps.example/interaction"; code="ABCD-EFGH"`)
			return response, nil
		}
		compact, err := aauth.MintAuthToken(harness.protocol.accessServerKey, aauth.AuthTokenClaims{
			Issuer:       harness.protocol.accessServerID,
			DWK:          aauth.AccessDiscoveryDocument,
			Audience:     harness.protocol.resourceID,
			JTI:          "subagent-auth-token",
			Confirmation: aauth.Confirmation{JWK: harness.authConfirmation},
			IssuedAt:     harness.protocol.now.Unix(),
			ExpiresAt:    harness.authExpiresAt,
			Subject:      "person-123",
			Scope:        "records.read",
			PersonServer: harness.protocol.personServerID,
		})
		if err != nil {
			harness.t.Fatal(err)
		}
		return jsonResponse(request, http.StatusOK, map[string]any{
			"auth_token": compact,
			"expires_in": harness.authExpiresAt - harness.protocol.now.Unix(),
		}), nil
	default:
		return nil, errors.New("unexpected request: " + request.URL.String())
	}
}
