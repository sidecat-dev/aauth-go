package agent_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/agent"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

func TestCallChainingRoutesFromUpstreamTokenAndCarriesItExactly(t *testing.T) {
	t.Parallel()

	protocol := newTestProtocol(t)
	const (
		intermediaryID      = "https://resource-one.example"
		intermediaryAgentID = "aauth:worker@resource-one.example"
		intermediaryOwnPS   = "https://unrelated-ps.example"
		upstreamSubject     = "person-at-resource-one"
		downstreamSubject   = "person-123"
		upstreamScope       = "orders.fulfill"
		downstreamScope     = "records.read"
	)
	protocol.agentProviderID = intermediaryID
	protocol.agentID = intermediaryAgentID
	protocol.agentProviderKey = testSigningKey(t, "intermediary-provider", 81)
	protocol.agentKey = testSigningKey(t, "intermediary-agent", 82)
	protocol.resourceAudience = protocol.personServerID
	protocol.resourceScope = downstreamScope
	protocol.authIssuer = protocol.personServerID
	protocol.authDiscoveryDocument = aauth.PersonDiscoveryDocument
	protocol.authSigningKey = protocol.personServerKey
	protocol.authPersonServer = protocol.personServerID
	protocol.resolver[signaturekey.StaticKeyReference{
		Issuer: intermediaryID, DiscoveryDocument: aauth.AgentDiscoveryDocument,
		KeyID: protocol.agentProviderKey.ID(),
	}] = protocol.agentProviderKey.PublicJWK()
	var err error
	protocol.agentToken, err = aauth.MintAgentToken(
		intermediaryID,
		protocol.agentProviderKey,
		aauth.AgentTokenRequest{
			Agent: intermediaryAgentID, PersonServer: intermediaryOwnPS,
			PublicKey: protocol.agentKey.PublicJWK(), Lifetime: time.Hour,
		},
		protocol.now,
		"intermediary-agent-token",
	)
	if err != nil {
		t.Fatal(err)
	}
	originalAgentKey := testSigningKey(t, "original-agent", 83)
	upstreamToken, err := aauth.MintAuthToken(protocol.personServerKey, aauth.AuthTokenClaims{
		Issuer: protocol.personServerID, DWK: aauth.PersonDiscoveryDocument,
		Audience: intermediaryID, JTI: "upstream-auth-token",
		PersonServer: protocol.personServerID, Subject: upstreamSubject,
		Confirmation: aauth.Confirmation{JWK: originalAgentKey.PublicJWK()},
		IssuedAt:     protocol.now.Unix(), ExpiresAt: protocol.now.Add(15 * time.Minute).Unix(),
		Scope: upstreamScope,
	})
	if err != nil {
		t.Fatal(err)
	}
	if originalAgentKey.PublicJWK().Equal(protocol.agentKey.PublicJWK()) {
		t.Fatal("test requires different original-Agent and intermediary keys")
	}

	var personUpstream, exchangeUpstream string
	var visitedURLs []string
	transport := roundTripperFunc(func(request *http.Request) (*http.Response, error) {
		visitedURLs = append(visitedURLs, request.URL.String())
		if request.Method == http.MethodPost &&
			(request.URL.String() == protocol.personTokenEndpoint || request.URL.String() == protocol.authTokenEndpoint) {
			protocol.paths = append(protocol.paths, request.URL.Path)
			body, err := io.ReadAll(request.Body)
			if err != nil {
				t.Fatal(err)
			}
			request.Body = io.NopCloser(bytes.NewReader(body))
			var input struct {
				Resource      string `json:"resource"`
				ResourceToken string `json:"resource_token"`
				UpstreamToken string `json:"upstream_token"`
			}
			if err := json.Unmarshal(body, &input); err != nil {
				t.Fatal(err)
			}
			verified := verifyProof(t, request, protocol.resolver, protocol.clock, aauth.AgentTokenType)
			agentClaims, err := verified.AgentClaims()
			if err != nil || agentClaims.Subject != intermediaryAgentID {
				t.Fatalf("intermediary proof = %#v, error=%v", agentClaims, err)
			}
			if request.URL.String() == protocol.personTokenEndpoint {
				personUpstream = input.UpstreamToken
				if input.Resource != protocol.resourceID {
					t.Fatalf("downstream resource = %q", input.Resource)
				}
				compact, err := aauth.MintPersonToken(protocol.personServerKey, aauth.PersonTokenClaims{
					Issuer: protocol.personServerID, DWK: aauth.PersonDiscoveryDocument,
					Audience: protocol.resourceID, Subject: downstreamSubject,
					Confirmation: aauth.Confirmation{JWK: protocol.agentKey.PublicJWK()},
					JTI:          "downstream-person-token", IssuedAt: protocol.now.Unix(),
					ExpiresAt: protocol.now.Add(20 * time.Minute).Unix(),
				})
				if err != nil {
					t.Fatal(err)
				}
				return jsonResponse(request, http.StatusOK, map[string]any{
					"person_token": compact, "expires_in": 1200,
				}), nil
			} else {
				exchangeUpstream = input.UpstreamToken
				if input.ResourceToken == "" {
					t.Fatal("exchange omitted resource token")
				}
				compact, err := aauth.MintAuthToken(protocol.personServerKey, aauth.AuthTokenClaims{
					Issuer: protocol.personServerID, DWK: aauth.PersonDiscoveryDocument,
					Audience: protocol.resourceID, JTI: "downstream-auth-token",
					PersonServer: protocol.personServerID, Subject: downstreamSubject,
					Confirmation: aauth.Confirmation{JWK: protocol.agentKey.PublicJWK()},
					IssuedAt:     protocol.now.Unix(), ExpiresAt: protocol.now.Add(30 * time.Minute).Unix(),
					Scope: downstreamScope,
				})
				if err != nil {
					t.Fatal(err)
				}
				return jsonResponse(request, http.StatusOK, map[string]any{
					"auth_token": compact, "expires_in": 1800,
				}), nil
			}
		}
		if strings.Contains(request.URL.String(), upstreamToken) {
			t.Fatalf("upstream token leaked into Resource URL %q", request.URL)
		}
		for name, values := range request.Header {
			for _, value := range values {
				if strings.Contains(value, upstreamToken) {
					t.Fatalf("upstream token leaked into Resource header %q", name)
				}
			}
		}
		if request.Body != nil {
			body, err := io.ReadAll(request.Body)
			if err != nil {
				t.Fatal(err)
			}
			request.Body = io.NopCloser(bytes.NewReader(body))
			if bytes.Contains(body, []byte(upstreamToken)) {
				t.Fatal("upstream token leaked into Resource request body")
			}
		}
		return protocol.roundTrip(request)
	})
	client := protocol.newClientWithHTTPClient(t, &http.Client{Transport: transport})

	personResult, err := client.PersonToken(context.Background(), agent.PersonTokenRequest{
		Resource: protocol.resourceID, UpstreamToken: upstreamToken,
	})
	if err != nil {
		t.Fatal(err)
	}
	personToken, ok := personResult.Token()
	if !ok {
		t.Fatalf("person-token result = %#v", personResult)
	}
	resourceToken, err := client.Authorize(context.Background(), agent.AuthorizeRequest{
		Resource: protocol.resourceID, PersonToken: personToken,
		Scopes: []string{downstreamScope}, UpstreamToken: upstreamToken,
	})
	if err != nil {
		t.Fatal(err)
	}
	authToken, err := client.Exchange(context.Background(), agent.ExchangeRequest{
		ResourceToken: resourceToken, PresentedToken: personToken, UpstreamToken: upstreamToken,
	})
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest(http.MethodGet, protocol.resourceID+"/records/42", nil)
	if err != nil {
		t.Fatal(err)
	}
	// The upstream token had to be valid at both Person Server requests. The
	// downstream authorization has its own lifetime and remains usable after
	// that upstream token expires.
	protocol.now = protocol.now.Add(16 * time.Minute)
	response, err := client.Do(context.Background(), agent.Call{
		Request: request, AuthToken: authToken, UpstreamToken: upstreamToken,
	})
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("protected response = %d", response.StatusCode)
	}
	if personUpstream != upstreamToken || exchangeUpstream != upstreamToken {
		t.Fatalf("upstream tokens = person %t exchange %t", personUpstream == upstreamToken, exchangeUpstream == upstreamToken)
	}
	for _, target := range visitedURLs {
		if strings.Contains(target, "unrelated-ps.example") {
			t.Fatalf("call chain used intermediary Agent-token ps: %q", target)
		}
	}

	before := len(protocol.paths)
	if _, err := client.PersonToken(context.Background(), agent.PersonTokenRequest{
		PersonServer: protocol.personServerID, Resource: protocol.resourceID,
	}); err == nil || !strings.Contains(err.Error(), "person server does not match agent token") {
		t.Fatalf("ordinary request error = %v", err)
	}
	if len(protocol.paths) != before {
		t.Fatal("ordinary wrong-Person-Server request reached the network")
	}
}

func TestCallChainingRejectsInvalidContextBeforeNetwork(t *testing.T) {
	t.Parallel()

	protocol := newTestProtocol(t)
	client := protocol.newClient(t)
	otherKey := testSigningKey(t, "other-resource", 84)
	wrongAudience, err := aauth.MintAuthToken(protocol.personServerKey, aauth.AuthTokenClaims{
		Issuer: protocol.personServerID, DWK: aauth.PersonDiscoveryDocument,
		Audience: "https://other-resource.example", JTI: "wrong-audience",
		PersonServer: protocol.personServerID, Subject: "person-123",
		Confirmation: aauth.Confirmation{JWK: otherKey.PublicJWK()},
		IssuedAt:     protocol.now.Unix(), ExpiresAt: protocol.now.Add(time.Minute).Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	validUpstream, err := aauth.MintAuthToken(protocol.personServerKey, aauth.AuthTokenClaims{
		Issuer: protocol.personServerID, DWK: aauth.PersonDiscoveryDocument,
		Audience: protocol.agentProviderID, JTI: "valid-upstream",
		PersonServer: protocol.personServerID, Subject: "person-123",
		Confirmation: aauth.Confirmation{JWK: otherKey.PublicJWK()},
		IssuedAt:     protocol.now.Unix(), ExpiresAt: protocol.now.Add(time.Minute).Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	wrongRole, err := aauth.MintAuthToken(protocol.accessServerKey, aauth.AuthTokenClaims{
		Issuer: protocol.accessServerID, DWK: aauth.AccessDiscoveryDocument,
		Audience: protocol.agentProviderID, JTI: "wrong-role-upstream",
		PersonServer: protocol.personServerID, Subject: "person-123",
		Confirmation: aauth.Confirmation{JWK: otherKey.PublicJWK()},
		IssuedAt:     protocol.now.Unix(), ExpiresAt: protocol.now.Add(time.Minute).Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	missionClaims := aauth.AuthTokenClaims{
		Issuer: protocol.personServerID, DWK: aauth.PersonDiscoveryDocument,
		Audience: protocol.agentProviderID, JTI: "mission-upstream",
		PersonServer: protocol.personServerID, Subject: "person-123",
		Confirmation: aauth.Confirmation{JWK: otherKey.PublicJWK()},
		IssuedAt:     protocol.now.Unix(), ExpiresAt: protocol.now.Add(time.Minute).Unix(),
		MissionS256: strings.Repeat("A", 43),
	}
	missionBound, err := aauth.MintAuthToken(protocol.personServerKey, missionClaims)
	if err != nil {
		t.Fatal(err)
	}
	accountClaims := missionClaims
	accountClaims.JTI = "account-upstream"
	accountClaims.MissionS256 = ""
	accountClaims.Account = testStringPointer("account-17")
	accountBound, err := aauth.MintAuthToken(protocol.personServerKey, accountClaims)
	if err != nil {
		t.Fatal(err)
	}
	expiredUpstream, err := aauth.MintAuthToken(protocol.personServerKey, aauth.AuthTokenClaims{
		Issuer: protocol.personServerID, DWK: aauth.PersonDiscoveryDocument,
		Audience: protocol.agentProviderID, JTI: "expired-upstream",
		PersonServer: protocol.personServerID, Subject: "person-123",
		Confirmation: aauth.Confirmation{JWK: otherKey.PublicJWK()},
		IssuedAt:     protocol.now.Add(-2 * time.Minute).Unix(), ExpiresAt: protocol.now.Add(-time.Minute).Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		name    string
		request agent.PersonTokenRequest
		want    string
	}{
		{name: "malformed", request: agent.PersonTokenRequest{Resource: protocol.resourceID, UpstreamToken: "not-a-compact-token"}, want: "verify upstream token"},
		{name: "wrong audience", request: agent.PersonTokenRequest{Resource: protocol.resourceID, UpstreamToken: wrongAudience}, want: "audience"},
		{name: "wrong issuer role", request: agent.PersonTokenRequest{Resource: protocol.resourceID, UpstreamToken: wrongRole}, want: "not issued by its Person Server"},
		{name: "mission bound", request: agent.PersonTokenRequest{Resource: protocol.resourceID, UpstreamToken: missionBound}, want: "mission- or account-bound"},
		{name: "account bound", request: agent.PersonTokenRequest{Resource: protocol.resourceID, UpstreamToken: accountBound}, want: "mission- or account-bound"},
		{name: "wrong explicit person server", request: agent.PersonTokenRequest{PersonServer: "https://other-ps.example", Resource: protocol.resourceID, UpstreamToken: validUpstream}, want: "does not match upstream token"},
		{name: "sub-agent combination", request: agent.PersonTokenRequest{Resource: protocol.resourceID, UpstreamToken: validUpstream, SubagentToken: protocol.agentToken}, want: "mutually exclusive"},
		{name: "expired", request: agent.PersonTokenRequest{Resource: protocol.resourceID, UpstreamToken: expiredUpstream}, want: "expired"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := client.PersonToken(context.Background(), test.request); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("PersonToken error = %v, want %q", err, test.want)
			}
		})
	}
	if len(protocol.paths) != 0 {
		t.Fatalf("invalid call-chain request reached network: %v", protocol.paths)
	}
}

func TestCallChainingRejectsPendingInteractionWithTypedError(t *testing.T) {
	t.Parallel()

	for _, operation := range []string{"person-token issuance", "auth-token exchange"} {
		t.Run(operation, func(t *testing.T) {
			protocol := newTestProtocol(t)
			upstreamToken, err := aauth.MintAuthToken(protocol.personServerKey, aauth.AuthTokenClaims{
				Issuer: protocol.personServerID, DWK: aauth.PersonDiscoveryDocument,
				Audience: protocol.agentProviderID, JTI: "pending-upstream",
				PersonServer: protocol.personServerID, Subject: "person-123",
				Confirmation: aauth.Confirmation{JWK: protocol.agentKey.PublicJWK()},
				IssuedAt:     protocol.now.Unix(), ExpiresAt: protocol.now.Add(time.Minute).Unix(),
			})
			if err != nil {
				t.Fatal(err)
			}
			transport := roundTripperFunc(func(request *http.Request) (*http.Response, error) {
				switch {
				case operation == "person-token issuance" && request.URL.String() == protocol.personTokenEndpoint:
					return validPersonTokenPendingResponse(request, "0", "pending"), nil
				case operation == "auth-token exchange" && request.URL.String() == protocol.authTokenEndpoint:
					return validExchangePendingResponse(request, "/pending/exchange-1", "0", "pending"), nil
				default:
					return protocol.roundTrip(request)
				}
			})
			client := protocol.newClientWithHTTPClient(t, &http.Client{Transport: transport})
			if operation == "person-token issuance" {
				_, err = client.PersonToken(context.Background(), agent.PersonTokenRequest{
					Resource: protocol.resourceID, UpstreamToken: upstreamToken,
				})
			} else {
				agentJKT, thumbprintErr := protocol.agentKey.PublicJWK().Thumbprint()
				if thumbprintErr != nil {
					t.Fatal(thumbprintErr)
				}
				resourceToken, mintErr := aauth.MintResourceToken(protocol.resourceKey, aauth.ResourceTokenClaims{
					Issuer: protocol.resourceID, DWK: aauth.ResourceDiscoveryDocument,
					Audience: protocol.personServerID, JTI: "pending-resource-token",
					PersonServer: protocol.personServerID, Subject: "person-123",
					PresentedJTI: "pending-person-token", AgentJKT: agentJKT,
					IssuedAt: protocol.now.Unix(), ExpiresAt: protocol.now.Add(time.Minute).Unix(), Scope: "records.read",
				})
				if mintErr != nil {
					t.Fatal(mintErr)
				}
				resourceClaims, verifyErr := aauth.VerifyResourceToken(
					context.Background(), resourceToken, protocol.resolver, protocol.clock,
				)
				if verifyErr != nil {
					t.Fatal(verifyErr)
				}
				_, err = client.BeginExchange(context.Background(), agent.ExchangeRequest{
					ResourceToken: resourceToken, UpstreamToken: upstreamToken,
					PresentedToken: protocol.presentedPersonToken(t, resourceClaims, protocol.agentKey.PublicJWK()),
					Capabilities:   []string{"interaction"},
				})
			}
			var unsupported *agent.CallChainingInteractionUnsupportedError
			if !errors.As(err, &unsupported) || unsupported.Operation == "" {
				t.Fatalf("error = %v, want typed unsupported call-chain interaction", err)
			}
		})
	}
}
