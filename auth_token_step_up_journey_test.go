package aauth_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	aa "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/reference"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

func TestCurrentAuthTokenStepUpRetriesTheExactCall(t *testing.T) {
	now := time.Date(2026, 8, 29, 23, 15, 0, 0, time.UTC)
	clock := aa.ClockFunc(func() time.Time { return now })
	apKey := testSigningKey(t, "step-up-ap")
	psKey := testSigningKey(t, "step-up-ps")
	asKey := testSigningKey(t, "step-up-as")
	resourceKey := testSigningKey(t, "step-up-resource")
	agentKey := testSigningKey(t, "step-up-agent")

	ap, err := reference.NewAgentProvider(reference.AgentProviderConfig{
		Identifier: "https://ap.example", SigningKey: apKey, Clock: clock,
		NewID: sequentialIDs("step-up-agent-token"),
	})
	if err != nil {
		t.Fatal(err)
	}
	agentToken, err := ap.IssueAgentToken(aa.AgentTokenRequest{
		Agent: "aauth:step-up-agent@ap.example", PersonServer: "https://ps.example",
		PublicKey: agentKey.PublicJWK(), Lifetime: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}

	protocolClient := &http.Client{}
	resolver, err := signaturekey.NewHTTPKeyResolver(signaturekey.HTTPKeyResolverConfig{
		Client: protocolClient, Clock: clock,
		Admit: func(_ context.Context, endpoint string) error {
			for _, prefix := range []string{
				"https://ap.example/", "https://ps.example/", "https://as.example/", "https://resource.example/",
			} {
				if strings.HasPrefix(endpoint, prefix) {
					return nil
				}
			}
			return fmt.Errorf("endpoint outside step-up trust boundary: %s", endpoint)
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	accessPolicyCalls := 0
	accessServer, err := reference.NewAccessServer(reference.AccessServerConfig{
		Identifier: "https://as.example", SigningKey: asKey, KeyResolver: resolver,
		Clock: clock, NewID: sequentialIDs("step-up-auth-token", "step-up-renewed-auth-token"),
		AuthorizationStore: testAuthorizationStateStore(t),
		TrustedPersonServer: func(_ context.Context, identifier string) error {
			if identifier != "https://ps.example" {
				return fmt.Errorf("untrusted person server: %s", identifier)
			}
			return nil
		},
		AuthorizationPolicy: func(_ context.Context, request aa.AuthorizationRequest) (aa.AuthorizationDecision, error) {
			accessPolicyCalls++
			return aa.AuthorizationDecision{Subject: request.Subject, Scope: request.Scope}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	personTokens, missionIssuance := testCurrentPersonServerCustody(t)
	personPolicyCalls := 0
	personServer, err := reference.NewPersonServer(reference.PersonServerConfig{
		Identifier: "https://ps.example", SigningKey: psKey, KeyResolver: resolver,
		Clock: clock, NewID: sequentialIDs("step-up-person-token"),
		AuthorizationStore: testAuthorizationStateStore(t),
		PersonTokenStore:   personTokens, MissionIssuanceStore: missionIssuance,
		PersonTokenPolicy: func(context.Context, aa.PersonTokenRequest) (aa.PersonTokenDecision, error) {
			return aa.PersonTokenDecision{Subject: "step-up-person", Lifetime: time.Hour}, nil
		},
		CurrentMissionPolicy: func(_ context.Context, evaluation aa.MissionEvaluation) (aa.MissionDecision, error) {
			return aa.MissionDecision{Description: evaluation.Proposal.Description}, nil
		},
		AuthorizationPolicy: func(_ context.Context, request aa.AuthorizationRequest) (aa.AuthorizationDecision, error) {
			personPolicyCalls++
			return aa.AuthorizationDecision{Subject: request.Subject, Scope: request.Scope}, nil
		},
		FederationClient: protocolClient,
		AccessServerEndpoint: func(context.Context, string) (string, error) {
			return "https://as.example/token", nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	operationCalls := 0
	var operationRequest aa.AuthorizedRequest
	var operationAuthTokenIDs []string
	resource, err := reference.NewResource(reference.ResourceConfig{
		Identifier: "https://resource.example", AccessMode: aa.AccessModeAuthToken,
		AccessServer: "https://as.example", SigningKey: resourceKey, KeyResolver: resolver,
		Clock: clock, NewID: sequentialIDs("step-up-resource-token"),
		Scopes: []string{"records.read", "records.write"},
		ScopeDescriptions: map[string]string{
			"records.read": "Read records", "records.write": "Write records",
		},
		RequiredScopesForRequest:     testRequiredResourceScopes("records.read"),
		ReplayStore:                  testResourceReplayStore(t, clock),
		ProtectedAuthorizationPolicy: func(context.Context, aa.AuthorizedRequest) error { return nil },
		Operation: func(_ context.Context, request aa.AuthorizedRequest) (any, error) {
			operationCalls++
			operationRequest = request
			operationAuthTokenIDs = append(operationAuthTokenIDs, request.AuthTokenID)
			return map[string]string{"status": "stored"}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	var stepUpArmed bool
	var stepUpToken string
	var presentedPerson aa.PersonTokenClaims
	stepUpHandler := http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		credential := signatureKeyJWT(request.Header.Get("Signature-Key"))
		if request.URL.Path == "/records" && credential != "" {
			parsed, parseErr := jose.ParseCompact(credential)
			if parseErr == nil {
				switch parsed.Header().Type {
				case aa.PersonTokenType:
					if err := json.Unmarshal(parsed.Payload(), &presentedPerson); err != nil {
						t.Errorf("capture person token: %v", err)
					}
				case aa.AuthTokenType:
					if stepUpArmed {
						stepUpArmed = false
						requirement, requirementErr := aa.FormatRequirementHeader(aa.Requirement{
							Type: aa.RequirementAuthToken, ResourceToken: stepUpToken,
						})
						if requirementErr != nil {
							t.Errorf("format step-up requirement: %v", requirementErr)
							return
						}
						response.Header().Set("Cache-Control", "no-store")
						response.Header().Set("AAuth-Requirement", requirement)
						response.WriteHeader(http.StatusUnauthorized)
						_, _ = io.WriteString(response, `{"error":"authorization_required"}`)
						return
					}
				}
			}
		}
		resource.Handler().ServeHTTP(response, request)
	})

	gateway := newLogicalGateway(t, map[string]http.Handler{
		"ap.example": ap.Handler(), "ps.example": personServer.Handler(),
		"as.example": accessServer.Handler(), "resource.example": stepUpHandler,
	})
	defer gateway.Close()
	protocolClient.Transport = gateway.Client().Transport

	agent, err := reference.NewAgent(reference.AgentConfig{
		Identifier: "aauth:step-up-agent@ap.example", SigningKey: agentKey,
		AgentToken: agentToken, KeyResolver: resolver, HTTPClient: protocolClient, Clock: clock,
		AuthorizationStore: testAuthorizationStateStore(t),
	})
	if err != nil {
		t.Fatal(err)
	}
	call := reference.AuthorizedCall{
		Method: http.MethodPost, Endpoint: "https://resource.example/records",
		Body: []byte(`{"name":"step-up"}`), ContentType: "application/json",
	}
	response, err := agent.Do(context.Background(), call)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(response.Body)
		response.Body.Close()
		t.Fatalf("initial protected result status = %d, body = %s", response.StatusCode, body)
	}
	response.Body.Close()
	if operationCalls != 1 || personPolicyCalls != 1 || accessPolicyCalls != 1 {
		t.Fatalf("initial operation/PS/AS calls = %d/%d/%d", operationCalls, personPolicyCalls, accessPolicyCalls)
	}
	if presentedPerson.JTI == "" || presentedPerson.Subject == "" {
		t.Fatalf("protected request did not expose a person-token context: %#v", presentedPerson)
	}
	thumbprint, err := agentKey.PublicJWK().Thumbprint()
	if err != nil {
		t.Fatal(err)
	}
	stepUpToken, err = aa.MintResourceToken(resourceKey, aa.ResourceTokenClaims{
		Issuer: "https://resource.example", DWK: aa.ResourceDiscoveryDocument,
		Audience: "https://as.example", JTI: "step-up-resource-token",
		AgentJKT: thumbprint, IssuedAt: now.Unix(), ExpiresAt: now.Add(5 * time.Minute).Unix(),
		Scope: "records.read records.write", PersonServer: presentedPerson.Issuer,
		Subject: presentedPerson.Subject, PresentedJTI: presentedPerson.JTI,
	})
	if err != nil {
		t.Fatal(err)
	}
	stepUpArmed = true

	response, err = agent.Do(context.Background(), call)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(response.Body)
		t.Fatalf("step-up protected result status = %d, body = %s", response.StatusCode, body)
	}
	if operationCalls != 2 || personPolicyCalls != 2 || accessPolicyCalls != 2 {
		t.Fatalf("step-up operation/PS/AS calls = %d/%d/%d, want 2/2/2", operationCalls, personPolicyCalls, accessPolicyCalls)
	}
	if operationRequest.Method != call.Method || operationRequest.Path != "/records" ||
		operationRequest.Target != "/records" || string(operationRequest.Body) != string(call.Body) ||
		operationRequest.ContentType != call.ContentType {
		t.Fatalf("step-up operation call changed: %#v", operationRequest)
	}

	response.Body.Close()
	response, err = agent.Do(context.Background(), call)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(response.Body)
		t.Fatalf("cached upgraded protected result status = %d, body = %s", response.StatusCode, body)
	}
	if operationCalls != 3 || len(operationAuthTokenIDs) != 3 {
		t.Fatalf("cached upgraded operation calls = %d, token ids = %#v", operationCalls, operationAuthTokenIDs)
	}
	if operationAuthTokenIDs[2] != operationAuthTokenIDs[1] {
		t.Fatalf("cached call used token %q after upgraded token %q", operationAuthTokenIDs[2], operationAuthTokenIDs[1])
	}
}
