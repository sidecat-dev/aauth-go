package agent_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/agent"
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

func TestNewUsesCallerContextForTokenVerification(t *testing.T) {
	t.Parallel()

	protocol := newTestProtocol(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := agent.New(ctx, agent.Config{
		Identifier: protocol.agentID, SigningKey: protocol.agentKey,
		AgentToken: protocol.agentToken,
		KeyResolver: resolverFunc(func(ctx context.Context, _, _, _ string) (jose.JWK, error) {
			return jose.JWK{}, ctx.Err()
		}),
		HTTPClient: http.DefaultClient,
		Clock:      protocol.clock,
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("New error = %v, want context canceled", err)
	}
}

func TestExchangeForwardsResourceLoginHintUnchanged(t *testing.T) {
	t.Parallel()

	const hint = "person@example.com"
	protocol := newTestProtocol(t)
	protocol.resourceLoginHint = hint
	client := protocol.newClient(t)
	personToken := requestImmediatePersonToken(t, client, agent.PersonTokenRequest{
		PersonServer: protocol.personServerID,
		Resource:     protocol.resourceID,
		LoginHint:    "not-sent-on-the-token-request",
		Capabilities: []string{"interaction"},
	})
	if protocol.personLoginHint != "not-sent-on-the-token-request" || len(protocol.personCapabilities) != 1 || protocol.personCapabilities[0] != "interaction" {
		t.Fatalf("person request hint = %q capabilities = %#v", protocol.personLoginHint, protocol.personCapabilities)
	}
	resourceToken, err := client.Authorize(context.Background(), agent.AuthorizeRequest{
		Resource: protocol.resourceID, PersonToken: personToken, Scopes: []string{"records.read"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Exchange(context.Background(), agent.ExchangeRequest{
		PersonServer: protocol.personServerID, ResourceToken: resourceToken, PresentedToken: personToken,
	}); err != nil {
		t.Fatal(err)
	}
	if protocol.exchangedLoginHint != hint {
		t.Fatalf("token request login_hint = %q, want %q", protocol.exchangedLoginHint, hint)
	}
}

func TestClientCompletesImmediateCoreCallsWithJWTProofs(t *testing.T) {
	t.Parallel()

	protocol := newTestProtocol(t)
	client := protocol.newClient(t)

	personToken := requestImmediatePersonToken(t, client, agent.PersonTokenRequest{
		PersonServer: protocol.personServerID,
		Resource:     protocol.resourceID,
	})
	var err error
	resourceToken, err := client.Authorize(context.Background(), agent.AuthorizeRequest{
		Resource:    protocol.resourceID,
		PersonToken: personToken,
		Scopes:      []string{"records.read"},
	})
	if err != nil {
		t.Fatal(err)
	}
	authToken, err := client.Exchange(context.Background(), agent.ExchangeRequest{
		PersonServer:   protocol.personServerID,
		ResourceToken:  resourceToken,
		PresentedToken: personToken,
	})
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest(http.MethodGet, protocol.resourceID+"/records/42", nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Do(context.Background(), agent.Call{Request: request, AuthToken: authToken})
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("protected status = %d", response.StatusCode)
	}
	if got, want := protocol.paths, []string{
		"/.well-known/aauth-person.json", "/person",
		"/.well-known/aauth-resource.json", "/authorize",
		"/.well-known/aauth-person.json", "/token",
		"/.well-known/aauth-resource.json",
		"/records/42",
	}; !slicesEqual(got, want) {
		t.Fatalf("request paths = %v, want %v", got, want)
	}
}

func TestClientAcceptsIndependentResourceAndAuthTokenLifetimes(t *testing.T) {
	t.Parallel()

	protocol := newTestProtocol(t)
	protocol.personTokenLifetime = time.Minute
	protocol.resourceTokenLifetime = 5 * time.Minute
	protocol.authTokenLifetime = 30 * time.Minute
	client := protocol.newClient(t)

	personToken := requestImmediatePersonToken(t, client, agent.PersonTokenRequest{
		PersonServer: protocol.personServerID, Resource: protocol.resourceID,
	})
	var err error
	resourceToken, err := client.Authorize(context.Background(), agent.AuthorizeRequest{
		Resource: protocol.resourceID, PersonToken: personToken, Scopes: []string{"records.read"},
	})
	if err != nil {
		t.Fatal(err)
	}
	resourceClaims, err := aauth.VerifyResourceToken(context.Background(), resourceToken, protocol.resolver, protocol.clock)
	if err != nil {
		t.Fatal(err)
	}
	if resourceClaims.ExpiresAt != protocol.now.Add(5*time.Minute).Unix() {
		t.Fatalf("resource-token exp = %d", resourceClaims.ExpiresAt)
	}
	authToken, err := client.Exchange(context.Background(), agent.ExchangeRequest{
		PersonServer: protocol.personServerID, ResourceToken: resourceToken, PresentedToken: personToken,
	})
	if err != nil {
		t.Fatal(err)
	}
	authClaims, err := aauth.VerifyAuthToken(context.Background(), authToken, protocol.resolver, protocol.clock)
	if err != nil {
		t.Fatal(err)
	}
	if authClaims.ExpiresAt != protocol.now.Add(30*time.Minute).Unix() {
		t.Fatalf("auth-token exp = %d", authClaims.ExpiresAt)
	}
}

func TestClientRejectsAPersonTokenThatOutlivesTheAgentTokenUsedToRequestIt(t *testing.T) {
	t.Parallel()

	protocol := newTestProtocol(t)
	shortAgentToken, err := aauth.MintAgentToken(
		protocol.agentProviderID, protocol.agentProviderKey,
		aauth.AgentTokenRequest{
			Agent: protocol.agentID, PersonServer: protocol.personServerID,
			PublicKey: protocol.agentKey.PublicJWK(), Lifetime: 5 * time.Minute,
		}, protocol.now, "short-agent-token",
	)
	if err != nil {
		t.Fatal(err)
	}
	protocol.agentToken = shortAgentToken
	protocol.personTokenLifetime = 30 * time.Minute
	client := protocol.newClient(t)
	_, err = client.PersonToken(context.Background(), agent.PersonTokenRequest{
		PersonServer: protocol.personServerID, Resource: protocol.resourceID,
	})
	if err == nil || !strings.Contains(err.Error(), "lifetime exceeds agent token") {
		t.Fatalf("PersonToken error = %v", err)
	}
}

func TestClientRefusesUnrelatedAuthTokensBeforeProtectedNetworkUse(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name   string
		change func(*aauth.AuthTokenClaims)
	}{
		{name: "outlives agent token", change: func(claims *aauth.AuthTokenClaims) {
			claims.ExpiresAt = claims.IssuedAt + int64((30*time.Minute)/time.Second)
		}},
		{name: "wrong person server", change: func(claims *aauth.AuthTokenClaims) {
			claims.PersonServer = "https://other-ps.example"
		}},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			protocol := newTestProtocol(t)
			shortAgentToken, err := aauth.MintAgentToken(
				protocol.agentProviderID, protocol.agentProviderKey,
				aauth.AgentTokenRequest{
					Agent: protocol.agentID, PersonServer: protocol.personServerID,
					PublicKey: protocol.agentKey.PublicJWK(), Lifetime: 5 * time.Minute,
				}, protocol.now, "short-agent-token",
			)
			if err != nil {
				t.Fatal(err)
			}
			protocol.agentToken = shortAgentToken
			client := protocol.newClient(t)
			claims := aauth.AuthTokenClaims{
				Issuer: protocol.accessServerID, DWK: aauth.AccessDiscoveryDocument,
				Audience: protocol.resourceID, JTI: "auth-token-1",
				PersonServer: protocol.personServerID, Subject: "person-123", Scope: "records.read",
				Confirmation: aauth.Confirmation{JWK: protocol.agentKey.PublicJWK()},
				IssuedAt:     protocol.now.Unix(), ExpiresAt: protocol.now.Add(4 * time.Minute).Unix(),
			}
			test.change(&claims)
			authToken, err := aauth.MintAuthToken(protocol.accessServerKey, claims)
			if err != nil {
				t.Fatal(err)
			}
			request, _ := http.NewRequest(http.MethodGet, protocol.resourceID+"/records/42", nil)
			_, err = client.Do(context.Background(), agent.Call{Request: request, AuthToken: authToken})
			if err == nil {
				t.Fatal("Do accepted an unrelated auth token")
			}
			if test.name == "wrong person server" && !strings.Contains(err.Error(), "auth-token person server:") {
				t.Fatalf("Do error = %v", err)
			}
			if len(protocol.paths) != 0 {
				t.Fatalf("network paths = %v", protocol.paths)
			}
		})
	}
}

func TestClientUsesResourceMetadataSignatureComponents(t *testing.T) {
	t.Parallel()

	protocol := newTestProtocol(t)
	protocol.additionalSignatureComponents = []string{"content-type", "content-digest", "x-request-id"}
	protocol.authorizationHeaders = http.Header{"X-Request-ID": []string{"authorize-42"}}
	client := protocol.newClient(t)
	authToken := protocol.issueAuthToken(t, client)
	for _, component := range protocol.additionalSignatureComponents {
		if !containsString(protocol.authorizationComponents, component) {
			t.Errorf("authorization signature components = %v, missing %q", protocol.authorizationComponents, component)
		}
	}

	body := `{"query":"current"}`
	request, err := http.NewRequest(http.MethodPost, protocol.resourceID+"/records/42", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Request-ID", "request-42")
	response, err := client.Do(context.Background(), agent.Call{Request: request, AuthToken: authToken})
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	for _, component := range protocol.additionalSignatureComponents {
		if !containsString(protocol.protectedComponents, component) {
			t.Errorf("protected signature components = %v, missing %q", protocol.protectedComponents, component)
		}
	}

	limited := protocol.newClientWithMaxSignedBodyBytes(t, int64(len(body)-1))
	request, err = http.NewRequest(http.MethodPost, protocol.resourceID+"/records/42", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Request-ID", "request-too-large")
	if _, err := limited.Do(context.Background(), agent.Call{Request: request, AuthToken: authToken}); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversize protected call error = %v", err)
	}
}

func TestClientSignsBodylessProtectedRequestWithoutDigest(t *testing.T) {
	t.Parallel()

	protocol := newTestProtocol(t)
	protocol.additionalSignatureComponents = []string{"x-request-id"}
	protocol.authorizationHeaders = http.Header{"X-Request-ID": []string{"authorize-bodyless-42"}}
	client := protocol.newClient(t)
	authToken := protocol.issueAuthToken(t, client)
	// A protected call does not require the optional authorization endpoint.
	protocol.authorizationEndpoint = ""

	request, err := http.NewRequest(http.MethodGet, protocol.resourceID+"/records/42", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("X-Request-ID", "bodyless-42")
	response, err := client.Do(context.Background(), agent.Call{Request: request, AuthToken: authToken})
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if !containsString(protocol.protectedComponents, "x-request-id") {
		t.Fatalf("protected signature components = %v", protocol.protectedComponents)
	}
	if containsString(protocol.protectedComponents, "content-digest") {
		t.Fatalf("bodyless signature components = %v, want no content-digest", protocol.protectedComponents)
	}
}

func TestClientUsesConfiguredAuthorizationHeaderComponent(t *testing.T) {
	t.Parallel()

	protocol := newTestProtocol(t)
	protocol.additionalSignatureComponents = []string{"authorization"}
	protocol.authorizationHeaders = http.Header{"Authorization": []string{"AAuth wrapped-session-token"}}
	client := protocol.newClient(t)
	protocol.issueAuthToken(t, client)
	if !containsString(protocol.authorizationComponents, "authorization") {
		t.Fatalf("authorization signature components = %v", protocol.authorizationComponents)
	}
}

func TestClientAcceptsOptionalAndExtensionMetadataMembers(t *testing.T) {
	t.Parallel()

	protocol := newTestProtocol(t)
	protocol.metadataExtensions = true
	client := protocol.newClient(t)
	personToken := requestImmediatePersonToken(t, client, agent.PersonTokenRequest{
		PersonServer: protocol.personServerID, Resource: protocol.resourceID,
	})
	if _, err := client.Authorize(context.Background(), agent.AuthorizeRequest{
		Resource: protocol.resourceID, PersonToken: personToken, Scopes: []string{"records.read"},
	}); err != nil {
		t.Fatal(err)
	}
}

func TestAuthorizePreservesCoreEmptyScopeError(t *testing.T) {
	t.Parallel()

	protocol := newTestProtocol(t)
	client := protocol.newClient(t)
	personToken := requestImmediatePersonToken(t, client, agent.PersonTokenRequest{
		PersonServer: protocol.personServerID, Resource: protocol.resourceID,
	})
	_, err := client.Authorize(context.Background(), agent.AuthorizeRequest{
		Resource: protocol.resourceID, PersonToken: personToken,
	})
	if err == nil || !strings.Contains(err.Error(), "at least one scope is required") {
		t.Fatalf("Authorize error = %v", err)
	}
}

func TestClientAcceptsCaseDistinctScopeDescriptionKeys(t *testing.T) {
	t.Parallel()

	protocol := newTestProtocol(t)
	protocol.caseDistinctScopeNames = true
	client := protocol.newClient(t)
	personToken := requestImmediatePersonToken(t, client, agent.PersonTokenRequest{
		PersonServer: protocol.personServerID, Resource: protocol.resourceID,
	})
	if _, err := client.Authorize(context.Background(), agent.AuthorizeRequest{
		Resource: protocol.resourceID, PersonToken: personToken, Scopes: []string{"records.read"},
	}); err != nil {
		t.Fatal(err)
	}
}

func TestClientAcceptsAdditiveTokenResponseMembers(t *testing.T) {
	t.Parallel()

	protocol := newTestProtocol(t)
	protocol.responseExtensions = true
	client := protocol.newClient(t)
	if token := protocol.issueAuthToken(t, client); token == "" {
		t.Fatal("four-party flow returned an empty auth token")
	}
}

func TestClientLeavesOrdinaryProblemDetailsToTheProtectedApplication(t *testing.T) {
	t.Parallel()

	protocol := newTestProtocol(t)
	protocol.protectedProblem = true
	client := protocol.newClient(t)
	authToken := protocol.issueAuthToken(t, client)
	request, err := http.NewRequest(http.MethodGet, protocol.resourceID+"/records/42", nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Do(context.Background(), agent.Call{Request: request, AuthToken: authToken})
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusConflict || string(body) != `{"type":"https://resource.example/problems/version","status":409,"detail":"version changed"}` {
		t.Fatalf("protected response = %d %s", response.StatusCode, body)
	}
}

func TestClientUsesAuthoritativeSignatureErrorOnProtected401(t *testing.T) {
	t.Parallel()

	protocol := newTestProtocol(t)
	client := protocol.newClient(t)
	authToken := protocol.issueAuthToken(t, client)
	protocol.protectedSignatureError = &signaturekey.Error{Code: signaturekey.ErrorExpiredJWT}
	request, err := http.NewRequest(http.MethodGet, protocol.resourceID+"/records/42", nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Do(context.Background(), agent.Call{Request: request, AuthToken: authToken})
	var signatureFailure *signaturekey.Error
	if !errors.As(err, &signatureFailure) || signatureFailure.Code != signaturekey.ErrorExpiredJWT {
		t.Fatalf("protected error = %v, Signature-Error = %#v", err, signatureFailure)
	}
}

func TestClientReturnsOrdinaryProtected401WithoutSignatureError(t *testing.T) {
	t.Parallel()

	protocol := newTestProtocol(t)
	client := protocol.newClient(t)
	authToken := protocol.issueAuthToken(t, client)
	protocol.protectedUnauthorized = true
	request, err := http.NewRequest(http.MethodGet, protocol.resourceID+"/records/42", nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Do(context.Background(), agent.Call{Request: request, AuthToken: authToken})
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized || response.Header.Get("AAuth-Requirement") == "" {
		t.Fatalf("protected response = %d %#v", response.StatusCode, response.Header)
	}
}

func TestClientUsesEndpointsDiscoveredFromRoleMetadata(t *testing.T) {
	t.Parallel()

	protocol := newTestProtocol(t)
	protocol.personTokenEndpoint = protocol.personServerID + "/v2/person-tokens"
	protocol.authTokenEndpoint = protocol.personServerID + "/v2/authorizations"
	protocol.authorizationEndpoint = protocol.resourceID + "/v3/agent-authorizations"
	client := protocol.newClient(t)

	personToken := requestImmediatePersonToken(t, client, agent.PersonTokenRequest{
		PersonServer: protocol.personServerID,
		Resource:     protocol.resourceID,
	})
	var err error
	resourceToken, err := client.Authorize(context.Background(), agent.AuthorizeRequest{
		Resource: protocol.resourceID, PersonToken: personToken,
		Scopes: []string{"records.read"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Exchange(context.Background(), agent.ExchangeRequest{
		PersonServer: protocol.personServerID, ResourceToken: resourceToken, PresentedToken: personToken,
	}); err != nil {
		t.Fatal(err)
	}

	want := []string{
		"/.well-known/aauth-person.json", "/v2/person-tokens",
		"/.well-known/aauth-resource.json", "/v3/agent-authorizations",
		"/.well-known/aauth-person.json", "/v2/authorizations",
	}
	if !slicesEqual(protocol.paths, want) {
		t.Fatalf("request paths = %v, want %v", protocol.paths, want)
	}
}

func TestClientRejectsInvalidRoleMetadata(t *testing.T) {
	t.Parallel()

	t.Run("person server issuer mismatch", func(t *testing.T) {
		protocol := newTestProtocol(t)
		protocol.personMetadataIssuer = "https://other-ps.example"
		_, err := protocol.newClient(t).PersonToken(context.Background(), agent.PersonTokenRequest{
			PersonServer: protocol.personServerID, Resource: protocol.resourceID,
		})
		if err == nil || !strings.Contains(err.Error(), "metadata issuer") {
			t.Fatalf("PersonToken error = %v", err)
		}
	})

	t.Run("person token endpoint is not https", func(t *testing.T) {
		protocol := newTestProtocol(t)
		protocol.personTokenEndpoint = "http://ps.example/person"
		_, err := protocol.newClient(t).PersonToken(context.Background(), agent.PersonTokenRequest{
			PersonServer: protocol.personServerID, Resource: protocol.resourceID,
		})
		if err == nil || !strings.Contains(err.Error(), "person_token_endpoint") {
			t.Fatalf("PersonToken error = %v", err)
		}
	})

	t.Run("resource issuer mismatch", func(t *testing.T) {
		protocol := newTestProtocol(t)
		client := protocol.newClient(t)
		personToken := requestImmediatePersonToken(t, client, agent.PersonTokenRequest{
			PersonServer: protocol.personServerID, Resource: protocol.resourceID,
		})
		protocol.resourceMetadataIssuer = "https://other-resource.example"
		_, err := client.Authorize(context.Background(), agent.AuthorizeRequest{
			Resource: protocol.resourceID, PersonToken: personToken, Scopes: []string{"records.read"},
		})
		if err == nil || !strings.Contains(err.Error(), "metadata issuer") {
			t.Fatalf("Authorize error = %v", err)
		}
	})

	t.Run("display URI is not https", func(t *testing.T) {
		for _, field := range []string{"logo_uri", "logo_dark_uri", "documentation_uri", "tos_uri", "policy_uri"} {
			field := field
			t.Run(field, func(t *testing.T) {
				protocol := newTestProtocol(t)
				protocol.personDisplayURIField = field
				protocol.personDisplayURIValue = "http://insecure.example/" + field
				_, err := protocol.newClient(t).PersonToken(context.Background(), agent.PersonTokenRequest{
					PersonServer: protocol.personServerID, Resource: protocol.resourceID,
				})
				if err == nil || !strings.Contains(err.Error(), field) {
					t.Fatalf("PersonToken error = %v", err)
				}
			})
		}
	})

	t.Run("display URI may carry a query", func(t *testing.T) {
		protocol := newTestProtocol(t)
		protocol.personDisplayURIField = "logo_uri"
		protocol.personDisplayURIValue = "https://ps.example/logo.svg?v=1"
		if _, err := protocol.newClient(t).PersonToken(context.Background(), agent.PersonTokenRequest{
			PersonServer: protocol.personServerID, Resource: protocol.resourceID,
		}); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("resource display URI is not https", func(t *testing.T) {
		protocol := newTestProtocol(t)
		client := protocol.newClient(t)
		personToken := requestImmediatePersonToken(t, client, agent.PersonTokenRequest{
			PersonServer: protocol.personServerID, Resource: protocol.resourceID,
		})
		protocol.resourceDisplayURIField = "policy_uri"
		protocol.resourceDisplayURIValue = "http://resource.example/policy"
		_, err := client.Authorize(context.Background(), agent.AuthorizeRequest{
			Resource: protocol.resourceID, PersonToken: personToken, Scopes: []string{"records.read"},
		})
		if err == nil || !strings.Contains(err.Error(), "policy_uri") {
			t.Fatalf("Authorize error = %v", err)
		}
	})

	t.Run("authorization endpoint has a query", func(t *testing.T) {
		protocol := newTestProtocol(t)
		client := protocol.newClient(t)
		personToken := requestImmediatePersonToken(t, client, agent.PersonTokenRequest{
			PersonServer: protocol.personServerID, Resource: protocol.resourceID,
		})
		protocol.authorizationEndpoint = protocol.resourceID + "/authorize?mode=agent"
		_, err := client.Authorize(context.Background(), agent.AuthorizeRequest{
			Resource: protocol.resourceID, PersonToken: personToken, Scopes: []string{"records.read"},
		})
		if err == nil || !strings.Contains(err.Error(), "authorization_endpoint") {
			t.Fatalf("Authorize error = %v", err)
		}
	})
}

func TestClientRefusesRedirectsWithoutMutatingCallerHTTPClient(t *testing.T) {
	t.Parallel()

	for _, status := range []int{http.StatusFound, http.StatusTemporaryRedirect} {
		status := status
		t.Run(http.StatusText(status), func(t *testing.T) {
			protocol := newTestProtocol(t)
			protocol.redirectStatus = status
			callerClient := &http.Client{Transport: roundTripperFunc(protocol.roundTrip)}
			client := protocol.newClientWithHTTPClient(t, callerClient)
			_, err := client.PersonToken(context.Background(), agent.PersonTokenRequest{
				PersonServer: protocol.personServerID, Resource: protocol.resourceID,
			})
			if err == nil || !strings.Contains(err.Error(), "redirect") {
				t.Fatalf("PersonToken error = %v", err)
			}
			if protocol.redirectedRequests != 0 {
				t.Fatalf("cross-origin redirected requests = %d, want 0", protocol.redirectedRequests)
			}
			if callerClient.CheckRedirect != nil {
				t.Fatal("New mutated the caller's HTTP client")
			}
		})
	}
}

func TestClientRejectsReturnedTokensOutsideThePrecedingContext(t *testing.T) {
	t.Parallel()

	t.Run("person token audience", func(t *testing.T) {
		protocol := newTestProtocol(t)
		protocol.personAudience = "https://other-resource.example"
		_, err := protocol.newClient(t).PersonToken(context.Background(), agent.PersonTokenRequest{
			PersonServer: protocol.personServerID,
			Resource:     protocol.resourceID,
		})
		if err == nil || !strings.Contains(err.Error(), "audience") {
			t.Fatalf("PersonToken error = %v", err)
		}
	})

	t.Run("resource token scope", func(t *testing.T) {
		protocol := newTestProtocol(t)
		client := protocol.newClient(t)
		personToken := requestImmediatePersonToken(t, client, agent.PersonTokenRequest{
			PersonServer: protocol.personServerID,
			Resource:     protocol.resourceID,
		})
		protocol.resourceScope = "records.write"
		_, err := client.Authorize(context.Background(), agent.AuthorizeRequest{
			Resource: protocol.resourceID, PersonToken: personToken,
			Scopes: []string{"records.read"},
		})
		if err == nil || !strings.Contains(err.Error(), "scope") {
			t.Fatalf("Authorize error = %v", err)
		}
	})

	t.Run("auth token person", func(t *testing.T) {
		protocol := newTestProtocol(t)
		client := protocol.newClient(t)
		personToken := requestImmediatePersonToken(t, client, agent.PersonTokenRequest{
			PersonServer: protocol.personServerID,
			Resource:     protocol.resourceID,
		})
		resourceToken, err := client.Authorize(context.Background(), agent.AuthorizeRequest{
			Resource: protocol.resourceID, PersonToken: personToken,
			Scopes: []string{"records.read"},
		})
		if err != nil {
			t.Fatal(err)
		}
		protocol.authSubject = "other-person"
		_, err = client.Exchange(context.Background(), agent.ExchangeRequest{
			PersonServer: protocol.personServerID, ResourceToken: resourceToken, PresentedToken: personToken,
		})
		if err == nil || !strings.Contains(err.Error(), "auth-token sub") {
			t.Fatalf("Exchange error = %v", err)
		}
	})

	t.Run("auth token changes person server", func(t *testing.T) {
		protocol := newTestProtocol(t)
		client := protocol.newClient(t)
		personToken := requestImmediatePersonToken(t, client, agent.PersonTokenRequest{
			PersonServer: protocol.personServerID, Resource: protocol.resourceID,
		})
		resourceToken, err := client.Authorize(context.Background(), agent.AuthorizeRequest{
			Resource: protocol.resourceID, PersonToken: personToken, Scopes: []string{"records.read"},
		})
		if err != nil {
			t.Fatal(err)
		}
		protocol.authDiscoveryDocument = aauth.PersonDiscoveryDocument
		protocol.authPersonServer = protocol.accessServerID
		_, err = client.Exchange(context.Background(), agent.ExchangeRequest{
			PersonServer: protocol.personServerID, ResourceToken: resourceToken, PresentedToken: personToken,
		})
		if err == nil || !strings.Contains(err.Error(), "auth-token ps") {
			t.Fatalf("Exchange error = %v", err)
		}
	})

	t.Run("PS-AS collapse accepts access-server issuer role", func(t *testing.T) {
		protocol := newTestProtocol(t)
		protocol.resourceAudience = protocol.personServerID
		protocol.authIssuer = protocol.personServerID
		protocol.authDiscoveryDocument = aauth.AccessDiscoveryDocument
		protocol.authSigningKey = protocol.accessServerKey
		client := protocol.newClient(t)
		personToken := requestImmediatePersonToken(t, client, agent.PersonTokenRequest{
			PersonServer: protocol.personServerID, Resource: protocol.resourceID,
		})
		resourceToken, err := client.Authorize(context.Background(), agent.AuthorizeRequest{
			Resource: protocol.resourceID, PersonToken: personToken, Scopes: []string{"records.read"},
		})
		if err != nil {
			t.Fatal(err)
		}
		authToken, err := client.Exchange(context.Background(), agent.ExchangeRequest{
			PersonServer: protocol.personServerID, ResourceToken: resourceToken, PresentedToken: personToken,
		})
		if err != nil || authToken == "" {
			t.Fatalf("Exchange = %q, %v", authToken, err)
		}
	})
}

func TestClientRefusesResourceTokenBranchesOutsideTheImmediateFlow(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name        string
		configure   func(*testProtocol)
		errorDetail string
	}{
		{
			name: "account",
			configure: func(protocol *testProtocol) {
				protocol.resourceAccount = "account-123"
			},
			errorDetail: "account does not match the request",
		},
		{
			name: "mission substitution",
			configure: func(protocol *testProtocol) {
				protocol.resourceMissionS256 = strings.Repeat("A", 43)
			},
			errorDetail: "context does not match person token",
		},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			protocol := newTestProtocol(t)
			test.configure(protocol)
			client := protocol.newClient(t)
			personToken := requestImmediatePersonToken(t, client, agent.PersonTokenRequest{
				PersonServer: protocol.personServerID, Resource: protocol.resourceID,
			})
			_, err := client.Authorize(context.Background(), agent.AuthorizeRequest{
				Resource: protocol.resourceID, PersonToken: personToken, Scopes: []string{"records.read"},
			})
			if err == nil || !strings.Contains(err.Error(), test.errorDetail) {
				t.Fatalf("Authorize error = %v", err)
			}
		})
	}
}

func TestClientPresentsMissionBoundProtectedCall(t *testing.T) {
	t.Parallel()

	protocol := newTestProtocol(t)
	client := protocol.newClient(t)
	compact, err := aauth.MintAuthToken(protocol.accessServerKey, aauth.AuthTokenClaims{
		Issuer: protocol.accessServerID, DWK: aauth.AccessDiscoveryDocument,
		Audience: protocol.resourceID, JTI: "mission-auth-token",
		Confirmation: aauth.Confirmation{JWK: protocol.agentKey.PublicJWK()},
		IssuedAt:     protocol.now.Unix(), ExpiresAt: protocol.now.Add(10 * time.Minute).Unix(),
		Subject: "person-123", Scope: "records.read", PersonServer: protocol.personServerID,
		MissionS256: strings.Repeat("A", 43),
	})
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest(http.MethodGet, protocol.resourceID+"/records/42", nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Do(context.Background(), agent.Call{Request: request, AuthToken: compact})
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", response.StatusCode)
	}
}

func TestClientAcceptsReturnedResourceScopeAsRequestedSubset(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name          string
		requested     []string
		returnedScope string
	}{
		{name: "reordered", requested: []string{"records.read", "profile.read"}, returnedScope: "profile.read records.read"},
		{name: "narrowed", requested: []string{"records.read", "profile.read"}, returnedScope: "records.read"},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			protocol := newTestProtocol(t)
			client := protocol.newClient(t)
			personToken := requestImmediatePersonToken(t, client, agent.PersonTokenRequest{
				PersonServer: protocol.personServerID, Resource: protocol.resourceID,
			})
			protocol.resourceScope = test.returnedScope
			if _, err := client.Authorize(context.Background(), agent.AuthorizeRequest{
				Resource: protocol.resourceID, PersonToken: personToken, Scopes: test.requested,
			}); err != nil {
				t.Fatalf("Authorize returned %v for scope %q within %v", err, test.returnedScope, test.requested)
			}
		})
	}
}

func TestClientPreservesRemoteAAuthProblem(t *testing.T) {
	t.Parallel()

	protocol := newTestProtocol(t)
	protocol.problem = &aauth.ProblemError{
		Type: "https://aauth.example/errors/person-token-denied", Title: "Forbidden",
		Status: http.StatusForbidden, Code: "person_token_denied", Detail: "person-token policy denied this request",
	}
	_, err := protocol.newClient(t).PersonToken(context.Background(), agent.PersonTokenRequest{
		PersonServer: protocol.personServerID,
		Resource:     protocol.resourceID,
	})
	if err == nil {
		t.Fatal("PersonToken succeeded")
	}
	var operationError *agent.Error
	if !errors.As(err, &operationError) || operationError.Operation != "person token" {
		t.Fatalf("operation error = %#v", operationError)
	}
	var problem *aauth.ProblemError
	if !errors.As(err, &problem) || problem.Code != "person_token_denied" ||
		problem.Detail != "person-token policy denied this request" {
		t.Fatalf("problem = %#v; error = %v", problem, err)
	}
}

func TestClientPreservesSignatureErrorOnUnauthorized(t *testing.T) {
	t.Parallel()

	protocol := newTestProtocol(t)
	protocol.signatureError = &signaturekey.Error{
		Code:               signaturekey.ErrorUnsupportedAlgorithm,
		AcceptedAlgorithms: []string{"Ed25519"},
		AcceptedSchemes:    []signaturekey.Scheme{signaturekey.SchemeJWT},
	}
	_, err := protocol.newClient(t).PersonToken(context.Background(), agent.PersonTokenRequest{
		PersonServer: protocol.personServerID,
		Resource:     protocol.resourceID,
	})
	if err == nil {
		t.Fatal("PersonToken succeeded")
	}
	var signatureError *signaturekey.Error
	if !errors.As(err, &signatureError) {
		t.Fatalf("error = %v, want *signaturekey.Error", err)
	}
	if signatureError.Code != signaturekey.ErrorUnsupportedAlgorithm ||
		!slicesEqual(signatureError.AcceptedAlgorithms, []string{"Ed25519"}) ||
		len(signatureError.AcceptedSchemes) != 1 || signatureError.AcceptedSchemes[0] != signaturekey.SchemeJWT {
		t.Fatalf("Signature-Error = %#v", signatureError)
	}
	var problem *aauth.ProblemError
	if errors.As(err, &problem) {
		t.Fatalf("401 problem body overrode Signature-Error: %#v", problem)
	}
}

type testProtocol struct {
	t                             *testing.T
	now                           time.Time
	clock                         aauth.Clock
	agentProviderID               string
	agentID                       string
	personServerID                string
	accessServerID                string
	resourceID                    string
	agentProviderKey              jose.SigningKey
	agentKey                      jose.SigningKey
	personServerKey               jose.SigningKey
	accessServerKey               jose.SigningKey
	resourceKey                   jose.SigningKey
	agentToken                    string
	resolver                      signaturekey.StaticKeyResolver
	paths                         []string
	personAudience                string
	resourceScope                 string
	resourceAudience              string
	resourceAccount               string
	resourceLoginHint             string
	resourceInteraction           *aauth.ResourceInteraction
	resourceMissionS256           string
	personTokenLifetime           time.Duration
	resourceTokenLifetime         time.Duration
	authTokenLifetime             time.Duration
	authSubject                   string
	authDiscoveryDocument         string
	authIssuer                    string
	authSigningKey                jose.SigningKey
	authPersonServer              string
	problem                       *aauth.ProblemError
	personMetadataIssuer          string
	resourceMetadataIssuer        string
	personTokenEndpoint           string
	authTokenEndpoint             string
	authorizationEndpoint         string
	redirectStatus                int
	redirectedRequests            int
	signatureError                *signaturekey.Error
	additionalSignatureComponents []string
	metadataExtensions            bool
	personDisplayURIField         string
	personDisplayURIValue         string
	resourceDisplayURIField       string
	resourceDisplayURIValue       string
	responseExtensions            bool
	caseDistinctScopeNames        bool
	protectedProblem              bool
	protectedUnauthorized         bool
	protectedSignatureError       *signaturekey.Error
	authorizationHeaders          http.Header
	authorizationComponents       []string
	protectedComponents           []string
	personLoginHint               string
	personCapabilities            []string
	exchangedLoginHint            string
}

func newTestProtocol(t *testing.T) *testProtocol {
	t.Helper()
	protocol := &testProtocol{
		t: t, now: time.Date(2026, 8, 29, 18, 0, 0, 0, time.UTC),
		agentProviderID: "https://ap.example", agentID: "aauth:reader@ap.example",
		personServerID: "https://ps.example", accessServerID: "https://as.example",
		resourceID: "https://resource.example", resourceScope: "records.read", authSubject: "person-123",
		personMetadataIssuer: "https://ps.example", resourceMetadataIssuer: "https://resource.example",
		personTokenEndpoint: "https://ps.example/person", authTokenEndpoint: "https://ps.example/token",
		authorizationEndpoint: "https://resource.example/authorize",
		personTokenLifetime:   30 * time.Minute, resourceTokenLifetime: 20 * time.Minute,
		authTokenLifetime: 10 * time.Minute,
	}
	protocol.clock = aauth.ClockFunc(func() time.Time { return protocol.now })
	protocol.agentProviderKey = testSigningKey(t, "ap-key", 1)
	protocol.agentKey = testSigningKey(t, "agent-key", 2)
	protocol.personServerKey = testSigningKey(t, "ps-key", 3)
	protocol.accessServerKey = testSigningKey(t, "as-key", 4)
	protocol.resourceKey = testSigningKey(t, "resource-key", 5)
	protocol.resolver = signaturekey.StaticKeyResolver{
		{Issuer: protocol.agentProviderID, DiscoveryDocument: aauth.AgentDiscoveryDocument, KeyID: protocol.agentProviderKey.ID()}: protocol.agentProviderKey.PublicJWK(),
		{Issuer: protocol.personServerID, DiscoveryDocument: aauth.PersonDiscoveryDocument, KeyID: protocol.personServerKey.ID()}:  protocol.personServerKey.PublicJWK(),
		{Issuer: protocol.personServerID, DiscoveryDocument: aauth.AccessDiscoveryDocument, KeyID: protocol.accessServerKey.ID()}:  protocol.accessServerKey.PublicJWK(),
		{Issuer: protocol.accessServerID, DiscoveryDocument: aauth.AccessDiscoveryDocument, KeyID: protocol.accessServerKey.ID()}:  protocol.accessServerKey.PublicJWK(),
		{Issuer: protocol.accessServerID, DiscoveryDocument: aauth.PersonDiscoveryDocument, KeyID: protocol.accessServerKey.ID()}:  protocol.accessServerKey.PublicJWK(),
		{Issuer: protocol.resourceID, DiscoveryDocument: aauth.ResourceDiscoveryDocument, KeyID: protocol.resourceKey.ID()}:        protocol.resourceKey.PublicJWK(),
	}
	compact, err := aauth.MintAgentToken(protocol.agentProviderID, protocol.agentProviderKey, aauth.AgentTokenRequest{
		Agent: protocol.agentID, PersonServer: protocol.personServerID,
		PublicKey: protocol.agentKey.PublicJWK(), Lifetime: time.Hour,
	}, protocol.now, "agent-token-1")
	if err != nil {
		t.Fatal(err)
	}
	protocol.agentToken = compact
	return protocol
}

func (protocol *testProtocol) newClient(t *testing.T) *agent.Client {
	t.Helper()
	return protocol.newClientWithHTTPClient(t, &http.Client{Transport: roundTripperFunc(protocol.roundTrip)})
}

func (protocol *testProtocol) newClientWithMaxSignedBodyBytes(t *testing.T, limit int64) *agent.Client {
	t.Helper()
	client, err := agent.New(context.Background(), agent.Config{
		Identifier: protocol.agentID, SigningKey: protocol.agentKey,
		AgentToken: protocol.agentToken, KeyResolver: protocol.resolver,
		HTTPClient:         &http.Client{Transport: roundTripperFunc(protocol.roundTrip)},
		Clock:              protocol.clock,
		MaxSignedBodyBytes: limit,
	})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

type resolverFunc func(context.Context, string, string, string) (jose.JWK, error)

func (resolve resolverFunc) ResolveKey(ctx context.Context, issuer, document, keyID string) (jose.JWK, error) {
	return resolve(ctx, issuer, document, keyID)
}

func (protocol *testProtocol) issueAuthToken(t *testing.T, client *agent.Client) string {
	t.Helper()
	personToken := requestImmediatePersonToken(t, client, agent.PersonTokenRequest{
		PersonServer: protocol.personServerID, Resource: protocol.resourceID,
	})
	var err error
	resourceToken, err := client.Authorize(context.Background(), agent.AuthorizeRequest{
		Resource: protocol.resourceID, PersonToken: personToken, Scopes: []string{"records.read"},
		Header: protocol.authorizationHeaders,
	})
	if err != nil {
		t.Fatal(err)
	}
	authToken, err := client.Exchange(context.Background(), agent.ExchangeRequest{
		PersonServer: protocol.personServerID, ResourceToken: resourceToken, PresentedToken: personToken,
	})
	if err != nil {
		t.Fatal(err)
	}
	return authToken
}

func requestImmediatePersonToken(t *testing.T, client *agent.Client, request agent.PersonTokenRequest) string {
	t.Helper()
	result, err := client.PersonToken(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	token, ok := result.Token()
	if !ok || token == "" {
		t.Fatalf("PersonToken result = %#v, want immediate token", result)
	}
	return token
}

// presentedPersonToken mints the person token a hand-built resource token
// names, bound to the given agent key.
func (protocol *testProtocol) presentedPersonToken(
	t *testing.T, resource aauth.ResourceTokenClaims, confirmation jose.JWK,
) string {
	t.Helper()
	compact, err := aauth.MintPersonToken(protocol.personServerKey, aauth.PersonTokenClaims{
		Issuer: protocol.personServerID, DWK: aauth.PersonDiscoveryDocument, Audience: resource.Issuer,
		Subject: resource.Subject, Confirmation: aauth.Confirmation{JWK: confirmation},
		JTI: resource.PresentedJTI, IssuedAt: protocol.now.Unix(), ExpiresAt: protocol.now.Add(30 * time.Minute).Unix(),
		MissionS256: resource.MissionS256, Tenant: resource.Tenant,
	})
	if err != nil {
		t.Fatal(err)
	}
	return compact
}

func (protocol *testProtocol) newClientWithHTTPClient(t *testing.T, httpClient *http.Client) *agent.Client {
	t.Helper()
	client, err := agent.New(context.Background(), agent.Config{
		Identifier: protocol.agentID, SigningKey: protocol.agentKey,
		AgentToken: protocol.agentToken, KeyResolver: protocol.resolver,
		HTTPClient: httpClient,
		Clock:      protocol.clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func (protocol *testProtocol) roundTrip(request *http.Request) (*http.Response, error) {
	protocol.paths = append(protocol.paths, request.URL.Path)
	if request.URL.Host == "redirect-target.example" {
		protocol.redirectedRequests++
		return jsonResponse(request, http.StatusBadGateway, map[string]string{"error": "redirect followed"}), nil
	}
	if request.Method == http.MethodGet && request.URL.String() == protocol.personServerID+"/.well-known/aauth-person.json" {
		metadata := map[string]any{
			"issuer":                protocol.personMetadataIssuer,
			"person_token_endpoint": protocol.personTokenEndpoint,
			"auth_token_endpoint":   protocol.authTokenEndpoint,
		}
		if protocol.metadataExtensions {
			metadata["name"] = "Example Person Server"
			metadata["logo_uri"] = "https://ps.example/logo.svg"
			metadata["example_extension"] = map[string]any{"enabled": true}
		}
		if protocol.personDisplayURIField != "" {
			metadata[protocol.personDisplayURIField] = protocol.personDisplayURIValue
		}
		return jsonResponse(request, http.StatusOK, metadata), nil
	}
	if request.Method == http.MethodGet && request.URL.String() == protocol.resourceID+"/.well-known/aauth-resource.json" {
		scopeDescriptions := map[string]string{"records.read": "Read records"}
		if protocol.caseDistinctScopeNames {
			scopeDescriptions["RECORDS.READ"] = "Read uppercase records"
		}
		metadata := map[string]any{
			"issuer":                          protocol.resourceMetadataIssuer,
			"authorization_endpoint":          protocol.authorizationEndpoint,
			"scope_descriptions":              scopeDescriptions,
			"additional_signature_components": protocol.additionalSignatureComponents,
		}
		if protocol.metadataExtensions {
			metadata["description"] = "Example records"
			metadata["documentation_uri"] = "https://resource.example/docs"
			metadata["signature_window"] = 60
			metadata["example_extension"] = []string{"one", "two"}
		}
		if protocol.resourceDisplayURIField != "" {
			metadata[protocol.resourceDisplayURIField] = protocol.resourceDisplayURIValue
		}
		return jsonResponse(request, http.StatusOK, metadata), nil
	}
	if protocol.problem != nil && request.Method != http.MethodGet {
		return problemResponse(request, protocol.problem), nil
	}
	if protocol.signatureError != nil && request.Method != http.MethodGet {
		response := problemResponse(request, &aauth.ProblemError{
			Type: "https://aauth.example/errors/deceptive-body", Title: "Unauthorized",
			Status: http.StatusUnauthorized, Code: "deceptive_body", Detail: "not authoritative",
		})
		encoded, err := signaturekey.FormatError(*protocol.signatureError)
		if err != nil {
			protocol.t.Fatal(err)
		}
		response.Header.Set("Signature-Error", encoded)
		response.Header.Set("Accept-Signature-Alg", "Ed25519")
		response.Header.Set("Accept-Signature-Scheme", "jwt")
		return response, nil
	}
	if request.Method == http.MethodPost && request.URL.String() == protocol.personTokenEndpoint {
		if protocol.redirectStatus != 0 {
			response := jsonResponse(request, protocol.redirectStatus, nil)
			response.Header.Set("Location", "https://redirect-target.example/stolen")
			return response, nil
		}
		verified := verifyProof(protocol.t, request, protocol.resolver, protocol.clock, aauth.AgentTokenType)
		agentClaims, err := verified.AgentClaims()
		if err != nil {
			protocol.t.Fatal(err)
		}
		var input struct {
			Resource     string   `json:"resource"`
			LoginHint    string   `json:"login_hint"`
			Capabilities []string `json:"capabilities"`
		}
		decodeRequest(protocol.t, request, &input)
		protocol.personLoginHint = input.LoginHint
		protocol.personCapabilities = append([]string(nil), input.Capabilities...)
		if agentClaims.Subject != protocol.agentID || input.Resource != protocol.resourceID {
			protocol.t.Fatalf("person request = %#v, agent = %#v", input, agentClaims)
		}
		audience := protocol.personAudience
		if audience == "" {
			audience = protocol.resourceID
		}
		compact, err := aauth.MintPersonToken(protocol.personServerKey, aauth.PersonTokenClaims{
			Issuer: protocol.personServerID, DWK: aauth.PersonDiscoveryDocument,
			Audience: audience, Subject: "person-123",
			Confirmation: aauth.Confirmation{JWK: protocol.agentKey.PublicJWK()},
			JTI:          "person-token-1", IssuedAt: protocol.now.Unix(), ExpiresAt: protocol.now.Add(protocol.personTokenLifetime).Unix(),
		})
		if err != nil {
			protocol.t.Fatal(err)
		}
		output := map[string]any{"person_token": compact, "expires_in": int64(protocol.personTokenLifetime / time.Second)}
		if protocol.responseExtensions {
			output["example_extension"] = map[string]any{"future": true}
		}
		return jsonResponse(request, http.StatusOK, output), nil
	}
	if request.Method == http.MethodPost && request.URL.String() == protocol.authorizationEndpoint {
		verified := verifyProofWithComponents(
			protocol.t, request, protocol.resolver, protocol.clock,
			aauth.PersonTokenType, expectedAuthorizationComponents(protocol.additionalSignatureComponents),
		)
		protocol.authorizationComponents = verified.Proof.CoveredComponents()
		personClaims, err := verified.PersonClaims()
		if err != nil {
			protocol.t.Fatal(err)
		}
		var input struct {
			Scope string `json:"scope"`
		}
		decodeRequest(protocol.t, request, &input)
		thumbprint, err := protocol.agentKey.PublicJWK().Thumbprint()
		if err != nil {
			protocol.t.Fatal(err)
		}
		resourceAudience := protocol.resourceAudience
		if resourceAudience == "" {
			resourceAudience = protocol.accessServerID
		}
		compact, err := aauth.MintResourceToken(protocol.resourceKey, aauth.ResourceTokenClaims{
			Issuer: protocol.resourceID, DWK: aauth.ResourceDiscoveryDocument,
			Audience: resourceAudience, JTI: "resource-token-1",
			AgentJKT: thumbprint, IssuedAt: protocol.now.Unix(), ExpiresAt: protocol.now.Add(protocol.resourceTokenLifetime).Unix(),
			Scope: protocol.resourceScope, PersonServer: protocol.personServerID,
			Subject: personClaims.Subject, PresentedJTI: personClaims.JTI,
			Account: optionalTestStringPointer(protocol.resourceAccount), LoginHint: protocol.resourceLoginHint,
			Interaction: protocol.resourceInteraction,
			MissionS256: protocol.resourceMissionS256,
		})
		if err != nil {
			protocol.t.Fatal(err)
		}
		output := map[string]any{"resource_token": compact}
		if protocol.responseExtensions {
			output["example_extension"] = []string{"future"}
		}
		return jsonResponse(request, http.StatusOK, output), nil
	}
	if request.Method == http.MethodPost && request.URL.String() == protocol.authTokenEndpoint {
		verified := verifyProof(protocol.t, request, protocol.resolver, protocol.clock, aauth.AgentTokenType)
		if _, err := verified.AgentClaims(); err != nil {
			protocol.t.Fatal(err)
		}
		var input struct {
			ResourceToken  string `json:"resource_token"`
			PresentedToken string `json:"presented_token"`
			LoginHint      string `json:"login_hint"`
		}
		decodeRequest(protocol.t, request, &input)
		protocol.exchangedLoginHint = input.LoginHint
		if input.ResourceToken == "" {
			protocol.t.Fatal("token exchange did not present the resource token")
		}
		if input.PresentedToken == "" {
			protocol.t.Fatal("token exchange did not carry the presented token")
		}
		authDiscoveryDocument := protocol.authDiscoveryDocument
		if authDiscoveryDocument == "" {
			authDiscoveryDocument = aauth.AccessDiscoveryDocument
		}
		authPersonServer := protocol.authPersonServer
		if authPersonServer == "" {
			authPersonServer = protocol.personServerID
		}
		authIssuer := protocol.authIssuer
		if authIssuer == "" {
			authIssuer = protocol.accessServerID
		}
		authSigningKey := protocol.authSigningKey
		if authSigningKey.ID() == "" {
			authSigningKey = protocol.accessServerKey
		}
		compact, err := aauth.MintAuthToken(authSigningKey, aauth.AuthTokenClaims{
			Issuer: authIssuer, DWK: authDiscoveryDocument,
			Audience: protocol.resourceID, JTI: "auth-token-1",
			Confirmation: aauth.Confirmation{JWK: protocol.agentKey.PublicJWK()},
			IssuedAt:     protocol.now.Unix(), ExpiresAt: protocol.now.Add(protocol.authTokenLifetime).Unix(),
			Subject: protocol.authSubject, Scope: "records.read", PersonServer: authPersonServer,
		})
		if err != nil {
			protocol.t.Fatal(err)
		}
		output := map[string]any{"auth_token": compact, "expires_in": int64(protocol.authTokenLifetime / time.Second)}
		if protocol.responseExtensions {
			output["example_extension"] = true
		}
		return jsonResponse(request, http.StatusOK, output), nil
	}
	if request.URL.Host+request.URL.Path == "resource.example/records/42" {
		if protocol.protectedSignatureError != nil {
			header, err := signaturekey.FormatError(*protocol.protectedSignatureError)
			if err != nil {
				protocol.t.Fatal(err)
			}
			return &http.Response{
				StatusCode: http.StatusUnauthorized,
				Status:     "401 Unauthorized",
				Header: http.Header{
					"Content-Type":    []string{"text/plain"},
					"Signature-Error": []string{header},
				},
				Body:    io.NopCloser(strings.NewReader("body is not authoritative")),
				Request: request,
			}, nil
		}
		if protocol.protectedUnauthorized {
			return &http.Response{
				StatusCode: http.StatusUnauthorized,
				Status:     "401 Unauthorized",
				Header: http.Header{
					"Content-Type":      []string{"text/plain"},
					"Aauth-Requirement": []string{"requirement=person-token"},
				},
				Body:    io.NopCloser(strings.NewReader("additional authorization is required")),
				Request: request,
			}, nil
		}
		verified := verifyProofWithComponents(
			protocol.t, request, protocol.resolver, protocol.clock,
			aauth.AuthTokenType, protocol.additionalSignatureComponents,
		)
		protocol.protectedComponents = verified.Proof.CoveredComponents()
		claims, err := verified.AuthClaims()
		if err != nil {
			protocol.t.Fatal(err)
		}
		if claims.Subject != "person-123" || claims.Scope != "records.read" {
			protocol.t.Fatalf("protected auth claims = %#v", claims)
		}
		if protocol.protectedProblem {
			return &http.Response{
				StatusCode: http.StatusConflict,
				Status:     "409 Conflict",
				Header:     http.Header{"Content-Type": []string{"application/problem+json"}},
				Body: io.NopCloser(strings.NewReader(
					`{"type":"https://resource.example/problems/version","status":409,"detail":"version changed"}`,
				)),
				Request: request,
			}, nil
		}
		return jsonResponse(request, http.StatusOK, map[string]bool{"ok": true}), nil
	}
	return nil, errors.New("unexpected request: " + request.URL.String())
}

type verifiedCall struct {
	Proof  signaturekey.VerifiedRequest
	agent  *aauth.AgentTokenClaims
	person *aauth.PersonTokenClaims
	auth   *aauth.AuthTokenClaims
}

func (verified verifiedCall) AgentClaims() (aauth.AgentTokenClaims, error) {
	if verified.agent == nil {
		return aauth.AgentTokenClaims{}, errors.New("request has no agent token")
	}
	return *verified.agent, nil
}

func (verified verifiedCall) PersonClaims() (aauth.PersonTokenClaims, error) {
	if verified.person == nil {
		return aauth.PersonTokenClaims{}, errors.New("request has no person token")
	}
	return *verified.person, nil
}

func (verified verifiedCall) AuthClaims() (aauth.AuthTokenClaims, error) {
	if verified.auth == nil {
		return aauth.AuthTokenClaims{}, errors.New("request has no auth token")
	}
	return *verified.auth, nil
}

func expectedAuthorizationComponents(additional []string) []string {
	components := []string{"content-type", "content-digest"}
	for _, component := range additional {
		if !containsString(components, component) {
			components = append(components, component)
		}
	}
	return components
}

func verifyProof(t *testing.T, request *http.Request, resolver signaturekey.KeyResolver, clock aauth.Clock, tokenType string) verifiedCall {
	t.Helper()
	var components []string
	if request.Body != nil {
		components = []string{"content-type", "content-digest"}
	}
	return verifyProofWithComponents(t, request, resolver, clock, tokenType, components)
}

func verifyProofWithComponents(
	t *testing.T,
	request *http.Request,
	resolver signaturekey.KeyResolver,
	clock aauth.Clock,
	tokenType string,
	components []string,
) verifiedCall {
	t.Helper()
	prepared, err := signaturekey.PrepareRequest(request, clock, signaturekey.VerifyOptions{
		AcceptedSchemes:    []signaturekey.Scheme{signaturekey.SchemeJWT},
		RequiredComponents: components,
	})
	if err != nil {
		t.Fatal(err)
	}
	compact, ok := prepared.Credential().JWT()
	if !ok {
		t.Fatal("request did not carry a JWT credential")
	}
	verificationClock := aauth.ClockFunc(func() time.Time { return prepared.VerifiedAt() })
	verified := verifiedCall{}
	var key jose.JWK
	switch tokenType {
	case aauth.AgentTokenType:
		claims, err := aauth.VerifyAgentToken(request.Context(), compact, resolver, verificationClock)
		if err != nil {
			t.Fatal(err)
		}
		verified.agent = &claims
		key = claims.Confirmation.JWK
	case aauth.PersonTokenType:
		claims, err := aauth.VerifyPersonToken(request.Context(), compact, resolver, verificationClock)
		if err != nil {
			t.Fatal(err)
		}
		verified.person = &claims
		key = claims.Confirmation.JWK
	case aauth.AuthTokenType:
		claims, err := aauth.VerifyAuthToken(request.Context(), compact, resolver, verificationClock)
		if err != nil {
			t.Fatal(err)
		}
		verified.auth = &claims
		key = claims.Confirmation.JWK
	default:
		t.Fatalf("unsupported token type %q", tokenType)
	}
	verified.Proof, err = prepared.Verify(key)
	if err != nil {
		t.Fatal(err)
	}
	return verified
}

func decodeRequest(t *testing.T, request *http.Request, destination any) {
	t.Helper()
	decoder := json.NewDecoder(io.LimitReader(request.Body, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		t.Fatal(err)
	}
}

func jsonResponse(request *http.Request, status int, value any) *http.Response {
	body, _ := json.Marshal(value)
	return &http.Response{
		StatusCode: status, Status: http.StatusText(status), Request: request,
		Header: http.Header{"Content-Type": []string{"application/json"}},
		Body:   io.NopCloser(bytes.NewReader(body)),
	}
}

func problemResponse(request *http.Request, problem *aauth.ProblemError) *http.Response {
	body, _ := json.Marshal(map[string]any{
		"type": problem.Type, "title": problem.Title, "status": problem.Status,
		"error": problem.Code, "detail": problem.Detail,
	})
	return &http.Response{
		StatusCode: problem.Status, Status: problem.Title, Request: request,
		Header: http.Header{"Content-Type": []string{"application/problem+json"}},
		Body:   io.NopCloser(bytes.NewReader(body)),
	}
}

func testSigningKey(t *testing.T, id string, fill byte) jose.SigningKey {
	t.Helper()
	key, err := jose.NewEd25519SigningKey(id, ed25519.NewKeyFromSeed(bytes.Repeat([]byte{fill}, ed25519.SeedSize)))
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func slicesEqual(first, second []string) bool {
	if len(first) != len(second) {
		return false
	}
	for index := range first {
		if first[index] != second[index] {
			return false
		}
	}
	return true
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (function roundTripperFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}
