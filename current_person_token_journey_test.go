package aauth_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/reference"
)

// AAuth Protocol sections Person Token, Resource Access and Resource Tokens,
// Person Server, Access Server Federation, and Auth Token.
func TestCurrentFourPartyPersonTokenJourneySurvivesPersonServerRestart(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 28, 14, 0, 0, 123456789, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	apKey := testSigningKey(t, "ap-key")
	psKey := testSigningKey(t, "ps-key")
	accessKey := testSigningKey(t, "access-key")
	resourceKey := testSigningKey(t, "resource-key")
	agentKey := testSigningKey(t, "agent-key")
	otherAgentKey := testSigningKey(t, "other-agent-key")

	ap, err := reference.NewAgentProvider(reference.AgentProviderConfig{
		Identifier: "https://ap.example",
		SigningKey: apKey,
		Clock:      clock,
		NewID:      sequentialIDs("agent-token"),
	})
	if err != nil {
		t.Fatal(err)
	}
	agentToken, err := ap.IssueAgentToken(aauth.AgentTokenRequest{
		Agent:        "aauth:planner@ap.example",
		PersonServer: "https://ps.example",
		PublicKey:    agentKey.PublicJWK(),
		Lifetime:     2 * time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}

	protocolClient := &http.Client{}
	keyResolver, err := aauth.NewHTTPKeyResolver(aauth.HTTPKeyResolverConfig{
		Client: protocolClient,
		Clock:  clock,
		Admit: func(_ context.Context, endpoint string) error {
			for _, allowed := range []string{
				"https://ap.example/",
				"https://ps.example/",
				"https://as.example/",
				"https://resource.example/",
			} {
				if strings.HasPrefix(endpoint, allowed) {
					return nil
				}
			}
			return fmt.Errorf("endpoint outside trust boundary: %s", endpoint)
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	var accessPolicyRequest aauth.AuthorizationRequest
	accessServer, err := reference.NewAccessServer(reference.AccessServerConfig{
		Identifier:  "https://as.example",
		SigningKey:  accessKey,
		KeyResolver: keyResolver,
		Clock:       clock,
		NewID:       sequentialIDs("auth-token", "auth-token-replay", "auth-token-issued-before-person-expiry"),
		TrustedPersonServer: func(_ context.Context, identifier string) error {
			if identifier != "https://ps.example" {
				return fmt.Errorf("untrusted person server %s", identifier)
			}
			return nil
		},
		AuthorizationPolicy: func(_ context.Context, request aauth.AuthorizationRequest) (aauth.AuthorizationDecision, error) {
			accessPolicyRequest = request
			return aauth.AuthorizationDecision{
				Subject: request.Subject,
				Scope:   request.Scope,
			}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	governanceStore, err := reference.NewFileGovernanceStore(t.TempDir() + "/governance.json")
	if err != nil {
		t.Fatal(err)
	}
	personTokenStorePath := t.TempDir() + "/person-tokens.json"
	missionIssuanceStorePath := t.TempDir() + "/mission-issuances.json"
	personIDs := sequentialIDs("person-token-mission", "person-token-endpoint")
	var missionEvaluations []aauth.MissionEvaluation
	personTokenPolicyCalls := 0
	newPersonServer := func() *reference.PersonServer {
		personTokenStore, err := reference.NewFilePersonTokenStore(personTokenStorePath)
		if err != nil {
			t.Fatal(err)
		}
		missionIssuanceStore, err := reference.NewFileMissionIssuanceStore(missionIssuanceStorePath)
		if err != nil {
			t.Fatal(err)
		}
		server, err := reference.NewPersonServer(reference.PersonServerConfig{
			Identifier:           "https://ps.example",
			SigningKey:           psKey,
			KeyResolver:          keyResolver,
			Clock:                clock,
			NewID:                personIDs,
			GovernanceStore:      governanceStore,
			PersonTokenStore:     personTokenStore,
			MissionIssuanceStore: missionIssuanceStore,
			PersonTokenPolicy: func(_ context.Context, request aauth.PersonTokenRequest) (aauth.PersonTokenDecision, error) {
				personTokenPolicyCalls++
				if request.Agent != "aauth:planner@ap.example" || request.Resource != "https://resource.example" {
					return aauth.PersonTokenDecision{}, fmt.Errorf("person binding not found")
				}
				return aauth.PersonTokenDecision{
					Subject:  "directed-person-7",
					Tenant:   "example-org",
					Lifetime: time.Hour,
				}, nil
			},
			FederationClient: protocolClient,
			AccessServerEndpoint: func(_ context.Context, identifier string) (string, error) {
				if identifier != "https://as.example" {
					return "", fmt.Errorf("unknown access server %s", identifier)
				}
				return identifier + "/token", nil
			},
			CurrentMissionPolicy: func(_ context.Context, evaluation aauth.MissionEvaluation) (aauth.MissionDecision, error) {
				missionEvaluations = append(missionEvaluations, evaluation)
				if evaluation.Agent != "aauth:planner@ap.example" {
					return aauth.MissionDecision{}, fmt.Errorf("agent is not permitted to create this mission")
				}
				return aauth.MissionDecision{
					Description:       evaluation.Proposal.Description,
					ApprovedResources: append([]string(nil), evaluation.Proposal.Resources...),
				}, nil
			},
			AuthorizationPolicy: func(_ context.Context, request aauth.AuthorizationRequest) (aauth.AuthorizationDecision, error) {
				return aauth.AuthorizationDecision{
					Subject: request.Subject,
					Scope:   request.Scope,
				}, nil
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		return server
	}
	personServer := newPersonServer()

	var operationRequest aauth.AuthorizedRequest
	operationCalls := 0
	resource, err := reference.NewResource(reference.ResourceConfig{
		Identifier:   "https://resource.example",
		AccessMode:   aauth.AccessModeAuthToken,
		AccessServer: "https://as.example",
		SigningKey:   resourceKey,
		KeyResolver:  keyResolver,
		Clock:        clock,
		NewID:        sequentialIDs("resource-token"),
		Scopes:       []string{"records.read"},
		Operation: func(_ context.Context, request aauth.AuthorizedRequest) (any, error) {
			operationCalls++
			operationRequest = request
			return map[string]any{"records": []string{"one"}}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	personHandler := personServer.Handler()
	resourceHandler := resource.Handler()
	accessHandler := accessServer.Handler()
	var injectedPersonServerAuthToken string
	var injectedAccessServerAuthToken string
	gateway := newLogicalGateway(t, map[string]http.Handler{
		"ap.example": ap.Handler(),
		"ps.example": http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			if request.URL.Path == "/token-injected" {
				response.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(response).Encode(map[string]string{"auth_token": injectedPersonServerAuthToken})
				return
			}
			personHandler.ServeHTTP(response, request)
		}),
		"as.example": http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			if request.URL.Path == "/.well-known/aauth-person.json" {
				response.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(response).Encode(map[string]string{
					"issuer":   "https://as.example",
					"jwks_uri": "https://as.example/jwks",
				})
				return
			}
			if request.URL.Path == "/token" && injectedAccessServerAuthToken != "" {
				response.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(response).Encode(map[string]string{"auth_token": injectedAccessServerAuthToken})
				return
			}
			accessHandler.ServeHTTP(response, request)
		}),
		"resource.example": http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			if request.URL.Path == "/authorize-substitution" {
				thumbprint, _ := agentKey.PublicJWK().Thumbprint()
				substituted, err := aauth.MintResourceToken(resourceKey, aauth.ResourceTokenClaims{
					Issuer:       "https://resource.example",
					DWK:          aauth.ResourceDiscoveryDocument,
					Audience:     "https://as.example",
					JTI:          "substituted-session-resource-token",
					AgentJKT:     thumbprint,
					IssuedAt:     now.Unix(),
					ExpiresAt:    now.Add(5 * time.Minute).Unix(),
					Scope:        "records.read",
					PersonServer: "https://ps.example",
					Subject:      "different-session-person",
					PresentedJTI: "different-session-person-token",
				})
				if err != nil {
					t.Error(err)
					response.WriteHeader(http.StatusInternalServerError)
					return
				}
				response.Header().Set("Content-Type", "application/json")
				if err := json.NewEncoder(response).Encode(map[string]string{"resource_token": substituted}); err != nil {
					t.Error(err)
				}
				return
			}
			resourceHandler.ServeHTTP(response, request)
		}),
	})
	defer gateway.Close()
	protocolClient.Transport = gateway.Client().Transport
	for _, metadataTest := range []struct {
		name string
		url  string
		want map[string]string
	}{
		{
			name: "resource",
			url:  "https://resource.example/.well-known/aauth-resource.json",
			want: map[string]string{"access_mode": "auth-token"},
		},
		{
			name: "person server",
			url:  "https://ps.example/.well-known/aauth-person.json",
			want: map[string]string{
				"auth_token_endpoint":   "https://ps.example/token",
				"person_token_endpoint": "https://ps.example/person",
			},
		},
		{
			name: "access server",
			url:  "https://as.example/.well-known/aauth-access.json",
			want: map[string]string{"auth_token_endpoint": "https://as.example/token"},
		},
	} {
		t.Run(metadataTest.name+" current metadata", func(t *testing.T) {
			response, err := protocolClient.Get(metadataTest.url)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			var metadata map[string]any
			if err := json.NewDecoder(response.Body).Decode(&metadata); err != nil {
				t.Fatal(err)
			}
			for field, want := range metadataTest.want {
				if metadata[field] != want {
					t.Fatalf("%s = %#v, want %q", field, metadata[field], want)
				}
			}
			if _, legacy := metadata["token_endpoint"]; legacy {
				t.Fatal("current metadata exposed legacy token_endpoint")
			}
		})
	}

	agent, err := reference.NewAgent(reference.AgentConfig{
		Identifier:  "aauth:planner@ap.example",
		SigningKey:  agentKey,
		AgentToken:  agentToken,
		KeyResolver: keyResolver,
		HTTPClient:  protocolClient,
		Clock:       clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name     string
		proposal aauth.MissionProposal
	}{
		{
			name: "insecure resource identifier",
			proposal: aauth.MissionProposal{
				Description: "Do the same work.",
				Resources:   []string{"http://resource.example"},
			},
		},
		{
			name: "duplicate resource identifier",
			proposal: aauth.MissionProposal{
				Description: "Do the same work.",
				Resources: []string{
					"https://resource.example",
					"https://resource.example",
				},
			},
		},
		{
			name: "incomplete tool declaration",
			proposal: aauth.MissionProposal{
				Description: "Do the same work.",
				Tools:       []aauth.Tool{{Name: "WebSearch"}},
			},
		},
	} {
		t.Run(test.name+" never reaches mission policy", func(t *testing.T) {
			beforeEvaluations := len(missionEvaluations)
			_, err := agent.CreateMission(context.Background(), "https://ps.example/mission", test.proposal)
			assertProblemCode(t, err, http.StatusBadRequest, "invalid_request")
			if len(missionEvaluations) != beforeEvaluations || personTokenPolicyCalls != 0 {
				t.Fatalf(
					"invalid proposal reached policy: mission evaluations %d -> %d, person-token calls %d",
					beforeEvaluations,
					len(missionEvaluations),
					personTokenPolicyCalls,
				)
			}
		})
	}
	_, err = agent.RequestPersonToken(
		context.Background(),
		"https://ps.example/person",
		"https://policy-denied.example",
		nil,
	)
	assertProblemCode(t, err, http.StatusForbidden, "person_token_denied")
	unboundAgentToken, err := aauth.MintAgentToken(
		"https://ap.example",
		apKey,
		aauth.AgentTokenRequest{
			Agent:     "aauth:planner@ap.example",
			PublicKey: agentKey.PublicJWK(),
			Lifetime:  time.Hour,
		},
		now,
		"agent-token-without-person-server",
	)
	if err != nil {
		t.Fatal(err)
	}
	unboundAgent, err := reference.NewAgent(reference.AgentConfig{
		Identifier:  "aauth:planner@ap.example",
		SigningKey:  agentKey,
		AgentToken:  unboundAgentToken,
		KeyResolver: keyResolver,
		HTTPClient:  protocolClient,
		Clock:       clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	wrongPersonServerAgentToken, err := aauth.MintAgentToken(
		"https://ap.example",
		apKey,
		aauth.AgentTokenRequest{
			Agent:        "aauth:planner@ap.example",
			PersonServer: "https://other-ps.example",
			PublicKey:    agentKey.PublicJWK(),
			Lifetime:     time.Hour,
		},
		now,
		"agent-token-with-wrong-person-server",
	)
	if err != nil {
		t.Fatal(err)
	}
	wrongPersonServerAgent, err := reference.NewAgent(reference.AgentConfig{
		Identifier:  "aauth:planner@ap.example",
		SigningKey:  agentKey,
		AgentToken:  wrongPersonServerAgentToken,
		KeyResolver: keyResolver,
		HTTPClient:  protocolClient,
		Clock:       clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = unboundAgent.CreateMission(
		context.Background(),
		"https://ps.example/mission",
		aauth.MissionProposal{Description: "A mission without a bound person server."},
	)
	assertProblemCode(t, err, http.StatusBadRequest, "invalid_agent_token")
	_, err = unboundAgent.RequestPersonToken(
		context.Background(),
		"https://ps.example/person",
		"https://resource.example",
		nil,
	)
	assertProblemCode(t, err, http.StatusBadRequest, "invalid_agent_token")
	_, err = wrongPersonServerAgent.CreateMission(
		context.Background(),
		"https://ps.example/mission",
		aauth.MissionProposal{Description: "A mission bound to another person server."},
	)
	assertProblemCode(t, err, http.StatusBadRequest, "invalid_agent_token")
	_, err = wrongPersonServerAgent.RequestPersonToken(
		context.Background(),
		"https://ps.example/person",
		"https://resource.example",
		nil,
	)
	assertProblemCode(t, err, http.StatusBadRequest, "invalid_agent_token")
	legacyRequest, err := http.NewRequestWithContext(
		context.Background(),
		http.MethodPost,
		"https://resource.example/authorize",
		strings.NewReader(`{"scope":"records.read"}`),
	)
	if err != nil {
		t.Fatal(err)
	}
	legacyRequest.Header.Set("Content-Type", "application/json")
	if err := aauth.SignRequest(legacyRequest, agentKey, agentToken, clock); err != nil {
		t.Fatal(err)
	}
	legacyResponse, err := protocolClient.Do(legacyRequest)
	if err != nil {
		t.Fatal(err)
	}
	defer legacyResponse.Body.Close()
	if legacyResponse.StatusCode != http.StatusUnauthorized {
		t.Fatalf("agent-token authorization status = %d", legacyResponse.StatusCode)
	}
	requirement, err := aauth.ParseRequirementHeader(legacyResponse.Header.Get("AAuth-Requirement"))
	if err != nil {
		t.Fatal(err)
	}
	if requirement.Type != aauth.RequirementPersonToken {
		t.Fatalf("agent-token authorization requirement = %#v", requirement)
	}
	personInput := aauth.PersonTokenClaims{
		Issuer:       "https://ps.example",
		DWK:          aauth.PersonDiscoveryDocument,
		Audience:     "https://resource.example",
		Subject:      "directed-person-7",
		Confirmation: aauth.Confirmation{JWK: agentKey.PublicJWK()},
		JTI:          "authorization-error-person-token",
		IssuedAt:     now.Unix(),
		ExpiresAt:    now.Add(5 * time.Minute).Unix(),
	}
	wrongAudienceInput := personInput
	wrongAudienceInput.JTI = "wrong-audience-person-token"
	wrongAudienceInput.Audience = "https://other-resource.example"
	wrongAudienceToken := mintPersonToken(t, psKey, wrongAudienceInput)
	expiredInput := personInput
	expiredInput.JTI = "expired-person-token"
	expiredInput.IssuedAt = now.Add(-2 * time.Hour).Unix()
	expiredInput.ExpiresAt = now.Add(-time.Hour).Unix()
	expiredPersonToken := mintPersonToken(t, psKey, expiredInput)
	wrongSignerInput := personInput
	wrongSignerInput.JTI = "wrong-signer-person-token"
	wrongSignerPersonToken := mintPersonToken(t, resourceKey, wrongSignerInput)
	for _, test := range []struct {
		name    string
		compact string
	}{
		{name: "malformed person token", compact: "not-a-jwt"},
		{name: "expired person token", compact: expiredPersonToken},
		{name: "wrong person-token signer", compact: wrongSignerPersonToken},
		{name: "wrong person-token audience", compact: wrongAudienceToken},
	} {
		t.Run(test.name, func(t *testing.T) {
			request, err := http.NewRequestWithContext(
				context.Background(),
				http.MethodPost,
				"https://resource.example/authorize",
				strings.NewReader(`{"scope":"records.read"}`),
			)
			if err != nil {
				t.Fatal(err)
			}
			request.Header.Set("Content-Type", "application/json")
			if err := aauth.SignRequest(request, agentKey, test.compact, clock); err != nil {
				t.Fatal(err)
			}
			response, err := protocolClient.Do(request)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			problem, err := aauth.DecodeProblemResponse(response)
			if err != nil {
				t.Fatal(err)
			}
			if response.StatusCode != http.StatusBadRequest || problem.Code != "invalid_person_token" {
				t.Fatalf("person-token refusal = %d %#v", response.StatusCode, problem)
			}
		})
	}
	proposal := aauth.MissionProposal{
		Description: "Read the federated records needed for the report.",
		Resources:   []string{"https://resource.example"},
	}
	otherAgentToken, err := aauth.MintAgentToken(
		"https://ap.example",
		apKey,
		aauth.AgentTokenRequest{
			Agent:        "aauth:other@ap.example",
			PersonServer: "https://ps.example",
			PublicKey:    otherAgentKey.PublicJWK(),
			Lifetime:     2 * time.Hour,
		},
		now,
		"other-agent-token",
	)
	if err != nil {
		t.Fatal(err)
	}
	otherAgent, err := reference.NewAgent(reference.AgentConfig{
		Identifier:  "aauth:other@ap.example",
		SigningKey:  otherAgentKey,
		AgentToken:  otherAgentToken,
		KeyResolver: keyResolver,
		HTTPClient:  protocolClient,
		Clock:       clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = otherAgent.CreateMission(context.Background(), "https://ps.example/mission", proposal)
	assertProblemCode(t, err, http.StatusForbidden, "mission_denied")
	mission, err := agent.CreateMission(context.Background(), "https://ps.example/mission", proposal)
	if err != nil {
		t.Fatal(err)
	}
	if len(missionEvaluations) != 2 ||
		missionEvaluations[0].Agent != "aauth:other@ap.example" ||
		missionEvaluations[1].Agent != "aauth:planner@ap.example" ||
		missionEvaluations[0].PersonServer != "https://ps.example" ||
		missionEvaluations[0].AgentExpiresAt.Unix() != now.Add(2*time.Hour).Unix() ||
		!missionEvaluations[0].Confirmation.Equal(otherAgentKey.PublicJWK()) {
		t.Fatalf("mission policy evaluations = %#v", missionEvaluations)
	}
	personToken := mission.PersonTokens["https://resource.example"]
	if personToken == "" {
		t.Fatal("mission approval omitted the approved resource person token")
	}
	personClaims, err := aauth.VerifyPersonToken(context.Background(), personToken, keyResolver, clock)
	if err != nil {
		t.Fatal(err)
	}
	if personClaims.Issuer != "https://ps.example" ||
		personClaims.Audience != "https://resource.example" ||
		personClaims.Subject != "directed-person-7" ||
		personClaims.MissionS256 != mission.Reference.S256 ||
		personClaims.Tenant != "example-org" ||
		!personClaims.Confirmation.JWK.Equal(agentKey.PublicJWK()) {
		t.Fatalf("person-token claims = %#v", personClaims)
	}
	assertTokenOmitsClaims(t, personToken, "scope", "account")

	// The exact token record must survive the issuing PS process. The resource
	// token is redeemed only after the new instance reloads durable custody.
	personServer = newPersonServer()
	personHandler = personServer.Handler()
	directPersonGrant, err := agent.RequestPersonToken(
		context.Background(),
		"https://ps.example/person",
		"https://resource.example",
		&mission,
	)
	if err != nil {
		t.Fatal(err)
	}
	if directPersonGrant.Claims.MissionS256 != mission.Reference.S256 ||
		directPersonGrant.Claims.Subject != personClaims.Subject ||
		directPersonGrant.Claims.Tenant != personClaims.Tenant {
		t.Fatalf("person-token endpoint claims = %#v", directPersonGrant.Claims)
	}
	reloadedPersonStore, err := reference.NewFilePersonTokenStore(personTokenStorePath)
	if err != nil {
		t.Fatal(err)
	}
	retainedPerson, err := reloadedPersonStore.Load(
		context.Background(),
		directPersonGrant.Claims.Issuer,
		directPersonGrant.Claims.JTI,
	)
	if err != nil {
		t.Fatal(err)
	}
	wantPersonExpiry := time.Unix(directPersonGrant.Claims.ExpiresAt, 0).UTC()
	if !retainedPerson.ExpiresAt.Equal(wantPersonExpiry) ||
		!retainedPerson.RetainUntil.Equal(wantPersonExpiry.Add(5*time.Minute)) ||
		retainedPerson.TokenSHA256 != aauth.S256([]byte(directPersonGrant.PersonToken)) {
		t.Fatalf("retained person-token custody = %#v", retainedPerson)
	}
	for _, test := range []struct {
		name    string
		compact func() string
		want    string
	}{
		{
			name: "wrong token type",
			compact: func() string {
				return agentToken
			},
			want: "token typ",
		},
		{
			name: "wrong audience",
			compact: func() string {
				claims := directPersonGrant.Claims
				claims.Audience = "https://other-resource.example"
				return mintPersonToken(t, psKey, claims)
			},
			want: "audience",
		},
		{
			name: "wrong confirmation key",
			compact: func() string {
				claims := directPersonGrant.Claims
				claims.Confirmation = aauth.Confirmation{JWK: resourceKey.PublicJWK()}
				return mintPersonToken(t, psKey, claims)
			},
			want: "confirmation key",
		},
		{
			name: "expired",
			compact: func() string {
				claims := directPersonGrant.Claims
				claims.IssuedAt = now.Add(-2 * time.Hour).Unix()
				claims.ExpiresAt = now.Add(-time.Hour).Unix()
				return mintPersonToken(t, psKey, claims)
			},
			want: "expired",
		},
	} {
		t.Run("person token "+test.name, func(t *testing.T) {
			_, err := agent.RequestResourceTokenWithPersonToken(
				context.Background(),
				"https://resource.example/authorize",
				[]string{"records.read"},
				test.compact(),
			)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want text %q", err, test.want)
			}
		})
	}
	personToken = directPersonGrant.PersonToken
	_, err = agent.RequestResourceTokenWithPersonToken(
		context.Background(),
		"https://resource.example/authorize-substitution",
		[]string{"records.read"},
		personToken,
	)
	if err == nil || !strings.Contains(err.Error(), "does not match the presented person token") {
		t.Fatalf("cross-session resource-token substitution error = %v", err)
	}

	// Reconstruct both the server and its file-backed token store once more so
	// endpoint issuance is proven independently of process memory.
	personServer = newPersonServer()
	personHandler = personServer.Handler()

	resourceGrant, err := agent.RequestResourceTokenWithPersonToken(
		context.Background(),
		"https://resource.example/authorize",
		[]string{"records.read"},
		personToken,
	)
	if err != nil {
		t.Fatal(err)
	}
	assertTokenOmitsClaims(t, resourceGrant.ResourceToken, "agent", "mission")
	_, err = unboundAgent.ExchangeResourceToken(
		context.Background(),
		"https://ps.example/token",
		resourceGrant,
	)
	assertProblemCode(t, err, http.StatusBadRequest, "invalid_agent_token")
	_, err = wrongPersonServerAgent.ExchangeResourceToken(
		context.Background(),
		"https://ps.example/token",
		resourceGrant,
	)
	assertProblemCode(t, err, http.StatusBadRequest, "invalid_agent_token")
	for name, presentedAgentToken := range map[string]string{
		"missing ps": unboundAgentToken,
		"wrong ps":   wrongPersonServerAgentToken,
	} {
		t.Run("access server refuses agent token with "+name, func(t *testing.T) {
			asBody, err := json.Marshal(map[string]string{
				"resource_token": resourceGrant.ResourceToken,
				"agent_token":    presentedAgentToken,
			})
			if err != nil {
				t.Fatal(err)
			}
			asRequest, err := http.NewRequestWithContext(
				context.Background(),
				http.MethodPost,
				"https://as.example/token",
				strings.NewReader(string(asBody)),
			)
			if err != nil {
				t.Fatal(err)
			}
			asRequest.Header.Set("Content-Type", "application/json")
			if err := aauth.SignRequestWithJWKSURI(
				asRequest,
				psKey,
				"https://ps.example",
				aauth.PersonDiscoveryDocument,
				clock,
			); err != nil {
				t.Fatal(err)
			}
			asResponse, err := protocolClient.Do(asRequest)
			if err != nil {
				t.Fatal(err)
			}
			defer asResponse.Body.Close()
			if asResponse.StatusCode != http.StatusBadRequest {
				t.Fatalf("access-server exchange status = %d", asResponse.StatusCode)
			}
			asProblem, err := aauth.DecodeProblemResponse(asResponse)
			if err != nil {
				t.Fatal(err)
			}
			if asProblem.Code != "invalid_agent_token" {
				t.Fatalf("access-server exchange problem = %#v", asProblem)
			}
		})
	}
	baseResponseClaims := aauth.AuthTokenClaims{
		Issuer:       "https://as.example",
		DWK:          aauth.AccessDiscoveryDocument,
		Audience:     "https://resource.example",
		JTI:          "injected-exchange-auth-token",
		Confirmation: aauth.Confirmation{JWK: agentKey.PublicJWK()},
		IssuedAt:     now.Unix(),
		ExpiresAt:    resourceGrant.Claims.ExpiresAt,
		Subject:      resourceGrant.Claims.Subject,
		Scope:        resourceGrant.Claims.Scope,
		PersonServer: resourceGrant.Claims.PersonServer,
		MissionS256:  resourceGrant.Claims.MissionS256,
		Tenant:       resourceGrant.Claims.Tenant,
	}
	overlongClaims := baseResponseClaims
	overlongClaims.JTI = "overlong-exchange-auth-token"
	overlongClaims.ExpiresAt++
	overlongAuthToken, err := aauth.MintAuthToken(accessKey, overlongClaims)
	if err != nil {
		t.Fatal(err)
	}
	injectedPersonServerAuthToken = overlongAuthToken
	_, err = agent.ExchangeResourceToken(
		context.Background(),
		"https://ps.example/token-injected",
		resourceGrant,
	)
	if err == nil || !strings.Contains(err.Error(), "outlives the resource token") {
		t.Fatalf("agent accepted overlong auth-token response: %v", err)
	}
	injectedAccessServerAuthToken = overlongAuthToken
	_, err = agent.ExchangeResourceToken(
		context.Background(),
		"https://ps.example/token",
		resourceGrant,
	)
	if err == nil || !strings.Contains(err.Error(), "outlives the resource token") {
		t.Fatalf("person server forwarded overlong access-server auth token: %v", err)
	}
	injectedAccessServerAuthToken = ""
	personServer = newPersonServer()
	personHandler = personServer.Handler()

	wrongRoleClaims := baseResponseClaims
	wrongRoleClaims.DWK = aauth.PersonDiscoveryDocument
	wrongRoleClaims.JTI = "wrong-role-exchange-auth-token"
	injectedPersonServerAuthToken, err = aauth.MintAuthToken(accessKey, wrongRoleClaims)
	if err != nil {
		t.Fatal(err)
	}
	_, err = agent.ExchangeResourceToken(
		context.Background(),
		"https://ps.example/token-injected",
		resourceGrant,
	)
	if err == nil || !strings.Contains(err.Error(), "discovery document") {
		t.Fatalf("wrong-role auth-token response error = %v", err)
	}
	grant, err := agent.ExchangeResourceToken(
		context.Background(),
		"https://ps.example/token",
		resourceGrant,
	)
	if err != nil {
		t.Fatal(err)
	}
	if grant.Claims.Issuer != "https://as.example" ||
		grant.Claims.DWK != aauth.AccessDiscoveryDocument ||
		grant.Claims.Audience != "https://resource.example" ||
		grant.Claims.PersonServer != "https://ps.example" ||
		grant.Claims.Subject != "directed-person-7" ||
		grant.Claims.MissionS256 != mission.Reference.S256 ||
		grant.Claims.Agent != "" || grant.Claims.Actor != nil {
		t.Fatalf("current auth-token claims = %#v", grant.Claims)
	}
	if grant.Claims.ExpiresAt != resourceGrant.Claims.ExpiresAt {
		t.Fatalf(
			"current auth-token exp = %d, want resource-token exp %d",
			grant.Claims.ExpiresAt,
			resourceGrant.Claims.ExpiresAt,
		)
	}
	assertTokenOmitsClaims(t, grant.AuthToken, "agent", "act", "mission")
	if accessPolicyRequest.Agent != "aauth:planner@ap.example" ||
		accessPolicyRequest.PersonServer != "https://ps.example" ||
		accessPolicyRequest.Subject != "directed-person-7" ||
		accessPolicyRequest.MissionS256 != mission.Reference.S256 {
		t.Fatalf("access-server policy input = %#v", accessPolicyRequest)
	}

	response, err := agent.DoAuthorized(
		context.Background(),
		http.MethodGet,
		"https://resource.example/records",
		grant,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(response.Body)
		t.Fatalf("current protected operation status = %d, body = %s", response.StatusCode, body)
	}
	if operationRequest.Agent != "" ||
		operationRequest.PersonServer != "https://ps.example" ||
		operationRequest.Subject != "directed-person-7" ||
		operationRequest.MissionS256 != mission.Reference.S256 {
		t.Fatalf("protected operation context = %#v", operationRequest)
	}
	if operationCalls != 1 {
		t.Fatalf("protected operation calls = %d", operationCalls)
	}

	for _, test := range []struct {
		name   string
		claims aauth.AuthTokenClaims
	}{
		{
			name: "legacy auth-token shape",
			claims: aauth.AuthTokenClaims{
				Issuer:       "https://as.example",
				DWK:          aauth.AccessDiscoveryDocument,
				Audience:     "https://resource.example",
				JTI:          "legacy-auth-token",
				Agent:        "aauth:planner@ap.example",
				Confirmation: aauth.Confirmation{JWK: agentKey.PublicJWK()},
				IssuedAt:     now.Unix(),
				ExpiresAt:    now.Add(5 * time.Minute).Unix(),
				Scope:        "records.read",
			},
		},
		{
			name: "person-server discovery role from access server",
			claims: func() aauth.AuthTokenClaims {
				claims := grant.Claims
				claims.DWK = aauth.PersonDiscoveryDocument
				claims.JTI = "wrong-auth-token-role"
				return claims
			}(),
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			compact, err := aauth.MintAuthToken(accessKey, test.claims)
			if err != nil {
				t.Fatal(err)
			}
			response, err := agent.DoAuthorized(
				context.Background(),
				http.MethodGet,
				"https://resource.example/records",
				reference.Grant{
					Resource:  "https://resource.example",
					AuthToken: compact,
					Claims:    test.claims,
				},
			)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			if response.StatusCode != http.StatusForbidden {
				t.Fatalf("protected refusal status = %d", response.StatusCode)
			}
			if operationCalls != 1 {
				t.Fatalf("protected operation calls = %d", operationCalls)
			}
		})
	}

	// A valid token from the person's PS is still not an authorization from
	// this resource's configured access server. The same person and proof key
	// cannot substitute one trusted issuer for another.
	wrongIssuerClaims := grant.Claims
	wrongIssuerClaims.Issuer = "https://ps.example"
	wrongIssuerClaims.DWK = aauth.PersonDiscoveryDocument
	wrongIssuerClaims.JTI = "wrong-auth-token-issuer"
	wrongIssuerToken, err := aauth.MintAuthToken(psKey, wrongIssuerClaims)
	if err != nil {
		t.Fatal(err)
	}
	wrongIssuerResponse, err := agent.DoAuthorized(
		context.Background(),
		http.MethodGet,
		"https://resource.example/records",
		reference.Grant{
			Resource:  grant.Resource,
			AuthToken: wrongIssuerToken,
			Claims:    wrongIssuerClaims,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer wrongIssuerResponse.Body.Close()
	wrongIssuerProblem, err := aauth.DecodeProblemResponse(wrongIssuerResponse)
	if err != nil {
		t.Fatal(err)
	}
	if wrongIssuerResponse.StatusCode != http.StatusForbidden || wrongIssuerProblem.Code != "invalid_token" {
		t.Fatalf("wrong-issuer response = %d %#v", wrongIssuerResponse.StatusCode, wrongIssuerProblem)
	}

	baseClaims := resourceGrant.Claims
	for _, test := range []struct {
		name   string
		status int
		code   aauth.PollingErrorCode
		make   func() reference.ResourceGrant
	}{
		{
			name:   "wrong token type",
			status: http.StatusBadRequest,
			code:   "invalid_resource_token",
			make: func() reference.ResourceGrant {
				return reference.ResourceGrant{
					Resource:      resourceGrant.Resource,
					ResourceToken: personToken,
					Claims:        baseClaims,
				}
			},
		},
		{
			name:   "unknown presented jti",
			status: http.StatusBadRequest,
			code:   "unknown_person_token",
			make: func() reference.ResourceGrant {
				claims := baseClaims
				claims.JTI = "resource-token-unknown"
				claims.PresentedJTI = "person-token-unknown"
				return mintCurrentResourceGrant(t, resourceKey, claims, resourceGrant.Resource)
			},
		},
		{
			name:   "changed directed subject",
			status: http.StatusBadRequest,
			code:   "invalid_resource_token",
			make: func() reference.ResourceGrant {
				claims := baseClaims
				claims.JTI = "resource-token-substitution"
				claims.Subject = "different-directed-person"
				return mintCurrentResourceGrant(t, resourceKey, claims, resourceGrant.Resource)
			},
		},
		{
			name:   "stripped mission",
			status: http.StatusBadRequest,
			code:   "invalid_resource_token",
			make: func() reference.ResourceGrant {
				claims := baseClaims
				claims.JTI = "resource-token-stripped-mission"
				claims.MissionS256 = ""
				return mintCurrentResourceGrant(t, resourceKey, claims, resourceGrant.Resource)
			},
		},
		{
			name:   "changed tenant",
			status: http.StatusBadRequest,
			code:   "invalid_resource_token",
			make: func() reference.ResourceGrant {
				claims := baseClaims
				claims.JTI = "resource-token-tenant-substitution"
				claims.Tenant = "different-org"
				return mintCurrentResourceGrant(t, resourceKey, claims, resourceGrant.Resource)
			},
		},
		{
			name:   "expired resource token",
			status: http.StatusBadRequest,
			code:   "expired_resource_token",
			make: func() reference.ResourceGrant {
				claims := baseClaims
				claims.JTI = "resource-token-expired"
				claims.IssuedAt = now.Add(-10 * time.Minute).Unix()
				claims.ExpiresAt = now.Add(-5 * time.Minute).Unix()
				return mintCurrentResourceGrant(t, resourceKey, claims, resourceGrant.Resource)
			},
		},
		{
			name:   "resource token exceeds accepted lifetime",
			status: http.StatusBadRequest,
			code:   "invalid_resource_token",
			make: func() reference.ResourceGrant {
				claims := baseClaims
				claims.JTI = "resource-token-overlong"
				claims.ExpiresAt = time.Unix(claims.IssuedAt, 0).Add(6 * time.Minute).Unix()
				return mintCurrentResourceGrant(t, resourceKey, claims, resourceGrant.Resource)
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := agent.ExchangeResourceToken(context.Background(), "https://ps.example/token", test.make())
			assertProblemCode(t, err, test.status, test.code)
		})
	}

	replayClaims := baseClaims
	replayClaims.JTI = "resource-token-replay"
	replayGrant := mintCurrentResourceGrant(t, resourceKey, replayClaims, resourceGrant.Resource)
	if _, err := agent.ExchangeResourceToken(context.Background(), "https://ps.example/token", replayGrant); err != nil {
		t.Fatal(err)
	}
	_, err = agent.ExchangeResourceToken(context.Background(), "https://ps.example/token", replayGrant)
	assertProblemCode(t, err, http.StatusUnauthorized, "invalid_signature")

	personExpiredAt := time.Unix(directPersonGrant.Claims.ExpiresAt, 0).UTC()
	now = personExpiredAt.Add(time.Second)
	validLateClaims := baseClaims
	validLateClaims.JTI = "resource-token-issued-before-person-expiry"
	validLateClaims.IssuedAt = personExpiredAt.Add(-time.Minute).Unix()
	validLateClaims.ExpiresAt = personExpiredAt.Add(4 * time.Minute).Unix()
	validLateGrant := mintCurrentResourceGrant(t, resourceKey, validLateClaims, resourceGrant.Resource)
	if _, err := agent.ExchangeResourceToken(
		context.Background(),
		"https://ps.example/token",
		validLateGrant,
	); err != nil {
		t.Fatalf("resource token issued while person token was valid: %v", err)
	}
	invalidLateClaims := baseClaims
	invalidLateClaims.JTI = "resource-token-issued-after-person-expiry"
	invalidLateClaims.IssuedAt = now.Unix()
	invalidLateClaims.ExpiresAt = now.Add(4 * time.Minute).Unix()
	invalidLateGrant := mintCurrentResourceGrant(t, resourceKey, invalidLateClaims, resourceGrant.Resource)
	_, err = agent.ExchangeResourceToken(
		context.Background(),
		"https://ps.example/token",
		invalidLateGrant,
	)
	assertProblemCode(t, err, http.StatusBadRequest, "invalid_resource_token")
}

func mintCurrentResourceGrant(
	t *testing.T,
	key aauth.SigningKey,
	claims aauth.ResourceTokenClaims,
	resource string,
) reference.ResourceGrant {
	t.Helper()
	compact, err := aauth.MintResourceToken(key, claims)
	if err != nil {
		t.Fatal(err)
	}
	return reference.ResourceGrant{Resource: resource, ResourceToken: compact, Claims: claims}
}

func mintPersonToken(t *testing.T, key aauth.SigningKey, claims aauth.PersonTokenClaims) string {
	t.Helper()
	compact, err := aauth.MintPersonToken(key, claims)
	if err != nil {
		t.Fatal(err)
	}
	return compact
}

func assertTokenOmitsClaims(t *testing.T, compact string, names ...string) {
	t.Helper()
	parts := strings.Split(compact, ".")
	if len(parts) != 3 {
		t.Fatalf("compact token parts = %d, want 3", len(parts))
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var claims map[string]json.RawMessage
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatal(err)
	}
	for _, name := range names {
		if _, exists := claims[name]; exists {
			t.Fatalf("token unexpectedly contains %q: %s", name, payload)
		}
	}
}
