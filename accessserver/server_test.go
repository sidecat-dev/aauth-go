package accessserver

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

func TestServerIssuesCurrentAuthTokenForTrustedPersonServer(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 29, 18, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	apKey := accessServerTestKey(t, "ap-key")
	psKey := accessServerTestKey(t, "ps-key")
	resourceKey := accessServerTestKey(t, "resource-key")
	accessKey := accessServerTestKey(t, "access-key")
	agentKey := accessServerTestKey(t, "agent-key")
	resolver := newRefreshingKeyResolver(signaturekey.StaticKeyResolver{
		{Issuer: "https://ap.example", DiscoveryDocument: aauth.AgentDiscoveryDocument, KeyID: apKey.ID()}:                apKey.PublicJWK(),
		{Issuer: "https://ps.example", DiscoveryDocument: aauth.PersonDiscoveryDocument, KeyID: psKey.ID()}:               psKey.PublicJWK(),
		{Issuer: "https://resource.example", DiscoveryDocument: aauth.ResourceDiscoveryDocument, KeyID: resourceKey.ID()}: resourceKey.PublicJWK(),
		{Issuer: "https://as.example", DiscoveryDocument: aauth.AccessDiscoveryDocument, KeyID: accessKey.ID()}:           accessKey.PublicJWK(),
	})

	agentToken, err := aauth.MintAgentToken(
		"https://ap.example",
		apKey,
		aauth.AgentTokenRequest{
			Agent:        "aauth:planner@ap.example",
			PersonServer: "https://ps.example",
			PublicKey:    agentKey.PublicJWK(),
			Lifetime:     time.Hour,
			AdditionalClaims: map[string]json.RawMessage{
				"platform_attestation": json.RawMessage(`{"level":"example"}`),
			},
		},
		now,
		"agent-token-1",
	)
	if err != nil {
		t.Fatal(err)
	}
	subagentKey := accessServerTestKey(t, "subagent-key")
	subagentToken, err := aauth.MintAgentToken(
		"https://ap.example",
		apKey,
		aauth.AgentTokenRequest{
			Agent:        "aauth:planner+search@ap.example",
			ParentAgent:  "aauth:planner@ap.example",
			PersonServer: "https://ps.example",
			PublicKey:    subagentKey.PublicJWK(),
			Lifetime:     12 * time.Minute,
			AdditionalClaims: map[string]json.RawMessage{
				"workload": json.RawMessage(`"search-worker"`),
			},
		},
		now,
		"subagent-token-1",
	)
	if err != nil {
		t.Fatal(err)
	}
	agentJKT, err := agentKey.PublicJWK().Thumbprint()
	if err != nil {
		t.Fatal(err)
	}
	otherAgentJKT, err := accessServerTestKey(t, "other-agent-key").PublicJWK().Thumbprint()
	if err != nil {
		t.Fatal(err)
	}
	resourceToken, err := aauth.MintResourceToken(resourceKey, aauth.ResourceTokenClaims{
		Issuer:       "https://resource.example",
		DWK:          aauth.ResourceDiscoveryDocument,
		Audience:     "https://as.example",
		JTI:          "resource-token-1",
		AgentJKT:     agentJKT,
		IssuedAt:     now.Unix(),
		ExpiresAt:    now.Add(5 * time.Minute).Unix(),
		Scope:        "records.read records.write",
		PersonServer: "https://ps.example",
		Subject:      "directed-person-1",
		PresentedJTI: "person-token-1",
		Tenant:       "example-tenant",
	})
	if err != nil {
		t.Fatal(err)
	}

	var evaluated AuthorizationRequest
	var trustErr error
	var authorizeErr error
	decision := Decision{Scopes: []string{"records.read"}, Lifetime: 30 * time.Minute}
	trustCalls := 0
	authorizeCalls := 0
	server, err := New(Config{
		Issuer:      "https://as.example",
		SigningKey:  accessKey,
		KeyResolver: resolver,
		Clock:       clock,
		NewID:       func() string { return "auth-token-1" },
		TrustPersonServer: func(_ context.Context, issuer string) error {
			trustCalls++
			if issuer != "https://ps.example" {
				t.Fatalf("person server = %q", issuer)
			}
			return trustErr
		},
		Authorize: func(_ context.Context, request AuthorizationRequest) (Decision, error) {
			authorizeCalls++
			evaluated = request
			if authorizeErr != nil {
				return Decision{}, authorizeErr
			}
			return decision, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	personServerProofKey := psKey
	callTokenEndpointWith := func(input map[string]any) *httptest.ResponseRecorder {
		body, err := json.Marshal(input)
		if err != nil {
			t.Fatal(err)
		}
		request := httptest.NewRequest(http.MethodPost, "https://as.example/token", bytes.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("X-AAuth-Client", "test-client")
		if err := signaturekey.SignJWKSURIRequestWithOptions(
			request, personServerProofKey, "https://ps.example", aauth.PersonDiscoveryDocument, clock,
			signaturekey.SignOptions{
				AdditionalComponents: []string{"content-type", "content-digest", "x-aauth-client"},
				MaxBodyBytes:         int64(len(body)),
			},
		); err != nil {
			t.Fatal(err)
		}
		response := httptest.NewRecorder()
		server.Handler().ServeHTTP(response, request)
		return response
	}
	callTokenEndpoint := func(agentToken, resourceToken string) *httptest.ResponseRecorder {
		return callTokenEndpointWith(map[string]any{
			"resource_token": resourceToken,
			"agent_token":    agentToken,
		})
	}
	response := callTokenEndpoint(agentToken, resourceToken)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	if got := response.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("token Cache-Control = %q", got)
	}
	var output struct {
		AuthToken string `json:"auth_token"`
		ExpiresIn int64  `json:"expires_in"`
	}
	if err := json.NewDecoder(response.Body).Decode(&output); err != nil {
		t.Fatal(err)
	}
	claims, err := aauth.VerifyAuthToken(context.Background(), output.AuthToken, resolver, clock)
	if err != nil {
		t.Fatal(err)
	}
	if claims.Issuer != "https://as.example" ||
		claims.DWK != aauth.AccessDiscoveryDocument ||
		claims.Audience != "https://resource.example" ||
		claims.PersonServer != "https://ps.example" ||
		claims.Subject != "directed-person-1" ||
		claims.Scope != "records.read" ||
		claims.Tenant != "example-tenant" ||
		!claims.Confirmation.JWK.Equal(agentKey.PublicJWK()) ||
		output.ExpiresIn != int64((30*time.Minute)/time.Second) {
		t.Fatalf("auth token = %#v; expires_in = %d", claims, output.ExpiresIn)
	}
	if evaluated.PersonServer != "https://ps.example" ||
		evaluated.Resource != "https://resource.example" ||
		evaluated.Subject != "directed-person-1" ||
		evaluated.Tenant != "example-tenant" ||
		evaluated.Agent.Identifier != "aauth:planner@ap.example" ||
		!evaluated.Agent.Confirmation.Equal(agentKey.PublicJWK()) ||
		string(evaluated.Agent.AdditionalClaims["platform_attestation"]) != `{"level":"example"}` ||
		!reflect.DeepEqual(evaluated.Scopes, []string{"records.read", "records.write"}) {
		t.Fatalf("authorization request = %#v", evaluated)
	}
	if trustCalls != 1 || authorizeCalls != 1 {
		t.Fatalf("policy calls: trust=%d authorize=%d", trustCalls, authorizeCalls)
	}

	t.Run("parent-mediated sub-agent issuance", func(t *testing.T) {
		subagentJKT, err := subagentKey.PublicJWK().Thumbprint()
		if err != nil {
			t.Fatal(err)
		}
		subagentResourceToken, err := aauth.MintResourceToken(resourceKey, aauth.ResourceTokenClaims{
			Issuer: "https://resource.example", DWK: aauth.ResourceDiscoveryDocument,
			Audience: "https://as.example", JTI: "subagent-resource-token", AgentJKT: subagentJKT,
			IssuedAt: now.Unix(), ExpiresAt: now.Add(5 * time.Minute).Unix(), Scope: "records.read",
			PersonServer: "https://ps.example", Subject: "directed-person-1", PresentedJTI: "person-token-1",
		})
		if err != nil {
			t.Fatal(err)
		}
		response := callTokenEndpointWith(map[string]any{
			"resource_token": subagentResourceToken,
			"agent_token":    agentToken,
			"subagent_token": subagentToken,
		})
		if response.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
		}
		var output struct {
			AuthToken string `json:"auth_token"`
			ExpiresIn int64  `json:"expires_in"`
		}
		if err := json.NewDecoder(response.Body).Decode(&output); err != nil {
			t.Fatal(err)
		}
		claims, err := aauth.VerifyAuthToken(context.Background(), output.AuthToken, resolver, clock)
		if err != nil {
			t.Fatal(err)
		}
		if !claims.Confirmation.JWK.Equal(subagentKey.PublicJWK()) || claims.ExpiresAt != now.Add(12*time.Minute).Unix() || output.ExpiresIn != 720 {
			t.Fatalf("sub-agent auth token = %#v; expires_in = %d", claims, output.ExpiresIn)
		}
		if evaluated.Agent.Identifier != "aauth:planner@ap.example" || evaluated.Subagent == nil ||
			evaluated.Subagent.Identifier != "aauth:planner+search@ap.example" ||
			!evaluated.Subagent.Confirmation.Equal(subagentKey.PublicJWK()) ||
			string(evaluated.Subagent.AdditionalClaims["workload"]) != `"search-worker"` {
			t.Fatalf("parent-mediated authorization request = %#v", evaluated)
		}
	})

	t.Run("parent expiry caps parent-mediated issuance", func(t *testing.T) {
		shortParentToken, err := aauth.MintAgentToken(
			"https://ap.example",
			apKey,
			aauth.AgentTokenRequest{
				Agent: "aauth:planner@ap.example", PersonServer: "https://ps.example",
				PublicKey: agentKey.PublicJWK(), Lifetime: 7 * time.Minute,
			},
			now,
			"short-parent-token",
		)
		if err != nil {
			t.Fatal(err)
		}
		subagentJKT, err := subagentKey.PublicJWK().Thumbprint()
		if err != nil {
			t.Fatal(err)
		}
		subagentResourceToken, err := aauth.MintResourceToken(resourceKey, aauth.ResourceTokenClaims{
			Issuer: "https://resource.example", DWK: aauth.ResourceDiscoveryDocument,
			Audience: "https://as.example", JTI: "short-parent-resource-token", AgentJKT: subagentJKT,
			IssuedAt: now.Unix(), ExpiresAt: now.Add(5 * time.Minute).Unix(), Scope: "records.read",
			PersonServer: "https://ps.example", Subject: "directed-person-1", PresentedJTI: "person-token-1",
		})
		if err != nil {
			t.Fatal(err)
		}
		response := callTokenEndpointWith(map[string]any{
			"resource_token": subagentResourceToken,
			"agent_token":    shortParentToken,
			"subagent_token": subagentToken,
		})
		if response.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
		}
		var output struct {
			AuthToken string `json:"auth_token"`
			ExpiresIn int64  `json:"expires_in"`
		}
		if err := json.NewDecoder(response.Body).Decode(&output); err != nil {
			t.Fatal(err)
		}
		claims, err := aauth.VerifyAuthToken(context.Background(), output.AuthToken, resolver, clock)
		if err != nil {
			t.Fatal(err)
		}
		if claims.ExpiresAt != now.Add(7*time.Minute).Unix() || output.ExpiresIn != 420 {
			t.Fatalf("parent-capped sub-agent auth token = %#v; expires_in = %d", claims, output.ExpiresIn)
		}
	})

	t.Run("parent-mediated request refuses a child of another parent", func(t *testing.T) {
		otherChildKey := accessServerTestKey(t, "other-child-key")
		otherChildToken, err := aauth.MintAgentToken(
			"https://ap.example", apKey,
			aauth.AgentTokenRequest{
				Agent: "aauth:other+search@ap.example", ParentAgent: "aauth:other@ap.example",
				PersonServer: "https://ps.example", PublicKey: otherChildKey.PublicJWK(), Lifetime: time.Hour,
			}, now, "other-child-token",
		)
		if err != nil {
			t.Fatal(err)
		}
		otherJKT, err := otherChildKey.PublicJWK().Thumbprint()
		if err != nil {
			t.Fatal(err)
		}
		childResourceToken, err := aauth.MintResourceToken(resourceKey, aauth.ResourceTokenClaims{
			Issuer: "https://resource.example", DWK: aauth.ResourceDiscoveryDocument,
			Audience: "https://as.example", JTI: "other-child-resource", AgentJKT: otherJKT,
			IssuedAt: now.Unix(), ExpiresAt: now.Add(5 * time.Minute).Unix(), Scope: "records.read",
			PersonServer: "https://ps.example", Subject: "directed-person-1", PresentedJTI: "person-token-1",
		})
		if err != nil {
			t.Fatal(err)
		}
		beforeAuthorize := authorizeCalls
		assertAccessProblem(t, callTokenEndpointWith(map[string]any{
			"resource_token": childResourceToken,
			"agent_token":    agentToken,
			"subagent_token": otherChildToken,
		}), "invalid_agent_token")
		if authorizeCalls != beforeAuthorize {
			t.Fatal("wrong-parent sub-agent reached authorization policy")
		}
	})

	for name, malformed := range map[string]any{
		"null":         nil,
		"empty string": "",
		"object":       map[string]any{"token": subagentToken},
	} {
		name, malformed := name, malformed
		t.Run("malformed subagent_token "+name, func(t *testing.T) {
			beforeAuthorize := authorizeCalls
			assertAccessProblemStatus(t, callTokenEndpointWith(map[string]any{
				"resource_token": resourceToken,
				"agent_token":    agentToken,
				"subagent_token": malformed,
			}), http.StatusBadRequest, "invalid_request")
			if authorizeCalls != beforeAuthorize {
				t.Fatal("malformed sub-agent token reached authorization policy")
			}
		})
	}

	t.Run("parent-mediated request refuses a resource token bound to the parent", func(t *testing.T) {
		beforeAuthorize := authorizeCalls
		assertAccessProblem(t, callTokenEndpointWith(map[string]any{
			"resource_token": resourceToken,
			"agent_token":    agentToken,
			"subagent_token": subagentToken,
		}), "invalid_resource_token")
		if authorizeCalls != beforeAuthorize {
			t.Fatal("wrong-key resource token reached authorization policy")
		}
	})

	t.Run("parent-mediated request refuses a child sharing the parent key", func(t *testing.T) {
		sharedKeyToken, err := aauth.MintAgentToken(
			"https://ap.example", apKey,
			aauth.AgentTokenRequest{
				Agent: "aauth:planner+shared@ap.example", ParentAgent: "aauth:planner@ap.example",
				PublicKey: agentKey.PublicJWK(), Lifetime: time.Hour,
			}, now, "shared-key-child-token",
		)
		if err != nil {
			t.Fatal(err)
		}
		beforeAuthorize := authorizeCalls
		assertAccessProblem(t, callTokenEndpointWith(map[string]any{
			"resource_token": resourceToken,
			"agent_token":    agentToken,
			"subagent_token": sharedKeyToken,
		}), "invalid_agent_token")
		if authorizeCalls != beforeAuthorize {
			t.Fatal("shared-key sub-agent reached authorization policy")
		}
	})

	t.Run("agent-token expiry remains the auth-token ceiling", func(t *testing.T) {
		shortAgentToken, err := aauth.MintAgentToken(
			"https://ap.example", apKey,
			aauth.AgentTokenRequest{
				Agent: "aauth:planner@ap.example", PersonServer: "https://ps.example",
				PublicKey: agentKey.PublicJWK(), Lifetime: 10 * time.Minute,
			}, now, "short-agent-token",
		)
		if err != nil {
			t.Fatal(err)
		}
		response := callTokenEndpoint(shortAgentToken, resourceToken)
		if response.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
		}
		var output struct {
			AuthToken string `json:"auth_token"`
			ExpiresIn int64  `json:"expires_in"`
		}
		if err := json.NewDecoder(response.Body).Decode(&output); err != nil {
			t.Fatal(err)
		}
		claims, err := aauth.VerifyAuthToken(context.Background(), output.AuthToken, resolver, clock)
		if err != nil {
			t.Fatal(err)
		}
		if claims.ExpiresAt != now.Add(10*time.Minute).Unix() || output.ExpiresIn != 600 {
			t.Fatalf("short-agent auth token = %#v; expires_in = %d", claims, output.ExpiresIn)
		}
	})

	t.Run("mission digest is preserved without disclosing mission content", func(t *testing.T) {
		missionS256 := aauth.MissionS256([]byte("approved mission content"))
		missionResourceToken, err := aauth.MintResourceToken(resourceKey, aauth.ResourceTokenClaims{
			Issuer: "https://resource.example", DWK: aauth.ResourceDiscoveryDocument,
			Audience: "https://as.example", JTI: "mission-resource-token", AgentJKT: agentJKT,
			IssuedAt: now.Unix(), ExpiresAt: now.Add(5 * time.Minute).Unix(), Scope: "records.read",
			PersonServer: "https://ps.example", Subject: "directed-person-1", PresentedJTI: "person-token-1",
			MissionS256: missionS256,
		})
		if err != nil {
			t.Fatal(err)
		}
		response := callTokenEndpoint(agentToken, missionResourceToken)
		if response.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
		}
		var output struct {
			AuthToken string `json:"auth_token"`
			ExpiresIn int64  `json:"expires_in"`
		}
		if err := json.NewDecoder(response.Body).Decode(&output); err != nil {
			t.Fatal(err)
		}
		claims, err := aauth.VerifyAuthToken(context.Background(), output.AuthToken, resolver, clock)
		if err != nil {
			t.Fatal(err)
		}
		if claims.MissionS256 != missionS256 || claims.ExpiresAt != now.Add(5*time.Minute).Unix() ||
			output.ExpiresIn != int64((5*time.Minute)/time.Second) {
			t.Fatalf("mission auth token = %#v; expires_in = %d", claims, output.ExpiresIn)
		}
		if evaluated.MissionS256 != missionS256 {
			t.Fatalf("authorization policy mission_s256 = %q, want %q", evaluated.MissionS256, missionS256)
		}
	})

	t.Run("same-ID Person Server key rotation refreshes once", func(t *testing.T) {
		rotated := accessServerTestKey(t, psKey.ID())
		resolver.StageRefresh(signaturekey.StaticKeyReference{
			Issuer: "https://ps.example", DiscoveryDocument: aauth.PersonDiscoveryDocument, KeyID: psKey.ID(),
		}, rotated.PublicJWK())
		personServerProofKey = rotated
		before := resolver.RefreshCalls()
		response := callTokenEndpoint(agentToken, resourceToken)
		if response.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
		}
		if resolver.RefreshCalls() != before+1 {
			t.Fatalf("refresh calls = %d, want %d", resolver.RefreshCalls(), before+1)
		}
	})

	t.Run("person server trust denial", func(t *testing.T) {
		trustErr = errors.Join(ErrAccessDenied, errors.New("person server is not trusted"))
		beforeAuthorize := authorizeCalls
		assertAccessProblemStatus(t, callTokenEndpoint(agentToken, resourceToken), http.StatusForbidden, "access_denied")
		trustErr = nil
		if authorizeCalls != beforeAuthorize {
			t.Fatal("trust denial reached authorization policy")
		}
	})

	t.Run("person server trust failure", func(t *testing.T) {
		trustErr = errors.New("person server trust data is unavailable")
		beforeAuthorize := authorizeCalls
		assertAccessProblemStatus(t, callTokenEndpoint(agentToken, resourceToken), http.StatusInternalServerError, "server_error")
		trustErr = nil
		if authorizeCalls != beforeAuthorize {
			t.Fatal("trust failure reached authorization policy")
		}
	})

	t.Run("authorization denial", func(t *testing.T) {
		authorizeErr = errors.Join(ErrAccessDenied, errors.New("resource policy denied access"))
		assertAccessProblemStatus(t, callTokenEndpoint(agentToken, resourceToken), http.StatusForbidden, "access_denied")
		authorizeErr = nil
	})

	t.Run("authorization failure", func(t *testing.T) {
		authorizeErr = errors.New("resource policy data is unavailable")
		assertAccessProblemStatus(t, callTokenEndpoint(agentToken, resourceToken), http.StatusInternalServerError, "server_error")
		authorizeErr = nil
	})

	for _, test := range []struct {
		name     string
		decision Decision
	}{
		{name: "empty decision", decision: Decision{}},
		{name: "unrequested scope", decision: Decision{Scopes: []string{"records.admin"}, Lifetime: time.Minute}},
		{name: "duplicate scope", decision: Decision{Scopes: []string{"records.read", "records.read"}, Lifetime: time.Minute}},
		{name: "excessive lifetime", decision: Decision{Scopes: []string{"records.read"}, Lifetime: 2 * time.Hour}},
	} {
		test := test
		t.Run("invalid policy "+test.name, func(t *testing.T) {
			decision = test.decision
			assertAccessProblemStatus(t, callTokenEndpoint(agentToken, resourceToken), http.StatusInternalServerError, "server_error")
		})
	}
	decision = Decision{Scopes: []string{"records.read"}, Lifetime: 30 * time.Minute}

	for _, name := range []string{"upstream_token"} {
		name := name
		t.Run("known unsupported request "+name, func(t *testing.T) {
			beforeAuthorize := authorizeCalls
			assertAccessProblemStatus(t, callTokenEndpointWith(map[string]any{
				"resource_token": resourceToken,
				"agent_token":    agentToken,
				name:             "token",
			}), http.StatusBadRequest, "invalid_request")
			if authorizeCalls != beforeAuthorize {
				t.Fatal("unsupported request reached authorization policy")
			}
		})
	}

	for _, test := range []struct {
		name   string
		change func(*aauth.ResourceTokenClaims)
	}{
		{name: "wrong audience", change: func(claims *aauth.ResourceTokenClaims) { claims.Audience = "https://other-as.example" }},
		{name: "wrong person server", change: func(claims *aauth.ResourceTokenClaims) { claims.PersonServer = "https://other-ps.example" }},
		{name: "wrong agent key", change: func(claims *aauth.ResourceTokenClaims) { claims.AgentJKT = otherAgentJKT }},
		{name: "account", change: func(claims *aauth.ResourceTokenClaims) { claims.Account = testStringPointer("account-123") }},
		{name: "interaction", change: func(claims *aauth.ResourceTokenClaims) {
			claims.Interaction = &aauth.ResourceInteraction{URL: "https://resource.example/interaction", Code: "ABCD-EFGH"}
		}},
	} {
		test := test
		t.Run("resource context "+test.name, func(t *testing.T) {
			resourceClaims := aauth.ResourceTokenClaims{
				Issuer: "https://resource.example", DWK: aauth.ResourceDiscoveryDocument,
				Audience: "https://as.example", JTI: "resource-token-negative", AgentJKT: agentJKT,
				IssuedAt: now.Unix(), ExpiresAt: now.Add(10 * time.Minute).Unix(),
				Scope: "records.read", PersonServer: "https://ps.example", Subject: "directed-person-1",
				PresentedJTI: "person-token-1", Tenant: "example-tenant",
			}
			test.change(&resourceClaims)
			token, err := aauth.MintResourceToken(resourceKey, resourceClaims)
			if err != nil {
				t.Fatal(err)
			}
			beforeAuthorize := authorizeCalls
			assertAccessProblem(t, callTokenEndpoint(agentToken, token), "invalid_resource_token")
			if authorizeCalls != beforeAuthorize {
				t.Fatal("invalid resource context reached authorization policy")
			}
		})
	}

	t.Run("agent person server mismatch", func(t *testing.T) {
		wrongAgentToken, err := aauth.MintAgentToken(
			"https://ap.example", apKey,
			aauth.AgentTokenRequest{
				Agent: "aauth:planner@ap.example", PersonServer: "https://other-ps.example",
				PublicKey: agentKey.PublicJWK(), Lifetime: time.Hour,
			},
			now, "wrong-person-server-agent-token",
		)
		if err != nil {
			t.Fatal(err)
		}
		beforeAuthorize := authorizeCalls
		assertAccessProblem(t, callTokenEndpoint(wrongAgentToken, resourceToken), "invalid_agent_token")
		if authorizeCalls != beforeAuthorize {
			t.Fatal("invalid agent context reached authorization policy")
		}
	})

	expiredAgentToken, err := aauth.MintAgentToken(
		"https://ap.example", apKey,
		aauth.AgentTokenRequest{
			Agent: "aauth:planner@ap.example", PersonServer: "https://ps.example",
			PublicKey: agentKey.PublicJWK(), Lifetime: time.Hour,
		},
		now.Add(-2*time.Hour), "expired-agent-token",
	)
	if err != nil {
		t.Fatal(err)
	}
	assertAccessProblem(t, callTokenEndpoint(expiredAgentToken, resourceToken), "expired_agent_token")

	expiredResourceToken, err := aauth.MintResourceToken(resourceKey, aauth.ResourceTokenClaims{
		Issuer: "https://resource.example", DWK: aauth.ResourceDiscoveryDocument,
		Audience: "https://as.example", JTI: "expired-resource-token", AgentJKT: agentJKT,
		IssuedAt: now.Add(-10 * time.Minute).Unix(), ExpiresAt: now.Add(-5 * time.Minute).Unix(),
		Scope: "records.read", PersonServer: "https://ps.example", Subject: "directed-person-1",
		PresentedJTI: "person-token-1", Tenant: "example-tenant",
	})
	if err != nil {
		t.Fatal(err)
	}
	assertAccessProblem(t, callTokenEndpoint(agentToken, expiredResourceToken), "expired_resource_token")
}

func TestServerMetadataAndJWKSRemainCacheable(t *testing.T) {
	t.Parallel()

	key := accessServerTestKey(t, "as-key")
	server, err := New(Config{
		Issuer: "https://as.example", SigningKey: key,
		KeyResolver:       signaturekey.StaticKeyResolver{},
		Clock:             aauth.ClockFunc(func() time.Time { return time.Date(2026, 8, 29, 18, 0, 0, 0, time.UTC) }),
		NewID:             func() string { return "unused" },
		TrustPersonServer: func(context.Context, string) error { return nil },
		Authorize: func(context.Context, AuthorizationRequest) (Decision, error) {
			return Decision{}, errors.New("unused")
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/.well-known/aauth-access.json", "/.well-known/jwks.json"} {
		request := httptest.NewRequest(http.MethodGet, "https://as.example"+path, nil)
		response := httptest.NewRecorder()
		server.Handler().ServeHTTP(response, request)
		if response.Code != http.StatusOK {
			t.Fatalf("%s status = %d", path, response.Code)
		}
		if got := response.Header().Get("Cache-Control"); got == "no-store" {
			t.Fatalf("%s Cache-Control = %q", path, got)
		}
	}
}

func assertAccessProblem(t *testing.T, response *httptest.ResponseRecorder, code string) {
	t.Helper()
	assertAccessProblemStatus(t, response, http.StatusBadRequest, code)
}

func assertAccessProblemStatus(t *testing.T, response *httptest.ResponseRecorder, status int, code string) {
	t.Helper()
	var problem struct {
		Code string `json:"error"`
	}
	if err := json.NewDecoder(response.Body).Decode(&problem); err != nil {
		t.Fatal(err)
	}
	if response.Code != status || problem.Code != code {
		t.Fatalf("status = %d, problem = %#v", response.Code, problem)
	}
}

func accessServerTestKey(t *testing.T, id string) jose.SigningKey {
	t.Helper()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := jose.NewEd25519SigningKey(id, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

type refreshingKeyResolver struct {
	mu           sync.Mutex
	keys         signaturekey.StaticKeyResolver
	staged       map[signaturekey.StaticKeyReference]jose.JWK
	refreshCalls int
}

func newRefreshingKeyResolver(keys signaturekey.StaticKeyResolver) *refreshingKeyResolver {
	return &refreshingKeyResolver{keys: keys, staged: make(map[signaturekey.StaticKeyReference]jose.JWK)}
}

func (resolver *refreshingKeyResolver) ResolveKey(
	ctx context.Context,
	issuer string,
	document string,
	keyID string,
) (jose.JWK, error) {
	resolver.mu.Lock()
	defer resolver.mu.Unlock()
	return resolver.keys.ResolveKey(ctx, issuer, document, keyID)
}

func (resolver *refreshingKeyResolver) RefreshKey(
	ctx context.Context,
	issuer string,
	document string,
	keyID string,
) (jose.JWK, error) {
	resolver.mu.Lock()
	defer resolver.mu.Unlock()
	resolver.refreshCalls++
	reference := signaturekey.StaticKeyReference{Issuer: issuer, DiscoveryDocument: document, KeyID: keyID}
	if key, ok := resolver.staged[reference]; ok {
		resolver.keys[reference] = key
		delete(resolver.staged, reference)
	}
	return resolver.keys.ResolveKey(ctx, issuer, document, keyID)
}

func (resolver *refreshingKeyResolver) StageRefresh(reference signaturekey.StaticKeyReference, key jose.JWK) {
	resolver.mu.Lock()
	defer resolver.mu.Unlock()
	resolver.staged[reference] = key
}

func (resolver *refreshingKeyResolver) RefreshCalls() int {
	resolver.mu.Lock()
	defer resolver.mu.Unlock()
	return resolver.refreshCalls
}

func testStringPointer(value string) *string { return &value }
