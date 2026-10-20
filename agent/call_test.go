package agent_test

import (
	"context"
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

func TestBeginReturnsVerifiedAuthTokenRequirement(t *testing.T) {
	t.Parallel()

	protocol := newTestProtocol(t)
	protocol.additionalSignatureComponents = []string{"x-request-id"}
	personToken, err := aauth.MintPersonToken(protocol.personServerKey, aauth.PersonTokenClaims{
		Issuer: protocol.personServerID, DWK: aauth.PersonDiscoveryDocument,
		Audience: protocol.resourceID, Subject: "person-123",
		Confirmation: aauth.Confirmation{JWK: protocol.agentKey.PublicJWK()},
		JTI:          "person-token-begin", IssuedAt: protocol.now.Unix(), ExpiresAt: protocol.now.Add(30 * time.Minute).Unix(),
		Tenant: "tenant-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	applicationCalls := 0
	challengeBody := &trackedBody{Reader: strings.NewReader("authorization required")}
	var resourceToken string
	client := protocol.newClientWithHTTPClient(t, &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
		if request.Method == http.MethodGet && request.URL.String() == protocol.resourceID+"/.well-known/aauth-resource.json" {
			return protocol.roundTrip(request)
		}
		applicationCalls++
		verified := verifyProofWithComponents(
			t, request, protocol.resolver, protocol.clock,
			aauth.PersonTokenType, protocol.additionalSignatureComponents,
		)
		person, err := verified.PersonClaims()
		if err != nil {
			t.Fatal(err)
		}
		if request.Method != http.MethodGet || request.URL.EscapedPath() != "/records/42" || request.Header.Get("X-Request-ID") != "begin-42" {
			t.Fatalf("application request = %s %s, X-Request-ID = %q", request.Method, request.URL.EscapedPath(), request.Header.Get("X-Request-ID"))
		}
		thumbprint, err := protocol.agentKey.PublicJWK().Thumbprint()
		if err != nil {
			t.Fatal(err)
		}
		resourceToken, err = aauth.MintResourceToken(protocol.resourceKey, aauth.ResourceTokenClaims{
			Issuer: protocol.resourceID, DWK: aauth.ResourceDiscoveryDocument,
			Audience: protocol.accessServerID, JTI: "resource-token-begin",
			PersonServer: person.Issuer, Subject: person.Subject, PresentedJTI: person.JTI,
			AgentJKT: thumbprint, IssuedAt: protocol.now.Unix(), ExpiresAt: protocol.now.Add(5 * time.Minute).Unix(),
			Scope: "records.read", Tenant: person.Tenant,
		})
		if err != nil {
			t.Fatal(err)
		}
		header, err := aauth.FormatAuthTokenRequirement(aauth.AuthTokenRequirement{ResourceToken: resourceToken})
		if err != nil {
			t.Fatal(err)
		}
		responseHeader := make(http.Header)
		responseHeader.Set("AAuth-Requirement", header)
		return &http.Response{
			StatusCode: http.StatusUnauthorized,
			Status:     "401 Unauthorized",
			Header:     responseHeader,
			Body:       challengeBody,
			Request:    request,
		}, nil
	})})
	request, err := http.NewRequest(http.MethodGet, protocol.resourceID+"/records/42", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("X-Request-ID", "begin-42")

	result, err := client.Begin(context.Background(), agent.InitialCall{
		Request: request, PersonToken: personToken,
	})
	if err != nil {
		t.Fatal(err)
	}
	requirement, ok := result.AuthorizationRequired()
	if !ok || requirement.ResourceToken != resourceToken {
		t.Fatalf("AuthorizationRequired = %#v, %t", requirement, ok)
	}
	if response, ok := result.Response(); ok || response != nil {
		t.Fatalf("Response = %#v, %t", response, ok)
	}
	if applicationCalls != 1 {
		t.Fatalf("application calls = %d, want 1", applicationCalls)
	}
	if !challengeBody.closed {
		t.Fatal("Begin did not close the verified challenge response")
	}
}

func TestBeginPreservesOriginalReplayableRequest(t *testing.T) {
	t.Parallel()

	protocol := newTestProtocol(t)
	protocol.additionalSignatureComponents = []string{"content-type", "content-digest", "x-selected-route"}
	personToken := mintBeginPersonToken(t, protocol, nil)
	const (
		body        = `{"record":"alpha","enabled":true}`
		escapedPath = "/records/a%2Fb"
		rawQuery    = "view=full%20detail&tag=a%2Fb"
	)
	applicationCalls := 0
	responseBody := &trackedBody{Reader: strings.NewReader("accepted")}
	client := protocol.newClientWithHTTPClient(t, &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
		if request.Method == http.MethodGet && request.URL.String() == protocol.resourceID+"/.well-known/aauth-resource.json" {
			return protocol.roundTrip(request)
		}
		applicationCalls++
		verifyProofWithComponents(
			t, request, protocol.resolver, protocol.clock,
			aauth.PersonTokenType, protocol.additionalSignatureComponents,
		)
		applicationBody, err := io.ReadAll(request.Body)
		if err != nil {
			t.Fatal(err)
		}
		if request.Method != http.MethodPatch || request.URL.EscapedPath() != escapedPath || request.URL.RawQuery != rawQuery ||
			request.Header.Get("X-Selected-Route") != "original-selection" || string(applicationBody) != body {
			t.Fatalf("application request = %s %s?%s, selected = %q, body = %q", request.Method, request.URL.EscapedPath(), request.URL.RawQuery, request.Header.Get("X-Selected-Route"), applicationBody)
		}
		return &http.Response{
			StatusCode: http.StatusNoContent, Status: "204 No Content",
			Header: make(http.Header), Body: responseBody, Request: request,
		}, nil
	})})
	original, err := http.NewRequest(
		http.MethodPatch,
		protocol.resourceID+escapedPath+"?"+rawQuery,
		strings.NewReader(body),
	)
	if err != nil {
		t.Fatal(err)
	}
	original.Header.Set("Content-Type", "application/json")
	original.Header.Set("X-Selected-Route", "original-selection")

	result, err := client.Begin(context.Background(), agent.InitialCall{Request: original, PersonToken: personToken})
	if err != nil {
		t.Fatal(err)
	}
	response, ok := result.Response()
	if !ok || response.StatusCode != http.StatusNoContent {
		t.Fatalf("Response = %#v, %t", response, ok)
	}
	if _, ok := result.AuthorizationRequired(); ok {
		t.Fatal("ordinary response also exposed an authorization requirement")
	}
	if responseBody.closed {
		t.Fatal("Begin closed the caller-owned ordinary response body")
	}
	for _, name := range []string{"Signature-Key", "Signature-Input", "Signature", "Content-Digest"} {
		if value := original.Header.Get(name); value != "" {
			t.Fatalf("original %s = %q", name, value)
		}
	}
	if original.Method != http.MethodPatch || original.URL.EscapedPath() != escapedPath || original.URL.RawQuery != rawQuery ||
		original.Header.Get("X-Selected-Route") != "original-selection" {
		t.Fatalf("original request mutated: %s %s?%s, selected = %q", original.Method, original.URL.EscapedPath(), original.URL.RawQuery, original.Header.Get("X-Selected-Route"))
	}
	originalBody, err := io.ReadAll(original.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(originalBody) != body {
		t.Fatalf("original body = %q, want %q", originalBody, body)
	}
	if applicationCalls != 1 {
		t.Fatalf("application calls = %d, want 1", applicationCalls)
	}
	if err := response.Body.Close(); err != nil {
		t.Fatal(err)
	}
	if !responseBody.closed {
		t.Fatal("ordinary response body remained open after caller close")
	}
}

func TestBeginReturnsOrdinaryResponseWithoutRequirement(t *testing.T) {
	t.Parallel()

	for _, scenario := range []struct {
		name   string
		status int
		body   string
	}{
		{name: "successful response", status: http.StatusOK, body: "application result"},
		{name: "plain unauthorized response", status: http.StatusUnauthorized, body: "ordinary application denial"},
	} {
		scenario := scenario
		t.Run(scenario.name, func(t *testing.T) {
			protocol := newTestProtocol(t)
			personToken := mintBeginPersonToken(t, protocol, nil)
			applicationCalls := 0
			responseBody := &trackedBody{Reader: strings.NewReader(scenario.body)}
			client := protocol.newClientWithHTTPClient(t, &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
				if request.Method == http.MethodGet && request.URL.String() == protocol.resourceID+"/.well-known/aauth-resource.json" {
					return protocol.roundTrip(request)
				}
				applicationCalls++
				verifyProofWithComponents(t, request, protocol.resolver, protocol.clock, aauth.PersonTokenType, nil)
				return &http.Response{
					StatusCode: scenario.status, Status: http.StatusText(scenario.status),
					Header: make(http.Header), Body: responseBody, Request: request,
				}, nil
			})})
			request, err := http.NewRequest(http.MethodGet, protocol.resourceID+"/records/42", nil)
			if err != nil {
				t.Fatal(err)
			}
			result, err := client.Begin(context.Background(), agent.InitialCall{Request: request, PersonToken: personToken})
			if err != nil {
				t.Fatal(err)
			}
			response, ok := result.Response()
			if !ok || response.StatusCode != scenario.status || responseBody.closed {
				t.Fatalf("Response = %#v, %t; closed = %t", response, ok, responseBody.closed)
			}
			if _, ok := result.AuthorizationRequired(); ok {
				t.Fatal("ordinary response exposed an authorization requirement")
			}
			body, err := io.ReadAll(response.Body)
			if err != nil {
				t.Fatal(err)
			}
			if string(body) != scenario.body {
				t.Fatalf("response body = %q, want %q", body, scenario.body)
			}
			response.Body.Close()
			if applicationCalls != 1 {
				t.Fatalf("application calls = %d, want 1", applicationCalls)
			}
		})
	}
}

func TestBeginRejectsInvalidAuthTokenRequirement(t *testing.T) {
	t.Parallel()

	for _, scenario := range []struct {
		name             string
		change           func(*aauth.ResourceTokenClaims)
		header           string
		signatureFailure bool
	}{
		{name: "wrong resource issuer", change: func(claims *aauth.ResourceTokenClaims) { claims.Issuer = "https://other-resource.example" }},
		{name: "wrong person server", change: func(claims *aauth.ResourceTokenClaims) { claims.PersonServer = "https://other-ps.example" }},
		{name: "wrong subject", change: func(claims *aauth.ResourceTokenClaims) { claims.Subject = "other-person" }},
		{name: "wrong presented jti", change: func(claims *aauth.ResourceTokenClaims) { claims.PresentedJTI = "other-person-token" }},
		{name: "wrong agent jkt", change: func(claims *aauth.ResourceTokenClaims) { claims.AgentJKT = strings.Repeat("A", 43) }},
		{name: "wrong tenant", change: func(claims *aauth.ResourceTokenClaims) { claims.Tenant = "other-tenant" }},
		{name: "issued before person token", change: func(claims *aauth.ResourceTokenClaims) { claims.IssuedAt-- }},
		{name: "interaction", change: func(claims *aauth.ResourceTokenClaims) {
			claims.Interaction = &aauth.ResourceInteraction{URL: "https://resource.example/interaction", Code: "ABCD-EFGH"}
		}},
		{name: "account", change: func(claims *aauth.ResourceTokenClaims) { claims.Account = testStringPointer("primary") }},
		{name: "mission", change: func(claims *aauth.ResourceTokenClaims) { claims.MissionS256 = strings.Repeat("A", 43) }},
		{name: "expired resource token", change: func(claims *aauth.ResourceTokenClaims) {
			claims.IssuedAt -= int64((10 * time.Minute) / time.Second)
			claims.ExpiresAt = claims.IssuedAt + int64((5*time.Minute)/time.Second)
		}},
		{name: "malformed requirement", header: `requirement=auth-token;resource-token=?1`},
		{name: "wrong requirement", header: `requirement=person-token`},
		{name: "Signature-Error precedence", signatureFailure: true},
	} {
		scenario := scenario
		t.Run(scenario.name, func(t *testing.T) {
			protocol := newTestProtocol(t)
			personToken := mintBeginPersonToken(t, protocol, nil)
			person, err := aauth.VerifyPersonToken(context.Background(), personToken, protocol.resolver, protocol.clock)
			if err != nil {
				t.Fatal(err)
			}
			claims := beginResourceTokenClaims(t, protocol, person)
			if scenario.change != nil {
				scenario.change(&claims)
			}
			protocol.resolver[signaturekey.StaticKeyReference{
				Issuer: claims.Issuer, DiscoveryDocument: aauth.ResourceDiscoveryDocument, KeyID: protocol.resourceKey.ID(),
			}] = protocol.resourceKey.PublicJWK()
			header := scenario.header
			if header == "" {
				header = mintAuthTokenRequirementHeader(t, protocol, claims)
			}
			applicationCalls := 0
			responseBody := &trackedBody{Reader: strings.NewReader("not authoritative")}
			client := protocol.newClientWithHTTPClient(t, &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
				if request.Method == http.MethodGet && request.URL.String() == protocol.resourceID+"/.well-known/aauth-resource.json" {
					return protocol.roundTrip(request)
				}
				applicationCalls++
				verifyProofWithComponents(t, request, protocol.resolver, protocol.clock, aauth.PersonTokenType, nil)
				responseHeader := make(http.Header)
				responseHeader.Set("AAuth-Requirement", header)
				if scenario.signatureFailure {
					encoded, err := signaturekey.FormatError(signaturekey.Error{Code: signaturekey.ErrorExpiredJWT})
					if err != nil {
						t.Fatal(err)
					}
					responseHeader.Set("Signature-Error", encoded)
				}
				return &http.Response{
					StatusCode: http.StatusUnauthorized, Status: "401 Unauthorized",
					Header: responseHeader, Body: responseBody, Request: request,
				}, nil
			})})
			request, err := http.NewRequest(http.MethodGet, protocol.resourceID+"/records/42", nil)
			if err != nil {
				t.Fatal(err)
			}
			result, err := client.Begin(context.Background(), agent.InitialCall{Request: request, PersonToken: personToken})
			if err == nil {
				t.Fatal("Begin accepted an invalid auth-token requirement")
			}
			var clientFailure *agent.Error
			if !errors.As(err, &clientFailure) || clientFailure.Operation != "begin" {
				t.Fatalf("Begin error = %v, typed error = %#v", err, clientFailure)
			}
			if scenario.signatureFailure {
				var signatureFailure *signaturekey.Error
				if !errors.As(err, &signatureFailure) || signatureFailure.Code != signaturekey.ErrorExpiredJWT {
					t.Fatalf("Signature-Error = %#v; error = %v", signatureFailure, err)
				}
			}
			if _, ok := result.AuthorizationRequired(); ok {
				t.Fatal("invalid challenge returned an authorization requirement")
			}
			if _, ok := result.Response(); ok {
				t.Fatal("invalid challenge returned an ordinary response")
			}
			if !responseBody.closed {
				t.Fatal("Begin did not close the invalid challenge response")
			}
			if applicationCalls != 1 {
				t.Fatalf("application calls = %d, want 1", applicationCalls)
			}
		})
	}
}

func TestBeginRefusesInvalidInputBeforeApplicationRequest(t *testing.T) {
	t.Parallel()

	for _, scenario := range []struct {
		name   string
		input  func(*testing.T, *testProtocol, string) agent.InitialCall
		nilCtx bool
	}{
		{
			name: "nil context", nilCtx: true,
			input: func(t *testing.T, protocol *testProtocol, token string) agent.InitialCall {
				request, _ := http.NewRequest(http.MethodGet, protocol.resourceID+"/records", nil)
				return agent.InitialCall{Request: request, PersonToken: token}
			},
		},
		{
			name: "nil request",
			input: func(*testing.T, *testProtocol, string) agent.InitialCall {
				return agent.InitialCall{}
			},
		},
		{
			name: "invalid resource URL",
			input: func(t *testing.T, _ *testProtocol, token string) agent.InitialCall {
				request, _ := http.NewRequest(http.MethodGet, "http://resource.example/records", nil)
				return agent.InitialCall{Request: request, PersonToken: token}
			},
		},
		{
			name: "empty person token",
			input: func(t *testing.T, protocol *testProtocol, _ string) agent.InitialCall {
				request, _ := http.NewRequest(http.MethodGet, protocol.resourceID+"/records", nil)
				return agent.InitialCall{Request: request}
			},
		},
		{
			name: "wrong-context person token",
			input: func(t *testing.T, protocol *testProtocol, _ string) agent.InitialCall {
				request, _ := http.NewRequest(http.MethodGet, protocol.resourceID+"/records", nil)
				token := mintBeginPersonToken(t, protocol, func(claims *aauth.PersonTokenClaims) {
					claims.Audience = "https://other-resource.example"
				})
				return agent.InitialCall{Request: request, PersonToken: token}
			},
		},
		{
			name: "wrong person-token issuer",
			input: func(t *testing.T, protocol *testProtocol, _ string) agent.InitialCall {
				const otherPersonServer = "https://other-ps.example"
				protocol.resolver[signaturekey.StaticKeyReference{
					Issuer: otherPersonServer, DiscoveryDocument: aauth.PersonDiscoveryDocument, KeyID: protocol.personServerKey.ID(),
				}] = protocol.personServerKey.PublicJWK()
				token := mintBeginPersonToken(t, protocol, func(claims *aauth.PersonTokenClaims) {
					claims.Issuer = otherPersonServer
				})
				request, _ := http.NewRequest(http.MethodGet, protocol.resourceID+"/records", nil)
				return agent.InitialCall{Request: request, PersonToken: token}
			},
		},
		{
			name: "wrong person-token confirmation key",
			input: func(t *testing.T, protocol *testProtocol, _ string) agent.InitialCall {
				otherKey := testSigningKey(t, "other-agent-key", 71)
				token := mintBeginPersonToken(t, protocol, func(claims *aauth.PersonTokenClaims) {
					claims.Confirmation = aauth.Confirmation{JWK: otherKey.PublicJWK()}
				})
				request, _ := http.NewRequest(http.MethodGet, protocol.resourceID+"/records", nil)
				return agent.InitialCall{Request: request, PersonToken: token}
			},
		},
		{
			name: "mission-bound person token",
			input: func(t *testing.T, protocol *testProtocol, _ string) agent.InitialCall {
				token := mintBeginPersonToken(t, protocol, func(claims *aauth.PersonTokenClaims) {
					claims.MissionS256 = strings.Repeat("A", 43)
				})
				request, _ := http.NewRequest(http.MethodGet, protocol.resourceID+"/records", nil)
				return agent.InitialCall{Request: request, PersonToken: token}
			},
		},
		{
			name: "non-replayable body",
			input: func(t *testing.T, protocol *testProtocol, token string) agent.InitialCall {
				request, _ := http.NewRequest(
					http.MethodPost, protocol.resourceID+"/records",
					io.NopCloser(strings.NewReader("non-replayable")),
				)
				request.GetBody = nil
				return agent.InitialCall{Request: request, PersonToken: token}
			},
		},
		{
			name: "GetBody fails",
			input: func(t *testing.T, protocol *testProtocol, token string) agent.InitialCall {
				request, _ := http.NewRequest(http.MethodPost, protocol.resourceID+"/records", strings.NewReader("replayable"))
				request.GetBody = func() (io.ReadCloser, error) { return nil, errors.New("copy failed") }
				return agent.InitialCall{Request: request, PersonToken: token}
			},
		},
		{
			name: "GetBody returns nil",
			input: func(t *testing.T, protocol *testProtocol, token string) agent.InitialCall {
				request, _ := http.NewRequest(http.MethodPost, protocol.resourceID+"/records", strings.NewReader("replayable"))
				request.GetBody = func() (io.ReadCloser, error) { return nil, nil }
				return agent.InitialCall{Request: request, PersonToken: token}
			},
		},
	} {
		scenario := scenario
		t.Run(scenario.name, func(t *testing.T) {
			protocol := newTestProtocol(t)
			networkCalls := 0
			client := protocol.newClientWithHTTPClient(t, &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
				networkCalls++
				return nil, errors.New("unexpected network request: " + request.URL.String())
			})})
			personToken := mintBeginPersonToken(t, protocol, nil)
			ctx := context.Background()
			if scenario.nilCtx {
				ctx = nil
			}
			result, err := client.Begin(ctx, scenario.input(t, protocol, personToken))
			if err == nil {
				t.Fatal("Begin accepted invalid local input")
			}
			var clientFailure *agent.Error
			if !errors.As(err, &clientFailure) || clientFailure.Operation != "begin" {
				t.Fatalf("Begin error = %v, typed error = %#v", err, clientFailure)
			}
			if _, ok := result.Response(); ok {
				t.Fatal("local refusal returned a response")
			}
			if _, ok := result.AuthorizationRequired(); ok {
				t.Fatal("local refusal returned a requirement")
			}
			if networkCalls != 0 {
				t.Fatalf("network calls = %d, want 0", networkCalls)
			}
		})
	}

	var nilClient *agent.Client
	request, _ := http.NewRequest(http.MethodGet, "https://resource.example/records", nil)
	if _, err := nilClient.Begin(context.Background(), agent.InitialCall{Request: request, PersonToken: "person-token"}); err == nil {
		t.Fatal("nil Client accepted Begin")
	}
}

func TestBeginRefusesPersonTokenThatOutlivesAgentBeforeNetwork(t *testing.T) {
	t.Parallel()

	protocol := newTestProtocol(t)
	shortAgentToken, err := aauth.MintAgentToken(
		protocol.agentProviderID,
		protocol.agentProviderKey,
		aauth.AgentTokenRequest{
			Agent: protocol.agentID, PersonServer: protocol.personServerID,
			PublicKey: protocol.agentKey.PublicJWK(), Lifetime: 10 * time.Minute,
		},
		protocol.now,
		"short-agent-token-begin",
	)
	if err != nil {
		t.Fatal(err)
	}
	protocol.agentToken = shortAgentToken
	networkCalls := 0
	client := protocol.newClientWithHTTPClient(t, &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
		networkCalls++
		return nil, errors.New("unexpected network request: " + request.URL.String())
	})})
	personToken := mintBeginPersonToken(t, protocol, nil)
	request, err := http.NewRequest(http.MethodGet, protocol.resourceID+"/records", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Begin(context.Background(), agent.InitialCall{Request: request, PersonToken: personToken}); err == nil ||
		!strings.Contains(err.Error(), "lifetime exceeds agent token") {
		t.Fatalf("Begin error = %v", err)
	}
	if networkCalls != 0 {
		t.Fatalf("network calls = %d, want 0", networkCalls)
	}
}

func TestBeginReturnsVerifiedPendingAuthTokenCall(t *testing.T) {
	t.Parallel()

	protocol := newTestProtocol(t)
	personToken := mintBeginPersonToken(t, protocol, nil)
	person, err := aauth.VerifyPersonToken(context.Background(), personToken, protocol.resolver, protocol.clock)
	if err != nil {
		t.Fatal(err)
	}
	resourceToken := mintBeginResourceToken(t, protocol, beginResourceTokenClaims(t, protocol, person))
	requirement, err := aauth.FormatAuthTokenRequirement(aauth.AuthTokenRequirement{ResourceToken: resourceToken})
	if err != nil {
		t.Fatal(err)
	}
	applicationCalls := 0
	responseBody := &trackedBody{Reader: strings.NewReader(`{"status":"future-state","extension":true}`)}
	client := protocol.newClientWithHTTPClient(t, &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
		if request.Method == http.MethodGet && request.URL.String() == protocol.resourceID+"/.well-known/aauth-resource.json" {
			return protocol.roundTrip(request)
		}
		applicationCalls++
		verifyProofWithComponents(t, request, protocol.resolver, protocol.clock, aauth.PersonTokenType, nil)
		header := make(http.Header)
		header.Set("Location", "/pending/f7a3b9c")
		header.Set("Cache-Control", "private, NO-STORE")
		header.Set("Content-Type", "application/json; charset=utf-8")
		header.Set("AAuth-Requirement", requirement)
		return &http.Response{
			StatusCode: http.StatusAccepted, Status: "202 Accepted",
			Header: header, Body: responseBody, Request: request,
		}, nil
	})})
	request, err := http.NewRequest(http.MethodPost, protocol.resourceID+"/records", strings.NewReader("original body"))
	if err != nil {
		t.Fatal(err)
	}
	result, err := client.Begin(context.Background(), agent.InitialCall{Request: request, PersonToken: personToken})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := result.Response(); ok {
		t.Fatal("pending response also exposed an ordinary response")
	}
	if _, ok := result.AuthorizationRequired(); ok {
		t.Fatal("pending response also exposed a baseline authorization requirement")
	}
	pending, ok := result.PendingAuthToken()
	if !ok {
		t.Fatal("202 did not return a pending auth-token call")
	}
	if pending.ResourceToken() != resourceToken || pending.Location() != protocol.resourceID+"/pending/f7a3b9c" || pending.RetryAfter() != 5*time.Second {
		t.Fatalf("pending = resource token %q, location %q, retry after %s", pending.ResourceToken(), pending.Location(), pending.RetryAfter())
	}
	if !responseBody.closed {
		t.Fatal("Begin did not close the verified pending response")
	}
	if applicationCalls != 1 {
		t.Fatalf("application calls = %d, want 1", applicationCalls)
	}
}

func TestPendingAuthTokenAccessorsAreZeroSafe(t *testing.T) {
	t.Parallel()

	var result agent.CallResult
	if response, ok := result.Response(); response != nil || ok {
		t.Fatalf("zero Response = %#v, %t", response, ok)
	}
	if requirement, ok := result.AuthorizationRequired(); requirement.ResourceToken != "" || ok {
		t.Fatalf("zero AuthorizationRequired = %#v, %t", requirement, ok)
	}
	pending, ok := result.PendingAuthToken()
	if ok || pending.ResourceToken() != "" || pending.Location() != "" || pending.RetryAfter() != 0 {
		t.Fatalf("zero PendingAuthToken = %#v, %t", pending, ok)
	}
}

func TestBeginAcceptsAbsoluteSameOriginPendingLocation(t *testing.T) {
	t.Parallel()

	protocol := newTestProtocol(t)
	personToken := mintBeginPersonToken(t, protocol, nil)
	person, err := aauth.VerifyPersonToken(context.Background(), personToken, protocol.resolver, protocol.clock)
	if err != nil {
		t.Fatal(err)
	}
	resourceToken := mintBeginResourceToken(t, protocol, beginResourceTokenClaims(t, protocol, person))
	requirement, err := aauth.FormatAuthTokenRequirement(aauth.AuthTokenRequirement{ResourceToken: resourceToken})
	if err != nil {
		t.Fatal(err)
	}
	const location = "https://resource.example/pending/absolute?invocation=42"
	client := protocol.newClientWithHTTPClient(t, &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.String() == protocol.resourceID+"/.well-known/aauth-resource.json" {
			return protocol.roundTrip(request)
		}
		return pendingResponse(request, requirement, location, "0", pollBodyFor("pending")), nil
	})})
	request, err := http.NewRequest(http.MethodGet, protocol.resourceID+"/records", nil)
	if err != nil {
		t.Fatal(err)
	}
	result, err := client.Begin(context.Background(), agent.InitialCall{Request: request, PersonToken: personToken})
	if err != nil {
		t.Fatal(err)
	}
	pending, ok := result.PendingAuthToken()
	if !ok || pending.Location() != location || pending.RetryAfter() != 0 {
		t.Fatalf("PendingAuthToken = %#v, %t", pending, ok)
	}
}

func TestBeginRejectsInvalidPendingAuthTokenResponse(t *testing.T) {
	t.Parallel()

	for _, scenario := range []struct {
		name         string
		body         string
		badToken     bool
		changeClaims func(*aauth.ResourceTokenClaims)
		change       func(*http.Response)
	}{
		{name: "missing Location", change: func(response *http.Response) { response.Header.Del("Location") }},
		{name: "multiple Location", change: func(response *http.Response) {
			response.Header["Location"] = []string{"/pending/one", "/pending/two"}
		}},
		{name: "invalid Location", change: func(response *http.Response) { response.Header.Set("Location", "%") }},
		{name: "cross-origin Location", change: func(response *http.Response) {
			response.Header.Set("Location", "https://attacker.example/pending")
		}},
		{name: "HTTP Location", change: func(response *http.Response) {
			response.Header.Set("Location", "http://resource.example/pending")
		}},
		{name: "userinfo Location", change: func(response *http.Response) {
			response.Header.Set("Location", "https://user@resource.example/pending")
		}},
		{name: "fragment Location", change: func(response *http.Response) {
			response.Header.Set("Location", "/pending#fragment")
		}},
		{name: "multiple Retry-After", change: func(response *http.Response) {
			response.Header["Retry-After"] = []string{"1", "2"}
		}},
		{name: "negative Retry-After", change: func(response *http.Response) { response.Header.Set("Retry-After", "-1") }},
		{name: "fractional Retry-After", change: func(response *http.Response) { response.Header.Set("Retry-After", "1.5") }},
		{name: "date Retry-After", change: func(response *http.Response) {
			response.Header.Set("Retry-After", "Sun, 30 Aug 2026 18:00:00 GMT")
		}},
		{name: "overflow Retry-After", change: func(response *http.Response) {
			response.Header.Set("Retry-After", "9223372037")
		}},
		{name: "missing no-store", change: func(response *http.Response) {
			response.Header.Set("Cache-Control", "private, max-age=0")
		}},
		{name: "parameterized no-store", change: func(response *http.Response) {
			response.Header.Set("Cache-Control", "no-store=true")
		}},
		{name: "bad content type", change: func(response *http.Response) {
			response.Header.Set("Content-Type", "text/plain")
		}},
		{name: "multiple content types", change: func(response *http.Response) {
			response.Header["Content-Type"] = []string{"application/json", "text/plain"}
		}},
		{name: "malformed body", body: `{"status":`},
		{name: "missing status", body: `{}`},
		{name: "empty status", body: `{"status":""}`},
		{name: "non-string status", body: `{"status":1}`},
		{name: "oversized body", body: `{"status":"` + strings.Repeat("x", (1<<20)+1) + `"}`},
		{name: "missing requirement", change: func(response *http.Response) {
			response.Header.Del("AAuth-Requirement")
		}},
		{name: "malformed requirement", change: func(response *http.Response) {
			response.Header.Set("AAuth-Requirement", `requirement=auth-token;resource-token=?1`)
		}},
		{name: "wrong requirement", change: func(response *http.Response) {
			response.Header.Set("AAuth-Requirement", `requirement=person-token`)
		}},
		{name: "multiple requirements", change: func(response *http.Response) {
			response.Header["Aauth-Requirement"] = []string{
				response.Header.Get("AAuth-Requirement"),
				response.Header.Get("AAuth-Requirement"),
			}
		}},
		{name: "malformed resource token", change: func(response *http.Response) {
			response.Header.Set("AAuth-Requirement", `requirement=auth-token;resource-token="not.jwt"`)
		}},
		{name: "bad resource-token signature", badToken: true},
		{name: "wrong resource-token context", changeClaims: func(claims *aauth.ResourceTokenClaims) {
			claims.Tenant = "other-tenant"
		}},
	} {
		scenario := scenario
		t.Run(scenario.name, func(t *testing.T) {
			protocol := newTestProtocol(t)
			personToken := mintBeginPersonToken(t, protocol, nil)
			person, err := aauth.VerifyPersonToken(context.Background(), personToken, protocol.resolver, protocol.clock)
			if err != nil {
				t.Fatal(err)
			}
			claims := beginResourceTokenClaims(t, protocol, person)
			if scenario.changeClaims != nil {
				scenario.changeClaims(&claims)
			}
			resourceToken := mintBeginResourceToken(t, protocol, claims)
			if scenario.badToken {
				last := len(resourceToken) - 1
				replacement := byte('A')
				if resourceToken[last] == replacement {
					replacement = 'B'
				}
				resourceToken = resourceToken[:last] + string(replacement)
			}
			requirement, err := aauth.FormatAuthTokenRequirement(aauth.AuthTokenRequirement{ResourceToken: resourceToken})
			if err != nil {
				t.Fatal(err)
			}
			body := scenario.body
			if body == "" {
				body = `{"status":"pending"}`
			}
			responseBody := &trackedBody{Reader: strings.NewReader(body)}
			applicationCalls := 0
			client := protocol.newClientWithHTTPClient(t, &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
				if request.URL.String() == protocol.resourceID+"/.well-known/aauth-resource.json" {
					return protocol.roundTrip(request)
				}
				applicationCalls++
				response := pendingResponse(request, requirement, "/pending/valid", "5", responseBody)
				if scenario.change != nil {
					scenario.change(response)
				}
				return response, nil
			})})
			request, err := http.NewRequest(http.MethodGet, protocol.resourceID+"/records", nil)
			if err != nil {
				t.Fatal(err)
			}
			result, err := client.Begin(context.Background(), agent.InitialCall{Request: request, PersonToken: personToken})
			var clientFailure *agent.Error
			if !errors.As(err, &clientFailure) || clientFailure.Operation != "begin" {
				t.Fatalf("Begin error = %v, typed error = %#v", err, clientFailure)
			}
			if _, ok := result.Response(); ok {
				t.Fatal("invalid pending response exposed an ordinary response")
			}
			if _, ok := result.AuthorizationRequired(); ok {
				t.Fatal("invalid pending response exposed a baseline requirement")
			}
			if _, ok := result.PendingAuthToken(); ok {
				t.Fatal("invalid pending response exposed a pending call")
			}
			if !responseBody.closed {
				t.Fatal("Begin did not close invalid pending response")
			}
			if applicationCalls != 1 {
				t.Fatalf("application calls = %d, want 1", applicationCalls)
			}
		})
	}
}

func TestPollAuthTokenPerformsOneSignedGETForHeldInvocation(t *testing.T) {
	t.Parallel()

	protocol := newTestProtocol(t)
	personToken := mintBeginPersonToken(t, protocol, nil)
	person, err := aauth.VerifyPersonToken(context.Background(), personToken, protocol.resolver, protocol.clock)
	if err != nil {
		t.Fatal(err)
	}
	resourceClaims := beginResourceTokenClaims(t, protocol, person)
	resourceToken := mintBeginResourceToken(t, protocol, resourceClaims)
	authToken := mintPendingAuthToken(t, protocol, resourceClaims, nil)
	requirement, err := aauth.FormatAuthTokenRequirement(aauth.AuthTokenRequirement{ResourceToken: resourceToken})
	if err != nil {
		t.Fatal(err)
	}
	pollBody := &trackedBody{Reader: strings.NewReader("held invocation result")}
	pollCalls := 0
	client := protocol.newClientWithHTTPClient(t, &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
		switch request.URL.String() {
		case protocol.resourceID + "/.well-known/aauth-resource.json":
			return protocol.roundTrip(request)
		case protocol.resourceID + "/records":
			verifyProofWithComponents(t, request, protocol.resolver, protocol.clock, aauth.PersonTokenType, nil)
			return pendingResponse(request, requirement, "/pending/f7a3b9c", "5", pollBodyFor("pending")), nil
		case protocol.resourceID + "/pending/f7a3b9c":
			pollCalls++
			verified := verifyProof(t, request, protocol.resolver, protocol.clock, aauth.AuthTokenType)
			claims, err := verified.AuthClaims()
			if err != nil {
				t.Fatal(err)
			}
			if request.Method != http.MethodGet || request.Body != nil || claims.JTI != "auth-token-pending" {
				t.Fatalf("poll request = %s %s, body = %#v, auth token jti = %q", request.Method, request.URL, request.Body, claims.JTI)
			}
			return &http.Response{
				StatusCode: http.StatusOK, Status: "200 OK", Header: make(http.Header),
				Body: pollBody, Request: request,
			}, nil
		default:
			return nil, errors.New("unexpected request: " + request.URL.String())
		}
	})})
	original, err := http.NewRequest(http.MethodPost, protocol.resourceID+"/records", strings.NewReader("must not be resent"))
	if err != nil {
		t.Fatal(err)
	}
	result, err := client.Begin(context.Background(), agent.InitialCall{Request: original, PersonToken: personToken})
	if err != nil {
		t.Fatal(err)
	}
	pending, ok := result.PendingAuthToken()
	if !ok {
		t.Fatal("Begin did not return pending call")
	}
	pathsBeforePoll := len(protocol.paths)
	response, err := client.PollAuthToken(context.Background(), agent.AuthTokenPoll{Pending: pending, AuthToken: authToken})
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK || pollCalls != 1 {
		t.Fatalf("poll status = %d, calls = %d", response.StatusCode, pollCalls)
	}
	if len(protocol.paths) != pathsBeforePoll {
		t.Fatalf("PollAuthToken made a metadata request: paths before = %d, after = %d (%v)", pathsBeforePoll, len(protocol.paths), protocol.paths)
	}
	if pollBody.closed {
		t.Fatal("PollAuthToken closed the caller-owned response body")
	}
	if err := response.Body.Close(); err != nil {
		t.Fatal(err)
	}
	if !pollBody.closed {
		t.Fatal("caller close did not close the poll response body")
	}
	if response, err := client.PollAuthToken(context.Background(), agent.AuthTokenPoll{Pending: pending}); response != nil || err == nil {
		t.Fatalf("empty auth-token poll response = %#v, error = %v", response, err)
	}
	if pollCalls != 1 {
		t.Fatalf("empty auth-token input made a network request; poll calls = %d", pollCalls)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if response, err := client.PollAuthToken(canceled, agent.AuthTokenPoll{Pending: pending, AuthToken: authToken}); response != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled poll response = %#v, error = %v", response, err)
	}
	if pollCalls != 1 {
		t.Fatalf("canceled context made a network request; poll calls = %d", pollCalls)
	}
}

func TestPollAuthTokenRejectsUnboundAuthTokensBeforeNetwork(t *testing.T) {
	t.Parallel()

	for _, scenario := range []struct {
		name           string
		changeResource func(*aauth.ResourceTokenClaims)
		change         func(*aauth.AuthTokenClaims)
		setup          func(*testProtocol)
	}{
		{name: "wrong issuer", setup: func(protocol *testProtocol) {
			protocol.resolver[signaturekey.StaticKeyReference{
				Issuer: "https://other-as.example", DiscoveryDocument: aauth.AccessDiscoveryDocument,
				KeyID: protocol.accessServerKey.ID(),
			}] = protocol.accessServerKey.PublicJWK()
		}, change: func(claims *aauth.AuthTokenClaims) { claims.Issuer = "https://other-as.example" }},
		{name: "wrong issuer role", setup: func(protocol *testProtocol) {
			protocol.resolver[signaturekey.StaticKeyReference{
				Issuer: protocol.personServerID, DiscoveryDocument: aauth.PersonDiscoveryDocument,
				KeyID: protocol.accessServerKey.ID(),
			}] = protocol.accessServerKey.PublicJWK()
		}, change: func(claims *aauth.AuthTokenClaims) {
			claims.Issuer = claims.PersonServer
			claims.DWK = aauth.PersonDiscoveryDocument
		}},
		{name: "wrong audience", change: func(claims *aauth.AuthTokenClaims) { claims.Audience = "https://other-resource.example" }},
		{name: "wrong person server", change: func(claims *aauth.AuthTokenClaims) { claims.PersonServer = "https://other-ps.example" }},
		{name: "wrong subject", change: func(claims *aauth.AuthTokenClaims) { claims.Subject = "other-person" }},
		{name: "wrong confirmation key", change: func(claims *aauth.AuthTokenClaims) {
			claims.Confirmation = aauth.Confirmation{JWK: testSigningKey(t, "wrong-poll-key", 91).PublicJWK()}
		}},
		{name: "scope outside resource token", change: func(claims *aauth.AuthTokenClaims) { claims.Scope = "records.write" }},
		{
			name: "missing held scope",
			changeResource: func(claims *aauth.ResourceTokenClaims) {
				claims.Scope = "records.read records.write"
			},
			change: func(claims *aauth.AuthTokenClaims) { claims.Scope = "records.read" },
		},
		{name: "account mismatch", change: func(claims *aauth.AuthTokenClaims) { claims.Account = testStringPointer("other-account") }},
		{name: "mission mismatch", change: func(claims *aauth.AuthTokenClaims) { claims.MissionS256 = strings.Repeat("A", 43) }},
		{name: "tenant mismatch", change: func(claims *aauth.AuthTokenClaims) { claims.Tenant = "other-tenant" }},
		{name: "expired", change: func(claims *aauth.AuthTokenClaims) {
			claims.IssuedAt -= int64((20 * time.Minute) / time.Second)
			claims.ExpiresAt = claims.IssuedAt + int64((10*time.Minute)/time.Second)
		}},
	} {
		scenario := scenario
		t.Run(scenario.name, func(t *testing.T) {
			protocol := newTestProtocol(t)
			if scenario.setup != nil {
				scenario.setup(protocol)
			}
			personToken := mintBeginPersonToken(t, protocol, nil)
			person, err := aauth.VerifyPersonToken(context.Background(), personToken, protocol.resolver, protocol.clock)
			if err != nil {
				t.Fatal(err)
			}
			resourceClaims := beginResourceTokenClaims(t, protocol, person)
			if scenario.changeResource != nil {
				scenario.changeResource(&resourceClaims)
			}
			resourceToken := mintBeginResourceToken(t, protocol, resourceClaims)
			requirement, err := aauth.FormatAuthTokenRequirement(aauth.AuthTokenRequirement{ResourceToken: resourceToken})
			if err != nil {
				t.Fatal(err)
			}
			httpCalls := 0
			client := protocol.newClientWithHTTPClient(t, &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
				httpCalls++
				if request.URL.String() == protocol.resourceID+"/.well-known/aauth-resource.json" {
					return protocol.roundTrip(request)
				}
				if request.URL.String() == protocol.resourceID+"/records" {
					return pendingResponse(request, requirement, "/pending/one", "0", pollBodyFor("pending")), nil
				}
				return nil, errors.New("unexpected poll network request")
			})})
			request, err := http.NewRequest(http.MethodGet, protocol.resourceID+"/records", nil)
			if err != nil {
				t.Fatal(err)
			}
			result, err := client.Begin(context.Background(), agent.InitialCall{Request: request, PersonToken: personToken})
			if err != nil {
				t.Fatal(err)
			}
			pending, ok := result.PendingAuthToken()
			if !ok {
				t.Fatal("Begin did not return pending call")
			}
			authToken := mintPendingAuthToken(t, protocol, resourceClaims, scenario.change)
			callsBefore := httpCalls
			response, err := client.PollAuthToken(context.Background(), agent.AuthTokenPoll{Pending: pending, AuthToken: authToken})
			var clientFailure *agent.Error
			if response != nil || !errors.As(err, &clientFailure) || clientFailure.Operation != "poll auth token" {
				t.Fatalf("PollAuthToken response = %#v, error = %v, typed error = %#v", response, err, clientFailure)
			}
			if httpCalls != callsBefore {
				t.Fatalf("HTTP calls = %d after local rejection, want %d", httpCalls, callsBefore)
			}
		})
	}
}

func TestPollAuthTokenRejectsPendingValueFromAnotherClientBeforeNetwork(t *testing.T) {
	t.Parallel()

	protocol := newTestProtocol(t)
	personToken := mintBeginPersonToken(t, protocol, nil)
	person, err := aauth.VerifyPersonToken(context.Background(), personToken, protocol.resolver, protocol.clock)
	if err != nil {
		t.Fatal(err)
	}
	resourceClaims := beginResourceTokenClaims(t, protocol, person)
	resourceToken := mintBeginResourceToken(t, protocol, resourceClaims)
	requirement, err := aauth.FormatAuthTokenRequirement(aauth.AuthTokenRequirement{ResourceToken: resourceToken})
	if err != nil {
		t.Fatal(err)
	}
	first := protocol.newClientWithHTTPClient(t, &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.String() == protocol.resourceID+"/.well-known/aauth-resource.json" {
			return protocol.roundTrip(request)
		}
		return pendingResponse(request, requirement, "/pending/foreign-client", "0", pollBodyFor("pending")), nil
	})})
	request, err := http.NewRequest(http.MethodGet, protocol.resourceID+"/records", nil)
	if err != nil {
		t.Fatal(err)
	}
	result, err := first.Begin(context.Background(), agent.InitialCall{Request: request, PersonToken: personToken})
	if err != nil {
		t.Fatal(err)
	}
	pending, ok := result.PendingAuthToken()
	if !ok {
		t.Fatal("Begin did not return pending call")
	}

	otherKey := testSigningKey(t, "other-poll-client-key", 101)
	otherAgentToken, err := aauth.MintAgentToken(protocol.agentProviderID, protocol.agentProviderKey, aauth.AgentTokenRequest{
		Agent: protocol.agentID, PersonServer: protocol.personServerID,
		PublicKey: otherKey.PublicJWK(), Lifetime: time.Hour,
	}, protocol.now, "other-poll-client-agent-token")
	if err != nil {
		t.Fatal(err)
	}
	networkCalls := 0
	other, err := agent.New(context.Background(), agent.Config{
		Identifier: protocol.agentID, SigningKey: otherKey, AgentToken: otherAgentToken,
		KeyResolver: protocol.resolver, Clock: protocol.clock,
		HTTPClient: &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
			networkCalls++
			return nil, errors.New("unexpected network request: " + request.URL.String())
		})},
	})
	if err != nil {
		t.Fatal(err)
	}
	authClaims := aauth.AuthTokenClaims{
		Issuer: resourceClaims.Audience, DWK: aauth.AccessDiscoveryDocument,
		Audience: resourceClaims.Issuer, JTI: "foreign-client-auth-token",
		PersonServer: resourceClaims.PersonServer, Subject: resourceClaims.Subject,
		Confirmation: aauth.Confirmation{JWK: otherKey.PublicJWK()},
		IssuedAt:     protocol.now.Unix(), ExpiresAt: protocol.now.Add(10 * time.Minute).Unix(),
		Scope: resourceClaims.Scope, Tenant: resourceClaims.Tenant,
	}
	authToken, err := aauth.MintAuthToken(protocol.accessServerKey, authClaims)
	if err != nil {
		t.Fatal(err)
	}
	response, err := other.PollAuthToken(context.Background(), agent.AuthTokenPoll{Pending: pending, AuthToken: authToken})
	if response != nil || err == nil || !strings.Contains(err.Error(), "signing key") {
		t.Fatalf("cross-client PollAuthToken response = %#v, error = %v", response, err)
	}
	if networkCalls != 0 {
		t.Fatalf("cross-client Pending made %d network calls", networkCalls)
	}
}

func TestPollAuthTokenValidatesInputBeforeNetwork(t *testing.T) {
	t.Parallel()

	protocol := newTestProtocol(t)
	httpCalls := 0
	client := protocol.newClientWithHTTPClient(t, &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
		httpCalls++
		return nil, errors.New("unexpected request: " + request.URL.String())
	})})
	for _, scenario := range []struct {
		name   string
		client *agent.Client
		ctx    context.Context
		input  agent.AuthTokenPoll
	}{
		{name: "nil client", client: nil, ctx: context.Background()},
		{name: "nil context", client: client, ctx: nil},
		{name: "zero pending", client: client, ctx: context.Background(), input: agent.AuthTokenPoll{AuthToken: "auth-token"}},
	} {
		scenario := scenario
		t.Run(scenario.name, func(t *testing.T) {
			response, err := scenario.client.PollAuthToken(scenario.ctx, scenario.input)
			var clientFailure *agent.Error
			if response != nil || !errors.As(err, &clientFailure) || clientFailure.Operation != "poll auth token" {
				t.Fatalf("PollAuthToken response = %#v, error = %v, typed error = %#v", response, err, clientFailure)
			}
		})
	}
	if httpCalls != 0 {
		t.Fatalf("HTTP calls = %d, want 0", httpCalls)
	}
}

func TestPollAuthTokenRejectsTokenThatOutlivesAgentBeforeNetwork(t *testing.T) {
	t.Parallel()

	protocol := newTestProtocol(t)
	shortAgentToken, err := aauth.MintAgentToken(
		protocol.agentProviderID,
		protocol.agentProviderKey,
		aauth.AgentTokenRequest{
			Agent: protocol.agentID, PersonServer: protocol.personServerID,
			PublicKey: protocol.agentKey.PublicJWK(), Lifetime: 20 * time.Minute,
		},
		protocol.now,
		"short-poll-agent-token",
	)
	if err != nil {
		t.Fatal(err)
	}
	protocol.agentToken = shortAgentToken
	personToken := mintBeginPersonToken(t, protocol, func(claims *aauth.PersonTokenClaims) {
		claims.ExpiresAt = protocol.now.Add(10 * time.Minute).Unix()
	})
	person, err := aauth.VerifyPersonToken(context.Background(), personToken, protocol.resolver, protocol.clock)
	if err != nil {
		t.Fatal(err)
	}
	resourceClaims := beginResourceTokenClaims(t, protocol, person)
	resourceToken := mintBeginResourceToken(t, protocol, resourceClaims)
	requirement, err := aauth.FormatAuthTokenRequirement(aauth.AuthTokenRequirement{ResourceToken: resourceToken})
	if err != nil {
		t.Fatal(err)
	}
	httpCalls := 0
	client := protocol.newClientWithHTTPClient(t, &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
		httpCalls++
		if request.URL.String() == protocol.resourceID+"/.well-known/aauth-resource.json" {
			return protocol.roundTrip(request)
		}
		if request.URL.String() == protocol.resourceID+"/records" {
			return pendingResponse(request, requirement, "/pending/lifetime", "0", pollBodyFor("pending")), nil
		}
		return nil, errors.New("unexpected poll network request")
	})})
	request, err := http.NewRequest(http.MethodGet, protocol.resourceID+"/records", nil)
	if err != nil {
		t.Fatal(err)
	}
	result, err := client.Begin(context.Background(), agent.InitialCall{Request: request, PersonToken: personToken})
	if err != nil {
		t.Fatal(err)
	}
	pending, ok := result.PendingAuthToken()
	if !ok {
		t.Fatal("Begin did not return pending call")
	}
	authToken := mintPendingAuthToken(t, protocol, resourceClaims, func(claims *aauth.AuthTokenClaims) {
		claims.ExpiresAt = protocol.now.Add(25 * time.Minute).Unix()
	})
	callsBefore := httpCalls
	response, err := client.PollAuthToken(context.Background(), agent.AuthTokenPoll{Pending: pending, AuthToken: authToken})
	if response != nil || err == nil || !strings.Contains(err.Error(), "lifetime exceeds the agent token") {
		t.Fatalf("PollAuthToken response = %#v, error = %v", response, err)
	}
	if httpCalls != callsBefore {
		t.Fatalf("HTTP calls = %d after lifetime rejection, want %d", httpCalls, callsBefore)
	}
}

func TestPollAuthTokenReturnsRetryableResponsesRaw(t *testing.T) {
	t.Parallel()

	for _, status := range []int{http.StatusAccepted, http.StatusTooManyRequests, http.StatusServiceUnavailable} {
		status := status
		t.Run(http.StatusText(status), func(t *testing.T) {
			protocol := newTestProtocol(t)
			personToken := mintBeginPersonToken(t, protocol, nil)
			person, err := aauth.VerifyPersonToken(context.Background(), personToken, protocol.resolver, protocol.clock)
			if err != nil {
				t.Fatal(err)
			}
			resourceClaims := beginResourceTokenClaims(t, protocol, person)
			resourceToken := mintBeginResourceToken(t, protocol, resourceClaims)
			authToken := mintPendingAuthToken(t, protocol, resourceClaims, nil)
			requirement, err := aauth.FormatAuthTokenRequirement(aauth.AuthTokenRequirement{ResourceToken: resourceToken})
			if err != nil {
				t.Fatal(err)
			}
			pollCalls := 0
			pollBody := &trackedBody{Reader: strings.NewReader(`{"error":"slow_down"}`)}
			client := protocol.newClientWithHTTPClient(t, &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
				switch request.URL.String() {
				case protocol.resourceID + "/.well-known/aauth-resource.json":
					return protocol.roundTrip(request)
				case protocol.resourceID + "/records":
					return pendingResponse(request, requirement, "/pending/retryable", "0", pollBodyFor("pending")), nil
				case protocol.resourceID + "/pending/retryable":
					pollCalls++
					header := make(http.Header)
					header.Set("Content-Type", "application/problem+json")
					header.Set("Retry-After", "7")
					return &http.Response{StatusCode: status, Status: http.StatusText(status), Header: header, Body: pollBody, Request: request}, nil
				default:
					return nil, errors.New("unexpected request: " + request.URL.String())
				}
			})})
			request, err := http.NewRequest(http.MethodGet, protocol.resourceID+"/records", nil)
			if err != nil {
				t.Fatal(err)
			}
			result, err := client.Begin(context.Background(), agent.InitialCall{Request: request, PersonToken: personToken})
			if err != nil {
				t.Fatal(err)
			}
			pending, ok := result.PendingAuthToken()
			if !ok {
				t.Fatal("Begin did not return pending call")
			}
			response, err := client.PollAuthToken(context.Background(), agent.AuthTokenPoll{Pending: pending, AuthToken: authToken})
			if err != nil {
				t.Fatal(err)
			}
			if response.StatusCode != status || response.Header.Get("Retry-After") != "7" || pollCalls != 1 {
				t.Fatalf("response = %d Retry-After %q, poll calls = %d", response.StatusCode, response.Header.Get("Retry-After"), pollCalls)
			}
			if pollBody.closed {
				t.Fatal("PollAuthToken closed raw retryable response")
			}
			response.Body.Close()
			if !pollBody.closed {
				t.Fatal("caller close did not close raw retryable response")
			}
		})
	}
}

func TestPollAuthTokenPreservesSignatureErrorAndAAuthProblem(t *testing.T) {
	t.Parallel()

	for _, scenario := range []struct {
		name     string
		response func(*testing.T, *http.Request, *trackedBody) *http.Response
		check    func(*testing.T, error)
	}{
		{
			name: "revoked Auth token requires reauthorization",
			response: func(_ *testing.T, request *http.Request, body *trackedBody) *http.Response {
				header := make(http.Header)
				header.Set("Signature-Error", "error=revoked_jwt")
				header.Set("AAuth-Requirement", "requirement=person-token")
				return &http.Response{
					StatusCode: http.StatusUnauthorized, Header: header,
					Request: request, Body: body,
				}
			},
			check: func(t *testing.T, err error) {
				assertReauthorizationRequired(t, err)
			},
		},
		{
			name: "Signature-Error precedence",
			response: func(t *testing.T, request *http.Request, body *trackedBody) *http.Response {
				header, err := signaturekey.FormatError(signaturekey.Error{Code: signaturekey.ErrorExpiredJWT})
				if err != nil {
					t.Fatal(err)
				}
				response := problemResponse(request, &aauth.ProblemError{Status: http.StatusUnauthorized, Code: "deceptive_body"})
				response.Header.Set("Signature-Error", header)
				response.Body = body
				return response
			},
			check: func(t *testing.T, err error) {
				var signatureFailure *signaturekey.Error
				if !errors.As(err, &signatureFailure) || signatureFailure.Code != signaturekey.ErrorExpiredJWT {
					t.Fatalf("Signature-Error = %#v; error = %v", signatureFailure, err)
				}
				var problem *aauth.ProblemError
				if errors.As(err, &problem) {
					t.Fatalf("problem body overrode Signature-Error: %#v", problem)
				}
			},
		},
		{
			name: "AAuth problem",
			response: func(_ *testing.T, request *http.Request, body *trackedBody) *http.Response {
				response := problemResponse(request, &aauth.ProblemError{Status: http.StatusForbidden, Code: "denied", Detail: "person denied"})
				response.Body = body
				return response
			},
			check: func(t *testing.T, err error) {
				var problem *aauth.ProblemError
				if !errors.As(err, &problem) || problem.Code != "denied" || problem.Detail != "person denied" {
					t.Fatalf("problem = %#v; error = %v", problem, err)
				}
			},
		},
	} {
		scenario := scenario
		t.Run(scenario.name, func(t *testing.T) {
			protocol := newTestProtocol(t)
			personToken := mintBeginPersonToken(t, protocol, nil)
			person, err := aauth.VerifyPersonToken(context.Background(), personToken, protocol.resolver, protocol.clock)
			if err != nil {
				t.Fatal(err)
			}
			resourceClaims := beginResourceTokenClaims(t, protocol, person)
			resourceToken := mintBeginResourceToken(t, protocol, resourceClaims)
			authToken := mintPendingAuthToken(t, protocol, resourceClaims, nil)
			requirement, err := aauth.FormatAuthTokenRequirement(aauth.AuthTokenRequirement{ResourceToken: resourceToken})
			if err != nil {
				t.Fatal(err)
			}
			pollCalls := 0
			responseBody := &trackedBody{Reader: strings.NewReader(`{"error":"denied","detail":"person denied"}`)}
			client := protocol.newClientWithHTTPClient(t, &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
				switch request.URL.String() {
				case protocol.resourceID + "/.well-known/aauth-resource.json":
					return protocol.roundTrip(request)
				case protocol.resourceID + "/records":
					return pendingResponse(request, requirement, "/pending/error", "0", pollBodyFor("pending")), nil
				case protocol.resourceID + "/pending/error":
					pollCalls++
					return scenario.response(t, request, responseBody), nil
				default:
					return nil, errors.New("unexpected request: " + request.URL.String())
				}
			})})
			request, err := http.NewRequest(http.MethodGet, protocol.resourceID+"/records", nil)
			if err != nil {
				t.Fatal(err)
			}
			result, err := client.Begin(context.Background(), agent.InitialCall{Request: request, PersonToken: personToken})
			if err != nil {
				t.Fatal(err)
			}
			pending, ok := result.PendingAuthToken()
			if !ok {
				t.Fatal("Begin did not return pending call")
			}
			response, err := client.PollAuthToken(context.Background(), agent.AuthTokenPoll{Pending: pending, AuthToken: authToken})
			var clientFailure *agent.Error
			if response != nil || !errors.As(err, &clientFailure) || clientFailure.Operation != "poll auth token" {
				t.Fatalf("PollAuthToken response = %#v, error = %v, typed error = %#v", response, err, clientFailure)
			}
			scenario.check(t, err)
			if pollCalls != 1 || !responseBody.closed {
				t.Fatalf("poll calls = %d, response body closed = %t", pollCalls, responseBody.closed)
			}
		})
	}
}

func TestBeginPreservesRemoteAAuthProblem(t *testing.T) {
	t.Parallel()

	protocol := newTestProtocol(t)
	personToken := mintBeginPersonToken(t, protocol, nil)
	applicationCalls := 0
	client := protocol.newClientWithHTTPClient(t, &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
		if request.Method == http.MethodGet && request.URL.String() == protocol.resourceID+"/.well-known/aauth-resource.json" {
			return protocol.roundTrip(request)
		}
		applicationCalls++
		verifyProofWithComponents(t, request, protocol.resolver, protocol.clock, aauth.PersonTokenType, nil)
		return problemResponse(request, &aauth.ProblemError{
			Type: "https://aauth.example/errors/access-denied", Title: "Forbidden",
			Status: http.StatusForbidden, Code: "access_denied", Detail: "application policy denied the request",
		}), nil
	})})
	request, err := http.NewRequest(http.MethodGet, protocol.resourceID+"/records", nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Begin(context.Background(), agent.InitialCall{Request: request, PersonToken: personToken})
	var clientFailure *agent.Error
	if !errors.As(err, &clientFailure) || clientFailure.Operation != "begin" {
		t.Fatalf("Begin error = %v, typed error = %#v", err, clientFailure)
	}
	var problem *aauth.ProblemError
	if !errors.As(err, &problem) || problem.Code != "access_denied" || problem.Detail != "application policy denied the request" {
		t.Fatalf("problem = %#v; error = %v", problem, err)
	}
	if applicationCalls != 1 {
		t.Fatalf("application calls = %d, want 1", applicationCalls)
	}
}

func TestBeginHonorsMaximumSignedBodySizeBeforeApplicationRequest(t *testing.T) {
	t.Parallel()

	protocol := newTestProtocol(t)
	protocol.additionalSignatureComponents = []string{"content-type", "content-digest"}
	const body = `{"record":"too-large"}`
	client := protocol.newClientWithMaxSignedBodyBytes(t, int64(len(body)-1))
	personToken := mintBeginPersonToken(t, protocol, nil)
	request, err := http.NewRequest(http.MethodPost, protocol.resourceID+"/records", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	if _, err := client.Begin(context.Background(), agent.InitialCall{Request: request, PersonToken: personToken}); err == nil ||
		!strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("Begin error = %v", err)
	}
	if got, want := protocol.paths, []string{"/.well-known/aauth-resource.json"}; !slicesEqual(got, want) {
		t.Fatalf("request paths = %v, want %v", got, want)
	}
	originalBody, err := io.ReadAll(request.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(originalBody) != body {
		t.Fatalf("original body = %q, want %q", originalBody, body)
	}
}

func mintBeginPersonToken(t *testing.T, protocol *testProtocol, change func(*aauth.PersonTokenClaims)) string {
	t.Helper()
	claims := aauth.PersonTokenClaims{
		Issuer: protocol.personServerID, DWK: aauth.PersonDiscoveryDocument,
		Audience: protocol.resourceID, Subject: "person-123",
		Confirmation: aauth.Confirmation{JWK: protocol.agentKey.PublicJWK()},
		JTI:          "person-token-begin", IssuedAt: protocol.now.Unix(), ExpiresAt: protocol.now.Add(30 * time.Minute).Unix(),
		Tenant: "tenant-1",
	}
	if change != nil {
		change(&claims)
	}
	compact, err := aauth.MintPersonToken(protocol.personServerKey, claims)
	if err != nil {
		t.Fatal(err)
	}
	return compact
}

func beginResourceTokenClaims(t *testing.T, protocol *testProtocol, person aauth.PersonTokenClaims) aauth.ResourceTokenClaims {
	t.Helper()
	thumbprint, err := protocol.agentKey.PublicJWK().Thumbprint()
	if err != nil {
		t.Fatal(err)
	}
	return aauth.ResourceTokenClaims{
		Issuer: protocol.resourceID, DWK: aauth.ResourceDiscoveryDocument,
		Audience: protocol.accessServerID, JTI: "resource-token-begin",
		PersonServer: person.Issuer, Subject: person.Subject, PresentedJTI: person.JTI,
		AgentJKT: thumbprint, IssuedAt: protocol.now.Unix(), ExpiresAt: protocol.now.Add(5 * time.Minute).Unix(),
		Scope: "records.read", MissionS256: person.MissionS256, Tenant: person.Tenant,
	}
}

func mintAuthTokenRequirementHeader(t *testing.T, protocol *testProtocol, claims aauth.ResourceTokenClaims) string {
	t.Helper()
	compact := mintBeginResourceToken(t, protocol, claims)
	header, err := aauth.FormatAuthTokenRequirement(aauth.AuthTokenRequirement{ResourceToken: compact})
	if err != nil {
		t.Fatal(err)
	}
	return header
}

func mintBeginResourceToken(t *testing.T, protocol *testProtocol, claims aauth.ResourceTokenClaims) string {
	t.Helper()
	compact, err := aauth.MintResourceToken(protocol.resourceKey, claims)
	if err != nil {
		t.Fatal(err)
	}
	return compact
}

func mintPendingAuthToken(
	t *testing.T,
	protocol *testProtocol,
	resource aauth.ResourceTokenClaims,
	change func(*aauth.AuthTokenClaims),
) string {
	t.Helper()
	claims := aauth.AuthTokenClaims{
		Issuer: resource.Audience, DWK: aauth.AccessDiscoveryDocument,
		Audience: resource.Issuer, JTI: "auth-token-pending",
		PersonServer: resource.PersonServer, Subject: resource.Subject,
		Confirmation: aauth.Confirmation{JWK: protocol.agentKey.PublicJWK()},
		IssuedAt:     protocol.now.Unix(), ExpiresAt: protocol.now.Add(10 * time.Minute).Unix(),
		Scope: resource.Scope, Account: resource.Account, MissionS256: resource.MissionS256, Tenant: resource.Tenant,
	}
	if change != nil {
		change(&claims)
	}
	compact, err := aauth.MintAuthToken(protocol.accessServerKey, claims)
	if err != nil {
		t.Fatal(err)
	}
	return compact
}

func pendingResponse(request *http.Request, requirement, location, retryAfter string, body io.ReadCloser) *http.Response {
	header := make(http.Header)
	header.Set("Location", location)
	header.Set("Retry-After", retryAfter)
	header.Set("Cache-Control", "no-store")
	header.Set("Content-Type", "application/json")
	header.Set("AAuth-Requirement", requirement)
	return &http.Response{
		StatusCode: http.StatusAccepted, Status: "202 Accepted",
		Header: header, Body: body, Request: request,
	}
}

func pollBodyFor(status string) io.ReadCloser {
	return io.NopCloser(strings.NewReader(`{"status":"` + status + `"}`))
}

type trackedBody struct {
	io.Reader
	closed bool
}

func (body *trackedBody) Close() error {
	body.closed = true
	return nil
}

func testStringPointer(value string) *string { return &value }

func optionalTestStringPointer(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}
