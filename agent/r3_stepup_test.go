package agent_test

import (
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
	"gitlab.com/sidecat-dev/aauth-go/r3"
	"gitlab.com/sidecat-dev/aauth-go/r3/vocab/mcp"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

func TestBeginR3CallRefusesMalformedClassClaimsBeforeNetwork(t *testing.T) {
	t.Parallel()

	for _, scenario := range []struct {
		name   string
		change func(map[string]json.RawMessage)
	}{
		{name: "partial reference", change: func(claims map[string]json.RawMessage) { delete(claims, "r3_s256") }},
		{name: "malformed per-call operations", change: func(claims map[string]json.RawMessage) {
			claims["r3_per_call"] = json.RawMessage(`{"vocabulary":"urn:aauth:vocabulary:mcp","operations":true}`)
		}},
		{name: "case-variant per-call claim", change: func(claims map[string]json.RawMessage) {
			claims["R3_Per_Call"] = claims["r3_per_call"]
			delete(claims, "r3_per_call")
		}},
	} {
		scenario := scenario
		t.Run(scenario.name, func(t *testing.T) {
			t.Parallel()
			fixture := newAgentR3StepUpFixture(t)
			claims := fixture.rawClassAdditionalClaims(t)
			scenario.change(claims)
			compact := fixture.mintRawClassAuthToken(t, claims)
			networkCalls := 0
			client := fixture.newClientWithHTTPClient(t, &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
				networkCalls++
				return nil, errors.New("unexpected network request: " + request.URL.String())
			})})
			request := fixture.newRequest(t, `{"record":"alpha","enabled":true}`)

			result, err := client.BeginR3Call(context.Background(), agent.R3Call{
				Request: request, ClassAuthToken: compact,
				Operation: fixture.operation, AdditionalSignatureComponents: fixture.components,
			})
			if err == nil {
				t.Fatal("BeginR3Call accepted malformed class R3 claims")
			}
			if networkCalls != 0 {
				t.Fatalf("network calls = %d, want 0", networkCalls)
			}
			if _, ok := result.Response(); ok {
				t.Fatal("malformed class token returned a response")
			}
			if _, ok := result.AuthorizationRequired(); ok {
				t.Fatal("malformed class token returned an authorization")
			}
			if _, ok := result.Pending(); ok {
				t.Fatal("malformed class token returned a pending call")
			}
		})
	}
}

func TestBeginR3CallRefusesClassContextSubstitutionBeforeNetwork(t *testing.T) {
	t.Parallel()

	for _, scenario := range []struct {
		name   string
		change func(*aauth.AuthTokenClaims, agentR3StepUpFixture)
	}{
		{name: "Resource changed", change: func(claims *aauth.AuthTokenClaims, _ agentR3StepUpFixture) {
			claims.Audience = "https://other-resource.example"
		}},
		{name: "Person Server changed", change: func(claims *aauth.AuthTokenClaims, _ agentR3StepUpFixture) {
			claims.PersonServer = "https://other-ps.example"
		}},
		{name: "request key changed", change: func(claims *aauth.AuthTokenClaims, fixture agentR3StepUpFixture) {
			claims.Confirmation = aauth.Confirmation{JWK: fixture.protocol.resourceKey.PublicJWK()}
		}},
	} {
		scenario := scenario
		t.Run(scenario.name, func(t *testing.T) {
			t.Parallel()
			fixture := newAgentR3StepUpFixture(t)
			compact := fixture.mintRawClassAuthTokenWith(
				t, fixture.rawClassAdditionalClaims(t),
				func(claims *aauth.AuthTokenClaims) { scenario.change(claims, fixture) },
			)
			networkCalls := 0
			client := fixture.newClientWithHTTPClient(t, &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
				networkCalls++
				return nil, errors.New("unexpected network request: " + request.URL.String())
			})})
			request := fixture.newRequest(t, `{"record":"alpha","enabled":true}`)
			if _, err := client.BeginR3Call(context.Background(), agent.R3Call{
				Request: request, ClassAuthToken: compact,
				Operation: fixture.operation, AdditionalSignatureComponents: fixture.components,
			}); err == nil {
				t.Fatal("BeginR3Call accepted substituted class context")
			}
			if networkCalls != 0 {
				t.Fatalf("network calls = %d, want 0", networkCalls)
			}
		})
	}
}

func TestBeginR3CallRefusesPersonServerRoleClassTokenBeforeNetwork(t *testing.T) {
	t.Parallel()

	fixture := newAgentR3StepUpFixture(t)
	compact, err := aauth.MintAuthTokenCore(fixture.protocol.personServerKey, aauth.AuthTokenClaims{
		Issuer: fixture.protocol.personServerID, DWK: aauth.PersonDiscoveryDocument,
		Audience: fixture.protocol.resourceID, JTI: "person-role-class-auth-token",
		PersonServer: fixture.protocol.personServerID, Subject: "person-123",
		Confirmation: aauth.Confirmation{JWK: fixture.protocol.agentKey.PublicJWK()},
		IssuedAt:     fixture.protocol.now.Unix(), ExpiresAt: fixture.protocol.now.Add(20 * time.Minute).Unix(),
		Scope: "records.read", Tenant: "tenant-1", AdditionalClaims: fixture.rawClassAdditionalClaims(t),
	})
	if err != nil {
		t.Fatal(err)
	}
	networkCalls := 0
	client := fixture.newClientWithHTTPClient(t, &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
		networkCalls++
		return &http.Response{
			StatusCode: http.StatusOK, Status: "200 OK", Request: request,
			Header: make(http.Header), Body: io.NopCloser(strings.NewReader("not authoritative")),
		}, nil
	})})
	request := fixture.newRequest(t, `{"record":"alpha","enabled":true}`)
	if _, err := client.BeginR3Call(context.Background(), agent.R3Call{
		Request: request, ClassAuthToken: compact,
		Operation: fixture.operation, AdditionalSignatureComponents: fixture.components,
	}); err == nil {
		t.Fatal("BeginR3Call accepted a Person-Server-role class Auth token")
	}
	if networkCalls != 0 {
		t.Fatalf("network calls = %d, want 0", networkCalls)
	}
}

func TestRetryR3CallRefusesPersonServerRoleCompletionAtCollocatedIssuerBeforeNetwork(t *testing.T) {
	t.Parallel()

	fixture := newAgentR3StepUpFixture(t)
	classToken, err := aauth.MintAuthTokenCore(fixture.protocol.accessServerKey, aauth.AuthTokenClaims{
		Issuer: fixture.protocol.personServerID, DWK: aauth.AccessDiscoveryDocument,
		Audience: fixture.protocol.resourceID, JTI: "collocated-access-role-class-token",
		PersonServer: fixture.protocol.personServerID, Subject: "person-123",
		Confirmation: aauth.Confirmation{JWK: fixture.protocol.agentKey.PublicJWK()},
		IssuedAt:     fixture.protocol.now.Unix(), ExpiresAt: fixture.protocol.now.Add(20 * time.Minute).Unix(),
		Scope: "records.read", Tenant: "tenant-1", AdditionalClaims: fixture.rawClassAdditionalClaims(t),
	})
	if err != nil {
		t.Fatal(err)
	}
	proposalToken, proposalReference, exactProposal := fixture.proposalResourceTokenWith(
		t, "collocated-proposal", "", func(claims *aauth.ResourceTokenClaims) {
			claims.Audience = fixture.protocol.personServerID
			claims.Scope = "records.read"
			claims.PresentedJTI = "collocated-access-role-class-token"
		},
	)
	personRoleCompletion, err := r3.MintPerCallAuthToken(fixture.registry, fixture.protocol.personServerKey, aauth.AuthTokenClaims{
		Issuer: fixture.protocol.personServerID, DWK: aauth.PersonDiscoveryDocument,
		Audience: fixture.protocol.resourceID, JTI: "person-role-completion-token",
		PersonServer: fixture.protocol.personServerID, Subject: "person-123",
		Confirmation: aauth.Confirmation{JWK: fixture.protocol.agentKey.PublicJWK()},
		IssuedAt:     fixture.protocol.now.Unix(), ExpiresAt: fixture.protocol.now.Add(5 * time.Minute).Unix(),
		Scope: "records.read", Tenant: "tenant-1",
	}, proposalReference, exactProposal)
	if err != nil {
		t.Fatal(err)
	}
	requirement := formatAgentR3Requirement(t, proposalToken)
	networkCalls := 0
	client := fixture.newClientWithHTTPClient(t, &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
		networkCalls++
		if networkCalls != 1 {
			return nil, errors.New("Person-Server-role completion reached the protected Resource")
		}
		header := make(http.Header)
		header.Set("AAuth-Requirement", requirement)
		header.Set("Cache-Control", "no-store")
		return &http.Response{
			StatusCode: http.StatusUnauthorized, Status: "401 Unauthorized", Request: request,
			Header: header, Body: io.NopCloser(strings.NewReader("authorization required")),
		}, nil
	})})
	request := fixture.newRequest(t, `{"record":"alpha","enabled":true}`)
	result, err := client.BeginR3Call(context.Background(), agent.R3Call{
		Request: request, ClassAuthToken: classToken,
		Operation: fixture.operation, AdditionalSignatureComponents: fixture.components,
	})
	if err != nil {
		t.Fatal(err)
	}
	retry, ok := result.AuthorizationRequired()
	if !ok {
		t.Fatal("collocated Access-role class token did not return a retry handle")
	}
	if _, err := client.RetryR3Call(context.Background(), agent.R3Retry{
		Authorization: retry, AuthToken: personRoleCompletion,
	}); err == nil {
		t.Fatal("RetryR3Call accepted a Person-Server-role completion token")
	}
	if networkCalls != 1 {
		t.Fatalf("network calls = %d, want 1", networkCalls)
	}
}

func TestBeginR3CallRefusesProposalReferenceAndContextSubstitution(t *testing.T) {
	t.Parallel()

	for _, scenario := range []struct {
		name  string
		token func(*testing.T, agentR3StepUpFixture) string
	}{
		{
			name: "class reference reused as proposal",
			token: func(t *testing.T, fixture agentR3StepUpFixture) string {
				return fixture.rawProposalResourceToken(t, "proposal-reused-class", fixture.classReference, nil)
			},
		},
		{
			name: "proposal Access Server changed",
			token: func(t *testing.T, fixture agentR3StepUpFixture) string {
				compact, _, _ := fixture.proposalResourceTokenWith(t, "proposal-other-as", "", func(claims *aauth.ResourceTokenClaims) {
					claims.Audience = "https://other-as.example"
				})
				return compact
			},
		},
		{
			name: "proposal names another presented token",
			token: func(t *testing.T, fixture agentR3StepUpFixture) string {
				compact, _, _ := fixture.proposalResourceTokenWith(t, "proposal-other-presented", "", func(claims *aauth.ResourceTokenClaims) {
					claims.PresentedJTI = "person-token-1"
				})
				return compact
			},
		},
		{
			name: "proposal subject changed",
			token: func(t *testing.T, fixture agentR3StepUpFixture) string {
				compact, _, _ := fixture.proposalResourceTokenWith(t, "proposal-other-person", "", func(claims *aauth.ResourceTokenClaims) {
					claims.Subject = "other-person"
				})
				return compact
			},
		},
	} {
		scenario := scenario
		t.Run(scenario.name, func(t *testing.T) {
			t.Parallel()
			fixture := newAgentR3StepUpFixture(t)
			requirement := formatAgentR3Requirement(t, scenario.token(t, fixture))
			networkCalls := 0
			responseBody := &trackedBody{Reader: strings.NewReader("not authoritative")}
			client := fixture.newClientWithHTTPClient(t, &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
				networkCalls++
				header := make(http.Header)
				header.Set("AAuth-Requirement", requirement)
				header.Set("Cache-Control", "no-store")
				return &http.Response{
					StatusCode: http.StatusUnauthorized, Status: "401 Unauthorized", Request: request,
					Header: header, Body: responseBody,
				}, nil
			})})
			request := fixture.newRequest(t, `{"record":"alpha","enabled":true}`)

			result, err := client.BeginR3Call(context.Background(), agent.R3Call{
				Request: request, ClassAuthToken: fixture.classAuthToken,
				Operation: fixture.operation, AdditionalSignatureComponents: fixture.components,
			})
			if err == nil {
				t.Fatal("BeginR3Call accepted a substituted proposal requirement")
			}
			if networkCalls != 1 {
				t.Fatalf("network calls = %d, want 1", networkCalls)
			}
			if !responseBody.closed {
				t.Fatal("invalid proposal response body remained open")
			}
			if _, ok := result.AuthorizationRequired(); ok {
				t.Fatal("substituted proposal returned an authorization")
			}
		})
	}
}

func TestBeginR3CallRefusesOperationOutsideClassPerCallSetBeforeNetwork(t *testing.T) {
	t.Parallel()

	fixture := newAgentR3StepUpFixture(t)
	other := newAgentMCPOperation(t, "records.delete")
	networkCalls := 0
	client := fixture.newClientWithHTTPClient(t, &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
		networkCalls++
		return nil, errors.New("unexpected network request: " + request.URL.String())
	})})
	request := fixture.newRequest(t, `{"record":"alpha","enabled":true}`)
	if _, err := client.BeginR3Call(context.Background(), agent.R3Call{
		Request: request, ClassAuthToken: fixture.classAuthToken,
		Operation: other, AdditionalSignatureComponents: fixture.components,
	}); err == nil {
		t.Fatal("BeginR3Call accepted an operation outside r3_per_call")
	}
	if networkCalls != 0 {
		t.Fatalf("network calls = %d, want 0", networkCalls)
	}
}

func TestBeginR3CallRefusesResponseOriginSubstitution(t *testing.T) {
	t.Parallel()

	fixture := newAgentR3StepUpFixture(t)
	networkCalls := 0
	responseBody := &trackedBody{Reader: strings.NewReader("not authoritative")}
	client := fixture.newClientWithHTTPClient(t, &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
		networkCalls++
		other, err := http.NewRequest(http.MethodPost, "https://other.example/records", nil)
		if err != nil {
			t.Fatal(err)
		}
		return &http.Response{
			StatusCode: http.StatusOK, Status: "200 OK", Request: other,
			Header: make(http.Header), Body: responseBody,
		}, nil
	})})
	request := fixture.newRequest(t, `{"record":"alpha","enabled":true}`)
	if _, err := client.BeginR3Call(context.Background(), agent.R3Call{
		Request: request, ClassAuthToken: fixture.classAuthToken,
		Operation: fixture.operation, AdditionalSignatureComponents: fixture.components,
	}); err == nil {
		t.Fatal("BeginR3Call accepted a response attributed to another origin")
	}
	if networkCalls != 1 {
		t.Fatalf("network calls = %d, want 1", networkCalls)
	}
	if !responseBody.closed {
		t.Fatal("wrong-origin response body remained open")
	}
}

func TestRetryR3CallRefusesCompletionReferenceAndContextSubstitutionBeforeNetwork(t *testing.T) {
	t.Parallel()

	for _, scenario := range []struct {
		name  string
		token func(*testing.T, agentR3StepUpFixture, r3.Reference, []byte) string
	}{
		{
			name: "proposal reference changed",
			token: func(t *testing.T, fixture agentR3StepUpFixture, reference r3.Reference, exactProposal []byte) string {
				other, err := r3.NewReference(fixture.protocol.resourceID+"/r3/proposal/other", reference.Digest())
				if err != nil {
					t.Fatal(err)
				}
				return fixture.perCallAuthToken(t, "completion-other-reference", other, exactProposal)
			},
		},
		{
			name: "subject changed",
			token: func(t *testing.T, fixture agentR3StepUpFixture, reference r3.Reference, exactProposal []byte) string {
				return fixture.perCallAuthTokenWith(t, "completion-other-person", reference, exactProposal, func(claims *aauth.AuthTokenClaims) {
					claims.Subject = "other-person"
				})
			},
		},
		{
			name: "tenant changed",
			token: func(t *testing.T, fixture agentR3StepUpFixture, reference r3.Reference, exactProposal []byte) string {
				return fixture.perCallAuthTokenWith(t, "completion-other-tenant", reference, exactProposal, func(claims *aauth.AuthTokenClaims) {
					claims.Tenant = "other-tenant"
				})
			},
		},
		{
			name: "scope expanded",
			token: func(t *testing.T, fixture agentR3StepUpFixture, reference r3.Reference, exactProposal []byte) string {
				return fixture.perCallAuthTokenWith(t, "completion-expanded-scope", reference, exactProposal, func(claims *aauth.AuthTokenClaims) {
					claims.Scope = "records.read records.admin"
				})
			},
		},
		{
			name: "explicit empty per-call claim",
			token: func(t *testing.T, fixture agentR3StepUpFixture, reference r3.Reference, exactProposal []byte) string {
				return fixture.perCallAuthTokenWithEmptyPerCallClaim(t, reference, exactProposal)
			},
		},
	} {
		scenario := scenario
		t.Run(scenario.name, func(t *testing.T) {
			t.Parallel()
			fixture := newAgentR3StepUpFixture(t)
			proposalToken, proposalReference, exactProposal := fixture.proposalResourceToken(t, "proposal-for-substitution")
			requirement := formatAgentR3Requirement(t, proposalToken)
			networkCalls := 0
			client := fixture.newClientWithHTTPClient(t, &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
				networkCalls++
				if networkCalls != 1 {
					t.Fatalf("substituted completion token caused network call %d", networkCalls)
				}
				header := make(http.Header)
				header.Set("AAuth-Requirement", requirement)
				header.Set("Cache-Control", "no-store")
				return &http.Response{
					StatusCode: http.StatusUnauthorized, Status: "401 Unauthorized", Request: request,
					Header: header, Body: io.NopCloser(strings.NewReader("authorization required")),
				}, nil
			})})
			request := fixture.newRequest(t, `{"record":"alpha","enabled":true}`)
			result, err := client.BeginR3Call(context.Background(), agent.R3Call{
				Request: request, ClassAuthToken: fixture.classAuthToken,
				Operation: fixture.operation, AdditionalSignatureComponents: fixture.components,
			})
			if err != nil {
				t.Fatal(err)
			}
			retry, ok := result.AuthorizationRequired()
			if !ok {
				t.Fatal("valid proposal did not return retry handle")
			}
			compact := scenario.token(t, fixture, proposalReference, exactProposal)
			if _, err := client.RetryR3Call(context.Background(), agent.R3Retry{
				Authorization: retry, AuthToken: compact,
			}); err == nil {
				t.Fatal("RetryR3Call accepted substituted completion token")
			}
			if networkCalls != 1 {
				t.Fatalf("network calls = %d, want 1", networkCalls)
			}
		})
	}
}

func TestR3CallResultsAndHandlesAreZeroSafe(t *testing.T) {
	t.Parallel()

	var result agent.R3CallResult
	if response, ok := result.Response(); response != nil || ok {
		t.Fatalf("zero Response = %#v, %t", response, ok)
	}
	authorization, ok := result.AuthorizationRequired()
	if ok || authorization.ResourceToken() != "" || authorization.Reference().URI() != "" {
		t.Fatalf("zero AuthorizationRequired = %#v, %t", authorization, ok)
	}
	pending, ok := result.Pending()
	if ok || pending.ResourceToken() != "" || pending.Reference().URI() != "" || pending.Location() != "" || pending.RetryAfter() != 0 {
		t.Fatalf("zero Pending = %#v, %t", pending, ok)
	}
	fixture := newAgentR3StepUpFixture(t)
	networkCalls := 0
	client := fixture.newClientWithHTTPClient(t, &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
		networkCalls++
		return nil, errors.New("unexpected network request: " + request.URL.String())
	})})
	if _, err := client.RetryR3Call(context.Background(), agent.R3Retry{AuthToken: fixture.classAuthToken}); err == nil {
		t.Fatal("RetryR3Call accepted a zero authorization")
	}
	if _, err := client.PollR3Call(context.Background(), agent.R3Poll{AuthToken: fixture.classAuthToken}); err == nil {
		t.Fatal("PollR3Call accepted a zero pending call")
	}
	if networkCalls != 0 {
		t.Fatalf("zero handles caused %d network calls", networkCalls)
	}
}

func TestBeginR3CallReturnsOrdinaryResponseAfterExactlyOneNetworkCall(t *testing.T) {
	t.Parallel()

	fixture := newAgentR3StepUpFixture(t)
	const body = `{"record":"alpha","enabled":true}`
	networkCalls := 0
	responseBody := &trackedBody{Reader: strings.NewReader("application result")}
	client := fixture.newClientWithHTTPClient(t, &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
		networkCalls++
		fixture.verifyClassCall(t, request, body)
		return &http.Response{
			StatusCode: http.StatusOK, Status: "200 OK", Request: request,
			Header: make(http.Header), Body: responseBody,
		}, nil
	})})
	original := fixture.newRequest(t, body)

	result, err := client.BeginR3Call(context.Background(), agent.R3Call{
		Request: original, ClassAuthToken: fixture.classAuthToken,
		Operation: fixture.operation, AdditionalSignatureComponents: fixture.components,
	})
	if err != nil {
		t.Fatal(err)
	}
	response, ok := result.Response()
	if !ok || response.StatusCode != http.StatusOK || responseBody.closed {
		t.Fatalf("Response = %#v, %t; closed = %t", response, ok, responseBody.closed)
	}
	if _, ok := result.AuthorizationRequired(); ok {
		t.Fatal("ordinary response also exposed an authorization requirement")
	}
	if _, ok := result.Pending(); ok {
		t.Fatal("ordinary response also exposed a pending call")
	}
	if networkCalls != 1 {
		t.Fatalf("network calls = %d, want 1", networkCalls)
	}
	assertAgentR3OriginalUnchanged(t, original, body)
	response.Body.Close()
}

func TestBeginR3CallReturnsRetryThatPreservesExactOriginalRequest(t *testing.T) {
	t.Parallel()

	fixture := newAgentR3StepUpFixture(t)
	const body = `{"record":"alpha","enabled":true}`
	missionS256 := strings.Repeat("M", 43)
	classAuthToken := fixture.mintRawClassAuthTokenWith(
		t, fixture.rawClassAdditionalClaims(t), func(claims *aauth.AuthTokenClaims) {
			claims.Scope = "records.read records.audit"
			claims.MissionS256 = missionS256
		},
	)
	proposalToken, proposalReference, exactProposal := fixture.proposalResourceTokenWith(
		t, "proposal-token-401", "", func(claims *aauth.ResourceTokenClaims) {
			claims.MissionS256 = missionS256
			claims.PresentedJTI = "raw-class-auth-token"
		},
	)
	completionToken := fixture.perCallAuthTokenWith(
		t, "auth-token-401", proposalReference, exactProposal, func(claims *aauth.AuthTokenClaims) {
			claims.MissionS256 = missionS256
		},
	)
	requirement := formatAgentR3Requirement(t, proposalToken)
	networkCalls := 0
	client := fixture.newClientWithHTTPClient(t, &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
		networkCalls++
		switch networkCalls {
		case 1:
			fixture.verifyClassCallWithToken(t, request, classAuthToken, body)
			header := make(http.Header)
			header.Set("AAuth-Requirement", requirement)
			header.Set("Cache-Control", "private, no-store")
			return &http.Response{
				StatusCode: http.StatusUnauthorized, Status: "401 Unauthorized", Request: request,
				Header: header, Body: io.NopCloser(strings.NewReader("authorization required")),
			}, nil
		case 2:
			fixture.verifyCompletionCall(t, request, completionToken, body)
			return &http.Response{
				StatusCode: http.StatusCreated, Status: "201 Created", Request: request,
				Header: make(http.Header), Body: io.NopCloser(strings.NewReader("created")),
			}, nil
		default:
			t.Fatalf("unexpected network call %d to %s", networkCalls, request.URL)
			return nil, nil
		}
	})})
	original := fixture.newRequest(t, body)

	result, err := client.BeginR3Call(context.Background(), agent.R3Call{
		Request: original, ClassAuthToken: classAuthToken,
		Operation: fixture.operation, AdditionalSignatureComponents: fixture.components,
	})
	if err != nil {
		t.Fatal(err)
	}
	retry, ok := result.AuthorizationRequired()
	if !ok || retry.ResourceToken() != proposalToken || retry.Reference() != proposalReference {
		t.Fatalf("AuthorizationRequired = %#v, %t", retry, ok)
	}
	if networkCalls != 1 {
		t.Fatalf("begin network calls = %d, want 1", networkCalls)
	}
	assertAgentR3OriginalUnchanged(t, original, body)
	original.Method = http.MethodDelete
	original.URL.Path = "/caller-mutated"
	original.URL.RawPath = ""
	original.URL.RawQuery = "changed=true"
	original.Header.Set("X-Request-ID", "caller-mutated")
	original.Header.Set("X-Caller-Context", "caller-mutated")
	original.Body = io.NopCloser(strings.NewReader("caller-mutated"))
	original.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(strings.NewReader("caller-mutated")), nil
	}

	response, err := client.RetryR3Call(context.Background(), agent.R3Retry{
		Authorization: retry, AuthToken: completionToken,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("retry status = %d, want %d", response.StatusCode, http.StatusCreated)
	}
	if networkCalls != 2 {
		t.Fatalf("total network calls = %d, want 2", networkCalls)
	}
}

func TestBeginR3CallReturnsPendingThatPollsWithoutResendingBody(t *testing.T) {
	t.Parallel()

	fixture := newAgentR3StepUpFixture(t)
	const body = `{"record":"alpha","enabled":true}`
	proposalToken, proposalReference, exactProposal := fixture.proposalResourceToken(t, "proposal-token-202")
	completionToken := fixture.perCallAuthToken(t, "auth-token-202", proposalReference, exactProposal)
	requirement := formatAgentR3Requirement(t, proposalToken)
	networkCalls := 0
	client := fixture.newClientWithHTTPClient(t, &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
		networkCalls++
		switch networkCalls {
		case 1:
			fixture.verifyClassCall(t, request, body)
			header := make(http.Header)
			header.Set("AAuth-Requirement", requirement)
			header.Set("Location", "/r3/pending/invocation-202")
			header.Set("Retry-After", "3")
			header.Set("Cache-Control", "private, no-store")
			header.Set("Content-Type", "application/json")
			return &http.Response{
				StatusCode: http.StatusAccepted, Status: "202 Accepted", Request: request,
				Header: header, Body: io.NopCloser(strings.NewReader(`{"status":"pending"}`)),
			}, nil
		case 2:
			if request.Method != http.MethodGet || request.URL.String() != fixture.protocol.resourceID+"/r3/pending/invocation-202" {
				t.Fatalf("poll request = %s %s", request.Method, request.URL)
			}
			if request.Body != nil && request.Body != http.NoBody {
				pollBody, err := io.ReadAll(request.Body)
				if err != nil {
					t.Fatal(err)
				}
				if len(pollBody) != 0 {
					t.Fatalf("poll resent application body %q", pollBody)
				}
			}
			fixture.verifyProofToken(t, request, completionToken, nil)
			return &http.Response{
				StatusCode: http.StatusOK, Status: "200 OK", Request: request,
				Header: make(http.Header), Body: io.NopCloser(strings.NewReader("complete")),
			}, nil
		default:
			t.Fatalf("unexpected network call %d to %s", networkCalls, request.URL)
			return nil, nil
		}
	})})
	original := fixture.newRequest(t, body)

	result, err := client.BeginR3Call(context.Background(), agent.R3Call{
		Request: original, ClassAuthToken: fixture.classAuthToken,
		Operation: fixture.operation, AdditionalSignatureComponents: fixture.components,
	})
	if err != nil {
		t.Fatal(err)
	}
	pending, ok := result.Pending()
	if !ok || pending.ResourceToken() != proposalToken || pending.Reference() != proposalReference ||
		pending.Location() != fixture.protocol.resourceID+"/r3/pending/invocation-202" || pending.RetryAfter() != 3*time.Second {
		t.Fatalf("Pending = %#v, %t", pending, ok)
	}
	if networkCalls != 1 {
		t.Fatalf("begin network calls = %d, want 1", networkCalls)
	}
	assertAgentR3OriginalUnchanged(t, original, body)

	response, err := client.PollR3Call(context.Background(), agent.R3Poll{
		Pending: pending, AuthToken: completionToken,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("poll status = %d, want %d", response.StatusCode, http.StatusOK)
	}
	if networkCalls != 2 {
		t.Fatalf("total network calls = %d, want 2", networkCalls)
	}
}

type agentR3StepUpFixture struct {
	protocol       *testProtocol
	registry       r3.Registry
	operation      r3.Operation
	classReference r3.Reference
	classAuthToken string
	components     []string
}

func newAgentR3StepUpFixture(t *testing.T) agentR3StepUpFixture {
	t.Helper()
	protocol := newTestProtocol(t)
	registry := newAgentR3Registry(t)
	operation := newAgentMCPOperation(t, "records.update")
	operations := newAgentMCPOperationSet(t, operation)
	document, err := r3.NewDocument(operations, r3.DocumentOptions{})
	if err != nil {
		t.Fatal(err)
	}
	exactDocument, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	classReference, err := r3.NewReference(protocol.resourceID+"/r3/class-1", r3.Digest(exactDocument))
	if err != nil {
		t.Fatal(err)
	}
	direct, err := r3.NewGrantedOperations(mcp.Vocabulary())
	if err != nil {
		t.Fatal(err)
	}
	perCall, err := r3.NewGrantedOperations(mcp.Vocabulary(), operation)
	if err != nil {
		t.Fatal(err)
	}
	authorization, err := r3.NewAuthorization(direct, perCall, document)
	if err != nil {
		t.Fatal(err)
	}
	classAuthToken, err := r3.MintAuthToken(registry, protocol.accessServerKey, aauth.AuthTokenClaims{
		Issuer: protocol.accessServerID, DWK: aauth.AccessDiscoveryDocument,
		Audience: protocol.resourceID, JTI: "class-auth-token-1",
		PersonServer: protocol.personServerID, Subject: "person-123",
		Confirmation: aauth.Confirmation{JWK: protocol.agentKey.PublicJWK()},
		IssuedAt:     protocol.now.Unix(), ExpiresAt: protocol.now.Add(20 * time.Minute).Unix(),
		Scope: "records.read records.audit", Tenant: "tenant-1",
	}, classReference, exactDocument, authorization)
	if err != nil {
		t.Fatal(err)
	}
	return agentR3StepUpFixture{
		protocol: protocol, registry: registry, operation: operation, classReference: classReference,
		classAuthToken: classAuthToken,
		components:     []string{"content-type", "content-digest", "x-request-id"},
	}
}

func (fixture agentR3StepUpFixture) newClientWithHTTPClient(t *testing.T, httpClient *http.Client) *agent.Client {
	t.Helper()
	client, err := agent.New(context.Background(), agent.Config{
		Identifier: fixture.protocol.agentID, SigningKey: fixture.protocol.agentKey,
		AgentToken: fixture.protocol.agentToken, KeyResolver: fixture.protocol.resolver,
		HTTPClient: httpClient, Clock: fixture.protocol.clock,
		R3: &agent.R3Config{Registry: fixture.registry},
	})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func (fixture agentR3StepUpFixture) newRequest(t *testing.T, body string) *http.Request {
	t.Helper()
	request, err := http.NewRequest(http.MethodPost, fixture.protocol.resourceID+"/records/a%2Fb?view=full%20detail", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Request-ID", "request-42")
	request.Header.Set("X-Caller-Context", "preserve-me")
	return request
}

func (fixture agentR3StepUpFixture) proposalResourceToken(t *testing.T, jti string) (string, r3.Reference, []byte) {
	return fixture.proposalResourceTokenWith(t, jti, "", nil)
}

func (fixture agentR3StepUpFixture) proposalResourceTokenWith(
	t *testing.T,
	jti string,
	uri string,
	change func(*aauth.ResourceTokenClaims),
) (string, r3.Reference, []byte) {
	t.Helper()
	parameter, err := r3.NewInlineParameter([]byte(`{"record":"alpha","enabled":true}`))
	if err != nil {
		t.Fatal(err)
	}
	parameters, err := r3.NewParameters(map[string]r3.Parameter{"input": parameter})
	if err != nil {
		t.Fatal(err)
	}
	proposal, err := r3.NewProposal(fixture.operation, parameters, r3.ProposalOptions{})
	if err != nil {
		t.Fatal(err)
	}
	exactProposal, err := json.Marshal(proposal)
	if err != nil {
		t.Fatal(err)
	}
	thumbprint, err := fixture.protocol.agentKey.PublicJWK().Thumbprint()
	if err != nil {
		t.Fatal(err)
	}
	claims := aauth.ResourceTokenClaims{
		Issuer: fixture.protocol.resourceID, DWK: aauth.ResourceDiscoveryDocument,
		Audience: fixture.protocol.accessServerID, JTI: jti,
		PersonServer: fixture.protocol.personServerID, Subject: "person-123", PresentedJTI: "class-auth-token-1",
		AgentJKT: thumbprint, IssuedAt: fixture.protocol.now.Unix(), ExpiresAt: fixture.protocol.now.Add(5 * time.Minute).Unix(),
		Scope: "records.read records.audit", Tenant: "tenant-1",
	}
	if change != nil {
		change(&claims)
	}
	if uri == "" {
		uri = fixture.protocol.resourceID + "/r3/proposal/" + jti
	}
	compact, reference, err := r3.MintProposalResourceToken(
		fixture.registry, fixture.protocol.resourceKey, claims, uri, exactProposal,
	)
	if err != nil {
		t.Fatal(err)
	}
	return compact, reference, exactProposal
}

func (fixture agentR3StepUpFixture) perCallAuthToken(t *testing.T, jti string, reference r3.Reference, exactProposal []byte) string {
	return fixture.perCallAuthTokenWith(t, jti, reference, exactProposal, nil)
}

func (fixture agentR3StepUpFixture) perCallAuthTokenWith(
	t *testing.T,
	jti string,
	reference r3.Reference,
	exactProposal []byte,
	change func(*aauth.AuthTokenClaims),
) string {
	t.Helper()
	claims := aauth.AuthTokenClaims{
		Issuer: fixture.protocol.accessServerID, DWK: aauth.AccessDiscoveryDocument,
		Audience: fixture.protocol.resourceID, JTI: jti,
		PersonServer: fixture.protocol.personServerID, Subject: "person-123",
		Confirmation: aauth.Confirmation{JWK: fixture.protocol.agentKey.PublicJWK()},
		IssuedAt:     fixture.protocol.now.Unix(), ExpiresAt: fixture.protocol.now.Add(10 * time.Minute).Unix(),
		Scope: "records.read", Tenant: "tenant-1",
	}
	if change != nil {
		change(&claims)
	}
	compact, err := r3.MintPerCallAuthToken(
		fixture.registry, fixture.protocol.accessServerKey, claims, reference, exactProposal,
	)
	if err != nil {
		t.Fatal(err)
	}
	return compact
}

func (fixture agentR3StepUpFixture) perCallAuthTokenWithEmptyPerCallClaim(
	t *testing.T,
	reference r3.Reference,
	exactProposal []byte,
) string {
	t.Helper()
	proposal, err := fixture.registry.ParseReferencedProposal(reference, exactProposal)
	if err != nil {
		t.Fatal(err)
	}
	granted, err := r3.NewGrantedOperations(mcp.Vocabulary(), proposal.Operation())
	if err != nil {
		t.Fatal(err)
	}
	empty, err := r3.NewGrantedOperations(mcp.Vocabulary())
	if err != nil {
		t.Fatal(err)
	}
	compact, err := aauth.MintAuthTokenCore(fixture.protocol.accessServerKey, aauth.AuthTokenClaims{
		Issuer: fixture.protocol.accessServerID, DWK: aauth.AccessDiscoveryDocument,
		Audience: fixture.protocol.resourceID, JTI: "explicit-empty-per-call-auth-token",
		PersonServer: fixture.protocol.personServerID, Subject: "person-123",
		Confirmation: aauth.Confirmation{JWK: fixture.protocol.agentKey.PublicJWK()},
		IssuedAt:     fixture.protocol.now.Unix(), ExpiresAt: fixture.protocol.now.Add(10 * time.Minute).Unix(),
		Scope: "records.read", Tenant: "tenant-1",
		AdditionalClaims: map[string]json.RawMessage{
			"r3_uri": mustAgentR3JSON(t, reference.URI()), "r3_s256": mustAgentR3JSON(t, reference.Digest()),
			"r3_granted": mustAgentR3JSON(t, granted), "r3_per_call": mustAgentR3JSON(t, empty),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return compact
}

func (fixture agentR3StepUpFixture) rawClassAdditionalClaims(t *testing.T) map[string]json.RawMessage {
	t.Helper()
	empty, err := r3.NewGrantedOperations(mcp.Vocabulary())
	if err != nil {
		t.Fatal(err)
	}
	perCall, err := r3.NewGrantedOperations(mcp.Vocabulary(), fixture.operation)
	if err != nil {
		t.Fatal(err)
	}
	return map[string]json.RawMessage{
		"r3_uri":      mustAgentR3JSON(t, fixture.classReference.URI()),
		"r3_s256":     mustAgentR3JSON(t, fixture.classReference.Digest()),
		"r3_granted":  mustAgentR3JSON(t, empty),
		"r3_per_call": mustAgentR3JSON(t, perCall),
	}
}

func (fixture agentR3StepUpFixture) mintRawClassAuthToken(t *testing.T, additional map[string]json.RawMessage) string {
	return fixture.mintRawClassAuthTokenWith(t, additional, nil)
}

func (fixture agentR3StepUpFixture) mintRawClassAuthTokenWith(
	t *testing.T,
	additional map[string]json.RawMessage,
	change func(*aauth.AuthTokenClaims),
) string {
	t.Helper()
	claims := aauth.AuthTokenClaims{
		Issuer: fixture.protocol.accessServerID, DWK: aauth.AccessDiscoveryDocument,
		Audience: fixture.protocol.resourceID, JTI: "raw-class-auth-token",
		PersonServer: fixture.protocol.personServerID, Subject: "person-123",
		Confirmation: aauth.Confirmation{JWK: fixture.protocol.agentKey.PublicJWK()},
		IssuedAt:     fixture.protocol.now.Unix(), ExpiresAt: fixture.protocol.now.Add(20 * time.Minute).Unix(),
		Scope: "records.read", Tenant: "tenant-1", AdditionalClaims: additional,
	}
	if change != nil {
		change(&claims)
	}
	compact, err := aauth.MintAuthTokenCore(fixture.protocol.accessServerKey, claims)
	if err != nil {
		t.Fatal(err)
	}
	return compact
}

func (fixture agentR3StepUpFixture) rawProposalResourceToken(
	t *testing.T,
	jti string,
	reference r3.Reference,
	change func(*aauth.ResourceTokenClaims),
) string {
	t.Helper()
	thumbprint, err := fixture.protocol.agentKey.PublicJWK().Thumbprint()
	if err != nil {
		t.Fatal(err)
	}
	claims := aauth.ResourceTokenClaims{
		Issuer: fixture.protocol.resourceID, DWK: aauth.ResourceDiscoveryDocument,
		Audience: fixture.protocol.accessServerID, JTI: jti,
		PersonServer: fixture.protocol.personServerID, Subject: "person-123", PresentedJTI: "class-auth-token-1",
		AgentJKT: thumbprint, IssuedAt: fixture.protocol.now.Unix(), ExpiresAt: fixture.protocol.now.Add(5 * time.Minute).Unix(),
		Scope: "records.read", Tenant: "tenant-1",
		AdditionalClaims: map[string]json.RawMessage{
			"r3_uri":  mustAgentR3JSON(t, reference.URI()),
			"r3_s256": mustAgentR3JSON(t, reference.Digest()),
		},
	}
	if change != nil {
		change(&claims)
	}
	compact, err := aauth.MintResourceTokenCore(fixture.protocol.resourceKey, claims)
	if err != nil {
		t.Fatal(err)
	}
	return compact
}

func mustAgentR3JSON(t *testing.T, value any) json.RawMessage {
	t.Helper()
	exact, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return exact
}

func (fixture agentR3StepUpFixture) verifyClassCall(t *testing.T, request *http.Request, body string) {
	fixture.verifyClassCallWithToken(t, request, fixture.classAuthToken, body)
}

func (fixture agentR3StepUpFixture) verifyClassCallWithToken(t *testing.T, request *http.Request, compact, body string) {
	t.Helper()
	if request.Method != http.MethodPost || request.URL.EscapedPath() != "/records/a%2Fb" || request.URL.RawQuery != "view=full%20detail" ||
		request.Header.Get("X-Request-ID") != "request-42" || request.Header.Get("X-Caller-Context") != "preserve-me" {
		t.Fatalf("class request = %s %s?%s, request id %q, caller context %q", request.Method, request.URL.EscapedPath(), request.URL.RawQuery, request.Header.Get("X-Request-ID"), request.Header.Get("X-Caller-Context"))
	}
	fixture.verifyProofToken(t, request, compact, fixture.components)
	exact, err := io.ReadAll(request.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(exact) != body {
		t.Fatalf("class request body = %q, want %q", exact, body)
	}
}

func (fixture agentR3StepUpFixture) verifyCompletionCall(t *testing.T, request *http.Request, compact, body string) {
	t.Helper()
	if request.Method != http.MethodPost || request.URL.EscapedPath() != "/records/a%2Fb" || request.URL.RawQuery != "view=full%20detail" ||
		request.Header.Get("X-Request-ID") != "request-42" || request.Header.Get("X-Caller-Context") != "preserve-me" {
		t.Fatalf("completion request = %s %s?%s, request id %q, caller context %q", request.Method, request.URL.EscapedPath(), request.URL.RawQuery, request.Header.Get("X-Request-ID"), request.Header.Get("X-Caller-Context"))
	}
	fixture.verifyProofToken(t, request, compact, fixture.components)
	exact, err := io.ReadAll(request.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(exact) != body {
		t.Fatalf("completion body = %q, want %q", exact, body)
	}
}

func (fixture agentR3StepUpFixture) verifyProofToken(t *testing.T, request *http.Request, want string, components []string) {
	t.Helper()
	prepared, err := signaturekey.PrepareRequest(request, fixture.protocol.clock, signaturekey.VerifyOptions{
		AcceptedSchemes: []signaturekey.Scheme{signaturekey.SchemeJWT}, RequiredComponents: components,
	})
	if err != nil {
		t.Fatal(err)
	}
	compact, ok := prepared.Credential().JWT()
	if !ok || compact != want {
		t.Fatalf("request credential = %q, JWT = %t", compact, ok)
	}
	if _, err := prepared.Verify(fixture.protocol.agentKey.PublicJWK()); err != nil {
		t.Fatal(err)
	}
}

func assertAgentR3OriginalUnchanged(t *testing.T, request *http.Request, body string) {
	t.Helper()
	for _, name := range []string{"Signature-Key", "Signature-Input", "Signature", "Content-Digest"} {
		if value := request.Header.Get(name); value != "" {
			t.Fatalf("original %s = %q", name, value)
		}
	}
	if request.Method != http.MethodPost || request.URL.EscapedPath() != "/records/a%2Fb" || request.URL.RawQuery != "view=full%20detail" ||
		request.Header.Get("X-Request-ID") != "request-42" || request.Header.Get("X-Caller-Context") != "preserve-me" {
		t.Fatalf("original request mutated: %s %s?%s", request.Method, request.URL.EscapedPath(), request.URL.RawQuery)
	}
	exact, err := io.ReadAll(request.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(exact) != body {
		t.Fatalf("original body = %q, want %q", exact, body)
	}
	if request.GetBody != nil {
		restored, err := request.GetBody()
		if err != nil {
			t.Fatal(err)
		}
		request.Body = restored
	}
}

func formatAgentR3Requirement(t *testing.T, resourceToken string) string {
	t.Helper()
	header, err := aauth.FormatAuthTokenRequirement(aauth.AuthTokenRequirement{ResourceToken: resourceToken})
	if err != nil {
		t.Fatal(err)
	}
	return header
}
