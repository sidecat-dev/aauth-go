package agent_test

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/agent"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

// Protocol -11 (28e8258), Presenting a Revoked Token: a revoked Auth
// token can be accompanied by a person-token requirement. Other signature
// failures and other token types must not acquire that recovery meaning.
func TestAuthTokenCallsPreserveRevocationRequirement(t *testing.T) {
	t.Parallel()

	for _, method := range []string{"Do", "BeginBudgetCall", "CallAsAgent", "Begin"} {
		for _, test := range []struct {
			name        string
			signature   string
			requirement string
			want        bool
		}{
			{"person token", "revoked_jwt", "requirement=person-token", true},
			{"additive parameter", "revoked_jwt", "requirement=person-token;extension=?1", true},
			{"absent", "revoked_jwt", "", false},
			{"malformed", "revoked_jwt", `requirement="person-token"`, false},
			{"auth token", "revoked_jwt", `requirement=auth-token;resource-token="untrusted"`, false},
			{"unknown", "revoked_jwt", "requirement=future-extension", false},
			{"expired", "expired_jwt", "requirement=person-token", false},
			{"invalid signature", "invalid_signature", "requirement=person-token", false},
		} {
			t.Run(method+"/"+test.name, func(t *testing.T) {
				t.Parallel()
				fixture := newBudgetCallFixture(t)
				protocol := fixture.protocol
				authToken := protocol.issueAuthToken(t, protocol.newClient(t))
				personToken := mintBeginPersonToken(t, protocol, nil)
				body := &trackedBody{Reader: strings.NewReader(`{"error":"deceptive_body"}`)}
				calls := 0
				client := protocol.newClientWithHTTPClient(t, &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
					if request.URL.Path == "/.well-known/aauth-resource.json" {
						return fixture.metadata(request), nil
					}
					calls++
					header := make(http.Header)
					header.Set("Signature-Error", "error="+test.signature)
					header.Set("Content-Type", "application/problem+json")
					if test.requirement != "" {
						header.Set("AAuth-Requirement", test.requirement)
					}
					return &http.Response{
						StatusCode: http.StatusUnauthorized, Header: header,
						Body: body, Request: request,
					}, nil
				})})
				request, err := http.NewRequest(http.MethodGet, protocol.resourceID+"/records", nil)
				if err != nil {
					t.Fatal(err)
				}
				switch method {
				case "Do":
					_, err = client.Do(context.Background(), agent.Call{Request: request, AuthToken: authToken})
				case "BeginBudgetCall":
					_, err = client.BeginBudgetCall(context.Background(), agent.BudgetCall{Request: request, AuthToken: fixture.authToken})
				case "CallAsAgent":
					_, err = client.CallAsAgentWithComponents(context.Background(), request, nil)
				case "Begin":
					_, err = client.Begin(context.Background(), agent.InitialCall{Request: request, PersonToken: personToken})
				}
				var signatureFailure *signaturekey.Error
				if !errors.As(err, &signatureFailure) || string(signatureFailure.Code) != test.signature {
					t.Fatalf("error = %v, want Signature-Error %s", err, test.signature)
				}
				var recovery interface{ Requirement() aauth.Requirement }
				got := errors.As(err, &recovery)
				want := test.want && (method == "Do" || method == "BeginBudgetCall")
				if got != want || (got && recovery.Requirement() != aauth.RequirementPersonToken) {
					t.Fatalf("recovery = %v, want %v; error = %v", got, want, err)
				}
				var problem *aauth.ProblemError
				if errors.As(err, &problem) {
					t.Fatalf("body overrode Signature-Error: %#v", problem)
				}
				if calls != 1 || !body.closed {
					t.Fatalf("calls = %d, body closed = %v; want one call and closed body", calls, body.closed)
				}
			})
		}
	}
}

func TestR3CallsPreserveRevocationRequirement(t *testing.T) {
	t.Parallel()

	for _, method := range []string{"BeginR3Call", "RetryR3Call", "PollR3Call"} {
		t.Run(method, func(t *testing.T) {
			t.Parallel()
			fixture := newAgentR3StepUpFixture(t)
			const body = `{"record":"alpha","enabled":true}`
			proposalToken, reference, proposal := fixture.proposalResourceToken(t, "revoked-proposal")
			completionToken := fixture.perCallAuthToken(t, "revoked-completion", reference, proposal)
			responseBody := &trackedBody{Reader: strings.NewReader("revoked")}
			calls := 0
			client := fixture.newClientWithHTTPClient(t, &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
				calls++
				header := make(http.Header)
				if calls == 1 && method != "BeginR3Call" {
					fixture.verifyClassCall(t, request, body)
					header.Set("AAuth-Requirement", formatAgentR3Requirement(t, proposalToken))
					header.Set("Cache-Control", "private, no-store")
					response := &http.Response{
						StatusCode: http.StatusUnauthorized, Header: header, Request: request,
						Body: http.NoBody,
					}
					if method == "PollR3Call" {
						response.StatusCode = http.StatusAccepted
						header.Set("Location", "/r3/pending/revoked")
						header.Set("Retry-After", "0")
						header.Set("Content-Type", "application/json")
						response.Body = &trackedBody{Reader: strings.NewReader(`{"status":"pending"}`)}
					}
					return response, nil
				}
				switch method {
				case "BeginR3Call":
					fixture.verifyClassCall(t, request, body)
				case "RetryR3Call":
					fixture.verifyCompletionCall(t, request, completionToken, body)
				case "PollR3Call":
					fixture.verifyProofToken(t, request, completionToken, nil)
				}
				header.Set("Signature-Error", "error=revoked_jwt")
				header.Set("AAuth-Requirement", "requirement=person-token")
				return &http.Response{
					StatusCode: http.StatusUnauthorized, Header: header,
					Request: request, Body: responseBody,
				}, nil
			})})
			result, err := client.BeginR3Call(context.Background(), agent.R3Call{
				Request: fixture.newRequest(t, body), ClassAuthToken: fixture.classAuthToken,
				Operation: fixture.operation, AdditionalSignatureComponents: fixture.components,
			})
			if method != "BeginR3Call" {
				if err != nil {
					t.Fatal(err)
				}
				switch method {
				case "RetryR3Call":
					retry, ok := result.AuthorizationRequired()
					if !ok {
						t.Fatal("BeginR3Call did not return authorization requirement")
					}
					_, err = client.RetryR3Call(context.Background(), agent.R3Retry{
						Authorization: retry, AuthToken: completionToken,
					})
				case "PollR3Call":
					pending, ok := result.Pending()
					if !ok {
						t.Fatal("BeginR3Call did not return pending call")
					}
					_, err = client.PollR3Call(context.Background(), agent.R3Poll{
						Pending: pending, AuthToken: completionToken,
					})
				}
			}
			assertReauthorizationRequired(t, err)
			wantCalls := 2
			if method == "BeginR3Call" {
				wantCalls = 1
			}
			if calls != wantCalls || !responseBody.closed {
				t.Fatalf("calls = %d, body closed = %t; want %d calls and closed body", calls, responseBody.closed, wantCalls)
			}
		})
	}
}

func assertReauthorizationRequired(t *testing.T, err error) {
	t.Helper()
	var recovery *agent.ReauthorizationRequiredError
	if !errors.As(err, &recovery) || recovery.Requirement() != aauth.RequirementPersonToken {
		t.Fatalf("reauthorization requirement missing: %v", err)
	}
	var signatureFailure *signaturekey.Error
	if !errors.As(err, &signatureFailure) || signatureFailure.Code != signaturekey.ErrorRevokedJWT {
		t.Fatalf("revoked_jwt missing: %v", err)
	}
}
