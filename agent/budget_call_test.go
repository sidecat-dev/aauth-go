package agent_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/agent"
	"gitlab.com/sidecat-dev/aauth-go/budgets"
)

func TestAgentBeginBudgetCallRejectsInconsistentStepUpSemantics(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name      string
		reason    budgets.Reason
		remaining int64
		required  *int64
		cost      *int64
		raw       string
	}{
		{name: "exhausted with a remainder", reason: budgets.ReasonBudgetExhausted, remaining: 1},
		{name: "insufficient with a fitting requirement", reason: budgets.ReasonInsufficientBudget, remaining: 200_000, required: testInt64Pointer(150_000), raw: `remaining=200000, required=150000, unit="USD", decimals=6`},
		{name: "insufficient with a current-request cost", reason: budgets.ReasonInsufficientBudget, remaining: 200_000, required: testInt64Pointer(300_000), cost: testInt64Pointer(1)},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			fixture := newBudgetCallFixture(t)
			formattedFeedback := test.raw
			if formattedFeedback == "" {
				feedback, err := budgets.NewRefusalFeedback(
					fixture.grant, test.remaining, test.required,
				)
				if err != nil {
					t.Fatal(err)
				}
				formattedFeedback, err = budgets.FormatFeedback(feedback)
				if err != nil {
					t.Fatal(err)
				}
			}
			if test.cost != nil {
				formattedFeedback = fmt.Sprintf(
					`cost=%d, remaining=%d, required=%d, unit="USD", decimals=6`,
					*test.cost, test.remaining, *test.required,
				)
			}
			requirement, err := budgets.FormatAuthTokenRequirement(
				aauth.AuthTokenRequirement{ResourceToken: fixture.challenge}, test.reason,
			)
			if err != nil {
				t.Fatal(err)
			}
			body := &trackedBody{Reader: strings.NewReader("refused")}
			applicationCalls := 0
			client := fixture.protocol.newClientWithHTTPClient(t, &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
				if request.URL.String() == fixture.protocol.resourceID+"/.well-known/aauth-resource.json" {
					return fixture.metadata(request), nil
				}
				applicationCalls++
				return &http.Response{
					StatusCode: http.StatusUnauthorized, Status: "401 Unauthorized", Request: request,
					Header: http.Header{
						"Aauth-Requirement": []string{requirement},
						"Aauth-Budget":      []string{formattedFeedback},
					},
					Body: body,
				}, nil
			})})
			request, _ := http.NewRequest(http.MethodPost, fixture.protocol.resourceID+"/records", strings.NewReader("request"))
			_, err = client.BeginBudgetCall(context.Background(), agent.BudgetCall{
				Request: request, AuthToken: fixture.authToken,
			})
			var uncertain *agent.BudgetCallUncertainError
			if !errors.As(err, &uncertain) {
				t.Fatalf("BeginBudgetCall error = %v, want uncertain invalid step-up", err)
			}
			if !body.closed {
				t.Fatal("invalid step-up response body was not closed")
			}
			if applicationCalls != 1 {
				t.Fatalf("application calls = %d, want one and no retry", applicationCalls)
			}
		})
	}
}

func TestAgentBeginBudgetCallRejectsCostOnReasonlessCoreStepUp(t *testing.T) {
	t.Parallel()

	fixture := newBudgetCallFixture(t)
	thumbprint, err := fixture.protocol.agentKey.PublicJWK().Thumbprint()
	if err != nil {
		t.Fatal(err)
	}
	challenge, err := aauth.MintResourceToken(fixture.protocol.resourceKey, aauth.ResourceTokenClaims{
		Issuer: fixture.protocol.resourceID, DWK: aauth.ResourceDiscoveryDocument,
		Audience: fixture.protocol.personServerID, JTI: "reasonless-budget-step-up",
		PersonServer: fixture.protocol.personServerID, Subject: "person-123",
		PresentedJTI: "person-token-current", AgentJKT: thumbprint,
		IssuedAt: fixture.protocol.now.Unix(), ExpiresAt: fixture.protocol.now.Add(5 * time.Minute).Unix(),
		Scope: "records.read",
	})
	if err != nil {
		t.Fatal(err)
	}
	requirement, err := aauth.FormatAuthTokenRequirement(aauth.AuthTokenRequirement{ResourceToken: challenge})
	if err != nil {
		t.Fatal(err)
	}
	feedback, err := budgets.NewSuccessFeedback(fixture.grant, 1, fixture.grant.Amount()-1)
	if err != nil {
		t.Fatal(err)
	}
	formatted, err := budgets.FormatFeedback(feedback)
	if err != nil {
		t.Fatal(err)
	}
	body := &trackedBody{Reader: strings.NewReader("step-up")}
	client := fixture.protocol.newClientWithHTTPClient(t, &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.String() == fixture.protocol.resourceID+"/.well-known/aauth-resource.json" {
			return fixture.metadata(request), nil
		}
		return &http.Response{
			StatusCode: http.StatusUnauthorized, Status: "401 Unauthorized", Request: request,
			Header: http.Header{
				"Aauth-Requirement": []string{requirement},
				"Aauth-Budget":      []string{formatted},
			},
			Body: body,
		}, nil
	})})
	request, _ := http.NewRequest(http.MethodGet, fixture.protocol.resourceID+"/records", nil)
	_, err = client.BeginBudgetCall(context.Background(), agent.BudgetCall{
		Request: request, AuthToken: fixture.authToken,
	})
	var uncertain *agent.BudgetCallUncertainError
	if !errors.As(err, &uncertain) {
		t.Fatalf("reasonless charged step-up error = %v, want uncertain", err)
	}
	if !body.closed {
		t.Fatal("reasonless charged step-up body was not closed")
	}
}

func TestAgentBeginBudgetCallIgnoresCachedBudgetFeedback(t *testing.T) {
	t.Parallel()

	fixture := newBudgetCallFixture(t)
	feedback, err := budgets.NewSuccessFeedback(fixture.grant, 150_000, 250_000)
	if err != nil {
		t.Fatal(err)
	}
	formatted, err := budgets.FormatFeedback(feedback)
	if err != nil {
		t.Fatal(err)
	}
	body := &trackedBody{Reader: strings.NewReader("cached")}
	client := fixture.protocol.newClientWithHTTPClient(t, &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.String() == fixture.protocol.resourceID+"/.well-known/aauth-resource.json" {
			return fixture.metadata(request), nil
		}
		return &http.Response{
			StatusCode: http.StatusOK, Status: "200 OK", Request: request,
			Header: http.Header{"Aauth-Budget": []string{formatted}, "Age": []string{"0"}},
			Body:   body,
		}, nil
	})})
	request, _ := http.NewRequest(http.MethodGet, fixture.protocol.resourceID+"/records", nil)
	result, err := client.BeginBudgetCall(context.Background(), agent.BudgetCall{
		Request: request, AuthToken: fixture.authToken,
	})
	if err != nil {
		t.Fatal(err)
	}
	response, ok := result.Response()
	if !ok || response.Body != body {
		t.Fatalf("cached response = %#v, %t", response, ok)
	}
	if _, ok := result.Feedback(); ok {
		t.Fatal("Age-bearing cached AAuth-Budget was treated as current feedback")
	}
	if _, ok := result.Cost(); ok {
		t.Fatal("Age-bearing cached cost was treated as the current request cost")
	}
	if grant, ok := result.Grant(); !ok || !sameBudget(grant, fixture.grant) {
		t.Fatalf("cached result lost the signed grant: %#v, %t", grant, ok)
	}
	if body.closed {
		t.Fatal("caller-owned cached response body was closed")
	}
	response.Body.Close()
	if !body.closed {
		t.Fatal("caller could not close the cached response body")
	}
}

func TestAgentBeginBudgetCallWithoutFeedbackRemainsUncertain(t *testing.T) {
	for _, status := range []int{http.StatusOK, http.StatusForbidden} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			fixture := newBudgetCallFixture(t)
			protocol := fixture.protocol
			applicationCalls := 0
			client := protocol.newClientWithHTTPClient(t, &http.Client{
				Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
					if request.URL.Path == "/.well-known/aauth-resource.json" {
						return fixture.metadata(request), nil
					}
					applicationCalls++
					return jsonResponse(request, status, map[string]string{"result": "ordinary response"}), nil
				}),
			})
			request, err := http.NewRequest(http.MethodGet, protocol.resourceID+"/records", nil)
			if err != nil {
				t.Fatal(err)
			}
			_, err = client.BeginBudgetCall(context.Background(), agent.BudgetCall{
				Request: request, AuthToken: fixture.authToken,
			})
			var uncertain *agent.BudgetCallUncertainError
			if !errors.As(err, &uncertain) {
				t.Fatalf("missing feedback error = %v, want BudgetCallUncertainError", err)
			}
			if assumed, ok := uncertain.AssumedCost(); !ok || !sameBudget(assumed, fixture.grant) {
				t.Fatalf("assumed cost = %#v, %t, want the full signed grant", assumed, ok)
			}
			if applicationCalls != 1 {
				t.Fatalf("application calls = %d, want one attempt without retry", applicationCalls)
			}
		})
	}
}

type budgetCallFixture struct {
	protocol  *testProtocol
	unit      budgets.Unit
	grant     budgets.Value
	authToken string
	challenge string
}

func newBudgetCallFixture(t *testing.T) budgetCallFixture {
	t.Helper()
	protocol := newTestProtocol(t)
	unit := budgetUnit(t, "USD", 6)
	grant := budgetValue(t, 400_000, unit)
	authToken, err := budgets.MintAuthToken(protocol.personServerKey, aauth.AuthTokenClaims{
		Issuer: protocol.personServerID, DWK: aauth.PersonDiscoveryDocument,
		Audience: protocol.resourceID, JTI: "budget-call-auth-token",
		PersonServer: protocol.personServerID, Subject: "person-123",
		Confirmation: aauth.Confirmation{JWK: protocol.agentKey.PublicJWK()},
		IssuedAt:     protocol.now.Unix(), ExpiresAt: protocol.now.Add(30 * time.Minute).Unix(),
		Scope: "records.read",
	}, grant)
	if err != nil {
		t.Fatal(err)
	}
	thumbprint, err := protocol.agentKey.PublicJWK().Thumbprint()
	if err != nil {
		t.Fatal(err)
	}
	challenge, err := budgets.MintResourceToken(protocol.resourceKey, aauth.ResourceTokenClaims{
		Issuer: protocol.resourceID, DWK: aauth.ResourceDiscoveryDocument,
		Audience: protocol.personServerID, JTI: "budget-call-resource-token",
		PersonServer: protocol.personServerID, Subject: "person-123", PresentedJTI: "person-token-current",
		AgentJKT: thumbprint,
		IssuedAt: protocol.now.Unix(), ExpiresAt: protocol.now.Add(5 * time.Minute).Unix(),
		Scope: "records.read",
	}, grant, nil)
	if err != nil {
		t.Fatal(err)
	}
	return budgetCallFixture{protocol: protocol, unit: unit, grant: grant, authToken: authToken, challenge: challenge}
}

func (fixture budgetCallFixture) metadata(request *http.Request) *http.Response {
	return jsonResponse(request, http.StatusOK, map[string]any{
		"issuer": fixture.protocol.resourceID,
		"budget_units": []map[string]any{{
			"unit": fixture.unit.Name(), "decimals": fixture.unit.Decimals(), "max": 1_000_000,
		}},
	})
}

func testInt64Pointer(value int64) *int64 { return &value }

var _ io.ReadCloser = (*trackedBody)(nil)

// Core Resource Token Claims and Budgets Exhaustion and Step-Up: aud names
// the issuer of the Auth token being replaced, PS or AS according to topology.
func TestBudgetStepUpBindsAudienceToAuthTokenIssuer(t *testing.T) {
	for _, federated := range []bool{false, true} {
		for _, audience := range []string{"issuer", "other role", "unrelated"} {
			t.Run(fmt.Sprintf("federated=%t/%s", federated, audience), func(t *testing.T) {
				fixture := newBudgetCallFixture(t)
				protocol := fixture.protocol
				claims, _, err := budgets.VerifyAuthToken(context.Background(), fixture.authToken, protocol.resolver, protocol.clock)
				if err != nil {
					t.Fatal(err)
				}
				key := protocol.personServerKey
				other := protocol.accessServerID
				if federated {
					claims.Issuer = protocol.accessServerID
					claims.DWK = aauth.AccessDiscoveryDocument
					key = protocol.accessServerKey
					other = protocol.personServerID
				}
				authToken, err := budgets.MintAuthToken(key, claims, fixture.grant)
				if err != nil {
					t.Fatal(err)
				}
				challenge, offer, _, err := budgets.VerifyResourceToken(context.Background(), fixture.challenge, protocol.resolver, protocol.clock)
				if err != nil {
					t.Fatal(err)
				}
				challenge.PresentedJTI = claims.JTI
				challenge.Audience = claims.Issuer
				if audience == "other role" {
					challenge.Audience = other
				}
				if audience == "unrelated" {
					challenge.Audience = "https://other.example"
				}
				compact, err := budgets.MintResourceToken(protocol.resourceKey, challenge, offer, nil)
				if err != nil {
					t.Fatal(err)
				}
				requirement, err := budgets.FormatAuthTokenRequirement(aauth.AuthTokenRequirement{ResourceToken: compact}, budgets.ReasonBudgetExhausted)
				if err != nil {
					t.Fatal(err)
				}
				feedback, err := budgets.NewRefusalFeedback(fixture.grant, 0, nil)
				if err != nil {
					t.Fatal(err)
				}
				formatted, err := budgets.FormatFeedback(feedback)
				if err != nil {
					t.Fatal(err)
				}
				calls := 0
				body := &trackedBody{Reader: strings.NewReader("refusal")}
				client := protocol.newClientWithHTTPClient(t, &http.Client{Transport: roundTripperFunc(func(r *http.Request) (*http.Response, error) {
					if r.URL.Path == "/.well-known/aauth-resource.json" {
						return fixture.metadata(r), nil
					}
					calls++
					return &http.Response{StatusCode: http.StatusUnauthorized, Request: r, Header: http.Header{"Aauth-Requirement": {requirement}, "Aauth-Budget": {formatted}}, Body: body}, nil
				})})
				request, _ := http.NewRequest(http.MethodGet, protocol.resourceID+"/records", nil)
				result, err := client.BeginBudgetCall(context.Background(), agent.BudgetCall{Request: request, AuthToken: authToken})
				if audience == "issuer" {
					if _, ok := result.AuthorizationRequired(); err != nil || !ok {
						t.Fatalf("step-up=%#v error=%v", result, err)
					}
				} else {
					var uncertain *agent.BudgetCallUncertainError
					if !errors.As(err, &uncertain) {
						t.Fatalf("wrong audience accepted: %v", err)
					}
				}
				if calls != 1 || !body.closed {
					t.Fatalf("calls=%d body closed=%t", calls, body.closed)
				}
			})
		}
	}
}
