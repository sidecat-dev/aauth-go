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
	"gitlab.com/sidecat-dev/aauth-go/budgets"
)

func TestAgentCompletesAndVerifiesAProactiveBudgetExchange(t *testing.T) {
	t.Parallel()

	protocol := newTestProtocol(t)
	protocol.resourceAudience = protocol.personServerID
	protocol.authIssuer = protocol.personServerID
	protocol.authDiscoveryDocument = aauth.PersonDiscoveryDocument
	protocol.authSigningKey = protocol.personServerKey
	requestedUnit := budgetUnit(t, "tokens", 0)
	offeredUnit := budgetUnit(t, "USD", 6)
	requested := budgetValue(t, 800_000, requestedUnit)
	offered := budgetValue(t, 600_000, offeredUnit)
	granted := budgetValue(t, 400_000, offeredUnit)
	personToken, err := aauth.MintPersonToken(protocol.personServerKey, aauth.PersonTokenClaims{
		Issuer: protocol.personServerID, DWK: aauth.PersonDiscoveryDocument,
		Audience: protocol.resourceID, Subject: "person-123", Tenant: "tenant-1",
		Confirmation: aauth.Confirmation{JWK: protocol.agentKey.PublicJWK()},
		JTI:          "budget-person-token", IssuedAt: protocol.now.Unix(), ExpiresAt: protocol.now.Add(30 * time.Minute).Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	thumbprint, err := protocol.agentKey.PublicJWK().Thumbprint()
	if err != nil {
		t.Fatal(err)
	}
	var capabilities []string
	client := protocol.newClientWithHTTPClient(t, &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
		switch request.URL.String() {
		case protocol.resourceID + "/.well-known/aauth-resource.json":
			return jsonResponse(request, http.StatusOK, map[string]any{
				"issuer": protocol.resourceID, "authorization_endpoint": protocol.authorizationEndpoint,
				"scope_descriptions": map[string]string{"records.read": "Read records"},
				"budget_units": []map[string]any{
					{"unit": "tokens", "decimals": 0, "max": 2_000_000},
					{"unit": "USD", "decimals": 6, "max": 1_000_000},
				},
			}), nil
		case protocol.authorizationEndpoint:
			verified := verifyProofWithComponents(
				t, request, protocol.resolver, protocol.clock, aauth.PersonTokenType,
				expectedAuthorizationComponents(nil),
			)
			person, verifyErr := verified.PersonClaims()
			if verifyErr != nil {
				t.Fatal(verifyErr)
			}
			var input struct {
				Scope  string          `json:"scope"`
				Budget json.RawMessage `json:"budget"`
			}
			decodeRequest(t, request, &input)
			got, parseErr := budgets.ParseValueJSON(input.Budget)
			if parseErr != nil || !sameBudget(got, requested) || input.Scope != "records.read" {
				t.Fatalf("authorization Budget = %#v, %v; scope=%q", got, parseErr, input.Scope)
			}
			compact, mintErr := budgets.MintResourceToken(protocol.resourceKey, aauth.ResourceTokenClaims{
				Issuer: protocol.resourceID, DWK: aauth.ResourceDiscoveryDocument,
				Audience: protocol.personServerID, JTI: "budget-resource-token",
				PersonServer: protocol.personServerID, Subject: person.Subject, PresentedJTI: person.JTI,
				AgentJKT: thumbprint, IssuedAt: protocol.now.Unix(), ExpiresAt: protocol.now.Add(5 * time.Minute).Unix(),
				Scope: "records.read", Tenant: person.Tenant,
			}, offered, nil)
			if mintErr != nil {
				t.Fatal(mintErr)
			}
			return jsonResponse(request, http.StatusOK, map[string]string{"resource_token": compact}), nil
		case protocol.personServerID + "/.well-known/aauth-person.json":
			return jsonResponse(request, http.StatusOK, map[string]string{
				"issuer": protocol.personServerID, "person_token_endpoint": protocol.personTokenEndpoint,
				"auth_token_endpoint": protocol.authTokenEndpoint,
			}), nil
		case protocol.authTokenEndpoint:
			var input struct {
				ResourceToken  string   `json:"resource_token"`
				PresentedToken string   `json:"presented_token"`
				Capabilities   []string `json:"capabilities"`
			}
			decodeRequest(t, request, &input)
			if input.PresentedToken != personToken {
				t.Fatal("exchange changed the presented token bytes")
			}
			capabilities = append([]string(nil), input.Capabilities...)
			resourceClaims, resourceBudget, _, verifyErr := budgets.VerifyResourceToken(
				context.Background(), input.ResourceToken, protocol.resolver, protocol.clock,
			)
			if verifyErr != nil || !sameBudget(resourceBudget, offered) {
				t.Fatalf("exchange Resource token = %#v, %#v, %v", resourceClaims, resourceBudget, verifyErr)
			}
			compact, mintErr := budgets.MintAuthToken(protocol.personServerKey, aauth.AuthTokenClaims{
				Issuer: protocol.personServerID, DWK: aauth.PersonDiscoveryDocument,
				Audience: protocol.resourceID, JTI: "budget-auth-token",
				PersonServer: protocol.personServerID, Subject: resourceClaims.Subject,
				Confirmation: aauth.Confirmation{JWK: protocol.agentKey.PublicJWK()},
				IssuedAt:     protocol.now.Unix(), ExpiresAt: protocol.now.Add(30 * time.Minute).Unix(),
				Scope: resourceClaims.Scope, Tenant: resourceClaims.Tenant,
			}, granted)
			if mintErr != nil {
				t.Fatal(mintErr)
			}
			return jsonResponse(request, http.StatusOK, map[string]any{
				"auth_token": compact, "expires_in": int64((30 * time.Minute) / time.Second),
			}), nil
		default:
			t.Fatalf("unexpected request: %s %s", request.Method, request.URL)
			return nil, nil
		}
	})})

	resourceToken, err := client.Authorize(context.Background(), agent.AuthorizeRequest{
		Resource: protocol.resourceID, PersonToken: personToken,
		Scopes: []string{"records.read"}, Budget: &requested,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, gotOffer, _, err := budgets.VerifyResourceToken(context.Background(), resourceToken, protocol.resolver, protocol.clock)
	if err != nil || !sameBudget(gotOffer, offered) {
		t.Fatalf("verified offer = %#v, %v", gotOffer, err)
	}
	authToken, err := client.Exchange(context.Background(), agent.ExchangeRequest{
		PersonServer: protocol.personServerID, ResourceToken: resourceToken, PresentedToken: personToken,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, gotGrant, err := budgets.VerifyAuthToken(context.Background(), authToken, protocol.resolver, protocol.clock)
	if err != nil || !sameBudget(gotGrant, granted) {
		t.Fatalf("verified grant = %#v, %v", gotGrant, err)
	}
	if len(capabilities) != 1 || capabilities[0] != "budget" {
		t.Fatalf("exchange capabilities = %v, want [budget]", capabilities)
	}
}

func TestAgentRefusesAnAuthTokenThatBroadensTheResourceBudget(t *testing.T) {
	t.Parallel()

	protocol := newTestProtocol(t)
	protocol.resourceAudience = protocol.personServerID
	unit := budgetUnit(t, "USD", 6)
	offered := budgetValue(t, 400_000, unit)
	broadened := budgetValue(t, 400_001, unit)
	thumbprint, _ := protocol.agentKey.PublicJWK().Thumbprint()
	resourceClaims := aauth.ResourceTokenClaims{
		Issuer: protocol.resourceID, DWK: aauth.ResourceDiscoveryDocument,
		Audience: protocol.personServerID, JTI: "budget-resource-broadened",
		PersonServer: protocol.personServerID, Subject: "person-123", PresentedJTI: "person-token-1",
		AgentJKT: thumbprint, IssuedAt: protocol.now.Unix(), ExpiresAt: protocol.now.Add(5 * time.Minute).Unix(),
		Scope: "records.read",
	}
	resourceToken, err := budgets.MintResourceToken(protocol.resourceKey, resourceClaims, offered, nil)
	if err != nil {
		t.Fatal(err)
	}
	personToken := protocol.presentedPersonToken(t, resourceClaims, protocol.agentKey.PublicJWK())
	requests := 0
	client := protocol.newClientWithHTTPClient(t, &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
		requests++
		if request.URL.String() == protocol.personServerID+"/.well-known/aauth-person.json" {
			return jsonResponse(request, http.StatusOK, map[string]string{
				"issuer": protocol.personServerID, "person_token_endpoint": protocol.personTokenEndpoint,
				"auth_token_endpoint": protocol.authTokenEndpoint,
			}), nil
		}
		compact, mintErr := budgets.MintAuthToken(protocol.personServerKey, aauth.AuthTokenClaims{
			Issuer: protocol.personServerID, DWK: aauth.PersonDiscoveryDocument,
			Audience: protocol.resourceID, JTI: "budget-auth-broadened",
			PersonServer: protocol.personServerID, Subject: "person-123",
			Confirmation: aauth.Confirmation{JWK: protocol.agentKey.PublicJWK()},
			IssuedAt:     protocol.now.Unix(), ExpiresAt: protocol.now.Add(30 * time.Minute).Unix(),
			Scope: "records.read",
		}, broadened)
		if mintErr != nil {
			t.Fatal(mintErr)
		}
		return jsonResponse(request, http.StatusOK, map[string]any{
			"auth_token": compact, "expires_in": int64((30 * time.Minute) / time.Second),
		}), nil
	})})

	if _, err := client.Exchange(context.Background(), agent.ExchangeRequest{
		PersonServer: protocol.personServerID, ResourceToken: resourceToken, PresentedToken: personToken,
	}); err == nil || !strings.Contains(err.Error(), "narrow") {
		t.Fatalf("Exchange error = %v, want Budget narrowing refusal", err)
	}
	if requests != 2 {
		t.Fatalf("network requests = %d, want metadata plus exchange", requests)
	}
}

func TestAgentAcceptsAnAuthTokenThatOmitsAnOfferedBudget(t *testing.T) {
	t.Parallel()

	protocol := newTestProtocol(t)
	protocol.resourceAudience = protocol.personServerID
	unit := budgetUnit(t, "USD", 6)
	offered := budgetValue(t, 400_000, unit)
	thumbprint, _ := protocol.agentKey.PublicJWK().Thumbprint()
	resourceClaims := aauth.ResourceTokenClaims{
		Issuer: protocol.resourceID, DWK: aauth.ResourceDiscoveryDocument,
		Audience: protocol.personServerID, JTI: "budget-resource-omitted-grant",
		PersonServer: protocol.personServerID, Subject: "person-123", PresentedJTI: "person-token-1",
		AgentJKT: thumbprint, IssuedAt: protocol.now.Unix(), ExpiresAt: protocol.now.Add(5 * time.Minute).Unix(),
		Scope: "records.read",
	}
	resourceToken, err := budgets.MintResourceToken(protocol.resourceKey, resourceClaims, offered, nil)
	if err != nil {
		t.Fatal(err)
	}
	personToken := protocol.presentedPersonToken(t, resourceClaims, protocol.agentKey.PublicJWK())
	client := protocol.newClientWithHTTPClient(t, &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.String() == protocol.personServerID+"/.well-known/aauth-person.json" {
			return jsonResponse(request, http.StatusOK, map[string]string{
				"issuer": protocol.personServerID, "person_token_endpoint": protocol.personTokenEndpoint,
				"auth_token_endpoint": protocol.authTokenEndpoint,
			}), nil
		}
		compact, mintErr := aauth.MintAuthToken(protocol.personServerKey, aauth.AuthTokenClaims{
			Issuer: protocol.personServerID, DWK: aauth.PersonDiscoveryDocument,
			Audience: protocol.resourceID, JTI: "budget-auth-omitted-grant",
			PersonServer: protocol.personServerID, Subject: "person-123",
			Confirmation: aauth.Confirmation{JWK: protocol.agentKey.PublicJWK()},
			IssuedAt:     protocol.now.Unix(), ExpiresAt: protocol.now.Add(30 * time.Minute).Unix(),
			Scope: "records.read",
		})
		if mintErr != nil {
			t.Fatal(mintErr)
		}
		return jsonResponse(request, http.StatusOK, map[string]any{
			"auth_token": compact, "expires_in": int64((30 * time.Minute) / time.Second),
		}), nil
	})})

	authToken, err := client.Exchange(context.Background(), agent.ExchangeRequest{
		PersonServer: protocol.personServerID, ResourceToken: resourceToken, PresentedToken: personToken,
	})
	if err != nil {
		t.Fatal(err)
	}
	carries, err := budgets.TokenCarriesClaims(authToken)
	if err != nil || carries {
		t.Fatalf("omitted grant carries a budget=%t err=%v", carries, err)
	}
}

func TestAgentDoBudgetReturnsValidatedSuccessFeedback(t *testing.T) {
	t.Parallel()

	protocol := newTestProtocol(t)
	unit := budgetUnit(t, "USD", 6)
	grant := budgetValue(t, 400_000, unit)
	authToken, err := budgets.MintAuthToken(protocol.personServerKey, aauth.AuthTokenClaims{
		Issuer: protocol.personServerID, DWK: aauth.PersonDiscoveryDocument,
		Audience: protocol.resourceID, JTI: "budget-auth-use",
		PersonServer: protocol.personServerID, Subject: "person-123",
		Confirmation: aauth.Confirmation{JWK: protocol.agentKey.PublicJWK()},
		IssuedAt:     protocol.now.Unix(), ExpiresAt: protocol.now.Add(30 * time.Minute).Unix(),
		Scope: "records.read",
	}, grant)
	if err != nil {
		t.Fatal(err)
	}
	feedback, err := budgets.NewSuccessFeedback(grant, 150_000, 250_000)
	if err != nil {
		t.Fatal(err)
	}
	formatted, err := budgets.FormatFeedback(feedback)
	if err != nil {
		t.Fatal(err)
	}
	applicationCalls := 0
	client := protocol.newClientWithHTTPClient(t, &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.String() == protocol.resourceID+"/.well-known/aauth-resource.json" {
			return jsonResponse(request, http.StatusOK, map[string]any{"issuer": protocol.resourceID}), nil
		}
		applicationCalls++
		response := jsonResponse(request, http.StatusOK, map[string]string{"result": "ok"})
		response.Header.Set("AAuth-Budget", formatted)
		return response, nil
	})})
	request, _ := http.NewRequest(http.MethodPost, protocol.resourceID+"/records", strings.NewReader(`{"query":"current"}`))
	request.Header.Set("Content-Type", "application/json")
	result, err := client.BeginBudgetCall(context.Background(), agent.BudgetCall{
		Request: request, AuthToken: authToken,
	})
	if err != nil {
		t.Fatal(err)
	}
	response, ok := result.Response()
	if !ok {
		t.Fatal("DoBudget result omitted the application response")
	}
	defer response.Body.Close()
	if _, err := io.ReadAll(response.Body); err != nil {
		t.Fatal(err)
	}
	parsed, ok := result.Feedback()
	if !ok || parsed.Remaining() != 250_000 {
		t.Fatalf("Budget feedback = %#v, %t", parsed, ok)
	}
	cost, reported := result.Cost()
	if cost != 150_000 || !reported {
		t.Fatalf("Budget cost = %d, reported=%t, want 150000, true", cost, reported)
	}
	gotGrant, ok := result.Grant()
	if !ok || !sameBudget(gotGrant, grant) {
		t.Fatalf("Budget grant = %#v, %t", gotGrant, ok)
	}
	if applicationCalls != 1 {
		t.Fatalf("application calls = %d, want 1", applicationCalls)
	}
}

func TestAgentAcceptsReservedBudgetFeedbackWithoutATrailer(t *testing.T) {
	t.Parallel()

	protocol := newTestProtocol(t)
	unit := budgetUnit(t, "USD", 6)
	grant := budgetValue(t, 2_000_000, unit)
	authToken, err := budgets.MintAuthToken(protocol.personServerKey, aauth.AuthTokenClaims{
		Issuer: protocol.personServerID, DWK: aauth.PersonDiscoveryDocument,
		Audience: protocol.resourceID, JTI: "budget-auth-reserved",
		PersonServer: protocol.personServerID, Subject: "person-123",
		Confirmation: aauth.Confirmation{JWK: protocol.agentKey.PublicJWK()},
		IssuedAt:     protocol.now.Unix(), ExpiresAt: protocol.now.Add(30 * time.Minute).Unix(),
		Scope: "records.read",
	}, grant)
	if err != nil {
		t.Fatal(err)
	}
	feedback, err := budgets.NewReservedFeedback(grant, 1_568_800, 431_200)
	if err != nil {
		t.Fatal(err)
	}
	formatted, err := budgets.FormatFeedback(feedback)
	if err != nil {
		t.Fatal(err)
	}
	client := protocol.newClientWithHTTPClient(t, &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.String() == protocol.resourceID+"/.well-known/aauth-resource.json" {
			return jsonResponse(request, http.StatusOK, map[string]any{"issuer": protocol.resourceID}), nil
		}
		response := jsonResponse(request, http.StatusOK, map[string]string{"result": "ok"})
		response.Header.Set("Trailer", "AAuth-Budget")
		response.Header.Set("AAuth-Budget", formatted)
		return response, nil
	})})
	request, _ := http.NewRequest(http.MethodPost, protocol.resourceID+"/records", strings.NewReader(`{"query":"current"}`))
	request.Header.Set("Content-Type", "application/json")
	result, err := client.BeginBudgetCall(context.Background(), agent.BudgetCall{
		Request: request, AuthToken: authToken,
	})
	if err != nil {
		t.Fatal(err)
	}
	response, ok := result.Response()
	if !ok {
		t.Fatal("reserved Budget response was not complete")
	}
	defer response.Body.Close()
	if cost, reported := result.Cost(); reported {
		t.Fatalf("exact cost = %d", cost)
	}
	assumed, ok := result.AssumedCost()
	if !ok || assumed != 431_200 {
		t.Fatalf("assumed cost = %d, %t", assumed, ok)
	}
	response.Trailer = make(http.Header)
	response.Trailer.Set("AAuth-Budget", "cost=221200")
	if err := result.ApplyTrailer(); err != nil {
		t.Fatal(err)
	}
	cost, reported := result.Cost()
	if !reported || cost != 221_200 {
		t.Fatalf("settled cost = %d, %t", cost, reported)
	}
}

func TestAgentDoBudgetReturnsTypedAuthorizationRequirementWithoutRetry(t *testing.T) {
	t.Parallel()

	protocol := newTestProtocol(t)
	unit := budgetUnit(t, "USD", 6)
	grant := budgetValue(t, 400_000, unit)
	authToken, err := budgets.MintAuthToken(protocol.personServerKey, aauth.AuthTokenClaims{
		Issuer: protocol.personServerID, DWK: aauth.PersonDiscoveryDocument,
		Audience: protocol.resourceID, JTI: "budget-auth-step-up",
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
		Audience: protocol.personServerID, JTI: "budget-step-up-resource",
		PersonServer: protocol.personServerID, Subject: "person-123", PresentedJTI: "budget-auth-step-up",
		AgentJKT: thumbprint,
		IssuedAt: protocol.now.Unix(), ExpiresAt: protocol.now.Add(5 * time.Minute).Unix(),
		Scope: "records.read",
	}, grant, nil)
	if err != nil {
		t.Fatal(err)
	}
	requirement, err := budgets.FormatAuthTokenRequirement(
		aauth.AuthTokenRequirement{ResourceToken: challenge}, budgets.ReasonInsufficientBudget,
	)
	if err != nil {
		t.Fatal(err)
	}
	required := int64(300_000)
	feedback, err := budgets.NewRefusalFeedback(grant, 200_000, &required)
	if err != nil {
		t.Fatal(err)
	}
	formatted, err := budgets.FormatFeedback(feedback)
	if err != nil {
		t.Fatal(err)
	}
	applicationCalls := 0
	body := &trackedBody{Reader: strings.NewReader("refused")}
	client := protocol.newClientWithHTTPClient(t, &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.String() == protocol.resourceID+"/.well-known/aauth-resource.json" {
			return jsonResponse(request, http.StatusOK, map[string]any{
				"issuer":       protocol.resourceID,
				"budget_units": []map[string]any{{"unit": "USD", "decimals": 6, "max": 1_000_000}},
			}), nil
		}
		applicationCalls++
		return &http.Response{StatusCode: http.StatusUnauthorized, Status: "401 Unauthorized", Request: request,
			Header: http.Header{"Aauth-Requirement": []string{requirement}, "Aauth-Budget": []string{formatted}}, Body: body}, nil
	})})
	request, _ := http.NewRequest(http.MethodPost, protocol.resourceID+"/records", strings.NewReader(`{"query":"current"}`))
	result, err := client.BeginBudgetCall(context.Background(), agent.BudgetCall{
		Request: request, AuthToken: authToken,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := result.Response(); ok {
		t.Fatal("Budget refusal returned an application response")
	}
	stepUp, ok := result.AuthorizationRequired()
	if !ok {
		t.Fatal("Budget refusal omitted the verified authorization requirement")
	}
	if stepUp.ResourceToken() != challenge {
		t.Fatalf("step-up Resource token = %q, want challenge", stepUp.ResourceToken())
	}
	if reason, ok := stepUp.Reason(); !ok || reason != budgets.ReasonInsufficientBudget {
		t.Fatalf("step-up reason = %q, %t", reason, ok)
	}
	gotFeedback, ok := result.Feedback()
	if !ok || gotFeedback.Remaining() != 200_000 {
		t.Fatalf("step-up feedback = %#v, %t", gotFeedback, ok)
	}
	if !body.closed {
		t.Fatal("DoBudget did not close the consumed refusal response")
	}
	if applicationCalls != 1 {
		t.Fatalf("application calls = %d, want one call and no automatic retry", applicationCalls)
	}
}

func TestAgentDoBudgetMarksOnlyAttemptedCallsUncertain(t *testing.T) {
	t.Parallel()

	protocol := newTestProtocol(t)
	unit := budgetUnit(t, "USD", 6)
	grant := budgetValue(t, 400_000, unit)
	authToken, err := budgets.MintAuthToken(protocol.personServerKey, aauth.AuthTokenClaims{
		Issuer: protocol.personServerID, DWK: aauth.PersonDiscoveryDocument,
		Audience: protocol.resourceID, JTI: "budget-auth-uncertain",
		PersonServer: protocol.personServerID, Subject: "person-123",
		Confirmation: aauth.Confirmation{JWK: protocol.agentKey.PublicJWK()},
		IssuedAt:     protocol.now.Unix(), ExpiresAt: protocol.now.Add(30 * time.Minute).Unix(),
		Scope: "records.read",
	}, grant)
	if err != nil {
		t.Fatal(err)
	}
	lost := errors.New("connection lost after request transmission")
	applicationCalls := 0
	client := protocol.newClientWithHTTPClient(t, &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.String() == protocol.resourceID+"/.well-known/aauth-resource.json" {
			return jsonResponse(request, http.StatusOK, map[string]any{"issuer": protocol.resourceID}), nil
		}
		applicationCalls++
		return nil, lost
	})})
	request, _ := http.NewRequest(http.MethodPost, protocol.resourceID+"/records", strings.NewReader(`{"query":"current"}`))
	_, err = client.BeginBudgetCall(context.Background(), agent.BudgetCall{
		Request: request, AuthToken: authToken,
	})
	var uncertain *agent.BudgetCallUncertainError
	if !errors.As(err, &uncertain) || !errors.Is(err, lost) {
		t.Fatalf("DoBudget error = %v, want uncertain error wrapping transport failure", err)
	}
	if assumed, ok := uncertain.AssumedCost(); !ok || !sameBudget(assumed, grant) {
		t.Fatalf("assumed cost = %#v, %t, want full signed grant %#v", assumed, ok, grant)
	}
	if got, ok := uncertain.Grant(); !ok || !sameBudget(got, grant) {
		t.Fatalf("uncertain grant = %#v, %t", got, ok)
	}
	if applicationCalls != 1 {
		t.Fatalf("application calls = %d, want 1", applicationCalls)
	}

	preflightRequest, _ := http.NewRequest(http.MethodGet, protocol.resourceID+"/records", nil)
	_, err = client.BeginBudgetCall(context.Background(), agent.BudgetCall{
		Request: preflightRequest, AuthToken: "not-a-token",
	})
	if errors.As(err, &uncertain) {
		t.Fatalf("preflight failure was marked uncertain: %v", err)
	}
	if applicationCalls != 1 {
		t.Fatalf("preflight failure made an application call; calls=%d", applicationCalls)
	}
}

func TestAgentOrdinaryDoRefusesBudgetTokenBeforeNetworkUse(t *testing.T) {
	t.Parallel()

	protocol := newTestProtocol(t)
	unit := budgetUnit(t, "USD", 6)
	grant := budgetValue(t, 1, unit)
	authToken, err := budgets.MintAuthToken(protocol.personServerKey, aauth.AuthTokenClaims{
		Issuer: protocol.personServerID, DWK: aauth.PersonDiscoveryDocument,
		Audience: protocol.resourceID, JTI: "budget-auth-wrong-call-surface",
		PersonServer: protocol.personServerID, Subject: "person-123",
		Confirmation: aauth.Confirmation{JWK: protocol.agentKey.PublicJWK()},
		IssuedAt:     protocol.now.Unix(), ExpiresAt: protocol.now.Add(30 * time.Minute).Unix(), Scope: "records.read",
	}, grant)
	if err != nil {
		t.Fatal(err)
	}
	networkCalls := 0
	client := protocol.newClientWithHTTPClient(t, &http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
		networkCalls++
		return nil, errors.New("network must not be used")
	})})
	request, _ := http.NewRequest(http.MethodGet, protocol.resourceID+"/records", nil)
	if _, err := client.Do(context.Background(), agent.Call{Request: request, AuthToken: authToken}); err == nil ||
		!strings.Contains(err.Error(), "BeginBudgetCall") {
		t.Fatalf("Do error = %v, want BeginBudgetCall guidance", err)
	}
	if networkCalls != 0 {
		t.Fatalf("ordinary Do made %d network calls for a Budget token", networkCalls)
	}
}

func TestAgentUsesAccountBoundBudgetOnce(t *testing.T) {
	t.Parallel()

	fixture := newBudgetCallFixture(t)
	account := "primary"
	accountToken, err := budgets.MintAuthToken(fixture.protocol.personServerKey, aauth.AuthTokenClaims{
		Issuer: fixture.protocol.personServerID, DWK: aauth.PersonDiscoveryDocument,
		Audience: fixture.protocol.resourceID, JTI: "account-budget-auth",
		PersonServer: fixture.protocol.personServerID, Subject: "person-123",
		Confirmation: aauth.Confirmation{JWK: fixture.protocol.agentKey.PublicJWK()},
		IssuedAt:     fixture.protocol.now.Unix(), ExpiresAt: fixture.protocol.now.Add(30 * time.Minute).Unix(),
		Scope: "records.read", Account: &account,
	}, fixture.grant)
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
	applicationCalls := 0
	client := fixture.protocol.newClientWithHTTPClient(t, &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.String() == fixture.protocol.resourceID+"/.well-known/aauth-resource.json" {
			return fixture.metadata(request), nil
		}
		applicationCalls++
		return &http.Response{
			StatusCode: http.StatusNoContent, Status: "204 No Content", Request: request,
			Header: http.Header{"Aauth-Budget": []string{formatted}}, Body: http.NoBody,
		}, nil
	})})
	request, _ := http.NewRequest(http.MethodGet, fixture.protocol.resourceID+"/records", nil)
	result, err := client.BeginBudgetCall(context.Background(), agent.BudgetCall{
		Request: request, AuthToken: accountToken,
	})
	response, ok := result.Response()
	if err != nil || !ok || response.StatusCode != http.StatusNoContent {
		t.Fatalf("account-bound Budget result = %#v, %v", result, err)
	}
	if applicationCalls != 1 {
		t.Fatalf("account-bound Budget application calls = %d, want 1", applicationCalls)
	}
}

func TestOptionalBudgetMetadataDoesNotBreakOrdinaryCoreUse(t *testing.T) {
	t.Parallel()

	protocol := newTestProtocol(t)
	authToken, err := aauth.MintAuthToken(protocol.personServerKey, aauth.AuthTokenClaims{
		Issuer: protocol.personServerID, DWK: aauth.PersonDiscoveryDocument,
		Audience: protocol.resourceID, JTI: "ordinary-auth-with-unusable-budget-metadata",
		PersonServer: protocol.personServerID, Subject: "person-123",
		Confirmation: aauth.Confirmation{JWK: protocol.agentKey.PublicJWK()},
		IssuedAt:     protocol.now.Unix(), ExpiresAt: protocol.now.Add(30 * time.Minute).Unix(),
		Scope: "records.read",
	})
	if err != nil {
		t.Fatal(err)
	}
	applicationCalls := 0
	client := protocol.newClientWithHTTPClient(t, &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.String() == protocol.resourceID+"/.well-known/aauth-resource.json" {
			return jsonResponse(request, http.StatusOK, map[string]any{
				"issuer": protocol.resourceID,
				"budget_units": []map[string]any{{
					"unit": "USD", "decimals": 6, "max": -1,
				}},
			}), nil
		}
		applicationCalls++
		return jsonResponse(request, http.StatusOK, map[string]bool{"ok": true}), nil
	})})
	request, _ := http.NewRequest(http.MethodGet, protocol.resourceID+"/records", nil)
	response, err := client.Do(context.Background(), agent.Call{Request: request, AuthToken: authToken})
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if applicationCalls != 1 {
		t.Fatalf("application calls = %d, want 1", applicationCalls)
	}
}

func budgetUnit(t *testing.T, name string, decimals int64) budgets.Unit {
	t.Helper()
	unit, err := budgets.NewUnit(name, decimals)
	if err != nil {
		t.Fatal(err)
	}
	return unit
}

func budgetValue(t *testing.T, amount int64, unit budgets.Unit) budgets.Value {
	t.Helper()
	value, err := budgets.NewValue(amount, unit)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func sameBudget(left, right budgets.Value) bool {
	return left.Amount() == right.Amount() && left.Unit().Equal(right.Unit())
}
