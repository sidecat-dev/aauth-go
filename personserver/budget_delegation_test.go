package personserver

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/budgets"
)

var errFederatedBudgetCalled = errors.New("federated budget request reached the access server")
var errUnexpectedBudgetResource = errors.New("unexpected budget resource")

func TestDirectPSSizesEachSubagentBudgetFromThatTokensOffer(t *testing.T) {
	t.Parallel()

	p := newSubagentPersonServerProtocol(t)
	offer := delegationValue(t, 5_000_000)
	grant := delegationValue(t, 2_000_000)
	var offers []int64
	ids := []string{"delegated-budget-person", "delegated-budget-auth-1", "delegated-budget-auth-2"}
	server, err := NewPSAuthorization(PSAuthorizationConfig{
		Issuer: "https://ps.example", SigningKey: p.personKey, KeyResolver: p.resolver,
		Clock: p.clock, Tokens: p.store,
		NewID: func() string {
			id := ids[0]
			ids = ids[1:]
			return id
		},
		BindPerson: p.policyPerson,
		Authorize: func(_ context.Context, request AuthorizationRequest) (AuthorizationDecision, error) {
			if request.Agent != "aauth:planner@ap.example" || request.Subagent != "aauth:planner+search@ap.example" || request.Budget == nil {
				t.Fatalf("delegated budget policy context = agent %q subagent %q budget %v", request.Agent, request.Subagent, request.Budget != nil)
			}
			offers = append(offers, request.Budget.Amount())
			granted := grant
			return AuthorizationDecision{Scopes: []string{"records.read"}, Lifetime: 30 * time.Minute, Budget: &granted}, nil
		},
		Budget: &BudgetConfig{ResolveResourceUnits: delegationUnits(t, "https://resource.example")},
	})
	if err != nil {
		t.Fatal(err)
	}
	personResponse := p.personRequest(t, server, p.childToken)
	if personResponse.Code != http.StatusOK {
		t.Fatalf("person-token response = %d %s", personResponse.Code, personResponse.Body.String())
	}
	var personOutput struct {
		PersonToken string `json:"person_token"`
	}
	if err := json.Unmarshal(personResponse.Body.Bytes(), &personOutput); err != nil {
		t.Fatal(err)
	}
	personClaims, err := aauth.VerifyPersonToken(context.Background(), personOutput.PersonToken, p.resolver, p.clock)
	if err != nil {
		t.Fatal(err)
	}
	childJKT, err := p.childKey.PublicJWK().Thumbprint()
	if err != nil {
		t.Fatal(err)
	}
	var grants []budgets.Value
	for _, jti := range []string{"delegated-budget-resource-1", "delegated-budget-resource-2"} {
		resourceToken := delegationResourceToken(t, p, jti, personClaims.JTI, childJKT, offer)
		response := p.tokenRequest(t, server, p.parentKey, p.parentToken, p.childToken, resourceToken)
		if response.Code != http.StatusOK {
			t.Fatalf("%s = %d %s", jti, response.Code, response.Body.String())
		}
		var output struct {
			AuthToken string `json:"auth_token"`
		}
		if err := json.Unmarshal(response.Body.Bytes(), &output); err != nil {
			t.Fatal(err)
		}
		claims, got, err := budgets.VerifyAuthToken(context.Background(), output.AuthToken, p.resolver, p.clock)
		if err != nil {
			t.Fatal(err)
		}
		if !claims.Confirmation.JWK.Equal(p.childKey.PublicJWK()) || claims.Confirmation.JWK.Equal(p.parentKey.PublicJWK()) {
			t.Fatalf("%s confirmation is not the child key", jti)
		}
		grants = append(grants, got)
	}
	if len(offers) != 2 || offers[0] != offer.Amount() || offers[1] != offer.Amount() {
		t.Fatalf("offers seen by policy = %v, want two full offers of %d", offers, offer.Amount())
	}
	if !sameBudgetValue(grants[0], grant) || !sameBudgetValue(grants[1], grant) || grants[0].Amount() != grants[1].Amount() {
		t.Fatalf("grants = %d and %d, want two independent grants of %d", grants[0].Amount(), grants[1].Amount(), grant.Amount())
	}
}

func TestCallChainBudgetIsSizedForTheDownstreamToken(t *testing.T) {
	protocol := newCallChainingProtocol(t)
	offer := delegationValue(t, 5_000_000)
	grant := delegationValue(t, 2_000_000)
	upstreamBefore := protocol.upstreamToken
	var offers []int64
	protocol.chainAuthorize = func(request AuthorizationRequest) (AuthorizationDecision, error) {
		protocol.assertUpstreamPolicyClaims(request.Upstream)
		if request.Budget == nil || request.Budget.Amount() != offer.Amount() || !request.Budget.Unit().Equal(offer.Unit()) {
			t.Fatalf("downstream offer = %#v", request.Budget)
		}
		if request.Subject == request.Upstream.Subject {
			t.Fatalf("downstream subject %q draws on the upstream subject", request.Subject)
		}
		offers = append(offers, request.Budget.Amount())
		granted := grant
		return AuthorizationDecision{Scopes: []string{"payments.charge"}, Lifetime: 20 * time.Minute, Budget: &granted}, nil
	}
	config := protocol.config()
	config.Budget = &BudgetConfig{ResolveResourceUnits: delegationUnits(t, protocol.resourceTwoID)}
	server := protocol.newServer(t, config)

	personResponse := protocol.personRequest(t, server, protocol.upstreamToken, "")
	if personResponse.Code != http.StatusOK {
		t.Fatalf("person response = %d %s", personResponse.Code, personResponse.Body.String())
	}
	var personOutput struct {
		PersonToken string `json:"person_token"`
	}
	if err := json.Unmarshal(personResponse.Body.Bytes(), &personOutput); err != nil {
		t.Fatal(err)
	}
	personClaims, err := aauth.VerifyPersonToken(context.Background(), personOutput.PersonToken, protocol.resolver, protocol.clock)
	if err != nil {
		t.Fatal(err)
	}
	protocol.personTokens = map[string]string{personClaims.JTI: personOutput.PersonToken}

	var grants []budgets.Value
	for _, jti := range []string{"downstream-budget-resource-1", "downstream-budget-resource-2"} {
		resourceToken := protocol.budgetResourceToken(t, personClaims, jti, offer)
		response := protocol.tokenRequest(t, server, resourceToken, protocol.upstreamToken, "")
		if response.Code != http.StatusOK {
			t.Fatalf("%s = %d %s", jti, response.Code, response.Body.String())
		}
		var output struct {
			AuthToken string `json:"auth_token"`
		}
		if err := json.Unmarshal(response.Body.Bytes(), &output); err != nil {
			t.Fatal(err)
		}
		claims, got, err := budgets.VerifyAuthToken(context.Background(), output.AuthToken, protocol.resolver, protocol.clock)
		if err != nil {
			t.Fatal(err)
		}
		if claims.Subject != protocol.downstreamSubject || claims.Subject == protocol.upstreamClaims.Subject {
			t.Fatalf("%s subject = %q", jti, claims.Subject)
		}
		if !claims.Confirmation.JWK.Equal(protocol.resourceOneProofKey.PublicJWK()) {
			t.Fatalf("%s confirmation is not the downstream caller", jti)
		}
		grants = append(grants, got)
	}
	if protocol.upstreamToken != upstreamBefore {
		t.Fatal("downstream issuance rewrote the upstream token")
	}
	carriesBudget, err := budgets.TokenCarriesClaims(protocol.upstreamToken)
	if err != nil || carriesBudget {
		t.Fatalf("upstream budget claim = %t, %v", carriesBudget, err)
	}
	if len(offers) != 2 || offers[0] != offer.Amount() || offers[1] != offer.Amount() {
		t.Fatalf("downstream offers = %v, want two full offers of %d", offers, offer.Amount())
	}
	if !sameBudgetValue(grants[0], grant) || !sameBudgetValue(grants[1], grant) {
		t.Fatalf("downstream grants = %d and %d, want %d twice", grants[0].Amount(), grants[1].Amount(), grant.Amount())
	}
}

func TestFederatedPSRefusesDelegatedBudget(t *testing.T) {
	t.Parallel()

	p := newSubagentPersonServerProtocol(t)
	if err := p.store.Commit(context.Background(), PersonTokenRecord{
		JTI: "person-token", PersonServer: "https://ps.example", Resource: "https://resource.example",
		Subject: "person-123", Tenant: "tenant-1", ExpiresAt: p.now.Add(10 * time.Minute),
		RetainUntil: p.now.Add(15 * time.Minute), AgentProvider: "https://ap.example",
		Agent: "aauth:planner+search@ap.example", ParentAgent: "aauth:planner@ap.example",
		Confirmation: p.childKey.PublicJWK(),
	}); err != nil {
		t.Fatal(err)
	}
	offer := delegationValue(t, 5_000_000)
	childJKT, err := p.childKey.PublicJWK().Thumbprint()
	if err != nil {
		t.Fatal(err)
	}
	resourceToken, err := budgets.MintResourceToken(p.resourceKey, aauth.ResourceTokenClaims{
		Issuer: "https://resource.example", DWK: aauth.ResourceDiscoveryDocument,
		Audience: "https://as.example", JTI: "federated-delegated-budget", AgentJKT: childJKT,
		IssuedAt: p.now.Unix(), ExpiresAt: p.now.Add(5 * time.Minute).Unix(), Scope: "records.read",
		PersonServer: "https://ps.example", Subject: "person-123", PresentedJTI: "person-token",
		Tenant: "tenant-1",
	}, offer, nil)
	if err != nil {
		t.Fatal(err)
	}
	downstreamCalls := 0
	server, err := NewFederatedAuthorization(FederatedAuthorizationConfig{
		Issuer: "https://ps.example", SigningKey: p.personKey, KeyResolver: p.resolver,
		Clock: p.clock, NewID: func() string { return "unused" }, Tokens: p.store,
		HTTPClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			downstreamCalls++
			return nil, errFederatedBudgetCalled
		})},
		AccessServerEndpoint: func(context.Context, string) (string, error) {
			downstreamCalls++
			return "https://as.example/token", nil
		},
		BindPerson: p.policyPerson,
		Consent: func(context.Context, AuthorizationRequest) error {
			p.authorizationCalls++
			return nil
		},
		Budget: &FederatedBudgetConfig{
			ResolveResourceUnits: delegationUnits(t, "https://resource.example"),
			Ceiling: func(context.Context, AuthorizationRequest) (*budgets.Value, error) {
				t.Fatal("federated ceiling ran for a delegated budget")
				return nil, nil
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	response := p.tokenRequest(t, server, p.parentKey, p.parentToken, p.childToken, resourceToken)
	var problem struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &problem); err != nil {
		t.Fatal(err)
	}
	if response.Code != http.StatusBadRequest || problem.Error != "invalid_request" ||
		p.authorizationCalls != 0 || downstreamCalls != 0 {
		t.Fatalf("response=%d %s policy=%d downstream=%d", response.Code, response.Body.String(), p.authorizationCalls, downstreamCalls)
	}
}

func delegationValue(t *testing.T, amount int64) budgets.Value {
	t.Helper()
	unit, err := budgets.NewUnit("USD", 6)
	if err != nil {
		t.Fatal(err)
	}
	value, err := budgets.NewValue(amount, unit)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func delegationUnits(t *testing.T, resourceID string) func(context.Context, string) ([]budgets.UnitDeclaration, error) {
	t.Helper()
	unit, err := budgets.NewUnit("USD", 6)
	if err != nil {
		t.Fatal(err)
	}
	declaration, err := budgets.NewBoundedUnitDeclaration(unit, 10_000_000, "")
	if err != nil {
		t.Fatal(err)
	}
	return func(_ context.Context, resource string) ([]budgets.UnitDeclaration, error) {
		if resource != resourceID {
			return nil, errUnexpectedBudgetResource
		}
		return []budgets.UnitDeclaration{declaration}, nil
	}
}

func delegationResourceToken(t *testing.T, p *subagentPersonServerProtocol, jti, presentedJTI, agentJKT string, offer budgets.Value) string {
	t.Helper()
	compact, err := budgets.MintResourceToken(p.resourceKey, aauth.ResourceTokenClaims{
		Issuer: "https://resource.example", DWK: aauth.ResourceDiscoveryDocument,
		Audience: "https://ps.example", JTI: jti, AgentJKT: agentJKT,
		IssuedAt: p.now.Unix(), ExpiresAt: p.now.Add(5 * time.Minute).Unix(), Scope: "records.read",
		PersonServer: "https://ps.example", Subject: "person-123", PresentedJTI: presentedJTI,
		Tenant: "tenant-1",
	}, offer, nil)
	if err != nil {
		t.Fatal(err)
	}
	return compact
}

func (protocol *callChainingProtocol) budgetResourceToken(t *testing.T, person aauth.PersonTokenClaims, jti string, offer budgets.Value) string {
	t.Helper()
	agentJKT, err := protocol.resourceOneProofKey.PublicJWK().Thumbprint()
	if err != nil {
		t.Fatal(err)
	}
	compact, err := budgets.MintResourceToken(protocol.resourceTwoKey, aauth.ResourceTokenClaims{
		Issuer: protocol.resourceTwoID, DWK: aauth.ResourceDiscoveryDocument,
		Audience: protocol.personServerID, JTI: jti, PersonServer: protocol.personServerID,
		Subject: person.Subject, PresentedJTI: person.JTI, AgentJKT: agentJKT,
		IssuedAt: protocol.now.Unix(), ExpiresAt: protocol.now.Add(4 * time.Minute).Unix(),
		Scope: "payments.charge",
	}, offer, nil)
	if err != nil {
		t.Fatal(err)
	}
	protocol.present(compact, protocol.personTokens[person.JTI])
	return compact
}
