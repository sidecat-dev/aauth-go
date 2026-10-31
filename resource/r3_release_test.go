package resource

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/budgets"
	"gitlab.com/sidecat-dev/aauth-go/r3"
	"gitlab.com/sidecat-dev/aauth-go/r3/vocab/mcp"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

// TestR3ReleaseGatedCallRunsOnceAndReleasesOnlyOnApproval runs a held
// per-call operation through the Resource handler. The call runs before the
// challenge, the proposal carries result and a release display, and the
// approved poll receives that response without the call running again.
func TestR3ReleaseGatedCallRunsOnceAndReleasesOnlyOnApproval(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 31, 13, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	resourceKey := testSigningKey(t, "resource-key", 151)
	personKey := testSigningKey(t, "person-key", 152)
	accessKey := testSigningKey(t, "access-key", 153)
	agentKey := testSigningKey(t, "agent-key", 154)
	resolver := signaturekey.StaticKeyResolver{
		{Issuer: personIssuer, DiscoveryDocument: aauth.PersonDiscoveryDocument, KeyID: personKey.ID()}:       personKey.PublicJWK(),
		{Issuer: resourceIssuer, DiscoveryDocument: aauth.ResourceDiscoveryDocument, KeyID: resourceKey.ID()}: resourceKey.PublicJWK(),
		{Issuer: accessIssuer, DiscoveryDocument: aauth.AccessDiscoveryDocument, KeyID: accessKey.ID()}:       accessKey.PublicJWK(),
	}
	var runs atomic.Int32
	config := validConfigWithKey(resourceKey, http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		runs.Add(1)
		writeJSON(response, http.StatusOK, map[string]any{"records": 214})
	}))
	config.Clock = clock
	config.KeyResolver = resolver
	config.AdditionalSignatureComponents = nil
	config.ScopeDescriptions = map[string]string{"records.read": "Read records"}
	config.RequiredScopes = func(*http.Request) []string { return []string{"records.read"} }
	config.MaxRetainedRequestBodyBytes = 64 << 10
	config.MaxRetainedResponseBodyBytes = 64 << 10
	config.MaxRetainedHeaderBytes = 16 << 10
	identifiers := 0
	config.NewID = func() string {
		identifiers++
		return "release-token-" + string(rune('a'+identifiers))
	}
	config.R3 = newResourceMCPConfig(t, &r3TestDocumentStore{}, []string{"records.query"}, func(*http.Request) (string, bool, error) {
		return "records.query", true, nil
	})
	config.R3.HTTP.PresentParameters = func(request *http.Request, _ r3.Operation) (map[string]r3.PresentedParameter, error) {
		encoded, _ := json.Marshal(strings.TrimPrefix(request.URL.Path, "/records/"))
		presented, err := r3.NewPresentedInlineParameter(encoded)
		if err != nil {
			return nil, err
		}
		return map[string]r3.PresentedParameter{"query": presented}, nil
	}
	parameters := func(invocation r3.Invocation) r3.Parameters {
		encoded, _ := invocation.PresentedParameters()["query"].InlineJSON()
		inline, err := r3.NewInlineParameter(encoded)
		if err != nil {
			t.Fatal(err)
		}
		values, err := r3.NewParameters(map[string]r3.Parameter{"query": inline})
		if err != nil {
			t.Fatal(err)
		}
		return values
	}
	var describedRelease *R3ReleaseRequest
	proposals := &r3ProposalTestStore{}
	config.R3.PerCall = &R3PerCallConfig{
		Proposals: proposals,
		Retries:   &r3RetryTestStore{},
		DescribeCall: func(context.Context, r3.Invocation, *string) (R3CallDescription, error) {
			t.Error("a release-gated call was described for execution approval")
			return R3CallDescription{}, nil
		},
		Release: &R3ReleaseConfig{
			Eligible: func(context.Context, r3.Invocation) (bool, error) { return true, nil },
			DescribeResult: func(_ context.Context, request R3ReleaseRequest) (R3ReleaseDescription, error) {
				describedRelease = &request
				display, err := r3.NewDisplay("Release the result of a query over employee records", "", "214 employee records", "")
				if err != nil {
					return R3ReleaseDescription{}, err
				}
				return R3ReleaseDescription{
					Parameters: parameters(request.Invocation),
					Result:     json.RawMessage(`{"records":214,"contains":["compensation"]}`),
					Display:    display, Detail: "## Details\n214 rows.",
				}, nil
			},
		},
	}
	held := newHeldMemoryStore()
	config.HeldInvocations = held
	config.HoldAuthTokenRequest = func(*http.Request) bool { return true }
	server, err := NewFederatedAuthorization(config)
	if err != nil {
		t.Fatal(err)
	}
	registry := config.R3.Registry

	personToken := mintPersonToken(t, personKey, agentKey.PublicJWK(), now, resourceIssuer, "person-token-release")
	authorize := signedRequest(t, clock, agentKey, personToken, http.MethodPost, resourceIssuer+"/authorize",
		`{"scope":"records.read","r3_operations":{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"records.query"}]}}`)
	authorized := httptest.NewRecorder()
	server.Handler().ServeHTTP(authorized, authorize)
	if authorized.Code != http.StatusOK {
		t.Fatalf("class authorization = %d %s", authorized.Code, authorized.Body.String())
	}
	var output struct {
		ResourceToken string `json:"resource_token"`
	}
	if err := json.Unmarshal(authorized.Body.Bytes(), &output); err != nil {
		t.Fatal(err)
	}
	classClaims, classReference, err := r3.VerifyResourceToken(context.Background(), output.ResourceToken, resolver, clock)
	if err != nil {
		t.Fatal(err)
	}
	classRecord, err := config.R3.Documents.Load(context.Background(), classReference.URI())
	if err != nil {
		t.Fatal(err)
	}
	classDocument, err := registry.ParseReferencedDocument(classReference, classRecord.ExactJSON)
	if err != nil {
		t.Fatal(err)
	}
	query := newResourceMCPOperation(t, "records.query")
	empty, _ := r3.NewGrantedOperations(mcp.Vocabulary())
	perCall, _ := r3.NewGrantedOperations(mcp.Vocabulary(), query)
	classAuthorization, err := r3.NewAuthorization(empty, perCall, classDocument)
	if err != nil {
		t.Fatal(err)
	}
	authClaims := func(jti string) aauth.AuthTokenClaims {
		return aauth.AuthTokenClaims{
			Issuer: accessIssuer, DWK: aauth.AccessDiscoveryDocument, Audience: resourceIssuer, JTI: jti,
			PersonServer: personIssuer, Subject: classClaims.Subject, Tenant: classClaims.Tenant,
			Confirmation: aauth.Confirmation{JWK: agentKey.PublicJWK()},
			IssuedAt:     now.Unix(), ExpiresAt: now.Add(30 * time.Minute).Unix(), Scope: "records.read",
		}
	}
	classAuthToken, err := r3.MintAuthToken(registry, accessKey, authClaims("class-auth-token"), classReference, classRecord.ExactJSON, classAuthorization)
	if err != nil {
		t.Fatal(err)
	}

	call := signedRequest(t, clock, agentKey, classAuthToken, http.MethodGet, resourceIssuer+"/records/engineering", "")
	challenge := httptest.NewRecorder()
	server.Handler().ServeHTTP(challenge, call)
	if challenge.Code != http.StatusAccepted || runs.Load() != 1 {
		t.Fatalf("release-gated challenge = %d %s, runs %d; want 202 after one run", challenge.Code, challenge.Body.String(), runs.Load())
	}
	if describedRelease == nil || describedRelease.Response.StatusCode != http.StatusOK ||
		!strings.Contains(string(describedRelease.Response.Body), `"records":214`) {
		t.Fatalf("release description input = %#v", describedRelease)
	}
	requirement, err := aauth.ParseAuthTokenRequirement(challenge.Header().Values("AAuth-Requirement"))
	if err != nil {
		t.Fatal(err)
	}
	_, proposalReference, err := r3.VerifyResourceToken(context.Background(), requirement.ResourceToken, resolver, clock)
	if err != nil {
		t.Fatal(err)
	}
	record, err := proposals.Load(context.Background(), proposalReference.URI())
	if err != nil {
		t.Fatal(err)
	}
	// The PS and AS parse the fetched proposal the same way.
	proposal, err := registry.ParseReferencedProposal(proposalReference, record.ExactJSON)
	if err != nil {
		t.Fatal(err)
	}
	result, released := proposal.Result()
	display, displayed := proposal.Display()
	if !released || string(result) != `{"records":214,"contains":["compensation"]}` || !displayed ||
		display.Detail() != r3.ReleaseAction+"\n\n## Details\n214 rows." {
		t.Fatalf("release proposal = %s", record.ExactJSON)
	}

	perCallToken, err := r3.MintPerCallAuthToken(registry, accessKey, authClaims("per-call-auth-token"), proposalReference, record.ExactJSON)
	if err != nil {
		t.Fatal(err)
	}
	poll := func() *httptest.ResponseRecorder {
		response := httptest.NewRecorder()
		server.Handler().ServeHTTP(response, signedRequest(t, clock, agentKey, perCallToken, http.MethodGet, challenge.Header().Get("Location"), ""))
		return response
	}
	first := poll()
	if first.Code != http.StatusOK || !strings.Contains(first.Body.String(), `"records":214`) || runs.Load() != 1 {
		t.Fatalf("approved poll = %d %s, runs %d; want the held response and no second run", first.Code, first.Body.String(), runs.Load())
	}
	replay := poll()
	if replay.Code != first.Code || replay.Body.String() != first.Body.String() || runs.Load() != 1 {
		t.Fatalf("replayed poll = %d %s, runs %d", replay.Code, replay.Body.String(), runs.Load())
	}

	// A held release whose response a store dropped fails closed rather
	// than running the call again.
	call = signedRequest(t, clock, agentKey, classAuthToken, http.MethodGet, resourceIssuer+"/records/sales", "")
	second := httptest.NewRecorder()
	held.pendingID = "held-call-fedcba9876543210"
	server.Handler().ServeHTTP(second, call)
	if second.Code != http.StatusAccepted || runs.Load() != 2 {
		t.Fatalf("second release-gated challenge = %d, runs %d", second.Code, runs.Load())
	}
	held.loadResult = func(invocation HeldInvocation) HeldInvocation {
		invocation.R3PerCall.Release = nil
		return invocation
	}
	requirement, err = aauth.ParseAuthTokenRequirement(second.Header().Values("AAuth-Requirement"))
	if err != nil {
		t.Fatal(err)
	}
	_, secondReference, err := r3.VerifyResourceToken(context.Background(), requirement.ResourceToken, resolver, clock)
	if err != nil {
		t.Fatal(err)
	}
	secondRecord, err := proposals.Load(context.Background(), secondReference.URI())
	if err != nil {
		t.Fatal(err)
	}
	secondToken, err := r3.MintPerCallAuthToken(registry, accessKey, authClaims("per-call-auth-token-2"), secondReference, secondRecord.ExactJSON)
	if err != nil {
		t.Fatal(err)
	}
	dropped := httptest.NewRecorder()
	server.Handler().ServeHTTP(dropped, signedRequest(t, clock, agentKey, secondToken, http.MethodGet, second.Header().Get("Location"), ""))
	if dropped.Code != http.StatusInternalServerError || runs.Load() != 2 {
		t.Fatalf("poll of a release without its response = %d, runs %d; want 500 and no run", dropped.Code, runs.Load())
	}
}

// TestR3ReleaseGatingRefusesMeteredAndBudgetAnnotatedCalls checks the rule
// that approval precedes a call whose running is the metered event, unless
// the Resource meters the release of a budget:true operation instead.
func TestR3ReleaseGatingRefusesMeteredAndBudgetAnnotatedCalls(t *testing.T) {
	t.Parallel()

	body := []byte(`{"tools":[` +
		`{"name":"records.query","inputSchema":{"type":"object"}},` +
		`{"name":"records.billed","inputSchema":{"type":"object"},"_meta":{"aauth.dev/budget":true}}]}`)
	definition := newResourceMCPDefinitionFromBody(t, body)
	config := &R3Config{
		Registry:     newResourceR3Registry(t),
		Definitions:  newResourceR3DefinitionRegistry(t),
		Vocabularies: []R3VocabularyConfig{{Definition: definition}},
		Documents:    &r3TestDocumentStore{},
		HTTP: R3HTTPAdapter{
			OperationForRequest: func(*http.Request) (r3.Operation, bool, error) { return r3.Operation{}, false, nil },
			PresentParameters: func(*http.Request, r3.Operation) (map[string]r3.PresentedParameter, error) {
				return nil, nil
			},
		},
		PerCall: &R3PerCallConfig{
			Proposals: &r3ProposalTestStore{}, Retries: &r3RetryTestStore{},
			DescribeCall: func(context.Context, r3.Invocation, *string) (R3CallDescription, error) {
				return R3CallDescription{}, nil
			},
			Release: &R3ReleaseConfig{
				Eligible: func(context.Context, r3.Invocation) (bool, error) { return true, nil },
				DescribeResult: func(context.Context, R3ReleaseRequest) (R3ReleaseDescription, error) {
					return R3ReleaseDescription{}, nil
				},
			},
		},
	}
	validated, err := validateR3Config(config)
	if err != nil {
		t.Fatal(err)
	}
	invocation := func(tool string) r3.Invocation {
		value, err := r3.NewInvocation(newResourceMCPOperation(t, tool), nil)
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	request := httptest.NewRequest(http.MethodGet, resourceIssuer+"/records/q", nil)
	unmeteredRoute := &budgetConfig{metered: func(*http.Request) bool { return false }}
	for _, test := range []struct {
		name         string
		budget       *budgetConfig
		tool         string
		meterRelease bool
		eligible     bool
		metered      bool
	}{
		{name: "unmetered", tool: "records.query", eligible: true},
		{name: "route metered by the Budget profile", tool: "records.query", budget: &budgetConfig{}},
		{name: "route outside the metered set", tool: "records.query", eligible: true, budget: unmeteredRoute},
		{name: "operation annotated budget:true", tool: "records.billed"},
		{name: "budget:true with a metered release", tool: "records.billed", budget: unmeteredRoute, meterRelease: true, eligible: true, metered: true},
		{name: "unannotated with a metered release", tool: "records.query", budget: unmeteredRoute, meterRelease: true, eligible: true},
		{name: "budget:true on a metered route", tool: "records.billed", budget: &budgetConfig{}, meterRelease: true},
	} {
		validated.perCall.release.meterRelease = test.meterRelease
		server := &Server{r3: validated, budget: test.budget}
		eligible, metered, err := server.releaseEligible(request, invocation(test.tool))
		if err != nil || eligible != test.eligible || metered != test.metered {
			t.Errorf("%s: eligible = %t, metered = %t, %v; want %t, %t", test.name, eligible, metered, err, test.eligible, test.metered)
		}
	}
}

// TestR3MeteredReleaseDrawsTheCostDownOnceFromThePerCallToken meters the
// release of a budget:true operation's result (R3 Approving Release Rather
// Than Execution; Budgets Deferred Delivery). The proposal's Resource token
// offers the release cost, a per-call token whose budget is short or above
// the offer releases nothing, the fitting token releases the result once with
// AAuth-Budget, and its replay meters nothing again. An unannotated
// operation's release beside it is not metered.
func TestR3MeteredReleaseDrawsTheCostDownOnceFromThePerCallToken(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 10, 31, 13, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	resourceKey := testSigningKey(t, "resource-key", 161)
	personKey := testSigningKey(t, "person-key", 162)
	accessKey := testSigningKey(t, "access-key", 163)
	agentKey := testSigningKey(t, "agent-key", 164)
	resolver := signaturekey.StaticKeyResolver{
		{Issuer: personIssuer, DiscoveryDocument: aauth.PersonDiscoveryDocument, KeyID: personKey.ID()}:       personKey.PublicJWK(),
		{Issuer: resourceIssuer, DiscoveryDocument: aauth.ResourceDiscoveryDocument, KeyID: resourceKey.ID()}: resourceKey.PublicJWK(),
		{Issuer: accessIssuer, DiscoveryDocument: aauth.AccessDiscoveryDocument, KeyID: accessKey.ID()}:       accessKey.PublicJWK(),
	}
	unit, err := budgets.NewUnit("credits", 0)
	if err != nil {
		t.Fatal(err)
	}
	credits := func(amount int64) budgets.Value {
		value, err := budgets.NewValue(amount, unit)
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	declaration, err := budgets.NewBoundedUnitDeclaration(unit, 1000, "Credits")
	if err != nil {
		t.Fatal(err)
	}
	var runs atomic.Int32
	config := validConfigWithKey(resourceKey, http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		runs.Add(1)
		writeJSON(response, http.StatusOK, map[string]any{"report": strings.TrimPrefix(request.URL.Path, "/")})
	}))
	config.Clock = clock
	config.KeyResolver = resolver
	config.AdditionalSignatureComponents = nil
	config.ScopeDescriptions = map[string]string{"records.read": "Read records"}
	config.RequiredScopes = func(*http.Request) []string { return []string{"records.read"} }
	config.MaxRetainedRequestBodyBytes = 64 << 10
	config.MaxRetainedResponseBodyBytes = 64 << 10
	config.MaxRetainedHeaderBytes = 16 << 10
	identifiers := 0
	config.NewID = func() string {
		identifiers++
		return "metered-release-" + string(rune('a'+identifiers))
	}
	toolFor := func(request *http.Request) string {
		if strings.HasPrefix(request.URL.Path, "/billed/") {
			return "records.billed"
		}
		return "records.query"
	}
	config.R3 = &R3Config{
		Registry:    newResourceR3Registry(t),
		Definitions: newResourceR3DefinitionRegistry(t),
		Vocabularies: []R3VocabularyConfig{{Definition: newResourceMCPDefinitionFromBody(t, []byte(`{"tools":[`+
			`{"name":"records.query","inputSchema":{"type":"object"}},`+
			`{"name":"records.billed","inputSchema":{"type":"object"},"_meta":{"aauth.dev/budget":true}}]}`))}},
		Documents: &r3TestDocumentStore{},
		HTTP: R3HTTPAdapter{
			OperationForRequest: func(request *http.Request) (r3.Operation, bool, error) {
				return newResourceMCPOperation(t, toolFor(request)), true, nil
			},
			PresentParameters: func(*http.Request, r3.Operation) (map[string]r3.PresentedParameter, error) {
				return nil, nil
			},
		},
	}
	proposals := &r3ProposalTestStore{}
	config.R3.PerCall = &R3PerCallConfig{
		Proposals: proposals, Retries: &r3RetryTestStore{},
		DescribeCall: func(context.Context, r3.Invocation, *string) (R3CallDescription, error) {
			t.Error("a release-gated call was described for execution approval")
			return R3CallDescription{}, nil
		},
		Release: &R3ReleaseConfig{
			Eligible:     func(context.Context, r3.Invocation) (bool, error) { return true, nil },
			MeterRelease: true,
			DescribeResult: func(_ context.Context, request R3ReleaseRequest) (R3ReleaseDescription, error) {
				display, err := r3.NewDisplay("Release a report", "", "One report", "")
				if err != nil {
					return R3ReleaseDescription{}, err
				}
				none, err := r3.NewParameters(nil)
				if err != nil {
					return R3ReleaseDescription{}, err
				}
				description := R3ReleaseDescription{
					Parameters: none, Result: json.RawMessage(`{"reports":1}`), Display: display,
				}
				if resourceMCPTool(t, request.Invocation.Operation()) == "records.billed" {
					cost := credits(25)
					description.Cost = &cost
				}
				return description, nil
			},
		},
	}
	ledger := newBudgetMemoryStore()
	config.Budget = &BudgetConfig{
		Units:         []budgets.UnitDeclaration{declaration},
		Metered:       func(*http.Request) bool { return false },
		RetainLineage: func(context.Context, BudgetLineage) error { return nil },
		Cost:          func(context.Context, BudgetCostRequest) (int64, error) { return 0, nil },
		Store:         ledger,
		Challenge: func(context.Context, BudgetChallengeRequest) (string, error) {
			return "", errors.New("no step-up in this test")
		},
	}
	config.HeldInvocations = newHeldMemoryStore()
	config.HoldAuthTokenRequest = func(*http.Request) bool { return true }
	server, err := NewFederatedAuthorization(config)
	if err != nil {
		t.Fatal(err)
	}
	registry := config.R3.Registry

	personToken := mintPersonToken(t, personKey, agentKey.PublicJWK(), now, resourceIssuer, "person-token-metered")
	authorize := signedRequest(t, clock, agentKey, personToken, http.MethodPost, resourceIssuer+"/authorize",
		`{"scope":"records.read","r3_operations":{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"records.query"},{"tool":"records.billed"}]}}`)
	authorized := httptest.NewRecorder()
	server.Handler().ServeHTTP(authorized, authorize)
	if authorized.Code != http.StatusOK {
		t.Fatalf("class authorization = %d %s", authorized.Code, authorized.Body.String())
	}
	var output struct {
		ResourceToken string `json:"resource_token"`
	}
	if err := json.Unmarshal(authorized.Body.Bytes(), &output); err != nil {
		t.Fatal(err)
	}
	classClaims, classReference, err := r3.VerifyResourceToken(context.Background(), output.ResourceToken, resolver, clock)
	if err != nil {
		t.Fatal(err)
	}
	classRecord, err := config.R3.Documents.Load(context.Background(), classReference.URI())
	if err != nil {
		t.Fatal(err)
	}
	classDocument, err := registry.ParseReferencedDocument(classReference, classRecord.ExactJSON)
	if err != nil {
		t.Fatal(err)
	}
	empty, _ := r3.NewGrantedOperations(mcp.Vocabulary())
	perCall, _ := r3.NewGrantedOperations(mcp.Vocabulary(), newResourceMCPOperation(t, "records.query"), newResourceMCPOperation(t, "records.billed"))
	classAuthorization, err := r3.NewAuthorization(empty, perCall, classDocument)
	if err != nil {
		t.Fatal(err)
	}
	authClaims := func(jti string) aauth.AuthTokenClaims {
		return aauth.AuthTokenClaims{
			Issuer: accessIssuer, DWK: aauth.AccessDiscoveryDocument, Audience: resourceIssuer, JTI: jti,
			PersonServer: personIssuer, Subject: classClaims.Subject, Tenant: classClaims.Tenant,
			Confirmation: aauth.Confirmation{JWK: agentKey.PublicJWK()},
			IssuedAt:     now.Unix(), ExpiresAt: now.Add(30 * time.Minute).Unix(), Scope: "records.read",
		}
	}
	classAuthToken, err := r3.MintAuthToken(registry, accessKey, authClaims("class-auth-token"), classReference, classRecord.ExactJSON, classAuthorization)
	if err != nil {
		t.Fatal(err)
	}
	type held struct {
		location  string
		reference r3.Reference
		proposal  []byte
		offer     *budgets.Value
	}
	challenge := func(path string) held {
		t.Helper()
		response := httptest.NewRecorder()
		server.Handler().ServeHTTP(response, signedRequest(t, clock, agentKey, classAuthToken, http.MethodGet, resourceIssuer+path, ""))
		if response.Code != http.StatusAccepted {
			t.Fatalf("%s challenge = %d %s", path, response.Code, response.Body.String())
		}
		requirement, err := aauth.ParseAuthTokenRequirement(response.Header().Values("AAuth-Requirement"))
		if err != nil {
			t.Fatal(err)
		}
		challenged := held{location: response.Header().Get("Location")}
		if carries, _ := budgets.TokenCarriesClaims(requirement.ResourceToken); carries {
			var offer budgets.Value
			_, challenged.reference, offer, _, err = r3.VerifyBudgetResourceToken(context.Background(), registry, requirement.ResourceToken, resolver, clock)
			challenged.offer = &offer
		} else {
			_, challenged.reference, err = r3.VerifyResourceToken(context.Background(), requirement.ResourceToken, resolver, clock)
		}
		if err != nil {
			t.Fatal(err)
		}
		record, err := proposals.Load(context.Background(), challenged.reference.URI())
		if err != nil {
			t.Fatal(err)
		}
		challenged.proposal = record.ExactJSON
		return challenged
	}
	poll := func(location, token string) *httptest.ResponseRecorder {
		t.Helper()
		response := httptest.NewRecorder()
		server.Handler().ServeHTTP(response, signedRequest(t, clock, agentKey, token, http.MethodGet, location, ""))
		return response
	}
	feedback := func(response *httptest.ResponseRecorder) budgets.Feedback {
		t.Helper()
		parsed, err := budgets.ParseFeedback(response.Header().Values("AAuth-Budget"))
		if err != nil {
			t.Fatalf("AAuth-Budget %q: %v", response.Header().Values("AAuth-Budget"), err)
		}
		return parsed
	}

	billed := challenge("/billed/q3")
	if runs.Load() != 1 || billed.offer == nil || billed.offer.Amount() != 25 || !billed.offer.Unit().Equal(unit) {
		t.Fatalf("metered release offer = %v after %d runs", billed.offer, runs.Load())
	}
	for _, grant := range []int64{10, 30} {
		token, err := r3.MintBudgetPerCallAuthToken(registry, accessKey, authClaims(fmt.Sprintf("per-call-%d", grant)), billed.reference, billed.proposal, credits(grant))
		if err != nil {
			t.Fatal(err)
		}
		refused := poll(billed.location, token)
		if refused.Code != http.StatusForbidden {
			t.Fatalf("per-call budget %d released %d %s", grant, refused.Code, refused.Body.String())
		}
		if grant == 10 {
			short := feedback(refused)
			if required, ok := short.Required(); short.Remaining() != 10 || !ok || required != 25 {
				t.Fatalf("short per-call budget feedback = %q", refused.Header().Values("AAuth-Budget"))
			}
		}
	}
	if consumed := ledger.personConsumed(personIssuer, classClaims.Subject, resourceIssuer); consumed != 0 {
		t.Fatalf("a refused release metered %d", consumed)
	}
	fitting, err := r3.MintBudgetPerCallAuthToken(registry, accessKey, authClaims("per-call-25"), billed.reference, billed.proposal, credits(25))
	if err != nil {
		t.Fatal(err)
	}
	for _, attempt := range []string{"release", "replay"} {
		released := poll(billed.location, fitting)
		if released.Code != http.StatusOK || !strings.Contains(released.Body.String(), `"report":"billed/q3"`) || runs.Load() != 1 {
			t.Fatalf("%s = %d %s after %d runs", attempt, released.Code, released.Body.String(), runs.Load())
		}
		metered := feedback(released)
		if cost, ok := metered.Cost(); !ok || cost != 25 || metered.Remaining() != 0 {
			t.Fatalf("%s feedback = %q", attempt, released.Header().Values("AAuth-Budget"))
		}
		if consumed := ledger.personConsumed(personIssuer, classClaims.Subject, resourceIssuer); consumed != 25 {
			t.Fatalf("after the %s the ledger holds %d, want 25", attempt, consumed)
		}
	}

	unmetered := challenge("/reports/q3")
	if unmetered.offer != nil || runs.Load() != 2 {
		t.Fatalf("unmetered release offer = %v after %d runs", unmetered.offer, runs.Load())
	}
	plain, err := r3.MintPerCallAuthToken(registry, accessKey, authClaims("per-call-plain"), unmetered.reference, unmetered.proposal)
	if err != nil {
		t.Fatal(err)
	}
	released := poll(unmetered.location, plain)
	if released.Code != http.StatusOK || released.Header().Get("AAuth-Budget") != "" ||
		ledger.personConsumed(personIssuer, classClaims.Subject, resourceIssuer) != 25 {
		t.Fatalf("unmetered release = %d %q", released.Code, released.Header().Values("AAuth-Budget"))
	}
}
