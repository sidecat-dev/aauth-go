package resource

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
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
// that approval precedes a call whose running is the metered event.
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
	for _, test := range []struct {
		name     string
		budget   *budgetConfig
		tool     string
		eligible bool
	}{
		{name: "unmetered", tool: "records.query", eligible: true},
		{name: "route metered by the Budget profile", tool: "records.query", budget: &budgetConfig{}},
		{name: "route outside the metered set", tool: "records.query", eligible: true,
			budget: &budgetConfig{metered: func(*http.Request) bool { return false }}},
		{name: "operation annotated budget:true", tool: "records.billed"},
	} {
		server := &Server{r3: validated, budget: test.budget}
		eligible, err := server.releaseEligible(request, invocation(test.tool))
		if err != nil || eligible != test.eligible {
			t.Errorf("%s: eligible = %t, %v; want %t", test.name, eligible, err, test.eligible)
		}
	}
}
