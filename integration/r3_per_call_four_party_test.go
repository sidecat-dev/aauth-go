package integration_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/accessserver"
	clientagent "gitlab.com/sidecat-dev/aauth-go/agent"
	"gitlab.com/sidecat-dev/aauth-go/agentprovider"
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/personserver"
	"gitlab.com/sidecat-dev/aauth-go/r3"
	"gitlab.com/sidecat-dev/aauth-go/resource"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

const r3PerCallScope = "records.write"

// TestR3PerCallFourPartyJourney exercises AAuth R3 a99d353, "R3
// Processing", "Per-Call Proposals", and "Resource Enforcement" through real
// AP, Agent, PS, Resource, and AS handlers. It covers both the baseline 401
// retry and preferred Resource-held 202 delivery without giving the Agent
// proposal contents or a hidden retry/poll loop.
func TestR3PerCallFourPartyJourney(t *testing.T) {
	registry := newIntegrationR3Registry(t)
	for _, vocabulary := range integrationR3Vocabularies() {
		vocabulary := vocabulary
		t.Run(vocabulary.name, func(t *testing.T) {
			testR3PerCallFourPartyJourney(t, registry, vocabulary)
		})
	}
}

func testR3PerCallFourPartyJourney(t *testing.T, registry r3.Registry, vocabulary integrationR3Vocabulary) {
	ctx := context.Background()
	now := time.Date(2026, 8, 31, 15, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })

	const (
		agentProviderID = "https://ap.example"
		agentID         = "aauth:operator@ap.example"
		personServerID  = "https://ps.example"
		accessServerID  = "https://as.example"
		resourceID      = "https://resource.example"
		personSubject   = "person-123"
		tenant          = "tenant-blue"
		account         = "operations-account"
	)

	providerKey := newSigningKey(t, "r3-per-call-ap-key")
	agentKey := newSigningKey(t, "r3-per-call-agent-key")
	personKey := newSigningKey(t, "r3-per-call-ps-key")
	accessKey := newSigningKey(t, "r3-per-call-as-key")
	resourceKey := newSigningKey(t, "r3-per-call-resource-key")
	deleteRecord := vocabulary.newOperation(t, "records.delete")
	requestedOperations, err := r3.NewOperationSet(deleteRecord)
	if err != nil {
		t.Fatal(err)
	}
	emptyOperations, err := r3.NewGrantedOperations(vocabulary.registration)
	if err != nil {
		t.Fatal(err)
	}
	perCallOperations, err := r3.NewGrantedOperations(vocabulary.registration, deleteRecord)
	if err != nil {
		t.Fatal(err)
	}
	classDisplay, err := r3.NewDisplay(
		"Delete one selected record",
		"Each deletion still requires approval of its concrete record and payload",
		"The selected record and deletion reason",
		"Deletion cannot be undone",
	)
	if err != nil {
		t.Fatal(err)
	}

	network := newLogicalTransport()
	traffic := &r3PerCallTraffic{}
	httpClient := &http.Client{Transport: network}
	resolver, err := signaturekey.NewHTTPKeyResolver(signaturekey.HTTPKeyResolverConfig{
		Client: httpClient, TransportEnforcesEgress: true,
		Clock: clock,
		Admit: func(_ context.Context, endpoint string) error {
			if strings.HasSuffix(endpoint, ".example/.well-known/aauth-agent.json") ||
				strings.HasSuffix(endpoint, ".example/.well-known/aauth-person.json") ||
				strings.HasSuffix(endpoint, ".example/.well-known/aauth-access.json") ||
				strings.HasSuffix(endpoint, ".example/.well-known/aauth-resource.json") ||
				strings.HasSuffix(endpoint, ".example/.well-known/jwks.json") {
				return nil
			}
			return errors.New("unexpected discovery endpoint: " + endpoint)
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	provider, err := agentprovider.New(agentprovider.Config{
		Issuer: agentProviderID, SigningKey: providerKey, Clock: clock,
		NewID: func() string { return "r3-per-call-agent-token" },
	})
	if err != nil {
		t.Fatal(err)
	}
	agentToken, err := provider.Issue(aauth.AgentTokenRequest{
		Agent: agentID, PersonServer: personServerID,
		PublicKey: agentKey.PublicJWK(), Lifetime: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}

	documents := newIntegrationR3DocumentStore()
	proposals := newR3PerCallProposalStore(registry)
	retries := newR3PerCallRetryStore()
	held := newR3PerCallHeldStore()
	issuances := newR3PerCallIssuanceStore()
	observations := newR3PerCallPolicyObservations()
	personTokens := newMemoryPersonTokenStore()

	var adapterMu sync.Mutex
	descriptionsEnabled := true
	descriptionCalls := make(map[string]int)
	presentationCalls := make(map[string]int)
	setDescriptionsEnabled := func(enabled bool) {
		adapterMu.Lock()
		defer adapterMu.Unlock()
		descriptionsEnabled = enabled
	}
	adapterCounts := func(record string) (descriptions, presentations int) {
		adapterMu.Lock()
		defer adapterMu.Unlock()
		return descriptionCalls[record], presentationCalls[record]
	}

	var applicationMu sync.Mutex
	applicationCalls := make(map[string]int)
	protected := http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		record, body, err := parseR3PerCallRequest(request)
		if err != nil {
			t.Errorf("protected request: %v", err)
			http.Error(response, "invalid protected request", http.StatusInternalServerError)
			return
		}
		principal, ok := resource.AuthPrincipalFromContext(request.Context())
		if !ok || principal.PersonServer != personServerID || principal.Subject != personSubject ||
			principal.Tenant != tenant || principal.Account == nil || *principal.Account != account ||
			!slices.Equal(principal.Scope, []string{r3PerCallScope}) || !principal.Confirmation.Equal(agentKey.PublicJWK()) {
			t.Errorf("per-call principal = %#v, present=%t", principal, ok)
			http.Error(response, "invalid principal", http.StatusInternalServerError)
			return
		}
		compact, ok := resource.AuthTokenFromContext(request.Context())
		if !ok || compact == "" {
			t.Error("protected request received no exact Auth token")
			http.Error(response, "missing token", http.StatusInternalServerError)
			return
		}
		if !bytes.Equal(body, r3PerCallBody(record)) {
			t.Errorf("protected body for %q = %q", record, body)
			http.Error(response, "changed body", http.StatusInternalServerError)
			return
		}
		applicationMu.Lock()
		applicationCalls[record]++
		sequence := applicationCalls[record]
		applicationMu.Unlock()
		response.Header().Set("Content-Type", "application/json")
		response.WriteHeader(http.StatusCreated)
		_, _ = fmt.Fprintf(response, `{"record":%q,"execution":%d}`, record, sequence)
	})
	executionCount := func(record string) int {
		applicationMu.Lock()
		defer applicationMu.Unlock()
		return applicationCalls[record]
	}

	resourceTokenIDs := 0
	displayAccount := account
	newResource := func() *resource.Server {
		server, err := resource.NewFederatedAuthorization(resource.FederatedAuthorizationConfig{
			Issuer: resourceID, AccessServer: accessServerID,
			SigningKey: resourceKey, KeyResolver: resolver, Clock: clock,
			NewID: func() string {
				resourceTokenIDs++
				return fmt.Sprintf("r3-per-call-resource-token-%d", resourceTokenIDs)
			},
			ScopeDescriptions:             map[string]string{r3PerCallScope: "Delete records"},
			AdditionalSignatureComponents: []string{"content-type", "content-digest"},
			RequiredScopes:                func(*http.Request) []string { return []string{r3PerCallScope} },
			ResolvePerson: func(_ context.Context, identity resource.PersonIdentity, personContext resource.PersonContext) error {
				if identity != (resource.PersonIdentity{Issuer: personServerID, Subject: personSubject}) ||
					personContext.Tenant != tenant {
					return fmt.Errorf("unexpected person context: %#v %#v", identity, personContext)
				}
				return nil
			},
			ValidateAccount: func(_ context.Context, identity resource.PersonIdentity, got string) error {
				if identity != (resource.PersonIdentity{Issuer: personServerID, Subject: personSubject}) || got != account {
					return fmt.Errorf("unexpected account binding: %#v %q", identity, got)
				}
				return nil
			},
			Protected: protected,
			R3: &resource.R3Config{
				Registry:    registry,
				Definitions: newIntegrationR3DefinitionRegistry(t),
				Vocabularies: integrationR3ResourceVocabularies(
					t, resourceID, []string{"records.delete"}, &displayAccount, &classDisplay,
				),
				Documents: documents,
				HTTP: resource.R3HTTPAdapter{
					OperationForRequest: func(request *http.Request) (r3.Operation, bool, error) {
						if request.Method == http.MethodPost && strings.HasPrefix(request.URL.Path, "/records/") {
							return deleteRecord, true, nil
						}
						return r3.Operation{}, false, nil
					},
					PresentParameters: func(request *http.Request, operation r3.Operation) (map[string]r3.PresentedParameter, error) {
						record, presented, err := presentedR3PerCallParameters(t, vocabulary, request, operation, deleteRecord)
						if err != nil {
							return nil, err
						}
						adapterMu.Lock()
						presentationCalls[record]++
						adapterMu.Unlock()
						return presented, nil
					},
				},
				PerCall: &resource.R3PerCallConfig{
					DescribeCall: func(_ context.Context, invocation r3.Invocation, gotAccount *string) (resource.R3CallDescription, error) {
						record, description, err := describeR3PerCall(t, vocabulary, invocation, gotAccount, deleteRecord, account)
						if err != nil {
							return resource.R3CallDescription{}, err
						}
						adapterMu.Lock()
						defer adapterMu.Unlock()
						descriptionCalls[record]++
						if !descriptionsEnabled {
							return resource.R3CallDescription{}, errors.New("proposal description source is no longer available")
						}
						return description, nil
					},
					Proposals: proposals,
					Retries:   retries,
				},
			},
			HeldInvocations: held,
			HoldAuthTokenRequest: func(request *http.Request) bool {
				return strings.HasPrefix(request.URL.Path, "/records/held-")
			},
			MaxRetainedRequestBodyBytes:  64 << 10,
			MaxRetainedResponseBodyBytes: 64 << 10,
			MaxRetainedHeaderBytes:       16 << 10,
		})
		if err != nil {
			t.Fatal(err)
		}
		return server
	}

	authTokenIDs := 0
	access, err := accessserver.New(accessserver.Config{
		Issuer: accessServerID, SigningKey: accessKey, KeyResolver: resolver, Clock: clock,
		NewID: func() string {
			authTokenIDs++
			return fmt.Sprintf("r3-per-call-auth-token-%d", authTokenIDs)
		},
		TrustPersonServer: func(_ context.Context, issuer string) error {
			if issuer != personServerID {
				return errors.New("untrusted Person Server")
			}
			return nil
		},
		Authorize: func(_ context.Context, _ accessserver.AuthorizationRequest) (accessserver.Decision, error) {
			return accessserver.Decision{}, errors.New("Core policy must not receive an R3 request")
		},
		R3: &accessserver.R3Config{
			Registry:   registry,
			HTTPClient: httpClient,
			Admit: func(_ context.Context, endpoint string) error {
				if !strings.HasPrefix(endpoint, resourceID+"/r3/") {
					return errors.New("unexpected R3 endpoint")
				}
				return nil
			},
			AuthorizeDocument: func(_ context.Context, request accessserver.AuthorizationRequest, _ r3.Reference, document r3.Document) (accessserver.R3DocumentDecision, error) {
				if err := validateR3PerCallAccessContext(request, personServerID, resourceID, personSubject, tenant, account, agentID); err != nil {
					return accessserver.R3DocumentDecision{}, err
				}
				if !vocabulary.operationSetsEqual(t, document.OperationSet(), requestedOperations) {
					return accessserver.R3DocumentDecision{}, errors.New("class policy did not receive the exact R3 document")
				}
				authorization, err := r3.NewAuthorization(emptyOperations, perCallOperations, document)
				if err != nil {
					return accessserver.R3DocumentDecision{}, err
				}
				observations.observeClassAS()
				return accessserver.R3DocumentDecision{
					Scopes: append([]string(nil), request.Scopes...), Lifetime: 30 * time.Minute,
					Authorization: &authorization,
				}, nil
			},
			AuthorizeProposal: func(_ context.Context, request accessserver.AuthorizationRequest, reference r3.Reference, proposal r3.Proposal) (accessserver.R3ProposalDecision, error) {
				if err := validateR3PerCallAccessContext(request, personServerID, resourceID, personSubject, tenant, account, agentID); err != nil {
					return accessserver.R3ProposalDecision{}, err
				}
				if !vocabulary.operationsEqual(t, proposal.Operation(), deleteRecord) {
					return accessserver.R3ProposalDecision{}, errors.New("proposal policy received a substituted R3 operation")
				}
				if err := observations.observeProposal("as", reference, proposal); err != nil {
					return accessserver.R3ProposalDecision{}, err
				}
				return accessserver.R3ProposalDecision{
					Scopes: append([]string(nil), request.Scopes...), Lifetime: 5 * time.Minute,
				}, nil
			},
			Issuances: issuances,
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	people, err := personserver.NewFederatedAuthorization(personserver.FederatedAuthorizationConfig{
		Issuer: personServerID, SigningKey: personKey, KeyResolver: resolver, Clock: clock,
		NewID:      func() string { return "r3-per-call-person-token" },
		HTTPClient: httpClient, Tokens: personTokens,
		AccessServerEndpoint: func(_ context.Context, issuer string) (string, error) {
			if issuer != accessServerID {
				return "", errors.New("unknown Access Server")
			}
			return accessServerID + "/token", nil
		},
		BindPerson: func(_ context.Context, request personserver.PersonTokenRequest) (personserver.Person, error) {
			if request.Agent != agentID || request.Resource != resourceID {
				return personserver.Person{}, errors.New("unexpected person-token request")
			}
			return personserver.Person{Subject: personSubject, Tenant: tenant, Lifetime: time.Hour}, nil
		},
		Consent: func(context.Context, personserver.AuthorizationRequest) error {
			return errors.New("Core consent must not receive an R3 request")
		},
		R3: &personserver.R3Config{
			Registry: registry,
			Admit: func(_ context.Context, endpoint string) error {
				if !strings.HasPrefix(endpoint, resourceID+"/r3/") {
					return errors.New("unexpected R3 endpoint")
				}
				return nil
			},
			ConsentDocument: func(_ context.Context, request personserver.AuthorizationRequest, _ r3.Reference, document r3.Document) error {
				if err := validateR3PerCallPersonContext(request, agentID, resourceID, personSubject, tenant, account); err != nil {
					return err
				}
				if !vocabulary.operationSetsEqual(t, document.OperationSet(), requestedOperations) {
					return errors.New("class consent did not receive the exact R3 document")
				}
				observations.observeClassPS()
				return nil
			},
			ConsentProposal: func(_ context.Context, request personserver.AuthorizationRequest, reference r3.Reference, proposal r3.Proposal) error {
				if err := validateR3PerCallPersonContext(request, agentID, resourceID, personSubject, tenant, account); err != nil {
					return err
				}
				if !vocabulary.operationsEqual(t, proposal.Operation(), deleteRecord) {
					return errors.New("proposal consent received a substituted operation")
				}
				return observations.observeProposal("ps", reference, proposal)
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	network.Handle(agentProviderID, traffic.wrap(agentProviderID, provider.Handler()))
	network.Handle(personServerID, traffic.wrap(personServerID, people.Handler()))
	network.Handle(accessServerID, traffic.wrap(accessServerID, r3PerCallAuditBeforeReleaseHandler(access.Handler(), issuances)))
	initialResource := newResource()
	requireIntegrationR3ResourceMetadata(t, initialResource.Handler(), resourceID)
	network.Handle(resourceID, traffic.wrap(resourceID, initialResource.Handler()))
	installResource := func() {
		network.Handle(resourceID, traffic.wrap(resourceID, newResource().Handler()))
	}

	agent, err := clientagent.New(ctx, clientagent.Config{
		Identifier: agentID, SigningKey: agentKey, AgentToken: agentToken,
		KeyResolver: resolver, HTTPClient: httpClient, Clock: clock,
		R3: &clientagent.R3Config{Registry: registry},
	})
	if err != nil {
		t.Fatal(err)
	}
	personResult, err := agent.PersonToken(ctx, clientagent.PersonTokenRequest{
		PersonServer: personServerID, Resource: resourceID,
	})
	if err != nil {
		t.Fatal(err)
	}
	personToken, ok := personResult.Token()
	if !ok {
		t.Fatalf("person-token result = %#v", personResult)
	}

	accountValue := account
	classResourceToken, err := agent.Authorize(ctx, clientagent.AuthorizeRequest{
		Resource: resourceID, PersonToken: personToken,
		Scopes: []string{r3PerCallScope}, Account: &accountValue, R3Operations: &requestedOperations,
	})
	if err != nil {
		t.Fatal(err)
	}
	classAuthToken, err := agent.Exchange(ctx, clientagent.ExchangeRequest{
		PersonServer: personServerID, ResourceToken: classResourceToken, PresentedToken: personToken,
	})
	if err != nil {
		psCalls, asCalls := observations.classCounts()
		t.Fatalf(
			"class exchange: %v; class PS/AS=%d/%d, document loads=%d, audits=%d",
			err, psCalls, asCalls, documents.loadCount(), issuances.count(),
		)
	}
	classClaims, classReference, classAuthorization, err := r3.VerifyAuthTokenClaims(ctx, registry, classAuthToken, resolver, clock)
	if err != nil {
		t.Fatal(err)
	}
	if classClaims.Account == nil || *classClaims.Account != account || classClaims.Tenant != tenant ||
		classClaims.Scope != r3PerCallScope ||
		len(classAuthorization.GrantedOperations().Operations()) != 0 ||
		!vocabulary.grantedEqual(t, classAuthorization.PerCallOperations(), perCallOperations) {
		t.Fatalf("class Auth token = claims %#v, operations %#v", classClaims, classAuthorization)
	}
	if ps, as := observations.classCounts(); ps != 1 || as != 1 {
		t.Fatalf("class PS/AS policy calls = %d/%d, want 1/1", ps, as)
	}
	if record, ok := issuances.recordForReference(classReference); !ok || record.AuthTokenReference.JTI == "" {
		t.Fatalf("class issuance audit = %#v, present=%t", record, ok)
	}

	// Baseline 401: create two distinct proposals, then prove the first token
	// cannot be paired with the second handle or the second call parameters.
	baselineA := newR3PerCallRequest(t, resourceID, "baseline-a")
	before := traffic.count()
	baselineAResult, err := agent.BeginR3Call(ctx, clientagent.R3Call{
		Request: baselineA, ClassAuthToken: classAuthToken, Operation: deleteRecord,
		AdditionalSignatureComponents: []string{"content-type", "content-digest"},
	})
	if err != nil {
		t.Fatal(err)
	}
	baselineAuthorizationA, ok := baselineAResult.AuthorizationRequired()
	if !ok {
		t.Fatalf("baseline call A result = %#v", baselineAResult)
	}
	requireSingleR3PerCallTraffic(t, traffic.since(before), resourceID, http.MethodPost, "/records/baseline-a")

	baselineB := newR3PerCallRequest(t, resourceID, "baseline-b")
	before = traffic.count()
	baselineBResult, err := agent.BeginR3Call(ctx, clientagent.R3Call{
		Request: baselineB, ClassAuthToken: classAuthToken, Operation: deleteRecord,
		AdditionalSignatureComponents: []string{"content-type", "content-digest"},
	})
	if err != nil {
		t.Fatal(err)
	}
	baselineAuthorizationB, ok := baselineBResult.AuthorizationRequired()
	if !ok || baselineAuthorizationB.Reference() == baselineAuthorizationA.Reference() {
		t.Fatalf("baseline call B result = %#v; A/B references = %#v/%#v", baselineBResult, baselineAuthorizationA.Reference(), baselineAuthorizationB.Reference())
	}
	requireSingleR3PerCallTraffic(t, traffic.since(before), resourceID, http.MethodPost, "/records/baseline-b")
	if executionCount("baseline-a") != 0 || executionCount("baseline-b") != 0 {
		t.Fatal("baseline proposal executed before approval")
	}

	// Fetch both proposal views through a freshly composed Resource. The exact
	// bytes live in the host stores, not in the old Server value.
	installResource()
	baselineAuthToken, err := agent.Exchange(ctx, clientagent.ExchangeRequest{
		PersonServer: personServerID, ResourceToken: baselineAuthorizationA.ResourceToken(), PresentedToken: classAuthToken,
	})
	if err != nil {
		t.Fatal(err)
	}
	requireR3PerCallProposalExchange(
		t, vocabulary, registry, proposals, observations, traffic, issuances,
		baselineAuthorizationA.Reference(), baselineAuthToken,
		deleteRecord, account, classClaims.JTI, agentID,
	)
	requireR3PerCallCompletionToken(t, vocabulary, ctx, registry, resolver, clock, baselineAuthToken, baselineAuthorizationA.Reference(), deleteRecord, account, tenant)

	before = traffic.count()
	if _, err := agent.RetryR3Call(ctx, clientagent.R3Retry{
		Authorization: baselineAuthorizationB, AuthToken: baselineAuthToken,
	}); err == nil {
		t.Fatal("Agent paired a proposal Auth token with another 401 continuation")
	}
	if got := len(traffic.since(before)); got != 0 {
		t.Fatalf("cross-proposal Agent refusal made %d hidden network calls", got)
	}

	changed := newR3PerCallRequest(t, resourceID, "baseline-b")
	changedResponse := sendR3PerCallTokenRequest(t, httpClient, clock, agentKey, baselineAuthToken, changed, true)
	changedBody := readAndCloseR3PerCallResponse(t, changedResponse)
	if changedResponse.StatusCode != http.StatusForbidden || executionCount("baseline-a") != 0 || executionCount("baseline-b") != 0 {
		t.Fatalf("changed/cross-proposal call = %d %s; executions A/B=%d/%d", changedResponse.StatusCode, changedBody, executionCount("baseline-a"), executionCount("baseline-b"))
	}

	// The proposal description source may change after approval. Retry uses
	// only concrete parameter extraction and the retained proposal.
	setDescriptionsEnabled(false)
	baselineA.Method = http.MethodGet
	baselineA.URL.Path = "/caller-mutated"
	baselineA.URL.RawQuery = "changed=true"
	baselineA.Header.Set("X-Request-ID", "caller-mutated")
	baselineA.Body = io.NopCloser(strings.NewReader("caller-mutated"))
	baselineA.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(strings.NewReader("caller-mutated")), nil
	}
	before = traffic.count()
	baselineResponse, err := agent.RetryR3Call(ctx, clientagent.R3Retry{
		Authorization: baselineAuthorizationA, AuthToken: baselineAuthToken,
	})
	if err != nil {
		t.Fatal(err)
	}
	baselineBody := readAndCloseR3PerCallResponse(t, baselineResponse)
	requireSingleR3PerCallTraffic(t, traffic.since(before), resourceID, http.MethodPost, "/records/baseline-a")
	if baselineResponse.StatusCode != http.StatusCreated || baselineBody != `{"record":"baseline-a","execution":1}` || executionCount("baseline-a") != 1 {
		t.Fatalf("baseline completion = %d %s; executions=%d", baselineResponse.StatusCode, baselineBody, executionCount("baseline-a"))
	}
	if descriptions, _ := adapterCounts("baseline-a"); descriptions != 1 {
		t.Fatalf("baseline proposal was re-described %d times", descriptions)
	}

	before = traffic.count()
	baselineReplay, err := agent.RetryR3Call(ctx, clientagent.R3Retry{
		Authorization: baselineAuthorizationA, AuthToken: baselineAuthToken,
	})
	if err != nil {
		t.Fatal(err)
	}
	baselineReplayBody := readAndCloseR3PerCallResponse(t, baselineReplay)
	requireSingleR3PerCallTraffic(t, traffic.since(before), resourceID, http.MethodPost, "/records/baseline-a")
	if baselineReplay.StatusCode != baselineResponse.StatusCode || baselineReplayBody != baselineBody || executionCount("baseline-a") != 1 {
		t.Fatalf("baseline exact-token replay = %d %s; want %d %s; executions=%d", baselineReplay.StatusCode, baselineReplayBody, baselineResponse.StatusCode, baselineBody, executionCount("baseline-a"))
	}

	// Preferred 202: the Agent sends one application call, then only a signed
	// bodyless GET. The Resource is recomposed before proposal fetch, execution,
	// and replay around the same proposal and held-invocation stores.
	setDescriptionsEnabled(true)
	heldA := newR3PerCallRequest(t, resourceID, "held-a")
	before = traffic.count()
	heldAResult, err := agent.BeginR3Call(ctx, clientagent.R3Call{
		Request: heldA, ClassAuthToken: classAuthToken, Operation: deleteRecord,
		AdditionalSignatureComponents: []string{"content-type", "content-digest"},
	})
	if err != nil {
		t.Fatal(err)
	}
	pendingA, ok := heldAResult.Pending()
	if !ok || pendingA.RetryAfter() != 5*time.Second || pendingA.Location() == "" {
		t.Fatalf("held call A result = %#v", heldAResult)
	}
	requireSingleR3PerCallTraffic(t, traffic.since(before), resourceID, http.MethodPost, "/records/held-a")

	heldB := newR3PerCallRequest(t, resourceID, "held-b")
	before = traffic.count()
	heldBResult, err := agent.BeginR3Call(ctx, clientagent.R3Call{
		Request: heldB, ClassAuthToken: classAuthToken, Operation: deleteRecord,
		AdditionalSignatureComponents: []string{"content-type", "content-digest"},
	})
	if err != nil {
		t.Fatal(err)
	}
	pendingB, ok := heldBResult.Pending()
	if !ok || pendingB.Reference() == pendingA.Reference() || pendingB.Location() == pendingA.Location() {
		t.Fatalf("held call B result = %#v; A/B=%#v/%#v", heldBResult, pendingA, pendingB)
	}
	requireSingleR3PerCallTraffic(t, traffic.since(before), resourceID, http.MethodPost, "/records/held-b")
	if executionCount("held-a") != 0 || executionCount("held-b") != 0 {
		t.Fatal("held proposal executed before approval")
	}

	installResource()
	heldAuthToken, err := agent.Exchange(ctx, clientagent.ExchangeRequest{
		PersonServer: personServerID, ResourceToken: pendingA.ResourceToken(), PresentedToken: classAuthToken,
	})
	if err != nil {
		t.Fatal(err)
	}
	requireR3PerCallProposalExchange(
		t, vocabulary, registry, proposals, observations, traffic, issuances,
		pendingA.Reference(), heldAuthToken,
		deleteRecord, account, classClaims.JTI, agentID,
	)
	requireR3PerCallCompletionToken(t, vocabulary, ctx, registry, resolver, clock, heldAuthToken, pendingA.Reference(), deleteRecord, account, tenant)

	before = traffic.count()
	if _, err := agent.PollR3Call(ctx, clientagent.R3Poll{Pending: pendingB, AuthToken: heldAuthToken}); err == nil {
		t.Fatal("Agent paired a proposal Auth token with another pending invocation")
	}
	if got := len(traffic.since(before)); got != 0 {
		t.Fatalf("cross-pending Agent refusal made %d hidden network calls", got)
	}

	crossPendingRequest, err := http.NewRequestWithContext(ctx, http.MethodGet, pendingB.Location(), nil)
	if err != nil {
		t.Fatal(err)
	}
	crossPendingResponse := sendR3PerCallTokenRequest(t, httpClient, clock, agentKey, heldAuthToken, crossPendingRequest, false)
	crossPendingBody := readAndCloseR3PerCallResponse(t, crossPendingResponse)
	if crossPendingResponse.StatusCode != http.StatusForbidden || executionCount("held-a") != 0 || executionCount("held-b") != 0 {
		t.Fatalf("cross-pending Resource call = %d %s; executions A/B=%d/%d", crossPendingResponse.StatusCode, crossPendingBody, executionCount("held-a"), executionCount("held-b"))
	}

	setDescriptionsEnabled(false)
	descriptionsBeforePoll, presentationsBeforePoll := adapterCounts("held-a")
	installResource()
	before = traffic.count()
	heldResponseResult, err := agent.PollR3Call(ctx, clientagent.R3Poll{Pending: pendingA, AuthToken: heldAuthToken})
	if err != nil {
		t.Fatal(err)
	}
	heldResponse, ok := heldResponseResult.Response()
	if !ok {
		t.Fatal("held poll returned no response")
	}
	heldBody := readAndCloseR3PerCallResponse(t, heldResponse)
	pollTraffic := requireSingleR3PerCallTraffic(t, traffic.since(before), resourceID, http.MethodGet, strings.TrimPrefix(pendingA.Location(), resourceID))
	if pollTraffic.ContentLength != 0 || pollTraffic.HasBody {
		t.Fatalf("held poll resent application content: %#v", pollTraffic)
	}
	if heldResponse.StatusCode != http.StatusCreated || heldBody != `{"record":"held-a","execution":1}` || executionCount("held-a") != 1 {
		t.Fatalf("held completion = %d %s; executions=%d", heldResponse.StatusCode, heldBody, executionCount("held-a"))
	}
	if descriptions, presentations := adapterCounts("held-a"); descriptions != descriptionsBeforePoll || presentations != presentationsBeforePoll {
		t.Fatalf("held poll re-entered call adapters: descriptions %d->%d, presentations %d->%d", descriptionsBeforePoll, descriptions, presentationsBeforePoll, presentations)
	}

	installResource()
	before = traffic.count()
	heldReplayResult, err := agent.PollR3Call(ctx, clientagent.R3Poll{Pending: pendingA, AuthToken: heldAuthToken})
	if err != nil {
		t.Fatal(err)
	}
	heldReplay, ok := heldReplayResult.Response()
	if !ok {
		t.Fatal("held poll returned no response")
	}
	heldReplayBody := readAndCloseR3PerCallResponse(t, heldReplay)
	requireSingleR3PerCallTraffic(t, traffic.since(before), resourceID, http.MethodGet, strings.TrimPrefix(pendingA.Location(), resourceID))
	if heldReplay.StatusCode != heldResponse.StatusCode || heldReplayBody != heldBody || executionCount("held-a") != 1 {
		t.Fatalf("held exact-token replay = %d %s; want %d %s; executions=%d", heldReplay.StatusCode, heldReplayBody, heldResponse.StatusCode, heldBody, executionCount("held-a"))
	}

	if executionCount("baseline-a") != 1 || executionCount("held-a") != 1 ||
		executionCount("baseline-b") != 0 || executionCount("held-b") != 0 {
		t.Fatalf("final executions = %#v", applicationCalls)
	}
	if proposals.count() != 4 || retries.count() != 2 || held.count() != 2 {
		t.Fatalf("retained proposal/retry/held records = %d/%d/%d, want 4/2/2", proposals.count(), retries.count(), held.count())
	}
	if claims, retains := retries.observation(baselineAuthorizationA.Reference()); claims != 2 || retains != 1 {
		t.Fatalf("baseline retry transitions = claims %d, retains %d; want 2/1", claims, retains)
	}
	if claims, retains := held.observation(pendingA.Location()); claims != 2 || retains != 1 {
		t.Fatalf("held transitions = claims %d, retains %d; want 2/1", claims, retains)
	}
	if violations := issuances.releaseViolationCount(); violations != 0 {
		t.Fatalf("Access Server released %d successful R3 responses before their audit commit", violations)
	}

	assertR3PerCallStoreCopies(t, ctx, proposals, retries, held, baselineAuthorizationA.Reference(), pendingA.Location())
}

func validateR3PerCallAccessContext(
	request accessserver.AuthorizationRequest,
	personServer, resourceID, subject, tenant, account, agentID string,
) error {
	if request.PersonServer != personServer || request.Resource != resourceID || request.Subject != subject ||
		request.Tenant != tenant || request.Account == nil || *request.Account != account ||
		!slices.Equal(request.Scopes, []string{r3PerCallScope}) || request.Agent.Identifier != agentID || request.Subagent != nil {
		return fmt.Errorf("unexpected Access Server context: %#v", request)
	}
	return nil
}

func validateR3PerCallPersonContext(
	request personserver.AuthorizationRequest,
	agentID, resourceID, subject, tenant, account string,
) error {
	if request.Agent != agentID || request.Subagent != "" || request.Resource != resourceID ||
		request.Subject != subject || request.Tenant != tenant || request.Account == nil ||
		*request.Account != account || !slices.Equal(request.Scopes, []string{r3PerCallScope}) {
		return fmt.Errorf("unexpected Person Server context: %#v", request)
	}
	return nil
}

func describeR3PerCall(
	t *testing.T,
	vocabulary integrationR3Vocabulary,
	invocation r3.Invocation,
	gotAccount *string,
	wantOperation r3.Operation,
	wantAccount string,
) (string, resource.R3CallDescription, error) {
	if gotAccount == nil || *gotAccount != wantAccount ||
		!vocabulary.operationsEqual(t, invocation.Operation(), wantOperation) {
		return "", resource.R3CallDescription{}, errors.New("unexpected concrete R3 invocation context")
	}
	presented := invocation.PresentedParameters()
	recordValue, ok := presented["record"]
	if !ok {
		return "", resource.R3CallDescription{}, errors.New("R3 invocation is missing record")
	}
	recordJSON, ok := recordValue.InlineJSON()
	if !ok {
		return "", resource.R3CallDescription{}, errors.New("R3 invocation record is not inline JSON")
	}
	var record string
	if err := json.Unmarshal(recordJSON, &record); err != nil || record == "" {
		return "", resource.R3CallDescription{}, errors.New("R3 invocation record is invalid")
	}
	payloadValue, ok := presented["payload"]
	if !ok {
		return "", resource.R3CallDescription{}, errors.New("R3 invocation is missing payload")
	}
	body, ok := payloadValue.ExactBytes()
	if !ok {
		return "", resource.R3CallDescription{}, errors.New("R3 invocation payload is not digest-backed bytes")
	}
	recordParameter, err := r3.NewInlineParameter(recordJSON)
	if err != nil {
		return "", resource.R3CallDescription{}, err
	}
	payloadParameter, err := r3.NewDigestParameterFromBytes(body, string(body), "application/json")
	if err != nil {
		return "", resource.R3CallDescription{}, err
	}
	parameters, err := r3.NewParameters(map[string]r3.Parameter{
		"record": recordParameter, "payload": payloadParameter,
	})
	if err != nil {
		return "", resource.R3CallDescription{}, err
	}
	display, err := r3.NewDisplay(
		"Delete record "+record,
		"The record will no longer be available",
		"Record "+record+" and the submitted deletion reason",
		"Deletion cannot be undone",
	)
	if err != nil {
		return "", resource.R3CallDescription{}, err
	}
	proposalDisplay, err := r3.NewProposalDisplay(
		display,
		"## Action\nDelete record "+record+"\n\n## Irreversible\nThis deletion cannot be undone.",
	)
	if err != nil {
		return "", resource.R3CallDescription{}, err
	}
	return record, resource.R3CallDescription{Parameters: parameters, Display: &proposalDisplay}, nil
}

func presentedR3PerCallParameters(
	t *testing.T,
	vocabulary integrationR3Vocabulary,
	request *http.Request,
	operation r3.Operation,
	wantOperation r3.Operation,
) (string, map[string]r3.PresentedParameter, error) {
	record, body, err := validateR3PerCallAdapterInput(t, vocabulary, request, operation, wantOperation)
	if err != nil {
		return "", nil, err
	}
	recordJSON, _ := json.Marshal(record)
	presentedRecord, err := r3.NewPresentedInlineParameter(recordJSON)
	if err != nil {
		return "", nil, err
	}
	return record, map[string]r3.PresentedParameter{
		"record":  presentedRecord,
		"payload": r3.NewPresentedDigestBytes(body),
	}, nil
}

func validateR3PerCallAdapterInput(
	t *testing.T,
	vocabulary integrationR3Vocabulary,
	request *http.Request,
	operation r3.Operation,
	wantOperation r3.Operation,
) (string, []byte, error) {
	if request == nil || request.URL == nil || request.Method != http.MethodPost ||
		request.URL.RawQuery != "mode=purge" || request.Header.Get("X-Request-ID") == "" ||
		request.Header.Get("X-Caller-Context") == "" {
		return "", nil, errors.New("unexpected concrete R3 call context")
	}
	if !vocabulary.operationsEqual(t, operation, wantOperation) {
		return "", nil, errors.New("unexpected concrete R3 operation")
	}
	record := strings.TrimPrefix(request.URL.Path, "/records/")
	if record == "" || record == request.URL.Path || strings.Contains(record, "/") {
		return "", nil, errors.New("invalid record path")
	}
	if request.Header.Get("X-Request-ID") != "request-"+record ||
		request.Header.Get("X-Caller-Context") != "preserve-"+record {
		return "", nil, errors.New("invalid call headers")
	}
	body, err := io.ReadAll(request.Body)
	if err != nil {
		return "", nil, err
	}
	request.Body = io.NopCloser(bytes.NewReader(body))
	if len(body) == 0 || !json.Valid(body) {
		return "", nil, errors.New("invalid deletion payload")
	}
	return record, body, nil
}

func parseR3PerCallRequest(request *http.Request) (string, []byte, error) {
	if request == nil || request.URL == nil || request.Method != http.MethodPost ||
		request.URL.RawQuery != "mode=purge" {
		return "", nil, errors.New("request identity changed")
	}
	record := strings.TrimPrefix(request.URL.Path, "/records/")
	if record == "" || record == request.URL.Path || strings.Contains(record, "/") {
		return "", nil, errors.New("record path changed")
	}
	if request.Header.Get("X-Request-ID") != "request-"+record ||
		request.Header.Get("X-Caller-Context") != "preserve-"+record {
		return "", nil, errors.New("request headers changed")
	}
	body, err := io.ReadAll(request.Body)
	if err != nil {
		return "", nil, err
	}
	return record, body, nil
}

func newR3PerCallRequest(t *testing.T, resourceID, record string) *http.Request {
	t.Helper()
	request, err := http.NewRequest(
		http.MethodPost,
		resourceID+"/records/"+record+"?mode=purge",
		bytes.NewReader(r3PerCallBody(record)),
	)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Request-ID", "request-"+record)
	request.Header.Set("X-Caller-Context", "preserve-"+record)
	return request
}

func r3PerCallBody(record string) []byte {
	return []byte(fmt.Sprintf(`{"reason":"duplicate","record":%q}`, record))
}

func sendR3PerCallTokenRequest(
	t *testing.T,
	httpClient *http.Client,
	clock aauth.Clock,
	agentKey jose.SigningKey,
	compact string,
	request *http.Request,
	withApplicationComponents bool,
) *http.Response {
	t.Helper()
	options := signaturekey.SignOptions{}
	if withApplicationComponents {
		options.AdditionalComponents = []string{"content-type", "content-digest"}
		options.MaxBodyBytes = 64 << 10
	}
	if err := signaturekey.SignJWTRequestWithOptions(request, agentKey, compact, clock, options); err != nil {
		t.Fatal(err)
	}
	response, err := httpClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func readAndCloseR3PerCallResponse(t *testing.T, response *http.Response) string {
	t.Helper()
	if response == nil || response.Body == nil {
		t.Fatal("response body is required")
	}
	body, err := io.ReadAll(response.Body)
	closeErr := response.Body.Close()
	if err != nil || closeErr != nil {
		t.Fatal(errors.Join(err, closeErr))
	}
	return string(body)
}

func requireR3PerCallCompletionToken(
	t *testing.T,
	vocabulary integrationR3Vocabulary,
	ctx context.Context,
	registry r3.Registry,
	resolver signaturekey.KeyResolver,
	clock aauth.Clock,
	compact string,
	wantReference r3.Reference,
	wantOperation r3.Operation,
	wantAccount, wantTenant string,
) {
	t.Helper()
	claims, reference, operations, err := r3.VerifyAuthTokenClaims(ctx, registry, compact, resolver, clock)
	if err != nil {
		t.Fatal(err)
	}
	granted := operations.GrantedOperations().Operations()
	if reference != wantReference || len(granted) != 1 || !vocabulary.operationsEqual(t, granted[0], wantOperation) ||
		len(operations.PerCallOperations().Operations()) != 0 || claims.Account == nil ||
		*claims.Account != wantAccount || claims.Tenant != wantTenant ||
		!slices.Equal(strings.Fields(claims.Scope), []string{r3PerCallScope}) {
		t.Fatalf("proposal Auth token = claims %#v, reference %#v, operations %#v", claims, reference, operations)
	}
}

func requireR3PerCallProposalExchange(
	t *testing.T,
	vocabulary integrationR3Vocabulary,
	registry r3.Registry,
	proposals *r3PerCallProposalStore,
	observations *r3PerCallPolicyObservations,
	traffic *r3PerCallTraffic,
	issuances *r3PerCallIssuanceStore,
	reference r3.Reference,
	compact string,
	wantOperation r3.Operation,
	wantAccount, wantPresentedJTI, wantAgent string,
) {
	t.Helper()
	record, err := proposals.Load(context.Background(), reference.URI())
	if err != nil {
		t.Fatal(err)
	}
	proposal, err := registry.ParseReferencedProposal(reference, record.ExactJSON)
	if err != nil {
		t.Fatal(err)
	}
	proposalAccount, hasAccount := proposal.Account()
	display, hasDisplay := proposal.Display()
	if !vocabulary.operationsEqual(t, proposal.Operation(), wantOperation) || !hasAccount || proposalAccount != wantAccount ||
		!hasDisplay || display.Summary() == "" || display.Detail() == "" ||
		!slices.Equal(proposal.Parameters().Names(), []string{"payload", "record"}) {
		t.Fatalf("retained proposal = %#v", proposal)
	}
	for _, role := range []string{"ps", "as"} {
		exact, calls := observations.proposal(role, reference)
		if calls != 1 || !bytes.Equal(exact, record.ExactJSON) {
			t.Fatalf("%s proposal observation calls=%d exact=%s, want %s", role, calls, exact, record.ExactJSON)
		}
	}
	fetches := traffic.proposalFetches(reference.URI())
	if len(fetches) != 2 {
		t.Fatalf("proposal fetches for %s = %#v, want one PS and one AS fetch", reference.URI(), fetches)
	}
	roles := make([]string, 0, len(fetches))
	for _, fetch := range fetches {
		if fetch.Signature == "" || fetch.SignatureInput == "" || fetch.SignatureKey == "" {
			t.Fatalf("unsigned proposal fetch = %#v", fetch)
		}
		switch {
		case strings.Contains(fetch.SignatureKey, aauth.PersonDiscoveryDocument):
			roles = append(roles, "ps")
		case strings.Contains(fetch.SignatureKey, aauth.AccessDiscoveryDocument):
			roles = append(roles, "as")
		default:
			t.Fatalf("proposal fetched under an unexpected role: %#v", fetch)
		}
	}
	slices.Sort(roles)
	if !slices.Equal(roles, []string{"as", "ps"}) {
		t.Fatalf("proposal fetch roles = %v", roles)
	}
	audit, ok := issuances.recordForReference(reference)
	if !ok || audit.R3Reference != reference ||
		audit.Resource != "https://resource.example" || audit.PersonServer != "https://ps.example" ||
		audit.Subject != "person-123" || audit.Account == nil || *audit.Account != wantAccount ||
		audit.PresentedJTI != wantPresentedJTI || audit.AgentJKT == "" ||
		audit.Agent != wantAgent || audit.ParentAgent != "" {
		t.Fatalf("proposal issuance audit = %#v, present=%t", audit, ok)
	}
}

type r3PerCallTrafficRecord struct {
	Origin         string
	Method         string
	URL            string
	Path           string
	ContentLength  int64
	HasBody        bool
	Signature      string
	SignatureInput string
	SignatureKey   string
}

type r3PerCallTraffic struct {
	mu      sync.Mutex
	records []r3PerCallTrafficRecord
}

func (traffic *r3PerCallTraffic) wrap(origin string, handler http.Handler) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		record := r3PerCallTrafficRecord{
			Origin: origin, Method: request.Method, URL: request.URL.String(), Path: request.URL.Path,
			ContentLength: request.ContentLength,
			HasBody:       request.Body != nil && request.Body != http.NoBody && request.ContentLength != 0,
			Signature:     request.Header.Get("Signature"), SignatureInput: request.Header.Get("Signature-Input"),
			SignatureKey: request.Header.Get("Signature-Key"),
		}
		traffic.mu.Lock()
		traffic.records = append(traffic.records, record)
		traffic.mu.Unlock()
		handler.ServeHTTP(response, request)
	})
}

func (traffic *r3PerCallTraffic) count() int {
	traffic.mu.Lock()
	defer traffic.mu.Unlock()
	return len(traffic.records)
}

func (traffic *r3PerCallTraffic) since(index int) []r3PerCallTrafficRecord {
	traffic.mu.Lock()
	defer traffic.mu.Unlock()
	if index < 0 || index > len(traffic.records) {
		return nil
	}
	return append([]r3PerCallTrafficRecord(nil), traffic.records[index:]...)
}

func (traffic *r3PerCallTraffic) proposalFetches(uri string) []r3PerCallTrafficRecord {
	traffic.mu.Lock()
	defer traffic.mu.Unlock()
	var result []r3PerCallTrafficRecord
	for _, record := range traffic.records {
		if record.Method == http.MethodGet && record.URL == uri {
			result = append(result, record)
		}
	}
	return result
}

func requireSingleR3PerCallTraffic(
	t *testing.T,
	records []r3PerCallTrafficRecord,
	wantOrigin, wantMethod, wantPath string,
) r3PerCallTrafficRecord {
	t.Helper()
	if len(records) != 1 || records[0].Origin != wantOrigin || records[0].Method != wantMethod || records[0].Path != wantPath {
		t.Fatalf("network calls = %#v, want exactly %s %s%s", records, wantMethod, wantOrigin, wantPath)
	}
	return records[0]
}

type r3PerCallPolicyObservations struct {
	mu             sync.Mutex
	classPS        int
	classAS        int
	proposalByRole map[string]map[string]r3PerCallProposalObservation
}

type r3PerCallProposalObservation struct {
	exact []byte
	calls int
}

func newR3PerCallPolicyObservations() *r3PerCallPolicyObservations {
	return &r3PerCallPolicyObservations{proposalByRole: map[string]map[string]r3PerCallProposalObservation{
		"ps": {}, "as": {},
	}}
}

func (observations *r3PerCallPolicyObservations) observeClassPS() {
	observations.mu.Lock()
	defer observations.mu.Unlock()
	observations.classPS++
}

func (observations *r3PerCallPolicyObservations) observeClassAS() {
	observations.mu.Lock()
	defer observations.mu.Unlock()
	observations.classAS++
}

func (observations *r3PerCallPolicyObservations) classCounts() (ps, as int) {
	observations.mu.Lock()
	defer observations.mu.Unlock()
	return observations.classPS, observations.classAS
}

func (observations *r3PerCallPolicyObservations) observeProposal(role string, reference r3.Reference, proposal r3.Proposal) error {
	exact, err := json.Marshal(proposal)
	if err != nil {
		return err
	}
	observations.mu.Lock()
	defer observations.mu.Unlock()
	byRole, ok := observations.proposalByRole[role]
	if !ok {
		return errors.New("unexpected proposal policy role")
	}
	observation := byRole[reference.URI()]
	if observation.calls != 0 && !bytes.Equal(observation.exact, exact) {
		return errors.New("proposal policy received different bytes for one reference")
	}
	observation.exact = append([]byte(nil), exact...)
	observation.calls++
	byRole[reference.URI()] = observation
	return nil
}

func (observations *r3PerCallPolicyObservations) proposal(role string, reference r3.Reference) ([]byte, int) {
	observations.mu.Lock()
	defer observations.mu.Unlock()
	observation := observations.proposalByRole[role][reference.URI()]
	return append([]byte(nil), observation.exact...), observation.calls
}

func r3PerCallAuditBeforeReleaseHandler(next http.Handler, store *r3PerCallIssuanceStore) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		before := store.count()
		buffer := httptest.NewRecorder()
		next.ServeHTTP(buffer, request)
		if request.Method == http.MethodPost && request.URL.Path == "/token" &&
			buffer.Code == http.StatusOK && store.count() <= before {
			store.recordReleaseViolation()
		}
		for name, values := range buffer.Header() {
			for _, value := range values {
				response.Header().Add(name, value)
			}
		}
		response.WriteHeader(buffer.Code)
		_, _ = response.Write(buffer.Body.Bytes())
	})
}

type r3PerCallIssuanceStore struct {
	mu                sync.Mutex
	records           []r3.IssuanceRecord
	releaseViolations int
}

func newR3PerCallIssuanceStore() *r3PerCallIssuanceStore {
	return &r3PerCallIssuanceStore{}
}

func (store *r3PerCallIssuanceStore) Commit(_ context.Context, record r3.IssuanceRecord) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	record = cloneIntegrationR3Issuance(record)
	for _, retained := range store.records {
		if retained.AuthTokenReference != record.AuthTokenReference {
			continue
		}
		if !reflect.DeepEqual(retained, record) {
			return r3.ErrIssuanceConflict
		}
		return nil
	}
	store.records = append(store.records, record)
	return nil
}

func (store *r3PerCallIssuanceStore) count() int {
	store.mu.Lock()
	defer store.mu.Unlock()
	return len(store.records)
}

func (store *r3PerCallIssuanceStore) recordForReference(reference r3.Reference) (r3.IssuanceRecord, bool) {
	store.mu.Lock()
	defer store.mu.Unlock()
	for _, record := range store.records {
		if record.R3Reference == reference {
			return cloneIntegrationR3Issuance(record), true
		}
	}
	return r3.IssuanceRecord{}, false
}

func (store *r3PerCallIssuanceStore) recordReleaseViolation() {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.releaseViolations++
}

func (store *r3PerCallIssuanceStore) releaseViolationCount() int {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.releaseViolations
}

var _ r3.IssuanceStore = (*r3PerCallIssuanceStore)(nil)

type r3PerCallProposalStore struct {
	mu       sync.Mutex
	records  map[string]resource.R3ProposalRecord
	registry r3.Registry
}

func newR3PerCallProposalStore(registry r3.Registry) *r3PerCallProposalStore {
	return &r3PerCallProposalStore{records: make(map[string]resource.R3ProposalRecord), registry: registry}
}

func (store *r3PerCallProposalStore) Commit(_ context.Context, record resource.R3ProposalRecord) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if _, err := store.registry.ParseReferencedProposal(record.Reference, record.ExactJSON); err != nil {
		return err
	}
	record = cloneR3PerCallProposalRecord(record)
	if _, ok := store.records[record.Reference.URI()]; ok {
		return resource.ErrR3ProposalConflict
	}
	store.records[record.Reference.URI()] = record
	return nil
}

func (store *r3PerCallProposalStore) Load(_ context.Context, uri string) (resource.R3ProposalRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	record, ok := store.records[uri]
	if !ok {
		return resource.R3ProposalRecord{}, resource.ErrR3ProposalNotFound
	}
	return cloneR3PerCallProposalRecord(record), nil
}

func (store *r3PerCallProposalStore) count() int {
	store.mu.Lock()
	defer store.mu.Unlock()
	return len(store.records)
}

func cloneR3PerCallProposalRecord(record resource.R3ProposalRecord) resource.R3ProposalRecord {
	record.ExactJSON = append([]byte(nil), record.ExactJSON...)
	return record
}

var _ resource.R3ProposalStore = (*r3PerCallProposalStore)(nil)

type r3PerCallRetryStore struct {
	mu        sync.Mutex
	records   map[string]*r3PerCallRetryEntry
	nextFence int
}

type r3PerCallRetryEntry struct {
	invocation resource.R3RetryInvocation
	state      string
	token      resource.R3RetryAuthToken
	fence      string
	response   resource.HeldResponse
	claims     int
	retains    int
}

func newR3PerCallRetryStore() *r3PerCallRetryStore {
	return &r3PerCallRetryStore{records: make(map[string]*r3PerCallRetryEntry)}
}

func (store *r3PerCallRetryStore) Prepare(_ context.Context, invocation resource.R3RetryInvocation) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	key := invocation.Reference.URI()
	invocation = cloneR3PerCallRetryInvocation(invocation)
	if retained, ok := store.records[key]; ok {
		if !reflect.DeepEqual(retained.invocation, invocation) {
			return resource.ErrR3RetryConflict
		}
		return nil
	}
	store.records[key] = &r3PerCallRetryEntry{invocation: invocation, state: "pending"}
	return nil
}

func (store *r3PerCallRetryStore) Load(_ context.Context, reference r3.Reference) (resource.R3RetryInvocation, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	entry, ok := store.records[reference.URI()]
	if !ok {
		return resource.R3RetryInvocation{}, resource.ErrR3RetryNotFound
	}
	return cloneR3PerCallRetryInvocation(entry.invocation), nil
}

func (store *r3PerCallRetryStore) Claim(
	_ context.Context,
	reference r3.Reference,
	token resource.R3RetryAuthToken,
) (resource.R3RetryClaim, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	entry, ok := store.records[reference.URI()]
	if !ok {
		return resource.R3RetryClaim{}, resource.ErrR3RetryNotFound
	}
	entry.claims++
	switch entry.state {
	case "pending":
		if !token.PresentedAt.Before(entry.invocation.CompletionUntil) {
			entry.state = "expired"
			return resource.R3RetryClaim{}, resource.ErrR3RetryExpired
		}
		store.nextFence++
		entry.state = "executing"
		entry.token = token
		entry.fence = fmt.Sprintf("r3-retry-fence-%d", store.nextFence)
		return resource.NewHeldExecution(resource.HeldExecution{
			InvocationID: reference.URI(), Fence: entry.fence,
		}), nil
	case "executing":
		return resource.R3RetryClaim{}, resource.ErrR3RetryConflict
	case "complete":
		if entry.token.SHA256 != token.SHA256 {
			return resource.R3RetryClaim{}, resource.ErrR3RetryTokenMismatch
		}
		return resource.NewHeldReplay(cloneHeldResponse(entry.response)), nil
	case "expired":
		return resource.R3RetryClaim{}, resource.ErrR3RetryExpired
	case "unresolved":
		return resource.R3RetryClaim{}, resource.ErrR3RetryUnresolved
	default:
		return resource.R3RetryClaim{}, resource.ErrR3RetryConflict
	}
}

func (store *r3PerCallRetryStore) Retain(
	_ context.Context,
	execution resource.R3RetryExecution,
	response resource.HeldResponse,
) (resource.HeldResponse, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	entry, ok := store.records[execution.InvocationID]
	if !ok || entry.state != "executing" || entry.fence != execution.Fence {
		return resource.HeldResponse{}, resource.ErrR3RetryCompletionStale
	}
	entry.response = cloneHeldResponse(response)
	entry.state = "complete"
	entry.retains++
	return cloneHeldResponse(entry.response), nil
}

func (store *r3PerCallRetryStore) count() int {
	store.mu.Lock()
	defer store.mu.Unlock()
	return len(store.records)
}

func (store *r3PerCallRetryStore) observation(reference r3.Reference) (claims, retains int) {
	store.mu.Lock()
	defer store.mu.Unlock()
	entry := store.records[reference.URI()]
	if entry == nil {
		return 0, 0
	}
	return entry.claims, entry.retains
}

func cloneR3PerCallRetryInvocation(invocation resource.R3RetryInvocation) resource.R3RetryInvocation {
	invocation.ExactProposal = append([]byte(nil), invocation.ExactProposal...)
	invocation.RequiredScopes = append([]string(nil), invocation.RequiredScopes...)
	return invocation
}

var _ resource.R3RetryStore = (*r3PerCallRetryStore)(nil)

type r3PerCallHeldStore struct {
	mu      sync.Mutex
	records map[string]*r3PerCallHeldEntry
	nextID  int
}

type r3PerCallHeldEntry struct {
	invocation resource.HeldInvocation
	state      string
	token      resource.HeldAuthToken
	fence      string
	response   resource.HeldResponse
	claims     int
	retains    int
}

func newR3PerCallHeldStore() *r3PerCallHeldStore {
	return &r3PerCallHeldStore{records: make(map[string]*r3PerCallHeldEntry)}
}

func (store *r3PerCallHeldStore) Create(_ context.Context, invocation resource.HeldInvocation) (string, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.nextID++
	id := fmt.Sprintf("r3-held-%016d", store.nextID)
	store.records[id] = &r3PerCallHeldEntry{
		invocation: cloneHeldInvocation(invocation), state: "pending",
	}
	return id, nil
}

func (store *r3PerCallHeldStore) Load(_ context.Context, id string) (resource.HeldInvocation, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	entry, ok := store.records[id]
	if !ok {
		return resource.HeldInvocation{}, resource.ErrHeldInvocationNotFound
	}
	return cloneHeldInvocation(entry.invocation), nil
}

func (store *r3PerCallHeldStore) Claim(
	_ context.Context,
	id string,
	token resource.HeldAuthToken,
) (resource.HeldClaim, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	entry, ok := store.records[id]
	if !ok {
		return resource.HeldClaim{}, resource.ErrHeldInvocationNotFound
	}
	entry.claims++
	switch entry.state {
	case "pending":
		if !token.PresentedAt.Before(entry.invocation.CompletionUntil) {
			entry.state = "expired"
			return resource.HeldClaim{}, resource.ErrHeldInvocationExpired
		}
		entry.state = "executing"
		entry.token = token
		entry.fence = "fence-" + id
		return resource.NewHeldExecution(resource.HeldExecution{InvocationID: id, Fence: entry.fence}), nil
	case "executing":
		return resource.HeldClaim{}, resource.ErrHeldInvocationConflict
	case "complete":
		if entry.token.SHA256 != token.SHA256 {
			return resource.HeldClaim{}, resource.ErrHeldAuthTokenMismatch
		}
		return resource.NewHeldReplay(cloneHeldResponse(entry.response)), nil
	case "expired":
		return resource.HeldClaim{}, resource.ErrHeldInvocationExpired
	case "unresolved":
		return resource.HeldClaim{}, resource.ErrHeldExecutionUnresolved
	default:
		return resource.HeldClaim{}, resource.ErrHeldInvocationConflict
	}
}

func (store *r3PerCallHeldStore) Retain(
	_ context.Context,
	execution resource.HeldExecution,
	response resource.HeldResponse,
) (resource.HeldResponse, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	entry, ok := store.records[execution.InvocationID]
	if !ok || entry.state != "executing" || entry.fence != execution.Fence {
		return resource.HeldResponse{}, resource.ErrHeldCompletionStale
	}
	entry.response = cloneHeldResponse(response)
	entry.state = "complete"
	entry.retains++
	return cloneHeldResponse(entry.response), nil
}

func (store *r3PerCallHeldStore) count() int {
	store.mu.Lock()
	defer store.mu.Unlock()
	return len(store.records)
}

func (store *r3PerCallHeldStore) observation(location string) (claims, retains int) {
	store.mu.Lock()
	defer store.mu.Unlock()
	id := location[strings.LastIndex(location, "/")+1:]
	entry := store.records[id]
	if entry == nil {
		return 0, 0
	}
	return entry.claims, entry.retains
}

func (store *r3PerCallHeldStore) Rechallenge(_ context.Context, id string, challenge resource.HeldRechallenge) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	entry, ok := store.records[id]
	if !ok {
		return resource.ErrHeldInvocationNotFound
	}
	switch entry.state {
	case "pending":
	case "complete":
		return resource.ErrHeldAuthTokenMismatch
	case "expired":
		return resource.ErrHeldInvocationExpired
	default:
		return resource.ErrHeldInvocationConflict
	}
	if entry.invocation.ResourceToken != challenge.Previous {
		return resource.ErrHeldInvocationConflict
	}
	entry.invocation.ResourceToken = challenge.ResourceToken
	entry.invocation.ResourceTokenIssuedAt = challenge.ResourceTokenIssuedAt
	entry.invocation.ExpiresAt = challenge.ExpiresAt
	entry.invocation.CompletionUntil = challenge.CompletionUntil
	return nil
}

var _ resource.HeldBudgetStore = (*r3PerCallHeldStore)(nil)

func assertR3PerCallStoreCopies(
	t *testing.T,
	ctx context.Context,
	proposals *r3PerCallProposalStore,
	retries *r3PerCallRetryStore,
	held *r3PerCallHeldStore,
	reference r3.Reference,
	heldLocation string,
) {
	t.Helper()
	proposal, err := proposals.Load(ctx, reference.URI())
	if err != nil {
		t.Fatal(err)
	}
	wantProposal := append([]byte(nil), proposal.ExactJSON...)
	proposal.ExactJSON[0] ^= 0xff
	reloadedProposal, err := proposals.Load(ctx, reference.URI())
	if err != nil || !bytes.Equal(reloadedProposal.ExactJSON, wantProposal) {
		t.Fatalf("proposal store leaked mutable bytes: %v, %x want %x", err, reloadedProposal.ExactJSON, wantProposal)
	}

	retry, err := retries.Load(ctx, reference)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(retry.RequiredScopes, []string{r3PerCallScope}) {
		t.Fatalf("retry store lost required scopes: %#v", retry.RequiredScopes)
	}
	retry.RequiredScopes[0] = "mutated-scope"
	reloadedRetry, err := retries.Load(ctx, reference)
	if err != nil || slices.Contains(reloadedRetry.RequiredScopes, "mutated-scope") {
		t.Fatalf("retry store leaked mutable scopes: %#v, %v", reloadedRetry, err)
	}

	id := heldLocation[strings.LastIndex(heldLocation, "/")+1:]
	invocation, err := held.Load(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if len(invocation.Body) == 0 || invocation.R3PerCall == nil {
		t.Fatalf("held copy is incomplete: %#v", invocation)
	}
	wantBody := append([]byte(nil), invocation.Body...)
	invocation.Body[0] ^= 0xff
	invocation.Header.Set("X-Request-ID", "mutated")
	invocation.R3PerCall.Reference = r3.Reference{}
	reloadedInvocation, err := held.Load(ctx, id)
	if err != nil || !bytes.Equal(reloadedInvocation.Body, wantBody) ||
		reloadedInvocation.Header.Get("X-Request-ID") == "mutated" ||
		reloadedInvocation.R3PerCall == nil || reloadedInvocation.R3PerCall.Reference.URI() == "" {
		t.Fatalf("held store leaked mutable invocation state: %#v, %v", reloadedInvocation, err)
	}
}
