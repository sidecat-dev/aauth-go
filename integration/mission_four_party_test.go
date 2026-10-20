package integration_test

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/accessserver"
	clientagent "gitlab.com/sidecat-dev/aauth-go/agent"
	"gitlab.com/sidecat-dev/aauth-go/agentprovider"
	"gitlab.com/sidecat-dev/aauth-go/budgets"
	"gitlab.com/sidecat-dev/aauth-go/personserver"
	"gitlab.com/sidecat-dev/aauth-go/r3"
	"gitlab.com/sidecat-dev/aauth-go/resource"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

// TestMissionBoundImmediateFourPartyR3BudgetJourney covers Core sections
// "Resource Token Verification", "PS-AS Federation", and "Mission Log" at
// the exact pinned source revision plus the fixed-price Budgets profile. The
// PS alone evaluates the retained mission and ordered accepted updates; the AS
// receives only mission_s256 plus ordinary authorization and Budget context.
func TestMissionBoundImmediateFourPartyR3BudgetJourney(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	now := time.Date(2026, 8, 30, 22, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	const (
		agentProviderID = "https://ap.example"
		agentID         = "aauth:reader@ap.example"
		personServerID  = "https://ps.example"
		accessServerID  = "https://as.example"
		resourceID      = "https://resource.example"
		scope           = "records.read"
	)
	missionExpiry := now.Add(4 * time.Minute)
	unit, err := budgets.NewUnit("USD", 6)
	if err != nil {
		t.Fatal(err)
	}
	registry := newIntegrationR3Registry(t)
	vocabulary := integrationR3Vocabularies()[0]
	readOperation := vocabulary.newOperation(t, "records.read")
	requestedOperations, err := r3.NewOperationSet(readOperation)
	if err != nil {
		t.Fatal(err)
	}
	display, err := r3.NewDisplay("Read records", "", "Record contents", "")
	if err != nil {
		t.Fatal(err)
	}
	requestedBudget := integrationBudgetValue(t, 800_000, unit)
	resourceOffer := integrationBudgetValue(t, 600_000, unit)
	personCeiling := integrationBudgetValue(t, 450_000, unit)
	accessGrant := integrationBudgetValue(t, 300_000, unit)
	declaration, err := budgets.NewBoundedUnitDeclaration(
		unit, 1_000_000, "US dollars at micro-dollar precision",
	)
	if err != nil {
		t.Fatal(err)
	}

	providerKey := newSigningKey(t, "mission-four-party-ap")
	agentKey := newSigningKey(t, "mission-four-party-agent")
	personKey := newSigningKey(t, "mission-four-party-ps")
	accessKey := newSigningKey(t, "mission-four-party-as")
	resourceKey := newSigningKey(t, "mission-four-party-resource")
	network := newLogicalTransport()
	httpClient := &http.Client{Transport: network}
	resolver, err := signaturekey.NewHTTPKeyResolver(signaturekey.HTTPKeyResolverConfig{
		Client: httpClient,
		Clock:  clock,
		Admit: func(_ context.Context, endpoint string) error {
			if strings.Contains(endpoint, ".example/.well-known/") {
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
		NewID: func() string { return "mission-four-party-agent-token" },
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

	store := newMissionFourPartyStore()
	personIDs := []string{"mission-four-party-person", "mission-four-party-race-person"}
	resourceIDs := []string{"mission-four-party-resource", "mission-four-party-race-resource"}
	authIDs := []string{"mission-four-party-auth", "mission-four-party-race-auth"}
	var consentMissions []personserver.MissionContext
	var consentAttempts int
	var acceptedCompletions []personserver.MissionCompletionPolicyRequest
	newPeople := func() *personserver.Server {
		people, err := personserver.NewFederatedAuthorization(personserver.FederatedAuthorizationConfig{
			Issuer: personServerID, SigningKey: personKey, KeyResolver: resolver,
			Clock: clock, Tokens: store, HTTPClient: httpClient,
			NewID: func() string {
				id := personIDs[0]
				personIDs = personIDs[1:]
				return id
			},
			Missions: &personserver.MissionConfig{
				Approve: func(_ context.Context, request personserver.MissionApprovalRequest) (personserver.MissionDecision, error) {
					if request.Agent != agentID ||
						(request.Proposal.Description != "# Read the four-party report" &&
							request.Proposal.Description != "# Race the four-party report") ||
						!slices.Equal(request.Proposal.Resources, []string{resourceID}) {
						return personserver.MissionDecision{}, errors.New("unexpected mission proposal")
					}
					return personserver.MissionDecision{
						Description:       request.Proposal.Description,
						ApprovedResources: []string{resourceID},
						ExpiresAt:         &missionExpiry,
					}, nil
				},
				AcceptUpdate: func(_ context.Context, request personserver.MissionUpdatePolicyRequest) error {
					if request.Agent != agentID || request.Mission.Blob.Description != "# Read the four-party report" ||
						request.Document.Update.Description != "Include the retained correction" {
						return errors.New("unexpected mission update")
					}
					return nil
				},
				ConfirmPersonAcceptedCompletion: func(_ context.Context, request personserver.MissionCompletionPolicyRequest) error {
					acceptedCompletions = append(acceptedCompletions, request)
					return nil
				},
			},
			AccessServerEndpoint: func(_ context.Context, issuer string) (string, error) {
				if issuer != accessServerID {
					return "", errors.New("unknown access server")
				}
				return accessServerID + "/token", nil
			},
			BindPerson: func(_ context.Context, request personserver.PersonTokenRequest) (personserver.Person, error) {
				if request.Agent != agentID || request.Resource != resourceID || request.Mission == nil ||
					(request.Mission.Blob.Description != "# Read the four-party report" &&
						request.Mission.Blob.Description != "# Race the four-party report") {
					return personserver.Person{}, errors.New("unexpected mission person context")
				}
				return personserver.Person{Subject: "person-123", Tenant: "tenant-1", Lifetime: time.Hour}, nil
			},
			Consent: func(context.Context, personserver.AuthorizationRequest) error {
				return errors.New("Core consent must not receive an R3 request")
			},
			R3: &personserver.R3Config{
				Registry: registry,
				Admit: func(_ context.Context, endpoint string) error {
					if !strings.HasPrefix(endpoint, resourceID+"/r3/") {
						return errors.New("unexpected R3 document endpoint")
					}
					return nil
				},
				ConsentDocument: func(_ context.Context, request personserver.AuthorizationRequest, _ r3.Reference, document r3.Document) error {
					consentAttempts++
					if request.Agent != agentID || request.Resource != resourceID || request.Subject != "person-123" ||
						request.Mission == nil || request.Budget == nil ||
						!integrationSameBudget(*request.Budget, resourceOffer) ||
						!slices.Equal(request.Scopes, []string{scope}) ||
						!vocabulary.operationSetsEqual(t, document.OperationSet(), requestedOperations) {
						t.Errorf("unexpected mission R3 Budget authorization context: %#v document=%#v", request, document)
						return errors.New("unexpected mission authorization context")
					}
					if request.Mission.Blob.Description == "# Read the four-party report" {
						if len(request.Mission.AcceptedUpdates) != 1 ||
							request.Mission.AcceptedUpdates[0].Document.Update.Description != "Include the retained correction" {
							t.Errorf("mission authorization omitted accepted update history: %#v", request.Mission)
							return errors.New("mission authorization omitted the accepted update history")
						}
					} else if request.Mission.Blob.Description != "# Race the four-party report" ||
						len(request.Mission.AcceptedUpdates) != 0 {
						t.Errorf("unexpected race mission context: %#v", request.Mission)
						return errors.New("unexpected race mission context")
					}
					consentMissions = append(consentMissions, cloneFourPartyMissionContext(*request.Mission))
					return nil
				},
			},
			Budget: &personserver.FederatedBudgetConfig{
				ResolveResourceUnits: func(_ context.Context, resource string) ([]budgets.UnitDeclaration, error) {
					if resource != resourceID {
						return nil, errors.New("unexpected Resource metadata request")
					}
					return []budgets.UnitDeclaration{declaration}, nil
				},
				Ceiling: func(_ context.Context, request personserver.AuthorizationRequest) (*budgets.Value, error) {
					if request.Mission == nil || request.Budget == nil ||
						!integrationSameBudget(*request.Budget, resourceOffer) {
						return nil, errors.New("unexpected mission Budget ceiling context")
					}
					return &personCeiling, nil
				},
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		return people
	}
	people := newPeople()

	var terminateAtAccessServer string
	var accessPolicyCalls int
	issuances := &integrationR3IssuanceStore{}
	access, err := accessserver.New(accessserver.Config{
		Issuer: accessServerID, SigningKey: accessKey, KeyResolver: resolver, Clock: clock,
		NewID: func() string {
			id := authIDs[0]
			authIDs = authIDs[1:]
			return id
		},
		TrustPersonServer: func(_ context.Context, issuer string) error {
			if issuer != personServerID {
				return errors.New("untrusted person server")
			}
			return nil
		},
		Authorize: func(context.Context, accessserver.AuthorizationRequest) (accessserver.Decision, error) {
			return accessserver.Decision{}, errors.New("Core policy must not receive an R3 request")
		},
		R3: &accessserver.R3Config{
			Registry: registry, HTTPClient: httpClient,
			Admit: func(_ context.Context, endpoint string) error {
				if !strings.HasPrefix(endpoint, resourceID+"/r3/") {
					return errors.New("unexpected R3 document endpoint")
				}
				return nil
			},
			AuthorizeDocument: func(_ context.Context, request accessserver.AuthorizationRequest, _ r3.Reference, document r3.Document) (accessserver.R3DocumentDecision, error) {
				accessPolicyCalls++
				if !vocabulary.operationSetsEqual(t, document.OperationSet(), requestedOperations) {
					return accessserver.R3DocumentDecision{}, errors.New("unexpected R3 document")
				}
				if request.PersonServer != personServerID || request.Resource != resourceID ||
					request.Subject != "person-123" || request.Tenant != "tenant-1" ||
					request.Agent.Identifier != agentID || request.MissionS256 == "" || request.Budget == nil ||
					!integrationSameBudget(*request.Budget, personCeiling) ||
					!slices.Equal(request.Scopes, []string{scope}) {
					return accessserver.R3DocumentDecision{}, errors.New("unexpected access policy context")
				}
				if terminateAtAccessServer != "" {
					if err := store.terminateMission(agentID, terminateAtAccessServer, "revoked-during-authorization"); err != nil {
						return accessserver.R3DocumentDecision{}, err
					}
					terminateAtAccessServer = ""
				}
				granted, err := r3.NewGrantedOperations(vocabulary.registration, readOperation)
				if err != nil {
					return accessserver.R3DocumentDecision{}, err
				}
				empty, err := r3.NewGrantedOperations(vocabulary.registration)
				if err != nil {
					return accessserver.R3DocumentDecision{}, err
				}
				authorization, err := r3.NewAuthorization(granted, empty, document)
				if err != nil {
					return accessserver.R3DocumentDecision{}, err
				}
				return accessserver.R3DocumentDecision{
					Scopes: []string{scope}, Lifetime: 30 * time.Minute,
					Authorization: &authorization, Budget: &accessGrant,
				}, nil
			},
			Issuances: issuances,
		},
		Budget: &accessserver.BudgetConfig{
			ResolveResourceUnits: func(_ context.Context, resource string) ([]budgets.UnitDeclaration, error) {
				if resource != resourceID {
					return nil, errors.New("unexpected Resource metadata request")
				}
				return []budgets.UnitDeclaration{declaration}, nil
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	var retainedLineages sync.Map
	budgetLedger := newIntegrationBudgetStore()
	documents := newIntegrationR3DocumentStore()
	var resolvedMission string
	var protectedMission string
	protectedResource, err := resource.NewFederatedAuthorization(resource.FederatedAuthorizationConfig{
		Issuer: resourceID, AccessServer: accessServerID, SigningKey: resourceKey,
		KeyResolver: resolver, Clock: clock,
		NewID: func() string {
			id := resourceIDs[0]
			resourceIDs = resourceIDs[1:]
			return id
		},
		ScopeDescriptions: map[string]string{scope: "Read records"},
		RequiredScopes:    func(*http.Request) []string { return []string{scope} },
		ResolvePerson: func(_ context.Context, identity resource.PersonIdentity, personContext resource.PersonContext) error {
			if identity != (resource.PersonIdentity{Issuer: personServerID, Subject: "person-123"}) {
				return errors.New("unexpected person")
			}
			resolvedMission = personContext.MissionS256
			return nil
		},
		Budget: &resource.BudgetConfig{
			Units: []budgets.UnitDeclaration{declaration},
			Offer: func(_ context.Context, request resource.BudgetOfferRequest) (budgets.Value, error) {
				if request.PersonContext.MissionS256 == "" || !integrationSameBudget(request.Requested, requestedBudget) {
					return budgets.Value{}, errors.New("unexpected mission Budget offer context")
				}
				return resourceOffer, nil
			},
			RetainLineage: func(_ context.Context, lineage resource.BudgetLineage) error {
				retainedLineages.Store(lineage.ResourceToken, lineage)
				return nil
			},
			Cost: func(_ context.Context, request resource.BudgetCostRequest) (int64, error) {
				if request.Principal.MissionS256 == "" || !integrationSameBudget(request.Grant, accessGrant) {
					return 0, errors.New("unexpected mission Budget cost context")
				}
				return 125_000, nil
			},
			Store: budgetLedger,
			Challenge: func(context.Context, resource.BudgetChallengeRequest) (string, error) {
				return "", errors.New("Budget step-up is outside this journey")
			},
		},
		R3: &resource.R3Config{
			Registry:    registry,
			Definitions: newIntegrationR3DefinitionRegistry(t),
			Vocabularies: integrationR3ResourceVocabularies(
				t, resourceID, []string{"records.read"}, nil, &display,
			),
			Documents: documents,
			HTTP: resource.R3HTTPAdapter{OperationForRequest: func(request *http.Request) (r3.Operation, bool, error) {
				if request.Method == http.MethodGet && request.URL.Path == "/records" {
					return readOperation, true, nil
				}
				return r3.Operation{}, false, nil
			}},
		},
		Protected: http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			principal, ok := resource.AuthPrincipalFromContext(request.Context())
			if !ok {
				t.Error("protected handler received no AAuth principal")
				return
			}
			protectedMission = principal.MissionS256
			_, _ = io.WriteString(response, "mission accepted")
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	requireIntegrationR3ResourceMetadata(t, protectedResource.Handler(), resourceID)

	var accessWireMissions []string
	var personR3Fetches, accessR3Fetches int
	network.Handle(agentProviderID, provider.Handler())
	network.Handle(personServerID, people.Handler())
	network.Handle(resourceID, protectedResource.Handler())
	network.Handle(resourceID, http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if strings.HasPrefix(request.URL.Path, "/r3/") {
			signature := request.Header.Get("Signature-Key")
			switch {
			case strings.Contains(signature, aauth.PersonDiscoveryDocument):
				personR3Fetches++
			case strings.Contains(signature, aauth.AccessDiscoveryDocument):
				accessR3Fetches++
			}
		}
		protectedResource.Handler().ServeHTTP(response, request)
	}))
	network.Handle(accessServerID, http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Method == http.MethodPost && request.URL.Path == "/token" {
			body, readErr := io.ReadAll(request.Body)
			if readErr != nil {
				t.Error(readErr)
				return
			}
			request.Body = io.NopCloser(strings.NewReader(string(body)))
			var input struct {
				ResourceToken string `json:"resource_token"`
			}
			if err := json.Unmarshal(body, &input); err != nil {
				t.Error(err)
				return
			}
			claims, reference, offer, _, err := r3.VerifyBudgetResourceToken(
				request.Context(), registry, input.ResourceToken, resolver, clock,
			)
			if err != nil {
				t.Error(err)
				return
			}
			if reference.URI() == "" || !integrationSameBudget(offer, resourceOffer) {
				t.Errorf("PS-to-AS Resource-token Budget = %#v, want %#v", offer, resourceOffer)
				return
			}
			accessWireMissions = append(accessWireMissions, claims.MissionS256)
		}
		access.Handler().ServeHTTP(response, request)
	}))

	reader, err := clientagent.New(ctx, clientagent.Config{
		Identifier: agentID, SigningKey: agentKey, AgentToken: agentToken,
		KeyResolver: resolver, HTTPClient: httpClient, Clock: clock,
		R3: &clientagent.R3Config{Registry: registry},
	})
	if err != nil {
		t.Fatal(err)
	}

	missionResult, err := reader.ProposeMission(ctx, clientagent.MissionRequest{
		PersonServer: personServerID,
		Proposal: aauth.MissionProposal{
			Description: "# Read the four-party report", Resources: []string{resourceID},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	mission := missionResult.Mission()
	personToken, ok := missionResult.PersonToken(resourceID)
	if !ok {
		t.Fatal("mission approval omitted the approved Resource person token")
	}
	if _, err := reader.UpdateMission(ctx, clientagent.MissionUpdateRequest{
		PersonServer: personServerID, MissionS256: mission.S256,
		Description: "Include the retained correction",
	}); err != nil {
		t.Fatal(err)
	}
	personClaims, err := aauth.VerifyPersonToken(ctx, personToken, resolver, clock)
	if err != nil {
		t.Fatal(err)
	}
	resourceToken, err := reader.Authorize(ctx, clientagent.AuthorizeRequest{
		Resource: resourceID, PersonToken: personToken, Scopes: []string{scope},
		R3Operations: &requestedOperations, Budget: &requestedBudget,
	})
	if err != nil {
		t.Fatal(err)
	}
	resourceClaims, resourceReference, verifiedOffer, _, err := r3.VerifyBudgetResourceToken(
		ctx, registry, resourceToken, resolver, clock,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !integrationSameBudget(verifiedOffer, resourceOffer) {
		t.Fatalf("Resource Budget offer = %#v, want %#v", verifiedOffer, resourceOffer)
	}
	documentRecord, err := documents.Load(ctx, resourceReference.URI())
	if err != nil {
		t.Fatal(err)
	}

	for name, changedMission := range map[string]string{
		"omitted": "", "substituted": aauth.MissionS256([]byte("another mission")),
	} {
		tampered := resourceClaims
		tampered.JTI = "mission-four-party-" + name + "-resource"
		tampered.MissionS256 = changedMission
		compact, _, err := r3.MintBudgetResourceToken(
			registry, resourceKey, tampered, resourceReference.URI(), documentRecord.ExactJSON, resourceOffer, nil,
		)
		if err != nil {
			t.Fatal(err)
		}
		released, err := reader.Exchange(ctx, clientagent.ExchangeRequest{
			PersonServer: personServerID, ResourceToken: compact, PresentedToken: personToken,
		})
		// The Agent compares the Resource token with the token it presented
		// and refuses before any request leaves; the Person Server's own
		// refusal is proven at its token endpoint.
		if released != "" || !errors.Is(err, aauth.ErrPresentedTokenMismatch) {
			t.Fatalf("%s mission binding result = %q, err=%v", name, released, err)
		}
	}
	if accessPolicyCalls != 0 {
		t.Fatalf("tampered mission binding reached Access Server policy %d times", accessPolicyCalls)
	}

	type exchangeResult struct {
		token string
		err   error
	}
	// Observe commit entry or exchange completion; scheduler latency is not a
	// protocol failure. The test context releases the commit gate on failure.
	exchangeDone := make(chan exchangeResult, 1)
	go func() {
		token, err := reader.Exchange(ctx, clientagent.ExchangeRequest{
			PersonServer: personServerID, ResourceToken: resourceToken, PresentedToken: personToken,
		})
		exchangeDone <- exchangeResult{token: token, err: err}
	}()
	select {
	case <-store.firstMissionAuthCommit:
		retainedIssuances := issuances.recordsCopy()
		if len(retainedIssuances) != 1 ||
			retainedIssuances[0].AuthTokenReference != (aauth.TokenReference{Issuer: accessServerID, JTI: "mission-four-party-auth"}) {
			t.Fatalf("AS R3 issuance before PS mission commit = %#v", retainedIssuances)
		}
		select {
		case result := <-exchangeDone:
			t.Fatalf("Person Server released auth token before retaining it: token=%q err=%v", result.token, result.err)
		default:
		}
		close(store.allowFirstMissionAuthCommit)
	case result := <-exchangeDone:
		t.Fatalf("federated exchange completed before mission auth-token retention: token=%q err=%v", result.token, result.err)
	}
	result := <-exchangeDone
	if result.err != nil {
		t.Fatal(result.err)
	}
	authToken := result.token
	authClaims, authReference, _, verifiedGrant, err := r3.VerifyBudgetAuthToken(
		ctx, registry, authToken, resolver, clock,
	)
	if err != nil {
		t.Fatal(err)
	}
	if authReference != resourceReference || !integrationSameBudget(verifiedGrant, accessGrant) {
		t.Fatalf("Access Server Budget grant = %#v, want %#v", verifiedGrant, accessGrant)
	}
	if accessPolicyCalls != 1 || !slices.Equal(accessWireMissions, []string{mission.S256}) {
		t.Fatalf("Access Server observations = policy:%d missions:%v", accessPolicyCalls, accessWireMissions)
	}
	if len(consentMissions) != 1 || consentMissions[0].S256 != mission.S256 ||
		len(consentMissions[0].ExactJSON) == 0 || len(consentMissions[0].AcceptedUpdates) != 1 {
		t.Fatalf("Person Server mission policy context = %#v", consentMissions)
	}
	for name, digest := range map[string]string{
		"person": personClaims.MissionS256, "resource": resourceClaims.MissionS256, "auth": authClaims.MissionS256,
	} {
		if digest != mission.S256 {
			t.Fatalf("%s mission_s256 = %q, want %q", name, digest, mission.S256)
		}
	}
	for name, expiry := range map[string]int64{
		"person": personClaims.ExpiresAt, "resource": resourceClaims.ExpiresAt, "auth": authClaims.ExpiresAt,
	} {
		if expiry > missionExpiry.Unix() {
			t.Fatalf("%s token expires at %d after mission %d", name, expiry, missionExpiry.Unix())
		}
	}

	store.mu.Lock()
	retainedPerson, personRetained := store.records[personServerID+"\x00"+personClaims.JTI]
	retainedAuth, authRetained := store.auth[accessServerID+"\x00"+authClaims.JTI]
	authCount := len(store.auth)
	personLoads := store.loads
	store.mu.Unlock()
	if !personRetained || retainedPerson.MissionS256 != mission.S256 || personLoads == 0 {
		t.Fatalf("retained person-token lineage = present:%t record:%#v loads:%d", personRetained, retainedPerson, personLoads)
	}
	if !authRetained || authCount != 1 || retainedAuth.MissionS256 != mission.S256 ||
		retainedAuth.Reference != (aauth.TokenReference{Issuer: accessServerID, JTI: authClaims.JTI}) ||
		retainedAuth.CompactSHA256 != sha256.Sum256([]byte(authToken)) {
		t.Fatalf("retained federated auth-token = present:%t count:%d record:%#v", authRetained, authCount, retainedAuth)
	}

	request, _ := http.NewRequestWithContext(ctx, http.MethodGet, resourceID+"/records", nil)
	call, err := reader.BeginBudgetCall(ctx, clientagent.BudgetCall{Request: request, AuthToken: authToken})
	if err != nil {
		t.Fatal(err)
	}
	response, ok := call.Response()
	if !ok {
		t.Fatal("mission Budget call returned a step-up")
	}
	body, _ := io.ReadAll(response.Body)
	response.Body.Close()
	cost, hasCost := call.Cost()
	feedback, hasFeedback := call.Feedback()
	if response.StatusCode != http.StatusOK || string(body) != "mission accepted" ||
		resolvedMission != mission.S256 || protectedMission != mission.S256 || !hasCost || !hasFeedback ||
		cost != 125_000 || feedback.Remaining() != 175_000 {
		t.Fatalf("protected result = %d %q, resolved=%q, principal=%q, cost=%d/%t remaining=%d/%t",
			response.StatusCode, body, resolvedMission, protectedMission, cost, hasCost, feedback.Remaining(), hasFeedback)
	}
	lineageValue, retained := retainedLineages.Load(aauth.TokenReference{Issuer: resourceID, JTI: resourceClaims.JTI})
	lineage, lineageOK := lineageValue.(resource.BudgetLineage)
	if !retained || !lineageOK || lineage.PersonContext.MissionS256 != mission.S256 ||
		!integrationSameBudget(lineage.Offer, resourceOffer) {
		t.Fatalf("retained mission Budget lineage = present:%t value:%#v", retained && lineageOK, lineageValue)
	}

	// Recompose the Person Server around the same retained mission and token
	// store. Completion and the later terminal refusal must not depend on
	// process-local mission context.
	network.Handle(personServerID, newPeople().Handler())
	if err := reader.CompleteMission(ctx, clientagent.MissionCompletionRequest{
		PersonServer: personServerID, MissionS256: mission.S256,
		Summary: "Four-party report read completed",
	}); err != nil {
		t.Fatal(err)
	}
	if len(acceptedCompletions) != 1 || acceptedCompletions[0].Mission.S256 != mission.S256 ||
		len(acceptedCompletions[0].Mission.AcceptedUpdates) != 1 ||
		acceptedCompletions[0].Document.Completion.Summary != "Four-party report read completed" {
		t.Fatalf("mission completion context = %#v", acceptedCompletions)
	}
	released, err := reader.Exchange(ctx, clientagent.ExchangeRequest{
		PersonServer: personServerID, ResourceToken: resourceToken, PresentedToken: personToken,
	})
	var completedProblem *aauth.ProblemError
	if released != "" || !errors.As(err, &completedProblem) || completedProblem.Code != "mission_terminated" ||
		completedProblem.MissionStatus != "terminated" || completedProblem.TerminationReason != "completed" ||
		accessPolicyCalls != 1 {
		t.Fatalf("completed mission exchange = %q, problem=%#v, err=%v, AS calls=%d",
			released, completedProblem, err, accessPolicyCalls)
	}

	raceResult, err := reader.ProposeMission(ctx, clientagent.MissionRequest{
		PersonServer: personServerID,
		Proposal: aauth.MissionProposal{
			Description: "# Race the four-party report", Resources: []string{resourceID},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	raceMission := raceResult.Mission()
	racePersonToken, ok := raceResult.PersonToken(resourceID)
	if !ok {
		t.Fatal("race mission approval omitted its person token")
	}
	raceResourceToken, err := reader.Authorize(ctx, clientagent.AuthorizeRequest{
		Resource: resourceID, PersonToken: racePersonToken, Scopes: []string{scope},
		R3Operations: &requestedOperations, Budget: &requestedBudget,
	})
	if err != nil {
		t.Fatal(err)
	}
	terminateAtAccessServer = raceMission.S256
	released, err = reader.Exchange(ctx, clientagent.ExchangeRequest{
		PersonServer: personServerID, ResourceToken: raceResourceToken, PresentedToken: racePersonToken,
	})
	var problem *aauth.ProblemError
	if released != "" || !errors.As(err, &problem) || problem.Code != "mission_terminated" ||
		problem.MissionStatus != "terminated" || problem.TerminationReason != "revoked-during-authorization" {
		t.Fatalf("termination race result = %q, problem=%#v, err=%v", released, problem, err)
	}
	store.mu.Lock()
	_, raceRetained := store.auth[accessServerID+"\x00mission-four-party-race-auth"]
	authCount = len(store.auth)
	store.mu.Unlock()
	retainedIssuances := issuances.recordsCopy()
	if accessPolicyCalls != 2 || len(accessWireMissions) != 2 || accessWireMissions[1] != raceMission.S256 ||
		raceRetained || authCount != 1 || len(authIDs) != 0 || len(retainedIssuances) != 2 ||
		personR3Fetches != 3 || accessR3Fetches != 2 ||
		retainedIssuances[1].AuthTokenReference != (aauth.TokenReference{Issuer: accessServerID, JTI: "mission-four-party-race-auth"}) {
		t.Fatalf("termination race state = policy:%d missions:%v retained:%t count:%d remaining IDs:%v fetches:%d/%d issuances:%#v",
			accessPolicyCalls, accessWireMissions, raceRetained, authCount, authIDs,
			personR3Fetches, accessR3Fetches, retainedIssuances)
	}
}

type missionFourPartyStore struct {
	*memoryPersonTokenStore
	firstMissionAuthCommit      chan struct{}
	allowFirstMissionAuthCommit chan struct{}
	firstCommit                 sync.Once
}

func newMissionFourPartyStore() *missionFourPartyStore {
	return &missionFourPartyStore{
		memoryPersonTokenStore:      newMemoryPersonTokenStore(),
		firstMissionAuthCommit:      make(chan struct{}),
		allowFirstMissionAuthCommit: make(chan struct{}),
	}
}

func (store *missionFourPartyStore) CommitMissionAuthToken(
	ctx context.Context,
	expected personserver.MissionRecord,
	at time.Time,
	token personserver.IssuedAuthTokenRecord,
) error {
	first := false
	store.firstCommit.Do(func() {
		first = true
		close(store.firstMissionAuthCommit)
	})
	if first {
		select {
		case <-store.allowFirstMissionAuthCommit:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return store.memoryPersonTokenStore.CommitMissionAuthToken(ctx, expected, at, token)
}

func cloneFourPartyMissionContext(context personserver.MissionContext) personserver.MissionContext {
	context.ExactJSON = append([]byte(nil), context.ExactJSON...)
	context.AcceptedUpdates = append([]personserver.MissionUpdateRecord(nil), context.AcceptedUpdates...)
	return context
}
