// The hosted-service example composes the launch-profile paths on one set of
// AAuth roles. It demonstrates protocol boundaries; applications still own
// account login, administrative authentication, persistence, and connector
// credentials.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sync/atomic"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	clientagent "gitlab.com/sidecat-dev/aauth-go/agent"
	"gitlab.com/sidecat-dev/aauth-go/agentprovider"
	"gitlab.com/sidecat-dev/aauth-go/budgets"
	"gitlab.com/sidecat-dev/aauth-go/internal/exampleutil"
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/personserver"
	"gitlab.com/sidecat-dev/aauth-go/r3"
	"gitlab.com/sidecat-dev/aauth-go/r3/vocab/mcp"
	"gitlab.com/sidecat-dev/aauth-go/resource"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

const (
	agentProviderID  = "https://agents.example"
	agentID          = "aauth:hosted-worker@agents.example"
	personServerID   = "https://person.example"
	hostedResourceID = "https://service.example"
	localResourceID  = "https://local.example"
)

func main() {
	if err := run(os.Stdout); err != nil {
		log.Fatal(err)
	}
}

func run(output io.Writer) error {
	if output == nil {
		return errors.New("hosted-service example: output is required")
	}
	ctx := context.Background()
	now := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	providerKey, err := newSigningKey("hosted-provider-key")
	if err != nil {
		return err
	}
	durableKey, err := newSigningKey("hosted-durable-key")
	if err != nil {
		return err
	}
	agentKey, err := newSigningKey("hosted-agent-key")
	if err != nil {
		return err
	}
	personKey, err := newSigningKey("hosted-person-key")
	if err != nil {
		return err
	}
	resourceKey, err := newSigningKey("hosted-resource-key")
	if err != nil {
		return err
	}

	registry, definitions, operationSet, operation, definition, err := hostedR3Model()
	if err != nil {
		return err
	}
	unit, err := budgets.NewUnit("USD", 6)
	if err != nil {
		return err
	}
	requestedBudget, err := budgets.NewValue(500_000, unit)
	if err != nil {
		return err
	}
	resourceOffer, err := budgets.NewValue(400_000, unit)
	if err != nil {
		return err
	}
	personGrant, err := budgets.NewValue(300_000, unit)
	if err != nil {
		return err
	}
	unitDeclaration, err := budgets.NewBoundedUnitDeclaration(unit, 1_000_000, "US dollars at micro-dollar precision")
	if err != nil {
		return err
	}

	network := newLogicalTransport()
	httpClient := &http.Client{Transport: network}
	resolver, err := signaturekey.NewHTTPKeyResolver(signaturekey.HTTPKeyResolverConfig{
		Client: httpClient, Clock: clock, Admit: network.Admit,
	})
	if err != nil {
		return err
	}
	var agentTokenIDs atomic.Int64
	provider, err := agentprovider.New(agentprovider.Config{
		Issuer: agentProviderID, SigningKey: providerKey, Clock: clock,
		NewID: func() string { return fmt.Sprintf("agent-token-%d", agentTokenIDs.Add(1)) },
	})
	if err != nil {
		return err
	}
	enrollments := exampleutil.NewEnrollmentStore(clock)
	enrollmentService, err := agentprovider.NewEnrollmentService(agentprovider.EnrollmentServiceConfig{
		Provider: provider, Store: enrollments,
		Enroll: func(_ context.Context, request agentprovider.EnrollmentRequest) (agentprovider.EnrollmentDecision, error) {
			if string(request.Evidence) != `{"account":"person-123"}` {
				return agentprovider.EnrollmentDecision{}, agentprovider.ErrEnrollmentDenied
			}
			return agentprovider.EnrollmentDecision{Agent: agentID}, nil
		},
		Refresh: func(_ context.Context, request agentprovider.RefreshRequest) (agentprovider.RefreshDecision, error) {
			if request.RequestedPersonServer != personServerID || string(request.Evidence) != `{"posture":"current"}` {
				return agentprovider.RefreshDecision{}, agentprovider.ErrRefreshDenied
			}
			return agentprovider.RefreshDecision{PersonServer: personServerID, Lifetime: 30 * time.Minute}, nil
		},
	})
	if err != nil {
		return err
	}
	network.Handle(agentProviderID, providerWithBootstrap(provider, enrollmentService))
	bootstrap, err := clientagent.NewBootstrapClient(clientagent.BootstrapConfig{
		AgentProvider: agentProviderID, EnrollmentEndpoint: agentProviderID + "/internal/enrollment",
		RefreshEndpoint: agentProviderID + "/internal/refresh", DurableKey: durableKey,
		KeyResolver: resolver, HTTPClient: httpClient, Clock: clock,
	})
	if err != nil {
		return err
	}
	enrollment, err := bootstrap.Enroll(ctx, json.RawMessage(`{"account":"person-123"}`))
	if err != nil {
		return err
	}
	refreshed, err := bootstrap.Refresh(ctx, clientagent.RefreshAgentTokenInput{
		Agent: enrollment.Agent, PersonServer: personServerID,
		Evidence: json.RawMessage(`{"posture":"current"}`), SigningKey: agentKey,
		DelegationJTI: "hosted-refresh-1", DelegationIssuedAt: now,
		DelegationExpiresAt: now.Add(10 * time.Minute),
	})
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintln(output, "1. enrollment + delegated Agent-token refresh complete"); err != nil {
		return err
	}

	documents := newR3DocumentStore()
	issuances := newR3IssuanceStore()
	budgetCharges := newBudgetStore()
	lineage := &lineageStore{}
	missionPermissions := exampleutil.NewMissionPermissionStore()
	personRevocations := newAgentTokenRevocationStore()
	localRevocations := newAgentTokenRevocationStore()
	connector := &connectorApplication{oauthCredential: "application-only-oauth-credential"}
	var personIDs atomic.Int64
	newPeople := func() (*personserver.Server, error) {
		return personserver.NewPSAuthorization(personserver.PSAuthorizationConfig{
			Issuer: personServerID, SigningKey: personKey, KeyResolver: resolver, Clock: clock,
			NewID:  func() string { return fmt.Sprintf("person-server-token-%d", personIDs.Add(1)) },
			Tokens: missionPermissions,
			BindPerson: func(_ context.Context, request personserver.PersonTokenRequest) (personserver.Person, error) {
				if request.Agent != agentID || request.Resource != hostedResourceID {
					return personserver.Person{}, errors.New("hosted-service example: unexpected person binding")
				}
				return personserver.Person{Subject: "person-123", Tenant: "tenant-1", Lifetime: 30 * time.Minute}, nil
			},
			Missions: &personserver.MissionConfig{
				DeferProposal: func(context.Context, personserver.MissionApprovalRequest) (personserver.MissionProposalPendingPolicy, bool, error) {
					return personserver.MissionProposalPendingPolicy{Lifetime: 5 * time.Minute}, true, nil
				},
			},
			Permission: &personserver.PermissionConfig{
				Policy: func(_ context.Context, request personserver.PermissionPolicyRequest) (personserver.PermissionPolicyResult, error) {
					if request.Agent != agentID || request.Mission != nil || request.Action != "connector.prepare" {
						return personserver.PermissionPolicyResult{}, errors.New("hosted-service example: unexpected local permission")
					}
					return personserver.PermissionPolicyResult{Immediate: &personserver.PermissionDecision{Permission: aauth.PermissionGranted}}, nil
				},
			},
			Budget: &personserver.BudgetConfig{ResolveResourceUnits: func(_ context.Context, resourceID string) ([]budgets.UnitDeclaration, error) {
				if resourceID != hostedResourceID {
					return nil, errors.New("hosted-service example: unexpected Resource unit lookup")
				}
				return []budgets.UnitDeclaration{unitDeclaration}, nil
			}},
			R3: &personserver.DirectR3Config{
				Registry: registry, HTTPClient: httpClient, Admit: network.Admit, Issuances: issuances,
				AuthorizeDocument: func(_ context.Context, request personserver.AuthorizationRequest, _ r3.Reference, document r3.Document) (personserver.DirectR3Decision, error) {
					if request.Agent != agentID || request.Resource != hostedResourceID || request.Subject != "person-123" ||
						request.Budget == nil || !sameBudget(*request.Budget, resourceOffer) || len(request.Scopes) != 0 {
						return personserver.DirectR3Decision{}, errors.New("hosted-service example: unexpected R3 Budget authorization")
					}
					operations, err := r3.NewGrantedOperations(mcp.Vocabulary(), operation)
					if err != nil {
						return personserver.DirectR3Decision{}, err
					}
					grant, err := r3.NewGrant(operations, document)
					if err != nil {
						return personserver.DirectR3Decision{}, err
					}
					return personserver.DirectR3Decision{Lifetime: 10 * time.Minute, Grant: grant, Budget: &personGrant}, nil
				},
			},
			AgentTokenRevocations: personRevocations,
		})
	}

	protectedResource, err := resource.NewPSAuthorization(resource.PSAuthorizationConfig{
		Issuer: hostedResourceID, SigningKey: resourceKey, KeyResolver: resolver, Clock: clock,
		NewID: func() string { return "resource-token-1" }, RequiredScopes: func(*http.Request) []string { return nil },
		ResolvePerson: func(_ context.Context, identity resource.PersonIdentity, _ resource.PersonContext) error {
			if identity != (resource.PersonIdentity{Issuer: personServerID, Subject: "person-123"}) {
				return errors.New("hosted-service example: unexpected person identity")
			}
			return nil
		},
		R3: &resource.R3Config{
			Registry: registry, Definitions: definitions,
			Vocabularies: []resource.R3VocabularyConfig{{Definition: definition}}, Documents: documents,
			HTTP: resource.R3HTTPAdapter{OperationForRequest: func(request *http.Request) (r3.Operation, bool, error) {
				if request.URL.Path == "/records/current" {
					return operation, true, nil
				}
				return r3.Operation{}, false, nil
			}},
		},
		Budget: &resource.BudgetConfig{
			Units: []budgets.UnitDeclaration{unitDeclaration}, RetainLineage: lineage.Retain,
			Offer: func(_ context.Context, request resource.BudgetOfferRequest) (budgets.Value, error) {
				if !sameBudget(request.Requested, requestedBudget) {
					return budgets.Value{}, errors.New("hosted-service example: unexpected Budget request")
				}
				return resourceOffer, nil
			},
			Cost:  func(context.Context, resource.BudgetCostRequest) (int64, error) { return 100_000, nil },
			Store: budgetCharges,
			Challenge: func(context.Context, resource.BudgetChallengeRequest) (string, error) {
				return "", errors.New("hosted-service example: Budget challenge was not expected")
			},
		},
		Protected: http.HandlerFunc(connector.serve),
	})
	if err != nil {
		return err
	}
	newLocalResource := func() (*resource.Server, error) {
		return resource.NewAgentIdentity(resource.AgentIdentityConfig{
			Issuer: localResourceID, KeyResolver: resolver, Clock: clock,
			AgentTokenRevocations: localRevocations,
			Protected: http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
				response.WriteHeader(http.StatusNoContent)
			}),
		})
	}
	people, err := newPeople()
	if err != nil {
		return err
	}
	localResource, err := newLocalResource()
	if err != nil {
		return err
	}
	network.Handle(personServerID, people.Handler())
	network.Handle(hostedResourceID, protectedResource.Handler())
	network.Handle(localResourceID, localResource.Handler())

	agentClient, err := clientagent.New(ctx, clientagent.Config{
		Identifier: enrollment.Agent, SigningKey: agentKey, AgentToken: refreshed.AgentToken,
		KeyResolver: resolver, HTTPClient: httpClient, Clock: clock,
		R3: &clientagent.R3Config{Registry: registry},
	})
	if err != nil {
		return err
	}
	localRequest, _ := http.NewRequestWithContext(ctx, http.MethodGet, localResourceID+"/status", nil)
	localResponse, err := agentClient.CallAsAgent(ctx, localRequest)
	if err != nil {
		return err
	}
	localResponse.Body.Close()

	permissionResult, err := agentClient.RequestPermission(ctx, clientagent.PermissionRequest{
		PersonServer: personServerID, Action: "connector.prepare",
		Description: "Prepare the account connector without invoking it.",
	})
	if err != nil {
		return err
	}
	permission, ok := permissionResult.Decision()
	if !ok || permission.Permission() != aauth.PermissionGranted {
		return errors.New("hosted-service example: local permission was not granted")
	}
	if _, err := fmt.Fprintln(output, "2. missionless local permission granted"); err != nil {
		return err
	}

	missionResult, err := agentClient.BeginMission(ctx, clientagent.MissionRequest{
		PersonServer: personServerID,
		Proposal:     aauth.MissionProposal{Description: "Review and approve the hosted records query."},
	})
	if err != nil {
		return err
	}
	pendingMission, ok := missionResult.Pending()
	if !ok {
		return errors.New("hosted-service example: mission did not enter host review")
	}
	reviews, err := people.PendingMissionProposals(ctx, 10)
	if err != nil || len(reviews) != 1 {
		return fmt.Errorf("hosted-service example: mission review queue = %d, %v", len(reviews), err)
	}
	missionExpiry := now.Add(20 * time.Minute)
	if err := people.ApproveMissionProposal(ctx, reviews[0], personserver.MissionDecision{
		Description: reviews[0].Proposal().Description, ExpiresAt: &missionExpiry,
	}); err != nil {
		return err
	}
	approvedMission, err := agentClient.PollMissionProposal(ctx, pendingMission)
	if err != nil {
		return err
	}
	if _, ok := approvedMission.Approval(); !ok {
		return errors.New("hosted-service example: approved mission was not delivered")
	}
	if _, err := fmt.Fprintln(output, "3. approval-only mission reviewed and delivered"); err != nil {
		return err
	}

	personResult, err := agentClient.PersonToken(ctx, clientagent.PersonTokenRequest{
		PersonServer: personServerID, Resource: hostedResourceID,
	})
	if err != nil {
		return err
	}
	personToken, ok := personResult.Token()
	if !ok {
		return errors.New("hosted-service example: person token unexpectedly deferred")
	}
	resourceToken, err := agentClient.Authorize(ctx, clientagent.AuthorizeRequest{
		Resource: hostedResourceID, PersonToken: personToken,
		R3Operations: &operationSet, Budget: &requestedBudget,
	})
	if err != nil {
		return err
	}
	authToken, err := agentClient.Exchange(ctx, clientagent.ExchangeRequest{
		PersonServer: personServerID, ResourceToken: resourceToken,
	})
	if err != nil {
		return err
	}
	callRequest, _ := http.NewRequestWithContext(ctx, http.MethodGet, hostedResourceID+"/records/current", nil)
	call, err := agentClient.BeginBudgetCall(ctx, clientagent.BudgetCall{Request: callRequest, AuthToken: authToken})
	if err != nil {
		return err
	}
	callResponse, ok := call.Response()
	if !ok {
		return errors.New("hosted-service example: R3 Budget call returned no application response")
	}
	callResponse.Body.Close()
	cost, hasCost := call.Cost()
	feedback, hasFeedback := call.Feedback()
	if !hasCost || cost != 100_000 || !hasFeedback || feedback.Remaining() != 200_000 || connector.calls.Load() != 1 {
		return errors.New("hosted-service example: R3 Budget consequence was not retained exactly once")
	}
	if _, err := fmt.Fprintln(output, "4. MCP operation authorized; fixed Budget charged before one connector call"); err != nil {
		return err
	}
	if !connector.credentialStayedPrivate() {
		return errors.New("hosted-service example: connector credential left application custody")
	}
	if _, err := fmt.Fprintln(output, "5. OAuth service credential remained inside the connector application"); err != nil {
		return err
	}

	claims, err := aauth.VerifyAgentToken(ctx, refreshed.AgentToken, resolver, clock)
	if err != nil {
		return err
	}
	reference := aauth.TokenReference{Issuer: claims.Issuer, JTI: claims.JTI}
	revoker, err := agentprovider.NewRevocationClient(agentprovider.RevocationClientConfig{
		Provider: provider, HTTPClient: httpClient, Admit: network.Admit,
	})
	if err != nil {
		return err
	}
	if err := revoker.RevokeAgentToken(ctx, personServerID, reference); err != nil {
		return err
	}
	if err := revoker.RevokeAgentTokenAtResource(ctx, localResourceID, reference); err != nil {
		return err
	}
	people, err = newPeople()
	if err != nil {
		return err
	}
	localResource, err = newLocalResource()
	if err != nil {
		return err
	}
	network.Handle(personServerID, people.Handler())
	network.Handle(localResourceID, localResource.Handler())
	_, personErr := agentClient.PersonToken(ctx, clientagent.PersonTokenRequest{
		PersonServer: personServerID, Resource: hostedResourceID,
	})
	localRequest, _ = http.NewRequestWithContext(ctx, http.MethodGet, localResourceID+"/status", nil)
	localResponse, localErr := agentClient.CallAsAgent(ctx, localRequest)
	if localResponse != nil {
		localResponse.Body.Close()
	}
	if personErr == nil || localErr == nil {
		return errors.New("hosted-service example: revoked Agent token remained usable")
	}
	_, err = fmt.Fprintln(output, "6. Agent token revoked at PS and local Resource; later requests refused")
	return err
}

func hostedR3Model() (r3.Registry, r3.DefinitionRegistry, r3.OperationSet, r3.Operation, r3.AuthoritativeSnapshot, error) {
	registry, err := r3.NewRegistry(mcp.Vocabulary())
	if err != nil {
		return r3.Registry{}, r3.DefinitionRegistry{}, r3.OperationSet{}, r3.Operation{}, r3.AuthoritativeSnapshot{}, err
	}
	definitions, err := r3.NewDefinitionRegistry(mcp.DefinitionRegistration())
	if err != nil {
		return r3.Registry{}, r3.DefinitionRegistry{}, r3.OperationSet{}, r3.Operation{}, r3.AuthoritativeSnapshot{}, err
	}
	mcpOperation, err := mcp.NewOperation("records.current")
	if err != nil {
		return r3.Registry{}, r3.DefinitionRegistry{}, r3.OperationSet{}, r3.Operation{}, r3.AuthoritativeSnapshot{}, err
	}
	operation, err := mcpOperation.ToR3()
	if err != nil {
		return r3.Registry{}, r3.DefinitionRegistry{}, r3.OperationSet{}, r3.Operation{}, r3.AuthoritativeSnapshot{}, err
	}
	operations, err := mcp.NewOperationSet(mcpOperation)
	if err != nil {
		return r3.Registry{}, r3.DefinitionRegistry{}, r3.OperationSet{}, r3.Operation{}, r3.AuthoritativeSnapshot{}, err
	}
	definition, err := mcp.ParseDefinition(hostedResourceID+"/mcp", mcp.NewToolsListSnapshot(mcp.NewInitialToolsListPage([]byte(`{
		"tools":[{"name":"records.current","inputSchema":{"type":"object"},"_meta":{"aauth.dev/budget":true}}]
	}`))))
	return registry, definitions, operations, operation, definition, err
}

type connectorApplication struct {
	oauthCredential string
	calls           atomic.Int64
}

func (connector *connectorApplication) serve(response http.ResponseWriter, request *http.Request) {
	principal, ok := resource.AuthPrincipalFromContext(request.Context())
	if !ok || principal.Subject != "person-123" || connector.oauthCredential == "" {
		http.Error(response, "connector context unavailable", http.StatusInternalServerError)
		return
	}
	// Only application code can read oauthCredential. AAuth policy and tokens
	// carry the person, operation, and Budget—not this third-party secret.
	connector.calls.Add(1)
	response.WriteHeader(http.StatusNoContent)
}

func (connector *connectorApplication) credentialStayedPrivate() bool {
	return connector.oauthCredential == "application-only-oauth-credential" && connector.calls.Load() == 1
}

func providerWithBootstrap(provider *agentprovider.Server, service *agentprovider.EnrollmentService) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/internal/enrollment":
			service.EnrollmentHandler().ServeHTTP(response, request)
		case "/internal/refresh":
			service.RefreshHandler().ServeHTTP(response, request)
		default:
			provider.Handler().ServeHTTP(response, request)
		}
	})
}

func newSigningKey(id string) (jose.SigningKey, error) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return jose.SigningKey{}, err
	}
	return jose.NewEd25519SigningKey(id, privateKey)
}
