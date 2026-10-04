package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync/atomic"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/budgets"
	"gitlab.com/sidecat-dev/aauth-go/internal/exampleutil"
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/personserver"
	"gitlab.com/sidecat-dev/aauth-go/r3"
	"gitlab.com/sidecat-dev/aauth-go/r3/vocab/mcp"
	"gitlab.com/sidecat-dev/aauth-go/resource"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

type roleInputs struct {
	clock           aauth.Clock
	resolver        signaturekey.KeyResolver
	network         *logicalTransport
	httpClient      *http.Client
	personKey       jose.SigningKey
	resourceKey     jose.SigningKey
	registry        r3.Registry
	definitions     r3.DefinitionRegistry
	operation       r3.Operation
	definition      r3.AuthoritativeSnapshot
	account         string
	observations    *profileObservations
	requestedBudget budgets.Value
	resourceOffer   budgets.Value
	personGrant     budgets.Value
	unit            budgets.UnitDeclaration
}

type profileObservations struct {
	budgetOffers   atomic.Int64
	budgetCharges  atomic.Int64
	connectorCalls atomic.Int64
}

type composedRoles struct {
	people    *personserver.Server
	connector *connectorApplication
	newPeople func() (*personserver.Server, error)
	newLocal  func() (*resource.Server, error)
}

func composeRoles(input roleInputs) (composedRoles, error) {
	documents := newR3DocumentStore()
	issuances := newR3IssuanceStore()
	budgetCharges := newBudgetStore()
	budgetCharges.observations = input.observations
	lineage := &lineageStore{}
	missionPermissions := exampleutil.NewMissionPermissionStore()
	personRevocations := newAgentTokenRevocationStore()
	localRevocations := newAgentTokenRevocationStore()
	connector := &connectorApplication{
		oauthCredential: "application-only-oauth-credential",
		account:         input.account,
		observations:    input.observations,
	}
	var personIDs atomic.Int64
	newPeople := func() (*personserver.Server, error) {
		return personserver.NewPSAuthorization(personserver.PSAuthorizationConfig{
			Issuer: personServerID, SigningKey: input.personKey, KeyResolver: input.resolver, Clock: input.clock,
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
				ConfirmPersonAcceptedCompletion: func(_ context.Context, request personserver.MissionCompletionPolicyRequest) error {
					if request.Mission.Blob.Description != "Review and approve the hosted records query." ||
						request.Document.Completion.Summary != "Recovered connector query completed" {
						return errors.New("hosted-service example: unexpected mission completion")
					}
					return nil
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
				return []budgets.UnitDeclaration{input.unit}, nil
			}},
			R3: &personserver.DirectR3Config{
				Registry: input.registry, HTTPClient: input.httpClient, Admit: input.network.Admit, Issuances: issuances,
				AuthorizeDocument: func(_ context.Context, request personserver.AuthorizationRequest, _ r3.Reference, document r3.Document) (personserver.DirectR3Decision, error) {
					if request.Agent != agentID || request.Resource != hostedResourceID || request.Subject != "person-123" ||
						request.Account == nil || *request.Account != input.account || request.Budget == nil ||
						!sameBudget(*request.Budget, input.resourceOffer) || len(request.Scopes) != 0 {
						return personserver.DirectR3Decision{}, errors.New("hosted-service example: unexpected R3 Budget authorization")
					}
					operations, err := r3.NewGrantedOperations(mcp.Vocabulary(), input.operation)
					if err != nil {
						return personserver.DirectR3Decision{}, err
					}
					grant, err := r3.NewGrant(operations, document)
					if err != nil {
						return personserver.DirectR3Decision{}, err
					}
					return personserver.DirectR3Decision{Lifetime: 10 * time.Minute, Grant: grant, Budget: &input.personGrant}, nil
				},
			},
			AgentTokenRevocations: personRevocations,
		})
	}

	protectedResource, err := resource.NewPSAuthorization(resource.PSAuthorizationConfig{
		Issuer: hostedResourceID, SigningKey: input.resourceKey, KeyResolver: input.resolver, Clock: input.clock,
		NewID: func() string { return "resource-token-1" }, RequiredScopes: func(*http.Request) []string { return nil },
		ResolvePerson: func(_ context.Context, identity resource.PersonIdentity, _ resource.PersonContext) error {
			if identity != (resource.PersonIdentity{Issuer: personServerID, Subject: "person-123"}) {
				return errors.New("hosted-service example: unexpected person identity")
			}
			return nil
		},
		ValidateAccount: func(_ context.Context, identity resource.PersonIdentity, account string) error {
			if identity != (resource.PersonIdentity{Issuer: personServerID, Subject: "person-123"}) ||
				account != input.account {
				return errors.Join(resource.ErrInvalidAccount, errors.New("hosted-service example: unknown account"))
			}
			return nil
		},
		R3: &resource.R3Config{
			Registry: input.registry, Definitions: input.definitions,
			Vocabularies: []resource.R3VocabularyConfig{{Definition: input.definition}}, Documents: documents,
			HTTP: resource.R3HTTPAdapter{OperationForRequest: func(request *http.Request) (r3.Operation, bool, error) {
				if request.URL.Path == "/records/current" {
					return input.operation, true, nil
				}
				return r3.Operation{}, false, nil
			}},
		},
		Budget: &resource.BudgetConfig{
			Units: []budgets.UnitDeclaration{input.unit}, RetainLineage: lineage.Retain,
			Offer: func(_ context.Context, request resource.BudgetOfferRequest) (budgets.Value, error) {
				if input.observations != nil {
					input.observations.budgetOffers.Add(1)
				}
				if request.Account == nil || *request.Account != input.account ||
					!sameBudget(request.Requested, input.requestedBudget) {
					return budgets.Value{}, errors.New("hosted-service example: unexpected Budget request")
				}
				return input.resourceOffer, nil
			},
			Cost: func(_ context.Context, request resource.BudgetCostRequest) (int64, error) {
				if request.Principal.Account == nil || *request.Principal.Account != input.account {
					return 0, errors.New("hosted-service example: Budget pricing lost the account")
				}
				return 100_000, nil
			},
			Store: budgetCharges,
			Challenge: func(ctx context.Context, challenge resource.BudgetChallengeRequest) (string, error) {
				retained, ok := lineage.Load()
				if !ok {
					return "", errors.New("hosted-service example: Budget lineage is unavailable")
				}
				if challenge.R3Reference == nil || challenge.Reason != budgets.ReasonBudgetExhausted ||
					challenge.Remaining != 0 || challenge.Required != 100_000 ||
					!sameBudget(challenge.Grant, input.personGrant) ||
					challenge.Principal.Account == nil || *challenge.Principal.Account != input.account ||
					challenge.Principal.PersonServer != retained.Person.Issuer ||
					challenge.Principal.Subject != retained.Person.Subject ||
					challenge.Principal.Tenant != retained.PersonContext.Tenant {
					return "", errors.New("hosted-service example: unexpected Budget challenge")
				}
				document, err := documents.Load(ctx, challenge.R3Reference.URI())
				if err != nil {
					return "", err
				}
				now := input.clock.Now().UTC()
				compact, reference, err := r3.MintBudgetResourceToken(
					input.registry, input.resourceKey,
					aauth.ResourceTokenClaims{
						Issuer: hostedResourceID, DWK: aauth.ResourceDiscoveryDocument,
						Audience: retained.Person.Issuer, JTI: "resource-token-step-up-1",
						PersonServer: retained.Person.Issuer, Subject: retained.Person.Subject,
						PresentedJTI: challenge.Token.JTI, AgentJKT: retained.AgentJKT,
						IssuedAt: now.Unix(), ExpiresAt: retained.ExpiresAt,
						Account:     cloneOptionalString(retained.Account),
						MissionS256: retained.PersonContext.MissionS256,
						Tenant:      retained.PersonContext.Tenant,
					},
					challenge.R3Reference.URI(), document.ExactJSON, retained.Offer, nil,
				)
				if err != nil {
					return "", err
				}
				if reference != *challenge.R3Reference {
					return "", errors.New("hosted-service example: Budget challenge changed the R3 reference")
				}
				return compact, nil
			},
		},
		Protected: http.HandlerFunc(connector.serve),
	})
	if err != nil {
		return composedRoles{}, err
	}
	newLocal := func() (*resource.Server, error) {
		return resource.NewAgentIdentity(resource.AgentIdentityConfig{
			Issuer: localResourceID, KeyResolver: input.resolver, Clock: input.clock,
			AgentTokenRevocations: localRevocations,
			Protected: http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
				response.WriteHeader(http.StatusNoContent)
			}),
		})
	}
	people, err := newPeople()
	if err != nil {
		return composedRoles{}, err
	}
	local, err := newLocal()
	if err != nil {
		return composedRoles{}, err
	}
	input.network.Handle(personServerID, people.Handler())
	input.network.Handle(hostedResourceID, protectedResource.Handler())
	input.network.Handle(localResourceID, local.Handler())
	return composedRoles{
		people: people, connector: connector, newPeople: newPeople, newLocal: newLocal,
	}, nil
}
