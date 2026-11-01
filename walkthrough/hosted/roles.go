package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/budgets"
	"gitlab.com/sidecat-dev/aauth-go/personserver"
	"gitlab.com/sidecat-dev/aauth-go/r3"
	"gitlab.com/sidecat-dev/aauth-go/r3/vocab/mcp"
	"gitlab.com/sidecat-dev/aauth-go/resource"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

type hostedRoles struct {
	people     http.Handler
	resource   http.Handler
	operations r3.OperationSet
	unit       budgets.UnitDeclaration
}

func composeHostedRoles(stateDir string, config hostConfig, accounts *accountFileStore, protocol *hostedProtocolStore, clock aauth.Clock) (hostedRoles, error) {
	personOrigin := hostedPersonOrigin(config.Origin)
	resourceOrigin := hostedResourceOrigin(config.Origin)
	clientConfig := agentConfig{ServiceOrigin: config.Origin, ServiceAddress: config.Listen, EnrollmentCode: config.EnrollmentCode, ControlToken: config.ControlToken}
	httpClient, err := newHostedHTTPClient(stateDir, clientConfig)
	if err != nil {
		return hostedRoles{}, err
	}
	resolver, err := signaturekey.NewHTTPKeyResolver(signaturekey.HTTPKeyResolverConfig{
		Client: httpClient, Clock: clock, Admit: admitHostedRoles(config.Origin),
		TransportEnforcesEgress: clientConfig.transportEnforcesEgress(),
	})
	if err != nil {
		return hostedRoles{}, err
	}
	personKey, err := loadHostedSigningKey(stateDir, "person")
	if err != nil {
		return hostedRoles{}, err
	}
	resourceKey, err := loadHostedSigningKey(stateDir, "resource")
	if err != nil {
		return hostedRoles{}, err
	}
	registry, definitions, operations, operation, definition, err := hostedR3Model(resourceOrigin)
	if err != nil {
		return hostedRoles{}, err
	}
	unit, err := budgets.NewUnit("USD", 6)
	if err != nil {
		return hostedRoles{}, err
	}
	grant, err := budgets.NewValue(100_000, unit)
	if err != nil {
		return hostedRoles{}, err
	}
	declaration, err := budgets.NewBoundedUnitDeclaration(unit, 1_000_000, "US dollars at micro-dollar precision")
	if err != nil {
		return hostedRoles{}, err
	}
	people, err := personserver.NewPSAuthorization(personserver.PSAuthorizationConfig{
		Issuer: personOrigin, SigningKey: personKey, KeyResolver: resolver, Clock: clock,
		NewID: hostedRandomID, Tokens: protocol, AgentTokenRevocations: protocol,
		BindPerson: func(_ context.Context, request personserver.PersonTokenRequest) (personserver.Person, error) {
			if request.Resource != resourceOrigin {
				return personserver.Person{}, errors.New("hosted walkthrough: unexpected Person-token Resource")
			}
			return personserver.Person{Subject: "person-1", Tenant: "tenant-1", Lifetime: 20 * time.Minute}, nil
		},
		Missions: &personserver.MissionConfig{Approve: func(_ context.Context, request personserver.MissionApprovalRequest) (personserver.MissionDecision, error) {
			account, approved, err := accounts.approvedMissionAccount()
			if err != nil {
				return personserver.MissionDecision{}, err
			}
			if !approved || account != "records-primary" || request.Proposal.Description != "Read one hosted record under a fixed Budget." ||
				len(request.Proposal.Tools) != 1 || request.Proposal.Tools[0].Name != "records.current" ||
				len(request.Proposal.Resources) != 1 || request.Proposal.Resources[0] != resourceOrigin {
				return personserver.MissionDecision{}, personserver.ErrMissionDenied
			}
			expiresAt := clock.Now().UTC().Add(15 * time.Minute)
			return personserver.MissionDecision{
				Description: request.Proposal.Description, ApprovedTools: request.Proposal.Tools,
				ApprovedResources: request.Proposal.Resources, ExpiresAt: &expiresAt,
			}, nil
		}},
		Budget: &personserver.BudgetConfig{ResolveResourceUnits: func(_ context.Context, requested string) ([]budgets.UnitDeclaration, error) {
			if requested != resourceOrigin {
				return nil, errors.New("hosted walkthrough: unexpected Budget Resource")
			}
			return []budgets.UnitDeclaration{declaration}, nil
		}},
		R3: &personserver.DirectR3Config{
			Registry: registry, HTTPClient: httpClient, Admit: admitHostedRoles(config.Origin),
			Issuances: hostedR3IssuanceStore{store: protocol},
			AuthorizeDocument: func(_ context.Context, request personserver.AuthorizationRequest, _ r3.Reference, document r3.Document) (personserver.DirectR3Decision, error) {
				if request.Resource != resourceOrigin || request.Subject != "person-1" || request.Account == nil || *request.Account != "records-primary" ||
					request.Budget == nil || !sameHostedBudget(*request.Budget, grant) {
					return personserver.DirectR3Decision{}, errors.New("hosted walkthrough: unexpected MCP Budget authorization")
				}
				granted, err := r3.NewGrantedOperations(mcp.Vocabulary(), operation)
				if err != nil {
					return personserver.DirectR3Decision{}, err
				}
				r3Grant, err := r3.NewGrant(granted, document)
				if err != nil {
					return personserver.DirectR3Decision{}, err
				}
				return personserver.DirectR3Decision{Lifetime: 10 * time.Minute, Grant: r3Grant, Budget: &grant}, nil
			},
		},
	})
	if err != nil {
		return hostedRoles{}, err
	}
	documents := hostedR3DocumentStore{store: protocol}
	protected, err := resource.NewPSAuthorization(resource.PSAuthorizationConfig{
		Issuer: resourceOrigin, SigningKey: resourceKey, KeyResolver: resolver, Clock: clock, NewID: hostedRandomID,
		ResolvePerson: func(_ context.Context, identity resource.PersonIdentity, _ resource.PersonContext) error {
			if identity != (resource.PersonIdentity{Issuer: personOrigin, Subject: "person-1"}) {
				return errors.New("hosted walkthrough: unexpected person identity")
			}
			return nil
		},
		ValidateAccount: func(_ context.Context, identity resource.PersonIdentity, account string) error {
			if identity != (resource.PersonIdentity{Issuer: personOrigin, Subject: "person-1"}) || account != "records-primary" {
				return errors.Join(resource.ErrInvalidAccount, errors.New("hosted walkthrough: account is not linked"))
			}
			if _, err := accounts.connectorCredential(account); err != nil {
				return errors.Join(resource.ErrInvalidAccount, err)
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
			Units: []budgets.UnitDeclaration{declaration}, Store: hostedBudgetStore{store: protocol},
			RetainLineage: protocol.retainLineage,
			Offer: func(_ context.Context, request resource.BudgetOfferRequest) (budgets.Value, error) {
				if request.Account == nil || *request.Account != "records-primary" || !sameHostedBudget(request.Requested, grant) {
					return budgets.Value{}, errors.New("hosted walkthrough: unexpected Budget offer")
				}
				return grant, nil
			},
			Cost: func(_ context.Context, request resource.BudgetCostRequest) (int64, error) {
				requestKey := request.Request.Header.Get("Idempotency-Key")
				if requestKey == "" {
					return 0, errors.New("hosted walkthrough: Idempotency-Key is required")
				}
				retained, err := protocol.hasConnectorResult(requestKey)
				if err != nil {
					return 0, err
				}
				if retained {
					return 0, nil
				}
				return 100_000, nil
			},
			Challenge: func(ctx context.Context, challenge resource.BudgetChallengeRequest) (string, error) {
				lineage, err := protocol.oneLineage()
				if err != nil {
					return "", err
				}
				if challenge.R3Reference == nil {
					return "", errors.New("hosted walkthrough: Budget challenge lost the R3 reference")
				}
				document, err := documents.Load(ctx, challenge.R3Reference.URI())
				if err != nil {
					return "", err
				}
				now := clock.Now().UTC()
				compact, reference, err := r3.MintBudgetResourceToken(registry, resourceKey, aauth.ResourceTokenClaims{
					Issuer: resourceOrigin, DWK: aauth.ResourceDiscoveryDocument, Audience: lineage.Person.Issuer,
					JTI: hostedRandomID(), PersonServer: lineage.Person.Issuer, Subject: lineage.Person.Subject,
					PresentedJTI: challenge.Token.JTI, AgentJKT: lineage.AgentJKT, IssuedAt: now.Unix(), ExpiresAt: lineage.ExpiresAt,
					Account: cloneHostedString(lineage.Account), MissionS256: lineage.PersonContext.MissionS256, Tenant: lineage.PersonContext.Tenant,
				}, challenge.R3Reference.URI(), document.ExactJSON, lineage.Offer, nil)
				if err != nil {
					return "", err
				}
				if reference != *challenge.R3Reference {
					return "", errors.New("hosted walkthrough: Budget challenge changed the R3 reference")
				}
				return compact, nil
			},
		},
		Protected: http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			principal, ok := resource.AuthPrincipalFromContext(request.Context())
			if !ok || principal.Account == nil {
				writeHostedJSON(response, http.StatusInternalServerError, map[string]string{"error": "connector_context_unavailable"})
				return
			}
			credential, err := accounts.connectorCredential(*principal.Account)
			if err != nil {
				writeHostedJSON(response, http.StatusInternalServerError, map[string]string{"error": "connector_credential_unavailable"})
				return
			}
			result, replayed, calls, err := protocol.connectorResult(request.Header.Get("Idempotency-Key"), *principal.Account, credential)
			if err != nil {
				writeHostedJSON(response, http.StatusConflict, map[string]string{"error": "connector_request_conflict"})
				return
			}
			writeHostedJSON(response, http.StatusOK, map[string]any{"result": result.Result, "replayed": replayed, "connector_calls": calls})
		}),
	})
	if err != nil {
		return hostedRoles{}, err
	}
	return hostedRoles{people: people.Handler(), resource: protected.Handler(), operations: operations, unit: declaration}, nil
}

func admitHostedRoles(base string) signaturekey.EgressAdmitter {
	allowed := map[string]bool{base: true, hostedPersonOrigin(base): true, hostedResourceOrigin(base): true}
	return func(_ context.Context, endpoint string) error {
		request, err := http.NewRequest(http.MethodGet, endpoint, nil)
		if err != nil {
			return err
		}
		origin := request.URL.Scheme + "://" + request.URL.Host
		if !allowed[origin] {
			return fmt.Errorf("endpoint %q is outside the hosted roles", endpoint)
		}
		return nil
	}
}

func cloneHostedString(value *string) *string {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}
