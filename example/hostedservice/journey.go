package main

import (
	"context"
	"errors"
	"net/http"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	clientagent "gitlab.com/sidecat-dev/aauth-go/agent"
	"gitlab.com/sidecat-dev/aauth-go/agentprovider"
	"gitlab.com/sidecat-dev/aauth-go/budgets"
	"gitlab.com/sidecat-dev/aauth-go/personserver"
	"gitlab.com/sidecat-dev/aauth-go/r3"
	"gitlab.com/sidecat-dev/aauth-go/resource"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

func proveLocalAgentAccess(ctx context.Context, client *clientagent.Client) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, localResourceID+"/status", nil)
	if err != nil {
		return err
	}
	response, err := client.CallAsAgent(ctx, request)
	if err != nil {
		return err
	}
	return response.Body.Close()
}

func grantLocalPermission(ctx context.Context, client *clientagent.Client) error {
	result, err := client.RequestPermission(ctx, clientagent.PermissionRequest{
		PersonServer: personServerID, Action: "connector.prepare",
		Description: "Prepare the account connector without invoking it.",
	})
	if err != nil {
		return err
	}
	decision, ok := result.Decision()
	if !ok || decision.Permission() != aauth.PermissionGranted {
		return errors.New("hosted-service example: local permission was not granted")
	}
	return nil
}

func approveMission(
	ctx context.Context,
	now time.Time,
	client *clientagent.Client,
	people *personserver.Server,
) (clientagent.MissionResult, error) {
	result, err := client.BeginMission(ctx, clientagent.MissionRequest{
		PersonServer: personServerID,
		Proposal: aauth.MissionProposal{
			Description: "Review and approve the hosted records query.",
			Tools:       []aauth.MissionTool{{Name: "records.current", Description: "Read the current hosted record"}},
			Resources:   []string{hostedResourceID},
		},
	})
	if err != nil {
		return clientagent.MissionResult{}, err
	}
	pending, ok := result.Pending()
	if !ok {
		return clientagent.MissionResult{}, errors.New("hosted-service example: mission did not enter host review")
	}
	reviews, err := people.PendingMissionProposals(ctx, 10)
	if err != nil || len(reviews) != 1 {
		return clientagent.MissionResult{}, errors.Join(errors.New("hosted-service example: expected one pending mission review"), err)
	}
	expiresAt := now.Add(20 * time.Minute)
	if err := people.ApproveMissionProposal(ctx, reviews[0], personserver.MissionDecision{
		Description:   reviews[0].Proposal().Description,
		ApprovedTools: reviews[0].Proposal().Tools, ApprovedResources: reviews[0].Proposal().Resources,
		ExpiresAt: &expiresAt,
	}); err != nil {
		return clientagent.MissionResult{}, err
	}
	completed, err := client.PollMissionProposal(ctx, pending)
	if err != nil {
		return clientagent.MissionResult{}, err
	}
	mission, ok := completed.Approval()
	if !ok {
		return clientagent.MissionResult{}, errors.New("hosted-service example: approved mission was not delivered")
	}
	return mission, nil
}

func callHostedConnector(
	ctx context.Context,
	client *clientagent.Client,
	operations r3.OperationSet,
	requestedBudget budgets.Value,
	mission clientagent.MissionResult,
	connector *connectorApplication,
) error {
	if !mission.ApprovesTool("records.current") {
		return errors.New("hosted-service example: mission did not approve the connector tool")
	}
	personToken, ok := mission.PersonToken(hostedResourceID)
	if !ok {
		return errors.New("hosted-service example: mission omitted the connector Person token")
	}
	resourceToken, err := client.Authorize(ctx, clientagent.AuthorizeRequest{
		Resource: hostedResourceID, PersonToken: personToken,
		R3Operations: &operations, Budget: &requestedBudget,
	})
	if err != nil {
		return err
	}
	authToken, err := client.Exchange(ctx, clientagent.ExchangeRequest{
		PersonServer: personServerID, ResourceToken: resourceToken,
	})
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, hostedResourceID+"/records/current", nil)
	if err != nil {
		return err
	}
	call, err := client.BeginBudgetCall(ctx, clientagent.BudgetCall{Request: request, AuthToken: authToken})
	if err != nil {
		return err
	}
	response, ok := call.Response()
	if !ok {
		return errors.New("hosted-service example: R3 Budget call returned no application response")
	}
	if err := response.Body.Close(); err != nil {
		return err
	}
	cost, hasCost := call.Cost()
	feedback, hasFeedback := call.Feedback()
	if !hasCost || cost != 100_000 || !hasFeedback || feedback.Remaining() != 0 || connector.calls.Load() != 1 {
		return errors.New("hosted-service example: R3 Budget consequence was not retained exactly once")
	}
	secondRequest, err := http.NewRequestWithContext(ctx, http.MethodGet, hostedResourceID+"/records/current", nil)
	if err != nil {
		return err
	}
	refused, err := client.BeginBudgetCall(ctx, clientagent.BudgetCall{Request: secondRequest, AuthToken: authToken})
	if err != nil {
		return err
	}
	if response, ok := refused.Response(); ok {
		_ = response.Body.Close()
		return errors.New("hosted-service example: exhausted Budget reached the connector")
	}
	authorization, ok := refused.AuthorizationRequired()
	if !ok || authorization.ResourceToken() == "" {
		return errors.New("hosted-service example: exhausted Budget returned no verified step-up")
	}
	reason, hasReason := authorization.Reason()
	refusalFeedback, hasRefusalFeedback := refused.Feedback()
	_, hasRefusalCost := refused.Cost()
	if !hasReason || reason != budgets.ReasonBudgetExhausted || !hasRefusalFeedback ||
		refusalFeedback.Remaining() != 0 || hasRefusalCost || connector.calls.Load() != 1 {
		return errors.New("hosted-service example: exhausted Budget refusal was inconsistent")
	}
	reauthorizedToken, err := client.Exchange(ctx, clientagent.ExchangeRequest{
		PersonServer: personServerID, ResourceToken: authorization.ResourceToken(),
	})
	if err != nil {
		return err
	}
	recoveredRequest, err := http.NewRequestWithContext(ctx, http.MethodGet, hostedResourceID+"/records/current", nil)
	if err != nil {
		return err
	}
	recovered, err := client.BeginBudgetCall(ctx, clientagent.BudgetCall{
		Request: recoveredRequest, AuthToken: reauthorizedToken,
	})
	if err != nil {
		return err
	}
	recoveredResponse, ok := recovered.Response()
	if !ok || recoveredResponse.StatusCode != http.StatusNoContent {
		return errors.New("hosted-service example: replacement Budget grant did not resume connector work")
	}
	if err := recoveredResponse.Body.Close(); err != nil {
		return err
	}
	recoveredCost, hasRecoveredCost := recovered.Cost()
	recoveredFeedback, hasRecoveredFeedback := recovered.Feedback()
	if !hasRecoveredCost || recoveredCost != 100_000 || !hasRecoveredFeedback ||
		recoveredFeedback.Remaining() != 0 || connector.calls.Load() != 2 {
		return errors.New("hosted-service example: resumed connector consequence was not retained exactly once")
	}
	if !connector.credentialStayedPrivate() {
		return errors.New("hosted-service example: connector credential left application custody")
	}
	return nil
}

type revocationJourney struct {
	client     *clientagent.Client
	agentToken string
	provider   *agentprovider.Server
	resolver   signaturekey.KeyResolver
	clock      aauth.Clock
	httpClient *http.Client
	network    *logicalTransport
	newPeople  func() (*personserver.Server, error)
	newLocal   func() (*resource.Server, error)
}

func (journey revocationJourney) run(ctx context.Context) error {
	claims, err := aauth.VerifyAgentToken(ctx, journey.agentToken, journey.resolver, journey.clock)
	if err != nil {
		return err
	}
	reference := aauth.TokenReference{Issuer: claims.Issuer, JTI: claims.JTI}
	revoker, err := agentprovider.NewRevocationClient(agentprovider.RevocationClientConfig{
		Provider: journey.provider, HTTPClient: journey.httpClient, Admit: journey.network.Admit,
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
	people, err := journey.newPeople()
	if err != nil {
		return err
	}
	local, err := journey.newLocal()
	if err != nil {
		return err
	}
	journey.network.Handle(personServerID, people.Handler())
	journey.network.Handle(localResourceID, local.Handler())
	_, personErr := journey.client.PersonToken(ctx, clientagent.PersonTokenRequest{
		PersonServer: personServerID, Resource: hostedResourceID,
	})
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, localResourceID+"/status", nil)
	if err != nil {
		return err
	}
	response, localErr := journey.client.CallAsAgent(ctx, request)
	if response != nil {
		_ = response.Body.Close()
	}
	if personErr == nil || localErr == nil {
		return errors.New("hosted-service example: revoked Agent token remained usable")
	}
	return nil
}
