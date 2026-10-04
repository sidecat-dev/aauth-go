package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	clientagent "gitlab.com/sidecat-dev/aauth-go/agent"
	"gitlab.com/sidecat-dev/aauth-go/budgets"
	"gitlab.com/sidecat-dev/aauth-go/r3"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

type actionCredential struct {
	RequestKey string `json:"request_key"`
	AuthToken  string `json:"auth_token"`
}

type actionResultState struct {
	Status          string `json:"status"`
	RequestKey      string `json:"request_key"`
	Result          string `json:"result"`
	Replayed        bool   `json:"replayed"`
	ConnectorCalls  int    `json:"connector_calls"`
	BudgetRemaining int64  `json:"budget_remaining"`
}

func actCommand(arguments []string) error {
	flags := flag.NewFlagSet("act", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	stateDir := flags.String("state", "", "Agent state directory")
	requestKey := flags.String("request-key", "", "application idempotency key")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if *stateDir == "" || strings.TrimSpace(*requestKey) == "" || *requestKey != strings.TrimSpace(*requestKey) || flags.NArg() != 0 {
		return errors.New("act requires --state DIR --request-key KEY")
	}
	resultPath := actionResultPath(*stateDir, *requestKey)
	var retained actionResultState
	if err := readJSON(resultPath, &retained); err == nil {
		if retained.RequestKey != *requestKey {
			return errors.New("request key conflicts with retained action")
		}
		return json.NewEncoder(os.Stdout).Encode(retained)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	config, httpClient, err := loadHostedAgentHTTP(*stateDir)
	if err != nil {
		return err
	}
	client, operations, requestedBudget, err := newHostedAgentClient(*stateDir, config, httpClient)
	if err != nil {
		return err
	}
	credentialPath := actionCredentialPath(*stateDir, *requestKey)
	var credential actionCredential
	if err := readJSON(credentialPath, &credential); err == nil {
		if credential.RequestKey != *requestKey || credential.AuthToken == "" {
			return errors.New("request key conflicts with retained authorization")
		}
	} else if errors.Is(err, os.ErrNotExist) {
		credential, err = authorizeHostedAction(client, config, operations, requestedBudget, *requestKey)
		if err != nil {
			return err
		}
		if err := writeJSONFile(credentialPath, 0o600, credential); err != nil {
			return err
		}
	} else {
		return err
	}
	request, err := http.NewRequestWithContext(context.Background(), http.MethodPost, hostedResourceOrigin(config.ServiceOrigin)+"/records/current", strings.NewReader(`{}`))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", *requestKey)
	call, err := client.BeginBudgetCall(context.Background(), clientagent.BudgetCall{Request: request, AuthToken: credential.AuthToken})
	if err != nil {
		return err
	}
	response, ok := call.Response()
	if !ok {
		if requirement, exists := call.AuthorizationRequired(); exists {
			reason, _ := requirement.Reason()
			return fmt.Errorf("hosted authorization required: %s", reason)
		}
		return errors.New("hosted connector returned no application response")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return readHostedRemoteError(response)
	}
	var connector struct {
		Result         string `json:"result"`
		Replayed       bool   `json:"replayed"`
		ConnectorCalls int    `json:"connector_calls"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&connector); err != nil {
		return err
	}
	feedback, ok := call.Feedback()
	if !ok {
		return errors.New("hosted Budget call returned no feedback")
	}
	retained = actionResultState{
		Status: "completed", RequestKey: *requestKey, Result: connector.Result, Replayed: connector.Replayed,
		ConnectorCalls: connector.ConnectorCalls, BudgetRemaining: feedback.Remaining(),
	}
	if err := writeJSONFile(resultPath, 0o600, retained); err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(retained)
}

func actionResultPath(stateDir, requestKey string) string {
	return filepath.Join(stateDir, "action-result-"+actionKeySuffix(requestKey)+".json")
}

func actionCredentialPath(stateDir, requestKey string) string {
	return filepath.Join(stateDir, "action-credential-"+actionKeySuffix(requestKey)+".json")
}

func actionKeySuffix(requestKey string) string {
	digest := sha256.Sum256([]byte(requestKey))
	return fmt.Sprintf("%x", digest[:16])
}

func newHostedAgentClient(stateDir string, config agentConfig, httpClient *http.Client) (*clientagent.Client, r3.OperationSet, budgets.Value, error) {
	connection, err := loadRetainedConnection(stateDir)
	if err != nil {
		return nil, r3.OperationSet{}, budgets.Value{}, errors.New("connect the Agent before acting")
	}
	agentKey, err := loadHostedSigningKey(stateDir, "agent")
	if err != nil {
		return nil, r3.OperationSet{}, budgets.Value{}, err
	}
	clock := aauth.ClockFunc(func() time.Time { return time.Now().UTC() })
	resolver, err := signaturekey.NewHTTPKeyResolver(signaturekey.HTTPKeyResolverConfig{
		Client: httpClient, Clock: clock, Admit: admitHostedRoles(config.ServiceOrigin),
	})
	if err != nil {
		return nil, r3.OperationSet{}, budgets.Value{}, err
	}
	registry, _, operations, _, _, err := hostedR3Model(hostedResourceOrigin(config.ServiceOrigin))
	if err != nil {
		return nil, r3.OperationSet{}, budgets.Value{}, err
	}
	client, err := clientagent.New(context.Background(), clientagent.Config{
		Identifier: connection.Agent, SigningKey: agentKey, AgentToken: connection.AgentToken,
		KeyResolver: resolver, HTTPClient: httpClient, Clock: clock, R3: &clientagent.R3Config{Registry: registry},
	})
	if err != nil {
		return nil, r3.OperationSet{}, budgets.Value{}, err
	}
	unit, err := budgets.NewUnit("USD", 6)
	if err != nil {
		return nil, r3.OperationSet{}, budgets.Value{}, err
	}
	value, err := budgets.NewValue(100_000, unit)
	return client, operations, value, err
}

func authorizeHostedAction(client *clientagent.Client, config agentConfig, operations r3.OperationSet, requestedBudget budgets.Value, requestKey string) (actionCredential, error) {
	personOrigin := hostedPersonOrigin(config.ServiceOrigin)
	resourceOrigin := hostedResourceOrigin(config.ServiceOrigin)
	mission, err := client.BeginMission(context.Background(), clientagent.MissionRequest{
		PersonServer: personOrigin,
		Proposal: aauth.MissionProposal{
			Description: "Read one hosted record under a fixed Budget.",
			Tools:       []aauth.MissionTool{{Name: "records.current", Description: "Read the current hosted record"}},
			Resources:   []string{resourceOrigin},
		},
	})
	if err != nil {
		return actionCredential{}, err
	}
	approval, ok := mission.Approval()
	if !ok || !approval.ApprovesTool("records.current") {
		return actionCredential{}, errors.New("hosted mission was not approved")
	}
	personToken, ok := approval.PersonToken(resourceOrigin)
	if !ok {
		return actionCredential{}, errors.New("hosted mission omitted the Resource Person token")
	}
	account := "records-primary"
	resourceToken, err := client.Authorize(context.Background(), clientagent.AuthorizeRequest{
		Resource: resourceOrigin, PersonToken: personToken, Account: &account,
		R3Operations: &operations, Budget: &requestedBudget,
	})
	if err != nil {
		return actionCredential{}, err
	}
	authToken, err := client.Exchange(context.Background(), clientagent.ExchangeRequest{
		PersonServer: personOrigin, ResourceToken: resourceToken, PresentedToken: personToken,
	})
	if err != nil {
		return actionCredential{}, err
	}
	return actionCredential{RequestKey: requestKey, AuthToken: authToken}, nil
}
