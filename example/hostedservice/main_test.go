package main

import (
	"bytes"
	"errors"
	"net/http"
	"strings"
	"testing"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/personserver"
	personstoretest "gitlab.com/sidecat-dev/aauth-go/personserver/storetest"
	"gitlab.com/sidecat-dev/aauth-go/resource"
	resourcestoretest "gitlab.com/sidecat-dev/aauth-go/resource/storetest"
)

func TestRunCompletesHostedServiceLaunchProfile(t *testing.T) {
	var output bytes.Buffer
	if err := run(&output); err != nil {
		t.Fatal(err)
	}
	want := "1. enrollment + delegated Agent-token refresh complete\n" +
		"2. missionless local permission granted\n" +
		"3. reviewed mission supplied the connector Person token and approved tool\n" +
		"4. account-bound MCP operation authorized; exhausted call recovered; person-accepted mission completion retained\n" +
		"5. OAuth service credential remained inside the connector application\n" +
		"6. Agent token revoked at PS and local Resource; later requests refused\n"
	if output.String() != want {
		t.Fatalf("output = %q, want %q", output.String(), want)
	}
}

func TestRunCompletesSelfHostedAgentLaunchProfile(t *testing.T) {
	var output bytes.Buffer
	if err := runSelfHosted(&output); err != nil {
		t.Fatal(err)
	}
	want := "1. self-hosted Agent token for hosted Person Server complete\n" +
		"2. missionless local permission granted\n" +
		"3. reviewed mission supplied the connector Person token and approved tool\n" +
		"4. account-bound MCP operation authorized; exhausted call recovered; person-accepted mission completion retained\n" +
		"5. OAuth service credential remained inside the connector application\n"
	if output.String() != want {
		t.Fatalf("output = %q, want %q", output.String(), want)
	}
}

func TestHostedServiceLaunchProfileRefusesUnknownAccountBeforeConnectorUse(t *testing.T) {
	var output bytes.Buffer
	observations := &profileObservations{}
	err := runProfileForAccountObserved(&output, false, "unknown-account", observations)
	var problem *aauth.ProblemError
	if !errors.As(err, &problem) || problem.Status != http.StatusBadRequest || problem.Code != "invalid_account" {
		t.Fatalf("unknown account error = %v; problem = %#v", err, problem)
	}
	if offers, charges, connectors := observations.budgetOffers.Load(), observations.budgetCharges.Load(), observations.connectorCalls.Load(); offers != 0 || charges != 0 || connectors != 0 {
		t.Fatalf("unknown account consequences = offers %d, charges %d, connector calls %d", offers, charges, connectors)
	}
	if strings.Contains(output.String(), "account-bound MCP operation authorized") ||
		strings.Contains(output.String(), "OAuth service credential") {
		t.Fatalf("unknown account reached connector completion: %q", output.String())
	}
}

func TestAgentTokenRevocationStoreContracts(t *testing.T) {
	t.Run("Person Server", func(t *testing.T) {
		personstoretest.RunAgentTokenRevocation(t, personstoretest.AgentTokenRevocationContract{
			New: func(testing.TB) personserver.AgentTokenRevocationStore {
				return newAgentTokenRevocationStore()
			},
		})
	})
	t.Run("Resource", func(t *testing.T) {
		resourcestoretest.RunAgentTokenRevocation(t, resourcestoretest.AgentTokenRevocationContract{
			New: func(testing.TB) resource.AgentTokenRevocationStore {
				return newAgentTokenRevocationStore()
			},
		})
	})
}
