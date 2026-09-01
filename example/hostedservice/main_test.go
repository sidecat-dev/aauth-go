package main

import (
	"bytes"
	"testing"

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
		"3. approval-only mission reviewed and delivered\n" +
		"4. MCP operation authorized; exhausted call refused before dispatch; replacement grant resumed connector work once\n" +
		"5. OAuth service credential remained inside the connector application\n" +
		"6. Agent token revoked at PS and local Resource; later requests refused\n"
	if output.String() != want {
		t.Fatalf("output = %q, want %q", output.String(), want)
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
