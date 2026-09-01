package main

import (
	"bytes"
	"testing"
)

func TestRunCompletesHostedServiceLaunchProfile(t *testing.T) {
	var output bytes.Buffer
	if err := run(&output); err != nil {
		t.Fatal(err)
	}
	want := "1. enrollment + delegated Agent-token refresh complete\n" +
		"2. missionless local permission granted\n" +
		"3. approval-only mission reviewed and delivered\n" +
		"4. MCP operation authorized; fixed Budget charged before one connector call\n" +
		"5. OAuth service credential remained inside the connector application\n" +
		"6. Agent token revoked at PS and local Resource; later requests refused\n"
	if output.String() != want {
		t.Fatalf("output = %q, want %q", output.String(), want)
	}
}
