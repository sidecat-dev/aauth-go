package main

import (
	"bytes"
	"testing"
)

func TestRunCompletesSelfHostedJourney(t *testing.T) {
	t.Parallel()
	var output bytes.Buffer
	if err := run(&output); err != nil {
		t.Fatal(err)
	}
	const want = "AAuth local permission granted: workspace.inspect\n" +
		"AAuth self-hosted Agent accepted: aauth:local@agent.example\n" +
		"AAuth hosted Resource accepted: account-123 has records.read\n"
	if output.String() != want {
		t.Fatalf("output = %q, want %q", output.String(), want)
	}
}
