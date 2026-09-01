package main

import (
	"bytes"
	"testing"
)

func TestRunCompletesHostedBootstrapProfiles(t *testing.T) {
	var output bytes.Buffer
	if err := run(&output); err != nil {
		t.Fatal(err)
	}
	const want = "AAuth two-key bootstrap complete: aauth:reference@agents.example\n" +
		"AAuth single-key bootstrap complete: aauth:reference@agents.example\n" +
		"AAuth enrollment revoked: new Agent-token refresh refused\n"
	if output.String() != want {
		t.Fatalf("output = %q, want %q", output.String(), want)
	}
}
