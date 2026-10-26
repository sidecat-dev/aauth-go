package main

import (
	"bytes"
	"testing"
)

func TestSubagentJourneys(t *testing.T) {
	var output bytes.Buffer
	run(&output)
	const want = "Agent Provider issued sub-agent aauth:planner+search@agents.example for aauth:planner@agents.example\n" +
		"Three-party: the sub-agent called /records/42 for person-123 with records.read\n" +
		"Four-party: the Access Server is waiting for approval; the parent polls the Person Server\n" +
		"Four-party: the sub-agent called /orders/7 for person-123 with orders.read\n" +
		"Binding revoked: the Person Server refused the next child Person token (person_token_denied)\n"
	if output.String() != want {
		t.Fatalf("output = %q", output.String())
	}
}
