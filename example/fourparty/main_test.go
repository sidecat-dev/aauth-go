package main

import (
	"bytes"
	"testing"
)

func TestRunCompletesMissionBoundFourPartyJourney(t *testing.T) {
	t.Parallel()

	var output bytes.Buffer
	run(&output)
	const want = "AAuth missionless four-party flow complete: person-123 has records.read\n" +
		"AAuth mission-bound four-party flow complete: person-123 has records.read\n" +
		"mission completed with person acceptance\n"
	if output.String() != want {
		t.Fatalf("output = %q, want %q", output.String(), want)
	}
}
