package main

import (
	"bytes"
	"testing"
)

func TestRunCompletesMissionlessAndMissionInteractionRelayJourneys(t *testing.T) {
	t.Parallel()

	var output bytes.Buffer
	if err := run(&output); err != nil {
		t.Fatal(err)
	}
	const want = "Person Server relayed: https://resource.example/confirm ABCD-EFGH\n" +
		"Agent observed relay state: interacting\n" +
		"Person Server relayed under mission: https://resource.example/confirm ABCD-EFGH\n" +
		"Agent observed mission relay state: interacting\n"
	if output.String() != want {
		t.Fatalf("output = %q, want %q", output.String(), want)
	}
}
