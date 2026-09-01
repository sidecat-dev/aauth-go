package main

import (
	"bytes"
	"testing"
)

func TestRunCompletesMissionlessAndMissionInteractionQuestionJourneys(t *testing.T) {
	t.Parallel()

	var output bytes.Buffer
	if err := run(&output); err != nil {
		t.Fatal(err)
	}
	const want = "Person Server received question: Which route should I take?\n" +
		"Agent received answer: Take the northern route.\n" +
		"Person Server received mission question: Should I continue the mission?\n" +
		"Agent received mission answer: Continue the mission.\n"
	if output.String() != want {
		t.Fatalf("output = %q, want %q", output.String(), want)
	}
}
