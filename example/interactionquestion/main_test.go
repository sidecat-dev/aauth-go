package main

import (
	"bytes"
	"testing"
)

func TestRunCompletesInteractionQuestionJourney(t *testing.T) {
	t.Parallel()

	var output bytes.Buffer
	if err := run(&output); err != nil {
		t.Fatal(err)
	}
	const want = "Person Server received question: Which route should I take?\n" +
		"Agent received answer: Take the northern route.\n"
	if output.String() != want {
		t.Fatalf("output = %q, want %q", output.String(), want)
	}
}
