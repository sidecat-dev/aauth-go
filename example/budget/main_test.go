package main

import (
	"bytes"
	"testing"
)

func TestRunCompletesDirectFixedPriceBudgetJourney(t *testing.T) {
	t.Parallel()

	var output bytes.Buffer
	if err := run(&output); err != nil {
		t.Fatal(err)
	}

	const want = "AAuth R3 Budget success: operations records.current and records.export; Resource offered 600000; Person Server granted 400000; charged 150000; remaining 250000\n" +
		"AAuth R3 Budget refusal: insufficient-budget; required 300000; remaining 250000; R3 reference preserved; protected calls 1\n"
	if output.String() != want {
		t.Fatalf("output = %q, want %q", output.String(), want)
	}
}
