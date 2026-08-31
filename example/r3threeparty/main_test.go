package main

import (
	"bytes"
	"testing"
)

func TestRunCompletesDirectThreePartyR3Journey(t *testing.T) {
	t.Parallel()

	var output bytes.Buffer
	if err := run(&output); err != nil {
		t.Fatal(err)
	}

	const want = "AAuth direct R3 three-party flow complete: granted records.read; withheld records.export\n"
	if output.String() != want {
		t.Fatalf("output = %q, want %q", output.String(), want)
	}
}
