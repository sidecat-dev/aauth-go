package main

import (
	"bytes"
	"testing"
)

func TestRunCompletesMissionAuditJourney(t *testing.T) {
	t.Parallel()

	var output bytes.Buffer
	if err := run(&output); err != nil {
		t.Fatal(err)
	}
	const want = "Application action complete: prepared status report\n" +
		"Person Server audit retained: documents.prepare\n"
	if output.String() != want {
		t.Fatalf("output = %q, want %q", output.String(), want)
	}
}
