package main

import (
	"bytes"
	"testing"
)

func TestRunCompletesMissionlessAndMissionBoundPermissionJourneys(t *testing.T) {
	t.Parallel()

	var output bytes.Buffer
	if err := run(&output); err != nil {
		t.Fatal(err)
	}
	const want = "Permission request retained: messages.send is pending\n" +
		"Permission granted: application sent one message\n" +
		"Mission permission granted: application archived one report\n"
	if output.String() != want {
		t.Fatalf("output = %q, want %q", output.String(), want)
	}
}
