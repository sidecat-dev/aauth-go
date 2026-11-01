package main

import (
	"bytes"
	"testing"
)

func TestRunPrintsTheThreeAnswers(t *testing.T) {
	var output bytes.Buffer
	if err := run(&output); err != nil {
		t.Fatal(err)
	}
	want := "unsigned: 401 requirement=agent-token\n" +
		"signed: 200 hello, aauth:assistant@ap.example\n" +
		"not admitted: 403\n"
	if output.String() != want {
		t.Fatalf("output = %q, want %q", output.String(), want)
	}
}
