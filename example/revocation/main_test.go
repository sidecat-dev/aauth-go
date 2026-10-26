package main

import (
	"bytes"
	"testing"
)

func TestRunCompletesRevocationAndExplicitPersonTokenRecovery(t *testing.T) {
	var output bytes.Buffer
	if err := run(&output); err != nil {
		t.Fatal(err)
	}
	want := "auth-token-1 accepted\n" +
		"auth-token-1 revocation response lost; explicit retry succeeded after Resource recomposition\n" +
		"auth-token-1 refused: 401 revoked_jwt\n" +
		"person-token-2 obtained; original request retried with it\n" +
		"auth-token-2 accepted after Person-token recovery\n" +
		"agent-token-1 Agent token revoked at Person Server and direct Resource; exact replays succeeded; later requests refused\n"
	if output.String() != want {
		t.Fatalf("output = %q, want %q", output.String(), want)
	}
}
