package main

import (
	"bytes"
	"testing"
)

func TestRunCompletesRevocationAndExplicitReauthorization(t *testing.T) {
	var output bytes.Buffer
	if err := run(&output); err != nil {
		t.Fatal(err)
	}
	want := "auth-token-1 accepted\n" +
		"auth-token-1 revocation response lost; explicit retry succeeded after Resource recomposition\n" +
		"auth-token-1 refused: 403 access_denied\n" +
		"auth-token-2 accepted after explicit re-authorization\n" +
		"agent-token-1 Agent token revoked; exact replay succeeded; later Person Server request refused\n"
	if output.String() != want {
		t.Fatalf("output = %q, want %q", output.String(), want)
	}
}
