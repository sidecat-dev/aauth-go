package main

import (
	"bytes"
	"testing"
)

func TestPaymentApprovalJourney(t *testing.T) {
	var output bytes.Buffer
	run(&output)
	const want = "Payment required at Access Server\nPayment confirmed; approval pending\nApproved: records.read\n"
	if output.String() != want {
		t.Fatalf("output = %q", output.String())
	}
}
