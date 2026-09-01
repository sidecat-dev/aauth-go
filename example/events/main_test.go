package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestExample(t *testing.T) {
	t.Parallel()
	var output bytes.Buffer
	if err := run(&output); err != nil {
		t.Fatal(err)
	}
	if got := output.String(); !strings.Contains(got, "AAuth public event complete:") ||
		!strings.Contains(got, `"event_type":"slot.available"`) || !strings.Contains(got, "remaining uses 0") ||
		!strings.Contains(got, "AAuth protected event complete:") ||
		!strings.Contains(got, `"event_type":"appointment.changed"`) {
		t.Fatalf("output = %q", got)
	}
}
