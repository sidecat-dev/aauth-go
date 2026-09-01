package main

import (
	"bytes"
	"errors"
	"testing"

	"gitlab.com/sidecat-dev/aauth-go/resource"
	"gitlab.com/sidecat-dev/aauth-go/resource/storetest"
)

var errWriteOutput = errors.New("write output")

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errWriteOutput }

func TestRunCompletesFourPartyFixedBudgetJourney(t *testing.T) {
	t.Parallel()

	var output bytes.Buffer
	if err := run(&output); err != nil {
		t.Fatal(err)
	}

	const want = "AAuth four-party Budget success: Resource offered 600000 USD/6; Person Server ceiling 450000; Access Server granted 300000; charged 125000; remaining 175000; protected calls 1\n"
	if output.String() != want {
		t.Fatalf("output = %q, want %q", output.String(), want)
	}
}

func TestBudgetStoreContract(t *testing.T) {
	storetest.RunBudget(t, storetest.BudgetContract{
		New: func(testing.TB) resource.BudgetStore { return newBudgetStore() },
	})
}

func TestRunReturnsOutputFailure(t *testing.T) {
	t.Parallel()

	if err := run(failingWriter{}); !errors.Is(err, errWriteOutput) {
		t.Fatalf("run error = %v, want %v", err, errWriteOutput)
	}
}
