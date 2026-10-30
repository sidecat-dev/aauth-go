package r3_test

import (
	"encoding/json"
	"strings"
	"testing"

	"gitlab.com/sidecat-dev/aauth-go/r3"
)

func TestReleaseProposalCarriesResultAndStatesTheRelease(t *testing.T) {
	t.Parallel()

	registry := newMCPRegistry()
	operation := mustOperation(t, "runQuery")
	parameters, err := r3.NewParameters(nil)
	if err != nil {
		t.Fatal(err)
	}
	display, err := r3.NewDisplay("Release the result of a query over employee records", "", "214 employee records", "")
	if err != nil {
		t.Fatal(err)
	}
	execution, err := r3.NewProposalDisplay(display, "## Action\nRun a query")
	if err != nil {
		t.Fatal(err)
	}
	result := json.RawMessage(`{ "records": 214, "contains": ["national_id"] }`)
	if _, err := r3.NewProposal(operation, parameters, r3.ProposalOptions{Result: result, Display: &execution}); err == nil {
		t.Fatal("a proposal with a result was built with a display that does not state the release")
	}
	if _, err := r3.NewProposal(operation, parameters, r3.ProposalOptions{Result: result}); err == nil {
		t.Fatal("a proposal with a result was built without a display")
	}
	release, err := r3.NewReleaseProposalDisplay(display, "## Details\n214 rows.")
	if err != nil {
		t.Fatal(err)
	}
	if !release.StatesRelease() || !strings.HasPrefix(release.Detail(), r3.ReleaseAction+"\n\n") {
		t.Fatalf("release detail = %q", release.Detail())
	}
	proposal, err := r3.NewProposal(operation, parameters, r3.ProposalOptions{Result: result, Display: &release})
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(proposal)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(encoded), `"parameters":{},"result":{"records":214,"contains":["national_id"]},"display"`) {
		t.Fatalf("release proposal = %s", encoded)
	}
	parsed, err := registry.ParseProposal(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := parsed.Result(); !ok || string(got) != `{"records":214,"contains":["national_id"]}` {
		t.Fatalf("parsed result = %s, %t", got, ok)
	}

	// A received proposal is judged by its wire form, not this library's
	// wording, and a proposal without result is approval for execution.
	foreign := `{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"runQuery"}],"parameters":{},` +
		`"result":{},"display":{"summary":"Release","detail":"## Action\nThis query has already run."}}`
	if _, err := registry.ParseProposal([]byte(foreign)); err != nil {
		t.Fatalf("a received release proposal was refused: %v", err)
	}
	execute, err := r3.NewProposal(operation, parameters, r3.ProposalOptions{Display: &execution})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := execute.Result(); ok {
		t.Fatal("an execution proposal reports a result")
	}
	for _, invalid := range []string{`[]`, `"rows"`, `{"a":1,"a":2}`} {
		body := `{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"runQuery"}],"parameters":{},"result":` + invalid + `}`
		if _, err := registry.ParseProposal([]byte(body)); err == nil {
			t.Errorf("result %s was accepted", invalid)
		}
	}
}

func TestMergeDisplaysKeepsEveryStatedConsequence(t *testing.T) {
	t.Parallel()

	read, _ := r3.NewDisplay("Read your calendar", "", "Event titles and times", "")
	write, _ := r3.NewDisplay("Create calendar events", "Invitations are sent", "Event titles and times", "Sent invitations cannot be unsent")
	merged, err := r3.MergeDisplays(read, write)
	if err != nil {
		t.Fatal(err)
	}
	if merged.Summary() != "Read your calendar; Create calendar events" || merged.Implications() != "Invitations are sent" ||
		merged.DataAccessed() != "Event titles and times" || merged.Irreversible() != "Sent invitations cannot be unsent" {
		t.Fatalf("merged display = %#v", merged)
	}
	if single, err := r3.MergeDisplays(read); err != nil || single != read {
		t.Fatalf("merging one display = %#v, %v", single, err)
	}
	if _, err := r3.MergeDisplays(); err == nil {
		t.Fatal("merging no displays succeeded")
	}
}
