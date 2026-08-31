package r3_test

import (
	"encoding/json"
	"strings"
	"testing"

	"aauth-go/r3"
)

func TestMCPOperationSetJSONRoundTrip(t *testing.T) {
	set := mustSet(t, "create_calendar_event", "modify_calendar_event")

	encoded, err := json.Marshal(set)
	if err != nil {
		t.Fatalf("marshal operation set: %v", err)
	}
	want := `{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"create_calendar_event"},{"tool":"modify_calendar_event"}]}`
	if string(encoded) != want {
		t.Fatalf("encoded operation set = %s, want %s", encoded, want)
	}

	var decoded r3.MCPOperationSet
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("unmarshal operation set: %v", err)
	}
	if !decoded.Equal(set) {
		t.Fatal("round-tripped operation set is not semantically equal")
	}
	if got := decoded.Operations()[0].Tool(); got != "create_calendar_event" {
		t.Fatalf("first tool = %q", got)
	}
}

func TestMCPOperationAndSetRejectInvalidJSON(t *testing.T) {
	tests := []struct {
		name string
		json string
	}{
		{"empty tool", `{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":""}]}`},
		{"whitespace tool", `{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":" x "}]}`},
		{"empty set", `{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[]}`},
		{"duplicate tool", `{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"x"},{"tool":"x"}]}`},
		{"unknown set member", `{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"x"}],"extra":true}`},
		{"duplicate set member", `{"vocabulary":"urn:aauth:vocabulary:mcp","vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"x"}]}`},
		{"case variant set member", `{"Vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"x"}]}`},
		{"wrong vocabulary", `{"vocabulary":"urn:aauth:vocabulary:openapi","operations":[{"tool":"x"}]}`},
		{"unknown operation member", `{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"x","extra":true}]}`},
		{"duplicate operation member", `{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"x","tool":"y"}]}`},
		{"case variant operation member", `{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"Tool":"x"}]}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var set r3.MCPOperationSet
			if err := json.Unmarshal([]byte(tt.json), &set); err == nil {
				t.Fatalf("accepted invalid JSON: %s", tt.json)
			}
		})
	}

	if _, err := r3.NewMCPOperation(""); err == nil {
		t.Fatal("accepted an empty tool through the constructor")
	}
	if _, err := r3.NewMCPOperation(" x "); err == nil {
		t.Fatal("accepted an untrimmed tool through the constructor")
	}
}

func TestMCPOperationSetSemanticComparisonIsOrderInsensitive(t *testing.T) {
	ab := mustSet(t, "a", "b")
	ba := mustSet(t, "b", "a")
	a := mustSet(t, "a")
	c := mustSet(t, "c")

	if !ab.Equal(ba) {
		t.Fatal("sets with the same tools in a different order are not equal")
	}
	if !a.IsSubsetOf(ab) {
		t.Fatal("single known operation is not a subset")
	}
	if c.IsSubsetOf(ab) {
		t.Fatal("unknown operation reported as a subset")
	}
	if got := ab.Operations()[0].Tool(); got != "a" {
		t.Fatalf("semantic comparison reordered retained operations; first = %q", got)
	}
}

func TestMCPOperationSetComparisonsFailClosedForInvalidOperands(t *testing.T) {
	valid := mustSet(t, "a")
	var empty r3.MCPOperationSet

	if empty.Equal(empty) {
		t.Fatal("invalid empty sets compared equal")
	}
	if empty.Equal(valid) || valid.Equal(empty) {
		t.Fatal("equality accepted an invalid operand")
	}
	if empty.IsSubsetOf(valid) || valid.IsSubsetOf(empty) {
		t.Fatal("subset comparison accepted an invalid operand")
	}
}

func TestKnownToolsValidationIsAuthoritative(t *testing.T) {
	set := mustSet(t, "known", "unknown")
	if err := set.ValidateKnownTools([]string{"known"}); err == nil {
		t.Fatal("validation silently accepted an operation absent from the authoritative tool set")
	}
	if err := mustSet(t, "known").ValidateKnownTools([]string{"known", "other"}); err != nil {
		t.Fatalf("known operation rejected: %v", err)
	}
}

func TestDocumentValidationAndStrictJSON(t *testing.T) {
	display := mustDisplay(t, "Create events", "May send invitations", "Calendar data", "Invitations cannot be unsent")
	account := "work-account"
	doc, err := r3.NewDocument(mustSet(t, "create_event"), r3.DocumentOptions{Account: &account, Display: &display})
	if err != nil {
		t.Fatalf("new document: %v", err)
	}
	encoded, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal document: %v", err)
	}
	want := `{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"create_event"}],"account":"work-account","display":{"summary":"Create events","implications":"May send invitations","data_accessed":"Calendar data","irreversible":"Invitations cannot be unsent"}}`
	if string(encoded) != want {
		t.Fatalf("encoded document = %s, want %s", encoded, want)
	}

	parsed, err := r3.ParseDocument(encoded)
	if err != nil {
		t.Fatalf("parse document: %v", err)
	}
	if !parsed.OperationSet().Equal(doc.OperationSet()) {
		t.Fatal("parsed document operation set differs")
	}
	if got, ok := parsed.Account(); !ok || got != account {
		t.Fatalf("parsed account = %q, %v", got, ok)
	}
	if got, ok := parsed.Display(); !ok || got.Summary() != "Create events" {
		t.Fatalf("parsed display = %#v, %v", got, ok)
	}

	invalid := []string{
		`{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"x"}],"display":{}}`,
		`{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"x"}],"display":{"summary":""}}`,
		`{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"x"}],"display":{"summary":"x","extra":"no"}}`,
		`{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"x"}],"display":{"summary":"x","summary":"y"}}`,
		`{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"x"}],"display":{"Summary":"x"}}`,
		`{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"x"}],"display":{"summary":"x","implications":null}}`,
		`{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"x"}],"extra":true}`,
		`{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"x"}],"account":"a","account":"b"}`,
		`{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"x"}],"Account":"a"}`,
		`{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"x"}],"account":null}`,
	}
	for _, source := range invalid {
		if _, err := r3.ParseDocument([]byte(source)); err == nil {
			t.Errorf("accepted invalid document: %s", source)
		}
	}
}

func TestDigestUsesExactCallerOwnedBytes(t *testing.T) {
	compact := []byte(`{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"x"}]}`)
	spaced := []byte(`{ "vocabulary":"urn:aauth:vocabulary:mcp", "operations":[{"tool":"x"}] }`)
	if _, err := r3.ParseDocument(compact); err != nil {
		t.Fatalf("parse compact document: %v", err)
	}
	if _, err := r3.ParseDocument(spaced); err != nil {
		t.Fatalf("parse spaced document: %v", err)
	}
	if r3.Digest(compact) == r3.Digest(spaced) {
		t.Fatal("digest canonicalized semantically identical JSON")
	}

	parsed, err := r3.ParseDocument(compact)
	if err != nil {
		t.Fatal(err)
	}
	compact[0] = '['
	if got := parsed.OperationSet().Operations()[0].Tool(); got != "x" {
		t.Fatalf("mutating source bytes changed parsed value: %q", got)
	}
}

func TestReferenceValidation(t *testing.T) {
	digest := r3.Digest([]byte("exact document bytes"))
	ref, err := r3.NewReference("https://resource.example/r3/document", digest)
	if err != nil {
		t.Fatalf("new valid reference: %v", err)
	}
	if ref.URI() != "https://resource.example/r3/document" || ref.Digest() != digest {
		t.Fatalf("reference accessors returned unexpected values: %q %q", ref.URI(), ref.Digest())
	}
	queryURI := "https://resource.example/r3/document?version=1&tenant=work"
	queryRef, err := r3.NewReference(queryURI, digest)
	if err != nil {
		t.Fatalf("new query-bearing reference: %v", err)
	}
	if queryRef.URI() != queryURI {
		t.Fatalf("query-bearing reference URI = %q, want %q", queryRef.URI(), queryURI)
	}

	invalid := []struct {
		uri    string
		digest string
	}{
		{"", digest},
		{"/relative", digest},
		{"http://resource.example/r3/document", digest},
		{"https:///document", digest},
		{"https://user@resource.example/document", digest},
		{"https://resource.example/document#part", digest},
		{"https://resource.example/document", ""},
		{"https://resource.example/document", "abcd"},
		{"https://resource.example/document", digest + "="},
		{"https://resource.example/document", strings.Repeat("+", len(digest))},
	}
	for _, tt := range invalid {
		if _, err := r3.NewReference(tt.uri, tt.digest); err == nil {
			t.Errorf("accepted invalid reference uri=%q digest=%q", tt.uri, tt.digest)
		}
	}
}

func TestGrantMustBeDocumentSubset(t *testing.T) {
	doc, err := r3.NewDocument(mustSet(t, "read", "write"), r3.DocumentOptions{})
	if err != nil {
		t.Fatal(err)
	}
	grant, err := r3.NewGrant(mustGranted(t, "write"), doc)
	if err != nil {
		t.Fatalf("new subset grant: %v", err)
	}
	if !grant.GrantedOperations().Equal(mustGranted(t, "write")) {
		t.Fatal("grant does not retain its operations")
	}
	if _, err := r3.NewGrant(mustGranted(t, "delete"), doc); err == nil {
		t.Fatal("accepted an over-broad grant")
	}
	if _, err := r3.NewGrant(mustGranted(t), doc); err != nil {
		t.Fatalf("rejected a valid empty grant: %v", err)
	}
}

func TestReturnedOperationSlicesAreCopies(t *testing.T) {
	set := mustSet(t, "a", "b")
	operations := set.Operations()
	operations[0] = mustOperation(t, "changed")
	operations = append(operations, mustOperation(t, "added"))

	retained := set.Operations()
	if len(retained) != 2 || retained[0].Tool() != "a" {
		t.Fatalf("caller mutated retained set through accessor: %#v", retained)
	}

	doc, err := r3.NewDocument(set, r3.DocumentOptions{})
	if err != nil {
		t.Fatal(err)
	}
	docOperations := doc.OperationSet().Operations()
	docOperations[0] = mustOperation(t, "changed-again")
	if got := doc.OperationSet().Operations()[0].Tool(); got != "a" {
		t.Fatalf("caller mutated document operations through accessor: %q", got)
	}

	grant, err := r3.NewGrant(mustGranted(t, "a"), doc)
	if err != nil {
		t.Fatal(err)
	}
	grantOperations := grant.GrantedOperations().Operations()
	grantOperations[0] = mustOperation(t, "changed-grant")
	if got := grant.GrantedOperations().Operations()[0].Tool(); got != "a" {
		t.Fatalf("caller mutated grant operations through accessor: %q", got)
	}
}

func mustOperation(t *testing.T, tool string) r3.MCPOperation {
	t.Helper()
	op, err := r3.NewMCPOperation(tool)
	if err != nil {
		t.Fatalf("new MCP operation %q: %v", tool, err)
	}
	return op
}

func mustSet(t *testing.T, tools ...string) r3.MCPOperationSet {
	t.Helper()
	operations := make([]r3.MCPOperation, 0, len(tools))
	for _, tool := range tools {
		operations = append(operations, mustOperation(t, tool))
	}
	set, err := r3.NewMCPOperationSet(operations...)
	if err != nil {
		t.Fatalf("new MCP operation set: %v", err)
	}
	return set
}

func mustGranted(t *testing.T, tools ...string) r3.GrantedOperations {
	t.Helper()
	operations := make([]r3.MCPOperation, 0, len(tools))
	for _, tool := range tools {
		operations = append(operations, mustOperation(t, tool))
	}
	granted, err := r3.NewGrantedOperations(operations...)
	if err != nil {
		t.Fatalf("new granted operations: %v", err)
	}
	return granted
}

func mustDisplay(t *testing.T, summary, implications, dataAccessed, irreversible string) r3.Display {
	t.Helper()
	display, err := r3.NewDisplay(summary, implications, dataAccessed, irreversible)
	if err != nil {
		t.Fatalf("new display: %v", err)
	}
	return display
}
