package mcp

import (
	"encoding/json"
	"slices"
	"testing"

	"aauth-go/r3"
)

func TestOperationRoundTripsThroughNeutralR3(t *testing.T) {
	operation, err := NewOperation("calendar.create")
	if err != nil {
		t.Fatal(err)
	}
	if got := operation.Tool(); got != "calendar.create" {
		t.Fatalf("Tool() = %q", got)
	}
	encoded, err := json.Marshal(operation)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(encoded), `{"tool":"calendar.create"}`; got != want {
		t.Fatalf("operation JSON = %s, want %s", got, want)
	}

	neutral, err := operation.ToR3()
	if err != nil {
		t.Fatal(err)
	}
	if got := neutral.Vocabulary(); got != URI {
		t.Fatalf("neutral vocabulary = %q", got)
	}
	roundTripped, err := FromR3(neutral)
	if err != nil {
		t.Fatal(err)
	}
	if roundTripped.Tool() != operation.Tool() {
		t.Fatalf("round-tripped tool = %q", roundTripped.Tool())
	}

	set, err := NewOperationSet(operation)
	if err != nil {
		t.Fatal(err)
	}
	setJSON, err := json.Marshal(set)
	if err != nil {
		t.Fatal(err)
	}
	wantSet := `{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"calendar.create"}]}`
	if string(setJSON) != wantSet {
		t.Fatalf("operation set JSON = %s, want %s", setJSON, wantSet)
	}

	registry, err := r3.NewRegistry(Vocabulary())
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := registry.ParseOperationSet(setJSON)
	if err != nil {
		t.Fatal(err)
	}
	equal, err := parsed.Equal(set)
	if err != nil || !equal {
		t.Fatalf("parsed set Equal(set) = %v, %v", equal, err)
	}
}

func TestOperationRejectsInvalidConstructionAndJSON(t *testing.T) {
	invalidTools := []string{"", " calendar.create", "calendar.create ", string([]byte{0xff})}
	for _, tool := range invalidTools {
		if _, err := NewOperation(tool); err == nil {
			t.Fatalf("NewOperation(%q) succeeded", tool)
		}
	}

	invalidJSON := []string{
		`{}`,
		`{"tool":""}`,
		`{"tool":" calendar.create"}`,
		`{"tool":null}`,
		`{"Tool":"calendar.create"}`,
		`{"tool":"calendar.create","extra":true}`,
		`{"tool":"calendar.create","tool":"calendar.delete"}`,
		`{"tool":"calendar.create"} true`,
	}
	for _, source := range invalidJSON {
		var operation Operation
		if err := json.Unmarshal([]byte(source), &operation); err == nil {
			t.Fatalf("Unmarshal(%s) succeeded", source)
		}
	}
}

func TestCodecRejectsDuplicateOperations(t *testing.T) {
	codec := codec{}
	create := json.RawMessage(`{"tool":"calendar.create"}`)
	if _, err := codec.ParseSet([]json.RawMessage{create, create}); err == nil {
		t.Fatal("ParseSet accepted duplicate tools")
	}
}

func TestCodecImplementsWholeSetAlgebra(t *testing.T) {
	codec := codec{}
	read := mustParseSet(t, codec, `{"tool":"records.read"}`)
	write := mustParseSet(t, codec, `{"tool":"records.write"}`)
	both := mustParseSet(t, codec, `{"tool":"records.read"}`, `{"tool":"records.write"}`)
	reversed := mustParseSet(t, codec, `{"tool":"records.write"}`, `{"tool":"records.read"}`)

	if !codec.Equal(both, reversed) {
		t.Fatal("Equal depends on retained wire order")
	}
	if !codec.Subset(read, both) || codec.Subset(both, read) {
		t.Fatal("Subset does not implement semantic containment")
	}
	if !codec.Disjoint(read, write) || codec.Disjoint(read, both) {
		t.Fatal("Disjoint does not detect overlap")
	}

	union, err := codec.Union(read, write, read)
	if err != nil {
		t.Fatal(err)
	}
	if !codec.Equal(union, both) {
		t.Fatal("Union did not deduplicate semantic operations")
	}
	returned := union.Operations()
	returned[0] = Operation{}
	if got := union.Operations()[0].Tool(); got != "records.read" {
		t.Fatalf("mutating returned operations changed set: %q", got)
	}
	wire, err := codec.MarshalSet(union)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := rawStrings(wire), []string{`{"tool":"records.read"}`, `{"tool":"records.write"}`}; !slices.Equal(got, want) {
		t.Fatalf("union wire order = %v, want %v", got, want)
	}

}

func TestFromR3RejectsAnotherRegistrationOfTheMCPURI(t *testing.T) {
	otherVocabulary, err := r3.NewVocabulary(codec{})
	if err != nil {
		t.Fatal(err)
	}
	other, err := r3.NewOperation(otherVocabulary, json.RawMessage(`{"tool":"records.read"}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := FromR3(other); err == nil {
		t.Fatal("FromR3 accepted another registration of the MCP URI")
	}
}

func mustParseSet(t *testing.T, codec codec, operations ...string) set {
	t.Helper()
	raw := make([]json.RawMessage, len(operations))
	for index, operation := range operations {
		raw[index] = json.RawMessage(operation)
	}
	set, err := codec.ParseSet(raw)
	if err != nil {
		t.Fatal(err)
	}
	return set
}

func rawStrings(values []json.RawMessage) []string {
	result := make([]string, len(values))
	for index, value := range values {
		result[index] = string(value)
	}
	return result
}
