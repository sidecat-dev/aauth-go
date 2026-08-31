package openapi

import (
	"encoding/json"
	"slices"
	"testing"

	"gitlab.com/sidecat-dev/aauth-go/r3"
)

func TestOperationRoundTripsThroughNeutralR3(t *testing.T) {
	operation, err := NewOperation("createEvent")
	if err != nil {
		t.Fatal(err)
	}
	if got := operation.OperationID(); got != "createEvent" {
		t.Fatalf("OperationID() = %q", got)
	}
	encoded, err := json.Marshal(operation)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(encoded), `{"operationId":"createEvent"}`; got != want {
		t.Fatalf("operation JSON = %s, want %s", got, want)
	}

	neutral, err := operation.ToR3()
	if err != nil {
		t.Fatal(err)
	}
	if neutral.Vocabulary() != URI {
		t.Fatalf("neutral vocabulary = %q", neutral.Vocabulary())
	}
	roundTripped, err := FromR3(neutral)
	if err != nil {
		t.Fatal(err)
	}
	if roundTripped.OperationID() != operation.OperationID() {
		t.Fatalf("round-tripped operationId = %q", roundTripped.OperationID())
	}

	set, err := NewOperationSet(operation)
	if err != nil {
		t.Fatal(err)
	}
	setJSON, err := json.Marshal(set)
	if err != nil {
		t.Fatal(err)
	}
	wantSet := `{"vocabulary":"urn:aauth:vocabulary:openapi","operations":[{"operationId":"createEvent"}]}`
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

func TestOperationRejectsInvalidConstructionAndExactJSON(t *testing.T) {
	for _, operationID := range []string{"", " createEvent", "createEvent ", string([]byte{0xff})} {
		if _, err := NewOperation(operationID); err == nil {
			t.Fatalf("NewOperation(%q) succeeded", operationID)
		}
	}

	invalidJSON := []string{
		`{}`,
		`{"operationId":""}`,
		`{"operationId":" createEvent"}`,
		`{"operationId":null}`,
		`{"operationID":"createEvent"}`,
		`{"OperationId":"createEvent"}`,
		`{"operationId":"createEvent","extra":true}`,
		`{"operationId":"createEvent","operationId":"deleteEvent"}`,
		`{"operationId":"createEvent"} false`,
	}
	for _, source := range invalidJSON {
		var operation Operation
		if err := json.Unmarshal([]byte(source), &operation); err == nil {
			t.Fatalf("Unmarshal(%s) succeeded", source)
		}
	}
}

func TestCodecRejectsSemanticDuplicates(t *testing.T) {
	codec := codec{}
	create := json.RawMessage(`{"operationId":"createEvent"}`)
	if _, err := codec.ParseSet([]json.RawMessage{create, create}); err == nil {
		t.Fatal("ParseSet accepted duplicate operationId values")
	}
}

func TestCodecImplementsWholeSetAlgebraAndCopySafety(t *testing.T) {
	codec := codec{}
	read := mustParseSet(t, codec, `{"operationId":"readEvent"}`)
	write := mustParseSet(t, codec, `{"operationId":"writeEvent"}`)
	both := mustParseSet(t, codec, `{"operationId":"readEvent"}`, `{"operationId":"writeEvent"}`)
	reversed := mustParseSet(t, codec, `{"operationId":"writeEvent"}`, `{"operationId":"readEvent"}`)

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
		t.Fatal("Union did not deduplicate operationId values")
	}
	returned := union.Operations()
	returned[0] = Operation{}
	if got := union.Operations()[0].OperationID(); got != "readEvent" {
		t.Fatalf("mutating returned operations changed set: %q", got)
	}
	wire, err := codec.MarshalSet(union)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := rawStrings(wire), []string{`{"operationId":"readEvent"}`, `{"operationId":"writeEvent"}`}; !slices.Equal(got, want) {
		t.Fatalf("union wire order = %v, want %v", got, want)
	}

}

func TestFromR3RejectsAnotherRegistrationOfTheOpenAPIURI(t *testing.T) {
	otherVocabulary, err := r3.NewVocabulary(codec{})
	if err != nil {
		t.Fatal(err)
	}
	other, err := r3.NewOperation(otherVocabulary, json.RawMessage(`{"operationId":"readEvent"}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := FromR3(other); err == nil {
		t.Fatal("FromR3 accepted another registration of the OpenAPI URI")
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
