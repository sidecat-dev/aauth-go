package graphql

import (
	"encoding/json"
	"slices"
	"testing"

	"gitlab.com/sidecat-dev/aauth-go/r3"
)

func TestOperationRoundTripsThroughNeutralR3(t *testing.T) {
	operation, err := NewOperation("CreateCalendarEvent", Mutation)
	if err != nil {
		t.Fatal(err)
	}
	if got := operation.OperationName(); got != "CreateCalendarEvent" {
		t.Fatalf("OperationName() = %q", got)
	}
	if got := operation.Type(); got != Mutation {
		t.Fatalf("Type() = %q", got)
	}
	encoded, err := json.Marshal(operation)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(encoded), `{"operation":"CreateCalendarEvent","type":"mutation"}`; got != want {
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
	if roundTripped.OperationName() != operation.OperationName() || roundTripped.Type() != operation.Type() {
		t.Fatalf("round-tripped operation = %#v", roundTripped)
	}

	set, err := NewOperationSet(operation)
	if err != nil {
		t.Fatal(err)
	}
	setJSON, err := json.Marshal(set)
	if err != nil {
		t.Fatal(err)
	}
	wantSet := `{"vocabulary":"urn:aauth:vocabulary:graphql","operations":[{"operation":"CreateCalendarEvent","type":"mutation"}]}`
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

func TestOperationRequiresGraphQLNameAndDefinedType(t *testing.T) {
	for _, operationType := range []OperationType{Query, Mutation, Subscription} {
		if _, err := NewOperation("_CalendarEvent2", operationType); err != nil {
			t.Fatalf("NewOperation with type %q: %v", operationType, err)
		}
	}

	invalidNames := []string{
		"",
		" CreateCalendarEvent",
		"CreateCalendarEvent ",
		string([]byte{0xff}),
		"2CreateCalendarEvent",
		"Create-Calendar-Event",
		"Create.Calendar.Event",
	}
	for _, name := range invalidNames {
		if _, err := NewOperation(name, Query); err == nil {
			t.Fatalf("NewOperation(%q, query) succeeded", name)
		}
	}
	for _, operationType := range []OperationType{"", "QUERY", "read", "mutation "} {
		if _, err := NewOperation("CalendarEvent", operationType); err == nil {
			t.Fatalf("NewOperation with type %q succeeded", operationType)
		}
	}
}

func TestOperationRejectsAmbiguousOrNonExactJSON(t *testing.T) {
	invalidJSON := []string{
		`{}`,
		`{"operation":"CalendarEvent"}`,
		`{"type":"query"}`,
		`{"operation":"","type":"query"}`,
		`{"operation":"CalendarEvent","type":"QUERY"}`,
		`{"operation":null,"type":"query"}`,
		`{"Operation":"CalendarEvent","type":"query"}`,
		`{"operation":"CalendarEvent","Type":"query"}`,
		`{"operation":"CalendarEvent","type":"query","extra":true}`,
		`{"operation":"CalendarEvent","operation":"Other","type":"query"}`,
		`{"operation":"CalendarEvent","type":"query","type":"mutation"}`,
		`{"operation":"CalendarEvent","type":"query"} []`,
	}
	for _, source := range invalidJSON {
		var operation Operation
		if err := json.Unmarshal([]byte(source), &operation); err == nil {
			t.Fatalf("Unmarshal(%s) succeeded", source)
		}
	}
}

func TestCodecUsesOperationNameAndTypeAsSemanticIdentity(t *testing.T) {
	codec := codec{}
	query := json.RawMessage(`{"operation":"CalendarEvent","type":"query"}`)
	mutation := json.RawMessage(`{"operation":"CalendarEvent","type":"mutation"}`)
	if _, err := codec.ParseSet([]json.RawMessage{query, mutation}); err != nil {
		t.Fatalf("ParseSet collapsed distinct query and mutation operations: %v", err)
	}
	if _, err := codec.ParseSet([]json.RawMessage{query, query}); err == nil {
		t.Fatal("ParseSet accepted a duplicate operation name/type pair")
	}
}

func TestCodecImplementsWholeSetAlgebraAndCopySafety(t *testing.T) {
	codec := codec{}
	query := mustParseSet(t, codec, `{"operation":"Record","type":"query"}`)
	mutation := mustParseSet(t, codec, `{"operation":"Record","type":"mutation"}`)
	both := mustParseSet(t, codec, `{"operation":"Record","type":"query"}`, `{"operation":"Record","type":"mutation"}`)
	reversed := mustParseSet(t, codec, `{"operation":"Record","type":"mutation"}`, `{"operation":"Record","type":"query"}`)

	if !codec.Equal(both, reversed) {
		t.Fatal("Equal depends on retained wire order")
	}
	if !codec.Subset(query, both) || codec.Subset(both, query) {
		t.Fatal("Subset does not implement composite semantic containment")
	}
	if !codec.Disjoint(query, mutation) || codec.Disjoint(query, both) {
		t.Fatal("Disjoint does not use the operation name/type pair")
	}
	union, err := codec.Union(query, mutation, query)
	if err != nil {
		t.Fatal(err)
	}
	if !codec.Equal(union, both) {
		t.Fatal("Union did not deduplicate composite operations")
	}
	returned := union.Operations()
	returned[0] = Operation{}
	if got := union.Operations()[0].OperationName(); got != "Record" {
		t.Fatalf("mutating returned operations changed set: %q", got)
	}
	wire, err := codec.MarshalSet(union)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := rawStrings(wire), []string{`{"operation":"Record","type":"query"}`, `{"operation":"Record","type":"mutation"}`}; !slices.Equal(got, want) {
		t.Fatalf("union wire order = %v, want %v", got, want)
	}

}

func TestFromR3RejectsAnotherRegistrationOfTheGraphQLURI(t *testing.T) {
	otherVocabulary, err := r3.NewVocabulary(codec{})
	if err != nil {
		t.Fatal(err)
	}
	other, err := r3.NewOperation(otherVocabulary, json.RawMessage(`{"operation":"Record","type":"query"}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := FromR3(other); err == nil {
		t.Fatal("FromR3 accepted another registration of the GraphQL URI")
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
