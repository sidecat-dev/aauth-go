package grpc

import (
	"encoding/json"
	"slices"
	"testing"

	"aauth-go/r3"
)

func TestOperationRoundTripsThroughNeutralR3(t *testing.T) {
	operation, err := NewOperation("calendar.CalendarService/CreateEvent")
	if err != nil {
		t.Fatal(err)
	}
	if got := operation.Method(); got != "calendar.CalendarService/CreateEvent" {
		t.Fatalf("Method() = %q", got)
	}
	encoded, err := json.Marshal(operation)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(encoded), `{"method":"calendar.CalendarService/CreateEvent"}`; got != want {
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
	if roundTripped.Method() != operation.Method() {
		t.Fatalf("round-tripped method = %q", roundTripped.Method())
	}

	set, err := NewOperationSet(operation)
	if err != nil {
		t.Fatal(err)
	}
	setJSON, err := json.Marshal(set)
	if err != nil {
		t.Fatal(err)
	}
	wantSet := `{"vocabulary":"urn:aauth:vocabulary:grpc","operations":[{"method":"calendar.CalendarService/CreateEvent"}]}`
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

func TestOperationRequiresFullyQualifiedProtobufMethodGrammar(t *testing.T) {
	valid := []string{
		"calendar.CalendarService/CreateEvent",
		"com.example.calendar.Calendar_Service/Create_Event2",
		"_package._Service/_Method",
	}
	for _, method := range valid {
		if _, err := NewOperation(method); err != nil {
			t.Fatalf("NewOperation(%q): %v", method, err)
		}
	}

	invalid := []string{
		"",
		" calendar.CalendarService/CreateEvent",
		"calendar.CalendarService/CreateEvent ",
		string([]byte{0xff}),
		"CalendarService/CreateEvent",
		"calendar.CalendarServiceCreateEvent",
		"/calendar.CalendarService/CreateEvent",
		"calendar.CalendarService/CreateEvent/Again",
		"calendar..CalendarService/CreateEvent",
		"calendar.2CalendarService/CreateEvent",
		"calendar.Calendar-Service/CreateEvent",
		"calendar.CalendarService/2CreateEvent",
		"calendar.CalendarService/Create.Event",
	}
	for _, method := range invalid {
		if _, err := NewOperation(method); err == nil {
			t.Fatalf("NewOperation(%q) succeeded", method)
		}
	}
}

func TestOperationRejectsAmbiguousOrNonExactJSON(t *testing.T) {
	invalidJSON := []string{
		`{}`,
		`{"method":""}`,
		`{"method":null}`,
		`{"Method":"calendar.CalendarService/CreateEvent"}`,
		`{"method":"calendar.CalendarService/CreateEvent","extra":true}`,
		`{"method":"calendar.CalendarService/CreateEvent","method":"calendar.CalendarService/DeleteEvent"}`,
		`{"method":"calendar.CalendarService/CreateEvent"} null`,
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
	create := json.RawMessage(`{"method":"calendar.CalendarService/CreateEvent"}`)
	if _, err := codec.ParseSet([]json.RawMessage{create, create}); err == nil {
		t.Fatal("ParseSet accepted duplicate methods")
	}
}

func TestDiscoveryEndpointUsesTheCurrentHTTPSURLProfile(t *testing.T) {
	t.Parallel()

	codec := codec{}
	for _, endpoint := range []string{
		"https://grpc.example/reflection?service=records.v1.Records",
		"https://grpc.example/records.proto",
	} {
		if err := codec.ValidateDiscoveryEndpoint(endpoint); err != nil {
			t.Fatalf("ValidateDiscoveryEndpoint(%q) = %v", endpoint, err)
		}
	}
	for _, endpoint := range []string{
		"dns:///grpc.example",
		"grpc://grpc.example",
	} {
		if err := codec.ValidateDiscoveryEndpoint(endpoint); err == nil {
			t.Fatalf("ValidateDiscoveryEndpoint(%q) succeeded outside the current HTTPS URL profile", endpoint)
		}
	}
}

func TestCodecImplementsWholeSetAlgebraAndCopySafety(t *testing.T) {
	codec := codec{}
	read := mustParseSet(t, codec, `{"method":"records.RecordService/Read"}`)
	write := mustParseSet(t, codec, `{"method":"records.RecordService/Write"}`)
	both := mustParseSet(t, codec, `{"method":"records.RecordService/Read"}`, `{"method":"records.RecordService/Write"}`)
	reversed := mustParseSet(t, codec, `{"method":"records.RecordService/Write"}`, `{"method":"records.RecordService/Read"}`)

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
		t.Fatal("Union did not deduplicate methods")
	}
	returned := union.Operations()
	returned[0] = Operation{}
	if got := union.Operations()[0].Method(); got != "records.RecordService/Read" {
		t.Fatalf("mutating returned operations changed set: %q", got)
	}
	wire, err := codec.MarshalSet(union)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := rawStrings(wire), []string{`{"method":"records.RecordService/Read"}`, `{"method":"records.RecordService/Write"}`}; !slices.Equal(got, want) {
		t.Fatalf("union wire order = %v, want %v", got, want)
	}

}

func TestFromR3RejectsAnotherRegistrationOfTheGRPCURI(t *testing.T) {
	otherVocabulary, err := r3.NewVocabulary(codec{})
	if err != nil {
		t.Fatal(err)
	}
	other, err := r3.NewOperation(otherVocabulary, json.RawMessage(`{"method":"records.RecordService/Read"}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := FromR3(other); err == nil {
		t.Fatal("FromR3 accepted another registration of the gRPC URI")
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
