package wsdl_test

import (
	"encoding/json"
	"testing"

	"gitlab.com/sidecat-dev/aauth-go/r3"
	"gitlab.com/sidecat-dev/aauth-go/r3/vocab/wsdl"
)

func TestOperationRoundTripPreservesOptionalService(t *testing.T) {
	unqualified, err := wsdl.NewOperation("Health")
	if err != nil {
		t.Fatal(err)
	}
	qualified, err := wsdl.NewServiceOperation("CreateCalendarEvent", "CalendarService")
	if err != nil {
		t.Fatal(err)
	}
	if _, present := unqualified.Service(); present {
		t.Fatal("unqualified operation reported a service")
	}
	if service, present := qualified.Service(); !present || service != "CalendarService" {
		t.Fatalf("service = %q, %t", service, present)
	}

	set, err := wsdl.NewOperationSet(unqualified, qualified)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(set)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"vocabulary":"urn:aauth:vocabulary:wsdl","operations":[{"operation":"Health"},{"operation":"CreateCalendarEvent","service":"CalendarService"}]}`
	if string(encoded) != want {
		t.Fatalf("operation set JSON = %s, want %s", encoded, want)
	}

	neutral, err := qualified.ToR3()
	if err != nil {
		t.Fatal(err)
	}
	roundTripped, err := wsdl.FromR3(neutral)
	if err != nil {
		t.Fatal(err)
	}
	if roundTripped.OperationName() != "CreateCalendarEvent" {
		t.Fatalf("operation = %q", roundTripped.OperationName())
	}
	if service, present := roundTripped.Service(); !present || service != "CalendarService" {
		t.Fatalf("round-tripped service = %q, %t", service, present)
	}
	if wsdl.Vocabulary().URI() != wsdl.URI {
		t.Fatalf("vocabulary URI = %q", wsdl.Vocabulary().URI())
	}
}

func TestOperationJSONRoundTrip(t *testing.T) {
	operation, _ := wsdl.NewServiceOperation("Create", "Calendar")
	encoded, err := json.Marshal(operation)
	if err != nil {
		t.Fatal(err)
	}
	if string(encoded) != `{"operation":"Create","service":"Calendar"}` {
		t.Fatalf("operation JSON = %s", encoded)
	}
	var parsed wsdl.Operation
	if err := json.Unmarshal(encoded, &parsed); err != nil {
		t.Fatal(err)
	}
	if parsed.OperationName() != "Create" {
		t.Fatalf("parsed operation = %q", parsed.OperationName())
	}
}

func TestUnqualifiedOperationRejectsAmbiguousQualifiedOverlap(t *testing.T) {
	unqualified, _ := wsdl.NewOperation("Create")
	serviceA, _ := wsdl.NewServiceOperation("Create", "ServiceA")
	serviceB, _ := wsdl.NewServiceOperation("Create", "ServiceB")
	unqualifiedSet, _ := wsdl.NewOperationSet(unqualified)
	serviceASet, _ := wsdl.NewOperationSet(serviceA)
	serviceBSet, _ := wsdl.NewOperationSet(serviceB)

	if _, err := wsdl.NewOperationSet(unqualified, serviceA); err == nil {
		t.Fatal("set accepted unqualified and service-qualified overlap")
	}
	if _, err := unqualifiedSet.Union(serviceASet); err == nil {
		t.Fatal("union accepted unqualified and service-qualified overlap")
	}
	if disjoint, err := unqualifiedSet.Disjoint(serviceASet); err != nil || disjoint {
		t.Fatalf("unqualified disjoint service A = %t, %v", disjoint, err)
	}
	if disjoint, err := serviceASet.Disjoint(serviceBSet); err != nil || !disjoint {
		t.Fatalf("service A disjoint service B = %t, %v", disjoint, err)
	}
	combined, err := serviceASet.Union(serviceBSet)
	if err != nil {
		t.Fatal(err)
	}
	if operations := combined.Operations(); len(operations) != 2 {
		t.Fatalf("qualified union operation count = %d", len(operations))
	}
}

func TestStrictWSDLOperationWireShape(t *testing.T) {
	registry, err := r3.NewRegistry(wsdl.Vocabulary())
	if err != nil {
		t.Fatal(err)
	}
	invalidOperations := []string{
		`{}`,
		`{"operation":""}`,
		`{"operation":" x "}`,
		`{"operation":"x","service":""}`,
		`{"operation":"x","service":null}`,
		`{"operation":"x","extra":true}`,
		`{"operation":"x","operation":"y"}`,
	}
	for _, operation := range invalidOperations {
		source := `{"vocabulary":"urn:aauth:vocabulary:wsdl","operations":[` + operation + `]}`
		if _, err := registry.ParseOperationSet([]byte(source)); err == nil {
			t.Errorf("accepted invalid operation: %s", operation)
		}
	}
	duplicate := `{"vocabulary":"urn:aauth:vocabulary:wsdl","operations":[{"operation":"x","service":"A"},{"operation":"x","service":"A"}]}`
	if _, err := registry.ParseOperationSet([]byte(duplicate)); err == nil {
		t.Fatal("wire parser accepted a duplicate qualified operation")
	}
}
