package odata_test

import (
	"encoding/json"
	"slices"
	"testing"

	"aauth-go/r3"
	"aauth-go/r3/vocab/odata"
)

func TestOperationRoundTripPreservesMethodsPresenceAndOrder(t *testing.T) {
	bound, err := odata.NewOperation("Events/SendCancellation")
	if err != nil {
		t.Fatal(err)
	}
	entitySet, err := odata.NewMethodOperation("Events", "POST", "GET")
	if err != nil {
		t.Fatal(err)
	}
	if _, present := bound.Methods(); present {
		t.Fatal("bound operation reported methods present")
	}
	if methods, present := entitySet.Methods(); !present || !slices.Equal(methods, []string{"POST", "GET"}) {
		t.Fatalf("methods = %#v, %t", methods, present)
	}

	set, err := odata.NewOperationSet(bound, entitySet)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(set)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"vocabulary":"urn:aauth:vocabulary:odata","operations":[{"operation":"Events/SendCancellation"},{"operation":"Events","methods":["POST","GET"]}]}`
	if string(encoded) != want {
		t.Fatalf("operation set JSON = %s, want %s", encoded, want)
	}

	neutral, err := entitySet.ToR3()
	if err != nil {
		t.Fatal(err)
	}
	roundTripped, err := odata.FromR3(neutral)
	if err != nil {
		t.Fatal(err)
	}
	if roundTripped.OperationName() != "Events" {
		t.Fatalf("operation = %q", roundTripped.OperationName())
	}
	if methods, present := roundTripped.Methods(); !present || !slices.Equal(methods, []string{"POST", "GET"}) {
		t.Fatalf("round-tripped methods = %#v, %t", methods, present)
	}
	if odata.Vocabulary().URI() != odata.URI {
		t.Fatalf("vocabulary URI = %q", odata.Vocabulary().URI())
	}
}

func TestOperationJSONRoundTrip(t *testing.T) {
	operation, _ := odata.NewMethodOperation("Events", "GET", "POST")
	encoded, err := json.Marshal(operation)
	if err != nil {
		t.Fatal(err)
	}
	if string(encoded) != `{"operation":"Events","methods":["GET","POST"]}` {
		t.Fatalf("operation JSON = %s", encoded)
	}
	var parsed odata.Operation
	if err := json.Unmarshal(encoded, &parsed); err != nil {
		t.Fatal(err)
	}
	if parsed.OperationName() != "Events" {
		t.Fatalf("parsed operation = %q", parsed.OperationName())
	}
}

func TestMethodSetsDriveEqualitySubsetUnionAndDisjoint(t *testing.T) {
	get, _ := odata.NewMethodOperation("Events", "GET")
	post, _ := odata.NewMethodOperation("Events", "POST")
	getPost, _ := odata.NewMethodOperation("Events", "GET", "POST")
	postGet, _ := odata.NewMethodOperation("Events", "POST", "GET")
	getSet, _ := odata.NewOperationSet(get)
	postSet, _ := odata.NewOperationSet(post)
	getPostSet, _ := odata.NewOperationSet(getPost)
	postGetSet, _ := odata.NewOperationSet(postGet)

	if equal, err := getPostSet.Equal(postGetSet); err != nil || !equal {
		t.Fatalf("method-order equality = %t, %v", equal, err)
	}
	if subset, err := getSet.IsSubsetOf(getPostSet); err != nil || !subset {
		t.Fatalf("GET subset GET+POST = %t, %v", subset, err)
	}
	if subset, err := getPostSet.IsSubsetOf(getSet); err != nil || subset {
		t.Fatalf("GET+POST subset GET = %t, %v", subset, err)
	}
	if disjoint, err := getSet.Disjoint(postSet); err != nil || !disjoint {
		t.Fatalf("GET disjoint POST = %t, %v", disjoint, err)
	}
	if disjoint, err := getSet.Disjoint(getPostSet); err != nil || disjoint {
		t.Fatalf("GET disjoint GET+POST = %t, %v", disjoint, err)
	}

	union, err := getSet.Union(postSet)
	if err != nil {
		t.Fatal(err)
	}
	operations := union.Operations()
	if len(operations) != 1 {
		t.Fatalf("union operation count = %d", len(operations))
	}
	merged, err := odata.FromR3(operations[0])
	if err != nil {
		t.Fatal(err)
	}
	if methods, present := merged.Methods(); !present || !slices.Equal(methods, []string{"GET", "POST"}) {
		t.Fatalf("union methods = %#v, %t", methods, present)
	}
}

func TestAbsentAndPresentMethodsForOneOperationAreAmbiguous(t *testing.T) {
	absent, _ := odata.NewOperation("Events")
	present, _ := odata.NewMethodOperation("Events", "GET")
	absentSet, _ := odata.NewOperationSet(absent)
	presentSet, _ := odata.NewOperationSet(present)

	if _, err := odata.NewOperationSet(absent, present); err == nil {
		t.Fatal("set accepted mixed absent and present methods")
	}
	if _, err := absentSet.Union(presentSet); err == nil {
		t.Fatal("union accepted mixed absent and present methods")
	}
	if disjoint, err := absentSet.Disjoint(presentSet); err != nil || disjoint {
		t.Fatalf("ambiguous operations reported disjoint = %t, %v", disjoint, err)
	}
}

func TestPresentMethodsRequiresAtLeastOneMethod(t *testing.T) {
	if _, err := odata.NewMethodOperation("Events"); err == nil {
		t.Fatal("NewMethodOperation accepted present-but-empty methods")
	}
	registry, err := r3.NewRegistry(odata.Vocabulary())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := registry.ParseOperationSet([]byte(
		`{"vocabulary":"urn:aauth:vocabulary:odata","operations":[{"operation":"Events","methods":[]}]}`,
	)); err == nil {
		t.Fatal("wire parser accepted present-but-empty methods")
	}
}

func TestStrictODataOperationWireShapeAndMethodCopySafety(t *testing.T) {
	registry, err := r3.NewRegistry(odata.Vocabulary())
	if err != nil {
		t.Fatal(err)
	}
	invalidOperations := []string{
		`{}`,
		`{"operation":""}`,
		`{"operation":" x "}`,
		`{"operation":"x","methods":["GET","GET"]}`,
		`{"operation":"x","methods":["BAD METHOD"]}`,
		`{"operation":"x","methods":null}`,
		`{"operation":"x","extra":true}`,
		`{"operation":"x","operation":"y"}`,
	}
	for _, operation := range invalidOperations {
		source := `{"vocabulary":"urn:aauth:vocabulary:odata","operations":[` + operation + `]}`
		if _, err := registry.ParseOperationSet([]byte(source)); err == nil {
			t.Errorf("accepted invalid operation: %s", operation)
		}
	}
	duplicate := `{"vocabulary":"urn:aauth:vocabulary:odata","operations":[{"operation":"Events","methods":["GET"]},{"operation":"Events","methods":["POST"]}]}`
	if _, err := registry.ParseOperationSet([]byte(duplicate)); err == nil {
		t.Fatal("wire parser accepted duplicate operation entries")
	}

	operation, _ := odata.NewMethodOperation("Events", "GET", "POST")
	methods, _ := operation.Methods()
	methods[0] = "DELETE"
	retained, _ := operation.Methods()
	if !slices.Equal(retained, []string{"GET", "POST"}) {
		t.Fatalf("caller mutated retained methods: %#v", retained)
	}
}
