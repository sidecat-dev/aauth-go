package asyncapi_test

import (
	"encoding/json"
	"testing"

	"gitlab.com/sidecat-dev/aauth-go/r3"
	"gitlab.com/sidecat-dev/aauth-go/r3/vocab/asyncapi"
)

func TestOperationRoundTripPreservesOptionalAction(t *testing.T) {
	withoutAction, err := asyncapi.NewOperation("receiveCalendarEvent")
	if err != nil {
		t.Fatal(err)
	}
	withAction, err := asyncapi.NewOperationWithAction("publishCalendarUpdate", asyncapi.ActionSend)
	if err != nil {
		t.Fatal(err)
	}
	if _, present := withoutAction.Action(); present {
		t.Fatal("operation without action reported one present")
	}
	if action, present := withAction.Action(); !present || action != asyncapi.ActionSend {
		t.Fatalf("action = %q, %t", action, present)
	}

	set, err := asyncapi.NewOperationSet(withoutAction, withAction)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(set)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"vocabulary":"urn:aauth:vocabulary:asyncapi","operations":[{"operationId":"receiveCalendarEvent"},{"operationId":"publishCalendarUpdate","action":"send"}]}`
	if string(encoded) != want {
		t.Fatalf("operation set JSON = %s, want %s", encoded, want)
	}

	neutral, err := withAction.ToR3()
	if err != nil {
		t.Fatal(err)
	}
	roundTripped, err := asyncapi.FromR3(neutral)
	if err != nil {
		t.Fatal(err)
	}
	if roundTripped.OperationID() != "publishCalendarUpdate" {
		t.Fatalf("operationId = %q", roundTripped.OperationID())
	}
	if action, present := roundTripped.Action(); !present || action != asyncapi.ActionSend {
		t.Fatalf("round-tripped action = %q, %t", action, present)
	}
	if asyncapi.Vocabulary().URI() != asyncapi.URI {
		t.Fatalf("vocabulary URI = %q", asyncapi.Vocabulary().URI())
	}
}

func TestOperationJSONRoundTrip(t *testing.T) {
	operation, _ := asyncapi.NewOperationWithAction("publish", asyncapi.ActionSend)
	encoded, err := json.Marshal(operation)
	if err != nil {
		t.Fatal(err)
	}
	if string(encoded) != `{"operationId":"publish","action":"send"}` {
		t.Fatalf("operation JSON = %s", encoded)
	}
	var parsed asyncapi.Operation
	if err := json.Unmarshal(encoded, &parsed); err != nil {
		t.Fatal(err)
	}
	if parsed.OperationID() != "publish" {
		t.Fatalf("parsed operationId = %q", parsed.OperationID())
	}
}

func TestActionPresenceIsSemanticAndOperationIDIsUnique(t *testing.T) {
	absent, _ := asyncapi.NewOperation("calendarEvent")
	send, _ := asyncapi.NewOperationWithAction("calendarEvent", asyncapi.ActionSend)
	receive, _ := asyncapi.NewOperationWithAction("calendarEvent", asyncapi.ActionReceive)
	absentSet, _ := asyncapi.NewOperationSet(absent)
	sendSet, _ := asyncapi.NewOperationSet(send)
	receiveSet, _ := asyncapi.NewOperationSet(receive)

	if equal, err := absentSet.Equal(sendSet); err != nil || equal {
		t.Fatalf("absent equals send = %t, %v", equal, err)
	}
	if disjoint, err := absentSet.Disjoint(sendSet); err != nil || !disjoint {
		t.Fatalf("absent disjoint send = %t, %v", disjoint, err)
	}
	if disjoint, err := sendSet.Disjoint(receiveSet); err != nil || !disjoint {
		t.Fatalf("send disjoint receive = %t, %v", disjoint, err)
	}
	if _, err := absentSet.Union(sendSet); err == nil {
		t.Fatal("union accepted one operationId with conflicting action presence")
	}
	if _, err := sendSet.Union(receiveSet); err == nil {
		t.Fatal("union accepted one operationId with conflicting action values")
	}
	union, err := sendSet.Union(sendSet)
	if err != nil {
		t.Fatal(err)
	}
	if equal, err := union.Equal(sendSet); err != nil || !equal {
		t.Fatalf("idempotent union equality = %t, %v", equal, err)
	}

	registry, err := r3.NewRegistry(asyncapi.Vocabulary())
	if err != nil {
		t.Fatal(err)
	}
	duplicate := `{"vocabulary":"urn:aauth:vocabulary:asyncapi","operations":[{"operationId":"calendarEvent"},{"operationId":"calendarEvent","action":"send"}]}`
	if _, err := registry.ParseOperationSet([]byte(duplicate)); err == nil {
		t.Fatal("wire parser accepted duplicate operationId")
	}
}

func TestStrictAsyncAPIOperationWireShape(t *testing.T) {
	registry, err := r3.NewRegistry(asyncapi.Vocabulary())
	if err != nil {
		t.Fatal(err)
	}
	invalidOperations := []string{
		`{}`,
		`{"operationId":""}`,
		`{"operationId":" x "}`,
		`{"operationId":"x","action":"publish"}`,
		`{"operationId":"x","action":null}`,
		`{"operationId":"x","extra":true}`,
		`{"operationId":"x","operationId":"y"}`,
	}
	for _, operation := range invalidOperations {
		source := `{"vocabulary":"urn:aauth:vocabulary:asyncapi","operations":[` + operation + `]}`
		if _, err := registry.ParseOperationSet([]byte(source)); err == nil {
			t.Errorf("accepted invalid operation: %s", operation)
		}
	}
	if _, err := asyncapi.NewOperationWithAction("x", asyncapi.Action("publish")); err == nil {
		t.Fatal("constructor accepted invalid action")
	}
}
