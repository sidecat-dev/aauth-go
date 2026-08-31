package asyncapi

import (
	"errors"
	"strings"
	"testing"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/r3"
)

func TestJSONDefinitionDerivesOperationsAndSparseHints(t *testing.T) {
	exact := []byte(`{
		"asyncapi":"3.0.0",
		"info":{"title":"events","version":"1.0.0"},
		"operations":{
			"receiveEvent":{"action":"receive","channel":{"$ref":"#/channels/events"}},
			"publishEvent":{"action":"send","channel":{"$ref":"#/channels/events"},"x-aauth-access-mode":"person-token","x-aauth-budget":false}
		},
		"channels":{"events":{"address":"events","messages":{}}}
	}`)
	source := NewJSONDocumentSource(exact)
	snapshot, err := ParseDefinition("https://resource.example/asyncapi.json", source)
	if err != nil {
		t.Fatal(err)
	}
	exact[0] = '['
	if snapshot.Receipt().Digest() != r3.Digest(source.ExactBytes()) {
		t.Fatalf("source digest = %q", snapshot.Receipt().Digest())
	}
	if snapshot.Receipt().Encoding() != sourceEncoding {
		t.Fatalf("source encoding = %q", snapshot.Receipt().Encoding())
	}
	operations := snapshot.Operations().Operations()
	if len(operations) != 2 {
		t.Fatalf("operations = %d", len(operations))
	}
	first, err := FromR3(operations[0])
	if err != nil {
		t.Fatal(err)
	}
	if first.OperationID() != "publishEvent" {
		t.Fatalf("first operation = %q", first.OperationID())
	}
	hints, present, err := snapshot.HintsFor(operations[0])
	if err != nil || !present {
		t.Fatalf("hints = %#v, %t, %v", hints, present, err)
	}
	mode, modePresent := hints.AccessMode()
	budget, budgetPresent := hints.Budget()
	if !modePresent || mode != aauth.AccessModePersonToken || !budgetPresent || budget {
		t.Fatalf("hints = %q/%t budget=%t/%t", mode, modePresent, budget, budgetPresent)
	}
	if _, present, err := snapshot.HintsFor(operations[1]); err != nil || present {
		t.Fatalf("unannotated hints = %t, %v", present, err)
	}
	if err := snapshot.ValidateDefined(snapshot.Operations()); err != nil {
		t.Fatalf("validate operations: %v", err)
	}
}

func TestJSONDefinitionPreservesOperationMapKeysWithoutPrivateGrammar(t *testing.T) {
	snapshot := parseAsyncAPIFixture(
		t,
		strings.Replace(
			asyncAPIDocument(`{"action":"send","channel":{"$ref":"#/channels/events"}}`),
			`"event":`,
			`"calendar.events/read":`,
			1,
		),
	)
	operations := snapshot.Operations().Operations()
	if len(operations) != 1 {
		t.Fatalf("operations = %d", len(operations))
	}
	operation, err := FromR3(operations[0])
	if err != nil {
		t.Fatal(err)
	}
	if operation.OperationID() != "calendar.events/read" {
		t.Fatalf("operationId = %q", operation.OperationID())
	}
}

func TestJSONDefinitionResolvesOneEscapedChannelPointerToken(t *testing.T) {
	snapshot := parseAsyncAPIFixture(t, `{"asyncapi":"3.0.0","info":{"title":"events","version":"1"},"channels":{"events/archive":{"address":"events"}},"operations":{"read":{"action":"receive","channel":{"$ref":"#/channels/events~1archive"}}}}`)
	if len(snapshot.Operations().Operations()) != 1 {
		t.Fatalf("operations = %d", len(snapshot.Operations().Operations()))
	}
}

func TestJSONDefinitionDecodesURIFragmentBeforeChannelPointer(t *testing.T) {
	snapshot := parseAsyncAPIFixture(t, `{"asyncapi":"3.0.0","info":{"title":"events","version":"1"},"channels":{"events archive":{"address":"events"}},"operations":{"read":{"action":"receive","channel":{"$ref":"#/channels/events%20archive"}}}}`)
	if len(snapshot.Operations().Operations()) != 1 {
		t.Fatalf("operations = %d", len(snapshot.Operations().Operations()))
	}
}

func TestJSONDefinitionRefusesOmittedR3ActionAsNotDefined(t *testing.T) {
	snapshot := parseAsyncAPIFixture(t, asyncAPIDocument(`{"action":"send","channel":{"$ref":"#/channels/events"}}`))
	operation, err := NewOperation("publishEvent")
	if err != nil {
		t.Fatal(err)
	}
	declared, err := NewOperationSet(operation)
	if err != nil {
		t.Fatal(err)
	}
	err = snapshot.ValidateDefined(declared)
	var refusal *r3.DefinitionError
	if !errors.As(err, &refusal) || refusal.Kind != r3.DefinitionOperationNotDefined {
		t.Fatalf("refusal = %T %v", err, err)
	}
}

func TestJSONDefinitionRefusesInvalidSources(t *testing.T) {
	for _, test := range []struct {
		name string
		raw  string
		kind r3.DefinitionErrorKind
	}{
		{name: "invalid JSON", raw: `{`, kind: r3.DefinitionInvalidSource},
		{name: "duplicate member", raw: `{"asyncapi":"3.0.0","asyncapi":"3.1.0","operations":{}}`, kind: r3.DefinitionInvalidSource},
		{name: "old version", raw: `{"asyncapi":"2.6.0","operations":{"event":{"action":"send"}}}`, kind: r3.DefinitionSourceKindUnsupported},
		{name: "missing info", raw: `{"asyncapi":"3.0.0","channels":{"events":{}},"operations":{"event":{"action":"send","channel":{"$ref":"#/channels/events"}}}}`, kind: r3.DefinitionIncompleteSource},
		{name: "missing operations", raw: `{"asyncapi":"3.0.0","info":{"title":"events","version":"1"},"channels":{"events":{}}}`, kind: r3.DefinitionIncompleteSource},
		{name: "empty operations", raw: `{"asyncapi":"3.0.0","info":{"title":"events","version":"1"},"channels":{"events":{}},"operations":{}}`, kind: r3.DefinitionIncompleteSource},
		{name: "reference", raw: asyncAPIDocument(`{"$ref":"other.json#/event"}`), kind: r3.DefinitionUnresolvedDependency},
		{name: "missing action", raw: asyncAPIDocument(`{"channel":{"$ref":"#/channels/events"}}`), kind: r3.DefinitionInvalidSource},
		{name: "missing channel", raw: asyncAPIDocument(`{"action":"send"}`), kind: r3.DefinitionIncompleteSource},
		{name: "external channel", raw: asyncAPIDocument(`{"action":"send","channel":{"$ref":"https://example.test/channel"}}`), kind: r3.DefinitionUnresolvedDependency},
		{name: "nested channel pointer", raw: `{"asyncapi":"3.0.0","info":{"title":"events","version":"1"},"channels":{"events/child":{"address":"events"}},"operations":{"event":{"action":"send","channel":{"$ref":"#/channels/events/child"}}}}`, kind: r3.DefinitionUnresolvedDependency},
		{name: "invalid channel pointer escape", raw: `{"asyncapi":"3.0.0","info":{"title":"events","version":"1"},"channels":{"events~2":{"address":"events"}},"operations":{"event":{"action":"send","channel":{"$ref":"#/channels/events~2"}}}}`, kind: r3.DefinitionUnresolvedDependency},
		{name: "nested external reference", raw: `{"asyncapi":"3.0.0","info":{"title":"events","version":"1"},"channels":{"events":{"address":"events","messages":{"event":{"$ref":"https://example.test/message"}}}},"operations":{"event":{"action":"send","channel":{"$ref":"#/channels/events"}}}}`, kind: r3.DefinitionUnresolvedDependency},
		{name: "operation traits", raw: asyncAPIDocument(`{"action":"send","channel":{"$ref":"#/channels/events"},"traits":[]}`), kind: r3.DefinitionSourceKindUnsupported},
		{name: "invalid access hint", raw: asyncAPIDocument(`{"action":"send","channel":{"$ref":"#/channels/events"},"x-aauth-access-mode":"session-token"}`), kind: r3.DefinitionInvalidAnnotation},
		{name: "invalid budget hint", raw: asyncAPIDocument(`{"action":"send","channel":{"$ref":"#/channels/events"},"x-aauth-budget":"yes"}`), kind: r3.DefinitionInvalidAnnotation},
		{name: "null budget hint", raw: asyncAPIDocument(`{"action":"send","channel":{"$ref":"#/channels/events"},"x-aauth-budget":null}`), kind: r3.DefinitionInvalidAnnotation},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := ParseDefinition(
				"https://resource.example/asyncapi.json",
				NewJSONDocumentSource([]byte(test.raw)),
			)
			var refusal *r3.DefinitionError
			if !errors.As(err, &refusal) || refusal.Kind != test.kind {
				t.Fatalf("refusal = %T %v", err, err)
			}
		})
	}
}

func TestJSONDocumentSourceOwnsExactBytes(t *testing.T) {
	exact := []byte(`{"asyncapi":"3.0.0","operations":{"event":{"action":"send"}}}`)
	source := NewJSONDocumentSource(exact)
	exact[0] = '['
	copy := source.ExactBytes()
	copy[0] = '['
	if got := string(source.ExactBytes()); got[0] != '{' {
		t.Fatalf("source changed through caller memory: %s", got)
	}
}

func parseAsyncAPIFixture(t *testing.T, source string) r3.AuthoritativeSnapshot {
	t.Helper()
	snapshot, err := ParseDefinition(
		"https://resource.example/asyncapi.json",
		NewJSONDocumentSource([]byte(source)),
	)
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func asyncAPIDocument(operation string) string {
	return `{"asyncapi":"3.0.0","info":{"title":"events","version":"1"},"channels":{"events":{"address":"events","messages":{}}},"operations":{"event":` + operation + `}}`
}
