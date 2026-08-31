package openapi

import (
	"errors"
	"slices"
	"testing"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/r3"
)

const definitionEndpoint = "https://resource.example/openapi.yaml"

func TestParseDefinitionOwnsExactSourceAndDerivesCallerOperations(t *testing.T) {
	original := []byte(`openapi: 3.1.0
info:
  title: Pet API
  version: 1.0.0
paths:
  /pets:
    get:
      operationId: listPets
      x-aauth-access-mode: person-token
      x-aauth-budget: false
      responses:
        "200":
          description: ok
    post:
      operationId: createPet
      responses:
        "204":
          description: created
`)
	wantBytes := append([]byte(nil), original...)
	source := NewDocumentSource(original)
	original[0] = 'X'

	snapshot, err := ParseDefinition(definitionEndpoint, source)
	if err != nil {
		t.Fatal(err)
	}
	if got := source.ExactBytes(); !slices.Equal(got, wantBytes) {
		t.Fatalf("DocumentSource.ExactBytes() changed: %q", got)
	}
	returned := source.ExactBytes()
	returned[0] = 'Y'
	if got := source.ExactBytes(); !slices.Equal(got, wantBytes) {
		t.Fatalf("mutating returned bytes changed source: %q", got)
	}
	if got, want := snapshot.Receipt().Digest(), r3.Digest(wantBytes); got != want {
		t.Fatalf("source digest = %q, want %q", got, want)
	}
	if got, want := snapshot.Receipt().ByteLength(), int64(len(wantBytes)); got != want {
		t.Fatalf("source bytes = %d, want %d", got, want)
	}
	if got := snapshot.Receipt().DiscoveryEndpoint(); got != definitionEndpoint {
		t.Fatalf("source endpoint = %q", got)
	}

	operations := operationIDs(t, snapshot)
	if !slices.Equal(operations, []string{"listPets", "createPet"}) {
		t.Fatalf("operationIds = %v", operations)
	}
	known := mustOperationSet(t, "listPets")
	if err := snapshot.ValidateDefined(known); err != nil {
		t.Fatalf("ValidateDefined(known): %v", err)
	}
	if err := snapshot.ValidateDefined(mustOperationSet(t, "missing")); definitionKind(err) != r3.DefinitionOperationNotDefined {
		t.Fatalf("ValidateDefined(unknown) = %v", err)
	}

	listPets, err := NewOperation("listPets")
	if err != nil {
		t.Fatal(err)
	}
	hints, present, err := snapshot.HintsFor(mustR3Operation(t, listPets))
	if err != nil {
		t.Fatal(err)
	}
	mode, modePresent := hints.AccessMode()
	budget, budgetPresent := hints.Budget()
	if !present || !modePresent || mode != aauth.AccessModePersonToken || !budgetPresent || budget {
		t.Fatalf("listPets hints = present:%t mode:%q/%t budget:%t/%t", present, mode, modePresent, budget, budgetPresent)
	}

	registry, err := r3.NewDefinitionRegistry(DefinitionRegistration())
	if err != nil {
		t.Fatal(err)
	}
	if err := registry.Validate(snapshot); err != nil {
		t.Fatalf("definition registration did not validate snapshot: %v", err)
	}
}

func TestParseDefinitionAcceptsSelfContainedOpenAPI30AndInternalReferences(t *testing.T) {
	source := NewDocumentSource([]byte(`{
  "openapi":"3.0.3",
  "info":{"title":"Pet API","version":"1"},
  "paths":{"/pets":{"get":{"operationId":"listPets","responses":{"200":{"description":"ok","content":{"application/json":{"schema":{"$ref":"#/components/schemas/Pet"}}}}}}}},
  "components":{"schemas":{"Pet":{"type":"object","properties":{"name":{"type":"string"}}}}}
}`))
	snapshot, err := ParseDefinition("https://resource.example/openapi.json", source)
	if err != nil {
		t.Fatal(err)
	}
	if got := operationIDs(t, snapshot); !slices.Equal(got, []string{"listPets"}) {
		t.Fatalf("operationIds = %v", got)
	}
}

func TestParseDefinitionDoesNotTreatExamplePayloadFieldsAsOpenAPIReferences(t *testing.T) {
	source := NewDocumentSource([]byte(`{
  "openapi":"3.1.0",
  "info":{"title":"Example API","version":"1"},
  "paths":{"/example":{"get":{"operationId":"example","responses":{"200":{"description":"ok","content":{"application/json":{"example":{"$ref":"https://payload.example/not-an-openapi-reference"}}}}}}}}
}`))
	snapshot, err := ParseDefinition(definitionEndpoint, source)
	if err != nil {
		t.Fatal(err)
	}
	if got := operationIDs(t, snapshot); !slices.Equal(got, []string{"example"}) {
		t.Fatalf("operationIds = %v", got)
	}
}

func TestParseDefinitionKeepsNamedSubsetWhenOtherPathOperationsAreUnnamed(t *testing.T) {
	source := NewDocumentSource([]byte(`{"openapi":"3.1.0","info":{"title":"test","version":"1"},"paths":{"/named":{"get":{"operationId":"named","responses":{"204":{"description":"ok"}}}},"/unnamed":{"post":{"responses":{"204":{"description":"ok"}}}}}}`))
	snapshot, err := ParseDefinition(definitionEndpoint, source)
	if err != nil {
		t.Fatal(err)
	}
	if got := operationIDs(t, snapshot); !slices.Equal(got, []string{"named"}) {
		t.Fatalf("operationIds = %v", got)
	}
}

func TestParseDefinitionRefusesNoIdentifiableOrDuplicatePathOperations(t *testing.T) {
	for _, test := range []struct {
		name  string
		paths string
		kind  r3.DefinitionErrorKind
	}{
		{name: "none identifiable", paths: `{"/a":{"get":{"responses":{"204":{"description":"ok"}}}}}`, kind: r3.DefinitionIdentityUnavailable},
		{name: "duplicate", paths: `{"/a":{"get":{"operationId":"same","responses":{"204":{"description":"ok"}}}},"/b":{"post":{"operationId":"same","responses":{"204":{"description":"ok"}}}}}`, kind: r3.DefinitionIdentityAmbiguous},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := ParseDefinition(definitionEndpoint, NewDocumentSource([]byte(`{"openapi":"3.1.0","info":{"title":"test","version":"1"},"paths":`+test.paths+`}`)))
			if got := definitionKind(err); got != test.kind {
				t.Fatalf("ParseDefinition() kind = %q, want %q; error: %v", got, test.kind, err)
			}
		})
	}
}

func TestParseDefinitionRefusesInvalidVersionsDocumentsAndExternalReferences(t *testing.T) {
	tests := []struct {
		name   string
		source string
		kind   r3.DefinitionErrorKind
	}{
		{name: "invalid document", source: `{`, kind: r3.DefinitionInvalidSource},
		{name: "swagger 2", source: `{"swagger":"2.0","info":{"title":"x","version":"1"},"paths":{}}`, kind: r3.DefinitionSourceKindUnsupported},
		{name: "unsupported OpenAPI version", source: `{"openapi":"3.2.0","info":{"title":"x","version":"1"},"paths":{}}`, kind: r3.DefinitionSourceKindUnsupported},
		{name: "external HTTPS reference", source: `{"openapi":"3.1.0","info":{"title":"x","version":"1"},"paths":{"/x":{"get":{"operationId":"x","responses":{"200":{"$ref":"https://schemas.example/responses.yaml#/OK"}}}}}}`, kind: r3.DefinitionUnresolvedDependency},
		{name: "external file reference", source: `{"openapi":"3.1.0","info":{"title":"x","version":"1"},"paths":{"/x":{"get":{"operationId":"x","responses":{"200":{"$ref":"./responses.yaml#/OK"}}}}}}`, kind: r3.DefinitionUnresolvedDependency},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := ParseDefinition(definitionEndpoint, NewDocumentSource([]byte(test.source)))
			if got := definitionKind(err); got != test.kind {
				t.Fatalf("ParseDefinition() kind = %q, want %q; error: %v", got, test.kind, err)
			}
		})
	}
}

func TestParseDefinitionPreservesSparseHintsAndReportsInvalidOnes(t *testing.T) {
	valid := NewDocumentSource([]byte(`{
  "openapi":"3.1.0",
  "info":{"title":"hints","version":"1"},
  "paths":{
    "/mode":{"get":{"operationId":"modeOnly","x-aauth-access-mode":"per-call","responses":{"204":{"description":"ok"}}}},
    "/budget":{"get":{"operationId":"budgetOnly","x-aauth-budget":true,"responses":{"204":{"description":"ok"}}}},
    "/conflict":{"get":{"operationId":"conflict","x-aauth-access-mode":"agent-token","x-aauth-budget":true,"responses":{"204":{"description":"ok"}}}},
    "/none":{"get":{"operationId":"none","responses":{"204":{"description":"ok"}}}}
  }
}`))
	snapshot, err := ParseDefinition(definitionEndpoint, valid)
	if err != nil {
		t.Fatal(err)
	}

	modeHints := hintsFor(t, snapshot, "modeOnly")
	if mode, ok := modeHints.AccessMode(); !ok || mode != r3.AccessModePerCall {
		t.Fatalf("modeOnly access mode = %q/%t", mode, ok)
	}
	if _, ok := modeHints.Budget(); ok {
		t.Fatal("modeOnly acquired an absent budget hint")
	}
	budgetHints := hintsFor(t, snapshot, "budgetOnly")
	if budget, ok := budgetHints.Budget(); !ok || !budget {
		t.Fatalf("budgetOnly budget = %t/%t", budget, ok)
	}
	if _, ok := budgetHints.AccessMode(); ok {
		t.Fatal("budgetOnly acquired an absent access-mode hint")
	}
	conflictHints := hintsFor(t, snapshot, "conflict")
	planned, err := conflictHints.Plan(aauth.AccessModePersonToken)
	if err != nil {
		t.Fatal(err)
	}
	if !planned.PublisherConflict() || planned.AccessMode() != aauth.AccessModeAuthToken {
		t.Fatalf("contradictory hints planned as mode=%q conflict=%t", planned.AccessMode(), planned.PublisherConflict())
	}
	none, err := NewOperation("none")
	if err != nil {
		t.Fatal(err)
	}
	if _, present, err := snapshot.HintsFor(mustR3Operation(t, none)); err != nil || present {
		t.Fatalf("unannotated hints = present:%t error:%v", present, err)
	}

	invalid := []string{
		`"x-aauth-access-mode":true`,
		`"x-aauth-access-mode":"session-token"`,
		`"x-aauth-budget":"true"`,
		`"x-aauth-budget":null`,
	}
	for _, extension := range invalid {
		source := `{"openapi":"3.1.0","info":{"title":"x","version":"1"},"paths":{"/x":{"get":{"operationId":"x",` + extension + `,"responses":{"204":{"description":"ok"}}}}}}`
		_, err := ParseDefinition(definitionEndpoint, NewDocumentSource([]byte(source)))
		if got := definitionKind(err); got != r3.DefinitionInvalidAnnotation {
			t.Fatalf("extension %s kind = %q, want %q; error: %v", extension, got, r3.DefinitionInvalidAnnotation, err)
		}
	}
}

func TestParseDefinitionIgnoresCallbackAndWebhookOperationsInInitialProfile(t *testing.T) {
	source := NewDocumentSource([]byte(`{
  "openapi":"3.1.0",
  "info":{"title":"profile","version":"1"},
  "paths":{"/start":{"post":{"operationId":"start","responses":{"202":{"description":"ok"}},"callbacks":{"finished":{"{$request.body#/callback}":{"post":{"operationId":"callbackFinished","responses":{"204":{"description":"ok"}}}}}}}}},
  "webhooks":{"updated":{"post":{"operationId":"webhookUpdated","responses":{"204":{"description":"ok"}}}}}
}`))
	snapshot, err := ParseDefinition(definitionEndpoint, source)
	if err != nil {
		t.Fatal(err)
	}
	if got := operationIDs(t, snapshot); !slices.Equal(got, []string{"start"}) {
		t.Fatalf("caller operationIds = %v", got)
	}
}

func operationIDs(t *testing.T, snapshot r3.AuthoritativeSnapshot) []string {
	t.Helper()
	operations := snapshot.Operations().Operations()
	result := make([]string, len(operations))
	for index, operation := range operations {
		typed, err := FromR3(operation)
		if err != nil {
			t.Fatal(err)
		}
		result[index] = typed.OperationID()
	}
	return result
}

func mustOperationSet(t *testing.T, operationIDs ...string) r3.OperationSet {
	t.Helper()
	operations := make([]Operation, len(operationIDs))
	for index, operationID := range operationIDs {
		operation, err := NewOperation(operationID)
		if err != nil {
			t.Fatal(err)
		}
		operations[index] = operation
	}
	result, err := NewOperationSet(operations...)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func mustR3Operation(t *testing.T, operation Operation) r3.Operation {
	t.Helper()
	neutral, err := operation.ToR3()
	if err != nil {
		t.Fatal(err)
	}
	return neutral
}

func hintsFor(t *testing.T, snapshot r3.AuthoritativeSnapshot, operationID string) r3.OperationHints {
	t.Helper()
	operation, err := NewOperation(operationID)
	if err != nil {
		t.Fatal(err)
	}
	hints, present, err := snapshot.HintsFor(mustR3Operation(t, operation))
	if err != nil {
		t.Fatal(err)
	}
	if !present {
		t.Fatalf("hints for %q are absent", operationID)
	}
	return hints
}

func definitionKind(err error) r3.DefinitionErrorKind {
	var failure *r3.DefinitionError
	if errors.As(err, &failure) {
		return failure.Kind
	}
	return ""
}
