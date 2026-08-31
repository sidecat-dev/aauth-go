package odata

import (
	"errors"
	"testing"

	"gitlab.com/sidecat-dev/aauth-go/r3"
)

const metadataEndpoint = "https://resource.example/odata"

func TestMetadataDefinitionDerivesEntitySetsAndUniqueBoundOperations(t *testing.T) {
	snapshot := parseMetadataFixture(t, `
<edmx:Edmx xmlns:edmx="http://docs.oasis-open.org/odata/ns/edmx" Version="4.0">
  <edmx:DataServices>
    <Schema xmlns="http://docs.oasis-open.org/odata/ns/edm" Namespace="Calendar" Alias="Cal">
      <EntityType Name="Event"/>
      <EntityContainer Name="Service">
        <EntitySet Name="Events" EntityType="Calendar.Event"/>
      </EntityContainer>
      <Action Name="Cancel" IsBound="true">
        <Parameter Name="bindingParameter" Type="Cal.Event"/>
      </Action>
      <Function Name="Upcoming" IsBound="true">
        <Parameter Name="bindingParameter" Type="Collection(Calendar.Event)"/>
      </Function>
    </Schema>
  </edmx:DataServices>
</edmx:Edmx>`)
	operations := snapshot.Operations().Operations()
	if len(operations) != 3 {
		t.Fatalf("operations = %d", len(operations))
	}
	want := []string{"Events", "Events/Cancel", "Events/Upcoming"}
	for index, neutral := range operations {
		operation, err := FromR3(neutral)
		if err != nil {
			t.Fatal(err)
		}
		if operation.OperationName() != want[index] {
			t.Fatalf("operation %d = %q", index, operation.OperationName())
		}
		if _, present, err := snapshot.HintsFor(neutral); err != nil || present {
			t.Fatalf("hints for %q = %t, %v", want[index], present, err)
		}
	}
	if err := snapshot.ValidateDefined(snapshot.Operations()); err != nil {
		t.Fatalf("validate derived operations: %v", err)
	}
}

func TestMetadataDefinitionDoesNotClaimMethodValidationTheMetadataCannotProve(t *testing.T) {
	snapshot := parseMetadataFixture(t, basicMetadata())
	operation, err := NewMethodOperation("Events", "GET")
	if err != nil {
		t.Fatal(err)
	}
	declared, err := NewOperationSet(operation)
	if err != nil {
		t.Fatal(err)
	}
	err = snapshot.ValidateDefined(declared)
	assertMetadataRefusal(t, err, r3.DefinitionOperationNotDefined)
}

func TestMetadataDefinitionRefusesAmbiguousIdentities(t *testing.T) {
	for _, test := range []struct {
		name string
		xml  string
	}{
		{name: "overloaded bound function", xml: `
<edmx:Edmx xmlns:edmx="http://docs.oasis-open.org/odata/ns/edmx" Version="4.0"><edmx:DataServices>
<Schema xmlns="http://docs.oasis-open.org/odata/ns/edm" Namespace="Calendar">
<EntityType Name="Event"/><EntityContainer Name="Service"><EntitySet Name="Events" EntityType="Calendar.Event"/></EntityContainer>
<Function Name="Upcoming" IsBound="true"><Parameter Name="bindingParameter" Type="Calendar.Event"/></Function>
<Function Name="Upcoming" IsBound="true"><Parameter Name="bindingParameter" Type="Calendar.Event"/><Parameter Name="days" Type="Edm.Int32"/></Function>
</Schema></edmx:DataServices></edmx:Edmx>`},
		{name: "multiple containers", xml: `
<edmx:Edmx xmlns:edmx="http://docs.oasis-open.org/odata/ns/edmx" Version="4.0"><edmx:DataServices>
<Schema xmlns="http://docs.oasis-open.org/odata/ns/edm" Namespace="Calendar">
<EntityType Name="Event"/>
<EntityContainer Name="First"><EntitySet Name="Events" EntityType="Calendar.Event"/></EntityContainer>
<EntityContainer Name="Second"><EntitySet Name="Other" EntityType="Calendar.Event"/></EntityContainer>
</Schema></edmx:DataServices></edmx:Edmx>`},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := ParseDefinition(metadataEndpoint, NewMetadataSource([]byte(test.xml)))
			assertMetadataRefusal(t, err, r3.DefinitionIdentityAmbiguous)
		})
	}
}

func TestMetadataDefinitionRefusesDependenciesAndUndefinedAAuthTerms(t *testing.T) {
	for _, test := range []struct {
		name string
		xml  string
		kind r3.DefinitionErrorKind
	}{
		{name: "external reference", xml: `<edmx:Edmx xmlns:edmx="http://docs.oasis-open.org/odata/ns/edmx" Version="4.0"><edmx:Reference Uri="types.xml"/><edmx:DataServices/></edmx:Edmx>`, kind: r3.DefinitionUnresolvedDependency},
		{name: "entity set type is missing", xml: `<edmx:Edmx xmlns:edmx="http://docs.oasis-open.org/odata/ns/edmx" Version="4.0"><edmx:DataServices><Schema xmlns="http://docs.oasis-open.org/odata/ns/edm" Namespace="Calendar"><EntityContainer Name="Service"><EntitySet Name="Events" EntityType="Missing.Event"/></EntityContainer></Schema></edmx:DataServices></edmx:Edmx>`, kind: r3.DefinitionUnresolvedDependency},
		{name: "bound operation type is missing", xml: `<edmx:Edmx xmlns:edmx="http://docs.oasis-open.org/odata/ns/edmx" Version="4.0"><edmx:DataServices><Schema xmlns="http://docs.oasis-open.org/odata/ns/edm" Namespace="Calendar"><EntityType Name="Event"/><EntityContainer Name="Service"><EntitySet Name="Events" EntityType="Calendar.Event"/></EntityContainer><Action Name="Cancel" IsBound="true"><Parameter Name="bindingParameter" Type="Missing.Event"/></Action></Schema></edmx:DataServices></edmx:Edmx>`, kind: r3.DefinitionUnresolvedDependency},
		{name: "AAuth term", xml: `
<edmx:Edmx xmlns:edmx="http://docs.oasis-open.org/odata/ns/edmx" Version="4.0"><edmx:DataServices>
<Schema xmlns="http://docs.oasis-open.org/odata/ns/edm" Namespace="Calendar"><EntityType Name="Event"/>
<EntityContainer Name="Service"><EntitySet Name="Events" EntityType="Calendar.Event"><Annotation Term="AAuth.AccessMode" String="person-token"/></EntitySet></EntityContainer>
</Schema></edmx:DataServices></edmx:Edmx>`, kind: r3.DefinitionSourceKindUnsupported},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := ParseDefinition(metadataEndpoint, NewMetadataSource([]byte(test.xml)))
			assertMetadataRefusal(t, err, test.kind)
		})
	}
}

func TestMetadataDefinitionRefusesInvalidAndIncompleteSources(t *testing.T) {
	for _, test := range []struct {
		name string
		xml  string
		kind r3.DefinitionErrorKind
	}{
		{name: "invalid XML", xml: `<`, kind: r3.DefinitionInvalidSource},
		{name: "wrong root", xml: `<metadata/>`, kind: r3.DefinitionInvalidSource},
		{name: "multiple roots", xml: basicMetadata() + `<metadata/>`, kind: r3.DefinitionInvalidSource},
		{name: "text after root", xml: basicMetadata() + `not-xml`, kind: r3.DefinitionInvalidSource},
		{name: "no container", xml: `<edmx:Edmx xmlns:edmx="http://docs.oasis-open.org/odata/ns/edmx" Version="4.0"><edmx:DataServices/></edmx:Edmx>`, kind: r3.DefinitionIncompleteSource},
		{name: "container without name", xml: `<edmx:Edmx xmlns:edmx="http://docs.oasis-open.org/odata/ns/edmx" Version="4.0"><edmx:DataServices><Schema xmlns="http://docs.oasis-open.org/odata/ns/edm" Namespace="Calendar"><EntityType Name="Event"/><EntityContainer><EntitySet Name="Events" EntityType="Calendar.Event"/></EntityContainer></Schema></edmx:DataServices></edmx:Edmx>`, kind: r3.DefinitionInvalidSource},
		{name: "duplicate identity attribute", xml: `<edmx:Edmx xmlns:edmx="http://docs.oasis-open.org/odata/ns/edmx" Version="4.0"><edmx:DataServices><Schema xmlns="http://docs.oasis-open.org/odata/ns/edm" Namespace="Calendar"><EntityType Name="Event"/><EntityContainer Name="Service"><EntitySet Name="Events" Name="Other" EntityType="Calendar.Event"/></EntityContainer></Schema></edmx:DataServices></edmx:Edmx>`, kind: r3.DefinitionInvalidSource},
		{name: "binding parameter without name", xml: metadataWithBindingParameter(`<Parameter Type="Calendar.Event"/>`), kind: r3.DefinitionInvalidSource},
		{name: "unterminated collection type", xml: metadataWithBindingParameter(`<Parameter Name="bindingParameter" Type="Collection(Calendar.Event"/>`), kind: r3.DefinitionInvalidSource},
		{name: "stray collection terminator", xml: metadataWithBindingParameter(`<Parameter Name="bindingParameter" Type="Calendar.Event)"/>`), kind: r3.DefinitionInvalidSource},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := ParseDefinition(metadataEndpoint, NewMetadataSource([]byte(test.xml)))
			assertMetadataRefusal(t, err, test.kind)
		})
	}
}

func TestMetadataSourceOwnsExactBytes(t *testing.T) {
	exact := []byte(basicMetadata())
	source := NewMetadataSource(exact)
	exact[0] = '['
	copy := source.ExactBytes()
	copy[0] = '['
	if source.ExactBytes()[0] != '\n' {
		t.Fatal("metadata source changed through caller memory")
	}
	snapshot, err := ParseDefinition(metadataEndpoint, source)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Receipt().Digest() != r3.Digest(source.ExactBytes()) {
		t.Fatal("metadata source receipt does not cover exact bytes")
	}
}

func basicMetadata() string {
	return `
<edmx:Edmx xmlns:edmx="http://docs.oasis-open.org/odata/ns/edmx" Version="4.0">
  <edmx:DataServices><Schema xmlns="http://docs.oasis-open.org/odata/ns/edm" Namespace="Calendar">
    <EntityType Name="Event"/>
    <EntityContainer Name="Service"><EntitySet Name="Events" EntityType="Calendar.Event"/></EntityContainer>
  </Schema></edmx:DataServices>
</edmx:Edmx>`
}

func metadataWithBindingParameter(parameter string) string {
	return `<edmx:Edmx xmlns:edmx="http://docs.oasis-open.org/odata/ns/edmx" Version="4.0"><edmx:DataServices><Schema xmlns="http://docs.oasis-open.org/odata/ns/edm" Namespace="Calendar"><EntityType Name="Event"/><EntityContainer Name="Service"><EntitySet Name="Events" EntityType="Calendar.Event"/></EntityContainer><Action Name="Cancel" IsBound="true">` + parameter + `</Action></Schema></edmx:DataServices></edmx:Edmx>`
}

func parseMetadataFixture(t *testing.T, source string) r3.AuthoritativeSnapshot {
	t.Helper()
	snapshot, err := ParseDefinition(metadataEndpoint, NewMetadataSource([]byte(source)))
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func assertMetadataRefusal(t *testing.T, err error, kind r3.DefinitionErrorKind) {
	t.Helper()
	var refusal *r3.DefinitionError
	if !errors.As(err, &refusal) || refusal.Kind != kind || refusal.Vocabulary != URI {
		t.Fatalf("refusal = %T %v", err, err)
	}
}
