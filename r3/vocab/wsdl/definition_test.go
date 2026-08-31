package wsdl

import (
	"errors"
	"slices"
	"testing"

	"gitlab.com/sidecat-dev/aauth-go/r3"
)

const definitionEndpoint = "https://resource.example/service.wsdl"

func TestParseDefinitionDerivesUniqueBoundOperation(t *testing.T) {
	exact := []byte(`<?xml version="1.0"?>
<definitions xmlns="http://schemas.xmlsoap.org/wsdl/"
  xmlns:tns="urn:example:health" targetNamespace="urn:example:health">
  <message name="HealthRequest"/>
  <portType name="HealthPortType">
    <operation name="Health"><input message="tns:HealthRequest"/></operation>
  </portType>
  <binding name="HealthBinding" type="tns:HealthPortType">
    <operation name="Health"/>
  </binding>
  <service name="HealthService">
    <port name="HealthPort" binding="tns:HealthBinding"/>
  </service>
</definitions>`)
	wantExact := append([]byte(nil), exact...)
	source := NewXMLDocumentSource(exact)
	exact[0] = 'X'

	snapshot, err := ParseDefinition(definitionEndpoint, source)
	if err != nil {
		t.Fatal(err)
	}
	if got := source.ExactBytes(); !slices.Equal(got, wantExact) {
		t.Fatalf("ExactBytes() = %q, want original source", got)
	}
	returned := source.ExactBytes()
	returned[0] = 'Y'
	if got := source.ExactBytes(); !slices.Equal(got, wantExact) {
		t.Fatalf("mutating returned bytes changed source: %q", got)
	}
	if got, want := snapshot.Receipt().Digest(), r3.Digest(wantExact); got != want {
		t.Fatalf("source digest = %q, want %q", got, want)
	}
	if got := snapshot.Receipt().DiscoveryEndpoint(); got != definitionEndpoint {
		t.Fatalf("source endpoint = %q", got)
	}
	if got := definitionOperations(t, snapshot); !slices.Equal(got, []string{"Health"}) {
		t.Fatalf("operations = %v", got)
	}

	known, err := NewOperation("Health")
	if err != nil {
		t.Fatal(err)
	}
	knownSet, err := NewOperationSet(known)
	if err != nil {
		t.Fatal(err)
	}
	if err := snapshot.ValidateDefined(knownSet); err != nil {
		t.Fatalf("ValidateDefined(known): %v", err)
	}
	unknown, _ := NewOperation("Missing")
	unknownSet, _ := NewOperationSet(unknown)
	if err := snapshot.ValidateDefined(unknownSet); definitionErrorKind(err) != r3.DefinitionOperationNotDefined {
		t.Fatalf("ValidateDefined(unknown) = %v", err)
	}

	registry, err := r3.NewDefinitionRegistry(DefinitionRegistration())
	if err != nil {
		t.Fatal(err)
	}
	if err := registry.Validate(snapshot); err != nil {
		t.Fatalf("definition registration did not validate snapshot: %v", err)
	}
}

func TestParseDefinitionQualifiesSameOperationNameAcrossServices(t *testing.T) {
	snapshot, err := ParseDefinition(definitionEndpoint, NewXMLDocumentSource([]byte(`
<definitions xmlns="http://schemas.xmlsoap.org/wsdl/"
  xmlns:tns="urn:example:dual" targetNamespace="urn:example:dual">
  <message name="SubmitRequest"/>
  <portType name="AlphaPortType"><operation name="Submit"><input message="tns:SubmitRequest"/></operation></portType>
  <portType name="BetaPortType"><operation name="Submit"><input message="tns:SubmitRequest"/></operation></portType>
  <binding name="AlphaBinding" type="tns:AlphaPortType"><operation name="Submit"/></binding>
  <binding name="BetaBinding" type="tns:BetaPortType"><operation name="Submit"/></binding>
  <service name="AlphaService"><port name="AlphaPort" binding="tns:AlphaBinding"/></service>
  <service name="BetaService"><port name="BetaPort" binding="tns:BetaBinding"/></service>
</definitions>`)))
	if err != nil {
		t.Fatal(err)
	}
	if got := definitionOperations(t, snapshot); !slices.Equal(got, []string{"AlphaService/Submit", "BetaService/Submit"}) {
		t.Fatalf("operations = %v", got)
	}
}

func TestParseDefinitionRefusesAmbiguousBoundMeaningWithinService(t *testing.T) {
	_, err := ParseDefinition(definitionEndpoint, NewXMLDocumentSource([]byte(`
<definitions xmlns="http://schemas.xmlsoap.org/wsdl/"
  xmlns:tns="urn:example:ambiguous" targetNamespace="urn:example:ambiguous">
  <message name="SubmitRequest"/>
  <portType name="AlphaPortType"><operation name="Submit"><input message="tns:SubmitRequest"/></operation></portType>
  <portType name="BetaPortType"><operation name="Submit"><input message="tns:SubmitRequest"/></operation></portType>
  <binding name="AlphaBinding" type="tns:AlphaPortType"><operation name="Submit"/></binding>
  <binding name="BetaBinding" type="tns:BetaPortType"><operation name="Submit"/></binding>
  <service name="CombinedService">
    <port name="AlphaPort" binding="tns:AlphaBinding"/>
    <port name="BetaPort" binding="tns:BetaBinding"/>
  </service>
</definitions>`)))
	if got := definitionErrorKind(err); got != r3.DefinitionIdentityAmbiguous {
		t.Fatalf("ParseDefinition() kind = %q, want %q; error: %v", got, r3.DefinitionIdentityAmbiguous, err)
	}
}

func TestParseDefinitionRefusesOverloadedPortTypeOperation(t *testing.T) {
	_, err := ParseDefinition(definitionEndpoint, NewXMLDocumentSource([]byte(`
<definitions xmlns="http://schemas.xmlsoap.org/wsdl/"
  xmlns:tns="urn:example:overload" targetNamespace="urn:example:overload">
  <message name="First"/><message name="Second"/>
  <portType name="PortType">
    <operation name="Lookup"><input message="tns:First"/></operation>
    <operation name="Lookup"><input message="tns:Second"/></operation>
  </portType>
  <binding name="Binding" type="tns:PortType"><operation name="Lookup"/></binding>
  <service name="Service"><port name="Port" binding="tns:Binding"/></service>
</definitions>`)))
	if got := definitionErrorKind(err); got != r3.DefinitionIdentityAmbiguous {
		t.Fatalf("ParseDefinition() kind = %q, want %q; error: %v", got, r3.DefinitionIdentityAmbiguous, err)
	}
}

func TestParseDefinitionRefusesImportsAndIncludes(t *testing.T) {
	for _, element := range []string{
		`<import namespace="urn:other" location="other.wsdl"/>`,
		`<include location="other.wsdl"/>`,
	} {
		_, err := ParseDefinition(definitionEndpoint, NewXMLDocumentSource([]byte(`
<definitions xmlns="http://schemas.xmlsoap.org/wsdl/" targetNamespace="urn:example:dependency">`+element+`</definitions>`)))
		if got := definitionErrorKind(err); got != r3.DefinitionUnresolvedDependency {
			t.Fatalf("%s kind = %q, want %q; error: %v", element, got, r3.DefinitionUnresolvedDependency, err)
		}
	}
}

func TestParseDefinitionRefusesMultipleRootsAndIncompletePortTypeOperation(t *testing.T) {
	for _, test := range []struct {
		name string
		xml  string
		kind r3.DefinitionErrorKind
	}{
		{
			name: "multiple roots",
			xml: `<definitions xmlns="http://schemas.xmlsoap.org/wsdl/" xmlns:tns="urn:first" targetNamespace="urn:first"><message name="Request"/><portType name="Port"><operation name="Read"><input message="tns:Request"/></operation></portType><binding name="Binding" type="tns:Port"><operation name="Read"/></binding><service name="Service"><port name="Port" binding="tns:Binding"/></service></definitions>` +
				`<definitions xmlns="http://schemas.xmlsoap.org/wsdl/" targetNamespace="urn:second"></definitions>`,
			kind: r3.DefinitionInvalidSource,
		},
		{
			name: "port type operation has no message exchange",
			xml: `<definitions xmlns="http://schemas.xmlsoap.org/wsdl/" xmlns:tns="urn:test" targetNamespace="urn:test">` +
				`<portType name="Port"><operation name="Read"/></portType>` +
				`<binding name="Binding" type="tns:Port"><operation name="Read"/></binding>` +
				`<service name="Service"><port name="Port" binding="tns:Binding"/></service></definitions>`,
			kind: r3.DefinitionIncompleteSource,
		},
		{
			name: "text after root",
			xml:  `<definitions xmlns="http://schemas.xmlsoap.org/wsdl/" xmlns:tns="urn:test" targetNamespace="urn:test"><message name="Request"/><portType name="Port"><operation name="Read"><input message="tns:Request"/></operation></portType><binding name="Binding" type="tns:Port"><operation name="Read"/></binding><service name="Service"><port name="Port" binding="tns:Binding"/></service></definitions>` + `not-xml`,
			kind: r3.DefinitionInvalidSource,
		},
		{
			name: "nested port type",
			xml:  `<definitions xmlns="http://schemas.xmlsoap.org/wsdl/" xmlns:tns="urn:test" targetNamespace="urn:test"><message name="Request"/><portType name="Outer"><portType name="Inner"><operation name="Read"><input message="tns:Request"/></operation></portType></portType><binding name="Binding" type="tns:Outer"><operation name="Read"/></binding><service name="Service"><port name="Port" binding="tns:Binding"/></service></definitions>`,
			kind: r3.DefinitionInvalidSource,
		},
		{
			name: "duplicate identity attribute",
			xml:  `<definitions xmlns="http://schemas.xmlsoap.org/wsdl/" xmlns:tns="urn:first" targetNamespace="urn:first" targetNamespace="urn:second"><message name="Request"/><portType name="Port"><operation name="Read"><input message="tns:Request"/></operation></portType><binding name="Binding" type="tns:Port"><operation name="Read"/></binding><service name="Service"><port name="Port" binding="tns:Binding"/></service></definitions>`,
			kind: r3.DefinitionInvalidSource,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := ParseDefinition(definitionEndpoint, NewXMLDocumentSource([]byte(test.xml)))
			if got := definitionErrorKind(err); got != test.kind {
				t.Fatalf("ParseDefinition() kind = %q, want %q; error: %v", got, test.kind, err)
			}
		})
	}
}

func TestParseDefinitionRefusesBrokenQNames(t *testing.T) {
	for _, document := range []string{
		`<definitions xmlns="http://schemas.xmlsoap.org/wsdl/" targetNamespace="urn:example:broken"><binding name="Binding" type="missing:PortType"/></definitions>`,
		`<definitions xmlns="http://schemas.xmlsoap.org/wsdl/" xmlns:tns="urn:example:broken" targetNamespace="urn:example:broken"><service name="Service"><port name="Port" binding="tns:MissingBinding"/></service></definitions>`,
		`<definitions xmlns="http://schemas.xmlsoap.org/wsdl/" xmlns:tns="urn:example:broken" targetNamespace="urn:example:broken"><portType name="PortType"><operation name="Read"><input message="tns:MissingMessage"/></operation></portType><binding name="Binding" type="tns:PortType"><operation name="Read"/></binding><service name="Service"><port name="Port" binding="tns:Binding"/></service></definitions>`,
	} {
		_, err := ParseDefinition(definitionEndpoint, NewXMLDocumentSource([]byte(document)))
		if got := definitionErrorKind(err); got != r3.DefinitionUnresolvedDependency {
			t.Fatalf("broken QName kind = %q, want %q; error: %v", got, r3.DefinitionUnresolvedDependency, err)
		}
	}
}

func TestParseDefinitionReturnsStableRefusalAcrossBrokenBindings(t *testing.T) {
	source := NewXMLDocumentSource([]byte(`<definitions xmlns="http://schemas.xmlsoap.org/wsdl/" xmlns:tns="urn:test" targetNamespace="urn:test"><binding name="Zulu" type="tns:MissingZulu"/><binding name="Alpha" type="tns:MissingAlpha"/></definitions>`))
	var first string
	for attempt := 0; attempt < 100; attempt++ {
		_, err := ParseDefinition(definitionEndpoint, source)
		if definitionErrorKind(err) != r3.DefinitionUnresolvedDependency {
			t.Fatalf("attempt %d refusal = %v", attempt, err)
		}
		if attempt == 0 {
			first = err.Error()
			continue
		}
		if err.Error() != first {
			t.Fatalf("attempt %d refusal = %q, want %q", attempt, err, first)
		}
	}
}

func definitionOperations(t *testing.T, snapshot r3.AuthoritativeSnapshot) []string {
	t.Helper()
	operations := snapshot.Operations().Operations()
	result := make([]string, len(operations))
	for index, operation := range operations {
		typed, err := FromR3(operation)
		if err != nil {
			t.Fatal(err)
		}
		service, present := typed.Service()
		if present {
			result[index] = service + "/" + typed.OperationName()
		} else {
			result[index] = typed.OperationName()
		}
	}
	return result
}

func definitionErrorKind(err error) r3.DefinitionErrorKind {
	var refusal *r3.DefinitionError
	if errors.As(err, &refusal) {
		return refusal.Kind
	}
	return ""
}
