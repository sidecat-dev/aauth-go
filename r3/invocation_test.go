package r3

import (
	"encoding/json"
	"testing"
)

func TestInvocationRetainsAnOwnedOperationAndParameterView(t *testing.T) {
	vocabulary, err := NewVocabulary(namedCodec{uri: "https://example.test/vocabulary/invocation"})
	if err != nil {
		t.Fatal(err)
	}
	operation, err := NewOperation(vocabulary, json.RawMessage(`{"name":"send"}`))
	if err != nil {
		t.Fatal(err)
	}
	exact := []byte(`{"recipient":"person-1"}`)
	presented, err := NewPresentedInlineParameter(exact)
	if err != nil {
		t.Fatal(err)
	}
	parameters := map[string]PresentedParameter{"message": presented}

	invocation, err := NewInvocation(operation, parameters)
	if err != nil {
		t.Fatal(err)
	}
	exact[14] = '2'
	parameters["message"] = PresentedParameter{}

	if !operationsEqual(t, invocation.Operation(), operation) {
		t.Fatal("invocation changed its operation")
	}
	approved, err := NewInlineParameter([]byte(`{"recipient":"person-1"}`))
	if err != nil {
		t.Fatal(err)
	}
	approvedParameters, err := NewParameters(map[string]Parameter{"message": approved})
	if err != nil {
		t.Fatal(err)
	}
	if matches, err := approvedParameters.Matches(invocation.PresentedParameters()); err != nil || !matches {
		t.Fatalf("approved parameters match retained invocation = %v, %v", matches, err)
	}

	returned := invocation.PresentedParameters()
	returned["message"] = PresentedParameter{}
	if matches, err := approvedParameters.Matches(invocation.PresentedParameters()); err != nil || !matches {
		t.Fatalf("caller mutation changed retained invocation = %v, %v", matches, err)
	}
}

func TestInvocationRejectsInvalidInputs(t *testing.T) {
	vocabulary, err := NewVocabulary(namedCodec{uri: "https://example.test/vocabulary/invocation-invalid"})
	if err != nil {
		t.Fatal(err)
	}
	operation, err := NewOperation(vocabulary, json.RawMessage(`{"name":"send"}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewInvocation(Operation{}, nil); err == nil {
		t.Fatal("invocation accepted an uninitialized operation")
	}
	if _, err := NewInvocation(operation, map[string]PresentedParameter{"message": {}}); err == nil {
		t.Fatal("invocation accepted an uninitialized presented parameter")
	}
}

func TestPresentedParametersExposeOwnedTypedValues(t *testing.T) {
	inlineSource := []byte(`{"recipient":"person-1"}`)
	inline, err := NewPresentedInlineParameter(inlineSource)
	if err != nil {
		t.Fatal(err)
	}
	inlineJSON, ok := inline.InlineJSON()
	if !ok || string(inlineJSON) != string(inlineSource) {
		t.Fatalf("inline JSON = %s, %v", inlineJSON, ok)
	}
	inlineJSON[0] = '['
	again, ok := inline.InlineJSON()
	if !ok || string(again) != string(inlineSource) {
		t.Fatal("mutating returned inline JSON changed the parameter")
	}
	if _, ok := inline.ExactBytes(); ok {
		t.Fatal("inline parameter exposed a digest-backed byte value")
	}

	digestSource := []byte("exact request bytes")
	digest := NewPresentedDigestBytes(digestSource)
	exact, ok := digest.ExactBytes()
	if !ok || string(exact) != string(digestSource) {
		t.Fatalf("exact bytes = %q, %v", exact, ok)
	}
	exact[0] = 'X'
	againExact, ok := digest.ExactBytes()
	if !ok || string(againExact) != string(digestSource) {
		t.Fatal("mutating returned exact bytes changed the parameter")
	}
	if _, ok := digest.InlineJSON(); ok {
		t.Fatal("digest-backed parameter exposed inline JSON")
	}
}

func TestOpaqueOperationAndInvocationRefuseAccidentalWireEncoding(t *testing.T) {
	vocabulary, err := NewVocabulary(namedCodec{uri: "https://example.test/vocabulary/opaque"})
	if err != nil {
		t.Fatal(err)
	}
	operation, err := NewOperation(vocabulary, json.RawMessage(`{"name":"read"}`))
	if err != nil {
		t.Fatal(err)
	}
	invocation, err := NewInvocation(operation, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := json.Marshal(operation); err == nil {
		t.Fatal("opaque Operation silently encoded without its vocabulary envelope")
	}
	if err := json.Unmarshal([]byte(`{"name":"write"}`), &operation); err == nil {
		t.Fatal("opaque Operation accepted JSON without a vocabulary registration")
	}
	if _, err := json.Marshal(invocation); err == nil {
		t.Fatal("runtime Invocation silently encoded as a wire value")
	}
	if err := json.Unmarshal([]byte(`{}`), &invocation); err == nil {
		t.Fatal("runtime Invocation accepted a wire value")
	}
}

func TestAuthTokenOperationsClassifyRegisteredOperationsWithoutTransport(t *testing.T) {
	vocabulary, err := NewVocabulary(namedCodec{uri: "https://example.test/vocabulary/access"})
	if err != nil {
		t.Fatal(err)
	}
	read, err := NewOperation(vocabulary, json.RawMessage(`{"name":"read"}`))
	if err != nil {
		t.Fatal(err)
	}
	write, err := NewOperation(vocabulary, json.RawMessage(`{"name":"write"}`))
	if err != nil {
		t.Fatal(err)
	}
	remove, err := NewOperation(vocabulary, json.RawMessage(`{"name":"remove"}`))
	if err != nil {
		t.Fatal(err)
	}
	granted, err := NewGrantedOperations(vocabulary, read)
	if err != nil {
		t.Fatal(err)
	}
	perCall, err := NewGrantedOperations(vocabulary, write)
	if err != nil {
		t.Fatal(err)
	}
	operations := AuthTokenOperations{granted: granted, perCall: perCall, perCallPresent: true}

	for _, test := range []struct {
		name      string
		operation Operation
		want      OperationAccess
	}{
		{name: "direct", operation: read, want: OperationAccessGranted},
		{name: "per call", operation: write, want: OperationAccessPerCall},
		{name: "absent", operation: remove, want: OperationAccessDenied},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := operations.AccessFor(test.operation)
			if err != nil {
				t.Fatal(err)
			}
			if got != test.want {
				t.Fatalf("access = %v, want %v", got, test.want)
			}
		})
	}
}

func operationsEqual(t *testing.T, operation, other Operation) bool {
	t.Helper()
	equal, err := operation.Equal(other)
	if err != nil {
		t.Fatal(err)
	}
	return equal
}
