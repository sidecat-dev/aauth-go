package r3_test

import (
	"encoding/json"
	"strings"
	"testing"

	"aauth-go/r3"
)

func TestGrantedOperationsExactJSONRoundTripIncludingEmpty(t *testing.T) {
	tests := []struct {
		name       string
		granted    r3.GrantedOperations
		wantJSON   string
		wantLength int
	}{
		{
			name:       "empty",
			granted:    mustGranted(t),
			wantJSON:   `{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[]}`,
			wantLength: 0,
		},
		{
			name:       "nonempty",
			granted:    mustGranted(t, "read", "write"),
			wantJSON:   `{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"read"},{"tool":"write"}]}`,
			wantLength: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoded, err := json.Marshal(tt.granted)
			if err != nil {
				t.Fatalf("marshal granted operations: %v", err)
			}
			if string(encoded) != tt.wantJSON {
				t.Fatalf("encoded granted operations = %s, want %s", encoded, tt.wantJSON)
			}

			var parsed r3.GrantedOperations
			if err := json.Unmarshal(encoded, &parsed); err != nil {
				t.Fatalf("unmarshal granted operations: %v", err)
			}
			if !parsed.Equal(tt.granted) || len(parsed.Operations()) != tt.wantLength {
				t.Fatalf("round trip changed granted operations: %#v", parsed.Operations())
			}
		})
	}

	var zero r3.GrantedOperations
	if !zero.Equal(mustGranted(t)) {
		t.Fatal("zero GrantedOperations is not the valid empty claim value")
	}
}

func TestGrantedOperationsStrictParsingAndConstruction(t *testing.T) {
	invalidJSON := [][]byte{
		[]byte(`{}`),
		[]byte(`{"vocabulary":"urn:aauth:vocabulary:mcp"}`),
		[]byte(`{"operations":[]}`),
		[]byte(`{"vocabulary":"urn:aauth:vocabulary:openapi","operations":[]}`),
		[]byte(`{"vocabulary":"urn:aauth:vocabulary:mcp","operations":null}`),
		[]byte(`{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[],"extra":true}`),
		[]byte(`{"Vocabulary":"urn:aauth:vocabulary:mcp","operations":[]}`),
		[]byte(`{"vocabulary":"urn:aauth:vocabulary:mcp","vocabulary":"urn:aauth:vocabulary:mcp","operations":[]}`),
		[]byte(`{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"a"},{"tool":"a"}]}`),
		[]byte(`{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":""}]}`),
		[]byte(`{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"Tool":"a"}]}`),
		invalidUTF8JSON(`{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"`, `"}]}`),
	}
	for _, source := range invalidJSON {
		var granted r3.GrantedOperations
		if err := json.Unmarshal(source, &granted); err == nil {
			t.Errorf("accepted invalid granted operations JSON: %q", source)
		}
	}

	duplicate := mustOperation(t, "same")
	if _, err := r3.NewGrantedOperations(duplicate, duplicate); err == nil {
		t.Fatal("accepted duplicate constructed granted operations")
	}
	var invalidOperation r3.MCPOperation
	if _, err := r3.NewGrantedOperations(invalidOperation); err == nil {
		t.Fatal("accepted an invalid constructed granted operation")
	}
}

func TestGrantedOperationsSemanticHelpersAndCopySafety(t *testing.T) {
	ab := mustGranted(t, "a", "b")
	ba := mustGranted(t, "b", "a")
	a := mustGranted(t, "a")
	empty := mustGranted(t)

	if !ab.Equal(ba) {
		t.Fatal("order changed granted-operation equality")
	}
	if !a.IsSubsetOf(ab) || !empty.IsSubsetOf(ab) || !empty.IsSubsetOf(empty) {
		t.Fatal("valid granted-operation subset relation failed")
	}
	if ab.IsSubsetOf(a) || a.IsSubsetOf(empty) {
		t.Fatal("over-broad granted operations reported as a subset")
	}

	operations := []r3.MCPOperation{mustOperation(t, "retained")}
	granted, err := r3.NewGrantedOperations(operations...)
	if err != nil {
		t.Fatal(err)
	}
	operations[0] = mustOperation(t, "changed-input")
	returned := granted.Operations()
	returned[0] = mustOperation(t, "changed-output")
	if got := granted.Operations()[0].Tool(); got != "retained" {
		t.Fatalf("caller mutated granted operations: %q", got)
	}
}

func TestParseGrantAcceptsEmptyAndSubsetAndRejectsAdversarialInput(t *testing.T) {
	document, err := r3.NewDocument(mustSet(t, "read", "write"), r3.DocumentOptions{})
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name       string
		source     string
		wantLength int
	}{
		{
			name:       "empty",
			source:     `{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[]}`,
			wantLength: 0,
		},
		{
			name:       "subset",
			source:     `{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"write"}]}`,
			wantLength: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			grant, err := r3.ParseGrant([]byte(tt.source), document)
			if err != nil {
				t.Fatalf("parse grant: %v", err)
			}
			if len(grant.GrantedOperations().Operations()) != tt.wantLength {
				t.Fatalf("grant length = %d, want %d", len(grant.GrantedOperations().Operations()), tt.wantLength)
			}
			encoded, err := json.Marshal(grant)
			if err != nil {
				t.Fatalf("marshal valid grant: %v", err)
			}
			if string(encoded) != tt.source {
				t.Fatalf("grant JSON = %s, want %s", encoded, tt.source)
			}
		})
	}

	invalid := [][]byte{
		[]byte(`{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"delete"}]}`),
		[]byte(`{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"read"},{"tool":"read"}]}`),
		[]byte(`{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[],"extra":true}`),
		invalidUTF8JSON(`{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"`, `"}]}`),
	}
	for _, source := range invalid {
		if _, err := r3.ParseGrant(source, document); err == nil {
			t.Errorf("accepted invalid grant: %q", source)
		}
	}

	var invalidDocument r3.Document
	if _, err := r3.ParseGrant([]byte(`{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[]}`), invalidDocument); err == nil {
		t.Fatal("accepted grant against invalid document")
	}
}

func TestGrantUnmarshalAlwaysRequiresDocumentContext(t *testing.T) {
	source := []byte(`{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[]}`)
	var zero r3.Grant
	if err := json.Unmarshal(source, &zero); err == nil || !strings.Contains(err.Error(), "ParseGrant") {
		t.Fatalf("zero Grant unmarshal error = %v, want ParseGrant direction", err)
	}
	if _, err := json.Marshal(zero); err == nil {
		t.Fatal("zero unproven Grant marshaled successfully")
	}

	document, err := r3.NewDocument(mustSet(t, "read"), r3.DocumentOptions{})
	if err != nil {
		t.Fatal(err)
	}
	valid, err := r3.NewGrant(mustGranted(t, "read"), document)
	if err != nil {
		t.Fatal(err)
	}
	before := valid.GrantedOperations()
	if err := json.Unmarshal(source, &valid); err == nil || !strings.Contains(err.Error(), "ParseGrant") {
		t.Fatalf("valid Grant unmarshal error = %v, want ParseGrant direction", err)
	}
	if !valid.GrantedOperations().Equal(before) {
		t.Fatal("failed Grant unmarshal mutated a valid receiver")
	}
}

func TestReferenceRejectsContextFreeJSONForZeroAndPopulatedValues(t *testing.T) {
	digest := r3.Digest([]byte("document"))
	populated, err := r3.NewReference("https://resource.example/r3/document", digest)
	if err != nil {
		t.Fatal(err)
	}

	var zero r3.Reference
	for name, reference := range map[string]r3.Reference{"zero": zero, "populated": populated} {
		t.Run(name+" marshal", func(t *testing.T) {
			if _, err := json.Marshal(reference); err == nil {
				t.Fatal("context-free Reference marshal succeeded")
			}
		})
	}

	if err := json.Unmarshal([]byte(`{}`), &zero); err == nil {
		t.Fatal("zero Reference unmarshal succeeded")
	}
	beforeURI, beforeDigest := populated.URI(), populated.Digest()
	if err := json.Unmarshal([]byte(`{}`), &populated); err == nil {
		t.Fatal("populated Reference unmarshal succeeded")
	}
	if populated.URI() != beforeURI || populated.Digest() != beforeDigest {
		t.Fatal("failed Reference unmarshal mutated populated receiver")
	}
}

func TestParseReferencedDocumentBindsExactBytesBeforeParsing(t *testing.T) {
	exactBytes := []byte(`{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"read"}]}`)
	reference, err := r3.NewReference(
		"https://resource.example/r3/document?version=1",
		r3.Digest(exactBytes),
	)
	if err != nil {
		t.Fatal(err)
	}

	document, err := r3.ParseReferencedDocument(reference, exactBytes)
	if err != nil {
		t.Fatalf("parse referenced document: %v", err)
	}
	if got := document.OperationSet().Operations()[0].Tool(); got != "read" {
		t.Fatalf("parsed referenced tool = %q, want read", got)
	}

	if _, err := r3.ParseReferencedDocument(reference, append(exactBytes, ' ')); err == nil {
		t.Fatal("accepted referenced document bytes with a mismatched digest")
	}

	var invalidReference r3.Reference
	if _, err := r3.ParseReferencedDocument(invalidReference, exactBytes); err == nil || !strings.Contains(err.Error(), "reference") {
		t.Fatalf("invalid Reference error = %v, want reference validation failure", err)
	}

	invalidDocumentBytes := []byte(`{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[]}`)
	invalidDocumentReference, err := r3.NewReference(
		"https://resource.example/r3/invalid",
		r3.Digest(invalidDocumentBytes),
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r3.ParseReferencedDocument(invalidDocumentReference, invalidDocumentBytes); err == nil {
		t.Fatal("accepted digest-matching bytes that are not a valid R3 document")
	}
}

func TestConstructorsRejectInvalidUTF8(t *testing.T) {
	invalid := string([]byte{'x', 0xff})
	if _, err := r3.NewMCPOperation(invalid); err == nil {
		t.Fatal("MCP operation accepted invalid UTF-8")
	}

	displays := []struct {
		summary, implications, dataAccessed, irreversible string
	}{
		{invalid, "", "", ""},
		{"summary", invalid, "", ""},
		{"summary", "", invalid, ""},
		{"summary", "", "", invalid},
	}
	for _, display := range displays {
		if _, err := r3.NewDisplay(display.summary, display.implications, display.dataAccessed, display.irreversible); err == nil {
			t.Errorf("display accepted invalid UTF-8: %#v", display)
		}
	}

	account := invalid
	if _, err := r3.NewDocument(mustSet(t, "read"), r3.DocumentOptions{Account: &account}); err == nil {
		t.Fatal("document account accepted invalid UTF-8")
	}
	if _, err := r3.NewReference("https://resource.example/r3/"+invalid, r3.Digest([]byte("document"))); err == nil {
		t.Fatal("Reference URI accepted invalid UTF-8")
	}
}

func TestJSONDecodersRejectRawInvalidUTF8InStringValues(t *testing.T) {
	var operation r3.MCPOperation
	if err := json.Unmarshal(invalidUTF8JSON(`{"tool":"`, `"}`), &operation); err == nil {
		t.Fatal("MCP operation JSON accepted raw invalid UTF-8")
	}

	documents := [][]byte{
		invalidUTF8JSON(`{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"read"}],"account":"`, `"}`),
		invalidUTF8JSON(`{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"read"}],"display":{"summary":"`, `"}}`),
		invalidUTF8JSON(`{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"read"}],"display":{"summary":"summary","implications":"`, `"}}`),
		invalidUTF8JSON(`{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"read"}],"display":{"summary":"summary","data_accessed":"`, `"}}`),
		invalidUTF8JSON(`{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"read"}],"display":{"summary":"summary","irreversible":"`, `"}}`),
	}
	for _, source := range documents {
		if _, err := r3.ParseDocument(source); err == nil {
			t.Errorf("document accepted raw invalid UTF-8: %q", source)
		}
	}
}

func TestKnownToolsValidationRejectsMalformedAuthority(t *testing.T) {
	requested := mustSet(t, "known")
	invalidUTF8 := string([]byte{'x', 0xff})
	invalidAuthorities := [][]string{
		{"known", ""},
		{"known", " other"},
		{"known", "other "},
		{"known", "known"},
		{"known", invalidUTF8},
	}
	for _, knownTools := range invalidAuthorities {
		if err := requested.ValidateKnownTools(knownTools); err == nil {
			t.Errorf("accepted malformed authoritative tool list: %q", knownTools)
		}
	}

	if err := requested.ValidateKnownTools([]string{"known", "other"}); err != nil {
		t.Fatalf("rejected valid authoritative tool list: %v", err)
	}
}

func invalidUTF8JSON(prefix, suffix string) []byte {
	source := append([]byte(prefix), 0xff)
	return append(source, []byte(suffix)...)
}
