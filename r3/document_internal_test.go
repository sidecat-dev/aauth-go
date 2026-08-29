package r3

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestR3StandardVocabularyOperationShapes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		vocabulary string
		operation  string
	}{
		{"mcp", VocabularyMCP, `{"tool":"read_record"}`},
		{"openapi", VocabularyOpenAPI, `{"operationId":"readRecord"}`},
		{"grpc", VocabularyGRPC, `{"method":"records.RecordService/Read"}`},
		{"graphql", VocabularyGraphQL, `{"operation":"ReadRecord","type":"query"}`},
		{"asyncapi", VocabularyAsyncAPI, `{"operationId":"receiveRecord","action":"receive"}`},
		{"wsdl", VocabularyWSDL, `{"operation":"ReadRecord","service":"RecordService"}`},
		{"odata", VocabularyOData, `{"operation":"Records","methods":["GET"]}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			set := OperationSet{
				Vocabulary: test.vocabulary,
				Operations: []json.RawMessage{json.RawMessage(test.operation)},
			}
			if err := set.Validate(); err != nil {
				t.Fatal(err)
			}
		})
	}

	for index, set := range []OperationSet{
		{Vocabulary: "urn:aauth:vocabulary:openapi-gateway", Operations: []json.RawMessage{json.RawMessage(`{"service":"records","operationId":"read"}`)}},
		{Vocabulary: VocabularyMCP, Operations: []json.RawMessage{json.RawMessage(`{"operationId":"wrong"}`)}},
		{Vocabulary: VocabularyGRPC, Operations: []json.RawMessage{json.RawMessage(`{"method":"not-qualified"}`)}},
		{Vocabulary: VocabularyGraphQL, Operations: []json.RawMessage{json.RawMessage(`{"operation":"Read","type":"read"}`)}},
		{Vocabulary: VocabularyAsyncAPI, Operations: []json.RawMessage{json.RawMessage(`{"operationId":"event","action":"poll"}`)}},
		{Vocabulary: VocabularyOData, Operations: []json.RawMessage{json.RawMessage(`{"operation":"Records","methods":["get"]}`)}},
	} {
		if err := set.Validate(); err == nil {
			t.Fatalf("invalid standard operation %d was accepted", index)
		}
	}
}

func TestR3OperationSetUsesSemanticSetEquality(t *testing.T) {
	t.Parallel()

	left := OperationSet{
		Vocabulary: VocabularyOpenAPI,
		Operations: []json.RawMessage{
			json.RawMessage(`{"operationId":"readRecord"}`),
			json.RawMessage(`{"operationId":"writeRecord"}`),
		},
	}
	right := OperationSet{
		Vocabulary: VocabularyOpenAPI,
		Operations: []json.RawMessage{
			json.RawMessage(`{ "operationId": "writeRecord" }`),
			json.RawMessage(`{"operationId":"readRecord"}`),
		},
	}
	if !left.Equal(right) {
		t.Fatalf("semantically equal operation sets differ:\nleft: %#v\nright: %#v", left, right)
	}
	if !left.ContainsSet(OperationSet{
		Vocabulary: VocabularyOpenAPI,
		Operations: []json.RawMessage{json.RawMessage(`{"operationId":"readRecord"}`)},
	}) {
		t.Fatal("operation set does not contain its semantic subset")
	}
}

func TestR3DocumentRetainsExactIdentityAndCurrentNeutralShape(t *testing.T) {
	t.Parallel()

	compact := []byte(`{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"send_email"}],"account":"work-account","parameters":{"to":"person@example.com","body":{"s256":"abc","media_type":"text/plain"}},"display":{"summary":"Send email","detail":"## To\nperson@example.com"}}`)
	spaced := []byte(`{ "vocabulary": "urn:aauth:vocabulary:mcp", "operations": [{"tool":"send_email"}], "account": "work-account", "parameters": {"to":"person@example.com","body":{"s256":"abc","media_type":"text/plain"}}, "display": {"summary":"Send email","detail":"## To\nperson@example.com"} }`)
	compactDocument, err := ParseDocument(compact)
	if err != nil {
		t.Fatal(err)
	}
	spacedDocument, err := ParseDocument(spaced)
	if err != nil {
		t.Fatal(err)
	}
	if !compactDocument.OperationSet().Equal(spacedDocument.OperationSet()) {
		t.Fatal("equivalent R3 documents produced different operation sets")
	}
	if S256(compact) == S256(spaced) {
		t.Fatal("different exact R3 bytes produced the same test digest")
	}
	if len(S256(compact)) != 43 {
		t.Fatalf("R3 SHA-256 base64url length = %d, want 43", len(S256(compact)))
	}
	encoded, err := json.Marshal(compactDocument)
	if err != nil {
		t.Fatal(err)
	}
	for _, member := range []string{`"account":"work-account"`, `"parameters":`, `"detail":"## To\nperson@example.com"`} {
		if !strings.Contains(string(encoded), member) {
			t.Fatalf("parsed current R3 document does not retain %s: %s", member, encoded)
		}
	}
}

func TestParseR3DocumentRejectsRemovedAndMalformedMembers(t *testing.T) {
	t.Parallel()

	for name, exactBytes := range map[string][]byte{
		"removed version":  []byte(`{"version":"1","vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"read"}]}`),
		"unknown member":   []byte(`{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"read"}],"grant":true}`),
		"null parameters":  []byte(`{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"read"}],"parameters":null}`),
		"array parameters": []byte(`{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"read"}],"parameters":[]}`),
		"empty display":    []byte(`{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"read"}],"display":{}}`),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := ParseDocument(exactBytes); err == nil {
				t.Fatalf("invalid R3 document was accepted: %s", exactBytes)
			}
		})
	}
}

func TestR3DocumentRejectsDuplicateNamesAtEveryDepth(t *testing.T) {
	t.Parallel()

	for name, exactBytes := range map[string][]byte{
		"top-level vocabulary":    []byte(`{"vocabulary":"urn:aauth:vocabulary:mcp","vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"read"}]}`),
		"nested parameters":       []byte(`{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"read"}],"parameters":{"key":1,"key":2}}`),
		"case-variant vocabulary": []byte(`{"vocabulary":"urn:aauth:vocabulary:mcp","Vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"read"}]}`),
		"case-variant display":    []byte(`{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"read"}],"display":{"summary":"Read","SUMMARY":"Read"}}`),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := ParseDocument(exactBytes); err == nil ||
				(!strings.Contains(err.Error(), "duplicate object name") &&
					!strings.Contains(err.Error(), "case-ambiguous object names")) {
				t.Fatalf("duplicate-name error = %v", err)
			}
		})
	}
}
