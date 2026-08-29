package r3_test

import (
	"encoding/json"
	"strings"
	"testing"

	"gitlab.com/sidecat-dev/aauth-go/r3"
)

func TestExactDocumentAndOperationModelIsPortable(t *testing.T) {
	compact := []byte(`{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"send_email"}],"account":"work-account","parameters":{"to":"person@example.com"},"display":{"summary":"Send email"}}`)
	spaced := []byte(`{ "vocabulary": "urn:aauth:vocabulary:mcp", "operations": [{"tool":"send_email"}], "account": "work-account", "parameters": {"to":"person@example.com"}, "display": {"summary":"Send email"} }`)

	compactDocument, err := r3.ParseDocument(compact)
	if err != nil {
		t.Fatal(err)
	}
	spacedDocument, err := r3.ParseDocument(spaced)
	if err != nil {
		t.Fatal(err)
	}
	if !compactDocument.OperationSet().Equal(spacedDocument.OperationSet()) {
		t.Fatal("equivalent operation sets differ")
	}
	if r3.S256(compact) == r3.S256(spaced) || len(r3.S256(compact)) != 43 {
		t.Fatal("exact document identity was normalized")
	}

	cloned := compactDocument.OperationSet().Clone()
	cloned.Operations[0][0] = 'x'
	if !compactDocument.OperationSet().Contains(json.RawMessage(`{"tool":"send_email"}`)) {
		t.Fatal("operation-set clone aliases the parsed document")
	}
	encoded, err := json.Marshal(compactDocument)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(encoded), `"account":"work-account"`) {
		t.Fatalf("document projection = %s", encoded)
	}
}

func TestStandardAndThirdPartyVocabulariesAreExplicit(t *testing.T) {
	standards := map[string]json.RawMessage{
		r3.VocabularyMCP:      json.RawMessage(`{"tool":"read"}`),
		r3.VocabularyOpenAPI:  json.RawMessage(`{"operationId":"read"}`),
		r3.VocabularyGRPC:     json.RawMessage(`{"method":"records.Service/Read"}`),
		r3.VocabularyGraphQL:  json.RawMessage(`{"operation":"Read","type":"query"}`),
		r3.VocabularyAsyncAPI: json.RawMessage(`{"operationId":"receive","action":"receive"}`),
		r3.VocabularyWSDL:     json.RawMessage(`{"operation":"Read"}`),
		r3.VocabularyOData:    json.RawMessage(`{"operation":"Records","methods":["GET"]}`),
	}
	for vocabulary, operation := range standards {
		if err := (r3.OperationSet{Vocabulary: vocabulary, Operations: []json.RawMessage{operation}}).Validate(); err != nil {
			t.Fatalf("%s: %v", vocabulary, err)
		}
	}
	if err := (r3.OperationSet{
		Vocabulary: "https://example.com/vocabularies/tasks",
		Operations: []json.RawMessage{json.RawMessage(`{"task":"read"}`)},
	}).Validate(); err != nil {
		t.Fatal(err)
	}
	if err := r3.ValidateVocabularyURI("urn:aauth:vocabulary:future"); err == nil {
		t.Fatal("unknown AAuth vocabulary was accepted")
	}
}
