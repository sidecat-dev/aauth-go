package reference

import (
	"encoding/json"
	"testing"

	"gitlab.com/sidecat-dev/aauth-go/r3"
)

func TestR3DocumentSelectionIsExactlyTheAgentRequest(t *testing.T) {
	requested := r3.OperationSet{
		Vocabulary: r3.VocabularyMCP,
		Operations: []json.RawMessage{json.RawMessage(`{"tool":"read"}`)},
	}
	exact := []byte(`{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"read"}]}`)
	if reference, err := selectR3Document("https://resource.example", requested, exact); err != nil || !reference.Valid() {
		t.Fatalf("exact selection = %#v, %v", reference, err)
	}
	broader := []byte(`{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"read"},{"tool":"write"}]}`)
	if _, err := selectR3Document("https://resource.example", requested, broader); err == nil {
		t.Fatal("broader document escaped the agent request")
	}
}
