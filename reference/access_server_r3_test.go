package reference

import (
	"encoding/json"
	"testing"

	aauth "gitlab.com/sidecat-dev/aauth-go"
)

func TestValidateR3AuthorizationDecisionRequiresExactDirectProposalGrant(t *testing.T) {
	t.Parallel()

	approved := aauth.R3OperationSet{
		Vocabulary: aauth.R3VocabularyMCP,
		Operations: []json.RawMessage{json.RawMessage(`{"tool":"send_message"}`)},
	}
	other := aauth.R3OperationSet{
		Vocabulary: aauth.R3VocabularyMCP,
		Operations: []json.RawMessage{json.RawMessage(`{"tool":"delete_message"}`)},
	}
	wrongVocabulary := aauth.R3OperationSet{
		Vocabulary: aauth.R3VocabularyOpenAPI,
		Operations: []json.RawMessage{json.RawMessage(`{"operationId":"sendMessage"}`)},
	}
	documentBytes, err := aauth.BuildR3Proposal(approved, aauth.R3Proposal{
		Parameters: map[string]aauth.R3CallParameter{
			"recipient": {Value: json.RawMessage(`"person@example.com"`)},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	document, err := aauth.ParseR3Document(documentBytes)
	if err != nil {
		t.Fatal(err)
	}
	authorization := &aauth.R3Authorization{
		URI:        "https://resource.example/r3/proposals/" + aauth.R3S256(documentBytes),
		S256:       aauth.R3S256(documentBytes),
		ExactBytes: documentBytes,
		Document:   document,
	}

	if err := validateR3AuthorizationDecision(aauth.AuthorizationDecision{
		R3Granted: &approved,
	}, authorization); err != nil {
		t.Fatalf("exact direct proposal grant was refused: %v", err)
	}

	empty := aauth.R3OperationSet{Vocabulary: aauth.R3VocabularyMCP, Operations: []json.RawMessage{}}
	for name, decision := range map[string]aauth.AuthorizationDecision{
		"missing direct grant": {},
		"empty direct grant":   {R3Granted: &empty},
		"recursive conditional": {
			R3Granted:     &empty,
			R3Conditional: &approved,
		},
		"different operation":  {R3Granted: &other},
		"different vocabulary": {R3Granted: &wrongVocabulary},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if err := validateR3AuthorizationDecision(decision, authorization); err == nil {
				t.Fatal("invalid proposal decision was accepted")
			}
		})
	}
}

func TestValidateR3AuthorizationDecisionAcceptsOnlyDisjointDocumentSubsets(t *testing.T) {
	t.Parallel()

	documentBytes := []byte(
		`{"vocabulary":"urn:aauth:vocabulary:mcp",` +
			`"operations":[{"tool":"read"},{"tool":"write"}]}`,
	)
	document, err := aauth.ParseR3Document(documentBytes)
	if err != nil {
		t.Fatal(err)
	}
	authorization := &aauth.R3Authorization{Document: document}
	read := aauth.R3OperationSet{
		Vocabulary: aauth.R3VocabularyMCP,
		Operations: []json.RawMessage{json.RawMessage(`{"tool":"read"}`)},
	}
	write := aauth.R3OperationSet{
		Vocabulary: aauth.R3VocabularyMCP,
		Operations: []json.RawMessage{json.RawMessage(`{"tool":"write"}`)},
	}
	if err := validateR3AuthorizationDecision(aauth.AuthorizationDecision{
		R3Granted:     &read,
		R3Conditional: &write,
	}, authorization); err != nil {
		t.Fatalf("disjoint document subsets were refused: %v", err)
	}
	if err := validateR3AuthorizationDecision(aauth.AuthorizationDecision{
		R3Granted:     &read,
		R3Conditional: &read,
	}, authorization); err == nil {
		t.Fatal("overlapping direct and conditional operation was accepted")
	}
	outside := aauth.R3OperationSet{
		Vocabulary: aauth.R3VocabularyMCP,
		Operations: []json.RawMessage{json.RawMessage(`{"tool":"delete"}`)},
	}
	if err := validateR3AuthorizationDecision(aauth.AuthorizationDecision{
		R3Granted:     &read,
		R3Conditional: &outside,
	}, authorization); err == nil {
		t.Fatal("conditional operation outside the verified document was accepted")
	}
}
