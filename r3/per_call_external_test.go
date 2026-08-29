package r3_test

import (
	"encoding/json"
	"testing"

	"gitlab.com/sidecat-dev/aauth-go/r3"
)

func TestPerCallProposalMatchesInlineAndDigestParameters(t *testing.T) {
	body := []byte("private note bytes")
	exact := []byte(`{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"delete_record"}],"parameters":{"body":{"s256":"` + r3.S256(body) + `","excerpt":"private note","media_type":"Text/Plain; Charset=UTF-8"},"record":{"z":1,"a":2}},"display":{"summary":"Delete one record","detail":"## Action\nDelete record 7"}}`)

	proposal, err := r3.ParsePerCallProposal(exact)
	if err != nil {
		t.Fatal(err)
	}
	operation, err := proposal.Operation()
	if err != nil || !operation.Contains(json.RawMessage(`{"tool":"delete_record"}`)) {
		t.Fatalf("operation = %#v, %v", operation, err)
	}
	presented := r3.PresentedParameters{
		"body":   r3.PresentedBytes(body),
		"record": r3.PresentedJSON(json.RawMessage(`{"a":2,"z":1}`)),
	}
	if err := proposal.Match(presented); err != nil {
		t.Fatalf("matching parameters = %v", err)
	}

	body[0] = 'X'
	if err := proposal.Match(presented); err != nil {
		t.Fatalf("proposal or presented values were not copy-safe: %v", err)
	}
	changed := r3.PresentedParameters{
		"body":   r3.PresentedBytes([]byte("changed note bytes")),
		"record": r3.PresentedJSON(json.RawMessage(`{"a":2,"z":1}`)),
	}
	if err := proposal.Match(changed); err == nil {
		t.Fatal("changed digest parameter matched the approved proposal")
	}
	missing := r3.PresentedParameters{
		"record": r3.PresentedJSON(json.RawMessage(`{"a":2,"z":1}`)),
	}
	if err := proposal.Match(missing); err == nil {
		t.Fatal("missing parameter matched the approved proposal")
	}
}

func TestPerCallProposalRejectsAmbiguousParameterForms(t *testing.T) {
	for _, exact := range [][]byte{
		[]byte(`{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"delete_record"}],"display":{"summary":"Delete one record"}}`),
		[]byte(`{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"delete_record"},{"tool":"read_record"}],"parameters":{"record":"7"},"display":{"summary":"Two operations"}}`),
		[]byte(`{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"delete_record"}],"parameters":{"body":{"s256":"bad"}},"display":{"summary":"Delete one record"}}`),
		[]byte(`{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"delete_record"}],"parameters":{"body":{"s256":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","unknown":true}},"display":{"summary":"Delete one record"}}`),
		[]byte(`{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"delete_record"}],"parameters":{"body":{"s256":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","media_type":"not a media type"}},"display":{"summary":"Delete one record"}}`),
	} {
		if _, err := r3.ParsePerCallProposal(exact); err == nil {
			t.Fatalf("invalid proposal accepted: %s", exact)
		}
	}

	valid := []byte(`{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"delete_record"}],"parameters":{"record":"7"},"display":{"summary":"Delete one record"}}`)
	proposal, err := r3.ParsePerCallProposal(valid)
	if err != nil {
		t.Fatal(err)
	}
	if err := proposal.Match(r3.PresentedParameters{
		"record": r3.PresentedBytes([]byte(`"7"`)),
	}); err == nil {
		t.Fatal("byte presentation matched an inline JSON proposal parameter")
	}
}
