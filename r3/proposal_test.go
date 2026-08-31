package r3_test

import (
	"encoding/json"
	"strings"
	"testing"

	"aauth-go/r3"
)

func TestMCPProposalJSONRoundTripAndCopySafety(t *testing.T) {
	operation := mustOperation(t, "send_email")
	to, err := r3.NewInlineParameter([]byte(`"mom@example.com"`))
	if err != nil {
		t.Fatal(err)
	}
	bodyBytes := []byte("Hi Mom, are you free for dinner?")
	body, err := r3.NewDigestParameter(r3.Digest(bodyBytes), "Hi Mom, are you free…", "text/plain")
	if err != nil {
		t.Fatal(err)
	}
	parameters, err := r3.NewParameters(map[string]r3.Parameter{"to": to, "body": body})
	if err != nil {
		t.Fatal(err)
	}
	display := mustDisplay(t, "Send an email as you", "", "", "")
	proposalDisplay, err := r3.NewProposalDisplay(display, "## Action\nSend an email")
	if err != nil {
		t.Fatal(err)
	}
	account := "personal"
	proposal, err := r3.NewProposal(operation, parameters, r3.ProposalOptions{
		Account: &account,
		Display: &proposalDisplay,
	})
	if err != nil {
		t.Fatal(err)
	}

	exact, err := json.Marshal(proposal)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"send_email"}],"parameters":{"body":{"s256":"` + r3.Digest(bodyBytes) + `","excerpt":"Hi Mom, are you free…","media_type":"text/plain"},"to":"mom@example.com"},"account":"personal","display":{"summary":"Send an email as you","detail":"## Action\nSend an email"}}`
	if string(exact) != want {
		t.Fatalf("proposal JSON = %s, want %s", exact, want)
	}

	parsed, err := mcpRegistry.ParseProposal(exact)
	if err != nil {
		t.Fatal(err)
	}
	if mcpTool(t, parsed.Operation()) != "send_email" {
		t.Fatalf("operation = %q", mcpTool(t, parsed.Operation()))
	}
	if got, ok := parsed.Account(); !ok || got != account {
		t.Fatalf("account = %q, %t", got, ok)
	}
	if got, ok := parsed.Display(); !ok || got.Detail() != "## Action\nSend an email" || got.Summary() != "Send an email as you" {
		t.Fatalf("display = %#v, %t", got, ok)
	}
	parsedTo, ok := parsed.Parameters().Get("to")
	if !ok {
		t.Fatal("parsed proposal lost inline parameter")
	}
	inline, ok := parsedTo.InlineJSON()
	if !ok || string(inline) != `"mom@example.com"` {
		t.Fatalf("inline parameter = %s, %t", inline, ok)
	}
	inline[0] = 'x'
	again, _ := parsed.Parameters().Get("to")
	owned, _ := again.InlineJSON()
	if string(owned) != `"mom@example.com"` {
		t.Fatalf("returned bytes mutated proposal: %s", owned)
	}
	parsedBody, ok := parsed.Parameters().Get("body")
	if !ok {
		t.Fatal("parsed proposal lost digest parameter")
	}
	digest, ok := parsedBody.Digest()
	if !ok || digest.S256() != r3.Digest(bodyBytes) || digest.Excerpt() != "Hi Mom, are you free…" || digest.MediaType() != "text/plain" {
		t.Fatalf("digest parameter = %#v, %t", digest, ok)
	}
}

func TestMCPProposalParameterMatchingUsesStructuralJSONAndExactDigestBytes(t *testing.T) {
	inline, err := r3.NewInlineParameter([]byte(`{"count":1,"nested":{"a":true,"b":[1,2]}}`))
	if err != nil {
		t.Fatal(err)
	}
	for _, equivalent := range [][]byte{
		[]byte(` { "nested" : { "b" : [1.0, 2e0], "a" : true }, "count" : 1.00 } `),
		[]byte(`{"nested":{"a":true,"b":[1,2]},"count":1}`),
	} {
		presented, err := r3.NewPresentedInlineParameter(equivalent)
		if err != nil {
			t.Fatal(err)
		}
		one, _ := r3.NewParameters(map[string]r3.Parameter{"value": inline})
		matches, err := one.Matches(map[string]r3.PresentedParameter{"value": presented})
		if err != nil || !matches {
			t.Fatalf("structural match = %t, %v for %s", matches, err, equivalent)
		}
	}
	for _, different := range [][]byte{
		[]byte(`{"count":2,"nested":{"a":true,"b":[1,2]}}`),
		[]byte(`{"count":1,"nested":{"a":true,"b":[2,1]}}`),
	} {
		presented, err := r3.NewPresentedInlineParameter(different)
		if err != nil {
			t.Fatal(err)
		}
		one, _ := r3.NewParameters(map[string]r3.Parameter{"value": inline})
		matches, err := one.Matches(map[string]r3.PresentedParameter{"value": presented})
		if matches {
			t.Fatalf("different JSON matched: %s", different)
		}
	}
	if _, err := r3.NewPresentedInlineParameter([]byte(`{"count":1,"count":1}`)); err == nil {
		t.Fatal("matching accepted duplicate JSON object members")
	}

	exact := []byte{0, 1, 2, 3, 255}
	digested, err := r3.NewDigestParameterFromBytes(exact, "", "application/octet-stream")
	if err != nil {
		t.Fatal(err)
	}
	digestSet, _ := r3.NewParameters(map[string]r3.Parameter{"value": digested})
	if matches, err := digestSet.Matches(map[string]r3.PresentedParameter{"value": r3.NewPresentedDigestBytes(exact)}); err != nil || !matches {
		t.Fatalf("exact digest match = %t, %v", matches, err)
	}
	if matches, err := digestSet.Matches(map[string]r3.PresentedParameter{"value": r3.NewPresentedDigestBytes([]byte{0, 1, 2, 3})}); err != nil || matches {
		t.Fatalf("changed digest match = %t, %v", matches, err)
	}

	parameters, err := r3.NewParameters(map[string]r3.Parameter{"inline": inline, "binary": digested})
	if err != nil {
		t.Fatal(err)
	}
	presentedInline, _ := r3.NewPresentedInlineParameter([]byte(`{"nested":{"b":[1,2],"a":true},"count":1}`))
	presented := map[string]r3.PresentedParameter{
		"inline": presentedInline,
		"binary": r3.NewPresentedDigestBytes(exact),
	}
	if matches, err := parameters.Matches(presented); err != nil || !matches {
		t.Fatalf("parameter-set match = %t, %v", matches, err)
	}
	changedInline, _ := r3.NewPresentedInlineParameter([]byte(`{"count":2,"nested":{"a":true,"b":[1,2]}}`))
	extraInline, _ := r3.NewPresentedInlineParameter([]byte(`true`))
	for name, changed := range map[string]map[string]r3.PresentedParameter{
		"missing":           {"inline": presented["inline"]},
		"extra":             {"inline": presented["inline"], "binary": presented["binary"], "other": extraInline},
		"case-substitution": {"Inline": presented["inline"], "binary": presented["binary"]},
		"changed":           {"inline": changedInline, "binary": presented["binary"]},
		"wrong-kind":        {"inline": r3.NewPresentedDigestBytes([]byte(`{"nested":{"b":[1,2],"a":true},"count":1}`)), "binary": presented["binary"]},
	} {
		if matches, err := parameters.Matches(changed); err != nil || matches {
			t.Fatalf("%s parameter-set match = %t, %v", name, matches, err)
		}
	}
	empty, _ := r3.NewParameters(map[string]r3.Parameter{})
	if matches, err := empty.Matches(map[string]r3.PresentedParameter{}); err != nil || !matches {
		t.Fatalf("empty parameter-set match = %t, %v", matches, err)
	}
	if matches, err := empty.Matches(map[string]r3.PresentedParameter{"extra": extraInline}); err != nil || matches {
		t.Fatalf("nonempty presentation matched empty proposal = %t, %v", matches, err)
	}
}

func TestMCPProposalRejectsAmbiguousOrInvalidShapes(t *testing.T) {
	validDigest := r3.Digest([]byte("value"))
	tests := []struct {
		name string
		json string
	}{
		{"missing operations", `{"vocabulary":"urn:aauth:vocabulary:mcp","parameters":{}}`},
		{"multiple operations", `{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"a"},{"tool":"b"}],"parameters":{}}`},
		{"missing parameters", `{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"a"}]}`},
		{"non-object parameters", `{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"a"}],"parameters":[]}`},
		{"duplicate parameter", `{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"a"}],"parameters":{"x":1,"x":1}}`},
		{"nested duplicate parameter member", `{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"a"}],"parameters":{"x":{"a":1,"a":2}}}`},
		{"escaped duplicate parameter member", `{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"a"}],"parameters":{"x":1,"\u0078":2}}`},
		{"duplicate operation tool", `{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"a","tool":"b"}],"parameters":{}}`},
		{"duplicate digest s256", `{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"a"}],"parameters":{"x":{"s256":"` + validDigest + `","s256":"` + validDigest + `"}}}`},
		{"duplicate display detail", `{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"a"}],"parameters":{},"display":{"summary":"a","detail":"one","detail":"two"}}`},
		{"digest unknown member", `{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"a"}],"parameters":{"x":{"s256":"` + validDigest + `","other":true}}}`},
		{"digest invalid hash", `{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"a"}],"parameters":{"x":{"s256":"short"}}}`},
		{"digest non-string excerpt", `{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"a"}],"parameters":{"x":{"s256":"` + validDigest + `","excerpt":1}}}`},
		{"proposal unknown member", `{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"a"}],"parameters":{},"extra":true}`},
		{"proposal duplicate member", `{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"a"}],"parameters":{},"parameters":{}}`},
		{"document parser refuses proposal", `{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"a"}],"parameters":{}}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if test.name == "document parser refuses proposal" {
				if _, err := mcpRegistry.ParseDocument([]byte(test.json)); err == nil {
					t.Fatalf("document parser accepted proposal: %s", test.json)
				}
				return
			}
			if _, err := mcpRegistry.ParseProposal([]byte(test.json)); err == nil {
				t.Fatalf("accepted invalid proposal: %s", test.json)
			}
		})
	}

	operation := mustOperation(t, "a")
	var parameters r3.Parameters
	if _, err := r3.NewProposal(operation, parameters, r3.ProposalOptions{}); err == nil {
		t.Fatal("accepted zero parameters value")
	}
	if _, err := r3.NewInlineParameter([]byte(`{"x":1,"x":2}`)); err == nil {
		t.Fatal("accepted duplicate inline object members")
	}
	bounded, err := r3.NewInlineParameter([]byte(`1e1000000`))
	if err != nil {
		t.Fatalf("rejected large valid number: %v", err)
	}
	presentedBounded, _ := r3.NewPresentedInlineParameter([]byte(`10e999999`))
	boundedSet, _ := r3.NewParameters(map[string]r3.Parameter{"value": bounded})
	if matches, err := boundedSet.Matches(map[string]r3.PresentedParameter{"value": presentedBounded}); err != nil || !matches {
		t.Fatalf("large number reflexivity = %t, %v", matches, err)
	}
	for _, numeric := range []struct {
		approved  string
		presented string
		matches   bool
	}{
		{"9007199254740992", "9007199254740993", false},
		{"1.0000000000000000000000000001", "1", false},
		{"1e1000000", "1e999999", false},
		{"-0", "0e999999999999999999", true},
		{`"a"`, `"\u0061"`, true},
	} {
		approved, err := r3.NewInlineParameter([]byte(numeric.approved))
		if err != nil {
			t.Fatal(err)
		}
		actual, err := r3.NewPresentedInlineParameter([]byte(numeric.presented))
		if err != nil {
			t.Fatal(err)
		}
		set, _ := r3.NewParameters(map[string]r3.Parameter{"value": approved})
		matches, err := set.Matches(map[string]r3.PresentedParameter{"value": actual})
		if err != nil || matches != numeric.matches {
			t.Fatalf("numeric/string equality %s vs %s = %t, %v, want %t", numeric.approved, numeric.presented, matches, err, numeric.matches)
		}
	}
	if _, err := r3.NewDigestParameter(validDigest, strings.Repeat("x", 4097), "text/plain"); err != nil {
		t.Fatalf("source-valid long excerpt rejected: %v", err)
	}
	excerptOnly, err := mcpRegistry.ParseProposal([]byte(`{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"a"}],"parameters":{"x":{"excerpt":"ordinary application value"}}}`))
	if err != nil {
		t.Fatalf("ordinary inline object using excerpt was treated as a digest descriptor: %v", err)
	}
	parameter, ok := excerptOnly.Parameters().Get("x")
	if _, inline := parameter.InlineJSON(); !ok || !inline {
		t.Fatal("ordinary excerpt object did not remain inline")
	}
	for _, ordinary := range []string{
		`{"media_type":"ordinary"}`,
		`{"S256":"ordinary"}`,
		`{"nested":{"s256":"ordinary"}}`,
	} {
		inline, err := r3.NewInlineParameter([]byte(ordinary))
		if err != nil {
			t.Fatalf("ordinary object %s rejected: %v", ordinary, err)
		}
		if _, ok := inline.InlineJSON(); !ok {
			t.Fatalf("ordinary object %s did not remain inline", ordinary)
		}
	}
	if _, err := r3.NewInlineParameter([]byte(`{"s256":"ordinary","mode":"application"}`)); err == nil {
		t.Fatal("inline constructor accepted the reserved top-level s256 shape")
	}
	for _, name := range []string{"", " x "} {
		proposal, err := mcpRegistry.ParseProposal([]byte(`{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"a"}],"parameters":{` + string(mustJSON(t, name)) + `:1}}`))
		if err != nil {
			t.Fatalf("source-valid parameter name %q rejected: %v", name, err)
		}
		if _, ok := proposal.Parameters().Get(name); !ok {
			t.Fatalf("parameter name %q was not retained", name)
		}
	}
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}
