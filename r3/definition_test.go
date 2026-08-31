package r3

import (
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"

	aauth "gitlab.com/sidecat-dev/aauth-go"
)

type sortingNamedCodec struct{ namedCodec }

func (codec sortingNamedCodec) MarshalSet(set namedSet) ([]json.RawMessage, error) {
	owned := append(namedSet(nil), set...)
	slices.Sort(owned)
	return codec.namedCodec.MarshalSet(owned)
}

type caseFoldNamedCodec struct{ namedCodec }

func (caseFoldNamedCodec) Equal(left, right namedSet) bool {
	return len(left) == len(right) && caseFoldSubset(left, right)
}

func (caseFoldNamedCodec) Subset(left, right namedSet) bool {
	return caseFoldSubset(left, right)
}

func (caseFoldNamedCodec) Disjoint(left, right namedSet) bool {
	for _, candidate := range left {
		for _, other := range right {
			if strings.EqualFold(candidate, other) {
				return false
			}
		}
	}
	return true
}

func (caseFoldNamedCodec) Union(sets ...namedSet) (namedSet, error) {
	var result namedSet
	for _, set := range sets {
		for _, candidate := range set {
			if caseFoldSubset(namedSet{candidate}, result) {
				continue
			}
			result = append(result, candidate)
		}
	}
	return result, nil
}

func caseFoldSubset(left, right namedSet) bool {
	for _, candidate := range left {
		found := false
		for _, other := range right {
			if strings.EqualFold(candidate, other) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

const testSourceEncoding SourceEncoding = "application/vnd.example.widgets+json"

type atomicDefinitionCodec struct {
	vocabulary Vocabulary
	parse      func([]byte) (DefinitionMaterial, error)
	calls      *int
}

func (codec atomicDefinitionCodec) Vocabulary() Vocabulary { return codec.vocabulary }

func (codec atomicDefinitionCodec) ParseDefinition(source []byte) (DefinitionMaterial, error) {
	if codec.calls != nil {
		(*codec.calls)++
	}
	return codec.parse(source)
}

func TestDefinitionParserAtomicallyOwnsSourceOperationsAndHints(t *testing.T) {
	vocabulary := mustVocabularyForTest(t, namedCodec{uri: "https://example.test/r3/widgets"})
	mode := aauth.AccessModePersonToken
	hints, err := NewOperationHints(&mode, nil)
	if err != nil {
		t.Fatal(err)
	}
	readRaw := json.RawMessage(`{"name":"read"}`)
	writeRaw := json.RawMessage(`{"name":"write"}`)
	calls := 0
	parser, err := NewDefinitionParser(atomicDefinitionCodec{
		vocabulary: vocabulary,
		calls:      &calls,
		parse: func(source []byte) (DefinitionMaterial, error) {
			if string(source) != `{"operations":["read","write"]}` {
				return DefinitionMaterial{}, NewDefinitionError(DefinitionInvalidSource, "unexpected fixture", nil)
			}
			read, err := NewDefinedOperation(readRaw, &hints)
			if err != nil {
				return DefinitionMaterial{}, err
			}
			write, err := NewDefinedOperation(writeRaw, nil)
			if err != nil {
				return DefinitionMaterial{}, err
			}
			return NewDefinitionMaterial(testSourceEncoding, source, read, write)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	registry, err := NewDefinitionRegistry(parser.Registration())
	if err != nil {
		t.Fatal(err)
	}

	exact := []byte(`{"operations":["read","write"]}`)
	snapshot, err := parser.Parse("https://resource.example/definitions/widgets", exact)
	if err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("codec calls = %d, want one atomic parse", calls)
	}
	exact[0], readRaw[0], writeRaw[0] = '[', '[', '['
	mode = aauth.AccessModeAuthToken

	receipt := snapshot.Receipt()
	if receipt.Encoding() != testSourceEncoding || receipt.DiscoveryEndpoint() != "https://resource.example/definitions/widgets" {
		t.Fatalf("receipt = %#v", receipt)
	}
	wantSource := []byte(`{"operations":["read","write"]}`)
	if receipt.Digest() != Digest(wantSource) || receipt.ByteLength() != int64(len(wantSource)) {
		t.Fatalf("receipt digest/length = %q/%d", receipt.Digest(), receipt.ByteLength())
	}
	operations := snapshot.Operations()
	if len(operations.Operations()) != 2 {
		t.Fatalf("operation count = %d", len(operations.Operations()))
	}
	read := operations.Operations()[0]
	gotHints, present, err := snapshot.HintsFor(read)
	if err != nil || !present {
		t.Fatalf("read hints = %#v, %t, %v", gotHints, present, err)
	}
	gotMode, modePresent := gotHints.AccessMode()
	if !modePresent || gotMode != aauth.AccessModePersonToken {
		t.Fatalf("read access mode = %q, %t", gotMode, modePresent)
	}
	if err := snapshot.ValidateDefined(operations); err != nil {
		t.Fatalf("validate derived operations: %v", err)
	}
	if err := registry.Validate(snapshot); err != nil {
		t.Fatalf("validate snapshot registration: %v", err)
	}
}

func TestDefinitionSnapshotRefusesUnknownAndForeignOperations(t *testing.T) {
	localVocabulary := mustVocabularyForTest(t, namedCodec{uri: "https://example.test/r3/widgets"})
	foreignVocabulary := mustVocabularyForTest(t, namedCodec{uri: "https://example.test/r3/widgets"})
	parser := mustAtomicDefinitionParser(t, localVocabulary, `{"name":"read"}`)
	snapshot, err := parser.Parse("https://resource.example/widgets", []byte(`source`))
	if err != nil {
		t.Fatal(err)
	}
	unknown, err := NewOperation(localVocabulary, json.RawMessage(`{"name":"unknown"}`))
	if err != nil {
		t.Fatal(err)
	}
	unknownSet, err := NewOperationSet(unknown)
	if err != nil {
		t.Fatal(err)
	}
	var refusal *DefinitionError
	if err := snapshot.ValidateDefined(unknownSet); !errors.As(err, &refusal) || refusal.Kind != DefinitionOperationNotDefined {
		t.Fatalf("unknown refusal = %T %v", err, err)
	}
	if _, _, err := snapshot.HintsFor(unknown); err == nil {
		t.Fatal("snapshot served hints for an unknown operation")
	}
	foreign, err := NewOperation(foreignVocabulary, json.RawMessage(`{"name":"read"}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := snapshot.HintsFor(foreign); err == nil {
		t.Fatal("snapshot accepted another vocabulary registration")
	}
	foreignParser := mustAtomicDefinitionParser(t, foreignVocabulary, `{"name":"read"}`)
	foreignRegistry, err := NewDefinitionRegistry(foreignParser.Registration())
	if err != nil {
		t.Fatal(err)
	}
	if err := foreignRegistry.Validate(snapshot); err == nil {
		t.Fatal("foreign definition registry accepted the snapshot")
	}
}

func TestDefinitionHintsFollowOperationsAcrossCanonicalReordering(t *testing.T) {
	vocabulary, err := NewVocabulary[namedSet](sortingNamedCodec{namedCodec{uri: "https://example.test/r3/sorted"}})
	if err != nil {
		t.Fatal(err)
	}
	mode := aauth.AccessModePersonToken
	hints, err := NewOperationHints(&mode, nil)
	if err != nil {
		t.Fatal(err)
	}
	parser, err := NewDefinitionParser(atomicDefinitionCodec{
		vocabulary: vocabulary,
		parse: func(source []byte) (DefinitionMaterial, error) {
			z, err := NewDefinedOperation(json.RawMessage(`{"name":"z"}`), &hints)
			if err != nil {
				return DefinitionMaterial{}, err
			}
			a, err := NewDefinedOperation(json.RawMessage(`{"name":"a"}`), nil)
			if err != nil {
				return DefinitionMaterial{}, err
			}
			return NewDefinitionMaterial(testSourceEncoding, source, z, a)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := parser.Parse("https://resource.example/sorted", []byte(`source`))
	if err != nil {
		t.Fatal(err)
	}
	operations := snapshot.Operations().Operations()
	if string(operations[0].JSON()) != `{"name":"a"}` || string(operations[1].JSON()) != `{"name":"z"}` {
		t.Fatalf("canonical operations = %s, %s", operations[0].JSON(), operations[1].JSON())
	}
	got, present, err := snapshot.HintsFor(operations[1])
	if err != nil || !present {
		t.Fatalf("z hints = %#v, %t, %v", got, present, err)
	}
	gotMode, _ := got.AccessMode()
	if gotMode != mode {
		t.Fatalf("z access mode = %q", gotMode)
	}
	if _, present, err := snapshot.HintsFor(operations[0]); err != nil || present {
		t.Fatalf("a hints = %t, %v", present, err)
	}
}

func TestDefinitionHintsFollowSemanticallyEqualOperationEncoding(t *testing.T) {
	vocabulary, err := NewVocabulary[namedSet](caseFoldNamedCodec{namedCodec{uri: "https://example.test/r3/case-folded"}})
	if err != nil {
		t.Fatal(err)
	}
	mode := aauth.AccessModePersonToken
	hints, err := NewOperationHints(&mode, nil)
	if err != nil {
		t.Fatal(err)
	}
	parser, err := NewDefinitionParser(atomicDefinitionCodec{
		vocabulary: vocabulary,
		parse: func(source []byte) (DefinitionMaterial, error) {
			operation, err := NewDefinedOperation(json.RawMessage(`{"name":"read"}`), &hints)
			if err != nil {
				return DefinitionMaterial{}, err
			}
			return NewDefinitionMaterial(testSourceEncoding, source, operation)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := parser.Parse("https://resource.example/case-folded", []byte(`source`))
	if err != nil {
		t.Fatal(err)
	}
	alias, err := NewOperation(vocabulary, json.RawMessage(`{"name":"READ"}`))
	if err != nil {
		t.Fatal(err)
	}
	got, present, err := snapshot.HintsFor(alias)
	if err != nil || !present {
		t.Fatalf("alias hints = %#v, %t, %v", got, present, err)
	}
	gotMode, _ := got.AccessMode()
	if gotMode != mode {
		t.Fatalf("alias access mode = %q", gotMode)
	}

	unknown, err := NewOperation(vocabulary, json.RawMessage(`{"name":"write"}`))
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = snapshot.HintsFor(unknown)
	var refusal *DefinitionError
	if !errors.As(err, &refusal) || refusal.Kind != DefinitionOperationNotDefined {
		t.Fatalf("unknown hint refusal = %T %v", err, err)
	}
}

func TestDefinitionParserReturnsStableTypedRefusal(t *testing.T) {
	vocabulary := mustVocabularyForTest(t, namedCodec{uri: "https://example.test/r3/widgets"})
	cause := errors.New("missing registry")
	parser, err := NewDefinitionParser(atomicDefinitionCodec{
		vocabulary: vocabulary,
		parse: func([]byte) (DefinitionMaterial, error) {
			return DefinitionMaterial{}, NewDefinitionError(
				DefinitionIdentityUnavailable,
				"the source does not publish operation identities",
				cause,
			)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = parser.Parse("https://resource.example/widgets", []byte(`source`))
	var refusal *DefinitionError
	if !errors.As(err, &refusal) || refusal.Kind != DefinitionIdentityUnavailable || refusal.Vocabulary != vocabulary.URI() {
		t.Fatalf("refusal = %T %v", err, err)
	}
	if !errors.Is(err, cause) {
		t.Fatal("definition refusal lost its cause")
	}
}

func TestDefinitionParserRejectsNilCodec(t *testing.T) {
	var codec DefinitionCodec[[]byte]
	if _, err := NewDefinitionParser(codec); err == nil {
		t.Fatal("nil definition codec was accepted")
	}
}

func TestDefinitionMaterialRefusesEmptyOrUnownedEvidence(t *testing.T) {
	operation, err := NewDefinedOperation(json.RawMessage(`{"name":"read"}`), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name        string
		encoding    SourceEncoding
		digestInput []byte
		operations  []DefinedOperation
	}{
		{name: "missing encoding", digestInput: []byte(`source`), operations: []DefinedOperation{operation}},
		{name: "empty receipt input", encoding: testSourceEncoding, operations: []DefinedOperation{operation}},
		{name: "no operations", encoding: testSourceEncoding, digestInput: []byte(`source`)},
		{name: "uninitialized operation", encoding: testSourceEncoding, digestInput: []byte(`source`), operations: []DefinedOperation{{}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := NewDefinitionMaterial(test.encoding, test.digestInput, test.operations...); err == nil {
				t.Fatal("invalid definition material was accepted")
			}
		})
	}
}

func mustAtomicDefinitionParser(t *testing.T, vocabulary Vocabulary, raw string) DefinitionParser[[]byte] {
	t.Helper()
	parser, err := NewDefinitionParser(atomicDefinitionCodec{
		vocabulary: vocabulary,
		parse: func(source []byte) (DefinitionMaterial, error) {
			operation, err := NewDefinedOperation(json.RawMessage(raw), nil)
			if err != nil {
				return DefinitionMaterial{}, err
			}
			return NewDefinitionMaterial(testSourceEncoding, source, operation)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return parser
}

func mustVocabularyForTest(t *testing.T, codec namedCodec) Vocabulary {
	t.Helper()
	vocabulary, err := NewVocabulary[namedSet](codec)
	if err != nil {
		t.Fatal(err)
	}
	return vocabulary
}
