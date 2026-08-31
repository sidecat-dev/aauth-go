package r3

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"
)

type namedSet []string

type namedCodec struct {
	uri VocabularyURI
}

func (c namedCodec) URI() VocabularyURI { return c.uri }

func (namedCodec) AnnotationEncoding() AnnotationEncoding { return AnnotationUnavailable }

func (namedCodec) ValidateDiscoveryEndpoint(string) error { return nil }

func (c namedCodec) ParseSet(raw []json.RawMessage) (namedSet, error) {
	set := make(namedSet, 0, len(raw))
	seen := make(map[string]struct{}, len(raw))
	for _, value := range raw {
		var operation struct {
			Name string `json:"name"`
		}
		if err := json.Unmarshal(value, &operation); err != nil || operation.Name == "" {
			return nil, fmt.Errorf("invalid named operation")
		}
		if _, duplicate := seen[operation.Name]; duplicate {
			return nil, fmt.Errorf("duplicate named operation %q", operation.Name)
		}
		seen[operation.Name] = struct{}{}
		set = append(set, operation.Name)
	}
	return set, nil
}

func TestVocabularyEnforcesCardinalityBeforeCodecDispatch(t *testing.T) {
	parseCalls := 0
	vocabulary, err := NewVocabulary(untrustedCodec{
		uri:        "https://example.test/vocabulary/cardinality-before",
		parseCalls: &parseCalls,
	})
	if err != nil {
		t.Fatal(err)
	}
	one := []json.RawMessage{json.RawMessage(`{"name":"one"}`)}
	two := append(append([]json.RawMessage(nil), one...), json.RawMessage(`{"name":"two"}`))
	for _, test := range []struct {
		name string
		use  setUse
		raw  []json.RawMessage
	}{
		{name: "empty request", use: setUseRequest},
		{name: "empty document", use: setUseDocument},
		{name: "empty proposal", use: setUseProposal},
		{name: "multi-operation proposal", use: setUseProposal, raw: two},
	} {
		t.Run(test.name, func(t *testing.T) {
			parseCalls = 0
			if _, err := newOperationValue(vocabulary, test.raw, test.use); err == nil {
				t.Fatal("invalid cardinality reached the codec and was accepted")
			}
			if parseCalls != 0 {
				t.Fatalf("codec parse calls = %d, want 0", parseCalls)
			}
		})
	}

	parseCalls = 0
	if _, err := newOperationValue(vocabulary, nil, setUseGrant); err != nil {
		t.Fatalf("empty grant was refused: %v", err)
	}
	if parseCalls != 2 {
		t.Fatalf("valid empty grant parse calls = %d, want initial and canonical parse", parseCalls)
	}
}

func TestVocabularyEnforcesCardinalityAfterCanonicalMarshal(t *testing.T) {
	parseCalls := 0
	vocabulary, err := NewVocabulary(untrustedCodec{
		uri:           "https://example.test/vocabulary/cardinality-after",
		parseCalls:    &parseCalls,
		expandMarshal: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewOperation(vocabulary, json.RawMessage(`{"name":"one"}`)); err == nil {
		t.Fatal("codec expanded a proposal during canonical marshal")
	}
	if parseCalls != 1 {
		t.Fatalf("codec parse calls = %d, want no dispatch after invalid canonical cardinality", parseCalls)
	}
}

func TestVocabularyRejectsCodecThatDropsOperationsDuringNormalization(t *testing.T) {
	vocabulary, err := NewVocabulary(untrustedCodec{
		uri:         "https://example.test/vocabulary/lossy",
		dropOnParse: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	raw := []json.RawMessage{
		json.RawMessage(`{"name":"one"}`),
		json.RawMessage(`{"name":"two"}`),
	}
	for _, use := range []setUse{setUseRequest, setUseGrant} {
		if _, err := newOperationValue(vocabulary, raw, use); err == nil {
			t.Fatalf("lossy codec dropped a %v operation", use)
		}
	}
}

func TestVocabularyRejectsCodecThatChangesOperationsDuringNormalization(t *testing.T) {
	vocabulary, err := NewVocabulary(untrustedCodec{
		uri:            "https://example.test/vocabulary/substituting",
		rewriteMarshal: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewOperation(vocabulary, json.RawMessage(`{"name":"one"}`)); err == nil {
		t.Fatal("codec substituted an operation during normalization")
	}
}

func (namedCodec) MarshalSet(set namedSet) ([]json.RawMessage, error) {
	result := make([]json.RawMessage, len(set))
	for index, name := range set {
		encoded, err := json.Marshal(struct {
			Name string `json:"name"`
		}{Name: name})
		if err != nil {
			return nil, err
		}
		result[index] = encoded
	}
	return result, nil
}

func (namedCodec) Union(sets ...namedSet) (namedSet, error) {
	var union namedSet
	seen := make(map[string]struct{})
	for _, set := range sets {
		for _, name := range set {
			if _, ok := seen[name]; ok {
				continue
			}
			seen[name] = struct{}{}
			union = append(union, name)
		}
	}
	return union, nil
}

func (namedCodec) Equal(left, right namedSet) bool {
	return len(left) == len(right) && subsetNames(left, right)
}

func (namedCodec) Subset(subset, superset namedSet) bool {
	return subsetNames(subset, superset)
}

func (namedCodec) Disjoint(left, right namedSet) bool {
	return !slices.ContainsFunc(left, func(name string) bool { return slices.Contains(right, name) })
}

func subsetNames(subset, superset namedSet) bool {
	for _, name := range subset {
		if !slices.Contains(superset, name) {
			return false
		}
	}
	return true
}

type customDiscoveryCodec struct {
	namedCodec
	seen *string
}

type customAnnotationCodec struct {
	namedCodec
	encoding AnnotationEncoding
}

func (codec customAnnotationCodec) AnnotationEncoding() AnnotationEncoding { return codec.encoding }

func TestVocabularyAcceptsANamespacedThirdPartyAnnotationEncoding(t *testing.T) {
	const encoding AnnotationEncoding = "https://example.test/r3/annotation-encoding"
	vocabulary, err := NewVocabulary(customAnnotationCodec{
		namedCodec: namedCodec{uri: "https://example.test/vocabulary/custom-annotation"},
		encoding:   encoding,
	})
	if err != nil {
		t.Fatal(err)
	}
	if vocabulary.AnnotationEncoding() != encoding {
		t.Fatalf("annotation encoding = %q", vocabulary.AnnotationEncoding())
	}
	if _, err := NewVocabulary(customAnnotationCodec{
		namedCodec: namedCodec{uri: "https://example.test/vocabulary/invalid-annotation"},
		encoding:   AnnotationEncoding("private words"),
	}); err == nil {
		t.Fatal("vocabulary accepted an unnamespaced third-party annotation encoding")
	}
}

func (codec customDiscoveryCodec) ValidateDiscoveryEndpoint(endpoint string) error {
	if codec.seen != nil {
		*codec.seen = endpoint
	}
	if !strings.HasPrefix(endpoint, "custom+unix:///") {
		return fmt.Errorf("custom discovery endpoint must use custom+unix")
	}
	return nil
}

func TestVocabularyDelegatesDiscoveryEndpointValidationToCodec(t *testing.T) {
	t.Parallel()

	var seen string
	vocabulary, err := NewVocabulary(customDiscoveryCodec{
		namedCodec: namedCodec{uri: "https://example.test/vocabulary/custom-discovery"},
		seen:       &seen,
	})
	if err != nil {
		t.Fatal(err)
	}
	const endpoint = "custom+unix:///run/example.sock?definition=current"
	if err := vocabulary.ValidateDiscoveryEndpoint(endpoint); err != nil {
		t.Fatalf("custom discovery endpoint was refused: %v", err)
	}
	if seen != endpoint {
		t.Fatalf("codec saw endpoint %q, want %q", seen, endpoint)
	}
	if err := vocabulary.ValidateDiscoveryEndpoint("https://resource.example/openapi.json"); err == nil {
		t.Fatal("custom codec accepted an endpoint outside its own grammar")
	}
}

func TestVocabularyRegistryDrivesWholeSetAlgebra(t *testing.T) {
	vocabulary, err := NewVocabulary(namedCodec{uri: "https://example.test/vocabulary/named"})
	if err != nil {
		t.Fatal(err)
	}
	registry, err := NewRegistry(vocabulary)
	if err != nil {
		t.Fatal(err)
	}

	all, err := registry.ParseOperationSet([]byte(`{
		"vocabulary":"https://example.test/vocabulary/named",
		"operations":[{"name":"read"},{"name":"write"}]
	}`))
	if err != nil {
		t.Fatal(err)
	}
	read, err := NewOperation(vocabulary, json.RawMessage(`{"name":"read"}`))
	if err != nil {
		t.Fatal(err)
	}
	readSet, err := NewOperationSet(read)
	if err != nil {
		t.Fatal(err)
	}

	subset, err := readSet.IsSubsetOf(all)
	if err != nil || !subset {
		t.Fatalf("read subset of all = %v, %v", subset, err)
	}
	disjoint, err := readSet.Disjoint(all)
	if err != nil || disjoint {
		t.Fatalf("read disjoint from all = %v, %v", disjoint, err)
	}
	union, err := readSet.Union(all)
	if err != nil {
		t.Fatal(err)
	}
	equal, err := union.Equal(all)
	if err != nil || !equal {
		t.Fatalf("union equals all = %v, %v", equal, err)
	}

	encoded, err := json.Marshal(all)
	if err != nil {
		t.Fatal(err)
	}
	if string(encoded) != `{"vocabulary":"https://example.test/vocabulary/named","operations":[{"name":"read"},{"name":"write"}]}` {
		t.Fatalf("operation set JSON = %s", encoded)
	}
}

func TestVocabularyRegistryFailsClosed(t *testing.T) {
	first, err := NewVocabulary(namedCodec{uri: "https://example.test/vocabulary/named"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewRegistry(first, first); err == nil {
		t.Fatal("registry accepted a duplicate vocabulary URI")
	}
	registry, err := NewRegistry(first)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := registry.ParseOperationSet([]byte(`{"vocabulary":"https://example.test/vocabulary/unknown","operations":[{"name":"read"}]}`)); err == nil {
		t.Fatal("registry accepted an unknown vocabulary")
	}

	second, err := NewVocabulary(namedCodec{uri: first.URI()})
	if err != nil {
		t.Fatal(err)
	}
	left, err := NewOperation(first, json.RawMessage(`{"name":"read"}`))
	if err != nil {
		t.Fatal(err)
	}
	right, err := NewOperation(second, json.RawMessage(`{"name":"read"}`))
	if err != nil {
		t.Fatal(err)
	}
	leftSet, err := NewOperationSet(left)
	if err != nil {
		t.Fatal(err)
	}
	rightSet, err := NewOperationSet(right)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := leftSet.Equal(rightSet); err == nil {
		t.Fatal("set algebra crossed distinct registrations of one URI")
	}
	if err := registry.ValidateOperationSet(leftSet); err != nil {
		t.Fatalf("registry refused its own operation set: %v", err)
	}
	if err := registry.ValidateOperationSet(rightSet); err == nil {
		t.Fatal("registry accepted an operation set from a different same-URI registration")
	}
}

func TestZeroValueOperationSetUnionReturnsAnError(t *testing.T) {
	if _, err := (OperationSet{}).Union(); err == nil {
		t.Fatal("zero-value OperationSet union succeeded")
	}
}

func TestContextBoundOperationEnvelopesRefuseContextFreeUnmarshal(t *testing.T) {
	vocabulary, err := NewVocabulary(namedCodec{uri: "https://example.test/vocabulary/unmarshal"})
	if err != nil {
		t.Fatal(err)
	}
	operation, err := NewOperation(vocabulary, json.RawMessage(`{"name":"read"}`))
	if err != nil {
		t.Fatal(err)
	}
	operationSet, err := NewOperationSet(operation)
	if err != nil {
		t.Fatal(err)
	}
	granted, err := NewGrantedOperations(vocabulary, operation)
	if err != nil {
		t.Fatal(err)
	}
	encoded := []byte(`{"vocabulary":"https://example.test/vocabulary/unmarshal","operations":[{"name":"write"}]}`)

	setBefore, _ := json.Marshal(operationSet)
	if err := json.Unmarshal(encoded, &operationSet); err == nil {
		t.Fatal("OperationSet accepted context-free JSON unmarshal")
	}
	setAfter, _ := json.Marshal(operationSet)
	if string(setAfter) != string(setBefore) {
		t.Fatal("failed OperationSet unmarshal changed the receiver")
	}

	grantBefore, _ := json.Marshal(granted)
	if err := json.Unmarshal(encoded, &granted); err == nil {
		t.Fatal("GrantedOperations accepted context-free JSON unmarshal")
	}
	grantAfter, _ := json.Marshal(granted)
	if string(grantAfter) != string(grantBefore) {
		t.Fatal("failed GrantedOperations unmarshal changed the receiver")
	}
}

type untrustedCodec struct {
	uri            VocabularyURI
	parseCalls     *int
	dropOnParse    bool
	expandMarshal  bool
	rewriteMarshal bool
}

func (codec untrustedCodec) URI() VocabularyURI { return codec.uri }

func (untrustedCodec) AnnotationEncoding() AnnotationEncoding { return AnnotationUnavailable }

func (untrustedCodec) ValidateDiscoveryEndpoint(string) error { return nil }

func (codec untrustedCodec) ParseSet(raw []json.RawMessage) (namedSet, error) {
	if codec.parseCalls != nil {
		*codec.parseCalls++
	}
	set, err := parseNamedSet(raw)
	if err != nil {
		return nil, err
	}
	if codec.dropOnParse && len(set) > 0 {
		set = set[:len(set)-1]
	}
	return set, nil
}

func (codec untrustedCodec) MarshalSet(set namedSet) ([]json.RawMessage, error) {
	set = append(namedSet(nil), set...)
	if codec.rewriteMarshal && len(set) > 0 {
		set[0] = "substituted"
	}
	if codec.expandMarshal {
		set = append(set, "injected")
	}
	return namedCodec{}.MarshalSet(set)
}

func (untrustedCodec) Union(sets ...namedSet) (namedSet, error) {
	return namedCodec{}.Union(sets...)
}

func (untrustedCodec) Equal(left, right namedSet) bool { return namedCodec{}.Equal(left, right) }

func (untrustedCodec) Subset(left, right namedSet) bool { return namedCodec{}.Subset(left, right) }

func (untrustedCodec) Disjoint(left, right namedSet) bool { return namedCodec{}.Disjoint(left, right) }

func parseNamedSet(raw []json.RawMessage) (namedSet, error) {
	set := make(namedSet, 0, len(raw))
	seen := make(map[string]struct{}, len(raw))
	for _, value := range raw {
		var operation struct {
			Name string `json:"name"`
		}
		if err := json.Unmarshal(value, &operation); err != nil || operation.Name == "" {
			return nil, fmt.Errorf("invalid named operation")
		}
		if _, duplicate := seen[operation.Name]; duplicate {
			return nil, fmt.Errorf("duplicate named operation %q", operation.Name)
		}
		seen[operation.Name] = struct{}{}
		set = append(set, operation.Name)
	}
	return set, nil
}
