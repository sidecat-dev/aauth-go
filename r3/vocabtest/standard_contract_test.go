package vocabtest_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"

	"gitlab.com/sidecat-dev/aauth-go/r3"
	"gitlab.com/sidecat-dev/aauth-go/r3/vocab/asyncapi"
	"gitlab.com/sidecat-dev/aauth-go/r3/vocab/graphql"
	grpcvocab "gitlab.com/sidecat-dev/aauth-go/r3/vocab/grpc"
	"gitlab.com/sidecat-dev/aauth-go/r3/vocab/mcp"
	"gitlab.com/sidecat-dev/aauth-go/r3/vocab/odata"
	"gitlab.com/sidecat-dev/aauth-go/r3/vocab/openapi"
	"gitlab.com/sidecat-dev/aauth-go/r3/vocab/wsdl"
	"gitlab.com/sidecat-dev/aauth-go/r3/vocabtest"
)

type standardVocabulary struct {
	name            string
	uri             r3.VocabularyURI
	vocabulary      func() r3.Vocabulary
	operationA      string
	operationB      string
	unknownMember   string
	duplicateMember string
	roundTrip       func(*testing.T, r3.Operation)
	fromR3          func(r3.Operation) error
}

func TestStandardVocabularyContracts(t *testing.T) {
	t.Parallel()

	standards := standardVocabularies()
	registry := standardRegistry(t, standards)
	for _, standard := range standards {
		standard := standard
		t.Run(standard.name, func(t *testing.T) {
			t.Parallel()

			vocabtest.Run(t, vocabtest.Contract{
				Vocabulary:          standard.vocabulary(),
				Registry:            registry,
				ForeignRegistration: registerFresh(t, foreignCodec{uri: standard.uri}),
				OperationA:          json.RawMessage(standard.operationA),
				OperationB:          json.RawMessage(standard.operationB),
				InvalidOperations: []json.RawMessage{
					json.RawMessage(standard.unknownMember),
				},
				DuplicateOperations: []json.RawMessage{
					json.RawMessage(standard.duplicateMember),
				},
				ValidDiscoveryEndpoint: "https://resource.example/definition?version=current",
				InvalidDiscoveryEndpoints: []string{
					"http://resource.example/definition",
					"https://user@resource.example/definition",
					"https://resource.example/definition#fragment",
				},
			})
		})
	}
}

func TestStandardVocabularyTypedRoundTrips(t *testing.T) {
	t.Parallel()

	standards := standardVocabularies()
	registry := standardRegistry(t, standards)
	for _, standard := range standards {
		standard := standard
		t.Run(standard.name, func(t *testing.T) {
			t.Parallel()

			exact := operationEnvelope(standard.uri, standard.operationA)
			set, err := registry.ParseOperationSet(exact)
			if err != nil {
				t.Fatal(err)
			}
			if set.Vocabulary() != standard.uri {
				t.Fatalf("parsed vocabulary = %q, want %q", set.Vocabulary(), standard.uri)
			}
			operations := set.Operations()
			if len(operations) != 1 {
				t.Fatalf("parsed operations = %d, want 1", len(operations))
			}
			if got := operations[0].JSON(); !bytes.Equal(got, []byte(standard.operationA)) {
				t.Fatalf("canonical operation = %s, want %s", got, standard.operationA)
			}
			encoded, err := json.Marshal(set)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(encoded, exact) {
				t.Fatalf("operation-set round trip = %s, want exact %s", encoded, exact)
			}
			standard.roundTrip(t, operations[0])
		})
	}
}

func TestStandardVocabularyAnnotationCapabilities(t *testing.T) {
	t.Parallel()

	for _, encoding := range []r3.AnnotationEncoding{
		r3.AnnotationMCPMeta,
		r3.AnnotationSpecificationExtension,
		r3.AnnotationODataMetadata,
	} {
		if encoding == r3.AnnotationUnavailable {
			t.Fatalf("supported annotation encoding %q is indistinguishable from unavailable", encoding)
		}
	}

	for _, test := range []struct {
		name       string
		vocabulary func() r3.Vocabulary
		want       r3.AnnotationEncoding
	}{
		{name: "mcp", vocabulary: mcp.Vocabulary, want: r3.AnnotationMCPMeta},
		{name: "openapi", vocabulary: openapi.Vocabulary, want: r3.AnnotationSpecificationExtension},
		{name: "grpc", vocabulary: grpcvocab.Vocabulary, want: r3.AnnotationUnavailable},
		{name: "graphql", vocabulary: graphql.Vocabulary, want: r3.AnnotationUnavailable},
		{name: "asyncapi", vocabulary: asyncapi.Vocabulary, want: r3.AnnotationSpecificationExtension},
		{name: "wsdl", vocabulary: wsdl.Vocabulary, want: r3.AnnotationUnavailable},
		{name: "odata", vocabulary: odata.Vocabulary, want: r3.AnnotationODataMetadata},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			if got := test.vocabulary().AnnotationEncoding(); got != test.want {
				t.Fatalf("AnnotationEncoding() = %q, want %q", got, test.want)
			}
		})
	}
}

func TestStandardTypedConversionsRefuseForeignRegistrations(t *testing.T) {
	t.Parallel()

	for _, standard := range standardVocabularies() {
		standard := standard
		t.Run(standard.name, func(t *testing.T) {
			t.Parallel()

			fresh := registerFresh(t, foreignCodec{uri: standard.uri})
			freshRegistry := mustRegistry(t, fresh)
			freshSet := parseOperationSet(t, freshRegistry, standard.uri, standard.operationA)
			freshOperation := freshSet.Operations()[0]
			if err := standard.fromR3(freshOperation); err == nil {
				t.Fatal("typed conversion accepted another registration with the same URI")
			}
		})
	}
}

func TestStandardVocabularyCrossVocabularyIsRefused(t *testing.T) {
	t.Parallel()

	standards := standardVocabularies()
	registry := standardRegistry(t, standards)
	sets := make([]r3.OperationSet, len(standards))
	for index, standard := range standards {
		sets[index] = parseOperationSet(t, registry, standard.uri, standard.operationA)
	}
	for leftIndex := range standards {
		for rightIndex := leftIndex + 1; rightIndex < len(standards); rightIndex++ {
			leftStandard := standards[leftIndex]
			rightStandard := standards[rightIndex]
			t.Run(leftStandard.name+"_to_"+rightStandard.name, func(t *testing.T) {
				t.Parallel()

				left := sets[leftIndex]
				right := sets[rightIndex]
				assertCrossBoundaryRefusal(t, left, right)
				if _, err := left.Operations()[0].Equal(right.Operations()[0]); err == nil {
					t.Fatal("operation equality crossed vocabularies")
				}
				if _, err := r3.NewOperationSet(left.Operations()[0], right.Operations()[0]); err == nil {
					t.Fatal("operation-set construction crossed vocabularies")
				}
			})
		}
	}
}

func TestRegistryDispatchesOnlyToTheNamedVocabulary(t *testing.T) {
	t.Parallel()

	standards := standardVocabularies()
	var calls []r3.VocabularyURI
	vocabularies := make([]r3.Vocabulary, len(standards))
	for index, standard := range standards {
		vocabulary, err := r3.NewVocabulary[trackingSet](trackingCodec{
			uri: standard.uri, calls: &calls,
		})
		if err != nil {
			t.Fatal(err)
		}
		vocabularies[index] = vocabulary
	}
	registry := mustRegistry(t, vocabularies...)
	for _, standard := range standards {
		calls = nil
		set, err := registry.ParseOperationSet(operationEnvelope(standard.uri, `{"id":"one"}`))
		if err != nil {
			t.Fatal(err)
		}
		if set.Vocabulary() != standard.uri || len(calls) == 0 {
			t.Fatalf("dispatch for %q produced set %q and calls %#v", standard.uri, set.Vocabulary(), calls)
		}
		for _, called := range calls {
			if called != standard.uri {
				t.Fatalf("dispatch for %q also called %q: %#v", standard.uri, called, calls)
			}
		}
	}

	onlyMCP := mustRegistry(t, vocabularies[0])
	if _, err := onlyMCP.ParseOperationSet(operationEnvelope(openapi.URI, `{"id":"one"}`)); err == nil {
		t.Fatal("registry parsed an unregistered named vocabulary")
	}
}

func standardVocabularies() []standardVocabulary {
	return []standardVocabulary{
		{
			name: "mcp", uri: mcp.URI, vocabulary: mcp.Vocabulary,
			operationA:      `{"tool":"records.read"}`,
			operationB:      `{"tool":"records.write"}`,
			unknownMember:   `{"tool":"records.read","unknown":true}`,
			duplicateMember: `{"tool":"records.read","tool":"records.write"}`,
			roundTrip: func(t *testing.T, neutral r3.Operation) {
				t.Helper()
				typed, err := mcp.FromR3(neutral)
				if err != nil || typed.Tool() != "records.read" {
					t.Fatalf("typed round trip = %#v, %v", typed, err)
				}
				back, err := typed.ToR3()
				requireOperationEqual(t, back, neutral, err)
			},
			fromR3: func(operation r3.Operation) error { _, err := mcp.FromR3(operation); return err },
		},
		{
			name: "openapi", uri: openapi.URI, vocabulary: openapi.Vocabulary,
			operationA:      `{"operationId":"readRecord"}`,
			operationB:      `{"operationId":"writeRecord"}`,
			unknownMember:   `{"operationId":"readRecord","unknown":true}`,
			duplicateMember: `{"operationId":"readRecord","operationId":"writeRecord"}`,
			roundTrip: func(t *testing.T, neutral r3.Operation) {
				t.Helper()
				typed, err := openapi.FromR3(neutral)
				if err != nil || typed.OperationID() != "readRecord" {
					t.Fatalf("typed round trip = %#v, %v", typed, err)
				}
				back, err := typed.ToR3()
				requireOperationEqual(t, back, neutral, err)
			},
			fromR3: func(operation r3.Operation) error { _, err := openapi.FromR3(operation); return err },
		},
		{
			name: "grpc", uri: grpcvocab.URI, vocabulary: grpcvocab.Vocabulary,
			operationA:      `{"method":"records.RecordService/Read"}`,
			operationB:      `{"method":"records.RecordService/Write"}`,
			unknownMember:   `{"method":"records.RecordService/Read","unknown":true}`,
			duplicateMember: `{"method":"records.RecordService/Read","method":"records.RecordService/Write"}`,
			roundTrip: func(t *testing.T, neutral r3.Operation) {
				t.Helper()
				typed, err := grpcvocab.FromR3(neutral)
				if err != nil || typed.Method() != "records.RecordService/Read" {
					t.Fatalf("typed round trip = %#v, %v", typed, err)
				}
				back, err := typed.ToR3()
				requireOperationEqual(t, back, neutral, err)
			},
			fromR3: func(operation r3.Operation) error { _, err := grpcvocab.FromR3(operation); return err },
		},
		{
			name: "graphql", uri: graphql.URI, vocabulary: graphql.Vocabulary,
			operationA:      `{"operation":"ReadRecord","type":"query"}`,
			operationB:      `{"operation":"WriteRecord","type":"mutation"}`,
			unknownMember:   `{"operation":"ReadRecord","type":"query","unknown":true}`,
			duplicateMember: `{"operation":"ReadRecord","operation":"Other","type":"query"}`,
			roundTrip: func(t *testing.T, neutral r3.Operation) {
				t.Helper()
				typed, err := graphql.FromR3(neutral)
				if err != nil || typed.OperationName() != "ReadRecord" || typed.Type() != graphql.Query {
					t.Fatalf("typed round trip = %#v, %v", typed, err)
				}
				back, err := typed.ToR3()
				requireOperationEqual(t, back, neutral, err)
			},
			fromR3: func(operation r3.Operation) error { _, err := graphql.FromR3(operation); return err },
		},
		{
			name: "asyncapi", uri: asyncapi.URI, vocabulary: asyncapi.Vocabulary,
			operationA:      `{"operationId":"recordRead","action":"receive"}`,
			operationB:      `{"operationId":"recordWrite","action":"send"}`,
			unknownMember:   `{"operationId":"recordRead","action":"receive","unknown":true}`,
			duplicateMember: `{"operationId":"recordRead","operationId":"other","action":"receive"}`,
			roundTrip: func(t *testing.T, neutral r3.Operation) {
				t.Helper()
				typed, err := asyncapi.FromR3(neutral)
				action, present := typed.Action()
				if err != nil || typed.OperationID() != "recordRead" || !present || action != asyncapi.ActionReceive {
					t.Fatalf("typed round trip = %#v, %v", typed, err)
				}
				back, err := typed.ToR3()
				requireOperationEqual(t, back, neutral, err)
			},
			fromR3: func(operation r3.Operation) error { _, err := asyncapi.FromR3(operation); return err },
		},
		{
			name: "wsdl", uri: wsdl.URI, vocabulary: wsdl.Vocabulary,
			operationA:      `{"operation":"ReadRecord","service":"RecordService"}`,
			operationB:      `{"operation":"WriteRecord","service":"RecordService"}`,
			unknownMember:   `{"operation":"ReadRecord","service":"RecordService","unknown":true}`,
			duplicateMember: `{"operation":"ReadRecord","operation":"Other","service":"RecordService"}`,
			roundTrip: func(t *testing.T, neutral r3.Operation) {
				t.Helper()
				typed, err := wsdl.FromR3(neutral)
				service, present := typed.Service()
				if err != nil || typed.OperationName() != "ReadRecord" || !present || service != "RecordService" {
					t.Fatalf("typed round trip = %#v, %v", typed, err)
				}
				back, err := typed.ToR3()
				requireOperationEqual(t, back, neutral, err)
			},
			fromR3: func(operation r3.Operation) error { _, err := wsdl.FromR3(operation); return err },
		},
		{
			name: "odata", uri: odata.URI, vocabulary: odata.Vocabulary,
			operationA:      `{"operation":"Records","methods":["GET"]}`,
			operationB:      `{"operation":"OtherRecords","methods":["POST"]}`,
			unknownMember:   `{"operation":"Records","methods":["GET"],"unknown":true}`,
			duplicateMember: `{"operation":"Records","operation":"Other","methods":["GET"]}`,
			roundTrip: func(t *testing.T, neutral r3.Operation) {
				t.Helper()
				typed, err := odata.FromR3(neutral)
				methods, present := typed.Methods()
				if err != nil || typed.OperationName() != "Records" || !present || !reflect.DeepEqual(methods, []string{"GET"}) {
					t.Fatalf("typed round trip = %#v, %v", typed, err)
				}
				back, err := typed.ToR3()
				requireOperationEqual(t, back, neutral, err)
			},
			fromR3: func(operation r3.Operation) error { _, err := odata.FromR3(operation); return err },
		},
	}
}

func standardRegistry(t *testing.T, standards []standardVocabulary) r3.Registry {
	t.Helper()
	vocabularies := make([]r3.Vocabulary, len(standards))
	seen := make(map[r3.VocabularyURI]struct{}, len(standards))
	for index, standard := range standards {
		if _, duplicate := seen[standard.uri]; duplicate {
			t.Fatalf("duplicate standard URI %q", standard.uri)
		}
		seen[standard.uri] = struct{}{}
		vocabularies[index] = standard.vocabulary()
	}
	return mustRegistry(t, vocabularies...)
}

func registerFresh[S any](t *testing.T, codec r3.Codec[S]) r3.Vocabulary {
	t.Helper()
	vocabulary, err := r3.NewVocabulary[S](codec)
	if err != nil {
		t.Fatal(err)
	}
	return vocabulary
}

func mustRegistry(t *testing.T, vocabularies ...r3.Vocabulary) r3.Registry {
	t.Helper()
	registry, err := r3.NewRegistry(vocabularies...)
	if err != nil {
		t.Fatal(err)
	}
	return registry
}

func operationEnvelope(uri r3.VocabularyURI, operations ...string) []byte {
	return []byte(`{"vocabulary":` + strconv.Quote(string(uri)) + `,"operations":[` + strings.Join(operations, ",") + `]}`)
}

func parseOperationSet(t *testing.T, registry r3.Registry, uri r3.VocabularyURI, operations ...string) r3.OperationSet {
	t.Helper()
	set, err := registry.ParseOperationSet(operationEnvelope(uri, operations...))
	if err != nil {
		t.Fatal(err)
	}
	return set
}

func requireOperationEqual(t *testing.T, left, right r3.Operation, constructionErr error) {
	t.Helper()
	if constructionErr != nil {
		t.Fatal(constructionErr)
	}
	equal, err := left.Equal(right)
	if err != nil || !equal {
		t.Fatalf("operation round trip equality = %t, %v", equal, err)
	}
}

func assertCrossBoundaryRefusal(t *testing.T, left, right r3.OperationSet) {
	t.Helper()
	if _, err := left.Equal(right); err == nil {
		t.Fatal("set equality crossed the boundary")
	}
	if _, err := left.IsSubsetOf(right); err == nil {
		t.Fatal("set subset crossed the boundary")
	}
	if _, err := left.Disjoint(right); err == nil {
		t.Fatal("set disjointness crossed the boundary")
	}
	if _, err := left.Union(right); err == nil {
		t.Fatal("set union crossed the boundary")
	}
}

// foreignCodec supplies a second private registration with the same URI and
// exact operation JSON. It exercises registration identity without exposing a
// standard adapter's implementation types as public API.
type foreignSet []json.RawMessage

type foreignCodec struct{ uri r3.VocabularyURI }

func (codec foreignCodec) URI() r3.VocabularyURI { return codec.uri }

func (foreignCodec) AnnotationEncoding() r3.AnnotationEncoding {
	return r3.AnnotationUnavailable
}

func (foreignCodec) ValidateDiscoveryEndpoint(endpoint string) error {
	if !strings.HasPrefix(endpoint, "custom+unix:///") {
		return fmt.Errorf("foreign: discovery endpoint must use custom+unix")
	}
	return nil
}

func (foreignCodec) ParseSet(raw []json.RawMessage) (foreignSet, error) {
	return cloneForeignSet(raw), nil
}

func (foreignCodec) MarshalSet(set foreignSet) ([]json.RawMessage, error) {
	return cloneForeignSet(set), nil
}

func (foreignCodec) Union(sets ...foreignSet) (foreignSet, error) {
	var result foreignSet
	for _, set := range sets {
		for _, operation := range set {
			if !foreignContains(result, operation) {
				result = append(result, append(json.RawMessage(nil), operation...))
			}
		}
	}
	return result, nil
}

func (foreignCodec) Equal(left, right foreignSet) bool {
	return len(left) == len(right) && foreignSubset(left, right)
}

func (foreignCodec) Subset(left, right foreignSet) bool { return foreignSubset(left, right) }

func (foreignCodec) Disjoint(left, right foreignSet) bool {
	for _, operation := range left {
		if foreignContains(right, operation) {
			return false
		}
	}
	return true
}

func cloneForeignSet(source []json.RawMessage) foreignSet {
	result := make(foreignSet, len(source))
	for index, operation := range source {
		result[index] = append(json.RawMessage(nil), operation...)
	}
	return result
}

func foreignSubset(left, right foreignSet) bool {
	for _, operation := range left {
		if !foreignContains(right, operation) {
			return false
		}
	}
	return true
}

func foreignContains(set foreignSet, wanted json.RawMessage) bool {
	return slices.ContainsFunc(set, func(operation json.RawMessage) bool {
		return bytes.Equal(operation, wanted)
	})
}

var _ r3.Codec[foreignSet] = foreignCodec{}

type trackingOperation string

type trackingSet []trackingOperation

type trackingCodec struct {
	uri   r3.VocabularyURI
	calls *[]r3.VocabularyURI
}

func (codec trackingCodec) URI() r3.VocabularyURI { return codec.uri }

func (trackingCodec) AnnotationEncoding() r3.AnnotationEncoding {
	return r3.AnnotationUnavailable
}

func (trackingCodec) ValidateDiscoveryEndpoint(endpoint string) error {
	if !strings.HasPrefix(endpoint, "custom+unix:///") {
		return fmt.Errorf("tracking: discovery endpoint must use custom+unix")
	}
	return nil
}

func (codec trackingCodec) ParseSet(raw []json.RawMessage) (trackingSet, error) {
	*codec.calls = append(*codec.calls, codec.uri)
	result := make(trackingSet, len(raw))
	for index, encoded := range raw {
		var object struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(encoded, &object); err != nil || object.ID == "" {
			return nil, fmt.Errorf("tracking: %q operation %d", codec.uri, index)
		}
		result[index] = trackingOperation(object.ID)
	}
	return result, nil
}

func (trackingCodec) MarshalSet(set trackingSet) ([]json.RawMessage, error) {
	result := make([]json.RawMessage, len(set))
	for index, operation := range set {
		encoded, err := json.Marshal(struct {
			ID string `json:"id"`
		}{ID: string(operation)})
		if err != nil {
			return nil, err
		}
		result[index] = encoded
	}
	return result, nil
}

func (trackingCodec) Union(sets ...trackingSet) (trackingSet, error) {
	var result trackingSet
	for _, set := range sets {
		for _, operation := range set {
			if !slices.Contains(result, operation) {
				result = append(result, operation)
			}
		}
	}
	return result, nil
}

func (trackingCodec) Equal(left, right trackingSet) bool {
	return len(left) == len(right) && trackingSubset(left, right)
}

func (trackingCodec) Subset(left, right trackingSet) bool { return trackingSubset(left, right) }

func (trackingCodec) Disjoint(left, right trackingSet) bool {
	for _, operation := range left {
		if slices.Contains(right, operation) {
			return false
		}
	}
	return true
}

func trackingSubset(left, right trackingSet) bool {
	for _, operation := range left {
		if !slices.Contains(right, operation) {
			return false
		}
	}
	return true
}

var _ r3.Codec[trackingSet] = trackingCodec{}
