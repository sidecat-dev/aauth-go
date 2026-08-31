// Package vocabtest checks the two independent extension contracts implemented
// by an R3 vocabulary: operation grammar/algebra and native authoritative
// definition parsing. It is intended for both standard adapters and
// third-party vocabulary packages.
//
// A codec test normally constructs the package's stable registration, a fresh
// registration of the same codec, and an application registry:
//
//	func TestContract(t *testing.T) {
//		stable := Vocabulary()
//		foreign, err := r3.NewVocabulary[set](codec{})
//		if err != nil {
//			t.Fatal(err)
//		}
//		registry, err := r3.NewRegistry(stable)
//		if err != nil {
//			t.Fatal(err)
//		}
//		vocabtest.Run(t, vocabtest.Contract{
//			Vocabulary: stable, Registry: registry,
//			ForeignRegistration: foreign,
//			OperationA: json.RawMessage(`{"name":"read"}`),
//			OperationB: json.RawMessage(`{"name":"write"}`),
//			InvalidOperations: []json.RawMessage{
//				json.RawMessage(`{"unknown":true}`),
//			},
//			DuplicateOperations: []json.RawMessage{
//				json.RawMessage(`{"name":"read","name":"write"}`),
//			},
//			ValidDiscoveryEndpoint: "custom+unix:///definitions/widgets",
//			InvalidDiscoveryEndpoints: []string{"https://example.com/widgets"},
//		})
//	}
//
// Run checks representative grammar and algebra laws. RunDefinition separately
// checks parser-registration isolation, receipt completeness and stable replay,
// changed-source divergence, known and unknown operation containment, hint
// lookup, and typed source refusals. It does not impose a common native source
// representation.
//
// A codec must still have exhaustive tests for its own operation fields,
// discovery endpoint grammar, and bounded native-source profile. Discovery
// transport, dependency resolution, source freshness, parser-resource limits,
// application policy, authorization, and enforcement are outside this package.
// Hints remain advisory even when a definition contract checks them.
package vocabtest
