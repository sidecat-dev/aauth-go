// Package vocabtest checks the shared contract implemented by an R3 operation
// vocabulary. It is intended for both the standard adapters and third-party
// vocabulary packages.
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
// Run checks representative grammar and algebra laws. The codec must still
// have exhaustive tests for its operation fields and discovery endpoint
// grammar. Definition fetching, access annotations, and authorization behavior
// are outside this package.
package vocabtest
