package vocabtest

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"testing"

	"aauth-go/r3"
)

// Contract supplies representative values for checking one R3 vocabulary.
// OperationA and OperationB must be valid, semantically distinct, and
// disjoint. InvalidOperations and DuplicateOperations must each contain at
// least one operation object the codec rejects. ForeignRegistration must be a
// separately constructed Vocabulary with the same URI.
//
// Run checks that the codec reaches a stable canonical form; its set equality,
// subset, disjointness, and union operations agree; its public values are
// copy-safe; its discovery validator accepts and rejects the supplied examples;
// and the registry does not fall back across names or registrations.
type Contract struct {
	Vocabulary          r3.Vocabulary
	Registry            r3.Registry
	ForeignRegistration r3.Vocabulary

	OperationA          json.RawMessage
	OperationB          json.RawMessage
	InvalidOperations   []json.RawMessage
	DuplicateOperations []json.RawMessage

	ValidDiscoveryEndpoint    string
	InvalidDiscoveryEndpoints []string
}

// Run checks the representative grammar, algebra, registration, and copy
// safety laws described by Contract. It reports the first violated law through
// t. Passing this helper complements, but does not replace, exhaustive tests of
// a vocabulary's own grammar and discovery endpoint profile.
func Run(t testing.TB, contract Contract) {
	t.Helper()
	if err := check(contract); err != nil {
		t.Fatal(err)
	}
}

func check(contract Contract) error {
	if len(contract.OperationA) == 0 || len(contract.OperationB) == 0 {
		return fmt.Errorf("vocabtest: OperationA and OperationB are required")
	}
	if len(contract.InvalidOperations) == 0 {
		return fmt.Errorf("vocabtest: InvalidOperations must contain at least one refusal vector")
	}
	if len(contract.DuplicateOperations) == 0 {
		return fmt.Errorf("vocabtest: DuplicateOperations must contain at least one refusal vector")
	}
	if contract.ValidDiscoveryEndpoint == "" {
		return fmt.Errorf("vocabtest: ValidDiscoveryEndpoint is required")
	}
	if len(contract.InvalidDiscoveryEndpoints) == 0 {
		return fmt.Errorf("vocabtest: InvalidDiscoveryEndpoints must contain at least one refusal vector")
	}

	uri := contract.Vocabulary.URI()
	if uri == "" {
		return fmt.Errorf("vocabtest: Vocabulary is uninitialized")
	}
	if contract.ForeignRegistration.URI() != uri {
		return fmt.Errorf(
			"vocabtest: ForeignRegistration URI = %q, want %q",
			contract.ForeignRegistration.URI(), uri,
		)
	}
	if err := checkDiscoveryEndpoints(contract); err != nil {
		return err
	}

	localRegistry, err := r3.NewRegistry(contract.Vocabulary)
	if err != nil {
		return fmt.Errorf("vocabtest: register Vocabulary: %w", err)
	}
	localA, err := parse(localRegistry, uri, contract.OperationA)
	if err != nil {
		return fmt.Errorf("vocabtest: parse OperationA through Vocabulary: %w", err)
	}
	registryA, err := parse(contract.Registry, uri, contract.OperationA)
	if err != nil {
		return fmt.Errorf("vocabtest: Registry did not dispatch the named Vocabulary: %w", err)
	}
	if err := requireEqual("Registry uses the supplied registration", localA, registryA, true); err != nil {
		return err
	}

	unknownURI := unregisteredURI(contract.Registry, uri)
	if _, err := parse(contract.Registry, unknownURI, contract.OperationA); err == nil {
		return fmt.Errorf("vocabtest: Registry accepted unregistered vocabulary %q", unknownURI)
	}

	a, err := parse(contract.Registry, uri, contract.OperationA)
	if err != nil {
		return fmt.Errorf("vocabtest: parse OperationA: %w", err)
	}
	b, err := parse(contract.Registry, uri, contract.OperationB)
	if err != nil {
		return fmt.Errorf("vocabtest: parse OperationB: %w", err)
	}
	both, err := parse(contract.Registry, uri, contract.OperationA, contract.OperationB)
	if err != nil {
		return fmt.Errorf("vocabtest: parse OperationA and OperationB: %w", err)
	}

	if err := checkRefusals(contract, uri); err != nil {
		return err
	}
	for _, set := range []r3.OperationSet{a, b, both} {
		if err := checkMarshalStability(contract.Registry, set); err != nil {
			return err
		}
	}
	if err := checkAlgebra(a, b, both); err != nil {
		return err
	}
	if err := checkCopySafety(contract.Registry, uri, contract.OperationA); err != nil {
		return err
	}
	if err := checkForeignRegistration(contract, localA); err != nil {
		return err
	}
	return nil
}

func checkDiscoveryEndpoints(contract Contract) error {
	if err := contract.Vocabulary.ValidateDiscoveryEndpoint(contract.ValidDiscoveryEndpoint); err != nil {
		return fmt.Errorf("vocabtest: valid discovery endpoint was refused: %w", err)
	}
	for index, endpoint := range contract.InvalidDiscoveryEndpoints {
		if err := contract.Vocabulary.ValidateDiscoveryEndpoint(endpoint); err == nil {
			return fmt.Errorf("vocabtest: invalid discovery endpoint %d was accepted: %q", index, endpoint)
		}
	}
	return nil
}

func checkRefusals(contract Contract, uri r3.VocabularyURI) error {
	for index, operation := range contract.InvalidOperations {
		if _, err := parse(contract.Registry, uri, operation); err == nil {
			return fmt.Errorf("vocabtest: invalid operation %d was accepted: %s", index, operation)
		}
	}
	for index, operation := range contract.DuplicateOperations {
		if _, err := parse(contract.Registry, uri, operation); err == nil {
			return fmt.Errorf("vocabtest: duplicate-member operation %d was accepted: %s", index, operation)
		}
	}
	if _, err := parse(contract.Registry, uri, contract.OperationA, contract.OperationA); err == nil {
		return fmt.Errorf("vocabtest: duplicate OperationA was accepted")
	}

	quotedURI := strconv.Quote(string(uri))
	unknownEnvelopeMember := []byte(
		`{"vocabulary":` + quotedURI + `,"operations":[` + string(contract.OperationA) + `],"unknown":true}`,
	)
	if _, err := contract.Registry.ParseOperationSet(unknownEnvelopeMember); err == nil {
		return fmt.Errorf("vocabtest: unknown operation-set envelope member was accepted")
	}
	duplicateEnvelopeMember := []byte(
		`{"vocabulary":` + quotedURI + `,"vocabulary":` + quotedURI + `,"operations":[` + string(contract.OperationA) + `]}`,
	)
	if _, err := contract.Registry.ParseOperationSet(duplicateEnvelopeMember); err == nil {
		return fmt.Errorf("vocabtest: duplicate operation-set envelope member was accepted")
	}
	return nil
}

func checkMarshalStability(registry r3.Registry, set r3.OperationSet) error {
	first, err := json.Marshal(set)
	if err != nil {
		return fmt.Errorf("vocabtest: marshal parsed set: %w", err)
	}
	reparsed, err := registry.ParseOperationSet(first)
	if err != nil {
		return fmt.Errorf("vocabtest: parse canonical set: %w", err)
	}
	second, err := json.Marshal(reparsed)
	if err != nil {
		return fmt.Errorf("vocabtest: remarshal canonical set: %w", err)
	}
	if !bytes.Equal(first, second) {
		return fmt.Errorf("vocabtest: marshal/parse did not reach a stable canonical form: %s then %s", first, second)
	}
	return requireEqual("marshal/parse preserves semantics", set, reparsed, true)
}

func checkAlgebra(a, b, both r3.OperationSet) error {
	checks := []func() error{
		func() error { return requireEqual("equality is reflexive", a, a, true) },
		func() error { return requireEqual("distinct samples compare unequal", a, b, false) },
		func() error { return requireEqual("distinct equality is symmetric", b, a, false) },
		func() error { return requireSubset("subset is reflexive", a, a, true) },
		func() error { return requireSubset("OperationA is a subset of the combined set", a, both, true) },
		func() error { return requireSubset("OperationB is a subset of the combined set", b, both, true) },
		func() error { return requireSubset("the combined set is not a subset of OperationA", both, a, false) },
		func() error { return requireDisjoint("distinct samples are disjoint", a, b, true) },
		func() error { return requireDisjoint("disjointness is symmetric", b, a, true) },
		func() error { return requireDisjoint("OperationA overlaps itself", a, a, false) },
		func() error { return requireDisjoint("OperationB overlaps itself", b, b, false) },
		func() error { return requireDisjoint("the combined set overlaps itself", both, both, false) },
		func() error { return requireDisjoint("a member overlaps the combined set", a, both, false) },
	}
	for _, check := range checks {
		if err := check(); err != nil {
			return err
		}
	}

	aBefore, err := json.Marshal(a)
	if err != nil {
		return fmt.Errorf("vocabtest: marshal OperationA before union: %w", err)
	}
	bBefore, err := json.Marshal(b)
	if err != nil {
		return fmt.Errorf("vocabtest: marshal OperationB before union: %w", err)
	}
	ab, err := a.Union(b)
	if err != nil {
		return fmt.Errorf("vocabtest: union OperationA and OperationB: %w", err)
	}
	ba, err := b.Union(a)
	if err != nil {
		return fmt.Errorf("vocabtest: union OperationB and OperationA: %w", err)
	}
	aa, err := a.Union(a)
	if err != nil {
		return fmt.Errorf("vocabtest: union OperationA with itself: %w", err)
	}
	leftAssociated, err := ab.Union(a)
	if err != nil {
		return fmt.Errorf("vocabtest: left-associated union: %w", err)
	}
	baAgain, err := b.Union(a)
	if err != nil {
		return fmt.Errorf("vocabtest: inner right-associated union: %w", err)
	}
	rightAssociated, err := a.Union(baAgain)
	if err != nil {
		return fmt.Errorf("vocabtest: right-associated union: %w", err)
	}
	for _, check := range []func() error{
		func() error { return requireEqual("union contains exactly both samples", ab, both, true) },
		func() error { return requireEqual("union is commutative", ab, ba, true) },
		func() error { return requireEqual("union is idempotent", aa, a, true) },
		func() error {
			return requireEqual("union is associative for the samples", leftAssociated, rightAssociated, true)
		},
		func() error { return requireSubset("union contains OperationA", a, ab, true) },
		func() error { return requireSubset("union contains OperationB", b, ab, true) },
	} {
		if err := check(); err != nil {
			return err
		}
	}
	aAfter, err := json.Marshal(a)
	if err != nil {
		return fmt.Errorf("vocabtest: marshal OperationA after union: %w", err)
	}
	bAfter, err := json.Marshal(b)
	if err != nil {
		return fmt.Errorf("vocabtest: marshal OperationB after union: %w", err)
	}
	if !bytes.Equal(aBefore, aAfter) || !bytes.Equal(bBefore, bAfter) {
		return fmt.Errorf("vocabtest: union mutated an operand")
	}
	return nil
}

func checkCopySafety(registry r3.Registry, uri r3.VocabularyURI, operation json.RawMessage) error {
	source := operationEnvelope(uri, operation)
	set, err := registry.ParseOperationSet(source)
	if err != nil {
		return fmt.Errorf("vocabtest: parse copy-safety sample: %w", err)
	}
	want, err := json.Marshal(set)
	if err != nil {
		return fmt.Errorf("vocabtest: marshal copy-safety sample: %w", err)
	}
	for index := range source {
		source[index] = ' '
	}
	got, err := json.Marshal(set)
	if err != nil {
		return fmt.Errorf("vocabtest: marshal set after source mutation: %w", err)
	}
	if !bytes.Equal(got, want) {
		return fmt.Errorf("vocabtest: parsed set retained the caller's input buffer")
	}

	operations := set.Operations()
	if len(operations) != 1 {
		return fmt.Errorf("vocabtest: one-operation set exposed %d operations", len(operations))
	}
	operationJSON := operations[0].JSON()
	if len(operationJSON) == 0 {
		return fmt.Errorf("vocabtest: operation exposed no canonical JSON")
	}
	wantOperation := append([]byte(nil), operationJSON...)
	operationJSON[0] ^= 0xff
	if gotOperation := operations[0].JSON(); !bytes.Equal(gotOperation, wantOperation) {
		return fmt.Errorf("vocabtest: Operation.JSON exposed mutable internal storage")
	}
	operations[0] = r3.Operation{}
	if fresh := set.Operations(); len(fresh) != 1 || !bytes.Equal(fresh[0].JSON(), wantOperation) {
		return fmt.Errorf("vocabtest: OperationSet.Operations exposed mutable internal storage")
	}

	marshaled := append([]byte(nil), want...)
	marshaled[0] ^= 0xff
	got, err = json.Marshal(set)
	if err != nil {
		return fmt.Errorf("vocabtest: remarshal after output mutation: %w", err)
	}
	if !bytes.Equal(got, want) {
		return fmt.Errorf("vocabtest: marshaled output aliased set storage")
	}
	return nil
}

func checkForeignRegistration(contract Contract, stableSet r3.OperationSet) error {
	if _, err := r3.NewRegistry(contract.Vocabulary, contract.ForeignRegistration); err == nil {
		return fmt.Errorf("vocabtest: Registry accepted two registrations for URI %q", contract.Vocabulary.URI())
	}
	foreignRegistry, err := r3.NewRegistry(contract.ForeignRegistration)
	if err != nil {
		return fmt.Errorf("vocabtest: register ForeignRegistration: %w", err)
	}
	foreignSet, err := parse(foreignRegistry, contract.Vocabulary.URI(), contract.OperationA)
	if err != nil {
		return fmt.Errorf("vocabtest: ForeignRegistration could not parse OperationA: %w", err)
	}
	if _, err := stableSet.Equal(foreignSet); err == nil {
		return fmt.Errorf("vocabtest: equality crossed same-URI registrations")
	}
	if _, err := stableSet.IsSubsetOf(foreignSet); err == nil {
		return fmt.Errorf("vocabtest: subset crossed same-URI registrations")
	}
	if _, err := stableSet.Disjoint(foreignSet); err == nil {
		return fmt.Errorf("vocabtest: disjointness crossed same-URI registrations")
	}
	if _, err := stableSet.Union(foreignSet); err == nil {
		return fmt.Errorf("vocabtest: union crossed same-URI registrations")
	}

	stableOperation := stableSet.Operations()
	foreignOperation := foreignSet.Operations()
	if len(stableOperation) != 1 || len(foreignOperation) != 1 {
		return fmt.Errorf("vocabtest: registration samples did not expose one operation")
	}
	if _, err := stableOperation[0].Equal(foreignOperation[0]); err == nil {
		return fmt.Errorf("vocabtest: operation equality crossed same-URI registrations")
	}
	if _, err := r3.NewOperationSet(stableOperation[0], foreignOperation[0]); err == nil {
		return fmt.Errorf("vocabtest: operation-set construction crossed same-URI registrations")
	}
	return nil
}

func parse(registry r3.Registry, uri r3.VocabularyURI, operations ...json.RawMessage) (r3.OperationSet, error) {
	return registry.ParseOperationSet(operationEnvelope(uri, operations...))
}

func operationEnvelope(uri r3.VocabularyURI, operations ...json.RawMessage) []byte {
	var buffer bytes.Buffer
	buffer.WriteString(`{"vocabulary":`)
	buffer.WriteString(strconv.Quote(string(uri)))
	buffer.WriteString(`,"operations":[`)
	for index, operation := range operations {
		if index > 0 {
			buffer.WriteByte(',')
		}
		buffer.Write(operation)
	}
	buffer.WriteString(`]}`)
	return buffer.Bytes()
}

func unregisteredURI(registry r3.Registry, registered r3.VocabularyURI) r3.VocabularyURI {
	for suffix := 0; ; suffix++ {
		candidate := r3.VocabularyURI("urn:aauth:vocabtest:unregistered:" + strconv.Itoa(suffix))
		if candidate == registered {
			continue
		}
		if _, found := registry.Vocabulary(candidate); !found {
			return candidate
		}
	}
}

func requireEqual(name string, left, right r3.OperationSet, want bool) error {
	got, err := left.Equal(right)
	if err != nil {
		return fmt.Errorf("vocabtest: %s returned an error: %w", name, err)
	}
	if got != want {
		return fmt.Errorf("vocabtest: %s = %t, want %t", name, got, want)
	}
	return nil
}

func requireSubset(name string, left, right r3.OperationSet, want bool) error {
	got, err := left.IsSubsetOf(right)
	if err != nil {
		return fmt.Errorf("vocabtest: %s returned an error: %w", name, err)
	}
	if got != want {
		return fmt.Errorf("vocabtest: %s = %t, want %t", name, got, want)
	}
	return nil
}

func requireDisjoint(name string, left, right r3.OperationSet, want bool) error {
	got, err := left.Disjoint(right)
	if err != nil {
		return fmt.Errorf("vocabtest: %s returned an error: %w", name, err)
	}
	if got != want {
		return fmt.Errorf("vocabtest: %s = %t, want %t", name, got, want)
	}
	return nil
}
