package vocabtest

import (
	"errors"
	"fmt"
	"sync"
	"testing"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/r3"
)

// DefinitionRefusal is one native source that must fail with Kind.
type DefinitionRefusal[S any] struct {
	Name   string
	Source S
	Kind   r3.DefinitionErrorKind
}

// DefinitionContract supplies one positive native definition source, one
// changed source, representative known and unknown operations, and refusal
// vectors for a vocabulary adapter.
type DefinitionContract[S any] struct {
	// Registration must be the stable identity of Parse.
	Registration r3.DefinitionRegistration
	// Parse performs one deterministic, concurrency-safe, I/O-free parse.
	Parse func(string, S) (r3.AuthoritativeSnapshot, error)
	// Endpoint is one vocabulary-valid advertised discovery endpoint.
	Endpoint string
	// Source is one complete valid native source.
	Source S
	// ChangedSource is valid and adds ChangedOnly without removing Known.
	ChangedSource S
	// Known is defined by both Source values.
	Known r3.Operation
	// Unknown is well-formed but absent from both Source values.
	Unknown r3.Operation
	// ChangedOnly is absent from Source and defined by ChangedSource.
	ChangedOnly r3.Operation
	// Hints optionally checks exact sparse hints through parse and replay.
	Hints *DefinitionHintsExpectation
	// Refusals contains representative typed native-source failures.
	Refusals []DefinitionRefusal[S]
}

// DefinitionHintsExpectation describes exact sparse hints that must survive
// parsing and stable replay for one defined operation. Nil members mean the
// corresponding source annotation must be absent.
type DefinitionHintsExpectation struct {
	Operation  r3.Operation
	AccessMode *aauth.AccessMode
	Budget     *bool
}

// RunDefinition checks the shared authoritative-definition laws without
// imposing a common native source representation.
func RunDefinition[S any](t testing.TB, contract DefinitionContract[S]) {
	t.Helper()
	if err := checkDefinition(contract); err != nil {
		t.Fatal(err)
	}
}

func checkDefinition[S any](contract DefinitionContract[S]) error {
	if contract.Parse == nil {
		return errors.New("vocabtest: definition Parse is required")
	}
	if contract.Endpoint == "" {
		return errors.New("vocabtest: definition Endpoint is required")
	}
	if contract.Known.JSON() == nil || contract.Unknown.JSON() == nil || contract.ChangedOnly.JSON() == nil {
		return errors.New("vocabtest: definition Known, Unknown, and ChangedOnly operations are required")
	}
	if len(contract.Refusals) == 0 {
		return errors.New("vocabtest: definition Refusals must not be empty")
	}
	registry, err := r3.NewDefinitionRegistry(contract.Registration)
	if err != nil {
		return fmt.Errorf("vocabtest: register definition parser: %w", err)
	}
	snapshot, err := contract.Parse(contract.Endpoint, contract.Source)
	if err != nil {
		return fmt.Errorf("vocabtest: parse valid definition source: %w", err)
	}
	if err := registry.Validate(snapshot); err != nil {
		return fmt.Errorf("vocabtest: validate definition registration: %w", err)
	}
	if snapshot.Receipt().Encoding() == "" || snapshot.Receipt().DiscoveryEndpoint() != contract.Endpoint || snapshot.Receipt().Digest() == "" || snapshot.Receipt().ByteLength() <= 0 {
		return fmt.Errorf("vocabtest: definition source receipt is incomplete")
	}
	if len(snapshot.Operations().Operations()) == 0 {
		return errors.New("vocabtest: definition snapshot has no operations")
	}
	known, err := r3.NewOperationSet(contract.Known)
	if err != nil {
		return fmt.Errorf("vocabtest: construct known operation set: %w", err)
	}
	if err := snapshot.ValidateDefined(known); err != nil {
		return fmt.Errorf("vocabtest: known operation was not defined: %w", err)
	}
	unknown, err := r3.NewOperationSet(contract.Unknown)
	if err != nil {
		return fmt.Errorf("vocabtest: construct unknown operation set: %w", err)
	}
	if err := requireDefinitionKind(snapshot.ValidateDefined(unknown), r3.DefinitionOperationNotDefined); err != nil {
		return fmt.Errorf("vocabtest: unknown operation refusal: %w", err)
	}
	if _, _, err := snapshot.HintsFor(contract.Unknown); err == nil {
		return errors.New("vocabtest: definition snapshot served hints for an unknown operation")
	}
	if contract.Hints != nil {
		if err := checkDefinitionHints(snapshot, *contract.Hints); err != nil {
			return fmt.Errorf("vocabtest: definition hints: %w", err)
		}
	}

	replayed, err := contract.Parse(contract.Endpoint, contract.Source)
	if err != nil {
		return fmt.Errorf("vocabtest: replay valid definition source: %w", err)
	}
	equal, err := snapshot.Operations().Equal(replayed.Operations())
	if err != nil || !equal || snapshot.Receipt().Digest() != replayed.Receipt().Digest() {
		return fmt.Errorf("vocabtest: definition replay was not stable")
	}
	if contract.Hints != nil {
		if err := checkDefinitionHints(replayed, *contract.Hints); err != nil {
			return fmt.Errorf("vocabtest: replayed definition hints: %w", err)
		}
	}
	if err := checkConcurrentDefinitionReplay(contract, snapshot); err != nil {
		return err
	}
	changed, err := contract.Parse(contract.Endpoint, contract.ChangedSource)
	if err != nil {
		return fmt.Errorf("vocabtest: parse changed definition source: %w", err)
	}
	if changed.Receipt().Digest() == snapshot.Receipt().Digest() {
		return errors.New("vocabtest: changed exact definition source retained the same digest")
	}
	equal, err = snapshot.Operations().Equal(changed.Operations())
	if err != nil || equal {
		return errors.New("vocabtest: changed native source did not change derived operations")
	}
	if err := changed.ValidateDefined(known); err != nil {
		return fmt.Errorf("vocabtest: changed source removed known operation: %w", err)
	}
	changedOnly, err := r3.NewOperationSet(contract.ChangedOnly)
	if err != nil {
		return fmt.Errorf("vocabtest: construct changed-only operation set: %w", err)
	}
	if err := requireDefinitionKind(snapshot.ValidateDefined(changedOnly), r3.DefinitionOperationNotDefined); err != nil {
		return fmt.Errorf("vocabtest: baseline accepted changed-only operation: %w", err)
	}
	if err := changed.ValidateDefined(changedOnly); err != nil {
		return fmt.Errorf("vocabtest: changed source did not derive changed-only operation: %w", err)
	}

	for index, refusal := range contract.Refusals {
		_, err := contract.Parse(contract.Endpoint, refusal.Source)
		if kindErr := requireDefinitionKind(err, refusal.Kind); kindErr != nil {
			return fmt.Errorf("vocabtest: definition refusal %d %q: %w", index, refusal.Name, kindErr)
		}
	}
	return nil
}

func checkConcurrentDefinitionReplay[S any](contract DefinitionContract[S], baseline r3.AuthoritativeSnapshot) error {
	const readers = 8
	errorsFromReaders := make(chan error, readers)
	var group sync.WaitGroup
	group.Add(readers)
	for index := 0; index < readers; index++ {
		go func() {
			defer group.Done()
			replayed, err := contract.Parse(contract.Endpoint, contract.Source)
			if err != nil {
				errorsFromReaders <- err
				return
			}
			equal, err := baseline.Operations().Equal(replayed.Operations())
			if err != nil || !equal || baseline.Receipt().Digest() != replayed.Receipt().Digest() {
				errorsFromReaders <- errors.New("concurrent definition replay was not stable")
				return
			}
			if contract.Hints != nil {
				if err := checkDefinitionHints(replayed, *contract.Hints); err != nil {
					errorsFromReaders <- err
				}
			}
		}()
	}
	group.Wait()
	close(errorsFromReaders)
	for err := range errorsFromReaders {
		return fmt.Errorf("vocabtest: concurrent definition replay: %w", err)
	}
	return nil
}

func checkDefinitionHints(snapshot r3.AuthoritativeSnapshot, expected DefinitionHintsExpectation) error {
	if expected.Operation.JSON() == nil {
		return errors.New("expected hint operation is required")
	}
	hints, present, err := snapshot.HintsFor(expected.Operation)
	if err != nil {
		return err
	}
	if !present {
		return errors.New("expected hints are absent")
	}
	mode, modePresent := hints.AccessMode()
	if (expected.AccessMode != nil) != modePresent ||
		(expected.AccessMode != nil && mode != *expected.AccessMode) {
		return fmt.Errorf("access mode = %q/%t, want %v", mode, modePresent, expected.AccessMode)
	}
	budget, budgetPresent := hints.Budget()
	if (expected.Budget != nil) != budgetPresent ||
		(expected.Budget != nil && budget != *expected.Budget) {
		return fmt.Errorf("budget = %t/%t, want %v", budget, budgetPresent, expected.Budget)
	}
	return nil
}

// DefinitionRefusalContract checks a vocabulary whose authoritative source
// cannot produce an R3 operation identity under the current specification.
type DefinitionRefusalContract[S any] struct {
	Parse      func(string, S) (r3.AuthoritativeSnapshot, error)
	Endpoint   string
	Source     S
	Vocabulary r3.VocabularyURI
	Kind       r3.DefinitionErrorKind
}

// RunDefinitionRefusal checks one deliberate specification-bound refusal.
func RunDefinitionRefusal[S any](t testing.TB, contract DefinitionRefusalContract[S]) {
	t.Helper()
	if contract.Parse == nil || contract.Endpoint == "" || contract.Vocabulary == "" {
		t.Fatal("vocabtest: complete definition refusal contract is required")
	}
	_, err := contract.Parse(contract.Endpoint, contract.Source)
	var refusal *r3.DefinitionError
	if !errors.As(err, &refusal) || refusal.Kind != contract.Kind || refusal.Vocabulary != contract.Vocabulary {
		t.Fatalf("vocabtest: definition refusal = %T %v", err, err)
	}
}

func requireDefinitionKind(err error, want r3.DefinitionErrorKind) error {
	var refusal *r3.DefinitionError
	if !errors.As(err, &refusal) {
		return fmt.Errorf("error = %T %v, want *r3.DefinitionError", err, err)
	}
	if refusal.Kind != want {
		return fmt.Errorf("definition error kind = %q, want %q", refusal.Kind, want)
	}
	return nil
}
