package resource

import (
	"context"
	"errors"
	"fmt"

	"gitlab.com/sidecat-dev/aauth-go/r3"
)

// R3InternalDefinition is one of the Resource's own authorization
// definitions within a vocabulary, for example one per scope or operation
// group. R3 lets a Resource organize its definitions this way and keeps the
// organization opaque: an agent request whose operations fall under more
// than one definition still yields one Resource token naming one composed R3
// document. That document's operations are the requested operations, and its
// display merges the display of every definition the request draws from with
// r3.MergeDisplays, unless DisplayForOperations writes a summary for the
// combination.
type R3InternalDefinition struct {
	// Name identifies the definition in errors and to DisplayForOperations.
	Name string
	// Operations are the operations this definition covers. Each must be
	// defined by the vocabulary's authoritative snapshot.
	Operations r3.OperationSet
	// Display describes granting this definition's operations.
	Display r3.Display
}

type r3InternalDefinition struct {
	name       string
	operations r3.OperationSet
	display    r3.Display
}

func validateR3InternalDefinitions(
	uri r3.VocabularyURI,
	snapshot r3.AuthoritativeSnapshot,
	definitions []R3InternalDefinition,
) ([]r3InternalDefinition, error) {
	if len(definitions) == 0 {
		return nil, nil
	}
	validated := make([]r3InternalDefinition, 0, len(definitions))
	sets := make([]r3.OperationSet, 0, len(definitions))
	for index, definition := range definitions {
		if definition.Name == "" {
			return nil, fmt.Errorf("aauth: Resource R3 vocabulary %q internal definition %d requires a name", uri, index)
		}
		for _, earlier := range validated {
			if earlier.name == definition.Name {
				return nil, fmt.Errorf("aauth: Resource R3 vocabulary %q repeats internal definition %q", uri, definition.Name)
			}
		}
		if definition.Operations.Vocabulary() != uri {
			return nil, fmt.Errorf("aauth: Resource R3 internal definition %q is not in vocabulary %q", definition.Name, uri)
		}
		if err := snapshot.ValidateDefined(definition.Operations); err != nil {
			return nil, fmt.Errorf("aauth: Resource R3 internal definition %q: %w", definition.Name, err)
		}
		if _, err := r3.MergeDisplays(definition.Display); err != nil {
			return nil, fmt.Errorf("aauth: Resource R3 internal definition %q display: %w", definition.Name, err)
		}
		validated = append(validated, r3InternalDefinition{
			name: definition.Name, operations: definition.Operations, display: definition.Display,
		})
		sets = append(sets, definition.Operations)
	}
	covered, err := sets[0].Union(sets[1:]...)
	if err != nil {
		return nil, fmt.Errorf("aauth: Resource R3 vocabulary %q internal definitions: %w", uri, err)
	}
	whole, err := snapshot.Operations().IsSubsetOf(covered)
	if err != nil {
		return nil, fmt.Errorf("aauth: Resource R3 vocabulary %q internal definitions: %w", uri, err)
	}
	if !whole {
		return nil, fmt.Errorf("aauth: Resource R3 vocabulary %q has operations outside every internal definition", uri)
	}
	return validated, nil
}

// definitionsFor returns the internal definitions the requested operations
// draw from.
func (vocabulary r3VocabularyConfig) definitionsFor(operations r3.OperationSet) ([]r3InternalDefinition, error) {
	var involved []r3InternalDefinition
	for _, definition := range vocabulary.internalDefinitions {
		disjoint, err := operations.Disjoint(definition.operations)
		if err != nil {
			return nil, err
		}
		if !disjoint {
			involved = append(involved, definition)
		}
	}
	return involved, nil
}

// documentDisplay is the display of the one R3 document a Resource token
// names. A host DisplayForOperations writes it for the exact combination.
// Without one, a Resource with internal definitions merges the display of
// each definition the request draws from, and a Resource without them sends
// none.
func (vocabulary r3VocabularyConfig) documentDisplay(
	ctx context.Context,
	operations r3.OperationSet,
	account *string,
) (*r3.Display, error) {
	if vocabulary.displayForOperations != nil {
		display, err := vocabulary.displayForOperations(ctx, operations, cloneAuthorizationAccount(account))
		if err != nil {
			return nil, fmt.Errorf("aauth: describe R3 operations: %w", err)
		}
		return display, nil
	}
	if len(vocabulary.internalDefinitions) == 0 {
		return nil, nil
	}
	involved, err := vocabulary.definitionsFor(operations)
	if err != nil {
		return nil, err
	}
	if len(involved) == 0 {
		return nil, errors.New("aauth: requested R3 operations fall under no internal definition")
	}
	displays := make([]r3.Display, len(involved))
	for index, definition := range involved {
		displays[index] = definition.display
	}
	merged, err := r3.MergeDisplays(displays...)
	if err != nil {
		return nil, fmt.Errorf("aauth: compose R3 display: %w", err)
	}
	return &merged, nil
}
