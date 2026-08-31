package r3

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"unicode/utf8"
)

// VocabularyURI identifies one R3 operation vocabulary.
type VocabularyURI string

func (uri VocabularyURI) validate() error {
	text := string(uri)
	if !utf8.ValidString(text) || text == "" || strings.TrimSpace(text) != text {
		return errors.New("r3: vocabulary URI must be non-empty, trimmed UTF-8")
	}
	parsed, err := url.Parse(text)
	if err != nil || !parsed.IsAbs() || parsed.Scheme == "" || parsed.Fragment != "" || parsed.RawFragment != "" {
		return fmt.Errorf("r3: vocabulary URI %q must be an absolute URI without a fragment", text)
	}
	return nil
}

// setUse identifies the root-owned R3 boundary cardinality. Operation
// vocabularies parse their own grammar but never decide common set shape.
type setUse uint8

const (
	setUseRequest setUse = iota + 1
	setUseDocument
	setUseGrant
	setUseProposal
)

func (use setUse) validate() error {
	switch use {
	case setUseRequest, setUseDocument, setUseGrant, setUseProposal:
		return nil
	default:
		return fmt.Errorf("r3: invalid operation-set use %d", use)
	}
}

func validateSetCardinality(use setUse, length int) error {
	if err := use.validate(); err != nil {
		return err
	}
	switch use {
	case setUseRequest, setUseDocument:
		if length == 0 {
			return errors.New("r3: operation set must not be empty")
		}
	case setUseGrant:
		// Empty grants are valid and retain their explicit vocabulary.
	case setUseProposal:
		if length != 1 {
			return errors.New("r3: proposal must contain exactly one operation")
		}
	}
	return nil
}

// AnnotationEncoding identifies only the location and encoding mechanism a
// registered vocabulary defines for access-mode and Budget hints. Standard
// mechanisms use the constants below; third-party mechanisms use an absolute
// URI. This value does not parse, validate, apply, or enforce an annotation.
type AnnotationEncoding string

const (
	AnnotationUnavailable            AnnotationEncoding = "unavailable"
	AnnotationMCPMeta                AnnotationEncoding = "mcp-meta"
	AnnotationSpecificationExtension AnnotationEncoding = "specification-extension"
	AnnotationODataMetadata          AnnotationEncoding = "odata-metadata"
)

func (encoding AnnotationEncoding) validate() error {
	switch encoding {
	case AnnotationUnavailable, AnnotationMCPMeta, AnnotationSpecificationExtension, AnnotationODataMetadata:
		return nil
	}
	if err := VocabularyURI(encoding).validate(); err != nil {
		return fmt.Errorf("r3: custom annotation encoding must be an absolute URI: %w", err)
	}
	return nil
}

// Codec implements one operation grammar and coherent whole-set algebra.
// Implementations must be deterministic and concurrency-safe after
// registration. ParseSet and MarshalSet are semantic inverses, returned data
// is owned and copy-safe, and canonical marshal must not drop or change an
// operation. Equal, Subset, Disjoint, and Union must agree with one another.
type Codec[S any] interface {
	URI() VocabularyURI
	AnnotationEncoding() AnnotationEncoding
	// ValidateDiscoveryEndpoint validates only this vocabulary's advertised
	// discovery endpoint syntax. It does not fetch or validate the
	// authoritative operation definition at that endpoint.
	ValidateDiscoveryEndpoint(string) error
	ParseSet([]json.RawMessage) (S, error)
	MarshalSet(S) ([]json.RawMessage, error)
	Union(...S) (S, error)
	Equal(S, S) bool
	Subset(S, S) bool
	Disjoint(S, S) bool
}

// Vocabulary is one immutable, type-erased codec registration. Two values
// with the same URI but different registrations are deliberately not
// interchangeable.
type Vocabulary struct {
	uri                       VocabularyURI
	annotationEncoding        AnnotationEncoding
	identity                  *vocabularyIdentity
	validateDiscoveryEndpoint func(string) error
	normalize                 func([]json.RawMessage, setUse) ([]json.RawMessage, error)
	union                     func([]operationValue) ([]json.RawMessage, error)
	equal                     func(operationValue, operationValue) (bool, error)
	subset                    func(operationValue, operationValue) (bool, error)
	disjoint                  func(operationValue, operationValue) (bool, error)
}

type vocabularyIdentity struct{ marker byte }

// NewVocabulary erases one typed codec without retaining an any payload or
// installing it in global state.
func NewVocabulary[S any](codec Codec[S]) (Vocabulary, error) {
	uri := codec.URI()
	if err := uri.validate(); err != nil {
		return Vocabulary{}, err
	}
	annotationEncoding := codec.AnnotationEncoding()
	if err := annotationEncoding.validate(); err != nil {
		return Vocabulary{}, fmt.Errorf("r3: vocabulary %q: %w", uri, err)
	}
	identity := &vocabularyIdentity{marker: 1}

	parse := func(raw []json.RawMessage, use setUse) (S, error) {
		var zero S
		if err := validateSetCardinality(use, len(raw)); err != nil {
			return zero, err
		}
		owned := cloneRawMessages(raw)
		set, err := codec.ParseSet(owned)
		if err != nil {
			return zero, err
		}
		return set, nil
	}
	marshal := func(set S, use setUse) ([]json.RawMessage, error) {
		raw, err := codec.MarshalSet(set)
		if err != nil {
			return nil, err
		}
		if err := validateSetCardinality(use, len(raw)); err != nil {
			return nil, fmt.Errorf("r3: vocabulary %q emitted invalid operation cardinality: %w", uri, err)
		}
		for index, operation := range raw {
			if len(operation) == 0 || !json.Valid(operation) {
				return nil, fmt.Errorf("r3: vocabulary %q emitted invalid operation %d", uri, index)
			}
			var object map[string]json.RawMessage
			if err := json.Unmarshal(operation, &object); err != nil || object == nil {
				return nil, fmt.Errorf("r3: vocabulary %q emitted non-object operation %d", uri, index)
			}
		}
		return cloneRawMessages(raw), nil
	}
	normalize := func(raw []json.RawMessage, use setUse) ([]json.RawMessage, error) {
		set, err := parse(raw, use)
		if err != nil {
			return nil, err
		}
		canonical, err := marshal(set, use)
		if err != nil {
			return nil, err
		}
		if len(canonical) != len(raw) {
			return nil, fmt.Errorf(
				"r3: vocabulary %q changed operation count during normalization from %d to %d",
				uri, len(raw), len(canonical),
			)
		}
		canonicalSet, err := parse(canonical, use)
		if err != nil {
			return nil, fmt.Errorf("r3: vocabulary %q emitted an invalid canonical set: %w", uri, err)
		}
		if !codec.Equal(set, canonicalSet) {
			return nil, fmt.Errorf("r3: vocabulary %q changed operation semantics during normalization", uri)
		}
		return canonical, nil
	}
	decodeValue := func(value operationValue) (S, error) {
		var zero S
		if value.vocabulary.identity != identity || value.vocabulary.uri != uri {
			return zero, errors.New("r3: operation sets use different vocabulary registrations")
		}
		return parse(value.raw, value.use)
	}
	binary := func(
		left, right operationValue,
		apply func(S, S) bool,
	) (bool, error) {
		leftSet, err := decodeValue(left)
		if err != nil {
			return false, err
		}
		rightSet, err := decodeValue(right)
		if err != nil {
			return false, err
		}
		return apply(leftSet, rightSet), nil
	}

	return Vocabulary{
		uri: uri, annotationEncoding: annotationEncoding, identity: identity,
		validateDiscoveryEndpoint: codec.ValidateDiscoveryEndpoint,
		normalize:                 normalize,
		union: func(values []operationValue) ([]json.RawMessage, error) {
			sets := make([]S, len(values))
			for index, value := range values {
				set, err := decodeValue(value)
				if err != nil {
					return nil, err
				}
				sets[index] = set
			}
			union, err := codec.Union(sets...)
			if err != nil {
				return nil, err
			}
			return marshal(union, setUseDocument)
		},
		equal: func(left, right operationValue) (bool, error) {
			return binary(left, right, codec.Equal)
		},
		subset: func(left, right operationValue) (bool, error) {
			return binary(left, right, codec.Subset)
		},
		disjoint: func(left, right operationValue) (bool, error) {
			return binary(left, right, codec.Disjoint)
		},
	}, nil
}

// URI returns the exact registered vocabulary URI.
func (v Vocabulary) URI() VocabularyURI { return v.uri }

// AnnotationEncoding reports the registered vocabulary's annotation
// mechanism, or AnnotationUnavailable when it defines none.
func (v Vocabulary) AnnotationEncoding() AnnotationEncoding { return v.annotationEncoding }

// ValidateDiscoveryEndpoint applies the registered vocabulary's endpoint
// grammar. It does not fetch or validate an authoritative operation
// definition or its annotations.
func (v Vocabulary) ValidateDiscoveryEndpoint(endpoint string) error {
	if err := v.validate(); err != nil {
		return err
	}
	if err := v.validateDiscoveryEndpoint(endpoint); err != nil {
		return fmt.Errorf("r3: vocabulary %q discovery endpoint: %w", v.uri, err)
	}
	return nil
}

func (v Vocabulary) validate() error {
	if err := v.uri.validate(); err != nil {
		return err
	}
	if err := v.annotationEncoding.validate(); err != nil {
		return err
	}
	if v.identity == nil || v.validateDiscoveryEndpoint == nil || v.normalize == nil || v.union == nil || v.equal == nil || v.subset == nil || v.disjoint == nil {
		return fmt.Errorf("r3: vocabulary %q is uninitialized", v.uri)
	}
	return nil
}

type operationValue struct {
	vocabulary Vocabulary
	use        setUse
	raw        []json.RawMessage
}

func (value operationValue) clone() operationValue {
	return operationValue{vocabulary: value.vocabulary, use: value.use, raw: cloneRawMessages(value.raw)}
}

func (value operationValue) validate() error {
	if err := value.vocabulary.validate(); err != nil {
		return err
	}
	if err := value.use.validate(); err != nil {
		return err
	}
	_, err := value.vocabulary.normalize(value.raw, value.use)
	return err
}

func newOperationValue(vocabulary Vocabulary, raw []json.RawMessage, use setUse) (operationValue, error) {
	if err := vocabulary.validate(); err != nil {
		return operationValue{}, err
	}
	canonical, err := vocabulary.normalize(raw, use)
	if err != nil {
		return operationValue{}, fmt.Errorf("r3: invalid %q operations: %w", vocabulary.uri, err)
	}
	return operationValue{vocabulary: vocabulary, use: use, raw: canonical}, nil
}

func compatibleOperations(left, right operationValue) error {
	if err := left.validate(); err != nil {
		return err
	}
	if err := right.validate(); err != nil {
		return err
	}
	if left.vocabulary.uri != right.vocabulary.uri {
		return fmt.Errorf("r3: operation vocabularies differ: %q and %q", left.vocabulary.uri, right.vocabulary.uri)
	}
	if left.vocabulary.identity != right.vocabulary.identity {
		return fmt.Errorf("r3: vocabulary %q uses different registrations", left.vocabulary.uri)
	}
	return nil
}

// Operation is one vocabulary-tagged R3 operation.
type Operation struct{ value operationValue }

// NewOperation parses one operation through the supplied allowlisted
// vocabulary.
func NewOperation(vocabulary Vocabulary, raw json.RawMessage) (Operation, error) {
	value, err := newOperationValue(vocabulary, []json.RawMessage{raw}, setUseProposal)
	if err != nil {
		return Operation{}, err
	}
	if len(value.raw) != 1 {
		return Operation{}, errors.New("r3: vocabulary did not preserve one proposal operation")
	}
	return Operation{value: value}, nil
}

// Vocabulary returns the operation's vocabulary URI.
func (operation Operation) Vocabulary() VocabularyURI { return operation.value.vocabulary.uri }

// JSON returns an owned canonical operation object.
func (operation Operation) JSON() []byte {
	if operation.value.validate() != nil || len(operation.value.raw) != 1 {
		return nil
	}
	return append([]byte(nil), operation.value.raw[0]...)
}

// MarshalJSON refuses to drop the vocabulary envelope. Use JSON only when an
// enclosing registered value supplies that context.
func (Operation) MarshalJSON() ([]byte, error) {
	return nil, errors.New("r3: Operation has no context-free JSON form; use Operation.JSON inside a registered vocabulary envelope")
}

// UnmarshalJSON refuses parsing without an explicit vocabulary registration.
func (*Operation) UnmarshalJSON([]byte) error {
	return errors.New("r3: Operation requires a vocabulary; use NewOperation or a typed vocabulary adapter")
}

// Equal reports vocabulary-semantic operation equality.
func (operation Operation) Equal(other Operation) (bool, error) {
	if err := compatibleOperations(operation.value, other.value); err != nil {
		return false, err
	}
	return operation.value.vocabulary.equal(operation.value, other.value)
}

// OperationSet is a non-empty, homogeneous R3 operation set.
type OperationSet struct{ value operationValue }

// NewOperationSet constructs a homogeneous set from validated operations.
func NewOperationSet(operations ...Operation) (OperationSet, error) {
	if len(operations) == 0 {
		return OperationSet{}, errors.New("r3: operation set must not be empty")
	}
	vocabulary := operations[0].value.vocabulary
	raw := make([]json.RawMessage, len(operations))
	for index, operation := range operations {
		if err := compatibleOperations(operations[0].value, operation.value); err != nil {
			return OperationSet{}, fmt.Errorf("r3: operation %d: %w", index, err)
		}
		if len(operation.value.raw) != 1 {
			return OperationSet{}, fmt.Errorf("r3: operation %d is not singular", index)
		}
		raw[index] = operation.value.raw[0]
	}
	value, err := newOperationValue(vocabulary, raw, setUseRequest)
	if err != nil {
		return OperationSet{}, err
	}
	return OperationSet{value: value}, nil
}

func newParsedOperationSet(vocabulary Vocabulary, raw []json.RawMessage, use setUse) (OperationSet, error) {
	value, err := newOperationValue(vocabulary, raw, use)
	if err != nil {
		return OperationSet{}, err
	}
	return OperationSet{value: value}, nil
}

// Vocabulary returns the operation set's vocabulary URI.
func (set OperationSet) Vocabulary() VocabularyURI { return set.value.vocabulary.uri }

// Operations returns the set's operations in retained wire order.
func (set OperationSet) Operations() []Operation {
	if set.value.validate() != nil {
		return nil
	}
	operations := make([]Operation, len(set.value.raw))
	for index, raw := range set.value.raw {
		value, err := newOperationValue(set.value.vocabulary, []json.RawMessage{raw}, setUseProposal)
		if err != nil {
			return nil
		}
		operations[index] = Operation{value: value}
	}
	return operations
}

// Equal reports vocabulary-semantic set equality.
func (set OperationSet) Equal(other OperationSet) (bool, error) {
	if err := compatibleOperations(set.value, other.value); err != nil {
		return false, err
	}
	return set.value.vocabulary.equal(set.value, other.value)
}

// IsSubsetOf reports vocabulary-semantic containment.
func (set OperationSet) IsSubsetOf(other OperationSet) (bool, error) {
	if err := compatibleOperations(set.value, other.value); err != nil {
		return false, err
	}
	return set.value.vocabulary.subset(set.value, other.value)
}

// Disjoint reports whether the sets contain no overlapping authorization.
func (set OperationSet) Disjoint(other OperationSet) (bool, error) {
	if err := compatibleOperations(set.value, other.value); err != nil {
		return false, err
	}
	return set.value.vocabulary.disjoint(set.value, other.value)
}

// Union composes operation sets using vocabulary-defined semantics.
func (set OperationSet) Union(others ...OperationSet) (OperationSet, error) {
	if err := set.value.validate(); err != nil {
		return OperationSet{}, err
	}
	values := make([]operationValue, 1, len(others)+1)
	values[0] = set.value
	for index, other := range others {
		if err := compatibleOperations(set.value, other.value); err != nil {
			return OperationSet{}, fmt.Errorf("r3: union operand %d: %w", index+1, err)
		}
		values = append(values, other.value)
	}
	raw, err := set.value.vocabulary.union(values)
	if err != nil {
		return OperationSet{}, err
	}
	return newParsedOperationSet(set.value.vocabulary, raw, setUseDocument)
}

// MarshalJSON emits the shared vocabulary/operations envelope.
func (set OperationSet) MarshalJSON() ([]byte, error) {
	if err := set.value.validate(); err != nil {
		return nil, err
	}
	return marshalOperationEnvelope(set.value)
}

// UnmarshalJSON refuses parsing without an explicit vocabulary registry.
func (*OperationSet) UnmarshalJSON([]byte) error {
	return errors.New("r3: OperationSet requires a registry; use Registry.ParseOperationSet")
}

func marshalOperationEnvelope(value operationValue) ([]byte, error) {
	operations := cloneRawMessages(value.raw)
	if operations == nil {
		operations = []json.RawMessage{}
	}
	return json.Marshal(struct {
		Vocabulary VocabularyURI     `json:"vocabulary"`
		Operations []json.RawMessage `json:"operations"`
	}{Vocabulary: value.vocabulary.uri, Operations: operations})
}

// Registry is an immutable allowlist of R3 vocabularies.
type Registry struct{ vocabularies map[VocabularyURI]Vocabulary }

// NewRegistry constructs an explicit vocabulary allowlist.
func NewRegistry(vocabularies ...Vocabulary) (Registry, error) {
	registry := Registry{vocabularies: make(map[VocabularyURI]Vocabulary, len(vocabularies))}
	for index, vocabulary := range vocabularies {
		if err := vocabulary.validate(); err != nil {
			return Registry{}, fmt.Errorf("r3: vocabulary %d: %w", index, err)
		}
		if _, duplicate := registry.vocabularies[vocabulary.uri]; duplicate {
			return Registry{}, fmt.Errorf("r3: duplicate vocabulary URI %q", vocabulary.uri)
		}
		registry.vocabularies[vocabulary.uri] = vocabulary
	}
	return registry, nil
}

// Vocabulary returns one allowlisted registration.
func (registry Registry) Vocabulary(uri VocabularyURI) (Vocabulary, bool) {
	vocabulary, ok := registry.vocabularies[uri]
	return vocabulary, ok
}

// Len reports the number of explicitly allowlisted vocabularies.
func (registry Registry) Len() int { return len(registry.vocabularies) }

// ValidateOperationSet proves that set was constructed by this registry's
// exact allowlisted registration, not merely another codec using the same URI.
func (registry Registry) ValidateOperationSet(set OperationSet) error {
	if err := set.value.validate(); err != nil {
		return err
	}
	registered, ok := registry.vocabularies[set.value.vocabulary.uri]
	if !ok {
		return fmt.Errorf("r3: vocabulary %q is not registered", set.value.vocabulary.uri)
	}
	if registered.identity != set.value.vocabulary.identity {
		return fmt.Errorf("r3: vocabulary %q uses a different registration", set.value.vocabulary.uri)
	}
	return nil
}

// ParseOperationSet strictly parses one non-empty operations envelope and
// dispatches to exactly the vocabulary named by that envelope.
func (registry Registry) ParseOperationSet(source []byte) (OperationSet, error) {
	uri, raw, err := parseOperationEnvelope(source)
	if err != nil {
		return OperationSet{}, err
	}
	vocabulary, ok := registry.vocabularies[uri]
	if !ok {
		return OperationSet{}, fmt.Errorf("r3: vocabulary %q is not registered", uri)
	}
	return newParsedOperationSet(vocabulary, raw, setUseRequest)
}

func parseOperationEnvelope(source []byte) (VocabularyURI, []json.RawMessage, error) {
	var uri string
	var operationsRaw json.RawMessage
	seen, err := decodeStrictObject(source, map[string]func(json.RawMessage) error{
		"vocabulary": func(raw json.RawMessage) error { return decodeJSONString(raw, &uri) },
		"operations": func(raw json.RawMessage) error {
			operationsRaw = append(operationsRaw[:0], raw...)
			return nil
		},
	})
	if err != nil {
		return "", nil, fmt.Errorf("r3: invalid operation set: %w", err)
	}
	if _, ok := seen["vocabulary"]; !ok {
		return "", nil, errors.New("r3: operation set is missing vocabulary")
	}
	if _, ok := seen["operations"]; !ok {
		return "", nil, errors.New("r3: operation set is missing operations")
	}
	vocabularyURI := VocabularyURI(uri)
	if err := vocabularyURI.validate(); err != nil {
		return "", nil, err
	}
	operations, err := decodeJSONArray(operationsRaw)
	if err != nil {
		return "", nil, fmt.Errorf("r3: invalid operations: %w", err)
	}
	return vocabularyURI, operations, nil
}

func cloneRawMessages(values []json.RawMessage) []json.RawMessage {
	if values == nil {
		return nil
	}
	cloned := make([]json.RawMessage, len(values))
	for index, value := range values {
		cloned[index] = append(json.RawMessage(nil), value...)
	}
	return cloned
}
