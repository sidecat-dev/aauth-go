package r3

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"
)

// DefinitionErrorKind classifies why an authoritative vocabulary source
// could not be reduced to R3-identifiable operations.
type DefinitionErrorKind string

const (
	DefinitionInvalidSource         DefinitionErrorKind = "invalid_source"
	DefinitionIncompleteSource      DefinitionErrorKind = "incomplete_source"
	DefinitionUnresolvedDependency  DefinitionErrorKind = "unresolved_dependency"
	DefinitionSourceKindUnsupported DefinitionErrorKind = "source_kind_unsupported"
	DefinitionIdentityUnavailable   DefinitionErrorKind = "operation_identity_unavailable"
	DefinitionIdentityAmbiguous     DefinitionErrorKind = "operation_identity_ambiguous"
	DefinitionInvalidAnnotation     DefinitionErrorKind = "invalid_annotation"
	DefinitionOperationNotDefined   DefinitionErrorKind = "operation_not_defined"
)

// DefinitionError is a stable refusal from native definition parsing.
type DefinitionError struct {
	Kind       DefinitionErrorKind
	Vocabulary VocabularyURI
	Reason     string
	cause      error
}

// NewDefinitionError constructs a typed adapter refusal. DefinitionParser
// adds the exact registered vocabulary URI.
func NewDefinitionError(kind DefinitionErrorKind, reason string, cause error) error {
	return &DefinitionError{Kind: kind, Reason: reason, cause: cause}
}

func (failure *DefinitionError) Error() string {
	if failure == nil {
		return "r3: definition refusal is nil"
	}
	prefix := "r3: definition"
	if failure.Vocabulary != "" {
		prefix += " " + fmt.Sprintf("%q", failure.Vocabulary)
	}
	message := prefix + " refused with " + string(failure.Kind)
	if failure.Reason != "" {
		message += ": " + failure.Reason
	}
	if failure.cause != nil {
		message += ": " + failure.cause.Error()
	}
	return message
}

// Unwrap returns the format-specific cause, when one was retained.
func (failure *DefinitionError) Unwrap() error {
	if failure == nil {
		return nil
	}
	return failure.cause
}

func (kind DefinitionErrorKind) validate() error {
	switch kind {
	case DefinitionInvalidSource, DefinitionIncompleteSource, DefinitionUnresolvedDependency,
		DefinitionSourceKindUnsupported, DefinitionIdentityUnavailable,
		DefinitionIdentityAmbiguous, DefinitionInvalidAnnotation,
		DefinitionOperationNotDefined:
		return nil
	default:
		return fmt.Errorf("r3: unknown definition refusal kind %q", kind)
	}
}

// SourceEncoding names the exact byte encoding covered by a SourceReceipt.
// Document adapters normally use a media type; multipart discovery adapters
// use a namespaced manifest encoding.
type SourceEncoding string

func (encoding SourceEncoding) validate() error {
	value := string(encoding)
	if !utf8.ValidString(value) || value == "" || strings.TrimSpace(value) != value {
		return errors.New("r3: definition source encoding must be non-empty, trimmed UTF-8")
	}
	return nil
}

// DefinedOperation is one adapter-derived operation plus optional advisory
// hints. Its constructor owns both values.
type DefinedOperation struct {
	raw    json.RawMessage
	hints  OperationHints
	hinted bool
}

// NewDefinedOperation copies one native-derived R3 operation. A nil hints
// pointer means the source published no AAuth annotations for this operation.
func NewDefinedOperation(raw json.RawMessage, hints *OperationHints) (DefinedOperation, error) {
	if len(raw) == 0 || !json.Valid(raw) {
		return DefinedOperation{}, errors.New("r3: defined operation must be valid JSON")
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil || object == nil {
		return DefinedOperation{}, errors.New("r3: defined operation must be a JSON object")
	}
	operation := DefinedOperation{raw: append(json.RawMessage(nil), raw...)}
	if hints != nil {
		if err := hints.validate(); err != nil {
			return DefinedOperation{}, err
		}
		operation.hints = hints.clone()
		operation.hinted = true
	}
	return operation, nil
}

func (operation DefinedOperation) clone() DefinedOperation {
	return DefinedOperation{
		raw:   append(json.RawMessage(nil), operation.raw...),
		hints: operation.hints.clone(), hinted: operation.hinted,
	}
}

// DefinitionMaterial is the bounded output of one atomic native parse. It
// contains only an exact digest input and copied derived values—never a parser
// AST, resolver, transport, cache, policy, or lifecycle object.
type DefinitionMaterial struct {
	encoding    SourceEncoding
	digestInput []byte
	operations  []DefinedOperation
}

// NewDefinitionMaterial owns the exact receipt input and all derived
// operations. Empty receipt input cannot identify a nonempty definition.
func NewDefinitionMaterial(
	encoding SourceEncoding,
	digestInput []byte,
	operations ...DefinedOperation,
) (DefinitionMaterial, error) {
	if err := encoding.validate(); err != nil {
		return DefinitionMaterial{}, err
	}
	if len(digestInput) == 0 {
		return DefinitionMaterial{}, errors.New("r3: definition receipt input must not be empty")
	}
	if len(operations) == 0 {
		return DefinitionMaterial{}, errors.New("r3: definition must derive at least one operation")
	}
	material := DefinitionMaterial{
		encoding:    encoding,
		digestInput: append([]byte(nil), digestInput...),
		operations:  make([]DefinedOperation, len(operations)),
	}
	for index, operation := range operations {
		if len(operation.raw) == 0 {
			return DefinitionMaterial{}, fmt.Errorf("r3: defined operation %d is uninitialized", index)
		}
		if operation.hinted {
			if err := operation.hints.validate(); err != nil {
				return DefinitionMaterial{}, fmt.Errorf("r3: defined operation %d hints: %w", index, err)
			}
		}
		material.operations[index] = operation.clone()
	}
	return material, nil
}

func (material DefinitionMaterial) validate() error {
	if err := material.encoding.validate(); err != nil {
		return err
	}
	if len(material.digestInput) == 0 || len(material.operations) == 0 {
		return errors.New("r3: definition material is incomplete")
	}
	for index, operation := range material.operations {
		if len(operation.raw) == 0 || !json.Valid(operation.raw) {
			return fmt.Errorf("r3: defined operation %d is invalid", index)
		}
		if operation.hinted {
			if err := operation.hints.validate(); err != nil {
				return fmt.Errorf("r3: defined operation %d hints: %w", index, err)
			}
		}
	}
	return nil
}

// DefinitionCodec atomically owns and parses one vocabulary-native source.
// Implementations must be deterministic, concurrency-safe, and free of I/O.
// Digest input, operations, and hints must come from the same source
// observation. External acquisition and dependency resolution remain caller
// responsibilities; an adapter may resolve dependencies contained in the
// supplied source.
type DefinitionCodec[S any] interface {
	Vocabulary() Vocabulary
	ParseDefinition(S) (DefinitionMaterial, error)
}

// DefinitionParser is one immutable parser over a vocabulary-native source.
type DefinitionParser[S any] struct {
	vocabulary Vocabulary
	identity   *definitionIdentity
	codec      DefinitionCodec[S]
}

type definitionIdentity struct{ marker byte }

// NewDefinitionParser binds a native definition codec to its exact operation
// vocabulary registration.
func NewDefinitionParser[S any](codec DefinitionCodec[S]) (DefinitionParser[S], error) {
	if codec == nil {
		return DefinitionParser[S]{}, errors.New("r3: definition codec is required")
	}
	vocabulary := codec.Vocabulary()
	if err := vocabulary.validate(); err != nil {
		return DefinitionParser[S]{}, fmt.Errorf("r3: definition vocabulary: %w", err)
	}
	return DefinitionParser[S]{
		vocabulary: vocabulary,
		identity:   &definitionIdentity{marker: 1},
		codec:      codec,
	}, nil
}

func (parser DefinitionParser[S]) validate() error {
	if err := parser.vocabulary.validate(); err != nil {
		return err
	}
	if parser.identity == nil || parser.codec == nil {
		return fmt.Errorf("r3: definition parser %q is uninitialized", parser.vocabulary.uri)
	}
	return nil
}

// Registration returns the type-erased identity used only for explicit
// allowlisting. Parsing remains typed to the vocabulary's native source.
func (parser DefinitionParser[S]) Registration() DefinitionRegistration {
	return DefinitionRegistration{uri: parser.vocabulary.uri, identity: parser.identity}
}

// Parse atomically reduces one native source to a copied, source-bound
// authoritative snapshot. It performs no I/O.
func (parser DefinitionParser[S]) Parse(endpoint string, source S) (AuthoritativeSnapshot, error) {
	if err := parser.validate(); err != nil {
		return AuthoritativeSnapshot{}, err
	}
	if err := parser.vocabulary.ValidateDiscoveryEndpoint(endpoint); err != nil {
		return AuthoritativeSnapshot{}, definitionFailure(parser.vocabulary.uri, DefinitionInvalidSource, "invalid discovery endpoint", err)
	}
	material, err := parser.codec.ParseDefinition(source)
	if err != nil {
		return AuthoritativeSnapshot{}, attachDefinitionVocabulary(parser.vocabulary.uri, err)
	}
	if err := material.validate(); err != nil {
		return AuthoritativeSnapshot{}, definitionFailure(parser.vocabulary.uri, DefinitionInvalidSource, "invalid definition material", err)
	}
	raw := make([]json.RawMessage, len(material.operations))
	hints := make(map[string]OperationHints)
	for index, operation := range material.operations {
		raw[index] = append(json.RawMessage(nil), operation.raw...)
		if operation.hinted {
			canonical, err := NewOperation(parser.vocabulary, operation.raw)
			if err != nil {
				return AuthoritativeSnapshot{}, definitionFailure(parser.vocabulary.uri, DefinitionInvalidSource, "derived operation is invalid", err)
			}
			hints[string(canonical.JSON())] = operation.hints.clone()
		}
	}
	operations, err := newParsedOperationSet(parser.vocabulary, raw, setUseDocument)
	if err != nil {
		return AuthoritativeSnapshot{}, definitionFailure(parser.vocabulary.uri, DefinitionInvalidSource, "derived operations are invalid", err)
	}
	return AuthoritativeSnapshot{
		parserIdentity: parser.identity,
		operations:     operations,
		receipt: SourceReceipt{
			encoding:   material.encoding,
			endpoint:   endpoint,
			digest:     Digest(material.digestInput),
			byteLength: int64(len(material.digestInput)),
		},
		hints: hints,
	}, nil
}

// DefinitionRegistration is the type-erased identity of one native parser.
type DefinitionRegistration struct {
	uri      VocabularyURI
	identity *definitionIdentity
}

func (registration DefinitionRegistration) validate() error {
	if err := registration.uri.validate(); err != nil {
		return err
	}
	if registration.identity == nil {
		return fmt.Errorf("r3: definition registration %q is uninitialized", registration.uri)
	}
	return nil
}

// DefinitionRegistry prevents accidental mixing of snapshots from different
// parser registrations. It does not attest that a host chose a trustworthy
// parser or source.
type DefinitionRegistry struct {
	registrations map[VocabularyURI]DefinitionRegistration
}

// NewDefinitionRegistry constructs an explicit parser-registration allowlist.
func NewDefinitionRegistry(registrations ...DefinitionRegistration) (DefinitionRegistry, error) {
	registry := DefinitionRegistry{registrations: make(map[VocabularyURI]DefinitionRegistration, len(registrations))}
	for index, registration := range registrations {
		if err := registration.validate(); err != nil {
			return DefinitionRegistry{}, fmt.Errorf("r3: definition registration %d: %w", index, err)
		}
		if _, duplicate := registry.registrations[registration.uri]; duplicate {
			return DefinitionRegistry{}, fmt.Errorf("r3: duplicate definition parser for vocabulary %q", registration.uri)
		}
		registry.registrations[registration.uri] = registration
	}
	return registry, nil
}

// Len reports the number of explicitly allowlisted definition parsers.
func (registry DefinitionRegistry) Len() int { return len(registry.registrations) }

// Contains reports whether uri has an explicitly allowlisted native parser.
func (registry DefinitionRegistry) Contains(uri VocabularyURI) bool {
	_, present := registry.registrations[uri]
	return present
}

// Validate rejects accidental parser-registration mismatches.
func (registry DefinitionRegistry) Validate(snapshot AuthoritativeSnapshot) error {
	if err := snapshot.validate(); err != nil {
		return err
	}
	registration, ok := registry.registrations[snapshot.Vocabulary()]
	if !ok {
		return fmt.Errorf("r3: definition parser for vocabulary %q is not registered", snapshot.Vocabulary())
	}
	if registration.identity != snapshot.parserIdentity {
		return fmt.Errorf("r3: definition snapshot for vocabulary %q uses another parser registration", snapshot.Vocabulary())
	}
	return nil
}

// SourceReceipt identifies the exact digest-input encoding used by one native
// parser. ByteLength measures that encoding, which may be a document,
// descriptor set, or framed multipart manifest.
type SourceReceipt struct {
	encoding   SourceEncoding
	endpoint   string
	digest     string
	byteLength int64
}

// Encoding identifies how the exact digest input was formed.
func (receipt SourceReceipt) Encoding() SourceEncoding { return receipt.encoding }

// DiscoveryEndpoint returns the advertised vocabulary discovery endpoint.
func (receipt SourceReceipt) DiscoveryEndpoint() string { return receipt.endpoint }

// Digest returns unpadded base64url SHA-256 over the encoded receipt input.
func (receipt SourceReceipt) Digest() string { return receipt.digest }

// ByteLength returns the encoded receipt-input length.
func (receipt SourceReceipt) ByteLength() int64 { return receipt.byteLength }

// AuthoritativeSnapshot is a copied operation and hint view. It owns no raw
// source, AST, transport, resolver, cache, policy, token, or lifecycle state.
type AuthoritativeSnapshot struct {
	parserIdentity *definitionIdentity
	operations     OperationSet
	receipt        SourceReceipt
	hints          map[string]OperationHints
}

// Vocabulary returns the snapshot's exact operation vocabulary.
func (snapshot AuthoritativeSnapshot) Vocabulary() VocabularyURI {
	return snapshot.operations.Vocabulary()
}

// Receipt returns the exact parser digest-input receipt.
func (snapshot AuthoritativeSnapshot) Receipt() SourceReceipt { return snapshot.receipt }

// Operations returns the immutable derived operation set.
func (snapshot AuthoritativeSnapshot) Operations() OperationSet { return snapshot.operations }

// ValidateDefined verifies semantic containment in the copied authoritative
// operation set. It never invokes the source codec again.
func (snapshot AuthoritativeSnapshot) ValidateDefined(declared OperationSet) error {
	if err := snapshot.validate(); err != nil {
		return err
	}
	known, err := declared.IsSubsetOf(snapshot.operations)
	if err != nil {
		return err
	}
	if !known {
		return definitionFailure(snapshot.Vocabulary(), DefinitionOperationNotDefined, "declared operation is outside the authoritative source", nil)
	}
	return nil
}

// HintsFor returns copied sparse advisory hints for one operation in the
// snapshot.
func (snapshot AuthoritativeSnapshot) HintsFor(operation Operation) (OperationHints, bool, error) {
	if err := snapshot.validate(); err != nil {
		return OperationHints{}, false, err
	}
	if err := compatibleOperations(snapshot.operations.value, operation.value); err != nil {
		return OperationHints{}, false, err
	}
	for _, candidate := range snapshot.operations.Operations() {
		equal, err := candidate.Equal(operation)
		if err != nil {
			return OperationHints{}, false, err
		}
		if equal {
			hints, ok := snapshot.hints[string(candidate.JSON())]
			return hints.clone(), ok, nil
		}
	}
	return OperationHints{}, false, definitionFailure(
		snapshot.Vocabulary(),
		DefinitionOperationNotDefined,
		"operation is outside the authoritative source",
		nil,
	)
}

func (snapshot AuthoritativeSnapshot) validate() error {
	if snapshot.parserIdentity == nil {
		return errors.New("r3: authoritative snapshot is uninitialized")
	}
	if err := snapshot.operations.value.validate(); err != nil {
		return err
	}
	if err := snapshot.receipt.encoding.validate(); err != nil {
		return err
	}
	if snapshot.receipt.endpoint == "" || snapshot.receipt.digest == "" || snapshot.receipt.byteLength <= 0 {
		return errors.New("r3: authoritative snapshot receipt is incomplete")
	}
	for _, hints := range snapshot.hints {
		if err := hints.validate(); err != nil {
			return err
		}
	}
	return nil
}

func attachDefinitionVocabulary(uri VocabularyURI, err error) error {
	var typed *DefinitionError
	if !errors.As(err, &typed) {
		return definitionFailure(uri, DefinitionInvalidSource, "parse authoritative definition", err)
	}
	copy := *typed
	if err := copy.Kind.validate(); err != nil {
		return definitionFailure(uri, DefinitionInvalidSource, "parser returned an unknown refusal kind", err)
	}
	if copy.Vocabulary != "" && copy.Vocabulary != uri {
		return definitionFailure(uri, DefinitionInvalidSource, "parser returned a refusal for another vocabulary", err)
	}
	copy.Vocabulary = uri
	return &copy
}

func definitionFailure(uri VocabularyURI, kind DefinitionErrorKind, reason string, cause error) error {
	return &DefinitionError{Kind: kind, Vocabulary: uri, Reason: reason, cause: cause}
}
