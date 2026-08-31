// Package graphql implements the R3 GraphQL operation-object grammar and set algebra.
package graphql

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"unicode/utf8"

	"aauth-go/r3"
	"aauth-go/r3/internal/wirejson"
	"aauth-go/r3/vocab/internal/discoveryendpoint"
)

// URI is the standard R3 GraphQL vocabulary URI.
const URI r3.VocabularyURI = "urn:aauth:vocabulary:graphql"

// OperationType is one of the GraphQL operation types defined by R3.
type OperationType string

const (
	// Query identifies a named GraphQL query.
	Query OperationType = "query"
	// Mutation identifies a named GraphQL mutation.
	Mutation OperationType = "mutation"
	// Subscription identifies a named GraphQL subscription.
	Subscription OperationType = "subscription"
)

// Operation identifies one named GraphQL query, mutation, or subscription.
type Operation struct {
	name          string
	operationType OperationType
}

// NewOperation constructs a validated named GraphQL operation.
func NewOperation(name string, operationType OperationType) (Operation, error) {
	operation := Operation{name: name, operationType: operationType}
	if err := operation.validate(); err != nil {
		return Operation{}, err
	}
	return operation, nil
}

func (operation Operation) validate() error {
	if !utf8.ValidString(operation.name) || operation.name == "" || strings.TrimSpace(operation.name) != operation.name || !validGraphQLName(operation.name) {
		return errors.New("r3/graphql: operation must be a valid GraphQL name")
	}
	switch operation.operationType {
	case Query, Mutation, Subscription:
		return nil
	default:
		return fmt.Errorf("r3/graphql: invalid operation type %q", operation.operationType)
	}
}

func validGraphQLName(value string) bool {
	if value == "" || !isGraphQLNameStart(value[0]) {
		return false
	}
	for index := 1; index < len(value); index++ {
		if !isGraphQLNameStart(value[index]) && (value[index] < '0' || value[index] > '9') {
			return false
		}
	}
	return true
}

func isGraphQLNameStart(value byte) bool {
	return value == '_' || value >= 'A' && value <= 'Z' || value >= 'a' && value <= 'z'
}

// OperationName returns the named GraphQL operation.
func (operation Operation) OperationName() string { return operation.name }

// Type returns the GraphQL operation type.
func (operation Operation) Type() OperationType { return operation.operationType }

// MarshalJSON emits the exact GraphQL R3 operation object.
func (operation Operation) MarshalJSON() ([]byte, error) {
	if err := operation.validate(); err != nil {
		return nil, err
	}
	return json.Marshal(struct {
		Operation string        `json:"operation"`
		Type      OperationType `json:"type"`
	}{Operation: operation.name, Type: operation.operationType})
}

// UnmarshalJSON accepts only the exact GraphQL R3 operation object.
func (operation *Operation) UnmarshalJSON(source []byte) error {
	parsed, err := parseOperation(source)
	if err != nil {
		return err
	}
	*operation = parsed
	return nil
}

func parseOperation(source []byte) (Operation, error) {
	var name, operationType string
	seen, err := wirejson.Object(source, map[string]func(json.RawMessage) error{
		"operation": func(raw json.RawMessage) error { return wirejson.String(raw, &name) },
		"type":      func(raw json.RawMessage) error { return wirejson.String(raw, &operationType) },
	})
	if err != nil {
		return Operation{}, fmt.Errorf("r3/graphql: invalid operation: %w", err)
	}
	if _, ok := seen["operation"]; !ok {
		return Operation{}, errors.New("r3/graphql: operation is missing operation")
	}
	if _, ok := seen["type"]; !ok {
		return Operation{}, errors.New("r3/graphql: operation is missing type")
	}
	return NewOperation(name, OperationType(operationType))
}

// ToR3 converts the typed GraphQL operation into the neutral R3 value
// registered by Vocabulary.
func (operation Operation) ToR3() (r3.Operation, error) {
	encoded, err := json.Marshal(operation)
	if err != nil {
		return r3.Operation{}, err
	}
	return r3.NewOperation(vocabulary, encoded)
}

// FromR3 converts an operation created by this package's registration back to
// its typed GraphQL form.
func FromR3(operation r3.Operation) (Operation, error) {
	if operation.Vocabulary() != URI {
		return Operation{}, fmt.Errorf("r3/graphql: operation uses vocabulary %q", operation.Vocabulary())
	}
	encoded := operation.JSON()
	if encoded == nil {
		return Operation{}, errors.New("r3/graphql: operation is invalid")
	}
	local, err := r3.NewOperation(vocabulary, encoded)
	if err != nil {
		return Operation{}, err
	}
	equal, err := local.Equal(operation)
	if err != nil {
		return Operation{}, fmt.Errorf("r3/graphql: operation uses another registration: %w", err)
	}
	if !equal {
		return Operation{}, errors.New("r3/graphql: operation is not semantically equal to its GraphQL encoding")
	}
	return parseOperation(encoded)
}

type operationKey struct {
	name          string
	operationType OperationType
}

func (operation Operation) key() operationKey {
	return operationKey{name: operation.name, operationType: operation.operationType}
}

// set is an immutable GraphQL operation set retained in wire order.
type set struct {
	operations []Operation
}

// Operations returns a copy of the retained operation sequence.
func (set set) Operations() []Operation {
	return append([]Operation(nil), set.operations...)
}

// codec implements strict GraphQL operation parsing and set algebra.
type codec struct{}

// URI returns the standard GraphQL vocabulary URI.
func (codec) URI() r3.VocabularyURI { return URI }

// AnnotationEncoding reports that the R3 draft defines no GraphQL annotation mechanism.
func (codec) AnnotationEncoding() r3.AnnotationEncoding { return r3.AnnotationUnavailable }

func (codec) ValidateDiscoveryEndpoint(endpoint string) error {
	return discoveryendpoint.ValidateStandard(endpoint)
}

// ParseSet parses and validates one GraphQL operation sequence.
func (codec) ParseSet(raw []json.RawMessage) (set, error) {
	operations := make([]Operation, 0, len(raw))
	seen := make(map[operationKey]struct{}, len(raw))
	for index, encoded := range raw {
		operation, err := parseOperation(encoded)
		if err != nil {
			return set{}, fmt.Errorf("r3/graphql: operation %d: %w", index, err)
		}
		if _, duplicate := seen[operation.key()]; duplicate {
			return set{}, fmt.Errorf("r3/graphql: duplicate %s operation %q", operation.operationType, operation.name)
		}
		seen[operation.key()] = struct{}{}
		operations = append(operations, operation)
	}
	return set{operations: operations}, nil
}

// MarshalSet emits canonical GraphQL operation objects in retained order.
func (codec) MarshalSet(operations set) ([]json.RawMessage, error) {
	result := make([]json.RawMessage, len(operations.operations))
	seen := make(map[operationKey]struct{}, len(operations.operations))
	for index, operation := range operations.operations {
		if err := operation.validate(); err != nil {
			return nil, fmt.Errorf("r3/graphql: operation %d: %w", index, err)
		}
		if _, duplicate := seen[operation.key()]; duplicate {
			return nil, fmt.Errorf("r3/graphql: duplicate %s operation %q", operation.operationType, operation.name)
		}
		seen[operation.key()] = struct{}{}
		encoded, err := json.Marshal(operation)
		if err != nil {
			return nil, err
		}
		result[index] = encoded
	}
	return result, nil
}

// Union returns a stable semantic union, retaining the first occurrence.
func (codec) Union(sets ...set) (set, error) {
	union := set{}
	seen := make(map[operationKey]struct{})
	for _, candidateSet := range sets {
		for _, operation := range candidateSet.operations {
			if err := operation.validate(); err != nil {
				return set{}, err
			}
			if _, present := seen[operation.key()]; present {
				continue
			}
			seen[operation.key()] = struct{}{}
			union.operations = append(union.operations, operation)
		}
	}
	return union, nil
}

// Equal reports order-insensitive GraphQL set equality.
func (codec) Equal(left, right set) bool {
	return len(left.operations) == len(right.operations) && subset(left, right)
}

// Subset reports whether every operation in sub occurs in sup.
func (codec) Subset(sub, sup set) bool { return subset(sub, sup) }

func subset(sub, sup set) bool {
	for _, operation := range sub.operations {
		if !slices.ContainsFunc(sup.operations, func(candidate Operation) bool {
			return candidate.key() == operation.key()
		}) {
			return false
		}
	}
	return true
}

// Disjoint reports whether two GraphQL sets have no operation in common.
func (codec) Disjoint(left, right set) bool {
	for _, operation := range left.operations {
		if slices.ContainsFunc(right.operations, func(candidate Operation) bool {
			return candidate.key() == operation.key()
		}) {
			return false
		}
	}
	return true
}

var vocabulary = mustVocabulary()

func mustVocabulary() r3.Vocabulary {
	registered, err := r3.NewVocabulary[set](codec{})
	if err != nil {
		panic(err)
	}
	return registered
}

// Vocabulary returns this package's immutable codec registration.
func Vocabulary() r3.Vocabulary { return vocabulary }

// NewOperationSet converts typed GraphQL operations into a neutral R3
// operation set using this package's stable registration.
func NewOperationSet(operations ...Operation) (r3.OperationSet, error) {
	neutral := make([]r3.Operation, len(operations))
	for index, operation := range operations {
		converted, err := operation.ToR3()
		if err != nil {
			return r3.OperationSet{}, fmt.Errorf("r3/graphql: operation %d: %w", index, err)
		}
		neutral[index] = converted
	}
	return r3.NewOperationSet(neutral...)
}

var _ r3.Codec[set] = codec{}
