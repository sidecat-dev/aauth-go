// Package grpc implements the R3 gRPC operation-object grammar and set algebra.
package grpc

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

// URI is the standard R3 gRPC vocabulary URI.
const URI r3.VocabularyURI = "urn:aauth:vocabulary:grpc"

// Operation identifies one fully qualified gRPC method.
type Operation struct {
	method string
}

// NewOperation constructs a validated gRPC operation in
// package.ServiceName/MethodName form.
func NewOperation(method string) (Operation, error) {
	operation := Operation{method: method}
	if err := operation.validate(); err != nil {
		return Operation{}, err
	}
	return operation, nil
}

func (operation Operation) validate() error {
	if !utf8.ValidString(operation.method) || operation.method == "" || strings.TrimSpace(operation.method) != operation.method {
		return errors.New("r3/grpc: method must be non-empty, trimmed UTF-8")
	}
	if strings.Count(operation.method, "/") != 1 {
		return errors.New("r3/grpc: method must use package.ServiceName/MethodName form")
	}
	service, method, _ := strings.Cut(operation.method, "/")
	serviceParts := strings.Split(service, ".")
	if len(serviceParts) < 2 || !validProtoIdentifier(method) {
		return errors.New("r3/grpc: method must use package.ServiceName/MethodName form")
	}
	for _, part := range serviceParts {
		if !validProtoIdentifier(part) {
			return errors.New("r3/grpc: method must use package.ServiceName/MethodName form")
		}
	}
	return nil
}

func validProtoIdentifier(value string) bool {
	if value == "" || !isProtoIdentifierStart(value[0]) {
		return false
	}
	for index := 1; index < len(value); index++ {
		if !isProtoIdentifierStart(value[index]) && (value[index] < '0' || value[index] > '9') {
			return false
		}
	}
	return true
}

func isProtoIdentifierStart(value byte) bool {
	return value == '_' || value >= 'A' && value <= 'Z' || value >= 'a' && value <= 'z'
}

// Method returns the fully qualified gRPC method.
func (operation Operation) Method() string { return operation.method }

// MarshalJSON emits the exact gRPC R3 operation object.
func (operation Operation) MarshalJSON() ([]byte, error) {
	if err := operation.validate(); err != nil {
		return nil, err
	}
	return json.Marshal(struct {
		Method string `json:"method"`
	}{Method: operation.method})
}

// UnmarshalJSON accepts only the exact gRPC R3 operation object.
func (operation *Operation) UnmarshalJSON(source []byte) error {
	parsed, err := parseOperation(source)
	if err != nil {
		return err
	}
	*operation = parsed
	return nil
}

func parseOperation(source []byte) (Operation, error) {
	var method string
	seen, err := wirejson.Object(source, map[string]func(json.RawMessage) error{
		"method": func(raw json.RawMessage) error { return wirejson.String(raw, &method) },
	})
	if err != nil {
		return Operation{}, fmt.Errorf("r3/grpc: invalid operation: %w", err)
	}
	if _, ok := seen["method"]; !ok {
		return Operation{}, errors.New("r3/grpc: operation is missing method")
	}
	return NewOperation(method)
}

// ToR3 converts the typed gRPC operation into the neutral R3 value registered
// by Vocabulary.
func (operation Operation) ToR3() (r3.Operation, error) {
	encoded, err := json.Marshal(operation)
	if err != nil {
		return r3.Operation{}, err
	}
	return r3.NewOperation(vocabulary, encoded)
}

// FromR3 converts an operation created by this package's registration back to
// its typed gRPC form.
func FromR3(operation r3.Operation) (Operation, error) {
	if operation.Vocabulary() != URI {
		return Operation{}, fmt.Errorf("r3/grpc: operation uses vocabulary %q", operation.Vocabulary())
	}
	encoded := operation.JSON()
	if encoded == nil {
		return Operation{}, errors.New("r3/grpc: operation is invalid")
	}
	local, err := r3.NewOperation(vocabulary, encoded)
	if err != nil {
		return Operation{}, err
	}
	equal, err := local.Equal(operation)
	if err != nil {
		return Operation{}, fmt.Errorf("r3/grpc: operation uses another registration: %w", err)
	}
	if !equal {
		return Operation{}, errors.New("r3/grpc: operation is not semantically equal to its gRPC encoding")
	}
	return parseOperation(encoded)
}

// set is an immutable gRPC operation set retained in wire order.
type set struct {
	operations []Operation
}

// Operations returns a copy of the retained operation sequence.
func (set set) Operations() []Operation {
	return append([]Operation(nil), set.operations...)
}

// codec implements strict gRPC operation parsing and set algebra.
type codec struct{}

// URI returns the standard gRPC vocabulary URI.
func (codec) URI() r3.VocabularyURI { return URI }

// AnnotationEncoding reports that the R3 draft defines no gRPC annotation mechanism.
func (codec) AnnotationEncoding() r3.AnnotationEncoding { return r3.AnnotationUnavailable }

func (codec) ValidateDiscoveryEndpoint(endpoint string) error {
	return discoveryendpoint.ValidateGRPC(endpoint)
}

// ParseSet parses and validates one gRPC operation sequence.
func (codec) ParseSet(raw []json.RawMessage) (set, error) {
	operations := make([]Operation, 0, len(raw))
	seen := make(map[string]struct{}, len(raw))
	for index, encoded := range raw {
		operation, err := parseOperation(encoded)
		if err != nil {
			return set{}, fmt.Errorf("r3/grpc: operation %d: %w", index, err)
		}
		if _, duplicate := seen[operation.method]; duplicate {
			return set{}, fmt.Errorf("r3/grpc: duplicate method %q", operation.method)
		}
		seen[operation.method] = struct{}{}
		operations = append(operations, operation)
	}
	return set{operations: operations}, nil
}

// MarshalSet emits canonical gRPC operation objects in retained order.
func (codec) MarshalSet(operations set) ([]json.RawMessage, error) {
	result := make([]json.RawMessage, len(operations.operations))
	seen := make(map[string]struct{}, len(operations.operations))
	for index, operation := range operations.operations {
		if err := operation.validate(); err != nil {
			return nil, fmt.Errorf("r3/grpc: operation %d: %w", index, err)
		}
		if _, duplicate := seen[operation.method]; duplicate {
			return nil, fmt.Errorf("r3/grpc: duplicate method %q", operation.method)
		}
		seen[operation.method] = struct{}{}
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
	seen := make(map[string]struct{})
	for _, candidateSet := range sets {
		for _, operation := range candidateSet.operations {
			if err := operation.validate(); err != nil {
				return set{}, err
			}
			if _, present := seen[operation.method]; present {
				continue
			}
			seen[operation.method] = struct{}{}
			union.operations = append(union.operations, operation)
		}
	}
	return union, nil
}

// Equal reports order-insensitive gRPC set equality.
func (codec) Equal(left, right set) bool {
	return len(left.operations) == len(right.operations) && subset(left, right)
}

// Subset reports whether every operation in sub occurs in sup.
func (codec) Subset(sub, sup set) bool { return subset(sub, sup) }

func subset(sub, sup set) bool {
	for _, operation := range sub.operations {
		if !slices.ContainsFunc(sup.operations, func(candidate Operation) bool {
			return candidate.method == operation.method
		}) {
			return false
		}
	}
	return true
}

// Disjoint reports whether two gRPC sets have no method in common.
func (codec) Disjoint(left, right set) bool {
	for _, operation := range left.operations {
		if slices.ContainsFunc(right.operations, func(candidate Operation) bool {
			return candidate.method == operation.method
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

// NewOperationSet converts typed gRPC operations into a neutral R3 operation
// set using this package's stable registration.
func NewOperationSet(operations ...Operation) (r3.OperationSet, error) {
	neutral := make([]r3.Operation, len(operations))
	for index, operation := range operations {
		converted, err := operation.ToR3()
		if err != nil {
			return r3.OperationSet{}, fmt.Errorf("r3/grpc: operation %d: %w", index, err)
		}
		neutral[index] = converted
	}
	return r3.NewOperationSet(neutral...)
}

var _ r3.Codec[set] = codec{}
