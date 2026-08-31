// Package openapi implements the R3 OpenAPI operation grammar and a
// self-contained OpenAPI 3.0/3.1 Paths definition adapter. Callbacks, webhooks,
// external reference acquisition, and network I/O are outside the adapter.
package openapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"unicode/utf8"

	"gitlab.com/sidecat-dev/aauth-go/r3"
	"gitlab.com/sidecat-dev/aauth-go/r3/internal/wirejson"
	"gitlab.com/sidecat-dev/aauth-go/r3/vocab/internal/discoveryendpoint"
)

// URI is the standard R3 OpenAPI vocabulary URI.
const URI r3.VocabularyURI = "urn:aauth:vocabulary:openapi"

// Operation identifies one OpenAPI Operation Object by operationId.
type Operation struct {
	operationID string
}

// NewOperation constructs a validated OpenAPI operation.
func NewOperation(operationID string) (Operation, error) {
	operation := Operation{operationID: operationID}
	if err := operation.validate(); err != nil {
		return Operation{}, err
	}
	return operation, nil
}

func (operation Operation) validate() error {
	if !utf8.ValidString(operation.operationID) || operation.operationID == "" || strings.TrimSpace(operation.operationID) != operation.operationID {
		return errors.New("r3/openapi: operationId must be non-empty, trimmed UTF-8")
	}
	return nil
}

// OperationID returns the OpenAPI operationId.
func (operation Operation) OperationID() string { return operation.operationID }

// MarshalJSON emits the exact OpenAPI R3 operation object.
func (operation Operation) MarshalJSON() ([]byte, error) {
	if err := operation.validate(); err != nil {
		return nil, err
	}
	return json.Marshal(struct {
		OperationID string `json:"operationId"`
	}{OperationID: operation.operationID})
}

// UnmarshalJSON accepts only the exact OpenAPI R3 operation object.
func (operation *Operation) UnmarshalJSON(source []byte) error {
	parsed, err := parseOperation(source)
	if err != nil {
		return err
	}
	*operation = parsed
	return nil
}

func parseOperation(source []byte) (Operation, error) {
	var operationID string
	seen, err := wirejson.Object(source, map[string]func(json.RawMessage) error{
		"operationId": func(raw json.RawMessage) error { return wirejson.String(raw, &operationID) },
	})
	if err != nil {
		return Operation{}, fmt.Errorf("r3/openapi: invalid operation: %w", err)
	}
	if _, ok := seen["operationId"]; !ok {
		return Operation{}, errors.New("r3/openapi: operation is missing operationId")
	}
	return NewOperation(operationID)
}

// ToR3 converts the typed OpenAPI operation into the neutral R3 value
// registered by Vocabulary.
func (operation Operation) ToR3() (r3.Operation, error) {
	encoded, err := json.Marshal(operation)
	if err != nil {
		return r3.Operation{}, err
	}
	return r3.NewOperation(vocabulary, encoded)
}

// FromR3 converts an operation created by this package's registration back to
// its typed OpenAPI form.
func FromR3(operation r3.Operation) (Operation, error) {
	if operation.Vocabulary() != URI {
		return Operation{}, fmt.Errorf("r3/openapi: operation uses vocabulary %q", operation.Vocabulary())
	}
	encoded := operation.JSON()
	if encoded == nil {
		return Operation{}, errors.New("r3/openapi: operation is invalid")
	}
	local, err := r3.NewOperation(vocabulary, encoded)
	if err != nil {
		return Operation{}, err
	}
	equal, err := local.Equal(operation)
	if err != nil {
		return Operation{}, fmt.Errorf("r3/openapi: operation uses another registration: %w", err)
	}
	if !equal {
		return Operation{}, errors.New("r3/openapi: operation is not semantically equal to its OpenAPI encoding")
	}
	return parseOperation(encoded)
}

// set is an immutable OpenAPI operation set retained in wire order.
type set struct {
	operations []Operation
}

// Operations returns a copy of the retained operation sequence.
func (set set) Operations() []Operation {
	return append([]Operation(nil), set.operations...)
}

// codec implements strict OpenAPI operation parsing and set algebra.
type codec struct{}

// URI returns the standard OpenAPI vocabulary URI.
func (codec) URI() r3.VocabularyURI { return URI }

// AnnotationEncoding reports that OpenAPI carries R3 hints in specification extensions.
func (codec) AnnotationEncoding() r3.AnnotationEncoding {
	return r3.AnnotationSpecificationExtension
}

func (codec) ValidateDiscoveryEndpoint(endpoint string) error {
	return discoveryendpoint.ValidateStandard(endpoint)
}

// ParseSet parses and validates one OpenAPI operation sequence.
func (codec) ParseSet(raw []json.RawMessage) (set, error) {
	operations := make([]Operation, 0, len(raw))
	seen := make(map[string]struct{}, len(raw))
	for index, encoded := range raw {
		operation, err := parseOperation(encoded)
		if err != nil {
			return set{}, fmt.Errorf("r3/openapi: operation %d: %w", index, err)
		}
		if _, duplicate := seen[operation.operationID]; duplicate {
			return set{}, fmt.Errorf("r3/openapi: duplicate operationId %q", operation.operationID)
		}
		seen[operation.operationID] = struct{}{}
		operations = append(operations, operation)
	}
	return set{operations: operations}, nil
}

// MarshalSet emits canonical OpenAPI operation objects in retained order.
func (codec) MarshalSet(operations set) ([]json.RawMessage, error) {
	result := make([]json.RawMessage, len(operations.operations))
	seen := make(map[string]struct{}, len(operations.operations))
	for index, operation := range operations.operations {
		if err := operation.validate(); err != nil {
			return nil, fmt.Errorf("r3/openapi: operation %d: %w", index, err)
		}
		if _, duplicate := seen[operation.operationID]; duplicate {
			return nil, fmt.Errorf("r3/openapi: duplicate operationId %q", operation.operationID)
		}
		seen[operation.operationID] = struct{}{}
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
			if _, present := seen[operation.operationID]; present {
				continue
			}
			seen[operation.operationID] = struct{}{}
			union.operations = append(union.operations, operation)
		}
	}
	return union, nil
}

// Equal reports order-insensitive OpenAPI set equality.
func (codec) Equal(left, right set) bool {
	return len(left.operations) == len(right.operations) && subset(left, right)
}

// Subset reports whether every operation in sub occurs in sup.
func (codec) Subset(sub, sup set) bool { return subset(sub, sup) }

func subset(sub, sup set) bool {
	for _, operation := range sub.operations {
		if !slices.ContainsFunc(sup.operations, func(candidate Operation) bool {
			return candidate.operationID == operation.operationID
		}) {
			return false
		}
	}
	return true
}

// Disjoint reports whether two OpenAPI sets have no operationId in common.
func (codec) Disjoint(left, right set) bool {
	for _, operation := range left.operations {
		if slices.ContainsFunc(right.operations, func(candidate Operation) bool {
			return candidate.operationID == operation.operationID
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

// NewOperationSet converts typed OpenAPI operations into a neutral R3
// operation set using this package's stable registration.
func NewOperationSet(operations ...Operation) (r3.OperationSet, error) {
	neutral := make([]r3.Operation, len(operations))
	for index, operation := range operations {
		converted, err := operation.ToR3()
		if err != nil {
			return r3.OperationSet{}, fmt.Errorf("r3/openapi: operation %d: %w", index, err)
		}
		neutral[index] = converted
	}
	return r3.NewOperationSet(neutral...)
}

var _ r3.Codec[set] = codec{}
