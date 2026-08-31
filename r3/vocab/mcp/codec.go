// Package mcp implements the R3 MCP operation-object grammar and set algebra.
package mcp

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

// URI is the standard R3 MCP vocabulary URI.
const URI r3.VocabularyURI = "urn:aauth:vocabulary:mcp"

// Operation identifies one MCP tool by its advertised name.
type Operation struct {
	tool string
}

// NewOperation constructs a validated MCP tool operation.
func NewOperation(tool string) (Operation, error) {
	operation := Operation{tool: tool}
	if err := operation.validate(); err != nil {
		return Operation{}, err
	}
	return operation, nil
}

func (operation Operation) validate() error {
	if !utf8.ValidString(operation.tool) || operation.tool == "" || strings.TrimSpace(operation.tool) != operation.tool {
		return errors.New("r3/mcp: tool must be non-empty, trimmed UTF-8")
	}
	return nil
}

// Tool returns the MCP tool name.
func (operation Operation) Tool() string { return operation.tool }

// MarshalJSON emits the exact MCP operation object.
func (operation Operation) MarshalJSON() ([]byte, error) {
	if err := operation.validate(); err != nil {
		return nil, err
	}
	return json.Marshal(struct {
		Tool string `json:"tool"`
	}{Tool: operation.tool})
}

// UnmarshalJSON accepts only the exact MCP operation object.
func (operation *Operation) UnmarshalJSON(source []byte) error {
	parsed, err := parseOperation(source)
	if err != nil {
		return err
	}
	*operation = parsed
	return nil
}

func parseOperation(source []byte) (Operation, error) {
	var tool string
	seen, err := wirejson.Object(source, map[string]func(json.RawMessage) error{
		"tool": func(raw json.RawMessage) error { return wirejson.String(raw, &tool) },
	})
	if err != nil {
		return Operation{}, fmt.Errorf("r3/mcp: invalid operation: %w", err)
	}
	if _, ok := seen["tool"]; !ok {
		return Operation{}, errors.New("r3/mcp: operation is missing tool")
	}
	return NewOperation(tool)
}

// ToR3 converts the typed MCP operation into the neutral R3 value registered
// by Vocabulary.
func (operation Operation) ToR3() (r3.Operation, error) {
	encoded, err := json.Marshal(operation)
	if err != nil {
		return r3.Operation{}, err
	}
	return r3.NewOperation(vocabulary, encoded)
}

// FromR3 converts an operation created by this package's registration back to
// its typed MCP form.
func FromR3(operation r3.Operation) (Operation, error) {
	if operation.Vocabulary() != URI {
		return Operation{}, fmt.Errorf("r3/mcp: operation uses vocabulary %q", operation.Vocabulary())
	}
	encoded := operation.JSON()
	if encoded == nil {
		return Operation{}, errors.New("r3/mcp: operation is invalid")
	}
	local, err := r3.NewOperation(vocabulary, encoded)
	if err != nil {
		return Operation{}, err
	}
	equal, err := local.Equal(operation)
	if err != nil {
		return Operation{}, fmt.Errorf("r3/mcp: operation uses another registration: %w", err)
	}
	if !equal {
		return Operation{}, errors.New("r3/mcp: operation is not semantically equal to its MCP encoding")
	}
	return parseOperation(encoded)
}

// set is an immutable MCP operation set retained in wire order.
type set struct {
	operations []Operation
}

// Operations returns a copy of the retained operation sequence.
func (set set) Operations() []Operation {
	return append([]Operation(nil), set.operations...)
}

// codec implements strict MCP operation parsing and set algebra.
type codec struct{}

// URI returns the standard MCP vocabulary URI.
func (codec) URI() r3.VocabularyURI { return URI }

// AnnotationEncoding reports that MCP carries R3 hints in operation _meta.
func (codec) AnnotationEncoding() r3.AnnotationEncoding { return r3.AnnotationMCPMeta }

func (codec) ValidateDiscoveryEndpoint(endpoint string) error {
	return discoveryendpoint.ValidateStandard(endpoint)
}

// ParseSet parses and validates one MCP operation sequence.
func (codec) ParseSet(raw []json.RawMessage) (set, error) {
	operations := make([]Operation, 0, len(raw))
	seen := make(map[string]struct{}, len(raw))
	for index, encoded := range raw {
		operation, err := parseOperation(encoded)
		if err != nil {
			return set{}, fmt.Errorf("r3/mcp: operation %d: %w", index, err)
		}
		if _, duplicate := seen[operation.tool]; duplicate {
			return set{}, fmt.Errorf("r3/mcp: duplicate tool %q", operation.tool)
		}
		seen[operation.tool] = struct{}{}
		operations = append(operations, operation)
	}
	return set{operations: operations}, nil
}

// MarshalSet emits canonical MCP operation objects in retained order.
func (codec) MarshalSet(operations set) ([]json.RawMessage, error) {
	result := make([]json.RawMessage, len(operations.operations))
	seen := make(map[string]struct{}, len(operations.operations))
	for index, operation := range operations.operations {
		if err := operation.validate(); err != nil {
			return nil, fmt.Errorf("r3/mcp: operation %d: %w", index, err)
		}
		if _, duplicate := seen[operation.tool]; duplicate {
			return nil, fmt.Errorf("r3/mcp: duplicate tool %q", operation.tool)
		}
		seen[operation.tool] = struct{}{}
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
			if _, present := seen[operation.tool]; present {
				continue
			}
			seen[operation.tool] = struct{}{}
			union.operations = append(union.operations, operation)
		}
	}
	return union, nil
}

// Equal reports order-insensitive MCP set equality.
func (codec) Equal(left, right set) bool {
	return len(left.operations) == len(right.operations) && subset(left, right)
}

// Subset reports whether every operation in sub occurs in sup.
func (codec) Subset(sub, sup set) bool { return subset(sub, sup) }

func subset(sub, sup set) bool {
	for _, operation := range sub.operations {
		if !slices.ContainsFunc(sup.operations, func(candidate Operation) bool {
			return candidate.tool == operation.tool
		}) {
			return false
		}
	}
	return true
}

// Disjoint reports whether two MCP sets have no tool in common.
func (codec) Disjoint(left, right set) bool {
	for _, operation := range left.operations {
		if slices.ContainsFunc(right.operations, func(candidate Operation) bool {
			return candidate.tool == operation.tool
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

// NewOperationSet converts typed MCP operations into a neutral R3 operation
// set using this package's stable registration.
func NewOperationSet(operations ...Operation) (r3.OperationSet, error) {
	neutral := make([]r3.Operation, len(operations))
	for index, operation := range operations {
		converted, err := operation.ToR3()
		if err != nil {
			return r3.OperationSet{}, fmt.Errorf("r3/mcp: operation %d: %w", index, err)
		}
		neutral[index] = converted
	}
	return r3.NewOperationSet(neutral...)
}

var _ r3.Codec[set] = codec{}
