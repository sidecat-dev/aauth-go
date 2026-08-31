package r3

import (
	"encoding/json"
	"fmt"
	"strings"
	"unicode/utf8"
)

// MCPVocabulary is the vocabulary URI assigned to MCP operations by R3.
const MCPVocabulary = "urn:aauth:vocabulary:mcp"

// MCPOperation identifies one MCP tool.
type MCPOperation struct {
	tool string
}

// NewMCPOperation constructs a validated MCP operation.
func NewMCPOperation(tool string) (MCPOperation, error) {
	operation := MCPOperation{tool: tool}
	if err := operation.validate(); err != nil {
		return MCPOperation{}, err
	}
	return operation, nil
}

// Tool returns the MCP tool name.
func (o MCPOperation) Tool() string {
	return o.tool
}

func (o MCPOperation) validate() error {
	if !utf8.ValidString(o.tool) {
		return fmt.Errorf("r3: MCP tool must be valid UTF-8")
	}
	if o.tool == "" {
		return fmt.Errorf("r3: MCP tool is required")
	}
	if strings.TrimSpace(o.tool) != o.tool {
		return fmt.Errorf("r3: MCP tool %q is not trimmed", o.tool)
	}
	return nil
}

// MarshalJSON emits the exact MCP operation member shape.
func (o MCPOperation) MarshalJSON() ([]byte, error) {
	if err := o.validate(); err != nil {
		return nil, err
	}
	return json.Marshal(struct {
		Tool string `json:"tool"`
	}{Tool: o.tool})
}

// UnmarshalJSON accepts only an exact MCP operation object.
func (o *MCPOperation) UnmarshalJSON(data []byte) error {
	operation, err := parseMCPOperation(data)
	if err != nil {
		return err
	}
	*o = operation
	return nil
}

func parseMCPOperation(data []byte) (MCPOperation, error) {
	var tool string
	seen, err := decodeStrictObject(data, map[string]func(json.RawMessage) error{
		"tool": func(raw json.RawMessage) error {
			return decodeJSONString(raw, &tool)
		},
	})
	if err != nil {
		return MCPOperation{}, fmt.Errorf("r3: invalid MCP operation: %w", err)
	}
	if _, ok := seen["tool"]; !ok {
		return MCPOperation{}, fmt.Errorf("r3: MCP operation is missing tool")
	}
	return NewMCPOperation(tool)
}

// MCPOperationSet is a non-empty set of distinct MCP operations. It retains
// insertion order for serialization while comparisons use set semantics.
type MCPOperationSet struct {
	operations []MCPOperation
}

// NewMCPOperationSet constructs a validated MCP operation set.
func NewMCPOperationSet(operations ...MCPOperation) (MCPOperationSet, error) {
	set := MCPOperationSet{operations: append([]MCPOperation(nil), operations...)}
	if err := set.validate(); err != nil {
		return MCPOperationSet{}, err
	}
	return set, nil
}

func (s MCPOperationSet) validate() error {
	if len(s.operations) == 0 {
		return fmt.Errorf("r3: MCP operation set must not be empty")
	}
	seen := make(map[string]struct{}, len(s.operations))
	for i, operation := range s.operations {
		if err := operation.validate(); err != nil {
			return fmt.Errorf("r3: operation %d: %w", i, err)
		}
		if _, exists := seen[operation.tool]; exists {
			return fmt.Errorf("r3: duplicate MCP tool %q", operation.tool)
		}
		seen[operation.tool] = struct{}{}
	}
	return nil
}

// Operations returns a copy of the retained operation sequence.
func (s MCPOperationSet) Operations() []MCPOperation {
	return append([]MCPOperation(nil), s.operations...)
}

// Equal reports semantic equality using order-insensitive set semantics.
func (s MCPOperationSet) Equal(other MCPOperationSet) bool {
	if s.validate() != nil || other.validate() != nil {
		return false
	}
	if len(s.operations) != len(other.operations) {
		return false
	}
	return s.IsSubsetOf(other)
}

// IsSubsetOf reports whether every operation in s occurs in other.
func (s MCPOperationSet) IsSubsetOf(other MCPOperationSet) bool {
	if s.validate() != nil || other.validate() != nil {
		return false
	}
	available := make(map[string]struct{}, len(other.operations))
	for _, operation := range other.operations {
		available[operation.tool] = struct{}{}
	}
	for _, operation := range s.operations {
		if _, ok := available[operation.tool]; !ok {
			return false
		}
	}
	return true
}

// ValidateKnownTools checks every requested operation against a caller-owned,
// Resource-authoritative MCP tool list.
func (s MCPOperationSet) ValidateKnownTools(knownTools []string) error {
	if err := s.validate(); err != nil {
		return err
	}
	known := make(map[string]struct{}, len(knownTools))
	for i, tool := range knownTools {
		operation := MCPOperation{tool: tool}
		if err := operation.validate(); err != nil {
			return fmt.Errorf("r3: authoritative MCP tool %d: %w", i, err)
		}
		if _, duplicate := known[tool]; duplicate {
			return fmt.Errorf("r3: duplicate authoritative MCP tool %q", tool)
		}
		known[tool] = struct{}{}
	}
	for _, operation := range s.operations {
		if _, ok := known[operation.tool]; !ok {
			return fmt.Errorf("r3: MCP tool %q is not in the authoritative tool set", operation.tool)
		}
	}
	return nil
}

// MarshalJSON emits an MCP operation set with vocabulary before operations.
func (s MCPOperationSet) MarshalJSON() ([]byte, error) {
	if err := s.validate(); err != nil {
		return nil, err
	}
	return json.Marshal(struct {
		Vocabulary string         `json:"vocabulary"`
		Operations []MCPOperation `json:"operations"`
	}{
		Vocabulary: MCPVocabulary,
		Operations: s.Operations(),
	})
}

// UnmarshalJSON accepts only the exact MCP operation-set shape.
func (s *MCPOperationSet) UnmarshalJSON(data []byte) error {
	set, err := parseMCPOperationSet(data)
	if err != nil {
		return err
	}
	*s = set
	return nil
}

func parseMCPOperationSet(data []byte) (MCPOperationSet, error) {
	var vocabularyRaw, operationsRaw json.RawMessage
	seen, err := decodeStrictObject(data, map[string]func(json.RawMessage) error{
		"vocabulary": func(raw json.RawMessage) error {
			vocabularyRaw = append(vocabularyRaw[:0], raw...)
			return nil
		},
		"operations": func(raw json.RawMessage) error {
			operationsRaw = append(operationsRaw[:0], raw...)
			return nil
		},
	})
	if err != nil {
		return MCPOperationSet{}, fmt.Errorf("r3: invalid MCP operation set: %w", err)
	}
	if _, ok := seen["vocabulary"]; !ok {
		return MCPOperationSet{}, fmt.Errorf("r3: MCP operation set is missing vocabulary")
	}
	if _, ok := seen["operations"]; !ok {
		return MCPOperationSet{}, fmt.Errorf("r3: MCP operation set is missing operations")
	}
	return parseMCPOperationSetParts(vocabularyRaw, operationsRaw)
}

func parseMCPOperationSetParts(vocabularyRaw, operationsRaw json.RawMessage) (MCPOperationSet, error) {
	operations, err := parseMCPOperationsParts(vocabularyRaw, operationsRaw)
	if err != nil {
		return MCPOperationSet{}, err
	}
	return NewMCPOperationSet(operations...)
}

func parseMCPOperationsParts(vocabularyRaw, operationsRaw json.RawMessage) ([]MCPOperation, error) {
	var vocabulary string
	if err := decodeJSONString(vocabularyRaw, &vocabulary); err != nil {
		return nil, fmt.Errorf("r3: invalid vocabulary: %w", err)
	}
	if vocabulary != MCPVocabulary {
		return nil, fmt.Errorf("r3: vocabulary %q is not %q", vocabulary, MCPVocabulary)
	}

	rawOperations, err := decodeJSONArray(operationsRaw)
	if err != nil {
		return nil, fmt.Errorf("r3: invalid operations: %w", err)
	}
	operations := make([]MCPOperation, 0, len(rawOperations))
	for i, raw := range rawOperations {
		operation, err := parseMCPOperation(raw)
		if err != nil {
			return nil, fmt.Errorf("r3: operation %d: %w", i, err)
		}
		operations = append(operations, operation)
	}
	return operations, nil
}
