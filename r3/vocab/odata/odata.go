// Package odata implements the R3 OData operation-object grammar and set
// algebra. Methods are an order-insensitive narrowing set.
package odata

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"aauth-go/r3"
	"aauth-go/r3/internal/wirejson"
	"aauth-go/r3/vocab/internal/discoveryendpoint"
)

// URI is the standard R3 OData vocabulary URI.
const URI r3.VocabularyURI = "urn:aauth:vocabulary:odata"

// Operation identifies an OData entity set or bound operation and retains
// whether the optional methods member was present.
type Operation struct {
	name    string
	methods []string
	present bool
}

// NewOperation constructs an operation with no methods member.
func NewOperation(name string) (Operation, error) { return newOperation(name, nil, false) }

// NewMethodOperation constructs an operation with a nonempty HTTP method set.
// Method order is retained for wire output but is not semantic.
func NewMethodOperation(name string, methods ...string) (Operation, error) {
	return newOperation(name, methods, true)
}

func newOperation(name string, methods []string, present bool) (Operation, error) {
	if err := validateName(name); err != nil {
		return Operation{}, err
	}
	operation := Operation{name: name, present: present}
	if !present {
		if methods != nil {
			return Operation{}, errors.New("odata: absent methods member cannot carry methods")
		}
		return operation, nil
	}
	if len(methods) == 0 {
		return Operation{}, errors.New("odata: present methods must not be empty")
	}
	seen := make(map[string]struct{}, len(methods))
	operation.methods = make([]string, len(methods))
	for index, method := range methods {
		if !validHTTPMethod(method) {
			return Operation{}, fmt.Errorf("odata: method %d %q is not a valid HTTP method token", index, method)
		}
		if _, duplicate := seen[method]; duplicate {
			return Operation{}, fmt.Errorf("odata: duplicate method %q", method)
		}
		seen[method] = struct{}{}
		operation.methods[index] = method
	}
	return operation, nil
}

// OperationName returns the exact OData operation identifier.
func (operation Operation) OperationName() string { return operation.name }

// Methods returns an owned method sequence and whether the optional member was
// present.
func (operation Operation) Methods() ([]string, bool) {
	if !operation.present {
		return nil, false
	}
	return append([]string(nil), operation.methods...), true
}

// MarshalJSON emits the exact OData R3 operation object.
func (operation Operation) MarshalJSON() ([]byte, error) { return marshalOperation(operation) }

// UnmarshalJSON accepts only the exact OData R3 operation object.
func (operation *Operation) UnmarshalJSON(source []byte) error {
	parsed, err := parseOperation(source)
	if err != nil {
		return err
	}
	*operation = parsed
	return nil
}

// ToR3 converts the typed operation through the package's immutable
// vocabulary registration.
func (operation Operation) ToR3() (r3.Operation, error) {
	raw, err := marshalOperation(operation)
	if err != nil {
		return r3.Operation{}, err
	}
	return r3.NewOperation(Vocabulary(), raw)
}

// FromR3 converts an OData-tagged neutral operation to its typed form.
func FromR3(operation r3.Operation) (Operation, error) {
	if operation.Vocabulary() != URI {
		return Operation{}, fmt.Errorf("odata: operation vocabulary is %q, want %q", operation.Vocabulary(), URI)
	}
	encoded := operation.JSON()
	if encoded == nil {
		return Operation{}, errors.New("odata: operation is invalid")
	}
	local, err := r3.NewOperation(vocabulary, encoded)
	if err != nil {
		return Operation{}, err
	}
	equal, err := local.Equal(operation)
	if err != nil {
		return Operation{}, fmt.Errorf("odata: operation uses another registration: %w", err)
	}
	if !equal {
		return Operation{}, errors.New("odata: operation is not semantically equal to its OData encoding")
	}
	return parseOperation(encoded)
}

// NewOperationSet constructs one neutral OData operation set.
func NewOperationSet(operations ...Operation) (r3.OperationSet, error) {
	neutral := make([]r3.Operation, len(operations))
	for index, operation := range operations {
		converted, err := operation.ToR3()
		if err != nil {
			return r3.OperationSet{}, fmt.Errorf("odata: operation %d: %w", index, err)
		}
		neutral[index] = converted
	}
	return r3.NewOperationSet(neutral...)
}

// set is an immutable OData operation set retained in wire order.
type set struct{ operations []Operation }

// Operations returns a copy-safe retained operation sequence.
func (set set) Operations() []Operation {
	operations := make([]Operation, len(set.operations))
	for index, operation := range set.operations {
		operations[index] = cloneOperation(operation)
	}
	return operations
}

// codec implements strict OData operation parsing and set algebra.
type codec struct{}

var vocabulary = mustVocabulary()

func mustVocabulary() r3.Vocabulary {
	value, err := r3.NewVocabulary[set](codec{})
	if err != nil {
		panic(err)
	}
	return value
}

// Vocabulary returns the immutable standard OData registration.
func Vocabulary() r3.Vocabulary { return vocabulary }

func (codec) URI() r3.VocabularyURI { return URI }

// AnnotationEncoding reports that OData carries R3 hints in OData metadata.
func (codec) AnnotationEncoding() r3.AnnotationEncoding { return r3.AnnotationODataMetadata }

func (codec) ValidateDiscoveryEndpoint(endpoint string) error {
	return discoveryendpoint.ValidateStandard(endpoint)
}

func (codec) ParseSet(raw []json.RawMessage) (set, error) {
	result := set{operations: make([]Operation, 0, len(raw))}
	for index, value := range raw {
		operation, err := parseOperation(value)
		if err != nil {
			return set{}, fmt.Errorf("odata: operation %d: %w", index, err)
		}
		if err := appendParsed(&result, operation); err != nil {
			return set{}, err
		}
	}
	return result, nil
}

func (codec) MarshalSet(operations set) ([]json.RawMessage, error) {
	result := make([]json.RawMessage, len(operations.operations))
	for index, operation := range operations.operations {
		encoded, err := marshalOperation(operation)
		if err != nil {
			return nil, fmt.Errorf("odata: operation %d: %w", index, err)
		}
		result[index] = encoded
	}
	return result, nil
}

func (codec) Union(sets ...set) (set, error) {
	var result set
	indices := make(map[string]int)
	for _, candidateSet := range sets {
		for _, operation := range candidateSet.operations {
			index, exists := indices[operation.name]
			if !exists {
				indices[operation.name] = len(result.operations)
				result.operations = append(result.operations, cloneOperation(operation))
				continue
			}
			existing := result.operations[index]
			if existing.present != operation.present {
				return set{}, fmt.Errorf("odata: operation %q ambiguously mixes absent and present methods", operation.name)
			}
			if !existing.present {
				continue
			}
			for _, method := range operation.methods {
				if !containsString(existing.methods, method) {
					existing.methods = append(existing.methods, method)
				}
			}
			result.operations[index] = existing
		}
	}
	return result, nil
}

func (codec) Equal(left, right set) bool {
	return len(left.operations) == len(right.operations) && subset(left, right)
}

func (codec) Subset(left, right set) bool { return subset(left, right) }

func (codec) Disjoint(left, right set) bool {
	for _, leftOperation := range left.operations {
		for _, rightOperation := range right.operations {
			if overlaps(leftOperation, rightOperation) {
				return false
			}
		}
	}
	return true
}

func parseOperation(raw []byte) (Operation, error) {
	var name string
	var methods []string
	seen, err := wirejson.Object(raw, map[string]func(json.RawMessage) error{
		"operation": func(value json.RawMessage) error { return wirejson.String(value, &name) },
		"methods": func(value json.RawMessage) error {
			parsed, err := wirejson.StringArray(value)
			methods = parsed
			return err
		},
	})
	if err != nil {
		return Operation{}, err
	}
	if _, present := seen["operation"]; !present {
		return Operation{}, errors.New("operation is required")
	}
	if _, present := seen["methods"]; present {
		return NewMethodOperation(name, methods...)
	}
	return NewOperation(name)
}

func marshalOperation(operation Operation) (json.RawMessage, error) {
	validated, err := newOperation(operation.name, operation.methods, operation.present)
	if err != nil {
		return nil, err
	}
	if !validated.present {
		return json.Marshal(struct {
			Operation string `json:"operation"`
		}{Operation: validated.name})
	}
	return json.Marshal(struct {
		Operation string   `json:"operation"`
		Methods   []string `json:"methods"`
	}{Operation: validated.name, Methods: validated.methods})
}

func appendParsed(set *set, operation Operation) error {
	for _, existing := range set.operations {
		if existing.name != operation.name {
			continue
		}
		if existing.present != operation.present {
			return fmt.Errorf("odata: operation %q ambiguously mixes absent and present methods", operation.name)
		}
		return fmt.Errorf("odata: duplicate operation %q", operation.name)
	}
	set.operations = append(set.operations, cloneOperation(operation))
	return nil
}

func cloneOperation(operation Operation) Operation {
	if operation.present {
		methods := make([]string, len(operation.methods))
		copy(methods, operation.methods)
		operation.methods = methods
	} else {
		operation.methods = nil
	}
	return operation
}

func equalOperation(left, right Operation) bool {
	if left.name != right.name || left.present != right.present {
		return false
	}
	return !left.present || sameStringSet(left.methods, right.methods)
}

func overlaps(left, right Operation) bool {
	if left.name != right.name {
		return false
	}
	if left.present != right.present {
		return true
	}
	if !left.present {
		return true
	}
	for _, method := range left.methods {
		if containsString(right.methods, method) {
			return true
		}
	}
	return false
}

func subset(left, right set) bool {
	for _, operation := range left.operations {
		found := false
		for _, candidate := range right.operations {
			if operation.name != candidate.name || operation.present != candidate.present {
				continue
			}
			if !operation.present || stringSubset(operation.methods, candidate.methods) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

var _ r3.Codec[set] = codec{}

func sameStringSet(left, right []string) bool {
	return len(left) == len(right) && stringSubset(left, right)
}

func stringSubset(left, right []string) bool {
	for _, value := range left {
		if !containsString(right, value) {
			return false
		}
	}
	return true
}

func containsString(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func validateName(value string) error {
	if !utf8.ValidString(value) || value == "" || strings.TrimSpace(value) != value {
		return errors.New("odata: operation must be non-empty, trimmed UTF-8")
	}
	return nil
}

func validHTTPMethod(method string) bool {
	if method == "" {
		return false
	}
	for index := 0; index < len(method); index++ {
		character := method[index]
		if character >= '0' && character <= '9' || character >= 'A' && character <= 'Z' || character >= 'a' && character <= 'z' {
			continue
		}
		switch character {
		case '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~':
			continue
		default:
			return false
		}
	}
	return true
}
