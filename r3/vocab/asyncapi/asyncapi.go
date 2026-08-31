// Package asyncapi implements the R3 AsyncAPI operation-object grammar and set
// algebra. Action presence and value are semantic.
package asyncapi

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

// URI is the standard R3 AsyncAPI vocabulary URI.
const URI r3.VocabularyURI = "urn:aauth:vocabulary:asyncapi"

// Action is the optional AsyncAPI operation action carried by R3.
type Action string

const (
	ActionSend    Action = "send"
	ActionReceive Action = "receive"
)

// Operation identifies one AsyncAPI operationId and retains whether action was
// present on the wire.
type Operation struct {
	operationID string
	action      *Action
}

// NewOperation constructs an operation with no action member.
func NewOperation(operationID string) (Operation, error) {
	return newOperation(operationID, nil)
}

// NewOperationWithAction constructs an operation with an explicit action.
func NewOperationWithAction(operationID string, action Action) (Operation, error) {
	return newOperation(operationID, &action)
}

func newOperation(operationID string, action *Action) (Operation, error) {
	if err := validateIdentifier("operationId", operationID); err != nil {
		return Operation{}, err
	}
	operation := Operation{operationID: operationID}
	if action != nil {
		if *action != ActionSend && *action != ActionReceive {
			return Operation{}, fmt.Errorf("asyncapi: action %q must be send or receive", *action)
		}
		copied := *action
		operation.action = &copied
	}
	return operation, nil
}

// OperationID returns the exact AsyncAPI operationId.
func (operation Operation) OperationID() string { return operation.operationID }

// Action returns the action and whether the optional member was present.
func (operation Operation) Action() (Action, bool) {
	if operation.action == nil {
		return "", false
	}
	return *operation.action, true
}

// MarshalJSON emits the exact AsyncAPI R3 operation object.
func (operation Operation) MarshalJSON() ([]byte, error) { return marshalOperation(operation) }

// UnmarshalJSON accepts only the exact AsyncAPI R3 operation object.
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

// FromR3 converts an AsyncAPI-tagged neutral operation to its typed form.
func FromR3(operation r3.Operation) (Operation, error) {
	if operation.Vocabulary() != URI {
		return Operation{}, fmt.Errorf("asyncapi: operation vocabulary is %q, want %q", operation.Vocabulary(), URI)
	}
	encoded := operation.JSON()
	if encoded == nil {
		return Operation{}, errors.New("asyncapi: operation is invalid")
	}
	local, err := r3.NewOperation(vocabulary, encoded)
	if err != nil {
		return Operation{}, err
	}
	equal, err := local.Equal(operation)
	if err != nil {
		return Operation{}, fmt.Errorf("asyncapi: operation uses another registration: %w", err)
	}
	if !equal {
		return Operation{}, errors.New("asyncapi: operation is not semantically equal to its AsyncAPI encoding")
	}
	return parseOperation(encoded)
}

// NewOperationSet constructs one neutral AsyncAPI operation set.
func NewOperationSet(operations ...Operation) (r3.OperationSet, error) {
	neutral := make([]r3.Operation, len(operations))
	for index, operation := range operations {
		converted, err := operation.ToR3()
		if err != nil {
			return r3.OperationSet{}, fmt.Errorf("asyncapi: operation %d: %w", index, err)
		}
		neutral[index] = converted
	}
	return r3.NewOperationSet(neutral...)
}

// set is an immutable AsyncAPI operation set retained in wire order.
type set struct{ operations []Operation }

// Operations returns a copy of the retained operation sequence.
func (set set) Operations() []Operation { return append([]Operation(nil), set.operations...) }

// codec implements strict AsyncAPI operation parsing and set algebra.
type codec struct{}

var vocabulary = mustVocabulary()

func mustVocabulary() r3.Vocabulary {
	value, err := r3.NewVocabulary[set](codec{})
	if err != nil {
		panic(err)
	}
	return value
}

// Vocabulary returns the immutable standard AsyncAPI registration.
func Vocabulary() r3.Vocabulary { return vocabulary }

func (codec) URI() r3.VocabularyURI { return URI }

// AnnotationEncoding reports that AsyncAPI carries R3 hints in specification extensions.
func (codec) AnnotationEncoding() r3.AnnotationEncoding {
	return r3.AnnotationSpecificationExtension
}

func (codec) ValidateDiscoveryEndpoint(endpoint string) error {
	return discoveryendpoint.ValidateStandard(endpoint)
}

func (codec) ParseSet(raw []json.RawMessage) (set, error) {
	operations := make([]Operation, 0, len(raw))
	seen := make(map[string]struct{}, len(raw))
	for index, value := range raw {
		operation, err := parseOperation(value)
		if err != nil {
			return set{}, fmt.Errorf("asyncapi: operation %d: %w", index, err)
		}
		if _, duplicate := seen[operation.operationID]; duplicate {
			return set{}, fmt.Errorf("asyncapi: duplicate operationId %q", operation.operationID)
		}
		seen[operation.operationID] = struct{}{}
		operations = append(operations, operation)
	}
	return set{operations: operations}, nil
}

func (codec) MarshalSet(operations set) ([]json.RawMessage, error) {
	result := make([]json.RawMessage, len(operations.operations))
	for index, operation := range operations.operations {
		encoded, err := marshalOperation(operation)
		if err != nil {
			return nil, fmt.Errorf("asyncapi: operation %d: %w", index, err)
		}
		result[index] = encoded
	}
	return result, nil
}

func (codec) Union(sets ...set) (set, error) {
	var result set
	seen := make(map[string]Operation)
	for _, candidateSet := range sets {
		for _, operation := range candidateSet.operations {
			prior, exists := seen[operation.operationID]
			if !exists {
				seen[operation.operationID] = operation
				result.operations = append(result.operations, operation)
				continue
			}
			if !equalOperation(prior, operation) {
				return set{}, fmt.Errorf("asyncapi: operationId %q has conflicting action presence or value", operation.operationID)
			}
		}
	}
	return result, nil
}

func (codec) Equal(left, right set) bool {
	return len(left.operations) == len(right.operations) && subset(left, right)
}

func (codec) Subset(left, right set) bool { return subset(left, right) }

func (codec) Disjoint(left, right set) bool {
	for _, operation := range left.operations {
		if contains(right, operation) {
			return false
		}
	}
	return true
}

func parseOperation(raw []byte) (Operation, error) {
	var operationID, actionText string
	seen, err := wirejson.Object(raw, map[string]func(json.RawMessage) error{
		"operationId": func(value json.RawMessage) error { return wirejson.String(value, &operationID) },
		"action":      func(value json.RawMessage) error { return wirejson.String(value, &actionText) },
	})
	if err != nil {
		return Operation{}, err
	}
	if _, present := seen["operationId"]; !present {
		return Operation{}, errors.New("operationId is required")
	}
	if _, present := seen["action"]; present {
		return NewOperationWithAction(operationID, Action(actionText))
	}
	return NewOperation(operationID)
}

func marshalOperation(operation Operation) (json.RawMessage, error) {
	validated, err := newOperation(operation.operationID, operation.action)
	if err != nil {
		return nil, err
	}
	return json.Marshal(struct {
		OperationID string  `json:"operationId"`
		Action      *Action `json:"action,omitempty"`
	}{OperationID: validated.operationID, Action: validated.action})
}

func equalOperation(left, right Operation) bool {
	if left.operationID != right.operationID || (left.action == nil) != (right.action == nil) {
		return false
	}
	return left.action == nil || *left.action == *right.action
}

func subset(left, right set) bool {
	for _, operation := range left.operations {
		if !contains(right, operation) {
			return false
		}
	}
	return true
}

func contains(set set, operation Operation) bool {
	for _, candidate := range set.operations {
		if equalOperation(candidate, operation) {
			return true
		}
	}
	return false
}

var _ r3.Codec[set] = codec{}

func validateIdentifier(name, value string) error {
	if !utf8.ValidString(value) || value == "" || strings.TrimSpace(value) != value {
		return fmt.Errorf("asyncapi: %s must be non-empty, trimmed UTF-8", name)
	}
	return nil
}
