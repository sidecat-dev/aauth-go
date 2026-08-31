// Package wsdl implements the R3 WSDL operation grammar and a self-contained
// WSDL 1.1 service/binding definition adapter. Ambiguous bindings and external
// imports refuse rather than being guessed. An omitted service overlaps a
// qualified operation with the same name.
package wsdl

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"gitlab.com/sidecat-dev/aauth-go/r3"
	"gitlab.com/sidecat-dev/aauth-go/r3/internal/wirejson"
	"gitlab.com/sidecat-dev/aauth-go/r3/vocab/internal/discoveryendpoint"
)

// URI is the standard R3 WSDL vocabulary URI.
const URI r3.VocabularyURI = "urn:aauth:vocabulary:wsdl"

// Operation identifies one WSDL operation and retains whether service was
// present on the wire.
type Operation struct {
	name    string
	service *string
}

// NewOperation constructs an operation with no service member.
func NewOperation(name string) (Operation, error) { return newOperation(name, nil) }

// NewServiceOperation constructs an operation qualified by a WSDL service.
func NewServiceOperation(name, service string) (Operation, error) {
	return newOperation(name, &service)
}

func newOperation(name string, service *string) (Operation, error) {
	if err := validateName("operation", name); err != nil {
		return Operation{}, err
	}
	operation := Operation{name: name}
	if service != nil {
		if err := validateName("service", *service); err != nil {
			return Operation{}, err
		}
		copied := *service
		operation.service = &copied
	}
	return operation, nil
}

// OperationName returns the exact WSDL operation name.
func (operation Operation) OperationName() string { return operation.name }

// Service returns the service and whether the optional member was present.
func (operation Operation) Service() (string, bool) {
	if operation.service == nil {
		return "", false
	}
	return *operation.service, true
}

// MarshalJSON emits the exact WSDL R3 operation object.
func (operation Operation) MarshalJSON() ([]byte, error) { return marshalOperation(operation) }

// UnmarshalJSON accepts only the exact WSDL R3 operation object.
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

// FromR3 converts a WSDL-tagged neutral operation to its typed form.
func FromR3(operation r3.Operation) (Operation, error) {
	if operation.Vocabulary() != URI {
		return Operation{}, fmt.Errorf("wsdl: operation vocabulary is %q, want %q", operation.Vocabulary(), URI)
	}
	encoded := operation.JSON()
	if encoded == nil {
		return Operation{}, errors.New("wsdl: operation is invalid")
	}
	local, err := r3.NewOperation(vocabulary, encoded)
	if err != nil {
		return Operation{}, err
	}
	equal, err := local.Equal(operation)
	if err != nil {
		return Operation{}, fmt.Errorf("wsdl: operation uses another registration: %w", err)
	}
	if !equal {
		return Operation{}, errors.New("wsdl: operation is not semantically equal to its WSDL encoding")
	}
	return parseOperation(encoded)
}

// NewOperationSet constructs one neutral WSDL operation set.
func NewOperationSet(operations ...Operation) (r3.OperationSet, error) {
	neutral := make([]r3.Operation, len(operations))
	for index, operation := range operations {
		converted, err := operation.ToR3()
		if err != nil {
			return r3.OperationSet{}, fmt.Errorf("wsdl: operation %d: %w", index, err)
		}
		neutral[index] = converted
	}
	return r3.NewOperationSet(neutral...)
}

// set is an immutable WSDL operation set retained in wire order.
type set struct{ operations []Operation }

// Operations returns a copy of the retained operation sequence.
func (set set) Operations() []Operation { return append([]Operation(nil), set.operations...) }

// codec implements strict WSDL operation parsing and set algebra.
type codec struct{}

var vocabulary = mustVocabulary()

func mustVocabulary() r3.Vocabulary {
	value, err := r3.NewVocabulary[set](codec{})
	if err != nil {
		panic(err)
	}
	return value
}

// Vocabulary returns the immutable standard WSDL registration.
func Vocabulary() r3.Vocabulary { return vocabulary }

func (codec) URI() r3.VocabularyURI { return URI }

// AnnotationEncoding reports that the R3 draft defines no WSDL annotation mechanism.
func (codec) AnnotationEncoding() r3.AnnotationEncoding { return r3.AnnotationUnavailable }

func (codec) ValidateDiscoveryEndpoint(endpoint string) error {
	return discoveryendpoint.ValidateStandard(endpoint)
}

func (codec) ParseSet(raw []json.RawMessage) (set, error) {
	result := set{operations: make([]Operation, 0, len(raw))}
	for index, value := range raw {
		operation, err := parseOperation(value)
		if err != nil {
			return set{}, fmt.Errorf("wsdl: operation %d: %w", index, err)
		}
		if err := appendOperation(&result, operation, false); err != nil {
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
			return nil, fmt.Errorf("wsdl: operation %d: %w", index, err)
		}
		result[index] = encoded
	}
	return result, nil
}

func (codec) Union(sets ...set) (set, error) {
	var result set
	for _, candidateSet := range sets {
		for _, operation := range candidateSet.operations {
			if err := appendOperation(&result, operation, true); err != nil {
				return set{}, err
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
	var name, service string
	seen, err := wirejson.Object(raw, map[string]func(json.RawMessage) error{
		"operation": func(value json.RawMessage) error { return wirejson.String(value, &name) },
		"service":   func(value json.RawMessage) error { return wirejson.String(value, &service) },
	})
	if err != nil {
		return Operation{}, err
	}
	if _, present := seen["operation"]; !present {
		return Operation{}, errors.New("operation is required")
	}
	if _, present := seen["service"]; present {
		return NewServiceOperation(name, service)
	}
	return NewOperation(name)
}

func marshalOperation(operation Operation) (json.RawMessage, error) {
	validated, err := newOperation(operation.name, operation.service)
	if err != nil {
		return nil, err
	}
	return json.Marshal(struct {
		Operation string  `json:"operation"`
		Service   *string `json:"service,omitempty"`
	}{Operation: validated.name, Service: validated.service})
}

func appendOperation(set *set, operation Operation, dedupeExact bool) error {
	for _, existing := range set.operations {
		if existing.name != operation.name {
			continue
		}
		if equalOperation(existing, operation) {
			if dedupeExact {
				return nil
			}
			return fmt.Errorf("wsdl: duplicate operation %q", operation.name)
		}
		if existing.service == nil || operation.service == nil {
			return fmt.Errorf("wsdl: unqualified operation %q ambiguously overlaps a service-qualified operation", operation.name)
		}
	}
	set.operations = append(set.operations, operation)
	return nil
}

func equalOperation(left, right Operation) bool {
	if left.name != right.name || (left.service == nil) != (right.service == nil) {
		return false
	}
	return left.service == nil || *left.service == *right.service
}

func overlaps(left, right Operation) bool {
	if left.name != right.name {
		return false
	}
	return left.service == nil || right.service == nil || *left.service == *right.service
}

func subset(left, right set) bool {
	for _, operation := range left.operations {
		found := false
		for _, candidate := range right.operations {
			if equalOperation(operation, candidate) {
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

func validateName(name, value string) error {
	if !utf8.ValidString(value) || value == "" || strings.TrimSpace(value) != value {
		return fmt.Errorf("wsdl: %s must be non-empty, trimmed UTF-8", name)
	}
	return nil
}
