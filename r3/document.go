// Package r3 implements the current exact-byte R3 document and operation
// vocabulary model. It does not, by itself, authorize an operation.
package r3

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"

	"gitlab.com/sidecat-dev/aauth-go/internal/jsonstrict"
)

const (
	VocabularyMCP      = "urn:aauth:vocabulary:mcp"
	VocabularyOpenAPI  = "urn:aauth:vocabulary:openapi"
	VocabularyGRPC     = "urn:aauth:vocabulary:grpc"
	VocabularyGraphQL  = "urn:aauth:vocabulary:graphql"
	VocabularyAsyncAPI = "urn:aauth:vocabulary:asyncapi"
	VocabularyWSDL     = "urn:aauth:vocabulary:wsdl"
	VocabularyOData    = "urn:aauth:vocabulary:odata"
)

// ValidateVocabularyURI accepts the standard R3 vocabulary URIs and absolute
// third-party vocabulary URIs. The AAuth-owned namespace is closed to unknown
// names so a typo cannot silently become a proprietary vocabulary.
func ValidateVocabularyURI(vocabulary string) error {
	return validateVocabularyURI(vocabulary)
}

// OperationSet is the vocabulary envelope retained in a neutral R3 document.
//
// Operations remain raw JSON because each vocabulary owns its entry shape.
// Validate enforces the standard vocabulary shapes defined by the R3 draft and
// admits structurally valid object entries for third-party vocabulary URIs.
type OperationSet struct {
	Vocabulary string            `json:"vocabulary"`
	Operations []json.RawMessage `json:"operations"`
}

// ParseOperationSet strictly decodes and validates one operation-set value.
func ParseOperationSet(exact []byte) (OperationSet, error) {
	var set OperationSet
	if err := jsonstrict.RejectAmbiguousNames(exact); err != nil {
		return set, fmt.Errorf("aauth: R3 operation set: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(exact))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&set); err != nil {
		return set, fmt.Errorf("aauth: parse R3 operation set: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return set, errors.New("aauth: R3 operation set must contain one JSON value")
	}
	if err := set.Validate(); err != nil {
		return OperationSet{}, err
	}
	return set, nil
}

// Validate checks the vocabulary envelope and every operation entry.
func (set OperationSet) Validate() error {
	return set.validate(false)
}

func (set OperationSet) validate(allowEmpty bool) error {
	if err := validateVocabularyURI(set.Vocabulary); err != nil {
		return err
	}
	if len(set.Operations) == 0 && !allowEmpty {
		return errors.New("aauth: R3 operations must not be empty")
	}
	seen := make(map[string]struct{}, len(set.Operations))
	for index, operation := range set.Operations {
		normalized, fields, err := parseR3Operation(operation)
		if err != nil {
			return fmt.Errorf("aauth: R3 operation %d: %w", index, err)
		}
		if err := validateR3OperationFields(set.Vocabulary, fields); err != nil {
			return fmt.Errorf("aauth: R3 operation %d: %w", index, err)
		}
		if _, duplicate := seen[normalized]; duplicate {
			return fmt.Errorf("aauth: R3 operation %d duplicates an earlier operation", index)
		}
		seen[normalized] = struct{}{}
	}
	return nil
}

// Clone returns an independent copy suitable for crossing a policy boundary.
func (set OperationSet) Clone() OperationSet {
	cloned := OperationSet{
		Vocabulary: set.Vocabulary,
		Operations: make([]json.RawMessage, len(set.Operations)),
	}
	for index, operation := range set.Operations {
		cloned.Operations[index] = append(json.RawMessage(nil), operation...)
	}
	return cloned
}

// Equal compares operation sets as JSON values. Object member order,
// insignificant JSON whitespace, and array order do not affect set equality.
func (set OperationSet) Equal(other OperationSet) bool {
	if set.Vocabulary != other.Vocabulary || len(set.Operations) != len(other.Operations) {
		return false
	}
	if set.Validate() != nil || other.Validate() != nil {
		return false
	}
	for _, operation := range set.Operations {
		if !other.Contains(operation) {
			return false
		}
	}
	return true
}

// Contains reports whether an operation is a member of this set.
func (set OperationSet) Contains(operation json.RawMessage) bool {
	candidate, _, err := parseR3Operation(operation)
	if err != nil {
		return false
	}
	for _, member := range set.Operations {
		normalized, _, memberErr := parseR3Operation(member)
		if memberErr == nil && normalized == candidate {
			return true
		}
	}
	return false
}

// ContainsSet reports whether every operation in subset is present in set.
func (set OperationSet) ContainsSet(subset OperationSet) bool {
	if set.Vocabulary != subset.Vocabulary {
		return false
	}
	for _, operation := range subset.Operations {
		if !set.Contains(operation) {
			return false
		}
	}
	return true
}

// Display describes the human-visible consequences of a grant.
type Display struct {
	Summary      string `json:"summary"`
	Implications string `json:"implications,omitempty"`
	DataAccessed string `json:"data_accessed,omitempty"`
	Irreversible string `json:"irreversible,omitempty"`
	Detail       string `json:"detail,omitempty"`
}

// Document is the parsed form of the exact bytes published by a resource.
// Exact bytes remain separate because re-marshalling this value must never be
// used to verify or serve the document's content hash.
type Document struct {
	Vocabulary string                     `json:"vocabulary"`
	Operations []json.RawMessage          `json:"operations"`
	Account    string                     `json:"account,omitempty"`
	Parameters map[string]json.RawMessage `json:"parameters,omitempty"`
	Display    *Display                   `json:"display,omitempty"`
}

// ParseDocument validates an R3 document without altering its source bytes.
func ParseDocument(exactBytes []byte) (Document, error) {
	var document Document
	if len(exactBytes) == 0 {
		return document, errors.New("aauth: R3 document is empty")
	}
	if err := jsonstrict.RejectAmbiguousNames(exactBytes); err != nil {
		return document, fmt.Errorf("aauth: R3 document: %w", err)
	}
	var topLevel map[string]json.RawMessage
	if err := json.Unmarshal(exactBytes, &topLevel); err != nil {
		return document, fmt.Errorf("aauth: parse R3 document fields: %w", err)
	}
	if raw, present := topLevel["parameters"]; present && bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return document, errors.New("aauth: R3 document parameters must be an object")
	}
	decoder := json.NewDecoder(bytes.NewReader(exactBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&document); err != nil {
		return document, fmt.Errorf("aauth: parse R3 document: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return document, errors.New("aauth: R3 document must contain one JSON value")
	}
	if err := document.OperationSet().Validate(); err != nil {
		return document, fmt.Errorf("aauth: R3 document: %w", err)
	}
	if document.Display != nil && strings.TrimSpace(document.Display.Summary) == "" {
		return document, errors.New("aauth: R3 document display.summary is required")
	}
	return document, nil
}

// OperationSet returns an independent operation-set view of the document.
func (document Document) OperationSet() OperationSet {
	return OperationSet{
		Vocabulary: document.Vocabulary,
		Operations: cloneRawMessages(document.Operations),
	}
}

// S256 computes the unpadded base64url SHA-256 digest over exact bytes.
func S256(exactBytes []byte) string {
	digest := sha256.Sum256(exactBytes)
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

func validateVocabularyURI(vocabulary string) error {
	parsed, err := url.Parse(vocabulary)
	if err != nil || !parsed.IsAbs() || parsed.Scheme == "" {
		return errors.New("aauth: R3 vocabulary must be an absolute URI")
	}
	if strings.HasPrefix(vocabulary, "urn:aauth:vocabulary:") {
		switch vocabulary {
		case VocabularyMCP,
			VocabularyOpenAPI,
			VocabularyGRPC,
			VocabularyGraphQL,
			VocabularyAsyncAPI,
			VocabularyWSDL,
			VocabularyOData:
			return nil
		default:
			return errors.New("aauth: R3 standard vocabulary URI is unknown")
		}
	}
	return nil
}

func parseR3Operation(operation json.RawMessage) (string, map[string]json.RawMessage, error) {
	if len(operation) == 0 || !json.Valid(operation) {
		return "", nil, errors.New("operation must be valid JSON")
	}
	if err := jsonstrict.RejectAmbiguousNames(operation); err != nil {
		return "", nil, err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(operation, &fields); err != nil || fields == nil {
		return "", nil, errors.New("operation must be a JSON object")
	}
	if len(fields) == 0 {
		return "", nil, errors.New("operation object must not be empty")
	}
	decoder := json.NewDecoder(bytes.NewReader(operation))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return "", nil, errors.New("operation must be valid JSON")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return "", nil, errors.New("operation must contain one JSON value")
	}
	normalized, err := json.Marshal(value)
	if err != nil {
		return "", nil, errors.New("operation cannot be normalized")
	}
	return string(normalized), fields, nil
}

func validateR3OperationFields(vocabulary string, fields map[string]json.RawMessage) error {
	requireString := func(name string) (string, error) {
		raw, exists := fields[name]
		if !exists {
			return "", fmt.Errorf("%s is required", name)
		}
		var value string
		if err := json.Unmarshal(raw, &value); err != nil || strings.TrimSpace(value) == "" {
			return "", fmt.Errorf("%s must be a non-empty string", name)
		}
		return value, nil
	}
	optionalString := func(name string) (string, bool, error) {
		raw, exists := fields[name]
		if !exists {
			return "", false, nil
		}
		var value string
		if err := json.Unmarshal(raw, &value); err != nil || strings.TrimSpace(value) == "" {
			return "", true, fmt.Errorf("%s must be a non-empty string", name)
		}
		return value, true, nil
	}

	switch vocabulary {
	case VocabularyMCP:
		_, err := requireString("tool")
		return err
	case VocabularyOpenAPI:
		_, err := requireString("operationId")
		return err
	case VocabularyGRPC:
		method, err := requireString("method")
		if err != nil {
			return err
		}
		if !strings.Contains(method, "/") {
			return errors.New("method must be a fully qualified gRPC method")
		}
		return nil
	case VocabularyGraphQL:
		if _, err := requireString("operation"); err != nil {
			return err
		}
		operationType, err := requireString("type")
		if err != nil {
			return err
		}
		if operationType != "query" && operationType != "mutation" && operationType != "subscription" {
			return errors.New("type must be query, mutation, or subscription")
		}
		return nil
	case VocabularyAsyncAPI:
		if _, err := requireString("operationId"); err != nil {
			return err
		}
		action, exists, err := optionalString("action")
		if err != nil {
			return err
		}
		if exists && action != "send" && action != "receive" {
			return errors.New("action must be send or receive")
		}
		return nil
	case VocabularyWSDL:
		if _, err := requireString("operation"); err != nil {
			return err
		}
		_, _, err := optionalString("service")
		return err
	case VocabularyOData:
		if _, err := requireString("operation"); err != nil {
			return err
		}
		raw, exists := fields["methods"]
		if !exists {
			return nil
		}
		var methods []string
		if err := json.Unmarshal(raw, &methods); err != nil || len(methods) == 0 {
			return errors.New("methods must be a non-empty string array")
		}
		for _, method := range methods {
			if strings.TrimSpace(method) == "" || method != strings.ToUpper(method) {
				return errors.New("methods entries must be non-empty uppercase strings")
			}
		}
		return nil
	default:
		return nil
	}
}

func cloneRawMessages(messages []json.RawMessage) []json.RawMessage {
	if messages == nil {
		return nil
	}
	cloned := make([]json.RawMessage, len(messages))
	for index, message := range messages {
		cloned[index] = append(json.RawMessage(nil), message...)
	}
	return cloned
}
