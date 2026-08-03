package aauth

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
	"time"
)

const (
	R3VocabularyMCP            = "urn:aauth:vocabulary:mcp"
	R3VocabularyOpenAPI        = "urn:aauth:vocabulary:openapi"
	R3VocabularyOpenAPIGateway = "urn:aauth:vocabulary:openapi-gateway"
	R3VocabularyGRPC           = "urn:aauth:vocabulary:grpc"
	R3VocabularyGraphQL        = "urn:aauth:vocabulary:graphql"
	R3VocabularyAsyncAPI       = "urn:aauth:vocabulary:asyncapi"
	R3VocabularyWSDL           = "urn:aauth:vocabulary:wsdl"
	R3VocabularyOData          = "urn:aauth:vocabulary:odata"
)

// ValidateR3VocabularyURI accepts the standard R3 vocabulary URIs and absolute
// third-party vocabulary URIs. The AAuth-owned namespace is closed to unknown
// names so a typo cannot silently become a proprietary vocabulary.
func ValidateR3VocabularyURI(vocabulary string) error {
	return validateR3VocabularyURI(vocabulary)
}

// R3OperationSet is the common vocabulary envelope used by an agent request,
// an R3 document, and the granted or conditional claims in an auth token.
//
// Operations remain raw JSON because each vocabulary owns its entry shape.
// Validate enforces the standard vocabulary shapes defined by the R3 draft and
// admits structurally valid object entries for third-party vocabulary URIs.
type R3OperationSet struct {
	Vocabulary string            `json:"vocabulary"`
	Operations []json.RawMessage `json:"operations"`
}

// Validate checks the vocabulary envelope and every operation entry.
func (set R3OperationSet) Validate() error {
	return set.validate(false)
}

func (set R3OperationSet) validate(allowEmpty bool) error {
	if err := validateR3VocabularyURI(set.Vocabulary); err != nil {
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
func (set R3OperationSet) Clone() R3OperationSet {
	cloned := R3OperationSet{
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
func (set R3OperationSet) Equal(other R3OperationSet) bool {
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
func (set R3OperationSet) Contains(operation json.RawMessage) bool {
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
func (set R3OperationSet) ContainsSet(subset R3OperationSet) bool {
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

// R3Display describes the human-visible consequences of a grant.
type R3Display struct {
	Summary      string `json:"summary"`
	Implications string `json:"implications,omitempty"`
	DataAccessed string `json:"data_accessed,omitempty"`
	Irreversible string `json:"irreversible,omitempty"`
	Detail       string `json:"detail,omitempty"`
}

// R3Parameters preserves the proposal's machine-readable parameter values.
// A value with an s256 member is the draft's digest-object representation;
// every other value is an inline parameter.
type R3Parameters map[string]json.RawMessage

// R3CallParameter is the deployment-owned view of one actual call parameter.
// Inline values use Value. Digested values set Digest and provide the exact
// PresentedValue bytes; Excerpt is display-only and never authorizes a value.
type R3CallParameter struct {
	Value          json.RawMessage
	PresentedValue []byte
	Digest         bool
	Excerpt        string
	MediaType      string
}

// R3Proposal supplies the concrete call parameters and optional human context
// from which a resource serializes one exact per-call proposal.
type R3Proposal struct {
	Parameters map[string]R3CallParameter
	Display    *R3Display
}

// R3Document is the parsed form of the exact bytes published by a resource.
// Exact bytes remain separate because re-marshalling this value must never be
// used to verify or serve the document's content hash.
type R3Document struct {
	Version    string            `json:"version,omitempty"`
	Vocabulary string            `json:"vocabulary"`
	Operations []json.RawMessage `json:"operations"`
	Parameters *R3Parameters     `json:"parameters,omitempty"`
	Display    *R3Display        `json:"display,omitempty"`
}

// ParseR3Document validates an R3 document without altering its source bytes.
func ParseR3Document(exactBytes []byte) (R3Document, error) {
	var document R3Document
	if len(exactBytes) == 0 {
		return document, errors.New("aauth: R3 document is empty")
	}
	if err := rejectDuplicateJSONNames(exactBytes); err != nil {
		return document, fmt.Errorf("aauth: R3 document: %w", err)
	}
	if err := json.Unmarshal(exactBytes, &document); err != nil {
		return document, fmt.Errorf("aauth: parse R3 document: %w", err)
	}
	if err := document.OperationSet().Validate(); err != nil {
		return document, fmt.Errorf("aauth: R3 document: %w", err)
	}
	if document.Display != nil && strings.TrimSpace(document.Display.Summary) == "" {
		return document, errors.New("aauth: R3 document display.summary is required")
	}
	var topLevel map[string]json.RawMessage
	if err := json.Unmarshal(exactBytes, &topLevel); err != nil {
		return document, fmt.Errorf("aauth: parse R3 document fields: %w", err)
	}
	if raw, present := topLevel["parameters"]; present {
		if document.Parameters == nil || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return document, errors.New("aauth: R3 proposal parameters must be an object")
		}
		if len(document.Operations) != 1 {
			return document, errors.New("aauth: R3 proposal must contain exactly one operation")
		}
		if err := validateR3Parameters(*document.Parameters); err != nil {
			return document, err
		}
	}
	return document, nil
}

// OperationSet returns an independent operation-set view of the document.
func (document R3Document) OperationSet() R3OperationSet {
	return R3OperationSet{
		Vocabulary: document.Vocabulary,
		Operations: cloneRawMessages(document.Operations),
	}
}

// BuildR3Proposal serializes one validated proposal exactly once. Callers must
// retain the returned bytes and use them for both hashing and serving.
func BuildR3Proposal(operation R3OperationSet, proposal R3Proposal) ([]byte, error) {
	if err := operation.Validate(); err != nil {
		return nil, err
	}
	if len(operation.Operations) != 1 {
		return nil, errors.New("aauth: R3 proposal requires exactly one operation")
	}
	if proposal.Parameters == nil {
		return nil, errors.New("aauth: R3 proposal parameters are required")
	}
	parameters := make(R3Parameters, len(proposal.Parameters))
	for name, parameter := range proposal.Parameters {
		if name == "" {
			return nil, errors.New("aauth: R3 proposal parameter name must not be empty")
		}
		if parameter.Digest {
			if parameter.PresentedValue == nil {
				return nil, fmt.Errorf("aauth: R3 proposal parameter %q has no presented bytes", name)
			}
			encoded, err := json.Marshal(r3ParameterDigest{
				S256:      R3S256(parameter.PresentedValue),
				Excerpt:   parameter.Excerpt,
				MediaType: parameter.MediaType,
			})
			if err != nil {
				return nil, err
			}
			parameters[name] = encoded
			continue
		}
		if parameter.PresentedValue != nil {
			return nil, fmt.Errorf("aauth: inline R3 proposal parameter %q also has presented bytes", name)
		}
		if _, err := normalizeR3JSONValue(parameter.Value); err != nil {
			return nil, fmt.Errorf("aauth: R3 proposal parameter %q: %w", name, err)
		}
		parameters[name] = append(json.RawMessage(nil), parameter.Value...)
	}
	document := R3Document{
		Vocabulary: operation.Vocabulary,
		Operations: cloneRawMessages(operation.Operations),
		Parameters: &parameters,
		Display:    cloneR3Display(proposal.Display),
	}
	exactBytes, err := json.Marshal(document)
	if err != nil {
		return nil, fmt.Errorf("aauth: serialize R3 proposal: %w", err)
	}
	if _, err := ParseR3Document(exactBytes); err != nil {
		return nil, err
	}
	return exactBytes, nil
}

// MatchR3Call verifies one actual operation and every actual parameter against
// a parsed proposal. Digest values are checked over exact presented bytes;
// excerpts are intentionally ignored during enforcement.
func (document R3Document) MatchR3Call(
	operation R3OperationSet,
	actual map[string]R3CallParameter,
) error {
	if document.Parameters == nil {
		return errors.New("aauth: R3 document is not a per-call proposal")
	}
	if !document.OperationSet().Equal(operation) || len(operation.Operations) != 1 {
		return errors.New("aauth: R3 proposal operation does not match the actual call")
	}
	if actual == nil || len(actual) != len(*document.Parameters) {
		return errors.New("aauth: R3 proposal parameters do not match the actual call")
	}
	for name, approved := range *document.Parameters {
		parameter, exists := actual[name]
		if !exists {
			return fmt.Errorf("aauth: R3 proposal parameter %q is missing from the actual call", name)
		}
		digest, isDigest, err := parseR3ParameterDigest(approved)
		if err != nil {
			return fmt.Errorf("aauth: R3 proposal parameter %q: %w", name, err)
		}
		if isDigest {
			if !parameter.Digest || parameter.PresentedValue == nil ||
				R3S256(parameter.PresentedValue) != digest.S256 ||
				parameter.MediaType != digest.MediaType {
				return fmt.Errorf("aauth: R3 proposal parameter %q digest does not match the actual call", name)
			}
			continue
		}
		if parameter.Digest || parameter.PresentedValue != nil {
			return fmt.Errorf("aauth: R3 proposal parameter %q representation changed", name)
		}
		approvedValue, err := normalizeR3JSONValue(approved)
		if err != nil {
			return fmt.Errorf("aauth: R3 proposal parameter %q: %w", name, err)
		}
		actualValue, err := normalizeR3JSONValue(parameter.Value)
		if err != nil || !bytes.Equal(approvedValue, actualValue) {
			return fmt.Errorf("aauth: R3 proposal parameter %q does not match the actual call", name)
		}
	}
	return nil
}

// R3Authorization is the verified, exact-byte R3 input presented to access
// policy. URI and S256 are the resource-token reference that was verified.
type R3Authorization struct {
	URI        string
	S256       string
	ExactBytes []byte
	Document   R3Document
}

// Clone returns an independent policy input.
func (authorization *R3Authorization) Clone() *R3Authorization {
	if authorization == nil {
		return nil
	}
	return &R3Authorization{
		URI:        authorization.URI,
		S256:       authorization.S256,
		ExactBytes: append([]byte(nil), authorization.ExactBytes...),
		Document: R3Document{
			Version:    authorization.Document.Version,
			Vocabulary: authorization.Document.Vocabulary,
			Operations: cloneRawMessages(authorization.Document.Operations),
			Parameters: cloneR3Parameters(authorization.Document.Parameters),
			Display:    cloneR3Display(authorization.Document.Display),
		},
	}
}

// R3AuditRecord is the issuance fact the reference access server requires its
// deployment to retain before it releases an R3 auth token.
type R3AuditRecord struct {
	R3URI           string            `json:"r3_uri"`
	R3S256          string            `json:"r3_s256"`
	Agent           string            `json:"agent"`
	Resource        string            `json:"resource"`
	ResourceTokenID string            `json:"resource_token_id"`
	TokenID         string            `json:"token_id"`
	Mission         *MissionReference `json:"mission,omitempty"`
	R3Granted       *R3OperationSet   `json:"r3_granted,omitempty"`
	R3Conditional   *R3OperationSet   `json:"r3_conditional,omitempty"`
	IssuedAt        time.Time         `json:"issued_at"`
}

// R3S256 computes the unpadded base64url SHA-256 digest over exact bytes.
func R3S256(exactBytes []byte) string {
	digest := sha256.Sum256(exactBytes)
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

func validateR3Reference(uri, s256 string) error {
	if (uri == "") != (s256 == "") {
		return errors.New("aauth: R3 reference requires both r3_uri and r3_s256")
	}
	if uri == "" {
		return nil
	}
	if err := ValidateEndpoint(uri); err != nil {
		return fmt.Errorf("aauth: r3_uri: %w", err)
	}
	digest, err := base64.RawURLEncoding.DecodeString(s256)
	if err != nil || len(digest) != sha256.Size || base64.RawURLEncoding.EncodeToString(digest) != s256 {
		return errors.New("aauth: r3_s256 must be an unpadded base64url SHA-256 value")
	}
	return nil
}

func validateR3VocabularyURI(vocabulary string) error {
	parsed, err := url.Parse(vocabulary)
	if err != nil || !parsed.IsAbs() || parsed.Scheme == "" {
		return errors.New("aauth: R3 vocabulary must be an absolute URI")
	}
	if strings.HasPrefix(vocabulary, "urn:aauth:vocabulary:") {
		switch vocabulary {
		case R3VocabularyMCP,
			R3VocabularyOpenAPI,
			R3VocabularyOpenAPIGateway,
			R3VocabularyGRPC,
			R3VocabularyGraphQL,
			R3VocabularyAsyncAPI,
			R3VocabularyWSDL,
			R3VocabularyOData:
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
	if err := rejectDuplicateJSONNames(operation); err != nil {
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

type r3ParameterDigest struct {
	S256      string `json:"s256"`
	Excerpt   string `json:"excerpt,omitempty"`
	MediaType string `json:"media_type,omitempty"`
}

func validateR3Parameters(parameters R3Parameters) error {
	for name, raw := range parameters {
		if name == "" {
			return errors.New("aauth: R3 proposal parameter name must not be empty")
		}
		if _, err := normalizeR3JSONValue(raw); err != nil {
			return fmt.Errorf("aauth: R3 proposal parameter %q: %w", name, err)
		}
		if _, _, err := parseR3ParameterDigest(raw); err != nil {
			return fmt.Errorf("aauth: R3 proposal parameter %q: %w", name, err)
		}
	}
	return nil
}

func parseR3ParameterDigest(raw json.RawMessage) (r3ParameterDigest, bool, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil || fields == nil {
		return r3ParameterDigest{}, false, nil
	}
	if _, present := fields["s256"]; !present {
		return r3ParameterDigest{}, false, nil
	}
	for name := range fields {
		if name != "s256" && name != "excerpt" && name != "media_type" {
			return r3ParameterDigest{}, true, errors.New("digest object contains an unknown member")
		}
	}
	var digest r3ParameterDigest
	if err := json.Unmarshal(raw, &digest); err != nil {
		return r3ParameterDigest{}, true, errors.New("digest object is invalid")
	}
	decoded, err := base64.RawURLEncoding.DecodeString(digest.S256)
	if err != nil || len(decoded) != sha256.Size ||
		base64.RawURLEncoding.EncodeToString(decoded) != digest.S256 {
		return r3ParameterDigest{}, true, errors.New("digest object s256 is invalid")
	}
	if _, present := fields["excerpt"]; present && digest.Excerpt == "" {
		return r3ParameterDigest{}, true, errors.New("digest object excerpt must not be empty")
	}
	if _, present := fields["media_type"]; present && digest.MediaType == "" {
		return r3ParameterDigest{}, true, errors.New("digest object media_type must not be empty")
	}
	return digest, true, nil
}

func normalizeR3JSONValue(raw json.RawMessage) ([]byte, error) {
	if len(raw) == 0 || !json.Valid(raw) {
		return nil, errors.New("value must be valid JSON")
	}
	if err := rejectDuplicateJSONNames(raw); err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, errors.New("value must be valid JSON")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, errors.New("value must contain one JSON value")
	}
	normalized, err := json.Marshal(value)
	if err != nil {
		return nil, errors.New("value cannot be normalized")
	}
	return normalized, nil
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
	case R3VocabularyMCP:
		_, err := requireString("tool")
		return err
	case R3VocabularyOpenAPI:
		_, err := requireString("operationId")
		return err
	case R3VocabularyOpenAPIGateway:
		if _, err := requireString("service"); err != nil {
			return err
		}
		_, err := requireString("operationId")
		return err
	case R3VocabularyGRPC:
		method, err := requireString("method")
		if err != nil {
			return err
		}
		if !strings.Contains(method, "/") {
			return errors.New("method must be a fully qualified gRPC method")
		}
		return nil
	case R3VocabularyGraphQL:
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
	case R3VocabularyAsyncAPI:
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
	case R3VocabularyWSDL:
		if _, err := requireString("operation"); err != nil {
			return err
		}
		_, _, err := optionalString("service")
		return err
	case R3VocabularyOData:
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

func cloneR3Display(display *R3Display) *R3Display {
	if display == nil {
		return nil
	}
	cloned := *display
	return &cloned
}

func cloneR3Parameters(parameters *R3Parameters) *R3Parameters {
	if parameters == nil {
		return nil
	}
	cloned := make(R3Parameters, len(*parameters))
	for name, value := range *parameters {
		cloned[name] = append(json.RawMessage(nil), value...)
	}
	return &cloned
}

func cloneR3CallParameters(parameters map[string]R3CallParameter) map[string]R3CallParameter {
	if parameters == nil {
		return nil
	}
	cloned := make(map[string]R3CallParameter, len(parameters))
	for name, parameter := range parameters {
		parameter.Value = append(json.RawMessage(nil), parameter.Value...)
		parameter.PresentedValue = append([]byte(nil), parameter.PresentedValue...)
		cloned[name] = parameter
	}
	return cloned
}
