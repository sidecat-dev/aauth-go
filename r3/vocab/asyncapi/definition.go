package asyncapi

import (
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/r3"
	"gitlab.com/sidecat-dev/aauth-go/r3/internal/wirejson"
)

const sourceEncoding r3.SourceEncoding = "urn:aauth:source-encoding:asyncapi-application-json-focused-v1"

// JSONDocumentSource owns one exact AsyncAPI JSON document. YAML conversion,
// fetching, and reference resolution are outside this parser.
type JSONDocumentSource struct{ exact []byte }

// NewJSONDocumentSource copies an exact AsyncAPI JSON document.
func NewJSONDocumentSource(exact []byte) JSONDocumentSource {
	return JSONDocumentSource{exact: append([]byte(nil), exact...)}
}

// ExactBytes returns an owned copy of the document.
func (source JSONDocumentSource) ExactBytes() []byte {
	return append([]byte(nil), source.exact...)
}

type definitionCodec struct{}

func (definitionCodec) Vocabulary() r3.Vocabulary { return Vocabulary() }

func (definitionCodec) ParseDefinition(source JSONDocumentSource) (r3.DefinitionMaterial, error) {
	if err := wirejson.ValidateSource(source.exact); err != nil {
		return r3.DefinitionMaterial{}, definitionError(r3.DefinitionInvalidSource, "invalid AsyncAPI JSON", err)
	}
	if err := validateNoExternalReferences(source.exact); err != nil {
		return r3.DefinitionMaterial{}, err
	}
	var document struct {
		Version    string                     `json:"asyncapi"`
		Info       json.RawMessage            `json:"info"`
		Channels   map[string]json.RawMessage `json:"channels"`
		Operations map[string]json.RawMessage `json:"operations"`
	}
	if err := json.Unmarshal(source.exact, &document); err != nil {
		return r3.DefinitionMaterial{}, definitionError(r3.DefinitionInvalidSource, "invalid AsyncAPI document", err)
	}
	if document.Version != "3.0.0" && document.Version != "3.1.0" {
		return r3.DefinitionMaterial{}, definitionError(r3.DefinitionSourceKindUnsupported, "only AsyncAPI 3.0.0 and 3.1.0 JSON documents are supported", nil)
	}
	if err := validateInfo(document.Info); err != nil {
		return r3.DefinitionMaterial{}, err
	}
	if len(document.Channels) == 0 {
		return r3.DefinitionMaterial{}, definitionError(r3.DefinitionIncompleteSource, "AsyncAPI document has no channels", nil)
	}
	if len(document.Operations) == 0 {
		return r3.DefinitionMaterial{}, definitionError(r3.DefinitionIncompleteSource, "AsyncAPI document has no operations", nil)
	}
	identifiers := make([]string, 0, len(document.Operations))
	for identifier := range document.Operations {
		identifiers = append(identifiers, identifier)
	}
	sort.Strings(identifiers)

	operations := make([]r3.DefinedOperation, 0, len(identifiers))
	for _, identifier := range identifiers {
		defined, err := parseDefinedOperation(identifier, document.Operations[identifier], document.Channels)
		if err != nil {
			return r3.DefinitionMaterial{}, err
		}
		operations = append(operations, defined)
	}
	return r3.NewDefinitionMaterial(sourceEncoding, source.ExactBytes(), operations...)
}

func validateInfo(raw json.RawMessage) error {
	var info struct {
		Title   string `json:"title"`
		Version string `json:"version"`
	}
	if len(raw) == 0 || json.Unmarshal(raw, &info) != nil || info.Title == "" || info.Version == "" {
		return definitionError(r3.DefinitionIncompleteSource, "AsyncAPI info requires title and version", nil)
	}
	return nil
}

func parseDefinedOperation(
	identifier string,
	raw json.RawMessage,
	channels map[string]json.RawMessage,
) (r3.DefinedOperation, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil || fields == nil {
		return r3.DefinedOperation{}, definitionError(r3.DefinitionInvalidSource, fmt.Sprintf("AsyncAPI operation %q is not an object", identifier), err)
	}
	if _, referenced := fields["$ref"]; referenced {
		return r3.DefinedOperation{}, definitionError(r3.DefinitionUnresolvedDependency, fmt.Sprintf("AsyncAPI operation %q is a reference", identifier), nil)
	}
	if _, traits := fields["traits"]; traits {
		return r3.DefinedOperation{}, definitionError(r3.DefinitionSourceKindUnsupported, fmt.Sprintf("AsyncAPI operation %q uses traits outside the focused parser profile", identifier), nil)
	}
	if err := validateOperationChannel(identifier, fields["channel"], channels); err != nil {
		return r3.DefinedOperation{}, err
	}
	var action Action
	actionRaw, present := fields["action"]
	if !present || json.Unmarshal(actionRaw, &action) != nil || (action != ActionSend && action != ActionReceive) {
		return r3.DefinedOperation{}, definitionError(r3.DefinitionInvalidSource, fmt.Sprintf("AsyncAPI operation %q requires action send or receive", identifier), nil)
	}
	operation, err := NewOperationWithAction(identifier, action)
	if err != nil {
		return r3.DefinedOperation{}, definitionError(r3.DefinitionInvalidSource, "invalid AsyncAPI operation identity", err)
	}

	var mode *aauth.AccessMode
	if rawMode, present := fields["x-aauth-access-mode"]; present {
		var value aauth.AccessMode
		if err := json.Unmarshal(rawMode, &value); err != nil {
			return r3.DefinedOperation{}, definitionError(r3.DefinitionInvalidAnnotation, fmt.Sprintf("AsyncAPI operation %q has a non-string access mode", identifier), err)
		}
		mode = &value
	}
	var budget *bool
	if rawBudget, present := fields["x-aauth-budget"]; present {
		var value *bool
		if err := json.Unmarshal(rawBudget, &value); err != nil || value == nil {
			return r3.DefinedOperation{}, definitionError(r3.DefinitionInvalidAnnotation, fmt.Sprintf("AsyncAPI operation %q has a non-boolean budget", identifier), err)
		}
		budget = value
	}
	encoded, err := json.Marshal(operation)
	if err != nil {
		return r3.DefinedOperation{}, definitionError(r3.DefinitionInvalidSource, "encode derived AsyncAPI operation", err)
	}
	if mode == nil && budget == nil {
		return r3.NewDefinedOperation(encoded, nil)
	}
	hints, err := r3.NewOperationHints(mode, budget)
	if err != nil {
		return r3.DefinedOperation{}, definitionError(r3.DefinitionInvalidAnnotation, fmt.Sprintf("AsyncAPI operation %q has invalid hints", identifier), err)
	}
	return r3.NewDefinedOperation(encoded, &hints)
}

func validateOperationChannel(identifier string, raw json.RawMessage, channels map[string]json.RawMessage) error {
	var reference struct {
		Ref string `json:"$ref"`
	}
	if len(raw) == 0 || json.Unmarshal(raw, &reference) != nil || reference.Ref == "" {
		return definitionError(r3.DefinitionIncompleteSource, fmt.Sprintf("AsyncAPI operation %q requires a channel reference", identifier), nil)
	}
	name, err := decodeChannelReference(reference.Ref)
	if err != nil {
		return definitionError(r3.DefinitionUnresolvedDependency, fmt.Sprintf("AsyncAPI operation %q uses external channel reference %q", identifier, reference.Ref), nil)
	}
	channel, present := channels[name]
	if !present {
		return definitionError(r3.DefinitionUnresolvedDependency, fmt.Sprintf("AsyncAPI operation %q references missing channel %q", identifier, name), nil)
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(channel, &fields) != nil || fields == nil {
		return definitionError(r3.DefinitionInvalidSource, fmt.Sprintf("AsyncAPI channel %q is not an object", name), nil)
	}
	if _, reference := fields["$ref"]; reference {
		return definitionError(r3.DefinitionUnresolvedDependency, fmt.Sprintf("AsyncAPI channel %q requires reference resolution", name), nil)
	}
	return nil
}

func decodeChannelReference(reference string) (string, error) {
	const prefix = "#/channels/"
	if !strings.HasPrefix(reference, prefix) {
		return "", fmt.Errorf("reference is not a local channel pointer")
	}
	token, err := url.PathUnescape(strings.TrimPrefix(reference, prefix))
	if err != nil {
		return "", fmt.Errorf("channel reference contains invalid percent encoding")
	}
	if token == "" || strings.Contains(token, "/") {
		return "", fmt.Errorf("channel reference must contain exactly one JSON Pointer token")
	}
	var decoded strings.Builder
	for index := 0; index < len(token); index++ {
		if token[index] != '~' {
			decoded.WriteByte(token[index])
			continue
		}
		if index+1 >= len(token) || (token[index+1] != '0' && token[index+1] != '1') {
			return "", fmt.Errorf("channel reference contains an invalid JSON Pointer escape")
		}
		index++
		if token[index] == '0' {
			decoded.WriteByte('~')
		} else {
			decoded.WriteByte('/')
		}
	}
	return decoded.String(), nil
}

func validateNoExternalReferences(source []byte) error {
	var document any
	if err := json.Unmarshal(source, &document); err != nil {
		return definitionError(r3.DefinitionInvalidSource, "invalid AsyncAPI JSON", err)
	}
	var walk func(any) error
	walk = func(value any) error {
		switch value := value.(type) {
		case map[string]any:
			if raw, present := value["$ref"]; present {
				reference, ok := raw.(string)
				if !ok {
					return definitionError(r3.DefinitionInvalidSource, "AsyncAPI $ref must be a string", nil)
				}
				if !strings.HasPrefix(reference, "#/") {
					return definitionError(r3.DefinitionUnresolvedDependency, fmt.Sprintf("AsyncAPI external reference %q requires caller resolution", reference), nil)
				}
			}
			keys := make([]string, 0, len(value))
			for key := range value {
				keys = append(keys, key)
			}
			sort.Strings(keys)
			for _, key := range keys {
				if err := walk(value[key]); err != nil {
					return err
				}
			}
		case []any:
			for _, child := range value {
				if err := walk(child); err != nil {
					return err
				}
			}
		}
		return nil
	}
	return walk(document)
}

func definitionError(kind r3.DefinitionErrorKind, reason string, cause error) error {
	return r3.NewDefinitionError(kind, reason, cause)
}

var definitionParser = mustDefinitionParser()

func mustDefinitionParser() r3.DefinitionParser[JSONDocumentSource] {
	parser, err := r3.NewDefinitionParser[JSONDocumentSource](definitionCodec{})
	if err != nil {
		panic(err)
	}
	return parser
}

// ParseDefinition derives R3 operations and advisory hints from the focused
// self-contained AsyncAPI JSON profile documented by this package.
func ParseDefinition(endpoint string, source JSONDocumentSource) (r3.AuthoritativeSnapshot, error) {
	return definitionParser.Parse(endpoint, source)
}

// DefinitionRegistration returns the stable AsyncAPI definition registration.
func DefinitionRegistration() r3.DefinitionRegistration {
	return definitionParser.Registration()
}
