package openapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"slices"
	"strings"

	"github.com/getkin/kin-openapi/openapi3"
	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/r3"
	"gitlab.com/sidecat-dev/aauth-go/r3/internal/wirejson"
	"gopkg.in/yaml.v3"
)

// DocumentSource owns the exact caller-supplied OpenAPI document bytes.
// Acquisition and external reference resolution are deliberately outside the
// adapter.
type DocumentSource struct {
	data []byte
}

// NewDocumentSource copies one complete, self-contained OpenAPI document.
func NewDocumentSource(data []byte) DocumentSource {
	return DocumentSource{data: append([]byte(nil), data...)}
}

// ExactBytes returns a copy of the exact caller bytes.
func (source DocumentSource) ExactBytes() []byte {
	return append([]byte(nil), source.data...)
}

const sourceEncoding r3.SourceEncoding = "urn:aauth:source-encoding:openapi-document-exact-v1"

type definitionCodec struct{}

func (definitionCodec) Vocabulary() r3.Vocabulary { return Vocabulary() }

func (definitionCodec) ParseDefinition(source DocumentSource) (r3.DefinitionMaterial, error) {
	tree, err := validateDocumentSource(source.data)
	if err != nil {
		return r3.DefinitionMaterial{}, err
	}
	version, ok := mappingScalar(tree.Content[0], "openapi")
	if !ok || !supportedVersion(version) {
		return r3.DefinitionMaterial{}, r3.NewDefinitionError(
			r3.DefinitionSourceKindUnsupported,
			"document must declare an OpenAPI 3.0.x or 3.1.x version",
			nil,
		)
	}

	loader := openapi3.NewLoader()
	loader.Context = context.Background()
	loader.ReadFromURIFunc = func(_ *openapi3.Loader, location *url.URL) ([]byte, error) {
		return nil, fmt.Errorf("%w: %s", errExternalReference, location)
	}
	parsed, err := loader.LoadFromData(source.data)
	if err != nil {
		if errors.Is(err, errExternalReference) {
			return r3.DefinitionMaterial{}, r3.NewDefinitionError(r3.DefinitionUnresolvedDependency, "external OpenAPI reference requires caller resolution", err)
		}
		return r3.DefinitionMaterial{}, r3.NewDefinitionError(r3.DefinitionInvalidSource, "parse OpenAPI document", err)
	}
	var operations []r3.DefinedOperation
	seen := make(map[string]struct{})
	paths := parsed.Paths.Map()
	pathNames := make([]string, 0, len(paths))
	for path := range paths {
		pathNames = append(pathNames, path)
	}
	slices.Sort(pathNames)
	for _, path := range pathNames {
		pathItem := paths[path]
		methods := pathItem.Operations()
		methodNames := make([]string, 0, len(methods))
		for method := range methods {
			methodNames = append(methodNames, method)
		}
		slices.Sort(methodNames)
		for _, method := range methodNames {
			native := methods[method]
			if native.OperationID == "" {
				continue
			}
			operation, err := NewOperation(native.OperationID)
			if err != nil {
				return r3.DefinitionMaterial{}, r3.NewDefinitionError(
					r3.DefinitionIdentityUnavailable,
					fmt.Sprintf("path %q method %s has an invalid operationId", path, method),
					err,
				)
			}
			if _, duplicate := seen[operation.OperationID()]; duplicate {
				return r3.DefinitionMaterial{}, r3.NewDefinitionError(
					r3.DefinitionIdentityAmbiguous,
					fmt.Sprintf("operationId %q is not globally unique", operation.OperationID()),
					nil,
				)
			}
			hints, hinted, err := parseOperationHints(native.Extensions)
			if err != nil {
				return r3.DefinitionMaterial{}, err
			}
			encoded, err := json.Marshal(operation)
			if err != nil {
				return r3.DefinitionMaterial{}, err
			}
			var published *r3.OperationHints
			if hinted {
				published = &hints
			}
			defined, err := r3.NewDefinedOperation(encoded, published)
			if err != nil {
				return r3.DefinitionMaterial{}, err
			}
			operations = append(operations, defined)
			seen[operation.OperationID()] = struct{}{}
		}
	}
	if len(operations) == 0 {
		return r3.DefinitionMaterial{}, r3.NewDefinitionError(
			r3.DefinitionIdentityUnavailable,
			"OpenAPI Paths contains no operation with an operationId",
			nil,
		)
	}
	if err := parsed.Validate(context.Background()); err != nil {
		return r3.DefinitionMaterial{}, r3.NewDefinitionError(r3.DefinitionInvalidSource, "validate OpenAPI document", err)
	}
	return r3.NewDefinitionMaterial(sourceEncoding, source.ExactBytes(), operations...)
}

var definitionParser = mustDefinitionParser()

func mustDefinitionParser() r3.DefinitionParser[DocumentSource] {
	parser, err := r3.NewDefinitionParser[DocumentSource](definitionCodec{})
	if err != nil {
		panic(err)
	}
	return parser
}

// DefinitionRegistration returns the OpenAPI authoritative-definition parser
// identity for an explicit r3.DefinitionRegistry.
func DefinitionRegistration() r3.DefinitionRegistration {
	return definitionParser.Registration()
}

// ParseDefinition validates a self-contained OpenAPI 3.0 or 3.1 document and
// derives its caller-invocable Paths operations. Callback and webhook
// operations are outside this initial adapter profile.
func ParseDefinition(endpoint string, source DocumentSource) (r3.AuthoritativeSnapshot, error) {
	return definitionParser.Parse(endpoint, source)
}

func parseOperationHints(extensions map[string]any) (r3.OperationHints, bool, error) {
	var mode *aauth.AccessMode
	if raw, present := extensions["x-aauth-access-mode"]; present {
		value, ok := raw.(string)
		if !ok {
			return r3.OperationHints{}, false, invalidAnnotation("x-aauth-access-mode must be a string", nil)
		}
		parsed := aauth.AccessMode(value)
		mode = &parsed
	}
	var budget *bool
	if raw, present := extensions["x-aauth-budget"]; present {
		value, ok := raw.(bool)
		if !ok {
			return r3.OperationHints{}, false, invalidAnnotation("x-aauth-budget must be a boolean", nil)
		}
		budget = &value
	}
	if mode == nil && budget == nil {
		return r3.OperationHints{}, false, nil
	}
	hints, err := r3.NewOperationHints(mode, budget)
	if err != nil {
		return r3.OperationHints{}, false, invalidAnnotation("invalid OpenAPI operation hints", err)
	}
	return hints, true, nil
}

func invalidAnnotation(reason string, cause error) error {
	return r3.NewDefinitionError(r3.DefinitionInvalidAnnotation, reason, cause)
}

var errExternalReference = errors.New("external OpenAPI reference")

func validateDocumentSource(source []byte) (*yaml.Node, error) {
	if len(bytes.TrimSpace(source)) == 0 {
		return nil, r3.NewDefinitionError(r3.DefinitionIncompleteSource, "OpenAPI document is empty", nil)
	}
	trimmed := bytes.TrimSpace(source)
	if trimmed[0] == '{' || trimmed[0] == '[' {
		if err := wirejson.ValidateSource(source); err != nil {
			return nil, r3.NewDefinitionError(r3.DefinitionInvalidSource, "invalid JSON document", err)
		}
	}
	decoder := yaml.NewDecoder(bytes.NewReader(source))
	var tree yaml.Node
	if err := decoder.Decode(&tree); err != nil {
		return nil, r3.NewDefinitionError(r3.DefinitionInvalidSource, "invalid YAML document", err)
	}
	var extra yaml.Node
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			err = errors.New("multiple YAML documents are not allowed")
		}
		return nil, r3.NewDefinitionError(r3.DefinitionInvalidSource, "invalid YAML document", err)
	}
	if len(tree.Content) != 1 || tree.Content[0].Kind != yaml.MappingNode {
		return nil, r3.NewDefinitionError(r3.DefinitionInvalidSource, "OpenAPI document root must be a mapping", nil)
	}
	if err := validateYAMLNode(tree.Content[0], make(map[*yaml.Node]bool)); err != nil {
		return nil, err
	}
	return &tree, nil
}

func validateYAMLNode(node *yaml.Node, stack map[*yaml.Node]bool) error {
	if node == nil {
		return nil
	}
	if stack[node] {
		return r3.NewDefinitionError(r3.DefinitionInvalidSource, "cyclic YAML aliases are not allowed", nil)
	}
	stack[node] = true
	defer delete(stack, node)
	if node.Kind == yaml.AliasNode {
		return validateYAMLNode(node.Alias, stack)
	}
	if node.Kind == yaml.MappingNode {
		seen := make(map[string]struct{}, len(node.Content)/2)
		for index := 0; index < len(node.Content); index += 2 {
			key, value := node.Content[index], node.Content[index+1]
			if key.Kind != yaml.ScalarNode || key.Tag != "!!str" {
				return r3.NewDefinitionError(r3.DefinitionInvalidSource, "YAML mapping keys must be strings", nil)
			}
			if _, duplicate := seen[key.Value]; duplicate {
				return r3.NewDefinitionError(r3.DefinitionInvalidSource, fmt.Sprintf("duplicate YAML member %q", key.Value), nil)
			}
			seen[key.Value] = struct{}{}
			if err := validateYAMLNode(value, stack); err != nil {
				return err
			}
		}
		return nil
	}
	for _, child := range node.Content {
		if err := validateYAMLNode(child, stack); err != nil {
			return err
		}
	}
	return nil
}

func mappingScalar(mapping *yaml.Node, name string) (string, bool) {
	for index := 0; index < len(mapping.Content); index += 2 {
		if mapping.Content[index].Value == name {
			value := mapping.Content[index+1]
			if value.Kind == yaml.ScalarNode && value.Tag == "!!str" {
				return value.Value, true
			}
			return "", false
		}
	}
	return "", false
}

func supportedVersion(version string) bool {
	parts := strings.Split(version, ".")
	if len(parts) != 3 || parts[0] != "3" || (parts[1] != "0" && parts[1] != "1") || parts[2] == "" {
		return false
	}
	for _, character := range parts[2] {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}

var _ r3.DefinitionCodec[DocumentSource] = definitionCodec{}
