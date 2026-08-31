package odata

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"

	"gitlab.com/sidecat-dev/aauth-go/r3"
)

const (
	edmxNamespace                    = "http://docs.oasis-open.org/odata/ns/edmx"
	edmNamespace                     = "http://docs.oasis-open.org/odata/ns/edm"
	sourceEncoding r3.SourceEncoding = "application/xml;profile=odata-csdl-edmx-4.0"
)

// MetadataSource owns one exact OData CSDL XML metadata document.
type MetadataSource struct{ exact []byte }

// NewMetadataSource copies an exact metadata document.
func NewMetadataSource(exact []byte) MetadataSource {
	return MetadataSource{exact: append([]byte(nil), exact...)}
}

// ExactBytes returns an owned copy of the metadata document.
func (source MetadataSource) ExactBytes() []byte {
	return append([]byte(nil), source.exact...)
}

type metadataDocument struct {
	XMLName      xml.Name         `xml:"http://docs.oasis-open.org/odata/ns/edmx Edmx"`
	Version      string           `xml:"Version,attr"`
	References   []metadataRef    `xml:"http://docs.oasis-open.org/odata/ns/edmx Reference"`
	DataServices metadataServices `xml:"http://docs.oasis-open.org/odata/ns/edmx DataServices"`
}

type metadataRef struct {
	URI string `xml:"Uri,attr"`
}

type metadataServices struct {
	Schemas []metadataSchema `xml:"http://docs.oasis-open.org/odata/ns/edm Schema"`
}

type metadataSchema struct {
	Namespace   string               `xml:"Namespace,attr"`
	Alias       string               `xml:"Alias,attr"`
	EntityTypes []metadataEntityType `xml:"http://docs.oasis-open.org/odata/ns/edm EntityType"`
	Containers  []metadataContainer  `xml:"http://docs.oasis-open.org/odata/ns/edm EntityContainer"`
	Actions     []boundOperation     `xml:"http://docs.oasis-open.org/odata/ns/edm Action"`
	Functions   []boundOperation     `xml:"http://docs.oasis-open.org/odata/ns/edm Function"`
}

type metadataEntityType struct {
	Name string `xml:"Name,attr"`
}

type metadataContainer struct {
	Name       string              `xml:"Name,attr"`
	EntitySets []metadataEntitySet `xml:"http://docs.oasis-open.org/odata/ns/edm EntitySet"`
}

type metadataEntitySet struct {
	Name       string `xml:"Name,attr"`
	EntityType string `xml:"EntityType,attr"`
}

type boundOperation struct {
	Name       string               `xml:"Name,attr"`
	IsBound    string               `xml:"IsBound,attr"`
	Parameters []operationParameter `xml:"http://docs.oasis-open.org/odata/ns/edm Parameter"`
}

type operationParameter struct {
	Name string `xml:"Name,attr"`
	Type string `xml:"Type,attr"`
}

type definitionCodec struct{}

func (definitionCodec) Vocabulary() r3.Vocabulary { return Vocabulary() }

func (definitionCodec) ParseDefinition(source MetadataSource) (r3.DefinitionMaterial, error) {
	if err := scanMetadataBoundaries(source.exact); err != nil {
		return r3.DefinitionMaterial{}, err
	}
	var document metadataDocument
	if err := xml.Unmarshal(source.exact, &document); err != nil {
		return r3.DefinitionMaterial{}, metadataError(r3.DefinitionInvalidSource, "invalid OData metadata XML", err)
	}
	if document.XMLName.Space != edmxNamespace || document.XMLName.Local != "Edmx" {
		return r3.DefinitionMaterial{}, metadataError(r3.DefinitionInvalidSource, "OData metadata root must be edmx:Edmx", nil)
	}
	if document.Version != "4.0" {
		return r3.DefinitionMaterial{}, metadataError(r3.DefinitionSourceKindUnsupported, "only OData CSDL Edmx version 4.0 is supported", nil)
	}
	if len(document.References) != 0 {
		return r3.DefinitionMaterial{}, metadataError(r3.DefinitionUnresolvedDependency, "OData metadata contains edmx:Reference", nil)
	}

	var containers []metadataContainer
	var schemas []metadataSchema
	entityTypes := make(map[string]string)
	for _, schema := range document.DataServices.Schemas {
		if schema.Namespace == "" {
			return r3.DefinitionMaterial{}, metadataError(r3.DefinitionInvalidSource, "OData Schema requires Namespace", nil)
		}
		for _, entityType := range schema.EntityTypes {
			if entityType.Name == "" {
				return r3.DefinitionMaterial{}, metadataError(r3.DefinitionInvalidSource, "OData EntityType requires Name", nil)
			}
			canonical := schema.Namespace + "." + entityType.Name
			if err := registerEntityType(entityTypes, canonical, canonical); err != nil {
				return r3.DefinitionMaterial{}, err
			}
			if schema.Alias != "" && schema.Alias != schema.Namespace {
				if err := registerEntityType(entityTypes, schema.Alias+"."+entityType.Name, canonical); err != nil {
					return r3.DefinitionMaterial{}, err
				}
			}
		}
		containers = append(containers, schema.Containers...)
		schemas = append(schemas, schema)
	}
	if len(containers) == 0 {
		return r3.DefinitionMaterial{}, metadataError(r3.DefinitionIncompleteSource, "OData metadata has no EntityContainer", nil)
	}
	if len(containers) != 1 {
		return r3.DefinitionMaterial{}, metadataError(r3.DefinitionIdentityAmbiguous, "OData metadata has multiple EntityContainers", nil)
	}
	if containers[0].Name == "" || strings.TrimSpace(containers[0].Name) != containers[0].Name {
		return r3.DefinitionMaterial{}, metadataError(r3.DefinitionInvalidSource, "OData EntityContainer requires Name", nil)
	}

	entitySets := make(map[string][]string)
	seenSetNames := make(map[string]struct{})
	var identifiers []string
	for _, entitySet := range containers[0].EntitySets {
		if entitySet.Name == "" || entitySet.EntityType == "" {
			return r3.DefinitionMaterial{}, metadataError(r3.DefinitionInvalidSource, "OData EntitySet requires Name and EntityType", nil)
		}
		if _, duplicate := seenSetNames[entitySet.Name]; duplicate {
			return r3.DefinitionMaterial{}, metadataError(r3.DefinitionIdentityAmbiguous, fmt.Sprintf("duplicate OData EntitySet %q", entitySet.Name), nil)
		}
		seenSetNames[entitySet.Name] = struct{}{}
		entityType, present := entityTypes[entitySet.EntityType]
		if !present {
			return r3.DefinitionMaterial{}, metadataError(r3.DefinitionUnresolvedDependency, fmt.Sprintf("OData EntitySet %q references unknown EntityType %q", entitySet.Name, entitySet.EntityType), nil)
		}
		entitySets[entityType] = append(entitySets[entityType], entitySet.Name)
		identifiers = append(identifiers, entitySet.Name)
	}
	if len(identifiers) == 0 {
		return r3.DefinitionMaterial{}, metadataError(r3.DefinitionIncompleteSource, "OData EntityContainer has no EntitySets", nil)
	}

	seenBound := make(map[string]struct{})
	for _, schema := range schemas {
		operations := append(append([]boundOperation(nil), schema.Actions...), schema.Functions...)
		for _, operation := range operations {
			if operation.IsBound != "true" && operation.IsBound != "1" {
				continue
			}
			if operation.Name == "" || len(operation.Parameters) == 0 ||
				operation.Parameters[0].Name == "" || operation.Parameters[0].Type == "" {
				return r3.DefinitionMaterial{}, metadataError(r3.DefinitionInvalidSource, "bound OData operation requires Name and binding parameter", nil)
			}
			bindingType, err := parseBindingType(operation.Parameters[0].Type)
			if err != nil {
				return r3.DefinitionMaterial{}, metadataError(r3.DefinitionInvalidSource, "bound OData operation has invalid binding parameter type", err)
			}
			canonicalType, present := entityTypes[bindingType]
			if !present {
				return r3.DefinitionMaterial{}, metadataError(r3.DefinitionUnresolvedDependency, fmt.Sprintf("bound OData operation %q references unknown EntityType %q", operation.Name, bindingType), nil)
			}
			for _, entitySet := range entitySets[canonicalType] {
				identifier := entitySet + "/" + operation.Name
				if _, ambiguous := seenBound[identifier]; ambiguous {
					return r3.DefinitionMaterial{}, metadataError(r3.DefinitionIdentityAmbiguous, fmt.Sprintf("OData operation %q has multiple overloads", identifier), nil)
				}
				seenBound[identifier] = struct{}{}
				identifiers = append(identifiers, identifier)
			}
		}
	}
	sort.Strings(identifiers)
	operations := make([]r3.DefinedOperation, len(identifiers))
	for index, identifier := range identifiers {
		operation, err := NewOperation(identifier)
		if err != nil {
			return r3.DefinitionMaterial{}, metadataError(r3.DefinitionInvalidSource, "invalid derived OData operation", err)
		}
		encoded, err := json.Marshal(operation)
		if err != nil {
			return r3.DefinitionMaterial{}, metadataError(r3.DefinitionInvalidSource, "encode derived OData operation", err)
		}
		operations[index], err = r3.NewDefinedOperation(encoded, nil)
		if err != nil {
			return r3.DefinitionMaterial{}, err
		}
	}
	return r3.NewDefinitionMaterial(sourceEncoding, source.ExactBytes(), operations...)
}

func registerEntityType(types map[string]string, name, canonical string) error {
	if existing, present := types[name]; present {
		if existing != canonical {
			return metadataError(r3.DefinitionIdentityAmbiguous, fmt.Sprintf("OData EntityType name %q resolves to multiple types", name), nil)
		}
		return metadataError(r3.DefinitionIdentityAmbiguous, fmt.Sprintf("duplicate OData EntityType %q", canonical), nil)
	}
	types[name] = canonical
	return nil
}

func parseBindingType(value string) (string, error) {
	if value == "" || strings.TrimSpace(value) != value {
		return "", fmt.Errorf("binding type must be nonempty and trimmed")
	}
	const collectionPrefix = "Collection("
	if strings.HasPrefix(value, collectionPrefix) {
		if !strings.HasSuffix(value, ")") {
			return "", fmt.Errorf("Collection binding type is missing its closing parenthesis")
		}
		value = strings.TrimSuffix(strings.TrimPrefix(value, collectionPrefix), ")")
		if value == "" || strings.ContainsAny(value, "()") {
			return "", fmt.Errorf("Collection binding type is malformed")
		}
		return value, nil
	}
	if strings.ContainsAny(value, "()") {
		return "", fmt.Errorf("binding type contains unmatched collection punctuation")
	}
	return value, nil
}

func scanMetadataBoundaries(source []byte) error {
	decoder := xml.NewDecoder(bytes.NewReader(source))
	depth := 0
	rootSeen := false
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return metadataError(r3.DefinitionInvalidSource, "invalid OData metadata XML", err)
		}
		switch token := token.(type) {
		case xml.StartElement:
			if err := validateDistinctMetadataAttributes(token.Attr); err != nil {
				return metadataError(r3.DefinitionInvalidSource, "OData metadata element has duplicate attributes", err)
			}
			if depth == 0 {
				if rootSeen {
					return metadataError(r3.DefinitionInvalidSource, "OData metadata contains multiple top-level elements", nil)
				}
				rootSeen = true
			}
			depth++
			if token.Name.Space == edmxNamespace && token.Name.Local == "Reference" {
				return metadataError(r3.DefinitionUnresolvedDependency, "OData metadata contains edmx:Reference", nil)
			}
			if token.Name.Space == edmNamespace && token.Name.Local == "Annotation" {
				for _, attribute := range token.Attr {
					if attribute.Name.Local == "Term" && strings.HasPrefix(attribute.Value, "AAuth.") {
						return metadataError(
							r3.DefinitionSourceKindUnsupported,
							"the R3 draft does not define the OData AAuth term namespace and overload targeting",
							nil,
						)
					}
				}
			}
		case xml.EndElement:
			depth--
			if depth < 0 {
				return metadataError(r3.DefinitionInvalidSource, "OData metadata XML is unbalanced", nil)
			}
		case xml.CharData:
			if depth == 0 && len(bytes.TrimSpace(token)) != 0 {
				return metadataError(r3.DefinitionInvalidSource, "OData metadata contains text outside its root element", nil)
			}
		}
	}
}

func validateDistinctMetadataAttributes(attributes []xml.Attr) error {
	seen := make(map[xml.Name]struct{}, len(attributes))
	for _, attribute := range attributes {
		if _, duplicate := seen[attribute.Name]; duplicate {
			return fmt.Errorf("duplicate attribute %s", attribute.Name.Local)
		}
		seen[attribute.Name] = struct{}{}
	}
	return nil
}

func metadataError(kind r3.DefinitionErrorKind, reason string, cause error) error {
	return r3.NewDefinitionError(kind, reason, cause)
}

var (
	definitionParserOnce sync.Once
	definitionParser     r3.DefinitionParser[MetadataSource]
)

func definitions() r3.DefinitionParser[MetadataSource] {
	definitionParserOnce.Do(func() {
		parser, err := r3.NewDefinitionParser[MetadataSource](definitionCodec{})
		if err != nil {
			panic(err)
		}
		definitionParser = parser
	})
	return definitionParser
}

// ParseDefinition derives the R3-identifiable subset of one exact OData
// structural metadata document.
func ParseDefinition(endpoint string, source MetadataSource) (r3.AuthoritativeSnapshot, error) {
	return definitions().Parse(endpoint, source)
}

// DefinitionRegistration returns the stable OData definition registration.
func DefinitionRegistration() r3.DefinitionRegistration {
	return definitions().Registration()
}
