package wsdl

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

const wsdlNamespace = "http://schemas.xmlsoap.org/wsdl/"

const sourceEncoding r3.SourceEncoding = "application/wsdl+xml"

// XMLDocumentSource owns the exact caller-supplied, self-contained WSDL 1.1
// document. Fetching and import resolution remain caller responsibilities.
type XMLDocumentSource struct{ exact []byte }

// NewXMLDocumentSource copies one exact WSDL document.
func NewXMLDocumentSource(exact []byte) XMLDocumentSource {
	return XMLDocumentSource{exact: append([]byte(nil), exact...)}
}

// ExactBytes returns an owned copy of the document.
func (source XMLDocumentSource) ExactBytes() []byte {
	return append([]byte(nil), source.exact...)
}

type qualifiedName struct {
	namespace string
	local     string
}

func (name qualifiedName) String() string { return "{" + name.namespace + "}" + name.local }

type portTypeDefinition struct {
	name       qualifiedName
	operations []string
	byName     map[string]struct{}
}

type bindingDefinition struct {
	name       qualifiedName
	portType   qualifiedName
	operations []string
	byName     map[string]struct{}
}

type serviceDefinition struct {
	name     string
	bindings []qualifiedName
}

type definitionCodec struct{}

func (definitionCodec) Vocabulary() r3.Vocabulary { return Vocabulary() }

func (definitionCodec) ParseDefinition(source XMLDocumentSource) (r3.DefinitionMaterial, error) {
	if len(bytes.TrimSpace(source.exact)) == 0 {
		return r3.DefinitionMaterial{}, r3.NewDefinitionError(r3.DefinitionIncompleteSource, "WSDL document is empty", nil)
	}
	portTypes, bindings, services, err := parseWSDLDocument(source.exact)
	if err != nil {
		return r3.DefinitionMaterial{}, err
	}
	typed, err := deriveBoundOperations(portTypes, bindings, services)
	if err != nil {
		return r3.DefinitionMaterial{}, err
	}
	operations := make([]r3.DefinedOperation, len(typed))
	for index, operation := range typed {
		encoded, err := json.Marshal(operation)
		if err != nil {
			return r3.DefinitionMaterial{}, err
		}
		operations[index], err = r3.NewDefinedOperation(encoded, nil)
		if err != nil {
			return r3.DefinitionMaterial{}, err
		}
	}
	return r3.NewDefinitionMaterial(sourceEncoding, source.ExactBytes(), operations...)
}

var (
	definitionParserOnce sync.Once
	definitionParser     r3.DefinitionParser[XMLDocumentSource]
)

func definitions() r3.DefinitionParser[XMLDocumentSource] {
	definitionParserOnce.Do(func() {
		parser, err := r3.NewDefinitionParser[XMLDocumentSource](definitionCodec{})
		if err != nil {
			panic(err)
		}
		definitionParser = parser
	})
	return definitionParser
}

// DefinitionRegistration returns the stable WSDL definition registration.
func DefinitionRegistration() r3.DefinitionRegistration {
	return definitions().Registration()
}

// ParseDefinition parses the package's self-contained WSDL 1.1 subset and
// derives the operations that services expose through resolved bindings.
func ParseDefinition(endpoint string, source XMLDocumentSource) (r3.AuthoritativeSnapshot, error) {
	return definitions().Parse(endpoint, source)
}

type elementFrame struct {
	name       xml.Name
	namespaces map[string]string
}

func parseWSDLDocument(source []byte) (
	map[qualifiedName]*portTypeDefinition,
	map[qualifiedName]*bindingDefinition,
	[]*serviceDefinition,
	error,
) {
	decoder := xml.NewDecoder(bytes.NewReader(source))
	portTypes := make(map[qualifiedName]*portTypeDefinition)
	bindings := make(map[qualifiedName]*bindingDefinition)
	messages := make(map[qualifiedName]struct{})
	var messageReferences []qualifiedName
	var services []*serviceDefinition
	var frames []elementFrame
	var targetNamespace string
	var currentPortType *portTypeDefinition
	var currentPortTypeOperation string
	var currentPortTypeOperationHasMessage bool
	var currentBinding *bindingDefinition
	var currentService *serviceDefinition
	var rootSeen bool

	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, nil, nil, invalidSource("invalid WSDL XML", err)
		}
		switch token := token.(type) {
		case xml.Directive:
			return nil, nil, nil, invalidSource("WSDL directives are not supported", nil)
		case xml.StartElement:
			if len(frames) == 0 && rootSeen {
				return nil, nil, nil, invalidSource("WSDL document contains multiple top-level elements", nil)
			}
			if err := validateDistinctAttributes(token.Attr); err != nil {
				return nil, nil, nil, invalidSource("WSDL element has duplicate attributes", err)
			}
			namespaces := inheritedNamespaces(frames)
			applyNamespaceDeclarations(namespaces, token.Attr)
			parent := xml.Name{}
			if len(frames) > 0 {
				parent = frames[len(frames)-1].name
			}
			frames = append(frames, elementFrame{name: token.Name, namespaces: namespaces})

			if !rootSeen {
				rootSeen = true
				if token.Name.Space != wsdlNamespace || token.Name.Local != "definitions" {
					return nil, nil, nil, r3.NewDefinitionError(
						r3.DefinitionSourceKindUnsupported,
						"document root must be WSDL 1.1 definitions",
						nil,
					)
				}
				targetNamespace = attribute(token.Attr, "targetNamespace")
				if targetNamespace == "" {
					return nil, nil, nil, r3.NewDefinitionError(
						r3.DefinitionIncompleteSource,
						"WSDL definitions requires targetNamespace",
						nil,
					)
				}
			}

			if token.Name.Local == "import" || token.Name.Local == "include" {
				return nil, nil, nil, r3.NewDefinitionError(
					r3.DefinitionUnresolvedDependency,
					fmt.Sprintf("WSDL %s requires caller resolution", token.Name.Local),
					nil,
				)
			}
			if token.Name.Space != wsdlNamespace {
				continue
			}
			if !validWSDLPlacement(token.Name.Local, parent) {
				return nil, nil, nil, invalidSource(
					fmt.Sprintf("WSDL %s is not valid below %s", token.Name.Local, parent.Local),
					nil,
				)
			}

			switch {
			case parent.Space == wsdlNamespace && parent.Local == "definitions" && token.Name.Local == "message":
				name, err := declaredName(token.Attr, targetNamespace, "message")
				if err != nil {
					return nil, nil, nil, err
				}
				if _, duplicate := messages[name]; duplicate {
					return nil, nil, nil, ambiguous("duplicate WSDL message " + name.String())
				}
				messages[name] = struct{}{}
			case parent.Space == wsdlNamespace && parent.Local == "definitions" && token.Name.Local == "portType":
				name, err := declaredName(token.Attr, targetNamespace, "portType")
				if err != nil {
					return nil, nil, nil, err
				}
				if _, duplicate := portTypes[name]; duplicate {
					return nil, nil, nil, ambiguous("duplicate WSDL portType " + name.String())
				}
				currentPortType = &portTypeDefinition{name: name, byName: make(map[string]struct{})}
				portTypes[name] = currentPortType
			case parent.Space == wsdlNamespace && parent.Local == "portType" && token.Name.Local == "operation" && currentPortType != nil:
				name, err := requiredAttribute(token.Attr, "name", "portType operation")
				if err != nil {
					return nil, nil, nil, err
				}
				if _, duplicate := currentPortType.byName[name]; duplicate {
					return nil, nil, nil, ambiguous(fmt.Sprintf("portType %s overloads operation %q", currentPortType.name, name))
				}
				currentPortType.byName[name] = struct{}{}
				currentPortType.operations = append(currentPortType.operations, name)
				currentPortTypeOperation = name
				currentPortTypeOperationHasMessage = false
			case parent.Space == wsdlNamespace && parent.Local == "operation" &&
				currentPortTypeOperation != "" && (token.Name.Local == "input" || token.Name.Local == "output"):
				reference, err := requiredQName(token.Attr, "message", namespaces, "portType operation "+token.Name.Local)
				if err != nil {
					return nil, nil, nil, err
				}
				messageReferences = append(messageReferences, reference)
				currentPortTypeOperationHasMessage = true
			case parent.Space == wsdlNamespace && parent.Local == "definitions" && token.Name.Local == "binding":
				name, err := declaredName(token.Attr, targetNamespace, "binding")
				if err != nil {
					return nil, nil, nil, err
				}
				if _, duplicate := bindings[name]; duplicate {
					return nil, nil, nil, ambiguous("duplicate WSDL binding " + name.String())
				}
				reference, err := requiredQName(token.Attr, "type", namespaces, "binding type")
				if err != nil {
					return nil, nil, nil, err
				}
				currentBinding = &bindingDefinition{name: name, portType: reference, byName: make(map[string]struct{})}
				bindings[name] = currentBinding
			case parent.Space == wsdlNamespace && parent.Local == "binding" && token.Name.Local == "operation" && currentBinding != nil:
				name, err := requiredAttribute(token.Attr, "name", "binding operation")
				if err != nil {
					return nil, nil, nil, err
				}
				if _, duplicate := currentBinding.byName[name]; duplicate {
					return nil, nil, nil, ambiguous(fmt.Sprintf("binding %s repeats operation %q", currentBinding.name, name))
				}
				currentBinding.byName[name] = struct{}{}
				currentBinding.operations = append(currentBinding.operations, name)
			case parent.Space == wsdlNamespace && parent.Local == "definitions" && token.Name.Local == "service":
				name, err := requiredAttribute(token.Attr, "name", "service")
				if err != nil {
					return nil, nil, nil, err
				}
				for _, existing := range services {
					if existing.name == name {
						return nil, nil, nil, ambiguous(fmt.Sprintf("duplicate WSDL service %q", name))
					}
				}
				currentService = &serviceDefinition{name: name}
				services = append(services, currentService)
			case parent.Space == wsdlNamespace && parent.Local == "service" && token.Name.Local == "port" && currentService != nil:
				reference, err := requiredQName(token.Attr, "binding", namespaces, "service port binding")
				if err != nil {
					return nil, nil, nil, err
				}
				currentService.bindings = append(currentService.bindings, reference)
			}
		case xml.EndElement:
			if token.Name.Space == wsdlNamespace {
				switch token.Name.Local {
				case "operation":
					if currentPortTypeOperation != "" {
						if !currentPortTypeOperationHasMessage {
							return nil, nil, nil, r3.NewDefinitionError(
								r3.DefinitionIncompleteSource,
								fmt.Sprintf("WSDL portType operation %q requires input or output message", currentPortTypeOperation),
								nil,
							)
						}
						currentPortTypeOperation = ""
						currentPortTypeOperationHasMessage = false
					}
				case "portType":
					currentPortType = nil
				case "binding":
					currentBinding = nil
				case "service":
					currentService = nil
				}
			}
			if len(frames) == 0 {
				return nil, nil, nil, invalidSource("unbalanced WSDL XML", nil)
			}
			frames = frames[:len(frames)-1]
		case xml.CharData:
			if len(frames) == 0 && len(bytes.TrimSpace(token)) != 0 {
				return nil, nil, nil, invalidSource("WSDL document contains text outside its root element", nil)
			}
		}
	}
	if !rootSeen {
		return nil, nil, nil, r3.NewDefinitionError(r3.DefinitionIncompleteSource, "WSDL document is empty", nil)
	}
	for _, reference := range messageReferences {
		if _, present := messages[reference]; !present {
			return nil, nil, nil, unresolved("portType operation references unknown message " + reference.String())
		}
	}
	return portTypes, bindings, services, nil
}

func validWSDLPlacement(local string, parent xml.Name) bool {
	if local == "documentation" {
		return true
	}
	if local == "definitions" {
		return parent == (xml.Name{})
	}
	if parent.Space != wsdlNamespace {
		return false
	}
	switch parent.Local {
	case "definitions":
		return local == "types" || local == "import" || local == "include" ||
			local == "message" || local == "portType" || local == "binding" || local == "service"
	case "message":
		return local == "part"
	case "portType", "binding":
		return local == "operation"
	case "operation":
		return local == "input" || local == "output" || local == "fault"
	case "service":
		return local == "port"
	default:
		return false
	}
}

func validateDistinctAttributes(attributes []xml.Attr) error {
	seen := make(map[xml.Name]struct{}, len(attributes))
	for _, attribute := range attributes {
		if _, duplicate := seen[attribute.Name]; duplicate {
			return fmt.Errorf("duplicate attribute %s", attribute.Name.Local)
		}
		seen[attribute.Name] = struct{}{}
	}
	return nil
}

type boundObservation struct {
	service string
	name    string
	meaning string
}

func deriveBoundOperations(
	portTypes map[qualifiedName]*portTypeDefinition,
	bindings map[qualifiedName]*bindingDefinition,
	services []*serviceDefinition,
) ([]Operation, error) {
	bindingNames := make([]qualifiedName, 0, len(bindings))
	for name := range bindings {
		bindingNames = append(bindingNames, name)
	}
	sort.Slice(bindingNames, func(left, right int) bool {
		if bindingNames[left].namespace != bindingNames[right].namespace {
			return bindingNames[left].namespace < bindingNames[right].namespace
		}
		return bindingNames[left].local < bindingNames[right].local
	})
	for _, name := range bindingNames {
		binding := bindings[name]
		portType, ok := portTypes[binding.portType]
		if !ok {
			return nil, unresolved(fmt.Sprintf("binding %s references unknown portType %s", binding.name, binding.portType))
		}
		for _, operation := range binding.operations {
			if _, ok := portType.byName[operation]; !ok {
				return nil, unresolved(fmt.Sprintf("binding %s operation %q is absent from portType %s", binding.name, operation, portType.name))
			}
		}
	}

	var observations []boundObservation
	for _, service := range services {
		byOperation := make(map[string]string)
		for _, bindingName := range service.bindings {
			binding, ok := bindings[bindingName]
			if !ok {
				return nil, unresolved(fmt.Sprintf("service %q references unknown binding %s", service.name, bindingName))
			}
			for _, operation := range binding.operations {
				meaning := binding.name.String() + "/" + operation
				if previous, exists := byOperation[operation]; exists {
					if previous != meaning {
						return nil, ambiguous(fmt.Sprintf("service %q maps operation %q to multiple bindings", service.name, operation))
					}
					continue
				}
				byOperation[operation] = meaning
				observations = append(observations, boundObservation{service: service.name, name: operation, meaning: meaning})
			}
		}
	}

	byName := make(map[string][]boundObservation)
	var names []string
	for _, observation := range observations {
		if _, seen := byName[observation.name]; !seen {
			names = append(names, observation.name)
		}
		byName[observation.name] = append(byName[observation.name], observation)
	}
	var result []Operation
	for _, name := range names {
		group := byName[name]
		meanings := make(map[string]struct{})
		for _, observation := range group {
			meanings[observation.meaning] = struct{}{}
		}
		if len(meanings) == 1 {
			operation, err := NewOperation(name)
			if err != nil {
				return nil, r3.NewDefinitionError(r3.DefinitionIdentityUnavailable, "invalid WSDL operation name", err)
			}
			result = append(result, operation)
			continue
		}
		for _, observation := range group {
			operation, err := NewServiceOperation(name, observation.service)
			if err != nil {
				return nil, r3.NewDefinitionError(r3.DefinitionIdentityUnavailable, "invalid WSDL service-qualified operation", err)
			}
			result = append(result, operation)
		}
	}
	return result, nil
}

func inheritedNamespaces(frames []elementFrame) map[string]string {
	if len(frames) == 0 {
		return make(map[string]string)
	}
	parent := frames[len(frames)-1].namespaces
	result := make(map[string]string, len(parent))
	for prefix, namespace := range parent {
		result[prefix] = namespace
	}
	return result
}

func applyNamespaceDeclarations(namespaces map[string]string, attributes []xml.Attr) {
	for _, attribute := range attributes {
		switch {
		case attribute.Name.Space == "xmlns":
			namespaces[attribute.Name.Local] = attribute.Value
		case attribute.Name.Space == "" && attribute.Name.Local == "xmlns":
			namespaces[""] = attribute.Value
		}
	}
}

func declaredName(attributes []xml.Attr, namespace, kind string) (qualifiedName, error) {
	name, err := requiredAttribute(attributes, "name", kind)
	if err != nil {
		return qualifiedName{}, err
	}
	return qualifiedName{namespace: namespace, local: name}, nil
}

func requiredQName(attributes []xml.Attr, name string, namespaces map[string]string, context string) (qualifiedName, error) {
	value, err := requiredAttribute(attributes, name, context)
	if err != nil {
		return qualifiedName{}, err
	}
	parts := strings.Split(value, ":")
	if len(parts) > 2 || parts[0] == "" || (len(parts) == 2 && parts[1] == "") {
		return qualifiedName{}, unresolved(fmt.Sprintf("%s has invalid QName %q", context, value))
	}
	prefix, local := "", parts[0]
	if len(parts) == 2 {
		prefix, local = parts[0], parts[1]
	}
	namespace, ok := namespaces[prefix]
	if !ok || namespace == "" {
		return qualifiedName{}, unresolved(fmt.Sprintf("%s QName %q has no namespace mapping", context, value))
	}
	return qualifiedName{namespace: namespace, local: local}, nil
}

func requiredAttribute(attributes []xml.Attr, name, context string) (string, error) {
	value := attribute(attributes, name)
	if value == "" || strings.TrimSpace(value) != value {
		return "", r3.NewDefinitionError(
			r3.DefinitionIncompleteSource,
			fmt.Sprintf("WSDL %s requires a nonempty %s", context, name),
			nil,
		)
	}
	return value, nil
}

func attribute(attributes []xml.Attr, name string) string {
	for _, attribute := range attributes {
		if attribute.Name.Space == "" && attribute.Name.Local == name {
			return attribute.Value
		}
	}
	return ""
}

func invalidSource(reason string, cause error) error {
	return r3.NewDefinitionError(r3.DefinitionInvalidSource, reason, cause)
}

func unresolved(reason string) error {
	return r3.NewDefinitionError(r3.DefinitionUnresolvedDependency, reason, nil)
}

func ambiguous(reason string) error {
	return r3.NewDefinitionError(r3.DefinitionIdentityAmbiguous, reason, nil)
}
