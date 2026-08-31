package integration_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"unicode/utf8"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/r3"
	"gitlab.com/sidecat-dev/aauth-go/r3/vocab/mcp"
	"gitlab.com/sidecat-dev/aauth-go/r3/vocab/openapi"
	"gitlab.com/sidecat-dev/aauth-go/r3/vocabtest"
	"gitlab.com/sidecat-dev/aauth-go/resource"
)

type integrationR3Vocabulary struct {
	name              string
	uri               r3.VocabularyURI
	discoveryEndpoint func(string) string
	registration      r3.Vocabulary
	definition        func(*testing.T, string, []string) r3.AuthoritativeSnapshot
	newOperation      func(*testing.T, string) r3.Operation
	operationID       func(*testing.T, r3.Operation) string
}

func integrationR3Vocabularies() []integrationR3Vocabulary {
	return []integrationR3Vocabulary{
		{
			name: "MCP", uri: mcp.URI, discoveryEndpoint: integrationHTTPSDiscoveryEndpoint("/mcp"), registration: mcp.Vocabulary(),
			definition: integrationMCPDefinition,
			newOperation: func(t *testing.T, name string) r3.Operation {
				t.Helper()
				typed, err := mcp.NewOperation(name)
				if err != nil {
					t.Fatal(err)
				}
				operation, err := typed.ToR3()
				if err != nil {
					t.Fatal(err)
				}
				return operation
			},
			operationID: func(t *testing.T, operation r3.Operation) string {
				t.Helper()
				typed, err := mcp.FromR3(operation)
				if err != nil {
					t.Fatal(err)
				}
				return typed.Tool()
			},
		},
		{
			name: "OpenAPI", uri: openapi.URI, discoveryEndpoint: integrationHTTPSDiscoveryEndpoint("/openapi"), registration: openapi.Vocabulary(),
			definition: integrationOpenAPIDefinition,
			newOperation: func(t *testing.T, name string) r3.Operation {
				t.Helper()
				typed, err := openapi.NewOperation(name)
				if err != nil {
					t.Fatal(err)
				}
				operation, err := typed.ToR3()
				if err != nil {
					t.Fatal(err)
				}
				return operation
			},
			operationID: func(t *testing.T, operation r3.Operation) string {
				t.Helper()
				typed, err := openapi.FromR3(operation)
				if err != nil {
					t.Fatal(err)
				}
				return typed.OperationID()
			},
		},
		{
			name: "ThirdParty", uri: integrationThirdPartyURI,
			discoveryEndpoint: func(string) string { return integrationThirdPartyDiscoveryEndpoint },
			registration:      integrationThirdPartyVocabulary,
			definition:        integrationThirdPartyDefinition,
			newOperation: func(t *testing.T, name string) r3.Operation {
				t.Helper()
				operation, err := newIntegrationThirdPartyOperation(name)
				if err != nil {
					t.Fatal(err)
				}
				encoded, err := json.Marshal(operation)
				if err != nil {
					t.Fatal(err)
				}
				neutral, err := r3.NewOperation(integrationThirdPartyVocabulary, encoded)
				if err != nil {
					t.Fatal(err)
				}
				return neutral
			},
			operationID: func(t *testing.T, operation r3.Operation) string {
				t.Helper()
				if operation.Vocabulary() != integrationThirdPartyURI {
					t.Fatalf("third-party operation vocabulary = %q", operation.Vocabulary())
				}
				local, err := r3.NewOperation(integrationThirdPartyVocabulary, operation.JSON())
				if err != nil {
					t.Fatal(err)
				}
				equal, err := local.Equal(operation)
				if err != nil || !equal {
					t.Fatalf("third-party operation registration = %t, %v", equal, err)
				}
				typed, err := parseIntegrationThirdPartyOperation(operation.JSON())
				if err != nil {
					t.Fatal(err)
				}
				return typed.service + "." + typed.command
			},
		},
	}
}

func integrationHTTPSDiscoveryEndpoint(path string) func(string) string {
	return func(resourceID string) string { return resourceID + path }
}

func newIntegrationR3Registry(t *testing.T) r3.Registry {
	t.Helper()
	registry, err := r3.NewRegistry(mcp.Vocabulary(), openapi.Vocabulary(), integrationThirdPartyVocabulary)
	if err != nil {
		t.Fatal(err)
	}
	return registry
}

func newIntegrationR3DefinitionRegistry(t *testing.T) r3.DefinitionRegistry {
	t.Helper()
	registry, err := r3.NewDefinitionRegistry(
		mcp.DefinitionRegistration(),
		openapi.DefinitionRegistration(),
		integrationThirdPartyDefinitions().Registration(),
	)
	if err != nil {
		t.Fatal(err)
	}
	return registry
}

func integrationR3ResourceVocabularies(
	t *testing.T,
	resourceID string,
	operationNames []string,
	account string,
	display *r3.Display,
) []resource.R3VocabularyConfig {
	t.Helper()
	vocabularies := integrationR3Vocabularies()
	result := make([]resource.R3VocabularyConfig, 0, len(vocabularies))
	for _, vocabulary := range vocabularies {
		expected := vocabulary.operationSet(t, operationNames...)
		definition := vocabulary.definition(t, vocabulary.discoveryEndpoint(resourceID), operationNames)
		result = append(result, resource.R3VocabularyConfig{
			Definition: definition,
			DisplayForOperations: func(_ context.Context, operations r3.OperationSet, gotAccount *string) (*r3.Display, error) {
				if !vocabulary.operationSetsEqual(t, operations, expected) || gotAccount == nil || *gotAccount != account {
					return nil, errors.New("unexpected R3 display input")
				}
				return display, nil
			},
		})
	}
	return result
}

func integrationMCPDefinition(t *testing.T, endpoint string, names []string) r3.AuthoritativeSnapshot {
	t.Helper()
	tools := make([]map[string]any, len(names))
	for index, name := range names {
		tools[index] = map[string]any{"name": name, "inputSchema": map[string]any{"type": "object"}}
	}
	body, err := json.Marshal(map[string]any{"tools": tools})
	if err != nil {
		t.Fatal(err)
	}
	source := mcp.NewToolsListSnapshot(mcp.NewInitialToolsListPage(body))
	snapshot, err := mcp.ParseDefinition(endpoint, source)
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func integrationOpenAPIDefinition(t *testing.T, endpoint string, names []string) r3.AuthoritativeSnapshot {
	t.Helper()
	paths := make(map[string]any, len(names))
	for index, name := range names {
		paths[fmt.Sprintf("/operation/%d", index)] = map[string]any{
			"post": map[string]any{
				"operationId": name,
				"responses":   map[string]any{"204": map[string]any{"description": "ok"}},
			},
		}
	}
	body, err := json.Marshal(map[string]any{
		"openapi": "3.1.0",
		"info":    map[string]string{"title": "integration", "version": "1"},
		"paths":   paths,
	})
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := openapi.ParseDefinition(endpoint, openapi.NewDocumentSource(body))
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func requireIntegrationR3ResourceMetadata(t *testing.T, handler http.Handler, resourceID string) {
	t.Helper()
	request := httptest.NewRequest(
		http.MethodGet,
		resourceID+"/.well-known/"+aauth.ResourceDiscoveryDocument,
		nil,
	)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("Resource metadata status = %d, body = %s", response.Code, response.Body.String())
	}
	var metadata struct {
		R3Vocabularies map[string]string `json:"r3_vocabularies"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &metadata); err != nil {
		t.Fatal(err)
	}
	want := make(map[string]string)
	for _, vocabulary := range integrationR3Vocabularies() {
		want[string(vocabulary.uri)] = vocabulary.discoveryEndpoint(resourceID)
	}
	if !maps.Equal(metadata.R3Vocabularies, want) {
		t.Fatalf("r3_vocabularies = %#v, want %#v", metadata.R3Vocabularies, want)
	}
}

const (
	integrationThirdPartyURI               r3.VocabularyURI = "tag:integration.example,2026:r3:command"
	integrationThirdPartyDiscoveryEndpoint                  = "custom+unix:///run/resource.sock?definition=current"
)

type integrationThirdPartyOperation struct {
	service string
	command string
}

func newIntegrationThirdPartyOperation(name string) (integrationThirdPartyOperation, error) {
	service, command, found := strings.Cut(name, ".")
	operation := integrationThirdPartyOperation{service: service, command: command}
	if !found || strings.Contains(command, ".") {
		return integrationThirdPartyOperation{}, fmt.Errorf("third-party operation %q must contain one service separator", name)
	}
	if err := operation.validate(); err != nil {
		return integrationThirdPartyOperation{}, err
	}
	return operation, nil
}

func (operation integrationThirdPartyOperation) validate() error {
	if err := validateIntegrationThirdPartyIdentifier("service", operation.service); err != nil {
		return err
	}
	return validateIntegrationThirdPartyIdentifier("command", operation.command)
}

func validateIntegrationThirdPartyIdentifier(field, value string) error {
	if !utf8.ValidString(value) || value == "" {
		return fmt.Errorf("third-party %s must be non-empty UTF-8", field)
	}
	for _, character := range value {
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' && character != '_' {
			return fmt.Errorf("third-party %s %q contains an invalid character", field, value)
		}
	}
	return nil
}

func (operation integrationThirdPartyOperation) MarshalJSON() ([]byte, error) {
	if err := operation.validate(); err != nil {
		return nil, err
	}
	return json.Marshal(struct {
		Service  string `json:"service"`
		Command  string `json:"command"`
		Revision int    `json:"revision"`
	}{Service: operation.service, Command: operation.command, Revision: 1})
}

func parseIntegrationThirdPartyOperation(source []byte) (integrationThirdPartyOperation, error) {
	var service, command string
	var revision int
	seen, err := decodeIntegrationThirdPartyObject(source, map[string]func(json.RawMessage) error{
		"service":  func(raw json.RawMessage) error { return json.Unmarshal(raw, &service) },
		"command":  func(raw json.RawMessage) error { return json.Unmarshal(raw, &command) },
		"revision": func(raw json.RawMessage) error { return json.Unmarshal(raw, &revision) },
	})
	if err != nil {
		return integrationThirdPartyOperation{}, err
	}
	for _, required := range []string{"service", "command", "revision"} {
		if _, present := seen[required]; !present {
			return integrationThirdPartyOperation{}, fmt.Errorf("third-party operation is missing %s", required)
		}
	}
	if revision != 1 {
		return integrationThirdPartyOperation{}, fmt.Errorf("third-party operation revision = %d, want 1", revision)
	}
	operation := integrationThirdPartyOperation{service: service, command: command}
	if err := operation.validate(); err != nil {
		return integrationThirdPartyOperation{}, err
	}
	return operation, nil
}

func decodeIntegrationThirdPartyObject(
	source []byte,
	fields map[string]func(json.RawMessage) error,
) (map[string]struct{}, error) {
	decoder := json.NewDecoder(bytes.NewReader(source))
	opening, err := decoder.Token()
	if err != nil || opening != json.Delim('{') {
		return nil, errors.New("third-party operation must be an object")
	}
	seen := make(map[string]struct{}, len(fields))
	for decoder.More() {
		nameToken, err := decoder.Token()
		if err != nil {
			return nil, err
		}
		name, ok := nameToken.(string)
		if !ok {
			return nil, errors.New("third-party operation member name must be a string")
		}
		if _, duplicate := seen[name]; duplicate {
			return nil, fmt.Errorf("third-party operation repeats %q", name)
		}
		decode, known := fields[name]
		if !known {
			return nil, fmt.Errorf("third-party operation contains unknown member %q", name)
		}
		var raw json.RawMessage
		if err := decoder.Decode(&raw); err != nil {
			return nil, err
		}
		if err := decode(raw); err != nil {
			return nil, fmt.Errorf("third-party operation member %q: %w", name, err)
		}
		seen[name] = struct{}{}
	}
	closing, err := decoder.Token()
	if err != nil || closing != json.Delim('}') {
		return nil, errors.New("third-party operation is not a complete object")
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("third-party operation has trailing data")
	}
	return seen, nil
}

type integrationThirdPartySet struct {
	operations []integrationThirdPartyOperation
}

type integrationThirdPartyCodec struct{}

func (integrationThirdPartyCodec) URI() r3.VocabularyURI { return integrationThirdPartyURI }

func (integrationThirdPartyCodec) AnnotationEncoding() r3.AnnotationEncoding {
	return r3.AnnotationUnavailable
}

func (integrationThirdPartyCodec) ValidateDiscoveryEndpoint(endpoint string) error {
	if endpoint != integrationThirdPartyDiscoveryEndpoint {
		return fmt.Errorf("third-party discovery endpoint %q is not the registered local endpoint", endpoint)
	}
	return nil
}

func (integrationThirdPartyCodec) ParseSet(raw []json.RawMessage) (integrationThirdPartySet, error) {
	operations := make([]integrationThirdPartyOperation, len(raw))
	seen := make(map[string]struct{}, len(raw))
	for index, encoded := range raw {
		operation, err := parseIntegrationThirdPartyOperation(encoded)
		if err != nil {
			return integrationThirdPartySet{}, fmt.Errorf("third-party operation %d: %w", index, err)
		}
		key := operation.service + "\x00" + operation.command
		if _, duplicate := seen[key]; duplicate {
			return integrationThirdPartySet{}, fmt.Errorf("third-party operation %d duplicates %s.%s", index, operation.service, operation.command)
		}
		seen[key] = struct{}{}
		operations[index] = operation
	}
	return integrationThirdPartySet{operations: operations}, nil
}

func (integrationThirdPartyCodec) MarshalSet(set integrationThirdPartySet) ([]json.RawMessage, error) {
	raw := make([]json.RawMessage, len(set.operations))
	seen := make(map[string]struct{}, len(set.operations))
	for index, operation := range set.operations {
		if err := operation.validate(); err != nil {
			return nil, fmt.Errorf("third-party operation %d: %w", index, err)
		}
		key := operation.service + "\x00" + operation.command
		if _, duplicate := seen[key]; duplicate {
			return nil, fmt.Errorf("third-party operation %d duplicates %s.%s", index, operation.service, operation.command)
		}
		seen[key] = struct{}{}
		encoded, err := json.Marshal(operation)
		if err != nil {
			return nil, err
		}
		raw[index] = encoded
	}
	return raw, nil
}

func (integrationThirdPartyCodec) Union(sets ...integrationThirdPartySet) (integrationThirdPartySet, error) {
	union := integrationThirdPartySet{}
	seen := make(map[string]struct{})
	for _, set := range sets {
		for _, operation := range set.operations {
			if err := operation.validate(); err != nil {
				return integrationThirdPartySet{}, err
			}
			key := operation.service + "\x00" + operation.command
			if _, present := seen[key]; present {
				continue
			}
			seen[key] = struct{}{}
			union.operations = append(union.operations, operation)
		}
	}
	return union, nil
}

func (integrationThirdPartyCodec) Equal(left, right integrationThirdPartySet) bool {
	return len(left.operations) == len(right.operations) && integrationThirdPartySubset(left, right)
}

func (integrationThirdPartyCodec) Subset(left, right integrationThirdPartySet) bool {
	return integrationThirdPartySubset(left, right)
}

func integrationThirdPartySubset(left, right integrationThirdPartySet) bool {
	for _, operation := range left.operations {
		if !slices.Contains(right.operations, operation) {
			return false
		}
	}
	return true
}

func (integrationThirdPartyCodec) Disjoint(left, right integrationThirdPartySet) bool {
	for _, operation := range left.operations {
		if slices.Contains(right.operations, operation) {
			return false
		}
	}
	return true
}

var integrationThirdPartyVocabulary = func() r3.Vocabulary {
	vocabulary, err := r3.NewVocabulary[integrationThirdPartySet](integrationThirdPartyCodec{})
	if err != nil {
		panic(err)
	}
	return vocabulary
}()

type integrationThirdPartyDefinitionSource struct{ exact []byte }

const integrationThirdPartySourceEncoding r3.SourceEncoding = "tag:integration.example,2026:r3:definition-source-v1"

type integrationThirdPartyDefinitionCodec struct{}

func (integrationThirdPartyDefinitionCodec) Vocabulary() r3.Vocabulary {
	return integrationThirdPartyVocabulary
}

func (integrationThirdPartyDefinitionCodec) ParseDefinition(source integrationThirdPartyDefinitionSource) (r3.DefinitionMaterial, error) {
	var document struct {
		Operations []string `json:"operations"`
	}
	if err := json.Unmarshal(source.exact, &document); err != nil {
		return r3.DefinitionMaterial{}, r3.NewDefinitionError(r3.DefinitionInvalidSource, "invalid third-party definition", err)
	}
	if len(document.Operations) == 0 {
		return r3.DefinitionMaterial{}, r3.NewDefinitionError(r3.DefinitionIncompleteSource, "third-party definition has no operations", nil)
	}
	operations := make([]r3.DefinedOperation, len(document.Operations))
	seen := make(map[string]struct{}, len(document.Operations))
	for index, name := range document.Operations {
		if _, duplicate := seen[name]; duplicate {
			return r3.DefinitionMaterial{}, r3.NewDefinitionError(r3.DefinitionIdentityAmbiguous, "duplicate third-party operation", nil)
		}
		seen[name] = struct{}{}
		operation, err := newIntegrationThirdPartyOperation(name)
		if err != nil {
			return r3.DefinitionMaterial{}, r3.NewDefinitionError(r3.DefinitionIdentityUnavailable, "invalid third-party operation", err)
		}
		encoded, err := json.Marshal(operation)
		if err != nil {
			return r3.DefinitionMaterial{}, err
		}
		operations[index], err = r3.NewDefinedOperation(encoded, nil)
		if err != nil {
			return r3.DefinitionMaterial{}, err
		}
	}
	return r3.NewDefinitionMaterial(integrationThirdPartySourceEncoding, source.exact, operations...)
}

var (
	integrationThirdPartyDefinitionOnce   sync.Once
	integrationThirdPartyDefinitionParser r3.DefinitionParser[integrationThirdPartyDefinitionSource]
)

func integrationThirdPartyDefinitions() r3.DefinitionParser[integrationThirdPartyDefinitionSource] {
	integrationThirdPartyDefinitionOnce.Do(func() {
		parser, err := r3.NewDefinitionParser[integrationThirdPartyDefinitionSource](integrationThirdPartyDefinitionCodec{})
		if err != nil {
			panic(err)
		}
		integrationThirdPartyDefinitionParser = parser
	})
	return integrationThirdPartyDefinitionParser
}

func integrationThirdPartyDefinition(t *testing.T, endpoint string, names []string) r3.AuthoritativeSnapshot {
	t.Helper()
	exact, err := json.Marshal(struct {
		Operations []string `json:"operations"`
	}{Operations: append([]string(nil), names...)})
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := integrationThirdPartyDefinitions().Parse(
		endpoint,
		integrationThirdPartyDefinitionSource{exact: exact},
	)
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}

var _ r3.Codec[integrationThirdPartySet] = integrationThirdPartyCodec{}

func TestIntegrationThirdPartyVocabularyContract(t *testing.T) {
	foreign, err := r3.NewVocabulary[integrationThirdPartySet](integrationThirdPartyCodec{})
	if err != nil {
		t.Fatal(err)
	}
	vocabtest.Run(t, vocabtest.Contract{
		Vocabulary:          integrationThirdPartyVocabulary,
		Registry:            newIntegrationR3Registry(t),
		ForeignRegistration: foreign,
		OperationA:          json.RawMessage(`{"service":"records","command":"read","revision":1}`),
		OperationB:          json.RawMessage(`{"service":"records","command":"write","revision":1}`),
		InvalidOperations: []json.RawMessage{
			json.RawMessage(`{"service":"records","command":"read","revision":1,"unexpected":true}`),
			json.RawMessage(`{"service":"records","command":"read","revision":2}`),
		},
		DuplicateOperations: []json.RawMessage{
			json.RawMessage(`{"service":"records","command":"read","command":"write","revision":1}`),
		},
		ValidDiscoveryEndpoint: integrationThirdPartyDiscoveryEndpoint,
		InvalidDiscoveryEndpoints: []string{
			"https://resource.example/custom",
			"custom+unix:///run/resource.sock?definition=stale",
		},
	})
}

func (vocabulary integrationR3Vocabulary) operationSet(t *testing.T, names ...string) r3.OperationSet {
	t.Helper()
	operations := make([]r3.Operation, len(names))
	for index, name := range names {
		operations[index] = vocabulary.newOperation(t, name)
	}
	set, err := r3.NewOperationSet(operations...)
	if err != nil {
		t.Fatal(err)
	}
	return set
}

func (vocabulary integrationR3Vocabulary) operationSetsEqual(t *testing.T, left, right r3.OperationSet) bool {
	t.Helper()
	if left.Vocabulary() != vocabulary.uri || right.Vocabulary() != vocabulary.uri {
		return false
	}
	return vocabulary.operationSlicesEqual(t, left.Operations(), right.Operations())
}

func (vocabulary integrationR3Vocabulary) operationsEqual(t *testing.T, left, right r3.Operation) bool {
	t.Helper()
	return vocabulary.operationID(t, left) == vocabulary.operationID(t, right)
}

func (vocabulary integrationR3Vocabulary) grantedEqual(t *testing.T, left, right r3.GrantedOperations) bool {
	t.Helper()
	if left.Vocabulary() != vocabulary.uri || right.Vocabulary() != vocabulary.uri {
		return false
	}
	return vocabulary.operationSlicesEqual(t, left.Operations(), right.Operations())
}

func (vocabulary integrationR3Vocabulary) operationSlicesEqual(t *testing.T, left, right []r3.Operation) bool {
	t.Helper()
	if len(left) != len(right) {
		return false
	}
	leftIDs := make([]string, len(left))
	rightIDs := make([]string, len(right))
	for index := range left {
		leftIDs[index] = vocabulary.operationID(t, left[index])
		rightIDs[index] = vocabulary.operationID(t, right[index])
	}
	slices.Sort(leftIDs)
	slices.Sort(rightIDs)
	return slices.Equal(leftIDs, rightIDs)
}
