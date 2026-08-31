package graphql

import (
	"bytes"
	"encoding/json"

	"gitlab.com/sidecat-dev/aauth-go/r3"
	"gitlab.com/sidecat-dev/aauth-go/r3/internal/wirejson"
)

// IntrospectionSource owns one exact GraphQL introspection response. Fetching
// and request policy remain application responsibilities.
type IntrospectionSource struct{ exact []byte }

const sourceEncoding r3.SourceEncoding = "urn:aauth:source-encoding:graphql-introspection-response-exact-v1"

// NewIntrospectionSource copies an exact introspection response.
func NewIntrospectionSource(exact []byte) IntrospectionSource {
	return IntrospectionSource{exact: append([]byte(nil), exact...)}
}

// ExactBytes returns an owned copy of the response.
func (source IntrospectionSource) ExactBytes() []byte {
	return append([]byte(nil), source.exact...)
}

type definitionCodec struct{}

func (definitionCodec) Vocabulary() r3.Vocabulary { return Vocabulary() }

func (definitionCodec) ParseDefinition(source IntrospectionSource) (r3.DefinitionMaterial, error) {
	if err := wirejson.ValidateSource(source.exact); err != nil {
		return r3.DefinitionMaterial{}, r3.NewDefinitionError(r3.DefinitionInvalidSource, "invalid GraphQL introspection response", err)
	}
	var response struct {
		Data *struct {
			Schema json.RawMessage `json:"__schema"`
		} `json:"data"`
	}
	if err := json.Unmarshal(source.exact, &response); err != nil {
		return r3.DefinitionMaterial{}, r3.NewDefinitionError(r3.DefinitionInvalidSource, "invalid GraphQL introspection response", err)
	}
	if response.Data == nil || len(response.Data.Schema) == 0 || bytes.Equal(bytes.TrimSpace(response.Data.Schema), []byte("null")) {
		return r3.DefinitionMaterial{}, r3.NewDefinitionError(r3.DefinitionIncompleteSource, "GraphQL introspection response is missing data.__schema", nil)
	}
	var schema map[string]json.RawMessage
	if err := json.Unmarshal(response.Data.Schema, &schema); err != nil || schema == nil {
		return r3.DefinitionMaterial{}, r3.NewDefinitionError(r3.DefinitionInvalidSource, "GraphQL data.__schema is not an object", err)
	}
	return r3.DefinitionMaterial{}, r3.NewDefinitionError(
		r3.DefinitionIdentityUnavailable,
		"GraphQL schema introspection does not publish client-authored executable operation names",
		nil,
	)
}

var definitionParser = mustDefinitionParser()

func mustDefinitionParser() r3.DefinitionParser[IntrospectionSource] {
	parser, err := r3.NewDefinitionParser(definitionCodec{})
	if err != nil {
		panic(err)
	}
	return parser
}

// ParseDefinition checks for JSON containing object-valued data.__schema, then
// returns the R3 identity-gap refusal defined by the current draft.
func ParseDefinition(endpoint string, source IntrospectionSource) (r3.AuthoritativeSnapshot, error) {
	return definitionParser.Parse(endpoint, source)
}

// DefinitionRegistration returns the stable GraphQL definition registration.
func DefinitionRegistration() r3.DefinitionRegistration {
	return definitionParser.Registration()
}
