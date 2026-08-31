// Package standard constructs explicit operation and native-definition
// registries for the seven standard R3 vocabularies. Applications may instead
// register only the vocabularies their Resource actually advertises.
package standard

import (
	"gitlab.com/sidecat-dev/aauth-go/r3"
	"gitlab.com/sidecat-dev/aauth-go/r3/vocab/asyncapi"
	"gitlab.com/sidecat-dev/aauth-go/r3/vocab/graphql"
	"gitlab.com/sidecat-dev/aauth-go/r3/vocab/grpc"
	"gitlab.com/sidecat-dev/aauth-go/r3/vocab/mcp"
	"gitlab.com/sidecat-dev/aauth-go/r3/vocab/odata"
	"gitlab.com/sidecat-dev/aauth-go/r3/vocab/openapi"
	"gitlab.com/sidecat-dev/aauth-go/r3/vocab/wsdl"
)

// Registry returns a new immutable allowlist containing all seven standard
// vocabularies. Construction has no global registration side effect.
func Registry() r3.Registry {
	registry, err := r3.NewRegistry(
		mcp.Vocabulary(),
		openapi.Vocabulary(),
		grpc.Vocabulary(),
		graphql.Vocabulary(),
		asyncapi.Vocabulary(),
		wsdl.Vocabulary(),
		odata.Vocabulary(),
	)
	if err != nil {
		panic(err)
	}
	return registry
}

// Definitions returns the immutable allowlist of all seven standard native
// definition parsers. Some registrations deliberately return typed
// specification-gap refusals rather than inventing operation identities.
func Definitions() r3.DefinitionRegistry {
	registry, err := r3.NewDefinitionRegistry(
		mcp.DefinitionRegistration(),
		openapi.DefinitionRegistration(),
		grpc.DefinitionRegistration(),
		graphql.DefinitionRegistration(),
		asyncapi.DefinitionRegistration(),
		wsdl.DefinitionRegistration(),
		odata.DefinitionRegistration(),
	)
	if err != nil {
		panic(err)
	}
	return registry
}
