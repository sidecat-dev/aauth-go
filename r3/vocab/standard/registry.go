// Package standard constructs the explicit registry of the seven standard R3
// operation vocabularies. Applications may instead register only the
// vocabularies their Resource actually advertises.
package standard

import (
	"aauth-go/r3"
	"aauth-go/r3/vocab/asyncapi"
	"aauth-go/r3/vocab/graphql"
	"aauth-go/r3/vocab/grpc"
	"aauth-go/r3/vocab/mcp"
	"aauth-go/r3/vocab/odata"
	"aauth-go/r3/vocab/openapi"
	"aauth-go/r3/vocab/wsdl"
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
