package main

import (
	"gitlab.com/sidecat-dev/aauth-go/r3"
	"gitlab.com/sidecat-dev/aauth-go/r3/vocab/mcp"
)

func hostedR3Model(resourceOrigin string) (r3.Registry, r3.DefinitionRegistry, r3.OperationSet, r3.Operation, r3.AuthoritativeSnapshot, error) {
	registry, err := r3.NewRegistry(mcp.Vocabulary())
	if err != nil {
		return r3.Registry{}, r3.DefinitionRegistry{}, r3.OperationSet{}, r3.Operation{}, r3.AuthoritativeSnapshot{}, err
	}
	definitions, err := r3.NewDefinitionRegistry(mcp.DefinitionRegistration())
	if err != nil {
		return r3.Registry{}, r3.DefinitionRegistry{}, r3.OperationSet{}, r3.Operation{}, r3.AuthoritativeSnapshot{}, err
	}
	mcpOperation, err := mcp.NewOperation("records.current")
	if err != nil {
		return r3.Registry{}, r3.DefinitionRegistry{}, r3.OperationSet{}, r3.Operation{}, r3.AuthoritativeSnapshot{}, err
	}
	operation, err := mcpOperation.ToR3()
	if err != nil {
		return r3.Registry{}, r3.DefinitionRegistry{}, r3.OperationSet{}, r3.Operation{}, r3.AuthoritativeSnapshot{}, err
	}
	operations, err := mcp.NewOperationSet(mcpOperation)
	if err != nil {
		return r3.Registry{}, r3.DefinitionRegistry{}, r3.OperationSet{}, r3.Operation{}, r3.AuthoritativeSnapshot{}, err
	}
	definition, err := mcp.ParseDefinition(resourceOrigin+"/mcp", mcp.NewToolsListSnapshot(mcp.NewInitialToolsListPage([]byte(`{
		"tools":[{"name":"records.current","inputSchema":{"type":"object"},"_meta":{"aauth.dev/budget":true}}]
	}`))))
	return registry, definitions, operations, operation, definition, err
}
