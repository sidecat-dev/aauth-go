package aauth_test

import (
	"testing"

	"gitlab.com/sidecat-dev/aauth-go/r3"
	"gitlab.com/sidecat-dev/aauth-go/r3/vocab/mcp"
)

var tokenMCPRegistry = newTokenMCPRegistry()

func newTokenMCPRegistry() r3.Registry {
	registry, err := r3.NewRegistry(mcp.Vocabulary())
	if err != nil {
		panic(err)
	}
	return registry
}

func newMCPR3Operation(tool string) (r3.Operation, error) {
	typed, err := mcp.NewOperation(tool)
	if err != nil {
		return r3.Operation{}, err
	}
	return typed.ToR3()
}

func mcpR3Tool(t *testing.T, operation r3.Operation) string {
	t.Helper()
	typed, err := mcp.FromR3(operation)
	if err != nil {
		t.Fatalf("decode MCP operation: %v", err)
	}
	return typed.Tool()
}

func tokenGrantedEqual(t *testing.T, left, right r3.GrantedOperations) bool {
	t.Helper()
	equal, err := left.Equal(right)
	if err != nil {
		t.Fatalf("compare granted operations: %v", err)
	}
	return equal
}

func tokenGrantedContains(t *testing.T, granted r3.GrantedOperations, operation r3.Operation) bool {
	t.Helper()
	contains, err := granted.Contains(operation)
	if err != nil {
		t.Fatalf("check granted operation membership: %v", err)
	}
	return contains
}
