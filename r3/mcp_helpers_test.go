package r3_test

import (
	"testing"

	"aauth-go/r3"
	"aauth-go/r3/vocab/mcp"
)

var mcpRegistry = newMCPRegistry()

func newMCPRegistry() r3.Registry {
	registry, err := r3.NewRegistry(mcp.Vocabulary())
	if err != nil {
		panic(err)
	}
	return registry
}

func mustOperation(t *testing.T, tool string) r3.Operation {
	t.Helper()
	typed, err := mcp.NewOperation(tool)
	if err != nil {
		t.Fatalf("new MCP operation %q: %v", tool, err)
	}
	operation, err := typed.ToR3()
	if err != nil {
		t.Fatalf("convert MCP operation %q: %v", tool, err)
	}
	return operation
}

func mustSet(t *testing.T, tools ...string) r3.OperationSet {
	t.Helper()
	operations := make([]mcp.Operation, len(tools))
	for index, tool := range tools {
		operation, err := mcp.NewOperation(tool)
		if err != nil {
			t.Fatalf("new MCP operation %q: %v", tool, err)
		}
		operations[index] = operation
	}
	set, err := mcp.NewOperationSet(operations...)
	if err != nil {
		t.Fatalf("new MCP operation set: %v", err)
	}
	return set
}

func mustGranted(t *testing.T, tools ...string) r3.GrantedOperations {
	t.Helper()
	operations := make([]r3.Operation, len(tools))
	for index, tool := range tools {
		operations[index] = mustOperation(t, tool)
	}
	granted, err := r3.NewGrantedOperations(mcp.Vocabulary(), operations...)
	if err != nil {
		t.Fatalf("new granted operations: %v", err)
	}
	return granted
}

func mcpTool(t *testing.T, operation r3.Operation) string {
	t.Helper()
	typed, err := mcp.FromR3(operation)
	if err != nil {
		t.Fatalf("decode MCP operation: %v", err)
	}
	return typed.Tool()
}

func operationSetsEqual(t *testing.T, left, right r3.OperationSet) bool {
	t.Helper()
	equal, err := left.Equal(right)
	if err != nil {
		t.Fatalf("compare operation sets: %v", err)
	}
	return equal
}

func operationSetSubset(t *testing.T, subset, superset r3.OperationSet) bool {
	t.Helper()
	contained, err := subset.IsSubsetOf(superset)
	if err != nil {
		t.Fatalf("compare operation-set subset: %v", err)
	}
	return contained
}

func grantedEqual(t *testing.T, left, right r3.GrantedOperations) bool {
	t.Helper()
	equal, err := left.Equal(right)
	if err != nil {
		t.Fatalf("compare granted operations: %v", err)
	}
	return equal
}

func grantedSubset(t *testing.T, subset, superset r3.GrantedOperations) bool {
	t.Helper()
	if subset.Vocabulary() != superset.Vocabulary() {
		t.Fatalf("grant vocabularies differ: %q and %q", subset.Vocabulary(), superset.Vocabulary())
	}
	if len(subset.Operations()) == 0 {
		return true
	}
	if len(superset.Operations()) == 0 {
		return false
	}
	subsetSet, err := r3.NewOperationSet(subset.Operations()...)
	if err != nil {
		t.Fatal(err)
	}
	supersetSet, err := r3.NewOperationSet(superset.Operations()...)
	if err != nil {
		t.Fatal(err)
	}
	return operationSetSubset(t, subsetSet, supersetSet)
}

func grantedContains(t *testing.T, granted r3.GrantedOperations, operation r3.Operation) bool {
	t.Helper()
	contains, err := granted.Contains(operation)
	if err != nil {
		t.Fatalf("check granted operation membership: %v", err)
	}
	return contains
}
