package main

import (
	"net/http"
	"sync/atomic"

	"gitlab.com/sidecat-dev/aauth-go/r3"
	"gitlab.com/sidecat-dev/aauth-go/r3/vocab/mcp"
	"gitlab.com/sidecat-dev/aauth-go/resource"
)

func hostedR3Model() (r3.Registry, r3.DefinitionRegistry, r3.OperationSet, r3.Operation, r3.AuthoritativeSnapshot, error) {
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
	definition, err := mcp.ParseDefinition(hostedResourceID+"/mcp", mcp.NewToolsListSnapshot(mcp.NewInitialToolsListPage([]byte(`{
		"tools":[{"name":"records.current","inputSchema":{"type":"object"},"_meta":{"aauth.dev/budget":true}}]
	}`))))
	return registry, definitions, operations, operation, definition, err
}

type connectorApplication struct {
	oauthCredential string
	account         string
	observations    *profileObservations
	calls           atomic.Int64
}

func (connector *connectorApplication) serve(response http.ResponseWriter, request *http.Request) {
	principal, ok := resource.AuthPrincipalFromContext(request.Context())
	if !ok || principal.Subject != "person-123" || principal.Account == nil ||
		*principal.Account != connector.account || connector.oauthCredential == "" {
		http.Error(response, "connector context unavailable", http.StatusInternalServerError)
		return
	}
	// Only application code can read oauthCredential. AAuth policy and tokens
	// carry the person, account, operation, and Budget—not this third-party secret.
	if connector.observations != nil {
		connector.observations.connectorCalls.Add(1)
	}
	connector.calls.Add(1)
	response.WriteHeader(http.StatusNoContent)
}

func (connector *connectorApplication) credentialStayedPrivate() bool {
	return connector.oauthCredential == "application-only-oauth-credential"
}
