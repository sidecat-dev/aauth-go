// The r3threeparty example runs direct MCP class authorization through an
// Agent Provider, Agent, Person Server, and Resource. The Person Server grants
// one of the two requested operations and no Access Server participates.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	clientagent "gitlab.com/sidecat-dev/aauth-go/agent"
	"gitlab.com/sidecat-dev/aauth-go/agentprovider"
	"gitlab.com/sidecat-dev/aauth-go/personserver"
	"gitlab.com/sidecat-dev/aauth-go/r3"
	"gitlab.com/sidecat-dev/aauth-go/r3/vocab/mcp"
	"gitlab.com/sidecat-dev/aauth-go/resource"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

const (
	agentProviderID = "https://agents.example"
	agentID         = "aauth:reader@agents.example"
	personServerID  = "https://person.example"
	resourceID      = "https://resource.example"
)

func main() {
	if err := run(os.Stdout); err != nil {
		log.Fatal(err)
	}
}

func run(output io.Writer) error {
	ctx := context.Background()
	now := time.Date(2026, 8, 31, 18, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })

	providerKey, err := newSigningKey("agent-provider-key")
	if err != nil {
		return err
	}
	agentKey, err := newSigningKey("agent-key")
	if err != nil {
		return err
	}
	personKey, err := newSigningKey("person-server-key")
	if err != nil {
		return err
	}
	resourceKey, err := newSigningKey("resource-key")
	if err != nil {
		return err
	}

	network := newLogicalTransport()
	httpClient := &http.Client{Transport: network}
	resolver, err := signaturekey.NewHTTPKeyResolver(signaturekey.HTTPKeyResolverConfig{
		Client: httpClient,
		Clock:  clock,
		Admit:  network.Admit,
	})
	if err != nil {
		return fmt.Errorf("create key resolver: %w", err)
	}

	provider, err := agentprovider.New(agentprovider.Config{
		Issuer: agentProviderID, SigningKey: providerKey, Clock: clock,
		NewID: func() string { return "agent-token-1" },
	})
	if err != nil {
		return fmt.Errorf("create Agent Provider: %w", err)
	}
	agentToken, err := provider.Issue(aauth.AgentTokenRequest{
		Agent: agentID, PersonServer: personServerID,
		PublicKey: agentKey.PublicJWK(), Lifetime: time.Hour,
	})
	if err != nil {
		return fmt.Errorf("issue Agent token: %w", err)
	}

	registry, err := r3.NewRegistry(mcp.Vocabulary())
	if err != nil {
		return fmt.Errorf("create R3 registry: %w", err)
	}
	definitions, err := r3.NewDefinitionRegistry(mcp.DefinitionRegistration())
	if err != nil {
		return fmt.Errorf("create R3 definition registry: %w", err)
	}
	readMCP, err := mcp.NewOperation("records.read")
	if err != nil {
		return err
	}
	exportMCP, err := mcp.NewOperation("records.export")
	if err != nil {
		return err
	}
	readOperation, err := readMCP.ToR3()
	if err != nil {
		return err
	}
	exportOperation, err := exportMCP.ToR3()
	if err != nil {
		return err
	}
	requested, err := mcp.NewOperationSet(readMCP, exportMCP)
	if err != nil {
		return err
	}
	definition, err := mcp.ParseDefinition(resourceID+"/mcp", mcp.NewToolsListSnapshot(
		mcp.NewInitialToolsListPage([]byte(`{
			"tools":[
				{"name":"records.read","inputSchema":{"type":"object"}},
				{"name":"records.export","inputSchema":{"type":"object"}}
			]
		}`)),
	))
	if err != nil {
		return fmt.Errorf("parse authoritative MCP definition: %w", err)
	}
	display, err := r3.NewDisplay(
		"Read and export records",
		"Exports may leave the system",
		"Record contents",
		"Exported copies cannot be recalled",
	)
	if err != nil {
		return err
	}

	resourceServer, err := resource.NewPSAuthorization(resource.PSAuthorizationConfig{
		Issuer: resourceID, SigningKey: resourceKey, KeyResolver: resolver, Clock: clock,
		NewID: func() string { return "resource-token-1" },
		ResolvePerson: func(_ context.Context, identity resource.PersonIdentity, _ resource.PersonContext) error {
			if identity.Issuer != personServerID || identity.Subject != "person-123" {
				return errors.New("unrecognized person")
			}
			return nil
		},
		R3: &resource.R3Config{
			Registry: registry, Definitions: definitions,
			Vocabularies: []resource.R3VocabularyConfig{{
				Definition: definition,
				DisplayForOperations: func(_ context.Context, operations r3.OperationSet, _ *string) (*r3.Display, error) {
					equal, err := operations.Equal(requested)
					if err != nil || !equal {
						return nil, errors.New("unexpected MCP operation request")
					}
					return &display, nil
				},
			}},
			Documents: newMemoryDocumentStore(),
			HTTP: resource.R3HTTPAdapter{OperationForRequest: func(request *http.Request) (r3.Operation, bool, error) {
				switch request.URL.Path {
				case "/records/read":
					return readOperation, true, nil
				case "/records/export":
					return exportOperation, true, nil
				default:
					return r3.Operation{}, false, nil
				}
			}},
		},
		Protected: http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			principal, ok := resource.AuthPrincipalFromContext(request.Context())
			if !ok || principal.PersonServer != personServerID || principal.Subject != "person-123" {
				http.Error(response, "missing expected AAuth principal", http.StatusInternalServerError)
				return
			}
			response.WriteHeader(http.StatusNoContent)
		}),
	})
	if err != nil {
		return fmt.Errorf("create Resource: %w", err)
	}

	personIDs := []string{"person-token-1", "auth-token-1"}
	personServer, err := personserver.NewPSAuthorization(personserver.PSAuthorizationConfig{
		Issuer: personServerID, SigningKey: personKey, KeyResolver: resolver, Clock: clock,
		Tokens: newMemoryPersonTokenStore(),
		NewID: func() string {
			id := personIDs[0]
			personIDs = personIDs[1:]
			return id
		},
		BindPerson: func(_ context.Context, request personserver.PersonTokenRequest) (personserver.Person, error) {
			if request.Agent != agentID || request.Resource != resourceID {
				return personserver.Person{}, errors.New("unexpected person-token request")
			}
			return personserver.Person{Subject: "person-123", Lifetime: time.Hour}, nil
		},
		R3: &personserver.DirectR3Config{
			Registry: registry, HTTPClient: httpClient,
			Admit: func(_ context.Context, endpoint string) error {
				if !strings.HasPrefix(endpoint, resourceID+"/r3/") {
					return errors.New("R3 document endpoint is not admitted")
				}
				return nil
			},
			AuthorizeDocument: func(_ context.Context, request personserver.AuthorizationRequest, _ r3.Reference, document r3.Document) (personserver.DirectR3Decision, error) {
				equal, err := document.OperationSet().Equal(requested)
				if err != nil || !equal || request.Subject != "person-123" || request.Resource != resourceID {
					return personserver.DirectR3Decision{}, errors.New("unexpected direct R3 authorization request")
				}
				granted, err := r3.NewGrantedOperations(mcp.Vocabulary(), readOperation)
				if err != nil {
					return personserver.DirectR3Decision{}, err
				}
				grant, err := r3.NewGrant(granted, document)
				if err != nil {
					return personserver.DirectR3Decision{}, err
				}
				return personserver.DirectR3Decision{
					Lifetime: 30 * time.Minute, Grant: grant,
				}, nil
			},
			Issuances: newMemoryIssuanceStore(),
		},
	})
	if err != nil {
		return fmt.Errorf("create Person Server: %w", err)
	}

	network.Handle(agentProviderID, provider.Handler())
	network.Handle(personServerID, personServer.Handler())
	network.Handle(resourceID, resourceServer.Handler())

	agent, err := clientagent.New(ctx, clientagent.Config{
		Identifier: agentID, SigningKey: agentKey, AgentToken: agentToken,
		KeyResolver: resolver, HTTPClient: httpClient, Clock: clock,
		R3: &clientagent.R3Config{Registry: registry},
	})
	if err != nil {
		return fmt.Errorf("create Agent: %w", err)
	}
	personResult, err := agent.PersonToken(ctx, clientagent.PersonTokenRequest{
		PersonServer: personServerID, Resource: resourceID,
	})
	if err != nil {
		return fmt.Errorf("obtain Person token: %w", err)
	}
	personToken, ok := personResult.Token()
	if !ok {
		return errors.New("Person Server unexpectedly required interaction")
	}
	resourceToken, err := agent.Authorize(ctx, clientagent.AuthorizeRequest{
		Resource: resourceID, PersonToken: personToken, R3Operations: &requested,
	})
	if err != nil {
		return fmt.Errorf("obtain Resource token: %w", err)
	}
	authToken, err := agent.Exchange(ctx, clientagent.ExchangeRequest{
		PersonServer: personServerID, ResourceToken: resourceToken,
	})
	if err != nil {
		return fmt.Errorf("exchange at Person Server: %w", err)
	}

	_, _, granted, err := r3.VerifyDirectAuthToken(ctx, registry, authToken, resolver, clock)
	if err != nil {
		return fmt.Errorf("verify direct R3 Auth token: %w", err)
	}
	grantedOperations := granted.Operations()
	if len(grantedOperations) != 1 {
		return fmt.Errorf("Person Server granted %d operations, want 1", len(grantedOperations))
	}
	equal, err := grantedOperations[0].Equal(readOperation)
	if err != nil || !equal {
		return errors.New("Person Server did not narrow the grant to records.read")
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, resourceID+"/records/read", nil)
	if err != nil {
		return err
	}
	response, err := agent.Do(ctx, clientagent.Call{Request: request, AuthToken: authToken})
	if err != nil {
		return fmt.Errorf("call granted MCP operation: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		return fmt.Errorf("protected call returned %s", response.Status)
	}
	exportRequest, err := http.NewRequestWithContext(ctx, http.MethodGet, resourceID+"/records/export", nil)
	if err != nil {
		return err
	}
	if exportResponse, err := agent.Do(ctx, clientagent.Call{Request: exportRequest, AuthToken: authToken}); err == nil {
		exportResponse.Body.Close()
		return errors.New("Resource accepted records.export without an R3 grant")
	}

	_, err = fmt.Fprintln(output, "AAuth direct R3 three-party flow complete: granted records.read; withheld records.export")
	return err
}
