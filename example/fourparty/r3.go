package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"time"

	aauth "aauth-go"
	"aauth-go/accessserver"
	clientagent "aauth-go/agent"
	"aauth-go/agentprovider"
	"aauth-go/internal/exampleutil"
	"aauth-go/personserver"
	"aauth-go/r3"
	"aauth-go/resource"
	"aauth-go/signaturekey"
)

func runR3Direct(output io.Writer) {
	now := time.Date(2026, 8, 31, 18, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	ctx := context.Background()

	providerKey := newSigningKey("r3-agent-provider-key")
	agentKey := newSigningKey("r3-agent-key")
	personKey := newSigningKey("r3-person-server-key")
	accessKey := newSigningKey("r3-access-server-key")
	resourceKey := newSigningKey("r3-resource-key")
	network := newLogicalTransport()
	httpClient := &http.Client{Transport: network}
	resolver := must(signaturekey.NewHTTPKeyResolver(signaturekey.HTTPKeyResolverConfig{
		Client: httpClient,
		Clock:  clock,
		Admit:  network.Admit,
	}))

	provider := must(agentprovider.New(agentprovider.Config{
		Issuer: agentProviderID, SigningKey: providerKey, Clock: clock,
		NewID: func() string { return "r3-agent-token-1" },
	}))
	agentToken := must(provider.Issue(aauth.AgentTokenRequest{
		Agent: agentID, PersonServer: personServerID,
		PublicKey: agentKey.PublicJWK(), Lifetime: time.Hour,
	}))

	read := must(r3.NewMCPOperation("records.read"))
	export := must(r3.NewMCPOperation("records.export"))
	requested := must(r3.NewMCPOperationSet(read, export))
	display := must(r3.NewDisplay(
		"Read and export records",
		"Exported records may leave the system",
		"Record contents",
		"Exported copies cannot be recalled",
	))
	account := "work-account"
	documents := newExampleR3DocumentStore()

	protectedResource := must(resource.NewFederatedAuthorization(resource.FederatedAuthorizationConfig{
		Issuer: resourceID, AccessServer: accessServerID,
		SigningKey: resourceKey, KeyResolver: resolver, Clock: clock,
		NewID:             func() string { return "r3-resource-token-1" },
		ScopeDescriptions: map[string]string{scope: "Read records"},
		RequiredScopes:    func(*http.Request) []string { return nil },
		ResolvePerson: func(_ context.Context, identity resource.PersonIdentity, _ resource.PersonContext) error {
			if identity != (resource.PersonIdentity{Issuer: personServerID, Subject: "person-123"}) {
				return errors.New("unrecognized person")
			}
			return nil
		},
		ValidateAccount: func(_ context.Context, _ resource.PersonIdentity, got string) error {
			if got != account {
				return errors.New("unexpected account")
			}
			return nil
		},
		MCPR3: &resource.MCPR3Config{
			DiscoveryEndpoint: resourceID + "/mcp",
			KnownTools:        []string{"records.read", "records.export"},
			Documents:         documents,
			DisplayForOperations: func(_ context.Context, operations r3.MCPOperationSet, gotAccount *string) (*r3.Display, error) {
				if !operations.Equal(requested) || gotAccount == nil || *gotAccount != account {
					return nil, errors.New("unexpected R3 display input")
				}
				return &display, nil
			},
			OperationForRequest: func(request *http.Request) (string, bool, error) {
				switch request.URL.Path {
				case "/records/read":
					return "records.read", true, nil
				case "/records/export":
					return "records.export", true, nil
				default:
					return "", false, nil
				}
			},
		},
		Protected: http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			principal, ok := resource.AuthPrincipalFromContext(request.Context())
			if !ok || principal.Account == nil || *principal.Account != account {
				http.Error(response, "missing R3 principal", http.StatusInternalServerError)
				return
			}
			fmt.Fprintf(output, "AAuth MCP R3 four-party flow complete: %s can use records.read\n", principal.Subject)
		}),
	}))

	issuances := newExampleR3IssuanceStore()
	access := must(accessserver.New(accessserver.Config{
		Issuer: accessServerID, SigningKey: accessKey,
		KeyResolver: resolver, Clock: clock,
		NewID: func() string { return "r3-auth-token-1" },
		TrustPersonServer: func(_ context.Context, issuer string) error {
			if issuer != personServerID {
				return errors.Join(accessserver.ErrAccessDenied, errors.New("untrusted Person Server"))
			}
			return nil
		},
		Authorize: func(_ context.Context, request accessserver.AuthorizationRequest) (accessserver.Decision, error) {
			if request.MCPR3 == nil || !request.MCPR3.Document.OperationSet().Equal(requested) {
				return accessserver.Decision{}, errors.Join(accessserver.ErrAccessDenied, errors.New("unexpected R3 document"))
			}
			granted := must(r3.NewGrantedOperations(read))
			grant := must(r3.NewGrant(granted, request.MCPR3.Document))
			return accessserver.Decision{Lifetime: 30 * time.Minute, MCPR3Grant: &grant}, nil
		},
		MCPR3: &accessserver.MCPR3Config{
			HTTPClient: httpClient,
			Admit:      network.Admit,
			Issuances:  issuances,
		},
	}))

	people := must(personserver.NewFederatedAuthorization(personserver.FederatedAuthorizationConfig{
		Issuer: personServerID, SigningKey: personKey,
		KeyResolver: resolver, Clock: clock,
		NewID:      func() string { return "r3-person-token-1" },
		HTTPClient: httpClient, Tokens: exampleutil.NewMissionStore(),
		AccessServerEndpoint: func(_ context.Context, issuer string) (string, error) {
			if issuer != accessServerID {
				return "", errors.New("unknown Access Server")
			}
			return accessServerID + "/token", nil
		},
		BindPerson: func(_ context.Context, request personserver.PersonTokenRequest) (personserver.Person, error) {
			if request.Agent != agentID || request.Resource != resourceID {
				return personserver.Person{}, errors.New("unexpected person-token request")
			}
			return personserver.Person{Subject: "person-123", Lifetime: time.Hour}, nil
		},
		Consent: func(context.Context, personserver.AuthorizationRequest) error {
			return errors.New("Core consent must not receive an R3 request")
		},
		MCPR3: &personserver.MCPR3Config{
			Admit: network.Admit,
			Consent: func(_ context.Context, request personserver.AuthorizationRequest, _ r3.Reference, document r3.Document) error {
				gotDisplay, ok := document.Display()
				if request.Account == nil || *request.Account != account || !document.OperationSet().Equal(requested) ||
					!ok || gotDisplay.Summary() != display.Summary() {
					return errors.Join(personserver.ErrAccessDenied, errors.New("unexpected R3 consent input"))
				}
				return nil
			},
		},
	}))

	network.Handle(agentProviderID, provider.Handler())
	network.Handle(personServerID, people.Handler())
	network.Handle(accessServerID, access.Handler())
	network.Handle(resourceID, protectedResource.Handler())

	reader := must(clientagent.New(ctx, clientagent.Config{
		Identifier: agentID, SigningKey: agentKey, AgentToken: agentToken,
		KeyResolver: resolver, HTTPClient: httpClient, Clock: clock,
	}))
	personResult := must(reader.PersonToken(ctx, clientagent.PersonTokenRequest{
		PersonServer: personServerID, Resource: resourceID,
	}))
	personToken, ok := personResult.Token()
	if !ok {
		panic("R3 example unexpectedly required interaction")
	}
	resourceToken := must(reader.Authorize(ctx, clientagent.AuthorizeRequest{
		Resource: resourceID, PersonToken: personToken,
		Account: &account, MCPR3Operations: &requested,
	}))
	authToken := must(reader.Exchange(ctx, clientagent.ExchangeRequest{
		PersonServer: personServerID, ResourceToken: resourceToken,
	}))
	request := must(http.NewRequestWithContext(ctx, http.MethodGet, resourceID+"/records/read", nil))
	response := must(reader.Do(ctx, clientagent.Call{Request: request, AuthToken: authToken}))
	response.Body.Close()
	if response.StatusCode != http.StatusOK || issuances.Count() != 1 {
		panic("R3 example did not retain and execute one grant")
	}
	request = must(http.NewRequestWithContext(ctx, http.MethodGet, resourceID+"/records/export", nil))
	if response, err := reader.Do(ctx, clientagent.Call{Request: request, AuthToken: authToken}); err == nil {
		response.Body.Close()
		panic("R3 example accepted an operation omitted from the direct grant")
	}
}

type exampleR3DocumentStore struct {
	mu      sync.Mutex
	records map[string]resource.R3DocumentRecord
}

func newExampleR3DocumentStore() *exampleR3DocumentStore {
	return &exampleR3DocumentStore{records: make(map[string]resource.R3DocumentRecord)}
}

func (store *exampleR3DocumentStore) Commit(_ context.Context, record resource.R3DocumentRecord) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if retained, ok := store.records[record.Reference.URI()]; ok {
		if retained.Reference != record.Reference || retained.PersonServer != record.PersonServer ||
			retained.AccessServer != record.AccessServer || !bytes.Equal(retained.ExactJSON, record.ExactJSON) {
			return resource.ErrR3DocumentConflict
		}
		return nil
	}
	record.ExactJSON = append([]byte(nil), record.ExactJSON...)
	store.records[record.Reference.URI()] = record
	return nil
}

func (store *exampleR3DocumentStore) Load(_ context.Context, uri string) (resource.R3DocumentRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	record, ok := store.records[uri]
	if !ok {
		return resource.R3DocumentRecord{}, resource.ErrR3DocumentNotFound
	}
	record.ExactJSON = append([]byte(nil), record.ExactJSON...)
	return record, nil
}

type exampleR3IssuanceStore struct {
	mu      sync.Mutex
	records map[aauth.TokenReference]accessserver.R3IssuanceRecord
}

func newExampleR3IssuanceStore() *exampleR3IssuanceStore {
	return &exampleR3IssuanceStore{records: make(map[aauth.TokenReference]accessserver.R3IssuanceRecord)}
}

func (store *exampleR3IssuanceStore) Commit(_ context.Context, record accessserver.R3IssuanceRecord) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	record = cloneExampleR3Issuance(record)
	if retained, ok := store.records[record.AuthTokenReference]; ok {
		if !reflect.DeepEqual(retained, record) {
			return accessserver.ErrR3IssuanceConflict
		}
		return nil
	}
	store.records[record.AuthTokenReference] = record
	return nil
}

func (store *exampleR3IssuanceStore) Count() int {
	store.mu.Lock()
	defer store.mu.Unlock()
	return len(store.records)
}

func cloneExampleR3Issuance(record accessserver.R3IssuanceRecord) accessserver.R3IssuanceRecord {
	record.ExactAuthToken = strings.Clone(record.ExactAuthToken)
	if record.Account != nil {
		account := *record.Account
		record.Account = &account
	}
	return record
}
