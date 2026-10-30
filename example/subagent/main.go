// The subagent example runs one-level parent-mediated authorization in
// process: the parent asks its hosted Agent Provider for a sub-agent token with
// its own signed request, the parent obtains every credential from the Person
// Server, and only the sub-agent calls the Resource. It shows a three-party
// immediate grant, a four-party grant that waits for Access Server approval and
// is advanced from the Person Server host's queue, and how revoking the
// parent's binding stops the next authorization.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"sync/atomic"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/accessserver"
	"gitlab.com/sidecat-dev/aauth-go/agent"
	"gitlab.com/sidecat-dev/aauth-go/agentprovider"
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/personserver"
	"gitlab.com/sidecat-dev/aauth-go/resource"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
	"gitlab.com/sidecat-dev/aauth-go/testutil"
)

const (
	agentProviderID = "https://agents.example"
	parentAgentID   = "aauth:planner@agents.example"
	personServerID  = "https://person.example"
	accessServerID  = "https://access.example"
	recordsID       = "https://records.example"
	ordersID        = "https://orders.example"
)

func main() { run(os.Stdout) }

func run(output io.Writer) {
	ctx := context.Background()
	clock := aauth.ClockFunc(func() time.Time { return time.Date(2026, 10, 20, 20, 0, 0, 0, time.UTC) })
	network := newLogicalTransport()
	httpClient := &http.Client{Transport: network}
	resolver := must(signaturekey.NewHTTPKeyResolver(signaturekey.HTTPKeyResolverConfig{
		Client: httpClient, Clock: clock, Admit: network.Admit,
		// The in-memory network makes no connection. Leave this unset with a
		// network transport, so the resolver checks every destination.
		TransportEnforcesEgress: true,
	}))
	var ids atomic.Uint64
	newID := func() string { return fmt.Sprintf("example-%d", ids.Add(1)) }

	// The parent's own hosted Agent Provider issues the child. Its metadata
	// and JWKS share the origin with the sub-agent endpoint, and its policy
	// decides which parents may spawn which sub-agents. The child's private
	// key never leaves the child.
	parentKey, childKey := newSigningKey("parent-key"), newSigningKey("child-key")
	provider := must(agentprovider.New(agentprovider.Config{
		Issuer: agentProviderID, SigningKey: newSigningKey("agent-provider-key"), Clock: clock, NewID: newID,
	}))
	providerRoutes := http.NewServeMux()
	providerRoutes.Handle("/", provider.Handler())
	providerRoutes.Handle("POST /subagent", provider.SubagentHandler(func(_ context.Context, request agentprovider.SubagentRequest) (agentprovider.SubagentDecision, error) {
		if request.Parent.Subject != parentAgentID || request.Discriminator != "search" {
			return agentprovider.SubagentDecision{}, agentprovider.ErrSubagentDenied
		}
		return agentprovider.SubagentDecision{Discriminator: "search", Lifetime: 30 * time.Minute}, nil
	}))
	network.Handle(agentProviderID, providerRoutes)
	parentToken := must(provider.Issue(aauth.AgentTokenRequest{
		Agent: parentAgentID, PersonServer: personServerID, PublicKey: parentKey.PublicJWK(), Lifetime: time.Hour,
	}))
	parent := must(agent.New(ctx, agent.Config{
		Identifier: parentAgentID, SigningKey: parentKey, AgentToken: parentToken,
		KeyResolver: resolver, HTTPClient: httpClient, Clock: clock,
	}))
	childToken := must(parent.RequestSubagentToken(ctx, agent.SubagentTokenRequest{
		Endpoint: agentProviderID + "/subagent", PublicKey: childKey.PublicJWK(), Discriminator: "search",
	}))
	childClaims := must(aauth.VerifyAgentToken(ctx, childToken, resolver, clock))
	fmt.Fprintf(output, "Agent Provider issued sub-agent %s for %s\n", childClaims.Subject, childClaims.ParentAgent)

	child := must(agent.New(ctx, agent.Config{
		Identifier: childClaims.Subject, SigningKey: childKey, AgentToken: childToken,
		KeyResolver: resolver, HTTPClient: httpClient, Clock: clock,
	}))
	personKey := newSigningKey("person-server-key")
	bindPerson := func(_ context.Context, request personserver.PersonTokenRequest) (personserver.Person, error) {
		// Policy sees the parent whose person binding applies and the child
		// that will hold the credential.
		if request.Agent != parentAgentID || request.Subagent != childClaims.Subject {
			return personserver.Person{}, errors.New("unexpected parent-mediated request")
		}
		return personserver.Person{Subject: "person-123", Lifetime: 20 * time.Minute}, nil
	}

	// Scene 1: the Person Server authorizes immediately (three-party).
	threeParty := must(personserver.NewPSAuthorization(personserver.PSAuthorizationConfig{
		Issuer: personServerID, SigningKey: personKey, KeyResolver: resolver, Clock: clock, NewID: newID,
		Tokens: testutil.NewMissionStore(), BindPerson: bindPerson,
		Authorize: func(_ context.Context, request personserver.AuthorizationRequest) (personserver.AuthorizationDecision, error) {
			return personserver.AuthorizationDecision{Scopes: request.Scopes, Lifetime: 15 * time.Minute}, nil
		},
	}))
	network.Handle(personServerID, threeParty.Handler())
	network.Handle(recordsID, must(resource.NewPSAuthorization(resource.PSAuthorizationConfig{
		Issuer: recordsID, SigningKey: newSigningKey("records-key"), KeyResolver: resolver, Clock: clock, NewID: newID,
		ScopeDescriptions: map[string]string{"records.read": "Read records"},
		RequiredScopes:    func(*http.Request) []string { return []string{"records.read"} },
		ResolvePerson:     knownPerson,
		Protected:         childOnly(childKey, "Three-party"),
	})).Handler())
	personToken := mustToken(must(parent.PersonToken(ctx, agent.PersonTokenRequest{
		PersonServer: personServerID, Resource: recordsID, SubagentToken: childToken,
	})).Token())
	resourceToken := must(child.Authorize(ctx, agent.AuthorizeRequest{
		Resource: recordsID, PersonToken: personToken, Scopes: []string{"records.read"},
	}))
	authToken := must(parent.Exchange(ctx, agent.ExchangeRequest{
		PersonServer: personServerID, ResourceToken: resourceToken, PresentedToken: personToken, SubagentToken: childToken,
	}))
	callAsChild(ctx, output, child, recordsID+"/records/42", authToken)

	// Scene 2: the Access Server waits for approval (four-party). The parent
	// polls the Person Server; the Person Server alone polls the AS.
	var approved atomic.Bool
	bindings := testutil.NewAgentBindingRevocationStore()
	federated := must(personserver.NewFederatedAuthorization(personserver.FederatedAuthorizationConfig{
		Issuer: personServerID, SigningKey: personKey, KeyResolver: resolver, Clock: clock, NewID: newID,
		Tokens: testutil.NewMissionStore(), HTTPClient: httpClient, BindPerson: bindPerson,
		AccessServerEndpoint: func(_ context.Context, issuer string) (string, error) {
			if issuer != accessServerID {
				return "", errors.New("unconfigured Access Server")
			}
			return issuer + "/token", nil
		},
		Consent:                 func(context.Context, personserver.AuthorizationRequest) error { return nil },
		Deferred:                &personserver.FederatedDeferredConfig{Store: testutil.NewFederatedAuthorizationStore(), Lifetime: 5 * time.Minute},
		AgentBindingRevocations: bindings,
	}))
	network.Handle(personServerID, federated.Handler())
	network.Handle(accessServerID, must(accessserver.New(accessserver.Config{
		Issuer: accessServerID, SigningKey: newSigningKey("access-server-key"), KeyResolver: resolver, Clock: clock, NewID: newID,
		TrustPersonServer: func(_ context.Context, issuer string) error {
			if issuer != personServerID {
				return accessserver.ErrAccessDenied
			}
			return nil
		},
		Deferred: &accessserver.DeferredConfig{Store: testutil.NewAccessAuthorizationStore(), Lifetime: 5 * time.Minute},
		Authorize: func(_ context.Context, request accessserver.AuthorizationRequest) (accessserver.Decision, error) {
			// The AS verifies both Agent tokens itself and grants the child key.
			if request.Subagent == nil || request.Agent.Identifier != parentAgentID {
				return accessserver.Decision{}, accessserver.ErrAccessDenied
			}
			if !approved.Load() {
				return accessserver.Decision{Pending: &accessserver.PendingDecision{}}, nil
			}
			return accessserver.Decision{Scopes: request.Scopes, Lifetime: 10 * time.Minute}, nil
		},
	})).Handler())
	network.Handle(ordersID, must(resource.NewFederatedAuthorization(resource.FederatedAuthorizationConfig{
		Issuer: ordersID, AccessServer: accessServerID, SigningKey: newSigningKey("orders-key"), KeyResolver: resolver,
		Clock: clock, NewID: newID, ScopeDescriptions: map[string]string{"orders.read": "Read orders"},
		RequiredScopes: func(*http.Request) []string { return []string{"orders.read"} },
		ResolvePerson:  knownPerson,
		Protected:      childOnly(childKey, "Four-party"),
	})).Handler())
	personToken = mustToken(must(parent.PersonToken(ctx, agent.PersonTokenRequest{
		PersonServer: personServerID, Resource: ordersID, SubagentToken: childToken,
	})).Token())
	ordersURL := ordersID + "/orders/7"
	challenge := must(child.Begin(ctx, agent.InitialCall{Request: must(http.NewRequest(http.MethodGet, ordersURL, nil)), PersonToken: personToken}))
	required, ok := challenge.AuthorizationRequired()
	check(ok, "expected the Resource to challenge the child")
	exchange := must(parent.BeginExchange(ctx, agent.ExchangeRequest{
		PersonServer: personServerID, ResourceToken: required.ResourceToken, PresentedToken: personToken, SubagentToken: childToken,
	}))
	pending, ok := exchange.Pending()
	check(ok, "expected a pending exchange")
	fmt.Fprintln(output, "Four-party: the Access Server is waiting for approval; the parent polls the Person Server")
	// A real host authenticates its operator and schedules AS polls from its
	// own queue; this example approves at the AS, then advances the one due
	// PS-owned continuation.
	approved.Store(true)
	references := must(federated.PendingFederatedAuthorizationReferences(ctx, 10))
	check(len(references) == 1, "expected one pending continuation")
	mustSucceed(federated.AdvanceFederation(ctx, references[0]))
	authToken = mustToken(must(parent.PollExchange(ctx, pending)).Token())
	callAsChild(ctx, output, child, ordersURL, authToken)

	// Scene 3: revoking the parent's binding makes the next authorization
	// fail. Delivered Auth tokens expire normally.
	mustSucceed(federated.RevokeAgentBinding(ctx, personserver.AgentBinding{AgentProvider: agentProviderID, Agent: parentAgentID}))
	_, err := parent.PersonToken(ctx, agent.PersonTokenRequest{PersonServer: personServerID, Resource: ordersID, SubagentToken: childToken})
	var problem *aauth.ProblemError
	check(errors.As(err, &problem) && problem.Code == "person_token_denied", "expected the revoked binding to refuse a Person token")
	fmt.Fprintf(output, "Binding revoked: the Person Server refused the next child Person token (%s)\n", problem.Code)
}

// childOnly answers with the verified principal, and only for credentials
// bound to the sub-agent's key.
func childOnly(childKey jose.SigningKey, scene string) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		principal, ok := resource.AuthPrincipalFromContext(request.Context())
		if !ok || !principal.Confirmation.Equal(childKey.PublicJWK()) {
			http.Error(response, "missing child-bound principal", http.StatusInternalServerError)
			return
		}
		fmt.Fprintf(response, "%s: the sub-agent called %s for %s with %s\n", scene, request.URL.Path, principal.Subject, principal.Scope[0])
	})
}

func knownPerson(_ context.Context, identity resource.PersonIdentity, _ resource.PersonContext) error {
	if identity.Issuer != personServerID || identity.Subject != "person-123" {
		return errors.New("unrecognized person identity")
	}
	return nil
}

func callAsChild(ctx context.Context, output io.Writer, child *agent.Client, target, authToken string) {
	response := must(child.Do(ctx, agent.Call{Request: must(http.NewRequest(http.MethodGet, target, nil)), AuthToken: authToken}))
	defer response.Body.Close()
	check(response.StatusCode == http.StatusOK, "protected call returned "+response.Status)
	_, err := io.Copy(output, response.Body)
	mustSucceed(err)
}

func newSigningKey(id string) jose.SigningKey {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	mustSucceed(err)
	return must(jose.NewEd25519SigningKey(id, privateKey))
}

func must[T any](value T, err error) T {
	mustSucceed(err)
	return value
}

func mustToken(token string, ok bool) string {
	check(ok, "expected an immediate token")
	return token
}

func mustSucceed(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func check(ok bool, message string) {
	if !ok {
		log.Fatal(message)
	}
}

// logicalTransport routes requests to in-process handlers by origin and
// admits discovery only for configured origins.
type logicalTransport struct {
	mu     sync.RWMutex
	routes map[string]http.Handler
}

func newLogicalTransport() *logicalTransport {
	return &logicalTransport{routes: make(map[string]http.Handler)}
}

func (transport *logicalTransport) Handle(origin string, handler http.Handler) {
	transport.mu.Lock()
	defer transport.mu.Unlock()
	transport.routes[origin] = handler
}

func (transport *logicalTransport) Admit(_ context.Context, endpoint string) error {
	request, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	transport.mu.RLock()
	_, ok := transport.routes[request.URL.Scheme+"://"+request.URL.Host]
	transport.mu.RUnlock()
	if !ok {
		return fmt.Errorf("discovery is not admitted for %s", request.URL.Host)
	}
	return nil
}

func (transport *logicalTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	transport.mu.RLock()
	handler := transport.routes[request.URL.Scheme+"://"+request.URL.Host]
	transport.mu.RUnlock()
	if handler == nil {
		return nil, fmt.Errorf("no handler for %s", request.URL.Host)
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	response := recorder.Result()
	response.Request = request
	return response, nil
}
