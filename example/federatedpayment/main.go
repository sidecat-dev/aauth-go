// The federatedpayment example drives AS payment, approval and token delivery
// through in-process HTTP. Payment settlement is simulated host state: no money
// moves and no payment provider is contacted.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
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

func main() { run(os.Stdout) }
func run(output io.Writer) {
	ctx := context.Background()
	clock := aauth.ClockFunc(func() time.Time { return time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC) })
	apKey, agentKey, psKey, asKey, resourceKey := key("ap"), key("agent"), key("ps"), key("as"), key("resource")
	network := localTransport{}
	client := &http.Client{Transport: network}
	resolver := must(signaturekey.NewHTTPKeyResolver(signaturekey.HTTPKeyResolverConfig{Client: client, Clock: clock, Admit: func(_ context.Context, endpoint string) error {
		request, err := http.NewRequest("GET", endpoint, nil)
		if err != nil {
			return err
		}
		if network[request.URL.Scheme+"://"+request.URL.Host] == nil {
			return fmt.Errorf("unconfigured discovery host")
		}
		return nil
	}}))
	var ids atomic.Uint64
	newID := func() string { return fmt.Sprintf("example-%d", ids.Add(1)) }
	provider := must(agentprovider.New(agentprovider.Config{Issuer: "https://ap.example", SigningKey: apKey, Clock: clock, NewID: newID}))
	token := must(provider.Issue(aauth.AgentTokenRequest{Agent: "aauth:reader@ap.example", PersonServer: "https://ps.example", PublicKey: agentKey.PublicJWK(), Lifetime: time.Hour}))
	network["https://ap.example"] = provider.Handler()
	var settled, approved atomic.Bool
	access := must(accessserver.New(accessserver.Config{
		Issuer: "https://as.example", SigningKey: asKey, KeyResolver: resolver, Clock: clock, NewID: newID,
		Deferred: &accessserver.DeferredConfig{Store: testutil.NewAccessAuthorizationStore(), Lifetime: time.Minute},
		TrustPersonServer: func(_ context.Context, ps string) error {
			if ps != "https://ps.example" {
				return accessserver.ErrAccessDenied
			}
			return nil
		},
		Authorize: func(_ context.Context, request accessserver.AuthorizationRequest) (accessserver.Decision, error) {
			if !settled.Load() {
				return accessserver.Decision{Pending: &accessserver.PendingDecision{Payment: &accessserver.PaymentChallenge{Authenticate: `Payment id="example-billing", method="example"`}}}, nil
			}
			if !approved.Load() {
				return accessserver.Decision{Pending: &accessserver.PendingDecision{}}, nil
			}
			return accessserver.Decision{Scopes: request.Scopes, Lifetime: time.Minute}, nil
		},
	}))
	network["https://as.example"] = access.Handler()
	people := must(personserver.NewFederatedAuthorization(personserver.FederatedAuthorizationConfig{
		Issuer: "https://ps.example", SigningKey: psKey, KeyResolver: resolver, Clock: clock, NewID: newID, HTTPClient: client, Tokens: testutil.NewMissionStore(),
		Deferred: &personserver.FederatedDeferredConfig{Store: testutil.NewFederatedAuthorizationStore(), Lifetime: time.Minute},
		AccessServerEndpoint: func(_ context.Context, as string) (string, error) {
			if as != "https://as.example" {
				return "", fmt.Errorf("unconfigured AS")
			}
			return as + "/token", nil
		},
		BindPerson: func(context.Context, personserver.PersonTokenRequest) (personserver.Person, error) {
			return personserver.Person{Subject: "example-person", Lifetime: time.Minute}, nil
		},
		Consent: func(context.Context, personserver.AuthorizationRequest) error { return nil },
	}))
	network["https://ps.example"] = people.Handler()
	protected := must(resource.NewFederatedAuthorization(resource.FederatedAuthorizationConfig{
		Issuer: "https://resource.example", AccessServer: "https://as.example", SigningKey: resourceKey, KeyResolver: resolver, Clock: clock, NewID: newID,
		ScopeDescriptions: map[string]string{"records.read": "Read records"}, RequiredScopes: func(*http.Request) []string { return []string{"records.read"} },
		ResolvePerson: func(_ context.Context, identity resource.PersonIdentity, _ resource.PersonContext) error {
			if identity.Issuer != "https://ps.example" || identity.Subject != "example-person" {
				return fmt.Errorf("unrecognized person")
			}
			return nil
		},
		Protected: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			principal, ok := resource.AuthPrincipalFromContext(r.Context())
			if !ok {
				http.Error(w, "missing principal", 500)
				return
			}
			fmt.Fprintf(w, "Approved: %s\n", strings.Join(principal.Scope, " "))
		}),
	}))
	network["https://resource.example"] = protected.Handler()
	reader := must(agent.New(ctx, agent.Config{Identifier: "aauth:reader@ap.example", AgentToken: token, SigningKey: agentKey, Clock: clock, KeyResolver: resolver, HTTPClient: client}))
	personResult := must(reader.PersonToken(ctx, agent.PersonTokenRequest{PersonServer: "https://ps.example", Resource: "https://resource.example"}))
	person, ok := personResult.Token()
	check(ok, "expected Person token")
	request := must(http.NewRequest("GET", "https://resource.example/records", nil))
	initial := must(reader.Begin(ctx, agent.InitialCall{Request: request, PersonToken: person}))
	required, ok := initial.AuthorizationRequired()
	check(ok, "expected Resource token")
	result := must(reader.BeginExchange(ctx, agent.ExchangeRequest{PersonServer: "https://ps.example", ResourceToken: required.ResourceToken, PresentedToken: person}))
	pending, ok := result.Pending()
	check(ok, "expected PS pending response")
	check(pending.WaitReason() == "awaiting_payment", "expected payment hint")
	// Hosts discover their own queue; no Agent callback or store hook is needed.
	references := must(people.PendingFederatedAuthorizationReferences(ctx, 10))
	check(len(references) == 1, "expected one pending continuation")
	reference := references[0]
	host := must(people.FederatedAuthorization(ctx, reference))
	check(host.Response.Status == 402, "expected AS payment challenge")
	fmt.Fprintln(output, "Payment required at Access Server")
	// A real host authenticates its operator, settles through the indicated
	// payment protocol, and retains the billing relationship per AS. Here the
	// corresponding AS host state is changed directly for the demonstration.
	settled.Store(true)
	mustSucceed(people.AdvanceFederation(ctx, reference))
	host = must(people.FederatedAuthorization(ctx, reference))
	check(host.Response.Status == 202, "expected approval wait")
	result = must(reader.PollExchange(ctx, pending))
	pending, ok = result.Pending()
	check(ok && pending.WaitReason() == "awaiting_approval", "expected approval hint")
	fmt.Fprintln(output, "Payment confirmed; approval pending")
	approved.Store(true)
	mustSucceed(people.AdvanceFederation(ctx, reference))
	result = must(reader.PollExchange(ctx, pending))
	auth, ok := result.Token()
	check(ok, "expected verified Auth token")
	response := must(reader.Do(ctx, agent.Call{Request: request, AuthToken: auth}))
	defer response.Body.Close()
	check(response.StatusCode == 200, "protected Resource refused grant")
	_, err := io.Copy(output, response.Body)
	mustSucceed(err)
}

func key(id string) jose.SigningKey {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	mustSucceed(err)
	return must(jose.NewEd25519SigningKey(id, private))
}
func must[T any](value T, err error) T { mustSucceed(err); return value }
func mustSucceed(err error) {
	if err != nil {
		panic(err)
	}
}
func check(ok bool, message string) {
	if !ok {
		panic(message)
	}
}

type localTransport map[string]http.Handler

func (t localTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	handler := t[request.URL.Scheme+"://"+request.URL.Host]
	if handler == nil {
		return nil, fmt.Errorf("unconfigured host")
	}
	if request.Body != nil {
		defer request.Body.Close()
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	response := recorder.Result()
	response.Request = request
	return response, nil
}
