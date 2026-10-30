package integration_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	clientagent "gitlab.com/sidecat-dev/aauth-go/agent"
	"gitlab.com/sidecat-dev/aauth-go/agentprovider"
	"gitlab.com/sidecat-dev/aauth-go/internal/exampleutil"
	"gitlab.com/sidecat-dev/aauth-go/personserver"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

func TestCurrentCoreMissionlessPermissionAcrossPersonServerRecomposition(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	now := time.Date(2026, 8, 31, 23, 30, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	const (
		agentProviderID = "https://ap.example"
		agentID         = "aauth:operator@ap.example"
		personServerID  = "https://ps.example"
		resourceID      = "https://resource.example"
		accessServerID  = "https://as.example"
	)
	agentProviderKey := newSigningKey(t, "permission-journey-ap")
	agentKey := newSigningKey(t, "permission-journey-agent")
	personServerKey := newSigningKey(t, "permission-journey-ps")

	network := newLogicalTransport()
	httpClient := &http.Client{Transport: network}
	resolver, err := signaturekey.NewHTTPKeyResolver(signaturekey.HTTPKeyResolverConfig{
		Client: httpClient, TransportEnforcesEgress: true,
		Clock: clock,
		Admit: func(_ context.Context, endpoint string) error {
			if strings.HasSuffix(endpoint, ".example/.well-known/aauth-agent.json") ||
				strings.HasSuffix(endpoint, ".example/.well-known/aauth-person.json") ||
				strings.HasSuffix(endpoint, ".example/.well-known/jwks.json") {
				return nil
			}
			return errors.New("unexpected discovery endpoint: " + endpoint)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	provider, err := agentprovider.New(agentprovider.Config{
		Issuer: agentProviderID, SigningKey: agentProviderKey, Clock: clock,
		NewID: func() string { return "permission-agent-token" },
	})
	if err != nil {
		t.Fatal(err)
	}
	agentToken, err := provider.Issue(aauth.AgentTokenRequest{
		Agent: agentID, PersonServer: personServerID,
		PublicKey: agentKey.PublicJWK(), Lifetime: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}

	permissions := exampleutil.NewPermissionStore()
	policyCalls := 0
	newPeople := func() *personserver.Server {
		people, err := personserver.NewPSAuthorization(personserver.PSAuthorizationConfig{
			Issuer: personServerID, SigningKey: personServerKey, KeyResolver: resolver,
			Clock: clock, NewID: func() string { return "unused-person-token" },
			Tokens: newMemoryPersonTokenStore(),
			BindPerson: func(context.Context, personserver.PersonTokenRequest) (personserver.Person, error) {
				return personserver.Person{Subject: "person", Lifetime: time.Minute}, nil
			},
			Authorize: func(context.Context, personserver.AuthorizationRequest) (personserver.AuthorizationDecision, error) {
				return personserver.AuthorizationDecision{Scopes: []string{"unused"}, Lifetime: time.Minute}, nil
			},
			Permission: &personserver.PermissionConfig{
				Store: permissions,
				Policy: func(_ context.Context, request personserver.PermissionPolicyRequest) (personserver.PermissionPolicyResult, error) {
					policyCalls++
					if request.AgentProvider != agentProviderID || request.Agent != agentID ||
						(request.Action != "messages.send" && request.Action != "files.delete") {
						return personserver.PermissionPolicyResult{}, errors.New("unexpected permission request")
					}
					return personserver.PermissionPolicyResult{Deferred: &personserver.PermissionPendingPolicy{
						Lifetime: 5 * time.Minute, RetryAfter: 0,
					}}, nil
				},
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		return people
	}

	permissionPosts := 0
	permissionPolls := 0
	people := newPeople()
	servePeople := func(server *personserver.Server) {
		network.Handle(personServerID, http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			switch {
			case request.Method == http.MethodPost && request.URL.Path == "/permission":
				permissionPosts++
			case request.Method == http.MethodGet && strings.HasPrefix(request.URL.Path, "/permission/pending/"):
				permissionPolls++
			}
			server.Handler().ServeHTTP(response, request)
		}))
	}
	resourceCalls := 0
	accessServerCalls := 0
	network.Handle(agentProviderID, provider.Handler())
	servePeople(people)
	network.Handle(resourceID, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { resourceCalls++ }))
	network.Handle(accessServerID, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { accessServerCalls++ }))

	operator, err := clientagent.New(ctx, clientagent.Config{
		Identifier: agentID, SigningKey: agentKey, AgentToken: agentToken,
		KeyResolver: resolver, HTTPClient: httpClient, Clock: clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	grantParameters := json.RawMessage(`{"channel":"ops","body":"ready"}`)
	grantResult, err := operator.RequestPermission(ctx, clientagent.PermissionRequest{
		PersonServer: personServerID, Action: "messages.send",
		Description: "Send the prepared status message.", Parameters: grantParameters,
	})
	if err != nil {
		t.Fatal(err)
	}
	grantPending, ok := grantResult.Pending()
	if !ok || grantPending.RetryAfter() != 0 {
		t.Fatalf("grant pending = %#v, present=%t", grantPending, ok)
	}
	if permissionPosts != 1 || permissionPolls != 0 || policyCalls != 1 || resourceCalls != 0 || accessServerCalls != 0 {
		t.Fatalf("initial effects: posts=%d polls=%d policy=%d Resource=%d AS=%d",
			permissionPosts, permissionPolls, policyCalls, resourceCalls, accessServerCalls)
	}

	// The Person Server can be recomposed around the retained store before the
	// host independently authenticates the person and records the decision.
	people = newPeople()
	servePeople(people)
	grantReference := strings.TrimPrefix(grantPending.Location(), personServerID+"/permission/pending/")
	grantRequest, err := people.ResumePermission(ctx, grantReference)
	if err != nil {
		t.Fatal(err)
	}
	if grantRequest.AgentProvider() != agentProviderID || grantRequest.Agent() != agentID ||
		grantRequest.Action() != "messages.send" || grantRequest.Description() != "Send the prepared status message." ||
		!bytes.Equal(grantRequest.Parameters(), grantParameters) {
		t.Fatalf("resumed grant request = agent provider %q, agent %q, action %q, description %q, parameters %s",
			grantRequest.AgentProvider(), grantRequest.Agent(), grantRequest.Action(), grantRequest.Description(), grantRequest.Parameters())
	}
	mutated := grantRequest.Parameters()
	mutated[0] = '['
	if bytes.Equal(grantRequest.Parameters(), mutated) {
		t.Fatal("permission host handle aliased returned parameters")
	}
	if err := people.GrantPermission(ctx, grantRequest); err != nil {
		t.Fatal(err)
	}

	people = newPeople()
	servePeople(people)
	grantCompletion, err := operator.PollPermission(ctx, grantPending)
	if err != nil {
		t.Fatal(err)
	}
	grantDecision, ok := grantCompletion.Decision()
	if !ok || grantDecision.Permission() != aauth.PermissionGranted || grantDecision.Reason() != "" {
		t.Fatalf("grant decision = %#v, present=%t", grantDecision, ok)
	}
	applicationCalls := 0
	if grantDecision.Permission() == aauth.PermissionGranted {
		applicationCalls++
	}
	if applicationCalls != 1 {
		t.Fatalf("application calls after grant = %d", applicationCalls)
	}
	if _, err := operator.PollPermission(ctx, grantPending); err == nil {
		t.Fatal("consumed permission result was replayed")
	} else {
		var problem *aauth.ProblemError
		if !errors.As(err, &problem) || problem.Status != http.StatusGone || problem.Code != "invalid_code" {
			t.Fatalf("second grant poll = %T %v", err, err)
		}
	}

	denyResult, err := operator.RequestPermission(ctx, clientagent.PermissionRequest{
		PersonServer: personServerID, Action: "files.delete",
		Description: "Delete the retained draft.", Parameters: json.RawMessage(`{"path":"draft.md"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	denyPending, ok := denyResult.Pending()
	if !ok {
		t.Fatal("denial request did not defer")
	}
	denyReference := strings.TrimPrefix(denyPending.Location(), personServerID+"/permission/pending/")
	denyRequest, err := people.ResumePermission(ctx, denyReference)
	if err != nil {
		t.Fatal(err)
	}
	if err := people.DenyPermission(ctx, denyRequest, "The retained draft must remain available."); err != nil {
		t.Fatal(err)
	}
	denyCompletion, err := operator.PollPermission(ctx, denyPending)
	if err != nil {
		t.Fatal(err)
	}
	denyDecision, ok := denyCompletion.Decision()
	if !ok || denyDecision.Permission() != aauth.PermissionDenied ||
		denyDecision.Reason() != "The retained draft must remain available." {
		t.Fatalf("denial decision = %#v, present=%t", denyDecision, ok)
	}
	if applicationCalls != 1 || permissionPosts != 2 || permissionPolls != 3 || policyCalls != 2 ||
		resourceCalls != 0 || accessServerCalls != 0 {
		t.Fatalf("final effects: application=%d posts=%d polls=%d policy=%d Resource=%d AS=%d",
			applicationCalls, permissionPosts, permissionPolls, policyCalls, resourceCalls, accessServerCalls)
	}
}
