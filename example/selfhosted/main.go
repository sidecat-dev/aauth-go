// The self-hosted example publishes ordinary Agent Provider metadata and JWKS,
// self-issues a short-lived Agent token, obtains one local-action permission
// from the token's Person Server, and uses the same key for one signed Resource
// call. It then self-issues a second token naming a hosted Person Server and
// completes one hosted three-party Resource call. Bootstrap defines no
// separate refresh ceremony for this profile; the Agent self-issues another
// token when needed.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	clientagent "gitlab.com/sidecat-dev/aauth-go/agent"
	"gitlab.com/sidecat-dev/aauth-go/agentprovider"
	"gitlab.com/sidecat-dev/aauth-go/internal/exampleutil"
	"gitlab.com/sidecat-dev/aauth-go/personserver"
	"gitlab.com/sidecat-dev/aauth-go/resource"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

const (
	agentOrigin    = "https://agent.example"
	agentID        = "aauth:local@agent.example"
	personServerID = "https://person.example"
	resourceID     = "https://resource.example"
	hostedPersonID = "https://account.example"
	hostedResource = "https://service.example"
	hostedScope    = "records.read"
)

func main() {
	if err := run(os.Stdout); err != nil {
		log.Fatal(err)
	}
}

func run(output io.Writer) error {
	if output == nil {
		return errors.New("output is required")
	}
	ctx := context.Background()
	now := time.Date(2026, 8, 31, 9, 15, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	key, err := newSigningKey("self-hosted-key")
	if err != nil {
		return err
	}
	personKey, err := newSigningKey("local-person-server-key")
	if err != nil {
		return err
	}
	hostedPersonKey, err := newSigningKey("hosted-person-server-key")
	if err != nil {
		return err
	}
	hostedResourceKey, err := newSigningKey("hosted-resource-key")
	if err != nil {
		return err
	}
	agentTokenIDs := []string{"local-agent-token", "hosted-agent-token"}
	selfHosted, err := agentprovider.NewSelfHostedAgent(agentprovider.SelfHostedAgentConfig{
		Issuer: agentOrigin, Agent: agentID, SigningKey: key, Clock: clock,
		NewID: func() string {
			id := agentTokenIDs[0]
			agentTokenIDs = agentTokenIDs[1:]
			return id
		},
	})
	if err != nil {
		return err
	}
	network := newLogicalTransport()
	network.Handle(agentOrigin, selfHosted.Handler())
	httpClient := &http.Client{Transport: network}
	resolver, err := signaturekey.NewHTTPKeyResolver(signaturekey.HTTPKeyResolverConfig{
		Client: httpClient, Clock: clock, Admit: network.Admit,
	})
	if err != nil {
		return err
	}
	compact, err := selfHosted.Issue(agentprovider.SelfHostedAgentTokenRequest{
		PersonServer: personServerID, Lifetime: time.Hour,
	})
	if err != nil {
		return err
	}
	localStore := exampleutil.NewMissionPermissionStore()
	people, err := personserver.NewPSAuthorization(personserver.PSAuthorizationConfig{
		Issuer: personServerID, SigningKey: personKey, KeyResolver: resolver, Clock: clock,
		NewID: func() string { return "unused-local-token" }, Tokens: localStore,
		BindPerson: func(context.Context, personserver.PersonTokenRequest) (personserver.Person, error) {
			return personserver.Person{Subject: "local-person", Lifetime: time.Minute}, nil
		},
		Authorize: func(context.Context, personserver.AuthorizationRequest) (personserver.AuthorizationDecision, error) {
			return personserver.AuthorizationDecision{Scopes: []string{"unused"}, Lifetime: time.Minute}, nil
		},
		Permission: &personserver.PermissionConfig{
			Store: localStore,
			Policy: func(_ context.Context, request personserver.PermissionPolicyRequest) (personserver.PermissionPolicyResult, error) {
				if request.Agent != agentID || request.Mission != nil || request.Action != "workspace.inspect" {
					return personserver.PermissionPolicyResult{}, errors.New("self-hosted example: unexpected local permission")
				}
				return personserver.PermissionPolicyResult{Immediate: &personserver.PermissionDecision{
					Permission: aauth.PermissionGranted,
				}}, nil
			},
		},
	})
	if err != nil {
		return err
	}
	network.Handle(personServerID, people.Handler())
	protected, err := resource.NewAgentIdentity(resource.AgentIdentityConfig{
		Issuer: resourceID, KeyResolver: resolver, Clock: clock,
		Protected: http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			principal, ok := resource.AgentPrincipalFromContext(request.Context())
			if !ok {
				http.Error(response, "missing Agent principal", http.StatusInternalServerError)
				return
			}
			_, _ = io.WriteString(response, principal.Agent)
		}),
	})
	if err != nil {
		return err
	}
	network.Handle(resourceID, protected.Handler())
	client, err := clientagent.New(ctx, clientagent.Config{
		Identifier: agentID, SigningKey: key, AgentToken: compact,
		KeyResolver: resolver, HTTPClient: httpClient, Clock: clock,
	})
	if err != nil {
		return err
	}
	permission, err := client.RequestPermission(ctx, clientagent.PermissionRequest{
		PersonServer: personServerID, Action: "workspace.inspect",
		Description: "Inspect the local workspace without changing it.",
	})
	if err != nil {
		return err
	}
	decision, ok := permission.Decision()
	if !ok || decision.Permission() != aauth.PermissionGranted {
		return errors.New("self-hosted example: local permission was not granted")
	}
	if _, err := fmt.Fprintln(output, "AAuth local permission granted: workspace.inspect"); err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, resourceID+"/records", nil)
	if err != nil {
		return err
	}
	response, err := client.CallAsAgent(ctx, request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return err
	}
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("Resource returned %s: %s", response.Status, body)
	}
	if _, err = fmt.Fprintf(output, "AAuth self-hosted Agent accepted: %s\n", body); err != nil {
		return err
	}

	hostedPeople, hostedService, err := hostedHandlers(resolver, clock, hostedPersonKey, hostedResourceKey)
	if err != nil {
		return err
	}
	network.Handle(hostedPersonID, hostedPeople)
	network.Handle(hostedResource, hostedService)
	hostedToken, err := selfHosted.Issue(agentprovider.SelfHostedAgentTokenRequest{
		PersonServer: hostedPersonID, Lifetime: time.Hour,
	})
	if err != nil {
		return err
	}
	hostedClient, err := clientagent.New(ctx, clientagent.Config{
		Identifier: agentID, SigningKey: key, AgentToken: hostedToken,
		KeyResolver: resolver, HTTPClient: httpClient, Clock: clock,
	})
	if err != nil {
		return err
	}
	return callHostedResource(ctx, output, hostedClient)
}
