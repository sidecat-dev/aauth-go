// The revocation example runs issuer-driven Agent- and Auth-token revocation,
// caller-controlled retry, and explicit re-authorization in process.
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
	"os"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	clientagent "gitlab.com/sidecat-dev/aauth-go/agent"
	"gitlab.com/sidecat-dev/aauth-go/agentprovider"
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/personserver"
	"gitlab.com/sidecat-dev/aauth-go/resource"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

const (
	agentProviderID  = "https://agents.example"
	agentID          = "aauth:reader@agents.example"
	personServerID   = "https://person.example"
	resourceID       = "https://resource.example"
	directResourceID = "https://direct-resource.example"
	scope            = "records.read"
)

func main() {
	if err := run(os.Stdout); err != nil {
		log.Fatal(err)
	}
}

func run(output io.Writer) error {
	ctx := context.Background()
	now := time.Date(2026, 8, 30, 22, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	providerKey := newSigningKey("agent-provider-key")
	agentKey := newSigningKey("agent-key")
	personKey := newSigningKey("person-server-key")
	resourceKey := newSigningKey("resource-key")
	network := newLogicalTransport()
	lostResponse := errors.New("revocation response lost after delivery")
	transport := &loseOneRevocationResponseTransport{base: network, failure: lostResponse}
	httpClient := &http.Client{Transport: transport}
	resolver, err := signaturekey.NewHTTPKeyResolver(signaturekey.HTTPKeyResolverConfig{
		Client: httpClient, Clock: clock, Admit: network.Admit,
	})
	if err != nil {
		return err
	}
	provider, err := agentprovider.New(agentprovider.Config{
		Issuer: agentProviderID, SigningKey: providerKey, Clock: clock,
		NewID: func() string { return "agent-token-1" },
	})
	if err != nil {
		return err
	}
	agentToken, err := provider.Issue(aauth.AgentTokenRequest{
		Agent: agentID, PersonServer: personServerID,
		PublicKey: agentKey.PublicJWK(), Lifetime: time.Hour,
	})
	if err != nil {
		return err
	}
	personTokens := newPersonTokenStore()
	issuedTokens := newIssuedAuthTokenStore()
	personAgentRevocations := newAgentTokenRevocationStore()
	resourceAgentRevocations := newAgentTokenRevocationStore()
	personIDs := []string{"person-token-1", "auth-token-1", "auth-token-2"}
	newPersonServer := func() (*personserver.Server, error) {
		return personserver.NewPSAuthorization(personserver.PSAuthorizationConfig{
			Issuer: personServerID, SigningKey: personKey, KeyResolver: resolver, Clock: clock,
			Tokens: personTokens,
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
			Authorize: func(_ context.Context, request personserver.AuthorizationRequest) (personserver.AuthorizationDecision, error) {
				return personserver.AuthorizationDecision{Scopes: request.Scopes, Lifetime: 30 * time.Minute}, nil
			},
			Revocation: &personserver.AuthTokenRevocationConfig{
				IssuedTokens: issuedTokens, HTTPClient: httpClient, Admit: network.Admit,
			},
			AgentTokenRevocations: personAgentRevocations,
		})
	}
	people, err := newPersonServer()
	if err != nil {
		return err
	}
	statuses := newAuthTokenStatusStore()
	resourceIDs := []string{"resource-token-1", "resource-token-2"}
	newResource := func() (*resource.Server, error) {
		return resource.NewPSAuthorization(resource.PSAuthorizationConfig{
			Issuer: resourceID, SigningKey: resourceKey, KeyResolver: resolver, Clock: clock,
			NewID: func() string {
				id := resourceIDs[0]
				resourceIDs = resourceIDs[1:]
				return id
			},
			ScopeDescriptions: map[string]string{scope: "Read records"},
			RequiredScopes:    func(*http.Request) []string { return []string{scope} },
			ResolvePerson: func(_ context.Context, identity resource.PersonIdentity, _ resource.PersonContext) error {
				if identity.Issuer != personServerID || identity.Subject == "" {
					return errors.New("unrecognized person identity")
				}
				return nil
			},
			Protected: http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
				response.WriteHeader(http.StatusNoContent)
			}),
			AuthTokenStatuses: statuses,
		})
	}
	protectedResource, err := newResource()
	if err != nil {
		return err
	}
	directCalls := 0
	newDirectResource := func() (*resource.Server, error) {
		return resource.NewAgentIdentity(resource.AgentIdentityConfig{
			Issuer: directResourceID, KeyResolver: resolver, Clock: clock,
			AgentTokenRevocations: resourceAgentRevocations,
			Protected: http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
				directCalls++
				response.WriteHeader(http.StatusNoContent)
			}),
		})
	}
	directResource, err := newDirectResource()
	if err != nil {
		return err
	}
	network.Handle(agentProviderID, provider.Handler())
	network.Handle(personServerID, people.Handler())
	network.Handle(resourceID, protectedResource.Handler())
	network.Handle(directResourceID, directResource.Handler())
	reader, err := clientagent.New(ctx, clientagent.Config{
		Identifier: agentID, SigningKey: agentKey, AgentToken: agentToken,
		KeyResolver: resolver, HTTPClient: httpClient, Clock: clock,
	})
	if err != nil {
		return err
	}
	directRequest, _ := http.NewRequestWithContext(ctx, http.MethodGet, directResourceID+"/status", nil)
	directResponse, err := reader.CallAsAgent(ctx, directRequest)
	if err != nil {
		return err
	}
	directResponse.Body.Close()
	if directResponse.StatusCode != http.StatusNoContent || directCalls != 1 {
		return fmt.Errorf("direct Agent call returned %s", directResponse.Status)
	}
	personResult, err := reader.PersonToken(ctx, clientagent.PersonTokenRequest{
		PersonServer: personServerID, Resource: resourceID,
	})
	if err != nil {
		return err
	}
	personToken, ok := personResult.Token()
	if !ok {
		return errors.New("Person Server unexpectedly required interaction")
	}
	authorize := func() (string, aauth.AuthTokenClaims, error) {
		resourceToken, err := reader.Authorize(ctx, clientagent.AuthorizeRequest{
			Resource: resourceID, PersonToken: personToken, Scopes: []string{scope},
		})
		if err != nil {
			return "", aauth.AuthTokenClaims{}, err
		}
		authToken, err := reader.Exchange(ctx, clientagent.ExchangeRequest{
			PersonServer: personServerID, ResourceToken: resourceToken,
		})
		if err != nil {
			return "", aauth.AuthTokenClaims{}, err
		}
		claims, err := aauth.VerifyAuthToken(ctx, authToken, resolver, clock)
		return authToken, claims, err
	}
	use := func(authToken string) error {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, resourceID+"/records/42", nil)
		if err != nil {
			return err
		}
		response, err := reader.Do(ctx, clientagent.Call{Request: request, AuthToken: authToken})
		if err != nil {
			return err
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusNoContent {
			return fmt.Errorf("protected call returned %s", response.Status)
		}
		return nil
	}
	firstToken, firstClaims, err := authorize()
	if err != nil {
		return err
	}
	if err := use(firstToken); err != nil {
		return err
	}
	fmt.Fprintf(output, "%s accepted\n", firstClaims.JTI)

	people, err = newPersonServer()
	if err != nil {
		return err
	}
	network.Handle(personServerID, people.Handler())
	reference := aauth.TokenReference{Issuer: firstClaims.Issuer, JTI: firstClaims.JTI}
	transport.Arm()
	if err := people.RevokeIssuedAuthToken(ctx, reference); !errors.Is(err, lostResponse) {
		return fmt.Errorf("expected lost revocation response, got %w", err)
	}
	protectedResource, err = newResource()
	if err != nil {
		return err
	}
	network.Handle(resourceID, protectedResource.Handler())
	now = now.Add(time.Second)
	if err := people.RevokeIssuedAuthToken(ctx, reference); err != nil {
		return err
	}
	fmt.Fprintf(output, "%s revocation response lost; explicit retry succeeded after Resource recomposition\n", firstClaims.JTI)

	request, _ := http.NewRequestWithContext(ctx, http.MethodGet, resourceID+"/records/42", nil)
	response, err := reader.Do(ctx, clientagent.Call{Request: request, AuthToken: firstToken})
	if response != nil {
		response.Body.Close()
	}
	var problem *aauth.ProblemError
	if !errors.As(err, &problem) || problem.Status != http.StatusForbidden || problem.Code != "access_denied" {
		return fmt.Errorf("revoked token returned %v", err)
	}
	fmt.Fprintf(output, "%s refused: %d %s\n", firstClaims.JTI, problem.Status, problem.Code)

	secondToken, secondClaims, err := authorize()
	if err != nil {
		return err
	}
	if err := use(secondToken); err != nil {
		return err
	}
	fmt.Fprintf(output, "%s accepted after explicit re-authorization\n", secondClaims.JTI)

	agentClaims, err := aauth.VerifyAgentToken(ctx, agentToken, resolver, clock)
	if err != nil {
		return err
	}
	revoker, err := agentprovider.NewRevocationClient(agentprovider.RevocationClientConfig{
		Provider: provider, HTTPClient: httpClient, Admit: network.Admit,
	})
	if err != nil {
		return err
	}
	agentReference := aauth.TokenReference{Issuer: agentClaims.Issuer, JTI: agentClaims.JTI}
	if err := revoker.RevokeAgentToken(ctx, personServerID, agentReference); err != nil {
		return err
	}
	if err := revoker.RevokeAgentToken(ctx, personServerID, agentReference); err != nil {
		return err
	}
	if err := revoker.RevokeAgentTokenAtResource(ctx, directResourceID, agentReference); err != nil {
		return err
	}
	if err := revoker.RevokeAgentTokenAtResource(ctx, directResourceID, agentReference); err != nil {
		return err
	}
	people, err = newPersonServer()
	if err != nil {
		return err
	}
	network.Handle(personServerID, people.Handler())
	directResource, err = newDirectResource()
	if err != nil {
		return err
	}
	network.Handle(directResourceID, directResource.Handler())
	_, err = reader.PersonToken(ctx, clientagent.PersonTokenRequest{
		PersonServer: personServerID, Resource: resourceID,
	})
	if !errors.As(err, &problem) || problem.Code != "invalid_agent_token" {
		return fmt.Errorf("revoked Agent token returned %v", err)
	}
	directRequest, _ = http.NewRequestWithContext(ctx, http.MethodGet, directResourceID+"/status", nil)
	directResponse, err = reader.CallAsAgent(ctx, directRequest)
	if directResponse != nil {
		directResponse.Body.Close()
	}
	if err == nil || directCalls != 1 {
		return fmt.Errorf("revoked Agent token direct call returned response %v, error %v", directResponse, err)
	}
	fmt.Fprintf(output, "%s Agent token revoked at Person Server and direct Resource; exact replays succeeded; later requests refused\n", agentClaims.JTI)
	return nil
}

func newSigningKey(id string) jose.SigningKey {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	key, err := jose.NewEd25519SigningKey(id, privateKey)
	if err != nil {
		log.Fatal(err)
	}
	return key
}
