// The psconsent example runs deferred three-party Person Server consent
// entirely in process. Each protocol role still communicates through HTTP.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"slices"
	"strings"
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
	agentProviderID = "https://agents.example"
	agentID         = "aauth:reader@agents.example"
	personServerID  = "https://person.example"
	resourceID      = "https://resource.example"
	scope           = "records.read"
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
	now := time.Date(2026, 8, 30, 22, 0, 0, 0, time.UTC)
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
		Client: httpClient, Clock: clock, Admit: network.Admit,
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

	personTokens := newMemoryTokenStore()
	authorizations := newMemoryAuthorizationStore()
	issuedIDs := 0
	people, err := personserver.NewPSAuthorization(personserver.PSAuthorizationConfig{
		Issuer: personServerID, SigningKey: personKey, KeyResolver: resolver,
		Clock: clock, Tokens: personTokens,
		NewID: func() string {
			issuedIDs++
			return fmt.Sprintf("person-server-token-%d", issuedIDs)
		},
		BindPerson: func(_ context.Context, request personserver.PersonTokenRequest) (personserver.Person, error) {
			if request.Agent != agentID || request.Resource != resourceID {
				return personserver.Person{}, errors.New("unexpected person-token request")
			}
			return personserver.Person{Subject: "person-123", Lifetime: time.Hour}, nil
		},
		RequireAuthorizationInteraction: func(_ context.Context, request personserver.AuthorizationRequest) (personserver.AuthorizationInteractionPolicy, bool, error) {
			if request.Agent != agentID || request.Resource != resourceID || request.Subject != "person-123" ||
				!slices.Equal(request.Scopes, []string{scope}) ||
				!slices.Equal(request.Capabilities, []string{"interaction", "clarification"}) {
				return personserver.AuthorizationInteractionPolicy{}, false, errors.New("unexpected authorization request")
			}
			return personserver.AuthorizationInteractionPolicy{
				URL: personServerID + "/consent", Lifetime: 5 * time.Minute, RetryAfter: 0,
			}, true, nil
		},
		AuthorizationInteractions: authorizations,
	})
	if err != nil {
		return fmt.Errorf("create Person Server: %w", err)
	}

	protected := http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		principal, ok := resource.AuthPrincipalFromContext(request.Context())
		if !ok || principal.Subject != "person-123" || !slices.Equal(principal.Scope, []string{scope}) {
			http.Error(response, "unexpected AAuth principal", http.StatusInternalServerError)
			return
		}
		fmt.Fprintf(response, "AAuth clarification complete: %s explained the request and has %s\n", principal.Subject, principal.Scope[0])
	})
	protectedResource, err := resource.NewPSAuthorization(resource.PSAuthorizationConfig{
		Issuer: resourceID, SigningKey: resourceKey, KeyResolver: resolver, Clock: clock,
		NewID:             func() string { return "resource-token-1" },
		ScopeDescriptions: map[string]string{scope: "Read records"},
		RequiredScopes:    func(*http.Request) []string { return []string{scope} },
		ResolvePerson: func(_ context.Context, identity resource.PersonIdentity, _ resource.PersonContext) error {
			if identity.Issuer != personServerID || identity.Subject != "person-123" {
				return errors.New("unrecognized person identity")
			}
			return nil
		},
		Protected: protected,
	})
	if err != nil {
		return fmt.Errorf("create Resource: %w", err)
	}
	network.Handle(agentProviderID, provider.Handler())
	network.Handle(personServerID, people.Handler())
	network.Handle(resourceID, protectedResource.Handler())

	reader, err := clientagent.New(ctx, clientagent.Config{
		Identifier: agentID, SigningKey: agentKey, AgentToken: agentToken,
		KeyResolver: resolver, HTTPClient: httpClient, Clock: clock,
	})
	if err != nil {
		return fmt.Errorf("create Agent: %w", err)
	}
	personResult, err := reader.PersonToken(ctx, clientagent.PersonTokenRequest{
		PersonServer: personServerID, Resource: resourceID,
	})
	if err != nil {
		return fmt.Errorf("obtain person token: %w", err)
	}
	personToken, ok := personResult.Token()
	if !ok {
		return errors.New("Person Server unexpectedly deferred the person token")
	}
	resourceToken, err := reader.Authorize(ctx, clientagent.AuthorizeRequest{
		Resource: resourceID, PersonToken: personToken, Scopes: []string{scope},
	})
	if err != nil {
		return fmt.Errorf("obtain resource token: %w", err)
	}
	exchange, err := reader.BeginExchange(ctx, clientagent.ExchangeRequest{
		PersonServer: personServerID, ResourceToken: resourceToken,
		Capabilities: []string{"interaction", "clarification"},
	})
	if err != nil {
		return fmt.Errorf("begin deferred auth-token exchange: %w", err)
	}
	pending, ok := exchange.Pending()
	if !ok || pending.InteractionURL() == "" || pending.InteractionCode() == "" || pending.Location() == "" {
		return errors.New("Person Server did not return a complete pending interaction")
	}

	// An application displays the URL and code, then authenticates the person
	// independently before recording this approval.
	reference := strings.TrimPrefix(pending.InteractionURL(), personServerID+"/consent/")
	if reference == "" || reference == pending.InteractionURL() {
		return errors.New("pending interaction URL did not contain its reference")
	}
	interaction, err := people.ConsumeAuthorizationInteractionCode(ctx, reference, pending.InteractionCode())
	if err != nil {
		return fmt.Errorf("consume interaction code: %w", err)
	}
	if err := people.RequestAuthorizationClarification(ctx, interaction, personserver.AuthorizationClarificationRequest{
		Question: "Why do you need this record?",
		Options:  []string{"Complete the requested analysis", "Cancel"},
		Lifetime: 2 * time.Minute,
	}); err != nil {
		return fmt.Errorf("request clarification: %w", err)
	}
	clarificationResult, err := reader.PollExchange(ctx, pending)
	if err != nil {
		return fmt.Errorf("poll clarification: %w", err)
	}
	clarifying, ok := clarificationResult.Pending()
	if !ok {
		return errors.New("Person Server did not return a pending clarification")
	}
	question, ok := clarifying.Clarification()
	if !ok || question.Question() != "Why do you need this record?" ||
		!slices.Equal(question.Options(), []string{"Complete the requested analysis", "Cancel"}) {
		return errors.New("Person Server returned an unexpected clarification")
	}

	// An Agent process can persist this credential-bearing continuation and
	// later restore it under the same verified identity and key.
	snapshot, err := clarifying.Snapshot()
	if err != nil {
		return fmt.Errorf("snapshot clarification: %w", err)
	}
	encodedSnapshot, err := json.Marshal(snapshot)
	if err != nil {
		return fmt.Errorf("encode clarification snapshot: %w", err)
	}
	clarifying = clientagent.PendingExchange{}
	var persisted clientagent.PendingExchangeSnapshot
	if err := json.Unmarshal(encodedSnapshot, &persisted); err != nil {
		return fmt.Errorf("decode clarification snapshot: %w", err)
	}
	restoredReader, err := clientagent.New(ctx, clientagent.Config{
		Identifier: agentID, SigningKey: agentKey, AgentToken: agentToken,
		KeyResolver: resolver, HTTPClient: httpClient, Clock: clock,
	})
	if err != nil {
		return fmt.Errorf("recreate Agent: %w", err)
	}
	restored, err := restoredReader.RestorePendingExchange(ctx, persisted)
	if err != nil {
		return fmt.Errorf("restore clarification: %w", err)
	}
	if err := restoredReader.AnswerClarification(ctx, restored, "The person asked me to include it in the analysis."); err != nil {
		return fmt.Errorf("answer clarification: %w", err)
	}
	resumed, err := people.ResumeAuthorizationInteraction(ctx, reference)
	if err != nil {
		return fmt.Errorf("resume clarified authorization: %w", err)
	}
	rounds := resumed.Clarifications()
	if len(rounds) != 1 || rounds[0].Response != "The person asked me to include it in the analysis." {
		return errors.New("Person Server did not retain the clarification answer")
	}
	if err := people.ApproveAuthorizationInteraction(ctx, resumed, personserver.AuthorizationDecision{
		Scopes: []string{scope}, Lifetime: 30 * time.Minute,
	}); err != nil {
		return fmt.Errorf("approve authorization: %w", err)
	}

	completion, err := restoredReader.PollExchange(ctx, restored)
	if err != nil {
		return fmt.Errorf("poll deferred auth-token exchange: %w", err)
	}
	authToken, ok := completion.Token()
	if !ok {
		return errors.New("approved exchange did not return an auth token")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, resourceID+"/records/42", nil)
	if err != nil {
		return err
	}
	response, err := restoredReader.Do(ctx, clientagent.Call{Request: request, AuthToken: authToken})
	if err != nil {
		return fmt.Errorf("call protected Resource: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("protected Resource returned %s", response.Status)
	}
	if _, err := io.Copy(output, response.Body); err != nil {
		return fmt.Errorf("write result: %w", err)
	}
	return nil
}

func newSigningKey(id string) (jose.SigningKey, error) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return jose.SigningKey{}, err
	}
	return jose.NewEd25519SigningKey(id, privateKey)
}
