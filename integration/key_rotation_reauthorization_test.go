package integration_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	clientagent "gitlab.com/sidecat-dev/aauth-go/agent"
	"gitlab.com/sidecat-dev/aauth-go/agentprovider"
	"gitlab.com/sidecat-dev/aauth-go/personserver"
	"gitlab.com/sidecat-dev/aauth-go/resource"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

// Core Re-authorization: when an agent rotates its signing key, every auth
// token bound to the old key stops working, and the agent re-authorizes by
// obtaining fresh resource tokens and submitting them to the PS.
func TestKeyRotationReauthorizesWithFreshResourceTokensAtThePersonServer(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	now := time.Date(2026, 9, 2, 10, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	const (
		agentProviderID = "https://ap-rotation.example"
		agentID         = "aauth:reader@ap-rotation.example"
		personServerID  = "https://ps-rotation.example"
		resourceID      = "https://resource-rotation.example"
	)
	scope := []string{"records.read"}
	agentProviderKey := newSigningKey(t, "rotation-ap")
	oldKey := newSigningKey(t, "rotation-agent-old")
	newKey := newSigningKey(t, "rotation-agent-new")
	personServerKey := newSigningKey(t, "rotation-ps")
	resourceKey := newSigningKey(t, "rotation-resource")

	network := newLogicalTransport()
	submitted := &submittedResourceTokens{base: network, personServer: personServerID}
	httpClient := &http.Client{Transport: submitted}
	keyResolver, err := signaturekey.NewHTTPKeyResolver(signaturekey.HTTPKeyResolverConfig{
		Client: httpClient, Clock: clock,
		Admit: func(_ context.Context, endpoint string) error {
			if stringsHasAnySuffix(endpoint,
				"/.well-known/aauth-agent.json", "/.well-known/aauth-person.json",
				"/.well-known/aauth-resource.json", "/.well-known/jwks.json",
			) {
				return nil
			}
			return errors.New("unexpected egress endpoint: " + endpoint)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	agentTokenIDs := 0
	provider, err := agentprovider.New(agentprovider.Config{
		Issuer: agentProviderID, SigningKey: agentProviderKey, Clock: clock,
		NewID: func() string {
			agentTokenIDs++
			return fmt.Sprintf("rotation-agent-token-%d", agentTokenIDs)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	personServerIDs := 0
	authorizations := 0
	people, err := personserver.NewPSAuthorization(personserver.PSAuthorizationConfig{
		Issuer: personServerID, SigningKey: personServerKey, KeyResolver: keyResolver,
		Clock: clock, Tokens: newMemoryPersonTokenStore(),
		NewID: func() string {
			personServerIDs++
			return fmt.Sprintf("rotation-ps-token-%d", personServerIDs)
		},
		BindPerson: func(_ context.Context, request personserver.PersonTokenRequest) (personserver.Person, error) {
			if request.Agent != agentID || request.Resource != resourceID {
				return personserver.Person{}, errors.New("unexpected person binding context")
			}
			return personserver.Person{Subject: "person-123", Tenant: "tenant-1", Lifetime: 20 * time.Minute}, nil
		},
		Authorize: func(_ context.Context, request personserver.AuthorizationRequest) (personserver.AuthorizationDecision, error) {
			authorizations++
			if request.Agent != agentID || request.Resource != resourceID || request.Subject != "person-123" ||
				!slices.Equal(request.Scopes, scope) {
				return personserver.AuthorizationDecision{}, errors.New("unexpected authorization context")
			}
			return personserver.AuthorizationDecision{Scopes: append([]string(nil), scope...), Lifetime: 30 * time.Minute}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	resourceTokenIDs := 0
	protectedCalls := 0
	protectedResource, err := resource.NewPSAuthorization(resource.PSAuthorizationConfig{
		Issuer: resourceID, SigningKey: resourceKey, KeyResolver: keyResolver, Clock: clock,
		NewID: func() string {
			resourceTokenIDs++
			return fmt.Sprintf("rotation-resource-token-%d", resourceTokenIDs)
		},
		ScopeDescriptions: map[string]string{"records.read": "Read records"},
		RequiredScopes:    func(*http.Request) []string { return append([]string(nil), scope...) },
		ResolvePerson: func(_ context.Context, identity resource.PersonIdentity, _ resource.PersonContext) error {
			if identity != (resource.PersonIdentity{Issuer: personServerID, Subject: "person-123"}) {
				return errors.New("unexpected Resource person")
			}
			return nil
		},
		Protected: http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
			protectedCalls++
			_, _ = io.WriteString(response, "accepted")
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	network.Handle(agentProviderID, provider.Handler())
	network.Handle(personServerID, people.Handler())
	network.Handle(resourceID, protectedResource.Handler())

	call := func(t *testing.T, reader *clientagent.Client, authToken string) (*http.Response, error) {
		t.Helper()
		request, err := http.NewRequest(http.MethodGet, resourceID+"/records", nil)
		if err != nil {
			t.Fatal(err)
		}
		return reader.Do(ctx, clientagent.Call{Request: request, AuthToken: authToken})
	}

	oldToken, err := provider.Issue(aauth.AgentTokenRequest{
		Agent: agentID, PersonServer: personServerID, PublicKey: oldKey.PublicJWK(), Lifetime: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	oldReader, err := clientagent.New(ctx, clientagent.Config{
		Identifier: agentID, SigningKey: oldKey, AgentToken: oldToken,
		KeyResolver: keyResolver, HTTPClient: httpClient, Clock: clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	oldPersonToken := requestImmediatePersonTokenFor(t, ctx, oldReader, personServerID, resourceID)
	firstResourceToken, err := oldReader.Authorize(ctx, clientagent.AuthorizeRequest{
		Resource: resourceID, PersonToken: oldPersonToken, Scopes: scope,
	})
	if err != nil {
		t.Fatal(err)
	}
	priorAuthToken, err := oldReader.Exchange(ctx, clientagent.ExchangeRequest{
		PersonServer: personServerID, ResourceToken: firstResourceToken, PresentedToken: oldPersonToken,
	})
	if err != nil {
		t.Fatal(err)
	}
	response, err := call(t, oldReader, priorAuthToken)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusOK || protectedCalls != 1 {
		t.Fatalf("call before rotation = %d, protected calls %d", response.StatusCode, protectedCalls)
	}

	// The Agent rotates its signing key and receives a new Agent token for the
	// same identity. Thirty-one minutes later the prior auth token has also
	// expired.
	newToken, err := provider.Issue(aauth.AgentTokenRequest{
		Agent: agentID, PersonServer: personServerID, PublicKey: newKey.PublicJWK(), Lifetime: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	reader, err := clientagent.New(ctx, clientagent.Config{
		Identifier: agentID, SigningKey: newKey, AgentToken: newToken,
		KeyResolver: keyResolver, HTTPClient: httpClient, Clock: clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	if response, err := call(t, reader, priorAuthToken); err == nil || response != nil ||
		!strings.Contains(err.Error(), "confirmation key does not match signing key") || protectedCalls != 1 {
		t.Fatalf("auth token bound to the old key after rotation: response=%v error=%v protected calls %d", response, err, protectedCalls)
	}
	now = now.Add(31 * time.Minute)

	// A person token bound to the old key cannot carry the re-authorization.
	if _, err := reader.Reauthorize(ctx, clientagent.ReauthorizationRequest{
		PriorAuthToken: priorAuthToken, PersonToken: oldPersonToken,
	}); err == nil {
		t.Fatal("re-authorized with a person token bound to the old key")
	}
	if len(submitted.tokens()) != 1 || authorizations != 1 {
		t.Fatalf("refused re-authorization reached the Person Server: submitted %d, authorizations %d",
			len(submitted.tokens()), authorizations)
	}

	newPersonToken := requestImmediatePersonTokenFor(t, ctx, reader, personServerID, resourceID)
	result, err := reader.Reauthorize(ctx, clientagent.ReauthorizationRequest{
		PriorAuthToken: priorAuthToken, PersonToken: newPersonToken,
	})
	if err != nil {
		t.Fatal(err)
	}
	authToken, ok := result.Token()
	if !ok {
		t.Fatalf("re-authorization did not complete immediately: %#v", result)
	}

	// The Person Server received a fresh resource token bound to the new key
	// and naming the new person token, and issued an auth token bound to it.
	tokens := submitted.tokens()
	if len(tokens) != 2 || tokens[1] == firstResourceToken || authorizations != 2 {
		t.Fatalf("resource tokens submitted = %d, authorizations %d", len(tokens), authorizations)
	}
	freshResource, err := aauth.VerifyResourceToken(ctx, tokens[1], keyResolver, clock)
	if err != nil {
		t.Fatal(err)
	}
	newThumbprint, err := newKey.PublicJWK().Thumbprint()
	if err != nil {
		t.Fatal(err)
	}
	newPerson, err := aauth.VerifyPersonToken(ctx, newPersonToken, keyResolver, clock)
	if err != nil {
		t.Fatal(err)
	}
	if freshResource.AgentJKT != newThumbprint || freshResource.PresentedJTI != newPerson.JTI ||
		freshResource.Scope != "records.read" || freshResource.Issuer != resourceID {
		t.Fatalf("fresh resource token = %#v", freshResource)
	}
	authClaims, err := aauth.VerifyAuthToken(ctx, authToken, keyResolver, clock)
	if err != nil {
		t.Fatal(err)
	}
	if !authClaims.Confirmation.JWK.Equal(newKey.PublicJWK()) || authClaims.Audience != resourceID ||
		authClaims.Scope != "records.read" || authClaims.Subject != "person-123" {
		t.Fatalf("re-authorized auth token = %#v", authClaims)
	}
	response, err = call(t, reader, authToken)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusOK || protectedCalls != 2 {
		t.Fatalf("call after re-authorization = %d, protected calls %d", response.StatusCode, protectedCalls)
	}
}

func requestImmediatePersonTokenFor(
	t *testing.T,
	ctx context.Context,
	reader *clientagent.Client,
	personServer string,
	resourceID string,
) string {
	t.Helper()
	result, err := reader.PersonToken(ctx, clientagent.PersonTokenRequest{PersonServer: personServer, Resource: resourceID})
	if err != nil {
		t.Fatal(err)
	}
	token, ok := result.Token()
	if !ok {
		t.Fatalf("person-token result = %#v", result)
	}
	return token
}

// submittedResourceTokens records each resource token an Agent submits to the
// Person Server.
type submittedResourceTokens struct {
	base         http.RoundTripper
	personServer string
	mu           sync.Mutex
	submitted    []string
}

func (recorder *submittedResourceTokens) RoundTrip(request *http.Request) (*http.Response, error) {
	if request.Method == http.MethodPost && request.Body != nil &&
		request.URL.Scheme+"://"+request.URL.Host == recorder.personServer {
		body, err := io.ReadAll(request.Body)
		if err != nil {
			return nil, err
		}
		request.Body.Close()
		request.Body = io.NopCloser(bytes.NewReader(body))
		var input struct {
			ResourceToken string `json:"resource_token"`
		}
		if json.Unmarshal(body, &input) == nil && input.ResourceToken != "" {
			recorder.mu.Lock()
			recorder.submitted = append(recorder.submitted, input.ResourceToken)
			recorder.mu.Unlock()
		}
	}
	return recorder.base.RoundTrip(request)
}

func (recorder *submittedResourceTokens) tokens() []string {
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	return append([]string(nil), recorder.submitted...)
}
