// The mission example runs one deferred mission-bound three-party journey in
// process. Each role still communicates through ordinary HTTP handlers.
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
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	clientagent "gitlab.com/sidecat-dev/aauth-go/agent"
	"gitlab.com/sidecat-dev/aauth-go/agentprovider"
	"gitlab.com/sidecat-dev/aauth-go/internal/exampleutil"
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
	now := time.Date(2026, 8, 30, 20, 30, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	providerKey := newSigningKey("agent-provider-key")
	agentKey := newSigningKey("agent-key")
	personKey := newSigningKey("person-server-key")
	resourceKey := newSigningKey("resource-key")
	network := newLogicalTransport()
	httpClient := &http.Client{Transport: network}
	resolver := must(signaturekey.NewHTTPKeyResolver(signaturekey.HTTPKeyResolverConfig{
		Client: httpClient, Clock: clock, Admit: network.Admit,
	}))

	provider := must(agentprovider.New(agentprovider.Config{
		Issuer: agentProviderID, SigningKey: providerKey, Clock: clock,
		NewID: func() string { return "agent-token-1" },
	}))
	agentToken := must(provider.Issue(aauth.AgentTokenRequest{
		Agent: agentID, PersonServer: personServerID,
		PublicKey: agentKey.PublicJWK(), Lifetime: time.Hour,
	}))
	missionExpiry := now.Add(15 * time.Minute)
	personAcceptedCompletion := false
	ids := []string{"person-token-1", "auth-token-1"}
	people := must(personserver.NewPSAuthorization(personserver.PSAuthorizationConfig{
		Issuer: personServerID, SigningKey: personKey,
		KeyResolver: resolver, Clock: clock, Tokens: exampleutil.NewMissionStore(),
		NewID: func() string {
			id := ids[0]
			ids = ids[1:]
			return id
		},
		Missions: &personserver.MissionConfig{
			DeferProposal: func(context.Context, personserver.MissionApprovalRequest) (personserver.MissionProposalPendingPolicy, bool, error) {
				return personserver.MissionProposalPendingPolicy{Lifetime: 5 * time.Minute, RetryAfter: 0}, true, nil
			},
			AcceptUpdate: func(_ context.Context, request personserver.MissionUpdatePolicyRequest) error {
				if request.Document.Update.Description == "" {
					return errors.New("mission update description is required")
				}
				return nil
			},
			ConfirmPersonAcceptedCompletion: func(_ context.Context, request personserver.MissionCompletionPolicyRequest) error {
				if !personAcceptedCompletion {
					return fmt.Errorf("%w: the responsible person has not accepted completion", personserver.ErrMissionDenied)
				}
				return nil
			},
		},
		BindPerson: func(_ context.Context, request personserver.PersonTokenRequest) (personserver.Person, error) {
			if request.Mission == nil || request.Mission.Blob.Description == "" {
				return personserver.Person{}, errors.New("mission context is required")
			}
			return personserver.Person{Subject: "person-123", Lifetime: time.Hour}, nil
		},
		Authorize: func(_ context.Context, request personserver.AuthorizationRequest) (personserver.AuthorizationDecision, error) {
			if request.Mission == nil || len(request.Mission.AcceptedUpdates) != 1 ||
				request.Mission.AcceptedUpdates[0].Document.Update.Description != "Report inputs selected" {
				return personserver.AuthorizationDecision{}, errors.Join(personserver.ErrAccessDenied, errors.New("accepted mission update is required"))
			}
			return personserver.AuthorizationDecision{Scopes: request.Scopes, Lifetime: time.Hour}, nil
		},
	}))
	protectedResource := must(resource.NewPSAuthorization(resource.PSAuthorizationConfig{
		Issuer: resourceID, SigningKey: resourceKey, KeyResolver: resolver, Clock: clock,
		NewID:             func() string { return "resource-token-1" },
		ScopeDescriptions: map[string]string{scope: "Read records"},
		RequiredScopes:    func(*http.Request) []string { return []string{scope} },
		ResolvePerson: func(context.Context, resource.PersonIdentity, resource.PersonContext) error {
			return nil
		},
		Protected: http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			principal, ok := resource.AuthPrincipalFromContext(request.Context())
			if !ok || principal.MissionS256 == "" {
				http.Error(response, "missing mission-bound principal", http.StatusInternalServerError)
				return
			}
			fmt.Fprintf(response, "mission-bound call complete for %s\n", principal.Subject)
		}),
	}))
	network.Handle(agentProviderID, provider.Handler())
	network.Handle(personServerID, people.Handler())
	network.Handle(resourceID, protectedResource.Handler())

	reader := must(clientagent.New(context.Background(), clientagent.Config{
		Identifier: agentID, SigningKey: agentKey, AgentToken: agentToken,
		KeyResolver: resolver, HTTPClient: httpClient, Clock: clock,
	}))
	ctx := context.Background()
	proposalResult := must(reader.BeginMission(ctx, clientagent.MissionRequest{
		PersonServer: personServerID,
		Proposal: aauth.MissionProposal{
			Description: "# Read the report inputs", Resources: []string{resourceID},
		},
	}))
	pending, ok := proposalResult.Pending()
	if !ok {
		log.Fatal("mission proposal unexpectedly completed without host review")
	}
	reviews := must(people.PendingMissionProposals(ctx, 10))
	if len(reviews) != 1 {
		log.Fatalf("host mission queue contains %d proposals, want 1", len(reviews))
	}
	proposal := reviews[0].Proposal()
	if err := people.ApproveMissionProposal(ctx, reviews[0], personserver.MissionDecision{
		Description: proposal.Description, ApprovedResources: proposal.Resources, ExpiresAt: &missionExpiry,
	}); err != nil {
		log.Fatal(err)
	}
	completed := must(reader.PollMissionProposal(ctx, pending))
	mission, approved := completed.Approval()
	if !approved {
		log.Fatal("approved mission remained pending")
	}
	update := must(reader.UpdateMission(ctx, clientagent.MissionUpdateRequest{
		PersonServer: personServerID, MissionS256: mission.Mission().S256,
		Description: "Report inputs selected",
	}))
	if update.S256() == "" {
		log.Fatal("mission update returned no exact document digest")
	}
	personToken, ok := mission.PersonToken(resourceID)
	if !ok {
		log.Fatal("mission approval omitted the approved Resource person token")
	}
	resourceToken := must(reader.Authorize(ctx, clientagent.AuthorizeRequest{
		Resource: resourceID, PersonToken: personToken, Scopes: []string{scope},
	}))
	authToken := must(reader.Exchange(ctx, clientagent.ExchangeRequest{
		PersonServer: personServerID, ResourceToken: resourceToken,
	}))
	request := must(http.NewRequestWithContext(ctx, http.MethodGet, resourceID+"/records/42", nil))
	response := must(reader.Do(ctx, clientagent.Call{Request: request, AuthToken: authToken}))
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		log.Fatalf("protected call returned %s", response.Status)
	}
	_, _ = io.Copy(os.Stdout, response.Body)
	// A real host sets this only after authenticating the responsible person's
	// response. This example makes that application-owned decision explicit.
	personAcceptedCompletion = true
	if err := reader.CompleteMission(ctx, clientagent.MissionCompletionRequest{
		PersonServer: personServerID, MissionS256: mission.Mission().S256,
		Summary: "Protected report read completed",
	}); err != nil {
		log.Fatal(err)
	}
	fmt.Println("mission completed with person acceptance")
}

func newSigningKey(id string) jose.SigningKey {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	return must(jose.NewEd25519SigningKey(id, privateKey))
}

func must[T any](value T, err error) T {
	if err != nil {
		log.Fatal(err)
	}
	return value
}

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
	origin := request.URL.Scheme + "://" + request.URL.Host
	transport.mu.RLock()
	_, ok := transport.routes[origin]
	transport.mu.RUnlock()
	if !ok {
		return fmt.Errorf("discovery is not admitted for %s", origin)
	}
	return nil
}

func (transport *logicalTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	origin := request.URL.Scheme + "://" + request.URL.Host
	transport.mu.RLock()
	handler := transport.routes[origin]
	transport.mu.RUnlock()
	if handler == nil {
		return nil, fmt.Errorf("no handler for %s", origin)
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	response := recorder.Result()
	response.Request = request
	return response, nil
}
