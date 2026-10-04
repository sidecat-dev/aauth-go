package integration_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	clientagent "gitlab.com/sidecat-dev/aauth-go/agent"
	"gitlab.com/sidecat-dev/aauth-go/agentprovider"
	"gitlab.com/sidecat-dev/aauth-go/internal/exampleutil"
	"gitlab.com/sidecat-dev/aauth-go/personserver"
	"gitlab.com/sidecat-dev/aauth-go/resource"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

func TestDeferredMissionProposalContinuesThroughProtectedResource(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	now := time.Date(2026, 8, 31, 18, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	const (
		agentProviderID = "https://ap.example"
		agentID         = "aauth:reader@ap.example"
		personServerID  = "https://ps.example"
		resourceID      = "https://resource.example"
		scope           = "records.read"
	)
	providerKey := newSigningKey(t, "deferred-mission-ap")
	agentKey := newSigningKey(t, "deferred-mission-agent")
	personKey := newSigningKey(t, "deferred-mission-ps")
	resourceKey := newSigningKey(t, "deferred-mission-resource")
	network := newLogicalTransport()
	httpClient := &http.Client{Transport: network}
	resolver, err := signaturekey.NewHTTPKeyResolver(signaturekey.HTTPKeyResolverConfig{
		Client: httpClient, Clock: clock,
		Admit: func(_ context.Context, endpoint string) error {
			if strings.Contains(endpoint, ".example/.well-known/") {
				return nil
			}
			return errors.New("unexpected discovery endpoint: " + endpoint)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	provider, err := agentprovider.New(agentprovider.Config{
		Issuer: agentProviderID, SigningKey: providerKey, Clock: clock,
		NewID: func() string { return "deferred-mission-agent-token" },
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
	store := exampleutil.NewMissionStore()
	ids := 0
	people, err := personserver.NewPSAuthorization(personserver.PSAuthorizationConfig{
		Issuer: personServerID, SigningKey: personKey, KeyResolver: resolver,
		Clock: clock, Tokens: store, NewID: func() string {
			ids++
			return fmt.Sprintf("deferred-mission-token-%d", ids)
		},
		Missions: &personserver.MissionConfig{
			DeferProposal: func(context.Context, personserver.MissionApprovalRequest) (personserver.MissionProposalPendingPolicy, bool, error) {
				return personserver.MissionProposalPendingPolicy{Lifetime: 10 * time.Minute, RetryAfter: 0}, true, nil
			},
		},
		BindPerson: func(_ context.Context, request personserver.PersonTokenRequest) (personserver.Person, error) {
			if request.Mission == nil || request.Mission.Blob.Agent != agentID || request.Resource != resourceID {
				return personserver.Person{}, errors.New("missing approved mission context")
			}
			return personserver.Person{Subject: "person-123", Lifetime: time.Hour}, nil
		},
		Authorize: func(_ context.Context, request personserver.AuthorizationRequest) (personserver.AuthorizationDecision, error) {
			if request.Mission == nil || request.Mission.Blob.Agent != agentID {
				return personserver.AuthorizationDecision{}, errors.New("missing mission authorization context")
			}
			return personserver.AuthorizationDecision{Scopes: request.Scopes, Lifetime: time.Hour}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	protected, err := resource.NewPSAuthorization(resource.PSAuthorizationConfig{
		Issuer: resourceID, SigningKey: resourceKey, KeyResolver: resolver, Clock: clock,
		NewID:             func() string { return "deferred-mission-resource-token" },
		ScopeDescriptions: map[string]string{scope: "Read records"},
		RequiredScopes:    func(*http.Request) []string { return []string{scope} },
		ResolvePerson:     func(context.Context, resource.PersonIdentity, resource.PersonContext) error { return nil },
		Protected: http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			principal, ok := resource.AuthPrincipalFromContext(request.Context())
			if !ok || principal.MissionS256 == "" {
				t.Error("protected request omitted the approved mission")
				return
			}
			_, _ = io.WriteString(response, "mission accepted")
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	network.Handle(agentProviderID, provider.Handler())
	network.Handle(personServerID, people.Handler())
	network.Handle(resourceID, protected.Handler())

	reader, err := clientagent.New(ctx, clientagent.Config{
		Identifier: agentID, SigningKey: agentKey, AgentToken: agentToken,
		KeyResolver: resolver, HTTPClient: httpClient, Clock: clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	started, err := reader.BeginMission(ctx, clientagent.MissionRequest{
		PersonServer: personServerID,
		Proposal: aauth.MissionProposal{
			Description: "Read the records needed for the report.",
			Tools:       []aauth.MissionTool{{Name: "Read", Description: "Read report records"}},
			Resources:   []string{resourceID},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	pending, ok := started.Pending()
	if !ok {
		t.Fatalf("mission proposal = %#v, want pending", started)
	}
	reviews, err := people.PendingMissionProposals(ctx, 10)
	if err != nil || len(reviews) != 1 || !strings.HasSuffix(pending.Location(), "/"+reviews[0].Reference()) {
		t.Fatalf("host proposal queue = %#v, %v; Agent pending = %q", reviews, err, pending.Location())
	}
	review := reviews[0]
	missionExpiry := now.Add(20 * time.Minute)
	if err := people.ApproveMissionProposal(ctx, review, personserver.MissionDecision{
		Description: review.Proposal().Description, ApprovedTools: review.Proposal().Tools,
		ApprovedResources: []string{resourceID}, ExpiresAt: &missionExpiry,
	}); err != nil {
		t.Fatal(err)
	}
	completed, err := reader.PollMissionProposal(ctx, pending)
	if err != nil {
		t.Fatal(err)
	}
	mission, ok := completed.Approval()
	if !ok {
		t.Fatalf("mission poll = %#v, want approval", completed)
	}
	if !mission.ApprovesTool("Read") || mission.ApprovesTool("Publish") {
		t.Fatalf("approved_tools planning = Read:%t Publish:%t", mission.ApprovesTool("Read"), mission.ApprovesTool("Publish"))
	}
	personToken, ok := mission.PersonToken(resourceID)
	if !ok {
		t.Fatal("mission approval omitted the approved Resource person token")
	}
	resourceToken, err := reader.Authorize(ctx, clientagent.AuthorizeRequest{
		Resource: resourceID, PersonToken: personToken, Scopes: []string{scope},
	})
	if err != nil {
		t.Fatal(err)
	}
	authToken, err := reader.Exchange(ctx, clientagent.ExchangeRequest{
		PersonServer: personServerID, ResourceToken: resourceToken, PresentedToken: personToken,
	})
	if err != nil {
		t.Fatal(err)
	}
	request, _ := http.NewRequest(http.MethodGet, resourceID+"/records", nil)
	response, err := reader.Do(ctx, clientagent.Call{Request: request, AuthToken: authToken})
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode != http.StatusOK || string(body) != "mission accepted" {
		t.Fatalf("protected result = %d %q", response.StatusCode, body)
	}
}
