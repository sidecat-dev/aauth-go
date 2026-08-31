package integration_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	clientagent "gitlab.com/sidecat-dev/aauth-go/agent"
	"gitlab.com/sidecat-dev/aauth-go/agentprovider"
	"gitlab.com/sidecat-dev/aauth-go/personserver"
	"gitlab.com/sidecat-dev/aauth-go/resource"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

func TestMissionBoundImmediateThreePartyJourney(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	now := time.Date(2026, 8, 30, 20, 30, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	const (
		agentProviderID = "https://ap.example"
		agentID         = "aauth:reader@ap.example"
		personServerID  = "https://ps.example"
		resourceID      = "https://resource.example"
		scope           = "records.read"
	)
	missionExpiry := now.Add(4 * time.Minute)
	providerKey := newSigningKey(t, "mission-three-party-ap")
	agentKey := newSigningKey(t, "mission-three-party-agent")
	personKey := newSigningKey(t, "mission-three-party-ps")
	resourceKey := newSigningKey(t, "mission-three-party-resource")
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
		NewID: func() string { return "mission-agent-token" },
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
	store := newMemoryPersonTokenStore()
	ids := []string{
		"mission-person-token", "mission-pre-update-auth-token",
		"mission-updated-person-token", "mission-post-update-auth-token",
	}
	var acceptedUpdates []personserver.MissionUpdatePolicyRequest
	var acceptedCompletions []personserver.MissionCompletionPolicyRequest
	var personPolicyUpdateCounts []int
	var authorizationPolicyUpdateCounts []int
	people, err := personserver.NewPSAuthorization(personserver.PSAuthorizationConfig{
		Issuer: personServerID, SigningKey: personKey, KeyResolver: resolver,
		Clock: clock, Tokens: store, NewID: func() string {
			id := ids[0]
			ids = ids[1:]
			return id
		},
		Missions: &personserver.MissionConfig{
			Approve: func(_ context.Context, request personserver.MissionApprovalRequest) (personserver.MissionDecision, error) {
				if request.Agent != agentID || request.Proposal.Description != "# Read report inputs" ||
					!slices.Equal(request.Proposal.Resources, []string{resourceID}) {
					return personserver.MissionDecision{}, errors.New("unexpected mission proposal")
				}
				return personserver.MissionDecision{
					Description: request.Proposal.Description, ApprovedResources: request.Proposal.Resources,
					ExpiresAt: &missionExpiry, Capabilities: []string{"interaction"},
				}, nil
			},
			AcceptUpdate: func(_ context.Context, request personserver.MissionUpdatePolicyRequest) error {
				acceptedUpdates = append(acceptedUpdates, request)
				return nil
			},
			ConfirmPersonAcceptedCompletion: func(_ context.Context, request personserver.MissionCompletionPolicyRequest) error {
				acceptedCompletions = append(acceptedCompletions, request)
				return nil
			},
		},
		BindPerson: func(_ context.Context, request personserver.PersonTokenRequest) (personserver.Person, error) {
			if request.Agent != agentID || request.Resource != resourceID || request.Mission == nil ||
				request.Mission.Blob.Description != "# Read report inputs" || string(request.Mission.ExactJSON) == "" {
				return personserver.Person{}, errors.New("unexpected mission person context")
			}
			personPolicyUpdateCounts = append(personPolicyUpdateCounts, len(request.Mission.AcceptedUpdates))
			return personserver.Person{Subject: "person-123", Tenant: "tenant-1", Lifetime: time.Hour}, nil
		},
		Authorize: func(_ context.Context, request personserver.AuthorizationRequest) (personserver.AuthorizationDecision, error) {
			if request.Agent != agentID || request.Resource != resourceID || request.Subject != "person-123" ||
				request.Mission == nil || request.Mission.Blob.Description != "# Read report inputs" ||
				!slices.Equal(request.Scopes, []string{scope}) {
				return personserver.AuthorizationDecision{}, errors.New("unexpected mission authorization context")
			}
			updates := len(request.Mission.AcceptedUpdates)
			if updates != 0 && updates != 2 {
				return personserver.AuthorizationDecision{}, errors.New("unexpected accepted-update count")
			}
			authorizationPolicyUpdateCounts = append(authorizationPolicyUpdateCounts, updates)
			return personserver.AuthorizationDecision{Scopes: request.Scopes, Lifetime: time.Hour}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	var resolvedMission string
	var protectedMission string
	resourceIDs := []string{"mission-pre-update-resource-token", "mission-post-update-resource-token"}
	protectedResource, err := resource.NewPSAuthorization(resource.PSAuthorizationConfig{
		Issuer: resourceID, SigningKey: resourceKey, KeyResolver: resolver, Clock: clock,
		NewID: func() string {
			id := resourceIDs[0]
			resourceIDs = resourceIDs[1:]
			return id
		},
		ScopeDescriptions: map[string]string{scope: "Read records"},
		RequiredScopes:    func(*http.Request) []string { return []string{scope} },
		ResolvePerson: func(_ context.Context, identity resource.PersonIdentity, personContext resource.PersonContext) error {
			if identity != (resource.PersonIdentity{Issuer: personServerID, Subject: "person-123"}) {
				return errors.New("unexpected person")
			}
			resolvedMission = personContext.MissionS256
			return nil
		},
		Protected: http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			principal, ok := resource.AuthPrincipalFromContext(request.Context())
			if !ok {
				t.Error("missing auth principal")
				return
			}
			protectedMission = principal.MissionS256
			_, _ = io.WriteString(response, "mission accepted")
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	network.Handle(agentProviderID, provider.Handler())
	network.Handle(personServerID, people.Handler())
	network.Handle(resourceID, protectedResource.Handler())

	reader, err := clientagent.New(ctx, clientagent.Config{
		Identifier: agentID, SigningKey: agentKey, AgentToken: agentToken,
		KeyResolver: resolver, HTTPClient: httpClient, Clock: clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	missionResult, err := reader.ProposeMission(ctx, clientagent.MissionRequest{
		PersonServer: personServerID,
		Proposal:     aauth.MissionProposal{Description: "# Read report inputs", Resources: []string{resourceID}},
	})
	if err != nil {
		t.Fatal(err)
	}
	mission := missionResult.Mission()
	initialPersonToken, ok := missionResult.PersonToken(resourceID)
	if !ok {
		t.Fatal("mission approval omitted the approved Resource person token")
	}
	initialPersonClaims, err := aauth.VerifyPersonToken(ctx, initialPersonToken, resolver, clock)
	if err != nil {
		t.Fatal(err)
	}
	preUpdateResourceToken, err := reader.Authorize(ctx, clientagent.AuthorizeRequest{
		Resource: resourceID, PersonToken: initialPersonToken, Scopes: []string{scope},
	})
	if err != nil {
		t.Fatal(err)
	}
	preUpdateResourceClaims, err := aauth.VerifyResourceToken(ctx, preUpdateResourceToken, resolver, clock)
	if err != nil {
		t.Fatal(err)
	}
	preUpdateAuthToken, err := reader.Exchange(ctx, clientagent.ExchangeRequest{
		PersonServer: personServerID, ResourceToken: preUpdateResourceToken,
	})
	if err != nil {
		t.Fatal(err)
	}
	preUpdateAuthClaims, err := aauth.VerifyAuthToken(ctx, preUpdateAuthToken, resolver, clock)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reader.UpdateMission(ctx, clientagent.MissionUpdateRequest{
		PersonServer: personServerID, MissionS256: mission.S256, Description: "Read the source report first",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := reader.UpdateMission(ctx, clientagent.MissionUpdateRequest{
		PersonServer: personServerID, MissionS256: mission.S256, Description: "Include the retained correction",
	}); err != nil {
		t.Fatal(err)
	}
	if len(acceptedUpdates) != 2 || len(acceptedUpdates[0].Mission.AcceptedUpdates) != 0 ||
		len(acceptedUpdates[1].Mission.AcceptedUpdates) != 1 ||
		acceptedUpdates[1].Mission.AcceptedUpdates[0].Document.Update.Description != "Read the source report first" {
		t.Fatalf("mission update contexts = %#v", acceptedUpdates)
	}
	personResult, err := reader.PersonToken(ctx, clientagent.PersonTokenRequest{
		PersonServer: personServerID, Resource: resourceID, MissionS256: mission.S256,
	})
	if err != nil {
		t.Fatal(err)
	}
	personToken, ok := personResult.Token()
	if !ok {
		t.Fatal("updated mission person-token request did not complete immediately")
	}
	if !slices.Equal(personPolicyUpdateCounts, []int{0, 2}) {
		t.Fatalf("person policy update counts = %v, want [0 2]", personPolicyUpdateCounts)
	}
	if initialPersonToken == personToken {
		t.Fatal("updated mission person-token request reused the approval-time token")
	}
	personClaims, err := aauth.VerifyPersonToken(ctx, personToken, resolver, clock)
	if err != nil {
		t.Fatal(err)
	}
	postUpdateResourceToken, err := reader.Authorize(ctx, clientagent.AuthorizeRequest{
		Resource: resourceID, PersonToken: initialPersonToken, Scopes: []string{scope},
	})
	if err != nil {
		t.Fatal(err)
	}
	postUpdateResourceClaims, err := aauth.VerifyResourceToken(ctx, postUpdateResourceToken, resolver, clock)
	if err != nil {
		t.Fatal(err)
	}
	for name, changedMission := range map[string]string{
		"omitted": "", "substituted": aauth.MissionS256([]byte("another mission")),
	} {
		tampered := postUpdateResourceClaims
		tampered.JTI = "mission-" + name + "-resource-token"
		tampered.MissionS256 = changedMission
		compact, err := aauth.MintResourceToken(resourceKey, tampered)
		if err != nil {
			t.Fatal(err)
		}
		_, err = reader.Exchange(ctx, clientagent.ExchangeRequest{
			PersonServer: personServerID, ResourceToken: compact,
		})
		var problem *aauth.ProblemError
		if !errors.As(err, &problem) || problem.Code != "invalid_resource_token" {
			t.Fatalf("%s mission binding error = %#v, %v", name, problem, err)
		}
	}
	postUpdateAuthToken, err := reader.Exchange(ctx, clientagent.ExchangeRequest{
		PersonServer: personServerID, ResourceToken: preUpdateResourceToken,
	})
	if err != nil {
		t.Fatal(err)
	}
	postUpdateAuthClaims, err := aauth.VerifyAuthToken(ctx, postUpdateAuthToken, resolver, clock)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(authorizationPolicyUpdateCounts, []int{0, 2}) {
		t.Fatalf("authorization policy update counts = %v, want [0 2]", authorizationPolicyUpdateCounts)
	}
	store.mu.Lock()
	authCount := len(store.auth)
	if authCount != 2 {
		store.mu.Unlock()
		t.Fatalf("retained mission auth-token records = %d, want 2", authCount)
	}
	var retainedPostUpdateAuth personserver.IssuedAuthTokenRecord
	for _, record := range store.auth {
		if record.Reference.JTI == postUpdateAuthClaims.JTI {
			retainedPostUpdateAuth = record
		}
	}
	store.mu.Unlock()
	if retainedPostUpdateAuth.MissionS256 != mission.S256 || retainedPostUpdateAuth.Reference.JTI != postUpdateAuthClaims.JTI {
		t.Fatalf("retained post-update auth-token record = %#v", retainedPostUpdateAuth)
	}
	for name, digest := range map[string]string{
		"initial person":       initialPersonClaims.MissionS256,
		"pre-update resource":  preUpdateResourceClaims.MissionS256,
		"pre-update auth":      preUpdateAuthClaims.MissionS256,
		"updated person":       personClaims.MissionS256,
		"post-update resource": postUpdateResourceClaims.MissionS256,
		"post-update auth":     postUpdateAuthClaims.MissionS256,
	} {
		if digest != mission.S256 {
			t.Fatalf("%s mission_s256 = %q, want %q", name, digest, mission.S256)
		}
	}
	for name, expiry := range map[string]int64{
		"initial person":       initialPersonClaims.ExpiresAt,
		"pre-update resource":  preUpdateResourceClaims.ExpiresAt,
		"pre-update auth":      preUpdateAuthClaims.ExpiresAt,
		"updated person":       personClaims.ExpiresAt,
		"post-update resource": postUpdateResourceClaims.ExpiresAt,
		"post-update auth":     postUpdateAuthClaims.ExpiresAt,
	} {
		if expiry > missionExpiry.Unix() {
			t.Fatalf("%s token expires at %d after mission %d", name, expiry, missionExpiry.Unix())
		}
	}
	request, _ := http.NewRequest(http.MethodGet, resourceID+"/records", nil)
	response, err := reader.Do(ctx, clientagent.Call{Request: request, AuthToken: preUpdateAuthToken})
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode != http.StatusOK || string(body) != "mission accepted" ||
		resolvedMission != mission.S256 || protectedMission != mission.S256 {
		t.Fatalf("protected result = %d %q, resolved=%q, principal=%q", response.StatusCode, body, resolvedMission, protectedMission)
	}

	if err := reader.CompleteMission(ctx, clientagent.MissionCompletionRequest{
		PersonServer: personServerID, MissionS256: mission.S256, Summary: "Read completed",
	}); err != nil {
		t.Fatal(err)
	}
	if len(acceptedCompletions) != 1 ||
		len(acceptedCompletions[0].Mission.AcceptedUpdates) != 2 ||
		acceptedCompletions[0].Document.Completion.Summary != "Read completed" {
		t.Fatalf("completion policy=%#v", acceptedCompletions)
	}
	// Characterization only: a conforming Agent must stop using a completed
	// mission. The Resource has no termination signal, so an outstanding Auth
	// token remains usable until its own expiry.
	request, _ = http.NewRequest(http.MethodGet, resourceID+"/records", nil)
	response, err = reader.Do(ctx, clientagent.Call{Request: request, AuthToken: preUpdateAuthToken})
	if err != nil {
		t.Fatal(err)
	}
	body, _ = io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode != http.StatusOK || string(body) != "mission accepted" {
		t.Fatalf("outstanding completed-mission credential = %d %q", response.StatusCode, body)
	}
	_, err = reader.UpdateMission(ctx, clientagent.MissionUpdateRequest{
		PersonServer: personServerID, MissionS256: mission.S256, Description: "Too late",
	})
	var problem *aauth.ProblemError
	if !errors.As(err, &problem) || problem.Code != "mission_terminated" ||
		problem.MissionStatus != "terminated" || problem.TerminationReason != "completed" {
		t.Fatalf("post-completion update error = %#v, %v", problem, err)
	}
	_, err = reader.Exchange(ctx, clientagent.ExchangeRequest{
		PersonServer: personServerID, ResourceToken: preUpdateResourceToken,
	})
	if !errors.As(err, &problem) || problem.Code != "mission_terminated" ||
		problem.MissionStatus != "terminated" || problem.TerminationReason != "completed" {
		t.Fatalf("terminated mission error = %#v, %v", problem, err)
	}
}
