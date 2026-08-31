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

	aauth "aauth-go"
	clientagent "aauth-go/agent"
	"aauth-go/agentprovider"
	"aauth-go/personserver"
	"aauth-go/resource"
	"aauth-go/signaturekey"
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
	ids := []string{"mission-person-token", "mission-auth-token"}
	people, err := personserver.NewPSAuthorization(personserver.PSAuthorizationConfig{
		Issuer: personServerID, SigningKey: personKey, KeyResolver: resolver,
		Clock: clock, Tokens: store, NewID: func() string {
			id := ids[0]
			ids = ids[1:]
			return id
		},
		Missions: &personserver.MissionConfig{Approve: func(_ context.Context, request personserver.MissionApprovalRequest) (personserver.MissionDecision, error) {
			if request.Agent != agentID || request.Proposal.Description != "# Read report inputs" ||
				!slices.Equal(request.Proposal.Resources, []string{resourceID}) {
				return personserver.MissionDecision{}, errors.New("unexpected mission proposal")
			}
			return personserver.MissionDecision{
				Description: request.Proposal.Description, ApprovedResources: request.Proposal.Resources,
				ExpiresAt: &missionExpiry, Capabilities: []string{"interaction"},
			}, nil
		}},
		BindPerson: func(_ context.Context, request personserver.PersonTokenRequest) (personserver.Person, error) {
			if request.Agent != agentID || request.Resource != resourceID || request.Mission == nil ||
				request.Mission.Blob.Description != "# Read report inputs" || string(request.Mission.ExactJSON) == "" {
				return personserver.Person{}, errors.New("unexpected mission person context")
			}
			return personserver.Person{Subject: "person-123", Tenant: "tenant-1", Lifetime: time.Hour}, nil
		},
		Authorize: func(_ context.Context, request personserver.AuthorizationRequest) (personserver.AuthorizationDecision, error) {
			if request.Agent != agentID || request.Resource != resourceID || request.Subject != "person-123" ||
				request.Mission == nil || request.Mission.Blob.Description != "# Read report inputs" ||
				!slices.Equal(request.Scopes, []string{scope}) {
				return personserver.AuthorizationDecision{}, errors.New("unexpected mission authorization context")
			}
			return personserver.AuthorizationDecision{Scopes: request.Scopes, Lifetime: time.Hour}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	var resolvedMission string
	var protectedMission string
	protectedResource, err := resource.NewPSAuthorization(resource.PSAuthorizationConfig{
		Issuer: resourceID, SigningKey: resourceKey, KeyResolver: resolver, Clock: clock,
		NewID:             func() string { return "mission-resource-token" },
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
	personToken, ok := missionResult.PersonToken(resourceID)
	if !ok {
		t.Fatal("mission approval omitted the approved Resource person token")
	}
	personClaims, err := aauth.VerifyPersonToken(ctx, personToken, resolver, clock)
	if err != nil {
		t.Fatal(err)
	}
	resourceToken, err := reader.Authorize(ctx, clientagent.AuthorizeRequest{
		Resource: resourceID, PersonToken: personToken, Scopes: []string{scope},
	})
	if err != nil {
		t.Fatal(err)
	}
	resourceClaims, err := aauth.VerifyResourceToken(ctx, resourceToken, resolver, clock)
	if err != nil {
		t.Fatal(err)
	}
	for name, changedMission := range map[string]string{
		"omitted": "", "substituted": aauth.MissionS256([]byte("another mission")),
	} {
		tampered := resourceClaims
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
	authToken, err := reader.Exchange(ctx, clientagent.ExchangeRequest{
		PersonServer: personServerID, ResourceToken: resourceToken,
	})
	if err != nil {
		t.Fatal(err)
	}
	authClaims, err := aauth.VerifyAuthToken(ctx, authToken, resolver, clock)
	if err != nil {
		t.Fatal(err)
	}
	store.mu.Lock()
	authCount := len(store.auth)
	if authCount != 1 {
		store.mu.Unlock()
		t.Fatalf("retained mission auth-token records = %d, want 1", authCount)
	}
	var retainedAuth personserver.IssuedAuthTokenRecord
	for _, record := range store.auth {
		retainedAuth = record
	}
	store.mu.Unlock()
	if retainedAuth.MissionS256 != mission.S256 || retainedAuth.Reference.JTI != authClaims.JTI {
		t.Fatalf("retained mission auth-token record = %#v", retainedAuth)
	}
	for name, digest := range map[string]string{
		"person": personClaims.MissionS256, "resource": resourceClaims.MissionS256, "auth": authClaims.MissionS256,
	} {
		if digest != mission.S256 {
			t.Fatalf("%s mission_s256 = %q, want %q", name, digest, mission.S256)
		}
	}
	for name, expiry := range map[string]int64{
		"person": personClaims.ExpiresAt, "resource": resourceClaims.ExpiresAt, "auth": authClaims.ExpiresAt,
	} {
		if expiry > missionExpiry.Unix() {
			t.Fatalf("%s token expires at %d after mission %d", name, expiry, missionExpiry.Unix())
		}
	}
	request, _ := http.NewRequest(http.MethodGet, resourceID+"/records", nil)
	response, err := reader.Do(ctx, clientagent.Call{Request: request, AuthToken: authToken})
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode != http.StatusOK || string(body) != "mission accepted" ||
		resolvedMission != mission.S256 || protectedMission != mission.S256 {
		t.Fatalf("protected result = %d %q, resolved=%q, principal=%q", response.StatusCode, body, resolvedMission, protectedMission)
	}

	if err := store.terminateMission(agentID, mission.S256, "revoked"); err != nil {
		t.Fatal(err)
	}
	_, err = reader.Exchange(ctx, clientagent.ExchangeRequest{
		PersonServer: personServerID, ResourceToken: resourceToken,
	})
	var problem *aauth.ProblemError
	if !errors.As(err, &problem) || problem.Code != "mission_terminated" ||
		problem.MissionStatus != "terminated" || problem.TerminationReason != "revoked" {
		t.Fatalf("terminated mission error = %#v, %v", problem, err)
	}
}
