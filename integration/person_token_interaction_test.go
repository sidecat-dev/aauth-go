package integration_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	clientagent "gitlab.com/sidecat-dev/aauth-go/agent"
	"gitlab.com/sidecat-dev/aauth-go/agentprovider"
	"gitlab.com/sidecat-dev/aauth-go/personserver"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

func TestCurrentCorePersonTokenInteractionAcrossPersonServerRecomposition(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	now := time.Date(2026, 8, 30, 18, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	const (
		agentProviderID = "https://ap.example"
		agentID         = "aauth:reader@ap.example"
		personServerID  = "https://ps.example"
		resourceID      = "https://resource.example"
	)
	providerKey := newSigningKey(t, "interaction-ap-key")
	agentKey := newSigningKey(t, "interaction-agent-key")
	personServerKey := newSigningKey(t, "interaction-ps-key")
	network := newLogicalTransport()
	httpClient := &http.Client{Transport: network}

	provider, err := agentprovider.New(agentprovider.Config{
		Issuer: agentProviderID, SigningKey: providerKey, Clock: clock,
		NewID: func() string { return "interaction-agent-token" },
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
	resolver, err := signaturekey.NewHTTPKeyResolver(signaturekey.HTTPKeyResolverConfig{
		Client: httpClient, Clock: clock,
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
	store := newMemoryPersonTokenStore()
	missionExpiry := now.Add(30 * time.Minute)
	mission, err := aauth.EncodeMission(aauth.MissionBlob{
		Agent: agentID, ApprovedAt: now.Add(-time.Minute),
		ExpiresAt: &missionExpiry, Description: "Read the approved records.",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CommitMission(ctx, personserver.MissionRecord{
		S256: mission.S256, Agent: agentID, ExactJSON: mission.ExactJSON,
		ApprovedAt: mission.Blob.ApprovedAt, ExpiresAt: missionExpiry,
		State: personserver.MissionActive,
	}, nil); err != nil {
		t.Fatal(err)
	}
	nextTokenID := 0
	newPeople := func() *personserver.Server {
		server, err := personserver.NewFederatedAuthorization(personserver.FederatedAuthorizationConfig{
			Issuer: personServerID, SigningKey: personServerKey,
			KeyResolver: resolver, Clock: clock, NewID: func() string {
				nextTokenID++
				return "interaction-person-token-" + strconv.Itoa(nextTokenID)
			},
			HTTPClient: httpClient, Tokens: store,
			AccessServerEndpoint: func(context.Context, string) (string, error) {
				return "https://as.example/token", nil
			},
			BindPerson: func(context.Context, personserver.PersonTokenRequest) (personserver.Person, error) {
				return personserver.Person{}, errors.New("interaction path called immediate person binding")
			},
			RequirePersonTokenInteraction: func(_ context.Context, request personserver.PersonTokenRequest) (personserver.PersonTokenInteractionPolicy, bool, error) {
				if request.Agent != agentID || request.Resource != resourceID {
					return personserver.PersonTokenInteractionPolicy{}, false, errors.New("unexpected person-token request")
				}
				if request.Mission != nil && request.Mission.S256 != mission.S256 {
					return personserver.PersonTokenInteractionPolicy{}, false, errors.New("unexpected person-token mission")
				}
				return personserver.PersonTokenInteractionPolicy{
					URL: personServerID + "/interaction", Lifetime: 5 * time.Minute, RetryAfter: 2 * time.Second,
				}, true, nil
			},
			Consent: func(context.Context, personserver.AuthorizationRequest) error { return nil },
			Missions: &personserver.MissionConfig{
				Approve: func(context.Context, personserver.MissionApprovalRequest) (personserver.MissionDecision, error) {
					return personserver.MissionDecision{}, errors.New("mission approval is not used in this journey")
				},
				AcceptUpdate: func(context.Context, personserver.MissionUpdatePolicyRequest) error {
					return errors.New("mission update is not used in this journey")
				},
				ConfirmPersonAcceptedCompletion: func(context.Context, personserver.MissionCompletionPolicyRequest) error {
					return errors.New("mission completion is not used in this journey")
				},
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		return server
	}
	people := newPeople()
	network.Handle(agentProviderID, provider.Handler())
	network.Handle(personServerID, people.Handler())
	reader, err := clientagent.New(ctx, clientagent.Config{
		Identifier: agentID, SigningKey: agentKey, AgentToken: agentToken,
		KeyResolver: resolver, HTTPClient: httpClient, Clock: clock,
	})
	if err != nil {
		t.Fatal(err)
	}

	result, err := reader.PersonToken(ctx, clientagent.PersonTokenRequest{
		PersonServer: personServerID, Resource: resourceID, Capabilities: []string{"interaction"},
	})
	if err != nil {
		t.Fatal(err)
	}
	pending, ok := result.Pending()
	if !ok || !strings.HasPrefix(pending.InteractionURL(), personServerID+"/interaction/") || pending.RetryAfter() != 2*time.Second {
		t.Fatalf("initial result = %#v, pending = %#v", result, pending)
	}
	if _, commits, _ := store.observation(); commits != 0 {
		t.Fatalf("person-token records before approval = %d", commits)
	}

	// A new Person Server value continues the retained pending request.
	people = newPeople()
	network.Handle(personServerID, people.Handler())
	interactionReference := strings.TrimPrefix(pending.InteractionURL(), personServerID+"/interaction/")
	if interactionReference == pending.InteractionURL() || interactionReference == "" {
		t.Fatalf("interaction URL = %q", pending.InteractionURL())
	}
	interaction, err := people.ConsumePersonTokenInteractionCode(ctx, interactionReference, pending.InteractionCode())
	if err != nil {
		t.Fatal(err)
	}
	reference := interaction.Reference()
	interacting, err := reader.PollPersonToken(ctx, pending)
	if err != nil {
		t.Fatal(err)
	}
	updated, ok := interacting.Pending()
	if !ok || updated.Location() != pending.Location() {
		t.Fatalf("interacting result = %#v", interacting)
	}
	people = newPeople()
	network.Handle(personServerID, people.Handler())
	interaction, err = people.ResumePersonTokenInteraction(ctx, reference)
	if err != nil {
		t.Fatal(err)
	}
	if err := people.ApprovePersonTokenInteraction(ctx, interaction, personserver.Person{
		Subject: "person-123", Lifetime: 20 * time.Minute,
	}); err != nil {
		t.Fatal(err)
	}

	people = newPeople()
	network.Handle(personServerID, people.Handler())
	approved, err := reader.PollPersonToken(ctx, updated)
	if err != nil {
		t.Fatal(err)
	}
	personToken, ok := approved.Token()
	if !ok {
		t.Fatalf("approved result = %#v", approved)
	}
	claims, err := aauth.VerifyPersonToken(ctx, personToken, resolver, clock)
	if err != nil {
		t.Fatal(err)
	}
	if claims.Issuer != personServerID || claims.Audience != resourceID || claims.Subject != "person-123" ||
		!claims.Confirmation.JWK.Equal(agentKey.PublicJWK()) {
		t.Fatalf("approved person token = %#v", claims)
	}
	if record, err := store.Load(ctx, claims.Issuer, claims.JTI); err != nil || record.Subject != claims.Subject {
		t.Fatalf("retained person token = %#v, %v", record, err)
	}

	_, err = reader.PollPersonToken(ctx, updated)
	var gone *aauth.ProblemError
	if !errors.As(err, &gone) || gone.Status != http.StatusGone || gone.Code != "invalid_code" {
		t.Fatalf("terminal replay error = %v, problem = %#v", err, gone)
	}

	result, err = reader.PersonToken(ctx, clientagent.PersonTokenRequest{
		PersonServer: personServerID, Resource: resourceID, MissionS256: mission.S256,
		Capabilities: []string{"interaction"},
	})
	if err != nil {
		t.Fatal(err)
	}
	pending, ok = result.Pending()
	if !ok {
		t.Fatalf("mission interaction result = %#v", result)
	}
	people = newPeople()
	network.Handle(personServerID, people.Handler())
	interactionReference = strings.TrimPrefix(pending.InteractionURL(), personServerID+"/interaction/")
	interaction, err = people.ConsumePersonTokenInteractionCode(ctx, interactionReference, pending.InteractionCode())
	if err != nil {
		t.Fatal(err)
	}
	missionContext, ok := interaction.Mission()
	if !ok || missionContext.S256 != mission.S256 {
		t.Fatalf("mission interaction host context = %#v, %t", missionContext, ok)
	}
	if err := people.ApprovePersonTokenInteraction(ctx, interaction, personserver.Person{
		Subject: "person-123", Lifetime: 20 * time.Minute,
	}); err != nil {
		t.Fatal(err)
	}
	approved, err = reader.PollPersonToken(ctx, pending)
	if err != nil {
		t.Fatal(err)
	}
	personToken, ok = approved.Token()
	if !ok {
		t.Fatalf("mission approved result = %#v", approved)
	}
	claims, err = aauth.VerifyPersonToken(ctx, personToken, resolver, clock)
	if err != nil {
		t.Fatal(err)
	}
	if claims.MissionS256 != mission.S256 {
		t.Fatalf("mission person token = %#v", claims)
	}

	result, err = reader.PersonToken(ctx, clientagent.PersonTokenRequest{
		PersonServer: personServerID, Resource: resourceID, MissionS256: mission.S256,
		Capabilities: []string{"interaction"},
	})
	if err != nil {
		t.Fatal(err)
	}
	pending, ok = result.Pending()
	if !ok {
		t.Fatalf("second mission interaction result = %#v", result)
	}
	interactionReference = strings.TrimPrefix(pending.InteractionURL(), personServerID+"/interaction/")
	interaction, err = people.ConsumePersonTokenInteractionCode(ctx, interactionReference, pending.InteractionCode())
	if err != nil {
		t.Fatal(err)
	}
	if err := people.ApprovePersonTokenInteraction(ctx, interaction, personserver.Person{
		Subject: "person-123", Lifetime: 20 * time.Minute,
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.terminateMission(agentID, mission.S256, "revoked"); err != nil {
		t.Fatal(err)
	}
	_, err = reader.PollPersonToken(ctx, pending)
	if !errors.As(err, &gone) || gone.Status != http.StatusForbidden || gone.Code != "mission_terminated" {
		t.Fatalf("terminated mission poll = %T %v", err, err)
	}

	const childID = "aauth:reader+worker@ap.example"
	childKey := newSigningKey(t, "interaction-child-key")
	childToken, err := aauth.MintAgentToken(agentProviderID, providerKey, aauth.AgentTokenRequest{
		Agent: childID, ParentAgent: agentID, PersonServer: personServerID,
		PublicKey: childKey.PublicJWK(), Lifetime: 20 * time.Minute,
		AdditionalClaims: map[string]json.RawMessage{"workload": json.RawMessage(`"records-worker"`)},
	}, now, "interaction-child-token")
	if err != nil {
		t.Fatal(err)
	}
	result, err = reader.PersonToken(ctx, clientagent.PersonTokenRequest{
		PersonServer: personServerID, Resource: resourceID, SubagentToken: childToken,
		Capabilities: []string{"interaction"},
	})
	if err != nil {
		t.Fatal(err)
	}
	pending, ok = result.Pending()
	if !ok {
		t.Fatalf("sub-agent interaction result = %#v", result)
	}
	interactionReference = strings.TrimPrefix(pending.InteractionURL(), personServerID+"/interaction/")
	interaction, err = people.ConsumePersonTokenInteractionCode(ctx, interactionReference, pending.InteractionCode())
	if err != nil {
		t.Fatal(err)
	}
	if interaction.Agent() != agentID || interaction.Resource() != resourceID {
		t.Fatalf("sub-agent host context: agent=%q resource=%q", interaction.Agent(), interaction.Resource())
	}
	subagent, ok := interaction.Subagent()
	if !ok || subagent != childID || string(interaction.SubagentAdditionalClaims()["workload"]) != `"records-worker"` {
		t.Fatalf("sub-agent host context: subagent=%q present=%t claims=%v", subagent, ok, interaction.SubagentAdditionalClaims())
	}
	if err := people.ApprovePersonTokenInteraction(ctx, interaction, personserver.Person{
		Subject: "person-123", Lifetime: 10 * time.Minute,
	}); err != nil {
		t.Fatal(err)
	}
	approved, err = reader.PollPersonToken(ctx, pending)
	if err != nil {
		t.Fatal(err)
	}
	personToken, ok = approved.Token()
	if !ok {
		t.Fatalf("sub-agent approved result = %#v", approved)
	}
	claims, err = aauth.VerifyPersonToken(ctx, personToken, resolver, clock)
	if err != nil {
		t.Fatal(err)
	}
	if !claims.Confirmation.JWK.Equal(childKey.PublicJWK()) {
		t.Fatalf("sub-agent person-token confirmation = %#v", claims.Confirmation)
	}
	record, err := store.Load(ctx, claims.Issuer, claims.JTI)
	if err != nil || record.Agent != childID || record.ParentAgent != agentID ||
		!record.Confirmation.Equal(childKey.PublicJWK()) {
		t.Fatalf("retained sub-agent person token = %#v, %v", record, err)
	}
}
