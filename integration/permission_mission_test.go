package integration_test

import (
	"context"
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

func TestCurrentCoreMissionBoundPermissionAcrossPersonServerRecomposition(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	now := time.Date(2026, 9, 1, 2, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	const (
		agentProviderID = "https://ap.example"
		agentID         = "aauth:operator@ap.example"
		personServerID  = "https://ps.example"
	)
	providerKey := newSigningKey(t, "mission-permission-ap")
	agentKey := newSigningKey(t, "mission-permission-agent")
	personKey := newSigningKey(t, "mission-permission-ps")
	network := newLogicalTransport()
	httpClient := &http.Client{Transport: network}
	resolver, err := signaturekey.NewHTTPKeyResolver(signaturekey.HTTPKeyResolverConfig{
		Client: httpClient, TransportEnforcesEgress: true, Clock: clock,
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
		Issuer: agentProviderID, SigningKey: providerKey, Clock: clock,
		NewID: func() string { return "mission-permission-agent-token" },
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

	store := exampleutil.NewMissionPermissionStore()
	missionExpiry := now.Add(30 * time.Minute)
	mission, err := aauth.EncodeMission(aauth.MissionBlob{
		Agent: agentID, ApprovedAt: now.Add(-time.Minute),
		ExpiresAt: &missionExpiry, Description: "Prepare and send the reviewed incident update.",
	})
	if err != nil {
		t.Fatal(err)
	}
	missionRecord := personserver.MissionRecord{
		S256: mission.S256, Agent: agentID, ExactJSON: mission.ExactJSON,
		ApprovedAt: mission.Blob.ApprovedAt, ExpiresAt: missionExpiry,
		State: personserver.MissionActive,
	}
	if err := store.CommitMission(ctx, missionRecord, nil); err != nil {
		t.Fatal(err)
	}
	policyCalls := 0
	newPeople := func() *personserver.Server {
		server, err := personserver.NewPSAuthorization(personserver.PSAuthorizationConfig{
			Issuer: personServerID, SigningKey: personKey, KeyResolver: resolver,
			Clock: clock, NewID: func() string { return "unused-person-token" }, Tokens: store,
			BindPerson: func(context.Context, personserver.PersonTokenRequest) (personserver.Person, error) {
				return personserver.Person{Subject: "person", Lifetime: time.Minute}, nil
			},
			Authorize: func(context.Context, personserver.AuthorizationRequest) (personserver.AuthorizationDecision, error) {
				return personserver.AuthorizationDecision{Scopes: []string{"unused"}, Lifetime: time.Minute}, nil
			},
			Missions: &personserver.MissionConfig{
				Approve: func(context.Context, personserver.MissionApprovalRequest) (personserver.MissionDecision, error) {
					return personserver.MissionDecision{}, errors.New("unused mission approval")
				},
				AcceptUpdate: func(context.Context, personserver.MissionUpdatePolicyRequest) error {
					return errors.New("unused mission update")
				},
				ConfirmPersonAcceptedCompletion: func(context.Context, personserver.MissionCompletionPolicyRequest) error {
					return errors.New("unused mission completion")
				},
			},
			Permission: &personserver.PermissionConfig{
				Policy: func(_ context.Context, request personserver.PermissionPolicyRequest) (personserver.PermissionPolicyResult, error) {
					policyCalls++
					if request.Agent != agentID || request.Mission == nil || request.Mission.S256 != mission.S256 ||
						request.Mission.Blob.Description != mission.Blob.Description || request.Action != "messages.send" {
						return personserver.PermissionPolicyResult{}, errors.New("unexpected mission permission request")
					}
					return personserver.PermissionPolicyResult{Deferred: &personserver.PermissionPendingPolicy{
						Lifetime: 5 * time.Minute,
					}}, nil
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
	operator, err := clientagent.New(ctx, clientagent.Config{
		Identifier: agentID, SigningKey: agentKey, AgentToken: agentToken,
		KeyResolver: resolver, HTTPClient: httpClient, Clock: clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := operator.RequestPermission(ctx, clientagent.PermissionRequest{
		PersonServer: personServerID, MissionS256: mission.S256,
		Action: "messages.send", Description: "Send the reviewed incident update.",
	})
	if err != nil {
		t.Fatal(err)
	}
	pending, ok := result.Pending()
	if !ok || policyCalls != 1 {
		t.Fatalf("pending = %#v, %t; policy calls=%d", pending, ok, policyCalls)
	}

	people = newPeople()
	network.Handle(personServerID, people.Handler())
	reference := strings.TrimPrefix(pending.Location(), personServerID+"/permission/pending/")
	handle, err := people.ResumePermission(ctx, reference)
	if err != nil {
		t.Fatal(err)
	}
	contextView, ok := handle.Mission()
	if !ok || contextView.S256 != mission.S256 || contextView.Blob.Description != mission.Blob.Description {
		t.Fatalf("resumed mission = %#v, %t", contextView, ok)
	}
	if err := people.GrantPermission(ctx, handle); err != nil {
		t.Fatal(err)
	}

	people = newPeople()
	network.Handle(personServerID, people.Handler())
	completed, err := operator.PollPermission(ctx, pending)
	if err != nil {
		t.Fatal(err)
	}
	decision, ok := completed.Decision()
	if !ok || decision.Permission() != aauth.PermissionGranted {
		t.Fatalf("mission permission = %#v, %t", decision, ok)
	}
}
