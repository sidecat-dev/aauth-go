package integration_test

import (
	"bytes"
	"context"
	"encoding/json"
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

func TestCurrentCoreMissionAuditAcrossPersonServerRecomposition(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	now := time.Date(2026, 9, 1, 0, 30, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	const (
		agentProviderID = "https://ap.example"
		agentID         = "aauth:operator@ap.example"
		personServerID  = "https://ps.example"
		resourceID      = "https://resource.example"
		accessServerID  = "https://as.example"
	)
	providerKey := newSigningKey(t, "audit-journey-ap")
	agentKey := newSigningKey(t, "audit-journey-agent")
	personKey := newSigningKey(t, "audit-journey-ps")
	network := newLogicalTransport()
	httpClient := &http.Client{Transport: network}
	resolver, err := signaturekey.NewHTTPKeyResolver(signaturekey.HTTPKeyResolverConfig{
		Client: httpClient, TransportEnforcesEgress: true, Clock: clock,
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
		NewID: func() string { return "audit-agent-token" },
	})
	if err != nil {
		t.Fatal(err)
	}
	agentToken, err := provider.Issue(ctx, aauth.AgentTokenRequest{
		Agent: agentID, PersonServer: personServerID,
		PublicKey: agentKey.PublicJWK(), Lifetime: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}

	store := exampleutil.NewMissionStore()
	missionExpiry := now.Add(10 * time.Minute)
	newPeople := func() *personserver.Server {
		people, err := personserver.NewPSAuthorization(personserver.PSAuthorizationConfig{
			Issuer: personServerID, SigningKey: personKey, KeyResolver: resolver,
			Clock: clock, Tokens: store, NewID: func() string { return "unused-person-token" },
			Missions: &personserver.MissionConfig{
				Approve: func(_ context.Context, request personserver.MissionApprovalRequest) (personserver.MissionDecision, error) {
					if request.Agent != agentID || request.Proposal.Description != "# Prepare the status report" {
						return personserver.MissionDecision{}, errors.New("unexpected mission proposal")
					}
					return personserver.MissionDecision{Description: request.Proposal.Description, ExpiresAt: &missionExpiry}, nil
				},
				AcceptUpdate: func(context.Context, personserver.MissionUpdatePolicyRequest) error { return nil },
				ConfirmPersonAcceptedCompletion: func(context.Context, personserver.MissionCompletionPolicyRequest) error {
					return nil
				},
			},
			Audit: &personserver.AuditConfig{},
			BindPerson: func(context.Context, personserver.PersonTokenRequest) (personserver.Person, error) {
				return personserver.Person{Subject: "person", Lifetime: time.Minute}, nil
			},
			Authorize: func(context.Context, personserver.AuthorizationRequest) (personserver.AuthorizationDecision, error) {
				return personserver.AuthorizationDecision{Scopes: []string{"unused"}, Lifetime: time.Minute}, nil
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		return people
	}

	auditPosts := 0
	people := newPeople()
	servePeople := func(server *personserver.Server) {
		network.Handle(personServerID, http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			if request.Method == http.MethodPost && request.URL.Path == "/audit" {
				auditPosts++
			}
			server.Handler().ServeHTTP(response, request)
		}))
	}
	resourceCalls := 0
	accessServerCalls := 0
	network.Handle(agentProviderID, provider.Handler())
	servePeople(people)
	network.Handle(resourceID, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { resourceCalls++ }))
	network.Handle(accessServerID, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { accessServerCalls++ }))

	operator, err := clientagent.New(ctx, clientagent.Config{
		Identifier: agentID, SigningKey: agentKey, AgentToken: agentToken,
		KeyResolver: resolver, HTTPClient: httpClient, Clock: clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	missionResult, err := operator.ProposeMission(ctx, clientagent.MissionRequest{
		PersonServer: personServerID,
		Proposal:     aauth.MissionProposal{Description: "# Prepare the status report"},
	})
	if err != nil {
		t.Fatal(err)
	}
	mission := missionResult.Mission()

	applicationCalls := 0
	applicationCalls++ // The application performs the action before reporting it.
	entry := aauth.AuditEntry{
		MissionS256: mission.S256,
		Action:      "files.write",
		Description: "Wrote the reviewed status report.",
		Parameters:  json.RawMessage(`{"path":"status.md"}`),
		Result:      json.RawMessage(`{"bytes":128,"status":"completed"}`),
	}
	people = newPeople()
	servePeople(people)
	if err := operator.SubmitAudit(ctx, clientagent.AuditRequest{
		PersonServer: personServerID, Entry: entry,
	}); err != nil {
		t.Fatal(err)
	}
	records, err := store.LoadMissionAuditsForAgent(ctx, agentID, mission.S256, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0].Document.Entry.Action != entry.Action ||
		records[0].Document.Entry.Description != entry.Description ||
		!bytes.Equal(records[0].Document.Entry.Parameters, entry.Parameters) ||
		!bytes.Equal(records[0].Document.Entry.Result, entry.Result) ||
		!records[0].RecordedAt.Equal(now) {
		t.Fatalf("retained audit records = %#v", records)
	}
	records[0].Document.ExactJSON[0] = '['
	reloaded, err := store.LoadMissionAuditsForAgent(ctx, agentID, mission.S256, now)
	if err != nil || len(reloaded) != 1 || reloaded[0].Document.ExactJSON[0] != '{' {
		t.Fatalf("reloaded audit records = %#v, %v", reloaded, err)
	}

	if err := operator.CompleteMission(ctx, clientagent.MissionCompletionRequest{
		PersonServer: personServerID, MissionS256: mission.S256,
		Summary: "Status report completed.",
	}); err != nil {
		t.Fatal(err)
	}
	err = operator.SubmitAudit(ctx, clientagent.AuditRequest{PersonServer: personServerID, Entry: entry})
	var problem *aauth.ProblemError
	if !errors.As(err, &problem) || problem.Status != http.StatusForbidden ||
		problem.Code != "mission_terminated" || problem.MissionStatus != "terminated" ||
		problem.TerminationReason != "completed" {
		t.Fatalf("post-completion audit = %T %v", err, err)
	}
	reloaded, err = store.LoadMissionAuditsForAgent(ctx, agentID, mission.S256, now)
	if err != nil || len(reloaded) != 1 {
		t.Fatalf("post-completion audit log = %#v, %v", reloaded, err)
	}
	if applicationCalls != 1 || auditPosts != 2 || resourceCalls != 0 || accessServerCalls != 0 {
		t.Fatalf("effects: application=%d audit=%d Resource=%d AS=%d",
			applicationCalls, auditPosts, resourceCalls, accessServerCalls)
	}
}
