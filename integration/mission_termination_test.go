package integration_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"slices"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	clientagent "gitlab.com/sidecat-dev/aauth-go/agent"
	"gitlab.com/sidecat-dev/aauth-go/personserver"
	"gitlab.com/sidecat-dev/aauth-go/resource"
	"gitlab.com/sidecat-dev/aauth-go/supervision"
	"gitlab.com/sidecat-dev/aauth-go/supervisionserver"
	"gitlab.com/sidecat-dev/aauth-go/testutil"
)

// Protocol 70d6737, Mission Management and Revocation Cascade ("PS revokes a
// mission"): a mission the host ends as revoked is terminated, every later
// request under it is refused with mission_terminated, and the Person Server
// revokes what it issued under it from its own records: the person token at
// its Resource and at the Access Server it was presented to, and the auth
// token, at its Resource or, in four-party access, through the Access Server.
// What was issued outside the mission is untouched, and a repeat records
// nothing new.
func TestTerminatedMissionRevokesWhatWasIssuedUnderIt(t *testing.T) {
	t.Parallel()
	for _, fourParty := range []bool{false, true} {
		name := "three-party"
		if fourParty {
			name = "four-party"
		}
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			fixture := newRevocationFixture(t, fourParty, aauth.RevocationLimits{}, 0)
			ctx := fixture.ctx
			missions := &personserver.MissionConfig{
				Approve: func(_ context.Context, request personserver.MissionApprovalRequest) (personserver.MissionDecision, error) {
					return personserver.MissionDecision{
						Description: request.Proposal.Description, ApprovedResources: request.Proposal.Resources,
					}, nil
				},
			}
			var people *personserver.Server
			var err error
			if fourParty {
				config := fixture.peopleConfig
				config.Missions = missions
				people, err = personserver.NewFederatedAuthorization(config)
			} else {
				config := fixture.threeParty
				config.Missions = missions
				people, err = personserver.NewPSAuthorization(config)
			}
			if err != nil {
				t.Fatal(err)
			}
			fixture.people = people
			fixture.route(cascadePersonServer, people.Handler())

			proposal, err := fixture.agent.BeginMission(ctx, clientagent.MissionRequest{
				PersonServer: cascadePersonServer,
				Proposal:     aauth.MissionProposal{Description: "# Read records", Resources: []string{cascadeResource}},
			})
			if err != nil {
				t.Fatal(err)
			}
			approval, ok := proposal.Approval()
			if !ok {
				t.Fatal("the mission was not approved at once")
			}
			mission := approval.Mission()
			missionToken, ok := approval.PersonToken(cascadeResource)
			if !ok {
				t.Fatal("the approval omitted the Resource's person token")
			}
			resourceToken, err := fixture.agent.Authorize(ctx, clientagent.AuthorizeRequest{
				Resource: cascadeResource, PersonToken: missionToken, Scopes: []string{"records.read"},
			})
			if err != nil {
				t.Fatal(err)
			}
			authToken, err := fixture.agent.Exchange(ctx, clientagent.ExchangeRequest{
				PersonServer: cascadePersonServer, ResourceToken: resourceToken, PresentedToken: missionToken,
			})
			if err != nil {
				t.Fatal(err)
			}
			if err := fixture.call(authToken); err != nil {
				t.Fatal(err)
			}
			missionless := fixture.personToken()

			for _, reason := range []string{"", "completed", "expired"} {
				if _, err := people.TerminateMission(ctx, cascadeAgent, mission.S256, reason); err == nil {
					t.Fatalf("termination with reason %q succeeded", reason)
				}
			}
			if err := fixture.call(authToken); err != nil {
				t.Fatalf("a refused termination changed the mission: %v", err)
			}

			ended, err := people.TerminateMission(ctx, cascadeAgent, mission.S256, "revoked")
			if err != nil {
				t.Fatal(err)
			}
			want := []string{cascadeResource + " recorded"}
			if fourParty {
				want = append(want, cascadeAccessServer+" recorded")
			}
			requireAttempts(t, "mission termination", ended.Attempts, want...)
			if ended.Reason != "revoked" || ended.Pending() {
				t.Fatalf("termination = %#v", ended)
			}
			if fourParty {
				if report := ended.Attempts[1].Downstream; len(report) != 1 || report[0] != (aauth.DownstreamRevocation{Recipient: cascadeResource}) {
					t.Fatalf("Access Server downstream report = %#v, want the auth token revoked at the Resource", report)
				}
			}

			requireRevokedJWT(t, fixture.call(authToken), "auth token issued under the mission")
			_, err = fixture.agent.Authorize(ctx, clientagent.AuthorizeRequest{
				Resource: cascadeResource, PersonToken: missionToken, Scopes: []string{"records.read"},
			})
			requireRevokedJWT(t, err, "the mission's person token at the Resource")
			_, err = fixture.agent.UpdateMission(ctx, clientagent.MissionUpdateRequest{
				PersonServer: cascadePersonServer, MissionS256: mission.S256, Description: "More records",
			})
			requireProblem(t, err, http.StatusForbidden, "mission_terminated", "update of a revoked mission")
			var problem *aauth.ProblemError
			if !errors.As(err, &problem) || problem.TerminationReason != "revoked" {
				t.Fatalf("termination reason = %v, want revoked", err)
			}
			if _, err := fixture.resourceToken(fixture.agent, missionless); err != nil {
				t.Fatalf("a person token issued outside the mission was revoked: %v", err)
			}

			sent := fixture.count("POST "+cascadeResource+"/revoke") + fixture.count("POST "+cascadeAccessServer+"/revoke")
			again, err := people.TerminateMission(ctx, cascadeAgent, mission.S256, "superseded")
			if err != nil {
				t.Fatal(err)
			}
			requireAttempts(t, "repeated mission termination", again.Attempts, want...)
			if again.Reason != "revoked" {
				t.Fatalf("repeated termination reason = %q, want the first one kept", again.Reason)
			}
			if fixture.count("POST "+cascadeResource+"/revoke")+fixture.count("POST "+cascadeAccessServer+"/revoke") != sent {
				t.Fatal("a repeated termination called a recipient that had recorded the revocation")
			}
		})
	}
}

// Supervision, Terminated and Event Endpoint: a mission the host ends is
// reported terminated with its reason to the Agent's deciding supervisor, and a
// Resource's revocation of a resource token the supervised Agent presented
// reaches the supervisor as revocation.received.
func TestSupervisorIsToldOfAHostEndedMissionAndAWithdrawnResourceToken(t *testing.T) {
	t.Parallel()
	const ledgerID = "https://ledger.example"
	world := newSupervisionWorld(t, supervisionWorldOptions{})
	home := world.addSupervisor(homeSupervisorID, true, func(request supervisionserver.DecisionRequest) supervisionserver.DecisionResult {
		if request.Request.Kind == supervision.KindMissionProposal {
			return decided(supervision.Decision{Verdict: supervision.VerdictAllow, Mission: &supervision.MissionTerms{
				Description: request.Request.Description, ApprovedResources: request.Request.Resources,
			}})
		}
		return decided(supervision.Decision{Verdict: supervision.VerdictAllow})
	})
	config := world.personConfig
	config.TokenRevocation = &personserver.TokenRevocationConfig{Revocations: testutil.NewTokenRevocationStore()}
	people, err := personserver.NewPSAuthorization(config)
	if err != nil {
		t.Fatal(err)
	}
	world.people = people
	world.network.Handle(supervisedPersonID, people.Handler())
	ledger, err := resource.NewPSAuthorization(resource.PSAuthorizationConfig{
		Issuer: ledgerID, SigningKey: newSigningKey(t, "supervision-ledger"), KeyResolver: world.resolver,
		Clock: world.clock, NewID: world.id,
		ScopeDescriptions: map[string]string{"ledger.read": "Read the ledger"},
		RequiredScopes:    func(*http.Request) []string { return []string{"ledger.read"} },
		ResolvePerson:     func(context.Context, resource.PersonIdentity, resource.PersonContext) error { return nil },
		Protected: http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(response, "ledger")
		}),
		Revocation: &resource.RevocationConfig{HTTPClient: world.httpClient, Admit: admitExampleOrigins},
	})
	if err != nil {
		t.Fatal(err)
	}
	world.network.Handle(ledgerID, ledger.Handler())
	clerk, clerkID := world.newAgent("clerk")
	supervisor := personserver.Supervisor{Issuer: homeSupervisorID, Subject: "home-person-1"}
	world.route(clerkID, supervisor)
	ctx := world.ctx

	proposal, err := clerk.BeginMission(ctx, clientagent.MissionRequest{
		PersonServer: supervisedPersonID,
		Proposal:     aauth.MissionProposal{Description: "# Balance the ledger", Resources: []string{ledgerID}},
	})
	if err != nil {
		t.Fatal(err)
	}
	approval, ok := proposal.Approval()
	if !ok {
		t.Fatal("the supervisor's allow did not approve the mission at once")
	}
	mission := approval.Mission()
	personToken, ok := approval.PersonToken(ledgerID)
	if !ok {
		t.Fatal("the approval omitted the ledger's person token")
	}
	resourceToken, err := clerk.Authorize(ctx, clientagent.AuthorizeRequest{
		Resource: ledgerID, PersonToken: personToken, Scopes: []string{"ledger.read"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := clerk.Exchange(ctx, clientagent.ExchangeRequest{
		PersonServer: supervisedPersonID, ResourceToken: resourceToken, PresentedToken: personToken,
	}); err != nil {
		t.Fatal(err)
	}

	claims := tokenClaims(t, resourceToken)
	resourceJTI := claimString(t, claims, "jti")
	resourceExpiry := int64(claims["exp"].(float64))
	withdrawn, err := ledger.RevokeResourceToken(ctx, resource.ResourceTokenRevocation{
		JTI: resourceJTI, ExpiresAt: time.Unix(resourceExpiry, 0), Audience: supervisedPersonID,
	})
	if err != nil {
		t.Fatal(err)
	}
	requireAttempts(t, "resource-token revocation", withdrawn.Attempts, supervisedPersonID+" recorded")

	ended, err := world.people.TerminateMission(ctx, clerkID, mission.S256, "revoked")
	if err != nil {
		t.Fatal(err)
	}
	if ended.Reason != "revoked" || len(ended.Attempts) != 0 {
		t.Fatalf("termination without revocation delivery = %#v", ended)
	}
	wantTold := []string{
		"agent.bound", "approved", "person_token.issued", "auth_token.issued", "revocation.received", "terminated",
	}
	if told := home.told(); !slices.Equal(told, wantTold) {
		t.Fatalf("the supervisor was told %v, want %v", told, wantTold)
	}
	if revocations := home.events(supervision.EventRevocationReceived); len(revocations) != 1 ||
		revocations[0].TokenType != "resource_token" || revocations[0].TokenIssuer != ledgerID ||
		revocations[0].JTI != resourceJTI || revocations[0].ExpiresAt != resourceExpiry ||
		revocations[0].Agent != clerkID || revocations[0].MissionS256 != "" {
		t.Fatalf("revocation.received = %#v, want the ledger's resource token", revocations)
	}
	reports := home.reports()
	if len(reports) != 2 || reports[1].Action != supervision.ReportTerminated || reports[1].MissionS256 != mission.S256 ||
		reports[1].Reason != "revoked" || reports[1].SDI != "" || reports[1].Agent != clerkID {
		t.Fatalf("mission reports = %#v, want the approval and the host's termination", reports)
	}

	if _, err := world.people.TerminateMission(ctx, clerkID, mission.S256, "administrative"); err != nil {
		t.Fatal(err)
	}
	_, err = clerk.UpdateMission(ctx, clientagent.MissionUpdateRequest{
		PersonServer: supervisedPersonID, MissionS256: mission.S256, Description: "One more account",
	})
	requireProblem(t, err, http.StatusForbidden, "mission_terminated", "update of a revoked mission")
	if _, err := world.people.DeliverSupervisionEvents(ctx, supervisor); err != nil {
		t.Fatal(err)
	}
	if told := home.told(); !slices.Equal(told, wantTold) {
		t.Fatalf("after a repeat the supervisor was told %v, want the end reported once", told)
	}
	for _, asked := range home.asked() {
		if asked.Request.Kind == supervision.KindMissionUpdate {
			t.Fatal("an update of a terminated mission was put to the supervisor")
		}
	}
}
