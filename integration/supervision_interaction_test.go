package integration_test

import (
	"context"
	"slices"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	clientagent "gitlab.com/sidecat-dev/aauth-go/agent"
	"gitlab.com/sidecat-dev/aauth-go/personserver"
	"gitlab.com/sidecat-dev/aauth-go/supervision"
	"gitlab.com/sidecat-dev/aauth-go/supervisionserver"
	"gitlab.com/sidecat-dev/aauth-go/testutil"
)

// TestRelayedInteractionsReachTheSupervisor has an Agent relay a Resource's
// interaction through its Person Server within a mission, before and after
// the person routes it to a supervisor. The supervisor is told of both: the
// first in the replay of the mission's log entries, after the mission, and
// the second as it happens. Neither carries the interaction code.
func TestRelayedInteractionsReachTheSupervisor(t *testing.T) {
	t.Parallel()
	world := newSupervisionWorld(t, supervisionWorldOptions{})
	config := world.personConfig
	config.Tokens = testutil.NewMissionInteractionRelayStore()
	config.Permission = nil
	config.InteractionRelay = &personserver.InteractionRelayConfig{
		Policy: func(context.Context, personserver.InteractionRelayPolicyRequest) (personserver.InteractionRelayPendingPolicy, error) {
			return personserver.InteractionRelayPendingPolicy{Lifetime: time.Minute, RetryAfter: time.Second}, nil
		},
	}
	people, err := personserver.NewPSAuthorization(config)
	if err != nil {
		t.Fatal(err)
	}
	world.people = people
	world.network.Handle(supervisedPersonID, people.Handler())
	home := world.addSupervisor(homeSupervisorID, true, func(supervisionserver.DecisionRequest) supervisionserver.DecisionResult {
		return decided(supervision.Decision{Verdict: supervision.VerdictAllow})
	})
	assistant, assistantID := world.newAgent("assistant")
	ctx := world.ctx

	proposal, err := assistant.BeginMission(ctx, clientagent.MissionRequest{
		PersonServer: supervisedPersonID, Proposal: aauth.MissionProposal{Description: "# Sign up for records"},
	})
	if err != nil {
		t.Fatal(err)
	}
	approval, ok := proposal.Approval()
	if !ok {
		t.Fatal("the mission was not approved")
	}
	mission := approval.Mission()
	relay := func(url string) {
		t.Helper()
		result, err := assistant.RequestInteractionRelay(ctx, clientagent.InteractionRelayRequest{
			PersonServer: supervisedPersonID,
			Relay: aauth.InteractionRelay{
				Type: aauth.InteractionRelayInteraction, URL: url, Code: "A1B2-C3D4", MissionS256: mission.S256,
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := result.Pending(); !ok {
			t.Fatal("the Person Server did not relay the interaction")
		}
	}
	relay("https://records.example/consent")
	route := personserver.Supervisor{Issuer: homeSupervisorID, Subject: "home-person-1"}
	world.route(assistantID, route)
	relay("https://records.example/payment")
	if _, err := world.people.DeliverSupervisionEvents(ctx, route); err != nil {
		t.Fatal(err)
	}

	told := home.told()
	approved := slices.Index(told, "approved")
	first := slices.Index(told, string(supervision.EventInteractionRequested))
	if len(told) == 0 || told[0] != "agent.bound" || approved < 0 || first < approved {
		t.Fatalf("the supervisor was told %v, want the binding and the mission before its log entries", told)
	}
	interactions := home.events(supervision.EventInteractionRequested)
	if len(interactions) != 2 ||
		interactions[0].URL != "https://records.example/consent" || interactions[1].URL != "https://records.example/payment" {
		t.Fatalf("interaction.requested = %#v, want both relayed interactions in order", interactions)
	}
	for _, event := range interactions {
		if event.Type != "interaction" || event.MissionS256 != mission.S256 || event.Agent != assistantID || event.Subject != route.Subject {
			t.Fatalf("interaction.requested = %#v", event)
		}
	}
}
