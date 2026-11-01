package supervisionserver_test

import (
	"context"
	"testing"

	"gitlab.com/sidecat-dev/aauth-go/supervision"
)

// Reach of an Answer: the SS remembers an answer the person gave for the
// mission or always, and applies it, before its policy, to the Agent's later
// acts of the same kind. An answer given once, an act of another kind, and an
// act under a mission that ended go to the policy.
func TestStandingAnswersDecideLaterActsOfTheSameKind(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	ctx := context.Background()
	f.connectSubject(t, f.ps, subject)
	trip := f.approve(t, missionBlob)
	second := f.approve(t, []byte(`{"agent":"aauth:assistant@agent.example","approver":"https://ps.example","description":"# Plan a second trip"}`))
	f.setDecide(decided(supervision.Decision{Verdict: supervision.VerdictAsk, Summary: "Ask the person."}))
	act := func(sdi, mission, action string) supervision.Outcome {
		t.Helper()
		request := f.request(supervision.KindPermission, sdi, mission)
		if action != "" {
			request.Action = action
		}
		return supervise(t, f.ps, request)
	}
	resolve := func(sdi, mission string, answer supervision.Answer, apply string) {
		t.Helper()
		outcome, err := f.ps.PostEvent(ctx, supervisor, supervision.Event{
			Name: supervision.EventDecisionResolved, ID: "e-" + sdi, SDI: sdi, IssuedAt: f.clock.Now().Unix(),
			Subject: subject, Agent: agentID, MissionS256: mission, Answer: answer, Apply: apply,
		})
		if err != nil || !outcome.Accepted {
			t.Fatalf("decision.resolved for %s = %#v, %v", sdi, outcome, err)
		}
	}
	asked := func() int { return len(f.decisionRequests()) }

	requireVerdict(t, act("d-1", trip, ""), supervision.VerdictAsk)
	resolve("d-1", trip, supervision.AnswerAllow, supervision.ApplyOnce)
	requireVerdict(t, act("d-2", trip, ""), supervision.VerdictAsk)
	resolve("d-2", trip, supervision.AnswerAllow, supervision.ApplyMission)
	before := asked()
	requireVerdict(t, act("d-3", trip, ""), supervision.VerdictAllow)
	if asked() != before {
		t.Fatal("the policy was asked about an act the person's answer for the mission decides")
	}
	requireVerdict(t, act("d-4", second, ""), supervision.VerdictAsk)
	requireVerdict(t, act("d-5", trip, "DeleteEmail"), supervision.VerdictAsk)

	resolve("d-4", second, supervision.AnswerDeny, supervision.ApplyAlways)
	requireVerdict(t, act("d-6", "", ""), supervision.VerdictDeny)
	requireVerdict(t, act("d-7", trip, ""), supervision.VerdictDeny)
	resolve("d-5", trip, supervision.AnswerAllow, supervision.ApplyMission)
	before = asked()
	requireVerdict(t, act("d-8", trip, "DeleteEmail"), supervision.VerdictAllow)
	if asked() != before {
		t.Fatal("the policy was asked about an act the person's latest answer decides")
	}

	terminated, err := f.ps.PostReport(ctx, supervisor, supervision.Report{
		Action: supervision.ReportTerminated, ID: "e-trip-ended", IssuedAt: f.clock.Now().Unix(),
		Subject: subject, Agent: agentID, MissionS256: trip, Reason: "completed",
	})
	if err != nil || !terminated.Accepted {
		t.Fatalf("terminated report = %#v, %v", terminated, err)
	}
	answers, err := f.store.StandingAnswers(ctx, personServer, subject, agentID)
	if err != nil || len(answers) != 1 || answers[0].MissionS256 != "" || answers[0].Answer != supervision.AnswerDeny {
		t.Fatalf("standing answers after the mission ended = %#v, %v; want only the answer for always", answers, err)
	}
}
