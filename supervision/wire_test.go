package supervision_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/supervision"
)

const (
	testAgent = "aauth:assistant@agent.example"
	testToken = "eyJhbGciOiJFZDI1NTE5In0.eyJzdWIiOiJ4In0.c2ln"
	testS256  = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
)

func envelope(kind supervision.Kind) supervision.Request {
	return supervision.Request{Kind: kind, SDI: "d-1", IssuedAt: 1790600000, Subject: "sub-1", Agent: testAgent}
}

// TestRequestsRoundTripThroughTheirEndpoints encodes one request of each kind
// and decodes it as the SS receives it, at the endpoint it is sent to.
func TestRequestsRoundTripThroughTheirEndpoints(t *testing.T) {
	proposal := envelope(supervision.KindMissionProposal)
	proposal.AgentToken, proposal.Description = testToken, "# Plan"
	proposal.Resources = []string{"https://flights.example"}
	update := envelope(supervision.KindMissionUpdate)
	update.MissionS256, update.Description = testS256, "Hotel changed."
	completion := envelope(supervision.KindMissionCompletion)
	completion.MissionS256, completion.Summary = testS256, "Booked."
	personToken := envelope(supervision.KindPersonToken)
	personToken.AgentToken, personToken.Resource = testToken, "https://calendar.example"
	authToken := envelope(supervision.KindAuthToken)
	authToken.AgentToken, authToken.ResourceToken, authToken.PresentedToken = testToken, testToken, testToken
	authToken.Justification = "Find a free week."
	permission := envelope(supervision.KindPermission)
	permission.Action, permission.Parameters = "SendEmail", []byte(`{"to":"user@example.com"}`)

	for _, request := range []supervision.Request{proposal, update, completion, personToken, authToken, permission} {
		body, err := request.Encode()
		if err != nil {
			t.Fatalf("%s: %v", request.Kind, err)
		}
		var decoded supervision.Request
		switch request.Kind {
		case supervision.KindMissionProposal:
			decoded, err = supervision.DecodeMissionProposal(body)
		case supervision.KindMissionUpdate, supervision.KindMissionCompletion:
			var action *supervision.Request
			action, _, err = supervision.DecodeMissionAction(testS256, body)
			if action != nil {
				decoded = *action
			}
		default:
			decoded, err = supervision.DecodeDecisionRequest(body)
		}
		if err != nil {
			t.Fatalf("%s: decode %s: %v", request.Kind, body, err)
		}
		again, err := decoded.Encode()
		if err != nil || string(again) != string(body) {
			t.Fatalf("%s: re-encoded %s, want %s", request.Kind, again, body)
		}
	}
	body, _ := permission.Encode()
	if want := `{"act":"permission","sdi":"d-1","iat":1790600000,"sub":"sub-1","agent":"` + testAgent + `","action":"SendEmail","parameters":{"to":"user@example.com"}}`; string(body) != want {
		t.Fatalf("permission body = %s, want %s", body, want)
	}
}

// TestRequestsCarryOnlyTheirKindsMembers refuses requests that omit a
// required member, carry one their kind does not define, or name an
// unrecognized act or action.
func TestRequestsCarryOnlyTheirKindsMembers(t *testing.T) {
	missingResource := envelope(supervision.KindPersonToken)
	missingResource.AgentToken = testToken
	strayScope := envelope(supervision.KindPermission)
	strayScope.Action, strayScope.ResourceToken = "SendEmail", testToken
	noSDI := envelope(supervision.KindPermission)
	noSDI.Action, noSDI.SDI = "SendEmail", ""
	for name, request := range map[string]supervision.Request{
		"missing resource": missingResource, "member of another kind": strayScope, "missing sdi": noSDI,
	} {
		if _, err := request.Encode(); err == nil {
			t.Errorf("%s: encoded", name)
		}
	}
	for name, body := range map[string]string{
		"unknown act":    `{"act":"payment","sdi":"d-1","iat":1,"sub":"s","agent":"` + testAgent + `"}`,
		"missing act":    `{"sdi":"d-1","iat":1,"sub":"s","agent":"` + testAgent + `","action":"SendEmail"}`,
		"case variant":   `{"Act":"permission","sdi":"d-1","iat":1,"sub":"s","agent":"` + testAgent + `","action":"x"}`,
		"trailing value": `{"act":"permission","sdi":"d-1","iat":1,"sub":"s","agent":"` + testAgent + `","action":"x"} {}`,
	} {
		_, err := supervision.DecodeDecisionRequest([]byte(body))
		var requestError *supervision.RequestError
		if !errors.As(err, &requestError) {
			t.Errorf("%s: err = %v, want a RequestError", name, err)
		}
	}
	if _, _, err := supervision.DecodeMissionAction(testS256, []byte(`{"action":"pause","id":"e-1"}`)); err == nil {
		t.Error("an unrecognized mission action decoded")
	}
}

// TestDecisionsCarryOnlyWhatTheirVerdictAndKindAllow checks the members a
// decision may carry for the request it answers.
func TestDecisionsCarryOnlyWhatTheirVerdictAndKindAllow(t *testing.T) {
	expires := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	valid := []struct {
		kind     supervision.Kind
		decision supervision.Decision
	}{
		{supervision.KindAuthToken, supervision.Decision{SDI: "d-1", Verdict: supervision.VerdictAllow, Scope: "calendar.read", ExpiresAt: 1790603600}},
		{supervision.KindPersonToken, supervision.Decision{SDI: "d-1", Verdict: supervision.VerdictAllow, ExpiresAt: 1790603600}},
		{supervision.KindMissionProposal, supervision.Decision{SDI: "d-1", Verdict: supervision.VerdictAllow, Mission: &supervision.MissionTerms{
			Description: "# Plan", ApprovedResources: []string{"https://flights.example"}, ExpiresAt: &expires,
		}}},
		{supervision.KindPermission, supervision.Decision{SDI: "d-1", Verdict: supervision.VerdictDeny, Reason: "Not now."}},
		{supervision.KindMissionProposal, supervision.Decision{SDI: "d-1", Verdict: supervision.VerdictAsk, Summary: "Large budget.",
			Recommendation: supervision.VerdictAllow, Proposed: &supervision.MissionTerms{Description: "# Smaller plan"},
			ApplyOptions: []supervision.ApplyOption{{Value: supervision.ApplyOnce, Label: "This one"}}}},
	}
	for _, test := range valid {
		body, err := test.decision.Encode(test.kind)
		if err != nil {
			t.Fatalf("%s %s: %v", test.kind, test.decision.Verdict, err)
		}
		decoded, err := supervision.DecodeDecision(test.kind, body)
		if err != nil {
			t.Fatalf("%s %s: decode %s: %v", test.kind, test.decision.Verdict, body, err)
		}
		if again, _ := decoded.Encode(test.kind); string(again) != string(body) {
			t.Fatalf("%s: re-encoded %s, want %s", test.kind, again, body)
		}
	}
	invalid := map[string]struct {
		kind     supervision.Kind
		decision supervision.Decision
	}{
		"scope on a person token":       {supervision.KindPersonToken, supervision.Decision{SDI: "d-1", Verdict: supervision.VerdictAllow, Scope: "a"}},
		"scope on a deny":               {supervision.KindAuthToken, supervision.Decision{SDI: "d-1", Verdict: supervision.VerdictDeny, Scope: "a"}},
		"proposal allow without terms":  {supervision.KindMissionProposal, supervision.Decision{SDI: "d-1", Verdict: supervision.VerdictAllow}},
		"terms on a permission":         {supervision.KindPermission, supervision.Decision{SDI: "d-1", Verdict: supervision.VerdictAllow, Mission: &supervision.MissionTerms{Description: "x"}}},
		"reason on an allow":            {supervision.KindPermission, supervision.Decision{SDI: "d-1", Verdict: supervision.VerdictAllow, Reason: "x"}},
		"summary on an allow":           {supervision.KindPermission, supervision.Decision{SDI: "d-1", Verdict: supervision.VerdictAllow, Summary: "x"}},
		"proposed outside a proposal":   {supervision.KindPermission, supervision.Decision{SDI: "d-1", Verdict: supervision.VerdictAsk, Proposed: &supervision.MissionTerms{Description: "x"}}},
		"repeated apply value":          {supervision.KindPermission, supervision.Decision{SDI: "d-1", Verdict: supervision.VerdictAsk, ApplyOptions: []supervision.ApplyOption{{Value: "a", Label: "A"}, {Value: "a", Label: "B"}}}},
		"clarify is not a decision":     {supervision.KindPermission, supervision.Decision{SDI: "d-1", Verdict: "clarify"}},
		"recommendation other than two": {supervision.KindPermission, supervision.Decision{SDI: "d-1", Verdict: supervision.VerdictAsk, Recommendation: supervision.VerdictAsk}},
	}
	for name, test := range invalid {
		if _, err := test.decision.Encode(test.kind); err == nil {
			t.Errorf("%s: encoded", name)
		}
	}
	if _, err := supervision.DecodeDecision(supervision.KindPermission, []byte(`{"sdi":"d-1","status":"pending","decision":"allow"}`)); err == nil {
		t.Error("a pending body decoded as a decision")
	}
}

// TestReportsAndEventsNameWhatTheyReport checks an approved report's digest
// and the members events require.
func TestReportsAndEventsNameWhatTheyReport(t *testing.T) {
	blob := []byte(`{"agent":"` + testAgent + `","approved_at":"2026-10-31T09:00:00Z","description":"# Plan"}`)
	approved := supervision.Report{
		Action: supervision.ReportApproved, ID: "e-1", SDI: "d-1", IssuedAt: 1790600045, Subject: "sub-1",
		Agent: testAgent, MissionS256: aauth.MissionS256(blob), Mission: blob,
	}
	body, err := approved.Encode()
	if err != nil {
		t.Fatal(err)
	}
	_, report, err := supervision.DecodeMissionAction(approved.MissionS256, body)
	if err != nil || report == nil || string(report.Mission) != string(blob) {
		t.Fatalf("approved report = %#v, %v", report, err)
	}
	if _, _, err := supervision.DecodeMissionAction(testS256, body); err == nil {
		t.Error("an approved report decoded under another mission's path")
	}
	approved.Mission = append([]byte(nil), blob[:len(blob)-1]...)
	if _, err := approved.Encode(); err == nil {
		t.Error("an approved report whose blob does not hash to s256 encoded")
	}
	resolved := supervision.Event{
		Name: supervision.EventDecisionResolved, ID: "e-2", SDI: "d-1", IssuedAt: 1790600130, Subject: "sub-1",
		Agent: testAgent, Answer: supervision.AnswerAllow, Supervisor: supervision.SupervisorUnavailable,
	}
	if _, err := resolved.Encode(); err != nil {
		t.Fatal(err)
	}
	resolved.Recommendation = supervision.VerdictDeny
	if _, err := resolved.Encode(); err == nil {
		t.Error("an unavailable supervisor's resolution carried a recommendation")
	}
	issued := supervision.Event{
		Name: supervision.EventAuthTokenIssued, ID: "e-3", IssuedAt: 1790600200, Subject: "sub-1", Agent: testAgent,
		JTI: "t-1", Audience: "https://calendar.example", ExpiresAt: 1790603800, Issuer: "https://ps.example",
	}
	if _, err := issued.Encode(); err == nil || !strings.Contains(err.Error(), "sdi") {
		t.Errorf("an issued token without its sdi = %v", err)
	}
	if _, err := supervision.DecodeEvent([]byte(`{"event":"mission.paused","id":"e-4","iat":1,"sub":"s","agent":"` + testAgent + `"}`)); err == nil {
		t.Error("an unrecognized event decoded")
	}
}

// TestMetadataKeepsEndpointsOnTheIssuerOrigin refuses a metadata document
// that names an endpoint elsewhere or another issuer.
func TestMetadataKeepsEndpointsOnTheIssuerOrigin(t *testing.T) {
	good := `{"issuer":"https://ss.example","connect_endpoint":"https://ss.example/connect","mission_endpoint":"https://ss.example/mission",` +
		`"decision_endpoint":"https://ss.example/decision","event_endpoint":"https://ss.example/event"}`
	metadata, err := supervision.DecodeMetadata([]byte(good), "https://ss.example")
	if err != nil || metadata.Signs() {
		t.Fatalf("metadata %#v, %v", metadata, err)
	}
	if _, err := supervision.DecodeMetadata([]byte(good), "https://other.example"); err == nil {
		t.Error("metadata for another issuer decoded")
	}
	elsewhere := strings.Replace(good, "https://ss.example/event", "https://collector.example/event", 1)
	if _, err := supervision.DecodeMetadata([]byte(elsewhere), "https://ss.example"); err == nil {
		t.Error("an endpoint on another origin was accepted")
	}
}
