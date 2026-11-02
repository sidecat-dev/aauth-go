package integration_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
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

const supervisedCalendarID = "https://calendar.example"

// supervisedInteractionWorld is a supervision world whose Person Server also
// accepts Resource-initiated interaction, with a Resource whose tokens carry
// one.
type supervisedInteractionWorld struct {
	*supervisionWorld
	calendar *resource.Server
	served   int
}

func newSupervisedInteractionWorld(t *testing.T) *supervisedInteractionWorld {
	t.Helper()
	world := &supervisedInteractionWorld{supervisionWorld: newSupervisionWorld(t, supervisionWorldOptions{})}
	config := world.personConfig
	config.AuthorizationInteractions = testutil.NewDeferredAuthorizationStore()
	config.ResourceInteraction = &personserver.ResourceInteractionConfig{
		Policy: func(context.Context, personserver.AuthorizationRequest) (personserver.AuthorizationInteractionPolicy, error) {
			return personserver.AuthorizationInteractionPolicy{URL: supervisedPersonID + "/consent", Lifetime: 4 * time.Minute}, nil
		},
		CallbackURL: supervisedPersonID + "/from-resource", Admit: admitExampleOrigins,
	}
	people, err := personserver.NewPSAuthorization(config)
	if err != nil {
		t.Fatal(err)
	}
	world.people = people
	world.network.Handle(supervisedPersonID, people.Handler())
	world.calendar, err = resource.NewPSAuthorization(resource.PSAuthorizationConfig{
		Issuer: supervisedCalendarID, SigningKey: newSigningKey(t, "supervised-calendar"), KeyResolver: world.resolver,
		Clock: world.clock, NewID: world.id,
		ScopeDescriptions: map[string]string{"calendar.read": "Read your calendar", "calendar.write": "Change your calendar"},
		RequiredScopes:    func(*http.Request) []string { return []string{"calendar.read", "calendar.write"} },
		ResolvePerson:     func(context.Context, resource.PersonIdentity, resource.PersonContext) error { return nil },
		InitiatedInteraction: &resource.InitiatedInteractionConfig{
			URL:     supervisedCalendarID + "/connect",
			Require: func(context.Context, resource.InitiatedInteractionRequest) (bool, error) { return true, nil },
			Store:   testutil.NewInitiatedInteractionStore(),
		},
		Protected: http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
			world.served++
			_, _ = io.WriteString(response, "calendar")
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	world.network.Handle(supervisedCalendarID, world.calendar.Handler())
	return world
}

// beginExchange obtains a resource token that carries the Resource's
// interaction and presents it to the Person Server.
func (world *supervisedInteractionWorld) beginExchange(t *testing.T, client *clientagent.Client) (clientagent.ExchangeResult, string) {
	t.Helper()
	personResult, err := client.PersonToken(world.ctx, clientagent.PersonTokenRequest{
		PersonServer: supervisedPersonID, Resource: supervisedCalendarID,
	})
	if err != nil {
		t.Fatal(err)
	}
	personToken, ok := personResult.Token()
	if !ok {
		t.Fatal("person token was not issued immediately")
	}
	resourceToken, err := client.Authorize(world.ctx, clientagent.AuthorizeRequest{
		Resource: supervisedCalendarID, PersonToken: personToken, Scopes: []string{"calendar.read", "calendar.write"},
	})
	if err != nil {
		t.Fatal(err)
	}
	claims, err := aauth.VerifyResourceToken(world.ctx, resourceToken, world.resolver, world.clock)
	if err != nil || claims.Interaction == nil {
		t.Fatalf("resource token interaction = %#v, %v", claims.Interaction, err)
	}
	result, err := client.BeginExchange(world.ctx, clientagent.ExchangeRequest{
		PersonServer: supervisedPersonID, ResourceToken: resourceToken, PresentedToken: personToken,
		Capabilities: []string{"interaction"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return result, claims.Interaction.URL
}

// completeAtResource plays the person: the Person Server's interstitial, the
// Resource's own flow, and the return to the Person Server, which issues the
// supervised request's auth token with no consent of its own.
func (world *supervisedInteractionWorld) completeAtResource(t *testing.T, pending clientagent.PendingExchange, claimURL string) {
	t.Helper()
	parsed, err := url.Parse(pending.InteractionURL())
	if err != nil {
		t.Fatal(err)
	}
	reference := strings.TrimPrefix(parsed.Path, "/consent/")
	visit, err := world.people.ConsumeAuthorizationInteractionCode(world.ctx, reference, pending.InteractionCode())
	if err != nil {
		t.Fatal(err)
	}
	if !visit.Supervised() {
		t.Fatal("the supervised request reads as the host's to decide")
	}
	decision := personserver.AuthorizationDecision{Scopes: []string{"calendar.read", "calendar.write"}, Lifetime: time.Hour}
	if err := world.people.ApproveAuthorizationInteraction(world.ctx, visit, decision); !errors.Is(err, personserver.ErrSupervisedAuthorization) {
		t.Fatalf("host consent for a supervised request = %v, want ErrSupervisedAuthorization", err)
	}
	redirect, err := world.people.RedirectToResourceInteraction(world.ctx, visit, "")
	if err != nil {
		t.Fatal(err)
	}
	target, err := url.Parse(redirect)
	if err != nil || target.Scheme+"://"+target.Host+target.Path != claimURL {
		t.Fatalf("redirect %q does not target the claim URL %q", redirect, claimURL)
	}
	resourceVisit, err := aauth.ParseInteractionVisit(target.RawQuery, aauth.InteractionVisitOptions{})
	if err != nil {
		t.Fatal(err)
	}
	atResource, err := world.calendar.ConsumeInitiatedInteraction(world.ctx, strings.TrimPrefix(target.Path, "/connect/"), resourceVisit)
	if err != nil {
		t.Fatal(err)
	}
	completion, err := atResource.CompletionURL()
	if err != nil {
		t.Fatal(err)
	}
	back, err := url.Parse(completion)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(strings.TrimPrefix(back.Path, "/from-resource/"), "/")
	if len(parts) != 2 {
		t.Fatalf("callback path = %q", back.Path)
	}
	if _, err := world.people.ReceiveResourceInteractionCallback(world.ctx, parts[0], parts[1], back.RawQuery); err != nil {
		t.Fatal(err)
	}
}

// authToken returns the exchange's auth token and its verified claims.
func (world *supervisedInteractionWorld) authToken(t *testing.T, result clientagent.ExchangeResult) (string, aauth.AuthTokenClaims) {
	t.Helper()
	authToken, ok := result.Token()
	if !ok {
		t.Fatalf("exchange did not complete: %#v", result)
	}
	claims, err := aauth.VerifyAuthToken(world.ctx, authToken, world.resolver, world.clock)
	if err != nil {
		t.Fatal(err)
	}
	return authToken, claims
}

// callCalendar presents the auth token to the Resource.
func (world *supervisedInteractionWorld) callCalendar(t *testing.T, client *clientagent.Client, authToken string) {
	t.Helper()
	request, err := http.NewRequestWithContext(world.ctx, http.MethodGet, supervisedCalendarID+"/events", nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Do(world.ctx, clientagent.Call{Request: request, AuthToken: authToken})
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || world.served != 1 {
		t.Fatalf("call = %d, served %d", response.StatusCode, world.served)
	}
}

// TestSupervisorAllowsAResourceInitiatedInteraction: the supervisor decides
// the auth-token request at once, narrowing its scope; the Person Server then
// sends the person to the Resource's own flow and, when the Resource returns
// the person, issues within the allow. The allow also brings the token's exp
// earlier than the Person Server would issue, and the Person Server applies
// it. The Person Server's own policy and the host's consent decide nothing,
// and the token is reported under the decision's sdi.
func TestSupervisorAllowsAResourceInitiatedInteraction(t *testing.T) {
	t.Parallel()
	world := newSupervisedInteractionWorld(t)
	route := personserver.Supervisor{Issuer: homeSupervisorID, Subject: "home-person-1"}
	bound := world.clock.Now().Add(3 * time.Minute).Unix()
	host := world.addSupervisor(homeSupervisorID, true, func(request supervisionserver.DecisionRequest) supervisionserver.DecisionResult {
		if request.Request.Kind == supervision.KindAuthToken {
			return decided(supervision.Decision{Verdict: supervision.VerdictAllow, Scope: "calendar.read", ExpiresAt: bound})
		}
		return decided(supervision.Decision{Verdict: supervision.VerdictAllow})
	})
	client, agentID := world.newAgent("planner")
	world.route(agentID, route)

	result, claimURL := world.beginExchange(t, client)
	pending, ok := result.Pending()
	if !ok || pending.Requirement() != aauth.RequirementInteraction || !strings.HasPrefix(pending.InteractionURL(), supervisedPersonID+"/consent/") {
		t.Fatalf("supervised exchange = %#v, %t", pending, ok)
	}
	world.completeAtResource(t, pending, claimURL)
	world.advance(5 * time.Second)
	approved, err := client.PollExchange(world.ctx, pending)
	if err != nil {
		t.Fatal(err)
	}
	// The Resource requires both scopes, so the narrowed token is not
	// presented to it.
	_, claims := world.authToken(t, approved)
	if claims.Scope != "calendar.read" || claims.Audience != supervisedCalendarID {
		t.Fatalf("auth token scope %q for %q, want the supervisor's narrowing", claims.Scope, claims.Audience)
	}
	if claims.ExpiresAt != bound {
		t.Fatalf("auth token exp %d, want the supervisor's %d", claims.ExpiresAt, bound)
	}
	if _, err := world.people.DeliverSupervisionEvents(world.ctx, route); err != nil {
		t.Fatal(err)
	}
	var sdi string
	for _, asked := range host.asked() {
		if asked.Request.Kind == supervision.KindAuthToken {
			sdi = asked.Request.SDI
		}
	}
	issued := host.events(supervision.EventAuthTokenIssued)
	if sdi == "" || len(issued) != 1 || issued[0].SDI != sdi || issued[0].JTI != claims.JTI {
		t.Fatalf("auth_token.issued = %#v, want one under sdi %q", issued, sdi)
	}
}

// TestPersonAllowsAResourceInitiatedInteractionTheSupervisorAsked: the
// supervisor asks; the Agent waits at its supervised pending URL. After the
// person allows, that same URL names the Person Server's interaction, the
// person completes the Resource's flow, and the Agent's next poll there
// receives the auth token.
func TestPersonAllowsAResourceInitiatedInteractionTheSupervisorAsked(t *testing.T) {
	t.Parallel()
	world := newSupervisedInteractionWorld(t)
	route := personserver.Supervisor{Issuer: homeSupervisorID, Subject: "home-person-1"}
	host := world.addSupervisor(homeSupervisorID, true, func(request supervisionserver.DecisionRequest) supervisionserver.DecisionResult {
		if request.Request.Kind == supervision.KindAuthToken {
			return decided(supervision.Decision{Verdict: supervision.VerdictAsk, Summary: "The calendar needs its own sign-in."})
		}
		return decided(supervision.Decision{Verdict: supervision.VerdictAllow})
	})
	client, agentID := world.newAgent("assistant")
	world.route(agentID, route)

	result, claimURL := world.beginExchange(t, client)
	waiting, ok := result.Pending()
	if !ok || waiting.Requirement() != aauth.RequirementApproval {
		t.Fatalf("asked exchange = %#v, %t", waiting, ok)
	}
	location := waiting.Location()
	reviews, err := world.people.PendingSupervision(world.ctx, 10)
	if err != nil || len(reviews) != 1 {
		t.Fatalf("pending supervision = %#v, %v", reviews, err)
	}
	if err := world.people.ResolveSupervision(world.ctx, reviews[0].Reference, personserver.SupervisionAnswer{Answer: supervision.AnswerAllow}); err != nil {
		t.Fatal(err)
	}
	world.advance(5 * time.Second)
	polled, err := client.PollExchange(world.ctx, waiting)
	if err != nil {
		t.Fatal(err)
	}
	interacting, ok := polled.Pending()
	if !ok || interacting.Location() != location || interacting.Requirement() != aauth.RequirementInteraction ||
		!strings.HasPrefix(interacting.InteractionURL(), supervisedPersonID+"/consent/") {
		t.Fatalf("poll after the person allowed = %#v, %t (Location %q)", interacting, ok, location)
	}
	world.advance(5 * time.Second)
	again, err := client.PollExchange(world.ctx, interacting)
	if err != nil {
		t.Fatal(err)
	}
	if next, ok := again.Pending(); !ok || next.Location() != location {
		t.Fatalf("poll before the Resource's flow = %#v, %t", again, ok)
	}
	world.completeAtResource(t, interacting, claimURL)
	world.advance(5 * time.Second)
	approved, err := client.PollExchange(world.ctx, interacting)
	if err != nil {
		t.Fatal(err)
	}
	authToken, claims := world.authToken(t, approved)
	if claims.Scope != "calendar.read calendar.write" {
		t.Fatalf("auth token scope = %q", claims.Scope)
	}
	world.callCalendar(t, client, authToken)
	world.advance(5 * time.Second)
	if _, err := client.PollExchange(world.ctx, interacting); err == nil {
		t.Fatal("the supervised pending URL answered after the token was delivered")
	}
	if _, err := world.people.DeliverSupervisionEvents(world.ctx, route); err != nil {
		t.Fatal(err)
	}
	resolved := host.events(supervision.EventDecisionResolved)
	issued := host.events(supervision.EventAuthTokenIssued)
	if len(resolved) != 1 || len(issued) != 1 || issued[0].SDI != resolved[0].SDI || issued[0].JTI != claims.JTI {
		t.Fatalf("decision.resolved = %#v, auth_token.issued = %#v", resolved, issued)
	}
}
