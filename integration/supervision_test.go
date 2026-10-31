package integration_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/accessserver"
	clientagent "gitlab.com/sidecat-dev/aauth-go/agent"
	"gitlab.com/sidecat-dev/aauth-go/agentprovider"
	"gitlab.com/sidecat-dev/aauth-go/personserver"
	"gitlab.com/sidecat-dev/aauth-go/resource"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
	"gitlab.com/sidecat-dev/aauth-go/supervision"
	"gitlab.com/sidecat-dev/aauth-go/supervisionserver"
	"gitlab.com/sidecat-dev/aauth-go/testutil"
)

const (
	supervisedProviderID = "https://agents.example"
	supervisedPersonID   = "https://person.example"
	supervisedResourceID = "https://records.example"
	homeSupervisorID     = "https://supervisor.example"
	workSupervisorID     = "https://governance.example"
)

// supervisionWorld is one person's Person Server with Agents, a Resource and
// supervision servers on an in-memory network. The Person Server's own
// policies fail the test when called for an Agent routed to a supervisor.
type supervisionWorld struct {
	t           *testing.T
	ctx         context.Context
	mu          sync.Mutex
	now         time.Time
	clock       aauth.Clock
	network     *logicalTransport
	httpClient  *http.Client
	resolver    signaturekey.KeyResolver
	provider    *agentprovider.Server
	people      *personserver.Server
	tokens      testutil.MissionStore
	store       *testutil.SupervisionStore
	routes      map[string]personserver.Supervisor
	supervisors map[string]*supervisorHost
	nextID      int
}

// supervisorHost is one supervision server and the host around it: its
// standing policy, what it was asked and what it was told.
type supervisorHost struct {
	issuer   string
	server   *supervisionserver.Server
	handler  http.Handler
	network  *logicalTransport
	mu       sync.Mutex
	decide   func(supervisionserver.DecisionRequest) supervisionserver.DecisionResult
	connect  func(supervisionserver.ConnectRequest) supervisionserver.ConnectResult
	requests []supervisionserver.DecisionRequest
	observed []supervisionserver.Observation
}

type supervisionWorldOptions struct {
	requireSigned bool
}

func newSupervisionWorld(t *testing.T, options supervisionWorldOptions) *supervisionWorld {
	t.Helper()
	world := &supervisionWorld{
		t: t, ctx: context.Background(), now: time.Date(2026, 10, 31, 9, 0, 0, 0, time.UTC),
		network: newLogicalTransport(), store: testutil.NewSupervisionStore(),
		tokens: testutil.NewMissionStore(), routes: map[string]personserver.Supervisor{},
		supervisors: map[string]*supervisorHost{},
	}
	world.clock = aauth.ClockFunc(func() time.Time {
		world.mu.Lock()
		defer world.mu.Unlock()
		return world.now
	})
	world.httpClient = &http.Client{Transport: world.network}
	resolver, err := signaturekey.NewHTTPKeyResolver(signaturekey.HTTPKeyResolverConfig{
		Client: world.httpClient, TransportEnforcesEgress: true, Clock: world.clock,
		Admit: admitExampleOrigins,
	})
	if err != nil {
		t.Fatal(err)
	}
	world.resolver = resolver
	world.provider, err = agentprovider.New(agentprovider.Config{
		Issuer: supervisedProviderID, SigningKey: newSigningKey(t, "supervision-ap"), Clock: world.clock,
		NewID: world.id,
	})
	if err != nil {
		t.Fatal(err)
	}
	world.people, err = personserver.NewPSAuthorization(personserver.PSAuthorizationConfig{
		Issuer: supervisedPersonID, SigningKey: newSigningKey(t, "supervision-ps"), KeyResolver: resolver,
		Clock: world.clock, NewID: world.id, Tokens: world.tokens,
		BindPerson: func(_ context.Context, request personserver.PersonTokenRequest) (personserver.Person, error) {
			return personserver.Person{Subject: "person-at-" + strings.TrimPrefix(request.Resource, "https://"), Lifetime: time.Hour}, nil
		},
		Authorize: func(_ context.Context, request personserver.AuthorizationRequest) (personserver.AuthorizationDecision, error) {
			world.hostDecided("Authorize", request.Agent)
			return personserver.AuthorizationDecision{Scopes: request.Scopes, Lifetime: time.Hour}, nil
		},
		Missions: &personserver.MissionConfig{
			Approve: func(_ context.Context, request personserver.MissionApprovalRequest) (personserver.MissionDecision, error) {
				world.hostDecided("Missions.Approve", request.Agent)
				return personserver.MissionDecision{Description: request.Proposal.Description, ApprovedResources: request.Proposal.Resources}, nil
			},
			AcceptUpdate: func(_ context.Context, request personserver.MissionUpdatePolicyRequest) error {
				world.hostDecided("Missions.AcceptUpdate", request.Agent)
				return nil
			},
			ConfirmPersonAcceptedCompletion: func(_ context.Context, request personserver.MissionCompletionPolicyRequest) error {
				world.hostDecided("Missions.ConfirmPersonAcceptedCompletion", request.Agent)
				return nil
			},
		},
		Permission: &personserver.PermissionConfig{
			Policy: func(_ context.Context, request personserver.PermissionPolicyRequest) (personserver.PermissionPolicyResult, error) {
				world.hostDecided("Permission.Policy", request.Agent)
				return personserver.PermissionPolicyResult{Immediate: &personserver.PermissionDecision{Permission: aauth.PermissionGranted}}, nil
			},
		},
		Supervision: &personserver.SupervisionConfig{
			Route: func(_ context.Context, agent personserver.SupervisedAgent) (personserver.Supervisor, bool, error) {
				world.mu.Lock()
				defer world.mu.Unlock()
				supervisor, ok := world.routes[agent.Agent]
				return supervisor, ok, nil
			},
			Store: world.store, HTTPClient: world.httpClient, Admit: admitExampleOrigins,
			RequireSignedDecisions: options.requireSigned,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	records, err := resource.NewPSAuthorization(resource.PSAuthorizationConfig{
		Issuer: supervisedResourceID, SigningKey: newSigningKey(t, "supervision-resource"), KeyResolver: resolver,
		Clock: world.clock, NewID: world.id,
		ScopeDescriptions: map[string]string{"records.read": "Read records", "records.write": "Change records"},
		RequiredScopes:    func(*http.Request) []string { return []string{"records.read", "records.write"} },
		ResolvePerson:     func(context.Context, resource.PersonIdentity, resource.PersonContext) error { return nil },
		Protected: http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(response, "records")
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	world.network.Handle(supervisedProviderID, world.provider.Handler())
	world.network.Handle(supervisedPersonID, world.people.Handler())
	world.network.Handle(supervisedResourceID, records.Handler())
	return world
}

func admitExampleOrigins(_ context.Context, endpoint string) error {
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Scheme != "https" || !strings.HasSuffix(parsed.Hostname(), ".example") {
		return errors.New("endpoint is not admitted: " + endpoint)
	}
	return nil
}

func (world *supervisionWorld) id() string {
	world.mu.Lock()
	defer world.mu.Unlock()
	world.nextID++
	return fmt.Sprintf("id-%d", world.nextID)
}

func (world *supervisionWorld) advance(duration time.Duration) {
	world.mu.Lock()
	defer world.mu.Unlock()
	world.now = world.now.Add(duration)
}

// hostDecided fails the test when the Person Server's own policy decides for
// an Agent that has a deciding supervisor.
func (world *supervisionWorld) hostDecided(policy, agent string) {
	world.mu.Lock()
	_, routed := world.routes[agent]
	world.mu.Unlock()
	if routed {
		world.t.Errorf("the Person Server's %s decided for supervised Agent %s", policy, agent)
	}
}

func (world *supervisionWorld) route(agent string, supervisor personserver.Supervisor) {
	world.mu.Lock()
	defer world.mu.Unlock()
	world.routes[agent] = supervisor
}

func (world *supervisionWorld) addSupervisor(
	issuer string,
	signed bool,
	decide func(supervisionserver.DecisionRequest) supervisionserver.DecisionResult,
) *supervisorHost {
	world.t.Helper()
	host := &supervisorHost{
		issuer: issuer, decide: decide,
		connect: func(supervisionserver.ConnectRequest) supervisionserver.ConnectResult {
			return supervisionserver.ConnectResult{Accept: true}
		},
	}
	config := supervisionserver.Config{
		Issuer: issuer, Name: "Supervisor at " + issuer, KeyResolver: world.resolver, Clock: world.clock,
		Store: testutil.NewSupervisorStore(),
		Connect: func(_ context.Context, request supervisionserver.ConnectRequest) (supervisionserver.ConnectResult, error) {
			host.mu.Lock()
			defer host.mu.Unlock()
			return host.connect(request), nil
		},
		Decide: func(_ context.Context, request supervisionserver.DecisionRequest) (supervisionserver.DecisionResult, error) {
			host.mu.Lock()
			host.requests = append(host.requests, request)
			decide := host.decide
			host.mu.Unlock()
			return decide(request), nil
		},
		Observe: func(_ context.Context, observation supervisionserver.Observation) error {
			host.mu.Lock()
			defer host.mu.Unlock()
			host.observed = append(host.observed, observation)
			return nil
		},
	}
	if signed {
		key := newSigningKey(world.t, "supervisor-key-"+strings.TrimPrefix(issuer, "https://"))
		config.SigningKey = &key
	}
	server, err := supervisionserver.New(config)
	if err != nil {
		world.t.Fatal(err)
	}
	host.server, host.handler, host.network = server, server.Handler(), world.network
	world.network.Handle(issuer, host.handler)
	world.supervisors[issuer] = host
	return host
}

// newAgent issues an Agent token and returns the Agent's client.
func (world *supervisionWorld) newAgent(local string) (*clientagent.Client, string) {
	world.t.Helper()
	agentID := "aauth:" + local + "@agents.example"
	key := newSigningKey(world.t, "agent-"+local)
	token, err := world.provider.Issue(aauth.AgentTokenRequest{
		Agent: agentID, PersonServer: supervisedPersonID, PublicKey: key.PublicJWK(), Lifetime: time.Hour,
	})
	if err != nil {
		world.t.Fatal(err)
	}
	client, err := clientagent.New(world.ctx, clientagent.Config{
		Identifier: agentID, SigningKey: key, AgentToken: token, KeyResolver: world.resolver,
		HTTPClient: world.httpClient, Clock: world.clock,
	})
	if err != nil {
		world.t.Fatal(err)
	}
	return client, agentID
}

// setOffline takes the supervisor off the network, as a machine that sleeps:
// nothing answers at its origin.
func (host *supervisorHost) setOffline(offline bool) {
	if offline {
		host.network.Handle(host.issuer, nil)
		return
	}
	host.network.Handle(host.issuer, host.handler)
}

func (host *supervisorHost) asked() []supervisionserver.DecisionRequest {
	host.mu.Lock()
	defer host.mu.Unlock()
	return append([]supervisionserver.DecisionRequest(nil), host.requests...)
}

// told returns the names of the events and reports the supervisor
// acknowledged, in order.
func (host *supervisorHost) told() []string {
	host.mu.Lock()
	defer host.mu.Unlock()
	var names []string
	for _, observation := range host.observed {
		if observation.Event != nil {
			names = append(names, string(observation.Event.Name))
		} else {
			names = append(names, string(observation.Report.Action))
		}
	}
	return names
}

func (host *supervisorHost) events(name supervision.EventName) []supervision.Event {
	host.mu.Lock()
	defer host.mu.Unlock()
	var events []supervision.Event
	for _, observation := range host.observed {
		if observation.Event != nil && observation.Event.Name == name {
			events = append(events, *observation.Event)
		}
	}
	return events
}

func (host *supervisorHost) reports() []supervision.Report {
	host.mu.Lock()
	defer host.mu.Unlock()
	var reports []supervision.Report
	for _, observation := range host.observed {
		if observation.Report != nil {
			reports = append(reports, *observation.Report)
		}
	}
	return reports
}

func decided(decision supervision.Decision) supervisionserver.DecisionResult {
	return supervisionserver.DecisionResult{Decision: &decision}
}

// TestSupervisorDecidesForSupervisedAgentAndAsksOnlyForExceptions runs one
// person's Agent through a whole mission with a supervisor that applies
// standing policy and asks the person only for an exception. The Person
// Server's own policies are never called for the Agent, the person's answer
// reaches the supervisor with the reach they gave it, and the supervisor then
// applies that reach without asking again.
func TestSupervisorDecidesForSupervisedAgentAndAsksOnlyForExceptions(t *testing.T) {
	t.Parallel()
	world := newSupervisionWorld(t, supervisionWorldOptions{})
	var reachMu sync.Mutex
	asksByActionSDI := map[string]string{}
	reach := map[string]string{}
	home := world.addSupervisor(homeSupervisorID, true, func(request supervisionserver.DecisionRequest) supervisionserver.DecisionResult {
		switch request.Request.Kind {
		case supervision.KindMissionProposal:
			return decided(supervision.Decision{Verdict: supervision.VerdictAllow, Mission: &supervision.MissionTerms{
				Description:       request.Request.Description + "\n\nDo not change records without asking.",
				ApprovedResources: request.Request.Resources,
			}})
		case supervision.KindAuthToken:
			return decided(supervision.Decision{Verdict: supervision.VerdictAllow, Scope: "records.read"})
		case supervision.KindPermission:
			reachMu.Lock()
			defer reachMu.Unlock()
			if request.Request.Action != "payments.send" || reach[request.Request.MissionS256+" "+request.Request.Action] == supervision.ApplyMission {
				return decided(supervision.Decision{Verdict: supervision.VerdictAllow})
			}
			asksByActionSDI[request.Request.SDI] = request.Request.Action
			return decided(supervision.Decision{
				Verdict: supervision.VerdictAsk, Summary: "The agent wants to send a payment.",
				Recommendation: supervision.VerdictDeny,
				ApplyOptions: []supervision.ApplyOption{
					{Value: supervision.ApplyOnce, Label: "This payment only"},
					{Value: supervision.ApplyMission, Label: "Any payment on this mission"},
				},
			})
		default:
			return decided(supervision.Decision{Verdict: supervision.VerdictAllow})
		}
	})
	// The supervisor's standing policy learns the reach of each answer.
	learn := func() {
		for _, event := range home.events(supervision.EventDecisionResolved) {
			reachMu.Lock()
			if action, ok := asksByActionSDI[event.SDI]; ok && event.Answer == supervision.AnswerAllow {
				reach[event.MissionS256+" "+action] = event.Apply
			}
			reachMu.Unlock()
		}
	}
	assistant, assistantID := world.newAgent("assistant")
	world.route(assistantID, personserver.Supervisor{Issuer: homeSupervisorID, Subject: "home-person-1"})
	ctx := world.ctx

	proposal, err := assistant.BeginMission(ctx, clientagent.MissionRequest{
		PersonServer: supervisedPersonID,
		Proposal:     aauth.MissionProposal{Description: "# Reconcile records", Resources: []string{supervisedResourceID}},
	})
	if err != nil {
		t.Fatal(err)
	}
	approval, ok := proposal.Approval()
	if !ok {
		t.Fatal("the supervisor's allow did not approve the mission at once")
	}
	mission := approval.Mission()
	if !strings.HasSuffix(mission.Blob.Description, "Do not change records without asking.") {
		t.Fatalf("approved description = %q, want the supervisor's refinement", mission.Blob.Description)
	}
	personToken, ok := approval.PersonToken(supervisedResourceID)
	if !ok {
		t.Fatal("the approval omitted the approved resource's person token")
	}
	resourceToken, err := assistant.Authorize(ctx, clientagent.AuthorizeRequest{
		Resource: supervisedResourceID, PersonToken: personToken, Scopes: []string{"records.read", "records.write"},
	})
	if err != nil {
		t.Fatal(err)
	}
	authToken, err := assistant.Exchange(ctx, clientagent.ExchangeRequest{
		PersonServer: supervisedPersonID, ResourceToken: resourceToken, PresentedToken: personToken,
	})
	if err != nil {
		t.Fatal(err)
	}
	authClaims, err := aauth.VerifyAuthToken(ctx, authToken, world.resolver, world.clock)
	if err != nil {
		t.Fatal(err)
	}
	if authClaims.Scope != "records.read" {
		t.Fatalf("auth token scope = %q, want the supervisor's narrowing to records.read", authClaims.Scope)
	}

	routine, err := assistant.RequestPermission(ctx, clientagent.PermissionRequest{
		PersonServer: supervisedPersonID, MissionS256: mission.S256, Action: "messages.send",
	})
	if err != nil {
		t.Fatal(err)
	}
	if decision, ok := routine.Decision(); !ok || decision.Permission() != aauth.PermissionGranted {
		t.Fatal("a routine permission was not granted at once")
	}

	exception, err := assistant.RequestPermission(ctx, clientagent.PermissionRequest{
		PersonServer: supervisedPersonID, MissionS256: mission.S256, Action: "payments.send",
		Description: "Pay the reconciliation fee",
	})
	if err != nil {
		t.Fatal(err)
	}
	pending, ok := exception.Pending()
	if !ok {
		t.Fatal("the supervisor's ask did not leave the permission pending")
	}
	reviews, err := world.people.PendingSupervision(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(reviews) != 1 || reviews[0].Kind != supervision.KindPermission || reviews[0].Ask == nil ||
		reviews[0].Ask.Summary != "The agent wants to send a payment." || reviews[0].Request.Action != "payments.send" ||
		len(reviews[0].ApplyOptions) != 2 || reviews[0].ApplyOptions[1].Value != supervision.ApplyMission {
		t.Fatalf("reviews = %#v, want the supervisor's ask with its reaches", reviews)
	}
	if err := world.people.ResolveSupervision(ctx, reviews[0].Reference, personserver.SupervisionAnswer{
		Answer: supervision.AnswerAllow, Apply: supervision.ApplyMission,
	}); err != nil {
		t.Fatal(err)
	}
	world.advance(5 * time.Second)
	granted, err := assistant.PollPermission(ctx, pending)
	if err != nil {
		t.Fatal(err)
	}
	if decision, ok := granted.Decision(); !ok || decision.Permission() != aauth.PermissionGranted {
		t.Fatal("the person's allow did not grant the permission")
	}
	resolved := home.events(supervision.EventDecisionResolved)
	if len(resolved) != 1 || resolved[0].Answer != supervision.AnswerAllow || resolved[0].Apply != supervision.ApplyMission ||
		resolved[0].Recommendation != supervision.VerdictDeny || resolved[0].Supervisor != "" {
		t.Fatalf("decision.resolved = %#v, want the person's allow with reach mission and the supervisor's recommendation", resolved)
	}
	learn()

	again, err := assistant.RequestPermission(ctx, clientagent.PermissionRequest{
		PersonServer: supervisedPersonID, MissionS256: mission.S256, Action: "payments.send",
	})
	if err != nil {
		t.Fatal(err)
	}
	if decision, ok := again.Decision(); !ok || decision.Permission() != aauth.PermissionGranted {
		t.Fatal("the supervisor did not apply the reach the person gave")
	}
	if _, err := assistant.UpdateMission(ctx, clientagent.MissionUpdateRequest{
		PersonServer: supervisedPersonID, MissionS256: mission.S256, Description: "Two records needed a second look.",
	}); err != nil {
		t.Fatal(err)
	}
	if err := assistant.CompleteMission(ctx, clientagent.MissionCompletionRequest{
		PersonServer: supervisedPersonID, MissionS256: mission.S256, Summary: "Reconciled 40 records.",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := world.people.DeliverSupervisionEvents(ctx, personserver.Supervisor{Issuer: homeSupervisorID, Subject: "home-person-1"}); err != nil {
		t.Fatal(err)
	}

	var kinds []supervision.Kind
	authSDI := ""
	for _, request := range home.asked() {
		kinds = append(kinds, request.Request.Kind)
		if request.Request.Subject != "home-person-1" || request.Request.Agent != assistantID {
			t.Fatalf("the supervisor saw sub %q agent %q", request.Request.Subject, request.Request.Agent)
		}
		if request.Request.Kind == supervision.KindAuthToken {
			authSDI = request.Request.SDI
			if request.Request.ResourceToken != resourceToken || request.Request.PresentedToken != personToken {
				t.Fatal("the supervisor did not see the tokens the Agent presented")
			}
		}
	}
	wantKinds := []supervision.Kind{
		supervision.KindMissionProposal, supervision.KindAuthToken, supervision.KindPermission,
		supervision.KindPermission, supervision.KindPermission, supervision.KindMissionUpdate,
		supervision.KindMissionCompletion,
	}
	if !slices.Equal(kinds, wantKinds) {
		t.Fatalf("the supervisor was asked %v, want %v", kinds, wantKinds)
	}
	wantTold := []string{
		"agent.bound", "approved", "person_token.issued", "auth_token.issued", "decision.resolved", "terminated",
	}
	if told := home.told(); !slices.Equal(told, wantTold) {
		t.Fatalf("the supervisor was told %v, want %v", told, wantTold)
	}
	issued := home.events(supervision.EventAuthTokenIssued)
	if len(issued) != 1 || issued[0].SDI != authSDI || issued[0].JTI != authClaims.JTI ||
		issued[0].Issuer != supervisedPersonID || issued[0].Scope != "records.read" {
		t.Fatalf("auth_token.issued = %#v, want the token under the auth decision's sdi", issued)
	}
	if reports := home.reports(); len(reports) != 2 || reports[0].MissionS256 != mission.S256 ||
		string(reports[0].Mission) != string(mission.ExactJSON) || reports[1].Reason != "completed" {
		t.Fatalf("mission reports = %#v", reports)
	}
}

// TestAgentsOfOnePersonGoToTheirOwnSupervisors routes a person's work Agent
// to an organization's supervisor, which accepts the person's tenant without
// interaction, and their personal Agent to their own supervisor, which they
// confirm. Each supervisor sees only its Agent, under its own directed sub.
// When the person moves the personal Agent to the organization's supervisor,
// the Person Server replays that Agent's active mission to it first.
func TestAgentsOfOnePersonGoToTheirOwnSupervisors(t *testing.T) {
	t.Parallel()
	world := newSupervisionWorld(t, supervisionWorldOptions{})
	allow := func(supervisionserver.DecisionRequest) supervisionserver.DecisionResult {
		return decided(supervision.Decision{Verdict: supervision.VerdictAllow})
	}
	work := world.addSupervisor(workSupervisorID, false, func(request supervisionserver.DecisionRequest) supervisionserver.DecisionResult {
		if request.Request.Kind == supervision.KindMissionProposal {
			return decided(supervision.Decision{Verdict: supervision.VerdictAllow, Mission: &supervision.MissionTerms{Description: request.Request.Description}})
		}
		return allow(request)
	})
	work.connect = func(request supervisionserver.ConnectRequest) supervisionserver.ConnectResult {
		return supervisionserver.ConnectResult{Accept: request.Tenant == "acme.example"}
	}
	home := world.addSupervisor(homeSupervisorID, true, func(request supervisionserver.DecisionRequest) supervisionserver.DecisionResult {
		if request.Request.Kind == supervision.KindMissionProposal {
			return decided(supervision.Decision{Verdict: supervision.VerdictAllow, Mission: &supervision.MissionTerms{Description: request.Request.Description}})
		}
		return allow(request)
	})
	home.connect = func(supervisionserver.ConnectRequest) supervisionserver.ConnectResult {
		return supervisionserver.ConnectResult{Interaction: &supervisionserver.ConnectInteraction{URL: homeSupervisorID + "/confirm"}}
	}
	worker, workerID := world.newAgent("worker")
	personal, personalID := world.newAgent("personal")
	workRoute := personserver.Supervisor{Issuer: workSupervisorID, Subject: "acme-person-7", Tenant: "acme.example"}
	homeRoute := personserver.Supervisor{Issuer: homeSupervisorID, Subject: "home-person-1"}
	world.route(workerID, workRoute)
	world.route(personalID, homeRoute)
	ctx := world.ctx

	// The person registers their own supervisor and confirms the Person
	// Server there.
	connection, err := world.people.ConnectSupervisor(ctx, homeRoute)
	if err != nil {
		t.Fatal(err)
	}
	if connection.State != personserver.SupervisorConnecting || connection.InteractionCode == "" {
		t.Fatalf("connection = %#v, want a confirmation for the person", connection)
	}
	reference := path.Base(strings.TrimSuffix(connection.InteractionURL, "/"))
	confirmation, err := home.server.ConsumeConnectCode(ctx, reference, connection.InteractionCode)
	if err != nil {
		t.Fatal(err)
	}
	if confirmation.PersonServer != supervisedPersonID {
		t.Fatalf("the supervisor showed the person %q", confirmation.PersonServer)
	}
	if err := home.server.ConfirmConnect(ctx, reference, "the person"); err != nil {
		t.Fatal(err)
	}
	if connection, err = world.people.PollSupervisorConnect(ctx, homeRoute); err != nil || connection.State != personserver.SupervisorConnected {
		t.Fatalf("connection = %#v, %v; want connected", connection, err)
	}

	for _, agent := range []*clientagent.Client{worker, personal} {
		result, err := agent.RequestPermission(ctx, clientagent.PermissionRequest{
			PersonServer: supervisedPersonID, Action: "files.read",
		})
		if err != nil {
			t.Fatal(err)
		}
		if decision, ok := result.Decision(); !ok || decision.Permission() != aauth.PermissionGranted {
			t.Fatal("permission was not granted")
		}
	}
	proposal, err := personal.BeginMission(ctx, clientagent.MissionRequest{
		PersonServer: supervisedPersonID, Proposal: aauth.MissionProposal{Description: "# Plan a weekend"},
	})
	if err != nil {
		t.Fatal(err)
	}
	approval, ok := proposal.Approval()
	if !ok {
		t.Fatal("mission was not approved")
	}
	mission := approval.Mission()
	for _, check := range []struct {
		host    *supervisorHost
		agent   string
		subject string
	}{{work, workerID, "acme-person-7"}, {home, personalID, "home-person-1"}} {
		for _, request := range check.host.asked() {
			if request.Request.Agent != check.agent || request.Request.Subject != check.subject {
				t.Fatalf("%s was asked about %s as %s", check.host.issuer, request.Request.Agent, request.Request.Subject)
			}
		}
	}

	// The person moves the personal Agent to the organization's supervisor.
	world.route(personalID, workRoute)
	if _, err := personal.RequestPermission(ctx, clientagent.PermissionRequest{
		PersonServer: supervisedPersonID, MissionS256: mission.S256, Action: "calendar.write",
	}); err != nil {
		t.Fatal(err)
	}
	asked := work.asked()
	last := asked[len(asked)-1]
	if last.Request.Agent != personalID || last.Mission == nil || string(last.Mission.Blob) != string(mission.ExactJSON) {
		t.Fatalf("the new supervisor decided without the replayed mission: %#v", last.Mission)
	}
	// Events reach a supervisor before the next request to it, or when the
	// host delivers them; home still holds the approval it was due.
	if _, err := world.people.DeliverSupervisionEvents(ctx, homeRoute); err != nil {
		t.Fatal(err)
	}
	homeBound := home.events(supervision.EventAgentBound)
	var replayedBound []supervision.Event
	for _, event := range work.events(supervision.EventAgentBound) {
		if event.Agent == personalID {
			replayedBound = append(replayedBound, event)
		}
	}
	if len(homeBound) != 1 || len(replayedBound) != 1 || replayedBound[0].ID != homeBound[0].ID {
		t.Fatalf("agent.bound at home %#v and replayed %#v, want one event under one id", homeBound, replayedBound)
	}
	if homeReports, workReports := home.reports(), work.reports(); len(homeReports) != 1 || len(workReports) != 1 ||
		workReports[0].ID != homeReports[0].ID || workReports[0].Subject != "acme-person-7" {
		t.Fatalf("approved at home %#v and replayed %#v, want the same report under the new sub", homeReports, workReports)
	}
}

// TestUnavailableSupervisorLeavesTheDecisionToThePerson takes a supervisor
// offline, as a machine that sleeps. The act goes to the person, who
// decides; the supervisor is told what they decided, in order, once it is
// reachable again. A supervisor that defers is polled by the host until it
// decides, and a deferral that outlives the Agent's wait ends as expired.
func TestUnavailableSupervisorLeavesTheDecisionToThePerson(t *testing.T) {
	t.Parallel()
	world := newSupervisionWorld(t, supervisionWorldOptions{})
	var deferMu sync.Mutex
	deferNext := false
	home := world.addSupervisor(homeSupervisorID, true, func(request supervisionserver.DecisionRequest) supervisionserver.DecisionResult {
		deferMu.Lock()
		defer deferMu.Unlock()
		if deferNext {
			return supervisionserver.DecisionResult{Defer: &supervisionserver.Deferral{}}
		}
		return decided(supervision.Decision{Verdict: supervision.VerdictAllow})
	})
	assistant, assistantID := world.newAgent("assistant")
	route := personserver.Supervisor{Issuer: homeSupervisorID, Subject: "home-person-1"}
	world.route(assistantID, route)
	ctx := world.ctx
	if _, err := world.people.ConnectSupervisor(ctx, route); err != nil {
		t.Fatal(err)
	}

	home.setOffline(true)
	result, err := assistant.PersonToken(ctx, clientagent.PersonTokenRequest{PersonServer: supervisedPersonID, Resource: supervisedResourceID})
	if err != nil {
		t.Fatal(err)
	}
	waiting, ok := result.Approval()
	if !ok {
		t.Fatal("the Person Server did not hold the request for the person")
	}
	reviews, err := world.people.PendingSupervision(ctx, 10)
	if err != nil || len(reviews) != 1 || !reviews[0].SupervisorUnavailable || reviews[0].Ask != nil {
		t.Fatalf("reviews = %#v, %v; want one with the supervisor unavailable", reviews, err)
	}
	if err := world.people.ResolveSupervision(ctx, reviews[0].Reference, personserver.SupervisionAnswer{Answer: supervision.AnswerAllow}); err != nil {
		t.Fatal(err)
	}
	world.advance(5 * time.Second)
	issued, err := waiting.Poll(ctx, clientagent.PollOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := issued.Value(); !ok {
		t.Fatal("the person's allow did not issue the person token")
	}
	entries := world.store.Log()
	if len(entries) == 0 || entries[len(entries)-1].Exchange != nil || entries[len(entries)-1].Outcome != "unavailable" {
		t.Fatalf("the log does not record that the supervisor was not consulted: %#v", entries)
	}

	home.setOffline(false)
	if _, err := world.people.DeliverSupervisionEvents(ctx, route); err != nil {
		t.Fatal(err)
	}
	if told := home.told(); !slices.Equal(told, []string{"agent.bound", "decision.resolved", "person_token.issued"}) {
		t.Fatalf("the supervisor was told %v", told)
	}
	resolved := home.events(supervision.EventDecisionResolved)
	tokenIssued := home.events(supervision.EventPersonTokenIssued)
	if resolved[0].Supervisor != supervision.SupervisorUnavailable || resolved[0].Answer != supervision.AnswerAllow ||
		resolved[0].Recommendation != "" || tokenIssued[0].SDI != resolved[0].SDI {
		t.Fatalf("decision.resolved %#v and person_token.issued %#v", resolved[0], tokenIssued[0])
	}

	// The supervisor takes its time over a permission.
	deferMu.Lock()
	deferNext = true
	deferMu.Unlock()
	permission, err := assistant.RequestPermission(ctx, clientagent.PermissionRequest{PersonServer: supervisedPersonID, Action: "files.delete"})
	if err != nil {
		t.Fatal(err)
	}
	pendingPermission, ok := permission.Pending()
	if !ok {
		t.Fatal("a deferred decision did not leave the permission pending")
	}
	reviews, err = world.people.PendingSupervision(ctx, 10)
	if err != nil || len(reviews) != 1 || reviews[0].State != personserver.SupervisedWaitingForSupervisor {
		t.Fatalf("reviews = %#v, %v; want one waiting on the supervisor", reviews, err)
	}
	if err := world.people.AdvanceSupervision(ctx, reviews[0].Reference); !errors.Is(err, personserver.ErrSupervisionNotReady) {
		t.Fatalf("an early advance = %v, want ErrSupervisionNotReady", err)
	}
	if err := home.server.ResolveDecision(ctx, supervisedPersonID, reviews[0].SDI, decided(supervision.Decision{Verdict: supervision.VerdictAllow})); err != nil {
		t.Fatal(err)
	}
	world.advance(5 * time.Second)
	if err := world.people.AdvanceSupervision(ctx, reviews[0].Reference); err != nil {
		t.Fatal(err)
	}
	granted, err := assistant.PollPermission(ctx, pendingPermission)
	if err != nil {
		t.Fatal(err)
	}
	if decision, ok := granted.Decision(); !ok || decision.Permission() != aauth.PermissionGranted {
		t.Fatal("the deferred allow did not grant the permission")
	}

	// A deferral the supervisor never resolves ends with the Agent's wait.
	slow, err := assistant.RequestPermission(ctx, clientagent.PermissionRequest{PersonServer: supervisedPersonID, Action: "files.share"})
	if err != nil {
		t.Fatal(err)
	}
	slowPending, _ := slow.Pending()
	world.advance(personserver.DefaultSupervisionPendingLifetime)
	if _, err := assistant.PollPermission(ctx, slowPending); err == nil {
		t.Fatal("an expired supervised request did not end")
	} else if problem := (*aauth.ProblemError)(nil); !errors.As(err, &problem) || problem.Status != http.StatusRequestTimeout {
		t.Fatalf("expired poll = %v, want 408 expired", err)
	}
	if _, err := world.people.DeliverSupervisionEvents(ctx, route); err != nil {
		t.Fatal(err)
	}
	resolved = home.events(supervision.EventDecisionResolved)
	if last := resolved[len(resolved)-1]; last.Answer != supervision.AnswerAbandoned || last.Supervisor != supervision.SupervisorUnavailable {
		t.Fatalf("decision.resolved after expiry = %#v, want abandoned with the supervisor unavailable", last)
	}
}

// TestSignedSupervisorDecisionsAreAVerifiableRecord checks that the Person
// Server's log entry for a signed decision verifies later from the record
// alone, that an altered entry does not, and that a Person Server requiring
// signed decisions puts the act to the person rather than accept an unsigned
// one.
func TestSignedSupervisorDecisionsAreAVerifiableRecord(t *testing.T) {
	t.Parallel()
	world := newSupervisionWorld(t, supervisionWorldOptions{})
	world.addSupervisor(homeSupervisorID, true, func(supervisionserver.DecisionRequest) supervisionserver.DecisionResult {
		return decided(supervision.Decision{Verdict: supervision.VerdictDeny, Reason: "Not during the freeze."})
	})
	assistant, assistantID := world.newAgent("assistant")
	world.route(assistantID, personserver.Supervisor{Issuer: homeSupervisorID, Subject: "home-person-1"})
	result, err := assistant.RequestPermission(world.ctx, clientagent.PermissionRequest{PersonServer: supervisedPersonID, Action: "deploy"})
	if err != nil {
		t.Fatal(err)
	}
	if decision, ok := result.Decision(); !ok || decision.Permission() != aauth.PermissionDenied || decision.Reason() != "Not during the freeze." {
		t.Fatal("the supervisor's deny did not reach the Agent with its reason")
	}
	var signed *supervision.Exchange
	for _, entry := range world.store.Log() {
		if entry.Kind == supervision.KindPermission && entry.Exchange != nil && entry.Exchange.Signed {
			signed = entry.Exchange
		}
	}
	if signed == nil {
		t.Fatal("no signed decision was logged")
	}
	world.advance(time.Hour)
	verified, err := supervision.VerifyExchange(world.ctx, *signed, world.resolver)
	if err != nil {
		t.Fatal(err)
	}
	if verified.Signer() != homeSupervisorID {
		t.Fatalf("signer = %q", verified.Signer())
	}
	altered := signed.Clone()
	altered.Response.Body = []byte(strings.Replace(string(altered.Response.Body), `"deny"`, `"allow"`, 1))
	if _, err := supervision.VerifyExchange(world.ctx, altered, world.resolver); err == nil {
		t.Fatal("an altered decision verified")
	}

	strict := newSupervisionWorld(t, supervisionWorldOptions{requireSigned: true})
	strict.addSupervisor(homeSupervisorID, false, func(supervisionserver.DecisionRequest) supervisionserver.DecisionResult {
		t.Error("a Person Server that requires signed decisions consulted an unsigned supervisor")
		return decided(supervision.Decision{Verdict: supervision.VerdictAllow})
	})
	strictAgent, strictID := strict.newAgent("assistant")
	strict.route(strictID, personserver.Supervisor{Issuer: homeSupervisorID, Subject: "home-person-1"})
	pending, err := strictAgent.RequestPermission(strict.ctx, clientagent.PermissionRequest{PersonServer: supervisedPersonID, Action: "deploy"})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := pending.Pending(); !ok {
		t.Fatal("an unsigned supervisor's act did not go to the person")
	}
}

// TestSupervisorClarifiesThroughThePersonServer relays a supervisor's
// question to the Agent and the Agent's answer back. It then has the person,
// asked about another request, question the Agent themselves; that chat is
// reported to the supervisor with the person's decision.
func TestSupervisorClarifiesThroughThePersonServer(t *testing.T) {
	t.Parallel()
	world := newSupervisionWorld(t, supervisionWorldOptions{})
	var exchanges sync.Map
	home := world.addSupervisor(homeSupervisorID, false, func(request supervisionserver.DecisionRequest) supervisionserver.DecisionResult {
		if request.Request.Kind != supervision.KindAuthToken {
			return decided(supervision.Decision{Verdict: supervision.VerdictAllow})
		}
		if _, seen := exchanges.LoadOrStore(request.Request.SDI, true); !seen {
			count := 0
			exchanges.Range(func(any, any) bool { count++; return true })
			if count > 1 {
				return decided(supervision.Decision{Verdict: supervision.VerdictAsk, Summary: "Unusual access."})
			}
		}
		if len(request.Rounds) == 0 {
			return supervisionserver.DecisionResult{Clarify: &supervision.Clarification{Question: "Which records, and why?"}}
		}
		if request.Rounds[0].Answer == "Only this week's invoices." {
			return decided(supervision.Decision{Verdict: supervision.VerdictAllow, Scope: "records.read"})
		}
		return decided(supervision.Decision{Verdict: supervision.VerdictDeny})
	})
	assistant, assistantID := world.newAgent("assistant")
	route := personserver.Supervisor{Issuer: homeSupervisorID, Subject: "home-person-1"}
	world.route(assistantID, route)
	ctx := world.ctx
	exchange := func() clientagent.PendingExchange {
		t.Helper()
		personResult, err := assistant.PersonToken(ctx, clientagent.PersonTokenRequest{PersonServer: supervisedPersonID, Resource: supervisedResourceID})
		if err != nil {
			t.Fatal(err)
		}
		personToken, ok := personResult.Token()
		if !ok {
			t.Fatal("person token was not issued")
		}
		resourceToken, err := assistant.Authorize(ctx, clientagent.AuthorizeRequest{
			Resource: supervisedResourceID, PersonToken: personToken, Scopes: []string{"records.read"},
		})
		if err != nil {
			t.Fatal(err)
		}
		result, err := assistant.BeginExchange(ctx, clientagent.ExchangeRequest{
			PersonServer: supervisedPersonID, ResourceToken: resourceToken, PresentedToken: personToken,
			Capabilities: []string{"clarification"},
		})
		if err != nil {
			t.Fatal(err)
		}
		pending, ok := result.Pending()
		if !ok {
			t.Fatal("the exchange did not wait")
		}
		return pending
	}

	pending := exchange()
	question, ok := pending.Clarification()
	if !ok || question.Question() != "Which records, and why?" {
		t.Fatal("the supervisor's question did not reach the Agent")
	}
	if err := assistant.AnswerClarification(ctx, pending, "Only this week's invoices."); err != nil {
		t.Fatal(err)
	}
	world.advance(5 * time.Second)
	result, err := assistant.PollExchange(ctx, pending)
	if err != nil {
		t.Fatal(err)
	}
	token, ok := result.Token()
	if !ok {
		t.Fatalf("the supervisor's allow after the answer did not issue a token: %v", result.Failure())
	}
	claims, err := aauth.VerifyAuthToken(ctx, token, world.resolver, world.clock)
	if err != nil || claims.Scope != "records.read" {
		t.Fatalf("auth token %#v, %v", claims, err)
	}
	asked := home.asked()
	if rounds := asked[len(asked)-1].Rounds; len(rounds) != 1 || rounds[0].Answer != "Only this week's invoices." {
		t.Fatalf("the supervisor saw rounds %#v", rounds)
	}

	// The supervisor asks the person about a second request, and the person
	// questions the Agent before they decide.
	second := exchange()
	reviews, err := world.people.PendingSupervision(ctx, 10)
	if err != nil || len(reviews) != 1 || reviews[0].Ask == nil {
		t.Fatalf("reviews = %#v, %v; want the supervisor's ask", reviews, err)
	}
	if err := world.people.AskSupervisedAgent(ctx, reviews[0].Reference, supervision.Clarification{Question: "Why now?"}); err != nil {
		t.Fatal(err)
	}
	world.advance(5 * time.Second)
	polled, err := assistant.PollExchange(ctx, second)
	if err != nil {
		t.Fatal(err)
	}
	asking, ok := polled.Pending()
	if question, ok2 := asking.Clarification(); !ok || !ok2 || question.Question() != "Why now?" {
		t.Fatal("the person's question did not reach the Agent")
	}
	if err := assistant.AnswerClarification(ctx, asking, "The quarter closes today."); err != nil {
		t.Fatal(err)
	}
	if err := world.people.ResolveSupervision(ctx, reviews[0].Reference, personserver.SupervisionAnswer{Answer: supervision.AnswerDeny}); err != nil {
		t.Fatal(err)
	}
	world.advance(5 * time.Second)
	if _, err := assistant.PollExchange(ctx, asking); err == nil {
		t.Fatal("the person's deny did not end the exchange")
	}
	resolved := home.events(supervision.EventDecisionResolved)
	want := []supervision.TranscriptEntry{
		{From: supervision.FromPerson, Text: "Why now?"}, {From: supervision.FromAgent, Text: "The quarter closes today."},
	}
	if len(resolved) != 1 || resolved[0].Answer != supervision.AnswerDeny || !slices.Equal(resolved[0].Transcript, want) {
		t.Fatalf("decision.resolved = %#v, want the deny with the person's chat", resolved)
	}
}

// TestUnknownMissionIsReplayedBeforeTheSupervisorDecides routes an Agent to a
// supervisor after its mission was approved without one. The supervisor does
// not know the mission, so the Person Server gives it a copy of the mission
// from its own record and asks again under the same sdi.
func TestUnknownMissionIsReplayedBeforeTheSupervisorDecides(t *testing.T) {
	t.Parallel()
	world := newSupervisionWorld(t, supervisionWorldOptions{})
	home := world.addSupervisor(homeSupervisorID, false, func(request supervisionserver.DecisionRequest) supervisionserver.DecisionResult {
		if request.Mission == nil {
			t.Error("the supervisor decided without the mission")
		}
		return decided(supervision.Decision{Verdict: supervision.VerdictAllow})
	})
	assistant, assistantID := world.newAgent("assistant")
	proposal, err := assistant.BeginMission(world.ctx, clientagent.MissionRequest{
		PersonServer: supervisedPersonID, Proposal: aauth.MissionProposal{Description: "# Tidy the archive"},
	})
	if err != nil {
		t.Fatal(err)
	}
	approval, ok := proposal.Approval()
	if !ok {
		t.Fatal("mission was not approved by the person's own policy")
	}
	mission := approval.Mission()
	world.route(assistantID, personserver.Supervisor{Issuer: homeSupervisorID, Subject: "home-person-1"})
	result, err := assistant.RequestPermission(world.ctx, clientagent.PermissionRequest{
		PersonServer: supervisedPersonID, MissionS256: mission.S256, Action: "archive.move",
	})
	if err != nil {
		t.Fatal(err)
	}
	if decision, ok := result.Decision(); !ok || decision.Permission() != aauth.PermissionGranted {
		t.Fatal("permission was not granted after the replay")
	}
	reports := home.reports()
	if len(reports) != 1 || reports[0].Action != supervision.ReportApproved || string(reports[0].Mission) != string(mission.ExactJSON) {
		t.Fatalf("replayed reports = %#v", reports)
	}
	var outcomes []string
	for _, entry := range world.store.Log() {
		if entry.Kind == supervision.KindPermission {
			outcomes = append(outcomes, entry.Outcome)
		}
	}
	if !slices.Equal(outcomes, []string{"unknown_mission", "allow"}) {
		t.Fatalf("logged outcomes = %v, want the refusal and then the allow", outcomes)
	}
}

// TestFourPartySupervisorDecidesAndThePersonServerEnforcesIt puts a
// four-party auth-token request to a supervisor in place of Consent. The
// Access Server issues the token, which the supervisor is told came from it.
// A narrowing the PS-to-AS request cannot carry is enforced on delivery: a
// token broader than the supervisor allowed is refused.
func TestFourPartySupervisorDecidesAndThePersonServerEnforcesIt(t *testing.T) {
	t.Parallel()
	const accessServerID = "https://access.example"
	world := &supervisionWorld{
		t: t, ctx: context.Background(), now: time.Date(2026, 10, 31, 9, 0, 0, 0, time.UTC),
		network: newLogicalTransport(), store: testutil.NewSupervisionStore(),
		tokens: testutil.NewMissionStore(), routes: map[string]personserver.Supervisor{},
		supervisors: map[string]*supervisorHost{},
	}
	world.clock = aauth.ClockFunc(func() time.Time {
		world.mu.Lock()
		defer world.mu.Unlock()
		return world.now
	})
	world.httpClient = &http.Client{Transport: world.network}
	resolver, err := signaturekey.NewHTTPKeyResolver(signaturekey.HTTPKeyResolverConfig{
		Client: world.httpClient, TransportEnforcesEgress: true, Clock: world.clock, Admit: admitExampleOrigins,
	})
	if err != nil {
		t.Fatal(err)
	}
	world.resolver = resolver
	world.provider, err = agentprovider.New(agentprovider.Config{
		Issuer: supervisedProviderID, SigningKey: newSigningKey(t, "four-party-ap"), Clock: world.clock, NewID: world.id,
	})
	if err != nil {
		t.Fatal(err)
	}
	access, err := accessserver.New(accessserver.Config{
		Issuer: accessServerID, SigningKey: newSigningKey(t, "four-party-as"), KeyResolver: resolver,
		Clock: world.clock, NewID: world.id,
		TrustPersonServer: func(context.Context, string) error { return nil },
		Authorize: func(_ context.Context, request accessserver.AuthorizationRequest) (accessserver.Decision, error) {
			return accessserver.Decision{Scopes: append([]string(nil), request.Scopes...), Lifetime: 30 * time.Minute}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	records, err := resource.NewFederatedAuthorization(resource.FederatedAuthorizationConfig{
		Issuer: supervisedResourceID, AccessServer: accessServerID, SigningKey: newSigningKey(t, "four-party-resource"),
		KeyResolver: resolver, Clock: world.clock, NewID: world.id,
		ScopeDescriptions: map[string]string{"records.read": "Read records", "records.write": "Change records"},
		RequiredScopes:    func(*http.Request) []string { return []string{"records.read", "records.write"} },
		ResolvePerson:     func(context.Context, resource.PersonIdentity, resource.PersonContext) error { return nil },
		Protected: http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(response, "records")
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	world.people, err = personserver.NewFederatedAuthorization(personserver.FederatedAuthorizationConfig{
		Issuer: supervisedPersonID, SigningKey: newSigningKey(t, "four-party-ps"), KeyResolver: resolver,
		Clock: world.clock, NewID: world.id, HTTPClient: world.httpClient, Tokens: world.tokens,
		AccessServerEndpoint: func(context.Context, string) (string, error) { return accessServerID + "/token", nil },
		BindPerson: func(context.Context, personserver.PersonTokenRequest) (personserver.Person, error) {
			return personserver.Person{Subject: "person-at-records", Lifetime: time.Hour}, nil
		},
		Consent: func(_ context.Context, request personserver.AuthorizationRequest) error {
			world.hostDecided("Consent", request.Agent)
			return nil
		},
		Supervision: &personserver.SupervisionConfig{
			Route: func(_ context.Context, agent personserver.SupervisedAgent) (personserver.Supervisor, bool, error) {
				world.mu.Lock()
				defer world.mu.Unlock()
				supervisor, ok := world.routes[agent.Agent]
				return supervisor, ok, nil
			},
			Store: world.store, HTTPClient: world.httpClient, Admit: admitExampleOrigins,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	world.network.Handle(supervisedProviderID, world.provider.Handler())
	world.network.Handle(supervisedPersonID, world.people.Handler())
	world.network.Handle(supervisedResourceID, records.Handler())
	world.network.Handle(accessServerID, access.Handler())
	var narrow sync.Map
	home := world.addSupervisor(homeSupervisorID, true, func(request supervisionserver.DecisionRequest) supervisionserver.DecisionResult {
		if _, ok := narrow.Load("on"); ok && request.Request.Kind == supervision.KindAuthToken {
			return decided(supervision.Decision{Verdict: supervision.VerdictAllow, Scope: "records.read"})
		}
		return decided(supervision.Decision{Verdict: supervision.VerdictAllow})
	})
	assistant, assistantID := world.newAgent("assistant")
	route := personserver.Supervisor{Issuer: homeSupervisorID, Subject: "home-person-1"}
	world.route(assistantID, route)
	ctx := world.ctx
	exchange := func() (string, error) {
		t.Helper()
		personResult, err := assistant.PersonToken(ctx, clientagent.PersonTokenRequest{PersonServer: supervisedPersonID, Resource: supervisedResourceID})
		if err != nil {
			t.Fatal(err)
		}
		personToken, ok := personResult.Token()
		if !ok {
			t.Fatal("person token was not issued")
		}
		resourceToken, err := assistant.Authorize(ctx, clientagent.AuthorizeRequest{
			Resource: supervisedResourceID, PersonToken: personToken, Scopes: []string{"records.read", "records.write"},
		})
		if err != nil {
			t.Fatal(err)
		}
		return assistant.Exchange(ctx, clientagent.ExchangeRequest{
			PersonServer: supervisedPersonID, ResourceToken: resourceToken, PresentedToken: personToken,
		})
	}
	authToken, err := exchange()
	if err != nil {
		t.Fatal(err)
	}
	claims, err := aauth.VerifyAuthToken(ctx, authToken, resolver, world.clock)
	if err != nil || claims.Issuer != accessServerID {
		t.Fatalf("auth token %#v, %v; want one from the Access Server", claims, err)
	}
	narrow.Store("on", true)
	if _, err := exchange(); err == nil {
		t.Fatal("a token broader than the supervisor allowed was delivered")
	} else if problem := (*aauth.ProblemError)(nil); !errors.As(err, &problem) || problem.Status != http.StatusForbidden {
		t.Fatalf("broader token = %v, want 403", err)
	}
	if _, err := world.people.DeliverSupervisionEvents(ctx, route); err != nil {
		t.Fatal(err)
	}
	issued := home.events(supervision.EventAuthTokenIssued)
	if len(issued) != 1 || issued[0].Issuer != accessServerID || issued[0].JTI != claims.JTI {
		t.Fatalf("auth_token.issued = %#v, want the Access Server's token", issued)
	}
}
