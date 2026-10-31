// The supervision example runs one person's Agents under two supervision
// servers entirely in process. Work Agents are routed to an organization's
// supervisor, which accepts the person's tenant without interaction; personal
// Agents to the person's own supervisor, which the person confirms once. The
// supervisors apply standing policy and ask the person only for exceptions;
// the Person Server decides nothing itself for them. When the person's own
// supervisor is offline, as on a machine that sleeps, the person decides, and
// the supervisor is told afterwards. Both sign their decisions, which remain
// a record the person can verify later.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path"
	"strings"
	"sync"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	clientagent "gitlab.com/sidecat-dev/aauth-go/agent"
	"gitlab.com/sidecat-dev/aauth-go/agentprovider"
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/personserver"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
	"gitlab.com/sidecat-dev/aauth-go/supervision"
	"gitlab.com/sidecat-dev/aauth-go/supervisionserver"
	"gitlab.com/sidecat-dev/aauth-go/testutil"
)

const (
	agentProviderID  = "https://agents.example"
	personServerID   = "https://person.example"
	resourceID       = "https://files.example"
	organizationSSID = "https://governance.example"
	personalSSID     = "https://supervisor.example"
	workAgentID      = "aauth:builder@agents.example"
	personalAgentID  = "aauth:planner@agents.example"
)

func main() {
	if err := run(os.Stdout); err != nil {
		log.Fatal(err)
	}
}

// standingPolicy is a supervisor's own policy: it allows routine actions,
// asks the person about payments, and remembers the reach of each answer.
type standingPolicy struct {
	mu      sync.Mutex
	asked   map[string]string
	allowed map[string]bool
}

func (policy *standingPolicy) decide(_ context.Context, request supervisionserver.DecisionRequest) (supervisionserver.DecisionResult, error) {
	policy.mu.Lock()
	defer policy.mu.Unlock()
	allow := supervision.Decision{Verdict: supervision.VerdictAllow}
	if request.Request.Kind == supervision.KindMissionProposal {
		allow.Mission = &supervision.MissionTerms{
			Description:       request.Request.Description + "\n\nAsk before any payment.",
			ApprovedResources: request.Request.Resources,
		}
	}
	if request.Request.Kind != supervision.KindPermission || request.Request.Action != "payments.send" ||
		policy.allowed[request.Request.MissionS256+" "+request.Request.Action] {
		return supervisionserver.DecisionResult{Decision: &allow}, nil
	}
	policy.asked[request.Request.SDI] = request.Request.Action
	return supervisionserver.DecisionResult{Decision: &supervision.Decision{
		Verdict: supervision.VerdictAsk, Summary: "The agent wants to pay an invoice.",
		Recommendation: supervision.VerdictAllow,
		ApplyOptions: []supervision.ApplyOption{
			{Value: supervision.ApplyOnce, Label: "This payment only"},
			{Value: supervision.ApplyMission, Label: "Any payment on this mission"},
		},
	}}, nil
}

// observe learns from what the person decided.
func (policy *standingPolicy) observe(_ context.Context, observation supervisionserver.Observation) error {
	policy.mu.Lock()
	defer policy.mu.Unlock()
	event := observation.Event
	if event == nil || event.Name != supervision.EventDecisionResolved || event.Answer != supervision.AnswerAllow {
		return nil
	}
	if action, ok := policy.asked[event.SDI]; ok && event.Apply == supervision.ApplyMission {
		policy.allowed[event.MissionS256+" "+action] = true
	}
	return nil
}

func run(output io.Writer) error {
	if output == nil {
		return errors.New("output is required")
	}
	ctx := context.Background()
	var mu sync.Mutex
	now := time.Date(2026, 10, 31, 9, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return now
	})
	advance := func(duration time.Duration) {
		mu.Lock()
		defer mu.Unlock()
		now = now.Add(duration)
	}
	print := func(format string, values ...any) error {
		_, err := fmt.Fprintf(output, format+"\n", values...)
		return err
	}

	network := newLogicalTransport()
	httpClient := &http.Client{Transport: network}
	resolver, err := signaturekey.NewHTTPKeyResolver(signaturekey.HTTPKeyResolverConfig{
		Client: httpClient, Clock: clock, Admit: network.Admit,
		// The in-memory network makes no connection. Leave this unset with a
		// network transport, so the resolver checks every destination.
		TransportEnforcesEgress: true,
	})
	if err != nil {
		return err
	}
	keys := map[string]jose.SigningKey{}
	for _, name := range []string{"agent-provider", "person-server", "organization", "personal", "builder", "planner"} {
		if keys[name], err = newSigningKey(name + "-key"); err != nil {
			return err
		}
	}

	// Two supervisors. The organization's accepts its tenant's people at
	// once; the person's own asks them to confirm. Both sign their decisions,
	// as a Person Server requires by default.
	organizationPolicy := &standingPolicy{asked: map[string]string{}, allowed: map[string]bool{}}
	organizationKey := keys["organization"]
	organization, err := supervisionserver.New(supervisionserver.Config{
		Issuer: organizationSSID, Name: "Organization supervisor", SigningKey: &organizationKey,
		KeyResolver: resolver, Clock: clock, Store: testutil.NewSupervisorStore(),
		Connect: func(_ context.Context, request supervisionserver.ConnectRequest) (supervisionserver.ConnectResult, error) {
			return supervisionserver.ConnectResult{Accept: request.Tenant == "example.org"}, nil
		},
		Decide: organizationPolicy.decide, Observe: organizationPolicy.observe,
	})
	if err != nil {
		return err
	}
	personalPolicy := &standingPolicy{asked: map[string]string{}, allowed: map[string]bool{}}
	var told []string
	personalKey := keys["personal"]
	personal, err := supervisionserver.New(supervisionserver.Config{
		Issuer: personalSSID, Name: "My supervisor", SigningKey: &personalKey, KeyResolver: resolver, Clock: clock,
		Store: testutil.NewSupervisorStore(),
		Connect: func(context.Context, supervisionserver.ConnectRequest) (supervisionserver.ConnectResult, error) {
			return supervisionserver.ConnectResult{Interaction: &supervisionserver.ConnectInteraction{URL: personalSSID + "/confirm"}}, nil
		},
		Decide: personalPolicy.decide,
		Observe: func(ctx context.Context, observation supervisionserver.Observation) error {
			if observation.Event != nil {
				name := string(observation.Event.Name)
				if observation.Event.Supervisor != "" {
					name += " (supervisor " + observation.Event.Supervisor + ")"
				}
				told = append(told, name)
			}
			return personalPolicy.observe(ctx, observation)
		},
	})
	if err != nil {
		return err
	}

	// The Person Server routes each Agent to its deciding supervisor. Its own
	// policies are not called for a supervised Agent.
	routes := map[string]personserver.Supervisor{
		workAgentID:     {Issuer: organizationSSID, Subject: "org-person-7", Tenant: "example.org"},
		personalAgentID: {Issuer: personalSSID, Subject: "own-person-1"},
	}
	notCalled := errors.New("the Person Server does not decide for a supervised Agent")
	supervisionStore := testutil.NewSupervisionStore()
	people, err := personserver.NewPSAuthorization(personserver.PSAuthorizationConfig{
		Issuer: personServerID, SigningKey: keys["person-server"], KeyResolver: resolver, Clock: clock,
		NewID: newID, Tokens: testutil.NewMissionStore(),
		BindPerson: func(context.Context, personserver.PersonTokenRequest) (personserver.Person, error) {
			return personserver.Person{Subject: "person-at-files", Lifetime: time.Hour}, nil
		},
		Authorize: func(context.Context, personserver.AuthorizationRequest) (personserver.AuthorizationDecision, error) {
			return personserver.AuthorizationDecision{}, notCalled
		},
		Missions: &personserver.MissionConfig{
			Approve: func(context.Context, personserver.MissionApprovalRequest) (personserver.MissionDecision, error) {
				return personserver.MissionDecision{}, notCalled
			},
		},
		Permission: &personserver.PermissionConfig{
			Policy: func(context.Context, personserver.PermissionPolicyRequest) (personserver.PermissionPolicyResult, error) {
				return personserver.PermissionPolicyResult{}, notCalled
			},
		},
		Supervision: &personserver.SupervisionConfig{
			Route: func(_ context.Context, agent personserver.SupervisedAgent) (personserver.Supervisor, bool, error) {
				supervisor, ok := routes[agent.Agent]
				return supervisor, ok, nil
			},
			Store: supervisionStore, HTTPClient: httpClient, Admit: network.Admit,
		},
	})
	if err != nil {
		return err
	}
	provider, err := agentprovider.New(agentprovider.Config{
		Issuer: agentProviderID, SigningKey: keys["agent-provider"], Clock: clock, NewID: newID,
	})
	if err != nil {
		return err
	}
	network.Handle(agentProviderID, provider.Handler())
	network.Handle(personServerID, people.Handler())
	network.Handle(organizationSSID, organization.Handler())
	network.Handle(personalSSID, personal.Handler())
	newAgent := func(agentID, keyName string) (*clientagent.Client, error) {
		token, err := provider.Issue(aauth.AgentTokenRequest{
			Agent: agentID, PersonServer: personServerID, PublicKey: keys[keyName].PublicJWK(), Lifetime: time.Hour,
		})
		if err != nil {
			return nil, err
		}
		return clientagent.New(ctx, clientagent.Config{
			Identifier: agentID, SigningKey: keys[keyName], AgentToken: token,
			KeyResolver: resolver, HTTPClient: httpClient, Clock: clock,
		})
	}
	builder, err := newAgent(workAgentID, "builder")
	if err != nil {
		return err
	}
	planner, err := newAgent(personalAgentID, "planner")
	if err != nil {
		return err
	}

	// The person registers their own supervisor and confirms this Person
	// Server there.
	connection, err := people.ConnectSupervisor(ctx, routes[personalAgentID])
	if err != nil {
		return err
	}
	reference := path.Base(connection.InteractionURL)
	confirmation, err := personal.ConsumeConnectCode(ctx, reference, connection.InteractionCode)
	if err != nil {
		return err
	}
	if err := personal.ConfirmConnect(ctx, reference, "the person"); err != nil {
		return err
	}
	if connection, err = people.PollSupervisorConnect(ctx, routes[personalAgentID]); err != nil || connection.State != personserver.SupervisorConnected {
		return errors.New("the personal supervisor did not connect")
	}
	if err := print("Personal supervisor connected after the person confirmed %s", confirmation.PersonServer); err != nil {
		return err
	}

	// A work Agent: the organization's supervisor decides by its policy.
	routine, err := builder.RequestPermission(ctx, clientagent.PermissionRequest{PersonServer: personServerID, Action: "builds.start"})
	if err != nil {
		return err
	}
	if decision, ok := routine.Decision(); !ok || decision.Permission() != aauth.PermissionGranted {
		return errors.New("the organization's supervisor did not allow a routine action")
	}
	if err := print("Work agent: builds.start granted by the organization's supervisor"); err != nil {
		return err
	}

	// A personal Agent proposes a mission; its supervisor refines it.
	proposal, err := planner.BeginMission(ctx, clientagent.MissionRequest{
		PersonServer: personServerID,
		Proposal:     aauth.MissionProposal{Description: "# Pay this month's bills", Resources: []string{resourceID}},
	})
	if err != nil {
		return err
	}
	approval, ok := proposal.Approval()
	if !ok {
		return errors.New("the mission was not approved")
	}
	mission := approval.Mission()
	if err := print("Mission approved as refined: %q", lastLine(mission.Blob.Description)); err != nil {
		return err
	}

	// A payment is an exception: the supervisor asks the person.
	payment, err := planner.RequestPermission(ctx, clientagent.PermissionRequest{
		PersonServer: personServerID, MissionS256: mission.S256, Action: "payments.send",
	})
	if err != nil {
		return err
	}
	waiting, ok := payment.Pending()
	if !ok {
		return errors.New("the payment was not put to the person")
	}
	reviews, err := people.PendingSupervision(ctx, 10)
	if err != nil || len(reviews) != 1 || reviews[0].Ask == nil {
		return errors.New("the Person Server holds no ask for the person")
	}
	if err := print("Asked the person: %s (supervisor recommends %s)", reviews[0].Ask.Summary, reviews[0].Ask.Recommendation); err != nil {
		return err
	}
	// The host authenticates the person, shows them the request and the
	// supervisor's summary, and records their answer and its reach.
	if err := people.ResolveSupervision(ctx, reviews[0].Reference, personserver.SupervisionAnswer{
		Answer: supervision.AnswerAllow, Apply: supervision.ApplyMission,
	}); err != nil {
		return err
	}
	advance(5 * time.Second)
	if result, err := planner.PollPermission(ctx, waiting); err != nil {
		return err
	} else if decision, ok := result.Decision(); !ok || decision.Permission() != aauth.PermissionGranted {
		return errors.New("the person's allow did not grant the payment")
	}
	again, err := planner.RequestPermission(ctx, clientagent.PermissionRequest{
		PersonServer: personServerID, MissionS256: mission.S256, Action: "payments.send",
	})
	if err != nil {
		return err
	}
	if decision, ok := again.Decision(); !ok || decision.Permission() != aauth.PermissionGranted {
		return errors.New("the supervisor did not apply the person's reach")
	}
	if err := print("Person allowed it for the mission; the next payment was granted without asking"); err != nil {
		return err
	}

	// The person's supervisor goes offline. The person decides instead.
	network.Handle(personalSSID, nil)
	result, err := planner.PersonToken(ctx, clientagent.PersonTokenRequest{PersonServer: personServerID, Resource: resourceID})
	if err != nil {
		return err
	}
	pendingToken, ok := result.Approval()
	if !ok {
		return errors.New("the person-token request was not put to the person")
	}
	reviews, err = people.PendingSupervision(ctx, 10)
	if err != nil || len(reviews) != 1 || !reviews[0].SupervisorUnavailable {
		return errors.New("the Person Server does not hold the request for the person")
	}
	if err := people.ResolveSupervision(ctx, reviews[0].Reference, personserver.SupervisionAnswer{Answer: supervision.AnswerAllow}); err != nil {
		return err
	}
	advance(5 * time.Second)
	if result, err := pendingToken.Poll(ctx, clientagent.PollOptions{}); err != nil {
		return err
	} else if _, ok := result.Value(); !ok {
		return errors.New("the person's allow did not issue the token")
	}
	if err := print("Personal supervisor offline: the person allowed the person-token request"); err != nil {
		return err
	}
	network.Handle(personalSSID, personal.Handler())
	told = nil
	if _, err := people.DeliverSupervisionEvents(ctx, routes[personalAgentID]); err != nil {
		return err
	}
	if err := print("Supervisor back online, told: %s", strings.Join(told, ", ")); err != nil {
		return err
	}

	// Each supervisor signed every decision it made. The Person Server's log
	// entry verifies later from the record alone and names its signer.
	verified := map[string]int{}
	for _, entry := range supervisionStore.Log() {
		if entry.Exchange == nil || !entry.Exchange.Signed {
			continue
		}
		signed, err := supervision.VerifyExchange(ctx, *entry.Exchange, resolver)
		if err != nil {
			return err
		}
		if signed.Signer() != entry.Supervisor.Issuer {
			return errors.New("a logged decision names another signer")
		}
		verified[signed.Signer()]++
	}
	return print("Signed decisions in the log verified: %d by %s, %d by %s",
		verified[organizationSSID], organizationSSID, verified[personalSSID], personalSSID)
}

func lastLine(text string) string {
	lines := strings.Split(strings.TrimSpace(text), "\n")
	return lines[len(lines)-1]
}

var (
	idMu   sync.Mutex
	nextID int
)

func newID() string {
	idMu.Lock()
	defer idMu.Unlock()
	nextID++
	return fmt.Sprintf("supervision-example-%d", nextID)
}

func newSigningKey(id string) (jose.SigningKey, error) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return jose.SigningKey{}, err
	}
	return jose.NewEd25519SigningKey(id, privateKey)
}
