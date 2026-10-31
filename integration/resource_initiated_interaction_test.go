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
	"gitlab.com/sidecat-dev/aauth-go/agentprovider"
	"gitlab.com/sidecat-dev/aauth-go/personserver"
	"gitlab.com/sidecat-dev/aauth-go/resource"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
	"gitlab.com/sidecat-dev/aauth-go/testutil"
)

const (
	initiatedAgentProvider = "https://ap.example"
	initiatedAgent         = "aauth:reader@ap.example"
	initiatedPersonServer  = "https://ps.example"
	initiatedResource      = "https://calendar.example"
	initiatedAgentCallback = "https://ap.example/callback/flow-1"
)

// initiatedInteractionFixture composes an Agent, a three-party Person Server
// and a Resource whose Resource tokens carry its own interaction claim (Core,
// Resource-Initiated Interaction). The test plays the person's browser and
// the two hosts' pages.
type initiatedInteractionFixture struct {
	ctx          context.Context
	keys         signaturekey.KeyResolver
	clock        aauth.Clock
	people       *personserver.Server
	calendar     *resource.Server
	reader       *clientagent.Client
	refuseEgress bool
	admitted     []string
	served       int
	issued       aauth.ResourceTokenClaims
}

func newInitiatedInteractionFixture(t *testing.T) *initiatedInteractionFixture {
	t.Helper()
	fixture := &initiatedInteractionFixture{ctx: context.Background()}
	now := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	network := newLogicalTransport()
	httpClient := &http.Client{Transport: network}
	keyResolver, err := signaturekey.NewHTTPKeyResolver(signaturekey.HTTPKeyResolverConfig{
		Client: httpClient, TransportEnforcesEgress: true, Clock: clock,
		Admit: func(context.Context, string) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	fixture.keys, fixture.clock = keyResolver, clock
	agentKey := newSigningKey(t, "initiated-agent")
	provider, err := agentprovider.New(agentprovider.Config{
		Issuer: initiatedAgentProvider, SigningKey: newSigningKey(t, "initiated-ap"), Clock: clock,
		NewID: func() string { return "initiated-agent-token" }, CallbackEndpoint: initiatedAgentProvider + "/callback",
	})
	if err != nil {
		t.Fatal(err)
	}
	agentToken, err := provider.Issue(aauth.AgentTokenRequest{
		Agent: initiatedAgent, PersonServer: initiatedPersonServer, PublicKey: agentKey.PublicJWK(), Lifetime: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	ids := 0
	fixture.people, err = personserver.NewPSAuthorization(personserver.PSAuthorizationConfig{
		Issuer: initiatedPersonServer, SigningKey: newSigningKey(t, "initiated-ps"), KeyResolver: keyResolver,
		Clock: clock, Tokens: newMemoryPersonTokenStore(),
		NewID: func() string {
			ids++
			return "initiated-ps-token-" + string(rune('a'+ids))
		},
		BindPerson: func(context.Context, personserver.PersonTokenRequest) (personserver.Person, error) {
			return personserver.Person{Subject: "person-123", Lifetime: 20 * time.Minute}, nil
		},
		AuthorizationInteractions: testutil.NewDeferredAuthorizationStore(),
		TokenRevocation:           &personserver.TokenRevocationConfig{Revocations: testutil.NewTokenRevocationStore()},
		ResourceInteraction: &personserver.ResourceInteractionConfig{
			Policy: func(_ context.Context, request personserver.AuthorizationRequest) (personserver.AuthorizationInteractionPolicy, error) {
				if request.Resource != initiatedResource || request.Subject != "person-123" {
					return personserver.AuthorizationInteractionPolicy{}, errors.New("unexpected authorization request")
				}
				return personserver.AuthorizationInteractionPolicy{
					URL: initiatedPersonServer + "/consent", Lifetime: 4 * time.Minute,
				}, nil
			},
			CallbackURL: initiatedPersonServer + "/from-resource",
			Admit: func(_ context.Context, endpoint string) error {
				fixture.admitted = append(fixture.admitted, endpoint)
				if fixture.refuseEgress {
					return errors.New("egress refused")
				}
				return nil
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	fixture.calendar, err = resource.NewPSAuthorization(resource.PSAuthorizationConfig{
		Issuer: initiatedResource, SigningKey: newSigningKey(t, "initiated-resource"), KeyResolver: keyResolver,
		Clock: clock, NewID: func() string { return "initiated-resource-token" },
		ScopeDescriptions: map[string]string{"calendar.read": "Read your calendar"},
		RequiredScopes:    func(*http.Request) []string { return []string{"calendar.read"} },
		ResolvePerson:     func(context.Context, resource.PersonIdentity, resource.PersonContext) error { return nil },
		Revocation: &resource.RevocationConfig{
			HTTPClient: httpClient, Admit: func(context.Context, string) error { return nil },
		},
		InitiatedInteraction: &resource.InitiatedInteractionConfig{
			URL: initiatedResource + "/connect",
			Require: func(_ context.Context, request resource.InitiatedInteractionRequest) (bool, error) {
				return request.Person == resource.PersonIdentity{Issuer: initiatedPersonServer, Subject: "person-123"}, nil
			},
			Store: testutil.NewInitiatedInteractionStore(),
		},
		Protected: http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
			fixture.served++
			_, _ = io.WriteString(response, "calendar")
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	network.Handle(initiatedAgentProvider, provider.Handler())
	network.Handle(initiatedPersonServer, fixture.people.Handler())
	network.Handle(initiatedResource, fixture.calendar.Handler())
	fixture.reader, err = clientagent.New(fixture.ctx, clientagent.Config{
		Identifier: initiatedAgent, SigningKey: agentKey, AgentToken: agentToken,
		KeyResolver: keyResolver, HTTPClient: httpClient, Clock: clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	return fixture
}

// begin obtains a Resource token carrying the Resource's interaction and
// presents it to the Person Server, which answers with its own interaction.
func (fixture *initiatedInteractionFixture) begin(t *testing.T) (clientagent.PendingExchange, aauth.ResourceInteraction) {
	t.Helper()
	personResult, err := fixture.reader.PersonToken(fixture.ctx, clientagent.PersonTokenRequest{
		PersonServer: initiatedPersonServer, Resource: initiatedResource,
	})
	if err != nil {
		t.Fatal(err)
	}
	personToken, ok := personResult.Token()
	if !ok {
		t.Fatal("person token was not issued immediately")
	}
	resourceToken, err := fixture.reader.Authorize(fixture.ctx, clientagent.AuthorizeRequest{
		Resource: initiatedResource, PersonToken: personToken, Scopes: []string{"calendar.read"},
	})
	if err != nil {
		t.Fatal(err)
	}
	resourceClaims, err := aauth.VerifyResourceToken(fixture.ctx, resourceToken, fixture.keys, fixture.clock)
	if err != nil {
		t.Fatal(err)
	}
	if resourceClaims.Interaction == nil || !strings.HasPrefix(resourceClaims.Interaction.URL, initiatedResource+"/connect/") {
		t.Fatalf("Resource token interaction = %#v", resourceClaims.Interaction)
	}
	fixture.issued = resourceClaims
	if _, err := fixture.reader.Exchange(fixture.ctx, clientagent.ExchangeRequest{
		PersonServer: initiatedPersonServer, ResourceToken: resourceToken, PresentedToken: personToken,
		Capabilities: []string{"interaction"},
	}); err == nil {
		t.Fatal("the immediate exchange accepted a Resource token that needs an interaction")
	}
	result, err := fixture.reader.BeginExchange(fixture.ctx, clientagent.ExchangeRequest{
		PersonServer: initiatedPersonServer, ResourceToken: resourceToken, PresentedToken: personToken,
		Capabilities: []string{"interaction"},
	})
	if err != nil {
		t.Fatal(err)
	}
	pending, ok := result.Pending()
	if !ok || pending.Requirement() != aauth.RequirementInteraction ||
		!strings.HasPrefix(pending.InteractionURL(), initiatedPersonServer+"/consent/") {
		t.Fatalf("pending = %#v, %t", pending, ok)
	}
	return pending, *resourceClaims.Interaction
}

// visitPersonServer plays the person arriving at the Person Server with the
// Agent's callback, the interstitial, and the redirect to the Resource.
func (fixture *initiatedInteractionFixture) visitPersonServer(
	t *testing.T,
	pending clientagent.PendingExchange,
) (personserver.AuthorizationInteraction, string, error) {
	t.Helper()
	target, err := aauth.FormatInteractionVisitURL(pending.InteractionURL(), pending.InteractionCode(), initiatedAgentCallback)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(target)
	if err != nil {
		t.Fatal(err)
	}
	visit, err := aauth.ParseInteractionVisit(parsed.RawQuery, aauth.InteractionVisitOptions{})
	if err != nil || visit.Callback != initiatedAgentCallback {
		t.Fatalf("visit = %#v, %v", visit, err)
	}
	reference := strings.TrimPrefix(parsed.Path, "/consent/")
	interaction, err := fixture.people.ConsumeAuthorizationInteractionCode(fixture.ctx, reference, visit.Code)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := interaction.ResourceInteraction(); !ok {
		t.Fatal("authorization does not carry the Resource interaction")
	}
	redirect, err := fixture.people.RedirectToResourceInteraction(fixture.ctx, interaction, visit.Callback)
	return interaction, redirect, err
}

// visitResource plays the person arriving at the Resource's own page. The
// Resource reads code and callback the same way whoever sent the person.
func (fixture *initiatedInteractionFixture) visitResource(
	t *testing.T,
	redirect string,
	claim aauth.ResourceInteraction,
) resource.InitiatedInteraction {
	t.Helper()
	parsed, err := url.Parse(redirect)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Scheme+"://"+parsed.Host+parsed.Path != claim.URL {
		t.Fatalf("redirect %q does not target the claim URL %q", redirect, claim.URL)
	}
	visit, err := aauth.ParseInteractionVisit(parsed.RawQuery, aauth.InteractionVisitOptions{})
	if err != nil || !aauth.MatchInteractionCode(claim.Code, visit.Code) ||
		!strings.HasPrefix(visit.Callback, initiatedPersonServer+"/from-resource/") {
		t.Fatalf("Resource visit = %#v, %v", visit, err)
	}
	reference := strings.TrimPrefix(parsed.Path, "/connect/")
	interaction, err := fixture.calendar.ConsumeInitiatedInteraction(fixture.ctx, reference, visit)
	if err != nil {
		t.Fatal(err)
	}
	if interaction.Person() != (resource.PersonIdentity{Issuer: initiatedPersonServer, Subject: "person-123"}) {
		t.Fatalf("Resource interaction person = %#v", interaction.Person())
	}
	if _, err := fixture.calendar.ConsumeInitiatedInteraction(fixture.ctx, reference, visit); !errors.Is(err, resource.ErrInitiatedInteractionCodeUsed) {
		t.Fatalf("second visit = %v", err)
	}
	return interaction
}

// returnToPersonServer plays the Resource's redirect back to the Person
// Server's per-flow callback.
func (fixture *initiatedInteractionFixture) returnToPersonServer(t *testing.T, callback string) (personserver.AuthorizationInteraction, string, error) {
	t.Helper()
	parsed, err := url.Parse(callback)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(strings.TrimPrefix(parsed.Path, "/from-resource/"), "/")
	if len(parts) != 2 {
		t.Fatalf("callback path = %q", parsed.Path)
	}
	interaction, err := fixture.people.ReceiveResourceInteractionCallback(fixture.ctx, parts[0], parts[1], parsed.RawQuery)
	return interaction, parts[0], err
}

func TestResourceInitiatedInteractionCompletesBeforePersonServerConsent(t *testing.T) {
	t.Parallel()
	fixture := newInitiatedInteractionFixture(t)
	pending, claim := fixture.begin(t)
	consent, redirect, err := fixture.visitPersonServer(t, pending)
	if err != nil {
		t.Fatal(err)
	}
	if len(fixture.admitted) != 1 || fixture.admitted[0] != claim.URL {
		t.Fatalf("egress admission saw %v, want the claim URL", fixture.admitted)
	}
	if _, err := fixture.people.RedirectToResourceInteraction(fixture.ctx, consent, ""); err == nil {
		t.Fatal("the person was sent to the Resource twice")
	}
	decision := personserver.AuthorizationDecision{Scopes: []string{"calendar.read"}, Lifetime: 10 * time.Minute}
	if err := fixture.people.ApproveAuthorizationInteraction(fixture.ctx, consent, decision); !errors.Is(err, personserver.ErrResourceInteractionPending) {
		t.Fatalf("consent before the Resource's flow = %v", err)
	}
	interacting, err := fixture.reader.PollExchange(fixture.ctx, pending)
	if err != nil {
		t.Fatal(err)
	}
	if next, ok := interacting.Pending(); !ok || !next.Interacting() {
		t.Fatalf("poll while at the Resource = %#v", interacting)
	}

	atResource := fixture.visitResource(t, redirect, claim)
	completion, err := atResource.CompletionURL()
	if err != nil {
		t.Fatal(err)
	}
	forged := completion[:strings.LastIndex(completion, "/")+1] + "forged-flow"
	if _, _, err := fixture.returnToPersonServer(t, forged); !errors.Is(err, personserver.ErrResourceInteractionCallbackInvalid) {
		t.Fatalf("a callback with a forged flow = %v", err)
	}
	afterResource, reference, err := fixture.returnToPersonServer(t, completion)
	if err != nil {
		t.Fatal(err)
	}
	if err := fixture.people.ApproveAuthorizationInteraction(fixture.ctx, afterResource, decision); err != nil {
		t.Fatal(err)
	}
	back, err := fixture.people.AuthorizationCallbackURL(fixture.ctx, reference)
	if err != nil || back != initiatedAgentCallback {
		t.Fatalf("Agent callback = %q, %v", back, err)
	}
	if err := aauth.ReadInteractionCallback(""); err != nil {
		t.Fatal(err)
	}

	approved, err := fixture.reader.PollExchange(fixture.ctx, pending)
	if err != nil {
		t.Fatal(err)
	}
	authToken, ok := approved.Token()
	if !ok {
		t.Fatalf("approved poll = %#v", approved)
	}
	request, err := http.NewRequestWithContext(fixture.ctx, http.MethodGet, initiatedResource+"/events", nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := fixture.reader.Do(fixture.ctx, clientagent.Call{Request: request, AuthToken: authToken})
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || fixture.served != 1 {
		t.Fatalf("call = %d, served %d", response.StatusCode, fixture.served)
	}
}

// A Resource that cannot complete its flow returns the person with an error.
// The Person Server never treats that request as completable: it ends with
// the mapped polling error, and the Agent's callback carries the error too.
func TestResourceInteractionCallbackErrorsEndThePendingRequest(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		failure aauth.InteractionCallbackError
		status  int
		polling aauth.ErrorCode
		toAgent aauth.InteractionCallbackError
	}{
		{aauth.InteractionCallbackAccessDenied, http.StatusForbidden, "denied", aauth.InteractionCallbackAccessDenied},
		{aauth.InteractionCallbackUserAbandoned, http.StatusForbidden, "abandoned", aauth.InteractionCallbackUserAbandoned},
		{aauth.InteractionCallbackInteractionExpired, http.StatusRequestTimeout, "expired", aauth.InteractionCallbackInteractionExpired},
		{aauth.InteractionCallbackServerError, http.StatusInternalServerError, "server_error", aauth.InteractionCallbackServerError},
		{aauth.InteractionCallbackTemporarilyUnavailable, http.StatusInternalServerError, "server_error", aauth.InteractionCallbackServerError},
	} {
		test := test
		t.Run(string(test.failure), func(t *testing.T) {
			t.Parallel()
			fixture := newInitiatedInteractionFixture(t)
			pending, claim := fixture.begin(t)
			_, redirect, err := fixture.visitPersonServer(t, pending)
			if err != nil {
				t.Fatal(err)
			}
			atResource := fixture.visitResource(t, redirect, claim)
			failed, err := atResource.FailureURL(test.failure)
			if err != nil || !strings.HasSuffix(failed, "?error="+string(test.failure)) {
				t.Fatalf("Resource failure redirect = %q, %v", failed, err)
			}
			_, reference, err := fixture.returnToPersonServer(t, failed)
			var surfaced aauth.InteractionCallbackError
			if !errors.As(err, &surfaced) || surfaced != test.failure {
				t.Fatalf("callback error = %v, want %s", err, test.failure)
			}
			back, err := fixture.people.AuthorizationCallbackURL(fixture.ctx, reference)
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := url.Parse(back)
			if err != nil {
				t.Fatal(err)
			}
			agentSide := aauth.ReadInteractionCallback(parsed.RawQuery)
			if !errors.Is(agentSide, test.toAgent) {
				t.Fatalf("Agent callback %q read as %v, want %s", back, agentSide, test.toAgent)
			}
			_, err = fixture.reader.PollExchange(fixture.ctx, pending)
			var problem *aauth.ProblemError
			if !errors.As(err, &problem) || problem.Status != test.status || problem.Code != test.polling {
				t.Fatalf("poll after %s = %v, want %d %s", test.failure, err, test.status, test.polling)
			}
			if fixture.served != 0 {
				t.Fatal("the Resource served a request whose interaction failed")
			}
		})
	}
}

func TestPersonServerRefusesAResourceInteractionURLEgressDenies(t *testing.T) {
	t.Parallel()
	fixture := newInitiatedInteractionFixture(t)
	fixture.refuseEgress = true
	pending, _ := fixture.begin(t)
	_, redirect, err := fixture.visitPersonServer(t, pending)
	if !errors.Is(err, personserver.ErrResourceInteractionRefused) || redirect != "" {
		t.Fatalf("redirect = %q, %v", redirect, err)
	}
	_, err = fixture.reader.PollExchange(fixture.ctx, pending)
	var problem *aauth.ProblemError
	if !errors.As(err, &problem) || problem.Code != "server_error" {
		t.Fatalf("poll after refused egress = %v", err)
	}
}

// A Resource that withdraws the Resource token its interaction belongs to
// ends the Person Server's request: the person is not sent on, the
// Resource's callback is refused, and the Agent's next poll is revoked.
func TestWithdrawnResourceTokenEndsResourceInitiatedInteraction(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name           string
		beforeRedirect bool
	}{
		{name: "before the person is sent to the Resource", beforeRedirect: true},
		{name: "while the person is at the Resource"},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			fixture := newInitiatedInteractionFixture(t)
			pending, claim := fixture.begin(t)
			withdraw := func() {
				t.Helper()
				if _, err := fixture.calendar.RevokeResourceToken(fixture.ctx, resource.ResourceTokenRevocation{
					JTI: fixture.issued.JTI, ExpiresAt: time.Unix(fixture.issued.ExpiresAt, 0),
					Audience: initiatedPersonServer, PersonServer: initiatedPersonServer,
				}); err != nil {
					t.Fatal(err)
				}
			}
			if test.beforeRedirect {
				withdraw()
				_, redirect, err := fixture.visitPersonServer(t, pending)
				if !errors.Is(err, personserver.ErrResourceTokenRevoked) || redirect != "" {
					t.Fatalf("redirect after withdrawal = %q, %v", redirect, err)
				}
			} else {
				_, redirect, err := fixture.visitPersonServer(t, pending)
				if err != nil {
					t.Fatal(err)
				}
				completion, err := fixture.visitResource(t, redirect, claim).CompletionURL()
				if err != nil {
					t.Fatal(err)
				}
				withdraw()
				if _, _, err := fixture.returnToPersonServer(t, completion); !errors.Is(err, personserver.ErrResourceTokenRevoked) {
					t.Fatalf("callback after withdrawal = %v", err)
				}
			}
			_, err := fixture.reader.PollExchange(fixture.ctx, pending)
			var problem *aauth.ProblemError
			if !errors.As(err, &problem) || problem.Code != "revoked" {
				t.Fatalf("poll after withdrawal = %v", err)
			}
		})
	}
}
