package integration_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	clientagent "gitlab.com/sidecat-dev/aauth-go/agent"
	"gitlab.com/sidecat-dev/aauth-go/agentprovider"
	"gitlab.com/sidecat-dev/aauth-go/personserver"
	"gitlab.com/sidecat-dev/aauth-go/personserver/storetest"
	"gitlab.com/sidecat-dev/aauth-go/resource"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

func TestCurrentCoreDeferredPSAuthorizationAcrossRecomposition(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	now := time.Date(2026, 8, 30, 22, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	const (
		agentProviderID = "https://ap.example"
		agentID         = "aauth:reader@ap.example"
		personServerID  = "https://ps.example"
		resourceID      = "https://resource.example"
		accessServerID  = "https://as.example"
	)
	scope := []string{"records.read", "records.list"}
	agentProviderKey := newSigningKey(t, "deferred-ps-ap")
	agentKey := newSigningKey(t, "deferred-ps-agent")
	personServerKey := newSigningKey(t, "deferred-ps-person")
	resourceKey := newSigningKey(t, "deferred-ps-resource")

	network := newLogicalTransport()
	httpClient := &http.Client{Transport: network}
	keyResolver, err := signaturekey.NewHTTPKeyResolver(signaturekey.HTTPKeyResolverConfig{
		Client: httpClient,
		Clock:  clock,
		Admit: func(_ context.Context, endpoint string) error {
			if strings.HasSuffix(endpoint, ".example/.well-known/aauth-agent.json") ||
				strings.HasSuffix(endpoint, ".example/.well-known/aauth-person.json") ||
				strings.HasSuffix(endpoint, ".example/.well-known/aauth-resource.json") ||
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
		Issuer: agentProviderID, SigningKey: agentProviderKey, Clock: clock,
		NewID: func() string { return "deferred-ps-agent-token" },
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

	personTokens := newMemoryPersonTokenStore()
	authorizations := newIntegrationDeferredAuthorizationStore()
	ids := []string{"deferred-ps-person-token", "deferred-ps-auth-token"}
	newIDCalls := 0
	policyCalls := 0
	newPeople := func() *personserver.Server {
		people, err := personserver.NewPSAuthorization(personserver.PSAuthorizationConfig{
			Issuer: personServerID, SigningKey: personServerKey, KeyResolver: keyResolver,
			Clock: clock, Tokens: personTokens,
			NewID: func() string {
				if len(ids) == 0 {
					t.Fatal("Person Server minted an unexpected third token")
				}
				id := ids[0]
				ids = ids[1:]
				newIDCalls++
				return id
			},
			BindPerson: func(_ context.Context, request personserver.PersonTokenRequest) (personserver.Person, error) {
				if request.Agent != agentID || request.Resource != resourceID {
					return personserver.Person{}, errors.New("unexpected person-token request")
				}
				return personserver.Person{Subject: "person-123", Tenant: "tenant-1", Lifetime: 20 * time.Minute}, nil
			},
			RequireAuthorizationInteraction: func(_ context.Context, request personserver.AuthorizationRequest) (personserver.AuthorizationInteractionPolicy, bool, error) {
				policyCalls++
				if request.Agent != agentID || request.Resource != resourceID || request.Subject != "person-123" ||
					request.Tenant != "tenant-1" || !slices.Equal(request.Scopes, scope) ||
					!slices.Equal(request.Capabilities, []string{"interaction"}) {
					return personserver.AuthorizationInteractionPolicy{}, false, errors.New("unexpected deferred authorization request")
				}
				return personserver.AuthorizationInteractionPolicy{
					URL: personServerID + "/consent", Lifetime: 4 * time.Minute, RetryAfter: 0,
				}, true, nil
			},
			AuthorizationInteractions: authorizations,
		})
		if err != nil {
			t.Fatal(err)
		}
		return people
	}

	protectedCalls := 0
	protectedResource, err := resource.NewPSAuthorization(resource.PSAuthorizationConfig{
		Issuer: resourceID, SigningKey: resourceKey, KeyResolver: keyResolver, Clock: clock,
		NewID: func() string { return "deferred-ps-resource-token" },
		ScopeDescriptions: map[string]string{
			"records.read": "Read records", "records.list": "List records",
		},
		RequiredScopes: func(*http.Request) []string { return append([]string(nil), scope...) },
		ResolvePerson: func(_ context.Context, identity resource.PersonIdentity, personContext resource.PersonContext) error {
			if identity != (resource.PersonIdentity{Issuer: personServerID, Subject: "person-123"}) || personContext.Tenant != "tenant-1" {
				return errors.New("unexpected Resource person")
			}
			return nil
		},
		Protected: http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			protectedCalls++
			principal, ok := resource.AuthPrincipalFromContext(request.Context())
			if !ok || principal.PersonServer != personServerID || principal.Subject != "person-123" ||
				principal.Tenant != "tenant-1" || !slices.Equal(principal.Scope, scope) ||
				!principal.Confirmation.Equal(agentKey.PublicJWK()) {
				t.Errorf("deferred principal = %#v, present=%t", principal, ok)
			}
			_, _ = io.WriteString(response, "deferred accepted")
		}),
	})
	if err != nil {
		t.Fatal(err)
	}

	tokenRequests := 0
	pollRequests := 0
	people := newPeople()
	servePeople := func(server *personserver.Server) {
		network.Handle(personServerID, http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			switch {
			case request.Method == http.MethodPost && request.URL.Path == "/token":
				tokenRequests++
				if request.Header.Get("Prefer") != "wait=0" {
					t.Errorf("auth-token Prefer = %q, want wait=0", request.Header.Get("Prefer"))
				}
			case request.Method == http.MethodGet && strings.HasPrefix(request.URL.Path, "/token/pending/"):
				pollRequests++
			}
			server.Handler().ServeHTTP(response, request)
		}))
	}
	accessCalls := 0
	network.Handle(agentProviderID, provider.Handler())
	servePeople(people)
	network.Handle(resourceID, protectedResource.Handler())
	network.Handle(accessServerID, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { accessCalls++ }))

	newReader := func() *clientagent.Client {
		reader, err := clientagent.New(ctx, clientagent.Config{
			Identifier: agentID, SigningKey: agentKey, AgentToken: agentToken,
			KeyResolver: keyResolver, HTTPClient: httpClient, Clock: clock,
		})
		if err != nil {
			t.Fatal(err)
		}
		return reader
	}
	reader := newReader()
	personResult, err := reader.PersonToken(ctx, clientagent.PersonTokenRequest{
		PersonServer: personServerID, Resource: resourceID,
	})
	if err != nil {
		t.Fatal(err)
	}
	personToken, ok := personResult.Token()
	if !ok {
		t.Fatalf("person-token result = %#v", personResult)
	}
	resourceToken, err := reader.Authorize(ctx, clientagent.AuthorizeRequest{
		Resource: resourceID, PersonToken: personToken, Scopes: scope,
	})
	if err != nil {
		t.Fatal(err)
	}

	begin, err := reader.BeginExchange(ctx, clientagent.ExchangeRequest{
		PersonServer: personServerID, ResourceToken: resourceToken, PresentedToken: personToken,
		Capabilities: []string{"interaction"},
	})
	if err != nil {
		t.Fatal(err)
	}
	pending, ok := begin.Pending()
	if !ok || pending.PersonServer() != personServerID || pending.RetryAfter() != 0 || pending.Interacting() ||
		!strings.HasPrefix(pending.Location(), personServerID+"/token/pending/") ||
		!strings.HasPrefix(pending.InteractionURL(), personServerID+"/consent/") || pending.InteractionCode() == "" {
		t.Fatalf("initial pending = %#v, present=%t", pending, ok)
	}
	if tokenRequests != 1 || pollRequests != 0 || protectedCalls != 0 || accessCalls != 0 ||
		policyCalls != 1 || newIDCalls != 1 {
		t.Fatalf("initial effects: token=%d poll=%d protected=%d AS=%d policy=%d ids=%d",
			tokenRequests, pollRequests, protectedCalls, accessCalls, policyCalls, newIDCalls)
	}

	reference := strings.TrimPrefix(pending.InteractionURL(), personServerID+"/consent/")
	if reference == "" || reference == pending.InteractionURL() {
		t.Fatalf("interaction URL = %q", pending.InteractionURL())
	}
	if _, err := people.ConsumeAuthorizationInteractionCode(ctx, reference, "***"); !errors.Is(err, personserver.ErrAuthorizationInteractionCodeInvalid) {
		t.Fatalf("malformed interaction code = %v", err)
	}
	if attempts := authorizations.failedAttempts(t, reference); attempts != 1 {
		t.Fatalf("failed interaction-code attempts = %d, want 1", attempts)
	}
	interaction, err := people.ConsumeAuthorizationInteractionCode(ctx, reference, strings.ToLower(pending.InteractionCode()))
	if err != nil {
		t.Fatal(err)
	}

	// Recompose the Person Server over the retained store after the code is used.
	people = newPeople()
	servePeople(people)
	interactingResult, err := reader.PollExchange(ctx, pending)
	if err != nil {
		t.Fatal(err)
	}
	interacting, ok := interactingResult.Pending()
	if !ok || !interacting.Interacting() || pollRequests != 1 {
		t.Fatalf("interacting result = %#v, present=%t, polls=%d", interactingResult, ok, pollRequests)
	}
	interactingSnapshot, err := authorizations.LoadPendingAuthorization(ctx, reference, now)
	if err != nil || interactingSnapshot.State != personserver.AuthorizationPollInteracting ||
		!integrationAuthorizationApprovalIsZero(interactingSnapshot.Approval) {
		t.Fatalf("interacting snapshot = %#v, %v", interactingSnapshot, err)
	}
	resumed, err := people.ResumeAuthorizationInteraction(ctx, interaction.Reference())
	if err != nil {
		t.Fatal(err)
	}
	decision := personserver.AuthorizationDecision{Scopes: append([]string(nil), scope...), Lifetime: 10 * time.Minute}
	beforeApprovalIDs := newIDCalls
	if err := people.ApproveAuthorizationInteraction(ctx, resumed, decision); err != nil {
		t.Fatal(err)
	}
	approvedSnapshot, err := authorizations.LoadPendingAuthorization(ctx, reference, now)
	if err != nil || approvedSnapshot.State != personserver.AuthorizationPollApproved ||
		approvedSnapshot.Approval.Token == "" || approvedSnapshot.Approval.ExpiresIn <= 0 ||
		approvedSnapshot.Approval.DecidedAt.IsZero() {
		t.Fatalf("approved snapshot = %#v, %v", approvedSnapshot, err)
	}
	if err := people.ApproveAuthorizationInteraction(ctx, resumed, decision); err != nil {
		t.Fatalf("exact repeated approval: %v", err)
	}
	noncanonicalProposal := cloneIntegrationAuthorizationApproval(approvedSnapshot.Approval)
	noncanonicalProposal.Decision.Scopes = []string{"records.list", "records.read"}
	noncanonicalProposal.Token = "not-the-canonical-auth-token"
	noncanonicalProposal.DecidedAt = noncanonicalProposal.DecidedAt.Add(time.Second)
	canonical, err := authorizations.ApprovePendingAuthorization(ctx, reference, noncanonicalProposal)
	if err != nil || canonical.Token != approvedSnapshot.Approval.Token ||
		canonical.Token == noncanonicalProposal.Token || canonical.DecidedAt != approvedSnapshot.Approval.DecidedAt {
		t.Fatalf("canonical repeated approval = %#v, %v; first=%#v", canonical, err, approvedSnapshot.Approval)
	}
	if newIDCalls != beforeApprovalIDs+1 {
		t.Fatalf("exact repeated approval minted %d tokens, want 1", newIDCalls-beforeApprovalIDs)
	}

	// A new Agent client with the same stable identity and key continues the handle.
	recomposedReader := newReader()
	approvedResult, err := recomposedReader.PollExchange(ctx, interacting)
	if err != nil {
		t.Fatal(err)
	}
	authToken, ok := approvedResult.Token()
	if !ok || authToken == "" || pollRequests != 2 {
		t.Fatalf("approved result = %#v, present=%t, polls=%d", approvedResult, ok, pollRequests)
	}
	authClaims, err := aauth.VerifyAuthToken(ctx, authToken, keyResolver, clock)
	if err != nil {
		t.Fatal(err)
	}
	if authClaims.Issuer != personServerID || authClaims.DWK != aauth.PersonDiscoveryDocument ||
		authClaims.Audience != resourceID || authClaims.PersonServer != personServerID ||
		authClaims.Subject != "person-123" || authClaims.Tenant != "tenant-1" ||
		!authClaims.Confirmation.JWK.Equal(agentKey.PublicJWK()) || !slices.Equal(strings.Fields(authClaims.Scope), scope) {
		t.Fatalf("deferred auth token = %#v", authClaims)
	}

	protectedRequest, _ := http.NewRequest(http.MethodGet, resourceID+"/records", nil)
	protectedResponse, err := recomposedReader.Do(ctx, clientagent.Call{Request: protectedRequest, AuthToken: authToken})
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(protectedResponse.Body)
	protectedResponse.Body.Close()
	if protectedResponse.StatusCode != http.StatusOK || string(body) != "deferred accepted" || protectedCalls != 1 || accessCalls != 0 {
		t.Fatalf("protected response=%d %q protected=%d AS=%d", protectedResponse.StatusCode, body, protectedCalls, accessCalls)
	}

	_, err = recomposedReader.PollExchange(ctx, interacting)
	var gone *aauth.ProblemError
	if !errors.As(err, &gone) || gone.Status != http.StatusGone || gone.Code != "invalid_code" || pollRequests != 3 {
		t.Fatalf("terminal replay = %v, problem=%#v, polls=%d", err, gone, pollRequests)
	}
	creates, approvals, terminalConsumes := authorizations.counts()
	if creates != 1 || approvals != 1 || terminalConsumes != 1 || policyCalls != 1 ||
		newIDCalls != 2 || accessCalls != 0 {
		t.Fatalf("retained effects: creates=%d approvals=%d consumes=%d policy=%d ids=%d AS=%d",
			creates, approvals, terminalConsumes, policyCalls, newIDCalls, accessCalls)
	}
}

func TestDeferredPSAuthorizationStoreClarificationContract(t *testing.T) {
	t.Parallel()

	storetest.RunDeferredAuthorization(t, storetest.DeferredAuthorizationContract{
		New: func(testing.TB) personserver.DeferredAuthorizationStore {
			return newIntegrationDeferredAuthorizationStore()
		},
	})

	storetest.RunClarification(t, storetest.Contract{
		New: func(testing.TB) storetest.ClarificationStore {
			return newIntegrationDeferredAuthorizationStore()
		},
	})
}

type integrationDeferredAuthorizationStore struct {
	mu               sync.Mutex
	pending          map[string]*integrationPendingAuthorization
	byCode           map[[32]byte]string
	creates          int
	approvals        int
	terminalConsumes int
}

type integrationPendingAuthorization struct {
	record             personserver.PendingAuthorizationRecord
	state              personserver.AuthorizationPollState
	clarifications     []personserver.AuthorizationClarificationRound
	approval           personserver.AuthorizationApproval
	deniedAt           time.Time
	failedCodeAttempts int
	cancelledAt        time.Time
}

func newIntegrationDeferredAuthorizationStore() *integrationDeferredAuthorizationStore {
	return &integrationDeferredAuthorizationStore{
		pending: make(map[string]*integrationPendingAuthorization),
		byCode:  make(map[[32]byte]string),
	}
}

func (store *integrationDeferredAuthorizationStore) CreatePendingAuthorization(
	_ context.Context,
	record personserver.PendingAuthorizationRecord,
) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if _, exists := store.pending[record.ID]; exists {
		return personserver.ErrPendingAuthorizationConflict
	}
	if _, exists := store.byCode[record.CodeSHA256]; exists {
		return personserver.ErrPendingAuthorizationConflict
	}
	store.pending[record.ID] = &integrationPendingAuthorization{
		record: cloneIntegrationPendingAuthorization(record), state: personserver.AuthorizationPollWaiting,
	}
	store.byCode[record.CodeSHA256] = record.ID
	store.creates++
	return nil
}

func (store *integrationDeferredAuthorizationStore) ConsumeAuthorizationInteractionCode(
	_ context.Context,
	personServer string,
	reference string,
	presentation personserver.AuthorizationCodePresentation,
	now time.Time,
) (personserver.PendingAuthorizationRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	pending, ok := store.pending[reference]
	if !ok || pending.record.PersonServer != personServer {
		return personserver.PendingAuthorizationRecord{}, personserver.ErrAuthorizationInteractionCodeInvalid
	}
	materializeIntegrationAuthorizationExpiry(pending, now)
	switch pending.state {
	case personserver.AuthorizationPollGone, personserver.AuthorizationPollCancelled:
		return personserver.PendingAuthorizationRecord{}, personserver.ErrPendingAuthorizationGone
	case personserver.AuthorizationPollExpired:
		return personserver.PendingAuthorizationRecord{}, personserver.ErrPendingAuthorizationExpired
	case personserver.AuthorizationPollInteracting, personserver.AuthorizationPollClarifying:
		return personserver.PendingAuthorizationRecord{}, personserver.ErrAuthorizationInteractionCodeUsed
	case personserver.AuthorizationPollApproved, personserver.AuthorizationPollDenied,
		personserver.AuthorizationPollAbandoned, personserver.AuthorizationPollServerError:
		return personserver.PendingAuthorizationRecord{}, personserver.ErrAuthorizationInteractionCodeUsed
	}
	if !presentation.SyntacticallyValid || pending.record.CodeSHA256 != presentation.CodeSHA256 {
		pending.failedCodeAttempts++
		if pending.failedCodeAttempts >= personserver.MaximumAuthorizationCodeAttempts {
			pending.failedCodeAttempts = personserver.MaximumAuthorizationCodeAttempts
			pending.state = personserver.AuthorizationPollGone
			return personserver.PendingAuthorizationRecord{}, personserver.ErrPendingAuthorizationGone
		}
		return personserver.PendingAuthorizationRecord{}, personserver.ErrAuthorizationInteractionCodeInvalid
	}
	if pending.state != personserver.AuthorizationPollWaiting {
		return personserver.PendingAuthorizationRecord{}, personserver.ErrAuthorizationInteractionCodeUsed
	}
	pending.state = personserver.AuthorizationPollInteracting
	return cloneIntegrationPendingAuthorization(pending.record), nil
}

func (store *integrationDeferredAuthorizationStore) LoadPendingAuthorization(
	_ context.Context,
	id string,
	now time.Time,
) (personserver.PendingAuthorizationSnapshot, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	pending, ok := store.pending[id]
	if !ok {
		return personserver.PendingAuthorizationSnapshot{}, personserver.ErrPendingAuthorizationNotFound
	}
	materializeIntegrationAuthorizationExpiry(pending, now)
	snapshot := personserver.PendingAuthorizationSnapshot{
		Record: cloneIntegrationPendingAuthorization(pending.record), State: pending.state,
		Clarifications: cloneIntegrationAuthorizationClarifications(pending.clarifications),
		CancelledAt:    pending.cancelledAt,
	}
	if pending.state == personserver.AuthorizationPollApproved {
		snapshot.Approval = cloneIntegrationAuthorizationApproval(pending.approval)
	}
	return snapshot, nil
}

func (store *integrationDeferredAuthorizationStore) RequestPendingAuthorizationClarification(
	_ context.Context,
	id string,
	request personserver.AuthorizationClarificationRequest,
	now time.Time,
) (personserver.AuthorizationClarificationRound, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	pending, ok := store.pending[id]
	if !ok {
		return personserver.AuthorizationClarificationRound{}, personserver.ErrPendingAuthorizationNotFound
	}
	materializeIntegrationAuthorizationExpiry(pending, now)
	if pending.state == personserver.AuthorizationPollClarifying {
		current := pending.clarifications[len(pending.clarifications)-1]
		if current.Question == request.Question && reflect.DeepEqual(current.Options, request.Options) &&
			current.ExpiresAt.Sub(current.RequestedAt) == request.Lifetime {
			return cloneIntegrationAuthorizationClarification(current), nil
		}
		return personserver.AuthorizationClarificationRound{}, personserver.ErrPendingAuthorizationConflict
	}
	if pending.state == personserver.AuthorizationPollExpired {
		return personserver.AuthorizationClarificationRound{}, personserver.ErrPendingAuthorizationExpired
	}
	if pending.state == personserver.AuthorizationPollGone || pending.state == personserver.AuthorizationPollCancelled {
		return personserver.AuthorizationClarificationRound{}, personserver.ErrPendingAuthorizationGone
	}
	if pending.state != personserver.AuthorizationPollInteracting ||
		len(pending.clarifications) >= personserver.MaximumAuthorizationClarificationRounds {
		return personserver.AuthorizationClarificationRound{}, personserver.ErrPendingAuthorizationConflict
	}
	if err := validateIntegrationAuthorizationClarificationRequest(request, now, pending.record.ExpiresAt); err != nil {
		return personserver.AuthorizationClarificationRound{}, err
	}
	round := personserver.AuthorizationClarificationRound{
		Question: request.Question, Options: append([]string(nil), request.Options...),
		RequestedAt: now, ExpiresAt: now.Add(request.Lifetime),
	}
	pending.clarifications = append(pending.clarifications, cloneIntegrationAuthorizationClarification(round))
	pending.state = personserver.AuthorizationPollClarifying
	return cloneIntegrationAuthorizationClarification(round), nil
}

func (store *integrationDeferredAuthorizationStore) AnswerPendingAuthorizationClarification(
	_ context.Context,
	id string,
	identity personserver.AuthorizationPollIdentity,
	answer string,
	now time.Time,
) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	pending, ok := store.pending[id]
	if !ok || !integrationAuthorizationIdentityMatches(pending, identity) {
		return personserver.ErrPendingAuthorizationNotFound
	}
	materializeIntegrationAuthorizationExpiry(pending, now)
	if pending.state == personserver.AuthorizationPollExpired {
		return personserver.ErrPendingAuthorizationExpired
	}
	if pending.state == personserver.AuthorizationPollGone || pending.state == personserver.AuthorizationPollCancelled {
		return personserver.ErrPendingAuthorizationGone
	}
	if len(pending.clarifications) == 0 {
		return personserver.ErrPendingAuthorizationConflict
	}
	latest := &pending.clarifications[len(pending.clarifications)-1]
	if pending.state == personserver.AuthorizationPollInteracting && latest.Response != "" {
		if latest.Response == answer {
			return nil
		}
		return personserver.ErrPendingAuthorizationConflict
	}
	if pending.state != personserver.AuthorizationPollClarifying || latest.Response != "" ||
		strings.TrimSpace(answer) == "" || len(answer) > personserver.MaximumAuthorizationClarificationBytes ||
		!now.Before(latest.ExpiresAt) {
		return personserver.ErrPendingAuthorizationConflict
	}
	latest.Response = answer
	latest.RespondedAt = now
	pending.state = personserver.AuthorizationPollInteracting
	return nil
}

func (store *integrationDeferredAuthorizationStore) CancelPendingAuthorizationClarification(
	_ context.Context,
	id string,
	identity personserver.AuthorizationPollIdentity,
	now time.Time,
) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	pending, ok := store.pending[id]
	if !ok || !integrationAuthorizationIdentityMatches(pending, identity) {
		return personserver.ErrPendingAuthorizationNotFound
	}
	materializeIntegrationAuthorizationExpiry(pending, now)
	if pending.state == personserver.AuthorizationPollExpired {
		return personserver.ErrPendingAuthorizationExpired
	}
	if pending.state == personserver.AuthorizationPollGone || pending.state == personserver.AuthorizationPollCancelled {
		return personserver.ErrPendingAuthorizationGone
	}
	if pending.state != personserver.AuthorizationPollClarifying {
		return personserver.ErrPendingAuthorizationConflict
	}
	pending.state = personserver.AuthorizationPollCancelled
	pending.cancelledAt = now
	return nil
}

func (store *integrationDeferredAuthorizationStore) ApprovePendingAuthorization(
	_ context.Context,
	id string,
	approval personserver.AuthorizationApproval,
) (personserver.AuthorizationApproval, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	pending, ok := store.pending[id]
	if !ok {
		return personserver.AuthorizationApproval{}, personserver.ErrPendingAuthorizationNotFound
	}
	materializeIntegrationAuthorizationExpiry(pending, approval.DecidedAt)
	if pending.state == personserver.AuthorizationPollApproved {
		if !integrationAuthorizationDecisionsSemanticallyEqual(pending.approval.Decision, approval.Decision) {
			return personserver.AuthorizationApproval{}, personserver.ErrPendingAuthorizationConflict
		}
		return cloneIntegrationAuthorizationApproval(pending.approval), nil
	}
	if pending.state == personserver.AuthorizationPollExpired {
		return personserver.AuthorizationApproval{}, personserver.ErrPendingAuthorizationExpired
	}
	if pending.state != personserver.AuthorizationPollInteracting {
		return personserver.AuthorizationApproval{}, personserver.ErrPendingAuthorizationConflict
	}
	if !integrationAuthorizationApprovalIsComplete(pending.record, approval) {
		return personserver.AuthorizationApproval{}, personserver.ErrPendingAuthorizationConflict
	}
	pending.approval = cloneIntegrationAuthorizationApproval(approval)
	pending.state = personserver.AuthorizationPollApproved
	store.approvals++
	return cloneIntegrationAuthorizationApproval(pending.approval), nil
}

func (store *integrationDeferredAuthorizationStore) DenyPendingAuthorization(
	_ context.Context,
	id string,
	decidedAt time.Time,
) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	pending, ok := store.pending[id]
	if !ok {
		return personserver.ErrPendingAuthorizationNotFound
	}
	materializeIntegrationAuthorizationExpiry(pending, decidedAt)
	if pending.state == personserver.AuthorizationPollDenied {
		return nil
	}
	if pending.state == personserver.AuthorizationPollExpired {
		return personserver.ErrPendingAuthorizationExpired
	}
	if pending.state != personserver.AuthorizationPollInteracting {
		return personserver.ErrPendingAuthorizationConflict
	}
	pending.deniedAt = decidedAt
	pending.state = personserver.AuthorizationPollDenied
	return nil
}

func (store *integrationDeferredAuthorizationStore) AbandonPendingAuthorization(
	_ context.Context,
	id string,
	now time.Time,
) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	pending, ok := store.pending[id]
	if !ok {
		return personserver.ErrPendingAuthorizationNotFound
	}
	materializeIntegrationAuthorizationExpiry(pending, now)
	if pending.state == personserver.AuthorizationPollAbandoned {
		return nil
	}
	if pending.state == personserver.AuthorizationPollExpired {
		return personserver.ErrPendingAuthorizationExpired
	}
	if pending.state != personserver.AuthorizationPollInteracting {
		return personserver.ErrPendingAuthorizationConflict
	}
	pending.state = personserver.AuthorizationPollAbandoned
	return nil
}

func (store *integrationDeferredAuthorizationStore) FailPendingAuthorization(
	_ context.Context,
	id string,
	now time.Time,
) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	pending, ok := store.pending[id]
	if !ok {
		return personserver.ErrPendingAuthorizationNotFound
	}
	materializeIntegrationAuthorizationExpiry(pending, now)
	if pending.state == personserver.AuthorizationPollServerError {
		return nil
	}
	if pending.state == personserver.AuthorizationPollExpired {
		return personserver.ErrPendingAuthorizationExpired
	}
	if pending.state != personserver.AuthorizationPollWaiting && pending.state != personserver.AuthorizationPollInteracting {
		return personserver.ErrPendingAuthorizationConflict
	}
	pending.state = personserver.AuthorizationPollServerError
	return nil
}

func (store *integrationDeferredAuthorizationStore) PollPendingAuthorization(
	_ context.Context,
	id string,
	identity personserver.AuthorizationPollIdentity,
	now time.Time,
) (personserver.AuthorizationPollRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	pending, ok := store.pending[id]
	if !ok {
		return personserver.AuthorizationPollRecord{}, personserver.ErrPendingAuthorizationNotFound
	}
	materializeIntegrationAuthorizationExpiry(pending, now)
	if !integrationAuthorizationIdentityMatches(pending, identity) {
		return personserver.AuthorizationPollRecord{}, personserver.ErrPendingAuthorizationNotFound
	}
	if pending.state == personserver.AuthorizationPollGone || pending.state == personserver.AuthorizationPollCancelled {
		return personserver.AuthorizationPollRecord{}, personserver.ErrPendingAuthorizationGone
	}
	return integrationAuthorizationPollRecord(pending), nil
}

func (store *integrationDeferredAuthorizationStore) ConsumePendingAuthorizationResult(
	_ context.Context,
	id string,
	result personserver.AuthorizationPollRecord,
) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	pending, ok := store.pending[id]
	if !ok {
		return personserver.ErrPendingAuthorizationNotFound
	}
	if pending.state == personserver.AuthorizationPollGone || pending.state == personserver.AuthorizationPollCancelled {
		return personserver.ErrPendingAuthorizationGone
	}
	if pending.state != personserver.AuthorizationPollApproved && pending.state != personserver.AuthorizationPollDenied &&
		pending.state != personserver.AuthorizationPollAbandoned && pending.state != personserver.AuthorizationPollServerError &&
		pending.state != personserver.AuthorizationPollExpired {
		return personserver.ErrPendingAuthorizationConflict
	}
	if !reflect.DeepEqual(result, integrationAuthorizationPollRecord(pending)) {
		return personserver.ErrPendingAuthorizationConflict
	}
	pending.state = personserver.AuthorizationPollGone
	store.terminalConsumes++
	return nil
}

func (store *integrationDeferredAuthorizationStore) counts() (int, int, int) {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.creates, store.approvals, store.terminalConsumes
}

func (store *integrationDeferredAuthorizationStore) onlyPending(t *testing.T) personserver.PendingAuthorizationRecord {
	t.Helper()
	store.mu.Lock()
	defer store.mu.Unlock()
	if len(store.pending) != 1 {
		t.Fatalf("pending authorization records = %d, want 1", len(store.pending))
	}
	for _, pending := range store.pending {
		return cloneIntegrationPendingAuthorization(pending.record)
	}
	panic("unreachable")
}

func (store *integrationDeferredAuthorizationStore) failedAttempts(t *testing.T, reference string) int {
	t.Helper()
	store.mu.Lock()
	defer store.mu.Unlock()
	pending, ok := store.pending[reference]
	if !ok {
		t.Fatalf("pending authorization %q not found", reference)
	}
	return pending.failedCodeAttempts
}

func integrationAuthorizationPollRecord(pending *integrationPendingAuthorization) personserver.AuthorizationPollRecord {
	result := personserver.AuthorizationPollRecord{
		State: pending.state, Pending: cloneIntegrationPendingAuthorization(pending.record),
		RetryAfter: pending.record.RetryAfter,
	}
	if pending.state == personserver.AuthorizationPollClarifying {
		clarification := cloneIntegrationAuthorizationClarification(pending.clarifications[len(pending.clarifications)-1])
		result.Clarification = &clarification
	}
	if pending.state == personserver.AuthorizationPollApproved {
		result.Token = pending.approval.Token
		result.Decision = cloneIntegrationAuthorizationDecision(pending.approval.Decision)
		result.ExpiresIn = pending.approval.ExpiresIn
		result.DecidedAt = pending.approval.DecidedAt
	}
	return result
}

func cloneIntegrationPendingAuthorization(record personserver.PendingAuthorizationRecord) personserver.PendingAuthorizationRecord {
	record.Scopes = append([]string(nil), record.Scopes...)
	record.Capabilities = append([]string(nil), record.Capabilities...)
	record.AgentAdditionalClaims = cloneIntegrationRawClaims(record.AgentAdditionalClaims)
	record.SubagentAdditionalClaims = cloneIntegrationRawClaims(record.SubagentAdditionalClaims)
	return record
}

func cloneIntegrationRawClaims(claims map[string]json.RawMessage) map[string]json.RawMessage {
	if len(claims) == 0 {
		return nil
	}
	cloned := make(map[string]json.RawMessage, len(claims))
	for name, value := range claims {
		cloned[name] = append(json.RawMessage(nil), value...)
	}
	return cloned
}

func cloneIntegrationAuthorizationDecision(decision personserver.AuthorizationDecision) personserver.AuthorizationDecision {
	decision.Scopes = append([]string(nil), decision.Scopes...)
	return decision
}

func cloneIntegrationAuthorizationApproval(approval personserver.AuthorizationApproval) personserver.AuthorizationApproval {
	approval.Decision = cloneIntegrationAuthorizationDecision(approval.Decision)
	return approval
}

func cloneIntegrationAuthorizationClarification(
	round personserver.AuthorizationClarificationRound,
) personserver.AuthorizationClarificationRound {
	round.Options = append([]string(nil), round.Options...)
	return round
}

func cloneIntegrationAuthorizationClarifications(
	rounds []personserver.AuthorizationClarificationRound,
) []personserver.AuthorizationClarificationRound {
	if len(rounds) == 0 {
		return nil
	}
	cloned := make([]personserver.AuthorizationClarificationRound, len(rounds))
	for index, round := range rounds {
		cloned[index] = cloneIntegrationAuthorizationClarification(round)
	}
	return cloned
}

func integrationAuthorizationApprovalIsZero(approval personserver.AuthorizationApproval) bool {
	return len(approval.Decision.Scopes) == 0 && approval.Decision.Lifetime == 0 &&
		approval.Token == "" && approval.ExpiresIn == 0 && approval.DecidedAt.IsZero()
}

func integrationAuthorizationApprovalIsComplete(
	pending personserver.PendingAuthorizationRecord,
	approval personserver.AuthorizationApproval,
) bool {
	if approval.Decision.Lifetime <= 0 || approval.Decision.Lifetime > time.Hour ||
		approval.Token == "" || approval.ExpiresIn <= 0 || approval.DecidedAt.IsZero() ||
		approval.DecidedAt.Before(pending.CreatedAt) || !approval.DecidedAt.Before(pending.ExpiresAt) ||
		len(approval.Decision.Scopes) == 0 {
		return false
	}
	requested := make(map[string]struct{}, len(pending.Scopes))
	for _, scope := range pending.Scopes {
		if scope == "" {
			return false
		}
		requested[scope] = struct{}{}
	}
	granted := make(map[string]struct{}, len(approval.Decision.Scopes))
	for _, scope := range approval.Decision.Scopes {
		if _, ok := requested[scope]; !ok {
			return false
		}
		if _, duplicate := granted[scope]; duplicate {
			return false
		}
		granted[scope] = struct{}{}
	}
	return true
}

func integrationAuthorizationDecisionsSemanticallyEqual(
	left personserver.AuthorizationDecision,
	right personserver.AuthorizationDecision,
) bool {
	if left.Lifetime != right.Lifetime || len(left.Scopes) != len(right.Scopes) {
		return false
	}
	leftScopes := make(map[string]struct{}, len(left.Scopes))
	for _, scope := range left.Scopes {
		if _, duplicate := leftScopes[scope]; duplicate {
			return false
		}
		leftScopes[scope] = struct{}{}
	}
	rightScopes := make(map[string]struct{}, len(right.Scopes))
	for _, scope := range right.Scopes {
		if _, duplicate := rightScopes[scope]; duplicate {
			return false
		}
		rightScopes[scope] = struct{}{}
		if _, ok := leftScopes[scope]; !ok {
			return false
		}
	}
	return true
}

func materializeIntegrationAuthorizationExpiry(pending *integrationPendingAuthorization, now time.Time) {
	if (pending.state == personserver.AuthorizationPollWaiting || pending.state == personserver.AuthorizationPollInteracting) &&
		!now.Before(pending.record.ExpiresAt) {
		pending.state = personserver.AuthorizationPollExpired
	}
	if pending.state == personserver.AuthorizationPollClarifying {
		deadline := pending.clarifications[len(pending.clarifications)-1].ExpiresAt
		if !now.Before(deadline) || !now.Before(pending.record.ExpiresAt) {
			pending.state = personserver.AuthorizationPollExpired
		}
	}
}

func integrationAuthorizationIdentityMatches(
	pending *integrationPendingAuthorization,
	identity personserver.AuthorizationPollIdentity,
) bool {
	thumbprint, err := pending.record.Confirmation.Thumbprint()
	return err == nil && identity.PersonServer == pending.record.PersonServer &&
		identity.AgentProvider == pending.record.AgentProvider && identity.Agent == pending.record.Agent &&
		identity.ConfirmationThumbprint == thumbprint
}

func validateIntegrationAuthorizationClarificationRequest(
	request personserver.AuthorizationClarificationRequest,
	now time.Time,
	pendingExpiry time.Time,
) error {
	if strings.TrimSpace(request.Question) == "" || len(request.Question) > personserver.MaximumAuthorizationClarificationBytes {
		return errors.New("personserver: clarification question must be nonempty and at most 65536 bytes")
	}
	if request.Lifetime <= 0 || request.Lifetime%time.Second != 0 {
		return errors.New("personserver: clarification lifetime must be positive whole seconds")
	}
	if !now.Add(request.Lifetime).After(now) || now.Add(request.Lifetime).After(pendingExpiry) {
		return errors.New("personserver: clarification deadline exceeds the pending authorization")
	}
	if len(request.Options) > 32 {
		return errors.New("personserver: clarification has too many options")
	}
	seen := make(map[string]struct{}, len(request.Options))
	for _, option := range request.Options {
		if strings.TrimSpace(option) == "" || len(option) > 4<<10 {
			return errors.New("personserver: clarification option must be nonempty and at most 4096 bytes")
		}
		if _, duplicate := seen[option]; duplicate {
			return errors.New("personserver: clarification options must be distinct")
		}
		seen[option] = struct{}{}
	}
	return nil
}

var _ personserver.DeferredAuthorizationStore = (*integrationDeferredAuthorizationStore)(nil)
var _ personserver.AuthorizationClarificationStore = (*integrationDeferredAuthorizationStore)(nil)
