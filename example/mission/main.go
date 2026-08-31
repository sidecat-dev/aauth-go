// The mission example runs one immediate mission-bound three-party journey in
// process. Each role still communicates through ordinary HTTP handlers.
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
	"net/http/httptest"
	"os"
	"sync"
	"time"

	aauth "aauth-go"
	clientagent "aauth-go/agent"
	"aauth-go/agentprovider"
	"aauth-go/jose"
	"aauth-go/personserver"
	"aauth-go/resource"
	"aauth-go/signaturekey"
)

const (
	agentProviderID = "https://agents.example"
	agentID         = "aauth:reader@agents.example"
	personServerID  = "https://person.example"
	resourceID      = "https://resource.example"
	scope           = "records.read"
)

func main() {
	now := time.Date(2026, 8, 30, 20, 30, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	providerKey := newSigningKey("agent-provider-key")
	agentKey := newSigningKey("agent-key")
	personKey := newSigningKey("person-server-key")
	resourceKey := newSigningKey("resource-key")
	network := newLogicalTransport()
	httpClient := &http.Client{Transport: network}
	resolver := must(signaturekey.NewHTTPKeyResolver(signaturekey.HTTPKeyResolverConfig{
		Client: httpClient, Clock: clock, Admit: network.Admit,
	}))

	provider := must(agentprovider.New(agentprovider.Config{
		Issuer: agentProviderID, SigningKey: providerKey, Clock: clock,
		NewID: func() string { return "agent-token-1" },
	}))
	agentToken := must(provider.Issue(aauth.AgentTokenRequest{
		Agent: agentID, PersonServer: personServerID,
		PublicKey: agentKey.PublicJWK(), Lifetime: time.Hour,
	}))
	missionExpiry := now.Add(15 * time.Minute)
	personAcceptedCompletion := false
	ids := []string{"person-token-1", "auth-token-1"}
	people := must(personserver.NewPSAuthorization(personserver.PSAuthorizationConfig{
		Issuer: personServerID, SigningKey: personKey,
		KeyResolver: resolver, Clock: clock, Tokens: newMemoryMissionStore(),
		NewID: func() string {
			id := ids[0]
			ids = ids[1:]
			return id
		},
		Missions: &personserver.MissionConfig{
			Approve: func(_ context.Context, request personserver.MissionApprovalRequest) (personserver.MissionDecision, error) {
				return personserver.MissionDecision{
					Description:       request.Proposal.Description,
					ApprovedResources: request.Proposal.Resources,
					ExpiresAt:         &missionExpiry,
				}, nil
			},
			AcceptUpdate: func(_ context.Context, request personserver.MissionUpdatePolicyRequest) error {
				if request.Document.Update.Description == "" {
					return errors.New("mission update description is required")
				}
				return nil
			},
			ConfirmPersonAcceptedCompletion: func(_ context.Context, request personserver.MissionCompletionPolicyRequest) error {
				if !personAcceptedCompletion {
					return fmt.Errorf("%w: the responsible person has not accepted completion", personserver.ErrMissionDenied)
				}
				return nil
			},
		},
		BindPerson: func(_ context.Context, request personserver.PersonTokenRequest) (personserver.Person, error) {
			if request.Mission == nil || request.Mission.Blob.Description == "" {
				return personserver.Person{}, errors.New("mission context is required")
			}
			return personserver.Person{Subject: "person-123", Lifetime: time.Hour}, nil
		},
		Authorize: func(_ context.Context, request personserver.AuthorizationRequest) (personserver.AuthorizationDecision, error) {
			if request.Mission == nil || len(request.Mission.AcceptedUpdates) != 1 ||
				request.Mission.AcceptedUpdates[0].Document.Update.Description != "Report inputs selected" {
				return personserver.AuthorizationDecision{}, errors.New("accepted mission update is required")
			}
			return personserver.AuthorizationDecision{Scopes: request.Scopes, Lifetime: time.Hour}, nil
		},
	}))
	protectedResource := must(resource.NewPSAuthorization(resource.PSAuthorizationConfig{
		Issuer: resourceID, SigningKey: resourceKey, KeyResolver: resolver, Clock: clock,
		NewID:             func() string { return "resource-token-1" },
		ScopeDescriptions: map[string]string{scope: "Read records"},
		RequiredScopes:    func(*http.Request) []string { return []string{scope} },
		ResolvePerson: func(context.Context, resource.PersonIdentity, resource.PersonContext) error {
			return nil
		},
		Protected: http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			principal, ok := resource.AuthPrincipalFromContext(request.Context())
			if !ok || principal.MissionS256 == "" {
				http.Error(response, "missing mission-bound principal", http.StatusInternalServerError)
				return
			}
			fmt.Fprintf(response, "mission-bound call complete for %s\n", principal.Subject)
		}),
	}))
	network.Handle(agentProviderID, provider.Handler())
	network.Handle(personServerID, people.Handler())
	network.Handle(resourceID, protectedResource.Handler())

	reader := must(clientagent.New(context.Background(), clientagent.Config{
		Identifier: agentID, SigningKey: agentKey, AgentToken: agentToken,
		KeyResolver: resolver, HTTPClient: httpClient, Clock: clock,
	}))
	ctx := context.Background()
	mission := must(reader.ProposeMission(ctx, clientagent.MissionRequest{
		PersonServer: personServerID,
		Proposal: aauth.MissionProposal{
			Description: "# Read the report inputs", Resources: []string{resourceID},
		},
	}))
	update := must(reader.UpdateMission(ctx, clientagent.MissionUpdateRequest{
		PersonServer: personServerID, MissionS256: mission.Mission().S256,
		Description: "Report inputs selected",
	}))
	if update.S256() == "" {
		log.Fatal("mission update returned no exact document digest")
	}
	personToken, ok := mission.PersonToken(resourceID)
	if !ok {
		log.Fatal("mission approval omitted the approved Resource person token")
	}
	resourceToken := must(reader.Authorize(ctx, clientagent.AuthorizeRequest{
		Resource: resourceID, PersonToken: personToken, Scopes: []string{scope},
	}))
	authToken := must(reader.Exchange(ctx, clientagent.ExchangeRequest{
		PersonServer: personServerID, ResourceToken: resourceToken,
	}))
	request := must(http.NewRequestWithContext(ctx, http.MethodGet, resourceID+"/records/42", nil))
	response := must(reader.Do(ctx, clientagent.Call{Request: request, AuthToken: authToken}))
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		log.Fatalf("protected call returned %s", response.Status)
	}
	_, _ = io.Copy(os.Stdout, response.Body)
	// A real host sets this only after authenticating the responsible person's
	// response. This example makes that application-owned decision explicit.
	personAcceptedCompletion = true
	if err := reader.CompleteMission(ctx, clientagent.MissionCompletionRequest{
		PersonServer: personServerID, MissionS256: mission.Mission().S256,
		Summary: "Protected report read completed",
	}); err != nil {
		log.Fatal(err)
	}
	fmt.Println("mission completed with person acceptance")
}

func newSigningKey(id string) jose.SigningKey {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	return must(jose.NewEd25519SigningKey(id, privateKey))
}

func must[T any](value T, err error) T {
	if err != nil {
		log.Fatal(err)
	}
	return value
}

type memoryMissionStore struct {
	mu       sync.Mutex
	missions map[string]personserver.MissionRecord
	tokens   map[string]personserver.PersonTokenRecord
	auth     map[string]personserver.IssuedAuthTokenRecord
}

func newMemoryMissionStore() *memoryMissionStore {
	return &memoryMissionStore{
		missions: make(map[string]personserver.MissionRecord),
		tokens:   make(map[string]personserver.PersonTokenRecord),
		auth:     make(map[string]personserver.IssuedAuthTokenRecord),
	}
}

func (store *memoryMissionStore) Commit(_ context.Context, record personserver.PersonTokenRecord) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	key := record.PersonServer + "\x00" + record.JTI
	if _, exists := store.tokens[key]; exists {
		return errors.New("person-token record already exists")
	}
	store.tokens[key] = record
	return nil
}

func (store *memoryMissionStore) Load(_ context.Context, issuer, jti string) (personserver.PersonTokenRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	record, ok := store.tokens[issuer+"\x00"+jti]
	if !ok {
		return personserver.PersonTokenRecord{}, personserver.ErrPersonTokenNotFound
	}
	return record, nil
}

func (store *memoryMissionStore) CommitMission(_ context.Context, mission personserver.MissionRecord, tokens []personserver.PersonTokenRecord) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	missionKey := mission.Agent + "\x00" + mission.S256
	if _, exists := store.missions[missionKey]; exists {
		return errors.New("mission record already exists")
	}
	batch := make(map[string]struct{}, len(tokens))
	for _, token := range tokens {
		key := token.PersonServer + "\x00" + token.JTI
		if _, exists := store.tokens[key]; exists {
			return errors.New("person-token record already exists")
		}
		if _, duplicate := batch[key]; duplicate {
			return errors.New("person-token identity is duplicated within mission approval")
		}
		batch[key] = struct{}{}
	}
	store.missions[missionKey] = cloneExampleMissionRecord(mission)
	for _, token := range tokens {
		store.tokens[token.PersonServer+"\x00"+token.JTI] = token
	}
	return nil
}

func (store *memoryMissionStore) LoadMissionForAgent(
	_ context.Context, agent, s256 string, at time.Time,
) (personserver.MissionRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	key := agent + "\x00" + s256
	record, ok := store.missions[key]
	if !ok {
		return personserver.MissionRecord{}, personserver.ErrMissionNotFound
	}
	if record.State == personserver.MissionActive && !record.ExpiresAt.IsZero() && !at.Before(record.ExpiresAt) {
		record.State = personserver.MissionTerminated
		record.TerminationReason = "expired"
		store.missions[key] = cloneExampleMissionRecord(record)
	}
	return cloneExampleMissionRecord(record), nil
}

func (store *memoryMissionStore) AppendMissionUpdate(
	_ context.Context,
	expected personserver.MissionRecord,
	acceptedAt time.Time,
	document aauth.MissionUpdateDocument,
) (personserver.MissionRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if acceptedAt.IsZero() {
		return personserver.MissionRecord{}, errors.New("mission acceptance time is required")
	}
	if err := store.requireActiveMission(expected, acceptedAt); err != nil {
		return personserver.MissionRecord{}, err
	}
	key := expected.Agent + "\x00" + expected.S256
	current := store.missions[key]
	current.AcceptedUpdates = append(current.AcceptedUpdates, personserver.MissionUpdateRecord{
		Document: cloneExampleMissionUpdateDocument(document), AcceptedAt: acceptedAt,
	})
	store.missions[key] = cloneExampleMissionRecord(current)
	return cloneExampleMissionRecord(current), nil
}

func (store *memoryMissionStore) CompleteMission(
	_ context.Context,
	expected personserver.MissionRecord,
	acceptedAt time.Time,
	document aauth.MissionCompletionDocument,
) (personserver.MissionRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if acceptedAt.IsZero() {
		return personserver.MissionRecord{}, errors.New("mission acceptance time is required")
	}
	if err := store.requireActiveMission(expected, acceptedAt); err != nil {
		return personserver.MissionRecord{}, err
	}
	key := expected.Agent + "\x00" + expected.S256
	current := store.missions[key]
	current.State = personserver.MissionTerminated
	current.TerminationReason = "completed"
	current.Completion = &personserver.MissionCompletionRecord{
		Document: cloneExampleMissionCompletionDocument(document), AcceptedAt: acceptedAt,
	}
	store.missions[key] = cloneExampleMissionRecord(current)
	return cloneExampleMissionRecord(current), nil
}

func (store *memoryMissionStore) CommitMissionPersonToken(
	_ context.Context, expected personserver.MissionRecord, at time.Time, token personserver.PersonTokenRecord,
) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.requireActiveMission(expected, at); err != nil {
		return err
	}
	if token.MissionS256 != expected.S256 || token.Agent != expected.Agent {
		return personserver.ErrMissionConflict
	}
	key := token.PersonServer + "\x00" + token.JTI
	if _, exists := store.tokens[key]; exists {
		return errors.New("person-token record already exists")
	}
	store.tokens[key] = token
	return nil
}

func (store *memoryMissionStore) CommitMissionAuthToken(
	_ context.Context, expected personserver.MissionRecord, at time.Time, token personserver.IssuedAuthTokenRecord,
) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.requireActiveMission(expected, at); err != nil {
		return err
	}
	if token.MissionS256 != expected.S256 {
		return personserver.ErrMissionConflict
	}
	key := token.Reference.Issuer + "\x00" + token.Reference.JTI
	if _, exists := store.auth[key]; exists {
		return errors.New("auth-token record already exists")
	}
	store.auth[key] = token
	return nil
}

func (store *memoryMissionStore) requireActiveMission(expected personserver.MissionRecord, at time.Time) error {
	key := expected.Agent + "\x00" + expected.S256
	current, ok := store.missions[key]
	if !ok {
		return personserver.ErrMissionNotFound
	}
	if current.State == personserver.MissionActive && !current.ExpiresAt.IsZero() && !at.Before(current.ExpiresAt) {
		current.State = personserver.MissionTerminated
		current.TerminationReason = "expired"
		store.missions[key] = cloneExampleMissionRecord(current)
	}
	if current.State == personserver.MissionTerminated {
		return &personserver.MissionTerminatedError{TerminationReason: current.TerminationReason}
	}
	if !current.Equal(expected) {
		return personserver.ErrMissionConflict
	}
	return nil
}

func cloneExampleMissionRecord(record personserver.MissionRecord) personserver.MissionRecord {
	record.ExactJSON = append([]byte(nil), record.ExactJSON...)
	record.AcceptedUpdates = append([]personserver.MissionUpdateRecord(nil), record.AcceptedUpdates...)
	for index := range record.AcceptedUpdates {
		record.AcceptedUpdates[index].Document = cloneExampleMissionUpdateDocument(record.AcceptedUpdates[index].Document)
	}
	if record.Completion != nil {
		completion := *record.Completion
		completion.Document = cloneExampleMissionCompletionDocument(completion.Document)
		record.Completion = &completion
	}
	return record
}

func cloneExampleMissionUpdateDocument(document aauth.MissionUpdateDocument) aauth.MissionUpdateDocument {
	document.ExactJSON = append([]byte(nil), document.ExactJSON...)
	return document
}

func cloneExampleMissionCompletionDocument(document aauth.MissionCompletionDocument) aauth.MissionCompletionDocument {
	document.ExactJSON = append([]byte(nil), document.ExactJSON...)
	return document
}

type logicalTransport struct {
	mu     sync.RWMutex
	routes map[string]http.Handler
}

func newLogicalTransport() *logicalTransport {
	return &logicalTransport{routes: make(map[string]http.Handler)}
}

func (transport *logicalTransport) Handle(origin string, handler http.Handler) {
	transport.mu.Lock()
	defer transport.mu.Unlock()
	transport.routes[origin] = handler
}

func (transport *logicalTransport) Admit(_ context.Context, endpoint string) error {
	request, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	origin := request.URL.Scheme + "://" + request.URL.Host
	transport.mu.RLock()
	_, ok := transport.routes[origin]
	transport.mu.RUnlock()
	if !ok {
		return fmt.Errorf("discovery is not admitted for %s", origin)
	}
	return nil
}

func (transport *logicalTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	origin := request.URL.Scheme + "://" + request.URL.Host
	transport.mu.RLock()
	handler := transport.routes[origin]
	transport.mu.RUnlock()
	if handler == nil {
		return nil, fmt.Errorf("no handler for %s", origin)
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	response := recorder.Result()
	response.Request = request
	return response, nil
}
