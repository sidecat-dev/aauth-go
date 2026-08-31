package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync"
	"time"

	"gitlab.com/sidecat-dev/aauth-go/personserver"
)

type memoryTokenStore struct {
	mu      sync.Mutex
	records map[string]personserver.PersonTokenRecord
}

func newMemoryTokenStore() *memoryTokenStore {
	return &memoryTokenStore{records: make(map[string]personserver.PersonTokenRecord)}
}

func (store *memoryTokenStore) Commit(_ context.Context, record personserver.PersonTokenRecord) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	key := record.PersonServer + "\x00" + record.JTI
	if existing, ok := store.records[key]; ok {
		if reflect.DeepEqual(existing, record) {
			return nil
		}
		return errors.New("person-token record conflicts with retained value")
	}
	store.records[key] = record
	return nil
}

func (store *memoryTokenStore) Load(_ context.Context, issuer, tokenID string) (personserver.PersonTokenRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	record, ok := store.records[issuer+"\x00"+tokenID]
	if !ok {
		return personserver.PersonTokenRecord{}, personserver.ErrPersonTokenNotFound
	}
	return record, nil
}

type memoryAuthorizationStore struct {
	mu      sync.Mutex
	pending map[string]*memoryPendingAuthorization
	byCode  map[[32]byte]string
}

type memoryPendingAuthorization struct {
	record         personserver.PendingAuthorizationRecord
	state          personserver.AuthorizationPollState
	approval       personserver.AuthorizationApproval
	failedAttempts int
}

func newMemoryAuthorizationStore() *memoryAuthorizationStore {
	return &memoryAuthorizationStore{
		pending: make(map[string]*memoryPendingAuthorization),
		byCode:  make(map[[32]byte]string),
	}
}

func (store *memoryAuthorizationStore) CreatePendingAuthorization(
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
	store.pending[record.ID] = &memoryPendingAuthorization{
		record: clonePendingAuthorization(record), state: personserver.AuthorizationPollWaiting,
	}
	store.byCode[record.CodeSHA256] = record.ID
	return nil
}

func (store *memoryAuthorizationStore) ConsumeAuthorizationInteractionCode(
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
	materializeAuthorizationExpiry(pending, now)
	switch pending.state {
	case personserver.AuthorizationPollGone:
		return personserver.PendingAuthorizationRecord{}, personserver.ErrPendingAuthorizationGone
	case personserver.AuthorizationPollExpired:
		return personserver.PendingAuthorizationRecord{}, personserver.ErrPendingAuthorizationExpired
	case personserver.AuthorizationPollInteracting:
		return personserver.PendingAuthorizationRecord{}, personserver.ErrAuthorizationInteractionCodeUsed
	case personserver.AuthorizationPollApproved, personserver.AuthorizationPollDenied,
		personserver.AuthorizationPollAbandoned, personserver.AuthorizationPollServerError:
		return personserver.PendingAuthorizationRecord{}, personserver.ErrAuthorizationInteractionCodeUsed
	}
	if !presentation.SyntacticallyValid || pending.record.CodeSHA256 != presentation.CodeSHA256 {
		pending.failedAttempts++
		if pending.failedAttempts >= personserver.MaximumAuthorizationCodeAttempts {
			pending.failedAttempts = personserver.MaximumAuthorizationCodeAttempts
			pending.state = personserver.AuthorizationPollGone
			return personserver.PendingAuthorizationRecord{}, personserver.ErrPendingAuthorizationGone
		}
		return personserver.PendingAuthorizationRecord{}, personserver.ErrAuthorizationInteractionCodeInvalid
	}
	if pending.state != personserver.AuthorizationPollWaiting {
		return personserver.PendingAuthorizationRecord{}, personserver.ErrAuthorizationInteractionCodeUsed
	}
	pending.state = personserver.AuthorizationPollInteracting
	return clonePendingAuthorization(pending.record), nil
}

func (store *memoryAuthorizationStore) LoadPendingAuthorization(
	_ context.Context,
	reference string,
	now time.Time,
) (personserver.PendingAuthorizationSnapshot, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	pending, ok := store.pending[reference]
	if !ok {
		return personserver.PendingAuthorizationSnapshot{}, personserver.ErrPendingAuthorizationNotFound
	}
	materializeAuthorizationExpiry(pending, now)
	snapshot := personserver.PendingAuthorizationSnapshot{
		Record: clonePendingAuthorization(pending.record), State: pending.state,
	}
	if pending.state == personserver.AuthorizationPollApproved {
		snapshot.Approval = cloneAuthorizationApproval(pending.approval)
	}
	return snapshot, nil
}

func (store *memoryAuthorizationStore) ApprovePendingAuthorization(
	_ context.Context,
	reference string,
	proposal personserver.AuthorizationApproval,
) (personserver.AuthorizationApproval, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	pending, ok := store.pending[reference]
	if !ok {
		return personserver.AuthorizationApproval{}, personserver.ErrPendingAuthorizationNotFound
	}
	materializeAuthorizationExpiry(pending, proposal.DecidedAt)
	if pending.state == personserver.AuthorizationPollApproved {
		if !decisionsEqual(pending.approval.Decision, proposal.Decision) {
			return personserver.AuthorizationApproval{}, personserver.ErrPendingAuthorizationConflict
		}
		return cloneAuthorizationApproval(pending.approval), nil
	}
	if pending.state == personserver.AuthorizationPollExpired {
		return personserver.AuthorizationApproval{}, personserver.ErrPendingAuthorizationExpired
	}
	if pending.state != personserver.AuthorizationPollInteracting || !approvalComplete(pending.record, proposal) {
		return personserver.AuthorizationApproval{}, personserver.ErrPendingAuthorizationConflict
	}
	pending.approval = cloneAuthorizationApproval(proposal)
	pending.state = personserver.AuthorizationPollApproved
	return cloneAuthorizationApproval(pending.approval), nil
}

func (store *memoryAuthorizationStore) DenyPendingAuthorization(
	_ context.Context,
	reference string,
	decidedAt time.Time,
) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	pending, ok := store.pending[reference]
	if !ok {
		return personserver.ErrPendingAuthorizationNotFound
	}
	materializeAuthorizationExpiry(pending, decidedAt)
	if pending.state == personserver.AuthorizationPollDenied {
		return nil
	}
	if pending.state == personserver.AuthorizationPollExpired {
		return personserver.ErrPendingAuthorizationExpired
	}
	if pending.state != personserver.AuthorizationPollInteracting {
		return personserver.ErrPendingAuthorizationConflict
	}
	pending.state = personserver.AuthorizationPollDenied
	return nil
}

func (store *memoryAuthorizationStore) AbandonPendingAuthorization(
	_ context.Context,
	reference string,
	now time.Time,
) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	pending, ok := store.pending[reference]
	if !ok {
		return personserver.ErrPendingAuthorizationNotFound
	}
	materializeAuthorizationExpiry(pending, now)
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

func (store *memoryAuthorizationStore) FailPendingAuthorization(
	_ context.Context,
	reference string,
	now time.Time,
) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	pending, ok := store.pending[reference]
	if !ok {
		return personserver.ErrPendingAuthorizationNotFound
	}
	materializeAuthorizationExpiry(pending, now)
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

func (store *memoryAuthorizationStore) PollPendingAuthorization(
	_ context.Context,
	reference string,
	identity personserver.AuthorizationPollIdentity,
	now time.Time,
) (personserver.AuthorizationPollRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	pending, ok := store.pending[reference]
	if !ok {
		return personserver.AuthorizationPollRecord{}, personserver.ErrPendingAuthorizationNotFound
	}
	materializeAuthorizationExpiry(pending, now)
	wantThumbprint, err := pending.record.Confirmation.Thumbprint()
	if err != nil || identity.PersonServer != pending.record.PersonServer ||
		identity.AgentProvider != pending.record.AgentProvider || identity.Agent != pending.record.Agent ||
		identity.ConfirmationThumbprint != wantThumbprint {
		return personserver.AuthorizationPollRecord{}, personserver.ErrPendingAuthorizationNotFound
	}
	if pending.state == personserver.AuthorizationPollGone {
		return personserver.AuthorizationPollRecord{}, personserver.ErrPendingAuthorizationGone
	}
	return authorizationPollRecord(pending), nil
}

func (store *memoryAuthorizationStore) ConsumePendingAuthorizationResult(
	_ context.Context,
	reference string,
	result personserver.AuthorizationPollRecord,
) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	pending, ok := store.pending[reference]
	if !ok {
		return personserver.ErrPendingAuthorizationNotFound
	}
	if pending.state == personserver.AuthorizationPollGone {
		return personserver.ErrPendingAuthorizationGone
	}
	if pending.state != personserver.AuthorizationPollApproved && pending.state != personserver.AuthorizationPollDenied &&
		pending.state != personserver.AuthorizationPollAbandoned && pending.state != personserver.AuthorizationPollServerError &&
		pending.state != personserver.AuthorizationPollExpired {
		return personserver.ErrPendingAuthorizationConflict
	}
	if !reflect.DeepEqual(result, authorizationPollRecord(pending)) {
		return personserver.ErrPendingAuthorizationConflict
	}
	pending.state = personserver.AuthorizationPollGone
	return nil
}

func authorizationPollRecord(pending *memoryPendingAuthorization) personserver.AuthorizationPollRecord {
	result := personserver.AuthorizationPollRecord{
		State: pending.state, Pending: clonePendingAuthorization(pending.record),
		RetryAfter: pending.record.RetryAfter,
	}
	if pending.state == personserver.AuthorizationPollApproved {
		result.Token = pending.approval.Token
		result.Decision = cloneAuthorizationDecision(pending.approval.Decision)
		result.ExpiresIn = pending.approval.ExpiresIn
		result.DecidedAt = pending.approval.DecidedAt
	}
	return result
}

func materializeAuthorizationExpiry(pending *memoryPendingAuthorization, now time.Time) {
	if (pending.state == personserver.AuthorizationPollWaiting || pending.state == personserver.AuthorizationPollInteracting) &&
		!now.Before(pending.record.ExpiresAt) {
		pending.state = personserver.AuthorizationPollExpired
	}
}

func approvalComplete(
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
		if _, duplicate := requested[scope]; duplicate {
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

func decisionsEqual(left, right personserver.AuthorizationDecision) bool {
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

func clonePendingAuthorization(record personserver.PendingAuthorizationRecord) personserver.PendingAuthorizationRecord {
	record.Scopes = append([]string(nil), record.Scopes...)
	record.Capabilities = append([]string(nil), record.Capabilities...)
	if len(record.AgentAdditionalClaims) > 0 {
		claims := make(map[string]json.RawMessage, len(record.AgentAdditionalClaims))
		for name, value := range record.AgentAdditionalClaims {
			claims[name] = append(json.RawMessage(nil), value...)
		}
		record.AgentAdditionalClaims = claims
	}
	return record
}

func cloneAuthorizationDecision(decision personserver.AuthorizationDecision) personserver.AuthorizationDecision {
	decision.Scopes = append([]string(nil), decision.Scopes...)
	return decision
}

func cloneAuthorizationApproval(approval personserver.AuthorizationApproval) personserver.AuthorizationApproval {
	approval.Decision = cloneAuthorizationDecision(approval.Decision)
	return approval
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

var _ personserver.TokenStore = (*memoryTokenStore)(nil)
var _ personserver.DeferredAuthorizationStore = (*memoryAuthorizationStore)(nil)
