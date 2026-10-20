package testutil

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"sync"
	"time"

	"gitlab.com/sidecat-dev/aauth-go/personserver"
)

type deferredAuthorizationStore struct {
	mu      sync.Mutex
	pending map[string]*memoryPendingAuthorization
	byCode  map[[32]byte]string
}

type memoryPendingAuthorization struct {
	record         personserver.PendingAuthorizationRecord
	state          personserver.AuthorizationPollState
	clarifications []personserver.AuthorizationClarificationRound
	approval       personserver.AuthorizationApproval
	failedAttempts int
	cancelledAt    time.Time
}

// NewDeferredAuthorizationStore returns an empty, concurrency-safe consent and
// clarification store. It also implements personserver.AuthorizationClarificationStore
// over the same pending records. Retained results survive Server recomposition,
// not a process restart. Records are retained for the lifetime of the store.
func NewDeferredAuthorizationStore() personserver.DeferredAuthorizationStore {
	return &deferredAuthorizationStore{
		pending: make(map[string]*memoryPendingAuthorization),
		byCode:  make(map[[32]byte]string),
	}
}

func (store *deferredAuthorizationStore) CreatePendingAuthorization(
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

func (store *deferredAuthorizationStore) ConsumeAuthorizationInteractionCode(
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

func (store *deferredAuthorizationStore) LoadPendingAuthorization(
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
		Clarifications: cloneAuthorizationClarifications(pending.clarifications),
		CancelledAt:    pending.cancelledAt,
	}
	if pending.state == personserver.AuthorizationPollApproved {
		snapshot.Approval = cloneAuthorizationApproval(pending.approval)
	}
	return snapshot, nil
}

func (store *deferredAuthorizationStore) RequestPendingAuthorizationClarification(
	_ context.Context,
	reference string,
	request personserver.AuthorizationClarificationRequest,
	now time.Time,
) (personserver.AuthorizationClarificationRound, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	pending, ok := store.pending[reference]
	if !ok {
		return personserver.AuthorizationClarificationRound{}, personserver.ErrPendingAuthorizationNotFound
	}
	materializeAuthorizationExpiry(pending, now)
	if pending.state == personserver.AuthorizationPollClarifying {
		current := pending.clarifications[len(pending.clarifications)-1]
		if current.Question == request.Question && reflect.DeepEqual(current.Options, request.Options) &&
			current.ExpiresAt.Sub(current.RequestedAt) == request.Lifetime {
			return cloneAuthorizationClarification(current), nil
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
	if err := validateAuthorizationClarificationRequest(request, now, pending.record.ExpiresAt); err != nil {
		return personserver.AuthorizationClarificationRound{}, err
	}
	round := personserver.AuthorizationClarificationRound{
		Question: request.Question, Options: append([]string(nil), request.Options...),
		RequestedAt: now, ExpiresAt: now.Add(request.Lifetime),
	}
	pending.clarifications = append(pending.clarifications, cloneAuthorizationClarification(round))
	pending.state = personserver.AuthorizationPollClarifying
	return cloneAuthorizationClarification(round), nil
}

func (store *deferredAuthorizationStore) AnswerPendingAuthorizationClarification(
	_ context.Context,
	reference string,
	identity personserver.AuthorizationPollIdentity,
	answer string,
	now time.Time,
) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	pending, ok := store.pending[reference]
	if !ok || !authorizationIdentityMatches(pending, identity) {
		return personserver.ErrPendingAuthorizationNotFound
	}
	materializeAuthorizationExpiry(pending, now)
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

func (store *deferredAuthorizationStore) CancelPendingAuthorizationClarification(
	_ context.Context,
	reference string,
	identity personserver.AuthorizationPollIdentity,
	now time.Time,
) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	pending, ok := store.pending[reference]
	if !ok || !authorizationIdentityMatches(pending, identity) {
		return personserver.ErrPendingAuthorizationNotFound
	}
	materializeAuthorizationExpiry(pending, now)
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

func (store *deferredAuthorizationStore) ApprovePendingAuthorization(
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

func (store *deferredAuthorizationStore) DenyPendingAuthorization(
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

func (store *deferredAuthorizationStore) AbandonPendingAuthorization(
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

func (store *deferredAuthorizationStore) FailPendingAuthorization(
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

func (store *deferredAuthorizationStore) PollPendingAuthorization(
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
	if !authorizationIdentityMatches(pending, identity) {
		return personserver.AuthorizationPollRecord{}, personserver.ErrPendingAuthorizationNotFound
	}
	if pending.state == personserver.AuthorizationPollGone || pending.state == personserver.AuthorizationPollCancelled {
		return personserver.AuthorizationPollRecord{}, personserver.ErrPendingAuthorizationGone
	}
	return authorizationPollRecord(pending), nil
}

func (store *deferredAuthorizationStore) ConsumePendingAuthorizationResult(
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
	if pending.state == personserver.AuthorizationPollGone || pending.state == personserver.AuthorizationPollCancelled {
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
	if pending.state == personserver.AuthorizationPollClarifying {
		clarification := cloneAuthorizationClarification(pending.clarifications[len(pending.clarifications)-1])
		result.Clarification = &clarification
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
	if pending.state == personserver.AuthorizationPollClarifying {
		deadline := pending.clarifications[len(pending.clarifications)-1].ExpiresAt
		if !now.Before(deadline) || !now.Before(pending.record.ExpiresAt) {
			pending.state = personserver.AuthorizationPollExpired
		}
	}
}

func authorizationIdentityMatches(
	pending *memoryPendingAuthorization,
	identity personserver.AuthorizationPollIdentity,
) bool {
	thumbprint, err := pending.record.Confirmation.Thumbprint()
	return err == nil && identity.PersonServer == pending.record.PersonServer &&
		identity.AgentProvider == pending.record.AgentProvider && identity.Agent == pending.record.Agent &&
		identity.ConfirmationThumbprint == thumbprint
}

func validateAuthorizationClarificationRequest(
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
	record.AgentAdditionalClaims = cloneAuthorizationClaims(record.AgentAdditionalClaims)
	record.SubagentAdditionalClaims = cloneAuthorizationClaims(record.SubagentAdditionalClaims)
	return record
}

func cloneAuthorizationClaims(claims map[string]json.RawMessage) map[string]json.RawMessage {
	if len(claims) == 0 {
		return nil
	}
	cloned := make(map[string]json.RawMessage, len(claims))
	for name, value := range claims {
		cloned[name] = append(json.RawMessage(nil), value...)
	}
	return cloned
}

func cloneAuthorizationDecision(decision personserver.AuthorizationDecision) personserver.AuthorizationDecision {
	decision.Scopes = append([]string(nil), decision.Scopes...)
	return decision
}

func cloneAuthorizationApproval(approval personserver.AuthorizationApproval) personserver.AuthorizationApproval {
	approval.Decision = cloneAuthorizationDecision(approval.Decision)
	return approval
}

func cloneAuthorizationClarification(
	round personserver.AuthorizationClarificationRound,
) personserver.AuthorizationClarificationRound {
	round.Options = append([]string(nil), round.Options...)
	return round
}

func cloneAuthorizationClarifications(
	rounds []personserver.AuthorizationClarificationRound,
) []personserver.AuthorizationClarificationRound {
	if len(rounds) == 0 {
		return nil
	}
	cloned := make([]personserver.AuthorizationClarificationRound, len(rounds))
	for index, round := range rounds {
		cloned[index] = cloneAuthorizationClarification(round)
	}
	return cloned
}
