package main

import (
	"context"
	"encoding/json"
	"reflect"
	"sync"
	"time"

	"gitlab.com/sidecat-dev/aauth-go/personserver"
)

type deferredPersonTokenStore struct {
	mu      sync.Mutex
	records map[string]personserver.PersonTokenRecord
	pending map[string]*pendingPersonToken
	byCode  map[[32]byte]string
}

type pendingPersonToken struct {
	record   personserver.PendingPersonTokenRecord
	state    personserver.PersonTokenPollState
	approval personserver.PersonTokenApproval
}

func newDeferredPersonTokenStore() *deferredPersonTokenStore {
	return &deferredPersonTokenStore{
		records: make(map[string]personserver.PersonTokenRecord),
		pending: make(map[string]*pendingPersonToken),
		byCode:  make(map[[32]byte]string),
	}
}

func (store *deferredPersonTokenStore) Commit(_ context.Context, record personserver.PersonTokenRecord) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	key := record.PersonServer + "\x00" + record.JTI
	if _, exists := store.records[key]; exists {
		return personserver.ErrPendingPersonTokenConflict
	}
	store.records[key] = record
	return nil
}

func (store *deferredPersonTokenStore) Load(_ context.Context, issuer, tokenID string) (personserver.PersonTokenRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	record, ok := store.records[issuer+"\x00"+tokenID]
	if !ok {
		return personserver.PersonTokenRecord{}, personserver.ErrPersonTokenNotFound
	}
	return record, nil
}

func (store *deferredPersonTokenStore) CreatePendingPersonToken(_ context.Context, record personserver.PendingPersonTokenRecord) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if _, exists := store.pending[record.ID]; exists {
		return personserver.ErrPendingPersonTokenConflict
	}
	if _, exists := store.byCode[record.CodeSHA256]; exists {
		return personserver.ErrPendingPersonTokenConflict
	}
	store.pending[record.ID] = &pendingPersonToken{
		record: clonePendingPersonToken(record), state: personserver.PersonTokenPollWaiting,
	}
	store.byCode[record.CodeSHA256] = record.ID
	return nil
}

func (store *deferredPersonTokenStore) ConsumePersonTokenInteractionCode(
	_ context.Context,
	personServer string,
	reference string,
	code [32]byte,
	now time.Time,
) (personserver.PendingPersonTokenRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	pending, ok := store.pending[reference]
	if !ok || pending.record.PersonServer != personServer || pending.record.CodeSHA256 != code {
		return personserver.PendingPersonTokenRecord{}, personserver.ErrInteractionCodeInvalid
	}
	if pending.state != personserver.PersonTokenPollWaiting {
		return personserver.PendingPersonTokenRecord{}, personserver.ErrInteractionCodeUsed
	}
	if !now.Before(pending.record.ExpiresAt) {
		pending.state = personserver.PersonTokenPollExpired
		return personserver.PendingPersonTokenRecord{}, personserver.ErrPendingPersonTokenExpired
	}
	pending.state = personserver.PersonTokenPollInteracting
	return clonePendingPersonToken(pending.record), nil
}

func (store *deferredPersonTokenStore) LoadPendingPersonToken(
	_ context.Context,
	id string,
) (personserver.PendingPersonTokenSnapshot, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	pending, ok := store.pending[id]
	if !ok {
		return personserver.PendingPersonTokenSnapshot{}, personserver.ErrPendingPersonTokenNotFound
	}
	snapshot := personserver.PendingPersonTokenSnapshot{
		Record: clonePendingPersonToken(pending.record), State: pending.state,
	}
	if pending.state == personserver.PersonTokenPollApproved {
		snapshot.ApprovedPerson = pending.approval.Person
	}
	return snapshot, nil
}

func (store *deferredPersonTokenStore) ApprovePendingPersonToken(
	_ context.Context,
	id string,
	approval personserver.PersonTokenApproval,
) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	pending, ok := store.pending[id]
	if !ok {
		return personserver.ErrPendingPersonTokenNotFound
	}
	if pending.state == personserver.PersonTokenPollApproved && pending.approval.Person == approval.Person {
		return nil
	}
	if pending.state != personserver.PersonTokenPollInteracting {
		return personserver.ErrPendingPersonTokenConflict
	}
	store.records[approval.Record.PersonServer+"\x00"+approval.Record.JTI] = approval.Record
	pending.approval = approval
	pending.state = personserver.PersonTokenPollApproved
	return nil
}

func (store *deferredPersonTokenStore) DenyPendingPersonToken(_ context.Context, id string, _ time.Time) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	pending, ok := store.pending[id]
	if !ok {
		return personserver.ErrPendingPersonTokenNotFound
	}
	if pending.state == personserver.PersonTokenPollDenied {
		return nil
	}
	if pending.state != personserver.PersonTokenPollInteracting {
		return personserver.ErrPendingPersonTokenConflict
	}
	pending.state = personserver.PersonTokenPollDenied
	return nil
}

func (store *deferredPersonTokenStore) InvalidatePendingPersonToken(_ context.Context, id string, _ time.Time) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	pending, ok := store.pending[id]
	if !ok {
		return personserver.ErrPendingPersonTokenNotFound
	}
	if pending.state == personserver.PersonTokenPollGone {
		return nil
	}
	if pending.state != personserver.PersonTokenPollWaiting && pending.state != personserver.PersonTokenPollInteracting {
		return personserver.ErrPendingPersonTokenConflict
	}
	pending.state = personserver.PersonTokenPollGone
	return nil
}

func (store *deferredPersonTokenStore) PollPendingPersonToken(
	_ context.Context,
	id string,
	identity personserver.PersonTokenPollIdentity,
	now time.Time,
) (personserver.PersonTokenPollRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	pending, ok := store.pending[id]
	if !ok {
		return personserver.PersonTokenPollRecord{}, personserver.ErrPendingPersonTokenNotFound
	}
	wantJKT, _ := pending.record.Confirmation.Thumbprint()
	if identity.PersonServer != pending.record.PersonServer || identity.Agent != pending.record.Agent ||
		identity.ConfirmationThumbprint != wantJKT {
		return personserver.PersonTokenPollRecord{}, personserver.ErrPendingPersonTokenNotFound
	}
	if pending.state == personserver.PersonTokenPollGone {
		return personserver.PersonTokenPollRecord{}, personserver.ErrPendingPersonTokenGone
	}
	if !now.Before(pending.record.ExpiresAt) &&
		(pending.state == personserver.PersonTokenPollWaiting || pending.state == personserver.PersonTokenPollInteracting) {
		pending.state = personserver.PersonTokenPollExpired
	}
	result := personserver.PersonTokenPollRecord{State: pending.state, RetryAfter: pending.record.RetryAfter}
	if pending.state == personserver.PersonTokenPollApproved {
		result.Token = pending.approval.Token
		result.Record = pending.approval.Record
		result.ExpiresIn = pending.approval.ExpiresIn
	}
	return result, nil
}

func (store *deferredPersonTokenStore) ConsumePendingPersonTokenResult(
	_ context.Context,
	id string,
	result personserver.PersonTokenPollRecord,
) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	pending, ok := store.pending[id]
	if !ok {
		return personserver.ErrPendingPersonTokenNotFound
	}
	if pending.state == personserver.PersonTokenPollGone {
		return personserver.ErrPendingPersonTokenGone
	}
	want := personserver.PersonTokenPollRecord{State: pending.state, RetryAfter: pending.record.RetryAfter}
	switch pending.state {
	case personserver.PersonTokenPollApproved:
		want.Token = pending.approval.Token
		want.Record = pending.approval.Record
		want.ExpiresIn = pending.approval.ExpiresIn
	case personserver.PersonTokenPollDenied, personserver.PersonTokenPollExpired:
	default:
		return personserver.ErrPendingPersonTokenConflict
	}
	if !reflect.DeepEqual(result, want) {
		return personserver.ErrPendingPersonTokenConflict
	}
	pending.state = personserver.PersonTokenPollGone
	return nil
}

func clonePendingPersonToken(record personserver.PendingPersonTokenRecord) personserver.PendingPersonTokenRecord {
	if record.AgentAdditionalClaims == nil {
		return record
	}
	claims := make(map[string]json.RawMessage, len(record.AgentAdditionalClaims))
	for name, value := range record.AgentAdditionalClaims {
		claims[name] = append(json.RawMessage(nil), value...)
	}
	record.AgentAdditionalClaims = claims
	return record
}
