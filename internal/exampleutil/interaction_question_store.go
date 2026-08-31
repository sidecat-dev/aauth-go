package exampleutil

import (
	"context"
	"reflect"
	"sync"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/personserver"
)

func NewInteractionQuestionStore() personserver.InteractionQuestionStore {
	return &interactionQuestionStore{records: make(map[string]personserver.InteractionQuestionRecord)}
}

type interactionQuestionStore struct {
	mu      sync.Mutex
	records map[string]personserver.InteractionQuestionRecord
}

func (store *interactionQuestionStore) CreateInteractionQuestion(_ context.Context, record personserver.InteractionQuestionRecord) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if _, exists := store.records[record.ID]; exists {
		return personserver.ErrInteractionQuestionConflict
	}
	store.records[record.ID] = cloneExampleQuestionRecord(record)
	return nil
}

func (store *interactionQuestionStore) LoadInteractionQuestion(_ context.Context, id string, at time.Time) (personserver.InteractionQuestionRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	record, err := store.load(id, at)
	if err != nil {
		return personserver.InteractionQuestionRecord{}, err
	}
	return cloneExampleQuestionRecord(record), nil
}

func (store *interactionQuestionStore) ResolveInteractionQuestion(_ context.Context, id string, state personserver.InteractionQuestionState, answer aauth.InteractionAnswerDocument, at time.Time) (personserver.InteractionQuestionRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	record, err := store.load(id, at)
	if err != nil {
		return personserver.InteractionQuestionRecord{}, err
	}
	if record.State == personserver.InteractionQuestionAnswered || record.State == personserver.InteractionQuestionUnreachable {
		if record.State == state && reflect.DeepEqual(record.Answer, answer) {
			return cloneExampleQuestionRecord(record), nil
		}
		return personserver.InteractionQuestionRecord{}, personserver.ErrInteractionQuestionConflict
	}
	if record.State != personserver.InteractionQuestionPending {
		return personserver.InteractionQuestionRecord{}, questionStoreStateError(record.State)
	}
	if state != personserver.InteractionQuestionAnswered && state != personserver.InteractionQuestionUnreachable {
		return personserver.InteractionQuestionRecord{}, personserver.ErrInteractionQuestionConflict
	}
	record.State, record.AnsweredAt = state, at
	record.Answer = cloneExampleAnswer(answer)
	store.records[id] = cloneExampleQuestionRecord(record)
	return cloneExampleQuestionRecord(record), nil
}

func (store *interactionQuestionStore) PollInteractionQuestion(_ context.Context, id string, identity personserver.InteractionQuestionPollIdentity, at time.Time) (personserver.InteractionQuestionRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	record, err := store.load(id, at)
	if err != nil {
		return personserver.InteractionQuestionRecord{}, err
	}
	if record.PersonServer != identity.PersonServer || record.AgentProvider != identity.AgentProvider || record.Agent != identity.Agent || record.ConfirmationThumbprint != identity.ConfirmationThumbprint {
		return personserver.InteractionQuestionRecord{}, personserver.ErrInteractionQuestionNotFound
	}
	return cloneExampleQuestionRecord(record), nil
}

func (store *interactionQuestionStore) ConsumeInteractionQuestion(_ context.Context, id string, expected personserver.InteractionQuestionRecord) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	record, exists := store.records[id]
	if !exists {
		return personserver.ErrInteractionQuestionNotFound
	}
	if record.State == personserver.InteractionQuestionGone {
		return personserver.ErrInteractionQuestionGone
	}
	if !reflect.DeepEqual(record, expected) {
		return personserver.ErrInteractionQuestionConflict
	}
	if record.State != personserver.InteractionQuestionAnswered && record.State != personserver.InteractionQuestionUnreachable && record.State != personserver.InteractionQuestionExpired {
		return personserver.ErrInteractionQuestionConflict
	}
	record.State = personserver.InteractionQuestionGone
	store.records[id] = cloneExampleQuestionRecord(record)
	return nil
}

func (store *interactionQuestionStore) load(id string, at time.Time) (personserver.InteractionQuestionRecord, error) {
	record, exists := store.records[id]
	if !exists {
		return personserver.InteractionQuestionRecord{}, personserver.ErrInteractionQuestionNotFound
	}
	if record.State == personserver.InteractionQuestionGone {
		return personserver.InteractionQuestionRecord{}, personserver.ErrInteractionQuestionGone
	}
	if record.State == personserver.InteractionQuestionPending && !at.Before(record.ExpiresAt) {
		record.State = personserver.InteractionQuestionExpired
		store.records[id] = cloneExampleQuestionRecord(record)
	}
	return record, nil
}

func questionStoreStateError(state personserver.InteractionQuestionState) error {
	if state == personserver.InteractionQuestionExpired {
		return personserver.ErrInteractionQuestionExpired
	}
	if state == personserver.InteractionQuestionGone {
		return personserver.ErrInteractionQuestionGone
	}
	return personserver.ErrInteractionQuestionConflict
}

func cloneExampleQuestionRecord(record personserver.InteractionQuestionRecord) personserver.InteractionQuestionRecord {
	record.Document.ExactJSON = append([]byte(nil), record.Document.ExactJSON...)
	record.Answer = cloneExampleAnswer(record.Answer)
	return record
}
func cloneExampleAnswer(answer aauth.InteractionAnswerDocument) aauth.InteractionAnswerDocument {
	answer.ExactJSON = append([]byte(nil), answer.ExactJSON...)
	return answer
}

var _ personserver.InteractionQuestionStore = (*interactionQuestionStore)(nil)
