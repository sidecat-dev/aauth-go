package exampleutil

import (
	"context"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/personserver"
)

// NewMissionInteractionQuestionStore returns one in-memory transaction
// boundary for mission lifecycle, mission-bound tokens, and Interaction
// question state.
func NewMissionInteractionQuestionStore() personserver.MissionInteractionQuestionStore {
	return &missionInteractionQuestionStore{
		missionStore: newMissionStore(),
		questions:    make(map[string]personserver.InteractionQuestionRecord),
	}
}

type missionInteractionQuestionStore struct {
	*missionStore
	questions map[string]personserver.InteractionQuestionRecord
}

func (store *missionInteractionQuestionStore) CreateInteractionQuestion(
	_ context.Context,
	record personserver.InteractionQuestionRecord,
) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	return createInteractionQuestionRecord(store.questions, record)
}

func (store *missionInteractionQuestionStore) LoadInteractionQuestion(
	_ context.Context,
	id string,
	at time.Time,
) (personserver.InteractionQuestionRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	return loadInteractionQuestionRecord(store.questions, id, at)
}

func (store *missionInteractionQuestionStore) ResolveInteractionQuestion(
	_ context.Context,
	id string,
	state personserver.InteractionQuestionState,
	answer aauth.InteractionAnswerDocument,
	at time.Time,
) (personserver.InteractionQuestionRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	return resolveInteractionQuestionRecord(store.questions, id, state, answer, at)
}

func (store *missionInteractionQuestionStore) PollInteractionQuestion(
	_ context.Context,
	id string,
	identity personserver.InteractionQuestionPollIdentity,
	at time.Time,
) (personserver.InteractionQuestionRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	return pollInteractionQuestionRecord(store.questions, id, identity, at)
}

func (store *missionInteractionQuestionStore) ConsumeInteractionQuestion(
	_ context.Context,
	id string,
	record personserver.InteractionQuestionRecord,
) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	return consumeInteractionQuestionRecord(store.questions, id, record)
}

func (store *missionInteractionQuestionStore) CommitMissionInteractionQuestion(
	_ context.Context,
	expected personserver.MissionRecord,
	record personserver.InteractionQuestionRecord,
	at time.Time,
) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.requireActive(expected, at); err != nil {
		return err
	}
	if record.Agent != expected.Agent || record.Document.Question.MissionS256 != expected.S256 {
		return personserver.ErrMissionConflict
	}
	return createInteractionQuestionRecord(store.questions, record)
}

func (store *missionInteractionQuestionStore) ResolveMissionInteractionQuestion(
	_ context.Context,
	expected personserver.MissionRecord,
	id string,
	state personserver.InteractionQuestionState,
	answer aauth.InteractionAnswerDocument,
	at time.Time,
) (personserver.InteractionQuestionRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.requireActive(expected, at); err != nil {
		return personserver.InteractionQuestionRecord{}, err
	}
	if err := requireMissionQuestion(store.questions, id, expected); err != nil {
		return personserver.InteractionQuestionRecord{}, err
	}
	return resolveInteractionQuestionRecord(store.questions, id, state, answer, at)
}

func (store *missionInteractionQuestionStore) PollMissionInteractionQuestion(
	_ context.Context,
	expected personserver.MissionRecord,
	id string,
	identity personserver.InteractionQuestionPollIdentity,
	at time.Time,
) (personserver.InteractionQuestionRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.requireActive(expected, at); err != nil {
		return personserver.InteractionQuestionRecord{}, err
	}
	if err := requireMissionQuestion(store.questions, id, expected); err != nil {
		return personserver.InteractionQuestionRecord{}, err
	}
	return pollInteractionQuestionRecord(store.questions, id, identity, at)
}

func (store *missionInteractionQuestionStore) ConsumeMissionInteractionQuestion(
	_ context.Context,
	expected personserver.MissionRecord,
	id string,
	record personserver.InteractionQuestionRecord,
	at time.Time,
) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.requireActive(expected, at); err != nil {
		return err
	}
	if err := requireMissionQuestion(store.questions, id, expected); err != nil {
		return err
	}
	return consumeInteractionQuestionRecord(store.questions, id, record)
}

func requireMissionQuestion(
	records map[string]personserver.InteractionQuestionRecord,
	id string,
	mission personserver.MissionRecord,
) error {
	record, exists := records[id]
	if !exists {
		return personserver.ErrInteractionQuestionNotFound
	}
	if record.Agent != mission.Agent || record.Document.Question.MissionS256 != mission.S256 {
		return personserver.ErrMissionConflict
	}
	return nil
}

var _ personserver.MissionInteractionQuestionStore = (*missionInteractionQuestionStore)(nil)
