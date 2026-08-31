// Package exampleutil contains small in-memory role stores shared by runnable
// examples. They demonstrate interface semantics, not production persistence.
package exampleutil

import (
	"context"
	"errors"
	"sync"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/personserver"
)

// NewMissionStore returns a concurrency-safe in-memory Person Server mission
// store for examples.
func NewMissionStore() personserver.MissionStore {
	return &missionStore{
		missions: make(map[string]personserver.MissionRecord),
		tokens:   make(map[string]personserver.PersonTokenRecord),
		auth:     make(map[string]personserver.IssuedAuthTokenRecord),
	}
}

type missionStore struct {
	mu       sync.Mutex
	missions map[string]personserver.MissionRecord
	tokens   map[string]personserver.PersonTokenRecord
	auth     map[string]personserver.IssuedAuthTokenRecord
}

var _ personserver.MissionStore = (*missionStore)(nil)

func (store *missionStore) Commit(_ context.Context, record personserver.PersonTokenRecord) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	key := record.PersonServer + "\x00" + record.JTI
	if _, exists := store.tokens[key]; exists {
		return errors.New("example mission store: person-token record already exists")
	}
	store.tokens[key] = record
	return nil
}

func (store *missionStore) Load(_ context.Context, issuer, jti string) (personserver.PersonTokenRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	record, ok := store.tokens[issuer+"\x00"+jti]
	if !ok {
		return personserver.PersonTokenRecord{}, personserver.ErrPersonTokenNotFound
	}
	return record, nil
}

func (store *missionStore) CommitMission(
	_ context.Context,
	mission personserver.MissionRecord,
	tokens []personserver.PersonTokenRecord,
) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	missionKey := mission.Agent + "\x00" + mission.S256
	if _, exists := store.missions[missionKey]; exists {
		return errors.New("example mission store: mission already exists")
	}
	batch := make(map[string]struct{}, len(tokens))
	for _, token := range tokens {
		key := token.PersonServer + "\x00" + token.JTI
		if _, exists := store.tokens[key]; exists {
			return errors.New("example mission store: person-token record already exists")
		}
		if _, duplicate := batch[key]; duplicate {
			return errors.New("example mission store: duplicate person-token identity")
		}
		batch[key] = struct{}{}
	}
	store.missions[missionKey] = cloneMissionRecord(mission)
	for _, token := range tokens {
		store.tokens[token.PersonServer+"\x00"+token.JTI] = token
	}
	return nil
}

func (store *missionStore) LoadMissionForAgent(
	_ context.Context,
	agent, s256 string,
	at time.Time,
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
		store.missions[key] = cloneMissionRecord(record)
	}
	return cloneMissionRecord(record), nil
}

func (store *missionStore) AppendMissionUpdate(
	_ context.Context,
	expected personserver.MissionRecord,
	acceptedAt time.Time,
	document aauth.MissionUpdateDocument,
) (personserver.MissionRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if acceptedAt.IsZero() {
		return personserver.MissionRecord{}, errors.New("example mission store: acceptance time is required")
	}
	if err := store.requireActive(expected, acceptedAt); err != nil {
		return personserver.MissionRecord{}, err
	}
	key := expected.Agent + "\x00" + expected.S256
	current := store.missions[key]
	current.AcceptedUpdates = append(current.AcceptedUpdates, personserver.MissionUpdateRecord{
		Document: cloneUpdateDocument(document), AcceptedAt: acceptedAt,
	})
	store.missions[key] = cloneMissionRecord(current)
	return cloneMissionRecord(current), nil
}

func (store *missionStore) CompleteMission(
	_ context.Context,
	expected personserver.MissionRecord,
	acceptedAt time.Time,
	document aauth.MissionCompletionDocument,
) (personserver.MissionRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if acceptedAt.IsZero() {
		return personserver.MissionRecord{}, errors.New("example mission store: acceptance time is required")
	}
	if err := store.requireActive(expected, acceptedAt); err != nil {
		return personserver.MissionRecord{}, err
	}
	key := expected.Agent + "\x00" + expected.S256
	current := store.missions[key]
	current.State = personserver.MissionTerminated
	current.TerminationReason = "completed"
	current.Completion = &personserver.MissionCompletionRecord{
		Document: cloneCompletionDocument(document), AcceptedAt: acceptedAt,
	}
	store.missions[key] = cloneMissionRecord(current)
	return cloneMissionRecord(current), nil
}

func (store *missionStore) CommitMissionPersonToken(
	_ context.Context,
	expected personserver.MissionRecord,
	at time.Time,
	token personserver.PersonTokenRecord,
) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.requireActive(expected, at); err != nil {
		return err
	}
	if token.MissionS256 != expected.S256 || token.Agent != expected.Agent {
		return personserver.ErrMissionConflict
	}
	key := token.PersonServer + "\x00" + token.JTI
	if _, exists := store.tokens[key]; exists {
		return errors.New("example mission store: person-token record already exists")
	}
	store.tokens[key] = token
	return nil
}

func (store *missionStore) CommitMissionAuthToken(
	_ context.Context,
	expected personserver.MissionRecord,
	at time.Time,
	token personserver.IssuedAuthTokenRecord,
) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.requireActive(expected, at); err != nil {
		return err
	}
	if token.MissionS256 != expected.S256 {
		return personserver.ErrMissionConflict
	}
	key := token.Reference.Issuer + "\x00" + token.Reference.JTI
	if _, exists := store.auth[key]; exists {
		return errors.New("example mission store: auth-token record already exists")
	}
	store.auth[key] = token
	return nil
}

func (store *missionStore) requireActive(expected personserver.MissionRecord, at time.Time) error {
	key := expected.Agent + "\x00" + expected.S256
	current, ok := store.missions[key]
	if !ok {
		return personserver.ErrMissionNotFound
	}
	if current.State == personserver.MissionActive && !current.ExpiresAt.IsZero() && !at.Before(current.ExpiresAt) {
		current.State = personserver.MissionTerminated
		current.TerminationReason = "expired"
		store.missions[key] = cloneMissionRecord(current)
	}
	if current.State == personserver.MissionTerminated {
		return &personserver.MissionTerminatedError{TerminationReason: current.TerminationReason}
	}
	if !current.Equal(expected) {
		return personserver.ErrMissionConflict
	}
	return nil
}

func cloneMissionRecord(record personserver.MissionRecord) personserver.MissionRecord {
	record.ExactJSON = append([]byte(nil), record.ExactJSON...)
	record.AcceptedUpdates = append([]personserver.MissionUpdateRecord(nil), record.AcceptedUpdates...)
	for index := range record.AcceptedUpdates {
		record.AcceptedUpdates[index].Document = cloneUpdateDocument(record.AcceptedUpdates[index].Document)
	}
	if record.Completion != nil {
		completion := *record.Completion
		completion.Document = cloneCompletionDocument(completion.Document)
		record.Completion = &completion
	}
	return record
}

func cloneUpdateDocument(document aauth.MissionUpdateDocument) aauth.MissionUpdateDocument {
	document.ExactJSON = append([]byte(nil), document.ExactJSON...)
	return document
}

func cloneCompletionDocument(document aauth.MissionCompletionDocument) aauth.MissionCompletionDocument {
	document.ExactJSON = append([]byte(nil), document.ExactJSON...)
	return document
}
