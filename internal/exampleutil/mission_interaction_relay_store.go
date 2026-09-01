package exampleutil

import (
	"context"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/personserver"
)

// NewMissionInteractionRelayStore returns one in-memory transaction boundary
// for mission lifecycle, mission-bound tokens, and Interaction relay state.
func NewMissionInteractionRelayStore() personserver.MissionInteractionRelayStore {
	return &missionInteractionRelayStore{
		missionStore: newMissionStore(),
		relays:       make(map[string]personserver.InteractionRelayRecord),
	}
}

type missionInteractionRelayStore struct {
	*missionStore
	relays map[string]personserver.InteractionRelayRecord
}

func (store *missionInteractionRelayStore) CreateInteractionRelay(
	_ context.Context,
	record personserver.InteractionRelayRecord,
) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	return createInteractionRelayRecord(store.relays, record)
}

func (store *missionInteractionRelayStore) LoadInteractionRelay(
	_ context.Context,
	id string,
	at time.Time,
) (personserver.InteractionRelayRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	return loadInteractionRelayRecord(store.relays, id, at)
}

func (store *missionInteractionRelayStore) ResolveInteractionRelay(
	_ context.Context,
	id string,
	status aauth.InteractionRelayStatus,
	at time.Time,
) (personserver.InteractionRelayRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	return resolveInteractionRelayRecord(store.relays, id, status, at)
}

func (store *missionInteractionRelayStore) PollInteractionRelay(
	_ context.Context,
	id string,
	identity personserver.InteractionRelayPollIdentity,
	at time.Time,
) (personserver.InteractionRelayRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	return pollInteractionRelayRecord(store.relays, id, identity, at)
}

func (store *missionInteractionRelayStore) ConsumeInteractionRelay(
	_ context.Context,
	id string,
	record personserver.InteractionRelayRecord,
) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	return consumeInteractionRelayRecord(store.relays, id, record)
}

func (store *missionInteractionRelayStore) CreateMissionInteractionRelay(
	_ context.Context,
	expected personserver.MissionRecord,
	record personserver.InteractionRelayRecord,
	at time.Time,
) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.requireActive(expected, at); err != nil {
		return err
	}
	if record.Agent != expected.Agent || record.Document.Relay.MissionS256 != expected.S256 {
		return personserver.ErrMissionConflict
	}
	return createInteractionRelayRecord(store.relays, record)
}

func (store *missionInteractionRelayStore) ResolveMissionInteractionRelay(
	_ context.Context,
	expected personserver.MissionRecord,
	id string,
	status aauth.InteractionRelayStatus,
	at time.Time,
) (personserver.InteractionRelayRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.requireActive(expected, at); err != nil {
		return personserver.InteractionRelayRecord{}, err
	}
	if err := requireMissionRelay(store.relays, id, expected); err != nil {
		return personserver.InteractionRelayRecord{}, err
	}
	return resolveInteractionRelayRecord(store.relays, id, status, at)
}

func (store *missionInteractionRelayStore) PollMissionInteractionRelay(
	_ context.Context,
	expected personserver.MissionRecord,
	id string,
	identity personserver.InteractionRelayPollIdentity,
	at time.Time,
) (personserver.InteractionRelayRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.requireActive(expected, at); err != nil {
		return personserver.InteractionRelayRecord{}, err
	}
	if err := requireMissionRelay(store.relays, id, expected); err != nil {
		return personserver.InteractionRelayRecord{}, err
	}
	return pollInteractionRelayRecord(store.relays, id, identity, at)
}

func (store *missionInteractionRelayStore) ConsumeMissionInteractionRelay(
	_ context.Context,
	expected personserver.MissionRecord,
	id string,
	record personserver.InteractionRelayRecord,
	at time.Time,
) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.requireActive(expected, at); err != nil {
		return err
	}
	if err := requireMissionRelay(store.relays, id, expected); err != nil {
		return err
	}
	return consumeInteractionRelayRecord(store.relays, id, record)
}

func requireMissionRelay(
	records map[string]personserver.InteractionRelayRecord,
	id string,
	mission personserver.MissionRecord,
) error {
	record, exists := records[id]
	if !exists {
		return personserver.ErrInteractionRelayNotFound
	}
	if record.Agent != mission.Agent || record.Document.Relay.MissionS256 != mission.S256 {
		return personserver.ErrMissionConflict
	}
	return nil
}

var _ personserver.MissionInteractionRelayStore = (*missionInteractionRelayStore)(nil)
