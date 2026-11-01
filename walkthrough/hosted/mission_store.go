package main

import (
	"context"
	"errors"
	"reflect"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/personserver"
	"gitlab.com/sidecat-dev/aauth-go/r3"
)

func (store *hostedProtocolStore) Commit(_ context.Context, record personserver.PersonTokenRecord) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	state, err := store.load()
	if err != nil {
		return err
	}
	key := tokenKey(record.PersonServer, record.JTI)
	if retained, ok := state.PersonTokens[key]; ok {
		if reflect.DeepEqual(retained, record) {
			return nil
		}
		return personserver.ErrMissionConflict
	}
	state.PersonTokens[key] = record
	return store.save(state)
}

func (store *hostedProtocolStore) Load(_ context.Context, issuer, jti string) (personserver.PersonTokenRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	state, err := store.load()
	if err != nil {
		return personserver.PersonTokenRecord{}, err
	}
	record, ok := state.PersonTokens[tokenKey(issuer, jti)]
	if !ok {
		return personserver.PersonTokenRecord{}, personserver.ErrPersonTokenNotFound
	}
	return record, nil
}

func (store *hostedProtocolStore) CommitMission(_ context.Context, mission personserver.MissionRecord, tokens []personserver.PersonTokenRecord) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	state, err := store.load()
	if err != nil {
		return err
	}
	key := missionKey(mission.Agent, mission.S256)
	if _, exists := state.Missions[key]; exists {
		return personserver.ErrMissionConflict
	}
	batch := map[string]bool{}
	for _, token := range tokens {
		tokenIdentity := tokenKey(token.PersonServer, token.JTI)
		if batch[tokenIdentity] {
			return personserver.ErrMissionConflict
		}
		if _, exists := state.PersonTokens[tokenIdentity]; exists {
			return personserver.ErrMissionConflict
		}
		batch[tokenIdentity] = true
	}
	state.Missions[key] = mission
	for _, token := range tokens {
		state.PersonTokens[tokenKey(token.PersonServer, token.JTI)] = token
	}
	return store.save(state)
}

func (store *hostedProtocolStore) LoadMissionForAgent(_ context.Context, agent, digest string, at time.Time) (personserver.MissionRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	state, err := store.load()
	if err != nil {
		return personserver.MissionRecord{}, err
	}
	key := missionKey(agent, digest)
	record, ok := state.Missions[key]
	if !ok {
		return personserver.MissionRecord{}, personserver.ErrMissionNotFound
	}
	if record.State == personserver.MissionActive && !at.Before(record.ExpiresAt) {
		record.State = personserver.MissionTerminated
		record.TerminationReason = "expired"
		state.Missions[key] = record
		if err := store.save(state); err != nil {
			return personserver.MissionRecord{}, err
		}
	}
	return record, nil
}

func (store *hostedProtocolStore) AppendMissionUpdate(_ context.Context, expected personserver.MissionRecord, acceptedAt time.Time, document aauth.MissionUpdateDocument) (personserver.MissionRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	state, current, err := store.activeMission(expected, acceptedAt)
	if err != nil {
		return personserver.MissionRecord{}, err
	}
	current.AcceptedUpdates = append(current.AcceptedUpdates, personserver.MissionUpdateRecord{Document: document, AcceptedAt: acceptedAt})
	state.Missions[missionKey(current.Agent, current.S256)] = current
	if err := store.save(state); err != nil {
		return personserver.MissionRecord{}, err
	}
	return current, nil
}

func (store *hostedProtocolStore) CompleteMission(_ context.Context, expected personserver.MissionRecord, acceptedAt time.Time, document aauth.MissionCompletionDocument) (personserver.MissionRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	state, current, err := store.activeMission(expected, acceptedAt)
	if err != nil {
		return personserver.MissionRecord{}, err
	}
	current.State = personserver.MissionTerminated
	current.TerminationReason = "completed"
	current.Completion = &personserver.MissionCompletionRecord{Document: document, AcceptedAt: acceptedAt}
	state.Missions[missionKey(current.Agent, current.S256)] = current
	if err := store.save(state); err != nil {
		return personserver.MissionRecord{}, err
	}
	return current, nil
}

func (store *hostedProtocolStore) CommitMissionPersonToken(_ context.Context, expected personserver.MissionRecord, decidedAt time.Time, token personserver.PersonTokenRecord) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	state, _, err := store.activeMission(expected, decidedAt)
	if err != nil {
		return err
	}
	if token.MissionS256 != expected.S256 || token.Agent != expected.Agent {
		return personserver.ErrMissionConflict
	}
	key := tokenKey(token.PersonServer, token.JTI)
	if _, exists := state.PersonTokens[key]; exists {
		return personserver.ErrMissionConflict
	}
	state.PersonTokens[key] = token
	return store.save(state)
}

func (store *hostedProtocolStore) CommitMissionAuthToken(_ context.Context, expected personserver.MissionRecord, decidedAt time.Time, token personserver.IssuedAuthTokenRecord) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	state, _, err := store.activeMission(expected, decidedAt)
	if err != nil {
		return err
	}
	if token.MissionS256 != expected.S256 {
		return personserver.ErrMissionConflict
	}
	key := referenceKey(token.Reference)
	if _, exists := state.AuthTokens[key]; exists {
		return personserver.ErrMissionConflict
	}
	state.AuthTokens[key] = token
	return store.save(state)
}

func (store *hostedProtocolStore) CommitMissionR3AuthToken(_ context.Context, expected personserver.MissionRecord, decidedAt time.Time, token personserver.IssuedAuthTokenRecord, issuance r3.IssuanceRecord) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	state, _, err := store.activeMission(expected, decidedAt)
	if err != nil {
		return err
	}
	if token.MissionS256 != expected.S256 || issuance.AuthTokenReference != token.Reference ||
		issuance.Resource != token.Resource || !issuance.IssuedAt.Equal(token.IssuedAt) ||
		issuance.PersonServer != token.Reference.Issuer || issuance.Agent != expected.Agent {
		return personserver.ErrMissionConflict
	}
	key := referenceKey(token.Reference)
	if _, exists := state.AuthTokens[key]; exists {
		return personserver.ErrMissionConflict
	}
	if _, exists := state.R3Issuances[key]; exists {
		return r3.ErrIssuanceConflict
	}
	state.AuthTokens[key] = token
	state.R3Issuances[key] = encodeHostedR3Issuance(issuance)
	return store.save(state)
}

func (store *hostedProtocolStore) TerminateMission(_ context.Context, agent, digest string, terminatedAt time.Time, reason string) (personserver.MissionRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if terminatedAt.IsZero() || reason == "" {
		return personserver.MissionRecord{}, errors.New("mission termination time and reason are required")
	}
	state, err := store.load()
	if err != nil {
		return personserver.MissionRecord{}, err
	}
	key := missionKey(agent, digest)
	current, ok := state.Missions[key]
	if !ok {
		return personserver.MissionRecord{}, personserver.ErrMissionNotFound
	}
	if current.State != personserver.MissionActive {
		return current, nil
	}
	current.State = personserver.MissionTerminated
	current.TerminationReason = reason
	if !current.ExpiresAt.IsZero() && !terminatedAt.Before(current.ExpiresAt) {
		current.TerminationReason = "expired"
	}
	state.Missions[key] = current
	if err := store.save(state); err != nil {
		return personserver.MissionRecord{}, err
	}
	return current, nil
}

func (store *hostedProtocolStore) LoadMissionTokens(_ context.Context, digest string) (personserver.MissionTokens, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	state, err := store.load()
	if err != nil {
		return personserver.MissionTokens{}, err
	}
	issued := personserver.MissionTokens{
		PersonTokens: []personserver.PersonTokenRecord{}, AuthTokens: []personserver.IssuedAuthTokenRecord{},
	}
	for _, record := range state.PersonTokens {
		if record.MissionS256 == digest {
			issued.PersonTokens = append(issued.PersonTokens, record)
		}
	}
	for _, record := range state.AuthTokens {
		if record.MissionS256 == digest {
			issued.AuthTokens = append(issued.AuthTokens, record)
		}
	}
	return issued, nil
}

func (store *hostedProtocolStore) activeMission(expected personserver.MissionRecord, at time.Time) (hostedProtocolState, personserver.MissionRecord, error) {
	state, err := store.load()
	if err != nil {
		return state, personserver.MissionRecord{}, err
	}
	key := missionKey(expected.Agent, expected.S256)
	current, ok := state.Missions[key]
	if !ok {
		return state, personserver.MissionRecord{}, personserver.ErrMissionNotFound
	}
	if current.State != personserver.MissionActive {
		return state, personserver.MissionRecord{}, &personserver.MissionTerminatedError{TerminationReason: current.TerminationReason}
	}
	if at.IsZero() {
		return state, personserver.MissionRecord{}, errors.New("mission decision time is required")
	}
	if !at.Before(current.ExpiresAt) {
		current.State = personserver.MissionTerminated
		current.TerminationReason = "expired"
		state.Missions[key] = current
		if err := store.save(state); err != nil {
			return state, personserver.MissionRecord{}, err
		}
		return state, personserver.MissionRecord{}, &personserver.MissionTerminatedError{TerminationReason: "expired"}
	}
	if !current.Equal(expected) {
		return state, personserver.MissionRecord{}, personserver.ErrMissionConflict
	}
	return state, current, nil
}

func missionKey(agent, digest string) string { return agent + "\x1f" + digest }

var _ personserver.MissionR3IssuanceStore = (*hostedProtocolStore)(nil)
