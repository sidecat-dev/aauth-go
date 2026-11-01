package testutil

import (
	"bytes"
	"context"
	"sync"
	"time"

	"gitlab.com/sidecat-dev/aauth-go/supervisionserver"
)

// NewSupervisorStore returns an empty, concurrency-safe in-memory store for
// a supervision server. It keeps every record until the process ends.
func NewSupervisorStore() supervisionserver.Store {
	return &supervisionStore{
		connections:     make(map[supervisionPair]supervisionserver.Connection),
		pendingConnects: make(map[string]supervisionserver.PendingConnect),
		missions:        make(map[supervisionMissionKey]supervisionserver.MissionRecord),
		decisions:       make(map[supervisionPair]supervisionserver.DecisionRecord),
		pending:         make(map[string]supervisionPair),
		deliveries:      make(map[supervisionPair]supervisionserver.Delivery),
		standing:        make(map[supervisionAgentKey][]supervisionserver.StandingAnswer),
	}
}

// supervisionPair keys a record by Person Server and one second value: a
// sub, an sdi or a delivery id.
type supervisionPair struct{ personServer, value string }

type supervisionMissionKey struct{ personServer, subject, s256 string }

type supervisionAgentKey struct{ personServer, subject, agent string }

type supervisionStore struct {
	mu              sync.Mutex
	connections     map[supervisionPair]supervisionserver.Connection
	pendingConnects map[string]supervisionserver.PendingConnect
	missions        map[supervisionMissionKey]supervisionserver.MissionRecord
	decisions       map[supervisionPair]supervisionserver.DecisionRecord
	pending         map[string]supervisionPair
	deliveries      map[supervisionPair]supervisionserver.Delivery
	standing        map[supervisionAgentKey][]supervisionserver.StandingAnswer
}

func (store *supervisionStore) LoadConnection(ctx context.Context, personServer, subject string) (supervisionserver.Connection, error) {
	if err := ctx.Err(); err != nil {
		return supervisionserver.Connection{}, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	connection, ok := store.connections[supervisionPair{personServer, subject}]
	if !ok {
		return supervisionserver.Connection{}, supervisionserver.ErrNotFound
	}
	return connection, nil
}

func (store *supervisionStore) PutConnection(ctx context.Context, connection supervisionserver.Connection) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	store.connections[supervisionPair{connection.PersonServer, connection.Subject}] = connection
	return nil
}

func (store *supervisionStore) DeleteConnection(ctx context.Context, personServer, subject string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	delete(store.connections, supervisionPair{personServer, subject})
	return nil
}

func (store *supervisionStore) CreatePendingConnect(
	ctx context.Context,
	pending supervisionserver.PendingConnect,
	now time.Time,
) (supervisionserver.PendingConnect, error) {
	if err := ctx.Err(); err != nil {
		return supervisionserver.PendingConnect{}, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if _, exists := store.pendingConnects[pending.ID]; exists || pending.ID == "" || pending.Revision != 1 {
		return supervisionserver.PendingConnect{}, supervisionserver.ErrConflict
	}
	for _, existing := range store.pendingConnects {
		if existing.PersonServer == pending.PersonServer && existing.Subject == pending.Subject && existing.Live(now) {
			return existing, nil
		}
	}
	store.pendingConnects[pending.ID] = pending
	return pending, nil
}

func (store *supervisionStore) LoadPendingConnect(ctx context.Context, id string) (supervisionserver.PendingConnect, error) {
	if err := ctx.Err(); err != nil {
		return supervisionserver.PendingConnect{}, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	pending, ok := store.pendingConnects[id]
	if !ok {
		return supervisionserver.PendingConnect{}, supervisionserver.ErrNotFound
	}
	return pending, nil
}

func (store *supervisionStore) ReplacePendingConnect(
	ctx context.Context,
	before, after supervisionserver.PendingConnect,
	connection *supervisionserver.Connection,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	current, ok := store.pendingConnects[before.ID]
	if !ok || current.Revision != before.Revision || after.Revision != before.Revision+1 ||
		after.ID != current.ID || after.PersonServer != current.PersonServer || after.Subject != current.Subject ||
		after.Tenant != current.Tenant || after.URL != current.URL || after.Code != current.Code ||
		!after.CreatedAt.Equal(current.CreatedAt) || !after.ExpiresAt.Equal(current.ExpiresAt) ||
		after.RetryAfter != current.RetryAfter {
		return supervisionserver.ErrConflict
	}
	if connection != nil && (connection.PersonServer != current.PersonServer || connection.Subject != current.Subject) {
		return supervisionserver.ErrConflict
	}
	store.pendingConnects[before.ID] = after
	if connection != nil {
		store.connections[supervisionPair{connection.PersonServer, connection.Subject}] = *connection
	}
	return nil
}

func (store *supervisionStore) PutMission(ctx context.Context, mission supervisionserver.MissionRecord) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	key := supervisionMissionKey{mission.PersonServer, mission.Subject, mission.S256}
	if _, exists := store.missions[key]; !exists {
		store.missions[key] = mission.Clone()
	}
	return nil
}

func (store *supervisionStore) LoadMission(ctx context.Context, personServer, subject, s256 string) (supervisionserver.MissionRecord, error) {
	if err := ctx.Err(); err != nil {
		return supervisionserver.MissionRecord{}, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	mission, ok := store.missions[supervisionMissionKey{personServer, subject, s256}]
	if !ok {
		return supervisionserver.MissionRecord{}, supervisionserver.ErrNotFound
	}
	return mission.Clone(), nil
}

func (store *supervisionStore) TerminateMission(ctx context.Context, personServer, subject, s256, reason string, at time.Time) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	key := supervisionMissionKey{personServer, subject, s256}
	mission, ok := store.missions[key]
	if !ok {
		return supervisionserver.ErrNotFound
	}
	if !mission.Terminated {
		mission.Terminated, mission.Reason, mission.TerminatedAt = true, reason, at
		store.missions[key] = mission
	}
	return nil
}

func (store *supervisionStore) CreateDecision(
	ctx context.Context,
	record supervisionserver.DecisionRecord,
) (supervisionserver.DecisionRecord, bool, error) {
	if err := ctx.Err(); err != nil {
		return supervisionserver.DecisionRecord{}, false, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	key := supervisionPair{record.PersonServer, record.SDI}
	if existing, ok := store.decisions[key]; ok {
		return existing.Clone(), false, nil
	}
	if record.Revision != 1 || record.SDI == "" {
		return supervisionserver.DecisionRecord{}, false, supervisionserver.ErrConflict
	}
	if record.Pending != "" {
		if _, used := store.pending[record.Pending]; used {
			return supervisionserver.DecisionRecord{}, false, supervisionserver.ErrConflict
		}
		store.pending[record.Pending] = key
	}
	store.decisions[key] = record.Clone()
	return record.Clone(), true, nil
}

func (store *supervisionStore) LoadDecision(ctx context.Context, personServer, sdi string) (supervisionserver.DecisionRecord, error) {
	if err := ctx.Err(); err != nil {
		return supervisionserver.DecisionRecord{}, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	record, ok := store.decisions[supervisionPair{personServer, sdi}]
	if !ok {
		return supervisionserver.DecisionRecord{}, supervisionserver.ErrNotFound
	}
	return record.Clone(), nil
}

func (store *supervisionStore) LoadPendingDecision(ctx context.Context, pending string) (supervisionserver.DecisionRecord, error) {
	if err := ctx.Err(); err != nil {
		return supervisionserver.DecisionRecord{}, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	key, ok := store.pending[pending]
	if !ok {
		return supervisionserver.DecisionRecord{}, supervisionserver.ErrNotFound
	}
	return store.decisions[key].Clone(), nil
}

func (store *supervisionStore) ReplaceDecision(ctx context.Context, before, after supervisionserver.DecisionRecord) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	key := supervisionPair{before.PersonServer, before.SDI}
	current, ok := store.decisions[key]
	if !ok || current.Revision != before.Revision || after.Revision != before.Revision+1 ||
		after.PersonServer != current.PersonServer || after.SDI != current.SDI || after.Kind != current.Kind ||
		after.Subject != current.Subject || after.Agent != current.Agent || after.MissionS256 != current.MissionS256 ||
		!bytes.Equal(after.Request, current.Request) || after.Pending != current.Pending ||
		!after.CreatedAt.Equal(current.CreatedAt) {
		return supervisionserver.ErrConflict
	}
	store.decisions[key] = after.Clone()
	return nil
}

func (store *supervisionStore) LoadDelivery(ctx context.Context, personServer, id string) (supervisionserver.Delivery, error) {
	if err := ctx.Err(); err != nil {
		return supervisionserver.Delivery{}, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	delivery, ok := store.deliveries[supervisionPair{personServer, id}]
	if !ok {
		return supervisionserver.Delivery{}, supervisionserver.ErrNotFound
	}
	delivery.Body = append([]byte(nil), delivery.Body...)
	return delivery, nil
}

func (store *supervisionStore) RecordDelivery(ctx context.Context, delivery supervisionserver.Delivery) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	key := supervisionPair{delivery.PersonServer, delivery.ID}
	if _, exists := store.deliveries[key]; exists {
		return supervisionserver.ErrConflict
	}
	delivery.Body = append([]byte(nil), delivery.Body...)
	store.deliveries[key] = delivery
	return nil
}

func (store *supervisionStore) PutStandingAnswer(ctx context.Context, answer supervisionserver.StandingAnswer) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	key := supervisionAgentKey{answer.PersonServer, answer.Subject, answer.Agent}
	kept := make([]supervisionserver.StandingAnswer, 0, len(store.standing[key])+1)
	for _, held := range store.standing[key] {
		if held.Kind != answer.Kind || held.MissionS256 != answer.MissionS256 {
			kept = append(kept, held)
		}
	}
	store.standing[key] = append(kept, answer)
	return nil
}

func (store *supervisionStore) StandingAnswers(ctx context.Context, personServer, subject, agent string) ([]supervisionserver.StandingAnswer, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	return append([]supervisionserver.StandingAnswer(nil), store.standing[supervisionAgentKey{personServer, subject, agent}]...), nil
}

func (store *supervisionStore) ForgetMissionAnswers(ctx context.Context, personServer, subject, s256 string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	for key, answers := range store.standing {
		if key.personServer != personServer || key.subject != subject {
			continue
		}
		kept := answers[:0:0]
		for _, answer := range answers {
			if answer.MissionS256 != s256 {
				kept = append(kept, answer)
			}
		}
		store.standing[key] = kept
	}
	return nil
}
