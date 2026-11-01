package testutil

import (
	"context"
	"net/http"
	"sort"
	"sync"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/personserver"
	"gitlab.com/sidecat-dev/aauth-go/supervision"
)

// SupervisionStore is an in-memory personserver.SupervisionStore. Log
// returns the retained log entries, for a test or an example to inspect
// what the Person Server recorded of each decision. It keeps the Agent of each
// recorded Agent token until the process ends, past expiresAt.
type SupervisionStore struct {
	mu          sync.Mutex
	connections map[supervisionKey]personserver.SupervisorConnection
	routes      map[string]personserver.Supervisor
	log         []personserver.SupervisionLogEntry
	notices     []personserver.SupervisionNotice
	sequences   map[supervisionKey]uint64
	requests    map[string]personserver.SupervisedRequest
	tokens      map[aauth.TokenReference]string
}

type supervisionKey struct{ issuer, subject string }

// NewSupervisionStore returns an empty, concurrency-safe in-memory store for
// a Person Server's supervision state. It keeps every record until the
// process ends.
func NewSupervisionStore() *SupervisionStore {
	return &SupervisionStore{
		connections: make(map[supervisionKey]personserver.SupervisorConnection),
		routes:      make(map[string]personserver.Supervisor),
		sequences:   make(map[supervisionKey]uint64),
		requests:    make(map[string]personserver.SupervisedRequest),
		tokens:      make(map[aauth.TokenReference]string),
	}
}

// Log returns copies of the retained log entries in the order recorded.
func (store *SupervisionStore) Log() []personserver.SupervisionLogEntry {
	store.mu.Lock()
	defer store.mu.Unlock()
	entries := make([]personserver.SupervisionLogEntry, len(store.log))
	for index, entry := range store.log {
		entries[index] = cloneLogEntry(entry)
	}
	return entries
}

func (store *SupervisionStore) LoadSupervisorConnection(ctx context.Context, issuer, subject string) (personserver.SupervisorConnection, error) {
	if err := ctx.Err(); err != nil {
		return personserver.SupervisorConnection{}, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	connection, ok := store.connections[supervisionKey{issuer, subject}]
	if !ok {
		return personserver.SupervisorConnection{}, personserver.ErrSupervisionNotFound
	}
	return connection, nil
}

func (store *SupervisionStore) SaveSupervisorConnection(ctx context.Context, connection personserver.SupervisorConnection) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	store.connections[supervisionKey{connection.Supervisor.Issuer, connection.Supervisor.Subject}] = connection
	return nil
}

func (store *SupervisionStore) LoadAgentSupervisor(ctx context.Context, agent string) (personserver.Supervisor, error) {
	if err := ctx.Err(); err != nil {
		return personserver.Supervisor{}, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	supervisor, ok := store.routes[agent]
	if !ok {
		return personserver.Supervisor{}, personserver.ErrSupervisionNotFound
	}
	return supervisor, nil
}

func (store *SupervisionStore) SaveAgentSupervisor(ctx context.Context, agent string, supervisor personserver.Supervisor) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	store.routes[agent] = supervisor
	return nil
}

func (store *SupervisionStore) RecordSupervisionLog(ctx context.Context, entry personserver.SupervisionLogEntry) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	store.log = append(store.log, cloneLogEntry(entry))
	return nil
}

func (store *SupervisionStore) AppendSupervisionNotices(ctx context.Context, notices []personserver.SupervisionNotice) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	for _, notice := range notices {
		key := supervisionKey{notice.Supervisor.Issuer, notice.Supervisor.Subject}
		queued := false
		for _, existing := range store.notices {
			if existing.ID == notice.ID && existing.Supervisor == notice.Supervisor && !existing.Delivered {
				queued = true
				break
			}
		}
		if queued {
			continue
		}
		store.sequences[key]++
		notice = cloneNotice(notice)
		notice.Sequence = store.sequences[key]
		notice.Delivered = false
		store.notices = append(store.notices, notice)
	}
	return nil
}

func (store *SupervisionStore) PendingSupervisionNotices(ctx context.Context, issuer, subject string, limit int) ([]personserver.SupervisionNotice, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	var pending []personserver.SupervisionNotice
	for _, notice := range store.notices {
		if notice.Supervisor.Issuer != "" && notice.Supervisor.Issuer == issuer &&
			notice.Supervisor.Subject == subject && !notice.Delivered {
			pending = append(pending, cloneNotice(notice))
		}
	}
	sort.SliceStable(pending, func(i, j int) bool { return pending[i].Sequence < pending[j].Sequence })
	if limit > 0 && len(pending) > limit {
		pending = pending[:limit]
	}
	return pending, nil
}

func (store *SupervisionStore) MarkSupervisionNoticeDelivered(ctx context.Context, issuer, subject, id string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	for index, notice := range store.notices {
		if notice.ID == id && notice.Supervisor.Issuer == issuer && notice.Supervisor.Subject == subject {
			store.notices[index].Delivered = true
		}
	}
	return nil
}

func (store *SupervisionStore) SupervisionHistory(ctx context.Context, agent string) ([]personserver.SupervisionNotice, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	var history []personserver.SupervisionNotice
	for _, notice := range store.notices {
		if notice.Agent == agent {
			history = append(history, cloneNotice(notice))
		}
	}
	return history, nil
}

func (store *SupervisionStore) RecordTokenAgent(ctx context.Context, token aauth.TokenReference, agent string, _ time.Time) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	store.tokens[token] = agent
	return nil
}

func (store *SupervisionStore) LoadTokenAgent(ctx context.Context, token aauth.TokenReference) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	agent, ok := store.tokens[token]
	if !ok {
		return "", personserver.ErrSupervisionNotFound
	}
	return agent, nil
}

func (store *SupervisionStore) CreateSupervisedRequest(ctx context.Context, request personserver.SupervisedRequest) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if _, exists := store.requests[request.Reference]; exists || request.Reference == "" || request.Revision != 1 {
		return personserver.ErrSupervisionConflict
	}
	store.requests[request.Reference] = cloneSupervised(request)
	return nil
}

func (store *SupervisionStore) LoadSupervisedRequest(ctx context.Context, reference string) (personserver.SupervisedRequest, error) {
	if err := ctx.Err(); err != nil {
		return personserver.SupervisedRequest{}, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	request, ok := store.requests[reference]
	if !ok {
		return personserver.SupervisedRequest{}, personserver.ErrSupervisionNotFound
	}
	return cloneSupervised(request), nil
}

func (store *SupervisionStore) ReplaceSupervisedRequest(ctx context.Context, before, after personserver.SupervisedRequest) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	current, ok := store.requests[before.Reference]
	if !ok || current.Revision != before.Revision || after.Revision != before.Revision+1 ||
		after.Reference != current.Reference || after.SDI != current.SDI || after.Kind != current.Kind ||
		after.Supervisor != current.Supervisor || after.Agent != current.Agent || after.AgentJKT != current.AgentJKT ||
		after.AgentProvider != current.AgentProvider || after.MissionS256 != current.MissionS256 ||
		string(after.Request) != string(current.Request) || !after.CreatedAt.Equal(current.CreatedAt) ||
		!after.ExpiresAt.Equal(current.ExpiresAt) {
		return personserver.ErrSupervisionConflict
	}
	store.requests[before.Reference] = cloneSupervised(after)
	return nil
}

func (store *SupervisionStore) PendingSupervisedRequests(ctx context.Context, limit int) ([]personserver.SupervisedRequest, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	var pending []personserver.SupervisedRequest
	for _, request := range store.requests {
		switch request.State {
		case personserver.SupervisedWaitingForSupervisor, personserver.SupervisedWaitingForPerson, personserver.SupervisedClarifying:
			pending = append(pending, cloneSupervised(request))
		}
	}
	sort.Slice(pending, func(i, j int) bool {
		if !pending[i].CreatedAt.Equal(pending[j].CreatedAt) {
			return pending[i].CreatedAt.Before(pending[j].CreatedAt)
		}
		return pending[i].Reference < pending[j].Reference
	})
	if limit > 0 && len(pending) > limit {
		pending = pending[:limit]
	}
	return pending, nil
}

func cloneLogEntry(entry personserver.SupervisionLogEntry) personserver.SupervisionLogEntry {
	if entry.Exchange != nil {
		exchange := entry.Exchange.Clone()
		entry.Exchange = &exchange
	}
	return entry
}

func cloneNotice(notice personserver.SupervisionNotice) personserver.SupervisionNotice {
	notice.Body = append([]byte(nil), notice.Body...)
	return notice
}

func cloneSupervised(request personserver.SupervisedRequest) personserver.SupervisedRequest {
	request.Request = append([]byte(nil), request.Request...)
	request.AgentRequest.Header = http.Header(request.AgentRequest.Header).Clone()
	request.AgentRequest.Body = append([]byte(nil), request.AgentRequest.Body...)
	if request.Update != nil {
		update := *request.Update
		update.Header = http.Header(update.Header).Clone()
		update.Body = append([]byte(nil), update.Body...)
		request.Update = &update
	}
	if request.Question != nil {
		question := *request.Question
		question.Clarification.Options = append([]string(nil), question.Clarification.Options...)
		request.Question = &question
	}
	request.Transcript = append([]supervision.TranscriptEntry(nil), request.Transcript...)
	if request.Ask != nil {
		ask := cloneSupervisionDecision(*request.Ask)
		request.Ask = &ask
	}
	if request.Decision != nil {
		decision := cloneSupervisionDecision(*request.Decision)
		request.Decision = &decision
	}
	if request.Answer != nil {
		answer := *request.Answer
		if answer.Mission != nil {
			terms := cloneTerms(*answer.Mission)
			answer.Mission = &terms
		}
		request.Answer = &answer
	}
	if request.Response != nil {
		response := *request.Response
		response.Header = http.Header(response.Header).Clone()
		response.Body = append([]byte(nil), response.Body...)
		request.Response = &response
	}
	return request
}

func cloneSupervisionDecision(decision supervision.Decision) supervision.Decision {
	if decision.Mission != nil {
		terms := cloneTerms(*decision.Mission)
		decision.Mission = &terms
	}
	if decision.Proposed != nil {
		terms := cloneTerms(*decision.Proposed)
		decision.Proposed = &terms
	}
	decision.ApplyOptions = append([]supervision.ApplyOption(nil), decision.ApplyOptions...)
	return decision
}

func cloneTerms(terms supervision.MissionTerms) supervision.MissionTerms {
	terms.ApprovedTools = append(terms.ApprovedTools[:0:0], terms.ApprovedTools...)
	terms.ApprovedResources = append([]string(nil), terms.ApprovedResources...)
	if terms.ExpiresAt != nil {
		value := *terms.ExpiresAt
		terms.ExpiresAt = &value
	}
	return terms
}
