package testutil

import (
	"context"
	"errors"
	"reflect"
	"sort"
	"sync"
	"time"

	"gitlab.com/sidecat-dev/aauth-go/accessserver"
	"gitlab.com/sidecat-dev/aauth-go/personserver"
)

// NewAccessAuthorizationStore returns an empty concurrency-safe AS pending
// store. State survives server recomposition, not process restart.
func NewAccessAuthorizationStore() accessserver.DeferredAuthorizationStore {
	return &accessAuthorizationStore{records: make(map[string]accessserver.PendingAuthorizationRecord)}
}

type accessAuthorizationStore struct {
	mu      sync.Mutex
	records map[string]accessserver.PendingAuthorizationRecord
}

func cloneAccess(r accessserver.PendingAuthorizationRecord) accessserver.PendingAuthorizationRecord {
	r.Request = append([]byte(nil), r.Request...)
	return r
}
func (s *accessAuthorizationStore) CreateAccessAuthorization(ctx context.Context, r accessserver.PendingAuthorizationRecord) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.records[r.ID]; ok || r.ID == "" || r.Revision != 1 || r.Gone {
		return accessserver.ErrPendingAuthorizationConflict
	}
	s.records[r.ID] = cloneAccess(r)
	return nil
}
func (s *accessAuthorizationStore) LoadAccessAuthorization(ctx context.Context, id string) (accessserver.PendingAuthorizationRecord, error) {
	if err := ctx.Err(); err != nil {
		return accessserver.PendingAuthorizationRecord{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.records[id]
	if !ok {
		return r, accessserver.ErrPendingAuthorizationConflict
	}
	return cloneAccess(r), nil
}
func (s *accessAuthorizationStore) ReplaceAccessAuthorization(ctx context.Context, before, after accessserver.PendingAuthorizationRecord) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	immutable := after
	immutable.Revision = before.Revision
	immutable.NextPollAt = before.NextPollAt
	immutable.Gone = before.Gone
	current, exists := s.records[before.ID]
	if !exists || !reflect.DeepEqual(current, before) || !reflect.DeepEqual(immutable, before) || after.Revision != before.Revision+1 || before.Gone {
		return accessserver.ErrPendingAuthorizationConflict
	}
	s.records[before.ID] = cloneAccess(after)
	return nil
}

// NewFederatedAuthorizationStore returns an empty concurrency-safe PS
// federation store. It fences in-flight AS calls and retains exact responses;
// it does not settle payments or bound retained records.
func NewFederatedAuthorizationStore() personserver.FederatedAuthorizationQueueStore {
	return &federatedAuthorizationStore{records: make(map[string]personserver.FederatedAuthorizationRecord)}
}

type federatedAuthorizationStore struct {
	mu      sync.Mutex
	records map[string]personserver.FederatedAuthorizationRecord
}

func cloneFederated(r personserver.FederatedAuthorizationRecord) personserver.FederatedAuthorizationRecord {
	r.Response.Header = r.Response.Header.Clone()
	r.Response.Body = append([]byte(nil), r.Response.Body...)
	return r
}
func (s *federatedAuthorizationStore) CreateFederatedAuthorization(ctx context.Context, r personserver.FederatedAuthorizationRecord) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.records[r.ID]; ok || r.ID == "" || r.Revision != 1 || r.Gone || r.Terminal || r.Advancing {
		return personserver.ErrFederatedAuthorizationConflict
	}
	s.records[r.ID] = cloneFederated(r)
	return nil
}
func (s *federatedAuthorizationStore) LoadFederatedAuthorization(ctx context.Context, id string) (personserver.FederatedAuthorizationRecord, error) {
	if err := ctx.Err(); err != nil {
		return personserver.FederatedAuthorizationRecord{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.records[id]
	if !ok {
		return r, personserver.ErrFederatedAuthorizationConflict
	}
	return cloneFederated(r), nil
}
func (s *federatedAuthorizationStore) ListPendingFederatedAuthorizations(ctx context.Context, personServer string, now time.Time, limit int) ([]personserver.FederatedAuthorizationRecord, error) {
	if ctx == nil {
		return nil, errors.New("testutil: context is required")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if limit < 1 || limit > 1000 {
		return nil, errors.New("testutil: pending list limit must be between 1 and 1000")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var rows []personserver.FederatedAuthorizationRecord
	for _, r := range s.records {
		if r.PersonServer == personServer && now.Before(r.ExpiresAt) && !r.Terminal && !r.Gone {
			rows = append(rows, cloneFederated(r))
		}
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].NextPollAt.Equal(rows[j].NextPollAt) {
			return rows[i].ID < rows[j].ID
		}
		return rows[i].NextPollAt.Before(rows[j].NextPollAt)
	})
	if len(rows) > limit {
		rows = rows[:limit]
	}
	return rows, nil
}

func (s *federatedAuthorizationStore) ReplaceFederatedAuthorization(ctx context.Context, before, after personserver.FederatedAuthorizationRecord) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	immutable := after
	immutable.Revision = before.Revision
	immutable.NextPollAt = before.NextPollAt
	immutable.RetryAfter = before.RetryAfter
	immutable.Gone = before.Gone
	immutable.Advancing = before.Advancing
	immutable.Terminal = before.Terminal
	immutable.Response = before.Response
	current, exists := s.records[before.ID]
	if !exists || !reflect.DeepEqual(current, before) || !reflect.DeepEqual(immutable, before) || after.Revision != before.Revision+1 || before.Gone || before.Terminal && (!after.Terminal || !reflect.DeepEqual(before.Response, after.Response)) {
		return personserver.ErrFederatedAuthorizationConflict
	}
	s.records[before.ID] = cloneFederated(after)
	return nil
}
