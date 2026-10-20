package testutil

import (
	"context"
	"reflect"
	"sync"

	"gitlab.com/sidecat-dev/aauth-go/r3"
)

type r3IssuanceStore struct {
	mu      sync.Mutex
	records map[string]r3.IssuanceRecord
}

// NewR3IssuanceStore returns an empty, concurrency-safe issuance audit fixture.
// Use a separate instance for each deciding role. Records are retained for the
// store lifetime; the fixture does not provide durable audit storage.
func NewR3IssuanceStore() r3.IssuanceStore {
	return &r3IssuanceStore{records: make(map[string]r3.IssuanceRecord)}
}

func (store *r3IssuanceStore) Commit(_ context.Context, record r3.IssuanceRecord) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	owned := record.Clone()
	key := record.AuthTokenReference.Issuer + "\x00" + record.AuthTokenReference.JTI
	if retained, ok := store.records[key]; ok {
		if reflect.DeepEqual(retained, owned) {
			return nil
		}
		return r3.ErrIssuanceConflict
	}
	store.records[key] = owned
	return nil
}
