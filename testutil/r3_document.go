package testutil

import (
	"context"
	"reflect"
	"sync"

	"gitlab.com/sidecat-dev/aauth-go/resource"
)

type r3DocumentStore struct {
	mu      sync.Mutex
	records map[string]resource.R3DocumentRecord
}

// NewR3DocumentStore returns an empty, concurrency-safe Resource document store.
// Documents are copied on commit and load and retained for the store lifetime.
func NewR3DocumentStore() resource.R3DocumentStore {
	return &r3DocumentStore{records: make(map[string]resource.R3DocumentRecord)}
}

func (store *r3DocumentStore) Commit(_ context.Context, record resource.R3DocumentRecord) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	owned := record.Clone()
	if retained, ok := store.records[record.Reference.URI()]; ok {
		if !reflect.DeepEqual(retained, owned) {
			return resource.ErrR3DocumentConflict
		}
		return nil
	}
	store.records[record.Reference.URI()] = owned
	return nil
}

func (store *r3DocumentStore) Load(_ context.Context, uri string) (resource.R3DocumentRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	record, ok := store.records[uri]
	if !ok {
		return resource.R3DocumentRecord{}, resource.ErrR3DocumentNotFound
	}
	return record.Clone(), nil
}
