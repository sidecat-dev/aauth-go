package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync"

	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/personserver"
	"gitlab.com/sidecat-dev/aauth-go/r3"
	"gitlab.com/sidecat-dev/aauth-go/resource"
)

func newSigningKey(id string) (jose.SigningKey, error) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return jose.SigningKey{}, err
	}
	return jose.NewEd25519SigningKey(id, privateKey)
}

type logicalTransport struct {
	mu     sync.RWMutex
	routes map[string]http.Handler
}

func newLogicalTransport() *logicalTransport {
	return &logicalTransport{routes: make(map[string]http.Handler)}
}

func (transport *logicalTransport) Handle(origin string, handler http.Handler) {
	transport.mu.Lock()
	defer transport.mu.Unlock()
	transport.routes[origin] = handler
}

func (transport *logicalTransport) Admit(_ context.Context, endpoint string) error {
	request, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	origin := request.URL.Scheme + "://" + request.URL.Host
	transport.mu.RLock()
	_, ok := transport.routes[origin]
	transport.mu.RUnlock()
	if !ok {
		return fmt.Errorf("endpoint origin is not admitted: %s", origin)
	}
	return nil
}

func (transport *logicalTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if request.Body != nil {
		defer request.Body.Close()
	}
	origin := request.URL.Scheme + "://" + request.URL.Host
	transport.mu.RLock()
	handler := transport.routes[origin]
	transport.mu.RUnlock()
	if handler == nil {
		return nil, fmt.Errorf("no handler for %s", origin)
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	response := recorder.Result()
	response.Request = request
	return response, nil
}

type memoryPersonTokenStore struct {
	mu      sync.Mutex
	records map[string]personserver.PersonTokenRecord
}

func newMemoryPersonTokenStore() *memoryPersonTokenStore {
	return &memoryPersonTokenStore{records: make(map[string]personserver.PersonTokenRecord)}
}

func (store *memoryPersonTokenStore) Commit(_ context.Context, record personserver.PersonTokenRecord) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	key := record.PersonServer + "\x00" + record.JTI
	if retained, ok := store.records[key]; ok {
		if reflect.DeepEqual(retained, record) {
			return nil
		}
		return errors.New("person-token record conflicts with retained state")
	}
	store.records[key] = record
	return nil
}

func (store *memoryPersonTokenStore) Load(_ context.Context, issuer, tokenID string) (personserver.PersonTokenRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	record, ok := store.records[issuer+"\x00"+tokenID]
	if !ok {
		return personserver.PersonTokenRecord{}, personserver.ErrPersonTokenNotFound
	}
	return record, nil
}

type memoryDocumentStore struct {
	mu      sync.Mutex
	records map[string]resource.R3DocumentRecord
}

func newMemoryDocumentStore() *memoryDocumentStore {
	return &memoryDocumentStore{records: make(map[string]resource.R3DocumentRecord)}
}

func (store *memoryDocumentStore) Commit(_ context.Context, record resource.R3DocumentRecord) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	owned := cloneDocumentRecord(record)
	key := record.Reference.URI()
	if retained, ok := store.records[key]; ok {
		if reflect.DeepEqual(retained, owned) {
			return nil
		}
		return resource.ErrR3DocumentConflict
	}
	store.records[key] = owned
	return nil
}

func (store *memoryDocumentStore) Load(_ context.Context, uri string) (resource.R3DocumentRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	record, ok := store.records[uri]
	if !ok {
		return resource.R3DocumentRecord{}, resource.ErrR3DocumentNotFound
	}
	return cloneDocumentRecord(record), nil
}

func cloneDocumentRecord(record resource.R3DocumentRecord) resource.R3DocumentRecord {
	return record.Clone()
}

type memoryIssuanceStore struct {
	mu      sync.Mutex
	records map[string]r3.IssuanceRecord
}

func newMemoryIssuanceStore() *memoryIssuanceStore {
	return &memoryIssuanceStore{records: make(map[string]r3.IssuanceRecord)}
}

func (store *memoryIssuanceStore) Commit(_ context.Context, record r3.IssuanceRecord) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	owned := cloneIssuanceRecord(record)
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

func cloneIssuanceRecord(record r3.IssuanceRecord) r3.IssuanceRecord {
	if record.Account != nil {
		account := *record.Account
		record.Account = &account
	}
	return record
}

var _ http.RoundTripper = (*logicalTransport)(nil)
var _ personserver.TokenStore = (*memoryPersonTokenStore)(nil)
var _ resource.R3DocumentStore = (*memoryDocumentStore)(nil)
var _ r3.IssuanceStore = (*memoryIssuanceStore)(nil)
