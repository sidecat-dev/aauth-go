package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync"

	"gitlab.com/sidecat-dev/aauth-go/personserver"
)

type memoryTokenStore struct {
	mu      sync.Mutex
	records map[string]personserver.PersonTokenRecord
}

func newMemoryTokenStore() *memoryTokenStore {
	return &memoryTokenStore{records: make(map[string]personserver.PersonTokenRecord)}
}

func (store *memoryTokenStore) Commit(_ context.Context, record personserver.PersonTokenRecord) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	key := record.PersonServer + "\x00" + record.JTI
	if existing, ok := store.records[key]; ok {
		if reflect.DeepEqual(existing, record) {
			return nil
		}
		return errors.New("person-token record conflicts with retained value")
	}
	store.records[key] = record
	return nil
}

func (store *memoryTokenStore) Load(_ context.Context, issuer, tokenID string) (personserver.PersonTokenRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	record, ok := store.records[issuer+"\x00"+tokenID]
	if !ok {
		return personserver.PersonTokenRecord{}, personserver.ErrPersonTokenNotFound
	}
	return record, nil
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
		return fmt.Errorf("discovery is not admitted for %s", origin)
	}
	return nil
}

func (transport *logicalTransport) RoundTrip(request *http.Request) (*http.Response, error) {
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

var _ personserver.TokenStore = (*memoryTokenStore)(nil)
