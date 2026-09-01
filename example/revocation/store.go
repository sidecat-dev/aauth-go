package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/personserver"
	"gitlab.com/sidecat-dev/aauth-go/resource"
)

type personTokenStore struct {
	mu      sync.Mutex
	records map[string]personserver.PersonTokenRecord
}

func newPersonTokenStore() *personTokenStore {
	return &personTokenStore{records: make(map[string]personserver.PersonTokenRecord)}
}

func (store *personTokenStore) Commit(_ context.Context, record personserver.PersonTokenRecord) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	key := record.PersonServer + "\x00" + record.JTI
	if retained, ok := store.records[key]; ok {
		if retained != record {
			return errors.New("person-token identity conflict")
		}
		return nil
	}
	store.records[key] = record
	return nil
}

func (store *personTokenStore) Load(_ context.Context, issuer, jti string) (personserver.PersonTokenRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	record, ok := store.records[issuer+"\x00"+jti]
	if !ok {
		return personserver.PersonTokenRecord{}, personserver.ErrPersonTokenNotFound
	}
	return record, nil
}

type issuedAuthTokenStore struct {
	mu      sync.Mutex
	records map[aauth.TokenReference]personserver.IssuedAuthTokenRecord
}

func newIssuedAuthTokenStore() *issuedAuthTokenStore {
	return &issuedAuthTokenStore{records: make(map[aauth.TokenReference]personserver.IssuedAuthTokenRecord)}
}

func (store *issuedAuthTokenStore) CommitIssuedAuthToken(_ context.Context, record personserver.IssuedAuthTokenRecord) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if retained, ok := store.records[record.Reference]; ok && retained != record {
		return personserver.ErrIssuedAuthTokenConflict
	}
	store.records[record.Reference] = record
	return nil
}

func (store *issuedAuthTokenStore) LoadIssuedAuthToken(_ context.Context, reference aauth.TokenReference) (personserver.IssuedAuthTokenRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	record, ok := store.records[reference]
	if !ok {
		return personserver.IssuedAuthTokenRecord{}, personserver.ErrIssuedAuthTokenNotFound
	}
	return record, nil
}

type authTokenStatusStore struct {
	mu      sync.Mutex
	records map[aauth.TokenReference]resource.ObservedAuthToken
	revoked map[aauth.TokenReference]bool
}

type agentTokenRevocationStore struct {
	mu      sync.Mutex
	revoked map[aauth.TokenReference]struct{}
}

func newAgentTokenRevocationStore() *agentTokenRevocationStore {
	return &agentTokenRevocationStore{revoked: make(map[aauth.TokenReference]struct{})}
}

func (store *agentTokenRevocationStore) Revoke(_ context.Context, reference aauth.TokenReference) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.revoked[reference] = struct{}{}
	return nil
}

func (store *agentTokenRevocationStore) IsRevoked(_ context.Context, reference aauth.TokenReference) (bool, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	_, revoked := store.revoked[reference]
	return revoked, nil
}

func newAuthTokenStatusStore() *authTokenStatusStore {
	return &authTokenStatusStore{
		records: make(map[aauth.TokenReference]resource.ObservedAuthToken),
		revoked: make(map[aauth.TokenReference]bool),
	}
}

func (store *authTokenStatusStore) Observe(_ context.Context, record resource.ObservedAuthToken) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	reference := record.Reference
	if retained, ok := store.records[reference]; ok {
		if retained != record {
			return resource.ErrAuthTokenConflict
		}
		if store.revoked[reference] {
			return resource.ErrAuthTokenRevoked
		}
		return nil
	}
	store.records[reference] = record
	return nil
}

func (store *authTokenStatusStore) Revoke(_ context.Context, reference aauth.TokenReference) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if _, ok := store.records[reference]; !ok {
		return resource.ErrAuthTokenNotFound
	}
	store.revoked[reference] = true
	return nil
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

type loseOneRevocationResponseTransport struct {
	mu      sync.Mutex
	base    http.RoundTripper
	failure error
	armed   bool
}

func (transport *loseOneRevocationResponseTransport) Arm() {
	transport.mu.Lock()
	defer transport.mu.Unlock()
	transport.armed = true
}

func (transport *loseOneRevocationResponseTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	response, err := transport.base.RoundTrip(request)
	if err != nil {
		return nil, err
	}
	transport.mu.Lock()
	lose := transport.armed && request.Method == http.MethodPost && request.URL.Path == "/revoke"
	if lose {
		transport.armed = false
	}
	transport.mu.Unlock()
	if !lose {
		return response, nil
	}
	response.Body.Close()
	return nil, transport.failure
}

var _ personserver.TokenStore = (*personTokenStore)(nil)
var _ personserver.IssuedAuthTokenStore = (*issuedAuthTokenStore)(nil)
var _ personserver.AgentTokenRevocationStore = (*agentTokenRevocationStore)(nil)
var _ resource.AuthTokenStatusStore = (*authTokenStatusStore)(nil)
