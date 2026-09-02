package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/personserver"
	"gitlab.com/sidecat-dev/aauth-go/resource"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

const interopWriteScope = "notes.write"

type interopAuthorizationServiceConfig struct {
	Origin   string
	Agent    string
	Clock    aauth.Clock
	Resolver signaturekey.KeyResolver
	Notes    *interopNoteStore
}

type interopAuthorizationService struct {
	handler http.Handler
}

type interopAuthorizationRunConfig struct {
	Origin      string
	AgentIssuer string
	Agent       string
	StateDir    string
	Clock       aauth.Clock
	HTTPClient  *http.Client
}

type interopTokenStore struct {
	mu      sync.Mutex
	records map[string]personserver.PersonTokenRecord
}

func newInteropAuthorizationService(config interopAuthorizationServiceConfig) (*interopAuthorizationService, error) {
	if err := aauth.ValidateServerIdentifier(config.Origin); err != nil {
		return nil, fmt.Errorf("service origin: %w", err)
	}
	if err := aauth.ValidateAgentIdentifier(config.Agent); err != nil {
		return nil, fmt.Errorf("Agent: %w", err)
	}
	if config.Clock == nil || config.Resolver == nil || config.Notes == nil {
		return nil, errors.New("service clock, key resolver, and note store are required")
	}
	personKey, err := newInteropSigningKey("person-key-1")
	if err != nil {
		return nil, err
	}
	resourceKey, err := newInteropSigningKey("resource-key-1")
	if err != nil {
		return nil, err
	}
	var sequence atomic.Uint64
	newID := func() string { return fmt.Sprintf("interop-%d", sequence.Add(1)) }
	people, err := personserver.NewPSAuthorization(personserver.PSAuthorizationConfig{
		Issuer: config.Origin, SigningKey: personKey, KeyResolver: config.Resolver,
		Clock: config.Clock, NewID: newID, Tokens: newInteropTokenStore(),
		BindPerson: func(_ context.Context, request personserver.PersonTokenRequest) (personserver.Person, error) {
			if request.Agent != config.Agent || request.Resource != config.Origin {
				return personserver.Person{}, personserver.ErrAccessDenied
			}
			return personserver.Person{Subject: "interop-person", Lifetime: 10 * time.Minute}, nil
		},
		Authorize: func(_ context.Context, request personserver.AuthorizationRequest) (personserver.AuthorizationDecision, error) {
			return personserver.AuthorizationDecision{Scopes: request.Scopes, Lifetime: 10 * time.Minute}, nil
		},
	})
	if err != nil {
		return nil, err
	}
	protected := http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		principal, ok := resource.AuthPrincipalFromContext(request.Context())
		if !ok {
			http.Error(response, "verified authorization principal is unavailable", http.StatusInternalServerError)
			return
		}
		serveInteropNote(response, request, config.Notes, principal.Subject)
	})
	protectedResource, err := resource.NewPSAuthorization(resource.PSAuthorizationConfig{
		Issuer: config.Origin, SigningKey: resourceKey, KeyResolver: config.Resolver,
		Clock: config.Clock, NewID: newID,
		ScopeDescriptions:             map[string]string{interopWriteScope: "Create one interoperability note"},
		AdditionalSignatureComponents: []string{"content-type", "content-digest", "idempotency-key"},
		MaxSignedBodyBytes:            interopMaxResponseBytes,
		RequiredScopes:                func(*http.Request) []string { return []string{interopWriteScope} },
		ResolvePerson: func(_ context.Context, identity resource.PersonIdentity, _ resource.PersonContext) error {
			if identity.Issuer != config.Origin || identity.Subject != "interop-person" {
				return errors.New("unrecognized person")
			}
			return nil
		},
		Protected: protected,
	})
	if err != nil {
		return nil, err
	}

	personHandler := people.Handler()
	resourceHandler := protectedResource.Handler()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/jwks.json", func(response http.ResponseWriter, _ *http.Request) {
		writeInteropServiceJSON(response, http.StatusOK, map[string]any{
			"keys": []jose.JWK{personKey.PublicJWK(), resourceKey.PublicJWK()},
		})
	})
	mux.Handle("GET /.well-known/aauth-person.json", personHandler)
	mux.Handle("POST /person", personHandler)
	mux.Handle("POST /token", personHandler)
	mux.Handle("GET /.well-known/aauth-resource.json", resourceHandler)
	mux.Handle("/", resourceHandler)
	return &interopAuthorizationService{handler: mux}, nil
}

func serveInteropNote(response http.ResponseWriter, request *http.Request, store *interopNoteStore, person string) {
	if request.Method != http.MethodPost {
		response.Header().Set("Allow", http.MethodPost)
		writeInteropServiceJSON(response, http.StatusMethodNotAllowed, map[string]string{"error": "method_not_allowed"})
		return
	}
	requestKey := strings.TrimSpace(request.Header.Get("Idempotency-Key"))
	if requestKey == "" {
		writeInteropServiceJSON(response, http.StatusBadRequest, map[string]string{"error": "idempotency_key_required"})
		return
	}
	var input struct {
		Text string `json:"text"`
	}
	decoder := json.NewDecoder(io.LimitReader(request.Body, interopMaxResponseBytes+1))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil || strings.TrimSpace(input.Text) == "" {
		writeInteropServiceJSON(response, http.StatusBadRequest, map[string]string{"error": "invalid_note"})
		return
	}
	result, err := store.Create(requestKey, input.Text, person)
	if errors.Is(err, errInteropNoteConflict) {
		writeInteropServiceJSON(response, http.StatusConflict, map[string]string{"error": "idempotency_conflict"})
		return
	}
	if err != nil {
		writeInteropServiceJSON(response, http.StatusInternalServerError, map[string]string{"error": "note_store_failed"})
		return
	}
	status := http.StatusCreated
	if result.Replayed {
		status = http.StatusOK
	}
	writeInteropServiceJSON(response, status, result)
}

func newInteropTokenStore() *interopTokenStore {
	return &interopTokenStore{records: make(map[string]personserver.PersonTokenRecord)}
}

func (store *interopTokenStore) Commit(_ context.Context, record personserver.PersonTokenRecord) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	key := record.PersonServer + "\x00" + record.JTI
	if _, exists := store.records[key]; exists {
		return errors.New("person-token record already exists")
	}
	store.records[key] = record
	return nil
}

func (store *interopTokenStore) Load(_ context.Context, issuer, tokenID string) (personserver.PersonTokenRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	record, ok := store.records[issuer+"\x00"+tokenID]
	if !ok {
		return personserver.PersonTokenRecord{}, personserver.ErrPersonTokenNotFound
	}
	return record, nil
}

func (service *interopAuthorizationService) Handler() http.Handler {
	return service.handler
}

func serveInteropAuthorization(ctx context.Context, listener net.Listener, config interopAuthorizationRunConfig) error {
	if listener == nil {
		return errors.New("service listener is required")
	}
	host, _, err := net.SplitHostPort(listener.Addr().String())
	if err != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() {
		return errors.New("service listener must use a loopback address behind the TLS proxy")
	}
	if err := aauth.ValidateServerIdentifier(config.AgentIssuer); err != nil {
		return fmt.Errorf("Agent issuer: %w", err)
	}
	if config.StateDir == "" {
		return errors.New("service state directory is required")
	}
	clock := config.Clock
	if clock == nil {
		clock = aauth.SystemClock{}
	}
	client := config.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}
	resolver, err := signaturekey.NewHTTPKeyResolver(signaturekey.HTTPKeyResolverConfig{
		Client: client, Clock: clock,
		Admit: func(_ context.Context, endpoint string) error {
			parsed, err := url.Parse(endpoint)
			if err != nil {
				return err
			}
			origin := parsed.Scheme + "://" + parsed.Host
			if origin != config.AgentIssuer && origin != config.Origin {
				return fmt.Errorf("discovery endpoint is outside the two admitted origins: %s", origin)
			}
			return nil
		},
	})
	if err != nil {
		return err
	}
	service, err := newInteropAuthorizationService(interopAuthorizationServiceConfig{
		Origin: config.Origin, Agent: config.Agent, Clock: clock, Resolver: resolver,
		Notes: newInteropNoteStore(filepath.Join(config.StateDir, "notes.json")),
	})
	if err != nil {
		return err
	}
	server := &http.Server{Handler: service.Handler(), ReadHeaderTimeout: 5 * time.Second}
	shutdown := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = server.Shutdown(context.Background())
		case <-shutdown:
		}
	}()
	err = server.Serve(listener)
	close(shutdown)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func newInteropSigningKey(id string) (jose.SigningKey, error) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return jose.SigningKey{}, err
	}
	return jose.NewEd25519SigningKey(id, privateKey)
}

func writeInteropServiceJSON(response http.ResponseWriter, status int, value any) {
	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(value)
}
