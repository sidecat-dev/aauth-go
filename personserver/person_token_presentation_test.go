package personserver

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

// A Person Server records, for each person token it issues, which Access
// Server it presented the token to. The record is written before the token is
// sent, a repeated presentation to the same Access Server is recorded once, and
// a store that cannot record presentations cannot back a four-party Person
// Server.
func TestFederatedAuthorizationRecordsTheAccessServerAPersonTokenWasPresentedTo(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 10, 30, 10, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	providerKey := personServerTestKey(t, "presentation-provider")
	personKey := personServerTestKey(t, "presentation-person")
	resourceKey := personServerTestKey(t, "presentation-resource")
	accessKey := personServerTestKey(t, "presentation-access")
	agentKey := personServerTestKey(t, "presentation-agent")
	const (
		providerID = "https://provider.example"
		personID   = "https://person.example"
		resourceID = "https://resource.example"
		accessID   = "https://access.example"
		agentID    = "aauth:planner@provider.example"
	)
	resolver := signaturekey.StaticKeyResolver{
		{Issuer: providerID, DiscoveryDocument: aauth.AgentDiscoveryDocument, KeyID: providerKey.ID()}:    providerKey.PublicJWK(),
		{Issuer: personID, DiscoveryDocument: aauth.PersonDiscoveryDocument, KeyID: personKey.ID()}:       personKey.PublicJWK(),
		{Issuer: resourceID, DiscoveryDocument: aauth.ResourceDiscoveryDocument, KeyID: resourceKey.ID()}: resourceKey.PublicJWK(),
		{Issuer: accessID, DiscoveryDocument: aauth.AccessDiscoveryDocument, KeyID: accessKey.ID()}:       accessKey.PublicJWK(),
	}
	agentToken, err := aauth.MintAgentToken(providerID, providerKey, aauth.AgentTokenRequest{
		Agent: agentID, PersonServer: personID, PublicKey: agentKey.PublicJWK(), Lifetime: time.Hour,
	}, now, "presentation-agent-token")
	if err != nil {
		t.Fatal(err)
	}
	agentJKT, err := agentKey.PublicJWK().Thumbprint()
	if err != nil {
		t.Fatal(err)
	}
	mintResourceToken := func(jti, presentedJTI string) string {
		t.Helper()
		token, err := aauth.MintResourceToken(resourceKey, aauth.ResourceTokenClaims{
			Issuer: resourceID, DWK: aauth.ResourceDiscoveryDocument, Audience: accessID,
			JTI: jti, AgentJKT: agentJKT, IssuedAt: now.Unix(), ExpiresAt: now.Add(5 * time.Minute).Unix(),
			Scope: "records.read", PersonServer: personID, Subject: "person-123",
			PresentedJTI: presentedJTI, Tenant: "tenant-1",
		})
		if err != nil {
			t.Fatal(err)
		}
		return token
	}
	store := newMemoryTokenStore()
	retained := directPersonTokenRecord(
		"presented-person-token", personID, resourceID, "person-123", "tenant-1",
		providerID, agentID, agentKey.PublicJWK(), now.Add(20*time.Minute), now.Add(25*time.Minute),
	)
	if err := store.Commit(context.Background(), retained); err != nil {
		t.Fatal(err)
	}

	var mu sync.Mutex
	accessCalls := 0
	var recordedAtSend [][]string
	httpClient := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		var input struct {
			PresentedToken string `json:"presented_token"`
		}
		if err := json.NewDecoder(request.Body).Decode(&input); err != nil {
			t.Error(err)
		}
		segments := strings.Split(input.PresentedToken, ".")
		var presentedJTI string
		if len(segments) == 3 {
			var claims struct {
				JTI string `json:"jti"`
			}
			if payload, err := base64.RawURLEncoding.DecodeString(segments[1]); err == nil {
				_ = json.Unmarshal(payload, &claims)
			}
			presentedJTI = claims.JTI
		}
		recorded, err := store.LoadPersonTokenPresentations(request.Context(), personID, presentedJTI)
		mu.Lock()
		accessCalls++
		if err == nil {
			recordedAtSend = append(recordedAtSend, recorded)
		}
		mu.Unlock()
		return &http.Response{
			StatusCode: http.StatusForbidden,
			Status:     "403 Forbidden",
			Header:     http.Header{"Content-Type": []string{"application/problem+json"}},
			Body:       io.NopCloser(strings.NewReader(`{"status":403,"error":"access_denied"}`)),
			Request:    request,
		}, nil
	})}
	server, err := NewFederatedAuthorization(FederatedAuthorizationConfig{
		Issuer: personID, SigningKey: personKey, KeyResolver: resolver, Clock: clock,
		NewID:      func() string { return "unused" },
		HTTPClient: httpClient,
		AccessServerEndpoint: func(context.Context, string) (string, error) {
			return "https://api.access.example/token", nil
		},
		Tokens: store,
		BindPerson: func(context.Context, PersonTokenRequest) (Person, error) {
			return Person{}, errors.New("not used")
		},
		Consent: func(context.Context, AuthorizationRequest) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	exchange := func(resourceToken, presentedToken string) *httptest.ResponseRecorder {
		t.Helper()
		request := httptest.NewRequest(http.MethodPost, personID+"/token",
			bytes.NewReader(testTokenRequestBody(t, resourceToken, presentedToken)))
		request.Header.Set("Content-Type", "application/json")
		if err := signPersonServerTestRequest(request, agentKey, agentToken, clock); err != nil {
			t.Fatal(err)
		}
		response := httptest.NewRecorder()
		server.Handler().ServeHTTP(response, request)
		return response
	}

	firstResource := mintResourceToken("presentation-resource-1", "presented-person-token")
	presented := testPresentedPersonToken(t, personKey, firstResource, agentKey.PublicJWK(), now, now.Add(20*time.Minute))
	for attempt, resourceToken := range []string{
		firstResource, mintResourceToken("presentation-resource-2", "presented-person-token"),
	} {
		if response := exchange(resourceToken, presented); response.Code != http.StatusForbidden {
			t.Fatalf("exchange %d = %d %s", attempt, response.Code, response.Body.String())
		}
	}
	recorded, err := store.LoadPersonTokenPresentations(context.Background(), personID, "presented-person-token")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(recorded, []string{accessID}) {
		t.Fatalf("recorded Access Servers = %q, want [%q]", recorded, accessID)
	}
	if retainUntil := store.presentationRetainUntil(personID, "presented-person-token"); retainUntil.Before(now.Add(20 * time.Minute)) {
		t.Fatalf("presentation retained until %s, before the person token's exp", retainUntil)
	}
	// The person-token issuance record itself is unchanged.
	loaded, err := store.Load(context.Background(), personID, "presented-person-token")
	if err != nil {
		t.Fatal(err)
	}
	assertPersonTokenRecordEqual(t, loaded, retained)
	mu.Lock()
	if accessCalls != 2 || len(recordedAtSend) != 2 ||
		!slices.Equal(recordedAtSend[0], []string{accessID}) || !slices.Equal(recordedAtSend[1], []string{accessID}) {
		t.Fatalf("access calls = %d, AccessServers when sent = %q", accessCalls, recordedAtSend)
	}
	mu.Unlock()

	// A presentation that cannot be recorded is not made.
	store.failPresentations(errors.New("presentation store unavailable"))
	secondResource := mintResourceToken("presentation-resource-3", "presented-person-token")
	response := exchange(secondResource, presented)
	mu.Lock()
	calls := accessCalls
	mu.Unlock()
	if response.Code != http.StatusInternalServerError || calls != 2 {
		t.Fatalf("unrecorded presentation = %d %s; access calls = %d", response.Code, response.Body.String(), calls)
	}
	store.failPresentations(nil)

	// A four-party Person Server cannot be built on a store that cannot record
	// presentations.
	if _, err := NewFederatedAuthorization(FederatedAuthorizationConfig{
		Issuer: personID, SigningKey: personKey, KeyResolver: resolver, Clock: clock,
		NewID: func() string { return "unused" }, HTTPClient: httpClient,
		AccessServerEndpoint: func(context.Context, string) (string, error) { return "https://api.access.example/token", nil },
		Tokens:               commitOnlyTokenStore{store},
		BindPerson:           func(context.Context, PersonTokenRequest) (Person, error) { return Person{}, nil },
		Consent:              func(context.Context, AuthorizationRequest) error { return nil },
	}); err == nil {
		t.Fatal("four-party Person Server accepted a store that cannot record presentations")
	}
}

// commitOnlyTokenStore hides every method but TokenStore.
type commitOnlyTokenStore struct{ inner TokenStore }

func (store commitOnlyTokenStore) Commit(ctx context.Context, record PersonTokenRecord) error {
	return store.inner.Commit(ctx, record)
}

func (store commitOnlyTokenStore) Load(ctx context.Context, issuer, jti string) (PersonTokenRecord, error) {
	return store.inner.Load(ctx, issuer, jti)
}

func (store *memoryTokenStore) presentationRetainUntil(personServer, jti string) time.Time {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.presentationRetention[personServer+"\x00"+jti]
}

func (store *memoryTokenStore) failPresentations(err error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.presentationErr = err
}
