package personserver

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

// chainedMemoryTokenStore finds person tokens by the upstream token they were
// issued with.
type chainedMemoryTokenStore struct{ *memoryTokenStore }

func (store chainedMemoryTokenStore) LoadChainedPersonTokens(_ context.Context, upstream aauth.TokenReference) ([]PersonTokenRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	var chained []PersonTokenRecord
	for _, record := range store.records {
		if record.UpstreamTokenReference == upstream {
			chained = append(chained, record)
		}
	}
	return chained, nil
}

// revocationRecipients answers every Resource's metadata and revocation
// endpoint, and records the jti each one was asked to revoke. A Resource in
// metadataStatus answers its metadata URL with that status instead.
type revocationRecipients struct {
	mu             sync.Mutex
	revoked        []string
	metadataStatus map[string]int
}

func (recipients *revocationRecipients) RoundTrip(request *http.Request) (*http.Response, error) {
	origin := request.URL.Scheme + "://" + request.URL.Host
	response := httptest.NewRecorder()
	switch {
	case request.Method == http.MethodGet && request.URL.Path == "/.well-known/aauth-resource.json" && recipients.metadataStatus[origin] != 0:
		response.WriteHeader(recipients.metadataStatus[origin])
	case request.Method == http.MethodGet && request.URL.Path == "/.well-known/aauth-resource.json":
		_ = json.NewEncoder(response).Encode(map[string]string{"issuer": origin, "revocation_endpoint": origin + "/revoke"})
	case request.Method == http.MethodPost && request.URL.Path == "/revoke":
		body, _ := io.ReadAll(request.Body)
		var revocation struct {
			JTI string `json:"jti"`
		}
		_ = json.Unmarshal(body, &revocation)
		recipients.mu.Lock()
		recipients.revoked = append(recipients.revoked, origin+" "+revocation.JTI)
		recipients.mu.Unlock()
	default:
		response.WriteHeader(http.StatusNotFound)
	}
	result := response.Result()
	result.Request = request
	return result, nil
}

// Protocol 70d6737, Revocation Cascade: where a revoked person token was later
// presented as an upstream_token, the Person Server revokes the person tokens
// it issued from it in the same cascade, at their Resources.
func TestRevokePersonTokenRevokesThePersonTokensChainedFromIt(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 10, 30, 18, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	tokens := chainedMemoryTokenStore{newMemoryTokenStore()}
	record := func(jti, resource string, upstream string) PersonTokenRecord {
		value := PersonTokenRecord{
			JTI: jti, PersonServer: "https://ps.example", Resource: resource, Subject: "person-123",
			AgentProvider: "https://ap.example", Agent: "aauth:reader@ap.example", AgentTokenJTI: "agent-token",
			Confirmation: personServerTestKey(t, jti+"-agent").PublicJWK(),
			ExpiresAt:    now.Add(20 * time.Minute), RetainUntil: now.Add(30 * time.Minute),
		}
		if upstream != "" {
			value.UpstreamTokenReference = aauth.TokenReference{Issuer: "https://ps.example", JTI: upstream}
			value.UpstreamTokenSHA256 = [32]byte{1}
		}
		if err := tokens.Commit(context.Background(), value); err != nil {
			t.Fatal(err)
		}
		return value
	}
	record("person-token", "https://first.example", "")
	record("chained-token", "https://second.example", "person-token")
	record("twice-chained-token", "https://third.example", "chained-token")
	record("unrelated-token", "https://fourth.example", "")
	// Core, Resource Metadata: a Resource MAY publish no metadata, and one
	// that publishes none has no revocation_endpoint. A 410 is not that.
	record("unpublished-token", "https://unpublished.example", "person-token")
	record("gone-token", "https://gone.example", "person-token")

	recipients := &revocationRecipients{metadataStatus: map[string]int{
		"https://unpublished.example": http.StatusNotFound,
		"https://gone.example":        http.StatusGone,
	}}
	revocations := newChainRevocationStore()
	server, err := NewPSAuthorization(PSAuthorizationConfig{
		Issuer: "https://ps.example", SigningKey: personServerTestKey(t, "chain-ps"),
		KeyResolver: signaturekey.StaticKeyResolver{}, Clock: clock, NewID: func() string { return "unused" }, Tokens: tokens,
		BindPerson: func(context.Context, PersonTokenRequest) (Person, error) { return Person{}, nil },
		Authorize: func(context.Context, AuthorizationRequest) (AuthorizationDecision, error) {
			return AuthorizationDecision{}, nil
		},
		TokenRevocation: &TokenRevocationConfig{
			Revocations: revocations, HTTPClient: &http.Client{Transport: recipients},
			Admit: func(context.Context, string) error { return nil },
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := server.RevokePersonToken(context.Background(), "person-token")
	if err != nil {
		t.Fatal(err)
	}
	var reached []string
	for _, attempt := range result.Attempts {
		switch attempt.Recipient {
		case "https://unpublished.example":
			if attempt.Error != aauth.RevocationUnsupported {
				t.Fatalf("Resource that publishes no metadata: attempt = %#v", attempt)
			}
			continue
		case "https://gone.example":
			if attempt.Error != aauth.RevocationUnavailable {
				t.Fatalf("Resource whose metadata is gone: attempt = %#v", attempt)
			}
			continue
		}
		if !attempt.Recorded() {
			t.Fatalf("attempt = %#v", attempt)
		}
		reached = append(reached, attempt.Recipient)
	}
	if len(result.Attempts) != 5 {
		t.Fatalf("attempts = %#v", result.Attempts)
	}
	if !slices.Equal(reached, []string{"https://first.example", "https://second.example", "https://third.example"}) {
		t.Fatalf("recipients = %v", reached)
	}
	slices.Sort(recipients.revoked)
	if !slices.Equal(recipients.revoked, []string{
		"https://first.example person-token", "https://second.example chained-token", "https://third.example twice-chained-token",
	}) {
		t.Fatalf("revocations sent = %v", recipients.revoked)
	}
	for _, jti := range []string{"person-token", "chained-token", "twice-chained-token", "unpublished-token", "gone-token"} {
		if !revocations.revoked[aauth.TokenReference{Issuer: "https://ps.example", JTI: jti}] {
			t.Fatalf("%s was not recorded as revoked", jti)
		}
	}
	if revocations.revoked[aauth.TokenReference{Issuer: "https://ps.example", JTI: "unrelated-token"}] {
		t.Fatal("an unrelated person token was revoked")
	}
}

type chainRevocationStore struct {
	mu      sync.Mutex
	revoked map[aauth.TokenReference]bool
}

func newChainRevocationStore() *chainRevocationStore {
	return &chainRevocationStore{revoked: make(map[aauth.TokenReference]bool)}
}

func (store *chainRevocationStore) Revoke(_ context.Context, request aauth.RevocationRequest) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.revoked[request.Reference] = true
	return nil
}

func (store *chainRevocationStore) IsRevoked(_ context.Context, reference aauth.TokenReference) (bool, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.revoked[reference], nil
}
