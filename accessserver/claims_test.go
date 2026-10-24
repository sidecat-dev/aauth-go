package accessserver

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

func TestAccessServerClaimsContinuation(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 10, 24, 23, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	apKey := accessServerTestKey(t, "ap-key")
	psKey := accessServerTestKey(t, "ps-key")
	resourceKey := accessServerTestKey(t, "resource-key")
	accessKey := accessServerTestKey(t, "access-key")
	agentKey := accessServerTestKey(t, "agent-key")
	resolver := newRefreshingKeyResolver(signaturekey.StaticKeyResolver{
		{Issuer: "https://ap.example", DiscoveryDocument: aauth.AgentDiscoveryDocument, KeyID: apKey.ID()}:                apKey.PublicJWK(),
		{Issuer: "https://ps.example", DiscoveryDocument: aauth.PersonDiscoveryDocument, KeyID: psKey.ID()}:               psKey.PublicJWK(),
		{Issuer: "https://resource.example", DiscoveryDocument: aauth.ResourceDiscoveryDocument, KeyID: resourceKey.ID()}: resourceKey.PublicJWK(),
		{Issuer: "https://as.example", DiscoveryDocument: aauth.AccessDiscoveryDocument, KeyID: accessKey.ID()}:           accessKey.PublicJWK(),
	})
	agentToken, err := aauth.MintAgentToken("https://ap.example", apKey, aauth.AgentTokenRequest{
		Agent: "aauth:planner@ap.example", PersonServer: "https://ps.example", PublicKey: agentKey.PublicJWK(), Lifetime: time.Hour,
	}, now, "agent-token-1")
	if err != nil {
		t.Fatal(err)
	}
	agentJKT, err := agentKey.PublicJWK().Thumbprint()
	if err != nil {
		t.Fatal(err)
	}
	resourceToken, err := aauth.MintResourceToken(resourceKey, aauth.ResourceTokenClaims{
		Issuer: "https://resource.example", DWK: aauth.ResourceDiscoveryDocument, Audience: "https://as.example",
		JTI: "resource-token-1", AgentJKT: agentJKT, IssuedAt: now.Unix(), ExpiresAt: now.Add(5 * time.Minute).Unix(),
		Scope: "records.read", PersonServer: "https://ps.example", Subject: "person-1", PresentedJTI: "person-token-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	mode := "claims"
	var seen map[string]json.RawMessage
	server, err := New(Config{
		Issuer: "https://as.example", SigningKey: accessKey, KeyResolver: resolver, Clock: clock,
		NewID:             func() string { return "auth-token-claims" },
		TrustPersonServer: func(context.Context, string) error { return nil },
		Deferred:          &DeferredConfig{Store: newClaimsTestStore(), Lifetime: time.Minute},
		Authorize: func(_ context.Context, request AuthorizationRequest) (Decision, error) {
			seen = request.Claims
			switch mode {
			case "sub":
				return Decision{Pending: &PendingDecision{RequiredClaims: []string{"sub"}}}, nil
			case "payment-and-claims":
				return Decision{Pending: &PendingDecision{Payment: &PaymentChallenge{Authenticate: `Payment id="bill"`}, RequiredClaims: []string{"email"}}}, nil
			case "duplicate":
				return Decision{Pending: &PendingDecision{RequiredClaims: []string{"email", "email"}}}, nil
			default:
				if _, ok := request.Claims["email"]; ok {
					return Decision{Scopes: request.Scopes, Lifetime: time.Minute}, nil
				}
				return Decision{Pending: &PendingDecision{RequiredClaims: []string{"email"}}}, nil
			}
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	postToken := func() *httptest.ResponseRecorder {
		t.Helper()
		body, err := json.Marshal(map[string]string{
			"resource_token": resourceToken, "agent_token": agentToken,
			"presented_token": accessServerPresentedToken(t, psKey, now, resourceToken, agentKey),
		})
		if err != nil {
			t.Fatal(err)
		}
		request := httptest.NewRequest(http.MethodPost, "https://as.example/token", bytes.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		if err := signaturekey.SignJWKSURIRequestWithOptions(request, psKey, "https://ps.example", aauth.PersonDiscoveryDocument, clock, signaturekey.SignOptions{
			AdditionalComponents: []string{"content-type", "content-digest"}, MaxBodyBytes: int64(len(body)),
		}); err != nil {
			t.Fatal(err)
		}
		response := httptest.NewRecorder()
		server.Handler().ServeHTTP(response, request)
		return response
	}
	for _, bad := range []string{"sub", "payment-and-claims", "duplicate"} {
		mode = bad
		response := postToken()
		if response.Code != http.StatusInternalServerError {
			t.Fatalf("%s status = %d body = %s", bad, response.Code, response.Body.String())
		}
	}
	mode = "claims"
	response := postToken()
	if response.Code != http.StatusAccepted || response.Header().Get("AAuth-Requirement") != "requirement=claims" || !bytes.Contains(response.Body.Bytes(), []byte(`"email"`)) {
		t.Fatalf("claims wait = %d %q %s", response.Code, response.Header().Get("AAuth-Requirement"), response.Body.String())
	}
	location := response.Header().Get("Location")
	postClaims := func(payload string) *httptest.ResponseRecorder {
		t.Helper()
		request := httptest.NewRequest(http.MethodPost, location, bytes.NewReader([]byte(payload)))
		request.Header.Set("Content-Type", "application/json")
		if err := signaturekey.SignJWKSURIRequestWithOptions(request, psKey, "https://ps.example", aauth.PersonDiscoveryDocument, clock, signaturekey.SignOptions{
			AdditionalComponents: []string{"content-type", "content-digest"}, MaxBodyBytes: int64(len(payload)),
		}); err != nil {
			t.Fatal(err)
		}
		response := httptest.NewRecorder()
		server.Handler().ServeHTTP(response, request)
		return response
	}
	rejected := postClaims(`{"sub":"person-1","email":"a@example.com"}`)
	if rejected.Code != http.StatusBadRequest {
		t.Fatalf("sub claims status = %d %s", rejected.Code, rejected.Body.String())
	}
	granted := postClaims(`{"email":"a@example.com","nickname":"ignored"}`)
	if granted.Code != http.StatusOK {
		t.Fatalf("claims grant = %d %s", granted.Code, granted.Body.String())
	}
	if string(seen["email"]) != `"a@example.com"` {
		t.Fatalf("policy claims = %#v", seen)
	}
	if _, present := seen["nickname"]; present || len(seen) != 1 {
		t.Fatalf("policy retained unrequested claims: %#v", seen)
	}
}

type claimsTestStore struct {
	mu      sync.Mutex
	records map[string]PendingAuthorizationRecord
}

func newClaimsTestStore() *claimsTestStore {
	return &claimsTestStore{records: map[string]PendingAuthorizationRecord{}}
}

func cloneClaimsRecord(record PendingAuthorizationRecord) PendingAuthorizationRecord {
	record.Request = append([]byte(nil), record.Request...)
	record.RequiredClaims = append([]string(nil), record.RequiredClaims...)
	if record.Claims != nil {
		cloned := make(map[string]json.RawMessage, len(record.Claims))
		for name, value := range record.Claims {
			cloned[name] = append(json.RawMessage(nil), value...)
		}
		record.Claims = cloned
	}
	return record
}

func (s *claimsTestStore) CreateAccessAuthorization(_ context.Context, record PendingAuthorizationRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.records[record.ID]; ok || record.ID == "" || record.Revision != 1 || record.Gone {
		return ErrPendingAuthorizationConflict
	}
	s.records[record.ID] = cloneClaimsRecord(record)
	return nil
}

func (s *claimsTestStore) LoadAccessAuthorization(_ context.Context, id string) (PendingAuthorizationRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.records[id]
	if !ok {
		return PendingAuthorizationRecord{}, ErrPendingAuthorizationConflict
	}
	return cloneClaimsRecord(record), nil
}

func (s *claimsTestStore) ReplaceAccessAuthorization(_ context.Context, before, after PendingAuthorizationRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	immutable := after
	immutable.Revision = before.Revision
	immutable.NextPollAt = before.NextPollAt
	immutable.Gone = before.Gone
	immutable.Claims = before.Claims
	immutable.RequiredClaims = before.RequiredClaims
	current, ok := s.records[before.ID]
	if !ok || !reflect.DeepEqual(current, before) || !reflect.DeepEqual(immutable, before) || after.Revision != before.Revision+1 || before.Gone {
		return ErrPendingAuthorizationConflict
	}
	s.records[before.ID] = cloneClaimsRecord(after)
	return nil
}
