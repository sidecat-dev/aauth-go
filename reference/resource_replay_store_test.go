package reference_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/reference"
)

type expectedAuthorizationStateStore interface {
	Load(context.Context) ([]byte, error)
	Replace(context.Context, []byte) error
}

func TestDeferredCapableRolesExposeOneExplicitAuthorizationStateStore(t *testing.T) {
	t.Parallel()

	storeType := reflect.TypeOf((*expectedAuthorizationStateStore)(nil)).Elem()
	for _, config := range []struct {
		name   string
		typeOf reflect.Type
	}{
		{name: "resource", typeOf: reflect.TypeOf(reference.ResourceConfig{})},
		{name: "person server", typeOf: reflect.TypeOf(reference.PersonServerConfig{})},
		{name: "access server", typeOf: reflect.TypeOf(reference.AccessServerConfig{})},
		{name: "agent", typeOf: reflect.TypeOf(reference.AgentConfig{})},
	} {
		t.Run(config.name, func(t *testing.T) {
			field, exists := config.typeOf.FieldByName("AuthorizationStore")
			if !exists {
				t.Fatal("current deferred-capable config has no AuthorizationStore")
			}
			if !field.Type.Implements(storeType) {
				t.Fatalf("AuthorizationStore type = %v, want AuthorizationStateStore contract", field.Type)
			}
		})
	}
}

func TestDeferredCapableConstructorsRequireAuthorizationStateStore(t *testing.T) {
	now := time.Date(2026, 8, 28, 18, 15, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	key := referenceTestSigningKey(t, "authorization-state-key")
	resolver := aauth.StaticKeyResolver{}
	replayStore, err := reference.NewMemoryProofReplayStore(clock, 8)
	if err != nil {
		t.Fatal(err)
	}

	_, err = reference.NewResource(reference.ResourceConfig{
		Identifier: "https://resource.example", AccessMode: aauth.AccessModeSessionToken,
		KeyResolver: resolver, Clock: clock, NewID: func() string { return "id" },
		Scopes: []string{"operation.a"}, RequiredScopesForRequest: referenceTestRequiredResourceScopes("operation.a"),
		ReplayStore: replayStore,
		AuthorizationPolicy: func(context.Context, aauth.AuthorizationRequest) (aauth.AuthorizationDecision, error) {
			return aauth.AuthorizationDecision{Subject: "person", Scope: []string{"operation.a"}}, nil
		},
		Operation: func(context.Context, aauth.AuthorizedRequest) (any, error) { return nil, nil },
	})
	if err == nil || !strings.Contains(err.Error(), "authorization state store") {
		t.Fatalf("session resource missing store error = %v", err)
	}

	_, err = reference.NewPersonServer(reference.PersonServerConfig{
		Identifier: "https://ps.example", SigningKey: key, KeyResolver: resolver, Clock: clock,
		NewID: func() string { return "id" }, PersonTokenStore: discardPersonTokenStore{},
		MissionIssuanceStore: discardMissionIssuanceStore{},
		PersonTokenPolicy: func(context.Context, aauth.PersonTokenRequest) (aauth.PersonTokenDecision, error) {
			return aauth.PersonTokenDecision{Subject: "person", Lifetime: time.Minute}, nil
		},
		CurrentMissionPolicy: func(context.Context, aauth.MissionEvaluation) (aauth.MissionDecision, error) {
			return aauth.MissionDecision{Description: "current"}, nil
		},
		AuthorizationPolicy: func(context.Context, aauth.AuthorizationRequest) (aauth.AuthorizationDecision, error) {
			return aauth.AuthorizationDecision{Subject: "person", Scope: []string{"operation.a"}}, nil
		},
	})
	if err == nil || !strings.Contains(err.Error(), "authorization state store") {
		t.Fatalf("person server missing store error = %v", err)
	}

	_, err = reference.NewAccessServer(reference.AccessServerConfig{
		Identifier: "https://as.example", SigningKey: key, KeyResolver: resolver, Clock: clock,
		NewID:               func() string { return "id" },
		TrustedPersonServer: func(context.Context, string) error { return nil },
		AuthorizationPolicy: func(context.Context, aauth.AuthorizationRequest) (aauth.AuthorizationDecision, error) {
			return aauth.AuthorizationDecision{Subject: "person", Scope: []string{"operation.a"}}, nil
		},
	})
	if err == nil || !strings.Contains(err.Error(), "authorization state store") {
		t.Fatalf("access server missing store error = %v", err)
	}

	_, err = reference.NewAgent(reference.AgentConfig{
		Identifier: "aauth:agent@ap.example", SigningKey: key, AgentToken: "agent-token",
		KeyResolver: resolver, HTTPClient: &http.Client{}, Clock: clock,
	})
	if err == nil || !strings.Contains(err.Error(), "authorization state store") {
		t.Fatalf("agent missing store error = %v", err)
	}
}

type discardPersonTokenStore struct{}

func (discardPersonTokenStore) Commit(context.Context, reference.PersonTokenRecord) error { return nil }

func (discardPersonTokenStore) Load(context.Context, string, string) (reference.PersonTokenRecord, error) {
	return reference.PersonTokenRecord{}, reference.ErrPersonTokenNotFound
}

type discardMissionIssuanceStore struct{}

func (discardMissionIssuanceStore) Commit(context.Context, reference.MissionIssuanceRecord) error {
	return nil
}

func (discardMissionIssuanceStore) Load(context.Context, string) (reference.MissionIssuanceRecord, error) {
	return reference.MissionIssuanceRecord{}, reference.ErrMissionIssuanceNotFound
}

func TestCurrentProtectedResourceDurablyConsumesExactProof(t *testing.T) {
	now := time.Date(2026, 8, 28, 18, 30, 0, 987654321, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	personKey := referenceTestSigningKey(t, "person-key")
	agentKey := referenceTestSigningKey(t, "agent-key")
	resourceKey := referenceTestSigningKey(t, "resource-key")
	resolver := aauth.StaticKeyResolver{
		"https://ps.example": {personKey.ID(): personKey.PublicJWK()},
	}
	authToken, err := aauth.MintAuthToken(personKey, aauth.AuthTokenClaims{
		Issuer:       "https://ps.example",
		DWK:          aauth.PersonDiscoveryDocument,
		Audience:     "https://resource.example",
		JTI:          "auth-token-1",
		Confirmation: aauth.Confirmation{JWK: agentKey.PublicJWK()},
		IssuedAt:     now.Unix(),
		ExpiresAt:    now.Add(5 * time.Minute).Unix(),
		Subject:      "person-7",
		Scope:        "operation.a",
		PersonServer: "https://ps.example",
	})
	if err != nil {
		t.Fatal(err)
	}

	directory := filepath.Join(t.TempDir(), "proof-replays")
	replayStore := openTestProofReplayStore(t, directory, clock)
	operationCalls := 0
	policyCalls := 0
	var policyRequest aauth.AuthorizedRequest
	var operationRequest aauth.AuthorizedRequest
	newResource := func(store reference.ProofReplayStore) *reference.Resource {
		resource, err := reference.NewResource(reference.ResourceConfig{
			Identifier:   "https://resource.example",
			AccessMode:   aauth.AccessModeAuthToken,
			PersonServer: "https://ps.example",
			SigningKey:   resourceKey,
			KeyResolver:  resolver,
			Clock:        clock,
			NewID:        func() string { return "resource-token" },
			Scopes:       []string{"operation.a", "operation.b"},
			ScopeDescriptions: map[string]string{
				"operation.a": "Perform operation A",
				"operation.b": "Perform operation B",
			},
			RequiredScopesForRequest: func(_ context.Context, request *http.Request) ([]string, error) {
				switch request.URL.Path {
				case "/a":
					return []string{"operation.a"}, nil
				case "/b":
					return []string{"operation.b"}, nil
				case "/deny":
					return []string{"operation.a"}, nil
				default:
					return nil, errors.New("operation is not mapped")
				}
			},
			ReplayStore: store,
			ProtectedAuthorizationPolicy: func(_ context.Context, request aauth.AuthorizedRequest) error {
				policyCalls++
				policyRequest = request
				policyRequest.Scope = append([]string(nil), request.Scope...)
				policyRequest.Body = append([]byte(nil), request.Body...)
				if request.Path == "/deny" {
					return errors.New("secret principal-policy detail")
				}
				request.Scope[0] = "policy-mutated-scope"
				if len(request.Body) != 0 {
					request.Body[0] = 'X'
				}
				return nil
			},
			Operation: func(_ context.Context, request aauth.AuthorizedRequest) (any, error) {
				operationCalls++
				operationRequest = request
				return map[string]string{"status": "applied"}, nil
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		return resource
	}
	resource := newResource(replayStore)
	body := []byte(`{"value":1}`)
	exactProof := signedCurrentProtectedRequest(t, agentKey, authToken, clock, "/a", body, "proof-a")
	verified, err := aauth.VerifyRequest(
		context.Background(),
		cloneProtectedRequest(exactProof, body),
		resolver,
		clock,
		aauth.VerifyRequestOptions{
			RequiredComponents:     []string{"content-type"},
			AllowedCredentialTypes: []string{aauth.AuthTokenType},
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	first := serveProtected(resource, cloneProtectedRequest(exactProof, body))
	if first.Code != http.StatusOK {
		t.Fatalf("first protected call = %d: %s", first.Code, first.Body.String())
	}
	if operationCalls != 1 || operationRequest.Agent != "" ||
		operationRequest.PersonServer != "https://ps.example" ||
		operationRequest.Subject != "person-7" ||
		operationRequest.AuthTokenIssuer != "https://ps.example" ||
		operationRequest.AuthTokenDWK != aauth.PersonDiscoveryDocument ||
		operationRequest.AuthTokenID != "auth-token-1" ||
		!operationRequest.AuthTokenIssuedAt.Equal(now.Truncate(time.Second)) ||
		!operationRequest.AuthTokenExpiresAt.Equal(now.Add(5*time.Minute).Truncate(time.Second)) ||
		operationRequest.ConfirmationKey != agentKey.PublicJWK() ||
		operationRequest.ProofReplayKey != verified.ReplayKey ||
		!operationRequest.ProofCreatedAt.Equal(verified.Created.UTC()) ||
		operationRequest.AuthToken != authToken ||
		operationRequest.Method != http.MethodPost || operationRequest.Path != "/a" ||
		operationRequest.ContentType != "application/json" ||
		strings.Join(operationRequest.Scope, " ") != "operation.a" {
		t.Fatalf("authorized operation context = %#v, verified = %#v", operationRequest, verified)
	}
	if policyCalls != 1 || policyRequest.AuthTokenIssuer != operationRequest.AuthTokenIssuer ||
		policyRequest.AuthTokenDWK != operationRequest.AuthTokenDWK ||
		policyRequest.AuthTokenID != operationRequest.AuthTokenID ||
		!policyRequest.AuthTokenIssuedAt.Equal(operationRequest.AuthTokenIssuedAt) ||
		!policyRequest.AuthTokenExpiresAt.Equal(operationRequest.AuthTokenExpiresAt) ||
		policyRequest.PersonServer != operationRequest.PersonServer ||
		policyRequest.Subject != operationRequest.Subject ||
		policyRequest.ConfirmationKey != operationRequest.ConfirmationKey ||
		policyRequest.ProofReplayKey != operationRequest.ProofReplayKey ||
		!policyRequest.ProofCreatedAt.Equal(operationRequest.ProofCreatedAt) ||
		policyRequest.AuthToken != operationRequest.AuthToken ||
		policyRequest.Method != operationRequest.Method || policyRequest.Path != operationRequest.Path ||
		policyRequest.ContentType != operationRequest.ContentType ||
		!bytes.Equal(policyRequest.Body, body) ||
		strings.Join(policyRequest.Scope, " ") != "operation.a" {
		t.Fatalf("protected policy context = %#v, operation = %#v", policyRequest, operationRequest)
	}
	decodedReplayKey, err := base64.RawURLEncoding.DecodeString(operationRequest.ProofReplayKey)
	if err != nil || len(decodedReplayKey) != 32 {
		t.Fatalf("operation replay key = %q, decoded bytes = %d, err = %v", operationRequest.ProofReplayKey, len(decodedReplayKey), err)
	}
	if !bytes.Equal(operationRequest.Body, body) {
		t.Fatalf("operation body = %q, want %q", operationRequest.Body, body)
	}

	tamperedMediaTypeProof := signedCurrentProtectedRequest(
		t, agentKey, authToken, clock, "/a", body, "proof-content-type-tamper",
	)
	tamperedMediaTypeProof.Header.Set("Content-Type", "application/cbor")
	tamperedMediaType := serveProtected(resource, tamperedMediaTypeProof)
	if tamperedMediaType.Code != http.StatusUnauthorized {
		t.Fatalf("tampered signed Content-Type = %d: %s", tamperedMediaType.Code, tamperedMediaType.Body.String())
	}
	if operationCalls != 1 || policyCalls != 1 {
		t.Fatalf("tampered signed Content-Type reached policy/operation: %d/%d", policyCalls, operationCalls)
	}

	duplicate := serveProtected(resource, cloneProtectedRequest(exactProof, body))
	assertReplayRefusal(t, duplicate)
	if operationCalls != 1 {
		t.Fatalf("duplicate proof reached operation: calls = %d", operationCalls)
	}

	if err := replayStore.Close(); err != nil {
		t.Fatal(err)
	}
	replayStore = openTestProofReplayStore(t, directory, clock)
	t.Cleanup(func() { _ = replayStore.Close() })
	resource = newResource(replayStore)
	afterReopen := serveProtected(resource, cloneProtectedRequest(exactProof, body))
	assertReplayRefusal(t, afterReopen)
	if operationCalls != 1 {
		t.Fatalf("reopened store admitted duplicate proof: calls = %d", operationCalls)
	}

	freshProof := signedCurrentProtectedRequest(t, agentKey, authToken, clock, "/a", body, "proof-a-fresh")
	fresh := serveProtected(resource, freshProof)
	if fresh.Code != http.StatusOK {
		t.Fatalf("fresh proof with same token and body = %d: %s", fresh.Code, fresh.Body.String())
	}
	if operationCalls != 2 {
		t.Fatalf("fresh proof operation calls = %d, want 2", operationCalls)
	}

	wrongPathProof := signedCurrentProtectedRequest(t, agentKey, authToken, clock, "/b", body, "proof-b")
	wrongPath := serveProtected(resource, wrongPathProof)
	if wrongPath.Code != http.StatusForbidden || !strings.Contains(wrongPath.Body.String(), `"error":"invalid_token"`) {
		t.Fatalf("operation A token on path B = %d: %s", wrongPath.Code, wrongPath.Body.String())
	}
	if operationCalls != 2 {
		t.Fatalf("wrong-path token reached operation: calls = %d", operationCalls)
	}

	failing := newResource(failingProofReplayStore{})
	storeFailureProof := signedCurrentProtectedRequest(t, agentKey, authToken, clock, "/a", body, "proof-store-failure")
	storeFailure := serveProtected(failing, storeFailureProof)
	if storeFailure.Code != http.StatusServiceUnavailable ||
		!strings.Contains(storeFailure.Body.String(), `"error":"proof_replay_unavailable"`) ||
		!strings.Contains(storeFailure.Body.String(), `"detail":"proof replay protection is temporarily unavailable"`) {
		t.Fatalf("replay store failure = %d: %s", storeFailure.Code, storeFailure.Body.String())
	}
	if strings.Contains(storeFailure.Body.String(), "/srv/aauth/private/replay-state.db") ||
		strings.Contains(storeFailure.Body.String(), "tenant-secret") {
		t.Fatalf("replay store failure leaked local custody detail: %s", storeFailure.Body.String())
	}
	if operationCalls != 2 {
		t.Fatalf("replay store failure reached operation: calls = %d", operationCalls)
	}
	if policyCalls != 2 {
		t.Fatalf("replay store failure or refused proof reached policy: calls = %d", policyCalls)
	}

	deniedProof := signedCurrentProtectedRequest(t, agentKey, authToken, clock, "/deny", body, "proof-policy-denied")
	denied := serveProtected(resource, deniedProof)
	wantDenial := `{"detail":"protected request was denied by resource policy","error":"invalid_token","status":403,"title":"Forbidden","type":"about:blank"}`
	if denied.Code != http.StatusForbidden || denied.Header().Get("Content-Type") != "application/problem+json" ||
		denied.Header().Get("Cache-Control") != "no-store" || denied.Body.String() != wantDenial ||
		strings.Contains(denied.Body.String(), "secret principal-policy detail") {
		t.Fatalf("protected policy denial = %d %q %#v", denied.Code, denied.Body.String(), denied.Header())
	}
	if policyCalls != 3 || operationCalls != 2 {
		t.Fatalf("protected policy denial calls policy/operation = %d/%d", policyCalls, operationCalls)
	}
}

func TestCurrentProtectedResourceRejectsRawUnsupportedExtensionTokensBeforePolicyReplayAndOperation(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 28, 21, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	accessKey, accessPrivate := rawReferenceTestSigningMaterial(t, "access-key")
	agentKey := referenceTestSigningKey(t, "agent-key")
	resourceKey := referenceTestSigningKey(t, "resource-key")
	resolver := aauth.StaticKeyResolver{
		"https://as.example": {accessKey.ID(): accessKey.PublicJWK()},
	}
	claims := aauth.AuthTokenClaims{
		Issuer:       "https://as.example",
		DWK:          aauth.AccessDiscoveryDocument,
		Audience:     "https://resource.example",
		JTI:          "conditional-auth-token",
		Confirmation: aauth.Confirmation{JWK: agentKey.PublicJWK()},
		IssuedAt:     now.Unix(),
		ExpiresAt:    now.Add(5 * time.Minute).Unix(),
		Subject:      "person-7",
		Scope:        "operation.a",
		PersonServer: "https://ps.example",
	}
	replayStore := &countingProofReplayStore{}
	operationCalls := 0
	policyCalls := 0
	resource, err := reference.NewResource(reference.ResourceConfig{
		Identifier:        "https://resource.example",
		AccessMode:        aauth.AccessModeAuthToken,
		AccessServer:      "https://as.example",
		SigningKey:        resourceKey,
		KeyResolver:       resolver,
		Clock:             clock,
		NewID:             func() string { return "resource-token" },
		Scopes:            []string{"operation.a"},
		ScopeDescriptions: map[string]string{"operation.a": "Perform operation A"},
		RequiredScopesForRequest: func(context.Context, *http.Request) ([]string, error) {
			return []string{"operation.a"}, nil
		},
		ReplayStore: replayStore,
		ProtectedAuthorizationPolicy: func(context.Context, aauth.AuthorizedRequest) error {
			policyCalls++
			return nil
		},
		Operation: func(context.Context, aauth.AuthorizedRequest) (any, error) {
			operationCalls++
			return nil, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	for index, test := range []struct {
		member string
		value  string
	}{
		{"r3_uri", `"https://resource.example/r3/document"`},
		{"r3_s256", `"digest"`},
		{"r3_granted", `{}`},
		{"r3_per_call", `{}`},
		{"r3_conditional", `{}`},
		{"budget", `{"amount":100,"unit":"USD","decimals":2}`},
		{"budget_consumed", `[{"jti":"auth-1","consumed":10}]`},
	} {
		authToken := signRawReferenceAuthToken(t, accessKey, accessPrivate, claims, test.member, test.value)
		request := signedCurrentProtectedRequest(t, agentKey, authToken, clock, "/a", nil, fmt.Sprintf("unsupported-extension-%d", index))
		response := serveProtected(resource, request)
		if response.Code != http.StatusUnauthorized || !strings.Contains(response.Body.String(), `"error":"invalid_jwt"`) {
			t.Fatalf("raw unsupported %s token = %d: %s", test.member, response.Code, response.Body.String())
		}
		if !strings.Contains(response.Body.String(), test.member) {
			t.Fatalf("raw unsupported %s refusal did not name the member: %s", test.member, response.Body.String())
		}
	}
	if replayStore.calls != 0 || policyCalls != 0 || operationCalls != 0 {
		t.Fatalf("raw unsupported extension tokens reached replay/policy/operation = %d/%d/%d", replayStore.calls, policyCalls, operationCalls)
	}
}

type countingProofReplayStore struct{ calls int }

func (store *countingProofReplayStore) Consume(context.Context, string, time.Time) error {
	store.calls++
	return nil
}

func rawReferenceTestSigningMaterial(t *testing.T, id string) (aauth.SigningKey, ed25519.PrivateKey) {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := aauth.NewEd25519SigningKey(id, private)
	if err != nil {
		t.Fatal(err)
	}
	return key, private
}

func signRawReferenceAuthToken(
	t *testing.T,
	key aauth.SigningKey,
	private ed25519.PrivateKey,
	claims aauth.AuthTokenClaims,
	claimName string,
	claimValue string,
) string {
	t.Helper()
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	payload = append(payload[:len(payload)-1], []byte(`,"`+claimName+`":`+claimValue)...)
	payload = append(payload, '}')
	header, err := json.Marshal(aauth.TokenHeader{
		Algorithm: aauth.Ed25519Algorithm,
		Type:      aauth.AuthTokenType,
		KeyID:     key.ID(),
	})
	if err != nil {
		t.Fatal(err)
	}
	signingInput := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, []byte(signingInput)))
}

func TestCurrentResourceRequiresCanonicalRequestScopeMapping(t *testing.T) {
	now := time.Date(2026, 8, 28, 19, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	personKey := referenceTestSigningKey(t, "person-key")
	agentKey := referenceTestSigningKey(t, "agent-key")
	resourceKey := referenceTestSigningKey(t, "resource-key")
	resolver := aauth.StaticKeyResolver{
		"https://ps.example": {personKey.ID(): personKey.PublicJWK()},
	}
	authToken, err := aauth.MintAuthToken(personKey, aauth.AuthTokenClaims{
		Issuer:       "https://ps.example",
		DWK:          aauth.PersonDiscoveryDocument,
		Audience:     "https://resource.example",
		JTI:          "auth-token-1",
		Confirmation: aauth.Confirmation{JWK: agentKey.PublicJWK()},
		IssuedAt:     now.Unix(),
		ExpiresAt:    now.Add(5 * time.Minute).Unix(),
		Subject:      "person-7",
		Scope:        "operation.a operation.b",
		PersonServer: "https://ps.example",
	})
	if err != nil {
		t.Fatal(err)
	}

	for index, test := range []struct {
		name   string
		mapped []string
	}{
		{name: "empty", mapped: nil},
		{name: "duplicate", mapped: []string{"operation.a", "operation.a"}},
		{name: "outside issuance allowlist", mapped: []string{"operation.c"}},
		{name: "noncanonical whitespace", mapped: []string{" operation.a"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			store, err := reference.NewMemoryProofReplayStore(clock, 8)
			if err != nil {
				t.Fatal(err)
			}
			operationCalls := 0
			resource, err := reference.NewResource(reference.ResourceConfig{
				Identifier:   "https://resource.example",
				AccessMode:   aauth.AccessModeAuthToken,
				PersonServer: "https://ps.example",
				SigningKey:   resourceKey,
				KeyResolver:  resolver,
				Clock:        clock,
				NewID:        func() string { return "resource-token" },
				Scopes:       []string{"operation.a", "operation.b"},
				ScopeDescriptions: map[string]string{
					"operation.a": "Perform operation A",
					"operation.b": "Perform operation B",
				},
				RequiredScopesForRequest: func(context.Context, *http.Request) ([]string, error) {
					return append([]string(nil), test.mapped...), nil
				},
				ReplayStore: store,
				ProtectedAuthorizationPolicy: func(context.Context, aauth.AuthorizedRequest) error {
					return nil
				},
				Operation: func(context.Context, aauth.AuthorizedRequest) (any, error) {
					operationCalls++
					return nil, nil
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			request := signedCurrentProtectedRequest(t, agentKey, authToken, clock, "/a", nil, "scope-"+string(rune('a'+index)))
			response := serveProtected(resource, request)
			if response.Code != http.StatusInternalServerError || !strings.Contains(response.Body.String(), `"error":"scope_mapping_failed"`) {
				t.Fatalf("invalid scope mapping = %d: %s", response.Code, response.Body.String())
			}
			if operationCalls != 0 {
				t.Fatalf("invalid scope mapping reached operation: calls = %d", operationCalls)
			}
		})
	}
}

func TestResourceRequiresExplicitProofReplayStoreAndCurrentScopeMapper(t *testing.T) {
	now := time.Date(2026, 8, 28, 19, 30, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	resourceKey := referenceTestSigningKey(t, "resource-key")
	config := reference.ResourceConfig{
		Identifier:        "https://resource.example",
		AccessMode:        aauth.AccessModeAuthToken,
		PersonServer:      "https://ps.example",
		SigningKey:        resourceKey,
		KeyResolver:       aauth.StaticKeyResolver{},
		Clock:             clock,
		NewID:             func() string { return "id" },
		Scopes:            []string{"operation.a"},
		ScopeDescriptions: map[string]string{"operation.a": "Perform operation A"},
		RequiredScopesForRequest: func(context.Context, *http.Request) ([]string, error) {
			return []string{"operation.a"}, nil
		},
		ProtectedAuthorizationPolicy: func(context.Context, aauth.AuthorizedRequest) error {
			return nil
		},
		Operation: func(context.Context, aauth.AuthorizedRequest) (any, error) { return nil, nil },
	}
	if _, err := reference.NewResource(config); err == nil || !strings.Contains(err.Error(), "replay store") {
		t.Fatalf("NewResource without replay store error = %v", err)
	}
	store, err := reference.NewMemoryProofReplayStore(clock, 8)
	if err != nil {
		t.Fatal(err)
	}
	config.ReplayStore = store
	config.RequiredScopesForRequest = nil
	if _, err := reference.NewResource(config); err == nil || !strings.Contains(err.Error(), "required-scope mapper") {
		t.Fatalf("NewResource without required-scope mapper error = %v", err)
	}
	config.RequiredScopesForRequest = func(context.Context, *http.Request) ([]string, error) {
		return []string{"operation.a"}, nil
	}
	config.ProtectedAuthorizationPolicy = nil
	if _, err := reference.NewResource(config); err == nil || !strings.Contains(err.Error(), "protected authorization policy") {
		t.Fatalf("NewResource without protected authorization policy error = %v", err)
	}
}

func TestCurrentAuthTokenResourceRequiresExactScopeDescriptionsAndPublishesDeterministically(t *testing.T) {
	now := time.Date(2026, 8, 28, 19, 40, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	resourceKey := referenceTestSigningKey(t, "resource-key")
	store, err := reference.NewMemoryProofReplayStore(clock, 8)
	if err != nil {
		t.Fatal(err)
	}
	base := reference.ResourceConfig{
		Identifier:   "https://resource.example",
		AccessMode:   aauth.AccessModeAuthToken,
		PersonServer: "https://ps.example",
		SigningKey:   resourceKey,
		KeyResolver:  aauth.StaticKeyResolver{},
		Clock:        clock,
		NewID:        func() string { return "id" },
		Scopes:       []string{"operation.b", "operation.a"},
		RequiredScopesForRequest: func(context.Context, *http.Request) ([]string, error) {
			return []string{"operation.a"}, nil
		},
		ReplayStore: store,
		ProtectedAuthorizationPolicy: func(context.Context, aauth.AuthorizedRequest) error {
			return nil
		},
		Operation: func(context.Context, aauth.AuthorizedRequest) (any, error) { return nil, nil },
	}
	for _, test := range []struct {
		name         string
		descriptions map[string]string
	}{
		{name: "missing", descriptions: map[string]string{"operation.a": "Perform operation A"}},
		{name: "extra", descriptions: map[string]string{
			"operation.a": "Perform operation A", "operation.b": "Perform operation B", "operation.c": "Unexpected",
		}},
		{name: "mismatched key", descriptions: map[string]string{
			"operation.a": "Perform operation A", "operation.c": "Perform operation B",
		}},
		{name: "empty description", descriptions: map[string]string{
			"operation.a": "Perform operation A", "operation.b": "",
		}},
		{name: "noncanonical description", descriptions: map[string]string{
			"operation.a": "Perform operation A", "operation.b": " Perform operation B",
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			config := base
			config.ScopeDescriptions = test.descriptions
			if _, err := reference.NewResource(config); err == nil || !strings.Contains(err.Error(), "scope descriptions") {
				t.Fatalf("NewResource scope descriptions error = %v", err)
			}
		})
	}

	descriptions := map[string]string{
		"operation.a": "Perform operation A",
		"operation.b": "Perform operation B",
	}
	base.ScopeDescriptions = descriptions
	resource, err := reference.NewResource(base)
	if err != nil {
		t.Fatal(err)
	}
	descriptions["operation.a"] = "mutated after construction"
	descriptions["operation.c"] = "also mutated"
	first := httptest.NewRecorder()
	resource.Handler().ServeHTTP(first, httptest.NewRequest(http.MethodGet, "https://resource.example/.well-known/aauth-resource.json", nil))
	second := httptest.NewRecorder()
	resource.Handler().ServeHTTP(second, httptest.NewRequest(http.MethodGet, "https://resource.example/.well-known/aauth-resource.json", nil))
	if first.Code != http.StatusOK || second.Code != http.StatusOK || first.Body.String() != second.Body.String() {
		t.Fatalf("metadata status/body = %d/%d %q/%q", first.Code, second.Code, first.Body.String(), second.Body.String())
	}
	wantDescriptions := `"scope_descriptions":{"operation.a":"Perform operation A","operation.b":"Perform operation B"}`
	if !strings.Contains(first.Body.String(), wantDescriptions) {
		t.Fatalf("metadata scope descriptions are not exact and deterministic: %s", first.Body.String())
	}
}

func TestResourceRequiresExplicitCurrentAccessMode(t *testing.T) {
	now := time.Date(2026, 8, 28, 19, 45, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	resourceKey := referenceTestSigningKey(t, "resource-key")
	store, err := reference.NewMemoryProofReplayStore(clock, 8)
	if err != nil {
		t.Fatal(err)
	}
	_, err = reference.NewResource(reference.ResourceConfig{
		Identifier:        "https://resource.example",
		PersonServer:      "https://ps.example",
		SigningKey:        resourceKey,
		KeyResolver:       aauth.StaticKeyResolver{},
		Clock:             clock,
		NewID:             func() string { return "id" },
		Scopes:            []string{"operation.a"},
		ScopeDescriptions: map[string]string{"operation.a": "Perform operation A"},
		RequiredScopesForRequest: func(context.Context, *http.Request) ([]string, error) {
			return []string{"operation.a"}, nil
		},
		ReplayStore: store,
		Operation:   func(context.Context, aauth.AuthorizedRequest) (any, error) { return nil, nil },
	})
	if err == nil || !strings.Contains(err.Error(), "access mode is required") {
		t.Fatalf("NewResource without explicit access mode error = %v", err)
	}
}

func TestFileProofReplayStoreRejectsCorruptAndUnsafeCustody(t *testing.T) {
	now := time.Date(2026, 8, 28, 20, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })

	t.Run("corrupt state", func(t *testing.T) {
		directory := filepath.Join(t.TempDir(), "proof-replays")
		store := openTestProofReplayStore(t, directory, clock)
		if err := store.Close(); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(directory, "state.json"), []byte(`{"schema":"wrong","entries":[]}`), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := reference.OpenFileProofReplayStore(testProofReplayStoreConfig(directory, clock))
		if !errors.Is(err, reference.ErrProofReplayStoreIntegrity) {
			t.Fatalf("corrupt state error = %v", err)
		}
	})

	t.Run("noncanonical state", func(t *testing.T) {
		directory := filepath.Join(t.TempDir(), "proof-replays")
		store := openTestProofReplayStore(t, directory, clock)
		if err := store.Close(); err != nil {
			t.Fatal(err)
		}
		body := []byte(`{"entries":[],"schema":"aauth.reference.proof-replay-store"}`)
		if err := os.WriteFile(filepath.Join(directory, "state.json"), body, 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := reference.OpenFileProofReplayStore(testProofReplayStoreConfig(directory, clock))
		if !errors.Is(err, reference.ErrProofReplayStoreIntegrity) {
			t.Fatalf("noncanonical state error = %v", err)
		}
	})

	t.Run("unsafe state permissions", func(t *testing.T) {
		directory := filepath.Join(t.TempDir(), "proof-replays")
		store := openTestProofReplayStore(t, directory, clock)
		if err := store.Close(); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(filepath.Join(directory, "state.json"), 0o644); err != nil {
			t.Fatal(err)
		}
		_, err := reference.OpenFileProofReplayStore(testProofReplayStoreConfig(directory, clock))
		if !errors.Is(err, reference.ErrProofReplayStoreUnsafe) {
			t.Fatalf("unsafe state error = %v", err)
		}
	})

	t.Run("symlinked custody directory", func(t *testing.T) {
		parent := t.TempDir()
		realDirectory := filepath.Join(parent, "real")
		if err := os.Mkdir(realDirectory, 0o700); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(parent, "link")
		if err := os.Symlink(realDirectory, link); err != nil {
			t.Fatal(err)
		}
		_, err := reference.OpenFileProofReplayStore(testProofReplayStoreConfig(link, clock))
		if !errors.Is(err, reference.ErrProofReplayStoreUnsafe) {
			t.Fatalf("symlinked directory error = %v", err)
		}
	})

	t.Run("second writer", func(t *testing.T) {
		directory := filepath.Join(t.TempDir(), "proof-replays")
		store := openTestProofReplayStore(t, directory, clock)
		defer store.Close()
		_, err := reference.OpenFileProofReplayStore(testProofReplayStoreConfig(directory, clock))
		if !errors.Is(err, reference.ErrProofReplayStoreLocked) {
			t.Fatalf("second writer error = %v", err)
		}
	})
}

func TestProofReplayStoresAtomicallyConsumeOneExactProof(t *testing.T) {
	now := time.Date(2026, 8, 28, 20, 30, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	for _, test := range []struct {
		name string
		open func(*testing.T) (reference.ProofReplayStore, func())
	}{
		{
			name: "memory",
			open: func(t *testing.T) (reference.ProofReplayStore, func()) {
				t.Helper()
				store, err := reference.NewMemoryProofReplayStore(clock, 8)
				if err != nil {
					t.Fatal(err)
				}
				return store, func() {}
			},
		},
		{
			name: "file",
			open: func(t *testing.T) (reference.ProofReplayStore, func()) {
				t.Helper()
				store := openTestProofReplayStore(t, filepath.Join(t.TempDir(), "proof-replays"), clock)
				return store, func() {
					if err := store.Close(); err != nil {
						t.Error(err)
					}
				}
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			store, closeStore := test.open(t)
			defer closeStore()
			replayKey := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x51}, 32))
			ready := make(chan struct{})
			results := make(chan error, 2)
			for range 2 {
				go func() {
					<-ready
					results <- store.Consume(context.Background(), replayKey, now.Add(time.Minute))
				}()
			}
			close(ready)
			var admitted, replayed int
			for range 2 {
				err := <-results
				switch {
				case err == nil:
					admitted++
				case errors.Is(err, reference.ErrProofReplay):
					replayed++
				default:
					t.Fatalf("concurrent Consume error = %v", err)
				}
			}
			if admitted != 1 || replayed != 1 {
				t.Fatalf("concurrent Consume admitted/replayed = %d/%d, want 1/1", admitted, replayed)
			}
		})
	}
}

type failingProofReplayStore struct{}

func (failingProofReplayStore) Consume(context.Context, string, time.Time) error {
	return errors.New("open /srv/aauth/private/replay-state.db: tenant-secret custody failure")
}

func openTestProofReplayStore(t *testing.T, directory string, clock aauth.Clock) *reference.FileProofReplayStore {
	t.Helper()
	store, err := reference.OpenFileProofReplayStore(testProofReplayStoreConfig(directory, clock))
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func testProofReplayStoreConfig(directory string, clock aauth.Clock) reference.FileProofReplayStoreConfig {
	return reference.FileProofReplayStoreConfig{
		Directory:  directory,
		Clock:      clock,
		MaxEntries: 32,
		MaxBytes:   16 << 10,
	}
}

func referenceTestResourceReplayStore(t *testing.T, clock aauth.Clock) reference.ProofReplayStore {
	t.Helper()
	store, err := reference.NewMemoryProofReplayStore(clock, 1024)
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func referenceTestAuthorizationStateStore(t *testing.T) reference.AuthorizationStateStore {
	t.Helper()
	store, err := reference.NewMemoryAuthorizationStateStore(1024, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func referenceTestRequiredResourceScopes(scopes ...string) func(context.Context, *http.Request) ([]string, error) {
	return func(context.Context, *http.Request) ([]string, error) {
		return append([]string(nil), scopes...), nil
	}
}

func signedCurrentProtectedRequest(
	t *testing.T,
	key aauth.SigningKey,
	authToken string,
	clock aauth.Clock,
	path string,
	body []byte,
	nonce string,
) *http.Request {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, "https://resource.example"+path, bytes.NewReader(body))
	if len(body) != 0 {
		request.Header.Set("Content-Type", "application/json")
	}
	if err := aauth.SignRequestWithOptions(request, key, authToken, clock, aauth.SignRequestOptions{Nonce: nonce}); err != nil {
		t.Fatal(err)
	}
	return request
}

func cloneProtectedRequest(request *http.Request, body []byte) *http.Request {
	cloned := request.Clone(context.Background())
	cloned.Body = io.NopCloser(bytes.NewReader(body))
	cloned.ContentLength = int64(len(body))
	return cloned
}

func serveProtected(resource *reference.Resource, request *http.Request) *httptest.ResponseRecorder {
	response := httptest.NewRecorder()
	resource.Handler().ServeHTTP(response, request)
	return response
}

func assertReplayRefusal(t *testing.T, response *httptest.ResponseRecorder) {
	t.Helper()
	if response.Code != http.StatusUnauthorized || !strings.Contains(response.Body.String(), `"error":"invalid_signature"`) {
		t.Fatalf("proof replay response = %d: %s", response.Code, response.Body.String())
	}
}
