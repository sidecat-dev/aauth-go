package personserver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

const (
	presentedProviderID = "https://provider.example"
	presentedPersonID   = "https://person.example"
	presentedResourceID = "https://resource.example"
	presentedAccessID   = "https://access.example"
	presentedAgentID    = "aauth:planner@provider.example"
)

// presentedTokenProtocol holds the parties of one token request whose
// presented_token the Person Server has to verify for itself.
type presentedTokenProtocol struct {
	now         time.Time
	clock       aauth.Clock
	providerKey jose.SigningKey
	personKey   jose.SigningKey
	resourceKey jose.SigningKey
	accessKey   jose.SigningKey
	agentKey    jose.SigningKey
	resolver    signaturekey.StaticKeyResolver
	agentToken  string
	agentJKT    string
	store       *memoryTokenStore
}

func newPresentedTokenProtocol(t *testing.T) *presentedTokenProtocol {
	t.Helper()
	protocol := &presentedTokenProtocol{
		now:         time.Date(2026, 10, 3, 18, 0, 0, 0, time.UTC),
		providerKey: personServerTestKey(t, "presented-provider"),
		personKey:   personServerTestKey(t, "presented-person"),
		resourceKey: personServerTestKey(t, "presented-resource"),
		accessKey:   personServerTestKey(t, "presented-access"),
		agentKey:    personServerTestKey(t, "presented-agent"),
		store:       newMemoryTokenStore(),
	}
	protocol.clock = aauth.ClockFunc(func() time.Time { return protocol.now })
	protocol.resolver = signaturekey.StaticKeyResolver{
		{Issuer: presentedProviderID, DiscoveryDocument: aauth.AgentDiscoveryDocument, KeyID: protocol.providerKey.ID()}:    protocol.providerKey.PublicJWK(),
		{Issuer: presentedPersonID, DiscoveryDocument: aauth.PersonDiscoveryDocument, KeyID: protocol.personKey.ID()}:       protocol.personKey.PublicJWK(),
		{Issuer: presentedResourceID, DiscoveryDocument: aauth.ResourceDiscoveryDocument, KeyID: protocol.resourceKey.ID()}: protocol.resourceKey.PublicJWK(),
		{Issuer: presentedAccessID, DiscoveryDocument: aauth.AccessDiscoveryDocument, KeyID: protocol.accessKey.ID()}:       protocol.accessKey.PublicJWK(),
	}
	var err error
	protocol.agentToken, err = aauth.MintAgentToken(presentedProviderID, protocol.providerKey, aauth.AgentTokenRequest{
		Agent: presentedAgentID, PersonServer: presentedPersonID,
		PublicKey: protocol.agentKey.PublicJWK(), Lifetime: time.Hour,
	}, protocol.now, "presented-agent-token")
	if err != nil {
		t.Fatal(err)
	}
	protocol.agentJKT, err = protocol.agentKey.PublicJWK().Thumbprint()
	if err != nil {
		t.Fatal(err)
	}
	return protocol
}

func (protocol *presentedTokenProtocol) personToken(t *testing.T, jti string, expiresAt time.Time) string {
	t.Helper()
	compact, err := aauth.MintPersonToken(protocol.personKey, aauth.PersonTokenClaims{
		Issuer: presentedPersonID, DWK: aauth.PersonDiscoveryDocument, Audience: presentedResourceID,
		Subject: "person-123", Confirmation: aauth.Confirmation{JWK: protocol.agentKey.PublicJWK()},
		JTI: jti, IssuedAt: protocol.now.Add(-time.Minute).Unix(), ExpiresAt: expiresAt.Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return compact
}

// authToken mints the auth token an agent presents on step-up: issuer is the
// Person Server in the three-party flow and the Access Server otherwise.
func (protocol *presentedTokenProtocol) authToken(t *testing.T, issuer, jti string, expiresAt time.Time) string {
	t.Helper()
	key, document := protocol.personKey, aauth.PersonDiscoveryDocument
	if issuer == presentedAccessID {
		key, document = protocol.accessKey, aauth.AccessDiscoveryDocument
	}
	compact, err := aauth.MintAuthToken(key, aauth.AuthTokenClaims{
		Issuer: issuer, DWK: document, Audience: presentedResourceID, JTI: jti,
		Confirmation: aauth.Confirmation{JWK: protocol.agentKey.PublicJWK()},
		IssuedAt:     protocol.now.Add(-time.Minute).Unix(), ExpiresAt: expiresAt.Unix(),
		Subject: "person-123", Scope: "records.read", PersonServer: presentedPersonID,
	})
	if err != nil {
		t.Fatal(err)
	}
	return compact
}

func (protocol *presentedTokenProtocol) resourceToken(t *testing.T, audience, presentedJTI string) string {
	t.Helper()
	compact, err := aauth.MintResourceToken(protocol.resourceKey, aauth.ResourceTokenClaims{
		Issuer: presentedResourceID, DWK: aauth.ResourceDiscoveryDocument, Audience: audience,
		JTI: "presented-resource-token", AgentJKT: protocol.agentJKT,
		IssuedAt: protocol.now.Unix(), ExpiresAt: protocol.now.Add(5 * time.Minute).Unix(),
		Scope: "records.read records.write", PersonServer: presentedPersonID,
		Subject: "person-123", PresentedJTI: presentedJTI,
	})
	if err != nil {
		t.Fatal(err)
	}
	return compact
}

func (protocol *presentedTokenProtocol) threePartyServer(t *testing.T) *Server {
	t.Helper()
	server, err := NewPSAuthorization(PSAuthorizationConfig{
		Issuer: presentedPersonID, SigningKey: protocol.personKey, KeyResolver: protocol.resolver,
		Clock: protocol.clock, NewID: func() string { return "issued-auth-token" }, Tokens: protocol.store,
		BindPerson: func(context.Context, PersonTokenRequest) (Person, error) { return Person{}, nil },
		Authorize: func(context.Context, AuthorizationRequest) (AuthorizationDecision, error) {
			return AuthorizationDecision{Scopes: []string{"records.read"}, Lifetime: time.Hour}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return server
}

func (protocol *presentedTokenProtocol) federatedServer(t *testing.T, transport roundTripFunc) *Server {
	t.Helper()
	server, err := NewFederatedAuthorization(FederatedAuthorizationConfig{
		Issuer: presentedPersonID, SigningKey: protocol.personKey, KeyResolver: protocol.resolver,
		Clock: protocol.clock, NewID: func() string { return "unused" },
		HTTPClient: &http.Client{Transport: transport},
		AccessServerEndpoint: func(context.Context, string) (string, error) {
			return "https://api.access.example/token", nil
		},
		Tokens:     protocol.store,
		BindPerson: func(context.Context, PersonTokenRequest) (Person, error) { return Person{}, nil },
		Consent:    func(context.Context, AuthorizationRequest) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	return server
}

func (protocol *presentedTokenProtocol) tokenRequest(t *testing.T, server *Server, body any) *httptest.ResponseRecorder {
	t.Helper()
	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, presentedPersonID+"/token", bytes.NewReader(encoded))
	request.Header.Set("Content-Type", "application/json")
	if err := signPersonServerTestRequest(request, protocol.agentKey, protocol.agentToken, protocol.clock); err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	return response
}

func (protocol *presentedTokenProtocol) exchange(t *testing.T, server *Server, resourceToken, presented string) *httptest.ResponseRecorder {
	t.Helper()
	return protocol.tokenRequest(t, server, map[string]string{
		"resource_token": resourceToken, "presented_token": presented,
	})
}

func (protocol *presentedTokenProtocol) issuedAuthToken(t *testing.T, response *httptest.ResponseRecorder) aauth.AuthTokenClaims {
	t.Helper()
	if response.Code != http.StatusOK {
		t.Fatalf("token response = %d %s", response.Code, response.Body.String())
	}
	var output struct {
		AuthToken string `json:"auth_token"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &output); err != nil {
		t.Fatal(err)
	}
	claims, err := aauth.VerifyAuthToken(context.Background(), output.AuthToken, protocol.resolver, protocol.clock)
	if err != nil {
		t.Fatal(err)
	}
	return claims
}

func assertPresentedTokenProblem(t *testing.T, response *httptest.ResponseRecorder, status int, code string) {
	t.Helper()
	var problem struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &problem); err != nil {
		t.Fatalf("problem body = %q: %v", response.Body.String(), err)
	}
	if response.Code != status || problem.Error != code {
		t.Fatalf("problem = %d %q, want %d %q; body = %s", response.Code, problem.Error, status, code, response.Body.String())
	}
}

func TestTokenEndpointAcceptsVerifiedPersonTokenWithoutRetainedRecord(t *testing.T) {
	t.Parallel()

	protocol := newPresentedTokenProtocol(t)
	presentedExpiry := protocol.now.Add(10 * time.Minute)
	response := protocol.exchange(t, protocol.threePartyServer(t),
		protocol.resourceToken(t, presentedPersonID, "person-token-1"),
		protocol.personToken(t, "person-token-1", presentedExpiry))
	claims := protocol.issuedAuthToken(t, response)
	if claims.Subject != "person-123" || claims.ExpiresAt != presentedExpiry.Unix() {
		t.Fatalf("issued auth token = %#v; presented token expires %d", claims, presentedExpiry.Unix())
	}
	if _, _, loads := protocol.store.observation(); loads != 1 {
		t.Fatalf("person token record loads = %d", loads)
	}
}

func TestTokenEndpointAcceptsAuthTypedPresentedTokenOnStepUp(t *testing.T) {
	t.Parallel()

	protocol := newPresentedTokenProtocol(t)
	presentedExpiry := protocol.now.Add(7 * time.Minute)
	response := protocol.exchange(t, protocol.threePartyServer(t),
		protocol.resourceToken(t, presentedPersonID, "current-auth-token"),
		protocol.authToken(t, presentedPersonID, "current-auth-token", presentedExpiry))
	claims := protocol.issuedAuthToken(t, response)
	if claims.JTI != "issued-auth-token" || claims.ExpiresAt != presentedExpiry.Unix() {
		t.Fatalf("step-up auth token = %#v; presented token expires %d", claims, presentedExpiry.Unix())
	}
	// A person token record is keyed by a person token identifier. An auth
	// token identifier must never be looked up there.
	if _, _, loads := protocol.store.observation(); loads != 0 {
		t.Fatalf("person token record loads for an auth token = %d", loads)
	}
}

func TestTokenEndpointRefusesUnusablePresentedToken(t *testing.T) {
	t.Parallel()

	protocol := newPresentedTokenProtocol(t)
	server := protocol.threePartyServer(t)
	live := protocol.now.Add(10 * time.Minute)
	resourceToken := protocol.resourceToken(t, presentedPersonID, "person-token-1")

	t.Run("missing", func(t *testing.T) {
		response := protocol.tokenRequest(t, server, map[string]string{"resource_token": resourceToken})
		assertPresentedTokenProblem(t, response, http.StatusBadRequest, "invalid_request")
	})
	t.Run("not a token", func(t *testing.T) {
		response := protocol.exchange(t, server, resourceToken, "not-a-token")
		assertPresentedTokenProblem(t, response, http.StatusBadRequest, "invalid_presented_token")
	})
	t.Run("resource token presented as its own predecessor", func(t *testing.T) {
		response := protocol.exchange(t, server, resourceToken, resourceToken)
		assertPresentedTokenProblem(t, response, http.StatusBadRequest, "invalid_presented_token")
	})
	t.Run("unverifiable signature", func(t *testing.T) {
		forged, err := aauth.MintPersonToken(personServerTestKey(t, protocol.personKey.ID()), aauth.PersonTokenClaims{
			Issuer: presentedPersonID, DWK: aauth.PersonDiscoveryDocument, Audience: presentedResourceID,
			Subject: "person-123", Confirmation: aauth.Confirmation{JWK: protocol.agentKey.PublicJWK()},
			JTI: "person-token-1", IssuedAt: protocol.now.Unix(), ExpiresAt: live.Unix(),
		})
		if err != nil {
			t.Fatal(err)
		}
		response := protocol.exchange(t, server, resourceToken, forged)
		assertPresentedTokenProblem(t, response, http.StatusBadRequest, "invalid_presented_token")
	})
	t.Run("expired", func(t *testing.T) {
		response := protocol.exchange(t, server, resourceToken,
			protocol.personToken(t, "person-token-1", protocol.now.Add(-time.Second)))
		assertPresentedTokenProblem(t, response, http.StatusBadRequest, "expired_presented_token")
	})
	t.Run("expired auth token", func(t *testing.T) {
		response := protocol.exchange(t, server,
			protocol.resourceToken(t, presentedPersonID, "current-auth-token"),
			protocol.authToken(t, presentedPersonID, "current-auth-token", protocol.now.Add(-time.Second)))
		assertPresentedTokenProblem(t, response, http.StatusBadRequest, "expired_presented_token")
	})
	t.Run("another token than the resource token names", func(t *testing.T) {
		response := protocol.exchange(t, server, resourceToken, protocol.personToken(t, "person-token-2", live))
		assertPresentedTokenProblem(t, response, http.StatusBadRequest, "invalid_resource_token")
	})
	t.Run("mission the resource token does not carry", func(t *testing.T) {
		missionBound, err := aauth.MintPersonToken(protocol.personKey, aauth.PersonTokenClaims{
			Issuer: presentedPersonID, DWK: aauth.PersonDiscoveryDocument, Audience: presentedResourceID,
			Subject: "person-123", Confirmation: aauth.Confirmation{JWK: protocol.agentKey.PublicJWK()},
			JTI: "person-token-1", IssuedAt: protocol.now.Unix(), ExpiresAt: live.Unix(),
			MissionS256: aauth.MissionS256([]byte("another mission")),
		})
		if err != nil {
			t.Fatal(err)
		}
		response := protocol.exchange(t, server, resourceToken, missionBound)
		assertPresentedTokenProblem(t, response, http.StatusBadRequest, "invalid_resource_token")
	})
	t.Run("bound to another agent key", func(t *testing.T) {
		other, err := aauth.MintPersonToken(protocol.personKey, aauth.PersonTokenClaims{
			Issuer: presentedPersonID, DWK: aauth.PersonDiscoveryDocument, Audience: presentedResourceID,
			Subject: "person-123", Confirmation: aauth.Confirmation{JWK: protocol.resourceKey.PublicJWK()},
			JTI: "person-token-1", IssuedAt: protocol.now.Unix(), ExpiresAt: live.Unix(),
		})
		if err != nil {
			t.Fatal(err)
		}
		response := protocol.exchange(t, server, resourceToken, other)
		assertPresentedTokenProblem(t, response, http.StatusBadRequest, "invalid_presented_token")
	})
}

func TestTokenEndpointStillChecksARetainedPersonTokenRecord(t *testing.T) {
	t.Parallel()

	protocol := newPresentedTokenProtocol(t)
	live := protocol.now.Add(10 * time.Minute)
	// The retained record names a different agent than the one asking.
	if err := protocol.store.Commit(context.Background(), directPersonTokenRecord(
		"person-token-1", presentedPersonID, presentedResourceID, "person-123", "",
		presentedProviderID, "aauth:other@provider.example", protocol.agentKey.PublicJWK(),
		live, live.Add(5*time.Minute),
	)); err != nil {
		t.Fatal(err)
	}
	response := protocol.exchange(t, protocol.threePartyServer(t),
		protocol.resourceToken(t, presentedPersonID, "person-token-1"),
		protocol.personToken(t, "person-token-1", live))
	assertPresentedTokenProblem(t, response, http.StatusBadRequest, "invalid_resource_token")
}

// accessServerReply answers the Person Server's forwarded token request.
type accessServerReply struct {
	status      int
	contentType string
	body        string
	err         error
}

func (protocol *presentedTokenProtocol) accessServer(t *testing.T, reply *accessServerReply, forwarded *string) roundTripFunc {
	t.Helper()
	return func(request *http.Request) (*http.Response, error) {
		var input struct {
			PresentedToken string `json:"presented_token"`
		}
		if err := json.NewDecoder(request.Body).Decode(&input); err != nil {
			t.Fatal(err)
		}
		*forwarded = input.PresentedToken
		if reply.err != nil {
			return nil, reply.err
		}
		return &http.Response{
			StatusCode: reply.status,
			Header:     http.Header{"Content-Type": []string{reply.contentType}},
			Body:       io.NopCloser(strings.NewReader(reply.body)),
			Request:    request,
		}, nil
	}
}

func (protocol *presentedTokenProtocol) accessServerAuthToken(t *testing.T, expiresAt time.Time) string {
	t.Helper()
	compact, err := aauth.MintAuthToken(protocol.accessKey, aauth.AuthTokenClaims{
		Issuer: presentedAccessID, DWK: aauth.AccessDiscoveryDocument, Audience: presentedResourceID,
		JTI: "delivered-auth-token", Confirmation: aauth.Confirmation{JWK: protocol.agentKey.PublicJWK()},
		IssuedAt: protocol.now.Unix(), ExpiresAt: expiresAt.Unix(),
		Subject: "person-123", Scope: "records.read", PersonServer: presentedPersonID,
	})
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(map[string]any{"auth_token": compact, "expires_in": 60})
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}

func TestFederatedTokenEndpointVerifiesAccessServerIssuedPresentedToken(t *testing.T) {
	t.Parallel()

	protocol := newPresentedTokenProtocol(t)
	presentedExpiry := protocol.now.Add(10 * time.Minute)
	presented := protocol.authToken(t, presentedAccessID, "current-auth-token", presentedExpiry)
	reply := &accessServerReply{
		status: http.StatusOK, contentType: "application/json",
		body: protocol.accessServerAuthToken(t, presentedExpiry),
	}
	var forwarded string
	server := protocol.federatedServer(t, protocol.accessServer(t, reply, &forwarded))
	response := protocol.exchange(t, server,
		protocol.resourceToken(t, presentedAccessID, "current-auth-token"), presented)
	if response.Code != http.StatusOK {
		t.Fatalf("federated step-up = %d %s", response.Code, response.Body.String())
	}
	if forwarded != presented {
		t.Fatalf("Access Server received presented_token %q", forwarded)
	}
	if _, _, loads := protocol.store.observation(); loads != 0 {
		t.Fatalf("person token record loads for an auth token = %d", loads)
	}
}

func TestFederatedTokenEndpointMapsAccessServerDelivery(t *testing.T) {
	t.Parallel()

	protocol := newPresentedTokenProtocol(t)
	presentedExpiry := protocol.now.Add(10 * time.Minute)
	for _, test := range []struct {
		name   string
		reply  accessServerReply
		status int
		code   string
	}{
		{
			name:   "unreachable",
			reply:  accessServerReply{err: errors.New("dial timeout")},
			status: http.StatusBadGateway, code: "as_unreachable",
		},
		{
			name:   "malformed error",
			reply:  accessServerReply{status: http.StatusInternalServerError, contentType: "text/plain", body: "boom"},
			status: http.StatusBadGateway, code: "as_unreachable",
		},
		{
			name:   "malformed success",
			reply:  accessServerReply{status: http.StatusOK, contentType: "application/json", body: `{"auth_token":""}`},
			status: http.StatusBadGateway, code: "as_unreachable",
		},
		{
			name:   "unverifiable auth token",
			reply:  accessServerReply{status: http.StatusOK, contentType: "application/json", body: `{"auth_token":"a.b.c","expires_in":60}`},
			status: http.StatusBadGateway, code: "as_unreachable",
		},
		{
			name: "auth token outlives the presented token",
			reply: accessServerReply{
				status: http.StatusOK, contentType: "application/json",
				body: protocol.accessServerAuthToken(t, presentedExpiry.Add(time.Second)),
			},
			status: http.StatusBadGateway, code: "as_unreachable",
		},
		{
			name: "refused signature of the Person Server",
			reply: accessServerReply{
				status: http.StatusUnauthorized, contentType: "application/problem+json",
				body: `{"status":401,"error":"invalid_signature"}`,
			},
			status: http.StatusBadGateway, code: "as_unreachable",
		},
		{
			name: "terminal denial",
			reply: accessServerReply{
				status: http.StatusForbidden, contentType: "application/problem+json",
				body: `{"status":403,"error":"access_denied"}`,
			},
			status: http.StatusForbidden, code: "access_denied",
		},
		{
			name: "terminal presented token refusal",
			reply: accessServerReply{
				status: http.StatusBadRequest, contentType: "application/problem+json",
				body: `{"status":400,"error":"invalid_presented_token"}`,
			},
			status: http.StatusBadRequest, code: "invalid_presented_token",
		},
		{
			name: "terminal server error",
			reply: accessServerReply{
				status: http.StatusInternalServerError, contentType: "application/problem+json",
				body: `{"status":500,"error":"server_error"}`,
			},
			status: http.StatusInternalServerError, code: "server_error",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			var forwarded string
			server := protocol.federatedServer(t, protocol.accessServer(t, &test.reply, &forwarded))
			response := protocol.exchange(t, server,
				protocol.resourceToken(t, presentedAccessID, "person-token-1"),
				protocol.personToken(t, "person-token-1", presentedExpiry))
			assertPresentedTokenProblem(t, response, test.status, test.code)
		})
	}
}
