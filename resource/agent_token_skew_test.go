package resource

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

func TestDirectAgentTokenIssuedBeyondSignatureWindowIsHeaderClockSkew(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 1, 9, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	providerKey := testSigningKey(t, "skew-provider", 0xb1)
	personKey := testSigningKey(t, "skew-person", 0xb2)
	agentKey := testSigningKey(t, "skew-agent", 0xb3)
	protected := http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusNoContent)
	})
	server := newDirectAgentRevocationTestServer(t, clock, providerKey, personKey, newAgentTokenRevocationTestStore(), protected)

	otherKey := testSigningKey(t, "skew-other", 0xb4)
	useWith := func(proofKey jose.SigningKey, issuedAt time.Time, jti string) *httptest.ResponseRecorder {
		t.Helper()
		agentToken, err := aauth.MintAgentToken("https://provider.example", providerKey, aauth.AgentTokenRequest{
			Agent: "aauth:local@provider.example", PublicKey: agentKey.PublicJWK(), Lifetime: time.Hour,
		}, issuedAt, jti)
		if err != nil {
			t.Fatal(err)
		}
		request := httptest.NewRequest(http.MethodGet, resourceIssuer+"/records", nil)
		if err := signaturekey.SignJWTRequest(request, proofKey, agentToken, clock); err != nil {
			t.Fatal(err)
		}
		response := httptest.NewRecorder()
		server.Handler().ServeHTTP(response, request)
		return response
	}
	use := func(issuedAt time.Time, jti string) *httptest.ResponseRecorder {
		t.Helper()
		return useWith(agentKey, issuedAt, jti)
	}

	// The HTTP signature is current; the Signature-Key token is 90 seconds early.
	assertSignatureError(t, use(now.Add(90*time.Second), "future-agent-token"), signaturekey.ErrorClockSkew)
	for _, offset := range []time.Duration{30 * time.Second, 60 * time.Second} {
		if response := use(now.Add(offset), "near-agent-token-"+offset.String()); response.Code != http.StatusNoContent {
			t.Fatalf("agent token issued %s ahead: status = %d %q %s", offset, response.Code, response.Header().Get("Signature-Error"), response.Body.String())
		}
	}
	// A key that does not match the in-window token's confirmation key is still
	// an invalid signature, and lifetime refusals keep their codes.
	assertSignatureError(t, useWith(otherKey, now.Add(30*time.Second), "mismatched-agent-token"), signaturekey.ErrorInvalidSignature)
	assertSignatureError(t, use(now.Add(-2*time.Hour), "expired-agent-token"), signaturekey.ErrorExpiredJWT)
}
