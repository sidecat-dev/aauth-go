package resource

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

// Core at a99d353, AAuth-Access Header, authenticates Agent proofs before
// creating or loading sessions. Local authority admission also applies to this
// Resource surface; see INTERPRETATIONS.md, Resource request authority admission.
func TestResourceManagedRejectsForeignAuthorityBeforeSessionAccess(t *testing.T) {
	protocol := newResourceSessionProtocol(t)
	store := newMemorySessionStore()
	authorized, dispatched := 0, 0
	config := protocol.config(store, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		dispatched++
		w.WriteHeader(http.StatusNoContent)
	}))
	config.Interaction = SessionInteractionPolicy{}
	config.AuthorizeImmediately = func(context.Context, SessionAuthorizationRequest) (SessionGrant, bool, error) {
		authorized++
		return SessionGrant{Subject: "person-123", Scope: []string{"records.read"}, Lifetime: time.Hour}, true, nil
	}
	server, err := NewResourceManaged(config)
	if err != nil {
		t.Fatal(err)
	}
	// Establish a real session on the intended Resource as the positive control.
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, protocol.signedAgentRequest(t, protocol.agentKey, protocol.agentToken, http.MethodGet, "/records", false))
	if response.Code != http.StatusNoContent || authorized != 1 || dispatched != 1 || len(store.sessions) != 1 {
		t.Fatalf("initial request: status=%d authorized=%d dispatched=%d sessions=%d", response.Code, authorized, dispatched, len(store.sessions))
	}
	var sessionToken string
	for token := range store.sessions {
		sessionToken = token
	}
	response = httptest.NewRecorder()
	server.Handler().ServeHTTP(response, protocol.signedSessionRequest(t, protocol.agentKey, protocol.agentToken, sessionToken, http.MethodGet, "/records"))
	if response.Code != http.StatusNoContent || store.loadCount() != 1 || dispatched != 2 {
		t.Fatalf("session request: status=%d loads=%d dispatched=%d", response.Code, store.loadCount(), dispatched)
	}

	for _, test := range []struct {
		name, path string
		session    bool
	}{
		{name: "initial Agent proof", path: "/records"},
		{name: "session proof", path: "/records", session: true},
		{name: "discovery", path: "/.well-known/aauth-resource.json"},
		{name: "pending poll", path: "/session/pending/example"},
		{name: "pending namespace", path: "/session/pending/"},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "https://other.example"+test.path, nil)
			request.Header.Set("X-Route-Proof", "route-1")
			if test.session {
				request.Header.Set("Authorization", "AAuth "+sessionToken)
			}
			// Sign the foreign authority itself: this is not a post-signature mutation.
			if err := signaturekey.SignJWTRequestWithOptions(request, protocol.agentKey, protocol.agentToken, protocol.clock, signaturekey.SignOptions{AdditionalComponents: []string{"x-route-proof"}}); err != nil {
				t.Fatal(err)
			}
			response := httptest.NewRecorder()
			server.Handler().ServeHTTP(response, request)
			if response.Code != http.StatusMisdirectedRequest {
				t.Errorf("status=%d body=%s", response.Code, response.Body.String())
			}
			if authorized != 1 || dispatched != 2 || len(store.sessions) != 1 || store.loadCount() != 1 || len(store.pending) != 0 {
				t.Fatalf("foreign authority reached policy or state: authorized=%d dispatched=%d sessions=%d loads=%d pending=%d", authorized, dispatched, len(store.sessions), store.loadCount(), len(store.pending))
			}
		})
	}
}
