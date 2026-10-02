package personserver

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The HTTP/2 permission test exercises the transport. These route-level tests
// check the identical empty-body contract while preserving each handler's
// credential rejection; they do not claim full journeys for sibling routes.
func TestBodylessContinuationHandlersAcceptEmptyReaders(t *testing.T) {
	protocol := newPermissionProtocol(t)
	server := protocol.newServer(t, "direct", protocol.config("direct", &PermissionConfig{Policy: protocol.policy, Store: newMemoryPermissionStore()}))
	server.authorizationInteractions = newMemoryDeferredAuthorizationStore()
	for _, test := range []struct {
		name    string
		method  string
		handler http.HandlerFunc
	}{
		{"permission", http.MethodGet, server.handlePendingPermission},
		{"authorization", http.MethodGet, server.handlePendingAuthorization},
		{"authorization cancellation", http.MethodDelete, server.handlePendingAuthorizationCancellation},
		{"interaction relay", http.MethodGet, server.handlePendingInteractionRelay},
		{"interaction question", http.MethodGet, server.handlePendingInteractionQuestion},
		{"mission proposal", http.MethodGet, server.handlePendingMissionProposal},
	} {
		t.Run(test.name, func(t *testing.T) {
			call := func(body io.ReadCloser) *httptest.ResponseRecorder {
				request := httptest.NewRequest(test.method, protocol.personServerID+"/pending/example", nil)
				request.Body = body
				response := httptest.NewRecorder()
				test.handler(response, request)
				return response
			}
			baseline := call(http.NoBody)
			if baseline.Header().Get("Signature-Error") == "" {
				t.Fatalf("bodyless request did not reach credential validation: %d %s", baseline.Code, baseline.Body.String())
			}
			empty := call(io.NopCloser(strings.NewReader("")))
			if empty.Code != baseline.Code || empty.Body.String() != baseline.Body.String() || empty.Header().Get("Signature-Error") != baseline.Header().Get("Signature-Error") {
				t.Fatalf("empty reader changed route validation: %d %s, want %d %s", empty.Code, empty.Body.String(), baseline.Code, baseline.Body.String())
			}
			payload := call(io.NopCloser(strings.NewReader("x")))
			if payload.Code != http.StatusBadRequest || payload.Header().Get("Signature-Error") != "" {
				t.Fatalf("body-bearing request was not rejected before credential validation: %d %s", payload.Code, payload.Body.String())
			}
		})
	}
}
