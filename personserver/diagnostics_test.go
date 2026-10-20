package personserver

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"gitlab.com/sidecat-dev/aauth-go/diagnostics"
)

func TestDiagnosticsReceivesPermissionPolicyFailure(t *testing.T) {
	p := newPermissionProtocol(t)
	private := errors.New("private consent backend unavailable")
	server := p.newServer(t, "direct", p.config("direct", &PermissionConfig{Store: newMemoryPermissionStore(), Policy: func(context.Context, PermissionPolicyRequest) (PermissionPolicyResult, error) {
		return PermissionPolicyResult{}, private
	}}))
	request := httptest.NewRequest(http.MethodPost, p.personServerID+"/permission", strings.NewReader(`{"action":"SendEmail"}`))
	request.Header.Set("Content-Type", "application/json")
	if err := signPersonServerTestRequest(request, p.agentKey, p.agentToken, p.clock); err != nil {
		t.Fatal(err)
	}
	var got []diagnostics.Problem
	response := httptest.NewRecorder()
	diagnostics.Handler(server.Handler(), func(_ context.Context, problem diagnostics.Problem) { got = append(got, problem) }).ServeHTTP(response, request)
	if response.Code != 500 || strings.Contains(response.Body.String(), private.Error()) {
		t.Fatalf("response %d %s", response.Code, response.Body.String())
	}
	if len(got) != 1 || !errors.Is(got[0].Cause, private) || got[0].Code != "server_error" {
		t.Fatalf("observations: %#v", got)
	}
}
