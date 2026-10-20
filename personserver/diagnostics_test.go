package personserver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"gitlab.com/sidecat-dev/aauth-go/diagnostics"
)

func TestDiagnosticsReceivesMissionTermination(t *testing.T) {
	for _, endpoint := range []string{"/person", "/mission/update"} {
		t.Run(endpoint, func(t *testing.T) {
			p := newMissionProtocol(t)
			mission := p.commitMission(t, p.agentID, p.now.Add(time.Hour), MissionTerminated, "revoked")
			input := map[string]string{"resource": p.resourceID, "mission_s256": mission.S256}
			if endpoint == "/mission/update" {
				input = map[string]string{"action": "update", "description": "Progress"}
				endpoint = "/mission/" + mission.S256
			}
			body, err := json.Marshal(input)
			if err != nil {
				t.Fatal(err)
			}
			request := httptest.NewRequest(http.MethodPost, p.personServerID+endpoint, bytes.NewReader(body))
			request.Header.Set("Content-Type", "application/json")
			if err := signPersonServerTestRequest(request, p.agentKey, p.agentToken, p.clock); err != nil {
				t.Fatal(err)
			}
			var got []diagnostics.Problem
			response := httptest.NewRecorder()
			diagnostics.Handler(p.server.Handler(), func(_ context.Context, problem diagnostics.Problem) {
				got = append(got, problem)
			}).ServeHTTP(response, request)
			assertMissionProblem(t, response, http.StatusForbidden, "mission_terminated", "terminated", "revoked")
			if response.Header().Get("Cache-Control") != "no-store" || response.Header().Get("Content-Type") != "application/problem+json" {
				t.Fatalf("headers = %v", response.Header())
			}
			if len(got) != 1 || got[0].Status != http.StatusForbidden || got[0].Code != "mission_terminated" {
				t.Fatalf("observations = %#v", got)
			}
			var terminated *MissionTerminatedError
			if !errors.As(got[0].Cause, &terminated) || terminated.TerminationReason != "revoked" {
				t.Fatalf("cause = %v", got[0].Cause)
			}
		})
	}
}

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
