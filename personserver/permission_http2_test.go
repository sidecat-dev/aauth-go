package personserver

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

func TestPermissionPollAcceptsEmptyHTTP2BodyWithoutAcceptingPayload(t *testing.T) {
	protocol := newPermissionProtocol(t)
	store := newMemoryPermissionStore()
	protocol.policyResult = PermissionPolicyResult{Deferred: &PermissionPendingPolicy{Lifetime: time.Minute}}
	server := protocol.newServer(t, "direct", protocol.config("direct", &PermissionConfig{Policy: protocol.policy, Store: store}))
	created := permissionRequest(t, protocol, server, protocol.agentKey, protocol.agentToken, `{"action":"SendEmail"}`)
	if created.Code != http.StatusAccepted {
		t.Fatalf("create: %d %s", created.Code, created.Body.String())
	}
	handle, err := server.ResumePermission(context.Background(), store.onlyRecord(t).ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := server.GrantPermission(context.Background(), handle); err != nil {
		t.Fatal(err)
	}

	transportServer := httptest.NewUnstartedServer(server.Handler())
	transportServer.EnableHTTP2 = true
	transportServer.StartTLS()
	defer transportServer.Close()
	transportURL, err := url.Parse(transportServer.URL)
	if err != nil {
		t.Fatal(err)
	}
	client := transportServer.Client()
	defer client.CloseIdleConnections()
	poll := func(payload string) (int, string) {
		t.Helper()
		request, err := http.NewRequest(http.MethodGet, protocol.personServerID+created.Header().Get("Location"), nil)
		if err != nil {
			t.Fatal(err)
		}
		request.Host = request.URL.Host
		if err := signaturekey.SignJWTRequest(request, protocol.agentKey, protocol.agentToken, protocol.clock); err != nil {
			t.Fatal(err)
		}
		// Dial the local TLS listener while preserving the signed authority.
		request.URL.Host = transportURL.Host
		if payload != "" {
			request.Body = io.NopCloser(strings.NewReader(payload))
			request.ContentLength = int64(len(payload))
		}
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		body, err := io.ReadAll(response.Body)
		if err != nil {
			t.Fatal(err)
		}
		if response.ProtoMajor != 2 {
			t.Fatalf("protocol = %s, want HTTP/2", response.Proto)
		}
		return response.StatusCode, string(body)
	}
	if status, body := poll("x"); status != http.StatusBadRequest {
		t.Fatalf("body-bearing poll: %d %s", status, body)
	}
	if status, body := poll(""); status != http.StatusOK || !strings.Contains(body, `"permission":"granted"`) {
		t.Fatalf("empty HTTP/2 poll: %d %s", status, body)
	}
	if status, body := poll(""); status != http.StatusGone {
		t.Fatalf("consumed poll: %d %s", status, body)
	}
}
