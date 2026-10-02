package agent_test

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"gitlab.com/sidecat-dev/aauth-go/agent"
)

func TestPollPermissionDistinguishesFailureBeforeHTTPHandoff(t *testing.T) {
	fixture := newPermissionFixture(t)
	fixture.initial = func(request *http.Request) (*http.Response, error) {
		return permissionPendingResponse(request, "0", "pending"), nil
	}
	pending := requestPendingPermission(t, fixture)
	discoveryFails := true
	client := newPermissionClient(t, fixture.protocol, fixture.protocol.agentID, fixture.protocol.agentKey, func(request *http.Request) (*http.Response, error) {
		if request.URL.String() == fixture.protocol.personServerID+"/.well-known/aauth-person.json" && discoveryFails {
			return nil, errors.New("metadata unavailable")
		}
		return fixture.roundTrip(request)
	})
	_, err := client.PollPermission(context.Background(), pending)
	var notStarted *agent.PermissionPollNotStartedError
	if !errors.As(err, &notStarted) || fixture.pollCalls != 0 || fixture.initialCalls != 1 {
		t.Fatalf("pre-poll error=%v posts=%d polls=%d", err, fixture.initialCalls, fixture.pollCalls)
	}
	discoveryFails = false
	fixture.poll = func(*http.Request) (*http.Response, error) { return nil, errors.New("poll response lost") }
	_, err = client.PollPermission(context.Background(), pending)
	notStarted = nil
	if err == nil || errors.As(err, &notStarted) || fixture.pollCalls != 1 || fixture.initialCalls != 1 {
		t.Fatalf("post-handoff error=%v posts=%d polls=%d", err, fixture.initialCalls, fixture.pollCalls)
	}
}
