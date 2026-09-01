package agent_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/agent"
	"gitlab.com/sidecat-dev/aauth-go/jose"
)

const (
	permissionEndpoint = "https://ps.example/permission"
	permissionLocation = "https://ps.example/permission/pending-1"
)

func TestRequestPermissionSendsOneSignedMissionlessRequest(t *testing.T) {
	for _, test := range []struct {
		name       string
		response   map[string]any
		permission aauth.Permission
		reason     string
	}{
		{name: "granted", response: map[string]any{"permission": "granted"}, permission: aauth.PermissionGranted},
		{name: "denied", response: map[string]any{"permission": "denied", "reason": "**Policy** declined this."}, permission: aauth.PermissionDenied, reason: "**Policy** declined this."},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newPermissionFixture(t)
			fixture.initial = func(request *http.Request) (*http.Response, error) {
				verified := verifyProof(t, request, fixture.protocol.resolver, fixture.protocol.clock, aauth.AgentTokenType)
				claims, err := verified.AgentClaims()
				if err != nil {
					t.Fatal(err)
				}
				if claims.Subject != fixture.protocol.agentID {
					t.Fatalf("signed Agent = %q", claims.Subject)
				}
				if request.Method != http.MethodPost || request.URL.String() != permissionEndpoint {
					t.Fatalf("request = %s %s", request.Method, request.URL)
				}
				for _, name := range []string{"Content-Type", "Content-Digest", "Signature-Key", "Signature-Input", "Signature"} {
					if request.Header.Get(name) == "" {
						t.Errorf("request is missing %s", name)
					}
				}
				var body map[string]json.RawMessage
				decodeRequest(t, request, &body)
				if _, present := body["mission_s256"]; present {
					t.Fatal("missionless request carried mission_s256")
				}
				var action, description string
				if err := json.Unmarshal(body["action"], &action); err != nil || action != "SendEmail" {
					t.Fatalf("action = %q, %v", action, err)
				}
				if err := json.Unmarshal(body["description"], &description); err != nil || description != "Send the proposed itinerary." {
					t.Fatalf("description = %q, %v", description, err)
				}
				if string(body["parameters"]) != `{"subject":"Japan trip","to":"user@example.com"}` {
					t.Fatalf("parameters = %s", body["parameters"])
				}
				return jsonResponse(request, http.StatusOK, test.response), nil
			}

			result, err := fixture.client.RequestPermission(context.Background(), agent.PermissionRequest{
				PersonServer: fixture.protocol.personServerID,
				Action:       "SendEmail",
				Description:  "Send the proposed itinerary.",
				Parameters:   json.RawMessage(`{"subject":"Japan trip","to":"user@example.com"}`),
			})
			if err != nil {
				t.Fatal(err)
			}
			decision, ok := result.Decision()
			if !ok || decision.Permission() != test.permission || decision.Reason() != test.reason {
				t.Fatalf("decision = %#v, %t", decision, ok)
			}
			if _, ok := result.Pending(); ok {
				t.Fatal("decision also reported pending")
			}
			if _, ok := result.Response(); ok {
				t.Fatal("decision also reported a response")
			}
			if fixture.initialCalls != 1 || fixture.pollCalls != 0 {
				t.Fatalf("calls = initial %d, poll %d", fixture.initialCalls, fixture.pollCalls)
			}
		})
	}
}

func TestRequestPermissionCarriesMissionDigest(t *testing.T) {
	fixture := newPermissionFixture(t)
	mission := aauth.MissionS256([]byte(`{"agent":"aauth:agent@ap.example"}`))
	fixture.initial = func(request *http.Request) (*http.Response, error) {
		verified := verifyProof(t, request, fixture.protocol.resolver, fixture.protocol.clock, aauth.AgentTokenType)
		if _, err := verified.AgentClaims(); err != nil {
			t.Fatal(err)
		}
		var body map[string]json.RawMessage
		decodeRequest(t, request, &body)
		var got string
		if err := json.Unmarshal(body["mission_s256"], &got); err != nil || got != mission {
			t.Fatalf("mission_s256 = %q, %v", got, err)
		}
		return jsonResponse(request, http.StatusOK, map[string]any{"permission": "granted"}), nil
	}

	result, err := fixture.client.RequestPermission(context.Background(), agent.PermissionRequest{
		PersonServer: fixture.protocol.personServerID,
		MissionS256:  mission,
		Action:       "files.write",
	})
	if err != nil {
		t.Fatal(err)
	}
	decision, ok := result.Decision()
	if !ok || decision.Permission() != aauth.PermissionGranted {
		t.Fatalf("decision = %#v, %t", decision, ok)
	}
}

func TestPermissionPendingAndExplicitPoll(t *testing.T) {
	fixture := newPermissionFixture(t)
	fixture.initial = func(request *http.Request) (*http.Response, error) {
		return permissionPendingResponse(request, "7", "future-status"), nil
	}
	fixture.poll = func(request *http.Request) (*http.Response, error) {
		verifyProof(t, request, fixture.protocol.resolver, fixture.protocol.clock, aauth.AgentTokenType)
		if request.Method != http.MethodGet || request.URL.String() != permissionLocation {
			t.Fatalf("poll = %s %s", request.Method, request.URL)
		}
		if request.Body != nil && request.Body != http.NoBody {
			t.Fatal("poll carried a body")
		}
		if request.ContentLength != 0 || request.GetBody != nil {
			t.Fatalf("poll body metadata = length %d, GetBody %v", request.ContentLength, request.GetBody != nil)
		}
		for _, name := range []string{"Content-Type", "Content-Digest"} {
			if request.Header.Get(name) != "" {
				t.Errorf("poll %s = %q", name, request.Header.Get(name))
			}
		}
		return problemResponse(request, &aauth.ProblemError{
			Status: http.StatusForbidden, Code: "denied", Detail: "The user declined this action.",
		}), nil
	}

	result, err := fixture.client.RequestPermission(context.Background(), agent.PermissionRequest{
		PersonServer: fixture.protocol.personServerID,
		Action:       "files.write",
	})
	if err != nil {
		t.Fatal(err)
	}
	pending, ok := result.Pending()
	if !ok {
		t.Fatal("202 did not produce pending permission")
	}
	if pending.PersonServer() != fixture.protocol.personServerID || pending.Location() != permissionLocation || pending.RetryAfter() != 7*time.Second {
		t.Fatalf("pending = person server %q, location %q, retry %s", pending.PersonServer(), pending.Location(), pending.RetryAfter())
	}
	if fixture.pollCalls != 0 {
		t.Fatal("RequestPermission polled automatically")
	}

	result, err = fixture.client.PollPermission(context.Background(), pending)
	if err != nil {
		t.Fatal(err)
	}
	decision, ok := result.Decision()
	if !ok || decision.Permission() != aauth.PermissionDenied || decision.Reason() != "The user declined this action." {
		t.Fatalf("deferred decision = %#v, %t", decision, ok)
	}
	if fixture.initialCalls != 1 || fixture.pollCalls != 1 {
		t.Fatalf("calls = initial %d, poll %d", fixture.initialCalls, fixture.pollCalls)
	}
}

func TestPermissionPollReturnsUpdatedPendingWithoutLooping(t *testing.T) {
	fixture := newPermissionFixture(t)
	fixture.initial = func(request *http.Request) (*http.Response, error) {
		return permissionPendingResponse(request, "0", "pending"), nil
	}
	fixture.poll = func(request *http.Request) (*http.Response, error) {
		return permissionPendingResponse(request, "11", "interacting"), nil
	}
	pending := requestPendingPermission(t, fixture)
	result, err := fixture.client.PollPermission(context.Background(), pending)
	if err != nil {
		t.Fatal(err)
	}
	next, ok := result.Pending()
	if !ok || next.Location() != pending.Location() || next.RetryAfter() != 11*time.Second {
		t.Fatalf("updated pending = %#v, %t", next, ok)
	}
	if fixture.pollCalls != 1 {
		t.Fatalf("poll calls = %d, want 1", fixture.pollCalls)
	}
}

func TestPermissionRetryableResponsesRemainCallerOwned(t *testing.T) {
	for _, status := range []int{http.StatusTooManyRequests, http.StatusServiceUnavailable} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			fixture := newPermissionFixture(t)
			body := &trackingReadCloser{Reader: strings.NewReader("retry later")}
			fixture.initial = func(request *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: status, Status: http.StatusText(status), Request: request,
					Header: http.Header{"Retry-After": []string{"13"}}, Body: body,
				}, nil
			}
			result, err := fixture.client.RequestPermission(context.Background(), agent.PermissionRequest{
				PersonServer: fixture.protocol.personServerID, Action: "files.write",
			})
			if err != nil {
				t.Fatal(err)
			}
			response, ok := result.Response()
			if !ok || response.StatusCode != status || body.closed {
				t.Fatalf("response = %#v, %t; closed = %t", response, ok, body.closed)
			}
			if fixture.initialCalls != 1 || fixture.pollCalls != 0 {
				t.Fatalf("calls = initial %d, poll %d", fixture.initialCalls, fixture.pollCalls)
			}
			_ = response.Body.Close()
			if !body.closed {
				t.Fatal("caller could not close response body")
			}
		})
	}
}

func TestPollPermissionReturnsRetryableResponseWithoutAction(t *testing.T) {
	fixture := newPermissionFixture(t)
	fixture.initial = func(request *http.Request) (*http.Response, error) {
		return permissionPendingResponse(request, "1", "pending"), nil
	}
	body := &trackingReadCloser{Reader: strings.NewReader("temporarily unavailable")}
	fixture.poll = func(request *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusServiceUnavailable, Status: http.StatusText(http.StatusServiceUnavailable),
			Request: request, Header: http.Header{"Retry-After": []string{"3"}}, Body: body,
		}, nil
	}
	pending := requestPendingPermission(t, fixture)
	result, err := fixture.client.PollPermission(context.Background(), pending)
	if err != nil {
		t.Fatal(err)
	}
	response, ok := result.Response()
	if !ok || response.StatusCode != http.StatusServiceUnavailable || body.closed {
		t.Fatalf("response = %#v, %t; closed = %t", response, ok, body.closed)
	}
	if fixture.pollCalls != 1 {
		t.Fatalf("poll calls = %d, want 1", fixture.pollCalls)
	}
	_ = response.Body.Close()
}

func TestRequestPermissionRejectsInvalidInputWithoutNetwork(t *testing.T) {
	for _, test := range []struct {
		name    string
		request agent.PermissionRequest
	}{
		{name: "missing person server", request: agent.PermissionRequest{Action: "read"}},
		{name: "wrong person server", request: agent.PermissionRequest{PersonServer: "https://other-ps.example", Action: "read"}},
		{name: "empty action", request: agent.PermissionRequest{PersonServer: "https://ps.example"}},
		{name: "blank action", request: agent.PermissionRequest{PersonServer: "https://ps.example", Action: "  \n"}},
		{name: "action too large", request: agent.PermissionRequest{PersonServer: "https://ps.example", Action: strings.Repeat("a", 4097)}},
		{name: "description too large", request: agent.PermissionRequest{PersonServer: "https://ps.example", Action: "read", Description: strings.Repeat("d", 65537)}},
		{name: "invalid mission", request: agent.PermissionRequest{PersonServer: "https://ps.example", MissionS256: "not-a-digest", Action: "read"}},
		{name: "malformed parameters", request: agent.PermissionRequest{PersonServer: "https://ps.example", Action: "read", Parameters: json.RawMessage(`{"x":`)}},
		{name: "null parameters", request: agent.PermissionRequest{PersonServer: "https://ps.example", Action: "read", Parameters: json.RawMessage(`null`)}},
		{name: "array parameters", request: agent.PermissionRequest{PersonServer: "https://ps.example", Action: "read", Parameters: json.RawMessage(`[]`)}},
		{name: "scalar parameters", request: agent.PermissionRequest{PersonServer: "https://ps.example", Action: "read", Parameters: json.RawMessage(`true`)}},
		{name: "ambiguous parameters", request: agent.PermissionRequest{PersonServer: "https://ps.example", Action: "read", Parameters: json.RawMessage(`{"x":1,"x":2}`)}},
		{name: "signed body too large", request: agent.PermissionRequest{PersonServer: "https://ps.example", Action: "read", Parameters: json.RawMessage(`{"value":"` + strings.Repeat("v", 1<<20) + `"}`)}},
	} {
		t.Run(test.name, func(t *testing.T) {
			protocol := newTestProtocol(t)
			calls := 0
			client := protocol.newClientWithHTTPClient(t, &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
				calls++
				return nil, errors.New("unexpected network request")
			})})
			if _, err := client.RequestPermission(context.Background(), test.request); err == nil {
				t.Fatal("RequestPermission accepted invalid input")
			}
			if calls != 0 {
				t.Fatalf("network calls = %d, want 0", calls)
			}
		})
	}
}

func TestRequestPermissionTransportFailureIsUncertainAndNotRetried(t *testing.T) {
	fixture := newPermissionFixture(t)
	want := errors.New("connection reset after request handoff")
	fixture.initial = func(request *http.Request) (*http.Response, error) { return nil, want }
	_, err := fixture.client.RequestPermission(context.Background(), agent.PermissionRequest{
		PersonServer: fixture.protocol.personServerID, Action: "messages.send",
	})
	if err == nil {
		t.Fatal("RequestPermission succeeded")
	}
	var uncertain *agent.PermissionSubmissionUncertainError
	if !errors.As(err, &uncertain) || !errors.Is(err, want) {
		t.Fatalf("error = %T %v, want PermissionSubmissionUncertainError wrapping transport failure", err, err)
	}
	if fixture.initialCalls != 1 || fixture.pollCalls != 0 {
		t.Fatalf("calls = initial %d, poll %d", fixture.initialCalls, fixture.pollCalls)
	}
}

func TestRequestPermissionUnverifiablePostHandoffOutcomeIsUncertain(t *testing.T) {
	for _, test := range []struct {
		name   string
		status int
		body   map[string]any
	}{
		{name: "malformed success", status: http.StatusOK, body: map[string]any{}},
		{name: "unexpected success", status: http.StatusCreated, body: map[string]any{"permission": "granted"}},
		{name: "server failure", status: http.StatusInternalServerError, body: map[string]any{"error": "server_error"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newPermissionFixture(t)
			fixture.initial = func(request *http.Request) (*http.Response, error) {
				return jsonResponse(request, test.status, test.body), nil
			}
			_, err := fixture.client.RequestPermission(context.Background(), agent.PermissionRequest{
				PersonServer: fixture.protocol.personServerID, Action: "messages.send",
			})
			var uncertain *agent.PermissionSubmissionUncertainError
			if !errors.As(err, &uncertain) {
				t.Fatalf("error = %T %v, want PermissionSubmissionUncertainError", err, err)
			}
			if fixture.initialCalls != 1 || fixture.pollCalls != 0 {
				t.Fatalf("calls = initial %d, poll %d", fixture.initialCalls, fixture.pollCalls)
			}
		})
	}
}

func TestRequestPermissionDefiniteClientRejectionIsNotUncertain(t *testing.T) {
	fixture := newPermissionFixture(t)
	fixture.initial = func(request *http.Request) (*http.Response, error) {
		return problemResponse(request, &aauth.ProblemError{
			Status: http.StatusBadRequest, Code: "invalid_request", Detail: "action is invalid",
		}), nil
	}
	_, err := fixture.client.RequestPermission(context.Background(), agent.PermissionRequest{
		PersonServer: fixture.protocol.personServerID, Action: "messages.send",
	})
	if err == nil {
		t.Fatal("definite rejection succeeded")
	}
	var uncertain *agent.PermissionSubmissionUncertainError
	if errors.As(err, &uncertain) {
		t.Fatalf("definite rejection became uncertain: %v", err)
	}
}

func TestPermissionRejectsInvalidResponseShapes(t *testing.T) {
	tests := []struct {
		name string
		make func(*http.Request) *http.Response
	}{
		{name: "201 is not success", make: func(request *http.Request) *http.Response {
			return jsonResponse(request, http.StatusCreated, map[string]any{"permission": "granted"})
		}},
		{name: "other 2xx is not success", make: func(request *http.Request) *http.Response { return jsonResponse(request, http.StatusNoContent, nil) }},
		{name: "missing permission", make: func(request *http.Request) *http.Response {
			return jsonResponse(request, http.StatusOK, map[string]any{})
		}},
		{name: "unknown permission", make: func(request *http.Request) *http.Response {
			return jsonResponse(request, http.StatusOK, map[string]any{"permission": "maybe"})
		}},
		{name: "null reason", make: func(request *http.Request) *http.Response {
			return jsonResponse(request, http.StatusOK, map[string]any{"permission": "denied", "reason": nil})
		}},
		{name: "non-string reason", make: func(request *http.Request) *http.Response {
			return jsonResponse(request, http.StatusOK, map[string]any{"permission": "denied", "reason": []string{"no"}})
		}},
		{name: "reason on grant", make: func(request *http.Request) *http.Response {
			return jsonResponse(request, http.StatusOK, map[string]any{"permission": "granted", "reason": "surplus"})
		}},
		{name: "duplicate content type", make: func(request *http.Request) *http.Response {
			response := jsonResponse(request, http.StatusOK, map[string]any{"permission": "granted"})
			response.Header.Add("Content-Type", "application/json")
			return response
		}},
		{name: "202 missing location", make: func(request *http.Request) *http.Response {
			response := permissionPendingResponse(request, "1", "pending")
			response.Header.Del("Location")
			return response
		}},
		{name: "202 cross origin", make: func(request *http.Request) *http.Response {
			response := permissionPendingResponse(request, "1", "pending")
			response.Header.Set("Location", "https://attacker.example/pending")
			return response
		}},
		{name: "202 missing no-store", make: func(request *http.Request) *http.Response {
			response := permissionPendingResponse(request, "1", "pending")
			response.Header.Del("Cache-Control")
			return response
		}},
		{name: "202 missing status", make: func(request *http.Request) *http.Response {
			response := permissionPendingResponse(request, "1", "")
			return response
		}},
		{name: "403 abandoned is not denial", make: func(request *http.Request) *http.Response {
			return problemResponse(request, &aauth.ProblemError{Status: http.StatusForbidden, Code: "abandoned", Detail: "left"})
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newPermissionFixture(t)
			fixture.initial = func(request *http.Request) (*http.Response, error) { return test.make(request), nil }
			if _, err := fixture.client.RequestPermission(context.Background(), agent.PermissionRequest{
				PersonServer: fixture.protocol.personServerID, Action: "files.write",
			}); err == nil {
				t.Fatal("RequestPermission accepted invalid response")
			}
			if fixture.initialCalls != 1 || fixture.pollCalls != 0 {
				t.Fatalf("calls = initial %d, poll %d", fixture.initialCalls, fixture.pollCalls)
			}
		})
	}
}

func TestPollPermissionRejectsWrongClientOrMetadataOriginBeforePoll(t *testing.T) {
	fixture := newPermissionFixture(t)
	fixture.initial = func(request *http.Request) (*http.Response, error) {
		return permissionPendingResponse(request, "1", "pending"), nil
	}
	pending := requestPendingPermission(t, fixture)

	otherIdentity := newPermissionClient(t, fixture.protocol, "aauth:other@ap.example", testSigningKey(t, "other-permission-agent", 121), fixture.roundTrip)
	metadataBefore, pollBefore := fixture.metadataCalls, fixture.pollCalls
	if _, err := otherIdentity.PollPermission(context.Background(), pending); err == nil {
		t.Fatal("other Agent accepted pending permission")
	}
	if fixture.metadataCalls != metadataBefore || fixture.pollCalls != pollBefore {
		t.Fatal("wrong Agent reached the network")
	}

	otherKey := newPermissionClient(t, fixture.protocol, fixture.protocol.agentID, testSigningKey(t, "rotated-permission-agent", 122), fixture.roundTrip)
	if _, err := otherKey.PollPermission(context.Background(), pending); err == nil {
		t.Fatal("other key accepted pending permission")
	}
	if fixture.metadataCalls != metadataBefore || fixture.pollCalls != pollBefore {
		t.Fatal("wrong key reached the network")
	}

	fixture.permissionEndpoint = "https://new-ps.example/permission"
	if _, err := fixture.client.PollPermission(context.Background(), pending); err == nil {
		t.Fatal("poll accepted changed metadata origin")
	}
	if fixture.pollCalls != pollBefore {
		t.Fatal("metadata-origin mismatch reached the pending URL")
	}
}

func TestPermissionValuesAreZeroSafe(t *testing.T) {
	var result agent.PermissionResult
	if decision, ok := result.Decision(); ok || decision != (agent.PermissionDecision{}) {
		t.Fatalf("zero decision = %#v, %t", decision, ok)
	}
	if pending, ok := result.Pending(); ok || pending != (agent.PendingPermission{}) {
		t.Fatalf("zero pending = %#v, %t", pending, ok)
	}
	if response, ok := result.Response(); ok || response != nil {
		t.Fatalf("zero response = %#v, %t", response, ok)
	}
	var decision agent.PermissionDecision
	if decision.Permission() != "" || decision.Reason() != "" {
		t.Fatalf("zero PermissionDecision = %#v", decision)
	}
	var pending agent.PendingPermission
	if pending.PersonServer() != "" || pending.Location() != "" || pending.RetryAfter() != 0 {
		t.Fatalf("zero PendingPermission = %#v", pending)
	}
}

type permissionFixture struct {
	t                  *testing.T
	protocol           *testProtocol
	client             *agent.Client
	permissionEndpoint string
	metadataCalls      int
	initialCalls       int
	pollCalls          int
	initial            func(*http.Request) (*http.Response, error)
	poll               func(*http.Request) (*http.Response, error)
}

func newPermissionFixture(t *testing.T) *permissionFixture {
	t.Helper()
	fixture := &permissionFixture{t: t, protocol: newTestProtocol(t), permissionEndpoint: permissionEndpoint}
	fixture.client = fixture.protocol.newClientWithHTTPClient(t, &http.Client{Transport: roundTripperFunc(fixture.roundTrip)})
	return fixture
}

func (fixture *permissionFixture) roundTrip(request *http.Request) (*http.Response, error) {
	switch request.URL.String() {
	case fixture.protocol.personServerID + "/.well-known/aauth-person.json":
		fixture.metadataCalls++
		return jsonResponse(request, http.StatusOK, map[string]any{
			"issuer": fixture.protocol.personServerID, "person_token_endpoint": fixture.protocol.personTokenEndpoint,
			"auth_token_endpoint": fixture.protocol.authTokenEndpoint, "permission_endpoint": fixture.permissionEndpoint,
		}), nil
	case permissionEndpoint:
		fixture.initialCalls++
		if fixture.initial == nil {
			fixture.t.Fatal("unexpected initial permission request")
		}
		return fixture.initial(request)
	case permissionLocation:
		fixture.pollCalls++
		if fixture.poll == nil {
			fixture.t.Fatal("unexpected permission poll")
		}
		return fixture.poll(request)
	default:
		fixture.t.Fatalf("unexpected request: %s %s", request.Method, request.URL)
		return nil, errors.New("unexpected request")
	}
}

func requestPendingPermission(t *testing.T, fixture *permissionFixture) agent.PendingPermission {
	t.Helper()
	result, err := fixture.client.RequestPermission(context.Background(), agent.PermissionRequest{
		PersonServer: fixture.protocol.personServerID, Action: "files.write",
	})
	if err != nil {
		t.Fatal(err)
	}
	pending, ok := result.Pending()
	if !ok {
		t.Fatal("request did not return pending permission")
	}
	return pending
}

func permissionPendingResponse(request *http.Request, retryAfter, status string) *http.Response {
	response := jsonResponse(request, http.StatusAccepted, map[string]any{"status": status})
	response.Header.Set("Location", "/permission/pending-1")
	response.Header.Set("Retry-After", retryAfter)
	response.Header.Set("Cache-Control", "private, no-store")
	return response
}

func newPermissionClient(t *testing.T, protocol *testProtocol, identifier string, key jose.SigningKey, transport func(*http.Request) (*http.Response, error)) *agent.Client {
	t.Helper()
	token, err := aauth.MintAgentToken(protocol.agentProviderID, protocol.agentProviderKey, aauth.AgentTokenRequest{
		Agent: identifier, PersonServer: protocol.personServerID, PublicKey: key.PublicJWK(), Lifetime: time.Hour,
	}, protocol.now, identifier+"-permission-token")
	if err != nil {
		t.Fatal(err)
	}
	client, err := agent.New(context.Background(), agent.Config{
		Identifier: identifier, SigningKey: key, AgentToken: token, KeyResolver: protocol.resolver,
		HTTPClient: &http.Client{Transport: roundTripperFunc(transport)}, Clock: protocol.clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

type trackingReadCloser struct {
	io.Reader
	closed bool
}

func (body *trackingReadCloser) Close() error {
	body.closed = true
	return nil
}
