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
)

const auditEndpoint = "https://ps.example/audit"

func TestSubmitAuditSendsOneExactSignedRequest(t *testing.T) {
	fixture := newAuditFixture(t)
	entry := validAgentAuditEntry()
	document, err := aauth.EncodeAudit(entry)
	if err != nil {
		t.Fatal(err)
	}
	responseBody := &trackingReadCloser{Reader: strings.NewReader("")}
	fixture.submit = func(request *http.Request) (*http.Response, error) {
		verified := verifyProofWithComponents(
			t, request, fixture.protocol.resolver, fixture.protocol.clock,
			aauth.AgentTokenType, []string{"content-type", "content-digest"},
		)
		claims, err := verified.AgentClaims()
		if err != nil {
			t.Fatal(err)
		}
		if claims.Subject != fixture.protocol.agentID || claims.PersonServer != fixture.protocol.personServerID {
			t.Fatalf("Agent claims = %#v", claims)
		}
		if request.Method != http.MethodPost || request.URL.String() != auditEndpoint {
			t.Fatalf("request = %s %s", request.Method, request.URL)
		}
		for _, name := range []string{"Content-Type", "Content-Digest", "Signature-Key", "Signature-Input", "Signature"} {
			if request.Header.Get(name) == "" {
				t.Errorf("request is missing %s", name)
			}
		}
		if got := verified.Proof.ExactBody(); string(got) != string(document.ExactJSON) {
			t.Fatalf("signed audit body = %s, want %s", got, document.ExactJSON)
		}
		decoded, err := aauth.DecodeAudit(verified.Proof.ExactBody())
		if err != nil {
			t.Fatal(err)
		}
		if decoded.Entry.MissionS256 != entry.MissionS256 || decoded.Entry.Action != entry.Action {
			t.Fatalf("decoded submitted audit = %#v", decoded.Entry)
		}
		return &http.Response{
			StatusCode: http.StatusCreated, Status: http.StatusText(http.StatusCreated),
			Request: request, Header: make(http.Header), Body: responseBody,
		}, nil
	}

	err = fixture.client.SubmitAudit(context.Background(), agent.AuditRequest{
		PersonServer: fixture.protocol.personServerID,
		Entry:        entry,
	})
	if err != nil {
		t.Fatal(err)
	}
	if fixture.metadataCalls != 1 || fixture.submitCalls != 1 || fixture.otherCalls != 0 {
		t.Fatalf("calls = metadata %d, submit %d, other %d", fixture.metadataCalls, fixture.submitCalls, fixture.otherCalls)
	}
	if !responseBody.closed {
		t.Fatal("successful empty response body was not closed")
	}
}

func TestSubmitAuditRejectsInvalidInputBeforeNetwork(t *testing.T) {
	valid := validAgentAuditEntry()
	for _, test := range []struct {
		name    string
		request agent.AuditRequest
	}{
		{name: "missing person server", request: agent.AuditRequest{Entry: valid}},
		{name: "wrong person server", request: agent.AuditRequest{PersonServer: "https://other-ps.example", Entry: valid}},
		{name: "missing mission", request: agent.AuditRequest{PersonServer: "https://ps.example", Entry: func() aauth.AuditEntry { entry := valid; entry.MissionS256 = ""; return entry }()}},
		{name: "missing action", request: agent.AuditRequest{PersonServer: "https://ps.example", Entry: func() aauth.AuditEntry { entry := valid; entry.Action = ""; return entry }()}},
		{name: "invalid parameters", request: agent.AuditRequest{PersonServer: "https://ps.example", Entry: func() aauth.AuditEntry { entry := valid; entry.Parameters = json.RawMessage(`[]`); return entry }()}},
		{name: "signed body too large", request: agent.AuditRequest{PersonServer: "https://ps.example", Entry: func() aauth.AuditEntry {
			entry := valid
			entry.Result = json.RawMessage(`{"value":"` + strings.Repeat("v", 1<<20) + `"}`)
			return entry
		}()}},
	} {
		t.Run(test.name, func(t *testing.T) {
			protocol := newTestProtocol(t)
			calls := 0
			client := protocol.newClientWithHTTPClient(t, &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
				calls++
				return nil, errors.New("unexpected network request")
			})})
			if err := client.SubmitAudit(context.Background(), test.request); err == nil {
				t.Fatal("SubmitAudit accepted invalid input")
			}
			if calls != 0 {
				t.Fatalf("network calls = %d, want 0", calls)
			}
		})
	}
}

func TestSubmitAuditRejectsSubagentBeforeNetwork(t *testing.T) {
	protocol := newTestProtocol(t)
	childID := "aauth:reader+audit@ap.example"
	childKey := testSigningKey(t, "audit-child-key", 123)
	compact, err := aauth.MintAgentToken(
		protocol.agentProviderID,
		protocol.agentProviderKey,
		aauth.AgentTokenRequest{
			Agent: childID, ParentAgent: protocol.agentID, PersonServer: protocol.personServerID,
			PublicKey: childKey.PublicJWK(), Lifetime: time.Hour,
		},
		protocol.now,
		"audit-child-token",
	)
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	client, err := agent.New(context.Background(), agent.Config{
		Identifier: childID, SigningKey: childKey, AgentToken: compact, KeyResolver: protocol.resolver,
		HTTPClient: &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
			calls++
			return nil, errors.New("subagent reached network")
		})},
		Clock: protocol.clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := client.SubmitAudit(context.Background(), agent.AuditRequest{
		PersonServer: protocol.personServerID, Entry: validAgentAuditEntry(),
	}); err == nil {
		t.Fatal("subagent submitted an audit directly")
	}
	if calls != 0 {
		t.Fatalf("subagent network calls = %d, want 0", calls)
	}
}

func TestSubmitAuditRequiresValidDiscoveredEndpoint(t *testing.T) {
	for _, test := range []struct {
		name           string
		metadataIssuer string
		endpoint       string
	}{
		{name: "missing endpoint", metadataIssuer: "https://ps.example"},
		{name: "invalid endpoint", metadataIssuer: "https://ps.example", endpoint: "http://ps.example/audit"},
		{name: "wrong metadata issuer", metadataIssuer: "https://other-ps.example", endpoint: auditEndpoint},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newAuditFixture(t)
			fixture.metadataIssuer = test.metadataIssuer
			fixture.auditEndpoint = test.endpoint
			if err := fixture.client.SubmitAudit(context.Background(), agent.AuditRequest{
				PersonServer: fixture.protocol.personServerID, Entry: validAgentAuditEntry(),
			}); err == nil {
				t.Fatal("SubmitAudit accepted invalid metadata")
			}
			if fixture.metadataCalls != 1 || fixture.submitCalls != 0 {
				t.Fatalf("calls = metadata %d, submit %d", fixture.metadataCalls, fixture.submitCalls)
			}
		})
	}
}

func TestSubmitAuditPostHandoffUnverifiableOutcomeIsUncertain(t *testing.T) {
	transportFailure := errors.New("connection reset after audit handoff")
	for _, test := range []struct {
		name     string
		response func(*http.Request) (*http.Response, error)
	}{
		{name: "transport failure", response: func(*http.Request) (*http.Response, error) { return nil, transportFailure }},
		{name: "200", response: func(request *http.Request) (*http.Response, error) {
			return jsonResponse(request, http.StatusOK, map[string]any{}), nil
		}},
		{name: "202", response: func(request *http.Request) (*http.Response, error) {
			return jsonResponse(request, http.StatusAccepted, map[string]any{"status": "pending"}), nil
		}},
		{name: "204", response: func(request *http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusNoContent, Status: http.StatusText(http.StatusNoContent), Request: request, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(""))}, nil
		}},
		{name: "500", response: func(request *http.Request) (*http.Response, error) {
			return problemResponse(request, &aauth.ProblemError{Status: http.StatusInternalServerError, Code: "server_error", Detail: "storage outcome unavailable"}), nil
		}},
		{name: "503", response: func(request *http.Request) (*http.Response, error) {
			return problemResponse(request, &aauth.ProblemError{Status: http.StatusServiceUnavailable, Code: "server_error", Detail: "temporarily unavailable"}), nil
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newAuditFixture(t)
			fixture.submit = test.response
			err := fixture.client.SubmitAudit(context.Background(), agent.AuditRequest{
				PersonServer: fixture.protocol.personServerID, Entry: validAgentAuditEntry(),
			})
			var uncertain *agent.AuditSubmissionUncertainError
			if !errors.As(err, &uncertain) {
				t.Fatalf("error = %T %v, want AuditSubmissionUncertainError", err, err)
			}
			if test.name == "transport failure" && !errors.Is(err, transportFailure) {
				t.Fatalf("transport error = %v, want wrapped transport failure", err)
			}
			if fixture.submitCalls != 1 || fixture.otherCalls != 0 {
				t.Fatalf("calls = submit %d, other %d", fixture.submitCalls, fixture.otherCalls)
			}
		})
	}
}

func TestSubmitAuditAcceptsAny201AcknowledgementRepresentation(t *testing.T) {
	for _, test := range []struct {
		name     string
		response func(*http.Request) (*http.Response, error)
	}{
		{name: "JSON receipt", response: func(request *http.Request) (*http.Response, error) {
			return jsonResponse(request, http.StatusCreated, map[string]any{"id": "optional-receipt"}), nil
		}},
		{name: "declared body length", response: func(request *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusCreated, Status: http.StatusText(http.StatusCreated),
				ContentLength: 1, Request: request, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("x")),
			}, nil
		}},
		{name: "unreadable optional body", response: func(request *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusCreated, Status: http.StatusText(http.StatusCreated),
				Request: request, Header: make(http.Header), Body: auditReadErrorBody{},
			}, nil
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newAuditFixture(t)
			fixture.submit = test.response
			if err := fixture.client.SubmitAudit(context.Background(), agent.AuditRequest{
				PersonServer: fixture.protocol.personServerID, Entry: validAgentAuditEntry(),
			}); err != nil {
				t.Fatalf("201 acknowledgement = %v", err)
			}
			if fixture.submitCalls != 1 || fixture.otherCalls != 0 {
				t.Fatalf("calls = submit %d, other %d", fixture.submitCalls, fixture.otherCalls)
			}
		})
	}
}

func TestSubmitAuditDefiniteClientFailureRemainsTyped(t *testing.T) {
	fixture := newAuditFixture(t)
	fixture.submit = func(request *http.Request) (*http.Response, error) {
		return problemResponse(request, &aauth.ProblemError{
			Status: http.StatusConflict, Code: "mission_terminated", Detail: "mission is no longer active",
		}), nil
	}
	err := fixture.client.SubmitAudit(context.Background(), agent.AuditRequest{
		PersonServer: fixture.protocol.personServerID, Entry: validAgentAuditEntry(),
	})
	if err == nil {
		t.Fatal("SubmitAudit accepted definite client failure")
	}
	var problem *aauth.ProblemError
	if !errors.As(err, &problem) || problem.Status != http.StatusConflict || problem.Code != "mission_terminated" {
		t.Fatalf("error = %T %v, want typed mission_terminated problem", err, err)
	}
	var uncertain *agent.AuditSubmissionUncertainError
	if errors.As(err, &uncertain) {
		t.Fatalf("definite client failure became uncertain: %v", err)
	}
	if fixture.submitCalls != 1 {
		t.Fatalf("submit calls = %d, want 1", fixture.submitCalls)
	}
}

func TestSubmitAuditServerFailureBodyIsNotCallerOwned(t *testing.T) {
	fixture := newAuditFixture(t)
	body := &trackingReadCloser{Reader: strings.NewReader(`{"error":"server_error","detail":"storage outcome unavailable"}`)}
	fixture.submit = func(request *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusInternalServerError, Status: http.StatusText(http.StatusInternalServerError),
			Request: request, Header: http.Header{"Content-Type": []string{"application/problem+json"}}, Body: body,
		}, nil
	}
	err := fixture.client.SubmitAudit(context.Background(), agent.AuditRequest{
		PersonServer: fixture.protocol.personServerID, Entry: validAgentAuditEntry(),
	})
	var uncertain *agent.AuditSubmissionUncertainError
	if !errors.As(err, &uncertain) {
		t.Fatalf("error = %T %v, want AuditSubmissionUncertainError", err, err)
	}
	if !body.closed {
		t.Fatal("5xx response body remained caller-owned")
	}
}

func TestAuditSubmissionUncertainErrorIsZeroSafe(t *testing.T) {
	t.Parallel()

	var failure *agent.AuditSubmissionUncertainError
	if failure.Error() == "" || failure.Unwrap() != nil {
		t.Fatalf("zero uncertain error = %q, unwrap %v", failure.Error(), failure.Unwrap())
	}
}

type auditFixture struct {
	t              *testing.T
	protocol       *testProtocol
	client         *agent.Client
	metadataIssuer string
	auditEndpoint  string
	metadataCalls  int
	submitCalls    int
	otherCalls     int
	submit         func(*http.Request) (*http.Response, error)
}

func newAuditFixture(t *testing.T) *auditFixture {
	t.Helper()
	fixture := &auditFixture{
		t: t, protocol: newTestProtocol(t), metadataIssuer: "https://ps.example", auditEndpoint: auditEndpoint,
	}
	fixture.client = fixture.protocol.newClientWithHTTPClient(t, &http.Client{Transport: roundTripperFunc(fixture.roundTrip)})
	return fixture
}

func (fixture *auditFixture) roundTrip(request *http.Request) (*http.Response, error) {
	switch request.URL.String() {
	case fixture.protocol.personServerID + "/.well-known/aauth-person.json":
		fixture.metadataCalls++
		return jsonResponse(request, http.StatusOK, map[string]any{
			"issuer": fixture.metadataIssuer, "person_token_endpoint": fixture.protocol.personTokenEndpoint,
			"auth_token_endpoint": fixture.protocol.authTokenEndpoint, "audit_endpoint": fixture.auditEndpoint,
		}), nil
	case auditEndpoint:
		fixture.submitCalls++
		if fixture.submit == nil {
			fixture.t.Fatal("unexpected audit submission")
		}
		return fixture.submit(request)
	default:
		fixture.otherCalls++
		fixture.t.Fatalf("unexpected request: %s %s", request.Method, request.URL)
		return nil, errors.New("unexpected request")
	}
}

func validAgentAuditEntry() aauth.AuditEntry {
	return aauth.AuditEntry{
		MissionS256: aauth.MissionS256([]byte("agent audit mission")),
		Action:      "WebSearch",
		Description: "Searched for the reviewed flight options.",
		Parameters:  json.RawMessage(`{"query":"flights to Tokyo"}`),
		Result:      json.RawMessage(`{"count":12}`),
	}
}

type auditReadErrorBody struct{}

func (auditReadErrorBody) Read([]byte) (int, error) { return 0, errors.New("response read failed") }
func (auditReadErrorBody) Close() error             { return nil }
