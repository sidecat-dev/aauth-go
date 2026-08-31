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

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

func TestInteractionQuestionConfigurationAndExactAnswerInBothPersonServerModes(t *testing.T) {
	for _, mode := range []string{"direct", "federated"} {
		mode := mode
		t.Run(mode, func(t *testing.T) {
			protocol := newInteractionQuestionProtocol(t)
			without := protocol.newServer(t, mode, nil)
			metadata := interactionQuestionMetadata(t, without)
			if _, present := metadata["interaction_endpoint"]; present {
				t.Fatal("interaction_endpoint advertised without explicit configuration")
			}
			response := interactionQuestionRequest(t, protocol, without, protocol.agentKey, protocol.agentToken,
				`{"type":"question","question":"Which route?"}`)
			if response.Code != http.StatusNotFound {
				t.Fatalf("unconfigured route = %d %s", response.Code, response.Body.String())
			}
			if _, err := protocol.construct(mode, &InteractionQuestionConfig{}); err == nil {
				t.Fatal("question configuration without policy was accepted")
			}

			body := []byte("{\n" +
				`  "question": "Which **route** should I take?",` + "\n" +
				`  "type": "question",` + "\n" +
				`  "description": "A route decision is required.",` + "\n" +
				`  "extension": {"trace": true}` + "\n" +
				"}")
			var policyRequest InteractionQuestionPolicyRequest
			calls := 0
			server := protocol.newServer(t, mode, &InteractionQuestionConfig{
				Answer: func(_ context.Context, request InteractionQuestionPolicyRequest) (InteractionQuestionDecision, error) {
					calls++
					policyRequest = request
					return InteractionQuestionDecision{Answer: "Take the northern route."}, nil
				},
			})
			metadata = interactionQuestionMetadata(t, server)
			if metadata["interaction_endpoint"] != protocol.personServerID+"/interaction" {
				t.Fatalf("interaction_endpoint = %q", metadata["interaction_endpoint"])
			}
			response = interactionQuestionRequest(t, protocol, server, protocol.agentKey, protocol.agentToken, string(body))
			if response.Code != http.StatusOK || response.Body.String() != `{"answer":"Take the northern route."}` ||
				response.Header().Get("Content-Type") != "application/json" ||
				response.Header().Get("Cache-Control") != "no-store" {
				t.Fatalf("question response = %d headers=%#v body=%q", response.Code, response.Header(), response.Body.String())
			}
			if calls != 1 || policyRequest.Agent != protocol.agentID ||
				policyRequest.Document.Question.Question != "Which **route** should I take?" ||
				policyRequest.Document.Question.Description != "A route decision is required." ||
				!bytes.Equal(policyRequest.Document.ExactJSON, body) || !policyRequest.ReceivedAt.Equal(protocol.now) {
				t.Fatalf("policy request = %#v, calls=%d", policyRequest, calls)
			}
			body[0] = '['
			if policyRequest.Document.ExactJSON[0] != '{' {
				t.Fatal("policy request aliases caller body")
			}
		})
	}
}

func TestInteractionQuestionRejectsUnsupportedShapeMissionAndTopologyBeforePolicy(t *testing.T) {
	protocol := newInteractionQuestionProtocol(t)
	policyCalls := 0
	server := protocol.newServer(t, "direct", &InteractionQuestionConfig{
		Answer: func(context.Context, InteractionQuestionPolicyRequest) (InteractionQuestionDecision, error) {
			policyCalls++
			return InteractionQuestionDecision{Answer: "unexpected"}, nil
		},
	})
	mission := aauth.MissionS256([]byte("question mission"))
	for _, body := range []string{
		`[]`,
		`{"type":"question"}`,
		`{"type":"interaction","url":"https://resource.example/act","code":"ABCD-EFGH"}`,
		`{"type":"payment","url":"https://resource.example/pay","code":"ABCD-EFGH"}`,
		`{"type":"question","question":"Choose?","mission_s256":"` + mission + `"}`,
		`{"type":"question","question":"Choose?","url":"https://resource.example/act"}`,
	} {
		response := interactionQuestionRequest(t, protocol, server, protocol.agentKey, protocol.agentToken, body)
		if response.Code != http.StatusBadRequest {
			t.Fatalf("unsupported question body %s = %d %s", body, response.Code, response.Body.String())
		}
	}

	unsigned := httptest.NewRequest(http.MethodPost, protocol.personServerID+"/interaction", strings.NewReader(
		`{"type":"question","question":"Choose?"}`,
	))
	unsigned.Header.Set("Content-Type", "application/json")
	unsignedResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(unsignedResponse, unsigned)
	if unsignedResponse.Code != http.StatusUnauthorized {
		t.Fatalf("unsigned question = %d %s", unsignedResponse.Code, unsignedResponse.Body.String())
	}

	childKey := personServerTestKey(t, "interaction-question-child")
	childToken, err := aauth.MintAgentToken(protocol.providerID, protocol.providerKey, aauth.AgentTokenRequest{
		Agent: "aauth:operator+child@provider.example", ParentAgent: protocol.agentID,
		PersonServer: protocol.personServerID, PublicKey: childKey.PublicJWK(), Lifetime: time.Minute,
	}, protocol.now, "interaction-question-child-token")
	if err != nil {
		t.Fatal(err)
	}
	child := interactionQuestionRequest(t, protocol, server, childKey, childToken,
		`{"type":"question","question":"Choose?"}`)
	if child.Code != http.StatusBadRequest {
		t.Fatalf("child question = %d %s", child.Code, child.Body.String())
	}

	oversized := `{"type":"question","question":"` + strings.Repeat("q", int(maxRequestBytes)) + `"}`
	oversizedRequest := httptest.NewRequest(
		http.MethodPost, protocol.personServerID+"/interaction", strings.NewReader(oversized),
	)
	oversizedRequest.Header.Set("Content-Type", "application/json")
	if err := signaturekey.SignJWTRequestWithOptions(
		oversizedRequest, protocol.agentKey, protocol.agentToken, protocol.clock,
		signaturekey.SignOptions{
			AdditionalComponents: []string{"content-type", "content-digest"},
			MaxBodyBytes:         int64(len(oversized) + 1),
		},
	); err != nil {
		t.Fatal(err)
	}
	oversizedResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(oversizedResponse, oversizedRequest)
	if oversizedResponse.Code == http.StatusOK {
		t.Fatalf("oversized question = %d %s", oversizedResponse.Code, oversizedResponse.Body.String())
	}
	if policyCalls != 0 {
		t.Fatalf("invalid requests reached policy %d times", policyCalls)
	}
}

func TestInteractionQuestionMapsUnreachableAndOperationalPolicyFailures(t *testing.T) {
	for _, test := range []struct {
		name   string
		answer InteractionQuestionDecision
		err    error
		status int
		code   string
	}{
		{name: "unreachable", err: ErrInteractionUserUnreachable, status: http.StatusForbidden, code: "user_unreachable"},
		{name: "operational", err: errors.New("question channel failed"), status: http.StatusInternalServerError, code: "server_error"},
		{name: "invalid answer", answer: InteractionQuestionDecision{Answer: string([]byte{0xff})}, status: http.StatusInternalServerError, code: "server_error"},
	} {
		t.Run(test.name, func(t *testing.T) {
			protocol := newInteractionQuestionProtocol(t)
			server := protocol.newServer(t, "direct", &InteractionQuestionConfig{
				Answer: func(context.Context, InteractionQuestionPolicyRequest) (InteractionQuestionDecision, error) {
					return test.answer, test.err
				},
			})
			response := interactionQuestionRequest(t, protocol, server, protocol.agentKey, protocol.agentToken,
				`{"type":"question","question":"Which route?"}`)
			assertAuditProblem(t, response, test.status, test.code, "", "")
		})
	}
}

type interactionQuestionProtocol struct {
	now            time.Time
	clock          aauth.Clock
	providerID     string
	personServerID string
	agentID        string
	providerKey    jose.SigningKey
	personKey      jose.SigningKey
	agentKey       jose.SigningKey
	resolver       signaturekey.KeyResolver
	agentToken     string
	tokens         TokenStore
}

func newInteractionQuestionProtocol(t *testing.T) *interactionQuestionProtocol {
	t.Helper()
	protocol := &interactionQuestionProtocol{
		now:        time.Date(2026, 9, 1, 1, 0, 0, 0, time.UTC),
		providerID: "https://provider.example", personServerID: "https://person.example",
		agentID: "aauth:operator@provider.example", providerKey: personServerTestKey(t, "question-provider"),
		personKey: personServerTestKey(t, "question-person"), agentKey: personServerTestKey(t, "question-agent"),
		tokens: newMemoryTokenStore(),
	}
	protocol.clock = aauth.ClockFunc(func() time.Time { return protocol.now })
	protocol.resolver = signaturekey.StaticKeyResolver{
		{Issuer: protocol.providerID, DiscoveryDocument: aauth.AgentDiscoveryDocument, KeyID: protocol.providerKey.ID()}: protocol.providerKey.PublicJWK(),
	}
	var err error
	protocol.agentToken, err = aauth.MintAgentToken(protocol.providerID, protocol.providerKey, aauth.AgentTokenRequest{
		Agent: protocol.agentID, PersonServer: protocol.personServerID,
		PublicKey: protocol.agentKey.PublicJWK(), Lifetime: time.Hour,
	}, protocol.now, "interaction-question-agent-token")
	if err != nil {
		t.Fatal(err)
	}
	return protocol
}

func (protocol *interactionQuestionProtocol) construct(
	mode string,
	questions *InteractionQuestionConfig,
) (*Server, error) {
	if mode == "federated" {
		return NewFederatedAuthorization(FederatedAuthorizationConfig{
			Issuer: protocol.personServerID, SigningKey: protocol.personKey, KeyResolver: protocol.resolver,
			Clock: protocol.clock, NewID: func() string { return "question-token" }, Tokens: protocol.tokens,
			HTTPClient: &http.Client{}, AccessServerEndpoint: func(context.Context, string) (string, error) {
				return "https://access.example/token", nil
			},
			BindPerson: func(context.Context, PersonTokenRequest) (Person, error) {
				return Person{Subject: "person", Lifetime: time.Minute}, nil
			},
			Consent: func(context.Context, AuthorizationRequest) error { return nil }, InteractionQuestion: questions,
		})
	}
	return NewPSAuthorization(PSAuthorizationConfig{
		Issuer: protocol.personServerID, SigningKey: protocol.personKey, KeyResolver: protocol.resolver,
		Clock: protocol.clock, NewID: func() string { return "question-token" }, Tokens: protocol.tokens,
		BindPerson: func(context.Context, PersonTokenRequest) (Person, error) {
			return Person{Subject: "person", Lifetime: time.Minute}, nil
		},
		Authorize: func(context.Context, AuthorizationRequest) (AuthorizationDecision, error) {
			return AuthorizationDecision{Scopes: []string{"read"}, Lifetime: time.Minute}, nil
		},
		InteractionQuestion: questions,
	})
}

func (protocol *interactionQuestionProtocol) newServer(t *testing.T, mode string, questions *InteractionQuestionConfig) *Server {
	t.Helper()
	server, err := protocol.construct(mode, questions)
	if err != nil {
		t.Fatal(err)
	}
	return server
}

func interactionQuestionRequest(
	t *testing.T,
	protocol *interactionQuestionProtocol,
	server *Server,
	key jose.SigningKey,
	token string,
	body string,
) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, protocol.personServerID+"/interaction", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	if err := signPersonServerTestRequest(request, key, token, protocol.clock); err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	return response
}

func interactionQuestionMetadata(t *testing.T, server *Server) map[string]string {
	t.Helper()
	request := httptest.NewRequest(http.MethodGet, "https://person.example/.well-known/aauth-person.json", nil)
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("metadata response = %d %s", response.Code, response.Body.String())
	}
	var metadata map[string]string
	if err := json.NewDecoder(response.Body).Decode(&metadata); err != nil {
		t.Fatal(err)
	}
	return metadata
}
