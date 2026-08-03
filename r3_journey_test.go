package aauth_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/reference"
)

func TestR3DirectGrantJourney(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 29, 9, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	ids := sequentialIDs(
		"agent-token",
		"resource-token",
		"auth-token",
		"resource-token-2",
		"auth-token-2",
		"resource-token-3",
		"auth-token-3",
		"resource-token-4",
	)
	apKey := testSigningKey(t, "ap-key")
	psKey := testSigningKey(t, "ps-key")
	accessKey := testSigningKey(t, "access-key")
	resourceKey := testSigningKey(t, "resource-key")
	agentKey := testSigningKey(t, "agent-key")
	requestedOperations := aauth.R3OperationSet{
		Vocabulary: aauth.R3VocabularyMCP,
		Operations: []json.RawMessage{json.RawMessage(`{"tool":"list_records"}`)},
	}
	documentBytes := []byte(
		`{"version":"2","vocabulary":"urn:aauth:vocabulary:mcp",` +
			`"operations":[{"tool":"list_records"}],` +
			`"display":{"summary":"Read the records needed for a report",` +
			`"data_accessed":"Record identifiers and titles"}}`,
	)
	currentDocumentBytes := documentBytes

	ap, err := reference.NewAgentProvider(reference.AgentProviderConfig{
		Identifier: "https://ap.example",
		SigningKey: apKey,
		Clock:      clock,
		NewID:      ids,
	})
	if err != nil {
		t.Fatal(err)
	}
	agentToken, err := ap.IssueAgentToken(aauth.AgentTokenRequest{
		Agent:        "aauth:planner@ap.example",
		PersonServer: "https://ps.example",
		PublicKey:    agentKey.PublicJWK(),
		Lifetime:     time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}

	protocolClient := &http.Client{}
	keyResolver, err := aauth.NewHTTPKeyResolver(aauth.HTTPKeyResolverConfig{
		Client: protocolClient,
		Clock:  clock,
		Admit: func(_ context.Context, endpoint string) error {
			for _, allowed := range []string{
				"https://ap.example/",
				"https://ps.example/",
				"https://as.example/",
				"https://resource.example/",
			} {
				if strings.HasPrefix(endpoint, allowed) {
					return nil
				}
			}
			return fmt.Errorf("endpoint outside trust boundary: %s", endpoint)
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	var auditRecords []aauth.R3AuditRecord
	auditFailure := false
	r3Admissions := 0
	var accessPolicyRequest aauth.AuthorizationRequest
	accessPolicyCalls := 0
	accessServer, err := reference.NewAccessServer(reference.AccessServerConfig{
		Identifier:   "https://as.example",
		SigningKey:   accessKey,
		KeyResolver:  keyResolver,
		Clock:        clock,
		NewID:        ids,
		R3HTTPClient: protocolClient,
		R3Audit: func(_ context.Context, record aauth.R3AuditRecord) error {
			if auditFailure {
				return fmt.Errorf("audit store unavailable")
			}
			auditRecords = append(auditRecords, record)
			return nil
		},
		R3Admit: func(_ context.Context, endpoint string) error {
			r3Admissions++
			if !strings.HasPrefix(endpoint, "https://resource.example/r3/") {
				return fmt.Errorf("R3 endpoint outside trust boundary: %s", endpoint)
			}
			return nil
		},
		TrustedPersonServer: func(_ context.Context, identifier string) error {
			if identifier != "https://ps.example" {
				return fmt.Errorf("untrusted person server %s", identifier)
			}
			return nil
		},
		AuthorizationPolicy: func(_ context.Context, request aauth.AuthorizationRequest) (aauth.AuthorizationDecision, error) {
			accessPolicyCalls++
			accessPolicyRequest = request
			if request.R3 == nil {
				return aauth.AuthorizationDecision{}, fmt.Errorf("R3 context is missing")
			}
			granted := request.R3.Document.OperationSet()
			return aauth.AuthorizationDecision{
				Subject:   "federated-pairwise-user",
				Scope:     request.Scope,
				R3Granted: &granted,
			}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	personServer, err := reference.NewPersonServer(reference.PersonServerConfig{
		Identifier:       "https://ps.example",
		SigningKey:       psKey,
		KeyResolver:      keyResolver,
		Clock:            clock,
		NewID:            ids,
		FederationClient: protocolClient,
		AccessServerEndpoint: func(_ context.Context, identifier string) (string, error) {
			if identifier != "https://as.example" {
				return "", fmt.Errorf("unknown access server %s", identifier)
			}
			return identifier + "/token", nil
		},
		MissionPolicy: func(_ context.Context, proposal aauth.MissionProposal) (aauth.MissionDecision, error) {
			return aauth.MissionDecision{Description: proposal.Description}, nil
		},
		AuthorizationPolicy: func(_ context.Context, request aauth.AuthorizationRequest) (aauth.AuthorizationDecision, error) {
			return aauth.AuthorizationDecision{
				Subject: "person-server-user",
				Scope:   request.Scope,
			}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	operationCalls := 0
	resource, err := reference.NewResource(reference.ResourceConfig{
		Identifier:   "https://resource.example",
		AccessServer: "https://as.example",
		SigningKey:   resourceKey,
		KeyResolver:  keyResolver,
		Clock:        clock,
		NewID:        ids,
		Scopes:       []string{"records.read"},
		R3Vocabularies: map[string]json.RawMessage{
			aauth.R3VocabularyMCP: json.RawMessage(`"https://resource.example/mcp"`),
		},
		R3DocumentForOperations: func(
			_ context.Context,
			operations aauth.R3OperationSet,
		) ([]byte, error) {
			if !operations.Equal(requestedOperations) {
				return nil, fmt.Errorf("unexpected requested operations: %#v", operations)
			}
			return currentDocumentBytes, nil
		},
		R3OperationForRequest: func(
			_ context.Context,
			request *http.Request,
		) (aauth.R3OperationSet, error) {
			var operation json.RawMessage
			switch request.URL.Path {
			case "/records":
				operation = json.RawMessage(`{"tool":"list_records"}`)
			case "/records/delete":
				operation = json.RawMessage(`{"tool":"delete_record"}`)
			default:
				return aauth.R3OperationSet{}, fmt.Errorf("unmapped operation path %s", request.URL.Path)
			}
			return aauth.R3OperationSet{
				Vocabulary: aauth.R3VocabularyMCP,
				Operations: []json.RawMessage{operation},
			}, nil
		},
		Operation: func(_ context.Context, _ aauth.AuthorizedRequest) (any, error) {
			operationCalls++
			return map[string]any{"records": []string{"one"}}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	resourceHandler := resource.Handler()
	r3Fetches := 0
	mutateR3Response := false
	interceptedResource := http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet || !strings.HasPrefix(request.URL.Path, "/r3/") {
			resourceHandler.ServeHTTP(response, request)
			return
		}
		r3Fetches++
		if !mutateR3Response {
			resourceHandler.ServeHTTP(response, request)
			return
		}
		recorder := httptest.NewRecorder()
		resourceHandler.ServeHTTP(recorder, request)
		for name, values := range recorder.Header() {
			for _, value := range values {
				response.Header().Add(name, value)
			}
		}
		body := append([]byte(nil), recorder.Body.Bytes()...)
		if recorder.Code == http.StatusOK && len(body) != 0 {
			body[len(body)-1] ^= 1
		}
		response.WriteHeader(recorder.Code)
		_, _ = response.Write(body)
	})

	gateway := newLogicalGateway(t, map[string]http.Handler{
		"ap.example":       ap.Handler(),
		"ps.example":       personServer.Handler(),
		"as.example":       accessServer.Handler(),
		"resource.example": interceptedResource,
	})
	defer gateway.Close()
	protocolClient.Transport = gateway.Client().Transport

	agent, err := reference.NewAgent(reference.AgentConfig{
		Identifier:  "aauth:planner@ap.example",
		SigningKey:  agentKey,
		AgentToken:  agentToken,
		KeyResolver: keyResolver,
		HTTPClient:  protocolClient,
		Clock:       clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	mission, err := agent.CreateMission(context.Background(), "https://ps.example/mission", aauth.MissionProposal{
		Description: "Read the federated records needed for the report.",
	})
	if err != nil {
		t.Fatal(err)
	}
	grant, err := agent.AuthorizeR3(
		context.Background(),
		"https://resource.example/authorize",
		"https://ps.example/token",
		[]string{"records.read"},
		mission,
		requestedOperations,
	)
	if err != nil {
		t.Fatal(err)
	}

	if grant.Claims.R3URI == "" ||
		grant.Claims.R3S256 != aauth.R3S256(documentBytes) ||
		grant.Claims.R3Granted == nil ||
		!grant.Claims.R3Granted.Equal(requestedOperations) ||
		grant.Claims.R3Conditional != nil {
		t.Fatalf("R3 auth-token claims = %#v", grant.Claims)
	}
	if accessPolicyRequest.R3 == nil ||
		!accessPolicyRequest.R3.Document.OperationSet().Equal(requestedOperations) ||
		string(accessPolicyRequest.R3.ExactBytes) != string(documentBytes) {
		t.Fatalf("access policy R3 input = %#v", accessPolicyRequest.R3)
	}
	if len(auditRecords) != 1 ||
		auditRecords[0].R3URI != grant.Claims.R3URI ||
		auditRecords[0].R3S256 != grant.Claims.R3S256 ||
		auditRecords[0].Agent != "aauth:planner@ap.example" ||
		auditRecords[0].TokenID != grant.Claims.JTI {
		t.Fatalf("R3 audit records = %#v", auditRecords)
	}
	if accessPolicyCalls != 1 || r3Fetches != 1 || r3Admissions != 1 {
		t.Fatalf(
			"issuance policy calls = %d, R3 fetches = %d, admissions = %d; want 1, 1, 1",
			accessPolicyCalls,
			r3Fetches,
			r3Admissions,
		)
	}

	metadataResponse, err := protocolClient.Get("https://resource.example/.well-known/aauth-resource.json")
	if err != nil {
		t.Fatal(err)
	}
	defer metadataResponse.Body.Close()
	var metadata struct {
		R3Vocabularies map[string]json.RawMessage `json:"r3_vocabularies"`
	}
	if err := json.NewDecoder(metadataResponse.Body).Decode(&metadata); err != nil {
		t.Fatal(err)
	}
	if string(metadata.R3Vocabularies[aauth.R3VocabularyMCP]) != `"https://resource.example/mcp"` {
		t.Fatalf("R3 vocabulary discovery = %s", metadata.R3Vocabularies[aauth.R3VocabularyMCP])
	}

	unsignedFetch, err := http.NewRequest(
		http.MethodGet,
		grant.Claims.R3URI,
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	unsignedResponse, err := protocolClient.Do(unsignedFetch)
	if err != nil {
		t.Fatal(err)
	}
	defer unsignedResponse.Body.Close()
	if unsignedResponse.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unsigned R3 fetch status = %d, want 401", unsignedResponse.StatusCode)
	}

	wrongServerFetch, err := http.NewRequest(http.MethodGet, grant.Claims.R3URI, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := aauth.SignRequestWithJWKSURI(
		wrongServerFetch,
		psKey,
		"https://ps.example",
		aauth.PersonDiscoveryDocument,
		clock,
	); err != nil {
		t.Fatal(err)
	}
	wrongServerResponse, err := protocolClient.Do(wrongServerFetch)
	if err != nil {
		t.Fatal(err)
	}
	defer wrongServerResponse.Body.Close()
	if wrongServerResponse.StatusCode != http.StatusUnauthorized {
		t.Fatalf("non-AS R3 fetch status = %d, want 401", wrongServerResponse.StatusCode)
	}
	fetchesBeforeProtectedCalls := r3Fetches

	response, err := agent.DoAuthorized(
		context.Background(),
		http.MethodGet,
		"https://resource.example/records",
		grant,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(response.Body)
		t.Fatalf("R3-granted operation status = %d, body = %s", response.StatusCode, body)
	}
	if operationCalls != 1 {
		t.Fatalf("granted operation calls = %d, want 1", operationCalls)
	}

	denied, err := agent.DoAuthorized(
		context.Background(),
		http.MethodDelete,
		"https://resource.example/records/delete",
		grant,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer denied.Body.Close()
	if denied.StatusCode != http.StatusForbidden {
		body, _ := io.ReadAll(denied.Body)
		t.Fatalf("ungranted operation status = %d, want 403; body = %s", denied.StatusCode, body)
	}
	if operationCalls != 1 {
		t.Fatalf("ungranted operation ran; calls = %d", operationCalls)
	}
	if r3Fetches != fetchesBeforeProtectedCalls {
		t.Fatalf("protected-call enforcement fetched R3: before = %d, after = %d", fetchesBeforeProtectedCalls, r3Fetches)
	}

	now = now.Add(time.Second)
	fetchesBeforeCachedIssuance := r3Fetches
	secondGrant, err := agent.AuthorizeR3(
		context.Background(),
		"https://resource.example/authorize",
		"https://ps.example/token",
		[]string{"records.read"},
		mission,
		requestedOperations,
	)
	if err != nil {
		t.Fatal(err)
	}
	if secondGrant.Claims.R3S256 != grant.Claims.R3S256 {
		t.Fatalf("cached issuance R3 hash = %q, want %q", secondGrant.Claims.R3S256, grant.Claims.R3S256)
	}
	if r3Fetches != fetchesBeforeCachedIssuance {
		t.Fatalf("same-hash issuance refetched R3: before = %d, after = %d", fetchesBeforeCachedIssuance, r3Fetches)
	}

	now = now.Add(time.Second)
	auditFailure = true
	auditsBeforeFailure := len(auditRecords)
	_, err = agent.AuthorizeR3(
		context.Background(),
		"https://resource.example/authorize",
		"https://ps.example/token",
		[]string{"records.read"},
		mission,
		requestedOperations,
	)
	if err == nil {
		t.Fatal("R3 authorization succeeded despite an issuance-audit failure")
	}
	if len(auditRecords) != auditsBeforeFailure {
		t.Fatalf("failed audit was recorded as successful: %#v", auditRecords)
	}

	now = now.Add(time.Second)
	auditFailure = false
	currentDocumentBytes = []byte(
		`{"version":"3","vocabulary":"urn:aauth:vocabulary:mcp",` +
			`"operations":[{"tool":"list_records"}],` +
			`"display":{"summary":"Read records under the revised definition"}}`,
	)
	mutateR3Response = true
	policyCallsBeforeMutation := accessPolicyCalls
	auditsBeforeMutation := len(auditRecords)
	_, err = agent.AuthorizeR3(
		context.Background(),
		"https://resource.example/authorize",
		"https://ps.example/token",
		[]string{"records.read"},
		mission,
		requestedOperations,
	)
	if err == nil {
		t.Fatal("R3 authorization succeeded with mutated document bytes")
	}
	if accessPolicyCalls != policyCallsBeforeMutation || len(auditRecords) != auditsBeforeMutation {
		t.Fatalf(
			"mutated R3 reached policy or audit: policy %d -> %d, audit %d -> %d",
			policyCallsBeforeMutation,
			accessPolicyCalls,
			auditsBeforeMutation,
			len(auditRecords),
		)
	}

	now = now.Add(time.Second)
	mutateR3Response = false
	fetchesBeforeInvalidOperation := r3Fetches
	policyCallsBeforeInvalidOperation := accessPolicyCalls
	_, err = agent.AuthorizeR3(
		context.Background(),
		"https://resource.example/authorize",
		"https://ps.example/token",
		[]string{"records.read"},
		mission,
		aauth.R3OperationSet{
			Vocabulary: aauth.R3VocabularyMCP,
			Operations: []json.RawMessage{json.RawMessage(`{"tool":"delete_record"}`)},
		},
	)
	if err == nil {
		t.Fatal("resource accepted an operation absent from its authoritative definition")
	}
	if r3Fetches != fetchesBeforeInvalidOperation || accessPolicyCalls != policyCallsBeforeInvalidOperation {
		t.Fatalf(
			"invalid operation escaped resource validation: fetches %d -> %d, policy %d -> %d",
			fetchesBeforeInvalidOperation,
			r3Fetches,
			policyCallsBeforeInvalidOperation,
			accessPolicyCalls,
		)
	}
}
