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
		"resource-token-5",
		"auth-token-5",
		"resource-token-6",
		"resource-token-7",
		"resource-token-8",
		"resource-token-9",
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

	deferPersonAuthorization := false
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
		InteractionRequired: func(_ context.Context, _ aauth.AuthorizationRequest) (bool, error) {
			return deferPersonAuthorization, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	operationCalls := 0
	documentStoreConfig := reference.FileR3DocumentStoreConfig{
		Directory:        privateTestDirectory(t),
		Clock:            clock,
		MaxDocuments:     8,
		MaxBytes:         8 << 20,
		MaxDocumentBytes: 1 << 20,
	}
	openDocumentStore := func() reference.R3DocumentStore {
		store, storeErr := reference.OpenFileR3DocumentStore(documentStoreConfig)
		if storeErr != nil {
			t.Fatal(storeErr)
		}
		return store
	}
	newResource := func(store reference.R3DocumentStore) *reference.Resource {
		resource, resourceErr := reference.NewResource(reference.ResourceConfig{
			Identifier:      "https://resource.example",
			AccessServer:    "https://as.example",
			SigningKey:      resourceKey,
			KeyResolver:     keyResolver,
			Clock:           clock,
			NewID:           ids,
			Scopes:          []string{"records.read"},
			R3DocumentStore: store,
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
			R3RequiredForRequest: func(
				_ context.Context,
				request *http.Request,
			) (bool, error) {
				return strings.HasPrefix(request.URL.Path, "/records"), nil
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
		if resourceErr != nil {
			t.Fatal(resourceErr)
		}
		return resource
	}
	resource := newResource(openDocumentStore())

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

	accessServerHandler := accessServer.Handler()
	var accessServerTokenOverride string
	interceptedAccessServer := http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if accessServerTokenOverride == "" || request.Method != http.MethodPost || request.URL.Path != "/token" {
			accessServerHandler.ServeHTTP(response, request)
			return
		}
		response.Header().Set("Content-Type", "application/json")
		response.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(response).Encode(map[string]any{
			"auth_token": accessServerTokenOverride,
			"expires_in": 300,
		})
	})
	personServerHandler := personServer.Handler()
	externalDeferredR3 := false
	interceptedPersonServer := http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if !externalDeferredR3 || request.Method != http.MethodPost || request.URL.Path != "/token" {
			personServerHandler.ServeHTTP(response, request)
			return
		}
		response.Header().Set("Location", "/pending/external-r3")
		response.Header().Set("Retry-After", "0")
		response.Header().Set("Cache-Control", "no-store")
		response.Header().Set(
			"AAuth-Requirement",
			`requirement=interaction; url="https://ps.example/interaction/external-r3"; code="A1B2-C3D4"`,
		)
		response.WriteHeader(http.StatusAccepted)
		_, _ = io.WriteString(response, `{"status":"interacting"}`)
	})
	gateway := newLogicalGateway(t, map[string]http.Handler{
		"ap.example":       ap.Handler(),
		"ps.example":       interceptedPersonServer,
		"as.example":       interceptedAccessServer,
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
	missionHeader, err := mission.Reference.Header()
	if err != nil {
		t.Fatal(err)
	}
	ambiguousAuthorizeBody := []byte(
		`{"scope":"records.read",` +
			`"r3_operations":{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"list_records"}]},` +
			`"R3_OPERATIONS":{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"list_records"}]}}`,
	)
	ambiguousAuthorizeRequest, err := http.NewRequest(
		http.MethodPost,
		"https://resource.example/authorize",
		strings.NewReader(string(ambiguousAuthorizeBody)),
	)
	if err != nil {
		t.Fatal(err)
	}
	ambiguousAuthorizeRequest.Header.Set("Content-Type", "application/json")
	ambiguousAuthorizeRequest.Header.Set("AAuth-Mission", missionHeader)
	if err := aauth.SignRequest(
		ambiguousAuthorizeRequest,
		agentKey,
		agentToken,
		clock,
	); err != nil {
		t.Fatal(err)
	}
	ambiguousAuthorizeResponse, err := protocolClient.Do(ambiguousAuthorizeRequest)
	if err != nil {
		t.Fatal(err)
	}
	defer ambiguousAuthorizeResponse.Body.Close()
	if ambiguousAuthorizeResponse.StatusCode != http.StatusBadRequest {
		body, _ := io.ReadAll(ambiguousAuthorizeResponse.Body)
		t.Fatalf(
			"case-ambiguous R3 authorization status = %d, want 400; body = %s",
			ambiguousAuthorizeResponse.StatusCode,
			body,
		)
	}
	resourceGrant, err := agent.RequestResourceTokenR3(
		context.Background(),
		"https://resource.example/authorize",
		[]string{"records.read"},
		mission,
		requestedOperations,
	)
	if err != nil {
		t.Fatal(err)
	}
	// Reconstruct the resource and its document store after the resource token
	// exists but before the access server fetches the exact document.
	resource = newResource(openDocumentStore())
	resourceHandler = resource.Handler()
	missingBinding := resourceGrant
	missingBinding.RequestedR3 = nil
	if _, err := agent.RequestTokenAuthorization(
		context.Background(),
		"https://ps.example/token",
		missingBinding,
	); err == nil || !strings.Contains(err.Error(), "missing the requested R3 operation binding") {
		t.Fatalf("missing persisted R3 binding error = %v", err)
	}
	grant, err := agent.ExchangeResourceToken(
		context.Background(),
		"https://ps.example/token",
		resourceGrant,
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
	scopeOnlyToken, err := aauth.MintAuthToken(accessKey, aauth.AuthTokenClaims{
		Issuer:       "https://as.example",
		DWK:          aauth.AccessDiscoveryDocument,
		Audience:     "https://resource.example",
		JTI:          "scope-only-auth-token",
		Agent:        "aauth:planner@ap.example",
		Confirmation: aauth.Confirmation{JWK: agentKey.PublicJWK()},
		IssuedAt:     now.Unix(),
		ExpiresAt:    now.Add(time.Hour).Unix(),
		Subject:      "federated-pairwise-user",
		Scope:        "records.read",
		Mission:      grant.Claims.Mission,
	})
	if err != nil {
		t.Fatal(err)
	}
	scopeOnlyResponse, err := agent.DoAuthorized(
		context.Background(),
		http.MethodGet,
		"https://resource.example/records",
		reference.Grant{
			Resource:  "https://resource.example",
			AuthToken: scopeOnlyToken,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer scopeOnlyResponse.Body.Close()
	if scopeOnlyResponse.StatusCode != http.StatusForbidden {
		body, _ := io.ReadAll(scopeOnlyResponse.Body)
		t.Fatalf("scope-only R3-required operation status = %d, body = %s", scopeOnlyResponse.StatusCode, body)
	}
	if operationCalls != 1 {
		t.Fatalf("scope-only token ran R3-required operation; calls = %d", operationCalls)
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

	// Proposal documents are a later, exact-call stage. They must never be
	// accepted as class documents and projected into an ambient resource token.
	mutateR3Response = false
	currentDocumentBytes = []byte(
		`{"vocabulary":"urn:aauth:vocabulary:mcp",` +
			`"operations":[{"tool":"list_records"}],` +
			`"parameters":{"record_id":"one"}}`,
	)
	fetchesBeforeProposalClass := r3Fetches
	policyCallsBeforeProposalClass := accessPolicyCalls
	_, err = agent.RequestResourceTokenR3(
		context.Background(),
		"https://resource.example/authorize",
		[]string{"records.read"},
		mission,
		requestedOperations,
	)
	if err == nil {
		t.Fatal("resource accepted a per-call proposal as a class R3 document")
	}
	if r3Fetches != fetchesBeforeProposalClass || accessPolicyCalls != policyCallsBeforeProposalClass {
		t.Fatalf(
			"proposal class confusion escaped resource validation: fetches %d -> %d, policy %d -> %d",
			fetchesBeforeProposalClass,
			r3Fetches,
			policyCallsBeforeProposalClass,
			accessPolicyCalls,
		)
	}
	currentDocumentBytes = []byte(
		`{"version":"3","vocabulary":"urn:aauth:vocabulary:mcp",` +
			`"operations":[{"tool":"list_records"}],` +
			`"display":{"summary":"Read records under the revised definition"}}`,
	)

	now = now.Add(time.Second)
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

	// A persisted resource grant must retain the agent's requested operation
	// set. Otherwise reconstructing it would silently remove the only check
	// that prevents a valid access server from granting the document superset.
	now = now.Add(time.Second)
	currentDocumentBytes = []byte(
		`{"version":"4","vocabulary":"urn:aauth:vocabulary:mcp",` +
			`"operations":[{"tool":"list_records"},{"tool":"delete_record"}],` +
			`"display":{"summary":"Read or delete records"}}`,
	)
	overbroadResourceGrant, err := agent.RequestResourceTokenR3(
		context.Background(),
		"https://resource.example/authorize",
		[]string{"records.read"},
		mission,
		requestedOperations,
	)
	if err != nil {
		t.Fatal(err)
	}
	encodedGrant, err := json.Marshal(overbroadResourceGrant)
	if err != nil {
		t.Fatal(err)
	}
	var restoredGrant reference.ResourceGrant
	if err := json.Unmarshal(encodedGrant, &restoredGrant); err != nil {
		t.Fatal(err)
	}
	if _, err := agent.ExchangeResourceToken(
		context.Background(),
		"https://ps.example/token",
		restoredGrant,
	); err == nil || !strings.Contains(err.Error(), "outside the agent request") {
		t.Fatalf("reconstructed overgrant error = %v", err)
	}

	// This profile does not implement deferred R3 authorization. It must be
	// refused before the agent reports usable or pending state.
	now = now.Add(time.Second)
	currentDocumentBytes = documentBytes
	deferredResourceGrant, err := agent.RequestResourceTokenR3(
		context.Background(),
		"https://resource.example/authorize",
		[]string{"records.read"},
		mission,
		requestedOperations,
	)
	if err != nil {
		t.Fatal(err)
	}
	deferPersonAuthorization = true
	_, err = agent.ExchangeResourceToken(
		context.Background(),
		"https://ps.example/token",
		deferredResourceGrant,
	)
	deferPersonAuthorization = false
	if err == nil || !strings.Contains(err.Error(), "deferred R3 authorization is not implemented") {
		t.Fatalf("deferred R3 error = %v", err)
	}

	now = now.Add(time.Second)
	externalDeferredResourceGrant, err := agent.RequestResourceTokenR3(
		context.Background(),
		"https://resource.example/authorize",
		[]string{"records.read"},
		mission,
		requestedOperations,
	)
	if err != nil {
		t.Fatal(err)
	}
	externalDeferredR3 = true
	externalAuthorization, err := agent.RequestTokenAuthorization(
		context.Background(),
		"https://ps.example/token",
		externalDeferredResourceGrant,
	)
	externalDeferredR3 = false
	if err == nil || !strings.Contains(err.Error(), "deferred R3 authorization is not implemented") {
		t.Fatalf("external deferred R3 error = %v", err)
	}
	if externalAuthorization.Grant != nil || externalAuthorization.Pending != nil {
		t.Fatalf("external deferred R3 exposed authorization state = %#v", externalAuthorization)
	}

	now = now.Add(time.Second)
	conditionalResourceGrant, err := agent.RequestResourceTokenR3(
		context.Background(),
		"https://resource.example/authorize",
		[]string{"records.read"},
		mission,
		requestedOperations,
	)
	if err != nil {
		t.Fatal(err)
	}
	emptyGrant := &aauth.R3OperationSet{
		Vocabulary: aauth.R3VocabularyMCP,
		Operations: []json.RawMessage{},
	}
	conditionalGrant := aauth.R3OperationSet{
		Vocabulary: aauth.R3VocabularyMCP,
		Operations: []json.RawMessage{json.RawMessage(`{"tool":"delete_record"}`)},
	}
	accessServerTokenOverride, err = aauth.MintAuthToken(accessKey, aauth.AuthTokenClaims{
		Issuer:        "https://as.example",
		DWK:           aauth.AccessDiscoveryDocument,
		Audience:      "https://resource.example",
		JTI:           "external-conditional-auth-token",
		Agent:         "aauth:planner@ap.example",
		Confirmation:  aauth.Confirmation{JWK: agentKey.PublicJWK()},
		IssuedAt:      now.Unix(),
		ExpiresAt:     conditionalResourceGrant.Claims.ExpiresAt,
		Subject:       "federated-pairwise-user",
		Scope:         conditionalResourceGrant.Claims.Scope,
		Mission:       conditionalResourceGrant.Claims.Mission,
		R3URI:         conditionalResourceGrant.Claims.R3URI,
		R3S256:        conditionalResourceGrant.Claims.R3S256,
		R3Granted:     emptyGrant,
		R3Conditional: &conditionalGrant,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = agent.ExchangeResourceToken(
		context.Background(),
		"https://ps.example/token",
		conditionalResourceGrant,
	)
	accessServerTokenOverride = ""
	if err == nil || !strings.Contains(err.Error(), "conditional outside the agent request") {
		t.Fatalf("overbroad conditional R3 error = %v", err)
	}

	now = now.Add(time.Second)
	resource = newResource(&refusingR3DocumentStore{
		R3DocumentStore: openDocumentStore(),
		err:             reference.ErrR3DocumentCapacity,
	})
	resourceHandler = resource.Handler()
	if _, err := agent.RequestResourceTokenR3(
		context.Background(),
		"https://resource.example/authorize",
		[]string{"records.read"},
		mission,
		requestedOperations,
	); err == nil || !strings.Contains(err.Error(), "capacity is exhausted") {
		t.Fatalf("pre-token custody refusal error = %v", err)
	}
}

type refusingR3DocumentStore struct {
	reference.R3DocumentStore
	err error
}

func (store *refusingR3DocumentStore) Retain(
	context.Context,
	string,
	[]byte,
	time.Time,
) error {
	return store.err
}
