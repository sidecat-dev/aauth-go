package aauth_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/r3"
	"gitlab.com/sidecat-dev/aauth-go/reference"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

// R3 sections Resource Token Extensions, R3 Processing, Auth Token
// Extensions, Resource Enforcement, and R3 Document Access Restriction.
func TestCurrentDirectR3JourneySurvivesResourceReconstruction(t *testing.T) {
	now := time.Date(2026, 8, 29, 8, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	apKey := testSigningKey(t, "ap-key")
	psKey := testSigningKey(t, "ps-key")
	accessKey := testSigningKey(t, "access-key")
	resourceKey := testSigningKey(t, "resource-key")
	agentKey := testSigningKey(t, "agent-key")
	otherServerKey := testSigningKey(t, "other-server-key")

	ap, err := reference.NewAgentProvider(reference.AgentProviderConfig{
		Identifier: "https://ap.example", SigningKey: apKey, Clock: clock,
		NewID: sequentialIDs("agent-token"),
	})
	if err != nil {
		t.Fatal(err)
	}
	agentToken, err := ap.IssueAgentToken(aauth.AgentTokenRequest{
		Agent: "aauth:planner@ap.example", PersonServer: "https://ps.example",
		PublicKey: agentKey.PublicJWK(), Lifetime: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}

	protocolClient := &http.Client{}
	resolver, err := signaturekey.NewHTTPKeyResolver(signaturekey.HTTPKeyResolverConfig{
		Client: protocolClient,
		Clock:  clock,
		Admit: func(_ context.Context, endpoint string) error {
			for _, prefix := range []string{
				"https://ap.example/", "https://ps.example/", "https://as.example/", "https://resource.example/", "https://other.example/",
			} {
				if strings.HasPrefix(endpoint, prefix) {
					return nil
				}
			}
			return fmt.Errorf("endpoint outside test trust: %s", endpoint)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	admitR3 := func(_ context.Context, endpoint string) error {
		if !strings.HasPrefix(endpoint, "https://resource.example/r3/") {
			return fmt.Errorf("R3 endpoint outside resource: %s", endpoint)
		}
		return nil
	}

	documentBytes := []byte(`{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"list_records"}],"display":{"summary":"Use the selected records"}}`)
	requested := r3.OperationSet{
		Vocabulary: r3.VocabularyMCP,
		Operations: []json.RawMessage{json.RawMessage(`{"tool":"list_records"}`)},
	}
	personReviews := 0
	denyReview := false
	personTokenStore, err := reference.NewFilePersonTokenStore(t.TempDir() + "/person-tokens.json")
	if err != nil {
		t.Fatal(err)
	}
	missionStore, err := reference.NewFileMissionIssuanceStore(t.TempDir() + "/mission-issuance.json")
	if err != nil {
		t.Fatal(err)
	}
	personServer, err := reference.NewPersonServer(reference.PersonServerConfig{
		Identifier: "https://ps.example", SigningKey: psKey, KeyResolver: resolver,
		Clock: clock, NewID: sequentialIDs("person-token"),
		AuthorizationStore: testAuthorizationStateStore(t),
		PersonTokenStore:   personTokenStore, MissionIssuanceStore: missionStore,
		PersonTokenPolicy: func(context.Context, aauth.PersonTokenRequest) (aauth.PersonTokenDecision, error) {
			return aauth.PersonTokenDecision{Subject: "directed-person", Lifetime: time.Hour}, nil
		},
		CurrentMissionPolicy: func(_ context.Context, evaluation aauth.MissionEvaluation) (aauth.MissionDecision, error) {
			return aauth.MissionDecision{Description: evaluation.Proposal.Description}, nil
		},
		AuthorizationPolicy: func(_ context.Context, request aauth.AuthorizationRequest) (aauth.AuthorizationDecision, error) {
			return aauth.AuthorizationDecision{Subject: request.Subject, Scope: request.Scope}, nil
		},
		FederationClient: protocolClient,
		AccessServerEndpoint: func(context.Context, string) (string, error) {
			return "https://as.example/token", nil
		},
		R3HTTPClient: protocolClient,
		R3Admit:      admitR3,
		R3Review: func(_ context.Context, request aauth.AuthorizationRequest, document r3.DocumentReference) error {
			personReviews++
			if request.Resource != "https://resource.example" || !document.Valid() || document.Digest() != r3.S256(documentBytes) {
				return errors.New("unexpected R3 review context")
			}
			if denyReview {
				return errors.New("person denied")
			}
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	accessPolicies := 0
	accessServer, err := reference.NewAccessServer(reference.AccessServerConfig{
		Identifier: "https://as.example", SigningKey: accessKey, KeyResolver: resolver,
		Clock: clock, NewID: sequentialIDs("auth-token"),
		AuthorizationStore: testAuthorizationStateStore(t),
		TrustedPersonServer: func(_ context.Context, identifier string) error {
			if identifier != "https://ps.example" {
				return errors.New("untrusted person server")
			}
			return nil
		},
		AuthorizationPolicy: func(_ context.Context, request aauth.AuthorizationRequest) (aauth.AuthorizationDecision, error) {
			return aauth.AuthorizationDecision{Subject: request.Subject, Scope: request.Scope}, nil
		},
		R3HTTPClient: protocolClient,
		R3Admit:      admitR3,
		R3GrantPolicy: func(_ context.Context, _ aauth.AuthorizationRequest, document r3.DocumentReference) (r3.OperationSet, error) {
			accessPolicies++
			parsed, err := document.Document()
			if err != nil {
				return r3.OperationSet{}, err
			}
			return r3.OperationSet{
				Vocabulary: parsed.Vocabulary,
				Operations: []json.RawMessage{json.RawMessage(`{"tool":"list_records"}`)},
			}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	documentDirectory := filepath.Join(t.TempDir(), "r3-documents")
	if err := os.Mkdir(documentDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	documentConfig := reference.FileR3DocumentStoreConfig{
		Directory: documentDirectory, Clock: clock,
		MaxDocuments: 4, MaxBytes: 1 << 20, MaxDocumentBytes: 1 << 18,
	}
	replayStore, err := reference.NewMemoryProofReplayStore(clock, 128)
	if err != nil {
		t.Fatal(err)
	}
	operationCalls := 0
	newResource := func() *reference.Resource {
		documents, openErr := reference.OpenFileR3DocumentStore(documentConfig)
		if openErr != nil {
			t.Fatal(openErr)
		}
		resource, resourceErr := reference.NewResource(reference.ResourceConfig{
			Identifier: "https://resource.example", AccessMode: aauth.AccessModeAuthToken,
			AccessServer: "https://as.example", SigningKey: resourceKey,
			KeyResolver: resolver, Clock: clock, NewID: sequentialIDs("resource-token"),
			Scopes: []string{"records.read"}, ScopeDescriptions: map[string]string{"records.read": "Read records"},
			RequiredScopesForRequest: func(context.Context, *http.Request) ([]string, error) {
				return []string{"records.read"}, nil
			},
			ReplayStore:                  replayStore,
			ProtectedAuthorizationPolicy: func(context.Context, aauth.AuthorizedRequest) error { return nil },
			R3: &reference.ResourceR3Config{
				Vocabularies:  map[string]json.RawMessage{r3.VocabularyMCP: json.RawMessage(`"https://resource.example/mcp"`)},
				DocumentStore: documents,
				DocumentForOperations: func(_ context.Context, operations r3.OperationSet) ([]byte, error) {
					if !operations.Equal(requested) {
						return nil, errors.New("unexpected operation request")
					}
					return append([]byte(nil), documentBytes...), nil
				},
				OperationForRequest: func(_ context.Context, request *http.Request) (r3.OperationSet, error) {
					tool := "list_records"
					if request.URL.Path == "/records/delete" {
						tool = "delete_record"
					}
					return r3.OperationSet{Vocabulary: r3.VocabularyMCP, Operations: []json.RawMessage{json.RawMessage(`{"tool":"` + tool + `"}`)}}, nil
				},
			},
			Operation: func(context.Context, aauth.AuthorizedRequest) (any, error) {
				operationCalls++
				return map[string]bool{"ok": true}, nil
			},
		})
		if resourceErr != nil {
			t.Fatal(resourceErr)
		}
		return resource
	}
	resource := newResource()

	resourceHandler := resource.Handler()
	mutateDocument := false
	r3Fetches := 0
	gateway := newLogicalGateway(t, map[string]http.Handler{
		"ap.example": ap.Handler(),
		"ps.example": personServer.Handler(),
		"as.example": accessServer.Handler(),
		"other.example": http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			switch request.URL.Path {
			case "/.well-known/aauth-access.json":
				writeTestJSON(t, response, map[string]any{"issuer": "https://other.example", "jwks_uri": "https://other.example/jwks"})
			case "/jwks":
				writeTestJSON(t, response, map[string]any{"keys": []any{otherServerKey.PublicJWK()}})
			default:
				response.WriteHeader(http.StatusNotFound)
			}
		}),
		"resource.example": http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			if request.Method == http.MethodGet && strings.HasPrefix(request.URL.Path, "/r3/") {
				r3Fetches++
				if mutateDocument {
					recorder := httptest.NewRecorder()
					resourceHandler.ServeHTTP(recorder, request)
					for name, values := range recorder.Header() {
						response.Header()[name] = append([]string(nil), values...)
					}
					response.WriteHeader(recorder.Code)
					_, _ = response.Write(append(recorder.Body.Bytes(), ' '))
					return
				}
			}
			resourceHandler.ServeHTTP(response, request)
		}),
	})
	defer gateway.Close()
	protocolClient.Transport = gateway.Client().Transport

	agent, err := reference.NewAgent(reference.AgentConfig{
		Identifier: "aauth:planner@ap.example", SigningKey: agentKey, AgentToken: agentToken,
		KeyResolver: resolver, HTTPClient: protocolClient, Clock: clock,
		AuthorizationStore: testAuthorizationStateStore(t),
	})
	if err != nil {
		t.Fatal(err)
	}
	personGrant, err := agent.RequestPersonToken(
		context.Background(), "https://ps.example/person", "https://resource.example", nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	resourceGrant, err := agent.RequestR3ResourceTokenWithPersonToken(
		context.Background(), "https://resource.example/authorize", []string{"records.read"}, personGrant.PersonToken, requested,
	)
	if err != nil {
		t.Fatal(err)
	}
	resource = newResource()
	resourceHandler = resource.Handler()
	resourceCore, err := aauth.VerifyResourceToken(context.Background(), resourceGrant.ResourceToken, resolver, clock)
	if err != nil {
		t.Fatal(err)
	}
	resourceR3, err := r3.ValidateResourceToken(resourceCore)
	if err != nil {
		t.Fatal(err)
	}
	unauthorizedRequest, err := http.NewRequest(http.MethodGet, resourceR3.URI(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := signaturekey.SignJWKSURIRequest(
		unauthorizedRequest, otherServerKey, "https://other.example", aauth.AccessDiscoveryDocument, clock,
	); err != nil {
		t.Fatal(err)
	}
	unauthorizedResponse, err := protocolClient.Do(unauthorizedRequest)
	if err != nil {
		t.Fatal(err)
	}
	if unauthorizedResponse.StatusCode != http.StatusForbidden {
		unauthorizedResponse.Body.Close()
		t.Fatalf("unauthorized R3 reader = %d", unauthorizedResponse.StatusCode)
	}
	unauthorizedProblem, err := aauth.DecodeProblemResponse(unauthorizedResponse)
	if err != nil || unauthorizedProblem.Code != "r3_document_forbidden" {
		unauthorizedResponse.Body.Close()
		t.Fatalf("unauthorized R3 reader problem = %#v, %v", unauthorizedProblem, err)
	}
	unauthorizedResponse.Body.Close()

	mutateDocument = true
	_, err = agent.ExchangeResourceToken(context.Background(), "https://ps.example/token", resourceGrant)
	assertProblemCode(t, err, http.StatusBadGateway, "r3_document_verification_failed")
	mutateDocument = false
	denyReview = true
	_, err = agent.ExchangeResourceToken(context.Background(), "https://ps.example/token", resourceGrant)
	assertProblemCode(t, err, http.StatusForbidden, "r3_review_denied")
	denyReview = false
	grant, err := agent.ExchangeResourceToken(context.Background(), "https://ps.example/token", resourceGrant)
	if err != nil || grant.R3 == nil || !grant.R3.Valid() {
		t.Fatalf("direct R3 grant = %#v, %v", grant.R3, err)
	}
	if personReviews != 2 || accessPolicies != 1 || r3Fetches != 5 {
		t.Fatalf("review/policy/fetch counts = %d/%d/%d", personReviews, accessPolicies, r3Fetches)
	}

	response, err := agent.DoAuthorized(context.Background(), http.MethodGet, "https://resource.example/records", grant)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusOK || operationCalls != 1 {
		t.Fatalf("granted operation = %d, calls %d", response.StatusCode, operationCalls)
	}
	response, err = agent.DoAuthorized(context.Background(), http.MethodDelete, "https://resource.example/records/delete", grant)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusForbidden || operationCalls != 1 {
		t.Fatalf("ungranted operation = %d, calls %d", response.StatusCode, operationCalls)
	}
	problem, err := aauth.DecodeProblemResponse(response)
	if err != nil || problem.Code != "r3_operation_not_granted" {
		t.Fatalf("ungranted problem = %#v, %v", problem, err)
	}
}
