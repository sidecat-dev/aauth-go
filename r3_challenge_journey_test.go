package aauth_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	aa "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/r3"
	"gitlab.com/sidecat-dev/aauth-go/reference"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

func TestResourceSelectsAndRetainsR3DocumentForPersonChallenge(t *testing.T) {
	now := time.Date(2026, 8, 29, 22, 30, 0, 0, time.UTC)
	clock := aa.ClockFunc(func() time.Time { return now })
	psKey := testSigningKey(t, "r3-challenge-ps")
	resourceKey := testSigningKey(t, "r3-challenge-resource")
	agentKey := testSigningKey(t, "r3-challenge-agent")
	resolver := signaturekey.StaticKeyResolver{
		"https://ps.example": {psKey.ID(): psKey.PublicJWK()},
	}
	documentDirectory := filepath.Join(t.TempDir(), "documents")
	if err := os.Mkdir(documentDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	documents, err := reference.OpenFileR3DocumentStore(reference.FileR3DocumentStoreConfig{
		Directory: documentDirectory, Clock: clock,
		MaxDocuments: 4, MaxBytes: 1 << 20, MaxDocumentBytes: 1 << 16,
	})
	if err != nil {
		t.Fatal(err)
	}
	documentBytes := []byte(`{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"list_records"}],"display":{"summary":"List records"}}`)
	requested := r3.OperationSet{
		Vocabulary: r3.VocabularyMCP,
		Operations: []json.RawMessage{json.RawMessage(`{"tool":"list_records"}`)},
	}
	selectionCalls := 0
	resource, err := reference.NewResource(reference.ResourceConfig{
		Identifier: "https://resource.example", AccessMode: aa.AccessModeAuthToken,
		AccessServer: "https://as.example", SigningKey: resourceKey,
		KeyResolver: resolver, Clock: clock, NewID: sequentialIDs("resource-token"),
		Scopes:                       []string{"records.read"},
		ScopeDescriptions:            map[string]string{"records.read": "Read records"},
		RequiredScopesForRequest:     testRequiredResourceScopes("records.read"),
		ReplayStore:                  testResourceReplayStore(t, clock),
		ProtectedAuthorizationPolicy: func(context.Context, aa.AuthorizedRequest) error { return nil },
		Operation: func(context.Context, aa.AuthorizedRequest) (any, error) {
			return map[string]bool{"ok": true}, nil
		},
		R3: &reference.ResourceR3Config{
			Vocabularies: map[string]json.RawMessage{
				r3.VocabularyMCP: json.RawMessage(`"https://resource.example/mcp"`),
			},
			DocumentStore: documents,
			DocumentForOperations: func(_ context.Context, operations r3.OperationSet) ([]byte, error) {
				selectionCalls++
				if !operations.Equal(requested) {
					t.Fatalf("selected operations = %#v, want %#v", operations, requested)
				}
				return append([]byte(nil), documentBytes...), nil
			},
			OperationForRequest: func(_ context.Context, request *http.Request) (r3.OperationSet, error) {
				if request.Method != http.MethodGet || request.URL.Path != "/records" {
					t.Fatalf("mapped request = %s %s", request.Method, request.URL.Path)
				}
				return requested.Clone(), nil
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	personClaims := aa.PersonTokenClaims{
		Issuer: "https://ps.example", DWK: aa.PersonDiscoveryDocument,
		Audience: "https://resource.example", Subject: "directed-person",
		Confirmation: aa.Confirmation{JWK: agentKey.PublicJWK()}, JTI: "person-token",
		IssuedAt: now.Unix(), ExpiresAt: now.Add(time.Hour).Unix(),
	}
	personToken, err := aa.MintPersonToken(psKey, personClaims)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "https://resource.example/records", nil)
	if err := signaturekey.SignJWTRequest(request, agentKey, personToken, clock); err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	resource.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("person-token R3 challenge status = %d, body = %s", recorder.Code, recorder.Body.Bytes())
	}
	requirement, err := aa.ParseRequirementHeader(recorder.Header().Get("AAuth-Requirement"))
	if err != nil {
		t.Fatal(err)
	}
	if requirement.Type != aa.RequirementAuthToken || requirement.ResourceToken == "" {
		t.Fatalf("R3 challenge requirement = %#v", requirement)
	}
	if selectionCalls != 1 {
		t.Fatalf("R3 document selection calls = %d, want 1", selectionCalls)
	}

	resourceEvidence, err := aa.VerifyResourceToken(
		context.Background(), requirement.ResourceToken,
		signaturekey.StaticKeyResolver{"https://resource.example": {resourceKey.ID(): resourceKey.PublicJWK()}},
		clock,
	)
	if err != nil {
		t.Fatal(err)
	}
	resourceR3, err := r3.ValidateResourceToken(resourceEvidence)
	if err != nil {
		t.Fatal(err)
	}
	if resourceR3.URI() != "https://resource.example/r3/"+r3.S256(documentBytes) || resourceR3.Digest() != r3.S256(documentBytes) {
		t.Fatalf("R3 reference = %q/%q", resourceR3.URI(), resourceR3.Digest())
	}
	if _, err := documents.LoadAuthorized(context.Background(), resourceR3.Digest(), "https://ps.example"); err != nil {
		t.Fatalf("PS could not read retained R3 document: %v", err)
	}
	if _, err := documents.LoadAuthorized(context.Background(), resourceR3.Digest(), "https://as.example"); err != nil {
		t.Fatalf("AS could not read retained R3 document: %v", err)
	}
	if _, err := documents.LoadAuthorized(context.Background(), resourceR3.Digest(), "https://agent.example"); err == nil || !strings.Contains(err.Error(), "not authorized") {
		t.Fatalf("unauthorized R3 reader error = %v", err)
	}
}

func TestCurrentFourPartyR3PersonChallengeCompletesProtectedCall(t *testing.T) {
	now := time.Date(2026, 8, 29, 22, 45, 0, 0, time.UTC)
	clock := aa.ClockFunc(func() time.Time { return now })
	apKey := testSigningKey(t, "r3-chain-ap")
	psKey := testSigningKey(t, "r3-chain-ps")
	accessKey := testSigningKey(t, "r3-chain-access")
	resourceKey := testSigningKey(t, "r3-chain-resource")
	agentKey := testSigningKey(t, "r3-chain-agent")
	protocolClient := &http.Client{}
	resolver, err := signaturekey.NewHTTPKeyResolver(signaturekey.HTTPKeyResolverConfig{
		Client: protocolClient,
		Clock:  clock,
		Admit: func(_ context.Context, endpoint string) error {
			for _, prefix := range []string{
				"https://ap.example/", "https://ps.example/", "https://as.example/", "https://resource.example/",
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
	ap, err := reference.NewAgentProvider(reference.AgentProviderConfig{
		Identifier: "https://ap.example", SigningKey: apKey, Clock: clock,
		NewID: sequentialIDs("chain-agent-token"),
	})
	if err != nil {
		t.Fatal(err)
	}
	agentToken, err := ap.IssueAgentToken(aa.AgentTokenRequest{
		Agent: "aauth:r3-chain@ap.example", PersonServer: "https://ps.example",
		PublicKey: agentKey.PublicJWK(), Lifetime: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}

	documentBytes := []byte(`{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"list_records"}],"display":{"summary":"List records"}}`)
	requested := r3.OperationSet{
		Vocabulary: r3.VocabularyMCP,
		Operations: []json.RawMessage{json.RawMessage(`{"tool":"list_records"}`)},
	}
	documentDirectory := filepath.Join(t.TempDir(), "r3-documents")
	if err := os.Mkdir(documentDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	documents, err := reference.OpenFileR3DocumentStore(reference.FileR3DocumentStoreConfig{
		Directory: documentDirectory, Clock: clock,
		MaxDocuments: 4, MaxBytes: 1 << 20, MaxDocumentBytes: 1 << 16,
	})
	if err != nil {
		t.Fatal(err)
	}
	personTokens, missionIssuance := testCurrentPersonServerCustody(t)
	personReviews := 0
	personServer, err := reference.NewPersonServer(reference.PersonServerConfig{
		Identifier: "https://ps.example", SigningKey: psKey, KeyResolver: resolver,
		Clock: clock, NewID: sequentialIDs("chain-person-token"),
		AuthorizationStore: testAuthorizationStateStore(t),
		PersonTokenStore:   personTokens, MissionIssuanceStore: missionIssuance,
		PersonTokenPolicy: func(context.Context, aa.PersonTokenRequest) (aa.PersonTokenDecision, error) {
			return aa.PersonTokenDecision{Subject: "chain-person", Lifetime: time.Hour}, nil
		},
		CurrentMissionPolicy: func(_ context.Context, evaluation aa.MissionEvaluation) (aa.MissionDecision, error) {
			return aa.MissionDecision{Description: evaluation.Proposal.Description}, nil
		},
		AuthorizationPolicy: func(_ context.Context, request aa.AuthorizationRequest) (aa.AuthorizationDecision, error) {
			return aa.AuthorizationDecision{Subject: request.Subject, Scope: request.Scope}, nil
		},
		FederationClient:     protocolClient,
		AccessServerEndpoint: func(context.Context, string) (string, error) { return "https://as.example/token", nil },
		R3HTTPClient:         protocolClient,
		R3Admit: func(_ context.Context, endpoint string) error {
			if strings.HasPrefix(endpoint, "https://resource.example/r3/") {
				return nil
			}
			return fmt.Errorf("R3 endpoint outside resource: %s", endpoint)
		},
		R3Review: func(_ context.Context, request aa.AuthorizationRequest, document r3.DocumentReference) error {
			personReviews++
			if request.Resource != "https://resource.example" {
				return errors.New("unexpected R3 review resource")
			}
			parsed, parseErr := document.Document()
			parsedOperations := r3.OperationSet{Vocabulary: parsed.Vocabulary, Operations: parsed.Operations}
			if parseErr != nil || !parsedOperations.Equal(requested) {
				return errors.New("unexpected R3 review document")
			}
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	accessPolicies := 0
	issuanceStore, err := reference.NewFileR3IssuanceStore(filepath.Join(t.TempDir(), "r3-issuance.json"))
	if err != nil {
		t.Fatal(err)
	}
	accessServer, err := reference.NewAccessServer(reference.AccessServerConfig{
		Identifier: "https://as.example", SigningKey: accessKey, KeyResolver: resolver,
		Clock: clock, NewID: sequentialIDs("chain-auth-token"),
		AuthorizationStore: testAuthorizationStateStore(t),
		TrustedPersonServer: func(_ context.Context, identifier string) error {
			if identifier != "https://ps.example" {
				return errors.New("untrusted person server")
			}
			return nil
		},
		AuthorizationPolicy: func(_ context.Context, request aa.AuthorizationRequest) (aa.AuthorizationDecision, error) {
			return aa.AuthorizationDecision{Subject: request.Subject, Scope: request.Scope}, nil
		},
		R3HTTPClient: protocolClient,
		R3Admit: func(_ context.Context, endpoint string) error {
			if strings.HasPrefix(endpoint, "https://resource.example/r3/") {
				return nil
			}
			return fmt.Errorf("R3 endpoint outside resource: %s", endpoint)
		},
		R3IssuanceStore: issuanceStore,
		R3AuthorizationPolicy: func(_ context.Context, _ aa.AuthorizationRequest, document r3.DocumentReference) (r3.AuthorizationDecision, error) {
			accessPolicies++
			parsed, parseErr := document.Document()
			if parseErr != nil {
				return r3.AuthorizationDecision{}, parseErr
			}
			return r3.AuthorizationDecision{Granted: r3.OperationSet{Vocabulary: parsed.Vocabulary, Operations: parsed.Operations}}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	operationCalls := 0
	resource, err := reference.NewResource(reference.ResourceConfig{
		Identifier: "https://resource.example", AccessMode: aa.AccessModeAuthToken,
		AccessServer: "https://as.example", SigningKey: resourceKey, KeyResolver: resolver,
		Clock: clock, NewID: sequentialIDs("chain-resource-token"),
		Scopes: []string{"records.read"}, ScopeDescriptions: map[string]string{"records.read": "Read records"},
		RequiredScopesForRequest:     testRequiredResourceScopes("records.read"),
		ReplayStore:                  testResourceReplayStore(t, clock),
		ProtectedAuthorizationPolicy: func(context.Context, aa.AuthorizedRequest) error { return nil },
		Operation: func(_ context.Context, _ aa.AuthorizedRequest) (any, error) {
			operationCalls++
			return map[string]string{"status": "listed"}, nil
		},
		R3: &reference.ResourceR3Config{
			Vocabularies:  map[string]json.RawMessage{r3.VocabularyMCP: json.RawMessage(`"https://resource.example/mcp"`)},
			DocumentStore: documents,
			DocumentForOperations: func(_ context.Context, operations r3.OperationSet) ([]byte, error) {
				if !operations.Equal(requested) {
					return nil, errors.New("unexpected selected R3 operations")
				}
				return append([]byte(nil), documentBytes...), nil
			},
			OperationForRequest: func(_ context.Context, request *http.Request) (r3.OperationSet, error) {
				if request.Method != http.MethodGet || request.URL.Path != "/records" {
					return r3.OperationSet{}, errors.New("unexpected protected request")
				}
				return requested.Clone(), nil
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	gateway := newLogicalGateway(t, map[string]http.Handler{
		"ap.example": ap.Handler(), "ps.example": personServer.Handler(),
		"as.example": accessServer.Handler(), "resource.example": resource.Handler(),
	})
	defer gateway.Close()
	protocolClient.Transport = gateway.Client().Transport
	agent, err := reference.NewAgent(reference.AgentConfig{
		Identifier: "aauth:r3-chain@ap.example", SigningKey: agentKey, AgentToken: agentToken,
		KeyResolver: resolver, HTTPClient: protocolClient, Clock: clock,
		AuthorizationStore: testAuthorizationStateStore(t),
	})
	if err != nil {
		t.Fatal(err)
	}
	response, err := agent.Do(context.Background(), reference.AuthorizedCall{
		Method: http.MethodGet, Endpoint: "https://resource.example/records",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK || !strings.Contains(string(body), `"listed"`) {
		t.Fatalf("protected R3 response = %d %s", response.StatusCode, body)
	}
	if personReviews != 1 || accessPolicies != 1 || operationCalls != 1 {
		t.Fatalf("R3 review/access/operation calls = %d/%d/%d", personReviews, accessPolicies, operationCalls)
	}
}
