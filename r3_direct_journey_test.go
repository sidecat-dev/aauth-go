package aauth_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
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

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/r3"
	"gitlab.com/sidecat-dev/aauth-go/reference"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

// R3 sections Resource Token Extensions, R3 Processing, Auth Token
// Extensions, Resource Enforcement, and R3 Document Access Restriction.
func TestCurrentFourPartyR3JourneySurvivesReconstruction(t *testing.T) {
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

	documentBytes := []byte(`{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"list_records"},{"tool":"delete_record"}],"display":{"summary":"Use the selected records"}}`)
	requested := r3.OperationSet{
		Vocabulary: r3.VocabularyMCP,
		Operations: []json.RawMessage{json.RawMessage(`{"tool":"list_records"}`), json.RawMessage(`{"tool":"delete_record"}`)},
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
			if request.Resource != "https://resource.example" || !document.Valid() {
				return errors.New("unexpected R3 review context")
			}
			parsed, parseErr := document.Document()
			if parseErr != nil || parsed.Vocabulary != r3.VocabularyMCP {
				return errors.New("unexpected R3 review document")
			}
			parsedOperations := r3.OperationSet{Vocabulary: parsed.Vocabulary, Operations: parsed.Operations}
			initial := document.Digest() == r3.S256(documentBytes) && parsedOperations.Equal(requested)
			proposal, proposalErr := r3.ParsePerCallProposal(document.ExactBytes())
			proposalOperation, operationErr := proposal.Operation()
			perCall := proposalErr == nil && operationErr == nil && proposalOperation.Equal(r3.OperationSet{
				Vocabulary: r3.VocabularyMCP,
				Operations: []json.RawMessage{json.RawMessage(`{"tool":"delete_record"}`)},
			})
			if !initial && !perCall {
				return errors.New("unexpected R3 review document")
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
	accessTrustCalls := 0
	denyFreshAccessTrust := false
	authIDCalls := 0
	issuancePath := filepath.Join(t.TempDir(), "r3-issuance.json")
	newAccessServer := func() *reference.AccessServer {
		issuanceStore, storeErr := reference.NewFileR3IssuanceStore(issuancePath)
		if storeErr != nil {
			t.Fatal(storeErr)
		}
		server, serverErr := reference.NewAccessServer(reference.AccessServerConfig{
			Identifier: "https://as.example", SigningKey: accessKey, KeyResolver: resolver,
			Clock: clock, NewID: func() string {
				authIDCalls++
				return fmt.Sprintf("auth-token-%d", authIDCalls)
			},
			AuthorizationStore: testAuthorizationStateStore(t),
			TrustedPersonServer: func(_ context.Context, identifier string) error {
				accessTrustCalls++
				if identifier != "https://ps.example" {
					return errors.New("untrusted person server")
				}
				if denyFreshAccessTrust {
					return errors.New("fresh trust disabled")
				}
				return nil
			},
			AuthorizationPolicy: func(_ context.Context, request aauth.AuthorizationRequest) (aauth.AuthorizationDecision, error) {
				return aauth.AuthorizationDecision{Subject: request.Subject, Scope: request.Scope}, nil
			},
			R3HTTPClient:    protocolClient,
			R3Admit:         admitR3,
			R3IssuanceStore: issuanceStore,
			R3AuthorizationPolicy: func(_ context.Context, _ aauth.AuthorizationRequest, document r3.DocumentReference) (r3.AuthorizationDecision, error) {
				accessPolicies++
				parsed, err := document.Document()
				if err != nil {
					return r3.AuthorizationDecision{}, err
				}
				deleteOperation := r3.OperationSet{
					Vocabulary: parsed.Vocabulary,
					Operations: []json.RawMessage{json.RawMessage(`{"tool":"delete_record"}`)},
				}
				parsedOperations := r3.OperationSet{Vocabulary: parsed.Vocabulary, Operations: parsed.Operations}
				if parsedOperations.Equal(deleteOperation) {
					return r3.AuthorizationDecision{Granted: deleteOperation}, nil
				}
				perCall := r3.OperationSet{
					Vocabulary: parsed.Vocabulary,
					Operations: []json.RawMessage{json.RawMessage(`{"tool":"delete_record"}`)},
				}
				return r3.AuthorizationDecision{Granted: r3.OperationSet{
					Vocabulary: parsed.Vocabulary,
					Operations: []json.RawMessage{json.RawMessage(`{"tool":"list_records"}`)},
				}, PerCall: &perCall}, nil
			},
		})
		if serverErr != nil {
			t.Fatal(serverErr)
		}
		return server
	}
	accessServer := newAccessServer()

	documentDirectory := filepath.Join(t.TempDir(), "r3-documents")
	if err := os.Mkdir(documentDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	documentConfig := reference.FileR3DocumentStoreConfig{
		Directory: documentDirectory, Clock: clock,
		MaxDocuments: 4, MaxBytes: 1 << 20, MaxDocumentBytes: 1 << 18,
	}
	resourceTokenPath := filepath.Join(t.TempDir(), "r3-resource-tokens.json")
	perCallPath := filepath.Join(t.TempDir(), "r3-per-call.json")
	replayStore, err := reference.NewMemoryProofReplayStore(clock, 128)
	if err != nil {
		t.Fatal(err)
	}
	operationCalls := 0
	perCallCalls := 0
	blockPerCall := false
	perCallStarted := make(chan struct{}, 1)
	perCallContinue := make(chan struct{})
	newResource := func() *reference.Resource {
		documents, openErr := reference.OpenFileR3DocumentStore(documentConfig)
		if openErr != nil {
			t.Fatal(openErr)
		}
		resourceTokens, openErr := reference.NewFileResourceTokenLineageStore(resourceTokenPath)
		if openErr != nil {
			t.Fatal(openErr)
		}
		perCallStore, openErr := reference.NewFileR3PerCallStore(perCallPath)
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
				Vocabularies:       map[string]json.RawMessage{r3.VocabularyMCP: json.RawMessage(`"https://resource.example/mcp"`)},
				DocumentStore:      documents,
				ResourceTokenStore: resourceTokens,
				PerCallStore:       perCallStore,
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
				ProposalForRequest: func(_ context.Context, request *http.Request, body []byte) ([]byte, error) {
					if request.Method != http.MethodDelete || request.URL.Path != "/records/delete" {
						return nil, errors.New("unexpected per-call request")
					}
					var fields map[string]json.RawMessage
					if err := json.Unmarshal(body, &fields); err != nil || fields["record"] == nil || fields["note"] == nil {
						return nil, errors.New("invalid delete parameters")
					}
					return []byte(fmt.Sprintf(`{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"delete_record"}],"parameters":{"note":{"s256":%q,"excerpt":"private note","media_type":"application/json"},"record":%s},"display":{"summary":"Delete one record","detail":"## Action\nDelete the selected record"}}`, r3.S256(fields["note"]), fields["record"])), nil
				},
				ParametersForRequest: func(_ context.Context, _ *http.Request, body []byte) (r3.PresentedParameters, error) {
					var fields map[string]json.RawMessage
					if err := json.Unmarshal(body, &fields); err != nil || fields["record"] == nil || fields["note"] == nil {
						return nil, errors.New("invalid delete parameters")
					}
					return r3.PresentedParameters{"record": r3.PresentedJSON(fields["record"]), "note": r3.PresentedBytes(fields["note"])}, nil
				},
				PerCallOperation: func(_ context.Context, request aauth.AuthorizedRequest, _ string) (any, error) {
					perCallCalls++
					if blockPerCall {
						perCallStarted <- struct{}{}
						<-perCallContinue
					}
					var fields map[string]json.RawMessage
					if err := json.Unmarshal(request.Body, &fields); err != nil {
						return nil, err
					}
					return map[string]json.RawMessage{"deleted": fields["record"]}, nil
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
	accessHandler := accessServer.Handler()
	mutateDocument := false
	dropAccessResponse := false
	r3Fetches := 0
	gateway := newLogicalGateway(t, map[string]http.Handler{
		"ap.example": ap.Handler(),
		"ps.example": personServer.Handler(),
		"as.example": http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			accessHandler.ServeHTTP(response, request)
		}),
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
	dropResourceResponse := false
	protocolClient.Transport = &r3LostResponseTransport{
		base: gateway.Client().Transport, dropAccess: &dropAccessResponse, dropResource: &dropResourceResponse,
	}

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
	dropAccessResponse = true
	_, err = agent.ExchangeResourceToken(context.Background(), "https://ps.example/token", resourceGrant)
	assertProblemCode(t, err, http.StatusBadGateway, "federation_failed")
	requestBody, err := json.Marshal(map[string]string{
		"resource_token": resourceGrant.ResourceToken,
		"agent_token":    agentToken,
	})
	if err != nil {
		t.Fatal(err)
	}
	bodyDigest := sha256.Sum256(requestBody)
	bodySHA256 := base64.RawURLEncoding.EncodeToString(bodyDigest[:])
	identity := sha256.Sum256([]byte("gitlab.com/sidecat-dev/aauth-go/r3-issuance-request/v1\x00https://ps.example\x00" + bodySHA256))
	requestKey := base64.RawURLEncoding.EncodeToString(identity[:])
	issuanceStore, err := reference.NewFileR3IssuanceStore(issuancePath)
	if err != nil {
		t.Fatal(err)
	}
	retained, err := issuanceStore.Load(context.Background(), requestKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := issuanceStore.Commit(context.Background(), retained); err != nil {
		t.Fatalf("exact issuance replay = %v", err)
	}
	var retainedResponse struct {
		AuthToken string `json:"auth_token"`
		ExpiresIn int64  `json:"expires_in"`
	}
	if err := json.Unmarshal(retained.ResponseBody, &retainedResponse); err != nil {
		t.Fatal(err)
	}
	conflict := retained
	conflict.ResponseBody = []byte(fmt.Sprintf(`{"expires_in":%d,"auth_token":%q}`, retainedResponse.ExpiresIn, retainedResponse.AuthToken))
	if err := issuanceStore.Commit(context.Background(), conflict); !errors.Is(err, reference.ErrR3IssuanceConflict) {
		t.Fatalf("conflicting issuance replay = %v", err)
	}
	accessServer = newAccessServer()
	accessHandler = accessServer.Handler()
	trustCallsBeforeRecovery := accessTrustCalls
	denyFreshAccessTrust = true
	grant, err := agent.ExchangeResourceToken(context.Background(), "https://ps.example/token", resourceGrant)
	if err != nil || grant.R3 == nil || !grant.R3.Valid() {
		t.Fatalf("initial R3 grant = %#v, %v", grant.R3, err)
	}
	if grant.AuthToken != retained.AuthToken {
		t.Fatal("R3 retry after AS reconstruction returned a different auth token")
	}
	perCall, present := grant.R3.PerCall()
	if !present || !perCall.Contains(json.RawMessage(`{"tool":"delete_record"}`)) {
		t.Fatalf("R3 per-call partition = %#v, %t", perCall, present)
	}
	if accessTrustCalls != trustCallsBeforeRecovery {
		t.Fatal("R3 recovery reran access-server trust policy")
	}
	if personReviews != 3 || accessPolicies != 1 || r3Fetches != 6 || authIDCalls != 1 {
		t.Fatalf("review/policy/fetch/id counts = %d/%d/%d/%d", personReviews, accessPolicies, r3Fetches, authIDCalls)
	}
	denyFreshAccessTrust = false

	response, err := agent.DoAuthorized(context.Background(), http.MethodGet, "https://resource.example/records", grant)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusOK || operationCalls != 1 {
		t.Fatalf("granted operation = %d, calls %d", response.StatusCode, operationCalls)
	}
	call := reference.AuthorizedCall{Method: http.MethodDelete, Endpoint: "https://resource.example/records/delete", Body: []byte(`{"record":{"z":1,"a":2},"note":"private note bytes"}`), ContentType: "application/json"}
	challenge, err := agent.RequestR3PerCall(context.Background(), call, grant, perCall)
	if err != nil {
		t.Fatal(err)
	}
	perCallGrant, err := agent.ExchangeResourceToken(context.Background(), "https://ps.example/token", challenge)
	if err != nil {
		t.Fatal(err)
	}
	changed := call
	changed.Body = []byte(`{"record":{"a":2,"z":1},"note":"changed note bytes"}`)
	response, err = agent.DoAuthorizedRequest(context.Background(), changed, perCallGrant)
	if err != nil {
		t.Fatal(err)
	}
	problem, problemErr := aauth.DecodeProblemResponse(response)
	response.Body.Close()
	if response.StatusCode != http.StatusForbidden || problemErr != nil || problem.Code != "r3_per_call_parameters_mismatch" || perCallCalls != 0 {
		t.Fatalf("changed retry = %d %#v %v calls=%d", response.StatusCode, problem, problemErr, perCallCalls)
	}
	equivalent := call
	equivalent.Body = []byte(`{"record":{"a":2,"z":1},"note":"private note bytes"}`)
	blockPerCall = true
	dropResourceResponse = true
	lostResult := make(chan error, 1)
	go func() {
		_, requestErr := agent.DoAuthorizedRequest(context.Background(), equivalent, perCallGrant)
		lostResult <- requestErr
	}()
	<-perCallStarted
	response, err = agent.DoAuthorizedRequest(context.Background(), equivalent, perCallGrant)
	if err != nil {
		t.Fatal(err)
	}
	problem, problemErr = aauth.DecodeProblemResponse(response)
	response.Body.Close()
	if response.StatusCode != http.StatusConflict || problemErr != nil || problem.Code != "r3_per_call_in_progress" || perCallCalls != 1 {
		t.Fatalf("concurrent retry = %d %#v %v calls=%d", response.StatusCode, problem, problemErr, perCallCalls)
	}
	close(perCallContinue)
	if err := <-lostResult; !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("lost per-call result = %v", err)
	}
	resource = newResource()
	resourceHandler = resource.Handler()
	response, err = agent.DoAuthorizedRequest(context.Background(), equivalent, perCallGrant)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var completed map[string]json.RawMessage
	if err := json.NewDecoder(response.Body).Decode(&completed); err != nil || string(completed["deleted"]) != `{"a":2,"z":1}` || perCallCalls != 1 {
		t.Fatalf("retained per-call result = %#v, %v calls=%d", completed, err, perCallCalls)
	}
}

type r3LostResponseTransport struct {
	base         http.RoundTripper
	dropAccess   *bool
	dropResource *bool
}

func (transport *r3LostResponseTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	response, err := transport.base.RoundTrip(request)
	if err != nil {
		return response, err
	}
	drop := transport.dropAccess != nil && *transport.dropAccess && request.URL.Host == "as.example" && request.URL.Path == "/token"
	if transport.dropResource != nil && *transport.dropResource && request.URL.Host == "resource.example" && request.URL.Path == "/records/delete" && response.StatusCode == http.StatusOK {
		drop = true
		*transport.dropResource = false
	}
	if !drop {
		return response, err
	}
	if transport.dropAccess != nil && request.URL.Host == "as.example" {
		*transport.dropAccess = false
	}
	_, _ = io.Copy(io.Discard, response.Body)
	_ = response.Body.Close()
	return nil, io.ErrUnexpectedEOF
}
