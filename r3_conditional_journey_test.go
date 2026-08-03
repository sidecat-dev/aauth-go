package aauth_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/reference"
)

func TestR3ConditionalPerCallJourney(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 2, 20, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	ids := sequentialIDs(
		"agent-token",
		"resource-token",
		"initial-auth-token",
		"proposal-resource-token",
		"failed-per-call-auth-token",
		"per-call-auth-token",
	)
	apKey := testSigningKey(t, "ap-key")
	psKey := testSigningKey(t, "ps-key")
	accessKey := testSigningKey(t, "access-key")
	resourceKey := testSigningKey(t, "resource-key")
	agentKey := testSigningKey(t, "agent-key")
	directOperation := aauth.R3OperationSet{
		Vocabulary: aauth.R3VocabularyMCP,
		Operations: []json.RawMessage{json.RawMessage(`{"tool":"list_messages"}`)},
	}
	conditionalOperation := aauth.R3OperationSet{
		Vocabulary: aauth.R3VocabularyMCP,
		Operations: []json.RawMessage{json.RawMessage(`{"tool":"send_message"}`)},
	}
	requestedOperations := aauth.R3OperationSet{
		Vocabulary: aauth.R3VocabularyMCP,
		Operations: []json.RawMessage{
			json.RawMessage(`{"tool":"list_messages"}`),
			json.RawMessage(`{"tool":"send_message"}`),
		},
	}
	classDocument := []byte(
		`{"version":"2","vocabulary":"urn:aauth:vocabulary:mcp",` +
			`"operations":[{"tool":"list_messages"},{"tool":"send_message"}],` +
			`"display":{"summary":"List messages or send one for the user"}}`,
	)

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
		Agent:        "aauth:messenger@ap.example",
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
	auditedTokenIDs := make(map[string]bool)
	auditFailure := false
	proposalPolicyFailure := false
	var proposalPolicyAuthorization *aauth.R3Authorization
	issuanceStoreConfig := reference.FileR3PerCallIssuanceStoreConfig{
		Directory:  privateTestDirectory(t),
		Clock:      clock,
		MaxRecords: 8,
	}
	issuanceStore, err := reference.OpenFileR3PerCallIssuanceStore(issuanceStoreConfig)
	if err != nil {
		t.Fatal(err)
	}
	failingIssuanceStore := &r3FailFirstIssuanceCommitStore{R3PerCallIssuanceStore: issuanceStore}
	accessServerConfig := reference.AccessServerConfig{
		Identifier:   "https://as.example",
		SigningKey:   accessKey,
		KeyResolver:  keyResolver,
		Clock:        clock,
		NewID:        ids,
		R3HTTPClient: protocolClient,
		R3Audit: func(_ context.Context, record aauth.R3AuditRecord) error {
			if auditFailure {
				return fmt.Errorf("durable audit is unavailable")
			}
			if !auditedTokenIDs[record.TokenID] {
				auditedTokenIDs[record.TokenID] = true
				auditRecords = append(auditRecords, record)
			}
			return nil
		},
		R3Admit: func(_ context.Context, endpoint string) error {
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
			if request.R3 == nil {
				return aauth.AuthorizationDecision{}, fmt.Errorf("R3 context is missing")
			}
			operations := request.R3.Document.OperationSet()
			if request.R3.Document.Parameters != nil {
				proposalPolicyAuthorization = request.R3.Clone()
				if proposalPolicyFailure {
					return aauth.AuthorizationDecision{}, fmt.Errorf("proposal policy is unavailable")
				}
				return aauth.AuthorizationDecision{
					Subject:   "federated-pairwise-user",
					Scope:     request.Scope,
					R3Granted: &operations,
				}, nil
			}
			if !operations.ContainsSet(directOperation) || !operations.ContainsSet(conditionalOperation) {
				return aauth.AuthorizationDecision{}, fmt.Errorf("class document lost the mixed operation set")
			}
			direct := directOperation.Clone()
			conditional := conditionalOperation.Clone()
			return aauth.AuthorizationDecision{
				Subject:       "federated-pairwise-user",
				Scope:         request.Scope,
				R3Granted:     &direct,
				R3Conditional: &conditional,
			}, nil
		},
	}
	newAccessServer := func(store reference.R3PerCallIssuanceStore) *reference.AccessServer {
		config := accessServerConfig
		config.R3PerCallIssuanceStore = store
		server, serverErr := reference.NewAccessServer(config)
		if serverErr != nil {
			t.Fatal(serverErr)
		}
		return server
	}
	accessServer := newAccessServer(failingIssuanceStore)
	accessServerHandler := accessServer.Handler()

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
			return aauth.AuthorizationDecision{Subject: "person-server-user", Scope: request.Scope}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	documentStoreConfig := reference.FileR3DocumentStoreConfig{
		Directory:        privateTestDirectory(t),
		Clock:            clock,
		MaxDocuments:     8,
		MaxBytes:         8 << 20,
		MaxDocumentBytes: 1 << 20,
	}
	documentStore, err := reference.OpenFileR3DocumentStore(documentStoreConfig)
	if err != nil {
		t.Fatal(err)
	}
	directOperationCalls := 0
	operationCalls := 0
	proposalBuilds := 0
	resourceConfig := reference.ResourceConfig{
		Identifier:   "https://resource.example",
		AccessServer: "https://as.example",
		SigningKey:   resourceKey,
		KeyResolver:  keyResolver,
		Clock:        clock,
		NewID:        ids,
		Scopes:       []string{"messages.send"},
		R3Vocabularies: map[string]json.RawMessage{
			aauth.R3VocabularyMCP: json.RawMessage(`"https://resource.example/mcp"`),
		},
		R3DocumentForOperations: func(_ context.Context, operations aauth.R3OperationSet) ([]byte, error) {
			if !operations.Equal(requestedOperations) {
				return nil, fmt.Errorf("unexpected requested operations: %#v", operations)
			}
			return classDocument, nil
		},
		R3RequiredForRequest: func(_ context.Context, request *http.Request) (bool, error) {
			return request.URL.Path == "/messages", nil
		},
		R3OperationForRequest: func(_ context.Context, request *http.Request) (aauth.R3OperationSet, error) {
			if request.URL.Path != "/messages" {
				return aauth.R3OperationSet{}, fmt.Errorf("unmapped operation path %s", request.URL.Path)
			}
			switch request.Method {
			case http.MethodGet:
				return directOperation.Clone(), nil
			case http.MethodPost:
				return conditionalOperation.Clone(), nil
			default:
				return aauth.R3OperationSet{}, fmt.Errorf("unmapped operation method %s", request.Method)
			}
		},
		R3ProposalForRequest: func(
			_ context.Context,
			request *http.Request,
			exactBody []byte,
		) (aauth.R3Proposal, error) {
			proposalBuilds++
			if request.Method != http.MethodPost || request.URL.RawQuery != "" ||
				request.Header.Get("Content-Type") != "application/json" {
				return aauth.R3Proposal{}, fmt.Errorf("conditional call must use POST with query-free JSON")
			}
			var input struct {
				Recipient string `json:"recipient"`
				Body      string `json:"body"`
			}
			if err := json.Unmarshal(exactBody, &input); err != nil || input.Recipient == "" {
				return aauth.R3Proposal{}, fmt.Errorf("invalid message call")
			}
			recipient, err := json.Marshal(input.Recipient)
			if err != nil {
				return aauth.R3Proposal{}, err
			}
			return aauth.R3Proposal{
				Parameters: map[string]aauth.R3CallParameter{
					"recipient": {Value: recipient},
					"request_body": {
						Digest:         true,
						PresentedValue: append([]byte(nil), exactBody...),
						Excerpt:        "approved JSON message call",
						MediaType:      "application/json",
					},
				},
				Display: &aauth.R3Display{
					Summary: "Send one approved message",
					Detail:  "## Recipient\n" + input.Recipient,
				},
			}, nil
		},
		Operation: func(_ context.Context, request aauth.AuthorizedRequest) (any, error) {
			if request.Method == http.MethodGet {
				directOperationCalls++
			} else {
				operationCalls++
			}
			return map[string]string{"status": "sent"}, nil
		},
	}
	newResource := func(store reference.R3DocumentStore) *reference.Resource {
		config := resourceConfig
		config.R3DocumentStore = store
		resource, resourceErr := reference.NewResource(config)
		if resourceErr != nil {
			t.Fatal(resourceErr)
		}
		return resource
	}
	resource := newResource(documentStore)
	resourceHandler := resource.Handler()

	gateway := newLogicalGateway(t, map[string]http.Handler{
		"ap.example": ap.Handler(),
		"ps.example": personServer.Handler(),
		"as.example": http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			accessServerHandler.ServeHTTP(response, request)
		}),
		"resource.example": http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			resourceHandler.ServeHTTP(response, request)
		}),
	})
	defer gateway.Close()
	protocolClient.Transport = gateway.Client().Transport

	agent, err := reference.NewAgent(reference.AgentConfig{
		Identifier:  "aauth:messenger@ap.example",
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
		Description: "Send the approved message.",
	})
	if err != nil {
		t.Fatal(err)
	}
	grant, err := agent.AuthorizeR3(
		context.Background(),
		"https://resource.example/authorize",
		"https://ps.example/token",
		[]string{"messages.send"},
		mission,
		requestedOperations,
	)
	if err != nil {
		t.Fatal(err)
	}
	if grant.Claims.R3Granted == nil || !grant.Claims.R3Granted.Equal(directOperation) ||
		grant.Claims.R3Conditional == nil || !grant.Claims.R3Conditional.Equal(conditionalOperation) {
		t.Fatalf("initial conditional R3 claims = %#v", grant.Claims)
	}
	directResponse, err := agent.DoAuthorized(
		context.Background(),
		http.MethodGet,
		"https://resource.example/messages",
		grant,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer directResponse.Body.Close()
	if directResponse.StatusCode != http.StatusOK || directOperationCalls != 1 || operationCalls != 0 {
		t.Fatalf(
			"mixed-grant direct call status = %d, direct calls = %d, conditional calls = %d; want 200, 1, 0",
			directResponse.StatusCode,
			directOperationCalls,
			operationCalls,
		)
	}

	callBody := []byte(`{"recipient":"person@example.com","body":"hello from the exact call"}`)
	resource = newResource(r3ProposalRetentionFailureStore{R3ProposalDocumentStore: documentStore})
	resourceHandler = resource.Handler()
	custodyFailureCall, err := http.NewRequestWithContext(
		context.Background(),
		http.MethodPost,
		"https://resource.example/messages",
		bytes.NewReader(callBody),
	)
	if err != nil {
		t.Fatal(err)
	}
	custodyFailureCall.Header.Set("Content-Type", "application/json")
	if err := aauth.SignRequestWithOptions(
		custodyFailureCall,
		agentKey,
		grant.AuthToken,
		clock,
		aauth.SignRequestOptions{Nonce: "custody-failure-proof"},
	); err != nil {
		t.Fatal(err)
	}
	custodyFailureResponse, err := protocolClient.Do(custodyFailureCall)
	if err != nil {
		t.Fatal(err)
	}
	defer custodyFailureResponse.Body.Close()
	if custodyFailureResponse.StatusCode != http.StatusServiceUnavailable ||
		custodyFailureResponse.Header.Get("AAuth-Requirement") != "" || operationCalls != 0 {
		t.Fatalf(
			"proposal custody failure status = %d, requirement = %q, operation calls = %d; want 503, empty, 0",
			custodyFailureResponse.StatusCode,
			custodyFailureResponse.Header.Get("AAuth-Requirement"),
			operationCalls,
		)
	}
	resource = newResource(documentStore)
	resourceHandler = resource.Handler()

	queryCall, err := http.NewRequestWithContext(
		context.Background(),
		http.MethodPost,
		"https://resource.example/messages?draft=true",
		bytes.NewReader(callBody),
	)
	if err != nil {
		t.Fatal(err)
	}
	queryCall.Header.Set("Content-Type", "application/json")
	if err := aauth.SignRequestWithOptions(
		queryCall,
		agentKey,
		grant.AuthToken,
		clock,
		aauth.SignRequestOptions{Nonce: "query-call-proof"},
	); err != nil {
		t.Fatal(err)
	}
	queryResponse, err := protocolClient.Do(queryCall)
	if err != nil {
		t.Fatal(err)
	}
	defer queryResponse.Body.Close()
	if queryResponse.StatusCode != http.StatusBadRequest ||
		queryResponse.Header.Get("AAuth-Requirement") != "" || operationCalls != 0 {
		t.Fatalf(
			"conditional query status = %d, requirement = %q, operation calls = %d; want 400, empty, 0",
			queryResponse.StatusCode,
			queryResponse.Header.Get("AAuth-Requirement"),
			operationCalls,
		)
	}

	unsignedContentTypeCall, err := http.NewRequestWithContext(
		context.Background(),
		http.MethodPost,
		"https://resource.example/messages",
		bytes.NewReader(callBody),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := aauth.SignRequestWithOptions(
		unsignedContentTypeCall,
		agentKey,
		grant.AuthToken,
		clock,
		aauth.SignRequestOptions{Nonce: "missing-content-type-proof"},
	); err != nil {
		t.Fatal(err)
	}
	// A custom signer can attach a media type without covering it. The
	// resource must reject that unsigned security input before proposal
	// construction sees it.
	unsignedContentTypeCall.Header.Set("Content-Type", "application/json")
	unsignedContentTypeResponse, err := protocolClient.Do(unsignedContentTypeCall)
	if err != nil {
		t.Fatal(err)
	}
	defer unsignedContentTypeResponse.Body.Close()
	unsignedContentTypeError, parseErr := aauth.ParseSignatureError(
		unsignedContentTypeResponse.Header.Get("Signature-Error"),
	)
	if unsignedContentTypeResponse.StatusCode != http.StatusUnauthorized || parseErr != nil ||
		unsignedContentTypeError.Code != aauth.SignatureErrorInvalidInput || operationCalls != 0 {
		t.Fatalf(
			"unsigned content-type status = %d, error = %#v (%v), operation calls = %d; want 401, invalid-input, 0",
			unsignedContentTypeResponse.StatusCode,
			unsignedContentTypeError,
			parseErr,
			operationCalls,
		)
	}

	unsignedDigestCall, err := http.NewRequestWithContext(
		context.Background(),
		http.MethodPost,
		"https://resource.example/messages",
		bytes.NewReader(callBody),
	)
	if err != nil {
		t.Fatal(err)
	}
	unsignedDigestCall.Header.Set("Content-Type", "application/json")
	if err := aauth.SignRequestWithOptions(
		unsignedDigestCall,
		agentKey,
		grant.AuthToken,
		clock,
		aauth.SignRequestOptions{Nonce: "missing-content-digest-proof"},
	); err != nil {
		t.Fatal(err)
	}
	unsignedDigestCall.Header.Set(
		"Signature-Input",
		strings.Replace(unsignedDigestCall.Header.Get("Signature-Input"), ` "content-digest"`, "", 1),
	)
	unsignedDigestResponse, err := protocolClient.Do(unsignedDigestCall)
	if err != nil {
		t.Fatal(err)
	}
	defer unsignedDigestResponse.Body.Close()
	unsignedDigestError, parseErr := aauth.ParseSignatureError(
		unsignedDigestResponse.Header.Get("Signature-Error"),
	)
	if unsignedDigestResponse.StatusCode != http.StatusUnauthorized || parseErr != nil ||
		unsignedDigestError.Code != aauth.SignatureErrorInvalidInput || operationCalls != 0 {
		t.Fatalf(
			"unsigned content digest status = %d, error = %#v (%v), operation calls = %d; want 401, invalid-input, 0",
			unsignedDigestResponse.StatusCode,
			unsignedDigestError,
			parseErr,
			operationCalls,
		)
	}

	call, err := http.NewRequestWithContext(
		context.Background(),
		http.MethodPost,
		"https://resource.example/messages",
		bytes.NewReader(callBody),
	)
	if err != nil {
		t.Fatal(err)
	}
	call.Header.Set("Content-Type", "application/json")
	if err := aauth.SignRequest(call, agentKey, grant.AuthToken, clock); err != nil {
		t.Fatal(err)
	}
	challenge, err := protocolClient.Do(call)
	if err != nil {
		t.Fatal(err)
	}
	defer challenge.Body.Close()
	if challenge.StatusCode != http.StatusUnauthorized {
		t.Fatalf("conditional challenge status = %d, want 401", challenge.StatusCode)
	}
	challengeBody, err := io.ReadAll(challenge.Body)
	if err != nil {
		t.Fatal(err)
	}
	challenge.Body = io.NopCloser(bytes.NewReader(challengeBody))
	if challenge.Header.Get("Cache-Control") != "no-store" ||
		bytes.Contains(challengeBody, []byte("person@example.com")) ||
		strings.Contains(challenge.Header.Get("AAuth-Requirement"), "person@example.com") {
		t.Fatalf(
			"conditional challenge leaked proposal data or was cacheable: cache-control = %q, body = %s",
			challenge.Header.Get("Cache-Control"),
			challengeBody,
		)
	}
	if operationCalls != 0 || proposalBuilds != 2 {
		t.Fatalf("challenge operation calls = %d, proposal builds = %d; want 0, 2", operationCalls, proposalBuilds)
	}
	requirement, err := aauth.ParseRequirementHeader(challenge.Header.Get("AAuth-Requirement"))
	if err != nil {
		t.Fatal(err)
	}
	if requirement.Type != aauth.RequirementAuthToken || requirement.ResourceToken == "" {
		t.Fatalf("conditional requirement = %#v", requirement)
	}
	proposalClaims, err := aauth.VerifyResourceToken(
		context.Background(),
		requirement.ResourceToken,
		keyResolver,
		clock,
	)
	if err != nil {
		t.Fatal(err)
	}
	if proposalClaims.Agent != grant.Claims.Agent ||
		proposalClaims.Scope != grant.Claims.Scope ||
		proposalClaims.Mission == nil || grant.Claims.Mission == nil ||
		*proposalClaims.Mission != *grant.Claims.Mission ||
		!strings.HasPrefix(proposalClaims.R3URI, "https://resource.example/r3/proposals/") {
		t.Fatalf("proposal resource-token claims = %#v", proposalClaims)
	}
	retainedProposal, err := documentStore.Load(context.Background(), proposalClaims.R3S256)
	if err != nil {
		t.Fatal(err)
	}
	parsedProposal, err := aauth.ParseR3Document(retainedProposal)
	if err != nil {
		t.Fatal(err)
	}
	if parsedProposal.Parameters == nil || !parsedProposal.OperationSet().Equal(conditionalOperation) {
		t.Fatalf("retained proposal = %#v", parsedProposal)
	}
	unsignedProposalFetch, err := http.NewRequest(http.MethodGet, proposalClaims.R3URI, nil)
	if err != nil {
		t.Fatal(err)
	}
	unsignedProposalResponse, err := protocolClient.Do(unsignedProposalFetch)
	if err != nil {
		t.Fatal(err)
	}
	unsignedProposalBody, err := io.ReadAll(unsignedProposalResponse.Body)
	unsignedProposalResponse.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if unsignedProposalResponse.StatusCode != http.StatusUnauthorized ||
		bytes.Contains(unsignedProposalBody, []byte("person@example.com")) {
		t.Fatalf(
			"unsigned proposal fetch status = %d, body = %s; want 401 without proposal data",
			unsignedProposalResponse.StatusCode,
			unsignedProposalBody,
		)
	}
	personServerProposalFetch, err := http.NewRequest(http.MethodGet, proposalClaims.R3URI, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := aauth.SignRequestWithJWKSURI(
		personServerProposalFetch,
		psKey,
		"https://ps.example",
		aauth.PersonDiscoveryDocument,
		clock,
	); err != nil {
		t.Fatal(err)
	}
	personServerProposalResponse, err := protocolClient.Do(personServerProposalFetch)
	if err != nil {
		t.Fatal(err)
	}
	personServerProposalBody, err := io.ReadAll(personServerProposalResponse.Body)
	personServerProposalResponse.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if personServerProposalResponse.StatusCode != http.StatusUnauthorized ||
		bytes.Contains(personServerProposalBody, []byte("person@example.com")) {
		t.Fatalf(
			"person-server proposal fetch status = %d, body = %s; want 401 without proposal data",
			personServerProposalResponse.StatusCode,
			personServerProposalBody,
		)
	}
	if len(auditRecords) != 1 {
		t.Fatalf("class grant audit count = %d, want 1", len(auditRecords))
	}

	proposalGrant, err := agent.ParseR3ConditionalChallenge(
		context.Background(),
		challenge,
		grant,
		conditionalOperation,
	)
	if err != nil {
		t.Fatal(err)
	}
	encodedProposalGrant, err := json.Marshal(proposalGrant)
	if err != nil {
		t.Fatal(err)
	}
	var restoredProposalGrant reference.ResourceGrant
	if err := json.Unmarshal(encodedProposalGrant, &restoredProposalGrant); err != nil {
		t.Fatal(err)
	}
	if !restoredProposalGrant.R3Proposal {
		t.Fatalf("proposal stage was not retained: %#v", restoredProposalGrant)
	}
	_, err = agent.ExchangeResourceToken(
		context.Background(),
		"https://ps.example/token",
		restoredProposalGrant,
	)
	if err == nil {
		t.Fatal("proposal exchange released a token despite durable issuance failure")
	}
	if _, loadErr := issuanceStore.Load(
		context.Background(),
		proposalClaims.Issuer,
		proposalClaims.JTI,
		aauth.R3S256([]byte(requirement.ResourceToken)),
	); loadErr == nil {
		t.Fatal("failed proposal issuance became durable")
	}
	if len(auditRecords) != 1 {
		t.Fatalf("failed proposal issuance escaped into direct audit path: %#v", auditRecords)
	}

	now = now.Add(time.Second)
	auditFailure = true
	_, err = agent.ExchangeResourceToken(
		context.Background(),
		"https://ps.example/token",
		restoredProposalGrant,
	)
	if err == nil {
		t.Fatal("proposal exchange released a token despite durable audit failure")
	}
	if len(auditRecords) != 1 {
		t.Fatalf("failed proposal audit was recorded as successful: %#v", auditRecords)
	}
	storedIssuance, err := issuanceStore.Load(
		context.Background(),
		proposalClaims.Issuer,
		proposalClaims.JTI,
		aauth.R3S256([]byte(requirement.ResourceToken)),
	)
	if err != nil {
		t.Fatal(err)
	}
	storedClaims, err := aauth.VerifyAuthToken(
		context.Background(),
		storedIssuance.AuthToken,
		keyResolver,
		clock,
	)
	if err != nil {
		t.Fatal(err)
	}
	if storedIssuance.Audit.TokenID != storedClaims.JTI ||
		storedIssuance.Audit.ResourceTokenID != proposalClaims.JTI ||
		storedIssuance.Audit.Mission == nil || proposalClaims.Mission == nil ||
		*storedIssuance.Audit.Mission != *proposalClaims.Mission ||
		storedIssuance.Audit.R3Granted == nil ||
		!storedIssuance.Audit.R3Granted.Equal(conditionalOperation) ||
		storedIssuance.Audit.R3Conditional != nil {
		t.Fatalf("durable proposal issuance = %#v", storedIssuance)
	}

	issuanceStore, err = reference.OpenFileR3PerCallIssuanceStore(issuanceStoreConfig)
	if err != nil {
		t.Fatal(err)
	}
	accessServer = newAccessServer(issuanceStore)
	accessServerHandler = accessServer.Handler()

	auditFailure = false
	proposalPolicyFailure = true
	now = now.Add(time.Second)
	perCallGrant, err := agent.ExchangeResourceToken(
		context.Background(),
		"https://ps.example/token",
		restoredProposalGrant,
	)
	if err != nil {
		t.Fatal(err)
	}
	if perCallGrant.AuthToken != storedIssuance.AuthToken ||
		perCallGrant.Claims.JTI != storedClaims.JTI ||
		perCallGrant.Claims.R3Conditional != nil ||
		perCallGrant.Claims.R3Granted == nil ||
		!perCallGrant.Claims.R3Granted.Equal(conditionalOperation) ||
		perCallGrant.Claims.R3URI != proposalClaims.R3URI ||
		perCallGrant.Claims.R3S256 != proposalClaims.R3S256 ||
		perCallGrant.Claims.ExpiresAt > proposalClaims.ExpiresAt {
		t.Fatalf("recovered per-call auth-token = %#v", perCallGrant.Claims)
	}
	if len(auditRecords) != 2 || auditRecords[1].TokenID != perCallGrant.Claims.JTI {
		t.Fatalf("durable proposal audit records = %#v", auditRecords)
	}
	proposalPolicyFailure = false
	if proposalPolicyAuthorization == nil ||
		proposalPolicyAuthorization.URI != proposalClaims.R3URI ||
		proposalPolicyAuthorization.S256 != proposalClaims.R3S256 ||
		!bytes.Equal(proposalPolicyAuthorization.ExactBytes, retainedProposal) ||
		proposalPolicyAuthorization.Document.Parameters == nil ||
		len(*proposalPolicyAuthorization.Document.Parameters) != len(*parsedProposal.Parameters) {
		t.Fatalf("proposal policy authorization = %#v", proposalPolicyAuthorization)
	}
	for name, expected := range *parsedProposal.Parameters {
		if !bytes.Equal((*proposalPolicyAuthorization.Document.Parameters)[name], expected) {
			t.Fatalf("proposal policy parameter %q changed", name)
		}
	}

	issuanceStore, err = reference.OpenFileR3PerCallIssuanceStore(issuanceStoreConfig)
	if err != nil {
		t.Fatal(err)
	}
	accessServer = newAccessServer(issuanceStore)
	accessServerHandler = accessServer.Handler()
	now = now.Add(time.Second)
	recoveredPerCallGrant, err := agent.ExchangeResourceToken(
		context.Background(),
		"https://ps.example/token",
		restoredProposalGrant,
	)
	if err != nil {
		t.Fatal(err)
	}
	if recoveredPerCallGrant.AuthToken != perCallGrant.AuthToken ||
		recoveredPerCallGrant.Claims.JTI != perCallGrant.Claims.JTI {
		t.Fatalf("duplicate proposal exchange minted another token: %#v", recoveredPerCallGrant.Claims)
	}
	if len(auditRecords) != 2 {
		t.Fatalf("idempotent proposal recovery duplicated audit: %#v", auditRecords)
	}

	documentStore, err = reference.OpenFileR3DocumentStore(documentStoreConfig)
	if err != nil {
		t.Fatal(err)
	}
	resource = newResource(documentStore)
	resourceHandler = resource.Handler()

	addedFieldBody := []byte(
		`{"recipient":"person@example.com","body":"hello from the exact call","admin":true}`,
	)
	addedFieldRetry, err := http.NewRequestWithContext(
		context.Background(),
		http.MethodPost,
		"https://resource.example/messages",
		bytes.NewReader(addedFieldBody),
	)
	if err != nil {
		t.Fatal(err)
	}
	addedFieldRetry.Header.Set("Content-Type", "application/json")
	if err := aauth.SignRequestWithOptions(
		addedFieldRetry,
		agentKey,
		perCallGrant.AuthToken,
		clock,
		aauth.SignRequestOptions{Nonce: "added-field-proof"},
	); err != nil {
		t.Fatal(err)
	}
	addedFieldResponse, err := protocolClient.Do(addedFieldRetry)
	if err != nil {
		t.Fatal(err)
	}
	defer addedFieldResponse.Body.Close()
	if addedFieldResponse.StatusCode != http.StatusForbidden || operationCalls != 0 {
		t.Fatalf(
			"added-field per-call retry status = %d, operation calls = %d; want 403, 0",
			addedFieldResponse.StatusCode,
			operationCalls,
		)
	}

	changedMethodRetry, err := http.NewRequestWithContext(
		context.Background(),
		http.MethodDelete,
		"https://resource.example/messages",
		bytes.NewReader(callBody),
	)
	if err != nil {
		t.Fatal(err)
	}
	changedMethodRetry.Header.Set("Content-Type", "application/json")
	if err := aauth.SignRequestWithOptions(
		changedMethodRetry,
		agentKey,
		perCallGrant.AuthToken,
		clock,
		aauth.SignRequestOptions{Nonce: "changed-method-proof"},
	); err != nil {
		t.Fatal(err)
	}
	changedMethodResponse, err := protocolClient.Do(changedMethodRetry)
	if err != nil {
		t.Fatal(err)
	}
	defer changedMethodResponse.Body.Close()
	if changedMethodResponse.StatusCode != http.StatusForbidden || operationCalls != 0 {
		t.Fatalf(
			"changed-method per-call retry status = %d, operation calls = %d; want 403, 0",
			changedMethodResponse.StatusCode,
			operationCalls,
		)
	}

	changedBody := []byte(`{"recipient":"person@example.com","body":"changed after approval"}`)
	changedRetry, err := http.NewRequestWithContext(
		context.Background(),
		http.MethodPost,
		"https://resource.example/messages",
		bytes.NewReader(changedBody),
	)
	if err != nil {
		t.Fatal(err)
	}
	changedRetry.Header.Set("Content-Type", "application/json")
	if err := aauth.SignRequestWithOptions(
		changedRetry,
		agentKey,
		perCallGrant.AuthToken,
		clock,
		aauth.SignRequestOptions{Nonce: "changed-call-proof"},
	); err != nil {
		t.Fatal(err)
	}
	changedResponse, err := protocolClient.Do(changedRetry)
	if err != nil {
		t.Fatal(err)
	}
	defer changedResponse.Body.Close()
	if changedResponse.StatusCode != http.StatusForbidden || operationCalls != 0 {
		t.Fatalf(
			"changed per-call retry status = %d, operation calls = %d; want 403, 0",
			changedResponse.StatusCode,
			operationCalls,
		)
	}

	retryResponse, err := agent.DoAuthorizedRequest(
		context.Background(),
		reference.AuthorizedCall{
			Method:      http.MethodPost,
			Endpoint:    "https://resource.example/messages",
			Body:        callBody,
			ContentType: "application/json",
		},
		perCallGrant,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer retryResponse.Body.Close()
	if retryResponse.StatusCode != http.StatusOK {
		t.Fatalf("matching per-call retry status = %d, want 200", retryResponse.StatusCode)
	}
	if operationCalls != 1 || proposalBuilds != 5 {
		t.Fatalf("retry operation calls = %d, proposal builds = %d; want 1, 5", operationCalls, proposalBuilds)
	}

	exactProofReplay, err := http.NewRequestWithContext(
		context.Background(),
		http.MethodPost,
		"https://resource.example/messages",
		bytes.NewReader(callBody),
	)
	if err != nil {
		t.Fatal(err)
	}
	exactProofReplay.Header.Set("Content-Type", "application/json")
	if err := aauth.SignRequest(exactProofReplay, agentKey, perCallGrant.AuthToken, clock); err != nil {
		t.Fatal(err)
	}
	exactReplayResponse, err := protocolClient.Do(exactProofReplay)
	if err != nil {
		t.Fatal(err)
	}
	defer exactReplayResponse.Body.Close()
	if exactReplayResponse.StatusCode != http.StatusUnauthorized || operationCalls != 1 {
		t.Fatalf(
			"identical request-proof replay status = %d, operation calls = %d; want 401, 1",
			exactReplayResponse.StatusCode,
			operationCalls,
		)
	}

	documentStore, err = reference.OpenFileR3DocumentStore(documentStoreConfig)
	if err != nil {
		t.Fatal(err)
	}
	resource = newResource(documentStore)
	resourceHandler = resource.Handler()

	freshReplay, err := http.NewRequestWithContext(
		context.Background(),
		http.MethodPost,
		"https://resource.example/messages",
		bytes.NewReader(callBody),
	)
	if err != nil {
		t.Fatal(err)
	}
	freshReplay.Header.Set("Content-Type", "application/json")
	if err := aauth.SignRequestWithOptions(
		freshReplay,
		agentKey,
		perCallGrant.AuthToken,
		clock,
		aauth.SignRequestOptions{Nonce: "fresh-replay-proof"},
	); err != nil {
		t.Fatal(err)
	}
	replayResponse, err := protocolClient.Do(freshReplay)
	if err != nil {
		t.Fatal(err)
	}
	defer replayResponse.Body.Close()
	if replayResponse.StatusCode != http.StatusForbidden || operationCalls != 1 || proposalBuilds != 6 {
		t.Fatalf(
			"fresh per-call replay status = %d, operation calls = %d, proposal builds = %d; want 403, 1, 6",
			replayResponse.StatusCode,
			operationCalls,
			proposalBuilds,
		)
	}
}

type r3ProposalRetentionFailureStore struct {
	reference.R3ProposalDocumentStore
}

type r3FailFirstIssuanceCommitStore struct {
	reference.R3PerCallIssuanceStore
	failed bool
}

func (store *r3FailFirstIssuanceCommitStore) Commit(
	ctx context.Context,
	candidate reference.R3PerCallIssuance,
) (reference.R3PerCallIssuance, error) {
	if !store.failed {
		store.failed = true
		return reference.R3PerCallIssuance{}, fmt.Errorf("durable issuance commit is unavailable")
	}
	return store.R3PerCallIssuanceStore.Commit(ctx, candidate)
}

func (r3ProposalRetentionFailureStore) RetainProposal(
	context.Context,
	string,
	[]byte,
	time.Time,
) error {
	return fmt.Errorf("proposal custody is unavailable")
}
