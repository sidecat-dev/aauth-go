package accessserver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	aauth "aauth-go"
	"aauth-go/jose"
	"aauth-go/r3"
	"aauth-go/signaturekey"
)

func TestMCPR3ProposalUsesDistinctPolicyAndAuditsExactOneOperationToken(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 31, 16, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	providerKey := accessServerTestKey(t, "provider-key")
	personKey := accessServerTestKey(t, "person-key")
	resourceKey := accessServerTestKey(t, "resource-key")
	accessKey := accessServerTestKey(t, "access-key")
	agentKey := accessServerTestKey(t, "agent-key")
	resolver := signaturekey.StaticKeyResolver{
		{Issuer: "https://provider.example", DiscoveryDocument: aauth.AgentDiscoveryDocument, KeyID: providerKey.ID()}:    providerKey.PublicJWK(),
		{Issuer: "https://person.example", DiscoveryDocument: aauth.PersonDiscoveryDocument, KeyID: personKey.ID()}:       personKey.PublicJWK(),
		{Issuer: "https://resource.example", DiscoveryDocument: aauth.ResourceDiscoveryDocument, KeyID: resourceKey.ID()}: resourceKey.PublicJWK(),
		{Issuer: "https://access.example", DiscoveryDocument: aauth.AccessDiscoveryDocument, KeyID: accessKey.ID()}:       accessKey.PublicJWK(),
	}
	agentToken, err := aauth.MintAgentToken(
		"https://provider.example", providerKey,
		aauth.AgentTokenRequest{
			Agent: "aauth:planner@provider.example", PersonServer: "https://person.example",
			PublicKey: agentKey.PublicJWK(), Lifetime: time.Hour,
		},
		now, "agent-token-1",
	)
	if err != nil {
		t.Fatal(err)
	}
	agentJKT, err := agentKey.PublicJWK().Thumbprint()
	if err != nil {
		t.Fatal(err)
	}
	account := "work-account"
	operation, err := r3.NewMCPOperation("records.export")
	if err != nil {
		t.Fatal(err)
	}
	filter, err := r3.NewMCPInlineParameter([]byte(`{"status":"open"}`))
	if err != nil {
		t.Fatal(err)
	}
	parameters, err := r3.NewMCPParameters(map[string]r3.MCPParameter{"filter": filter})
	if err != nil {
		t.Fatal(err)
	}
	proposal, err := r3.NewMCPProposal(operation, parameters, r3.ProposalOptions{Account: &account})
	if err != nil {
		t.Fatal(err)
	}
	exactProposal, err := json.Marshal(proposal)
	if err != nil {
		t.Fatal(err)
	}
	missionS256 := r3.Digest([]byte("approved mission"))
	resourceClaims := aauth.ResourceTokenClaims{
		Issuer: "https://resource.example", DWK: aauth.ResourceDiscoveryDocument,
		Audience: "https://access.example", JTI: "proposal-resource-token-1", AgentJKT: agentJKT,
		IssuedAt: now.Unix(), ExpiresAt: now.Add(5 * time.Minute).Unix(), Scope: "records.read records.export",
		PersonServer: "https://person.example", Subject: "person-123", PresentedJTI: "person-token-1",
		Account: &account, Tenant: "tenant-1", MissionS256: missionS256,
	}
	resourceToken, reference, err := r3.MintMCPProposalResourceToken(
		resourceKey, resourceClaims,
		"https://resource.example/r3/class-looking-artifact", exactProposal,
	)
	if err != nil {
		t.Fatal(err)
	}

	var sequence []string
	fetchCalls := 0
	servedArtifact := exactProposal
	httpClient := &http.Client{Transport: accessR3RoundTripper(func(request *http.Request) (*http.Response, error) {
		fetchCalls++
		sequence = append(sequence, "proposal-fetch")
		if request.URL.String() != reference.URI() {
			t.Fatalf("fetch URI = %q, want %q", request.URL, reference.URI())
		}
		prepared, err := signaturekey.PrepareRequest(request, clock, signaturekey.VerifyOptions{
			RequireExactComponents: true,
			AcceptedSchemes:        []signaturekey.Scheme{signaturekey.SchemeJWKSURI},
		})
		if err != nil {
			t.Fatal(err)
		}
		issuer, discovery, _, ok := prepared.Credential().JWKSURI()
		if !ok || issuer != "https://access.example" || discovery != aauth.AccessDiscoveryDocument {
			t.Fatalf("fetch credential = %q %q, %t", issuer, discovery, ok)
		}
		if _, err := prepared.Verify(accessKey.PublicJWK()); err != nil {
			t.Fatal(err)
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body:       io.NopCloser(bytes.NewReader(servedArtifact)), Request: request,
		}, nil
	})}
	issuances := &r3TestIssuanceStore{onCommit: func() { sequence = append(sequence, "audit-commit") }}
	classPolicyCalls := 0
	proposalPolicyCalls := 0
	var proposalPolicyErr error
	var evaluated AuthorizationRequest
	server, err := New(Config{
		Issuer: "https://access.example", SigningKey: accessKey, KeyResolver: resolver,
		Clock: clock, NewID: func() string { return "proposal-auth-token-1" },
		TrustPersonServer: func(context.Context, string) error { return nil },
		Authorize: func(context.Context, AuthorizationRequest) (Decision, error) {
			classPolicyCalls++
			return Decision{}, nil
		},
		MCPR3: &MCPR3Config{
			HTTPClient: httpClient,
			Admit: func(_ context.Context, endpoint string) error {
				sequence = append(sequence, "admit")
				if endpoint != reference.URI() {
					t.Fatalf("admitted endpoint = %q, want %q", endpoint, reference.URI())
				}
				return nil
			},
			AuthorizeProposal: func(
				_ context.Context,
				request AuthorizationRequest,
				gotReference r3.Reference,
				gotProposal r3.MCPProposal,
			) (MCPR3ProposalDecision, error) {
				proposalPolicyCalls++
				sequence = append(sequence, "proposal-policy")
				evaluated = request
				if gotReference != reference || gotProposal.Operation() != operation ||
					!reflect.DeepEqual(gotProposal.Parameters().Names(), []string{"filter"}) {
					t.Fatalf("proposal policy artifact = %#v %#v", gotReference, gotProposal)
				}
				return MCPR3ProposalDecision{
					Scopes: []string{"records.read"}, Lifetime: 30 * time.Minute,
				}, proposalPolicyErr
			},
			Issuances: issuances,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	call := func() *httptest.ResponseRecorder {
		body, err := json.Marshal(map[string]string{"resource_token": resourceToken, "agent_token": agentToken})
		if err != nil {
			t.Fatal(err)
		}
		request := httptest.NewRequest(http.MethodPost, "https://access.example/token", bytes.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		if err := signaturekey.SignJWKSURIRequestWithOptions(
			request, personKey, "https://person.example", aauth.PersonDiscoveryDocument, clock,
			signaturekey.SignOptions{
				AdditionalComponents: []string{"content-type", "content-digest"},
				MaxBodyBytes:         int64(len(body)),
			},
		); err != nil {
			t.Fatal(err)
		}
		response := httptest.NewRecorder()
		server.Handler().ServeHTTP(response, request)
		return response
	}
	reset := func() {
		sequence = nil
		fetchCalls = 0
		classPolicyCalls = 0
		proposalPolicyCalls = 0
		proposalPolicyErr = nil
		servedArtifact = exactProposal
		issuances.reset()
	}
	response := call()
	if response.Code != http.StatusOK {
		t.Fatalf("proposal token = %d %s", response.Code, response.Body.String())
	}
	var output struct {
		AuthToken string `json:"auth_token"`
		ExpiresIn int64  `json:"expires_in"`
	}
	if err := json.NewDecoder(response.Body).Decode(&output); err != nil {
		t.Fatal(err)
	}
	claims, gotReference, gotOperation, err := r3.VerifyMCPPerCallAuthToken(
		context.Background(), output.AuthToken, resolver, clock, reference, exactProposal,
	)
	if err != nil {
		t.Fatal(err)
	}
	if gotReference != reference || gotOperation != operation {
		t.Fatalf("proposal token reference/operation = %#v/%#v", gotReference, gotOperation)
	}
	if claims.Issuer != "https://access.example" || claims.DWK != aauth.AccessDiscoveryDocument ||
		claims.Audience != "https://resource.example" || claims.PersonServer != "https://person.example" ||
		claims.Subject != "person-123" || claims.Tenant != "tenant-1" || claims.MissionS256 != missionS256 ||
		claims.Account == nil || *claims.Account != account || !claims.Confirmation.JWK.Equal(agentKey.PublicJWK()) ||
		claims.Scope != "records.read" || claims.IssuedAt != now.Unix() ||
		claims.ExpiresAt != now.Add(5*time.Minute).Unix() || output.ExpiresIn != int64((5*time.Minute).Seconds()) {
		t.Fatalf("proposal Auth token claims/output = %#v/%#v", claims, output)
	}
	parsed, err := jose.ParseCompact(output.AuthToken)
	if err != nil {
		t.Fatal(err)
	}
	var tokenMembers map[string]json.RawMessage
	if err := json.Unmarshal(parsed.Payload(), &tokenMembers); err != nil {
		t.Fatal(err)
	}
	if _, present := tokenMembers["r3_per_call"]; present {
		t.Fatal("per-call Auth token contains r3_per_call")
	}
	if classPolicyCalls != 0 || proposalPolicyCalls != 1 || fetchCalls != 1 ||
		!reflect.DeepEqual(sequence, []string{"admit", "proposal-fetch", "proposal-policy", "audit-commit"}) {
		t.Fatalf("class/proposal/fetch/sequence = %d/%d/%d/%#v", classPolicyCalls, proposalPolicyCalls, fetchCalls, sequence)
	}
	if evaluated.MCPR3 != nil || evaluated.PersonServer != "https://person.example" ||
		evaluated.Resource != "https://resource.example" || evaluated.Subject != "person-123" ||
		evaluated.Tenant != "tenant-1" || evaluated.MissionS256 != missionS256 ||
		evaluated.Account == nil || *evaluated.Account != account ||
		!reflect.DeepEqual(evaluated.Scopes, []string{"records.read", "records.export"}) ||
		evaluated.Agent.Identifier != "aauth:planner@provider.example" ||
		!evaluated.Agent.Confirmation.Equal(agentKey.PublicJWK()) || evaluated.Subagent != nil {
		t.Fatalf("proposal policy context = %#v", evaluated)
	}
	records := issuances.recordsCopy()
	if len(records) != 1 || records[0].ExactAuthToken != output.AuthToken ||
		records[0].AuthTokenReference != (aauth.TokenReference{Issuer: "https://access.example", JTI: "proposal-auth-token-1"}) ||
		records[0].Resource != "https://resource.example" || records[0].R3Reference != reference ||
		records[0].PersonServer != "https://person.example" || records[0].Subject != "person-123" ||
		records[0].PresentedJTI != "person-token-1" || records[0].AgentJKT != agentJKT ||
		records[0].Agent != "aauth:planner@provider.example" || records[0].ParentAgent != "" ||
		records[0].Account == nil || *records[0].Account != account {
		t.Fatalf("proposal audit records = %#v", records)
	}

	t.Run("policy refusal exposes no token and calls no class policy", func(t *testing.T) {
		reset()
		proposalPolicyErr = errors.Join(ErrAccessDenied, errors.New("proposal refused"))
		response := call()
		if response.Code != http.StatusForbidden ||
			!bytes.Contains(response.Body.Bytes(), []byte(`"error":"access_denied"`)) ||
			bytes.Contains(response.Body.Bytes(), []byte("auth_token")) || len(issuances.recordsCopy()) != 0 {
			t.Fatalf("proposal refusal = %d %s, audit %#v", response.Code, response.Body.String(), issuances.recordsCopy())
		}
		if classPolicyCalls != 0 || proposalPolicyCalls != 1 || fetchCalls != 1 ||
			!reflect.DeepEqual(sequence, []string{"admit", "proposal-fetch", "proposal-policy"}) {
			t.Fatalf("refusal class/proposal/fetch/sequence = %d/%d/%d/%#v", classPolicyCalls, proposalPolicyCalls, fetchCalls, sequence)
		}
	})

	t.Run("substituted proposal bytes fail before either policy", func(t *testing.T) {
		reset()
		otherOperation, err := r3.NewMCPOperation("records.delete")
		if err != nil {
			t.Fatal(err)
		}
		otherProposal, err := r3.NewMCPProposal(otherOperation, parameters, r3.ProposalOptions{Account: &account})
		if err != nil {
			t.Fatal(err)
		}
		servedArtifact, err = json.Marshal(otherProposal)
		if err != nil {
			t.Fatal(err)
		}
		response := call()
		if response.Code != http.StatusBadRequest ||
			!bytes.Contains(response.Body.Bytes(), []byte(`"error":"invalid_resource_token"`)) ||
			bytes.Contains(response.Body.Bytes(), []byte("auth_token")) || len(issuances.recordsCopy()) != 0 {
			t.Fatalf("proposal substitution = %d %s, audit %#v", response.Code, response.Body.String(), issuances.recordsCopy())
		}
		if classPolicyCalls != 0 || proposalPolicyCalls != 0 || fetchCalls != 1 ||
			!reflect.DeepEqual(sequence, []string{"admit", "proposal-fetch"}) {
			t.Fatalf("substitution class/proposal/fetch/sequence = %d/%d/%d/%#v", classPolicyCalls, proposalPolicyCalls, fetchCalls, sequence)
		}
	})

	t.Run("missing proposal policy fails closed after content classification", func(t *testing.T) {
		reset()
		authorizeProposal := server.mcpR3.authorizeProposal
		server.mcpR3.authorizeProposal = nil
		response := call()
		server.mcpR3.authorizeProposal = authorizeProposal
		if response.Code != http.StatusInternalServerError ||
			!bytes.Contains(response.Body.Bytes(), []byte(`"error":"server_error"`)) ||
			bytes.Contains(response.Body.Bytes(), []byte("auth_token")) || len(issuances.recordsCopy()) != 0 {
			t.Fatalf("missing proposal policy = %d %s, audit %#v", response.Code, response.Body.String(), issuances.recordsCopy())
		}
		if classPolicyCalls != 0 || proposalPolicyCalls != 0 || fetchCalls != 1 ||
			!reflect.DeepEqual(sequence, []string{"admit", "proposal-fetch"}) {
			t.Fatalf("missing policy class/proposal/fetch/sequence = %d/%d/%d/%#v", classPolicyCalls, proposalPolicyCalls, fetchCalls, sequence)
		}
	})

	for _, failure := range []struct {
		name           string
		commitThenFail bool
		wantRecords    int
	}{
		{name: "definite audit failure"},
		{name: "uncertain audit commit", commitThenFail: true, wantRecords: 1},
	} {
		t.Run(failure.name, func(t *testing.T) {
			reset()
			issuances.commitErr = errors.New("audit unavailable")
			issuances.commitThenFail = failure.commitThenFail
			response := call()
			if response.Code != http.StatusInternalServerError ||
				!bytes.Contains(response.Body.Bytes(), []byte(`"error":"server_error"`)) ||
				bytes.Contains(response.Body.Bytes(), []byte("auth_token")) {
				t.Fatalf("proposal audit failure = %d %s", response.Code, response.Body.String())
			}
			if got := len(issuances.recordsCopy()); got != failure.wantRecords {
				t.Fatalf("proposal audit records = %d, want %d", got, failure.wantRecords)
			}
			if classPolicyCalls != 0 || proposalPolicyCalls != 1 || fetchCalls != 1 ||
				!reflect.DeepEqual(sequence, []string{"admit", "proposal-fetch", "proposal-policy", "audit-commit"}) {
				t.Fatalf("audit failure class/proposal/fetch/sequence = %d/%d/%d/%#v", classPolicyCalls, proposalPolicyCalls, fetchCalls, sequence)
			}
		})
	}
}
