package personserver

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
	"aauth-go/r3/vocab/mcp"
	"aauth-go/signaturekey"
)

func TestFederatedR3MCPProposalUsesDistinctConsentAndVerifiesExactResult(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 31, 16, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	registry := newPersonServerR3Registry(t)
	personTokenExpiresAt := now.Add(time.Minute)
	personRetainUntil := personTokenExpiresAt.Add(
		DefaultMaximumResourceTokenLifetime + aauth.MaximumAuthTokenLifetime,
	)
	providerKey := personServerTestKey(t, "provider-key")
	personKey := personServerTestKey(t, "person-key")
	resourceKey := personServerTestKey(t, "resource-key")
	accessKey := personServerTestKey(t, "access-key")
	agentKey := personServerTestKey(t, "agent-key")
	resolver := signaturekey.StaticKeyResolver{
		{Issuer: "https://provider.example", DiscoveryDocument: aauth.AgentDiscoveryDocument, KeyID: providerKey.ID()}:    providerKey.PublicJWK(),
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
	now = now.Add(7 * time.Minute)
	agentJKT, err := agentKey.PublicJWK().Thumbprint()
	if err != nil {
		t.Fatal(err)
	}
	account := "work-account"
	typedOperation, err := mcp.NewOperation("records.export")
	if err != nil {
		t.Fatal(err)
	}
	operation, err := typedOperation.ToR3()
	if err != nil {
		t.Fatal(err)
	}
	filter, err := r3.NewInlineParameter([]byte(`{"status":"open"}`))
	if err != nil {
		t.Fatal(err)
	}
	parameters, err := r3.NewParameters(map[string]r3.Parameter{"filter": filter})
	if err != nil {
		t.Fatal(err)
	}
	display, err := r3.NewDisplay(
		"Export matching records", "Copies leave the service", "Matching records", "Export cannot be recalled",
	)
	if err != nil {
		t.Fatal(err)
	}
	proposalDisplay, err := r3.NewProposalDisplay(display, "Only records whose status is `open` are exported.")
	if err != nil {
		t.Fatal(err)
	}
	proposal, err := r3.NewProposal(operation, parameters, r3.ProposalOptions{
		Account: &account, Display: &proposalDisplay,
	})
	if err != nil {
		t.Fatal(err)
	}
	exactProposal, err := json.Marshal(proposal)
	if err != nil {
		t.Fatal(err)
	}
	resourceClaims := aauth.ResourceTokenClaims{
		Issuer: "https://resource.example", DWK: aauth.ResourceDiscoveryDocument,
		Audience: "https://access.example", JTI: "proposal-resource-token-1", AgentJKT: agentJKT,
		IssuedAt: now.Unix(), ExpiresAt: now.Add(5 * time.Minute).Unix(),
		PersonServer: "https://person.example", Subject: "person-123", PresentedJTI: "person-token-1",
		Account: &account, Tenant: "tenant-1",
	}
	resourceToken, reference, err := r3.MintProposalResourceToken(
		registry, resourceKey, resourceClaims, "https://resource.example/r3/proposal-1", exactProposal,
	)
	if err != nil {
		t.Fatal(err)
	}
	authClaims := aauth.AuthTokenClaims{
		Issuer: "https://access.example", DWK: aauth.AccessDiscoveryDocument,
		Audience: "https://resource.example", JTI: "proposal-auth-token-1",
		PersonServer: "https://person.example", Subject: "person-123",
		Account: &account, Tenant: "tenant-1", Confirmation: aauth.Confirmation{JWK: agentKey.PublicJWK()},
		IssuedAt: now.Unix(), ExpiresAt: now.Add(30 * time.Minute).Unix(),
	}
	authToken, err := r3.MintPerCallAuthToken(registry, accessKey, authClaims, reference, exactProposal)
	if err != nil {
		t.Fatal(err)
	}
	accessOutput, err := json.Marshal(struct {
		AuthToken string `json:"auth_token"`
		ExpiresIn int64  `json:"expires_in"`
	}{AuthToken: authToken, ExpiresIn: 1800})
	if err != nil {
		t.Fatal(err)
	}

	var sequence []string
	httpClient := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		switch request.URL.String() {
		case reference.URI():
			sequence = append(sequence, "proposal-fetch")
			prepared, err := signaturekey.PrepareRequest(request, clock, signaturekey.VerifyOptions{
				RequireExactComponents: true,
				AcceptedSchemes:        []signaturekey.Scheme{signaturekey.SchemeJWKSURI},
			})
			if err != nil {
				t.Fatal(err)
			}
			issuer, discovery, _, ok := prepared.Credential().JWKSURI()
			if !ok || issuer != "https://person.example" || discovery != aauth.PersonDiscoveryDocument {
				t.Fatalf("proposal fetch credential = %q %q, %t", issuer, discovery, ok)
			}
			if _, err := prepared.Verify(personKey.PublicJWK()); err != nil {
				t.Fatal(err)
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Content-Type": []string{"application/json"}},
				Body:       io.NopCloser(bytes.NewReader(exactProposal)), Request: request,
			}, nil
		case "https://api.access.example/token":
			sequence = append(sequence, "access-server")
			var input struct {
				ResourceToken string `json:"resource_token"`
				AgentToken    string `json:"agent_token"`
			}
			if err := json.NewDecoder(request.Body).Decode(&input); err != nil {
				t.Fatal(err)
			}
			if input.ResourceToken != resourceToken || input.AgentToken != agentToken {
				t.Fatal("Access Server input changed the exact proposal exchange tokens")
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Content-Type": []string{"application/json"}},
				Body:       io.NopCloser(bytes.NewReader(accessOutput)), Request: request,
			}, nil
		default:
			return nil, errors.New("unexpected request: " + request.URL.String())
		}
	})}
	store := newMemoryTokenStore()
	if err := store.Commit(context.Background(), directPersonTokenRecord(
		"person-token-1", "https://person.example", "https://resource.example", "person-123", "tenant-1",
		"https://provider.example", "aauth:planner@provider.example", agentKey.PublicJWK(),
		personTokenExpiresAt, personRetainUntil,
	)); err != nil {
		t.Fatal(err)
	}
	coreConsentCalls := 0
	classConsentCalls := 0
	var consentRequest AuthorizationRequest
	var proposalConsentErr error
	server, err := NewFederatedAuthorization(FederatedAuthorizationConfig{
		Issuer: "https://person.example", SigningKey: personKey, KeyResolver: resolver,
		Clock: clock, NewID: func() string { return "unused" }, HTTPClient: httpClient, Tokens: store,
		AccessServerEndpoint: func(context.Context, string) (string, error) {
			return "https://api.access.example/token", nil
		},
		BindPerson: func(context.Context, PersonTokenRequest) (Person, error) {
			return Person{}, errors.New("not used")
		},
		Consent: func(context.Context, AuthorizationRequest) error {
			coreConsentCalls++
			return nil
		},
		R3: &R3Config{
			Registry: registry,
			Admit:    func(context.Context, string) error { return nil },
			ConsentDocument: func(context.Context, AuthorizationRequest, r3.Reference, r3.Document) error {
				classConsentCalls++
				return nil
			},
			ConsentProposal: func(_ context.Context, request AuthorizationRequest, gotReference r3.Reference, gotProposal r3.Proposal) error {
				sequence = append(sequence, "proposal-consent")
				consentRequest = request
				if gotReference != reference || !personServerOperationsEqual(t, gotProposal.Operation(), operation) ||
					!reflect.DeepEqual(gotProposal.Parameters().Names(), []string{"filter"}) {
					t.Fatalf("proposal consent = %#v %#v", gotReference, gotProposal)
				}
				gotDisplay, ok := gotProposal.Display()
				if !ok || gotDisplay.Summary() != proposalDisplay.Summary() || gotDisplay.Detail() != proposalDisplay.Detail() {
					t.Fatalf("proposal display = %#v, %t", gotDisplay, ok)
				}
				return proposalConsentErr
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	call := func() *httptest.ResponseRecorder {
		body, err := json.Marshal(struct {
			ResourceToken string `json:"resource_token"`
		}{ResourceToken: resourceToken})
		if err != nil {
			t.Fatal(err)
		}
		request := httptest.NewRequest(http.MethodPost, "https://person.example/token", bytes.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		if err := signPersonServerTestRequest(request, agentKey, agentToken, clock); err != nil {
			t.Fatal(err)
		}
		response := httptest.NewRecorder()
		server.Handler().ServeHTTP(response, request)
		return response
	}
	response := call()
	if response.Code != http.StatusOK {
		t.Fatalf("proposal exchange = %d %s", response.Code, response.Body.String())
	}
	var output struct {
		AuthToken string `json:"auth_token"`
	}
	if err := json.NewDecoder(response.Body).Decode(&output); err != nil {
		t.Fatal(err)
	}
	if output.AuthToken != authToken || coreConsentCalls != 0 || classConsentCalls != 0 ||
		!reflect.DeepEqual(sequence, []string{"proposal-fetch", "proposal-consent", "access-server"}) {
		t.Fatalf("output/core/class/sequence = %t/%d/%d/%#v", output.AuthToken == authToken, coreConsentCalls, classConsentCalls, sequence)
	}
	if consentRequest.Account == nil || *consentRequest.Account != account ||
		consentRequest.Subject != "person-123" || consentRequest.Tenant != "tenant-1" || len(consentRequest.Scopes) != 0 {
		t.Fatalf("proposal consent request = %#v", consentRequest)
	}

	proposalConsentErr = errors.Join(ErrAccessDenied, errors.New("person declined exact proposal"))
	sequence = nil
	response = call()
	if response.Code != http.StatusForbidden ||
		!reflect.DeepEqual(sequence, []string{"proposal-fetch", "proposal-consent"}) {
		t.Fatalf("proposal consent refusal = %d %s, sequence %#v", response.Code, response.Body.String(), sequence)
	}
	proposalConsentErr = nil

	otherTypedOperation, err := mcp.NewOperation("records.delete")
	if err != nil {
		t.Fatal(err)
	}
	otherOperation, err := otherTypedOperation.ToR3()
	if err != nil {
		t.Fatal(err)
	}
	wrongReference, err := r3.NewReference("https://resource.example/r3/proposal-other", reference.Digest())
	if err != nil {
		t.Fatal(err)
	}
	changedReferenceToken, err := r3.MintPerCallAuthToken(registry, accessKey, authClaims, wrongReference, exactProposal)
	if err != nil {
		t.Fatal(err)
	}
	changedSubjectClaims := authClaims
	changedSubjectClaims.JTI = "changed-subject"
	changedSubjectClaims.Subject = "person-other"
	changedSubjectToken, err := r3.MintPerCallAuthToken(registry, accessKey, changedSubjectClaims, reference, exactProposal)
	if err != nil {
		t.Fatal(err)
	}
	changedTenantClaims := authClaims
	changedTenantClaims.JTI = "changed-tenant"
	changedTenantClaims.Tenant = "tenant-other"
	changedTenantToken, err := r3.MintPerCallAuthToken(registry, accessKey, changedTenantClaims, reference, exactProposal)
	if err != nil {
		t.Fatal(err)
	}
	otherAgentKey := personServerTestKey(t, "other-agent-key")
	changedKeyClaims := authClaims
	changedKeyClaims.JTI = "changed-key"
	changedKeyClaims.Confirmation = aauth.Confirmation{JWK: otherAgentKey.PublicJWK()}
	changedKeyToken, err := r3.MintPerCallAuthToken(registry, accessKey, changedKeyClaims, reference, exactProposal)
	if err != nil {
		t.Fatal(err)
	}
	otherAccount := "other-account"
	changedAccountClaims := authClaims
	changedAccountClaims.JTI = "changed-account"
	changedAccountClaims.Account = &otherAccount
	changedAccountToken := mintRawR3AuthTokenForTest(
		t, accessKey, changedAccountClaims, reference, []r3.Operation{operation}, nil,
	)
	changedOperationClaims := authClaims
	changedOperationClaims.JTI = "changed-operation"
	changedOperationToken := mintRawR3AuthTokenForTest(
		t, accessKey, changedOperationClaims, reference, []r3.Operation{otherOperation}, nil,
	)
	perCallClaims := authClaims
	perCallClaims.JTI = "continued-per-call"
	continuedPerCallToken := mintRawR3AuthTokenForTest(
		t, accessKey, perCallClaims, reference, []r3.Operation{operation}, []r3.Operation{},
	)
	for _, invalid := range []struct {
		name  string
		token string
	}{
		{name: "changed proposal reference", token: changedReferenceToken},
		{name: "changed proposal account", token: changedAccountToken},
		{name: "changed person", token: changedSubjectToken},
		{name: "changed tenant", token: changedTenantToken},
		{name: "changed agent key", token: changedKeyToken},
		{name: "changed proposal operation", token: changedOperationToken},
		{name: "continued per-call grant", token: continuedPerCallToken},
	} {
		t.Run(invalid.name, func(t *testing.T) {
			accessOutput, err = json.Marshal(struct {
				AuthToken string `json:"auth_token"`
				ExpiresIn int64  `json:"expires_in"`
			}{AuthToken: invalid.token, ExpiresIn: 1800})
			if err != nil {
				t.Fatal(err)
			}
			sequence = nil
			response := call()
			if response.Code != http.StatusInternalServerError || bytes.Contains(response.Body.Bytes(), []byte(invalid.token)) {
				t.Fatalf("invalid Access Server proposal result = %d %s", response.Code, response.Body.String())
			}
		})
	}

	missingLineageClaims := resourceClaims
	missingLineageClaims.JTI = "proposal-resource-token-missing-lineage"
	missingLineageClaims.PresentedJTI = "person-token-missing"
	resourceToken, _, err = r3.MintProposalResourceToken(
		registry, resourceKey, missingLineageClaims, reference.URI(), exactProposal,
	)
	if err != nil {
		t.Fatal(err)
	}
	sequence = nil
	response = call()
	if response.Code != http.StatusBadRequest || len(sequence) != 0 {
		t.Fatalf("missing proposal lineage = %d %s, sequence %#v", response.Code, response.Body.String(), sequence)
	}
}

func TestR3ProposalFailsClosedWithoutProposalConsentPolicy(t *testing.T) {
	classConsentCalls := 0
	server := &Server{r3: &r3Config{
		consentDocument: func(context.Context, AuthorizationRequest, r3.Reference, r3.Document) error {
			classConsentCalls++
			return nil
		},
	}}
	typedOperation, err := mcp.NewOperation("records.export")
	if err != nil {
		t.Fatal(err)
	}
	operation, err := typedOperation.ToR3()
	if err != nil {
		t.Fatal(err)
	}
	parameters, err := r3.NewParameters(map[string]r3.Parameter{})
	if err != nil {
		t.Fatal(err)
	}
	proposal, err := r3.NewProposal(operation, parameters, r3.ProposalOptions{})
	if err != nil {
		t.Fatal(err)
	}
	reference, err := r3.NewReference("https://resource.example/r3/proposal", r3.Digest([]byte("proposal")))
	if err != nil {
		t.Fatal(err)
	}
	err = server.consentR3(context.Background(), AuthorizationRequest{}, &verifiedR3{
		reference: reference, proposal: proposal, kind: r3.ArtifactProposal,
	})
	if err == nil || classConsentCalls != 0 {
		t.Fatalf("proposal consent error/class calls = %v/%d", err, classConsentCalls)
	}
}

func mintRawR3AuthTokenForTest(
	t *testing.T,
	key jose.SigningKey,
	claims aauth.AuthTokenClaims,
	reference r3.Reference,
	granted []r3.Operation,
	perCall []r3.Operation,
) string {
	t.Helper()
	grantedOperations, err := r3.NewGrantedOperations(mcp.Vocabulary(), granted...)
	if err != nil {
		t.Fatal(err)
	}
	grantedJSON, err := json.Marshal(grantedOperations)
	if err != nil {
		t.Fatal(err)
	}
	uriJSON, err := json.Marshal(reference.URI())
	if err != nil {
		t.Fatal(err)
	}
	digestJSON, err := json.Marshal(reference.Digest())
	if err != nil {
		t.Fatal(err)
	}
	claims.AdditionalClaims = map[string]json.RawMessage{
		"r3_uri":     uriJSON,
		"r3_s256":    digestJSON,
		"r3_granted": grantedJSON,
	}
	if perCall != nil {
		operations, err := r3.NewGrantedOperations(mcp.Vocabulary(), perCall...)
		if err != nil {
			t.Fatal(err)
		}
		perCallJSON, err := json.Marshal(operations)
		if err != nil {
			t.Fatal(err)
		}
		claims.AdditionalClaims["r3_per_call"] = perCallJSON
	}
	compact, err := aauth.MintAuthTokenCore(key, claims)
	if err != nil {
		t.Fatal(err)
	}
	return compact
}
