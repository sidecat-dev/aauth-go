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
	"aauth-go/r3"
	"aauth-go/signaturekey"
)

func TestFederatedMCPR3FetchesBeforeConsentAndVerifiesAccessServerResult(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 31, 9, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
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
	agentJKT, err := agentKey.PublicJWK().Thumbprint()
	if err != nil {
		t.Fatal(err)
	}
	account := "work-account"
	read, _ := r3.NewMCPOperation("records.read")
	export, _ := r3.NewMCPOperation("records.export")
	operationSet, _ := r3.NewMCPOperationSet(read, export)
	display, _ := r3.NewDisplay("Read and export records", "Exports may leave the system", "Record contents", "Exported copies cannot be recalled")
	document, _ := r3.NewDocument(operationSet, r3.DocumentOptions{Account: &account, Display: &display})
	exactDocument, _ := json.Marshal(document)
	reference, _ := r3.NewReference("https://resource.example/r3/document", r3.Digest(exactDocument))
	resourceClaims := aauth.ResourceTokenClaims{
		Issuer: "https://resource.example", DWK: aauth.ResourceDiscoveryDocument,
		Audience: "https://access.example", JTI: "resource-token-1", AgentJKT: agentJKT,
		IssuedAt: now.Unix(), ExpiresAt: now.Add(5 * time.Minute).Unix(), Scope: "records.read",
		PersonServer: "https://person.example", Subject: "person-123", PresentedJTI: "person-token-1",
		Account: &account, Tenant: "tenant-1",
	}
	resourceToken, _, err := r3.MintMCPResourceToken(resourceKey, resourceClaims, reference.URI(), exactDocument)
	if err != nil {
		t.Fatal(err)
	}
	grantedOperations, _ := r3.NewGrantedOperations(read)
	grant, _ := r3.NewGrant(grantedOperations, document)
	authToken, err := r3.MintMCPDirectAuthToken(accessKey, aauth.AuthTokenClaims{
		Issuer: "https://access.example", DWK: aauth.AccessDiscoveryDocument,
		Audience: "https://resource.example", JTI: "auth-token-1",
		PersonServer: "https://person.example", Subject: "person-123", Scope: "records.read",
		Account: &account, Tenant: "tenant-1", Confirmation: aauth.Confirmation{JWK: agentKey.PublicJWK()},
		IssuedAt: now.Unix(), ExpiresAt: now.Add(30 * time.Minute).Unix(),
	}, reference, exactDocument, grant)
	if err != nil {
		t.Fatal(err)
	}
	accessOutput, _ := json.Marshal(struct {
		AuthToken string `json:"auth_token"`
		ExpiresIn int64  `json:"expires_in"`
	}{AuthToken: authToken, ExpiresIn: 1800})

	var sequence []string
	var resourceFetchErr error
	resourceFetchStatus := http.StatusOK
	httpClient := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		switch request.URL.String() {
		case reference.URI():
			sequence = append(sequence, "resource-fetch")
			if resourceFetchErr != nil {
				return nil, resourceFetchErr
			}
			prepared, err := signaturekey.PrepareRequest(request, clock, signaturekey.VerifyOptions{
				RequireExactComponents: true,
				AcceptedSchemes:        []signaturekey.Scheme{signaturekey.SchemeJWKSURI},
			})
			if err != nil {
				t.Fatal(err)
			}
			issuer, discovery, _, ok := prepared.Credential().JWKSURI()
			if !ok || issuer != "https://person.example" || discovery != aauth.PersonDiscoveryDocument {
				t.Fatalf("R3 fetch credential = %q %q, %t", issuer, discovery, ok)
			}
			if _, err := prepared.Verify(personKey.PublicJWK()); err != nil {
				t.Fatal(err)
			}
			return &http.Response{
				StatusCode: resourceFetchStatus,
				Header:     http.Header{"Content-Type": []string{"application/json"}},
				Body:       io.NopCloser(bytes.NewReader(exactDocument)), Request: request,
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
				t.Fatalf("Access Server input changed exact tokens")
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
	personRecord := directPersonTokenRecord(
		"person-token-1", "https://person.example", "https://resource.example", "person-123", "tenant-1",
		"https://provider.example", "aauth:planner@provider.example", agentKey.PublicJWK(),
		now.Add(20*time.Minute), now.Add(25*time.Minute),
	)
	if err := store.Commit(context.Background(), personRecord); err != nil {
		t.Fatal(err)
	}
	coreConsentCalls := 0
	var consentRequest AuthorizationRequest
	var r3ConsentErr error
	server, err := NewFederatedAuthorization(FederatedAuthorizationConfig{
		Issuer: "https://person.example", SigningKey: personKey, KeyResolver: resolver,
		Clock: clock, NewID: func() string { return "unused" }, HTTPClient: httpClient, Tokens: store,
		AccessServerEndpoint: func(context.Context, string) (string, error) {
			return "https://api.access.example/token", nil
		},
		BindPerson: func(context.Context, PersonTokenRequest) (Person, error) { return Person{}, errors.New("not used") },
		Consent: func(context.Context, AuthorizationRequest) error {
			coreConsentCalls++
			return nil
		},
		MCPR3: &MCPR3Config{
			Admit: func(_ context.Context, endpoint string) error {
				if endpoint != reference.URI() {
					t.Fatalf("admitted endpoint = %q", endpoint)
				}
				return nil
			},
			Consent: func(_ context.Context, request AuthorizationRequest, gotReference r3.Reference, gotDocument r3.Document) error {
				sequence = append(sequence, "consent")
				consentRequest = request
				if gotReference != reference || !gotDocument.OperationSet().Equal(operationSet) {
					t.Fatalf("R3 consent = %#v %#v", gotReference, gotDocument)
				}
				gotDisplay, ok := gotDocument.Display()
				if !ok || gotDisplay.Summary() != display.Summary() {
					t.Fatalf("R3 display = %#v, %t", gotDisplay, ok)
				}
				return r3ConsentErr
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	call := func() *httptest.ResponseRecorder {
		body, _ := json.Marshal(struct {
			ResourceToken string `json:"resource_token"`
		}{ResourceToken: resourceToken})
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
		t.Fatalf("exchange = %d %s", response.Code, response.Body.String())
	}
	var output struct {
		AuthToken string `json:"auth_token"`
	}
	if err := json.NewDecoder(response.Body).Decode(&output); err != nil {
		t.Fatal(err)
	}
	if output.AuthToken != authToken || coreConsentCalls != 0 ||
		!reflect.DeepEqual(sequence, []string{"resource-fetch", "consent", "access-server"}) {
		t.Fatalf("output/core/sequence = %t/%d/%#v", output.AuthToken == authToken, coreConsentCalls, sequence)
	}
	if consentRequest.Account == nil || *consentRequest.Account != account ||
		!reflect.DeepEqual(consentRequest.Scopes, []string{"records.read"}) {
		t.Fatalf("consent request = %#v", consentRequest)
	}

	resourceToken, _, err = r3.MintMCPResourceToken(resourceKey, aauth.ResourceTokenClaims{
		Issuer: "https://resource.example", DWK: aauth.ResourceDiscoveryDocument,
		Audience: "https://access.example", JTI: "scopeless-resource-token", AgentJKT: agentJKT,
		IssuedAt: now.Unix(), ExpiresAt: now.Add(5 * time.Minute).Unix(),
		PersonServer: "https://person.example", Subject: "person-123", PresentedJTI: "person-token-1",
		Account: &account, Tenant: "tenant-1",
	}, reference.URI(), exactDocument)
	if err != nil {
		t.Fatal(err)
	}
	authToken, err = r3.MintMCPDirectAuthToken(accessKey, aauth.AuthTokenClaims{
		Issuer: "https://access.example", DWK: aauth.AccessDiscoveryDocument,
		Audience: "https://resource.example", JTI: "scopeless-auth-token",
		PersonServer: "https://person.example", Subject: "person-123",
		Account: &account, Tenant: "tenant-1", Confirmation: aauth.Confirmation{JWK: agentKey.PublicJWK()},
		IssuedAt: now.Unix(), ExpiresAt: now.Add(30 * time.Minute).Unix(),
	}, reference, exactDocument, grant)
	if err != nil {
		t.Fatal(err)
	}
	accessOutput, _ = json.Marshal(struct {
		AuthToken string `json:"auth_token"`
		ExpiresIn int64  `json:"expires_in"`
	}{AuthToken: authToken, ExpiresIn: 1800})
	sequence = nil
	consentRequest = AuthorizationRequest{}
	response = call()
	if response.Code != http.StatusOK {
		t.Fatalf("scopeless exchange = %d %s", response.Code, response.Body.String())
	}
	if len(consentRequest.Scopes) != 0 || !reflect.DeepEqual(sequence, []string{"resource-fetch", "consent", "access-server"}) {
		t.Fatalf("scopeless consent/sequence = %#v/%#v", consentRequest, sequence)
	}

	coreOnly, err := aauth.MintAuthToken(accessKey, aauth.AuthTokenClaims{
		Issuer: "https://access.example", DWK: aauth.AccessDiscoveryDocument,
		Audience: "https://resource.example", JTI: "core-only-auth-token",
		PersonServer: "https://person.example", Subject: "person-123", Scope: "records.read",
		Confirmation: aauth.Confirmation{JWK: agentKey.PublicJWK()},
		IssuedAt:     now.Unix(), ExpiresAt: now.Add(30 * time.Minute).Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	wrongReference, _ := r3.NewReference("https://resource.example/r3/other", reference.Digest())
	wrongReferenceToken, err := r3.MintMCPDirectAuthToken(accessKey, aauth.AuthTokenClaims{
		Issuer: "https://access.example", DWK: aauth.AccessDiscoveryDocument,
		Audience: "https://resource.example", JTI: "wrong-reference-auth-token",
		PersonServer: "https://person.example", Subject: "person-123",
		Account: &account, Tenant: "tenant-1", Confirmation: aauth.Confirmation{JWK: agentKey.PublicJWK()},
		IssuedAt: now.Unix(), ExpiresAt: now.Add(30 * time.Minute).Unix(),
	}, wrongReference, exactDocument, grant)
	if err != nil {
		t.Fatal(err)
	}
	for _, invalid := range []struct {
		name  string
		token string
	}{
		{name: "Core-only Access Server result", token: coreOnly},
		{name: "changed R3 reference", token: wrongReferenceToken},
	} {
		t.Run(invalid.name, func(t *testing.T) {
			accessOutput, _ = json.Marshal(struct {
				AuthToken string `json:"auth_token"`
				ExpiresIn int64  `json:"expires_in"`
			}{AuthToken: invalid.token, ExpiresIn: 1800})
			sequence = nil
			response := call()
			if response.Code != http.StatusInternalServerError || bytes.Contains(response.Body.Bytes(), []byte(invalid.token)) {
				t.Fatalf("invalid AS result = %d %s", response.Code, response.Body.String())
			}
		})
	}

	validDocumentBytes := append([]byte(nil), exactDocument...)
	exactDocument = append(exactDocument, ' ')
	sequence = nil
	response = call()
	if response.Code != http.StatusBadRequest || !reflect.DeepEqual(sequence, []string{"resource-fetch"}) {
		t.Fatalf("hash mismatch = %d %s, sequence %#v", response.Code, response.Body.String(), sequence)
	}
	exactDocument = validDocumentBytes
	r3ConsentErr = errors.Join(ErrAccessDenied, errors.New("person declined R3 consent"))
	sequence = nil
	response = call()
	if response.Code != http.StatusForbidden || !reflect.DeepEqual(sequence, []string{"resource-fetch", "consent"}) {
		t.Fatalf("consent refusal = %d %s, sequence %#v", response.Code, response.Body.String(), sequence)
	}
	r3ConsentErr = nil
	resourceFetchStatus = http.StatusUnauthorized
	sequence = nil
	response = call()
	if response.Code != http.StatusInternalServerError || !reflect.DeepEqual(sequence, []string{"resource-fetch"}) {
		t.Fatalf("Resource authentication failure = %d %s, sequence %#v", response.Code, response.Body.String(), sequence)
	}
	resourceFetchStatus = http.StatusOK
	resourceFetchErr = errors.New("Resource transport unavailable")
	sequence = nil
	response = call()
	if response.Code != http.StatusInternalServerError || !reflect.DeepEqual(sequence, []string{"resource-fetch"}) {
		t.Fatalf("fetch failure = %d %s, sequence %#v", response.Code, response.Body.String(), sequence)
	}
}
