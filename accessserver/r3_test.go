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
	"sync"
	"testing"
	"time"

	aauth "aauth-go"
	"aauth-go/r3"
	"aauth-go/signaturekey"
)

func TestMCPR3IssuesOnlyAfterIndependentFetchPolicyAndAtomicAudit(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 31, 10, 0, 0, 0, time.UTC)
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
	agentJKT, _ := agentKey.PublicJWK().Thumbprint()
	account := "work-account"
	read, _ := r3.NewMCPOperation("records.read")
	export, _ := r3.NewMCPOperation("records.export")
	operationSet, _ := r3.NewMCPOperationSet(read, export)
	document, _ := r3.NewDocument(operationSet, r3.DocumentOptions{Account: &account})
	exactDocument, _ := json.Marshal(document)
	reference, _ := r3.NewReference("https://resource.example/r3/document", r3.Digest(exactDocument))
	resourceToken, _, err := r3.MintMCPResourceToken(resourceKey, aauth.ResourceTokenClaims{
		Issuer: "https://resource.example", DWK: aauth.ResourceDiscoveryDocument,
		Audience: "https://access.example", JTI: "resource-token-1", AgentJKT: agentJKT,
		IssuedAt: now.Unix(), ExpiresAt: now.Add(5 * time.Minute).Unix(), Scope: "records.read records.export",
		PersonServer: "https://person.example", Subject: "person-123", PresentedJTI: "person-token-1",
		Account: &account, Tenant: "tenant-1",
	}, reference.URI(), exactDocument)
	if err != nil {
		t.Fatal(err)
	}
	granted, _ := r3.NewGrantedOperations(read)
	grant, _ := r3.NewGrant(granted, document)
	var sequence []string
	var resourceFetchErr error
	resourceFetchStatus := http.StatusOK
	httpClient := &http.Client{Transport: accessR3RoundTripper(func(request *http.Request) (*http.Response, error) {
		sequence = append(sequence, "resource-fetch")
		if resourceFetchErr != nil {
			return nil, resourceFetchErr
		}
		if request.URL.String() != reference.URI() {
			t.Fatalf("fetch URI = %q", request.URL)
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
			StatusCode: resourceFetchStatus,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body:       io.NopCloser(bytes.NewReader(exactDocument)), Request: request,
		}, nil
	})}
	issuances := &r3TestIssuanceStore{onCommit: func() { sequence = append(sequence, "audit-commit") }}
	var evaluated AuthorizationRequest
	policyDecision := Decision{Scopes: []string{"records.read"}, Lifetime: 30 * time.Minute, MCPR3Grant: &grant}
	server, err := New(Config{
		Issuer: "https://access.example", SigningKey: accessKey, KeyResolver: resolver,
		Clock: clock, NewID: func() string { return "auth-token-1" },
		TrustPersonServer: func(context.Context, string) error { return nil },
		Authorize: func(_ context.Context, request AuthorizationRequest) (Decision, error) {
			sequence = append(sequence, "policy")
			evaluated = request
			return policyDecision, nil
		},
		MCPR3: &MCPR3Config{
			HTTPClient: httpClient,
			Admit: func(_ context.Context, endpoint string) error {
				if endpoint != reference.URI() {
					t.Fatalf("admitted endpoint = %q", endpoint)
				}
				return nil
			},
			Issuances: issuances,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	call := func() *httptest.ResponseRecorder {
		body, _ := json.Marshal(map[string]string{"resource_token": resourceToken, "agent_token": agentToken})
		request := httptest.NewRequest(http.MethodPost, "https://access.example/token", bytes.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		if err := signaturekey.SignJWKSURIRequestWithOptions(
			request, personKey, "https://person.example", aauth.PersonDiscoveryDocument, clock,
			signaturekey.SignOptions{AdditionalComponents: []string{"content-type", "content-digest"}, MaxBodyBytes: int64(len(body))},
		); err != nil {
			t.Fatal(err)
		}
		response := httptest.NewRecorder()
		server.Handler().ServeHTTP(response, request)
		return response
	}
	response := call()
	if response.Code != http.StatusOK {
		t.Fatalf("token = %d %s", response.Code, response.Body.String())
	}
	var output struct {
		AuthToken string `json:"auth_token"`
		ExpiresIn int64  `json:"expires_in"`
	}
	if err := json.NewDecoder(response.Body).Decode(&output); err != nil {
		t.Fatal(err)
	}
	claims, gotReference, gotGranted, err := r3.VerifyMCPDirectAuthToken(context.Background(), output.AuthToken, resolver, clock)
	if err != nil {
		t.Fatal(err)
	}
	if gotReference != reference || !reflect.DeepEqual(gotGranted.Operations(), granted.Operations()) ||
		claims.Scope != "records.read" || claims.Account == nil || *claims.Account != account {
		t.Fatalf("R3 Auth token = %#v %#v %#v", claims, gotReference, gotGranted)
	}
	if evaluated.MCPR3 == nil || evaluated.MCPR3.Reference != reference ||
		!evaluated.MCPR3.Document.OperationSet().Equal(operationSet) {
		t.Fatalf("policy input = %#v", evaluated)
	}
	if !reflect.DeepEqual(sequence, []string{"resource-fetch", "policy", "audit-commit"}) {
		t.Fatalf("sequence = %#v", sequence)
	}
	records := issuances.recordsCopy()
	if len(records) != 1 || records[0].ExactAuthToken != output.AuthToken ||
		records[0].R3Reference != reference || records[0].PersonServer != "https://person.example" ||
		records[0].Subject != "person-123" || records[0].AgentJKT != agentJKT ||
		records[0].Agent != "aauth:planner@provider.example" || records[0].ParentAgent != "" {
		t.Fatalf("audit records = %#v", records)
	}

	for _, failure := range []struct {
		name           string
		commitThenFail bool
		wantRecords    int
	}{
		{name: "definite audit failure"},
		{name: "uncertain audit commit", commitThenFail: true, wantRecords: 1},
	} {
		t.Run(failure.name, func(t *testing.T) {
			sequence = nil
			issuances.reset()
			issuances.commitErr = errors.New("audit commit unavailable")
			issuances.commitThenFail = failure.commitThenFail
			response := call()
			if response.Code != http.StatusInternalServerError || bytes.Contains(response.Body.Bytes(), []byte("auth_token")) {
				t.Fatalf("failed issuance = %d %s", response.Code, response.Body.String())
			}
			if got := len(issuances.recordsCopy()); got != failure.wantRecords {
				t.Fatalf("retained records = %d", got)
			}
			if !reflect.DeepEqual(sequence, []string{"resource-fetch", "policy", "audit-commit"}) {
				t.Fatalf("failure sequence = %#v", sequence)
			}
		})
	}

	sequence = nil
	issuances.reset()
	policyDecision = Decision{Lifetime: 30 * time.Minute, MCPR3Grant: &grant}
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
	response = call()
	if response.Code != http.StatusOK {
		t.Fatalf("scopeless token = %d %s", response.Code, response.Body.String())
	}
	if err := json.NewDecoder(response.Body).Decode(&output); err != nil {
		t.Fatal(err)
	}
	claims, _, _, err = r3.VerifyMCPDirectAuthToken(context.Background(), output.AuthToken, resolver, clock)
	if err != nil || claims.Scope != "" {
		t.Fatalf("scopeless R3 Auth token = %#v, %v", claims, err)
	}
	sequence = nil
	issuances.reset()
	resourceFetchStatus = http.StatusUnauthorized
	response = call()
	if response.Code != http.StatusInternalServerError || bytes.Contains(response.Body.Bytes(), []byte("auth_token")) || len(issuances.recordsCopy()) != 0 {
		t.Fatalf("Resource authentication failure = %d %s, audit %#v", response.Code, response.Body.String(), issuances.recordsCopy())
	}
	resourceFetchStatus = http.StatusOK
	resourceFetchErr = errors.New("Resource transport unavailable")
	response = call()
	if response.Code != http.StatusInternalServerError || bytes.Contains(response.Body.Bytes(), []byte("auth_token")) || len(issuances.recordsCopy()) != 0 {
		t.Fatalf("fetch failure = %d %s, audit %#v", response.Code, response.Body.String(), issuances.recordsCopy())
	}
}

func TestR3IssuanceStoreFixturePreservesThePublicContract(t *testing.T) {
	t.Parallel()

	account := "account-1"
	reference, err := r3.NewReference(
		"https://resource.example/r3/document",
		r3.Digest([]byte(`{"operations":[{"tool":"records.read"}]}`)),
	)
	if err != nil {
		t.Fatal(err)
	}
	record := R3IssuanceRecord{
		AuthTokenReference: aauth.TokenReference{Issuer: "https://access.example", JTI: "auth-token-1"},
		ExactAuthToken:     "exact-token",
		Resource:           "https://resource.example",
		R3Reference:        reference,
		IssuedAt:           time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC),
		PersonServer:       "https://person.example",
		Subject:            "person-1",
		Account:            &account,
		AgentJKT:           "agent-thumbprint",
		Agent:              "aauth:planner@provider.example",
	}
	store := &r3TestIssuanceStore{}
	if err := store.Commit(context.Background(), record); err != nil {
		t.Fatal(err)
	}

	account = "mutated-by-caller"
	retained := store.recordsCopy()
	if len(retained) != 1 || retained[0].Account == nil || *retained[0].Account != "account-1" {
		t.Fatalf("retained record aliases caller state: %#v", retained)
	}
	if err := store.Commit(context.Background(), retained[0]); err != nil {
		t.Fatalf("exact repeat: %v", err)
	}
	if got := len(store.recordsCopy()); got != 1 {
		t.Fatalf("exact repeat retained %d records, want 1", got)
	}

	changed := retained[0]
	changed.Resource = "https://other-resource.example"
	if err := store.Commit(context.Background(), changed); !errors.Is(err, ErrR3IssuanceConflict) {
		t.Fatalf("changed repeat error = %v, want %v", err, ErrR3IssuanceConflict)
	}

	concurrent := &r3TestIssuanceStore{}
	const repeatCount = 16
	start := make(chan struct{})
	errorsSeen := make(chan error, repeatCount)
	var wait sync.WaitGroup
	for range repeatCount {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			errorsSeen <- concurrent.Commit(context.Background(), retained[0])
		}()
	}
	close(start)
	wait.Wait()
	close(errorsSeen)
	for err := range errorsSeen {
		if err != nil {
			t.Fatalf("concurrent exact repeat: %v", err)
		}
	}
	if got := len(concurrent.recordsCopy()); got != 1 {
		t.Fatalf("concurrent exact repeats retained %d records, want 1", got)
	}

	competing := &r3TestIssuanceStore{}
	changed = retained[0]
	changed.Resource = "https://other-resource.example"
	start = make(chan struct{})
	errorsSeen = make(chan error, repeatCount)
	wait = sync.WaitGroup{}
	for index := range repeatCount {
		candidate := retained[0]
		if index%2 != 0 {
			candidate = changed
		}
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			errorsSeen <- competing.Commit(context.Background(), candidate)
		}()
	}
	close(start)
	wait.Wait()
	close(errorsSeen)
	conflicts := 0
	for err := range errorsSeen {
		switch {
		case err == nil:
		case errors.Is(err, ErrR3IssuanceConflict):
			conflicts++
		default:
			t.Fatalf("competing commit: %v", err)
		}
	}
	winner := competing.recordsCopy()
	if len(winner) != 1 || conflicts == 0 ||
		!reflect.DeepEqual(winner[0], retained[0]) && !reflect.DeepEqual(winner[0], changed) {
		t.Fatalf("competing commits retained %#v with %d conflicts", winner, conflicts)
	}
}

type r3TestIssuanceStore struct {
	mu             sync.Mutex
	records        []R3IssuanceRecord
	commitErr      error
	commitThenFail bool
	onCommit       func()
}

func (store *r3TestIssuanceStore) Commit(_ context.Context, record R3IssuanceRecord) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.onCommit != nil {
		store.onCommit()
	}
	if store.commitErr != nil && !store.commitThenFail {
		return store.commitErr
	}
	copy := cloneR3IssuanceRecord(record)
	for _, retained := range store.records {
		if retained.AuthTokenReference != copy.AuthTokenReference {
			continue
		}
		if !reflect.DeepEqual(retained, copy) {
			return ErrR3IssuanceConflict
		}
		return store.commitErr
	}
	store.records = append(store.records, copy)
	if store.commitErr != nil {
		return store.commitErr
	}
	return nil
}

func (store *r3TestIssuanceStore) recordsCopy() []R3IssuanceRecord {
	store.mu.Lock()
	defer store.mu.Unlock()
	records := make([]R3IssuanceRecord, len(store.records))
	for i, record := range store.records {
		records[i] = cloneR3IssuanceRecord(record)
	}
	return records
}

func (store *r3TestIssuanceStore) reset() {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.records = nil
	store.commitErr = nil
	store.commitThenFail = false
}

func cloneR3IssuanceRecord(record R3IssuanceRecord) R3IssuanceRecord {
	copy := record
	if record.Account != nil {
		account := *record.Account
		copy.Account = &account
	}
	return copy
}

type accessR3RoundTripper func(*http.Request) (*http.Response, error)

func (roundTrip accessR3RoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	return roundTrip(request)
}
