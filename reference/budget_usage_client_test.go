package reference

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	aa "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/budgets"
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

func TestBudgetUsageClientDiscoversSignsAndVerifiesResponse(t *testing.T) {
	now := time.Date(2026, 8, 29, 23, 0, 0, 0, time.UTC)
	clock := aa.ClockFunc(func() time.Time { return now })
	resourceKey := usageClientTestKey(t, "resource-client-key", 0x71)
	psKey := usageClientTestKey(t, "ps-client-key", 0x72)
	store, err := NewFileBudgetStore(t.TempDir() + "/budget.json")
	if err != nil {
		t.Fatal(err)
	}
	grant := budgets.Budget{Amount: 5_000_000, Unit: "USD", Decimals: 6}
	execution, err := NewBudgetExecution("https://as.example", "auth-client", "call-client", grant, 1_000_000, now.Add(time.Hour).Unix())
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := store.Claim(context.Background(), execution); err != nil {
		t.Fatal(err)
	}
	agentJKT := aa.S256([]byte("usage-client-agent"))
	if _, _, err := store.CompleteWithUsage(context.Background(), execution.Key, BudgetResult{Status: http.StatusOK, ContentType: "application/json", Body: []byte(`{"ok":true}`), Cost: 400_000}, BudgetUsageRecord{
		Key: execution.Key, PersonServer: "https://ps.example", Subject: "person-client", AgentJKT: agentJKT,
		Unit: grant.Unit, Decimals: grant.Decimals, Consumed: 400_000, RecordedAt: now.Unix(),
	}); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(nil)
	server.StartTLS()
	defer server.Close()
	publicResource := "https://resource.example"
	resource := &Resource{
		identifier: publicResource, signingKey: resourceKey, hasSigningKey: true, clock: clock,
		keyResolver:      signaturekey.StaticKeyResolver{"https://ps.example": {psKey.ID(): psKey.PublicJWK()}},
		budgetUsageStore: store, budgetUsageEndpoint: publicResource + "/usage", budgetUsagePath: "/usage",
	}
	server.Config.Handler = resource.Handler()
	resourceHTTPClient := &http.Client{Transport: mapOriginTransport(server.Client().Transport, publicResource, server.URL)}
	resourceKeyResolver, err := signaturekey.NewHTTPKeyResolver(signaturekey.HTTPKeyResolverConfig{
		Client: resourceHTTPClient, Clock: clock,
		Admit: func(_ context.Context, endpoint string) error {
			if strings.HasPrefix(endpoint, publicResource+"/") {
				return nil
			}
			return errors.New("resource endpoint outside test trust")
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewBudgetUsageClient(BudgetUsageClientConfig{
		Client: resourceHTTPClient, PersonServer: "https://ps.example", SigningKey: psKey,
		KeyResolver: resourceKeyResolver, Clock: clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := client.Query(context.Background(), publicResource, BudgetUsageQuery{Subject: "person-client", AgentJKT: []string{agentJKT}})
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Unit != "USD" || snapshot.Decimals != 6 || snapshot.Usage == nil || snapshot.Usage.AllTime != 400_000 || snapshot.ByKey[agentJKT] != 400_000 {
		t.Fatalf("usage snapshot = %#v", snapshot)
	}
}

func TestBudgetUsageClientRejectsUnsignedTamperedAndWrongMetadata(t *testing.T) {
	now := time.Date(2026, 8, 29, 23, 10, 0, 0, time.UTC)
	clock := aa.ClockFunc(func() time.Time { return now })
	resourceKey := usageClientTestKey(t, "resource-client-negative", 0x73)
	psKey := usageClientTestKey(t, "ps-client-negative", 0x74)
	newServer := func(handler http.Handler) *httptest.Server {
		server := httptest.NewUnstartedServer(nil)
		server.StartTLS()
		server.Config.Handler = handler
		return server
	}
	newResource := func(serverURL string, signed bool) *Resource {
		resource := &Resource{identifier: serverURL, clock: clock, keyResolver: signaturekey.StaticKeyResolver{"https://ps.example": {psKey.ID(): psKey.PublicJWK()}}, budgetUsageStore: &fakeBudgetUsageStore{snapshot: BudgetUsageSnapshot{Unit: "USD", Decimals: 6, Usage: &BudgetUsageCounters{AllTime: 100}}}, budgetUsageEndpoint: serverURL + "/usage", budgetUsagePath: "/usage"}
		if signed {
			resource.signingKey, resource.hasSigningKey = resourceKey, true
		}
		return resource
	}
	resourceServer := newServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/.well-known/aauth-resource.json" {
			response.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(response, `{"issuer":"https://wrong.example","usage_endpoint":"https://wrong.example/usage","jwks_uri":"https://wrong.example/jwks"}`)
			return
		}
		http.NotFound(response, request)
	}))
	metadataOrigin := "https://metadata.example"
	client, err := NewBudgetUsageClient(BudgetUsageClientConfig{Client: &http.Client{Transport: mapOriginTransport(resourceServer.Client().Transport, metadataOrigin, resourceServer.URL)}, PersonServer: "https://ps.example", SigningKey: psKey, KeyResolver: signaturekey.StaticKeyResolver{}, Clock: clock})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Query(context.Background(), metadataOrigin, BudgetUsageQuery{Subject: "person"}); err == nil {
		t.Fatal("wrong metadata issuer was accepted")
	} else {
		var typed *BudgetUsageClientError
		if !errors.As(err, &typed) || typed.Code != BudgetUsageClientInvalid {
			t.Fatalf("wrong metadata error = %T %v", err, err)
		}
	}
	resourceServer.Close()

	unsignedOrigin := "https://unsigned.example"
	unsignedServer := newServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/.well-known/aauth-resource.json" {
			response.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(response, `{"issuer":"https://unsigned.example","usage_endpoint":"https://unsigned.example/usage","jwks_uri":"https://unsigned.example/jwks"}`)
			return
		}
		if request.URL.Path == "/usage" {
			response.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(response, `{"as_of":1777504200,"aud":"https://ps.example","unit":"USD","decimals":6,"sub":"person"}`)
			return
		}
		http.NotFound(response, request)
	}))
	client, err = NewBudgetUsageClient(BudgetUsageClientConfig{Client: &http.Client{Transport: mapOriginTransport(unsignedServer.Client().Transport, unsignedOrigin, unsignedServer.URL)}, PersonServer: "https://ps.example", SigningKey: psKey, KeyResolver: signaturekey.StaticKeyResolver{}, Clock: clock})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Query(context.Background(), unsignedOrigin, BudgetUsageQuery{Subject: "person"}); err == nil {
		t.Fatal("unsigned usage response was accepted")
	} else {
		var typed *BudgetUsageClientError
		if !errors.As(err, &typed) || typed.Code != BudgetUsageClientBadSignature {
			t.Fatalf("unsigned response error = %T %v", err, err)
		}
	}
	unsignedServer.Close()

	signedOrigin := "https://signed.example"
	signedServer := newServer(nil)
	signedResource := newResource(signedOrigin, true)
	signedServer.Config.Handler = signedResource.Handler()
	underlying := mapOriginTransport(signedServer.Client().Transport, signedOrigin, signedServer.URL)
	tamperingClient := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		response, err := underlying.RoundTrip(request)
		if err != nil || request.URL.Path != "/usage" {
			return response, err
		}
		body, err := io.ReadAll(response.Body)
		if err != nil {
			return nil, err
		}
		_ = response.Body.Close()
		body = bytes.Replace(body, []byte("\"as_of\""), []byte("\"as_of_changed\""), 1)
		response.Body = io.NopCloser(bytes.NewReader(body))
		return response, nil
	})}
	client, err = NewBudgetUsageClient(BudgetUsageClientConfig{Client: tamperingClient, PersonServer: "https://ps.example", SigningKey: psKey, KeyResolver: signaturekey.StaticKeyResolver{signedOrigin: {resourceKey.ID(): resourceKey.PublicJWK()}}, Clock: clock})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Query(context.Background(), signedOrigin, BudgetUsageQuery{Subject: "person"}); err == nil {
		t.Fatal("tampered usage response was accepted")
	} else {
		var typed *BudgetUsageClientError
		if !errors.As(err, &typed) || typed.Code != BudgetUsageClientBadSignature {
			t.Fatalf("tampered response error = %T %v", err, err)
		}
	}
	signedServer.Close()
}

func TestDecodeBudgetUsageResponseRequiresExactEchoesAndCounterShape(t *testing.T) {
	now := time.Date(2026, 8, 29, 23, 20, 0, 0, time.UTC)
	base := `{"as_of":1788045600,"aud":"https://ps.example","unit":"USD","decimals":6,"sub":"other","usage":{"all_time":10}}`
	if _, err := decodeBudgetUsageResponse([]byte(base), BudgetUsageQuery{Subject: "person"}, "https://ps.example", now); err == nil {
		t.Fatal("response with a mismatched scope echo was accepted")
	}
	withoutAllTime := `{"as_of":1788045600,"aud":"https://ps.example","unit":"USD","decimals":6,"sub":"person","usage":{"day":10}}`
	if _, err := decodeBudgetUsageResponse([]byte(withoutAllTime), BudgetUsageQuery{Subject: "person"}, "https://ps.example", now); err == nil {
		t.Fatal("usage response without all_time was accepted")
	}
	unexpectedKey := `{"as_of":1788045600,"aud":"https://ps.example","unit":"USD","decimals":6,"sub":"person","jkts":{"unexpected":1}}`
	if _, err := decodeBudgetUsageResponse([]byte(unexpectedKey), BudgetUsageQuery{Subject: "person", AgentJKT: []string{aa.S256([]byte("expected"))}}, "https://ps.example", now); err == nil {
		t.Fatal("usage response with an unrequested key was accepted")
	}
	unexpectedKeysWithoutRequest := `{"as_of":1788045600,"aud":"https://ps.example","unit":"USD","decimals":6,"sub":"person","jkts":{}}`
	if _, err := decodeBudgetUsageResponse([]byte(unexpectedKeysWithoutRequest), BudgetUsageQuery{Subject: "person"}, "https://ps.example", now); err == nil {
		t.Fatal("usage response with unrequested key figures was accepted")
	}
	nullUsage := `{"as_of":1788045600,"aud":"https://ps.example","unit":"USD","decimals":6,"sub":"person","usage":null}`
	if _, err := decodeBudgetUsageResponse([]byte(nullUsage), BudgetUsageQuery{Subject: "person"}, "https://ps.example", now); err == nil {
		t.Fatal("null usage response was accepted")
	}
}

func usageClientTestKey(t *testing.T, id string, seed byte) jose.SigningKey {
	t.Helper()
	key, err := jose.NewEd25519SigningKey(id, ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, ed25519.SeedSize)))
	if err != nil {
		t.Fatal(err)
	}
	return key
}

type fakeBudgetUsageStore struct {
	snapshot BudgetUsageSnapshot
}

func (store fakeBudgetUsageStore) Usage(context.Context, BudgetUsageQuery, time.Time) (BudgetUsageSnapshot, error) {
	if store.snapshot.Unit == "" {
		return BudgetUsageSnapshot{}, errors.New("fake usage store")
	}
	return store.snapshot, nil
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func mapOriginTransport(base http.RoundTripper, publicOrigin, backendOrigin string) http.RoundTripper {
	publicURL, _ := url.Parse(publicOrigin)
	backendURL, _ := url.Parse(backendOrigin)
	return roundTripFunc(func(request *http.Request) (*http.Response, error) {
		mapped := request.Clone(request.Context())
		mapped.URL.Scheme, mapped.URL.Host = backendURL.Scheme, backendURL.Host
		mapped.Host = publicURL.Host
		return base.RoundTrip(mapped)
	})
}
