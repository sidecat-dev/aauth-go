package resource

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/budgets"
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

func TestUsageEndpointAnswersTheSignedCallerAndRejectsABadBody(t *testing.T) {
	t.Parallel()

	protocol := newBudgetResourceProtocol(t, 1, http.NotFoundHandler())
	scripted := &scriptedUsageStore{
		budgetMemoryStore: protocol.store,
		result: BudgetUsageResult{
			Unit: protocol.unit, HasUnit: true, ScopeRecognized: true,
			AllTime: 5, AllTimeOK: true, Day: 5, DayOK: true, Week: 5, WeekOK: true,
			Month: 5, MonthOK: true, Year: 5, YearOK: true,
		},
	}
	protocol.config.Budget.Store = scripted
	accessKey := testSigningKey(t, "usage-access", 74)
	const accessIssuer = "https://access.example"
	protocol.resolver[signaturekey.StaticKeyReference{
		Issuer: accessIssuer, DiscoveryDocument: aauth.AccessDiscoveryDocument, KeyID: accessKey.ID(),
	}] = accessKey.PublicJWK()
	server := protocol.server(t)

	metadataResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(metadataResponse, httptest.NewRequest(http.MethodGet, resourceIssuer+"/.well-known/aauth-resource.json", nil))
	var metadata struct {
		UsageEndpoint string `json:"usage_endpoint"`
	}
	if err := json.Unmarshal(metadataResponse.Body.Bytes(), &metadata); err != nil {
		t.Fatal(err)
	}
	if metadata.UsageEndpoint != resourceIssuer+"/usage" {
		t.Fatalf("usage_endpoint = %q", metadata.UsageEndpoint)
	}

	usageRequest := signedUsageRequest(t, protocol, protocol.personKey, personIssuer, aauth.PersonDiscoveryDocument, `{"sub":"person-1"}`)
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, usageRequest)
	if response.Code != http.StatusOK {
		t.Fatalf("usage status = %d, body = %s", response.Code, response.Body.String())
	}
	if _, err := budgets.VerifyUsageResponse(
		context.Background(), usageRequest, response.Code, response.Header(), response.Body.Bytes(),
		resourceIssuer, protocol.resolver, protocol.clock,
	); err != nil {
		t.Fatalf("usage response signature = %v", err)
	}
	var body struct {
		AsOf     int64  `json:"as_of"`
		Audience string `json:"aud"`
		Unit     string `json:"unit"`
		Decimals int64  `json:"decimals"`
		Subject  string `json:"sub"`
		Usage    struct {
			AllTime int64 `json:"all_time"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Audience != personIssuer || body.Subject != "person-1" || body.Unit != "USD" || body.Decimals != 6 || body.Usage.AllTime != 5 || body.AsOf != protocol.now.Unix() {
		t.Fatalf("usage body = %+v", body)
	}
	if scripted.seen.Caller.Document != aauth.PersonDiscoveryDocument || scripted.seen.Subject != "person-1" {
		t.Fatalf("usage query = %+v", scripted.seen)
	}

	thumbprint := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	scripted.result = BudgetUsageResult{}
	emptyKeys := postUsage(t, server, protocol, protocol.personKey, personIssuer, aauth.PersonDiscoveryDocument, `{"sub":"missing","jkts":["`+thumbprint+`"]}`)
	if emptyKeys.Code != http.StatusOK || !strings.Contains(emptyKeys.Body.String(), `"jkts":{}`) || strings.Contains(emptyKeys.Body.String(), `"usage"`) {
		t.Fatalf("unrecognized usage = %d %s", emptyKeys.Code, emptyKeys.Body.String())
	}
	var omitted struct {
		Unit     string `json:"unit"`
		Decimals int64  `json:"decimals"`
		Subject  string `json:"sub"`
	}
	if err := json.Unmarshal(emptyKeys.Body.Bytes(), &omitted); err != nil {
		t.Fatal(err)
	}
	if omitted.Subject != "missing" || omitted.Unit != "USD" || omitted.Decimals != 6 {
		t.Fatalf("omitted usage denomination = %+v", omitted)
	}

	scripted.err = ErrUsageMixedUnit
	mixed := postUsage(t, server, protocol, protocol.personKey, personIssuer, aauth.PersonDiscoveryDocument, `{"sub":"person-1"}`)
	if mixed.Code != http.StatusInternalServerError || !strings.Contains(mixed.Body.String(), `"server_error"`) {
		t.Fatalf("mixed unit = %d %s", mixed.Code, mixed.Body.String())
	}
	scripted.err = nil

	for _, test := range []struct {
		name     string
		issuer   string
		document string
		payload  string
		status   int
	}{
		{name: "two scope keys", issuer: personIssuer, document: aauth.PersonDiscoveryDocument, payload: `{"sub":"person-1","tenant":"corp"}`, status: http.StatusBadRequest},
		{name: "person server sends ps", issuer: personIssuer, document: aauth.PersonDiscoveryDocument, payload: `{"sub":"person-1","ps":"https://person.example"}`, status: http.StatusBadRequest},
		{name: "access server omits ps", issuer: accessIssuer, document: aauth.AccessDiscoveryDocument, payload: `{"sub":"person-1"}`, status: http.StatusBadRequest},
	} {
		signer := protocol.personKey
		if test.issuer == accessIssuer {
			signer = accessKey
		}
		got := postUsage(t, server, protocol, signer, test.issuer, test.document, test.payload)
		if got.Code != test.status || !strings.Contains(got.Body.String(), `"invalid_request"`) {
			t.Fatalf("%s = %d %s", test.name, got.Code, got.Body.String())
		}
	}

	lag := protocol.now.Add(-2 * time.Hour)
	scripted.result = BudgetUsageResult{
		Unit: protocol.unit, HasUnit: true, ScopeRecognized: true, AsOf: lag,
		AllTime: 5, AllTimeOK: true, Day: 5, DayOK: true, Week: 5, WeekOK: true,
		Month: 5, MonthOK: true, Year: 5, YearOK: true,
	}
	lagging := postUsage(t, server, protocol, protocol.personKey, personIssuer, aauth.PersonDiscoveryDocument, `{"sub":"person-1"}`)
	if lagging.Code != http.StatusOK || !strings.Contains(lagging.Body.String(), fmt.Sprintf(`"as_of":%d`, lag.Unix())) {
		t.Fatalf("lagging usage = %d %s", lagging.Code, lagging.Body.String())
	}

	unsigned := httptest.NewRequest(http.MethodPost, resourceIssuer+"/usage", strings.NewReader(`{"sub":"person-1"}`))
	unsigned.Header.Set("Content-Type", "application/json")
	unsignedResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(unsignedResponse, unsigned)
	if unsignedResponse.Code != http.StatusUnauthorized {
		t.Fatalf("unsigned usage = %d %s", unsignedResponse.Code, unsignedResponse.Body.String())
	}
}

type scriptedUsageStore struct {
	*budgetMemoryStore
	result BudgetUsageResult
	err    error
	seen   BudgetUsageQuery
}

func (store *scriptedUsageStore) QueryUsage(_ context.Context, query BudgetUsageQuery) (BudgetUsageResult, error) {
	store.seen = query
	return store.result, store.err
}

func TestUsageEndpointRejectsASignatureThatOmitsContentTypeOrContentDigest(t *testing.T) {
	t.Parallel()

	protocol := newBudgetResourceProtocol(t, 1, http.NotFoundHandler())
	protocol.config.Budget.Store = &scriptedUsageStore{budgetMemoryStore: protocol.store}
	server := protocol.server(t)
	const payload = `{"sub":"person-1"}`
	sign := func(components []string) *http.Request {
		t.Helper()
		request := httptest.NewRequest(http.MethodPost, resourceIssuer+"/usage", strings.NewReader(payload))
		request.Header.Set("Content-Type", "application/json")
		if err := signaturekey.SignJWKSURIRequestWithOptions(
			request, protocol.personKey, personIssuer, aauth.PersonDiscoveryDocument, protocol.clock,
			signaturekey.SignOptions{AdditionalComponents: components, MaxBodyBytes: 1 << 20},
		); err != nil {
			t.Fatal(err)
		}
		return request
	}
	serve := func(request *http.Request) *httptest.ResponseRecorder {
		t.Helper()
		response := httptest.NewRecorder()
		server.Handler().ServeHTTP(response, request)
		return response
	}

	bare := httptest.NewRequest(http.MethodPost, resourceIssuer+"/usage", nil)
	if err := signaturekey.SignJWKSURIRequestWithOptions(
		bare, protocol.personKey, personIssuer, aauth.PersonDiscoveryDocument, protocol.clock,
		signaturekey.SignOptions{MaxBodyBytes: 1 << 20},
	); err != nil {
		t.Fatal(err)
	}
	bare.Body = io.NopCloser(strings.NewReader(payload))
	bare.ContentLength = int64(len(payload))
	bare.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(strings.NewReader(payload)), nil
	}
	bare.Header.Set("Content-Type", "application/json")
	omitted := serve(bare)
	if omitted.Code != http.StatusUnauthorized {
		t.Fatalf("signature without content-type and content-digest = %d %s", omitted.Code, omitted.Body.String())
	}
	wrongType := sign([]string{"content-type", "content-digest"})
	wrongType.Header.Set("Content-Type", "text/plain")
	changedType := serve(wrongType)
	if changedType.Code != http.StatusUnauthorized {
		t.Fatalf("replaced content-type = %d %s", changedType.Code, changedType.Body.String())
	}
	wrongDigest := sign([]string{"content-type", "content-digest"})
	replacement := `{"sub":"other"}`
	wrongDigest.Body = io.NopCloser(strings.NewReader(replacement))
	wrongDigest.ContentLength = int64(len(replacement))
	wrongDigest.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(strings.NewReader(replacement)), nil
	}
	changedBody := serve(wrongDigest)
	if changedBody.Code != http.StatusUnauthorized {
		t.Fatalf("replaced body = %d %s", changedBody.Code, changedBody.Body.String())
	}
}

func postUsage(
	t *testing.T,
	server *Server,
	protocol *budgetResourceProtocol,
	key jose.SigningKey,
	issuer, document, payload string,
) *httptest.ResponseRecorder {
	t.Helper()
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, signedUsageRequest(t, protocol, key, issuer, document, payload))
	return response
}

func signedUsageRequest(
	t *testing.T,
	protocol *budgetResourceProtocol,
	key jose.SigningKey,
	issuer, document, payload string,
) *http.Request {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, resourceIssuer+"/usage", strings.NewReader(payload))
	request.Header.Set("Content-Type", "application/json")
	if err := signaturekey.SignJWKSURIRequestWithOptions(
		request, key, issuer, document, protocol.clock,
		signaturekey.SignOptions{
			AdditionalComponents: []string{"content-type", "content-digest"},
			MaxBodyBytes:         1 << 20,
		},
	); err != nil {
		t.Fatal(err)
	}
	return request
}
