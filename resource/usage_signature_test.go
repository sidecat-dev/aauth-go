package resource

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/budgets"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

func TestUsageResponseIsSignedByTheResourceAndBoundToTheRequest(t *testing.T) {
	t.Parallel()

	protocol := newBudgetResourceProtocol(t, 1, http.NotFoundHandler())
	protocol.config.Budget.Store = &scriptedUsageStore{
		budgetMemoryStore: protocol.store,
		result: BudgetUsageResult{
			Unit: protocol.unit, HasUnit: true, ScopeRecognized: true, AllTime: 7, AllTimeOK: true,
		},
	}
	server := protocol.server(t)
	var tamper func(*http.Response)
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		recorder := httptest.NewRecorder()
		server.Handler().ServeHTTP(recorder, request)
		response := recorder.Result()
		if tamper != nil {
			tamper(response)
		}
		return response, nil
	})}
	query := budgets.UsageRequest{Subject: "person-1"}
	check := budgets.UsageSignatureCheck{
		Resource: resourceIssuer, KeyResolver: protocol.resolver, Client: client,
	}
	post := func() (budgets.UsageResult, error) {
		return budgets.PostUsageChecked(
			context.Background(), resourceIssuer+"/usage", protocol.personKey, personIssuer,
			aauth.PersonDiscoveryDocument, protocol.clock, query, check,
		)
	}

	result, err := post()
	if err != nil {
		t.Fatal(err)
	}
	if !result.Signed || result.Response.Usage == nil || result.Response.Usage.AllTime != 7 {
		t.Fatalf("usage result = %+v", result)
	}
	input := result.Header.Get("Signature-Input")
	if !strings.HasPrefix(input, `sig=("@status" "content-type" "content-digest" "@authority";req "@path";req);created=`) {
		t.Fatalf("Signature-Input = %q", input)
	}
	if key := result.Header.Get("Signature-Key"); key != `sig=jwks_uri;id="`+resourceIssuer+`";dwk="aauth-resource.json";kid="`+protocol.resourceKey.ID()+`"` {
		t.Fatalf("Signature-Key = %q", key)
	}

	replaceBody := func(body string) func(*http.Response) {
		return func(response *http.Response) {
			response.Body = io.NopCloser(strings.NewReader(body))
		}
	}
	for _, test := range []struct {
		name   string
		tamper func(*http.Response)
		check  func(*budgets.UsageSignatureCheck)
	}{
		{name: "changed figures", tamper: replaceBody(`{"as_of":1,"aud":"` + personIssuer + `","unit":"USD","decimals":6,"sub":"person-1","usage":{"all_time":1}}` + "\n")},
		{name: "status not covered", tamper: func(response *http.Response) {
			response.Header.Set("Signature-Input", strings.Replace(response.Header.Get("Signature-Input"), `"@status" `, "", 1))
		}},
		{name: "another signer", check: func(check *budgets.UsageSignatureCheck) {
			check.Resource = "https://other-resource.example"
		}},
		{name: "unsigned when a signature is required", tamper: func(response *http.Response) {
			for _, name := range []string{"Signature", "Signature-Input", "Signature-Key"} {
				response.Header.Del(name)
			}
		}, check: func(check *budgets.UsageSignatureCheck) { check.RequireSignature = true }},
	} {
		t.Run(test.name, func(t *testing.T) {
			tamper = test.tamper
			check = budgets.UsageSignatureCheck{Resource: resourceIssuer, KeyResolver: protocol.resolver, Client: client}
			if test.check != nil {
				test.check(&check)
			}
			defer func() { tamper = nil }()
			if _, err := post(); err == nil {
				t.Fatal("PostUsageChecked accepted the response")
			}
		})
	}

	// Unsigned and not required: read and reported as unsigned.
	tamper = func(response *http.Response) {
		for _, name := range []string{"Signature", "Signature-Input", "Signature-Key"} {
			response.Header.Del(name)
		}
	}
	check = budgets.UsageSignatureCheck{Resource: resourceIssuer, KeyResolver: protocol.resolver, Client: client}
	unsigned, err := post()
	tamper = nil
	if err != nil || unsigned.Signed {
		t.Fatalf("unsigned usage = %+v, %v", unsigned, err)
	}

	// The signature binds the request target: the same response presented
	// as the answer to a request for another path does not verify.
	request := signedUsageRequest(t, protocol, protocol.personKey, personIssuer, aauth.PersonDiscoveryDocument, `{"sub":"person-1"}`)
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	other := httptest.NewRequest(http.MethodPost, resourceIssuer+"/usage-v2", bytes.NewReader(nil))
	if _, err := budgets.VerifyUsageResponse(
		context.Background(), other, recorder.Code, recorder.Header(), recorder.Body.Bytes(),
		resourceIssuer, protocol.resolver, protocol.clock,
	); err == nil {
		t.Fatal("a usage response verified against another request path")
	}
	var failure *signaturekey.Error
	if _, err := budgets.VerifyUsageResponse(
		context.Background(), request, recorder.Code, recorder.Header(), append(recorder.Body.Bytes(), ' '),
		resourceIssuer, protocol.resolver, protocol.clock,
	); !errors.As(err, &failure) || failure.Code != signaturekey.ErrorInvalidSignature {
		t.Fatalf("altered body = %v, want invalid_signature", err)
	}
}
