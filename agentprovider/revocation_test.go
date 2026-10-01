package agentprovider_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/agentprovider"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

func TestRevocationClientRejectsForeignReferenceBeforeNetwork(t *testing.T) {
	t.Parallel()
	provider := newRevocationTestProvider(t)
	networkCalls := 0
	client, err := agentprovider.NewRevocationClient(agentprovider.RevocationClientConfig{
		Provider: provider,
		HTTPClient: &http.Client{Transport: revocationRoundTripFunc(func(*http.Request) (*http.Response, error) {
			networkCalls++
			return nil, errors.New("unexpected network call")
		})},
		Admit: func(context.Context, string) error {
			networkCalls++
			return errors.New("unexpected egress admission")
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	err = client.RevokeAgentToken(context.Background(), "https://ps.example", aauth.RevocationRequest{
		Reference: aauth.TokenReference{Issuer: "https://other.example", JTI: "token-1"},
		ExpiresAt: time.Unix(2000000000, 0),
	})
	if err == nil || !strings.Contains(err.Error(), "not issued by this provider") || networkCalls != 0 {
		t.Fatalf("RevokeAgentToken() = %v; network_calls=%d", err, networkCalls)
	}
}

func TestRevocationClientRefusesPersonServerWithoutEndpoint(t *testing.T) {
	t.Parallel()
	provider := newRevocationTestProvider(t)
	client, err := agentprovider.NewRevocationClient(agentprovider.RevocationClientConfig{
		Provider: provider,
		HTTPClient: &http.Client{Transport: revocationRoundTripFunc(func(request *http.Request) (*http.Response, error) {
			if request.Method != http.MethodGet || request.URL.String() != "https://ps.example/.well-known/aauth-person.json" {
				t.Fatalf("request = %s %s", request.Method, request.URL)
			}
			return &http.Response{
				StatusCode: http.StatusOK, Status: "200 OK", Header: make(http.Header),
				Body: io.NopCloser(strings.NewReader(`{"issuer":"https://ps.example"}`)), Request: request,
			}, nil
		})},
		Admit: func(context.Context, string) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	err = client.RevokeAgentToken(context.Background(), "https://ps.example", aauth.RevocationRequest{
		Reference: aauth.TokenReference{Issuer: "https://ap.example", JTI: "token-1"},
		ExpiresAt: time.Unix(2000000000, 0),
	})
	if err == nil || !strings.Contains(err.Error(), "revocation_endpoint") {
		t.Fatalf("RevokeAgentToken() = %v", err)
	}
}

func TestRevocationClientCoversResourceAdvertisedHeaders(t *testing.T) {
	t.Parallel()
	provider := newRevocationTestProvider(t)
	postCalls := 0
	client, err := agentprovider.NewRevocationClient(agentprovider.RevocationClientConfig{
		Provider: provider,
		HTTPClient: &http.Client{Transport: revocationRoundTripFunc(func(request *http.Request) (*http.Response, error) {
			switch request.URL.String() {
			case "https://resource.example/.well-known/aauth-resource.json":
				return revocationJSONResponse(request, `{"issuer":"https://resource.example","revocation_endpoint":"https://resource.example/revoke","additional_signature_components":["x-tenant"]}`), nil
			case "https://resource.example/revoke":
				postCalls++
				if body, _ := io.ReadAll(request.Body); string(body) != `{"jti":"token-1","exp":2000000000}` {
					t.Fatalf("revocation body = %s", body)
				}
				if request.Header.Get("X-Tenant") != "tenant-1" || !strings.Contains(request.Header.Get("Signature-Input"), `"x-tenant"`) {
					t.Fatalf("revocation headers = %v", request.Header)
				}
				return &http.Response{
					StatusCode: http.StatusOK, Status: "200 OK", Header: make(http.Header),
					Body: io.NopCloser(strings.NewReader("")), Request: request,
				}, nil
			default:
				return nil, errors.New("unexpected request: " + request.URL.String())
			}
		})},
		Admit: func(context.Context, string) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	reference := aauth.RevocationRequest{
		Reference: aauth.TokenReference{Issuer: "https://ap.example", JTI: "token-1"},
		ExpiresAt: time.Unix(2000000000, 0),
	}
	err = client.RevokeAgentTokenAtResource(context.Background(), "https://resource.example", reference)
	var failure *signaturekey.Error
	if !errors.As(err, &failure) || failure.Code != signaturekey.ErrorInvalidInput ||
		!slices.Equal(failure.RequiredInput, []string{"x-tenant"}) || postCalls != 0 {
		t.Fatalf("missing advertised header = %v; posts=%d", err, postCalls)
	}
	header := make(http.Header)
	header.Set("X-Tenant", "tenant-1")
	if err := client.RevokeAgentTokenAtResourceWithHeaders(context.Background(), "https://resource.example", reference, header); err != nil {
		t.Fatal(err)
	}
	if postCalls != 1 {
		t.Fatalf("revocation posts = %d", postCalls)
	}
}

func TestRevocationClientDoesNotFollowResourceRedirect(t *testing.T) {
	t.Parallel()
	provider := newRevocationTestProvider(t)
	requests := 0
	client, err := agentprovider.NewRevocationClient(agentprovider.RevocationClientConfig{
		Provider: provider,
		HTTPClient: &http.Client{Transport: revocationRoundTripFunc(func(request *http.Request) (*http.Response, error) {
			requests++
			switch request.URL.String() {
			case "https://resource.example/.well-known/aauth-resource.json":
				return revocationJSONResponse(request, `{"issuer":"https://resource.example","revocation_endpoint":"https://resource.example/revoke"}`), nil
			case "https://resource.example/revoke":
				return &http.Response{
					StatusCode: http.StatusFound, Status: "302 Found",
					Header: http.Header{"Location": []string{"https://attacker.example/revoke"}},
					Body:   io.NopCloser(strings.NewReader("")), Request: request,
				}, nil
			default:
				return nil, errors.New("redirect followed to " + request.URL.String())
			}
		})},
		Admit: func(context.Context, string) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	err = client.RevokeAgentTokenAtResource(context.Background(), "https://resource.example", aauth.RevocationRequest{
		Reference: aauth.TokenReference{Issuer: "https://ap.example", JTI: "token-1"},
		ExpiresAt: time.Unix(2000000000, 0),
	})
	if err == nil || !strings.Contains(err.Error(), "302 Found") || requests != 2 {
		t.Fatalf("redirect result = %v; requests=%d", err, requests)
	}
}

func newRevocationTestProvider(t *testing.T) *agentprovider.Server {
	t.Helper()
	provider, err := agentprovider.New(agentprovider.Config{
		Issuer: "https://ap.example", SigningKey: testSigningKey(t, "revocation-provider-key", 0x91),
		Clock: aauth.ClockFunc(func() time.Time { return time.Date(2026, 9, 1, 8, 0, 0, 0, time.UTC) }),
		NewID: func() string { return "unused" },
	})
	if err != nil {
		t.Fatal(err)
	}
	return provider
}

type revocationRoundTripFunc func(*http.Request) (*http.Response, error)

func (function revocationRoundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func revocationJSONResponse(request *http.Request, body string) *http.Response {
	return &http.Response{
		StatusCode: http.StatusOK, Status: "200 OK",
		Header: http.Header{"Content-Type": []string{"application/json"}},
		Body:   io.NopCloser(strings.NewReader(body)), Request: request,
	}
}

func TestRevocationClientReadsMalformed200AsUnavailable(t *testing.T) {
	t.Parallel()
	provider := newRevocationTestProvider(t)
	reference := aauth.RevocationRequest{
		Reference: aauth.TokenReference{Issuer: "https://ap.example", JTI: "token-1"},
		ExpiresAt: time.Unix(2000000000, 0),
	}
	for name, test := range map[string]struct {
		contentType string
		body        string
		wantErr     bool
	}{
		"no body":                {"", "", false},
		"empty object":           {"application/json", `{}`, false},
		"downstream report":      {"application/json; charset=utf-8", `{"downstream":[{"recipient":"https://r.example","error":"revocation_unavailable"}]}`, false},
		"not json":               {"application/json", `ok`, true},
		"array":                  {"application/json", `[]`, true},
		"wrong media type":       {"text/plain", `{}`, true},
		"missing media type":     {"", `{}`, true},
		"duplicate member":       {"application/json", `{"downstream":[],"downstream":[]}`, true},
		"trailing value":         {"application/json", `{} {}`, true},
		"downstream not array":   {"application/json", `{"downstream":"x"}`, true},
		"unknown downstream err": {"application/json", `{"downstream":[{"recipient":"https://r.example","error":"nope"}]}`, true},
	} {
		t.Run(name, func(t *testing.T) {
			client, err := agentprovider.NewRevocationClient(agentprovider.RevocationClientConfig{
				Provider: provider,
				HTTPClient: &http.Client{Transport: revocationRoundTripFunc(func(request *http.Request) (*http.Response, error) {
					if request.Method == http.MethodGet {
						return revocationJSONResponse(request, `{"issuer":"https://resource.example","revocation_endpoint":"https://resource.example/revoke"}`), nil
					}
					response := &http.Response{
						StatusCode: http.StatusOK, Status: "200 OK", Header: make(http.Header),
						Body: io.NopCloser(strings.NewReader(test.body)), Request: request,
					}
					if test.contentType != "" {
						response.Header.Set("Content-Type", test.contentType)
					}
					return response, nil
				})},
				Admit: func(context.Context, string) error { return nil },
			})
			if err != nil {
				t.Fatal(err)
			}
			err = client.RevokeAgentTokenAtResource(context.Background(), "https://resource.example", reference)
			if test.wantErr != errors.Is(err, aauth.ErrRevocationUnavailable) || (!test.wantErr && err != nil) {
				t.Fatalf("200 %q (%s) = %v; wantErr=%v", test.body, test.contentType, err, test.wantErr)
			}
		})
	}
}
