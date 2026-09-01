package agentprovider_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/agentprovider"
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
	err = client.RevokeAgentToken(context.Background(), "https://ps.example", aauth.TokenReference{
		Issuer: "https://other.example", JTI: "token-1",
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
	err = client.RevokeAgentToken(context.Background(), "https://ps.example", aauth.TokenReference{
		Issuer: "https://ap.example", JTI: "token-1",
	})
	if err == nil || !strings.Contains(err.Error(), "revocation_endpoint") {
		t.Fatalf("RevokeAgentToken() = %v", err)
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
