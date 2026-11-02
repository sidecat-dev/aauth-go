package agent_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/agent"
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

func TestTwoKeyBootstrapClientEnrollsAndRefreshesOnce(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	now := time.Date(2026, 8, 31, 5, 10, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	providerKey := testSigningKey(t, "bootstrap-ap-key", 0xc1)
	durable := testSigningKey(t, "bootstrap-durable-key", 0xc2)
	ephemeral := testSigningKey(t, "bootstrap-ephemeral-key", 0xc3)
	resolver := signaturekey.StaticKeyResolver{
		{Issuer: "https://ap.example", DiscoveryDocument: aauth.AgentDiscoveryDocument, KeyID: providerKey.ID()}: providerKey.PublicJWK(),
	}
	var calls []string
	httpClient := &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
		calls = append(calls, request.URL.Path)
		switch request.URL.Path {
		case "/custom/enrollment":
			verifyBootstrapEnrollmentRequest(t, request, durable, clock)
			return bootstrapJSONResponse(http.StatusCreated, `{"agent":"aauth:reference@ap.example"}`), nil
		case "/custom/refresh":
			verifyBootstrapRefreshRequest(t, request, durable, ephemeral, clock)
			compact, err := aauth.MintAgentToken("https://ap.example", providerKey, aauth.AgentTokenRequest{
				Agent: "aauth:reference@ap.example", PersonServer: "https://ps.example",
				PublicKey: ephemeral.PublicJWK(), Lifetime: 30 * time.Minute,
			}, now, "agent-token-bootstrap")
			if err != nil {
				return nil, err
			}
			return bootstrapJSONResponse(http.StatusOK, fmt.Sprintf(`{"agent_token":%q}`, compact)), nil
		default:
			return nil, fmt.Errorf("unexpected bootstrap request %s", request.URL)
		}
	})}

	bootstrap, err := agent.NewBootstrapClient(agent.BootstrapConfig{
		AgentProvider:      "https://ap.example",
		EnrollmentEndpoint: "https://ap.example/custom/enrollment",
		RefreshEndpoint:    "https://ap.example/custom/refresh",
		DurableKey:         durable, KeyResolver: resolver, HTTPClient: httpClient, Clock: clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	enrollment, err := bootstrap.Enroll(ctx, json.RawMessage(`{"account":"person-1"}`))
	if err != nil {
		t.Fatal(err)
	}
	refreshed, err := bootstrap.Refresh(ctx, agent.RefreshAgentTokenInput{
		Agent: enrollment.Agent, PersonServer: "https://ps.example",
		Evidence:   json.RawMessage(`{"posture":"current"}`),
		SigningKey: ephemeral, DelegationJTI: "refresh-1",
		DelegationIssuedAt: now, DelegationExpiresAt: now.Add(10 * time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	if refreshed.Claims.Subject != enrollment.Agent || !refreshed.Claims.Confirmation.JWK.Equal(ephemeral.PublicJWK()) {
		t.Fatalf("refreshed claims = %#v", refreshed.Claims)
	}
	if _, err := agent.New(ctx, agent.Config{
		Identifier: enrollment.Agent, SigningKey: ephemeral, AgentToken: refreshed.AgentToken,
		KeyResolver: resolver, HTTPClient: httpClient, Clock: clock,
	}); err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprint(calls); got != "[/custom/enrollment /custom/refresh]" {
		t.Fatalf("bootstrap calls = %s", got)
	}
}

func TestSingleKeyBootstrapClientRefreshesWithDurableHWK(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	now := time.Date(2026, 8, 31, 7, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	providerKey := testSigningKey(t, "single-key-bootstrap-ap", 0xa1)
	durable := testSigningKey(t, "single-key-bootstrap-durable", 0xa2)
	resolver := signaturekey.StaticKeyResolver{
		{Issuer: "https://ap.example", DiscoveryDocument: aauth.AgentDiscoveryDocument, KeyID: providerKey.ID()}: providerKey.PublicJWK(),
	}
	calls := 0
	httpClient := &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
		calls++
		prepared, err := signaturekey.PrepareRequest(request, clock, signaturekey.VerifyOptions{
			AcceptedSchemes:        []signaturekey.Scheme{signaturekey.SchemeHWK},
			RequiredComponents:     []string{"content-type", "content-digest"},
			RequireExactComponents: true,
		})
		if err != nil {
			return nil, err
		}
		key, ok := prepared.Credential().InlineJWK()
		if !ok || !key.Equal(durable.PublicJWK()) {
			return nil, errors.New("single-key refresh did not use the durable hwk")
		}
		proof, err := prepared.Verify(key)
		if err != nil {
			return nil, err
		}
		var input struct {
			PersonServer  string          `json:"ps"`
			Evidence      json.RawMessage `json:"evidence"`
			RefreshJTI    string          `json:"refresh_jti"`
			RefreshExpiry int64           `json:"refresh_expires_at"`
		}
		if err := json.Unmarshal(proof.ExactBody(), &input); err != nil ||
			input.PersonServer != "https://ps.example" || input.RefreshJTI != "single-refresh-1" ||
			input.RefreshExpiry != now.Add(10*time.Minute).Unix() || string(input.Evidence) != `{"posture":"current"}` {
			return nil, fmt.Errorf("single-key refresh body = %s, error = %v", proof.ExactBody(), err)
		}
		compact, err := aauth.MintAgentToken("https://ap.example", providerKey, aauth.AgentTokenRequest{
			Agent: "aauth:reference@ap.example", PersonServer: input.PersonServer,
			PublicKey: durable.PublicJWK(), Lifetime: 30 * time.Minute,
		}, now, "single-key-agent-token")
		if err != nil {
			return nil, err
		}
		return bootstrapJSONResponse(http.StatusOK, fmt.Sprintf(`{"agent_token":%q}`, compact)), nil
	})}
	bootstrap, err := agent.NewBootstrapClient(agent.BootstrapConfig{
		AgentProvider:      "https://ap.example",
		EnrollmentEndpoint: "https://ap.example/custom/enrollment",
		RefreshEndpoint:    "https://ap.example/custom/refresh",
		DurableKey:         durable, KeyResolver: resolver, HTTPClient: httpClient, Clock: clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := bootstrap.RefreshSingleKey(ctx, agent.SingleKeyRefreshAgentTokenInput{
		Agent: "aauth:reference@ap.example", PersonServer: "https://ps.example",
		Evidence:   json.RawMessage(`{"posture":"current"}`),
		RefreshJTI: "single-refresh-1", RefreshExpiresAt: now.Add(10 * time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Claims.Subject != "aauth:reference@ap.example" ||
		!result.Claims.Confirmation.JWK.Equal(durable.PublicJWK()) || calls != 1 {
		t.Fatalf("single-key refresh = %#v, calls=%d", result.Claims, calls)
	}
	if _, err := agent.New(ctx, agent.Config{
		Identifier: result.Claims.Subject, SigningKey: durable, AgentToken: result.AgentToken,
		KeyResolver: resolver, HTTPClient: httpClient, Clock: clock,
	}); err != nil {
		t.Fatal(err)
	}
}

func TestSingleKeyBootstrapClientRejectsInvalidInputBeforeNetwork(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 31, 7, 10, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	durable := testSigningKey(t, "single-key-negative-durable", 0xa3)
	calls := 0
	bootstrap, err := agent.NewBootstrapClient(agent.BootstrapConfig{
		AgentProvider:      "https://ap.example",
		EnrollmentEndpoint: "https://ap.example/enroll",
		RefreshEndpoint:    "https://ap.example/refresh",
		DurableKey:         durable,
		KeyResolver:        signaturekey.StaticKeyResolver{},
		HTTPClient: &http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
			calls++
			return nil, errors.New("unexpected request")
		})},
		Clock: clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	valid := agent.SingleKeyRefreshAgentTokenInput{
		Agent: "aauth:reference@ap.example", PersonServer: "https://ps.example",
		Evidence: json.RawMessage(`{}`), RefreshJTI: "refresh-1",
		RefreshExpiresAt: now.Add(time.Minute),
	}
	tests := []agent.SingleKeyRefreshAgentTokenInput{
		{},
		func() agent.SingleKeyRefreshAgentTokenInput { value := valid; value.RefreshJTI = ""; return value }(),
		func() agent.SingleKeyRefreshAgentTokenInput {
			value := valid
			value.RefreshExpiresAt = time.Time{}
			return value
		}(),
		func() agent.SingleKeyRefreshAgentTokenInput { value := valid; value.Evidence = nil; return value }(),
		func() agent.SingleKeyRefreshAgentTokenInput {
			value := valid
			value.RefreshExpiresAt = now
			return value
		}(),
		func() agent.SingleKeyRefreshAgentTokenInput {
			value := valid
			value.RefreshExpiresAt = now.Add(25 * time.Hour)
			return value
		}(),
	}
	for _, input := range tests {
		if _, err := bootstrap.RefreshSingleKey(context.Background(), input); err == nil {
			t.Fatalf("invalid input accepted: %#v", input)
		}
	}
	if calls != 0 {
		t.Fatalf("network calls = %d", calls)
	}
}

func TestTwoKeyBootstrapClientRejectsMismatchedReturnedAgentToken(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 31, 5, 15, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	providerKey := testSigningKey(t, "bootstrap-negative-ap-key", 0xd1)
	durable := testSigningKey(t, "bootstrap-negative-durable-key", 0xd2)
	ephemeral := testSigningKey(t, "bootstrap-negative-ephemeral-key", 0xd3)
	otherKey := testSigningKey(t, "bootstrap-negative-other-key", 0xd4)
	tests := []struct {
		name     string
		issuer   string
		issuedAt time.Time
		request  aauth.AgentTokenRequest
	}{
		{name: "issuer", issuer: "https://other-ap.example", issuedAt: now, request: aauth.AgentTokenRequest{
			Agent: "aauth:reference@other-ap.example", PersonServer: "https://ps.example",
			PublicKey: ephemeral.PublicJWK(), Lifetime: 30 * time.Minute,
		}},
		{name: "subject", issuedAt: now, request: aauth.AgentTokenRequest{
			Agent: "aauth:other@ap.example", PersonServer: "https://ps.example",
			PublicKey: ephemeral.PublicJWK(), Lifetime: 30 * time.Minute,
		}},
		{name: "confirmation key", issuedAt: now, request: aauth.AgentTokenRequest{
			Agent: "aauth:reference@ap.example", PersonServer: "https://ps.example",
			PublicKey: otherKey.PublicJWK(), Lifetime: 30 * time.Minute,
		}},
		{name: "person server", issuedAt: now, request: aauth.AgentTokenRequest{
			Agent: "aauth:reference@ap.example", PersonServer: "https://other-ps.example",
			PublicKey: ephemeral.PublicJWK(), Lifetime: 30 * time.Minute,
		}},
		{name: "expired", issuedAt: now.Add(-2 * time.Hour), request: aauth.AgentTokenRequest{
			Agent: "aauth:reference@ap.example", PersonServer: "https://ps.example",
			PublicKey: ephemeral.PublicJWK(), Lifetime: time.Hour,
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			issuer := test.issuer
			if issuer == "" {
				issuer = "https://ap.example"
			}
			compact, err := aauth.MintAgentToken(
				issuer, providerKey, test.request, test.issuedAt, "agent-token-negative",
			)
			if err != nil {
				t.Fatal(err)
			}
			calls := 0
			httpClient := &http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
				calls++
				return bootstrapJSONResponse(http.StatusOK, fmt.Sprintf(`{"agent_token":%q}`, compact)), nil
			})}
			bootstrap, err := agent.NewBootstrapClient(agent.BootstrapConfig{
				AgentProvider:      "https://ap.example",
				EnrollmentEndpoint: "https://ap.example/custom/enrollment",
				RefreshEndpoint:    "https://ap.example/custom/refresh",
				DurableKey:         durable,
				KeyResolver: signaturekey.StaticKeyResolver{
					{Issuer: "https://ap.example", DiscoveryDocument: aauth.AgentDiscoveryDocument, KeyID: providerKey.ID()}:       providerKey.PublicJWK(),
					{Issuer: "https://other-ap.example", DiscoveryDocument: aauth.AgentDiscoveryDocument, KeyID: providerKey.ID()}: providerKey.PublicJWK(),
				},
				HTTPClient: httpClient, Clock: clock,
			})
			if err != nil {
				t.Fatal(err)
			}
			_, err = bootstrap.Refresh(context.Background(), agent.RefreshAgentTokenInput{
				Agent: "aauth:reference@ap.example", PersonServer: "https://ps.example",
				Evidence: json.RawMessage(`{}`), SigningKey: ephemeral,
				DelegationJTI: "refresh-negative", DelegationIssuedAt: now,
				DelegationExpiresAt: now.Add(10 * time.Minute),
			})
			if err == nil || calls != 1 {
				t.Fatalf("Refresh error = %v, calls = %d", err, calls)
			}
		})
	}
}

func TestBootstrapClientRejectsCredentialResponseWithoutNoStore(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 31, 5, 25, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	durable := testSigningKey(t, "bootstrap-cache-durable-key", 0xe1)
	httpClient := &http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
		return bootstrapJSONResponseWithoutNoStore(http.StatusCreated, `{"agent":"aauth:reference@ap.example"}`), nil
	})}
	bootstrap, err := agent.NewBootstrapClient(agent.BootstrapConfig{
		AgentProvider:      "https://ap.example",
		EnrollmentEndpoint: "https://ap.example/custom/enrollment",
		RefreshEndpoint:    "https://ap.example/custom/refresh",
		DurableKey:         durable, KeyResolver: signaturekey.StaticKeyResolver{},
		HTTPClient: httpClient, Clock: clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bootstrap.Enroll(context.Background(), json.RawMessage(`{}`)); err == nil {
		t.Fatal("Enroll accepted a cacheable credential response")
	}
}

func TestBootstrapClientRejectsUnexpectedTokenIssuerBeforeKeyResolution(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 31, 5, 30, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	durable := testSigningKey(t, "bootstrap-egress-durable-key", 0xe2)
	ephemeral := testSigningKey(t, "bootstrap-egress-ephemeral-key", 0xe3)
	otherProvider := testSigningKey(t, "bootstrap-egress-other-ap-key", 0xe4)
	compact, err := aauth.MintAgentToken("https://other-ap.example", otherProvider, aauth.AgentTokenRequest{
		Agent: "aauth:reference@other-ap.example", PersonServer: "https://ps.example",
		PublicKey: ephemeral.PublicJWK(), Lifetime: 30 * time.Minute,
	}, now, "unexpected-issuer-token")
	if err != nil {
		t.Fatal(err)
	}
	resolver := &countingKeyResolver{key: otherProvider.PublicJWK()}
	httpClient := &http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
		return bootstrapJSONResponse(http.StatusOK, fmt.Sprintf(`{"agent_token":%q}`, compact)), nil
	})}
	bootstrap, err := agent.NewBootstrapClient(agent.BootstrapConfig{
		AgentProvider:      "https://ap.example",
		EnrollmentEndpoint: "https://ap.example/custom/enrollment",
		RefreshEndpoint:    "https://ap.example/custom/refresh",
		DurableKey:         durable, KeyResolver: resolver, HTTPClient: httpClient, Clock: clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = bootstrap.Refresh(context.Background(), agent.RefreshAgentTokenInput{
		Agent: "aauth:reference@ap.example", PersonServer: "https://ps.example",
		Evidence: json.RawMessage(`{}`), SigningKey: ephemeral,
		DelegationJTI: "refresh-unexpected-issuer", DelegationIssuedAt: now,
		DelegationExpiresAt: now.Add(10 * time.Minute),
	})
	if err == nil {
		t.Fatal("Refresh accepted an Agent token from another issuer")
	}
	if resolver.calls != 0 {
		t.Fatalf("key-resolution calls = %d", resolver.calls)
	}
}

func TestBootstrapClientUsesJKTJWTNumericDatePrecision(t *testing.T) {
	t.Parallel()
	base := time.Date(2026, 8, 31, 5, 35, 0, 0, time.UTC)
	providerKey := testSigningKey(t, "bootstrap-numeric-date-ap-key", 0xe5)
	durable := testSigningKey(t, "bootstrap-numeric-date-durable-key", 0xe6)
	ephemeral := testSigningKey(t, "bootstrap-numeric-date-ephemeral-key", 0xe7)
	compact, err := aauth.MintAgentToken("https://ap.example", providerKey, aauth.AgentTokenRequest{
		Agent: "aauth:reference@ap.example", PersonServer: "https://ps.example",
		PublicKey: ephemeral.PublicJWK(), Lifetime: 30 * time.Minute,
	}, base, "numeric-date-agent-token")
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name      string
		now       time.Time
		issuedAt  time.Time
		expiresAt time.Time
		wantCall  bool
	}{
		{
			name: "issued time later within the current NumericDate second",
			now:  base.Add(100 * time.Millisecond), issuedAt: base.Add(900 * time.Millisecond),
			expiresAt: base.Add(time.Minute), wantCall: true,
		},
		{
			name: "expiry later as a Time but expired at NumericDate precision",
			now:  base.Add(900 * time.Millisecond), issuedAt: base.Add(-900 * time.Millisecond),
			expiresAt: base.Add(950 * time.Millisecond), wantCall: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			clock := aauth.ClockFunc(func() time.Time { return test.now })
			calls := 0
			httpClient := &http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
				calls++
				return bootstrapJSONResponse(http.StatusOK, fmt.Sprintf(`{"agent_token":%q}`, compact)), nil
			})}
			bootstrap, err := agent.NewBootstrapClient(agent.BootstrapConfig{
				AgentProvider:      "https://ap.example",
				EnrollmentEndpoint: "https://ap.example/custom/enrollment",
				RefreshEndpoint:    "https://ap.example/custom/refresh",
				DurableKey:         durable,
				KeyResolver: signaturekey.StaticKeyResolver{
					{Issuer: "https://ap.example", DiscoveryDocument: aauth.AgentDiscoveryDocument, KeyID: providerKey.ID()}: providerKey.PublicJWK(),
				},
				HTTPClient: httpClient, Clock: clock,
			})
			if err != nil {
				t.Fatal(err)
			}
			_, err = bootstrap.Refresh(context.Background(), agent.RefreshAgentTokenInput{
				Agent: "aauth:reference@ap.example", PersonServer: "https://ps.example",
				Evidence: json.RawMessage(`{}`), SigningKey: ephemeral,
				DelegationJTI: "refresh-numeric-date", DelegationIssuedAt: test.issuedAt,
				DelegationExpiresAt: test.expiresAt,
			})
			if test.wantCall && err != nil {
				t.Fatalf("Refresh error = %v", err)
			}
			if !test.wantCall && err == nil {
				t.Fatal("Refresh accepted an expired NumericDate")
			}
			wantCalls := 0
			if test.wantCall {
				wantCalls = 1
			}
			if calls != wantCalls {
				t.Fatalf("HTTP calls = %d, want %d", calls, wantCalls)
			}
		})
	}
}

type countingKeyResolver struct {
	calls int
	key   jose.JWK
}

func (resolver *countingKeyResolver) ResolveKey(
	context.Context,
	string,
	string,
	string,
) (jose.JWK, error) {
	resolver.calls++
	return resolver.key, nil
}

func bootstrapJSONResponse(status int, body string) *http.Response {
	response := bootstrapJSONResponseWithoutNoStore(status, body)
	response.Header.Set("Cache-Control", "no-store")
	return response
}

func bootstrapJSONResponseWithoutNoStore(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}

func verifyBootstrapEnrollmentRequest(
	t *testing.T,
	request *http.Request,
	durable jose.SigningKey,
	clock aauth.Clock,
) {
	t.Helper()
	prepared, err := signaturekey.PrepareRequest(request, clock, signaturekey.VerifyOptions{
		AcceptedSchemes:    []signaturekey.Scheme{signaturekey.SchemeHWK},
		RequiredComponents: []string{"content-type", "content-digest"}, RequireExactComponents: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	key, ok := prepared.Credential().InlineJWK()
	if !ok || !key.Equal(durable.PublicJWK()) {
		t.Fatalf("enrollment key = %#v", key)
	}
	if _, err := prepared.Verify(key); err != nil {
		t.Fatal(err)
	}
	var body struct {
		Evidence json.RawMessage `json:"evidence"`
	}
	if err := json.NewDecoder(request.Body).Decode(&body); err != nil || string(body.Evidence) != `{"account":"person-1"}` {
		t.Fatalf("enrollment body = %s, error = %v", body.Evidence, err)
	}
}

func verifyBootstrapRefreshRequest(
	t *testing.T,
	request *http.Request,
	durable, ephemeral jose.SigningKey,
	clock aauth.Clock,
) {
	t.Helper()
	prepared, err := signaturekey.PrepareRequest(request, clock, signaturekey.VerifyOptions{
		AcceptedSchemes:    []signaturekey.Scheme{signaturekey.SchemeJKTJWT},
		RequiredComponents: []string{"content-type", "content-digest"}, RequireExactComponents: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, delegation, err := prepared.VerifyJKTJWT()
	if err != nil {
		t.Fatal(err)
	}
	if !delegation.IdentityKey().Equal(durable.PublicJWK()) ||
		!delegation.ConfirmationKey().Equal(ephemeral.PublicJWK()) || delegation.JTI() != "refresh-1" {
		t.Fatalf("refresh delegation = %#v", delegation)
	}
	var body struct {
		PersonServer string          `json:"ps"`
		Evidence     json.RawMessage `json:"evidence"`
	}
	if err := json.NewDecoder(request.Body).Decode(&body); err != nil ||
		body.PersonServer != "https://ps.example" || string(body.Evidence) != `{"posture":"current"}` {
		t.Fatalf("refresh body = %#v, error = %v", body, err)
	}
}
