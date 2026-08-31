package agentprovider_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"aauth-go"
	"aauth-go/agentprovider"
	"aauth-go/signaturekey"
)

func TestEnrollmentHTTPHandlersComposeAtCallerSelectedPaths(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 31, 4, 30, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	providerKey := testSigningKey(t, "ap-key-http", 0x51)
	durable := testSigningKey(t, "durable-key-http", 0x52)
	ephemeral := testSigningKey(t, "ephemeral-key-http", 0x53)
	provider, err := agentprovider.New(agentprovider.Config{
		Issuer: "https://ap.example", SigningKey: providerKey, Clock: clock,
		NewID: func() string { return "agent-token-http" },
	})
	if err != nil {
		t.Fatal(err)
	}
	identity, err := durable.PublicJWK().ThumbprintURI()
	if err != nil {
		t.Fatal(err)
	}
	service, err := newTestEnrollmentService(
		t, provider, newMemoryEnrollmentStore(), identity, "aauth:reference@ap.example",
	)
	if err != nil {
		t.Fatal(err)
	}
	enrollRequest := signedEnrollmentHTTPRequest(t, durable, clock)
	enrollResponse := httptest.NewRecorder()
	service.EnrollmentHandler().ServeHTTP(enrollResponse, enrollRequest)
	if enrollResponse.Code != http.StatusCreated {
		t.Fatalf("enrollment response = %d %s", enrollResponse.Code, enrollResponse.Body.String())
	}
	if enrollResponse.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("enrollment Cache-Control = %q", enrollResponse.Header().Get("Cache-Control"))
	}
	var enrolled struct {
		Agent string `json:"agent"`
	}
	if err := json.Unmarshal(enrollResponse.Body.Bytes(), &enrolled); err != nil || enrolled.Agent == "" {
		t.Fatalf("enrollment body = %s, error = %v", enrollResponse.Body.String(), err)
	}
	compact, err := signaturekey.MintJKTJWT(durable, ephemeral.PublicJWK(), now, now.Add(time.Hour), "refresh-1")
	if err != nil {
		t.Fatal(err)
	}
	refreshRequest := signedRefreshHTTPRequest(t, compact, ephemeral, clock)
	refreshResponse := httptest.NewRecorder()
	service.RefreshHandler().ServeHTTP(refreshResponse, refreshRequest)
	if refreshResponse.Code != http.StatusOK {
		t.Fatalf("refresh response = %d %s", refreshResponse.Code, refreshResponse.Body.String())
	}
	if refreshResponse.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("refresh Cache-Control = %q", refreshResponse.Header().Get("Cache-Control"))
	}
	var refreshed struct {
		AgentToken string `json:"agent_token"`
	}
	if err := json.Unmarshal(refreshResponse.Body.Bytes(), &refreshed); err != nil || refreshed.AgentToken == "" {
		t.Fatalf("refresh body = %s, error = %v", refreshResponse.Body.String(), err)
	}
	_, err = aauth.VerifyAgentToken(context.Background(), refreshed.AgentToken, signaturekey.StaticKeyResolver{
		{Issuer: "https://ap.example", DiscoveryDocument: aauth.AgentDiscoveryDocument, KeyID: providerKey.ID()}: providerKey.PublicJWK(),
	}, clock)
	if err != nil {
		t.Fatal(err)
	}
}

func TestEnrollmentHTTPHandlersRejectProofForDifferentProviderAuthority(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 31, 4, 32, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	provider, err := agentprovider.New(agentprovider.Config{
		Issuer:     "https://other-ap.example",
		SigningKey: testSigningKey(t, "other-ap-authority-key", 0x54), Clock: clock,
		NewID: func() string { return "agent-token-wrong-authority" },
	})
	if err != nil {
		t.Fatal(err)
	}
	durable := testSigningKey(t, "wrong-authority-durable-key", 0x55)
	ephemeral := testSigningKey(t, "wrong-authority-ephemeral-key", 0x56)
	policyCalls := 0
	service, err := agentprovider.NewEnrollmentService(agentprovider.EnrollmentServiceConfig{
		Provider: provider, Store: newMemoryEnrollmentStore(),
		Enroll: func(context.Context, agentprovider.EnrollmentRequest) (agentprovider.EnrollmentDecision, error) {
			policyCalls++
			return agentprovider.EnrollmentDecision{Agent: "aauth:reference@other-ap.example"}, nil
		},
		Refresh: func(context.Context, agentprovider.RefreshRequest) (agentprovider.RefreshDecision, error) {
			policyCalls++
			return agentprovider.RefreshDecision{PersonServer: "https://ps.example", Lifetime: 30 * time.Minute}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	enrollment := httptest.NewRecorder()
	service.EnrollmentHandler().ServeHTTP(enrollment, signedEnrollmentHTTPRequest(t, durable, clock))
	assertAuthorityMismatch(t, enrollment)

	compact, err := signaturekey.MintJKTJWT(
		durable, ephemeral.PublicJWK(), now, now.Add(time.Hour), "refresh-wrong-authority",
	)
	if err != nil {
		t.Fatal(err)
	}
	refresh := httptest.NewRecorder()
	service.RefreshHandler().ServeHTTP(refresh, signedRefreshHTTPRequest(t, compact, ephemeral, clock))
	assertAuthorityMismatch(t, refresh)

	if policyCalls != 0 {
		t.Fatalf("policy calls = %d", policyCalls)
	}
}

func assertAuthorityMismatch(t *testing.T, response *httptest.ResponseRecorder) {
	t.Helper()
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("response = %d %s", response.Code, response.Body.String())
	}
	failure, err := signaturekey.ParseError(response.Header().Get("Signature-Error"))
	if err != nil {
		t.Fatal(err)
	}
	if failure.Code != signaturekey.ErrorInvalidRequest {
		t.Fatalf("Signature-Error = %#v", failure)
	}
}

func TestEnrollmentHTTPHandlerRejectsAlteredSignedBody(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 31, 4, 35, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	provider, err := agentprovider.New(agentprovider.Config{
		Issuer: "https://ap.example", SigningKey: testSigningKey(t, "ap-key-tamper", 0x61), Clock: clock,
		NewID: func() string { return "unused" },
	})
	if err != nil {
		t.Fatal(err)
	}
	durable := testSigningKey(t, "durable-key-tamper", 0x62)
	identity, err := durable.PublicJWK().ThumbprintURI()
	if err != nil {
		t.Fatal(err)
	}
	service, err := newTestEnrollmentService(t, provider, newMemoryEnrollmentStore(), identity, "aauth:reference@ap.example")
	if err != nil {
		t.Fatal(err)
	}
	request := signedEnrollmentHTTPRequest(t, durable, clock)
	request.Body = io.NopCloser(strings.NewReader(`{"evidence":{"account":"another-person"}}`))
	request.ContentLength = -1
	response := httptest.NewRecorder()
	service.EnrollmentHandler().ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("response = %d %s", response.Code, response.Body.String())
	}
	failure, err := signaturekey.ParseError(response.Header().Get("Signature-Error"))
	if err != nil {
		t.Fatal(err)
	}
	if failure.Code != signaturekey.ErrorInvalidSignature {
		t.Fatalf("Signature-Error = %#v", failure)
	}
	var problem struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &problem); err != nil {
		t.Fatal(err)
	}
	if problem.Error != string(failure.Code) {
		t.Fatalf("problem error = %q, Signature-Error = %q", problem.Error, failure.Code)
	}
}

func TestEnrollmentHTTPHandlerSeparatesPolicyDenialFromOperationalFailure(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 31, 4, 40, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	provider, err := agentprovider.New(agentprovider.Config{
		Issuer: "https://ap.example", SigningKey: testSigningKey(t, "ap-key-refusal", 0x71), Clock: clock,
		NewID: func() string { return "unused" },
	})
	if err != nil {
		t.Fatal(err)
	}
	durable := testSigningKey(t, "durable-key-refusal", 0x72)

	newService := func(store agentprovider.EnrollmentStore, enroll func(context.Context, agentprovider.EnrollmentRequest) (agentprovider.EnrollmentDecision, error)) *agentprovider.EnrollmentService {
		service, err := agentprovider.NewEnrollmentService(agentprovider.EnrollmentServiceConfig{
			Provider: provider, Store: store, Enroll: enroll,
			Refresh: func(context.Context, agentprovider.RefreshRequest) (agentprovider.RefreshDecision, error) {
				return agentprovider.RefreshDecision{}, errors.New("unused")
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		return service
	}

	denied := newService(newMemoryEnrollmentStore(), func(context.Context, agentprovider.EnrollmentRequest) (agentprovider.EnrollmentDecision, error) {
		return agentprovider.EnrollmentDecision{}, agentprovider.ErrEnrollmentDenied
	})
	deniedResponse := httptest.NewRecorder()
	denied.EnrollmentHandler().ServeHTTP(deniedResponse, signedEnrollmentHTTPRequest(t, durable, clock))
	if deniedResponse.Code != http.StatusForbidden || deniedResponse.Header().Get("Signature-Error") != "" {
		t.Fatalf("policy denial = %d, Signature-Error %q", deniedResponse.Code, deniedResponse.Header().Get("Signature-Error"))
	}

	failed := newService(&failEnrollmentCommitStore{
		memoryEnrollmentStore: newMemoryEnrollmentStore(),
		err:                   errors.New("database unavailable"),
	}, func(context.Context, agentprovider.EnrollmentRequest) (agentprovider.EnrollmentDecision, error) {
		return agentprovider.EnrollmentDecision{Agent: "aauth:reference@ap.example"}, nil
	})
	failedResponse := httptest.NewRecorder()
	failed.EnrollmentHandler().ServeHTTP(failedResponse, signedEnrollmentHTTPRequest(t, durable, clock))
	if failedResponse.Code != http.StatusInternalServerError || failedResponse.Header().Get("Signature-Error") != "" {
		t.Fatalf("operational failure = %d, Signature-Error %q", failedResponse.Code, failedResponse.Header().Get("Signature-Error"))
	}
}

func TestRefreshHTTPHandlerRejectsChangedRequestForRetainedDelegation(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 31, 4, 45, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	provider, err := agentprovider.New(agentprovider.Config{
		Issuer: "https://ap.example", SigningKey: testSigningKey(t, "ap-key-conflict", 0x81), Clock: clock,
		NewID: func() string { return "agent-token-conflict" },
	})
	if err != nil {
		t.Fatal(err)
	}
	durable := testSigningKey(t, "durable-key-conflict", 0x82)
	ephemeral := testSigningKey(t, "ephemeral-key-conflict", 0x83)
	identity, err := durable.PublicJWK().ThumbprintURI()
	if err != nil {
		t.Fatal(err)
	}
	service, err := newTestEnrollmentService(t, provider, newMemoryEnrollmentStore(), identity, "aauth:reference@ap.example")
	if err != nil {
		t.Fatal(err)
	}
	enrollment := httptest.NewRecorder()
	service.EnrollmentHandler().ServeHTTP(enrollment, signedEnrollmentHTTPRequest(t, durable, clock))
	if enrollment.Code != http.StatusCreated {
		t.Fatalf("enrollment = %d %s", enrollment.Code, enrollment.Body.String())
	}
	compact, err := signaturekey.MintJKTJWT(durable, ephemeral.PublicJWK(), now, now.Add(time.Hour), "refresh-1")
	if err != nil {
		t.Fatal(err)
	}
	first := httptest.NewRecorder()
	service.RefreshHandler().ServeHTTP(first, signedRefreshHTTPRequest(t, compact, ephemeral, clock))
	if first.Code != http.StatusOK {
		t.Fatalf("first refresh = %d %s", first.Code, first.Body.String())
	}
	changed := httptest.NewRecorder()
	service.RefreshHandler().ServeHTTP(changed, signedRefreshHTTPRequestWithBody(
		t, compact, ephemeral, clock,
		`{"ps":"https://ps.example","evidence":{"posture":"current"},"extension":true}`,
	))
	if changed.Code != http.StatusConflict || changed.Header().Get("Signature-Error") != "" {
		t.Fatalf("changed refresh = %d %s, Signature-Error %q", changed.Code, changed.Body.String(), changed.Header().Get("Signature-Error"))
	}
}

func TestRefreshHTTPHandlerReturnsPolicyDenialWithoutSignatureChallenge(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 31, 4, 50, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	provider, err := agentprovider.New(agentprovider.Config{
		Issuer: "https://ap.example", SigningKey: testSigningKey(t, "ap-key-denial", 0x91), Clock: clock,
		NewID: func() string { return "unused" },
	})
	if err != nil {
		t.Fatal(err)
	}
	durable := testSigningKey(t, "durable-key-denial", 0x92)
	ephemeral := testSigningKey(t, "ephemeral-key-denial", 0x93)
	store := newMemoryEnrollmentStore()
	service, err := agentprovider.NewEnrollmentService(agentprovider.EnrollmentServiceConfig{
		Provider: provider, Store: store,
		Enroll: func(context.Context, agentprovider.EnrollmentRequest) (agentprovider.EnrollmentDecision, error) {
			return agentprovider.EnrollmentDecision{Agent: "aauth:reference@ap.example"}, nil
		},
		Refresh: func(context.Context, agentprovider.RefreshRequest) (agentprovider.RefreshDecision, error) {
			return agentprovider.RefreshDecision{}, agentprovider.ErrRefreshDenied
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	enrollment := httptest.NewRecorder()
	service.EnrollmentHandler().ServeHTTP(enrollment, signedEnrollmentHTTPRequest(t, durable, clock))
	if enrollment.Code != http.StatusCreated {
		t.Fatalf("enrollment = %d %s", enrollment.Code, enrollment.Body.String())
	}
	compact, err := signaturekey.MintJKTJWT(durable, ephemeral.PublicJWK(), now, now.Add(time.Hour), "refresh-denied")
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	service.RefreshHandler().ServeHTTP(response, signedRefreshHTTPRequest(t, compact, ephemeral, clock))
	if response.Code != http.StatusForbidden || response.Header().Get("Signature-Error") != "" {
		t.Fatalf("response = %d %s, Signature-Error %q", response.Code, response.Body.String(), response.Header().Get("Signature-Error"))
	}
}

func TestRefreshHTTPHandlerReturnsExpiredJWTWhenCommitWindowCloses(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 31, 4, 52, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	provider, err := agentprovider.New(agentprovider.Config{
		Issuer:     "https://ap.example",
		SigningKey: testSigningKey(t, "ap-key-expired-commit", 0x94), Clock: clock,
		NewID: func() string { return "expired-commit-token" },
	})
	if err != nil {
		t.Fatal(err)
	}
	durable := testSigningKey(t, "durable-key-expired-commit", 0x95)
	ephemeral := testSigningKey(t, "ephemeral-key-expired-commit", 0x96)
	identity, err := durable.PublicJWK().ThumbprintURI()
	if err != nil {
		t.Fatal(err)
	}
	store := newMemoryEnrollmentStore()
	store.now = func() time.Time { return now.Add(time.Minute) }
	if _, err := store.CommitEnrollment(context.Background(), agentprovider.EnrollmentRecord{
		Identity: identity, IdentityKey: durable.PublicJWK(),
		Agent: "aauth:reference@ap.example", State: agentprovider.EnrollmentActive, Revision: 1,
	}); err != nil {
		t.Fatal(err)
	}
	service, err := agentprovider.NewEnrollmentService(agentprovider.EnrollmentServiceConfig{
		Provider: provider, Store: store,
		Enroll: func(context.Context, agentprovider.EnrollmentRequest) (agentprovider.EnrollmentDecision, error) {
			return agentprovider.EnrollmentDecision{}, errors.New("unused")
		},
		Refresh: func(context.Context, agentprovider.RefreshRequest) (agentprovider.RefreshDecision, error) {
			return agentprovider.RefreshDecision{PersonServer: "https://ps.example", Lifetime: time.Minute}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	compact, err := signaturekey.MintJKTJWT(
		durable, ephemeral.PublicJWK(), now, now.Add(time.Minute), "refresh-expired-commit",
	)
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	service.RefreshHandler().ServeHTTP(response, signedRefreshHTTPRequest(t, compact, ephemeral, clock))
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("response = %d %s", response.Code, response.Body.String())
	}
	failure, err := signaturekey.ParseError(response.Header().Get("Signature-Error"))
	if err != nil {
		t.Fatal(err)
	}
	if failure.Code != signaturekey.ErrorExpiredJWT || len(store.refreshes) != 0 {
		t.Fatalf("Signature-Error = %#v, retained refreshes=%d", failure, len(store.refreshes))
	}
}

func TestRefreshHTTPHandlerNamesMissingEnrollment(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 31, 4, 55, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	provider, err := agentprovider.New(agentprovider.Config{
		Issuer: "https://ap.example", SigningKey: testSigningKey(t, "ap-key-missing", 0xa1), Clock: clock,
		NewID: func() string { return "unused" },
	})
	if err != nil {
		t.Fatal(err)
	}
	service, err := agentprovider.NewEnrollmentService(agentprovider.EnrollmentServiceConfig{
		Provider: provider, Store: newMemoryEnrollmentStore(),
		Enroll: func(context.Context, agentprovider.EnrollmentRequest) (agentprovider.EnrollmentDecision, error) {
			return agentprovider.EnrollmentDecision{}, errors.New("unused")
		},
		Refresh: func(context.Context, agentprovider.RefreshRequest) (agentprovider.RefreshDecision, error) {
			return agentprovider.RefreshDecision{}, errors.New("unused")
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	durable := testSigningKey(t, "durable-key-missing", 0xa2)
	ephemeral := testSigningKey(t, "ephemeral-key-missing", 0xa3)
	compact, err := signaturekey.MintJKTJWT(durable, ephemeral.PublicJWK(), now, now.Add(time.Hour), "refresh-missing")
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	service.RefreshHandler().ServeHTTP(response, signedRefreshHTTPRequest(t, compact, ephemeral, clock))
	if response.Code != http.StatusNotFound || response.Header().Get("Signature-Error") != "" {
		t.Fatalf("response = %d %s, Signature-Error %q", response.Code, response.Body.String(), response.Header().Get("Signature-Error"))
	}
}

func TestRefreshHTTPHandlerRefusesInactiveEnrollment(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 31, 5, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	provider, err := agentprovider.New(agentprovider.Config{
		Issuer: "https://ap.example", SigningKey: testSigningKey(t, "ap-key-inactive", 0xb1), Clock: clock,
		NewID: func() string { return "unused" },
	})
	if err != nil {
		t.Fatal(err)
	}
	durable := testSigningKey(t, "durable-key-inactive", 0xb2)
	ephemeral := testSigningKey(t, "ephemeral-key-inactive", 0xb3)
	identity, err := durable.PublicJWK().ThumbprintURI()
	if err != nil {
		t.Fatal(err)
	}
	store := newMemoryEnrollmentStore()
	_, err = store.CommitEnrollment(context.Background(), agentprovider.EnrollmentRecord{
		Identity: identity, IdentityKey: durable.PublicJWK(),
		Agent: "aauth:reference@ap.example", State: agentprovider.EnrollmentDisabled, Revision: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	service, err := agentprovider.NewEnrollmentService(agentprovider.EnrollmentServiceConfig{
		Provider: provider, Store: store,
		Enroll: func(context.Context, agentprovider.EnrollmentRequest) (agentprovider.EnrollmentDecision, error) {
			return agentprovider.EnrollmentDecision{}, errors.New("unused")
		},
		Refresh: func(context.Context, agentprovider.RefreshRequest) (agentprovider.RefreshDecision, error) {
			return agentprovider.RefreshDecision{}, errors.New("unused")
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	compact, err := signaturekey.MintJKTJWT(durable, ephemeral.PublicJWK(), now, now.Add(time.Hour), "refresh-inactive")
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	service.RefreshHandler().ServeHTTP(response, signedRefreshHTTPRequest(t, compact, ephemeral, clock))
	if response.Code != http.StatusForbidden || response.Header().Get("Signature-Error") != "" {
		t.Fatalf("response = %d %s, Signature-Error %q", response.Code, response.Body.String(), response.Header().Get("Signature-Error"))
	}
}

func TestEnrollmentHTTPHandlerReturnsBadRequestForInvalidProfileBody(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 31, 5, 5, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	provider, err := agentprovider.New(agentprovider.Config{
		Issuer: "https://ap.example", SigningKey: testSigningKey(t, "ap-key-invalid-body", 0xc1), Clock: clock,
		NewID: func() string { return "unused" },
	})
	if err != nil {
		t.Fatal(err)
	}
	policyCalls := 0
	service, err := agentprovider.NewEnrollmentService(agentprovider.EnrollmentServiceConfig{
		Provider: provider, Store: newMemoryEnrollmentStore(),
		Enroll: func(context.Context, agentprovider.EnrollmentRequest) (agentprovider.EnrollmentDecision, error) {
			policyCalls++
			return agentprovider.EnrollmentDecision{Agent: "aauth:reference@ap.example"}, nil
		},
		Refresh: func(context.Context, agentprovider.RefreshRequest) (agentprovider.RefreshDecision, error) {
			return agentprovider.RefreshDecision{}, errors.New("unused")
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	durable := testSigningKey(t, "durable-key-invalid-body", 0xc2)
	response := httptest.NewRecorder()
	service.EnrollmentHandler().ServeHTTP(response, signedEnrollmentHTTPRequestWithBody(t, durable, clock, `{"other":{}}`))
	if response.Code != http.StatusBadRequest || response.Header().Get("Signature-Error") != "" || policyCalls != 0 {
		t.Fatalf("response = %d %s, Signature-Error %q, policy calls=%d", response.Code, response.Body.String(), response.Header().Get("Signature-Error"), policyCalls)
	}
}

func TestEnrollmentHTTPHandlerRejectsMethodAndMediaTypeBeforePolicy(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 31, 5, 10, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	provider, err := agentprovider.New(agentprovider.Config{
		Issuer: "https://ap.example", SigningKey: testSigningKey(t, "ap-key-profile", 0xd1), Clock: clock,
		NewID: func() string { return "unused" },
	})
	if err != nil {
		t.Fatal(err)
	}
	policyCalls := 0
	service, err := agentprovider.NewEnrollmentService(agentprovider.EnrollmentServiceConfig{
		Provider: provider, Store: newMemoryEnrollmentStore(),
		Enroll: func(context.Context, agentprovider.EnrollmentRequest) (agentprovider.EnrollmentDecision, error) {
			policyCalls++
			return agentprovider.EnrollmentDecision{Agent: "aauth:reference@ap.example"}, nil
		},
		Refresh: func(context.Context, agentprovider.RefreshRequest) (agentprovider.RefreshDecision, error) {
			return agentprovider.RefreshDecision{}, errors.New("unused")
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	durable := testSigningKey(t, "durable-key-profile", 0xd2)
	tests := []struct {
		name   string
		change func(*http.Request)
		status int
	}{
		{name: "method", change: func(request *http.Request) { request.Method = http.MethodGet }, status: http.StatusMethodNotAllowed},
		{name: "media type", change: func(request *http.Request) { request.Header.Set("Content-Type", "text/plain") }, status: http.StatusUnsupportedMediaType},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := signedEnrollmentHTTPRequest(t, durable, clock)
			test.change(request)
			response := httptest.NewRecorder()
			service.EnrollmentHandler().ServeHTTP(response, request)
			if response.Code != test.status || response.Header().Get("Signature-Error") != "" {
				t.Fatalf("response = %d %s, Signature-Error %q", response.Code, response.Body.String(), response.Header().Get("Signature-Error"))
			}
		})
	}
	if policyCalls != 0 {
		t.Fatalf("policy calls = %d", policyCalls)
	}
}

func TestEnrollmentHTTPHandlerRejectsOversizeSignedBodyBeforePolicy(t *testing.T) {
	now := time.Date(2026, 8, 31, 5, 15, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	provider, err := agentprovider.New(agentprovider.Config{
		Issuer: "https://ap.example", SigningKey: testSigningKey(t, "ap-key-oversize", 0xe1), Clock: clock,
		NewID: func() string { return "unused" },
	})
	if err != nil {
		t.Fatal(err)
	}
	policyCalls := 0
	service, err := agentprovider.NewEnrollmentService(agentprovider.EnrollmentServiceConfig{
		Provider: provider, Store: newMemoryEnrollmentStore(),
		Enroll: func(context.Context, agentprovider.EnrollmentRequest) (agentprovider.EnrollmentDecision, error) {
			policyCalls++
			return agentprovider.EnrollmentDecision{Agent: "aauth:reference@ap.example"}, nil
		},
		Refresh: func(context.Context, agentprovider.RefreshRequest) (agentprovider.RefreshDecision, error) {
			return agentprovider.RefreshDecision{}, errors.New("unused")
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	body := `{"evidence":"` + strings.Repeat("x", 1<<20) + `"}`
	durable := testSigningKey(t, "durable-key-oversize", 0xe2)
	request := signedEnrollmentHTTPRequestWithLimit(t, durable, clock, body, int64(len(body)))
	response := httptest.NewRecorder()
	service.EnrollmentHandler().ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized || policyCalls != 0 {
		t.Fatalf("response = %d %s, policy calls=%d", response.Code, response.Body.String(), policyCalls)
	}
	failure, err := signaturekey.ParseError(response.Header().Get("Signature-Error"))
	if err != nil {
		t.Fatal(err)
	}
	if failure.Code != signaturekey.ErrorInvalidInput {
		t.Fatalf("Signature-Error = %#v", failure)
	}
}
