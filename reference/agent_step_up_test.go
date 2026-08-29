package reference

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	aa "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

func TestResourceGrantFromAuthChallengeRejectsChangedAuthorizationContext(t *testing.T) {
	now := time.Date(2026, 8, 29, 23, 30, 0, 0, time.UTC)
	clock := aa.ClockFunc(func() time.Time { return now })
	resourceKey := referenceTestSigningKey(t, "step-up-resource")
	agentKey := referenceTestSigningKey(t, "step-up-agent")
	agent := &Agent{
		keyResolver: signaturekey.StaticKeyResolver{
			"https://resource.example": {resourceKey.ID(): resourceKey.PublicJWK()},
		},
		signingKey: agentKey,
		clock:      clock,
	}
	thumbprint, err := agentKey.PublicJWK().Thumbprint()
	if err != nil {
		t.Fatal(err)
	}
	current := aa.AuthTokenClaims{
		Issuer: "https://as.example", DWK: aa.AccessDiscoveryDocument,
		Audience: "https://resource.example", JTI: "current-auth-token",
		Confirmation: aa.Confirmation{JWK: agentKey.PublicJWK()},
		IssuedAt:     now.Unix(), ExpiresAt: now.Add(time.Hour).Unix(),
		Subject: "person-a", Scope: "records.read", PersonServer: "https://ps.example",
	}
	for _, test := range []struct {
		name   string
		mutate func(*aa.ResourceTokenClaims)
	}{
		{
			name: "subject",
			mutate: func(claims *aa.ResourceTokenClaims) {
				claims.Subject = "person-b"
			},
		},
		{
			name: "audience",
			mutate: func(claims *aa.ResourceTokenClaims) {
				claims.Audience = "https://other-as.example"
			},
		},
		{
			name: "confirmation key",
			mutate: func(claims *aa.ResourceTokenClaims) {
				claims.AgentJKT = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			claims := aa.ResourceTokenClaims{
				Issuer: "https://resource.example", DWK: aa.ResourceDiscoveryDocument,
				Audience: current.Issuer, JTI: "step-up-resource-token-" + test.name,
				AgentJKT: thumbprint, IssuedAt: now.Unix(), ExpiresAt: now.Add(5 * time.Minute).Unix(),
				Scope: "records.read records.write", PersonServer: current.PersonServer,
				Subject: current.Subject, PresentedJTI: "person-token-jti",
			}
			test.mutate(&claims)
			compact, mintErr := aa.MintResourceToken(resourceKey, claims)
			if mintErr != nil {
				t.Fatal(mintErr)
			}
			_, grantErr := agent.resourceGrantFromAuthChallenge(context.Background(), "https://resource.example", current, compact)
			if grantErr == nil || !strings.Contains(grantErr.Error(), "does not match the existing auth-token context") {
				t.Fatalf("changed %s context error = %v", test.name, grantErr)
			}
		})
	}
}

func TestAgentAuthTokenStepUpDoesNotFollowASecondChallenge(t *testing.T) {
	now := time.Date(2026, 8, 29, 23, 45, 0, 0, time.UTC)
	clock := aa.ClockFunc(func() time.Time { return now })
	apKey := referenceTestSigningKey(t, "step-up-ap")
	psKey := referenceTestSigningKey(t, "step-up-ps")
	resourceKey := referenceTestSigningKey(t, "step-up-resource")
	agentKey := referenceTestSigningKey(t, "step-up-agent")
	currentClaims := aa.AuthTokenClaims{
		Issuer: "https://ps.example", DWK: aa.PersonDiscoveryDocument,
		Audience: "https://resource.example", JTI: "current-auth-token",
		Confirmation: aa.Confirmation{JWK: agentKey.PublicJWK()},
		IssuedAt:     now.Unix(), ExpiresAt: now.Add(time.Hour).Unix(),
		Subject: "step-up-person", Scope: "records.read", PersonServer: "https://ps.example",
	}
	currentCompact, err := aa.MintAuthToken(psKey, currentClaims)
	if err != nil {
		t.Fatal(err)
	}
	agentCompact, err := aa.MintAgentToken("https://ap.example", apKey, aa.AgentTokenRequest{
		Agent: "aauth:step-up-agent@ap.example", PersonServer: "https://ps.example",
		PublicKey: agentKey.PublicJWK(), Lifetime: time.Hour,
	}, now, "step-up-agent-token")
	if err != nil {
		t.Fatal(err)
	}
	thumbprint, err := agentKey.PublicJWK().Thumbprint()
	if err != nil {
		t.Fatal(err)
	}
	resourceCompact, err := aa.MintResourceToken(resourceKey, aa.ResourceTokenClaims{
		Issuer: "https://resource.example", DWK: aa.ResourceDiscoveryDocument,
		Audience: "https://ps.example", JTI: "step-up-resource-token",
		AgentJKT: thumbprint, IssuedAt: now.Unix(), ExpiresAt: now.Add(5 * time.Minute).Unix(),
		Scope: "records.read records.write", PersonServer: "https://ps.example",
		Subject: "step-up-person", PresentedJTI: "person-token-jti",
	})
	if err != nil {
		t.Fatal(err)
	}
	upgradedClaims := currentClaims
	upgradedClaims.JTI = "upgraded-auth-token"
	upgradedClaims.Scope = "records.read records.write"
	upgradedClaims.ExpiresAt = now.Add(4 * time.Minute).Unix()
	upgradedCompact, err := aa.MintAuthToken(psKey, upgradedClaims)
	if err != nil {
		t.Fatal(err)
	}
	requirement, err := aa.FormatRequirementHeader(aa.Requirement{
		Type: aa.RequirementAuthToken, ResourceToken: resourceCompact,
	})
	if err != nil {
		t.Fatal(err)
	}
	transport := &stepUpChallengeTransport{
		requirement: requirement, upgradedToken: upgradedCompact,
	}
	agent := &Agent{
		identifier: "aauth:step-up-agent@ap.example",
		agentToken: agentCompact,
		signingKey: agentKey,
		keyResolver: signaturekey.StaticKeyResolver{
			"https://ap.example":       {apKey.ID(): apKey.PublicJWK()},
			"https://ps.example":       {psKey.ID(): psKey.PublicJWK()},
			"https://resource.example": {resourceKey.ID(): resourceKey.PublicJWK()},
		},
		clock:      clock,
		httpClient: &http.Client{Transport: transport},
	}
	response, upgraded, err := agent.DoWithAuthTokenAuthorization(
		context.Background(),
		AuthorizedCall{Method: http.MethodGet, Endpoint: "https://resource.example/records"},
		"https://ps.example/token",
		Grant{Resource: "https://resource.example", AuthToken: currentCompact, Claims: currentClaims},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("second step-up challenge status = %d", response.StatusCode)
	}
	if upgraded.Claims.JTI != upgradedClaims.JTI || upgraded.AuthToken != upgradedCompact {
		t.Fatalf("upgraded grant = %#v", upgraded)
	}
	if transport.protectedRequests != 2 || transport.tokenRequests != 1 {
		t.Fatalf("protected/token requests = %d/%d, want 2/1", transport.protectedRequests, transport.tokenRequests)
	}
}

type stepUpChallengeTransport struct {
	requirement       string
	upgradedToken     string
	protectedRequests int
	tokenRequests     int
}

func (transport *stepUpChallengeTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	switch request.URL.Host {
	case "resource.example":
		transport.protectedRequests++
		response := &http.Response{
			StatusCode: http.StatusUnauthorized,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader(`{"error":"authorization_required"}`)),
			Request:    request,
		}
		response.Header.Set("AAuth-Requirement", transport.requirement)
		return response, nil
	case "ps.example":
		transport.tokenRequests++
		body, err := json.Marshal(map[string]string{"auth_token": transport.upgradedToken})
		if err != nil {
			return nil, err
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body:       io.NopCloser(strings.NewReader(string(body))),
			Request:    request,
		}, nil
	default:
		return nil, fmt.Errorf("unexpected step-up host %s", request.URL.Host)
	}
}

func TestParseAuthTokenChallengeDistinguishesMalformedAndOtherRequirements(t *testing.T) {
	for _, test := range []struct {
		name        string
		status      int
		header      string
		wantPresent bool
		wantError   bool
	}{
		{name: "ordinary unauthorized", status: 401},
		{name: "other requirement", status: 401, header: "requirement=person-token"},
		{name: "malformed requirement", status: 401, header: "requirement=auth-token; =broken", wantPresent: true, wantError: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			response := &httpResponseForStepUpTest{status: test.status, header: test.header}
			challenge, present, err := parseAuthTokenChallenge(response.response())
			if present != test.wantPresent || (err != nil) != test.wantError {
				t.Fatalf("challenge = %#v, present=%v, err=%v", challenge, present, err)
			}
		})
	}
	requirement, err := aa.FormatRequirementHeader(aa.Requirement{Type: aa.RequirementAuthToken, ResourceToken: "resource-token"})
	if err != nil {
		t.Fatal(err)
	}
	deferred := &http.Response{
		StatusCode: http.StatusAccepted,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(`{"status":"pending"}`)),
	}
	deferred.Header.Set("Location", "https://resource.example/pending/step-up")
	deferred.Header.Set("Retry-After", "0")
	deferred.Header.Set("Cache-Control", "no-store")
	deferred.Header.Set("Content-Type", "application/json")
	deferred.Header.Set("AAuth-Requirement", requirement)
	deferred.Request, err = http.NewRequest(http.MethodGet, "https://resource.example/records", nil)
	if err != nil {
		t.Fatal(err)
	}
	challenge, present, err := parseAuthTokenChallenge(deferred)
	if err != nil || !present || challenge.requirement.ResourceToken != "resource-token" || challenge.completionTarget != "https://resource.example/pending/step-up" {
		t.Fatalf("deferred challenge = %#v, present=%v, err=%v", challenge, present, err)
	}
}

type httpResponseForStepUpTest struct {
	status int
	header string
}

func (response *httpResponseForStepUpTest) response() *http.Response {
	result := &http.Response{
		StatusCode: response.status,
		Header:     make(http.Header),
		Body:       http.NoBody,
	}
	if response.header != "" {
		result.Header.Set("AAuth-Requirement", response.header)
	}
	return result
}
