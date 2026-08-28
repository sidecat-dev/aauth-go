package reference_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/reference"
)

func TestResourceReportsSignatureFailuresAsSignatureError(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	issuer := referenceTestSigningKey(t, "issuer-key")
	requestKey := referenceTestSigningKey(t, "request-key")
	credential, err := aauth.MintPersonToken(issuer, aauth.PersonTokenClaims{
		Issuer: "https://ps.example", DWK: aauth.PersonDiscoveryDocument,
		Audience: "https://resource.example", Subject: "person",
		Confirmation: aauth.Confirmation{JWK: requestKey.PublicJWK()},
		JTI:          "person-token", IssuedAt: now.Unix(), ExpiresAt: now.Add(time.Hour).Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	resource, err := reference.NewResource(reference.ResourceConfig{
		Identifier: "https://resource.example", AccessMode: aauth.AccessModeSessionToken,
		KeyResolver: aauth.StaticKeyResolver{
			"https://ps.example": {"issuer-key": issuer.PublicJWK()},
		},
		Clock:                    clock,
		NewID:                    func() string { return "access-token" },
		Scopes:                   []string{"documents.read"},
		RequiredScopesForRequest: referenceTestRequiredResourceScopes("documents.read"),
		ReplayStore:              referenceTestResourceReplayStore(t, clock),
		AuthorizationStore:       referenceTestAuthorizationStateStore(t),
		AuthorizationPolicy: func(context.Context, aauth.AuthorizationRequest) (aauth.AuthorizationDecision, error) {
			return aauth.AuthorizationDecision{Subject: "subject", Scope: []string{"documents.read"}}, nil
		},
		Operation: func(context.Context, aauth.AuthorizedRequest) (any, error) {
			return map[string]string{"ok": "true"}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		name  string
		setup func(*http.Request) error
		want  aauth.SignatureErrorCode
	}{
		{
			name:  "missing proof headers",
			setup: func(*http.Request) error { return nil },
			want:  aauth.SignatureErrorInvalidRequest,
		},
		{
			name: "missing covered component",
			setup: func(request *http.Request) error {
				if err := aauth.SignRequest(request, requestKey, credential, clock); err != nil {
					return err
				}
				request.Header.Set("Signature-Input", strings.Replace(request.Header.Get("Signature-Input"), ` "content-digest"`, "", 1))
				return nil
			},
			want: aauth.SignatureErrorInvalidInput,
		},
		{
			name: "invalid signature",
			setup: func(request *http.Request) error {
				if err := aauth.SignRequest(request, requestKey, credential, clock); err != nil {
					return err
				}
				request.Header.Set("Signature", "sig=:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==:")
				return nil
			},
			want: aauth.SignatureErrorInvalidSignature,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "https://resource.example/authorize", strings.NewReader(`{"scope":"documents.read"}`))
			request.Header.Set("Content-Type", "application/json")
			if err := test.setup(request); err != nil {
				t.Fatal(err)
			}
			response := httptest.NewRecorder()
			resource.Handler().ServeHTTP(response, request)
			if response.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401: %s", response.Code, response.Body.String())
			}
			parsed, err := aauth.ParseSignatureError(response.Header().Get("Signature-Error"))
			if err != nil || parsed.Code != test.want {
				t.Fatalf("Signature-Error = %q parsed=%#v err=%v", response.Header().Get("Signature-Error"), parsed, err)
			}
			if !strings.Contains(response.Body.String(), `"type":"urn:ietf:params:sig-error:`+string(test.want)+`"`) {
				t.Fatalf("problem body = %s", response.Body.String())
			}
		})
	}
}

func TestResourcePolicyDenialIsNotASignatureFailure(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	issuer := referenceTestSigningKey(t, "issuer-key")
	requestKey := referenceTestSigningKey(t, "request-key")
	credential, err := aauth.MintAgentToken("https://ap.example", issuer, aauth.AgentTokenRequest{
		Agent: "aauth:agent@ap.example", PublicKey: requestKey.PublicJWK(), Lifetime: time.Hour,
	}, now, "agent-token")
	if err != nil {
		t.Fatal(err)
	}
	resource, err := reference.NewResource(reference.ResourceConfig{
		Identifier: "https://resource.example", AccessMode: aauth.AccessModeSessionToken,
		KeyResolver: aauth.StaticKeyResolver{
			"https://ap.example": {"issuer-key": issuer.PublicJWK()},
		},
		Clock:                    clock,
		NewID:                    func() string { return "access-token" },
		Scopes:                   []string{"documents.read"},
		RequiredScopesForRequest: referenceTestRequiredResourceScopes("documents.read"),
		ReplayStore:              referenceTestResourceReplayStore(t, clock),
		AuthorizationStore:       referenceTestAuthorizationStateStore(t),
		AuthorizationPolicy: func(context.Context, aauth.AuthorizationRequest) (aauth.AuthorizationDecision, error) {
			return aauth.AuthorizationDecision{}, errors.New("secret tenant policy backend /srv/policy.db")
		},
		Operation: func(context.Context, aauth.AuthorizedRequest) (any, error) { return nil, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "https://resource.example/documents", nil)
	if err := aauth.SignRequest(request, requestKey, credential, clock); err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	resource.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403: %s", response.Code, response.Body.String())
	}
	if got := response.Header().Get("Signature-Error"); got != "" {
		t.Fatalf("403 Signature-Error = %q, want absent", got)
	}
	if got := response.Header().Get("Accept-Signature"); got != "" {
		t.Fatalf("403 Accept-Signature = %q, want absent", got)
	}
	if got := response.Header().Get("Accept-Signature-Alg"); got != "" {
		t.Fatalf("403 Accept-Signature-Alg = %q, want absent", got)
	}
	if got := response.Header().Get("Accept-Signature-Scheme"); got != "" {
		t.Fatalf("403 Accept-Signature-Scheme = %q, want absent", got)
	}
	if strings.Contains(response.Body.String(), "secret tenant") ||
		!strings.Contains(response.Body.String(), `"detail":"authorization policy denied the request"`) {
		t.Fatalf("policy denial leaked host detail: %s", response.Body.String())
	}
}

func TestResourceSanitizesOperationalKeyResolutionFailure(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	issuer := referenceTestSigningKey(t, "issuer-key")
	requestKey := referenceTestSigningKey(t, "request-key")
	credential, err := aauth.MintPersonToken(issuer, aauth.PersonTokenClaims{
		Issuer: "https://ps.example", DWK: aauth.PersonDiscoveryDocument,
		Audience: "https://resource.example", Subject: "person",
		Confirmation: aauth.Confirmation{JWK: requestKey.PublicJWK()},
		JTI:          "person-token", IssuedAt: now.Unix(), ExpiresAt: now.Add(time.Hour).Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	resource, err := reference.NewResource(reference.ResourceConfig{
		Identifier: "https://resource.example", AccessMode: aauth.AccessModeSessionToken,
		KeyResolver: failingReferenceKeyResolver{err: &aauth.KeyResolutionError{
			Code:  aauth.KeyResolutionUnavailable,
			Cause: errors.New("private endpoint and transport detail"),
		}},
		Clock:                    clock,
		NewID:                    func() string { return "access-token" },
		Scopes:                   []string{"documents.read"},
		RequiredScopesForRequest: referenceTestRequiredResourceScopes("documents.read"),
		ReplayStore:              referenceTestResourceReplayStore(t, clock),
		AuthorizationStore:       referenceTestAuthorizationStateStore(t),
		AuthorizationPolicy: func(context.Context, aauth.AuthorizationRequest) (aauth.AuthorizationDecision, error) {
			return aauth.AuthorizationDecision{}, nil
		},
		Operation: func(context.Context, aauth.AuthorizedRequest) (any, error) {
			return nil, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "https://resource.example/authorize", strings.NewReader(`{"scope":"documents.read"}`))
	request.Header.Set("Content-Type", "application/json")
	if err := aauth.SignRequest(request, requestKey, credential, clock); err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	resource.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503: %s", response.Code, response.Body.String())
	}
	if got := response.Header().Get("Signature-Error"); got != "" {
		t.Fatalf("operational failure Signature-Error = %q, want absent", got)
	}
	if strings.Contains(response.Body.String(), "private endpoint") {
		t.Fatalf("operational detail leaked: %s", response.Body.String())
	}
}

type failingReferenceKeyResolver struct{ err error }

func (resolver failingReferenceKeyResolver) ResolveKey(context.Context, string, string, string) (aauth.JWK, error) {
	return aauth.JWK{}, resolver.err
}

func referenceTestSigningKey(t *testing.T, id string) aauth.SigningKey {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := aauth.NewEd25519SigningKey(id, private)
	if err != nil {
		t.Fatal(err)
	}
	return key
}
