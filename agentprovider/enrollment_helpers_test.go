package agentprovider_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/agentprovider"
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

func newTestEnrollmentService(
	t *testing.T,
	provider *agentprovider.Server,
	store *memoryEnrollmentStore,
	identity, agentID string,
) (*agentprovider.EnrollmentService, error) {
	t.Helper()
	return agentprovider.NewEnrollmentService(agentprovider.EnrollmentServiceConfig{
		Provider: provider,
		Store:    store,
		Enroll: func(_ context.Context, request agentprovider.EnrollmentRequest) (agentprovider.EnrollmentDecision, error) {
			if request.Identity != identity || string(request.Evidence) != `{"account":"person-1"}` {
				t.Fatalf("enrollment request = %#v", request)
			}
			return agentprovider.EnrollmentDecision{Agent: agentID}, nil
		},
		Refresh: func(_ context.Context, request agentprovider.RefreshRequest) (agentprovider.RefreshDecision, error) {
			if request.Profile != agentprovider.RefreshProfileTwoKey ||
				request.Enrollment.Agent != agentID || request.Delegation.JTI() != "refresh-1" ||
				request.RequestedPersonServer != "https://ps.example" || string(request.Evidence) != `{"posture":"current"}` {
				t.Fatalf("refresh request = %#v", request)
			}
			return agentprovider.RefreshDecision{
				Lifetime: 30 * time.Minute, PersonServer: "https://ps.example",
				AdditionalClaims: map[string]json.RawMessage{"device_class": json.RawMessage(`"reference"`)},
			}, nil
		},
	})
}

func verifiedEnrollmentProof(
	t *testing.T,
	durable jose.SigningKey,
	clock aauth.Clock,
) signaturekey.VerifiedRequest {
	t.Helper()
	request, err := http.NewRequest(
		http.MethodPost, "https://ap.example/internal/enroll",
		bytes.NewReader([]byte(`{"evidence":{"account":"person-1"}}`)),
	)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	credential, err := signaturekey.NewHWKCredential(durable.PublicJWK())
	if err != nil {
		t.Fatal(err)
	}
	if err := signaturekey.SignRequest(request, durable, credential, clock, signaturekey.SignOptions{
		AdditionalComponents: []string{"content-type", "content-digest"},
	}); err != nil {
		t.Fatal(err)
	}
	prepared, err := signaturekey.PrepareRequest(request, clock, signaturekey.VerifyOptions{
		AcceptedSchemes:    []signaturekey.Scheme{signaturekey.SchemeHWK},
		RequiredComponents: []string{"content-type", "content-digest"}, RequireExactComponents: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	key, ok := prepared.Credential().InlineJWK()
	if !ok {
		t.Fatal("enrollment credential has no durable key")
	}
	proof, err := prepared.Verify(key)
	if err != nil {
		t.Fatal(err)
	}
	return proof
}

func verifiedRefreshProof(
	t *testing.T,
	compact string,
	ephemeral jose.SigningKey,
	clock aauth.Clock,
) (signaturekey.VerifiedRequest, signaturekey.JKTJWTDelegation) {
	t.Helper()
	request, err := http.NewRequest(
		http.MethodPost, "https://ap.example/internal/refresh",
		bytes.NewReader([]byte(`{"ps":"https://ps.example","evidence":{"posture":"current"}}`)),
	)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	credential, err := signaturekey.NewJKTJWTCredential(compact)
	if err != nil {
		t.Fatal(err)
	}
	if err := signaturekey.SignRequest(request, ephemeral, credential, clock, signaturekey.SignOptions{
		AdditionalComponents: []string{"content-type", "content-digest"},
	}); err != nil {
		t.Fatal(err)
	}
	prepared, err := signaturekey.PrepareRequest(request, clock, signaturekey.VerifyOptions{
		AcceptedSchemes:    []signaturekey.Scheme{signaturekey.SchemeJKTJWT},
		RequiredComponents: []string{"content-type", "content-digest"}, RequireExactComponents: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	proof, delegation, err := prepared.VerifyJKTJWT()
	if err != nil {
		t.Fatal(err)
	}
	return proof, delegation
}

func signedEnrollmentHTTPRequest(
	t *testing.T,
	durable jose.SigningKey,
	clock aauth.Clock,
) *http.Request {
	t.Helper()
	return signedEnrollmentHTTPRequestWithBody(t, durable, clock, `{"evidence":{"account":"person-1"}}`)
}

func signedEnrollmentHTTPRequestWithBody(
	t *testing.T,
	durable jose.SigningKey,
	clock aauth.Clock,
	body string,
) *http.Request {
	t.Helper()
	return signedEnrollmentHTTPRequestWithLimit(t, durable, clock, body, 0)
}

func signedEnrollmentHTTPRequestWithLimit(
	t *testing.T,
	durable jose.SigningKey,
	clock aauth.Clock,
	body string,
	maxBodyBytes int64,
) *http.Request {
	t.Helper()
	request, err := http.NewRequest(
		http.MethodPost, "https://ap.example/custom/enrollment",
		bytes.NewReader([]byte(body)),
	)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	credential, err := signaturekey.NewHWKCredential(durable.PublicJWK())
	if err != nil {
		t.Fatal(err)
	}
	if err := signaturekey.SignRequest(request, durable, credential, clock, signaturekey.SignOptions{
		AdditionalComponents: []string{"content-type", "content-digest"},
		MaxBodyBytes:         maxBodyBytes,
	}); err != nil {
		t.Fatal(err)
	}
	return request
}

func signedRefreshHTTPRequest(
	t *testing.T,
	compact string,
	ephemeral jose.SigningKey,
	clock aauth.Clock,
) *http.Request {
	t.Helper()
	return signedRefreshHTTPRequestWithBody(
		t, compact, ephemeral, clock,
		`{"ps":"https://ps.example","evidence":{"posture":"current"}}`,
	)
}

func signedRefreshHTTPRequestWithBody(
	t *testing.T,
	compact string,
	ephemeral jose.SigningKey,
	clock aauth.Clock,
	body string,
) *http.Request {
	t.Helper()
	request, err := http.NewRequest(
		http.MethodPost, "https://ap.example/custom/refresh",
		bytes.NewReader([]byte(body)),
	)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	credential, err := signaturekey.NewJKTJWTCredential(compact)
	if err != nil {
		t.Fatal(err)
	}
	if err := signaturekey.SignRequest(request, ephemeral, credential, clock, signaturekey.SignOptions{
		AdditionalComponents: []string{"content-type", "content-digest"},
	}); err != nil {
		t.Fatal(err)
	}
	return request
}
