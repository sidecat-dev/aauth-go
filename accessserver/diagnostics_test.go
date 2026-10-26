package accessserver

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/diagnostics"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

func TestDiagnosticsObservesAccessServerProofFailure(t *testing.T) {
	server, err := New(Config{Issuer: "https://as.example", SigningKey: accessServerTestKey(t, "diagnostic-as"), Clock: aauth.ClockFunc(func() time.Time { return time.Unix(1800000000, 0) }), KeyResolver: signaturekey.StaticKeyResolver{}, NewID: func() string { return "unused" }, TrustPersonServer: func(context.Context, string) error { t.Fatal("invalid proof reached trust policy"); return nil }, Authorize: func(context.Context, AuthorizationRequest) (Decision, error) {
		t.Fatal("invalid proof reached authorization")
		return Decision{}, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	var got []diagnostics.Problem
	response := httptest.NewRecorder()
	diagnostics.Handler(server.Handler(), func(_ context.Context, p diagnostics.Problem) { got = append(got, p) }).ServeHTTP(response, httptest.NewRequest(http.MethodPost, "https://as.example/token", nil))
	if response.Code != 401 || len(got) != 1 || got[0].Status != 401 || got[0].Code != "invalid_request" || got[0].Cause == nil {
		t.Fatalf("response %d observations %#v", response.Code, got)
	}
}
