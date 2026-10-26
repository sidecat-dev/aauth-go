package agentprovider_test

import (
	"context"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/agentprovider"
	"gitlab.com/sidecat-dev/aauth-go/diagnostics"
)

func TestDiagnosticsObservesEnrollmentCommitFailure(t *testing.T) {
	clock := aauth.ClockFunc(func() time.Time { return time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC) })
	provider, err := agentprovider.New(agentprovider.Config{Issuer: "https://ap.example", SigningKey: testSigningKey(t, "diagnostic-ap", 0x71), Clock: clock, NewID: func() string { return "unused" }})
	if err != nil {
		t.Fatal(err)
	}
	private := errors.New("private enrollment store unavailable")
	service, err := agentprovider.NewEnrollmentService(agentprovider.EnrollmentServiceConfig{
		Provider: provider, Store: &failEnrollmentCommitStore{memoryEnrollmentStore: newMemoryEnrollmentStore(), err: private},
		Enroll: func(context.Context, agentprovider.EnrollmentRequest) (agentprovider.EnrollmentDecision, error) {
			return agentprovider.EnrollmentDecision{Agent: "aauth:reference@ap.example"}, nil
		},
		Refresh: func(context.Context, agentprovider.RefreshRequest) (agentprovider.RefreshDecision, error) {
			return agentprovider.RefreshDecision{}, errors.New("unused")
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	var got []diagnostics.Problem
	handler := diagnostics.Handler(service.EnrollmentHandler(), func(_ context.Context, p diagnostics.Problem) { got = append(got, p) })
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, signedEnrollmentHTTPRequest(t, testSigningKey(t, "diagnostic-durable", 0x72), clock))
	if response.Code != 500 || strings.Contains(response.Body.String(), private.Error()) {
		t.Fatalf("response %d %s", response.Code, response.Body.String())
	}
	if len(got) != 1 || !errors.Is(got[0].Cause, private) {
		t.Fatalf("observations: %#v", got)
	}
}
