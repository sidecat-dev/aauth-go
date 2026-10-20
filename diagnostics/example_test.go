package diagnostics_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/diagnostics"
	"gitlab.com/sidecat-dev/aauth-go/resource"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

func ExampleHandler() {
	service, err := resource.NewAgentIdentity(resource.AgentIdentityConfig{
		Issuer:      "https://resource.example",
		Clock:       aauth.ClockFunc(func() time.Time { return time.Unix(1800000000, 0) }),
		KeyResolver: signaturekey.StaticKeyResolver{},
		Protected:   http.NotFoundHandler(),
	})
	if err != nil {
		panic(err)
	}
	handler := diagnostics.Handler(service.Handler(), func(ctx context.Context, problem diagnostics.Problem) {
		// A real host can use ctx for its request ID, and errors.Is/As on Cause.
		// Select or redact diagnostic fields before retaining them in logs.
		fmt.Printf("host: status=%d code=%s cause=%t\n", problem.Status, problem.Code, problem.Cause != nil)
	})
	request := httptest.NewRequest(http.MethodGet, "https://resource.example/notes", nil)
	request.Header.Set("Signature-Key", `sig=jwt;jwt="malformed"`)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	fmt.Printf("caller: status=%d\n", response.Code)
	// Output:
	// host: status=401 code=invalid_token cause=true
	// caller: status=401
}
