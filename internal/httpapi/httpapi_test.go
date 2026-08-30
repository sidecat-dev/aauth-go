package httpapi_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aauth-dev/auth-go/internal/httpapi"
	"github.com/aauth-dev/auth-go/signaturekey"
)

func TestDecodeJSONRejectsAmbiguityCaseVariantsTrailingValuesAndOversize(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name string
		body string
		max  int64
	}{
		{name: "duplicate", body: `{"name":"one","name":"two"}`},
		{name: "case ambiguous", body: `{"name":"one","Name":"two"}`},
		{name: "lone case variant", body: `{"Name":"one"}`},
		{name: "trailing", body: `{"name":"one"} {"name":"two"}`},
		{name: "oversize", body: `{"name":"one"}`, max: 4},
	} {
		t.Run(test.name, func(t *testing.T) {
			var value struct {
				Name string `json:"name"`
			}
			if err := httpapi.DecodeJSON(strings.NewReader(test.body), test.max, &value); err == nil {
				t.Fatal("DecodeJSON succeeded")
			}
		})
	}
}

func TestDecodeJSONPermitsAdditiveExtensionMembers(t *testing.T) {
	t.Parallel()

	var value struct {
		Name string `json:"name"`
	}
	if err := httpapi.DecodeJSON(
		strings.NewReader(`{"name":"one","extension":{"future":true}}`),
		0,
		&value,
	); err != nil {
		t.Fatal(err)
	}
	if value.Name != "one" {
		t.Fatalf("name = %q", value.Name)
	}
}

func TestWriteProblemUsesProblemJSONAndSignatureErrorWithoutLeakingCause(t *testing.T) {
	t.Parallel()

	recorder := httptest.NewRecorder()
	httpapi.WriteProblem(recorder, http.StatusUnauthorized, "invalid_signature", &signaturekey.Error{
		Code: signaturekey.ErrorInvalidInput, RequiredInput: []string{"content-digest"},
		Cause: errors.New("private verifier diagnostic"),
	})
	response := recorder.Result()
	if got := response.Header.Get("Content-Type"); got != "application/problem+json" {
		t.Fatalf("Content-Type = %q", got)
	}
	if got := response.Header.Get("Signature-Error"); !strings.Contains(got, "invalid_input") || !strings.Contains(got, "content-digest") {
		t.Fatalf("Signature-Error = %q", got)
	}
	body := recorder.Body.String()
	if strings.Contains(body, "private verifier diagnostic") ||
		!strings.Contains(body, `"error":"invalid_signature"`) ||
		!strings.Contains(body, `"type":"urn:ietf:params:sig-error:invalid_input"`) {
		t.Fatalf("problem body = %s", body)
	}
}

func TestWriteProblemAlwaysProvidesMachineReadableSignatureErrorOn401(t *testing.T) {
	t.Parallel()

	recorder := httptest.NewRecorder()
	httpapi.WriteProblem(recorder, http.StatusUnauthorized, "invalid_agent_token", errors.New("token verification failed"))
	if got := recorder.Header().Get("Signature-Error"); !strings.Contains(got, "invalid_jwt") {
		t.Fatalf("Signature-Error = %q", got)
	}
}

func TestWriteProblemPreservesDiscoveryErrorInHeaderAndProblemType(t *testing.T) {
	t.Parallel()

	recorder := httptest.NewRecorder()
	httpapi.WriteProblem(recorder, http.StatusUnauthorized, "invalid_signature", &signaturekey.ResolutionError{
		Code: signaturekey.ResolutionIssuerMismatch, Cause: errors.New("private metadata diagnostic"),
	})
	if got := recorder.Header().Get("Signature-Error"); !strings.Contains(got, "issuer_mismatch") {
		t.Fatalf("Signature-Error = %q", got)
	}
	body := recorder.Body.String()
	if !strings.Contains(body, `"type":"urn:ietf:params:sig-error:issuer_mismatch"`) || strings.Contains(body, "private metadata diagnostic") {
		t.Fatalf("problem body = %s", body)
	}
}
