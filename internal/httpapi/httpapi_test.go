package httpapi_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"aauth-go/internal/httpapi"
	"aauth-go/signaturekey"
)

func TestDecodeExactJSONReturnsIndependentExactInputBytes(t *testing.T) {
	t.Parallel()

	input := []byte(" \n{\"name\":\"one\",\"extension\":{\"future\":true}}\t")
	var value struct {
		Name string `json:"name"`
	}
	exact, err := httpapi.DecodeExactJSON(bytes.NewReader(input), 0, &value)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(exact, input) || value.Name != "one" {
		t.Fatalf("exact = %q, name = %q", exact, value.Name)
	}
	exact[0] = '!'
	if input[0] != ' ' {
		t.Fatal("returned exact bytes alias the reader input")
	}
}

func TestDecodeExactJSONDoesNotAliasDecodedRawMessage(t *testing.T) {
	t.Parallel()

	var value struct {
		Payload json.RawMessage `json:"payload"`
	}
	exact, err := httpapi.DecodeExactJSON(strings.NewReader(`{"payload":{"value":1}}`), 0, &value)
	if err != nil {
		t.Fatal(err)
	}
	wantPayload := append([]byte(nil), value.Payload...)
	exact[len(exact)-2] = '2'
	if !bytes.Equal(value.Payload, wantPayload) {
		t.Fatal("mutating exact bytes changed the decoded value")
	}
	wantExact := append([]byte(nil), exact...)
	value.Payload[0] = '['
	if !bytes.Equal(exact, wantExact) {
		t.Fatal("mutating the decoded value changed the exact bytes")
	}
}

func TestDecodeExactJSONPreservesDecodeJSONFailureClasses(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name   string
		reader io.Reader
		max    int64
	}{
		{name: "nil reader"},
		{name: "duplicate", reader: strings.NewReader(`{"name":"one","name":"two"}`)},
		{name: "case ambiguous", reader: strings.NewReader(`{"name":"one","Name":"two"}`)},
		{name: "lone case variant", reader: strings.NewReader(`{"Name":"one"}`)},
		{name: "trailing", reader: strings.NewReader(`{"name":"one"} {"name":"two"}`)},
		{name: "oversize", reader: strings.NewReader(`{"name":"one"}`), max: 4},
	} {
		t.Run(test.name, func(t *testing.T) {
			var value struct {
				Name string `json:"name"`
			}
			if _, err := httpapi.DecodeExactJSON(test.reader, test.max, &value); err == nil {
				t.Fatal("DecodeExactJSON succeeded")
			}
		})
	}
}

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
