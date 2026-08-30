package resource

import (
	"errors"
	"io"
	"net/http"

	"aauth-go/internal/httpapi"
	"aauth-go/signaturekey"
)

func decodeJSON(body io.Reader, target any) error {
	return httpapi.DecodeJSON(body, maximumAuthorizationRequestBytes, target)
}

func writeJSON(response http.ResponseWriter, status int, value any) {
	httpapi.WriteJSON(response, status, value)
}

func writeProblem(response http.ResponseWriter, status int, code string, cause error) {
	httpapi.WriteProblem(response, status, code, cause)
}

type requestTokenError struct{ cause error }

func (failure *requestTokenError) Error() string { return failure.cause.Error() }
func (failure *requestTokenError) Unwrap() error { return failure.cause }

func writeCredentialProblem(response http.ResponseWriter, code string, err error) {
	var tokenFailure *requestTokenError
	if !errors.As(err, &tokenFailure) {
		writeProblem(response, http.StatusUnauthorized, code, err)
		return
	}
	writeProblem(response, http.StatusUnauthorized, code, signaturekey.NormalizeError(tokenFailure.cause, signaturekey.ErrorInvalidJWT))
}

func writeAuthorizationProblem(response http.ResponseWriter, err error) {
	var tokenFailure *requestTokenError
	if errors.As(err, &tokenFailure) {
		writeProblem(response, http.StatusBadRequest, "invalid_person_token", tokenFailure.cause)
		return
	}
	writeProblem(response, http.StatusUnauthorized, "invalid_signature", err)
}
