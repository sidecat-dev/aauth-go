package resource

import (
	"errors"
	"io"
	"net/http"

	"gitlab.com/sidecat-dev/aauth-go/internal/httpapi"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
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

// revocationStoreError is a failure of the Resource's own revocation store,
// answered as server_error rather than as a credential failure.
type revocationStoreError struct{ cause error }

func (failure *revocationStoreError) Error() string { return failure.cause.Error() }
func (failure *revocationStoreError) Unwrap() error { return failure.cause }

func writeCredentialProblem(response http.ResponseWriter, code string, err error) {
	var storeFailure *revocationStoreError
	if errors.As(err, &storeFailure) {
		writeProblem(response, http.StatusInternalServerError, "server_error", storeFailure.cause)
		return
	}
	var tokenFailure *requestTokenError
	if !errors.As(err, &tokenFailure) {
		writeProblem(response, http.StatusUnauthorized, code, err)
		return
	}
	cause := tokenFailure.cause
	if errors.Is(cause, ErrAgentTokenRevoked) || errors.Is(cause, ErrPersonTokenRevoked) {
		cause = signaturekey.NewError(signaturekey.ErrorRevokedJWT, cause)
	}
	writeProblem(response, http.StatusUnauthorized, code, signaturekey.NormalizeError(cause, signaturekey.ErrorInvalidJWT))
}

// writeAuthorizationProblem answers a request proof or person token that fails
// verification at the authorization endpoint with 401 and Signature-Error,
// not with a code from the authorization-endpoint error table.
func writeAuthorizationProblem(response http.ResponseWriter, err error) {
	var tokenFailure *requestTokenError
	var storeFailure *revocationStoreError
	if errors.As(err, &tokenFailure) || errors.As(err, &storeFailure) {
		writeCredentialProblem(response, "invalid_token", err)
		return
	}
	writeProblem(response, http.StatusUnauthorized, "invalid_signature", err)
}
