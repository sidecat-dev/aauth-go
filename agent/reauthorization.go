package agent

import (
	"errors"
	"net/http"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

// PersonTokenRequiredError reports that a Resource refused an Auth token
// with revoked_jwt and requested a Person token. To satisfy the requirement,
// the caller obtains a Person token for that Resource and retries the original
// request with it. A Resource token naming the revoked Auth token cannot repair
// the failure and must not be used for an exchange.
//
// This error preserves the requirement; the client does not obtain a Person
// token or retry automatically. It does not implement the draft's separate
// re-authorization procedure for expiry or key rotation.
//
// Unwrap preserves the Signature-Key error for errors.As.
type PersonTokenRequiredError struct {
	Cause error
}

func (failure *PersonTokenRequiredError) Error() string {
	return "revoked_jwt: resource requires a person token"
}

// Requirement returns the Resource's validated person-token requirement.
func (failure *PersonTokenRequiredError) Requirement() aauth.Requirement {
	if failure == nil {
		return ""
	}
	return aauth.RequirementPersonToken
}

func (failure *PersonTokenRequiredError) Unwrap() error {
	if failure == nil {
		return nil
	}
	return failure.Cause
}

// authTokenResponseFailure is used only after presenting a verified Auth
// token. The same header cannot repair a revoked Agent or Person token.
func authTokenResponseFailure(response *http.Response) error {
	failure := responseFailure(response)
	var signatureFailure *signaturekey.Error
	if response.StatusCode == http.StatusUnauthorized &&
		errors.As(failure, &signatureFailure) && signatureFailure.Code == signaturekey.ErrorRevokedJWT &&
		aauth.ParsePersonTokenRequirement(response.Header.Values("AAuth-Requirement")) == nil {
		return &PersonTokenRequiredError{Cause: failure}
	}
	return failure
}
