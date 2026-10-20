package agent

import (
	"errors"
	"net/http"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

// ReauthorizationRequiredError reports that a Resource refused an Auth token
// with revoked_jwt and requested a Person token. The caller may explicitly
// restart authorization with a valid Person token for that Resource. The
// client does not retry the request or exchange the revoked token.
//
// Unwrap preserves the Signature-Key error for errors.As.
type ReauthorizationRequiredError struct {
	Cause error
}

func (failure *ReauthorizationRequiredError) Error() string {
	return "aauth agent: revoked auth token requires reauthorization with a person token"
}

// Requirement returns the Resource's validated person-token requirement.
func (failure *ReauthorizationRequiredError) Requirement() aauth.Requirement {
	if failure == nil {
		return ""
	}
	return aauth.RequirementPersonToken
}

func (failure *ReauthorizationRequiredError) Unwrap() error {
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
		return &ReauthorizationRequiredError{Cause: failure}
	}
	return failure
}
