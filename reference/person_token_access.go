package reference

import (
	"errors"
	"net/http"

	aauth "gitlab.com/sidecat-dev/aauth-go"
)

func (resource *Resource) servePersonTokenProtected(
	response http.ResponseWriter,
	request *http.Request,
	exactBody []byte,
	verified aauth.VerifiedRequest,
) {
	person, err := verified.PersonClaims()
	if err != nil || aauth.ValidatePersonTokenContext(person, resource.identifier, verified.PublicKey) != nil {
		writeTokenVerificationFailure(response, http.StatusForbidden, "invalid_person_token", errors.New("person token does not apply to this resource"))
		return
	}
	scopes, err := resource.requiredScopes(request)
	if err != nil {
		writeProblem(response, http.StatusInternalServerError, "scope_mapping_failed", err)
		return
	}
	if !resource.consumeProof(response, request, verified) {
		return
	}
	authorized := aauth.AuthorizedRequest{
		PersonServer: person.Issuer, Subject: person.Subject, ConfirmationKey: verified.PublicKey,
		ProofReplayKey: verified.ReplayKey, ProofCreatedAt: verified.Created.UTC(),
		Scope: append([]string(nil), scopes...), MissionS256: person.MissionS256, Tenant: person.Tenant,
		Method: request.Method, Path: request.URL.Path,
		Target: request.URL.RequestURI(), Body: append([]byte(nil), exactBody...), ContentType: request.Header.Get("Content-Type"),
	}
	if err := resource.protectedAuthorizationPolicy(request.Context(), copyAuthorizedRequest(authorized)); err != nil {
		writeProblem(response, http.StatusForbidden, "person_access_denied", errors.New("person identity is not permitted for this operation"))
		return
	}
	result, err := resource.operation(request.Context(), authorized)
	if err != nil {
		writeProblem(response, http.StatusInternalServerError, "operation_failed", err)
		return
	}
	writeJSON(response, http.StatusOK, result)
}
