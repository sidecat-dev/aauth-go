package reference

import (
	"errors"
	"net/http"
	"strings"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/budgets"
	"gitlab.com/sidecat-dev/aauth-go/r3"
)

func (resource *Resource) challengeProtectedWithPersonToken(
	response http.ResponseWriter,
	request *http.Request,
	verified aauth.VerifiedRequest,
) {
	person, err := verified.PersonClaims()
	if err != nil || aauth.ValidatePersonTokenContext(person, resource.identifier, verified.PublicKey) != nil {
		writeTokenVerificationFailure(response, http.StatusForbidden, "invalid_person_token", errors.New("person token does not apply to this protected resource"))
		return
	}
	if resource.authTokenDiscoveryDocument == aauth.PersonDiscoveryDocument && person.Issuer != resource.tokenAudience {
		writeTokenVerificationFailure(response, http.StatusForbidden, "invalid_person_token", errors.New("person-token issuer does not match the configured person server"))
		return
	}
	if resource.r3DocumentStore != nil {
		writeProblem(response, http.StatusNotImplemented, "r3_challenge_not_implemented", errors.New("protected-call R3 challenge selection is not implemented"))
		return
	}
	scopes, err := resource.requiredScopes(request)
	if err != nil {
		writeProblem(response, http.StatusInternalServerError, "scope_mapping_failed", err)
		return
	}
	var offer *budgets.Budget
	if resource.budgetOffer != nil {
		selected, offerErr := resource.budgetOffer(request.Context(), nil)
		if offerErr != nil {
			writeHostPolicyRefusal(response, "invalid_budget", "resource budget policy denied the request")
			return
		}
		if selected.Validate() != nil {
			writeProblem(response, http.StatusInternalServerError, "invalid_budget", errors.New("resource budget policy returned an invalid offer"))
			return
		}
		offer = &selected
	}
	if !resource.consumeProof(response, request, verified) {
		return
	}
	thumbprint, err := verified.PublicKey.Thumbprint()
	if err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", err)
		return
	}
	now := verified.VerifiedAt.UTC()
	expiresAt := now.Add(5 * time.Minute)
	if personExpiry := time.Unix(person.ExpiresAt, 0).UTC(); personExpiry.Before(expiresAt) {
		expiresAt = personExpiry
	}
	claims := aauth.ResourceTokenClaims{
		Issuer: resource.identifier, DWK: aauth.ResourceDiscoveryDocument,
		Audience: resource.tokenAudience, JTI: resource.newID(), AgentJKT: thumbprint,
		IssuedAt: now.Unix(), ExpiresAt: expiresAt.Unix(), Scope: strings.Join(scopes, " "),
		PersonServer: person.Issuer, Subject: person.Subject, PresentedJTI: person.JTI,
		MissionS256: person.MissionS256, Tenant: person.Tenant,
	}
	var compact string
	if offer != nil {
		compact, err = resource.mintAndRetainResourceToken(request.Context(), claims, r3.DocumentReference{}, offer, now)
	} else {
		compact, err = aauth.MintResourceToken(resource.signingKey, claims)
	}
	if err != nil {
		writeProblem(response, http.StatusServiceUnavailable, "resource_token_unavailable", err)
		return
	}
	requirement, err := aauth.FormatRequirementHeader(aauth.Requirement{
		Type: aauth.RequirementAuthToken, ResourceToken: compact,
	})
	if err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", err)
		return
	}
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("AAuth-Requirement", requirement)
	writeProblem(response, http.StatusUnauthorized, "auth_token_required", errors.New("protected operation requires an auth token"))
}
