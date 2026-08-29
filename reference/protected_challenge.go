package reference

import (
	"errors"
	"net/http"
	"strings"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/budgets"
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/r3"
)

func (resource *Resource) challengeProtectedWithPersonToken(
	response http.ResponseWriter,
	request *http.Request,
	exactBody []byte,
	verified aauth.VerifiedRequest,
	personIssuerKey jose.JWK,
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
		if err := resource.validateBudgetOffer(selected); err != nil {
			writeProblem(response, http.StatusInternalServerError, "invalid_budget", errors.New("resource budget policy returned an invalid or undeclared offer"))
			return
		}
		offer = &selected
	}
	deferred := false
	if resource.deferredProtectedStore != nil {
		deferred, err = resource.deferredProtectedSelect(request.Context(), request)
		if err != nil {
			writeHostPolicyRefusal(response, "deferred_selection_denied", "resource could not select challenge delivery")
			return
		}
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
	var r3Reference r3.DocumentReference
	if resource.r3DocumentStore != nil {
		operation, operationErr := resource.r3OperationForRequest(request.Context(), request)
		if operationErr != nil || operation.Validate() != nil {
			writeProblem(response, http.StatusInternalServerError, "r3_operation_mapping_failed", errors.New("protected request does not map to one valid R3 operation"))
			return
		}
		if len(operation.Operations) != 1 {
			writeProblem(response, http.StatusInternalServerError, "r3_operation_mapping_failed", errors.New("protected request must map to exactly one R3 operation"))
			return
		}
		exact, documentErr := resource.r3DocumentForOperations(request.Context(), operation.Clone())
		if documentErr != nil {
			writeHostPolicyRefusal(response, "r3_operations_denied", "requested R3 operation is not available")
			return
		}
		r3Reference, err = selectR3Document(resource.identifier, operation, exact)
		if err != nil {
			writeProblem(response, http.StatusInternalServerError, "invalid_r3_document", err)
			return
		}
		readers := []string{resource.tokenAudience, person.Issuer}
		if resource.tokenAudience == person.Issuer {
			readers = readers[:1]
		}
		if err := resource.r3DocumentStore.RetainAuthorized(
			request.Context(), r3Reference.Digest(), r3Reference.ExactBytes(), readers, expiresAt,
		); err != nil {
			writeProblem(response, http.StatusServiceUnavailable, "r3_custody_unavailable", err)
			return
		}
	}
	claims := aauth.ResourceTokenClaims{
		Issuer: resource.identifier, DWK: aauth.ResourceDiscoveryDocument,
		Audience: resource.tokenAudience, JTI: resource.newID(), AgentJKT: thumbprint,
		IssuedAt: now.Unix(), ExpiresAt: expiresAt.Unix(), Scope: strings.Join(scopes, " "),
		PersonServer: person.Issuer, Subject: person.Subject, PresentedJTI: person.JTI,
		MissionS256: person.MissionS256, Tenant: person.Tenant,
	}
	var compact string
	if r3Reference.Valid() || offer != nil {
		compact, err = resource.mintAndRetainResourceToken(request.Context(), claims, r3Reference, offer, now)
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
	if deferred {
		resource.randomMu.Lock()
		pendingID, pendingErr := aauth.GeneratePendingID(resource.random)
		resource.randomMu.Unlock()
		if pendingErr != nil {
			writeProblem(response, http.StatusInternalServerError, "server_error", pendingErr)
			return
		}
		record := DeferredProtectedCallRecord{
			ID: pendingID, Resource: resource.identifier, ResourceToken: compact,
			RequestProofKey: verified.ReplayKey, Method: request.Method, Target: request.URL.RequestURI(),
			RequestProof: requestProof(request, verified), PersonIssuerKey: personIssuerKey,
			Body: append([]byte(nil), exactBody...), ContentType: request.Header.Get("Content-Type"),
			RequiredScopes: append([]string(nil), scopes...), ExpiresAt: expiresAt,
			State: DeferredProtectedPending,
		}
		if err := resource.deferredProtectedStore.Create(request.Context(), record); err != nil {
			writeProblem(response, http.StatusServiceUnavailable, "deferred_custody_unavailable", err)
			return
		}
		response.Header().Set("Location", "/deferred/"+pendingID)
		response.Header().Set("Retry-After", "0")
		writeJSON(response, http.StatusAccepted, map[string]string{"status": "pending"})
		return
	}
	writeProblem(response, http.StatusUnauthorized, "auth_token_required", errors.New("protected operation requires an auth token"))
}
