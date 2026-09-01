package personserver

import (
	"errors"
	"net/http"
	"strings"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/r3"
)

func (server *Server) issueDirectR3AuthorizationToken(
	response http.ResponseWriter,
	request *http.Request,
	requestingAgent aauth.AgentTokenClaims,
	credentialAgent aauth.AgentTokenClaims,
	resourceToken aauth.ResourceTokenClaims,
	authorizationRequest AuthorizationRequest,
	verified *verifiedR3,
	missionRecord *MissionRecord,
) {
	if server == nil || server.r3 == nil || server.r3.authorizeDocument == nil || server.r3.issuances == nil ||
		verified == nil || verified.kind != r3.ArtifactDocument || len(verified.exactArtifact) == 0 {
		writeProblem(response, http.StatusInternalServerError, "server_error", errors.New("personserver: direct R3 issuance context is incomplete"))
		return
	}
	var missionR3Store MissionR3IssuanceStore
	if missionRecord != nil {
		var ok bool
		missionR3Store, ok = server.missions.(MissionR3IssuanceStore)
		if !ok {
			writeProblem(response, http.StatusInternalServerError, "server_error", errors.New("personserver: mission-bound direct R3 requires an atomic mission R3 issuance store"))
			return
		}
	}
	decision, err := server.r3.authorizeDocument(
		request.Context(), cloneAuthorizationRequest(authorizationRequest),
		verified.reference, verified.document,
	)
	if err != nil {
		writeAccessPolicyProblem(response, err)
		return
	}
	grantedScopes, err := validateDirectR3Decision(decision, authorizationRequest.Scopes)
	if err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", err)
		return
	}
	grantedBudget, err := validateBudgetDecision(authorizationRequest.Budget, decision.Budget)
	if err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", err)
		return
	}
	issuedAt := server.clock.Now().UTC()
	expiresAt := issuedAt.Add(decision.Lifetime)
	requestingAgentExpiresAt := time.Unix(requestingAgent.ExpiresAt, 0)
	if requestingAgentExpiresAt.Before(expiresAt) {
		expiresAt = requestingAgentExpiresAt
	}
	credentialAgentExpiresAt := time.Unix(credentialAgent.ExpiresAt, 0)
	if credentialAgentExpiresAt.Before(expiresAt) {
		expiresAt = credentialAgentExpiresAt
	}
	if missionRecord != nil && !missionRecord.ExpiresAt.IsZero() && missionRecord.ExpiresAt.Before(expiresAt) {
		expiresAt = missionRecord.ExpiresAt
	}
	if !expiresAt.After(issuedAt) {
		writeProblem(response, http.StatusInternalServerError, "server_error", errors.New("personserver: direct R3 decision has no usable lifetime"))
		return
	}
	claims := aauth.AuthTokenClaims{
		Issuer: server.issuer, DWK: aauth.PersonDiscoveryDocument,
		Audience: resourceToken.Issuer, JTI: server.newID(), PersonServer: server.issuer,
		Subject: resourceToken.Subject, Confirmation: aauth.Confirmation{JWK: credentialAgent.Confirmation.JWK},
		IssuedAt: issuedAt.Unix(), ExpiresAt: expiresAt.Unix(),
		Scope: strings.Join(grantedScopes, " "), Account: cloneAuthorizationAccount(resourceToken.Account),
		MissionS256: resourceToken.MissionS256, Tenant: resourceToken.Tenant,
	}
	var compact string
	if grantedBudget == nil {
		compact, err = r3.MintDirectAuthToken(
			server.r3.registry, server.signingKey, claims,
			verified.reference, verified.exactArtifact, decision.Grant,
		)
	} else {
		compact, err = r3.MintBudgetAuthToken(
			server.r3.registry, server.signingKey, claims,
			verified.reference, verified.exactArtifact, decision.Grant, *grantedBudget,
		)
	}
	if err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", err)
		return
	}
	issuedRecord, err := issuedAuthTokenRecord(compact, claims)
	if err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", err)
		return
	}
	issuance := r3.IssuanceRecord{
		AuthTokenReference: aauth.TokenReference{Issuer: claims.Issuer, JTI: claims.JTI},
		Resource:           claims.Audience, R3Reference: verified.reference,
		Vocabulary: verified.document.OperationSet().Vocabulary(),
		IssuedAt:   issuedAt, PersonServer: claims.PersonServer,
		Subject: claims.Subject, Account: cloneAuthorizationAccount(claims.Account),
		PresentedJTI: resourceToken.PresentedJTI, AgentJKT: resourceToken.AgentJKT,
		Agent: requestingAgent.Subject,
	}
	if missionRecord != nil {
		err = missionR3Store.CommitMissionR3AuthToken(request.Context(), *missionRecord, issuedAt, issuedRecord, issuance)
	} else if err = server.r3.issuances.Commit(request.Context(), issuance); err == nil {
		err = server.commitIssuedAuthToken(request.Context(), issuedRecord)
	}
	if err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", err)
		return
	}
	writePrivateJSON(response, http.StatusOK, struct {
		AuthToken string `json:"auth_token"`
		ExpiresIn int64  `json:"expires_in"`
	}{
		AuthToken: compact,
		ExpiresIn: claims.ExpiresAt - issuedAt.Unix(),
	})
}

func validateDirectR3Decision(decision DirectR3Decision, requested []string) ([]string, error) {
	if decision.Lifetime <= 0 || decision.Lifetime > time.Hour {
		return nil, errors.New("direct R3 authorization decision lifetime must be positive and at most one hour")
	}
	if len(decision.Scopes) == 0 {
		return nil, nil
	}
	granted, err := parseScopes(strings.Join(decision.Scopes, " "))
	if err != nil {
		return nil, errors.New("direct R3 authorization decision scope: " + err.Error())
	}
	if !scopeSubset(granted, requested) {
		return nil, errors.New("direct R3 authorization decision grants an unrequested scope")
	}
	return granted, nil
}

func directR3UnsupportedCombination(
	delegated bool,
	upstream *verifiedUpstreamToken,
) error {
	if delegated {
		return errors.New("personserver: direct R3 sub-agent authorization is not implemented")
	}
	if upstream != nil {
		return errors.New("personserver: direct R3 call chaining is not implemented")
	}
	return nil
}
