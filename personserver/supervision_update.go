package personserver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/budgets"
	"gitlab.com/sidecat-dev/aauth-go/internal/httpapi"
	"gitlab.com/sidecat-dev/aauth-go/internal/revocation"
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
	"gitlab.com/sidecat-dev/aauth-go/supervision"
)

// An Agent may answer a supervisor's clarification of an auth-token request
// with an updated request (Core, Agent Response to Clarification), and the
// Person Server relays it to the supervisor (Supervision, Clarification). The
// Person Server verifies the new pair before it relays it, keeps the Agent's
// signed updated_request, and completes the act with its tokens.

// supervisionUpdate is a verified updated_request a completion run issues
// against: its tokens, and the proof of the request that carried them.
type supervisionUpdate struct {
	resourceToken  string
	presentedToken string
	proof          signaturekey.VerifiedRequest
}

// verifySupervisedUpdate verifies the pair an updated_request carries, as the
// Person Server verifies it at its token endpoint and with the same errors,
// before the request is replaced. The new resource token must name the
// resource, Person Server, person, Agent key, mission and tenant of the one it
// replaces, and it and the presented token must last as long as the request
// may wait. It writes the refusal and reports false when the pair is refused.
// An accepted resource token is indexed to the Agent, as the original was.
func (server *Server) verifySupervisedUpdate(
	ctx context.Context,
	response http.ResponseWriter,
	record SupervisedRequest,
	proof signaturekey.VerifiedRequest,
	updated supervision.UpdatedRequest,
) bool {
	verificationClock := aauth.ClockFunc(func() time.Time { return proof.VerifiedAt() })
	resourceToken, r3Context, _, _, err := server.verifyResourceTokenForAuthorization(ctx, updated.ResourceToken, verificationClock)
	if err == nil {
		err = proof.CheckIssuedAt(time.Unix(resourceToken.IssuedAt, 0))
	}
	if err != nil {
		if server.refuseRevokedParameter(response, ctx, updated.ResourceToken, nil, err, "revoked_resource_token") {
			return false
		}
		if budgets.IsTokenClaimError(err) {
			writeProblem(response, http.StatusBadRequest, "invalid_budget", err)
		} else {
			writeEndpointTokenProblem(response, err, "invalid_resource_token", "expired_resource_token")
		}
		return false
	}
	resourceReference := aauth.TokenReference{Issuer: resourceToken.Issuer, JTI: resourceToken.JTI}
	if server.refuseRevokedParameter(response, ctx, updated.ResourceToken, &resourceReference, nil, "revoked_resource_token") {
		return false
	}
	if err := server.validateResourceTokenTopology(resourceToken); err != nil {
		writeProblem(response, http.StatusBadRequest, "invalid_resource_token", err)
		return false
	}
	if r3Context != nil || resourceToken.Interaction != nil && server.authorizationMode == authorizationModePersonServer {
		// The same requests this Person Server does not put to a supervisor.
		writeProblem(response, http.StatusBadRequest, "invalid_request",
			errors.New("personserver: a supervised request cannot be replaced by an R3 authorization or a Resource interaction"))
		return false
	}
	expiresAt := time.Unix(resourceToken.ExpiresAt, 0).UTC()
	if expiresAt.Sub(time.Unix(resourceToken.IssuedAt, 0).UTC()) > server.maximumResourceTokenLifetime {
		writeProblem(response, http.StatusBadRequest, "invalid_resource_token", errors.New("resource token exceeds the configured maximum lifetime"))
		return false
	}
	original, err := decodeSupervisionRequest(record)
	if err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", err)
		return false
	}
	// The replaced token was verified when the Agent made the request.
	replaced, err := unverifiedResourceClaims(original.ResourceToken)
	if err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", err)
		return false
	}
	if resourceToken.Issuer != replaced.Issuer || resourceToken.PersonServer != replaced.PersonServer ||
		resourceToken.Subject != replaced.Subject || resourceToken.AgentJKT != replaced.AgentJKT ||
		resourceToken.MissionS256 != replaced.MissionS256 || resourceToken.Tenant != replaced.Tenant {
		writeProblem(response, http.StatusBadRequest, "invalid_resource_token", errors.New("personserver: updated resource token does not match the pending request"))
		return false
	}
	presented, err := aauth.VerifyPresentedToken(ctx, updated.PresentedToken, resourceToken, server.keyResolver, verificationClock)
	if err == nil {
		err = proof.CheckIssuedAt(presentedTokenIssuedAt(presented))
	}
	if err != nil {
		if server.refuseRevokedParameter(response, ctx, updated.PresentedToken, nil, err, "revoked_presented_token") {
			return false
		}
		writePresentedTokenProblem(response, err)
		return false
	}
	presentedReference := aauth.TokenReference{Issuer: presented.Issuer, JTI: presented.JTI}
	if server.refuseRevokedParameter(response, ctx, updated.PresentedToken, &presentedReference, nil, "revoked_presented_token") {
		return false
	}
	if !UpdatedAuthorizationExpiriesCoverPending(record.ExpiresAt, expiresAt, presented.ExpiresAt) {
		writeProblem(response, http.StatusBadRequest, "invalid_resource_token", errors.New("personserver: updated tokens expire before the pending request"))
		return false
	}
	// The new resource token is indexed to the Agent as the one it replaces
	// was, so the Resource's revocation of it reaches the supervisor.
	if err := server.supervision.store.RecordTokenAgent(ctx, resourceReference, record.Agent, expiresAt.Add(revocation.Skew)); err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", err)
		return false
	}
	return true
}

func unverifiedResourceClaims(compact string) (aauth.ResourceTokenClaims, error) {
	parsed, err := jose.ParseCompact(compact)
	if err != nil {
		return aauth.ResourceTokenClaims{}, err
	}
	var claims aauth.ResourceTokenClaims
	if err := json.Unmarshal(parsed.Payload(), &claims); err != nil {
		return aauth.ResourceTokenClaims{}, err
	}
	return claims, nil
}

// retainedUpdate is the updated request a record's retained updated_request
// carries.
func retainedUpdate(retained SupervisedAgentRequest) (supervision.UpdatedRequest, error) {
	var body struct {
		Action         string `json:"action"`
		ResourceToken  string `json:"resource_token"`
		PresentedToken string `json:"presented_token"`
		Justification  string `json:"justification"`
	}
	if err := httpapi.DecodeJSON(bytes.NewReader(retained.Body), maxRequestBytes, &body); err != nil {
		return supervision.UpdatedRequest{}, err
	}
	if body.Action != "updated_request" || body.ResourceToken == "" || body.PresentedToken == "" {
		return supervision.UpdatedRequest{}, errors.New("personserver: retained updated_request is malformed")
	}
	return supervision.UpdatedRequest{
		ResourceToken: body.ResourceToken, PresentedToken: body.PresentedToken, Justification: body.Justification,
	}, nil
}

// currentSupervisionRequest is a supervised request as it now stands: the
// request put to the supervisor, with the tokens and justification of the
// Agent's updated_request in place. The person reviews it and an allow is
// checked against it.
func currentSupervisionRequest(record SupervisedRequest) (supervision.Request, error) {
	request, err := decodeSupervisionRequest(record)
	if err != nil || record.Update == nil {
		return request, err
	}
	updated, err := retainedUpdate(*record.Update)
	if err != nil {
		return supervision.Request{}, err
	}
	request.ResourceToken, request.PresentedToken = updated.ResourceToken, updated.PresentedToken
	request.Justification = updated.Justification
	return request, nil
}

// verifyRetainedUpdate verifies the Agent's retained updated_request again,
// as at the instant it was first verified, for a completion run.
func (server *Server) verifyRetainedUpdate(ctx context.Context, completion supervisionCompletion, record SupervisedRequest) (*supervisionUpdate, error) {
	completion.verifiedAt = record.Update.VerifiedAt
	request, err := retainedHTTPRequest(context.WithValue(ctx, supervisionCompletionKey{}, &completion), *record.Update)
	if err != nil {
		return nil, err
	}
	_, agent, proof, err := server.verifyAgentProof(request, []string{"content-type", "content-digest"})
	if err != nil {
		return nil, err
	}
	thumbprint, err := agent.Confirmation.JWK.Thumbprint()
	if err != nil || agent.Subject != record.Agent || agent.Issuer != record.AgentProvider || thumbprint != record.AgentJKT {
		return nil, errors.New("personserver: the updated request was not made by the supervised Agent")
	}
	updated, err := retainedUpdate(*record.Update)
	if err != nil {
		return nil, err
	}
	return &supervisionUpdate{resourceToken: updated.ResourceToken, presentedToken: updated.PresentedToken, proof: proof}, nil
}

// retainedHTTPRequest rebuilds a retained signed Agent request.
func retainedHTTPRequest(ctx context.Context, retained SupervisedAgentRequest) (*http.Request, error) {
	target := &url.URL{Scheme: "https", Host: retained.Host, Path: retained.Path}
	if unescaped, err := url.PathUnescape(retained.Path); err == nil {
		target.Path, target.RawPath = unescaped, retained.Path
	}
	request, err := http.NewRequestWithContext(ctx, retained.Method, target.String(), bytes.NewReader(retained.Body))
	if err != nil {
		return nil, err
	}
	request.Host = retained.Host
	request.Header = http.Header(retained.Header).Clone()
	return request, nil
}
