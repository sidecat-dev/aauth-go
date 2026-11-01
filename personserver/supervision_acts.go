package personserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/internal/httpapi"
	"gitlab.com/sidecat-dev/aauth-go/internal/revocation"
	"gitlab.com/sidecat-dev/aauth-go/r3"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
	"gitlab.com/sidecat-dev/aauth-go/supervision"
)

// SupervisionCompositionError identifies a request from a supervised Agent
// that this Person Server cannot put to a supervisor. It is available through
// diagnostics.Handler with errors.As; the wire response is 500 server_error
// with a public explanation. The Person Server does not fall back to its own
// policy for a supervised Agent.
type SupervisionCompositionError struct{ reason string }

// Reason returns resource_interaction (a Resource-initiated interaction
// before consent).
func (e *SupervisionCompositionError) Reason() string {
	if e == nil {
		return ""
	}
	return e.reason
}

func (e *SupervisionCompositionError) Error() string {
	switch e.Reason() {
	case "resource_interaction":
		return "personserver: a Resource-initiated interaction is not put to a supervisor"
	default:
		return "personserver: this request is not put to a supervisor"
	}
}

func writeSupervisionCompositionProblem(response http.ResponseWriter, err *SupervisionCompositionError) {
	response.Header().Set("Cache-Control", "no-store")
	httpapi.WriteProblem(response, http.StatusInternalServerError, "server_error", err, httpapi.ProblemFields{Detail: err.Error()})
}

// superviseAuthorization puts a verified auth-token request to the Agent's
// supervisor, an R3 one included. The supervisor sees the tokens and
// justification the Agent sent; an allow may narrow the scope to a subset of
// what the resource token requested, and bound exp.
func (server *Server) superviseAuthorization(
	response http.ResponseWriter,
	request *http.Request,
	agentToken string,
	agent aauth.AgentTokenClaims,
	proof signaturekey.VerifiedRequest,
	resourceTokenCompact, presentedTokenCompact, subagentToken string,
	rawJustification json.RawMessage,
	resourceToken aauth.ResourceTokenClaims,
	presented aauth.PresentedToken,
	credentialAgent aauth.AgentTokenClaims,
	upstream *verifiedUpstreamToken,
	missionRecord *MissionRecord,
	scopes []string,
) (*supervisionVerdict, bool) {
	justification, _ := parseOptionalRequestString("justification", rawJustification)
	act := supervisedAct{
		request: supervision.Request{
			Kind: supervision.KindAuthToken, MissionS256: resourceToken.MissionS256, AgentToken: agentToken,
			ResourceToken: resourceTokenCompact, PresentedToken: presentedTokenCompact,
			SubagentToken: subagentToken, Justification: justification,
		},
		agent: agent, proof: proof,
		expiresAt: []time.Time{
			time.Unix(credentialAgent.ExpiresAt, 0), time.Unix(resourceToken.ExpiresAt, 0), presented.ExpiresAt,
		},
		revocable: &revocableToken{
			reference: aauth.TokenReference{Issuer: resourceToken.Issuer, JTI: resourceToken.JTI},
			expiresAt: time.Unix(resourceToken.ExpiresAt, 0).UTC().Add(revocation.Skew),
		},
		validate: func(decision supervision.Decision) error {
			granted, err := supervision.ParseScope(decision.Scope)
			if err != nil || len(granted) > 0 && !scopeSubset(granted, scopes) {
				return errors.New("personserver: the supervisor allowed a scope the resource token did not request")
			}
			return nil
		},
	}
	if upstream != nil {
		act.request.UpstreamToken = upstream.compact
		act.expiresAt = append(act.expiresAt, upstream.expiresAt())
	}
	if missionRecord != nil {
		act.expiresAt = append(act.expiresAt, missionRecord.ExpiresAt)
	}
	if resourceToken.Interaction != nil && server.authorizationMode == authorizationModePersonServer {
		act.unsupported = &SupervisionCompositionError{reason: "resource_interaction"}
	}
	return server.supervise(response, request, act)
}

// supervisedAuthorization is the three-party authorization decision a
// supervisor's allow makes: the scope it narrowed to, or all that was
// requested, the Resource's Budget offer as offered, and the longest
// lifetime, which issuance then bounds by every token and by the
// supervisor's exp.
func supervisedAuthorization(verdict *supervisionVerdict) func(context.Context, AuthorizationRequest) (AuthorizationDecision, error) {
	return func(_ context.Context, request AuthorizationRequest) (AuthorizationDecision, error) {
		scopes := append([]string(nil), request.Scopes...)
		if verdict.decision.Scope != "" {
			narrowed, err := supervision.ParseScope(verdict.decision.Scope)
			if err != nil {
				return AuthorizationDecision{}, err
			}
			scopes = narrowed
		}
		return AuthorizationDecision{
			Scopes: scopes, Lifetime: aauth.MaximumAuthTokenLifetime, Budget: cloneBudgetValue(request.Budget),
		}, nil
	}
}

// supervisedR3Decision is the direct R3 decision a supervisor's allow makes:
// the act as the Resource described it, every operation of the document
// granted outright, with the Core scope, Budget and lifetime of
// supervisedAuthorization. Choosing which operations to hold back for
// per-call approval would be a decision of the Person Server's own.
func (server *Server) supervisedR3Decision(
	ctx context.Context,
	verdict *supervisionVerdict,
	request AuthorizationRequest,
	document r3.Document,
) (DirectR3Decision, error) {
	authorization, err := supervisedAuthorization(verdict)(ctx, request)
	if err != nil {
		return DirectR3Decision{}, err
	}
	operations := document.OperationSet()
	vocabulary, ok := server.r3.registry.Vocabulary(operations.Vocabulary())
	if !ok || len(operations.Operations()) == 0 {
		return DirectR3Decision{}, errors.New("personserver: the R3 document has no operations to grant")
	}
	granted, err := r3.NewGrantedOperations(vocabulary, operations.Operations()...)
	if err != nil {
		return DirectR3Decision{}, err
	}
	grant, err := r3.NewGrant(granted, document)
	if err != nil {
		return DirectR3Decision{}, err
	}
	return DirectR3Decision{
		Scopes: authorization.Scopes, Lifetime: authorization.Lifetime, Grant: grant, Budget: authorization.Budget,
	}, nil
}

// SupervisedR3Artifact fetches the R3 document or per-call proposal that the
// resource token of a supervised auth-token request names, verified against
// its r3_s256, so the host can present its display when the person decides
// after an ask or because the supervisor was unavailable. The supervisor
// itself cannot fetch it: a Resource serves R3 documents only to the Access
// Server and the Person Server. The host authenticates the person first.
func (server *Server) SupervisedR3Artifact(ctx context.Context, reference string) (r3.ReferencedArtifact, error) {
	if server.supervision == nil {
		return r3.ReferencedArtifact{}, errors.New("personserver: supervision is not configured")
	}
	if server.r3 == nil {
		return r3.ReferencedArtifact{}, errors.New("personserver: R3 is not configured")
	}
	record, err := server.supervision.store.LoadSupervisedRequest(ctx, reference)
	if err != nil {
		return r3.ReferencedArtifact{}, err
	}
	request, err := decodeSupervisionRequest(record)
	if err != nil {
		return r3.ReferencedArtifact{}, err
	}
	if record.Kind != supervision.KindAuthToken {
		return r3.ReferencedArtifact{}, errors.New("personserver: the supervised request is not an auth-token request")
	}
	// The resource token was verified when the Agent made the request.
	verifiedAt := record.AgentRequest.VerifiedAt
	resourceToken, verified, _, _, err := server.verifyResourceTokenForAuthorization(
		ctx, request.ResourceToken, aauth.ClockFunc(func() time.Time { return verifiedAt }),
	)
	if err != nil {
		return r3.ReferencedArtifact{}, err
	}
	if verified == nil {
		return r3.ReferencedArtifact{}, errors.New("personserver: the resource token names no R3 document")
	}
	if err := server.fetchR3Artifact(ctx, verified, resourceToken.Account); err != nil {
		return r3.ReferencedArtifact{}, err
	}
	return server.r3.registry.ParseReferencedArtifact(verified.reference, verified.exactArtifact)
}

// supervisedPermission is the permission decision a supervisor's verdict
// makes.
func supervisedPermission(verdict *supervisionVerdict) PermissionPolicyResult {
	if verdict.allowed() {
		return PermissionPolicyResult{Immediate: &PermissionDecision{Permission: aauth.PermissionGranted}}
	}
	return PermissionPolicyResult{Immediate: &PermissionDecision{Permission: aauth.PermissionDenied, Reason: verdict.decision.Reason}}
}

// supervisedMission is the mission approval a supervisor's or the person's
// allow makes. The supervisor refines; the Person Server builds.
func supervisedMission(verdict *supervisionVerdict) MissionDecision {
	terms := verdict.decision.Mission
	if terms == nil {
		return MissionDecision{}
	}
	decision := MissionDecision{
		Description:       terms.Description,
		ApprovedTools:     append([]aauth.MissionTool(nil), terms.ApprovedTools...),
		ApprovedResources: append([]string(nil), terms.ApprovedResources...),
	}
	if len(decision.ApprovedTools) == 0 {
		decision.ApprovedTools = nil
	}
	if len(decision.ApprovedResources) == 0 {
		decision.ApprovedResources = nil
	}
	if terms.ExpiresAt != nil {
		expiresAt := terms.ExpiresAt.UTC()
		decision.ExpiresAt = &expiresAt
	}
	return decision
}

// validateSupervisedMission checks a mission allow against the proposal it
// answers, as host approval is checked.
func validateSupervisedMission(proposal aauth.MissionProposal, now time.Time) func(supervision.Decision) error {
	return func(decision supervision.Decision) error {
		if decision.Mission == nil {
			return errors.New("personserver: the supervisor's allow carries no mission")
		}
		if err := validateMissionDecision(supervisedMission(&supervisionVerdict{decision: decision}), proposal, now); err != nil {
			return fmt.Errorf("personserver: the supervisor's mission: %w", err)
		}
		return nil
	}
}
