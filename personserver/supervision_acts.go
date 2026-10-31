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
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
	"gitlab.com/sidecat-dev/aauth-go/supervision"
)

// SupervisionCompositionError identifies a request from a supervised Agent
// that this Person Server cannot put to a supervisor. It is available through
// diagnostics.Handler with errors.As; the wire response is 500 server_error
// with a public explanation. The Person Server does not fall back to its own
// policy for a supervised Agent.
type SupervisionCompositionError struct{ reason string }

// Reason returns r3 (an R3 authorization) or resource_interaction (a
// Resource-initiated interaction before consent).
func (e *SupervisionCompositionError) Reason() string {
	if e == nil {
		return ""
	}
	return e.reason
}

func (e *SupervisionCompositionError) Error() string {
	switch e.Reason() {
	case "r3":
		return "personserver: an R3 authorization is not put to a supervisor"
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
// supervisor. The supervisor sees the tokens and justification the Agent
// sent; an allow may narrow the scope to a subset of what the resource token
// requested, and bound exp.
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
	r3Context *verifiedR3,
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
	switch {
	case r3Context != nil:
		act.unsupported = &SupervisionCompositionError{reason: "r3"}
	case resourceToken.Interaction != nil && server.authorizationMode == authorizationModePersonServer:
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
