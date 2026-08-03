package aauth

import "context"

// AuthorizationRequest is the verified input presented to deployment policy.
type AuthorizationRequest struct {
	Agent         string
	ParentAgent   string
	Resource      string
	Scope         []string
	R3            *R3Authorization
	Mission       *MissionReference
	Justification string
	Upstream      *AuthTokenClaims
}

// AuthorizationDecision is the authority's granted identity and scope.
type AuthorizationDecision struct {
	Subject       string
	Scope         []string
	R3Granted     *R3OperationSet
	R3Conditional *R3OperationSet
}

// AuthorizedRequest is supplied to a protected operation only after protocol
// proof and authorization checks have passed.
type AuthorizedRequest struct {
	Agent     string
	Subject   string
	Scope     []string
	Mission   *MissionReference
	Actor     *Actor
	AuthToken string
	Method    string
	Path      string
	Body      []byte
}

// MissionPolicy is intentionally caller-owned.
type MissionPolicy func(context.Context, MissionProposal) (MissionDecision, error)

// AuthorizationPolicy is intentionally caller-owned.
type AuthorizationPolicy func(context.Context, AuthorizationRequest) (AuthorizationDecision, error)
