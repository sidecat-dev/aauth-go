package aauth

import "context"

// AuthorizationRequest is the verified input presented to deployment policy.
type AuthorizationRequest struct {
	Agent         string
	Resource      string
	Scope         []string
	Mission       *MissionReference
	Justification string
}

// AuthorizationDecision is the authority's granted identity and scope.
type AuthorizationDecision struct {
	Subject string
	Scope   []string
}

// AuthorizedRequest is supplied to a protected operation only after protocol
// proof and authorization checks have passed.
type AuthorizedRequest struct {
	Agent   string
	Subject string
	Scope   []string
	Mission *MissionReference
	Method  string
	Path    string
}

// MissionPolicy is intentionally caller-owned.
type MissionPolicy func(context.Context, MissionProposal) (MissionDecision, error)

// AuthorizationPolicy is intentionally caller-owned.
type AuthorizationPolicy func(context.Context, AuthorizationRequest) (AuthorizationDecision, error)
