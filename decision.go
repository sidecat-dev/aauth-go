package aauth

import (
	"context"
	"time"
)

// AuthorizationRequest is the verified input presented to deployment policy.
type AuthorizationRequest struct {
	Agent         string
	ParentAgent   string
	PersonServer  string
	Subject       string
	Resource      string
	Scope         []string
	R3            *R3Authorization
	Mission       *MissionReference
	MissionS256   string
	Tenant        string
	Account       string
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
	Agent        string
	PersonServer string
	Subject      string
	Scope        []string
	Mission      *MissionReference
	MissionS256  string
	Tenant       string
	Account      string
	Actor        *Actor
	AuthToken    string
	Method       string
	Path         string
	Body         []byte
}

// PersonTokenRequest is the verified context a person server presents to its
// deployment-owned person binding policy before issuing a directed token.
type PersonTokenRequest struct {
	Agent          string
	Resource       string
	MissionS256    string
	Confirmation   JWK
	AgentExpiresAt time.Time
}

// PersonTokenDecision binds one agent key to one resource-directed person.
type PersonTokenDecision struct {
	Subject  string
	Tenant   string
	Lifetime time.Duration
}

// PersonTokenPolicy is intentionally caller-owned.
type PersonTokenPolicy func(context.Context, PersonTokenRequest) (PersonTokenDecision, error)

// MissionEvaluation is the authenticated current-profile input presented to
// deployment-owned mission policy. The identity fields come from the verified
// AgentToken and request proof, not from the proposal or ambient context.
type MissionEvaluation struct {
	Agent          string
	Proposal       MissionProposal
	Confirmation   JWK
	AgentExpiresAt time.Time
	PersonServer   string
}

// CurrentMissionPolicy decides a current-profile mission with its verified
// agent identity and person-server binding.
type CurrentMissionPolicy func(context.Context, MissionEvaluation) (MissionDecision, error)

// MissionPolicy is the caller-owned policy seam for the retained legacy
// mission profile. Current person-token servers use CurrentMissionPolicy.
type MissionPolicy func(context.Context, MissionProposal) (MissionDecision, error)

// AuthorizationPolicy is intentionally caller-owned.
type AuthorizationPolicy func(context.Context, AuthorizationRequest) (AuthorizationDecision, error)
