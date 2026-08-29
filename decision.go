package aauth

import (
	"context"
	"gitlab.com/sidecat-dev/aauth-go/jose"
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
	Mission       *MissionReference
	MissionS256   string
	Tenant        string
	Account       string
	Justification string
	Upstream      *AuthTokenClaims
}

// AuthorizationDecision is the authority's granted identity and scope.
type AuthorizationDecision struct {
	Subject string
	Scope   []string
}

// AuthorizedRequest is supplied to protected authorization policy and then a
// protected operation only after protocol proof, scope, and replay-admission
// checks have passed. In the current auth-token flow Agent is empty: the host
// resolves its local principal from the exact copy-safe ConfirmationKey while
// retaining PersonServer and Subject as the separately asserted person
// identity.
type AuthorizedRequest struct {
	Agent              string
	PersonServer       string
	Subject            string
	AuthTokenIssuer    string
	AuthTokenDWK       string
	AuthTokenID        string
	AuthTokenIssuedAt  time.Time
	AuthTokenExpiresAt time.Time
	ConfirmationKey    jose.JWK
	ProofReplayKey     string
	ProofCreatedAt     time.Time
	Scope              []string
	Mission            *MissionReference
	MissionS256        string
	Tenant             string
	Account            string
	Actor              *Actor
	AuthToken          string
	Method             string
	Path               string
	Target             string
	Body               []byte
	ContentType        string
}

// ProtectedAuthorizationPolicy applies deployment-owned authorization to one
// fully verified, replay-admitted current protected request.
type ProtectedAuthorizationPolicy func(context.Context, AuthorizedRequest) error

// PersonTokenRequest is the verified context a person server presents to its
// deployment-owned person binding policy before issuing a directed token.
type PersonTokenRequest struct {
	Agent                string
	ParentAgent          string
	Resource             string
	ResourcePresentation ResourcePresentation
	MissionS256          string
	Confirmation         jose.JWK
	AgentExpiresAt       time.Time
	Upstream             *AuthTokenClaims
}

// ResourcePresentation is the verified human-facing subset of one resource's
// metadata that a person server supplies to person-token interaction and
// policy. Description remains Markdown; a user interface sanitizes it before
// rendering.
type ResourcePresentation struct {
	Issuer      string
	Name        string
	Description string
	AccessMode  AccessMode
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
	Confirmation   jose.JWK
	AgentExpiresAt time.Time
	PersonServer   string
}

// CurrentMissionPolicy decides a current-profile mission with its verified
// agent identity and person-server binding.
type CurrentMissionPolicy func(context.Context, MissionEvaluation) (MissionDecision, error)

// AuthorizationPolicy is intentionally caller-owned.
type AuthorizationPolicy func(context.Context, AuthorizationRequest) (AuthorizationDecision, error)
