// Package personserver implements AAuth Person Server protocol handlers and
// host-facing policy and storage boundaries. Constructors select direct or
// federated authorization; optional focused configurations add only the
// protocol journeys an application uses. JOURNEYS.md identifies the supported
// compositions and their current limits.
package personserver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/budgets"
	"gitlab.com/sidecat-dev/aauth-go/internal/httpapi"
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/r3"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

const (
	maxRequestBytes       = 1 << 20
	maximumPersonLifetime = time.Hour
)

// DefaultMaximumResourceTokenLifetime is the retention and acceptance bound
// used when either public config leaves MaximumResourceTokenLifetime zero.
const DefaultMaximumResourceTokenLifetime = 5 * time.Minute

// ErrPersonTokenNotFound reports that no retained person-token record matches
// an issuer and token identifier.
var ErrPersonTokenNotFound = errors.New("personserver: person token not found")

// ErrAccessDenied distinguishes an intentional consent or authorization
// policy refusal from an operational callback failure. Policy callbacks wrap
// this error only when they mean to refuse an otherwise valid request.
var ErrAccessDenied = errors.New("personserver: access denied")

var errSubagentTokenSyntax = errors.New("personserver: subagent_token must be a non-empty compact token string")

// FederatedAuthorizationConfig supplies a four-party Person Server. It issues
// person tokens, retains their lineage, and federates auth-token requests to an
// Access Server.
type FederatedAuthorizationConfig struct {
	// Deferred enables host-driven AS approval and payment continuations.
	Deferred    *FederatedDeferredConfig
	Issuer      string
	SigningKey  jose.SigningKey
	KeyResolver signaturekey.KeyResolver
	Clock       aauth.Clock
	NewID       func() string
	HTTPClient  *http.Client
	// MaximumResourceTokenLifetime bounds resource tokens derived from a
	// retained person token. Zero selects DefaultMaximumResourceTokenLifetime.
	MaximumResourceTokenLifetime time.Duration
	AccessServerEndpoint         func(context.Context, string) (string, error)
	Tokens                       TokenStore
	BindPerson                   func(context.Context, PersonTokenRequest) (Person, error)
	// RequirePersonTokenInteraction optionally selects a host-authenticated
	// interaction before BindPerson. A required interaction uses the deferred
	// extension implemented by Tokens; with Missions, Tokens implements
	// MissionDeferredTokenStore.
	RequirePersonTokenInteraction func(context.Context, PersonTokenRequest) (PersonTokenInteractionPolicy, bool, error)
	Consent                       func(context.Context, AuthorizationRequest) error
	// Budget optionally validates the Resource offer and selects the ceiling
	// carried in the signed request to the Access Server.
	Budget *FederatedBudgetConfig
	// R3 optionally enables signed class-document and per-call proposal consent.
	R3 *R3Config
	// Missions enables mission approval and mission-bound Person and Auth-token
	// issuance. Tokens implements MissionStore and, when DeferProposal is set,
	// MissionProposalStore.
	Missions *MissionConfig
	// Permission optionally enables top-level permission decisions. With
	// Missions, Tokens supplies the MissionPermissionStore and Permission.Store
	// must be nil.
	Permission *PermissionConfig
	// Audit optionally enables mission-bound audit retention. Missions must be
	// configured and Tokens must implement MissionAuditStore.
	Audit *AuditConfig
	// InteractionQuestion optionally enables immediate or deferred,
	// missionless or mission-bound top-level questions.
	InteractionQuestion *InteractionQuestionConfig
	// InteractionRelay optionally relays missionless or mission-bound
	// interaction and payment requirements through a retained deferred response.
	InteractionRelay *InteractionRelayConfig
	// AgentTokenRevocations enables the Agent Provider's signed revocation
	// endpoint and checks retained revocations before any person policy runs.
	AgentTokenRevocations AgentTokenRevocationStore
	// AgentBindingRevocations enables host-invoked RevokeAgentBinding and
	// refuses issuance and pending delivery under a revoked binding.
	AgentBindingRevocations AgentBindingRevocationStore
}

// PSAuthorizationConfig supplies a three-party Person Server. It issues auth
// tokens itself, immediately or after host-authenticated consent, and therefore
// has no Access Server HTTP dependency.
type PSAuthorizationConfig struct {
	Issuer                        string
	SigningKey                    jose.SigningKey
	KeyResolver                   signaturekey.KeyResolver
	Clock                         aauth.Clock
	NewID                         func() string
	MaximumResourceTokenLifetime  time.Duration
	Tokens                        TokenStore
	BindPerson                    func(context.Context, PersonTokenRequest) (Person, error)
	RequirePersonTokenInteraction func(context.Context, PersonTokenRequest) (PersonTokenInteractionPolicy, bool, error)
	// Missions enables Agent-facing mission approval and mission-bound token
	// issuance. Tokens implements MissionStore and, when DeferProposal is set,
	// MissionProposalStore.
	Missions  *MissionConfig
	Authorize func(context.Context, AuthorizationRequest) (AuthorizationDecision, error)
	// Budget enables the direct fixed-price companion. The resolver must return
	// the Resource's trusted current budget_units metadata so the Person Server
	// independently checks the signed offer before policy.
	Budget *BudgetConfig
	// R3 optionally enables immediate direct class-document authorization and
	// exact issuance retention. Per-call proposals remain federated-only.
	R3 *DirectR3Config
	// CallChaining explicitly enables one immediate PS-authorized downstream
	// hop. Existing policies never receive an upstream authorization unless this
	// separate policy pair is configured. It requires an issued auth-token
	// store, which identifies the calling Agent of an upstream token.
	CallChaining *CallChainingConfig
	// IssuedTokens retains auth-token issuance records without enabling
	// revocation. When Revocation is configured its IssuedTokens store is used
	// and this field is ignored.
	IssuedTokens IssuedAuthTokenStore
	// RequireAuthorizationInteraction optionally selects host-authenticated
	// consent after the complete three-party request has been verified.
	RequireAuthorizationInteraction func(context.Context, AuthorizationRequest) (AuthorizationInteractionPolicy, bool, error)
	// AuthorizationInteractions durably retains the authorization-specific
	// pending request and its exact terminal result. With Missions, a nonnil
	// value supports only missionless deferred requests. Leave it nil and supply
	// DeferredAuthorizationStore plus MissionDeferredAuthorizationStore through
	// Tokens to enable both missionless and mission-bound requests atomically.
	AuthorizationInteractions DeferredAuthorizationStore
	// Revocation optionally retains issued auth-token routing and enables one
	// explicit Resource revocation attempt.
	Revocation *AuthTokenRevocationConfig
	// Permission optionally enables top-level permission decisions. With
	// Missions, Tokens supplies the MissionPermissionStore and Permission.Store
	// must be nil.
	Permission *PermissionConfig
	// Audit optionally enables mission-bound audit retention. Missions must be
	// configured and Tokens must implement MissionAuditStore.
	Audit *AuditConfig
	// InteractionQuestion optionally enables immediate or deferred,
	// missionless or mission-bound top-level questions.
	InteractionQuestion *InteractionQuestionConfig
	// InteractionRelay optionally relays missionless or mission-bound
	// interaction and payment requirements through a retained deferred response.
	InteractionRelay *InteractionRelayConfig
	// AgentTokenRevocations enables the Agent Provider's signed revocation
	// endpoint and checks retained revocations before any person policy runs.
	AgentTokenRevocations AgentTokenRevocationStore
	// AgentBindingRevocations enables host-invoked RevokeAgentBinding and
	// refuses issuance and pending delivery under a revoked binding.
	AgentBindingRevocations AgentBindingRevocationStore
}

// BudgetConfig supplies the Resource-metadata resolution required before a
// direct Person Server can accept a Budget offer.
type BudgetConfig struct {
	ResolveResourceUnits func(context.Context, string) ([]budgets.UnitDeclaration, error)
}

// FederatedBudgetConfig supplies the independent Resource-metadata lookup and
// Person Server ceiling decision for four-party Budget authorization. Ceiling
// runs after consent and receives an independent copy of the same verified
// policy input. It may return nil to omit the request member; the Access Server
// then uses the verified Resource offer as the Person Server ceiling.
type FederatedBudgetConfig struct {
	ResolveResourceUnits func(context.Context, string) ([]budgets.UnitDeclaration, error)
	Ceiling              func(context.Context, AuthorizationRequest) (*budgets.Value, error)
}

// CallChainingConfig maps a verified upstream person to a new directed person
// and applies the independent downstream authorization policy. It does not
// enable deferred interaction or Access Server federation.
type CallChainingConfig struct {
	BindPerson func(context.Context, PersonTokenRequest) (Person, error)
	Authorize  func(context.Context, AuthorizationRequest) (AuthorizationDecision, error)
}

// AuthorizationDecision is the scope and lifetime granted by one
// PS-authorization policy decision.
type AuthorizationDecision struct {
	Scopes   []string
	Lifetime time.Duration
	// Budget is required when AuthorizationRequest.Budget is present and must
	// be an amount-only narrowing of that Resource-selected offer. It must be
	// nil when the Resource token carried no Budget.
	Budget *budgets.Value
}

// PersonTokenRequest is the verified top-level Agent and requested Resource
// presented to person-binding policy. Subagent is nonempty only when the
// parent requested a credential for that verified one-level child.
type PersonTokenRequest struct {
	Agent                    string
	Subagent                 string
	Resource                 string
	AgentAdditionalClaims    map[string]json.RawMessage
	SubagentAdditionalClaims map[string]json.RawMessage
	// Mission is nonnil when the request names an active mission owned by the
	// verified Agent. It includes the exact approved content policy evaluates.
	Mission *MissionContext
	// Upstream is nonnil only for explicit call chaining. It is an independent
	// copy of the verified PS-issued auth-token claims.
	Upstream *aauth.AuthTokenClaims
}

// Person is the directed identity and lifetime selected by person-binding
// policy.
type Person struct {
	Subject  string
	Tenant   string
	Lifetime time.Duration
}

// AuthorizationRequest is the verified Core context presented to policy before
// direct auth-token issuance or an Access Server exchange. Agent is always the
// top-level requester whose grant is evaluated; Subagent names the credential
// recipient when the parent mediates.
type AuthorizationRequest struct {
	Agent        string
	Subagent     string
	Resource     string
	Subject      string
	Tenant       string
	Account      *string
	Scopes       []string
	Capabilities []string
	// Budget is the verified Resource-token offer. The callback receives an
	// independent copy and may return only an amount-narrowed value.
	Budget                   *budgets.Value
	AgentAdditionalClaims    map[string]json.RawMessage
	SubagentAdditionalClaims map[string]json.RawMessage
	// Mission is nonnil when the retained person-token lineage names an active
	// mission owned by the verified Agent.
	Mission *MissionContext
	// Upstream is nonnil only for explicit call chaining. It is an independent
	// copy of the same verified authorization bound at person-token issuance.
	Upstream *aauth.AuthTokenClaims
}

// PersonTokenRecord is the retained binding used to validate a later resource
// token's presented_jti. Agent is the credential recipient; ParentAgent is
// nonempty only for parent-mediated issuance.
type PersonTokenRecord struct {
	JTI           string
	PersonServer  string
	Resource      string
	Subject       string
	MissionS256   string
	Tenant        string
	AgentProvider string
	Agent         string
	ParentAgent   string
	Confirmation  jose.JWK
	ExpiresAt     time.Time
	RetainUntil   time.Time
	// UpstreamTokenReference and UpstreamTokenSHA256 bind a chained person
	// token to the exact PS-issued authorization presented at both Person
	// Server calls. Direct and parent-mediated records leave both zero.
	UpstreamTokenReference aauth.TokenReference
	UpstreamTokenSHA256    [32]byte
}

// TokenStore retains and resolves person-token bindings. Implementations must
// commit one issuer/JTI record atomically and round-trip every
// PersonTokenRecord field exactly.
type TokenStore interface {
	Commit(context.Context, PersonTokenRecord) error
	Load(context.Context, string, string) (PersonTokenRecord, error)
}

// Server is an AAuth Person Server.
type Server struct {
	issuer                           string
	signingKey                       jose.SigningKey
	keyResolver                      signaturekey.KeyResolver
	clock                            aauth.Clock
	newID                            func() string
	federatedDeferred                *FederatedDeferredConfig
	httpClient                       *http.Client
	maximumResourceTokenLifetime     time.Duration
	accessServerEndpoint             func(context.Context, string) (string, error)
	tokens                           TokenStore
	deferredTokens                   DeferredTokenStore
	missionDeferredTokens            MissionDeferredTokenStore
	bindPerson                       func(context.Context, PersonTokenRequest) (Person, error)
	requirePersonTokenInteraction    func(context.Context, PersonTokenRequest) (PersonTokenInteractionPolicy, bool, error)
	missions                         MissionStore
	missionProposals                 MissionProposalStore
	missionApprove                   func(context.Context, MissionApprovalRequest) (MissionDecision, error)
	missionDeferProposal             func(context.Context, MissionApprovalRequest) (MissionProposalPendingPolicy, bool, error)
	missionAcceptUpdate              func(context.Context, MissionUpdatePolicyRequest) error
	missionConfirmPersonCompletion   func(context.Context, MissionCompletionPolicyRequest) error
	consent                          func(context.Context, AuthorizationRequest) error
	r3                               *r3Config
	authorizationMode                authorizationMode
	authorize                        func(context.Context, AuthorizationRequest) (AuthorizationDecision, error)
	resolveBudgetResourceUnits       func(context.Context, string) ([]budgets.UnitDeclaration, error)
	federatedBudgetCeiling           func(context.Context, AuthorizationRequest) (*budgets.Value, error)
	bindChainedPerson                func(context.Context, PersonTokenRequest) (Person, error)
	authorizeChained                 func(context.Context, AuthorizationRequest) (AuthorizationDecision, error)
	requireAuthorizationInteraction  func(context.Context, AuthorizationRequest) (AuthorizationInteractionPolicy, bool, error)
	authorizationInteractions        DeferredAuthorizationStore
	missionAuthorizationInteractions MissionDeferredAuthorizationStore
	issuedAuthTokens                 IssuedAuthTokenStore
	revocationHTTPClient             *http.Client
	revocationAdmit                  signaturekey.EgressAdmitter
	permissionPolicy                 func(context.Context, PermissionPolicyRequest) (PermissionPolicyResult, error)
	permissions                      PermissionStore
	missionPermissions               MissionPermissionStore
	missionAudits                    MissionAuditStore
	interactionQuestionPolicy        func(context.Context, InteractionQuestionPolicyRequest) (InteractionQuestionPolicyResult, error)
	interactionQuestionStore         InteractionQuestionStore
	missionInteractionQuestions      MissionInteractionQuestionStore
	interactionRelayPolicy           func(context.Context, InteractionRelayPolicyRequest) (InteractionRelayPendingPolicy, error)
	interactionRelayStore            InteractionRelayStore
	missionInteractionRelays         MissionInteractionRelayStore
	agentTokenRevocations            AgentTokenRevocationStore
	agentBindingRevocations          AgentBindingRevocationStore
}

type authorizationMode uint8

const (
	authorizationModeFederated authorizationMode = iota + 1
	authorizationModePersonServer
)

type serverConfig struct {
	issuer                        string
	signingKey                    jose.SigningKey
	keyResolver                   signaturekey.KeyResolver
	clock                         aauth.Clock
	newID                         func() string
	maximumResourceTokenLifetime  time.Duration
	tokens                        TokenStore
	bindPerson                    func(context.Context, PersonTokenRequest) (Person, error)
	requirePersonTokenInteraction func(context.Context, PersonTokenRequest) (PersonTokenInteractionPolicy, bool, error)
	missions                      *MissionConfig
	permission                    *PermissionConfig
	audit                         *AuditConfig
	interactionQuestion           *InteractionQuestionConfig
	interactionRelay              *InteractionRelayConfig
	agentTokenRevocations         AgentTokenRevocationStore
	agentBindingRevocations       AgentBindingRevocationStore
}

// NewFederatedAuthorization constructs a four-party Person Server.
func NewFederatedAuthorization(config FederatedAuthorizationConfig) (*Server, error) {
	if err := validateFederatedDeferredConfig(config.Deferred); err != nil {
		return nil, err
	}
	if config.HTTPClient == nil {
		return nil, errors.New("personserver: HTTP client is required")
	}
	if config.AccessServerEndpoint == nil {
		return nil, errors.New("personserver: Access Server endpoint resolver is required")
	}
	if config.Consent == nil {
		return nil, errors.New("personserver: consent policy is required")
	}
	if config.Budget != nil {
		if config.Budget.ResolveResourceUnits == nil {
			return nil, errors.New("personserver: Budget Resource-unit resolver is required")
		}
		if config.Budget.Ceiling == nil {
			return nil, errors.New("personserver: federated Budget ceiling policy is required")
		}
	}
	server, err := newServer(serverConfig{
		issuer: config.Issuer, signingKey: config.SigningKey,
		keyResolver: config.KeyResolver, clock: config.Clock, newID: config.NewID,
		maximumResourceTokenLifetime: config.MaximumResourceTokenLifetime,
		tokens:                       config.Tokens, bindPerson: config.BindPerson,
		requirePersonTokenInteraction: config.RequirePersonTokenInteraction,
		missions:                      config.Missions,
		permission:                    config.Permission,
		audit:                         config.Audit,
		interactionQuestion:           config.InteractionQuestion,
		interactionRelay:              config.InteractionRelay,
		agentTokenRevocations:         config.AgentTokenRevocations,
		agentBindingRevocations:       config.AgentBindingRevocations,
	})
	if err != nil {
		return nil, err
	}
	httpClient := *config.HTTPClient
	httpClient.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	server.httpClient = &httpClient
	if config.Deferred != nil {
		v := *config.Deferred
		server.federatedDeferred = &v
	}
	server.accessServerEndpoint = config.AccessServerEndpoint
	server.consent = config.Consent
	if config.Budget != nil {
		server.resolveBudgetResourceUnits = config.Budget.ResolveResourceUnits
		server.federatedBudgetCeiling = config.Budget.Ceiling
	}
	r3Config, err := newR3Config(config.R3, config.HTTPClient, config.SigningKey, config.Issuer, config.Clock)
	if err != nil {
		return nil, err
	}
	server.r3 = r3Config
	server.authorizationMode = authorizationModeFederated
	return server, nil
}

// NewPSAuthorization constructs a three-party Person Server. Authorize supplies
// immediate Core authorization, R3 supplies immediate class authorization,
// and a paired interaction policy and store may supply the deferred Core path.
func NewPSAuthorization(config PSAuthorizationConfig) (*Server, error) {
	if config.RequireAuthorizationInteraction == nil && config.AuthorizationInteractions != nil {
		return nil, errors.New("personserver: authorization interaction store requires a policy")
	}
	if config.RequireAuthorizationInteraction != nil && config.Missions == nil && config.AuthorizationInteractions == nil {
		return nil, errors.New("personserver: authorization interaction policy and store must be configured together")
	}
	if config.R3 != nil && config.RequireAuthorizationInteraction != nil {
		return nil, errors.New("personserver: direct R3 does not compose with deferred Core authorization")
	}
	if config.Authorize == nil && config.R3 == nil && config.RequireAuthorizationInteraction == nil {
		return nil, errors.New("personserver: Core, R3, or deferred authorization policy is required")
	}
	if config.Budget != nil {
		if config.Authorize == nil && config.R3 == nil {
			return nil, errors.New("personserver: Budget requires a direct Core or R3 authorization policy")
		}
		if config.Budget.ResolveResourceUnits == nil {
			return nil, errors.New("personserver: Budget Resource-unit resolver is required")
		}
	}
	if config.CallChaining != nil &&
		(config.CallChaining.BindPerson == nil || config.CallChaining.Authorize == nil) {
		return nil, errors.New("personserver: call chaining requires person-binding and authorization policies")
	}
	if config.CallChaining != nil && config.Revocation == nil && config.IssuedTokens == nil {
		return nil, errors.New("personserver: call chaining requires an issued auth-token store")
	}
	server, err := newServer(serverConfig{
		issuer: config.Issuer, signingKey: config.SigningKey,
		keyResolver: config.KeyResolver, clock: config.Clock, newID: config.NewID,
		maximumResourceTokenLifetime: config.MaximumResourceTokenLifetime,
		tokens:                       config.Tokens, bindPerson: config.BindPerson,
		requirePersonTokenInteraction: config.RequirePersonTokenInteraction,
		missions:                      config.Missions,
		permission:                    config.Permission,
		audit:                         config.Audit,
		interactionQuestion:           config.InteractionQuestion,
		interactionRelay:              config.InteractionRelay,
		agentTokenRevocations:         config.AgentTokenRevocations,
		agentBindingRevocations:       config.AgentBindingRevocations,
	})
	if err != nil {
		return nil, err
	}
	server.authorizationMode = authorizationModePersonServer
	server.authorize = config.Authorize
	if config.Budget != nil {
		server.resolveBudgetResourceUnits = config.Budget.ResolveResourceUnits
	}
	r3Config, err := newDirectR3Config(config.R3, config.SigningKey, config.Issuer, config.Clock)
	if err != nil {
		return nil, err
	}
	server.r3 = r3Config
	if config.CallChaining != nil {
		server.bindChainedPerson = config.CallChaining.BindPerson
		server.authorizeChained = config.CallChaining.Authorize
	}
	server.requireAuthorizationInteraction = config.RequireAuthorizationInteraction
	if config.RequireAuthorizationInteraction != nil && config.Missions != nil && config.AuthorizationInteractions == nil {
		missionInteractions, ok := config.Tokens.(interface {
			DeferredAuthorizationStore
			MissionDeferredAuthorizationStore
		})
		if !ok {
			return nil, errors.New("personserver: missions with authorization interaction require Tokens to implement DeferredAuthorizationStore and MissionDeferredAuthorizationStore")
		}
		server.missionAuthorizationInteractions = missionInteractions
		server.authorizationInteractions = missionInteractions
	} else {
		server.authorizationInteractions = config.AuthorizationInteractions
	}
	if err := server.configureAuthTokenRevocation(config.Revocation); err != nil {
		return nil, err
	}
	if config.Revocation == nil {
		server.issuedAuthTokens = config.IssuedTokens
	}
	return server, nil
}

func newServer(config serverConfig) (*Server, error) {
	if config.permission != nil {
		if config.permission.Policy == nil {
			return nil, errors.New("personserver: permission policy is required")
		}
		if config.missions == nil && config.permission.Store == nil {
			return nil, errors.New("personserver: missionless permission store is required")
		}
		if config.missions != nil && config.permission.Store != nil {
			return nil, errors.New("personserver: mission permission store must be supplied through Tokens")
		}
	}
	if config.audit != nil && config.missions == nil {
		return nil, errors.New("personserver: audit requires missions")
	}
	if config.interactionQuestion != nil && config.interactionQuestion.Policy == nil {
		return nil, errors.New("personserver: interaction question policy is required")
	}
	if config.interactionQuestion != nil && config.missions != nil && config.interactionQuestion.Store != nil {
		return nil, errors.New("personserver: mission interaction question store must be supplied through Tokens")
	}
	if config.interactionRelay != nil {
		if config.interactionRelay.Policy == nil {
			return nil, errors.New("personserver: interaction relay policy is required")
		}
		if config.missions == nil && config.interactionRelay.Store == nil {
			return nil, errors.New("personserver: missionless interaction relay store is required")
		}
		if config.missions != nil && config.interactionRelay.Store != nil {
			return nil, errors.New("personserver: mission interaction relay store must be supplied through Tokens")
		}
	}
	if err := aauth.ValidateServerIdentifier(config.issuer); err != nil {
		return nil, fmt.Errorf("personserver: issuer: %w", err)
	}
	if _, err := config.signingKey.PublicJWK().PublicKey(); err != nil {
		return nil, fmt.Errorf("personserver: signing key: %w", err)
	}
	if config.keyResolver == nil {
		return nil, errors.New("personserver: key resolver is required")
	}
	if config.clock == nil {
		return nil, errors.New("personserver: clock is required")
	}
	if config.newID == nil {
		return nil, errors.New("personserver: token ID source is required")
	}
	if config.tokens == nil {
		return nil, errors.New("personserver: token store is required")
	}
	if config.bindPerson == nil {
		return nil, errors.New("personserver: person-binding policy is required")
	}
	var missions MissionStore
	var missionProposals MissionProposalStore
	var missionApprove func(context.Context, MissionApprovalRequest) (MissionDecision, error)
	var missionDeferProposal func(context.Context, MissionApprovalRequest) (MissionProposalPendingPolicy, bool, error)
	var missionAcceptUpdate func(context.Context, MissionUpdatePolicyRequest) error
	var missionConfirmPersonCompletion func(context.Context, MissionCompletionPolicyRequest) error
	var missionAudits MissionAuditStore
	var missionPermissions MissionPermissionStore
	var permissions PermissionStore
	var missionInteractionRelays MissionInteractionRelayStore
	var interactionRelayRecords InteractionRelayStore
	var missionInteractionQuestions MissionInteractionQuestionStore
	var interactionQuestionRecords InteractionQuestionStore
	if config.missions != nil {
		if config.missions.Approve == nil && config.missions.DeferProposal == nil {
			return nil, errors.New("personserver: mission approval policy is required")
		}
		var ok bool
		missions, ok = config.tokens.(MissionStore)
		if !ok {
			return nil, errors.New("personserver: missions require a mission store")
		}
		missionApprove = config.missions.Approve
		missionDeferProposal = config.missions.DeferProposal
		missionAcceptUpdate = config.missions.AcceptUpdate
		missionConfirmPersonCompletion = config.missions.ConfirmPersonAcceptedCompletion
		if missionDeferProposal != nil {
			missionProposals, ok = config.tokens.(MissionProposalStore)
			if !ok {
				return nil, errors.New("personserver: deferred mission proposals require Tokens to implement MissionProposalStore")
			}
		}
		if config.audit != nil {
			missionAudits, ok = config.tokens.(MissionAuditStore)
			if !ok {
				return nil, errors.New("personserver: audit requires Tokens to implement MissionAuditStore")
			}
		}
		if config.permission != nil {
			missionPermissions, ok = config.tokens.(MissionPermissionStore)
			if !ok {
				return nil, errors.New("personserver: missions with permission require Tokens to implement MissionPermissionStore")
			}
			permissions = missionPermissions
		}
		if config.interactionRelay != nil {
			missionInteractionRelays, ok = config.tokens.(MissionInteractionRelayStore)
			if !ok {
				return nil, errors.New("personserver: missions with interaction relay require Tokens to implement MissionInteractionRelayStore")
			}
			interactionRelayRecords = missionInteractionRelays
		}
		if config.interactionQuestion != nil {
			missionInteractionQuestions, ok = config.tokens.(MissionInteractionQuestionStore)
			if !ok {
				return nil, errors.New("personserver: missions with interaction questions require Tokens to implement MissionInteractionQuestionStore")
			}
			interactionQuestionRecords = missionInteractionQuestions
		}
	}
	if config.permission != nil && config.missions == nil {
		permissions = config.permission.Store
	}
	if config.interactionRelay != nil && config.missions == nil {
		interactionRelayRecords = config.interactionRelay.Store
	}
	if config.interactionQuestion != nil && config.missions == nil {
		interactionQuestionRecords = config.interactionQuestion.Store
	}
	var deferredTokens DeferredTokenStore
	var missionDeferredTokens MissionDeferredTokenStore
	if config.requirePersonTokenInteraction != nil {
		var ok bool
		deferredTokens, ok = config.tokens.(DeferredTokenStore)
		if !ok {
			return nil, errors.New("personserver: person-token interaction requires a deferred token store")
		}
		if config.missions != nil {
			missionDeferredTokens, ok = config.tokens.(MissionDeferredTokenStore)
			if !ok {
				return nil, errors.New("personserver: missions with person-token interaction require Tokens to implement MissionDeferredTokenStore")
			}
			deferredTokens = missionDeferredTokens
		}
	}
	maximumResourceTokenLifetime := config.maximumResourceTokenLifetime
	if maximumResourceTokenLifetime == 0 {
		maximumResourceTokenLifetime = DefaultMaximumResourceTokenLifetime
	}
	if maximumResourceTokenLifetime < 0 {
		return nil, errors.New("personserver: maximum resource-token lifetime must be positive")
	}
	return &Server{
		issuer: config.issuer, signingKey: config.signingKey,
		keyResolver: config.keyResolver, clock: config.clock, newID: config.newID,
		maximumResourceTokenLifetime: maximumResourceTokenLifetime,
		tokens:                       config.tokens, deferredTokens: deferredTokens,
		missionDeferredTokens: missionDeferredTokens, bindPerson: config.bindPerson,
		requirePersonTokenInteraction: config.requirePersonTokenInteraction,
		missions:                      missions, missionProposals: missionProposals,
		missionApprove: missionApprove, missionDeferProposal: missionDeferProposal,
		missionAcceptUpdate: missionAcceptUpdate, missionConfirmPersonCompletion: missionConfirmPersonCompletion,
		missionAudits:               missionAudits,
		permissionPolicy:            permissionPolicy(config.permission),
		permissions:                 permissions,
		missionPermissions:          missionPermissions,
		interactionQuestionPolicy:   interactionQuestionPolicy(config.interactionQuestion),
		interactionQuestionStore:    interactionQuestionRecords,
		missionInteractionQuestions: missionInteractionQuestions,
		interactionRelayPolicy:      interactionRelayPolicy(config.interactionRelay),
		interactionRelayStore:       interactionRelayRecords,
		missionInteractionRelays:    missionInteractionRelays,
		agentTokenRevocations:       config.agentTokenRevocations,
		agentBindingRevocations:     config.agentBindingRevocations,
	}, nil
}

// Handler serves immediate and interactive person-token issuance, the Person
// Server auth-token exchange, and the configured immediate mission lifecycle.
func (server *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /person", server.handlePerson)
	mux.HandleFunc("GET /person/pending/{id}", server.handlePendingPersonToken)
	mux.HandleFunc("POST /token", server.handleToken)
	if server.federatedDeferred != nil {
		mux.HandleFunc("GET /token/federated/{id}", server.handleFederatedPending)
		mux.HandleFunc("DELETE /token/federated/{id}", server.handleFederatedCancellation)
	}
	mux.HandleFunc("/token/pending/{id}", server.handlePendingAuthorization)
	mux.HandleFunc("GET /.well-known/aauth-person.json", server.handleMetadata)
	mux.HandleFunc("GET /.well-known/jwks.json", server.handleJWKS)
	if server.missions != nil {
		mux.HandleFunc("POST /mission", server.handleMission)
		mux.HandleFunc("POST /mission/{s256}", server.handleMissionAction)
	}
	if server.missionProposals != nil {
		mux.HandleFunc("GET /mission/pending/{id}", server.handlePendingMissionProposal)
	}
	if server.permissions != nil {
		mux.HandleFunc("POST /permission", server.handlePermission)
		mux.HandleFunc("GET /permission/pending/{id}", server.handlePendingPermission)
	}
	if server.missionAudits != nil {
		mux.HandleFunc("POST /audit", server.handleAudit)
	}
	if server.interactionQuestionPolicy != nil || server.interactionRelayPolicy != nil {
		mux.HandleFunc("POST /interaction", server.handleInteraction)
	}
	if server.interactionQuestionStore != nil {
		mux.HandleFunc("GET /interaction/pending/{id}", server.handlePendingInteractionQuestion)
	}
	if server.interactionRelayStore != nil {
		mux.HandleFunc("GET /interaction/relay/{id}", server.handlePendingInteractionRelay)
	}
	if server.agentTokenRevocations != nil {
		mux.HandleFunc("POST /revoke", server.handleAgentTokenRevocation)
	}
	return mux
}

func (server *Server) handlePerson(response http.ResponseWriter, request *http.Request) {
	agentToken, agent, proof, err := server.verifyAgentProof(request, []string{"content-type", "content-digest"})
	_ = agentToken
	if err != nil {
		writeAgentTokenProblem(response, err)
		return
	}
	var input struct {
		Resource      string          `json:"resource"`
		MissionS256   json.RawMessage `json:"mission_s256"`
		SubagentToken json.RawMessage `json:"subagent_token"`
		UpstreamToken json.RawMessage `json:"upstream_token"`
		Justification json.RawMessage `json:"justification"`
		LoginHint     json.RawMessage `json:"login_hint"`
		Tenant        json.RawMessage `json:"tenant"`
		DomainHint    json.RawMessage `json:"domain_hint"`
		Prompt        json.RawMessage `json:"prompt"`
		Platform      json.RawMessage `json:"platform"`
		Device        json.RawMessage `json:"device"`
		Capabilities  json.RawMessage `json:"capabilities"`
	}
	if err := decodeJSON(request.Body, &input); err != nil {
		writeProblem(response, http.StatusBadRequest, "invalid_request", err)
		return
	}
	if input.UpstreamToken == nil {
		if err := server.validateDirectAgentTopology(agent); err != nil {
			writeAgentTokenProblem(response, err)
			return
		}
	}
	if err := rejectUnsupportedRequestMembers(map[string]json.RawMessage{
		"justification": input.Justification, "login_hint": input.LoginHint,
		"tenant": input.Tenant, "domain_hint": input.DomainHint, "prompt": input.Prompt,
		"platform": input.Platform, "device": input.Device, "capabilities": input.Capabilities,
	}); err != nil {
		writeProblem(response, http.StatusBadRequest, "invalid_request", err)
		return
	}
	if err := aauth.ValidateServerIdentifier(input.Resource); err != nil {
		writeProblem(response, http.StatusBadRequest, "invalid_request", err)
		return
	}
	var missionRecord *MissionRecord
	var missionContext *MissionContext
	if input.MissionS256 != nil {
		if input.SubagentToken != nil || input.UpstreamToken != nil {
			writeProblem(response, http.StatusBadRequest, "invalid_request", errors.New("personserver: mission-bound delegated or call-chain person-token issuance is not implemented"))
			return
		}
		var s256 string
		if err := json.Unmarshal(input.MissionS256, &s256); err != nil || aauth.ValidateMissionS256(s256) != nil {
			writeProblem(response, http.StatusBadRequest, "invalid_request", errors.New("personserver: mission_s256 is invalid"))
			return
		}
		loaded, err := server.loadActiveMission(request.Context(), s256, agent.Subject, server.clock.Now().UTC())
		if err != nil {
			writeMissionReferenceProblem(response, err)
			return
		}
		missionRecord = &loaded
		missionContext, err = missionContextFromRecord(loaded)
		if err != nil {
			writeProblem(response, http.StatusInternalServerError, "server_error", err)
			return
		}
	}
	upstream, err := server.verifyOptionalUpstreamToken(
		request.Context(), input.UpstreamToken, agent, proof,
	)
	if err != nil {
		server.writeUpstreamTokenProblem(response, err)
		return
	}
	credentialAgent := agent
	delegated := false
	if upstream != nil && input.SubagentToken != nil {
		server.writeUpstreamTokenProblem(response, &unsupportedCallChainError{
			cause: errors.New("personserver: sub-agent and call-chain authorization cannot be combined"),
		})
		return
	}
	if upstream == nil {
		_, credentialAgent, delegated, err = server.verifyOptionalSubagentToken(
			request.Context(), input.SubagentToken, agent, proof,
		)
		if err != nil {
			server.writeSubagentTokenProblem(response, err)
			return
		}
	}
	if upstream == nil {
		// The signing Agent's binding authorizes it and every child it mediates.
		if err := server.checkAgentBinding(request.Context(), agentBinding(agent)); err != nil {
			writeAgentBindingProblem(response, err, http.StatusForbidden, "person_token_denied")
			return
		}
	}
	personRequest := PersonTokenRequest{
		Agent: agent.Subject, Resource: input.Resource,
		AgentAdditionalClaims: cloneClaims(agent.AdditionalClaims),
		Mission:               missionContext,
	}
	if delegated {
		personRequest.Subagent = credentialAgent.Subject
		personRequest.SubagentAdditionalClaims = cloneClaims(credentialAgent.AdditionalClaims)
	}
	if upstream != nil {
		personRequest.Upstream = upstream.policyClaims()
	}
	if upstream == nil && server.requirePersonTokenInteraction != nil {
		policyRequest := clonePersonTokenRequest(personRequest)
		policy, required, err := server.requirePersonTokenInteraction(request.Context(), policyRequest)
		if err != nil {
			writeProblem(response, http.StatusInternalServerError, "server_error", err)
			return
		}
		if required {
			if err := server.beginPersonTokenInteraction(
				response, request, personRequest, agent, credentialAgent, policy, missionRecord,
			); err != nil {
				writeProblem(response, http.StatusInternalServerError, "server_error", err)
			}
			return
		}
	}
	bindPerson := server.bindPerson
	if upstream != nil {
		bindPerson = server.bindChainedPerson
	}
	person, err := bindPerson(request.Context(), clonePersonTokenRequest(personRequest))
	if err != nil {
		writeProblem(response, http.StatusForbidden, "person_token_denied", err)
		return
	}
	if upstream != nil && person.Subject == upstream.claims.Subject {
		writeProblem(response, http.StatusInternalServerError, "server_error", errors.New("personserver: downstream directed subject must differ from upstream subject"))
		return
	}
	issuedAt := proof.VerifiedAt()
	if missionRecord != nil {
		issuedAt = server.clock.Now().UTC()
		current, err := server.recheckActiveMission(request.Context(), *missionRecord, issuedAt)
		if err != nil {
			writeMissionReferenceProblem(response, err)
			return
		}
		missionRecord = &current
	}
	compact, record, err := server.preparePersonToken(
		issuedAt, agent, credentialAgent, personRequest, person, missionRecord, upstream,
	)
	if err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", err)
		return
	}
	if missionRecord != nil {
		commitAt := server.clock.Now().UTC()
		if err := server.missions.CommitMissionPersonToken(
			request.Context(), *missionRecord, commitAt, record,
		); err != nil {
			writeMissionReferenceProblem(response, err)
			return
		}
	} else {
		if err := server.tokens.Commit(request.Context(), record); err != nil {
			writeProblem(response, http.StatusInternalServerError, "server_error", err)
			return
		}
	}
	writePrivateJSON(response, http.StatusOK, struct {
		PersonToken string `json:"person_token"`
		ExpiresIn   int64  `json:"expires_in"`
	}{PersonToken: compact, ExpiresIn: record.ExpiresAt.Unix() - issuedAt.Unix()})
}

func (server *Server) handleToken(response http.ResponseWriter, request *http.Request) {
	agentToken, agent, proof, err := server.verifyAgentProof(request, []string{"content-type", "content-digest"})
	if err != nil {
		writeAgentTokenProblem(response, err)
		return
	}
	var input struct {
		ResourceToken  string          `json:"resource_token"`
		PresentedToken string          `json:"presented_token"`
		UpstreamToken  json.RawMessage `json:"upstream_token"`
		SubagentToken  json.RawMessage `json:"subagent_token"`
		Justification  json.RawMessage `json:"justification"`
		LoginHint      json.RawMessage `json:"login_hint"`
		Tenant         json.RawMessage `json:"tenant"`
		DomainHint     json.RawMessage `json:"domain_hint"`
		Prompt         json.RawMessage `json:"prompt"`
		Platform       json.RawMessage `json:"platform"`
		Device         json.RawMessage `json:"device"`
		Capabilities   json.RawMessage `json:"capabilities"`
	}
	if err := decodeJSON(request.Body, &input); err != nil || input.ResourceToken == "" {
		writeProblem(response, http.StatusBadRequest, "invalid_request", err)
		return
	}
	if input.PresentedToken == "" {
		writeProblem(response, http.StatusBadRequest, "invalid_request", errors.New("personserver: presented_token is required"))
		return
	}
	if input.UpstreamToken == nil {
		if err := server.validateDirectAgentTopology(agent); err != nil {
			writeAgentTokenProblem(response, err)
			return
		}
	}
	unsupportedCapabilities := input.Capabilities
	supportsCapabilities := server.authorizationMode == authorizationModePersonServer ||
		server.federatedBudgetCeiling != nil
	if supportsCapabilities {
		unsupportedCapabilities = nil
	}
	if err := rejectUnsupportedRequestMembers(map[string]json.RawMessage{
		"justification": input.Justification, "login_hint": input.LoginHint,
		"tenant": input.Tenant, "domain_hint": input.DomainHint, "prompt": input.Prompt,
		"platform": input.Platform, "device": input.Device, "capabilities": unsupportedCapabilities,
	}); err != nil {
		writeProblem(response, http.StatusBadRequest, "invalid_request", err)
		return
	}
	var capabilities []string
	if supportsCapabilities {
		capabilities, err = parseAuthorizationCapabilities(input.Capabilities)
		if err != nil {
			writeProblem(response, http.StatusBadRequest, "invalid_request", err)
			return
		}
		if server.authorizationMode == authorizationModeFederated {
			for _, capability := range capabilities {
				if capability != "budget" {
					writeProblem(response, http.StatusBadRequest, "invalid_request", fmt.Errorf("personserver: federated Budget does not support capability %q", capability))
					return
				}
			}
		}
	}
	upstream, err := server.verifyOptionalUpstreamToken(
		request.Context(), input.UpstreamToken, agent, proof,
	)
	if err != nil {
		server.writeUpstreamTokenProblem(response, err)
		return
	}
	credentialAgent := agent
	delegated := false
	subagentToken := ""
	if upstream != nil && input.SubagentToken != nil {
		server.writeUpstreamTokenProblem(response, &unsupportedCallChainError{
			cause: errors.New("personserver: sub-agent and call-chain authorization cannot be combined"),
		})
		return
	}
	if upstream == nil {
		subagentToken, credentialAgent, delegated, err = server.verifyOptionalSubagentToken(
			request.Context(), input.SubagentToken, agent, proof,
		)
		if err != nil {
			server.writeSubagentTokenProblem(response, err)
			return
		}
	}
	verificationClock := aauth.ClockFunc(func() time.Time { return proof.VerifiedAt() })
	resourceToken, r3Context, budgetOffer, err := server.verifyResourceTokenForAuthorization(
		request.Context(), input.ResourceToken, verificationClock,
	)
	if err == nil {
		err = proof.CheckIssuedAt(time.Unix(resourceToken.IssuedAt, 0))
	}
	if err != nil {
		if budgets.IsTokenClaimError(err) {
			writeProblem(response, http.StatusBadRequest, "invalid_budget", err)
		} else {
			writeEndpointTokenProblem(response, err, "invalid_resource_token", "expired_resource_token")
		}
		return
	}
	if upstream != nil && resourceToken.Audience != server.issuer {
		server.writeUpstreamTokenProblem(response, &unsupportedCallChainError{
			cause: errors.New("personserver: Access Server call chaining is not implemented"),
		})
		return
	}
	if err := server.validateResourceTokenTopology(resourceToken); err != nil {
		writeProblem(response, http.StatusBadRequest, "invalid_resource_token", err)
		return
	}
	if resourceToken.Interaction != nil {
		writeProblem(response, http.StatusBadRequest, "invalid_resource_token", errors.New("resource-token interaction requires the deferred flow"))
		return
	}
	if resourceToken.MissionS256 != "" && (input.SubagentToken != nil || input.UpstreamToken != nil) {
		writeProblem(response, http.StatusBadRequest, "invalid_request", errors.New("personserver: mission-bound delegated or call-chain authorization is not implemented"))
		return
	}
	if server.authorizationMode == authorizationModePersonServer && r3Context != nil {
		if err := directR3UnsupportedCombination(delegated, upstream); err != nil {
			writeProblem(response, http.StatusBadRequest, "invalid_request", err)
			return
		}
		if resourceToken.MissionS256 != "" {
			if _, ok := server.missions.(MissionR3IssuanceStore); !ok {
				writeProblem(response, http.StatusInternalServerError, "server_error", errors.New("personserver: mission-bound direct R3 requires an atomic mission R3 issuance store"))
				return
			}
		}
	}
	if budgetOffer != nil && (delegated || upstream != nil) {
		writeProblem(response, http.StatusBadRequest, "invalid_request", errors.New("personserver: Budget does not compose with delegation or call chaining"))
		return
	}
	resourceTokenExpiresAt := time.Unix(resourceToken.ExpiresAt, 0).UTC()
	resourceTokenIssuedAt := time.Unix(resourceToken.IssuedAt, 0).UTC()
	if resourceTokenExpiresAt.Sub(resourceTokenIssuedAt) > server.maximumResourceTokenLifetime {
		writeProblem(response, http.StatusBadRequest, "invalid_resource_token", errors.New("resource token exceeds the configured maximum lifetime"))
		return
	}
	if err := aauth.ValidateServerIdentifier(resourceToken.Audience); err != nil {
		writeProblem(response, http.StatusBadRequest, "invalid_resource_token", err)
		return
	}
	agentJKT, err := credentialAgent.Confirmation.JWK.Thumbprint()
	if err != nil || resourceToken.AgentJKT != agentJKT {
		writeProblem(response, http.StatusBadRequest, "invalid_resource_token", errors.New("resource token does not name the signing agent key"))
		return
	}
	var scopes []string
	if resourceToken.Scope != "" {
		scopes, err = parseScopes(resourceToken.Scope)
		if err != nil {
			writeProblem(response, http.StatusBadRequest, "invalid_resource_token", err)
			return
		}
	} else if r3Context == nil {
		writeProblem(response, http.StatusBadRequest, "invalid_resource_token", errors.New("resource token has no authorization claim"))
		return
	}
	presented, err := aauth.VerifyPresentedToken(
		request.Context(), input.PresentedToken, resourceToken, server.keyResolver, verificationClock,
	)
	if err == nil {
		err = proof.CheckIssuedAt(presentedTokenIssuedAt(presented))
	}
	if err != nil {
		writePresentedTokenProblem(response, err)
		return
	}
	// A verified presented token is accepted on its own. A retained person
	// token record, where one exists, still has to agree with the request, and
	// it is the only record that can tie a call chain to its upstream token.
	var record PersonTokenRecord
	retained := false
	if presented.Person != nil {
		record, err = server.tokens.Load(request.Context(), server.issuer, presented.JTI)
		if err != nil && !errors.Is(err, ErrPersonTokenNotFound) {
			writeProblem(response, http.StatusInternalServerError, "server_error", err)
			return
		}
		retained = err == nil
	}
	if retained {
		if err := validatePersonTokenRecord(record); err != nil ||
			record.JTI != resourceToken.PresentedJTI ||
			record.PersonServer != resourceToken.PersonServer ||
			record.Resource != resourceToken.Issuer ||
			record.Subject != resourceToken.Subject ||
			record.MissionS256 != resourceToken.MissionS256 ||
			record.Tenant != resourceToken.Tenant ||
			record.AgentProvider != credentialAgent.Issuer ||
			record.Agent != credentialAgent.Subject ||
			record.ParentAgent != credentialAgent.ParentAgent ||
			!record.Confirmation.Equal(credentialAgent.Confirmation.JWK) ||
			resourceTokenExpiresAt.After(record.RetainUntil) ||
			!record.RetainUntil.After(proof.VerifiedAt()) {
			writeProblem(response, http.StatusBadRequest, "invalid_resource_token", errors.New("resource token does not match the retained person token"))
			return
		}
		if !upstream.matchesRecord(record) {
			server.writeUpstreamTokenProblem(response, errors.New("personserver: upstream token does not match the retained call chain"))
			return
		}
	}
	// On step-up the presented token is an auth token this Person Server
	// issued, and its issuance record carries the tie. A record that is no
	// longer retained says nothing about the chain, so a request without an
	// upstream token is then accepted on the verified token alone.
	issuedTie := false
	if !retained && presented.Auth != nil && presented.Issuer == server.issuer &&
		server.authorizeChained != nil && server.issuedAuthTokens != nil {
		issued, err := server.issuedAuthTokens.LoadIssuedAuthToken(
			request.Context(), aauth.TokenReference{Issuer: presented.Issuer, JTI: presented.JTI},
		)
		if err != nil && !errors.Is(err, ErrIssuedAuthTokenNotFound) {
			writeProblem(response, http.StatusInternalServerError, "server_error", err)
			return
		}
		if err == nil {
			if validateIssuedAuthTokenRecord(issued) != nil ||
				issued.CompactSHA256 != sha256.Sum256([]byte(input.PresentedToken)) ||
				issued.Resource != resourceToken.Issuer {
				writeProblem(response, http.StatusBadRequest, "invalid_resource_token", errors.New("resource token does not match the retained auth token"))
				return
			}
			if !upstream.matchesIssuedRecord(issued) {
				server.writeUpstreamTokenProblem(response, errors.New("personserver: upstream token does not match the retained call chain"))
				return
			}
			issuedTie = true
		}
	}
	if upstream != nil && !retained && !issuedTie {
		// Without a retained record of the presented token nothing ties it to
		// the upstream token, so the chain is unidentified.
		server.writeUpstreamTokenProblem(response, errors.New("personserver: no retained record ties the presented token to the upstream token"))
		return
	}
	if upstream == nil {
		// Only a top-level Agent signs here, so its binding authorized the
		// presented credential, whether it holds it or a child it mediates does.
		if err := server.checkAgentBinding(request.Context(), agentBinding(agent)); err != nil {
			writeAgentBindingProblem(response, err, http.StatusBadRequest, "revoked_presented_token")
			return
		}
	}
	if budgetOffer != nil {
		if server.resolveBudgetResourceUnits == nil {
			writeProblem(response, http.StatusBadRequest, "invalid_resource_token", errors.New("personserver: Budget authorization is not configured"))
			return
		}
		declarations, err := server.resolveBudgetResourceUnits(request.Context(), resourceToken.Issuer)
		if err != nil {
			writeProblem(response, http.StatusInternalServerError, "server_error", fmt.Errorf("resolve Resource Budget metadata: %w", err))
			return
		}
		if err := budgets.ValidateDeclaredValue(declarations, *budgetOffer); err != nil {
			writeProblem(response, http.StatusBadRequest, "invalid_budget", fmt.Errorf("resource-token Budget metadata: %w", err))
			return
		}
	}
	if r3Context != nil {
		if err := server.fetchR3Artifact(request.Context(), r3Context, resourceToken.Account); err != nil {
			if isInvalidR3Artifact(err) {
				writeProblem(response, http.StatusBadRequest, "invalid_resource_token", err)
			} else {
				writeProblem(response, http.StatusInternalServerError, "server_error", err)
			}
			return
		}
	}
	var missionRecord *MissionRecord
	var missionContext *MissionContext
	if resourceToken.MissionS256 != "" {
		loadedMission, err := server.loadActiveMission(
			request.Context(), resourceToken.MissionS256, agent.Subject, server.clock.Now().UTC(),
		)
		if err != nil {
			writeMissionReferenceProblem(response, err)
			return
		}
		if !loadedMission.ExpiresAt.IsZero() && resourceTokenExpiresAt.After(loadedMission.ExpiresAt) {
			writeProblem(response, http.StatusBadRequest, "invalid_resource_token", errors.New("resource token outlives the mission"))
			return
		}
		missionContext, err = missionContextFromRecord(loadedMission)
		if err != nil {
			writeProblem(response, http.StatusInternalServerError, "server_error", err)
			return
		}
		missionRecord = &loadedMission
		if input.Capabilities == nil {
			capabilities = append([]string(nil), loadedMission.Capabilities...)
		}
	}
	authorizationRequest := AuthorizationRequest{
		Agent: agent.Subject, Resource: resourceToken.Issuer,
		Subject: resourceToken.Subject, Tenant: resourceToken.Tenant,
		Account:               cloneAuthorizationAccount(resourceToken.Account),
		Scopes:                append([]string(nil), scopes...),
		Capabilities:          append([]string(nil), capabilities...),
		Budget:                cloneBudgetValue(budgetOffer),
		AgentAdditionalClaims: cloneClaims(agent.AdditionalClaims),
		Mission:               missionContext,
	}
	if delegated {
		authorizationRequest.Subagent = credentialAgent.Subject
		authorizationRequest.SubagentAdditionalClaims = cloneClaims(credentialAgent.AdditionalClaims)
	}
	if upstream != nil {
		authorizationRequest.Upstream = upstream.policyClaims()
	}
	if server.authorizationMode == authorizationModePersonServer {
		// Person Server authorization closes when the presented token expires,
		// and the Auth token it issues never outlives that token.
		if r3Context != nil {
			if r3Context.kind != r3.ArtifactDocument {
				writeProblem(response, http.StatusBadRequest, "invalid_resource_token", errors.New("personserver: direct R3 supports class documents only"))
				return
			}
			server.issueDirectR3AuthorizationToken(
				response, request, agent, credentialAgent, resourceToken,
				authorizationRequest, r3Context, missionRecord, presented.ExpiresAt,
			)
			return
		}
		if upstream == nil && server.requireAuthorizationInteraction != nil {
			policyRequest := cloneAuthorizationRequest(authorizationRequest)
			policy, required, err := server.requireAuthorizationInteraction(request.Context(), policyRequest)
			if err != nil {
				writeProblem(response, http.StatusInternalServerError, "server_error", err)
				return
			}
			if required {
				if budgetOffer != nil {
					writeProblem(response, http.StatusInternalServerError, "server_error", errors.New("personserver: Budget authorization interaction is not implemented"))
					return
				}
				if !slices.Contains(capabilities, "interaction") {
					writeProblem(response, http.StatusForbidden, "user_unreachable", errors.New("Agent did not declare interaction capability"))
					return
				}
				if err := server.beginAuthorizationInteraction(
					response, request, authorizationRequest, agent, credentialAgent, resourceToken, missionRecord, policy, presented.ExpiresAt,
				); err != nil {
					if missionRecord != nil {
						writeMissionActionProblem(response, err)
						return
					}
					writeProblem(response, http.StatusInternalServerError, "server_error", err)
				}
				return
			}
		}
		authorize := server.authorize
		if upstream != nil {
			authorize = server.authorizeChained
		}
		if authorize == nil {
			if server.r3 != nil && upstream == nil {
				writeAccessPolicyProblem(response, errors.Join(
					ErrAccessDenied,
					errors.New("personserver: Core authorization is not configured"),
				))
				return
			}
			writeProblem(response, http.StatusInternalServerError, "server_error", errors.New("deferred authorization policy did not select interaction and no immediate authorization policy is configured"))
			return
		}
		server.issuePSAuthorizationToken(
			response, request, agent, credentialAgent, resourceToken,
			authorizationRequest, missionRecord, authorize, presented.ExpiresAt, upstream,
		)
		return
	}
	var consentErr error
	if r3Context != nil {
		consentErr = server.consentR3(
			request.Context(), cloneAuthorizationRequest(authorizationRequest), r3Context,
		)
	} else {
		consentErr = server.consent(request.Context(), cloneAuthorizationRequest(authorizationRequest))
	}
	if consentErr != nil {
		writeAccessPolicyProblem(response, consentErr)
		return
	}
	var personBudgetCeiling *budgets.Value
	if budgetOffer != nil {
		if server.federatedBudgetCeiling == nil {
			writeProblem(response, http.StatusInternalServerError, "server_error", errors.New("personserver: federated Budget ceiling policy is not configured"))
			return
		}
		selected, err := server.federatedBudgetCeiling(
			request.Context(), cloneAuthorizationRequest(authorizationRequest),
		)
		if err != nil {
			writeAccessPolicyProblem(response, err)
			return
		}
		if selected != nil {
			if err := budgets.ValidateNarrowing(*budgetOffer, *selected); err != nil {
				writeProblem(response, http.StatusInternalServerError, "server_error", fmt.Errorf("Person Server Budget ceiling: %w", err))
				return
			}
			personBudgetCeiling = cloneBudgetValue(selected)
		}
	}
	endpoint, err := server.accessServerEndpoint(request.Context(), resourceToken.Audience)
	if err != nil {
		writeAccessServerUnreachable(response, err)
		return
	}
	if err := validateAccessServerEndpoint(endpoint); err != nil {
		writeAccessServerUnreachable(response, err)
		return
	}
	accessInput, err := json.Marshal(struct {
		ResourceToken  string         `json:"resource_token"`
		PresentedToken string         `json:"presented_token"`
		AgentToken     string         `json:"agent_token"`
		SubagentToken  string         `json:"subagent_token,omitempty"`
		Budget         *budgets.Value `json:"budget,omitempty"`
	}{
		ResourceToken: input.ResourceToken, PresentedToken: input.PresentedToken, AgentToken: agentToken,
		SubagentToken: subagentToken, Budget: personBudgetCeiling,
	})
	if err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", err)
		return
	}
	accessRequest, err := http.NewRequestWithContext(request.Context(), http.MethodPost, endpoint, bytes.NewReader(accessInput))
	if err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", err)
		return
	}
	accessRequest.Header.Set("Content-Type", "application/json")
	if err := signaturekey.SignJWKSURIRequestWithOptions(
		accessRequest, server.signingKey, server.issuer, aauth.PersonDiscoveryDocument, server.clock,
		signaturekey.SignOptions{
			AdditionalComponents: []string{"content-type", "content-digest"},
			MaxBodyBytes:         maxRequestBytes,
		},
	); err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", err)
		return
	}
	accessResponse, err := server.httpClient.Do(accessRequest)
	if err != nil {
		writeAccessServerUnreachable(response, err)
		return
	}
	defer accessResponse.Body.Close()
	if accessResponse.StatusCode == 202 || accessResponse.StatusCode == 402 {
		reason := ""
		switch {
		case server.federatedDeferred == nil:
			reason = "not_configured"
		case r3Context != nil:
			reason = "r3"
		case budgetOffer != nil:
			reason = "budget"
		case missionRecord != nil:
			reason = "mission"
		}
		if reason != "" {
			writeFederatedContinuationProblem(response, &DeferredCompositionError{reason: reason})
			return
		}
		server.beginFederatedAuthorization(response, request, accessResponse, endpoint, federatedContinuationInput{
			resourceToken: input.ResourceToken, agentToken: agentToken, presentedToken: input.PresentedToken,
			subagentToken: subagentToken, agent: agent, credentialAgent: credentialAgent,
			resource: resourceToken, presentedExpiresAt: presented.ExpiresAt,
		})
		return
	}
	if accessResponse.StatusCode != http.StatusOK {
		if relayAccessServerProblem(response, accessResponse) {
			return
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(accessResponse.Body, maxRequestBytes))
		writeAccessServerUnreachable(response, errors.New("access server returned no well-formed terminal error"))
		return
	}
	server.deliverFederatedAuthorization(response, request, accessResponse, resourceToken, agent, credentialAgent, presented.ExpiresAt, scopes, r3Context, budgetOffer, personBudgetCeiling, missionRecord, authorizationRequest)

}

func equalStringPointers(first, second *string) bool {
	if first == nil || second == nil {
		return first == nil && second == nil
	}
	return *first == *second
}

func (server *Server) validateResourceTokenTopology(resourceToken aauth.ResourceTokenClaims) error {
	if resourceToken.PersonServer != server.issuer {
		return errors.New("resource token does not name this person server")
	}
	switch server.authorizationMode {
	case authorizationModePersonServer:
		if resourceToken.Audience != server.issuer {
			return errors.New("resource token requires Access Server federation")
		}
	case authorizationModeFederated:
		// The explicit constructor selects federation even when the Access
		// Server is collocated at the Person Server's origin.
	default:
		return errors.New("person server authorization mode is invalid")
	}
	return nil
}

func (server *Server) issuePSAuthorizationToken(
	response http.ResponseWriter,
	request *http.Request,
	requestingAgent aauth.AgentTokenClaims,
	credentialAgent aauth.AgentTokenClaims,
	resourceToken aauth.ResourceTokenClaims,
	authorizationRequest AuthorizationRequest,
	missionRecord *MissionRecord,
	authorize func(context.Context, AuthorizationRequest) (AuthorizationDecision, error),
	personTokenExpiresAt time.Time,
	upstream *verifiedUpstreamToken,
) {
	policyRequest := cloneAuthorizationRequest(authorizationRequest)
	decision, err := authorize(request.Context(), policyRequest)
	if err != nil {
		writeAccessPolicyProblem(response, err)
		return
	}
	grantedScopes, err := validateAuthorizationDecision(decision, authorizationRequest.Scopes)
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
	if missionRecord != nil {
		current, err := server.recheckActiveMission(request.Context(), *missionRecord, issuedAt)
		if err != nil {
			writeMissionReferenceProblem(response, err)
			return
		}
		missionRecord = &current
	}
	if !server.authorizationInputsCurrent(response, resourceToken, personTokenExpiresAt, issuedAt) {
		return
	}
	expiresAt := issuedAt.Add(decision.Lifetime)
	if personTokenExpiresAt.Before(expiresAt) {
		expiresAt = personTokenExpiresAt
	}
	requestingAgentExpiresAt := time.Unix(requestingAgent.ExpiresAt, 0)
	if requestingAgentExpiresAt.Before(expiresAt) {
		expiresAt = requestingAgentExpiresAt
	}
	credentialAgentExpiresAt := time.Unix(credentialAgent.ExpiresAt, 0)
	if credentialAgentExpiresAt.Before(expiresAt) {
		expiresAt = credentialAgentExpiresAt
	}
	if authorizationRequest.Mission != nil && authorizationRequest.Mission.Blob.ExpiresAt != nil &&
		authorizationRequest.Mission.Blob.ExpiresAt.Before(expiresAt) {
		expiresAt = *authorizationRequest.Mission.Blob.ExpiresAt
	}
	// An auth token issued on a request carrying upstream_token expires no
	// later than that token.
	if authorizationRequest.Upstream != nil {
		if upstreamExpiresAt := time.Unix(authorizationRequest.Upstream.ExpiresAt, 0); upstreamExpiresAt.Before(expiresAt) {
			expiresAt = upstreamExpiresAt
		}
	}
	if !expiresAt.After(issuedAt) {
		writeProblem(response, http.StatusInternalServerError, "server_error", errors.New("authorization decision has no usable lifetime"))
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
	if grantedBudget != nil {
		compact, err = budgets.MintAuthToken(server.signingKey, claims, *grantedBudget)
	} else {
		compact, err = aauth.MintAuthToken(server.signingKey, claims)
	}
	if err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", err)
		return
	}
	issuedRecord, err := issuedAuthTokenRecord(compact, claims)
	if err == nil {
		err = issuedRecord.bindRecipient(credentialAgent, upstream)
	}
	if err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", err)
		return
	}
	if missionRecord != nil {
		if authorizationRequest.Mission == nil || authorizationRequest.Mission.S256 != missionRecord.S256 {
			writeProblem(response, http.StatusInternalServerError, "server_error", errors.New("personserver: mission record does not match authorization context"))
			return
		}
		commitAt := server.clock.Now().UTC()
		if err := server.missions.CommitMissionAuthToken(
			request.Context(), *missionRecord, commitAt, issuedRecord,
		); err != nil {
			writeMissionReferenceProblem(response, err)
			return
		}
	} else if authorizationRequest.Mission != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", errors.New("personserver: mission authorization has no retained mission"))
		return
	}
	if err := server.commitIssuedAuthToken(request.Context(), issuedRecord); err != nil {
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

func validateAuthorizationDecision(decision AuthorizationDecision, requested []string) ([]string, error) {
	if decision.Lifetime <= 0 || decision.Lifetime > time.Hour {
		return nil, errors.New("authorization decision lifetime must be positive and at most one hour")
	}
	granted, err := parseScopes(strings.Join(decision.Scopes, " "))
	if err != nil {
		return nil, fmt.Errorf("authorization decision scope: %w", err)
	}
	if !scopeSubset(granted, requested) {
		return nil, errors.New("authorization decision grants an unrequested scope")
	}
	return granted, nil
}

func validateBudgetDecision(offered, granted *budgets.Value) (*budgets.Value, error) {
	if offered == nil {
		if granted != nil {
			return nil, errors.New("authorization decision cannot invent a Budget")
		}
		return nil, nil
	}
	if granted == nil {
		return nil, errors.New("authorization decision must preserve the Resource-token Budget")
	}
	if err := budgets.ValidateNarrowing(*offered, *granted); err != nil {
		return nil, fmt.Errorf("authorization decision Budget: %w", err)
	}
	return cloneBudgetValue(granted), nil
}

func validateFederatedBudgetGrant(
	resourceOffer budgets.Value,
	personCeiling *budgets.Value,
	accessGrant budgets.Value,
) error {
	if err := budgets.ValidateNarrowing(resourceOffer, accessGrant); err != nil {
		return fmt.Errorf("Access Server Budget exceeds the Resource offer: %w", err)
	}
	if personCeiling == nil {
		return nil
	}
	if err := budgets.ValidateNarrowing(*personCeiling, accessGrant); err != nil {
		return fmt.Errorf("Access Server Budget exceeds the Person Server ceiling: %w", err)
	}
	return nil
}

// writeAccessServerUnreachable reports that no verifiable auth token could be
// obtained from the Access Server: it was unreachable, answered without a
// well-formed terminal error, or delivered a token that fails verification.
func writeAccessServerUnreachable(response http.ResponseWriter, err error) {
	writeProblem(response, http.StatusBadGateway, "as_unreachable", err)
}

func presentedTokenIssuedAt(presented aauth.PresentedToken) time.Time {
	if presented.Auth != nil {
		return time.Unix(presented.Auth.IssuedAt, 0)
	}
	if presented.Person != nil {
		return time.Unix(presented.Person.IssuedAt, 0)
	}
	return time.Time{}
}

func writePresentedTokenProblem(response http.ResponseWriter, err error) {
	if writeParameterClockSkew(response, err) {
		return
	}
	switch {
	case errors.Is(err, aauth.ErrExpiredPresentedToken):
		writeProblem(response, http.StatusBadRequest, "expired_presented_token", err)
	case errors.Is(err, aauth.ErrPresentedTokenMismatch):
		writeProblem(response, http.StatusBadRequest, "invalid_resource_token", err)
	default:
		writeProblem(response, http.StatusBadRequest, "invalid_presented_token", err)
	}
}

func relayAccessServerProblem(response http.ResponseWriter, accessResponse *http.Response) bool {
	// A 401 answers the Person Server's own request signature. It says nothing
	// about the Agent's request and is not relayed.
	if accessResponse.StatusCode < http.StatusBadRequest || accessResponse.StatusCode > 599 ||
		accessResponse.StatusCode == http.StatusUnauthorized {
		return false
	}
	problem, err := aauth.DecodeProblemResponse(accessResponse)
	if err != nil {
		return false
	}
	writeProblem(response, accessResponse.StatusCode, string(problem.Code), errors.New("access server refused the token exchange"))
	return true
}

func (server *Server) verifyOptionalSubagentToken(
	ctx context.Context,
	raw json.RawMessage,
	parent aauth.AgentTokenClaims,
	proof signaturekey.VerifiedRequest,
) (string, aauth.AgentTokenClaims, bool, error) {
	if raw == nil {
		return "", parent, false, nil
	}
	var compact string
	if err := json.Unmarshal(raw, &compact); err != nil || compact == "" {
		return "", aauth.AgentTokenClaims{}, false, errSubagentTokenSyntax
	}
	verificationClock := aauth.ClockFunc(func() time.Time { return proof.VerifiedAt() })
	child, err := aauth.VerifySubagentToken(ctx, compact, parent, server.keyResolver, verificationClock)
	if err != nil {
		return "", aauth.AgentTokenClaims{}, false, err
	}
	if err := proof.CheckIssuedAt(time.Unix(child.IssuedAt, 0)); err != nil {
		return "", aauth.AgentTokenClaims{}, false, err
	}
	if err := server.checkSubagentTokenRevocation(ctx, child); err != nil {
		return "", aauth.AgentTokenClaims{}, false, err
	}
	return compact, child, true, nil
}

// checkSubagentTokenRevocation applies the Agent Provider's retained
// revocations to a sub-agent token, as for the signing Agent's own token.
func (server *Server) checkSubagentTokenRevocation(ctx context.Context, child aauth.AgentTokenClaims) error {
	if server.agentTokenRevocations == nil {
		return nil
	}
	revoked, err := server.agentTokenRevocations.IsRevoked(ctx, aauth.TokenReference{Issuer: child.Issuer, JTI: child.JTI})
	if err != nil {
		return &agentTokenRevocationStoreError{cause: err}
	}
	if revoked {
		return errSubagentTokenRevoked
	}
	return nil
}

var errSubagentTokenRevoked = errors.New("personserver: sub-agent token revoked by its Agent Provider")

// writeSubagentTokenProblem maps a request-parameter sub-agent token failure
// to Protocol -11's <invalid|expired|revoked>_subagent_token codes.
func (server *Server) writeSubagentTokenProblem(response http.ResponseWriter, err error) {
	var storeFailure *agentTokenRevocationStoreError
	switch {
	case errors.Is(err, errSubagentTokenSyntax):
		writeProblem(response, http.StatusBadRequest, "invalid_request", err)
	case errors.As(err, &storeFailure):
		writeProblem(response, http.StatusInternalServerError, "server_error", storeFailure.cause)
	case writeParameterClockSkew(response, err):
	case errors.Is(err, errSubagentTokenRevoked):
		writeProblem(response, http.StatusBadRequest, "revoked_subagent_token", err)
	case errors.Is(err, aauth.ErrExpiredSubagentToken):
		writeProblem(response, http.StatusBadRequest, "expired_subagent_token", err)
	default:
		writeProblem(response, http.StatusBadRequest, "invalid_subagent_token", err)
	}
}

func (server *Server) verifyAgentRequest(request *http.Request, requiredComponents []string) (string, aauth.AgentTokenClaims, signaturekey.VerifiedRequest, error) {
	compact, agent, proof, err := server.verifyAgentProof(request, requiredComponents)
	if err != nil {
		return "", agent, signaturekey.VerifiedRequest{}, err
	}
	if err := server.validateDirectAgentTopology(agent); err != nil {
		return "", agent, signaturekey.VerifiedRequest{}, err
	}
	return compact, agent, proof, nil
}

func (server *Server) verifyAgentProof(request *http.Request, requiredComponents []string) (string, aauth.AgentTokenClaims, signaturekey.VerifiedRequest, error) {
	var agent aauth.AgentTokenClaims
	prepared, err := signaturekey.PrepareRequest(request, server.clock, signaturekey.VerifyOptions{
		RequiredComponents: requiredComponents,
		AcceptedSchemes:    []signaturekey.Scheme{signaturekey.SchemeJWT},
		MaxBodyBytes:       maxRequestBytes,
	})
	if err != nil {
		return "", agent, signaturekey.VerifiedRequest{}, err
	}
	compact, ok := prepared.Credential().JWT()
	if !ok {
		return "", agent, signaturekey.VerifiedRequest{}, errors.New("personserver: agent-token credential is required")
	}
	verificationClock := aauth.ClockFunc(func() time.Time { return prepared.VerifiedAt() })
	agent, err = aauth.VerifyAgentToken(request.Context(), compact, server.keyResolver, verificationClock)
	if err != nil {
		return "", agent, signaturekey.VerifiedRequest{}, &requestTokenError{cause: err}
	}
	proof, err := prepared.Verify(agent.Confirmation.JWK)
	if err != nil {
		return "", agent, signaturekey.VerifiedRequest{}, err
	}
	if err := proof.CheckIssuedAt(time.Unix(agent.IssuedAt, 0)); err != nil {
		return "", agent, signaturekey.VerifiedRequest{}, err
	}
	if server.agentTokenRevocations != nil {
		revoked, err := server.agentTokenRevocations.IsRevoked(request.Context(), aauth.TokenReference{
			Issuer: agent.Issuer,
			JTI:    agent.JTI,
		})
		if err != nil {
			return "", agent, signaturekey.VerifiedRequest{}, &agentTokenRevocationStoreError{cause: err}
		}
		if revoked {
			return "", agent, signaturekey.VerifiedRequest{}, &requestTokenError{cause: ErrAgentTokenRevoked}
		}
	}
	return compact, agent, proof, nil
}

func (server *Server) validateDirectAgentTopology(agent aauth.AgentTokenClaims) error {
	if agent.PersonServer != server.issuer || agent.ParentAgent != "" {
		return &requestTopologyError{cause: errors.New("personserver: only a top-level Agent token naming this Person Server may sign the request")}
	}
	return nil
}

type requestTokenError struct{ cause error }

func (failure *requestTokenError) Error() string { return failure.cause.Error() }
func (failure *requestTokenError) Unwrap() error { return failure.cause }

type requestTopologyError struct{ cause error }

func (failure *requestTopologyError) Error() string { return failure.cause.Error() }
func (failure *requestTopologyError) Unwrap() error { return failure.cause }

type agentTokenRevocationStoreError struct{ cause error }

func (failure *agentTokenRevocationStoreError) Error() string { return failure.cause.Error() }
func (failure *agentTokenRevocationStoreError) Unwrap() error { return failure.cause }

func writeAgentTokenProblem(response http.ResponseWriter, err error) {
	var storeFailure *agentTokenRevocationStoreError
	if errors.As(err, &storeFailure) {
		writeProblem(response, http.StatusInternalServerError, "server_error", storeFailure.cause)
		return
	}
	var tokenFailure *requestTokenError
	if errors.As(err, &tokenFailure) {
		if errors.Is(tokenFailure.cause, ErrAgentTokenRevoked) {
			writeProblem(response, http.StatusUnauthorized, "invalid_agent_token", signaturekey.NewError(signaturekey.ErrorRevokedJWT, tokenFailure.cause))
			return
		}
		writeEndpointTokenProblem(response, tokenFailure.cause, "invalid_agent_token", "expired_agent_token")
		return
	}
	var topologyFailure *requestTopologyError
	if errors.As(err, &topologyFailure) {
		writeProblem(response, http.StatusBadRequest, "invalid_agent_token", topologyFailure.cause)
		return
	}
	writeProblem(response, http.StatusUnauthorized, "invalid_agent_token", err)
}

func writeEndpointTokenProblem(response http.ResponseWriter, err error, invalidCode, expiredCode string) {
	if writeParameterClockSkew(response, err) {
		return
	}
	var tokenFailure *aauth.TokenValidationError
	if errors.As(err, &tokenFailure) && tokenFailure.Code == aauth.TokenValidationExpired {
		writeProblem(response, http.StatusBadRequest, expiredCode, err)
		return
	}
	writeProblem(response, http.StatusBadRequest, invalidCode, err)
}

// writeParameterClockSkew reports a request-parameter token issued beyond the
// request's signature window as HTTP 400 clock_skew. Only Signature-Key
// tokens and HTTP signature time use the 401 Signature-Error path.
func writeParameterClockSkew(response http.ResponseWriter, err error) bool {
	var failure *signaturekey.Error
	if !errors.As(err, &failure) || failure.Code != signaturekey.ErrorClockSkew {
		return false
	}
	writeProblem(response, http.StatusBadRequest, string(signaturekey.ErrorClockSkew), err)
	return true
}

func (server *Server) handleMetadata(response http.ResponseWriter, _ *http.Request) {
	metadata := map[string]string{
		"issuer":                server.issuer,
		"person_token_endpoint": server.issuer + "/person",
		"auth_token_endpoint":   server.issuer + "/token",
		"jwks_uri":              server.issuer + "/.well-known/jwks.json",
	}
	if server.missions != nil {
		metadata["mission_endpoint"] = server.issuer + "/mission"
	}
	if server.permissions != nil {
		metadata["permission_endpoint"] = server.issuer + "/permission"
	}
	if server.missionAudits != nil {
		metadata["audit_endpoint"] = server.issuer + "/audit"
	}
	if server.interactionQuestionPolicy != nil || server.interactionRelayPolicy != nil {
		metadata["interaction_endpoint"] = server.issuer + "/interaction"
	}
	if server.agentTokenRevocations != nil {
		metadata["revocation_endpoint"] = server.issuer + "/revoke"
	}
	writeJSON(response, http.StatusOK, metadata)
}

func (server *Server) handleJWKS(response http.ResponseWriter, _ *http.Request) {
	writeJSON(response, http.StatusOK, map[string]any{
		"keys": []jose.JWK{server.signingKey.PublicJWK()},
	})
}

func validatePersonTokenRecord(record PersonTokenRecord) error {
	if record.JTI == "" || record.PersonServer == "" || record.Resource == "" || record.Subject == "" ||
		record.AgentProvider == "" || record.Agent == "" || record.ExpiresAt.IsZero() ||
		!record.RetainUntil.After(record.ExpiresAt) {
		return errors.New("personserver: retained person token is invalid")
	}
	if err := aauth.ValidateServerIdentifier(record.PersonServer); err != nil {
		return fmt.Errorf("personserver: retained person-token issuer: %w", err)
	}
	if err := aauth.ValidateServerIdentifier(record.Resource); err != nil {
		return fmt.Errorf("personserver: retained person-token resource: %w", err)
	}
	if err := aauth.ValidateServerIdentifier(record.AgentProvider); err != nil {
		return fmt.Errorf("personserver: retained person-token agent provider: %w", err)
	}
	if err := aauth.ValidateAgentRelationship(record.Agent, record.ParentAgent); err != nil {
		return fmt.Errorf("personserver: retained person-token agent relationship: %w", err)
	}
	if _, err := record.Confirmation.PublicKey(); err != nil {
		return fmt.Errorf("personserver: retained person-token confirmation: %w", err)
	}
	if err := validateCallChainRecord(record); err != nil {
		return err
	}
	return nil
}

func parseScopes(value string) ([]string, error) {
	scopes, err := aauth.ParseScope(value)
	if err != nil {
		return nil, fmt.Errorf("personserver: token scope: %w", err)
	}
	return scopes, nil
}

func scopeSubset(granted, requested []string) bool {
	if len(granted) == 0 {
		return false
	}
	available := make(map[string]struct{}, len(requested))
	for _, scope := range requested {
		available[scope] = struct{}{}
	}
	for _, scope := range granted {
		if _, ok := available[scope]; !ok {
			return false
		}
	}
	return true
}

func validateAccessServerEndpoint(endpoint string) error {
	return aauth.ValidateEndpoint(endpoint)
}

func decodeJSON(reader io.Reader, destination any) error {
	return httpapi.DecodeJSON(reader, maxRequestBytes, destination)
}

func rejectUnsupportedRequestMembers(members map[string]json.RawMessage) error {
	for name, value := range members {
		if value != nil {
			return fmt.Errorf("personserver: request member %q is not supported by the immediate flow", name)
		}
	}
	return nil
}

func parseAuthorizationCapabilities(raw json.RawMessage) ([]string, error) {
	if raw == nil {
		return nil, nil
	}
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return nil, errors.New("personserver: capabilities must be a JSON array")
	}
	var capabilities []string
	if err := json.Unmarshal(raw, &capabilities); err != nil {
		return nil, fmt.Errorf("personserver: capabilities: %w", err)
	}
	seen := make(map[string]struct{}, len(capabilities))
	for _, capability := range capabilities {
		if _, duplicate := seen[capability]; duplicate {
			return nil, fmt.Errorf("personserver: capabilities repeats %q", capability)
		}
		if _, err := aauth.FormatCapabilities([]string{capability}); err != nil {
			return nil, fmt.Errorf("personserver: capability %q: %w", capability, err)
		}
		seen[capability] = struct{}{}
	}
	return append([]string(nil), capabilities...), nil
}

func clonePersonTokenRequest(request PersonTokenRequest) PersonTokenRequest {
	request.AgentAdditionalClaims = cloneClaims(request.AgentAdditionalClaims)
	request.SubagentAdditionalClaims = cloneClaims(request.SubagentAdditionalClaims)
	request.Mission = cloneMissionContext(request.Mission)
	if request.Upstream != nil {
		upstream := cloneAuthTokenClaims(*request.Upstream)
		request.Upstream = &upstream
	}
	return request
}

// authorizationInputsCurrent checks, at the issuance instant sampled after an
// authorization policy returns, that the Resource token and the retained
// Person token are still current. A slow policy must not issue from tokens
// that expired while it ran.
func (server *Server) authorizationInputsCurrent(
	response http.ResponseWriter,
	resourceToken aauth.ResourceTokenClaims,
	personTokenExpiresAt time.Time,
	now time.Time,
) bool {
	if !now.Before(time.Unix(resourceToken.ExpiresAt, 0)) {
		writeProblem(response, http.StatusBadRequest, "expired_resource_token", errors.New("personserver: resource token expired during authorization"))
		return false
	}
	if !now.Before(personTokenExpiresAt) {
		writeProblem(response, http.StatusBadRequest, "expired_presented_token", errors.New("personserver: presented token expired during authorization"))
		return false
	}
	return true
}

func cloneAuthorizationRequest(request AuthorizationRequest) AuthorizationRequest {
	request.Account = cloneAuthorizationAccount(request.Account)
	request.Scopes = append([]string(nil), request.Scopes...)
	request.Capabilities = append([]string(nil), request.Capabilities...)
	request.Budget = cloneBudgetValue(request.Budget)
	request.AgentAdditionalClaims = cloneClaims(request.AgentAdditionalClaims)
	request.SubagentAdditionalClaims = cloneClaims(request.SubagentAdditionalClaims)
	request.Mission = cloneMissionContext(request.Mission)
	if request.Upstream != nil {
		upstream := cloneAuthTokenClaims(*request.Upstream)
		request.Upstream = &upstream
	}
	return request
}

func cloneBudgetValue(value *budgets.Value) *budgets.Value {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}

func cloneClaims(claims map[string]json.RawMessage) map[string]json.RawMessage {
	if len(claims) == 0 {
		return nil
	}
	cloned := make(map[string]json.RawMessage, len(claims))
	for name, value := range claims {
		cloned[name] = append(json.RawMessage(nil), value...)
	}
	return cloned
}

func writeJSON(response http.ResponseWriter, status int, value any) {
	httpapi.WriteJSON(response, status, value)
}

func writePrivateJSON(response http.ResponseWriter, status int, value any) {
	response.Header().Set("Cache-Control", "no-store")
	httpapi.WriteJSON(response, status, value)
}

func writeAccessPolicyProblem(response http.ResponseWriter, err error) {
	if errors.Is(err, ErrAccessDenied) {
		writeProblem(response, http.StatusForbidden, "access_denied", err)
		return
	}
	writeProblem(response, http.StatusInternalServerError, "server_error", err)
}

func writeProblem(response http.ResponseWriter, status int, code string, cause error) {
	response.Header().Set("Cache-Control", "no-store")
	httpapi.WriteProblem(response, status, code, cause)
}

func (server *Server) deliverFederatedAuthorization(response http.ResponseWriter, request *http.Request, accessResponse *http.Response,
	resourceToken aauth.ResourceTokenClaims, agent, credentialAgent aauth.AgentTokenClaims, presentedExpiresAt time.Time,
	scopes []string, r3Context *verifiedR3, budgetOffer, personBudgetCeiling *budgets.Value,
	missionRecord *MissionRecord, authorizationRequest AuthorizationRequest) {
	accessBody, err := io.ReadAll(io.LimitReader(accessResponse.Body, maxRequestBytes+1))
	if err != nil || len(accessBody) > maxRequestBytes {
		writeAccessServerUnreachable(response, errors.New("access-server response is unavailable"))
		return
	}
	var accessOutput struct {
		AuthToken string `json:"auth_token"`
		ExpiresIn int64  `json:"expires_in"`
	}
	if err := decodeJSON(bytes.NewReader(accessBody), &accessOutput); err != nil || accessOutput.AuthToken == "" {
		writeAccessServerUnreachable(response, errors.New("access-server response is invalid"))
		return
	}
	var authToken aauth.AuthTokenClaims
	if r3Context != nil && budgetOffer != nil {
		var grant budgets.Value
		authToken, grant, err = server.verifyR3BudgetAccessResult(
			request.Context(), accessOutput.AuthToken, r3Context,
		)
		if err == nil {
			err = validateFederatedBudgetGrant(*budgetOffer, personBudgetCeiling, grant)
		}
	} else if r3Context != nil {
		authToken, err = server.verifyR3AccessResult(request.Context(), accessOutput.AuthToken, r3Context)
	} else if budgetOffer != nil {
		var grant budgets.Value
		authToken, grant, err = budgets.VerifyAuthToken(
			request.Context(), accessOutput.AuthToken, server.keyResolver, server.clock,
		)
		if err == nil {
			err = validateFederatedBudgetGrant(*budgetOffer, personBudgetCeiling, grant)
		}
	} else {
		carriesBudget, budgetErr := budgets.TokenCarriesClaims(accessOutput.AuthToken)
		if budgetErr != nil {
			err = budgetErr
		} else if carriesBudget {
			err = errors.New("Access Server auth token invented a Budget")
		} else {
			authToken, err = aauth.VerifyAuthToken(
				request.Context(), accessOutput.AuthToken, server.keyResolver, server.clock,
			)
		}
	}
	if err != nil {
		writeAccessServerUnreachable(response, err)
		return
	}
	if authToken.Issuer != resourceToken.Audience ||
		authToken.DWK != aauth.AccessDiscoveryDocument ||
		authToken.ExpiresAt > agent.ExpiresAt ||
		authToken.ExpiresAt > credentialAgent.ExpiresAt ||
		authToken.ExpiresAt > presentedExpiresAt.Unix() ||
		authToken.MissionS256 != resourceToken.MissionS256 ||
		authToken.Tenant != resourceToken.Tenant || !equalStringPointers(authToken.Account, resourceToken.Account) {
		writeAccessServerUnreachable(response, errors.New("access-server auth token changed the authorized context"))
		return
	}
	if err := aauth.ValidateCurrentAuthTokenContext(
		authToken,
		aauth.AuthTokenContext{
			Issuer: resourceToken.Audience, DiscoveryDocument: aauth.AccessDiscoveryDocument,
			Resource: resourceToken.Issuer, PersonServer: server.issuer, Subject: resourceToken.Subject,
			RequestKey: credentialAgent.Confirmation.JWK,
		},
	); err != nil {
		writeAccessServerUnreachable(response, err)
		return
	}
	var grantedScopes []string
	if authToken.Scope != "" {
		grantedScopes, err = parseScopes(authToken.Scope)
	} else if r3Context == nil {
		err = errors.New("Access Server auth token has no authorization claim")
	}
	validScopeGrant := len(scopes) == 0 && len(grantedScopes) == 0 ||
		len(scopes) > 0 && len(grantedScopes) > 0 && scopeSubset(grantedScopes, scopes)
	if err != nil || !validScopeGrant {
		writeAccessServerUnreachable(response, errors.New("access-server auth token grants an unrequested scope"))
		return
	}
	if missionRecord != nil {
		if authorizationRequest.Mission == nil || authorizationRequest.Mission.S256 != missionRecord.S256 {
			writeProblem(response, http.StatusInternalServerError, "server_error", errors.New("personserver: mission record does not match federated authorization context"))
			return
		}
		if !missionRecord.ExpiresAt.IsZero() && authToken.ExpiresAt > missionRecord.ExpiresAt.Unix() {
			writeAccessServerUnreachable(response, errors.New("access-server auth token outlives the mission-bound authorization"))
			return
		}
		issuedRecord, err := issuedAuthTokenRecord(accessOutput.AuthToken, authToken)
		if err != nil {
			writeProblem(response, http.StatusInternalServerError, "server_error", err)
			return
		}
		commitAt := server.clock.Now().UTC()
		if err := server.missions.CommitMissionAuthToken(
			request.Context(), *missionRecord, commitAt, issuedRecord,
		); err != nil {
			writeMissionReferenceProblem(response, err)
			return
		}
	} else if authorizationRequest.Mission != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", errors.New("personserver: federated mission authorization has no retained mission"))
		return
	}
	writePrivateJSON(response, http.StatusOK, struct {
		AuthToken string `json:"auth_token"`
		ExpiresIn int64  `json:"expires_in"`
	}{
		AuthToken: accessOutput.AuthToken,
		ExpiresIn: authToken.ExpiresAt - server.clock.Now().Unix(),
	})
}
