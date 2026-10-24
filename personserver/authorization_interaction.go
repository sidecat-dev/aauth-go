package personserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/budgets"
	"gitlab.com/sidecat-dev/aauth-go/internal/interaction"
	"gitlab.com/sidecat-dev/aauth-go/jose"
)

var (
	// ErrPendingAuthorizationNotFound reports an unknown pending auth-token request.
	ErrPendingAuthorizationNotFound = errors.New("personserver: pending authorization not found")
	// ErrPendingAuthorizationConflict reports a competing or inconsistent decision.
	ErrPendingAuthorizationConflict = errors.New("personserver: pending authorization conflicts with retained state")
	// ErrPendingAuthorizationExpired reports that the pending deadline passed.
	ErrPendingAuthorizationExpired = errors.New("personserver: pending authorization expired")
	// ErrPendingAuthorizationGone reports that the terminal response was delivered.
	ErrPendingAuthorizationGone = errors.New("personserver: pending authorization is gone")
	// ErrAuthorizationInteractionCodeInvalid reports a failed code correlation.
	ErrAuthorizationInteractionCodeInvalid = errors.New("personserver: authorization interaction code is invalid")
	// ErrAuthorizationInteractionCodeUsed reports a code already consumed.
	ErrAuthorizationInteractionCodeUsed = errors.New("personserver: authorization interaction code was already used")
	// ErrAuthorizationClarificationUnsupported reports that the Agent did not
	// declare the clarification capability on the retained authorization.
	ErrAuthorizationClarificationUnsupported = errors.New("personserver: authorization clarification was not declared by the Agent")
)

// MaximumAuthorizationCodeAttempts is the fixed failed-code bound for one
// pending authorization interaction.
const MaximumAuthorizationCodeAttempts = 3

// MaximumAuthorizationClarificationRounds is the safe dialogue bound for one
// pending authorization. Core carries no round identifier in an answer, so a
// later round cannot safely distinguish a delayed earlier answer (AAG-F095).
const MaximumAuthorizationClarificationRounds = 1

// MaximumAuthorizationClarificationBytes bounds one Markdown question or
// answer before it reaches host rendering or durable storage.
const MaximumAuthorizationClarificationBytes = 64 << 10

const (
	maximumAuthorizationClarificationOptions     = 32
	maximumAuthorizationClarificationOptionBytes = 4 << 10
)

// AuthorizationClarificationRequest is one host-authenticated question for
// the Agent. Question and Options are untrusted Markdown/display input at the
// receiving boundary; applications must sanitize them before rendering.
type AuthorizationClarificationRequest struct {
	Question string
	Options  []string
	Lifetime time.Duration
}

// AuthorizationClarificationRound is one durably retained question and its
// optional Agent response. Empty Response and RespondedAt identify an active
// question. Values returned by this package are independent copies.
type AuthorizationClarificationRound struct {
	Question    string
	Options     []string
	RequestedAt time.Time
	ExpiresAt   time.Time
	Response    string
	RespondedAt time.Time
}

// AuthorizationInteractionPolicy requests host-authenticated consent for a
// fully verified three-party auth-token request.
type AuthorizationInteractionPolicy struct {
	URL        string
	Lifetime   time.Duration
	RetryAfter time.Duration
}

// PendingAuthorizationRecord is the immutable verified authorization context
// retained before the Person Server exposes an interaction. CodeSHA256 is the
// normalized code digest; the plaintext correlation code is never retained.
// PersonTokenExpiresAt is the verified expiry of the Person token presented to
// the Person Server; the approved Auth token never outlives it. AgentTokenJTI
// names the Agent token that started the request and SubagentTokenJTI, for a
// parent-mediated request, the sub-agent token; both were issued by
// AgentProvider, and its revocation of either ends the wait.
type PendingAuthorizationRecord struct {
	ID                       string
	CodeSHA256               [32]byte
	PersonServer             string
	AgentProvider            string
	Agent                    string
	AgentTokenJTI            string
	Subagent                 string
	SubagentTokenJTI         string
	Resource                 string
	Subject                  string
	Tenant                   string
	MissionS256              string
	MissionExpiresAt         time.Time
	Scopes                   []string
	Confirmation             jose.JWK
	AgentExpiresAt           time.Time
	SubagentConfirmation     jose.JWK
	SubagentExpiresAt        time.Time
	ResourceTokenExpiresAt   time.Time
	PersonTokenExpiresAt     time.Time
	AgentAdditionalClaims    map[string]json.RawMessage
	SubagentAdditionalClaims map[string]json.RawMessage
	Capabilities             []string
	// BudgetOffer is the verified resource-token offer. Approval must narrow
	// it; a nil offer forbids a Budget on the decision.
	BudgetOffer *budgets.Value
	CreatedAt   time.Time
	ExpiresAt   time.Time
	RetryAfter  time.Duration
}

// AuthorizationApproval is the canonical host decision and PS-issued token
// retained atomically before polling can expose either value. Stores compare
// decisions semantically by lifetime and scope set, ignoring scope order; the
// first retained token, decision ordering, and decision time remain canonical.
type AuthorizationApproval struct {
	Decision  AuthorizationDecision
	Token     string
	ExpiresIn int64
	DecidedAt time.Time
}

// AuthorizationPollIdentity binds each poll to the original Agent and key.
type AuthorizationPollIdentity struct {
	PersonServer           string
	AgentProvider          string
	Agent                  string
	ConfirmationThumbprint string
}

// AuthorizationCodePresentation is one non-plaintext interaction-code attempt.
// SyntacticallyValid is true only when CodeSHA256 contains the digest of a
// successfully normalized Crockford presentation. A false value carries no
// digest authority but must still traverse the store's atomic expiry and
// failed-attempt transition.
type AuthorizationCodePresentation struct {
	CodeSHA256         [32]byte
	SyntacticallyValid bool
}

// AuthorizationPollState is one PS Token Endpoint pending state.
type AuthorizationPollState uint8

const (
	AuthorizationPollWaiting AuthorizationPollState = iota + 1
	AuthorizationPollInteracting
	AuthorizationPollClarifying
	AuthorizationPollApproved
	AuthorizationPollDenied
	AuthorizationPollAbandoned
	AuthorizationPollServerError
	AuthorizationPollExpired
	AuthorizationPollGone
	AuthorizationPollCancelled
)

// AuthorizationPollRecord is the exact store result about to become one HTTP
// response. Pending is returned atomically with the state so the Person Server
// can validate the retained result against its original verified context.
type AuthorizationPollRecord struct {
	State   AuthorizationPollState
	Pending PendingAuthorizationRecord
	// Clarification is present only while the Agent owes an answer.
	Clarification *AuthorizationClarificationRound
	Token         string
	Decision      AuthorizationDecision
	ExpiresIn     int64
	DecidedAt     time.Time
	RetryAfter    time.Duration
}

// PendingAuthorizationSnapshot lets an authenticated host resume an
// interaction and recover the canonical result of an uncertain decision.
type PendingAuthorizationSnapshot struct {
	Record         PendingAuthorizationRecord
	State          AuthorizationPollState
	Clarifications []AuthorizationClarificationRound
	CancelledAt    time.Time
	Approval       AuthorizationApproval
}

// DeferredAuthorizationStore owns only PS auth-token interaction state. It is
// separate from TokenStore and cannot issue or retain person tokens.
//
// Implementations atomically create one unique pending record. Consume must
// match the Person Server and reference, materialize expiry, then treat either
// a syntactically invalid presentation or a nonmatching valid digest as one
// failed attempt while the record is waiting. It changes the record to gone
// when MaximumAuthorizationCodeAttempts is reached. Once a
// valid code moves the record to interacting, every later code presentation
// returns ErrAuthorizationInteractionCodeUsed without changing state. Consume
// must never return a successful record for SyntacticallyValid=false. Expired
// has precedence when the deadline is reached before attempt counting. A
// terminal state committed before the deadline remains terminal. The plaintext
// code is never passed to or retained by the store.
//
// Implementations also retain one exact approval, denial, abandonment, or
// server failure, authenticate every poll identity, and compare and consume one
// exact terminal result immediately before HTTP delivery. Approve returns the
// first canonical retained approval.
// A proposed approval with the same lifetime and scope set is idempotent even
// when its scope order, token bytes, token ID, or decision time differs. A
// different decision conflicts. Repeated denial, abandonment, or failure is
// idempotent. Every mutable value crossing the contract is an independent copy.
// Approve requires a complete proposal while the record is interacting: valid
// decision, nonempty token, positive ExpiresIn, and decision time before the
// deadline. Load exposes the complete canonical approval in approved state.
//
// Every transition that accepts a time must first atomically materialize
// expired when a waiting or interacting record is at or past ExpiresAt. Load
// has the same responsibility. A terminal state committed before the deadline
// remains terminal after it. Poll returns the canonical expired state as
// AuthorizationPollExpired so the server can consume one 408 response; it does
// not return ErrPendingAuthorizationExpired for that ordinary transition.
type DeferredAuthorizationStore interface {
	CreatePendingAuthorization(context.Context, PendingAuthorizationRecord) error
	ConsumeAuthorizationInteractionCode(context.Context, string, string, AuthorizationCodePresentation, time.Time) (PendingAuthorizationRecord, error)
	LoadPendingAuthorization(context.Context, string, time.Time) (PendingAuthorizationSnapshot, error)
	ApprovePendingAuthorization(context.Context, string, AuthorizationApproval) (AuthorizationApproval, error)
	DenyPendingAuthorization(context.Context, string, time.Time) error
	AbandonPendingAuthorization(context.Context, string, time.Time) error
	FailPendingAuthorization(context.Context, string, time.Time) error
	PollPendingAuthorization(context.Context, string, AuthorizationPollIdentity, time.Time) (AuthorizationPollRecord, error)
	ConsumePendingAuthorizationResult(context.Context, string, AuthorizationPollRecord) error
}

// MissionDeferredAuthorizationStore adds mission-aware transitions to a
// DeferredAuthorizationStore. A configured implementation is also the
// MissionStore supplied through PSAuthorizationConfig.Tokens, so each method
// runs in the same backend transaction as mission state. Creation, host
// decisions, and clarification transitions compare the complete expected
// mission and reject a stale host view. Approval atomically retains the
// issued-token record. Poll and consume use expected only for its Agent and
// S256: they atomically require that same owned mission to remain active and
// unexpired, but MUST ignore accepted-update differences because Core keeps
// mission_s256 and already-issued tokens valid across updates.
type MissionDeferredAuthorizationStore interface {
	CreateMissionPendingAuthorization(context.Context, MissionRecord, PendingAuthorizationRecord, time.Time) error
	ApproveMissionPendingAuthorization(context.Context, MissionRecord, string, AuthorizationApproval, IssuedAuthTokenRecord, time.Time) (AuthorizationApproval, error)
	DenyMissionPendingAuthorization(context.Context, MissionRecord, string, time.Time) error
	AbandonMissionPendingAuthorization(context.Context, MissionRecord, string, time.Time) error
	FailMissionPendingAuthorization(context.Context, MissionRecord, string, time.Time) error
	PollMissionPendingAuthorization(context.Context, MissionRecord, string, AuthorizationPollIdentity, time.Time) (AuthorizationPollRecord, error)
	ConsumeMissionPendingAuthorizationResult(context.Context, MissionRecord, string, AuthorizationPollRecord, time.Time) error
}

// AuthorizationClarificationStore is the optional clarification extension to
// DeferredAuthorizationStore. Keeping it separate means an application that
// supports ordinary interaction is not required to implement chat state. A
// configured store that supports clarification implements both interfaces over
// the same pending records.
//
// Every method first atomically materializes pending or active-question expiry.
// Identity mismatch is reported as ErrPendingAuthorizationNotFound. Mutable
// inputs and outputs are independent copies, and an error commits no partial
// transition.
//
// RequestPendingAuthorizationClarification changes Interacting to Clarifying
// and appends one round, up to MaximumAuthorizationClarificationRounds. An
// exact repeat while that question is active returns the first canonical round
// and timestamps; a changed repeat conflicts. AnswerPendingAuthorizationClarification
// changes Clarifying back to Interacting and retains the answer. While that
// answered round remains latest and no later question is active, an exact
// answer replay succeeds and a changed replay conflicts.
// CancelPendingAuthorizationClarification changes Clarifying to Cancelled and
// retains CancelledAt for host observation. Every later request to that
// pending URL is gone. Other terminal or non-clarifying states conflict.
// PollPendingAuthorization must expose only
// the active question and return ErrPendingAuthorizationGone after cancellation;
// LoadPendingAuthorization exposes the complete ordered dialogue and terminal
// cancellation time.
type AuthorizationClarificationStore interface {
	RequestPendingAuthorizationClarification(context.Context, string, AuthorizationClarificationRequest, time.Time) (AuthorizationClarificationRound, error)
	AnswerPendingAuthorizationClarification(context.Context, string, AuthorizationPollIdentity, string, time.Time) error
	CancelPendingAuthorizationClarification(context.Context, string, AuthorizationPollIdentity, time.Time) error
}

// MissionAuthorizationClarificationStore is the optional clarification
// extension for a mission-bound deferred authorization. It preserves the same
// focused question, answer, and cancellation API while checking the exact
// active mission in the transaction that changes the dialogue.
type MissionAuthorizationClarificationStore interface {
	RequestMissionPendingAuthorizationClarification(context.Context, MissionRecord, string, AuthorizationClarificationRequest, time.Time) (AuthorizationClarificationRound, error)
	AnswerMissionPendingAuthorizationClarification(context.Context, MissionRecord, string, AuthorizationPollIdentity, string, time.Time) error
	CancelMissionPendingAuthorizationClarification(context.Context, MissionRecord, string, AuthorizationPollIdentity, time.Time) error
}

// AuthorizationInteraction is a correlated auth-token request. It is not
// proof that a host authenticated the person and carries no decision authority.
type AuthorizationInteraction struct {
	kind           uint8
	record         PendingAuthorizationRecord
	mission        *MissionContext
	missionRecord  *MissionRecord
	clarifications []AuthorizationClarificationRound
	cancelledAt    time.Time
}

const authorizationInteractionCorrelated uint8 = 1

// AgentProvider returns the issuer of the verified Agent token.
func (value AuthorizationInteraction) AgentProvider() string { return value.record.AgentProvider }

// Agent returns the verified Agent that requested authorization.
func (value AuthorizationInteraction) Agent() string { return value.record.Agent }

// Subagent returns the child credential recipient for a parent-mediated
// request. The bool is false for a top-level request.
func (value AuthorizationInteraction) Subagent() (string, bool) {
	if value.record.Subagent == "" {
		return "", false
	}
	return value.record.Subagent, true
}

// Resource returns the Resource named by the verified resource token.
func (value AuthorizationInteraction) Resource() string { return value.record.Resource }

// Subject returns the directed person identifier in the Person Server namespace.
func (value AuthorizationInteraction) Subject() string { return value.record.Subject }

// Tenant returns the verified tenant context, if any.
func (value AuthorizationInteraction) Tenant() string { return value.record.Tenant }

// Mission returns a caller-owned exact mission context for a mission-bound
// interaction. The bool is false for a missionless interaction.
func (value AuthorizationInteraction) Mission() (MissionContext, bool) {
	if value.kind != authorizationInteractionCorrelated || value.mission == nil {
		return MissionContext{}, false
	}
	return *cloneMissionContext(value.mission), true
}

// RequestedScopes returns an independent copy of the exact ordered request.
func (value AuthorizationInteraction) RequestedScopes() []string {
	return append([]string(nil), value.record.Scopes...)
}

// Capabilities returns an independent copy of the Agent's declared values.
func (value AuthorizationInteraction) Capabilities() []string {
	return append([]string(nil), value.record.Capabilities...)
}

// AgentAdditionalClaims returns an independent copy for authenticated host policy.
func (value AuthorizationInteraction) AgentAdditionalClaims() map[string]json.RawMessage {
	return cloneClaims(value.record.AgentAdditionalClaims)
}

// SubagentAdditionalClaims returns the child Agent Provider claims for a
// parent-mediated request. A top-level request returns nil.
func (value AuthorizationInteraction) SubagentAdditionalClaims() map[string]json.RawMessage {
	if value.record.Subagent == "" {
		return nil
	}
	return cloneClaims(value.record.SubagentAdditionalClaims)
}

// Reference returns the non-secret continuation reference.
func (value AuthorizationInteraction) Reference() string { return value.record.ID }

// ExpiresAt returns the effective pending deadline.
func (value AuthorizationInteraction) ExpiresAt() time.Time { return value.record.ExpiresAt }

func validateAuthorizationInteractionPolicy(policy AuthorizationInteractionPolicy) error {
	if _, err := aauth.FormatInteractionRequirement(aauth.InteractionRequirement{URL: policy.URL, Code: "0000-0000"}); err != nil {
		return fmt.Errorf("personserver: authorization interaction URL: %w", err)
	}
	if policy.Lifetime <= 0 {
		return errors.New("personserver: authorization interaction lifetime must be positive")
	}
	if policy.RetryAfter < 0 || policy.RetryAfter%time.Second != 0 {
		return errors.New("personserver: authorization interaction retry interval must be nonnegative whole seconds")
	}
	return nil
}

func validatePendingAuthorizationRecord(record PendingAuthorizationRecord) error {
	if record.ID == "" || record.CodeSHA256 == ([32]byte{}) || record.PersonServer == "" ||
		record.AgentProvider == "" || record.Agent == "" || record.AgentTokenJTI == "" || record.Resource == "" || record.Subject == "" ||
		record.AgentExpiresAt.IsZero() || record.ResourceTokenExpiresAt.IsZero() || record.PersonTokenExpiresAt.IsZero() ||
		record.CreatedAt.IsZero() || !record.ExpiresAt.After(record.CreatedAt) || record.AgentExpiresAt.Before(record.ExpiresAt) ||
		record.ResourceTokenExpiresAt.Before(record.ExpiresAt) || record.PersonTokenExpiresAt.Before(record.ExpiresAt) ||
		record.RetryAfter < 0 || record.RetryAfter%time.Second != 0 {
		return errors.New("personserver: pending authorization record is invalid")
	}
	if err := aauth.ValidateServerIdentifier(record.PersonServer); err != nil {
		return err
	}
	if err := aauth.ValidateServerIdentifier(record.AgentProvider); err != nil {
		return err
	}
	if err := aauth.ValidateAgentIdentifier(record.Agent); err != nil {
		return err
	}
	if err := aauth.ValidateAgentRelationship(record.Agent, ""); err != nil {
		return err
	}
	if record.Subagent == "" {
		if record.SubagentConfirmation != (jose.JWK{}) || !record.SubagentExpiresAt.IsZero() ||
			len(record.SubagentAdditionalClaims) != 0 || record.SubagentTokenJTI != "" {
			return errors.New("personserver: top-level pending authorization has sub-agent context")
		}
	} else {
		if err := aauth.ValidateAgentRelationship(record.Subagent, record.Agent); err != nil {
			return err
		}
		if record.SubagentTokenJTI == "" || record.SubagentExpiresAt.IsZero() || record.SubagentExpiresAt.Before(record.ExpiresAt) ||
			record.SubagentConfirmation == (jose.JWK{}) || record.SubagentConfirmation.Equal(record.Confirmation) {
			return errors.New("personserver: delegated pending authorization is inconsistent")
		}
		if _, err := record.SubagentConfirmation.PublicKey(); err != nil {
			return fmt.Errorf("personserver: pending sub-agent confirmation key: %w", err)
		}
	}
	if err := aauth.ValidateServerIdentifier(record.Resource); err != nil {
		return err
	}
	if _, err := record.Confirmation.PublicKey(); err != nil {
		return fmt.Errorf("personserver: pending authorization confirmation key: %w", err)
	}
	if _, err := parseScopes(strings.Join(record.Scopes, " ")); err != nil {
		return err
	}
	if len(record.Capabilities) > 0 {
		if _, err := aauth.FormatCapabilities(record.Capabilities); err != nil {
			return err
		}
	}
	if record.BudgetOffer != nil {
		if _, err := json.Marshal(record.BudgetOffer); err != nil {
			return fmt.Errorf("personserver: pending authorization budget: %w", err)
		}
	}
	if record.MissionS256 != "" {
		if err := aauth.ValidateMissionS256(record.MissionS256); err != nil {
			return err
		}
	} else if !record.MissionExpiresAt.IsZero() {
		return errors.New("personserver: missionless pending authorization has a mission expiry")
	}
	return nil
}

func (server *Server) beginAuthorizationInteraction(
	response http.ResponseWriter,
	request *http.Request,
	authorization AuthorizationRequest,
	agent aauth.AgentTokenClaims,
	credentialAgent aauth.AgentTokenClaims,
	resourceToken aauth.ResourceTokenClaims,
	missionRecord *MissionRecord,
	policy AuthorizationInteractionPolicy,
	personTokenExpiresAt time.Time,
	createdAt time.Time,
) error {
	if server.authorizationInteractions == nil {
		return errors.New("personserver: deferred authorization store is required")
	}
	if err := validateAuthorizationInteractionPolicy(policy); err != nil {
		return err
	}
	// Keep the verified request's admission time across host policy work.
	// A binding replaced while policy runs must not adopt the old request.
	createdAt = createdAt.UTC()
	expiresAt := createdAt.Add(policy.Lifetime)
	// Approval must finish while the retained Person token is current.
	if personTokenExpiresAt.Before(expiresAt) {
		expiresAt = personTokenExpiresAt
	}
	if !expiresAt.After(server.clock.Now()) {
		return ErrPendingAuthorizationExpired
	}
	agentExpiresAt := time.Unix(agent.ExpiresAt, 0).UTC()
	credentialAgentExpiresAt := time.Unix(credentialAgent.ExpiresAt, 0).UTC()
	resourceTokenExpiresAt := time.Unix(resourceToken.ExpiresAt, 0).UTC()
	if agentExpiresAt.Before(expiresAt) {
		expiresAt = agentExpiresAt
	}
	if credentialAgentExpiresAt.Before(expiresAt) {
		expiresAt = credentialAgentExpiresAt
	}
	if resourceTokenExpiresAt.Before(expiresAt) {
		expiresAt = resourceTokenExpiresAt
	}
	if missionRecord != nil && !missionRecord.ExpiresAt.IsZero() && missionRecord.ExpiresAt.Before(expiresAt) {
		expiresAt = missionRecord.ExpiresAt
	}
	if !expiresAt.After(server.clock.Now()) {
		return ErrPendingAuthorizationExpired
	}
	for attempt := 0; attempt < 3; attempt++ {
		id, err := interaction.GeneratePendingReference(nil)
		if err != nil {
			return fmt.Errorf("personserver: generate pending authorization identifier: %w", err)
		}
		code, err := interaction.GenerateCode(nil)
		if err != nil {
			return fmt.Errorf("personserver: generate authorization interaction code: %w", err)
		}
		interactionURL, err := pendingInteractionURL(policy.URL, id)
		if err != nil {
			return err
		}
		requirement, err := aauth.FormatInteractionRequirement(aauth.InteractionRequirement{URL: interactionURL, Code: code})
		if err != nil {
			return err
		}
		digest, err := interaction.Digest(code)
		if err != nil {
			return err
		}
		var missionExpiresAt time.Time
		if missionRecord != nil {
			missionExpiresAt = missionRecord.ExpiresAt
		}
		record := PendingAuthorizationRecord{
			ID: id, CodeSHA256: digest, PersonServer: server.issuer,
			AgentProvider: agent.Issuer, Agent: authorization.Agent, AgentTokenJTI: agent.JTI, Resource: authorization.Resource,
			Subject: authorization.Subject, Tenant: authorization.Tenant, MissionS256: resourceToken.MissionS256,
			MissionExpiresAt: missionExpiresAt,
			Scopes:           append([]string(nil), authorization.Scopes...), Confirmation: agent.Confirmation.JWK,
			AgentExpiresAt: agentExpiresAt, ResourceTokenExpiresAt: resourceTokenExpiresAt,
			PersonTokenExpiresAt:  personTokenExpiresAt.UTC(),
			AgentAdditionalClaims: cloneClaims(authorization.AgentAdditionalClaims),
			Capabilities:          append([]string(nil), authorization.Capabilities...),
			BudgetOffer:           cloneBudgetValue(authorization.Budget),
			CreatedAt:             createdAt, ExpiresAt: expiresAt, RetryAfter: policy.RetryAfter,
		}
		if authorization.Subagent != "" {
			record.Subagent = authorization.Subagent
			record.SubagentTokenJTI = credentialAgent.JTI
			record.SubagentConfirmation = credentialAgent.Confirmation.JWK
			record.SubagentExpiresAt = credentialAgentExpiresAt
			record.SubagentAdditionalClaims = cloneClaims(authorization.SubagentAdditionalClaims)
		}
		if err := validatePendingAuthorizationRecord(record); err != nil {
			return err
		}
		var createErr error
		if missionRecord != nil {
			if server.missionAuthorizationInteractions == nil || missionRecord.S256 != record.MissionS256 ||
				authorization.Mission == nil || authorization.Mission.S256 != record.MissionS256 {
				return ErrPendingAuthorizationConflict
			}
			createErr = server.missionAuthorizationInteractions.CreateMissionPendingAuthorization(
				request.Context(), cloneMissionRecordForTransition(*missionRecord), record, server.clock.Now().UTC(),
			)
		} else {
			createErr = server.authorizationInteractions.CreatePendingAuthorization(request.Context(), record)
		}
		if createErr != nil {
			if errors.Is(createErr, ErrPendingAuthorizationConflict) {
				continue
			}
			return createErr
		}
		response.Header().Set("Location", "/token/pending/"+id)
		response.Header().Set("Retry-After", strconv.FormatInt(int64(policy.RetryAfter/time.Second), 10))
		response.Header().Set("AAuth-Requirement", requirement)
		writePrivateJSON(response, http.StatusAccepted, struct {
			Status string `json:"status"`
		}{Status: "pending"})
		return nil
	}
	return errors.New("personserver: could not allocate a unique pending authorization")
}

// ConsumeAuthorizationInteractionCode correlates one host visit and consumes
// its code. The host must authenticate the person separately before deciding.
func (server *Server) ConsumeAuthorizationInteractionCode(ctx context.Context, reference, code string) (AuthorizationInteraction, error) {
	if server == nil || server.authorizationInteractions == nil {
		return AuthorizationInteraction{}, errors.New("personserver: authorization interactions are not configured")
	}
	if ctx == nil {
		return AuthorizationInteraction{}, errors.New("personserver: context is required")
	}
	if reference == "" {
		return AuthorizationInteraction{}, ErrAuthorizationInteractionCodeInvalid
	}
	presentation := AuthorizationCodePresentation{}
	if digest, err := interaction.Digest(code); err == nil {
		presentation.CodeSHA256 = digest
		presentation.SyntacticallyValid = true
	}
	now := server.clock.Now().UTC()
	record, err := server.authorizationInteractions.ConsumeAuthorizationInteractionCode(
		ctx, server.issuer, reference, presentation, now,
	)
	if err != nil {
		return AuthorizationInteraction{}, err
	}
	if !presentation.SyntacticallyValid {
		return AuthorizationInteraction{}, ErrPendingAuthorizationConflict
	}
	if err := validatePendingAuthorizationRecord(record); err != nil {
		return AuthorizationInteraction{}, err
	}
	if record.ID != reference || record.PersonServer != server.issuer || record.CodeSHA256 != presentation.CodeSHA256 {
		return AuthorizationInteraction{}, ErrPendingAuthorizationConflict
	}
	return server.authorizationInteractionFromRecord(ctx, record, now)
}

// ResumeAuthorizationInteraction reconstructs a host handle from durable state.
func (server *Server) ResumeAuthorizationInteraction(ctx context.Context, reference string) (AuthorizationInteraction, error) {
	if server == nil || server.authorizationInteractions == nil {
		return AuthorizationInteraction{}, errors.New("personserver: authorization interactions are not configured")
	}
	if ctx == nil {
		return AuthorizationInteraction{}, errors.New("personserver: context is required")
	}
	if reference == "" {
		return AuthorizationInteraction{}, errors.New("personserver: authorization interaction reference is required")
	}
	now := server.clock.Now().UTC()
	snapshot, err := server.authorizationInteractions.LoadPendingAuthorization(ctx, reference, now)
	if err != nil {
		return AuthorizationInteraction{}, err
	}
	if err := server.validatePendingAuthorizationSnapshot(ctx, snapshot); err != nil {
		return AuthorizationInteraction{}, err
	}
	if snapshot.Record.ID != reference {
		return AuthorizationInteraction{}, ErrPendingAuthorizationConflict
	}
	switch snapshot.State {
	case AuthorizationPollWaiting, AuthorizationPollInteracting, AuthorizationPollClarifying, AuthorizationPollApproved, AuthorizationPollDenied,
		AuthorizationPollAbandoned, AuthorizationPollServerError:
		return server.authorizationInteractionFromSnapshot(ctx, snapshot, now)
	case AuthorizationPollCancelled:
		return server.authorizationInteractionFromSnapshot(ctx, snapshot, now)
	case AuthorizationPollExpired:
		return AuthorizationInteraction{}, ErrPendingAuthorizationExpired
	case AuthorizationPollGone:
		return AuthorizationInteraction{}, ErrPendingAuthorizationGone
	default:
		return AuthorizationInteraction{}, ErrPendingAuthorizationConflict
	}
}

// ApproveAuthorizationInteraction mints and durably retains the exact PS auth
// token selected through a separately authenticated host decision.
func (server *Server) ApproveAuthorizationInteraction(ctx context.Context, value AuthorizationInteraction, decision AuthorizationDecision) error {
	if err := server.validateAuthorizationInteraction(ctx, value); err != nil {
		return err
	}
	granted, err := validateAuthorizationDecision(decision, value.record.Scopes)
	if err != nil {
		return err
	}
	grantedBudget, err := validateBudgetDecision(value.record.BudgetOffer, decision.Budget)
	if err != nil {
		return err
	}
	decision.Scopes = append([]string(nil), granted...)
	decision.Budget = cloneBudgetValue(grantedBudget)
	now := server.clock.Now().UTC()
	snapshot, err := server.loadAuthorizationInteraction(ctx, value, now)
	if err != nil {
		return err
	}
	switch snapshot.State {
	case AuthorizationPollApproved:
		if !authorizationDecisionsSemanticallyEqual(snapshot.Approval.Decision, decision) {
			return ErrPendingAuthorizationConflict
		}
		// loadAuthorizationInteraction already validated the complete canonical
		// snapshot approval against this pending context.
		return nil
	case AuthorizationPollDenied:
		return ErrPendingAuthorizationConflict
	case AuthorizationPollExpired:
		return ErrPendingAuthorizationExpired
	case AuthorizationPollGone, AuthorizationPollCancelled:
		return ErrPendingAuthorizationGone
	case AuthorizationPollInteracting:
		// Continue below.
	default:
		return ErrPendingAuthorizationConflict
	}
	if !now.Before(value.record.ExpiresAt) || !now.Before(value.record.AgentExpiresAt) ||
		(!value.record.SubagentExpiresAt.IsZero() && !now.Before(value.record.SubagentExpiresAt)) {
		return ErrPendingAuthorizationExpired
	}
	// Record.Agent is the top-level requester whose binding authorized the
	// request, including one it mediates for a sub-agent; a revoked Agent
	// token the request was made with refuses the decision too.
	if err := server.checkPendingRevocations(ctx, value.record.AgentProvider, value.record.Agent,
		value.record.AgentTokenJTI, value.record.SubagentTokenJTI, value.record.CreatedAt); err != nil {
		return err
	}
	// The pending deadline bounds only when approval may happen; it does not
	// shorten the Auth token, which stays inside its predecessor tokens.
	expiresAt := now.Add(decision.Lifetime)
	if value.record.PersonTokenExpiresAt.Before(expiresAt) {
		expiresAt = value.record.PersonTokenExpiresAt
	}
	if value.record.AgentExpiresAt.Before(expiresAt) {
		expiresAt = value.record.AgentExpiresAt
	}
	if !value.record.SubagentExpiresAt.IsZero() && value.record.SubagentExpiresAt.Before(expiresAt) {
		expiresAt = value.record.SubagentExpiresAt
	}
	if !value.record.MissionExpiresAt.IsZero() && value.record.MissionExpiresAt.Before(expiresAt) {
		expiresAt = value.record.MissionExpiresAt
	}
	if !expiresAt.After(now) {
		return ErrPendingAuthorizationExpired
	}
	confirmation := value.record.Confirmation
	if value.record.Subagent != "" {
		confirmation = value.record.SubagentConfirmation
	}
	claims := aauth.AuthTokenClaims{
		Issuer: server.issuer, DWK: aauth.PersonDiscoveryDocument, Audience: value.record.Resource,
		JTI: server.newID(), PersonServer: server.issuer, Subject: value.record.Subject,
		Confirmation: aauth.Confirmation{JWK: confirmation},
		IssuedAt:     now.Unix(), ExpiresAt: expiresAt.Unix(), Scope: strings.Join(granted, " "),
		MissionS256: value.record.MissionS256, Tenant: value.record.Tenant,
	}
	var compact string
	if grantedBudget != nil {
		compact, err = budgets.MintAuthToken(server.signingKey, claims, *grantedBudget)
	} else {
		compact, err = aauth.MintAuthToken(server.signingKey, claims)
	}
	if err != nil {
		return err
	}
	approval := AuthorizationApproval{
		Decision: decision, Token: compact, ExpiresIn: claims.ExpiresAt - claims.IssuedAt, DecidedAt: now,
	}
	var canonical AuthorizationApproval
	if value.missionRecord != nil {
		issued, recordErr := issuedAuthTokenRecord(compact, claims)
		if recordErr != nil {
			return recordErr
		}
		canonical, err = server.missionAuthorizationInteractions.ApproveMissionPendingAuthorization(
			ctx, cloneMissionRecordForTransition(*value.missionRecord), value.record.ID, approval, issued, server.clock.Now().UTC(),
		)
	} else {
		canonical, err = server.authorizationInteractions.ApprovePendingAuthorization(ctx, value.record.ID, approval)
	}
	if err != nil {
		return err
	}
	return server.validateCanonicalAuthorizationApproval(ctx, value.record, canonical)
}

func (server *Server) validateCanonicalAuthorizationApproval(
	ctx context.Context,
	pending PendingAuthorizationRecord,
	canonical AuthorizationApproval,
) error {
	thumbprint, err := pending.Confirmation.Thumbprint()
	if err != nil {
		return err
	}
	result := AuthorizationPollRecord{
		State: AuthorizationPollApproved, Pending: clonePendingAuthorizationRecord(pending),
		Token: canonical.Token, Decision: cloneAuthorizationDecision(canonical.Decision),
		ExpiresIn: canonical.ExpiresIn, DecidedAt: canonical.DecidedAt, RetryAfter: pending.RetryAfter,
	}
	if err := server.validateAuthorizationPollContext(pending.ID, AuthorizationPollIdentity{
		PersonServer: server.issuer, AgentProvider: pending.AgentProvider, Agent: pending.Agent,
		ConfirmationThumbprint: thumbprint,
	}, result); err != nil {
		return err
	}
	_, err = server.validateApprovedAuthorization(ctx, result)
	return err
}

// DenyAuthorizationInteraction durably retains a host-authenticated denial.
func (server *Server) DenyAuthorizationInteraction(ctx context.Context, value AuthorizationInteraction) error {
	now := server.clock.Now().UTC()
	snapshot, err := server.loadAuthorizationInteraction(ctx, value, now)
	if err != nil {
		return err
	}
	switch snapshot.State {
	case AuthorizationPollDenied:
		return nil
	case AuthorizationPollApproved:
		return ErrPendingAuthorizationConflict
	case AuthorizationPollExpired:
		return ErrPendingAuthorizationExpired
	case AuthorizationPollGone, AuthorizationPollCancelled:
		return ErrPendingAuthorizationGone
	case AuthorizationPollInteracting:
		// Continue below.
	default:
		return ErrPendingAuthorizationConflict
	}
	if !now.Before(value.record.ExpiresAt) {
		return ErrPendingAuthorizationExpired
	}
	if value.missionRecord != nil {
		now = server.clock.Now().UTC()
		return server.missionAuthorizationInteractions.DenyMissionPendingAuthorization(
			ctx, cloneMissionRecordForTransition(*value.missionRecord), value.record.ID, now,
		)
	}
	return server.authorizationInteractions.DenyPendingAuthorization(ctx, value.record.ID, now)
}

// AbandonAuthorizationInteraction durably retains that the person opened the
// interaction but did not complete it.
func (server *Server) AbandonAuthorizationInteraction(ctx context.Context, value AuthorizationInteraction) error {
	now := server.clock.Now().UTC()
	snapshot, err := server.loadAuthorizationInteraction(ctx, value, now)
	if err != nil {
		return err
	}
	switch snapshot.State {
	case AuthorizationPollAbandoned:
		return nil
	case AuthorizationPollGone, AuthorizationPollCancelled:
		return ErrPendingAuthorizationGone
	case AuthorizationPollInteracting:
		if value.missionRecord != nil {
			now = server.clock.Now().UTC()
			return server.missionAuthorizationInteractions.AbandonMissionPendingAuthorization(
				ctx, cloneMissionRecordForTransition(*value.missionRecord), value.record.ID, now,
			)
		}
		return server.authorizationInteractions.AbandonPendingAuthorization(ctx, value.record.ID, now)
	case AuthorizationPollExpired:
		return ErrPendingAuthorizationExpired
	default:
		return ErrPendingAuthorizationConflict
	}
}

// FailAuthorizationInteraction durably retains a host-side interaction failure
// without exposing internal error details to the Agent.
func (server *Server) FailAuthorizationInteraction(ctx context.Context, value AuthorizationInteraction) error {
	now := server.clock.Now().UTC()
	snapshot, err := server.loadAuthorizationInteraction(ctx, value, now)
	if err != nil {
		return err
	}
	switch snapshot.State {
	case AuthorizationPollServerError:
		return nil
	case AuthorizationPollGone, AuthorizationPollCancelled:
		return ErrPendingAuthorizationGone
	case AuthorizationPollWaiting, AuthorizationPollInteracting:
		if value.missionRecord != nil {
			now = server.clock.Now().UTC()
			return server.missionAuthorizationInteractions.FailMissionPendingAuthorization(
				ctx, cloneMissionRecordForTransition(*value.missionRecord), value.record.ID, now,
			)
		}
		return server.authorizationInteractions.FailPendingAuthorization(ctx, value.record.ID, now)
	case AuthorizationPollExpired:
		return ErrPendingAuthorizationExpired
	default:
		return ErrPendingAuthorizationConflict
	}
}

func (server *Server) authorizationInteractionFromRecord(
	ctx context.Context,
	record PendingAuthorizationRecord,
	at time.Time,
) (AuthorizationInteraction, error) {
	value := AuthorizationInteraction{kind: authorizationInteractionCorrelated, record: clonePendingAuthorizationRecord(record)}
	if record.MissionS256 == "" {
		return value, nil
	}
	if server.missionAuthorizationInteractions == nil {
		return AuthorizationInteraction{}, ErrPendingAuthorizationConflict
	}
	mission, err := server.loadActiveMission(ctx, record.MissionS256, record.Agent, at)
	if err != nil {
		return AuthorizationInteraction{}, err
	}
	if !record.MissionExpiresAt.Equal(mission.ExpiresAt) {
		return AuthorizationInteraction{}, ErrMissionConflict
	}
	missionContext, err := missionContextFromRecord(mission)
	if err != nil {
		return AuthorizationInteraction{}, err
	}
	value.mission = missionContext
	clone := cloneMissionRecordForTransition(mission)
	value.missionRecord = &clone
	return value, nil
}

func (server *Server) authorizationInteractionFromSnapshot(
	ctx context.Context,
	snapshot PendingAuthorizationSnapshot,
	at time.Time,
) (AuthorizationInteraction, error) {
	value, err := server.authorizationInteractionFromRecord(ctx, snapshot.Record, at)
	if err != nil {
		return AuthorizationInteraction{}, err
	}
	value.clarifications = cloneAuthorizationClarifications(snapshot.Clarifications)
	value.cancelledAt = snapshot.CancelledAt
	return value, nil
}

func (server *Server) validateAuthorizationInteraction(ctx context.Context, value AuthorizationInteraction) error {
	if server == nil || server.authorizationInteractions == nil {
		return errors.New("personserver: authorization interactions are not configured")
	}
	if ctx == nil {
		return errors.New("personserver: context is required")
	}
	if value.kind != authorizationInteractionCorrelated || value.record.PersonServer != server.issuer {
		return errors.New("personserver: correlated authorization interaction is required")
	}
	if err := validatePendingAuthorizationRecord(value.record); err != nil {
		return errors.New("personserver: correlated authorization interaction is invalid")
	}
	if (value.record.MissionS256 == "") != (value.mission == nil) ||
		(value.record.MissionS256 == "") != (value.missionRecord == nil) {
		return errors.New("personserver: authorization interaction mission state is invalid")
	}
	if value.missionRecord != nil &&
		(value.missionRecord.S256 != value.record.MissionS256 || value.missionRecord.Agent != value.record.Agent ||
			value.mission.S256 != value.record.MissionS256 ||
			!value.missionRecord.ExpiresAt.Equal(value.record.MissionExpiresAt)) {
		return errors.New("personserver: authorization interaction mission state is invalid")
	}
	return nil
}

func (server *Server) loadAuthorizationInteraction(ctx context.Context, value AuthorizationInteraction, now time.Time) (PendingAuthorizationSnapshot, error) {
	if err := server.validateAuthorizationInteraction(ctx, value); err != nil {
		return PendingAuthorizationSnapshot{}, err
	}
	snapshot, err := server.authorizationInteractions.LoadPendingAuthorization(ctx, value.record.ID, now)
	if err != nil {
		return PendingAuthorizationSnapshot{}, err
	}
	if err := server.validatePendingAuthorizationSnapshot(ctx, snapshot); err != nil {
		return PendingAuthorizationSnapshot{}, err
	}
	if !pendingAuthorizationRecordsEqual(snapshot.Record, value.record) {
		return PendingAuthorizationSnapshot{}, ErrPendingAuthorizationConflict
	}
	if value.missionRecord != nil {
		current, err := server.loadActiveMission(ctx, value.missionRecord.S256, value.missionRecord.Agent, now)
		if err != nil {
			return PendingAuthorizationSnapshot{}, err
		}
		if !value.missionRecord.Equal(current) {
			return PendingAuthorizationSnapshot{}, ErrMissionConflict
		}
	}
	return snapshot, nil
}

func (server *Server) validatePendingAuthorizationSnapshot(ctx context.Context, snapshot PendingAuthorizationSnapshot) error {
	if err := validatePendingAuthorizationRecord(snapshot.Record); err != nil || snapshot.Record.PersonServer != server.issuer {
		return ErrPendingAuthorizationConflict
	}
	if err := validateAuthorizationClarificationHistory(snapshot.Record, snapshot.State, snapshot.Clarifications); err != nil {
		return err
	}
	switch snapshot.State {
	case AuthorizationPollWaiting, AuthorizationPollInteracting, AuthorizationPollClarifying, AuthorizationPollDenied,
		AuthorizationPollAbandoned, AuthorizationPollServerError, AuthorizationPollExpired, AuthorizationPollGone:
		if !authorizationApprovalIsZero(snapshot.Approval) {
			return ErrPendingAuthorizationConflict
		}
		if !snapshot.CancelledAt.IsZero() {
			return ErrPendingAuthorizationConflict
		}
	case AuthorizationPollCancelled:
		last := snapshot.Clarifications[len(snapshot.Clarifications)-1]
		if !authorizationApprovalIsZero(snapshot.Approval) || snapshot.CancelledAt.Before(last.RequestedAt) ||
			!snapshot.CancelledAt.Before(last.ExpiresAt) {
			return ErrPendingAuthorizationConflict
		}
	case AuthorizationPollApproved:
		if !snapshot.CancelledAt.IsZero() {
			return ErrPendingAuthorizationConflict
		}
		if err := validateAuthorizationApprovalShape(snapshot.Record, snapshot.Approval); err != nil {
			return ErrPendingAuthorizationConflict
		}
		if err := server.validateCanonicalAuthorizationApproval(ctx, snapshot.Record, snapshot.Approval); err != nil {
			return err
		}
	default:
		return ErrPendingAuthorizationConflict
	}
	return nil
}

func pendingAuthorizationRecordsEqual(left, right PendingAuthorizationRecord) bool {
	return left.ID == right.ID && left.CodeSHA256 == right.CodeSHA256 && left.PersonServer == right.PersonServer &&
		left.AgentProvider == right.AgentProvider && left.Agent == right.Agent && left.Subagent == right.Subagent &&
		left.AgentTokenJTI == right.AgentTokenJTI && left.SubagentTokenJTI == right.SubagentTokenJTI &&
		left.Resource == right.Resource &&
		left.Subject == right.Subject && left.Tenant == right.Tenant && reflect.DeepEqual(left.Scopes, right.Scopes) &&
		left.Confirmation.Equal(right.Confirmation) && left.AgentExpiresAt.Equal(right.AgentExpiresAt) &&
		optionalAuthorizationJWKEqual(left.SubagentConfirmation, right.SubagentConfirmation) &&
		left.SubagentExpiresAt.Equal(right.SubagentExpiresAt) &&
		left.ResourceTokenExpiresAt.Equal(right.ResourceTokenExpiresAt) &&
		left.PersonTokenExpiresAt.Equal(right.PersonTokenExpiresAt) &&
		left.MissionS256 == right.MissionS256 && left.MissionExpiresAt.Equal(right.MissionExpiresAt) &&
		reflect.DeepEqual(left.AgentAdditionalClaims, right.AgentAdditionalClaims) &&
		reflect.DeepEqual(left.SubagentAdditionalClaims, right.SubagentAdditionalClaims) &&
		reflect.DeepEqual(left.Capabilities, right.Capabilities) && left.CreatedAt.Equal(right.CreatedAt) &&
		left.ExpiresAt.Equal(right.ExpiresAt) && left.RetryAfter == right.RetryAfter
}

func optionalAuthorizationJWKEqual(left, right jose.JWK) bool {
	if left == (jose.JWK{}) || right == (jose.JWK{}) {
		return left == right
	}
	return left.Equal(right)
}

func (server *Server) handlePendingAuthorization(response http.ResponseWriter, request *http.Request) {
	switch request.Method {
	case http.MethodPost:
		server.handlePendingAuthorizationClarificationAnswer(response, request)
		return
	case http.MethodDelete:
		server.handlePendingAuthorizationCancellation(response, request)
		return
	case http.MethodGet:
		// Continue below.
	default:
		response.Header().Set("Allow", "GET, POST, DELETE")
		writeProblem(response, http.StatusMethodNotAllowed, "method_not_allowed", errors.New("authorization continuation requires GET, POST, or DELETE"))
		return
	}
	if server.authorizationInteractions == nil {
		writeProblem(response, http.StatusGone, "invalid_code", ErrPendingAuthorizationNotFound)
		return
	}
	if !requestBodyIsEmpty(request) {
		writeProblem(response, http.StatusBadRequest, "invalid_request", errors.New("authorization polling requires a bodyless GET"))
		return
	}
	_, agent, _, err := server.verifyAgentRequest(request, nil)
	if err != nil {
		writeAgentTokenProblem(response, err)
		return
	}
	identity, err := authorizationPollIdentity(server.issuer, agent)
	if err != nil {
		writeAgentTokenProblem(response, err)
		return
	}
	id := request.PathValue("id")
	if id == "" {
		writeProblem(response, http.StatusGone, "invalid_code", ErrPendingAuthorizationNotFound)
		return
	}
	now := server.clock.Now().UTC()
	var mission *MissionRecord
	var result AuthorizationPollRecord
	if server.missionAuthorizationInteractions != nil {
		snapshot, snapshotErr := server.authorizationInteractions.LoadPendingAuthorization(request.Context(), id, now)
		if snapshotErr == nil && snapshot.Record.MissionS256 != "" {
			if !pendingAuthorizationIdentityMatches(snapshot.Record, identity) {
				writeProblem(response, http.StatusGone, "invalid_code", ErrPendingAuthorizationNotFound)
				return
			}
			loaded, loadErr := server.loadActiveMission(request.Context(), snapshot.Record.MissionS256, identity.Agent, now)
			if loadErr != nil {
				writeMissionActionProblem(response, loadErr)
				return
			}
			mission = &loaded
			result, err = server.missionAuthorizationInteractions.PollMissionPendingAuthorization(
				request.Context(), cloneMissionRecordForTransition(loaded), id, identity, now,
			)
		} else if snapshotErr != nil {
			err = snapshotErr
		} else {
			result, err = server.authorizationInteractions.PollPendingAuthorization(request.Context(), id, identity, now)
		}
	} else {
		result, err = server.authorizationInteractions.PollPendingAuthorization(request.Context(), id, identity, now)
	}
	if err != nil {
		if mission != nil {
			writeMissionActionProblem(response, err)
			return
		}
		switch {
		case errors.Is(err, ErrPendingAuthorizationNotFound), errors.Is(err, ErrPendingAuthorizationGone):
			writeProblem(response, http.StatusGone, "invalid_code", err)
		default:
			writeProblem(response, http.StatusInternalServerError, "server_error", err)
		}
		return
	}
	if err := server.validateAuthorizationPollContext(id, identity, result); err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", err)
		return
	}
	switch result.State {
	case AuthorizationPollWaiting, AuthorizationPollInteracting, AuthorizationPollClarifying, AuthorizationPollApproved:
		// A revoked Agent token or binding ends a live request and withholds a
		// retained token. The answer is terminal, so the request is ended first.
		pending := result.Pending
		if err := server.checkPendingRevocations(request.Context(), pending.AgentProvider, pending.Agent,
			pending.AgentTokenJTI, pending.SubagentTokenJTI, pending.CreatedAt); err != nil {
			if pendingRevoked(err) && !server.endPendingAuthorization(response, request, id, identity, result, mission) {
				return
			}
			writePendingRevocationProblem(response, err, http.StatusBadRequest, "revoked_presented_token")
			return
		}
	}
	switch result.State {
	case AuthorizationPollWaiting:
		server.writePendingAuthorization(response, request.URL.Path, result.RetryAfter, "pending")
	case AuthorizationPollInteracting:
		server.writePendingAuthorization(response, request.URL.Path, result.RetryAfter, "interacting")
	case AuthorizationPollClarifying:
		server.writePendingAuthorizationClarification(response, request.URL.Path, result, now)
	case AuthorizationPollApproved:
		claims, err := server.validateApprovedAuthorization(request.Context(), result)
		if err != nil {
			var tokenFailure *aauth.TokenValidationError
			if errors.As(err, &tokenFailure) && tokenFailure.Code == aauth.TokenValidationExpired {
				if server.consumePendingAuthorizationResult(response, request, id, result, mission) {
					writeProblem(response, http.StatusRequestTimeout, "expired", err)
				}
				return
			}
			writeProblem(response, http.StatusInternalServerError, "server_error", err)
			return
		}
		issuedRecord, err := issuedAuthTokenRecord(result.Token, claims)
		if err != nil {
			writeProblem(response, http.StatusInternalServerError, "server_error", err)
			return
		}
		if err := server.commitIssuedAuthToken(request.Context(), issuedRecord); err != nil {
			writeProblem(response, http.StatusInternalServerError, "server_error", err)
			return
		}
		if !server.consumePendingAuthorizationResult(response, request, id, result, mission) {
			return
		}
		writePrivateJSON(response, http.StatusOK, struct {
			AuthToken string `json:"auth_token"`
			ExpiresIn int64  `json:"expires_in"`
		}{AuthToken: result.Token, ExpiresIn: result.ExpiresIn})
	case AuthorizationPollDenied:
		if !server.consumePendingAuthorizationResult(response, request, id, result, mission) {
			return
		}
		writeProblem(response, http.StatusForbidden, "denied", errors.New("authorization interaction was denied"))
	case AuthorizationPollAbandoned:
		if !server.consumePendingAuthorizationResult(response, request, id, result, mission) {
			return
		}
		writeProblem(response, http.StatusForbidden, "abandoned", errors.New("authorization interaction was abandoned"))
	case AuthorizationPollServerError:
		if !server.consumePendingAuthorizationResult(response, request, id, result, mission) {
			return
		}
		writeProblem(response, http.StatusInternalServerError, "server_error", errors.New("authorization interaction failed"))
	case AuthorizationPollExpired:
		if !server.consumePendingAuthorizationResult(response, request, id, result, mission) {
			return
		}
		writeProblem(response, http.StatusRequestTimeout, "expired", ErrPendingAuthorizationExpired)
	case AuthorizationPollGone:
		writeProblem(response, http.StatusGone, "invalid_code", ErrPendingAuthorizationGone)
	default:
		writeProblem(response, http.StatusInternalServerError, "server_error", ErrPendingAuthorizationConflict)
	}
}

func authorizationPollIdentity(personServer string, agent aauth.AgentTokenClaims) (AuthorizationPollIdentity, error) {
	thumbprint, err := agent.Confirmation.JWK.Thumbprint()
	if err != nil {
		return AuthorizationPollIdentity{}, err
	}
	return AuthorizationPollIdentity{
		PersonServer: personServer, AgentProvider: agent.Issuer, Agent: agent.Subject,
		ConfirmationThumbprint: thumbprint,
	}, nil
}

func (server *Server) validateAuthorizationPollContext(id string, identity AuthorizationPollIdentity, result AuthorizationPollRecord) error {
	if err := validatePendingAuthorizationRecord(result.Pending); err != nil || result.Pending.ID != id ||
		result.Pending.PersonServer != identity.PersonServer || result.Pending.AgentProvider != identity.AgentProvider ||
		result.Pending.Agent != identity.Agent {
		return ErrPendingAuthorizationConflict
	}
	thumbprint, err := result.Pending.Confirmation.Thumbprint()
	if err != nil || thumbprint != identity.ConfirmationThumbprint || result.RetryAfter != result.Pending.RetryAfter {
		return ErrPendingAuthorizationConflict
	}
	emptyDecision := len(result.Decision.Scopes) == 0 && result.Decision.Lifetime == 0 && result.Decision.Budget == nil
	switch result.State {
	case AuthorizationPollWaiting, AuthorizationPollInteracting, AuthorizationPollDenied,
		AuthorizationPollAbandoned, AuthorizationPollServerError, AuthorizationPollExpired:
		if result.Clarification != nil || result.Token != "" || !emptyDecision || result.ExpiresIn != 0 || !result.DecidedAt.IsZero() {
			return ErrPendingAuthorizationConflict
		}
	case AuthorizationPollClarifying:
		if result.Clarification == nil || validateAuthorizationClarificationRound(*result.Clarification) != nil ||
			result.Clarification.Response != "" || result.Token != "" || !emptyDecision ||
			result.ExpiresIn != 0 || !result.DecidedAt.IsZero() ||
			result.Clarification.RequestedAt.Before(result.Pending.CreatedAt) ||
			result.Clarification.ExpiresAt.After(result.Pending.ExpiresAt) {
			return ErrPendingAuthorizationConflict
		}
	case AuthorizationPollApproved:
		if result.Clarification != nil || result.Token == "" || result.ExpiresIn <= 0 || result.DecidedAt.IsZero() {
			return ErrPendingAuthorizationConflict
		}
	case AuthorizationPollGone:
		if result.Clarification != nil || result.Token != "" || !emptyDecision || result.ExpiresIn != 0 || !result.DecidedAt.IsZero() {
			return ErrPendingAuthorizationConflict
		}
	default:
		return ErrPendingAuthorizationConflict
	}
	return nil
}

func (server *Server) validateApprovedAuthorization(ctx context.Context, result AuthorizationPollRecord) (aauth.AuthTokenClaims, error) {
	granted, err := validateAuthorizationDecision(result.Decision, result.Pending.Scopes)
	if err != nil {
		return aauth.AuthTokenClaims{}, err
	}
	grantedBudget, err := validateBudgetDecision(result.Pending.BudgetOffer, result.Decision.Budget)
	if err != nil {
		return aauth.AuthTokenClaims{}, err
	}
	if result.DecidedAt.Before(result.Pending.CreatedAt) || !result.DecidedAt.Before(result.Pending.ExpiresAt) ||
		!result.DecidedAt.Before(result.Pending.AgentExpiresAt) || !result.DecidedAt.Before(result.Pending.PersonTokenExpiresAt) ||
		(!result.Pending.SubagentExpiresAt.IsZero() && !result.DecidedAt.Before(result.Pending.SubagentExpiresAt)) ||
		(!result.Pending.MissionExpiresAt.IsZero() && !result.DecidedAt.Before(result.Pending.MissionExpiresAt)) {
		return aauth.AuthTokenClaims{}, errors.New("personserver: approved auth token has an invalid decision time")
	}
	var claims aauth.AuthTokenClaims
	if result.Pending.BudgetOffer != nil {
		verified, grant, verifyErr := budgets.VerifyAuthToken(ctx, result.Token, server.keyResolver, server.clock)
		if verifyErr != nil {
			return aauth.AuthTokenClaims{}, verifyErr
		}
		if !budgetValuesEqual(grant, *grantedBudget) {
			return aauth.AuthTokenClaims{}, errors.New("personserver: approved auth token Budget does not match the decision")
		}
		claims = verified
	} else {
		claims, err = aauth.VerifyAuthToken(ctx, result.Token, server.keyResolver, server.clock)
		if err != nil {
			return aauth.AuthTokenClaims{}, err
		}
	}
	confirmation := result.Pending.Confirmation
	if result.Pending.Subagent != "" {
		confirmation = result.Pending.SubagentConfirmation
	}
	if err := aauth.ValidateCurrentAuthTokenContext(claims, aauth.AuthTokenContext{
		Issuer: server.issuer, DiscoveryDocument: aauth.PersonDiscoveryDocument,
		Resource: result.Pending.Resource, PersonServer: server.issuer, Subject: result.Pending.Subject,
		RequestKey: confirmation,
	}); err != nil {
		return aauth.AuthTokenClaims{}, err
	}
	expiresAt := result.DecidedAt.Add(result.Decision.Lifetime)
	if result.Pending.PersonTokenExpiresAt.Before(expiresAt) {
		expiresAt = result.Pending.PersonTokenExpiresAt
	}
	if result.Pending.AgentExpiresAt.Before(expiresAt) {
		expiresAt = result.Pending.AgentExpiresAt
	}
	if !result.Pending.SubagentExpiresAt.IsZero() && result.Pending.SubagentExpiresAt.Before(expiresAt) {
		expiresAt = result.Pending.SubagentExpiresAt
	}
	if !result.Pending.MissionExpiresAt.IsZero() && result.Pending.MissionExpiresAt.Before(expiresAt) {
		expiresAt = result.Pending.MissionExpiresAt
	}
	if claims.Tenant != result.Pending.Tenant || claims.Scope != strings.Join(granted, " ") ||
		claims.IssuedAt != result.DecidedAt.Unix() || claims.ExpiresAt != expiresAt.Unix() ||
		result.ExpiresIn != claims.ExpiresAt-claims.IssuedAt || claims.MissionS256 != result.Pending.MissionS256 || claims.Account != nil ||
		len(claims.AdditionalClaims) != 0 {
		return aauth.AuthTokenClaims{}, errors.New("personserver: approved auth token does not match the retained authorization")
	}
	return claims, nil
}

func (server *Server) consumePendingAuthorizationResult(
	response http.ResponseWriter,
	request *http.Request,
	id string,
	result AuthorizationPollRecord,
	mission *MissionRecord,
) bool {
	var err error
	if mission != nil {
		err = server.missionAuthorizationInteractions.ConsumeMissionPendingAuthorizationResult(
			request.Context(), cloneMissionRecordForTransition(*mission), id, result, server.clock.Now().UTC(),
		)
	} else {
		err = server.authorizationInteractions.ConsumePendingAuthorizationResult(request.Context(), id, result)
	}
	if err != nil {
		if mission != nil {
			writeMissionActionProblem(response, err)
			return false
		}
		if errors.Is(err, ErrPendingAuthorizationNotFound) || errors.Is(err, ErrPendingAuthorizationGone) {
			writeProblem(response, http.StatusGone, "invalid_code", err)
		} else {
			writeProblem(response, http.StatusInternalServerError, "server_error", err)
		}
		return false
	}
	return true
}

// endPendingAuthorization makes a revocation answer terminal. It ends a live
// request through the store's own transitions, failing a waiting or
// interacting request or cancelling an active question, and consumes a
// terminal result, so the pending URL is gone afterwards. It reports whether
// the caller may write its answer.
func (server *Server) endPendingAuthorization(
	response http.ResponseWriter,
	request *http.Request,
	id string,
	identity AuthorizationPollIdentity,
	result AuthorizationPollRecord,
	mission *MissionRecord,
) bool {
	ctx := request.Context()
	for attempt := 0; attempt < 3; attempt++ {
		now := server.clock.Now().UTC()
		var err error
		switch result.State {
		case AuthorizationPollGone, AuthorizationPollCancelled:
			return true
		case AuthorizationPollWaiting, AuthorizationPollInteracting:
			if mission != nil {
				err = server.missionAuthorizationInteractions.FailMissionPendingAuthorization(
					ctx, cloneMissionRecordForTransition(*mission), id, now,
				)
			} else {
				err = server.authorizationInteractions.FailPendingAuthorization(ctx, id, now)
			}
		case AuthorizationPollClarifying:
			if err = server.cancelPendingAuthorizationQuestion(ctx, id, identity, mission, now); err == nil {
				return true
			}
		default:
			return server.consumePendingAuthorizationResult(response, request, id, result, mission)
		}
		if err != nil && !errors.Is(err, ErrPendingAuthorizationConflict) && !errors.Is(err, ErrPendingAuthorizationExpired) {
			writeProblem(response, http.StatusInternalServerError, "server_error", err)
			return false
		}
		if mission != nil {
			result, err = server.missionAuthorizationInteractions.PollMissionPendingAuthorization(
				ctx, cloneMissionRecordForTransition(*mission), id, identity, now,
			)
		} else {
			result, err = server.authorizationInteractions.PollPendingAuthorization(ctx, id, identity, now)
		}
		if errors.Is(err, ErrPendingAuthorizationNotFound) || errors.Is(err, ErrPendingAuthorizationGone) {
			return true
		}
		if err != nil {
			writeProblem(response, http.StatusInternalServerError, "server_error", err)
			return false
		}
	}
	writeProblem(response, http.StatusInternalServerError, "server_error", ErrPendingAuthorizationConflict)
	return false
}

// cancelPendingAuthorizationQuestion ends a request with an active
// clarification question, which only the clarification store can do.
func (server *Server) cancelPendingAuthorizationQuestion(
	ctx context.Context,
	id string,
	identity AuthorizationPollIdentity,
	mission *MissionRecord,
	now time.Time,
) error {
	if mission != nil {
		clarifications, ok := server.authorizationInteractions.(MissionAuthorizationClarificationStore)
		if !ok {
			return ErrPendingAuthorizationConflict
		}
		return clarifications.CancelMissionPendingAuthorizationClarification(
			ctx, cloneMissionRecordForTransition(*mission), id, identity, now,
		)
	}
	clarifications, ok := server.authorizationInteractions.(AuthorizationClarificationStore)
	if !ok {
		return ErrPendingAuthorizationConflict
	}
	return clarifications.CancelPendingAuthorizationClarification(ctx, id, identity, now)
}

func pendingAuthorizationIdentityMatches(record PendingAuthorizationRecord, identity AuthorizationPollIdentity) bool {
	thumbprint, err := record.Confirmation.Thumbprint()
	return err == nil && record.PersonServer == identity.PersonServer && record.AgentProvider == identity.AgentProvider &&
		record.Agent == identity.Agent && thumbprint == identity.ConfirmationThumbprint
}

func (server *Server) writePendingAuthorization(response http.ResponseWriter, location string, retryAfter time.Duration, status string) {
	if retryAfter < 0 || retryAfter%time.Second != 0 || (status != "pending" && status != "interacting") {
		writeProblem(response, http.StatusInternalServerError, "server_error", ErrPendingAuthorizationConflict)
		return
	}
	response.Header().Set("Location", location)
	response.Header().Set("Retry-After", strconv.FormatInt(int64(retryAfter/time.Second), 10))
	writePrivateJSON(response, http.StatusAccepted, struct {
		Status string `json:"status"`
	}{Status: status})
}

func cloneAuthorizationDecision(decision AuthorizationDecision) AuthorizationDecision {
	decision.Scopes = append([]string(nil), decision.Scopes...)
	decision.Budget = cloneBudgetValue(decision.Budget)
	return decision
}

func budgetValuesEqual(left, right budgets.Value) bool {
	return left.Amount() == right.Amount() && left.Unit().Equal(right.Unit())
}

func budgetPointersEqual(left, right *budgets.Value) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return budgetValuesEqual(*left, *right)
}

func authorizationDecisionsSemanticallyEqual(left, right AuthorizationDecision) bool {
	if left.Lifetime != right.Lifetime || len(left.Scopes) != len(right.Scopes) || !budgetPointersEqual(left.Budget, right.Budget) {
		return false
	}
	leftScopes := make(map[string]struct{}, len(left.Scopes))
	for _, scope := range left.Scopes {
		leftScopes[scope] = struct{}{}
	}
	if len(leftScopes) != len(left.Scopes) {
		return false
	}
	rightScopes := make(map[string]struct{}, len(right.Scopes))
	for _, scope := range right.Scopes {
		if _, duplicate := rightScopes[scope]; duplicate {
			return false
		}
		rightScopes[scope] = struct{}{}
		if _, ok := leftScopes[scope]; !ok {
			return false
		}
	}
	return true
}

func clonePendingAuthorizationRecord(record PendingAuthorizationRecord) PendingAuthorizationRecord {
	record.Scopes = append([]string(nil), record.Scopes...)
	record.AgentAdditionalClaims = cloneClaims(record.AgentAdditionalClaims)
	record.SubagentAdditionalClaims = cloneClaims(record.SubagentAdditionalClaims)
	record.Capabilities = append([]string(nil), record.Capabilities...)
	record.BudgetOffer = cloneBudgetValue(record.BudgetOffer)
	return record
}

func cloneAuthorizationApproval(approval AuthorizationApproval) AuthorizationApproval {
	approval.Decision = cloneAuthorizationDecision(approval.Decision)
	return approval
}

func authorizationApprovalIsZero(approval AuthorizationApproval) bool {
	return len(approval.Decision.Scopes) == 0 && approval.Decision.Lifetime == 0 && approval.Decision.Budget == nil &&
		approval.Token == "" && approval.ExpiresIn == 0 && approval.DecidedAt.IsZero()
}

func validateAuthorizationApprovalShape(pending PendingAuthorizationRecord, approval AuthorizationApproval) error {
	if _, err := validateAuthorizationDecision(approval.Decision, pending.Scopes); err != nil {
		return err
	}
	if approval.Token == "" || approval.ExpiresIn <= 0 || approval.DecidedAt.IsZero() ||
		approval.DecidedAt.Before(pending.CreatedAt) || !approval.DecidedAt.Before(pending.ExpiresAt) {
		return errors.New("personserver: canonical authorization approval is incomplete")
	}
	return nil
}

func cloneAuthorizationPollRecord(record AuthorizationPollRecord) AuthorizationPollRecord {
	record.Pending = clonePendingAuthorizationRecord(record.Pending)
	record.Decision = cloneAuthorizationDecision(record.Decision)
	if record.Clarification != nil {
		cloned := cloneAuthorizationClarification(*record.Clarification)
		record.Clarification = &cloned
	}
	return record
}
