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
)

// MaximumAuthorizationCodeAttempts is the fixed failed-code bound for one
// pending authorization interaction.
const MaximumAuthorizationCodeAttempts = 3

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
type PendingAuthorizationRecord struct {
	ID                     string
	CodeSHA256             [32]byte
	PersonServer           string
	AgentProvider          string
	Agent                  string
	Resource               string
	Subject                string
	Tenant                 string
	Scopes                 []string
	Confirmation           jose.JWK
	AgentExpiresAt         time.Time
	ResourceTokenExpiresAt time.Time
	AgentAdditionalClaims  map[string]json.RawMessage
	Capabilities           []string
	CreatedAt              time.Time
	ExpiresAt              time.Time
	RetryAfter             time.Duration
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
	AuthorizationPollApproved
	AuthorizationPollDenied
	AuthorizationPollAbandoned
	AuthorizationPollServerError
	AuthorizationPollExpired
	AuthorizationPollGone
)

// AuthorizationPollRecord is the exact store result about to become one HTTP
// response. Pending is returned atomically with the state so the Person Server
// can validate the retained result against its original verified context.
type AuthorizationPollRecord struct {
	State      AuthorizationPollState
	Pending    PendingAuthorizationRecord
	Token      string
	Decision   AuthorizationDecision
	ExpiresIn  int64
	DecidedAt  time.Time
	RetryAfter time.Duration
}

// PendingAuthorizationSnapshot lets an authenticated host resume an
// interaction and recover the canonical result of an uncertain decision.
type PendingAuthorizationSnapshot struct {
	Record   PendingAuthorizationRecord
	State    AuthorizationPollState
	Approval AuthorizationApproval
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

// AuthorizationInteraction is a correlated auth-token request. It is not
// proof that a host authenticated the person and carries no decision authority.
type AuthorizationInteraction struct {
	kind   uint8
	record PendingAuthorizationRecord
}

const authorizationInteractionCorrelated uint8 = 1

// AgentProvider returns the issuer of the verified Agent token.
func (value AuthorizationInteraction) AgentProvider() string { return value.record.AgentProvider }

// Agent returns the verified Agent that requested authorization.
func (value AuthorizationInteraction) Agent() string { return value.record.Agent }

// Resource returns the Resource named by the verified resource token.
func (value AuthorizationInteraction) Resource() string { return value.record.Resource }

// Subject returns the directed person identifier in the Person Server namespace.
func (value AuthorizationInteraction) Subject() string { return value.record.Subject }

// Tenant returns the verified tenant context, if any.
func (value AuthorizationInteraction) Tenant() string { return value.record.Tenant }

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
		record.AgentProvider == "" || record.Agent == "" || record.Resource == "" || record.Subject == "" ||
		record.AgentExpiresAt.IsZero() || record.ResourceTokenExpiresAt.IsZero() || record.CreatedAt.IsZero() ||
		!record.ExpiresAt.After(record.CreatedAt) || record.AgentExpiresAt.Before(record.ExpiresAt) ||
		record.ResourceTokenExpiresAt.Before(record.ExpiresAt) || record.RetryAfter < 0 || record.RetryAfter%time.Second != 0 {
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
	return nil
}

func (server *Server) beginAuthorizationInteraction(
	response http.ResponseWriter,
	request *http.Request,
	authorization AuthorizationRequest,
	agent aauth.AgentTokenClaims,
	resourceToken aauth.ResourceTokenClaims,
	policy AuthorizationInteractionPolicy,
) error {
	if server.authorizationInteractions == nil {
		return errors.New("personserver: deferred authorization store is required")
	}
	if err := validateAuthorizationInteractionPolicy(policy); err != nil {
		return err
	}
	createdAt := server.clock.Now().UTC()
	expiresAt := createdAt.Add(policy.Lifetime)
	if !expiresAt.After(createdAt) {
		return ErrPendingAuthorizationExpired
	}
	agentExpiresAt := time.Unix(agent.ExpiresAt, 0).UTC()
	resourceTokenExpiresAt := time.Unix(resourceToken.ExpiresAt, 0).UTC()
	if agentExpiresAt.Before(expiresAt) {
		expiresAt = agentExpiresAt
	}
	if resourceTokenExpiresAt.Before(expiresAt) {
		expiresAt = resourceTokenExpiresAt
	}
	if !expiresAt.After(createdAt) {
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
		record := PendingAuthorizationRecord{
			ID: id, CodeSHA256: digest, PersonServer: server.issuer,
			AgentProvider: agent.Issuer, Agent: authorization.Agent, Resource: authorization.Resource,
			Subject: authorization.Subject, Tenant: authorization.Tenant,
			Scopes: append([]string(nil), authorization.Scopes...), Confirmation: agent.Confirmation.JWK,
			AgentExpiresAt: agentExpiresAt, ResourceTokenExpiresAt: resourceTokenExpiresAt,
			AgentAdditionalClaims: cloneClaims(authorization.AgentAdditionalClaims),
			Capabilities:          append([]string(nil), authorization.Capabilities...),
			CreatedAt:             createdAt, ExpiresAt: expiresAt, RetryAfter: policy.RetryAfter,
		}
		if err := validatePendingAuthorizationRecord(record); err != nil {
			return err
		}
		if err := server.authorizationInteractions.CreatePendingAuthorization(request.Context(), record); err != nil {
			if errors.Is(err, ErrPendingAuthorizationConflict) {
				continue
			}
			return err
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
	record, err := server.authorizationInteractions.ConsumeAuthorizationInteractionCode(
		ctx, server.issuer, reference, presentation, server.clock.Now().UTC(),
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
	return authorizationInteractionFromRecord(record), nil
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
	snapshot, err := server.authorizationInteractions.LoadPendingAuthorization(ctx, reference, server.clock.Now().UTC())
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
	case AuthorizationPollWaiting, AuthorizationPollInteracting, AuthorizationPollApproved, AuthorizationPollDenied,
		AuthorizationPollAbandoned, AuthorizationPollServerError:
		return authorizationInteractionFromRecord(snapshot.Record), nil
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
	decision.Scopes = append([]string(nil), granted...)
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
	case AuthorizationPollGone:
		return ErrPendingAuthorizationGone
	case AuthorizationPollInteracting:
		// Continue below.
	default:
		return ErrPendingAuthorizationConflict
	}
	if !now.Before(value.record.ExpiresAt) || !now.Before(value.record.AgentExpiresAt) {
		return ErrPendingAuthorizationExpired
	}
	expiresAt := now.Add(decision.Lifetime)
	if value.record.AgentExpiresAt.Before(expiresAt) {
		expiresAt = value.record.AgentExpiresAt
	}
	if !expiresAt.After(now) {
		return ErrPendingAuthorizationExpired
	}
	claims := aauth.AuthTokenClaims{
		Issuer: server.issuer, DWK: aauth.PersonDiscoveryDocument, Audience: value.record.Resource,
		JTI: server.newID(), PersonServer: server.issuer, Subject: value.record.Subject,
		Confirmation: aauth.Confirmation{JWK: value.record.Confirmation},
		IssuedAt:     now.Unix(), ExpiresAt: expiresAt.Unix(), Scope: strings.Join(granted, " "), Tenant: value.record.Tenant,
	}
	compact, err := aauth.MintAuthToken(server.signingKey, claims)
	if err != nil {
		return err
	}
	canonical, err := server.authorizationInteractions.ApprovePendingAuthorization(ctx, value.record.ID, AuthorizationApproval{
		Decision: decision, Token: compact, ExpiresIn: claims.ExpiresAt - claims.IssuedAt, DecidedAt: now,
	})
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
	case AuthorizationPollGone:
		return ErrPendingAuthorizationGone
	case AuthorizationPollInteracting:
		// Continue below.
	default:
		return ErrPendingAuthorizationConflict
	}
	if !now.Before(value.record.ExpiresAt) {
		return ErrPendingAuthorizationExpired
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
	case AuthorizationPollGone:
		return ErrPendingAuthorizationGone
	case AuthorizationPollInteracting:
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
	case AuthorizationPollGone:
		return ErrPendingAuthorizationGone
	case AuthorizationPollWaiting, AuthorizationPollInteracting:
		return server.authorizationInteractions.FailPendingAuthorization(ctx, value.record.ID, now)
	case AuthorizationPollExpired:
		return ErrPendingAuthorizationExpired
	default:
		return ErrPendingAuthorizationConflict
	}
}

func authorizationInteractionFromRecord(record PendingAuthorizationRecord) AuthorizationInteraction {
	return AuthorizationInteraction{kind: authorizationInteractionCorrelated, record: clonePendingAuthorizationRecord(record)}
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
	return snapshot, nil
}

func (server *Server) validatePendingAuthorizationSnapshot(ctx context.Context, snapshot PendingAuthorizationSnapshot) error {
	if err := validatePendingAuthorizationRecord(snapshot.Record); err != nil || snapshot.Record.PersonServer != server.issuer {
		return ErrPendingAuthorizationConflict
	}
	switch snapshot.State {
	case AuthorizationPollWaiting, AuthorizationPollInteracting, AuthorizationPollDenied,
		AuthorizationPollAbandoned, AuthorizationPollServerError, AuthorizationPollExpired, AuthorizationPollGone:
		if !authorizationApprovalIsZero(snapshot.Approval) {
			return ErrPendingAuthorizationConflict
		}
	case AuthorizationPollApproved:
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
		left.AgentProvider == right.AgentProvider && left.Agent == right.Agent && left.Resource == right.Resource &&
		left.Subject == right.Subject && left.Tenant == right.Tenant && reflect.DeepEqual(left.Scopes, right.Scopes) &&
		left.Confirmation.Equal(right.Confirmation) && left.AgentExpiresAt.Equal(right.AgentExpiresAt) &&
		left.ResourceTokenExpiresAt.Equal(right.ResourceTokenExpiresAt) &&
		reflect.DeepEqual(left.AgentAdditionalClaims, right.AgentAdditionalClaims) &&
		reflect.DeepEqual(left.Capabilities, right.Capabilities) && left.CreatedAt.Equal(right.CreatedAt) &&
		left.ExpiresAt.Equal(right.ExpiresAt) && left.RetryAfter == right.RetryAfter
}

func (server *Server) handlePendingAuthorization(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		response.Header().Set("Allow", http.MethodGet)
		writeProblem(response, http.StatusMethodNotAllowed, "method_not_allowed", errors.New("authorization polling requires GET"))
		return
	}
	if server.authorizationInteractions == nil {
		writeProblem(response, http.StatusGone, "invalid_code", ErrPendingAuthorizationNotFound)
		return
	}
	if request.Body != nil && request.Body != http.NoBody {
		writeProblem(response, http.StatusBadRequest, "invalid_request", errors.New("authorization polling requires a bodyless GET"))
		return
	}
	_, agent, proof, err := server.verifyAgentRequest(request, nil)
	if err != nil {
		writeAgentTokenProblem(response, err)
		return
	}
	thumbprint, err := agent.Confirmation.JWK.Thumbprint()
	if err != nil {
		writeAgentTokenProblem(response, err)
		return
	}
	id := request.PathValue("id")
	if id == "" {
		writeProblem(response, http.StatusGone, "invalid_code", ErrPendingAuthorizationNotFound)
		return
	}
	identity := AuthorizationPollIdentity{
		PersonServer: server.issuer, AgentProvider: agent.Issuer, Agent: agent.Subject, ConfirmationThumbprint: thumbprint,
	}
	result, err := server.authorizationInteractions.PollPendingAuthorization(request.Context(), id, identity, proof.VerifiedAt())
	if err != nil {
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
	case AuthorizationPollWaiting:
		server.writePendingAuthorization(response, request.URL.Path, result.RetryAfter, "pending")
	case AuthorizationPollInteracting:
		server.writePendingAuthorization(response, request.URL.Path, result.RetryAfter, "interacting")
	case AuthorizationPollApproved:
		claims, err := server.validateApprovedAuthorization(request.Context(), result)
		if err != nil {
			var tokenFailure *aauth.TokenValidationError
			if errors.As(err, &tokenFailure) && tokenFailure.Code == aauth.TokenValidationExpired {
				if server.consumePendingAuthorizationResult(response, request, id, result) {
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
		if !server.consumePendingAuthorizationResult(response, request, id, result) {
			return
		}
		writePrivateJSON(response, http.StatusOK, struct {
			AuthToken string `json:"auth_token"`
			ExpiresIn int64  `json:"expires_in"`
		}{AuthToken: result.Token, ExpiresIn: result.ExpiresIn})
	case AuthorizationPollDenied:
		if !server.consumePendingAuthorizationResult(response, request, id, result) {
			return
		}
		writeProblem(response, http.StatusForbidden, "denied", errors.New("authorization interaction was denied"))
	case AuthorizationPollAbandoned:
		if !server.consumePendingAuthorizationResult(response, request, id, result) {
			return
		}
		writeProblem(response, http.StatusForbidden, "abandoned", errors.New("authorization interaction was abandoned"))
	case AuthorizationPollServerError:
		if !server.consumePendingAuthorizationResult(response, request, id, result) {
			return
		}
		writeProblem(response, http.StatusInternalServerError, "server_error", errors.New("authorization interaction failed"))
	case AuthorizationPollExpired:
		if !server.consumePendingAuthorizationResult(response, request, id, result) {
			return
		}
		writeProblem(response, http.StatusRequestTimeout, "expired", ErrPendingAuthorizationExpired)
	case AuthorizationPollGone:
		writeProblem(response, http.StatusGone, "invalid_code", ErrPendingAuthorizationGone)
	default:
		writeProblem(response, http.StatusInternalServerError, "server_error", ErrPendingAuthorizationConflict)
	}
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
	emptyDecision := len(result.Decision.Scopes) == 0 && result.Decision.Lifetime == 0
	switch result.State {
	case AuthorizationPollWaiting, AuthorizationPollInteracting, AuthorizationPollDenied,
		AuthorizationPollAbandoned, AuthorizationPollServerError, AuthorizationPollExpired:
		if result.Token != "" || !emptyDecision || result.ExpiresIn != 0 || !result.DecidedAt.IsZero() {
			return ErrPendingAuthorizationConflict
		}
	case AuthorizationPollApproved:
		if result.Token == "" || result.ExpiresIn <= 0 || result.DecidedAt.IsZero() {
			return ErrPendingAuthorizationConflict
		}
	case AuthorizationPollGone:
		if result.Token != "" || !emptyDecision || result.ExpiresIn != 0 || !result.DecidedAt.IsZero() {
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
	if result.DecidedAt.Before(result.Pending.CreatedAt) || !result.DecidedAt.Before(result.Pending.ExpiresAt) ||
		!result.DecidedAt.Before(result.Pending.AgentExpiresAt) {
		return aauth.AuthTokenClaims{}, errors.New("personserver: approved auth token has an invalid decision time")
	}
	claims, err := aauth.VerifyAuthToken(ctx, result.Token, server.keyResolver, server.clock)
	if err != nil {
		return aauth.AuthTokenClaims{}, err
	}
	if err := aauth.ValidateCurrentAuthTokenContext(claims, aauth.AuthTokenContext{
		Issuer: server.issuer, DiscoveryDocument: aauth.PersonDiscoveryDocument,
		Resource: result.Pending.Resource, PersonServer: server.issuer, Subject: result.Pending.Subject,
		RequestKey: result.Pending.Confirmation,
	}); err != nil {
		return aauth.AuthTokenClaims{}, err
	}
	expiresAt := result.DecidedAt.Add(result.Decision.Lifetime)
	if result.Pending.AgentExpiresAt.Before(expiresAt) {
		expiresAt = result.Pending.AgentExpiresAt
	}
	if claims.Tenant != result.Pending.Tenant || claims.Scope != strings.Join(granted, " ") ||
		claims.IssuedAt != result.DecidedAt.Unix() || claims.ExpiresAt != expiresAt.Unix() ||
		result.ExpiresIn != claims.ExpiresAt-claims.IssuedAt || claims.MissionS256 != "" || claims.Account != nil ||
		len(claims.AdditionalClaims) != 0 {
		return aauth.AuthTokenClaims{}, errors.New("personserver: approved auth token does not match the retained authorization")
	}
	return claims, nil
}

func (server *Server) consumePendingAuthorizationResult(response http.ResponseWriter, request *http.Request, id string, result AuthorizationPollRecord) bool {
	if err := server.authorizationInteractions.ConsumePendingAuthorizationResult(request.Context(), id, result); err != nil {
		if errors.Is(err, ErrPendingAuthorizationNotFound) || errors.Is(err, ErrPendingAuthorizationGone) {
			writeProblem(response, http.StatusGone, "invalid_code", err)
		} else {
			writeProblem(response, http.StatusInternalServerError, "server_error", err)
		}
		return false
	}
	return true
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
	return decision
}

func authorizationDecisionsSemanticallyEqual(left, right AuthorizationDecision) bool {
	if left.Lifetime != right.Lifetime || len(left.Scopes) != len(right.Scopes) {
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
	record.Capabilities = append([]string(nil), record.Capabilities...)
	return record
}

func cloneAuthorizationApproval(approval AuthorizationApproval) AuthorizationApproval {
	approval.Decision = cloneAuthorizationDecision(approval.Decision)
	return approval
}

func authorizationApprovalIsZero(approval AuthorizationApproval) bool {
	return len(approval.Decision.Scopes) == 0 && approval.Decision.Lifetime == 0 &&
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
	return record
}
