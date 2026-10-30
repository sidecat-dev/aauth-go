package personserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/internal/interaction"
	"gitlab.com/sidecat-dev/aauth-go/jose"
)

var (
	// ErrPendingPersonTokenNotFound reports an unknown pending request.
	ErrPendingPersonTokenNotFound = errors.New("personserver: pending person token not found")
	// ErrPendingPersonTokenConflict reports a competing or inconsistent state
	// transition for one pending request.
	ErrPendingPersonTokenConflict = errors.New("personserver: pending person token conflicts with retained state")
	// ErrPendingPersonTokenExpired reports that the interaction deadline passed.
	ErrPendingPersonTokenExpired = errors.New("personserver: pending person token expired")
	// ErrPendingPersonTokenGone reports that the terminal response was already
	// delivered from the pending URL.
	ErrPendingPersonTokenGone = errors.New("personserver: pending person token is gone")
	// ErrInteractionCodeInvalid reports an unknown or malformed correlation code.
	ErrInteractionCodeInvalid = errors.New("personserver: interaction code is invalid")
	// ErrInteractionCodeUsed reports a correlation code that was already consumed.
	ErrInteractionCodeUsed = errors.New("personserver: interaction code was already used")
)

// MaximumPersonTokenCodeAttempts is the fixed failed-code bound for one
// pending person-token interaction. The store terminally fails the
// interaction when it is reached.
const MaximumPersonTokenCodeAttempts = 3

// PersonTokenCodePresentation is one non-plaintext interaction-code attempt.
// SyntacticallyValid is true only when CodeSHA256 contains the digest of a
// successfully normalized Crockford presentation. A false value carries no
// digest authority but still counts as a failed attempt.
type PersonTokenCodePresentation struct {
	CodeSHA256         [32]byte
	SyntacticallyValid bool
}

// PersonTokenInteractionPolicy requests one PS-hosted interaction before a
// person token is issued. URL names the host's authenticated user-interface
// base; the server appends the unguessable pending reference as one path
// segment so failed code attempts can be attributed and rate-limited. Lifetime
// bounds the pending request; RetryAfter is the Agent's polling hint.
type PersonTokenInteractionPolicy struct {
	URL        string
	Lifetime   time.Duration
	RetryAfter time.Duration
}

// PendingPersonTokenRecord is the immutable verified request retained before
// a person-token interaction is exposed. Agent, AgentTokenJTI, ParentAgent,
// Confirmation, and AgentExpiresAt identify the eventual credential recipient.
// The Requesting fields independently identify the top-level Agent authorized
// to poll. They are equal for a direct request and distinct for a
// parent-mediated child. Both token identifiers name AgentProvider tokens, and
// its revocation of either ends the wait. CodeSHA256 hashes the normalized
// correlation code; the plaintext code is not durable authority.
type PendingPersonTokenRecord struct {
	ID                              string
	CodeSHA256                      [32]byte
	PersonServer                    string
	AgentProvider                   string
	Agent                           string
	AgentTokenJTI                   string
	ParentAgent                     string
	Resource                        string
	MissionS256                     string
	Confirmation                    jose.JWK
	AgentExpiresAt                  time.Time
	AgentAdditionalClaims           map[string]json.RawMessage
	RequestingAgent                 string
	RequestingAgentTokenJTI         string
	RequestingConfirmation          jose.JWK
	RequestingAgentExpiresAt        time.Time
	RequestingAgentAdditionalClaims map[string]json.RawMessage
	CreatedAt                       time.Time
	ExpiresAt                       time.Time
	RetryAfter                      time.Duration
}

// PersonTokenApproval is the exact approved response and the existing token
// record that must become visible atomically.
type PersonTokenApproval struct {
	Person    Person
	Token     string
	Record    PersonTokenRecord
	ExpiresIn int64
	DecidedAt time.Time
}

// PersonTokenPollIdentity binds a pending poll to the original verified Agent
// and request key.
type PersonTokenPollIdentity struct {
	PersonServer           string
	Agent                  string
	ConfirmationThumbprint string
}

// PersonTokenPollState is one Person Token Endpoint pending state.
type PersonTokenPollState uint8

const (
	PersonTokenPollWaiting PersonTokenPollState = iota + 1
	PersonTokenPollInteracting
	PersonTokenPollApproved
	PersonTokenPollDenied
	PersonTokenPollExpired
	PersonTokenPollGone
)

// PersonTokenPollRecord is the store result for one signed GET. Approved,
// denied, and expired are terminal deliveries; a later GET must report gone.
type PersonTokenPollRecord struct {
	State      PersonTokenPollState
	Token      string
	Record     PersonTokenRecord
	ExpiresIn  int64
	RetryAfter time.Duration
}

// PendingPersonTokenSnapshot lets the authenticated host resume an interaction
// after process restart and recover an uncertain decision result. Loading a
// snapshot does not consume the code or the terminal polling response.
type PendingPersonTokenSnapshot struct {
	Record         PendingPersonTokenRecord
	State          PersonTokenPollState
	ApprovedPerson Person
}

// DeferredTokenStore adds only Person Token Endpoint interactions to
// TokenStore. Its methods provide these atomic transitions:
//
//   - Create accepts one unique ID, issuer, and code digest or changes nothing.
//   - Consume matches issuer and pending reference. While the record is
//     waiting and unexpired, a syntactically invalid presentation or a
//     nonmatching digest is one failed attempt; at
//     MaximumPersonTokenCodeAttempts the record changes to gone, and every
//     later presentation returns ErrPendingPersonTokenGone. A matching digest
//     gives terminal/used state precedence over expiry and changes one live
//     unused code to interacting. Consume never returns a record for
//     SyntacticallyValid=false.
//   - Load is read-only and returns the exact retained snapshot.
//   - Approve atomically retains the exact token, token record, and Person
//     before any of them become pollable.
//   - Deny and Invalidate race atomically with approval and retain no token.
//   - Poll verifies all identity fields and returns a read-only result.
//   - ConsumePendingPersonTokenResult compares that exact terminal result and
//     atomically changes it to gone immediately before HTTP delivery.
//
// A repeated approval with the same Person, or a repeated denial, is
// idempotent even when the retry proposes a new token ID or decision time; the
// first retained value remains canonical. The failed-attempt bound is the
// store's; a host may also invalidate an interaction sooner.
type DeferredTokenStore interface {
	TokenStore
	CreatePendingPersonToken(context.Context, PendingPersonTokenRecord) error
	ConsumePersonTokenInteractionCode(context.Context, string, string, PersonTokenCodePresentation, time.Time) (PendingPersonTokenRecord, error)
	LoadPendingPersonToken(context.Context, string) (PendingPersonTokenSnapshot, error)
	ApprovePendingPersonToken(context.Context, string, PersonTokenApproval) error
	DenyPendingPersonToken(context.Context, string, time.Time) error
	InvalidatePendingPersonToken(context.Context, string, time.Time) error
	PollPendingPersonToken(context.Context, string, PersonTokenPollIdentity, time.Time) (PersonTokenPollRecord, error)
	ConsumePendingPersonTokenResult(context.Context, string, PersonTokenPollRecord) error
}

// MissionDeferredTokenStore keeps mission-bound pending creation, approval,
// denial, polling, and terminal consumption in the mission transaction.
type MissionDeferredTokenStore interface {
	MissionStore
	DeferredTokenStore
	CreateMissionPendingPersonToken(context.Context, MissionRecord, PendingPersonTokenRecord, time.Time) error
	ApproveMissionPendingPersonToken(context.Context, MissionRecord, string, PersonTokenApproval, time.Time) error
	DenyMissionPendingPersonToken(context.Context, MissionRecord, string, time.Time) error
	PollMissionPendingPersonToken(context.Context, MissionRecord, string, PersonTokenPollIdentity, time.Time) (PersonTokenPollRecord, error)
	ConsumeMissionPendingPersonTokenResult(context.Context, MissionRecord, string, PersonTokenPollRecord, time.Time) error
}

// PersonTokenInteraction is a correlated pending request. Receiving this value
// proves only that a code matched. The host must authenticate the person before
// calling an approval or denial method.
type PersonTokenInteraction struct {
	kind                            personTokenInteractionKind
	personServer                    string
	id                              string
	codeSHA256                      [32]byte
	agent                           string
	agentTokenJTI                   string
	agentProvider                   string
	parentAgent                     string
	requestingAgent                 string
	requestingAgentTokenJTI         string
	resource                        string
	missionS256                     string
	mission                         *MissionContext
	missionRecord                   *MissionRecord
	confirmation                    jose.JWK
	agentExpiresAt                  time.Time
	requestingConfirmation          jose.JWK
	requestingAgentExpiresAt        time.Time
	createdAt                       time.Time
	expiresAt                       time.Time
	retryAfter                      time.Duration
	agentAdditionalClaims           map[string]json.RawMessage
	requestingAgentAdditionalClaims map[string]json.RawMessage
}

type personTokenInteractionKind uint8

const personTokenInteractionCorrelated personTokenInteractionKind = 1

// Agent returns the verified top-level Agent that requested the token.
func (interaction PersonTokenInteraction) Agent() string { return interaction.requestingAgent }

// Subagent returns the child credential recipient for a parent-mediated
// request. The bool is false for a top-level request.
func (interaction PersonTokenInteraction) Subagent() (string, bool) {
	if interaction.parentAgent == "" {
		return "", false
	}
	return interaction.agent, true
}

// Resource returns the exact resource for which the person token was requested.
func (interaction PersonTokenInteraction) Resource() string { return interaction.resource }

// Reference returns a non-secret continuation value that the authenticated
// host may retain across process restart. It does not authorize a decision.
func (interaction PersonTokenInteraction) Reference() string { return interaction.id }

// ExpiresAt returns the pending interaction deadline.
func (interaction PersonTokenInteraction) ExpiresAt() time.Time { return interaction.expiresAt }

// Mission returns a caller-owned exact mission context for a mission-bound
// interaction. The bool is false for a missionless interaction.
func (interaction PersonTokenInteraction) Mission() (MissionContext, bool) {
	if interaction.kind != personTokenInteractionCorrelated || interaction.mission == nil {
		return MissionContext{}, false
	}
	return *cloneMissionContext(interaction.mission), true
}

// AgentAdditionalClaims returns an independent copy of the Agent Provider
// claims available to host policy.
func (interaction PersonTokenInteraction) AgentAdditionalClaims() map[string]json.RawMessage {
	return cloneClaims(interaction.requestingAgentAdditionalClaims)
}

// SubagentAdditionalClaims returns the child Agent Provider claims for a
// parent-mediated request. A top-level request returns nil.
func (interaction PersonTokenInteraction) SubagentAdditionalClaims() map[string]json.RawMessage {
	if interaction.parentAgent == "" {
		return nil
	}
	return cloneClaims(interaction.agentAdditionalClaims)
}

func validatePersonTokenInteractionPolicy(policy PersonTokenInteractionPolicy) error {
	if _, err := aauth.FormatInteractionRequirement(aauth.InteractionRequirement{
		URL: policy.URL, Code: "0000-0000",
	}); err != nil {
		return fmt.Errorf("personserver: interaction URL: %w", err)
	}
	if policy.Lifetime <= 0 {
		return errors.New("personserver: interaction lifetime must be positive")
	}
	if policy.RetryAfter < 0 || policy.RetryAfter%time.Second != 0 {
		return errors.New("personserver: interaction retry interval must be nonnegative whole seconds")
	}
	return nil
}

func validatePendingPersonTokenRecord(record PendingPersonTokenRecord) error {
	if record.ID == "" || record.CodeSHA256 == ([32]byte{}) || record.PersonServer == "" || record.AgentProvider == "" ||
		record.Agent == "" || record.RequestingAgent == "" || record.Resource == "" ||
		record.AgentTokenJTI == "" || record.RequestingAgentTokenJTI == "" ||
		record.AgentExpiresAt.IsZero() || record.RequestingAgentExpiresAt.IsZero() || record.CreatedAt.IsZero() ||
		!record.ExpiresAt.After(record.CreatedAt) || record.AgentExpiresAt.Before(record.ExpiresAt) ||
		record.RequestingAgentExpiresAt.Before(record.ExpiresAt) || record.RetryAfter < 0 || record.RetryAfter%time.Second != 0 {
		return errors.New("personserver: pending person-token record is invalid")
	}
	if err := aauth.ValidateServerIdentifier(record.PersonServer); err != nil {
		return err
	}
	if err := aauth.ValidateAgentIdentifier(record.Agent); err != nil {
		return err
	}
	if err := aauth.ValidateServerIdentifier(record.AgentProvider); err != nil {
		return err
	}
	if err := aauth.ValidateAgentRelationship(record.Agent, record.ParentAgent); err != nil {
		return err
	}
	if err := aauth.ValidateAgentRelationship(record.RequestingAgent, ""); err != nil {
		return err
	}
	if record.ParentAgent == "" {
		if record.Agent != record.RequestingAgent || !record.Confirmation.Equal(record.RequestingConfirmation) ||
			record.AgentTokenJTI != record.RequestingAgentTokenJTI {
			return errors.New("personserver: top-level pending identity is inconsistent")
		}
	} else if record.ParentAgent != record.RequestingAgent || record.Confirmation.Equal(record.RequestingConfirmation) {
		return errors.New("personserver: delegated pending identity is inconsistent")
	}
	if err := aauth.ValidateServerIdentifier(record.Resource); err != nil {
		return err
	}
	if record.MissionS256 != "" {
		if err := aauth.ValidateMissionS256(record.MissionS256); err != nil {
			return err
		}
	}
	if _, err := record.Confirmation.PublicKey(); err != nil {
		return fmt.Errorf("personserver: pending confirmation key: %w", err)
	}
	if _, err := record.RequestingConfirmation.PublicKey(); err != nil {
		return fmt.Errorf("personserver: pending requesting confirmation key: %w", err)
	}
	return nil
}

func (server *Server) beginPersonTokenInteraction(
	response http.ResponseWriter,
	request *http.Request,
	personRequest PersonTokenRequest,
	requestingAgent aauth.AgentTokenClaims,
	credentialAgent aauth.AgentTokenClaims,
	policy PersonTokenInteractionPolicy,
	mission *MissionRecord,
	createdAt time.Time,
) error {
	if server.deferredTokens == nil {
		return errors.New("personserver: deferred token store is required")
	}
	if err := validatePersonTokenInteractionPolicy(policy); err != nil {
		return err
	}
	// Policy latency must not move an old request into a replacement binding.
	createdAt = createdAt.UTC()
	expiresAt := createdAt.Add(policy.Lifetime)
	requestingAgentExpiresAt := time.Unix(requestingAgent.ExpiresAt, 0).UTC()
	agentExpiresAt := time.Unix(credentialAgent.ExpiresAt, 0).UTC()
	if agentExpiresAt.Before(expiresAt) {
		expiresAt = agentExpiresAt
	}
	if requestingAgentExpiresAt.Before(expiresAt) {
		expiresAt = requestingAgentExpiresAt
	}
	if mission != nil && !mission.ExpiresAt.IsZero() && mission.ExpiresAt.Before(expiresAt) {
		expiresAt = mission.ExpiresAt
	}
	if !expiresAt.After(server.clock.Now()) {
		return ErrPendingPersonTokenExpired
	}

	for attempt := 0; attempt < 3; attempt++ {
		id, err := interaction.GeneratePendingReference(nil)
		if err != nil {
			return fmt.Errorf("personserver: generate pending identifier: %w", err)
		}
		code, err := interaction.GenerateCode(nil)
		if err != nil {
			return fmt.Errorf("personserver: generate interaction code: %w", err)
		}
		interactionURL, err := pendingInteractionURL(policy.URL, id)
		if err != nil {
			return err
		}
		requirement, err := aauth.FormatInteractionRequirement(aauth.InteractionRequirement{
			URL: interactionURL, Code: code,
		})
		if err != nil {
			return err
		}
		codeSHA256, err := interaction.Digest(code)
		if err != nil {
			return err
		}
		record := PendingPersonTokenRecord{
			ID: id, CodeSHA256: codeSHA256, PersonServer: server.issuer,
			AgentProvider: credentialAgent.Issuer, Agent: credentialAgent.Subject, AgentTokenJTI: credentialAgent.JTI,
			ParentAgent: credentialAgent.ParentAgent,
			Resource:    personRequest.Resource, MissionS256: missionS256(mission), Confirmation: credentialAgent.Confirmation.JWK,
			AgentExpiresAt:                  agentExpiresAt,
			AgentAdditionalClaims:           cloneClaims(credentialAgent.AdditionalClaims),
			RequestingAgent:                 requestingAgent.Subject,
			RequestingAgentTokenJTI:         requestingAgent.JTI,
			RequestingConfirmation:          requestingAgent.Confirmation.JWK,
			RequestingAgentExpiresAt:        requestingAgentExpiresAt,
			RequestingAgentAdditionalClaims: cloneClaims(requestingAgent.AdditionalClaims),
			CreatedAt:                       createdAt, ExpiresAt: expiresAt, RetryAfter: policy.RetryAfter,
		}
		if err := validatePendingPersonTokenRecord(record); err != nil {
			return err
		}
		var createErr error
		if mission != nil {
			createErr = server.missionDeferredTokens.CreateMissionPendingPersonToken(
				request.Context(), cloneMissionRecordForTransition(*mission), record, server.clock.Now().UTC(),
			)
		} else {
			createErr = server.deferredTokens.CreatePendingPersonToken(request.Context(), record)
		}
		if createErr != nil {
			if errors.Is(createErr, ErrPendingPersonTokenConflict) {
				continue
			}
			return createErr
		}
		location := "/person/pending/" + id
		response.Header().Set("Location", location)
		response.Header().Set("Retry-After", strconv.FormatInt(int64(policy.RetryAfter/time.Second), 10))
		response.Header().Set("AAuth-Requirement", requirement)
		writePrivateJSON(response, http.StatusAccepted, struct {
			Status string `json:"status"`
		}{Status: "pending"})
		return nil
	}
	return errors.New("personserver: could not allocate a unique pending person-token request")
}

func pendingInteractionURL(base, id string) (string, error) {
	parsed, err := url.Parse(base)
	if err != nil {
		return "", err
	}
	parsed.Path = strings.TrimRight(parsed.Path, "/") + "/" + id
	parsed.RawPath = ""
	return parsed.String(), nil
}

func missionS256(record *MissionRecord) string {
	if record == nil {
		return ""
	}
	return record.S256
}

// ConsumePersonTokenInteractionCode correlates the code entered at one
// pending-reference URL and atomically consumes it. Neither value authorizes
// the request. The host must authenticate the person separately before
// deciding. Every failed code, malformed or wrong, counts against the
// pending interaction; after MaximumPersonTokenCodeAttempts the interaction
// is terminally failed, later presentations return ErrPendingPersonTokenGone,
// and the Agent's poll answers invalid_code.
func (server *Server) ConsumePersonTokenInteractionCode(ctx context.Context, reference, code string) (PersonTokenInteraction, error) {
	if server == nil || server.deferredTokens == nil {
		return PersonTokenInteraction{}, errors.New("personserver: person-token interactions are not configured")
	}
	if ctx == nil {
		return PersonTokenInteraction{}, errors.New("personserver: context is required")
	}
	if reference == "" {
		return PersonTokenInteraction{}, ErrInteractionCodeInvalid
	}
	presentation := PersonTokenCodePresentation{}
	if digest, err := interaction.Digest(code); err == nil {
		presentation.CodeSHA256 = digest
		presentation.SyntacticallyValid = true
	}
	record, err := server.deferredTokens.ConsumePersonTokenInteractionCode(
		ctx, server.issuer, reference, presentation, server.clock.Now().UTC(),
	)
	if err != nil {
		return PersonTokenInteraction{}, err
	}
	if !presentation.SyntacticallyValid {
		return PersonTokenInteraction{}, errors.New("personserver: interaction store accepted a malformed code")
	}
	if err := validatePendingPersonTokenRecord(record); err != nil {
		return PersonTokenInteraction{}, err
	}
	if record.ID != reference || record.PersonServer != server.issuer || record.CodeSHA256 != presentation.CodeSHA256 {
		return PersonTokenInteraction{}, errors.New("personserver: interaction store returned a different pending request")
	}
	return server.personTokenInteractionFromRecord(ctx, record, server.clock.Now().UTC())
}

// ResumePersonTokenInteraction reconstructs the non-authoritative host handle
// from a retained reference after process restart. The host must keep the
// reference in its authenticated session; the reference alone cannot approve.
func (server *Server) ResumePersonTokenInteraction(ctx context.Context, reference string) (PersonTokenInteraction, error) {
	if server == nil || server.deferredTokens == nil {
		return PersonTokenInteraction{}, errors.New("personserver: person-token interactions are not configured")
	}
	if ctx == nil {
		return PersonTokenInteraction{}, errors.New("personserver: context is required")
	}
	if reference == "" {
		return PersonTokenInteraction{}, errors.New("personserver: interaction reference is required")
	}
	snapshot, err := server.deferredTokens.LoadPendingPersonToken(ctx, reference)
	if err != nil {
		return PersonTokenInteraction{}, err
	}
	if err := server.validatePendingPersonTokenSnapshot(snapshot); err != nil {
		return PersonTokenInteraction{}, err
	}
	if snapshot.Record.ID != reference {
		return PersonTokenInteraction{}, errors.New("personserver: interaction store returned a different reference")
	}
	switch snapshot.State {
	case PersonTokenPollWaiting, PersonTokenPollInteracting, PersonTokenPollApproved, PersonTokenPollDenied:
		return server.personTokenInteractionFromRecord(ctx, snapshot.Record, server.clock.Now().UTC())
	case PersonTokenPollExpired:
		return PersonTokenInteraction{}, ErrPendingPersonTokenExpired
	case PersonTokenPollGone:
		return PersonTokenInteraction{}, ErrPendingPersonTokenGone
	default:
		return PersonTokenInteraction{}, ErrPendingPersonTokenConflict
	}
}

func (server *Server) personTokenInteractionFromRecord(
	ctx context.Context,
	record PendingPersonTokenRecord,
	at time.Time,
) (PersonTokenInteraction, error) {
	interaction := PersonTokenInteraction{
		kind: personTokenInteractionCorrelated, personServer: server.issuer, id: record.ID,
		codeSHA256:    record.CodeSHA256,
		agentProvider: record.AgentProvider, agent: record.Agent, agentTokenJTI: record.AgentTokenJTI,
		parentAgent: record.ParentAgent, requestingAgent: record.RequestingAgent,
		requestingAgentTokenJTI: record.RequestingAgentTokenJTI,
		resource:                record.Resource, missionS256: record.MissionS256, confirmation: record.Confirmation,
		agentExpiresAt: record.AgentExpiresAt, requestingConfirmation: record.RequestingConfirmation,
		requestingAgentExpiresAt: record.RequestingAgentExpiresAt,
		createdAt:                record.CreatedAt, expiresAt: record.ExpiresAt, retryAfter: record.RetryAfter,
		agentAdditionalClaims:           cloneClaims(record.AgentAdditionalClaims),
		requestingAgentAdditionalClaims: cloneClaims(record.RequestingAgentAdditionalClaims),
	}
	if record.MissionS256 == "" {
		return interaction, nil
	}
	if server.missionDeferredTokens == nil {
		return PersonTokenInteraction{}, ErrPendingPersonTokenConflict
	}
	mission, err := server.loadActiveMission(ctx, record.MissionS256, record.Agent, at)
	if err != nil {
		return PersonTokenInteraction{}, err
	}
	context, err := missionContextFromRecord(mission)
	if err != nil {
		return PersonTokenInteraction{}, err
	}
	interaction.mission = context
	clone := cloneMissionRecordForTransition(mission)
	interaction.missionRecord = &clone
	return interaction, nil
}

// ApprovePersonTokenInteraction records a host-authenticated approval. The
// interaction code cannot call this method and is not an authorization input.
func (server *Server) ApprovePersonTokenInteraction(ctx context.Context, interaction PersonTokenInteraction, person Person) error {
	if err := validatePerson(person); err != nil {
		return err
	}
	snapshot, err := server.loadPersonTokenInteraction(ctx, interaction)
	if err != nil {
		return err
	}
	switch snapshot.State {
	case PersonTokenPollApproved:
		if snapshot.ApprovedPerson == person {
			return nil
		}
		return ErrPendingPersonTokenConflict
	case PersonTokenPollDenied, PersonTokenPollGone:
		return ErrPendingPersonTokenConflict
	case PersonTokenPollExpired:
		return ErrPendingPersonTokenExpired
	case PersonTokenPollInteracting:
		// Continue below.
	default:
		return ErrPendingPersonTokenConflict
	}
	now := server.clock.Now().UTC()
	if !now.Before(interaction.expiresAt) || !now.Before(interaction.agentExpiresAt) {
		return ErrPendingPersonTokenExpired
	}
	// The requesting Agent is top-level; its binding authorizes this issuance,
	// including one it mediates for a sub-agent. A revoked Agent token the
	// request was made with refuses the decision too.
	if err := server.checkPersonTokenWaitRevocations(ctx, snapshot.Record); err != nil {
		return err
	}
	expiresAt := now.Add(person.Lifetime)
	if interaction.agentExpiresAt.Before(expiresAt) {
		expiresAt = interaction.agentExpiresAt
	}
	if interaction.requestingAgentExpiresAt.Before(expiresAt) {
		expiresAt = interaction.requestingAgentExpiresAt
	}
	if interaction.missionRecord != nil && !interaction.missionRecord.ExpiresAt.IsZero() && interaction.missionRecord.ExpiresAt.Before(expiresAt) {
		expiresAt = interaction.missionRecord.ExpiresAt
	}
	claims := aauth.PersonTokenClaims{
		Issuer: server.issuer, DWK: aauth.PersonDiscoveryDocument,
		Audience: interaction.resource, Subject: person.Subject,
		Confirmation: aauth.Confirmation{JWK: interaction.confirmation},
		JTI:          server.newID(), IssuedAt: now.Unix(), ExpiresAt: expiresAt.Unix(), Tenant: person.Tenant,
		MissionS256: interaction.missionS256,
	}
	compact, err := aauth.MintPersonToken(server.signingKey, claims)
	if err != nil {
		return err
	}
	canonicalExpiry := time.Unix(claims.ExpiresAt, 0).UTC()
	record := PersonTokenRecord{
		JTI: claims.JTI, PersonServer: claims.Issuer, Resource: claims.Audience,
		Subject: claims.Subject, MissionS256: claims.MissionS256, Tenant: claims.Tenant,
		AgentProvider: interaction.agentProvider, Agent: interaction.agent,
		ParentAgent: interaction.parentAgent, Confirmation: interaction.confirmation,
		AgentTokenJTI: interaction.agentTokenJTI,
		ExpiresAt:     canonicalExpiry,
		RetainUntil: canonicalExpiry.Add(
			server.maximumResourceTokenLifetime + aauth.MaximumAuthTokenLifetime,
		),
	}
	approval := PersonTokenApproval{
		Person: person, Token: compact, Record: record,
		ExpiresIn: claims.ExpiresAt - claims.IssuedAt, DecidedAt: now,
	}
	if interaction.missionRecord != nil {
		return server.missionDeferredTokens.ApproveMissionPendingPersonToken(
			ctx, cloneMissionRecordForTransition(*interaction.missionRecord), interaction.id, approval, now,
		)
	}
	return server.deferredTokens.ApprovePendingPersonToken(ctx, interaction.id, approval)
}

// DenyPersonTokenInteraction records a host-authenticated denial.
func (server *Server) DenyPersonTokenInteraction(ctx context.Context, interaction PersonTokenInteraction) error {
	snapshot, err := server.loadPersonTokenInteraction(ctx, interaction)
	if err != nil {
		return err
	}
	switch snapshot.State {
	case PersonTokenPollDenied:
		return nil
	case PersonTokenPollApproved, PersonTokenPollGone:
		return ErrPendingPersonTokenConflict
	case PersonTokenPollExpired:
		return ErrPendingPersonTokenExpired
	case PersonTokenPollInteracting:
		// Continue below.
	default:
		return ErrPendingPersonTokenConflict
	}
	now := server.clock.Now().UTC()
	if !now.Before(interaction.expiresAt) {
		return ErrPendingPersonTokenExpired
	}
	if interaction.missionRecord != nil {
		return server.missionDeferredTokens.DenyMissionPendingPersonToken(
			ctx, cloneMissionRecordForTransition(*interaction.missionRecord), interaction.id, now,
		)
	}
	return server.deferredTokens.DenyPendingPersonToken(ctx, interaction.id, now)
}

// InvalidatePersonTokenInteraction terminally fails a pending interaction. The
// store already does so after MaximumPersonTokenCodeAttempts failed codes; a
// host whose own limiter at the authenticated interaction endpoint trips
// sooner calls this.
func (server *Server) InvalidatePersonTokenInteraction(ctx context.Context, interaction PersonTokenInteraction) error {
	snapshot, err := server.loadPersonTokenInteraction(ctx, interaction)
	if err != nil {
		return err
	}
	switch snapshot.State {
	case PersonTokenPollGone:
		return nil
	case PersonTokenPollWaiting, PersonTokenPollInteracting:
		return server.deferredTokens.InvalidatePendingPersonToken(ctx, interaction.id, server.clock.Now().UTC())
	case PersonTokenPollExpired:
		return ErrPendingPersonTokenExpired
	default:
		return ErrPendingPersonTokenConflict
	}
}

func (server *Server) loadPersonTokenInteraction(ctx context.Context, interaction PersonTokenInteraction) (PendingPersonTokenSnapshot, error) {
	if err := server.validateCorrelatedPersonTokenInteraction(ctx, interaction); err != nil {
		return PendingPersonTokenSnapshot{}, err
	}
	snapshot, err := server.deferredTokens.LoadPendingPersonToken(ctx, interaction.id)
	if err != nil {
		return PendingPersonTokenSnapshot{}, err
	}
	if err := server.validatePendingPersonTokenSnapshot(snapshot); err != nil {
		return PendingPersonTokenSnapshot{}, err
	}
	if !pendingRecordMatchesInteraction(snapshot.Record, interaction) {
		return PendingPersonTokenSnapshot{}, ErrPendingPersonTokenConflict
	}
	if interaction.missionRecord != nil {
		current, err := server.loadActiveMission(
			ctx, interaction.missionRecord.S256, interaction.missionRecord.Agent, server.clock.Now().UTC(),
		)
		if err != nil {
			return PendingPersonTokenSnapshot{}, err
		}
		if !interaction.missionRecord.Equal(current) {
			return PendingPersonTokenSnapshot{}, ErrMissionConflict
		}
	}
	return snapshot, nil
}

func (server *Server) validatePendingPersonTokenSnapshot(snapshot PendingPersonTokenSnapshot) error {
	if err := validatePendingPersonTokenRecord(snapshot.Record); err != nil {
		return err
	}
	if snapshot.Record.PersonServer != server.issuer {
		return errors.New("personserver: pending snapshot belongs to another Person Server")
	}
	switch snapshot.State {
	case PersonTokenPollWaiting, PersonTokenPollInteracting, PersonTokenPollDenied,
		PersonTokenPollExpired, PersonTokenPollGone:
		if snapshot.ApprovedPerson != (Person{}) {
			return errors.New("personserver: non-approved snapshot contains a Person")
		}
	case PersonTokenPollApproved:
		if err := validatePerson(snapshot.ApprovedPerson); err != nil {
			return errors.New("personserver: approved snapshot contains an invalid Person")
		}
	default:
		return errors.New("personserver: pending snapshot has an invalid state")
	}
	return nil
}

func pendingRecordMatchesInteraction(record PendingPersonTokenRecord, interaction PersonTokenInteraction) bool {
	return record.ID == interaction.id && record.CodeSHA256 == interaction.codeSHA256 &&
		record.PersonServer == interaction.personServer && record.AgentProvider == interaction.agentProvider &&
		record.Agent == interaction.agent && record.ParentAgent == interaction.parentAgent &&
		record.AgentTokenJTI == interaction.agentTokenJTI &&
		record.RequestingAgentTokenJTI == interaction.requestingAgentTokenJTI &&
		record.Resource == interaction.resource && record.MissionS256 == interaction.missionS256 &&
		record.Confirmation.Equal(interaction.confirmation) &&
		record.AgentExpiresAt.Equal(interaction.agentExpiresAt) &&
		record.RequestingAgent == interaction.requestingAgent &&
		record.RequestingConfirmation.Equal(interaction.requestingConfirmation) &&
		record.RequestingAgentExpiresAt.Equal(interaction.requestingAgentExpiresAt) &&
		record.CreatedAt.Equal(interaction.createdAt) &&
		record.ExpiresAt.Equal(interaction.expiresAt) && record.RetryAfter == interaction.retryAfter &&
		reflect.DeepEqual(record.AgentAdditionalClaims, interaction.agentAdditionalClaims) &&
		reflect.DeepEqual(record.RequestingAgentAdditionalClaims, interaction.requestingAgentAdditionalClaims)
}

func (server *Server) validateCorrelatedPersonTokenInteraction(ctx context.Context, interaction PersonTokenInteraction) error {
	if server == nil || server.deferredTokens == nil {
		return errors.New("personserver: person-token interactions are not configured")
	}
	if ctx == nil {
		return errors.New("personserver: context is required")
	}
	if interaction.kind != personTokenInteractionCorrelated || interaction.personServer != server.issuer ||
		interaction.id == "" || interaction.codeSHA256 == ([32]byte{}) || interaction.agent == "" ||
		interaction.requestingAgent == "" || interaction.resource == "" || interaction.createdAt.IsZero() ||
		interaction.expiresAt.IsZero() || interaction.agentExpiresAt.IsZero() || interaction.requestingAgentExpiresAt.IsZero() {
		return errors.New("personserver: a correlated person-token interaction is required")
	}
	if (interaction.missionS256 == "") != (interaction.missionRecord == nil) ||
		(interaction.missionS256 == "") != (interaction.mission == nil) {
		return errors.New("personserver: interaction mission state is invalid")
	}
	if interaction.missionS256 != "" &&
		(aauth.ValidateMissionS256(interaction.missionS256) != nil ||
			interaction.missionRecord.S256 != interaction.missionS256 ||
			interaction.missionRecord.Agent != interaction.agent ||
			interaction.mission.S256 != interaction.missionS256) {
		return errors.New("personserver: interaction mission state is invalid")
	}
	if _, err := interaction.confirmation.PublicKey(); err != nil {
		return errors.New("personserver: interaction confirmation key is invalid")
	}
	if _, err := interaction.requestingConfirmation.PublicKey(); err != nil {
		return errors.New("personserver: interaction requesting confirmation key is invalid")
	}
	return nil
}

func validatePerson(person Person) error {
	if person.Subject == "" || person.Lifetime <= 0 || person.Lifetime > maximumPersonLifetime {
		return errors.New("personserver: person binding is invalid")
	}
	return nil
}

func (server *Server) handlePendingPersonToken(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		response.Header().Set("Allow", http.MethodGet)
		writeProblem(response, http.StatusMethodNotAllowed, "method_not_allowed", errors.New("person-token polling requires GET"))
		return
	}
	if server.deferredTokens == nil {
		writeProblem(response, http.StatusGone, "invalid_code", ErrPendingPersonTokenNotFound)
		return
	}
	_, agent, _, err := server.verifyAgentRequest(request, nil)
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
		writeProblem(response, http.StatusGone, "invalid_code", ErrPendingPersonTokenNotFound)
		return
	}
	identity := PersonTokenPollIdentity{
		PersonServer: server.issuer, Agent: agent.Subject, ConfirmationThumbprint: thumbprint,
	}
	now := server.clock.Now().UTC()
	var mission *MissionRecord
	var result PersonTokenPollRecord
	snapshot, snapshotErr := server.deferredTokens.LoadPendingPersonToken(request.Context(), id)
	if snapshotErr == nil {
		if err := server.validatePendingPersonTokenSnapshot(snapshot); err != nil {
			writeProblem(response, http.StatusInternalServerError, "server_error", err)
			return
		}
		retainedJKT, thumbprintErr := snapshot.Record.RequestingConfirmation.Thumbprint()
		if thumbprintErr != nil {
			writeProblem(response, http.StatusInternalServerError, "server_error", ErrPendingPersonTokenConflict)
			return
		}
		if snapshot.Record.PersonServer != identity.PersonServer || snapshot.Record.AgentProvider != agent.Issuer ||
			snapshot.Record.RequestingAgent != identity.Agent || retainedJKT != identity.ConfirmationThumbprint {
			writeProblem(response, http.StatusGone, "invalid_code", ErrPendingPersonTokenNotFound)
			return
		}
		if snapshot.Record.MissionS256 != "" {
			if server.missionDeferredTokens == nil {
				writeProblem(response, http.StatusInternalServerError, "server_error", ErrPendingPersonTokenConflict)
				return
			}
			loaded, loadErr := server.loadActiveMission(
				request.Context(), snapshot.Record.MissionS256, snapshot.Record.RequestingAgent, now,
			)
			if loadErr != nil {
				writeMissionActionProblem(response, loadErr)
				return
			}
			mission = &loaded
			result, err = server.missionDeferredTokens.PollMissionPendingPersonToken(
				request.Context(), cloneMissionRecordForTransition(loaded), id, identity, now,
			)
		} else {
			result, err = server.deferredTokens.PollPendingPersonToken(request.Context(), id, identity, now)
		}
	} else {
		err = snapshotErr
	}
	if err != nil {
		if mission != nil {
			writeMissionActionProblem(response, err)
			return
		}
		switch {
		case errors.Is(err, ErrPendingPersonTokenExpired):
			writeProblem(response, http.StatusRequestTimeout, "expired", err)
		case errors.Is(err, ErrPendingPersonTokenNotFound), errors.Is(err, ErrPendingPersonTokenGone):
			writeProblem(response, http.StatusGone, "invalid_code", err)
		default:
			writeProblem(response, http.StatusInternalServerError, "server_error", err)
		}
		return
	}
	switch result.State {
	case PersonTokenPollWaiting, PersonTokenPollInteracting, PersonTokenPollApproved:
		// A revoked Agent token or binding ends a live request and withholds a
		// retained token. The answer is terminal, so the request is ended first.
		if err := server.checkPersonTokenWaitRevocations(request.Context(), snapshot.Record); err != nil {
			if pendingRevoked(err) && !server.endPendingPersonToken(response, request, id, identity, result, mission) {
				return
			}
			writePendingRevocationProblem(response, err, http.StatusForbidden, "person_token_denied")
			return
		}
	}
	switch result.State {
	case PersonTokenPollWaiting:
		server.writePendingPersonToken(response, request.URL.Path, result.RetryAfter, "pending")
	case PersonTokenPollInteracting:
		server.writePendingPersonToken(response, request.URL.Path, result.RetryAfter, "interacting")
	case PersonTokenPollApproved:
		if err := server.validateApprovedPersonToken(request.Context(), result, snapshot.Record); err != nil {
			var tokenFailure *aauth.TokenValidationError
			if errors.As(err, &tokenFailure) && tokenFailure.Code == aauth.TokenValidationExpired {
				if !server.consumePendingPersonTokenResult(response, request, id, result, mission) {
					return
				}
				writeProblem(response, http.StatusRequestTimeout, "expired", err)
				return
			}
			writeProblem(response, http.StatusInternalServerError, "server_error", err)
			return
		}
		if !server.consumePendingPersonTokenResult(response, request, id, result, mission) {
			return
		}
		writePrivateJSON(response, http.StatusOK, struct {
			PersonToken string `json:"person_token"`
			ExpiresIn   int64  `json:"expires_in"`
		}{PersonToken: result.Token, ExpiresIn: result.ExpiresIn})
	case PersonTokenPollDenied:
		if !server.consumePendingPersonTokenResult(response, request, id, result, mission) {
			return
		}
		writeProblem(response, http.StatusForbidden, "denied", errors.New("person-token interaction was denied"))
	case PersonTokenPollExpired:
		if !server.consumePendingPersonTokenResult(response, request, id, result, mission) {
			return
		}
		writeProblem(response, http.StatusRequestTimeout, "expired", ErrPendingPersonTokenExpired)
	case PersonTokenPollGone:
		writeProblem(response, http.StatusGone, "invalid_code", ErrPendingPersonTokenGone)
	default:
		writeProblem(response, http.StatusInternalServerError, "server_error", errors.New("personserver: store returned an invalid pending state"))
	}
}

// checkPersonTokenWaitRevocations applies revocations to the Agent tokens a
// Person-token wait was started with and to the requesting Agent's binding.
func (server *Server) checkPersonTokenWaitRevocations(ctx context.Context, record PendingPersonTokenRecord) error {
	child := ""
	if record.ParentAgent != "" {
		child = record.AgentTokenJTI
	}
	return server.checkPendingRevocations(ctx, record.AgentProvider, record.RequestingAgent,
		record.RequestingAgentTokenJTI, child, record.CreatedAt)
}

// endPendingPersonToken makes a revocation answer terminal: it invalidates a
// live request and consumes a retained result, so the pending URL is gone
// afterwards. It reports whether the caller may write its answer.
func (server *Server) endPendingPersonToken(
	response http.ResponseWriter,
	request *http.Request,
	id string,
	identity PersonTokenPollIdentity,
	result PersonTokenPollRecord,
	mission *MissionRecord,
) bool {
	ctx := request.Context()
	for attempt := 0; attempt < 3; attempt++ {
		now := server.clock.Now().UTC()
		switch result.State {
		case PersonTokenPollGone:
			return true
		case PersonTokenPollWaiting, PersonTokenPollInteracting:
			err := server.deferredTokens.InvalidatePendingPersonToken(ctx, id, now)
			if err == nil {
				return true
			}
			if !errors.Is(err, ErrPendingPersonTokenConflict) && !errors.Is(err, ErrPendingPersonTokenExpired) {
				writeProblem(response, http.StatusInternalServerError, "server_error", err)
				return false
			}
		default:
			return server.consumePendingPersonTokenResult(response, request, id, result, mission)
		}
		var err error
		if mission != nil {
			result, err = server.missionDeferredTokens.PollMissionPendingPersonToken(
				ctx, cloneMissionRecordForTransition(*mission), id, identity, now,
			)
		} else {
			result, err = server.deferredTokens.PollPendingPersonToken(ctx, id, identity, now)
		}
		if errors.Is(err, ErrPendingPersonTokenNotFound) || errors.Is(err, ErrPendingPersonTokenGone) {
			return true
		}
		if err != nil {
			writeProblem(response, http.StatusInternalServerError, "server_error", err)
			return false
		}
	}
	writeProblem(response, http.StatusInternalServerError, "server_error", ErrPendingPersonTokenConflict)
	return false
}

func (server *Server) consumePendingPersonTokenResult(
	response http.ResponseWriter,
	request *http.Request,
	id string,
	result PersonTokenPollRecord,
	mission *MissionRecord,
) bool {
	var err error
	if mission != nil {
		err = server.missionDeferredTokens.ConsumeMissionPendingPersonTokenResult(
			request.Context(), cloneMissionRecordForTransition(*mission), id, result, server.clock.Now().UTC(),
		)
	} else {
		err = server.deferredTokens.ConsumePendingPersonTokenResult(request.Context(), id, result)
	}
	if err != nil {
		if mission != nil {
			writeMissionActionProblem(response, err)
			return false
		}
		if errors.Is(err, ErrPendingPersonTokenNotFound) || errors.Is(err, ErrPendingPersonTokenGone) {
			writeProblem(response, http.StatusGone, "invalid_code", err)
		} else {
			writeProblem(response, http.StatusInternalServerError, "server_error", err)
		}
		return false
	}
	return true
}

func (server *Server) writePendingPersonToken(response http.ResponseWriter, location string, retryAfter time.Duration, status string) {
	if retryAfter < 0 || retryAfter%time.Second != 0 || (status != "pending" && status != "interacting") {
		writeProblem(response, http.StatusInternalServerError, "server_error", errors.New("personserver: store returned an invalid pending response"))
		return
	}
	response.Header().Set("Location", location)
	response.Header().Set("Retry-After", strconv.FormatInt(int64(retryAfter/time.Second), 10))
	writePrivateJSON(response, http.StatusAccepted, struct {
		Status string `json:"status"`
	}{Status: status})
}

func (server *Server) validateApprovedPersonToken(
	ctx context.Context,
	result PersonTokenPollRecord,
	pending PendingPersonTokenRecord,
) error {
	if result.Token == "" || result.ExpiresIn <= 0 || validatePersonTokenRecord(result.Record) != nil {
		return errors.New("personserver: store returned an invalid approved person token")
	}
	claims, err := aauth.VerifyPersonToken(ctx, result.Token, server.keyResolver, server.clock)
	if err != nil {
		return err
	}
	if claims.Issuer != server.issuer || claims.JTI != result.Record.JTI || claims.Audience != result.Record.Resource ||
		claims.Subject != result.Record.Subject || claims.MissionS256 != result.Record.MissionS256 ||
		claims.Tenant != result.Record.Tenant || !claims.Confirmation.JWK.Equal(result.Record.Confirmation) ||
		result.Record.AgentProvider != pending.AgentProvider || result.Record.Agent != pending.Agent ||
		result.Record.ParentAgent != pending.ParentAgent || !result.Record.Confirmation.Equal(pending.Confirmation) ||
		claims.ExpiresAt != result.Record.ExpiresAt.Unix() || result.ExpiresIn != claims.ExpiresAt-claims.IssuedAt {
		return errors.New("personserver: approved person token does not match its retained record")
	}
	return nil
}
