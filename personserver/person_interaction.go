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

	aauth "github.com/aauth-dev/auth-go"
	"github.com/aauth-dev/auth-go/internal/interaction"
	"github.com/aauth-dev/auth-go/jose"
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
// a person-token interaction is exposed. CodeSHA256 hashes the normalized
// correlation code; the plaintext code is not durable authority.
type PendingPersonTokenRecord struct {
	ID                    string
	CodeSHA256            [32]byte
	PersonServer          string
	Agent                 string
	Resource              string
	Confirmation          jose.JWK
	AgentExpiresAt        time.Time
	AgentAdditionalClaims map[string]json.RawMessage
	CreatedAt             time.Time
	ExpiresAt             time.Time
	RetryAfter            time.Duration
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
//   - Consume matches issuer, pending reference, and digest, gives terminal/used
//     state precedence over expiry, and changes one live unused code to
//     interacting.
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
// first retained value remains canonical. The host rate-limits failed code
// entries at its authenticated interaction URL and calls Invalidate when the
// bound is reached.
type DeferredTokenStore interface {
	TokenStore
	CreatePendingPersonToken(context.Context, PendingPersonTokenRecord) error
	ConsumePersonTokenInteractionCode(context.Context, string, string, [32]byte, time.Time) (PendingPersonTokenRecord, error)
	LoadPendingPersonToken(context.Context, string) (PendingPersonTokenSnapshot, error)
	ApprovePendingPersonToken(context.Context, string, PersonTokenApproval) error
	DenyPendingPersonToken(context.Context, string, time.Time) error
	InvalidatePendingPersonToken(context.Context, string, time.Time) error
	PollPendingPersonToken(context.Context, string, PersonTokenPollIdentity, time.Time) (PersonTokenPollRecord, error)
	ConsumePendingPersonTokenResult(context.Context, string, PersonTokenPollRecord) error
}

// PersonTokenInteraction is a correlated pending request. Receiving this value
// proves only that a code matched. The host must authenticate the person before
// calling an approval or denial method.
type PersonTokenInteraction struct {
	kind                  personTokenInteractionKind
	personServer          string
	id                    string
	codeSHA256            [32]byte
	agent                 string
	resource              string
	confirmation          jose.JWK
	agentExpiresAt        time.Time
	createdAt             time.Time
	expiresAt             time.Time
	retryAfter            time.Duration
	agentAdditionalClaims map[string]json.RawMessage
}

type personTokenInteractionKind uint8

const personTokenInteractionCorrelated personTokenInteractionKind = 1

// Agent returns the verified Agent that requested the token.
func (interaction PersonTokenInteraction) Agent() string { return interaction.agent }

// Resource returns the exact resource for which the person token was requested.
func (interaction PersonTokenInteraction) Resource() string { return interaction.resource }

// Reference returns a non-secret continuation value that the authenticated
// host may retain across process restart. It does not authorize a decision.
func (interaction PersonTokenInteraction) Reference() string { return interaction.id }

// ExpiresAt returns the pending interaction deadline.
func (interaction PersonTokenInteraction) ExpiresAt() time.Time { return interaction.expiresAt }

// AgentAdditionalClaims returns an independent copy of the Agent Provider
// claims available to host policy.
func (interaction PersonTokenInteraction) AgentAdditionalClaims() map[string]json.RawMessage {
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
	if record.ID == "" || record.CodeSHA256 == ([32]byte{}) || record.PersonServer == "" || record.Agent == "" || record.Resource == "" ||
		record.AgentExpiresAt.IsZero() || record.CreatedAt.IsZero() || !record.ExpiresAt.After(record.CreatedAt) ||
		record.AgentExpiresAt.Before(record.ExpiresAt) || record.RetryAfter < 0 || record.RetryAfter%time.Second != 0 {
		return errors.New("personserver: pending person-token record is invalid")
	}
	if err := aauth.ValidateServerIdentifier(record.PersonServer); err != nil {
		return err
	}
	if err := aauth.ValidateAgentIdentifier(record.Agent); err != nil {
		return err
	}
	if err := aauth.ValidateServerIdentifier(record.Resource); err != nil {
		return err
	}
	if _, err := record.Confirmation.PublicKey(); err != nil {
		return fmt.Errorf("personserver: pending confirmation key: %w", err)
	}
	return nil
}

func (server *Server) beginPersonTokenInteraction(
	response http.ResponseWriter,
	request *http.Request,
	personRequest PersonTokenRequest,
	agent aauth.AgentTokenClaims,
	policy PersonTokenInteractionPolicy,
) error {
	if server.deferredTokens == nil {
		return errors.New("personserver: deferred token store is required")
	}
	if err := validatePersonTokenInteractionPolicy(policy); err != nil {
		return err
	}
	createdAt := server.clock.Now().UTC()
	expiresAt := createdAt.Add(policy.Lifetime)
	agentExpiresAt := time.Unix(agent.ExpiresAt, 0).UTC()
	if agentExpiresAt.Before(expiresAt) {
		expiresAt = agentExpiresAt
	}
	if !expiresAt.After(createdAt) {
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
			ID: id, CodeSHA256: codeSHA256, PersonServer: server.issuer, Agent: personRequest.Agent,
			Resource: personRequest.Resource, Confirmation: agent.Confirmation.JWK,
			AgentExpiresAt:        agentExpiresAt,
			AgentAdditionalClaims: cloneClaims(personRequest.AgentAdditionalClaims),
			CreatedAt:             createdAt, ExpiresAt: expiresAt, RetryAfter: policy.RetryAfter,
		}
		if err := validatePendingPersonTokenRecord(record); err != nil {
			return err
		}
		if err := server.deferredTokens.CreatePendingPersonToken(request.Context(), record); err != nil {
			if errors.Is(err, ErrPendingPersonTokenConflict) {
				continue
			}
			return err
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

// ConsumePersonTokenInteractionCode correlates the code entered at one
// pending-reference URL and atomically consumes it. Neither value authorizes
// the request. The host must authenticate the person separately before
// deciding.
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
	digest, err := interaction.Digest(code)
	if err != nil {
		return PersonTokenInteraction{}, ErrInteractionCodeInvalid
	}
	record, err := server.deferredTokens.ConsumePersonTokenInteractionCode(ctx, server.issuer, reference, digest, server.clock.Now().UTC())
	if err != nil {
		return PersonTokenInteraction{}, err
	}
	if err := validatePendingPersonTokenRecord(record); err != nil {
		return PersonTokenInteraction{}, err
	}
	if record.ID != reference || record.PersonServer != server.issuer || record.CodeSHA256 != digest {
		return PersonTokenInteraction{}, errors.New("personserver: interaction store returned a different pending request")
	}
	return personTokenInteractionFromRecord(server.issuer, record), nil
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
		return personTokenInteractionFromRecord(server.issuer, snapshot.Record), nil
	case PersonTokenPollExpired:
		return PersonTokenInteraction{}, ErrPendingPersonTokenExpired
	case PersonTokenPollGone:
		return PersonTokenInteraction{}, ErrPendingPersonTokenGone
	default:
		return PersonTokenInteraction{}, ErrPendingPersonTokenConflict
	}
}

func personTokenInteractionFromRecord(issuer string, record PendingPersonTokenRecord) PersonTokenInteraction {
	return PersonTokenInteraction{
		kind: personTokenInteractionCorrelated, personServer: issuer, id: record.ID,
		codeSHA256: record.CodeSHA256,
		agent:      record.Agent, resource: record.Resource, confirmation: record.Confirmation,
		agentExpiresAt: record.AgentExpiresAt, createdAt: record.CreatedAt, expiresAt: record.ExpiresAt,
		retryAfter:            record.RetryAfter,
		agentAdditionalClaims: cloneClaims(record.AgentAdditionalClaims),
	}
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
	expiresAt := now.Add(person.Lifetime)
	if interaction.agentExpiresAt.Before(expiresAt) {
		expiresAt = interaction.agentExpiresAt
	}
	claims := aauth.PersonTokenClaims{
		Issuer: server.issuer, DWK: aauth.PersonDiscoveryDocument,
		Audience: interaction.resource, Subject: person.Subject,
		Confirmation: aauth.Confirmation{JWK: interaction.confirmation},
		JTI:          server.newID(), IssuedAt: now.Unix(), ExpiresAt: expiresAt.Unix(), Tenant: person.Tenant,
	}
	compact, err := aauth.MintPersonToken(server.signingKey, claims)
	if err != nil {
		return err
	}
	canonicalExpiry := time.Unix(claims.ExpiresAt, 0).UTC()
	record := PersonTokenRecord{
		JTI: claims.JTI, PersonServer: claims.Issuer, Resource: claims.Audience,
		Subject: claims.Subject, MissionS256: claims.MissionS256, Tenant: claims.Tenant,
		ExpiresAt: canonicalExpiry, RetainUntil: canonicalExpiry.Add(server.maximumResourceTokenLifetime),
	}
	return server.deferredTokens.ApprovePendingPersonToken(ctx, interaction.id, PersonTokenApproval{
		Person: person, Token: compact, Record: record,
		ExpiresIn: claims.ExpiresAt - claims.IssuedAt, DecidedAt: now,
	})
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
	return server.deferredTokens.DenyPendingPersonToken(ctx, interaction.id, now)
}

// InvalidatePersonTokenInteraction terminally fails a pending interaction after
// the host's rate limiter reaches its failed-code-attempt bound. The host owns
// the authenticated interaction endpoint and its attempt key; this package
// owns only the retained terminal transition.
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
		record.PersonServer == interaction.personServer && record.Agent == interaction.agent &&
		record.Resource == interaction.resource && record.Confirmation.Equal(interaction.confirmation) &&
		record.AgentExpiresAt.Equal(interaction.agentExpiresAt) && record.CreatedAt.Equal(interaction.createdAt) &&
		record.ExpiresAt.Equal(interaction.expiresAt) && record.RetryAfter == interaction.retryAfter &&
		reflect.DeepEqual(record.AgentAdditionalClaims, interaction.agentAdditionalClaims)
}

func (server *Server) validateCorrelatedPersonTokenInteraction(ctx context.Context, interaction PersonTokenInteraction) error {
	if server == nil || server.deferredTokens == nil {
		return errors.New("personserver: person-token interactions are not configured")
	}
	if ctx == nil {
		return errors.New("personserver: context is required")
	}
	if interaction.kind != personTokenInteractionCorrelated || interaction.personServer != server.issuer ||
		interaction.id == "" || interaction.codeSHA256 == ([32]byte{}) || interaction.agent == "" || interaction.resource == "" ||
		interaction.createdAt.IsZero() || interaction.expiresAt.IsZero() || interaction.agentExpiresAt.IsZero() {
		return errors.New("personserver: a correlated person-token interaction is required")
	}
	if _, err := interaction.confirmation.PublicKey(); err != nil {
		return errors.New("personserver: interaction confirmation key is invalid")
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
	result, err := server.deferredTokens.PollPendingPersonToken(request.Context(), id, PersonTokenPollIdentity{
		PersonServer: server.issuer, Agent: agent.Subject, ConfirmationThumbprint: thumbprint,
	}, server.clock.Now().UTC())
	if err != nil {
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
	case PersonTokenPollWaiting:
		server.writePendingPersonToken(response, request.URL.Path, result.RetryAfter, "pending")
	case PersonTokenPollInteracting:
		server.writePendingPersonToken(response, request.URL.Path, result.RetryAfter, "interacting")
	case PersonTokenPollApproved:
		if err := server.validateApprovedPersonToken(request.Context(), result, agent); err != nil {
			var tokenFailure *aauth.TokenValidationError
			if errors.As(err, &tokenFailure) && tokenFailure.Code == aauth.TokenValidationExpired {
				if !server.consumePendingPersonTokenResult(response, request, id, result) {
					return
				}
				writeProblem(response, http.StatusRequestTimeout, "expired", err)
				return
			}
			writeProblem(response, http.StatusInternalServerError, "server_error", err)
			return
		}
		if !server.consumePendingPersonTokenResult(response, request, id, result) {
			return
		}
		writePrivateJSON(response, http.StatusOK, struct {
			PersonToken string `json:"person_token"`
			ExpiresIn   int64  `json:"expires_in"`
		}{PersonToken: result.Token, ExpiresIn: result.ExpiresIn})
	case PersonTokenPollDenied:
		if !server.consumePendingPersonTokenResult(response, request, id, result) {
			return
		}
		writeProblem(response, http.StatusForbidden, "denied", errors.New("person-token interaction was denied"))
	case PersonTokenPollExpired:
		if !server.consumePendingPersonTokenResult(response, request, id, result) {
			return
		}
		writeProblem(response, http.StatusRequestTimeout, "expired", ErrPendingPersonTokenExpired)
	case PersonTokenPollGone:
		writeProblem(response, http.StatusGone, "invalid_code", ErrPendingPersonTokenGone)
	default:
		writeProblem(response, http.StatusInternalServerError, "server_error", errors.New("personserver: store returned an invalid pending state"))
	}
}

func (server *Server) consumePendingPersonTokenResult(
	response http.ResponseWriter,
	request *http.Request,
	id string,
	result PersonTokenPollRecord,
) bool {
	if err := server.deferredTokens.ConsumePendingPersonTokenResult(request.Context(), id, result); err != nil {
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

func (server *Server) validateApprovedPersonToken(ctx context.Context, result PersonTokenPollRecord, agent aauth.AgentTokenClaims) error {
	if result.Token == "" || result.ExpiresIn <= 0 || validatePersonTokenRecord(result.Record) != nil {
		return errors.New("personserver: store returned an invalid approved person token")
	}
	claims, err := aauth.VerifyPersonToken(ctx, result.Token, server.keyResolver, server.clock)
	if err != nil {
		return err
	}
	if claims.Issuer != server.issuer || claims.JTI != result.Record.JTI || claims.Audience != result.Record.Resource ||
		claims.Subject != result.Record.Subject || claims.MissionS256 != result.Record.MissionS256 ||
		claims.Tenant != result.Record.Tenant || !claims.Confirmation.JWK.Equal(agent.Confirmation.JWK) ||
		claims.ExpiresAt != result.Record.ExpiresAt.Unix() || result.ExpiresIn != claims.ExpiresAt-claims.IssuedAt {
		return errors.New("personserver: approved person token does not match its retained record")
	}
	return nil
}
