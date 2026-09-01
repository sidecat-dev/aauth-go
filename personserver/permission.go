package personserver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/internal/httpapi"
	"gitlab.com/sidecat-dev/aauth-go/internal/interaction"
)

const (
	maximumPermissionActionBytes      = 4 << 10
	maximumPermissionDescriptionBytes = 64 << 10
	maximumPermissionReasonBytes      = 64 << 10
)

var (
	// ErrPermissionNotFound cloaks an absent permission record and a poll made
	// under another Agent identity.
	ErrPermissionNotFound = errors.New("personserver: permission request not found")
	// ErrPermissionConflict reports a transition or retained value that does not
	// match the canonical permission request.
	ErrPermissionConflict = errors.New("personserver: permission request conflicts with retained state")
	// ErrPermissionExpired reports a permission request whose decision deadline
	// has passed.
	ErrPermissionExpired = errors.New("personserver: permission request expired")
	// ErrPermissionGone reports a permission result that has already been
	// consumed.
	ErrPermissionGone = errors.New("personserver: permission request is gone")
)

// PermissionConfig enables the top-level Agent permission endpoint. Policy
// evaluates verified intent only; it never executes Action. Store retains every
// immediate decision or deferred request before release. When missions are
// also configured, Store must be nil and the server's Tokens must implement
// MissionPermissionStore so mission, token, and permission state share one
// atomic backing-store boundary.
type PermissionConfig struct {
	Policy func(context.Context, PermissionPolicyRequest) (PermissionPolicyResult, error)
	Store  PermissionStore
}

// PermissionPolicyRequest is the caller-owned verified intent presented to
// host policy. Description and Parameters are untrusted display/application
// input. Sanitize Description before rendering and validate Parameters before
// any later application use. Mission is a caller-owned exact active context
// when the Agent supplied mission_s256, otherwise nil.
type PermissionPolicyRequest struct {
	AgentProvider         string
	Agent                 string
	AgentAdditionalClaims map[string]json.RawMessage
	Action                string
	Description           string
	Parameters            json.RawMessage
	Mission               *MissionContext
}

// PermissionPolicyResult selects exactly one immediate decision or deferred
// host-decision policy.
type PermissionPolicyResult struct {
	Immediate *PermissionDecision
	Deferred  *PermissionPendingPolicy
}

// PermissionDecision is the endpoint's decision. Reason is untrusted Markdown
// allowed only for a denial and must be sanitized before rendering.
type PermissionDecision struct {
	Permission aauth.Permission
	Reason     string
}

// PermissionPendingPolicy bounds one deferred permission request. Durations
// use whole seconds because they are exposed through HTTP delay-seconds.
type PermissionPendingPolicy struct {
	Lifetime   time.Duration
	RetryAfter time.Duration
}

// PermissionState is one retained permission endpoint state.
type PermissionState uint8

const (
	PermissionStatePending PermissionState = iota + 1
	PermissionStateGranted
	PermissionStateDenied
	PermissionStateExpired
	PermissionStateGone
)

// PermissionRecord is the complete purpose-specific retained permission state.
// Parameters and AgentAdditionalClaims must be copied at every store boundary.
type PermissionRecord struct {
	ID                     string
	PersonServer           string
	AgentProvider          string
	Agent                  string
	ConfirmationThumbprint string
	AgentExpiresAt         time.Time
	AgentAdditionalClaims  map[string]json.RawMessage
	MissionS256            string
	Action                 string
	Description            string
	Parameters             json.RawMessage
	State                  PermissionState
	Decision               PermissionDecision
	CreatedAt              time.Time
	ExpiresAt              time.Time
	DecidedAt              time.Time
	RetryAfter             time.Duration
}

// PermissionPollIdentity binds polling to the original Agent and proof key.
type PermissionPollIdentity struct {
	PersonServer           string
	AgentProvider          string
	Agent                  string
	ConfirmationThumbprint string
}

// PermissionStore owns only permission-endpoint request and decision state.
//
// CreatePermission atomically retains one unique complete record. Immediate
// records are Granted or Denied with a complete decision and decision time;
// deferred records are Pending with an expiry and no decision.
//
// LoadPermission materializes expiry before returning a caller-owned complete
// record. DecidePermission atomically materializes expiry, changes Pending to
// the requested terminal decision, and returns the first canonical record. An
// exact replay returns that record; a changed decision conflicts.
//
// PollPermission authenticates the complete identity, cloaking mismatch as
// ErrPermissionNotFound, materializes expiry, and returns one complete record.
// ConsumePermissionResult atomically compares the exact terminal record and
// changes it to Gone immediately before HTTP delivery. Concurrent exact
// consumers have one winner; every loser returns ErrPermissionGone. Every
// mutable input and output is an independent copy, and an error commits no
// partial transition.
type PermissionStore interface {
	CreatePermission(context.Context, PermissionRecord) error
	LoadPermission(context.Context, string, time.Time) (PermissionRecord, error)
	DecidePermission(context.Context, string, PermissionDecision, time.Time) (PermissionRecord, error)
	PollPermission(context.Context, string, PermissionPollIdentity, time.Time) (PermissionRecord, error)
	ConsumePermissionResult(context.Context, string, PermissionRecord) error
}

// MissionPermissionStore adds the atomic boundary required when a permission
// is associated with a mission. Each method compares the complete expected
// mission, materializes expiry at the supplied instant, requires the mission
// to remain active and owned by the permission Agent, and commits no
// permission change on mismatch or termination.
type MissionPermissionStore interface {
	MissionStore
	PermissionStore
	CreateMissionPermission(context.Context, MissionRecord, PermissionRecord, time.Time) error
	DecideMissionPermission(context.Context, MissionRecord, string, PermissionDecision, time.Time) (PermissionRecord, error)
	PollMissionPermission(context.Context, MissionRecord, string, PermissionPollIdentity, time.Time) (PermissionRecord, error)
	ConsumeMissionPermissionResult(context.Context, MissionRecord, string, PermissionRecord, time.Time) error
}

func permissionPolicy(config *PermissionConfig) func(context.Context, PermissionPolicyRequest) (PermissionPolicyResult, error) {
	if config == nil {
		return nil
	}
	return config.Policy
}

type permissionRequestKind uint8

const permissionRequestVerified permissionRequestKind = 1

// PermissionRequest is a verified private host handle for one deferred
// permission request. It carries no authority to execute the requested action.
type PermissionRequest struct {
	kind          permissionRequestKind
	record        PermissionRecord
	mission       *MissionContext
	missionRecord *MissionRecord
}

// AgentProvider returns the issuer of the verified Agent token.
func (request PermissionRequest) AgentProvider() string {
	if request.kind != permissionRequestVerified {
		return ""
	}
	return request.record.AgentProvider
}

// Agent returns the verified top-level Agent.
func (request PermissionRequest) Agent() string {
	if request.kind != permissionRequestVerified {
		return ""
	}
	return request.record.Agent
}

// AgentAdditionalClaims returns a caller-owned copy for host policy.
func (request PermissionRequest) AgentAdditionalClaims() map[string]json.RawMessage {
	if request.kind != permissionRequestVerified {
		return nil
	}
	return cloneClaims(request.record.AgentAdditionalClaims)
}

// Action returns the untrusted requested action identifier.
func (request PermissionRequest) Action() string {
	if request.kind != permissionRequestVerified {
		return ""
	}
	return request.record.Action
}

// Description returns untrusted Markdown. Sanitize it before rendering.
func (request PermissionRequest) Description() string {
	if request.kind != permissionRequestVerified {
		return ""
	}
	return request.record.Description
}

// Parameters returns a caller-owned copy of the untrusted JSON object.
func (request PermissionRequest) Parameters() json.RawMessage {
	if request.kind != permissionRequestVerified {
		return nil
	}
	return append(json.RawMessage(nil), request.record.Parameters...)
}

// Reference returns the opaque pending permission reference.
func (request PermissionRequest) Reference() string {
	if request.kind != permissionRequestVerified {
		return ""
	}
	return request.record.ID
}

// ExpiresAt returns the deferred decision deadline.
func (request PermissionRequest) ExpiresAt() time.Time {
	if request.kind != permissionRequestVerified {
		return time.Time{}
	}
	return request.record.ExpiresAt
}

// Mission returns the active mission context associated with this request.
// The returned values are caller-owned. The bool is false for a missionless
// permission.
func (request PermissionRequest) Mission() (MissionContext, bool) {
	if request.kind != permissionRequestVerified || request.mission == nil {
		return MissionContext{}, false
	}
	return *cloneMissionContext(request.mission), true
}

func validatePermissionPolicyResult(result PermissionPolicyResult) error {
	if (result.Immediate == nil) == (result.Deferred == nil) {
		return errors.New("personserver: permission policy must select exactly one immediate or deferred result")
	}
	if result.Immediate != nil {
		return validatePermissionDecision(*result.Immediate)
	}
	if result.Deferred.Lifetime <= 0 || result.Deferred.Lifetime%time.Second != 0 {
		return errors.New("personserver: deferred permission lifetime must be positive whole seconds")
	}
	if result.Deferred.RetryAfter < 0 || result.Deferred.RetryAfter%time.Second != 0 {
		return errors.New("personserver: deferred permission retry interval must be nonnegative whole seconds")
	}
	return nil
}

func validatePermissionDecision(decision PermissionDecision) error {
	permission, err := aauth.ParsePermission(string(decision.Permission))
	if err != nil || permission != decision.Permission {
		return errors.New("personserver: permission decision is invalid")
	}
	if !utf8.ValidString(decision.Reason) {
		return errors.New("personserver: permission reason must be valid UTF-8")
	}
	if decision.Permission == aauth.PermissionGranted && decision.Reason != "" {
		return errors.New("personserver: granted permission must not carry a denial reason")
	}
	if len(decision.Reason) > maximumPermissionReasonBytes {
		return errors.New("personserver: permission reason exceeds 65536 bytes")
	}
	return nil
}

func validatePermissionIntent(action, description string, parameters json.RawMessage) error {
	if !utf8.ValidString(action) || strings.TrimSpace(action) == "" || len(action) > maximumPermissionActionBytes {
		return errors.New("personserver: permission action must be nonempty and at most 4096 bytes")
	}
	if !utf8.ValidString(description) || len(description) > maximumPermissionDescriptionBytes {
		return errors.New("personserver: permission description exceeds 65536 bytes")
	}
	if parameters == nil {
		return nil
	}
	trimmed := bytes.TrimSpace(parameters)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) || trimmed[0] != '{' {
		return errors.New("personserver: permission parameters must be a JSON object")
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(trimmed, &object); err != nil || object == nil {
		return errors.New("personserver: permission parameters must be a JSON object")
	}
	return nil
}

func permissionStateForDecision(decision PermissionDecision) PermissionState {
	if decision.Permission == aauth.PermissionGranted {
		return PermissionStateGranted
	}
	return PermissionStateDenied
}

func (server *Server) handlePermission(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		response.Header().Set("Allow", http.MethodPost)
		writeProblem(response, http.StatusMethodNotAllowed, "method_not_allowed", errors.New("permission endpoint requires POST"))
		return
	}
	if server.permissions == nil || server.permissionPolicy == nil {
		writeProblem(response, http.StatusNotFound, "not_found", errors.New("permission endpoint is not configured"))
		return
	}
	_, agent, proof, err := server.verifyAgentRequest(request, []string{"content-type", "content-digest"})
	if err != nil {
		writeAgentTokenProblem(response, err)
		return
	}
	var input struct {
		Action      string          `json:"action"`
		Description string          `json:"description"`
		Parameters  json.RawMessage `json:"parameters"`
		MissionS256 json.RawMessage `json:"mission_s256"`
	}
	body, err := httpapi.DecodeExactJSON(request.Body, maxRequestBytes, &input)
	if err != nil {
		writeProblem(response, http.StatusBadRequest, "invalid_request", err)
		return
	}
	if !utf8.Valid(body) {
		writeProblem(response, http.StatusBadRequest, "invalid_request", errors.New("permission request must be valid UTF-8 JSON"))
		return
	}
	var missionRecord *MissionRecord
	var missionContext *MissionContext
	if input.MissionS256 != nil {
		var s256 string
		if err := json.Unmarshal(input.MissionS256, &s256); err != nil || aauth.ValidateMissionS256(s256) != nil {
			writeProblem(response, http.StatusBadRequest, "invalid_request", errors.New("personserver: permission mission_s256 is invalid"))
			return
		}
		if server.missionPermissions == nil {
			writeProblem(response, http.StatusBadRequest, "invalid_request", errors.New("personserver: mission-bound permission is not configured"))
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
	if err := validatePermissionIntent(input.Action, input.Description, input.Parameters); err != nil {
		writeProblem(response, http.StatusBadRequest, "invalid_request", err)
		return
	}
	thumbprint, err := agent.Confirmation.JWK.Thumbprint()
	if err != nil {
		writeAgentTokenProblem(response, err)
		return
	}
	parameters := append(json.RawMessage(nil), input.Parameters...)
	policyRequest := PermissionPolicyRequest{
		AgentProvider: agent.Issuer, Agent: agent.Subject,
		AgentAdditionalClaims: cloneClaims(agent.AdditionalClaims),
		Action:                input.Action, Description: input.Description,
		Parameters: append(json.RawMessage(nil), parameters...),
		Mission:    missionContext,
	}
	result, err := server.permissionPolicy(request.Context(), policyRequest)
	if err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", err)
		return
	}
	if err := validatePermissionPolicyResult(result); err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", err)
		return
	}
	createdAt := proof.VerifiedAt().UTC()
	agentExpiresAt := time.Unix(agent.ExpiresAt, 0).UTC()
	for attempt := 0; attempt < 3; attempt++ {
		id, err := interaction.GeneratePendingReference(nil)
		if err != nil {
			writeProblem(response, http.StatusInternalServerError, "server_error", err)
			return
		}
		record := PermissionRecord{
			ID: id, PersonServer: server.issuer, AgentProvider: agent.Issuer, Agent: agent.Subject,
			ConfirmationThumbprint: thumbprint, AgentExpiresAt: agentExpiresAt,
			AgentAdditionalClaims: cloneClaims(agent.AdditionalClaims),
			MissionS256:           "",
			Action:                input.Action, Description: input.Description, Parameters: append(json.RawMessage(nil), parameters...),
			CreatedAt: createdAt,
		}
		if missionRecord != nil {
			record.MissionS256 = missionRecord.S256
		}
		if result.Immediate != nil {
			record.State = permissionStateForDecision(*result.Immediate)
			record.Decision = *result.Immediate
			record.DecidedAt = createdAt
		} else {
			record.State = PermissionStatePending
			record.ExpiresAt = createdAt.Add(result.Deferred.Lifetime)
			if agentExpiresAt.Before(record.ExpiresAt) {
				record.ExpiresAt = agentExpiresAt
			}
			if !record.ExpiresAt.After(createdAt) {
				writeProblem(response, http.StatusRequestTimeout, "expired", ErrPermissionExpired)
				return
			}
			record.RetryAfter = result.Deferred.RetryAfter
		}
		if err := validatePermissionRecord(record); err != nil {
			writeProblem(response, http.StatusInternalServerError, "server_error", err)
			return
		}
		var createErr error
		if missionRecord != nil {
			createErr = server.missionPermissions.CreateMissionPermission(
				request.Context(), cloneMissionRecordForTransition(*missionRecord),
				cloneRetainedPermissionRecord(record), server.clock.Now().UTC(),
			)
		} else {
			createErr = server.permissions.CreatePermission(request.Context(), cloneRetainedPermissionRecord(record))
		}
		if createErr != nil {
			if errors.Is(createErr, ErrPermissionConflict) {
				continue
			}
			if missionRecord != nil {
				writeMissionActionProblem(response, createErr)
				return
			}
			writeProblem(response, http.StatusInternalServerError, "server_error", createErr)
			return
		}
		if result.Immediate != nil {
			writePermissionDecision(response, *result.Immediate)
			return
		}
		server.writePendingPermission(response, "/permission/pending/"+id, record.RetryAfter)
		return
	}
	writeProblem(response, http.StatusInternalServerError, "server_error", errors.New("personserver: could not allocate a unique permission reference"))
}

func validatePermissionRecord(record PermissionRecord) error {
	if record.ID == "" || record.PersonServer == "" || record.AgentProvider == "" || record.Agent == "" ||
		record.ConfirmationThumbprint == "" || record.AgentExpiresAt.IsZero() || record.CreatedAt.IsZero() ||
		validatePermissionIntent(record.Action, record.Description, record.Parameters) != nil {
		return ErrPermissionConflict
	}
	if err := aauth.ValidateServerIdentifier(record.PersonServer); err != nil {
		return ErrPermissionConflict
	}
	if err := aauth.ValidateServerIdentifier(record.AgentProvider); err != nil {
		return ErrPermissionConflict
	}
	if err := aauth.ValidateAgentIdentifier(record.Agent); err != nil {
		return ErrPermissionConflict
	}
	if record.MissionS256 != "" && aauth.ValidateMissionS256(record.MissionS256) != nil {
		return ErrPermissionConflict
	}
	for _, raw := range record.AgentAdditionalClaims {
		if !json.Valid(raw) {
			return ErrPermissionConflict
		}
	}
	switch record.State {
	case PermissionStatePending:
		if record.Decision != (PermissionDecision{}) || !record.DecidedAt.IsZero() ||
			!record.ExpiresAt.After(record.CreatedAt) || record.AgentExpiresAt.Before(record.ExpiresAt) ||
			record.RetryAfter < 0 || record.RetryAfter%time.Second != 0 {
			return ErrPermissionConflict
		}
	case PermissionStateGranted, PermissionStateDenied:
		if validatePermissionDecision(record.Decision) != nil || permissionStateForDecision(record.Decision) != record.State ||
			record.DecidedAt.Before(record.CreatedAt) || !record.DecidedAt.Before(record.AgentExpiresAt) {
			return ErrPermissionConflict
		}
		if record.ExpiresAt.IsZero() {
			if record.RetryAfter != 0 {
				return ErrPermissionConflict
			}
		} else if !record.ExpiresAt.After(record.CreatedAt) || record.AgentExpiresAt.Before(record.ExpiresAt) ||
			!record.DecidedAt.Before(record.ExpiresAt) || record.RetryAfter < 0 || record.RetryAfter%time.Second != 0 {
			return ErrPermissionConflict
		}
	case PermissionStateExpired:
		if record.Decision != (PermissionDecision{}) || !record.DecidedAt.IsZero() ||
			!record.ExpiresAt.After(record.CreatedAt) || record.AgentExpiresAt.Before(record.ExpiresAt) ||
			record.RetryAfter < 0 || record.RetryAfter%time.Second != 0 {
			return ErrPermissionConflict
		}
	case PermissionStateGone:
		// Load may expose consumed state for host-side diagnosis. Gone must
		// preserve either the complete terminal decision or expired record.
		preceding := record
		if preceding.Decision == (PermissionDecision{}) {
			preceding.State = PermissionStateExpired
		} else {
			preceding.State = permissionStateForDecision(preceding.Decision)
		}
		if validatePermissionRecord(preceding) != nil {
			return ErrPermissionConflict
		}
	default:
		return ErrPermissionConflict
	}
	return nil
}

func cloneRetainedPermissionRecord(record PermissionRecord) PermissionRecord {
	record.Parameters = append(json.RawMessage(nil), record.Parameters...)
	record.AgentAdditionalClaims = cloneClaims(record.AgentAdditionalClaims)
	return record
}

func writePermissionDecision(response http.ResponseWriter, decision PermissionDecision) {
	writePrivateJSON(response, http.StatusOK, struct {
		Permission aauth.Permission `json:"permission"`
		Reason     string           `json:"reason,omitempty"`
	}{Permission: decision.Permission, Reason: decision.Reason})
}

func (server *Server) writePendingPermission(response http.ResponseWriter, location string, retryAfter time.Duration) {
	if retryAfter < 0 || retryAfter%time.Second != 0 {
		writeProblem(response, http.StatusInternalServerError, "server_error", ErrPermissionConflict)
		return
	}
	response.Header().Set("Location", location)
	response.Header().Set("Retry-After", strconv.FormatInt(int64(retryAfter/time.Second), 10))
	writePrivateJSON(response, http.StatusAccepted, struct {
		Status string `json:"status"`
	}{Status: "pending"})
}

func permissionRecordsEqual(left, right PermissionRecord) bool {
	return reflect.DeepEqual(left, right)
}

func permissionPollIdentity(personServer string, agent aauth.AgentTokenClaims) (PermissionPollIdentity, error) {
	thumbprint, err := agent.Confirmation.JWK.Thumbprint()
	if err != nil {
		return PermissionPollIdentity{}, err
	}
	return PermissionPollIdentity{
		PersonServer: personServer, AgentProvider: agent.Issuer,
		Agent: agent.Subject, ConfirmationThumbprint: thumbprint,
	}, nil
}

func (server *Server) handlePendingPermission(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		response.Header().Set("Allow", http.MethodGet)
		writeProblem(response, http.StatusMethodNotAllowed, "method_not_allowed", errors.New("permission polling requires GET"))
		return
	}
	if server.permissions == nil {
		writeProblem(response, http.StatusGone, "invalid_code", ErrPermissionNotFound)
		return
	}
	if request.Body != nil && request.Body != http.NoBody {
		writeProblem(response, http.StatusBadRequest, "invalid_request", errors.New("permission polling requires a bodyless GET"))
		return
	}
	_, agent, proof, err := server.verifyAgentRequest(request, nil)
	if err != nil {
		writeAgentTokenProblem(response, err)
		return
	}
	identity, err := permissionPollIdentity(server.issuer, agent)
	if err != nil {
		writeAgentTokenProblem(response, err)
		return
	}
	id := request.PathValue("id")
	if id == "" {
		writeProblem(response, http.StatusGone, "invalid_code", ErrPermissionNotFound)
		return
	}
	now := proof.VerifiedAt().UTC()
	var mission *MissionRecord
	var record PermissionRecord
	if server.missionPermissions != nil {
		peek, peekErr := server.permissions.LoadPermission(request.Context(), id, now)
		if peekErr == nil && peek.MissionS256 != "" {
			if peek.PersonServer != identity.PersonServer || peek.AgentProvider != identity.AgentProvider ||
				peek.Agent != identity.Agent || peek.ConfirmationThumbprint != identity.ConfirmationThumbprint {
				writeProblem(response, http.StatusGone, "invalid_code", ErrPermissionNotFound)
				return
			}
			if err := validatePolledPermissionRecord(id, identity, peek, now); err != nil {
				writeProblem(response, http.StatusInternalServerError, "server_error", err)
				return
			}
			loaded, loadErr := server.loadActiveMission(
				request.Context(), peek.MissionS256, identity.Agent, now,
			)
			if loadErr != nil {
				writeMissionActionProblem(response, loadErr)
				return
			}
			mission = &loaded
			record, err = server.missionPermissions.PollMissionPermission(
				request.Context(), cloneMissionRecordForTransition(loaded), id, identity, now,
			)
		} else if peekErr != nil {
			err = peekErr
		} else {
			record, err = server.permissions.PollPermission(request.Context(), id, identity, now)
		}
	} else {
		record, err = server.permissions.PollPermission(request.Context(), id, identity, now)
	}
	if err != nil {
		if mission != nil {
			writeMissionActionProblem(response, err)
			return
		}
		switch {
		case errors.Is(err, ErrPermissionNotFound), errors.Is(err, ErrPermissionGone):
			writeProblem(response, http.StatusGone, "invalid_code", err)
		case errors.Is(err, ErrPermissionExpired):
			writeProblem(response, http.StatusRequestTimeout, "expired", err)
		default:
			writeProblem(response, http.StatusInternalServerError, "server_error", err)
		}
		return
	}
	if err := validatePolledPermissionRecord(id, identity, record, now); err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", err)
		return
	}
	switch record.State {
	case PermissionStatePending:
		server.writePendingPermission(response, request.URL.Path, record.RetryAfter)
	case PermissionStateGranted, PermissionStateDenied:
		if !server.consumePermissionResult(response, request, id, record, mission) {
			return
		}
		writePermissionDecision(response, record.Decision)
	case PermissionStateExpired:
		if !server.consumePermissionResult(response, request, id, record, mission) {
			return
		}
		writeProblem(response, http.StatusRequestTimeout, "expired", ErrPermissionExpired)
	case PermissionStateGone:
		writeProblem(response, http.StatusGone, "invalid_code", ErrPermissionGone)
	default:
		writeProblem(response, http.StatusInternalServerError, "server_error", ErrPermissionConflict)
	}
}

func validatePolledPermissionRecord(id string, identity PermissionPollIdentity, record PermissionRecord, now time.Time) error {
	if err := validatePermissionRecordAt(record, now); err != nil || record.ID != id ||
		record.PersonServer != identity.PersonServer || record.AgentProvider != identity.AgentProvider ||
		record.Agent != identity.Agent || record.ConfirmationThumbprint != identity.ConfirmationThumbprint {
		return ErrPermissionConflict
	}
	return nil
}

func validatePermissionRecordAt(record PermissionRecord, now time.Time) error {
	if validatePermissionRecord(record) != nil || record.CreatedAt.After(now) {
		return ErrPermissionConflict
	}
	switch record.State {
	case PermissionStatePending:
		if !now.Before(record.ExpiresAt) || !now.Before(record.AgentExpiresAt) {
			return ErrPermissionConflict
		}
	case PermissionStateGranted, PermissionStateDenied:
		if record.DecidedAt.After(now) {
			return ErrPermissionConflict
		}
	case PermissionStateExpired:
		if now.Before(record.ExpiresAt) {
			return ErrPermissionConflict
		}
	case PermissionStateGone:
		// A consumed record may preserve either a terminal decision or expiry.
		if record.Decision == (PermissionDecision{}) && now.Before(record.ExpiresAt) {
			return ErrPermissionConflict
		}
	default:
		return ErrPermissionConflict
	}
	return nil
}

func (server *Server) consumePermissionResult(
	response http.ResponseWriter,
	request *http.Request,
	id string,
	record PermissionRecord,
	mission *MissionRecord,
) bool {
	var err error
	if mission != nil {
		err = server.missionPermissions.ConsumeMissionPermissionResult(
			request.Context(), cloneMissionRecordForTransition(*mission), id,
			cloneRetainedPermissionRecord(record), server.clock.Now().UTC(),
		)
	} else {
		err = server.permissions.ConsumePermissionResult(request.Context(), id, cloneRetainedPermissionRecord(record))
	}
	if err != nil {
		if mission != nil {
			writeMissionActionProblem(response, err)
			return false
		}
		if errors.Is(err, ErrPermissionNotFound) || errors.Is(err, ErrPermissionGone) {
			writeProblem(response, http.StatusGone, "invalid_code", err)
		} else {
			writeProblem(response, http.StatusInternalServerError, "server_error", err)
		}
		return false
	}
	return true
}

// ResumePermission reconstructs a non-authoritative private host handle from
// retained permission state after process restart. The host must separately
// authenticate the person; possession of a reference is not authority.
func (server *Server) ResumePermission(ctx context.Context, reference string) (PermissionRequest, error) {
	if server == nil || server.permissions == nil {
		return PermissionRequest{}, errors.New("personserver: permission endpoint is not configured")
	}
	if ctx == nil {
		return PermissionRequest{}, errors.New("personserver: context is required")
	}
	if reference == "" {
		return PermissionRequest{}, errors.New("personserver: permission reference is required")
	}
	now := server.clock.Now().UTC()
	record, err := server.permissions.LoadPermission(ctx, reference, now)
	if err != nil {
		return PermissionRequest{}, err
	}
	if err := validatePermissionRecordAt(record, now); err != nil || record.ID != reference || record.PersonServer != server.issuer {
		return PermissionRequest{}, ErrPermissionConflict
	}
	var mission *MissionContext
	var missionRecord *MissionRecord
	if record.MissionS256 != "" {
		if server.missionPermissions == nil {
			return PermissionRequest{}, ErrPermissionConflict
		}
		loaded, err := server.loadActiveMission(ctx, record.MissionS256, record.Agent, now)
		if err != nil {
			return PermissionRequest{}, err
		}
		mission, err = missionContextFromRecord(loaded)
		if err != nil {
			return PermissionRequest{}, err
		}
		missionRecord = &loaded
	}
	switch record.State {
	case PermissionStatePending, PermissionStateGranted, PermissionStateDenied:
		return permissionRequestFromRecord(record, mission, missionRecord), nil
	case PermissionStateExpired:
		return PermissionRequest{}, ErrPermissionExpired
	case PermissionStateGone:
		return PermissionRequest{}, ErrPermissionGone
	default:
		return PermissionRequest{}, ErrPermissionConflict
	}
}

func permissionRequestFromRecord(
	record PermissionRecord,
	mission *MissionContext,
	missionRecord *MissionRecord,
) PermissionRequest {
	var retainedMission *MissionRecord
	if missionRecord != nil {
		clone := cloneMissionRecordForTransition(*missionRecord)
		retainedMission = &clone
	}
	return PermissionRequest{
		kind:          permissionRequestVerified,
		record:        cloneRetainedPermissionRecord(record),
		mission:       cloneMissionContext(mission),
		missionRecord: retainedMission,
	}
}

// GrantPermission durably retains a host-authenticated permission grant. It
// does not execute Action.
func (server *Server) GrantPermission(ctx context.Context, request PermissionRequest) error {
	return server.decidePermission(ctx, request, PermissionDecision{Permission: aauth.PermissionGranted})
}

// DenyPermission durably retains a host-authenticated permission denial.
// Reason is untrusted Markdown and is returned only from this endpoint.
func (server *Server) DenyPermission(ctx context.Context, request PermissionRequest, reason string) error {
	return server.decidePermission(ctx, request, PermissionDecision{Permission: aauth.PermissionDenied, Reason: reason})
}

func (server *Server) decidePermission(ctx context.Context, request PermissionRequest, decision PermissionDecision) error {
	if server == nil || server.permissions == nil {
		return errors.New("personserver: permission endpoint is not configured")
	}
	if ctx == nil {
		return errors.New("personserver: context is required")
	}
	if err := validatePermissionDecision(decision); err != nil {
		return err
	}
	if err := server.validatePermissionRequest(request); err != nil {
		return err
	}
	now := server.clock.Now().UTC()
	canonical, err := server.permissions.LoadPermission(ctx, request.record.ID, now)
	if err != nil {
		return err
	}
	if err := validatePermissionRecordAt(canonical, now); err != nil || !permissionRecordContextEqual(canonical, request.record) {
		return ErrPermissionConflict
	}
	var mission *MissionRecord
	if canonical.MissionS256 != "" {
		if server.missionPermissions == nil {
			return ErrPermissionConflict
		}
		loaded, err := server.loadActiveMission(ctx, canonical.MissionS256, canonical.Agent, now)
		if err != nil {
			return err
		}
		if request.missionRecord == nil || !request.missionRecord.Equal(loaded) {
			return ErrMissionConflict
		}
		mission = request.missionRecord
	}
	switch canonical.State {
	case PermissionStateGranted, PermissionStateDenied:
		if canonical.Decision == decision {
			return nil
		}
		return ErrPermissionConflict
	case PermissionStateExpired:
		return ErrPermissionExpired
	case PermissionStateGone:
		return ErrPermissionGone
	case PermissionStatePending:
		if !now.Before(canonical.ExpiresAt) || !now.Before(canonical.AgentExpiresAt) {
			return ErrPermissionExpired
		}
	default:
		return ErrPermissionConflict
	}
	var decided PermissionRecord
	if mission != nil {
		decided, err = server.missionPermissions.DecideMissionPermission(
			ctx, cloneMissionRecordForTransition(*mission), canonical.ID, decision, now,
		)
	} else {
		decided, err = server.permissions.DecidePermission(ctx, canonical.ID, decision, now)
	}
	if err != nil {
		return err
	}
	if err := validatePermissionRecordAt(decided, now); err != nil || !permissionRecordContextEqual(decided, canonical) ||
		decided.State != permissionStateForDecision(decision) || decided.Decision != decision {
		return ErrPermissionConflict
	}
	return nil
}

func (server *Server) validatePermissionRequest(request PermissionRequest) error {
	if request.kind != permissionRequestVerified || validatePermissionRecord(request.record) != nil ||
		request.record.PersonServer != server.issuer {
		return ErrPermissionConflict
	}
	if request.record.MissionS256 == "" {
		if request.mission != nil || request.missionRecord != nil {
			return ErrPermissionConflict
		}
	} else if request.mission == nil || request.missionRecord == nil ||
		request.mission.S256 != request.record.MissionS256 || request.missionRecord.S256 != request.record.MissionS256 ||
		request.missionRecord.Agent != request.record.Agent {
		return ErrPermissionConflict
	}
	switch request.record.State {
	case PermissionStatePending, PermissionStateGranted, PermissionStateDenied:
		return nil
	default:
		return ErrPermissionConflict
	}
}

func permissionRecordContextEqual(left, right PermissionRecord) bool {
	left.State, right.State = 0, 0
	left.Decision, right.Decision = PermissionDecision{}, PermissionDecision{}
	left.DecidedAt, right.DecidedAt = time.Time{}, time.Time{}
	return permissionRecordsEqual(left, right)
}
