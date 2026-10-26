package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"slices"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

// MissionRequest names one Person Server and the mission proposal to submit.
type MissionRequest struct {
	PersonServer string
	Proposal     aauth.MissionProposal
}

// MissionContinuationUnsupportedError reports a mission-specific 202 response
// for which the named client operation does not expose a continuation.
type MissionContinuationUnsupportedError struct {
	Phase     string
	Operation string
}

// MissionProposalSubmissionUncertainError reports an unverifiable transport
// result after the signed proposal was handed to the HTTP client. The Person
// Server may have retained it, so callers must not automatically submit the
// proposal again.
type MissionProposalSubmissionUncertainError struct {
	cause error
}

func (failure *MissionProposalSubmissionUncertainError) Error() string {
	if failure == nil || failure.cause == nil {
		return "aauth agent: mission proposal submission outcome is uncertain"
	}
	return "aauth agent: mission proposal submission outcome is uncertain: " + failure.cause.Error()
}

func (failure *MissionProposalSubmissionUncertainError) Unwrap() error {
	if failure == nil {
		return nil
	}
	return failure.cause
}

// MissionProposalPollUncertainError reports that a pending-URL GET may have
// consumed a terminal response before transport failure hid it. Current Core
// makes terminal delivery one-shot, so callers must preserve the handle and
// must not resubmit the original proposal.
type MissionProposalPollUncertainError struct {
	cause error
}

func (failure *MissionProposalPollUncertainError) Error() string {
	if failure == nil || failure.cause == nil {
		return "aauth agent: mission proposal poll outcome is uncertain"
	}
	return "aauth agent: mission proposal poll outcome is uncertain: " + failure.cause.Error()
}

func (failure *MissionProposalPollUncertainError) Unwrap() error {
	if failure == nil {
		return nil
	}
	return failure.cause
}

// MissionProposalPendingError reports that the immediate-only ProposeMission
// call reached deferred approval. Pending returns the verified continuation so
// a misconfigured caller does not lose the retained proposal.
type MissionProposalPendingError struct {
	pending PendingMissionProposal
}

func (failure *MissionProposalPendingError) Error() string {
	return "aauth agent: mission approval is pending; use BeginMission when deferred approval is possible"
}

// Pending returns the verified continuation produced by the Person Server.
func (failure *MissionProposalPendingError) Pending() PendingMissionProposal {
	if failure == nil {
		return PendingMissionProposal{}
	}
	return failure.pending
}

func (failure *MissionContinuationUnsupportedError) Error() string {
	if failure == nil {
		return "aauth agent: mission continuation is not supported"
	}
	if failure.Operation == "" {
		return "aauth agent: mission " + failure.Phase + " continuation is not supported"
	}
	if failure.Phase == "" {
		return "aauth agent: " + failure.Operation + " does not support a mission continuation"
	}
	return "aauth agent: " + failure.Operation + " does not support mission " + failure.Phase + " continuation"
}

// MissionResult is one verified mission approval, returned immediately or
// after an explicit poll. Accessors return copies so callers cannot rewrite
// the verified mission or token map.
type MissionResult struct {
	mission      aauth.ApprovedMission
	capabilities []string
	personTokens map[string]string
}

type missionProposalResultKind uint8

const (
	missionProposalApproved missionProposalResultKind = iota + 1
	missionProposalPending
)

// MissionProposalResult is exactly one verified approval or pending proposal.
// BeginMission and PollMissionProposal each perform one HTTP request and
// return control to the caller; they never sleep or poll automatically.
type MissionProposalResult struct {
	kind     missionProposalResultKind
	approval MissionResult
	pending  PendingMissionProposal
}

// Approval returns the verified mission approval, when present.
func (result MissionProposalResult) Approval() (MissionResult, bool) {
	if result.kind != missionProposalApproved {
		return MissionResult{}, false
	}
	return result.approval, true
}

// Pending returns the verified proposal continuation, when present.
func (result MissionProposalResult) Pending() (PendingMissionProposal, bool) {
	if result.kind != missionProposalPending || result.pending.location == "" {
		return PendingMissionProposal{}, false
	}
	return result.pending, true
}

// PendingMissionProposal is one verified mission-proposal continuation. Its
// private identity and key bindings prevent callers from inventing or
// transferring polling authority.
type PendingMissionProposal struct {
	personServer  string
	location      string
	retryAfter    time.Duration
	agentProvider string
	agent         string
	agentJKT      string
	resources     []string
}

// PersonServer returns the Person Server that retained the proposal.
func (pending PendingMissionProposal) PersonServer() string { return pending.personServer }

// Location returns the verified URL for the next explicit poll.
func (pending PendingMissionProposal) Location() string { return pending.location }

// RetryAfter returns the Person Server's current polling interval hint.
func (pending PendingMissionProposal) RetryAfter() time.Duration { return pending.retryAfter }

// PendingMissionProposalSnapshot is the JSON-serializable state needed to
// restore one verified mission-proposal continuation. It contains authority
// and proposal context and must be stored with confidentiality and integrity
// protection.
type PendingMissionProposalSnapshot struct {
	PersonServer      string   `json:"person_server"`
	Location          string   `json:"location"`
	RetryAfter        int64    `json:"retry_after_seconds"`
	AgentProvider     string   `json:"agent_provider"`
	Agent             string   `json:"agent"`
	AgentJKT          string   `json:"agent_jkt"`
	ProposedResources []string `json:"proposed_resources,omitempty"`
}

// Snapshot returns caller-owned persistence state for this verified pending
// proposal. The caller must protect the returned value as authority-bearing
// continuation state.
func (pending PendingMissionProposal) Snapshot() (PendingMissionProposalSnapshot, error) {
	if pending.personServer == "" || pending.location == "" ||
		pending.agentProvider == "" || pending.agent == "" || pending.agentJKT == "" {
		return PendingMissionProposalSnapshot{}, errors.New("aauth agent: verified pending mission proposal is required")
	}
	if pending.retryAfter < 0 || pending.retryAfter%time.Second != 0 {
		return PendingMissionProposalSnapshot{}, errors.New("aauth agent: pending mission proposal retry interval must be whole nonnegative seconds")
	}
	return PendingMissionProposalSnapshot{
		PersonServer: pending.personServer, Location: pending.location,
		RetryAfter:    int64(pending.retryAfter / time.Second),
		AgentProvider: pending.agentProvider, Agent: pending.agent, AgentJKT: pending.agentJKT,
		ProposedResources: append([]string(nil), pending.resources...),
	}, nil
}

// Mission returns the exact verified mission and its parsed blob.
func (result MissionResult) Mission() aauth.ApprovedMission {
	return cloneApprovedMission(result.mission)
}

// ApprovesTool reports whether name exactly matches a tool recorded in the
// verified mission. It does not contact the Person Server or report whether a
// mission was later terminated there.
func (result MissionResult) ApprovesTool(name string) bool {
	return result.mission.ApprovesTool(name)
}

// Capabilities returns the Person Server capabilities available at approval.
func (result MissionResult) Capabilities() []string {
	return append([]string(nil), result.capabilities...)
}

// PersonToken looks up the exact Resource identifier in the verified approval.
// It returns ("", false) when that Resource has no returned token. PersonTokens
// exposes a copy of the complete Resource-to-token mapping.
func (result MissionResult) PersonToken(resource string) (string, bool) {
	token, ok := result.personTokens[resource]
	return token, ok && token != ""
}

// PersonTokens returns a copy of every verified Resource-to-token mapping.
func (result MissionResult) PersonTokens() map[string]string {
	if result.personTokens == nil {
		return nil
	}
	tokens := make(map[string]string, len(result.personTokens))
	for resource, token := range result.personTokens {
		tokens[resource] = token
	}
	return tokens
}

// ProposeMission performs one signed mission proposal and returns an immediate
// verified approval. Applications whose Person Server may defer approval use
// BeginMission instead.
func (client *Client) ProposeMission(ctx context.Context, input MissionRequest) (MissionResult, error) {
	const operation = "propose mission"
	result, err := client.beginMission(ctx, input, operation)
	if err != nil {
		return MissionResult{}, err
	}
	if approval, ok := result.Approval(); ok {
		return approval, nil
	}
	pending, _ := result.Pending()
	return MissionResult{}, fail(operation, &MissionProposalPendingError{pending: pending})
}

// BeginMission performs one signed mission proposal and returns either a
// verified approval or a verified pending continuation. It never sleeps,
// retries, or polls automatically.
func (client *Client) BeginMission(ctx context.Context, input MissionRequest) (MissionProposalResult, error) {
	return client.beginMission(ctx, input, "begin mission")
}

func (client *Client) beginMission(
	ctx context.Context,
	input MissionRequest,
	operation string,
) (MissionProposalResult, error) {
	if client == nil {
		return MissionProposalResult{}, fail(operation, errors.New("client is required"))
	}
	if ctx == nil {
		return MissionProposalResult{}, fail(operation, errors.New("context is required"))
	}
	if err := ctx.Err(); err != nil {
		return MissionProposalResult{}, fail(operation, err)
	}
	if err := input.Proposal.Validate(); err != nil {
		return MissionProposalResult{}, fail(operation, err)
	}
	credential, err := client.personServerRequestBinding(ctx, input.PersonServer, "", "")
	if err != nil {
		return MissionProposalResult{}, fail(operation, err)
	}
	metadata, err := client.personServerMetadata(ctx, credential.personServer)
	if err != nil {
		return MissionProposalResult{}, fail(operation, err)
	}
	if metadata.MissionEndpoint == "" {
		return MissionProposalResult{}, fail(operation, errors.New("person-server metadata mission_endpoint is required"))
	}
	if err := aauth.ValidateEndpoint(metadata.MissionEndpoint); err != nil {
		return MissionProposalResult{}, fail(operation, fmt.Errorf("person-server metadata mission_endpoint: %w", err))
	}
	body, err := json.Marshal(input.Proposal)
	if err != nil {
		return MissionProposalResult{}, fail(operation, err)
	}
	request, err := newJSONRequest(ctx, metadata.MissionEndpoint, body)
	if err != nil {
		return MissionProposalResult{}, fail(operation, err)
	}
	request.Header.Set("Prefer", "wait=0")
	if err := client.signJSONRequest(request, client.agentToken); err != nil {
		return MissionProposalResult{}, fail(operation, err)
	}
	response, err := client.httpClient.Do(request)
	if err != nil {
		return MissionProposalResult{}, fail(operation, &MissionProposalSubmissionUncertainError{cause: err})
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusAccepted {
		pending, err := client.pendingMissionProposal(response, credential.personServer, input.Proposal.Resources, PendingMissionProposal{}, "ProposeMission")
		if err != nil {
			return MissionProposalResult{}, fail(operation, &MissionProposalSubmissionUncertainError{cause: err})
		}
		return MissionProposalResult{kind: missionProposalPending, pending: pending}, nil
	}
	if response.StatusCode != http.StatusOK {
		cause := responseFailure(response)
		if response.StatusCode >= http.StatusInternalServerError {
			return MissionProposalResult{}, fail(operation, &MissionProposalSubmissionUncertainError{cause: cause})
		}
		return MissionProposalResult{}, fail(operation, cause)
	}
	verified, err := client.decodeMissionApproval(ctx, response, credential, input.Proposal.Resources)
	if err != nil {
		return MissionProposalResult{}, fail(operation, &MissionProposalSubmissionUncertainError{cause: err})
	}
	return MissionProposalResult{kind: missionProposalApproved, approval: verified}, nil
}

// PollMissionProposal performs exactly one signed, bodyless GET for a verified
// pending mission proposal. It never sleeps, loops, or resubmits the proposal.
func (client *Client) PollMissionProposal(ctx context.Context, pending PendingMissionProposal) (MissionProposalResult, error) {
	const operation = "poll mission proposal"
	if client == nil {
		return MissionProposalResult{}, fail(operation, errors.New("client is required"))
	}
	if err := client.validatePendingMissionProposal(ctx, pending); err != nil {
		return MissionProposalResult{}, fail(operation, err)
	}
	credential, err := client.personServerRequestBinding(ctx, pending.personServer, "", "")
	if err != nil {
		return MissionProposalResult{}, fail(operation, err)
	}
	metadata, err := client.personServerMetadata(ctx, pending.personServer)
	if err != nil {
		return MissionProposalResult{}, fail(operation, err)
	}
	if metadata.MissionEndpoint == "" {
		return MissionProposalResult{}, fail(operation, errors.New("person-server metadata mission_endpoint is required"))
	}
	missionEndpoint, err := url.Parse(metadata.MissionEndpoint)
	if err != nil {
		return MissionProposalResult{}, fail(operation, errors.New("person-server metadata mission_endpoint is invalid"))
	}
	currentOrigin, err := httpOrigin(missionEndpoint)
	pendingTarget, pendingErr := url.Parse(pending.location)
	pendingOrigin, pendingOriginErr := httpOrigin(pendingTarget)
	if err != nil || pendingErr != nil || pendingOriginErr != nil || currentOrigin != pendingOrigin {
		return MissionProposalResult{}, fail(operation, errors.New("pending mission proposal origin does not match current Person Server metadata"))
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, pending.location, nil)
	if err != nil {
		return MissionProposalResult{}, fail(operation, err)
	}
	if err := signaturekey.SignJWTRequest(request, client.signingKey, client.agentToken, client.clock); err != nil {
		return MissionProposalResult{}, fail(operation, err)
	}
	response, err := client.httpClient.Do(request)
	if err != nil {
		return MissionProposalResult{}, fail(operation, &MissionProposalPollUncertainError{
			cause: err,
		})
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusTooManyRequests || response.StatusCode == http.StatusServiceUnavailable {
		next := pending
		if response.StatusCode == http.StatusTooManyRequests {
			if next.retryAfter > time.Duration(math.MaxInt64)-5*time.Second {
				return MissionProposalResult{}, fail(operation, errors.New("poll retry interval overflows"))
			}
			next.retryAfter += 5 * time.Second
		} else {
			retryAfter, err := parseHTTPRetryAfter(response.Header.Values("Retry-After"), client.clock.Now())
			if err != nil {
				return MissionProposalResult{}, fail(operation, err)
			}
			next.retryAfter = retryAfter
		}
		return MissionProposalResult{kind: missionProposalPending, pending: next}, nil
	}
	if response.StatusCode == http.StatusAccepted {
		next, err := client.pendingMissionProposal(response, pending.personServer, pending.resources, pending, "PollMissionProposal")
		if err != nil {
			return MissionProposalResult{}, fail(operation, err)
		}
		return MissionProposalResult{kind: missionProposalPending, pending: next}, nil
	}
	if response.StatusCode != http.StatusOK {
		cause := responseFailure(response)
		if response.StatusCode >= http.StatusInternalServerError {
			return MissionProposalResult{}, fail(operation, &MissionProposalPollUncertainError{cause: cause})
		}
		var problem *aauth.ProblemError
		if errors.As(cause, &problem) {
			return MissionProposalResult{}, fail(operation, problem)
		}
		return MissionProposalResult{}, fail(operation, &MissionProposalPollUncertainError{cause: cause})
	}
	verified, err := client.decodeMissionApproval(ctx, response, credential, pending.resources)
	if err != nil {
		return MissionProposalResult{}, fail(operation, &MissionProposalPollUncertainError{cause: err})
	}
	return MissionProposalResult{kind: missionProposalApproved, approval: verified}, nil
}

// RestorePendingMissionProposal re-verifies one serialized continuation
// against the current Agent token, key, Person Server metadata, and proposal.
// It performs no poll or proposal submission.
func (client *Client) RestorePendingMissionProposal(
	ctx context.Context,
	snapshot PendingMissionProposalSnapshot,
) (PendingMissionProposal, error) {
	const operation = "restore pending mission proposal"
	if client == nil {
		return PendingMissionProposal{}, fail(operation, errors.New("client is required"))
	}
	if ctx == nil {
		return PendingMissionProposal{}, fail(operation, errors.New("context is required"))
	}
	if err := ctx.Err(); err != nil {
		return PendingMissionProposal{}, fail(operation, err)
	}
	if err := client.requireDirectPersonServerCaller(); err != nil {
		return PendingMissionProposal{}, fail(operation, err)
	}
	current, err := aauth.VerifyAgentToken(ctx, client.agentToken, client.keyResolver, client.clock)
	if err != nil {
		return PendingMissionProposal{}, fail(operation, fmt.Errorf("verify current Agent token: %w", err))
	}
	if current.Subject != client.identifier || !current.Confirmation.JWK.Equal(client.signingKey.PublicJWK()) {
		return PendingMissionProposal{}, fail(operation, errors.New("current Agent token does not match client identity and key"))
	}
	if snapshot.PersonServer == "" || snapshot.Location == "" || snapshot.AgentProvider == "" ||
		snapshot.Agent == "" || snapshot.AgentJKT == "" {
		return PendingMissionProposal{}, fail(operation, errors.New("snapshot is incomplete"))
	}
	if snapshot.RetryAfter < 0 || snapshot.RetryAfter > int64(math.MaxInt64/time.Second) {
		return PendingMissionProposal{}, fail(operation, errors.New("snapshot retry interval is invalid"))
	}
	if err := validateProposedMissionResources(snapshot.ProposedResources); err != nil {
		return PendingMissionProposal{}, fail(operation, fmt.Errorf("snapshot proposed resources: %w", err))
	}
	if err := aauth.ValidateServerIdentifier(snapshot.PersonServer); err != nil {
		return PendingMissionProposal{}, fail(operation, fmt.Errorf("snapshot person server: %w", err))
	}
	thumbprint, err := client.signingKey.PublicJWK().Thumbprint()
	if err != nil {
		return PendingMissionProposal{}, fail(operation, err)
	}
	if snapshot.PersonServer != current.PersonServer || snapshot.AgentProvider != current.Issuer ||
		snapshot.Agent != current.Subject || snapshot.AgentJKT != thumbprint {
		return PendingMissionProposal{}, fail(operation, errors.New("snapshot does not match current Agent identity, key, and Person Server"))
	}
	metadata, err := client.personServerMetadata(ctx, snapshot.PersonServer)
	if err != nil {
		return PendingMissionProposal{}, fail(operation, err)
	}
	if metadata.MissionEndpoint == "" {
		return PendingMissionProposal{}, fail(operation, errors.New("person-server metadata mission_endpoint is required"))
	}
	missionEndpoint, err := url.Parse(metadata.MissionEndpoint)
	if err != nil {
		return PendingMissionProposal{}, fail(operation, errors.New("person-server metadata mission_endpoint is invalid"))
	}
	origin, err := httpOrigin(missionEndpoint)
	if err != nil {
		return PendingMissionProposal{}, fail(operation, errors.New("person-server metadata mission_endpoint origin is invalid"))
	}
	location, err := url.Parse(snapshot.Location)
	if err != nil || location.String() != snapshot.Location || location.User != nil || location.Fragment != "" {
		return PendingMissionProposal{}, fail(operation, errors.New("snapshot pending Location is invalid"))
	}
	locationOrigin, err := httpOrigin(location)
	if err != nil || locationOrigin != origin {
		return PendingMissionProposal{}, fail(operation, errors.New("snapshot pending Location does not match current mission endpoint origin"))
	}
	return PendingMissionProposal{
		personServer: snapshot.PersonServer, location: snapshot.Location,
		retryAfter:    time.Duration(snapshot.RetryAfter) * time.Second,
		agentProvider: snapshot.AgentProvider, agent: snapshot.Agent, agentJKT: snapshot.AgentJKT,
		resources: append([]string(nil), snapshot.ProposedResources...),
	}, nil
}

func (client *Client) decodeMissionApproval(
	ctx context.Context,
	response *http.Response,
	credential personServerCredential,
	proposedResources []string,
) (MissionResult, error) {
	var approval aauth.MissionApproval
	if err := decodeJSONResponse(response, &approval); err != nil {
		return MissionResult{}, err
	}
	mission, err := aauth.DecodeMission(approval.S256, approval.Mission)
	if err != nil {
		return MissionResult{}, err
	}
	if mission.Blob.Approver != credential.personServer {
		return MissionResult{}, errors.New("mission approver does not match person server")
	}
	if mission.Blob.Agent != client.identifier {
		return MissionResult{}, errors.New("mission belongs to another Agent")
	}
	if mission.Blob.ExpiresAt != nil && !client.clock.Now().Before(*mission.Blob.ExpiresAt) {
		return MissionResult{}, errors.New("approved mission is already expired")
	}
	if err := validateApprovedResources(proposedResources, mission.Blob.ApprovedResources); err != nil {
		return MissionResult{}, err
	}
	if len(approval.Capabilities) > 0 {
		if _, err := aauth.FormatCapabilities(approval.Capabilities); err != nil {
			return MissionResult{}, fmt.Errorf("mission capabilities: %w", err)
		}
	}
	verifiedTokens := make(map[string]string, len(approval.PersonTokens))
	seenPersonTokens := make(map[struct {
		issuer string
		jti    string
	}]struct{}, len(approval.PersonTokens))
	for resource, compact := range approval.PersonTokens {
		if !slices.Contains(mission.Blob.ApprovedResources, resource) {
			return MissionResult{}, errors.New("mission response returned a token for an unapproved Resource")
		}
		if compact == "" {
			return MissionResult{}, errors.New("mission response returned an empty person token")
		}
		claims, err := aauth.VerifyPersonToken(ctx, compact, client.keyResolver, client.clock)
		if err != nil {
			return MissionResult{}, err
		}
		if claims.Issuer != credential.personServer {
			return MissionResult{}, errors.New("mission person-token issuer does not match person server")
		}
		identity := struct {
			issuer string
			jti    string
		}{issuer: claims.Issuer, jti: claims.JTI}
		if _, duplicate := seenPersonTokens[identity]; duplicate {
			return MissionResult{}, errors.New("mission response returned duplicate person-token issuer and jti")
		}
		seenPersonTokens[identity] = struct{}{}
		if err := aauth.ValidatePersonTokenContext(claims, resource, credential.requestKey); err != nil {
			return MissionResult{}, err
		}
		if claims.MissionS256 != mission.S256 {
			return MissionResult{}, errors.New("mission person token carries another mission_s256")
		}
		if claims.ExpiresAt > credential.expiresAt {
			return MissionResult{}, errors.New("mission person-token lifetime exceeds " + credential.expirySource)
		}
		if mission.Blob.ExpiresAt != nil && claims.ExpiresAt > mission.Blob.ExpiresAt.Unix() {
			return MissionResult{}, errors.New("mission person token outlives the mission")
		}
		verifiedTokens[resource] = compact
	}
	return MissionResult{
		mission: cloneApprovedMission(mission), capabilities: append([]string(nil), approval.Capabilities...),
		personTokens: verifiedTokens,
	}, nil
}

func (client *Client) pendingMissionProposal(
	response *http.Response,
	personServer string,
	proposedResources []string,
	prior PendingMissionProposal,
	operation string,
) (PendingMissionProposal, error) {
	location, err := parsePendingLocation(response)
	if err != nil {
		return PendingMissionProposal{}, err
	}
	if prior.location != "" && location != prior.location {
		return PendingMissionProposal{}, errors.New("pending mission proposal Location changed while polling")
	}
	target, err := url.Parse(location)
	if err != nil {
		return PendingMissionProposal{}, errors.New("pending mission proposal Location is invalid")
	}
	if _, err := httpOrigin(target); err != nil {
		return PendingMissionProposal{}, errors.New("pending mission proposal Location origin is invalid")
	}
	retryAfter, err := parseRetryAfter(response.Header.Values("Retry-After"))
	if err != nil {
		return PendingMissionProposal{}, err
	}
	if !hasNoStore(response.Header.Values("Cache-Control")) {
		return PendingMissionProposal{}, errors.New("pending mission proposal Cache-Control must contain no-store")
	}
	if len(response.Header.Values("Content-Type")) != 1 {
		return PendingMissionProposal{}, errors.New("pending mission proposal requires exactly one Content-Type")
	}
	if values := response.Header.Values("AAuth-Requirement"); len(values) > 0 {
		requirement, err := aauth.ParseRequirement(values)
		if err != nil {
			return PendingMissionProposal{}, err
		}
		if requirement != aauth.RequirementApproval {
			return PendingMissionProposal{}, &MissionContinuationUnsupportedError{
				Phase: string(requirement), Operation: operation,
			}
		}
	}
	var body struct {
		Status string `json:"status"`
	}
	if err := decodeJSONResponse(response, &body); err != nil {
		return PendingMissionProposal{}, err
	}
	if body.Status == "" {
		return PendingMissionProposal{}, errors.New("pending mission proposal status is required")
	}
	thumbprint, err := client.signingKey.PublicJWK().Thumbprint()
	if err != nil {
		return PendingMissionProposal{}, err
	}
	return PendingMissionProposal{
		personServer: personServer, location: location, retryAfter: retryAfter,
		agentProvider: client.agentClaims.Issuer, agent: client.identifier, agentJKT: thumbprint,
		resources: append([]string(nil), proposedResources...),
	}, nil
}

func (client *Client) validatePendingMissionProposal(ctx context.Context, pending PendingMissionProposal) error {
	if ctx == nil {
		return errors.New("context is required")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if pending.personServer == "" || pending.location == "" ||
		pending.agentProvider == "" || pending.agent == "" || pending.agentJKT == "" {
		return errors.New("verified pending mission proposal for this client is required")
	}
	if pending.personServer != client.agentClaims.PersonServer || pending.agentProvider != client.agentClaims.Issuer ||
		pending.agent != client.identifier {
		return errors.New("pending mission proposal does not match client identity")
	}
	thumbprint, err := client.signingKey.PublicJWK().Thumbprint()
	if err != nil {
		return err
	}
	if thumbprint != pending.agentJKT {
		return errors.New("pending mission proposal does not match client key")
	}
	target, err := url.Parse(pending.location)
	if err != nil {
		return errors.New("pending mission proposal Location is invalid")
	}
	if _, err := httpOrigin(target); err != nil {
		return errors.New("pending mission proposal Location does not match its verified origin")
	}
	return nil
}

func validateApprovedResources(proposed, approved []string) error {
	seen := make(map[string]struct{}, len(approved))
	for _, resource := range approved {
		if !slices.Contains(proposed, resource) {
			return errors.New("mission approved_resources contains an unproposed Resource")
		}
		if _, duplicate := seen[resource]; duplicate {
			return errors.New("mission approved_resources contains a duplicate Resource")
		}
		seen[resource] = struct{}{}
	}
	return nil
}

func validateProposedMissionResources(resources []string) error {
	seen := make(map[string]struct{}, len(resources))
	for _, resource := range resources {
		if err := aauth.ValidateServerIdentifier(resource); err != nil {
			return err
		}
		if _, duplicate := seen[resource]; duplicate {
			return errors.New("proposed resources contain a duplicate Resource")
		}
		seen[resource] = struct{}{}
	}
	return nil
}

func cloneApprovedMission(mission aauth.ApprovedMission) aauth.ApprovedMission {
	mission.ExactJSON = append([]byte(nil), mission.ExactJSON...)
	mission.Blob.ApprovedTools = append([]aauth.MissionTool(nil), mission.Blob.ApprovedTools...)
	mission.Blob.ApprovedResources = append([]string(nil), mission.Blob.ApprovedResources...)
	if mission.Blob.ExpiresAt != nil {
		expiresAt := *mission.Blob.ExpiresAt
		mission.Blob.ExpiresAt = &expiresAt
	}
	return mission
}
