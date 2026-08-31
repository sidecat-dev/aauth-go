package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"

	aauth "gitlab.com/sidecat-dev/aauth-go"
)

// MissionRequest names one Person Server and the mission proposal to submit.
type MissionRequest struct {
	PersonServer string
	Proposal     aauth.MissionProposal
}

// MissionUpdateRequest records one change against an existing mission.
type MissionUpdateRequest struct {
	PersonServer string
	MissionS256  string
	Description  string
}

// MissionUpdateResult is one immediately accepted mission update.
type MissionUpdateResult struct {
	s256 string
}

// S256 returns the Person Server's digest of the accepted update document.
func (result MissionUpdateResult) S256() string { return result.s256 }

// MissionCompletionRequest proposes that one existing mission is finished.
type MissionCompletionRequest struct {
	PersonServer string
	MissionS256  string
	Summary      string
}

// MissionContinuationUnsupportedError reports a mission-specific 202 response
// for which the named client operation does not expose a continuation.
type MissionContinuationUnsupportedError struct {
	Phase     string
	Operation string
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

// MissionResult is one verified immediate mission approval. Accessors return
// copies so callers cannot rewrite the verified mission or token map.
type MissionResult struct {
	mission      aauth.ApprovedMission
	capabilities []string
	personTokens map[string]string
}

// Mission returns the exact verified mission and its parsed blob.
func (result MissionResult) Mission() aauth.ApprovedMission {
	return cloneApprovedMission(result.mission)
}

// Capabilities returns the Person Server capabilities available at approval.
func (result MissionResult) Capabilities() []string {
	return append([]string(nil), result.capabilities...)
}

// PersonToken returns the verified mission-bound token for one Resource.
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

// ProposeMission performs one signed mission proposal and verifies one
// immediate approval. It does not drive deferred review, retry, or polling.
func (client *Client) ProposeMission(ctx context.Context, input MissionRequest) (MissionResult, error) {
	const operation = "propose mission"
	if client == nil {
		return MissionResult{}, fail(operation, errors.New("client is required"))
	}
	if ctx == nil {
		return MissionResult{}, fail(operation, errors.New("context is required"))
	}
	if err := ctx.Err(); err != nil {
		return MissionResult{}, fail(operation, err)
	}
	if err := input.Proposal.Validate(); err != nil {
		return MissionResult{}, fail(operation, err)
	}
	credential, err := client.personServerRequestBinding(ctx, input.PersonServer, "", "")
	if err != nil {
		return MissionResult{}, fail(operation, err)
	}
	metadata, err := client.personServerMetadata(ctx, credential.personServer)
	if err != nil {
		return MissionResult{}, fail(operation, err)
	}
	if metadata.MissionEndpoint == "" {
		return MissionResult{}, fail(operation, errors.New("person-server metadata mission_endpoint is required"))
	}
	if err := aauth.ValidateEndpoint(metadata.MissionEndpoint); err != nil {
		return MissionResult{}, fail(operation, fmt.Errorf("person-server metadata mission_endpoint: %w", err))
	}
	body, err := json.Marshal(input.Proposal)
	if err != nil {
		return MissionResult{}, fail(operation, err)
	}
	request, err := newJSONRequest(ctx, metadata.MissionEndpoint, body)
	if err != nil {
		return MissionResult{}, fail(operation, err)
	}
	if err := client.signJSONRequest(request, client.agentToken); err != nil {
		return MissionResult{}, fail(operation, err)
	}
	response, err := client.httpClient.Do(request)
	if err != nil {
		return MissionResult{}, fail(operation, err)
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusAccepted {
		if err := validateUnsupportedMissionContinuation(response); err != nil {
			return MissionResult{}, fail(operation, err)
		}
		return MissionResult{}, fail(operation, &MissionContinuationUnsupportedError{
			Phase: "approval", Operation: "ProposeMission",
		})
	}
	if response.StatusCode != http.StatusOK {
		return MissionResult{}, fail(operation, responseFailure(response))
	}
	var approval aauth.MissionApproval
	if err := decodeJSONResponse(response, &approval); err != nil {
		return MissionResult{}, fail(operation, err)
	}
	mission, err := aauth.DecodeMission(approval.S256, approval.Mission)
	if err != nil {
		return MissionResult{}, fail(operation, err)
	}
	if mission.Blob.Approver != credential.personServer {
		return MissionResult{}, fail(operation, errors.New("mission approver does not match person server"))
	}
	if mission.Blob.Agent != client.identifier {
		return MissionResult{}, fail(operation, errors.New("mission belongs to another Agent"))
	}
	if mission.Blob.ExpiresAt != nil && !client.clock.Now().Before(*mission.Blob.ExpiresAt) {
		return MissionResult{}, fail(operation, errors.New("approved mission is already expired"))
	}
	if err := validateApprovedResources(input.Proposal.Resources, mission.Blob.ApprovedResources); err != nil {
		return MissionResult{}, fail(operation, err)
	}
	if len(approval.Capabilities) > 0 {
		if _, err := aauth.FormatCapabilities(approval.Capabilities); err != nil {
			return MissionResult{}, fail(operation, fmt.Errorf("mission capabilities: %w", err))
		}
	}
	verifiedTokens := make(map[string]string, len(approval.PersonTokens))
	seenPersonTokens := make(map[struct {
		issuer string
		jti    string
	}]struct{}, len(approval.PersonTokens))
	for resource, compact := range approval.PersonTokens {
		if !slices.Contains(mission.Blob.ApprovedResources, resource) {
			return MissionResult{}, fail(operation, errors.New("mission response returned a token for an unapproved Resource"))
		}
		if compact == "" {
			return MissionResult{}, fail(operation, errors.New("mission response returned an empty person token"))
		}
		claims, err := aauth.VerifyPersonToken(ctx, compact, client.keyResolver, client.clock)
		if err != nil {
			return MissionResult{}, fail(operation, err)
		}
		if claims.Issuer != credential.personServer {
			return MissionResult{}, fail(operation, errors.New("mission person-token issuer does not match person server"))
		}
		identity := struct {
			issuer string
			jti    string
		}{issuer: claims.Issuer, jti: claims.JTI}
		if _, duplicate := seenPersonTokens[identity]; duplicate {
			return MissionResult{}, fail(operation, errors.New("mission response returned duplicate person-token issuer and jti"))
		}
		seenPersonTokens[identity] = struct{}{}
		if err := aauth.ValidatePersonTokenContext(claims, resource, credential.requestKey); err != nil {
			return MissionResult{}, fail(operation, err)
		}
		if claims.MissionS256 != mission.S256 {
			return MissionResult{}, fail(operation, errors.New("mission person token carries another mission_s256"))
		}
		if claims.ExpiresAt > credential.expiresAt {
			return MissionResult{}, fail(operation, errors.New("mission person-token lifetime exceeds "+credential.expirySource))
		}
		if mission.Blob.ExpiresAt != nil && claims.ExpiresAt > mission.Blob.ExpiresAt.Unix() {
			return MissionResult{}, fail(operation, errors.New("mission person token outlives the mission"))
		}
		verifiedTokens[resource] = compact
	}
	return MissionResult{
		mission: cloneApprovedMission(mission), capabilities: append([]string(nil), approval.Capabilities...),
		personTokens: verifiedTokens,
	}, nil
}

// UpdateMission performs one signed mission-update request and verifies one
// immediate acceptance. It does not drive deferred review, retry, or polling.
func (client *Client) UpdateMission(ctx context.Context, input MissionUpdateRequest) (MissionUpdateResult, error) {
	const operation = "update mission"
	if client == nil {
		return MissionUpdateResult{}, fail(operation, errors.New("client is required"))
	}
	document, err := aauth.EncodeMissionUpdate(aauth.MissionUpdate{
		Action: "update", Description: input.Description,
	})
	if err != nil {
		return MissionUpdateResult{}, fail(operation, err)
	}
	response, err := client.postMissionLifecycle(
		ctx, input.PersonServer, input.MissionS256, document.ExactJSON, "update", "UpdateMission",
	)
	if err != nil {
		return MissionUpdateResult{}, fail(operation, err)
	}
	defer response.Body.Close()
	var output aauth.MissionUpdateResponse
	if err := decodeJSONResponse(response, &output); err != nil {
		return MissionUpdateResult{}, fail(operation, err)
	}
	if err := aauth.ValidateMissionS256(output.S256); err != nil {
		return MissionUpdateResult{}, fail(operation, fmt.Errorf("mission update response s256: %w", err))
	}
	return MissionUpdateResult{s256: output.S256}, nil
}

// CompleteMission performs one signed mission-completion request and accepts
// one immediate completion. It does not drive deferred review, retry, or
// polling, and Core defines no success-response document to decode.
func (client *Client) CompleteMission(ctx context.Context, input MissionCompletionRequest) error {
	const operation = "complete mission"
	if client == nil {
		return fail(operation, errors.New("client is required"))
	}
	document, err := aauth.EncodeMissionCompletion(aauth.MissionCompletion{
		Action: "completion", Summary: input.Summary,
	})
	if err != nil {
		return fail(operation, err)
	}
	response, err := client.postMissionLifecycle(
		ctx, input.PersonServer, input.MissionS256, document.ExactJSON, "completion", "CompleteMission",
	)
	if err != nil {
		return fail(operation, err)
	}
	_ = response.Body.Close()
	return nil
}

func (client *Client) postMissionLifecycle(
	ctx context.Context,
	personServer string,
	missionS256 string,
	body []byte,
	phase string,
	operation string,
) (*http.Response, error) {
	if ctx == nil {
		return nil, errors.New("context is required")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	credential, err := client.personServerRequestBinding(ctx, personServer, "", "")
	if err != nil {
		return nil, err
	}
	if err := aauth.ValidateMissionS256(missionS256); err != nil {
		return nil, err
	}
	metadata, err := client.personServerMetadata(ctx, credential.personServer)
	if err != nil {
		return nil, err
	}
	if metadata.MissionEndpoint == "" {
		return nil, errors.New("person-server metadata mission_endpoint is required")
	}
	if err := aauth.ValidateEndpoint(metadata.MissionEndpoint); err != nil {
		return nil, fmt.Errorf("person-server metadata mission_endpoint: %w", err)
	}
	endpoint := strings.TrimRight(metadata.MissionEndpoint, "/") + "/" + missionS256
	request, err := newJSONRequest(ctx, endpoint, body)
	if err != nil {
		return nil, err
	}
	if err := client.signJSONRequest(request, client.agentToken); err != nil {
		return nil, err
	}
	response, err := client.httpClient.Do(request)
	if err != nil {
		return nil, err
	}
	if response.StatusCode == http.StatusAccepted {
		if err := validateUnsupportedMissionContinuation(response); err != nil {
			_ = response.Body.Close()
			return nil, err
		}
		_ = response.Body.Close()
		return nil, &MissionContinuationUnsupportedError{Phase: phase, Operation: operation}
	}
	if response.StatusCode != http.StatusOK {
		defer response.Body.Close()
		return nil, responseFailure(response)
	}
	return response, nil
}

func validateUnsupportedMissionContinuation(response *http.Response) error {
	if _, err := parsePendingLocation(response); err != nil {
		return err
	}
	if _, err := parseRetryAfter(response.Header.Values("Retry-After")); err != nil {
		return err
	}
	if !hasNoStore(response.Header.Values("Cache-Control")) {
		return errors.New("pending response Cache-Control must contain no-store")
	}
	if len(response.Header.Values("Content-Type")) != 1 {
		return errors.New("pending response requires exactly one Content-Type")
	}
	var body struct {
		Status string `json:"status"`
	}
	if err := decodeJSONResponse(response, &body); err != nil {
		return err
	}
	if strings.TrimSpace(body.Status) == "" {
		return errors.New("pending response status is required")
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
