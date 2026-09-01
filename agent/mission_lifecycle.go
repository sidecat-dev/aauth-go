package agent

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	aauth "gitlab.com/sidecat-dev/aauth-go"
)

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
