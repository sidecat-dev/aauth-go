package agent

import (
	"context"
	"encoding/json"
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

// MissionUpdateResult is one accepted mission update.
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

// MissionCompletionResult is the person's acceptance of a completion
// proposal: the Person Server terminated the mission with reason completed.
type MissionCompletionResult struct {
	missionS256 string
}

// MissionS256 returns the mission that was completed.
func (result MissionCompletionResult) MissionS256() string { return result.missionS256 }

// UpdateMission performs one signed mission-update request and verifies one
// immediate acceptance. When the Person Server defers the update while the
// person reviews it, the error is a *PendingError[MissionUpdateResult] that
// carries the pending update; BeginMissionUpdate returns it as a Result.
func (client *Client) UpdateMission(ctx context.Context, input MissionUpdateRequest) (MissionUpdateResult, error) {
	const operation = "update mission"
	result, err := client.beginMissionUpdate(ctx, input, operation)
	if err != nil {
		return MissionUpdateResult{}, err
	}
	return completed(operation, result)
}

// BeginMissionUpdate performs one signed mission-update request (Core,
// Mission Update). It returns the accepted update, or the pending update when
// the Person Server answers 202 while the person reviews it. Poll the pending
// update; a clarification asked during review is answered on it.
func (client *Client) BeginMissionUpdate(ctx context.Context, input MissionUpdateRequest) (Result[MissionUpdateResult], error) {
	return client.beginMissionUpdate(ctx, input, "begin mission update")
}

func (client *Client) beginMissionUpdate(
	ctx context.Context,
	input MissionUpdateRequest,
	operation string,
) (Result[MissionUpdateResult], error) {
	if client == nil {
		return Result[MissionUpdateResult]{}, fail(operation, errors.New("client is required"))
	}
	document, err := aauth.EncodeMissionUpdate(aauth.MissionUpdate{
		Action: "update", Description: input.Description,
	})
	if err != nil {
		return Result[MissionUpdateResult]{}, fail(operation, err)
	}
	response, err := client.postMissionLifecycle(ctx, input.PersonServer, input.MissionS256, document.ExactJSON)
	if err != nil {
		return Result[MissionUpdateResult]{}, fail(operation, err)
	}
	flow := newPendingFlow(client, "mission update", client.agentToken, readMissionUpdate)
	result, err := flow.begin(ctx, response)
	if err != nil {
		return Result[MissionUpdateResult]{}, fail(operation, err)
	}
	return result, nil
}

func readMissionUpdate(_ context.Context, response *http.Response) (MissionUpdateResult, error) {
	if response.StatusCode != http.StatusOK {
		return MissionUpdateResult{}, responseFailure(response)
	}
	var output aauth.MissionUpdateResponse
	if err := decodeJSONResponse(response, &output); err != nil {
		return MissionUpdateResult{}, err
	}
	if err := aauth.ValidateMissionS256(output.S256); err != nil {
		return MissionUpdateResult{}, fmt.Errorf("mission update response s256: %w", err)
	}
	return MissionUpdateResult{s256: output.S256}, nil
}

// CompleteMission performs one signed mission-completion request and accepts
// one immediate completion. Core defines no success-response document to
// decode. A Person Server may defer completion while the person reviews the
// summary; this module's Person Server answers at once unless a supervision
// server decides the completion. A deferred completion is a
// *PendingError[MissionCompletionResult] that carries the pending completion,
// and BeginMissionCompletion returns it as a Result.
func (client *Client) CompleteMission(ctx context.Context, input MissionCompletionRequest) error {
	const operation = "complete mission"
	result, err := client.beginMissionCompletion(ctx, input, operation)
	if err != nil {
		return err
	}
	_, err = completed(operation, result)
	return err
}

// BeginMissionCompletion performs one signed mission-completion request
// (Core, Mission Completion). It returns the accepted completion, or the
// pending completion while the person reviews the summary. The person may
// answer with follow-up questions, which arrive on the pending completion as
// a clarification; the mission stays active until the person accepts.
func (client *Client) BeginMissionCompletion(
	ctx context.Context,
	input MissionCompletionRequest,
) (Result[MissionCompletionResult], error) {
	return client.beginMissionCompletion(ctx, input, "begin mission completion")
}

func (client *Client) beginMissionCompletion(
	ctx context.Context,
	input MissionCompletionRequest,
	operation string,
) (Result[MissionCompletionResult], error) {
	if client == nil {
		return Result[MissionCompletionResult]{}, fail(operation, errors.New("client is required"))
	}
	document, err := aauth.EncodeMissionCompletion(aauth.MissionCompletion{
		Action: "completion", Summary: input.Summary,
	})
	if err != nil {
		return Result[MissionCompletionResult]{}, fail(operation, err)
	}
	response, err := client.postMissionLifecycle(ctx, input.PersonServer, input.MissionS256, document.ExactJSON)
	if err != nil {
		return Result[MissionCompletionResult]{}, fail(operation, err)
	}
	missionS256 := input.MissionS256
	flow := newPendingFlow(client, "mission completion", client.agentToken,
		func(_ context.Context, response *http.Response) (MissionCompletionResult, error) {
			if response.StatusCode != http.StatusOK {
				return MissionCompletionResult{}, responseFailure(response)
			}
			return MissionCompletionResult{missionS256: missionS256}, nil
		})
	result, err := flow.begin(ctx, response)
	if err != nil {
		return Result[MissionCompletionResult]{}, fail(operation, err)
	}
	return result, nil
}

// MissionReadRequest names one mission this Agent owns at its Person Server.
type MissionReadRequest struct {
	PersonServer string
	MissionS256  string
}

// ReadMission performs one signed, bodyless GET of the mission's own URL and
// verifies the answer: the approved mission as the bytes its s256 names, and
// each accepted update against its own s256, in acceptance order. A party
// auditing a mission reads both (Core, Mission Update). A terminated mission
// is refused with an *aauth.Problem whose code is mission_terminated.
func (client *Client) ReadMission(ctx context.Context, input MissionReadRequest) (aauth.MissionRead, error) {
	const operation = "read mission"
	if client == nil {
		return aauth.MissionRead{}, fail(operation, errors.New("client is required"))
	}
	if ctx == nil {
		return aauth.MissionRead{}, fail(operation, errors.New("context is required"))
	}
	endpoint, err := client.missionURL(ctx, input.PersonServer, input.MissionS256)
	if err != nil {
		return aauth.MissionRead{}, fail(operation, err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return aauth.MissionRead{}, fail(operation, err)
	}
	if err := client.pendingRequestSigner()(request); err != nil {
		return aauth.MissionRead{}, fail(operation, err)
	}
	response, err := client.httpClient.Do(request)
	if err != nil {
		return aauth.MissionRead{}, fail(operation, err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return aauth.MissionRead{}, fail(operation, responseFailure(response))
	}
	var exact json.RawMessage
	if err := decodeJSONResponse(response, &exact); err != nil {
		return aauth.MissionRead{}, fail(operation, err)
	}
	read, err := aauth.DecodeMissionRead(exact, input.MissionS256)
	if err != nil {
		return aauth.MissionRead{}, fail(operation, err)
	}
	return read, nil
}

// postMissionLifecycle sends one signed update or completion and returns its
// answer, whatever the status.
func (client *Client) postMissionLifecycle(
	ctx context.Context,
	personServer string,
	missionS256 string,
	body []byte,
) (*http.Response, error) {
	if ctx == nil {
		return nil, errors.New("context is required")
	}
	endpoint, err := client.missionURL(ctx, personServer, missionS256)
	if err != nil {
		return nil, err
	}
	request, err := newJSONRequest(ctx, endpoint, body)
	if err != nil {
		return nil, err
	}
	if err := client.signJSONRequest(request, client.agentToken); err != nil {
		return nil, err
	}
	return client.httpClient.Do(request)
}

// missionURL returns {mission_endpoint}/{mission_s256} at the Person Server
// this Agent's requests go to.
func (client *Client) missionURL(ctx context.Context, personServer, missionS256 string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	credential, err := client.personServerRequestBinding(ctx, personServer, "", "")
	if err != nil {
		return "", err
	}
	if err := aauth.ValidateMissionS256(missionS256); err != nil {
		return "", err
	}
	metadata, err := client.personServerMetadata(ctx, credential.personServer)
	if err != nil {
		return "", err
	}
	if metadata.MissionEndpoint == "" {
		return "", errors.New("person-server metadata mission_endpoint is required")
	}
	if err := aauth.ValidateEndpoint(metadata.MissionEndpoint); err != nil {
		return "", fmt.Errorf("person-server metadata mission_endpoint: %w", err)
	}
	return strings.TrimRight(metadata.MissionEndpoint, "/") + "/" + missionS256, nil
}
