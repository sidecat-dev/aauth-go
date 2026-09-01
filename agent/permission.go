package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/internal/jsonstrict"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

const (
	maxPermissionActionBytes         = 4 << 10
	maxPermissionDescriptionBytes    = 64 << 10
	defaultMaxPermissionRequestBytes = 1 << 20
)

// PermissionRequest asks the request's Person Server to decide one action not
// governed by a remote Resource. MissionS256 optionally associates the action
// with an already-approved mission owned by this Agent.
type PermissionRequest struct {
	PersonServer string
	MissionS256  string
	Action       string
	Description  string
	Parameters   json.RawMessage
}

type permissionResultKind uint8
type permissionDecisionKind uint8
type pendingPermissionKind uint8

const (
	permissionResultDecision permissionResultKind = iota + 1
	permissionResultPending
	permissionResultResponse
)

const (
	permissionDecisionVerified permissionDecisionKind = 1
	pendingPermissionVerified  pendingPermissionKind  = 1
)

// PermissionDecision is one validated permission decision. Reason returns
// untrusted raw Markdown supplied by the Person Server; callers must sanitize
// it before rendering.
type PermissionDecision struct {
	kind       permissionDecisionKind
	permission aauth.Permission
	reason     string
}

// Permission returns the validated decision.
func (decision PermissionDecision) Permission() aauth.Permission {
	if decision.kind != permissionDecisionVerified {
		return ""
	}
	return decision.permission
}

// Reason returns the optional, untrusted raw Markdown denial explanation.
func (decision PermissionDecision) Reason() string {
	if decision.kind != permissionDecisionVerified {
		return ""
	}
	return decision.reason
}

// PermissionResult is exactly one decision, verified pending continuation, or
// caller-owned 429/503 response. A response body returned by Response remains
// open and must be closed by the caller.
type PermissionResult struct {
	kind     permissionResultKind
	decision PermissionDecision
	pending  PendingPermission
	response *http.Response
}

// Decision returns the validated permission decision, when present.
func (result PermissionResult) Decision() (PermissionDecision, bool) {
	if result.kind != permissionResultDecision || result.decision.kind != permissionDecisionVerified {
		return PermissionDecision{}, false
	}
	return result.decision, true
}

// Pending returns the verified continuation, when present.
func (result PermissionResult) Pending() (PendingPermission, bool) {
	if result.kind != permissionResultPending || result.pending.kind != pendingPermissionVerified {
		return PendingPermission{}, false
	}
	return result.pending, true
}

// Response returns the explicit retryable response, when present. The caller
// owns and closes its body. RequestPermission and PollPermission never act on
// the response automatically.
func (result PermissionResult) Response() (*http.Response, bool) {
	if result.kind != permissionResultResponse || result.response == nil {
		return nil, false
	}
	return result.response, true
}

// PendingPermission is a verified permission continuation. Private binding
// fields prevent callers from inventing a target or transferring the polling
// authority to another Agent identity or key.
type PendingPermission struct {
	kind          pendingPermissionKind
	personServer  string
	location      string
	origin        string
	retryAfter    time.Duration
	agentProvider string
	agent         string
	agentJKT      string
}

// PersonServer returns the Person Server that accepted the request.
func (pending PendingPermission) PersonServer() string { return pending.personServer }

// Location returns the verified pending URL.
func (pending PendingPermission) Location() string { return pending.location }

// RetryAfter returns the server's current polling interval hint.
func (pending PendingPermission) RetryAfter() time.Duration { return pending.retryAfter }

// PermissionSubmissionUncertainError reports an unverifiable result after the
// initial permission POST was handed to the HTTP client. The Person Server may
// have accepted it, so callers must not automatically submit the action again.
type PermissionSubmissionUncertainError struct {
	cause error
}

func (failure *PermissionSubmissionUncertainError) Error() string {
	if failure == nil || failure.cause == nil {
		return "aauth agent: permission submission outcome is uncertain"
	}
	return "aauth agent: permission submission outcome is uncertain: " + failure.cause.Error()
}

func (failure *PermissionSubmissionUncertainError) Unwrap() error {
	if failure == nil {
		return nil
	}
	return failure.cause
}

// RequestPermission discovers the Person Server's permission endpoint and
// performs exactly one Agent-token-signed JSON POST. It never polls, sleeps,
// retries, or performs the requested action.
func (client *Client) RequestPermission(ctx context.Context, input PermissionRequest) (PermissionResult, error) {
	const operation = "request permission"
	if client == nil {
		return PermissionResult{}, fail(operation, errors.New("client is required"))
	}
	if ctx == nil {
		return PermissionResult{}, fail(operation, errors.New("context is required"))
	}
	if err := ctx.Err(); err != nil {
		return PermissionResult{}, fail(operation, err)
	}
	if err := validatePermissionInput(input); err != nil {
		return PermissionResult{}, fail(operation, err)
	}
	credential, err := client.personServerRequestBinding(ctx, input.PersonServer, "", "")
	if err != nil {
		return PermissionResult{}, fail(operation, err)
	}
	body, err := marshalPermissionRequest(input)
	if err != nil {
		return PermissionResult{}, fail(operation, err)
	}
	maxBodyBytes := client.maxSignedBodyBytes
	if maxBodyBytes == 0 {
		maxBodyBytes = defaultMaxPermissionRequestBytes
	}
	if int64(len(body)) > maxBodyBytes {
		return PermissionResult{}, fail(operation, errors.New("permission request exceeds maximum signed body size"))
	}
	endpoint, origin, err := client.discoverPermissionEndpoint(ctx, credential.personServer)
	if err != nil {
		return PermissionResult{}, fail(operation, err)
	}
	request, err := newJSONRequest(ctx, endpoint, body)
	if err != nil {
		return PermissionResult{}, fail(operation, err)
	}
	if err := client.signJSONRequest(request, client.agentToken); err != nil {
		return PermissionResult{}, fail(operation, err)
	}
	response, err := client.httpClient.Do(request)
	if err != nil {
		return PermissionResult{}, fail(operation, &PermissionSubmissionUncertainError{cause: err})
	}
	result, err := client.permissionResponse(response, credential.personServer, origin, PendingPermission{}, false)
	if err != nil {
		if permissionSubmissionOutcomeUncertain(response.StatusCode) {
			return PermissionResult{}, fail(operation, &PermissionSubmissionUncertainError{cause: err})
		}
		return PermissionResult{}, fail(operation, err)
	}
	return result, nil
}

func permissionSubmissionOutcomeUncertain(status int) bool {
	return status >= http.StatusOK && status < http.StatusMultipleChoices || status >= http.StatusInternalServerError
}

// PollPermission performs exactly one signed, bodyless GET for a verified
// pending permission. It never sleeps, loops, resubmits the original POST, or
// performs the requested action.
func (client *Client) PollPermission(ctx context.Context, pending PendingPermission) (PermissionResult, error) {
	const operation = "poll permission"
	if client == nil {
		return PermissionResult{}, fail(operation, errors.New("client is required"))
	}
	if err := client.validatePendingPermission(ctx, pending); err != nil {
		return PermissionResult{}, fail(operation, err)
	}
	_, currentOrigin, err := client.discoverPermissionEndpoint(ctx, pending.personServer)
	if err != nil {
		return PermissionResult{}, fail(operation, err)
	}
	if currentOrigin != pending.origin {
		return PermissionResult{}, fail(operation, errors.New("pending permission origin does not match current Person Server metadata"))
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, pending.location, nil)
	if err != nil {
		return PermissionResult{}, fail(operation, err)
	}
	if err := signaturekey.SignJWTRequest(request, client.signingKey, client.agentToken, client.clock); err != nil {
		return PermissionResult{}, fail(operation, err)
	}
	response, err := client.httpClient.Do(request)
	if err != nil {
		return PermissionResult{}, fail(operation, err)
	}
	result, err := client.permissionResponse(response, pending.personServer, pending.origin, pending, true)
	if err != nil {
		return PermissionResult{}, fail(operation, err)
	}
	return result, nil
}

func validatePermissionInput(input PermissionRequest) error {
	if input.MissionS256 != "" {
		if err := aauth.ValidateMissionS256(input.MissionS256); err != nil {
			return fmt.Errorf("permission mission: %w", err)
		}
	}
	if !utf8.ValidString(input.Action) || strings.TrimSpace(input.Action) == "" {
		return errors.New("permission action must be a nonempty UTF-8 string")
	}
	if len(input.Action) > maxPermissionActionBytes {
		return fmt.Errorf("permission action exceeds %d bytes", maxPermissionActionBytes)
	}
	if !utf8.ValidString(input.Description) {
		return errors.New("permission description must be UTF-8")
	}
	if len(input.Description) > maxPermissionDescriptionBytes {
		return fmt.Errorf("permission description exceeds %d bytes", maxPermissionDescriptionBytes)
	}
	if input.Parameters == nil || len(input.Parameters) == 0 {
		return nil
	}
	parameters := bytes.TrimSpace(input.Parameters)
	if len(parameters) == 0 || parameters[0] != '{' {
		return errors.New("permission parameters must be a JSON object when present")
	}
	if err := jsonstrict.RejectAmbiguousNames(parameters); err != nil {
		return fmt.Errorf("permission parameters: %w", err)
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(parameters, &object); err != nil {
		return fmt.Errorf("permission parameters must be a JSON object: %w", err)
	}
	if object == nil {
		return errors.New("permission parameters must be a JSON object when present")
	}
	return nil
}

func marshalPermissionRequest(input PermissionRequest) ([]byte, error) {
	wire := struct {
		Action      string          `json:"action"`
		Description string          `json:"description,omitempty"`
		Parameters  json.RawMessage `json:"parameters,omitempty"`
		MissionS256 string          `json:"mission_s256,omitempty"`
	}{
		Action: input.Action, Description: input.Description,
		Parameters:  append(json.RawMessage(nil), input.Parameters...),
		MissionS256: input.MissionS256,
	}
	body, err := json.Marshal(wire)
	if err != nil {
		return nil, fmt.Errorf("encode permission request: %w", err)
	}
	return body, nil
}

func (client *Client) discoverPermissionEndpoint(ctx context.Context, personServer string) (string, string, error) {
	metadata, err := client.personServerMetadata(ctx, personServer)
	if err != nil {
		return "", "", err
	}
	if metadata.PermissionEndpoint == "" {
		return "", "", errors.New("person-server metadata permission_endpoint is required")
	}
	if err := aauth.ValidateEndpoint(metadata.PermissionEndpoint); err != nil {
		return "", "", fmt.Errorf("person-server metadata permission_endpoint: %w", err)
	}
	target, err := url.Parse(metadata.PermissionEndpoint)
	if err != nil {
		return "", "", fmt.Errorf("person-server metadata permission_endpoint: %w", err)
	}
	origin, err := httpOrigin(target)
	if err != nil {
		return "", "", fmt.Errorf("person-server metadata permission_endpoint origin: %w", err)
	}
	return metadata.PermissionEndpoint, origin, nil
}

func (client *Client) permissionResponse(
	response *http.Response,
	personServer string,
	origin string,
	prior PendingPermission,
	polling bool,
) (PermissionResult, error) {
	if response == nil {
		return PermissionResult{}, errors.New("permission response is required")
	}
	if response.StatusCode == http.StatusTooManyRequests || response.StatusCode == http.StatusServiceUnavailable {
		return PermissionResult{kind: permissionResultResponse, response: response}, nil
	}
	defer response.Body.Close()
	switch response.StatusCode {
	case http.StatusOK:
		return decodePermissionDecision(response)
	case http.StatusAccepted:
		pending, err := client.pendingPermission(response, personServer, origin, prior)
		if err != nil {
			return PermissionResult{}, err
		}
		return PermissionResult{kind: permissionResultPending, pending: pending}, nil
	case http.StatusForbidden:
		if !polling {
			return PermissionResult{}, responseFailure(response)
		}
		problem, err := aauth.DecodeProblemResponse(response)
		if err != nil {
			return PermissionResult{}, err
		}
		if problem.Code != "denied" {
			return PermissionResult{}, problem
		}
		return permissionDecisionResult(aauth.PermissionDenied, problem.Detail), nil
	default:
		return PermissionResult{}, responseFailure(response)
	}
}

func decodePermissionDecision(response *http.Response) (PermissionResult, error) {
	if len(response.Header.Values("Content-Type")) != 1 {
		return PermissionResult{}, errors.New("permission response requires exactly one Content-Type")
	}
	var body struct {
		Permission string          `json:"permission"`
		Reason     json.RawMessage `json:"reason"`
	}
	if err := decodeJSONResponse(response, &body); err != nil {
		return PermissionResult{}, err
	}
	permission, err := aauth.ParsePermission(body.Permission)
	if err != nil {
		return PermissionResult{}, err
	}
	reason := ""
	if body.Reason != nil {
		if permission != aauth.PermissionDenied {
			return PermissionResult{}, errors.New("granted permission response must not contain reason")
		}
		if bytes.Equal(bytes.TrimSpace(body.Reason), []byte("null")) {
			return PermissionResult{}, errors.New("permission response reason must be a string")
		}
		if err := json.Unmarshal(body.Reason, &reason); err != nil {
			return PermissionResult{}, errors.New("permission response reason must be a string")
		}
	}
	return permissionDecisionResult(permission, reason), nil
}

func permissionDecisionResult(permission aauth.Permission, reason string) PermissionResult {
	return PermissionResult{
		kind: permissionResultDecision,
		decision: PermissionDecision{
			kind: permissionDecisionVerified, permission: permission, reason: reason,
		},
	}
}

func (client *Client) pendingPermission(
	response *http.Response,
	personServer string,
	origin string,
	prior PendingPermission,
) (PendingPermission, error) {
	location, err := parsePendingLocation(response)
	if err != nil {
		return PendingPermission{}, err
	}
	if prior.kind != 0 && location != prior.location {
		return PendingPermission{}, errors.New("pending permission Location changed while polling")
	}
	target, err := url.Parse(location)
	if err != nil {
		return PendingPermission{}, errors.New("pending permission Location is invalid")
	}
	locationOrigin, err := httpOrigin(target)
	if err != nil || locationOrigin != origin {
		return PendingPermission{}, errors.New("pending permission Location does not match metadata endpoint origin")
	}
	retryAfter, err := parseRetryAfter(response.Header.Values("Retry-After"))
	if err != nil {
		return PendingPermission{}, err
	}
	if !hasNoStore(response.Header.Values("Cache-Control")) {
		return PendingPermission{}, errors.New("pending permission response Cache-Control must contain no-store")
	}
	if len(response.Header.Values("Content-Type")) != 1 {
		return PendingPermission{}, errors.New("pending permission response requires exactly one Content-Type")
	}
	var body struct {
		Status string `json:"status"`
	}
	if err := decodeJSONResponse(response, &body); err != nil {
		return PendingPermission{}, err
	}
	if body.Status == "" {
		return PendingPermission{}, errors.New("pending permission response status is required")
	}
	thumbprint, err := client.signingKey.PublicJWK().Thumbprint()
	if err != nil {
		return PendingPermission{}, err
	}
	return PendingPermission{
		kind: pendingPermissionVerified, personServer: personServer,
		location: location, origin: origin, retryAfter: retryAfter,
		agentProvider: client.agentClaims.Issuer, agent: client.identifier, agentJKT: thumbprint,
	}, nil
}

func (client *Client) validatePendingPermission(ctx context.Context, pending PendingPermission) error {
	if ctx == nil {
		return errors.New("context is required")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := client.requireDirectPersonServerCaller(); err != nil {
		return err
	}
	if pending.kind != pendingPermissionVerified || pending.personServer == "" || pending.location == "" ||
		pending.origin == "" || pending.agentProvider == "" || pending.agent == "" || pending.agentJKT == "" {
		return errors.New("verified pending permission for this client is required")
	}
	if pending.personServer != client.agentClaims.PersonServer || pending.agentProvider != client.agentClaims.Issuer ||
		pending.agent != client.identifier {
		return errors.New("pending permission does not match client identity")
	}
	thumbprint, err := client.signingKey.PublicJWK().Thumbprint()
	if err != nil {
		return err
	}
	if thumbprint != pending.agentJKT {
		return errors.New("pending permission does not match client key")
	}
	target, err := url.Parse(pending.location)
	if err != nil {
		return errors.New("pending permission Location is invalid")
	}
	origin, err := httpOrigin(target)
	if err != nil || origin != pending.origin {
		return errors.New("pending permission Location does not match its verified origin")
	}
	return nil
}
