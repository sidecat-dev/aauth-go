package agent

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	aauth "gitlab.com/sidecat-dev/aauth-go"
)

const defaultMaxAuditRequestBytes = 1 << 20

// AuditRequest selects the Person Server and supplies one mission-bound audit
// entry for an action that has already been performed.
type AuditRequest struct {
	PersonServer string
	Entry        aauth.AuditEntry
}

// AuditSubmissionUncertainError reports an unverifiable outcome after the
// signed audit POST was handed to the HTTP client. The Person Server may have
// recorded the entry, so callers must not automatically submit it again.
type AuditSubmissionUncertainError struct {
	cause error
}

func (failure *AuditSubmissionUncertainError) Error() string {
	if failure == nil || failure.cause == nil {
		return "aauth agent: audit submission outcome is uncertain"
	}
	return "aauth agent: audit submission outcome is uncertain: " + failure.cause.Error()
}

func (failure *AuditSubmissionUncertainError) Unwrap() error {
	if failure == nil {
		return nil
	}
	return failure.cause
}

// AuditResult is a Person Server's acknowledgement (201 Created) of one
// audit entry.
type AuditResult struct{}

// SubmitAudit discovers the Person Server's audit endpoint and performs
// exactly one Agent-token-signed JSON POST. Any 201 Created response
// acknowledges the append; an optional response representation is ignored.
// It never retries, polls, sleeps, or executes the action described by the
// entry. When the Person Server defers the append, the error is a
// *PendingError[AuditResult] that carries the pending entry; BeginAudit
// returns it as a Result.
func (client *Client) SubmitAudit(ctx context.Context, input AuditRequest) error {
	const operation = "submit audit"
	result, err := client.beginAudit(ctx, input, operation)
	if err != nil {
		return err
	}
	_, err = completed(operation, result)
	return err
}

// BeginAudit performs the same single POST as SubmitAudit and returns the
// acknowledgement, or the pending entry when the Person Server answers 202.
// Audit is fire-and-forget (Core, Audit Response): the Agent need not wait
// for a pending entry before it continues its work, and may poll it later.
func (client *Client) BeginAudit(ctx context.Context, input AuditRequest) (Result[AuditResult], error) {
	return client.beginAudit(ctx, input, "begin audit")
}

func (client *Client) beginAudit(ctx context.Context, input AuditRequest, operation string) (Result[AuditResult], error) {
	if client == nil {
		return Result[AuditResult]{}, fail(operation, errors.New("client is required"))
	}
	if ctx == nil {
		return Result[AuditResult]{}, fail(operation, errors.New("context is required"))
	}
	if err := ctx.Err(); err != nil {
		return Result[AuditResult]{}, fail(operation, err)
	}
	document, err := aauth.EncodeAudit(input.Entry)
	if err != nil {
		return Result[AuditResult]{}, fail(operation, err)
	}
	credential, err := client.personServerRequestBinding(ctx, input.PersonServer, "", "")
	if err != nil {
		return Result[AuditResult]{}, fail(operation, err)
	}
	maxBodyBytes := client.maxSignedBodyBytes
	if maxBodyBytes == 0 {
		maxBodyBytes = defaultMaxAuditRequestBytes
	}
	if int64(len(document.ExactJSON)) > maxBodyBytes {
		return Result[AuditResult]{}, fail(operation, errors.New("audit request exceeds maximum signed body size"))
	}
	endpoint, err := client.discoverAuditEndpoint(ctx, credential.personServer)
	if err != nil {
		return Result[AuditResult]{}, fail(operation, err)
	}
	request, err := newJSONRequest(ctx, endpoint, document.ExactJSON)
	if err != nil {
		return Result[AuditResult]{}, fail(operation, err)
	}
	if err := client.signJSONRequest(request, client.agentToken); err != nil {
		return Result[AuditResult]{}, fail(operation, err)
	}
	response, err := client.httpClient.Do(request)
	if err != nil {
		return Result[AuditResult]{}, fail(operation, &AuditSubmissionUncertainError{cause: err})
	}
	accepted := response.StatusCode == http.StatusAccepted
	result, err := newPendingFlow(client, "audit", client.agentToken, readAuditResponse).begin(ctx, response)
	if err != nil {
		// A 202 that cannot be polled still says the Person Server took the
		// entry, so whether it was recorded is unknown.
		if accepted {
			err = &AuditSubmissionUncertainError{cause: err}
		}
		return Result[AuditResult]{}, fail(operation, err)
	}
	return result, nil
}

func readAuditResponse(_ context.Context, response *http.Response) (AuditResult, error) {
	if response.StatusCode == http.StatusCreated {
		return AuditResult{}, nil
	}
	failure := responseFailure(response)
	if auditSubmissionOutcomeUncertain(response.StatusCode) {
		return AuditResult{}, &AuditSubmissionUncertainError{cause: failure}
	}
	return AuditResult{}, failure
}

func (client *Client) discoverAuditEndpoint(ctx context.Context, personServer string) (string, error) {
	metadata, err := client.personServerMetadata(ctx, personServer)
	if err != nil {
		return "", err
	}
	if metadata.AuditEndpoint == "" {
		return "", errors.New("person-server metadata audit_endpoint is required")
	}
	if err := aauth.ValidateEndpoint(metadata.AuditEndpoint); err != nil {
		return "", fmt.Errorf("person-server metadata audit_endpoint: %w", err)
	}
	return metadata.AuditEndpoint, nil
}

func auditSubmissionOutcomeUncertain(status int) bool {
	return status >= http.StatusOK && status < http.StatusMultipleChoices ||
		status >= http.StatusInternalServerError && status < 600
}
