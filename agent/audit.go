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

// SubmitAudit discovers the Person Server's audit endpoint and performs
// exactly one Agent-token-signed JSON POST. Any 201 Created response
// acknowledges the append; an optional response representation is ignored.
// It never retries, polls, sleeps, or executes the action described by the
// entry.
func (client *Client) SubmitAudit(ctx context.Context, input AuditRequest) error {
	const operation = "submit audit"
	if client == nil {
		return fail(operation, errors.New("client is required"))
	}
	if ctx == nil {
		return fail(operation, errors.New("context is required"))
	}
	if err := ctx.Err(); err != nil {
		return fail(operation, err)
	}
	document, err := aauth.EncodeAudit(input.Entry)
	if err != nil {
		return fail(operation, err)
	}
	credential, err := client.personServerRequestBinding(ctx, input.PersonServer, "", "")
	if err != nil {
		return fail(operation, err)
	}
	maxBodyBytes := client.maxSignedBodyBytes
	if maxBodyBytes == 0 {
		maxBodyBytes = defaultMaxAuditRequestBytes
	}
	if int64(len(document.ExactJSON)) > maxBodyBytes {
		return fail(operation, errors.New("audit request exceeds maximum signed body size"))
	}
	endpoint, err := client.discoverAuditEndpoint(ctx, credential.personServer)
	if err != nil {
		return fail(operation, err)
	}
	request, err := newJSONRequest(ctx, endpoint, document.ExactJSON)
	if err != nil {
		return fail(operation, err)
	}
	if err := client.signJSONRequest(request, client.agentToken); err != nil {
		return fail(operation, err)
	}
	response, err := client.httpClient.Do(request)
	if err != nil {
		return fail(operation, &AuditSubmissionUncertainError{cause: err})
	}
	defer response.Body.Close()

	if response.StatusCode == http.StatusCreated {
		return nil
	}

	failure := responseFailure(response)
	if auditSubmissionOutcomeUncertain(response.StatusCode) {
		return fail(operation, &AuditSubmissionUncertainError{cause: failure})
	}
	return fail(operation, failure)
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
