package agent

import (
	"context"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"

	aauth "gitlab.com/sidecat-dev/aauth-go"
)

const defaultMaxInteractionQuestionBytes = 1 << 20

// InteractionQuestionRequest selects the Person Server and supplies one
// missionless question. Description and Question are untrusted raw Markdown.
type InteractionQuestionRequest struct {
	PersonServer string
	Description  string
	Question     string
}

// InteractionQuestionUncertainError reports that the signed question reached
// the HTTP client but no valid immediate answer was obtained. The Person
// Server may have delivered or retained the question, so callers must not
// automatically submit it again.
type InteractionQuestionUncertainError struct {
	cause error
}

func (failure *InteractionQuestionUncertainError) Error() string {
	if failure == nil || failure.cause == nil {
		return "aauth agent: interaction question outcome is uncertain"
	}
	return "aauth agent: interaction question outcome is uncertain: " + failure.cause.Error()
}

func (failure *InteractionQuestionUncertainError) Unwrap() error {
	if failure == nil {
		return nil
	}
	return failure.cause
}

// AskPersonQuestion discovers the Person Server's interaction endpoint and
// performs exactly one Agent-token-signed question POST. It returns the exact
// immediate answer document from a valid 200 response. It never retries,
// polls, renders Markdown, or contacts a person itself.
func (client *Client) AskPersonQuestion(
	ctx context.Context,
	input InteractionQuestionRequest,
) (aauth.InteractionAnswerDocument, error) {
	const operation = "ask person question"
	if client == nil {
		return aauth.InteractionAnswerDocument{}, fail(operation, errors.New("client is required"))
	}
	if ctx == nil {
		return aauth.InteractionAnswerDocument{}, fail(operation, errors.New("context is required"))
	}
	if err := ctx.Err(); err != nil {
		return aauth.InteractionAnswerDocument{}, fail(operation, err)
	}
	document, err := aauth.EncodeInteractionQuestion(aauth.InteractionQuestion{
		Description: input.Description, Question: input.Question,
	})
	if err != nil {
		return aauth.InteractionAnswerDocument{}, fail(operation, err)
	}
	credential, err := client.personServerRequestBinding(ctx, input.PersonServer, "", "")
	if err != nil {
		return aauth.InteractionAnswerDocument{}, fail(operation, err)
	}
	maxBodyBytes := client.maxSignedBodyBytes
	if maxBodyBytes == 0 {
		maxBodyBytes = defaultMaxInteractionQuestionBytes
	}
	if int64(len(document.ExactJSON)) > maxBodyBytes {
		return aauth.InteractionAnswerDocument{}, fail(operation, errors.New("interaction question exceeds maximum signed body size"))
	}
	endpoint, err := client.discoverInteractionEndpoint(ctx, credential.personServer)
	if err != nil {
		return aauth.InteractionAnswerDocument{}, fail(operation, err)
	}
	request, err := newJSONRequest(ctx, endpoint, document.ExactJSON)
	if err != nil {
		return aauth.InteractionAnswerDocument{}, fail(operation, err)
	}
	if err := client.signJSONRequest(request, client.agentToken); err != nil {
		return aauth.InteractionAnswerDocument{}, fail(operation, err)
	}
	response, err := client.httpClient.Do(request)
	if err != nil {
		return aauth.InteractionAnswerDocument{}, fail(operation, &InteractionQuestionUncertainError{cause: err})
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		failure := responseFailure(response)
		if interactionQuestionOutcomeUncertain(response.StatusCode) {
			failure = &InteractionQuestionUncertainError{cause: failure}
		}
		return aauth.InteractionAnswerDocument{}, fail(operation, failure)
	}
	answer, err := decodeInteractionAnswerResponse(response)
	if err != nil {
		return aauth.InteractionAnswerDocument{}, fail(operation, &InteractionQuestionUncertainError{cause: err})
	}
	return answer, nil
}

func (client *Client) discoverInteractionEndpoint(ctx context.Context, personServer string) (string, error) {
	metadata, err := client.personServerMetadata(ctx, personServer)
	if err != nil {
		return "", err
	}
	if metadata.InteractionEndpoint == "" {
		return "", errors.New("person-server metadata interaction_endpoint is required")
	}
	if err := aauth.ValidateEndpoint(metadata.InteractionEndpoint); err != nil {
		return "", fmt.Errorf("person-server metadata interaction_endpoint: %w", err)
	}
	return metadata.InteractionEndpoint, nil
}

func decodeInteractionAnswerResponse(response *http.Response) (aauth.InteractionAnswerDocument, error) {
	mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return aauth.InteractionAnswerDocument{}, errors.New("interaction answer must use application/json")
	}
	exactJSON, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
	if err != nil {
		return aauth.InteractionAnswerDocument{}, fmt.Errorf("read interaction answer: %w", err)
	}
	if len(exactJSON) > maxResponseBytes {
		return aauth.InteractionAnswerDocument{}, errors.New("interaction answer is too large")
	}
	return aauth.DecodeInteractionAnswer(exactJSON)
}

func interactionQuestionOutcomeUncertain(status int) bool {
	return status >= http.StatusOK && status < http.StatusMultipleChoices ||
		status >= http.StatusInternalServerError && status < 600
}
