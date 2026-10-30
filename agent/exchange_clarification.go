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
	"strings"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

const maxClarificationResponseBytes = 64 << 10

type clarificationQuestionKind uint8

const clarificationQuestionValidated clarificationQuestionKind = 1

type clarificationQuestionOptions struct{ values []string }

// ClarificationQuestion is a protocol-shaped question from a verified pending
// response. Its question and options remain raw, untrusted Markdown or display
// strings. Callers must sanitize them before rendering.
//
// The source draft defines timeout as a relative number of seconds without
// defining its reference instant. AnswerBefore is therefore derived from this
// client's response-observation time; the server may still expire it earlier.
type ClarificationQuestion struct {
	kind         clarificationQuestionKind
	question     string
	timeout      time.Duration
	hasTimeout   bool
	answerBefore time.Time
	options      *clarificationQuestionOptions
}

// Question returns raw, untrusted Markdown. Sanitize it before rendering.
func (question ClarificationQuestion) Question() string {
	if question.kind != clarificationQuestionValidated {
		return ""
	}
	return question.question
}

// Timeout returns the server's relative timeout when supplied. The source
// draft does not define the instant from which this duration starts.
func (question ClarificationQuestion) Timeout() (time.Duration, bool) {
	if question.kind != clarificationQuestionValidated || !question.hasTimeout {
		return 0, false
	}
	return question.timeout, true
}

// AnswerBefore returns the local instant derived from observing the response.
// The server may use an earlier reference instant and expire the request first.
func (question ClarificationQuestion) AnswerBefore() (time.Time, bool) {
	if question.kind != clarificationQuestionValidated || !question.hasTimeout || question.answerBefore.IsZero() {
		return time.Time{}, false
	}
	return question.answerBefore, true
}

// Options returns independent copies of raw, untrusted display strings.
// Sanitize each option before rendering it as Markdown or HTML.
func (question ClarificationQuestion) Options() []string {
	if question.kind != clarificationQuestionValidated || question.options == nil {
		return nil
	}
	return slices.Clone(question.options.values)
}

// Clarification returns the current protocol-shaped clarification question.
func (pending PendingExchange) Clarification() (ClarificationQuestion, bool) {
	if pending.kind != pendingExchangeVerified || pending.requirement != aauth.RequirementClarification ||
		pending.clarification.kind != clarificationQuestionValidated {
		return ClarificationQuestion{}, false
	}
	return pending.clarification, true
}

// PendingExchangeSnapshot is the minimal JSON-serializable state needed to
// restore one exchange continuation. It contains credentials and endpoint
// state, including the Resource token. Its confidentiality and integrity must
// be protected like any other credential-bearing continuation.
type PendingExchangeSnapshot struct {
	PersonServer string `json:"person_server"`
	Location     string `json:"location"`

	RetryAfterSeconds int64             `json:"retry_after_seconds"`
	Interacting       bool              `json:"interacting,omitempty"`
	Requirement       aauth.Requirement `json:"requirement,omitempty"`
	Capabilities      []string          `json:"capabilities,omitempty"`

	InteractionURL  string `json:"interaction_url,omitempty"`
	InteractionCode string `json:"interaction_code,omitempty"`

	Clarification               string     `json:"clarification,omitempty"`
	ClarificationTimeoutSeconds *int64     `json:"clarification_timeout_seconds,omitempty"`
	ClarificationAnswerBefore   *time.Time `json:"clarification_answer_before,omitempty"`
	ClarificationOptions        []string   `json:"clarification_options,omitempty"`

	ResourceToken       string   `json:"resource_token"`
	AgentProvider       string   `json:"agent_provider"`
	Agent               string   `json:"agent"`
	CredentialKey       jose.JWK `json:"credential_key"`
	CredentialExpiresAt int64    `json:"credential_expires_at"`
	ParentMediated      bool     `json:"parent_mediated,omitempty"`
}

// Snapshot returns caller-owned persistence state for this verified
// continuation. The returned value contains credentials and must be stored
// confidentially and with integrity protection.
func (pending PendingExchange) Snapshot() (PendingExchangeSnapshot, error) {
	if pending.kind != pendingExchangeVerified || pending.personServer == "" || pending.resourceToken == "" ||
		pending.resourceClaims == nil || pending.agentProvider == "" || pending.agent == "" || pending.agentJKT == "" ||
		pending.tokenExpiresAt <= 0 || pending.tokenExpirySource == "" {
		return PendingExchangeSnapshot{}, errors.New("aauth agent: verified pending exchange is required")
	}
	if pending.retryAfter < 0 || pending.retryAfter%time.Second != 0 {
		return PendingExchangeSnapshot{}, errors.New("aauth agent: pending retry interval must be whole nonnegative seconds")
	}
	if err := validatePendingExchangeLocation(pending); err != nil {
		return PendingExchangeSnapshot{}, fmt.Errorf("aauth agent: snapshot pending exchange: %w", err)
	}
	if err := validatePendingExchangeRequirement(pending); err != nil {
		return PendingExchangeSnapshot{}, fmt.Errorf("aauth agent: snapshot pending exchange: %w", err)
	}
	snapshot := PendingExchangeSnapshot{
		PersonServer:        pending.personServer,
		Location:            pending.location,
		RetryAfterSeconds:   int64(pending.retryAfter / time.Second),
		Interacting:         pending.interacting,
		Requirement:         pending.requirement,
		ResourceToken:       pending.resourceToken,
		AgentProvider:       pending.agentProvider,
		Agent:               pending.agent,
		CredentialKey:       pending.tokenKey,
		CredentialExpiresAt: pending.tokenExpiresAt,
		ParentMediated:      pending.parentMediated,
	}
	if pending.interactionCapable {
		snapshot.Capabilities = append(snapshot.Capabilities, "interaction")
	}
	if pending.clarificationCapable {
		snapshot.Capabilities = append(snapshot.Capabilities, "clarification")
	}
	if pending.requirement == aauth.RequirementInteraction {
		snapshot.InteractionURL = pending.interactionURL
		snapshot.InteractionCode = pending.interactionCode
	}
	if pending.requirement == aauth.RequirementClarification {
		snapshot.Clarification = pending.clarification.question
		if pending.clarification.hasTimeout {
			seconds := int64(pending.clarification.timeout / time.Second)
			answerBefore := pending.clarification.answerBefore
			snapshot.ClarificationTimeoutSeconds = &seconds
			snapshot.ClarificationAnswerBefore = &answerBefore
		}
		if pending.clarification.options != nil {
			snapshot.ClarificationOptions = slices.Clone(pending.clarification.options.values)
		}
	}
	return snapshot, nil
}

// RestorePendingExchange re-verifies a serialized continuation against the
// current Agent identity, key, Person Server metadata, resolver, and clock. It
// sends no continuation or application request. Metadata and configured key
// resolution may perform read-only discovery.
func (client *Client) RestorePendingExchange(ctx context.Context, snapshot PendingExchangeSnapshot) (PendingExchange, error) {
	const operation = "restore pending exchange"
	if client == nil {
		return PendingExchange{}, fail(operation, errors.New("client is required"))
	}
	if ctx == nil {
		return PendingExchange{}, fail(operation, errors.New("context is required"))
	}
	if err := ctx.Err(); err != nil {
		return PendingExchange{}, fail(operation, err)
	}
	if err := client.requireDirectPersonServerCaller(); err != nil {
		return PendingExchange{}, fail(operation, err)
	}
	currentAgent, err := aauth.VerifyAgentToken(ctx, client.agentToken, client.keyResolver, client.clock)
	if err != nil {
		return PendingExchange{}, fail(operation, fmt.Errorf("verify current Agent token: %w", err))
	}
	if currentAgent.Subject != client.identifier || !currentAgent.Confirmation.JWK.Equal(client.signingKey.PublicJWK()) {
		return PendingExchange{}, fail(operation, errors.New("current Agent token does not match client identity and key"))
	}
	if snapshot.PersonServer == "" || snapshot.Location == "" ||
		snapshot.ResourceToken == "" || snapshot.AgentProvider == "" || snapshot.Agent == "" ||
		snapshot.CredentialExpiresAt <= 0 {
		return PendingExchange{}, fail(operation, errors.New("snapshot is incomplete"))
	}
	if snapshot.RetryAfterSeconds < 0 || snapshot.RetryAfterSeconds > int64(math.MaxInt64/time.Second) {
		return PendingExchange{}, fail(operation, errors.New("snapshot retry interval is invalid"))
	}
	if err := aauth.ValidateServerIdentifier(snapshot.PersonServer); err != nil {
		return PendingExchange{}, fail(operation, fmt.Errorf("person server: %w", err))
	}
	if snapshot.AgentProvider != currentAgent.Issuer || snapshot.Agent != currentAgent.Subject ||
		snapshot.PersonServer != currentAgent.PersonServer {
		return PendingExchange{}, fail(operation, errors.New("snapshot does not match current Agent identity and Person Server"))
	}
	if snapshot.ParentMediated {
		if snapshot.CredentialKey.Equal(client.signingKey.PublicJWK()) {
			return PendingExchange{}, fail(operation, errors.New("parent-mediated snapshot uses the parent key as credential recipient"))
		}
	} else if !snapshot.CredentialKey.Equal(client.signingKey.PublicJWK()) {
		return PendingExchange{}, fail(operation, errors.New("snapshot does not match current Agent key"))
	}
	if len(snapshot.Capabilities) > 0 {
		if _, err := aauth.FormatCapabilities(snapshot.Capabilities); err != nil {
			return PendingExchange{}, fail(operation, fmt.Errorf("capabilities: %w", err))
		}
	}
	interactionCapable := false
	clarificationCapable := false
	for _, capability := range snapshot.Capabilities {
		switch capability {
		case "interaction":
			interactionCapable = true
		case "clarification":
			clarificationCapable = true
		default:
			return PendingExchange{}, fail(operation, fmt.Errorf("snapshot contains unrelated capability %q", capability))
		}
	}

	claims, err := aauth.VerifyResourceToken(ctx, snapshot.ResourceToken, client.keyResolver, client.clock)
	if err != nil {
		return PendingExchange{}, fail(operation, fmt.Errorf("verify Resource token: %w", err))
	}
	thumbprint, err := client.signingKey.PublicJWK().Thumbprint()
	if err != nil {
		return PendingExchange{}, fail(operation, err)
	}
	credentialThumbprint, err := snapshot.CredentialKey.Thumbprint()
	if err != nil {
		return PendingExchange{}, fail(operation, errors.New("snapshot credential key is invalid"))
	}
	if claims.PersonServer != snapshot.PersonServer || claims.AgentJKT != credentialThumbprint {
		return PendingExchange{}, fail(operation, errors.New("Resource token does not match current Person Server and credential key"))
	}
	if snapshot.CredentialExpiresAt < claims.ExpiresAt {
		return PendingExchange{}, fail(operation, errors.New("snapshot credential lifetime is invalid"))
	}
	credentialExpiresAt := snapshot.CredentialExpiresAt
	if currentAgent.ExpiresAt < credentialExpiresAt {
		credentialExpiresAt = currentAgent.ExpiresAt
	}
	if claims.Account != nil {
		return PendingExchange{}, fail(operation, errors.New("Resource token is outside the direct pending-exchange profile"))
	}
	metadata, err := client.personServerMetadata(ctx, snapshot.PersonServer)
	if err != nil {
		return PendingExchange{}, fail(operation, err)
	}
	authTokenEndpoint, err := url.Parse(metadata.AuthTokenEndpoint)
	if err != nil {
		return PendingExchange{}, fail(operation, errors.New("Person Server auth-token endpoint is invalid"))
	}
	verifiedOrigin, err := httpOrigin(authTokenEndpoint)
	if err != nil {
		return PendingExchange{}, fail(operation, errors.New("Person Server auth-token endpoint origin is invalid"))
	}

	pending := PendingExchange{
		kind:                 pendingExchangeVerified,
		personServer:         snapshot.PersonServer,
		location:             snapshot.Location,
		origin:               verifiedOrigin,
		retryAfter:           time.Duration(snapshot.RetryAfterSeconds) * time.Second,
		interactionURL:       snapshot.InteractionURL,
		interactionCode:      snapshot.InteractionCode,
		interacting:          snapshot.Interacting,
		requirement:          snapshot.Requirement,
		interactionCapable:   interactionCapable,
		clarificationCapable: clarificationCapable,
		resourceToken:        snapshot.ResourceToken,
		resourceClaims:       &claims,
		agentProvider:        snapshot.AgentProvider,
		agent:                snapshot.Agent,
		agentJKT:             thumbprint,
		tokenKey:             snapshot.CredentialKey,
		tokenExpiresAt:       credentialExpiresAt,
		tokenExpirySource:    "restored exchange credential",
		parentMediated:       snapshot.ParentMediated,
	}
	if snapshot.Clarification != "" || snapshot.ClarificationTimeoutSeconds != nil ||
		snapshot.ClarificationAnswerBefore != nil || snapshot.ClarificationOptions != nil {
		pending.clarification = ClarificationQuestion{
			kind:     clarificationQuestionValidated,
			question: snapshot.Clarification,
		}
		if snapshot.ClarificationTimeoutSeconds != nil {
			seconds := *snapshot.ClarificationTimeoutSeconds
			if seconds < 0 || seconds > int64(math.MaxInt64/time.Second) ||
				snapshot.ClarificationAnswerBefore == nil || snapshot.ClarificationAnswerBefore.IsZero() {
				return PendingExchange{}, fail(operation, errors.New("snapshot clarification timeout is invalid"))
			}
			pending.clarification.timeout = time.Duration(seconds) * time.Second
			pending.clarification.hasTimeout = true
			pending.clarification.answerBefore = *snapshot.ClarificationAnswerBefore
		} else if snapshot.ClarificationAnswerBefore != nil {
			return PendingExchange{}, fail(operation, errors.New("snapshot clarification answer deadline requires a timeout"))
		}
		if snapshot.ClarificationOptions != nil {
			pending.clarification.options = &clarificationQuestionOptions{values: slices.Clone(snapshot.ClarificationOptions)}
		}
	}
	if err := client.validatePendingExchange(ctx, pending); err != nil {
		return PendingExchange{}, fail(operation, err)
	}
	return pending, nil
}

// AnswerClarification performs exactly one Agent-token-signed JSON POST to a
// verified pending clarification. It does not poll or retry.
func (client *Client) AnswerClarification(ctx context.Context, pending PendingExchange, markdown string) error {
	const operation = "answer clarification"
	if client == nil {
		return fail(operation, errors.New("client is required"))
	}
	if strings.TrimSpace(markdown) == "" {
		return fail(operation, errors.New("clarification response is required"))
	}
	if len(markdown) > maxClarificationResponseBytes {
		return fail(operation, fmt.Errorf("clarification response exceeds %d bytes", maxClarificationResponseBytes))
	}
	if err := client.validatePendingExchange(ctx, pending); err != nil {
		return fail(operation, err)
	}
	if pending.requirement != aauth.RequirementClarification {
		return fail(operation, errors.New("pending clarification is required"))
	}
	if pending.clarification.hasTimeout && !client.clock.Now().Before(pending.clarification.answerBefore) {
		return fail(operation, errors.New("clarification answer deadline has passed"))
	}
	body, err := json.Marshal(struct {
		Action                string `json:"action"`
		ClarificationResponse string `json:"clarification_response"`
	}{Action: "clarification_response", ClarificationResponse: markdown})
	if err != nil {
		return fail(operation, err)
	}
	request, err := newJSONRequest(ctx, pending.location, body)
	if err != nil {
		return fail(operation, err)
	}
	if err := client.signJSONRequest(request, client.agentToken); err != nil {
		return fail(operation, err)
	}
	if err := client.performClarificationAction(request); err != nil {
		return fail(operation, err)
	}
	return nil
}

// CancelClarification performs exactly one bodyless Agent-token-signed DELETE
// for an active clarification. It does not poll or retry.
func (client *Client) CancelClarification(ctx context.Context, pending PendingExchange) error {
	const operation = "cancel clarification"
	if client == nil {
		return fail(operation, errors.New("client is required"))
	}
	if err := client.validatePendingExchange(ctx, pending); err != nil {
		return fail(operation, err)
	}
	if pending.requirement != aauth.RequirementClarification {
		return fail(operation, errors.New("pending clarification is required"))
	}
	if pending.clarification.hasTimeout && !client.clock.Now().Before(pending.clarification.answerBefore) {
		return fail(operation, errors.New("clarification response deadline has passed"))
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodDelete, pending.location, nil)
	if err != nil {
		return fail(operation, err)
	}
	if err := signaturekey.SignJWTRequest(request, client.signingKey, client.agentToken, client.clock); err != nil {
		return fail(operation, err)
	}
	if err := client.performClarificationAction(request); err != nil {
		return fail(operation, err)
	}
	return nil
}

// CancelExchange performs exactly one bodyless Agent-token-signed DELETE for a
// verified pending exchange, such as an Access Server approval or payment
// wait. A 2xx answer means the Person Server closed the continuation; later
// polls are 410. It does not poll or retry.
func (client *Client) CancelExchange(ctx context.Context, pending PendingExchange) error {
	const operation = "cancel exchange"
	if client == nil {
		return fail(operation, errors.New("client is required"))
	}
	if err := client.validatePendingExchange(ctx, pending); err != nil {
		return fail(operation, err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodDelete, pending.location, nil)
	if err != nil {
		return fail(operation, err)
	}
	if err := signaturekey.SignJWTRequest(request, client.signingKey, client.agentToken, client.clock); err != nil {
		return fail(operation, err)
	}
	if err := client.performClarificationAction(request); err != nil {
		return fail(operation, err)
	}
	return nil
}

func (client *Client) performClarificationAction(request *http.Request) error {
	response, err := client.httpClient.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return responseFailure(response)
	}
	return nil
}

func (client *Client) parseClarification(encoded json.RawMessage, observedAt time.Time) (ClarificationQuestion, error) {
	var body struct {
		Clarification json.RawMessage `json:"clarification"`
		Timeout       json.RawMessage `json:"timeout"`
		Options       json.RawMessage `json:"options"`
	}
	if err := decodePendingExchangeBody(encoded, &body); err != nil {
		return ClarificationQuestion{}, err
	}
	var question string
	if len(body.Clarification) == 0 || string(body.Clarification) == "null" ||
		json.Unmarshal(body.Clarification, &question) != nil || strings.TrimSpace(question) == "" {
		return ClarificationQuestion{}, errors.New("pending clarification is required and must be a string")
	}
	clarification := ClarificationQuestion{kind: clarificationQuestionValidated, question: question}
	if len(body.Timeout) > 0 {
		var timeout int64
		if string(body.Timeout) == "null" || json.Unmarshal(body.Timeout, &timeout) != nil {
			return ClarificationQuestion{}, errors.New("pending clarification timeout must be an integer")
		}
		if timeout < 0 {
			return ClarificationQuestion{}, errors.New("pending clarification timeout must be nonnegative")
		}
		if timeout > int64(math.MaxInt64/time.Second) {
			return ClarificationQuestion{}, errors.New("pending clarification timeout overflows")
		}
		clarification.timeout = time.Duration(timeout) * time.Second
		clarification.hasTimeout = true
		clarification.answerBefore = observedAt.Add(clarification.timeout)
	}
	if len(body.Options) > 0 {
		var options []string
		if string(body.Options) == "null" || json.Unmarshal(body.Options, &options) != nil {
			return ClarificationQuestion{}, errors.New("pending clarification options must be a string array")
		}
		clarification.options = &clarificationQuestionOptions{values: slices.Clone(options)}
	}
	return clarification, nil
}

func validatePendingExchangeLocation(pending PendingExchange) error {
	if pending.location == "" || pending.origin == "" {
		return errors.New("pending exchange Location and origin are required")
	}
	target, err := url.Parse(pending.location)
	if err != nil || !target.IsAbs() || target.Fragment != "" || target.User != nil {
		return errors.New("pending exchange Location must be an absolute HTTPS URL without userinfo or fragment")
	}
	origin, err := httpOrigin(target)
	if err != nil || origin != pending.origin {
		return errors.New("pending exchange Location must remain on its verified origin")
	}
	originURL, err := url.Parse(pending.origin)
	if err != nil || originURL.Path != "" || originURL.RawQuery != "" || originURL.Fragment != "" || originURL.User != nil {
		return errors.New("pending exchange origin is invalid")
	}
	canonical, err := httpOrigin(originURL)
	if err != nil || canonical != pending.origin {
		return errors.New("pending exchange origin is not canonical")
	}
	return nil
}

func validatePendingExchangeRequirement(pending PendingExchange) error {
	switch pending.requirement {
	case aauth.RequirementInteraction:
		if !pending.interactionCapable {
			return errors.New("pending interaction requires the declared interaction capability")
		}
		if pending.interactionURL == "" || pending.interactionCode == "" {
			return errors.New("pending interaction URL and code are required")
		}
		if pending.clarification.kind != 0 {
			return errors.New("pending interaction must not carry a clarification")
		}
	case aauth.RequirementClarification:
		if !pending.clarificationCapable {
			return errors.New("pending clarification requires the declared clarification capability")
		}
		if pending.clarification.kind != clarificationQuestionValidated || strings.TrimSpace(pending.clarification.question) == "" {
			return errors.New("pending clarification question is required")
		}
		if pending.interactionURL != "" || pending.interactionCode != "" {
			return errors.New("pending clarification must not carry interaction fields")
		}
		if pending.clarification.hasTimeout != !pending.clarification.answerBefore.IsZero() {
			return errors.New("pending clarification timeout and answer deadline must appear together")
		}
	case "", aauth.RequirementApproval:
		if pending.interactionURL != "" || pending.interactionCode != "" {
			return errors.New("non-interaction pending exchange must not carry interaction fields")
		}
		if pending.clarification.kind != 0 {
			return errors.New("non-clarification pending exchange must not carry a clarification")
		}
	default:
		if pending.interactionURL != "" || pending.interactionCode != "" || pending.clarification.kind != 0 {
			return errors.New("unsupported pending requirement must not carry a supported action shape")
		}
	}
	return nil
}
