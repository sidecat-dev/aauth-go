package supervision

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/internal/httpapi"
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

// DefaultWait is the Prefer: wait a Client sends on every supervision request
// and connect when ClientConfig.Wait is zero. The draft RECOMMENDS 30
// seconds, so an SS that decides within it never holds a pending record.
const DefaultWait = 30 * time.Second

const (
	metadataFreshness = 5 * time.Minute
	defaultRetryAfter = 5 * time.Second
	maximumRetryAfter = time.Hour
)

// ClientConfig supplies a Person Server's identity, keys and egress policy.
// The Client signs as PersonServer under the jwks_uri scheme with the Person
// Server metadata document, and verifies signed decisions with KeyResolver.
// Admit decides, before each request, whether a metadata, endpoint or pending
// URL may be contacted: the person names the SS, and anyone can run one.
type ClientConfig struct {
	PersonServer string
	SigningKey   jose.SigningKey
	KeyResolver  signaturekey.KeyResolver
	HTTPClient   *http.Client
	Admit        signaturekey.EgressAdmitter
	Clock        aauth.Clock
	// Wait is sent as Prefer: wait on supervision requests, their polls,
	// connect and its polls. Zero selects DefaultWait; it is rounded up to
	// whole seconds.
	Wait time.Duration
}

// Client makes a Person Server's signed requests to supervision servers. Each
// method sends one request and never sleeps or retries. Methods return an
// error only when no usable answer arrived: a transport failure, a malformed
// response, or a decision whose signature fails; the Person Server then
// treats the SS as unavailable for the act. An error response the draft
// defines is returned as Outcome.Problem with a nil error, so the caller can
// connect, replay or wait as it directs.
type Client struct {
	personServer string
	signingKey   jose.SigningKey
	keyResolver  signaturekey.KeyResolver
	httpClient   *http.Client
	admit        signaturekey.EgressAdmitter
	clock        aauth.Clock
	wait         time.Duration

	mu       sync.Mutex
	metadata map[string]cachedMetadata
}

type cachedMetadata struct {
	metadata  Metadata
	fetchedAt time.Time
}

// NewClient validates config and returns a Client over a copy of its HTTP
// client that follows no redirect and sends no cookies.
func NewClient(config ClientConfig) (*Client, error) {
	if err := aauth.ValidateServerIdentifier(config.PersonServer); err != nil {
		return nil, fmt.Errorf("supervision: person server: %w", err)
	}
	if _, err := config.SigningKey.PublicJWK().PublicKey(); err != nil {
		return nil, fmt.Errorf("supervision: signing key: %w", err)
	}
	if config.KeyResolver == nil {
		return nil, errors.New("supervision: key resolver is required")
	}
	if config.HTTPClient == nil {
		return nil, errors.New("supervision: HTTP client is required")
	}
	if config.Admit == nil {
		return nil, errors.New("supervision: egress admitter is required")
	}
	if config.Clock == nil {
		return nil, errors.New("supervision: clock is required")
	}
	if config.Wait < 0 {
		return nil, errors.New("supervision: wait must not be negative")
	}
	wait := config.Wait
	if wait == 0 {
		wait = DefaultWait
	}
	httpClient := *config.HTTPClient
	httpClient.Jar = nil
	httpClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &Client{
		personServer: config.PersonServer, signingKey: config.SigningKey, keyResolver: config.KeyResolver,
		httpClient: &httpClient, admit: config.Admit, clock: config.Clock, wait: wait,
		metadata: make(map[string]cachedMetadata),
	}, nil
}

// Problem is an error response from an SS. RetryAfter is set for
// rate_limited.
type Problem struct {
	Status     int
	Code       ErrorCode
	Detail     string
	RetryAfter time.Duration
}

// PendingAnswer is a 202 from an SS: the pending URL to poll, the interval,
// and a clarification when the SS asks the Agent a question.
type PendingAnswer struct {
	Location      string
	RetryAfter    time.Duration
	Clarification *Clarification
}

// ConnectInteraction is a connect the SS completes only after the person
// confirms the Person Server at {URL}?code={Code}. The Person Server polls
// Location until the SS answers 200. A poll answered 202 without a
// requirement, as once the person has reached the interaction page, is
// Outcome.Pending instead: keep polling.
type ConnectInteraction struct {
	URL        string
	Code       string
	Location   string
	RetryAfter time.Duration
}

// Outcome is one SS answer. Exactly one of Decision, Pending, Connected,
// Interaction, Accepted or Problem describes it. Exchange is the request as
// signed and the response as received.
type Outcome struct {
	Decision    *Decision
	Pending     *PendingAnswer
	Connected   bool
	Interaction *ConnectInteraction
	// Accepted reports a 201 to an event or report, or a 200 or 204 to a
	// cancellation.
	Accepted bool
	Problem  *Problem
	Exchange Exchange
}

// Metadata returns the supervisor's metadata, fetched under the egress rules
// and cached for five minutes.
func (client *Client) Metadata(ctx context.Context, supervisor string) (Metadata, error) {
	if err := aauth.ValidateServerIdentifier(supervisor); err != nil {
		return Metadata{}, fmt.Errorf("supervision: supervisor: %w", err)
	}
	now := client.clock.Now()
	client.mu.Lock()
	cached, ok := client.metadata[supervisor]
	client.mu.Unlock()
	if ok && now.Sub(cached.fetchedAt) < metadataFreshness && !now.Before(cached.fetchedAt) {
		return cached.metadata, nil
	}
	location := supervisor + "/.well-known/" + DiscoveryDocument
	if err := client.admit(ctx, location); err != nil {
		return Metadata{}, fmt.Errorf("supervision: metadata egress admission: %w", err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, location, nil)
	if err != nil {
		return Metadata{}, err
	}
	response, err := client.httpClient.Do(request)
	if err != nil {
		return Metadata{}, fmt.Errorf("supervision: fetch metadata: %w", err)
	}
	defer response.Body.Close()
	body, err := readBody(response)
	if err != nil {
		return Metadata{}, err
	}
	if response.StatusCode != http.StatusOK {
		return Metadata{}, fmt.Errorf("supervision: metadata returned %d", response.StatusCode)
	}
	metadata, err := DecodeMetadata(body, supervisor)
	if err != nil {
		return Metadata{}, err
	}
	client.mu.Lock()
	client.metadata[supervisor] = cachedMetadata{metadata: metadata, fetchedAt: now}
	client.mu.Unlock()
	return metadata, nil
}

// Connect posts a connect or disconnect to the supervisor's connect_endpoint.
// A 200 is Connected; a 202 with requirement=interaction is Interaction.
func (client *Client) Connect(ctx context.Context, supervisor string, request ConnectRequest) (Outcome, error) {
	metadata, err := client.Metadata(ctx, supervisor)
	if err != nil {
		return Outcome{}, err
	}
	body, err := request.Encode()
	if err != nil {
		return Outcome{}, err
	}
	wait := request.Action == ActionConnect
	outcome, response, err := client.send(ctx, supervisor, http.MethodPost, metadata.ConnectEndpoint, body, wait, "")
	if err != nil {
		return outcome, err
	}
	return client.connectAnswer(outcome, response, metadata.ConnectEndpoint)
}

// PollConnect polls a connect that waits for the person, with a signed GET.
func (client *Client) PollConnect(ctx context.Context, supervisor, location string) (Outcome, error) {
	metadata, err := client.Metadata(ctx, supervisor)
	if err != nil {
		return Outcome{}, err
	}
	outcome, response, err := client.send(ctx, supervisor, http.MethodGet, location, nil, true, "")
	if err != nil {
		return outcome, err
	}
	return client.connectAnswer(outcome, response, metadata.ConnectEndpoint)
}

func (client *Client) connectAnswer(outcome Outcome, response *RecordedResponse, endpoint string) (Outcome, error) {
	switch response.Status {
	case http.StatusOK:
		outcome.Connected = true
		return outcome, nil
	case http.StatusAccepted:
		location, retryAfter, err := pendingLocation(response, endpoint, client.clock.Now())
		if err != nil {
			return outcome, err
		}
		if len(response.Header.Values("AAuth-Requirement")) == 0 {
			outcome.Pending = &PendingAnswer{Location: location, RetryAfter: retryAfter}
			return outcome, nil
		}
		interaction, err := aauth.ParseInteractionRequirement(response.Header.Values("AAuth-Requirement"))
		if err != nil {
			return outcome, fmt.Errorf("supervision: connect interaction: %w", err)
		}
		outcome.Interaction = &ConnectInteraction{
			URL: interaction.URL, Code: interaction.Code, Location: location, RetryAfter: retryAfter,
		}
		return outcome, nil
	}
	return client.problemAnswer(outcome, response)
}

// Supervise puts one act to the supervisor: a POST to mission_endpoint, to
// {mission_endpoint}/{s256}, or to decision_endpoint, with Prefer: wait and
// Accept-Signature. A decision must echo the request's sdi and, from an SS
// that publishes a jwks_uri, carry a signature that verifies.
func (client *Client) Supervise(ctx context.Context, supervisor string, request Request) (Outcome, error) {
	metadata, err := client.Metadata(ctx, supervisor)
	if err != nil {
		return Outcome{}, err
	}
	body, err := request.Encode()
	if err != nil {
		return Outcome{}, err
	}
	endpoint := metadata.DecisionEndpoint
	if request.Kind.MissionEndpoint() {
		endpoint = metadata.MissionEndpoint + request.Path()
	}
	outcome, response, err := client.send(ctx, supervisor, http.MethodPost, endpoint, body, true, AcceptSignature(true))
	if err != nil {
		return outcome, err
	}
	return client.supervisionAnswer(ctx, outcome, response, metadata, request, endpoint)
}

// Poll fetches an SS pending URL with a signed, bodyless GET under the same
// identity that made request, with Prefer: wait.
func (client *Client) Poll(ctx context.Context, supervisor string, request Request, location string) (Outcome, error) {
	metadata, err := client.Metadata(ctx, supervisor)
	if err != nil {
		return Outcome{}, err
	}
	outcome, response, err := client.send(ctx, supervisor, http.MethodGet, location, nil, true, AcceptSignature(false))
	if err != nil {
		return outcome, err
	}
	return client.supervisionAnswer(ctx, outcome, response, metadata, request, location)
}

// AnswerClarification relays the Agent's answer to an SS clarification with a
// signed POST to the pending URL. The SS answers it as it answers a poll.
func (client *Client) AnswerClarification(ctx context.Context, supervisor string, request Request, location, answer string) (Outcome, error) {
	metadata, err := client.Metadata(ctx, supervisor)
	if err != nil {
		return Outcome{}, err
	}
	body, err := ClarificationResponse{Answer: answer}.Encode()
	if err != nil {
		return Outcome{}, err
	}
	outcome, response, err := client.send(ctx, supervisor, http.MethodPost, location, body, false, AcceptSignature(true))
	if err != nil {
		return outcome, err
	}
	return client.supervisionAnswer(ctx, outcome, response, metadata, request, location)
}

// Cancel withdraws a pending supervision request with a signed DELETE, as
// when the Agent cancels.
func (client *Client) Cancel(ctx context.Context, supervisor, location string) (Outcome, error) {
	outcome, response, err := client.send(ctx, supervisor, http.MethodDelete, location, nil, false, "")
	if err != nil {
		return outcome, err
	}
	switch response.Status {
	case http.StatusOK, http.StatusNoContent, http.StatusGone:
		outcome.Accepted = true
		return outcome, nil
	}
	return client.problemAnswer(outcome, response)
}

// PostEvent reports one event to event_endpoint. 201 is Accepted.
func (client *Client) PostEvent(ctx context.Context, supervisor string, event Event) (Outcome, error) {
	metadata, err := client.Metadata(ctx, supervisor)
	if err != nil {
		return Outcome{}, err
	}
	body, err := event.Encode()
	if err != nil {
		return Outcome{}, err
	}
	return client.report(ctx, supervisor, metadata.EventEndpoint, body)
}

// PostReport reports a mission approval or termination to
// {mission_endpoint}/{s256}. 201 is Accepted.
func (client *Client) PostReport(ctx context.Context, supervisor string, report Report) (Outcome, error) {
	metadata, err := client.Metadata(ctx, supervisor)
	if err != nil {
		return Outcome{}, err
	}
	body, err := report.Encode()
	if err != nil {
		return Outcome{}, err
	}
	return client.report(ctx, supervisor, metadata.MissionEndpoint+report.Path(), body)
}

// report posts an event or report. Any 2xx is delivery; the draft answers
// 201.
func (client *Client) report(ctx context.Context, supervisor, endpoint string, body []byte) (Outcome, error) {
	outcome, response, err := client.send(ctx, supervisor, http.MethodPost, endpoint, body, false, "")
	if err != nil {
		return outcome, err
	}
	if response.Status >= 200 && response.Status < 300 {
		outcome.Accepted = true
		return outcome, nil
	}
	return client.problemAnswer(outcome, response)
}

func (client *Client) supervisionAnswer(
	ctx context.Context,
	outcome Outcome,
	response *RecordedResponse,
	metadata Metadata,
	request Request,
	endpoint string,
) (Outcome, error) {
	switch response.Status {
	case http.StatusOK:
		if err := requireJSON(response.Header); err != nil {
			return outcome, err
		}
		decision, err := DecodeDecision(request.Kind, response.Body)
		if err != nil {
			return outcome, err
		}
		if decision.SDI != request.SDI {
			return outcome, errors.New("supervision: decision does not echo the request's sdi")
		}
		signed := len(response.Header.Values("Signature")) > 0 || len(response.Header.Values("Signature-Input")) > 0
		if metadata.Signs() && !signed {
			return outcome, errors.New("supervision: an SS that publishes jwks_uri sent an unsigned decision")
		}
		if signed {
			httpRequest, err := outcome.Exchange.Request.httpRequest(ctx)
			if err != nil {
				return outcome, err
			}
			if _, err := VerifyDecision(ctx, response.Status, response.Header, response.Body, httpRequest,
				metadata.Issuer, client.keyResolver, client.clock); err != nil {
				return outcome, err
			}
			outcome.Exchange.Signed = true
		}
		outcome.Decision = &decision
		return outcome, nil
	case http.StatusAccepted:
		location, retryAfter, err := pendingLocation(response, endpoint, client.clock.Now())
		if err != nil {
			return outcome, err
		}
		clarifying := false
		if values := response.Header.Values("AAuth-Requirement"); len(values) > 0 {
			requirement, err := aauth.ParseRequirement(values)
			if err != nil {
				return outcome, fmt.Errorf("supervision: pending requirement: %w", err)
			}
			switch requirement {
			case aauth.RequirementClarification:
				clarifying = true
			case aauth.RequirementApproval:
			default:
				return outcome, fmt.Errorf("supervision: a supervision request cannot require %s", requirement)
			}
		}
		if err := requireJSON(response.Header); err != nil {
			return outcome, err
		}
		sdi, clarification, err := decodePending(response.Body, clarifying)
		if err != nil {
			return outcome, err
		}
		if sdi != "" && sdi != request.SDI {
			return outcome, errors.New("supervision: pending response does not echo the request's sdi")
		}
		outcome.Pending = &PendingAnswer{Location: location, RetryAfter: retryAfter, Clarification: clarification}
		return outcome, nil
	}
	return client.problemAnswer(outcome, response)
}

// problemAnswer reads an error response. A status or error the draft does
// not define is server_error. rate_limited without a usable Retry-After is
// also server_error.
func (client *Client) problemAnswer(outcome Outcome, response *RecordedResponse) (Outcome, error) {
	problem := &Problem{Status: response.Status, Code: ErrorServerError}
	if decoded, err := aauth.DecodeProblemResponse(&http.Response{
		StatusCode: response.Status, Header: response.Header, Body: io.NopCloser(bytes.NewReader(response.Body)),
	}); err == nil {
		problem.Detail = decoded.Detail
		code := ErrorCode(decoded.Code)
		if code.Status() == response.Status {
			switch code {
			case ErrorInvalidRequest, ErrorUnsupportedIss, ErrorUnknownSub, ErrorUnknownMission,
				ErrorUnknownPending, ErrorRateLimited, ErrorServerError:
				problem.Code = code
			}
		}
	}
	if problem.Code == ErrorRateLimited {
		retryAfter, ok := httpapi.ParseRetryAfter(response.Header.Values("Retry-After"), client.clock.Now())
		if !ok {
			problem.Code = ErrorServerError
		} else {
			problem.RetryAfter = retryAfter
		}
	}
	outcome.Problem = problem
	return outcome, nil
}

// send signs and sends one request and records the exchange. A body is
// signed with content-type and content-digest covered.
func (client *Client) send(
	ctx context.Context,
	supervisor, method, endpoint string,
	body []byte,
	preferWait bool,
	acceptSignature string,
) (Outcome, *RecordedResponse, error) {
	var outcome Outcome
	outcome.Exchange.Supervisor = supervisor
	if err := aauth.ValidateEndpoint(endpoint); err != nil {
		return outcome, nil, fmt.Errorf("supervision: endpoint: %w", err)
	}
	if err := client.admit(ctx, endpoint); err != nil {
		return outcome, nil, fmt.Errorf("supervision: egress admission for %q: %w", endpoint, err)
	}
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	request, err := http.NewRequestWithContext(ctx, method, endpoint, reader)
	if err != nil {
		return outcome, nil, err
	}
	if preferWait {
		seconds := int64((client.wait + time.Second - 1) / time.Second)
		request.Header.Set("Prefer", "wait="+strconv.FormatInt(seconds, 10))
	}
	if acceptSignature != "" {
		request.Header.Set("Accept-Signature", acceptSignature)
	}
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
		err = signaturekey.SignJWKSURIRequestWithOptions(
			request, client.signingKey, client.personServer, aauth.PersonDiscoveryDocument, client.clock,
			signaturekey.SignOptions{AdditionalComponents: []string{"content-type", "content-digest"}, MaxBodyBytes: MaxBodyBytes},
		)
	} else {
		err = signaturekey.SignJWKSURIRequest(request, client.signingKey, client.personServer, aauth.PersonDiscoveryDocument, client.clock)
	}
	if err != nil {
		return outcome, nil, fmt.Errorf("supervision: sign request: %w", err)
	}
	outcome.Exchange.Request = RecordedRequest{
		Method: method, URL: endpoint, Header: request.Header.Clone(), Body: append([]byte(nil), body...),
	}
	outcome.Exchange.SentAt = client.clock.Now().UTC()
	response, err := client.httpClient.Do(request)
	if err != nil {
		return outcome, nil, fmt.Errorf("supervision: %s %s: %w", method, endpoint, err)
	}
	defer response.Body.Close()
	responseBody, err := readBody(response)
	if err != nil {
		return outcome, nil, err
	}
	recorded := &RecordedResponse{Status: response.StatusCode, Header: response.Header.Clone(), Body: responseBody}
	outcome.Exchange.Response = recorded
	outcome.Exchange.ReceivedAt = client.clock.Now().UTC()
	return outcome, recorded, nil
}

func (recorded RecordedRequest) httpRequest(ctx context.Context) (*http.Request, error) {
	request, err := http.NewRequestWithContext(ctx, recorded.Method, recorded.URL, bytes.NewReader(recorded.Body))
	if err != nil {
		return nil, err
	}
	request.Header = recorded.Header.Clone()
	return request, nil
}

func readBody(response *http.Response) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(response.Body, MaxBodyBytes+1))
	if err != nil {
		return nil, fmt.Errorf("supervision: read response: %w", err)
	}
	if len(body) > MaxBodyBytes {
		return nil, errors.New("supervision: response body is too large")
	}
	return body, nil
}

func requireJSON(header http.Header) error {
	media, _, err := mime.ParseMediaType(header.Get("Content-Type"))
	if err != nil || media != "application/json" || len(header.Values("Content-Type")) != 1 {
		return errors.New("supervision: response must be one application/json body")
	}
	return nil
}

// pendingLocation resolves a 202's Location against the URL it answered and
// reads Retry-After, five seconds when absent.
func pendingLocation(response *RecordedResponse, endpoint string, now time.Time) (string, time.Duration, error) {
	if len(response.Header.Values("Location")) != 1 {
		return "", 0, errors.New("supervision: a pending response needs one Location")
	}
	base, err := url.Parse(endpoint)
	if err != nil {
		return "", 0, err
	}
	reference, err := url.Parse(response.Header.Get("Location"))
	if err != nil || reference.String() == "" {
		return "", 0, errors.New("supervision: pending Location is invalid")
	}
	location := base.ResolveReference(reference)
	if location.Scheme != "https" || location.Host != base.Host || location.User != nil || location.Fragment != "" {
		return "", 0, errors.New("supervision: pending Location must be on the answering origin")
	}
	retryAfter := defaultRetryAfter
	if values := response.Header.Values("Retry-After"); len(values) > 0 {
		parsed, ok := httpapi.ParseRetryAfter(values, now)
		if !ok || parsed > maximumRetryAfter {
			return "", 0, errors.New("supervision: pending Retry-After is invalid")
		}
		retryAfter = parsed
	}
	return location.String(), retryAfter, nil
}
