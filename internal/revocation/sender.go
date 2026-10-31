package revocation

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/internal/httpapi"
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

const maximumResponseBytes = 1 << 20

// Target is one revocation a server sends: the token, in the sender's own
// namespace, and the recipient that is to refuse it.
type Target struct {
	// Recipient is the recipient's server identifier.
	Recipient string
	// Metadata is the recipient's metadata document name, such as
	// aauth-resource.json, from which its revocation_endpoint is read.
	Metadata string
	JTI      string
	// ExpiresAt is the revoked token's exp.
	ExpiresAt time.Time
	// Header supplies values for additional signature components a Resource
	// advertises.
	Header http.Header
}

func (target Target) key() string { return target.Recipient + "\x00" + target.JTI }

// Outcome is how one revocation exchange ended. A recipient that answered
// 202, or 429 rate_limited, has not reached a terminal outcome: the
// revocation is pending and is attempted again after RetryAfter.
type Outcome struct {
	Recorded   bool
	Error      aauth.RevocationError
	Pending    bool
	Location   string
	RetryAfter time.Duration
	Downstream []aauth.DownstreamRevocation
	Cause      error

	rateLimited bool
	retryAt     time.Time
}

func unavailable(cause error) Outcome {
	return Outcome{Error: aauth.RevocationUnavailable, Cause: cause}
}

func unsupported(cause error) Outcome {
	return Outcome{Error: aauth.RevocationUnsupported, Cause: cause}
}

// Sender sends signed revocations and polls their pending URLs. It signs as
// the server Issuer under the jwks_uri scheme with its own metadata document.
type Sender struct {
	client     *http.Client
	admit      signaturekey.EgressAdmitter
	signingKey jose.SigningKey
	issuer     string
	document   string
	clock      aauth.Clock
}

// NewSender returns a sender over a copy of client that never follows a
// redirect and sends no cookies. admit decides whether each metadata,
// revocation and pending URL may be contacted.
func NewSender(client *http.Client, admit signaturekey.EgressAdmitter, key jose.SigningKey, issuer, document string, clock aauth.Clock) (*Sender, error) {
	if client == nil {
		return nil, errors.New("revocation HTTP client is required")
	}
	if admit == nil {
		return nil, errors.New("revocation egress admitter is required")
	}
	copied := *client
	copied.Jar = nil
	copied.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &Sender{client: &copied, admit: admit, signingKey: key, issuer: issuer, document: document, clock: clock}, nil
}

// Send discovers the recipient's revocation endpoint and posts one signed
// revocation. wait, when positive, is sent as Prefer: wait.
func (sender *Sender) Send(ctx context.Context, target Target, wait time.Duration) Outcome {
	endpoint, additional, outcome, ok := sender.endpoint(ctx, target)
	if !ok {
		return outcome
	}
	body, err := aauth.EncodeRevocationRequest(aauth.RevocationRequest{
		Reference: aauth.TokenReference{Issuer: sender.issuer, JTI: target.JTI},
		ExpiresAt: target.ExpiresAt,
	})
	if err != nil {
		return unavailable(fmt.Errorf("encode revocation: %w", err))
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return unavailable(fmt.Errorf("create revocation request: %w", err))
	}
	request.Header.Set("Content-Type", "application/json")
	components, err := revocationComponents(additional, target.Header, request.Header)
	if err != nil {
		return unavailable(err)
	}
	setWait(request, wait)
	if err := signaturekey.SignJWKSURIRequestWithOptions(request, sender.signingKey, sender.issuer, sender.document, sender.clock,
		signaturekey.SignOptions{AdditionalComponents: components, MaxBodyBytes: maximumResponseBytes}); err != nil {
		return unavailable(fmt.Errorf("sign revocation: %w", err))
	}
	return sender.exchange(request)
}

// Poll fetches a pending revocation URL with a signed, bodyless GET under the
// identity that made the revocation.
func (sender *Sender) Poll(ctx context.Context, location string, wait time.Duration) Outcome {
	if err := sender.admit(ctx, location); err != nil {
		return unavailable(fmt.Errorf("pending revocation egress admission failed for %q: %w", location, err))
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, location, nil)
	if err != nil {
		return unavailable(fmt.Errorf("create pending revocation poll: %w", err))
	}
	setWait(request, wait)
	if err := signaturekey.SignJWKSURIRequest(request, sender.signingKey, sender.issuer, sender.document, sender.clock); err != nil {
		return unavailable(fmt.Errorf("sign pending revocation poll: %w", err))
	}
	outcome := sender.exchange(request)
	if outcome.Pending && outcome.Location != location {
		return unavailable(errors.New("pending revocation URL changed while polling"))
	}
	return outcome
}

func (sender *Sender) endpoint(ctx context.Context, target Target) (string, []string, Outcome, bool) {
	if err := aauth.ValidateServerIdentifier(target.Recipient); err != nil {
		return "", nil, unavailable(fmt.Errorf("revocation recipient: %w", err)), false
	}
	metadataURL := target.Recipient + "/.well-known/" + target.Metadata
	if err := sender.admit(ctx, metadataURL); err != nil {
		return "", nil, unavailable(fmt.Errorf("metadata egress admission failed for %q: %w", metadataURL, err)), false
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, metadataURL, nil)
	if err != nil {
		return "", nil, unavailable(fmt.Errorf("create metadata request: %w", err)), false
	}
	response, err := sender.client.Do(request)
	if err != nil {
		return "", nil, unavailable(fmt.Errorf("fetch %s metadata: %w", target.Recipient, err)), false
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, maximumResponseBytes))
		return "", nil, unavailable(fmt.Errorf("%s metadata returned %s", target.Recipient, response.Status)), false
	}
	var metadata struct {
		Issuer                        string   `json:"issuer"`
		RevocationEndpoint            string   `json:"revocation_endpoint"`
		AdditionalSignatureComponents []string `json:"additional_signature_components"`
	}
	if err := httpapi.DecodeJSON(response.Body, maximumResponseBytes, &metadata); err != nil {
		return "", nil, unavailable(fmt.Errorf("decode %s metadata: %w", target.Recipient, err)), false
	}
	if metadata.Issuer != target.Recipient {
		return "", nil, unavailable(errors.New("metadata issuer does not match the revocation recipient")), false
	}
	if metadata.RevocationEndpoint == "" {
		return "", nil, unsupported(errors.New("recipient publishes no revocation_endpoint")), false
	}
	if err := aauth.ValidateEndpoint(metadata.RevocationEndpoint); err != nil {
		return "", nil, unavailable(fmt.Errorf("metadata revocation_endpoint: %w", err)), false
	}
	if err := sender.admit(ctx, metadata.RevocationEndpoint); err != nil {
		return "", nil, unavailable(fmt.Errorf("revocation egress admission failed for %q: %w", metadata.RevocationEndpoint, err)), false
	}
	var additional []string
	if target.Metadata == aauth.ResourceDiscoveryDocument {
		additional = append(additional, metadata.AdditionalSignatureComponents...)
	}
	return metadata.RevocationEndpoint, additional, Outcome{}, true
}

func (sender *Sender) exchange(request *http.Request) Outcome {
	response, err := sender.client.Do(request)
	if err != nil {
		return unavailable(fmt.Errorf("revoke at %s: %w", request.URL.Host, err))
	}
	defer response.Body.Close()
	switch response.StatusCode {
	case http.StatusOK:
		downstream, err := aauth.ReadRevocationReport(response, maximumResponseBytes)
		if err != nil {
			return unavailable(err)
		}
		return Outcome{Recorded: true, Downstream: downstream}
	case http.StatusAccepted:
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, maximumResponseBytes))
		location, err := pendingLocation(request.URL, response.Header.Values("Location"))
		if err != nil {
			return unavailable(err)
		}
		retryAfter, ok := httpapi.ParseRetryAfter(response.Header.Values("Retry-After"), sender.clock.Now())
		if !ok {
			retryAfter = DefaultRetryAfter
		}
		return Outcome{Pending: true, Location: location, RetryAfter: retryAfter}
	case http.StatusUnauthorized:
		if response.Header.Get("Signature-Error") != "" {
			if failure, err := signaturekey.DecodeErrorResponse(response); err == nil {
				return unavailable(failure)
			}
		}
	}
	if mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type")); err == nil && mediaType == "application/problem+json" {
		if problem, err := aauth.DecodeProblemResponse(response); err == nil {
			// A refusal is read from its error member, not from its status.
			if problem.Code == "unsupported_iss" {
				return unsupported(problem)
			}
			if problem.Status == http.StatusTooManyRequests && problem.Code == "rate_limited" {
				// rate_limited asks the caller to come back later; it is not one of
				// the two terminal failures, so the revocation stays pending.
				delay, ok := httpapi.ParseRetryAfter(response.Header.Values("Retry-After"), sender.clock.Now())
				if !ok || delay <= 0 {
					delay = DefaultRetryAfter
				}
				return Outcome{
					Pending: true, RetryAfter: delay, rateLimited: true,
					Cause: &aauth.RateLimitedError{Problem: problem, RetryAfter: delay},
				}
			}
			return unavailable(problem)
		}
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, maximumResponseBytes))
	return unavailable(fmt.Errorf("revocation at %s returned %s", request.URL.Host, response.Status))
}

// pendingLocation resolves a 202 Location, which must be one HTTPS URL on the
// origin that answered.
func pendingLocation(requested *url.URL, values []string) (string, error) {
	if len(values) != 1 || values[0] == "" {
		return "", errors.New("pending revocation response has no single Location")
	}
	location, err := requested.Parse(values[0])
	if err != nil {
		return "", fmt.Errorf("pending revocation Location: %w", err)
	}
	if location.Scheme != "https" || location.Host != requested.Host || location.User != nil || location.Fragment != "" {
		return "", errors.New("pending revocation Location is not an HTTPS URL on the responding origin")
	}
	return location.String(), nil
}

func setWait(request *http.Request, wait time.Duration) {
	if wait > 0 {
		request.Header.Set("Prefer", "wait="+seconds(wait))
	}
}

func revocationComponents(additional []string, provided, destination http.Header) ([]string, error) {
	components := []string{"content-type", "content-digest"}
	seen := map[string]struct{}{"content-type": {}, "content-digest": {}}
	var missing []string
	for _, component := range additional {
		if err := signaturekey.ValidateAdditionalComponent(component); err != nil {
			return nil, fmt.Errorf("recipient revocation signature profile: %w", err)
		}
		if _, duplicate := seen[component]; duplicate {
			continue
		}
		seen[component] = struct{}{}
		values := provided.Values(component)
		if len(values) == 0 {
			missing = append(missing, component)
			continue
		}
		for _, value := range values {
			destination.Add(component, value)
		}
		components = append(components, component)
	}
	if len(missing) > 0 {
		return nil, &signaturekey.Error{
			Code: signaturekey.ErrorInvalidInput, RequiredInput: missing,
			Cause: errors.New("recipient revocation requires advertised headers"),
		}
	}
	return components, nil
}
