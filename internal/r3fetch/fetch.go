// Package r3fetch performs one bounded, role-authenticated R3 document fetch.
package r3fetch

import (
	"context"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strings"
	"time"

	aauth "aauth-go"
	"aauth-go/jose"
	"aauth-go/r3"
	"aauth-go/signaturekey"
)

const (
	defaultMaximumDocumentBytes = int64(1 << 20)
	defaultFetchTimeout         = 10 * time.Second
)

// Config supplies one Person Server or Access Server document-fetch identity.
type Config struct {
	HTTPClient           *http.Client
	SigningKey           jose.SigningKey
	Issuer               string
	DiscoveryDocument    string
	Clock                aauth.Clock
	Admit                signaturekey.EgressAdmitter
	MaximumDocumentBytes int64
	Timeout              time.Duration
}

// Client fetches exact documents as one configured server role.
type Client struct {
	httpClient           *http.Client
	signingKey           jose.SigningKey
	issuer               string
	discoveryDocument    string
	clock                aauth.Clock
	admit                signaturekey.EgressAdmitter
	maximumDocumentBytes int64
	timeout              time.Duration
}

type documentError struct{ cause error }

func (failure *documentError) Error() string { return failure.cause.Error() }
func (failure *documentError) Unwrap() error { return failure.cause }

// IsDocumentError reports a fetched response that cannot be the exact document
// named by the verified token, as distinct from local egress/transport failure.
func IsDocumentError(err error) bool {
	var failure *documentError
	return errors.As(err, &failure)
}

func invalidDocument(cause error) error { return &documentError{cause: cause} }

// New constructs a bounded client and disables HTTP redirects.
func New(config Config) (*Client, error) {
	if config.HTTPClient == nil {
		return nil, errors.New("r3fetch: HTTP client is required")
	}
	if _, err := config.SigningKey.PublicJWK().PublicKey(); err != nil {
		return nil, fmt.Errorf("r3fetch: signing key: %w", err)
	}
	if err := aauth.ValidateServerIdentifier(config.Issuer); err != nil {
		return nil, fmt.Errorf("r3fetch: issuer: %w", err)
	}
	if config.DiscoveryDocument != aauth.PersonDiscoveryDocument &&
		config.DiscoveryDocument != aauth.AccessDiscoveryDocument {
		return nil, errors.New("r3fetch: Person or Access Server discovery role is required")
	}
	if config.Clock == nil {
		return nil, errors.New("r3fetch: clock is required")
	}
	if config.Admit == nil {
		return nil, errors.New("r3fetch: egress admission is required")
	}
	if config.MaximumDocumentBytes < 0 {
		return nil, errors.New("r3fetch: maximum document bytes must not be negative")
	}
	if config.Timeout < 0 {
		return nil, errors.New("r3fetch: timeout must not be negative")
	}
	maximumDocumentBytes := config.MaximumDocumentBytes
	if maximumDocumentBytes == 0 {
		maximumDocumentBytes = defaultMaximumDocumentBytes
	}
	timeout := config.Timeout
	if timeout == 0 {
		timeout = defaultFetchTimeout
	}
	httpClient := *config.HTTPClient
	httpClient.Jar = nil
	httpClient.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return &Client{
		httpClient: &httpClient, signingKey: config.SigningKey,
		issuer: config.Issuer, discoveryDocument: config.DiscoveryDocument,
		clock: config.Clock, admit: config.Admit,
		maximumDocumentBytes: maximumDocumentBytes, timeout: timeout,
	}, nil
}

// Fetch retrieves, hashes, and strictly parses the exact referenced document.
func (client *Client) Fetch(ctx context.Context, reference r3.Reference) (r3.Document, []byte, error) {
	if client == nil {
		return r3.Document{}, nil, errors.New("r3fetch: client is required")
	}
	if ctx == nil {
		return r3.Document{}, nil, errors.New("r3fetch: context is required")
	}
	validated, err := r3.NewReference(reference.URI(), reference.Digest())
	if err != nil || validated != reference {
		return r3.Document{}, nil, invalidDocument(errors.New("r3fetch: reference is invalid"))
	}
	fetchContext, cancel := context.WithTimeout(ctx, client.timeout)
	defer cancel()
	if err := client.admit(fetchContext, reference.URI()); err != nil {
		return r3.Document{}, nil, fmt.Errorf("r3fetch: document egress: %w", err)
	}
	request, err := http.NewRequestWithContext(fetchContext, http.MethodGet, reference.URI(), nil)
	if err != nil {
		return r3.Document{}, nil, fmt.Errorf("r3fetch: request: %w", err)
	}
	request.Header.Set("Accept-Encoding", "identity")
	request.Header.Set("Accept", "application/json")
	if err := signaturekey.SignJWKSURIRequest(
		request, client.signingKey, client.issuer, client.discoveryDocument, client.clock,
	); err != nil {
		return r3.Document{}, nil, fmt.Errorf("r3fetch: sign request: %w", err)
	}
	response, err := client.httpClient.Do(request)
	if err != nil {
		return r3.Document{}, nil, fmt.Errorf("r3fetch: request document: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, client.maximumDocumentBytes))
		if response.StatusCode >= http.StatusOK && response.StatusCode < http.StatusBadRequest ||
			response.StatusCode == http.StatusNotFound || response.StatusCode == http.StatusGone {
			return r3.Document{}, nil, invalidDocument(fmt.Errorf("r3fetch: document response status is %d", response.StatusCode))
		}
		return r3.Document{}, nil, fmt.Errorf("r3fetch: Resource document service returned status %d", response.StatusCode)
	}
	contentTypes := response.Header.Values("Content-Type")
	if len(contentTypes) != 1 {
		return r3.Document{}, nil, invalidDocument(errors.New("r3fetch: document response requires exactly one Content-Type"))
	}
	mediaType, _, err := mime.ParseMediaType(contentTypes[0])
	if err != nil || !strings.EqualFold(mediaType, "application/json") {
		return r3.Document{}, nil, invalidDocument(errors.New("r3fetch: document response Content-Type is not application/json"))
	}
	contentEncodings := response.Header.Values("Content-Encoding")
	if len(contentEncodings) > 1 {
		return r3.Document{}, nil, invalidDocument(errors.New("r3fetch: document response has ambiguous Content-Encoding"))
	}
	if len(contentEncodings) == 1 {
		encoding := strings.TrimSpace(contentEncodings[0])
		if encoding != "" && !strings.EqualFold(encoding, "identity") {
			return r3.Document{}, nil, invalidDocument(fmt.Errorf("r3fetch: document response content encoding %q is not identity", encoding))
		}
	}
	exact, err := io.ReadAll(io.LimitReader(response.Body, client.maximumDocumentBytes+1))
	if err != nil {
		return r3.Document{}, nil, fmt.Errorf("r3fetch: read document: %w", err)
	}
	if int64(len(exact)) > client.maximumDocumentBytes {
		return r3.Document{}, nil, invalidDocument(errors.New("r3fetch: document exceeds the configured byte limit"))
	}
	document, err := r3.ParseReferencedDocument(reference, exact)
	if err != nil {
		return r3.Document{}, nil, invalidDocument(fmt.Errorf("r3fetch: verify document: %w", err))
	}
	return document, exact, nil
}
