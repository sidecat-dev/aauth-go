package personserver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"time"

	aauth "github.com/aauth-dev/auth-go"
	"github.com/aauth-dev/auth-go/signaturekey"
)

// ErrIssuedAuthTokenNotFound reports that the Person Server did not retain the
// identified issued auth token.
var ErrIssuedAuthTokenNotFound = errors.New("personserver: issued auth token not found")

// ErrIssuedAuthTokenConflict reports that one issuer/JTI pair is bound to a
// different retained issuance record.
var ErrIssuedAuthTokenConflict = errors.New("personserver: issued auth token conflicts with retained state")

// ErrRevocationNotRecognized reports a Resource's 404 response for an auth
// token the Resource has not observed.
var ErrRevocationNotRecognized = errors.New("personserver: resource did not recognize the auth token")

// IssuedAuthTokenRecord retains the exact compact-token digest, routing, and
// lifetime of one three-party auth token before it is returned to the Agent.
type IssuedAuthTokenRecord struct {
	Reference     aauth.TokenReference
	Resource      string
	CompactSHA256 [32]byte
	IssuedAt      time.Time
	ExpiresAt     time.Time
}

// IssuedAuthTokenStore retains three-party auth-token issuance records.
// CommitIssuedAuthToken must be idempotent for an identical record and return
// ErrIssuedAuthTokenConflict for a changed record at the same reference. A
// record must remain loadable through ExpiresAt; it may be removed afterward.
// LoadIssuedAuthToken returns ErrIssuedAuthTokenNotFound for an absent record.
// Commit and Load for one reference must be linearizable.
type IssuedAuthTokenStore interface {
	CommitIssuedAuthToken(context.Context, IssuedAuthTokenRecord) error
	LoadIssuedAuthToken(context.Context, aauth.TokenReference) (IssuedAuthTokenRecord, error)
}

// AuthTokenRevocationConfig enables exact three-party auth-token revocation.
// The caller owns transport through HTTPClient and admits each metadata or
// revocation endpoint through Admit before the client can contact it.
type AuthTokenRevocationConfig struct {
	IssuedTokens IssuedAuthTokenStore
	// HTTPClient supplies transport and timeout policy. The server clones it and
	// does not use its Cookie Jar or redirect callback.
	HTTPClient *http.Client
	Admit      signaturekey.EgressAdmitter
}

func (server *Server) configureAuthTokenRevocation(config *AuthTokenRevocationConfig) error {
	if config == nil {
		return nil
	}
	if config.IssuedTokens == nil {
		return errors.New("personserver: issued auth-token store is required for revocation")
	}
	if config.HTTPClient == nil {
		return errors.New("personserver: HTTP client is required for revocation")
	}
	if config.Admit == nil {
		return errors.New("personserver: egress admitter is required for revocation")
	}
	client := *config.HTTPClient
	// Revocation is authenticated by Signature-Key, not ambient caller cookies.
	client.Jar = nil
	client.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	server.issuedAuthTokens = config.IssuedTokens
	server.revocationHTTPClient = &client
	server.revocationAdmit = config.Admit
	return nil
}

func (server *Server) commitIssuedAuthToken(ctx context.Context, compact string, claims aauth.AuthTokenClaims) error {
	if server.issuedAuthTokens == nil {
		return nil
	}
	record := IssuedAuthTokenRecord{
		Reference: aauth.TokenReference{Issuer: claims.Issuer, JTI: claims.JTI},
		Resource:  claims.Audience, CompactSHA256: sha256.Sum256([]byte(compact)),
		IssuedAt: time.Unix(claims.IssuedAt, 0).UTC(), ExpiresAt: time.Unix(claims.ExpiresAt, 0).UTC(),
	}
	if err := validateIssuedAuthTokenRecord(record); err != nil {
		return err
	}
	return server.issuedAuthTokens.CommitIssuedAuthToken(ctx, record)
}

// RevokeIssuedAuthToken performs one explicit revocation attempt for an exact
// auth token previously issued and retained by this Person Server. It never
// retries internally.
func (server *Server) RevokeIssuedAuthToken(ctx context.Context, reference aauth.TokenReference) error {
	return server.RevokeIssuedAuthTokenWithHeaders(ctx, reference, nil)
}

// RevokeIssuedAuthTokenWithHeaders performs one explicit revocation attempt
// and supplies values for any additional signature components advertised by
// the Resource.
func (server *Server) RevokeIssuedAuthTokenWithHeaders(
	ctx context.Context,
	reference aauth.TokenReference,
	header http.Header,
) error {
	if server == nil || server.issuedAuthTokens == nil || server.revocationHTTPClient == nil {
		return errors.New("personserver: auth-token revocation is not configured")
	}
	if ctx == nil {
		return errors.New("personserver: revocation context is required")
	}
	if err := aauth.ValidateTokenReference(reference); err != nil {
		return err
	}
	if reference.Issuer != server.issuer {
		return errors.New("personserver: auth-token reference was not issued by this server")
	}
	record, err := server.issuedAuthTokens.LoadIssuedAuthToken(ctx, reference)
	if err != nil {
		return err
	}
	if err := validateIssuedAuthTokenRecord(record); err != nil || record.Reference != reference {
		return fmt.Errorf("%w: invalid loaded record", ErrIssuedAuthTokenConflict)
	}
	endpoint, additionalComponents, err := server.resourceRevocationProfile(ctx, record.Resource)
	if err != nil {
		return err
	}
	body, err := json.Marshal(reference)
	if err != nil {
		return fmt.Errorf("personserver: encode revocation request: %w", err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("personserver: create revocation request: %w", err)
	}
	request.Header = make(http.Header)
	request.Header.Set("Content-Type", "application/json")
	components, err := revocationSignatureComponents(additionalComponents, header, request.Header)
	if err != nil {
		return err
	}
	if err := signaturekey.SignJWKSURIRequestWithOptions(
		request, server.signingKey, server.issuer, aauth.PersonDiscoveryDocument, server.clock,
		signaturekey.SignOptions{
			AdditionalComponents: components,
			MaxBodyBytes:         maxRequestBytes,
		},
	); err != nil {
		return fmt.Errorf("personserver: sign revocation request: %w", err)
	}
	response, err := server.revocationHTTPClient.Do(request)
	if err != nil {
		return fmt.Errorf("personserver: revoke auth token: %w", err)
	}
	defer response.Body.Close()
	switch response.StatusCode {
	case http.StatusOK:
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, maxRequestBytes))
		return nil
	case http.StatusNotFound:
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, maxRequestBytes))
		return ErrRevocationNotRecognized
	case http.StatusUnauthorized:
		if response.Header.Get("Signature-Error") != "" {
			failure, decodeErr := signaturekey.DecodeErrorResponse(response)
			if decodeErr == nil {
				return failure
			}
		}
	}
	if mediaType, _, parseErr := mime.ParseMediaType(response.Header.Get("Content-Type")); parseErr == nil && mediaType == "application/problem+json" {
		problem, decodeErr := aauth.DecodeProblemResponse(response)
		if decodeErr == nil {
			return problem
		}
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, maxRequestBytes))
	return fmt.Errorf("personserver: Resource revocation endpoint returned %s", response.Status)
}

func (server *Server) resourceRevocationProfile(ctx context.Context, resource string) (string, []string, error) {
	if err := aauth.ValidateServerIdentifier(resource); err != nil {
		return "", nil, fmt.Errorf("personserver: retained auth-token Resource: %w", err)
	}
	metadataEndpoint := resource + "/.well-known/aauth-resource.json"
	if err := server.admitRevocationEgress(ctx, metadataEndpoint, "Resource metadata"); err != nil {
		return "", nil, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, metadataEndpoint, nil)
	if err != nil {
		return "", nil, fmt.Errorf("personserver: create Resource metadata request: %w", err)
	}
	response, err := server.revocationHTTPClient.Do(request)
	if err != nil {
		return "", nil, fmt.Errorf("personserver: fetch Resource metadata: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, maxRequestBytes))
		return "", nil, fmt.Errorf("personserver: Resource metadata returned %s", response.Status)
	}
	var metadata struct {
		Issuer                        string   `json:"issuer"`
		RevocationEndpoint            string   `json:"revocation_endpoint"`
		AdditionalSignatureComponents []string `json:"additional_signature_components"`
	}
	if err := decodeJSON(response.Body, &metadata); err != nil {
		return "", nil, fmt.Errorf("personserver: decode Resource metadata: %w", err)
	}
	if metadata.Issuer != resource {
		return "", nil, errors.New("personserver: Resource metadata issuer does not match requested Resource")
	}
	if err := aauth.ValidateEndpoint(metadata.RevocationEndpoint); err != nil {
		return "", nil, fmt.Errorf("personserver: Resource metadata revocation_endpoint: %w", err)
	}
	if err := server.admitRevocationEgress(ctx, metadata.RevocationEndpoint, "Resource revocation endpoint"); err != nil {
		return "", nil, err
	}
	return metadata.RevocationEndpoint, append([]string(nil), metadata.AdditionalSignatureComponents...), nil
}

func (server *Server) admitRevocationEgress(ctx context.Context, endpoint, kind string) error {
	if err := server.revocationAdmit(ctx, endpoint); err != nil {
		return fmt.Errorf("personserver: %s egress admission failed for %q: %w", kind, endpoint, err)
	}
	return nil
}

func revocationSignatureComponents(additional []string, provided, destination http.Header) ([]string, error) {
	components := []string{"content-type", "content-digest"}
	seen := map[string]struct{}{"content-type": {}, "content-digest": {}}
	var missing []string
	for _, component := range additional {
		if err := signaturekey.ValidateAdditionalComponent(component); err != nil {
			return nil, fmt.Errorf("personserver: Resource revocation signature profile: %w", err)
		}
		if _, duplicate := seen[component]; duplicate {
			return nil, fmt.Errorf("personserver: Resource revocation signature component %q is duplicated", component)
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
			Cause: errors.New("personserver: Resource revocation requires advertised headers"),
		}
	}
	return components, nil
}

func validateIssuedAuthTokenRecord(record IssuedAuthTokenRecord) error {
	if err := aauth.ValidateTokenReference(record.Reference); err != nil {
		return fmt.Errorf("personserver: issued auth-token record: %w", err)
	}
	if err := aauth.ValidateServerIdentifier(record.Resource); err != nil {
		return fmt.Errorf("personserver: issued auth-token Resource: %w", err)
	}
	if record.CompactSHA256 == ([32]byte{}) || record.IssuedAt.IsZero() || !record.ExpiresAt.After(record.IssuedAt) {
		return errors.New("personserver: issued auth-token record is invalid")
	}
	return nil
}
