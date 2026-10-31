package personserver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/internal/httpapi"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

// ErrIssuedAuthTokenNotFound reports that the Person Server did not retain the
// identified issued auth token.
var ErrIssuedAuthTokenNotFound = errors.New("personserver: issued auth token not found")

// ErrIssuedAuthTokenConflict reports that one issuer/JTI pair is bound to a
// different retained issuance record.
var ErrIssuedAuthTokenConflict = errors.New("personserver: issued auth token conflicts with retained state")

// IssuedAuthTokenRecord retains the exact compact-token digest, routing, and
// lifetime of one auth token before it is returned to the Agent. MissionStore
// uses it for both Person-Server-issued and federated mission-bound tokens.
//
// AgentProvider, Agent, AgentTokenJTI and AgentJKT name the Agent the token was
// issued to and the Agent token it signed the request with. They are all set
// or all empty. Call chaining identifies the calling Agent of an upstream auth
// token from them; a record without them identifies no caller. ParentAgent is
// nonempty when Agent is a sub-agent whose parent mediated the issuance; that
// parent's binding authorized the token.
//
// UpstreamTokenReference and UpstreamTokenSHA256 name the exact upstream
// token of a chained issuance. They are both set or both empty.
//
// PresentedTokenReference names the token the auth token was issued against:
// the person token, or on a step-up the auth token it replaces. Revocation
// follows it from a revoked person token to the auth tokens obtained with it.
// It is empty in records that predate it and for auth tokens issued after
// PS-hosted consent.
//
// A four-party Person Server keeps the same record, a receipt, for each auth
// token it delivers from an Access Server: Reference then names the Access
// Server's token.
type IssuedAuthTokenRecord struct {
	Reference     aauth.TokenReference
	Resource      string
	MissionS256   string
	CompactSHA256 [32]byte
	IssuedAt      time.Time
	ExpiresAt     time.Time

	AgentProvider string
	Agent         string
	ParentAgent   string
	AgentTokenJTI string
	AgentJKT      string

	UpstreamTokenReference aauth.TokenReference
	UpstreamTokenSHA256    [32]byte

	PresentedTokenReference aauth.TokenReference
}

// IssuedAuthTokenStore retains auth-token issuance records: those of the auth
// tokens a three-party Person Server issues, and the receipts of those a
// four-party Person Server delivers.
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

func issuedAuthTokenRecord(compact string, claims aauth.AuthTokenClaims) (IssuedAuthTokenRecord, error) {
	record := IssuedAuthTokenRecord{
		Reference: aauth.TokenReference{Issuer: claims.Issuer, JTI: claims.JTI},
		Resource:  claims.Audience, MissionS256: claims.MissionS256,
		CompactSHA256: sha256.Sum256([]byte(compact)),
		IssuedAt:      time.Unix(claims.IssuedAt, 0).UTC(), ExpiresAt: time.Unix(claims.ExpiresAt, 0).UTC(),
	}
	if err := validateIssuedAuthTokenRecord(record); err != nil {
		return IssuedAuthTokenRecord{}, err
	}
	return record, nil
}

// bindRecipient retains the Agent an auth token is issued to, the token it is
// issued against, and the upstream token of a chained issuance.
func (record *IssuedAuthTokenRecord) bindRecipient(
	agent aauth.AgentTokenClaims,
	presented aauth.TokenReference,
	upstream *verifiedUpstreamToken,
) error {
	thumbprint, err := agent.Confirmation.JWK.Thumbprint()
	if err != nil {
		return fmt.Errorf("personserver: issued auth-token recipient key: %w", err)
	}
	record.AgentProvider = agent.Issuer
	record.Agent = agent.Subject
	record.ParentAgent = agent.ParentAgent
	record.AgentTokenJTI = agent.JTI
	record.AgentJKT = thumbprint
	record.PresentedTokenReference = presented
	if upstream != nil {
		record.UpstreamTokenReference = upstream.reference
		record.UpstreamTokenSHA256 = upstream.digest
	}
	return validateIssuedAuthTokenRecord(*record)
}

func (record IssuedAuthTokenRecord) identifiesRecipient() bool {
	return record.AgentProvider != "" && record.Agent != "" && record.AgentTokenJTI != "" && record.AgentJKT != ""
}

func (server *Server) commitIssuedAuthToken(ctx context.Context, record IssuedAuthTokenRecord) error {
	if server.issuedAuthTokens == nil {
		return nil
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
	if err := server.recordIssuedAuthTokenRevocation(ctx, record); err != nil {
		return fmt.Errorf("personserver: record auth-token revocation: %w", err)
	}
	endpoint, additionalComponents, err := server.resourceRevocationProfile(ctx, record.Resource)
	if err != nil {
		return err
	}
	body, err := aauth.EncodeRevocationRequest(aauth.RevocationRequest{Reference: reference, ExpiresAt: record.ExpiresAt})
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
		return aauth.ReadRevocationResponse(response, maxRequestBytes)
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
			if problem.Status == http.StatusTooManyRequests && problem.Code == "rate_limited" {
				if delay, ok := httpapi.ParseRetryAfter(response.Header.Values("Retry-After"), server.clock.Now()); ok {
					return &aauth.RateLimitedError{Problem: problem, RetryAfter: delay}
				}
			}
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
	if record.MissionS256 != "" {
		if err := aauth.ValidateMissionS256(record.MissionS256); err != nil {
			return fmt.Errorf("personserver: issued auth-token mission: %w", err)
		}
	}
	if record.CompactSHA256 == ([32]byte{}) || record.IssuedAt.IsZero() || !record.ExpiresAt.After(record.IssuedAt) {
		return errors.New("personserver: issued auth-token record is invalid")
	}
	if record.AgentProvider != "" || record.Agent != "" || record.ParentAgent != "" || record.AgentTokenJTI != "" || record.AgentJKT != "" {
		if !record.identifiesRecipient() {
			return errors.New("personserver: issued auth-token recipient is incomplete")
		}
		if err := aauth.ValidateTokenReference(aauth.TokenReference{
			Issuer: record.AgentProvider, JTI: record.AgentTokenJTI,
		}); err != nil {
			return fmt.Errorf("personserver: issued auth-token recipient: %w", err)
		}
		if record.ParentAgent != "" {
			if err := aauth.ValidateAgentRelationship(record.Agent, record.ParentAgent); err != nil {
				return fmt.Errorf("personserver: issued auth-token recipient: %w", err)
			}
		}
	}
	emptyReference := record.UpstreamTokenReference == (aauth.TokenReference{})
	if emptyReference != (record.UpstreamTokenSHA256 == ([32]byte{})) {
		return errors.New("personserver: issued auth-token upstream binding is incomplete")
	}
	if !emptyReference {
		if err := aauth.ValidateTokenReference(record.UpstreamTokenReference); err != nil {
			return errors.New("personserver: issued auth-token upstream reference is invalid")
		}
	}
	if record.PresentedTokenReference != (aauth.TokenReference{}) {
		if err := aauth.ValidateTokenReference(record.PresentedTokenReference); err != nil {
			return errors.New("personserver: issued auth-token presented reference is invalid")
		}
	}
	return nil
}
