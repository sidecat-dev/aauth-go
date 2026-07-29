package aauth

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	AgentTokenType    = "aa-agent+jwt"
	ResourceTokenType = "aa-resource+jwt"
	AuthTokenType     = "aa-auth+jwt"

	AgentDiscoveryDocument    = "aauth-agent.json"
	ResourceDiscoveryDocument = "aauth-resource.json"
	PersonDiscoveryDocument   = "aauth-person.json"
	AccessDiscoveryDocument   = "aauth-access.json"
)

// TokenValidationCode identifies a stable validation failure for a compact
// token. Callers that expose tokens through another protocol can classify the
// failure without inspecting diagnostic text.
type TokenValidationCode string

const (
	TokenValidationExpired    TokenValidationCode = "expired"
	TokenValidationInvalidKey TokenValidationCode = "invalid_key"
)

// TokenValidationError retains the underlying validation cause while exposing
// a stable code for protocol adapters.
type TokenValidationError struct {
	Code  TokenValidationCode
	Cause error
}

type unsupportedTokenAlgorithmError struct{ algorithm string }

func (err *unsupportedTokenAlgorithmError) Error() string {
	return fmt.Sprintf("aauth: unsupported token algorithm %q", err.algorithm)
}

func (err *TokenValidationError) Error() string {
	if err == nil || err.Cause == nil {
		return "aauth: token validation failed"
	}
	return "aauth: token validation " + string(err.Code) + ": " + err.Cause.Error()
}

func (err *TokenValidationError) Unwrap() error {
	if err == nil {
		return nil
	}
	return err.Cause
}

// Confirmation is the RFC 7800 confirmation claim used by AAuth.
type Confirmation struct {
	JWK JWK `json:"jwk"`
}

// AgentTokenRequest is the issuer-validated input to agent-token creation.
type AgentTokenRequest struct {
	Agent        string
	PersonServer string
	ParentAgent  string
	PublicKey    JWK
	Lifetime     time.Duration
}

// AgentTokenClaims are the claims of an aa-agent+jwt.
type AgentTokenClaims struct {
	Issuer       string       `json:"iss"`
	DWK          string       `json:"dwk"`
	Subject      string       `json:"sub"`
	JTI          string       `json:"jti"`
	Confirmation Confirmation `json:"cnf"`
	IssuedAt     int64        `json:"iat"`
	ExpiresAt    int64        `json:"exp"`
	PersonServer string       `json:"ps,omitempty"`
	ParentAgent  string       `json:"parent_agent,omitempty"`
}

// ResourceTokenClaims are the claims of an aa-resource+jwt.
type ResourceTokenClaims struct {
	Issuer    string            `json:"iss"`
	DWK       string            `json:"dwk"`
	Audience  string            `json:"aud"`
	JTI       string            `json:"jti"`
	Agent     string            `json:"agent"`
	AgentJKT  string            `json:"agent_jkt"`
	IssuedAt  int64             `json:"iat"`
	ExpiresAt int64             `json:"exp"`
	Scope     string            `json:"scope"`
	Mission   *MissionReference `json:"mission,omitempty"`
}

// Actor records one link in an AAuth delegation chain.
type Actor struct {
	Agent string `json:"agent"`
	Actor *Actor `json:"act,omitempty"`
}

// AuthTokenClaims are the claims of an aa-auth+jwt.
type AuthTokenClaims struct {
	Issuer       string            `json:"iss"`
	DWK          string            `json:"dwk"`
	Audience     string            `json:"aud"`
	JTI          string            `json:"jti"`
	Agent        string            `json:"agent"`
	Confirmation Confirmation      `json:"cnf"`
	Actor        *Actor            `json:"act,omitempty"`
	IssuedAt     int64             `json:"iat"`
	ExpiresAt    int64             `json:"exp"`
	Subject      string            `json:"sub,omitempty"`
	Scope        string            `json:"scope,omitempty"`
	Mission      *MissionReference `json:"mission,omitempty"`
	Tenant       string            `json:"tenant,omitempty"`
}

// TokenHeader is the protected JWS header common to AAuth tokens.
type TokenHeader struct {
	Algorithm string `json:"alg"`
	Type      string `json:"typ"`
	KeyID     string `json:"kid"`
}

// MintAgentToken creates an agent token with the supplied issuer key.
func MintAgentToken(issuer string, key SigningKey, request AgentTokenRequest, now time.Time, jti string) (string, error) {
	if err := ValidateServerIdentifier(issuer); err != nil {
		return "", fmt.Errorf("aauth: agent-token issuer: %w", err)
	}
	if err := ValidateAgentIdentifier(request.Agent); err != nil {
		return "", fmt.Errorf("aauth: agent-token subject: %w", err)
	}
	if err := validateAgentIssuerDomain(request.Agent, issuer); err != nil {
		return "", fmt.Errorf("aauth: agent-token subject: %w", err)
	}
	if request.PersonServer != "" {
		if err := ValidateServerIdentifier(request.PersonServer); err != nil {
			return "", fmt.Errorf("aauth: agent-token person server: %w", err)
		}
	}
	if request.ParentAgent != "" {
		if err := ValidateAgentIdentifier(request.ParentAgent); err != nil {
			return "", fmt.Errorf("aauth: agent-token parent: %w", err)
		}
	}
	if err := ValidateAgentRelationship(request.Agent, request.ParentAgent); err != nil {
		return "", fmt.Errorf("aauth: agent-token relationship: %w", err)
	}
	if _, err := request.PublicKey.PublicKey(); err != nil {
		return "", fmt.Errorf("aauth: agent-token confirmation key: %w", err)
	}
	if request.Lifetime <= 0 || request.Lifetime > 24*time.Hour {
		return "", errors.New("aauth: agent-token lifetime must be between zero and 24 hours")
	}
	if jti == "" {
		return "", errors.New("aauth: agent-token jti is required")
	}
	claims := AgentTokenClaims{
		Issuer:       issuer,
		DWK:          AgentDiscoveryDocument,
		Subject:      request.Agent,
		JTI:          jti,
		Confirmation: Confirmation{JWK: request.PublicKey},
		IssuedAt:     now.Unix(),
		ExpiresAt:    now.Add(request.Lifetime).Unix(),
		PersonServer: request.PersonServer,
		ParentAgent:  request.ParentAgent,
	}
	return mintToken(key, AgentTokenType, claims)
}

// MintResourceToken creates the short-lived resource assertion carried to a
// person or access server.
func MintResourceToken(key SigningKey, claims ResourceTokenClaims) (string, error) {
	if err := validateResourceClaims(claims, time.Unix(claims.IssuedAt, 0), false); err != nil {
		return "", err
	}
	return mintToken(key, ResourceTokenType, claims)
}

// MintAuthToken creates the proof-bound authorization assertion.
func MintAuthToken(key SigningKey, claims AuthTokenClaims) (string, error) {
	if err := validateAuthClaims(claims, time.Unix(claims.IssuedAt, 0), false); err != nil {
		return "", err
	}
	return mintToken(key, AuthTokenType, claims)
}

func mintToken(key SigningKey, tokenType string, claims any) (string, error) {
	headerBytes, err := json.Marshal(TokenHeader{
		Algorithm: "EdDSA",
		Type:      tokenType,
		KeyID:     key.ID(),
	})
	if err != nil {
		return "", fmt.Errorf("aauth: marshal token header: %w", err)
	}
	claimsBytes, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("aauth: marshal token claims: %w", err)
	}
	signingInput := rawURL.EncodeToString(headerBytes) + "." + rawURL.EncodeToString(claimsBytes)
	signature, err := key.sign([]byte(signingInput))
	if err != nil {
		return "", err
	}
	return signingInput + "." + rawURL.EncodeToString(signature), nil
}

// VerifyAgentToken verifies issuer trust, JWS integrity, structure, and time.
func VerifyAgentToken(ctx context.Context, compact string, resolver KeyResolver, clock Clock) (AgentTokenClaims, error) {
	var claims AgentTokenClaims
	if err := verifyAndDecodeToken(ctx, compact, AgentTokenType, AgentDiscoveryDocument, resolver, clock, &claims); err != nil {
		return claims, err
	}
	if err := validateAgentClaims(claims, clock.Now()); err != nil {
		return claims, err
	}
	return claims, nil
}

// VerifyResourceToken verifies issuer trust, JWS integrity, structure, and time.
func VerifyResourceToken(ctx context.Context, compact string, resolver KeyResolver, clock Clock) (ResourceTokenClaims, error) {
	var claims ResourceTokenClaims
	if err := verifyAndDecodeToken(ctx, compact, ResourceTokenType, ResourceDiscoveryDocument, resolver, clock, &claims); err != nil {
		return claims, err
	}
	if err := validateResourceClaims(claims, clock.Now(), true); err != nil {
		return claims, err
	}
	return claims, nil
}

// VerifyAuthToken verifies issuer trust, JWS integrity, structure, and time.
func VerifyAuthToken(ctx context.Context, compact string, resolver KeyResolver, clock Clock) (AuthTokenClaims, error) {
	var claims AuthTokenClaims
	header, payload, signature, signingInput, err := decodeToken(compact)
	if err != nil {
		return claims, err
	}
	if header.Type != AuthTokenType {
		return claims, fmt.Errorf("aauth: token typ is %q, want %q", header.Type, AuthTokenType)
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return claims, fmt.Errorf("aauth: decode auth-token claims: %w", err)
	}
	if claims.DWK != PersonDiscoveryDocument && claims.DWK != AccessDiscoveryDocument {
		return claims, fmt.Errorf("aauth: auth-token dwk is %q", claims.DWK)
	}
	if err := verifyResolvedTokenKey(ctx, header, claims.Issuer, claims.DWK, signingInput, signature, resolver); err != nil {
		return claims, err
	}
	if err := validateAuthClaims(claims, clock.Now(), true); err != nil {
		return claims, err
	}
	return claims, nil
}

func verifyAndDecodeToken[T AgentTokenClaims | ResourceTokenClaims](
	ctx context.Context,
	compact string,
	expectedType string,
	expectedDWK string,
	resolver KeyResolver,
	clock Clock,
	claims *T,
) error {
	if resolver == nil {
		return errors.New("aauth: key resolver is required")
	}
	if clock == nil {
		return errors.New("aauth: clock is required")
	}
	header, payload, signature, signingInput, err := decodeToken(compact)
	if err != nil {
		return err
	}
	if header.Type != expectedType {
		return fmt.Errorf("aauth: token typ is %q, want %q", header.Type, expectedType)
	}
	if err := json.Unmarshal(payload, claims); err != nil {
		return fmt.Errorf("aauth: decode %s claims: %w", expectedType, err)
	}
	var issuer, dwk string
	switch value := any(claims).(type) {
	case *AgentTokenClaims:
		issuer, dwk = value.Issuer, value.DWK
	case *ResourceTokenClaims:
		issuer, dwk = value.Issuer, value.DWK
	}
	if dwk != expectedDWK {
		return fmt.Errorf("aauth: token dwk is %q, want %q", dwk, expectedDWK)
	}
	if err := verifyResolvedTokenKey(ctx, header, issuer, dwk, signingInput, signature, resolver); err != nil {
		return err
	}
	return nil
}

func verifyResolvedTokenKey(
	ctx context.Context,
	header TokenHeader,
	issuer string,
	dwk string,
	signingInput string,
	signature []byte,
	resolver KeyResolver,
) error {
	if resolver == nil {
		return errors.New("aauth: key resolver is required")
	}
	if header.Algorithm == "none" {
		return errors.New("aauth: alg none is forbidden")
	}
	if header.Algorithm != "EdDSA" {
		return &unsupportedTokenAlgorithmError{algorithm: header.Algorithm}
	}
	if header.KeyID == "" {
		return errors.New("aauth: token kid is required")
	}
	if err := ValidateServerIdentifier(issuer); err != nil {
		return fmt.Errorf("aauth: token issuer: %w", err)
	}
	key, err := resolver.ResolveKey(ctx, issuer, dwk, header.KeyID)
	if err != nil {
		return normalizeKeyResolutionError(err)
	}
	publicKey, err := key.PublicKey()
	if err != nil {
		return err
	}
	ed25519Key, ok := publicKey.(ed25519.PublicKey)
	if !ok {
		return errors.New("aauth: resolved token key is not Ed25519")
	}
	if ed25519.Verify(ed25519Key, []byte(signingInput), signature) {
		return nil
	}
	if refresher, ok := resolver.(KeyRefresher); ok {
		refreshed, refreshErr := refresher.RefreshKey(ctx, issuer, dwk, header.KeyID)
		if refreshErr == nil {
			refreshedPublic, publicErr := refreshed.PublicKey()
			if publicErr == nil {
				if refreshedEd25519, isEd25519 := refreshedPublic.(ed25519.PublicKey); isEd25519 &&
					ed25519.Verify(refreshedEd25519, []byte(signingInput), signature) {
					return nil
				}
			}
		} else {
			normalized := normalizeKeyResolutionError(refreshErr)
			var resolutionError *KeyResolutionError
			if errors.As(normalized, &resolutionError) {
				return normalized
			}
		}
	}
	return errors.New("aauth: token signature is invalid")
}

func decodeToken(compact string) (TokenHeader, []byte, []byte, string, error) {
	var header TokenHeader
	parts := strings.Split(compact, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return header, nil, nil, "", errors.New("aauth: token must be a three-part compact JWS")
	}
	headerBytes, err := rawURL.DecodeString(parts[0])
	if err != nil {
		return header, nil, nil, "", fmt.Errorf("aauth: decode token header: %w", err)
	}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return header, nil, nil, "", fmt.Errorf("aauth: parse token header: %w", err)
	}
	payload, err := rawURL.DecodeString(parts[1])
	if err != nil {
		return header, nil, nil, "", fmt.Errorf("aauth: decode token payload: %w", err)
	}
	signature, err := rawURL.DecodeString(parts[2])
	if err != nil {
		return header, nil, nil, "", fmt.Errorf("aauth: decode token signature: %w", err)
	}
	if len(signature) != ed25519.SignatureSize {
		return header, nil, nil, "", fmt.Errorf("aauth: Ed25519 token signature has %d bytes", len(signature))
	}
	return header, payload, signature, parts[0] + "." + parts[1], nil
}

// PeekTokenHeader reads only the protected header. It does not establish trust.
func PeekTokenHeader(compact string) (TokenHeader, error) {
	header, _, _, _, err := decodeToken(compact)
	return header, err
}

func validateAgentClaims(claims AgentTokenClaims, now time.Time) error {
	if err := ValidateServerIdentifier(claims.Issuer); err != nil {
		return fmt.Errorf("aauth: agent-token issuer: %w", err)
	}
	if claims.DWK != AgentDiscoveryDocument {
		return errors.New("aauth: agent-token dwk is invalid")
	}
	if err := ValidateAgentIdentifier(claims.Subject); err != nil {
		return fmt.Errorf("aauth: agent-token subject: %w", err)
	}
	if err := validateAgentIssuerDomain(claims.Subject, claims.Issuer); err != nil {
		return fmt.Errorf("aauth: agent-token subject: %w", err)
	}
	if claims.JTI == "" {
		return errors.New("aauth: agent-token jti is required")
	}
	if err := validateTimes(claims.IssuedAt, claims.ExpiresAt, now); err != nil {
		return fmt.Errorf("aauth: agent-token: %w", err)
	}
	if claims.ExpiresAt-claims.IssuedAt > int64((24 * time.Hour).Seconds()) {
		return errors.New("aauth: agent-token lifetime exceeds 24 hours")
	}
	if _, err := claims.Confirmation.JWK.PublicKey(); err != nil {
		return &TokenValidationError{
			Code:  TokenValidationInvalidKey,
			Cause: fmt.Errorf("aauth: agent-token cnf.jwk: %w", err),
		}
	}
	if claims.PersonServer != "" {
		if err := ValidateServerIdentifier(claims.PersonServer); err != nil {
			return fmt.Errorf("aauth: agent-token ps: %w", err)
		}
	}
	if claims.ParentAgent != "" {
		if err := ValidateAgentIdentifier(claims.ParentAgent); err != nil {
			return fmt.Errorf("aauth: agent-token parent_agent: %w", err)
		}
	}
	if err := ValidateAgentRelationship(claims.Subject, claims.ParentAgent); err != nil {
		return fmt.Errorf("aauth: agent-token relationship: %w", err)
	}
	return nil
}

func validateResourceClaims(claims ResourceTokenClaims, now time.Time, enforceCurrentTime bool) error {
	if err := ValidateServerIdentifier(claims.Issuer); err != nil {
		return fmt.Errorf("aauth: resource-token issuer: %w", err)
	}
	if claims.DWK != ResourceDiscoveryDocument {
		return errors.New("aauth: resource-token dwk is invalid")
	}
	if err := ValidateServerIdentifier(claims.Audience); err != nil {
		return fmt.Errorf("aauth: resource-token audience: %w", err)
	}
	if claims.JTI == "" {
		return errors.New("aauth: resource-token jti is required")
	}
	if err := ValidateAgentIdentifier(claims.Agent); err != nil {
		return fmt.Errorf("aauth: resource-token agent: %w", err)
	}
	if claims.AgentJKT == "" {
		return errors.New("aauth: resource-token agent_jkt is required")
	}
	if claims.Scope == "" {
		return errors.New("aauth: resource-token scope is required")
	}
	checkTime := time.Unix(claims.IssuedAt, 0)
	if enforceCurrentTime {
		checkTime = now
	}
	if err := validateTimes(claims.IssuedAt, claims.ExpiresAt, checkTime); err != nil {
		return fmt.Errorf("aauth: resource-token: %w", err)
	}
	if claims.Mission != nil {
		if err := claims.Mission.Validate(); err != nil {
			return fmt.Errorf("aauth: resource-token mission: %w", err)
		}
	}
	return nil
}

func validateAuthClaims(claims AuthTokenClaims, now time.Time, enforceCurrentTime bool) error {
	if err := ValidateServerIdentifier(claims.Issuer); err != nil {
		return fmt.Errorf("aauth: auth-token issuer: %w", err)
	}
	if claims.DWK != PersonDiscoveryDocument && claims.DWK != AccessDiscoveryDocument {
		return errors.New("aauth: auth-token dwk is invalid")
	}
	if err := ValidateServerIdentifier(claims.Audience); err != nil {
		return fmt.Errorf("aauth: auth-token audience: %w", err)
	}
	if claims.JTI == "" {
		return errors.New("aauth: auth-token jti is required")
	}
	if err := ValidateAgentIdentifier(claims.Agent); err != nil {
		return fmt.Errorf("aauth: auth-token agent: %w", err)
	}
	if _, err := claims.Confirmation.JWK.PublicKey(); err != nil {
		return &TokenValidationError{
			Code:  TokenValidationInvalidKey,
			Cause: fmt.Errorf("aauth: auth-token cnf.jwk: %w", err),
		}
	}
	if claims.Subject == "" && claims.Scope == "" {
		return errors.New("aauth: auth-token requires sub or scope")
	}
	checkTime := time.Unix(claims.IssuedAt, 0)
	if enforceCurrentTime {
		checkTime = now
	}
	if err := validateTimes(claims.IssuedAt, claims.ExpiresAt, checkTime); err != nil {
		return fmt.Errorf("aauth: auth-token: %w", err)
	}
	if claims.ExpiresAt-claims.IssuedAt > int64(time.Hour.Seconds()) {
		return errors.New("aauth: auth-token lifetime exceeds one hour")
	}
	if claims.Mission != nil {
		if err := claims.Mission.Validate(); err != nil {
			return fmt.Errorf("aauth: auth-token mission: %w", err)
		}
	}
	for actor := claims.Actor; actor != nil; actor = actor.Actor {
		if err := ValidateAgentIdentifier(actor.Agent); err != nil {
			return fmt.Errorf("aauth: auth-token act.agent: %w", err)
		}
	}
	return nil
}

func validateTimes(issuedAt, expiresAt int64, now time.Time) error {
	if issuedAt <= 0 || expiresAt <= 0 || expiresAt <= issuedAt {
		return errors.New("iat and exp must define a positive lifetime")
	}
	if issuedAt > now.Unix() {
		return errors.New("iat is in the future")
	}
	if expiresAt <= now.Unix() {
		return &TokenValidationError{
			Code:  TokenValidationExpired,
			Cause: errors.New("token is expired"),
		}
	}
	return nil
}

func validateAgentIssuerDomain(agent string, issuer string) error {
	_, agentDomain, err := agentIdentifierParts(agent)
	if err != nil {
		return err
	}
	if err := ValidateServerIdentifier(issuer); err != nil {
		return err
	}
	providerDomain := strings.TrimPrefix(issuer, "https://")
	if agentDomain != providerDomain {
		return fmt.Errorf(
			"agent identifier domain %q does not match issuer domain %q",
			agentDomain,
			providerDomain,
		)
	}
	return nil
}

// ValidateAuthTokenContext applies the request-context checks that are distinct
// from JWT trust: audience, agent identity, proof key, and required scopes.
func ValidateAuthTokenContext(
	claims AuthTokenClaims,
	resourceIdentifier string,
	agentIdentifier string,
	requestKey JWK,
	requiredScopes []string,
) error {
	if err := ValidateServerIdentifier(resourceIdentifier); err != nil {
		return fmt.Errorf("aauth: auth-token expected resource: %w", err)
	}
	if err := ValidateAgentIdentifier(agentIdentifier); err != nil {
		return fmt.Errorf("aauth: auth-token signing-context agent: %w", err)
	}
	if claims.Audience != resourceIdentifier {
		return fmt.Errorf("aauth: auth-token audience %q does not match resource %q", claims.Audience, resourceIdentifier)
	}
	if claims.Agent != agentIdentifier {
		return fmt.Errorf("aauth: auth-token agent %q does not match signing context %q", claims.Agent, agentIdentifier)
	}
	if !claims.Confirmation.JWK.Equal(requestKey) {
		return errors.New("aauth: auth-token confirmation key does not match request key")
	}
	granted := make(map[string]bool)
	for _, scope := range strings.Fields(claims.Scope) {
		if granted[scope] {
			return fmt.Errorf("aauth: auth-token contains duplicate scope %q", scope)
		}
		granted[scope] = true
	}
	for _, required := range requiredScopes {
		if required == "" || !granted[required] {
			return fmt.Errorf("aauth: auth-token does not grant required scope %q", required)
		}
	}
	return nil
}
