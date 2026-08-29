package aauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"gitlab.com/sidecat-dev/aauth-go/jose"
)

const (
	AgentTokenType    = "aa-agent+jwt"
	PersonTokenType   = "aa-person+jwt"
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

type unsupportedTokenClaimError struct {
	tokenType string
	claim     string
}

func (err *unsupportedTokenAlgorithmError) Error() string {
	return fmt.Sprintf("aauth: unsupported token algorithm %q", err.algorithm)
}

func (err *unsupportedTokenClaimError) Error() string {
	if err == nil {
		return "aauth: token contains an unsupported claim"
	}
	return fmt.Sprintf("aauth: %s contains unsupported %s claim", err.tokenType, err.claim)
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
	JWK jose.JWK `json:"jwk"`
}

// AgentTokenRequest is the issuer-validated input to agent-token creation.
type AgentTokenRequest struct {
	Agent        string
	PersonServer string
	ParentAgent  string
	PublicKey    jose.JWK
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

// PersonTokenClaims are the claims of an aa-person+jwt. The token identifies
// one person, in one person-server namespace, to one resource and is bound to
// the agent's current signing key. It carries no authorization claims.
type PersonTokenClaims struct {
	Issuer       string       `json:"iss"`
	DWK          string       `json:"dwk"`
	Audience     string       `json:"aud"`
	Subject      string       `json:"sub"`
	Confirmation Confirmation `json:"cnf"`
	JTI          string       `json:"jti"`
	IssuedAt     int64        `json:"iat"`
	ExpiresAt    int64        `json:"exp"`
	MissionS256  string       `json:"mission_s256,omitempty"`
	Tenant       string       `json:"tenant,omitempty"`
}

// ResourceTokenClaims are the claims of an aa-resource+jwt.
type ResourceTokenClaims struct {
	Issuer       string            `json:"iss"`
	DWK          string            `json:"dwk"`
	Audience     string            `json:"aud"`
	JTI          string            `json:"jti"`
	Agent        string            `json:"agent,omitempty"`
	AgentJKT     string            `json:"agent_jkt"`
	IssuedAt     int64             `json:"iat"`
	ExpiresAt    int64             `json:"exp"`
	Scope        string            `json:"scope"`
	Mission      *MissionReference `json:"mission,omitempty"`
	PersonServer string            `json:"ps,omitempty"`
	Subject      string            `json:"sub,omitempty"`
	PresentedJTI string            `json:"presented_jti,omitempty"`
	Account      string            `json:"account,omitempty"`
	MissionS256  string            `json:"mission_s256,omitempty"`
	Tenant       string            `json:"tenant,omitempty"`
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
	Agent        string            `json:"agent,omitempty"`
	Confirmation Confirmation      `json:"cnf"`
	Actor        *Actor            `json:"act,omitempty"`
	IssuedAt     int64             `json:"iat"`
	ExpiresAt    int64             `json:"exp"`
	Subject      string            `json:"sub,omitempty"`
	Scope        string            `json:"scope,omitempty"`
	Mission      *MissionReference `json:"mission,omitempty"`
	PersonServer string            `json:"ps,omitempty"`
	Account      string            `json:"account,omitempty"`
	MissionS256  string            `json:"mission_s256,omitempty"`
	Tenant       string            `json:"tenant,omitempty"`
}

// MintAgentToken creates an agent token with the supplied issuer key.
func MintAgentToken(issuer string, key jose.SigningKey, request AgentTokenRequest, now time.Time, jti string) (string, error) {
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
func MintResourceToken(key jose.SigningKey, claims ResourceTokenClaims) (string, error) {
	if err := validateResourceClaims(claims, time.Unix(claims.IssuedAt, 0), false); err != nil {
		return "", err
	}
	return mintToken(key, ResourceTokenType, claims)
}

// MintPersonToken performs only the cryptographic construction of a
// proof-bound, resource-directed person token. It does not satisfy the person
// server's retention obligation. Issuers must retain the exact corresponding
// PersonTokenRecord before release; reference.PersonServer composes that
// custody and recovery boundary.
func MintPersonToken(key jose.SigningKey, claims PersonTokenClaims) (string, error) {
	if err := validatePersonClaims(claims, time.Unix(claims.IssuedAt, 0), false); err != nil {
		return "", err
	}
	return mintToken(key, PersonTokenType, claims)
}

// MintAuthToken creates the proof-bound authorization assertion.
func MintAuthToken(key jose.SigningKey, claims AuthTokenClaims) (string, error) {
	if err := validateAuthClaims(claims, time.Unix(claims.IssuedAt, 0), false); err != nil {
		return "", err
	}
	return mintToken(key, AuthTokenType, claims)
}

func mintToken(key jose.SigningKey, tokenType string, claims any) (string, error) {
	claimsBytes, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("aauth: marshal token claims: %w", err)
	}
	return jose.SignCompact(key, jose.Header{
		Algorithm: jose.Ed25519Algorithm,
		Type:      tokenType,
		KeyID:     key.ID(),
	}, claimsBytes)
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

// VerifyPersonToken verifies issuer trust, JWS integrity, structure, and time.
func VerifyPersonToken(ctx context.Context, compact string, resolver KeyResolver, clock Clock) (PersonTokenClaims, error) {
	var claims PersonTokenClaims
	if resolver == nil {
		return claims, errors.New("aauth: key resolver is required")
	}
	if clock == nil {
		return claims, errors.New("aauth: clock is required")
	}
	parsed, err := jose.ParseCompact(compact)
	if err != nil {
		return claims, err
	}
	header, payload := parsed.Header(), parsed.Payload()
	if header.Type != PersonTokenType {
		return claims, fmt.Errorf("aauth: token typ is %q, want %q", header.Type, PersonTokenType)
	}
	var names map[string]json.RawMessage
	if err := json.Unmarshal(payload, &names); err != nil {
		return claims, fmt.Errorf("aauth: decode %s claims: %w", PersonTokenType, err)
	}
	if _, exists := names["scope"]; exists {
		return claims, errors.New("aauth: person-token must not contain scope or account")
	}
	if _, exists := names["account"]; exists {
		return claims, errors.New("aauth: person-token must not contain scope or account")
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return claims, fmt.Errorf("aauth: decode %s claims: %w", PersonTokenType, err)
	}
	if claims.DWK != PersonDiscoveryDocument {
		return claims, fmt.Errorf("aauth: token dwk is %q, want %q", claims.DWK, PersonDiscoveryDocument)
	}
	if _, err := verifyResolvedTokenKey(ctx, parsed, claims.Issuer, claims.DWK, resolver); err != nil {
		return claims, err
	}
	if err := validatePersonClaims(claims, clock.Now(), true); err != nil {
		return claims, err
	}
	return claims, nil
}

// VerifyResourceToken verifies issuer trust, JWS integrity, structure, and time.
func VerifyResourceToken(ctx context.Context, compact string, resolver KeyResolver, clock Clock) (ResourceTokenClaims, error) {
	var claims ResourceTokenClaims
	if err := verifyAndDecodeToken(
		ctx,
		compact,
		ResourceTokenType,
		ResourceDiscoveryDocument,
		resolver,
		clock,
		&claims,
		"r3_uri",
		"r3_s256",
		"budget",
		"budget_consumed",
	); err != nil {
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
	parsed, err := jose.ParseCompact(compact)
	if err != nil {
		return claims, err
	}
	header, payload := parsed.Header(), parsed.Payload()
	if header.Type != AuthTokenType {
		return claims, fmt.Errorf("aauth: token typ is %q, want %q", header.Type, AuthTokenType)
	}
	if err := rejectUnsupportedTokenMembers(
		payload,
		AuthTokenType,
		"r3_uri",
		"r3_s256",
		"r3_granted",
		"r3_per_call",
		"r3_conditional",
		"budget",
		"budget_consumed",
	); err != nil {
		return claims, err
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return claims, fmt.Errorf("aauth: decode auth-token claims: %w", err)
	}
	if claims.DWK != PersonDiscoveryDocument && claims.DWK != AccessDiscoveryDocument {
		return claims, fmt.Errorf("aauth: auth-token dwk is %q", claims.DWK)
	}
	if _, err := verifyResolvedTokenKey(ctx, parsed, claims.Issuer, claims.DWK, resolver); err != nil {
		return claims, err
	}
	if err := validateAuthClaims(claims, clock.Now(), true); err != nil {
		return claims, err
	}
	return claims, nil
}

func verifyAndDecodeToken[T AgentTokenClaims | PersonTokenClaims | ResourceTokenClaims](
	ctx context.Context,
	compact string,
	expectedType string,
	expectedDWK string,
	resolver KeyResolver,
	clock Clock,
	claims *T,
	unsupportedMembers ...string,
) error {
	if resolver == nil {
		return errors.New("aauth: key resolver is required")
	}
	if clock == nil {
		return errors.New("aauth: clock is required")
	}
	parsed, err := jose.ParseCompact(compact)
	if err != nil {
		return err
	}
	header, payload := parsed.Header(), parsed.Payload()
	if header.Type != expectedType {
		return fmt.Errorf("aauth: token typ is %q, want %q", header.Type, expectedType)
	}
	if err := rejectUnsupportedTokenMembers(payload, expectedType, unsupportedMembers...); err != nil {
		return err
	}
	if err := json.Unmarshal(payload, claims); err != nil {
		return fmt.Errorf("aauth: decode %s claims: %w", expectedType, err)
	}
	var issuer, dwk string
	switch value := any(claims).(type) {
	case *AgentTokenClaims:
		issuer, dwk = value.Issuer, value.DWK
	case *PersonTokenClaims:
		issuer, dwk = value.Issuer, value.DWK
	case *ResourceTokenClaims:
		issuer, dwk = value.Issuer, value.DWK
	}
	if dwk != expectedDWK {
		return fmt.Errorf("aauth: token dwk is %q, want %q", dwk, expectedDWK)
	}
	if _, err := verifyResolvedTokenKey(ctx, parsed, issuer, dwk, resolver); err != nil {
		return err
	}
	return nil
}

func rejectUnsupportedTokenMembers(payload []byte, tokenType string, unsupportedMembers ...string) error {
	if len(unsupportedMembers) == 0 {
		return nil
	}
	var names map[string]json.RawMessage
	if err := json.Unmarshal(payload, &names); err != nil {
		return fmt.Errorf("aauth: decode %s claims: %w", tokenType, err)
	}
	for _, member := range unsupportedMembers {
		if _, exists := names[member]; exists {
			return &unsupportedTokenClaimError{tokenType: tokenType, claim: member}
		}
	}
	return nil
}

func verifyResolvedTokenKey(
	ctx context.Context,
	parsed jose.ParsedCompact,
	issuer string,
	dwk string,
	resolver KeyResolver,
) (jose.VerifiedCompact, error) {
	if resolver == nil {
		return jose.VerifiedCompact{}, errors.New("aauth: key resolver is required")
	}
	header := parsed.Header()
	if header.Algorithm == "none" {
		return jose.VerifiedCompact{}, errors.New("aauth: alg none is forbidden")
	}
	if header.Algorithm != jose.Ed25519Algorithm {
		return jose.VerifiedCompact{}, &unsupportedTokenAlgorithmError{algorithm: header.Algorithm}
	}
	if header.KeyID == "" {
		return jose.VerifiedCompact{}, errors.New("aauth: token kid is required")
	}
	if err := ValidateServerIdentifier(issuer); err != nil {
		return jose.VerifiedCompact{}, fmt.Errorf("aauth: token issuer: %w", err)
	}
	key, err := resolver.ResolveKey(ctx, issuer, dwk, header.KeyID)
	if err != nil {
		return jose.VerifiedCompact{}, normalizeKeyResolutionError(err)
	}
	if _, err := key.PublicKey(); err != nil {
		return jose.VerifiedCompact{}, err
	}
	verified, err := parsed.Verify(key)
	if err == nil {
		return verified, nil
	}
	if refresher, ok := resolver.(KeyRefresher); ok {
		refreshed, refreshErr := refresher.RefreshKey(ctx, issuer, dwk, header.KeyID)
		if refreshErr == nil {
			refreshedVerified, verifyErr := parsed.Verify(refreshed)
			if verifyErr == nil {
				return refreshedVerified, nil
			}
		} else {
			normalized := normalizeKeyResolutionError(refreshErr)
			var resolutionError *KeyResolutionError
			if errors.As(normalized, &resolutionError) {
				return jose.VerifiedCompact{}, normalized
			}
		}
	}
	return jose.VerifiedCompact{}, errors.New("aauth: token signature is invalid")
}

func verifyTokenSignatureWithKey(parsed jose.ParsedCompact, key jose.JWK) (jose.VerifiedCompact, error) {
	if _, err := key.PublicKey(); err != nil {
		return jose.VerifiedCompact{}, &TokenValidationError{Code: TokenValidationInvalidKey, Cause: err}
	}
	verified, err := parsed.Verify(key)
	if err != nil {
		return jose.VerifiedCompact{}, err
	}
	return verified, nil
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

func validatePersonClaims(claims PersonTokenClaims, now time.Time, enforceCurrentTime bool) error {
	if err := ValidateServerIdentifier(claims.Issuer); err != nil {
		return fmt.Errorf("aauth: person-token issuer: %w", err)
	}
	if claims.DWK != PersonDiscoveryDocument {
		return errors.New("aauth: person-token dwk is invalid")
	}
	if err := ValidateServerIdentifier(claims.Audience); err != nil {
		return fmt.Errorf("aauth: person-token audience: %w", err)
	}
	if claims.Subject == "" {
		return errors.New("aauth: person-token sub is required")
	}
	if claims.JTI == "" {
		return errors.New("aauth: person-token jti is required")
	}
	if _, err := claims.Confirmation.JWK.PublicKey(); err != nil {
		return &TokenValidationError{
			Code:  TokenValidationInvalidKey,
			Cause: fmt.Errorf("aauth: person-token cnf.jwk: %w", err),
		}
	}
	checkTime := time.Unix(claims.IssuedAt, 0)
	if enforceCurrentTime {
		checkTime = now
	}
	if err := validateTimes(claims.IssuedAt, claims.ExpiresAt, checkTime); err != nil {
		return fmt.Errorf("aauth: person-token: %w", err)
	}
	if claims.ExpiresAt-claims.IssuedAt > int64(time.Hour.Seconds()) {
		return errors.New("aauth: person-token lifetime exceeds one hour")
	}
	if claims.MissionS256 != "" {
		if err := validateS256("person-token mission_s256", claims.MissionS256); err != nil {
			return err
		}
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
	if err := ValidateServerIdentifier(claims.PersonServer); err != nil {
		return fmt.Errorf("aauth: resource-token ps: %w", err)
	}
	if claims.Subject == "" {
		return errors.New("aauth: resource-token sub is required")
	}
	if claims.PresentedJTI == "" {
		return errors.New("aauth: resource-token presented_jti is required")
	}
	if claims.Agent != "" || claims.Mission != nil {
		return errors.New("aauth: resource-token must not contain agent or mission")
	}
	if claims.MissionS256 != "" {
		if err := validateS256("resource-token mission_s256", claims.MissionS256); err != nil {
			return err
		}
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
	if err := ValidateServerIdentifier(claims.PersonServer); err != nil {
		return fmt.Errorf("aauth: auth-token ps: %w", err)
	}
	if claims.DWK == PersonDiscoveryDocument && claims.PersonServer != claims.Issuer {
		return errors.New("aauth: person-server-issued auth-token ps must equal issuer")
	}
	if claims.Subject == "" {
		return errors.New("aauth: auth-token sub is required")
	}
	if claims.Agent != "" || claims.Actor != nil || claims.Mission != nil {
		return errors.New("aauth: auth-token must not contain agent, act, or mission")
	}
	if claims.MissionS256 != "" {
		if err := validateS256("auth-token mission_s256", claims.MissionS256); err != nil {
			return err
		}
	}
	if _, err := claims.Confirmation.JWK.PublicKey(); err != nil {
		return &TokenValidationError{
			Code:  TokenValidationInvalidKey,
			Cause: fmt.Errorf("aauth: auth-token cnf.jwk: %w", err),
		}
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

// ValidatePersonTokenContext applies the resource and proof-key checks that
// bind a verified person token to the request where it is presented.
func ValidatePersonTokenContext(
	claims PersonTokenClaims,
	resourceIdentifier string,
	requestKey jose.JWK,
) error {
	if err := ValidateServerIdentifier(resourceIdentifier); err != nil {
		return fmt.Errorf("aauth: person-token expected resource: %w", err)
	}
	if claims.Audience != resourceIdentifier {
		return fmt.Errorf("aauth: person-token audience %q does not match resource %q", claims.Audience, resourceIdentifier)
	}
	if !claims.Confirmation.JWK.Equal(requestKey) {
		return errors.New("aauth: person-token confirmation key does not match request key")
	}
	return nil
}

// ValidateCurrentAuthTokenContext applies request-context checks for the
// current person-token topology, whose auth tokens intentionally name no
// agent. The directed person and person-server namespace replace agent
// identity as the resource-facing subject.
func ValidateCurrentAuthTokenContext(
	claims AuthTokenClaims,
	resourceIdentifier string,
	personServer string,
	subject string,
	requestKey jose.JWK,
	requiredScopes []string,
) error {
	if claims.PersonServer == "" {
		return errors.New("aauth: current auth-token ps is required")
	}
	if err := ValidateServerIdentifier(resourceIdentifier); err != nil {
		return fmt.Errorf("aauth: auth-token expected resource: %w", err)
	}
	if err := ValidateServerIdentifier(personServer); err != nil {
		return fmt.Errorf("aauth: auth-token expected person server: %w", err)
	}
	if claims.Audience != resourceIdentifier {
		return fmt.Errorf("aauth: auth-token audience %q does not match resource %q", claims.Audience, resourceIdentifier)
	}
	if claims.PersonServer != personServer {
		return fmt.Errorf("aauth: auth-token ps %q does not match person server %q", claims.PersonServer, personServer)
	}
	if claims.Subject != subject {
		return fmt.Errorf("aauth: auth-token sub %q does not match person %q", claims.Subject, subject)
	}
	if !claims.Confirmation.JWK.Equal(requestKey) {
		return errors.New("aauth: auth-token confirmation key does not match request key")
	}
	return validateRequiredScopes(claims.Scope, requiredScopes)
}

func validateRequiredScopes(scope string, requiredScopes []string) error {
	granted := make(map[string]bool)
	for _, value := range strings.Fields(scope) {
		if granted[value] {
			return fmt.Errorf("aauth: auth-token contains duplicate scope %q", value)
		}
		granted[value] = true
	}
	for _, required := range requiredScopes {
		if required == "" || !granted[required] {
			return fmt.Errorf("aauth: auth-token does not grant required scope %q", required)
		}
	}
	return nil
}
