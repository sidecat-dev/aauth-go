package aauth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

const (
	SubscribeTokenType = "aa-subscribe+jwt"
	EventTokenType     = "aa-event+jwt"
)

// SubscribeTokenClaims authorize one agent to register an event subscription
// at one resource. MaxUses is optional at the portable token layer; a host
// profile decides which positive values it admits.
type SubscribeTokenClaims struct {
	Issuer       string       `json:"iss"`
	DWK          string       `json:"dwk"`
	Subject      string       `json:"sub"`
	Audience     string       `json:"aud"`
	Confirmation Confirmation `json:"cnf"`
	EventID      string       `json:"eid"`
	IssuedAt     int64        `json:"iat"`
	ExpiresAt    int64        `json:"exp"`
	MaxUses      *int         `json:"max_uses,omitempty"`
}

// EventTokenClaims identify a payload-free event. Event data is deliberately
// outside the M5 token shape.
type EventTokenClaims struct {
	Issuer    string `json:"iss"`
	DWK       string `json:"dwk"`
	Audience  string `json:"aud"`
	EventID   string `json:"eid"`
	IssuedAt  int64  `json:"iat"`
	ExpiresAt int64  `json:"exp"`
}

// VerifiedSelfJWT contains raw claims only after the compact JWS has been
// verified with the same discovered key used for the HTTP Message Signature.
// Application profiles must decode Claims through a profile-specific decoder.
type VerifiedSelfJWT struct {
	Header jose.Header
	Issuer string
	DWK    string
	Claims json.RawMessage

	verified jose.VerifiedCompact
	issuer   string
	dwk      string
}

// MintSubscribeToken creates a strictly shaped public subscription token.
func MintSubscribeToken(key jose.SigningKey, claims SubscribeTokenClaims) (string, error) {
	if err := validateSubscribeTokenClaims(claims, time.Unix(claims.IssuedAt, 0)); err != nil {
		return "", err
	}
	return mintToken(key, SubscribeTokenType, claims)
}

// VerifySubscribeToken verifies issuer discovery, compact-JWS integrity, and
// the complete public subscription claim shape.
func VerifySubscribeToken(
	ctx context.Context,
	compact string,
	resolver signaturekey.KeyResolver,
	clock Clock,
) (SubscribeTokenClaims, error) {
	var claims SubscribeTokenClaims
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
	if header.Type != SubscribeTokenType {
		return claims, fmt.Errorf("aauth: token typ is %q, want %q", header.Type, SubscribeTokenType)
	}
	if err := decodeStrictJSON(payload, &claims); err != nil {
		return claims, fmt.Errorf("aauth: decode %s claims: %w", SubscribeTokenType, err)
	}
	if claims.DWK != AgentDiscoveryDocument {
		return claims, fmt.Errorf("aauth: subscribe-token dwk is %q, want %q", claims.DWK, AgentDiscoveryDocument)
	}
	if _, err := verifyResolvedTokenKey(
		ctx,
		parsed,
		claims.Issuer,
		claims.DWK,
		resolver,
	); err != nil {
		return claims, err
	}
	if err := validateSubscribeTokenClaims(claims, clock.Now()); err != nil {
		return claims, err
	}
	return claims, nil
}

// MintEventToken creates a strictly shaped, payload-free event token.
func MintEventToken(key jose.SigningKey, claims EventTokenClaims) (string, error) {
	if err := validateEventTokenClaims(claims, time.Unix(claims.IssuedAt, 0)); err != nil {
		return "", err
	}
	return mintToken(key, EventTokenType, claims)
}

// VerifyEventToken independently verifies a compact event JWS with the
// resource key selected by its exact issuer and discovery document.
func VerifyEventToken(
	ctx context.Context,
	compact string,
	resolver signaturekey.KeyResolver,
	clock Clock,
) (EventTokenClaims, error) {
	var claims EventTokenClaims
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
	if header.Type != EventTokenType {
		return claims, fmt.Errorf("aauth: token typ is %q, want %q", header.Type, EventTokenType)
	}
	if err := decodeStrictJSON(payload, &claims); err != nil {
		return claims, fmt.Errorf("aauth: decode %s claims: %w", EventTokenType, err)
	}
	if claims.DWK != ResourceDiscoveryDocument {
		return claims, fmt.Errorf("aauth: event-token dwk is %q, want %q", claims.DWK, ResourceDiscoveryDocument)
	}
	if _, err := verifyResolvedTokenKey(
		ctx,
		parsed,
		claims.Issuer,
		claims.DWK,
		resolver,
	); err != nil {
		return claims, err
	}
	if err := validateEventTokenClaims(claims, clock.Now()); err != nil {
		return claims, err
	}
	return claims, nil
}

// DecodeVerifiedEventToken applies the Events application policy to claims
// retained by generic self-jwt verification. It never accepts an unverified
// compact JWT.
func DecodeVerifiedEventToken(verified VerifiedSelfJWT, clock Clock) (EventTokenClaims, error) {
	var claims EventTokenClaims
	if clock == nil {
		return claims, errors.New("aauth: clock is required")
	}
	if verified.issuer != verified.Issuer || verified.dwk != verified.DWK {
		return claims, errors.New("aauth: event token requires intact verified self-jwt claims")
	}
	sealedHeader, err := verified.verified.Header()
	if err != nil || sealedHeader != verified.Header {
		return claims, errors.New("aauth: event token requires intact verified self-jwt claims")
	}
	sealedClaims, err := verified.verified.Payload()
	if err != nil || !bytes.Equal(sealedClaims, verified.Claims) {
		return claims, errors.New("aauth: event token requires intact verified self-jwt claims")
	}
	if sealedHeader.Type != EventTokenType {
		return claims, fmt.Errorf("aauth: token typ is %q, want %q", sealedHeader.Type, EventTokenType)
	}
	if sealedHeader.Algorithm != jose.Ed25519Algorithm || sealedHeader.KeyID == "" {
		return claims, errors.New("aauth: verified event token header is invalid")
	}
	if len(verified.Claims) == 0 {
		return claims, errors.New("aauth: verified event token claims are required")
	}
	if err := rejectDuplicateJSONNames(verified.Claims); err != nil {
		return claims, fmt.Errorf("aauth: parse event-token claims: %w", err)
	}
	if err := decodeStrictJSON(verified.Claims, &claims); err != nil {
		return claims, fmt.Errorf("aauth: decode event-token claims: %w", err)
	}
	if claims.Issuer != verified.Issuer || claims.DWK != verified.DWK {
		return claims, errors.New("aauth: event-token verified locator does not match claims")
	}
	if err := validateEventTokenClaims(claims, clock.Now()); err != nil {
		return claims, err
	}
	return claims, nil
}

func newVerifiedSelfJWT(compact jose.VerifiedCompact, issuer, dwk string) VerifiedSelfJWT {
	header, headerErr := compact.Header()
	claims, claimsErr := compact.Payload()
	if headerErr != nil || claimsErr != nil {
		return VerifiedSelfJWT{}
	}
	verified := VerifiedSelfJWT{
		Header:   header,
		Issuer:   issuer,
		DWK:      dwk,
		Claims:   append(json.RawMessage(nil), claims...),
		verified: compact,
		issuer:   issuer,
		dwk:      dwk,
	}
	return verified
}

func validateSubscribeTokenClaims(claims SubscribeTokenClaims, now time.Time) error {
	if err := ValidateServerIdentifier(claims.Issuer); err != nil {
		return fmt.Errorf("aauth: subscribe-token issuer: %w", err)
	}
	if claims.DWK != AgentDiscoveryDocument {
		return errors.New("aauth: subscribe-token dwk is invalid")
	}
	if err := ValidateAgentIdentifier(claims.Subject); err != nil {
		return fmt.Errorf("aauth: subscribe-token subject: %w", err)
	}
	if err := ValidateServerIdentifier(claims.Audience); err != nil {
		return fmt.Errorf("aauth: subscribe-token audience: %w", err)
	}
	if _, err := claims.Confirmation.JWK.PublicKey(); err != nil {
		return &TokenValidationError{
			Code:  TokenValidationInvalidKey,
			Cause: fmt.Errorf("aauth: subscribe-token cnf.jwk: %w", err),
		}
	}
	if claims.EventID == "" {
		return errors.New("aauth: subscribe-token eid is required")
	}
	if err := validateTimes(claims.IssuedAt, claims.ExpiresAt, now); err != nil {
		return fmt.Errorf("aauth: subscribe-token: %w", err)
	}
	if claims.MaxUses != nil && *claims.MaxUses <= 0 {
		return errors.New("aauth: subscribe-token max_uses must be positive")
	}
	return nil
}

func validateEventTokenClaims(claims EventTokenClaims, now time.Time) error {
	if err := ValidateServerIdentifier(claims.Issuer); err != nil {
		return fmt.Errorf("aauth: event-token issuer: %w", err)
	}
	if claims.DWK != ResourceDiscoveryDocument {
		return errors.New("aauth: event-token dwk is invalid")
	}
	if err := ValidateAgentIdentifier(claims.Audience); err != nil {
		return fmt.Errorf("aauth: event-token audience: %w", err)
	}
	if claims.EventID == "" {
		return errors.New("aauth: event-token eid is required")
	}
	if err := validateTimes(claims.IssuedAt, claims.ExpiresAt, now); err != nil {
		return fmt.Errorf("aauth: event-token: %w", err)
	}
	return nil
}

func decodeStrictJSON(value []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(value))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values are not allowed")
		}
		return err
	}
	return nil
}
