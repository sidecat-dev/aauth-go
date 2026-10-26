// Package events implements the reusable values and validation rules from the
// AAuth Events companion specification. Role-specific HTTP handlers and host
// storage remain in agentprovider, resource, and agent.
package events

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/internal/jsonstrict"
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

const (
	// SubscribeTokenType is the explicit JWT type of an AP-issued subscribe token.
	SubscribeTokenType = "aa-subscribe+jwt"
	// EventTokenType is the explicit JWT type of a Resource-issued event token.
	EventTokenType = "aa-event+jwt"
)

// SubscribeTokenRequest is the issuer-validated input to subscribe-token
// creation. Zero MaxUses means the token carries no use limit.
type SubscribeTokenRequest struct {
	Agent           string
	Resource        string
	ConfirmationKey jose.JWK
	EventID         string
	Lifetime        time.Duration
	MaxUses         int64
}

// SubscribeTokenClaims are the claims of an aa-subscribe+jwt.
type SubscribeTokenClaims struct {
	Issuer       string             `json:"iss"`
	DWK          string             `json:"dwk"`
	Subject      string             `json:"sub"`
	Audience     string             `json:"aud"`
	Confirmation aauth.Confirmation `json:"cnf"`
	EventID      string             `json:"eid"`
	IssuedAt     int64              `json:"iat"`
	ExpiresAt    int64              `json:"exp"`
	MaxUses      int64              `json:"max_uses,omitempty"`
}

// EventTokenRequest is the Resource-validated input to event-token creation.
type EventTokenRequest struct {
	Agent    string
	EventID  string
	JTI      string
	Lifetime time.Duration
}

// EventTokenClaims are the claims of an aa-event+jwt.
type EventTokenClaims struct {
	Issuer    string `json:"iss"`
	DWK       string `json:"dwk"`
	Audience  string `json:"aud"`
	EventID   string `json:"eid"`
	JTI       string `json:"jti"`
	IssuedAt  int64  `json:"iat"`
	ExpiresAt int64  `json:"exp"`
}

// MintSubscribeToken creates one AP-signed subscribe token.
func MintSubscribeToken(
	issuer string,
	key jose.SigningKey,
	request SubscribeTokenRequest,
	now time.Time,
) (string, error) {
	now = now.UTC().Truncate(time.Second)
	claims := SubscribeTokenClaims{
		Issuer:       issuer,
		DWK:          aauth.AgentDiscoveryDocument,
		Subject:      request.Agent,
		Audience:     request.Resource,
		Confirmation: aauth.Confirmation{JWK: request.ConfirmationKey},
		EventID:      request.EventID,
		IssuedAt:     now.Unix(),
		ExpiresAt:    now.Add(request.Lifetime).Unix(),
		MaxUses:      request.MaxUses,
	}
	if err := validateSubscribeClaims(claims, time.Time{}, request.MaxUses != 0); err != nil {
		return "", err
	}
	return signToken(key, SubscribeTokenType, claims)
}

// VerifySubscribeToken verifies an AP-issued subscribe token and its claims.
// A Resource must separately bind Audience to itself and Confirmation to the
// key that verified the subscription-registration request.
func VerifySubscribeToken(
	ctx context.Context,
	compact string,
	resolver signaturekey.KeyResolver,
	clock aauth.Clock,
) (SubscribeTokenClaims, error) {
	var claims SubscribeTokenClaims
	payload, err := verifyToken(ctx, compact, SubscribeTokenType, aauth.AgentDiscoveryDocument, false, resolver, clock)
	if err != nil {
		return claims, err
	}
	if err := jsonstrict.RejectCaseVariants(payload, &claims); err != nil {
		return claims, fmt.Errorf("aauth events: decode subscribe-token claims: %w", err)
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(payload, &members); err != nil {
		return claims, fmt.Errorf("aauth events: decode subscribe-token claims: %w", err)
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return claims, fmt.Errorf("aauth events: decode subscribe-token claims: %w", err)
	}
	_, hasMaxUses := members["max_uses"]
	if err := validateSubscribeClaims(claims, clock.Now().UTC(), hasMaxUses); err != nil {
		return SubscribeTokenClaims{}, err
	}
	return claims, nil
}

// ValidateSubscribeRegistration binds verified subscribe-token claims to the
// Resource receiving the registration and the key that verified its outer
// HTTP request.
func ValidateSubscribeRegistration(
	claims SubscribeTokenClaims,
	resource string,
	requestKey jose.JWK,
) error {
	if err := validateSubscribeClaims(claims, time.Time{}, claims.MaxUses != 0); err != nil {
		return err
	}
	if claims.Audience != resource {
		return errors.New("aauth events: subscribe-token audience does not match Resource")
	}
	if !claims.Confirmation.JWK.Equal(requestKey) {
		return errors.New("aauth events: subscribe-token confirmation key does not match request proof")
	}
	return nil
}

// MintEventToken creates one Resource-signed event token. Event-specific data
// belongs in the delivery body, not in this token.
func MintEventToken(
	issuer string,
	key jose.SigningKey,
	request EventTokenRequest,
	now time.Time,
) (string, error) {
	now = now.UTC().Truncate(time.Second)
	jti := request.JTI
	if jti == "" {
		generated, err := newEventTokenID()
		if err != nil {
			return "", err
		}
		jti = generated
	}
	claims := EventTokenClaims{
		Issuer:    issuer,
		DWK:       aauth.ResourceDiscoveryDocument,
		Audience:  request.Agent,
		EventID:   request.EventID,
		JTI:       jti,
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(request.Lifetime).Unix(),
	}
	if err := validateEventClaims(claims, time.Time{}); err != nil {
		return "", err
	}
	return signToken(key, EventTokenType, claims)
}

// VerifyEventToken verifies a Resource-issued event token received by an
// Agent after local AP delivery.
func VerifyEventToken(
	ctx context.Context,
	compact string,
	resolver signaturekey.KeyResolver,
	clock aauth.Clock,
) (EventTokenClaims, error) {
	var claims EventTokenClaims
	payload, err := verifyToken(ctx, compact, EventTokenType, aauth.ResourceDiscoveryDocument, true, resolver, clock)
	if err != nil {
		return claims, err
	}
	if err := decodeEventClaims(payload, &claims); err != nil {
		return claims, err
	}
	if err := validateEventClaims(claims, clock.Now().UTC()); err != nil {
		return EventTokenClaims{}, err
	}
	return claims, nil
}

// ValidateEventTokenProfile checks the untrusted compact token's explicit
// Events shape and time window without establishing signature trust. It lets
// an HTTP endpoint distinguish malformed input from later cryptographic
// authentication failure. Callers must still use VerifyEventToken or a
// verified self-jwt assertion before accepting the claims.
func ValidateEventTokenProfile(compact string, at time.Time) error {
	parsed, err := jose.ParseCompact(compact)
	if err != nil {
		return fmt.Errorf("aauth events: parse event token: %w", err)
	}
	header := parsed.Header()
	if header.Type != EventTokenType {
		return fmt.Errorf("aauth events: event-token typ is %q, want %q", header.Type, EventTokenType)
	}
	if header.Algorithm != jose.Ed25519Algorithm {
		return fmt.Errorf("aauth events: event-token algorithm is %q, want %q", header.Algorithm, jose.Ed25519Algorithm)
	}
	if header.KeyID == "" {
		return errors.New("aauth events: event-token kid is required")
	}
	var claims EventTokenClaims
	if err := decodeEventClaims(parsed.Payload(), &claims); err != nil {
		return err
	}
	return validateEventClaims(claims, at.UTC())
}

// EventTokenFromAssertion validates Events claims inside a self-jwt assertion
// whose JWT and accompanying HTTP request were already verified together.
func EventTokenFromAssertion(
	assertion signaturekey.SelfJWTAssertion,
	verifiedAt time.Time,
) (EventTokenClaims, error) {
	var claims EventTokenClaims
	if err := decodeEventClaims(assertion.Payload(), &claims); err != nil {
		return claims, err
	}
	if claims.Issuer != assertion.Issuer() || claims.DWK != assertion.DiscoveryDocument() ||
		claims.ExpiresAt != assertion.ExpiresAt().Unix() {
		return EventTokenClaims{}, errors.New("aauth events: event token does not match its verified self-jwt assertion")
	}
	if err := validateEventClaims(claims, verifiedAt.UTC()); err != nil {
		return EventTokenClaims{}, err
	}
	return claims, nil
}

func signToken(key jose.SigningKey, tokenType string, claims any) (string, error) {
	if key.ID() == "" {
		return "", errors.New("aauth events: signing key is required")
	}
	if _, err := key.PublicJWK().PublicKey(); err != nil {
		return "", fmt.Errorf("aauth events: signing key: %w", err)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("aauth events: marshal %s claims: %w", tokenType, err)
	}
	return jose.SignCompact(key, jose.Header{
		Algorithm: jose.Ed25519Algorithm,
		Type:      tokenType,
		KeyID:     key.ID(),
	}, payload)
}

func verifyToken(
	ctx context.Context,
	compact string,
	expectedType string,
	expectedDiscoveryDocument string,
	forbidConfirmation bool,
	resolver signaturekey.KeyResolver,
	clock aauth.Clock,
) ([]byte, error) {
	if ctx == nil {
		return nil, errors.New("aauth events: verification context is required")
	}
	if resolver == nil {
		return nil, errors.New("aauth events: key resolver is required")
	}
	if clock == nil {
		return nil, errors.New("aauth events: clock is required")
	}
	parsed, err := jose.ParseCompact(compact)
	if err != nil {
		return nil, err
	}
	header := parsed.Header()
	if header.Type != expectedType {
		return nil, fmt.Errorf("aauth events: token typ is %q, want %q", header.Type, expectedType)
	}
	if header.Algorithm != jose.Ed25519Algorithm {
		return nil, &aauth.TokenValidationError{
			Code:  aauth.TokenValidationUnsupportedAlgorithm,
			Cause: fmt.Errorf("aauth events: unsupported token algorithm %q", header.Algorithm),
		}
	}
	if header.KeyID == "" {
		return nil, errors.New("aauth events: token kid is required")
	}
	payload := parsed.Payload()
	if forbidConfirmation {
		var forbidden struct {
			Confirmation json.RawMessage `json:"cnf"`
		}
		if err := jsonstrict.RejectCaseVariants(payload, &forbidden); err != nil {
			return nil, fmt.Errorf("aauth events: decode token claims: %w", err)
		}
		var members map[string]json.RawMessage
		if err := json.Unmarshal(payload, &members); err != nil {
			return nil, fmt.Errorf("aauth events: decode token claims: %w", err)
		}
		if _, present := members["cnf"]; present {
			return nil, errors.New("aauth events: event token must not contain cnf")
		}
	}
	var locator struct {
		Issuer string `json:"iss"`
		DWK    string `json:"dwk"`
	}
	if err := jsonstrict.RejectCaseVariants(payload, &locator); err != nil {
		return nil, fmt.Errorf("aauth events: decode token claims: %w", err)
	}
	if err := json.Unmarshal(payload, &locator); err != nil {
		return nil, fmt.Errorf("aauth events: decode token claims: %w", err)
	}
	if err := aauth.ValidateServerIdentifier(locator.Issuer); err != nil {
		return nil, fmt.Errorf("aauth events: token issuer: %w", err)
	}
	if err := signaturekey.ValidateDiscoveryName(locator.DWK); err != nil {
		return nil, errors.New("aauth events: token discovery document is invalid")
	}
	if locator.DWK != expectedDiscoveryDocument {
		return nil, fmt.Errorf("aauth events: token dwk is %q, want %q", locator.DWK, expectedDiscoveryDocument)
	}
	key, err := resolver.ResolveKey(ctx, locator.Issuer, locator.DWK, header.KeyID)
	if err != nil {
		return nil, signaturekey.NormalizeResolutionError(err)
	}
	verified, err := parsed.Verify(key)
	if err != nil {
		if refresher, ok := resolver.(signaturekey.KeyRefresher); ok {
			key, refreshErr := refresher.RefreshKey(ctx, locator.Issuer, locator.DWK, header.KeyID)
			if refreshErr == nil {
				verified, err = parsed.Verify(key)
			} else {
				err = signaturekey.NormalizeResolutionError(refreshErr)
			}
		}
		if err != nil {
			return nil, err
		}
	}
	return verified.Payload()
}

func validateSubscribeClaims(claims SubscribeTokenClaims, now time.Time, hasMaxUses bool) error {
	if err := aauth.ValidateServerIdentifier(claims.Issuer); err != nil {
		return fmt.Errorf("aauth events: subscribe-token issuer: %w", err)
	}
	if claims.DWK != aauth.AgentDiscoveryDocument {
		return errors.New("aauth events: subscribe-token dwk is invalid")
	}
	if err := aauth.ValidateAgentIdentifier(claims.Subject); err != nil {
		return fmt.Errorf("aauth events: subscribe-token subject: %w", err)
	}
	if err := aauth.ValidateAgentIssuer(claims.Subject, claims.Issuer); err != nil {
		return fmt.Errorf("aauth events: subscribe-token subject: %w", err)
	}
	if err := aauth.ValidateServerIdentifier(claims.Audience); err != nil {
		return fmt.Errorf("aauth events: subscribe-token audience: %w", err)
	}
	if _, err := claims.Confirmation.JWK.PublicKey(); err != nil {
		return fmt.Errorf("aauth events: subscribe-token cnf.jwk: %w", err)
	}
	if claims.EventID == "" {
		return errors.New("aauth events: subscribe-token eid is required")
	}
	if hasMaxUses && claims.MaxUses <= 0 {
		return errors.New("aauth events: subscribe-token max_uses must be a positive integer")
	}
	return validateTimes("subscribe-token", claims.IssuedAt, claims.ExpiresAt, now)
}

func decodeEventClaims(payload []byte, claims *EventTokenClaims) error {
	if err := jsonstrict.RejectCaseVariants(payload, claims); err != nil {
		return fmt.Errorf("aauth events: decode event-token claims: %w", err)
	}
	var forbidden struct {
		Confirmation json.RawMessage `json:"cnf"`
	}
	if err := jsonstrict.RejectCaseVariants(payload, &forbidden); err != nil {
		return fmt.Errorf("aauth events: decode event-token claims: %w", err)
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(payload, &members); err != nil {
		return fmt.Errorf("aauth events: decode event-token claims: %w", err)
	}
	if _, present := members["cnf"]; present {
		return errors.New("aauth events: event token must not contain cnf")
	}
	if err := json.Unmarshal(payload, claims); err != nil {
		return fmt.Errorf("aauth events: decode event-token claims: %w", err)
	}
	return nil
}

func validateEventClaims(claims EventTokenClaims, now time.Time) error {
	if err := aauth.ValidateServerIdentifier(claims.Issuer); err != nil {
		return fmt.Errorf("aauth events: event-token issuer: %w", err)
	}
	if claims.DWK != aauth.ResourceDiscoveryDocument {
		return errors.New("aauth events: event-token dwk is invalid")
	}
	if err := aauth.ValidateAgentIdentifier(claims.Audience); err != nil {
		return fmt.Errorf("aauth events: event-token audience: %w", err)
	}
	if claims.EventID == "" {
		return errors.New("aauth events: event-token eid is required")
	}
	if claims.JTI == "" {
		return errors.New("aauth events: event-token jti is required")
	}
	return validateTimes("event-token", claims.IssuedAt, claims.ExpiresAt, now)
}

func newEventTokenID() (string, error) {
	var buf [16]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", fmt.Errorf("aauth events: event-token jti: %w", err)
	}
	return hex.EncodeToString(buf[:]), nil
}

func validateTimes(name string, issuedAt, expiresAt int64, now time.Time) error {
	if issuedAt <= 0 || expiresAt <= issuedAt {
		return fmt.Errorf("aauth events: %s iat and exp must define a positive lifetime", name)
	}
	if now.IsZero() {
		return nil
	}
	if issuedAt > now.Unix() {
		return fmt.Errorf("aauth events: %s iat is in the future", name)
	}
	if expiresAt <= now.Unix() {
		return &aauth.TokenValidationError{
			Code:  aauth.TokenValidationExpired,
			Cause: fmt.Errorf("aauth events: %s is expired", name),
		}
	}
	return nil
}
