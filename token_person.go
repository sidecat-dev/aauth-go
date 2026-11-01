package aauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

// PersonTokenClaims identify one person to one resource and bind that identity
// to the agent's current request key. A person token carries no authorization.
type PersonTokenClaims struct {
	Issuer       string       `json:"iss"`
	DWK          string       `json:"dwk"`
	Audience     string       `json:"aud"`
	Subject      string       `json:"sub"`
	Confirmation Confirmation `json:"cnf"`
	JTI          string       `json:"jti"`
	IssuedAt     int64        `json:"iat"`
	ExpiresAt    int64        `json:"exp"`
	NotBefore    int64        `json:"nbf,omitempty"`
	MissionS256  string       `json:"mission_s256,omitempty"`
	Tenant       string       `json:"tenant,omitempty"`
}

// readsSingleAudience lets verification read aud in either RFC 7519 form.
func (*PersonTokenClaims) readsSingleAudience() {}

// MintPersonToken constructs a proof-bound, resource-directed person token.
func MintPersonToken(key jose.SigningKey, claims PersonTokenClaims) (string, error) {
	if err := validatePersonClaims(claims, time.Time{}); err != nil {
		return "", err
	}
	return mintToken(key, PersonTokenType, claims)
}

// VerifyPersonToken verifies compact-token trust and claims. Call
// ValidatePersonTokenContext to bind the result to one resource and request key.
func VerifyPersonToken(ctx context.Context, compact string, resolver signaturekey.KeyResolver, clock Clock) (PersonTokenClaims, error) {
	var claims PersonTokenClaims
	return verifyCoreToken(
		ctx, compact, PersonTokenType, []string{PersonDiscoveryDocument}, resolver, clock,
		&claims,
		func(value PersonTokenClaims) (string, string) { return value.Issuer, value.DWK },
		func(members map[string]json.RawMessage) error {
			return rejectClaims(PersonTokenType, members, "a person token carries no authorization", "scope", "account")
		},
		validatePersonClaims,
	)
}

func validatePersonClaims(claims PersonTokenClaims, now time.Time) error {
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
		return tokenKeyValidationError("person-token cnf.jwk", err)
	}
	if err := validateTimes(claims.IssuedAt, claims.ExpiresAt, claims.NotBefore, now); err != nil {
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
