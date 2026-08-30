package aauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"aauth-go/jose"
	"aauth-go/signaturekey"
)

// ResourceInteraction describes a resource-owned user interaction carried by
// a resource token.
type ResourceInteraction struct {
	URL  string `json:"url"`
	Code string `json:"code"`
}

// ResourceTokenClaims are the current Core claims of an aa-resource+jwt.
type ResourceTokenClaims struct {
	Issuer       string               `json:"iss"`
	DWK          string               `json:"dwk"`
	Audience     string               `json:"aud"`
	JTI          string               `json:"jti"`
	PersonServer string               `json:"ps"`
	Subject      string               `json:"sub"`
	PresentedJTI string               `json:"presented_jti"`
	AgentJKT     string               `json:"agent_jkt"`
	IssuedAt     int64                `json:"iat"`
	ExpiresAt    int64                `json:"exp"`
	NotBefore    int64                `json:"nbf,omitempty"`
	Scope        string               `json:"scope"`
	Account      string               `json:"account,omitempty"`
	MissionS256  string               `json:"mission_s256,omitempty"`
	Tenant       string               `json:"tenant,omitempty"`
	Interaction  *ResourceInteraction `json:"interaction,omitempty"`
}

// MintResourceToken creates a short-lived resource assertion.
func MintResourceToken(key jose.SigningKey, claims ResourceTokenClaims) (string, error) {
	if err := validateResourceClaims(claims, time.Time{}); err != nil {
		return "", err
	}
	return mintToken(key, ResourceTokenType, claims)
}

// VerifyResourceToken verifies compact-token trust and claims. The caller must
// still bind the result to the agent, recipient, and retained person context.
// Known R3 and Budgets claims fail closed until their companion package is
// integrated with this API.
func VerifyResourceToken(ctx context.Context, compact string, resolver signaturekey.KeyResolver, clock Clock) (ResourceTokenClaims, error) {
	var claims ResourceTokenClaims
	return verifyCoreToken(
		ctx, compact, ResourceTokenType, []string{ResourceDiscoveryDocument}, resolver, clock,
		&claims,
		func(value ResourceTokenClaims) (string, string) { return value.Issuer, value.DWK },
		func(members map[string]json.RawMessage) error {
			if err := rejectClaims(ResourceTokenType, members, "the claim was removed from the current specification", "agent", "act", "mission", "r3_conditional"); err != nil {
				return err
			}
			return rejectUnsupportedAuthorizationClaims(ResourceTokenType, members)
		},
		validateResourceClaims,
	)
}

func validateResourceClaims(claims ResourceTokenClaims, now time.Time) error {
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
	if err := validateS256("resource-token agent_jkt", claims.AgentJKT); err != nil {
		return err
	}
	if _, err := ParseScope(claims.Scope); err != nil {
		return fmt.Errorf("aauth: resource-token scope: %w", err)
	}
	if err := validateTimes(claims.IssuedAt, claims.ExpiresAt, claims.NotBefore, now); err != nil {
		return fmt.Errorf("aauth: resource-token: %w", err)
	}
	if claims.MissionS256 != "" {
		if err := validateS256("resource-token mission_s256", claims.MissionS256); err != nil {
			return err
		}
	}
	if claims.Interaction != nil {
		if err := ValidateEndpoint(claims.Interaction.URL); err != nil {
			return fmt.Errorf("aauth: resource-token interaction url: %w", err)
		}
		if err := validateInteractionCode(claims.Interaction.Code); err != nil {
			return fmt.Errorf("aauth: resource-token interaction code: %w", err)
		}
	}
	return nil
}

func validateInteractionCode(code string) error {
	const alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
	symbols := 0
	for _, character := range code {
		if character == '-' {
			continue
		}
		if !strings.ContainsRune(alphabet, character) {
			return errors.New("code must use uppercase Crockford base32")
		}
		symbols++
	}
	if symbols < 8 {
		return errors.New("code must contain at least eight symbols")
	}
	return nil
}
