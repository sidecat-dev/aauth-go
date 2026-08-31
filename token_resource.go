package aauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

// ResourceInteraction describes a resource-owned user interaction carried by
// a resource token.
type ResourceInteraction struct {
	URL  string `json:"url"`
	Code string `json:"code"`
}

// ResourceTokenClaims are the current Core claims of an aa-resource+jwt.
type ResourceTokenClaims struct {
	Issuer           string                     `json:"iss"`
	DWK              string                     `json:"dwk"`
	Audience         string                     `json:"aud"`
	JTI              string                     `json:"jti"`
	PersonServer     string                     `json:"ps"`
	Subject          string                     `json:"sub"`
	PresentedJTI     string                     `json:"presented_jti"`
	AgentJKT         string                     `json:"agent_jkt"`
	IssuedAt         int64                      `json:"iat"`
	ExpiresAt        int64                      `json:"exp"`
	NotBefore        int64                      `json:"nbf,omitempty"`
	Scope            string                     `json:"scope,omitempty"`
	Account          *string                    `json:"account,omitempty"`
	MissionS256      string                     `json:"mission_s256,omitempty"`
	Tenant           string                     `json:"tenant,omitempty"`
	Interaction      *ResourceInteraction       `json:"interaction,omitempty"`
	AdditionalClaims map[string]json.RawMessage `json:"-"`
}

var resourceTokenClaimNames = map[string]struct{}{
	"iss": {}, "dwk": {}, "aud": {}, "jti": {}, "ps": {}, "sub": {},
	"presented_jti": {}, "agent_jkt": {}, "iat": {}, "exp": {}, "nbf": {},
	"scope": {}, "account": {}, "mission_s256": {}, "tenant": {}, "interaction": {},
}

// MintResourceToken creates a short-lived resource assertion.
func MintResourceToken(key jose.SigningKey, claims ResourceTokenClaims) (string, error) {
	return mintResourceToken(key, claims, validateResourceClaims, validateResourceTokenMembers)
}

// MintResourceTokenCore validates only the Core claim layer and deliberately
// leaves raw companion claims to a typed companion package. Calling it
// directly does not establish companion authorization.
func MintResourceTokenCore(key jose.SigningKey, claims ResourceTokenClaims) (string, error) {
	return mintResourceToken(
		key, claims, validateResourceClaimsWithOptionalScope, validateResourceTokenCoreMembers,
	)
}

func mintResourceToken(
	key jose.SigningKey,
	claims ResourceTokenClaims,
	validateClaims func(ResourceTokenClaims, time.Time) error,
	validateMembers func(map[string]json.RawMessage) error,
) (string, error) {
	if err := validateClaims(claims, time.Time{}); err != nil {
		return "", err
	}
	payload, members, err := marshalResourceTokenClaims(claims, resourceTokenClaimNames)
	if err != nil {
		return "", err
	}
	if err := validateMembers(members); err != nil {
		return "", err
	}
	return mintTokenPayload(key, ResourceTokenType, payload)
}

// VerifyResourceToken verifies compact-token trust and claims. The caller must
// still bind the result to the agent, recipient, and retained person context.
// Known R3 and Budgets claims fail closed until their companion package is
// integrated with this API.
func VerifyResourceToken(ctx context.Context, compact string, resolver signaturekey.KeyResolver, clock Clock) (ResourceTokenClaims, error) {
	return verifyResourceToken(ctx, compact, resolver, clock, validateResourceTokenMembers, validateResourceClaims)
}

// VerifyResourceTokenCore verifies only Core trust and claims while returning
// immutable copies of raw companion claims. A typed companion verifier must
// consume every recognized authorization claim before policy or use.
func VerifyResourceTokenCore(
	ctx context.Context,
	compact string,
	resolver signaturekey.KeyResolver,
	clock Clock,
) (ResourceTokenClaims, error) {
	return verifyResourceToken(
		ctx, compact, resolver, clock,
		validateResourceTokenCoreMembers, validateResourceClaimsWithOptionalScope,
	)
}

func verifyResourceToken(
	ctx context.Context,
	compact string,
	resolver signaturekey.KeyResolver,
	clock Clock,
	validateMembers func(map[string]json.RawMessage) error,
	validateClaims func(ResourceTokenClaims, time.Time) error,
) (ResourceTokenClaims, error) {
	var claims ResourceTokenClaims
	return verifyCoreToken(
		ctx, compact, ResourceTokenType, []string{ResourceDiscoveryDocument}, resolver, clock,
		&claims,
		func(value ResourceTokenClaims) (string, string) { return value.Issuer, value.DWK },
		validateMembers,
		validateClaims,
	)
}

func validateResourceTokenCoreMembers(members map[string]json.RawMessage) error {
	if err := rejectClaims(ResourceTokenType, members, "the claim was removed from the current specification", "agent", "act", "mission", "r3_conditional"); err != nil {
		return err
	}
	if err := validateOptionalStringClaim(ResourceTokenType, members, "scope", false); err != nil {
		return err
	}
	return validateOptionalStringClaim(ResourceTokenType, members, "account", true)
}

func validateResourceTokenMembers(members map[string]json.RawMessage) error {
	if err := validateResourceTokenCoreMembers(members); err != nil {
		return err
	}
	return rejectUnsupportedAuthorizationClaims(ResourceTokenType, members)
}

func marshalResourceTokenClaims(
	claims ResourceTokenClaims,
	known map[string]struct{},
) ([]byte, map[string]json.RawMessage, error) {
	additional := claims.AdditionalClaims
	claims.AdditionalClaims = nil
	return marshalTokenClaims("resource-token", claims, additional, known)
}

func (claims *ResourceTokenClaims) setTokenMembers(members map[string]json.RawMessage) {
	claims.AdditionalClaims = additionalTokenClaims(members, resourceTokenClaimNames)
}

func validateResourceClaims(claims ResourceTokenClaims, now time.Time) error {
	if claims.Scope == "" {
		return errors.New("aauth: resource-token scope is required without a companion authorization claim")
	}
	return validateResourceClaimsWithOptionalScope(claims, now)
}

func validateResourceClaimsWithOptionalScope(claims ResourceTokenClaims, now time.Time) error {
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
	if claims.Scope != "" {
		if _, err := ParseScope(claims.Scope); err != nil {
			return fmt.Errorf("aauth: resource-token scope: %w", err)
		}
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
