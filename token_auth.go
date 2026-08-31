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

// AuthTokenClaims are the current Core claims of an aa-auth+jwt.
type AuthTokenClaims struct {
	Issuer           string                     `json:"iss"`
	DWK              string                     `json:"dwk"`
	Audience         string                     `json:"aud"`
	JTI              string                     `json:"jti"`
	PersonServer     string                     `json:"ps"`
	Subject          string                     `json:"sub"`
	Confirmation     Confirmation               `json:"cnf"`
	IssuedAt         int64                      `json:"iat"`
	ExpiresAt        int64                      `json:"exp"`
	NotBefore        int64                      `json:"nbf,omitempty"`
	Scope            string                     `json:"scope,omitempty"`
	Account          *string                    `json:"account,omitempty"`
	MissionS256      string                     `json:"mission_s256,omitempty"`
	Tenant           string                     `json:"tenant,omitempty"`
	AdditionalClaims map[string]json.RawMessage `json:"-"`
}

var authTokenClaimNames = map[string]struct{}{
	"iss": {}, "dwk": {}, "aud": {}, "jti": {}, "ps": {}, "sub": {},
	"cnf": {}, "iat": {}, "exp": {}, "scope": {}, "account": {},
	"mission_s256": {}, "tenant": {}, "nbf": {},
}

// MintAuthToken creates a proof-bound authorization assertion.
func MintAuthToken(key jose.SigningKey, claims AuthTokenClaims) (string, error) {
	return mintAuthToken(key, claims, validateAuthTokenMembers)
}

// MintAuthTokenCore validates only the Core claim layer and deliberately
// leaves raw companion claims to a typed companion package. Calling it
// directly does not establish companion authorization.
func MintAuthTokenCore(key jose.SigningKey, claims AuthTokenClaims) (string, error) {
	return mintAuthToken(key, claims, validateAuthTokenCoreMembers)
}

func mintAuthToken(
	key jose.SigningKey,
	claims AuthTokenClaims,
	validateMembers func(map[string]json.RawMessage) error,
) (string, error) {
	if err := validateAuthClaims(claims, time.Time{}); err != nil {
		return "", err
	}
	payload, members, err := marshalAuthTokenClaims(claims)
	if err != nil {
		return "", err
	}
	if err := validateMembers(members); err != nil {
		return "", err
	}
	return mintTokenPayload(key, AuthTokenType, payload)
}

// VerifyAuthToken verifies compact-token trust and claims. Call
// ValidateCurrentAuthTokenContext to bind the result to one request.
// Known R3 and Budgets claims fail closed until their companion package is
// integrated with this API.
func VerifyAuthToken(ctx context.Context, compact string, resolver signaturekey.KeyResolver, clock Clock) (AuthTokenClaims, error) {
	return verifyAuthToken(ctx, compact, resolver, clock, validateAuthTokenMembers)
}

// VerifyAuthTokenCore verifies only Core trust and claims while returning
// immutable copies of raw companion claims. A typed companion verifier must
// consume every recognized authorization claim before policy or use.
func VerifyAuthTokenCore(
	ctx context.Context,
	compact string,
	resolver signaturekey.KeyResolver,
	clock Clock,
) (AuthTokenClaims, error) {
	return verifyAuthToken(ctx, compact, resolver, clock, validateAuthTokenCoreMembers)
}

func verifyAuthToken(
	ctx context.Context,
	compact string,
	resolver signaturekey.KeyResolver,
	clock Clock,
	validateMembers func(map[string]json.RawMessage) error,
) (AuthTokenClaims, error) {
	var claims AuthTokenClaims
	return verifyCoreToken(
		ctx, compact, AuthTokenType, []string{PersonDiscoveryDocument, AccessDiscoveryDocument}, resolver, clock,
		&claims,
		func(value AuthTokenClaims) (string, string) { return value.Issuer, value.DWK },
		validateMembers,
		validateAuthClaims,
	)
}

func validateAuthTokenMembers(members map[string]json.RawMessage) error {
	if err := validateAuthTokenCoreMembers(members); err != nil {
		return err
	}
	return rejectUnsupportedAuthorizationClaims(AuthTokenType, members)
}

func validateAuthTokenCoreMembers(members map[string]json.RawMessage) error {
	if err := rejectClaims(AuthTokenType, members, "the claim was removed from the current specification", "agent", "act", "mission", "r3_conditional"); err != nil {
		return err
	}
	if err := validateOptionalStringClaim(AuthTokenType, members, "scope", false); err != nil {
		return err
	}
	return validateOptionalStringClaim(AuthTokenType, members, "account", true)
}

func marshalAuthTokenClaims(claims AuthTokenClaims) ([]byte, map[string]json.RawMessage, error) {
	additional := claims.AdditionalClaims
	claims.AdditionalClaims = nil
	return marshalTokenClaims("auth-token", claims, additional, authTokenClaimNames)
}

func (claims *AuthTokenClaims) setTokenMembers(members map[string]json.RawMessage) {
	claims.AdditionalClaims = additionalTokenClaims(members, authTokenClaimNames)
}

func validateAuthClaims(claims AuthTokenClaims, now time.Time) error {
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
	if _, err := claims.Confirmation.JWK.PublicKey(); err != nil {
		return tokenKeyValidationError("auth-token cnf.jwk", err)
	}
	if err := validateTimes(claims.IssuedAt, claims.ExpiresAt, claims.NotBefore, now); err != nil {
		return fmt.Errorf("aauth: auth-token: %w", err)
	}
	if claims.Scope != "" {
		if _, err := ParseScope(claims.Scope); err != nil {
			return fmt.Errorf("aauth: auth-token scope: %w", err)
		}
	}
	if claims.ExpiresAt-claims.IssuedAt > int64(time.Hour.Seconds()) {
		return errors.New("aauth: auth-token lifetime exceeds one hour")
	}
	if claims.MissionS256 != "" {
		if err := validateS256("auth-token mission_s256", claims.MissionS256); err != nil {
			return err
		}
	}
	return nil
}

// AuthTokenContext names the request context that verified auth-token claims
// must match.
type AuthTokenContext struct {
	Issuer            string
	DiscoveryDocument string
	Resource          string
	PersonServer      string
	Subject           string
	RequestKey        jose.JWK
	RequiredScopes    []string
}

// ValidateCurrentAuthTokenContext binds verified claims to one request.
func ValidateCurrentAuthTokenContext(claims AuthTokenClaims, expected AuthTokenContext) error {
	if claims.PersonServer == "" {
		return errors.New("aauth: current auth-token ps is required")
	}
	if err := ValidateServerIdentifier(expected.Issuer); err != nil {
		return fmt.Errorf("aauth: auth-token expected issuer: %w", err)
	}
	if expected.DiscoveryDocument != PersonDiscoveryDocument && expected.DiscoveryDocument != AccessDiscoveryDocument {
		return errors.New("aauth: auth-token expected discovery document is invalid")
	}
	if err := ValidateServerIdentifier(expected.Resource); err != nil {
		return fmt.Errorf("aauth: auth-token expected resource: %w", err)
	}
	if err := ValidateServerIdentifier(expected.PersonServer); err != nil {
		return fmt.Errorf("aauth: auth-token expected person server: %w", err)
	}
	if claims.Audience != expected.Resource {
		return fmt.Errorf("aauth: auth-token audience %q does not match resource %q", claims.Audience, expected.Resource)
	}
	if claims.Issuer != expected.Issuer || claims.DWK != expected.DiscoveryDocument {
		return fmt.Errorf("aauth: auth-token issuer role %q/%q does not match %q/%q", claims.Issuer, claims.DWK, expected.Issuer, expected.DiscoveryDocument)
	}
	if claims.PersonServer != expected.PersonServer {
		return fmt.Errorf("aauth: auth-token ps %q does not match person server %q", claims.PersonServer, expected.PersonServer)
	}
	if claims.Subject != expected.Subject {
		return fmt.Errorf("aauth: auth-token sub %q does not match person %q", claims.Subject, expected.Subject)
	}
	if !claims.Confirmation.JWK.Equal(expected.RequestKey) {
		return errors.New("aauth: auth-token confirmation key does not match request key")
	}
	return validateRequiredScopes(claims.Scope, expected.RequiredScopes)
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
