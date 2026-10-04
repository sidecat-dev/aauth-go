package aauth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

var (
	// ErrInvalidPresentedToken maps to invalid_presented_token.
	ErrInvalidPresentedToken = errors.New("aauth: presented token is invalid")
	// ErrExpiredPresentedToken maps to expired_presented_token.
	ErrExpiredPresentedToken = errors.New("aauth: presented token is expired")
	// ErrPresentedTokenMismatch means a verified presented token is not the
	// one the resource token names; it maps to invalid_resource_token.
	ErrPresentedTokenMismatch = errors.New("aauth: resource token does not match the presented token")
)

// PresentedToken is a verified presented_token of either type. Exactly one of
// Person and Auth is set.
type PresentedToken struct {
	Type         string
	Issuer       string
	JTI          string
	PersonServer string
	Subject      string
	MissionS256  string
	Tenant       string
	ExpiresAt    time.Time
	Person       *PersonTokenClaims
	Auth         *AuthTokenClaims
}

// VerifyPresentedToken verifies the presented_token of a token request
// against the already verified resource token that names it. An auth token is
// verified at the Core layer only: it returns raw companion claims and does
// not establish Budgets or R3 authority. The caller still checks that the
// named Person Server is the expected one, and revocation.
func VerifyPresentedToken(
	ctx context.Context,
	compact string,
	resource ResourceTokenClaims,
	resolver signaturekey.KeyResolver,
	clock Clock,
) (PresentedToken, error) {
	parsed, err := jose.ParseCompact(compact)
	if err != nil {
		return PresentedToken{}, fmt.Errorf("%w: %w", ErrInvalidPresentedToken, err)
	}
	var presented PresentedToken
	var audience string
	var confirmation jose.JWK
	switch tokenType := parsed.Header().Type; tokenType {
	case PersonTokenType:
		claims, err := VerifyPersonToken(ctx, compact, resolver, clock)
		if err != nil {
			return PresentedToken{}, presentedTokenFailure(err)
		}
		presented = PresentedToken{
			Type: tokenType, Issuer: claims.Issuer, JTI: claims.JTI, PersonServer: claims.Issuer,
			Subject: claims.Subject, MissionS256: claims.MissionS256, Tenant: claims.Tenant,
			ExpiresAt: time.Unix(claims.ExpiresAt, 0).UTC(), Person: &claims,
		}
		audience, confirmation = claims.Audience, claims.Confirmation.JWK
	case AuthTokenType:
		claims, err := VerifyAuthTokenCore(ctx, compact, resolver, clock)
		if err != nil {
			return PresentedToken{}, presentedTokenFailure(err)
		}
		presented = PresentedToken{
			Type: tokenType, Issuer: claims.Issuer, JTI: claims.JTI, PersonServer: claims.PersonServer,
			Subject: claims.Subject, MissionS256: claims.MissionS256, Tenant: claims.Tenant,
			ExpiresAt: time.Unix(claims.ExpiresAt, 0).UTC(), Auth: &claims,
		}
		audience, confirmation = claims.Audience, claims.Confirmation.JWK
	default:
		return PresentedToken{}, fmt.Errorf("%w: typ is %q", ErrInvalidPresentedToken, tokenType)
	}
	if audience != resource.Issuer {
		return PresentedToken{}, fmt.Errorf("%w: audience %q is not the resource %q", ErrInvalidPresentedToken, audience, resource.Issuer)
	}
	thumbprint, err := confirmation.Thumbprint()
	if err != nil || thumbprint != resource.AgentJKT {
		return PresentedToken{}, fmt.Errorf("%w: confirmation key does not match agent_jkt", ErrInvalidPresentedToken)
	}
	if presented.JTI != resource.PresentedJTI || presented.PersonServer != resource.PersonServer ||
		presented.Subject != resource.Subject || presented.MissionS256 != resource.MissionS256 ||
		presented.Tenant != resource.Tenant {
		return PresentedToken{}, ErrPresentedTokenMismatch
	}
	return presented, nil
}

func presentedTokenFailure(err error) error {
	var validation *TokenValidationError
	if errors.As(err, &validation) && validation.Code == TokenValidationExpired {
		return fmt.Errorf("%w: %w", ErrExpiredPresentedToken, err)
	}
	return fmt.Errorf("%w: %w", ErrInvalidPresentedToken, err)
}
