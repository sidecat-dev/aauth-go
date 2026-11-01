package accessserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/internal/upstreamtoken"
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

// verifiedUpstream is a verified upstream_token. Exactly one of person and
// auth is set.
type verifiedUpstream struct {
	person *aauth.PersonTokenClaims
	auth   *aauth.AuthTokenClaims
}

func (upstream *verifiedUpstream) expiresAt() time.Time {
	if upstream.person != nil {
		return time.Unix(upstream.person.ExpiresAt, 0).UTC()
	}
	return time.Unix(upstream.auth.ExpiresAt, 0).UTC()
}

// reference is the upstream token's (iss, jti), the key of any revocation of it.
func (upstream *verifiedUpstream) reference() aauth.TokenReference {
	if upstream.person != nil {
		return aauth.TokenReference{Issuer: upstream.person.Issuer, JTI: upstream.person.JTI}
	}
	return aauth.TokenReference{Issuer: upstream.auth.Issuer, JTI: upstream.auth.JTI}
}

func (upstream *verifiedUpstream) issuedAt() time.Time {
	if upstream.person != nil {
		return time.Unix(upstream.person.IssuedAt, 0)
	}
	return time.Unix(upstream.auth.IssuedAt, 0)
}

// policyClaims returns independent copies for authorization policy.
func (upstream *verifiedUpstream) policyClaims() (*aauth.AuthTokenClaims, *aauth.PersonTokenClaims) {
	if upstream == nil {
		return nil, nil
	}
	if upstream.person != nil {
		claims := *upstream.person
		return nil, &claims
	}
	claims := *upstream.auth
	claims.Account = cloneStringPointer(claims.Account)
	claims.AdditionalClaims = cloneClaims(claims.AdditionalClaims)
	return &claims, nil
}

type upstreamTokenFailure struct{ cause error }

func (failure *upstreamTokenFailure) Error() string { return failure.cause.Error() }
func (failure *upstreamTokenFailure) Unwrap() error { return failure.cause }

// verifyUpstreamToken applies Upstream Token Verification at an Access
// Server. typ selects the person-token or auth-token verifier, and any other
// typ is refused. aud must be the intermediary: the iss of the Agent token that
// the Person Server passed for the intermediary. The token's cnf is the
// calling Agent's key and is compared with nothing here. A person token's iss,
// or an auth token's ps, must be the Person Server that signed this request;
// an auth token's iss is not checked beyond its signature, since that Person
// Server already checked it. The token grants nothing by itself.
func verifyUpstreamToken(
	ctx context.Context,
	raw json.RawMessage,
	intermediary aauth.AgentTokenClaims,
	personServer string,
	resolver signaturekey.KeyResolver,
	proof signaturekey.VerifiedRequest,
) (*verifiedUpstream, error) {
	var compact string
	if err := json.Unmarshal(raw, &compact); err != nil || compact == "" {
		return nil, &upstreamTokenFailure{cause: errors.New("accessserver: upstream_token must be a non-empty compact token string")}
	}
	header, err := jose.PeekHeader(compact)
	if err != nil {
		return nil, &upstreamTokenFailure{cause: err}
	}
	verificationClock := aauth.ClockFunc(proof.VerifiedAt)
	upstream := &verifiedUpstream{}
	var audience, namedPersonServer string
	switch header.Type {
	case aauth.PersonTokenType:
		claims, err := aauth.VerifyPersonToken(ctx, compact, resolver, verificationClock)
		if err != nil {
			return nil, &upstreamTokenFailure{cause: err}
		}
		upstream.person = &claims
		audience, namedPersonServer = claims.Audience, claims.Issuer
	case aauth.AuthTokenType:
		claims, err := upstreamtoken.VerifyAuthToken(ctx, compact, resolver, verificationClock)
		if err != nil {
			return nil, &upstreamTokenFailure{cause: err}
		}
		upstream.auth = &claims
		audience, namedPersonServer = claims.Audience, claims.PersonServer
	default:
		return nil, &upstreamTokenFailure{
			cause: fmt.Errorf("accessserver: upstream token typ %q is neither a person token nor an auth token", header.Type),
		}
	}
	if err := proof.CheckIssuedAt(upstream.issuedAt()); err != nil {
		return nil, &upstreamTokenFailure{cause: err}
	}
	if namedPersonServer != personServer {
		return nil, &upstreamTokenFailure{cause: errors.New("accessserver: upstream token does not name the Person Server that signed the request")}
	}
	if audience != intermediary.Issuer {
		return nil, &upstreamTokenFailure{cause: errors.New("accessserver: upstream token audience is not the intermediary that signed with its own Agent token")}
	}
	return upstream, nil
}

// writeUpstreamTokenProblem maps an upstream_token failure to Protocol's
// <invalid|expired>_upstream_token codes, keeping parameter clock_skew.
func writeUpstreamTokenProblem(response http.ResponseWriter, err error) {
	var skew *signaturekey.Error
	if errors.As(err, &skew) && skew.Code == signaturekey.ErrorClockSkew {
		writeProblem(response, http.StatusBadRequest, string(signaturekey.ErrorClockSkew), err)
		return
	}
	var validation *aauth.TokenValidationError
	if errors.As(err, &validation) && validation.Code == aauth.TokenValidationExpired {
		writeProblem(response, http.StatusBadRequest, "expired_upstream_token", err)
		return
	}
	writeProblem(response, http.StatusBadRequest, "invalid_upstream_token", err)
}
