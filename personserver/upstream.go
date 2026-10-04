package personserver

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

var (
	errUpstreamTokenSyntax      = errors.New("personserver: upstream_token must be a non-empty compact token string")
	errUpstreamTokenUnsupported = errors.New("personserver: upstream_token is not supported by this authorization configuration")
	errUpstreamCallerRevoked    = errors.New("personserver: the Agent token of the upstream token's calling Agent is revoked")
)

type verifiedUpstreamToken struct {
	claims    aauth.AuthTokenClaims
	reference aauth.TokenReference
	digest    [32]byte
}

type upstreamTokenFailure struct{ cause error }

func (failure *upstreamTokenFailure) Error() string { return failure.cause.Error() }
func (failure *upstreamTokenFailure) Unwrap() error { return failure.cause }

// upstreamStoreError reports a fault in this Person Server's own records.
type upstreamStoreError struct{ cause error }

func (failure *upstreamStoreError) Error() string { return failure.cause.Error() }
func (failure *upstreamStoreError) Unwrap() error { return failure.cause }

type unsupportedCallChainError struct{ cause error }

func (failure *unsupportedCallChainError) Error() string { return failure.cause.Error() }
func (failure *unsupportedCallChainError) Unwrap() error { return failure.cause }

func (server *Server) verifyOptionalUpstreamToken(
	ctx context.Context,
	raw json.RawMessage,
	intermediary aauth.AgentTokenClaims,
	proof signaturekey.VerifiedRequest,
) (*verifiedUpstreamToken, error) {
	if raw == nil {
		return nil, nil
	}
	if server.authorizationMode != authorizationModePersonServer ||
		server.bindChainedPerson == nil || server.authorizeChained == nil {
		return nil, errUpstreamTokenUnsupported
	}
	if intermediary.ParentAgent != "" {
		return nil, &unsupportedCallChainError{cause: errors.New("personserver: sub-agent call chaining is not implemented")}
	}
	var compact string
	if err := json.Unmarshal(raw, &compact); err != nil || compact == "" {
		return nil, errUpstreamTokenSyntax
	}
	verificationClock := aauth.ClockFunc(func() time.Time { return proof.VerifiedAt() })
	claims, err := aauth.VerifyAuthToken(ctx, compact, server.keyResolver, verificationClock)
	if err != nil {
		return nil, &upstreamTokenFailure{cause: err}
	}
	if err := proof.CheckIssuedAt(time.Unix(claims.IssuedAt, 0)); err != nil {
		return nil, &upstreamTokenFailure{cause: err}
	}
	if claims.DWK != aauth.PersonDiscoveryDocument || claims.Issuer != server.issuer ||
		claims.PersonServer != server.issuer {
		return nil, &upstreamTokenFailure{cause: errors.New("personserver: upstream token was not issued by this Person Server")}
	}
	if claims.Audience != intermediary.Issuer {
		return nil, &upstreamTokenFailure{cause: errors.New("personserver: upstream token audience does not match the intermediary Resource")}
	}
	if claims.MissionS256 != "" || claims.Account != nil {
		return nil, &unsupportedCallChainError{cause: errors.New("personserver: mission- or account-bound call chaining is not implemented")}
	}
	upstream := &verifiedUpstreamToken{
		claims: cloneAuthTokenClaims(claims),
		reference: aauth.TokenReference{
			Issuer: claims.Issuer,
			JTI:    claims.JTI,
		},
		digest: sha256.Sum256([]byte(compact)),
	}
	if err := server.identifyUpstreamCaller(ctx, upstream); err != nil {
		return nil, err
	}
	return upstream, nil
}

// identifyUpstreamCaller finds the Agent this Person Server issued the upstream
// auth token to, from the issuance record of that exact token, and refuses a
// caller whose Agent token has been revoked. The token's signature does not
// identify the caller, and neither do the intermediary's Agent token or the
// upstream token's own jti.
func (server *Server) identifyUpstreamCaller(ctx context.Context, upstream *verifiedUpstreamToken) error {
	if server.issuedAuthTokens == nil {
		return &upstreamTokenFailure{cause: errors.New("personserver: no issuance record identifies the upstream token's calling Agent")}
	}
	record, err := server.issuedAuthTokens.LoadIssuedAuthToken(ctx, upstream.reference)
	if errors.Is(err, ErrIssuedAuthTokenNotFound) {
		return &upstreamTokenFailure{cause: errors.New("personserver: no issuance record identifies the upstream token's calling Agent")}
	}
	if err != nil {
		return &upstreamStoreError{cause: err}
	}
	thumbprint, err := upstream.claims.Confirmation.JWK.Thumbprint()
	if err != nil {
		return &upstreamTokenFailure{cause: err}
	}
	if validateIssuedAuthTokenRecord(record) != nil ||
		record.Reference != upstream.reference ||
		record.CompactSHA256 != upstream.digest ||
		record.Resource != upstream.claims.Audience ||
		!record.identifiesRecipient() ||
		record.AgentJKT != thumbprint {
		return &upstreamTokenFailure{cause: errors.New("personserver: the upstream token's issuance record does not identify its calling Agent")}
	}
	if server.agentTokenRevocations != nil {
		revoked, err := server.agentTokenRevocations.IsRevoked(ctx, aauth.TokenReference{
			Issuer: record.AgentProvider,
			JTI:    record.AgentTokenJTI,
		})
		if err != nil {
			return &upstreamStoreError{cause: err}
		}
		if revoked {
			return errUpstreamCallerRevoked
		}
	}
	return nil
}

func (upstream *verifiedUpstreamToken) policyClaims() *aauth.AuthTokenClaims {
	if upstream == nil {
		return nil
	}
	claims := cloneAuthTokenClaims(upstream.claims)
	return &claims
}

func (upstream *verifiedUpstreamToken) bindRecord(record *PersonTokenRecord) {
	if upstream == nil || record == nil {
		return
	}
	record.UpstreamTokenReference = upstream.reference
	record.UpstreamTokenSHA256 = upstream.digest
}

func (upstream *verifiedUpstreamToken) matchesRecord(record PersonTokenRecord) bool {
	if upstream == nil {
		return record.UpstreamTokenReference == (aauth.TokenReference{}) && record.UpstreamTokenSHA256 == ([32]byte{})
	}
	return record.UpstreamTokenReference == upstream.reference && record.UpstreamTokenSHA256 == upstream.digest
}

// matchesIssuedRecord reports whether an issued auth-token record names
// exactly this upstream token, or none when the request carries none.
func (upstream *verifiedUpstreamToken) matchesIssuedRecord(record IssuedAuthTokenRecord) bool {
	if upstream == nil {
		return record.UpstreamTokenReference == (aauth.TokenReference{}) && record.UpstreamTokenSHA256 == ([32]byte{})
	}
	return record.UpstreamTokenReference == upstream.reference && record.UpstreamTokenSHA256 == upstream.digest
}

func validateCallChainRecord(record PersonTokenRecord) error {
	emptyReference := record.UpstreamTokenReference == (aauth.TokenReference{})
	emptyDigest := record.UpstreamTokenSHA256 == ([32]byte{})
	if emptyReference != emptyDigest {
		return errors.New("personserver: retained upstream-token binding is incomplete")
	}
	if emptyReference {
		return nil
	}
	if err := aauth.ValidateTokenReference(record.UpstreamTokenReference); err != nil {
		return errors.New("personserver: retained upstream-token reference is invalid")
	}
	return nil
}

func (server *Server) writeUpstreamTokenProblem(response http.ResponseWriter, err error) {
	if errors.Is(err, errUpstreamTokenSyntax) || errors.Is(err, errUpstreamTokenUnsupported) {
		writeProblem(response, http.StatusBadRequest, "invalid_request", err)
		return
	}
	var unsupported *unsupportedCallChainError
	if errors.As(err, &unsupported) {
		writeProblem(response, http.StatusInternalServerError, "server_error", unsupported.cause)
		return
	}
	var storeFailure *upstreamStoreError
	if errors.As(err, &storeFailure) {
		writeProblem(response, http.StatusInternalServerError, "server_error", storeFailure.cause)
		return
	}
	if errors.Is(err, errUpstreamCallerRevoked) {
		writeProblem(response, http.StatusBadRequest, "revoked_upstream_token", err)
		return
	}
	var tokenFailure *upstreamTokenFailure
	if errors.As(err, &tokenFailure) {
		if writeParameterClockSkew(response, tokenFailure.cause) {
			return
		}
		writeProblem(response, http.StatusBadRequest, "invalid_upstream_token", tokenFailure.cause)
		return
	}
	writeProblem(response, http.StatusBadRequest, "invalid_upstream_token", err)
}

func cloneAuthTokenClaims(claims aauth.AuthTokenClaims) aauth.AuthTokenClaims {
	claims.AdditionalClaims = cloneClaims(claims.AdditionalClaims)
	return claims
}
