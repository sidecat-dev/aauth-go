package personserver

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

var (
	errUpstreamTokenSyntax      = errors.New("personserver: upstream_token must be a non-empty compact token string")
	errUpstreamTokenUnsupported = errors.New("personserver: upstream_token is not supported by this authorization configuration")
	errUpstreamCallerRevoked    = errors.New("personserver: the Agent token or binding of the upstream token's calling Agent is revoked")
)

// verifiedUpstreamToken is a verified upstream person token or auth token.
// Exactly one of person and auth is set.
type verifiedUpstreamToken struct {
	person    *aauth.PersonTokenClaims
	auth      *aauth.AuthTokenClaims
	reference aauth.TokenReference
	digest    [32]byte
	// compact is the exact token, passed through to an Access Server.
	compact string
}

func (upstream *verifiedUpstreamToken) subject() string {
	if upstream.person != nil {
		return upstream.person.Subject
	}
	return upstream.auth.Subject
}

func (upstream *verifiedUpstreamToken) expiresAt() time.Time {
	if upstream.person != nil {
		return time.Unix(upstream.person.ExpiresAt, 0)
	}
	return time.Unix(upstream.auth.ExpiresAt, 0)
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
	switch {
	case server.bindChainedPerson == nil:
		return nil, errUpstreamTokenUnsupported
	case server.authorizationMode == authorizationModePersonServer && server.authorizeChained == nil:
		return nil, errUpstreamTokenUnsupported
	case server.authorizationMode == authorizationModeFederated && server.consentChained == nil:
		return nil, errUpstreamTokenUnsupported
	}
	if intermediary.ParentAgent != "" {
		return nil, &unsupportedCallChainError{cause: errors.New("personserver: sub-agent call chaining is not implemented")}
	}
	var compact string
	if err := json.Unmarshal(raw, &compact); err != nil || compact == "" {
		return nil, errUpstreamTokenSyntax
	}
	// An upstream token is a person token or an auth token; typ tells which,
	// and each is verified by its own verifier. Any other typ is refused.
	header, err := jose.PeekHeader(compact)
	if err != nil {
		return nil, &upstreamTokenFailure{cause: err}
	}
	verificationClock := aauth.ClockFunc(func() time.Time { return proof.VerifiedAt() })
	upstream := &verifiedUpstreamToken{digest: sha256.Sum256([]byte(compact)), compact: compact}
	switch header.Type {
	case aauth.PersonTokenType:
		claims, err := aauth.VerifyPersonToken(ctx, compact, server.keyResolver, verificationClock)
		if err != nil {
			return nil, &upstreamTokenFailure{cause: err}
		}
		if err := proof.CheckIssuedAt(time.Unix(claims.IssuedAt, 0)); err != nil {
			return nil, &upstreamTokenFailure{cause: err}
		}
		// The cnf of an upstream token is the calling Agent's key, not the
		// intermediary's, so it is not compared with the request signer.
		if claims.Issuer != server.issuer {
			return nil, &upstreamTokenFailure{cause: errors.New("personserver: upstream person token was not issued by this Person Server")}
		}
		if claims.Audience != intermediary.Issuer {
			return nil, &upstreamTokenFailure{cause: errors.New("personserver: upstream token audience does not match the intermediary Resource")}
		}
		if claims.MissionS256 != "" {
			return nil, &unsupportedCallChainError{cause: errors.New("personserver: mission-bound call chaining is not implemented")}
		}
		upstream.person = &claims
		upstream.reference = aauth.TokenReference{Issuer: claims.Issuer, JTI: claims.JTI}
	case aauth.AuthTokenType:
		claims, err := aauth.VerifyAuthToken(ctx, compact, server.keyResolver, verificationClock)
		if err != nil {
			return nil, &upstreamTokenFailure{cause: err}
		}
		if err := proof.CheckIssuedAt(time.Unix(claims.IssuedAt, 0)); err != nil {
			return nil, &upstreamTokenFailure{cause: err}
		}
		// Only an auth token this Person Server issued has an issuance record
		// that identifies the calling Agent. A four-party Person Server keeps
		// none for the auth tokens an Access Server issues.
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
		cloned := cloneAuthTokenClaims(claims)
		upstream.auth = &cloned
		upstream.reference = aauth.TokenReference{Issuer: claims.Issuer, JTI: claims.JTI}
	default:
		return nil, &upstreamTokenFailure{
			cause: fmt.Errorf("personserver: upstream token typ %q is neither a person token nor an auth token", header.Type),
		}
	}
	if err := server.checkUpstreamRevoked(ctx, upstream.reference); err != nil {
		return nil, err
	}
	if err := server.identifyUpstreamCaller(ctx, upstream); err != nil {
		return nil, err
	}
	return upstream, nil
}

// identifyUpstreamCaller finds the Agent this Person Server issued the upstream
// token to, from the issuance record of that exact token, and refuses a caller
// whose Agent token or binding has been revoked. The token's signature does not
// identify the caller, and neither do the intermediary's Agent token or the
// upstream token's own jti.
func (server *Server) identifyUpstreamCaller(ctx context.Context, upstream *verifiedUpstreamToken) error {
	if upstream.person != nil {
		return server.identifyUpstreamPersonTokenCaller(ctx, upstream)
	}
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
	thumbprint, err := upstream.auth.Confirmation.JWK.Thumbprint()
	if err != nil {
		return &upstreamTokenFailure{cause: err}
	}
	if validateIssuedAuthTokenRecord(record) != nil ||
		record.Reference != upstream.reference ||
		record.CompactSHA256 != upstream.digest ||
		record.Resource != upstream.auth.Audience ||
		!record.identifiesRecipient() ||
		record.AgentJKT != thumbprint {
		return &upstreamTokenFailure{cause: errors.New("personserver: the upstream token's issuance record does not identify its calling Agent")}
	}
	return server.checkUpstreamCaller(
		ctx, record.AgentProvider, record.Agent, record.ParentAgent, record.AgentTokenJTI,
		time.Unix(upstream.auth.IssuedAt, 0),
	)
}

// identifyUpstreamPersonTokenCaller finds the Agent this Person Server issued
// the upstream person token to, from the retained person-token record.
func (server *Server) identifyUpstreamPersonTokenCaller(ctx context.Context, upstream *verifiedUpstreamToken) error {
	claims := upstream.person
	record, err := server.tokens.Load(ctx, server.issuer, claims.JTI)
	if errors.Is(err, ErrPersonTokenNotFound) {
		return &upstreamTokenFailure{cause: errors.New("personserver: no issuance record identifies the upstream token's calling Agent")}
	}
	if err != nil {
		return &upstreamStoreError{cause: err}
	}
	if validatePersonTokenRecord(record) != nil ||
		record.JTI != claims.JTI ||
		record.PersonServer != server.issuer ||
		record.Resource != claims.Audience ||
		record.Subject != claims.Subject ||
		record.MissionS256 != claims.MissionS256 ||
		record.Tenant != claims.Tenant ||
		!record.ExpiresAt.Equal(time.Unix(claims.ExpiresAt, 0)) ||
		!record.Confirmation.Equal(claims.Confirmation.JWK) ||
		record.AgentTokenJTI == "" {
		return &upstreamTokenFailure{cause: errors.New("personserver: the upstream token's issuance record does not identify its calling Agent")}
	}
	return server.checkUpstreamCaller(
		ctx, record.AgentProvider, record.Agent, record.ParentAgent, record.AgentTokenJTI,
		time.Unix(claims.IssuedAt, 0),
	)
}

// checkUpstreamCaller refuses an upstream token whose calling Agent's Agent
// token, or binding to the person, this Person Server has revoked.
func (server *Server) checkUpstreamCaller(
	ctx context.Context,
	agentProvider, agent, parentAgent, agentTokenJTI string,
	issuedAt time.Time,
) error {
	if server.agentTokenRevocations != nil {
		revoked, err := server.agentTokenRevocations.IsRevoked(ctx, aauth.TokenReference{
			Issuer: agentProvider,
			JTI:    agentTokenJTI,
		})
		if err != nil {
			return &upstreamStoreError{cause: err}
		}
		if revoked {
			return errUpstreamCallerRevoked
		}
	}
	// The binding behind the chain is the caller's, or its parent's when the
	// upstream token was issued to a mediated sub-agent.
	binding := AgentBinding{AgentProvider: agentProvider, Agent: agent}
	if parentAgent != "" {
		binding.Agent = parentAgent
	}
	if err := server.checkAgentBinding(ctx, binding, issuedAt); err != nil {
		if errors.Is(err, ErrAgentBindingRevoked) {
			return fmt.Errorf("%w: %w", errUpstreamCallerRevoked, err)
		}
		return &upstreamStoreError{cause: err}
	}
	return nil
}

// policyClaims returns independent copies of the verified upstream token for
// policy: the auth token claims, or the person token claims.
func (upstream *verifiedUpstreamToken) policyClaims() (*aauth.AuthTokenClaims, *aauth.PersonTokenClaims) {
	if upstream == nil {
		return nil, nil
	}
	if upstream.person != nil {
		claims := *upstream.person
		return nil, &claims
	}
	claims := cloneAuthTokenClaims(*upstream.auth)
	return &claims, nil
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
		if upstreamTokenExpired(tokenFailure.cause) {
			writeProblem(response, http.StatusBadRequest, "expired_upstream_token", tokenFailure.cause)
			return
		}
		writeProblem(response, http.StatusBadRequest, "invalid_upstream_token", tokenFailure.cause)
		return
	}
	if upstreamTokenExpired(err) {
		writeProblem(response, http.StatusBadRequest, "expired_upstream_token", err)
		return
	}
	writeProblem(response, http.StatusBadRequest, "invalid_upstream_token", err)
}

func upstreamTokenExpired(err error) bool {
	var validation *aauth.TokenValidationError
	return errors.As(err, &validation) && validation.Code == aauth.TokenValidationExpired
}

func cloneAuthTokenClaims(claims aauth.AuthTokenClaims) aauth.AuthTokenClaims {
	claims.AdditionalClaims = cloneClaims(claims.AdditionalClaims)
	return claims
}
