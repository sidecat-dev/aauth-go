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
	"gitlab.com/sidecat-dev/aauth-go/internal/upstreamtoken"
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
	// caller is the calling Agent, as this Person Server's issuance record of
	// the token names it.
	caller upstreamCaller
}

// upstreamCaller is the Agent an upstream token was issued to.
type upstreamCaller struct {
	agentProvider, agent, parentAgent, agentTokenJTI string
}

// owner is the top-level Agent behind the chain: the caller, or its parent
// when the token was issued to a mediated sub-agent. Its binding authorized
// the token, and its missions are the ones the token can carry.
func (caller upstreamCaller) owner() string {
	if caller.parentAgent != "" {
		return caller.parentAgent
	}
	return caller.agent
}

// missionS256 is the mission the upstream token carries, if any.
func (upstream *verifiedUpstreamToken) missionS256() string {
	if upstream == nil {
		return ""
	}
	if upstream.person != nil {
		return upstream.person.MissionS256
	}
	return upstream.auth.MissionS256
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
	return server.verifyUpstreamToken(ctx, compact, intermediary, proof.VerifiedAt(), proof.CheckIssuedAt)
}

// verifyUpstreamToken applies Upstream Token Verification at the instant at.
// checkIssuedAt bounds the token's iat by the request signature; a retained
// request verified again while it waits passes nil.
func (server *Server) verifyUpstreamToken(
	ctx context.Context,
	compact string,
	intermediary aauth.AgentTokenClaims,
	at time.Time,
	checkIssuedAt func(time.Time) error,
) (*verifiedUpstreamToken, error) {
	// An upstream token is a person token or an auth token; typ tells which,
	// and each is verified by its own verifier. Any other typ is refused.
	header, err := jose.PeekHeader(compact)
	if err != nil {
		return nil, &upstreamTokenFailure{cause: err}
	}
	verificationClock := aauth.ClockFunc(func() time.Time { return at })
	withinSignature := func(iat int64) error {
		if checkIssuedAt == nil {
			return nil
		}
		return checkIssuedAt(time.Unix(iat, 0))
	}
	upstream := &verifiedUpstreamToken{digest: sha256.Sum256([]byte(compact)), compact: compact}
	switch header.Type {
	case aauth.PersonTokenType:
		claims, err := aauth.VerifyPersonToken(ctx, compact, server.keyResolver, verificationClock)
		if err == nil {
			err = withinSignature(claims.IssuedAt)
		}
		if err != nil {
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
		upstream.person = &claims
		upstream.reference = aauth.TokenReference{Issuer: claims.Issuer, JTI: claims.JTI}
	case aauth.AuthTokenType:
		claims, err := upstreamtoken.VerifyAuthToken(ctx, compact, server.keyResolver, verificationClock)
		if err == nil {
			err = withinSignature(claims.IssuedAt)
		}
		if err != nil {
			return nil, &upstreamTokenFailure{cause: err}
		}
		// Its ps is this Person Server, and its iss is this Person Server or an
		// Access Server it presented a person token to for that aud and sub.
		// Either way this Person Server retained the token when it issued it or
		// delivered it, and that record identifies the calling Agent.
		if claims.PersonServer != server.issuer ||
			claims.Issuer == server.issuer && claims.DWK != aauth.PersonDiscoveryDocument ||
			claims.Issuer != server.issuer && claims.DWK != aauth.AccessDiscoveryDocument {
			return nil, &upstreamTokenFailure{cause: errors.New("personserver: upstream auth token was not issued or delivered by this Person Server")}
		}
		if claims.Audience != intermediary.Issuer {
			return nil, &upstreamTokenFailure{cause: errors.New("personserver: upstream token audience does not match the intermediary Resource")}
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
	if err := server.checkUpstreamLineageRevoked(ctx, record); err != nil {
		return err
	}
	upstream.caller = upstreamCaller{
		agentProvider: record.AgentProvider, agent: record.Agent,
		parentAgent: record.ParentAgent, agentTokenJTI: record.AgentTokenJTI,
	}
	// An Access Server's clock cannot show which binding generation authorized
	// its token, so after a binding is replaced such a token is refused, as it
	// is as a presented token.
	bindingSince := time.Unix(upstream.auth.IssuedAt, 0)
	if upstream.auth.DWK == aauth.AccessDiscoveryDocument {
		bindingSince = time.Time{}
	}
	return server.checkUpstreamCaller(ctx, upstream.caller, bindingSince)
}

// maximumUpstreamLineage bounds how many step-ups checkUpstreamLineageRevoked
// follows back to the person token an upstream auth token was obtained with.
const maximumUpstreamLineage = 32

// checkUpstreamLineageRevoked refuses an upstream auth token obtained with a
// person token this Person Server revoked, directly or through step-ups, even
// where no cascade reached the auth token itself.
func (server *Server) checkUpstreamLineageRevoked(ctx context.Context, record IssuedAuthTokenRecord) error {
	presented := record.PresentedTokenReference
	for range maximumUpstreamLineage {
		if presented == (aauth.TokenReference{}) {
			return nil
		}
		if err := server.checkUpstreamRevoked(ctx, presented); err != nil {
			return err
		}
		earlier, err := server.issuedAuthTokens.LoadIssuedAuthToken(ctx, presented)
		if errors.Is(err, ErrIssuedAuthTokenNotFound) {
			return nil
		}
		if err != nil {
			return &upstreamStoreError{cause: err}
		}
		if earlier.Reference != presented {
			return &upstreamStoreError{cause: errors.New("personserver: issued auth-token store returned a record for another token")}
		}
		presented = earlier.PresentedTokenReference
	}
	return &upstreamTokenFailure{cause: errors.New("personserver: the upstream token's step-up lineage is too long")}
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
	upstream.caller = upstreamCaller{
		agentProvider: record.AgentProvider, agent: record.Agent,
		parentAgent: record.ParentAgent, agentTokenJTI: record.AgentTokenJTI,
	}
	return server.checkUpstreamCaller(ctx, upstream.caller, time.Unix(claims.IssuedAt, 0))
}

// checkUpstreamCaller refuses an upstream token whose calling Agent's Agent
// token, or binding to the person, this Person Server has revoked.
func (server *Server) checkUpstreamCaller(ctx context.Context, caller upstreamCaller, issuedAt time.Time) error {
	if server.agentTokenRevocations != nil {
		revoked, err := server.agentTokenRevocations.IsRevoked(ctx, aauth.TokenReference{
			Issuer: caller.agentProvider,
			JTI:    caller.agentTokenJTI,
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
	binding := AgentBinding{AgentProvider: caller.agentProvider, Agent: caller.owner()}
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

// writeUpstreamMissionProblem answers a chained request whose upstream token
// carries a mission this Person Server cannot use. The intermediary did not
// name the mission, so one this Person Server does not hold for the calling
// Agent makes the upstream token invalid; a terminated one ends the chain with
// mission_terminated, as it ends the calling Agent's own requests.
func (server *Server) writeUpstreamMissionProblem(response http.ResponseWriter, err error) {
	if errors.Is(err, ErrMissionNotFound) {
		server.writeUpstreamTokenProblem(response, &upstreamTokenFailure{
			cause: errors.New("personserver: the upstream token's mission is not one this Person Server holds for its calling Agent"),
		})
		return
	}
	writeMissionReferenceProblem(response, err)
}

func upstreamTokenExpired(err error) bool {
	var validation *aauth.TokenValidationError
	return errors.As(err, &validation) && validation.Code == aauth.TokenValidationExpired
}

func cloneAuthTokenClaims(claims aauth.AuthTokenClaims) aauth.AuthTokenClaims {
	claims.Account = cloneAuthorizationAccount(claims.Account)
	claims.AdditionalClaims = cloneClaims(claims.AdditionalClaims)
	return claims
}
