package aauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

type selfJWTLocator struct {
	Issuer string
	DWK    string
}

func preflightSelfJWTClaims(payload []byte, now time.Time) (selfJWTLocator, error) {
	var locator selfJWTLocator
	var claims map[string]json.RawMessage
	if err := json.Unmarshal(payload, &claims); err != nil {
		return locator, signaturekey.NewError(signaturekey.ErrorInvalidJWT, fmt.Errorf("aauth: decode self-jwt claims: %w", err))
	}
	if _, ok := claims["cnf"]; ok {
		return locator, signaturekey.NewError(signaturekey.ErrorInvalidJWT, errors.New("aauth: self-jwt must not contain cnf"))
	}
	if err := json.Unmarshal(claims["iss"], &locator.Issuer); err != nil || locator.Issuer == "" {
		return locator, signaturekey.NewError(signaturekey.ErrorInvalidJWT, errors.New("aauth: self-jwt iss is required and must be a string"))
	}
	if err := ValidateServerIdentifier(locator.Issuer); err != nil {
		return locator, signaturekey.NewError(signaturekey.ErrorInvalidJWT, fmt.Errorf("aauth: self-jwt issuer: %w", err))
	}
	if err := json.Unmarshal(claims["dwk"], &locator.DWK); err != nil ||
		signaturekey.ValidateDiscoveryName(locator.DWK) != nil {
		return locator, signaturekey.NewError(signaturekey.ErrorInvalidKey, errors.New("aauth: self-jwt dwk is required and must be a safe discovery document"))
	}
	if rawExpiry, ok := claims["exp"]; ok {
		var expiry int64
		if err := json.Unmarshal(rawExpiry, &expiry); err != nil || expiry <= 0 {
			return locator, signaturekey.NewError(signaturekey.ErrorInvalidJWT, errors.New("aauth: self-jwt exp must be a NumericDate"))
		}
		if expiry <= now.Unix() {
			return locator, signaturekey.NewError(signaturekey.ErrorExpiredJWT, &TokenValidationError{
				Code:  TokenValidationExpired,
				Cause: errors.New("token is expired"),
			})
		}
	}
	return locator, nil
}

// VerifiedRequest is the trusted signing context of an HTTP request.
type VerifiedRequest struct {
	Proof            signaturekey.VerifiedRequest
	SignatureKeyType signaturekey.Scheme
	Signer           string
	RawCredential    string
	CredentialType   string
	Agent            string
	PublicKey        jose.JWK
	IdentityKey      jose.JWK
	JKTJWT           *signaturekey.VerifiedJKTJWT
	AgentToken       *VerifiedToken[AgentTokenClaims]
	PersonToken      *VerifiedToken[PersonTokenClaims]
	AuthToken        *VerifiedToken[AuthTokenClaims]
	SubscribeToken   *SubscribeTokenClaims
	SelfJWT          *VerifiedSelfJWT
	Created          time.Time
	VerifiedAt       time.Time
	ReplayKey        string
}

// AgentClaims returns an independent projection of the verified agent token.
func (verified VerifiedRequest) AgentClaims() (AgentTokenClaims, error) {
	if verified.AgentToken == nil {
		return AgentTokenClaims{}, errors.New("aauth: verified request has no agent token")
	}
	if err := verified.AgentToken.RequireNoAuthorizationMembers(); err != nil {
		return AgentTokenClaims{}, err
	}
	return verified.AgentToken.Claims()
}

// PersonClaims returns an independent projection of the verified person token.
func (verified VerifiedRequest) PersonClaims() (PersonTokenClaims, error) {
	if verified.PersonToken == nil {
		return PersonTokenClaims{}, errors.New("aauth: verified request has no person token")
	}
	if err := verified.PersonToken.RequireNoAuthorizationMembers(); err != nil {
		return PersonTokenClaims{}, err
	}
	return verified.PersonToken.Claims()
}

// AuthClaims returns an independent projection of the verified auth token.
func (verified VerifiedRequest) AuthClaims() (AuthTokenClaims, error) {
	if verified.AuthToken == nil {
		return AuthTokenClaims{}, errors.New("aauth: verified request has no auth token")
	}
	if err := verified.AuthToken.RequireNoAuthorizationMembers(); err != nil {
		return AuthTokenClaims{}, err
	}
	return verified.AuthToken.Claims()
}

// SelfJWTClaimPolicy applies deployment-owned application claim rules after
// the self-jwt JWS is verified and before the HTTP Message Signature is
// verified. The supplied value is sealed and may be passed to a strict
// application decoder such as DecodeVerifiedEventToken.
type SelfJWTClaimPolicy func(VerifiedSelfJWT) error

// VerifyRequestOptions declares the message components and token forms a
// particular endpoint accepts.
type VerifyRequestOptions struct {
	RequiredComponents []string
	// RequireExactComponents rejects any covered component outside the
	// endpoint's required profile. Use it when the verified request will be
	// retained for offline replay and every covered value must remain in
	// custody.
	RequireExactComponents   bool
	AllowedCredentialTypes   []string
	AllowedSignatureKeyTypes []signaturekey.Scheme
	SignatureWindow          time.Duration
	SelfJWTMaximumLifetime   time.Duration
	SelfJWTClaimPolicy       SelfJWTClaimPolicy
}

// VerifyRequest verifies the JWT identity, required component coverage,
// content digest, freshness, confirmation-key binding, and HTTP signature.
func VerifyRequest(
	ctx context.Context,
	request *http.Request,
	resolver signaturekey.KeyResolver,
	clock Clock,
	options VerifyRequestOptions,
) (VerifiedRequest, error) {
	var verified VerifiedRequest
	if request == nil || request.URL == nil {
		return verified, errors.New("aauth: request URL is required")
	}
	if clock == nil {
		return verified, errors.New("aauth: clock is required")
	}
	if request.Header.Get("Signature") == "" || request.Header.Get("Signature-Input") == "" || len(request.Header.Values("Signature-Key")) == 0 {
		// The generic Signature-Key draft groups absent proof headers under
		// invalid_signature. The AAuth core profile explicitly overrides that
		// classification: its verification step 1 requires invalid_request
		// before parsing or resolving any supplied proof material.
		return verified, signaturekey.NewError(
			signaturekey.ErrorInvalidRequest,
			errors.New("aauth: Signature, Signature-Input, and Signature-Key headers are required"),
		)
	}
	allowedSignatureKeyTypes := acceptedSignatureKeyTypes(options)
	preparedProof, err := signaturekey.PrepareRequest(
		request,
		clock,
		signaturekey.VerifyOptions{
			RequiredComponents:     options.RequiredComponents,
			RequireExactComponents: options.RequireExactComponents,
			AcceptedSchemes:        allowedSignatureKeyTypes,
			SignatureWindow:        options.SignatureWindow,
		},
	)
	if err != nil {
		return verified, classifySignatureKeyProofError(err)
	}
	credential := preparedProof.Credential()
	verifiedAt := preparedProof.VerifiedAt()
	verificationClock := ClockFunc(func() time.Time { return verifiedAt })
	verified.SignatureKeyType = credential.Scheme()

	switch credential.Scheme() {
	case signaturekey.SchemeJWT:
		if resolver == nil {
			return verified, &signaturekey.ResolutionError{
				Code:  signaturekey.ResolutionUnavailable,
				Cause: errors.New("aauth: key resolver is required"),
			}
		}
		compact, _ := credential.JWT()
		header, err := jose.PeekHeader(compact)
		if err != nil {
			return verified, signaturekey.NewError(signaturekey.ErrorInvalidJWT, fmt.Errorf("aauth: Signature-Key JWT: %w", err))
		}
		allowedCredentialTypes := options.AllowedCredentialTypes
		if len(allowedCredentialTypes) == 0 {
			allowedCredentialTypes = []string{AgentTokenType, AuthTokenType}
		}
		if !contains(allowedCredentialTypes, header.Type) {
			return verified, signaturekey.NewError(signaturekey.ErrorInvalidJWT, fmt.Errorf("aauth: credential typ %q is not accepted", header.Type))
		}
		verified.RawCredential = compact
		verified.CredentialType = header.Type
		switch header.Type {
		case AgentTokenType:
			token, verifyErr := VerifyAgentToken(ctx, verified.RawCredential, resolver, verificationClock)
			if verifyErr != nil {
				return verified, classifyJWTVerificationError(verifyErr)
			}
			if memberErr := token.RequireNoAuthorizationMembers(); memberErr != nil {
				return verified, classifyJWTVerificationError(memberErr)
			}
			claims, claimsErr := token.Claims()
			if claimsErr != nil {
				return verified, classifyJWTVerificationError(claimsErr)
			}
			verified.Agent = claims.Subject
			verified.Signer = claims.Subject
			verified.PublicKey = claims.Confirmation.JWK
			verified.AgentToken = &token
		case PersonTokenType:
			token, verifyErr := VerifyPersonToken(ctx, verified.RawCredential, resolver, verificationClock)
			if verifyErr != nil {
				return verified, classifyJWTVerificationError(verifyErr)
			}
			if memberErr := token.RequireNoAuthorizationMembers(); memberErr != nil {
				return verified, classifyJWTVerificationError(memberErr)
			}
			claims, claimsErr := token.Claims()
			if claimsErr != nil {
				return verified, classifyJWTVerificationError(claimsErr)
			}
			verified.PublicKey = claims.Confirmation.JWK
			verified.PersonToken = &token
		case AuthTokenType:
			token, verifyErr := VerifyAuthToken(ctx, verified.RawCredential, resolver, verificationClock)
			if verifyErr != nil {
				return verified, classifyJWTVerificationError(verifyErr)
			}
			if memberErr := token.RequireNoAuthorizationMembers(); memberErr != nil {
				return verified, classifyJWTVerificationError(memberErr)
			}
			claims, claimsErr := token.Claims()
			if claimsErr != nil {
				return verified, classifyJWTVerificationError(claimsErr)
			}
			verified.Agent = claims.Agent
			verified.Signer = claims.Agent
			verified.PublicKey = claims.Confirmation.JWK
			verified.AuthToken = &token
		case SubscribeTokenType:
			claims, verifyErr := VerifySubscribeToken(ctx, verified.RawCredential, resolver, verificationClock)
			if verifyErr != nil {
				return verified, classifyJWTVerificationError(verifyErr)
			}
			verified.Agent = claims.Subject
			verified.Signer = claims.Subject
			verified.PublicKey = claims.Confirmation.JWK
			verified.SubscribeToken = &claims
		default:
			return verified, signaturekey.NewError(signaturekey.ErrorInvalidJWT, fmt.Errorf("aauth: unsupported Signature-Key JWT typ %q", header.Type))
		}
	case signaturekey.SchemeJWKSURI:
		if resolver == nil {
			return verified, &signaturekey.ResolutionError{
				Code:  signaturekey.ResolutionUnavailable,
				Cause: errors.New("aauth: key resolver is required"),
			}
		}
		identifier, document, keyID, _ := credential.JWKSURI()
		if err := ValidateServerIdentifier(identifier); err != nil {
			return verified, signaturekey.NewError(signaturekey.ErrorInvalidKey, fmt.Errorf("aauth: Signature-Key id: %w", err))
		}
		if signaturekey.ValidateDiscoveryName(document) != nil || keyID == "" {
			return verified, signaturekey.NewError(signaturekey.ErrorInvalidKey, errors.New("aauth: Signature-Key jwks_uri parameters are invalid"))
		}
		resolved, err := resolver.ResolveKey(ctx, identifier, document, keyID)
		if err != nil {
			return verified, classifyJWKSURIResolutionError(err)
		}
		verified.Signer = identifier
		verified.PublicKey = resolved
		verified.IdentityKey = resolved
	case signaturekey.SchemeHWK:
		inline, _ := credential.InlineJWK()
		if inline.Alg != jose.Ed25519Algorithm {
			return verified, &signaturekey.Error{
				Code:               signaturekey.ErrorUnsupportedAlgorithm,
				AcceptedAlgorithms: []string{jose.Ed25519Algorithm},
				Cause:              fmt.Errorf("aauth: unsupported hwk algorithm %q", inline.Alg),
			}
		}
		if _, err := inline.PublicKey(); err != nil {
			return verified, signaturekey.NewError(signaturekey.ErrorInvalidKey, fmt.Errorf("aauth: Signature-Key hwk: %w", err))
		}
		identity, err := inline.ThumbprintURI()
		if err != nil {
			return verified, signaturekey.NewError(signaturekey.ErrorInvalidKey, fmt.Errorf("aauth: Signature-Key hwk identity: %w", err))
		}
		verified.Signer = identity
		verified.PublicKey = inline
		verified.IdentityKey = inline
	case signaturekey.SchemeJKTJWT:
		compact, _ := credential.JWT()
		delegation, err := signaturekey.VerifyJKTJWT(compact, verificationClock)
		if err != nil {
			return verified, classifyJWTVerificationError(err)
		}
		verified.RawCredential = compact
		verified.Signer = delegation.Issuer
		verified.PublicKey = delegation.Confirmation
		verified.IdentityKey = delegation.IdentityKey
		verified.JKTJWT = &delegation
	case signaturekey.SchemeSelfJWT:
		if options.SelfJWTMaximumLifetime < 0 {
			return verified, signaturekey.NewError(
				signaturekey.ErrorInvalidRequest,
				errors.New("aauth: self-jwt maximum lifetime must not be negative"),
			)
		}
		if resolver == nil {
			return verified, &signaturekey.ResolutionError{
				Code:  signaturekey.ResolutionUnavailable,
				Cause: errors.New("aauth: key resolver is required"),
			}
		}
		compact, _ := credential.JWT()
		parsed, err := jose.ParseCompact(compact)
		if err != nil {
			return verified, signaturekey.NewError(signaturekey.ErrorInvalidJWT, fmt.Errorf("aauth: Signature-Key self-jwt: %w", err))
		}
		header, payload := parsed.Header(), parsed.Payload()
		if header.Algorithm == "none" {
			return verified, signaturekey.NewError(signaturekey.ErrorInvalidJWT, errors.New("aauth: alg none is forbidden"))
		}
		if header.Algorithm != jose.Ed25519Algorithm {
			return verified, &signaturekey.Error{
				Code:               signaturekey.ErrorUnsupportedAlgorithm,
				AcceptedAlgorithms: []string{jose.Ed25519Algorithm},
				Cause:              &unsupportedTokenAlgorithmError{algorithm: header.Algorithm},
			}
		}
		if len(options.AllowedCredentialTypes) > 0 && !contains(options.AllowedCredentialTypes, header.Type) {
			return verified, signaturekey.NewError(signaturekey.ErrorInvalidJWT, fmt.Errorf("aauth: credential typ %q is not accepted", header.Type))
		}
		locator, err := preflightSelfJWTClaims(payload, verifiedAt)
		if err != nil {
			return verified, err
		}
		if header.KeyID == "" {
			return verified, signaturekey.NewError(signaturekey.ErrorInvalidKey, errors.New("aauth: self-jwt kid is required"))
		}
		resolved, err := resolver.ResolveKey(ctx, locator.Issuer, locator.DWK, header.KeyID)
		if err != nil {
			return verified, classifyJWKSURIResolutionError(err)
		}
		verifiedCompact, err := verifyTokenSignatureWithKey(parsed, resolved)
		if err != nil {
			return verified, classifyJWTVerificationError(err)
		}
		selfJWT := newVerifiedSelfJWT(verifiedCompact, locator.Issuer, locator.DWK)
		if err := validateSelfJWTMaximumLifetime(selfJWT, options.SelfJWTMaximumLifetime); err != nil {
			return verified, signaturekey.NewError(signaturekey.ErrorInvalidJWT, err)
		}
		if options.SelfJWTClaimPolicy != nil {
			if err := options.SelfJWTClaimPolicy(selfJWT); err != nil {
				return verified, classifyJWTVerificationError(err)
			}
		}
		verified.RawCredential = compact
		verified.CredentialType = header.Type
		verified.Signer = locator.Issuer
		verified.PublicKey = resolved
		verified.IdentityKey = resolved
		verified.SelfJWT = &selfJWT
	}

	verified.Proof, err = preparedProof.Verify(verified.PublicKey)
	if err != nil {
		return VerifiedRequest{}, classifySignatureKeyProofError(err)
	}
	verified.Created = verified.Proof.Created()
	verified.VerifiedAt = verified.Proof.VerifiedAt()
	verified.ReplayKey = verified.Proof.ReplayKey()
	return verified, nil
}

func validateSelfJWTMaximumLifetime(verified VerifiedSelfJWT, maximum time.Duration) error {
	if maximum == 0 {
		return nil
	}
	var claims map[string]json.RawMessage
	if err := json.Unmarshal(verified.Claims, &claims); err != nil {
		return fmt.Errorf("aauth: decode self-jwt lifetime claims: %w", err)
	}
	var issuedAt, expiresAt int64
	if err := json.Unmarshal(claims["iat"], &issuedAt); err != nil || issuedAt <= 0 {
		return errors.New("aauth: self-jwt iat is required and must be a NumericDate")
	}
	if err := json.Unmarshal(claims["exp"], &expiresAt); err != nil || expiresAt <= issuedAt {
		return errors.New("aauth: self-jwt exp must define a positive lifetime after iat")
	}
	maximumSeconds := int64(maximum / time.Second)
	if expiresAt-issuedAt > maximumSeconds {
		return fmt.Errorf("aauth: self-jwt lifetime exceeds %s", maximum)
	}
	return nil
}

func classifySignatureKeyProofError(err error) error {
	if err == nil {
		return nil
	}
	var proofFailure *signaturekey.Error
	if errors.As(err, &proofFailure) {
		return proofFailure
	}
	var resolutionFailure *signaturekey.ResolutionError
	if errors.As(err, &resolutionFailure) {
		return err
	}
	return signaturekey.NewError(signaturekey.ErrorInvalidSignature, err)
}

func classifyJWTVerificationError(err error) error {
	if err == nil {
		return nil
	}
	var proofFailure *signaturekey.Error
	if errors.As(err, &proofFailure) {
		return proofFailure
	}
	var resolutionError *signaturekey.ResolutionError
	if errors.As(err, &resolutionError) {
		switch resolutionError.Code {
		case signaturekey.ResolutionUnknown:
			return signaturekey.NewError(signaturekey.ErrorUnknownKey, err)
		case signaturekey.ResolutionInvalid:
			return signaturekey.NewError(signaturekey.ErrorInvalidKey, err)
		case signaturekey.ResolutionIssuerMissing:
			return signaturekey.NewError(signaturekey.ErrorIssuerMissing, err)
		case signaturekey.ResolutionIssuerMismatch:
			return signaturekey.NewError(signaturekey.ErrorIssuerMismatch, err)
		case signaturekey.ResolutionUnsupportedAlgorithm:
			return &signaturekey.Error{
				Code:               signaturekey.ErrorUnsupportedAlgorithm,
				AcceptedAlgorithms: []string{jose.Ed25519Algorithm},
				Cause:              err,
			}
		case signaturekey.ResolutionDenied, signaturekey.ResolutionUnavailable:
			return err
		}
	}
	var validation *TokenValidationError
	if errors.As(err, &validation) {
		switch validation.Code {
		case TokenValidationExpired:
			return signaturekey.NewError(signaturekey.ErrorExpiredJWT, err)
		case TokenValidationInvalidKey:
			return signaturekey.NewError(signaturekey.ErrorInvalidKey, err)
		}
	}
	var unsupportedAlgorithm *unsupportedTokenAlgorithmError
	if errors.As(err, &unsupportedAlgorithm) {
		return &signaturekey.Error{
			Code:               signaturekey.ErrorUnsupportedAlgorithm,
			AcceptedAlgorithms: []string{jose.Ed25519Algorithm},
			Cause:              err,
		}
	}
	var unsupportedClaim *unsupportedTokenClaimError
	if errors.As(err, &unsupportedClaim) {
		return signaturekey.NewPublicError(signaturekey.ErrorInvalidJWT, unsupportedClaim.Error(), err)
	}
	return signaturekey.NewError(signaturekey.ErrorInvalidJWT, err)
}

func classifyJWKSURIResolutionError(err error) error {
	var resolutionError *signaturekey.ResolutionError
	if !errors.As(err, &resolutionError) {
		return signaturekey.NormalizeResolutionError(err)
	}
	switch resolutionError.Code {
	case signaturekey.ResolutionUnknown:
		return signaturekey.NewError(signaturekey.ErrorUnknownKey, err)
	case signaturekey.ResolutionInvalid:
		return signaturekey.NewError(signaturekey.ErrorInvalidKey, err)
	case signaturekey.ResolutionIssuerMissing:
		return signaturekey.NewError(signaturekey.ErrorIssuerMissing, err)
	case signaturekey.ResolutionIssuerMismatch:
		return signaturekey.NewError(signaturekey.ErrorIssuerMismatch, err)
	case signaturekey.ResolutionUnsupportedAlgorithm:
		return &signaturekey.Error{
			Code:               signaturekey.ErrorUnsupportedAlgorithm,
			AcceptedAlgorithms: []string{jose.Ed25519Algorithm},
			Cause:              err,
		}
	case signaturekey.ResolutionDenied, signaturekey.ResolutionUnavailable:
		return err
	default:
		return signaturekey.NewError(signaturekey.ErrorInvalidKey, err)
	}
}

func acceptedSignatureKeyTypes(options VerifyRequestOptions) []signaturekey.Scheme {
	if len(options.AllowedSignatureKeyTypes) == 0 {
		return []signaturekey.Scheme{signaturekey.SchemeJWT}
	}
	return append([]signaturekey.Scheme(nil), options.AllowedSignatureKeyTypes...)
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
