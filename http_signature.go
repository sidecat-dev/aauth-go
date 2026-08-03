package aauth

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type selfJWTLocator struct {
	Issuer string
	DWK    string
}

func preflightSelfJWTClaims(payload []byte, now time.Time) (selfJWTLocator, error) {
	var locator selfJWTLocator
	var claims map[string]json.RawMessage
	if err := json.Unmarshal(payload, &claims); err != nil {
		return locator, newSignatureError(SignatureErrorInvalidJWT, fmt.Errorf("aauth: decode self-jwt claims: %w", err))
	}
	if _, ok := claims["cnf"]; ok {
		return locator, newSignatureError(SignatureErrorInvalidJWT, errors.New("aauth: self-jwt must not contain cnf"))
	}
	if err := json.Unmarshal(claims["iss"], &locator.Issuer); err != nil || locator.Issuer == "" {
		return locator, newSignatureError(SignatureErrorInvalidJWT, errors.New("aauth: self-jwt iss is required and must be a string"))
	}
	if err := ValidateServerIdentifier(locator.Issuer); err != nil {
		return locator, newSignatureError(SignatureErrorInvalidJWT, fmt.Errorf("aauth: self-jwt issuer: %w", err))
	}
	if err := json.Unmarshal(claims["dwk"], &locator.DWK); err != nil ||
		!discoveryDocumentPattern.MatchString(locator.DWK) {
		return locator, newSignatureError(SignatureErrorInvalidKey, errors.New("aauth: self-jwt dwk is required and must be a safe discovery document"))
	}
	if rawExpiry, ok := claims["exp"]; ok {
		var expiry int64
		if err := json.Unmarshal(rawExpiry, &expiry); err != nil || expiry <= 0 {
			return locator, newSignatureError(SignatureErrorInvalidJWT, errors.New("aauth: self-jwt exp must be a NumericDate"))
		}
		if expiry <= now.Unix() {
			return locator, newSignatureError(SignatureErrorExpiredJWT, &TokenValidationError{
				Code:  TokenValidationExpired,
				Cause: errors.New("token is expired"),
			})
		}
	}
	return locator, nil
}

const DefaultSignatureWindow = 60 * time.Second

const (
	SignatureKeyJWT     = "jwt"
	SignatureKeyJWKSURI = "jwks_uri"
	SignatureKeyHWK     = "hwk"
	SignatureKeyJKTJWT  = "jkt-jwt"
	SignatureKeySelfJWT = "self-jwt"
)

// VerifiedRequest is the trusted signing context of an HTTP request.
type VerifiedRequest struct {
	SignatureKeyType string
	Signer           string
	RawCredential    string
	CredentialType   string
	Agent            string
	PublicKey        JWK
	IdentityKey      JWK
	JKTJWT           *VerifiedJKTJWT
	AgentToken       *AgentTokenClaims
	AuthToken        *AuthTokenClaims
	SelfJWT          *VerifiedSelfJWT
	Created          time.Time
	ReplayKey        string
}

// SelfJWTClaimPolicy applies deployment-owned application claim rules after
// the self-jwt JWS is verified and before the HTTP Message Signature is
// verified. The supplied value is sealed and may be passed to a strict
// application decoder such as DecodeVerifiedEventToken.
type SelfJWTClaimPolicy func(VerifiedSelfJWT) error

// VerifyRequestOptions declares the message components and token forms a
// particular endpoint accepts.
type VerifyRequestOptions struct {
	RequiredComponents       []string
	AllowedCredentialTypes   []string
	AllowedSignatureKeyTypes []string
	SignatureWindow          time.Duration
	SelfJWTMaximumLifetime   time.Duration
	SelfJWTClaimPolicy       SelfJWTClaimPolicy
}

// SignRequestOptions controls optional HTTP Message Signature parameters.
// A zero ExpiresAt and empty Nonce preserve the default created-only profile.
type SignRequestOptions struct {
	ExpiresAt time.Time
	Nonce     string
}

// SignRequest applies the AAuth HTTP Message Signatures profile using a JWT
// identity credential in Signature-Key.
func SignRequest(request *http.Request, key SigningKey, credential string, clock Clock) error {
	return SignRequestWithOptions(request, key, credential, clock, SignRequestOptions{})
}

// SignRequestWithSelfJWT carries the exact caller-supplied compact JWT and
// signs the HTTP request with the same key that signed the JWT.
func SignRequestWithSelfJWT(
	request *http.Request,
	key SigningKey,
	compact string,
	clock Clock,
) error {
	if compact == "" {
		return errors.New("aauth: self-jwt is required")
	}
	header, _, signature, signingInput, err := decodeToken(compact)
	if err != nil {
		return fmt.Errorf("aauth: self-jwt: %w", err)
	}
	if header.Algorithm != "EdDSA" || header.KeyID == "" || header.KeyID != key.ID() {
		return errors.New("aauth: self-jwt signing key does not match the token header")
	}
	if err := verifyTokenSignatureWithKey(signingInput, signature, key.PublicJWK()); err != nil {
		return fmt.Errorf("aauth: self-jwt signing key does not verify the token: %w", err)
	}
	return signRequestWithSignatureKey(
		request,
		key,
		`sig=self-jwt;jwt=`+strconv.Quote(compact),
		clock,
		SignRequestOptions{},
	)
}

// SignRequestWithOptions applies the JWT Signature-Key profile with optional
// RFC 9421 signature parameters. ExpiresAt, when present, must be after the
// signing clock's current time.
func SignRequestWithOptions(
	request *http.Request,
	key SigningKey,
	credential string,
	clock Clock,
	options SignRequestOptions,
) error {
	if request == nil || request.URL == nil {
		return errors.New("aauth: request URL is required")
	}
	if clock == nil {
		return errors.New("aauth: clock is required")
	}
	if credential == "" {
		return errors.New("aauth: JWT credential is required")
	}
	return signRequestWithSignatureKey(
		request,
		key,
		`sig=jwt;jwt=`+strconv.Quote(credential),
		clock,
		options,
	)
}

// SignRequestWithHWK signs with the Ed25519 key carried inline in
// Signature-Key. The key is pseudonymous and requires no discovery resolver.
func SignRequestWithHWK(request *http.Request, key SigningKey, clock Clock) error {
	public := key.PublicJWK()
	if _, err := public.PublicKey(); err != nil {
		return fmt.Errorf("aauth: hwk signing key: %w", err)
	}
	header := `sig=hwk;kty=` + strconv.Quote(public.Kty) +
		`;crv=` + strconv.Quote(public.Crv) +
		`;x=` + strconv.Quote(public.X)
	return signRequestWithSignatureKey(request, key, header, clock, SignRequestOptions{})
}

// SignRequestWithJKTJWT signs with the delegated key named by a valid
// durable-key JWK Thumbprint JWT.
func SignRequestWithJKTJWT(
	request *http.Request,
	key SigningKey,
	delegation string,
	clock Clock,
) error {
	if delegation == "" {
		return errors.New("aauth: jkt-jwt delegation is required")
	}
	verified, err := VerifyJKTJWT(delegation, clock)
	if err != nil {
		return err
	}
	if !verified.Confirmation.Equal(key.PublicJWK()) {
		return errors.New("aauth: jkt-jwt delegated key does not match the request signing key")
	}
	return signRequestWithSignatureKey(
		request,
		key,
		`sig=jkt-jwt;jwt=`+strconv.Quote(delegation),
		clock,
		SignRequestOptions{},
	)
}

// SignRequestWithJWKSURI signs as a URI-identified server whose key is
// discoverable through the Signature-Key two-hop metadata/JWKS scheme.
func SignRequestWithJWKSURI(
	request *http.Request,
	key SigningKey,
	identifier string,
	discoveryDocument string,
	clock Clock,
) error {
	return SignRequestWithJWKSURIOptions(
		request,
		key,
		identifier,
		discoveryDocument,
		clock,
		SignRequestOptions{},
	)
}

// SignRequestWithJWKSURIOptions signs with a URI-identified server key and
// optional RFC 9421 signature parameters.
func SignRequestWithJWKSURIOptions(
	request *http.Request,
	key SigningKey,
	identifier string,
	discoveryDocument string,
	clock Clock,
	options SignRequestOptions,
) error {
	if err := ValidateServerIdentifier(identifier); err != nil {
		return fmt.Errorf("aauth: jwks_uri signer: %w", err)
	}
	if !discoveryDocumentPattern.MatchString(discoveryDocument) {
		return errors.New("aauth: jwks_uri discovery document is invalid")
	}
	if key.ID() == "" {
		return errors.New("aauth: jwks_uri signing key is required")
	}
	header := `sig=jwks_uri;id=` + strconv.Quote(identifier) +
		`;dwk=` + strconv.Quote(discoveryDocument) +
		`;kid=` + strconv.Quote(key.ID())
	return signRequestWithSignatureKey(request, key, header, clock, options)
}

func signRequestWithSignatureKey(
	request *http.Request,
	key SigningKey,
	signatureKeyHeader string,
	clock Clock,
	options SignRequestOptions,
) error {
	if request == nil || request.URL == nil {
		return errors.New("aauth: request URL is required")
	}
	if clock == nil {
		return errors.New("aauth: clock is required")
	}
	request.Header.Set("Signature-Key", signatureKeyHeader)
	components := []string{"@method", "@authority", "@path"}

	if request.Header.Get("Authorization") != "" {
		components = append(components, "authorization")
	}
	if hasRequestBody(request) {
		body, err := readRequestBody(request)
		if err != nil {
			return err
		}
		digest := sha256.Sum256(body)
		request.Header.Set("Content-Digest", "sha-256=:"+base64.StdEncoding.EncodeToString(digest[:])+":")
		components = append(components, "content-digest")
		if request.Header.Get("Content-Type") != "" {
			components = append(components, "content-type")
		}
	}
	if request.Header.Get("AAuth-Mission") != "" {
		components = append(components, "aauth-mission")
	}
	components = append(components, "signature-key")

	now := clock.Now()
	if !options.ExpiresAt.IsZero() && options.ExpiresAt.Unix() <= now.Unix() {
		return errors.New("aauth: signature expires time must be after created time")
	}
	if strings.ContainsAny(options.Nonce, "\r\n") {
		return errors.New("aauth: signature nonce must not contain line breaks")
	}
	params := signatureParams(components, now.Unix(), options.ExpiresAt, options.Nonce)
	base, err := signatureBase(request, components, params)
	if err != nil {
		return err
	}
	signature, err := key.sign([]byte(base))
	if err != nil {
		return err
	}
	request.Header.Set("Signature-Input", "sig="+params)
	request.Header.Set("Signature", "sig=:"+base64.StdEncoding.EncodeToString(signature)+":")
	return nil
}

// VerifyRequest verifies the JWT identity, required component coverage,
// content digest, freshness, confirmation-key binding, and HTTP signature.
func VerifyRequest(
	ctx context.Context,
	request *http.Request,
	resolver KeyResolver,
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

	signatureHeader := request.Header.Get("Signature")
	signatureInputHeader := request.Header.Get("Signature-Input")
	signatureKeyHeader := request.Header.Get("Signature-Key")
	if signatureHeader == "" || signatureInputHeader == "" || signatureKeyHeader == "" {
		// The generic Signature-Key draft groups absent proof headers under
		// invalid_signature. The AAuth core profile explicitly overrides that
		// classification: its verification step 1 requires invalid_request
		// before parsing or resolving any supplied proof material.
		return verified, newSignatureError(
			SignatureErrorInvalidRequest,
			errors.New("aauth: Signature, Signature-Input, and Signature-Key headers are required"),
		)
	}
	components, created, expires, params, err := parseSignatureInput(signatureInputHeader)
	if err != nil {
		return VerifiedRequest{}, newSignatureError(SignatureErrorInvalidSignature, err)
	}
	required := append([]string{"@method", "@authority", "@path", "signature-key"}, options.RequiredComponents...)
	if hasRequestBody(request) {
		required = append(required, "content-digest")
	}
	if request.Header.Get("AAuth-Mission") != "" {
		required = append(required, "aauth-mission")
	}
	if request.Header.Get("Authorization") != "" {
		required = append(required, "authorization")
	}
	for _, component := range required {
		if !contains(components, strings.ToLower(component)) {
			return VerifiedRequest{}, signatureErrorWithRequiredInput(
				fmt.Errorf("aauth: signature does not cover required component %q", component),
				required,
			)
		}
	}

	window := options.SignatureWindow
	if window == 0 {
		window = DefaultSignatureWindow
	}
	if window < 0 {
		return VerifiedRequest{}, newSignatureError(
			SignatureErrorInvalidRequest,
			errors.New("aauth: signature window must not be negative"),
		)
	}
	createdAt := time.Unix(created, 0)
	age := clock.Now().Sub(createdAt)
	if age < -window || age > window {
		return VerifiedRequest{}, newSignatureError(
			SignatureErrorInvalidSignature,
			errors.New("aauth: signature created time is outside the validity window"),
		)
	}
	if expires != nil && !time.Unix(*expires, 0).After(clock.Now()) {
		return VerifiedRequest{}, newSignatureError(
			SignatureErrorInvalidSignature,
			errors.New("aauth: signature expires time is in the past"),
		)
	}

	signatureKey, err := parseSignatureKey(signatureKeyHeader)
	if err != nil {
		return verified, newSignatureError(SignatureErrorInvalidKey, err)
	}
	allowedSignatureKeyTypes := options.AllowedSignatureKeyTypes
	if len(allowedSignatureKeyTypes) == 0 {
		allowedSignatureKeyTypes = []string{SignatureKeyJWT}
	}
	if !contains(allowedSignatureKeyTypes, signatureKey.scheme) {
		return verified, newSignatureError(SignatureErrorInvalidKey, fmt.Errorf("aauth: Signature-Key type %q is not accepted", signatureKey.scheme))
	}
	verified.SignatureKeyType = signatureKey.scheme

	switch signatureKey.scheme {
	case SignatureKeyJWT:
		if resolver == nil {
			return verified, keyResolutionError(
				KeyResolutionUnavailable,
				errors.New("aauth: key resolver is required"),
			)
		}
		header, err := PeekTokenHeader(signatureKey.parameters["jwt"])
		if err != nil {
			return verified, newSignatureError(SignatureErrorInvalidJWT, fmt.Errorf("aauth: Signature-Key JWT: %w", err))
		}
		if len(options.AllowedCredentialTypes) > 0 && !contains(options.AllowedCredentialTypes, header.Type) {
			return verified, newSignatureError(SignatureErrorInvalidJWT, fmt.Errorf("aauth: credential typ %q is not accepted", header.Type))
		}
		verified.RawCredential = signatureKey.parameters["jwt"]
		switch header.Type {
		case AgentTokenType:
			claims, verifyErr := VerifyAgentToken(ctx, verified.RawCredential, resolver, clock)
			if verifyErr != nil {
				return verified, classifyJWTVerificationError(verifyErr)
			}
			verified.CredentialType = AgentTokenType
			verified.Agent = claims.Subject
			verified.Signer = claims.Subject
			verified.PublicKey = claims.Confirmation.JWK
			verified.AgentToken = &claims
		case AuthTokenType:
			claims, verifyErr := VerifyAuthToken(ctx, verified.RawCredential, resolver, clock)
			if verifyErr != nil {
				return verified, classifyJWTVerificationError(verifyErr)
			}
			verified.CredentialType = AuthTokenType
			verified.Agent = claims.Agent
			verified.Signer = claims.Agent
			verified.PublicKey = claims.Confirmation.JWK
			verified.AuthToken = &claims
		default:
			return verified, newSignatureError(SignatureErrorInvalidJWT, fmt.Errorf("aauth: unsupported Signature-Key JWT typ %q", header.Type))
		}
	case SignatureKeyJWKSURI:
		if resolver == nil {
			return verified, keyResolutionError(
				KeyResolutionUnavailable,
				errors.New("aauth: key resolver is required"),
			)
		}
		identifier := signatureKey.parameters["id"]
		document := signatureKey.parameters["dwk"]
		keyID := signatureKey.parameters["kid"]
		if err := ValidateServerIdentifier(identifier); err != nil {
			return verified, newSignatureError(SignatureErrorInvalidKey, fmt.Errorf("aauth: Signature-Key id: %w", err))
		}
		if !discoveryDocumentPattern.MatchString(document) || keyID == "" {
			return verified, newSignatureError(SignatureErrorInvalidKey, errors.New("aauth: Signature-Key jwks_uri parameters are invalid"))
		}
		resolved, err := resolver.ResolveKey(ctx, identifier, document, keyID)
		if err != nil {
			return verified, classifyJWKSURIResolutionError(err)
		}
		verified.Signer = identifier
		verified.PublicKey = resolved
		verified.IdentityKey = resolved
	case SignatureKeyHWK:
		inline := JWK{
			Kty: signatureKey.parameters["kty"],
			Crv: signatureKey.parameters["crv"],
			X:   signatureKey.parameters["x"],
		}
		if _, err := inline.PublicKey(); err != nil {
			return verified, newSignatureError(SignatureErrorInvalidKey, fmt.Errorf("aauth: Signature-Key hwk: %w", err))
		}
		identity, err := inline.ThumbprintURI()
		if err != nil {
			return verified, newSignatureError(SignatureErrorInvalidKey, fmt.Errorf("aauth: Signature-Key hwk identity: %w", err))
		}
		verified.Signer = identity
		verified.PublicKey = inline
		verified.IdentityKey = inline
	case SignatureKeyJKTJWT:
		delegation, err := VerifyJKTJWT(signatureKey.parameters["jwt"], clock)
		if err != nil {
			return verified, classifyJWTVerificationError(err)
		}
		verified.RawCredential = signatureKey.parameters["jwt"]
		verified.Signer = delegation.Issuer
		verified.PublicKey = delegation.Confirmation
		verified.IdentityKey = delegation.IdentityKey
		verified.JKTJWT = &delegation
	case SignatureKeySelfJWT:
		if options.SelfJWTMaximumLifetime < 0 {
			return verified, newSignatureError(
				SignatureErrorInvalidRequest,
				errors.New("aauth: self-jwt maximum lifetime must not be negative"),
			)
		}
		if resolver == nil {
			return verified, keyResolutionError(
				KeyResolutionUnavailable,
				errors.New("aauth: key resolver is required"),
			)
		}
		compact := signatureKey.parameters["jwt"]
		header, payload, tokenSignature, signingInput, err := decodeToken(compact)
		if err != nil {
			return verified, newSignatureError(SignatureErrorInvalidJWT, fmt.Errorf("aauth: Signature-Key self-jwt: %w", err))
		}
		if header.Algorithm == "none" {
			return verified, newSignatureError(SignatureErrorInvalidJWT, errors.New("aauth: alg none is forbidden"))
		}
		if header.Algorithm != "EdDSA" {
			return verified, newSignatureError(SignatureErrorInvalidJWT, &unsupportedTokenAlgorithmError{algorithm: header.Algorithm})
		}
		if len(options.AllowedCredentialTypes) > 0 && !contains(options.AllowedCredentialTypes, header.Type) {
			return verified, newSignatureError(SignatureErrorInvalidJWT, fmt.Errorf("aauth: credential typ %q is not accepted", header.Type))
		}
		locator, err := preflightSelfJWTClaims(payload, clock.Now())
		if err != nil {
			return verified, err
		}
		if header.KeyID == "" {
			return verified, newSignatureError(SignatureErrorInvalidKey, errors.New("aauth: self-jwt kid is required"))
		}
		resolved, err := resolver.ResolveKey(ctx, locator.Issuer, locator.DWK, header.KeyID)
		if err != nil {
			return verified, classifyJWKSURIResolutionError(err)
		}
		if err := verifyTokenSignatureWithKey(signingInput, tokenSignature, resolved); err != nil {
			return verified, classifyJWTVerificationError(err)
		}
		selfJWT := newVerifiedSelfJWT(header, locator.Issuer, locator.DWK, payload)
		if err := validateSelfJWTMaximumLifetime(selfJWT, options.SelfJWTMaximumLifetime); err != nil {
			return verified, newSignatureError(SignatureErrorInvalidJWT, err)
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

	if contains(components, "content-digest") {
		if err := verifyContentDigest(request); err != nil {
			return VerifiedRequest{}, newSignatureError(SignatureErrorInvalidSignature, err)
		}
	}
	base, err := signatureBase(request, components, params)
	if err != nil {
		return VerifiedRequest{}, newSignatureError(SignatureErrorInvalidSignature, err)
	}
	signature, err := parseSignature(signatureHeader)
	if err != nil {
		return VerifiedRequest{}, newSignatureError(SignatureErrorInvalidSignature, err)
	}
	publicKey, err := verified.PublicKey.PublicKey()
	if err != nil {
		if verified.PublicKey.Alg != "" && verified.PublicKey.Alg != "EdDSA" {
			return VerifiedRequest{}, &SignatureError{Code: SignatureErrorUnsupportedAlgorithm, SupportedAlgorithms: []string{"ed25519"}, Cause: err}
		}
		return VerifiedRequest{}, newSignatureError(SignatureErrorInvalidKey, err)
	}
	ed25519Key, ok := publicKey.(ed25519.PublicKey)
	if !ok {
		return VerifiedRequest{}, &SignatureError{Code: SignatureErrorUnsupportedAlgorithm, SupportedAlgorithms: []string{"ed25519"}, Cause: errors.New("aauth: request confirmation key is not Ed25519")}
	}
	if !ed25519.Verify(ed25519Key, []byte(base), signature) {
		return VerifiedRequest{}, newSignatureError(SignatureErrorInvalidSignature, errors.New("aauth: HTTP message signature is invalid"))
	}

	replayMaterial := append([]byte(base), signature...)
	replayDigest := sha256.Sum256(replayMaterial)
	verified.Created = createdAt
	verified.ReplayKey = rawURL.EncodeToString(replayDigest[:])
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

func signatureParams(components []string, created int64, expires time.Time, nonce string) string {
	var quoted []string
	for _, component := range components {
		quoted = append(quoted, strconv.Quote(component))
	}
	params := "(" + strings.Join(quoted, " ") + ");created=" + strconv.FormatInt(created, 10)
	if !expires.IsZero() {
		params += ";expires=" + strconv.FormatInt(expires.Unix(), 10)
	}
	if nonce != "" {
		params += ";nonce=" + strconv.Quote(nonce)
	}
	return params
}

func signatureBase(request *http.Request, components []string, params string) (string, error) {
	lines := make([]string, 0, len(components)+1)
	for _, component := range components {
		var value string
		switch component {
		case "@method":
			value = request.Method
		case "@authority":
			var err error
			value, err = normalizedRequestAuthority(request)
			if err != nil {
				return "", err
			}
		case "@path":
			value = request.URL.EscapedPath()
			if value == "" {
				value = "/"
			}
		default:
			if strings.HasPrefix(component, "@") {
				return "", fmt.Errorf("aauth: unsupported derived signature component %q", component)
			}
			values := request.Header.Values(http.CanonicalHeaderKey(component))
			if len(values) == 0 {
				return "", fmt.Errorf("aauth: covered header %q is absent", component)
			}
			// RFC 9421 Section 2.1 derives a single field value by combining
			// every field line in order with a comma and one space. Covering
			// only the first value would let an appended field line evade the
			// signature.
			value = strings.Join(values, ", ")
		}
		lines = append(lines, strconv.Quote(component)+": "+value)
	}
	lines = append(lines, `"@signature-params": `+params)
	return strings.Join(lines, "\n"), nil
}

func normalizedRequestAuthority(request *http.Request) (string, error) {
	authority := request.Host
	if authority == "" {
		authority = request.URL.Host
	}
	if authority == "" {
		return "", errors.New("aauth: request authority is required")
	}

	host, port, err := net.SplitHostPort(authority)
	if err != nil {
		// A bracketed IPv6 literal without a port is already in the authority
		// form. Registered host names are case-insensitive.
		if !strings.Contains(authority, ":") ||
			strings.HasPrefix(authority, "[") && strings.HasSuffix(authority, "]") {
			return strings.ToLower(authority), nil
		}
		return "", fmt.Errorf("aauth: request authority %q is invalid: %w", authority, err)
	}
	host = strings.ToLower(host)
	scheme := strings.ToLower(request.URL.Scheme)
	if scheme == "" {
		if request.TLS != nil {
			scheme = "https"
		} else {
			scheme = "http"
		}
	}
	if (scheme == "https" && port == "443") || (scheme == "http" && port == "80") {
		if strings.Contains(host, ":") {
			return "[" + host + "]", nil
		}
		return host, nil
	}
	return net.JoinHostPort(host, port), nil
}

func parseSignatureInput(header string) ([]string, int64, *int64, string, error) {
	if !strings.HasPrefix(header, "sig=(") {
		return nil, 0, nil, "", errors.New("aauth: Signature-Input must contain the sig label")
	}
	params := strings.TrimPrefix(header, "sig=")
	end := strings.IndexByte(params, ')')
	if end < 1 {
		return nil, 0, nil, "", errors.New("aauth: Signature-Input has invalid parameters")
	}
	componentText := params[1:end]

	var components []string
	for len(strings.TrimSpace(componentText)) > 0 {
		componentText = strings.TrimSpace(componentText)
		if componentText[0] != '"' {
			return nil, 0, nil, "", errors.New("aauth: Signature-Input component is not quoted")
		}
		endQuote := 1
		for endQuote < len(componentText) {
			if componentText[endQuote] == '"' && componentText[endQuote-1] != '\\' {
				break
			}
			endQuote++
		}
		if endQuote >= len(componentText) {
			return nil, 0, nil, "", errors.New("aauth: Signature-Input component quote is unterminated")
		}
		value, err := strconv.Unquote(componentText[:endQuote+1])
		if err != nil {
			return nil, 0, nil, "", fmt.Errorf("aauth: decode Signature-Input component: %w", err)
		}
		value = strings.ToLower(value)
		if contains(components, value) {
			return nil, 0, nil, "", fmt.Errorf("aauth: duplicate signed component %q", value)
		}
		components = append(components, value)
		componentText = componentText[endQuote+1:]
	}
	if len(components) == 0 {
		return nil, 0, nil, "", errors.New("aauth: Signature-Input covers no components")
	}

	var created int64
	var expires *int64
	seenCreated := false
	seenNonce := false
	remainder := params[end+1:]
	for remainder != "" {
		if !strings.HasPrefix(remainder, ";") {
			return nil, 0, nil, "", errors.New("aauth: Signature-Input parameter separator is invalid")
		}
		remainder = remainder[1:]
		parameterEnd := strings.IndexByte(remainder, ';')
		parameter := remainder
		if parameterEnd >= 0 {
			parameter = remainder[:parameterEnd]
			remainder = remainder[parameterEnd:]
		} else {
			remainder = ""
		}
		name, value, ok := strings.Cut(parameter, "=")
		if !ok || name == "" || value == "" || strings.ContainsAny(name, " ,\t\r\n") || strings.ContainsAny(value, " ,\t\r\n") {
			return nil, 0, nil, "", errors.New("aauth: Signature-Input parameter is invalid")
		}
		switch name {
		case "created":
			if seenCreated {
				return nil, 0, nil, "", errors.New("aauth: Signature-Input created is duplicated")
			}
			parsed, err := strconv.ParseInt(value, 10, 64)
			if err != nil || parsed <= 0 {
				return nil, 0, nil, "", errors.New("aauth: Signature-Input created is invalid")
			}
			created, seenCreated = parsed, true
		case "expires":
			if expires != nil {
				return nil, 0, nil, "", errors.New("aauth: Signature-Input expires is duplicated")
			}
			parsed, err := strconv.ParseInt(value, 10, 64)
			if err != nil || parsed <= 0 {
				return nil, 0, nil, "", errors.New("aauth: Signature-Input expires is invalid")
			}
			expires = &parsed
		case "nonce":
			if seenNonce {
				return nil, 0, nil, "", errors.New("aauth: Signature-Input nonce is duplicated")
			}
			nonce, err := strconv.Unquote(value)
			if err != nil || nonce == "" {
				return nil, 0, nil, "", errors.New("aauth: Signature-Input nonce is invalid")
			}
			seenNonce = true
		}
	}
	if !seenCreated {
		return nil, 0, nil, "", errors.New("aauth: Signature-Input created is required")
	}
	if expires != nil && *expires <= created {
		return nil, 0, nil, "", errors.New("aauth: Signature-Input expires must be after created")
	}
	return components, created, expires, params, nil
}

func classifyJWTVerificationError(err error) error {
	if err == nil {
		return nil
	}
	var resolutionError *KeyResolutionError
	if errors.As(err, &resolutionError) {
		switch resolutionError.Code {
		case KeyResolutionUnknown:
			return newSignatureError(SignatureErrorUnknownKey, err)
		case KeyResolutionDenied, KeyResolutionUnavailable:
			return err
		}
	}
	var validation *TokenValidationError
	if errors.As(err, &validation) {
		switch validation.Code {
		case TokenValidationExpired:
			return newSignatureError(SignatureErrorExpiredJWT, err)
		case TokenValidationInvalidKey:
			return newSignatureError(SignatureErrorInvalidKey, err)
		}
	}
	return newSignatureError(SignatureErrorInvalidJWT, err)
}

func classifyJWKSURIResolutionError(err error) error {
	var resolutionError *KeyResolutionError
	if !errors.As(err, &resolutionError) {
		return normalizeKeyResolutionError(err)
	}
	switch resolutionError.Code {
	case KeyResolutionUnknown:
		return newSignatureError(SignatureErrorUnknownKey, err)
	case KeyResolutionInvalid:
		return newSignatureError(SignatureErrorInvalidKey, err)
	case KeyResolutionDenied, KeyResolutionUnavailable:
		return err
	default:
		return newSignatureError(SignatureErrorInvalidKey, err)
	}
}

type parsedSignatureKey struct {
	scheme     string
	parameters map[string]string
}

func parseSignatureKey(header string) (parsedSignatureKey, error) {
	var parsed parsedSignatureKey
	if !strings.HasPrefix(header, "sig=") {
		return parsed, errors.New("aauth: Signature-Key must contain the sig label")
	}
	remainder := strings.TrimPrefix(header, "sig=")
	schemeEnd := strings.IndexByte(remainder, ';')
	if schemeEnd < 1 {
		return parsed, errors.New("aauth: Signature-Key scheme or parameters are missing")
	}
	parsed.scheme = remainder[:schemeEnd]
	parsed.parameters = make(map[string]string)
	remainder = remainder[schemeEnd:]
	for remainder != "" {
		if remainder[0] != ';' {
			return parsedSignatureKey{}, errors.New("aauth: Signature-Key parameter separator is invalid")
		}
		remainder = strings.TrimLeft(remainder[1:], " \t")
		equals := strings.IndexByte(remainder, '=')
		if equals <= 0 {
			return parsedSignatureKey{}, errors.New("aauth: Signature-Key parameter is invalid")
		}
		name := remainder[:equals]
		remainder = remainder[equals+1:]
		if _, exists := parsed.parameters[name]; exists {
			return parsedSignatureKey{}, fmt.Errorf("aauth: duplicate Signature-Key parameter %q", name)
		}
		if remainder == "" || remainder[0] != '"' {
			return parsedSignatureKey{}, fmt.Errorf("aauth: Signature-Key parameter %q must be a string", name)
		}
		endQuote := 1
		for endQuote < len(remainder) {
			if remainder[endQuote] == '"' && remainder[endQuote-1] != '\\' {
				break
			}
			endQuote++
		}
		if endQuote >= len(remainder) {
			return parsedSignatureKey{}, fmt.Errorf("aauth: Signature-Key parameter %q is unterminated", name)
		}
		value, err := strconv.Unquote(remainder[:endQuote+1])
		if err != nil || value == "" {
			return parsedSignatureKey{}, fmt.Errorf("aauth: Signature-Key parameter %q is invalid", name)
		}
		parsed.parameters[name] = value
		remainder = remainder[endQuote+1:]
	}
	required := map[string][]string{
		SignatureKeyJWT:     {"jwt"},
		SignatureKeyJWKSURI: {"id", "dwk", "kid"},
		SignatureKeyHWK:     {"kty", "crv", "x"},
		SignatureKeyJKTJWT:  {"jwt"},
		SignatureKeySelfJWT: {"jwt"},
	}[parsed.scheme]
	if required == nil {
		return parsedSignatureKey{}, fmt.Errorf("aauth: unsupported Signature-Key scheme %q", parsed.scheme)
	}
	if len(parsed.parameters) != len(required) {
		return parsedSignatureKey{}, fmt.Errorf("aauth: Signature-Key %s has unexpected parameters", parsed.scheme)
	}
	for _, name := range required {
		if parsed.parameters[name] == "" {
			return parsedSignatureKey{}, fmt.Errorf("aauth: Signature-Key %s requires %s", parsed.scheme, name)
		}
	}
	return parsed, nil
}

func parseSignature(header string) ([]byte, error) {
	const prefix = "sig=:"
	if !strings.HasPrefix(header, prefix) || !strings.HasSuffix(header, ":") {
		return nil, errors.New("aauth: Signature must contain the sig byte sequence")
	}
	encoded := strings.TrimSuffix(strings.TrimPrefix(header, prefix), ":")
	signature, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("aauth: decode HTTP signature: %w", err)
	}
	if len(signature) != ed25519.SignatureSize {
		return nil, fmt.Errorf("aauth: Ed25519 HTTP signature has %d bytes", len(signature))
	}
	return signature, nil
}

func verifyContentDigest(request *http.Request) error {
	header := request.Header.Get("Content-Digest")
	const prefix = "sha-256=:"
	if !strings.HasPrefix(header, prefix) || !strings.HasSuffix(header, ":") {
		return errors.New("aauth: Content-Digest must use sha-256")
	}
	expected, err := base64.StdEncoding.DecodeString(strings.TrimSuffix(strings.TrimPrefix(header, prefix), ":"))
	if err != nil || len(expected) != sha256.Size {
		return errors.New("aauth: Content-Digest sha-256 value is invalid")
	}
	body, err := readRequestBody(request)
	if err != nil {
		return err
	}
	actual := sha256.Sum256(body)
	if !bytes.Equal(expected, actual[:]) {
		return errors.New("aauth: Content-Digest does not match request body")
	}
	return nil
}

func readRequestBody(request *http.Request) ([]byte, error) {
	if !hasRequestBody(request) {
		return nil, nil
	}
	body, err := io.ReadAll(request.Body)
	if err != nil {
		return nil, fmt.Errorf("aauth: read request body: %w", err)
	}
	request.Body.Close()
	request.Body = io.NopCloser(bytes.NewReader(body))
	request.ContentLength = int64(len(body))
	request.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(body)), nil
	}
	return body, nil
}

func hasRequestBody(request *http.Request) bool {
	return request.Body != nil && request.Body != http.NoBody && request.ContentLength != 0
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
