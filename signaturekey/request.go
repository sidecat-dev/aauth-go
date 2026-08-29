package signaturekey

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"gitlab.com/sidecat-dev/aauth-go/jose"
)

const DefaultSignatureWindow = 60 * time.Second

// SignOptions controls optional RFC 9421 signature parameters.
type SignOptions struct {
	ExpiresAt time.Time
	Nonce     string
}

// VerifyOptions declares the proof schemes and message components accepted by
// one endpoint.
type VerifyOptions struct {
	RequiredComponents     []string
	RequireExactComponents bool
	AcceptedSchemes        []Scheme
	SignatureWindow        time.Duration
}

// PreparedRequest retains one exact parsed request proof before its selected
// key has been verified.
type PreparedRequest struct {
	initialized bool
	credential  Credential
	base        string
	signature   []byte
	components  []string
	created     time.Time
	verifiedAt  time.Time
	method      string
	authority   string
	path        string
}

// VerifiedRequest is sealed evidence that one exact prepared request verified
// under one exact public key.
type VerifiedRequest struct {
	credential Credential
	publicKey  jose.JWK
	signer     string
	replayKey  string
	components []string
	created    time.Time
	verifiedAt time.Time
	method     string
	authority  string
	path       string
}

// SignJWTRequest signs with an opaque JWT credential and the key selected by
// that credential's owning protocol.
func SignJWTRequest(request *http.Request, key jose.SigningKey, compact string, clock Clock) error {
	return SignJWTRequestWithOptions(request, key, compact, clock, SignOptions{})
}

// SignJWTRequestWithOptions signs with an opaque JWT credential and optional
// RFC 9421 signature parameters.
func SignJWTRequestWithOptions(request *http.Request, key jose.SigningKey, compact string, clock Clock, options SignOptions) error {
	credential, err := NewJWTCredential(compact)
	if err != nil {
		return err
	}
	return SignRequest(request, key, credential, clock, options)
}

// SignHWKRequest signs with an inline pseudonymous Ed25519 JWK.
func SignHWKRequest(request *http.Request, key jose.SigningKey, clock Clock) error {
	credential, err := NewHWKCredential(key.PublicJWK())
	if err != nil {
		return err
	}
	return SignRequest(request, key, credential, clock, SignOptions{})
}

// SignJWKSURIRequest signs as an HTTPS-identified server whose key is selected
// through a dot-well-known metadata document.
func SignJWKSURIRequest(request *http.Request, key jose.SigningKey, identifier, discoveryDocument string, clock Clock) error {
	return SignJWKSURIRequestWithOptions(request, key, identifier, discoveryDocument, clock, SignOptions{})
}

// SignJWKSURIRequestWithOptions signs a jwks_uri request with optional RFC
// 9421 signature parameters.
func SignJWKSURIRequestWithOptions(
	request *http.Request,
	key jose.SigningKey,
	identifier string,
	discoveryDocument string,
	clock Clock,
	options SignOptions,
) error {
	credential, err := NewJWKSURICredential(identifier, discoveryDocument, key.ID())
	if err != nil {
		return err
	}
	return SignRequest(request, key, credential, clock, options)
}

// SignSelfJWTRequest verifies that the selected key signed the compact JWT,
// then uses the same key for the HTTP Message Signature.
func SignSelfJWTRequest(request *http.Request, key jose.SigningKey, compact string, clock Clock) error {
	credential, err := NewSelfJWTCredential(compact)
	if err != nil {
		return err
	}
	parsed, err := jose.ParseCompact(compact)
	if err != nil {
		return fmt.Errorf("aauth: self-jwt: %w", err)
	}
	header := parsed.Header()
	if header.Algorithm != jose.Ed25519Algorithm || header.KeyID == "" || header.KeyID != key.ID() {
		return errors.New("aauth: self-jwt signing key does not match the token header")
	}
	if _, err := parsed.Verify(key.PublicJWK()); err != nil {
		return fmt.Errorf("aauth: self-jwt signing key does not verify the token: %w", err)
	}
	return SignRequest(request, key, credential, clock, SignOptions{})
}

// SignJKTJWTRequest verifies the durable delegation and signs with its exact
// delegated confirmation key.
func SignJKTJWTRequest(request *http.Request, key jose.SigningKey, compact string, clock Clock) error {
	credential, err := NewJKTJWTCredential(compact)
	if err != nil {
		return err
	}
	verified, err := VerifyJKTJWT(compact, clock)
	if err != nil {
		return err
	}
	if !verified.Confirmation.Equal(key.PublicJWK()) {
		return errors.New("aauth: jkt-jwt delegated key does not match the request signing key")
	}
	return SignRequest(request, key, credential, clock, SignOptions{})
}

// SignRequest signs one request with the exact supplied Signature-Key
// credential.
func SignRequest(request *http.Request, key jose.SigningKey, credential Credential, clock Clock, options SignOptions) error {
	if request == nil || request.URL == nil {
		return errors.New("aauth: request URL is required")
	}
	if clock == nil {
		return errors.New("aauth: clock is required")
	}
	if credential.scheme == "" || credential.header == "" {
		return errors.New("aauth: Signature-Key credential is required")
	}
	if credential.scheme == SchemeHWK {
		inline, ok := credential.InlineJWK()
		if !ok || !inline.Equal(key.PublicJWK()) {
			return errors.New("aauth: hwk credential does not match the request signing key")
		}
	}
	request.Header.Set("Signature-Key", credential.header)
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
	signature, err := key.Sign(rand.Reader, []byte(base), crypto.Hash(0))
	if err != nil {
		return err
	}
	request.Header.Set("Signature-Input", "sig="+params)
	request.Header.Set("Signature", "sig=:"+base64.StdEncoding.EncodeToString(signature)+":")
	return nil
}

// PrepareRequest validates and seals the key-independent parts of a signed
// request so credential-specific code can select its proof key.
func PrepareRequest(request *http.Request, clock Clock, options VerifyOptions) (PreparedRequest, error) {
	var prepared PreparedRequest
	if request == nil || request.URL == nil {
		return prepared, errors.New("aauth: request URL is required")
	}
	if clock == nil {
		return prepared, errors.New("aauth: clock is required")
	}
	signatureHeader := request.Header.Get("Signature")
	signatureInput := request.Header.Get("Signature-Input")
	credentialHeaders := request.Header.Values("Signature-Key")
	if signatureHeader == "" || signatureInput == "" || len(credentialHeaders) == 0 {
		return prepared, errors.New("aauth: Signature, Signature-Input, and Signature-Key headers are required")
	}
	components, created, expires, params, err := parseSignatureInput(signatureInput)
	if err != nil {
		return prepared, newError(ErrorInvalidSignature, err)
	}
	required := append([]string{"@method", "@authority", "@path", "signature-key"}, options.RequiredComponents...)
	if hasRequestBody(request) {
		required = append(required, "content-digest")
	}
	if request.Header.Get("Authorization") != "" {
		if options.RequireExactComponents && !contains(options.RequiredComponents, "authorization") {
			return prepared, newError(
				ErrorInvalidSignature,
				errors.New("aauth: Authorization is outside the endpoint's exact component profile"),
			)
		}
		required = append(required, "authorization")
	}
	for _, component := range required {
		if !contains(components, strings.ToLower(component)) {
			return prepared, &Error{
				Code:          ErrorInvalidInput,
				RequiredInput: uniqueLower(required),
				Cause:         fmt.Errorf("aauth: signature does not cover required component %q", component),
			}
		}
	}
	if options.RequireExactComponents {
		expected := make(map[string]struct{}, len(required))
		for _, component := range required {
			expected[strings.ToLower(component)] = struct{}{}
		}
		if len(components) != len(expected) {
			return prepared, newError(ErrorInvalidSignature, errors.New("aauth: signature does not match the endpoint's exact component profile"))
		}
		for _, component := range components {
			if _, ok := expected[component]; !ok {
				return prepared, newError(ErrorInvalidSignature, fmt.Errorf("aauth: covered component %q is outside the endpoint's exact component profile", component))
			}
		}
		retainedFields := []string{"signature", "signature-input"}
		for _, component := range components {
			if !strings.HasPrefix(component, "@") {
				retainedFields = append(retainedFields, component)
			}
		}
		for _, field := range retainedFields {
			if len(request.Header.Values(field)) != 1 {
				return prepared, newError(ErrorInvalidSignature, fmt.Errorf("aauth: exact component profile field %q has multiple field lines", field))
			}
		}
	}
	verifiedAt := clock.Now().UTC()
	window := options.SignatureWindow
	if window == 0 {
		window = DefaultSignatureWindow
	}
	if window < 0 {
		return prepared, newError(ErrorInvalidRequest, errors.New("aauth: signature window must not be negative"))
	}
	createdAt := time.Unix(created, 0)
	age := verifiedAt.Sub(createdAt)
	if age < -window || age > window {
		return prepared, newError(ErrorInvalidSignature, errors.New("aauth: signature created time is outside the validity window"))
	}
	if expires != nil && !time.Unix(*expires, 0).After(verifiedAt) {
		return prepared, newError(ErrorInvalidSignature, errors.New("aauth: signature expires time is in the past"))
	}
	accepted := options.AcceptedSchemes
	if len(accepted) == 0 {
		accepted = []Scheme{SchemeJWT}
	}
	credential, err := parseCredential(credentialHeaders)
	if err != nil {
		var failure *Error
		if errors.As(err, &failure) {
			if failure.Code == ErrorUnsupportedScheme {
				return prepared, &Error{
					Code:            failure.Code,
					AcceptedSchemes: append([]Scheme(nil), accepted...),
					Cause:           failure.Cause,
				}
			}
			return prepared, err
		}
		return prepared, &Error{Code: ErrorInvalidKey, Cause: err}
	}
	if !containsScheme(accepted, credential.scheme) {
		return prepared, &Error{
			Code:            ErrorUnsupportedScheme,
			AcceptedSchemes: append([]Scheme(nil), accepted...),
			Cause:           fmt.Errorf("aauth: Signature-Key type %q is not accepted", credential.scheme),
		}
	}
	if contains(components, "content-digest") {
		if err := verifyContentDigest(request); err != nil {
			return prepared, newError(ErrorInvalidSignature, err)
		}
	}
	base, err := signatureBase(request, components, params)
	if err != nil {
		return prepared, newError(ErrorInvalidSignature, err)
	}
	signature, err := parseSignature(signatureHeader)
	if err != nil {
		return prepared, newError(ErrorInvalidSignature, err)
	}
	authority, err := normalizedRequestAuthority(request)
	if err != nil {
		return prepared, err
	}
	path := request.URL.EscapedPath()
	if path == "" {
		path = "/"
	}
	return PreparedRequest{
		initialized: true,
		credential:  credential,
		base:        base,
		signature:   append([]byte(nil), signature...),
		components:  append([]string(nil), components...),
		created:     createdAt,
		verifiedAt:  verifiedAt,
		method:      request.Method,
		authority:   authority,
		path:        path,
	}, nil
}

// Credential returns an independent projection of the prepared credential.
func (prepared PreparedRequest) Credential() Credential {
	parameters := make(map[string]string, len(prepared.credential.parameters))
	for name, value := range prepared.credential.parameters {
		parameters[name] = value
	}
	return Credential{scheme: prepared.credential.scheme, parameters: parameters, header: prepared.credential.header}
}

// Created returns the trusted created time parsed from Signature-Input.
func (prepared PreparedRequest) Created() time.Time { return prepared.created }

// VerifiedAt returns the single trusted instant captured during preparation.
func (prepared PreparedRequest) VerifiedAt() time.Time { return prepared.verifiedAt }

// Verify verifies the prepared HTTP Message Signature with the selected key.
func (prepared PreparedRequest) Verify(key jose.JWK) (VerifiedRequest, error) {
	if !prepared.initialized || prepared.base == "" || len(prepared.signature) == 0 {
		return VerifiedRequest{}, errors.New("aauth: prepared request is not initialized")
	}
	publicKey, err := key.PublicKey()
	if err != nil {
		if key.Alg != jose.Ed25519Algorithm {
			return VerifiedRequest{}, &Error{Code: ErrorUnsupportedAlgorithm, AcceptedAlgorithms: []string{jose.Ed25519Algorithm}, Cause: err}
		}
		return VerifiedRequest{}, newError(ErrorInvalidKey, err)
	}
	ed25519Key, ok := publicKey.(ed25519.PublicKey)
	if !ok {
		return VerifiedRequest{}, &Error{Code: ErrorUnsupportedAlgorithm, AcceptedAlgorithms: []string{jose.Ed25519Algorithm}, Cause: errors.New("aauth: request confirmation key is not Ed25519")}
	}
	if !ed25519.Verify(ed25519Key, []byte(prepared.base), prepared.signature) {
		return VerifiedRequest{}, newError(ErrorInvalidSignature, errors.New("aauth: HTTP message signature is invalid"))
	}
	replayMaterial := append([]byte(prepared.base), prepared.signature...)
	replayDigest := sha256.Sum256(replayMaterial)
	signer := ""
	if prepared.credential.scheme == SchemeHWK {
		signer, err = key.ThumbprintURI()
		if err != nil {
			return VerifiedRequest{}, err
		}
	} else if prepared.credential.scheme == SchemeJWKSURI {
		signer, _, _, _ = prepared.credential.JWKSURI()
	}
	return VerifiedRequest{
		credential: prepared.Credential(),
		publicKey:  key,
		signer:     signer,
		replayKey:  base64.RawURLEncoding.EncodeToString(replayDigest[:]),
		components: append([]string(nil), prepared.components...),
		created:    prepared.created,
		verifiedAt: prepared.verifiedAt,
		method:     prepared.method,
		authority:  prepared.authority,
		path:       prepared.path,
	}, nil
}

func (verified VerifiedRequest) Scheme() Scheme        { return verified.credential.scheme }
func (verified VerifiedRequest) Signer() string        { return verified.signer }
func (verified VerifiedRequest) ReplayKey() string     { return verified.replayKey }
func (verified VerifiedRequest) PublicKey() jose.JWK   { return verified.publicKey }
func (verified VerifiedRequest) Created() time.Time    { return verified.created }
func (verified VerifiedRequest) VerifiedAt() time.Time { return verified.verifiedAt }
func (verified VerifiedRequest) Method() string        { return verified.method }
func (verified VerifiedRequest) Authority() string     { return verified.authority }
func (verified VerifiedRequest) Path() string          { return verified.path }
func (verified VerifiedRequest) CoveredComponents() []string {
	return append([]string(nil), verified.components...)
}

func signatureParams(components []string, created int64, expires time.Time, nonce string) string {
	quoted := make([]string, 0, len(components))
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
		if !strings.Contains(authority, ":") || strings.HasPrefix(authority, "[") && strings.HasSuffix(authority, "]") {
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
	if err := request.Body.Close(); err != nil {
		return nil, fmt.Errorf("aauth: close request body: %w", err)
	}
	request.Body = io.NopCloser(bytes.NewReader(body))
	request.ContentLength = int64(len(body))
	request.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(body)), nil }
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

func containsScheme(values []Scheme, target Scheme) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func uniqueLower(values []string) []string {
	result := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.ToLower(value)
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}
