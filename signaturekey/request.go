package signaturekey

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/dunglas/httpsfv"
	"gitlab.com/sidecat-dev/aauth-go/jose"
)

// DefaultSignatureWindow is the Core request-proof freshness window.
const DefaultSignatureWindow = 60 * time.Second

const defaultMaxBodyBytes = 1 << 20

// SignOptions controls optional RFC 9421 signature parameters. Nonempty content
// always adds content-digest and, when present, content-type coverage.
type SignOptions struct {
	ExpiresAt            time.Time
	Nonce                string
	AdditionalComponents []string
	MaxBodyBytes         int64
}

// VerifyOptions declares the proof schemes and message components accepted by
// one endpoint. Nonempty content additionally requires content-digest and, when
// present, content-type coverage. MaxBodyBytes bounds content verification and
// defaults to 1 MiB.
type VerifyOptions struct {
	RequiredComponents     []string
	RequireExactComponents bool
	AcceptedSchemes        []Scheme
	SignatureLabel         string
	SignatureWindow        time.Duration
	MaxBodyBytes           int64
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
	window      time.Duration
	method      string
	authority   string
	path        string
	exactBody   []byte
}

// VerifiedRequest contains one prepared request verified under one public key.
type VerifiedRequest struct {
	credential Credential
	publicKey  jose.JWK
	signer     string
	replayKey  string
	components []string
	created    time.Time
	verifiedAt time.Time
	window     time.Duration
	method     string
	authority  string
	path       string
	exactBody  []byte
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

// SignSelfJWTRequest signs with a self-issued JWT whose discovered signing
// key is also the HTTP request key.
func SignSelfJWTRequest(request *http.Request, key jose.SigningKey, compact string, clock Clock) error {
	return SignSelfJWTRequestWithOptions(request, key, compact, clock, SignOptions{})
}

// SignSelfJWTRequestWithOptions signs with a self-issued JWT and optional
// RFC 9421 signature parameters.
func SignSelfJWTRequestWithOptions(
	request *http.Request,
	key jose.SigningKey,
	compact string,
	clock Clock,
	options SignOptions,
) error {
	credential, err := NewSelfJWTCredential(compact)
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

// SignRequest signs one request with the exact supplied Signature-Key
// credential. It reads nonempty content within MaxBodyBytes (default 1 MiB),
// computes SHA-256 Content-Digest and covers it and any Content-Type. The caller
// can still read the request body after signing succeeds or fails. A positive
// ContentLength must match the buffered body size; zero and -1 impose no length.
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
	if options.MaxBodyBytes < 0 {
		return errors.New("aauth: maximum request body size must not be negative")
	}
	candidate := request.Clone(request.Context())
	candidate.Header = request.Header.Clone()
	if candidate.Header == nil {
		candidate.Header = make(http.Header)
	}
	candidate.Header.Set("Signature-Key", credential.header)
	components := []string{"@method", "@authority", "@path"}
	if request.URL.RawQuery != "" || request.URL.ForceQuery {
		components = append(components, "@query")
	}
	if candidate.Header.Get("Authorization") != "" {
		components = append(components, "authorization")
	}
	for _, component := range options.AdditionalComponents {
		if err := ValidateAdditionalComponent(component); err != nil {
			return err
		}
	}
	additional := uniqueLower(options.AdditionalComponents)
	if len(additional) != len(options.AdditionalComponents) {
		return errors.New("aauth: additional signature components contain a duplicate")
	}
	var body []byte
	if hasRequestBody(candidate) {
		maxBodyBytes := options.MaxBodyBytes
		if maxBodyBytes == 0 {
			maxBodyBytes = defaultMaxBodyBytes
		}
		copied, err := copyRequestBodyForSigning(request, candidate, maxBodyBytes)
		if err != nil {
			return err
		}
		body = copied
	}
	if request.ContentLength > 0 && request.ContentLength != int64(len(body)) {
		return fmt.Errorf("aauth: ContentLength %d does not match request body length %d", request.ContentLength, len(body))
	}
	if len(body) > 0 {
		additional = uniqueLower(append(additional, "content-digest"))
		if len(candidate.Header.Values("Content-Type")) > 0 {
			additional = uniqueLower(append(additional, "content-type"))
		}
	}
	if contains(additional, "content-digest") {
		digest := sha256.Sum256(body)
		candidate.Header.Set("Content-Digest", "sha-256=:"+base64.StdEncoding.EncodeToString(digest[:])+":")
	}
	for _, component := range additional {
		if contains(components, component) {
			continue
		}
		components = append(components, component)
	}
	components = append(components, "signature-key")
	now := clock.Now()
	if !options.ExpiresAt.IsZero() && options.ExpiresAt.Unix() <= now.Unix() {
		return errors.New("aauth: signature expires time must be after created time")
	}
	if err := validateStructuredFieldString(options.Nonce); err != nil {
		return fmt.Errorf("aauth: signature nonce: %w", err)
	}
	params := signatureParams(components, now.Unix(), options.ExpiresAt, options.Nonce)
	base, err := signatureBase(candidate, components, params)
	if err != nil {
		return err
	}
	signature, err := key.Sign(rand.Reader, []byte(base), crypto.Hash(0))
	if err != nil {
		return err
	}
	candidate.Header.Set("Signature-Input", "sig="+params)
	candidate.Header.Set("Signature", "sig=:"+base64.StdEncoding.EncodeToString(signature)+":")
	request.Header = candidate.Header
	return nil
}

// copyRequestBodyForSigning gives the temporary signing request an independent
// body while leaving the caller's request readable on either success or error.
func copyRequestBodyForSigning(original, candidate *http.Request, maxBodyBytes int64) ([]byte, error) {
	if original.GetBody != nil {
		body, err := original.GetBody()
		if err != nil {
			return nil, fmt.Errorf("aauth: copy request body: %w", err)
		}
		candidate.Body = body
		return readRequestBody(candidate, maxBodyBytes)
	}

	originalContentLength := original.ContentLength
	originalGetBody := original.GetBody
	body, err := readRequestBody(original, maxBodyBytes)
	original.ContentLength = originalContentLength
	original.GetBody = originalGetBody
	if err != nil {
		return nil, err
	}
	candidate.Body = io.NopCloser(bytes.NewReader(body))
	candidate.ContentLength = int64(len(body))
	candidate.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(body)), nil
	}
	return body, nil
}

// ValidateAdditionalComponent validates one lowercase HTTP field name that
// this implementation can add to a request signature.
func ValidateAdditionalComponent(component string) error {
	if component == "" || strings.ToLower(component) != component {
		return fmt.Errorf("aauth: additional signature component %q is invalid", component)
	}
	if err := validateStructuredFieldString(component); err != nil {
		return fmt.Errorf("aauth: additional signature component %q: %w", component, err)
	}
	switch component {
	case "signature", "signature-input", "signature-key":
		return fmt.Errorf("aauth: additional signature component %q is managed by the signature profile", component)
	}
	for index := 0; index < len(component); index++ {
		character := component[index]
		if !isHTTPTokenCharacter(character) {
			return fmt.Errorf("aauth: additional signature component %q is not a supported HTTP field name", component)
		}
	}
	return nil
}

func isHTTPTokenCharacter(character byte) bool {
	if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' {
		return true
	}
	return strings.ContainsRune("!#$%&'*+-.^_`|~", rune(character))
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
	if options.MaxBodyBytes < 0 {
		return prepared, newError(ErrorInvalidRequest, errors.New("aauth: maximum request body size must not be negative"))
	}
	maxBodyBytes := options.MaxBodyBytes
	if maxBodyBytes == 0 {
		maxBodyBytes = defaultMaxBodyBytes
	}
	signatureHeaders := request.Header.Values("Signature")
	signatureInputs := request.Header.Values("Signature-Input")
	credentialHeaders := request.Header.Values("Signature-Key")
	// A missing Signature, Signature-Input, or Signature-Key header is a
	// missing signature, not a request error unrelated to the signature.
	if len(signatureHeaders) == 0 || len(signatureInputs) == 0 || len(credentialHeaders) == 0 {
		return prepared, newError(
			ErrorInvalidSignature,
			errors.New("aauth: Signature, Signature-Input, and Signature-Key headers are required"),
		)
	}
	label, components, created, expires, params, err := parseSignatureInput(signatureInputs, options.SignatureLabel)
	if err != nil {
		return prepared, newError(ErrorInvalidSignature, err)
	}
	required := append([]string{"@method", "@authority", "@path", "signature-key"}, options.RequiredComponents...)
	hasContent, err := requestHasContent(request)
	if err != nil {
		return prepared, newError(ErrorInvalidSignature, err)
	}
	if hasContent {
		required = append(required, "content-digest")
		if len(request.Header.Values("Content-Type")) > 0 {
			required = append(required, "content-type")
		}
	}
	if request.URL.RawQuery != "" || request.URL.ForceQuery {
		required = append(required, "@query")
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
	if age < -window {
		return prepared, newError(ErrorClockSkew, errors.New("aauth: signature created time is ahead of the validity window"))
	}
	if age > window {
		return prepared, newError(ErrorInvalidSignature, errors.New("aauth: signature created time is older than the validity window"))
	}
	if expires != nil && !time.Unix(*expires, 0).After(verifiedAt) {
		return prepared, newError(ErrorInvalidSignature, errors.New("aauth: signature expires time is in the past"))
	}
	accepted := options.AcceptedSchemes
	if len(accepted) == 0 {
		accepted = []Scheme{SchemeJWT}
	}
	credential, err := parseCredentialForLabel(credentialHeaders, label)
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
	var exactBody []byte
	if contains(components, "content-digest") {
		exactBody, err = verifyContentDigest(request, maxBodyBytes)
		if err != nil {
			var limit *bodyLimitError
			if errors.As(err, &limit) {
				return prepared, newError(ErrorInvalidInput, err)
			}
			return prepared, newError(ErrorInvalidSignature, err)
		}
	}
	base, err := signatureBase(request, components, params)
	if err != nil {
		return prepared, newError(ErrorInvalidSignature, err)
	}
	signature, err := parseSignature(signatureHeaders, label)
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
		window:      window,
		method:      request.Method,
		authority:   authority,
		path:        path,
		exactBody:   append([]byte(nil), exactBody...),
	}, nil
}

// Credential returns an independent projection of the prepared credential.
func (prepared PreparedRequest) Credential() Credential {
	parameters := make(map[string]string, len(prepared.credential.parameters))
	for name, value := range prepared.credential.parameters {
		parameters[name] = value
	}
	return Credential{
		scheme:         prepared.credential.scheme,
		parameters:     parameters,
		cacheRequested: prepared.credential.cacheRequested,
		header:         prepared.credential.header,
	}
}

// Created returns the trusted created time parsed from Signature-Input.
func (prepared PreparedRequest) Created() time.Time { return prepared.created }

// VerifiedAt returns the single trusted instant captured during preparation.
func (prepared PreparedRequest) VerifiedAt() time.Time { return prepared.verifiedAt }

// SignatureWindow returns the effective signature validity window applied
// during preparation.
func (prepared PreparedRequest) SignatureWindow() time.Duration { return prepared.window }

// CheckIssuedAt judges a request-carried JWT iat against the captured
// verification time and effective signature window. An iat further ahead than
// the window is clock_skew.
func (prepared PreparedRequest) CheckIssuedAt(issuedAt time.Time) error {
	return checkIssuedAt(issuedAt, prepared.verifiedAt, prepared.window)
}

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
		window:     prepared.window,
		method:     prepared.method,
		authority:  prepared.authority,
		path:       prepared.path,
		exactBody:  append([]byte(nil), prepared.exactBody...),
	}, nil
}

// VerifyJWKSURI resolves and verifies a jwks_uri proof. A same-ID signature
// failure triggers at most one resolver refresh, subject to the resolver's
// refresh floor and cache policy.
func (prepared PreparedRequest) VerifyJWKSURI(
	ctx context.Context,
	resolver KeyResolver,
) (VerifiedRequest, error) {
	if ctx == nil {
		return VerifiedRequest{}, errors.New("aauth: verification context is required")
	}
	if resolver == nil {
		return VerifiedRequest{}, errors.New("aauth: key resolver is required")
	}
	issuer, document, keyID, ok := prepared.credential.JWKSURI()
	if !ok {
		return VerifiedRequest{}, errors.New("aauth: prepared request does not use jwks_uri")
	}
	key, err := resolver.ResolveKey(ctx, issuer, document, keyID)
	if err != nil {
		return VerifiedRequest{}, NormalizeResolutionError(err)
	}
	verified, err := prepared.Verify(key)
	if err == nil {
		return verified, nil
	}
	var signatureFailure *Error
	if !errors.As(err, &signatureFailure) || signatureFailure.Code != ErrorInvalidSignature {
		return VerifiedRequest{}, err
	}
	refresher, ok := resolver.(KeyRefresher)
	if !ok {
		return VerifiedRequest{}, err
	}
	refreshed, refreshErr := refresher.RefreshKey(ctx, issuer, document, keyID)
	if refreshErr != nil {
		return VerifiedRequest{}, NormalizeResolutionError(refreshErr)
	}
	return prepared.Verify(refreshed)
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

// SignatureWindow returns the effective signature validity window applied
// when the request was prepared.
func (verified VerifiedRequest) SignatureWindow() time.Duration { return verified.window }

// CheckIssuedAt judges a request-carried JWT iat against the captured
// verification time and effective signature window. An iat further ahead than
// the window is clock_skew.
func (verified VerifiedRequest) CheckIssuedAt(issuedAt time.Time) error {
	return checkIssuedAt(issuedAt, verified.verifiedAt, verified.window)
}

func checkIssuedAt(issuedAt, verifiedAt time.Time, window time.Duration) error {
	if verifiedAt.IsZero() {
		return errors.New("aauth: request was not prepared")
	}
	if issuedAt.After(verifiedAt.Add(window)) {
		return newError(ErrorClockSkew, errors.New("aauth: JWT iat is ahead of the request validity window"))
	}
	return nil
}

// ExactBody returns the independently copied request body authenticated by a
// covered Content-Digest. It is empty when the body is empty or not covered.
func (verified VerifiedRequest) ExactBody() []byte {
	return append([]byte(nil), verified.exactBody...)
}
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
		case "@query":
			value = "?" + request.URL.RawQuery
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

func parseSignatureInput(values []string, selectedLabel string) (string, []string, int64, *int64, string, error) {
	dictionary, members, err := parseDictionaryMembers(values, "Signature-Input")
	if err != nil {
		return "", nil, 0, nil, "", err
	}
	label := selectedLabel
	if label == "" {
		if len(members) != 1 || len(dictionary.Names()) != 1 {
			return "", nil, 0, nil, "", errors.New("aauth: Signature-Input contains multiple signatures; select one label")
		}
		label = dictionary.Names()[0]
	}
	member, ok := dictionary.Get(label)
	if !ok {
		return "", nil, 0, nil, "", fmt.Errorf("aauth: Signature-Input has no member for selected label %q", label)
	}
	innerList, ok := member.(httpsfv.InnerList)
	if !ok {
		return "", nil, 0, nil, "", errors.New("aauth: Signature-Input member must be an inner list")
	}
	if countTopLevelDelimiters(members[label], ';') != len(innerList.Params.Names()) {
		return "", nil, 0, nil, "", errors.New("aauth: Signature-Input has duplicate parameters")
	}
	components := make([]string, 0, len(innerList.Items))
	for _, item := range innerList.Items {
		component, ok := item.Value.(string)
		if !ok || component == "" || len(item.Params.Names()) != 0 {
			return "", nil, 0, nil, "", errors.New("aauth: Signature-Input component is invalid")
		}
		component = strings.ToLower(component)
		if contains(components, component) {
			return "", nil, 0, nil, "", fmt.Errorf("aauth: duplicate signed component %q", component)
		}
		components = append(components, component)
	}
	if len(components) == 0 {
		return "", nil, 0, nil, "", errors.New("aauth: Signature-Input covers no components")
	}
	createdValue, ok := innerList.Params.Get("created")
	created, ok := createdValue.(int64)
	if !ok || created <= 0 {
		return "", nil, 0, nil, "", errors.New("aauth: Signature-Input created is required and must be a positive integer")
	}
	var expires *int64
	if expiresValue, present := innerList.Params.Get("expires"); present {
		value, ok := expiresValue.(int64)
		if !ok || value <= 0 {
			return "", nil, 0, nil, "", errors.New("aauth: Signature-Input expires is invalid")
		}
		expires = &value
	}
	if nonceValue, present := innerList.Params.Get("nonce"); present {
		nonce, ok := nonceValue.(string)
		if !ok || nonce == "" {
			return "", nil, 0, nil, "", errors.New("aauth: Signature-Input nonce is invalid")
		}
	}
	if expires != nil && *expires <= created {
		return "", nil, 0, nil, "", errors.New("aauth: Signature-Input expires must be after created")
	}
	params, err := httpsfv.Marshal(innerList)
	if err != nil {
		return "", nil, 0, nil, "", fmt.Errorf("aauth: serialize Signature-Input: %w", err)
	}
	return label, components, created, expires, params, nil
}

func parseSignature(values []string, expectedLabel string) ([]byte, error) {
	dictionary, members, err := parseDictionaryMembers(values, "Signature")
	if err != nil {
		return nil, err
	}
	if len(members) == 0 {
		return nil, errors.New("aauth: Signature contains no signatures")
	}
	member, ok := dictionary.Get(expectedLabel)
	if !ok {
		return nil, fmt.Errorf("aauth: Signature has no member for Signature-Input label %q", expectedLabel)
	}
	item, ok := member.(httpsfv.Item)
	if !ok || len(item.Params.Names()) != 0 {
		return nil, errors.New("aauth: Signature member must be an unparameterized byte sequence")
	}
	signature, ok := item.Value.([]byte)
	if !ok {
		return nil, errors.New("aauth: Signature member must be a byte sequence")
	}
	if len(signature) != ed25519.SignatureSize {
		return nil, fmt.Errorf("aauth: Ed25519 HTTP signature has %d bytes", len(signature))
	}
	return append([]byte(nil), signature...), nil
}

func verifyContentDigest(request *http.Request, maxBodyBytes int64) ([]byte, error) {
	header := request.Header.Get("Content-Digest")
	const prefix = "sha-256=:"
	if !strings.HasPrefix(header, prefix) || !strings.HasSuffix(header, ":") {
		return nil, errors.New("aauth: Content-Digest must use sha-256")
	}
	expected, err := base64.StdEncoding.DecodeString(strings.TrimSuffix(strings.TrimPrefix(header, prefix), ":"))
	if err != nil || len(expected) != sha256.Size {
		return nil, errors.New("aauth: Content-Digest sha-256 value is invalid")
	}
	body, err := readRequestBody(request, maxBodyBytes)
	if err != nil {
		return nil, err
	}
	actual := sha256.Sum256(body)
	if !bytes.Equal(expected, actual[:]) {
		return nil, errors.New("aauth: Content-Digest does not match request body")
	}
	return body, nil
}

func readRequestBody(request *http.Request, maxBodyBytes int64) ([]byte, error) {
	if !hasRequestBody(request) {
		return nil, nil
	}
	original := request.Body
	restorePartial := func(prefix []byte) {
		if request.GetBody != nil {
			if replacement, err := request.GetBody(); err == nil {
				request.Body = replacement
				return
			}
		}
		request.Body = &prefixedReadCloser{
			Reader: io.MultiReader(bytes.NewReader(prefix), original),
			closer: original,
		}
	}
	reader := io.Reader(original)
	if maxBodyBytes > 0 && maxBodyBytes < math.MaxInt64 {
		reader = io.LimitReader(original, maxBodyBytes+1)
	}
	body, err := io.ReadAll(reader)
	if err != nil {
		restorePartial(body)
		return nil, fmt.Errorf("aauth: read request body: %w", err)
	}
	if maxBodyBytes > 0 && int64(len(body)) > maxBodyBytes {
		restorePartial(body)
		return nil, &bodyLimitError{maximum: maxBodyBytes}
	}
	if err := original.Close(); err != nil {
		request.Body = io.NopCloser(bytes.NewReader(body))
		return nil, fmt.Errorf("aauth: close request body: %w", err)
	}
	request.Body = io.NopCloser(bytes.NewReader(body))
	request.ContentLength = int64(len(body))
	request.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(body)), nil }
	return body, nil
}

type prefixedReadCloser struct {
	io.Reader
	closer io.Closer
}

func (reader *prefixedReadCloser) Close() error {
	return reader.closer.Close()
}

type bodyLimitError struct{ maximum int64 }

func (failure *bodyLimitError) Error() string {
	return fmt.Sprintf("aauth: request body exceeds %d bytes", failure.maximum)
}

func hasRequestBody(request *http.Request) bool {
	return request.Body != nil && request.Body != http.NoBody
}

// requestHasContent distinguishes empty transport readers from real content
// without trusting ContentLength or consuming bytes needed by verification.
func requestHasContent(request *http.Request) (bool, error) {
	if !hasRequestBody(request) {
		return false, nil
	}
	original := request.Body
	prefix, err := io.ReadAll(io.LimitReader(original, 1))
	if len(prefix) > 0 {
		request.Body = &prefixedReadCloser{
			Reader: io.MultiReader(bytes.NewReader(prefix), original),
			closer: original,
		}
	}
	if err != nil {
		return false, fmt.Errorf("aauth: read request content: %w", err)
	}
	return len(prefix) > 0, nil
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
