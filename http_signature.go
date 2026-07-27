package aauth

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const DefaultSignatureWindow = 60 * time.Second

const (
	SignatureKeyJWT     = "jwt"
	SignatureKeyJWKSURI = "jwks_uri"
)

// VerifiedRequest is the trusted signing context of an HTTP request.
type VerifiedRequest struct {
	SignatureKeyType string
	Signer           string
	RawCredential    string
	CredentialType   string
	Agent            string
	PublicKey        JWK
	AgentToken       *AgentTokenClaims
	AuthToken        *AuthTokenClaims
	Created          time.Time
	ReplayKey        string
}

// VerifyRequestOptions declares the message components and token forms a
// particular endpoint accepts.
type VerifyRequestOptions struct {
	RequiredComponents       []string
	AllowedCredentialTypes   []string
	AllowedSignatureKeyTypes []string
	SignatureWindow          time.Duration
}

// SignRequest applies the AAuth HTTP Message Signatures profile using a JWT
// identity credential in Signature-Key.
func SignRequest(request *http.Request, key SigningKey, credential string, clock Clock) error {
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
	return signRequestWithSignatureKey(request, key, header, clock)
}

func signRequestWithSignatureKey(
	request *http.Request,
	key SigningKey,
	signatureKeyHeader string,
	clock Clock,
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
	}
	if request.Header.Get("AAuth-Mission") != "" {
		components = append(components, "aauth-mission")
	}
	components = append(components, "signature-key")

	params := signatureParams(components, clock.Now().Unix())
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
	if resolver == nil {
		return verified, errors.New("aauth: key resolver is required")
	}
	if clock == nil {
		return verified, errors.New("aauth: clock is required")
	}

	signatureKey, err := parseSignatureKey(request.Header.Get("Signature-Key"))
	if err != nil {
		return verified, err
	}
	allowedSignatureKeyTypes := options.AllowedSignatureKeyTypes
	if len(allowedSignatureKeyTypes) == 0 {
		allowedSignatureKeyTypes = []string{SignatureKeyJWT}
	}
	if !contains(allowedSignatureKeyTypes, signatureKey.scheme) {
		return verified, fmt.Errorf("aauth: Signature-Key type %q is not accepted", signatureKey.scheme)
	}
	verified.SignatureKeyType = signatureKey.scheme

	switch signatureKey.scheme {
	case SignatureKeyJWT:
		header, err := PeekTokenHeader(signatureKey.parameters["jwt"])
		if err != nil {
			return verified, fmt.Errorf("aauth: Signature-Key JWT: %w", err)
		}
		if len(options.AllowedCredentialTypes) > 0 && !contains(options.AllowedCredentialTypes, header.Type) {
			return verified, fmt.Errorf("aauth: credential typ %q is not accepted", header.Type)
		}
		verified.RawCredential = signatureKey.parameters["jwt"]
		switch header.Type {
		case AgentTokenType:
			claims, verifyErr := VerifyAgentToken(ctx, verified.RawCredential, resolver, clock)
			if verifyErr != nil {
				return verified, verifyErr
			}
			verified.CredentialType = AgentTokenType
			verified.Agent = claims.Subject
			verified.Signer = claims.Subject
			verified.PublicKey = claims.Confirmation.JWK
			verified.AgentToken = &claims
		case AuthTokenType:
			claims, verifyErr := VerifyAuthToken(ctx, verified.RawCredential, resolver, clock)
			if verifyErr != nil {
				return verified, verifyErr
			}
			verified.CredentialType = AuthTokenType
			verified.Agent = claims.Agent
			verified.Signer = claims.Agent
			verified.PublicKey = claims.Confirmation.JWK
			verified.AuthToken = &claims
		default:
			return verified, fmt.Errorf("aauth: unsupported Signature-Key JWT typ %q", header.Type)
		}
	case SignatureKeyJWKSURI:
		identifier := signatureKey.parameters["id"]
		document := signatureKey.parameters["dwk"]
		keyID := signatureKey.parameters["kid"]
		if err := ValidateServerIdentifier(identifier); err != nil {
			return verified, fmt.Errorf("aauth: Signature-Key id: %w", err)
		}
		if !discoveryDocumentPattern.MatchString(document) || keyID == "" {
			return verified, errors.New("aauth: Signature-Key jwks_uri parameters are invalid")
		}
		resolved, err := resolver.ResolveKey(ctx, identifier, document, keyID)
		if err != nil {
			return verified, err
		}
		verified.Signer = identifier
		verified.PublicKey = resolved
	}

	components, created, params, err := parseSignatureInput(request.Header.Get("Signature-Input"))
	if err != nil {
		return VerifiedRequest{}, err
	}
	required := append([]string{"@method", "@authority", "@path", "signature-key"}, options.RequiredComponents...)
	for _, component := range required {
		if !contains(components, strings.ToLower(component)) {
			return VerifiedRequest{}, fmt.Errorf("aauth: signature does not cover required component %q", component)
		}
	}
	if hasRequestBody(request) && !contains(components, "content-digest") {
		return VerifiedRequest{}, errors.New("aauth: request body is not covered by content-digest")
	}
	if request.Header.Get("AAuth-Mission") != "" && !contains(components, "aauth-mission") {
		return VerifiedRequest{}, errors.New("aauth: AAuth-Mission is not covered by the signature")
	}
	if request.Header.Get("Authorization") != "" && !contains(components, "authorization") {
		return VerifiedRequest{}, errors.New("aauth: Authorization is not covered by the signature")
	}

	window := options.SignatureWindow
	if window == 0 {
		window = DefaultSignatureWindow
	}
	if window < 0 {
		return VerifiedRequest{}, errors.New("aauth: signature window must not be negative")
	}
	createdAt := time.Unix(created, 0)
	age := clock.Now().Sub(createdAt)
	if age < -window || age > window {
		return VerifiedRequest{}, errors.New("aauth: signature created time is outside the validity window")
	}

	if contains(components, "content-digest") {
		if err := verifyContentDigest(request); err != nil {
			return VerifiedRequest{}, err
		}
	}
	base, err := signatureBase(request, components, params)
	if err != nil {
		return VerifiedRequest{}, err
	}
	signature, err := parseSignature(request.Header.Get("Signature"))
	if err != nil {
		return VerifiedRequest{}, err
	}
	publicKey, err := verified.PublicKey.PublicKey()
	if err != nil {
		return VerifiedRequest{}, err
	}
	ed25519Key, ok := publicKey.(ed25519.PublicKey)
	if !ok {
		return VerifiedRequest{}, errors.New("aauth: request confirmation key is not Ed25519")
	}
	if !ed25519.Verify(ed25519Key, []byte(base), signature) {
		return VerifiedRequest{}, errors.New("aauth: HTTP message signature is invalid")
	}

	replayMaterial := append([]byte(base), signature...)
	replayDigest := sha256.Sum256(replayMaterial)
	verified.Created = createdAt
	verified.ReplayKey = rawURL.EncodeToString(replayDigest[:])
	return verified, nil
}

func signatureParams(components []string, created int64) string {
	var quoted []string
	for _, component := range components {
		quoted = append(quoted, strconv.Quote(component))
	}
	return "(" + strings.Join(quoted, " ") + ");created=" + strconv.FormatInt(created, 10)
}

func signatureBase(request *http.Request, components []string, params string) (string, error) {
	lines := make([]string, 0, len(components)+1)
	for _, component := range components {
		var value string
		switch component {
		case "@method":
			value = strings.ToUpper(request.Method)
		case "@authority":
			value = request.Host
			if value == "" {
				value = request.URL.Host
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
			value = request.Header.Get(http.CanonicalHeaderKey(component))
			if value == "" {
				return "", fmt.Errorf("aauth: covered header %q is absent", component)
			}
		}
		lines = append(lines, strconv.Quote(component)+": "+value)
	}
	lines = append(lines, `"@signature-params": `+params)
	return strings.Join(lines, "\n"), nil
}

func parseSignatureInput(header string) ([]string, int64, string, error) {
	if !strings.HasPrefix(header, "sig=(") {
		return nil, 0, "", errors.New("aauth: Signature-Input must contain the sig label")
	}
	params := strings.TrimPrefix(header, "sig=")
	end := strings.Index(params, ");created=")
	if end < 0 || !strings.HasSuffix(params[:end+1], ")") {
		return nil, 0, "", errors.New("aauth: Signature-Input has invalid parameters")
	}
	componentText := params[1:end]
	createdText := params[end+10:]
	if createdText == "" || strings.ContainsAny(createdText, ";, \t\r\n") {
		return nil, 0, "", errors.New("aauth: Signature-Input created is invalid")
	}
	created, err := strconv.ParseInt(createdText, 10, 64)
	if err != nil || created <= 0 {
		return nil, 0, "", errors.New("aauth: Signature-Input created is invalid")
	}

	var components []string
	for len(strings.TrimSpace(componentText)) > 0 {
		componentText = strings.TrimSpace(componentText)
		if componentText[0] != '"' {
			return nil, 0, "", errors.New("aauth: Signature-Input component is not quoted")
		}
		endQuote := 1
		for endQuote < len(componentText) {
			if componentText[endQuote] == '"' && componentText[endQuote-1] != '\\' {
				break
			}
			endQuote++
		}
		if endQuote >= len(componentText) {
			return nil, 0, "", errors.New("aauth: Signature-Input component quote is unterminated")
		}
		value, err := strconv.Unquote(componentText[:endQuote+1])
		if err != nil {
			return nil, 0, "", fmt.Errorf("aauth: decode Signature-Input component: %w", err)
		}
		value = strings.ToLower(value)
		if contains(components, value) {
			return nil, 0, "", fmt.Errorf("aauth: duplicate signed component %q", value)
		}
		components = append(components, value)
		componentText = componentText[endQuote+1:]
	}
	if len(components) == 0 {
		return nil, 0, "", errors.New("aauth: Signature-Input covers no components")
	}
	return components, created, params, nil
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
