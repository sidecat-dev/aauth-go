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
	"net/http"
	"strconv"
	"strings"
	"time"

	"gitlab.com/sidecat-dev/aauth-go/jose"
)

// ResponseVerifyOptions controls freshness validation of an HTTP response
// signature. Response signatures have one fixed component profile: status,
// content type, content digest, and the request authority/path.
type ResponseVerifyOptions struct {
	SignatureWindow time.Duration
}

// PreparedResponse retains the key-independent parts of a signed response
// until the caller selects the public key named by Signature-Key.
type PreparedResponse struct {
	initialized      bool
	credential       Credential
	base             string
	signature        []byte
	components       []responseComponent
	created          time.Time
	verifiedAt       time.Time
	status           int
	requestAuthority string
	requestPath      string
}

// VerifiedResponse is sealed evidence that one exact response representation
// verified under one exact public key and request binding.
type VerifiedResponse struct {
	credential       Credential
	publicKey        jose.JWK
	signer           string
	components       []responseComponent
	created          time.Time
	verifiedAt       time.Time
	status           int
	requestAuthority string
	requestPath      string
}

type responseComponent struct {
	name    string
	request bool
}

var expectedResponseComponents = []responseComponent{
	{name: "@status"},
	{name: "content-type"},
	{name: "content-digest"},
	{name: "@authority", request: true},
	{name: "@path", request: true},
}

// SignResponse signs one HTTP response using the resource's jwks_uri
// Signature-Key scheme. The signature is bound to request's authority and
// path, and covers the exact response status, content type, and body bytes.
// response.Body is restored after it is read.
func SignResponse(
	response *http.Response,
	request *http.Request,
	key jose.SigningKey,
	identifier string,
	discoveryDocument string,
	clock Clock,
) error {
	if response == nil || response.Header == nil {
		return errors.New("aauth: response and response headers are required")
	}
	if request == nil || request.URL == nil {
		return errors.New("aauth: response request URL is required")
	}
	if response.StatusCode < 100 || response.StatusCode > 599 {
		return errors.New("aauth: response status is invalid")
	}
	if clock == nil {
		return errors.New("aauth: clock is required")
	}
	if key.ID() == "" {
		return errors.New("aauth: response signing key is not initialized")
	}
	credential, err := NewJWKSURICredential(identifier, discoveryDocument, key.ID())
	if err != nil {
		return err
	}
	body, err := readResponseBody(response)
	if err != nil {
		return err
	}
	contentType, err := oneResponseHeader(response.Header, "Content-Type")
	if err != nil {
		return err
	}
	digest := sha256.Sum256(body)
	response.Header.Set("Content-Digest", "sha-256=:"+base64.StdEncoding.EncodeToString(digest[:])+":")
	components := append([]responseComponent(nil), expectedResponseComponents...)
	now := clock.Now()
	params := responseSignatureParams(components, now.Unix())
	base, err := responseSignatureBase(response, request, components, params)
	if err != nil {
		return err
	}
	signature, err := key.Sign(rand.Reader, []byte(base), crypto.Hash(0))
	if err != nil {
		return err
	}
	response.Header.Set("Content-Type", contentType)
	response.Header.Set("Signature-Key", credential.header)
	response.Header.Set("Signature-Input", "sig="+params)
	response.Header.Set("Signature", "sig=:"+base64.StdEncoding.EncodeToString(signature)+":")
	return nil
}

// PrepareResponse validates and seals the key-independent parts of a signed
// response. The supplied request is the exact request to which the response
// is bound. response.Body is restored after it is read.
func PrepareResponse(
	response *http.Response,
	request *http.Request,
	clock Clock,
	options ResponseVerifyOptions,
) (PreparedResponse, error) {
	var prepared PreparedResponse
	if response == nil || response.Header == nil {
		return prepared, errors.New("aauth: response and response headers are required")
	}
	if request == nil || request.URL == nil {
		return prepared, errors.New("aauth: response request URL is required")
	}
	if clock == nil {
		return prepared, errors.New("aauth: clock is required")
	}
	if response.StatusCode < 100 || response.StatusCode > 599 {
		return prepared, errors.New("aauth: response status is invalid")
	}
	signatureInput := response.Header.Get("Signature-Input")
	signatureHeader := response.Header.Get("Signature")
	credentialHeaders := response.Header.Values("Signature-Key")
	if signatureInput == "" || signatureHeader == "" || len(credentialHeaders) != 1 {
		return prepared, errors.New("aauth: response Signature, Signature-Input, and one Signature-Key are required")
	}
	components, created, expires, params, err := parseResponseSignatureInput(signatureInput)
	if err != nil {
		return prepared, newError(ErrorInvalidSignature, err)
	}
	if !sameResponseComponents(components, expectedResponseComponents) {
		return prepared, newError(ErrorInvalidSignature, errors.New("aauth: response signature does not match the exact component profile"))
	}
	credential, err := ParseCredential(credentialHeaders)
	if err != nil {
		return prepared, err
	}
	if credential.Scheme() != SchemeJWKSURI {
		return prepared, newError(ErrorUnsupportedScheme, errors.New("aauth: response Signature-Key must use jwks_uri"))
	}
	body, err := readResponseBody(response)
	if err != nil {
		return prepared, newError(ErrorInvalidSignature, err)
	}
	if err := verifyResponseContentDigest(response.Header, body); err != nil {
		return prepared, newError(ErrorInvalidSignature, err)
	}
	verifiedAt := clock.Now().UTC()
	window := options.SignatureWindow
	if window == 0 {
		window = DefaultSignatureWindow
	}
	if window < 0 {
		return prepared, newError(ErrorInvalidRequest, errors.New("aauth: response signature window must not be negative"))
	}
	createdAt := time.Unix(created, 0)
	age := verifiedAt.Sub(createdAt)
	if age < -window || age > window {
		return prepared, newError(ErrorInvalidSignature, errors.New("aauth: response signature created time is outside the validity window"))
	}
	if expires != nil && !time.Unix(*expires, 0).After(verifiedAt) {
		return prepared, newError(ErrorInvalidSignature, errors.New("aauth: response signature expires time is in the past"))
	}
	base, err := responseSignatureBase(response, request, components, params)
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
	return PreparedResponse{
		initialized:      true,
		credential:       credential,
		base:             base,
		signature:        append([]byte(nil), signature...),
		components:       append([]responseComponent(nil), components...),
		created:          createdAt,
		verifiedAt:       verifiedAt,
		status:           response.StatusCode,
		requestAuthority: authority,
		requestPath:      path,
	}, nil
}

// Credential returns an independent projection of the prepared response
// credential.
func (prepared PreparedResponse) Credential() Credential {
	parameters := make(map[string]string, len(prepared.credential.parameters))
	for name, value := range prepared.credential.parameters {
		parameters[name] = value
	}
	return Credential{scheme: prepared.credential.scheme, parameters: parameters, header: prepared.credential.header}
}

// Verify verifies the prepared response signature with the selected public
// key and checks that it is the key named by the jwks_uri credential.
func (prepared PreparedResponse) Verify(key jose.JWK) (VerifiedResponse, error) {
	if !prepared.initialized || prepared.base == "" || len(prepared.signature) == 0 {
		return VerifiedResponse{}, errors.New("aauth: prepared response is not initialized")
	}
	identifier, _, keyID, ok := prepared.credential.JWKSURI()
	if !ok || keyID == "" || keyID != key.Kid {
		return VerifiedResponse{}, newError(ErrorInvalidKey, errors.New("aauth: response credential does not name the selected key"))
	}
	publicKey, err := key.PublicKey()
	if err != nil {
		if key.Alg != jose.Ed25519Algorithm {
			return VerifiedResponse{}, &Error{Code: ErrorUnsupportedAlgorithm, AcceptedAlgorithms: []string{jose.Ed25519Algorithm}, Cause: err}
		}
		return VerifiedResponse{}, newError(ErrorInvalidKey, err)
	}
	ed25519Key, ok := publicKey.(ed25519.PublicKey)
	if !ok {
		return VerifiedResponse{}, &Error{Code: ErrorUnsupportedAlgorithm, AcceptedAlgorithms: []string{jose.Ed25519Algorithm}, Cause: errors.New("aauth: response verification key is not Ed25519")}
	}
	if !ed25519.Verify(ed25519Key, []byte(prepared.base), prepared.signature) {
		return VerifiedResponse{}, newError(ErrorInvalidSignature, errors.New("aauth: HTTP response signature is invalid"))
	}
	return VerifiedResponse{
		credential:       prepared.Credential(),
		publicKey:        key,
		signer:           identifier,
		components:       append([]responseComponent(nil), prepared.components...),
		created:          prepared.created,
		verifiedAt:       prepared.verifiedAt,
		status:           prepared.status,
		requestAuthority: prepared.requestAuthority,
		requestPath:      prepared.requestPath,
	}, nil
}

func (verified VerifiedResponse) Scheme() Scheme        { return verified.credential.Scheme() }
func (verified VerifiedResponse) Signer() string        { return verified.signer }
func (verified VerifiedResponse) PublicKey() jose.JWK   { return verified.publicKey }
func (verified VerifiedResponse) Created() time.Time    { return verified.created }
func (verified VerifiedResponse) VerifiedAt() time.Time { return verified.verifiedAt }
func (verified VerifiedResponse) Status() int           { return verified.status }
func (verified VerifiedResponse) Authority() string     { return verified.requestAuthority }
func (verified VerifiedResponse) Path() string          { return verified.requestPath }

// CoveredComponents returns the exact component names and request bindings
// carried by the response signature.
func (verified VerifiedResponse) CoveredComponents() []string {
	components := make([]string, 0, len(verified.components))
	for _, component := range verified.components {
		if component.request {
			components = append(components, component.name+";req")
		} else {
			components = append(components, component.name)
		}
	}
	return components
}

func readResponseBody(response *http.Response) ([]byte, error) {
	if response.Body == nil {
		return nil, errors.New("aauth: response body is required")
	}
	body, err := io.ReadAll(response.Body)
	if closeErr := response.Body.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return nil, fmt.Errorf("aauth: read response body: %w", err)
	}
	response.Body = io.NopCloser(bytes.NewReader(body))
	response.ContentLength = int64(len(body))
	return body, nil
}

func oneResponseHeader(header http.Header, name string) (string, error) {
	values := header.Values(name)
	if len(values) != 1 || strings.TrimSpace(values[0]) == "" {
		return "", fmt.Errorf("aauth: response %s must contain exactly one value", name)
	}
	return values[0], nil
}

func verifyResponseContentDigest(header http.Header, body []byte) error {
	digest, err := oneResponseHeader(header, "Content-Digest")
	if err != nil {
		return err
	}
	if !strings.HasPrefix(digest, "sha-256=:") || !strings.HasSuffix(digest, ":") {
		return errors.New("aauth: response Content-Digest must contain one sha-256 value")
	}
	encoded := strings.TrimSuffix(strings.TrimPrefix(digest, "sha-256=:"), ":")
	actual, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(actual) != sha256.Size {
		return errors.New("aauth: response Content-Digest is invalid")
	}
	expected := sha256.Sum256(body)
	if !bytes.Equal(actual, expected[:]) {
		return errors.New("aauth: response Content-Digest does not match the body")
	}
	return nil
}

func responseSignatureParams(components []responseComponent, created int64) string {
	quoted := make([]string, 0, len(components))
	for _, component := range components {
		quoted = append(quoted, strconv.Quote(component.name))
		if component.request {
			quoted[len(quoted)-1] += ";req"
		}
	}
	return "(" + strings.Join(quoted, " ") + ");created=" + strconv.FormatInt(created, 10)
}

func responseSignatureBase(response *http.Response, request *http.Request, components []responseComponent, params string) (string, error) {
	lines := make([]string, 0, len(components)+1)
	for _, component := range components {
		var value string
		switch component.name {
		case "@status":
			if component.request {
				return "", errors.New("aauth: @status cannot be a request component")
			}
			value = strconv.Itoa(response.StatusCode)
		case "@authority":
			if !component.request {
				return "", errors.New("aauth: response @authority must bind the request")
			}
			var err error
			value, err = normalizedRequestAuthority(request)
			if err != nil {
				return "", err
			}
		case "@path":
			if !component.request {
				return "", errors.New("aauth: response @path must bind the request")
			}
			value = request.URL.EscapedPath()
			if value == "" {
				value = "/"
			}
		default:
			if strings.HasPrefix(component.name, "@") || component.request {
				return "", fmt.Errorf("aauth: unsupported response signature component %q", component.name)
			}
			var err error
			value, err = oneResponseHeader(response.Header, component.name)
			if err != nil {
				return "", err
			}
		}
		lines = append(lines, strconv.Quote(component.name)+": "+value)
	}
	lines = append(lines, `"@signature-params": `+params)
	return strings.Join(lines, "\n"), nil
}

func parseResponseSignatureInput(header string) ([]responseComponent, int64, *int64, string, error) {
	if !strings.HasPrefix(header, "sig=(") {
		return nil, 0, nil, "", errors.New("aauth: response Signature-Input must contain the sig label")
	}
	params := strings.TrimPrefix(header, "sig=")
	end := strings.IndexByte(params, ')')
	if end < 1 {
		return nil, 0, nil, "", errors.New("aauth: response Signature-Input has invalid parameters")
	}
	componentText := params[1:end]
	components := make([]responseComponent, 0, 5)
	seen := make(map[string]struct{})
	for len(strings.TrimSpace(componentText)) > 0 {
		componentText = strings.TrimSpace(componentText)
		if componentText[0] != '"' {
			return nil, 0, nil, "", errors.New("aauth: response Signature-Input component is not quoted")
		}
		endQuote := 1
		for endQuote < len(componentText) {
			if componentText[endQuote] == '"' && componentText[endQuote-1] != '\\' {
				break
			}
			endQuote++
		}
		if endQuote >= len(componentText) {
			return nil, 0, nil, "", errors.New("aauth: response Signature-Input component quote is unterminated")
		}
		name, err := strconv.Unquote(componentText[:endQuote+1])
		if err != nil {
			return nil, 0, nil, "", fmt.Errorf("aauth: decode response Signature-Input component: %w", err)
		}
		name = strings.ToLower(name)
		componentText = componentText[endQuote+1:]
		requestComponent := false
		if strings.HasPrefix(componentText, ";req") {
			requestComponent = true
			componentText = componentText[len(";req"):]
		}
		if _, exists := seen[name]; exists {
			return nil, 0, nil, "", fmt.Errorf("aauth: duplicate response signed component %q", name)
		}
		seen[name] = struct{}{}
		components = append(components, responseComponent{name: name, request: requestComponent})
	}
	if len(components) == 0 {
		return nil, 0, nil, "", errors.New("aauth: response Signature-Input covers no components")
	}
	var created int64
	var expires *int64
	seenCreated := false
	remainder := params[end+1:]
	for remainder != "" {
		if !strings.HasPrefix(remainder, ";") {
			return nil, 0, nil, "", errors.New("aauth: response Signature-Input parameter separator is invalid")
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
			return nil, 0, nil, "", errors.New("aauth: response Signature-Input parameter is invalid")
		}
		switch name {
		case "created":
			if seenCreated {
				return nil, 0, nil, "", errors.New("aauth: response Signature-Input created is duplicated")
			}
			parsed, err := strconv.ParseInt(value, 10, 64)
			if err != nil || parsed <= 0 {
				return nil, 0, nil, "", errors.New("aauth: response Signature-Input created is invalid")
			}
			created, seenCreated = parsed, true
		case "expires":
			if expires != nil {
				return nil, 0, nil, "", errors.New("aauth: response Signature-Input expires is duplicated")
			}
			parsed, err := strconv.ParseInt(value, 10, 64)
			if err != nil || parsed <= 0 {
				return nil, 0, nil, "", errors.New("aauth: response Signature-Input expires is invalid")
			}
			expires = &parsed
		case "nonce":
			if _, err := strconv.Unquote(value); err != nil {
				return nil, 0, nil, "", errors.New("aauth: response Signature-Input nonce is invalid")
			}
		default:
			return nil, 0, nil, "", fmt.Errorf("aauth: response Signature-Input parameter %q is unsupported", name)
		}
	}
	if !seenCreated {
		return nil, 0, nil, "", errors.New("aauth: response Signature-Input created is required")
	}
	if expires != nil && *expires <= created {
		return nil, 0, nil, "", errors.New("aauth: response Signature-Input expires must be after created")
	}
	return components, created, expires, params, nil
}

func sameResponseComponents(got, want []responseComponent) bool {
	if len(got) != len(want) {
		return false
	}
	for index := range got {
		if got[index] != want[index] {
			return false
		}
	}
	return true
}
