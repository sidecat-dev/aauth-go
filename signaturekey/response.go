package signaturekey

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/dunglas/httpsfv"
	"gitlab.com/sidecat-dev/aauth-go/jose"
)

// ResponseSignOptions selects what a response signature covers. RFC 9421
// Section 2.4 binds a response to the request it answers by covering request
// components marked with the req parameter. The signature always covers
// @status first.
type ResponseSignOptions struct {
	// Label is the signature label. Empty means "sig".
	Label string
	// Components are the response fields covered after @status, in order.
	// Covering content-digest makes SignResponse set a sha-256
	// Content-Digest over the body.
	Components []string
	// RequestComponents are covered after Components, in order, each with
	// the req parameter: @method, @authority, @path, @query, or a request
	// field name.
	RequestComponents []string
	// KeyID, when set, is written as the keyid signature parameter after
	// created. It must be the kid the Signature-Key member names, so both
	// identify the same key (Signature-Key, Relationship to
	// Accept-Signature); a verifier takes the key from Signature-Key.
	KeyID string
}

// ResponseVerifyOptions states what a response signature must cover.
// @status is always required. AcceptedAlgorithms defaults to Ed25519 and ES256
// SignatureWindow to DefaultSignatureWindow.
type ResponseVerifyOptions struct {
	// Label selects one signature. Empty requires exactly one.
	Label                     string
	RequiredComponents        []string
	RequiredRequestComponents []string
	AcceptedAlgorithms        []string
	SignatureWindow           time.Duration
}

// VerifiedResponse is a response whose signature verified under a jwks_uri
// key. Signer is the verified id, the signer's server identifier.
type VerifiedResponse struct {
	label      string
	credential Credential
	signer     string
	publicKey  jose.JWK
	created    time.Time
	components []string
}

// Label returns the verified signature label.
func (verified VerifiedResponse) Label() string { return verified.label }

// Credential returns the verified Signature-Key member.
func (verified VerifiedResponse) Credential() Credential { return verified.credential.clone() }

// Signer returns the verified jwks_uri id.
func (verified VerifiedResponse) Signer() string { return verified.signer }

// PublicKey returns the key that verified the signature.
func (verified VerifiedResponse) PublicKey() jose.JWK { return verified.publicKey }

// Created returns the signature's created time.
func (verified VerifiedResponse) Created() time.Time { return verified.created }

// CoveredComponents returns the covered component identifiers in signature
// order, with ";req" on the request components.
func (verified VerifiedResponse) CoveredComponents() []string {
	return append([]string(nil), verified.components...)
}

type responseComponent struct {
	name    string
	request bool
}

func (component responseComponent) identifier() string {
	if component.request {
		return strconv.Quote(component.name) + ";req"
	}
	return strconv.Quote(component.name)
}

func (component responseComponent) String() string {
	if component.request {
		return component.name + ";req"
	}
	return component.name
}

// SignResponse signs a response a server sends in its own right, under the
// jwks_uri scheme, and sets Signature-Key, Signature-Input, Signature and,
// when covered, Content-Digest in header. status and body are the response
// that will be sent; request is the request it answers. Any change to the
// covered fields after signing invalidates the signature.
func SignResponse(
	header http.Header,
	status int,
	body []byte,
	request *http.Request,
	key jose.SigningKey,
	credential Credential,
	clock Clock,
	options ResponseSignOptions,
) error {
	if header == nil {
		return errors.New("aauth: response header is required")
	}
	if request == nil || request.URL == nil {
		return errors.New("aauth: the request a response answers is required")
	}
	if clock == nil {
		return errors.New("aauth: clock is required")
	}
	if status < 100 || status > 999 {
		return fmt.Errorf("aauth: response status %d is invalid", status)
	}
	if credential.scheme != SchemeJWKSURI {
		return errors.New("aauth: a response signature uses the jwks_uri scheme")
	}
	label := options.Label
	if label == "" {
		label = "sig"
	}
	if !isStructuredFieldKey(label) {
		return fmt.Errorf("aauth: signature label %q is not a lowercase structured-field key", label)
	}
	components, err := responseComponents(options.Components, options.RequestComponents)
	if err != nil {
		return err
	}
	if options.KeyID != "" {
		if _, _, keyID, _ := credential.JWKSURI(); options.KeyID != keyID {
			return errors.New("aauth: response keyid must be the kid Signature-Key names")
		}
		if err := validateStructuredFieldString(options.KeyID); err != nil {
			return fmt.Errorf("aauth: response keyid: %w", err)
		}
	}
	candidate := header.Clone()
	candidate.Set("Signature-Key", label+"="+credential.member)
	for _, component := range components {
		if !component.request && component.name == "content-digest" {
			digest := sha256.Sum256(body)
			candidate.Set("Content-Digest", "sha-256=:"+base64.StdEncoding.EncodeToString(digest[:])+":")
		}
	}
	params := responseSignatureParams(components, clock.Now().Unix(), options.KeyID)
	base, err := responseSignatureBase(status, candidate, request, components, params)
	if err != nil {
		return err
	}
	signature, err := key.SignMessage(rand.Reader, []byte(base))
	if err != nil {
		return err
	}
	candidate.Set("Signature-Input", label+"="+params)
	candidate.Set("Signature", label+"=:"+base64.StdEncoding.EncodeToString(signature)+":")
	for name := range header {
		delete(header, name)
	}
	for name, values := range candidate {
		header[name] = values
	}
	return nil
}

// VerifyResponse verifies a jwks_uri response signature over status, header
// and the exact body bytes, bound to request, the request the caller sent.
// It requires @status and the listed components, checks a covered
// Content-Digest against body, applies the signature window to created,
// resolves the key from the Signature-Key id, dwk and kid, and verifies the
// signature under the key's alg. The caller must still check Signer against
// the server it meant to ask.
func VerifyResponse(
	ctx context.Context,
	status int,
	header http.Header,
	body []byte,
	request *http.Request,
	resolver KeyResolver,
	clock Clock,
	options ResponseVerifyOptions,
) (VerifiedResponse, error) {
	if ctx == nil {
		return VerifiedResponse{}, errors.New("aauth: verification context is required")
	}
	if resolver == nil {
		return VerifiedResponse{}, errors.New("aauth: key resolver is required")
	}
	if clock == nil {
		return VerifiedResponse{}, errors.New("aauth: clock is required")
	}
	if request == nil || request.URL == nil {
		return VerifiedResponse{}, errors.New("aauth: the request a response answers is required")
	}
	for _, name := range []string{"Signature", "Signature-Input", "Signature-Key"} {
		if len(header.Values(name)) == 0 {
			return VerifiedResponse{}, newError(ErrorInvalidSignature, fmt.Errorf("aauth: response %s is missing", name))
		}
	}
	required, err := responseComponents(options.RequiredComponents, options.RequiredRequestComponents)
	if err != nil {
		return VerifiedResponse{}, err
	}
	algorithms, err := acceptedAlgorithms(options.AcceptedAlgorithms)
	if err != nil {
		return VerifiedResponse{}, err
	}
	label, components, created, expires, params, err := parseResponseSignatureInput(header.Values("Signature-Input"), options.Label)
	if err != nil {
		return VerifiedResponse{}, newError(ErrorInvalidInput, err)
	}
	for _, component := range required {
		if !containsResponseComponent(components, component) {
			return VerifiedResponse{}, newError(ErrorInvalidInput, fmt.Errorf("aauth: response signature does not cover %s", component))
		}
	}
	window := options.SignatureWindow
	if window == 0 {
		window = DefaultSignatureWindow
	}
	if window < 0 {
		return VerifiedResponse{}, errors.New("aauth: signature window must not be negative")
	}
	now := clock.Now()
	age := now.Sub(time.Unix(created, 0))
	if age < -window {
		return VerifiedResponse{}, newError(ErrorClockSkew, errors.New("aauth: response signature created time is ahead of the validity window"))
	}
	if age > window {
		return VerifiedResponse{}, newError(ErrorInvalidSignature, errors.New("aauth: response signature created time is older than the validity window"))
	}
	if expires != nil && now.Unix() >= *expires {
		return VerifiedResponse{}, newError(ErrorInvalidSignature, errors.New("aauth: response signature has expired"))
	}
	credential, err := parseCredentialForLabel(header.Values("Signature-Key"), label)
	if err != nil {
		return VerifiedResponse{}, err
	}
	issuer, document, keyID, ok := credential.JWKSURI()
	if !ok {
		return VerifiedResponse{}, &Error{
			Code:            ErrorUnsupportedScheme,
			AcceptedSchemes: []Scheme{SchemeJWKSURI},
			Cause:           errors.New("aauth: a response signature uses the jwks_uri scheme"),
		}
	}
	if containsResponseComponent(components, responseComponent{name: "content-digest"}) {
		if err := checkResponseContentDigest(header.Values("Content-Digest"), body); err != nil {
			return VerifiedResponse{}, newError(ErrorInvalidSignature, err)
		}
	}
	// As for a request, the length is judged against the resolved key, after
	// its type and algorithm.
	signature, err := parseSignature(header.Values("Signature"), label, func(size int) bool { return size > 0 })
	if err != nil {
		return VerifiedResponse{}, newError(ErrorInvalidSignature, err)
	}
	base, err := responseSignatureBase(status, header, request, components, params)
	if err != nil {
		return VerifiedResponse{}, newError(ErrorInvalidSignature, err)
	}
	key, err := resolver.ResolveKey(ctx, issuer, document, keyID)
	if err != nil {
		return VerifiedResponse{}, NormalizeResolutionError(err)
	}
	if err := verifyResponseSignature(key, algorithms, base, signature); err != nil {
		var failure *Error
		refresher, refreshable := resolver.(KeyRefresher)
		if !errors.As(err, &failure) || failure.Code != ErrorInvalidSignature || !refreshable {
			return VerifiedResponse{}, err
		}
		key, err = refresher.RefreshKey(ctx, issuer, document, keyID)
		if err != nil {
			return VerifiedResponse{}, NormalizeResolutionError(err)
		}
		if err := verifyResponseSignature(key, algorithms, base, signature); err != nil {
			return VerifiedResponse{}, err
		}
	}
	covered := make([]string, len(components))
	for index, component := range components {
		covered[index] = component.String()
	}
	return VerifiedResponse{
		label: label, credential: credential, signer: issuer, publicKey: key,
		created: time.Unix(created, 0), components: covered,
	}, nil
}

func verifyResponseSignature(key jose.JWK, algorithms []string, base string, signature []byte) error {
	if !contains(algorithms, key.Alg) {
		return unsupportedAlgorithm(algorithms, fmt.Errorf("aauth: response key algorithm %q is not accepted", key.Alg))
	}
	size, err := key.SignatureSize()
	if err != nil {
		return newError(ErrorInvalidKey, err)
	}
	if len(signature) != size {
		return newError(ErrorInvalidSignature, fmt.Errorf("aauth: %s response signature has %d bytes, want %d", key.Alg, len(signature), size))
	}
	if err := key.VerifySignature([]byte(base), signature); err != nil {
		return newError(ErrorInvalidSignature, errors.New("aauth: response signature is invalid"))
	}
	return nil
}

func responseComponents(fields, requestComponents []string) ([]responseComponent, error) {
	components := []responseComponent{{name: "@status"}}
	for _, field := range fields {
		name := strings.ToLower(field)
		if name == "@status" {
			continue
		}
		if strings.HasPrefix(name, "@") {
			return nil, fmt.Errorf("aauth: derived component %q is not a response field", field)
		}
		if err := ValidateAdditionalComponent(name); err != nil {
			return nil, err
		}
		components = append(components, responseComponent{name: name})
	}
	for _, field := range requestComponents {
		name := strings.ToLower(field)
		switch name {
		case "@method", "@authority", "@path", "@query":
		default:
			if strings.HasPrefix(name, "@") {
				return nil, fmt.Errorf("aauth: request component %q is not supported", field)
			}
			if err := ValidateAdditionalComponent(name); err != nil {
				return nil, err
			}
		}
		components = append(components, responseComponent{name: name, request: true})
	}
	for index, component := range components {
		for _, earlier := range components[:index] {
			if earlier == component {
				return nil, fmt.Errorf("aauth: response signature component %s is repeated", component)
			}
		}
	}
	return components, nil
}

func containsResponseComponent(components []responseComponent, wanted responseComponent) bool {
	for _, component := range components {
		if component == wanted {
			return true
		}
	}
	return false
}

func responseSignatureParams(components []responseComponent, created int64, keyID string) string {
	identifiers := make([]string, len(components))
	for index, component := range components {
		identifiers[index] = component.identifier()
	}
	params := "(" + strings.Join(identifiers, " ") + ");created=" + strconv.FormatInt(created, 10)
	if keyID != "" {
		params += ";keyid=" + strconv.Quote(keyID)
	}
	return params
}

func responseSignatureBase(
	status int,
	header http.Header,
	request *http.Request,
	components []responseComponent,
	params string,
) (string, error) {
	lines := make([]string, 0, len(components)+1)
	for _, component := range components {
		var value string
		switch {
		case component.name == "@status" && !component.request:
			value = strconv.Itoa(status)
		case component.request:
			var err error
			value, err = requestComponentValue(request, component.name)
			if err != nil {
				return "", err
			}
		default:
			values := header.Values(http.CanonicalHeaderKey(component.name))
			if len(values) == 0 {
				return "", fmt.Errorf("aauth: covered response field %q is absent", component.name)
			}
			value = strings.Join(values, ", ")
		}
		lines = append(lines, component.identifier()+": "+value)
	}
	lines = append(lines, `"@signature-params": `+params)
	return strings.Join(lines, "\n"), nil
}

func parseResponseSignatureInput(values []string, selectedLabel string) (string, []responseComponent, int64, *int64, string, error) {
	dictionary, members, err := parseDictionaryMembers(values, "Signature-Input")
	if err != nil {
		return "", nil, 0, nil, "", err
	}
	label := selectedLabel
	if label == "" {
		if len(dictionary.Names()) != 1 {
			return "", nil, 0, nil, "", errors.New("aauth: response Signature-Input contains multiple signatures; select one label")
		}
		label = dictionary.Names()[0]
	}
	member, ok := dictionary.Get(label)
	if !ok {
		return "", nil, 0, nil, "", fmt.Errorf("aauth: response Signature-Input has no member for label %q", label)
	}
	innerList, ok := member.(httpsfv.InnerList)
	if !ok {
		return "", nil, 0, nil, "", errors.New("aauth: response Signature-Input member must be an inner list")
	}
	if countTopLevelDelimiters(members[label], ';') != len(innerList.Params.Names()) {
		return "", nil, 0, nil, "", errors.New("aauth: response Signature-Input has duplicate parameters")
	}
	components := make([]responseComponent, 0, len(innerList.Items))
	for _, item := range innerList.Items {
		name, ok := item.Value.(string)
		if !ok || name == "" || name != strings.ToLower(name) {
			return "", nil, 0, nil, "", errors.New("aauth: response Signature-Input component is invalid")
		}
		component := responseComponent{name: name}
		for _, parameter := range item.Params.Names() {
			value, _ := item.Params.Get(parameter)
			if parameter != "req" || value != true {
				return "", nil, 0, nil, "", fmt.Errorf("aauth: response component parameter %q is not supported", parameter)
			}
			component.request = true
		}
		if containsResponseComponent(components, component) {
			return "", nil, 0, nil, "", fmt.Errorf("aauth: response component %s is repeated", component)
		}
		components = append(components, component)
	}
	createdValue, _ := innerList.Params.Get("created")
	created, ok := createdValue.(int64)
	if !ok || created <= 0 {
		return "", nil, 0, nil, "", errors.New("aauth: response Signature-Input created is required and must be a positive integer")
	}
	var expires *int64
	if expiresValue, present := innerList.Params.Get("expires"); present {
		value, ok := expiresValue.(int64)
		if !ok || value <= created {
			return "", nil, 0, nil, "", errors.New("aauth: response Signature-Input expires is invalid")
		}
		expires = &value
	}
	params, err := httpsfv.Marshal(innerList)
	if err != nil {
		return "", nil, 0, nil, "", fmt.Errorf("aauth: serialize response Signature-Input: %w", err)
	}
	return label, components, created, expires, params, nil
}

func checkResponseContentDigest(values []string, body []byte) error {
	if len(values) != 1 {
		return errors.New("aauth: response Content-Digest must be one sha-256 value")
	}
	const prefix = "sha-256=:"
	value := values[0]
	if !strings.HasPrefix(value, prefix) || !strings.HasSuffix(value, ":") {
		return errors.New("aauth: response Content-Digest must use sha-256")
	}
	expected, err := base64.StdEncoding.DecodeString(strings.TrimSuffix(strings.TrimPrefix(value, prefix), ":"))
	if err != nil || len(expected) != sha256.Size {
		return errors.New("aauth: response Content-Digest sha-256 value is invalid")
	}
	actual := sha256.Sum256(body)
	if !bytes.Equal(expected, actual[:]) {
		return errors.New("aauth: response Content-Digest does not match the body")
	}
	return nil
}
