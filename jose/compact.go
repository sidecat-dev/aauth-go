package jose

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"gitlab.com/sidecat-dev/aauth-go/internal/jsonstrict"
)

// Header is the protected compact-JWS header used by current AAuth tokens.
type Header struct {
	Algorithm string `json:"alg"`
	Type      string `json:"typ"`
	KeyID     string `json:"kid"`
}

// ParsedCompact contains structurally parsed but unverified compact-JWS
// material.
type ParsedCompact struct {
	header       Header
	protected    []byte
	embeddedJWK  JWK
	hasEmbedded  bool
	payload      []byte
	signature    []byte
	signingInput string
	compact      string
}

// Header returns the untrusted protected header.
func (parsed ParsedCompact) Header() Header {
	return parsed.header
}

// Protected returns an independent copy of the exact untrusted protected
// header JSON bytes.
func (parsed ParsedCompact) Protected() []byte {
	return append([]byte(nil), parsed.protected...)
}

// Payload returns an independent copy of the untrusted exact payload bytes.
func (parsed ParsedCompact) Payload() []byte {
	return append([]byte(nil), parsed.payload...)
}

// Compact returns the untrusted exact compact serialization.
func (parsed ParsedCompact) Compact() string {
	return parsed.compact
}

// ParseCompact structurally parses one three-part, raw-base64url compact JWS.
// It validates unambiguous JSON and, for Ed25519 and ES256, signature length,
// but does not establish trust.
func ParseCompact(compact string) (ParsedCompact, error) {
	var parsed ParsedCompact
	parts := strings.Split(compact, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return parsed, errors.New("aauth: token must be a three-part compact JWS")
	}
	headerBytes, err := decodeRawURLCanonical(parts[0])
	if err != nil {
		return parsed, fmt.Errorf("aauth: decode token header: %w", err)
	}
	header, embeddedJWK, _, err := decodeProtectedHeader(headerBytes)
	if err != nil {
		return parsed, fmt.Errorf("aauth: parse token header: %w", err)
	}
	payload, err := decodeRawURLCanonical(parts[1])
	if err != nil {
		return parsed, fmt.Errorf("aauth: decode token payload: %w", err)
	}
	if err := jsonstrict.RejectAmbiguousNames(payload); err != nil {
		return parsed, fmt.Errorf("aauth: parse token payload: %w", err)
	}
	signature, err := decodeRawURLCanonical(parts[2])
	if err != nil {
		return parsed, fmt.Errorf("aauth: decode token signature: %w", err)
	}
	if IsTokenAlgorithm(header.Algorithm) && len(signature) != tokenSignatureSize {
		return parsed, fmt.Errorf("aauth: %s token signature has %d bytes", header.Algorithm, len(signature))
	}
	parsed = ParsedCompact{
		header:       header,
		protected:    append([]byte(nil), headerBytes...),
		payload:      append([]byte(nil), payload...),
		signature:    append([]byte(nil), signature...),
		signingInput: parts[0] + "." + parts[1],
		compact:      compact,
	}
	if embeddedJWK != nil {
		parsed.embeddedJWK = *embeddedJWK
		parsed.hasEmbedded = true
	}
	return parsed, nil
}

// PeekHeader performs untrusted structural inspection of a compact JWS.
func PeekHeader(compact string) (Header, error) {
	parsed, err := ParseCompact(compact)
	if err != nil {
		return Header{}, err
	}
	return parsed.Header(), nil
}

// tokenSignatureSize is the length of an Ed25519 signature and of an ES256
// signature in its JWS form, R || S.
const tokenSignatureSize = ed25519.SignatureSize

// SignCompact signs the exact caller-supplied JSON payload bytes under the
// token profile. header.Algorithm must be the key's algorithm. It does not
// interpret typ or marshal claims.
func SignCompact(key SigningKey, header Header, payload []byte) (string, error) {
	if header.KeyID == "" {
		return "", errors.New("aauth: token kid is required")
	}
	if header.KeyID != key.ID() {
		return "", errors.New("aauth: token kid does not match signing key")
	}
	headerBytes, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("aauth: marshal token header: %w", err)
	}
	return SignCompactProtected(key, headerBytes, payload)
}

// SignCompactProtected signs exact caller-supplied protected-header and
// payload JSON bytes. The token profile requires a fully specified Ed25519 or
// ES256 key, a header alg equal to the key's, and exactly one matching key
// reference: either kid or an embedded public JWK. It does not interpret typ
// or protocol claims.
func SignCompactProtected(key SigningKey, protected, payload []byte) (string, error) {
	if key.ID() == "" {
		return "", errors.New("aauth: signing key is not initialized")
	}
	if !IsTokenAlgorithm(key.Algorithm()) {
		return "", fmt.Errorf("aauth: compact JWS requires an Ed25519 or ES256 signing key, not %q", key.Algorithm())
	}
	header, embeddedJWK, hasKeyID, err := decodeProtectedHeader(protected)
	if err != nil {
		return "", fmt.Errorf("aauth: parse token header: %w", err)
	}
	if header.Algorithm == "none" {
		return "", errors.New("aauth: alg none is forbidden")
	}
	if !IsTokenAlgorithm(header.Algorithm) {
		return "", fmt.Errorf("aauth: unsupported token algorithm %q", header.Algorithm)
	}
	if header.Algorithm != key.Algorithm() {
		return "", fmt.Errorf("aauth: token algorithm %q does not match the %s signing key", header.Algorithm, key.Algorithm())
	}
	if hasKeyID == (embeddedJWK != nil) {
		return "", errors.New("aauth: protected header must name exactly one signing key")
	}
	if hasKeyID && header.KeyID == "" {
		return "", errors.New("aauth: token kid is required")
	}
	if hasKeyID && header.KeyID != key.ID() {
		return "", errors.New("aauth: token kid does not match signing key")
	}
	if embeddedJWK != nil && !embeddedJWK.Equal(key.PublicJWK()) {
		return "", errors.New("aauth: protected header JWK does not match signing key")
	}
	if err := jsonstrict.RejectAmbiguousNames(payload); err != nil {
		return "", fmt.Errorf("aauth: parse token payload: %w", err)
	}
	signingInput := rawURL.EncodeToString(protected) + "." + rawURL.EncodeToString(payload)
	signature, err := key.SignMessage(rand.Reader, []byte(signingInput))
	if err != nil {
		return "", err
	}
	return signingInput + "." + rawURL.EncodeToString(signature), nil
}

func decodeProtectedHeader(value []byte) (Header, *JWK, bool, error) {
	var wire struct {
		Algorithm string   `json:"alg"`
		Type      string   `json:"typ"`
		KeyID     string   `json:"kid"`
		JWK       *JWK     `json:"jwk"`
		Critical  []string `json:"crit"`
		Unencoded *bool    `json:"b64"`
	}
	var header Header
	if err := jsonstrict.RejectAmbiguousNames(value); err != nil {
		return header, nil, false, err
	}
	if err := jsonstrict.RejectCaseVariants(value, &wire); err != nil {
		return header, nil, false, err
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(value, &members); err != nil {
		return header, nil, false, err
	}
	if err := json.Unmarshal(value, &wire); err != nil {
		return header, nil, false, err
	}
	if _, present := members["crit"]; present {
		if len(wire.Critical) == 0 {
			return header, nil, false, errors.New("protected header crit must be a nonempty string array")
		}
		seen := make(map[string]struct{}, len(wire.Critical))
		for _, name := range wire.Critical {
			if name == "" {
				return header, nil, false, errors.New("protected header crit contains an empty member name")
			}
			if _, duplicate := seen[name]; duplicate {
				return header, nil, false, fmt.Errorf("protected header crit repeats %q", name)
			}
			seen[name] = struct{}{}
			if _, present := members[name]; !present {
				return header, nil, false, fmt.Errorf("protected header crit names absent member %q", name)
			}
			return header, nil, false, fmt.Errorf("unsupported critical protected header member %q", name)
		}
	}
	if _, present := members["b64"]; present {
		return header, nil, false, errors.New("unsupported protected header member \"b64\"")
	}
	header = Header{Algorithm: wire.Algorithm, Type: wire.Type, KeyID: wire.KeyID}
	_, hasKeyID := members["kid"]
	_, hasJWK := members["jwk"]
	if hasKeyID && hasJWK {
		return header, nil, false, errors.New("protected header contains both kid and jwk")
	}
	if !hasJWK {
		return header, nil, hasKeyID, nil
	}
	embeddedJWK := wire.JWK
	if embeddedJWK == nil {
		return header, nil, false, errors.New("protected header jwk must be an object")
	}
	return header, embeddedJWK, false, nil
}

// Verify verifies the compact JWS with the supplied Ed25519 or ES256 JWK. The
// protected alg must be the key's alg, so a key is used only under the
// algorithm it names.
func (parsed ParsedCompact) Verify(key JWK) (VerifiedCompact, error) {
	if parsed.header.Algorithm == "none" {
		return VerifiedCompact{}, errors.New("aauth: alg none is forbidden")
	}
	if !IsTokenAlgorithm(parsed.header.Algorithm) {
		return VerifiedCompact{}, fmt.Errorf("aauth: unsupported token algorithm %q", parsed.header.Algorithm)
	}
	if parsed.header.KeyID != "" && key.Kid != "" && parsed.header.KeyID != key.Kid {
		return VerifiedCompact{}, errors.New("aauth: protected kid does not match verification key")
	}
	if parsed.hasEmbedded && !parsed.embeddedJWK.Equal(key) {
		return VerifiedCompact{}, errors.New("aauth: protected JWK does not match verification key")
	}
	if _, err := key.PublicKey(); err != nil {
		return VerifiedCompact{}, err
	}
	if key.Alg != parsed.header.Algorithm {
		return VerifiedCompact{}, fmt.Errorf("aauth: token algorithm %q does not match the %s verification key", parsed.header.Algorithm, key.Alg)
	}
	if err := key.VerifySignature([]byte(parsed.signingInput), parsed.signature); err != nil {
		return VerifiedCompact{}, errors.New("aauth: token signature is invalid")
	}
	verified := VerifiedCompact{
		initialized: true,
		header:      parsed.header,
		payload:     append([]byte(nil), parsed.payload...),
		compact:     parsed.compact,
		key:         key,
	}
	return verified, nil
}

// VerifiedCompact contains one verified compact JWS and its verification key.
// Its fields are unexported and its accessors return copies.
type VerifiedCompact struct {
	initialized bool
	header      Header
	payload     []byte
	compact     string
	key         JWK
}

func (verified VerifiedCompact) valid() bool {
	return verified.initialized
}

// Header returns the verified protected header.
func (verified VerifiedCompact) Header() (Header, error) {
	if !verified.valid() {
		return Header{}, errors.New("aauth: verified compact JWS is not valid")
	}
	return verified.header, nil
}

// Payload returns an independent copy of the exact verified payload bytes.
func (verified VerifiedCompact) Payload() ([]byte, error) {
	if !verified.valid() {
		return nil, errors.New("aauth: verified compact JWS is not valid")
	}
	return append([]byte(nil), verified.payload...), nil
}

// Compact returns the exact verified compact serialization.
func (verified VerifiedCompact) Compact() (string, error) {
	if !verified.valid() {
		return "", errors.New("aauth: verified compact JWS is not valid")
	}
	return verified.compact, nil
}

// CompactBytes returns an independent copy of the exact verified compact
// serialization bytes.
func (verified VerifiedCompact) CompactBytes() ([]byte, error) {
	compact, err := verified.Compact()
	if err != nil {
		return nil, err
	}
	return []byte(compact), nil
}

// VerificationKey returns the independent public JWK used for verification.
func (verified VerifiedCompact) VerificationKey() (JWK, error) {
	if !verified.valid() {
		return JWK{}, errors.New("aauth: verified compact JWS is not valid")
	}
	return verified.key, nil
}
