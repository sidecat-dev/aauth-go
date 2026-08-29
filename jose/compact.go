package jose

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
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
// material. Possession of this value establishes no cryptographic authority.
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
// It validates unambiguous JSON and Ed25519 signature length but does not
// establish trust.
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
	if len(signature) != ed25519.SignatureSize {
		return parsed, fmt.Errorf("aauth: Ed25519 token signature has %d bytes", len(signature))
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

// SignCompact signs the exact caller-supplied JSON payload bytes under the
// bounded Ed25519 profile. It does not interpret typ or marshal claims.
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
// payload JSON bytes. The bounded profile requires fully specified Ed25519 and
// exactly one matching key reference: either kid or an embedded public JWK.
// It does not interpret typ or protocol claims.
func SignCompactProtected(key SigningKey, protected, payload []byte) (string, error) {
	if key.ID() == "" {
		return "", errors.New("aauth: signing key is not initialized")
	}
	header, embeddedJWK, hasKeyID, err := decodeProtectedHeader(protected)
	if err != nil {
		return "", fmt.Errorf("aauth: parse token header: %w", err)
	}
	if header.Algorithm == "none" {
		return "", errors.New("aauth: alg none is forbidden")
	}
	if header.Algorithm != Ed25519Algorithm {
		return "", fmt.Errorf("aauth: unsupported token algorithm %q", header.Algorithm)
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
	signature, err := key.Sign(rand.Reader, []byte(signingInput), crypto.Hash(0))
	if err != nil {
		return "", err
	}
	return signingInput + "." + rawURL.EncodeToString(signature), nil
}

func decodeProtectedHeader(value []byte) (Header, *JWK, bool, error) {
	var header Header
	if err := jsonstrict.RejectAmbiguousNames(value); err != nil {
		return header, nil, false, err
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(value, &members); err != nil {
		return header, nil, false, err
	}
	for name := range members {
		switch name {
		case "alg", "typ", "kid", "jwk":
		default:
			return header, nil, false, fmt.Errorf("unsupported protected header member %q", name)
		}
	}
	if err := json.Unmarshal(value, &header); err != nil {
		return header, nil, false, err
	}
	_, hasKeyID := members["kid"]
	encodedJWK, hasJWK := members["jwk"]
	if hasKeyID && hasJWK {
		return header, nil, false, errors.New("protected header contains both kid and jwk")
	}
	if !hasJWK {
		return header, nil, hasKeyID, nil
	}
	var embeddedJWK *JWK
	if err := json.Unmarshal(encodedJWK, &embeddedJWK); err != nil {
		return header, nil, false, err
	}
	if embeddedJWK == nil {
		return header, nil, false, errors.New("protected header jwk must be an object")
	}
	return header, embeddedJWK, false, nil
}

// Verify verifies the compact JWS with the supplied Ed25519 JWK and returns a
// sealed value only after successful verification.
func (parsed ParsedCompact) Verify(key JWK) (VerifiedCompact, error) {
	if parsed.header.Algorithm == "none" {
		return VerifiedCompact{}, errors.New("aauth: alg none is forbidden")
	}
	if parsed.header.Algorithm != Ed25519Algorithm {
		return VerifiedCompact{}, fmt.Errorf("aauth: unsupported token algorithm %q", parsed.header.Algorithm)
	}
	if parsed.header.KeyID != "" && key.Kid != "" && parsed.header.KeyID != key.Kid {
		return VerifiedCompact{}, errors.New("aauth: protected kid does not match verification key")
	}
	if parsed.hasEmbedded && !parsed.embeddedJWK.Equal(key) {
		return VerifiedCompact{}, errors.New("aauth: protected JWK does not match verification key")
	}
	publicKey, err := key.PublicKey()
	if err != nil {
		return VerifiedCompact{}, err
	}
	ed25519Key, ok := publicKey.(ed25519.PublicKey)
	if !ok {
		return VerifiedCompact{}, errors.New("aauth: resolved token key is not Ed25519")
	}
	if !ed25519.Verify(ed25519Key, []byte(parsed.signingInput), parsed.signature) {
		return VerifiedCompact{}, errors.New("aauth: token signature is invalid")
	}
	verified := VerifiedCompact{
		header:  parsed.header,
		payload: append([]byte(nil), parsed.payload...),
		compact: parsed.compact,
		key:     key,
	}
	verified.seal = verified.sealValue()
	return verified, nil
}

// VerifiedCompact is cryptographic evidence for one exact compact JWS and
// verification key. All authority-bearing state is sealed and unexported.
type VerifiedCompact struct {
	header  Header
	payload []byte
	compact string
	key     JWK
	seal    [sha256.Size]byte
}

func (verified VerifiedCompact) valid() bool {
	return verified.seal != [sha256.Size]byte{} && verified.seal == verified.sealValue()
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

func (verified VerifiedCompact) sealValue() [sha256.Size]byte {
	encoded, _ := json.Marshal(struct {
		Header  Header `json:"header"`
		Payload []byte `json:"payload"`
		Compact string `json:"compact"`
		Key     JWK    `json:"key"`
	}{
		Header:  verified.header,
		Payload: verified.payload,
		Compact: verified.compact,
		Key:     verified.key,
	})
	return sha256.Sum256(encoded)
}
