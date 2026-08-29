package aauth

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"time"

	"gitlab.com/sidecat-dev/aauth-go/jose"
)

// TokenClaims is the closed set of current Core token profiles.
type TokenClaims interface {
	AgentTokenClaims | PersonTokenClaims | ResourceTokenClaims | AuthTokenClaims
}

// EvidenceID is the opaque identity of one exact Core token-verification
// result. Its zero value is invalid.
type EvidenceID struct {
	digest [sha256.Size]byte
}

// String returns the stable opaque presentation of a valid evidence identity.
func (identity EvidenceID) String() string {
	if identity.digest == [sha256.Size]byte{} {
		return ""
	}
	return "aauth-evidence:" + base64.RawURLEncoding.EncodeToString(identity.digest[:])
}

// VerifiedToken is sealed evidence that one exact compact Core token passed
// its cryptographic and token-profile verification at one trusted instant.
// The zero value and values assembled outside this package are invalid.
type VerifiedToken[T TokenClaims] struct {
	compact    jose.VerifiedCompact
	tokenType  string
	verifiedAt time.Time
	identity   EvidenceID
}

func newVerifiedToken[T TokenClaims](compact jose.VerifiedCompact, tokenType string, verifiedAt time.Time) (VerifiedToken[T], error) {
	verified := VerifiedToken[T]{compact: compact, tokenType: tokenType, verifiedAt: verifiedAt.UTC()}
	identity, err := verified.computeIdentity()
	if err != nil {
		return VerifiedToken[T]{}, err
	}
	verified.identity = identity
	return verified, nil
}

// Valid reports whether the evidence retains a self-consistent exact token,
// verification key, profile, and trusted instant.
func (verified VerifiedToken[T]) Valid() bool {
	if verified.identity.digest == [sha256.Size]byte{} {
		return false
	}
	identity, err := verified.computeIdentity()
	return err == nil && identity == verified.identity
}

// Type returns the verified Core token type.
func (verified VerifiedToken[T]) Type() (string, error) {
	if !verified.Valid() {
		return "", errors.New("aauth: verified token evidence is invalid")
	}
	return verified.tokenType, nil
}

// Compact returns the exact verified compact serialization.
func (verified VerifiedToken[T]) Compact() (string, error) {
	if !verified.Valid() {
		return "", errors.New("aauth: verified token evidence is invalid")
	}
	return verified.compact.Compact()
}

// VerificationKey returns an independent copy of the selected issuer key.
func (verified VerifiedToken[T]) VerificationKey() (jose.JWK, error) {
	if !verified.Valid() {
		return jose.JWK{}, errors.New("aauth: verified token evidence is invalid")
	}
	return verified.compact.VerificationKey()
}

// VerifiedAt returns the single trusted instant used for profile validation.
func (verified VerifiedToken[T]) VerifiedAt() (time.Time, error) {
	if !verified.Valid() {
		return time.Time{}, errors.New("aauth: verified token evidence is invalid")
	}
	return verified.verifiedAt, nil
}

// EvidenceID returns the opaque identity of this exact verified result.
func (verified VerifiedToken[T]) EvidenceID() (EvidenceID, error) {
	if !verified.Valid() {
		return EvidenceID{}, errors.New("aauth: verified token evidence is invalid")
	}
	return verified.identity, nil
}

// Claims decodes an independent typed projection from the exact verified
// payload. Mutating the returned value cannot alter the retained evidence.
func (verified VerifiedToken[T]) Claims() (T, error) {
	var claims T
	if !verified.Valid() {
		return claims, errors.New("aauth: verified token evidence is invalid")
	}
	payload, err := verified.compact.Payload()
	if err != nil {
		return claims, err
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return claims, err
	}
	return claims, nil
}

func (verified VerifiedToken[T]) computeIdentity() (EvidenceID, error) {
	compact, err := verified.compact.Compact()
	if err != nil {
		return EvidenceID{}, err
	}
	key, err := verified.compact.VerificationKey()
	if err != nil {
		return EvidenceID{}, err
	}
	if verified.tokenType == "" || verified.verifiedAt.IsZero() {
		return EvidenceID{}, errors.New("aauth: verified token evidence is incomplete")
	}
	material, err := json.Marshal(struct {
		Domain     string    `json:"domain"`
		Compact    string    `json:"compact"`
		Key        jose.JWK  `json:"key"`
		TokenType  string    `json:"token_type"`
		VerifiedAt time.Time `json:"verified_at"`
	}{
		Domain:     "gitlab.com/sidecat-dev/aauth-go/verified-token/v1",
		Compact:    compact,
		Key:        key,
		TokenType:  verified.tokenType,
		VerifiedAt: verified.verifiedAt.UTC(),
	})
	if err != nil {
		return EvidenceID{}, err
	}
	return EvidenceID{digest: sha256.Sum256(material)}, nil
}
