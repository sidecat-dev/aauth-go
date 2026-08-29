package aauth

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"

	"gitlab.com/sidecat-dev/aauth-go/jose"
)

var rawURL = base64.RawURLEncoding

// KeyResolver resolves an issuer key after the token's issuer, discovery
// document, and key id have been structurally validated. Implementations
// should return KeyResolutionError for every failed lookup. The library treats
// an untyped resolver error conservatively as KeyResolutionUnavailable rather
// than misreporting an operational failure as invalid client authentication.
type KeyResolver interface {
	ResolveKey(ctx context.Context, issuer, discoveryDocument, keyID string) (jose.JWK, error)
}

// KeyResolutionCode distinguishes protocol-visible key failures from local
// resolution failures. Callers must not infer these classes from diagnostic
// strings returned by a resolver.
type KeyResolutionCode string

const (
	// KeyResolutionUnknown means a successfully parsed, trusted key set did
	// not contain the requested key identifier.
	KeyResolutionUnknown KeyResolutionCode = "unknown"
	// KeyResolutionInvalid means the reference, trust relationship, metadata,
	// key set, or resolved key material was invalid.
	KeyResolutionInvalid KeyResolutionCode = "invalid"
	// KeyResolutionDenied means local egress admission refused discovery.
	KeyResolutionDenied KeyResolutionCode = "denied"
	// KeyResolutionUnavailable means required discovery could not currently
	// complete because of cancellation, transport, or remote-service failure.
	KeyResolutionUnavailable KeyResolutionCode = "unavailable"
	// KeyResolutionIssuerMissing means the fetched metadata document omitted
	// the issuer member required to bind it to its discovery identity.
	KeyResolutionIssuerMissing KeyResolutionCode = "issuer_missing"
	// KeyResolutionIssuerMismatch means the fetched metadata issuer did not
	// byte-for-byte match the discovery identity.
	KeyResolutionIssuerMismatch KeyResolutionCode = "issuer_mismatch"
	// KeyResolutionUnsupportedAlgorithm means the exact requested JWK names a
	// missing, polymorphic, or otherwise unsupported signing algorithm.
	KeyResolutionUnsupportedAlgorithm KeyResolutionCode = "unsupported_algorithm"
)

// KeyResolutionError preserves resolver diagnostics while exposing a stable
// classification to protocol adapters. Diagnostics are not safe to copy into
// remote responses.
type KeyResolutionError struct {
	Code  KeyResolutionCode
	Cause error
}

func (err *KeyResolutionError) Error() string {
	if err == nil || err.Cause == nil {
		return "aauth: key resolution failed"
	}
	return "aauth: key resolution " + string(err.Code) + ": " + err.Cause.Error()
}

func (err *KeyResolutionError) Unwrap() error {
	if err == nil {
		return nil
	}
	return err.Cause
}

func keyResolutionError(code KeyResolutionCode, cause error) error {
	return &KeyResolutionError{Code: code, Cause: cause}
}

func normalizeKeyResolutionError(err error) error {
	if err == nil {
		return nil
	}
	var resolutionError *KeyResolutionError
	if errors.As(err, &resolutionError) {
		return err
	}
	return keyResolutionError(KeyResolutionUnavailable, err)
}

// KeyRefresher is implemented by resolvers that can deliberately re-check an
// issuer after a same-kid signature failure.
type KeyRefresher interface {
	RefreshKey(ctx context.Context, issuer, discoveryDocument, keyID string) (jose.JWK, error)
}

// StaticKeyResolver is an explicit in-memory trust source useful for embedded
// deployments, deterministic qualification, and callers that own discovery.
type StaticKeyResolver map[string]map[string]jose.JWK

func (resolver StaticKeyResolver) ResolveKey(_ context.Context, issuer, _ string, keyID string) (jose.JWK, error) {
	issuerKeys, ok := resolver[issuer]
	if !ok {
		return jose.JWK{}, keyResolutionError(
			KeyResolutionInvalid,
			fmt.Errorf("aauth: issuer %q is not trusted", issuer),
		)
	}
	key, ok := issuerKeys[keyID]
	if !ok {
		return jose.JWK{}, keyResolutionError(
			KeyResolutionUnknown,
			fmt.Errorf("aauth: issuer %q has no key %q", issuer, keyID),
		)
	}
	if key.Kid != "" && key.Kid != keyID {
		return jose.JWK{}, keyResolutionError(
			KeyResolutionInvalid,
			fmt.Errorf("aauth: resolved key id %q does not match requested %q", key.Kid, keyID),
		)
	}
	if _, err := key.PublicKey(); err != nil {
		return jose.JWK{}, classifyResolvedJWKError(err)
	}
	return key, nil
}

func classifyResolvedJWKError(err error) error {
	var unsupportedAlgorithm interface{ UnsupportedAlgorithm() string }
	if errors.As(err, &unsupportedAlgorithm) {
		return keyResolutionError(KeyResolutionUnsupportedAlgorithm, err)
	}
	return keyResolutionError(KeyResolutionInvalid, err)
}
