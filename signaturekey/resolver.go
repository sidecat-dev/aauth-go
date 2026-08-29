package signaturekey

import (
	"context"
	"errors"
	"fmt"

	"gitlab.com/sidecat-dev/aauth-go/jose"
)

// KeyResolver resolves one fully qualified Signature-Key key reference.
type KeyResolver interface {
	ResolveKey(ctx context.Context, issuer, discoveryDocument, keyID string) (jose.JWK, error)
}

// ResolutionCode classifies discovery failures without exposing local
// diagnostics on the wire.
type ResolutionCode string

const (
	ResolutionUnknown              ResolutionCode = "unknown"
	ResolutionInvalid              ResolutionCode = "invalid"
	ResolutionDenied               ResolutionCode = "denied"
	ResolutionUnavailable          ResolutionCode = "unavailable"
	ResolutionIssuerMissing        ResolutionCode = "issuer_missing"
	ResolutionIssuerMismatch       ResolutionCode = "issuer_mismatch"
	ResolutionUnsupportedAlgorithm ResolutionCode = "unsupported_algorithm"
)

// ResolutionError retains one stable discovery classification.
type ResolutionError struct {
	Code  ResolutionCode
	Cause error
}

func resolutionError(code ResolutionCode, cause error) error {
	return &ResolutionError{Code: code, Cause: cause}
}

// NormalizeResolutionError preserves a typed resolution failure and
// conservatively classifies an untyped resolver error as unavailable.
func NormalizeResolutionError(err error) error {
	if err == nil {
		return nil
	}
	var classified *ResolutionError
	if errors.As(err, &classified) {
		return err
	}
	return resolutionError(ResolutionUnavailable, err)
}

func classifyResolvedJWKError(err error) error {
	var unsupported interface{ UnsupportedAlgorithm() string }
	if errors.As(err, &unsupported) {
		return resolutionError(ResolutionUnsupportedAlgorithm, err)
	}
	return resolutionError(ResolutionInvalid, err)
}

func (failure *ResolutionError) Error() string {
	if failure == nil || failure.Cause == nil {
		return "aauth: key resolution failed"
	}
	return "aauth: key resolution " + string(failure.Code) + ": " + failure.Cause.Error()
}

func (failure *ResolutionError) Unwrap() error {
	if failure == nil {
		return nil
	}
	return failure.Cause
}

// KeyRefresher deliberately re-checks a key after a same-kid verification
// failure.
type KeyRefresher interface {
	RefreshKey(ctx context.Context, issuer, discoveryDocument, keyID string) (jose.JWK, error)
}

// StaticKeyResolver is an explicit in-memory trust source.
type StaticKeyResolver map[string]map[string]jose.JWK

func (resolver StaticKeyResolver) ResolveKey(_ context.Context, issuer, _ string, keyID string) (jose.JWK, error) {
	issuerKeys, ok := resolver[issuer]
	if !ok {
		return jose.JWK{}, &ResolutionError{Code: ResolutionInvalid, Cause: fmt.Errorf("aauth: issuer %q is not trusted", issuer)}
	}
	key, ok := issuerKeys[keyID]
	if !ok {
		return jose.JWK{}, &ResolutionError{Code: ResolutionUnknown, Cause: fmt.Errorf("aauth: issuer %q has no key %q", issuer, keyID)}
	}
	if key.Kid != "" && key.Kid != keyID {
		return jose.JWK{}, &ResolutionError{Code: ResolutionInvalid, Cause: fmt.Errorf("aauth: resolved key id %q does not match requested %q", key.Kid, keyID)}
	}
	if _, err := key.PublicKey(); err != nil {
		var unsupported interface{ UnsupportedAlgorithm() string }
		if errors.As(err, &unsupported) {
			return jose.JWK{}, &ResolutionError{Code: ResolutionUnsupportedAlgorithm, Cause: err}
		}
		return jose.JWK{}, &ResolutionError{Code: ResolutionInvalid, Cause: err}
	}
	return key, nil
}
