package signaturekey

import (
	"context"
	"errors"
	"fmt"

	"gitlab.com/sidecat-dev/aauth-go/jose"
)

// JWKSKeyResolver resolves one key from the JWKS at a direct jwks URL.
//
// keySetURL is the url parameter exactly as presented. It is both the
// signer identity and the key location, so an implementation must not
// canonicalize or normalize it: two URLs that differ in any byte name
// different signers. An implementation that fetches must apply egress
// admission first. It returns a ResolutionError with ResolutionUnknown when
// the JWKS has no key for keyID. HTTPKeyResolver implements this interface.
type JWKSKeyResolver interface {
	ResolveJWKSKey(ctx context.Context, keySetURL, keyID string) (jose.JWK, error)
}

// JWKSKeyRefresher deliberately re-checks a direct JWKS after a same-kid
// verification failure.
type JWKSKeyRefresher interface {
	RefreshJWKSKey(ctx context.Context, keySetURL, keyID string) (jose.JWK, error)
}

// StaticJWKSReference identifies one key within a direct JWKS by its exact
// URL and key id.
type StaticJWKSReference struct {
	URL   string
	KeyID string
}

// StaticJWKSResolver is an exact in-memory trust source for direct JWKS
// keys. Lookup compares URLs byte for byte.
type StaticJWKSResolver map[StaticJWKSReference]jose.JWK

// ResolveJWKSKey returns the configured key for the exact URL and key id.
func (resolver StaticJWKSResolver) ResolveJWKSKey(_ context.Context, keySetURL, keyID string) (jose.JWK, error) {
	key, ok := resolver[StaticJWKSReference{URL: keySetURL, KeyID: keyID}]
	if !ok {
		return jose.JWK{}, &ResolutionError{
			Code:  ResolutionUnknown,
			Cause: fmt.Errorf("aauth: JWKS %q has no key %q", keySetURL, keyID),
		}
	}
	if key.Kid != "" && key.Kid != keyID {
		return jose.JWK{}, &ResolutionError{Code: ResolutionInvalid, Cause: fmt.Errorf("aauth: resolved key id %q does not match requested %q", key.Kid, keyID)}
	}
	if _, err := key.PublicKey(); err != nil {
		return jose.JWK{}, classifyResolvedJWKError(err)
	}
	return key, nil
}

// VerifyJWKS resolves the key of a direct jwks proof and verifies the HTTP
// Message Signature with it. The resolver receives url and kid exactly as
// presented, and the verified signer is that exact url. A same-kid signature
// failure triggers at most one refresh when the resolver also implements
// JWKSKeyRefresher, subject to its refresh floor.
func (prepared PreparedRequest) VerifyJWKS(ctx context.Context, resolver JWKSKeyResolver) (VerifiedRequest, error) {
	if ctx == nil {
		return VerifiedRequest{}, errors.New("aauth: verification context is required")
	}
	if resolver == nil {
		return VerifiedRequest{}, errors.New("aauth: JWKS key resolver is required")
	}
	keySetURL, keyID, ok := prepared.credential.JWKS()
	if !ok {
		return VerifiedRequest{}, errors.New("aauth: prepared request does not use jwks")
	}
	key, err := resolver.ResolveJWKSKey(ctx, keySetURL, keyID)
	if err != nil {
		return VerifiedRequest{}, NormalizeError(NormalizeResolutionError(err), ErrorInvalidKey)
	}
	verified, err := prepared.verifyWithKey(key)
	if err == nil {
		return verified, nil
	}
	var signatureFailure *Error
	if !errors.As(err, &signatureFailure) || signatureFailure.Code != ErrorInvalidSignature {
		return VerifiedRequest{}, err
	}
	refresher, ok := resolver.(JWKSKeyRefresher)
	if !ok {
		return VerifiedRequest{}, err
	}
	refreshed, refreshErr := refresher.RefreshJWKSKey(ctx, keySetURL, keyID)
	if refreshErr != nil {
		return VerifiedRequest{}, NormalizeError(NormalizeResolutionError(refreshErr), ErrorInvalidKey)
	}
	return prepared.verifyWithKey(refreshed)
}
