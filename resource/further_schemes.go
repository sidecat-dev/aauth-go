package resource

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"

	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

// FurtherSchemesConfig lets a Resource that also serves clients outside AAuth
// accept their HTTP Message Signatures under Signature-Key schemes AAuth does
// not use. AAuth Agents present the jwt scheme, and nothing here changes what
// an AAuth request may present or how it is verified. A request under one of
// these schemes is verified by its scheme's verifier and served by Protected,
// never by the Resource's AAuth handler, with the verified signer available
// from SignerFromContext. Every Accept-Signature-Scheme the protected routes
// send then lists jwt followed by Schemes.
type FurtherSchemesConfig struct {
	// Schemes lists the accepted schemes in descending preference: any of
	// hwk, jkt-jwt, self-jwt, jwks_uri, jwks, x509, and cached.
	Schemes []signaturekey.Scheme
	// SelfJWTType is the explicit JWT typ a self-jwt assertion must carry,
	// which the deployment selects. It is required exactly when self-jwt is
	// listed. The assertion's iss, dwk and kid select its key through the
	// Resource's KeyResolver, and that key verifies the HTTP signature too.
	SelfJWTType string
	// Algorithms lists the algorithms, from jose.SignatureAlgorithms, that an
	// hwk or x509 key may use. Ed25519 and ES256 are always accepted, because
	// AAuth requires the first and recommends the second; keys of the other
	// schemes use that token profile.
	Algorithms []string
	// JWKS resolves the key of a jwks proof. It is required with jwks; an
	// *signaturekey.HTTPKeyResolver implements it. jwks_uri proofs use the
	// Resource's KeyResolver.
	JWKS signaturekey.JWKSKeyResolver
	// X509 returns the certificate chain, trust anchors and CRLs for the exact
	// x5u of an x509 proof, after the host's own egress checks. It is required
	// with x509; the chain and revocation are always validated.
	X509 func(ctx context.Context, certificateURL string) (signaturekey.X509VerifyOptions, error)
	// Cache issues cache identifiers for jkt-jwt assertions that ask to be
	// cached and resolves cached proofs. It is required exactly when cached is
	// listed, and cached requires jkt-jwt.
	Cache *signaturekey.AssertionCache
	// Protected serves the verified requests of these clients.
	Protected http.Handler
}

// SignerPrincipal is the signer of a request verified under a further
// scheme. It is not an AAuth Agent and carries no person or authorization.
type SignerPrincipal struct {
	// Scheme is the scheme the request was verified under. For a cached proof
	// it is cached; the assertion it resolved to was jkt-jwt.
	Scheme signaturekey.Scheme
	// Signer identifies the signer: the key's JWK Thumbprint URI for hwk, the
	// durable key's for jkt-jwt and cached, the assertion's iss for self-jwt,
	// the id for jwks_uri, the exact url for jwks, and x5u for x509.
	Signer string
	// PublicKey is the key that verified the HTTP Message Signature.
	PublicKey jose.JWK
	// X509 is the verified certificate chain of an x509 proof.
	X509 *signaturekey.X509Identity
}

type signerPrincipalContextKey struct{}

// SignerFromContext returns the signer of a request verified under a further
// scheme. It is absent from AAuth requests.
func SignerFromContext(ctx context.Context) (SignerPrincipal, bool) {
	if ctx == nil {
		return SignerPrincipal{}, false
	}
	principal, ok := ctx.Value(signerPrincipalContextKey{}).(SignerPrincipal)
	if principal.X509 != nil {
		identity := *principal.X509
		principal.X509 = &identity
	}
	return principal, ok
}

type furtherSchemes struct {
	schemes     []signaturekey.Scheme
	algorithms  []string
	selfJWTType string
	jwks        signaturekey.JWKSKeyResolver
	x509        func(context.Context, string) (signaturekey.X509VerifyOptions, error)
	cache       *signaturekey.AssertionCache
	protected   http.Handler
}

func validateFurtherSchemes(config *FurtherSchemesConfig) (*furtherSchemes, error) {
	if config == nil {
		return nil, nil
	}
	if len(config.Schemes) == 0 {
		return nil, errors.New("aauth: Resource further schemes require at least one scheme")
	}
	if config.Protected == nil {
		return nil, errors.New("aauth: Resource further schemes require a protected handler")
	}
	for index, scheme := range config.Schemes {
		switch scheme {
		case signaturekey.SchemeHWK, signaturekey.SchemeJKTJWT, signaturekey.SchemeSelfJWT, signaturekey.SchemeJWKSURI,
			signaturekey.SchemeJWKS, signaturekey.SchemeX509, signaturekey.SchemeCached:
		default:
			return nil, fmt.Errorf("aauth: Resource cannot accept %q as a further scheme", scheme)
		}
		if slices.Contains(config.Schemes[:index], scheme) {
			return nil, fmt.Errorf("aauth: Resource further scheme %q is duplicated", scheme)
		}
	}
	if slices.Contains(config.Schemes, signaturekey.SchemeSelfJWT) != (config.SelfJWTType != "") {
		return nil, errors.New("aauth: Resource self-jwt scheme and its JWT type must be configured together")
	}
	if slices.Contains(config.Schemes, signaturekey.SchemeJWKS) && config.JWKS == nil {
		return nil, errors.New("aauth: Resource jwks scheme requires a JWKS resolver")
	}
	if slices.Contains(config.Schemes, signaturekey.SchemeX509) && config.X509 == nil {
		return nil, errors.New("aauth: Resource x509 scheme requires certificate trust inputs")
	}
	cached := slices.Contains(config.Schemes, signaturekey.SchemeCached)
	if cached != (config.Cache != nil) {
		return nil, errors.New("aauth: Resource assertion cache and the cached scheme must be configured together")
	}
	if cached && !slices.Contains(config.Schemes, signaturekey.SchemeJKTJWT) {
		return nil, errors.New("aauth: Resource cached scheme requires jkt-jwt, the assertion it caches")
	}
	algorithms := jose.TokenAlgorithms()
	for _, algorithm := range config.Algorithms {
		if !slices.Contains(jose.SignatureAlgorithms(), algorithm) {
			return nil, fmt.Errorf("aauth: Resource further-scheme algorithm %q is not supported", algorithm)
		}
		if !slices.Contains(algorithms, algorithm) {
			algorithms = append(algorithms, algorithm)
		}
	}
	return &furtherSchemes{
		schemes:     append([]signaturekey.Scheme(nil), config.Schemes...),
		algorithms:  algorithms,
		selfJWTType: config.SelfJWTType,
		jwks:        config.JWKS,
		x509:        config.X509,
		cache:       config.Cache,
		protected:   config.Protected,
	}, nil
}

// acceptedSchemes lists jwt, the AAuth scheme, before the further schemes.
func (further *furtherSchemes) acceptedSchemes() []signaturekey.Scheme {
	return append([]signaturekey.Scheme{signaturekey.SchemeJWT}, further.schemes...)
}

// prepareProtectedRequest prepares a protected-route request. It returns the
// compact token of an AAuth jwt request, or an empty token for a request
// under a further scheme.
func (server *Server) prepareProtectedRequest(request *http.Request) (signaturekey.PreparedRequest, string, error) {
	if server.furtherSchemes == nil {
		return server.prepareJWTRequest(request, server.additionalSignatureComponents)
	}
	prepared, err := signaturekey.PrepareRequest(request, server.clock, signaturekey.VerifyOptions{
		RequiredComponents: server.additionalSignatureComponents,
		AcceptedSchemes:    server.furtherSchemes.acceptedSchemes(),
		AcceptedAlgorithms: server.furtherSchemes.algorithms,
		MaxBodyBytes:       server.maxSignedBodyBytes,
	})
	if err != nil {
		return signaturekey.PreparedRequest{}, "", err
	}
	compact, _ := prepared.Credential().JWT()
	return prepared, compact, nil
}

// writeAcceptedSchemes states every scheme and algorithm the protected routes
// accept on an unsigned challenge, so a client outside AAuth can choose
// correctly before it signs.
func (server *Server) writeAcceptedSchemes(response http.ResponseWriter) {
	if server.furtherSchemes == nil {
		return
	}
	if header, err := signaturekey.FormatAcceptSchemes(server.furtherSchemes.acceptedSchemes()); err == nil {
		response.Header().Set("Accept-Signature-Scheme", header)
	}
	if header, err := signaturekey.FormatAcceptAlgorithms(server.furtherSchemes.algorithms); err == nil {
		response.Header().Set("Accept-Signature-Alg", header)
	}
}

func (server *Server) serveFurtherScheme(response http.ResponseWriter, request *http.Request, prepared signaturekey.PreparedRequest) {
	further := server.furtherSchemes
	credential := prepared.Credential()
	principal := SignerPrincipal{Scheme: credential.Scheme()}
	var (
		proof signaturekey.VerifiedRequest
		err   error
	)
	switch credential.Scheme() {
	case signaturekey.SchemeHWK:
		key, _ := credential.InlineJWK()
		proof, err = prepared.Verify(key)
		if err == nil {
			principal.Signer = proof.Signer()
		}
	case signaturekey.SchemeJKTJWT:
		var delegation signaturekey.JKTJWTDelegation
		proof, delegation, err = prepared.VerifyJKTJWT()
		if err == nil {
			principal.Signer = delegation.Issuer()
		}
	case signaturekey.SchemeSelfJWT:
		var assertion signaturekey.SelfJWTAssertion
		proof, assertion, err = prepared.VerifySelfJWT(request.Context(), server.keyResolver, further.selfJWTType)
		if err == nil {
			principal.Signer = assertion.Issuer()
		}
	case signaturekey.SchemeJWKSURI:
		proof, err = prepared.VerifyJWKSURI(request.Context(), server.keyResolver)
		if err == nil {
			principal.Signer = proof.Signer()
		}
	case signaturekey.SchemeJWKS:
		proof, err = prepared.VerifyJWKS(request.Context(), further.jwks)
		if err == nil {
			principal.Signer = proof.Signer()
		}
	case signaturekey.SchemeX509:
		certificateURL, _, _ := credential.X509()
		var options signaturekey.X509VerifyOptions
		options, err = further.x509(request.Context(), certificateURL)
		if err != nil {
			writeProblem(response, http.StatusInternalServerError, "server_error", fmt.Errorf("x509 trust inputs: %w", err))
			return
		}
		var identity signaturekey.X509Identity
		proof, identity, err = prepared.VerifyX509(options)
		if err == nil {
			principal.Signer, principal.X509 = identity.URL(), &identity
		}
	case signaturekey.SchemeCached:
		var assertion signaturekey.CachedAssertion
		proof, assertion, err = prepared.VerifyCached(further.cache)
		if err == nil && assertion.Scheme() != signaturekey.SchemeJKTJWT {
			err = signaturekey.NewError(signaturekey.ErrorInvalidJWT, errors.New("aauth: cached assertion was not presented under jkt-jwt"))
		}
		if err == nil {
			principal.Signer = assertion.Issuer()
		}
	default:
		err = signaturekey.NewError(signaturekey.ErrorUnsupportedScheme, fmt.Errorf("aauth: scheme %q is not accepted", credential.Scheme()))
	}
	if err != nil {
		writeProblem(response, http.StatusUnauthorized, "invalid_signature", err)
		return
	}
	principal.PublicKey = proof.PublicKey()
	if further.cache != nil && credential.CacheRequested() {
		grant, issued, err := further.cache.Issue(proof)
		if err != nil {
			writeProblem(response, http.StatusUnauthorized, "invalid_signature", err)
			return
		}
		if issued {
			if field, err := signaturekey.FormatCacheGrants(grant); err == nil {
				response.Header().Set("Signature-Key-Cache", field)
			}
		}
	}
	further.protected.ServeHTTP(response, request.WithContext(context.WithValue(request.Context(), signerPrincipalContextKey{}, principal)))
}
