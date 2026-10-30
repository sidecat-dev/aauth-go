package signaturekey

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	"gitlab.com/sidecat-dev/aauth-go/jose"
)

// X509VerifyOptions is the material the host supplies for one x509 member.
// This package does not fetch x5u: the host fetches that exact URL after its
// own egress admission, and fetches the certificate revocation lists (CRLs)
// for the chain.
type X509VerifyOptions struct {
	// ChainPEM is the PEM certificate chain fetched from x5u. The first
	// certificate is the end entity and any others are intermediates. Only
	// CERTIFICATE blocks are accepted.
	ChainPEM []byte
	// Roots are the trust anchors the host accepts. At least one is required.
	Roots []*x509.Certificate
	// RevocationLists are the current CRLs for the chain, one from the issuer
	// of the end entity and one from the issuer of each intermediate. The
	// first list whose issuer matches a certificate's issuer is the one
	// checked for it.
	RevocationLists []*x509.RevocationList
}

// X509Identity is the certificate chain that verified one x509 proof. Its
// accessors return independent copies.
type X509Identity struct {
	url        string
	thumbprint []byte
	chain      []*x509.Certificate
}

// URL returns x5u as presented. It was neither canonicalized nor fetched by
// this package.
func (identity X509Identity) URL() string { return identity.url }

// Thumbprint returns the SHA-256 of the end-entity certificate's DER
// encoding, which equals x5t.
func (identity X509Identity) Thumbprint() []byte {
	return append([]byte(nil), identity.thumbprint...)
}

// Certificate returns an independent parse of the end-entity certificate.
func (identity X509Identity) Certificate() *x509.Certificate {
	chain := identity.Chain()
	if len(chain) == 0 {
		return nil
	}
	return chain[0]
}

// Chain returns independent parses of the verified path, from the end
// entity to the trust anchor.
func (identity X509Identity) Chain() []*x509.Certificate {
	chain := make([]*x509.Certificate, 0, len(identity.chain))
	for _, certificate := range identity.chain {
		copied, err := x509.ParseCertificate(certificate.Raw)
		if err != nil {
			return nil
		}
		chain = append(chain, copied)
	}
	return chain
}

var (
	deltaCRLIndicator         = asn1.ObjectIdentifier{2, 5, 29, 27}
	issuingDistributionPoint  = asn1.ObjectIdentifier{2, 5, 29, 28}
	errX509RevocationUnproven = errors.New("aauth: x509 certificate revocation status is not established")
)

// VerifyX509 validates the host-supplied certificate chain for this
// request's x509 member and then verifies the HTTP Message Signature with
// the end-entity key.
//
// The chain is always validated, and validation runs before the thumbprint
// comparison and the signature: the end entity must chain to one of Roots at
// the verification time, for any extended key usage. Revocation is then
// checked for the end entity and every intermediate. Each must be covered by
// a CRL that its issuer signed, that is current at the verification time,
// and that does not list it. A certificate that a CRL lists, or that no
// usable CRL covers, is refused. Delta CRLs, CRLs scoped by an issuing
// distribution point, and CRLs with other critical extensions are not used.
// OCSP is not supported.
//
// The end-entity public key selects exactly one algorithm: Ed25519, P-256 as
// ES256, or P-384 as ES384. An RSA subject public key names neither padding
// nor hash, so an RSA certificate is unsupported_algorithm rather than a
// polymorphic choice. The selected algorithm must also be one of the
// endpoint's AcceptedAlgorithms.
//
// Unusable PEM, roots, or CRLs, a chain or revocation failure, and an x5t
// that is not the SHA-256 of the end-entity DER are invalid_key. A signature
// that does not verify is invalid_signature.
func (prepared PreparedRequest) VerifyX509(options X509VerifyOptions) (VerifiedRequest, X509Identity, error) {
	var identity X509Identity
	certificateURL, thumbprint, ok := prepared.credential.X509()
	if !ok {
		return VerifiedRequest{}, identity, errors.New("aauth: prepared request does not use x509")
	}
	invalidKey := func(cause error) error { return &Error{Code: ErrorInvalidKey, Cause: cause} }
	certificates, err := parseCertificateChainPEM(options.ChainPEM)
	if err != nil {
		return VerifiedRequest{}, identity, invalidKey(err)
	}
	if len(options.Roots) == 0 {
		return VerifiedRequest{}, identity, invalidKey(errors.New("aauth: x509 verification requires at least one trust anchor"))
	}
	roots := x509.NewCertPool()
	for _, root := range options.Roots {
		if root == nil {
			return VerifiedRequest{}, identity, invalidKey(errors.New("aauth: x509 trust anchor is missing"))
		}
		roots.AddCert(root)
	}
	for _, list := range options.RevocationLists {
		if list == nil {
			return VerifiedRequest{}, identity, invalidKey(errors.New("aauth: x509 revocation list is missing"))
		}
	}
	intermediates := x509.NewCertPool()
	for _, certificate := range certificates[1:] {
		intermediates.AddCert(certificate)
	}
	chains, err := certificates[0].Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   prepared.verifiedAt,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	if err != nil {
		return VerifiedRequest{}, identity, invalidKey(fmt.Errorf("aauth: x509 chain: %w", err))
	}
	var verifiedChain []*x509.Certificate
	revocationErr := errX509RevocationUnproven
	for _, chain := range chains {
		if revocationErr = checkChainRevocation(chain, options.RevocationLists, prepared.verifiedAt); revocationErr == nil {
			verifiedChain = chain
			break
		}
	}
	if verifiedChain == nil {
		return VerifiedRequest{}, identity, invalidKey(revocationErr)
	}
	digest := sha256.Sum256(certificates[0].Raw)
	if !bytes.Equal(digest[:], thumbprint) {
		return VerifiedRequest{}, identity, invalidKey(errors.New("aauth: x509 x5t does not match the end-entity certificate"))
	}
	key, err := certificateKey(certificates[0])
	if err != nil {
		var failure *Error
		if errors.As(err, &failure) && failure.Code == ErrorUnsupportedAlgorithm {
			return VerifiedRequest{}, identity, unsupportedAlgorithm(prepared.algorithms, failure.Cause)
		}
		return VerifiedRequest{}, identity, err
	}
	proof, err := prepared.verifyWithKey(key)
	if err != nil {
		return VerifiedRequest{}, identity, err
	}
	identity = X509Identity{url: certificateURL, thumbprint: digest[:], chain: verifiedChain}
	return proof, identity, nil
}

// parseCertificateChainPEM accepts only CERTIFICATE blocks without headers,
// separated by whitespace, and at least one of them.
func parseCertificateChainPEM(data []byte) ([]*x509.Certificate, error) {
	var certificates []*x509.Certificate
	rest := data
	for {
		rest = bytes.TrimLeft(rest, " \t\r\n")
		if len(rest) == 0 {
			break
		}
		if !bytes.HasPrefix(rest, []byte("-----BEGIN ")) {
			return nil, errors.New("aauth: x509 chain contains content outside PEM blocks")
		}
		block, remainder := pem.Decode(rest)
		if block == nil {
			return nil, errors.New("aauth: x509 chain contains a malformed PEM block")
		}
		if block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return nil, fmt.Errorf("aauth: x509 chain contains a %q PEM block", block.Type)
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("aauth: x509 chain certificate: %w", err)
		}
		certificates = append(certificates, certificate)
		rest = remainder
	}
	if len(certificates) == 0 {
		return nil, errors.New("aauth: x509 chain contains no certificate")
	}
	return certificates, nil
}

// checkChainRevocation requires a current, issuer-signed CRL for every
// certificate in chain except the trust anchor, and that none lists it.
func checkChainRevocation(chain []*x509.Certificate, lists []*x509.RevocationList, now time.Time) error {
	for index := 0; index+1 < len(chain); index++ {
		certificate, issuer := chain[index], chain[index+1]
		var list *x509.RevocationList
		for _, candidate := range lists {
			if bytes.Equal(candidate.RawIssuer, certificate.RawIssuer) {
				list = candidate
				break
			}
		}
		if list == nil {
			return fmt.Errorf("%w: no revocation list covers %q", errX509RevocationUnproven, certificate.Subject)
		}
		if err := checkRevocationList(list, issuer, now); err != nil {
			return fmt.Errorf("%w: revocation list for %q: %v", errX509RevocationUnproven, certificate.Subject, err)
		}
		for _, entry := range list.RevokedCertificateEntries {
			if entry.SerialNumber != nil && entry.SerialNumber.Cmp(certificate.SerialNumber) == 0 {
				return fmt.Errorf("aauth: x509 certificate %q is revoked", certificate.Subject)
			}
		}
	}
	return nil
}

func checkRevocationList(list *x509.RevocationList, issuer *x509.Certificate, now time.Time) error {
	if err := list.CheckSignatureFrom(issuer); err != nil {
		return fmt.Errorf("signature: %w", err)
	}
	if now.Before(list.ThisUpdate) {
		return errors.New("list is not yet valid")
	}
	if list.NextUpdate.IsZero() || !now.Before(list.NextUpdate) {
		return errors.New("list is past its nextUpdate")
	}
	for _, extension := range list.Extensions {
		switch {
		case extension.Id.Equal(deltaCRLIndicator):
			return errors.New("delta revocation lists are not supported")
		case extension.Id.Equal(issuingDistributionPoint):
			return errors.New("revocation lists scoped by an issuing distribution point are not supported")
		case extension.Critical:
			return fmt.Errorf("unsupported critical extension %s", extension.Id)
		}
	}
	for _, entry := range list.RevokedCertificateEntries {
		for _, extension := range entry.Extensions {
			if extension.Critical {
				return fmt.Errorf("unsupported critical entry extension %s", extension.Id)
			}
		}
	}
	return nil
}

// certificateKey selects the single algorithm an end-entity public key
// determines and returns it as a JWK.
func certificateKey(certificate *x509.Certificate) (jose.JWK, error) {
	unsupported := func(cause error) error { return &Error{Code: ErrorUnsupportedAlgorithm, Cause: cause} }
	encode := base64.RawURLEncoding.EncodeToString
	switch publicKey := certificate.PublicKey.(type) {
	case ed25519.PublicKey:
		return jose.JWK{Kty: "OKP", Crv: "Ed25519", X: encode(publicKey), Alg: jose.Ed25519Algorithm}, nil
	case *ecdsa.PublicKey:
		var curveName, algorithm string
		switch publicKey.Curve {
		case elliptic.P256():
			curveName, algorithm = "P-256", jose.ES256Algorithm
		case elliptic.P384():
			curveName, algorithm = "P-384", jose.ES384Algorithm
		default:
			return jose.JWK{}, unsupported(fmt.Errorf("aauth: x509 ECDSA curve %s is not supported", publicKey.Curve.Params().Name))
		}
		point, err := publicKey.Bytes()
		if err != nil {
			return jose.JWK{}, &Error{Code: ErrorInvalidKey, Cause: err}
		}
		size := (len(point) - 1) / 2
		return jose.JWK{
			Kty: "EC", Crv: curveName, Alg: algorithm,
			X: encode(point[1 : 1+size]), Y: encode(point[1+size:]),
		}, nil
	case *rsa.PublicKey:
		return jose.JWK{}, unsupported(errors.New("aauth: an x509 RSA key names neither padding nor hash"))
	}
	return jose.JWK{}, unsupported(fmt.Errorf("aauth: x509 public key algorithm %s is not supported", certificate.PublicKeyAlgorithm))
}
