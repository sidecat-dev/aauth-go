package signaturekey_test

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

const testCertificateURL = "https://client.example/.well-known/cert.pem"

type testAuthority struct {
	certificate *x509.Certificate
	key         crypto.Signer
}

var testSerial atomic.Int64

func nextTestSerial() *big.Int { return big.NewInt(testSerial.Add(1)) }

func newTestAuthority(t *testing.T, name string, parent *testAuthority, now time.Time) testAuthority {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          nextTestSerial(),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	issuer := &testAuthority{certificate: template, key: key}
	if parent != nil {
		issuer = parent
	}
	return testAuthority{certificate: issueTestCertificate(t, template, issuer, key.Public()), key: key}
}

func issueTestCertificate(t *testing.T, template *x509.Certificate, issuer *testAuthority, public crypto.PublicKey) *x509.Certificate {
	t.Helper()
	der, err := x509.CreateCertificate(rand.Reader, template, issuer.certificate, public, issuer.key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return certificate
}

func (authority testAuthority) issueLeaf(t *testing.T, public crypto.PublicKey, now time.Time) *x509.Certificate {
	t.Helper()
	return issueTestCertificate(t, &x509.Certificate{
		SerialNumber: nextTestSerial(),
		Subject:      pkix.Name{CommonName: "client.example"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(12 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}, &authority, public)
}

func (authority testAuthority) revocationList(t *testing.T, nextUpdate time.Time, revoked ...*x509.Certificate) *x509.RevocationList {
	t.Helper()
	entries := make([]x509.RevocationListEntry, 0, len(revoked))
	for _, certificate := range revoked {
		entries = append(entries, x509.RevocationListEntry{SerialNumber: certificate.SerialNumber, RevocationTime: nextUpdate.Add(-2 * time.Hour)})
	}
	der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:                    nextTestSerial(),
		ThisUpdate:                nextUpdate.Add(-2 * time.Hour),
		NextUpdate:                nextUpdate,
		RevokedCertificateEntries: entries,
	}, authority.certificate, authority.key)
	if err != nil {
		t.Fatal(err)
	}
	list, err := x509.ParseRevocationList(der)
	if err != nil {
		t.Fatal(err)
	}
	return list
}

func encodeTestChain(certificates ...*x509.Certificate) []byte {
	var chain bytes.Buffer
	for _, certificate := range certificates {
		_ = pem.Encode(&chain, &pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw})
	}
	return chain.Bytes()
}

func prepareTestX509Request(t *testing.T, key jose.SigningKey, leaf *x509.Certificate, now time.Time, algorithms []string) signaturekey.PreparedRequest {
	t.Helper()
	credential, err := signaturekey.NewX509Credential(testCertificateURL, leaf)
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest(http.MethodGet, "https://resource.example/items", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := signaturekey.SignRequest(request, key, credential, fixedClock(now), signaturekey.SignOptions{}); err != nil {
		t.Fatal(err)
	}
	prepared, err := signaturekey.PrepareRequest(request, fixedClock(now), signaturekey.VerifyOptions{
		AcceptedSchemes:    []signaturekey.Scheme{signaturekey.SchemeX509},
		AcceptedAlgorithms: algorithms,
	})
	if err != nil {
		t.Fatal(err)
	}
	return prepared
}

func TestX509ProofValidatesTheChainAndRevocationBeforeTheSignature(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 10, 30, 14, 0, 0, 0, time.UTC)
	root := newTestAuthority(t, "Test Root", nil, now)
	intermediate := newTestAuthority(t, "Test Intermediate", &root, now)
	for _, algorithm := range []string{jose.Ed25519Algorithm, jose.ES256Algorithm, jose.ES384Algorithm} {
		t.Run(algorithm, func(t *testing.T) {
			key := newTestAlgorithmKey(t, "client-key", algorithm)
			leaf := intermediate.issueLeaf(t, key.Public(), now)
			prepared := prepareTestX509Request(t, key, leaf, now, []string{algorithm})
			if certificateURL, thumbprint, ok := prepared.Credential().X509(); !ok || certificateURL != testCertificateURL ||
				len(thumbprint) != sha256.Size {
				t.Fatalf("X509() = %q, %x, %t", certificateURL, thumbprint, ok)
			}
			if _, err := prepared.Verify(key.PublicJWK()); err == nil {
				t.Fatal("Verify accepted an x509 proof without validating its chain")
			}
			proof, identity, err := prepared.VerifyX509(signaturekey.X509VerifyOptions{
				ChainPEM: encodeTestChain(leaf, intermediate.certificate),
				Roots:    []*x509.Certificate{root.certificate},
				RevocationLists: []*x509.RevocationList{
					intermediate.revocationList(t, now.Add(time.Hour)),
					root.revocationList(t, now.Add(time.Hour)),
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			digest := sha256.Sum256(leaf.Raw)
			if proof.Scheme() != signaturekey.SchemeX509 || proof.PublicKey().Alg != algorithm ||
				!proof.PublicKey().Equal(key.PublicJWK()) || identity.URL() != testCertificateURL ||
				!bytes.Equal(identity.Thumbprint(), digest[:]) || len(identity.Chain()) != 3 ||
				!identity.Certificate().Equal(leaf) {
				t.Fatalf("verified x509 proof = %q %#v, identity %q", proof.Scheme(), proof.PublicKey(), identity.URL())
			}
		})
	}
}

func TestX509ProofRefusesUnprovenCertificates(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 10, 30, 14, 0, 0, 0, time.UTC)
	root := newTestAuthority(t, "Test Root", nil, now)
	otherRoot := newTestAuthority(t, "Other Root", nil, now)
	intermediate := newTestAuthority(t, "Test Intermediate", &root, now)
	key := newTestAlgorithmKey(t, "client-key", jose.ES256Algorithm)
	leaf := intermediate.issueLeaf(t, key.Public(), now)
	otherLeaf := intermediate.issueLeaf(t, key.Public(), now)
	current := []*x509.RevocationList{
		intermediate.revocationList(t, now.Add(time.Hour)),
		root.revocationList(t, now.Add(time.Hour)),
	}
	valid := signaturekey.X509VerifyOptions{
		ChainPEM:        encodeTestChain(leaf, intermediate.certificate),
		Roots:           []*x509.Certificate{root.certificate},
		RevocationLists: current,
	}
	with := func(change func(*signaturekey.X509VerifyOptions)) signaturekey.X509VerifyOptions {
		options := valid
		change(&options)
		return options
	}
	tests := []struct {
		name    string
		leaf    *x509.Certificate
		options signaturekey.X509VerifyOptions
	}{
		{name: "untrusted root", leaf: leaf, options: with(func(options *signaturekey.X509VerifyOptions) {
			options.Roots = []*x509.Certificate{otherRoot.certificate}
		})},
		{name: "no trust anchor", leaf: leaf, options: with(func(options *signaturekey.X509VerifyOptions) { options.Roots = nil })},
		{name: "no revocation lists", leaf: leaf, options: with(func(options *signaturekey.X509VerifyOptions) { options.RevocationLists = nil })},
		{name: "intermediate not covered", leaf: leaf, options: with(func(options *signaturekey.X509VerifyOptions) {
			options.RevocationLists = current[:1]
		})},
		{name: "end entity revoked", leaf: leaf, options: with(func(options *signaturekey.X509VerifyOptions) {
			options.RevocationLists = []*x509.RevocationList{intermediate.revocationList(t, now.Add(time.Hour), leaf), current[1]}
		})},
		{name: "intermediate revoked", leaf: leaf, options: with(func(options *signaturekey.X509VerifyOptions) {
			options.RevocationLists = []*x509.RevocationList{current[0], root.revocationList(t, now.Add(time.Hour), intermediate.certificate)}
		})},
		{name: "revocation list past nextUpdate", leaf: leaf, options: with(func(options *signaturekey.X509VerifyOptions) {
			options.RevocationLists = []*x509.RevocationList{intermediate.revocationList(t, now), current[1]}
		})},
		{name: "x5t names another certificate", leaf: otherLeaf, options: valid},
		{name: "content outside PEM blocks", leaf: leaf, options: with(func(options *signaturekey.X509VerifyOptions) {
			options.ChainPEM = append([]byte("leaf:\n"), options.ChainPEM...)
		})},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			prepared := prepareTestX509Request(t, key, test.leaf, now, []string{jose.ES256Algorithm})
			_, _, err := prepared.VerifyX509(test.options)
			assertSignatureErrorCode(t, err, signaturekey.ErrorInvalidKey)
		})
	}
}

func TestX509KeySelectsExactlyOneAcceptedAlgorithm(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 10, 30, 14, 0, 0, 0, time.UTC)
	root := newTestAuthority(t, "Test Root", nil, now)
	verify := func(key jose.SigningKey, algorithms []string) error {
		leaf := root.issueLeaf(t, key.Public(), now)
		prepared := prepareTestX509Request(t, key, leaf, now, algorithms)
		_, _, err := prepared.VerifyX509(signaturekey.X509VerifyOptions{
			ChainPEM:        encodeTestChain(leaf),
			Roots:           []*x509.Certificate{root.certificate},
			RevocationLists: []*x509.RevocationList{root.revocationList(t, now.Add(time.Hour))},
		})
		return err
	}

	// rsaEncryption names neither padding nor hash, so no algorithm is chosen
	// for it even when the endpoint accepts both RSA algorithms.
	rsaKey := newTestAlgorithmKey(t, "client-key", jose.PS256Algorithm)
	err := verify(rsaKey, jose.SignatureAlgorithms())
	assertSignatureErrorCode(t, err, signaturekey.ErrorUnsupportedAlgorithm)

	err = verify(newTestAlgorithmKey(t, "client-key", jose.ES384Algorithm), nil)
	assertSignatureErrorCode(t, err, signaturekey.ErrorUnsupportedAlgorithm)
	var failure *signaturekey.Error
	if errors.As(err, &failure); !reflect.DeepEqual(failure.AcceptedAlgorithms, jose.TokenAlgorithms()) {
		t.Fatalf("accepted algorithms = %v, want the endpoint default", failure.AcceptedAlgorithms)
	}
}
