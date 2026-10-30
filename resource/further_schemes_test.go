package resource

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

func furtherSchemeKey(t *testing.T, id, algorithm string) jose.SigningKey {
	t.Helper()
	var signer crypto.Signer
	var err error
	switch algorithm {
	case jose.Ed25519Algorithm:
		_, signer, err = ed25519.GenerateKey(rand.Reader)
	case jose.ES384Algorithm:
		signer, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	default:
		signer, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	}
	if err != nil {
		t.Fatal(err)
	}
	key, err := jose.NewSigningKeyForAlgorithm(id, algorithm, signer)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func furtherSchemeCertificate(t *testing.T, public crypto.PublicKey, now time.Time) (*x509.Certificate, *x509.Certificate, *x509.RevocationList) {
	t.Helper()
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rootTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Client Root"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, rootKey.Public(), rootKey)
	if err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "client.example"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(12 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}, root, public, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}
	listDER, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number: big.NewInt(3), ThisUpdate: now.Add(-time.Hour), NextUpdate: now.Add(time.Hour),
	}, root, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	list, err := x509.ParseRevocationList(listDER)
	if err != nil {
		t.Fatal(err)
	}
	return root, leaf, list
}

// Signature-Key Scheme Rejection: a Resource that also serves clients outside
// AAuth may accept further schemes and must then list all of them. Their
// requests reach their own handler with the verified signer; AAuth requests
// are unchanged.
func TestResourceAcceptsFurtherSchemesForClientsOutsideAAuth(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 10, 30, 17, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	providerKey := furtherSchemeKey(t, "provider", jose.Ed25519Algorithm)
	agentKey := furtherSchemeKey(t, "agent", jose.Ed25519Algorithm)
	clientKey := furtherSchemeKey(t, "client-ec", jose.ES256Algorithm)
	// Keys found through a JWKS keep the Ed25519 profile.
	keySetKey := furtherSchemeKey(t, "client-jwks", jose.Ed25519Algorithm)
	durableKey := furtherSchemeKey(t, "client-durable", jose.Ed25519Algorithm)
	ephemeralKey := furtherSchemeKey(t, "client-ephemeral", jose.Ed25519Algorithm)
	root, leaf, crl := furtherSchemeCertificate(t, clientKey.Public(), now)
	const keySetURL = "https://client.example/keys.json"
	const certificateURL = "https://client.example/cert.pem"
	cache, err := signaturekey.NewAssertionCache(signaturekey.AssertionCacheConfig{Key: bytes.Repeat([]byte{7}, 32)})
	if err != nil {
		t.Fatal(err)
	}

	var signers []SignerPrincipal
	aauthCalls := 0
	config := AgentIdentityConfig{
		Issuer: "https://resource.example",
		KeyResolver: signaturekey.StaticKeyResolver{
			{Issuer: "https://ap.example", DiscoveryDocument: aauth.AgentDiscoveryDocument, KeyID: providerKey.ID()}: providerKey.PublicJWK(),
		},
		Clock: clock,
		Protected: http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			aauthCalls++
			if _, ok := SignerFromContext(request.Context()); ok {
				t.Error("an AAuth request carried a further-scheme signer")
			}
			if _, ok := AgentPrincipalFromContext(request.Context()); !ok {
				t.Error("an AAuth request carried no Agent principal")
			}
		}),
		FurtherSchemes: &FurtherSchemesConfig{
			Schemes: []signaturekey.Scheme{
				signaturekey.SchemeHWK, signaturekey.SchemeJKTJWT, signaturekey.SchemeJWKS,
				signaturekey.SchemeX509, signaturekey.SchemeCached,
			},
			Algorithms: []string{jose.ES256Algorithm},
			JWKS: signaturekey.StaticJWKSResolver{
				{URL: keySetURL, KeyID: keySetKey.ID()}: keySetKey.PublicJWK(),
			},
			X509: func(_ context.Context, url string) (signaturekey.X509VerifyOptions, error) {
				if url != certificateURL {
					return signaturekey.X509VerifyOptions{}, errors.New("unexpected x5u")
				}
				return signaturekey.X509VerifyOptions{
					ChainPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw}),
					Roots:    []*x509.Certificate{root}, RevocationLists: []*x509.RevocationList{crl},
				}, nil
			},
			Cache: cache,
			Protected: http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
				signer, ok := SignerFromContext(request.Context())
				if !ok {
					t.Error("a further-scheme request carried no signer")
				}
				if _, ok := AgentPrincipalFromContext(request.Context()); ok {
					t.Error("a further-scheme request carried an Agent principal")
				}
				signers = append(signers, signer)
			}),
		},
	}
	server, err := NewAgentIdentity(config)
	if err != nil {
		t.Fatal(err)
	}
	send := func(key jose.SigningKey, credential signaturekey.Credential) *httptest.ResponseRecorder {
		t.Helper()
		request := httptest.NewRequest(http.MethodGet, "https://resource.example/items", nil)
		if err := signaturekey.SignRequest(request, key, credential, clock, signaturekey.SignOptions{}); err != nil {
			t.Fatal(err)
		}
		response := httptest.NewRecorder()
		server.Handler().ServeHTTP(response, request)
		return response
	}
	const listed = "jwt, hwk, jkt-jwt, jwks, x509, cached"

	challenge := httptest.NewRecorder()
	server.Handler().ServeHTTP(challenge, httptest.NewRequest(http.MethodGet, "https://resource.example/items", nil))
	if challenge.Code != http.StatusUnauthorized || challenge.Header().Get("AAuth-Requirement") != "requirement=agent-token" ||
		challenge.Header().Get("Accept-Signature-Scheme") != listed || challenge.Header().Get("Accept-Signature-Alg") != "Ed25519, ES256" {
		t.Fatalf("unsigned challenge = %d %v", challenge.Code, challenge.Header())
	}

	hwk, err := signaturekey.NewHWKCredential(clientKey.PublicJWK())
	if err != nil {
		t.Fatal(err)
	}
	if response := send(clientKey, hwk); response.Code != http.StatusOK {
		t.Fatalf("hwk = %d %v", response.Code, response.Header())
	}
	jwks, err := signaturekey.NewJWKSCredential(keySetURL, keySetKey.ID())
	if err != nil {
		t.Fatal(err)
	}
	if response := send(keySetKey, jwks); response.Code != http.StatusOK {
		t.Fatalf("jwks = %d %v", response.Code, response.Header())
	}
	certificate, err := signaturekey.NewX509Credential(certificateURL, leaf)
	if err != nil {
		t.Fatal(err)
	}
	if response := send(clientKey, certificate); response.Code != http.StatusOK {
		t.Fatalf("x509 = %d %v", response.Code, response.Header())
	}
	delegation, err := signaturekey.MintJKTJWT(durableKey, ephemeralKey.PublicJWK(), now, now.Add(time.Hour), "delegation-1")
	if err != nil {
		t.Fatal(err)
	}
	chained, err := signaturekey.NewJKTJWTCredential(delegation)
	if err != nil {
		t.Fatal(err)
	}
	chained, err = chained.WithCache()
	if err != nil {
		t.Fatal(err)
	}
	cachedResponse := send(ephemeralKey, chained)
	grants, err := signaturekey.ParseCacheGrants(cachedResponse.Header().Values("Signature-Key-Cache"))
	if cachedResponse.Code != http.StatusOK || err != nil || len(grants) != 1 {
		t.Fatalf("jkt-jwt with cache = %d %v, %v", cachedResponse.Code, cachedResponse.Header(), err)
	}
	reference, err := signaturekey.NewCachedCredential(grants[0])
	if err != nil {
		t.Fatal(err)
	}
	if response := send(ephemeralKey, reference); response.Code != http.StatusOK {
		t.Fatalf("cached = %d %v", response.Code, response.Header())
	}
	thumbprintURI := func(key jose.SigningKey) string {
		uri, err := key.PublicJWK().ThumbprintURI()
		if err != nil {
			t.Fatal(err)
		}
		return uri
	}
	want := []SignerPrincipal{
		{Scheme: signaturekey.SchemeHWK, Signer: thumbprintURI(clientKey)},
		{Scheme: signaturekey.SchemeJWKS, Signer: keySetURL},
		{Scheme: signaturekey.SchemeX509, Signer: certificateURL},
		{Scheme: signaturekey.SchemeJKTJWT, Signer: thumbprintURI(durableKey)},
		{Scheme: signaturekey.SchemeCached, Signer: thumbprintURI(durableKey)},
	}
	if len(signers) != len(want) {
		t.Fatalf("further-scheme signers = %#v", signers)
	}
	for index, signer := range signers {
		if signer.Scheme != want[index].Scheme || signer.Signer != want[index].Signer {
			t.Fatalf("signer %d = %q %q, want %q %q", index, signer.Scheme, signer.Signer, want[index].Scheme, want[index].Signer)
		}
		if (signer.Scheme == signaturekey.SchemeX509) != (signer.X509 != nil) {
			t.Fatalf("signer %d x509 identity = %v", index, signer.X509)
		}
	}

	// An AAuth Agent still presents the jwt scheme and reaches the AAuth handler.
	agentToken, err := aauth.MintAgentToken("https://ap.example", providerKey, aauth.AgentTokenRequest{
		Agent: "aauth:reader@ap.example", PublicKey: agentKey.PublicJWK(), Lifetime: time.Hour,
	}, now, "agent-token")
	if err != nil {
		t.Fatal(err)
	}
	agentCredential, err := signaturekey.NewJWTCredential(agentToken)
	if err != nil {
		t.Fatal(err)
	}
	if response := send(agentKey, agentCredential); response.Code != http.StatusOK || aauthCalls != 1 {
		t.Fatalf("AAuth request = %d, AAuth handler calls %d", response.Code, aauthCalls)
	}

	// What is not accepted is refused with the full lists.
	selfJWT, err := signaturekey.NewSelfJWTCredential(agentToken)
	if err != nil {
		t.Fatal(err)
	}
	refused := send(agentKey, selfJWT)
	if refused.Code != http.StatusUnauthorized || refused.Header().Get("Signature-Error") != "error=unsupported_scheme" ||
		refused.Header().Get("Accept-Signature-Scheme") != listed {
		t.Fatalf("self-jwt = %d %v", refused.Code, refused.Header())
	}
	unlisted := furtherSchemeKey(t, "client-p384", jose.ES384Algorithm)
	unlistedCredential, err := signaturekey.NewHWKCredential(unlisted.PublicJWK())
	if err != nil {
		t.Fatal(err)
	}
	refused = send(unlisted, unlistedCredential)
	if refused.Code != http.StatusUnauthorized || refused.Header().Get("Signature-Error") != "error=unsupported_algorithm" ||
		refused.Header().Get("Accept-Signature-Alg") != "Ed25519, ES256" {
		t.Fatalf("hwk ES384 = %d %v", refused.Code, refused.Header())
	}

	for _, invalid := range []FurtherSchemesConfig{
		{Schemes: []signaturekey.Scheme{signaturekey.SchemeJWT}, Protected: http.NotFoundHandler()},
		{Schemes: []signaturekey.Scheme{signaturekey.SchemeHWK, signaturekey.SchemeHWK}, Protected: http.NotFoundHandler()},
		{Schemes: []signaturekey.Scheme{signaturekey.SchemeJWKS}, Protected: http.NotFoundHandler()},
		{Schemes: []signaturekey.Scheme{signaturekey.SchemeX509}, Protected: http.NotFoundHandler()},
		{Schemes: []signaturekey.Scheme{signaturekey.SchemeCached, signaturekey.SchemeJKTJWT}, Protected: http.NotFoundHandler()},
		{Schemes: []signaturekey.Scheme{signaturekey.SchemeCached}, Cache: cache, Protected: http.NotFoundHandler()},
		{Schemes: []signaturekey.Scheme{signaturekey.SchemeJKTJWT}, Cache: cache, Protected: http.NotFoundHandler()},
		{Schemes: []signaturekey.Scheme{signaturekey.SchemeHWK}},
		{Schemes: []signaturekey.Scheme{signaturekey.SchemeHWK}, Algorithms: []string{"HS256"}, Protected: http.NotFoundHandler()},
	} {
		invalid := invalid
		config.FurtherSchemes = &invalid
		if _, err := NewAgentIdentity(config); err == nil {
			t.Fatalf("further schemes %#v were accepted", invalid)
		}
	}
}
