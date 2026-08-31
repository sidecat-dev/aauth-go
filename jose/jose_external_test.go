package jose_test

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"strings"
	"testing"
	"time"

	aauth "aauth-go"
	"aauth-go/jose"
)

func TestJWKJSONRejectsPrivateAndSecretMembers(t *testing.T) {
	t.Parallel()
	for _, member := range []string{"d", "D", "k", "p", "q", "dp", "dq", "qi", "oth"} {
		member := member
		t.Run(member, func(t *testing.T) {
			encoded := `{"kty":"OKP","crv":"Ed25519","alg":"Ed25519",` +
				`"x":"A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg",` +
				`"` + member + `":"private"}`
			var key jose.JWK
			if err := json.Unmarshal([]byte(encoded), &key); err == nil {
				t.Fatalf("accepted private JWK member %q", member)
			}
		})
	}
}

type unsupportedSigner struct{}

func (unsupportedSigner) Public() crypto.PublicKey { return []byte("unsupported") }

func (unsupportedSigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	return nil, nil
}

func TestSigningKeyUsesCallerOwnedSignerAndExactJWK(t *testing.T) {
	t.Parallel()

	key := fixedSigningKey(t, "issuer-key", 0)
	var signer crypto.Signer = key
	if signer.Public() == nil {
		t.Fatal("crypto.Signer returned no public key")
	}
	want := jose.JWK{
		Kty: "OKP",
		Crv: "Ed25519",
		X:   "A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg",
		Alg: jose.Ed25519Algorithm,
		Kid: "issuer-key",
		Use: "sig",
	}
	if got := key.PublicJWK(); got != want {
		t.Fatalf("PublicJWK() = %#v, want %#v", got, want)
	}
	if thumbprint, err := want.Thumbprint(); err != nil || thumbprint != "1IG2tMH7J2wbJZnOf8LJzQitKf7LMvoAElsuDMVM54Y" {
		t.Fatalf("Thumbprint() = %q, %v", thumbprint, err)
	}
	if uri, err := want.ThumbprintURI(); err != nil || uri != "urn:jkt:sha-256:1IG2tMH7J2wbJZnOf8LJzQitKf7LMvoAElsuDMVM54Y" {
		t.Fatalf("ThumbprintURI() = %q, %v", uri, err)
	}
	noncanonical := want
	noncanonical.X = withNonzeroTrailingPadBits(t, noncanonical.X)
	if _, err := noncanonical.PublicKey(); err == nil {
		t.Fatal("PublicKey accepted noncanonical base64url trailing pad bits")
	}
	for name, separator := range map[string]string{"carriage return": "\r", "line feed": "\n"} {
		noncanonical = want
		noncanonical.X = noncanonical.X[:8] + separator + noncanonical.X[8:]
		if _, err := noncanonical.PublicKey(); err == nil {
			t.Fatalf("PublicKey accepted base64url containing %s", name)
		}
	}

	publicCopy := signer.Public().(ed25519.PublicKey)
	publicCopy[0] ^= 0xff
	if got := key.PublicJWK(); got != want {
		t.Fatalf("mutating Public() changed PublicJWK() to %#v", got)
	}
	publicJWKCopy := key.PublicJWK()
	publicJWKCopy.X = "mutated"
	if got := key.PublicJWK(); got != want {
		t.Fatalf("mutating PublicJWK() changed later value to %#v", got)
	}
}

func TestSigningKeyRefusesUnsupportedOrUninitializedUse(t *testing.T) {
	t.Parallel()

	if _, err := jose.NewSigningKey("key", nil); err == nil {
		t.Fatal("accepted nil crypto signer")
	}
	if _, err := jose.NewSigningKey("", unsupportedSigner{}); err == nil {
		t.Fatal("accepted empty key id")
	}
	if _, err := jose.NewSigningKey("key", unsupportedSigner{}); err == nil {
		t.Fatal("accepted signer without an Ed25519 public key")
	}
	if _, err := jose.NewEd25519SigningKey("key", ed25519.PrivateKey("short")); err == nil {
		t.Fatal("accepted a short Ed25519 private key")
	}
	if _, err := (jose.SigningKey{}).Sign(rand.Reader, []byte("message"), crypto.Hash(0)); err == nil {
		t.Fatal("zero SigningKey signed a message")
	}
	key := fixedSigningKey(t, "key", 0)
	if _, err := key.Sign(rand.Reader, []byte("digest"), crypto.SHA256); err == nil {
		t.Fatal("Ed25519 SigningKey accepted pre-hashed input")
	}
	if _, err := key.Sign(
		rand.Reader,
		[]byte("message"),
		&ed25519.Options{Context: "not-the-JOSE-Ed25519-operation"},
	); err == nil {
		t.Fatal("Ed25519 SigningKey accepted an Ed25519ctx operation")
	}
}

func TestCompactVerificationIsCopySafe(t *testing.T) {
	t.Parallel()

	key := fixedSigningKey(t, "issuer-key", 0)
	payload := []byte(`{"iss":"https://issuer.example","sub":"person-1"}`)
	header := jose.Header{Algorithm: jose.Ed25519Algorithm, Type: "example+jwt", KeyID: key.ID()}
	compact, err := jose.SignCompact(key, header, payload)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := jose.ParseCompact(compact)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Header() != header || parsed.Compact() != compact || string(parsed.Payload()) != string(payload) {
		t.Fatalf("parsed compact changed header, compact, or payload")
	}
	protected := parsed.Protected()
	if len(protected) == 0 {
		t.Fatal("ParsedCompact.Protected returned no protected JSON")
	}
	protected[0] = '['
	if second := parsed.Protected(); len(second) == 0 || second[0] != '{' {
		t.Fatal("ParsedCompact.Protected exposed mutable backing storage")
	}
	parsedPayload := parsed.Payload()
	parsedPayload[0] = '['
	if string(parsed.Payload()) != string(payload) {
		t.Fatal("ParsedCompact.Payload exposed mutable backing storage")
	}

	verified, err := parsed.Verify(key.PublicJWK())
	if err != nil {
		t.Fatal(err)
	}
	verifiedHeader, err := verified.Header()
	if err != nil || verifiedHeader != header {
		t.Fatalf("Header() = %#v, %v", verifiedHeader, err)
	}
	verifiedPayload, err := verified.Payload()
	if err != nil || string(verifiedPayload) != string(payload) {
		t.Fatalf("Payload() = %q, %v", verifiedPayload, err)
	}
	verifiedCompact, err := verified.Compact()
	if err != nil || verifiedCompact != compact {
		t.Fatalf("Compact() = %q, %v", verifiedCompact, err)
	}
	verifiedBytes, err := verified.CompactBytes()
	if err != nil || string(verifiedBytes) != compact {
		t.Fatalf("CompactBytes() = %q, %v", verifiedBytes, err)
	}
	verificationKey, err := verified.VerificationKey()
	if err != nil || !verificationKey.Equal(key.PublicJWK()) {
		t.Fatalf("VerificationKey() = %#v, %v", verificationKey, err)
	}

	verifiedHeader.Type = "mutated"
	verifiedPayload[0] = '['
	verifiedBytes[0] = 'x'
	verificationKey.X = "mutated"
	secondHeader, headerErr := verified.Header()
	secondPayload, payloadErr := verified.Payload()
	secondCompact, compactErr := verified.Compact()
	secondKey, keyErr := verified.VerificationKey()
	if headerErr != nil || payloadErr != nil || compactErr != nil || keyErr != nil ||
		secondHeader != header || string(secondPayload) != string(payload) || secondCompact != compact ||
		!secondKey.Equal(key.PublicJWK()) {
		t.Fatal("mutating verified accessors changed the verified value")
	}

	var zero jose.VerifiedCompact
	if _, err := zero.Header(); err == nil {
		t.Fatal("zero VerifiedCompact returned a header")
	}
	if _, err := zero.Payload(); err == nil {
		t.Fatal("zero VerifiedCompact returned a payload")
	}
	if _, err := zero.Compact(); err == nil {
		t.Fatal("zero VerifiedCompact returned a compact value")
	}
	if _, err := zero.CompactBytes(); err == nil {
		t.Fatal("zero VerifiedCompact returned compact bytes")
	}
	if _, err := zero.VerificationKey(); err == nil {
		t.Fatal("zero VerifiedCompact returned a verification key")
	}
}

func TestCompactRefusesAmbiguityMalformedInputAndInvalidVerification(t *testing.T) {
	t.Parallel()

	key := fixedSigningKey(t, "issuer-key", 0)
	other := fixedSigningKey(t, "other-key", 64)
	validHeader := `{"alg":"Ed25519","typ":"example+jwt","kid":"issuer-key"}`
	validPayload := `{"sub":"person-1"}`
	noncanonicalSignature := rawCompact(t, key, validHeader, validPayload)
	noncanonicalParts := strings.Split(noncanonicalSignature, ".")
	noncanonicalParts[2] = withNonzeroTrailingPadBits(t, noncanonicalParts[2])
	noncanonicalSignature = strings.Join(noncanonicalParts, ".")
	carriageReturnSignature := rawCompact(t, key, validHeader, validPayload)
	carriageReturnParts := strings.Split(carriageReturnSignature, ".")
	carriageReturnParts[2] = carriageReturnParts[2][:8] + "\r" + carriageReturnParts[2][8:]
	carriageReturnSignature = strings.Join(carriageReturnParts, ".")
	lineFeedSignature := rawCompact(t, key, validHeader, validPayload)
	lineFeedParts := strings.Split(lineFeedSignature, ".")
	lineFeedParts[2] = lineFeedParts[2][:8] + "\n" + lineFeedParts[2][8:]
	lineFeedSignature = strings.Join(lineFeedParts, ".")

	for _, test := range []struct {
		name    string
		compact string
	}{
		{name: "duplicate protected member", compact: rawCompact(t, key, `{"alg":"Ed25519","alg":"Ed25519","typ":"example+jwt","kid":"issuer-key"}`, validPayload)},
		{name: "case ambiguous protected member", compact: rawCompact(t, key, `{"alg":"Ed25519","ALG":"Ed25519","typ":"example+jwt","kid":"issuer-key"}`, validPayload)},
		{name: "unencoded payload critical semantics", compact: rawCompact(t, key, `{"alg":"Ed25519","typ":"example+jwt","kid":"issuer-key","b64":false,"crit":["b64"]}`, validPayload)},
		{name: "b64 member even when true", compact: rawCompact(t, key, `{"alg":"Ed25519","typ":"example+jwt","kid":"issuer-key","b64":true}`, validPayload)},
		{name: "unsupported critical member", compact: rawCompact(t, key, `{"alg":"Ed25519","typ":"example+jwt","kid":"issuer-key","crit":["exp"],"exp":true}`, validPayload)},
		{name: "case variant protected member", compact: rawCompact(t, key, `{"ALG":"Ed25519","typ":"example+jwt","kid":"issuer-key"}`, validPayload)},
		{name: "duplicate payload member", compact: rawCompact(t, key, validHeader, `{"sub":"person-1","sub":"person-1"}`)},
		{name: "missing segment", compact: "e30.e30"},
		{name: "extra segment", compact: "e30.e30.e30.e30"},
		{name: "empty segment", compact: "e30..e30"},
		{name: "bad protected base64url", compact: "%.e30." + rawSignature64()},
		{name: "bad payload base64url", compact: "e30.%25." + rawSignature64()},
		{name: "bad signature base64url", compact: "e30.e30.%"},
		{name: "bad Ed25519 signature size", compact: base64.RawURLEncoding.EncodeToString([]byte(validHeader)) + "." + base64.RawURLEncoding.EncodeToString([]byte(validPayload)) + ".eA"},
		{name: "noncanonical signature trailing pad bits", compact: noncanonicalSignature},
		{name: "signature containing carriage return", compact: carriageReturnSignature},
		{name: "signature containing line feed", compact: lineFeedSignature},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := jose.ParseCompact(test.compact); err == nil {
				t.Fatalf("ParseCompact(%q) succeeded", test.compact)
			}
		})
	}

	for _, algorithm := range []string{"", "EdDSA", "none", "ES256"} {
		t.Run("algorithm "+algorithm, func(t *testing.T) {
			compact := rawCompact(t, key, `{"alg":"`+algorithm+`","typ":"example+jwt","kid":"issuer-key"}`, validPayload)
			parsed, err := jose.ParseCompact(compact)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := parsed.Verify(key.PublicJWK()); err == nil {
				t.Fatalf("Verify accepted algorithm %q", algorithm)
			}
		})
	}

	compact, err := jose.SignCompact(
		key,
		jose.Header{Algorithm: jose.Ed25519Algorithm, Type: "example+jwt", KeyID: key.ID()},
		[]byte(validPayload),
	)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := jose.ParseCompact(compact)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parsed.Verify(other.PublicJWK()); err == nil {
		t.Fatal("Verify accepted the wrong key")
	}
	misleadingKeyID := rawCompact(t, key, `{"alg":"Ed25519","typ":"example+jwt","kid":"other-key"}`, validPayload)
	misleadingParsed, err := jose.ParseCompact(misleadingKeyID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := misleadingParsed.Verify(key.PublicJWK()); err == nil {
		t.Fatal("Verify accepted a protected kid that does not match the verification key")
	}
	parts := strings.Split(compact, ".")
	parts[1] = base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"person-2"}`))
	mutated, err := jose.ParseCompact(strings.Join(parts, "."))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := mutated.Verify(key.PublicJWK()); err == nil {
		t.Fatal("Verify accepted a mutated payload")
	}
}

func TestCompactAcceptsUnknownNoncriticalProtectedMember(t *testing.T) {
	t.Parallel()

	key := fixedSigningKey(t, "issuer-key", 0)
	compact := rawCompact(
		t,
		key,
		`{"alg":"Ed25519","typ":"example+jwt","kid":"issuer-key","zip":"DEF"}`,
		`{"sub":"person-1"}`,
	)
	parsed, err := jose.ParseCompact(compact)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parsed.Verify(key.PublicJWK()); err != nil {
		t.Fatal(err)
	}
}

func TestSignCompactProtectedPreservesBoundedJWKHeaderBytes(t *testing.T) {
	t.Parallel()

	key := fixedSigningKey(t, "issuer-key", 0)
	protected := []byte(`{"alg":"Ed25519","typ":"jkt-s256+jwt","jwk":{"kty":"OKP","crv":"Ed25519","x":"A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg","alg":"Ed25519","kid":"issuer-key","use":"sig"}}`)
	payload := []byte(`{"iss":"urn:jkt:sha-256:1IG2tMH7J2wbJZnOf8LJzQitKf7LMvoAElsuDMVM54Y"}`)
	compact, err := jose.SignCompactProtected(key, protected, payload)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(compact, ".")
	if len(parts) != 3 {
		t.Fatalf("compact parts = %d", len(parts))
	}
	gotProtected, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatal(err)
	}
	if string(gotProtected) != string(protected) {
		t.Fatalf("protected bytes = %q, want %q", gotProtected, protected)
	}
	parsed, err := jose.ParseCompact(compact)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parsed.Verify(key.PublicJWK()); err != nil {
		t.Fatal(err)
	}

	other := fixedSigningKey(t, "other-key", 64)
	if _, err := jose.SignCompactProtected(other, protected, payload); err == nil {
		t.Fatal("signed a protected JWK header that names another key")
	}
	misleading := rawCompact(t, other, string(protected), string(payload))
	misleadingParsed, err := jose.ParseCompact(misleading)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := misleadingParsed.Verify(other.PublicJWK()); err == nil {
		t.Fatal("Verify accepted an embedded JWK that does not match the verification key")
	}
}

func TestFixedCurrentTokenVectorsRemainByteIdentical(t *testing.T) {
	t.Parallel()

	issuerKey := fixedSigningKey(t, "issuer-key", 0)
	confirmationKey := fixedSigningKey(t, "confirmation-key", 32)
	now := time.Unix(1750000000, 0).UTC()
	agentJKT, err := confirmationKey.PublicJWK().Thumbprint()
	if err != nil {
		t.Fatal(err)
	}
	vectors := []compactVector{
		frozenVector(t, "agent", "cfb69955b3d60aeb2c33d13f9e87fabaedf714c46e7047b44ce6b4b059899623", func() (string, error) {
			return aauth.MintAgentToken("https://ap.example", issuerKey, aauth.AgentTokenRequest{Agent: "aauth:agent@ap.example", PersonServer: "https://ps.example", PublicKey: confirmationKey.PublicJWK(), Lifetime: time.Hour}, now, "agent-jti")
		}),
		frozenVector(t, "person", "cc90d833ec98b1e177cdafffef01d7bc268bb246daf7df6df650c6655d894e97", func() (string, error) {
			return aauth.MintPersonToken(issuerKey, aauth.PersonTokenClaims{Issuer: "https://ps.example", DWK: aauth.PersonDiscoveryDocument, Audience: "https://resource.example", Subject: "person-1", Confirmation: aauth.Confirmation{JWK: confirmationKey.PublicJWK()}, JTI: "person-jti", IssuedAt: now.Unix(), ExpiresAt: now.Add(time.Hour).Unix(), Tenant: "tenant-1"})
		}),
		frozenVector(t, "resource", "a747327e1ea0afaedc0b38a86f799fd58ddb6bc712cd2060050064f47d80c1de", func() (string, error) {
			return aauth.MintResourceToken(issuerKey, aauth.ResourceTokenClaims{Issuer: "https://resource.example", DWK: aauth.ResourceDiscoveryDocument, Audience: "https://as.example", JTI: "resource-jti", AgentJKT: agentJKT, IssuedAt: now.Unix(), ExpiresAt: now.Add(time.Hour).Unix(), Scope: "read write", PersonServer: "https://ps.example", Subject: "person-1", PresentedJTI: "person-jti", Tenant: "tenant-1"})
		}),
		frozenVector(t, "auth", "8df47aa4cb001508b4250b2cca44d38eccce9b2e23ede6d4b12d8043d7d84501", func() (string, error) {
			return aauth.MintAuthToken(issuerKey, aauth.AuthTokenClaims{Issuer: "https://as.example", DWK: aauth.AccessDiscoveryDocument, Audience: "https://resource.example", JTI: "auth-jti", Confirmation: aauth.Confirmation{JWK: confirmationKey.PublicJWK()}, IssuedAt: now.Unix(), ExpiresAt: now.Add(time.Hour).Unix(), Subject: "person-1", Scope: "read write", PersonServer: "https://ps.example", Tenant: "tenant-1"})
		}),
	}
	for _, vector := range vectors {
		digest := sha256.Sum256([]byte(vector.compact))
		if got := hex.EncodeToString(digest[:]); got != vector.sha256 {
			t.Errorf("%s compact SHA-256 = %s, want base oracle %s", vector.name, got, vector.sha256)
		}
	}
}

func fixedSigningKey(t *testing.T, id string, offset int) jose.SigningKey {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	for index := range seed {
		seed[index] = byte(index + offset)
	}
	key, err := jose.NewEd25519SigningKey(id, ed25519.NewKeyFromSeed(seed))
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func rawCompact(t *testing.T, key jose.SigningKey, header, payload string) string {
	t.Helper()
	encodedHeader := base64.RawURLEncoding.EncodeToString([]byte(header))
	encodedPayload := base64.RawURLEncoding.EncodeToString([]byte(payload))
	signingInput := encodedHeader + "." + encodedPayload
	signature, err := key.Sign(rand.Reader, []byte(signingInput), crypto.Hash(0))
	if err != nil {
		t.Fatal(err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func rawSignature64() string {
	return base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
}

func withNonzeroTrailingPadBits(t *testing.T, encoded string) string {
	t.Helper()
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	if encoded == "" {
		t.Fatal("cannot mutate empty base64url value")
	}
	index := strings.IndexByte(alphabet, encoded[len(encoded)-1])
	if index < 0 {
		t.Fatalf("base64url value ends with %q", encoded[len(encoded)-1])
	}
	if index%4 != 0 {
		t.Fatalf("base64url value already has nonzero trailing pad bits: %q", encoded)
	}
	return encoded[:len(encoded)-1] + string(alphabet[index+1])
}

type compactVector struct {
	name    string
	compact string
	sha256  string
}

func frozenVector(t *testing.T, name, expectedSHA256 string, mint func() (string, error)) compactVector {
	t.Helper()
	compact, err := mint()
	if err != nil {
		t.Fatal(err)
	}
	return compactVector{name: name, compact: compact, sha256: expectedSHA256}
}
