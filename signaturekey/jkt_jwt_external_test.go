package signaturekey_test

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

func TestJKTJWTDelegationIsOpaque(t *testing.T) {
	t.Parallel()
	typeOfDelegation := reflect.TypeOf(signaturekey.JKTJWTDelegation{})
	for index := 0; index < typeOfDelegation.NumField(); index++ {
		field := typeOfDelegation.Field(index)
		if field.IsExported() {
			t.Fatalf("JKTJWTDelegation exposes mutable field %s", field.Name)
		}
	}
}

func TestJKTJWTRequestProofBindsDurableAndEphemeralKeys(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 31, 3, 30, 0, 0, time.UTC)
	durable := testDiscoverySigningKey(t, "durable-key", 0x61)
	ephemeral := testDiscoverySigningKey(t, "ephemeral-key", 0x62)
	compact, err := signaturekey.MintJKTJWT(
		durable,
		ephemeral.PublicJWK(),
		now,
		now.Add(time.Hour),
		"refresh-1",
	)
	if err != nil {
		t.Fatal(err)
	}
	credential, err := signaturekey.NewJKTJWTCredential(compact)
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest(
		http.MethodPost,
		"https://ap.example/internal/refresh",
		bytes.NewReader([]byte(`{"ps":"https://ps.example"}`)),
	)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	if err := signaturekey.SignRequest(request, ephemeral, credential, fixedClock(now), signaturekey.SignOptions{
		AdditionalComponents: []string{"content-type", "content-digest"},
	}); err != nil {
		t.Fatal(err)
	}
	prepared, err := signaturekey.PrepareRequest(request, fixedClock(now), signaturekey.VerifyOptions{
		AcceptedSchemes:        []signaturekey.Scheme{signaturekey.SchemeJKTJWT},
		RequiredComponents:     []string{"content-type", "content-digest"},
		RequireExactComponents: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	proof, delegation, err := prepared.VerifyJKTJWT()
	if err != nil {
		t.Fatal(err)
	}
	identity, err := durable.PublicJWK().ThumbprintURI()
	if err != nil {
		t.Fatal(err)
	}
	if proof.Scheme() != signaturekey.SchemeJKTJWT || proof.Signer() != identity ||
		!proof.PublicKey().Equal(ephemeral.PublicJWK()) || proof.ReplayKey() == "" {
		t.Fatalf("verified proof = scheme:%q signer:%q key:%#v replay:%q",
			proof.Scheme(), proof.Signer(), proof.PublicKey(), proof.ReplayKey())
	}
	if delegation.Issuer() != identity || delegation.JTI() != "refresh-1" ||
		!delegation.IssuedAt().Equal(now) || !delegation.ExpiresAt().Equal(now.Add(time.Hour)) ||
		!delegation.IdentityKey().Equal(durable.PublicJWK()) ||
		!delegation.ConfirmationKey().Equal(ephemeral.PublicJWK()) ||
		delegation.Compact() != compact {
		t.Fatalf("verified delegation = %#v", delegation)
	}
	gotCompact, ok := credential.JKTJWT()
	if !ok || gotCompact != compact {
		t.Fatalf("JKTJWT() = %q, %t", gotCompact, ok)
	}
}

func TestJKTJWTRejectsUnsupportedDelegatedAlgorithm(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 31, 3, 30, 0, 0, time.UTC)
	durable := testDiscoverySigningKey(t, "durable-key", 0x63)
	ephemeral := testDiscoverySigningKey(t, "ephemeral-key", 0x64)
	unsupported := ephemeral.PublicJWK()
	unsupported.Alg = "ES256"
	compact := mintTestJKTJWT(t, durable, unsupported, now, now.Add(time.Hour), "refresh-unsupported")
	prepared := prepareTestJKTJWTRequest(t, compact, ephemeral, now)

	_, _, err := prepared.VerifyJKTJWT()
	var failure *signaturekey.Error
	if !errors.As(err, &failure) || failure.Code != signaturekey.ErrorUnsupportedAlgorithm ||
		len(failure.AcceptedAlgorithms) != 1 || failure.AcceptedAlgorithms[0] != jose.Ed25519Algorithm {
		t.Fatalf("VerifyJKTJWT() error = %#v, want unsupported_algorithm accepting Ed25519", err)
	}
}

func TestJKTJWTRejectsMissingConfirmationAsInvalidJWT(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 31, 3, 30, 0, 0, time.UTC)
	durable := testDiscoverySigningKey(t, "durable-key", 0x65)
	ephemeral := testDiscoverySigningKey(t, "ephemeral-key", 0x66)
	issuer, err := durable.PublicJWK().ThumbprintURI()
	if err != nil {
		t.Fatal(err)
	}
	compact := signTestJKTJWT(t, durable, struct {
		Issuer    string `json:"iss"`
		IssuedAt  int64  `json:"iat"`
		ExpiresAt int64  `json:"exp"`
		JTI       string `json:"jti"`
	}{
		Issuer: issuer, IssuedAt: now.Unix(), ExpiresAt: now.Add(time.Hour).Unix(), JTI: "refresh-missing-cnf",
	})
	prepared := prepareTestJKTJWTRequest(t, compact, ephemeral, now)

	_, _, err = prepared.VerifyJKTJWT()
	var failure *signaturekey.Error
	if !errors.As(err, &failure) || failure.Code != signaturekey.ErrorInvalidJWT {
		t.Fatalf("VerifyJKTJWT() error = %#v, want invalid_jwt", err)
	}
}

func TestJKTJWTAcceptsUnixEpochNumericDates(t *testing.T) {
	t.Parallel()

	issuedAt := time.Unix(0, 0).UTC()
	verifiedAt := issuedAt.Add(30 * time.Minute)
	durable := testDiscoverySigningKey(t, "durable-key", 0x67)
	ephemeral := testDiscoverySigningKey(t, "ephemeral-key", 0x68)
	compact := mintTestJKTJWT(t, durable, ephemeral.PublicJWK(), issuedAt, issuedAt.Add(time.Hour), "refresh-epoch")
	prepared := prepareTestJKTJWTRequest(t, compact, ephemeral, verifiedAt)

	_, delegation, err := prepared.VerifyJKTJWT()
	if err != nil {
		t.Fatal(err)
	}
	if !delegation.IssuedAt().Equal(issuedAt) || !delegation.ExpiresAt().Equal(issuedAt.Add(time.Hour)) {
		t.Fatalf("delegation times = %s through %s", delegation.IssuedAt(), delegation.ExpiresAt())
	}
}

func TestJKTJWTRejectsMissingIdentityKeyAsInvalidJWT(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 31, 3, 30, 0, 0, time.UTC)
	durable := testDiscoverySigningKey(t, "durable-key", 0x69)
	ephemeral := testDiscoverySigningKey(t, "ephemeral-key", 0x6a)
	issuer, err := durable.PublicJWK().ThumbprintURI()
	if err != nil {
		t.Fatal(err)
	}
	protected, err := json.Marshal(struct {
		Algorithm string `json:"alg"`
		Type      string `json:"typ"`
	}{Algorithm: jose.Ed25519Algorithm, Type: signaturekey.JKTJWTTypeSHA256})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(struct {
		Issuer       string `json:"iss"`
		IssuedAt     int64  `json:"iat"`
		ExpiresAt    int64  `json:"exp"`
		Confirmation struct {
			JWK jose.JWK `json:"jwk"`
		} `json:"cnf"`
		JTI string `json:"jti"`
	}{
		Issuer: issuer, IssuedAt: now.Unix(), ExpiresAt: now.Add(time.Hour).Unix(),
		Confirmation: struct {
			JWK jose.JWK `json:"jwk"`
		}{JWK: ephemeral.PublicJWK()},
		JTI: "refresh-missing-identity",
	})
	if err != nil {
		t.Fatal(err)
	}
	compact := signRawTestCompact(t, durable, protected, payload)
	prepared := prepareTestJKTJWTRequest(t, compact, ephemeral, now)

	_, _, err = prepared.VerifyJKTJWT()
	var failure *signaturekey.Error
	if !errors.As(err, &failure) || failure.Code != signaturekey.ErrorInvalidJWT {
		t.Fatalf("VerifyJKTJWT() error = %#v, want invalid_jwt", err)
	}
}

func TestJKTJWTChecksThumbprintIssuerBeforeSignature(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 31, 3, 30, 0, 0, time.UTC)
	durable := testDiscoverySigningKey(t, "durable-key", 0x6b)
	other := testDiscoverySigningKey(t, "other-durable-key", 0x6c)
	ephemeral := testDiscoverySigningKey(t, "ephemeral-key", 0x6d)
	protected, err := json.Marshal(struct {
		Algorithm string   `json:"alg"`
		Type      string   `json:"typ"`
		JWK       jose.JWK `json:"jwk"`
	}{
		Algorithm: jose.Ed25519Algorithm,
		Type:      signaturekey.JKTJWTTypeSHA256,
		JWK:       durable.PublicJWK(),
	})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(struct {
		Issuer       string `json:"iss"`
		IssuedAt     int64  `json:"iat"`
		ExpiresAt    int64  `json:"exp"`
		Confirmation struct {
			JWK jose.JWK `json:"jwk"`
		} `json:"cnf"`
		JTI string `json:"jti"`
	}{
		Issuer:   "urn:jkt:sha-256:not-the-identity-key",
		IssuedAt: now.Unix(), ExpiresAt: now.Add(time.Hour).Unix(),
		Confirmation: struct {
			JWK jose.JWK `json:"jwk"`
		}{JWK: ephemeral.PublicJWK()},
		JTI: "refresh-wrong-issuer",
	})
	if err != nil {
		t.Fatal(err)
	}
	compact := signRawTestCompact(t, other, protected, payload)
	prepared := prepareTestJKTJWTRequest(t, compact, ephemeral, now)

	_, _, err = prepared.VerifyJKTJWT()
	if err == nil || !strings.Contains(err.Error(), "issuer does not match") {
		t.Fatalf("VerifyJKTJWT() error = %v, want issuer mismatch before signature verification", err)
	}
}

func TestJKTJWTRejectsExpiredAndFutureAssertions(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 31, 3, 30, 0, 0, time.UTC)
	for _, test := range []struct {
		name      string
		issuedAt  time.Time
		expiresAt time.Time
		want      signaturekey.ErrorCode
	}{
		{name: "expired", issuedAt: now.Add(-2 * time.Hour), expiresAt: now.Add(-time.Hour), want: signaturekey.ErrorExpiredJWT},
		{name: "future issued at the window edge", issuedAt: now.Add(signaturekey.DefaultSignatureWindow), expiresAt: now.Add(time.Hour)},
		{name: "future issued beyond the window", issuedAt: now.Add(signaturekey.DefaultSignatureWindow + time.Second), expiresAt: now.Add(time.Hour), want: signaturekey.ErrorClockSkew},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			durable := testDiscoverySigningKey(t, "durable-key-"+test.name, byte(len(test.name)+0x70))
			ephemeral := testDiscoverySigningKey(t, "ephemeral-key-"+test.name, byte(len(test.name)+0x80))
			compact := mintTestJKTJWT(t, durable, ephemeral.PublicJWK(), test.issuedAt, test.expiresAt, "refresh-"+test.name)
			prepared := prepareTestJKTJWTRequest(t, compact, ephemeral, now)
			_, _, err := prepared.VerifyJKTJWT()
			if test.want == "" {
				if err != nil {
					t.Fatalf("VerifyJKTJWT() rejected an assertion issued within the request window: %v", err)
				}
				return
			}
			var failure *signaturekey.Error
			if !errors.As(err, &failure) || failure.Code != test.want {
				t.Fatalf("VerifyJKTJWT() error = %#v, want %s", err, test.want)
			}
		})
	}
}

func TestJKTJWTRejectsWrongJWTAndOuterRequestKeys(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 31, 3, 30, 0, 0, time.UTC)
	durable := testDiscoverySigningKey(t, "durable-key", 0x6e)
	otherDurable := testDiscoverySigningKey(t, "other-durable-key", 0x6f)
	ephemeral := testDiscoverySigningKey(t, "ephemeral-key", 0x70)
	otherEphemeral := testDiscoverySigningKey(t, "other-ephemeral-key", 0x71)
	compact := mintTestJKTJWT(t, durable, ephemeral.PublicJWK(), now, now.Add(time.Hour), "refresh-key-binding")

	wrongJWT := resignTestCompact(t, otherDurable, compact)
	prepared := prepareTestJKTJWTRequest(t, wrongJWT, ephemeral, now)
	_, _, err := prepared.VerifyJKTJWT()
	assertSignatureErrorCode(t, err, signaturekey.ErrorInvalidJWT)

	prepared = prepareTestJKTJWTRequest(t, compact, otherEphemeral, now)
	_, _, err = prepared.VerifyJKTJWT()
	assertSignatureErrorCode(t, err, signaturekey.ErrorInvalidSignature)
}

func TestJKTJWTCacheRequestRequiresJTI(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 31, 3, 30, 0, 0, time.UTC)
	durable := testDiscoverySigningKey(t, "durable-key", 0x72)
	ephemeral := testDiscoverySigningKey(t, "ephemeral-key", 0x73)
	compact := mintTestJKTJWT(t, durable, ephemeral.PublicJWK(), now, now.Add(time.Hour), "")
	credential, err := signaturekey.ParseCredential([]string{
		`sig=jkt-jwt;jwt=` + strconv.Quote(compact) + `;cache`,
	})
	if err != nil {
		t.Fatal(err)
	}
	prepared := prepareTestJKTJWTRequestWithCredential(t, credential, ephemeral, now)

	_, _, err = prepared.VerifyJKTJWT()
	assertSignatureErrorCode(t, err, signaturekey.ErrorInvalidJWT)
}

func TestJKTJWTRejectsPrivateKeyMaterial(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 31, 3, 30, 0, 0, time.UTC)
	durable := testDiscoverySigningKey(t, "private-durable-key", 0x74)
	ephemeral := testDiscoverySigningKey(t, "private-ephemeral-key", 0x75)
	issuer, err := durable.PublicJWK().ThumbprintURI()
	if err != nil {
		t.Fatal(err)
	}
	for _, location := range []string{"identity", "confirmation"} {
		t.Run(location, func(t *testing.T) {
			identity := testJWKObject(t, durable.PublicJWK())
			confirmation := testJWKObject(t, ephemeral.PublicJWK())
			if location == "identity" {
				identity["d"] = "private-material"
			} else {
				confirmation["d"] = "private-material"
			}
			protected, err := json.Marshal(map[string]any{
				"alg": jose.Ed25519Algorithm, "typ": signaturekey.JKTJWTTypeSHA256, "jwk": identity,
			})
			if err != nil {
				t.Fatal(err)
			}
			payload, err := json.Marshal(map[string]any{
				"iss": issuer, "iat": now.Unix(), "exp": now.Add(time.Hour).Unix(),
				"cnf": map[string]any{"jwk": confirmation}, "jti": "refresh-private-" + location,
			})
			if err != nil {
				t.Fatal(err)
			}
			compact := signRawTestCompact(t, durable, protected, payload)
			prepared := prepareTestJKTJWTRequest(t, compact, ephemeral, now)
			_, _, err = prepared.VerifyJKTJWT()
			assertSignatureErrorCode(t, err, signaturekey.ErrorInvalidJWT)
		})
	}
}

func TestJKTJWTRejectsMissingJWKAlgorithms(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 31, 3, 30, 0, 0, time.UTC)
	durable := testDiscoverySigningKey(t, "missing-alg-durable-key", 0x76)
	ephemeral := testDiscoverySigningKey(t, "missing-alg-ephemeral-key", 0x77)
	issuer, err := durable.PublicJWK().ThumbprintURI()
	if err != nil {
		t.Fatal(err)
	}
	for _, location := range []string{"identity", "confirmation"} {
		t.Run(location, func(t *testing.T) {
			identity := testJWKObject(t, durable.PublicJWK())
			confirmation := testJWKObject(t, ephemeral.PublicJWK())
			if location == "identity" {
				delete(identity, "alg")
			} else {
				delete(confirmation, "alg")
			}
			protected, err := json.Marshal(map[string]any{
				"alg": jose.Ed25519Algorithm, "typ": signaturekey.JKTJWTTypeSHA256, "jwk": identity,
			})
			if err != nil {
				t.Fatal(err)
			}
			payload, err := json.Marshal(map[string]any{
				"iss": issuer, "iat": now.Unix(), "exp": now.Add(time.Hour).Unix(),
				"cnf": map[string]any{"jwk": confirmation}, "jti": "refresh-missing-alg-" + location,
			})
			if err != nil {
				t.Fatal(err)
			}
			compact := signRawTestCompact(t, durable, protected, payload)
			prepared := prepareTestJKTJWTRequest(t, compact, ephemeral, now)
			_, _, err = prepared.VerifyJKTJWT()
			assertSignatureErrorCode(t, err, signaturekey.ErrorUnsupportedAlgorithm)
		})
	}
}

func testJWKObject(t *testing.T, key jose.JWK) map[string]any {
	t.Helper()
	encoded, err := json.Marshal(key)
	if err != nil {
		t.Fatal(err)
	}
	var object map[string]any
	if err := json.Unmarshal(encoded, &object); err != nil {
		t.Fatal(err)
	}
	return object
}

func mintTestJKTJWT(
	t *testing.T,
	identity jose.SigningKey,
	confirmation jose.JWK,
	issuedAt time.Time,
	expiresAt time.Time,
	jti string,
) string {
	t.Helper()
	issuer, err := identity.PublicJWK().ThumbprintURI()
	if err != nil {
		t.Fatal(err)
	}
	payload := struct {
		Issuer       string `json:"iss"`
		IssuedAt     int64  `json:"iat"`
		ExpiresAt    int64  `json:"exp"`
		Confirmation struct {
			JWK jose.JWK `json:"jwk"`
		} `json:"cnf"`
		JTI string `json:"jti,omitempty"`
	}{
		Issuer: issuer, IssuedAt: issuedAt.Unix(), ExpiresAt: expiresAt.Unix(),
		Confirmation: struct {
			JWK jose.JWK `json:"jwk"`
		}{JWK: confirmation},
		JTI: jti,
	}
	return signTestJKTJWT(t, identity, payload)
}

func signTestJKTJWT(t *testing.T, identity jose.SigningKey, payload any) string {
	t.Helper()
	protected, err := json.Marshal(struct {
		Algorithm string   `json:"alg"`
		Type      string   `json:"typ"`
		JWK       jose.JWK `json:"jwk"`
	}{
		Algorithm: jose.Ed25519Algorithm,
		Type:      signaturekey.JKTJWTTypeSHA256,
		JWK:       identity.PublicJWK(),
	})
	if err != nil {
		t.Fatal(err)
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	compact, err := jose.SignCompactProtected(identity, protected, payloadJSON)
	if err != nil {
		t.Fatal(err)
	}
	return compact
}

func signRawTestCompact(t *testing.T, key jose.SigningKey, protected, payload []byte) string {
	t.Helper()
	encodedProtected := base64.RawURLEncoding.EncodeToString(protected)
	encodedPayload := base64.RawURLEncoding.EncodeToString(payload)
	input := encodedProtected + "." + encodedPayload
	signature, err := key.Sign(rand.Reader, []byte(input), crypto.Hash(0))
	if err != nil {
		t.Fatal(err)
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func resignTestCompact(t *testing.T, key jose.SigningKey, compact string) string {
	t.Helper()
	parts := strings.Split(compact, ".")
	if len(parts) != 3 {
		t.Fatalf("compact has %d parts", len(parts))
	}
	input := parts[0] + "." + parts[1]
	signature, err := key.Sign(rand.Reader, []byte(input), crypto.Hash(0))
	if err != nil {
		t.Fatal(err)
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func prepareTestJKTJWTRequest(
	t *testing.T,
	compact string,
	requestKey jose.SigningKey,
	now time.Time,
) signaturekey.PreparedRequest {
	t.Helper()
	credential, err := signaturekey.NewJKTJWTCredential(compact)
	if err != nil {
		t.Fatal(err)
	}
	return prepareTestJKTJWTRequestWithCredential(t, credential, requestKey, now)
}

func prepareTestJKTJWTRequestWithCredential(
	t *testing.T,
	credential signaturekey.Credential,
	requestKey jose.SigningKey,
	now time.Time,
) signaturekey.PreparedRequest {
	t.Helper()
	request, err := http.NewRequest(
		http.MethodPost,
		"https://ap.example/internal/refresh",
		bytes.NewReader([]byte(`{"ps":"https://ps.example"}`)),
	)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	if err := signaturekey.SignRequest(request, requestKey, credential, fixedClock(now), signaturekey.SignOptions{
		AdditionalComponents: []string{"content-type", "content-digest"},
	}); err != nil {
		t.Fatal(err)
	}
	prepared, err := signaturekey.PrepareRequest(request, fixedClock(now), signaturekey.VerifyOptions{
		AcceptedSchemes:        []signaturekey.Scheme{signaturekey.SchemeJKTJWT},
		RequiredComponents:     []string{"content-type", "content-digest"},
		RequireExactComponents: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	return prepared
}

func assertSignatureErrorCode(t *testing.T, err error, want signaturekey.ErrorCode) {
	t.Helper()
	var failure *signaturekey.Error
	if !errors.As(err, &failure) || failure.Code != want {
		t.Fatalf("error = %#v, want %s", err, want)
	}
}
