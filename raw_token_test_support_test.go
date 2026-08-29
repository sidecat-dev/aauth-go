package aauth

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	"gitlab.com/sidecat-dev/aauth-go/jose"
)

func signRawTestToken(t *testing.T, key jose.SigningKey, tokenType string, claims []byte) string {
	t.Helper()
	header, err := json.Marshal(jose.Header{Algorithm: jose.Ed25519Algorithm, Type: tokenType, KeyID: key.ID()})
	if err != nil {
		t.Fatal(err)
	}
	signingInput := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(claims)
	signature, err := signTestMessage(key, []byte(signingInput))
	if err != nil {
		t.Fatal(err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature)
}
