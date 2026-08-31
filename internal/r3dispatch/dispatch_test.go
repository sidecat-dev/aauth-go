package r3dispatch

import (
	"encoding/base64"
	"testing"
)

func TestTokenCarriesClaimsIsOnlyACaseInsensitiveDispatchSignal(t *testing.T) {
	t.Parallel()

	compact := func(payload string) string {
		return base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`)) + "." +
			base64.RawURLEncoding.EncodeToString([]byte(payload)) + "." +
			base64.RawURLEncoding.EncodeToString([]byte("signature"))
	}
	for _, test := range []struct {
		name    string
		compact string
		want    bool
		wantErr bool
	}{
		{name: "Core", compact: compact(`{"iss":"https://issuer.example"}`)},
		{name: "complete reference", compact: compact(`{"r3_uri":"https://resource.example/r3/x","r3_s256":"x"}`), want: true},
		{name: "partial case variant", compact: compact(`{"R3_Granted":null}`), want: true},
		{name: "per-call", compact: compact(`{"r3_per_call":{}}`), want: true},
		{name: "malformed compact", compact: "not-a-token", wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := TokenCarriesClaims(test.compact)
			if (err != nil) != test.wantErr || got != test.want {
				t.Fatalf("TokenCarriesClaims = %t, %v", got, err)
			}
		})
	}
}
