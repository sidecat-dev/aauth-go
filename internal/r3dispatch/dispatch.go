// Package r3dispatch selects the strict R3 verifier for tokens that name any
// recognized R3 claim. Its result is untrusted dispatch input, not authority.
package r3dispatch

import (
	"encoding/json"
	"strings"

	"gitlab.com/sidecat-dev/aauth-go/jose"
)

var recognizedClaims = [...]string{"r3_uri", "r3_s256", "r3_granted", "r3_per_call"}

// TokenCarriesClaims reports whether an unverified compact token names any R3
// claim, including partial and case-variant forms that must fail in the strict
// R3 verifier rather than falling back to Core.
func TokenCarriesClaims(compact string) (bool, error) {
	parsed, err := jose.ParseCompact(compact)
	if err != nil {
		return false, err
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(parsed.Payload(), &members); err != nil {
		return false, err
	}
	for member := range members {
		for _, claim := range recognizedClaims {
			if strings.EqualFold(member, claim) {
				return true, nil
			}
		}
	}
	return false, nil
}
