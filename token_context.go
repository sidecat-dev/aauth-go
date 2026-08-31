package aauth

import (
	"errors"
	"fmt"

	"gitlab.com/sidecat-dev/aauth-go/jose"
)

// ValidatePersonTokenContext binds verified claims to one resource request.
func ValidatePersonTokenContext(claims PersonTokenClaims, resourceIdentifier string, requestKey jose.JWK) error {
	if err := ValidateServerIdentifier(resourceIdentifier); err != nil {
		return fmt.Errorf("aauth: person-token expected resource: %w", err)
	}
	if claims.Audience != resourceIdentifier {
		return fmt.Errorf("aauth: person-token audience %q does not match resource %q", claims.Audience, resourceIdentifier)
	}
	if !claims.Confirmation.JWK.Equal(requestKey) {
		return errors.New("aauth: person-token confirmation key does not match request key")
	}
	return nil
}
