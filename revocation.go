package aauth

import (
	"errors"
	"fmt"
)

// TokenReference identifies one token in its issuer's JTI namespace.
type TokenReference struct {
	Issuer string `json:"iss"`
	JTI    string `json:"jti"`
}

// ValidateTokenReference validates the Core token-revocation request shape.
func ValidateTokenReference(reference TokenReference) error {
	if err := ValidateServerIdentifier(reference.Issuer); err != nil {
		return fmt.Errorf("aauth: token reference issuer: %w", err)
	}
	if reference.JTI == "" {
		return errors.New("aauth: token reference jti is required")
	}
	return nil
}
