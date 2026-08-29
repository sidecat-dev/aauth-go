package aauth

import (
	"context"
	"errors"
	"strings"
)

// TokenRevocationRequest identifies one token in its issuer namespace. The
// issuer and JTI pair is the complete revocation key; token type is not part
// of the protocol identity.
type TokenRevocationRequest struct {
	Issuer string `json:"iss"`
	JTI    string `json:"jti"`
}

// Validate checks the protocol-level revocation request shape without
// dereferencing the token or making an authorization decision.
func (request TokenRevocationRequest) Validate() error {
	if err := ValidateServerIdentifier(request.Issuer); err != nil {
		return err
	}
	if strings.TrimSpace(request.JTI) == "" || request.JTI != strings.TrimSpace(request.JTI) {
		return errors.New("aauth: token revocation jti is required and must not have surrounding whitespace")
	}
	return nil
}

// TokenRevocationEvaluation describes the authenticated caller and the
// issuer/JTI pair it asks a server to revoke. Deployments may use it to admit
// a trusted person server or administrator in addition to the token issuer.
type TokenRevocationEvaluation struct {
	Request      TokenRevocationRequest
	CallerIssuer string
	CallerAgent  string
	CallerJTI    string
}

// TokenRevocationPolicy authorizes one revocation request after its signed
// caller and request body have been verified.
type TokenRevocationPolicy func(context.Context, TokenRevocationEvaluation) error
