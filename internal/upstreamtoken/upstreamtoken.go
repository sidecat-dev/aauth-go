// Package upstreamtoken verifies the auth token a calling Agent presented to an
// intermediary, when the intermediary passes it on as upstream_token. The
// intermediary's Agent client, its Person Server and an Access Server each
// verify it this way.
package upstreamtoken

import (
	"context"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/budgets"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

// VerifyAuthToken verifies an aa-auth+jwt presented as upstream_token. A
// token that names a Budget claim is verified with the complete Budget
// companion, and its grant is set aside: an upstream token grants nothing
// downstream, and each hop is metered on its own auth token (Budgets, Call
// Chaining). Any other token is verified as a Core auth token.
func VerifyAuthToken(
	ctx context.Context,
	compact string,
	resolver signaturekey.KeyResolver,
	clock aauth.Clock,
) (aauth.AuthTokenClaims, error) {
	budgeted, err := budgets.TokenCarriesClaims(compact)
	if err != nil {
		return aauth.AuthTokenClaims{}, err
	}
	if !budgeted {
		return aauth.VerifyAuthToken(ctx, compact, resolver, clock)
	}
	claims, _, err := budgets.VerifyAuthToken(ctx, compact, resolver, clock)
	return claims, err
}
