package agent

import (
	"context"
	"errors"
	"strings"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/r3"
)

func (client *Client) verifyR3ResourceTokenContext(
	ctx context.Context,
	compact, resource string,
	person aauth.PersonTokenClaims,
	requestedScopes []string,
	expectedAccount *string,
) (aauth.ResourceTokenClaims, r3.Reference, error) {
	if client.r3 == nil {
		return aauth.ResourceTokenClaims{}, r3.Reference{}, errors.New("R3 is not configured")
	}
	claims, reference, err := r3.VerifyResourceToken(ctx, compact, client.keyResolver, client.clock)
	if err != nil {
		return aauth.ResourceTokenClaims{}, r3.Reference{}, err
	}
	return client.validateR3ResourceTokenContext(claims, reference, resource, person, requestedScopes, expectedAccount)
}

func (client *Client) validateR3ResourceTokenContext(
	claims aauth.ResourceTokenClaims,
	reference r3.Reference,
	resource string,
	person aauth.PersonTokenClaims,
	requestedScopes []string,
	expectedAccount *string,
) (aauth.ResourceTokenClaims, r3.Reference, error) {
	if claims.Interaction != nil {
		return aauth.ResourceTokenClaims{}, r3.Reference{}, errors.New("resource-token interaction requires the deferred flow")
	}
	if !equalStringPointers(claims.Account, expectedAccount) {
		return aauth.ResourceTokenClaims{}, r3.Reference{}, errors.New("resource-token account does not match the authorization request")
	}
	thumbprint, err := client.signingKey.PublicJWK().Thumbprint()
	if err != nil {
		return aauth.ResourceTokenClaims{}, r3.Reference{}, err
	}
	if claims.Issuer != resource || claims.PersonServer != person.Issuer ||
		claims.Subject != person.Subject || claims.PresentedJTI != person.JTI || claims.AgentJKT != thumbprint {
		return aauth.ResourceTokenClaims{}, r3.Reference{}, errors.New("resource-token identity does not match the R3 authorization request")
	}
	if len(requestedScopes) == 0 {
		if claims.Scope != "" {
			return aauth.ResourceTokenClaims{}, r3.Reference{}, errors.New("resource token added an unrequested Core scope")
		}
	} else if !scopeSubset(strings.Fields(claims.Scope), requestedScopes) {
		return aauth.ResourceTokenClaims{}, r3.Reference{}, errors.New("resource-token scope is empty, duplicated, or outside the request")
	}
	if claims.MissionS256 != person.MissionS256 || claims.Tenant != person.Tenant {
		return aauth.ResourceTokenClaims{}, r3.Reference{}, errors.New("resource-token context does not match person token")
	}
	if claims.IssuedAt < person.IssuedAt || claims.IssuedAt >= person.ExpiresAt ||
		(person.NotBefore != 0 && claims.IssuedAt < person.NotBefore) {
		return aauth.ResourceTokenClaims{}, r3.Reference{}, errors.New("resource token was issued outside the person-token validity window")
	}
	return claims, reference, nil
}

func (client *Client) verifyR3AuthTokenForResourceBinding(
	ctx context.Context,
	compact string,
	resource aauth.ResourceTokenClaims,
	reference r3.Reference,
	credential personServerCredential,
) (aauth.AuthTokenClaims, error) {
	if client.r3 == nil {
		return aauth.AuthTokenClaims{}, errors.New("R3 is not configured")
	}
	claims, authReference, _, err := r3.VerifyAuthTokenClaims(ctx, client.r3.Registry, compact, client.keyResolver, client.clock)
	if err != nil {
		return aauth.AuthTokenClaims{}, err
	}
	if authReference != reference {
		return aauth.AuthTokenClaims{}, errors.New("auth token changed the R3 document reference")
	}
	return client.validateR3AuthTokenForResourceBinding(claims, resource, reference, credential)
}

func (client *Client) validateR3AuthTokenForResourceBinding(
	claims aauth.AuthTokenClaims,
	resource aauth.ResourceTokenClaims,
	reference r3.Reference,
	credential personServerCredential,
) (aauth.AuthTokenClaims, error) {
	// The signed token's dwk selects the issuing role. A class grant may come
	// directly from the Person Server or from a distinct or collocated Access
	// Server, so the Resource-token audience alone cannot select that role.
	if err := aauth.ValidateCurrentAuthTokenContext(claims, aauth.AuthTokenContext{
		Issuer: resource.Audience, DiscoveryDocument: claims.DWK,
		Resource: resource.Issuer, PersonServer: resource.PersonServer,
		Subject: resource.Subject, RequestKey: credential.requestKey,
	}); err != nil {
		return aauth.AuthTokenClaims{}, err
	}
	if resource.Scope == "" {
		if claims.Scope != "" {
			return aauth.AuthTokenClaims{}, errors.New("auth token added Core scope absent from the resource token")
		}
	} else if !scopeSubset(strings.Fields(claims.Scope), strings.Fields(resource.Scope)) {
		return aauth.AuthTokenClaims{}, errors.New("auth-token scope is outside resource token")
	}
	if claims.MissionS256 != resource.MissionS256 || claims.Tenant != resource.Tenant ||
		!equalStringPointers(claims.Account, resource.Account) {
		return aauth.AuthTokenClaims{}, errors.New("auth-token context does not match resource token")
	}
	if claims.ExpiresAt > credential.expiresAt {
		return aauth.AuthTokenClaims{}, errors.New("auth-token lifetime exceeds the " + credential.expirySource)
	}
	return claims, nil
}

func (client *Client) verifyR3AuthTokenForCall(
	ctx context.Context,
	compact, resource string,
) (aauth.AuthTokenClaims, error) {
	if client.r3 == nil {
		return aauth.AuthTokenClaims{}, errors.New("R3 is not configured")
	}
	claims, _, _, err := r3.VerifyDirectAuthToken(ctx, client.r3.Registry, compact, client.keyResolver, client.clock)
	if err != nil {
		return aauth.AuthTokenClaims{}, err
	}
	return client.validateR3AuthTokenForCallClaims(ctx, claims, resource)
}

func (client *Client) validateR3AuthTokenForCallClaims(
	ctx context.Context,
	claims aauth.AuthTokenClaims,
	resource string,
) (aauth.AuthTokenClaims, error) {
	if err := client.acceptIssuedPersonServer(
		ctx, "", claims.PersonServer, claims.MissionS256, time.Unix(claims.IssuedAt, 0),
	); err != nil {
		return aauth.AuthTokenClaims{}, err
	}
	if claims.ExpiresAt > client.agentClaims.ExpiresAt {
		return aauth.AuthTokenClaims{}, errors.New("auth-token lifetime exceeds the agent token")
	}
	if claims.Audience != resource || !claims.Confirmation.JWK.Equal(client.signingKey.PublicJWK()) {
		return aauth.AuthTokenClaims{}, errors.New("auth token does not match the protected call")
	}
	return claims, nil
}
