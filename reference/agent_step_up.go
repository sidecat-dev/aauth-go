package reference

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"reflect"

	aa "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/budgets"
	"gitlab.com/sidecat-dev/aauth-go/r3"
)

type authTokenChallenge struct {
	requirement      aa.Requirement
	completionTarget string
}

// DoWithAuthTokenAuthorization sends one exact call under an existing auth
// token and follows one resource-issued auth-token step-up challenge. The
// resource token in the challenge is verified against the existing grant's
// current person namespace, resource, account, mission, tenant, and signing
// key before the ordinary person-server exchange. The original call is then
// retried once under the resulting grant. A second challenge is returned to
// the caller rather than followed recursively.
func (agent *Agent) DoWithAuthTokenAuthorization(
	ctx context.Context,
	call AuthorizedCall,
	personServerEndpoint string,
	grant Grant,
) (*http.Response, Grant, error) {
	var zero Grant
	resource, err := endpointIdentifier(call.Endpoint)
	if err != nil {
		return nil, zero, err
	}
	if err := agent.validateExistingAuthGrant(ctx, resource, grant); err != nil {
		return nil, zero, err
	}
	_, err = preflightAuthStepUpEndpoint(personServerEndpoint, grant)
	if err != nil {
		return nil, zero, err
	}
	response, err := agent.DoAuthorizedRequest(ctx, call, grant)
	if err != nil {
		return nil, zero, err
	}
	challenge, present, err := parseAuthTokenChallenge(response)
	if err != nil {
		response.Body.Close()
		return nil, zero, err
	}
	if !present {
		return response, grant, nil
	}
	response.Body.Close()
	response, upgraded, err := agent.finishAuthTokenStepUp(ctx, call, resource, personServerEndpoint, grant, challenge)
	if err != nil {
		return nil, zero, err
	}
	return response, upgraded, nil
}

func preflightAuthStepUpEndpoint(personServerEndpoint string, grant Grant) (string, error) {
	if err := aa.ValidateEndpoint(personServerEndpoint); err != nil {
		return "", err
	}
	personServer, err := endpointIdentifier(personServerEndpoint)
	if err != nil {
		return "", err
	}
	if grant.Claims.PersonServer == "" || grant.Claims.PersonServer != personServer {
		return "", errors.New("reference: step-up endpoint does not match the existing auth-token person server")
	}
	return personServer, nil
}

func parseAuthTokenChallenge(response *http.Response) (authTokenChallenge, bool, error) {
	var challenge authTokenChallenge
	if response == nil {
		return challenge, false, errors.New("reference: protected response is missing")
	}
	switch response.StatusCode {
	case http.StatusUnauthorized:
		header := response.Header.Get("AAuth-Requirement")
		if header == "" {
			return challenge, false, nil
		}
		requirement, err := aa.ParseRequirementHeader(header)
		if err != nil {
			return challenge, true, fmt.Errorf("reference: parse auth-token step-up requirement: %w", err)
		}
		if requirement.Type != aa.RequirementAuthToken {
			return challenge, false, nil
		}
		challenge.requirement = requirement
		return challenge, true, nil
	case http.StatusAccepted:
		if response.Header.Get("AAuth-Requirement") == "" {
			return challenge, false, nil
		}
		deferred, err := aa.ParseDeferredResponse(response)
		if err != nil {
			return challenge, true, fmt.Errorf("reference: parse deferred auth-token step-up requirement: %w", err)
		}
		if deferred.Requirement == nil || deferred.Requirement.Type != aa.RequirementAuthToken {
			return challenge, false, nil
		}
		if deferred.Location == "" {
			return challenge, true, errors.New("reference: deferred auth-token step-up has no completion location")
		}
		challenge.requirement = *deferred.Requirement
		challenge.completionTarget = deferred.Location
		return challenge, true, nil
	default:
		return challenge, false, nil
	}
}

func (agent *Agent) finishAuthTokenStepUp(
	ctx context.Context,
	call AuthorizedCall,
	resource string,
	personServerEndpoint string,
	current Grant,
	challenge authTokenChallenge,
) (*http.Response, Grant, error) {
	resourceGrant, err := agent.resourceGrantFromAuthChallenge(ctx, resource, current.Claims, challenge.requirement.ResourceToken)
	if err != nil {
		return nil, Grant{}, err
	}
	upgraded, err := agent.ExchangeResourceToken(ctx, personServerEndpoint, resourceGrant)
	if err != nil {
		return nil, Grant{}, err
	}
	completion := call
	if challenge.completionTarget != "" {
		completionResource, endpointErr := endpointIdentifier(challenge.completionTarget)
		if endpointErr != nil || completionResource != resource {
			return nil, Grant{}, errors.New("reference: deferred auth-token step-up completion moved outside the resource")
		}
		completion = AuthorizedCall{Method: http.MethodGet, Endpoint: challenge.completionTarget}
	}
	response, err := agent.DoAuthorizedRequest(ctx, completion, upgraded)
	if err != nil && challenge.completionTarget != "" {
		response, err = agent.DoAuthorizedRequest(ctx, completion, upgraded)
	}
	if err != nil {
		return nil, Grant{}, err
	}
	return response, upgraded, nil
}

func (agent *Agent) validateExistingAuthGrant(ctx context.Context, resource string, grant Grant) error {
	if grant.Resource != resource || grant.AuthToken == "" {
		return errors.New("reference: existing auth-token grant does not apply to endpoint")
	}
	evidence, err := aa.VerifyAuthToken(ctx, grant.AuthToken, agent.keyResolver, agent.clock)
	if err != nil {
		return fmt.Errorf("reference: verify existing auth-token grant: %w", err)
	}
	var authR3 r3.TokenResult
	var authBudget budgets.TokenResult
	if grant.R3 == nil && grant.Budget == nil {
		grantClaims, claimsErr := claimsWithoutAuthorization(evidence)
		if claimsErr != nil {
			return claimsErr
		}
		if !reflect.DeepEqual(grantClaims, grant.Claims) {
			return errors.New("reference: existing auth-token grant claims do not match its compact token")
		}
	} else {
		_, authR3, authBudget, err = validateAuthCompanions(evidence, grant.R3 != nil, grant.Budget != nil)
		if err != nil {
			return err
		}
		grantClaims, claimsErr := evidence.Claims()
		if claimsErr != nil {
			return claimsErr
		}
		if !reflect.DeepEqual(grantClaims, grant.Claims) {
			return errors.New("reference: existing auth-token grant claims do not match its compact token")
		}
	}
	if grant.R3 != nil && (authR3.CoreEvidenceID() != grant.R3.CoreEvidenceID() || authR3.URI() != grant.R3.URI() || authR3.Digest() != grant.R3.Digest()) {
		return errors.New("reference: existing R3 grant does not match its compact token")
	}
	if grant.Budget != nil && authBudget.CoreEvidenceID() != grant.Budget.CoreEvidenceID() {
		return errors.New("reference: existing Budget grant does not match its compact token")
	}
	if grant.Claims.Audience != resource {
		return errors.New("reference: existing auth-token grant does not target endpoint")
	}
	requiredScopes, err := parseScopes(grant.Claims.Scope)
	if err != nil {
		return err
	}
	return aa.ValidateCurrentAuthTokenContext(
		grant.Claims,
		resource,
		grant.Claims.PersonServer,
		grant.Claims.Subject,
		agent.signingKey.PublicJWK(),
		requiredScopes,
	)
}

func (agent *Agent) resourceGrantFromAuthChallenge(
	ctx context.Context,
	resource string,
	current aa.AuthTokenClaims,
	compact string,
) (ResourceGrant, error) {
	var grant ResourceGrant
	evidence, err := aa.VerifyResourceToken(ctx, compact, agent.keyResolver, agent.clock)
	if err != nil {
		return grant, err
	}
	members, err := evidence.AuthorizationMembers()
	if err != nil {
		return grant, err
	}
	var resourceR3 r3.TokenResult
	var resourceBudget budgets.TokenResult
	_, hasR3 := members["r3_uri"]
	_, hasBudget := members["budget"]
	if hasR3 {
		resourceR3, err = r3.ValidateResourceToken(evidence)
	}
	if err == nil && hasBudget {
		resourceBudget, err = budgets.ValidateResourceToken(evidence)
	}
	if err == nil && !hasR3 && !hasBudget {
		err = evidence.RequireNoAuthorizationMembers()
	}
	if err != nil {
		return grant, err
	}
	claims, err := evidence.Claims()
	if err != nil {
		return grant, err
	}
	thumbprint, err := agent.signingKey.PublicJWK().Thumbprint()
	if err != nil {
		return grant, err
	}
	if claims.Issuer != resource || claims.Audience != current.Issuer ||
		claims.PersonServer != current.PersonServer || claims.Subject != current.Subject ||
		claims.AgentJKT != thumbprint || claims.MissionS256 != current.MissionS256 ||
		claims.Tenant != current.Tenant || claims.Account != current.Account {
		return grant, errors.New("reference: step-up resource token does not match the existing auth-token context")
	}
	if _, err := parseScopes(claims.Scope); err != nil {
		return grant, errors.New("reference: step-up resource token carries an invalid scope")
	}
	grant = ResourceGrant{
		Resource: resource, ResourceToken: compact, Claims: claims,
		R3: optionalR3Result(resourceR3), Budget: optionalBudgetResult(resourceBudget),
	}
	return grant, nil
}
