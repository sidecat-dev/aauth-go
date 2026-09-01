package resource

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/budgets"
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/r3"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

const maximumAuthorizationRequestBytes = 64 << 10

func (server *Server) serveAuthorization(response http.ResponseWriter, request *http.Request) {
	proof, claims, err := server.verifyAuthorizationPersonRequest(request)
	if err != nil {
		writeAuthorizationProblem(response, err)
		return
	}
	if err := aauth.ValidatePersonTokenContext(claims, server.issuer, proof.PublicKey()); err != nil {
		writeProblem(response, http.StatusBadRequest, "invalid_person_token", err)
		return
	}
	var input struct {
		Scope        json.RawMessage `json:"scope"`
		Account      json.RawMessage `json:"account"`
		R3Operations json.RawMessage `json:"r3_operations"`
		Budget       json.RawMessage `json:"budget"`
	}
	if err := decodeJSON(request.Body, &input); err != nil {
		writeProblem(response, http.StatusBadRequest, "invalid_request", err)
		return
	}
	if input.Account != nil && input.R3Operations == nil {
		writeProblem(response, http.StatusBadRequest, "invalid_request", errors.New("request member \"account\" is not supported by the immediate Core resource flow"))
		return
	}
	if input.Budget != nil && server.budget == nil {
		writeProblem(response, http.StatusBadRequest, "invalid_request", errors.New("request member \"budget\" is not supported by the immediate resource flow"))
		return
	}
	var operations *r3.OperationSet
	if input.R3Operations != nil {
		validated, err := server.parseR3Operations(input.R3Operations)
		if err != nil {
			writeProblem(response, http.StatusBadRequest, "invalid_request", err)
			return
		}
		operations = &validated
	}
	var scopes []string
	if input.Scope != nil {
		if bytes.Equal(bytes.TrimSpace(input.Scope), []byte("null")) {
			writeProblem(response, http.StatusBadRequest, "invalid_scope", errors.New("authorization scope must be a string, not null"))
			return
		}
		var scope string
		if err := json.Unmarshal(input.Scope, &scope); err != nil {
			writeProblem(response, http.StatusBadRequest, "invalid_scope", fmt.Errorf("authorization scope must be a string: %w", err))
			return
		}
		validated, err := server.validateScopes(scope)
		if err != nil {
			writeProblem(response, http.StatusBadRequest, "invalid_scope", err)
			return
		}
		scopes = validated
	} else if operations == nil {
		writeProblem(response, http.StatusBadRequest, "invalid_scope", errors.New("authorization requires Core scope or configured companion operations"))
		return
	}
	account, err := server.validateAuthorizationAccount(request, claims, input.Account)
	if err != nil {
		writeProblem(response, http.StatusBadRequest, "invalid_account", err)
		return
	}
	var budgetOffer *budgets.Value
	if input.Budget != nil {
		offer, err := server.budget.offerFor(request.Context(), claims, scopes, input.Budget)
		if err != nil {
			var policyFailure *budgetOfferPolicyError
			if errors.As(err, &policyFailure) {
				writeProblem(response, http.StatusInternalServerError, "server_error", err)
				return
			}
			writeProblem(response, http.StatusBadRequest, "invalid_budget", err)
			return
		}
		budgetOffer = &offer
	}
	compact, err := server.issueAuthorizationResourceToken(
		request, proof.VerifiedAt(), proof.PublicKey(), claims, scopes, account, operations, budgetOffer,
	)
	if err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", err)
		return
	}
	writeJSON(response, http.StatusOK, struct {
		ResourceToken string `json:"resource_token"`
	}{ResourceToken: compact})
}

func (server *Server) verifyAuthorizationPersonRequest(
	request *http.Request,
) (signaturekey.VerifiedRequest, aauth.PersonTokenClaims, error) {
	prepared, compact, err := server.prepareJWTRequest(
		request,
		authorizationSignatureComponents(server.additionalSignatureComponents),
	)
	if err != nil {
		return signaturekey.VerifiedRequest{}, aauth.PersonTokenClaims{}, err
	}
	return server.verifyPreparedPersonRequest(request, prepared, compact)
}

func authorizationSignatureComponents(additional []string) []string {
	components := []string{"content-type", "content-digest"}
	seen := map[string]struct{}{"content-type": {}, "content-digest": {}}
	for _, component := range additional {
		if _, exists := seen[component]; exists {
			continue
		}
		seen[component] = struct{}{}
		components = append(components, component)
	}
	return components
}

func (server *Server) issueAuthorizationResourceToken(
	request *http.Request,
	verifiedAt time.Time,
	requestKey jose.JWK,
	person aauth.PersonTokenClaims,
	scopes []string,
	account *string,
	operations *r3.OperationSet,
	budgetOffer *budgets.Value,
) (string, error) {
	claims, err := server.resourceTokenClaims(verifiedAt, requestKey, person, scopes, account)
	if err != nil {
		return "", err
	}
	if budgetOffer != nil {
		if operations != nil {
			compact, err := server.issueR3ResourceToken(request.Context(), claims, person, *operations, budgetOffer)
			if err != nil {
				return "", err
			}
			if err := server.retainBudgetLineage(request, claims, scopes, *budgetOffer); err != nil {
				return "", err
			}
			return compact, nil
		}
		compact, err := budgets.MintResourceToken(server.signingKey, claims, *budgetOffer, nil)
		if err != nil {
			return "", err
		}
		if err := server.retainBudgetLineage(request, claims, scopes, *budgetOffer); err != nil {
			return "", err
		}
		return compact, nil
	}
	if operations == nil {
		return aauth.MintResourceToken(server.signingKey, claims)
	}
	return server.issueR3ResourceToken(request.Context(), claims, person, *operations, nil)
}

func (server *Server) retainBudgetLineage(
	request *http.Request,
	claims aauth.ResourceTokenClaims,
	scopes []string,
	offer budgets.Value,
) error {
	if err := server.budget.retain(request.Context(), BudgetLineage{
		ResourceToken: aauth.TokenReference{Issuer: claims.Issuer, JTI: claims.JTI},
		Person:        PersonIdentity{Issuer: claims.PersonServer, Subject: claims.Subject},
		PersonContext: PersonContext{MissionS256: claims.MissionS256, Tenant: claims.Tenant},
		PresentedJTI:  claims.PresentedJTI,
		AgentJKT:      claims.AgentJKT,
		Scope:         append([]string(nil), scopes...),
		Offer:         offer,
		IssuedAt:      claims.IssuedAt,
		ExpiresAt:     claims.ExpiresAt,
	}); err != nil {
		return fmt.Errorf("retain Resource Budget lineage: %w", err)
	}
	return nil
}

func (server *Server) issueResourceToken(
	verifiedAt time.Time,
	requestKey jose.JWK,
	person aauth.PersonTokenClaims,
	scopes []string,
) (string, error) {
	claims, err := server.resourceTokenClaims(verifiedAt, requestKey, person, scopes, nil)
	if err != nil {
		return "", err
	}
	return aauth.MintResourceToken(server.signingKey, claims)
}

func (server *Server) resourceTokenClaims(
	verifiedAt time.Time,
	requestKey jose.JWK,
	person aauth.PersonTokenClaims,
	scopes []string,
	account *string,
) (aauth.ResourceTokenClaims, error) {
	agentJKT, err := requestKey.Thumbprint()
	if err != nil {
		return aauth.ResourceTokenClaims{}, err
	}
	audience := server.accessServer
	if server.authorizationTopology == authorizationTopologyPersonServer {
		audience = person.Issuer
	}
	expiresAt := verifiedAt.Add(5 * time.Minute)
	if person.MissionS256 != "" {
		personExpiresAt := time.Unix(person.ExpiresAt, 0)
		if personExpiresAt.Before(expiresAt) {
			expiresAt = personExpiresAt
		}
	}
	return aauth.ResourceTokenClaims{
		Issuer:       server.issuer,
		DWK:          aauth.ResourceDiscoveryDocument,
		Audience:     audience,
		JTI:          server.newID(),
		AgentJKT:     agentJKT,
		IssuedAt:     verifiedAt.Unix(),
		ExpiresAt:    expiresAt.Unix(),
		Scope:        strings.Join(scopes, " "),
		Account:      cloneAuthorizationAccount(account),
		PersonServer: person.Issuer,
		Subject:      person.Subject,
		PresentedJTI: person.JTI,
		MissionS256:  person.MissionS256,
		Tenant:       person.Tenant,
	}, nil
}

func (server *Server) validateAuthorizationAccount(
	request *http.Request,
	person aauth.PersonTokenClaims,
	raw json.RawMessage,
) (*string, error) {
	if raw == nil {
		return nil, nil
	}
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return nil, fmt.Errorf("aauth: authorization account must be a string, not null")
	}
	var account string
	if err := json.Unmarshal(raw, &account); err != nil {
		return nil, fmt.Errorf("aauth: authorization account must be a string: %w", err)
	}
	if server.validateAccount == nil {
		return nil, fmt.Errorf("aauth: Resource does not accept account-bound authorization")
	}
	identity := PersonIdentity{Issuer: person.Issuer, Subject: person.Subject}
	if err := server.validateAccount(request.Context(), identity, account); err != nil {
		return nil, err
	}
	return &account, nil
}

func cloneAuthorizationAccount(account *string) *string {
	if account == nil {
		return nil
	}
	cloned := *account
	return &cloned
}

func (server *Server) validateScopes(scope string) ([]string, error) {
	values, err := aauth.ParseScope(scope)
	if err != nil {
		return nil, err
	}
	for _, value := range values {
		if _, ok := server.scopeDescriptions[value]; !ok {
			return nil, fmt.Errorf("aauth: scope %q is not declared", value)
		}
	}
	return values, nil
}
