package resource

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	aauth "github.com/aauth-dev/auth-go"
	"github.com/aauth-dev/auth-go/jose"
	"github.com/aauth-dev/auth-go/signaturekey"
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
	if claims.MissionS256 != "" {
		writeProblem(response, http.StatusBadRequest, "invalid_person_token", errors.New("mission-bound person tokens require mission verification"))
		return
	}
	var input struct {
		Scope        string          `json:"scope"`
		Account      json.RawMessage `json:"account"`
		R3Operations json.RawMessage `json:"r3_operations"`
		Budget       json.RawMessage `json:"budget"`
	}
	if err := decodeJSON(request.Body, &input); err != nil {
		writeProblem(response, http.StatusBadRequest, "invalid_request", err)
		return
	}
	for name, value := range map[string]json.RawMessage{
		"account": input.Account, "r3_operations": input.R3Operations, "budget": input.Budget,
	} {
		if value != nil {
			writeProblem(response, http.StatusBadRequest, "invalid_request", fmt.Errorf("request member %q is not supported by the immediate resource flow", name))
			return
		}
	}
	scopes, err := server.validateScopes(input.Scope)
	if err != nil {
		writeProblem(response, http.StatusBadRequest, "invalid_scope", err)
		return
	}
	compact, err := server.issueResourceToken(proof.VerifiedAt(), proof.PublicKey(), claims, scopes)
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

func (server *Server) issueResourceToken(
	verifiedAt time.Time,
	requestKey jose.JWK,
	person aauth.PersonTokenClaims,
	scopes []string,
) (string, error) {
	agentJKT, err := requestKey.Thumbprint()
	if err != nil {
		return "", err
	}
	audience := server.accessServer
	if server.authorizationTopology == authorizationTopologyPersonServer {
		audience = person.Issuer
	}
	return aauth.MintResourceToken(server.signingKey, aauth.ResourceTokenClaims{
		Issuer:       server.issuer,
		DWK:          aauth.ResourceDiscoveryDocument,
		Audience:     audience,
		JTI:          server.newID(),
		AgentJKT:     agentJKT,
		IssuedAt:     verifiedAt.Unix(),
		ExpiresAt:    verifiedAt.Add(5 * time.Minute).Unix(),
		Scope:        strings.Join(scopes, " "),
		PersonServer: person.Issuer,
		Subject:      person.Subject,
		PresentedJTI: person.JTI,
		MissionS256:  person.MissionS256,
		Tenant:       person.Tenant,
	})
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
