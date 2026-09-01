package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	clientagent "gitlab.com/sidecat-dev/aauth-go/agent"
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/personserver"
	"gitlab.com/sidecat-dev/aauth-go/resource"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

func hostedHandlers(
	resolver signaturekey.KeyResolver,
	clock aauth.Clock,
	personKey jose.SigningKey,
	resourceKey jose.SigningKey,
) (http.Handler, http.Handler, error) {
	tokenIDs := []string{"hosted-person-token", "hosted-auth-token"}
	people, err := personserver.NewPSAuthorization(personserver.PSAuthorizationConfig{
		Issuer: hostedPersonID, SigningKey: personKey, KeyResolver: resolver, Clock: clock,
		Tokens: newPersonTokenStore(),
		NewID: func() string {
			id := tokenIDs[0]
			tokenIDs = tokenIDs[1:]
			return id
		},
		BindPerson: func(_ context.Context, request personserver.PersonTokenRequest) (personserver.Person, error) {
			if request.Agent != agentID || request.Resource != hostedResource {
				return personserver.Person{}, errors.New("self-hosted example: unexpected hosted account binding")
			}
			return personserver.Person{Subject: "account-123", Lifetime: time.Hour}, nil
		},
		Authorize: func(_ context.Context, request personserver.AuthorizationRequest) (personserver.AuthorizationDecision, error) {
			if request.Agent != agentID || request.Resource != hostedResource ||
				request.Subject != "account-123" || len(request.Scopes) != 1 || request.Scopes[0] != hostedScope {
				return personserver.AuthorizationDecision{}, errors.New("self-hosted example: unexpected hosted authorization")
			}
			return personserver.AuthorizationDecision{Scopes: []string{hostedScope}, Lifetime: 30 * time.Minute}, nil
		},
	})
	if err != nil {
		return nil, nil, err
	}
	service, err := resource.NewPSAuthorization(resource.PSAuthorizationConfig{
		Issuer: hostedResource, SigningKey: resourceKey, KeyResolver: resolver, Clock: clock,
		NewID:             func() string { return "hosted-resource-token" },
		ScopeDescriptions: map[string]string{hostedScope: "Read hosted records"},
		RequiredScopes:    func(*http.Request) []string { return []string{hostedScope} },
		ResolvePerson: func(_ context.Context, identity resource.PersonIdentity, _ resource.PersonContext) error {
			if identity.Issuer != hostedPersonID || identity.Subject != "account-123" {
				return errors.New("self-hosted example: unexpected hosted person")
			}
			return nil
		},
		Protected: http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			principal, ok := resource.AuthPrincipalFromContext(request.Context())
			if !ok {
				http.Error(response, "missing AAuth principal", http.StatusInternalServerError)
				return
			}
			_, _ = fmt.Fprintf(response, "%s has %s", principal.Subject, principal.Scope[0])
		}),
	})
	if err != nil {
		return nil, nil, err
	}
	return people.Handler(), service.Handler(), nil
}

func callHostedResource(ctx context.Context, output io.Writer, client *clientagent.Client) error {
	personResult, err := client.PersonToken(ctx, clientagent.PersonTokenRequest{
		PersonServer: hostedPersonID, Resource: hostedResource,
	})
	if err != nil {
		return err
	}
	personToken, ok := personResult.Token()
	if !ok {
		return errors.New("self-hosted example: hosted Person Server unexpectedly required interaction")
	}
	resourceToken, err := client.Authorize(ctx, clientagent.AuthorizeRequest{
		Resource: hostedResource, PersonToken: personToken, Scopes: []string{hostedScope},
	})
	if err != nil {
		return err
	}
	authToken, err := client.Exchange(ctx, clientagent.ExchangeRequest{
		PersonServer: hostedPersonID, ResourceToken: resourceToken,
	})
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, hostedResource+"/records", nil)
	if err != nil {
		return err
	}
	response, err := client.Do(ctx, clientagent.Call{Request: request, AuthToken: authToken})
	if err != nil {
		return err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return err
	}
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("hosted Resource returned %s: %s", response.Status, body)
	}
	_, err = fmt.Fprintf(output, "AAuth hosted Resource accepted: %s\n", body)
	return err
}
