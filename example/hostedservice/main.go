// The hosted-service example composes the launch-profile paths on one set of
// AAuth roles. It demonstrates protocol boundaries; applications still own
// account login, administrative authentication, persistence, and connector
// credentials.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/budgets"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

const (
	agentProviderID  = "https://agents.example"
	agentID          = "aauth:hosted-worker@agents.example"
	personServerID   = "https://person.example"
	hostedResourceID = "https://service.example"
	localResourceID  = "https://local.example"
)

func main() {
	if err := run(os.Stdout); err != nil {
		log.Fatal(err)
	}
}

func run(output io.Writer) error {
	if output == nil {
		return errors.New("hosted-service example: output is required")
	}
	ctx := context.Background()
	now := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	providerKey, err := newSigningKey("hosted-provider-key")
	if err != nil {
		return err
	}
	durableKey, err := newSigningKey("hosted-durable-key")
	if err != nil {
		return err
	}
	agentKey, err := newSigningKey("hosted-agent-key")
	if err != nil {
		return err
	}
	personKey, err := newSigningKey("hosted-person-key")
	if err != nil {
		return err
	}
	resourceKey, err := newSigningKey("hosted-resource-key")
	if err != nil {
		return err
	}

	registry, definitions, operationSet, operation, definition, err := hostedR3Model()
	if err != nil {
		return err
	}
	unit, err := budgets.NewUnit("USD", 6)
	if err != nil {
		return err
	}
	requestedBudget, err := budgets.NewValue(500_000, unit)
	if err != nil {
		return err
	}
	resourceOffer, err := budgets.NewValue(400_000, unit)
	if err != nil {
		return err
	}
	personGrant, err := budgets.NewValue(300_000, unit)
	if err != nil {
		return err
	}
	unitDeclaration, err := budgets.NewBoundedUnitDeclaration(unit, 1_000_000, "US dollars at micro-dollar precision")
	if err != nil {
		return err
	}

	network := newLogicalTransport()
	httpClient := &http.Client{Transport: network}
	resolver, err := signaturekey.NewHTTPKeyResolver(signaturekey.HTTPKeyResolverConfig{
		Client: httpClient, Clock: clock, Admit: network.Admit,
	})
	if err != nil {
		return err
	}
	bootstrap, err := bootstrapHostedAgent(
		ctx, now, clock, network, httpClient, resolver, registry,
		providerKey, durableKey, agentKey,
	)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintln(output, "1. enrollment + delegated Agent-token refresh complete"); err != nil {
		return err
	}

	roles, err := composeRoles(roleInputs{
		clock: clock, resolver: resolver, network: network, httpClient: httpClient,
		personKey: personKey, resourceKey: resourceKey,
		registry: registry, definitions: definitions, operation: operation, definition: definition,
		requestedBudget: requestedBudget, resourceOffer: resourceOffer,
		personGrant: personGrant, unit: unitDeclaration,
	})
	if err != nil {
		return err
	}

	if err := proveLocalAgentAccess(ctx, bootstrap.client); err != nil {
		return err
	}
	if err := grantLocalPermission(ctx, bootstrap.client); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(output, "2. missionless local permission granted"); err != nil {
		return err
	}
	if err := approveMission(ctx, now, bootstrap.client, roles.people); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(output, "3. approval-only mission reviewed and delivered"); err != nil {
		return err
	}
	if err := callHostedConnector(ctx, bootstrap.client, operationSet, requestedBudget, roles.connector); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(output, "4. MCP operation authorized; fixed Budget charged before one connector call"); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(output, "5. OAuth service credential remained inside the connector application"); err != nil {
		return err
	}
	if err := (revocationJourney{
		client: bootstrap.client, agentToken: bootstrap.agentToken, provider: bootstrap.provider,
		resolver: resolver, clock: clock, httpClient: httpClient, network: network,
		newPeople: roles.newPeople, newLocal: roles.newLocal,
	}).run(ctx); err != nil {
		return err
	}
	_, err = fmt.Fprintln(output, "6. Agent token revoked at PS and local Resource; later requests refused")
	return err
}
