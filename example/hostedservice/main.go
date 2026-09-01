// The hosted-service example composes the launch-profile paths on one set of
// AAuth roles. Its default uses hosted enrollment; --self-hosted uses a
// user-controlled Agent Provider and proof key against the same hosted roles.
// It demonstrates protocol boundaries; applications still own account login,
// administrative authentication, persistence, and connector credentials.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	clientagent "gitlab.com/sidecat-dev/aauth-go/agent"
	"gitlab.com/sidecat-dev/aauth-go/budgets"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

const (
	agentProviderID  = "https://agents.example"
	agentID          = "aauth:hosted-worker@agents.example"
	personServerID   = "https://person.example"
	hostedResourceID = "https://service.example"
	localResourceID  = "https://local.example"
	hostedAccountID  = "account-primary"
)

func main() {
	selfHosted := flag.Bool("self-hosted", false, "use a self-hosted Agent instead of hosted enrollment")
	flag.Parse()
	if flag.NArg() != 0 {
		log.Fatal("hosted-service example: no positional arguments are accepted")
	}
	runner := run
	if *selfHosted {
		runner = runSelfHosted
	}
	if err := runner(os.Stdout); err != nil {
		log.Fatal(err)
	}
}

func run(output io.Writer) error {
	return runProfile(output, false)
}

func runSelfHosted(output io.Writer) error {
	return runProfile(output, true)
}

func runProfile(output io.Writer, selfHosted bool) error {
	return runProfileForAccountObserved(output, selfHosted, hostedAccountID, nil)
}

func runProfileForAccount(output io.Writer, selfHosted bool, requestedAccount string) error {
	return runProfileForAccountObserved(output, selfHosted, requestedAccount, nil)
}

func runProfileForAccountObserved(
	output io.Writer,
	selfHosted bool,
	requestedAccount string,
	observations *profileObservations,
) error {
	if output == nil {
		return errors.New("hosted-service example: output is required")
	}
	ctx := context.Background()
	now := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
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
	personGrant, err := budgets.NewValue(100_000, unit)
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
	var bootstrap bootstrappedAgent
	if selfHosted {
		bootstrap, err = bootstrapSelfHostedAgent(ctx, clock, network, httpClient, resolver, registry, agentKey)
		if err != nil {
			return err
		}
		if _, err := fmt.Fprintln(output, "1. self-hosted Agent token for hosted Person Server complete"); err != nil {
			return err
		}
	} else {
		providerKey, err := newSigningKey("hosted-provider-key")
		if err != nil {
			return err
		}
		durableKey, err := newSigningKey("hosted-durable-key")
		if err != nil {
			return err
		}
		bootstrap, err = bootstrapHostedAgent(
			ctx, now, clock, network, httpClient, resolver, registry,
			providerKey, durableKey, agentKey,
		)
		if err != nil {
			return err
		}
		if _, err := fmt.Fprintln(output, "1. enrollment + delegated Agent-token refresh complete"); err != nil {
			return err
		}
	}

	roles, err := composeRoles(roleInputs{
		clock: clock, resolver: resolver, network: network, httpClient: httpClient,
		personKey: personKey, resourceKey: resourceKey,
		registry: registry, definitions: definitions, operation: operation, definition: definition,
		account: hostedAccountID, observations: observations,
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
	mission, err := approveMission(ctx, now, bootstrap.client, roles.people)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintln(output, "3. reviewed mission supplied the connector Person token and approved tool"); err != nil {
		return err
	}
	if err := callHostedConnector(
		ctx, bootstrap.client, operationSet, requestedBudget, requestedAccount, mission, roles.connector,
	); err != nil {
		return err
	}
	if err := bootstrap.client.CompleteMission(ctx, clientagent.MissionCompletionRequest{
		PersonServer: personServerID, MissionS256: mission.Mission().S256,
		Summary: "Recovered connector query completed",
	}); err != nil {
		return err
	}
	missionPersonToken, ok := mission.PersonToken(hostedResourceID)
	if !ok {
		return errors.New("hosted-service example: completed mission lost its Person token")
	}
	lateResourceToken, err := bootstrap.client.Authorize(ctx, clientagent.AuthorizeRequest{
		Resource: hostedResourceID, PersonToken: missionPersonToken,
		Account: &requestedAccount, R3Operations: &operationSet, Budget: &requestedBudget,
	})
	if err != nil {
		return err
	}
	if _, err := bootstrap.client.Exchange(ctx, clientagent.ExchangeRequest{
		PersonServer: personServerID, ResourceToken: lateResourceToken,
	}); err == nil {
		return errors.New("hosted-service example: completed mission authorized more connector work")
	}
	if _, err := fmt.Fprintln(output, "4. account-bound MCP operation authorized; exhausted call recovered; person-accepted mission completion retained"); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(output, "5. OAuth service credential remained inside the connector application"); err != nil {
		return err
	}
	if bootstrap.provider != nil {
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
	return nil
}
