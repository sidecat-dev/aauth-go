// The interaction-relay example forwards missionless and mission-bound
// Resource-hosted interactions to a Person Server and observes engagement.
// The Resource's own pending URL remains authoritative for the underlying work.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	clientagent "gitlab.com/sidecat-dev/aauth-go/agent"
	"gitlab.com/sidecat-dev/aauth-go/agentprovider"
	"gitlab.com/sidecat-dev/aauth-go/internal/exampleutil"
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/personserver"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

const (
	agentProviderID = "https://agents.example"
	agentID         = "aauth:operator@agents.example"
	personServerID  = "https://person.example"
)

func main() {
	if err := run(os.Stdout); err != nil {
		log.Fatal(err)
	}
}

func run(output io.Writer) error {
	if output == nil {
		return errors.New("output is required")
	}
	ctx := context.Background()
	now := time.Date(2026, 9, 1, 4, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	providerKey, err := newSigningKey("agent-provider-key")
	if err != nil {
		return err
	}
	agentKey, err := newSigningKey("agent-key")
	if err != nil {
		return err
	}
	personKey, err := newSigningKey("person-server-key")
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
	provider, err := agentprovider.New(agentprovider.Config{
		Issuer: agentProviderID, SigningKey: providerKey, Clock: clock,
		NewID: func() string { return "agent-token-1" },
	})
	if err != nil {
		return err
	}
	agentToken, err := provider.Issue(aauth.AgentTokenRequest{
		Agent: agentID, PersonServer: personServerID,
		PublicKey: agentKey.PublicJWK(), Lifetime: time.Hour,
	})
	if err != nil {
		return err
	}

	relayStore := exampleutil.NewMissionInteractionRelayStore()
	missionExpiry := now.Add(30 * time.Minute)
	mission, err := aauth.EncodeMission(aauth.MissionBlob{
		Approver: personServerID, Agent: agentID, ApprovedAt: now.Add(-time.Minute),
		ExpiresAt: &missionExpiry, Description: "Complete the approved confirmation.",
	})
	if err != nil {
		return err
	}
	if err := relayStore.CommitMission(ctx, personserver.MissionRecord{
		S256: mission.S256, Agent: agentID, ExactJSON: mission.ExactJSON,
		ApprovedAt: mission.Blob.ApprovedAt, ExpiresAt: missionExpiry,
		State: personserver.MissionActive,
	}, nil); err != nil {
		return err
	}
	people, err := personserver.NewPSAuthorization(personserver.PSAuthorizationConfig{
		Issuer: personServerID, SigningKey: personKey, KeyResolver: resolver,
		Clock: clock, Tokens: relayStore, NewID: func() string { return "unused-person-token" },
		BindPerson: func(context.Context, personserver.PersonTokenRequest) (personserver.Person, error) {
			return personserver.Person{Subject: "person", Lifetime: time.Minute}, nil
		},
		Authorize: func(context.Context, personserver.AuthorizationRequest) (personserver.AuthorizationDecision, error) {
			return personserver.AuthorizationDecision{Scopes: []string{"unused"}, Lifetime: time.Minute}, nil
		},
		Missions: &personserver.MissionConfig{
			Approve: func(context.Context, personserver.MissionApprovalRequest) (personserver.MissionDecision, error) {
				return personserver.MissionDecision{}, errors.New("mission approval is not used in this example")
			},
			AcceptUpdate: func(context.Context, personserver.MissionUpdatePolicyRequest) error {
				return errors.New("mission update is not used in this example")
			},
			ConfirmPersonAcceptedCompletion: func(context.Context, personserver.MissionCompletionPolicyRequest) error {
				return errors.New("mission completion is not used in this example")
			},
		},
		InteractionRelay: &personserver.InteractionRelayConfig{
			Policy: func(_ context.Context, request personserver.InteractionRelayPolicyRequest) (personserver.InteractionRelayPendingPolicy, error) {
				format := "Person Server relayed: %s %s\n"
				if request.Mission != nil {
					format = "Person Server relayed under mission: %s %s\n"
				}
				if _, err := fmt.Fprintf(output, format, request.Document.Relay.URL, request.Document.Relay.Code); err != nil {
					return personserver.InteractionRelayPendingPolicy{}, err
				}
				return personserver.InteractionRelayPendingPolicy{Lifetime: time.Minute}, nil
			},
		},
	})
	if err != nil {
		return err
	}
	network.Handle(agentProviderID, provider.Handler())
	network.Handle(personServerID, people.Handler())

	operator, err := clientagent.New(ctx, clientagent.Config{
		Identifier: agentID, SigningKey: agentKey, AgentToken: agentToken,
		KeyResolver: resolver, HTTPClient: httpClient, Clock: clock,
	})
	if err != nil {
		return err
	}
	result, err := operator.RequestInteractionRelay(ctx, clientagent.InteractionRelayRequest{
		PersonServer: personServerID,
		Relay: aauth.InteractionRelay{
			Type: aauth.InteractionRelayInteraction,
			URL:  "https://resource.example/confirm",
			Code: "ABCD-EFGH",
		},
	})
	if err != nil {
		return err
	}
	pending, ok := result.Pending()
	if !ok {
		return errors.New("Person Server did not return a pending relay")
	}
	reference := strings.TrimPrefix(pending.Location(), personServerID+"/interaction/relay/")
	handle, err := people.ResumeInteractionRelay(ctx, reference)
	if err != nil {
		return err
	}
	if err := people.MarkInteractionRelayEngaged(ctx, handle); err != nil {
		return err
	}
	result, err = operator.PollInteractionRelay(ctx, pending)
	if err != nil {
		return err
	}
	completion, ok := result.Completion()
	if !ok {
		return errors.New("Person Server did not return a terminal relay state")
	}
	_, err = fmt.Fprintf(output, "Agent observed relay state: %s\n", completion.Completion.Status)
	if err != nil {
		return err
	}

	missionResult, err := operator.RequestInteractionRelay(ctx, clientagent.InteractionRelayRequest{
		PersonServer: personServerID,
		Relay: aauth.InteractionRelay{
			Type: aauth.InteractionRelayInteraction, URL: "https://resource.example/confirm",
			Code: "ABCD-EFGH", MissionS256: mission.S256,
		},
	})
	if err != nil {
		return err
	}
	missionPending, ok := missionResult.Pending()
	if !ok {
		return errors.New("Person Server did not return a pending mission relay")
	}
	missionReference := strings.TrimPrefix(missionPending.Location(), personServerID+"/interaction/relay/")
	missionHandle, err := people.ResumeInteractionRelay(ctx, missionReference)
	if err != nil {
		return err
	}
	missionContext, ok := missionHandle.Mission()
	if !ok || missionContext.S256 != mission.S256 {
		return errors.New("Person Server resumed the wrong relay mission")
	}
	if err := people.MarkInteractionRelayEngaged(ctx, missionHandle); err != nil {
		return err
	}
	missionResult, err = operator.PollInteractionRelay(ctx, missionPending)
	if err != nil {
		return err
	}
	missionCompletion, ok := missionResult.Completion()
	if !ok {
		return errors.New("Person Server did not return a terminal mission relay state")
	}
	_, err = fmt.Fprintf(output, "Agent observed mission relay state: %s\n", missionCompletion.Completion.Status)
	return err
}

func newSigningKey(id string) (jose.SigningKey, error) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return jose.SigningKey{}, err
	}
	return jose.NewEd25519SigningKey(id, privateKey)
}
