// The audit example runs one mission-bound local action and records it at the
// Person Server. The application performs the action; AAuth carries the exact
// post-action record.
package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	clientagent "gitlab.com/sidecat-dev/aauth-go/agent"
	"gitlab.com/sidecat-dev/aauth-go/agentprovider"
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/personserver"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
	"gitlab.com/sidecat-dev/aauth-go/testutil"
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
	now := time.Date(2026, 9, 1, 0, 45, 0, 0, time.UTC)
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
		// The in-memory network makes no connection. Leave this unset with a
		// network transport, so the resolver checks every destination.
		TransportEnforcesEgress: true,
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
	agentToken, err := provider.Issue(ctx, aauth.AgentTokenRequest{
		Agent: agentID, PersonServer: personServerID,
		PublicKey: agentKey.PublicJWK(), Lifetime: time.Hour,
	})
	if err != nil {
		return err
	}

	store := testutil.NewMissionStore()
	missionExpiry := now.Add(15 * time.Minute)
	people, err := personserver.NewPSAuthorization(personserver.PSAuthorizationConfig{
		Issuer: personServerID, SigningKey: personKey, KeyResolver: resolver,
		Clock: clock, Tokens: store, NewID: func() string { return "unused-person-token" },
		Missions: &personserver.MissionConfig{
			Approve: func(_ context.Context, request personserver.MissionApprovalRequest) (personserver.MissionDecision, error) {
				return personserver.MissionDecision{Description: request.Proposal.Description, ExpiresAt: &missionExpiry}, nil
			},
			AcceptUpdate: func(context.Context, personserver.MissionUpdatePolicyRequest) error { return nil },
			ConfirmPersonAcceptedCompletion: func(context.Context, personserver.MissionCompletionPolicyRequest) error {
				return nil
			},
		},
		Audit: &personserver.AuditConfig{},
		BindPerson: func(context.Context, personserver.PersonTokenRequest) (personserver.Person, error) {
			return personserver.Person{Subject: "person", Lifetime: time.Minute}, nil
		},
		Authorize: func(context.Context, personserver.AuthorizationRequest) (personserver.AuthorizationDecision, error) {
			return personserver.AuthorizationDecision{Scopes: []string{"unused"}, Lifetime: time.Minute}, nil
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
	missionResult, err := operator.ProposeMission(ctx, clientagent.MissionRequest{
		PersonServer: personServerID,
		Proposal:     aauth.MissionProposal{Description: "# Prepare the status report"},
	})
	if err != nil {
		return err
	}
	mission := missionResult.Mission()

	// Application code performs the action. The audit is a later report of that
	// outcome, not permission to execute it and not the execution itself.
	var report bytes.Buffer
	if _, err := report.WriteString("# Status\n\nAll systems ready.\n"); err != nil {
		return err
	}
	result, err := json.Marshal(struct {
		Status string `json:"status"`
		Bytes  int    `json:"bytes"`
	}{Status: "completed", Bytes: report.Len()})
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintln(output, "Application action complete: prepared status report"); err != nil {
		return err
	}
	if err := operator.SubmitAudit(ctx, clientagent.AuditRequest{
		PersonServer: personServerID,
		Entry: aauth.AuditEntry{
			MissionS256: mission.S256,
			Action:      "documents.prepare",
			Description: "Prepared the reviewed status report.",
			Parameters:  json.RawMessage(`{"format":"text/markdown"}`),
			Result:      result,
		},
	}); err != nil {
		return err
	}
	records, err := store.LoadMissionAuditsForAgent(ctx, agentID, mission.S256, now)
	if err != nil {
		return err
	}
	if len(records) != 1 || records[0].Document.Entry.Action != "documents.prepare" {
		return errors.New("Person Server did not retain the audit entry")
	}
	_, err = fmt.Fprintln(output, "Person Server audit retained: documents.prepare")
	return err
}

func newSigningKey(id string) (jose.SigningKey, error) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return jose.SigningKey{}, err
	}
	return jose.NewEd25519SigningKey(id, privateKey)
}
