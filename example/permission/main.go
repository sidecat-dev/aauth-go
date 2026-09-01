// The permission example runs missionless and mission-bound local-action
// decisions entirely in process. The library carries the request and decision;
// the application remains responsible for acting after a typed grant.
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
	now := time.Date(2026, 8, 31, 23, 45, 0, 0, time.UTC)
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

	permissions := exampleutil.NewMissionPermissionStore()
	missionExpiry := now.Add(30 * time.Minute)
	mission, err := aauth.EncodeMission(aauth.MissionBlob{
		Approver: personServerID, Agent: agentID, ApprovedAt: now.Add(-time.Minute),
		ExpiresAt: &missionExpiry, Description: "Archive the reviewed incident report.",
	})
	if err != nil {
		return err
	}
	if err := permissions.CommitMission(ctx, personserver.MissionRecord{
		S256: mission.S256, Agent: agentID, ExactJSON: mission.ExactJSON,
		ApprovedAt: mission.Blob.ApprovedAt, ExpiresAt: missionExpiry,
		State: personserver.MissionActive,
	}, nil); err != nil {
		return err
	}
	people, err := personserver.NewPSAuthorization(personserver.PSAuthorizationConfig{
		Issuer: personServerID, SigningKey: personKey, KeyResolver: resolver,
		Clock: clock, NewID: func() string { return "unused-token" },
		Tokens: permissions,
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
		Permission: &personserver.PermissionConfig{
			Policy: func(_ context.Context, request personserver.PermissionPolicyRequest) (personserver.PermissionPolicyResult, error) {
				validMissionless := request.Mission == nil && request.Action == "messages.send"
				validMission := request.Mission != nil && request.Mission.S256 == mission.S256 &&
					request.Action == "reports.archive"
				if request.Agent != agentID || (!validMissionless && !validMission) {
					return personserver.PermissionPolicyResult{}, errors.New("unexpected permission request")
				}
				return personserver.PermissionPolicyResult{Deferred: &personserver.PermissionPendingPolicy{
					Lifetime: 5 * time.Minute, RetryAfter: 0,
				}}, nil
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
	result, err := operator.RequestPermission(ctx, clientagent.PermissionRequest{
		PersonServer: personServerID,
		Action:       "messages.send",
		Description:  "Send the prepared status message.",
		Parameters:   []byte(`{"channel":"ops","body":"ready"}`),
	})
	if err != nil {
		return err
	}
	pending, ok := result.Pending()
	if !ok {
		return errors.New("Person Server did not defer the permission request")
	}
	if _, err := fmt.Fprintln(output, "Permission request retained: messages.send is pending"); err != nil {
		return err
	}

	// The host authenticates the person independently. Before rendering the
	// request, it sanitizes Description and validates Parameters for the named
	// action. Possession of the opaque reference is not approval authority.
	reference := strings.TrimPrefix(pending.Location(), personServerID+"/permission/pending/")
	hostRequest, err := people.ResumePermission(ctx, reference)
	if err != nil {
		return err
	}
	if hostRequest.Action() != "messages.send" {
		return errors.New("Person Server resumed an unexpected action")
	}
	if err := people.GrantPermission(ctx, hostRequest); err != nil {
		return err
	}
	completion, err := operator.PollPermission(ctx, pending)
	if err != nil {
		return err
	}
	decision, ok := completion.Decision()
	if !ok || decision.Permission() != aauth.PermissionGranted {
		return errors.New("permission request was not granted")
	}

	// This is application behavior, not AAuth behavior. The application chooses
	// what messages.send means and invokes it exactly once after the typed grant.
	if _, err := fmt.Fprintln(output, "Permission granted: application sent one message"); err != nil {
		return err
	}

	missionResult, err := operator.RequestPermission(ctx, clientagent.PermissionRequest{
		PersonServer: personServerID, MissionS256: mission.S256,
		Action: "reports.archive", Description: "Archive the reviewed incident report.",
	})
	if err != nil {
		return err
	}
	missionPending, ok := missionResult.Pending()
	if !ok {
		return errors.New("Person Server did not defer the mission permission request")
	}
	missionReference := strings.TrimPrefix(missionPending.Location(), personServerID+"/permission/pending/")
	missionRequest, err := people.ResumePermission(ctx, missionReference)
	if err != nil {
		return err
	}
	missionContext, ok := missionRequest.Mission()
	if !ok || missionContext.S256 != mission.S256 {
		return errors.New("Person Server resumed the wrong mission")
	}
	if err := people.GrantPermission(ctx, missionRequest); err != nil {
		return err
	}
	missionCompletion, err := operator.PollPermission(ctx, missionPending)
	if err != nil {
		return err
	}
	missionDecision, ok := missionCompletion.Decision()
	if !ok || missionDecision.Permission() != aauth.PermissionGranted {
		return errors.New("mission permission request was not granted")
	}
	if _, err := fmt.Fprintln(output, "Mission permission granted: application archived one report"); err != nil {
		return err
	}
	return nil
}

func newSigningKey(id string) (jose.SigningKey, error) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return jose.SigningKey{}, err
	}
	return jose.NewEd25519SigningKey(id, privateKey)
}
