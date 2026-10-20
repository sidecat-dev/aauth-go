// The interaction-question example sends missionless and mission-bound
// questions from an Agent to its Person Server and returns retained answers.
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
	now := time.Date(2026, 9, 1, 1, 45, 0, 0, time.UTC)
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

	questionStore := testutil.NewMissionInteractionQuestionStore()
	missionExpiry := now.Add(30 * time.Minute)
	mission, err := aauth.EncodeMission(aauth.MissionBlob{
		Approver: personServerID, Agent: agentID, ApprovedAt: now.Add(-time.Minute),
		ExpiresAt: &missionExpiry, Description: "Choose the route for the approved trip.",
	})
	if err != nil {
		return err
	}
	if err := questionStore.CommitMission(ctx, personserver.MissionRecord{
		S256: mission.S256, Agent: agentID, ExactJSON: mission.ExactJSON,
		ApprovedAt: mission.Blob.ApprovedAt, ExpiresAt: missionExpiry,
		State: personserver.MissionActive,
	}, nil); err != nil {
		return err
	}
	config := personserver.PSAuthorizationConfig{
		Issuer: personServerID, SigningKey: personKey, KeyResolver: resolver,
		Clock: clock, Tokens: questionStore, NewID: func() string { return "unused-person-token" },
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
		InteractionQuestion: &personserver.InteractionQuestionConfig{
			Policy: func(_ context.Context, request personserver.InteractionQuestionPolicyRequest) (personserver.InteractionQuestionPolicyResult, error) {
				format := "Person Server received question: %s\n"
				if request.Mission != nil {
					format = "Person Server received mission question: %s\n"
				}
				if _, err := fmt.Fprintf(output, format, request.Document.Question.Question); err != nil {
					return personserver.InteractionQuestionPolicyResult{}, err
				}
				return personserver.InteractionQuestionPolicyResult{Deferred: &personserver.InteractionQuestionPendingPolicy{
					Lifetime: time.Minute, RetryAfter: 0,
				}}, nil
			},
		},
	}
	people, err := personserver.NewPSAuthorization(config)
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
	result, err := operator.AskPersonQuestion(ctx, clientagent.InteractionQuestionRequest{
		PersonServer: personServerID,
		Description:  "A route decision is required.",
		Question:     "Which route should I take?",
	})
	if err != nil {
		return err
	}
	pending, ok := result.Pending()
	if !ok {
		return errors.New("Person Server did not return a pending question")
	}
	// The host authenticates the person independently. A replacement server
	// discovers retained work without knowing the Agent's poll URL.
	host, err := personserver.NewPSAuthorization(config)
	if err != nil {
		return err
	}
	references, err := host.PendingInteractionQuestionReferences(ctx, 10)
	if err != nil {
		return err
	}
	if len(references) != 1 {
		return errors.New("expected one pending question")
	}
	reference := references[0]
	handle, err := host.ResumeInteractionQuestion(ctx, reference)
	if err != nil {
		return err
	}
	if err := host.AnswerInteractionQuestion(ctx, handle, "Take the northern route."); err != nil {
		return err
	}
	result, err = operator.PollPersonQuestion(ctx, pending)
	if err != nil {
		return err
	}
	answer, ok := result.Answer()
	if !ok {
		return errors.New("Person Server did not return the retained answer")
	}
	if _, err = fmt.Fprintf(output, "Agent received answer: %s\n", answer.Answer.Answer); err != nil {
		return err
	}

	result, err = operator.AskPersonQuestion(ctx, clientagent.InteractionQuestionRequest{
		PersonServer: personServerID, Question: "Should I continue the mission?", MissionS256: mission.S256,
	})
	if err != nil {
		return err
	}
	pending, ok = result.Pending()
	if !ok {
		return errors.New("Person Server did not return a pending mission question")
	}
	references, err = host.PendingInteractionQuestionReferences(ctx, 10)
	if err != nil {
		return err
	}
	if len(references) != 1 {
		return errors.New("expected one pending mission question")
	}
	reference = references[0]
	handle, err = host.ResumeInteractionQuestion(ctx, reference)
	if err != nil {
		return err
	}
	missionContext, ok := handle.Mission()
	if !ok || missionContext.S256 != mission.S256 {
		return errors.New("Person Server resumed the wrong question mission")
	}
	if err := host.AnswerInteractionQuestion(ctx, handle, "Continue the mission."); err != nil {
		return err
	}
	result, err = operator.PollPersonQuestion(ctx, pending)
	if err != nil {
		return err
	}
	answer, ok = result.Answer()
	if !ok {
		return errors.New("Person Server did not return the retained mission answer")
	}
	_, err = fmt.Fprintf(output, "Agent received mission answer: %s\n", answer.Answer.Answer)
	return err
}

func newSigningKey(id string) (jose.SigningKey, error) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return jose.SigningKey{}, err
	}
	return jose.NewEd25519SigningKey(id, privateKey)
}
