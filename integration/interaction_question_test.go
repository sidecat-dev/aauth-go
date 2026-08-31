package integration_test

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	clientagent "gitlab.com/sidecat-dev/aauth-go/agent"
	"gitlab.com/sidecat-dev/aauth-go/agentprovider"
	"gitlab.com/sidecat-dev/aauth-go/internal/exampleutil"
	"gitlab.com/sidecat-dev/aauth-go/personserver"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

func TestCurrentCoreMissionlessInteractionQuestion(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	now := time.Date(2026, 9, 1, 1, 30, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	const (
		agentProviderID = "https://ap.example"
		agentID         = "aauth:operator@ap.example"
		personServerID  = "https://ps.example"
		resourceID      = "https://resource.example"
		accessServerID  = "https://as.example"
	)
	providerKey := newSigningKey(t, "question-journey-ap")
	agentKey := newSigningKey(t, "question-journey-agent")
	personKey := newSigningKey(t, "question-journey-ps")
	network := newLogicalTransport()
	httpClient := &http.Client{Transport: network}
	resolver, err := signaturekey.NewHTTPKeyResolver(signaturekey.HTTPKeyResolverConfig{
		Client: httpClient, Clock: clock,
		Admit: func(_ context.Context, endpoint string) error {
			if strings.Contains(endpoint, ".example/.well-known/") {
				return nil
			}
			return errors.New("unexpected discovery endpoint: " + endpoint)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	provider, err := agentprovider.New(agentprovider.Config{
		Issuer: agentProviderID, SigningKey: providerKey, Clock: clock,
		NewID: func() string { return "question-agent-token" },
	})
	if err != nil {
		t.Fatal(err)
	}
	agentToken, err := provider.Issue(aauth.AgentTokenRequest{
		Agent: agentID, PersonServer: personServerID,
		PublicKey: agentKey.PublicJWK(), Lifetime: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}

	questionCalls := 0
	newPeople := func(answer func(context.Context, personserver.InteractionQuestionPolicyRequest) (personserver.InteractionQuestionDecision, error)) *personserver.Server {
		people, err := personserver.NewPSAuthorization(personserver.PSAuthorizationConfig{
			Issuer: personServerID, SigningKey: personKey, KeyResolver: resolver,
			Clock: clock, Tokens: exampleutil.NewMissionStore(), NewID: func() string { return "unused-person-token" },
			BindPerson: func(context.Context, personserver.PersonTokenRequest) (personserver.Person, error) {
				return personserver.Person{Subject: "person", Lifetime: time.Minute}, nil
			},
			Authorize: func(context.Context, personserver.AuthorizationRequest) (personserver.AuthorizationDecision, error) {
				return personserver.AuthorizationDecision{Scopes: []string{"unused"}, Lifetime: time.Minute}, nil
			},
			InteractionQuestion: &personserver.InteractionQuestionConfig{Policy: func(ctx context.Context, request personserver.InteractionQuestionPolicyRequest) (personserver.InteractionQuestionPolicyResult, error) {
				decision, err := answer(ctx, request)
				return personserver.InteractionQuestionPolicyResult{Immediate: &decision}, err
			}},
		})
		if err != nil {
			t.Fatal(err)
		}
		return people
	}
	people := newPeople(func(_ context.Context, request personserver.InteractionQuestionPolicyRequest) (personserver.InteractionQuestionDecision, error) {
		questionCalls++
		if request.Agent != agentID || request.Document.Question.Description != "A route decision is required." ||
			request.Document.Question.Question != "Which route should I take?" || request.Document.Question.MissionS256 != "" ||
			!request.ReceivedAt.Equal(now) {
			return personserver.InteractionQuestionDecision{}, errors.New("unexpected question policy input")
		}
		return personserver.InteractionQuestionDecision{Answer: "Take the northern route."}, nil
	})
	questionPosts := 0
	servePeople := func(server *personserver.Server) {
		network.Handle(personServerID, http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			if request.Method == http.MethodPost && request.URL.Path == "/interaction" {
				questionPosts++
			}
			server.Handler().ServeHTTP(response, request)
		}))
	}
	resourceCalls := 0
	accessServerCalls := 0
	network.Handle(agentProviderID, provider.Handler())
	servePeople(people)
	network.Handle(resourceID, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { resourceCalls++ }))
	network.Handle(accessServerID, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { accessServerCalls++ }))

	operator, err := clientagent.New(ctx, clientagent.Config{
		Identifier: agentID, SigningKey: agentKey, AgentToken: agentToken,
		KeyResolver: resolver, HTTPClient: httpClient, Clock: clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := operator.AskPersonQuestion(ctx, clientagent.InteractionQuestionRequest{
		PersonServer: personServerID,
		Description:  "A route decision is required.",
		Question:     "Which route should I take?",
	})
	if err != nil {
		t.Fatal(err)
	}
	answer, ok := result.Answer()
	if !ok {
		t.Fatalf("question result = %#v, want answer", result)
	}
	if answer.Answer.Answer != "Take the northern route." {
		t.Fatalf("answer = %#v", answer.Answer)
	}

	people = newPeople(func(context.Context, personserver.InteractionQuestionPolicyRequest) (personserver.InteractionQuestionDecision, error) {
		questionCalls++
		return personserver.InteractionQuestionDecision{}, personserver.ErrInteractionUserUnreachable
	})
	servePeople(people)
	_, err = operator.AskPersonQuestion(ctx, clientagent.InteractionQuestionRequest{
		PersonServer: personServerID, Question: "Can you answer another question?",
	})
	var problem *aauth.ProblemError
	if !errors.As(err, &problem) || problem.Status != http.StatusForbidden || problem.Code != "user_unreachable" {
		t.Fatalf("unreachable question = %T %v", err, err)
	}

	deferredStore := exampleutil.NewInteractionQuestionStore()
	newDeferredPeople := func() *personserver.Server {
		people, err := personserver.NewPSAuthorization(personserver.PSAuthorizationConfig{
			Issuer: personServerID, SigningKey: personKey, KeyResolver: resolver,
			Clock: clock, Tokens: exampleutil.NewMissionStore(), NewID: func() string { return "unused-person-token" },
			BindPerson: func(context.Context, personserver.PersonTokenRequest) (personserver.Person, error) {
				return personserver.Person{Subject: "person", Lifetime: time.Minute}, nil
			},
			Authorize: func(context.Context, personserver.AuthorizationRequest) (personserver.AuthorizationDecision, error) {
				return personserver.AuthorizationDecision{Scopes: []string{"unused"}, Lifetime: time.Minute}, nil
			},
			InteractionQuestion: &personserver.InteractionQuestionConfig{
				Store: deferredStore,
				Policy: func(context.Context, personserver.InteractionQuestionPolicyRequest) (personserver.InteractionQuestionPolicyResult, error) {
					questionCalls++
					return personserver.InteractionQuestionPolicyResult{Deferred: &personserver.InteractionQuestionPendingPolicy{
						Lifetime: 2 * time.Minute, RetryAfter: 0,
					}}, nil
				},
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		return people
	}
	people = newDeferredPeople()
	servePeople(people)
	result, err = operator.AskPersonQuestion(ctx, clientagent.InteractionQuestionRequest{
		PersonServer: personServerID, Question: "Should I publish the draft?",
	})
	if err != nil {
		t.Fatal(err)
	}
	pending, ok := result.Pending()
	if !ok {
		t.Fatalf("deferred result = %#v", result)
	}
	people = newDeferredPeople()
	servePeople(people)
	handle, err := people.ResumeInteractionQuestion(ctx, strings.TrimPrefix(pending.Location(), personServerID+"/interaction/pending/"))
	if err != nil {
		t.Fatal(err)
	}
	if err := people.AnswerInteractionQuestion(ctx, handle, "Yes, publish it."); err != nil {
		t.Fatal(err)
	}
	result, err = operator.PollPersonQuestion(ctx, pending)
	if err != nil {
		t.Fatal(err)
	}
	deferredAnswer, ok := result.Answer()
	if !ok || deferredAnswer.Answer.Answer != "Yes, publish it." {
		t.Fatalf("deferred answer = %#v", deferredAnswer)
	}
	if _, err := operator.PollPersonQuestion(ctx, pending); err == nil {
		t.Fatal("consumed answer replayed")
	}
	result, err = operator.AskPersonQuestion(ctx, clientagent.InteractionQuestionRequest{
		PersonServer: personServerID, Question: "Can the person be reached?",
	})
	if err != nil {
		t.Fatal(err)
	}
	pending, ok = result.Pending()
	if !ok {
		t.Fatalf("second deferred result = %#v", result)
	}
	handle, err = people.ResumeInteractionQuestion(ctx, strings.TrimPrefix(pending.Location(), personServerID+"/interaction/pending/"))
	if err != nil {
		t.Fatal(err)
	}
	if err := people.FailInteractionQuestionUnreachable(ctx, handle); err != nil {
		t.Fatal(err)
	}
	_, err = operator.PollPersonQuestion(ctx, pending)
	if !errors.As(err, &problem) || problem.Code != "user_unreachable" {
		t.Fatalf("deferred unreachable = %T %v", err, err)
	}

	if questionCalls != 4 || questionPosts != 4 || resourceCalls != 0 || accessServerCalls != 0 {
		t.Fatalf("effects: policy=%d question=%d Resource=%d AS=%d",
			questionCalls, questionPosts, resourceCalls, accessServerCalls)
	}
}
