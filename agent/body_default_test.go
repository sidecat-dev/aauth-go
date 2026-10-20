package agent_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"gitlab.com/sidecat-dev/aauth-go/agent"
)

func TestDefaultBodyCoverageHonorsClientLimitWithoutAdvertisedComponents(t *testing.T) {
	for _, method := range []string{"CallAsAgent", "Begin", "Do", "BeginBudgetCall"} {
		t.Run(method, func(t *testing.T) {
			fixture := newBudgetCallFixture(t)
			p := fixture.protocol
			authToken := p.issueAuthToken(t, p.newClient(t))
			personToken := mintBeginPersonToken(t, p, nil)
			applicationCalls := 0
			client, err := agent.New(context.Background(), agent.Config{
				Identifier: p.agentID, SigningKey: p.agentKey, AgentToken: p.agentToken,
				KeyResolver: p.resolver, Clock: p.clock, MaxSignedBodyBytes: 4,
				HTTPClient: &http.Client{Transport: roundTripperFunc(func(r *http.Request) (*http.Response, error) {
					if r.URL.Path == "/.well-known/aauth-resource.json" {
						return fixture.metadata(r), nil
					}
					applicationCalls++
					return nil, errors.New("oversize call reached transport")
				})},
			})
			if err != nil {
				t.Fatal(err)
			}
			request, err := http.NewRequest(http.MethodPost, p.resourceID+"/records", strings.NewReader("12345"))
			if err != nil {
				t.Fatal(err)
			}
			switch method {
			case "CallAsAgent":
				_, err = client.CallAsAgentWithComponents(context.Background(), request, nil)
			case "Begin":
				_, err = client.Begin(context.Background(), agent.InitialCall{Request: request, PersonToken: personToken})
			case "Do":
				_, err = client.Do(context.Background(), agent.Call{Request: request, AuthToken: authToken})
			case "BeginBudgetCall":
				_, err = client.BeginBudgetCall(context.Background(), agent.BudgetCall{Request: request, AuthToken: fixture.authToken})
			}
			if err == nil || !strings.Contains(err.Error(), "exceeds") || applicationCalls != 0 {
				t.Fatalf("%s: error=%v application calls=%d", method, err, applicationCalls)
			}
			body, err := io.ReadAll(request.Body)
			if err != nil || string(body) != "12345" {
				t.Fatalf("original body = %q, %v", body, err)
			}
		})
	}
}
