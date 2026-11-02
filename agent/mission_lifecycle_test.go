package agent_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/agent"
)

func TestClientUpdatesMissionWithExactSignedBody(t *testing.T) {
	t.Parallel()

	protocol := newTestProtocol(t)
	const missionEndpoint = "https://ps.example/missions"
	missionS256 := aauth.MissionS256([]byte("approved mission"))
	document, err := aauth.EncodeMissionUpdate(aauth.MissionUpdate{
		Action: "update", Description: "Use the reviewed source",
	})
	if err != nil {
		t.Fatal(err)
	}
	postCalls := 0
	client := protocol.newClientWithHTTPClient(t, &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
		switch {
		case request.Method == http.MethodGet && request.URL.String() == protocol.personServerID+"/.well-known/aauth-person.json":
			return jsonResponse(request, http.StatusOK, map[string]any{
				"issuer": protocol.personServerID, "jwks_uri": protocol.personServerID + "/.well-known/jwks.json", "person_token_endpoint": protocol.personTokenEndpoint,
				"auth_token_endpoint": protocol.authTokenEndpoint, "mission_endpoint": missionEndpoint,
			}), nil
		case request.Method == http.MethodPost && request.URL.String() == missionEndpoint+"/"+missionS256:
			postCalls++
			verified := verifyProofWithComponents(
				t, request, protocol.resolver, protocol.clock, aauth.AgentTokenType,
				[]string{"content-type", "content-digest"},
			)
			claims, err := verified.AgentClaims()
			if err != nil || claims.Subject != protocol.agentID {
				t.Fatalf("mission-update Agent = %#v, %v", claims, err)
			}
			body, err := io.ReadAll(request.Body)
			if err != nil {
				t.Fatal(err)
			}
			if string(body) != string(document.ExactJSON) {
				t.Fatalf("mission-update body = %s, want %s", body, document.ExactJSON)
			}
			response := jsonResponse(request, http.StatusOK, aauth.MissionUpdateResponse{S256: document.S256})
			response.Header.Set("Cache-Control", "no-store")
			return response, nil
		default:
			return nil, errors.New("unexpected request: " + request.Method + " " + request.URL.String())
		}
	})})

	result, err := client.UpdateMission(context.Background(), agent.MissionUpdateRequest{
		PersonServer: protocol.personServerID,
		MissionS256:  missionS256,
		Description:  "Use the reviewed source",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.S256() != document.S256 || postCalls != 1 {
		t.Fatalf("mission-update result s256 = %q, calls = %d", result.S256(), postCalls)
	}
}

func TestClientCompletesMissionWithExactSignedBody(t *testing.T) {
	t.Parallel()

	protocol := newTestProtocol(t)
	const missionEndpoint = "https://ps.example/missions"
	missionS256 := aauth.MissionS256([]byte("approved mission"))
	document, err := aauth.EncodeMissionCompletion(aauth.MissionCompletion{
		Action: "completion", Summary: "The reviewed work is complete.",
	})
	if err != nil {
		t.Fatal(err)
	}
	postCalls := 0
	client := protocol.newClientWithHTTPClient(t, &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
		switch {
		case request.Method == http.MethodGet && request.URL.String() == protocol.personServerID+"/.well-known/aauth-person.json":
			return jsonResponse(request, http.StatusOK, map[string]any{
				"issuer": protocol.personServerID, "jwks_uri": protocol.personServerID + "/.well-known/jwks.json", "person_token_endpoint": protocol.personTokenEndpoint,
				"auth_token_endpoint": protocol.authTokenEndpoint, "mission_endpoint": missionEndpoint,
			}), nil
		case request.Method == http.MethodPost && request.URL.String() == missionEndpoint+"/"+missionS256:
			postCalls++
			verifyProofWithComponents(
				t, request, protocol.resolver, protocol.clock, aauth.AgentTokenType,
				[]string{"content-type", "content-digest"},
			)
			body, err := io.ReadAll(request.Body)
			if err != nil {
				t.Fatal(err)
			}
			if string(body) != string(document.ExactJSON) {
				t.Fatalf("mission-completion body = %s, want %s", body, document.ExactJSON)
			}
			return &http.Response{
				StatusCode: http.StatusOK, Status: http.StatusText(http.StatusOK), Request: request,
				Header: http.Header{"Cache-Control": []string{"no-store"}},
				Body:   http.NoBody,
			}, nil
		default:
			return nil, errors.New("unexpected request: " + request.Method + " " + request.URL.String())
		}
	})})

	err = client.CompleteMission(context.Background(), agent.MissionCompletionRequest{
		PersonServer: protocol.personServerID,
		MissionS256:  missionS256,
		Summary:      "The reviewed work is complete.",
	})
	if err != nil {
		t.Fatal(err)
	}
	if postCalls != 1 {
		t.Fatalf("mission-completion calls = %d, want 1", postCalls)
	}
}

func TestMissionLifecycleRejectsInvalidInputBeforeHTTP(t *testing.T) {
	t.Parallel()

	missionS256 := aauth.MissionS256([]byte("approved mission"))
	for _, test := range []struct {
		name string
		call func(*agent.Client) error
	}{
		{name: "update description", call: func(client *agent.Client) error {
			_, err := client.UpdateMission(context.Background(), agent.MissionUpdateRequest{
				PersonServer: "https://ps.example", MissionS256: missionS256,
			})
			return err
		}},
		{name: "update mission identifier", call: func(client *agent.Client) error {
			_, err := client.UpdateMission(context.Background(), agent.MissionUpdateRequest{
				PersonServer: "https://ps.example", MissionS256: "not-a-digest", Description: "Changed work",
			})
			return err
		}},
		{name: "update person server", call: func(client *agent.Client) error {
			_, err := client.UpdateMission(context.Background(), agent.MissionUpdateRequest{
				PersonServer: "https://other.example", MissionS256: missionS256, Description: "Changed work",
			})
			return err
		}},
		{name: "completion summary", call: func(client *agent.Client) error {
			err := client.CompleteMission(context.Background(), agent.MissionCompletionRequest{
				PersonServer: "https://ps.example", MissionS256: missionS256,
			})
			return err
		}},
		{name: "completion context", call: func(client *agent.Client) error {
			err := client.CompleteMission(nil, agent.MissionCompletionRequest{
				PersonServer: "https://ps.example", MissionS256: missionS256, Summary: "Done",
			})
			return err
		}},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			protocol := newTestProtocol(t)
			httpCalls := 0
			client := protocol.newClientWithHTTPClient(t, &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
				httpCalls++
				return nil, errors.New("unexpected request: " + request.URL.String())
			})})
			if err := test.call(client); err == nil {
				t.Fatal("invalid mission lifecycle input was accepted")
			}
			if httpCalls != 0 {
				t.Fatalf("HTTP calls = %d, want zero", httpCalls)
			}
		})
	}
}

func TestMissionUpdateAcceptsThePersonServersPersistedDigest(t *testing.T) {
	t.Parallel()

	missionS256 := aauth.MissionS256([]byte("approved mission"))
	persistedS256 := aauth.MissionS256([]byte("person-server persisted representation"))
	protocol := newTestProtocol(t)
	client := newMissionLifecycleClient(t, protocol, func(request *http.Request) *http.Response {
		return jsonResponse(request, http.StatusOK, aauth.MissionUpdateResponse{S256: persistedS256})
	})
	result, err := client.UpdateMission(context.Background(), agent.MissionUpdateRequest{
		PersonServer: protocol.personServerID, MissionS256: missionS256, Description: "Changed work",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.S256() != persistedS256 {
		t.Fatalf("accepted update digest = %q, want %q", result.S256(), persistedS256)
	}
}

func TestMissionLifecycleAcceptsCoreSuccessWithoutNoStore(t *testing.T) {
	t.Parallel()

	missionS256 := aauth.MissionS256([]byte("approved mission"))
	update, err := aauth.EncodeMissionUpdate(aauth.MissionUpdate{Action: "update", Description: "Changed work"})
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name     string
		response func(*http.Request) *http.Response
		call     func(*agent.Client) error
	}{
		{
			name: "update",
			response: func(request *http.Request) *http.Response {
				return jsonResponse(request, http.StatusOK, aauth.MissionUpdateResponse{S256: update.S256})
			},
			call: func(client *agent.Client) error {
				_, err := client.UpdateMission(context.Background(), agent.MissionUpdateRequest{
					PersonServer: "https://ps.example", MissionS256: missionS256, Description: "Changed work",
				})
				return err
			},
		},
		{
			name: "completion",
			response: func(request *http.Request) *http.Response {
				return missionLifecycleEmptyResponse(request, http.StatusOK, false)
			},
			call: func(client *agent.Client) error {
				err := client.CompleteMission(context.Background(), agent.MissionCompletionRequest{
					PersonServer: "https://ps.example", MissionS256: missionS256, Summary: "Done",
				})
				return err
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			protocol := newTestProtocol(t)
			client := newMissionLifecycleClient(t, protocol, test.response)
			if err := test.call(client); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestMissionUpdateRejectsMalformedResponseDigest(t *testing.T) {
	t.Parallel()

	protocol := newTestProtocol(t)
	client := newMissionLifecycleClient(t, protocol, func(request *http.Request) *http.Response {
		return jsonResponse(request, http.StatusOK, aauth.MissionUpdateResponse{S256: "not-a-digest"})
	})
	_, err := client.UpdateMission(context.Background(), agent.MissionUpdateRequest{
		PersonServer: protocol.personServerID,
		MissionS256:  aauth.MissionS256([]byte("approved mission")), Description: "Changed work",
	})
	if err == nil {
		t.Fatal("malformed Person Server update digest was accepted")
	}
}

func TestMissionLifecyclePreservesContinuationAndProblemErrors(t *testing.T) {
	t.Parallel()

	missionS256 := aauth.MissionS256([]byte("approved mission"))
	for _, operation := range []struct {
		name     string
		call     func(*agent.Client) error
		location func(error) (string, bool)
	}{
		{name: "UpdateMission", call: func(client *agent.Client) error {
			_, err := client.UpdateMission(context.Background(), agent.MissionUpdateRequest{
				PersonServer: "https://ps.example", MissionS256: missionS256, Description: "Changed work",
			})
			return err
		}, location: func(err error) (string, bool) {
			var pending *agent.PendingError[agent.MissionUpdateResult]
			if !errors.As(err, &pending) {
				return "", false
			}
			return pending.Pending().Location(), true
		}},
		{name: "CompleteMission", call: func(client *agent.Client) error {
			err := client.CompleteMission(context.Background(), agent.MissionCompletionRequest{
				PersonServer: "https://ps.example", MissionS256: missionS256, Summary: "Done",
			})
			return err
		}, location: func(err error) (string, bool) {
			var pending *agent.PendingError[agent.MissionCompletionResult]
			if !errors.As(err, &pending) {
				return "", false
			}
			return pending.Pending().Location(), true
		}},
	} {
		operation := operation
		t.Run(operation.name+" continuation", func(t *testing.T) {
			t.Parallel()
			protocol := newTestProtocol(t)
			postCalls := 0
			client := newMissionLifecycleClient(t, protocol, func(request *http.Request) *http.Response {
				postCalls++
				return missionPendingResponse(request)
			})
			err := operation.call(client)
			if location, ok := operation.location(err); !ok || location != "https://ps.example/pending/mission" {
				t.Fatalf("%s error = %v, want the pending request", operation.name, err)
			}
			if postCalls != 1 {
				t.Fatalf("mission lifecycle POST calls = %d, want one", postCalls)
			}
		})

		t.Run(operation.name+" problem", func(t *testing.T) {
			t.Parallel()
			protocol := newTestProtocol(t)
			client := newMissionLifecycleClient(t, protocol, func(request *http.Request) *http.Response {
				response := jsonResponse(request, http.StatusForbidden, map[string]any{
					"type": "urn:aauth:error:mission_terminated", "title": "Mission terminated",
					"status": http.StatusForbidden, "error": "mission_terminated",
					"mission_status": "terminated", "termination_reason": "expired",
				})
				response.Header.Set("Content-Type", "application/problem+json")
				return response
			})
			err := operation.call(client)
			var problem *aauth.ProblemError
			if !errors.As(err, &problem) || problem.Code != "mission_terminated" ||
				problem.MissionStatus != "terminated" || problem.TerminationReason != "expired" {
				t.Fatalf("mission lifecycle error = %v, want mission_terminated ProblemError", err)
			}
		})
	}
}

func TestMissionLifecycleRejectsMalformedDeferredResponse(t *testing.T) {
	t.Parallel()

	missionS256 := aauth.MissionS256([]byte("approved mission"))
	for _, test := range []struct {
		name   string
		change func(*http.Response)
	}{
		{name: "missing location", change: func(response *http.Response) { response.Header.Del("Location") }},
		{name: "multiple retry after", change: func(response *http.Response) {
			response.Header["Retry-After"] = []string{"0", "1"}
		}},
		{name: "negative retry after", change: func(response *http.Response) { response.Header.Set("Retry-After", "-1") }},
		{name: "missing no-store", change: func(response *http.Response) { response.Header.Del("Cache-Control") }},
		{name: "missing status", change: func(response *http.Response) {
			response.Body = io.NopCloser(strings.NewReader(`{}`))
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			protocol := newTestProtocol(t)
			client := newMissionLifecycleClient(t, protocol, func(request *http.Request) *http.Response {
				response := missionPendingResponse(request)
				test.change(response)
				return response
			})
			_, err := client.UpdateMission(context.Background(), agent.MissionUpdateRequest{
				PersonServer: protocol.personServerID, MissionS256: missionS256, Description: "Changed work",
			})
			var pending *agent.PendingError[agent.MissionUpdateResult]
			if err == nil || errors.As(err, &pending) {
				t.Fatalf("malformed deferred response error = %v", err)
			}
		})
	}
}

func TestMissionContinuationUsesDefaultWhenRetryAfterIsAbsent(t *testing.T) {
	t.Parallel()

	protocol := newTestProtocol(t)
	client := newMissionLifecycleClient(t, protocol, func(request *http.Request) *http.Response {
		response := missionPendingResponse(request)
		response.Header.Del("Retry-After")
		return response
	})
	result, err := client.BeginMissionUpdate(context.Background(), agent.MissionUpdateRequest{
		PersonServer: protocol.personServerID,
		MissionS256:  aauth.MissionS256([]byte("approved mission")), Description: "Changed work",
	})
	if err != nil {
		t.Fatal(err)
	}
	if pending, ok := result.Pending(); !ok || pending.RetryAfter() != 5*time.Second ||
		!pending.NextPollAt().Equal(protocol.now.Add(5*time.Second)) {
		t.Fatalf("pending update = %#v", result)
	}
}

func TestMissionLifecycleDoesNotRetryAmbiguousTransportFailure(t *testing.T) {
	t.Parallel()

	missionS256 := aauth.MissionS256([]byte("approved mission"))
	ambiguous := errors.New("ambiguous mission response")
	for _, operation := range []struct {
		name string
		call func(*agent.Client) error
	}{
		{name: "update", call: func(client *agent.Client) error {
			_, err := client.UpdateMission(context.Background(), agent.MissionUpdateRequest{
				PersonServer: "https://ps.example", MissionS256: missionS256, Description: "Changed work",
			})
			return err
		}},
		{name: "completion", call: func(client *agent.Client) error {
			return client.CompleteMission(context.Background(), agent.MissionCompletionRequest{
				PersonServer: "https://ps.example", MissionS256: missionS256, Summary: "Done",
			})
		}},
	} {
		t.Run(operation.name, func(t *testing.T) {
			t.Parallel()
			protocol := newTestProtocol(t)
			postCalls := 0
			client := protocol.newClientWithHTTPClient(t, &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
				if request.Method == http.MethodGet {
					return jsonResponse(request, http.StatusOK, map[string]any{
						"issuer": protocol.personServerID, "jwks_uri": protocol.personServerID + "/.well-known/jwks.json", "person_token_endpoint": protocol.personTokenEndpoint,
						"auth_token_endpoint": protocol.authTokenEndpoint,
						"mission_endpoint":    protocol.personServerID + "/missions",
					}), nil
				}
				postCalls++
				return nil, ambiguous
			})})
			err := operation.call(client)
			if !errors.Is(err, ambiguous) || postCalls != 1 {
				t.Fatalf("error = %v, POST calls = %d", err, postCalls)
			}
		})
	}
}

func newMissionLifecycleClient(
	t *testing.T,
	protocol *testProtocol,
	post func(*http.Request) *http.Response,
) *agent.Client {
	t.Helper()
	return protocol.newClientWithHTTPClient(t, &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
		if request.Method == http.MethodGet && request.URL.String() == protocol.personServerID+"/.well-known/aauth-person.json" {
			return jsonResponse(request, http.StatusOK, map[string]any{
				"issuer": protocol.personServerID, "jwks_uri": protocol.personServerID + "/.well-known/jwks.json", "person_token_endpoint": protocol.personTokenEndpoint,
				"auth_token_endpoint": protocol.authTokenEndpoint, "mission_endpoint": protocol.personServerID + "/missions",
			}), nil
		}
		if request.Method != http.MethodPost {
			return nil, errors.New("unexpected mission lifecycle request: " + request.Method + " " + request.URL.String())
		}
		return post(request), nil
	})})
}

func missionLifecycleEmptyResponse(request *http.Request, status int, noStore bool) *http.Response {
	response := &http.Response{
		StatusCode: status, Status: http.StatusText(status), Request: request,
		Header: make(http.Header), Body: http.NoBody,
	}
	if noStore {
		response.Header.Set("Cache-Control", "no-store")
	}
	return response
}
