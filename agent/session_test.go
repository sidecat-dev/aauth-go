package agent_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/agent"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

const (
	resourceSessionLocation = "/sessions/pending-1"
	resourceInteractionURL  = "https://resource.example/interaction"
	resourceInteractionCode = "R1S2-T3V4"
	resourceSessionTokenOne = "opaque-session-one"
	resourceSessionTokenTwo = "opaque-session-two"
)

type resourceSessionBeginWithComponents interface {
	BeginResourceSessionWithComponents(context.Context, *http.Request, []string) (agent.ResourceSessionResult, error)
}

type resourceSessionDoWithComponents interface {
	DoWithResourceSessionWithComponents(context.Context, *http.Request, agent.ResourceSession, []string) (agent.ResourceSessionResult, error)
}

type resourceSessionPollWithComponents interface {
	PollResourceSessionWithComponents(context.Context, agent.PendingResourceSession, http.Header, []string) (agent.ResourceSessionResult, error)
}

type pendingResourceSessionComponentProfile interface {
	AdditionalSignatureComponents() []string
}

func TestBeginResourceSessionSignsOnePreservedRequestAndReturnsImmediateSession(t *testing.T) {
	protocol := newTestProtocol(t)
	metadataCalls := 0
	applicationCalls := 0
	responseBody := &trackedBody{Reader: strings.NewReader("application result")}
	client := protocol.newClientWithHTTPClient(t, &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
		if request.Method == http.MethodGet && request.URL.String() == protocol.resourceID+"/.well-known/aauth-resource.json" {
			metadataCalls++
			return resourceSessionMetadataResponseWithComponents(request, protocol.resourceID,
				[]string{"x-session-route", "content-type", "content-digest"}), nil
		}
		applicationCalls++
		verified := verifyProofWithComponents(t, request, protocol.resolver, protocol.clock, aauth.AgentTokenType,
			[]string{"x-session-route", "content-type", "content-digest"})
		claims, err := verified.AgentClaims()
		if err != nil {
			return nil, err
		}
		body, err := io.ReadAll(request.Body)
		if err != nil {
			return nil, err
		}
		if claims.Subject != protocol.agentID || request.Method != http.MethodPost ||
			request.URL.String() != protocol.resourceID+"/records?view=full" ||
			request.Header.Get("AAuth-Capabilities") != "" ||
			request.Header.Get("X-Session-Route") != "records" || string(body) != `{"query":"current"}` {
			return nil, errors.New("resource-session request context mismatch")
		}
		response := &http.Response{
			StatusCode: http.StatusOK,
			Status:     "200 OK",
			Header:     make(http.Header),
			Body:       responseBody,
			Request:    request,
		}
		response.Header.Set("AAuth-Access", resourceSessionTokenOne)
		return response, nil
	})})
	original, err := http.NewRequest(http.MethodPost, protocol.resourceID+"/records?view=full", strings.NewReader(`{"query":"current"}`))
	if err != nil {
		t.Fatal(err)
	}
	original.Header.Set("Content-Type", "application/json")
	original.Header.Set("X-Session-Route", "records")

	result, err := client.BeginResourceSession(context.Background(), original)
	if err != nil {
		t.Fatal(err)
	}
	response, ok := result.Response()
	if !ok || response.StatusCode != http.StatusOK || responseBody.closed {
		t.Fatalf("Response = %#v, %t; closed = %t", response, ok, responseBody.closed)
	}
	session, ok := result.Session()
	if !ok || session.Resource() != protocol.resourceID || session.Token() != resourceSessionTokenOne {
		t.Fatalf("Session = resource %q token %q, %t", session.Resource(), session.Token(), ok)
	}
	if _, ok := result.Pending(); ok {
		t.Fatal("immediate result also exposed a pending session")
	}
	if metadataCalls != 1 || applicationCalls != 1 {
		t.Fatalf("calls: metadata=%d application=%d, want 1 and 1", metadataCalls, applicationCalls)
	}
	for _, name := range []string{"AAuth-Capabilities", "Signature-Key", "Signature-Input", "Signature", "Content-Digest"} {
		if value := original.Header.Get(name); value != "" {
			t.Fatalf("caller request %s = %q", name, value)
		}
	}
	originalBody, err := io.ReadAll(original.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(originalBody) != `{"query":"current"}` {
		t.Fatalf("caller body = %q", originalBody)
	}
	response.Body.Close()
}

func TestBeginResourceSessionWithComponentsPerformsOneExactExchangeAndRetainsProfile(t *testing.T) {
	protocol := newTestProtocol(t)
	wantProfile := []string{"x-session-route", "prefer"}
	httpCalls := 0
	client := protocol.newClientWithHTTPClient(t, &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
		httpCalls++
		if request.URL.String() != protocol.resourceID+"/records" {
			return nil, errors.New("unexpected metadata or application request: " + request.URL.String())
		}
		verified := verifyProofWithComponents(t, request, protocol.resolver, protocol.clock, aauth.AgentTokenType, wantProfile)
		wantCovered := []string{"@method", "@authority", "@path", "x-session-route", "prefer", "signature-key"}
		if got := verified.Proof.CoveredComponents(); !slicesEqual(got, wantCovered) {
			t.Fatalf("covered components = %v, want %v", got, wantCovered)
		}
		if request.Header.Get("X-Session-Route") != "begin-fresh" || request.Header.Get("Prefer") != "wait=1" ||
			request.Header.Get("AAuth-Capabilities") != "custom, interaction" {
			t.Fatalf("begin headers = %#v", request.Header)
		}
		return validResourceSessionPendingResponse(request, "3", "pending", true), nil
	})})
	beginner, ok := any(client).(resourceSessionBeginWithComponents)
	if !ok {
		t.Fatal("*agent.Client is missing BeginResourceSessionWithComponents")
	}
	request, err := http.NewRequest(http.MethodPost, protocol.resourceID+"/records", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("X-Session-Route", "begin-fresh")
	request.Header.Set("Prefer", "wait=1")
	request.Header.Set("AAuth-Capabilities", "custom, interaction")
	components := append([]string(nil), wantProfile...)
	result, err := beginner.BeginResourceSessionWithComponents(context.Background(), request, components)
	if err != nil {
		t.Fatal(err)
	}
	pending, ok := result.Pending()
	if !ok {
		t.Fatal("metadata-less BeginResourceSessionWithComponents did not return pending")
	}
	profiled, ok := any(pending).(pendingResourceSessionComponentProfile)
	if !ok {
		t.Fatal("PendingResourceSession is missing AdditionalSignatureComponents")
	}
	components[0] = "mutated-caller-input"
	got := profiled.AdditionalSignatureComponents()
	if !slicesEqual(got, wantProfile) {
		t.Fatalf("retained component profile = %v, want %v", got, wantProfile)
	}
	got[0] = "mutated-return-value"
	if again := profiled.AdditionalSignatureComponents(); !slicesEqual(again, wantProfile) {
		t.Fatalf("component profile after caller mutation = %v, want %v", again, wantProfile)
	}
	if httpCalls != 1 {
		t.Fatalf("HTTP exchanges = %d, want exactly 1", httpCalls)
	}
	if got := request.Header.Get("AAuth-Capabilities"); got != "custom, interaction" {
		t.Fatalf("caller AAuth-Capabilities = %q", got)
	}
	for _, name := range []string{"Signature-Key", "Signature-Input", "Signature"} {
		if value := request.Header.Get(name); value != "" {
			t.Fatalf("caller request %s = %q", name, value)
		}
	}
}

func TestBeginResourceSessionRefusesUndeclaredInteraction(t *testing.T) {
	t.Parallel()

	protocol := newTestProtocol(t)
	applicationCalls := 0
	client := protocol.newClientWithHTTPClient(t, &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.Path == "/.well-known/aauth-resource.json" {
			return resourceSessionMetadataResponseWithComponents(request, protocol.resourceID, nil), nil
		}
		applicationCalls++
		if request.Header.Get("AAuth-Capabilities") != "" {
			return nil, errors.New("Agent invented an interaction capability")
		}
		return validResourceSessionPendingResponse(request, "3", "pending", true), nil
	})})
	request, err := http.NewRequest(http.MethodGet, protocol.resourceID+"/records", nil)
	if err != nil {
		t.Fatal(err)
	}
	result, err := client.BeginResourceSession(context.Background(), request)
	if err == nil || !strings.Contains(err.Error(), "did not declare") {
		t.Fatalf("BeginResourceSession result = %#v, error = %v", result, err)
	}
	if applicationCalls != 1 {
		t.Fatalf("application calls = %d, want 1", applicationCalls)
	}
}

func TestBeginResourceSessionRejectsMalformedCapabilitiesBeforeNetwork(t *testing.T) {
	t.Parallel()

	protocol := newTestProtocol(t)
	networkCalls := 0
	client := protocol.newClientWithHTTPClient(t, &http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
		networkCalls++
		return nil, errors.New("unexpected network request")
	})})
	request, err := http.NewRequest(http.MethodGet, protocol.resourceID+"/records", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("AAuth-Capabilities", "interaction,")
	if _, err := client.BeginResourceSession(context.Background(), request); err == nil ||
		!strings.Contains(err.Error(), "AAuth-Capabilities") {
		t.Fatalf("BeginResourceSession error = %v", err)
	}
	if networkCalls != 0 {
		t.Fatalf("malformed capabilities used network %d times", networkCalls)
	}
}

func TestBeginResourceSessionPreservesProtocolFailureWithReplacementSession(t *testing.T) {
	t.Parallel()

	protocol := newTestProtocol(t)
	client := protocol.newClientWithHTTPClient(t, &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.Path == "/.well-known/aauth-resource.json" {
			return resourceSessionMetadataResponseWithComponents(request, protocol.resourceID, nil), nil
		}
		response := problemResponse(request, &aauth.ProblemError{
			Status: http.StatusForbidden, Code: "access_denied", Detail: "session policy refused the request",
		})
		response.Header.Set("AAuth-Access", resourceSessionTokenTwo)
		return response, nil
	})})
	request, err := http.NewRequest(http.MethodGet, protocol.resourceID+"/records", nil)
	if err != nil {
		t.Fatal(err)
	}
	result, err := client.BeginResourceSession(context.Background(), request)
	if err != nil {
		t.Fatalf("valid protocol failure returned Go error: %v", err)
	}
	var problem *aauth.ProblemError
	if !errors.As(result.Failure(), &problem) || problem.Code != "access_denied" {
		t.Fatalf("Failure = %v, problem = %#v", result.Failure(), problem)
	}
	session, ok := result.Session()
	if !ok || session.Token() != resourceSessionTokenTwo {
		t.Fatalf("replacement session = %#v, present=%t", session, ok)
	}
	response, ok := result.Response()
	if !ok {
		t.Fatal("protocol failure lost its response")
	}
	if body, err := io.ReadAll(response.Body); err != nil || len(body) == 0 {
		t.Fatalf("protocol response body = %q, error = %v", body, err)
	}
	response.Body.Close()
}

func TestBeginResourceSessionTreatsMetadataModeAsAdvisoryAndRequiresStrictPendingInteraction(t *testing.T) {
	for _, test := range []struct {
		name             string
		metadataMode     aauth.AccessMode
		change           func(*http.Response)
		wantErr          bool
		wantApplications int
	}{
		{name: "valid", wantApplications: 1},
		{name: "metadata advertises another access mode", metadataMode: aauth.AccessModeAgentToken, wantApplications: 1},
		{name: "cross-origin Location", wantErr: true, wantApplications: 1, change: func(response *http.Response) {
			response.Header.Set("Location", "https://attacker.example/sessions/pending-1")
		}},
		{name: "non-decimal Retry-After", wantErr: true, wantApplications: 1, change: func(response *http.Response) {
			response.Header.Set("Retry-After", "Sun, 30 Aug 2026 18:00:00 GMT")
		}},
		{name: "missing no-store", wantErr: true, wantApplications: 1, change: func(response *http.Response) {
			response.Header.Del("Cache-Control")
		}},
		{name: "missing interaction", wantErr: true, wantApplications: 1, change: func(response *http.Response) {
			response.Header.Del("AAuth-Requirement")
		}},
		{name: "oversized status", wantErr: true, wantApplications: 1, change: func(response *http.Response) {
			response.Body = io.NopCloser(strings.NewReader(`{"status":"` + strings.Repeat("x", (1<<20)+1) + `"}`))
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			protocol := newTestProtocol(t)
			applicationCalls := 0
			client := protocol.newClientWithHTTPClient(t, &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
				if request.Method == http.MethodGet && request.URL.String() == protocol.resourceID+"/.well-known/aauth-resource.json" {
					if test.metadataMode != "" {
						return jsonResponse(request, http.StatusOK, map[string]any{
							"issuer": protocol.resourceID, "access_mode": string(test.metadataMode),
							"additional_signature_components": []string{"x-session-route", "content-type", "content-digest"},
						}), nil
					}
					return resourceSessionMetadataResponseWithComponents(request, protocol.resourceID,
						[]string{"x-session-route", "content-type", "content-digest"}), nil
				}
				applicationCalls++
				verifyProofWithComponents(t, request, protocol.resolver, protocol.clock, aauth.AgentTokenType,
					[]string{"x-session-route", "content-type", "content-digest"})
				response := validResourceSessionPendingResponse(request, "7", "pending", true)
				if test.change != nil {
					test.change(response)
				}
				return response, nil
			})})
			request, err := http.NewRequest(http.MethodPost, protocol.resourceID+"/records", strings.NewReader(`{"query":"current"}`))
			if err != nil {
				t.Fatal(err)
			}
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("X-Session-Route", "records")
			request.Header.Set("AAuth-Capabilities", "interaction")
			result, err := client.BeginResourceSession(context.Background(), request)
			if test.wantErr {
				if err == nil {
					t.Fatal("BeginResourceSession accepted an invalid pending response")
				}
				if _, ok := result.Pending(); ok {
					t.Fatal("invalid response produced a pending handle")
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				pending, ok := result.Pending()
				if !ok || pending.Resource() != protocol.resourceID ||
					pending.Location() != protocol.resourceID+resourceSessionLocation ||
					pending.RetryAfter() != 7*time.Second ||
					pending.InteractionURL() != resourceInteractionURL ||
					pending.InteractionCode() != resourceInteractionCode || pending.Interacting() {
					t.Fatalf("Pending = %#v, %t", pending, ok)
				}
			}
			if applicationCalls != test.wantApplications {
				t.Fatalf("application calls = %d, want %d", applicationCalls, test.wantApplications)
			}
		})
	}
}

func TestPollResourceSessionMakesOneSignedGETAndReturnsPendingThenTerminalSession(t *testing.T) {
	protocol := newTestProtocol(t)
	pollCalls := 0
	var lastPoll *http.Request
	client := protocol.newClientWithHTTPClient(t, &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
		switch {
		case request.Method == http.MethodGet && request.URL.String() == protocol.resourceID+"/.well-known/aauth-resource.json":
			return resourceSessionMetadataResponseWithComponents(request, protocol.resourceID, nil), nil
		case request.Method == http.MethodPost && request.URL.String() == protocol.resourceID+"/records":
			verifyProofWithComponents(t, request, protocol.resolver, protocol.clock, aauth.AgentTokenType, nil)
			return validResourceSessionPendingResponse(request, "1", "pending", true), nil
		case request.Method == http.MethodGet && request.URL.String() == protocol.resourceID+resourceSessionLocation:
			pollCalls++
			lastPoll = request
			verifyProof(t, request, protocol.resolver, protocol.clock, aauth.AgentTokenType)
			if pollCalls == 1 {
				return validResourceSessionPendingResponse(request, "9", "future-status", false), nil
			}
			if pollCalls == 2 {
				return resourceSessionSuccessResponse(request, resourceSessionTokenOne, "ready"), nil
			}
			return nil, errors.New("unexpected automatic resource-session poll")
		default:
			return nil, errors.New("unexpected request: " + request.Method + " " + request.URL.String())
		}
	})})
	pending := beginPendingResourceSession(t, client, protocol)

	result, err := client.PollResourceSession(context.Background(), pending)
	if err != nil {
		t.Fatal(err)
	}
	next, ok := result.Pending()
	if !ok || next.Resource() != pending.Resource() || next.Location() != pending.Location() ||
		next.RetryAfter() != 9*time.Second || next.InteractionURL() != pending.InteractionURL() ||
		next.InteractionCode() != pending.InteractionCode() || next.Interacting() {
		t.Fatalf("updated Pending = %#v, %t", next, ok)
	}
	if pollCalls != 1 {
		t.Fatalf("first PollResourceSession calls = %d, want 1", pollCalls)
	}
	if lastPoll == nil || lastPoll.Method != http.MethodGet || lastPoll.URL.String() != pending.Location() ||
		(lastPoll.Body != nil && lastPoll.Body != http.NoBody) || lastPoll.ContentLength != 0 || lastPoll.GetBody != nil {
		t.Fatalf("poll request = %#v", lastPoll)
	}

	result, err = client.PollResourceSession(context.Background(), next)
	if err != nil {
		t.Fatal(err)
	}
	response, ok := result.Response()
	if !ok || response.StatusCode != http.StatusOK {
		t.Fatalf("terminal Response = %#v, %t", response, ok)
	}
	session, ok := result.Session()
	if !ok || session.Resource() != protocol.resourceID || session.Token() != resourceSessionTokenOne {
		t.Fatalf("terminal Session = resource %q token %q, %t", session.Resource(), session.Token(), ok)
	}
	if _, ok := result.Pending(); ok {
		t.Fatal("terminal result also exposed pending")
	}
	if pollCalls != 2 {
		t.Fatalf("two explicit PollResourceSession calls used %d requests", pollCalls)
	}
	response.Body.Close()
}

func TestPollResourceSessionRefusesRetainedHeaderComponentsWithoutFreshValues(t *testing.T) {
	protocol := newTestProtocol(t)
	profile := []string{"x-session-route"}
	pollCalls := 0
	client := protocol.newClientWithHTTPClient(t, &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
		switch request.URL.String() {
		case protocol.resourceID + "/.well-known/aauth-resource.json":
			return resourceSessionMetadataResponseWithComponents(request, protocol.resourceID, profile), nil
		case protocol.resourceID + "/records":
			verifyProofWithComponents(t, request, protocol.resolver, protocol.clock, aauth.AgentTokenType, profile)
			return validResourceSessionPendingResponse(request, "1", "pending", true), nil
		case protocol.resourceID + resourceSessionLocation:
			pollCalls++
			return validResourceSessionPendingResponse(request, "1", "pending", false), nil
		default:
			return nil, errors.New("unexpected request: " + request.URL.String())
		}
	})})
	request, err := http.NewRequest(http.MethodGet, protocol.resourceID+"/records", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("X-Session-Route", "begin-value")
	request.Header.Set("AAuth-Capabilities", "interaction")
	result, err := client.BeginResourceSession(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	pending, ok := result.Pending()
	if !ok {
		t.Fatal("BeginResourceSession did not return pending")
	}
	polled, err := client.PollResourceSession(context.Background(), pending)
	if err == nil || !strings.Contains(err.Error(), "PollResourceSessionWithComponents") {
		t.Fatalf("PollResourceSession result = %#v, error = %v; want local WithComponents direction", polled, err)
	}
	if pollCalls != 0 {
		t.Fatalf("PollResourceSession sent %d under-signed requests, want 0", pollCalls)
	}
}

func TestPollResourceSessionWithComponentsUsesFreshHeadersAndExactRetainedProfile(t *testing.T) {
	protocol := newTestProtocol(t)
	wantProfile := []string{"x-session-route", "prefer"}
	pollCalls := 0
	client := protocol.newClientWithHTTPClient(t, &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
		switch request.URL.String() {
		case protocol.resourceID + "/.well-known/aauth-resource.json":
			return resourceSessionMetadataResponseWithComponents(request, protocol.resourceID, wantProfile), nil
		case protocol.resourceID + "/records":
			verifyProofWithComponents(t, request, protocol.resolver, protocol.clock, aauth.AgentTokenType, wantProfile)
			if request.Header.Get("X-Session-Route") != "begin-value" || request.Header.Get("Prefer") != "wait=1" {
				t.Fatalf("begin headers = %#v", request.Header)
			}
			return validResourceSessionPendingResponse(request, "1", "pending", true), nil
		case protocol.resourceID + resourceSessionLocation:
			pollCalls++
			verified := verifyProofWithComponents(t, request, protocol.resolver, protocol.clock, aauth.AgentTokenType, wantProfile)
			wantCovered := []string{"@method", "@authority", "@path", "x-session-route", "prefer", "signature-key"}
			if got := verified.Proof.CoveredComponents(); !slicesEqual(got, wantCovered) {
				t.Fatalf("poll covered components = %v, want %v", got, wantCovered)
			}
			if request.Header.Get("X-Session-Route") != "poll-fresh" || request.Header.Get("Prefer") != "wait=4" {
				t.Fatalf("poll headers = %#v", request.Header)
			}
			return validResourceSessionPendingResponse(request, "4", "interacting", false), nil
		default:
			return nil, errors.New("unexpected request: " + request.URL.String())
		}
	})})
	request, err := http.NewRequest(http.MethodGet, protocol.resourceID+"/records", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("X-Session-Route", "begin-value")
	request.Header.Set("Prefer", "wait=1")
	request.Header.Set("AAuth-Capabilities", "interaction")
	result, err := client.BeginResourceSession(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	pending, ok := result.Pending()
	if !ok {
		t.Fatal("BeginResourceSession did not return pending")
	}
	profiled, ok := any(pending).(pendingResourceSessionComponentProfile)
	if !ok {
		t.Fatal("PendingResourceSession is missing AdditionalSignatureComponents")
	}
	gotProfile := profiled.AdditionalSignatureComponents()
	if !slicesEqual(gotProfile, wantProfile) {
		t.Fatalf("discovered component profile = %v, want %v", gotProfile, wantProfile)
	}
	gotProfile[0] = "mutated-return-value"
	if again := profiled.AdditionalSignatureComponents(); !slicesEqual(again, wantProfile) {
		t.Fatalf("component profile after caller mutation = %v, want %v", again, wantProfile)
	}
	poller, ok := any(client).(resourceSessionPollWithComponents)
	if !ok {
		t.Fatal("*agent.Client is missing PollResourceSessionWithComponents")
	}
	headers := make(http.Header)
	headers.Set("X-Session-Route", "poll-fresh")
	headers.Set("Prefer", "wait=4")
	if _, err := poller.PollResourceSessionWithComponents(
		context.Background(), pending, headers, []string{"x-session-route"},
	); err == nil {
		t.Fatal("PollResourceSessionWithComponents accepted a component list that did not match the retained profile")
	}
	if pollCalls != 0 {
		t.Fatalf("mismatched component profile made %d poll requests, want 0", pollCalls)
	}
	missing := make(http.Header)
	missing.Set("X-Session-Route", "poll-fresh")
	if _, err := poller.PollResourceSessionWithComponents(context.Background(), pending, missing, wantProfile); err == nil {
		t.Fatal("PollResourceSessionWithComponents accepted missing fresh header values")
	}
	if pollCalls != 0 {
		t.Fatalf("missing fresh header made %d poll requests, want 0", pollCalls)
	}
	result, err = poller.PollResourceSessionWithComponents(context.Background(), pending, headers, wantProfile)
	if err != nil {
		t.Fatal(err)
	}
	next, ok := result.Pending()
	if !ok || !next.Interacting() || next.RetryAfter() != 4*time.Second {
		t.Fatalf("poll result = %#v, pending = %t", next, ok)
	}
	if pollCalls != 1 {
		t.Fatalf("exact explicit poll made %d requests, want 1", pollCalls)
	}
	if headers.Get("X-Session-Route") != "poll-fresh" || headers.Get("Prefer") != "wait=4" {
		t.Fatalf("caller headers changed = %#v", headers)
	}
	for _, name := range []string{"Signature-Key", "Signature-Input", "Signature"} {
		if value := headers.Get(name); value != "" {
			t.Fatalf("caller headers %s = %q", name, value)
		}
	}
}

func TestPendingResourceSessionInteractingStateIsMonotonic(t *testing.T) {
	for _, laterStatus := range []string{"pending", "future-status"} {
		laterStatus := laterStatus
		t.Run(laterStatus, func(t *testing.T) {
			protocol := newTestProtocol(t)
			pollCalls := 0
			client := protocol.newClientWithHTTPClient(t, &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
				switch request.URL.String() {
				case protocol.resourceID + "/.well-known/aauth-resource.json":
					return resourceSessionMetadataResponseWithComponents(request, protocol.resourceID, nil), nil
				case protocol.resourceID + "/records":
					verifyProofWithComponents(t, request, protocol.resolver, protocol.clock, aauth.AgentTokenType, nil)
					return validResourceSessionPendingResponse(request, "0", "pending", true), nil
				case protocol.resourceID + resourceSessionLocation:
					pollCalls++
					verifyProof(t, request, protocol.resolver, protocol.clock, aauth.AgentTokenType)
					status := "interacting"
					if pollCalls == 2 {
						status = laterStatus
					}
					if pollCalls > 2 {
						return nil, errors.New("unexpected automatic Resource-session poll")
					}
					return validResourceSessionPendingResponse(request, "0", status, false), nil
				default:
					return nil, errors.New("unexpected request: " + request.URL.String())
				}
			})})
			request, err := http.NewRequest(http.MethodGet, protocol.resourceID+"/records", nil)
			if err != nil {
				t.Fatal(err)
			}
			request.Header.Set("AAuth-Capabilities", "interaction")
			result, err := client.BeginResourceSession(context.Background(), request)
			if err != nil {
				t.Fatal(err)
			}
			pending, ok := result.Pending()
			if !ok {
				t.Fatal("BeginResourceSession did not return pending")
			}
			result, err = client.PollResourceSession(context.Background(), pending)
			if err != nil {
				t.Fatal(err)
			}
			interacting, ok := result.Pending()
			if !ok || !interacting.Interacting() {
				t.Fatalf("interacting poll = %#v, pending = %t", interacting, ok)
			}
			result, err = client.PollResourceSession(context.Background(), interacting)
			if err != nil {
				t.Fatal(err)
			}
			next, ok := result.Pending()
			if !ok || !next.Interacting() {
				t.Fatalf("later %q poll regressed interacting state: %#v, pending = %t", laterStatus, next, ok)
			}
			if pollCalls != 2 {
				t.Fatalf("poll calls = %d, want exactly 2", pollCalls)
			}
		})
	}
}

func TestPollResourceSessionRejectsChangedInteractionAndSurfacesTerminalStatusesOnce(t *testing.T) {
	t.Run("changed interaction", func(t *testing.T) {
		protocol := newTestProtocol(t)
		pollCalls := 0
		client := protocol.newClientWithHTTPClient(t, &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
			if request.Method == http.MethodGet && request.URL.String() == protocol.resourceID+"/.well-known/aauth-resource.json" {
				return resourceSessionMetadataResponseWithComponents(request, protocol.resourceID, nil), nil
			}
			if request.Method == http.MethodPost {
				verifyProofWithComponents(t, request, protocol.resolver, protocol.clock, aauth.AgentTokenType, nil)
				return validResourceSessionPendingResponse(request, "0", "pending", true), nil
			}
			pollCalls++
			verifyProof(t, request, protocol.resolver, protocol.clock, aauth.AgentTokenType)
			response := validResourceSessionPendingResponse(request, "1", "interacting", true)
			response.Header.Set("AAuth-Requirement", interactionRequirement("https://resource.example/other", resourceInteractionCode))
			return response, nil
		})})
		pending := beginPendingResourceSession(t, client, protocol)
		if _, err := client.PollResourceSession(context.Background(), pending); err == nil {
			t.Fatal("PollResourceSession accepted changed interaction data")
		}
		if pollCalls != 1 {
			t.Fatalf("poll calls = %d, want 1", pollCalls)
		}
	})

	for _, status := range []int{
		http.StatusForbidden,
		http.StatusRequestTimeout,
		http.StatusGone,
	} {
		status := status
		t.Run(http.StatusText(status), func(t *testing.T) {
			protocol := newTestProtocol(t)
			pollCalls := 0
			client := protocol.newClientWithHTTPClient(t, &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
				if request.Method == http.MethodGet && request.URL.String() == protocol.resourceID+"/.well-known/aauth-resource.json" {
					return resourceSessionMetadataResponseWithComponents(request, protocol.resourceID, nil), nil
				}
				if request.Method == http.MethodPost {
					verifyProofWithComponents(t, request, protocol.resolver, protocol.clock, aauth.AgentTokenType, nil)
					return validResourceSessionPendingResponse(request, "0", "pending", true), nil
				}
				pollCalls++
				verifyProof(t, request, protocol.resolver, protocol.clock, aauth.AgentTokenType)
				response := problemResponse(request, &aauth.ProblemError{
					Status: status, Code: aauth.ErrorCode("session_outcome"), Detail: "session outcome",
				})
				response.Header.Set("AAuth-Access", resourceSessionTokenTwo)
				return response, nil
			})})
			pending := beginPendingResourceSession(t, client, protocol)
			result, err := client.PollResourceSession(context.Background(), pending)
			if err != nil {
				t.Fatalf("terminal protocol response returned Go error: %v", err)
			}
			var problem *aauth.ProblemError
			if failure := result.Failure(); !errors.As(failure, &problem) || problem.Status != status {
				t.Fatalf("failure = %v, problem = %#v", failure, problem)
			}
			response, ok := result.Response()
			if !ok {
				t.Fatal("terminal protocol result lost its response")
			}
			replacement, ok := result.Session()
			if !ok || replacement.Resource() != protocol.resourceID || replacement.Token() != resourceSessionTokenTwo {
				t.Fatalf("terminal replacement = resource %q token %q, present=%t",
					replacement.Resource(), replacement.Token(), ok)
			}
			if pollCalls != 1 {
				t.Fatalf("poll calls = %d, want 1", pollCalls)
			}
			response.Body.Close()
		})
	}
}

func TestPollResourceSessionReturnsRetryableResponsesWithNextInterval(t *testing.T) {
	for _, status := range []int{http.StatusTooManyRequests, http.StatusServiceUnavailable} {
		status := status
		t.Run(http.StatusText(status), func(t *testing.T) {
			protocol := newTestProtocol(t)
			pollCalls := 0
			var returned *http.Response
			var responseBody *trackedBody
			var expectedBody string
			client := protocol.newClientWithHTTPClient(t, &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
				switch request.URL.String() {
				case protocol.resourceID + "/.well-known/aauth-resource.json":
					return resourceSessionMetadataResponseWithComponents(request, protocol.resourceID, nil), nil
				case protocol.resourceID + "/records":
					verifyProofWithComponents(t, request, protocol.resolver, protocol.clock, aauth.AgentTokenType, nil)
					return validResourceSessionPendingResponse(request, "7", "pending", true), nil
				case protocol.resourceID + resourceSessionLocation:
					pollCalls++
					verifyProof(t, request, protocol.resolver, protocol.clock, aauth.AgentTokenType)
					returned = problemResponse(request, &aauth.ProblemError{
						Status: status, Code: "temporarily_unavailable", Detail: "poll again later",
					})
					encoded, err := io.ReadAll(returned.Body)
					if err != nil {
						return nil, err
					}
					_ = returned.Body.Close()
					expectedBody = string(encoded)
					responseBody = &trackedBody{Reader: strings.NewReader(expectedBody)}
					returned.Body = responseBody
					returned.Header.Set("Retry-After", "11")
					returned.Header.Set("AAuth-Access", resourceSessionTokenTwo)
					return returned, nil
				default:
					return nil, errors.New("unexpected request: " + request.URL.String())
				}
			})})
			request, err := http.NewRequest(http.MethodGet, protocol.resourceID+"/records", nil)
			if err != nil {
				t.Fatal(err)
			}
			request.Header.Set("AAuth-Capabilities", "interaction")
			result, err := client.BeginResourceSession(context.Background(), request)
			if err != nil {
				t.Fatal(err)
			}
			pending, ok := result.Pending()
			if !ok {
				t.Fatal("BeginResourceSession did not return pending")
			}
			result, err = client.PollResourceSession(context.Background(), pending)
			if err != nil {
				t.Fatal(err)
			}
			response, ok := result.Response()
			if !ok || response != returned || response.StatusCode != status || response.Header.Get("Retry-After") != "11" {
				t.Fatalf("retryable response = %#v, present = %t", response, ok)
			}
			// A 429 adds five seconds to the current seven-second interval,
			// which already exceeds its Retry-After; a 503 takes Retry-After.
			want := 11 * time.Second
			if status == http.StatusTooManyRequests {
				want = 12 * time.Second
			}
			next, ok := result.Pending()
			if !ok || next.Location() != pending.Location() || next.RetryAfter() != want {
				t.Fatalf("retryable pending = %q after %s, present = %t; want %s", next.Location(), next.RetryAfter(), ok, want)
			}
			replacement, ok := result.Session()
			if !ok || replacement.Resource() != protocol.resourceID || replacement.Token() != resourceSessionTokenTwo {
				t.Fatalf("retryable replacement = resource %q token %q, present=%t",
					replacement.Resource(), replacement.Token(), ok)
			}
			if pollCalls != 1 {
				t.Fatalf("poll calls = %d, want 1", pollCalls)
			}
			if responseBody == nil || responseBody.closed {
				t.Fatal("PollResourceSession closed the caller-owned retryable response body")
			}
			body, err := io.ReadAll(response.Body)
			if err != nil || string(body) != expectedBody {
				t.Fatalf("retryable response body = %q, error = %v, want %q", body, err, expectedBody)
			}
			if err := response.Body.Close(); err != nil {
				t.Fatal(err)
			}
			if !responseBody.closed {
				t.Fatal("caller close did not close the retryable response body")
			}
		})
	}
}

func TestPollResourceSessionAllowsNoSessionAndRejectsAmbiguousAccessCredentials(t *testing.T) {
	for _, test := range []struct {
		name    string
		values  []string
		wantErr bool
	}{
		{name: "missing"},
		{name: "multiple", values: []string{"first", "second"}, wantErr: true},
		{name: "malformed", values: []string{"opaque token"}, wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			protocol := newTestProtocol(t)
			pollCalls := 0
			client := protocol.newClientWithHTTPClient(t, &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
				if request.Method == http.MethodGet && request.URL.String() == protocol.resourceID+"/.well-known/aauth-resource.json" {
					return resourceSessionMetadataResponseWithComponents(request, protocol.resourceID, nil), nil
				}
				if request.Method == http.MethodPost {
					verifyProofWithComponents(t, request, protocol.resolver, protocol.clock, aauth.AgentTokenType, nil)
					return validResourceSessionPendingResponse(request, "0", "pending", true), nil
				}
				pollCalls++
				verifyProof(t, request, protocol.resolver, protocol.clock, aauth.AgentTokenType)
				response := resourceSessionSuccessResponse(request, "", "ready")
				response.Header["Aauth-Access"] = append([]string(nil), test.values...)
				return response, nil
			})})
			pending := beginPendingResourceSession(t, client, protocol)
			result, err := client.PollResourceSession(context.Background(), pending)
			if test.wantErr && err == nil {
				if _, ok := result.Session(); ok {
					t.Fatal("invalid terminal response produced a session")
				}
				t.Fatal("invalid terminal AAuth-Access was accepted")
			}
			if !test.wantErr {
				if err != nil {
					t.Fatal(err)
				}
				if _, ok := result.Response(); !ok {
					t.Fatal("terminal response without AAuth-Access was not preserved")
				}
				if _, ok := result.Session(); ok {
					t.Fatal("missing AAuth-Access produced a session")
				}
			}
			if pollCalls != 1 {
				t.Fatalf("poll calls = %d, want 1", pollCalls)
			}
		})
	}
}

func TestDoWithResourceSessionSignsAuthorizationRotatesAndUsesReplacementNext(t *testing.T) {
	protocol := newTestProtocol(t)
	metadataCalls := 0
	protectedCalls := 0
	seenAuthorization := make([]string, 0, 2)
	client := protocol.newClientWithHTTPClient(t, &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
		if request.Method == http.MethodGet && request.URL.String() == protocol.resourceID+"/.well-known/aauth-resource.json" {
			metadataCalls++
			return resourceSessionMetadataResponse(request, protocol.resourceID), nil
		}
		if request.Method == http.MethodPost && request.URL.Path == "/session/start" {
			verifyProofWithComponents(t, request, protocol.resolver, protocol.clock, aauth.AgentTokenType,
				[]string{"x-session-route"})
			return resourceSessionSuccessResponse(request, resourceSessionTokenOne, "started"), nil
		}
		protectedCalls++
		verified := verifyProofWithComponents(t, request, protocol.resolver, protocol.clock, aauth.AgentTokenType,
			[]string{"authorization", "x-session-route"})
		claims, err := verified.AgentClaims()
		if err != nil || claims.Subject != protocol.agentID {
			return nil, errors.New("protected session proof used the wrong Agent")
		}
		seenAuthorization = append(seenAuthorization, request.Header.Get("Authorization"))
		response := &http.Response{
			StatusCode: http.StatusNoContent, Status: "204 No Content",
			Header: make(http.Header), Body: http.NoBody, Request: request,
		}
		if protectedCalls == 1 {
			response.Header.Set("AAuth-Access", resourceSessionTokenTwo)
		}
		return response, nil
	})})
	session := beginImmediateResourceSession(t, client, protocol)

	firstRequest, err := http.NewRequest(http.MethodGet, protocol.resourceID+"/records/42", nil)
	if err != nil {
		t.Fatal(err)
	}
	firstRequest.Header.Set("X-Session-Route", "records")
	result, err := client.DoWithResourceSession(context.Background(), firstRequest, session)
	response, replacement := requireResourceSessionResponse(t, result, err)
	response.Body.Close()
	if replacement.Resource() != protocol.resourceID || replacement.Token() != resourceSessionTokenTwo {
		t.Fatalf("replacement = resource %q token %q", replacement.Resource(), replacement.Token())
	}
	if session.Token() != resourceSessionTokenOne {
		t.Fatalf("caller-owned session mutated to %q", session.Token())
	}
	if firstRequest.Header.Get("Authorization") != "" || firstRequest.Header.Get("Signature") != "" {
		t.Fatalf("caller request mutated: Authorization=%q Signature=%q", firstRequest.Header.Get("Authorization"), firstRequest.Header.Get("Signature"))
	}

	secondRequest, err := http.NewRequest(http.MethodGet, protocol.resourceID+"/records/43", nil)
	if err != nil {
		t.Fatal(err)
	}
	secondRequest.Header.Set("X-Session-Route", "records")
	result, err = client.DoWithResourceSession(context.Background(), secondRequest, replacement)
	response, same := requireResourceSessionResponse(t, result, err)
	response.Body.Close()
	if same.Resource() != replacement.Resource() || same.Token() != replacement.Token() {
		t.Fatalf("unchanged session = resource %q token %q", same.Resource(), same.Token())
	}
	if want := []string{"AAuth " + resourceSessionTokenOne, "AAuth " + resourceSessionTokenTwo}; len(seenAuthorization) != len(want) || seenAuthorization[0] != want[0] || seenAuthorization[1] != want[1] {
		t.Fatalf("Authorization values = %q, want %q", seenAuthorization, want)
	}
	if protectedCalls != 2 {
		t.Fatalf("protected calls = %d, want 2", protectedCalls)
	}
	if metadataCalls != 3 {
		t.Fatalf("metadata calls = %d, want one uncached discovery per call", metadataCalls)
	}
}

func TestDoWithResourceSessionWithComponentsPerformsOneExactExchange(t *testing.T) {
	protocol := newTestProtocol(t)
	issuer := protocol.newClientWithHTTPClient(t, &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
		if request.Method == http.MethodGet && request.URL.String() == protocol.resourceID+"/.well-known/aauth-resource.json" {
			return resourceSessionMetadataResponse(request, protocol.resourceID), nil
		}
		if request.Method == http.MethodPost && request.URL.Path == "/session/start" {
			verifyProofWithComponents(t, request, protocol.resolver, protocol.clock, aauth.AgentTokenType, []string{"x-session-route"})
			return resourceSessionSuccessResponse(request, resourceSessionTokenOne, "started"), nil
		}
		return nil, errors.New("unexpected session issuance request: " + request.URL.String())
	})})
	session := beginImmediateResourceSession(t, issuer, protocol)

	wantProfile := []string{"x-session-route", "prefer"}
	httpCalls := 0
	client := protocol.newClientWithHTTPClient(t, &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
		httpCalls++
		if request.URL.String() != protocol.resourceID+"/records/42" {
			return nil, errors.New("unexpected metadata or application request: " + request.URL.String())
		}
		verified := verifyProofWithComponents(t, request, protocol.resolver, protocol.clock, aauth.AgentTokenType,
			[]string{"authorization", "x-session-route", "prefer"})
		wantCovered := []string{"@method", "@authority", "@path", "authorization", "x-session-route", "prefer", "signature-key"}
		if got := verified.Proof.CoveredComponents(); !slicesEqual(got, wantCovered) {
			t.Fatalf("covered components = %v, want %v", got, wantCovered)
		}
		if request.Header.Get("Authorization") != "AAuth "+resourceSessionTokenOne ||
			request.Header.Get("X-Session-Route") != "do-fresh" || request.Header.Get("Prefer") != "wait=2" {
			t.Fatalf("session request headers = %#v", request.Header)
		}
		return &http.Response{
			StatusCode: http.StatusNoContent, Status: "204 No Content", Header: make(http.Header),
			Body: http.NoBody, Request: request,
		}, nil
	})})
	doer, ok := any(client).(resourceSessionDoWithComponents)
	if !ok {
		t.Fatal("*agent.Client is missing DoWithResourceSessionWithComponents")
	}
	request, err := http.NewRequest(http.MethodGet, protocol.resourceID+"/records/42", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("X-Session-Route", "do-fresh")
	request.Header.Set("Prefer", "wait=2")
	components := append([]string(nil), wantProfile...)
	result, err := doer.DoWithResourceSessionWithComponents(context.Background(), request, session, components)
	response, next := requireResourceSessionResponse(t, result, err)
	response.Body.Close()
	if next.Resource() != session.Resource() || next.Token() != session.Token() {
		t.Fatalf("next session = resource %q token %q", next.Resource(), next.Token())
	}
	if httpCalls != 1 {
		t.Fatalf("HTTP exchanges = %d, want exactly 1", httpCalls)
	}
	if !slicesEqual(components, wantProfile) {
		t.Fatalf("caller component list changed = %v", components)
	}
	if request.Header.Get("Authorization") != "" || request.Header.Get("Signature") != "" ||
		request.Header.Get("X-Session-Route") != "do-fresh" || request.Header.Get("Prefer") != "wait=2" {
		t.Fatalf("caller request changed = %#v", request.Header)
	}
}

func TestDoWithResourceSessionRejectsWrongBindingsAndInvalidReplacementWithoutMutation(t *testing.T) {
	protocol := newTestProtocol(t)
	issuerClient := protocol.newClientWithHTTPClient(t, &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
		if request.Method == http.MethodGet && request.URL.String() == protocol.resourceID+"/.well-known/aauth-resource.json" {
			return resourceSessionMetadataResponse(request, protocol.resourceID), nil
		}
		if request.Method == http.MethodPost && request.URL.Path == "/session/start" {
			verifyProofWithComponents(t, request, protocol.resolver, protocol.clock, aauth.AgentTokenType,
				[]string{"x-session-route"})
			return resourceSessionSuccessResponse(request, resourceSessionTokenOne, "started"), nil
		}
		return nil, errors.New("unexpected session issuance request")
	})})
	session := beginImmediateResourceSession(t, issuerClient, protocol)

	t.Run("other resource", func(t *testing.T) {
		networkCalls := 0
		client := protocol.newClientWithHTTPClient(t, &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
			networkCalls++
			return nil, errors.New("unexpected network")
		})})
		request, err := http.NewRequest(http.MethodGet, "https://other-resource.example/records", nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := client.DoWithResourceSession(context.Background(), request, session); err == nil {
			t.Fatal("session was accepted for another Resource")
		}
		if networkCalls != 0 {
			t.Fatalf("wrong-Resource session used network %d times", networkCalls)
		}
	})

	t.Run("other Agent", func(t *testing.T) {
		other := newTestProtocol(t)
		other.agentID = "aauth:other@ap.example"
		other.agentKey = protocol.agentKey
		var err error
		other.agentToken, err = aauth.MintAgentToken(other.agentProviderID, other.agentProviderKey, aauth.AgentTokenRequest{
			Agent: other.agentID, PersonServer: other.personServerID,
			PublicKey: other.agentKey.PublicJWK(), Lifetime: time.Hour,
		}, other.now, "other-agent-session-token")
		if err != nil {
			t.Fatal(err)
		}
		networkCalls := 0
		client := other.newClientWithHTTPClient(t, &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
			networkCalls++
			return nil, errors.New("unexpected network")
		})})
		request, err := http.NewRequest(http.MethodGet, protocol.resourceID+"/records", nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := client.DoWithResourceSession(context.Background(), request, session); err == nil {
			t.Fatal("session was accepted by another Agent using the same key")
		}
		if networkCalls != 0 {
			t.Fatalf("cross-Agent session used network %d times", networkCalls)
		}
	})

	for _, test := range []struct {
		name   string
		values []string
	}{
		{name: "multiple", values: []string{"first", "second"}},
		{name: "malformed", values: []string{"opaque token"}},
	} {
		t.Run(test.name+" replacement", func(t *testing.T) {
			client := protocol.newClientWithHTTPClient(t, &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
				if request.Method == http.MethodGet && request.URL.String() == protocol.resourceID+"/.well-known/aauth-resource.json" {
					return resourceSessionMetadataResponse(request, protocol.resourceID), nil
				}
				verifyProofWithComponents(t, request, protocol.resolver, protocol.clock, aauth.AgentTokenType,
					[]string{"authorization", "x-session-route"})
				response := &http.Response{
					StatusCode: http.StatusOK, Status: "200 OK", Header: make(http.Header),
					Body: http.NoBody, Request: request,
				}
				response.Header["Aauth-Access"] = append([]string(nil), test.values...)
				return response, nil
			})})
			request, err := http.NewRequest(http.MethodGet, protocol.resourceID+"/records", nil)
			if err != nil {
				t.Fatal(err)
			}
			request.Header.Set("X-Session-Route", "records")
			beforeToken := session.Token()
			if _, err := client.DoWithResourceSession(context.Background(), request, session); err == nil {
				t.Fatal("invalid replacement credential was accepted")
			}
			if session.Token() != beforeToken {
				t.Fatalf("caller-owned session mutated to %q", session.Token())
			}
			if request.Header.Get("Authorization") != "" || request.Header.Get("Signature") != "" {
				t.Fatalf("caller request mutated: Authorization=%q Signature=%q", request.Header.Get("Authorization"), request.Header.Get("Signature"))
			}
		})
	}
}

func TestDoWithResourceSessionReturnsReplacementOnRecognizedProtocolError(t *testing.T) {
	protocol := newTestProtocol(t)
	issuer := protocol.newClientWithHTTPClient(t, &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
		if request.Method == http.MethodGet && request.URL.String() == protocol.resourceID+"/.well-known/aauth-resource.json" {
			return resourceSessionMetadataResponse(request, protocol.resourceID), nil
		}
		if request.Method == http.MethodPost && request.URL.Path == "/session/start" {
			verifyProofWithComponents(t, request, protocol.resolver, protocol.clock, aauth.AgentTokenType, []string{"x-session-route"})
			return resourceSessionSuccessResponse(request, resourceSessionTokenOne, "started"), nil
		}
		return nil, errors.New("unexpected session issuance request: " + request.URL.String())
	})})
	session := beginImmediateResourceSession(t, issuer, protocol)

	for _, test := range []struct {
		name       string
		response   func(*http.Request) (*http.Response, *trackedBody)
		checkError func(*testing.T, error)
	}{
		{
			name: "Signature-Error",
			response: func(request *http.Request) (*http.Response, *trackedBody) {
				encoded, err := signaturekey.FormatError(signaturekey.Error{Code: signaturekey.ErrorExpiredJWT})
				if err != nil {
					t.Fatal(err)
				}
				body := &trackedBody{Reader: strings.NewReader("signature rejected")}
				response := &http.Response{
					StatusCode: http.StatusUnauthorized, Status: "401 Unauthorized", Header: make(http.Header),
					Body: body, Request: request,
				}
				response.Header.Set("Signature-Error", encoded)
				return response, body
			},
			checkError: func(t *testing.T, err error) {
				var failure *signaturekey.Error
				if !errors.As(err, &failure) || failure.Code != signaturekey.ErrorExpiredJWT {
					t.Fatalf("error = %v, Signature-Error = %#v", err, failure)
				}
			},
		},
		{
			name: "AAuth problem",
			response: func(request *http.Request) (*http.Response, *trackedBody) {
				response := problemResponse(request, &aauth.ProblemError{
					Status: http.StatusForbidden, Code: "access_denied", Detail: "session no longer authorized",
				})
				encoded, err := io.ReadAll(response.Body)
				if err != nil {
					t.Fatal(err)
				}
				_ = response.Body.Close()
				body := &trackedBody{Reader: strings.NewReader(string(encoded))}
				response.Body = body
				return response, body
			},
			checkError: func(t *testing.T, err error) {
				var problem *aauth.ProblemError
				if !errors.As(err, &problem) || problem.Status != http.StatusForbidden || problem.Code != "access_denied" {
					t.Fatalf("error = %v, problem = %#v", err, problem)
				}
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			var body *trackedBody
			client := protocol.newClientWithHTTPClient(t, &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
				if request.Method == http.MethodGet && request.URL.String() == protocol.resourceID+"/.well-known/aauth-resource.json" {
					return resourceSessionMetadataResponse(request, protocol.resourceID), nil
				}
				verifyProofWithComponents(t, request, protocol.resolver, protocol.clock, aauth.AgentTokenType,
					[]string{"authorization", "x-session-route"})
				response, tracked := test.response(request)
				body = tracked
				response.Header.Set("AAuth-Access", resourceSessionTokenTwo)
				return response, nil
			})})
			request, err := http.NewRequest(http.MethodGet, protocol.resourceID+"/records", nil)
			if err != nil {
				t.Fatal(err)
			}
			request.Header.Set("X-Session-Route", "records")
			result, err := client.DoWithResourceSession(context.Background(), request, session)
			if err != nil {
				t.Fatalf("recognized protocol response returned Go error: %v", err)
			}
			test.checkError(t, result.Failure())
			response, ok := result.Response()
			if !ok || response == nil || response.Body == nil {
				t.Fatalf("recognized protocol result lost its response: %#v", result)
			}
			replacement, ok := result.Session()
			if !ok {
				t.Fatal("recognized protocol result lost its replacement session")
			}
			if replacement.Resource() != protocol.resourceID || replacement.Token() != resourceSessionTokenTwo {
				t.Fatalf("replacement = resource %q token %q", replacement.Resource(), replacement.Token())
			}
			if session.Token() != resourceSessionTokenOne {
				t.Fatalf("caller-owned input session changed to %q", session.Token())
			}
			if body == nil {
				t.Fatal("recognized protocol result did not expose a response body")
			}
			encoded, err := io.ReadAll(response.Body)
			if err != nil || len(encoded) == 0 {
				t.Fatalf("recognized protocol response body = %q, error = %v", encoded, err)
			}
			response.Body.Close()
		})
	}
}

func TestRestoreResourceSessionPreservesStableIdentityAcrossProofRotation(t *testing.T) {
	protocol := newTestProtocol(t)
	issuer := protocol.newClientWithHTTPClient(t, &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
		if request.Method == http.MethodGet && request.URL.String() == protocol.resourceID+"/.well-known/aauth-resource.json" {
			return resourceSessionMetadataResponse(request, protocol.resourceID), nil
		}
		if request.Method == http.MethodPost && request.URL.Path == "/session/start" {
			verifyProofWithComponents(t, request, protocol.resolver, protocol.clock, aauth.AgentTokenType, []string{"x-session-route"})
			return resourceSessionSuccessResponse(request, resourceSessionTokenOne, "started"), nil
		}
		return nil, errors.New("unexpected session issuance request: " + request.URL.String())
	})})
	session := beginImmediateResourceSession(t, issuer, protocol)
	state := persistedResourceSessionState(t, session)
	wantState := map[string]string{
		"Resource": protocol.resourceID, "Token": resourceSessionTokenOne,
		"AgentProvider": protocol.agentProviderID, "Agent": protocol.agentID, "ParentAgent": "",
	}
	if state.Type().NumField() != len(wantState) {
		t.Fatalf("ResourceSessionState fields = %d, want exactly %d", state.Type().NumField(), len(wantState))
	}
	for name, want := range wantState {
		field := state.FieldByName(name)
		if !field.IsValid() || field.Kind() != reflect.String || field.String() != want {
			t.Fatalf("ResourceSessionState.%s = %v, want %q", name, field, want)
		}
	}

	rotatedKey := testSigningKey(t, "restored-session-rotated-key", 117)
	rotatedToken, err := aauth.MintAgentToken(protocol.agentProviderID, protocol.agentProviderKey, aauth.AgentTokenRequest{
		Agent: protocol.agentID, PersonServer: protocol.personServerID,
		PublicKey: rotatedKey.PublicJWK(), Lifetime: time.Hour,
	}, protocol.now, "restored-session-rotated-agent-token")
	if err != nil {
		t.Fatal(err)
	}
	httpCalls := 0
	rotated, err := agent.New(context.Background(), agent.Config{
		Identifier: protocol.agentID, SigningKey: rotatedKey, AgentToken: rotatedToken,
		KeyResolver: protocol.resolver, Clock: protocol.clock,
		HTTPClient: &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
			httpCalls++
			if request.Method == http.MethodGet && request.URL.String() == protocol.resourceID+"/.well-known/aauth-resource.json" {
				return resourceSessionMetadataResponse(request, protocol.resourceID), nil
			}
			verified := verifyProofWithComponents(t, request, protocol.resolver, protocol.clock, aauth.AgentTokenType,
				[]string{"authorization", "x-session-route"})
			claims, err := verified.AgentClaims()
			if err != nil {
				return nil, err
			}
			if claims.JTI != "restored-session-rotated-agent-token" ||
				!claims.Confirmation.JWK.Equal(rotatedKey.PublicJWK()) ||
				request.Header.Get("Authorization") != "AAuth "+resourceSessionTokenOne {
				return nil, errors.New("restored session did not use the current Agent proof context")
			}
			return &http.Response{
				StatusCode: http.StatusNoContent, Status: "204 No Content", Header: make(http.Header),
				Body: http.NoBody, Request: request,
			}, nil
		})},
	})
	if err != nil {
		t.Fatal(err)
	}
	restored, err := restoreResourceSessionState(t, rotated, state)
	if err != nil {
		t.Fatal(err)
	}
	if httpCalls != 0 {
		t.Fatalf("RestoreResourceSession made %d HTTP requests, want 0", httpCalls)
	}
	request, err := http.NewRequest(http.MethodGet, protocol.resourceID+"/records", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("X-Session-Route", "records")
	result, err := rotated.DoWithResourceSession(context.Background(), request, restored)
	response, next := requireResourceSessionResponse(t, result, err)
	response.Body.Close()
	if next.Resource() != protocol.resourceID || next.Token() != resourceSessionTokenOne {
		t.Fatalf("next restored session = resource %q token %q", next.Resource(), next.Token())
	}
	if httpCalls != 2 {
		t.Fatalf("restored session use made %d HTTP requests, want metadata plus application", httpCalls)
	}
}

func TestRestoreResourceSessionRejectsInvalidOrDifferentStateWithoutNetwork(t *testing.T) {
	protocol := newTestProtocol(t)
	issuer := protocol.newClientWithHTTPClient(t, &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
		if request.Method == http.MethodGet && request.URL.String() == protocol.resourceID+"/.well-known/aauth-resource.json" {
			return resourceSessionMetadataResponse(request, protocol.resourceID), nil
		}
		if request.Method == http.MethodPost && request.URL.Path == "/session/start" {
			verifyProofWithComponents(t, request, protocol.resolver, protocol.clock, aauth.AgentTokenType, []string{"x-session-route"})
			return resourceSessionSuccessResponse(request, resourceSessionTokenOne, "started"), nil
		}
		return nil, errors.New("unexpected session issuance request: " + request.URL.String())
	})})
	valid := persistedResourceSessionState(t, beginImmediateResourceSession(t, issuer, protocol))
	networkCalls := 0
	client := protocol.newClientWithHTTPClient(t, &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
		networkCalls++
		return nil, errors.New("unexpected restore network request: " + request.URL.String())
	})})

	set := func(name, value string) func(reflect.Value) reflect.Value {
		return func(state reflect.Value) reflect.Value {
			copy := reflect.New(state.Type()).Elem()
			copy.Set(state)
			copy.FieldByName(name).SetString(value)
			return copy
		}
	}
	for _, test := range []struct {
		name   string
		client *agent.Client
		change func(reflect.Value) reflect.Value
	}{
		{name: "nil client", client: nil, change: func(state reflect.Value) reflect.Value { return state }},
		{name: "zero state", client: client, change: func(state reflect.Value) reflect.Value { return reflect.Zero(state.Type()) }},
		{name: "HTTP Resource", client: client, change: set("Resource", "http://resource.example")},
		{name: "Resource path", client: client, change: set("Resource", protocol.resourceID+"/api")},
		{name: "Resource query", client: client, change: set("Resource", protocol.resourceID+"?tenant=one")},
		{name: "mixed-case Resource", client: client, change: set("Resource", "https://Resource.example")},
		{name: "empty token", client: client, change: set("Token", "")},
		{name: "whitespace token", client: client, change: set("Token", "opaque session")},
		{name: "invalid token character", client: client, change: set("Token", "opaque?session")},
		{name: "leading token padding", client: client, change: set("Token", "=opaque")},
		{name: "embedded token padding", client: client, change: set("Token", "opaque=tail")},
		{name: "invalid Agent Provider", client: client, change: set("AgentProvider", "http://ap.example")},
		{name: "invalid Agent", client: client, change: set("Agent", "reader@example")},
		{name: "invalid parent relationship", client: client, change: set("ParentAgent", "aauth:parent@other.example")},
		{name: "different Agent Provider", client: client, change: set("AgentProvider", "https://other-ap.example")},
		{name: "different Agent", client: client, change: set("Agent", "aauth:other@ap.example")},
		{name: "different parent Agent", client: client, change: set("ParentAgent", "aauth:parent@ap.example")},
	} {
		t.Run(test.name, func(t *testing.T) {
			before := networkCalls
			restored, err := restoreResourceSessionState(t, test.client, test.change(valid))
			if restored != (agent.ResourceSession{}) {
				t.Fatalf("restored session = %#v, want zero", restored)
			}
			var failure *agent.Error
			if !errors.As(err, &failure) || failure.Operation != "restore resource session" {
				t.Fatalf("error = %v, agent error = %#v", err, failure)
			}
			if networkCalls != before {
				t.Fatalf("RestoreResourceSession made %d network requests", networkCalls-before)
			}
		})
	}
}

func persistedResourceSessionState(t *testing.T, session agent.ResourceSession) reflect.Value {
	t.Helper()
	method := reflect.ValueOf(session).MethodByName("State")
	if !method.IsValid() {
		t.Fatal("agent.ResourceSession is missing State")
		return reflect.Value{}
	}
	if method.Type().NumIn() != 0 || method.Type().NumOut() != 1 || method.Type().Out(0).Kind() != reflect.Struct {
		t.Fatalf("ResourceSession.State signature = %s", method.Type())
	}
	return method.Call(nil)[0]
}

func restoreResourceSessionState(t *testing.T, client *agent.Client, state reflect.Value) (agent.ResourceSession, error) {
	t.Helper()
	method := reflect.ValueOf(client).MethodByName("RestoreResourceSession")
	if !method.IsValid() {
		t.Fatal("*agent.Client is missing RestoreResourceSession")
		return agent.ResourceSession{}, errors.New("missing RestoreResourceSession")
	}
	errorType := reflect.TypeOf((*error)(nil)).Elem()
	sessionType := reflect.TypeOf(agent.ResourceSession{})
	if method.Type().NumIn() != 1 || method.Type().In(0) != state.Type() || method.Type().NumOut() != 2 ||
		method.Type().Out(0) != sessionType || method.Type().Out(1) != errorType {
		t.Fatalf("Client.RestoreResourceSession signature = %s, state = %s", method.Type(), state.Type())
	}
	output := method.Call([]reflect.Value{state})
	restored := output[0].Interface().(agent.ResourceSession)
	if output[1].IsNil() {
		return restored, nil
	}
	return restored, output[1].Interface().(error)
}

func resourceSessionMetadataResponse(request *http.Request, resource string) *http.Response {
	return resourceSessionMetadataResponseWithComponents(request, resource, []string{"x-session-route"})
}

func resourceSessionMetadataResponseWithComponents(request *http.Request, resource string, components []string) *http.Response {
	return jsonResponse(request, http.StatusOK, map[string]any{
		"issuer":                          resource,
		"access_mode":                     string(aauth.AccessModeSessionToken),
		"additional_signature_components": components,
	})
}

func resourceSessionSuccessResponse(request *http.Request, token, body string) *http.Response {
	response := &http.Response{
		StatusCode: http.StatusOK,
		Status:     "200 OK",
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(body)),
		Request:    request,
	}
	if token != "" {
		response.Header.Set("AAuth-Access", token)
	}
	return response
}

func validResourceSessionPendingResponse(request *http.Request, retryAfter, status string, includeInteraction bool) *http.Response {
	header := make(http.Header)
	header.Set("Location", resourceSessionLocation)
	header.Set("Retry-After", retryAfter)
	header.Set("Cache-Control", "no-store")
	header.Set("Content-Type", "application/json")
	if includeInteraction {
		header.Set("AAuth-Requirement", interactionRequirement(resourceInteractionURL, resourceInteractionCode))
	}
	return &http.Response{
		StatusCode: http.StatusAccepted,
		Status:     "202 Accepted",
		Header:     header,
		Body:       io.NopCloser(strings.NewReader(`{"status":"` + status + `"}`)),
		Request:    request,
	}
}

func beginPendingResourceSession(t *testing.T, client *agent.Client, protocol *testProtocol) agent.PendingResourceSession {
	t.Helper()
	request, err := http.NewRequest(http.MethodPost, protocol.resourceID+"/records", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("X-Session-Route", "records")
	request.Header.Set("AAuth-Capabilities", "interaction")
	result, err := client.BeginResourceSession(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	pending, ok := result.Pending()
	if !ok {
		t.Fatal("BeginResourceSession did not return pending")
	}
	return pending
}

func beginImmediateResourceSession(t *testing.T, client *agent.Client, protocol *testProtocol) agent.ResourceSession {
	t.Helper()
	request, err := http.NewRequest(http.MethodPost, protocol.resourceID+"/session/start", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("X-Session-Route", "session-start")
	result, err := client.BeginResourceSession(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	session, ok := result.Session()
	if !ok {
		t.Fatal("BeginResourceSession did not return a session")
	}
	if response, ok := result.Response(); ok {
		response.Body.Close()
	}
	return session
}

func requireResourceSessionResponse(
	t *testing.T,
	result agent.ResourceSessionResult,
	err error,
) (*http.Response, agent.ResourceSession) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
	if failure := result.Failure(); failure != nil {
		t.Fatalf("Resource session protocol failure = %v", failure)
	}
	response, ok := result.Response()
	if !ok {
		t.Fatal("Resource session result has no response")
	}
	session, ok := result.Session()
	if !ok {
		response.Body.Close()
		t.Fatal("Resource session result has no session")
	}
	return response, session
}
