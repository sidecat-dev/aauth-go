package agent_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	aauth "github.com/aauth-dev/auth-go"
	"github.com/aauth-dev/auth-go/agent"
	"github.com/aauth-dev/auth-go/jose"
	"github.com/aauth-dev/auth-go/signaturekey"
)

func TestCallAsAgentPerformsOneExplicitCurrentProof(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 30, 18, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	providerKey := agentIdentityKey(t, "agent-identity-provider")
	agentKey := agentIdentityKey(t, "agent-identity-agent")
	const (
		providerID = "https://ap.example"
		agentID    = "aauth:reader@ap.example"
		resourceID = "https://resource.example"
	)
	compact, err := aauth.MintAgentToken(providerID, providerKey, aauth.AgentTokenRequest{
		Agent: agentID, PublicKey: agentKey.PublicJWK(), Lifetime: time.Hour,
	}, now, "agent-identity-token")
	if err != nil {
		t.Fatal(err)
	}
	resolver := signaturekey.StaticKeyResolver{
		{Issuer: providerID, DiscoveryDocument: aauth.AgentDiscoveryDocument, KeyID: providerKey.ID()}: providerKey.PublicJWK(),
	}
	metadataCalls, protectedCalls := 0, 0
	var covered []string
	httpClient := &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
		switch request.URL.String() {
		case resourceID + "/.well-known/aauth-resource.json":
			metadataCalls++
			return jsonResponse(request, http.StatusOK, map[string]any{
				"issuer": resourceID, "access_mode": "agent-token",
				"additional_signature_components": []string{"x-request-id"},
			}), nil
		case resourceID + "/records":
			protectedCalls++
			verified := verifyProofWithComponents(t, request, resolver, clock, aauth.AgentTokenType, []string{"x-request-id"})
			claims, err := verified.AgentClaims()
			if err != nil || claims.Subject != agentID {
				t.Fatalf("agent claims = %#v, %v", claims, err)
			}
			covered = verified.Proof.CoveredComponents()
			return &http.Response{
				StatusCode: http.StatusOK, Status: "200 OK",
				Header: http.Header{"Content-Type": []string{"text/plain"}},
				Body:   io.NopCloser(strings.NewReader("accepted")), Request: request,
			}, nil
		default:
			return nil, errors.New("unexpected request: " + request.URL.String())
		}
	})}
	client, err := agent.New(context.Background(), agent.Config{
		Identifier: agentID, SigningKey: agentKey, AgentToken: compact,
		KeyResolver: resolver, HTTPClient: httpClient, Clock: clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest(http.MethodGet, resourceID+"/records", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("X-Request-ID", "direct-agent-1")
	response, err := client.CallAsAgent(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode != http.StatusOK || string(body) != "accepted" || metadataCalls != 1 || protectedCalls != 1 ||
		!containsString(covered, "x-request-id") {
		t.Fatalf("response=%d %q metadata=%d protected=%d covered=%v", response.StatusCode, body, metadataCalls, protectedCalls, covered)
	}
	if _, err := client.PersonToken(context.Background(), agent.PersonTokenRequest{
		PersonServer: "https://ps.example", Resource: resourceID,
	}); err == nil || !strings.Contains(err.Error(), "does not name a person server") {
		t.Fatalf("PS-less PersonToken error = %v", err)
	}
	if _, err := client.Exchange(context.Background(), agent.ExchangeRequest{
		PersonServer: "https://ps.example", ResourceToken: "not-used",
	}); err == nil || !strings.Contains(err.Error(), "does not name a person server") {
		t.Fatalf("PS-less Exchange error = %v", err)
	}
	if metadataCalls != 1 || protectedCalls != 1 {
		t.Fatalf("PS-less methods reached network: metadata=%d protected=%d", metadataCalls, protectedCalls)
	}

	now = now.Add(2 * time.Hour)
	request, _ = http.NewRequest(http.MethodGet, resourceID+"/records", nil)
	if _, err := client.CallAsAgent(context.Background(), request); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expired CallAsAgent error = %v", err)
	}
	if metadataCalls != 1 || protectedCalls != 1 {
		t.Fatalf("expired token reached network: metadata=%d protected=%d", metadataCalls, protectedCalls)
	}
}

func TestCallAsAgentRefusesUnsatisfiablePersonTokenRequirement(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 30, 18, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	providerKey := agentIdentityKey(t, "ps-less-requirement-provider")
	agentKey := agentIdentityKey(t, "ps-less-requirement-agent")
	const (
		providerID = "https://ap.example"
		agentID    = "aauth:reader@ap.example"
		resourceID = "https://resource.example"
	)
	compact, err := aauth.MintAgentToken(providerID, providerKey, aauth.AgentTokenRequest{
		Agent: agentID, PublicKey: agentKey.PublicJWK(), Lifetime: time.Hour,
	}, now, "ps-less-requirement-token")
	if err != nil {
		t.Fatal(err)
	}
	resolver := signaturekey.StaticKeyResolver{
		{Issuer: providerID, DiscoveryDocument: aauth.AgentDiscoveryDocument, KeyID: providerKey.ID()}: providerKey.PublicJWK(),
	}
	body := &trackedBody{Reader: strings.NewReader("authorization required")}
	metadataCalls, protectedCalls := 0, 0
	httpClient := &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
		switch request.URL.String() {
		case resourceID + "/.well-known/aauth-resource.json":
			metadataCalls++
			return jsonResponse(request, http.StatusOK, map[string]any{
				"issuer": resourceID, "access_mode": "person-token",
			}), nil
		case resourceID + "/records":
			protectedCalls++
			return &http.Response{
				StatusCode: http.StatusUnauthorized, Status: "401 Unauthorized", Request: request,
				Header: http.Header{"Aauth-Requirement": []string{aauth.FormatPersonTokenRequirement()}},
				Body:   body,
			}, nil
		default:
			return nil, errors.New("unexpected request: " + request.URL.String())
		}
	})}
	client, err := agent.New(context.Background(), agent.Config{
		Identifier: agentID, SigningKey: agentKey, AgentToken: compact,
		KeyResolver: resolver, HTTPClient: httpClient, Clock: clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	request, _ := http.NewRequest(http.MethodGet, resourceID+"/records", nil)
	response, err := client.CallAsAgent(context.Background(), request)
	if err == nil || !strings.Contains(err.Error(), "person-token requirement") {
		if response != nil {
			response.Body.Close()
		}
		t.Fatalf("CallAsAgent error = %v, response = %#v", err, response)
	}
	if response != nil || !body.closed || metadataCalls != 1 || protectedCalls != 1 {
		t.Fatalf("response=%#v closed=%t metadata=%d protected=%d", response, body.closed, metadataCalls, protectedCalls)
	}
}

func TestSubAgentCanCallAsAgentButCannotCallPersonServer(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 30, 18, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	providerKey := agentIdentityKey(t, "sub-agent-provider")
	subAgentKey := agentIdentityKey(t, "sub-agent-key")
	const (
		providerID   = "https://ap.example"
		parentID     = "aauth:reader@ap.example"
		subAgentID   = "aauth:reader+child@ap.example"
		personServer = "https://ps.example"
		resourceID   = "https://resource.example"
	)
	compact, err := aauth.MintAgentToken(providerID, providerKey, aauth.AgentTokenRequest{
		Agent: subAgentID, ParentAgent: parentID, PersonServer: personServer,
		PublicKey: subAgentKey.PublicJWK(), Lifetime: time.Hour,
	}, now, "sub-agent-identity-token")
	if err != nil {
		t.Fatal(err)
	}
	resolver := signaturekey.StaticKeyResolver{
		{Issuer: providerID, DiscoveryDocument: aauth.AgentDiscoveryDocument, KeyID: providerKey.ID()}: providerKey.PublicJWK(),
	}
	metadataCalls, protectedCalls, personServerCalls := 0, 0, 0
	httpClient := &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
		switch request.URL.String() {
		case resourceID + "/.well-known/aauth-resource.json":
			metadataCalls++
			return jsonResponse(request, http.StatusOK, map[string]any{
				"issuer": resourceID, "access_mode": "agent-token",
			}), nil
		case resourceID + "/records":
			protectedCalls++
			verified := verifyProofWithComponents(t, request, resolver, clock, aauth.AgentTokenType, nil)
			claims, err := verified.AgentClaims()
			if err != nil || claims.Subject != subAgentID || claims.ParentAgent != parentID {
				t.Fatalf("sub-agent claims = %#v, %v", claims, err)
			}
			return &http.Response{
				StatusCode: http.StatusOK, Status: "200 OK", Header: make(http.Header),
				Body: io.NopCloser(strings.NewReader("accepted")), Request: request,
			}, nil
		default:
			personServerCalls++
			return nil, errors.New("sub-agent reached Person Server: " + request.URL.String())
		}
	})}
	client, err := agent.New(context.Background(), agent.Config{
		Identifier: subAgentID, SigningKey: subAgentKey, AgentToken: compact,
		KeyResolver: resolver, HTTPClient: httpClient, Clock: clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	request, _ := http.NewRequest(http.MethodGet, resourceID+"/records", nil)
	response, err := client.CallAsAgent(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusOK || metadataCalls != 1 || protectedCalls != 1 {
		t.Fatalf("status=%d metadata=%d protected=%d", response.StatusCode, metadataCalls, protectedCalls)
	}

	for name, call := range map[string]func() error{
		"person token": func() error {
			_, err := client.PersonToken(context.Background(), agent.PersonTokenRequest{
				PersonServer: personServer, Resource: resourceID,
			})
			return err
		},
		"poll person token": func() error {
			_, err := client.PollPersonToken(context.Background(), agent.PendingPersonToken{})
			return err
		},
		"exchange": func() error {
			_, err := client.Exchange(context.Background(), agent.ExchangeRequest{
				PersonServer: personServer, ResourceToken: "not-used",
			})
			return err
		},
	} {
		if err := call(); err == nil || !strings.Contains(err.Error(), "sub-agent must not call the Person Server directly") {
			t.Fatalf("%s error = %v", name, err)
		}
	}
	if personServerCalls != 0 || metadataCalls != 1 || protectedCalls != 1 {
		t.Fatalf("unexpected calls: ps=%d metadata=%d protected=%d", personServerCalls, metadataCalls, protectedCalls)
	}
}

func TestCallAsAgentWithComponentsDoesNotRequireMetadata(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 30, 18, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	providerKey := agentIdentityKey(t, "metadata-less-provider")
	agentKey := agentIdentityKey(t, "metadata-less-agent")
	const (
		providerID = "https://ap.example"
		agentID    = "aauth:reader@ap.example"
		resourceID = "https://resource.example"
	)
	compact, err := aauth.MintAgentToken(providerID, providerKey, aauth.AgentTokenRequest{
		Agent: agentID, PublicKey: agentKey.PublicJWK(), Lifetime: time.Hour,
	}, now, "metadata-less-token")
	if err != nil {
		t.Fatal(err)
	}
	resolver := signaturekey.StaticKeyResolver{
		{Issuer: providerID, DiscoveryDocument: aauth.AgentDiscoveryDocument, KeyID: providerKey.ID()}: providerKey.PublicJWK(),
	}
	metadataCalls, protectedCalls := 0, 0
	httpClient := &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.Path == "/.well-known/aauth-resource.json" {
			metadataCalls++
			return nil, errors.New("metadata is not published")
		}
		if request.URL.String() != resourceID+"/records" {
			return nil, errors.New("unexpected request: " + request.URL.String())
		}
		protectedCalls++
		verified := verifyProofWithComponents(t, request, resolver, clock, aauth.AgentTokenType, []string{"x-request-id"})
		claims, err := verified.AgentClaims()
		if err != nil || claims.Subject != agentID {
			t.Fatalf("agent claims = %#v, %v", claims, err)
		}
		return &http.Response{
			StatusCode: http.StatusNoContent, Status: "204 No Content", Header: make(http.Header),
			Body: http.NoBody, Request: request,
		}, nil
	})}
	client, err := agent.New(context.Background(), agent.Config{
		Identifier: agentID, SigningKey: agentKey, AgentToken: compact,
		KeyResolver: resolver, HTTPClient: httpClient, Clock: clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	request, _ := http.NewRequest(http.MethodGet, resourceID+"/records", nil)
	request.Header.Set("X-Request-ID", "metadata-less-1")
	response, err := client.CallAsAgentWithComponents(context.Background(), request, []string{"x-request-id"})
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusNoContent || metadataCalls != 0 || protectedCalls != 1 {
		t.Fatalf("status=%d metadata=%d protected=%d", response.StatusCode, metadataCalls, protectedCalls)
	}
	request, _ = http.NewRequest(http.MethodGet, resourceID+"/records", nil)
	if _, err := client.CallAsAgentWithComponents(context.Background(), request, []string{"Content-Type"}); err == nil {
		t.Fatal("invalid component was accepted")
	}
	if metadataCalls != 0 || protectedCalls != 1 {
		t.Fatalf("invalid components reached network: metadata=%d protected=%d", metadataCalls, protectedCalls)
	}
}

func agentIdentityKey(t *testing.T, id string) jose.SigningKey {
	t.Helper()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := jose.NewEd25519SigningKey(id, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return key
}
