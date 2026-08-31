package agent_test

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	aauth "aauth-go"
	"aauth-go/agent"
)

func TestClientProposesAndVerifiesMission(t *testing.T) {
	t.Parallel()

	protocol := newTestProtocol(t)
	const missionEndpoint = "https://ps.example/mission"
	proposal := aauth.MissionProposal{
		Description: "# Read records\n\nRead the records needed for the report.",
		Resources:   []string{protocol.resourceID},
	}
	approvedAt := protocol.now
	expiresAt := protocol.now.Add(15 * time.Minute)
	mission := mustEncodeMission(t, aauth.MissionBlob{
		Approver: protocol.personServerID, Agent: protocol.agentID, ApprovedAt: approvedAt,
		ExpiresAt: &expiresAt, Description: proposal.Description,
		ApprovedResources: []string{protocol.resourceID},
	})
	personToken, err := aauth.MintPersonToken(protocol.personServerKey, aauth.PersonTokenClaims{
		Issuer: protocol.personServerID, DWK: aauth.PersonDiscoveryDocument,
		Audience: protocol.resourceID, Subject: "person-123",
		Confirmation: aauth.Confirmation{JWK: protocol.agentKey.PublicJWK()},
		JTI:          "mission-person-token", IssuedAt: protocol.now.Unix(), ExpiresAt: expiresAt.Unix(),
		MissionS256: mission.S256,
	})
	if err != nil {
		t.Fatal(err)
	}
	missionCalls := 0
	client := protocol.newClientWithHTTPClient(t, &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
		switch {
		case request.Method == http.MethodGet && request.URL.String() == protocol.personServerID+"/.well-known/aauth-person.json":
			return jsonResponse(request, http.StatusOK, map[string]any{
				"issuer": protocol.personServerID, "person_token_endpoint": protocol.personTokenEndpoint,
				"auth_token_endpoint": protocol.authTokenEndpoint, "mission_endpoint": missionEndpoint,
			}), nil
		case request.Method == http.MethodPost && request.URL.String() == missionEndpoint:
			missionCalls++
			verified := verifyProof(t, request, protocol.resolver, protocol.clock, aauth.AgentTokenType)
			claims, err := verified.AgentClaims()
			if err != nil || claims.Subject != protocol.agentID {
				t.Fatalf("mission Agent = %#v, %v", claims, err)
			}
			var got aauth.MissionProposal
			decodeRequest(t, request, &got)
			if !slices.Equal(got.Resources, proposal.Resources) || got.Description != proposal.Description {
				t.Fatalf("proposal = %#v", got)
			}
			response := jsonResponse(request, http.StatusOK, aauth.MissionApproval{
				S256: mission.S256, Mission: mission.Encoded, Capabilities: []string{"interaction"},
				PersonTokens: map[string]string{protocol.resourceID: personToken},
			})
			response.Header.Set("Cache-Control", "no-store")
			return response, nil
		default:
			return nil, errors.New("unexpected request: " + request.URL.String())
		}
	})})

	result, err := client.ProposeMission(context.Background(), agent.MissionRequest{
		PersonServer: protocol.personServerID, Proposal: proposal,
	})
	if err != nil {
		t.Fatal(err)
	}
	approved := result.Mission()
	if approved.S256 != mission.S256 || string(approved.ExactJSON) != string(mission.ExactJSON) ||
		approved.Blob.Agent != protocol.agentID || approved.Blob.Approver != protocol.personServerID {
		t.Fatalf("mission result = %#v", approved)
	}
	if !slices.Equal(result.Capabilities(), []string{"interaction"}) {
		t.Fatalf("capabilities = %#v", result.Capabilities())
	}
	gotToken, ok := result.PersonToken(protocol.resourceID)
	if !ok || gotToken != personToken || missionCalls != 1 {
		t.Fatalf("person token = %q, present=%t, calls=%d", gotToken, ok, missionCalls)
	}
	allTokens := result.PersonTokens()
	delete(allTokens, protocol.resourceID)
	if _, ok := result.PersonToken(protocol.resourceID); !ok {
		t.Fatal("caller mutated retained mission result")
	}
	approved.ExactJSON[0] ^= 1
	if result.Mission().ExactJSON[0] != mission.ExactJSON[0] {
		t.Fatal("caller mutated exact mission bytes")
	}
}

func TestClientRejectsInvalidMissionApprovalBindings(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name   string
		change func(*testProtocol, *aauth.ApprovedMission, *aauth.MissionApproval)
	}{
		{name: "digest substitution", change: func(_ *testProtocol, _ *aauth.ApprovedMission, approval *aauth.MissionApproval) {
			approval.S256 = aauth.MissionS256([]byte("other"))
		}},
		{name: "wrong approver", change: func(protocol *testProtocol, mission *aauth.ApprovedMission, approval *aauth.MissionApproval) {
			*mission = mustEncodeMission(t, aauth.MissionBlob{Approver: "https://other.example", Agent: protocol.agentID, ApprovedAt: protocol.now, Description: "Work"})
			approval.S256, approval.Mission = mission.S256, mission.Encoded
		}},
		{name: "wrong agent", change: func(protocol *testProtocol, mission *aauth.ApprovedMission, approval *aauth.MissionApproval) {
			*mission = mustEncodeMission(t, aauth.MissionBlob{Approver: protocol.personServerID, Agent: "aauth:other@ap.example", ApprovedAt: protocol.now, Description: "Work"})
			approval.S256, approval.Mission = mission.S256, mission.Encoded
		}},
		{name: "unapproved token resource", change: func(_ *testProtocol, _ *aauth.ApprovedMission, approval *aauth.MissionApproval) {
			approval.PersonTokens = map[string]string{"https://other.example": "token"}
		}},
		{name: "mission token mismatch", change: func(protocol *testProtocol, mission *aauth.ApprovedMission, approval *aauth.MissionApproval) {
			compact, err := aauth.MintPersonToken(protocol.personServerKey, aauth.PersonTokenClaims{
				Issuer: protocol.personServerID, DWK: aauth.PersonDiscoveryDocument,
				Audience: protocol.resourceID, Subject: "person", Confirmation: aauth.Confirmation{JWK: protocol.agentKey.PublicJWK()},
				JTI: "wrong-mission", IssuedAt: protocol.now.Unix(), ExpiresAt: protocol.now.Add(time.Minute).Unix(),
				MissionS256: aauth.MissionS256([]byte("other")),
			})
			if err != nil {
				t.Fatal(err)
			}
			approval.PersonTokens = map[string]string{protocol.resourceID: compact}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			protocol := newTestProtocol(t)
			mission := mustEncodeMission(t, aauth.MissionBlob{
				Approver: protocol.personServerID, Agent: protocol.agentID, ApprovedAt: protocol.now,
				Description: "Work", ApprovedResources: []string{protocol.resourceID},
			})
			personToken, err := aauth.MintPersonToken(protocol.personServerKey, aauth.PersonTokenClaims{
				Issuer: protocol.personServerID, DWK: aauth.PersonDiscoveryDocument,
				Audience: protocol.resourceID, Subject: "person", Confirmation: aauth.Confirmation{JWK: protocol.agentKey.PublicJWK()},
				JTI: "mission-person", IssuedAt: protocol.now.Unix(), ExpiresAt: protocol.now.Add(time.Minute).Unix(), MissionS256: mission.S256,
			})
			if err != nil {
				t.Fatal(err)
			}
			approval := aauth.MissionApproval{S256: mission.S256, Mission: mission.Encoded, PersonTokens: map[string]string{protocol.resourceID: personToken}}
			test.change(protocol, &mission, &approval)
			client := protocol.newClientWithHTTPClient(t, missionHTTPClient(t, protocol, approval))
			if _, err := client.ProposeMission(context.Background(), agent.MissionRequest{
				PersonServer: protocol.personServerID,
				Proposal:     aauth.MissionProposal{Description: "Work", Resources: []string{protocol.resourceID}},
			}); err == nil {
				t.Fatal("invalid approval was accepted")
			}
		})
	}
}

func TestClientRejectsDuplicatePersonTokenIdentityInMissionApproval(t *testing.T) {
	t.Parallel()

	protocol := newTestProtocol(t)
	const otherResource = "https://resource-2.example"
	mission := mustEncodeMission(t, aauth.MissionBlob{
		Approver: protocol.personServerID, Agent: protocol.agentID, ApprovedAt: protocol.now,
		Description: "Read both records", ApprovedResources: []string{protocol.resourceID, otherResource},
	})
	personTokens := make(map[string]string, 2)
	for _, resource := range mission.Blob.ApprovedResources {
		compact, err := aauth.MintPersonToken(protocol.personServerKey, aauth.PersonTokenClaims{
			Issuer: protocol.personServerID, DWK: aauth.PersonDiscoveryDocument,
			Audience: resource, Subject: "person", Confirmation: aauth.Confirmation{JWK: protocol.agentKey.PublicJWK()},
			JTI: "duplicate-person-token", IssuedAt: protocol.now.Unix(), ExpiresAt: protocol.now.Add(time.Minute).Unix(),
			MissionS256: mission.S256,
		})
		if err != nil {
			t.Fatal(err)
		}
		personTokens[resource] = compact
	}
	client := protocol.newClientWithHTTPClient(t, missionHTTPClient(t, protocol, aauth.MissionApproval{
		S256: mission.S256, Mission: mission.Encoded, PersonTokens: personTokens,
	}))

	_, err := client.ProposeMission(context.Background(), agent.MissionRequest{
		PersonServer: protocol.personServerID,
		Proposal: aauth.MissionProposal{
			Description: mission.Blob.Description, Resources: append([]string(nil), mission.Blob.ApprovedResources...),
		},
	})
	if err == nil || !strings.Contains(err.Error(), "duplicate person-token issuer and jti") {
		t.Fatalf("ProposeMission error = %v", err)
	}
}

func TestClientRequestsAndVerifiesMissionBoundPersonToken(t *testing.T) {
	t.Parallel()

	protocol := newTestProtocol(t)
	missionS256 := aauth.MissionS256([]byte("approved mission"))
	personToken, err := aauth.MintPersonToken(protocol.personServerKey, aauth.PersonTokenClaims{
		Issuer: protocol.personServerID, DWK: aauth.PersonDiscoveryDocument,
		Audience: protocol.resourceID, Subject: "person-123",
		Confirmation: aauth.Confirmation{JWK: protocol.agentKey.PublicJWK()},
		JTI:          "later-mission-person-token", IssuedAt: protocol.now.Unix(), ExpiresAt: protocol.now.Add(time.Minute).Unix(),
		MissionS256: missionS256,
	})
	if err != nil {
		t.Fatal(err)
	}
	client := protocol.newClientWithHTTPClient(t, &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
		if request.Method == http.MethodGet {
			return jsonResponse(request, http.StatusOK, map[string]any{
				"issuer": protocol.personServerID, "person_token_endpoint": protocol.personTokenEndpoint,
				"auth_token_endpoint": protocol.authTokenEndpoint,
			}), nil
		}
		verified := verifyProof(t, request, protocol.resolver, protocol.clock, aauth.AgentTokenType)
		if _, err := verified.AgentClaims(); err != nil {
			t.Fatal(err)
		}
		var input struct {
			Resource    string `json:"resource"`
			MissionS256 string `json:"mission_s256"`
		}
		decodeRequest(t, request, &input)
		if input.Resource != protocol.resourceID || input.MissionS256 != missionS256 {
			t.Fatalf("person-token request = %#v", input)
		}
		response := jsonResponse(request, http.StatusOK, map[string]any{
			"person_token": personToken, "expires_in": 60,
		})
		response.Header.Set("Cache-Control", "no-store")
		return response, nil
	})})
	result, err := client.PersonToken(context.Background(), agent.PersonTokenRequest{
		PersonServer: protocol.personServerID, Resource: protocol.resourceID, MissionS256: missionS256,
	})
	if err != nil {
		t.Fatal(err)
	}
	got, ok := result.Token()
	if !ok || got != personToken {
		t.Fatalf("person token = %q, present=%t", got, ok)
	}
}

func TestClientRejectsResourceTokenThatOutlivesMissionBoundPersonToken(t *testing.T) {
	t.Parallel()

	protocol := newTestProtocol(t)
	missionS256 := aauth.MissionS256([]byte("short mission"))
	personToken, err := aauth.MintPersonToken(protocol.personServerKey, aauth.PersonTokenClaims{
		Issuer: protocol.personServerID, DWK: aauth.PersonDiscoveryDocument,
		Audience: protocol.resourceID, Subject: "person-123",
		Confirmation: aauth.Confirmation{JWK: protocol.agentKey.PublicJWK()},
		JTI:          "short-mission-person", IssuedAt: protocol.now.Unix(), ExpiresAt: protocol.now.Add(time.Minute).Unix(),
		MissionS256: missionS256,
	})
	if err != nil {
		t.Fatal(err)
	}
	client := protocol.newClientWithHTTPClient(t, &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
		if request.Method == http.MethodGet {
			return jsonResponse(request, http.StatusOK, map[string]any{
				"issuer": protocol.resourceID, "authorization_endpoint": protocol.authorizationEndpoint,
				"scope_descriptions": map[string]string{"records.read": "Read records"},
			}), nil
		}
		verified := verifyProofWithComponents(
			t, request, protocol.resolver, protocol.clock, aauth.PersonTokenType,
			[]string{"content-type", "content-digest"},
		)
		person, err := verified.PersonClaims()
		if err != nil {
			t.Fatal(err)
		}
		thumbprint, _ := protocol.agentKey.PublicJWK().Thumbprint()
		resourceToken, err := aauth.MintResourceToken(protocol.resourceKey, aauth.ResourceTokenClaims{
			Issuer: protocol.resourceID, DWK: aauth.ResourceDiscoveryDocument,
			Audience: protocol.personServerID, JTI: "too-long-resource", AgentJKT: thumbprint,
			IssuedAt: protocol.now.Unix(), ExpiresAt: protocol.now.Add(5 * time.Minute).Unix(), Scope: "records.read",
			PersonServer: person.Issuer, Subject: person.Subject, PresentedJTI: person.JTI, MissionS256: missionS256,
		})
		if err != nil {
			t.Fatal(err)
		}
		return jsonResponse(request, http.StatusOK, map[string]string{"resource_token": resourceToken}), nil
	})})
	_, err = client.Authorize(context.Background(), agent.AuthorizeRequest{
		Resource: protocol.resourceID, PersonToken: personToken, Scopes: []string{"records.read"},
	})
	if err == nil || !strings.Contains(err.Error(), "outlives the mission-bound person token") {
		t.Fatalf("Authorize error = %v", err)
	}
}

func TestMissionSpecificContinuationsReturnTypedErrors(t *testing.T) {
	t.Run("mission approval", func(t *testing.T) {
		protocol := newTestProtocol(t)
		client := protocol.newClientWithHTTPClient(t, &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
			if request.Method == http.MethodGet {
				return jsonResponse(request, http.StatusOK, map[string]any{
					"issuer": protocol.personServerID, "person_token_endpoint": protocol.personTokenEndpoint,
					"auth_token_endpoint": protocol.authTokenEndpoint, "mission_endpoint": protocol.personServerID + "/mission",
				}), nil
			}
			return jsonResponse(request, http.StatusAccepted, map[string]string{"status": "pending"}), nil
		})})

		_, err := client.ProposeMission(context.Background(), agent.MissionRequest{
			PersonServer: protocol.personServerID,
			Proposal:     aauth.MissionProposal{Description: "Read records", Resources: []string{protocol.resourceID}},
		})
		assertMissionContinuationError(t, err, "approval", "ProposeMission")
	})

	t.Run("person-token issuance", func(t *testing.T) {
		protocol := newTestProtocol(t)
		client := protocol.newClientWithHTTPClient(t, &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
			if request.Method == http.MethodGet {
				return jsonResponse(request, http.StatusOK, map[string]any{
					"issuer": protocol.personServerID, "person_token_endpoint": protocol.personTokenEndpoint,
					"auth_token_endpoint": protocol.authTokenEndpoint,
				}), nil
			}
			return jsonResponse(request, http.StatusAccepted, map[string]string{"status": "pending"}), nil
		})})

		_, err := client.PersonToken(context.Background(), agent.PersonTokenRequest{
			PersonServer: protocol.personServerID, Resource: protocol.resourceID,
			MissionS256: aauth.MissionS256([]byte("approved mission")),
		})
		assertMissionContinuationError(t, err, "person-token issuance", "PersonToken")
	})

	for _, operation := range []struct {
		name string
		call func(*agent.Client, agent.ExchangeRequest) error
	}{
		{name: "Exchange", call: func(client *agent.Client, input agent.ExchangeRequest) error {
			_, err := client.Exchange(context.Background(), input)
			return err
		}},
		{name: "BeginExchange", call: func(client *agent.Client, input agent.ExchangeRequest) error {
			_, err := client.BeginExchange(context.Background(), input)
			return err
		}},
	} {
		operation := operation
		t.Run(operation.name, func(t *testing.T) {
			harness := newExchangeInteractionHarness(t)
			harness.resourceClaims.MissionS256 = aauth.MissionS256([]byte("approved mission"))
			var err error
			harness.resourceToken, err = aauth.MintResourceToken(harness.protocol.resourceKey, harness.resourceClaims)
			if err != nil {
				t.Fatal(err)
			}
			harness.initial = func(request *http.Request) (*http.Response, error) {
				return jsonResponse(request, http.StatusAccepted, map[string]string{"status": "pending"}), nil
			}
			err = operation.call(harness.client(t), agent.ExchangeRequest{
				PersonServer: harness.protocol.personServerID, ResourceToken: harness.resourceToken,
			})
			assertMissionContinuationError(t, err, "auth-token exchange", operation.name)
		})
	}
}

func assertMissionContinuationError(t *testing.T, err error, phase, operation string) {
	t.Helper()
	var unsupported *agent.MissionContinuationUnsupportedError
	if !errors.As(err, &unsupported) {
		t.Fatalf("error = %v, want *agent.MissionContinuationUnsupportedError", err)
	}
	if unsupported.Phase != phase || unsupported.Operation != operation {
		t.Fatalf("mission continuation error = %#v, want phase %q operation %q", unsupported, phase, operation)
	}
}

func missionHTTPClient(t *testing.T, protocol *testProtocol, approval aauth.MissionApproval) *http.Client {
	t.Helper()
	return &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
		if request.Method == http.MethodGet {
			return jsonResponse(request, http.StatusOK, map[string]any{
				"issuer": protocol.personServerID, "person_token_endpoint": protocol.personTokenEndpoint,
				"auth_token_endpoint": protocol.authTokenEndpoint, "mission_endpoint": protocol.personServerID + "/mission",
			}), nil
		}
		response := jsonResponse(request, http.StatusOK, approval)
		response.Header.Set("Cache-Control", "no-store")
		return response, nil
	})}
}

func mustEncodeMission(t *testing.T, blob aauth.MissionBlob) aauth.ApprovedMission {
	t.Helper()
	mission, err := aauth.EncodeMission(blob)
	if err != nil {
		t.Fatal(err)
	}
	return mission
}
