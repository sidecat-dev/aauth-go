package aauth_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"gitlab.com/sidecat-dev/aauth-go/signaturekey"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/reference"
)

type missionRemovalReplayStore struct {
	calls int
}

func (store *missionRemovalReplayStore) Consume(context.Context, string, time.Time) error {
	store.calls++
	return nil
}

func TestAgentRejectsLegacyHeaderOnlyMissionApproval(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 28, 21, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	providerKey := testSigningKey(t, "provider-key")
	agentKey := testSigningKey(t, "agent-key")
	agentID := "aauth:planner@provider.example"
	agentToken, err := aauth.MintAgentToken(
		"https://provider.example",
		providerKey,
		aauth.AgentTokenRequest{
			Agent:        agentID,
			PersonServer: "https://ps.example",
			PublicKey:    agentKey.PublicJWK(),
			Lifetime:     time.Hour,
		},
		now,
		"legacy-mission-agent-token",
	)
	if err != nil {
		t.Fatal(err)
	}
	missionBytes := []byte(fmt.Sprintf(`{"approver":"https://ps.example","agent":%q}`, agentID))
	gateway := newLogicalGateway(t, map[string]http.Handler{
		"ps.example": http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
			response.Header().Set(
				"AAuth-Mission",
				`approver="https://ps.example"; s256="`+aauth.S256(missionBytes)+`"`,
			)
			_, _ = response.Write(missionBytes)
		}),
	})
	defer gateway.Close()
	agent, err := reference.NewAgent(reference.AgentConfig{
		Identifier:         agentID,
		SigningKey:         agentKey,
		AgentToken:         agentToken,
		KeyResolver:        signaturekey.StaticKeyResolver{"https://provider.example": {providerKey.ID(): providerKey.PublicJWK()}},
		HTTPClient:         gateway.Client(),
		Clock:              clock,
		AuthorizationStore: testAuthorizationStateStore(t),
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = agent.CreateMission(
		context.Background(),
		"https://ps.example/mission",
		aauth.MissionProposal{Description: "Reject the obsolete response form."},
	)
	if err == nil || !strings.Contains(err.Error(), "mission") {
		t.Fatalf("legacy header-only mission approval error = %v", err)
	}
}

func TestResourceRejectsMissionHeaderBeforeProofConsumptionOrTokenAllocation(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 28, 21, 15, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	personKey := testSigningKey(t, "person-key")
	resourceKey := testSigningKey(t, "resource-key")
	agentKey := testSigningKey(t, "agent-key")
	replayStore := &missionRemovalReplayStore{}
	minted := false
	resource, err := reference.NewResource(reference.ResourceConfig{
		Identifier:   "https://resource.example",
		AccessMode:   aauth.AccessModeAuthToken,
		PersonServer: "https://ps.example",
		SigningKey:   resourceKey,
		KeyResolver: signaturekey.StaticKeyResolver{
			"https://ps.example": {personKey.ID(): personKey.PublicJWK()},
		},
		Clock: clock,
		NewID: func() string {
			minted = true
			return "must-not-allocate"
		},
		Scopes:                   []string{"records.read"},
		ScopeDescriptions:        map[string]string{"records.read": "Read records"},
		RequiredScopesForRequest: testRequiredResourceScopes("records.read"),
		ReplayStore:              replayStore,
		ProtectedAuthorizationPolicy: func(context.Context, aauth.AuthorizedRequest) error {
			return nil
		},
		Operation: func(context.Context, aauth.AuthorizedRequest) (any, error) {
			return map[string]bool{"ok": true}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	personToken, err := aauth.MintPersonToken(personKey, aauth.PersonTokenClaims{
		Issuer:       "https://ps.example",
		DWK:          aauth.PersonDiscoveryDocument,
		Audience:     "https://resource.example",
		Subject:      "person-1",
		Confirmation: aauth.Confirmation{JWK: agentKey.PublicJWK()},
		JTI:          "person-token-1",
		IssuedAt:     now.Unix(),
		ExpiresAt:    now.Add(5 * time.Minute).Unix(),
		MissionS256:  strings.Repeat("A", 43),
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		values []string
	}{
		{name: "nonempty", values: []string{"obsolete-wire-value"}},
		{name: "empty", values: []string{""}},
		{name: "empty first of multiple", values: []string{"", "obsolete-wire-value"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(
				http.MethodPost,
				"https://resource.example/authorize",
				strings.NewReader(`{"scope":"records.read"}`),
			)
			request.Header.Set("Content-Type", "application/json")
			request.Header["Aauth-Mission"] = append([]string(nil), test.values...)
			if err := signaturekey.SignJWTRequest(request, agentKey, personToken, clock); err != nil {
				t.Fatal(err)
			}
			response := httptest.NewRecorder()
			resource.Handler().ServeHTTP(response, request)
			if response.Code != http.StatusBadRequest {
				t.Fatalf("mission-header response = %d %s", response.Code, response.Body.String())
			}
			problem, err := aauth.DecodeProblemResponse(response.Result())
			if err != nil {
				t.Fatal(err)
			}
			if problem.Code != "invalid_mission" {
				t.Fatalf("mission-header problem = %#v", problem)
			}
			if replayStore.calls != 0 || minted {
				t.Fatalf("mission header crossed custody boundary: replay calls=%d token allocated=%t", replayStore.calls, minted)
			}
		})
	}
}
