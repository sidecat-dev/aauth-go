package reference

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
)

func TestPersonTokenEndpointClassifiesPolicyPreparationAndCustodyFailures(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 28, 23, 50, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	providerKey := referenceTestSigningKey(t, "provider-key")
	agentKey := referenceTestSigningKey(t, "agent-key")
	agentToken, err := aauth.MintAgentToken(
		"https://ap.example",
		providerKey,
		aauth.AgentTokenRequest{
			Agent:        "aauth:agent@ap.example",
			PersonServer: "https://ps.example",
			PublicKey:    agentKey.PublicJWK(),
			Lifetime:     time.Hour,
		},
		now,
		"agent-token",
	)
	if err != nil {
		t.Fatal(err)
	}
	normalSigningKey := referenceTestSigningKey(t, "person-key")
	failingSigningKey := newFailingPersonTokenSigningKey(t, "person-key")

	for _, test := range []struct {
		name          string
		signingKey    aauth.SigningKey
		policy        aauth.PersonTokenPolicy
		commitErr     error
		wantStatus    int
		wantCode      string
		wantDetail    string
		forbidDetails []string
	}{
		{
			name:       "policy denial",
			signingKey: normalSigningKey,
			policy: func(context.Context, aauth.PersonTokenRequest) (aauth.PersonTokenDecision, error) {
				return aauth.PersonTokenDecision{}, errors.New("secret policy backend /srv/policy.db")
			},
			wantStatus:    http.StatusForbidden,
			wantCode:      "person_token_denied",
			wantDetail:    "person-token policy denied the request",
			forbidDetails: []string{"secret policy"},
		},
		{
			name:       "invalid policy output",
			signingKey: normalSigningKey,
			policy: func(context.Context, aauth.PersonTokenRequest) (aauth.PersonTokenDecision, error) {
				return aauth.PersonTokenDecision{Lifetime: time.Hour}, nil
			},
			wantStatus:    http.StatusInternalServerError,
			wantCode:      "server_error",
			wantDetail:    "the server could not complete the request",
			forbidDetails: []string{"empty subject"},
		},
		{
			name:       "signing failure",
			signingKey: failingSigningKey,
			policy: func(context.Context, aauth.PersonTokenRequest) (aauth.PersonTokenDecision, error) {
				return aauth.PersonTokenDecision{Subject: "person-1", Lifetime: time.Hour}, nil
			},
			wantStatus:    http.StatusInternalServerError,
			wantCode:      "server_error",
			wantDetail:    "the server could not complete the request",
			forbidDetails: []string{"secret signing device"},
		},
		{
			name:       "custody failure",
			signingKey: normalSigningKey,
			policy: func(context.Context, aauth.PersonTokenRequest) (aauth.PersonTokenDecision, error) {
				return aauth.PersonTokenDecision{Subject: "person-1", Lifetime: time.Hour}, nil
			},
			commitErr:     errors.New("secret person-token database /srv/person.db"),
			wantStatus:    http.StatusServiceUnavailable,
			wantCode:      "person_token_custody_unavailable",
			wantDetail:    "person-token custody is temporarily unavailable",
			forbidDetails: []string{"secret person-token"},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			missionIssuance, err := NewFileMissionIssuanceStore(t.TempDir() + "/mission-issuance.json")
			if err != nil {
				t.Fatal(err)
			}
			server, err := NewPersonServer(PersonServerConfig{
				Identifier: "https://ps.example",
				SigningKey: test.signingKey,
				KeyResolver: aauth.StaticKeyResolver{
					"https://ap.example": {providerKey.ID(): providerKey.PublicJWK()},
				},
				Clock:                clock,
				NewID:                func() string { return "person-token" },
				AuthorizationStore:   testAuthorizationStateStore(t),
				PersonTokenStore:     classifiedPersonTokenStore{commitErr: test.commitErr},
				MissionIssuanceStore: missionIssuance,
				PersonTokenPolicy:    test.policy,
				CurrentMissionPolicy: func(context.Context, aauth.MissionEvaluation) (aauth.MissionDecision, error) {
					return aauth.MissionDecision{}, errors.New("unused")
				},
				AuthorizationPolicy: func(context.Context, aauth.AuthorizationRequest) (aauth.AuthorizationDecision, error) {
					return aauth.AuthorizationDecision{}, errors.New("unused")
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			request := httptest.NewRequest(
				http.MethodPost,
				"https://ps.example/person",
				strings.NewReader(`{"resource":"https://resource.example"}`),
			)
			request.Header.Set("Content-Type", "application/json")
			if err := aauth.SignRequest(request, agentKey, agentToken, clock); err != nil {
				t.Fatal(err)
			}
			response := httptest.NewRecorder()
			server.Handler().ServeHTTP(response, request)
			if response.Code != test.wantStatus ||
				!strings.Contains(response.Body.String(), `"error":"`+test.wantCode+`"`) ||
				!strings.Contains(response.Body.String(), `"detail":"`+test.wantDetail+`"`) {
				t.Fatalf("response = %d: %s", response.Code, response.Body.String())
			}
			for _, forbidden := range test.forbidDetails {
				if strings.Contains(response.Body.String(), forbidden) {
					t.Fatalf("response leaked %q: %s", forbidden, response.Body.String())
				}
			}
		})
	}
}

func TestMissionBundledPersonTokenPreparationFailureIsServerError(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 28, 23, 55, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	providerKey := referenceTestSigningKey(t, "provider-key")
	agentKey := referenceTestSigningKey(t, "agent-key")
	agentToken, err := aauth.MintAgentToken(
		"https://ap.example",
		providerKey,
		aauth.AgentTokenRequest{
			Agent:        "aauth:agent@ap.example",
			PersonServer: "https://ps.example",
			PublicKey:    agentKey.PublicJWK(),
			Lifetime:     time.Hour,
		},
		now,
		"agent-token",
	)
	if err != nil {
		t.Fatal(err)
	}
	missionIssuance, err := NewFileMissionIssuanceStore(t.TempDir() + "/mission-issuance.json")
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewPersonServer(PersonServerConfig{
		Identifier: "https://ps.example",
		SigningKey: referenceTestSigningKey(t, "person-key"),
		KeyResolver: aauth.StaticKeyResolver{
			"https://ap.example": {providerKey.ID(): providerKey.PublicJWK()},
		},
		Clock:                clock,
		NewID:                func() string { return "person-token" },
		AuthorizationStore:   testAuthorizationStateStore(t),
		PersonTokenStore:     classifiedPersonTokenStore{},
		MissionIssuanceStore: missionIssuance,
		PersonTokenPolicy: func(context.Context, aauth.PersonTokenRequest) (aauth.PersonTokenDecision, error) {
			return aauth.PersonTokenDecision{Lifetime: time.Hour}, nil
		},
		CurrentMissionPolicy: func(_ context.Context, evaluation aauth.MissionEvaluation) (aauth.MissionDecision, error) {
			return aauth.MissionDecision{
				Description:       evaluation.Proposal.Description,
				ApprovedResources: append([]string(nil), evaluation.Proposal.Resources...),
			}, nil
		},
		AuthorizationPolicy: func(context.Context, aauth.AuthorizationRequest) (aauth.AuthorizationDecision, error) {
			return aauth.AuthorizationDecision{}, errors.New("unused")
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(aauth.MissionProposal{
		Description: "Prepare a current person token.",
		Resources:   []string{"https://resource.example"},
	})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "https://ps.example/mission", strings.NewReader(string(body)))
	request.Header.Set("Content-Type", "application/json")
	if err := aauth.SignRequest(request, agentKey, agentToken, clock); err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusInternalServerError ||
		!strings.Contains(response.Body.String(), `"error":"server_error"`) ||
		!strings.Contains(response.Body.String(), `"detail":"the server could not complete the request"`) ||
		strings.Contains(response.Body.String(), "empty subject") {
		t.Fatalf("mission preparation failure = %d: %s", response.Code, response.Body.String())
	}
}

type classifiedPersonTokenStore struct{ commitErr error }

func (store classifiedPersonTokenStore) Commit(context.Context, PersonTokenRecord) error {
	return store.commitErr
}

func (classifiedPersonTokenStore) Load(context.Context, string, string) (PersonTokenRecord, error) {
	return PersonTokenRecord{}, ErrPersonTokenNotFound
}

type failingPersonTokenSigner struct{ public ed25519.PublicKey }

func (signer failingPersonTokenSigner) Public() crypto.PublicKey { return signer.public }

func (failingPersonTokenSigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	return nil, errors.New("secret signing device /dev/hsm0 failed")
}

func newFailingPersonTokenSigningKey(t *testing.T, id string) aauth.SigningKey {
	t.Helper()
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := aauth.NewSigningKey(id, failingPersonTokenSigner{public: public})
	if err != nil {
		t.Fatal(err)
	}
	return key
}
