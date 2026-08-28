package aauth_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/reference"
)

func TestCurrentMissionIssuanceRecoversExactResponseAcrossStoreBoundaries(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name                  string
		personFailureAt       int
		personUncertaintyAt   int
		issuanceUncertainty   int
		governanceUncertainty int
	}{
		{name: "second person-token commit fails", personFailureAt: 2},
		{name: "person-token commit is uncertain", personUncertaintyAt: 1},
		{name: "prepared issuance commit is uncertain", issuanceUncertainty: 1},
		{name: "mission governance commit is uncertain", governanceUncertainty: 1},
		{name: "completed issuance commit is uncertain", issuanceUncertainty: 2},
	} {
		t.Run(test.name, func(t *testing.T) {
			now := time.Date(2026, 8, 28, 20, 0, 0, 987654321, time.UTC)
			clock := aauth.ClockFunc(func() time.Time { return now })
			apKey := testSigningKey(t, "recovery-ap-key")
			psKey := testSigningKey(t, "recovery-ps-key")
			agentKey := testSigningKey(t, "recovery-agent-key")
			ap, err := reference.NewAgentProvider(reference.AgentProviderConfig{
				Identifier: "https://ap.example",
				SigningKey: apKey,
				Clock:      clock,
				NewID:      sequentialIDs("recovery-agent-token"),
			})
			if err != nil {
				t.Fatal(err)
			}
			agentToken, err := ap.IssueAgentToken(aauth.AgentTokenRequest{
				Agent:        "aauth:recovery-agent@ap.example",
				PersonServer: "https://ps.example",
				PublicKey:    agentKey.PublicJWK(),
				Lifetime:     time.Hour,
			})
			if err != nil {
				t.Fatal(err)
			}

			protocolClient := &http.Client{}
			resolver, err := aauth.NewHTTPKeyResolver(aauth.HTTPKeyResolverConfig{
				Client: protocolClient,
				Clock:  clock,
				Admit: func(_ context.Context, endpoint string) error {
					if strings.HasPrefix(endpoint, "https://ap.example/") ||
						strings.HasPrefix(endpoint, "https://ps.example/") {
						return nil
					}
					return fmt.Errorf("endpoint outside test trust boundary: %s", endpoint)
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			governanceFile, err := reference.NewFileGovernanceStore(t.TempDir() + "/governance.json")
			if err != nil {
				t.Fatal(err)
			}
			issuancePath := t.TempDir() + "/mission-issuances.json"
			issuanceFile, err := reference.NewFileMissionIssuanceStore(issuancePath)
			if err != nil {
				t.Fatal(err)
			}
			personTokenPath := t.TempDir() + "/person-tokens.json"
			personFile, err := reference.NewFilePersonTokenStore(personTokenPath)
			if err != nil {
				t.Fatal(err)
			}
			var firstGovernance reference.GovernanceStore = governanceFile
			if test.governanceUncertainty > 0 {
				firstGovernance = &missionRecoveryGovernanceStore{
					inner:       governanceFile,
					uncertainAt: test.governanceUncertainty,
				}
			}
			var firstPersonTokens reference.PersonTokenStore = personFile
			if test.personFailureAt > 0 || test.personUncertaintyAt > 0 {
				firstPersonTokens = &missionRecoveryPersonTokenStore{
					inner:       personFile,
					failAt:      test.personFailureAt,
					uncertainAt: test.personUncertaintyAt,
				}
			}
			var firstIssuances reference.MissionIssuanceStore = issuanceFile
			if test.issuanceUncertainty > 0 {
				firstIssuances = &missionRecoveryIssuanceStore{
					inner:       issuanceFile,
					uncertainAt: test.issuanceUncertainty,
				}
			}

			missionPolicyCalls := 0
			personPolicyCalls := 0
			idCalls := 0
			newID := func() string {
				idCalls++
				return fmt.Sprintf("recovery-person-token-%d", idCalls)
			}
			newPersonServer := func(
				governance reference.GovernanceStore,
				personTokens reference.PersonTokenStore,
				issuances reference.MissionIssuanceStore,
			) *reference.PersonServer {
				server, err := reference.NewPersonServer(reference.PersonServerConfig{
					Identifier:           "https://ps.example",
					SigningKey:           psKey,
					KeyResolver:          resolver,
					Clock:                clock,
					NewID:                newID,
					GovernanceStore:      governance,
					PersonTokenStore:     personTokens,
					MissionIssuanceStore: issuances,
					PersonTokenPolicy: func(_ context.Context, request aauth.PersonTokenRequest) (aauth.PersonTokenDecision, error) {
						personPolicyCalls++
						return aauth.PersonTokenDecision{
							Subject:  "recovery-directed-person",
							Tenant:   "recovery-tenant",
							Lifetime: 30 * time.Minute,
						}, nil
					},
					CurrentMissionPolicy: func(_ context.Context, evaluation aauth.MissionEvaluation) (aauth.MissionDecision, error) {
						missionPolicyCalls++
						return aauth.MissionDecision{
							Description:       evaluation.Proposal.Description,
							ApprovedResources: append([]string(nil), evaluation.Proposal.Resources...),
							Capabilities:      []string{"interaction"},
						}, nil
					},
					AuthorizationPolicy: func(context.Context, aauth.AuthorizationRequest) (aauth.AuthorizationDecision, error) {
						return aauth.AuthorizationDecision{}, nil
					},
				})
				if err != nil {
					t.Fatal(err)
				}
				return server
			}

			personHandler := newPersonServer(firstGovernance, firstPersonTokens, firstIssuances).Handler()
			gateway := newLogicalGateway(t, map[string]http.Handler{
				"ap.example": ap.Handler(),
				"ps.example": http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
					personHandler.ServeHTTP(response, request)
				}),
			})
			defer gateway.Close()
			protocolClient.Transport = gateway.Client().Transport

			proposal := aauth.MissionProposal{
				Description: "Recover one exact mission approval across every durable boundary.",
				Resources: []string{
					"https://alpha-resource.example",
					"https://beta-resource.example",
				},
			}
			requestBody, err := json.Marshal(proposal)
			if err != nil {
				t.Fatal(err)
			}
			request, err := http.NewRequestWithContext(
				context.Background(),
				http.MethodPost,
				"https://ps.example/mission",
				bytes.NewReader(requestBody),
			)
			if err != nil {
				t.Fatal(err)
			}
			request.Header.Set("Content-Type", "application/json")
			if err := aauth.SignRequest(request, agentKey, agentToken, clock); err != nil {
				t.Fatal(err)
			}

			firstStatus, firstHeader, firstBody := performExactMissionRequest(t, protocolClient, request)
			if firstStatus != http.StatusServiceUnavailable {
				t.Fatalf("first status = %d, body = %s", firstStatus, firstBody)
			}
			var firstProblem map[string]any
			if err := json.Unmarshal(firstBody, &firstProblem); err != nil {
				t.Fatal(err)
			}
			if firstProblem["error"] != "server_error" || firstHeader.Get("Retry-After") == "" {
				t.Fatalf("first recovery response = headers %#v body %#v", firstHeader, firstProblem)
			}

			reloadedPersonTokens, err := reference.NewFilePersonTokenStore(personTokenPath)
			if err != nil {
				t.Fatal(err)
			}
			reloadedIssuances, err := reference.NewFileMissionIssuanceStore(issuancePath)
			if err != nil {
				t.Fatal(err)
			}
			personHandler = newPersonServer(governanceFile, reloadedPersonTokens, reloadedIssuances).Handler()
			secondStatus, _, secondBody := performExactMissionRequest(t, protocolClient, request)
			if secondStatus != http.StatusOK {
				t.Fatalf("recovered status = %d, body = %s", secondStatus, secondBody)
			}

			reloadedAgain, err := reference.NewFilePersonTokenStore(personTokenPath)
			if err != nil {
				t.Fatal(err)
			}
			reloadedIssuancesAgain, err := reference.NewFileMissionIssuanceStore(issuancePath)
			if err != nil {
				t.Fatal(err)
			}
			personHandler = newPersonServer(governanceFile, reloadedAgain, reloadedIssuancesAgain).Handler()
			thirdStatus, _, thirdBody := performExactMissionRequest(t, protocolClient, request)
			if thirdStatus != http.StatusOK || !bytes.Equal(thirdBody, secondBody) {
				t.Fatalf("completed replay = status %d body %s, want exact %s", thirdStatus, thirdBody, secondBody)
			}
			if missionPolicyCalls != 1 || personPolicyCalls != 2 || idCalls != 2 {
				t.Fatalf(
					"recovery repeated policy or token creation: mission=%d person=%d ids=%d",
					missionPolicyCalls,
					personPolicyCalls,
					idCalls,
				)
			}

			var approval struct {
				S256         string            `json:"s256"`
				Mission      string            `json:"mission"`
				Capabilities []string          `json:"capabilities"`
				PersonTokens map[string]string `json:"person_tokens"`
			}
			if err := json.Unmarshal(secondBody, &approval); err != nil {
				t.Fatal(err)
			}
			missionBytes, err := base64.RawURLEncoding.DecodeString(approval.Mission)
			if err != nil || aauth.S256(missionBytes) != approval.S256 || len(approval.PersonTokens) != 2 {
				t.Fatalf("recovered approval = %#v, mission decode error = %v", approval, err)
			}
			for resource, compact := range approval.PersonTokens {
				claims, err := aauth.VerifyPersonToken(context.Background(), compact, resolver, clock)
				if err != nil {
					t.Fatal(err)
				}
				if claims.Audience != resource || claims.MissionS256 != approval.S256 {
					t.Fatalf("recovered person token for %s = %#v", resource, claims)
				}
				record, err := reloadedAgain.Load(context.Background(), claims.Issuer, claims.JTI)
				if err != nil || record.TokenSHA256 != aauth.S256([]byte(compact)) {
					t.Fatalf("recovered person-token custody for %s = %#v, %v", resource, record, err)
				}
			}
		})
	}
}

func performExactMissionRequest(
	t *testing.T,
	client *http.Client,
	template *http.Request,
) (int, http.Header, []byte) {
	t.Helper()
	request := template.Clone(template.Context())
	body, err := template.GetBody()
	if err != nil {
		t.Fatal(err)
	}
	request.Body = body
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	responseBody, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	return response.StatusCode, response.Header.Clone(), responseBody
}

type missionRecoveryPersonTokenStore struct {
	inner       reference.PersonTokenStore
	mu          sync.Mutex
	commits     int
	failAt      int
	uncertainAt int
}

func (store *missionRecoveryPersonTokenStore) Commit(
	ctx context.Context,
	record reference.PersonTokenRecord,
) error {
	store.mu.Lock()
	store.commits++
	commit := store.commits
	store.mu.Unlock()
	if commit == store.failAt {
		return errors.New("injected person-token commit failure")
	}
	if err := store.inner.Commit(ctx, record); err != nil {
		return err
	}
	if commit == store.uncertainAt {
		return fmt.Errorf("%w: injected person-token commit uncertainty", reference.ErrGovernanceStateUncertain)
	}
	return nil
}

func (store *missionRecoveryPersonTokenStore) Load(
	ctx context.Context,
	personServer string,
	jti string,
) (reference.PersonTokenRecord, error) {
	return store.inner.Load(ctx, personServer, jti)
}

type missionRecoveryGovernanceStore struct {
	inner       reference.GovernanceStore
	mu          sync.Mutex
	saves       int
	uncertainAt int
}

type missionRecoveryIssuanceStore struct {
	inner       reference.MissionIssuanceStore
	mu          sync.Mutex
	commits     int
	uncertainAt int
}

func (store *missionRecoveryIssuanceStore) Load(
	ctx context.Context,
	replayKey string,
) (reference.MissionIssuanceRecord, error) {
	return store.inner.Load(ctx, replayKey)
}

func (store *missionRecoveryIssuanceStore) Commit(
	ctx context.Context,
	record reference.MissionIssuanceRecord,
) error {
	store.mu.Lock()
	store.commits++
	commit := store.commits
	store.mu.Unlock()
	if err := store.inner.Commit(ctx, record); err != nil {
		return err
	}
	if commit == store.uncertainAt {
		return fmt.Errorf("%w: injected mission issuance uncertainty", reference.ErrGovernanceStateUncertain)
	}
	return nil
}

func (store *missionRecoveryGovernanceStore) Load() ([]byte, error) {
	return store.inner.Load()
}

func (store *missionRecoveryGovernanceStore) Save(body []byte) error {
	store.mu.Lock()
	store.saves++
	save := store.saves
	store.mu.Unlock()
	if err := store.inner.Save(body); err != nil {
		return err
	}
	if save == store.uncertainAt {
		return fmt.Errorf("%w: injected mission issuance uncertainty", reference.ErrGovernanceStateUncertain)
	}
	return nil
}
