package personserver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

func TestFederatedMissionAuthorizationAcceptsAuthTokenWithinMissionAfterResourceExpiry(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 30, 23, 0, 0, 0, time.UTC)
	fixture := newMissionFederationFixture(t, missionFederationTimes{
		now: now, resourceExpiresAt: now.Add(2 * time.Minute),
		missionExpiresAt: now.Add(5 * time.Minute), authExpiresAt: now.Add(4 * time.Minute),
	})
	response := fixture.exchange(t, httptest.NewRecorder())
	if response.Code != http.StatusOK {
		t.Fatalf("federated exchange = %d %s", response.Code, response.Body.String())
	}
	var output struct {
		AuthToken string `json:"auth_token"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &output); err != nil {
		t.Fatal(err)
	}
	if output.AuthToken != fixture.authToken {
		t.Fatalf("released auth token = %q, want Access Server token", output.AuthToken)
	}
	if attempts, committed, _ := fixture.store.observation(); attempts != 1 || !committed {
		t.Fatalf("mission auth-token commit = attempts:%d committed:%t", attempts, committed)
	}
}

func TestFederatedMissionAuthorizationRefusesAuthTokenAfterMissionExpiryBeforeCommit(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 30, 23, 0, 0, 0, time.UTC)
	fixture := newMissionFederationFixture(t, missionFederationTimes{
		now: now, resourceExpiresAt: now.Add(4 * time.Minute),
		missionExpiresAt: now.Add(4 * time.Minute), authExpiresAt: now.Add(5 * time.Minute),
	})
	response := fixture.exchange(t, httptest.NewRecorder())
	assertMissionFederationDidNotRelease(t, response, fixture.authToken)
	if attempts, committed, _ := fixture.store.observation(); attempts != 0 || committed {
		t.Fatalf("out-of-bound token reached mission commit: attempts:%d committed:%t", attempts, committed)
	}
	fixture.store.memoryMissionStore.mu.Lock()
	retained := len(fixture.store.memoryMissionStore.authTokens)
	fixture.store.memoryMissionStore.mu.Unlock()
	if retained != 0 {
		t.Fatalf("out-of-bound token retained %d auth tokens", retained)
	}
}

func TestFederatedMissionAuthorizationRefusesChangedMissionDigestBeforeCommit(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 30, 23, 0, 0, 0, time.UTC)
	omitted := ""
	substituted := aauth.MissionS256([]byte("another approved mission"))
	for name, changed := range map[string]*string{
		"omitted": &omitted, "substituted": &substituted,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			fixture := newMissionFederationFixture(t, missionFederationTimes{
				now: now, resourceExpiresAt: now.Add(3 * time.Minute),
				missionExpiresAt: now.Add(5 * time.Minute), authExpiresAt: now.Add(4 * time.Minute),
				authMissionS256: changed,
			})
			response := fixture.exchange(t, httptest.NewRecorder())
			assertMissionFederationDidNotRelease(t, response, fixture.authToken)
			if response.Code != http.StatusBadGateway || !bytes.Contains(response.Body.Bytes(), []byte(`"as_unreachable"`)) {
				t.Fatalf("changed mission digest status = %d, want %d as_unreachable; body=%s",
					response.Code, http.StatusBadGateway, response.Body.String())
			}
			if attempts, committed, _ := fixture.store.observation(); attempts != 0 || committed {
				t.Fatalf("changed mission digest reached mission commit: attempts:%d committed:%t", attempts, committed)
			}
		})
	}
}

func TestFederatedMissionAuthorizationDoesNotReleaseFailedMissionCommit(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name         string
		hook         func(context.Context, *missionAuthObservingStore, MissionRecord, time.Time, IssuedAuthTokenRecord) error
		want         int
		wantRetained bool
	}{
		{
			name: "store error",
			hook: func(context.Context, *missionAuthObservingStore, MissionRecord, time.Time, IssuedAuthTokenRecord) error {
				return errors.New("mission auth-token store unavailable")
			},
			want: http.StatusInternalServerError,
		},
		{
			name: "commit result unavailable after retention",
			hook: func(ctx context.Context, store *missionAuthObservingStore, expected MissionRecord, at time.Time, token IssuedAuthTokenRecord) error {
				if err := store.memoryMissionStore.CommitMissionAuthToken(ctx, expected, at, token); err != nil {
					return err
				}
				return errors.New("mission auth-token commit result unavailable")
			},
			want:         http.StatusInternalServerError,
			wantRetained: true,
		},
		{
			name: "mission terminated during Access Server call",
			hook: func(ctx context.Context, store *missionAuthObservingStore, expected MissionRecord, at time.Time, token IssuedAuthTokenRecord) error {
				store.terminateMission(expected.Agent, expected.S256, "revoked-during-authorization")
				return store.memoryMissionStore.CommitMissionAuthToken(ctx, expected, at, token)
			},
			want: http.StatusForbidden,
		},
		{
			name: "accepted update during Access Server call",
			hook: func(ctx context.Context, store *missionAuthObservingStore, expected MissionRecord, at time.Time, token IssuedAuthTokenRecord) error {
				update, err := aauth.EncodeMissionUpdate(aauth.MissionUpdate{
					Action: "update", Description: "Scope changed while the Access Server decided",
				})
				if err != nil {
					return err
				}
				if _, err := store.AppendMissionUpdate(ctx, expected, at, update); err != nil {
					return err
				}
				return store.memoryMissionStore.CommitMissionAuthToken(ctx, expected, at, token)
			},
			want: http.StatusInternalServerError,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			now := time.Date(2026, 8, 30, 23, 0, 0, 0, time.UTC)
			fixture := newMissionFederationFixture(t, missionFederationTimes{
				now: now, resourceExpiresAt: now.Add(3 * time.Minute),
				missionExpiresAt: now.Add(5 * time.Minute), authExpiresAt: now.Add(4 * time.Minute),
			})
			fixture.store.hook = test.hook
			response := fixture.exchange(t, httptest.NewRecorder())
			assertMissionFederationDidNotRelease(t, response, fixture.authToken)
			if response.Code != test.want {
				t.Fatalf("commit failure status = %d, want %d; body=%s", response.Code, test.want, response.Body.String())
			}
			attempts, committed, _ := fixture.store.observation()
			if attempts != 1 || committed {
				t.Fatalf("mission auth-token commit = attempts:%d committed:%t", attempts, committed)
			}
			fixture.store.memoryMissionStore.mu.Lock()
			retained := len(fixture.store.memoryMissionStore.authTokens)
			fixture.store.memoryMissionStore.mu.Unlock()
			if (retained == 1) != test.wantRetained {
				t.Fatalf("failed mission commit retained %d auth tokens, want retained=%t", retained, test.wantRetained)
			}
		})
	}
}

func TestFederatedMissionAuthorizationRetainsExactAuthIdentityBeforeResponse(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 30, 23, 0, 0, 0, time.UTC)
	fixture := newMissionFederationFixture(t, missionFederationTimes{
		now: now, resourceExpiresAt: now.Add(3 * time.Minute),
		missionExpiresAt: now.Add(5 * time.Minute), authExpiresAt: now.Add(4 * time.Minute),
	})
	recorder := &missionCommitOrderRecorder{
		ResponseRecorder: httptest.NewRecorder(), committed: fixture.store.isCommitted,
	}
	response := fixture.exchange(t, recorder)
	if response.Code != http.StatusOK {
		t.Fatalf("federated exchange = %d %s", response.Code, response.Body.String())
	}
	if recorder.successWrittenBeforeCommit {
		t.Fatal("success response was written before the mission auth token was committed")
	}
	attempts, committed, got := fixture.store.observation()
	agentJKT, err := fixture.protocol.agentKey.PublicJWK().Thumbprint()
	if err != nil {
		t.Fatal(err)
	}
	// The receipt names the Agent the token went to and the person token it
	// was obtained with.
	want := IssuedAuthTokenRecord{
		Reference: aauth.TokenReference{Issuer: fixture.accessServerID, JTI: fixture.authJTI},
		Resource:  fixture.protocol.resourceID, MissionS256: fixture.mission.S256,
		CompactSHA256: sha256.Sum256([]byte(fixture.authToken)),
		IssuedAt:      fixture.times.now, ExpiresAt: fixture.times.authExpiresAt,
		AgentProvider: fixture.protocol.agentProviderID, Agent: fixture.protocol.agentID,
		AgentTokenJTI: "mission-federated-agent-token", AgentJKT: agentJKT,
		PresentedTokenReference: aauth.TokenReference{Issuer: fixture.protocol.personServerID, JTI: "mission-federated-person"},
	}
	if attempts != 1 || !committed || !reflect.DeepEqual(got, want) {
		t.Fatalf("mission auth-token commit = attempts:%d committed:%t\ngot  %#v\nwant %#v", attempts, committed, got, want)
	}
	fixture.store.memoryMissionStore.mu.Lock()
	retained := fixture.store.memoryMissionStore.authTokens[fixture.accessServerID+"\x00"+fixture.authJTI]
	count := len(fixture.store.memoryMissionStore.authTokens)
	fixture.store.memoryMissionStore.mu.Unlock()
	if count != 1 || !reflect.DeepEqual(retained, want) {
		t.Fatalf("retained mission auth token = count:%d record:%#v", count, retained)
	}
}

type missionFederationTimes struct {
	now               time.Time
	resourceExpiresAt time.Time
	missionExpiresAt  time.Time
	authExpiresAt     time.Time
	authMissionS256   *string
}

type missionFederationFixture struct {
	protocol       *missionProtocol
	store          *missionAuthObservingStore
	server         *Server
	mission        MissionRecord
	times          missionFederationTimes
	accessServerID string
	authJTI        string
	authToken      string
	resourceToken  string
	presentedToken string
}

func newMissionFederationFixture(t *testing.T, times missionFederationTimes) *missionFederationFixture {
	t.Helper()
	protocol := newMissionProtocol(t)
	protocol.now = times.now
	var err error
	protocol.agentToken, err = aauth.MintAgentToken(
		protocol.agentProviderID,
		protocol.providerKey,
		aauth.AgentTokenRequest{
			Agent: protocol.agentID, PersonServer: protocol.personServerID,
			PublicKey: protocol.agentKey.PublicJWK(), Lifetime: time.Hour,
		},
		times.now,
		"mission-federated-agent-token",
	)
	if err != nil {
		t.Fatal(err)
	}
	const accessServerID = "https://access.example"
	const authJTI = "mission-federated-auth"
	accessKey := personServerTestKey(t, "mission-federated-access")
	protocol.resolver[signaturekey.StaticKeyReference{
		Issuer: accessServerID, DiscoveryDocument: aauth.AccessDiscoveryDocument, KeyID: accessKey.ID(),
	}] = accessKey.PublicJWK()
	mission := protocol.commitMission(t, protocol.agentID, times.missionExpiresAt, MissionActive, "")
	personRecord := PersonTokenRecord{
		JTI: "mission-federated-person", PersonServer: protocol.personServerID,
		Resource: protocol.resourceID, Subject: "person-123", MissionS256: mission.S256,
		AgentProvider: protocol.agentProviderID, Agent: protocol.agentID,
		Confirmation: protocol.agentKey.PublicJWK(), ExpiresAt: times.missionExpiresAt,
		RetainUntil: times.missionExpiresAt.Add(DefaultMaximumResourceTokenLifetime),
	}
	if err := protocol.store.Commit(context.Background(), personRecord); err != nil {
		t.Fatal(err)
	}
	agentJKT, err := protocol.agentKey.PublicJWK().Thumbprint()
	if err != nil {
		t.Fatal(err)
	}
	resourceToken, err := aauth.MintResourceToken(protocol.resourceKey, aauth.ResourceTokenClaims{
		Issuer: protocol.resourceID, DWK: aauth.ResourceDiscoveryDocument,
		Audience: accessServerID, JTI: "mission-federated-resource", AgentJKT: agentJKT,
		IssuedAt: times.now.Unix(), ExpiresAt: times.resourceExpiresAt.Unix(), Scope: "records.read",
		PersonServer: protocol.personServerID, Subject: personRecord.Subject,
		PresentedJTI: personRecord.JTI, MissionS256: mission.S256,
	})
	if err != nil {
		t.Fatal(err)
	}
	authMissionS256 := mission.S256
	if times.authMissionS256 != nil {
		authMissionS256 = *times.authMissionS256
	}
	authToken, err := aauth.MintAuthToken(accessKey, aauth.AuthTokenClaims{
		Issuer: accessServerID, DWK: aauth.AccessDiscoveryDocument,
		Audience: protocol.resourceID, JTI: authJTI, Confirmation: aauth.Confirmation{JWK: protocol.agentKey.PublicJWK()},
		IssuedAt: times.now.Unix(), ExpiresAt: times.authExpiresAt.Unix(), Scope: "records.read",
		PersonServer: protocol.personServerID, Subject: personRecord.Subject, MissionS256: authMissionS256,
	})
	if err != nil {
		t.Fatal(err)
	}
	accessBody, err := json.Marshal(struct {
		AuthToken string `json:"auth_token"`
		ExpiresIn int64  `json:"expires_in"`
	}{AuthToken: authToken, ExpiresIn: int64(times.authExpiresAt.Sub(times.now) / time.Second)})
	if err != nil {
		t.Fatal(err)
	}
	store := &missionAuthObservingStore{memoryMissionStore: protocol.store}
	server, err := NewFederatedAuthorization(FederatedAuthorizationConfig{
		Issuer: protocol.personServerID, SigningKey: protocol.personKey, KeyResolver: protocol.resolver,
		Clock: protocol.clock, NewID: func() string { return "unused" }, Tokens: store,
		HTTPClient: &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK, Status: "200 OK", Request: request,
				Header: http.Header{"Content-Type": []string{"application/json"}},
				Body:   io.NopCloser(bytes.NewReader(accessBody)),
			}, nil
		})},
		AccessServerEndpoint: func(context.Context, string) (string, error) {
			return accessServerID + "/token", nil
		},
		BindPerson: func(context.Context, PersonTokenRequest) (Person, error) {
			return Person{}, errors.New("not used")
		},
		Consent: func(_ context.Context, request AuthorizationRequest) error {
			if request.Mission == nil || request.Mission.S256 != mission.S256 {
				return errors.New("mission context is missing")
			}
			return nil
		},
		Missions: &MissionConfig{
			Approve: func(context.Context, MissionApprovalRequest) (MissionDecision, error) {
				return MissionDecision{}, errors.New("not used")
			},
			AcceptUpdate: func(context.Context, MissionUpdatePolicyRequest) error { return nil },
			ConfirmPersonAcceptedCompletion: func(context.Context, MissionCompletionPolicyRequest) error {
				return nil
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return &missionFederationFixture{
		protocol: protocol, store: store, server: server, mission: mission, times: times,
		accessServerID: accessServerID, authJTI: authJTI, authToken: authToken, resourceToken: resourceToken,
		// The Person token outlives the Access Server token so the Mission
		// bound, not the presented-token bound, decides these cases.
		presentedToken: testPresentedPersonToken(
			t, protocol.personKey, resourceToken, protocol.agentKey.PublicJWK(), times.now,
			laterTime(personRecord.ExpiresAt, times.authExpiresAt),
		),
	}
}

func (fixture *missionFederationFixture) exchange(t *testing.T, recorder http.ResponseWriter) *httptest.ResponseRecorder {
	t.Helper()
	body := testTokenRequestBody(t, fixture.resourceToken, fixture.presentedToken)
	request := httptest.NewRequest(http.MethodPost, fixture.protocol.personServerID+"/token", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	if err := signPersonServerTestRequest(
		request, fixture.protocol.agentKey, fixture.protocol.agentToken, fixture.protocol.clock,
	); err != nil {
		t.Fatal(err)
	}
	fixture.server.Handler().ServeHTTP(recorder, request)
	switch value := recorder.(type) {
	case *httptest.ResponseRecorder:
		return value
	case *missionCommitOrderRecorder:
		return value.ResponseRecorder
	default:
		t.Fatalf("unsupported test recorder %T", recorder)
		return nil
	}
}

type missionAuthObservingStore struct {
	*memoryMissionStore

	observationMu sync.Mutex
	attempts      int
	committed     bool
	last          IssuedAuthTokenRecord
	hook          func(context.Context, *missionAuthObservingStore, MissionRecord, time.Time, IssuedAuthTokenRecord) error
}

func (store *missionAuthObservingStore) CommitMissionAuthToken(
	ctx context.Context,
	expected MissionRecord,
	at time.Time,
	token IssuedAuthTokenRecord,
) error {
	store.observationMu.Lock()
	store.attempts++
	store.last = token
	hook := store.hook
	store.observationMu.Unlock()
	var err error
	if hook != nil {
		err = hook(ctx, store, expected, at, token)
	} else {
		err = store.memoryMissionStore.CommitMissionAuthToken(ctx, expected, at, token)
	}
	store.observationMu.Lock()
	store.committed = err == nil
	store.observationMu.Unlock()
	return err
}

func (store *missionAuthObservingStore) observation() (int, bool, IssuedAuthTokenRecord) {
	store.observationMu.Lock()
	defer store.observationMu.Unlock()
	return store.attempts, store.committed, store.last
}

func (store *missionAuthObservingStore) isCommitted() bool {
	store.observationMu.Lock()
	defer store.observationMu.Unlock()
	return store.committed
}

type missionCommitOrderRecorder struct {
	*httptest.ResponseRecorder
	committed                  func() bool
	successWrittenBeforeCommit bool
}

func (recorder *missionCommitOrderRecorder) WriteHeader(status int) {
	if status == http.StatusOK && !recorder.committed() {
		recorder.successWrittenBeforeCommit = true
	}
	recorder.ResponseRecorder.WriteHeader(status)
}

func assertMissionFederationDidNotRelease(t *testing.T, response *httptest.ResponseRecorder, compact string) {
	t.Helper()
	if response.Code == http.StatusOK || bytes.Contains(response.Body.Bytes(), []byte(compact)) {
		t.Fatalf("federated exchange released an unretained token: %d %s", response.Code, response.Body.String())
	}
	var output map[string]json.RawMessage
	if err := json.Unmarshal(response.Body.Bytes(), &output); err != nil {
		t.Fatal(err)
	}
	if _, exists := output["auth_token"]; exists {
		t.Fatalf("failed federated exchange returned auth_token: %s", response.Body.String())
	}
}

func laterTime(a, b time.Time) time.Time {
	if b.After(a) {
		return b
	}
	return a
}
