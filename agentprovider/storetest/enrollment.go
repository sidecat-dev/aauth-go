package storetest

import (
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/agentprovider"
	"gitlab.com/sidecat-dev/aauth-go/jose"
)

// EnrollmentContract constructs a fresh empty store using the supplied clock.
type EnrollmentContract struct {
	New func(testing.TB, aauth.Clock) agentprovider.EnrollmentStore
}

// RunEnrollment checks stable enrollment identity and exact refresh recovery
// for both hosted key profiles.
func RunEnrollment(t *testing.T, contract EnrollmentContract) {
	t.Helper()
	if contract.New == nil {
		t.Fatal("storetest: EnrollmentContract.New is required")
	}

	now := time.Date(2026, 8, 31, 8, 0, 0, 0, time.UTC)
	current := now
	clock := aauth.ClockFunc(func() time.Time { return current })
	store := contract.New(t, clock)
	ctx := context.Background()
	key := jose.JWK{
		Kty: "OKP", Crv: "Ed25519", Alg: "Ed25519",
		X: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
	}
	enrollment := agentprovider.EnrollmentRecord{
		Identity: "urn:jkt:sha-256:enrollment", IdentityKey: key,
		Agent: "aauth:reference@ap.example", State: agentprovider.EnrollmentActive, Revision: 1,
	}
	retained, err := store.CommitEnrollment(ctx, enrollment)
	if err != nil || !retained.Equal(enrollment) {
		t.Fatalf("CommitEnrollment = %#v, %v", retained, err)
	}
	disabled, err := store.TransitionEnrollment(
		ctx, enrollment.Identity, enrollment.Revision, agentprovider.EnrollmentDisabled,
	)
	if err != nil || disabled.State != agentprovider.EnrollmentDisabled || disabled.Revision != 2 ||
		disabled.Identity != enrollment.Identity || disabled.Agent != enrollment.Agent ||
		!disabled.IdentityKey.Equal(enrollment.IdentityKey) {
		t.Fatalf("disable enrollment = %#v, %v", disabled, err)
	}
	replayedDisabled, err := store.TransitionEnrollment(
		ctx, enrollment.Identity, enrollment.Revision, agentprovider.EnrollmentDisabled,
	)
	if err != nil || !replayedDisabled.Equal(disabled) {
		t.Fatalf("replay disable enrollment = %#v, %v", replayedDisabled, err)
	}
	active, err := store.TransitionEnrollment(
		ctx, enrollment.Identity, disabled.Revision, agentprovider.EnrollmentActive,
	)
	if err != nil || active.State != agentprovider.EnrollmentActive || active.Revision != 3 {
		t.Fatalf("restore enrollment = %#v, %v", active, err)
	}
	enrollment = active
	other := enrollment
	other.Identity = "urn:jkt:sha-256:other"
	if _, err := store.CommitEnrollment(ctx, other); !errors.Is(err, agentprovider.ErrEnrollmentConflict) {
		t.Fatalf("duplicate Agent enrollment = %v", err)
	}

	twoKey := refreshRecord(enrollment, key, agentprovider.RefreshProfileTwoKey, "refresh-shared", now)
	retainedTwoKey, err := store.CommitRefresh(ctx, enrollment, twoKey)
	if err != nil || !retainedTwoKey.SameRequest(twoKey) {
		t.Fatalf("two-key CommitRefresh = %#v, %v", retainedTwoKey, err)
	}
	replayed, err := store.CommitRefresh(ctx, enrollment, twoKey)
	if err != nil || replayed.AgentToken != twoKey.AgentToken {
		t.Fatalf("two-key replay = %#v, %v", replayed, err)
	}
	crossProfile := twoKey
	crossProfile.Profile = agentprovider.RefreshProfileSingleKey
	if _, err := store.CommitRefresh(ctx, enrollment, crossProfile); !errors.Is(err, agentprovider.ErrRefreshConflict) {
		t.Fatalf("cross-profile identity reuse = %v", err)
	}

	singleKey := refreshRecord(enrollment, key, agentprovider.RefreshProfileSingleKey, "refresh-single", now)
	retainedSingleKey, err := store.CommitRefresh(ctx, enrollment, singleKey)
	if err != nil || !retainedSingleKey.SameRequest(singleKey) {
		t.Fatalf("single-key CommitRefresh = %#v, %v", retainedSingleKey, err)
	}
	loaded, err := store.LoadRefresh(ctx, enrollment.Identity, singleKey.RequestJTI)
	if err != nil || !loaded.SameRequest(singleKey) || loaded.AgentToken != singleKey.AgentToken {
		t.Fatalf("single-key LoadRefresh = %#v, %v", loaded, err)
	}

	current = singleKey.RequestExpiresAt
	replayed, err = store.CommitRefresh(ctx, enrollment, singleKey)
	if err != nil || replayed.AgentToken != singleKey.AgentToken {
		t.Fatalf("retained result at expiry = %#v, %v", replayed, err)
	}
	firstAtExpiry := singleKey
	firstAtExpiry.RequestJTI = "refresh-first-at-expiry"
	if _, err := store.CommitRefresh(ctx, enrollment, firstAtExpiry); !errors.Is(err, agentprovider.ErrRefreshExpired) {
		t.Fatalf("first result at expiry = %v", err)
	}

	revoked, err := store.TransitionEnrollment(
		ctx, enrollment.Identity, enrollment.Revision, agentprovider.EnrollmentRevoked,
	)
	if err != nil || revoked.State != agentprovider.EnrollmentRevoked || revoked.Revision != 4 {
		t.Fatalf("revoke enrollment = %#v, %v", revoked, err)
	}
	if _, err := store.TransitionEnrollment(
		ctx, enrollment.Identity, revoked.Revision, agentprovider.EnrollmentActive,
	); !errors.Is(err, agentprovider.ErrEnrollmentInactive) {
		t.Fatalf("restore revoked enrollment = %v", err)
	}
}

func refreshRecord(
	enrollment agentprovider.EnrollmentRecord,
	key jose.JWK,
	profile agentprovider.RefreshProfile,
	jti string,
	now time.Time,
) agentprovider.RefreshRecord {
	return agentprovider.RefreshRecord{
		Identity:         enrollment.Identity,
		Profile:          profile,
		RequestJTI:       jti,
		RequestSHA256:    sha256.Sum256([]byte(string(profile) + jti)),
		Agent:            enrollment.Agent,
		Confirmation:     key,
		RequestExpiresAt: now.Add(time.Minute),
		AgentToken:       "agent-token-" + jti,
		TokenExpiresAt:   now.Add(30 * time.Second),
	}
}
