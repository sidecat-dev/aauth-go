package exampleutil_test

import (
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/agentprovider"
	"gitlab.com/sidecat-dev/aauth-go/internal/exampleutil"
	"gitlab.com/sidecat-dev/aauth-go/jose"
)

func TestEnrollmentStoreRetainsExactEnrollmentAndRefresh(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	now := time.Date(2026, 8, 31, 6, 0, 0, 0, time.UTC)
	store := exampleutil.NewEnrollmentStore(aauth.ClockFunc(func() time.Time { return now }))
	identityKey := jose.JWK{Kty: "OKP", Crv: "Ed25519", Alg: "Ed25519", X: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}
	enrollment := agentprovider.EnrollmentRecord{
		Identity: "urn:jkt:sha-256:identity", IdentityKey: identityKey,
		Agent: "aauth:reference@ap.example", State: agentprovider.EnrollmentActive, Revision: 1,
	}
	retained, err := store.CommitEnrollment(ctx, enrollment)
	if err != nil || !retained.Equal(enrollment) {
		t.Fatalf("CommitEnrollment = %#v, %v", retained, err)
	}
	otherIdentity := enrollment
	otherIdentity.Identity = "urn:jkt:sha-256:other-identity"
	if _, err := store.CommitEnrollment(ctx, otherIdentity); !errors.Is(err, agentprovider.ErrEnrollmentConflict) {
		t.Fatalf("duplicate Agent CommitEnrollment error = %v", err)
	}
	refresh := agentprovider.RefreshRecord{
		Identity: enrollment.Identity, Profile: agentprovider.RefreshProfileTwoKey,
		RequestJTI:    "refresh-1",
		RequestSHA256: sha256.Sum256([]byte("request")), Agent: enrollment.Agent,
		Confirmation: identityKey, RequestExpiresAt: now.Add(time.Minute), AgentToken: "agent-token",
	}
	retainedRefresh, err := store.CommitRefresh(ctx, enrollment, refresh)
	if err != nil || !retainedRefresh.SameRequest(refresh) || retainedRefresh.AgentToken != refresh.AgentToken {
		t.Fatalf("CommitRefresh = %#v, %v", retainedRefresh, err)
	}
	loaded, err := store.LoadRefresh(ctx, enrollment.Identity, refresh.RequestJTI)
	if err != nil || loaded.AgentToken != refresh.AgentToken {
		t.Fatalf("LoadRefresh = %#v, %v", loaded, err)
	}
	changed := refresh
	changed.RequestSHA256 = sha256.Sum256([]byte("changed"))
	if _, err := store.CommitRefresh(ctx, enrollment, changed); !errors.Is(err, agentprovider.ErrRefreshConflict) {
		t.Fatalf("changed CommitRefresh error = %v", err)
	}
}
