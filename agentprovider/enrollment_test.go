package agentprovider_test

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/agentprovider"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

func TestEnrollmentServiceIssuesAndReplaysTwoKeyRefresh(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	now := time.Date(2026, 8, 31, 4, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	const providerID = "https://ap.example"
	const agentID = "aauth:reference@ap.example"
	providerKey := testSigningKey(t, "ap-key", 0x41)
	durable := testSigningKey(t, "durable-key", 0x42)
	ephemeral := testSigningKey(t, "ephemeral-key", 0x43)
	ids := []string{"agent-token-1", "agent-token-unused"}
	provider, err := agentprovider.New(agentprovider.Config{
		Issuer: providerID, SigningKey: providerKey, Clock: clock,
		NewID: func() string { id := ids[0]; ids = ids[1:]; return id },
	})
	if err != nil {
		t.Fatal(err)
	}
	identity, err := durable.PublicJWK().ThumbprintURI()
	if err != nil {
		t.Fatal(err)
	}
	store := newMemoryEnrollmentStore()
	service, err := newTestEnrollmentService(t, provider, store, identity, agentID)
	if err != nil {
		t.Fatal(err)
	}
	enrollmentProof := verifiedEnrollmentProof(t, durable, clock)
	enrollment, err := service.Enroll(ctx, enrollmentProof)
	if err != nil {
		t.Fatal(err)
	}
	if enrollment.State != agentprovider.EnrollmentActive || enrollment.Agent != agentID ||
		enrollment.Identity != identity || enrollment.Revision != 1 ||
		!enrollment.IdentityKey.Equal(durable.PublicJWK()) {
		t.Fatalf("enrollment = %#v", enrollment)
	}
	compact, err := signaturekey.MintJKTJWT(
		durable, ephemeral.PublicJWK(), now, now.Add(10*time.Minute), "refresh-1",
	)
	if err != nil {
		t.Fatal(err)
	}
	proof, delegation := verifiedRefreshProof(t, compact, ephemeral, clock)
	result, err := service.Refresh(ctx, proof, delegation)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := aauth.VerifyAgentToken(ctx, result.AgentToken, signaturekey.StaticKeyResolver{
		{Issuer: providerID, DiscoveryDocument: aauth.AgentDiscoveryDocument, KeyID: providerKey.ID()}: providerKey.PublicJWK(),
	}, clock)
	if err != nil {
		t.Fatal(err)
	}
	if claims.Subject != agentID || claims.PersonServer != "https://ps.example" ||
		claims.JTI != "agent-token-1" || !claims.Confirmation.JWK.Equal(ephemeral.PublicJWK()) ||
		string(claims.AdditionalClaims["device_class"]) != `"reference"` {
		t.Fatalf("agent token claims = %#v", claims)
	}
	if result.Identity != identity || result.RequestJTI != "refresh-1" ||
		result.Agent != agentID || result.PersonServer != "https://ps.example" ||
		!result.RequestExpiresAt.Equal(now.Add(10*time.Minute)) {
		t.Fatalf("refresh result = %#v", result)
	}
	recomposed, err := newTestEnrollmentService(t, provider, store, identity, agentID)
	if err != nil {
		t.Fatal(err)
	}
	replayed, err := recomposed.Refresh(ctx, proof, delegation)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(replayed, result) {
		t.Fatalf("replayed refresh = %#v, want %#v", replayed, result)
	}
	if len(ids) != 1 {
		t.Fatalf("exact replay minted another Agent token; remaining IDs = %v", ids)
	}
	store.mu.Lock()
	inactive := store.enrollments[identity]
	inactive.State = agentprovider.EnrollmentRevoked
	inactive.Revision++
	store.enrollments[identity] = inactive
	store.mu.Unlock()
	recoveredAfterRevocation, err := recomposed.Refresh(ctx, proof, delegation)
	if err != nil {
		t.Fatal(err)
	}
	if recoveredAfterRevocation.AgentToken != result.AgentToken {
		t.Fatal("revocation changed an already-retained refresh result")
	}
}

func TestEnrollmentServiceRejectsProofForDifferentProviderAuthority(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 31, 4, 25, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	provider, err := agentprovider.New(agentprovider.Config{
		Issuer:     "https://other-ap.example",
		SigningKey: testSigningKey(t, "service-authority-ap-key", 0x14), Clock: clock,
		NewID: func() string { return "service-authority-agent-token" },
	})
	if err != nil {
		t.Fatal(err)
	}
	durable := testSigningKey(t, "service-authority-durable-key", 0x15)
	ephemeral := testSigningKey(t, "service-authority-ephemeral-key", 0x16)
	identity, err := durable.PublicJWK().ThumbprintURI()
	if err != nil {
		t.Fatal(err)
	}
	store := newMemoryEnrollmentStore()
	enrollment := agentprovider.EnrollmentRecord{
		Identity: identity, IdentityKey: durable.PublicJWK(),
		Agent: "aauth:reference@other-ap.example", State: agentprovider.EnrollmentActive, Revision: 1,
	}
	if _, err := store.CommitEnrollment(context.Background(), enrollment); err != nil {
		t.Fatal(err)
	}
	policyCalls := 0
	service, err := agentprovider.NewEnrollmentService(agentprovider.EnrollmentServiceConfig{
		Provider: provider, Store: store,
		Enroll: func(context.Context, agentprovider.EnrollmentRequest) (agentprovider.EnrollmentDecision, error) {
			policyCalls++
			return agentprovider.EnrollmentDecision{Agent: enrollment.Agent}, nil
		},
		Refresh: func(context.Context, agentprovider.RefreshRequest) (agentprovider.RefreshDecision, error) {
			policyCalls++
			return agentprovider.RefreshDecision{PersonServer: "https://ps.example", Lifetime: time.Minute}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := service.Enroll(context.Background(), verifiedEnrollmentProof(t, durable, clock)); !errors.Is(err, agentprovider.ErrInvalidEnrollmentRequest) {
		t.Fatalf("Enroll error = %v", err)
	}
	compact, err := signaturekey.MintJKTJWT(
		durable, ephemeral.PublicJWK(), now, now.Add(time.Minute), "service-authority-refresh",
	)
	if err != nil {
		t.Fatal(err)
	}
	proof, delegation := verifiedRefreshProof(t, compact, ephemeral, clock)
	if _, err := service.Refresh(context.Background(), proof, delegation); !errors.Is(err, agentprovider.ErrInvalidRefreshRequest) {
		t.Fatalf("Refresh error = %v", err)
	}
	if policyCalls != 0 {
		t.Fatalf("policy calls = %d", policyCalls)
	}
}

func TestEnrollmentServiceRejectsAgentOutsideProviderNamespaceBeforeCommit(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 31, 5, 40, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	provider, err := agentprovider.New(agentprovider.Config{
		Issuer: "https://ap.example", SigningKey: testSigningKey(t, "namespace-ap-key", 0xe1), Clock: clock,
		NewID: func() string { return "unused" },
	})
	if err != nil {
		t.Fatal(err)
	}
	store := newMemoryEnrollmentStore()
	service, err := agentprovider.NewEnrollmentService(agentprovider.EnrollmentServiceConfig{
		Provider: provider, Store: store,
		Enroll: func(context.Context, agentprovider.EnrollmentRequest) (agentprovider.EnrollmentDecision, error) {
			return agentprovider.EnrollmentDecision{Agent: "aauth:reference@other.example"}, nil
		},
		Refresh: func(context.Context, agentprovider.RefreshRequest) (agentprovider.RefreshDecision, error) {
			return agentprovider.RefreshDecision{}, errors.New("unused")
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	durable := testSigningKey(t, "namespace-durable-key", 0xe2)
	_, err = service.Enroll(context.Background(), verifiedEnrollmentProof(t, durable, clock))
	if err == nil {
		t.Fatal("Enroll succeeded")
	}
	if len(store.enrollments) != 0 {
		t.Fatalf("store retained %d enrollment(s)", len(store.enrollments))
	}
}

func TestEnrollmentServiceRecoversAmbiguousCommitWithoutRepeatingPolicy(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 31, 5, 45, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	provider, err := agentprovider.New(agentprovider.Config{
		Issuer: "https://ap.example", SigningKey: testSigningKey(t, "recovery-ap-key", 0xf1), Clock: clock,
		NewID: func() string { return "unused" },
	})
	if err != nil {
		t.Fatal(err)
	}
	store := &ambiguousEnrollmentCommitStore{memoryEnrollmentStore: newMemoryEnrollmentStore()}
	policyCalls := 0
	service, err := agentprovider.NewEnrollmentService(agentprovider.EnrollmentServiceConfig{
		Provider: provider, Store: store,
		Enroll: func(context.Context, agentprovider.EnrollmentRequest) (agentprovider.EnrollmentDecision, error) {
			policyCalls++
			return agentprovider.EnrollmentDecision{Agent: "aauth:reference@ap.example"}, nil
		},
		Refresh: func(context.Context, agentprovider.RefreshRequest) (agentprovider.RefreshDecision, error) {
			return agentprovider.RefreshDecision{}, errors.New("unused")
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	proof := verifiedEnrollmentProof(t, testSigningKey(t, "recovery-durable-key", 0xf2), clock)
	if _, err := service.Enroll(context.Background(), proof); err == nil {
		t.Fatal("first Enroll succeeded despite ambiguous commit result")
	}
	recovered, err := service.Enroll(context.Background(), proof)
	if err != nil {
		t.Fatal(err)
	}
	if recovered.Agent != "aauth:reference@ap.example" || policyCalls != 1 {
		t.Fatalf("recovered = %#v, policy calls = %d", recovered, policyCalls)
	}
}

func TestConcurrentDifferentKeysCannotClaimSameAgent(t *testing.T) {
	now := time.Date(2026, 8, 31, 5, 47, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	provider, err := agentprovider.New(agentprovider.Config{
		Issuer:     "https://ap.example",
		SigningKey: testSigningKey(t, "unique-agent-ap-key", 0x21), Clock: clock,
		NewID: func() string { return "unused" },
	})
	if err != nil {
		t.Fatal(err)
	}
	store := newMemoryEnrollmentStore()
	service, err := agentprovider.NewEnrollmentService(agentprovider.EnrollmentServiceConfig{
		Provider: provider, Store: store,
		Enroll: func(context.Context, agentprovider.EnrollmentRequest) (agentprovider.EnrollmentDecision, error) {
			return agentprovider.EnrollmentDecision{Agent: "aauth:reference@ap.example"}, nil
		},
		Refresh: func(context.Context, agentprovider.RefreshRequest) (agentprovider.RefreshDecision, error) {
			return agentprovider.RefreshDecision{}, errors.New("unused")
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	proofs := []signaturekey.VerifiedRequest{
		verifiedEnrollmentProof(t, testSigningKey(t, "unique-agent-durable-a", 0x22), clock),
		verifiedEnrollmentProof(t, testSigningKey(t, "unique-agent-durable-b", 0x23), clock),
	}
	errorsByCaller := make([]error, len(proofs))
	var wait sync.WaitGroup
	for index := range proofs {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			_, errorsByCaller[index] = service.Enroll(context.Background(), proofs[index])
		}(index)
	}
	wait.Wait()
	succeeded := 0
	conflicted := 0
	for _, err := range errorsByCaller {
		switch {
		case err == nil:
			succeeded++
		case errors.Is(err, agentprovider.ErrEnrollmentConflict):
			conflicted++
		default:
			t.Fatalf("Enroll error = %v", err)
		}
	}
	if succeeded != 1 || conflicted != 1 || len(store.enrollments) != 1 {
		t.Fatalf("succeeded=%d conflicted=%d retained=%d", succeeded, conflicted, len(store.enrollments))
	}
}

func TestRefreshRecordExpiryEqualsSignedAgentTokenExpiry(t *testing.T) {
	now := time.Date(2026, 8, 31, 5, 50, 0, 0, time.UTC)
	proofClock := aauth.ClockFunc(func() time.Time { return now })
	clockCalls := 0
	providerClock := aauth.ClockFunc(func() time.Time {
		clockCalls++
		if clockCalls == 1 {
			return now
		}
		return now.Add(5 * time.Minute)
	})
	providerKey := testSigningKey(t, "expiry-ap-key", 0x31)
	provider, err := agentprovider.New(agentprovider.Config{
		Issuer: "https://ap.example", SigningKey: providerKey, Clock: providerClock,
		NewID: func() string { return "expiry-agent-token" },
	})
	if err != nil {
		t.Fatal(err)
	}
	durable := testSigningKey(t, "expiry-durable-key", 0x32)
	ephemeral := testSigningKey(t, "expiry-ephemeral-key", 0x33)
	service, err := agentprovider.NewEnrollmentService(agentprovider.EnrollmentServiceConfig{
		Provider: provider, Store: newMemoryEnrollmentStore(),
		Enroll: func(context.Context, agentprovider.EnrollmentRequest) (agentprovider.EnrollmentDecision, error) {
			return agentprovider.EnrollmentDecision{Agent: "aauth:reference@ap.example"}, nil
		},
		Refresh: func(context.Context, agentprovider.RefreshRequest) (agentprovider.RefreshDecision, error) {
			return agentprovider.RefreshDecision{
				PersonServer: "https://ps.example",
				Lifetime:     1500 * time.Millisecond,
			}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Enroll(context.Background(), verifiedEnrollmentProof(t, durable, proofClock)); err != nil {
		t.Fatal(err)
	}
	compact, err := signaturekey.MintJKTJWT(durable, ephemeral.PublicJWK(), now, now.Add(10*time.Minute), "refresh-1")
	if err != nil {
		t.Fatal(err)
	}
	proof, delegation := verifiedRefreshProof(t, compact, ephemeral, proofClock)
	result, err := service.Refresh(context.Background(), proof, delegation)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := aauth.VerifyAgentToken(context.Background(), result.AgentToken, signaturekey.StaticKeyResolver{
		{Issuer: "https://ap.example", DiscoveryDocument: aauth.AgentDiscoveryDocument, KeyID: providerKey.ID()}: providerKey.PublicJWK(),
	}, proofClock)
	if err != nil {
		t.Fatal(err)
	}
	want := time.Unix(claims.ExpiresAt, 0).UTC()
	if !result.TokenExpiresAt.Equal(want) {
		t.Fatalf("TokenExpiresAt = %s, signed exp = %s", result.TokenExpiresAt, want)
	}
	if clockCalls != 1 {
		t.Fatalf("provider clock calls = %d", clockCalls)
	}
}

func TestConcurrentExactRefreshesConvergeOnRetainedWinner(t *testing.T) {
	now := time.Date(2026, 8, 31, 5, 55, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	var issued atomic.Int64
	provider, err := agentprovider.New(agentprovider.Config{
		Issuer: "https://ap.example", SigningKey: testSigningKey(t, "concurrent-ap-key", 0x51), Clock: clock,
		NewID: func() string { return fmt.Sprintf("concurrent-token-%d", issued.Add(1)) },
	})
	if err != nil {
		t.Fatal(err)
	}
	durable := testSigningKey(t, "concurrent-durable-key", 0x52)
	ephemeral := testSigningKey(t, "concurrent-ephemeral-key", 0x53)
	store := newMemoryEnrollmentStore()
	var policies atomic.Int64
	service, err := agentprovider.NewEnrollmentService(agentprovider.EnrollmentServiceConfig{
		Provider: provider, Store: store,
		Enroll: func(context.Context, agentprovider.EnrollmentRequest) (agentprovider.EnrollmentDecision, error) {
			return agentprovider.EnrollmentDecision{Agent: "aauth:reference@ap.example"}, nil
		},
		Refresh: func(context.Context, agentprovider.RefreshRequest) (agentprovider.RefreshDecision, error) {
			policies.Add(1)
			return agentprovider.RefreshDecision{PersonServer: "https://ps.example", Lifetime: time.Hour}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Enroll(context.Background(), verifiedEnrollmentProof(t, durable, clock)); err != nil {
		t.Fatal(err)
	}
	compact, err := signaturekey.MintJKTJWT(durable, ephemeral.PublicJWK(), now, now.Add(10*time.Minute), "refresh-concurrent")
	if err != nil {
		t.Fatal(err)
	}
	proof, delegation := verifiedRefreshProof(t, compact, ephemeral, clock)
	const callers = 8
	results := make([]agentprovider.RefreshRecord, callers)
	errorsByCaller := make([]error, callers)
	var wait sync.WaitGroup
	for index := range results {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			results[index], errorsByCaller[index] = service.Refresh(context.Background(), proof, delegation)
		}(index)
	}
	wait.Wait()
	for index := range results {
		if errorsByCaller[index] != nil {
			t.Fatalf("caller %d: %v", index, errorsByCaller[index])
		}
		if results[index].AgentToken != results[0].AgentToken {
			t.Fatalf("caller %d received a different retained token", index)
		}
	}
	if issued.Load() == 0 || policies.Load() == 0 {
		t.Fatalf("issued=%d policies=%d", issued.Load(), policies.Load())
	}
}

func TestVerifiedRefreshCannotRecommitAfterExpiryPrune(t *testing.T) {
	now := time.Date(2026, 8, 31, 6, 5, 0, 0, time.UTC)
	current := now
	clock := aauth.ClockFunc(func() time.Time { return current })
	issued := 0
	provider, err := agentprovider.New(agentprovider.Config{
		Issuer:     "https://ap.example",
		SigningKey: testSigningKey(t, "expiry-race-ap-key", 0x61), Clock: clock,
		NewID: func() string {
			issued++
			return fmt.Sprintf("expiry-race-token-%d", issued)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	durable := testSigningKey(t, "expiry-race-durable-key", 0x62)
	ephemeral := testSigningKey(t, "expiry-race-ephemeral-key", 0x63)
	identity, err := durable.PublicJWK().ThumbprintURI()
	if err != nil {
		t.Fatal(err)
	}
	store := newMemoryEnrollmentStore()
	store.now = func() time.Time { return current }
	service, err := newTestEnrollmentService(t, provider, store, identity, "aauth:reference@ap.example")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Enroll(context.Background(), verifiedEnrollmentProof(t, durable, clock)); err != nil {
		t.Fatal(err)
	}
	compact, err := signaturekey.MintJKTJWT(
		durable, ephemeral.PublicJWK(), now, now.Add(time.Minute), "refresh-1",
	)
	if err != nil {
		t.Fatal(err)
	}
	proof, delegation := verifiedRefreshProof(t, compact, ephemeral, clock)
	first, err := service.Refresh(context.Background(), proof, delegation)
	if err != nil {
		t.Fatal(err)
	}
	store.mu.Lock()
	delete(store.refreshes, identity+"\x00"+delegation.JTI())
	store.mu.Unlock()
	current = now.Add(2 * time.Minute)

	if _, err := service.Refresh(context.Background(), proof, delegation); !errors.Is(err, agentprovider.ErrRefreshExpired) {
		t.Fatalf("Refresh after prune error = %v", err)
	}
	store.mu.Lock()
	retained := len(store.refreshes)
	store.mu.Unlock()
	if retained != 0 || first.AgentToken == "" || issued != 2 {
		t.Fatalf("retained=%d first token empty=%t issued=%d", retained, first.AgentToken == "", issued)
	}
}
