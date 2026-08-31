package resource

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
)

func TestHeldClaimBranchesAreExclusive(t *testing.T) {
	t.Parallel()

	execution := HeldExecution{InvocationID: "pending-1", Fence: "fence-1"}
	executionClaim := NewHeldExecution(execution)
	if got, ok := executionClaim.Execution(); !ok || got != execution {
		t.Fatalf("Execution() = (%+v, %t), want (%+v, true)", got, ok, execution)
	}
	if got, ok := executionClaim.Replay(); ok || !heldResponseIsZero(got) {
		t.Fatalf("Replay() = (%+v, %t), want (zero, false)", got, ok)
	}

	response := HeldResponse{StatusCode: http.StatusCreated, Body: []byte("created")}
	replayClaim := NewHeldReplay(response)
	if got, ok := replayClaim.Replay(); !ok || got.StatusCode != response.StatusCode || string(got.Body) != string(response.Body) {
		t.Fatalf("Replay() = (%+v, %t), want (%+v, true)", got, ok, response)
	}
	if got, ok := replayClaim.Execution(); ok || got != (HeldExecution{}) {
		t.Fatalf("Execution() = (%+v, %t), want (zero, false)", got, ok)
	}

	var zero HeldClaim
	if got, ok := zero.Execution(); ok || got != (HeldExecution{}) {
		t.Fatalf("zero Execution() = (%+v, %t), want (zero, false)", got, ok)
	}
	if got, ok := zero.Replay(); ok || !heldResponseIsZero(got) {
		t.Fatalf("zero Replay() = (%+v, %t), want (zero, false)", got, ok)
	}

	invalid := HeldClaim{
		kind:      heldClaimKind(255),
		execution: execution,
		replay:    response,
	}
	if got, ok := invalid.Execution(); ok || got != (HeldExecution{}) {
		t.Fatalf("invalid Execution() = (%+v, %t), want (zero, false)", got, ok)
	}
	if got, ok := invalid.Replay(); ok || !heldResponseIsZero(got) {
		t.Fatalf("invalid Replay() = (%+v, %t), want (zero, false)", got, ok)
	}
}

func heldResponseIsZero(response HeldResponse) bool {
	return response.StatusCode == 0 && response.Header == nil && response.Body == nil && response.Trailer == nil
}

func TestHeldReplayOwnsConstructorInput(t *testing.T) {
	t.Parallel()

	response := HeldResponse{
		StatusCode: http.StatusAccepted,
		Header:     http.Header{"Content-Type": {"application/json"}},
		Body:       []byte(`{"state":"retained"}`),
		Trailer:    http.Header{"Digest": {"sha-256=:original:"}},
	}
	claim := NewHeldReplay(response)

	response.Header["Content-Type"][0] = "text/plain"
	response.Header.Set("X-Late", "alias")
	response.Body[2] = 'X'
	response.Trailer["Digest"][0] = "sha-256=:changed:"
	response.Trailer.Set("X-Late", "alias")

	got, ok := claim.Replay()
	if !ok {
		t.Fatal("Replay() did not expose the replay branch")
	}
	assertHeldResponseOriginal(t, got)
}

func TestHeldReplayReturnsIndependentCopies(t *testing.T) {
	t.Parallel()

	claim := NewHeldReplay(HeldResponse{
		StatusCode: http.StatusAccepted,
		Header:     http.Header{"Content-Type": {"application/json"}},
		Body:       []byte(`{"state":"retained"}`),
		Trailer:    http.Header{"Digest": {"sha-256=:original:"}},
	})

	first, ok := claim.Replay()
	if !ok {
		t.Fatal("Replay() did not expose the replay branch")
	}
	first.Header["Content-Type"][0] = "text/plain"
	first.Header.Set("X-Late", "alias")
	first.Body[2] = 'X'
	first.Trailer["Digest"][0] = "sha-256=:changed:"
	first.Trailer.Set("X-Late", "alias")

	second, ok := claim.Replay()
	if !ok {
		t.Fatal("second Replay() did not expose the replay branch")
	}
	assertHeldResponseOriginal(t, second)
}

func assertHeldResponseOriginal(t *testing.T, got HeldResponse) {
	t.Helper()
	if got.StatusCode != http.StatusAccepted {
		t.Fatalf("StatusCode = %d, want %d", got.StatusCode, http.StatusAccepted)
	}
	if value := got.Header.Get("Content-Type"); value != "application/json" {
		t.Fatalf("Content-Type = %q, want application/json", value)
	}
	if value := got.Header.Get("X-Late"); value != "" {
		t.Fatalf("late header alias = %q, want empty", value)
	}
	if value := string(got.Body); value != `{"state":"retained"}` {
		t.Fatalf("Body = %q, want retained response", value)
	}
	if value := got.Trailer.Get("Digest"); value != "sha-256=:original:" {
		t.Fatalf("Digest trailer = %q, want original digest", value)
	}
	if value := got.Trailer.Get("X-Late"); value != "" {
		t.Fatalf("late trailer alias = %q, want empty", value)
	}
}

func TestHeldStoreSentinelsAreDistinctAndWrapFriendly(t *testing.T) {
	t.Parallel()

	sentinels := []error{
		ErrHeldInvocationNotFound,
		ErrHeldInvocationExpired,
		ErrHeldInvocationConflict,
		ErrHeldExecutionUnresolved,
		ErrHeldAuthTokenMismatch,
		ErrHeldCompletionStale,
	}
	for i, sentinel := range sentinels {
		if sentinel == nil {
			t.Fatalf("sentinel %d is nil", i)
		}
		if !errors.Is(fmt.Errorf("store operation: %w", sentinel), sentinel) {
			t.Fatalf("wrapped sentinel %d is not discoverable with errors.Is", i)
		}
		for j, other := range sentinels {
			if i != j && errors.Is(sentinel, other) {
				t.Fatalf("sentinel %d matches distinct sentinel %d", i, j)
			}
		}
	}
}

func TestHeldStoreRecordsAreDirectlyUsable(t *testing.T) {
	t.Parallel()

	expiresAt := time.Date(2026, 8, 30, 16, 0, 0, 0, time.UTC)
	invocation := HeldInvocation{
		Method:                http.MethodPatch,
		Scheme:                "https",
		URLHost:               "resource.example",
		Host:                  "tenant.resource.example",
		EscapedPath:           "/records%2Falpha",
		RawPath:               "/records%2Falpha",
		RawQuery:              "view=full",
		ForceQuery:            true,
		RequestURI:            "/records%2Falpha?view=full",
		Header:                http.Header{"Content-Type": {"application/json"}},
		Body:                  []byte(`{"name":"alpha"}`),
		BodyKind:              HeldRequestBodyBytes,
		HasGetBody:            true,
		ContentLength:         16,
		Proto:                 "HTTP/1.1",
		ProtoMajor:            1,
		ProtoMinor:            1,
		ResourceToken:         "resource-token",
		ResourceTokenIssuedAt: expiresAt.Add(-5 * time.Minute),
		RequiredScopes:        []string{"records.write"},
		ExpiresAt:             expiresAt,
		CompletionUntil:       expiresAt.Add(aauth.MaximumAuthTokenLifetime),
	}
	if invocation.Method != http.MethodPatch || invocation.URLHost != "resource.example" || invocation.Host != "tenant.resource.example" ||
		invocation.RawPath != "/records%2Falpha" || invocation.RequestURI != "/records%2Falpha?view=full" ||
		invocation.BodyKind != HeldRequestBodyBytes || !invocation.HasGetBody {
		t.Fatalf("direct request fields were not retained: %+v", invocation)
	}
	if invocation.RequiredScopes[0] != "records.write" ||
		!invocation.ResourceTokenIssuedAt.Equal(expiresAt.Add(-5*time.Minute)) || !invocation.ExpiresAt.Equal(expiresAt) ||
		!invocation.CompletionUntil.Equal(expiresAt.Add(aauth.MaximumAuthTokenLifetime)) {
		t.Fatalf("direct authorization fields were not retained: %+v", invocation)
	}

	var digest [32]byte
	digest[0] = 0xa5
	token := HeldAuthToken{SHA256: digest, PresentedAt: expiresAt.Add(-time.Minute), RetainUntil: expiresAt.Add(time.Hour)}
	if token.SHA256[0] != 0xa5 || !token.PresentedAt.Before(expiresAt) || !token.RetainUntil.After(expiresAt) {
		t.Fatalf("direct token fields were not retained: %+v", token)
	}

	response := HeldResponse{
		StatusCode: http.StatusNoContent,
		Header:     make(http.Header),
		Body:       []byte("body"),
		Trailer:    make(http.Header),
	}
	execution := HeldExecution{InvocationID: "pending-1", Fence: "fence-1"}
	if response.StatusCode != http.StatusNoContent || execution.InvocationID != "pending-1" || execution.Fence != "fence-1" {
		t.Fatalf("direct response or execution fields were not retained: response=%+v execution=%+v", response, execution)
	}
}

type heldStoreFake struct{}

var _ HeldInvocationStore = (*heldStoreFake)(nil)

func (*heldStoreFake) Create(context.Context, HeldInvocation) (string, error) {
	return "pending-1", nil
}

func (*heldStoreFake) Load(context.Context, string) (HeldInvocation, error) {
	return HeldInvocation{}, nil
}

func (*heldStoreFake) Claim(context.Context, string, HeldAuthToken) (HeldClaim, error) {
	return HeldClaim{}, nil
}

func (*heldStoreFake) Retain(context.Context, HeldExecution, HeldResponse) (HeldResponse, error) {
	return HeldResponse{}, nil
}
