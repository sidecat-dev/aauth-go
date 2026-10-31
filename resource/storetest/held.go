package storetest

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"reflect"
	"sync"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/r3"
	"gitlab.com/sidecat-dev/aauth-go/resource"
)

// HeldInvocationContract constructs a fresh empty held-invocation store.
type HeldInvocationContract struct {
	New func(testing.TB) resource.HeldInvocationStore
}

// RunHeldInvocation checks request ownership, multiple pending records,
// expiry, atomic execution claims, fence enforcement, exact response
// retention, replay binding, and independent replay copies.
func RunHeldInvocation(t *testing.T, contract HeldInvocationContract) {
	t.Helper()
	if contract.New == nil {
		t.Fatal("storetest: HeldInvocationContract.New is required")
	}
	t.Run("create and load", func(t *testing.T) { runHeldCreateAndLoad(t, contract) })
	t.Run("execute and replay", func(t *testing.T) { runHeldExecuteAndReplay(t, contract) })
	t.Run("pending expiry", func(t *testing.T) { runHeldExpiry(t, contract) })
	t.Run("concurrent claim", func(t *testing.T) { runHeldConcurrentClaim(t, contract) })
}

func runHeldCreateAndLoad(t *testing.T, contract HeldInvocationContract) {
	store := newHeldStore(t, contract)
	ctx := context.Background()
	now := heldTestTime()
	invocation := heldInvocation(t, "one", now)
	pristine := cloneHeldInvocation(invocation)
	if _, err := store.Load(ctx, "unknown-held-invocation"); !errors.Is(err, resource.ErrHeldInvocationNotFound) {
		t.Fatalf("initial Load = %v", err)
	}
	id, err := store.Create(ctx, invocation)
	if err != nil || !validHeldID(id) {
		t.Fatalf("Create = %q, %v", id, err)
	}
	mutateHeldInvocation(&invocation)
	loaded, err := store.Load(ctx, id)
	if err != nil || !reflect.DeepEqual(loaded, pristine) {
		t.Fatalf("Load after input mutation = %#v, %v", loaded, err)
	}
	mutateHeldInvocation(&loaded)
	loadedAgain, err := store.Load(ctx, id)
	if err != nil || !reflect.DeepEqual(loadedAgain, pristine) {
		t.Fatalf("second Load = %#v, %v", loadedAgain, err)
	}

	other := heldInvocation(t, "two", now)
	otherID, err := store.Create(ctx, other)
	if err != nil || !validHeldID(otherID) || otherID == id {
		t.Fatalf("second Create = %q, %v", otherID, err)
	}
	firstAgain, firstErr := store.Load(ctx, id)
	secondAgain, secondErr := store.Load(ctx, otherID)
	if firstErr != nil || secondErr != nil || !reflect.DeepEqual(firstAgain, pristine) ||
		!reflect.DeepEqual(secondAgain, other) {
		t.Fatalf("coexisting invocations = first %#v/%v, second %#v/%v", firstAgain, firstErr, secondAgain, secondErr)
	}
}

func runHeldExecuteAndReplay(t *testing.T, contract HeldInvocationContract) {
	store := newHeldStore(t, contract)
	ctx := context.Background()
	now := heldTestTime()
	invocation := heldInvocation(t, "execute", now)
	id, err := store.Create(ctx, invocation)
	if err != nil {
		t.Fatal(err)
	}
	token := heldAuthToken(1, now)
	claim, err := store.Claim(ctx, id, token)
	execution, ok := claim.Execution()
	if err != nil || !ok || execution.InvocationID != id || execution.Fence == "" {
		t.Fatalf("Claim = %#v, %v", execution, err)
	}
	if _, err := store.Claim(ctx, id, token); !errors.Is(err, resource.ErrHeldInvocationConflict) {
		t.Fatalf("Claim while executing = %v", err)
	}
	wrongFence := execution
	wrongFence.Fence += "-wrong"
	if _, err := store.Retain(ctx, wrongFence, heldResponse()); !errors.Is(err, resource.ErrHeldCompletionStale) {
		t.Fatalf("Retain with wrong fence = %v", err)
	}

	response := heldResponse()
	pristineResponse := cloneHeldResponse(response)
	retained, err := store.Retain(ctx, execution, response)
	if err != nil || !reflect.DeepEqual(retained, pristineResponse) {
		t.Fatalf("Retain = %#v, %v", retained, err)
	}
	mutateHeldResponse(&response)
	mutateHeldResponse(&retained)
	replayClaim, err := store.Claim(ctx, id, token)
	replay, ok := replayClaim.Replay()
	if err != nil || !ok || !reflect.DeepEqual(replay, pristineResponse) {
		t.Fatalf("replay Claim = %#v, %v", replay, err)
	}
	mutateHeldResponse(&replay)
	replayClaim, err = store.Claim(ctx, id, resource.HeldAuthToken{
		SHA256: token.SHA256, PresentedAt: invocation.CompletionUntil.Add(time.Hour),
		RetainUntil: token.RetainUntil,
	})
	replay, ok = replayClaim.Replay()
	if err != nil || !ok || !reflect.DeepEqual(replay, pristineResponse) {
		t.Fatalf("post-deadline replay = %#v, %v", replay, err)
	}
	wrongToken := token
	wrongToken.SHA256[0]++
	if _, err := store.Claim(ctx, id, wrongToken); !errors.Is(err, resource.ErrHeldAuthTokenMismatch) {
		t.Fatalf("wrong-token replay = %v", err)
	}
	if _, err := store.Retain(ctx, execution, pristineResponse); !errors.Is(err, resource.ErrHeldCompletionStale) {
		t.Fatalf("second Retain = %v", err)
	}
}

func runHeldExpiry(t *testing.T, contract HeldInvocationContract) {
	store := newHeldStore(t, contract)
	ctx := context.Background()
	now := heldTestTime()
	invocation := heldInvocation(t, "expired", now)
	id, err := store.Create(ctx, invocation)
	if err != nil {
		t.Fatal(err)
	}
	token := heldAuthToken(2, now)
	token.PresentedAt = invocation.CompletionUntil
	if _, err := store.Claim(ctx, id, token); !errors.Is(err, resource.ErrHeldInvocationExpired) {
		t.Fatalf("Claim at completion deadline = %v", err)
	}
	token.PresentedAt = now
	if _, err := store.Claim(ctx, id, token); !errors.Is(err, resource.ErrHeldInvocationExpired) {
		t.Fatalf("expired invocation became executable = %v", err)
	}
}

func runHeldConcurrentClaim(t *testing.T, contract HeldInvocationContract) {
	store := newHeldStore(t, contract)
	ctx := context.Background()
	now := heldTestTime()
	id, err := store.Create(ctx, heldInvocation(t, "concurrent", now))
	if err != nil {
		t.Fatal(err)
	}
	token := heldAuthToken(3, now)
	claims := make([]resource.HeldClaim, 16)
	errorsByCall := make([]error, len(claims))
	var wait sync.WaitGroup
	for index := range claims {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			claims[index], errorsByCall[index] = store.Claim(ctx, id, token)
		}(index)
	}
	wait.Wait()
	var execution resource.HeldExecution
	executions := 0
	conflicts := 0
	for index, err := range errorsByCall {
		if candidate, ok := claims[index].Execution(); err == nil && ok {
			execution = candidate
			executions++
			continue
		}
		if errors.Is(err, resource.ErrHeldInvocationConflict) {
			conflicts++
			continue
		}
		t.Fatalf("concurrent Claim %d = %#v, %v", index, claims[index], err)
	}
	if executions != 1 || conflicts != len(claims)-1 {
		t.Fatalf("concurrent Claims: executions=%d conflicts=%d", executions, conflicts)
	}
	response := heldResponse()
	if _, err := store.Retain(ctx, execution, response); err != nil {
		t.Fatal(err)
	}
	claim, err := store.Claim(ctx, id, token)
	replay, ok := claim.Replay()
	if err != nil || !ok || !reflect.DeepEqual(replay, response) {
		t.Fatalf("Claim after concurrent execution = %#v, %v", replay, err)
	}
}

func newHeldStore(t *testing.T, contract HeldInvocationContract) resource.HeldInvocationStore {
	t.Helper()
	store := contract.New(t)
	if store == nil {
		t.Fatal("storetest: HeldInvocationContract.New returned nil")
	}
	return store
}

func validHeldID(id string) bool {
	return id != "" && id != "." && id != ".." && url.PathEscape(id) == id
}

func heldTestTime() time.Time {
	return time.Date(2026, 9, 1, 16, 0, 0, 0, time.UTC)
}

func heldInvocation(t *testing.T, suffix string, now time.Time) resource.HeldInvocation {
	t.Helper()
	reference, err := r3.NewReference(
		"https://resource.example/r3/proposal-"+suffix,
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
	)
	if err != nil {
		t.Fatal(err)
	}
	classReference, err := r3.NewReference(
		"https://resource.example/r3/class-"+suffix,
		"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA",
	)
	if err != nil {
		t.Fatal(err)
	}
	return resource.HeldInvocation{
		Method: "POST", Scheme: "https", URLHost: "resource.example", Host: "resource.example",
		EscapedPath: "/records/" + suffix, RawPath: "/records/" + suffix,
		RawQuery: "view=full", ForceQuery: true,
		RequestURI: "/records/" + suffix + "?view=full",
		Header: http.Header{
			"Content-Type": []string{"application/json"},
			"X-Trace":      []string{"one", "two"},
		},
		Body: []byte(`{"record":"` + suffix + `"}`), BodyKind: resource.HeldRequestBodyBytes,
		HasGetBody: true, ContentLength: int64(len(suffix) + 13),
		Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
		ResourceToken: "resource-token-" + suffix, ResourceTokenIssuedAt: now,
		RequiredScopes: []string{"records.read"}, ExpiresAt: now.Add(5 * time.Minute),
		CompletionUntil: now.Add(10 * time.Minute),
		R3PerCall: &resource.HeldR3PerCall{
			Reference: reference, ClassReference: classReference,
			ExactProposal: []byte(`{"operation":"records.read"}`),
			Release: &resource.HeldResponse{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Content-Type": []string{"application/json"}},
				Body:       []byte(`{"records":214}`),
			},
		},
	}
}

func heldAuthToken(marker byte, now time.Time) resource.HeldAuthToken {
	return resource.HeldAuthToken{
		SHA256: [32]byte{marker}, PresentedAt: now.Add(time.Minute), RetainUntil: now.Add(time.Hour),
	}
}

func heldResponse() resource.HeldResponse {
	return resource.HeldResponse{
		StatusCode: http.StatusCreated,
		Header:     http.Header{"Content-Type": []string{"application/json"}, "X-Result": []string{"created"}},
		Body:       []byte(`{"id":"record-1"}`), Trailer: http.Header{"Digest": []string{"sha-256=:abc=:"}},
	}
}

func cloneHeldInvocation(invocation resource.HeldInvocation) resource.HeldInvocation {
	invocation.Header = invocation.Header.Clone()
	invocation.Body = append([]byte(nil), invocation.Body...)
	invocation.RequiredScopes = append([]string(nil), invocation.RequiredScopes...)
	if invocation.Budget != nil {
		budget := *invocation.Budget
		invocation.Budget = &budget
	}
	if invocation.R3PerCall != nil {
		cloned := *invocation.R3PerCall
		cloned.ExactProposal = append([]byte(nil), invocation.R3PerCall.ExactProposal...)
		if cloned.Release != nil {
			release := cloneHeldResponse(*cloned.Release)
			cloned.Release = &release
		}
		invocation.R3PerCall = &cloned
	}
	return invocation
}

func mutateHeldInvocation(invocation *resource.HeldInvocation) {
	invocation.Header.Set("X-Trace", "mutated")
	invocation.Body[0] ^= 0xff
	invocation.RequiredScopes[0] = "mutated.scope"
	invocation.R3PerCall.ExactProposal[0] ^= 0xff
	invocation.R3PerCall.Release.Body[0] ^= 0xff
	invocation.R3PerCall.Release.Header.Set("X-Trace", "mutated")
}

func cloneHeldResponse(response resource.HeldResponse) resource.HeldResponse {
	return resource.HeldResponse{
		StatusCode: response.StatusCode,
		Header:     response.Header.Clone(), Body: append([]byte(nil), response.Body...),
		Trailer: response.Trailer.Clone(),
	}
}

func mutateHeldResponse(response *resource.HeldResponse) {
	response.Header.Set("X-Result", "mutated")
	response.Body[0] ^= 0xff
	response.Trailer.Set("Digest", "mutated")
}

// HeldBudgetContract constructs a fresh empty store for held Budget
// refusals.
type HeldBudgetContract struct {
	New func(testing.TB) resource.HeldBudgetStore
}

// RunHeldBudget checks Rechallenge: it replaces only the Resource token and
// completion horizon of a pending invocation still under the expected
// token, keeps the Budget marker, and refuses an unknown, executing,
// completed, or already rechallenged invocation with the documented errors.
func RunHeldBudget(t *testing.T, contract HeldBudgetContract) {
	t.Helper()
	if contract.New == nil {
		t.Fatal("storetest: HeldBudgetContract.New is required")
	}
	ctx := context.Background()
	now := heldTestTime()
	store := contract.New(t)
	invocation := heldInvocation(t, "budget", now)
	invocation.R3PerCall = nil
	invocation.Budget = &resource.HeldBudget{RefusedToken: aauth.TokenReference{Issuer: "https://as.example", JTI: "refused-token"}}
	pristine := cloneHeldInvocation(invocation)
	id, err := store.Create(ctx, invocation)
	if err != nil {
		t.Fatalf("Create = %v", err)
	}
	if err := store.Rechallenge(ctx, "unknown-held-invocation", resource.HeldRechallenge{Previous: invocation.ResourceToken}); !errors.Is(err, resource.ErrHeldInvocationNotFound) {
		t.Fatalf("Rechallenge unknown = %v, want ErrHeldInvocationNotFound", err)
	}
	next := resource.HeldRechallenge{
		Previous: invocation.ResourceToken, ResourceToken: "resource-token-rechallenged",
		ResourceTokenIssuedAt: now.Add(time.Minute), ExpiresAt: now.Add(6 * time.Minute),
		CompletionUntil: now.Add(66 * time.Minute),
	}
	if err := store.Rechallenge(ctx, id, next); err != nil {
		t.Fatalf("Rechallenge = %v", err)
	}
	loaded, err := store.Load(ctx, id)
	if err != nil {
		t.Fatalf("Load = %v", err)
	}
	want := cloneHeldInvocation(pristine)
	want.ResourceToken, want.ResourceTokenIssuedAt = next.ResourceToken, next.ResourceTokenIssuedAt
	want.ExpiresAt, want.CompletionUntil = next.ExpiresAt, next.CompletionUntil
	if !reflect.DeepEqual(loaded, want) {
		t.Fatalf("rechallenged invocation = %#v, want only the token and horizon replaced", loaded)
	}
	if err := store.Rechallenge(ctx, id, next); !errors.Is(err, resource.ErrHeldInvocationConflict) {
		t.Fatalf("Rechallenge under a replaced token = %v, want ErrHeldInvocationConflict", err)
	}
	claim, err := store.Claim(ctx, id, heldAuthToken(1, now))
	if err != nil {
		t.Fatalf("Claim = %v", err)
	}
	execution, ok := claim.Execution()
	if !ok {
		t.Fatal("Claim did not grant execution")
	}
	again := next
	again.Previous = next.ResourceToken
	if err := store.Rechallenge(ctx, id, again); !errors.Is(err, resource.ErrHeldInvocationConflict) {
		t.Fatalf("Rechallenge while executing = %v, want ErrHeldInvocationConflict", err)
	}
	if _, err := store.Retain(ctx, execution, heldResponse()); err != nil {
		t.Fatalf("Retain = %v", err)
	}
	if err := store.Rechallenge(ctx, id, again); !errors.Is(err, resource.ErrHeldAuthTokenMismatch) {
		t.Fatalf("Rechallenge after completion = %v, want ErrHeldAuthTokenMismatch", err)
	}
}
