package storetest

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/personserver"
)

// PermissionQueueContract constructs a fresh store with optional host listing.
type PermissionQueueContract struct {
	New func(testing.TB) personserver.PermissionQueueStore
}

// RunPermissionQueue checks issuer isolation, pending state, expiry, stable
// bounds and independent returned records. Also run RunPermission for the
// underlying transitions and backend-specific transaction/restart tests.
func RunPermissionQueue(t *testing.T, contract PermissionQueueContract) {
	t.Helper()
	if contract.New == nil {
		t.Fatal("storetest: PermissionQueueContract.New is required")
	}
	t.Run("pending permission queue", func(t *testing.T) {
		store := contract.New(t)
		ctx := context.Background()
		at := permissionNow.Add(time.Second)
		for _, id := range []string{"b", "a", "later", "foreign", "expired", "decided"} {
			record := permissionRecord(id, personserver.PermissionStatePending)
			record.ExpiresAt = permissionNow.Add(time.Minute)
			if id == "later" {
				record.CreatedAt = at
			}
			if id == "foreign" {
				record.PersonServer = "https://other.example"
			}
			if id == "expired" {
				record.ExpiresAt = at
			}
			if err := store.CreatePermission(ctx, record); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := store.DecidePermission(ctx, "decided", personserver.PermissionDecision{Permission: aauth.PermissionGranted}, at); err != nil {
			t.Fatal(err)
		}
		for _, limit := range []int{2, 10} {
			records, err := store.ListPendingPermissions(ctx, "https://person.example", at, limit)
			if err != nil {
				t.Fatal(err)
			}
			ids := []string{}
			for _, r := range records {
				ids = append(ids, r.ID)
			}
			want := []string{"a", "b", "later"}
			if limit == 2 {
				want = want[:2]
			}
			if !reflect.DeepEqual(ids, want) {
				t.Fatalf("limit %d: %v, want %v", limit, ids, want)
			}
			mutatePermissionRecord(&records[0])
			again, err := store.LoadPermission(ctx, "a", at)
			if err != nil {
				t.Fatal(err)
			}
			requirePermissionRecord(t, again, "a", personserver.PermissionStatePending)
		}
		foreign, err := store.ListPendingPermissions(ctx, "https://other.example", at, 10)
		if err != nil || len(foreign) != 1 || foreign[0].ID != "foreign" {
			t.Fatalf("issuer isolation: %#v %v", foreign, err)
		}
		expired, err := store.LoadPermission(ctx, "expired", permissionNow)
		if err != nil || expired.State != personserver.PermissionStateExpired {
			t.Fatalf("queue did not retain expiry: %#v %v", expired, err)
		}
		if _, err := store.DecidePermission(ctx, "a", personserver.PermissionDecision{Permission: aauth.PermissionDenied}, at); err != nil {
			t.Fatal(err)
		}
		after, err := store.ListPendingPermissions(ctx, "https://person.example", at, 1)
		if err != nil || len(after) != 1 || after[0].ID != "b" {
			t.Fatalf("decision remained pending: %#v %v", after, err)
		}
		for _, limit := range []int{-1, 0, 1001} {
			if _, err := store.ListPendingPermissions(ctx, "https://person.example", at, limit); err == nil {
				t.Fatalf("invalid limit %d accepted", limit)
			}
		}
		canceled, cancel := context.WithCancel(ctx)
		cancel()
		if _, err := store.ListPendingPermissions(canceled, "https://person.example", at, 1); !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled: %v", err)
		}
	})
}

// InteractionQuestionQueueContract constructs a fresh store with host listing.
type InteractionQuestionQueueContract struct {
	New func(testing.TB) personserver.InteractionQuestionQueueStore
}

// RunInteractionQuestionQueue checks issuer isolation, pending state, expiry,
// stable bounds and independent returned records. Also run RunInteractionQuestion.
func RunInteractionQuestionQueue(t *testing.T, contract InteractionQuestionQueueContract) {
	t.Helper()
	if contract.New == nil {
		t.Fatal("storetest: InteractionQuestionQueueContract.New is required")
	}
	t.Run("pending question queue", func(t *testing.T) {
		store := contract.New(t)
		ctx := context.Background()
		at := questionRecord(t, "clock").CreatedAt.Add(time.Second)
		for _, id := range []string{"b", "a", "later", "foreign", "expired", "answered"} {
			record := questionRecord(t, id)
			if id == "later" {
				record.CreatedAt = at
			}
			if id == "foreign" {
				record.PersonServer = "https://other.example"
			}
			if id == "expired" {
				record.ExpiresAt = at
			}
			if err := store.CreateInteractionQuestion(ctx, record); err != nil {
				t.Fatal(err)
			}
		}
		answer, err := aauth.EncodeInteractionAnswer(aauth.InteractionAnswer{Answer: "Yes."})
		if err != nil {
			t.Fatal(err)
		}
		if _, err = store.ResolveInteractionQuestion(ctx, "answered", personserver.InteractionQuestionAnswered, answer, at); err != nil {
			t.Fatal(err)
		}
		for _, limit := range []int{2, 10} {
			records, err := store.ListPendingInteractionQuestions(ctx, "https://ps.example", at, limit)
			if err != nil {
				t.Fatal(err)
			}
			ids := []string{}
			for _, r := range records {
				ids = append(ids, r.ID)
			}
			want := []string{"a", "b", "later"}
			if limit == 2 {
				want = want[:2]
			}
			if !reflect.DeepEqual(ids, want) {
				t.Fatalf("limit %d: %v, want %v", limit, ids, want)
			}
			records[0].Document.ExactJSON[0] = '['
			again, err := store.LoadInteractionQuestion(ctx, "a", at)
			if err != nil || again.Document.ExactJSON[0] != '{' {
				t.Fatalf("queue aliases retained document: %#v %v", again, err)
			}
		}
		foreign, err := store.ListPendingInteractionQuestions(ctx, "https://other.example", at, 10)
		if err != nil || len(foreign) != 1 || foreign[0].ID != "foreign" {
			t.Fatalf("issuer isolation: %#v %v", foreign, err)
		}
		expired, err := store.LoadInteractionQuestion(ctx, "expired", at.Add(-time.Second))
		if err != nil || expired.State != personserver.InteractionQuestionExpired {
			t.Fatalf("queue did not retain expiry: %#v %v", expired, err)
		}
		if _, err := store.ResolveInteractionQuestion(ctx, "a", personserver.InteractionQuestionUnreachable, aauth.InteractionAnswerDocument{}, at); err != nil {
			t.Fatal(err)
		}
		after, err := store.ListPendingInteractionQuestions(ctx, "https://ps.example", at, 1)
		if err != nil || len(after) != 1 || after[0].ID != "b" {
			t.Fatalf("terminal question remained pending: %#v %v", after, err)
		}
		for _, limit := range []int{-1, 0, 1001} {
			if _, err := store.ListPendingInteractionQuestions(ctx, "https://ps.example", at, limit); err == nil {
				t.Fatalf("invalid limit %d accepted", limit)
			}
		}
		canceled, cancel := context.WithCancel(ctx)
		cancel()
		if _, err := store.ListPendingInteractionQuestions(canceled, "https://ps.example", at, 1); !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled: %v", err)
		}
	})
}
