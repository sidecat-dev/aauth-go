// Package storetest supplies executable contracts for accessserver stores.
package storetest

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"gitlab.com/sidecat-dev/aauth-go/accessserver"
)

// DeferredAuthorizationContract constructs a fresh store for each check.
type DeferredAuthorizationContract struct {
	New func(testing.TB) accessserver.DeferredAuthorizationStore
}

// RunDeferredAuthorization checks copy isolation, immutable request retention, conditional
// updates and single consumption. Backend restart and failure testing remain
// the adapter author's responsibility.
func RunDeferredAuthorization(t *testing.T, contract DeferredAuthorizationContract) {
	t.Helper()
	if contract.New == nil {
		t.Fatal("store constructor is required")
	}
	ctx := context.Background()
	fixture := func() accessserver.PendingAuthorizationRecord {
		return accessserver.PendingAuthorizationRecord{ID: "request", PersonServer: "https://ps.example", Request: []byte(`{"agent_token":"exact"}`), InteractionCode: "ABCD-EFGH", ExpiresAt: time.Unix(100, 0), Revision: 1}
	}
	t.Run("replacement requires an existing record", func(t *testing.T) {
		store := contract.New(t)
		var before accessserver.PendingAuthorizationRecord
		after := before
		after.Revision = 1
		if err := store.ReplaceAccessAuthorization(ctx, before, after); !errors.Is(err, accessserver.ErrPendingAuthorizationConflict) {
			t.Fatalf("absent replacement = %v", err)
		}
	})
	t.Run("copy isolation and duplicate create", func(t *testing.T) {
		store := contract.New(t)
		record := fixture()
		if err := store.CreateAccessAuthorization(ctx, record); err != nil {
			t.Fatal(err)
		}
		if err := store.CreateAccessAuthorization(ctx, record); !errors.Is(err, accessserver.ErrPendingAuthorizationConflict) {
			t.Fatalf("duplicate = %v", err)
		}
		record.Request[0] = 'x'
		loaded, err := store.LoadAccessAuthorization(ctx, "request")
		if err != nil {
			t.Fatal(err)
		}
		if string(loaded.Request) != `{"agent_token":"exact"}` {
			t.Fatal("store retained caller-owned memory")
		}
		record = loaded
		record.Request[0] = 'x'
		again, err := store.LoadAccessAuthorization(ctx, "request")
		if err != nil || !reflect.DeepEqual(again, fixture()) {
			t.Fatal("load exposed store-owned memory")
		}
	})
	t.Run("immutable context and revision", func(t *testing.T) {
		store := contract.New(t)
		before := fixture()
		if err := store.CreateAccessAuthorization(ctx, before); err != nil {
			t.Fatal(err)
		}
		for _, field := range []string{"ID", "PersonServer", "Request", "InteractionCode", "ExpiresAt"} {
			after := fixture()
			after.Revision++
			v := reflect.ValueOf(&after).Elem().FieldByName(field)
			switch v.Kind() {
			case reflect.String:
				v.SetString("changed")
			case reflect.Slice:
				v.SetBytes([]byte("changed"))
			default:
				v.Set(reflect.ValueOf(time.Unix(999, 0)))
			}
			if err := store.ReplaceAccessAuthorization(ctx, before, after); !errors.Is(err, accessserver.ErrPendingAuthorizationConflict) {
				t.Fatalf("changed %s accepted: %v", field, err)
			}
		}
		after := fixture()
		after.Revision += 2
		if err := store.ReplaceAccessAuthorization(ctx, before, after); !errors.Is(err, accessserver.ErrPendingAuthorizationConflict) {
			t.Fatalf("skipped revision accepted: %v", err)
		}
	})
	t.Run("one winner and irreversible terminal consumption", func(t *testing.T) {
		store := contract.New(t)
		before := fixture()
		if err := store.CreateAccessAuthorization(ctx, before); err != nil {
			t.Fatal(err)
		}
		after := fixture()
		after.Revision++
		after.Gone = true
		var winners atomic.Int32
		var wg sync.WaitGroup
		for range 16 {
			wg.Go(func() {
				err := store.ReplaceAccessAuthorization(ctx, before, after)
				if err == nil {
					winners.Add(1)
				} else if !errors.Is(err, accessserver.ErrPendingAuthorizationConflict) {
					t.Error(err)
				}
			})
		}
		wg.Wait()
		if winners.Load() != 1 {
			t.Fatalf("winners = %d", winners.Load())
		}
		reopen := after
		reopen.Revision++
		reopen.Gone = false
		if err := store.ReplaceAccessAuthorization(ctx, after, reopen); !errors.Is(err, accessserver.ErrPendingAuthorizationConflict) {
			t.Fatalf("reopened = %v", err)
		}
	})
}
