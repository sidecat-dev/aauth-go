// Package storetest supplies executable contracts for personserver stores.
package storetest

import (
	"context"
	"errors"
	"net/http"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"gitlab.com/sidecat-dev/aauth-go/personserver"
)

// FederatedAuthorizationContract constructs a fresh store for each check.
type FederatedAuthorizationContract struct {
	New func(testing.TB) personserver.FederatedAuthorizationStore
}

// RunFederatedAuthorization checks copy isolation, immutable request retention, conditional
// updates and single consumption. Backend restart and failure testing remain
// the adapter author's responsibility.
func RunFederatedAuthorization(t *testing.T, contract FederatedAuthorizationContract) {
	t.Helper()
	if contract.New == nil {
		t.Fatal("store constructor is required")
	}
	ctx := context.Background()
	fixture := func() personserver.FederatedAuthorizationRecord {
		return personserver.FederatedAuthorizationRecord{ID: "request", PersonServer: "https://ps.example", ResourceToken: "resource", AgentToken: "agent", AgentIssuer: "https://ap.example", Agent: "aauth:test@ap.example", AgentJKT: "key", PresentedToken: "person", Location: "https://as.example/pending/test", ExpiresAt: time.Unix(100, 0), Revision: 1, Response: personserver.FederatedResponse{Status: 402, Header: http.Header{"Www-Authenticate": {`Payment id="test"`}}, Body: []byte("payment")}}
	}
	t.Run("replacement requires an existing record", func(t *testing.T) {
		store := contract.New(t)
		var before personserver.FederatedAuthorizationRecord
		after := before
		after.Revision = 1
		if err := store.ReplaceFederatedAuthorization(ctx, before, after); !errors.Is(err, personserver.ErrFederatedAuthorizationConflict) {
			t.Fatalf("absent replacement = %v", err)
		}
	})
	t.Run("copy isolation and duplicate create", func(t *testing.T) {
		store := contract.New(t)
		record := fixture()
		if err := store.CreateFederatedAuthorization(ctx, record); err != nil {
			t.Fatal(err)
		}
		if err := store.CreateFederatedAuthorization(ctx, record); !errors.Is(err, personserver.ErrFederatedAuthorizationConflict) {
			t.Fatalf("duplicate = %v", err)
		}
		record.Response.Body[0] = 'x'
		record.Response.Header.Set("WWW-Authenticate", "changed")
		loaded, err := store.LoadFederatedAuthorization(ctx, "request")
		if err != nil {
			t.Fatal(err)
		}
		if string(loaded.Response.Body) != "payment" || loaded.Response.Header.Get("WWW-Authenticate") != `Payment id="test"` {
			t.Fatal("store retained caller-owned memory")
		}
		record = loaded
		record.Response.Body[0] = 'x'
		record.Response.Header.Set("WWW-Authenticate", "changed")
		again, err := store.LoadFederatedAuthorization(ctx, "request")
		if err != nil || !reflect.DeepEqual(again, fixture()) {
			t.Fatal("load exposed store-owned memory")
		}
	})
	t.Run("immutable context and revision", func(t *testing.T) {
		store := contract.New(t)
		before := fixture()
		if err := store.CreateFederatedAuthorization(ctx, before); err != nil {
			t.Fatal(err)
		}
		for _, field := range []string{"ID", "PersonServer", "ResourceToken", "AgentToken", "AgentIssuer", "Agent", "AgentJKT", "PresentedToken", "Location", "ExpiresAt"} {
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
			if err := store.ReplaceFederatedAuthorization(ctx, before, after); !errors.Is(err, personserver.ErrFederatedAuthorizationConflict) {
				t.Fatalf("changed %s accepted: %v", field, err)
			}
		}
		after := fixture()
		after.Revision += 2
		if err := store.ReplaceFederatedAuthorization(ctx, before, after); !errors.Is(err, personserver.ErrFederatedAuthorizationConflict) {
			t.Fatalf("skipped revision accepted: %v", err)
		}
	})
	t.Run("terminal result cannot be replaced", func(t *testing.T) {
		store := contract.New(t)
		before := fixture()
		if err := store.CreateFederatedAuthorization(ctx, before); err != nil {
			t.Fatal(err)
		}
		terminal := fixture()
		terminal.Revision++
		terminal.Terminal = true
		terminal.Response = personserver.FederatedResponse{Status: 403, Body: []byte(`{"error":"denied"}`)}
		if err := store.ReplaceFederatedAuthorization(ctx, before, terminal); err != nil {
			t.Fatal(err)
		}
		for _, reopen := range []bool{false, true} {
			changed := terminal
			changed.Revision++
			if reopen {
				changed.Terminal = false
			} else {
				changed.Response.Body = []byte(`{"auth_token":"replacement"}`)
			}
			if err := store.ReplaceFederatedAuthorization(ctx, terminal, changed); !errors.Is(err, personserver.ErrFederatedAuthorizationConflict) {
				t.Fatalf("terminal replacement = %v", err)
			}
		}
		consumed := terminal
		consumed.Revision++
		consumed.Gone = true
		if err := store.ReplaceFederatedAuthorization(ctx, terminal, consumed); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("one winner and irreversible terminal consumption", func(t *testing.T) {
		store := contract.New(t)
		before := fixture()
		if err := store.CreateFederatedAuthorization(ctx, before); err != nil {
			t.Fatal(err)
		}
		after := fixture()
		after.Revision++
		after.Gone = true
		var winners atomic.Int32
		var wg sync.WaitGroup
		for range 16 {
			wg.Go(func() {
				err := store.ReplaceFederatedAuthorization(ctx, before, after)
				if err == nil {
					winners.Add(1)
				} else if !errors.Is(err, personserver.ErrFederatedAuthorizationConflict) {
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
		if err := store.ReplaceFederatedAuthorization(ctx, after, reopen); !errors.Is(err, personserver.ErrFederatedAuthorizationConflict) {
			t.Fatalf("reopened = %v", err)
		}
	})
}
