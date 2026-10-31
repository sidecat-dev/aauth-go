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

// RunFederatedAuthorization checks copy isolation, immutable request retention
// including the exact sub-agent token of a parent-mediated request, complete
// response retention including RefusalReason, conditional updates and single
// consumption. Backend restart and failure testing remain the adapter
// author's responsibility.
func RunFederatedAuthorization(t *testing.T, contract FederatedAuthorizationContract) {
	t.Helper()
	if contract.New == nil {
		t.Fatal("store constructor is required")
	}
	ctx := context.Background()
	fixture := federatedAuthorizationRecord
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
		for _, field := range []string{"ID", "PersonServer", "ResourceToken", "AgentToken", "AgentIssuer", "Agent", "AgentJKT", "PresentedToken", "SubagentToken", "InteractionCapable", "Location", "CreatedAt", "ExpiresAt"} {
			after := fixture()
			after.Revision++
			v := reflect.ValueOf(&after).Elem().FieldByName(field)
			switch v.Kind() {
			case reflect.String:
				v.SetString("changed")
			case reflect.Slice:
				v.SetBytes([]byte("changed"))
			case reflect.Bool:
				v.SetBool(!v.Bool())
			default:
				v.Set(reflect.ValueOf(time.Unix(999, 0).UTC()))
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
		terminal.Response = personserver.FederatedResponse{Status: 500, Body: []byte(`{"error":"server_error"}`), RefusalReason: "claims"}
		if err := store.ReplaceFederatedAuthorization(ctx, before, terminal); err != nil {
			t.Fatal(err)
		}
		retained, err := store.LoadFederatedAuthorization(ctx, terminal.ID)
		if err != nil {
			t.Fatal(err)
		}
		if retained.Response.RefusalReason != terminal.Response.RefusalReason {
			t.Fatalf("terminal refusal reason = %q, want %q", retained.Response.RefusalReason, terminal.Response.RefusalReason)
		}
		if !reflect.DeepEqual(retained, terminal) {
			t.Fatal("terminal record changed on load")
		}
		for _, field := range []string{"state", "body", "reason"} {
			changed := terminal
			changed.Revision++
			switch field {
			case "state":
				changed.Terminal = false
			case "body":
				changed.Response.Body = []byte(`{"auth_token":"replacement"}`)
			case "reason":
				changed.Response.RefusalReason = "interaction"
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

// UTC fixtures survive JSON timestamp round trips without a location mismatch.
func federatedAuthorizationRecord() personserver.FederatedAuthorizationRecord {
	return personserver.FederatedAuthorizationRecord{ID: "request", PersonServer: "https://ps.example", ResourceToken: "resource", AgentToken: "agent", AgentIssuer: "https://ap.example", Agent: "aauth:test@ap.example", AgentJKT: "key", PresentedToken: "person", SubagentToken: "child", UpstreamToken: "upstream", InteractionCapable: true, Location: "https://as.example/pending/test", CreatedAt: time.Unix(10, 0).UTC(), ExpiresAt: time.Unix(100, 0).UTC(), Revision: 1, Response: personserver.FederatedResponse{Status: 402, Header: http.Header{"Www-Authenticate": {`Payment id="test"`}}, Body: []byte("payment")}}
}

// FederatedAuthorizationQueueContract constructs a fresh store with optional
// host listing. Also run RunFederatedAuthorization for its transitions.
type FederatedAuthorizationQueueContract struct {
	New func(testing.TB) personserver.FederatedAuthorizationQueueStore
}

// RunFederatedAuthorizationQueue checks issuer isolation, pending state, expiry,
// stable bounds, read-only inspection and independent returned records.
func RunFederatedAuthorizationQueue(t *testing.T, contract FederatedAuthorizationQueueContract) {
	t.Helper()
	if contract.New == nil {
		t.Fatal("store constructor is required")
	}
	ctx := context.Background()
	fixture := federatedAuthorizationRecord
	t.Run("pending listing is bounded isolated and read only", func(t *testing.T) {
		store := contract.New(t)
		queue := store
		now := time.Unix(50, 0).UTC()
		for _, id := range []string{"later", "first-b", "first-a", "foreign", "expired", "terminal", "gone", "advancing"} {
			r := fixture()
			r.ID = id
			r.NextPollAt = now
			switch id {
			case "later":
				r.NextPollAt = now.Add(time.Second)
			case "foreign":
				r.PersonServer = "https://other.example"
			case "expired":
				r.ExpiresAt = now
			}
			if err := store.CreateFederatedAuthorization(ctx, r); err != nil {
				t.Fatal(err)
			}
			after := r
			switch id {
			case "terminal":
				after.Terminal = true
			case "gone":
				after.Gone = true
			case "advancing":
				after.Advancing = true
			default:
				continue
			}
			after.Revision++
			if err := store.ReplaceFederatedAuthorization(ctx, r, after); err != nil {
				t.Fatal(err)
			}
		}
		for _, limit := range []int{2, 1000} {
			rows, err := queue.ListPendingFederatedAuthorizations(ctx, "https://ps.example", now, limit)
			if err != nil {
				t.Fatal(err)
			}
			want := []string{"advancing", "first-a", "first-b", "later"}
			if limit < len(want) {
				want = want[:limit]
			}
			var ids []string
			for _, row := range rows {
				ids = append(ids, row.ID)
			}
			if !reflect.DeepEqual(ids, want) {
				t.Fatalf("pending IDs = %v, want %v", ids, want)
			}
			rows[0].Response.Body[0] = 'x'
			rows[0].Response.Header.Set("WWW-Authenticate", "changed")
		}
		retained, err := store.LoadFederatedAuthorization(ctx, "advancing")
		if err != nil || string(retained.Response.Body) != "payment" || retained.Response.Header.Get("WWW-Authenticate") != `Payment id="test"` || retained.Revision != 2 || !retained.Advancing {
			t.Fatalf("listing exposed or changed retained state: %#v %v", retained, err)
		}
		retained, err = store.LoadFederatedAuthorization(ctx, "expired")
		if err != nil || retained.Gone || retained.Revision != 1 {
			t.Fatal("listing consumed an expired result")
		}
		for _, limit := range []int{-1, 0, 1001} {
			if _, err := queue.ListPendingFederatedAuthorizations(ctx, "https://ps.example", now, limit); err == nil {
				t.Fatalf("accepted limit %d", limit)
			}
		}
		canceled, cancel := context.WithCancel(ctx)
		cancel()
		if _, err := queue.ListPendingFederatedAuthorizations(canceled, "https://ps.example", now, 1); !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled: %v", err)
		}
		if _, err := queue.ListPendingFederatedAuthorizations(nil, "https://ps.example", now, 1); err == nil {
			t.Fatal("accepted nil context")
		}
		rows, err := queue.ListPendingFederatedAuthorizations(ctx, "https://absent.example", now, 10)
		if err != nil || len(rows) != 0 {
			t.Fatalf("foreign queue = %v %v", rows, err)
		}
	})
}
