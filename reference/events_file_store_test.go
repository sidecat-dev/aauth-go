package reference

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestFileEventStoresEnforceEveryConfiguredLimit(t *testing.T) {
	ctx := context.Background()
	type harness struct {
		add    func(string) error
		absent func(string) error
		close  func() error
	}
	type adapter struct {
		name string
		open func(string, int, int64, int64) (harness, error)
	}
	adapters := []adapter{
		{name: "AP", open: func(directory string, maxRecords int, maxBytes, maxRecordBytes int64) (harness, error) {
			store, err := OpenFileAPEventStore(FileAPEventStoreConfig{
				Directory: directory, Issuer: "https://ap.example", MaxRecords: maxRecords,
				MaxBytes: maxBytes, MaxRecordBytes: maxRecordBytes,
			})
			if err != nil {
				return harness{}, err
			}
			return harness{
				add: func(eventID string) error {
					return store.CreateSubscription(ctx, fileEventTestAPSubscription(eventID))
				},
				absent: func(eventID string) error {
					_, _, err := store.AcceptEvent(ctx, AcceptedEventInput{
						Resource: "https://resource.example", Agent: "aauth:subscriber@ap.example",
						EventID: eventID, Token: "opaque-event-token", AcceptedAt: fileEventTestNow,
					})
					return err
				},
				close: store.Close,
			}, nil
		}},
		{name: "resource", open: func(directory string, maxRecords int, maxBytes, maxRecordBytes int64) (harness, error) {
			store, err := OpenFileResourceEventStore(FileResourceEventStoreConfig{
				Directory: directory, MaxRecords: maxRecords,
				MaxBytes: maxBytes, MaxRecordBytes: maxRecordBytes,
			})
			if err != nil {
				return harness{}, err
			}
			return harness{
				add: func(eventID string) error {
					return store.Register(ctx, fileEventTestResourceSubscription(eventID))
				},
				absent: func(eventID string) error {
					_, err := store.Load(ctx, "https://ap.example", eventID)
					return err
				},
				close: store.Close,
			}, nil
		}},
		{name: "agent", open: func(directory string, maxRecords int, maxBytes, maxRecordBytes int64) (harness, error) {
			store, err := OpenFileAgentEventStore(FileAgentEventStoreConfig{
				Directory: directory, MaxRecords: maxRecords,
				MaxBytes: maxBytes, MaxRecordBytes: maxRecordBytes,
			})
			if err != nil {
				return harness{}, err
			}
			return harness{
				add: func(eventID string) error {
					return store.PutContext(ctx, AgentEventContext{
						APIssuer: "https://ap.example", EventID: eventID, Value: []byte(`{"test":true}`),
					})
				},
				absent: func(eventID string) error {
					_, err := store.LookupContext(ctx, "https://ap.example", eventID)
					return err
				},
				close: store.Close,
			}, nil
		}},
	}

	for _, adapter := range adapters {
		adapter := adapter
		t.Run(adapter.name, func(t *testing.T) {
			t.Run("invalid limits", func(t *testing.T) {
				for _, limits := range [][3]int64{{-1, 1 << 20, 1 << 20}, {10, -1, 1 << 20}, {10, 1 << 20, -1}} {
					store, err := adapter.open(filepath.Join(t.TempDir(), "store"), int(limits[0]), limits[1], limits[2])
					if !errors.Is(err, ErrEventStoreConfig) {
						t.Fatalf("invalid limits %v error = %v, want config error", limits, err)
					}
					if store.close != nil {
						_ = store.close()
					}
				}
			})
			t.Run("retained state exceeds configured count", func(t *testing.T) {
				directory := filepath.Join(t.TempDir(), "store")
				store, err := adapter.open(directory, 10, 1<<20, 1<<20)
				if err != nil {
					t.Fatal(err)
				}
				if err := store.add("event-one"); err != nil {
					t.Fatal(err)
				}
				if err := store.add("event-two"); err != nil {
					t.Fatal(err)
				}
				if err := store.close(); err != nil {
					t.Fatal(err)
				}
				if reopened, err := adapter.open(directory, 1, 1<<20, 1<<20); !errors.Is(err, ErrEventStoreCapacity) {
					t.Fatalf("over-capacity retained state open error = %v", err)
				} else if reopened.close != nil {
					_ = reopened.close()
				}
			})
			for _, limit := range []struct {
				name                       string
				maxRecords                 int
				maxBytes, maxRecordBytes   int64
				seedFirst, rejectedEventID bool
			}{
				{name: "record count", maxRecords: 1, maxBytes: 1 << 20, maxRecordBytes: 1 << 20, seedFirst: true, rejectedEventID: true},
				{name: "total bytes", maxRecords: 10, maxBytes: 1 << 20, maxRecordBytes: 1 << 20},
				{name: "per-record bytes", maxRecords: 10, maxBytes: 1 << 20, maxRecordBytes: 1},
			} {
				limit := limit
				t.Run(limit.name, func(t *testing.T) {
					directory := filepath.Join(t.TempDir(), "store")
					if limit.name == "total bytes" {
						bootstrap, err := adapter.open(directory, limit.maxRecords, limit.maxBytes, limit.maxRecordBytes)
						if err != nil {
							t.Fatal(err)
						}
						if err := bootstrap.close(); err != nil {
							t.Fatal(err)
						}
						info, err := os.Stat(filepath.Join(directory, eventFileStateName))
						if err != nil {
							t.Fatal(err)
						}
						limit.maxBytes = info.Size()
					}
					store, err := adapter.open(directory, limit.maxRecords, limit.maxBytes, limit.maxRecordBytes)
					if err != nil {
						t.Fatal(err)
					}
					defer store.close()
					if limit.seedFirst {
						if err := store.add("event-one"); err != nil {
							t.Fatal(err)
						}
					}
					rejected := "event-one"
					if limit.rejectedEventID {
						rejected = "event-two"
					}
					if err := store.add(rejected); !errors.Is(err, ErrEventStoreCapacity) {
						t.Fatalf("rejected mutation error = %v, want capacity", err)
					}
					if err := store.absent(rejected); err == nil {
						t.Fatal("capacity-rejected record became reachable")
					}
				})
			}
		})
	}
}

func TestFileEventStoresRefuseUnsafeCustodyAndConcurrentWriter(t *testing.T) {
	type opener struct {
		name string
		open func(string) (io.Closer, error)
	}
	openers := []opener{
		{name: "AP", open: func(directory string) (io.Closer, error) {
			return OpenFileAPEventStore(FileAPEventStoreConfig{Directory: directory, Issuer: "https://ap.example"})
		}},
		{name: "resource", open: func(directory string) (io.Closer, error) {
			return OpenFileResourceEventStore(FileResourceEventStoreConfig{Directory: directory})
		}},
		{name: "agent", open: func(directory string) (io.Closer, error) {
			return OpenFileAgentEventStore(FileAgentEventStoreConfig{Directory: directory})
		}},
	}

	for _, opener := range openers {
		opener := opener
		t.Run(opener.name+" exclusive writer", func(t *testing.T) {
			directory := filepath.Join(t.TempDir(), "store")
			first, err := opener.open(directory)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := opener.open(directory); !errors.Is(err, ErrEventStoreLocked) {
				t.Fatalf("concurrent open error = %v, want locked", err)
			}
			if err := first.Close(); err != nil {
				t.Fatal(err)
			}
			reopened, err := opener.open(directory)
			if err != nil {
				t.Fatal(err)
			}
			if err := reopened.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}

	t.Run("unsafe directory mode", func(t *testing.T) {
		directory := filepath.Join(t.TempDir(), "store")
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(directory, 0o750); err != nil {
			t.Fatal(err)
		}
		if store, err := openers[0].open(directory); !errors.Is(err, ErrEventStoreUnsafe) {
			t.Fatalf("unsafe directory open = %#v, %v", store, err)
		}
	})

	t.Run("symlinked directory", func(t *testing.T) {
		base := t.TempDir()
		target := filepath.Join(base, "target")
		if err := os.Mkdir(target, 0o700); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(base, "store")
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		if store, err := openers[0].open(link); !errors.Is(err, ErrEventStoreUnsafe) {
			t.Fatalf("symlinked directory open = %#v, %v", store, err)
		}
	})

	t.Run("unexpected entry", func(t *testing.T) {
		directory := filepath.Join(t.TempDir(), "store")
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(directory, "unexpected"), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		if store, err := openers[0].open(directory); !errors.Is(err, ErrEventStoreUnsafe) {
			t.Fatalf("unexpected-entry open = %#v, %v", store, err)
		}
	})

	t.Run("unsafe state mode and symlink", func(t *testing.T) {
		directory := filepath.Join(t.TempDir(), "store")
		store, err := OpenFileAPEventStore(FileAPEventStoreConfig{Directory: directory, Issuer: "https://ap.example"})
		if err != nil {
			t.Fatal(err)
		}
		if err := store.CreateSubscription(context.Background(), fileEventTestAPSubscription("event-one")); err != nil {
			t.Fatal(err)
		}
		if err := store.Close(); err != nil {
			t.Fatal(err)
		}
		statePath := filepath.Join(directory, eventFileStateName)
		if err := os.Chmod(statePath, 0o644); err != nil {
			t.Fatal(err)
		}
		if reopened, err := OpenFileAPEventStore(FileAPEventStoreConfig{Directory: directory, Issuer: "https://ap.example"}); !errors.Is(err, ErrEventStoreUnsafe) || reopened != nil {
			t.Fatalf("unsafe state open = %#v, %v", reopened, err)
		}
		if err := os.Chmod(statePath, 0o600); err != nil {
			t.Fatal(err)
		}
		backup := filepath.Join(directory, "state.backup")
		if err := os.Rename(statePath, backup); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(backup, statePath); err != nil {
			t.Fatal(err)
		}
		if reopened, err := OpenFileAPEventStore(FileAPEventStoreConfig{Directory: directory, Issuer: "https://ap.example"}); !errors.Is(err, ErrEventStoreUnsafe) || reopened != nil {
			t.Fatalf("symlinked state open = %#v, %v", reopened, err)
		}
	})

	t.Run("empty AP authority is issuer-bound", func(t *testing.T) {
		directory := filepath.Join(t.TempDir(), "store")
		store, err := OpenFileAPEventStore(FileAPEventStoreConfig{Directory: directory, Issuer: "https://ap.example"})
		if err != nil {
			t.Fatal(err)
		}
		if err := store.Close(); err != nil {
			t.Fatal(err)
		}
		if reopened, err := OpenFileAPEventStore(FileAPEventStoreConfig{Directory: directory, Issuer: "https://other-ap.example"}); !errors.Is(err, ErrEventStoreIntegrity) || reopened != nil {
			t.Fatalf("cross-issuer AP open = %#v, %v", reopened, err)
		}
		store, err = OpenFileAPEventStore(FileAPEventStoreConfig{Directory: directory, Issuer: "https://ap.example"})
		if err != nil {
			t.Fatalf("failed open retained writer lock: %v", err)
		}
		_ = store.Close()
	})

	t.Run("crash temp custody", func(t *testing.T) {
		directory := filepath.Join(t.TempDir(), "store")
		store, err := OpenFileAPEventStore(FileAPEventStoreConfig{Directory: directory, Issuer: "https://ap.example"})
		if err != nil {
			t.Fatal(err)
		}
		if err := store.Close(); err != nil {
			t.Fatal(err)
		}
		target := filepath.Join(t.TempDir(), "target")
		if err := os.WriteFile(target, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		tempPath := filepath.Join(directory, eventFileTemporaryPrefix+"attacker")
		if err := os.Symlink(target, tempPath); err != nil {
			t.Fatal(err)
		}
		if reopened, err := OpenFileAPEventStore(FileAPEventStoreConfig{Directory: directory, Issuer: "https://ap.example"}); !errors.Is(err, ErrEventStoreUnsafe) || reopened != nil {
			t.Fatalf("symlink crash temp open = %#v, %v", reopened, err)
		}
		if err := os.Remove(tempPath); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(tempPath, []byte("partial"), 0o600); err != nil {
			t.Fatal(err)
		}
		reopened, err := OpenFileAPEventStore(FileAPEventStoreConfig{Directory: directory, Issuer: "https://ap.example"})
		if err != nil {
			t.Fatal(err)
		}
		defer reopened.Close()
		if _, err := os.Lstat(tempPath); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("private crash temp was not cleaned: %v", err)
		}
	})
}

func TestFileEventStoresPreserveCommittedSnapshotAcrossPartialWrite(t *testing.T) {
	ctx := context.Background()
	directory := filepath.Join(t.TempDir(), "resource")
	store, err := OpenFileResourceEventStore(FileResourceEventStoreConfig{Directory: directory})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Register(ctx, fileEventTestResourceSubscription("event-one")); err != nil {
		t.Fatal(err)
	}
	injected := errors.New("test: injected file commit failure")
	store.file.failCommit = func(phase eventFileCommitPhase) error {
		if phase == eventFileCommitAfterWrite {
			return injected
		}
		return nil
	}
	if err := store.Register(ctx, fileEventTestResourceSubscription("event-two")); !errors.Is(err, injected) {
		t.Fatalf("pre-publish failure = %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	store, err = OpenFileResourceEventStore(FileResourceEventStoreConfig{Directory: directory})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(ctx, "https://ap.example", "event-one"); err != nil {
		t.Fatalf("prior snapshot did not survive: %v", err)
	}
	if _, err := store.Load(ctx, "https://ap.example", "event-two"); !errors.Is(err, ErrEventSubscriptionNotFound) {
		t.Fatalf("partial successor became reachable: %v", err)
	}

	store.file.failCommit = func(phase eventFileCommitPhase) error {
		if phase == eventFileCommitAfterRename {
			return injected
		}
		return nil
	}
	if err := store.Register(ctx, fileEventTestResourceSubscription("event-three")); !errors.Is(err, injected) || !errors.Is(err, ErrEventStoreCommitUncertain) {
		t.Fatalf("post-publish failure = %v, want injected commit-uncertain", err)
	}
	if _, err := store.Load(ctx, "https://ap.example", "event-three"); err != nil {
		t.Fatalf("complete published successor was not adopted: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = OpenFileResourceEventStore(FileResourceEventStoreConfig{Directory: directory})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, err := store.Load(ctx, "https://ap.example", "event-three"); err != nil {
		t.Fatalf("post-rename complete successor did not reopen: %v", err)
	}
}

func TestFileEventStoresReopenAgentConsequencesExactly(t *testing.T) {
	ctx := context.Background()
	directory := filepath.Join(t.TempDir(), "agent")
	config := FileAgentEventStoreConfig{Directory: directory}
	store, err := OpenFileAgentEventStore(config)
	if err != nil {
		t.Fatal(err)
	}
	resourceKey := eventsProviderTestSigningKey(t, "file-agent-resource-key")
	accepted, claims := acceptedAgentEventTest(t, resourceKey, fileEventTestNow, "event-processing", "delivery-processing")
	putAgentEventTestContext(t, store, claims.EventID)
	admitAgentEventTestProcessing(t, store, accepted, claims)
	action := eventActionKeyForTest(claims, accepted)
	if claimed, err := store.BeginDispatch(ctx, action, fileEventTestNow); err != nil || !claimed {
		t.Fatalf("begin file-backed dispatch = %v, %v", claimed, err)
	}
	standalone := EventDeliveryKey{
		APIssuer: "https://ap.example", DeliveryID: "standalone-refusal",
		TokenDigest: testEventTokenDigest("standalone-token"),
	}
	if err := store.MarkRefused(ctx, standalone, EventRefusalInvalid); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	store, err = OpenFileAgentEventStore(config)
	if err != nil {
		t.Fatal(err)
	}
	processing, err := store.LoadProcessing(ctx, action)
	if err != nil || processing.State != EventDispatched || processing.Token != accepted.Token {
		t.Fatalf("reopened dispatched processing = %#v, %v", processing, err)
	}
	if state, err := store.LoadDisposition(ctx, standalone); err != nil || state != EventRefused {
		t.Fatalf("reopened standalone refusal = %q, %v", state, err)
	}
	if retried, err := store.RetryNotApplied(ctx, action, fileEventTestNow.Add(time.Second)); err != nil || !retried {
		t.Fatalf("file-backed not-applied retry = %v, %v", retried, err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = OpenFileAgentEventStore(config)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	processing, err = store.LoadProcessing(ctx, action)
	if err != nil || processing.State != EventPending {
		t.Fatalf("reopened retried processing = %#v, %v", processing, err)
	}
}

func TestFileEventStoresRefuseCorruptTruncatedAndUnknownVersions(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "ap")
	store, err := OpenFileAPEventStore(FileAPEventStoreConfig{Directory: directory, Issuer: "https://ap.example"})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CreateSubscription(context.Background(), fileEventTestAPSubscription("event-one")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.AcceptEvent(context.Background(), AcceptedEventInput{
		Resource: "https://resource.example", Agent: "aauth:subscriber@ap.example",
		EventID: "event-one", Token: "retained-token", AcceptedAt: fileEventTestNow,
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	statePath := filepath.Join(directory, eventFileStateName)
	original, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name string
		body []byte
	}{
		{name: "truncated", body: original[:len(original)/2]},
		{name: "corrupt", body: []byte(`{"schema":`)},
		{name: "unknown snapshot version", body: bytes.Replace(original, []byte("aauth.reference.events.ap-store.v1"), []byte("aauth.reference.events.ap-store.v999"), 1)},
		{name: "unknown record version", body: bytes.Replace(original, []byte("aauth.reference.events.ap-subscription.v1"), []byte("aauth.reference.events.ap-subscription.v999"), 1)},
		{name: "unknown field", body: bytes.Replace(original, []byte("{"), []byte(`{"unknown":true,`), 1)},
		{name: "duplicate field", body: bytes.Replace(original, []byte(`"schema":`), []byte(`"schema":"aauth.reference.events.ap-store.v1","schema":`), 1)},
		{name: "cross-record authority", body: replaceLastBytes(original, []byte("https://ap.example"), []byte("https://other-ap.example"))},
		{name: "delivery sequence contradiction", body: bytes.Replace(original, []byte("event-delivery-1"), []byte("event-delivery-999"), 1)},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			if err := os.WriteFile(statePath, test.body, 0o600); err != nil {
				t.Fatal(err)
			}
			if reopened, err := OpenFileAPEventStore(FileAPEventStoreConfig{Directory: directory, Issuer: "https://ap.example"}); !errors.Is(err, ErrEventStoreIntegrity) || reopened != nil {
				t.Fatalf("invalid state open = %#v, %v, want integrity failure", reopened, err)
			}
			if err := os.WriteFile(statePath, original, 0o600); err != nil {
				t.Fatal(err)
			}
		})
	}
	reopened, err := OpenFileAPEventStore(FileAPEventStoreConfig{Directory: directory, Issuer: "https://ap.example"})
	if err != nil {
		t.Fatalf("failed integrity opens retained writer lock: %v", err)
	}
	_ = reopened.Close()
}

var fileEventTestNow = time.Date(2026, 8, 3, 9, 0, 0, 0, time.UTC)

func fileEventTestAPSubscription(eventID string) APEventSubscription {
	return APEventSubscription{
		APIssuer: "https://ap.example", EventID: eventID,
		Resource: "https://resource.example", Agent: "aauth:subscriber@ap.example",
		ActiveUntil: fileEventTestNow.Add(time.Hour), MaxUses: 1,
	}
}

func fileEventTestResourceSubscription(eventID string) ResourceEventSubscription {
	return ResourceEventSubscription{
		APIssuer: "https://ap.example", EventID: eventID,
		Resource: "https://resource.example", Agent: "aauth:subscriber@ap.example",
		ActiveUntil: fileEventTestNow.Add(time.Hour),
	}
}

func replaceLastBytes(body, old, replacement []byte) []byte {
	index := bytes.LastIndex(body, old)
	if index < 0 {
		return body
	}
	result := make([]byte, 0, len(body)-len(old)+len(replacement))
	result = append(result, body[:index]...)
	result = append(result, replacement...)
	return append(result, body[index+len(old):]...)
}
