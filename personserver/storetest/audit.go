package storetest

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"sync"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/personserver"
)

// AuditContract constructs a fresh store containing one active mission.
type AuditContract struct {
	New func(testing.TB) (personserver.MissionAuditStore, personserver.MissionRecord)
}

// RunAudit checks the public mission-audit store contract. Passing the suite
// complements, but does not replace, backend transaction, restart, and
// failure-injection tests.
func RunAudit(t *testing.T, contract AuditContract) {
	t.Helper()
	if contract.New == nil {
		t.Fatal("storetest: AuditContract.New is required")
	}

	t.Run("ordered identical appends and copies", func(t *testing.T) {
		store, mission := contract.New(t)
		first := auditRecord(t, mission.S256, "files.write", mission.ApprovedAt.Add(time.Second))
		second := cloneAuditRecord(first)
		third := auditRecord(t, mission.S256, "messages.send", mission.ApprovedAt.Add(2*time.Second))
		wantFirst := cloneAuditRecord(first)
		wantThird := cloneAuditRecord(third)
		if err := store.AppendMissionAudit(context.Background(), cloneMission(mission), first); err != nil {
			t.Fatal(err)
		}
		if err := store.AppendMissionAudit(context.Background(), cloneMission(mission), second); err != nil {
			t.Fatalf("identical audit append = %v", err)
		}
		if err := store.AppendMissionAudit(context.Background(), cloneMission(mission), third); err != nil {
			t.Fatal(err)
		}
		mutateAuditRecord(&first)

		records, err := store.LoadMissionAuditsForAgent(
			context.Background(), mission.Agent, mission.S256, mission.ApprovedAt.Add(3*time.Second),
		)
		if err != nil {
			t.Fatal(err)
		}
		if len(records) != 3 || !auditRecordsEqual(records[0], wantFirst) ||
			!auditRecordsEqual(records[1], wantFirst) || !auditRecordsEqual(records[2], wantThird) {
			t.Fatalf("ordered audit records = %#v", records)
		}
		mutateAuditRecord(&records[0])
		if !auditRecordsEqual(records[1], wantFirst) {
			t.Fatal("audit load aliases sibling records")
		}
		reloaded, err := store.LoadMissionAuditsForAgent(
			context.Background(), mission.Agent, mission.S256, mission.ApprovedAt.Add(3*time.Second),
		)
		if err != nil {
			t.Fatal(err)
		}
		if len(reloaded) != 3 || !auditRecordsEqual(reloaded[0], wantFirst) ||
			!auditRecordsEqual(reloaded[1], wantFirst) || !auditRecordsEqual(reloaded[2], wantThird) {
			t.Fatalf("audit load aliases store state = %#v", reloaded)
		}
	})

	t.Run("owner cloaking and changed mission refusal", func(t *testing.T) {
		store, mission := contract.New(t)
		if _, err := store.LoadMissionAuditsForAgent(
			context.Background(), "aauth:other@provider.example", mission.S256, mission.ApprovedAt,
		); !errors.Is(err, personserver.ErrMissionNotFound) {
			t.Fatalf("wrong owner load = %v", err)
		}
		for _, test := range []struct {
			name    string
			change  func(*personserver.MissionRecord)
			wantErr error
		}{
			{name: "S256", change: func(record *personserver.MissionRecord) {
				record.S256 = aauth.MissionS256([]byte("different mission"))
			}, wantErr: personserver.ErrMissionNotFound},
			{name: "Agent", change: func(record *personserver.MissionRecord) {
				record.Agent = "aauth:other@provider.example"
			}, wantErr: personserver.ErrMissionNotFound},
			{name: "ExactJSON", change: func(record *personserver.MissionRecord) {
				record.ExactJSON[0] = '['
			}, wantErr: personserver.ErrMissionConflict},
			{name: "ApprovedAt", change: func(record *personserver.MissionRecord) {
				record.ApprovedAt = record.ApprovedAt.Add(-time.Second)
			}, wantErr: personserver.ErrMissionConflict},
			{name: "ExpiresAt", change: func(record *personserver.MissionRecord) {
				record.ExpiresAt = record.ExpiresAt.Add(time.Second)
			}, wantErr: personserver.ErrMissionConflict},
			{name: "State", change: func(record *personserver.MissionRecord) {
				record.State = personserver.MissionTerminated
			}, wantErr: personserver.ErrMissionConflict},
			{name: "TerminationReason", change: func(record *personserver.MissionRecord) {
				record.TerminationReason = "changed"
			}, wantErr: personserver.ErrMissionConflict},
			{name: "Completion", change: func(record *personserver.MissionRecord) {
				record.Completion = &personserver.MissionCompletionRecord{AcceptedAt: record.ApprovedAt}
			}, wantErr: personserver.ErrMissionConflict},
		} {
			t.Run(test.name, func(t *testing.T) {
				changed := cloneMission(mission)
				test.change(&changed)
				record := auditRecord(t, changed.S256, "files.write", mission.ApprovedAt.Add(time.Second))
				if err := store.AppendMissionAudit(context.Background(), changed, record); !errors.Is(err, test.wantErr) {
					t.Fatalf("changed mission append = %v, want %v", err, test.wantErr)
				}
			})
		}
		records, err := store.LoadMissionAuditsForAgent(
			context.Background(), mission.Agent, mission.S256, mission.ApprovedAt.Add(time.Second),
		)
		if err != nil || len(records) != 0 {
			t.Fatalf("failed append retained records = %#v, %v", records, err)
		}
	})

	t.Run("accepted update does not invalidate an audit append", func(t *testing.T) {
		store, mission := contract.New(t)
		at := mission.ApprovedAt.Add(time.Second)
		update, err := aauth.EncodeMissionUpdate(aauth.MissionUpdate{
			Action: "update", Description: "Recorded work changed without changing the mission.",
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := store.AppendMissionUpdate(context.Background(), cloneMission(mission), at, update); err != nil {
			t.Fatal(err)
		}
		if err := store.AppendMissionAudit(
			context.Background(), cloneMission(mission), auditRecord(t, mission.S256, "files.write", at),
		); err != nil {
			t.Fatalf("audit after accepted update = %v", err)
		}
		records, err := store.LoadMissionAuditsForAgent(
			context.Background(), mission.Agent, mission.S256, at,
		)
		if err != nil || len(records) != 1 {
			t.Fatalf("audit after accepted update = %#v, %v", records, err)
		}
	})

	t.Run("append is atomic with an accepted update", func(t *testing.T) {
		store, mission := contract.New(t)
		at := mission.ApprovedAt.Add(time.Second)
		update, err := aauth.EncodeMissionUpdate(aauth.MissionUpdate{
			Action: "update", Description: "Recorded work changed without changing the mission.",
		})
		if err != nil {
			t.Fatal(err)
		}
		audit := auditRecord(t, mission.S256, "files.write", at)
		start := make(chan struct{})
		var updateErr, auditErr error
		var wait sync.WaitGroup
		wait.Add(2)
		go func() {
			defer wait.Done()
			<-start
			_, updateErr = store.AppendMissionUpdate(context.Background(), cloneMission(mission), at, update)
		}()
		go func() {
			defer wait.Done()
			<-start
			auditErr = store.AppendMissionAudit(context.Background(), cloneMission(mission), audit)
		}()
		close(start)
		wait.Wait()
		if updateErr != nil || auditErr != nil {
			t.Fatalf("concurrent update and audit = update %v, audit %v", updateErr, auditErr)
		}
		current, err := store.LoadMissionForAgent(context.Background(), mission.Agent, mission.S256, at)
		if err != nil || len(current.AcceptedUpdates) != 1 {
			t.Fatalf("mission after concurrent update and audit = %#v, %v", current, err)
		}
		records, err := store.LoadMissionAuditsForAgent(
			context.Background(), mission.Agent, mission.S256, at,
		)
		if err != nil || len(records) != 1 {
			t.Fatalf("audit after concurrent update and audit = %#v, %v", records, err)
		}
	})

	t.Run("expiry prevents append atomically", func(t *testing.T) {
		store, mission := contract.New(t)
		record := auditRecord(t, mission.S256, "files.write", mission.ExpiresAt)
		err := store.AppendMissionAudit(context.Background(), cloneMission(mission), record)
		var terminated *personserver.MissionTerminatedError
		if !errors.As(err, &terminated) || terminated.TerminationReason != "expired" {
			t.Fatalf("append at expiry = %T %v", err, err)
		}
		records, err := store.LoadMissionAuditsForAgent(
			context.Background(), mission.Agent, mission.S256, mission.ExpiresAt,
		)
		if err != nil || len(records) != 0 {
			t.Fatalf("expired append retained records = %#v, %v", records, err)
		}
	})

	t.Run("append is atomic with mission completion", func(t *testing.T) {
		store, mission := contract.New(t)
		at := mission.ApprovedAt.Add(time.Second)
		audit := auditRecord(t, mission.S256, "files.write", at)
		completion, err := aauth.EncodeMissionCompletion(aauth.MissionCompletion{
			Action: "completion", Summary: "The mission is complete.",
		})
		if err != nil {
			t.Fatal(err)
		}
		start := make(chan struct{})
		var appendErr, completeErr error
		var wait sync.WaitGroup
		wait.Add(2)
		go func() {
			defer wait.Done()
			<-start
			appendErr = store.AppendMissionAudit(context.Background(), cloneMission(mission), audit)
		}()
		go func() {
			defer wait.Done()
			<-start
			_, completeErr = store.CompleteMission(context.Background(), cloneMission(mission), at, completion)
		}()
		close(start)
		wait.Wait()
		if completeErr != nil {
			t.Fatalf("concurrent completion = %v", completeErr)
		}
		if appendErr != nil {
			var terminated *personserver.MissionTerminatedError
			if !errors.As(appendErr, &terminated) || terminated.TerminationReason != "completed" {
				t.Fatalf("concurrent append = %T %v", appendErr, appendErr)
			}
		}
		records, err := store.LoadMissionAuditsForAgent(
			context.Background(), mission.Agent, mission.S256, at,
		)
		if err != nil {
			t.Fatal(err)
		}
		want := 1
		if appendErr != nil {
			want = 0
		}
		if len(records) != want {
			t.Fatalf("concurrent audit count = %d, want %d", len(records), want)
		}
	})
}

func auditRecord(t *testing.T, missionS256, action string, recordedAt time.Time) personserver.MissionAuditRecord {
	t.Helper()
	exactJSON := []byte("{\n" +
		`  "extension": {"retained": [1, 2, 3]},` + "\n" +
		`  "action": ` + strconv.Quote(action) + ",\n" +
		`  "mission_s256": ` + strconv.Quote(missionS256) + ",\n" +
		`  "description": "Recorded **action**.",` + "\n" +
		`  "parameters": {"path": "report.md"},` + "\n" +
		`  "result": {"ok": true}` + "\n" +
		"}")
	document, err := aauth.DecodeAudit(exactJSON)
	if err != nil {
		t.Fatal(err)
	}
	return personserver.MissionAuditRecord{Document: document, RecordedAt: recordedAt}
}

func auditRecordsEqual(left, right personserver.MissionAuditRecord) bool {
	return left.RecordedAt.Equal(right.RecordedAt) && bytes.Equal(left.Document.ExactJSON, right.Document.ExactJSON) &&
		left.Document.Entry.MissionS256 == right.Document.Entry.MissionS256 &&
		left.Document.Entry.Action == right.Document.Entry.Action &&
		left.Document.Entry.Description == right.Document.Entry.Description &&
		bytes.Equal(left.Document.Entry.Parameters, right.Document.Entry.Parameters) &&
		bytes.Equal(left.Document.Entry.Result, right.Document.Entry.Result)
}

func cloneAuditRecord(record personserver.MissionAuditRecord) personserver.MissionAuditRecord {
	record.Document.ExactJSON = append([]byte(nil), record.Document.ExactJSON...)
	record.Document.Entry.Parameters = append(json.RawMessage(nil), record.Document.Entry.Parameters...)
	record.Document.Entry.Result = append(json.RawMessage(nil), record.Document.Entry.Result...)
	return record
}

func mutateAuditRecord(record *personserver.MissionAuditRecord) {
	if len(record.Document.ExactJSON) > 0 {
		record.Document.ExactJSON[0] = '['
	}
	if len(record.Document.Entry.Parameters) > 0 {
		record.Document.Entry.Parameters[0] = '['
	}
	if len(record.Document.Entry.Result) > 0 {
		record.Document.Entry.Result[0] = '['
	}
}

func cloneMission(record personserver.MissionRecord) personserver.MissionRecord {
	record.ExactJSON = append([]byte(nil), record.ExactJSON...)
	record.AcceptedUpdates = append([]personserver.MissionUpdateRecord(nil), record.AcceptedUpdates...)
	for index := range record.AcceptedUpdates {
		record.AcceptedUpdates[index].Document.ExactJSON = append(
			[]byte(nil), record.AcceptedUpdates[index].Document.ExactJSON...,
		)
	}
	if record.Completion != nil {
		completion := *record.Completion
		completion.Document.ExactJSON = append([]byte(nil), completion.Document.ExactJSON...)
		record.Completion = &completion
	}
	return record
}
