package storetest

import (
	"context"
	"errors"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/personserver"
)

// MissionPermissionContract constructs a fresh store containing one active
// mission owned by the permission test Agent.
type MissionPermissionContract struct {
	New func(testing.TB) (personserver.MissionPermissionStore, personserver.MissionRecord)
}

// RunMissionPermission checks atomic permission retention and delivery against
// exact active mission state. It complements backend transaction and restart
// tests.
func RunMissionPermission(t *testing.T, contract MissionPermissionContract) {
	t.Helper()
	if contract.New == nil {
		t.Fatal("storetest: MissionPermissionContract.New is required")
	}

	t.Run("active mission binds immediate permission", func(t *testing.T) {
		store, mission := contract.New(t)
		record := permissionRecord("mission-immediate", personserver.PermissionStateGranted)
		record.MissionS256 = mission.S256
		record.Decision = personserver.PermissionDecision{Permission: aauth.PermissionGranted}
		record.DecidedAt = record.CreatedAt
		if err := store.CreateMissionPermission(context.Background(), mission, record, record.CreatedAt); err != nil {
			t.Fatal(err)
		}
		loaded, err := store.LoadPermission(context.Background(), record.ID, record.CreatedAt)
		if err != nil || loaded.MissionS256 != mission.S256 || loaded.State != personserver.PermissionStateGranted {
			t.Fatalf("mission permission = %#v, %v", loaded, err)
		}
		wrongOwner := mission
		wrongOwner.Agent = "aauth:other@provider.example"
		other := record
		other.ID = "mission-other-owner"
		if err := store.CreateMissionPermission(context.Background(), wrongOwner, other, record.CreatedAt); !errors.Is(err, personserver.ErrMissionNotFound) {
			t.Fatalf("wrong-owner create = %v", err)
		}
	})

	t.Run("mission expiry prevents first permission consequence", func(t *testing.T) {
		store, mission := contract.New(t)
		record := permissionRecord("mission-expired", personserver.PermissionStateGranted)
		record.MissionS256 = mission.S256
		record.Decision = personserver.PermissionDecision{Permission: aauth.PermissionGranted}
		record.DecidedAt = record.CreatedAt
		if err := store.CreateMissionPermission(context.Background(), mission, record, mission.ExpiresAt); err == nil {
			t.Fatal("expired mission created permission")
		} else {
			var terminated *personserver.MissionTerminatedError
			if !errors.As(err, &terminated) || terminated.TerminationReason != "expired" {
				t.Fatalf("expired create = %T %v", err, err)
			}
		}
		if _, err := store.LoadPermission(context.Background(), record.ID, mission.ExpiresAt); !errors.Is(err, personserver.ErrPermissionNotFound) {
			t.Fatalf("expired mission retained permission = %v", err)
		}
	})

	t.Run("termination prevents decision and result delivery", func(t *testing.T) {
		store, mission := contract.New(t)
		record := permissionRecord("mission-deferred", personserver.PermissionStatePending)
		record.MissionS256 = mission.S256
		record.ExpiresAt = permissionNow.Add(30 * time.Minute)
		if err := store.CreateMissionPermission(context.Background(), mission, record, permissionNow); err != nil {
			t.Fatal(err)
		}
		completion, err := aauth.EncodeMissionCompletion(aauth.MissionCompletion{
			Action: "completion", Summary: "Mission ended before the local action was approved.",
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := store.CompleteMission(context.Background(), mission, permissionNow.Add(time.Minute), completion); err != nil {
			t.Fatal(err)
		}
		if _, err := store.DecideMissionPermission(
			context.Background(), mission, record.ID,
			personserver.PermissionDecision{Permission: aauth.PermissionGranted}, permissionNow.Add(2*time.Minute),
		); err == nil {
			t.Fatal("terminated mission decided permission")
		} else {
			var terminated *personserver.MissionTerminatedError
			if !errors.As(err, &terminated) || terminated.TerminationReason != "completed" {
				t.Fatalf("terminated decision = %T %v", err, err)
			}
		}
		retained, err := store.LoadPermission(context.Background(), record.ID, permissionNow.Add(2*time.Minute))
		if err != nil || retained.State != personserver.PermissionStatePending {
			t.Fatalf("permission after mission termination = %#v, %v", retained, err)
		}
	})

	t.Run("exact active decision and consume remain canonical", func(t *testing.T) {
		store, mission := contract.New(t)
		record := permissionRecord("mission-canonical", personserver.PermissionStatePending)
		record.MissionS256 = mission.S256
		record.ExpiresAt = permissionNow.Add(30 * time.Minute)
		if err := store.CreateMissionPermission(context.Background(), mission, record, permissionNow); err != nil {
			t.Fatal(err)
		}
		decision := personserver.PermissionDecision{Permission: aauth.PermissionDenied, Reason: "person declined"}
		decidedAt := permissionNow.Add(time.Minute)
		decided, err := store.DecideMissionPermission(
			context.Background(), mission, record.ID, decision, decidedAt,
		)
		if err != nil || decided.Decision != decision || !decided.DecidedAt.Equal(decidedAt) {
			t.Fatalf("mission decision = %#v, %v", decided, err)
		}
		replayed, err := store.DecideMissionPermission(
			context.Background(), mission, record.ID, decision, permissionNow.Add(2*time.Minute),
		)
		if err != nil || !replayed.DecidedAt.Equal(decidedAt) {
			t.Fatalf("mission decision replay = %#v, %v", replayed, err)
		}
		polled, err := store.PollMissionPermission(
			context.Background(), mission, record.ID, permissionIdentity(), permissionNow.Add(2*time.Minute),
		)
		if err != nil || polled.State != personserver.PermissionStateDenied {
			t.Fatalf("mission poll = %#v, %v", polled, err)
		}
		if err := store.ConsumeMissionPermissionResult(
			context.Background(), mission, record.ID, polled, permissionNow.Add(2*time.Minute),
		); err != nil {
			t.Fatal(err)
		}
		if _, err := store.PollPermission(context.Background(), record.ID, permissionIdentity(), permissionNow.Add(2*time.Minute)); !errors.Is(err, personserver.ErrPermissionGone) {
			t.Fatalf("poll after mission consume = %v", err)
		}
	})
}
