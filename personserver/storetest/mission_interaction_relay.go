package storetest

import (
	"context"
	"errors"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/personserver"
)

// MissionInteractionRelayContract constructs a fresh store with one active
// mission owned by the relay test Agent.
type MissionInteractionRelayContract struct {
	New func(testing.TB) (personserver.MissionInteractionRelayStore, personserver.MissionRecord)
}

// RunMissionInteractionRelay checks exact mission comparison across relay
// create, resolution, polling, and terminal consumption.
func RunMissionInteractionRelay(t *testing.T, contract MissionInteractionRelayContract) {
	t.Helper()
	if contract.New == nil {
		t.Fatal("storetest: MissionInteractionRelayContract.New is required")
	}

	t.Run("active mission owns exact relay lifecycle", func(t *testing.T) {
		store, mission := contract.New(t)
		record := missionRelayRecord(t, "mission-relay", mission)
		if err := store.CreateMissionInteractionRelay(context.Background(), mission, record, record.CreatedAt); err != nil {
			t.Fatal(err)
		}
		wrong := relayIdentity(record)
		wrong.Agent = "aauth:other@ap.example"
		if _, err := store.PollMissionInteractionRelay(context.Background(), mission, record.ID, wrong, record.CreatedAt); !errors.Is(err, personserver.ErrInteractionRelayNotFound) {
			t.Fatalf("wrong-Agent mission poll = %v", err)
		}
		resolved, err := store.ResolveMissionInteractionRelay(
			context.Background(), mission, record.ID, aauth.InteractionRelayInteracting,
			record.CreatedAt.Add(time.Second),
		)
		if err != nil || resolved.Completion.Status != aauth.InteractionRelayInteracting {
			t.Fatalf("mission relay resolution = %#v, %v", resolved, err)
		}
		polled, err := store.PollMissionInteractionRelay(
			context.Background(), mission, record.ID, relayIdentity(record), record.CreatedAt.Add(time.Second),
		)
		if err != nil || polled.State != personserver.InteractionRelayResolved {
			t.Fatalf("mission relay poll = %#v, %v", polled, err)
		}
		if err := store.ConsumeMissionInteractionRelay(
			context.Background(), mission, record.ID, polled, record.CreatedAt.Add(time.Second),
		); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("mission expiry prevents first relay consequence", func(t *testing.T) {
		store, mission := contract.New(t)
		record := missionRelayRecord(t, "mission-relay-expired", mission)
		if err := store.CreateMissionInteractionRelay(context.Background(), mission, record, mission.ExpiresAt); err == nil {
			t.Fatal("expired mission retained relay")
		} else {
			var terminated *personserver.MissionTerminatedError
			if !errors.As(err, &terminated) || terminated.TerminationReason != "expired" {
				t.Fatalf("expired mission create = %T %v", err, err)
			}
		}
		if _, err := store.LoadInteractionRelay(context.Background(), record.ID, mission.ExpiresAt); !errors.Is(err, personserver.ErrInteractionRelayNotFound) {
			t.Fatalf("expired mission retained relay = %v", err)
		}
	})

	t.Run("mission completion blocks relay resolution", func(t *testing.T) {
		store, mission := contract.New(t)
		record := missionRelayRecord(t, "mission-relay-terminated", mission)
		if err := store.CreateMissionInteractionRelay(context.Background(), mission, record, record.CreatedAt); err != nil {
			t.Fatal(err)
		}
		completion, err := aauth.EncodeMissionCompletion(aauth.MissionCompletion{
			Action: "completion", Summary: "Mission completed before the person used the relay.",
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := store.CompleteMission(context.Background(), mission, record.CreatedAt.Add(time.Second), completion); err != nil {
			t.Fatal(err)
		}
		if _, err := store.ResolveMissionInteractionRelay(
			context.Background(), mission, record.ID, aauth.InteractionRelayInteracting,
			record.CreatedAt.Add(2*time.Second),
		); err == nil {
			t.Fatal("completed mission resolved relay")
		} else {
			var terminated *personserver.MissionTerminatedError
			if !errors.As(err, &terminated) || terminated.TerminationReason != "completed" {
				t.Fatalf("completed mission resolution = %T %v", err, err)
			}
		}
	})
}

func missionRelayRecord(t *testing.T, id string, mission personserver.MissionRecord) personserver.InteractionRelayRecord {
	t.Helper()
	record := relayRecord(t, id)
	record.Agent = mission.Agent
	document, err := aauth.EncodeInteractionRelay(aauth.InteractionRelay{
		Type: aauth.InteractionRelayPayment, URL: "https://resource.example/pay",
		Code: "X7K2-M9P4", MissionS256: mission.S256,
	})
	if err != nil {
		t.Fatal(err)
	}
	record.Document = document
	return record
}
