package storetest

import (
	"context"
	"errors"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/personserver"
)

// MissionInteractionQuestionContract constructs a fresh store with one active
// mission owned by the question test Agent.
type MissionInteractionQuestionContract struct {
	New func(testing.TB) (personserver.MissionInteractionQuestionStore, personserver.MissionRecord)
}

// RunMissionInteractionQuestion checks exact mission comparison across
// immediate retention, deferred creation, resolution, polling, and consume.
func RunMissionInteractionQuestion(t *testing.T, contract MissionInteractionQuestionContract) {
	t.Helper()
	if contract.New == nil {
		t.Fatal("storetest: MissionInteractionQuestionContract.New is required")
	}

	t.Run("immediate answer is retained under active mission", func(t *testing.T) {
		store, mission := contract.New(t)
		record := missionQuestionRecord(t, "mission-question-immediate", mission)
		answer, err := aauth.EncodeInteractionAnswer(aauth.InteractionAnswer{Answer: "Proceed."})
		if err != nil {
			t.Fatal(err)
		}
		record.State, record.Answer = personserver.InteractionQuestionAnswered, answer
		record.AnsweredAt = record.CreatedAt
		if err := store.CommitMissionInteractionQuestion(
			context.Background(), mission, record, record.CreatedAt,
		); err != nil {
			t.Fatal(err)
		}
		loaded, err := store.LoadInteractionQuestion(context.Background(), record.ID, record.CreatedAt)
		if err != nil || loaded.Answer.Answer.Answer != "Proceed." {
			t.Fatalf("immediate mission question = %#v, %v", loaded, err)
		}
	})

	t.Run("deferred lifecycle keeps mission and Agent binding", func(t *testing.T) {
		store, mission := contract.New(t)
		record := missionQuestionRecord(t, "mission-question-deferred", mission)
		if err := store.CommitMissionInteractionQuestion(
			context.Background(), mission, record, record.CreatedAt,
		); err != nil {
			t.Fatal(err)
		}
		wrong := questionIdentity(record)
		wrong.Agent = "aauth:other@ap.example"
		if _, err := store.PollMissionInteractionQuestion(
			context.Background(), mission, record.ID, wrong, record.CreatedAt,
		); !errors.Is(err, personserver.ErrInteractionQuestionNotFound) {
			t.Fatalf("wrong-Agent mission poll = %v", err)
		}
		answer, err := aauth.EncodeInteractionAnswer(aauth.InteractionAnswer{Answer: "Proceed."})
		if err != nil {
			t.Fatal(err)
		}
		resolved, err := store.ResolveMissionInteractionQuestion(
			context.Background(), mission, record.ID, personserver.InteractionQuestionAnswered,
			answer, record.CreatedAt.Add(time.Second),
		)
		if err != nil || resolved.State != personserver.InteractionQuestionAnswered {
			t.Fatalf("mission question resolution = %#v, %v", resolved, err)
		}
		polled, err := store.PollMissionInteractionQuestion(
			context.Background(), mission, record.ID, questionIdentity(record),
			record.CreatedAt.Add(time.Second),
		)
		if err != nil || polled.Answer.Answer.Answer != "Proceed." {
			t.Fatalf("mission question poll = %#v, %v", polled, err)
		}
		if err := store.ConsumeMissionInteractionQuestion(
			context.Background(), mission, record.ID, polled, record.CreatedAt.Add(time.Second),
		); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("mission expiry prevents first question consequence", func(t *testing.T) {
		store, mission := contract.New(t)
		record := missionQuestionRecord(t, "mission-question-expired", mission)
		if err := store.CommitMissionInteractionQuestion(
			context.Background(), mission, record, mission.ExpiresAt,
		); err == nil {
			t.Fatal("expired mission retained question")
		} else {
			var terminated *personserver.MissionTerminatedError
			if !errors.As(err, &terminated) || terminated.TerminationReason != "expired" {
				t.Fatalf("expired mission question = %T %v", err, err)
			}
		}
	})
}

func missionQuestionRecord(
	t *testing.T,
	id string,
	mission personserver.MissionRecord,
) personserver.InteractionQuestionRecord {
	t.Helper()
	record := questionRecord(t, id)
	record.Agent = mission.Agent
	document, err := aauth.EncodeInteractionQuestion(aauth.InteractionQuestion{
		Question: "Proceed?", MissionS256: mission.S256,
	})
	if err != nil {
		t.Fatal(err)
	}
	record.Document = document
	return record
}
