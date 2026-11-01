package supervisionserver

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/supervision"
)

// The person's answer to an ask comes back in decision.resolved with the
// reach they gave it, and the SS remembers and applies it to later acts
// (Supervision, Reach of an Answer). The meaning of once, mission and always
// is fixed; what "this kind" of act means is the SS's, Config.Kind.

// StandingAnswer is an answer the person gave with the mission or always
// reach. The SS applies it, before its policy, to the Agent's later acts of
// the same Kind: under MissionS256 only, until that mission terminates, or,
// when MissionS256 is empty, under any mission or none. Answer is allow or
// deny; SDI names the decision it answered.
type StandingAnswer struct {
	PersonServer string
	Subject      string
	Agent        string
	Kind         string
	MissionS256  string
	Answer       supervision.Answer
	SDI          string
	RecordedAt   time.Time
}

// ReachStore keeps the person's standing answers.
//
// PutStandingAnswer records answer, replacing one held for the same
// (PersonServer, Subject, Agent, Kind, MissionS256). StandingAnswers returns
// those held for (PersonServer, Subject, Agent) in the order they were
// recorded, a replaced one at its new place. ForgetMissionAnswers removes
// those limited to mission s256 of (PersonServer, Subject); removing none is
// not an error. Every value crossing the boundary is an independent copy.
type ReachStore interface {
	PutStandingAnswer(ctx context.Context, answer StandingAnswer) error
	StandingAnswers(ctx context.Context, personServer, subject, agent string) ([]StandingAnswer, error)
	ForgetMissionAnswers(ctx context.Context, personServer, subject, s256 string) error
}

// DefaultKind is what "this kind" of act means when Config.Kind is nil: the
// act with the resource it is for, a person token's resource or the issuer of
// an auth token's resource token, or with a permission's action; any other
// act is its kind alone.
func DefaultKind(request supervision.Request) string {
	switch request.Kind {
	case supervision.KindPersonToken:
		return string(request.Kind) + " " + request.Resource
	case supervision.KindAuthToken:
		// The Person Server verified the token; only its issuer is read.
		if parsed, err := jose.ParseCompact(request.ResourceToken); err == nil {
			var claims struct {
				Issuer string `json:"iss"`
			}
			if json.Unmarshal(parsed.Payload(), &claims) == nil && claims.Issuer != "" {
				return string(request.Kind) + " " + claims.Issuer
			}
		}
	case supervision.KindPermission:
		return string(request.Kind) + " " + request.Action
	}
	return string(request.Kind)
}

// reaches reports whether a standing answer can apply to an act of kind: a
// person-token, auth-token, permission or mission-update request. An allow
// carries no terms, which a proposal needs, and only the person accepts a
// completion.
func reaches(kind supervision.Kind) bool {
	switch kind {
	case supervision.KindPersonToken, supervision.KindAuthToken, supervision.KindPermission, supervision.KindMissionUpdate:
		return true
	}
	return false
}

// standingDecision returns the decision the person's latest matching
// standing answer makes for request, or nil when none applies. mission is the
// mission the request names, nil when it names none.
func (server *Server) standingDecision(ctx context.Context, personServer string, request supervision.Request, mission *MissionRecord) (*supervision.Decision, error) {
	if !reaches(request.Kind) {
		return nil, nil
	}
	answers, err := server.store.StandingAnswers(ctx, personServer, request.Subject, request.Agent)
	if err != nil || len(answers) == 0 {
		return nil, err
	}
	kind := server.kind(request)
	for index := len(answers) - 1; index >= 0; index-- {
		answer := answers[index]
		if answer.Kind != kind {
			continue
		}
		if answer.MissionS256 != "" && (mission == nil || mission.Terminated || mission.S256 != answer.MissionS256) {
			continue
		}
		decision := supervision.Decision{Verdict: supervision.VerdictDeny}
		if answer.Answer == supervision.AnswerAllow {
			decision.Verdict = supervision.VerdictAllow
		}
		return &decision, nil
	}
	return nil, nil
}

// rememberReach records the reach of the person's answer in a
// decision.resolved event, for the decision it names. An answer abandoned, or
// given once or with a reach the SS offered itself, is left to the policy,
// which sees the event through Config.Observe. So is one about a decision the
// SS does not hold, such as an act the Person Server put to the person
// because the SS could not be reached: the SS does not know its kind.
func (server *Server) rememberReach(ctx context.Context, personServer string, event supervision.Event, now time.Time) error {
	if event.Apply != supervision.ApplyMission && event.Apply != supervision.ApplyAlways ||
		event.Answer != supervision.AnswerAllow && event.Answer != supervision.AnswerDeny {
		return nil
	}
	record, err := server.store.LoadDecision(ctx, personServer, event.SDI)
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if record.Subject != event.Subject || record.Agent != event.Agent || !reaches(record.Kind) {
		return nil
	}
	request, err := currentRequest(record)
	if err != nil {
		return err
	}
	answer := StandingAnswer{
		PersonServer: personServer, Subject: record.Subject, Agent: record.Agent, Kind: server.kind(request),
		Answer: event.Answer, SDI: record.SDI, RecordedAt: now,
	}
	if event.Apply == supervision.ApplyMission {
		if record.MissionS256 == "" {
			return nil
		}
		answer.MissionS256 = record.MissionS256
	}
	return server.store.PutStandingAnswer(ctx, answer)
}
