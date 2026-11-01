package personserver

import (
	"context"
	"errors"
	"fmt"
	"time"
	"unicode/utf8"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/internal/revocation"
)

// maximumTerminationReasonBytes bounds a termination reason, as a terminated
// report to a supervision server bounds it.
const maximumTerminationReasonBytes = 256

// MissionTermination reports a mission ended by TerminateMission and how far
// revoking what was issued under it has reached.
type MissionTermination struct {
	// Reason is the reason the mission ended with: the one given, or the one
	// an earlier end retained, which a later call does not change.
	Reason string
	// Attempts holds one entry per recipient: the Resource of each person
	// token and of each auth token this Person Server issued under the
	// mission, and each Access Server a person token was presented to. It is
	// empty when nothing issued under the mission is outstanding, and when
	// the Person Server sends no revocations.
	Attempts []aauth.RevocationAttempt
}

// Pending reports whether any recipient has not reached a terminal outcome.
// Call TerminateMission again after RetryAfter to continue.
func (ended MissionTermination) Pending() bool { return attemptsPending(ended.Attempts) }

// RetryAfter is the longest delay a pending recipient asked for.
func (ended MissionTermination) RetryAfter() time.Duration { return attemptsRetryAfter(ended.Attempts) }

// TerminateMission ends an Agent's mission for a reason other than
// completion: revoked when the person, the owning Agent or an authorized
// administrator withdraws it, superseded when another approved mission
// replaces it, administrative when an administrator ends it under local
// policy, or another reason the deployment defines. agent and s256 name the
// mission as the mission store keys it. The host authenticates and
// authorizes whoever asks before calling it: the draft leaves the endpoint
// for this to a companion specification.
//
// The mission ends at once and for good, and every later request under it is
// refused with 403 mission_terminated and the reason. When TokenRevocation is
// configured with HTTPClient and Admit, the Person Server then revokes every
// unexpired token issued under the mission, from the mission store's records:
// each person token as RevokePersonToken does, at its Resource and at each
// Access Server it was presented to, which revokes the auth tokens it issued
// against it; and each auth token it issued itself, at its Resource. The end
// is reported to the supervisor deciding for the Agent, delivered at once when
// the supervisor can be reached and in order later when it cannot.
//
// completed and expired are refused: the person accepts a completion at the
// mission endpoint, and the store records expiry itself. A mission that has
// already ended keeps its reason, and is still revoked. Each call makes one
// attempt at each recipient that has not recorded the revocation, waiting at
// most the configured hold; repeating the call is safe and continues the
// cascade.
func (server *Server) TerminateMission(ctx context.Context, agent, s256, reason string) (MissionTermination, error) {
	if server == nil || server.missions == nil {
		return MissionTermination{}, errors.New("personserver: missions are not configured")
	}
	if ctx == nil {
		return MissionTermination{}, errors.New("personserver: mission termination context is required")
	}
	if err := aauth.ValidateAgentIdentifier(agent); err != nil {
		return MissionTermination{}, fmt.Errorf("personserver: mission Agent: %w", err)
	}
	if err := aauth.ValidateMissionS256(s256); err != nil {
		return MissionTermination{}, err
	}
	if err := validateTerminationReason(reason); err != nil {
		return MissionTermination{}, err
	}
	record, err := server.missions.TerminateMission(ctx, agent, s256, server.clock.Now().UTC(), reason)
	if err != nil {
		return MissionTermination{}, err
	}
	if record.Agent != agent || record.S256 != s256 {
		return MissionTermination{}, ErrMissionNotFound
	}
	if _, err := validateMissionRecord(record); err != nil || record.State != MissionTerminated {
		return MissionTermination{}, errors.New("personserver: mission store returned an invalid termination")
	}
	// Supervision, Terminated: when a mission ends for any reason, the
	// supervisor is told.
	server.reportMissionEnded(ctx, record)
	ended := MissionTermination{Reason: record.TerminationReason}
	if server.tokenRevocation != nil && server.tokenRevocation.sender != nil {
		ended.Attempts, err = server.revokeMissionTokens(ctx, s256)
	}
	server.deliverToAgentSupervisor(ctx, agent)
	if err != nil {
		return MissionTermination{}, err
	}
	return ended, nil
}

func validateTerminationReason(reason string) error {
	switch {
	case reason == "" || len(reason) > maximumTerminationReasonBytes || !utf8.ValidString(reason):
		return errors.New("personserver: a termination reason is 1 to 256 bytes of UTF-8")
	case reason == "completed":
		return errors.New("personserver: a mission is completed only by the person's acceptance at the mission endpoint")
	case reason == "expired":
		return errors.New("personserver: a mission expires at its expires_at, which the mission store records")
	}
	return nil
}

// revokeMissionTokens makes one step of a mission's cascade (Revocation
// Cascade, "PS revokes a mission"). It revokes each unexpired person token
// retained under the mission as RevokePersonToken does, chains and lineage
// included, and records each unexpired auth token retained under it as
// revoked, revoking one this Person Server issued at its Resource; an Access
// Server revokes its own when the person token reaches it.
func (server *Server) revokeMissionTokens(ctx context.Context, s256 string) ([]aauth.RevocationAttempt, error) {
	issued, err := server.missions.LoadMissionTokens(ctx, s256)
	if err != nil {
		return nil, fmt.Errorf("personserver: load the mission's tokens: %w", err)
	}
	now := server.clock.Now().UTC()
	roots := make([]PersonTokenRecord, 0, len(issued.PersonTokens))
	for _, record := range issued.PersonTokens {
		if validatePersonTokenRecord(record) != nil || record.PersonServer != server.issuer || record.MissionS256 != s256 {
			return nil, errors.New("personserver: mission store returned a person token of another mission")
		}
		if now.Before(record.ExpiresAt) {
			roots = append(roots, record)
		}
	}
	targets, retainUntil, err := server.personTokenCascade(ctx, roots)
	if err != nil {
		return nil, err
	}
	state := server.tokenRevocation
	for _, record := range issued.AuthTokens {
		if validateIssuedAuthTokenRecord(record) != nil || record.MissionS256 != s256 {
			return nil, errors.New("personserver: mission store returned an auth token of another mission")
		}
		if !now.Before(record.ExpiresAt) {
			continue
		}
		if err := state.store.Revoke(ctx, aauth.RevocationRequest{Reference: record.Reference, ExpiresAt: record.ExpiresAt}); err != nil {
			return nil, fmt.Errorf("personserver: record auth-token revocation: %w", err)
		}
		if record.ExpiresAt.After(retainUntil) {
			retainUntil = record.ExpiresAt
		}
		if record.Reference.Issuer == server.issuer {
			targets = append(targets, revocation.Target{
				Recipient: record.Resource, Metadata: aauth.ResourceDiscoveryDocument,
				JTI: record.Reference.JTI, ExpiresAt: record.ExpiresAt,
			})
		}
	}
	hold := state.hold
	if hold <= 0 {
		hold = revocation.DefaultHold
	}
	result := state.missions.Step(ctx, state.sender, revocation.Run{
		Key: aauth.TokenReference{Issuer: server.issuer, JTI: s256}, Caller: server.issuer,
		Targets: targets, Retry: true, Hold: hold, RetainUntil: retainUntil.Add(revocation.Skew), Now: now,
	})
	return revocation.Aggregate(result), nil
}

// deliverToAgentSupervisor delivers what is queued for the supervisor
// deciding for the Agent, in order. A supervisor that cannot be reached now
// receives it at the next delivery.
func (server *Server) deliverToAgentSupervisor(ctx context.Context, agent string) {
	if server.supervision == nil {
		return
	}
	supervisor, err := server.supervision.store.LoadAgentSupervisor(ctx, agent)
	if err != nil {
		return
	}
	_, _ = server.deliverNotices(ctx, supervisor)
}
