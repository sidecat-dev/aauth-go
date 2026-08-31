package personserver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"
	"unicode/utf8"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/internal/httpapi"
)

// AuditConfig explicitly enables the mission-bound Audit Endpoint. It has no
// action callback: the library records an action already performed and never
// executes the audited action.
type AuditConfig struct{}

// MissionAuditRecord retains one exact audit document and the verified
// request instant at which it was accepted.
type MissionAuditRecord struct {
	Document   aauth.AuditDocument
	RecordedAt time.Time
}

// MissionAuditStore keeps audit appends inside the same atomic backing-store
// boundary as mission lifecycle transitions.
//
// AppendMissionAudit compares the stable mission identity and lifecycle fields
// of expected with the current mission, atomically materializes expiry at
// record.RecordedAt, requires the mission to remain active and owned by
// expected.Agent, and appends one caller-owned exact record in Audit-entry
// order. Accepted updates are excluded from that comparison because Core says
// they do not change the mission. Identical records are distinct appends.
// It returns ErrMissionNotFound for an absent owner-scoped mission,
// *MissionTerminatedError for a terminal mission, and ErrMissionConflict for
// any other changed or invalid state. An error commits no audit append.
//
// LoadMissionAuditsForAgent supplies the host-side Audit-entry sublog read. It performs
// a combined owner-and-mission lookup, cloaking a different owner as
// ErrMissionNotFound, atomically materializes mission expiry at at, and returns
// independent record copies in append order. All returned Agent-authored
// values remain untrusted; Markdown must be sanitized before display and
// structured values need host-specific validation. Server exposes no
// Agent-facing Audit-log retrieval route or cross-event mission log.
type MissionAuditStore interface {
	MissionStore
	AppendMissionAudit(context.Context, MissionRecord, MissionAuditRecord) error
	LoadMissionAuditsForAgent(context.Context, string, string, time.Time) ([]MissionAuditRecord, error)
}

func (server *Server) handleAudit(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		response.Header().Set("Allow", http.MethodPost)
		writeProblem(response, http.StatusMethodNotAllowed, "method_not_allowed", errors.New("audit endpoint requires POST"))
		return
	}
	if server.missionAudits == nil {
		writeProblem(response, http.StatusNotFound, "not_found", errors.New("audit endpoint is not configured"))
		return
	}
	_, agent, _, err := server.verifyAgentProof(request, []string{"content-type", "content-digest"})
	if err != nil {
		writeAgentTokenProblem(response, err)
		return
	}
	if err := server.validateDirectAgentTopology(agent); err != nil {
		writeAgentTokenProblem(response, err)
		return
	}
	var raw json.RawMessage
	exactJSON, err := httpapi.DecodeExactJSON(request.Body, maxRequestBytes, &raw)
	if err != nil {
		writeProblem(response, http.StatusBadRequest, "invalid_request", err)
		return
	}
	if !utf8.Valid(exactJSON) {
		writeProblem(response, http.StatusBadRequest, "invalid_request", errors.New("audit document must be valid UTF-8 JSON"))
		return
	}
	document, err := aauth.DecodeAudit(exactJSON)
	if err != nil {
		writeProblem(response, http.StatusBadRequest, "invalid_request", err)
		return
	}
	// Evaluate mission liveness only after the complete signed body has been
	// read and verified. A request that crosses expiry while arriving must not
	// inherit the earlier proof-start instant.
	recordedAt := server.clock.Now().UTC()
	expected, err := server.loadActiveMissionForAudit(
		request.Context(), agent.Subject, document.Entry.MissionS256, recordedAt,
	)
	if err != nil {
		writeMissionActionProblem(response, err)
		return
	}
	record := MissionAuditRecord{Document: cloneAuditDocument(document), RecordedAt: recordedAt}
	if err := validateMissionAuditRecord(record); err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", err)
		return
	}
	if err := server.missionAudits.AppendMissionAudit(
		request.Context(), cloneMissionRecordForTransition(expected), cloneMissionAuditRecord(record),
	); err != nil {
		writeMissionActionProblem(response, err)
		return
	}
	response.Header().Set("Cache-Control", "no-store")
	response.WriteHeader(http.StatusCreated)
}

func (server *Server) loadActiveMissionForAudit(
	ctx context.Context,
	agent string,
	s256 string,
	at time.Time,
) (MissionRecord, error) {
	record, err := server.missionAudits.LoadMissionForAgent(ctx, agent, s256, at)
	if err != nil {
		return MissionRecord{}, err
	}
	if record.Agent != agent || record.S256 != s256 {
		return MissionRecord{}, errors.New("personserver: mission audit store returned a different mission")
	}
	mission, err := validateMissionRecord(record)
	if err != nil {
		return MissionRecord{}, err
	}
	if mission.Blob.Approver != server.issuer {
		return MissionRecord{}, errors.New("personserver: retained mission approver is not this Person Server")
	}
	if record.State == MissionTerminated {
		return MissionRecord{}, &MissionTerminatedError{TerminationReason: record.TerminationReason}
	}
	if !record.ExpiresAt.IsZero() && !at.Before(record.ExpiresAt) {
		return MissionRecord{}, errors.New("personserver: mission audit store returned an unmaterialized expiry")
	}
	return record, nil
}

func validateMissionAuditRecord(record MissionAuditRecord) error {
	if record.RecordedAt.IsZero() || len(record.Document.ExactJSON) == 0 {
		return ErrMissionConflict
	}
	decoded, err := aauth.DecodeAudit(record.Document.ExactJSON)
	if err != nil || !equalAuditDocument(decoded, record.Document) {
		return ErrMissionConflict
	}
	return nil
}

func cloneMissionAuditRecord(record MissionAuditRecord) MissionAuditRecord {
	record.Document = cloneAuditDocument(record.Document)
	return record
}

func cloneAuditDocument(document aauth.AuditDocument) aauth.AuditDocument {
	document.ExactJSON = append([]byte(nil), document.ExactJSON...)
	document.Entry.Parameters = append(json.RawMessage(nil), document.Entry.Parameters...)
	document.Entry.Result = append(json.RawMessage(nil), document.Entry.Result...)
	return document
}

func equalAuditDocument(left, right aauth.AuditDocument) bool {
	return bytes.Equal(left.ExactJSON, right.ExactJSON) && left.Entry.MissionS256 == right.Entry.MissionS256 &&
		left.Entry.Action == right.Entry.Action && left.Entry.Description == right.Entry.Description &&
		bytes.Equal(left.Entry.Parameters, right.Entry.Parameters) && bytes.Equal(left.Entry.Result, right.Entry.Result)
}
