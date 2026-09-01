// Package exampleutil contains small in-memory role stores shared by runnable
// examples. They demonstrate interface semantics, not production persistence.
package exampleutil

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"sync"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/personserver"
	"gitlab.com/sidecat-dev/aauth-go/r3"
)

// NewMissionStore returns the concurrency-safe in-memory Person Server store
// used by the mission examples. It demonstrates interface semantics, not
// production persistence.
func NewMissionStore() personserver.MissionAuditStore {
	return newMissionStore()
}

// NewMissionPermissionStore returns one in-memory transaction boundary for
// mission lifecycle, mission-bound tokens, and permission state.
func NewMissionPermissionStore() personserver.MissionPermissionStore {
	return newMissionStore()
}

func newMissionStore() *missionStore {
	return &missionStore{
		missions:    make(map[string]personserver.MissionRecord),
		tokens:      make(map[string]personserver.PersonTokenRecord),
		auth:        make(map[string]personserver.IssuedAuthTokenRecord),
		r3Issuances: make(map[aauth.TokenReference]r3.IssuanceRecord),
		audits:      make(map[string][]personserver.MissionAuditRecord),
		permissions: make(map[string]personserver.PermissionRecord),
		proposals:   make(map[string]personserver.MissionProposalSnapshot),
	}
}

type missionStore struct {
	mu          sync.Mutex
	missions    map[string]personserver.MissionRecord
	tokens      map[string]personserver.PersonTokenRecord
	auth        map[string]personserver.IssuedAuthTokenRecord
	r3Issuances map[aauth.TokenReference]r3.IssuanceRecord
	audits      map[string][]personserver.MissionAuditRecord
	permissions map[string]personserver.PermissionRecord
	proposals   map[string]personserver.MissionProposalSnapshot
}

var _ personserver.MissionAuditStore = (*missionStore)(nil)
var _ personserver.MissionPermissionStore = (*missionStore)(nil)
var _ personserver.MissionProposalStore = (*missionStore)(nil)
var _ personserver.MissionR3IssuanceStore = (*missionStore)(nil)

func (store *missionStore) CreateMissionProposal(
	_ context.Context,
	record personserver.MissionProposalRecord,
) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if _, exists := store.proposals[record.ID]; exists {
		return personserver.ErrMissionProposalConflict
	}
	store.proposals[record.ID] = (personserver.MissionProposalSnapshot{
		Record: record, State: personserver.MissionProposalPending,
	}).Clone()
	return nil
}

func (store *missionStore) LoadMissionProposal(
	_ context.Context,
	reference string,
	at time.Time,
) (personserver.MissionProposalSnapshot, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	snapshot, ok := store.proposals[reference]
	if !ok {
		return personserver.MissionProposalSnapshot{}, personserver.ErrMissionProposalNotFound
	}
	if materializeMissionProposalExpiry(&snapshot, at) {
		store.proposals[reference] = snapshot.Clone()
	}
	return snapshot.Clone(), nil
}

func (store *missionStore) ListPendingMissionProposals(
	_ context.Context,
	at time.Time,
	limit int,
) ([]personserver.MissionProposalRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	records := make([]personserver.MissionProposalRecord, 0, len(store.proposals))
	for reference, snapshot := range store.proposals {
		if materializeMissionProposalExpiry(&snapshot, at) {
			store.proposals[reference] = snapshot.Clone()
		}
		if snapshot.State == personserver.MissionProposalPending {
			records = append(records, snapshot.Record.Clone())
		}
	}
	sort.Slice(records, func(left, right int) bool {
		if records[left].CreatedAt.Equal(records[right].CreatedAt) {
			return records[left].ID < records[right].ID
		}
		return records[left].CreatedAt.Before(records[right].CreatedAt)
	})
	if len(records) > limit {
		records = records[:limit]
	}
	return records, nil
}

func (store *missionStore) ApproveMissionProposal(
	_ context.Context,
	expected personserver.MissionProposalRecord,
	approval personserver.MissionProposalApproval,
	at time.Time,
) (personserver.MissionProposalApproval, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	snapshot, ok := store.proposals[expected.ID]
	if !ok || !snapshot.Record.Equal(expected) {
		return personserver.MissionProposalApproval{}, personserver.ErrMissionProposalConflict
	}
	if materializeMissionProposalExpiry(&snapshot, at) {
		store.proposals[expected.ID] = snapshot.Clone()
	}
	if snapshot.State == personserver.MissionProposalApproved {
		if snapshot.Approval.Equivalent(approval) {
			return snapshot.Approval.Clone(), nil
		}
		return personserver.MissionProposalApproval{}, personserver.ErrMissionProposalConflict
	}
	if snapshot.State == personserver.MissionProposalExpired || !at.Before(snapshot.Record.ExpiresAt) {
		return personserver.MissionProposalApproval{}, personserver.ErrMissionProposalExpired
	}
	if snapshot.State != personserver.MissionProposalPending {
		return personserver.MissionProposalApproval{}, personserver.ErrMissionProposalConflict
	}
	missionKey := approval.Mission.Agent + "\x00" + approval.Mission.S256
	if _, exists := store.missions[missionKey]; exists {
		return personserver.MissionProposalApproval{}, personserver.ErrMissionProposalConflict
	}
	batch := make(map[string]struct{}, len(approval.PersonTokenRecords))
	for _, token := range approval.PersonTokenRecords {
		key := token.PersonServer + "\x00" + token.JTI
		if _, exists := store.tokens[key]; exists {
			return personserver.MissionProposalApproval{}, personserver.ErrMissionProposalConflict
		}
		if _, duplicate := batch[key]; duplicate {
			return personserver.MissionProposalApproval{}, personserver.ErrMissionProposalConflict
		}
		batch[key] = struct{}{}
	}
	store.missions[missionKey] = cloneMissionRecord(approval.Mission)
	for _, token := range approval.PersonTokenRecords {
		store.tokens[token.PersonServer+"\x00"+token.JTI] = token
	}
	snapshot.State = personserver.MissionProposalApproved
	snapshot.Approval = approval.Clone()
	snapshot.DecidedAt = at
	store.proposals[expected.ID] = snapshot.Clone()
	return snapshot.Approval.Clone(), nil
}

func (store *missionStore) DenyMissionProposal(
	_ context.Context,
	expected personserver.MissionProposalRecord,
	at time.Time,
) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	snapshot, ok := store.proposals[expected.ID]
	if !ok || !snapshot.Record.Equal(expected) {
		return personserver.ErrMissionProposalConflict
	}
	if materializeMissionProposalExpiry(&snapshot, at) {
		store.proposals[expected.ID] = snapshot.Clone()
	}
	if snapshot.State == personserver.MissionProposalDenied {
		return nil
	}
	if snapshot.State == personserver.MissionProposalExpired || !at.Before(snapshot.Record.ExpiresAt) {
		return personserver.ErrMissionProposalExpired
	}
	if snapshot.State != personserver.MissionProposalPending {
		return personserver.ErrMissionProposalConflict
	}
	snapshot.State = personserver.MissionProposalDenied
	snapshot.DecidedAt = at
	store.proposals[expected.ID] = snapshot.Clone()
	return nil
}

func (store *missionStore) PollMissionProposal(
	_ context.Context,
	reference string,
	identity personserver.MissionProposalPollIdentity,
	at time.Time,
) (personserver.MissionProposalSnapshot, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	snapshot, ok := store.proposals[reference]
	if !ok {
		return personserver.MissionProposalSnapshot{}, personserver.ErrMissionProposalNotFound
	}
	thumbprint, err := snapshot.Record.Confirmation.Thumbprint()
	if err != nil || snapshot.Record.PersonServer != identity.PersonServer ||
		snapshot.Record.AgentProvider != identity.AgentProvider || snapshot.Record.Agent != identity.Agent ||
		thumbprint != identity.ConfirmationThumbprint {
		return personserver.MissionProposalSnapshot{}, personserver.ErrMissionProposalNotFound
	}
	if !snapshot.DeliveredAt.IsZero() {
		return personserver.MissionProposalSnapshot{}, personserver.ErrMissionProposalGone
	}
	materializeMissionProposalExpiry(&snapshot, at)
	if snapshot.State != personserver.MissionProposalPending {
		snapshot.DeliveredAt = at
	}
	store.proposals[reference] = snapshot.Clone()
	return snapshot.Clone(), nil
}

func materializeMissionProposalExpiry(snapshot *personserver.MissionProposalSnapshot, at time.Time) bool {
	if snapshot == nil {
		return false
	}
	switch {
	case (snapshot.State == personserver.MissionProposalPending || snapshot.State == personserver.MissionProposalApproved) &&
		!at.Before(snapshot.Record.ExpiresAt):
		wasPending := snapshot.State == personserver.MissionProposalPending
		snapshot.State = personserver.MissionProposalExpired
		snapshot.Approval = personserver.MissionProposalApproval{}
		if wasPending {
			snapshot.DecidedAt = at
		}
		return true
	case snapshot.State == personserver.MissionProposalApproved && snapshot.Approval.Expired(at):
		snapshot.State = personserver.MissionProposalExpired
		snapshot.Approval = personserver.MissionProposalApproval{}
		return true
	default:
		return false
	}
}

func (store *missionStore) Commit(_ context.Context, record personserver.PersonTokenRecord) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	key := record.PersonServer + "\x00" + record.JTI
	if _, exists := store.tokens[key]; exists {
		return errors.New("example mission store: person-token record already exists")
	}
	store.tokens[key] = record
	return nil
}

func (store *missionStore) Load(_ context.Context, issuer, jti string) (personserver.PersonTokenRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	record, ok := store.tokens[issuer+"\x00"+jti]
	if !ok {
		return personserver.PersonTokenRecord{}, personserver.ErrPersonTokenNotFound
	}
	return record, nil
}

func (store *missionStore) CommitMission(
	_ context.Context,
	mission personserver.MissionRecord,
	tokens []personserver.PersonTokenRecord,
) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	missionKey := mission.Agent + "\x00" + mission.S256
	if _, exists := store.missions[missionKey]; exists {
		return errors.New("example mission store: mission already exists")
	}
	batch := make(map[string]struct{}, len(tokens))
	for _, token := range tokens {
		key := token.PersonServer + "\x00" + token.JTI
		if _, exists := store.tokens[key]; exists {
			return errors.New("example mission store: person-token record already exists")
		}
		if _, duplicate := batch[key]; duplicate {
			return errors.New("example mission store: duplicate person-token identity")
		}
		batch[key] = struct{}{}
	}
	store.missions[missionKey] = cloneMissionRecord(mission)
	for _, token := range tokens {
		store.tokens[token.PersonServer+"\x00"+token.JTI] = token
	}
	return nil
}

func (store *missionStore) LoadMissionForAgent(
	_ context.Context,
	agent, s256 string,
	at time.Time,
) (personserver.MissionRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	key := agent + "\x00" + s256
	record, ok := store.missions[key]
	if !ok {
		return personserver.MissionRecord{}, personserver.ErrMissionNotFound
	}
	if record.State == personserver.MissionActive && !record.ExpiresAt.IsZero() && !at.Before(record.ExpiresAt) {
		record.State = personserver.MissionTerminated
		record.TerminationReason = "expired"
		store.missions[key] = cloneMissionRecord(record)
	}
	return cloneMissionRecord(record), nil
}

func (store *missionStore) AppendMissionUpdate(
	_ context.Context,
	expected personserver.MissionRecord,
	acceptedAt time.Time,
	document aauth.MissionUpdateDocument,
) (personserver.MissionRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if acceptedAt.IsZero() {
		return personserver.MissionRecord{}, errors.New("example mission store: acceptance time is required")
	}
	if err := store.requireActive(expected, acceptedAt); err != nil {
		return personserver.MissionRecord{}, err
	}
	key := expected.Agent + "\x00" + expected.S256
	current := store.missions[key]
	current.AcceptedUpdates = append(current.AcceptedUpdates, personserver.MissionUpdateRecord{
		Document: cloneUpdateDocument(document), AcceptedAt: acceptedAt,
	})
	store.missions[key] = cloneMissionRecord(current)
	return cloneMissionRecord(current), nil
}

func (store *missionStore) CompleteMission(
	_ context.Context,
	expected personserver.MissionRecord,
	acceptedAt time.Time,
	document aauth.MissionCompletionDocument,
) (personserver.MissionRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if acceptedAt.IsZero() {
		return personserver.MissionRecord{}, errors.New("example mission store: acceptance time is required")
	}
	if err := store.requireActive(expected, acceptedAt); err != nil {
		return personserver.MissionRecord{}, err
	}
	key := expected.Agent + "\x00" + expected.S256
	current := store.missions[key]
	current.State = personserver.MissionTerminated
	current.TerminationReason = "completed"
	current.Completion = &personserver.MissionCompletionRecord{
		Document: cloneCompletionDocument(document), AcceptedAt: acceptedAt,
	}
	store.missions[key] = cloneMissionRecord(current)
	return cloneMissionRecord(current), nil
}

func (store *missionStore) CommitMissionPersonToken(
	_ context.Context,
	expected personserver.MissionRecord,
	at time.Time,
	token personserver.PersonTokenRecord,
) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.requireActive(expected, at); err != nil {
		return err
	}
	if token.MissionS256 != expected.S256 || token.Agent != expected.Agent {
		return personserver.ErrMissionConflict
	}
	key := token.PersonServer + "\x00" + token.JTI
	if _, exists := store.tokens[key]; exists {
		return errors.New("example mission store: person-token record already exists")
	}
	store.tokens[key] = token
	return nil
}

func (store *missionStore) CommitMissionAuthToken(
	_ context.Context,
	expected personserver.MissionRecord,
	at time.Time,
	token personserver.IssuedAuthTokenRecord,
) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.requireActive(expected, at); err != nil {
		return err
	}
	if token.MissionS256 != expected.S256 {
		return personserver.ErrMissionConflict
	}
	key := token.Reference.Issuer + "\x00" + token.Reference.JTI
	if _, exists := store.auth[key]; exists {
		return errors.New("example mission store: auth-token record already exists")
	}
	store.auth[key] = token
	return nil
}

func (store *missionStore) CommitMissionR3AuthToken(
	_ context.Context,
	expected personserver.MissionRecord,
	at time.Time,
	token personserver.IssuedAuthTokenRecord,
	issuance r3.IssuanceRecord,
) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.requireActive(expected, at); err != nil {
		return err
	}
	if token.MissionS256 != expected.S256 || issuance.AuthTokenReference != token.Reference ||
		issuance.Resource != token.Resource || !issuance.IssuedAt.Equal(token.IssuedAt) ||
		issuance.PersonServer != token.Reference.Issuer || issuance.Agent != expected.Agent {
		return personserver.ErrMissionConflict
	}
	key := token.Reference.Issuer + "\x00" + token.Reference.JTI
	if _, exists := store.auth[key]; exists {
		return errors.New("example mission store: auth-token record already exists")
	}
	if _, exists := store.r3Issuances[issuance.AuthTokenReference]; exists {
		return r3.ErrIssuanceConflict
	}
	store.auth[key] = token
	store.r3Issuances[issuance.AuthTokenReference] = issuance.Clone()
	return nil
}

func (store *missionStore) AppendMissionAudit(
	_ context.Context,
	expected personserver.MissionRecord,
	record personserver.MissionAuditRecord,
) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if record.RecordedAt.IsZero() || record.Document.Entry.MissionS256 != expected.S256 {
		return personserver.ErrMissionConflict
	}
	decoded, err := aauth.DecodeAudit(record.Document.ExactJSON)
	if err != nil || !auditDocumentsEqual(decoded, record.Document) {
		return personserver.ErrMissionConflict
	}
	if err := store.requireActiveForAudit(expected, record.RecordedAt); err != nil {
		return err
	}
	key := expected.Agent + "\x00" + expected.S256
	store.audits[key] = append(store.audits[key], cloneMissionAuditRecord(record))
	return nil
}

func (store *missionStore) LoadMissionAuditsForAgent(
	_ context.Context,
	agent string,
	s256 string,
	at time.Time,
) ([]personserver.MissionAuditRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	key := agent + "\x00" + s256
	mission, ok := store.missions[key]
	if !ok {
		return nil, personserver.ErrMissionNotFound
	}
	if mission.State == personserver.MissionActive && !mission.ExpiresAt.IsZero() && !at.Before(mission.ExpiresAt) {
		mission.State = personserver.MissionTerminated
		mission.TerminationReason = "expired"
		store.missions[key] = cloneMissionRecord(mission)
	}
	records := store.audits[key]
	cloned := make([]personserver.MissionAuditRecord, len(records))
	for index := range records {
		cloned[index] = cloneMissionAuditRecord(records[index])
	}
	return cloned, nil
}

func (store *missionStore) CreatePermission(_ context.Context, record personserver.PermissionRecord) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	return createPermissionRecord(store.permissions, record)
}

func (store *missionStore) LoadPermission(
	_ context.Context,
	id string,
	at time.Time,
) (personserver.PermissionRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	return loadPermissionRecord(store.permissions, id, at)
}

func (store *missionStore) DecidePermission(
	_ context.Context,
	id string,
	decision personserver.PermissionDecision,
	at time.Time,
) (personserver.PermissionRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	return decidePermissionRecord(store.permissions, id, decision, at)
}

func (store *missionStore) PollPermission(
	_ context.Context,
	id string,
	identity personserver.PermissionPollIdentity,
	at time.Time,
) (personserver.PermissionRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	return pollPermissionRecord(store.permissions, id, identity, at)
}

func (store *missionStore) ConsumePermissionResult(
	_ context.Context,
	id string,
	expected personserver.PermissionRecord,
) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	return consumePermissionRecord(store.permissions, id, expected)
}

func (store *missionStore) CreateMissionPermission(
	_ context.Context,
	expected personserver.MissionRecord,
	record personserver.PermissionRecord,
	at time.Time,
) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.requireActive(expected, at); err != nil {
		return err
	}
	if record.MissionS256 != expected.S256 || record.Agent != expected.Agent {
		return personserver.ErrMissionConflict
	}
	return createPermissionRecord(store.permissions, record)
}

func (store *missionStore) DecideMissionPermission(
	_ context.Context,
	expected personserver.MissionRecord,
	id string,
	decision personserver.PermissionDecision,
	at time.Time,
) (personserver.PermissionRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.requireActive(expected, at); err != nil {
		return personserver.PermissionRecord{}, err
	}
	if err := store.requireMissionPermission(id, expected); err != nil {
		return personserver.PermissionRecord{}, err
	}
	return decidePermissionRecord(store.permissions, id, decision, at)
}

func (store *missionStore) PollMissionPermission(
	_ context.Context,
	expected personserver.MissionRecord,
	id string,
	identity personserver.PermissionPollIdentity,
	at time.Time,
) (personserver.PermissionRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.requireActive(expected, at); err != nil {
		return personserver.PermissionRecord{}, err
	}
	if err := store.requireMissionPermission(id, expected); err != nil {
		return personserver.PermissionRecord{}, err
	}
	return pollPermissionRecord(store.permissions, id, identity, at)
}

func (store *missionStore) ConsumeMissionPermissionResult(
	_ context.Context,
	expected personserver.MissionRecord,
	id string,
	record personserver.PermissionRecord,
	at time.Time,
) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.requireActive(expected, at); err != nil {
		return err
	}
	if err := store.requireMissionPermission(id, expected); err != nil {
		return err
	}
	return consumePermissionRecord(store.permissions, id, record)
}

func (store *missionStore) requireMissionPermission(id string, mission personserver.MissionRecord) error {
	record, ok := store.permissions[id]
	if !ok {
		return personserver.ErrPermissionNotFound
	}
	if record.MissionS256 != mission.S256 || record.Agent != mission.Agent {
		return personserver.ErrMissionConflict
	}
	return nil
}

func (store *missionStore) requireActive(expected personserver.MissionRecord, at time.Time) error {
	key := expected.Agent + "\x00" + expected.S256
	current, ok := store.missions[key]
	if !ok {
		return personserver.ErrMissionNotFound
	}
	if current.State == personserver.MissionActive && !current.ExpiresAt.IsZero() && !at.Before(current.ExpiresAt) {
		current.State = personserver.MissionTerminated
		current.TerminationReason = "expired"
		store.missions[key] = cloneMissionRecord(current)
	}
	if current.State == personserver.MissionTerminated {
		return &personserver.MissionTerminatedError{TerminationReason: current.TerminationReason}
	}
	if !current.Equal(expected) {
		return personserver.ErrMissionConflict
	}
	return nil
}

func (store *missionStore) requireActiveForAudit(expected personserver.MissionRecord, at time.Time) error {
	key := expected.Agent + "\x00" + expected.S256
	current, ok := store.missions[key]
	if !ok {
		return personserver.ErrMissionNotFound
	}
	if current.State == personserver.MissionActive && !current.ExpiresAt.IsZero() && !at.Before(current.ExpiresAt) {
		current.State = personserver.MissionTerminated
		current.TerminationReason = "expired"
		store.missions[key] = cloneMissionRecord(current)
	}
	if current.State == personserver.MissionTerminated {
		return &personserver.MissionTerminatedError{TerminationReason: current.TerminationReason}
	}
	// Core says accepted updates do not change the mission. An audit append
	// therefore compares stable identity and lifecycle state while permitting
	// updates that committed after the handler loaded its mission context.
	current.AcceptedUpdates = nil
	expected.AcceptedUpdates = nil
	if !current.Equal(expected) {
		return personserver.ErrMissionConflict
	}
	return nil
}

func cloneMissionRecord(record personserver.MissionRecord) personserver.MissionRecord {
	record.ExactJSON = append([]byte(nil), record.ExactJSON...)
	record.Capabilities = append([]string(nil), record.Capabilities...)
	record.AcceptedUpdates = append([]personserver.MissionUpdateRecord(nil), record.AcceptedUpdates...)
	for index := range record.AcceptedUpdates {
		record.AcceptedUpdates[index].Document = cloneUpdateDocument(record.AcceptedUpdates[index].Document)
	}
	if record.Completion != nil {
		completion := *record.Completion
		completion.Document = cloneCompletionDocument(completion.Document)
		record.Completion = &completion
	}
	return record
}

func cloneUpdateDocument(document aauth.MissionUpdateDocument) aauth.MissionUpdateDocument {
	document.ExactJSON = append([]byte(nil), document.ExactJSON...)
	return document
}

func cloneCompletionDocument(document aauth.MissionCompletionDocument) aauth.MissionCompletionDocument {
	document.ExactJSON = append([]byte(nil), document.ExactJSON...)
	return document
}

func cloneMissionAuditRecord(record personserver.MissionAuditRecord) personserver.MissionAuditRecord {
	record.Document.ExactJSON = append([]byte(nil), record.Document.ExactJSON...)
	record.Document.Entry.Parameters = append(json.RawMessage(nil), record.Document.Entry.Parameters...)
	record.Document.Entry.Result = append(json.RawMessage(nil), record.Document.Entry.Result...)
	return record
}

func auditDocumentsEqual(left, right aauth.AuditDocument) bool {
	return string(left.ExactJSON) == string(right.ExactJSON) &&
		left.Entry.MissionS256 == right.Entry.MissionS256 &&
		left.Entry.Action == right.Entry.Action &&
		left.Entry.Description == right.Entry.Description &&
		string(left.Entry.Parameters) == string(right.Entry.Parameters) &&
		string(left.Entry.Result) == string(right.Entry.Result)
}
