package supervisionserver

import (
	"context"
	"errors"
	"net/http"
	"time"

	"gitlab.com/sidecat-dev/aauth-go/supervision"
)

var (
	// ErrNotFound reports that a store holds no record for the key asked.
	ErrNotFound = errors.New("supervisionserver: not found")
	// ErrConflict reports a store transition whose expected record is no
	// longer current, or a duplicate key on create.
	ErrConflict = errors.New("supervisionserver: conflicting state")
)

// Connection records that a Person Server speaks for Subject at this SS.
// Account is the host's own label for the person, set when the connection
// was accepted; the SS does not interpret it.
type Connection struct {
	PersonServer string
	Subject      string
	Tenant       string
	Account      string
	ConnectedAt  time.Time
}

// ConnectState is the state of a connect that waits for the person.
type ConnectState uint8

const (
	// ConnectWaiting means the person has not yet presented the code.
	ConnectWaiting ConnectState = iota + 1
	// ConnectVisited means the person presented the code, which is now
	// consumed, and the host has not yet recorded their answer.
	ConnectVisited
	// ConnectConfirmed means the person confirmed the Person Server.
	ConnectConfirmed
	// ConnectDeclined means the person refused the Person Server.
	ConnectDeclined
	// ConnectFailed means too many wrong codes were presented.
	ConnectFailed
)

// PendingConnect is a connect waiting for the person to confirm the Person
// Server at the interaction URL. ID is both the pending URL segment the
// Person Server polls and the segment of the interaction URL the person
// visits. Code is the correlation code; it is not authority. ID,
// PersonServer, Subject, Tenant, URL, Code, CreatedAt, ExpiresAt and
// RetryAfter never change after creation. Revision starts at one and each
// replacement increments it.
type PendingConnect struct {
	ID             string
	PersonServer   string
	Subject        string
	Tenant         string
	URL            string
	Code           string
	State          ConnectState
	FailedAttempts int
	Account        string
	CreatedAt      time.Time
	ExpiresAt      time.Time
	RetryAfter     time.Duration
	Revision       uint64
}

// Live reports whether the connect still waits for the person at now.
func (pending PendingConnect) Live(now time.Time) bool {
	return (pending.State == ConnectWaiting || pending.State == ConnectVisited) && now.Before(pending.ExpiresAt)
}

// ConnectionStore owns connections and the connects that wait for a person.
//
// LoadConnection returns ErrNotFound for an unconnected pair. PutConnection
// records or replaces the connection for its (PersonServer, Subject), and
// DeleteConnection removes it; deleting an absent pair is not an error.
//
// CreatePendingConnect atomically creates the record unless a connect for the
// same (PersonServer, Subject) is still live at now; it then returns that one
// instead and creates nothing. A duplicate ID is ErrConflict. LoadPendingConnect
// returns ErrNotFound for an unknown ID. ReplacePendingConnect atomically
// compares the stored record's Revision with before's, requires after to keep
// the immutable fields and carry the next revision, and returns ErrConflict
// otherwise. When connection is non-nil it is recorded in the same transition.
type ConnectionStore interface {
	LoadConnection(ctx context.Context, personServer, subject string) (Connection, error)
	PutConnection(ctx context.Context, connection Connection) error
	DeleteConnection(ctx context.Context, personServer, subject string) error
	CreatePendingConnect(ctx context.Context, pending PendingConnect, now time.Time) (PendingConnect, error)
	LoadPendingConnect(ctx context.Context, id string) (PendingConnect, error)
	ReplacePendingConnect(ctx context.Context, before, after PendingConnect, connection *Connection) error
}

// MissionRecord is one approved mission the Person Server reported, with the
// exact blob every later mission_s256 refers to. Terminated is set when the
// Person Server reports the mission ended.
type MissionRecord struct {
	PersonServer string
	Subject      string
	Agent        string
	S256         string
	Blob         []byte
	SDI          string
	ApprovedAt   time.Time
	Terminated   bool
	Reason       string
	TerminatedAt time.Time
}

// Clone returns an independent copy.
func (mission MissionRecord) Clone() MissionRecord {
	mission.Blob = append([]byte(nil), mission.Blob...)
	return mission
}

// MissionStore owns approved mission blobs, keyed by (PersonServer, Subject,
// S256). PutMission records a mission unless one is held for its key, in
// which case it changes nothing; the digest fixes the blob. LoadMission
// returns ErrNotFound for an unknown key. TerminateMission marks a held
// mission ended and changes nothing when it already is; an unknown key is
// ErrNotFound. Every value crossing the boundary is an independent copy.
type MissionStore interface {
	PutMission(ctx context.Context, mission MissionRecord) error
	LoadMission(ctx context.Context, personServer, subject, s256 string) (MissionRecord, error)
	TerminateMission(ctx context.Context, personServer, subject, s256, reason string, at time.Time) error
}

// DecisionState is the state of one supervision request.
type DecisionState uint8

const (
	// DecisionDeciding means the request was deferred and the host has not
	// yet resolved it.
	DecisionDeciding DecisionState = iota + 1
	// DecisionClarifying means the SS asked the Agent a question and waits
	// for the answer.
	DecisionClarifying
	// DecisionDecided means the SS gave a terminal decision.
	DecisionDecided
	// DecisionCancelled means the Person Server withdrew the request.
	DecisionCancelled
)

// ClarificationRound is one question the SS asked the Agent and the answer
// the Person Server relayed: a Markdown answer, or for an auth-token request
// an Updated request whose tokens replace the retained ones.
type ClarificationRound struct {
	Question   supervision.Clarification
	Answer     string
	Updated    *supervision.UpdatedRequest
	AnsweredAt time.Time
}

// RetainedResponse is one exact signed terminal response, kept so that a
// repeat of the same request gets the same bytes. Binding names what the
// signature binds the response to: the request's authority, path and
// Content-Digest.
type RetainedResponse struct {
	Binding string
	Header  http.Header
	Body    []byte
}

// DecisionRecord is one supervision request under (PersonServer, SDI).
//
// Request is the exact body of the first request. Pending is the pending URL
// segment of a request that went pending, and is empty for one answered at
// once. Decision is the exact decision body once State is DecisionDecided;
// every response to the request carries those bytes. Responses holds the
// signed responses already given, one per binding, when the SS signs.
// ExpiresAt is the deadline while the request is deciding or clarifying.
// RetainUntil is the earliest time a store may discard a decided or
// cancelled record: no earlier than the exp of any token the decision could
// have allowed.
//
// PersonServer, SDI, Kind, Subject, Agent, MissionS256, Request, Pending and
// CreatedAt never change after creation. Revision starts at one and each
// replacement increments it.
type DecisionRecord struct {
	PersonServer  string
	SDI           string
	Kind          supervision.Kind
	Subject       string
	Agent         string
	MissionS256   string
	Request       []byte
	Pending       string
	State         DecisionState
	Clarification *supervision.Clarification
	Rounds        []ClarificationRound
	Decision      []byte
	Responses     []RetainedResponse
	CreatedAt     time.Time
	ExpiresAt     time.Time
	RetryAfter    time.Duration
	DecidedAt     time.Time
	RetainUntil   time.Time
	Revision      uint64
}

// Clone returns an independent copy.
func (record DecisionRecord) Clone() DecisionRecord {
	record.Request = append([]byte(nil), record.Request...)
	if record.Clarification != nil {
		question := cloneClarification(*record.Clarification)
		record.Clarification = &question
	}
	if record.Rounds != nil {
		rounds := make([]ClarificationRound, len(record.Rounds))
		for index, round := range record.Rounds {
			round.Question = cloneClarification(round.Question)
			if round.Updated != nil {
				updated := *round.Updated
				round.Updated = &updated
			}
			rounds[index] = round
		}
		record.Rounds = rounds
	}
	if record.Decision != nil {
		record.Decision = append([]byte(nil), record.Decision...)
	}
	if record.Responses != nil {
		responses := make([]RetainedResponse, len(record.Responses))
		for index, response := range record.Responses {
			response.Header = response.Header.Clone()
			response.Body = append([]byte(nil), response.Body...)
			responses[index] = response
		}
		record.Responses = responses
	}
	return record
}

func cloneClarification(clarification supervision.Clarification) supervision.Clarification {
	if clarification.Options != nil {
		clarification.Options = append([]string(nil), clarification.Options...)
	}
	return clarification
}

// DecisionStore owns supervision requests and their answers.
//
// CreateDecision atomically creates the record unless one exists for the same
// (PersonServer, SDI). It returns the canonical record and whether this call
// created it; a caller that did not create it answers from the returned
// record. A record whose Pending segment is already in use is ErrConflict.
// LoadDecision and LoadPendingDecision return ErrNotFound for an unknown key.
// ReplaceDecision atomically compares the stored record's Revision with
// before's, requires after to keep the immutable fields and carry the next
// revision, and returns ErrConflict otherwise. A store keeps a decided or
// cancelled record at least until its RetainUntil; a record still deciding or
// clarifying may be discarded once its ExpiresAt passes. Every value crossing
// the boundary is an independent copy.
type DecisionStore interface {
	CreateDecision(ctx context.Context, record DecisionRecord) (DecisionRecord, bool, error)
	LoadDecision(ctx context.Context, personServer, sdi string) (DecisionRecord, error)
	LoadPendingDecision(ctx context.Context, pending string) (DecisionRecord, error)
	ReplaceDecision(ctx context.Context, before, after DecisionRecord) error
}

// Delivery is one event or mission report the SS acknowledged, kept for
// deduplication on (PersonServer, ID). Body is the exact request body.
type Delivery struct {
	PersonServer string
	ID           string
	Body         []byte
	ReceivedAt   time.Time
}

// DeliveryStore deduplicates events and mission reports. LoadDelivery returns
// ErrNotFound for an unknown (PersonServer, ID). RecordDelivery atomically
// records one delivery and returns ErrConflict when its key is already
// recorded. Every value crossing the boundary is an independent copy.
type DeliveryStore interface {
	LoadDelivery(ctx context.Context, personServer, id string) (Delivery, error)
	RecordDelivery(ctx context.Context, delivery Delivery) error
}

// Store is the complete state of a supervision server. Each part owns its own
// atomic transitions; no transition spans two parts.
type Store interface {
	ConnectionStore
	MissionStore
	DecisionStore
	DeliveryStore
}
