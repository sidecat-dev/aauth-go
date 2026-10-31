package personserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/internal/interaction"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
	"gitlab.com/sidecat-dev/aauth-go/supervision"
)

// DefaultSupervisionPendingLifetime bounds an Agent's pending supervised
// request when SupervisionConfig.PendingLifetime is zero. The request also
// ends no later than the tokens it depends on.
const DefaultSupervisionPendingLifetime = 10 * time.Minute

// ErrSupervisionNotFound reports that a SupervisionStore holds no record for
// the key asked.
var ErrSupervisionNotFound = errors.New("personserver: supervision record not found")

// ErrSupervisionConflict reports a SupervisionStore transition whose expected
// record is no longer current, or a duplicate key on create.
var ErrSupervisionConflict = errors.New("personserver: supervision record conflicts with retained state")

// ErrSupervisionExpired reports a supervised request whose time ran out
// before the person answered.
var ErrSupervisionExpired = errors.New("personserver: supervised request expired")

// ErrSupervisionNotReady reports a host call on a supervised request that is
// not in the state the call needs: an advance that is premature or not
// waiting on the supervisor, or a resolution of a request not with the person.
var ErrSupervisionNotReady = errors.New("personserver: supervised request is not ready for this step")

// SupervisionConfig makes the Person Server consult a supervision server for
// the Agents the person routes to one (AAuth Supervision). For an Agent with a
// deciding supervisor the Person Server makes no supervision decision of its
// own: it puts every mission proposal, update and completion, and every
// person-token, auth-token and permission request, to that supervisor and
// relays, records and enforces the answer. The host policies that decide for
// other Agents (Authorize, Consent, Missions, Permission and the interaction
// selectors) are not called for a supervised Agent. BindPerson still resolves
// the person's directed identity for a Resource; it must not decide consent.
//
// An ask, and an act the supervisor could not be reached for, goes to the
// person: the Agent receives a pending response and the host, after
// authenticating the person, answers with ResolveSupervision. A supervisor
// that defers is polled by the host with AdvanceSupervision; the Agent's own
// polls only observe retained state.
type SupervisionConfig struct {
	// Route names the Agent's deciding supervisor and the person's directed
	// identifier for it, or reports false when the person supervises the
	// Agent themselves. The person may route all their Agents to one
	// supervisor and particular Agents to others.
	Route func(context.Context, SupervisedAgent) (Supervisor, bool, error)
	// Store retains connections, routing, the log, queued events and pending
	// supervised requests.
	Store SupervisionStore
	// HTTPClient and Admit carry every request to a supervisor. Admit decides
	// whether each metadata, endpoint and pending URL may be contacted. The
	// server uses a copy of HTTPClient that follows no redirect and sends no
	// cookies.
	HTTPClient *http.Client
	Admit      signaturekey.EgressAdmitter
	// Wait is sent as Prefer: wait on every supervision request. Zero
	// selects supervision.DefaultWait, the 30 seconds the draft recommends.
	Wait time.Duration
	// PendingLifetime bounds an Agent's pending supervised request. Zero
	// selects DefaultSupervisionPendingLifetime.
	PendingLifetime time.Duration
	// AllowUnsignedDecisions consults a supervisor that publishes no
	// jwks_uri. By default such a supervisor is treated as unavailable, so
	// every decision the Person Server acts on is one it can later show was
	// the supervisor's.
	AllowUnsignedDecisions bool
}

// SupervisedAgent is the verified Agent a route is chosen for.
type SupervisedAgent struct {
	AgentProvider    string
	Agent            string
	AdditionalClaims map[string]json.RawMessage
}

// Supervisor names one deciding supervision server for one person: its
// issuer, the directed identifier the Person Server derives for the person
// with that server as audience, and the tenant it asserts at connect, if any.
type Supervisor struct {
	Issuer  string
	Subject string
	Tenant  string
}

// SupervisorConnectionState is the Person Server's view of a connect.
type SupervisorConnectionState uint8

const (
	// SupervisorConnected means the supervisor accepts this Person Server for
	// the person.
	SupervisorConnected SupervisorConnectionState = iota + 1
	// SupervisorConnecting means the supervisor waits for the person to
	// confirm this Person Server at InteractionURL with InteractionCode.
	SupervisorConnecting
	// SupervisorRefused means the supervisor does not accept this Person
	// Server. Tell the person.
	SupervisorRefused
	// SupervisorDisconnected means the person removed the supervisor.
	SupervisorDisconnected
)

// SupervisorConnection is one connect at one supervisor. While Connecting the
// host directs the person to InteractionURL with InteractionCode and calls
// PollSupervisorConnect; Location is the supervisor's pending URL.
type SupervisorConnection struct {
	Supervisor      Supervisor
	State           SupervisorConnectionState
	InteractionURL  string
	InteractionCode string
	Location        string
	RetryAfter      time.Duration
	UpdatedAt       time.Time
}

// SupervisionLogEntry is the Person Server's record of one supervision
// request, retry, poll or clarification under an sdi, and of a decision the
// supervisor was not consulted for. Exchange is the request as signed and the
// response as received, or nil when the supervisor was not reached. Outcome
// names what the Person Server took from it: allow, deny, ask, pending,
// clarify, or unavailable.
type SupervisionLogEntry struct {
	SDI        string
	Kind       supervision.Kind
	Agent      string
	Supervisor Supervisor
	Exchange   *supervision.Exchange
	Outcome    string
	RecordedAt time.Time
}

// SupervisionNotice is one event or mission report for one supervisor. The
// store keeps it, in Sequence order per (Supervisor.Issuer,
// Supervisor.Subject), until it is delivered, and keeps every notice about an
// Agent as the history replay reads. A notice with a zero Supervisor is
// history only, recorded about an Agent no supervisor decides for: it is never
// pending, and replay gives a copy of it to a supervisor the Agent is routed
// to later. Body is the exact body for that supervisor. Report marks a
// mission report sent to {mission_endpoint}/{s256} rather than an event.
// ExpiresAt is the exp of the token an issued event names.
type SupervisionNotice struct {
	ID          string
	Supervisor  Supervisor
	Agent       string
	MissionS256 string
	Report      bool
	Name        string
	Body        []byte
	ExpiresAt   time.Time
	CreatedAt   time.Time
	Sequence    uint64
	Delivered   bool
}

// SupervisionStore retains the Person Server's supervision state. The Person
// Server's mission log is authoritative: replay gives a supervisor a copy of
// it, read from SupervisionHistory.
//
// LoadSupervisorConnection and LoadAgentSupervisor return
// ErrSupervisionNotFound for an unknown key. Save methods record or replace.
// AppendSupervisionNotices atomically appends notices in order and assigns
// each the next Sequence for its (issuer, subject); a notice whose ID is
// already queued undelivered for the same supervisor is skipped.
// PendingSupervisionNotices returns undelivered notices for one supervisor in
// Sequence order, at most limit. MarkSupervisionNoticeDelivered marks one
// delivered and is idempotent. SupervisionHistory returns every notice about
// an Agent, for any supervisor, in the order appended.
//
// RecordTokenAgent records which Agent presented an Agent token, until
// expiresAt; LoadTokenAgent returns it, or ErrSupervisionNotFound, so an
// Agent Provider's revocation of the token reaches that Agent's supervisor.
//
// CreateSupervisedRequest rejects a duplicate Reference with
// ErrSupervisionConflict. ReplaceSupervisedRequest atomically compares the
// stored Revision with before's, requires after to keep the immutable fields
// and carry the next Revision, and returns ErrSupervisionConflict otherwise.
// PendingSupervisedRequests lists requests waiting on the supervisor or the
// person, oldest first, at most limit. Every value crossing the boundary is an
// independent copy.
type SupervisionStore interface {
	LoadSupervisorConnection(ctx context.Context, issuer, subject string) (SupervisorConnection, error)
	SaveSupervisorConnection(ctx context.Context, connection SupervisorConnection) error
	LoadAgentSupervisor(ctx context.Context, agent string) (Supervisor, error)
	SaveAgentSupervisor(ctx context.Context, agent string, supervisor Supervisor) error
	RecordSupervisionLog(ctx context.Context, entry SupervisionLogEntry) error
	AppendSupervisionNotices(ctx context.Context, notices []SupervisionNotice) error
	PendingSupervisionNotices(ctx context.Context, issuer, subject string, limit int) ([]SupervisionNotice, error)
	MarkSupervisionNoticeDelivered(ctx context.Context, issuer, subject, id string) error
	SupervisionHistory(ctx context.Context, agent string) ([]SupervisionNotice, error)
	RecordTokenAgent(ctx context.Context, token aauth.TokenReference, agent string, expiresAt time.Time) error
	LoadTokenAgent(ctx context.Context, token aauth.TokenReference) (string, error)
	CreateSupervisedRequest(ctx context.Context, request SupervisedRequest) error
	LoadSupervisedRequest(ctx context.Context, reference string) (SupervisedRequest, error)
	ReplaceSupervisedRequest(ctx context.Context, before, after SupervisedRequest) error
	PendingSupervisedRequests(ctx context.Context, limit int) ([]SupervisedRequest, error)
}

const maximumNoticesPerDelivery = 64

type supervisionState struct {
	route           func(context.Context, SupervisedAgent) (Supervisor, bool, error)
	store           SupervisionStore
	client          *supervision.Client
	pendingLifetime time.Duration
	requireSigned   bool
}

func (server *Server) configureSupervision(config *SupervisionConfig) error {
	if config == nil {
		return nil
	}
	if config.Route == nil {
		return errors.New("personserver: supervision route is required")
	}
	if config.Store == nil {
		return errors.New("personserver: supervision store is required")
	}
	if config.PendingLifetime < 0 || config.PendingLifetime%time.Second != 0 {
		return errors.New("personserver: supervision pending lifetime must be whole nonnegative seconds")
	}
	client, err := supervision.NewClient(supervision.ClientConfig{
		PersonServer: server.issuer, SigningKey: server.signingKey, KeyResolver: server.keyResolver,
		HTTPClient: config.HTTPClient, Admit: config.Admit, Clock: server.clock, Wait: config.Wait,
	})
	if err != nil {
		return fmt.Errorf("personserver: supervision: %w", err)
	}
	lifetime := config.PendingLifetime
	if lifetime == 0 {
		lifetime = DefaultSupervisionPendingLifetime
	}
	server.supervision = &supervisionState{
		route: config.Route, store: config.Store, client: client,
		pendingLifetime: lifetime, requireSigned: !config.AllowUnsignedDecisions,
	}
	return nil
}

// routeAgent returns the Agent's deciding supervisor, or false when it has
// none or supervision is not configured.
func (server *Server) routeAgent(ctx context.Context, agent aauth.AgentTokenClaims) (Supervisor, bool, error) {
	if server.supervision == nil {
		return Supervisor{}, false, nil
	}
	supervisor, ok, err := server.supervision.route(ctx, SupervisedAgent{
		AgentProvider: agent.Issuer, Agent: agent.Subject, AdditionalClaims: cloneClaims(agent.AdditionalClaims),
	})
	if err != nil || !ok {
		return Supervisor{}, false, err
	}
	if err := aauth.ValidateServerIdentifier(supervisor.Issuer); err != nil {
		return Supervisor{}, false, fmt.Errorf("personserver: supervision route issuer: %w", err)
	}
	if supervisor.Subject == "" || len(supervisor.Subject) > 255 {
		return Supervisor{}, false, errors.New("personserver: supervision route requires the person's directed subject")
	}
	return supervisor, true, nil
}

// ConnectSupervisor connects the person to a supervisor, as when they register
// it. A supervisor that needs the person's confirmation answers with a
// connection in SupervisorConnecting: show the person InteractionURL and
// InteractionCode, then call PollSupervisorConnect.
func (server *Server) ConnectSupervisor(ctx context.Context, supervisor Supervisor) (SupervisorConnection, error) {
	if server.supervision == nil {
		return SupervisorConnection{}, errors.New("personserver: supervision is not configured")
	}
	return server.connectSupervisor(ctx, supervisor, supervision.ActionConnect)
}

// DisconnectSupervisor tells the supervisor the person removed it, or that no
// Agent of theirs is routed to it any more.
func (server *Server) DisconnectSupervisor(ctx context.Context, supervisor Supervisor) error {
	if server.supervision == nil {
		return errors.New("personserver: supervision is not configured")
	}
	connection, err := server.connectSupervisor(ctx, supervisor, supervision.ActionDisconnect)
	if err != nil {
		return err
	}
	if connection.State != SupervisorDisconnected {
		return errors.New("personserver: supervisor did not accept the disconnect")
	}
	return nil
}

// PollSupervisorConnect polls a connect that waits for the person, once.
func (server *Server) PollSupervisorConnect(ctx context.Context, supervisor Supervisor) (SupervisorConnection, error) {
	if server.supervision == nil {
		return SupervisorConnection{}, errors.New("personserver: supervision is not configured")
	}
	state := server.supervision
	connection, err := state.store.LoadSupervisorConnection(ctx, supervisor.Issuer, supervisor.Subject)
	if err != nil {
		return SupervisorConnection{}, err
	}
	if connection.State != SupervisorConnecting || connection.Location == "" {
		return connection, nil
	}
	outcome, err := state.client.PollConnect(ctx, supervisor.Issuer, connection.Location)
	if err != nil {
		return connection, err
	}
	return server.recordConnect(ctx, connection, outcome)
}

func (server *Server) connectSupervisor(ctx context.Context, supervisor Supervisor, action supervision.ConnectAction) (SupervisorConnection, error) {
	state := server.supervision
	id, err := mintSupervisionID("c-")
	if err != nil {
		return SupervisorConnection{}, err
	}
	outcome, err := state.client.Connect(ctx, supervisor.Issuer, supervision.ConnectRequest{
		Action: action, ID: id, IssuedAt: server.clock.Now().Unix(),
		Subject: supervisor.Subject, Tenant: supervisor.Tenant,
	})
	if err != nil {
		return SupervisorConnection{}, err
	}
	connection := SupervisorConnection{Supervisor: supervisor}
	if action == supervision.ActionDisconnect {
		if !outcome.Connected {
			return connection, fmt.Errorf("personserver: supervisor answered the disconnect with %s", describeProblem(outcome.Problem))
		}
		connection.State = SupervisorDisconnected
		connection.UpdatedAt = server.clock.Now().UTC()
		return connection, state.store.SaveSupervisorConnection(ctx, connection)
	}
	return server.recordConnect(ctx, connection, outcome)
}

func (server *Server) recordConnect(ctx context.Context, connection SupervisorConnection, outcome supervision.Outcome) (SupervisorConnection, error) {
	connection.UpdatedAt = server.clock.Now().UTC()
	switch {
	case outcome.Connected:
		connection.State = SupervisorConnected
		connection.InteractionURL, connection.InteractionCode, connection.Location, connection.RetryAfter = "", "", "", 0
	case outcome.Interaction != nil:
		connection.State = SupervisorConnecting
		connection.InteractionURL = outcome.Interaction.URL
		connection.InteractionCode = outcome.Interaction.Code
		connection.Location = outcome.Interaction.Location
		connection.RetryAfter = outcome.Interaction.RetryAfter
	case outcome.Pending != nil:
		connection.State = SupervisorConnecting
		connection.Location = outcome.Pending.Location
		connection.RetryAfter = outcome.Pending.RetryAfter
	case outcome.Problem != nil && outcome.Problem.Code == supervision.ErrorUnsupportedIss:
		connection.State = SupervisorRefused
	default:
		return connection, fmt.Errorf("personserver: supervisor answered the connect with %s", describeProblem(outcome.Problem))
	}
	if err := server.supervision.store.SaveSupervisorConnection(ctx, connection); err != nil {
		return connection, err
	}
	return connection, nil
}

// ensureConnected connects the person before anything is put to the
// supervisor. It reports false when the supervisor does not accept the
// Person Server for the person now.
func (server *Server) ensureConnected(ctx context.Context, supervisor Supervisor) bool {
	state := server.supervision
	connection, err := state.store.LoadSupervisorConnection(ctx, supervisor.Issuer, supervisor.Subject)
	if err == nil && connection.State == SupervisorConnected {
		return true
	}
	if err == nil && connection.State == SupervisorConnecting {
		connection, err = server.PollSupervisorConnect(ctx, supervisor)
		return err == nil && connection.State == SupervisorConnected
	}
	if err != nil && !errors.Is(err, ErrSupervisionNotFound) {
		return false
	}
	connection, err = server.connectSupervisor(ctx, supervisor, supervision.ActionConnect)
	return err == nil && connection.State == SupervisorConnected
}

func describeProblem(problem *supervision.Problem) string {
	if problem == nil {
		return "an unexpected answer"
	}
	return fmt.Sprintf("%d %s", problem.Status, problem.Code)
}

// mintSupervisionID returns a fresh, unguessable sdi or event id.
func mintSupervisionID(prefix string) (string, error) {
	reference, err := interaction.GeneratePendingReference(nil)
	if err != nil {
		return "", err
	}
	return prefix + reference, nil
}

// --- Events and reports -----------------------------------------------------

// historySubject stands in for sub in a notice recorded for history only;
// replay writes the subject directed to the supervisor it goes to.
const historySubject = "-"

func noticeSubject(supervisor Supervisor) string {
	if supervisor.Issuer == "" {
		return historySubject
	}
	return supervisor.Subject
}

// queueEvent queues one event for the supervisor, or with a zero Supervisor
// records it for history only. ExpiresAt is retained for replay of
// outstanding tokens.
func (server *Server) queueEvent(ctx context.Context, supervisor Supervisor, event supervision.Event) error {
	if event.ID == "" {
		id, err := mintSupervisionID("e-")
		if err != nil {
			return err
		}
		event.ID = id
	}
	if event.IssuedAt == 0 {
		event.IssuedAt = server.clock.Now().Unix()
	}
	event.Subject = noticeSubject(supervisor)
	body, err := event.Encode()
	if err != nil {
		return err
	}
	notice := SupervisionNotice{
		ID: event.ID, Supervisor: supervisor, Agent: event.Agent, MissionS256: event.MissionS256,
		Name: string(event.Name), Body: body, CreatedAt: server.clock.Now().UTC(),
	}
	if event.Name == supervision.EventPersonTokenIssued || event.Name == supervision.EventAuthTokenIssued {
		notice.ExpiresAt = time.Unix(event.ExpiresAt, 0).UTC()
	}
	return server.supervision.store.AppendSupervisionNotices(ctx, []SupervisionNotice{notice})
}

// queueReport queues one mission report for the supervisor.
func (server *Server) queueReport(ctx context.Context, supervisor Supervisor, report supervision.Report) error {
	if report.ID == "" {
		id, err := mintSupervisionID("e-")
		if err != nil {
			return err
		}
		report.ID = id
	}
	if report.IssuedAt == 0 {
		report.IssuedAt = server.clock.Now().Unix()
	}
	report.Subject = noticeSubject(supervisor)
	body, err := report.Encode()
	if err != nil {
		return err
	}
	return server.supervision.store.AppendSupervisionNotices(ctx, []SupervisionNotice{{
		ID: report.ID, Supervisor: supervisor, Agent: report.Agent, MissionS256: report.MissionS256,
		Report: true, Name: string(report.Action), Body: body, CreatedAt: server.clock.Now().UTC(),
	}})
}

// notifyAgent queues an event about an Agent that is not part of a supervised
// act, such as an audit record or a relayed interaction, for the Agent's
// deciding supervisor. It does nothing for an Agent without one. A failure is
// returned for the caller to report; it does not change the Agent's answer.
func (server *Server) notifyAgent(ctx context.Context, agent aauth.AgentTokenClaims, event supervision.Event) error {
	supervisor, routed, err := server.routeAgent(ctx, agent)
	if err != nil || !routed {
		return err
	}
	if err := server.followRoute(ctx, agent, supervisor); err != nil {
		return err
	}
	event.Agent = agent.Subject
	return server.queueEvent(ctx, supervisor, event)
}

// DeliverSupervisionEvents delivers the events and mission reports queued for
// one supervisor, in order, as when it is reachable again. It stops at the
// first one the supervisor does not accept, so later ones are not delivered
// out of order, and returns how many it delivered.
func (server *Server) DeliverSupervisionEvents(ctx context.Context, supervisor Supervisor) (int, error) {
	if server.supervision == nil {
		return 0, errors.New("personserver: supervision is not configured")
	}
	return server.deliverNotices(ctx, supervisor)
}

func (server *Server) deliverNotices(ctx context.Context, supervisor Supervisor) (int, error) {
	state := server.supervision
	delivered := 0
	reconnected := false
	replayed := map[string]bool{}
	for {
		notices, err := state.store.PendingSupervisionNotices(ctx, supervisor.Issuer, supervisor.Subject, maximumNoticesPerDelivery)
		if err != nil {
			return delivered, err
		}
		if len(notices) == 0 {
			return delivered, nil
		}
		for _, notice := range notices {
			outcome, err := server.postNotice(ctx, notice)
			if err != nil {
				return delivered, err
			}
			if outcome.Problem != nil {
				switch outcome.Problem.Code {
				case supervision.ErrorUnknownSub:
					if reconnected || !server.reconnect(ctx, supervisor) {
						return delivered, fmt.Errorf("personserver: supervisor does not know the person: %s", describeProblem(outcome.Problem))
					}
					reconnected = true
					outcome, err = server.postNotice(ctx, notice)
					if err != nil {
						return delivered, err
					}
				case supervision.ErrorUnknownMission:
					// An event about a mission the supervisor does not hold:
					// give it the mission first, then the event again.
					if notice.MissionS256 == "" || replayed[notice.MissionS256] ||
						server.sendApproved(ctx, notice.Agent, notice.MissionS256, supervisor) != nil {
						return delivered, fmt.Errorf("personserver: supervisor does not know the mission: %s", describeProblem(outcome.Problem))
					}
					replayed[notice.MissionS256] = true
					outcome, err = server.postNotice(ctx, notice)
					if err != nil {
						return delivered, err
					}
				case supervision.ErrorUnsupportedIss:
					server.forgetConnection(ctx, supervisor)
				case supervision.ErrorInvalidRequest:
					// A body the supervisor cannot read is a defect or a
					// version mismatch; retrying cannot help, and keeping it
					// would hold back every later notice.
					outcome = supervision.Outcome{Accepted: true}
				}
			}
			if !outcome.Accepted {
				return delivered, fmt.Errorf("personserver: supervisor did not accept %s: %s", notice.Name, describeProblem(outcome.Problem))
			}
			if err := state.store.MarkSupervisionNoticeDelivered(ctx, supervisor.Issuer, supervisor.Subject, notice.ID); err != nil {
				return delivered, err
			}
			delivered++
		}
	}
}

func (server *Server) postNotice(ctx context.Context, notice SupervisionNotice) (supervision.Outcome, error) {
	client := server.supervision.client
	if notice.Report {
		report, err := decodeQueuedReport(notice)
		if err != nil {
			return supervision.Outcome{}, err
		}
		return client.PostReport(ctx, notice.Supervisor.Issuer, report)
	}
	event, err := supervision.DecodeEvent(notice.Body)
	if err != nil {
		return supervision.Outcome{}, err
	}
	return client.PostEvent(ctx, notice.Supervisor.Issuer, event)
}

func decodeQueuedReport(notice SupervisionNotice) (supervision.Report, error) {
	_, report, err := supervision.DecodeMissionAction(notice.MissionS256, notice.Body)
	if err != nil {
		return supervision.Report{}, err
	}
	if report == nil {
		return supervision.Report{}, errors.New("personserver: queued report is not a mission report")
	}
	return *report, nil
}

// sendApproved posts a mission's approved report to the supervisor at once:
// the one recorded for it, under its own id, or one built from the mission
// store under a fresh sdi for a mission approved before any was recorded.
func (server *Server) sendApproved(ctx context.Context, agent, s256 string, supervisor Supervisor) error {
	report, err := server.approvedReport(ctx, agent, s256)
	if err != nil {
		return err
	}
	report.Subject = supervisor.Subject
	outcome, err := server.supervision.client.PostReport(ctx, supervisor.Issuer, report)
	if err != nil {
		return err
	}
	if !outcome.Accepted {
		return fmt.Errorf("personserver: supervisor did not accept the mission: %s", describeProblem(outcome.Problem))
	}
	return nil
}

func (server *Server) approvedReport(ctx context.Context, agent, s256 string) (supervision.Report, error) {
	history, err := server.supervision.store.SupervisionHistory(ctx, agent)
	if err != nil {
		return supervision.Report{}, err
	}
	for _, notice := range history {
		if notice.Report && notice.Name == string(supervision.ReportApproved) && notice.MissionS256 == s256 {
			return decodeQueuedReport(notice)
		}
	}
	if server.missions == nil {
		return supervision.Report{}, ErrMissionNotFound
	}
	mission, err := server.missions.LoadMissionForAgent(ctx, agent, s256, server.clock.Now().UTC())
	if err != nil {
		return supervision.Report{}, err
	}
	id, err := mintSupervisionID("e-")
	if err != nil {
		return supervision.Report{}, err
	}
	sdi, err := mintSupervisionID("d-")
	if err != nil {
		return supervision.Report{}, err
	}
	return supervision.Report{
		Action: supervision.ReportApproved, ID: id, SDI: sdi, Agent: agent, MissionS256: s256,
		Mission: append([]byte(nil), mission.ExactJSON...), IssuedAt: mission.ApprovedAt.Unix(),
	}, nil
}

// forgetConnection drops a connection the supervisor no longer accepts, so
// the next act connects again; until it accepts, it is unavailable.
func (server *Server) forgetConnection(ctx context.Context, supervisor Supervisor) {
	_ = server.supervision.store.SaveSupervisorConnection(ctx, SupervisorConnection{
		Supervisor: supervisor, State: SupervisorRefused, UpdatedAt: server.clock.Now().UTC(),
	})
}

// reconnect connects again after a supervisor answered unknown_sub.
func (server *Server) reconnect(ctx context.Context, supervisor Supervisor) bool {
	connection, err := server.connectSupervisor(ctx, supervisor, supervision.ActionConnect)
	return err == nil && connection.State == SupervisorConnected
}

// reportMissionEnded tells the supervisor deciding for a mission's Agent that
// the mission ended, when the Person Server finds it terminated: expired, or
// ended for any other reason. A mission whose end was already reported, as a
// completion is when it is accepted, is not reported again. The end of a
// mission no supervisor decided for is recorded for replay.
func (server *Server) reportMissionEnded(ctx context.Context, mission MissionRecord) {
	if server.supervision == nil || mission.TerminationReason == "" {
		return
	}
	supervisor, err := server.supervision.store.LoadAgentSupervisor(ctx, mission.Agent)
	if err != nil && !errors.Is(err, ErrSupervisionNotFound) {
		return
	}
	history, err := server.supervision.store.SupervisionHistory(ctx, mission.Agent)
	if err != nil {
		return
	}
	for _, notice := range history {
		if notice.Report && notice.Name == string(supervision.ReportTerminated) && notice.MissionS256 == mission.S256 {
			return
		}
	}
	_ = server.queueReport(ctx, supervisor, supervision.Report{
		Action: supervision.ReportTerminated, Agent: mission.Agent,
		MissionS256: mission.S256, Reason: mission.TerminationReason,
	})
}

// reportAgentTokenRevocation tells the supervisor deciding for the Agent an
// Agent Provider revoked a token of that the Person Server received the
// revocation. The supervisor has no part in the cascade.
func (server *Server) reportAgentTokenRevocation(ctx context.Context, revocation aauth.RevocationRequest) {
	if server.supervision == nil {
		return
	}
	state := server.supervision
	agent, err := state.store.LoadTokenAgent(ctx, revocation.Reference)
	if err != nil {
		return
	}
	supervisor, err := state.store.LoadAgentSupervisor(ctx, agent)
	if err != nil {
		return
	}
	_ = server.queueEvent(ctx, supervisor, supervision.Event{
		Name: supervision.EventRevocationReceived, Agent: agent, TokenType: "agent_token",
		TokenIssuer: revocation.Reference.Issuer, JTI: revocation.Reference.JTI,
		ExpiresAt: revocation.ExpiresAt.Unix(),
	})
}

// --- Routing changes and replay ---------------------------------------------

// followRoute records the supervisor deciding for an Agent. The first time an
// Agent is routed, and when the person changed its deciding supervisor, it
// replays the Agent's active state to that supervisor, beginning with
// agent.bound, before anything new is put to it (Replay and Recovery).
func (server *Server) followRoute(ctx context.Context, agent aauth.AgentTokenClaims, supervisor Supervisor) error {
	state := server.supervision
	// The Agent token is indexed so that its revocation reaches the
	// supervisor.
	if err := state.store.RecordTokenAgent(ctx, aauth.TokenReference{Issuer: agent.Issuer, JTI: agent.JTI},
		agent.Subject, time.Unix(agent.ExpiresAt, 0).UTC()); err != nil {
		return err
	}
	previous, err := state.store.LoadAgentSupervisor(ctx, agent.Subject)
	switch {
	case err == nil && previous == supervisor:
		return nil
	case err == nil, errors.Is(err, ErrSupervisionNotFound):
		// A first route replays what the Person Server recorded before the
		// Agent was supervised; a changed one, what the last supervisor knew.
		if err := server.replayAgent(ctx, agent, supervisor); err != nil {
			return err
		}
	default:
		return err
	}
	return state.store.SaveAgentSupervisor(ctx, agent.Subject, supervisor)
}

// replayAgent gives a newly deciding supervisor a copy of the Agent's active
// state from the Person Server's record, in the order it was recorded:
// agent.bound; for each mission not reported terminated, the approved report
// and the mission's events; and the issued events of tokens still
// outstanding. Each replayed notice keeps the id it had.
func (server *Server) replayAgent(ctx context.Context, agent aauth.AgentTokenClaims, supervisor Supervisor) error {
	history, err := server.supervision.store.SupervisionHistory(ctx, agent.Subject)
	if err != nil {
		return err
	}
	history = distinctNotices(history)
	terminated := map[string]bool{}
	approved := map[string]bool{}
	for _, notice := range history {
		if notice.Report && notice.Name == string(supervision.ReportTerminated) {
			terminated[notice.MissionS256] = true
		}
		if notice.Report && notice.Name == string(supervision.ReportApproved) {
			approved[notice.MissionS256] = true
		}
	}
	now := server.clock.Now()
	var replay []SupervisionNotice
	bound := false
	for _, notice := range history {
		if notice.Name == string(supervision.EventAgentBound) && !bound {
			replay = append(replay, notice)
			bound = true
		}
	}
	if !bound {
		if err := server.queueEvent(ctx, supervisor, supervision.Event{
			Name: supervision.EventAgentBound, Agent: agent.Subject,
			AgentIssuer: agent.Issuer, AgentSubject: agent.Subject,
		}); err != nil {
			return err
		}
	}
	for _, notice := range history {
		active := notice.MissionS256 != "" && approved[notice.MissionS256] && !terminated[notice.MissionS256]
		outstanding := !notice.ExpiresAt.IsZero() && now.Before(notice.ExpiresAt)
		if notice.Name == string(supervision.EventAgentBound) {
			continue
		}
		if active || outstanding {
			replay = append(replay, notice)
		}
	}
	return server.requeue(ctx, supervisor, replay)
}

// replayMission gives the supervisor a copy of one mission it does not know,
// after it answered unknown_mission: the approved report, then the mission's
// events in order. A mission approved before the Person Server kept a record
// of reporting it is rebuilt from the mission store under a fresh sdi.
func (server *Server) replayMission(ctx context.Context, agent string, s256 string, supervisor Supervisor) error {
	history, err := server.supervision.store.SupervisionHistory(ctx, agent)
	if err != nil {
		return err
	}
	var replay []SupervisionNotice
	approvedSeen := false
	for _, notice := range distinctNotices(history) {
		if notice.MissionS256 != s256 {
			continue
		}
		if notice.Report && notice.Name == string(supervision.ReportApproved) {
			approvedSeen = true
		}
		replay = append(replay, notice)
	}
	if !approvedSeen {
		report, err := server.approvedReport(ctx, agent, s256)
		if err != nil {
			return err
		}
		if err := server.queueReport(ctx, supervisor, report); err != nil {
			return err
		}
	}
	return server.requeue(ctx, supervisor, replay)
}

// requeue queues retained notices for another supervisor under their own ids,
// rewriting only the directed subject.
func (server *Server) requeue(ctx context.Context, supervisor Supervisor, notices []SupervisionNotice) error {
	if len(notices) == 0 {
		return nil
	}
	copies := make([]SupervisionNotice, 0, len(notices))
	for _, notice := range notices {
		body, err := rewriteSubject(notice, supervisor.Subject)
		if err != nil {
			return err
		}
		copies = append(copies, SupervisionNotice{
			ID: notice.ID, Supervisor: supervisor, Agent: notice.Agent, MissionS256: notice.MissionS256,
			Report: notice.Report, Name: notice.Name, Body: body, ExpiresAt: notice.ExpiresAt,
			CreatedAt: server.clock.Now().UTC(),
		})
	}
	return server.supervision.store.AppendSupervisionNotices(ctx, copies)
}

func rewriteSubject(notice SupervisionNotice, subject string) ([]byte, error) {
	if notice.Report {
		report, err := decodeQueuedReport(notice)
		if err != nil {
			return nil, err
		}
		report.Subject = subject
		return report.Encode()
	}
	event, err := supervision.DecodeEvent(notice.Body)
	if err != nil {
		return nil, err
	}
	event.Subject = subject
	return event.Encode()
}

// distinctNotices keeps the first notice for each id: a notice replayed to
// several supervisors appears once per supervisor in the history.
func distinctNotices(notices []SupervisionNotice) []SupervisionNotice {
	seen := make(map[string]bool, len(notices))
	distinct := notices[:0:0]
	for _, notice := range notices {
		if seen[notice.ID] {
			continue
		}
		seen[notice.ID] = true
		distinct = append(distinct, notice)
	}
	return distinct
}
