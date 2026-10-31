package supervision

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	aauth "gitlab.com/sidecat-dev/aauth-go"
)

// EventName is the event member of a body posted to event_endpoint.
type EventName string

const (
	EventPersonTokenIssued    EventName = "person_token.issued"
	EventAuthTokenIssued      EventName = "auth_token.issued"
	EventDecisionResolved     EventName = "decision.resolved"
	EventAuditRecorded        EventName = "audit.recorded"
	EventInteractionRequested EventName = "interaction.requested"
	EventAgentBound           EventName = "agent.bound"
	EventRevocationReceived   EventName = "revocation.received"
)

// Answer is what the person decided after an ask, or when the SS was
// unavailable.
type Answer string

const (
	AnswerAllow     Answer = "allow"
	AnswerDeny      Answer = "deny"
	AnswerAbandoned Answer = "abandoned"
)

// SupervisorUnavailable is the supervisor member of a decision.resolved event
// for an act the Person Server put to the person because it could not reach
// the SS.
const SupervisorUnavailable = "unavailable"

// TranscriptEntry is one message of the clarification chat between the
// person and the Agent at the Person Server.
type TranscriptEntry struct {
	From string `json:"from"`
	Text string `json:"text"`
}

// The two speakers of a transcript.
const (
	FromPerson = "person"
	FromAgent  = "agent"
)

// Event is one report posted to event_endpoint. The SS records it and
// answers 201; it does not decide it. The members other than the envelope
// depend on Name.
type Event struct {
	Name        EventName
	ID          string
	SDI         string
	IssuedAt    int64
	Subject     string
	Agent       string
	MissionS256 string

	// JTI, Audience and ExpiresAt name an issued token, or a revoked one.
	JTI       string
	Audience  string
	ExpiresAt int64
	// Scope and Issuer belong to auth_token.issued; Issuer is the Person
	// Server or the Access Server that issued the token.
	Scope  string
	Issuer string

	// Answer through Reason belong to decision.resolved.
	Answer         Answer
	Apply          string
	Recommendation Verdict
	Proposed       *MissionTerms
	Transcript     []TranscriptEntry
	Supervisor     string
	Reason         string

	// Action, Description, Parameters and Result belong to audit.recorded,
	// as the Agent sent them.
	Action      string
	Description string
	Parameters  json.RawMessage
	Result      json.RawMessage

	// Type and URL belong to interaction.requested. The interaction code is
	// never forwarded.
	Type string
	URL  string

	// AgentIssuer and AgentSubject belong to agent.bound.
	AgentIssuer  string
	AgentSubject string

	// TokenType and TokenIssuer belong to revocation.received, with JTI and
	// ExpiresAt. TokenType is agent_token or resource_token.
	TokenType   string
	TokenIssuer string
}

// Validate checks the envelope and the members Name requires.
func (event Event) Validate() error {
	if err := validateIdentifier("id", event.ID); err != nil {
		return err
	}
	if event.SDI != "" {
		if err := validateIdentifier("sdi", event.SDI); err != nil {
			return err
		}
	}
	if err := validateEnvelope(event.IssuedAt, event.Subject, event.Agent, event.MissionS256); err != nil {
		return err
	}
	needSDI := false
	switch event.Name {
	case EventPersonTokenIssued, EventAuthTokenIssued:
		needSDI = true
		if event.JTI == "" || event.ExpiresAt <= 0 {
			return fmt.Errorf("supervision: %s requires jti and exp", event.Name)
		}
		if err := aauth.ValidateServerIdentifier(event.Audience); err != nil {
			return fmt.Errorf("supervision: %s aud: %w", event.Name, err)
		}
		if event.Name == EventAuthTokenIssued {
			if err := aauth.ValidateServerIdentifier(event.Issuer); err != nil {
				return fmt.Errorf("supervision: %s issuer: %w", event.Name, err)
			}
			if _, err := ParseScope(event.Scope); err != nil {
				return err
			}
		}
	case EventDecisionResolved:
		needSDI = true
		switch event.Answer {
		case AnswerAllow, AnswerDeny, AnswerAbandoned:
		default:
			return errors.New("supervision: decision.resolved answer must be allow, deny or abandoned")
		}
		switch event.Recommendation {
		case "", VerdictAllow, VerdictDeny:
		default:
			return errors.New("supervision: decision.resolved recommendation must be allow or deny")
		}
		if event.Supervisor != "" && event.Supervisor != SupervisorUnavailable {
			return errors.New("supervision: decision.resolved supervisor must be unavailable when present")
		}
		if event.Supervisor != "" && event.Recommendation != "" {
			return errors.New("supervision: an unavailable supervisor gave no recommendation")
		}
		if event.Proposed != nil {
			if err := event.Proposed.Validate(); err != nil {
				return err
			}
		}
		for _, entry := range event.Transcript {
			if entry.From != FromPerson && entry.From != FromAgent {
				return errors.New("supervision: transcript entries are from person or agent")
			}
			if err := validateMarkdown("transcript", entry.Text); err != nil {
				return err
			}
		}
		if err := validateMarkdown("reason", event.Reason); err != nil {
			return err
		}
		if len(event.Apply) > 255 {
			return errors.New("supervision: apply is too long")
		}
	case EventAuditRecorded:
		if event.Action == "" {
			return errors.New("supervision: audit.recorded requires action")
		}
		for _, raw := range []json.RawMessage{event.Parameters, event.Result} {
			if raw != nil {
				if err := validateObject("audit member", raw); err != nil {
					return err
				}
			}
		}
	case EventInteractionRequested:
		switch event.Type {
		case "interaction", "payment", "question":
		default:
			return errors.New("supervision: interaction.requested type is invalid")
		}
		if event.URL != "" {
			if err := aauth.ValidateHTTPSURL(event.URL); err != nil {
				return fmt.Errorf("supervision: interaction.requested url: %w", err)
			}
		}
	case EventAgentBound:
		if err := aauth.ValidateServerIdentifier(event.AgentIssuer); err != nil {
			return fmt.Errorf("supervision: agent.bound agent_iss: %w", err)
		}
		if err := aauth.ValidateAgentIdentifier(event.AgentSubject); err != nil {
			return fmt.Errorf("supervision: agent.bound agent_sub: %w", err)
		}
	case EventRevocationReceived:
		if event.TokenType != "agent_token" && event.TokenType != "resource_token" {
			return errors.New("supervision: revocation.received token_type must be agent_token or resource_token")
		}
		if event.JTI == "" || event.ExpiresAt <= 0 {
			return errors.New("supervision: revocation.received requires jti and exp")
		}
		if err := aauth.ValidateServerIdentifier(event.TokenIssuer); err != nil {
			return fmt.Errorf("supervision: revocation.received iss: %w", err)
		}
	default:
		return errors.New("supervision: event is missing or unrecognized")
	}
	if needSDI && event.SDI == "" {
		return fmt.Errorf("supervision: %s requires sdi", event.Name)
	}
	for name, value := range map[string]string{"description": event.Description, "action": event.Action} {
		if err := validateMarkdown(name, value); err != nil {
			return err
		}
	}
	return nil
}

// Encode returns the event body.
func (event Event) Encode() ([]byte, error) {
	if err := event.Validate(); err != nil {
		return nil, err
	}
	var object objectWriter
	object.add("event", string(event.Name))
	object.add("id", event.ID)
	object.addString("sdi", event.SDI)
	object.add("iat", event.IssuedAt)
	object.add("sub", event.Subject)
	object.add("agent", event.Agent)
	object.addString("mission_s256", event.MissionS256)
	object.addString("jti", event.JTI)
	object.addString("aud", event.Audience)
	object.addString("scope", event.Scope)
	if event.ExpiresAt != 0 {
		object.add("exp", event.ExpiresAt)
	}
	object.addString("issuer", event.Issuer)
	object.addString("answer", string(event.Answer))
	object.addString("apply", event.Apply)
	object.addString("recommendation", string(event.Recommendation))
	if event.Proposed != nil {
		object.add("proposed", event.Proposed.clone())
	}
	if event.Transcript != nil {
		object.add("transcript", event.Transcript)
	}
	object.addString("supervisor", event.Supervisor)
	object.addString("reason", event.Reason)
	object.addString("action", event.Action)
	object.addString("description", event.Description)
	if event.Parameters != nil {
		object.addRaw("parameters", event.Parameters)
	}
	if event.Result != nil {
		object.addRaw("result", event.Result)
	}
	object.addString("type", event.Type)
	object.addString("url", event.URL)
	object.addString("agent_iss", event.AgentIssuer)
	object.addString("agent_sub", event.AgentSubject)
	object.addString("token_type", event.TokenType)
	object.addString("iss", event.TokenIssuer)
	return object.bytes()
}

type eventWire struct {
	Event          string            `json:"event"`
	ID             string            `json:"id"`
	SDI            string            `json:"sdi"`
	IssuedAt       int64             `json:"iat"`
	Subject        string            `json:"sub"`
	Agent          string            `json:"agent"`
	MissionS256    string            `json:"mission_s256"`
	JTI            string            `json:"jti"`
	Audience       string            `json:"aud"`
	Scope          string            `json:"scope"`
	ExpiresAt      int64             `json:"exp"`
	Issuer         string            `json:"issuer"`
	Answer         string            `json:"answer"`
	Apply          string            `json:"apply"`
	Recommendation string            `json:"recommendation"`
	Proposed       *MissionTerms     `json:"proposed"`
	Transcript     []TranscriptEntry `json:"transcript"`
	Supervisor     string            `json:"supervisor"`
	Reason         string            `json:"reason"`
	Action         string            `json:"action"`
	Description    string            `json:"description"`
	Parameters     json.RawMessage   `json:"parameters"`
	Result         json.RawMessage   `json:"result"`
	Type           string            `json:"type"`
	URL            string            `json:"url"`
	AgentIssuer    string            `json:"agent_iss"`
	AgentSubject   string            `json:"agent_sub"`
	TokenType      string            `json:"token_type"`
	TokenIssuer    string            `json:"iss"`
}

// DecodeEvent decodes a body posted to event_endpoint. An unrecognized event
// is invalid_request.
func DecodeEvent(exact []byte) (Event, error) {
	var wire eventWire
	if err := decodeStrict(exact, &wire); err != nil {
		return Event{}, invalidRequest(err)
	}
	event := Event{
		Name: EventName(wire.Event), ID: wire.ID, SDI: wire.SDI, IssuedAt: wire.IssuedAt,
		Subject: wire.Subject, Agent: wire.Agent, MissionS256: wire.MissionS256,
		JTI: wire.JTI, Audience: wire.Audience, ExpiresAt: wire.ExpiresAt, Scope: wire.Scope,
		Issuer: wire.Issuer, Answer: Answer(wire.Answer), Apply: wire.Apply,
		Recommendation: Verdict(wire.Recommendation), Proposed: wire.Proposed,
		Transcript: wire.Transcript, Supervisor: wire.Supervisor, Reason: wire.Reason,
		Action: wire.Action, Description: wire.Description, Parameters: wire.Parameters,
		Result: wire.Result, Type: wire.Type, URL: wire.URL, AgentIssuer: wire.AgentIssuer,
		AgentSubject: wire.AgentSubject, TokenType: wire.TokenType, TokenIssuer: wire.TokenIssuer,
	}
	if err := event.Validate(); err != nil {
		return Event{}, invalidRequest(err)
	}
	return event, nil
}

// ReportAction is the action of a mission report.
type ReportAction string

const (
	// ReportApproved tells the SS the Person Server built and recorded a
	// mission.
	ReportApproved ReportAction = actionApproved
	// ReportTerminated tells the SS a mission ended, for any reason.
	ReportTerminated ReportAction = actionTerminated
)

// Report is a mission report posted to {mission_endpoint}/{s256}. The SS
// answers 201 and does not decide it.
type Report struct {
	Action      ReportAction
	ID          string
	SDI         string
	IssuedAt    int64
	Subject     string
	Agent       string
	MissionS256 string
	// Mission is the exact mission blob an approved report carries; its
	// SHA-256 is MissionS256.
	Mission []byte
	// Reason is the termination reason a terminated report carries.
	Reason string
}

// Path returns the path segment the report is sent to below
// mission_endpoint.
func (report Report) Path() string { return "/" + report.MissionS256 }

// Validate checks the envelope and the members Action requires. An approved
// report's blob must hash to MissionS256.
func (report Report) Validate() error {
	if err := validateIdentifier("id", report.ID); err != nil {
		return err
	}
	if err := validateEnvelope(report.IssuedAt, report.Subject, report.Agent, report.MissionS256); err != nil {
		return err
	}
	if report.MissionS256 == "" {
		return errors.New("supervision: a mission report names its mission")
	}
	switch report.Action {
	case ReportApproved:
		if err := validateIdentifier("sdi", report.SDI); err != nil {
			return err
		}
		if len(report.Mission) == 0 || aauth.MissionS256(report.Mission) != report.MissionS256 {
			return errors.New("supervision: approved s256 is not the digest of mission")
		}
		if report.Reason != "" {
			return errors.New("supervision: an approved report carries no reason")
		}
	case ReportTerminated:
		if report.Reason == "" {
			return errors.New("supervision: a terminated report carries its reason")
		}
		if report.SDI != "" || report.Mission != nil {
			return errors.New("supervision: a terminated report carries neither sdi nor mission")
		}
	default:
		return errors.New("supervision: report action must be approved or terminated")
	}
	return nil
}

// Encode returns the report body. An approved report carries s256 and the
// base64url mission blob; a terminated report carries mission_s256 and its
// reason.
func (report Report) Encode() ([]byte, error) {
	if err := report.Validate(); err != nil {
		return nil, err
	}
	var object objectWriter
	object.add("action", string(report.Action))
	object.add("id", report.ID)
	object.addString("sdi", report.SDI)
	object.add("iat", report.IssuedAt)
	object.add("sub", report.Subject)
	object.add("agent", report.Agent)
	if report.Action == ReportApproved {
		object.add("s256", report.MissionS256)
		object.add("mission", base64.RawURLEncoding.EncodeToString(report.Mission))
	} else {
		object.add("mission_s256", report.MissionS256)
		object.add("reason", report.Reason)
	}
	return object.bytes()
}

func decodeReport(s256 string, exact []byte) (Report, error) {
	var wire struct {
		Action      string `json:"action"`
		ID          string `json:"id"`
		SDI         string `json:"sdi"`
		IssuedAt    int64  `json:"iat"`
		Subject     string `json:"sub"`
		Agent       string `json:"agent"`
		S256        string `json:"s256"`
		MissionS256 string `json:"mission_s256"`
		Mission     string `json:"mission"`
		Reason      string `json:"reason"`
	}
	if err := decodeStrict(exact, &wire); err != nil {
		return Report{}, invalidRequest(err)
	}
	report := Report{
		Action: ReportAction(wire.Action), ID: wire.ID, SDI: wire.SDI, IssuedAt: wire.IssuedAt,
		Subject: wire.Subject, Agent: wire.Agent, MissionS256: s256, Reason: wire.Reason,
	}
	for _, named := range []string{wire.S256, wire.MissionS256} {
		if named != "" && named != s256 {
			return Report{}, invalidRequest(errors.New("supervision: report names a mission other than its path"))
		}
	}
	if wire.Mission != "" {
		blob, err := base64.RawURLEncoding.DecodeString(wire.Mission)
		if err != nil {
			return Report{}, invalidRequest(errors.New("supervision: approved mission is not base64url"))
		}
		report.Mission = blob
	}
	if err := report.Validate(); err != nil {
		return Report{}, invalidRequest(err)
	}
	return report, nil
}

// ConnectAction is the action of a connect request.
type ConnectAction string

const (
	ActionConnect    ConnectAction = "connect"
	ActionDisconnect ConnectAction = "disconnect"
)

// ConnectRequest establishes, or ends, that a Person Server speaks for Subject
// at the SS. Tenant is the person's tenant when the Person Server asserts one.
type ConnectRequest struct {
	Action   ConnectAction
	ID       string
	IssuedAt int64
	Subject  string
	Tenant   string
}

// Validate checks the members.
func (request ConnectRequest) Validate() error {
	if request.Action != ActionConnect && request.Action != ActionDisconnect {
		return errors.New("supervision: connect action must be connect or disconnect")
	}
	if err := validateIdentifier("id", request.ID); err != nil {
		return err
	}
	if request.IssuedAt <= 0 {
		return errors.New("supervision: iat is required")
	}
	if request.Subject == "" || len(request.Subject) > 255 {
		return errors.New("supervision: sub is required")
	}
	if request.Tenant != "" && len(request.Tenant) > 255 {
		return errors.New("supervision: tenant is too long")
	}
	return nil
}

// Encode returns the connect body.
func (request ConnectRequest) Encode() ([]byte, error) {
	if err := request.Validate(); err != nil {
		return nil, err
	}
	var object objectWriter
	object.add("action", string(request.Action))
	object.add("id", request.ID)
	object.add("iat", request.IssuedAt)
	object.add("sub", request.Subject)
	object.addString("tenant", request.Tenant)
	return object.bytes()
}

// DecodeConnectRequest decodes a body posted to connect_endpoint.
func DecodeConnectRequest(exact []byte) (ConnectRequest, error) {
	var wire struct {
		Action   string `json:"action"`
		ID       string `json:"id"`
		IssuedAt int64  `json:"iat"`
		Subject  string `json:"sub"`
		Tenant   string `json:"tenant"`
	}
	if err := decodeStrict(exact, &wire); err != nil {
		return ConnectRequest{}, invalidRequest(err)
	}
	request := ConnectRequest{
		Action: ConnectAction(wire.Action), ID: wire.ID, IssuedAt: wire.IssuedAt,
		Subject: wire.Subject, Tenant: wire.Tenant,
	}
	if err := request.Validate(); err != nil {
		return ConnectRequest{}, invalidRequest(err)
	}
	return request, nil
}
