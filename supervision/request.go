package supervision

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"unicode/utf8"

	aauth "gitlab.com/sidecat-dev/aauth-go"
)

// MaxBodyBytes bounds every supervision request and response body.
const MaxBodyBytes = 1 << 20

// MaxMarkdownBytes bounds one Markdown member: a description, summary,
// justification, reason, question or answer.
const MaxMarkdownBytes = 64 << 10

// Kind names one supervision request: an act the Person Server puts to the SS
// for decision. Mission kinds go to mission_endpoint; the others go to
// decision_endpoint with the matching act.
type Kind string

const (
	KindMissionProposal   Kind = "mission_proposal"
	KindMissionUpdate     Kind = "mission_update"
	KindMissionCompletion Kind = "mission_completion"
	KindPersonToken       Kind = "person_token"
	KindAuthToken         Kind = "auth_token"
	KindPermission        Kind = "permission"
)

// Mission reports that a Person Server sends to {mission_endpoint}/{s256},
// and the two supervision requests sent there.
const (
	actionApproved   = "approved"
	actionTerminated = "terminated"
	actionUpdate     = "update"
	actionCompletion = "completion"
)

// MissionEndpoint reports whether the kind is sent to mission_endpoint.
func (kind Kind) MissionEndpoint() bool {
	switch kind {
	case KindMissionProposal, KindMissionUpdate, KindMissionCompletion:
		return true
	}
	return false
}

func (kind Kind) valid() bool {
	switch kind {
	case KindMissionProposal, KindMissionUpdate, KindMissionCompletion,
		KindPersonToken, KindAuthToken, KindPermission:
		return true
	}
	return false
}

// Request is one supervision request: the envelope (Envelope) and the members
// its Kind defines. Members that the Kind does not define must be empty.
//
// Forwarded tokens and Agent-authored members are copied as the Agent sent
// them, so the SS sees what the Person Server saw. Agent-asserted content is
// carried only in members the Agent authored: Description, Summary,
// Justification, Action and Parameters. Resource-asserted content arrives in
// the forwarded resource token.
type Request struct {
	Kind        Kind
	SDI         string
	IssuedAt    int64
	Subject     string
	Agent       string
	MissionS256 string

	// AgentToken is required on a mission proposal, a person-token request
	// and an auth-token request.
	AgentToken string
	// Description is required on a mission proposal and update, and optional
	// on a permission request.
	Description string
	Tools       []aauth.MissionTool
	Resources   []string
	// Summary is required on a mission completion.
	Summary string
	// Resource is required on a person-token request.
	Resource string
	// ResourceToken and PresentedToken are required on an auth-token request.
	ResourceToken  string
	PresentedToken string
	UpstreamToken  string
	SubagentToken  string
	Justification  string
	// Action is the action named in a permission request; it is required
	// there.
	Action string
	// Parameters is the permission request's JSON object, exactly as sent.
	Parameters json.RawMessage
	// Extra holds the other members of the Agent's request body, forwarded
	// as the Agent sent them, such as capabilities or login_hint. A name this
	// package defines, or one of the envelope, never appears here.
	Extra map[string]json.RawMessage
}

// requestMembers are the member names a supervision request defines; any
// other member of an Agent's body is forwarded in Request.Extra.
var requestMembers = map[string]bool{
	"act": true, "action": true, "sdi": true, "id": true, "iat": true, "sub": true, "agent": true,
	"mission_s256": true, "agent_token": true, "resource": true, "resource_token": true,
	"presented_token": true, "upstream_token": true, "subagent_token": true, "justification": true,
	"description": true, "tools": true, "resources": true, "summary": true, "parameters": true,
}

// ForwardedMembers returns the members of an Agent's request body that a
// supervision request does not define, exactly as sent, for Request.Extra.
// A body that is not one JSON object forwards nothing.
func ForwardedMembers(body []byte) map[string]json.RawMessage {
	var members map[string]json.RawMessage
	if json.Unmarshal(body, &members) != nil {
		return nil
	}
	for name := range members {
		if requestMembers[name] {
			delete(members, name)
		}
	}
	if len(members) == 0 {
		return nil
	}
	return members
}

// Path returns the path segment a mission update or completion is sent to
// below mission_endpoint, or empty for any other kind.
func (request Request) Path() string {
	if request.Kind == KindMissionUpdate || request.Kind == KindMissionCompletion {
		return "/" + request.MissionS256
	}
	return ""
}

// Validate checks the envelope and the members the Kind requires and permits.
func (request Request) Validate() error {
	if !request.Kind.valid() {
		return errors.New("supervision: request kind is invalid")
	}
	if err := validateIdentifier("sdi", request.SDI); err != nil {
		return err
	}
	if err := validateEnvelope(request.IssuedAt, request.Subject, request.Agent, request.MissionS256); err != nil {
		return err
	}
	present := map[string]bool{
		"agent_token": request.AgentToken != "", "description": request.Description != "",
		"tools": request.Tools != nil, "resources": request.Resources != nil,
		"summary": request.Summary != "", "resource": request.Resource != "",
		"resource_token": request.ResourceToken != "", "presented_token": request.PresentedToken != "",
		"upstream_token": request.UpstreamToken != "", "subagent_token": request.SubagentToken != "",
		"justification": request.Justification != "", "action": request.Action != "",
		"parameters": request.Parameters != nil,
	}
	var required, optional []string
	switch request.Kind {
	case KindMissionProposal:
		required = []string{"agent_token", "description"}
		optional = []string{"tools", "resources"}
	case KindMissionUpdate:
		required = []string{"description"}
	case KindMissionCompletion:
		required = []string{"summary"}
	case KindPersonToken:
		required = []string{"agent_token", "resource"}
		optional = []string{"upstream_token", "subagent_token", "justification"}
	case KindAuthToken:
		required = []string{"resource_token", "presented_token"}
		optional = []string{"agent_token", "upstream_token", "subagent_token", "justification"}
	case KindPermission:
		required = []string{"action"}
		optional = []string{"agent_token", "description", "parameters"}
	}
	for _, name := range required {
		if !present[name] {
			return fmt.Errorf("supervision: %s requires %s", request.Kind, name)
		}
		delete(present, name)
	}
	for _, name := range optional {
		delete(present, name)
	}
	for name, set := range present {
		if set {
			return fmt.Errorf("supervision: %s does not carry %s", request.Kind, name)
		}
	}
	if (request.Kind == KindMissionUpdate || request.Kind == KindMissionCompletion) && request.MissionS256 == "" {
		return fmt.Errorf("supervision: %s requires mission_s256", request.Kind)
	}
	if request.Kind == KindMissionProposal && request.MissionS256 != "" {
		return errors.New("supervision: a mission proposal names no mission")
	}
	for name, value := range map[string]string{
		"description": request.Description, "summary": request.Summary,
		"justification": request.Justification, "action": request.Action,
	} {
		if err := validateMarkdown(name, value); err != nil {
			return err
		}
	}
	for _, token := range []string{request.AgentToken, request.ResourceToken, request.PresentedToken, request.UpstreamToken, request.SubagentToken} {
		if token != "" && strings.Count(token, ".") != 2 {
			return errors.New("supervision: a forwarded token must be a compact JWT")
		}
	}
	if request.Resource != "" {
		if err := aauth.ValidateServerIdentifier(request.Resource); err != nil {
			return fmt.Errorf("supervision: resource: %w", err)
		}
	}
	for _, resource := range request.Resources {
		if err := aauth.ValidateServerIdentifier(resource); err != nil {
			return fmt.Errorf("supervision: resources: %w", err)
		}
	}
	for _, tool := range request.Tools {
		if tool.Name == "" {
			return errors.New("supervision: tools: a tool needs a name")
		}
	}
	if request.Parameters != nil {
		if err := validateObject("parameters", request.Parameters); err != nil {
			return err
		}
	}
	for name, value := range request.Extra {
		if requestMembers[name] || !json.Valid(value) {
			return fmt.Errorf("supervision: forwarded member %q is not forwardable", name)
		}
	}
	return nil
}

// agentTokenSubject returns the unverified sub of a forwarded agent token,
// which must be the request's agent.
func agentTokenSubject(token string) (string, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", errors.New("supervision: agent_token is not a compact JWT")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", errors.New("supervision: agent_token payload is not base64url")
	}
	var claims struct {
		Subject string `json:"sub"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", errors.New("supervision: agent_token payload is not JSON")
	}
	return claims.Subject, nil
}

// Encode returns the request body. Members are written in a fixed order and
// the result is the exact bytes the Person Server signs and retains.
func (request Request) Encode() ([]byte, error) {
	if err := request.Validate(); err != nil {
		return nil, err
	}
	var object objectWriter
	switch request.Kind {
	case KindMissionUpdate:
		object.add("action", actionUpdate)
	case KindMissionCompletion:
		object.add("action", actionCompletion)
	case KindPersonToken, KindAuthToken, KindPermission:
		object.add("act", string(request.Kind))
	}
	object.add("sdi", request.SDI)
	object.add("iat", request.IssuedAt)
	object.add("sub", request.Subject)
	object.add("agent", request.Agent)
	object.addString("mission_s256", request.MissionS256)
	object.addString("agent_token", request.AgentToken)
	object.addString("resource", request.Resource)
	object.addString("resource_token", request.ResourceToken)
	object.addString("presented_token", request.PresentedToken)
	object.addString("upstream_token", request.UpstreamToken)
	object.addString("subagent_token", request.SubagentToken)
	object.addString("justification", request.Justification)
	if request.Kind == KindPermission {
		object.add("action", request.Action)
	}
	object.addString("description", request.Description)
	if request.Tools != nil {
		object.add("tools", request.Tools)
	}
	if request.Resources != nil {
		object.add("resources", request.Resources)
	}
	object.addString("summary", request.Summary)
	if request.Parameters != nil {
		object.addRaw("parameters", request.Parameters)
	}
	names := make([]string, 0, len(request.Extra))
	for name := range request.Extra {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		object.addRaw(name, request.Extra[name])
	}
	return object.bytes()
}

// requestWire is the union of every supervision request member.
type requestWire struct {
	Act            string              `json:"act"`
	Action         string              `json:"action"`
	SDI            string              `json:"sdi"`
	IssuedAt       int64               `json:"iat"`
	Subject        string              `json:"sub"`
	Agent          string              `json:"agent"`
	MissionS256    string              `json:"mission_s256"`
	AgentToken     string              `json:"agent_token"`
	Resource       string              `json:"resource"`
	ResourceToken  string              `json:"resource_token"`
	PresentedToken string              `json:"presented_token"`
	UpstreamToken  string              `json:"upstream_token"`
	SubagentToken  string              `json:"subagent_token"`
	Justification  string              `json:"justification"`
	Description    string              `json:"description"`
	Tools          []aauth.MissionTool `json:"tools"`
	Resources      []string            `json:"resources"`
	Summary        string              `json:"summary"`
	Parameters     json.RawMessage     `json:"parameters"`
}

// DecodeDecisionRequest decodes a body posted to decision_endpoint.
func DecodeDecisionRequest(exact []byte) (Request, error) {
	var wire requestWire
	if err := decodeStrict(exact, &wire); err != nil {
		return Request{}, invalidRequest(err)
	}
	var kind Kind
	switch wire.Act {
	case string(KindPersonToken), string(KindAuthToken), string(KindPermission):
		kind = Kind(wire.Act)
	default:
		return Request{}, invalidRequest(errors.New("supervision: act is missing or unrecognized"))
	}
	request := wire.request(kind)
	request.Extra = ForwardedMembers(exact)
	if kind == KindPermission {
		request.Action = wire.Action
	} else if wire.Action != "" {
		return Request{}, invalidRequest(fmt.Errorf("supervision: %s does not carry action", kind))
	}
	return request, validated(request)
}

// DecodeMissionProposal decodes a body posted to mission_endpoint itself.
func DecodeMissionProposal(exact []byte) (Request, error) {
	var wire requestWire
	if err := decodeStrict(exact, &wire); err != nil {
		return Request{}, invalidRequest(err)
	}
	if wire.Act != "" || wire.Action != "" {
		return Request{}, invalidRequest(errors.New("supervision: a mission proposal carries neither act nor action"))
	}
	request := wire.request(KindMissionProposal)
	request.Extra = ForwardedMembers(exact)
	return request, validated(request)
}

// DecodeMissionAction decodes a body posted to {mission_endpoint}/{s256}. It
// returns a Request for an update or completion and a Report for approved or
// terminated; exactly one is set. s256 is the path segment.
func DecodeMissionAction(s256 string, exact []byte) (*Request, *Report, error) {
	if err := aauth.ValidateMissionS256(s256); err != nil {
		return nil, nil, invalidRequest(errors.New("supervision: mission path is not a mission identifier"))
	}
	var head struct {
		Action string `json:"action"`
	}
	if err := decodeStrict(exact, &head); err != nil {
		return nil, nil, invalidRequest(err)
	}
	switch head.Action {
	case actionUpdate, actionCompletion:
		var wire requestWire
		if err := decodeStrict(exact, &wire); err != nil {
			return nil, nil, invalidRequest(err)
		}
		kind := KindMissionUpdate
		if head.Action == actionCompletion {
			kind = KindMissionCompletion
		}
		if wire.Act != "" {
			return nil, nil, invalidRequest(errors.New("supervision: a mission action carries no act"))
		}
		request := wire.request(kind)
		request.Extra = ForwardedMembers(exact)
		if request.MissionS256 == "" {
			request.MissionS256 = s256
		}
		if request.MissionS256 != s256 {
			return nil, nil, invalidRequest(errors.New("supervision: mission_s256 does not match the mission path"))
		}
		if err := validated(request); err != nil {
			return nil, nil, err
		}
		return &request, nil, nil
	case actionApproved, actionTerminated:
		report, err := decodeReport(s256, exact)
		if err != nil {
			return nil, nil, err
		}
		return nil, &report, nil
	default:
		return nil, nil, invalidRequest(errors.New("supervision: action is missing or unrecognized"))
	}
}

func (wire requestWire) request(kind Kind) Request {
	return Request{
		Kind: kind, SDI: wire.SDI, IssuedAt: wire.IssuedAt, Subject: wire.Subject, Agent: wire.Agent,
		MissionS256: wire.MissionS256, AgentToken: wire.AgentToken, Description: wire.Description,
		Tools: wire.Tools, Resources: wire.Resources, Summary: wire.Summary, Resource: wire.Resource,
		ResourceToken: wire.ResourceToken, PresentedToken: wire.PresentedToken,
		UpstreamToken: wire.UpstreamToken, SubagentToken: wire.SubagentToken,
		Justification: wire.Justification, Parameters: wire.Parameters,
	}
}

// validated checks a decoded request and, as an SS does, that a forwarded
// agent token names the request's agent.
func validated(request Request) error {
	if err := request.Validate(); err != nil {
		return invalidRequest(err)
	}
	if request.AgentToken != "" {
		subject, err := agentTokenSubject(request.AgentToken)
		if err != nil {
			return invalidRequest(err)
		}
		if subject != request.Agent {
			return invalidRequest(errors.New("supervision: agent_token does not name the request's agent"))
		}
	}
	return nil
}

func validateEnvelope(issuedAt int64, subject, agent, missionS256 string) error {
	if issuedAt <= 0 {
		return errors.New("supervision: iat is required")
	}
	if subject == "" || len(subject) > 255 || !utf8.ValidString(subject) {
		return errors.New("supervision: sub is required")
	}
	if err := aauth.ValidateAgentIdentifier(agent); err != nil {
		return fmt.Errorf("supervision: agent: %w", err)
	}
	if missionS256 != "" {
		if err := aauth.ValidateMissionS256(missionS256); err != nil {
			return fmt.Errorf("supervision: mission_s256: %w", err)
		}
	}
	return nil
}

// validateIdentifier checks a Person Server-minted sdi or id: 1 to 255
// visible ASCII characters.
func validateIdentifier(name, value string) error {
	if value == "" || len(value) > 255 {
		return fmt.Errorf("supervision: %s is required and at most 255 characters", name)
	}
	for index := 0; index < len(value); index++ {
		if value[index] < 0x21 || value[index] > 0x7e {
			return fmt.Errorf("supervision: %s must be visible ASCII", name)
		}
	}
	return nil
}

func validateMarkdown(name, value string) error {
	if !utf8.ValidString(value) {
		return fmt.Errorf("supervision: %s must be UTF-8", name)
	}
	if len(value) > MaxMarkdownBytes {
		return fmt.Errorf("supervision: %s exceeds %d bytes", name, MaxMarkdownBytes)
	}
	return nil
}

func validateObject(name string, value json.RawMessage) error {
	trimmed := bytes.TrimSpace(value)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return fmt.Errorf("supervision: %s must be a JSON object", name)
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(trimmed, &object); err != nil || object == nil {
		return fmt.Errorf("supervision: %s must be a JSON object", name)
	}
	return nil
}

// objectWriter writes one JSON object with members in the order added.
type objectWriter struct {
	buffer bytes.Buffer
	err    error
}

func (object *objectWriter) add(name string, value any) {
	if object.err != nil {
		return
	}
	encoded, err := marshal(value)
	if err != nil {
		object.err = fmt.Errorf("supervision: encode %s: %w", name, err)
		return
	}
	object.addRaw(name, encoded)
}

func (object *objectWriter) addString(name, value string) {
	if value != "" {
		object.add(name, value)
	}
}

func (object *objectWriter) addRaw(name string, value []byte) {
	if object.err != nil {
		return
	}
	if object.buffer.Len() == 0 {
		object.buffer.WriteByte('{')
	} else {
		object.buffer.WriteByte(',')
	}
	key, _ := marshal(name)
	object.buffer.Write(key)
	object.buffer.WriteByte(':')
	object.buffer.Write(bytes.TrimSpace(value))
}

func (object *objectWriter) bytes() ([]byte, error) {
	if object.err != nil {
		return nil, object.err
	}
	if object.buffer.Len() == 0 {
		return []byte("{}"), nil
	}
	return append(append([]byte(nil), object.buffer.Bytes()...), '}'), nil
}

// marshal encodes one value without HTML escaping, so Markdown travels as
// written.
func marshal(value any) ([]byte, error) {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buffer.Bytes(), "\n"), nil
}
