package supervision

import (
	"errors"
	"fmt"
	"strings"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
)

// Verdict is the decision member of a terminal answer.
type Verdict string

const (
	// VerdictAllow means the Person Server proceeds, narrowed as the decision
	// says.
	VerdictAllow Verdict = "allow"
	// VerdictDeny means the Person Server refuses the act.
	VerdictDeny Verdict = "deny"
	// VerdictAsk means the SS does not decide, and the Person Server puts the
	// act to the person.
	VerdictAsk Verdict = "ask"
)

// The fixed reaches a Person Server may offer when an ask carries no
// apply_options (Reach of an Answer).
const (
	ApplyOnce    = "once"
	ApplyMission = "mission"
	ApplyAlways  = "always"
)

// MaxClarificationRounds is the clarification limit a Person Server enforces
// on one supervision request, counting the SS's questions and the person's.
// The draft RECOMMENDS five.
const MaxClarificationRounds = 5

// MissionTerms are the mission members an SS approves or proposes for a
// mission proposal: the approved description and, optionally, tools,
// resources and expiry. The Person Server builds the mission blob from them.
type MissionTerms struct {
	Description       string              `json:"description"`
	ApprovedTools     []aauth.MissionTool `json:"approved_tools,omitempty"`
	ApprovedResources []string            `json:"approved_resources,omitempty"`
	ExpiresAt         *time.Time          `json:"expires_at,omitempty"`
}

// Validate checks the terms against the proposal they answer: a description
// is required, approved tools are named, and approved resources are server
// identifiers.
func (terms MissionTerms) Validate() error {
	if terms.Description == "" {
		return errors.New("supervision: approved mission description is required")
	}
	if err := validateMarkdown("description", terms.Description); err != nil {
		return err
	}
	for _, tool := range terms.ApprovedTools {
		if tool.Name == "" {
			return errors.New("supervision: approved tools: a tool needs a name")
		}
	}
	for _, resource := range terms.ApprovedResources {
		if err := aauth.ValidateServerIdentifier(resource); err != nil {
			return fmt.Errorf("supervision: approved resources: %w", err)
		}
	}
	return nil
}

// MarshalJSON writes the terms with expires_at in whole seconds.
func (terms MissionTerms) MarshalJSON() ([]byte, error) {
	var object objectWriter
	writeMissionTerms(&object, terms)
	return object.bytes()
}

func (terms MissionTerms) clone() MissionTerms {
	terms.ApprovedTools = append([]aauth.MissionTool(nil), terms.ApprovedTools...)
	terms.ApprovedResources = append([]string(nil), terms.ApprovedResources...)
	if terms.ExpiresAt != nil {
		value := terms.ExpiresAt.UTC()
		terms.ExpiresAt = &value
	}
	return terms
}

// ApplyOption is one reach an SS offers the person for their answer: a value
// the SS recognizes and a Markdown label the Person Server shows.
type ApplyOption struct {
	Value string `json:"value"`
	Label string `json:"label"`
}

// Decision is a terminal answer to a supervision request: allow, deny or ask.
// The members other than SDI and Verdict depend on the verdict and on the
// request it answers.
type Decision struct {
	SDI     string
	Verdict Verdict
	// Scope narrows an allowed auth-token request: a space-delimited subset
	// of the scope the resource token requested.
	Scope string
	// ExpiresAt bounds an allowed person or auth token: its exp is no later.
	ExpiresAt int64
	// Mission is the approved mission an allow of a mission proposal carries.
	Mission *MissionTerms
	// Reason is the Markdown reason a deny may carry.
	Reason string
	// Summary, Recommendation, Proposed and ApplyOptions belong to an ask.
	Summary        string
	Recommendation Verdict
	Proposed       *MissionTerms
	ApplyOptions   []ApplyOption
}

// Validate checks the decision against the kind of request it answers.
func (decision Decision) Validate(kind Kind) error {
	if !kind.valid() {
		return errors.New("supervision: request kind is invalid")
	}
	if err := validateIdentifier("sdi", decision.SDI); err != nil {
		return err
	}
	allow := decision.Verdict == VerdictAllow
	ask := decision.Verdict == VerdictAsk
	switch decision.Verdict {
	case VerdictAllow, VerdictDeny, VerdictAsk:
	default:
		return errors.New("supervision: decision is missing or unrecognized")
	}
	if decision.Scope != "" && (!allow || kind != KindAuthToken) {
		return errors.New("supervision: scope narrows only an allowed auth-token request")
	}
	if decision.Scope != "" {
		if _, err := ParseScope(decision.Scope); err != nil {
			return err
		}
	}
	if decision.ExpiresAt != 0 && (!allow || (kind != KindAuthToken && kind != KindPersonToken)) {
		return errors.New("supervision: exp bounds only an allowed person or auth token")
	}
	if decision.ExpiresAt < 0 {
		return errors.New("supervision: exp is invalid")
	}
	if kind == KindMissionProposal && allow {
		if decision.Mission == nil {
			return errors.New("supervision: an allowed mission proposal carries the approved mission")
		}
		if err := decision.Mission.Validate(); err != nil {
			return err
		}
	} else if decision.Mission != nil {
		return errors.New("supervision: only an allowed mission proposal carries an approved mission")
	}
	if decision.Reason != "" && decision.Verdict != VerdictDeny {
		return errors.New("supervision: only a deny carries a reason")
	}
	if err := validateMarkdown("reason", decision.Reason); err != nil {
		return err
	}
	if !ask && (decision.Summary != "" || decision.Recommendation != "" || decision.Proposed != nil || decision.ApplyOptions != nil) {
		return errors.New("supervision: summary, recommendation, proposed and apply_options belong to an ask")
	}
	if err := validateMarkdown("summary", decision.Summary); err != nil {
		return err
	}
	switch decision.Recommendation {
	case "", VerdictAllow, VerdictDeny:
	default:
		return errors.New("supervision: recommendation must be allow or deny")
	}
	if decision.Proposed != nil {
		if kind != KindMissionProposal {
			return errors.New("supervision: only an ask on a mission proposal carries proposed")
		}
		if err := decision.Proposed.Validate(); err != nil {
			return err
		}
	}
	seen := make(map[string]bool, len(decision.ApplyOptions))
	for _, option := range decision.ApplyOptions {
		if option.Value == "" || len(option.Value) > 255 || seen[option.Value] {
			return errors.New("supervision: apply_options values must be nonempty and distinct")
		}
		seen[option.Value] = true
		if option.Label == "" {
			return errors.New("supervision: an apply option needs a label")
		}
		if err := validateMarkdown("label", option.Label); err != nil {
			return err
		}
	}
	return nil
}

// Encode returns the decision body for the kind it answers.
func (decision Decision) Encode(kind Kind) ([]byte, error) {
	if err := decision.Validate(kind); err != nil {
		return nil, err
	}
	var object objectWriter
	object.add("sdi", decision.SDI)
	object.add("decision", string(decision.Verdict))
	object.addString("scope", decision.Scope)
	if decision.ExpiresAt != 0 {
		object.add("exp", decision.ExpiresAt)
	}
	if decision.Mission != nil {
		writeMissionTerms(&object, *decision.Mission)
	}
	object.addString("reason", decision.Reason)
	object.addString("summary", decision.Summary)
	object.addString("recommendation", string(decision.Recommendation))
	if decision.Proposed != nil {
		object.add("proposed", decision.Proposed.clone())
	}
	if decision.ApplyOptions != nil {
		object.add("apply_options", decision.ApplyOptions)
	}
	return object.bytes()
}

func writeMissionTerms(object *objectWriter, terms MissionTerms) {
	terms = terms.clone()
	object.add("description", terms.Description)
	if terms.ApprovedTools != nil {
		object.add("approved_tools", terms.ApprovedTools)
	}
	if terms.ApprovedResources != nil {
		object.add("approved_resources", terms.ApprovedResources)
	}
	if terms.ExpiresAt != nil {
		object.add("expires_at", terms.ExpiresAt.Format(time.RFC3339))
	}
}

type decisionWire struct {
	SDI               string              `json:"sdi"`
	Decision          string              `json:"decision"`
	Scope             string              `json:"scope"`
	ExpiresAt         int64               `json:"exp"`
	Description       *string             `json:"description"`
	ApprovedTools     []aauth.MissionTool `json:"approved_tools"`
	ApprovedResources []string            `json:"approved_resources"`
	MissionExpiresAt  *time.Time          `json:"expires_at"`
	Reason            string              `json:"reason"`
	Summary           string              `json:"summary"`
	Recommendation    string              `json:"recommendation"`
	Proposed          *MissionTerms       `json:"proposed"`
	ApplyOptions      []ApplyOption       `json:"apply_options"`
	Status            string              `json:"status"`
}

// DecodeDecision decodes and validates a 200 decision body answering a
// request of kind.
func DecodeDecision(kind Kind, exact []byte) (Decision, error) {
	var wire decisionWire
	if err := decodeStrict(exact, &wire); err != nil {
		return Decision{}, fmt.Errorf("supervision: decode decision: %w", err)
	}
	if wire.Status != "" {
		return Decision{}, errors.New("supervision: a terminal decision carries no status")
	}
	decision := Decision{
		SDI: wire.SDI, Verdict: Verdict(wire.Decision), Scope: wire.Scope, ExpiresAt: wire.ExpiresAt,
		Reason: wire.Reason, Summary: wire.Summary, Recommendation: Verdict(wire.Recommendation),
		Proposed: wire.Proposed, ApplyOptions: wire.ApplyOptions,
	}
	if wire.Description != nil || wire.ApprovedTools != nil || wire.ApprovedResources != nil || wire.MissionExpiresAt != nil {
		terms := MissionTerms{
			ApprovedTools: wire.ApprovedTools, ApprovedResources: wire.ApprovedResources,
			ExpiresAt: wire.MissionExpiresAt,
		}
		if wire.Description != nil {
			terms.Description = *wire.Description
		}
		decision.Mission = &terms
	}
	if err := decision.Validate(kind); err != nil {
		return Decision{}, err
	}
	return decision, nil
}

// ParseScope splits a space-delimited scope into distinct tokens.
func ParseScope(scope string) ([]string, error) {
	if scope == "" {
		return nil, nil
	}
	values := strings.Split(scope, " ")
	seen := make(map[string]bool, len(values))
	for _, value := range values {
		if value == "" || seen[value] {
			return nil, errors.New("supervision: scope must be distinct tokens separated by single spaces")
		}
		for _, character := range value {
			if character < 0x21 || character > 0x7e || character == '"' || character == '\\' {
				return nil, errors.New("supervision: scope token contains an invalid character")
			}
		}
		seen[value] = true
	}
	return values, nil
}

// Clarification is a question an SS asks the Agent before it decides
// (Clarification). Timeout, when positive, is how long the Agent has to
// answer.
type Clarification struct {
	Question string
	Timeout  time.Duration
	Options  []string
}

// Validate checks the question, timeout and options.
func (clarification Clarification) Validate() error {
	if clarification.Question == "" {
		return errors.New("supervision: clarification question is required")
	}
	if err := validateMarkdown("clarification", clarification.Question); err != nil {
		return err
	}
	if clarification.Timeout < 0 || clarification.Timeout%time.Second != 0 {
		return errors.New("supervision: clarification timeout must be whole nonnegative seconds")
	}
	if len(clarification.Options) > 32 {
		return errors.New("supervision: clarification has too many options")
	}
	for _, option := range clarification.Options {
		if option == "" {
			return errors.New("supervision: clarification options must be nonempty")
		}
		if err := validateMarkdown("option", option); err != nil {
			return err
		}
	}
	return nil
}

// EncodePending returns the body of a 202 for a pending request: sdi and
// status pending, and for a clarification, decision clarify with the
// question. sdi is omitted when empty.
func EncodePending(sdi string, clarification *Clarification) ([]byte, error) {
	var object objectWriter
	object.addString("sdi", sdi)
	object.add("status", "pending")
	if clarification != nil {
		if err := clarification.Validate(); err != nil {
			return nil, err
		}
		object.add("decision", "clarify")
		object.add("clarification", clarification.Question)
		if clarification.Timeout > 0 {
			object.add("timeout", int64(clarification.Timeout/time.Second))
		}
		if len(clarification.Options) > 0 {
			object.add("options", clarification.Options)
		}
	}
	return object.bytes()
}

type pendingWire struct {
	SDI           string   `json:"sdi"`
	Status        string   `json:"status"`
	Decision      string   `json:"decision"`
	Clarification *string  `json:"clarification"`
	Timeout       int64    `json:"timeout"`
	Options       []string `json:"options"`
}

// decodePending reads a 202 body. clarifying reports the requirement the
// response named. The returned sdi is empty when the body carried none.
func decodePending(exact []byte, clarifying bool) (string, *Clarification, error) {
	var wire pendingWire
	if err := decodeStrict(exact, &wire); err != nil {
		return "", nil, fmt.Errorf("supervision: decode pending response: %w", err)
	}
	if wire.Status == "" {
		return "", nil, errors.New("supervision: pending response status is required")
	}
	if !clarifying {
		if wire.Clarification != nil || (wire.Decision != "" && wire.Decision != "clarify") {
			return "", nil, errors.New("supervision: a pending response without requirement=clarification asks no question")
		}
		if wire.Decision == "clarify" {
			return "", nil, errors.New("supervision: decision clarify requires requirement=clarification")
		}
		return wire.SDI, nil, nil
	}
	if wire.Clarification == nil || wire.Timeout < 0 {
		return "", nil, errors.New("supervision: a clarification response requires the question")
	}
	if wire.Decision != "" && wire.Decision != "clarify" {
		return "", nil, errors.New("supervision: a clarification response's decision must be clarify")
	}
	clarification := &Clarification{
		Question: *wire.Clarification, Timeout: time.Duration(wire.Timeout) * time.Second,
		Options: wire.Options,
	}
	if err := clarification.Validate(); err != nil {
		return "", nil, err
	}
	return wire.SDI, clarification, nil
}

// ClarificationResponse is the answer a Person Server relays to an SS
// pending URL, as the Agent sent it: the Agent's Markdown answer, posted with
// action clarification_response, or for an auth-token request a replacement
// resource token and presented token, posted with action updated_request.
// Exactly one of Answer and Updated is set.
type ClarificationResponse struct {
	Answer  string
	Updated *UpdatedRequest
}

// UpdatedRequest is an auth-token request the Agent replaced while answering a
// clarification. The Person Server has verified the pair as the protocol
// requires before relaying it.
type UpdatedRequest struct {
	ResourceToken  string
	PresentedToken string
	Justification  string
}

// Encode returns the clarification_response or updated_request body.
func (response ClarificationResponse) Encode() ([]byte, error) {
	if err := response.validate(); err != nil {
		return nil, err
	}
	var object objectWriter
	if response.Updated != nil {
		object.add("action", "updated_request")
		object.add("resource_token", response.Updated.ResourceToken)
		object.add("presented_token", response.Updated.PresentedToken)
		object.addString("justification", response.Updated.Justification)
		return object.bytes()
	}
	object.add("action", "clarification_response")
	object.add("clarification_response", response.Answer)
	return object.bytes()
}

func (response ClarificationResponse) validate() error {
	if (response.Answer == "") == (response.Updated == nil) {
		return errors.New("supervision: a clarification response is an answer or an updated request")
	}
	if response.Updated != nil {
		for _, token := range []string{response.Updated.ResourceToken, response.Updated.PresentedToken} {
			if strings.Count(token, ".") != 2 {
				return errors.New("supervision: an updated request carries compact resource and presented tokens")
			}
		}
		return validateMarkdown("justification", response.Updated.Justification)
	}
	return validateMarkdown("clarification_response", response.Answer)
}

// DecodeClarificationResponse decodes a POST to an SS pending URL. A missing
// or unrecognized action is invalid_request.
func DecodeClarificationResponse(exact []byte) (ClarificationResponse, error) {
	var wire struct {
		Action         string  `json:"action"`
		Response       *string `json:"clarification_response"`
		ResourceToken  string  `json:"resource_token"`
		PresentedToken string  `json:"presented_token"`
		Justification  string  `json:"justification"`
	}
	if err := decodeStrict(exact, &wire); err != nil {
		return ClarificationResponse{}, invalidRequest(err)
	}
	var response ClarificationResponse
	switch wire.Action {
	case "clarification_response":
		if wire.Response != nil {
			response.Answer = *wire.Response
		}
	case "updated_request":
		response.Updated = &UpdatedRequest{
			ResourceToken: wire.ResourceToken, PresentedToken: wire.PresentedToken, Justification: wire.Justification,
		}
	default:
		return ClarificationResponse{}, invalidRequest(errors.New("supervision: action must be clarification_response or updated_request"))
	}
	if err := response.validate(); err != nil {
		return ClarificationResponse{}, invalidRequest(err)
	}
	return response, nil
}
