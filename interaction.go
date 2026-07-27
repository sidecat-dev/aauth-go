package aauth

import (
	"encoding/json"
	"errors"
	"strings"
	"time"
)

// InteractionType is one of the four person-server interaction forms defined
// by the core draft.
type InteractionType string

const (
	InteractionTypeInteraction InteractionType = "interaction"
	InteractionTypePayment     InteractionType = "payment"
	InteractionTypeQuestion    InteractionType = "question"
	InteractionTypeCompletion  InteractionType = "completion"
)

// InteractionRequest asks a person server to relay work to its person. Mission
// is optional in the general protocol, but completion is necessarily
// mission-bound.
type InteractionRequest struct {
	Type        InteractionType   `json:"type"`
	Description string            `json:"description,omitempty"`
	URL         string            `json:"url,omitempty"`
	Code        string            `json:"code,omitempty"`
	MaxWait     int               `json:"max_wait,omitempty"`
	Question    string            `json:"question,omitempty"`
	Summary     string            `json:"summary,omitempty"`
	Mission     *MissionReference `json:"mission,omitempty"`
}

// Validate checks the protocol-level interaction request shape.
func (request InteractionRequest) Validate() error {
	switch request.Type {
	case InteractionTypeInteraction,
		InteractionTypePayment,
		InteractionTypeQuestion,
		InteractionTypeCompletion:
	default:
		return errors.New("aauth: interaction type is invalid")
	}
	if request.MaxWait < 0 {
		return errors.New("aauth: interaction max_wait must not be negative")
	}
	if request.Mission != nil {
		if err := request.Mission.Validate(); err != nil {
			return err
		}
	}
	if request.Type == InteractionTypeCompletion {
		if request.Mission == nil {
			return errors.New("aauth: completion interaction requires a mission")
		}
		if strings.TrimSpace(request.Summary) == "" {
			return errors.New("aauth: completion interaction requires a summary")
		}
	}
	return nil
}

// ClarificationResponse is the signed action an agent posts to a pending URL.
type ClarificationResponse struct {
	Action                string `json:"action"`
	ClarificationResponse string `json:"clarification_response"`
}

// InteractionRecord is ordered person-server custody for every interaction
// request and terminal response. Proof contains sensitive credential evidence.
type InteractionRecord struct {
	Sequence   uint64          `json:"sequence"`
	RecordedAt time.Time       `json:"recorded_at"`
	Agent      string          `json:"agent"`
	Request    json.RawMessage `json:"request"`
	Proof      *RequestProof   `json:"proof"`
	PendingID  string          `json:"pending_id,omitempty"`
	DecidedAt  time.Time       `json:"decided_at,omitempty"`
	DecidedBy  string          `json:"decided_by,omitempty"`
	Response   json.RawMessage `json:"response,omitempty"`
}
