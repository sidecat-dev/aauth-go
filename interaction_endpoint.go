package aauth

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"gitlab.com/sidecat-dev/aauth-go/internal/jsonstrict"
)

const interactionQuestionType = "question"

// InteractionQuestion is one source-defined question for a person. Description
// and Question are untrusted raw Markdown and must be sanitized before display.
type InteractionQuestion struct {
	Description string `json:"description,omitempty"`
	Question    string `json:"question"`
	MissionS256 string `json:"mission_s256,omitempty"`
}

// InteractionQuestionDocument keeps the parsed question beside the exact JSON
// bytes authenticated by the Agent. Unknown additive members remain untrusted
// in ExactJSON.
type InteractionQuestionDocument struct {
	ExactJSON []byte
	Question  InteractionQuestion
}

// InteractionAnswer is the Person Server's answer to one question. Answer is
// untrusted text from the host policy and must be handled as such by the Agent
// application.
type InteractionAnswer struct {
	Answer string `json:"answer"`
}

// InteractionAnswerDocument keeps a parsed answer beside its exact JSON bytes.
// Unknown additive members remain untrusted in ExactJSON.
type InteractionAnswerDocument struct {
	ExactJSON []byte
	Answer    InteractionAnswer
}

type interactionQuestionWire struct {
	Type        string `json:"type"`
	Description string `json:"description,omitempty"`
	Question    string `json:"question"`
	MissionS256 string `json:"mission_s256,omitempty"`
}

// Validate checks the source-defined question members.
func (question InteractionQuestion) Validate() error {
	if !utf8.ValidString(question.Description) {
		return errors.New("aauth: interaction description must be valid UTF-8")
	}
	if !utf8.ValidString(question.Question) || strings.TrimSpace(question.Question) == "" {
		return errors.New("aauth: interaction question is required and must be valid UTF-8")
	}
	if question.MissionS256 != "" {
		if err := ValidateMissionS256(question.MissionS256); err != nil {
			return fmt.Errorf("aauth: interaction question mission: %w", err)
		}
	}
	return nil
}

// EncodeInteractionQuestion validates and deterministically encodes a question.
func EncodeInteractionQuestion(question InteractionQuestion) (InteractionQuestionDocument, error) {
	if err := question.Validate(); err != nil {
		return InteractionQuestionDocument{}, err
	}
	exactJSON, err := json.Marshal(interactionQuestionWire{
		Type: interactionQuestionType, Description: question.Description,
		Question: question.Question, MissionS256: question.MissionS256,
	})
	if err != nil {
		return InteractionQuestionDocument{}, fmt.Errorf("aauth: encode interaction question: %w", err)
	}
	return InteractionQuestionDocument{
		ExactJSON: append([]byte(nil), exactJSON...), Question: question,
	}, nil
}

// DecodeInteractionQuestion preserves exact bytes and decodes one question.
// Relay-only url, code, and max_wait members are rejected by this focused API.
func DecodeInteractionQuestion(exactJSON []byte) (InteractionQuestionDocument, error) {
	if !utf8.Valid(exactJSON) {
		return InteractionQuestionDocument{}, errors.New("aauth: decode interaction question: JSON input must be valid UTF-8")
	}
	var wire interactionQuestionWire
	if err := jsonstrict.RejectCaseVariants(exactJSON, &wire); err != nil {
		return InteractionQuestionDocument{}, fmt.Errorf("aauth: decode interaction question: %w", err)
	}
	if err := json.Unmarshal(exactJSON, &wire); err != nil {
		return InteractionQuestionDocument{}, fmt.Errorf("aauth: decode interaction question: %w", err)
	}
	members, err := interactionMembers(exactJSON)
	if err != nil {
		return InteractionQuestionDocument{}, err
	}
	if err := requireJSONMemberString(members, "type"); err != nil || wire.Type != interactionQuestionType {
		return InteractionQuestionDocument{}, errors.New("aauth: interaction type must be question")
	}
	if err := requireJSONMemberString(members, "question"); err != nil {
		return InteractionQuestionDocument{}, fmt.Errorf("aauth: interaction question: %w", err)
	}
	for _, name := range []string{"url", "code", "max_wait"} {
		if _, present := members[name]; present {
			return InteractionQuestionDocument{}, fmt.Errorf("aauth: interaction question must not contain %s", name)
		}
	}
	if raw, present := members["description"]; present && !jsonMemberIsString(raw) {
		return InteractionQuestionDocument{}, errors.New("aauth: interaction description must be a string when present")
	}
	if raw, present := members["mission_s256"]; present {
		if !jsonMemberIsString(raw) {
			return InteractionQuestionDocument{}, errors.New("aauth: interaction mission_s256 must be a string when present")
		}
		if err := ValidateMissionS256(wire.MissionS256); err != nil {
			return InteractionQuestionDocument{}, fmt.Errorf("aauth: interaction question mission: %w", err)
		}
	}
	question := InteractionQuestion{
		Description: wire.Description, Question: wire.Question, MissionS256: wire.MissionS256,
	}
	if err := question.Validate(); err != nil {
		return InteractionQuestionDocument{}, err
	}
	return InteractionQuestionDocument{
		ExactJSON: append([]byte(nil), exactJSON...), Question: question,
	}, nil
}

// EncodeInteractionAnswer validates and deterministically encodes one answer.
func EncodeInteractionAnswer(answer InteractionAnswer) (InteractionAnswerDocument, error) {
	if !utf8.ValidString(answer.Answer) {
		return InteractionAnswerDocument{}, errors.New("aauth: interaction answer must be valid UTF-8")
	}
	exactJSON, err := json.Marshal(answer)
	if err != nil {
		return InteractionAnswerDocument{}, fmt.Errorf("aauth: encode interaction answer: %w", err)
	}
	return InteractionAnswerDocument{
		ExactJSON: append([]byte(nil), exactJSON...), Answer: answer,
	}, nil
}

// DecodeInteractionAnswer preserves exact bytes and decodes one answer.
func DecodeInteractionAnswer(exactJSON []byte) (InteractionAnswerDocument, error) {
	if !utf8.Valid(exactJSON) {
		return InteractionAnswerDocument{}, errors.New("aauth: decode interaction answer: JSON input must be valid UTF-8")
	}
	var answer InteractionAnswer
	if err := jsonstrict.RejectCaseVariants(exactJSON, &answer); err != nil {
		return InteractionAnswerDocument{}, fmt.Errorf("aauth: decode interaction answer: %w", err)
	}
	if err := json.Unmarshal(exactJSON, &answer); err != nil {
		return InteractionAnswerDocument{}, fmt.Errorf("aauth: decode interaction answer: %w", err)
	}
	members, err := interactionMembers(exactJSON)
	if err != nil {
		return InteractionAnswerDocument{}, err
	}
	if err := requireJSONMemberString(members, "answer"); err != nil {
		return InteractionAnswerDocument{}, fmt.Errorf("aauth: interaction answer: %w", err)
	}
	if !utf8.ValidString(answer.Answer) {
		return InteractionAnswerDocument{}, errors.New("aauth: interaction answer must be valid UTF-8")
	}
	return InteractionAnswerDocument{
		ExactJSON: append([]byte(nil), exactJSON...), Answer: answer,
	}, nil
}

func interactionMembers(exactJSON []byte) (map[string]json.RawMessage, error) {
	var members map[string]json.RawMessage
	if err := json.Unmarshal(exactJSON, &members); err != nil || members == nil {
		return nil, errors.New("aauth: interaction JSON input must be one object")
	}
	return members, nil
}

func requireJSONMemberString(members map[string]json.RawMessage, name string) error {
	raw, present := members[name]
	if !present || !jsonMemberIsString(raw) {
		return fmt.Errorf("%s is required and must be a string", name)
	}
	return nil
}

func jsonMemberIsString(raw json.RawMessage) bool {
	value := bytes.TrimSpace(raw)
	if len(value) == 0 || value[0] != '"' {
		return false
	}
	var decoded string
	return json.Unmarshal(value, &decoded) == nil
}
