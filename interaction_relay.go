package aauth

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"time"
	"unicode/utf8"

	"gitlab.com/sidecat-dev/aauth-go/internal/jsonstrict"
)

// InteractionRelayType identifies an interaction that the Person Server can
// relay to the person. Core defines interaction and payment relays separately
// from question interactions.
type InteractionRelayType string

const (
	InteractionRelayInteraction InteractionRelayType = "interaction"
	InteractionRelayPayment     InteractionRelayType = "payment"
)

// InteractionRelay is the Resource's instruction for an interaction that the
// Person Server may present. Description is untrusted raw Markdown and must be
// sanitized before display.
type InteractionRelay struct {
	Type        InteractionRelayType
	Description string
	URL         string
	Code        string
	MaxWait     time.Duration
	MissionS256 string
}

// InteractionRelayDocument keeps the parsed relay beside the exact JSON bytes
// authenticated by the Agent. Unknown additive members remain untrusted in
// ExactJSON.
type InteractionRelayDocument struct {
	ExactJSON []byte
	Relay     InteractionRelay
}

// InteractionRelayStatus is the Person Server's reported relay state.
type InteractionRelayStatus string

const (
	InteractionRelayPending     InteractionRelayStatus = "pending"
	InteractionRelayInteracting InteractionRelayStatus = "interacting"
)

// InteractionRelayCompletion is the terminal body used by this implementation
// profile after the Person Server stops waiting. Completion of the underlying
// operation is signalled at the Resource's own pending URL.
type InteractionRelayCompletion struct {
	Status InteractionRelayStatus `json:"status"`
}

// InteractionRelayCompletionDocument preserves the exact terminal response.
type InteractionRelayCompletionDocument struct {
	ExactJSON  []byte
	Completion InteractionRelayCompletion
}

type interactionRelayWire struct {
	Type        InteractionRelayType `json:"type"`
	Description string               `json:"description,omitempty"`
	URL         string               `json:"url"`
	Code        string               `json:"code"`
	MaxWait     *int64               `json:"max_wait,omitempty"`
	MissionS256 string               `json:"mission_s256,omitempty"`
}

// Validate checks the source-defined interaction relay members.
func (relay InteractionRelay) Validate() error {
	if relay.Type != InteractionRelayInteraction && relay.Type != InteractionRelayPayment {
		return errors.New("aauth: relay type must be interaction or payment")
	}
	if !utf8.ValidString(relay.Description) {
		return errors.New("aauth: relay description must be valid UTF-8")
	}
	if err := ValidateEndpoint(relay.URL); err != nil {
		return fmt.Errorf("aauth: relay URL: %w", err)
	}
	if _, err := NormalizeInteractionCode(relay.Code); err != nil {
		return fmt.Errorf("aauth: relay code: %w", err)
	}
	if relay.MaxWait < 0 || relay.MaxWait%time.Second != 0 {
		return errors.New("aauth: relay max_wait must be nonnegative whole seconds")
	}
	if relay.MissionS256 != "" {
		if err := ValidateMissionS256(relay.MissionS256); err != nil {
			return fmt.Errorf("aauth: relay mission: %w", err)
		}
	}
	return nil
}

// EncodeInteractionRelay validates and deterministically encodes a relay.
func EncodeInteractionRelay(relay InteractionRelay) (InteractionRelayDocument, error) {
	if err := relay.Validate(); err != nil {
		return InteractionRelayDocument{}, err
	}
	var maxWait *int64
	if relay.MaxWait != 0 {
		seconds := int64(relay.MaxWait / time.Second)
		maxWait = &seconds
	}
	exactJSON, err := json.Marshal(interactionRelayWire{
		Type:        relay.Type,
		Description: relay.Description,
		URL:         relay.URL,
		Code:        relay.Code,
		MaxWait:     maxWait,
		MissionS256: relay.MissionS256,
	})
	if err != nil {
		return InteractionRelayDocument{}, fmt.Errorf("aauth: encode interaction relay: %w", err)
	}
	return InteractionRelayDocument{ExactJSON: exactJSON, Relay: relay}, nil
}

// DecodeInteractionRelay preserves exact bytes and decodes one interaction or
// payment relay. Question-only members are rejected by this focused API.
func DecodeInteractionRelay(exactJSON []byte) (InteractionRelayDocument, error) {
	if !utf8.Valid(exactJSON) {
		return InteractionRelayDocument{}, errors.New("aauth: relay JSON must be valid UTF-8")
	}
	var wire interactionRelayWire
	if err := jsonstrict.RejectCaseVariants(exactJSON, &wire); err != nil {
		return InteractionRelayDocument{}, fmt.Errorf("aauth: decode interaction relay: %w", err)
	}
	if err := json.Unmarshal(exactJSON, &wire); err != nil {
		return InteractionRelayDocument{}, fmt.Errorf("aauth: decode interaction relay: %w", err)
	}
	members, err := interactionMembers(exactJSON)
	if err != nil {
		return InteractionRelayDocument{}, err
	}
	for _, name := range []string{"type", "url", "code"} {
		if err := requireJSONMemberString(members, name); err != nil {
			return InteractionRelayDocument{}, fmt.Errorf("aauth: interaction relay: %w", err)
		}
	}
	if _, present := members["question"]; present {
		return InteractionRelayDocument{}, errors.New("aauth: relay must not contain question")
	}
	if raw, present := members["description"]; present && !jsonMemberIsString(raw) {
		return InteractionRelayDocument{}, errors.New("aauth: relay description must be a string")
	}
	if raw, present := members["mission_s256"]; present {
		if !jsonMemberIsString(raw) || wire.MissionS256 == "" {
			return InteractionRelayDocument{}, errors.New("aauth: relay mission_s256 must be a nonempty string")
		}
	}

	seconds := int64(0)
	if raw, present := members["max_wait"]; present {
		if wire.MaxWait == nil || *wire.MaxWait < 0 ||
			*wire.MaxWait > math.MaxInt64/int64(time.Second) || len(raw) == 0 {
			return InteractionRelayDocument{}, errors.New("aauth: relay max_wait must be nonnegative integer seconds")
		}
		seconds = *wire.MaxWait
	}
	relay := InteractionRelay{
		Type:        wire.Type,
		Description: wire.Description,
		URL:         wire.URL,
		Code:        wire.Code,
		MaxWait:     time.Duration(seconds) * time.Second,
		MissionS256: wire.MissionS256,
	}
	if err := relay.Validate(); err != nil {
		return InteractionRelayDocument{}, err
	}
	return InteractionRelayDocument{
		ExactJSON: append([]byte(nil), exactJSON...),
		Relay:     relay,
	}, nil
}

// EncodeInteractionRelayCompletion validates and deterministically encodes a
// terminal relay state.
func EncodeInteractionRelayCompletion(completion InteractionRelayCompletion) (InteractionRelayCompletionDocument, error) {
	if err := completion.Validate(); err != nil {
		return InteractionRelayCompletionDocument{}, err
	}
	exactJSON, err := json.Marshal(completion)
	if err != nil {
		return InteractionRelayCompletionDocument{}, fmt.Errorf("aauth: encode relay completion: %w", err)
	}
	return InteractionRelayCompletionDocument{ExactJSON: exactJSON, Completion: completion}, nil
}

// DecodeInteractionRelayCompletion preserves exact bytes and decodes a
// terminal relay state.
func DecodeInteractionRelayCompletion(exactJSON []byte) (InteractionRelayCompletionDocument, error) {
	if !utf8.Valid(exactJSON) {
		return InteractionRelayCompletionDocument{}, errors.New("aauth: relay completion must be valid UTF-8")
	}
	var completion InteractionRelayCompletion
	if err := jsonstrict.RejectCaseVariants(exactJSON, &completion); err != nil {
		return InteractionRelayCompletionDocument{}, fmt.Errorf("aauth: decode relay completion: %w", err)
	}
	if err := json.Unmarshal(exactJSON, &completion); err != nil {
		return InteractionRelayCompletionDocument{}, fmt.Errorf("aauth: decode relay completion: %w", err)
	}
	members, err := interactionMembers(exactJSON)
	if err != nil {
		return InteractionRelayCompletionDocument{}, err
	}
	if err := requireJSONMemberString(members, "status"); err != nil {
		return InteractionRelayCompletionDocument{}, fmt.Errorf("aauth: relay completion: %w", err)
	}
	if err := completion.Validate(); err != nil {
		return InteractionRelayCompletionDocument{}, err
	}
	return InteractionRelayCompletionDocument{
		ExactJSON:  append([]byte(nil), exactJSON...),
		Completion: completion,
	}, nil
}

// Validate checks the source-defined relay status.
func (completion InteractionRelayCompletion) Validate() error {
	if completion.Status != InteractionRelayPending && completion.Status != InteractionRelayInteracting {
		return errors.New("aauth: invalid relay completion status")
	}
	return nil
}
