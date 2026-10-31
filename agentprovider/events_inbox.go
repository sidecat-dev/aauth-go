package agentprovider

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"

	"gitlab.com/sidecat-dev/aauth-go/events"
)

// ErrEventInboxNotReadable reports an Events store that does not implement
// EventInboxReader, so the Agent Provider has no read path to its Agents.
var ErrEventInboxNotReadable = errors.New("aauth: event inbox store has no read path")

// EventInboxReader is the read half of the Agent Provider inbox: the path by
// which accepted deliveries leave the AP for their Agent. Events leaves the
// transport to the AP and Agent, but whatever carries them must hand the
// Agent the event token and the body bytes exactly as the Resource sent them,
// so the Agent can check body_s256. An EventInboxStore that also implements
// this interface lets Server.PendingEvents serve that path.
//
// PendingEvents returns independent copies of the deliveries accepted for
// agent and not yet acknowledged, oldest first. A delivery appears once: an
// exact replay that AcceptEvent reported as Duplicate is not queued again.
//
// AcknowledgeEvent removes one delivery from agent's pending list after the
// host has handed it over. A delivery that is not pending, or that belongs to
// another Agent, is left alone and is not an error. Acknowledging does not
// forget the delivery: an exact replay of it is still a duplicate.
type EventInboxReader interface {
	PendingEvents(ctx context.Context, agent string) ([]EventDelivery, error)
	AcknowledgeEvent(ctx context.Context, agent string, fingerprint events.DeliveryFingerprint) error
}

// PendingEvents returns the deliveries waiting for agent, oldest first, for
// the host's AP-to-Agent transport. Each one is checked against what the AP
// recorded when it accepted it: the Agent, the token and payload digests,
// and the delivery fingerprint over token, content type, and payload. A
// delivery that fails any check is refused rather than handed over, because
// an Agent given altered bytes would refuse them anyway and the fault would
// be lost. Pass Token, Payload, and ContentType to the Agent unchanged; its
// Client.AcceptEvent verifies the token and body_s256.
func (server *Server) PendingEvents(ctx context.Context, agent string) ([]EventDelivery, error) {
	reader, err := server.eventInboxReader(ctx, agent)
	if err != nil {
		return nil, err
	}
	pending, err := reader.PendingEvents(ctx, agent)
	if err != nil {
		return nil, err
	}
	checked := make([]EventDelivery, 0, len(pending))
	for index, delivery := range pending {
		if err := checkRetainedEventDelivery(agent, delivery); err != nil {
			return nil, fmt.Errorf("aauth: pending event %d: %w", index, err)
		}
		delivery.Payload = append([]byte(nil), delivery.Payload...)
		checked = append(checked, delivery)
	}
	return checked, nil
}

// AcknowledgeEvent records that the host handed one pending delivery to
// agent, so PendingEvents stops returning it. Acknowledge after the Agent's
// Client.AcceptEvent succeeds, not before: a delivery acknowledged and then
// lost in transport cannot be read again.
func (server *Server) AcknowledgeEvent(ctx context.Context, agent string, fingerprint events.DeliveryFingerprint) error {
	reader, err := server.eventInboxReader(ctx, agent)
	if err != nil {
		return err
	}
	return reader.AcknowledgeEvent(ctx, agent, fingerprint)
}

func (server *Server) eventInboxReader(ctx context.Context, agent string) (EventInboxReader, error) {
	if server == nil || server.events == nil {
		return nil, errors.New("aauth: Agent Provider Events is not configured")
	}
	if ctx == nil {
		return nil, errors.New("aauth: event inbox context is required")
	}
	if agent == "" {
		return nil, errors.New("aauth: event inbox Agent is required")
	}
	reader, ok := server.events.store.(EventInboxReader)
	if !ok {
		return nil, ErrEventInboxNotReadable
	}
	return reader, nil
}

func checkRetainedEventDelivery(agent string, delivery EventDelivery) error {
	switch {
	case delivery.Agent != agent:
		return errors.New("store returned a delivery for another Agent")
	case delivery.Token == "" || delivery.EventID == "" || delivery.Resource == "":
		return errors.New("store returned an incomplete delivery")
	case sha256.Sum256([]byte(delivery.Token)) != delivery.TokenSHA256:
		return errors.New("retained event token does not match its accepted digest")
	case sha256.Sum256(delivery.Payload) != delivery.PayloadSHA256:
		return errors.New("retained event payload does not match its accepted digest")
	case events.Fingerprint(delivery.Token, delivery.ContentType, delivery.Payload) != delivery.Fingerprint:
		return errors.New("retained event delivery does not match its fingerprint")
	}
	return nil
}
