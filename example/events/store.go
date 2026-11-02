package main

import (
	"bytes"
	"context"
	"sync"

	clientagent "gitlab.com/sidecat-dev/aauth-go/agent"
	"gitlab.com/sidecat-dev/aauth-go/events"
)

type agentEventStore struct {
	mu       sync.Mutex
	contexts map[string]clientagent.EventContext
	events   map[events.DeliveryFingerprint]clientagent.AcceptedEvent
}

func newAgentEventStore() *agentEventStore {
	return &agentEventStore{
		contexts: make(map[string]clientagent.EventContext),
		events:   make(map[events.DeliveryFingerprint]clientagent.AcceptedEvent),
	}
}

func (store *agentEventStore) BindContext(_ context.Context, record clientagent.EventContext) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	key := record.Resource + "\x00" + record.EventID
	if retained, ok := store.contexts[key]; ok {
		if retained.SubscribeTokenSHA256 == record.SubscribeTokenSHA256 && bytes.Equal(retained.Context, record.Context) {
			return nil
		}
		return clientagent.ErrEventContextConflict
	}
	record.Context = append([]byte(nil), record.Context...)
	store.contexts[key] = record
	return nil
}

func (store *agentEventStore) AcceptEvent(_ context.Context, candidate clientagent.AcceptedEvent) (clientagent.EventAcceptance, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	contextRecord, ok := store.contexts[candidate.Resource+"\x00"+candidate.EventID]
	if !ok {
		return clientagent.EventAcceptance{}, clientagent.ErrEventContextNotFound
	}
	if retained, ok := store.events[candidate.Fingerprint]; ok {
		if retained.EventToken != candidate.EventToken || !bytes.Equal(retained.Payload, candidate.Payload) ||
			retained.ContentType != candidate.ContentType {
			return clientagent.EventAcceptance{}, clientagent.ErrEventReplayConflict
		}
		contextRecord.Context = append([]byte(nil), contextRecord.Context...)
		return clientagent.EventAcceptance{Context: contextRecord, Duplicate: true}, nil
	}
	candidate.Payload = append([]byte(nil), candidate.Payload...)
	store.events[candidate.Fingerprint] = candidate
	contextRecord.Context = append([]byte(nil), contextRecord.Context...)
	return clientagent.EventAcceptance{Context: contextRecord}, nil
}
