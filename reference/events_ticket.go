package reference

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
)

var (
	ErrEventContractNotFound        = errors.New("reference: event contract is not retained")
	ErrEventContractIntegrity       = errors.New("reference: event contract integrity check failed")
	ErrProtectedEventTicketNotFound = errors.New("reference: protected event ticket was not found")
	ErrProtectedEventTicketConflict = errors.New("reference: protected event ticket identity collided")
	ErrProtectedEventTicketMismatch = errors.New("reference: protected event ticket binding does not match")
)

// EventContractStore retains exact AsyncAPI bytes by digest through a supplied
// future deadline. FileR3DocumentStore also satisfies this small interface.
type EventContractStore interface {
	Retain(context.Context, string, []byte, time.Time) error
	Load(context.Context, string) ([]byte, error)
}

type memoryEventContractEntry struct {
	exact       []byte
	retainUntil time.Time
}

// MemoryEventContractStore is a process-local qualification implementation.
type MemoryEventContractStore struct {
	mu      sync.Mutex
	clock   aauth.Clock
	entries map[string]memoryEventContractEntry
}

func NewMemoryEventContractStore(clock aauth.Clock) *MemoryEventContractStore {
	return &MemoryEventContractStore{clock: clock, entries: make(map[string]memoryEventContractEntry)}
}

func (store *MemoryEventContractStore) Retain(
	ctx context.Context,
	digest string,
	exact []byte,
	retainUntil time.Time,
) error {
	if err := eventContextError(ctx); err != nil {
		return err
	}
	if store == nil || store.clock == nil || digest == "" || !retainUntil.After(store.clock.Now()) {
		return fmt.Errorf("%w: contract retention is invalid", ErrEventContractIntegrity)
	}
	if aauth.R3S256(exact) != digest {
		return ErrEventContractIntegrity
	}
	if _, err := aauth.ParseEventsAsyncAPI(exact); err != nil {
		return fmt.Errorf("%w: %v", ErrEventContractIntegrity, err)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.entries == nil {
		store.entries = make(map[string]memoryEventContractEntry)
	}
	if existing, ok := store.entries[digest]; ok {
		if !bytes.Equal(existing.exact, exact) {
			return ErrEventContractIntegrity
		}
		if existing.retainUntil.After(retainUntil) {
			retainUntil = existing.retainUntil
		}
	}
	store.entries[digest] = memoryEventContractEntry{
		exact: append([]byte(nil), exact...), retainUntil: retainUntil.UTC(),
	}
	return nil
}

func (store *MemoryEventContractStore) Load(ctx context.Context, digest string) ([]byte, error) {
	if err := eventContextError(ctx); err != nil {
		return nil, err
	}
	if store == nil || store.clock == nil || digest == "" {
		return nil, ErrEventContractNotFound
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	entry, ok := store.entries[digest]
	if !ok || !entry.retainUntil.After(store.clock.Now()) {
		delete(store.entries, digest)
		return nil, ErrEventContractNotFound
	}
	if aauth.R3S256(entry.exact) != digest {
		return nil, ErrEventContractIntegrity
	}
	return append([]byte(nil), entry.exact...), nil
}

// ProtectedEventTicket is resource-owned durable authorization created by one
// prior authenticated operation. TicketDigest identifies the opaque URL
// capability without retaining the capability itself.
type ProtectedEventTicket struct {
	TicketDigest     string    `json:"ticket_digest"`
	Resource         string    `json:"resource"`
	Agent            string    `json:"agent"`
	AuthorizedMethod string    `json:"authorized_method"`
	AuthorizedPath   string    `json:"authorized_path"`
	ResourceRevision string    `json:"resource_revision"`
	ContractDigest   string    `json:"contract_digest"`
	OperationID      string    `json:"operation_id"`
	MessageID        string    `json:"message_id"`
	ExpiresAt        time.Time `json:"expires_at"`
	ActiveUntil      time.Time `json:"active_until"`
}

// ProtectedEventTicketConsumption carries the current authenticated handler's
// resource and agent assertions plus the new AP identity and registration
// time. The store atomically compares those assertions while loading every
// subscription authority binding from the ticket itself.
type ProtectedEventTicketConsumption struct {
	TicketDigest string    `json:"ticket_digest"`
	Resource     string    `json:"resource"`
	APIssuer     string    `json:"ap_issuer"`
	EventID      string    `json:"event_id"`
	Agent        string    `json:"agent"`
	RegisteredAt time.Time `json:"registered_at"`
}

type ProtectedEventTicketRequest struct {
	Agent            string
	ResourceRevision string
	ActiveUntil      time.Time
}

type ProtectedEventTicketGrant struct {
	URL            string `json:"url"`
	ContractDigest string `json:"contract_s256"`
	OperationID    string `json:"operation_id"`
	MessageID      string `json:"message_id"`
}

// ProtectedEventRegistration is the exact, already-authenticated input to an
// optional deployment validator. TicketDigest is safe to retain; the raw URL
// capability is deliberately excluded.
type ProtectedEventRegistration struct {
	TicketDigest string
	Resource     string
	Agent        string
	APIssuer     string
	EventID      string
	ContentType  string
	Body         []byte
}

// ProtectedEventOperationResult asks the already-authenticated Resource
// handler to issue a ticket and render the application response containing it.
type ProtectedEventOperationResult struct {
	Ticket   ProtectedEventTicketRequest
	Response func(ProtectedEventTicketGrant) (any, error)
}

func protectedEventTicketDigest(raw string) string {
	digest := sha256.Sum256([]byte(raw))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

func validateProtectedEventTicket(ticket ProtectedEventTicket) error {
	if decoded, err := base64.RawURLEncoding.DecodeString(ticket.TicketDigest); err != nil || len(decoded) != sha256.Size {
		return fmt.Errorf("%w: ticket digest is invalid", ErrEventRecordInvalid)
	}
	if err := aauth.ValidateServerIdentifier(ticket.Resource); err != nil {
		return fmt.Errorf("%w: ticket resource is invalid", ErrEventRecordInvalid)
	}
	if err := aauth.ValidateAgentIdentifier(ticket.Agent); err != nil {
		return fmt.Errorf("%w: ticket agent is invalid", ErrEventRecordInvalid)
	}
	if ticket.AuthorizedMethod == "" || ticket.AuthorizedMethod != strings.ToUpper(ticket.AuthorizedMethod) ||
		strings.ContainsAny(ticket.AuthorizedMethod, " \t\r\n") ||
		validatePublicRoutePath(ticket.AuthorizedPath) != nil || ticket.ResourceRevision == "" ||
		ticket.ExpiresAt.IsZero() ||
		!ticket.ActiveUntil.After(ticket.ExpiresAt) {
		return fmt.Errorf("%w: ticket binding is incomplete", ErrEventRecordInvalid)
	}
	if err := validateEventContractBinding(ticket.ContractDigest, ticket.OperationID, ticket.MessageID); err != nil {
		return fmt.Errorf("%w: ticket contract binding is invalid", ErrEventRecordInvalid)
	}
	return nil
}

func validateProtectedEventTicketConsumption(input ProtectedEventTicketConsumption) error {
	if input.TicketDigest == "" || input.EventID == "" || input.RegisteredAt.IsZero() ||
		aauth.ValidateServerIdentifier(input.Resource) != nil ||
		aauth.ValidateServerIdentifier(input.APIssuer) != nil ||
		aauth.ValidateAgentIdentifier(input.Agent) != nil {
		return fmt.Errorf("%w: ticket consumption is invalid", ErrEventRecordInvalid)
	}
	return nil
}

var _ EventContractStore = (*MemoryEventContractStore)(nil)
