package resource

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/events"
	"gitlab.com/sidecat-dev/aauth-go/internal/httpapi"
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

var (
	// ErrProtectedSubscriptionNotFound reports an unknown ticket or one bound
	// to another key. The handler answers 404 for both.
	ErrProtectedSubscriptionNotFound = errors.New("resource: protected subscription ticket not found")
	// ErrProtectedSubscriptionExpired reports an unused ticket past its
	// deadline. The handler answers 410.
	ErrProtectedSubscriptionExpired = errors.New("resource: protected subscription ticket expired")
	// ErrProtectedSubscriptionConflict reports a used ticket presented with a
	// different registration, or retained state that changed. The handler
	// answers 409.
	ErrProtectedSubscriptionConflict = errors.New("resource: protected subscription ticket conflicts with retained state")
)

// ProtectedSubscriptionConfig adds Resource-issued one-use ticket URLs to the
// public Events service.
type ProtectedSubscriptionConfig struct {
	EndpointPrefix        string
	NewTicketID           func() string
	MaximumTicketLifetime time.Duration
	Register              func(context.Context, ProtectedSubscriptionRequest) (PublicSubscriptionDecision, error)
}

type protectedSubscriptionConfig struct {
	prefix      *url.URL
	newTicketID func() string
	maxLifetime time.Duration
	register    func(context.Context, ProtectedSubscriptionRequest) (PublicSubscriptionDecision, error)
	store       ProtectedSubscriptionStore
}

// ProtectedSubscriptionTicketRequest carries the verified prior interaction
// selected by the Resource application. ConfirmationKey is the key the
// Resource verified on that interaction: the cnf.jwk of the person token or
// auth token it accepted (Confirmation in PersonPrincipal or AuthPrincipal).
// The ticket is bound to that key's JWK Thumbprint, not to an Agent
// identifier, because none of those tokens carries one.
type ProtectedSubscriptionTicketRequest struct {
	ConfirmationKey jose.JWK
	Context         []byte
	Lifetime        time.Duration
}

// IssuedProtectedSubscriptionTicket is the retained opaque URL and deadline.
type IssuedProtectedSubscriptionTicket struct {
	URL       string
	ExpiresAt time.Time
}

// ProtectedSubscriptionTicket is the complete Resource-retained authorization
// context for one opaque ticket URL. KeyThumbprint is the RFC 7638 SHA-256
// JWK Thumbprint of the key that established the ticket; only a subscribe
// token whose cnf.jwk has the same thumbprint can use it.
type ProtectedSubscriptionTicket struct {
	ID                 string
	Resource           string
	KeyThumbprint      string
	Context            []byte
	CreatedAt          time.Time
	ExpiresAt          time.Time
	UsedAt             time.Time
	RegistrationSHA256 [sha256.Size]byte
}

// ProtectedSubscriptionRequest contains the verified ticket, subscribe token,
// and opaque registration parameters available to Resource policy.
type ProtectedSubscriptionRequest struct {
	Ticket      ProtectedSubscriptionTicket
	Token       events.SubscribeTokenClaims
	Parameters  []byte
	ContentType string
	VerifiedAt  time.Time
}

// ProtectedSubscriptionStore owns tickets and Resource subscriptions in one
// atomic boundary. LoadProtectedSubscriptionTicket receives the ticket ID,
// the JWK Thumbprint of the calling subscribe token's cnf.jwk, and the
// verification time; it must cloak a thumbprint mismatch as not found and
// report an unused ticket at or past its deadline as expired. Commit must
// atomically consume an unused, unexpired expected ticket and retain the
// candidate subscription. Load must keep a successfully used ticket available
// after its issuance expiry so an exact retry can recover the first retained
// subscription; changed input returns ErrProtectedSubscriptionConflict.
type ProtectedSubscriptionStore interface {
	EventSubscriptionStore
	CreateProtectedSubscriptionTicket(context.Context, ProtectedSubscriptionTicket) error
	LoadProtectedSubscriptionTicket(context.Context, string, string, time.Time) (ProtectedSubscriptionTicket, error)
	CommitProtectedSubscription(context.Context, ProtectedSubscriptionTicket, EventSubscription) (EventSubscription, error)
}

func (service *EventService) configureProtectedSubscriptions(config *ProtectedSubscriptionConfig) error {
	if config == nil {
		return nil
	}
	if config.NewTicketID == nil || config.Register == nil {
		return errors.New("resource: protected Events requires ticket ID source and policy")
	}
	store, ok := service.store.(ProtectedSubscriptionStore)
	if !ok {
		return errors.New("resource: protected Events requires a protected subscription store")
	}
	prefix, err := parseExactHTTPSEndpoint(config.EndpointPrefix)
	if err != nil {
		return fmt.Errorf("resource: protected subscription endpoint prefix: %w", err)
	}
	issuer, _ := url.Parse(service.issuer)
	if !sameOrigin(prefix, issuer) || !strings.HasSuffix(prefix.Path, "/") {
		return errors.New("resource: protected subscription endpoint prefix must use the Resource origin and end in slash")
	}
	maximum := config.MaximumTicketLifetime
	if maximum == 0 {
		maximum = 5 * time.Minute
	}
	if maximum < time.Second || maximum%time.Second != 0 {
		return errors.New("resource: protected subscription maximum lifetime must be positive whole seconds")
	}
	service.protected = &protectedSubscriptionConfig{
		prefix: prefix, newTicketID: config.NewTicketID, maxLifetime: maximum,
		register: config.Register, store: store,
	}
	service.protectedHandler = http.HandlerFunc(service.handleProtectedSubscription)
	return nil
}

// ProtectedSubscriptionHandler returns the one-use ticket registration
// handler. The host mounts it at EndpointPrefix.
func (service *EventService) ProtectedSubscriptionHandler() http.Handler {
	if service == nil || service.protectedHandler == nil {
		return http.NotFoundHandler()
	}
	return service.protectedHandler
}

// IssueProtectedSubscriptionTicket retains one ticket before returning its
// opaque URL. The Resource application calls this only after an authenticated
// interaction has established Agent and context.
func (service *EventService) IssueProtectedSubscriptionTicket(
	ctx context.Context,
	request ProtectedSubscriptionTicketRequest,
) (IssuedProtectedSubscriptionTicket, error) {
	if service == nil || service.protected == nil {
		return IssuedProtectedSubscriptionTicket{}, errors.New("resource: protected Events is not configured")
	}
	if ctx == nil {
		return IssuedProtectedSubscriptionTicket{}, errors.New("resource: protected ticket context is required")
	}
	thumbprint, err := request.ConfirmationKey.Thumbprint()
	if err != nil {
		return IssuedProtectedSubscriptionTicket{}, fmt.Errorf("resource: protected ticket confirmation key: %w", err)
	}
	if len(request.Context) == 0 {
		return IssuedProtectedSubscriptionTicket{}, errors.New("resource: protected ticket authorization context is required")
	}
	if request.Lifetime < time.Second || request.Lifetime%time.Second != 0 || request.Lifetime > service.protected.maxLifetime {
		return IssuedProtectedSubscriptionTicket{}, errors.New("resource: protected ticket lifetime is outside the configured bound")
	}
	id := service.protected.newTicketID()
	if strings.TrimSpace(id) == "" || id != strings.TrimSpace(id) || strings.Contains(id, "/") {
		return IssuedProtectedSubscriptionTicket{}, errors.New("resource: protected ticket ID source returned an invalid path segment")
	}
	now := service.clock.Now().UTC().Truncate(time.Second)
	ticket := ProtectedSubscriptionTicket{
		ID: id, Resource: service.issuer, KeyThumbprint: thumbprint,
		Context:   append([]byte(nil), request.Context...),
		CreatedAt: now, ExpiresAt: now.Add(request.Lifetime),
	}
	if err := validateProtectedSubscriptionTicket(ticket); err != nil {
		return IssuedProtectedSubscriptionTicket{}, err
	}
	if err := service.protected.store.CreateProtectedSubscriptionTicket(ctx, cloneProtectedSubscriptionTicket(ticket)); err != nil {
		return IssuedProtectedSubscriptionTicket{}, err
	}
	return IssuedProtectedSubscriptionTicket{
		URL: service.protected.prefix.String() + url.PathEscape(id), ExpiresAt: ticket.ExpiresAt,
	}, nil
}

func (service *EventService) handleProtectedSubscription(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		response.Header().Set("Allow", http.MethodPost)
		httpapi.WriteProblem(response, http.StatusMethodNotAllowed, "invalid_request", errors.New("resource: protected event registration requires POST"))
		return
	}
	ticketID, err := service.protectedTicketID(request)
	if err != nil {
		httpapi.WriteProblem(response, http.StatusNotFound, "event_ticket_not_found", err)
		return
	}
	if request.Header.Get("Content-Type") != "" {
		if _, _, err := mime.ParseMediaType(request.Header.Get("Content-Type")); err != nil {
			httpapi.WriteProblem(response, http.StatusBadRequest, "invalid_request", errors.New("resource: event registration content type is invalid"))
			return
		}
	}
	verified, ok := service.verifySubscribeRegistration(response, request)
	if !ok {
		return
	}
	compact, claims, proof := verified.compact, verified.claims, verified.proof
	// The subscribe token's cnf.jwk is the key that signed this request; its
	// thumbprint must equal the one recorded when the ticket was issued.
	thumbprint, err := proof.PublicKey().Thumbprint()
	if err != nil {
		writeEventSignatureProblem(response, signaturekey.NewError(signaturekey.ErrorInvalidKey, err))
		return
	}
	ticket, err := service.protected.store.LoadProtectedSubscriptionTicket(
		request.Context(), ticketID, thumbprint, proof.VerifiedAt(),
	)
	if err != nil {
		service.writeProtectedSubscriptionError(response, err)
		return
	}
	if ticket.KeyThumbprint != thumbprint {
		service.writeProtectedSubscriptionError(response, ErrProtectedSubscriptionNotFound)
		return
	}
	if ticket.UsedAt.IsZero() && !proof.VerifiedAt().Before(ticket.ExpiresAt) {
		service.writeProtectedSubscriptionError(response, ErrProtectedSubscriptionExpired)
		return
	}
	if validateProtectedSubscriptionTicket(ticket) != nil || ticket.ID != ticketID || ticket.Resource != service.issuer {
		httpapi.WriteProblem(response, http.StatusInternalServerError, "server_error", ErrProtectedSubscriptionConflict)
		return
	}
	registrationSHA256 := protectedEventRegistrationSHA256(
		ticketID, compact, request.Header.Get("Content-Type"), proof.ExactBody(),
	)
	if !ticket.UsedAt.IsZero() {
		if ticket.RegistrationSHA256 != registrationSHA256 {
			service.writeProtectedSubscriptionError(response, ErrProtectedSubscriptionConflict)
			return
		}
		retained, err := service.protected.store.Load(request.Context(), EventSubscriptionRef{
			AgentProvider: claims.Issuer, EventID: claims.EventID,
		})
		if err != nil || retained.EventID != claims.EventID || retained.AgentProvider != claims.Issuer ||
			retained.Agent != claims.Subject || retained.SubscribeTokenSHA256 != sha256.Sum256([]byte(compact)) ||
			retained.RegistrationSHA256 != registrationSHA256 {
			httpapi.WriteProblem(response, http.StatusInternalServerError, "server_error", ErrProtectedSubscriptionConflict)
			return
		}
		response.Header().Set("Cache-Control", "no-store")
		response.WriteHeader(http.StatusOK)
		return
	}
	decision, err := service.protected.register(request.Context(), ProtectedSubscriptionRequest{
		Ticket: cloneProtectedSubscriptionTicket(ticket), Token: claims,
		Parameters: append([]byte(nil), proof.ExactBody()...), ContentType: request.Header.Get("Content-Type"),
		VerifiedAt: proof.VerifiedAt(),
	})
	if err != nil {
		if errors.Is(err, ErrEventSubscriptionDenied) {
			httpapi.WriteProblem(response, http.StatusForbidden, "event_subscription_denied", err)
		} else {
			httpapi.WriteProblem(response, http.StatusInternalServerError, "server_error", err)
		}
		return
	}
	if !decision.ExpiresAt.IsZero() && !decision.ExpiresAt.After(proof.VerifiedAt()) {
		httpapi.WriteProblem(response, http.StatusInternalServerError, "server_error", errors.New("resource: subscription policy returned a nonfuture expiry"))
		return
	}
	record := EventSubscription{
		EventID: claims.EventID, AgentProvider: claims.Issuer, Agent: claims.Subject,
		MaxUses: claims.MaxUses, SubscribeTokenSHA256: sha256.Sum256([]byte(compact)),
		RegistrationSHA256: registrationSHA256,
		Parameters:         append([]byte(nil), proof.ExactBody()...), ContentType: request.Header.Get("Content-Type"),
		RegisteredAt: proof.VerifiedAt(), ExpiresAt: decision.ExpiresAt.UTC().Truncate(time.Second),
	}
	retained, err := service.protected.store.CommitProtectedSubscription(
		request.Context(), cloneProtectedSubscriptionTicket(ticket), cloneEventSubscription(record),
	)
	if err != nil {
		service.writeProtectedSubscriptionError(response, err)
		return
	}
	if retained.EventID != record.EventID || retained.AgentProvider != record.AgentProvider ||
		retained.RegistrationSHA256 != record.RegistrationSHA256 {
		httpapi.WriteProblem(response, http.StatusInternalServerError, "server_error", errors.New("resource: protected store returned a mismatched registration"))
		return
	}
	response.Header().Set("Cache-Control", "no-store")
	response.WriteHeader(http.StatusOK)
}

func (service *EventService) protectedTicketID(request *http.Request) (string, error) {
	if service == nil || service.protected == nil || request == nil || request.URL == nil {
		return "", ErrProtectedSubscriptionNotFound
	}
	authority := request.Host
	if authority == "" {
		authority = request.URL.Host
	}
	prefix := service.protected.prefix
	if request.URL.Scheme != "" && !strings.EqualFold(request.URL.Scheme, prefix.Scheme) ||
		!strings.EqualFold(authority, prefix.Host) || request.URL.RawQuery != "" ||
		!strings.HasPrefix(request.URL.EscapedPath(), prefix.EscapedPath()) {
		return "", ErrProtectedSubscriptionNotFound
	}
	escaped := strings.TrimPrefix(request.URL.EscapedPath(), prefix.EscapedPath())
	if escaped == "" || strings.Contains(escaped, "/") {
		return "", ErrProtectedSubscriptionNotFound
	}
	id, err := url.PathUnescape(escaped)
	if err != nil || id == "" || strings.Contains(id, "/") {
		return "", ErrProtectedSubscriptionNotFound
	}
	return id, nil
}

func validateProtectedSubscriptionTicket(ticket ProtectedSubscriptionTicket) error {
	if ticket.ID == "" || ticket.Resource == "" || len(ticket.Context) == 0 ||
		ticket.CreatedAt.IsZero() || !ticket.ExpiresAt.After(ticket.CreatedAt) {
		return ErrProtectedSubscriptionConflict
	}
	if aauth.ValidateServerIdentifier(ticket.Resource) != nil || !validKeyThumbprint(ticket.KeyThumbprint) {
		return ErrProtectedSubscriptionConflict
	}
	used := !ticket.UsedAt.IsZero()
	if used != (ticket.RegistrationSHA256 != [sha256.Size]byte{}) || used &&
		(ticket.UsedAt.Before(ticket.CreatedAt) || !ticket.UsedAt.Before(ticket.ExpiresAt)) {
		return ErrProtectedSubscriptionConflict
	}
	return nil
}

// validKeyThumbprint accepts one canonical unpadded base64url SHA-256 digest.
func validKeyThumbprint(value string) bool {
	digest, err := base64.RawURLEncoding.Strict().DecodeString(value)
	return err == nil && len(digest) == sha256.Size && base64.RawURLEncoding.EncodeToString(digest) == value
}

func cloneProtectedSubscriptionTicket(ticket ProtectedSubscriptionTicket) ProtectedSubscriptionTicket {
	ticket.Context = append([]byte(nil), ticket.Context...)
	return ticket
}

func protectedEventRegistrationSHA256(ticketID, compact, contentType string, parameters []byte) [sha256.Size]byte {
	hash := sha256.New()
	for _, part := range [][]byte{[]byte(ticketID), []byte(compact), []byte(contentType), parameters} {
		_, _ = hash.Write(part)
		_, _ = hash.Write([]byte{0})
	}
	var digest [sha256.Size]byte
	copy(digest[:], hash.Sum(nil))
	return digest
}

func (service *EventService) writeProtectedSubscriptionError(response http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrProtectedSubscriptionNotFound):
		httpapi.WriteProblem(response, http.StatusNotFound, "event_ticket_not_found", err)
	case errors.Is(err, ErrProtectedSubscriptionExpired):
		httpapi.WriteProblem(response, http.StatusGone, "event_ticket_expired", err)
	case errors.Is(err, ErrProtectedSubscriptionConflict):
		httpapi.WriteProblem(response, http.StatusConflict, "event_ticket_conflict", err)
	default:
		httpapi.WriteProblem(response, http.StatusInternalServerError, "server_error", err)
	}
}
