package supervisionserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/internal/interaction"
	"gitlab.com/sidecat-dev/aauth-go/supervision"
)

var (
	// ErrInvalidCode reports an interaction code that does not match, was
	// already consumed, or belongs to an interaction that failed.
	ErrInvalidCode = errors.New("supervisionserver: interaction code is invalid or consumed")
	// ErrExpired reports a pending connect or supervision request whose
	// deadline has passed.
	ErrExpired = errors.New("supervisionserver: the request expired")
)

// ConnectRequest is a connect for a pair not yet connected: the verified
// Person Server, the person's directed sub, and the tenant the Person Server
// asserts, if any.
type ConnectRequest struct {
	PersonServer string
	Subject      string
	Tenant       string
}

// ConnectResult is the connect policy's answer. Accept connects the pair at
// once, recording Account. Interaction asks the person to confirm the Person
// Server first. A result with neither refuses this Person Server for this
// person with 403 unsupported_iss.
type ConnectResult struct {
	Accept      bool
	Account     string
	Interaction *ConnectInteraction
}

// ConnectInteraction asks the person to confirm the Person Server at the
// host's interaction page. URL is an https URL without query or fragment; the
// person visits {URL}/{reference}?code={code}. Lifetime and RetryAfter are
// whole seconds; zero selects DefaultPendingLifetime and DefaultRetryAfter.
type ConnectInteraction struct {
	URL        string
	Lifetime   time.Duration
	RetryAfter time.Duration
}

// ConnectConfirmation is what the host shows the person before they confirm:
// the connecting Person Server's issuer and name, and the code they
// presented, so they can recognize a connect they did not start. The host
// must show PersonServer and PersonServerName. PersonServerName is read from
// the Person Server's metadata when the Config.KeyResolver can fetch it, as
// signaturekey.HTTPKeyResolver can; otherwise it is empty and the host reads
// the metadata itself. It is the Person Server's own claim. Reference names
// the pending connect for ConfirmConnect and DeclineConnect.
type ConnectConfirmation struct {
	Reference        string
	PersonServer     string
	PersonServerName string
	Subject          string
	Tenant           string
	Code             string
	ExpiresAt        time.Time
}

// metadataFetcher is implemented by key resolvers that can return a server's
// metadata document.
type metadataFetcher interface {
	FetchMetadata(ctx context.Context, issuer, document string) ([]byte, error)
}

// personServerName returns the name the Person Server's metadata gives, or
// empty when it cannot be read.
func (server *Server) personServerName(ctx context.Context, personServer string) string {
	fetcher, ok := server.keyResolver.(metadataFetcher)
	if !ok {
		return ""
	}
	document, err := fetcher.FetchMetadata(ctx, personServer, aauth.PersonDiscoveryDocument)
	if err != nil {
		return ""
	}
	var metadata struct {
		Issuer string `json:"issuer"`
		Name   string `json:"name"`
	}
	if json.Unmarshal(document, &metadata) != nil || metadata.Issuer != personServer {
		return ""
	}
	return metadata.Name
}

func (server *Server) handleConnect(response http.ResponseWriter, request *http.Request) {
	personServer, _, body, ok := server.authenticate(response, request, true)
	if !ok {
		return
	}
	connect, err := supervision.DecodeConnectRequest(body)
	if err != nil {
		writeProblem(response, supervision.ErrorInvalidRequest, err)
		return
	}
	ctx := request.Context()
	if connect.Action == supervision.ActionDisconnect {
		if err := server.store.DeleteConnection(ctx, personServer, connect.Subject); err != nil {
			writeProblem(response, supervision.ErrorServerError, err)
			return
		}
		writeStatus(response, http.StatusOK, "disconnected")
		return
	}
	if _, err := server.store.LoadConnection(ctx, personServer, connect.Subject); err == nil {
		writeConnected(response)
		return
	} else if !errors.Is(err, ErrNotFound) {
		writeProblem(response, supervision.ErrorServerError, err)
		return
	}
	result, err := server.connect(ctx, ConnectRequest{PersonServer: personServer, Subject: connect.Subject, Tenant: connect.Tenant})
	if err != nil {
		writeProblem(response, supervision.ErrorServerError, err)
		return
	}
	now := server.clock.Now().UTC()
	switch {
	case result.Accept && result.Interaction != nil:
		writeProblem(response, supervision.ErrorServerError, errors.New("supervisionserver: connect policy both accepted and asked for interaction"))
	case result.Accept:
		connection := Connection{
			PersonServer: personServer, Subject: connect.Subject, Tenant: connect.Tenant,
			Account: result.Account, ConnectedAt: now,
		}
		if err := server.store.PutConnection(ctx, connection); err != nil {
			writeProblem(response, supervision.ErrorServerError, err)
			return
		}
		writeConnected(response)
	case result.Interaction != nil:
		pending, err := server.beginConnect(ctx, personServer, connect, *result.Interaction, now)
		if err != nil {
			writeProblem(response, supervision.ErrorServerError, err)
			return
		}
		writeConnectPending(response, pending)
	default:
		writeProblem(response, supervision.ErrorUnsupportedIss, errors.New("supervisionserver: connect policy refused the person server"))
	}
}

// beginConnect creates the pending connect, or returns the one still live
// for the same pair.
func (server *Server) beginConnect(
	ctx context.Context,
	personServer string,
	connect supervision.ConnectRequest,
	policy ConnectInteraction,
	now time.Time,
) (PendingConnect, error) {
	lifetime, retryAfter := policy.Lifetime, policy.RetryAfter
	if lifetime == 0 {
		lifetime = DefaultPendingLifetime
	}
	if retryAfter == 0 {
		retryAfter = DefaultRetryAfter
	}
	if lifetime <= 0 || !validWholeSeconds(lifetime, MaximumPendingLifetime) || !validWholeSeconds(retryAfter, maximumRetryAfter) {
		return PendingConnect{}, errors.New("supervisionserver: connect interaction lifetime and retry interval must be whole seconds within bounds")
	}
	for attempt := 0; attempt < maximumTransitionAttempts; attempt++ {
		id, err := interaction.GeneratePendingReference(nil)
		if err != nil {
			return PendingConnect{}, fmt.Errorf("supervisionserver: generate pending reference: %w", err)
		}
		code, err := interaction.GenerateCode(nil)
		if err != nil {
			return PendingConnect{}, fmt.Errorf("supervisionserver: generate interaction code: %w", err)
		}
		interactionURL, err := interactionPage(policy.URL, id)
		if err != nil {
			return PendingConnect{}, err
		}
		if _, err := aauth.FormatInteractionRequirement(aauth.InteractionRequirement{URL: interactionURL, Code: code}); err != nil {
			return PendingConnect{}, fmt.Errorf("supervisionserver: connect interaction: %w", err)
		}
		pending, err := server.store.CreatePendingConnect(ctx, PendingConnect{
			ID: id, PersonServer: personServer, Subject: connect.Subject, Tenant: connect.Tenant,
			URL: interactionURL, Code: code, State: ConnectWaiting,
			CreatedAt: now, ExpiresAt: now.Add(lifetime), RetryAfter: retryAfter, Revision: 1,
		}, now)
		if errors.Is(err, ErrConflict) {
			continue
		}
		if err != nil {
			return PendingConnect{}, err
		}
		if pending.PersonServer != personServer || pending.Subject != connect.Subject || !pending.Live(now) {
			return PendingConnect{}, errors.New("supervisionserver: store returned a different pending connect")
		}
		return pending, nil
	}
	return PendingConnect{}, errors.New("supervisionserver: could not allocate a pending connect")
}

func interactionPage(base, id string) (string, error) {
	parsed, err := url.Parse(base)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" {
		return "", errors.New("supervisionserver: connect interaction URL must be https without query or fragment")
	}
	parsed.Path = strings.TrimRight(parsed.Path, "/") + "/" + id
	parsed.RawPath = ""
	return parsed.String(), nil
}

func (server *Server) handleConnectPoll(response http.ResponseWriter, request *http.Request) {
	personServer, _, _, ok := server.authenticate(response, request, false)
	if !ok {
		return
	}
	ctx := request.Context()
	pending, err := server.store.LoadPendingConnect(ctx, request.PathValue("id"))
	if errors.Is(err, ErrNotFound) || (err == nil && pending.PersonServer != personServer) {
		writeProblem(response, supervision.ErrorUnknownPending, ErrNotFound)
		return
	}
	if err != nil {
		writeProblem(response, supervision.ErrorServerError, err)
		return
	}
	if _, err := server.store.LoadConnection(ctx, personServer, pending.Subject); err == nil {
		writeConnected(response)
		return
	} else if !errors.Is(err, ErrNotFound) {
		writeProblem(response, supervision.ErrorServerError, err)
		return
	}
	now := server.clock.Now().UTC()
	switch {
	case pending.Live(now):
		writeConnectPending(response, pending)
	case pending.State == ConnectConfirmed:
		writeProblem(response, supervision.ErrorUnknownSub, errors.New("supervisionserver: the pair was disconnected"))
	case pending.State == ConnectDeclined:
		writeStatusProblem(response, http.StatusForbidden, "denied", errors.New("supervisionserver: the person declined"))
	case pending.State == ConnectFailed:
		writeStatusProblem(response, http.StatusGone, "invalid_code", ErrInvalidCode)
	default:
		writeStatusProblem(response, http.StatusRequestTimeout, "expired", ErrExpired)
	}
}

func writeConnected(response http.ResponseWriter) {
	writeStatus(response, http.StatusOK, "connected")
}

// writeStatus answers with a body naming the outcome: connected,
// disconnected or cancelled.
func writeStatus(response http.ResponseWriter, code int, status string) {
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(code)
	_, _ = response.Write([]byte(`{"status":"` + status + `"}`))
}

// writeConnectPending answers 202 with the interaction requirement for as
// long as the connect waits for the person. Its status is interacting once
// the person has presented the code.
func writeConnectPending(response http.ResponseWriter, pending PendingConnect) {
	status := "pending"
	if pending.State != ConnectWaiting {
		status = "interacting"
	}
	requirement, err := aauth.FormatInteractionRequirement(aauth.InteractionRequirement{URL: pending.URL, Code: pending.Code})
	if err != nil {
		writeProblem(response, supervision.ErrorServerError, err)
		return
	}
	response.Header().Set("AAuth-Requirement", requirement)
	response.Header().Set("Location", pendingLocation(ConnectPendingPath, pending.ID))
	response.Header().Set("Retry-After", retryAfterValue(pending.RetryAfter))
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(http.StatusAccepted)
	_, _ = response.Write([]byte(`{"status":"` + status + `"}`))
}

// ConsumeConnectCode correlates the code the person entered at
// {URL}/{reference} with its pending connect and consumes it. The code is not
// authority: the host authenticates the person separately, shows them the
// returned confirmation, and records their answer with ConfirmConnect or
// DeclineConnect. Each wrong code counts against the interaction; after
// MaximumConnectCodeAttempts it fails, and later codes and polls are refused.
func (server *Server) ConsumeConnectCode(ctx context.Context, reference, code string) (ConnectConfirmation, error) {
	if ctx == nil {
		return ConnectConfirmation{}, errors.New("supervisionserver: context is required")
	}
	for attempt := 0; attempt < maximumTransitionAttempts; attempt++ {
		pending, err := server.store.LoadPendingConnect(ctx, reference)
		if err != nil {
			return ConnectConfirmation{}, err
		}
		now := server.clock.Now().UTC()
		if pending.State != ConnectWaiting {
			return ConnectConfirmation{}, ErrInvalidCode
		}
		if !pending.Live(now) {
			return ConnectConfirmation{}, ErrExpired
		}
		after := pending
		after.Revision++
		matched := aauth.MatchInteractionCode(pending.Code, code)
		if matched {
			after.State = ConnectVisited
		} else {
			after.FailedAttempts++
			if after.FailedAttempts >= MaximumConnectCodeAttempts {
				after.State = ConnectFailed
			}
		}
		if err := server.store.ReplacePendingConnect(ctx, pending, after, nil); errors.Is(err, ErrConflict) {
			continue
		} else if err != nil {
			return ConnectConfirmation{}, err
		}
		if !matched {
			return ConnectConfirmation{}, ErrInvalidCode
		}
		return ConnectConfirmation{
			Reference: pending.ID, PersonServer: pending.PersonServer,
			PersonServerName: server.personServerName(ctx, pending.PersonServer), Subject: pending.Subject,
			Tenant: pending.Tenant, Code: pending.Code, ExpiresAt: pending.ExpiresAt,
		}, nil
	}
	return ConnectConfirmation{}, ErrConflict
}

// ConfirmConnect records that the person, whom the host has authenticated,
// confirmed the Person Server, and connects the pair with the host's Account
// label. The Person Server's next poll answers 200. A host with its own
// channel to the person may confirm before any code is presented; the code is
// then consumed. Confirming again with the same Account is not an error.
func (server *Server) ConfirmConnect(ctx context.Context, reference, account string) error {
	return server.finishConnect(ctx, reference, ConnectConfirmed, account)
}

// DeclineConnect records that the person refused the Person Server. Its next
// poll answers 403 denied.
func (server *Server) DeclineConnect(ctx context.Context, reference string) error {
	return server.finishConnect(ctx, reference, ConnectDeclined, "")
}

func (server *Server) finishConnect(ctx context.Context, reference string, state ConnectState, account string) error {
	if ctx == nil {
		return errors.New("supervisionserver: context is required")
	}
	for attempt := 0; attempt < maximumTransitionAttempts; attempt++ {
		pending, err := server.store.LoadPendingConnect(ctx, reference)
		if err != nil {
			return err
		}
		now := server.clock.Now().UTC()
		if pending.State == state && pending.Account == account {
			return nil
		}
		if !pending.Live(now) {
			if pending.State == ConnectWaiting || pending.State == ConnectVisited {
				return ErrExpired
			}
			return ErrConflict
		}
		after := pending
		after.State = state
		after.Account = account
		after.Revision++
		var connection *Connection
		if state == ConnectConfirmed {
			connection = &Connection{
				PersonServer: pending.PersonServer, Subject: pending.Subject, Tenant: pending.Tenant,
				Account: account, ConnectedAt: now,
			}
		}
		if err := server.store.ReplacePendingConnect(ctx, pending, after, connection); errors.Is(err, ErrConflict) {
			continue
		} else if err != nil {
			return err
		}
		return nil
	}
	return ErrConflict
}
