package personserver

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/internal/interaction"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

var (
	// ErrResourceInteractionPending reports a consent decision attempted
	// before the Resource returned the person from its own interaction.
	ErrResourceInteractionPending = errors.New("personserver: the Resource's own interaction has not completed")
	// ErrResourceInteractionRefused reports a Resource interaction URL that is
	// not HTTPS or that egress admission refused. The pending request has
	// ended with server_error.
	ErrResourceInteractionRefused = errors.New("personserver: Resource interaction URL was refused")
	// ErrResourceInteractionCallbackInvalid reports a callback whose per-flow
	// identifier is unknown, already used, or does not match.
	ErrResourceInteractionCallbackInvalid = errors.New("personserver: Resource interaction callback is invalid")
)

// ResourceInteractionConfig accepts three-party Resource tokens that carry an
// interaction claim (Core, Resource-Initiated Interaction). Such a request
// always takes the deferred path: the Person Server answers 202 with its own
// interaction, and the host serves these steps, after authenticating the
// person at each one:
//
//  1. The person arrives at this server's interaction page. The host calls
//     ConsumeAuthorizationInteractionCode, shows its interstitial saying the
//     Resource needs additional permissions, then calls
//     RedirectToResourceInteraction and sends the browser to the result.
//  2. The Resource returns the browser to {CallbackURL}/{reference}/{flow}.
//     The host calls ReceiveResourceInteractionCallback. A callback error ends
//     the request with the mapped polling error; otherwise the host shows its
//     own consent and calls ApproveAuthorizationInteraction or
//     DenyAuthorizationInteraction.
//  3. AuthorizationCallbackURL returns where to send the browser afterwards:
//     the Agent's own callback, with an error when the request did not
//     complete.
//
// The configured deferred authorization store must implement
// ResourceInteractionAuthorizationStore. Call chaining, R3 and mission-bound
// requests that carry the claim are refused with invalid_request, and a
// federated Person Server refuses the claim as invalid_resource_token.
type ResourceInteractionConfig struct {
	// Policy selects this Person Server's interaction page, deadline and
	// polling interval for the request. It runs after the request verified.
	Policy func(context.Context, AuthorizationRequest) (AuthorizationInteractionPolicy, error)
	// CallbackURL is the HTTPS base the Resource returns the person to,
	// without a query or fragment. Each flow uses
	// {CallbackURL}/{reference}/{flow} with a fresh flow value the Agent never
	// sees.
	CallbackURL string
	// Admit is the egress admission policy applied to the Resource's
	// interaction URL before the person is redirected there.
	Admit signaturekey.EgressAdmitter
}

// ResourceInteractionProgress is the mutable state of a Resource's own
// interaction inside one pending authorization. CallbackSHA256 is the digest
// of the per-flow callback identifier; the identifier itself is not retained.
// StartedAt is set when the person is sent to the Resource and CompletedAt
// when the Resource returned the person without an error.
type ResourceInteractionProgress struct {
	CallbackSHA256 [32]byte
	AgentCallback  string
	StartedAt      time.Time
	CompletedAt    time.Time
}

// ResourceInteractionAuthorizationStore is the extension a
// DeferredAuthorizationStore implements to carry a Resource's own interaction
// inside a pending authorization. LoadPendingAuthorization reports the
// progress in PendingAuthorizationSnapshot.ResourceInteraction.
//
// Every method first materializes expiry as the base store does. A reference
// whose record carries no ResourceInteraction returns
// ErrPendingAuthorizationConflict.
//
// StartPendingAuthorizationResourceInteraction requires the record to be
// interacting and not yet started. It retains the progress with StartedAt set
// and leaves the state unchanged. Another start conflicts.
//
// FinishPendingAuthorizationResourceInteraction requires an interacting,
// started and unfinished record whose CallbackSHA256 equals the digest given;
// a different digest returns ErrPendingAuthorizationNotFound. outcome
// AuthorizationPollInteracting retains CompletedAt and leaves the record
// interacting for consent. AuthorizationPollDenied, AuthorizationPollAbandoned,
// AuthorizationPollServerError and AuthorizationPollExpired end the record in
// that state, which the next poll delivers once. A repeat of the same outcome
// is idempotent; any other transition conflicts.
type ResourceInteractionAuthorizationStore interface {
	StartPendingAuthorizationResourceInteraction(context.Context, string, ResourceInteractionProgress, time.Time) error
	FinishPendingAuthorizationResourceInteraction(context.Context, string, [32]byte, AuthorizationPollState, time.Time) error
}

type resourceInteractionConfig struct {
	policy      func(context.Context, AuthorizationRequest) (AuthorizationInteractionPolicy, error)
	callbackURL string
	admit       signaturekey.EgressAdmitter
	store       ResourceInteractionAuthorizationStore
}

func newResourceInteractionConfig(config *ResourceInteractionConfig, store DeferredAuthorizationStore) (*resourceInteractionConfig, error) {
	if config == nil {
		return nil, nil
	}
	if config.Policy == nil || config.Admit == nil {
		return nil, errors.New("personserver: Resource interaction requires a policy and egress admission")
	}
	if err := aauth.ValidateEndpoint(config.CallbackURL); err != nil {
		return nil, fmt.Errorf("personserver: Resource interaction callback URL: %w", err)
	}
	extended, ok := store.(ResourceInteractionAuthorizationStore)
	if store == nil || !ok {
		return nil, errors.New("personserver: Resource interaction requires a deferred authorization store that implements ResourceInteractionAuthorizationStore")
	}
	return &resourceInteractionConfig{
		policy: config.Policy, callbackURL: strings.TrimRight(config.CallbackURL, "/"),
		admit: config.Admit, store: extended,
	}, nil
}

// admitResourceInteractionClaim decides whether this server may continue a
// request whose Resource token carries an interaction claim.
func (server *Server) admitResourceInteractionClaim(
	response http.ResponseWriter,
	resourceToken aauth.ResourceTokenClaims,
	upstream *verifiedUpstreamToken,
	carriesR3 bool,
) bool {
	if resourceToken.Interaction == nil {
		return true
	}
	if server.resourceInteraction == nil || server.authorizationMode != authorizationModePersonServer || carriesR3 {
		writeProblem(response, http.StatusBadRequest, "invalid_resource_token", errors.New("resource-token interaction is not accepted by this Person Server"))
		return false
	}
	if upstream != nil || resourceToken.MissionS256 != "" {
		writeProblem(response, http.StatusBadRequest, "invalid_request", errors.New("personserver: Resource-initiated interaction is not implemented for call chaining or missions"))
		return false
	}
	return true
}

// beginResourceInteraction answers a verified three-party request whose
// Resource token carries an interaction claim with this server's own 202.
func (server *Server) beginResourceInteraction(
	response http.ResponseWriter,
	request *http.Request,
	authorization AuthorizationRequest,
	agent aauth.AgentTokenClaims,
	credentialAgent aauth.AgentTokenClaims,
	resourceToken aauth.ResourceTokenClaims,
	personTokenExpiresAt time.Time,
	createdAt time.Time,
) {
	if !slices.Contains(authorization.Capabilities, "interaction") {
		writeProblem(response, http.StatusForbidden, "user_unreachable", errors.New("Agent did not declare interaction capability"))
		return
	}
	policy, err := server.resourceInteraction.policy(request.Context(), cloneAuthorizationRequest(authorization))
	if err != nil {
		writeAccessPolicyProblem(response, err)
		return
	}
	if err := server.beginAuthorizationInteraction(
		response, request, authorization, agent, credentialAgent, resourceToken, nil, policy, personTokenExpiresAt, createdAt,
	); err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", err)
	}
}

// ResourceInteraction returns the Resource's own interaction this request
// must complete before consent. The bool is false when the Resource token
// carried none.
func (value AuthorizationInteraction) ResourceInteraction() (aauth.ResourceInteraction, bool) {
	if value.kind != authorizationInteractionCorrelated || value.record.ResourceInteraction == (aauth.ResourceInteraction{}) {
		return aauth.ResourceInteraction{}, false
	}
	return value.record.ResourceInteraction, true
}

// RedirectToResourceInteraction checks the Resource's interaction URL and
// returns the URL to send the person to:
// {interaction.url}?code={interaction.code}&callback={CallbackURL}/{reference}/{flow}.
// Call it after ConsumeAuthorizationInteractionCode, once the host has
// authenticated the person and shown its interstitial. agentCallback is the
// callback the person arrived with, from aauth.ParseInteractionVisit, or
// empty; it is retained for AuthorizationCallbackURL.
//
// The interaction URL must be HTTPS and pass egress admission. When it does
// not, the pending request ends with server_error and the error is
// ErrResourceInteractionRefused. The redirect can be made once per request.
func (server *Server) RedirectToResourceInteraction(
	ctx context.Context,
	value AuthorizationInteraction,
	agentCallback string,
) (string, error) {
	if server == nil || server.resourceInteraction == nil {
		return "", errors.New("personserver: Resource interaction is not configured")
	}
	target, ok := value.ResourceInteraction()
	if !ok {
		return "", errors.New("personserver: authorization carries no Resource interaction")
	}
	if agentCallback != "" {
		if err := aauth.ValidateInteractionCallback(agentCallback, true); err != nil {
			return "", err
		}
	}
	now := server.clock.Now().UTC()
	snapshot, err := server.loadAuthorizationInteraction(ctx, value, now)
	if err != nil {
		return "", err
	}
	switch snapshot.State {
	case AuthorizationPollInteracting:
	case AuthorizationPollExpired:
		return "", ErrPendingAuthorizationExpired
	case AuthorizationPollGone, AuthorizationPollCancelled:
		return "", ErrPendingAuthorizationGone
	default:
		return "", ErrPendingAuthorizationConflict
	}
	if !snapshot.ResourceInteraction.StartedAt.IsZero() {
		return "", ErrPendingAuthorizationConflict
	}
	// A withdrawn Resource token ends the request with revoked at the next
	// poll; the person is not sent on to the Resource's flow.
	if err := server.revokedPendingResourceToken(ctx, aauth.TokenReference{
		Issuer: value.record.Resource, JTI: value.record.ResourceTokenJTI,
	}); err != nil {
		return "", err
	}
	// The interaction URL is HTTPS without query or fragment by the time a
	// Resource token verifies; check it again, then ask egress admission.
	refused := validateResourceInteractionURL(target.URL)
	if refused == nil {
		refused = server.resourceInteraction.admit(ctx, target.URL)
	}
	if refused != nil {
		if err := server.FailAuthorizationInteraction(ctx, value); err != nil {
			return "", err
		}
		return "", fmt.Errorf("%w: %w", ErrResourceInteractionRefused, refused)
	}
	flow, err := interaction.GeneratePendingReference(nil)
	if err != nil {
		return "", fmt.Errorf("personserver: generate Resource interaction flow: %w", err)
	}
	callback := server.resourceInteraction.callbackURL + "/" + value.record.ID + "/" + flow
	redirect, err := aauth.FormatInteractionVisitURL(target.URL, target.Code, callback)
	if err != nil {
		return "", err
	}
	progress := ResourceInteractionProgress{
		CallbackSHA256: sha256.Sum256([]byte(flow)), AgentCallback: agentCallback, StartedAt: now,
	}
	if err := server.resourceInteraction.store.StartPendingAuthorizationResourceInteraction(
		ctx, value.record.ID, progress, now,
	); err != nil {
		return "", err
	}
	return redirect, nil
}

// ReceiveResourceInteractionCallback reads the Resource's return to
// {CallbackURL}/{reference}/{flow}; rawQuery is the callback's query without
// its leading "?". Without an error parameter the Resource's flow completed:
// it returns the interaction for the host's own consent step. With one, the
// pending request can no longer complete: it ends with the mapped polling
// error (access_denied as denied, user_abandoned as abandoned,
// interaction_expired as expired, server_error and temporarily_unavailable as
// server_error), and the returned error is the aauth.InteractionCallbackError.
// Either way, AuthorizationCallbackURL then returns the Agent's callback.
func (server *Server) ReceiveResourceInteractionCallback(
	ctx context.Context,
	reference string,
	flow string,
	rawQuery string,
) (AuthorizationInteraction, error) {
	if server == nil || server.resourceInteraction == nil {
		return AuthorizationInteraction{}, errors.New("personserver: Resource interaction is not configured")
	}
	if ctx == nil {
		return AuthorizationInteraction{}, errors.New("personserver: context is required")
	}
	if reference == "" || flow == "" {
		return AuthorizationInteraction{}, ErrResourceInteractionCallbackInvalid
	}
	value, err := server.ResumeAuthorizationInteraction(ctx, reference)
	if err != nil {
		return AuthorizationInteraction{}, err
	}
	if _, ok := value.ResourceInteraction(); !ok {
		return AuthorizationInteraction{}, ErrResourceInteractionCallbackInvalid
	}
	now := server.clock.Now().UTC()
	snapshot, err := server.loadAuthorizationInteraction(ctx, value, now)
	if err != nil {
		return AuthorizationInteraction{}, err
	}
	digest := sha256.Sum256([]byte(flow))
	progress := snapshot.ResourceInteraction
	if progress.StartedAt.IsZero() || subtle.ConstantTimeCompare(digest[:], progress.CallbackSHA256[:]) != 1 {
		return AuthorizationInteraction{}, ErrResourceInteractionCallbackInvalid
	}
	if err := server.revokedPendingResourceToken(ctx, aauth.TokenReference{
		Issuer: value.record.Resource, JTI: value.record.ResourceTokenJTI,
	}); err != nil {
		return AuthorizationInteraction{}, err
	}
	failure := aauth.ReadInteractionCallback(rawQuery)
	outcome := AuthorizationPollInteracting
	var callbackError aauth.InteractionCallbackError
	if failure != nil {
		callbackError, _ = failure.(aauth.InteractionCallbackError)
		outcome = pollStateForCallbackError(callbackError)
	}
	switch snapshot.State {
	case AuthorizationPollInteracting:
	case AuthorizationPollExpired:
		return AuthorizationInteraction{}, ErrPendingAuthorizationExpired
	case AuthorizationPollGone, AuthorizationPollCancelled:
		return AuthorizationInteraction{}, ErrPendingAuthorizationGone
	default:
		if snapshot.State != outcome {
			return AuthorizationInteraction{}, ErrPendingAuthorizationConflict
		}
	}
	if err := server.resourceInteraction.store.FinishPendingAuthorizationResourceInteraction(
		ctx, value.record.ID, digest, outcome, now,
	); err != nil {
		return AuthorizationInteraction{}, err
	}
	if failure != nil {
		return AuthorizationInteraction{}, callbackError
	}
	return value, nil
}

// AuthorizationCallbackURL returns where to send the person's browser when a
// pending authorization that carried a Resource interaction has ended: the
// callback the Agent sent, with an error unless the request was approved.
// It returns an empty string when the Agent sent no callback; the host then
// shows its own completion page. While the request can still complete it
// returns ErrPendingAuthorizationConflict.
func (server *Server) AuthorizationCallbackURL(ctx context.Context, reference string) (string, error) {
	if server == nil || server.authorizationInteractions == nil {
		return "", errors.New("personserver: authorization interactions are not configured")
	}
	if ctx == nil {
		return "", errors.New("personserver: context is required")
	}
	snapshot, err := server.authorizationInteractions.LoadPendingAuthorization(ctx, reference, server.clock.Now().UTC())
	if err != nil {
		return "", err
	}
	if snapshot.Record.ID != reference || snapshot.Record.PersonServer != server.issuer {
		return "", ErrPendingAuthorizationConflict
	}
	callback := snapshot.ResourceInteraction.AgentCallback
	var failure aauth.InteractionCallbackError
	switch snapshot.State {
	case AuthorizationPollApproved:
	case AuthorizationPollDenied:
		failure = aauth.InteractionCallbackAccessDenied
	case AuthorizationPollAbandoned:
		failure = aauth.InteractionCallbackUserAbandoned
	case AuthorizationPollExpired:
		failure = aauth.InteractionCallbackInteractionExpired
	case AuthorizationPollServerError, AuthorizationPollGone, AuthorizationPollCancelled:
		failure = aauth.InteractionCallbackServerError
	default:
		return "", ErrPendingAuthorizationConflict
	}
	if callback == "" {
		return "", nil
	}
	return aauth.InteractionCallbackURL(callback, failure)
}

func pollStateForCallbackError(failure aauth.InteractionCallbackError) AuthorizationPollState {
	switch failure.PollingError() {
	case "denied":
		return AuthorizationPollDenied
	case "abandoned":
		return AuthorizationPollAbandoned
	case "expired":
		return AuthorizationPollExpired
	default:
		return AuthorizationPollServerError
	}
}

func validateResourceInteractionURL(value string) error {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil ||
		parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" || strings.Contains(value, "#") {
		return errors.New("Resource interaction URL must be an HTTPS URL without query or fragment")
	}
	return nil
}

func validateResourceInteractionProgress(record PendingAuthorizationRecord, state AuthorizationPollState, progress ResourceInteractionProgress) error {
	if record.ResourceInteraction == (aauth.ResourceInteraction{}) {
		if progress != (ResourceInteractionProgress{}) {
			return ErrPendingAuthorizationConflict
		}
		return nil
	}
	if progress.StartedAt.IsZero() {
		if progress != (ResourceInteractionProgress{}) {
			return ErrPendingAuthorizationConflict
		}
		return nil
	}
	if progress.CallbackSHA256 == ([32]byte{}) || progress.StartedAt.Before(record.CreatedAt) ||
		(!progress.CompletedAt.IsZero() && progress.CompletedAt.Before(progress.StartedAt)) {
		return ErrPendingAuthorizationConflict
	}
	if progress.AgentCallback != "" && aauth.ValidateInteractionCallback(progress.AgentCallback, true) != nil {
		return ErrPendingAuthorizationConflict
	}
	if state == AuthorizationPollApproved && progress.CompletedAt.IsZero() {
		return ErrPendingAuthorizationConflict
	}
	return nil
}
