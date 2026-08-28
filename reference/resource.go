package reference

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"sort"
	"strings"
	"sync"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
)

type ResourceConfig struct {
	Identifier string
	// AccessMode explicitly selects one implemented current registry flow.
	AccessMode   aauth.AccessMode
	PersonServer string
	AccessServer string
	SigningKey   aauth.SigningKey
	KeyResolver  aauth.KeyResolver
	Clock        aauth.Clock
	NewID        func() string
	// Scopes is the canonical issuance allowlist. Auth-token resources must
	// describe every exact entry in ScopeDescriptions.
	Scopes            []string
	ScopeDescriptions map[string]string
	// RequiredScopesForRequest maps one protected request to a canonical,
	// nonempty subset of Scopes before context validation or replay admission.
	RequiredScopesForRequest func(context.Context, *http.Request) ([]string, error)
	// ReplayStore is the required atomic proof-admission authority for every
	// signed Resource endpoint.
	ReplayStore ProofReplayStore
	// AuthorizationStore is required for resource-managed authorization. It
	// retains pending decisions, terminal access artifacts, and live grants.
	AuthorizationStore AuthorizationStateStore
	// ProtectedAuthorizationPolicy is required in auth-token mode. It receives
	// a defensive copy of the fully verified current request after replay
	// admission and before any protected response or Operation consequence.
	ProtectedAuthorizationPolicy aauth.ProtectedAuthorizationPolicy
	AuthorizationPolicy          aauth.AuthorizationPolicy
	InteractionRequired          func(context.Context, aauth.AuthorizationRequest) (bool, error)
	Random                       io.Reader
	PendingLifetime              time.Duration
	Operation                    func(context.Context, aauth.AuthorizedRequest) (any, error)
	Events                       *ResourceEventsConfig
}

// ResourceEventsConfig enables public registration and supplies the external
// authority and delivery client used by the Events profile.
type ResourceEventsConfig struct {
	PublicSubscriptionPath string
	Store                  ResourceEventStore
	HTTPClient             *http.Client
	ActiveUntil            func(context.Context, aauth.SubscribeTokenClaims) (time.Time, error)
	// AsyncAPIPath and AsyncAPIDocument publish one exact JSON AsyncAPI 3.0.0
	// Events contract through the resource's R3 vocabulary metadata. They must
	// be configured together.
	AsyncAPIPath     string
	AsyncAPIDocument []byte
	// ProtectedOperationID and ProtectedMessageID select the one protected
	// registration operation published by AsyncAPIDocument. ContractStore
	// retains the exact selected contract before any ticket URL is released.
	// TicketLifetime bounds the resource-owned, single-use URL capability.
	ProtectedOperationID string
	ProtectedMessageID   string
	ContractStore        EventContractStore
	TicketLifetime       time.Duration
	// ProtectedRegistrationValidator is the only route to a body-bearing
	// protected registration. The body and its media type are proof-covered
	// before this callback runs; a refusal precedes ticket consumption.
	ProtectedRegistrationValidator func(context.Context, ProtectedEventRegistration) error
}

type agentEventMetadataResolver interface {
	ResolveAgentEventMetadata(context.Context, string) (aauth.AgentEventMetadata, error)
}

type Resource struct {
	identifier                   string
	accessMode                   aauth.AccessMode
	tokenAudience                string
	authTokenDiscoveryDocument   string
	signingKey                   aauth.SigningKey
	hasSigningKey                bool
	keyResolver                  aauth.KeyResolver
	clock                        aauth.Clock
	newID                        func() string
	scopes                       []string
	scopeDescriptions            map[string]string
	requiredScopesForRequest     func(context.Context, *http.Request) ([]string, error)
	replayStore                  ProofReplayStore
	authorizationStore           AuthorizationStateStore
	protectedAuthorizationPolicy aauth.ProtectedAuthorizationPolicy
	authorizationPolicy          aauth.AuthorizationPolicy
	interactionRequired          func(context.Context, aauth.AuthorizationRequest) (bool, error)
	random                       io.Reader
	pendingLifetime              time.Duration
	operation                    func(context.Context, aauth.AuthorizedRequest) (any, error)
	r3Vocabularies               map[string]json.RawMessage
	eventSubscriptionPath        string
	eventStore                   ResourceEventStore
	eventTicketStore             ProtectedEventTicketStore
	eventHTTPClient              *http.Client
	eventActiveUntil             func(context.Context, aauth.SubscribeTokenClaims) (time.Time, error)
	eventAsyncAPIPath            string
	eventAsyncAPIDocument        []byte
	eventAsyncAPIContract        *aauth.EventsAsyncAPIContract
	eventProtectedOperation      string
	eventProtectedMessage        aauth.EventsAsyncAPIMessage
	eventProtectedPath           string
	eventContractStore           EventContractStore
	eventTicketLifetime          time.Duration
	eventRegistrationValidator   func(context.Context, ProtectedEventRegistration) error
	randomMu                     sync.Mutex
	pendingMu                    sync.Mutex
	authorizationErr             error
	authorizationBody            []byte
	authorizationRecovery        []byte
	pending                      map[string]*pendingAuthorization
	access                       map[string]localAccessGrant
}

type localAccessGrant struct {
	agent           string
	subject         string
	thumbprint      string
	scope           []string
	mission         *aauth.MissionReference
	expiresAt       time.Time
	sourcePendingID string
}

type pendingAuthorization struct {
	pendingInteraction
	request                aauth.AuthorizationRequest
	requestBody            []byte
	requestProof           *aauth.RequestProof
	requestVerificationKey aauth.JWK
	decision               aauth.AuthorizationDecision
	agentThumbprint        string
	agentExpiresAt         time.Time
	terminalAccessToken    string
}

const resourceAuthorizationStateSchema = "aauth.reference.resource-authorization-state"

type resourceAuthorizationStateRecord struct {
	Kind    string                              `json:"kind"`
	Key     string                              `json:"key"`
	Pending *resourcePendingAuthorizationRecord `json:"pending,omitempty"`
	Grant   *resourceAccessGrantRecord          `json:"grant,omitempty"`
}

type resourcePendingAuthorizationRecord struct {
	ID                     string                      `json:"id"`
	Code                   string                      `json:"code"`
	NormalizedCode         string                      `json:"normalized_code"`
	CodeConsumed           bool                        `json:"code_consumed"`
	FailedCodeAttempts     int                         `json:"failed_code_attempts"`
	State                  pendingAuthorizationState   `json:"state"`
	PollingError           aauth.PollingErrorCode      `json:"polling_error,omitempty"`
	ExpiresAt              time.Time                   `json:"expires_at"`
	Request                aauth.AuthorizationRequest  `json:"request"`
	RequestBody            []byte                      `json:"request_body"`
	RequestProof           *aauth.RequestProof         `json:"request_proof"`
	RequestVerificationKey aauth.JWK                   `json:"request_verification_key"`
	Decision               aauth.AuthorizationDecision `json:"decision"`
	AgentThumbprint        string                      `json:"agent_thumbprint"`
	AgentExpiresAt         time.Time                   `json:"agent_expires_at"`
	TerminalAccessToken    string                      `json:"terminal_access_token,omitempty"`
}

type resourceAccessGrantRecord struct {
	Agent           string                  `json:"agent,omitempty"`
	Subject         string                  `json:"subject"`
	Thumbprint      string                  `json:"thumbprint"`
	Scope           []string                `json:"scope"`
	Mission         *aauth.MissionReference `json:"mission,omitempty"`
	ExpiresAt       time.Time               `json:"expires_at"`
	SourcePendingID string                  `json:"source_pending_id,omitempty"`
}

type resourceAuthorizationInput struct {
	Scope   string `json:"scope"`
	Account string `json:"account,omitempty"`
}

func NewResource(config ResourceConfig) (*Resource, error) {
	if err := aauth.ValidateServerIdentifier(config.Identifier); err != nil {
		return nil, err
	}
	switch config.AccessMode {
	case "":
		return nil, errors.New("reference: resource access mode is required")
	case aauth.AccessModeAuthToken:
		if (config.PersonServer == "") == (config.AccessServer == "") || config.AuthorizationPolicy != nil {
			return nil, errors.New("reference: auth-token resource requires exactly one person or access server")
		}
		if config.ProtectedAuthorizationPolicy == nil {
			return nil, errors.New("reference: auth-token resource requires a protected authorization policy")
		}
	case aauth.AccessModeSessionToken:
		if config.AuthorizationPolicy == nil || config.PersonServer != "" || config.AccessServer != "" {
			return nil, errors.New("reference: session-token resource requires local authorization policy")
		}
		if config.AuthorizationStore == nil {
			return nil, errors.New("reference: session-token resource requires an authorization state store")
		}
		if config.ProtectedAuthorizationPolicy != nil {
			return nil, errors.New("reference: session-token resource does not use an auth-token protected authorization policy")
		}
	default:
		return nil, fmt.Errorf("reference: resource access mode %q is not implemented", config.AccessMode)
	}
	tokenAudience := config.PersonServer
	authTokenDiscoveryDocument := aauth.PersonDiscoveryDocument
	if tokenAudience == "" {
		tokenAudience = config.AccessServer
		authTokenDiscoveryDocument = aauth.AccessDiscoveryDocument
	}
	if tokenAudience != "" {
		if err := aauth.ValidateServerIdentifier(tokenAudience); err != nil {
			return nil, err
		}
	}
	if tokenAudience != "" && config.SigningKey.ID() == "" {
		return nil, errors.New("reference: a resource that issues resource tokens requires a signing key")
	}
	if config.InteractionRequired != nil && config.AuthorizationPolicy == nil {
		return nil, errors.New("reference: deferred resource authorization requires a local authorization policy")
	}
	if config.KeyResolver == nil || config.Clock == nil || config.NewID == nil ||
		len(config.Scopes) == 0 || config.Operation == nil {
		return nil, errors.New("reference: resource requires resolver, clock, id source, scopes, and operation")
	}
	if config.ReplayStore == nil {
		return nil, errors.New("reference: resource requires a proof replay store")
	}
	if config.RequiredScopesForRequest == nil {
		return nil, errors.New("reference: current resource requires a required-scope mapper")
	}
	var eventSubscriptionPath string
	var eventStore ResourceEventStore
	var eventTicketStore ProtectedEventTicketStore
	var eventHTTPClient *http.Client
	var eventActiveUntil func(context.Context, aauth.SubscribeTokenClaims) (time.Time, error)
	var eventAsyncAPIPath string
	var eventAsyncAPIDocument []byte
	var eventAsyncAPIContract *aauth.EventsAsyncAPIContract
	var eventProtectedOperation string
	var eventProtectedMessage aauth.EventsAsyncAPIMessage
	var eventProtectedPath string
	var eventContractStore EventContractStore
	var eventTicketLifetime time.Duration
	var eventRegistrationValidator func(context.Context, ProtectedEventRegistration) error
	if config.Events != nil {
		if err := validatePublicRoutePath(config.Events.PublicSubscriptionPath); err != nil {
			return nil, fmt.Errorf("reference: resource Events subscription path: %w", err)
		}
		if strings.ContainsAny(config.Events.PublicSubscriptionPath, "{}") {
			return nil, errors.New("reference: resource public Events subscription path must be literal")
		}
		if config.Events.Store == nil || config.Events.HTTPClient == nil || config.Events.ActiveUntil == nil {
			return nil, errors.New("reference: resource Events requires store, HTTP client, and active-until policy")
		}
		if config.SigningKey.ID() == "" {
			return nil, errors.New("reference: resource Events requires a signing key")
		}
		eventSubscriptionPath = config.Events.PublicSubscriptionPath
		eventStore = config.Events.Store
		eventHTTPClient = config.Events.HTTPClient
		eventActiveUntil = config.Events.ActiveUntil
		if (config.Events.AsyncAPIPath == "") != (len(config.Events.AsyncAPIDocument) == 0) {
			return nil, errors.New("reference: resource Events AsyncAPI path and document must be configured together")
		}
		if config.Events.AsyncAPIPath != "" {
			if err := validatePublicRoutePath(config.Events.AsyncAPIPath); err != nil {
				return nil, fmt.Errorf("reference: resource Events AsyncAPI path: %w", err)
			}
			if strings.ContainsAny(config.Events.AsyncAPIPath, "{}") {
				return nil, errors.New("reference: resource Events AsyncAPI path must be literal")
			}
			if config.Events.AsyncAPIPath == config.Events.PublicSubscriptionPath {
				return nil, errors.New("reference: resource Events AsyncAPI and subscription paths must differ")
			}
			parsed, err := aauth.ParseEventsAsyncAPI(config.Events.AsyncAPIDocument)
			if err != nil {
				return nil, fmt.Errorf("reference: resource Events AsyncAPI document: %w", err)
			}
			eventAsyncAPIPath = config.Events.AsyncAPIPath
			eventAsyncAPIDocument = append([]byte(nil), config.Events.AsyncAPIDocument...)
			eventAsyncAPIContract = parsed
		}
		protectedParts := 0
		if config.Events.ProtectedOperationID != "" {
			protectedParts++
		}
		if config.Events.ProtectedMessageID != "" {
			protectedParts++
		}
		if config.Events.ContractStore != nil {
			protectedParts++
		}
		if config.Events.TicketLifetime != 0 {
			protectedParts++
		}
		if protectedParts != 0 && protectedParts != 4 {
			return nil, errors.New("reference: protected Events requires operation, message, contract custody, and ticket lifetime")
		}
		if protectedParts == 4 {
			if eventAsyncAPIContract == nil {
				return nil, errors.New("reference: protected Events requires an AsyncAPI contract")
			}
			if config.Events.TicketLifetime < time.Second || config.Events.TicketLifetime > time.Hour {
				return nil, errors.New("reference: protected Events ticket lifetime must be from one second through one hour")
			}
			var ok bool
			eventTicketStore, ok = config.Events.Store.(ProtectedEventTicketStore)
			if !ok {
				return nil, errors.New("reference: protected Events requires an atomic ticket authority")
			}
			selected, err := eventAsyncAPIContract.ProtectedMessage(
				config.Events.ProtectedOperationID,
				config.Events.ProtectedMessageID,
			)
			if err != nil {
				return nil, fmt.Errorf("reference: protected Events selection: %w", err)
			}
			route := strings.Replace(selected.Address, "{"+selected.TicketParameter+"}", "ticket", 1)
			if err := validatePublicRoutePath(route); err != nil {
				return nil, fmt.Errorf("reference: protected Events channel address: %w", err)
			}
			eventProtectedOperation = selected.OperationID
			eventProtectedMessage = selected
			eventProtectedPath = selected.Address
			eventContractStore = config.Events.ContractStore
			eventTicketLifetime = config.Events.TicketLifetime
			eventRegistrationValidator = config.Events.ProtectedRegistrationValidator
		} else if config.Events.ProtectedRegistrationValidator != nil {
			return nil, errors.New("reference: protected Events registration validator requires complete protected configuration")
		}
	}
	if err := validateResourceRoutePatterns(eventSubscriptionPath, eventAsyncAPIPath, eventProtectedPath); err != nil {
		return nil, err
	}
	r3Vocabularies := make(map[string]json.RawMessage)
	if eventAsyncAPIPath != "" {
		discovery, err := json.Marshal(eventAsyncAPIPath)
		if err != nil {
			return nil, err
		}
		r3Vocabularies[aauth.R3VocabularyAsyncAPI] = discovery
	}
	pendingLifetime := config.PendingLifetime
	if pendingLifetime == 0 {
		pendingLifetime = 5 * time.Minute
	}
	if pendingLifetime < 0 {
		return nil, errors.New("reference: pending lifetime must not be negative")
	}
	random := config.Random
	if random == nil {
		random = rand.Reader
	}
	if _, err := canonicalRequiredScopes(config.Scopes, config.Scopes); err != nil {
		return nil, err
	}
	if config.AccessMode == aauth.AccessModeAuthToken || config.ScopeDescriptions != nil {
		if err := validateScopeDescriptions(config.Scopes, config.ScopeDescriptions); err != nil {
			return nil, err
		}
	}
	resource := &Resource{
		identifier:                   config.Identifier,
		accessMode:                   config.AccessMode,
		tokenAudience:                tokenAudience,
		authTokenDiscoveryDocument:   authTokenDiscoveryDocument,
		signingKey:                   config.SigningKey,
		hasSigningKey:                config.SigningKey.ID() != "",
		keyResolver:                  config.KeyResolver,
		clock:                        config.Clock,
		newID:                        config.NewID,
		scopes:                       append([]string(nil), config.Scopes...),
		scopeDescriptions:            cloneScopeDescriptions(config.ScopeDescriptions),
		requiredScopesForRequest:     config.RequiredScopesForRequest,
		replayStore:                  config.ReplayStore,
		authorizationStore:           config.AuthorizationStore,
		protectedAuthorizationPolicy: config.ProtectedAuthorizationPolicy,
		authorizationPolicy:          config.AuthorizationPolicy,
		interactionRequired:          config.InteractionRequired,
		random:                       random,
		pendingLifetime:              pendingLifetime,
		operation:                    config.Operation,
		r3Vocabularies:               r3Vocabularies,
		eventSubscriptionPath:        eventSubscriptionPath,
		eventStore:                   eventStore,
		eventTicketStore:             eventTicketStore,
		eventHTTPClient:              eventHTTPClient,
		eventActiveUntil:             eventActiveUntil,
		eventAsyncAPIPath:            eventAsyncAPIPath,
		eventAsyncAPIDocument:        eventAsyncAPIDocument,
		eventAsyncAPIContract:        eventAsyncAPIContract,
		eventProtectedOperation:      eventProtectedOperation,
		eventProtectedMessage:        eventProtectedMessage,
		eventProtectedPath:           eventProtectedPath,
		eventContractStore:           eventContractStore,
		eventTicketLifetime:          eventTicketLifetime,
		eventRegistrationValidator:   eventRegistrationValidator,
		pending:                      make(map[string]*pendingAuthorization),
		access:                       make(map[string]localAccessGrant),
	}
	if resource.authorizationStore != nil {
		if err := resource.loadAuthorizationState(context.Background()); err != nil {
			return nil, fmt.Errorf("reference: load resource authorization state: %w", err)
		}
	}
	return resource, nil
}

func (resource *Resource) loadAuthorizationState(ctx context.Context) error {
	body, err := resource.authorizationStore.Load(ctx)
	if err != nil {
		return err
	}
	if len(body) == 0 {
		resource.pendingMu.Lock()
		defer resource.pendingMu.Unlock()
		return resource.persistAuthorizationStateLocked(ctx)
	}
	if err := resource.restoreAuthorizationStateLocked(body); err != nil {
		return err
	}
	resource.authorizationBody = append([]byte(nil), body...)
	return nil
}

func (resource *Resource) restoreAuthorizationStateLocked(body []byte) error {
	rawRecords, err := decodeAuthorizationStateRecords(body, resourceAuthorizationStateSchema)
	if err != nil {
		return err
	}
	pending := make(map[string]*pendingAuthorization)
	access := make(map[string]localAccessGrant)
	previous := ""
	for _, raw := range rawRecords {
		var record resourceAuthorizationStateRecord
		if err := decodeAuthorizationStateRecord(raw, &record); err != nil {
			return err
		}
		sortKey := record.Kind + "\x00" + record.Key
		if record.Key == "" || sortKey <= previous {
			return ErrAuthorizationStateIntegrity
		}
		previous = sortKey
		switch record.Kind {
		case "grant":
			if record.Grant == nil || record.Pending != nil ||
				validateResourceAccessGrantRecord(record.Key, *record.Grant) != nil {
				return ErrAuthorizationStateIntegrity
			}
			access[record.Key] = localAccessGrant{
				agent: record.Grant.Agent, subject: record.Grant.Subject,
				thumbprint: record.Grant.Thumbprint, scope: append([]string(nil), record.Grant.Scope...),
				mission: cloneMissionReference(record.Grant.Mission), expiresAt: record.Grant.ExpiresAt.UTC(),
				sourcePendingID: record.Grant.SourcePendingID,
			}
		case "pending":
			if record.Pending == nil || record.Grant != nil || record.Pending.ID != record.Key ||
				resource.validateResourcePendingAuthorizationRecord(*record.Pending) != nil {
				return ErrAuthorizationStateIntegrity
			}
			stored := record.Pending
			pending[record.Key] = &pendingAuthorization{
				pendingInteraction: pendingInteraction{
					id: stored.ID, code: stored.Code, normalizedCode: stored.NormalizedCode,
					codeConsumed: stored.CodeConsumed, failedCodeAttempts: stored.FailedCodeAttempts,
					state: stored.State, pollingError: stored.PollingError, expiresAt: stored.ExpiresAt.UTC(),
				},
				request:                copyAuthorizationRequest(stored.Request),
				requestBody:            append([]byte(nil), stored.RequestBody...),
				requestProof:           copyRequestProof(stored.RequestProof),
				requestVerificationKey: stored.RequestVerificationKey,
				decision:               stored.Decision,
				agentThumbprint:        stored.AgentThumbprint, agentExpiresAt: stored.AgentExpiresAt.UTC(),
				terminalAccessToken: stored.TerminalAccessToken,
			}
		default:
			return ErrAuthorizationStateIntegrity
		}
	}
	for _, stored := range pending {
		if stored.terminalAccessToken != "" {
			if _, exists := access[stored.terminalAccessToken]; !exists {
				return ErrAuthorizationStateIntegrity
			}
		}
	}
	if err := resource.validateResourceAuthorizationGraph(pending, access); err != nil {
		return err
	}
	resource.pending = pending
	resource.access = access
	return nil
}

func validateResourceAccessGrantRecord(key string, record resourceAccessGrantRecord) error {
	if aauth.ValidateAccessToken(key) != nil || record.Subject == "" ||
		record.Thumbprint == "" || len(record.Scope) == 0 || record.ExpiresAt.IsZero() {
		return ErrAuthorizationStateIntegrity
	}
	if record.Agent != "" && aauth.ValidateAgentIdentifier(record.Agent) != nil {
		return ErrAuthorizationStateIntegrity
	}
	if !validRetainedThumbprint(record.Thumbprint) {
		return ErrAuthorizationStateIntegrity
	}
	if scopes, err := parseScopes(strings.Join(record.Scope, " ")); err != nil || len(scopes) != len(record.Scope) {
		return ErrAuthorizationStateIntegrity
	}
	if record.Mission != nil && record.Mission.Validate() != nil {
		return ErrAuthorizationStateIntegrity
	}
	if record.SourcePendingID != "" && !validPendingID(record.SourcePendingID) {
		return ErrAuthorizationStateIntegrity
	}
	return nil
}

func (resource *Resource) validateResourcePendingAuthorizationRecord(record resourcePendingAuthorizationRecord) error {
	interaction := pendingInteractionRecord{
		ID: record.ID, Code: record.Code, NormalizedCode: record.NormalizedCode,
		CodeConsumed: record.CodeConsumed, FailedCodeAttempts: record.FailedCodeAttempts,
		State: record.State, PollingError: record.PollingError, ExpiresAt: record.ExpiresAt,
	}
	if _, err := restorePendingInteraction(interaction); err != nil {
		return err
	}
	if !validPendingID(record.ID) || validateLocalAuthorizationInteraction(interaction) != nil {
		return ErrAuthorizationStateIntegrity
	}
	terminalExpiry := int64(0)
	if record.TerminalAccessToken != "" {
		terminalExpiry = 1
	}
	if err := validateAuthorizationTerminalState(interaction, record.TerminalAccessToken, terminalExpiry, 0, "", ""); err != nil {
		return err
	}
	if !validRetainedThumbprint(record.AgentThumbprint) || record.AgentExpiresAt.IsZero() ||
		record.Request.Resource != resource.identifier ||
		record.ExpiresAt.After(record.AgentExpiresAt) {
		return ErrAuthorizationStateIntegrity
	}
	if err := resource.validateResourceAuthorizationRequestEvidence(record); err != nil {
		return ErrAuthorizationStateIntegrity
	}
	if !record.ExpiresAt.After(record.RequestProof.VerifiedAt) {
		return ErrAuthorizationStateIntegrity
	}
	decisionPresent := record.Decision.Subject != "" || len(record.Decision.Scope) != 0
	if record.State == pendingAuthorizationApproved ||
		record.State == pendingAuthorizationExpired && decisionPresent {
		if record.Decision.Subject == "" || validateAuthorizationDecision(record.Decision, record.Request.Scope) != nil {
			return ErrAuthorizationStateIntegrity
		}
		if record.Request.Subject != "" && record.Decision.Subject != record.Request.Subject {
			return ErrAuthorizationStateIntegrity
		}
	} else if decisionPresent {
		return ErrAuthorizationStateIntegrity
	}
	if record.TerminalAccessToken != "" && record.State != pendingAuthorizationApproved {
		return ErrAuthorizationStateIntegrity
	}
	return nil
}

func (resource *Resource) validateResourceAuthorizationRequestEvidence(
	record resourcePendingAuthorizationRecord,
) error {
	if len(record.RequestBody) > maxJSONBody || record.RequestProof == nil {
		return ErrAuthorizationStateIntegrity
	}
	proof := record.RequestProof
	if proof.Authority == "" || proof.Target == "" || proof.SignatureInput == "" || proof.Signature == "" ||
		proof.SignatureKey == "" || proof.SignatureKeyType != aauth.SignatureKeyJWT ||
		proof.CredentialIssuer == "" || proof.Created.IsZero() || proof.VerifiedAt.IsZero() ||
		proof.ReplayKey == "" || proof.Authorization != "" {
		return ErrAuthorizationStateIntegrity
	}
	identifier, err := endpointIdentifier("https://" + proof.Authority)
	if err != nil || identifier != resource.identifier {
		return ErrAuthorizationStateIntegrity
	}
	request, err := http.NewRequest(proof.Method, resource.identifier+proof.Target, bytes.NewReader(record.RequestBody))
	if err != nil {
		return ErrAuthorizationStateIntegrity
	}
	request.Host = proof.Authority
	request.Header.Set("Content-Digest", proof.ContentDigest)
	if proof.ContentType != "" {
		request.Header.Set("Content-Type", proof.ContentType)
	}
	request.Header.Set("Signature-Input", proof.SignatureInput)
	request.Header.Set("Signature", proof.Signature)
	request.Header.Set("Signature-Key", proof.SignatureKey)
	requiredComponents := []string(nil)
	if proof.ContentType != "" {
		requiredComponents = append(requiredComponents, "content-type")
	}
	verified, err := aauth.VerifyRequest(
		context.Background(),
		request,
		aauth.StaticKeyResolver{proof.CredentialIssuer: {record.RequestVerificationKey.Kid: record.RequestVerificationKey}},
		aauth.ClockFunc(func() time.Time { return proof.VerifiedAt.UTC() }),
		aauth.VerifyRequestOptions{
			RequiredComponents: requiredComponents, RequireExactComponents: true,
			AllowedCredentialTypes: []string{aauth.AgentTokenType, aauth.PersonTokenType},
		},
	)
	if err != nil || verified.CredentialType != proof.CredentialType ||
		!verified.PublicKey.Equal(proof.PublicKey) || !verified.Created.Equal(proof.Created) ||
		!verified.VerifiedAt.Equal(proof.VerifiedAt) || verified.ReplayKey != proof.ReplayKey {
		return ErrAuthorizationStateIntegrity
	}
	thumbprint, err := verified.PublicKey.Thumbprint()
	if err != nil || thumbprint != record.AgentThumbprint {
		return ErrAuthorizationStateIntegrity
	}
	switch proof.CredentialType {
	case aauth.PersonTokenType:
		if proof.Target != "/authorize" || proof.Method != http.MethodPost || verified.PersonToken == nil ||
			proof.CredentialIssuer != verified.PersonToken.Issuer || proof.Agent != "" || proof.Signer != "" ||
			record.Request.Agent != "" || record.Request.PersonServer != verified.PersonToken.Issuer ||
			record.Request.Subject != verified.PersonToken.Subject ||
			record.Request.MissionS256 != verified.PersonToken.MissionS256 ||
			record.Request.Tenant != verified.PersonToken.Tenant || record.Request.Mission != nil ||
			record.Request.Upstream != nil ||
			record.AgentExpiresAt.Unix() != verified.PersonToken.ExpiresAt ||
			aauth.ValidatePersonTokenContext(*verified.PersonToken, resource.identifier, verified.PublicKey) != nil {
			return ErrAuthorizationStateIntegrity
		}
		var input resourceAuthorizationInput
		if err := decodeJSONBytes(bytes.NewReader(record.RequestBody), &input); err != nil ||
			record.Request.Account != input.Account {
			return ErrAuthorizationStateIntegrity
		}
		scopes, err := parseScopes(input.Scope)
		if err != nil || !reflect.DeepEqual(scopes, record.Request.Scope) {
			return ErrAuthorizationStateIntegrity
		}
	case aauth.AgentTokenType:
		if proof.Target == "/authorize" || verified.AgentToken == nil ||
			proof.CredentialIssuer != verified.AgentToken.Issuer || proof.Agent != verified.Agent ||
			proof.Signer != verified.Agent || record.Request.Agent != verified.Agent ||
			record.Request.PersonServer != "" || record.Request.Subject != "" || record.Request.Account != "" ||
			record.Request.Tenant != "" || record.Request.Mission != nil || record.Request.Upstream != nil ||
			record.AgentExpiresAt.Unix() != verified.AgentToken.ExpiresAt {
			return ErrAuthorizationStateIntegrity
		}
		if resource.requiredScopesForRequest != nil {
			required, err := resource.requiredScopes(request)
			if err != nil || !reflect.DeepEqual(required, record.Request.Scope) {
				return ErrAuthorizationStateIntegrity
			}
		}
	default:
		return ErrAuthorizationStateIntegrity
	}
	return nil
}

func (resource *Resource) validateResourceAuthorizationGraph(
	pending map[string]*pendingAuthorization,
	access map[string]localAccessGrant,
) error {
	referenced := make(map[string]string)
	for pendingID, authorization := range pending {
		if authorization.terminalAccessToken == "" {
			continue
		}
		if previous, duplicate := referenced[authorization.terminalAccessToken]; duplicate && previous != pendingID {
			return ErrAuthorizationStateIntegrity
		}
		referenced[authorization.terminalAccessToken] = pendingID
		grant, exists := access[authorization.terminalAccessToken]
		if !exists || grant.sourcePendingID != pendingID || grant.agent != authorization.request.Agent ||
			grant.subject != authorization.decision.Subject || grant.thumbprint != authorization.agentThumbprint ||
			!reflect.DeepEqual(grant.scope, authorization.decision.Scope) ||
			!reflect.DeepEqual(grant.mission, authorization.request.Mission) ||
			grant.expiresAt.After(authorization.agentExpiresAt) {
			return ErrAuthorizationStateIntegrity
		}
	}
	for token, grant := range access {
		if grant.sourcePendingID == "" {
			continue
		}
		authorization, exists := pending[grant.sourcePendingID]
		if !exists || authorization.terminalAccessToken != token {
			return ErrAuthorizationStateIntegrity
		}
	}
	return nil
}

func (resource *Resource) persistAuthorizationStateLocked(ctx context.Context) error {
	if resource.authorizationStore == nil {
		return nil
	}
	if resource.authorizationErr != nil {
		return resource.authorizationErr
	}
	if err := resource.settleAuthorizationStateLocked(ctx); err != nil {
		return err
	}
	if err := resource.validateResourceAuthorizationGraph(resource.pending, resource.access); err != nil {
		return err
	}
	records := make([]resourceAuthorizationStateRecord, 0, len(resource.pending)+len(resource.access))
	for key, pending := range resource.pending {
		record := resourcePendingAuthorizationRecord{
			ID: pending.id, Code: pending.code, NormalizedCode: pending.normalizedCode,
			CodeConsumed: pending.codeConsumed, FailedCodeAttempts: pending.failedCodeAttempts,
			State: pending.state, PollingError: pending.pollingError, ExpiresAt: pending.expiresAt.UTC(),
			Request: copyAuthorizationRequest(pending.request), Decision: pending.decision,
			RequestBody:            append([]byte(nil), pending.requestBody...),
			RequestProof:           copyRequestProof(pending.requestProof),
			RequestVerificationKey: pending.requestVerificationKey,
			AgentThumbprint:        pending.agentThumbprint, AgentExpiresAt: pending.agentExpiresAt.UTC(),
			TerminalAccessToken: pending.terminalAccessToken,
		}
		if record.ID != key || resource.validateResourcePendingAuthorizationRecord(record) != nil {
			return ErrAuthorizationStateIntegrity
		}
		records = append(records, resourceAuthorizationStateRecord{Kind: "pending", Key: key, Pending: &record})
	}
	for key, grant := range resource.access {
		record := resourceAccessGrantRecord{
			Agent: grant.agent, Subject: grant.subject, Thumbprint: grant.thumbprint,
			Scope: append([]string(nil), grant.scope...), Mission: cloneMissionReference(grant.mission),
			ExpiresAt: grant.expiresAt.UTC(), SourcePendingID: grant.sourcePendingID,
		}
		if validateResourceAccessGrantRecord(key, record) != nil {
			return ErrAuthorizationStateIntegrity
		}
		records = append(records, resourceAuthorizationStateRecord{Kind: "grant", Key: key, Grant: &record})
	}
	sort.Slice(records, func(i, j int) bool {
		return records[i].Kind+"\x00"+records[i].Key < records[j].Kind+"\x00"+records[j].Key
	})
	raw := make([]json.RawMessage, 0, len(records))
	for _, record := range records {
		encoded, err := json.Marshal(record)
		if err != nil {
			return resource.reconcileAuthorizationStateLocked(ctx, nil, err)
		}
		raw = append(raw, encoded)
	}
	body, err := marshalAuthorizationStateRecords(resourceAuthorizationStateSchema, raw)
	if err != nil {
		return resource.reconcileAuthorizationStateLocked(ctx, nil, err)
	}
	if err := resource.authorizationStore.Replace(ctx, body); err != nil {
		return resource.reconcileAuthorizationStateLocked(ctx, body, err)
	}
	resource.authorizationBody = append(resource.authorizationBody[:0], body...)
	return nil
}

func (resource *Resource) reconcileAuthorizationStateLocked(ctx context.Context, candidate []byte, commitErr error) error {
	body, published, err := reconcileAuthorizationState(ctx, resource.authorizationStore, resource.authorizationBody, candidate)
	if err != nil || len(body) == 0 {
		resource.pending = make(map[string]*pendingAuthorization)
		resource.access = make(map[string]localAccessGrant)
		resource.authorizationErr = authorizationStateReconciliationFailure(commitErr, err)
		return resource.authorizationErr
	}
	if err := resource.restoreAuthorizationStateLocked(body); err != nil {
		resource.pending = make(map[string]*pendingAuthorization)
		resource.access = make(map[string]localAccessGrant)
		resource.authorizationErr = authorizationStateReconciliationFailure(commitErr, err)
		return resource.authorizationErr
	}
	if published {
		resource.authorizationRecovery = append(resource.authorizationRecovery[:0], body...)
		return authorizationStatePublishedUncertain(commitErr)
	}
	resource.authorizationBody = append(resource.authorizationBody[:0], body...)
	return commitErr
}

func (resource *Resource) settleAuthorizationStateLocked(ctx context.Context) error {
	if resource.authorizationErr != nil {
		return resource.authorizationErr
	}
	if len(resource.authorizationRecovery) == 0 {
		return nil
	}
	candidate := append([]byte(nil), resource.authorizationRecovery...)
	if err := resource.authorizationStore.Replace(ctx, candidate); err != nil {
		body, published, reconcileErr := reconcileAuthorizationState(ctx, resource.authorizationStore, nil, candidate)
		if reconcileErr == nil && published {
			reconcileErr = resource.restoreAuthorizationStateLocked(body)
		}
		if reconcileErr != nil || !published {
			resource.pending = make(map[string]*pendingAuthorization)
			resource.access = make(map[string]localAccessGrant)
			resource.authorizationErr = authorizationStateReconciliationFailure(err, reconcileErr)
			return resource.authorizationErr
		}
		return authorizationStatePublishedUncertain(err)
	}
	resource.authorizationBody = append(resource.authorizationBody[:0], candidate...)
	resource.authorizationRecovery = nil
	return nil
}

func (resource *Resource) Handler() http.Handler {
	mux := http.NewServeMux()
	if resource.eventAsyncAPIPath != "" {
		mux.HandleFunc("GET "+resource.eventAsyncAPIPath, resource.handleEventsAsyncAPI)
	}
	if resource.eventSubscriptionPath != "" {
		mux.HandleFunc("POST "+resource.eventSubscriptionPath, resource.handlePublicEventSubscription)
	}
	if resource.eventProtectedPath != "" {
		mux.HandleFunc("POST "+resource.eventProtectedPath, resource.handleProtectedEventRegistration)
	}
	mux.HandleFunc("POST /authorize", resource.handleAuthorize)
	mux.HandleFunc("GET /pending/{id}", resource.handlePendingAuthorization)
	mux.HandleFunc("GET /interaction/{id}", resource.handleInteraction)
	mux.HandleFunc("GET /.well-known/aauth-resource.json", resource.handleMetadata)
	mux.HandleFunc("GET /jwks", resource.handleJWKS)
	mux.HandleFunc("/", resource.handleProtected)
	return mux
}

func (resource *Resource) handleEventsAsyncAPI(response http.ResponseWriter, _ *http.Request) {
	response.Header().Set("Content-Type", "application/json")
	response.Header().Set("Cache-Control", "max-age=60")
	response.WriteHeader(http.StatusOK)
	_, _ = response.Write(resource.eventAsyncAPIDocument)
}

func (resource *Resource) handlePublicEventSubscription(response http.ResponseWriter, request *http.Request) {
	if request.ContentLength != 0 || len(request.TransferEncoding) != 0 ||
		(request.Body != nil && request.Body != http.NoBody) {
		writeProblem(response, http.StatusBadRequest, "invalid_request", errors.New("reference: public event registration must be bodyless"))
		return
	}
	verified, err := aauth.VerifyRequest(
		request.Context(),
		request,
		resource.keyResolver,
		resource.clock,
		aauth.VerifyRequestOptions{AllowedCredentialTypes: []string{aauth.SubscribeTokenType}},
	)
	if err != nil {
		writeSignatureFailure(response, err)
		return
	}
	claims := verified.SubscribeToken
	if claims == nil {
		writeSignatureFailure(response, errors.New("reference: verified subscribe token is required"))
		return
	}
	if claims.Audience != resource.identifier {
		writeProblem(response, http.StatusForbidden, "invalid_subscription", errors.New("reference: event subscription audience does not match resource"))
		return
	}
	if claims.MaxUses == nil || *claims.MaxUses != 1 {
		writeProblem(response, http.StatusForbidden, "unsupported_use_policy", errors.New("reference: public event subscription requires max_uses 1"))
		return
	}
	activeUntil, err := resource.eventActiveUntil(request.Context(), *claims)
	if err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", nil)
		return
	}
	if !activeUntil.After(resource.clock.Now()) {
		writeProblem(response, http.StatusInternalServerError, "server_error", errors.New("reference: resource event active-until must be in the future"))
		return
	}
	err = resource.eventStore.Register(request.Context(), ResourceEventSubscription{
		APIssuer:    claims.Issuer,
		EventID:     claims.EventID,
		Resource:    resource.identifier,
		Agent:       claims.Subject,
		ActiveUntil: activeUntil,
	})
	if err != nil {
		if errors.Is(err, ErrEventSubscriptionConflict) {
			writeProblem(response, http.StatusConflict, "subscription_conflict", errors.New("event subscription conflicts with retained state"))
			return
		}
		writeProblem(response, http.StatusInternalServerError, "server_error", nil)
		return
	}
	response.Header().Set("Cache-Control", "no-store")
	response.WriteHeader(http.StatusCreated)
}

func (resource *Resource) handleProtectedEventRegistration(response http.ResponseWriter, request *http.Request) {
	hasBody := request.ContentLength != 0 || len(request.TransferEncoding) != 0 ||
		(request.Body != nil && request.Body != http.NoBody)
	if hasBody && resource.eventRegistrationValidator == nil {
		writeProblem(response, http.StatusBadRequest, "invalid_request", errors.New("reference: protected event registration must be bodyless"))
		return
	}
	var exactBody []byte
	var err error
	var requiredComponents []string
	if hasBody {
		exactBody, err = readBoundedRequestBody(request)
		if err != nil {
			writeProblem(response, http.StatusRequestEntityTooLarge, "request_too_large", err)
			return
		}
		requiredComponents = []string{"content-type", "content-digest"}
	}
	verified, err := aauth.VerifyRequest(
		request.Context(),
		request,
		resource.keyResolver,
		resource.clock,
		aauth.VerifyRequestOptions{
			RequiredComponents:     requiredComponents,
			AllowedCredentialTypes: []string{aauth.SubscribeTokenType},
		},
	)
	if err != nil {
		writeSignatureFailure(response, err)
		return
	}
	claims := verified.SubscribeToken
	if claims == nil {
		writeSignatureFailure(response, errors.New("reference: verified subscribe token is required"))
		return
	}
	if claims.Audience != resource.identifier {
		writeProblem(response, http.StatusForbidden, "invalid_subscription", errors.New("reference: event subscription audience does not match resource"))
		return
	}
	if claims.MaxUses == nil || *claims.MaxUses != 1 {
		writeProblem(response, http.StatusForbidden, "unsupported_use_policy", errors.New("reference: protected event subscription requires max_uses 1"))
		return
	}
	rawTicket := request.PathValue(resource.eventProtectedMessage.TicketParameter)
	if rawTicket == "" {
		writeProblem(response, http.StatusNotFound, "event_ticket_not_found", ErrProtectedEventTicketNotFound)
		return
	}
	ticketDigest := protectedEventTicketDigest(rawTicket)
	if hasBody {
		registration := ProtectedEventRegistration{
			TicketDigest: ticketDigest, Resource: resource.identifier, Agent: verified.Agent,
			APIssuer: claims.Issuer, EventID: claims.EventID,
			ContentType: request.Header.Get("Content-Type"), Body: append([]byte(nil), exactBody...),
		}
		if err := resource.eventRegistrationValidator(request.Context(), registration); err != nil {
			writeProblem(response, http.StatusBadRequest, "invalid_registration", errors.New("event registration policy denied the request"))
			return
		}
	}
	_, err = resource.eventTicketStore.ConsumeTicket(request.Context(), ProtectedEventTicketConsumption{
		TicketDigest: ticketDigest, Resource: resource.identifier, APIssuer: claims.Issuer,
		EventID: claims.EventID, Agent: verified.Agent, RegisteredAt: resource.clock.Now(),
	})
	if err != nil {
		switch {
		case errors.Is(err, ErrProtectedEventTicketNotFound):
			writeProblem(response, http.StatusNotFound, "event_ticket_not_found", errors.New("event ticket was not found"))
		case errors.Is(err, ErrProtectedEventTicketMismatch):
			writeProblem(response, http.StatusForbidden, "event_ticket_mismatch", errors.New("event ticket does not match the request"))
		case errors.Is(err, ErrEventSubscriptionConflict):
			writeProblem(response, http.StatusConflict, "event_subscription_conflict", errors.New("event subscription conflicts with retained state"))
		default:
			writeProblem(response, http.StatusInternalServerError, "event_registration_failed", err)
		}
		return
	}
	writeJSON(response, http.StatusCreated, map[string]string{"status": "subscribed"})
}

// DeliverEvent preserves the M5 payload-free profile.
func (resource *Resource) DeliverEvent(ctx context.Context, apIssuer, eventID string) error {
	return resource.deliverEvent(ctx, apIssuer, eventID, nil)
}

// DeliverEventPayload validates and retains one exact direct JSON message
// before resolving the AP and sending it with signed content metadata.
func (resource *Resource) DeliverEventPayload(
	ctx context.Context,
	apIssuer string,
	eventID string,
	payload EventPayload,
) error {
	return resource.deliverEvent(ctx, apIssuer, eventID, &payload)
}

func (resource *Resource) deliverEvent(
	ctx context.Context,
	apIssuer string,
	eventID string,
	payload *EventPayload,
) error {
	if resource == nil || resource.eventStore == nil || resource.eventHTTPClient == nil {
		return errors.New("reference: resource Events is not configured")
	}
	metadataResolver, ok := resource.keyResolver.(agentEventMetadataResolver)
	if !ok {
		return errors.New("reference: resource Events requires agent event metadata resolution")
	}
	subscription, err := resource.eventStore.Load(ctx, apIssuer, eventID)
	if err != nil {
		return err
	}
	now := resource.clock.Now()
	if subscription.Resource != resource.identifier || !subscription.ActiveUntil.After(now) {
		return ErrEventSubscriptionNotFound
	}
	if (payload != nil) != hasEventContractBinding(
		subscription.ContractDigest,
		subscription.OperationID,
		subscription.MessageID,
	) {
		return ErrEventPayloadNotAllowed
	}
	var contentType string
	var exactPayload []byte
	var payloadDigest string
	if payload != nil {
		contentType, exactPayload, payloadDigest, err = resource.validateEventPayload(ctx, subscription, *payload)
		if err != nil {
			return err
		}
	}
	pending, err := resource.eventStore.LoadPending(ctx, apIssuer, eventID)
	if errors.Is(err, ErrEventPendingNotFound) {
		compact, mintErr := aauth.MintEventToken(resource.signingKey, aauth.EventTokenClaims{
			Issuer:    resource.identifier,
			DWK:       aauth.ResourceDiscoveryDocument,
			Audience:  subscription.Agent,
			EventID:   subscription.EventID,
			IssuedAt:  now.Unix(),
			ExpiresAt: now.Add(referenceEventTokenLifetime).Unix(),
		})
		if mintErr != nil {
			return mintErr
		}
		pending = PendingEventDelivery{
			APIssuer: apIssuer, EventID: eventID, Token: compact,
			ContentType: contentType, Payload: exactPayload, PayloadDigest: payloadDigest,
			CreatedAt: now,
		}
		if retainErr := resource.eventStore.RetainPending(ctx, pending); retainErr != nil {
			return retainErr
		}
	} else if err != nil {
		return err
	} else if pending.ContentType != contentType || pending.PayloadDigest != payloadDigest ||
		!bytes.Equal(pending.Payload, exactPayload) {
		return ErrEventPendingConflict
	}
	metadata, err := metadataResolver.ResolveAgentEventMetadata(ctx, apIssuer)
	if err != nil {
		return err
	}
	if metadata.Issuer != apIssuer {
		return errors.New("reference: resolved event metadata issuer does not match subscription")
	}
	if err := aauth.ValidateEndpoint(metadata.EventEndpoint); err != nil {
		return fmt.Errorf("reference: resolved event endpoint: %w", err)
	}
	var requestBody io.Reader
	if len(pending.Payload) != 0 {
		requestBody = bytes.NewReader(pending.Payload)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, metadata.EventEndpoint, requestBody)
	if err != nil {
		return err
	}
	if pending.ContentType != "" {
		request.Header.Set("Content-Type", pending.ContentType)
	}
	if err := aauth.SignRequestWithSelfJWT(request, resource.signingKey, pending.Token, resource.clock); err != nil {
		return err
	}
	if pending.PayloadDigest != "" && request.Header.Get("Content-Digest") != pending.PayloadDigest {
		return errors.New("reference: signed event payload digest does not match retained custody")
	}
	response, err := resource.eventHTTPClient.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	switch response.StatusCode {
	case http.StatusAccepted:
		decoder := json.NewDecoder(io.LimitReader(response.Body, maxJSONBody+1))
		decoder.DisallowUnknownFields()
		var result struct {
			RemainingUses int `json:"remaining_uses"`
		}
		if err := decoder.Decode(&result); err != nil || result.RemainingUses != 0 {
			return errors.New("reference: event acceptance response is invalid")
		}
		if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
			return errors.New("reference: event acceptance response has trailing data")
		}
	case http.StatusTooManyRequests:
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 8<<10))
	default:
		return responseError(response)
	}
	return resource.eventStore.CompletePending(ctx, apIssuer, eventID)
}

func (resource *Resource) validateEventPayload(
	ctx context.Context,
	subscription ResourceEventSubscription,
	payload EventPayload,
) (string, []byte, string, error) {
	if resource.eventContractStore == nil || subscription.ContractDigest == "" ||
		subscription.OperationID == "" || subscription.MessageID == "" {
		return "", nil, "", errors.New("reference: event payload subscription has no retained contract")
	}
	if payload.OperationID != subscription.OperationID || payload.MessageID != subscription.MessageID {
		return "", nil, "", errors.New("reference: event payload selection does not match subscription")
	}
	exactContract, err := resource.eventContractStore.Load(ctx, subscription.ContractDigest)
	if err != nil {
		return "", nil, "", err
	}
	if aauth.R3S256(exactContract) != subscription.ContractDigest {
		return "", nil, "", ErrEventContractIntegrity
	}
	contract, err := aauth.ParseEventsAsyncAPI(exactContract)
	if err != nil {
		return "", nil, "", err
	}
	message, err := contract.ProtectedMessage(subscription.OperationID, subscription.MessageID)
	if err != nil {
		return "", nil, "", err
	}
	if payload.ContentType != message.ContentType {
		return "", nil, "", errors.New("reference: event payload media type does not match contract")
	}
	if len(payload.Body) > maxEventPayloadBody {
		return "", nil, "", errors.New("reference: event payload exceeds the supported bound")
	}
	if err := message.ValidatePayload(payload.Body); err != nil {
		return "", nil, "", err
	}
	exact := append([]byte(nil), payload.Body...)
	return payload.ContentType, exact, eventPayloadDigest(exact), nil
}

func validatePublicRoutePath(value string) error {
	parsed, err := url.ParseRequestURI(value)
	if err != nil || value == "/" || !strings.HasPrefix(value, "/") ||
		parsed.Path != value || parsed.RawPath != "" || parsed.RawQuery != "" || parsed.Fragment != "" ||
		strings.Contains(value, "//") {
		return errors.New("public route must be one unescaped absolute path")
	}
	return nil
}

func validateResourceRoutePatterns(publicEvents, asyncAPI, protectedEvents string) (err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("reference: resource route configuration conflicts: %v", recovered)
		}
	}()
	mux := http.NewServeMux()
	dummy := func(http.ResponseWriter, *http.Request) {}
	for _, pattern := range []string{
		"POST /authorize",
		"GET /pending/{id}",
		"GET /interaction/{id}",
		"GET /.well-known/aauth-resource.json",
		"GET /jwks",
	} {
		mux.HandleFunc(pattern, dummy)
	}
	if publicEvents != "" {
		mux.HandleFunc("POST "+publicEvents, dummy)
	}
	if asyncAPI != "" {
		mux.HandleFunc("GET "+asyncAPI, dummy)
	}
	if protectedEvents != "" {
		mux.HandleFunc("POST "+protectedEvents, dummy)
	}
	return nil
}

func (resource *Resource) handleAuthorize(response http.ResponseWriter, request *http.Request) {
	if len(request.Header.Values("AAuth-Mission")) != 0 {
		writeProblem(
			response,
			http.StatusBadRequest,
			"invalid_mission",
			errors.New("AAuth-Mission is not supported; mission must be carried by the person token"),
		)
		return
	}
	resource.pendingMu.Lock()
	stateErr := resource.settleAuthorizationStateLocked(request.Context())
	resource.pendingMu.Unlock()
	if stateErr != nil {
		writeProblem(response, http.StatusServiceUnavailable, "authorization_state_unavailable", stateErr)
		return
	}
	credentialKeyCapture, verificationResolver := newRetainedKeyCapture(resource.keyResolver)
	verified, err := aauth.VerifyRequest(request.Context(), request, verificationResolver, resource.clock, aauth.VerifyRequestOptions{
		RequiredComponents:     []string{"content-type"},
		RequireExactComponents: true,
		AllowedCredentialTypes: []string{aauth.PersonTokenType, aauth.AgentTokenType},
	})
	if err != nil {
		if resource.accessMode == aauth.AccessModeAuthToken &&
			isPersonTokenCredentialFailure(verified, err) {
			writeTokenVerificationFailure(response, http.StatusBadRequest, "invalid_person_token", err)
			return
		}
		writeSignatureFailure(response, err)
		return
	}
	if verified.PersonToken == nil {
		writePersonTokenRequired(response, "authorization endpoint requires a person token")
		return
	}
	if resource.authTokenDiscoveryDocument == aauth.PersonDiscoveryDocument &&
		verified.PersonToken.Issuer != resource.tokenAudience {
		writeProblem(
			response,
			http.StatusBadRequest,
			"invalid_person_token",
			fmt.Errorf(
				"person-token issuer %q does not match configured person server %q",
				verified.PersonToken.Issuer,
				resource.tokenAudience,
			),
		)
		return
	}
	requestVerificationKey, err := credentialKeyCapture.retainedKey()
	if err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", err)
		return
	}
	if !resource.consumeProof(response, request, verified) {
		return
	}
	requestBody, err := readBoundedRequestBody(request)
	if err != nil {
		writeProblem(response, http.StatusBadRequest, "invalid_request", err)
		return
	}
	var input resourceAuthorizationInput
	if err := decodeJSONBytes(bytes.NewReader(requestBody), &input); err != nil {
		writeProblem(response, http.StatusBadRequest, "invalid_request", err)
		return
	}
	scopes, err := parseScopes(input.Scope)
	if err != nil || !scopesContained(scopes, resource.scopes) {
		writeProblem(response, http.StatusBadRequest, "invalid_scope", err)
		return
	}
	now := verified.VerifiedAt
	resourceTokenExpiresAt := now.Add(5 * time.Minute)
	if err := aauth.ValidatePersonTokenContext(*verified.PersonToken, resource.identifier, verified.PublicKey); err != nil {
		writeProblem(response, http.StatusBadRequest, "invalid_person_token", err)
		return
	}
	if personExpiry := time.Unix(verified.PersonToken.ExpiresAt, 0); personExpiry.Before(resourceTokenExpiresAt) {
		resourceTokenExpiresAt = personExpiry
	}
	thumbprint, err := verified.PublicKey.Thumbprint()
	if err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", nil)
		return
	}
	if resource.authorizationPolicy != nil {
		authorizationRequest := aauth.AuthorizationRequest{
			Agent:    verified.Agent,
			Resource: resource.identifier,
			Scope:    append([]string(nil), scopes...),
			Account:  input.Account,
		}
		authorizationRequest.PersonServer = verified.PersonToken.Issuer
		authorizationRequest.Subject = verified.PersonToken.Subject
		authorizationRequest.MissionS256 = verified.PersonToken.MissionS256
		authorizationRequest.Tenant = verified.PersonToken.Tenant
		resource.handleLocalAuthorization(
			response, request, requestBody, requestVerificationKey,
			authorizationRequest, verified, thumbprint, now,
		)
		return
	}

	claims := aauth.ResourceTokenClaims{
		Issuer:    resource.identifier,
		DWK:       aauth.ResourceDiscoveryDocument,
		Audience:  resource.tokenAudience,
		JTI:       resource.newID(),
		Agent:     verified.Agent,
		AgentJKT:  thumbprint,
		IssuedAt:  now.Unix(),
		ExpiresAt: resourceTokenExpiresAt.Unix(),
		Scope:     strings.Join(scopes, " "),
		Account:   input.Account,
	}
	claims.PersonServer = verified.PersonToken.Issuer
	claims.Subject = verified.PersonToken.Subject
	claims.PresentedJTI = verified.PersonToken.JTI
	claims.MissionS256 = verified.PersonToken.MissionS256
	claims.Tenant = verified.PersonToken.Tenant
	claims.Agent = ""
	token, err := aauth.MintResourceToken(resource.signingKey, claims)
	if err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", err)
		return
	}
	writeJSON(response, http.StatusOK, map[string]string{"resource_token": token})
}

func isPersonTokenCredentialFailure(verified aauth.VerifiedRequest, err error) bool {
	if verified.SignatureKeyType != aauth.SignatureKeyJWT {
		return false
	}
	var signatureError *aauth.SignatureError
	if !errors.As(err, &signatureError) {
		return false
	}
	switch signatureError.Code {
	case aauth.SignatureErrorInvalidJWT,
		aauth.SignatureErrorExpiredJWT,
		aauth.SignatureErrorUnknownKey,
		aauth.SignatureErrorIssuerMissing,
		aauth.SignatureErrorIssuerMismatch,
		aauth.SignatureErrorUnsupportedAlgorithm:
		return verified.CredentialType == "" || verified.CredentialType == aauth.PersonTokenType
	case aauth.SignatureErrorInvalidKey:
		return verified.CredentialType == aauth.PersonTokenType
	default:
		return false
	}
}

func credentialExpiry(verified aauth.VerifiedRequest) time.Time {
	if verified.PersonToken != nil {
		return time.Unix(verified.PersonToken.ExpiresAt, 0)
	}
	return time.Unix(verified.AgentToken.ExpiresAt, 0)
}

func validateAuthorizationDecision(decision aauth.AuthorizationDecision, requestedScope []string) error {
	seen := make(map[string]struct{}, len(decision.Scope))
	for _, scope := range decision.Scope {
		if scope == "" || strings.TrimSpace(scope) != scope {
			return errors.New("authorization decision contains an invalid scope")
		}
		if _, exists := seen[scope]; exists {
			return errors.New("authorization decision contains an invalid scope")
		}
		seen[scope] = struct{}{}
	}
	if len(decision.Scope) == 0 || !scopesContained(decision.Scope, requestedScope) {
		return errors.New("authorization decision contains an invalid scope")
	}
	return nil
}

func (resource *Resource) handleLocalAuthorization(
	response http.ResponseWriter,
	request *http.Request,
	requestBody []byte,
	requestVerificationKey aauth.JWK,
	authorizationRequest aauth.AuthorizationRequest,
	verified aauth.VerifiedRequest,
	thumbprint string,
	now time.Time,
) {
	if resource.interactionRequired != nil {
		required, err := resource.interactionRequired(request.Context(), copyAuthorizationRequest(authorizationRequest))
		if err != nil {
			writeHostPolicyRefusal(response, "access_denied", "authorization policy denied the request")
			return
		}
		if required {
			if err := resource.beginPendingAuthorization(
				response,
				authorizationRequest,
				requestBody,
				requestProof(request, verified),
				requestVerificationKey,
				thumbprint,
				credentialExpiry(verified),
				now,
			); err != nil {
				writeProblem(response, http.StatusInternalServerError, "server_error", err)
			}
			return
		}
	}
	decision, err := resource.authorizationPolicy(request.Context(), copyAuthorizationRequest(authorizationRequest))
	if err != nil {
		writeHostPolicyRefusal(response, "access_denied", "authorization policy denied the request")
		return
	}
	if err := validateAuthorizationDecision(decision, authorizationRequest.Scope); err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", errors.New("local authorization policy returned an invalid grant"))
		return
	}
	expiresAt := now.Add(time.Hour)
	if credentialExpiresAt := credentialExpiry(verified); credentialExpiresAt.Before(expiresAt) {
		expiresAt = credentialExpiresAt
	}
	if err := resource.writeAccessGrant(response, authorizationRequest, decision, thumbprint, expiresAt); err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", err)
	}
}

func (resource *Resource) writeAccessGrant(
	response http.ResponseWriter,
	request aauth.AuthorizationRequest,
	decision aauth.AuthorizationDecision,
	thumbprint string,
	expiresAt time.Time,
) error {
	token, err := resource.storeAccessGrant(request, decision, thumbprint, expiresAt)
	if err != nil {
		return err
	}
	response.Header().Set("AAuth-Access", token)
	writeJSON(response, http.StatusOK, map[string]any{
		"status": "authorized",
		"scope":  strings.Join(decision.Scope, " "),
	})
	return nil
}

func (resource *Resource) storeAccessGrant(
	request aauth.AuthorizationRequest,
	decision aauth.AuthorizationDecision,
	thumbprint string,
	expiresAt time.Time,
) (string, error) {
	resource.pendingMu.Lock()
	defer resource.pendingMu.Unlock()
	return resource.storeAccessGrantLocked(context.Background(), request, decision, thumbprint, expiresAt)
}

func (resource *Resource) storeAccessGrantLocked(
	ctx context.Context,
	request aauth.AuthorizationRequest,
	decision aauth.AuthorizationDecision,
	thumbprint string,
	expiresAt time.Time,
) (string, error) {
	accessToken, err := resource.addAccessGrantLocked(request, decision, thumbprint, expiresAt, "")
	if err != nil {
		return "", err
	}
	if err := resource.persistAuthorizationStateLocked(ctx); err != nil {
		return "", err
	}
	return accessToken, nil
}

func (resource *Resource) addAccessGrantLocked(
	request aauth.AuthorizationRequest,
	decision aauth.AuthorizationDecision,
	thumbprint string,
	expiresAt time.Time,
	sourcePendingID string,
) (string, error) {
	accessToken := resource.newID()
	if err := aauth.ValidateAccessToken(accessToken); err != nil {
		return "", err
	}
	if _, exists := resource.access[accessToken]; exists {
		return "", errors.New("access token source returned a duplicate value")
	}
	resource.access[accessToken] = localAccessGrant{
		agent:           request.Agent,
		subject:         decision.Subject,
		thumbprint:      thumbprint,
		scope:           append([]string(nil), decision.Scope...),
		mission:         request.Mission,
		expiresAt:       expiresAt,
		sourcePendingID: sourcePendingID,
	}
	return accessToken, nil
}

func (resource *Resource) beginPendingAuthorization(
	response http.ResponseWriter,
	request aauth.AuthorizationRequest,
	requestBody []byte,
	requestProof *aauth.RequestProof,
	requestVerificationKey aauth.JWK,
	thumbprint string,
	agentExpiresAt time.Time,
	now time.Time,
) error {
	expiresAt := now.Add(resource.pendingLifetime)
	if agentExpiresAt.Before(expiresAt) {
		expiresAt = agentExpiresAt
	}
	resource.randomMu.Lock()
	interaction, err := newPendingInteraction(resource.random, expiresAt)
	resource.randomMu.Unlock()
	if err != nil {
		return err
	}
	pending := &pendingAuthorization{
		pendingInteraction:     interaction,
		request:                copyAuthorizationRequest(request),
		requestBody:            append([]byte(nil), requestBody...),
		requestProof:           copyRequestProof(requestProof),
		requestVerificationKey: requestVerificationKey,
		agentThumbprint:        thumbprint,
		agentExpiresAt:         agentExpiresAt,
	}
	resource.pendingMu.Lock()
	if _, exists := resource.pending[interaction.id]; exists {
		resource.pendingMu.Unlock()
		return errors.New("pending identifier source returned a duplicate value")
	}
	resource.pending[interaction.id] = pending
	if err := resource.persistAuthorizationStateLocked(context.Background()); err != nil {
		resource.pendingMu.Unlock()
		return err
	}
	resource.pendingMu.Unlock()
	return resource.writePendingAuthorization(
		response,
		interaction.id,
		pendingAuthorizationWaiting,
		interaction.code,
	)
}

func copyAuthorizationRequest(request aauth.AuthorizationRequest) aauth.AuthorizationRequest {
	copied := request
	copied.Scope = append([]string(nil), request.Scope...)
	if request.Mission != nil {
		mission := *request.Mission
		copied.Mission = &mission
	}
	if request.Upstream != nil {
		upstream := *request.Upstream
		upstream.Actor = copyActor(request.Upstream.Actor)
		if request.Upstream.Mission != nil {
			mission := *request.Upstream.Mission
			upstream.Mission = &mission
		}
		copied.Upstream = &upstream
	}
	return copied
}

func copyAuthorizedRequest(request aauth.AuthorizedRequest) aauth.AuthorizedRequest {
	copied := request
	copied.Scope = append([]string(nil), request.Scope...)
	copied.Body = append([]byte(nil), request.Body...)
	if request.Mission != nil {
		mission := *request.Mission
		copied.Mission = &mission
	}
	copied.Actor = copyActor(request.Actor)
	return copied
}

func (resource *Resource) writePendingAuthorization(
	response http.ResponseWriter,
	pendingID string,
	state pendingAuthorizationState,
	code string,
) error {
	requirement, err := aauth.FormatRequirementHeader(aauth.Requirement{
		Type:            aauth.RequirementInteraction,
		InteractionURL:  resource.identifier + "/interaction/" + pendingID,
		InteractionCode: code,
	})
	if err != nil {
		return err
	}
	response.Header().Set("Location", "/pending/"+pendingID)
	response.Header().Set("Retry-After", "0")
	response.Header().Set("AAuth-Requirement", requirement)
	writeJSON(response, http.StatusAccepted, map[string]string{"status": string(state)})
	return nil
}

// ApproveAuthorization records a trusted approval for an interaction the user
// has entered. The interaction code itself cannot call this method or supply
// the grant; deployment policy is evaluated again at approval time.
func (resource *Resource) ApproveAuthorization(ctx context.Context, pendingID string) error {
	resource.pendingMu.Lock()
	if err := resource.settleAuthorizationStateLocked(ctx); err != nil {
		resource.pendingMu.Unlock()
		return err
	}
	pending, exists := resource.pending[pendingID]
	if !exists {
		resource.pendingMu.Unlock()
		return errors.New("reference: pending authorization does not exist")
	}
	now := resource.clock.Now()
	if !pending.expiresAt.After(now) {
		pending.state = pendingAuthorizationExpired
		if err := resource.persistAuthorizationStateLocked(ctx); err != nil {
			resource.pendingMu.Unlock()
			return err
		}
		resource.pendingMu.Unlock()
		return errors.New("reference: pending authorization expired")
	}
	if pending.state != pendingAuthorizationInteracting {
		resource.pendingMu.Unlock()
		return errors.New("reference: pending authorization is not awaiting a trusted decision")
	}
	request := copyAuthorizationRequest(pending.request)
	resource.pendingMu.Unlock()

	decision, err := resource.authorizationPolicy(ctx, request)
	if err != nil {
		return err
	}
	if err := validateAuthorizationDecision(decision, request.Scope); err != nil {
		return err
	}

	resource.pendingMu.Lock()
	defer resource.pendingMu.Unlock()
	if err := resource.settleAuthorizationStateLocked(context.Background()); err != nil {
		return err
	}
	current, exists := resource.pending[pendingID]
	if !exists || current != pending || current.state != pendingAuthorizationInteracting {
		return errors.New("reference: pending authorization changed while approval was evaluated")
	}
	pending = current
	if !pending.expiresAt.After(resource.clock.Now()) {
		pending.state = pendingAuthorizationExpired
		if err := resource.persistAuthorizationStateLocked(ctx); err != nil {
			return err
		}
		return errors.New("reference: pending authorization expired")
	}
	pending.decision = aauth.AuthorizationDecision{
		Subject: decision.Subject,
		Scope:   append([]string(nil), decision.Scope...),
	}
	pending.state = pendingAuthorizationApproved
	return resource.persistAuthorizationStateLocked(ctx)
}

// RejectAuthorization records a trusted terminal denial or abandonment. The
// interaction code cannot invoke this authority boundary.
func (resource *Resource) RejectAuthorization(
	pendingID string,
	code aauth.PollingErrorCode,
) error {
	if code != aauth.PollingDenied &&
		code != aauth.PollingAbandoned &&
		code != aauth.PollingServerError {
		return errors.New("reference: unsupported authorization rejection code")
	}
	resource.pendingMu.Lock()
	defer resource.pendingMu.Unlock()
	if err := resource.settleAuthorizationStateLocked(context.Background()); err != nil {
		return err
	}
	pending, exists := resource.pending[pendingID]
	if !exists {
		return errors.New("reference: pending authorization does not exist")
	}
	if !pending.expiresAt.After(resource.clock.Now()) {
		pending.state = pendingAuthorizationExpired
		if err := resource.persistAuthorizationStateLocked(context.Background()); err != nil {
			return err
		}
		return errors.New("reference: pending authorization expired")
	}
	if pending.state != pendingAuthorizationInteracting {
		return errors.New("reference: pending authorization is not awaiting a trusted decision")
	}
	pending.pollingError = code
	pending.state = pendingAuthorizationRejected
	return resource.persistAuthorizationStateLocked(context.Background())
}

func (resource *Resource) handlePendingAuthorization(response http.ResponseWriter, request *http.Request) {
	resource.pendingMu.Lock()
	stateErr := resource.settleAuthorizationStateLocked(request.Context())
	resource.pendingMu.Unlock()
	if stateErr != nil {
		writeProblem(response, http.StatusServiceUnavailable, "authorization_state_unavailable", stateErr)
		return
	}
	verified, err := aauth.VerifyRequest(request.Context(), request, resource.keyResolver, resource.clock, aauth.VerifyRequestOptions{
		AllowedCredentialTypes: []string{aauth.AgentTokenType},
	})
	if err != nil {
		writeSignatureFailure(response, err)
		return
	}
	thumbprint, err := verified.PublicKey.Thumbprint()
	if err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", nil)
		return
	}

	resource.pendingMu.Lock()
	pending, exists := resource.pending[request.PathValue("id")]
	if !exists {
		resource.pendingMu.Unlock()
		writeProblem(response, http.StatusGone, "gone", errors.New("pending authorization is unknown"))
		return
	}
	if pending.agentThumbprint != thumbprint ||
		pending.request.Agent != "" && pending.request.Agent != verified.Agent {
		resource.pendingMu.Unlock()
		writeProblem(response, http.StatusForbidden, "invalid_pending", errors.New("pending authorization belongs to a different agent key"))
		return
	}
	if (pending.state == pendingAuthorizationWaiting ||
		pending.state == pendingAuthorizationInteracting) &&
		!pending.expiresAt.After(resource.clock.Now()) {
		pending.state = pendingAuthorizationExpired
		if err := resource.persistAuthorizationStateLocked(request.Context()); err != nil {
			resource.pendingMu.Unlock()
			writeProblem(response, http.StatusServiceUnavailable, "authorization_state_unavailable", err)
			return
		}
	}

	switch pending.state {
	case pendingAuthorizationWaiting, pendingAuthorizationInteracting:
		id := pending.id
		state := pending.state
		code := pending.code
		resource.pendingMu.Unlock()
		if err := resource.writePendingAuthorization(response, id, state, code); err != nil {
			writeProblem(response, http.StatusInternalServerError, "server_error", err)
		}
	case pendingAuthorizationApproved:
		token := pending.terminalAccessToken
		if token == "" && !pending.agentExpiresAt.After(resource.clock.Now()) {
			pending.state = pendingAuthorizationExpired
			if err := resource.persistAuthorizationStateLocked(request.Context()); err != nil {
				resource.pendingMu.Unlock()
				writeProblem(response, http.StatusServiceUnavailable, "authorization_state_unavailable", err)
				return
			}
			resource.pendingMu.Unlock()
			writeProblem(response, http.StatusRequestTimeout, "expired", errors.New("pending authorization credential expired"))
			return
		}
		if token == "" {
			expiresAt := resource.clock.Now().Add(time.Hour)
			if pending.agentExpiresAt.Before(expiresAt) {
				expiresAt = pending.agentExpiresAt
			}
			var err error
			token, err = resource.addAccessGrantLocked(
				pending.request, pending.decision,
				pending.agentThumbprint, expiresAt, pending.id,
			)
			if err != nil {
				resource.pendingMu.Unlock()
				writeProblem(response, http.StatusInternalServerError, "server_error", err)
				return
			}
			pending.terminalAccessToken = token
			if err := resource.persistAuthorizationStateLocked(request.Context()); err != nil {
				resource.pendingMu.Unlock()
				writeProblem(response, http.StatusServiceUnavailable, "authorization_state_unavailable", err)
				return
			}
		}
		decision := pending.decision
		resource.pendingMu.Unlock()
		response.Header().Set("AAuth-Access", token)
		writeJSON(response, http.StatusOK, map[string]any{
			"status": "authorized",
			"scope":  strings.Join(decision.Scope, " "),
		})
	case pendingAuthorizationExpired:
		resource.pendingMu.Unlock()
		writeProblem(response, http.StatusRequestTimeout, "expired", errors.New("pending authorization expired"))
	case pendingAuthorizationRejected:
		code := pending.pollingError
		resource.pendingMu.Unlock()
		status := http.StatusForbidden
		if code == aauth.PollingServerError {
			status = http.StatusInternalServerError
		}
		writeProblem(response, status, string(code), errors.New("pending authorization was not approved"))
	case pendingAuthorizationInvalidCode:
		resource.pendingMu.Unlock()
		writeProblem(response, http.StatusGone, "invalid_code", errors.New("interaction code validation failed"))
	default:
		resource.pendingMu.Unlock()
		writeProblem(response, http.StatusGone, "gone", errors.New("pending authorization has an invalid state"))
	}
}

func (resource *Resource) handleInteraction(response http.ResponseWriter, request *http.Request) {
	resource.pendingMu.Lock()
	stateErr := resource.settleAuthorizationStateLocked(request.Context())
	resource.pendingMu.Unlock()
	if stateErr != nil {
		writeProblem(response, http.StatusServiceUnavailable, "authorization_state_unavailable", stateErr)
		return
	}
	resource.pendingMu.Lock()
	pending, exists := resource.pending[request.PathValue("id")]
	if !exists {
		resource.pendingMu.Unlock()
		writeProblem(response, http.StatusGone, "invalid_code", errors.New("pending interaction is unknown"))
		return
	}
	status, code, err := pending.correlate(
		request.URL.Query()["code"],
		resource.clock.Now(),
	)
	if persistErr := resource.persistAuthorizationStateLocked(request.Context()); persistErr != nil {
		resource.pendingMu.Unlock()
		writeProblem(response, http.StatusServiceUnavailable, "authorization_state_unavailable", persistErr)
		return
	}
	if err != nil {
		resource.pendingMu.Unlock()
		writeProblem(response, status, code, err)
		return
	}
	authorizationRequest := copyAuthorizationRequest(pending.request)
	resource.pendingMu.Unlock()

	writeJSON(response, http.StatusOK, map[string]any{
		"status":   "interacting",
		"agent":    authorizationRequest.Agent,
		"resource": authorizationRequest.Resource,
		"scope":    strings.Join(authorizationRequest.Scope, " "),
	})
}

func (resource *Resource) handleProtected(response http.ResponseWriter, request *http.Request) {
	if usesAAuthScheme(request.Header.Get("Authorization")) {
		resource.handleAccessProtected(response, request)
		return
	}
	if resource.accessMode == aauth.AccessModeSessionToken {
		resource.pendingMu.Lock()
		stateErr := resource.settleAuthorizationStateLocked(request.Context())
		resource.pendingMu.Unlock()
		if stateErr != nil {
			writeProblem(response, http.StatusServiceUnavailable, "authorization_state_unavailable", stateErr)
			return
		}
	}
	exactBody, err := readBoundedRequestBody(request)
	if err != nil {
		writeProblem(response, http.StatusRequestEntityTooLarge, "request_too_large", err)
		return
	}
	var requiredComponents []string
	if len(exactBody) != 0 {
		requiredComponents = append(requiredComponents, "content-type")
	}
	allowedCredentialTypes := []string{aauth.AuthTokenType}
	if resource.accessMode == aauth.AccessModeSessionToken {
		allowedCredentialTypes = []string{aauth.AgentTokenType}
	}
	credentialKeyCapture, verificationResolver := newRetainedKeyCapture(resource.keyResolver)
	verified, err := aauth.VerifyRequest(request.Context(), request, verificationResolver, resource.clock, aauth.VerifyRequestOptions{
		RequiredComponents:     requiredComponents,
		RequireExactComponents: true,
		AllowedCredentialTypes: allowedCredentialTypes,
	})
	if err != nil {
		writeSignatureFailure(response, err)
		return
	}
	if resource.accessMode == aauth.AccessModeSessionToken {
		requestVerificationKey, err := credentialKeyCapture.retainedKey()
		if err != nil {
			writeProblem(response, http.StatusInternalServerError, "server_error", err)
			return
		}
		requiredScopes, err := resource.requiredScopes(request)
		if err != nil {
			writeProblem(response, http.StatusInternalServerError, "scope_mapping_failed", err)
			return
		}
		if !resource.consumeProof(response, request, verified) {
			return
		}
		thumbprint, err := verified.PublicKey.Thumbprint()
		if err != nil {
			writeProblem(response, http.StatusInternalServerError, "server_error", nil)
			return
		}
		resource.handleLocalAuthorization(
			response,
			request,
			exactBody,
			requestVerificationKey,
			aauth.AuthorizationRequest{
				Agent:    verified.Agent,
				Resource: resource.identifier,
				Scope:    append([]string(nil), requiredScopes...),
			},
			verified,
			thumbprint,
			verified.VerifiedAt,
		)
		return
	}
	claims := verified.AuthToken
	if resource.accessMode != aauth.AccessModeAuthToken {
		writeProblem(response, http.StatusForbidden, "invalid_token", errors.New("resource does not accept auth tokens for protected operations"))
		return
	}
	if claims.Issuer != resource.tokenAudience {
		writeProblem(response, http.StatusForbidden, "invalid_token", errors.New("auth-token issuer is not the resource authorization server"))
		return
	}
	if claims.PersonServer == "" {
		writeProblem(response, http.StatusForbidden, "invalid_token", errors.New("current auth-token ps is required"))
		return
	}
	if claims.DWK != resource.authTokenDiscoveryDocument {
		writeProblem(response, http.StatusForbidden, "invalid_token", errors.New("auth-token issuer role does not match resource configuration"))
		return
	}
	requiredScopes, err := resource.requiredScopes(request)
	if err != nil {
		writeProblem(response, http.StatusInternalServerError, "scope_mapping_failed", err)
		return
	}
	contextErr := aauth.ValidateCurrentAuthTokenContext(
		*claims,
		resource.identifier,
		claims.PersonServer,
		claims.Subject,
		verified.PublicKey,
		requiredScopes,
	)
	if contextErr != nil {
		writeProblem(response, http.StatusForbidden, "invalid_token", contextErr)
		return
	}
	granted, err := parseScopes(claims.Scope)
	if err != nil {
		writeProblem(response, http.StatusForbidden, "insufficient_scope", err)
		return
	}
	if !resource.consumeProof(response, request, verified) {
		return
	}
	authorized := aauth.AuthorizedRequest{
		Agent:              claims.Agent,
		PersonServer:       claims.PersonServer,
		Subject:            claims.Subject,
		AuthTokenIssuer:    claims.Issuer,
		AuthTokenDWK:       claims.DWK,
		AuthTokenID:        claims.JTI,
		AuthTokenIssuedAt:  time.Unix(claims.IssuedAt, 0).UTC(),
		AuthTokenExpiresAt: time.Unix(claims.ExpiresAt, 0).UTC(),
		ConfirmationKey:    verified.PublicKey,
		ProofReplayKey:     verified.ReplayKey,
		ProofCreatedAt:     verified.Created.UTC(),
		Scope:              granted,
		Mission:            claims.Mission,
		MissionS256:        claims.MissionS256,
		Tenant:             claims.Tenant,
		Account:            claims.Account,
		Actor:              claims.Actor,
		AuthToken:          verified.RawCredential,
		Method:             request.Method,
		Path:               request.URL.Path,
		Body:               append([]byte(nil), exactBody...),
		ContentType:        request.Header.Get("Content-Type"),
	}
	if err := resource.protectedAuthorizationPolicy(
		request.Context(),
		copyAuthorizedRequest(authorized),
	); err != nil {
		writeProblem(response, http.StatusForbidden, "invalid_token", errors.New("protected request was denied by resource policy"))
		return
	}
	result, err := resource.operation(request.Context(), authorized)
	if err != nil {
		writeProblem(response, http.StatusInternalServerError, "operation_failed", err)
		return
	}
	if protected, ok := protectedEventOperationResult(result); ok {
		resource.issueProtectedEventTicket(response, request, authorized, protected)
		return
	}
	writeJSON(response, http.StatusOK, result)
}

func writePersonTokenRequired(response http.ResponseWriter, detail string) {
	requirement, err := aauth.FormatRequirementHeader(aauth.Requirement{Type: aauth.RequirementPersonToken})
	if err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", err)
		return
	}
	response.Header().Set("AAuth-Requirement", requirement)
	writeProblem(response, http.StatusUnauthorized, "person_token_required", errors.New(detail))
}

func protectedEventOperationResult(value any) (ProtectedEventOperationResult, bool) {
	switch result := value.(type) {
	case ProtectedEventOperationResult:
		return result, true
	case *ProtectedEventOperationResult:
		if result != nil {
			return *result, true
		}
	}
	return ProtectedEventOperationResult{}, false
}

func (resource *Resource) issueProtectedEventTicket(
	response http.ResponseWriter,
	request *http.Request,
	authorized aauth.AuthorizedRequest,
	result ProtectedEventOperationResult,
) {
	if resource.eventProtectedOperation == "" || resource.eventContractStore == nil ||
		resource.eventTicketStore == nil || result.Response == nil ||
		result.Ticket.ResourceRevision == "" {
		writeProblem(response, http.StatusInternalServerError, "event_ticket_not_configured", errors.New("reference: protected event ticket is not configured"))
		return
	}
	if err := aauth.ValidateAgentIdentifier(result.Ticket.Agent); err != nil {
		writeProblem(response, http.StatusInternalServerError, "invalid_event_ticket", fmt.Errorf("reference: protected event ticket agent: %w", err))
		return
	}
	now := resource.clock.Now()
	expiresAt := now.Add(resource.eventTicketLifetime)
	if !result.Ticket.ActiveUntil.After(expiresAt) {
		writeProblem(response, http.StatusInternalServerError, "invalid_event_ticket", errors.New("reference: protected event subscription must outlive its ticket"))
		return
	}
	if err := resource.eventContractStore.Retain(
		request.Context(),
		resource.eventAsyncAPIContract.Digest(),
		resource.eventAsyncAPIContract.ExactBytes(),
		result.Ticket.ActiveUntil,
	); err != nil {
		writeProblem(response, http.StatusServiceUnavailable, "event_ticket_unavailable", err)
		return
	}
	rawBytes := make([]byte, 32)
	resource.randomMu.Lock()
	_, randomErr := io.ReadFull(resource.random, rawBytes)
	resource.randomMu.Unlock()
	if randomErr != nil {
		writeProblem(response, http.StatusServiceUnavailable, "event_ticket_unavailable", randomErr)
		return
	}
	rawTicket := base64.RawURLEncoding.EncodeToString(rawBytes)
	ticket := ProtectedEventTicket{
		TicketDigest: protectedEventTicketDigest(rawTicket), Resource: resource.identifier,
		Agent: result.Ticket.Agent, AuthorizedMethod: authorized.Method, AuthorizedPath: authorized.Path,
		ResourceRevision: result.Ticket.ResourceRevision,
		ContractDigest:   resource.eventAsyncAPIContract.Digest(),
		OperationID:      resource.eventProtectedMessage.OperationID,
		MessageID:        resource.eventProtectedMessage.MessageID,
		ExpiresAt:        expiresAt, ActiveUntil: result.Ticket.ActiveUntil,
	}
	if err := resource.eventTicketStore.CreateTicket(request.Context(), ticket); err != nil {
		writeProblem(response, http.StatusServiceUnavailable, "event_ticket_unavailable", err)
		return
	}
	path := strings.Replace(
		resource.eventProtectedMessage.Address,
		"{"+resource.eventProtectedMessage.TicketParameter+"}",
		rawTicket,
		1,
	)
	grant := ProtectedEventTicketGrant{
		URL: resource.identifier + path, ContractDigest: ticket.ContractDigest,
		OperationID: ticket.OperationID, MessageID: ticket.MessageID,
	}
	rendered, err := result.Response(grant)
	if err != nil {
		writeProblem(response, http.StatusInternalServerError, "operation_response_failed", err)
		return
	}
	writeJSON(response, http.StatusOK, rendered)
}

func usesAAuthScheme(header string) bool {
	separator := strings.IndexByte(header, ' ')
	return separator > 0 && strings.EqualFold(header[:separator], "AAuth")
}

func (resource *Resource) handleAccessProtected(response http.ResponseWriter, request *http.Request) {
	resource.pendingMu.Lock()
	stateErr := resource.settleAuthorizationStateLocked(request.Context())
	resource.pendingMu.Unlock()
	if stateErr != nil {
		writeProblem(response, http.StatusServiceUnavailable, "authorization_state_unavailable", stateErr)
		return
	}
	exactBody, err := readBoundedRequestBody(request)
	if err != nil {
		writeProblem(response, http.StatusRequestEntityTooLarge, "request_too_large", err)
		return
	}
	requiredComponents := []string{"authorization"}
	if len(exactBody) != 0 {
		requiredComponents = append(requiredComponents, "content-type")
	}
	verified, err := aauth.VerifyRequest(request.Context(), request, resource.keyResolver, resource.clock, aauth.VerifyRequestOptions{
		RequiredComponents:     requiredComponents,
		AllowedCredentialTypes: []string{aauth.AgentTokenType},
	})
	if err != nil {
		writeSignatureFailure(response, err)
		return
	}
	accessToken, err := aauth.ParseAccessAuthorization(request.Header.Get("Authorization"))
	if err != nil {
		writeProblem(response, http.StatusBadRequest, "invalid_access", err)
		return
	}
	resource.pendingMu.Lock()
	grant, exists := resource.access[accessToken]
	if exists && !grant.expiresAt.After(resource.clock.Now()) {
		delete(resource.access, accessToken)
		if err := resource.persistAuthorizationStateLocked(request.Context()); err != nil {
			resource.pendingMu.Unlock()
			writeProblem(response, http.StatusServiceUnavailable, "authorization_state_unavailable", err)
			return
		}
		exists = false
	}
	resource.pendingMu.Unlock()
	if !exists {
		writeProblem(response, http.StatusForbidden, "invalid_access", errors.New("access token is unknown or expired"))
		return
	}
	thumbprint, err := verified.PublicKey.Thumbprint()
	if err != nil || grant.thumbprint != thumbprint ||
		grant.agent != "" && grant.agent != verified.Agent {
		writeProblem(response, http.StatusForbidden, "invalid_access", errors.New("access token is bound to a different agent key"))
		return
	}
	requiredScopes, err := resource.requiredScopes(request)
	if err != nil {
		writeProblem(response, http.StatusInternalServerError, "scope_mapping_failed", err)
		return
	}
	if !scopesContained(requiredScopes, grant.scope) {
		writeProblem(response, http.StatusForbidden, "insufficient_scope", errors.New("access token does not grant the operation scope"))
		return
	}
	if !resource.consumeProof(response, request, verified) {
		return
	}
	result, err := resource.operation(request.Context(), aauth.AuthorizedRequest{
		Agent:           verified.Agent,
		Subject:         grant.subject,
		ConfirmationKey: verified.PublicKey,
		ProofReplayKey:  verified.ReplayKey,
		ProofCreatedAt:  verified.Created.UTC(),
		Scope:           append([]string(nil), grant.scope...),
		Mission:         grant.mission,
		Method:          request.Method,
		Path:            request.URL.Path,
		Body:            append([]byte(nil), exactBody...),
		ContentType:     request.Header.Get("Content-Type"),
	})
	if err != nil {
		writeProblem(response, http.StatusInternalServerError, "operation_failed", err)
		return
	}
	writeJSON(response, http.StatusOK, result)
}

func (resource *Resource) consumeProof(
	response http.ResponseWriter,
	request *http.Request,
	verified aauth.VerifiedRequest,
) bool {
	err := resource.replayStore.Consume(
		request.Context(),
		verified.ReplayKey,
		verified.Created.Add(aauth.DefaultSignatureWindow),
	)
	if err == nil {
		return true
	}
	if errors.Is(err, ErrProofReplay) {
		writeSignatureFailure(response, ErrProofReplay)
		return false
	}
	writeProblem(response, http.StatusServiceUnavailable, "proof_replay_unavailable", err)
	return false
}

func (resource *Resource) requiredScopes(request *http.Request) ([]string, error) {
	if resource.requiredScopesForRequest == nil {
		return nil, errors.New("reference: current resource required-scope mapper is unavailable")
	}
	required, err := resource.requiredScopesForRequest(request.Context(), request)
	if err != nil {
		return nil, fmt.Errorf("reference: map protected request scopes: %w", err)
	}
	return canonicalRequiredScopes(required, resource.scopes)
}

func canonicalRequiredScopes(required, allowlist []string) ([]string, error) {
	positions := make(map[string]int, len(allowlist))
	for index, scope := range allowlist {
		if scope == "" || strings.TrimSpace(scope) != scope || len(strings.Fields(scope)) != 1 {
			return nil, fmt.Errorf("reference: resource scope %q is not canonical", scope)
		}
		if _, duplicate := positions[scope]; duplicate {
			return nil, fmt.Errorf("reference: resource scope %q is duplicated", scope)
		}
		positions[scope] = index
	}
	if len(required) == 0 {
		return nil, errors.New("reference: protected request requires at least one scope")
	}
	canonical := make([]string, len(required))
	previous := -1
	for index, scope := range required {
		position, allowed := positions[scope]
		if scope == "" || strings.TrimSpace(scope) != scope || len(strings.Fields(scope)) != 1 {
			return nil, fmt.Errorf("reference: required scope %q is not canonical", scope)
		}
		if !allowed {
			return nil, fmt.Errorf("reference: required scope %q is outside the issuance allowlist", scope)
		}
		if position <= previous {
			return nil, errors.New("reference: required scopes are duplicated or not in canonical allowlist order")
		}
		canonical[index] = scope
		previous = position
	}
	return canonical, nil
}

func validateScopeDescriptions(scopes []string, descriptions map[string]string) error {
	if len(descriptions) != len(scopes) {
		return errors.New("reference: scope descriptions must exactly cover the issuance allowlist")
	}
	allowed := make(map[string]struct{}, len(scopes))
	for _, scope := range scopes {
		allowed[scope] = struct{}{}
		description, exists := descriptions[scope]
		if !exists || description == "" || strings.TrimSpace(description) != description {
			return fmt.Errorf("reference: scope descriptions must contain a canonical nonempty description for %q", scope)
		}
	}
	for scope := range descriptions {
		if _, exists := allowed[scope]; !exists {
			return fmt.Errorf("reference: scope descriptions contain scope %q outside the issuance allowlist", scope)
		}
	}
	return nil
}

func cloneScopeDescriptions(descriptions map[string]string) map[string]string {
	if descriptions == nil {
		return nil
	}
	cloned := make(map[string]string, len(descriptions))
	for scope, description := range descriptions {
		cloned[scope] = description
	}
	return cloned
}

func (resource *Resource) handleMetadata(response http.ResponseWriter, _ *http.Request) {
	metadata := map[string]any{
		"issuer":                 resource.identifier,
		"authorization_endpoint": resource.identifier + "/authorize",
	}
	metadata["access_mode"] = string(resource.accessMode)
	if len(resource.scopeDescriptions) != 0 {
		metadata["scope_descriptions"] = cloneScopeDescriptions(resource.scopeDescriptions)
	}
	if resource.hasSigningKey {
		metadata["jwks_uri"] = resource.identifier + "/jwks"
	}
	if len(resource.r3Vocabularies) != 0 {
		vocabularies := make(map[string]json.RawMessage, len(resource.r3Vocabularies))
		for vocabulary, discovery := range resource.r3Vocabularies {
			vocabularies[vocabulary] = append(json.RawMessage(nil), discovery...)
		}
		metadata["r3_vocabularies"] = vocabularies
	}
	writeJSON(response, http.StatusOK, metadata)
}

func (resource *Resource) handleJWKS(response http.ResponseWriter, _ *http.Request) {
	if !resource.hasSigningKey {
		writeProblem(response, http.StatusNotFound, "not_found", errors.New("resource has no signing keys"))
		return
	}
	writeJSON(response, http.StatusOK, map[string]any{
		"keys": []aauth.JWK{resource.signingKey.PublicJWK()},
	})
}
