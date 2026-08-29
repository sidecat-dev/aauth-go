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

	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"

	aauth "gitlab.com/sidecat-dev/aauth-go"
)

type PersonServerConfig struct {
	Identifier                    string
	SigningKey                    jose.SigningKey
	KeyResolver                   signaturekey.KeyResolver
	Clock                         aauth.Clock
	NewID                         func() string
	CurrentMissionPolicy          aauth.CurrentMissionPolicy
	AuthorizationPolicy           aauth.AuthorizationPolicy
	PermissionPolicy              aauth.PermissionPolicy
	PermissionInteractionRequired func(context.Context, aauth.PermissionEvaluation) (bool, error)
	GovernanceStore               GovernanceStore
	PersonTokenStore              PersonTokenStore
	PersonTokenPolicy             aauth.PersonTokenPolicy
	MissionIssuanceStore          MissionIssuanceStore
	CompletionReviewEnabled       bool
	InteractionRequired           func(context.Context, aauth.AuthorizationRequest) (bool, error)
	Random                        io.Reader
	PendingLifetime               time.Duration
	AuthorizationStore            AuthorizationStateStore
	FederationClient              *http.Client
	AccessServerEndpoint          func(context.Context, string) (string, error)
	TrustedUpstreamIssuer         func(context.Context, string) error
}

type PersonServer struct {
	identifier                    string
	signingKey                    jose.SigningKey
	keyResolver                   signaturekey.KeyResolver
	clock                         aauth.Clock
	newID                         func() string
	currentMissionPolicy          aauth.CurrentMissionPolicy
	authorizationPolicy           aauth.AuthorizationPolicy
	permissionPolicy              aauth.PermissionPolicy
	permissionInteractionRequired func(context.Context, aauth.PermissionEvaluation) (bool, error)
	governanceStore               GovernanceStore
	personTokenStore              PersonTokenStore
	personTokenPolicy             aauth.PersonTokenPolicy
	missionIssuanceStore          MissionIssuanceStore
	completionReviewEnabled       bool
	interactionRequired           func(context.Context, aauth.AuthorizationRequest) (bool, error)
	random                        io.Reader
	pendingLifetime               time.Duration
	authorizationStore            AuthorizationStateStore
	federationClient              *http.Client
	accessServerEndpoint          func(context.Context, string) (string, error)
	trustedUpstreamIssuer         func(context.Context, string) error

	mu                    sync.RWMutex
	missionIssuanceMu     sync.Mutex
	missions              map[string]storedMission
	randomMu              sync.Mutex
	governanceReplays     map[string]time.Time
	permissionHistory     []aauth.PermissionRecord
	interactionHistory    []aauth.InteractionRecord
	completionPending     map[string]pendingCompletion
	pendingMu             sync.Mutex
	authorizationErr      error
	authorizationBody     []byte
	authorizationRecovery []byte
	pending               map[string]*pendingPersonAuthorization
	permissionPending     map[string]pendingPersonPermission
	replayMu              sync.Mutex
	replayedProof         map[string]time.Time
}

type personTokenPolicyDenialError struct{ cause error }

func (err *personTokenPolicyDenialError) Error() string {
	if err == nil || err.cause == nil {
		return "reference: person-token policy denied the request"
	}
	return "reference: person-token policy denied the request: " + err.cause.Error()
}

func (err *personTokenPolicyDenialError) Unwrap() error {
	if err == nil {
		return nil
	}
	return err.cause
}

type personTokenCustodyError struct{ cause error }

func (err *personTokenCustodyError) Error() string {
	if err == nil || err.cause == nil {
		return "reference: person-token custody failed"
	}
	return "reference: person-token custody failed: " + err.cause.Error()
}

func (err *personTokenCustodyError) Unwrap() error {
	if err == nil {
		return nil
	}
	return err.cause
}

type storedMission struct {
	reference         aauth.MissionReference
	agent             string
	bytes             []byte
	description       string
	approvedTools     []aauth.Tool
	approvedResources []string
	capabilities      []string
	expiresAt         *time.Time
	status            aauth.MissionStatus
	log               []aauth.MissionLogEntry
}

type missionBlob struct {
	Approver          string       `json:"approver"`
	Agent             string       `json:"agent"`
	ApprovedAt        string       `json:"approved_at"`
	ExpiresAt         string       `json:"expires_at,omitempty"`
	Description       string       `json:"description"`
	ApprovedTools     []aauth.Tool `json:"approved_tools,omitempty"`
	ApprovedResources []string     `json:"approved_resources,omitempty"`
	Capabilities      []string     `json:"capabilities,omitempty"`
}

type personAuthorizationContext struct {
	request                aauth.AuthorizationRequest
	resourceTokenCompact   string
	agentTokenCompact      string
	subagentTokenCompact   string
	upstreamTokenCompact   string
	tokenVerificationKeys  retainedAuthorizationTokenKeys
	targetAgent            string
	targetKey              jose.JWK
	parentAgent            string
	pollingAgent           string
	pollingAgentThumbprint string
	targetTokenExpiresAt   int64
	resourceToken          aauth.ResourceTokenClaims
	personTokenRecord      PersonTokenRecord
	requestBody            []byte
	requestProof           *aauth.RequestProof
}

type pendingPersonAuthorization struct {
	pendingInteraction
	context                 personAuthorizationContext
	decision                aauth.AuthorizationDecision
	federated               *pendingFederatedAuthorization
	pollingFederation       bool
	terminalAuthToken       string
	terminalVerificationKey *jose.JWK
	terminalExpiresAt       int64
	terminalStatus          int
	terminalCode            string
	terminalDetail          string
}

type pendingFederatedAuthorization struct {
	accessServer string
	location     string
	retryAfter   time.Duration
	notBefore    time.Time
	status       string
	requirement  *aauth.Requirement
}

type pendingPersonPermission struct {
	pendingInteraction
	agent                  string
	pollingAgentThumbprint string
	requestReplayKey       string
	requestBody            []byte
	decision               aauth.PermissionDecision
}

type accessServerExchange struct {
	authToken       string
	claims          aauth.AuthTokenClaims
	verificationKey *jose.JWK
	deferred        *aauth.DeferredResponse
}

// retainedKeyResolver records the exact key material returned to token
// verification. A resolver may refresh a same-kid key after the first
// signature check fails, so recovery custody must retain the key from the
// successful resolution path rather than perform a second lookup.
type retainedKeyResolver struct {
	resolver signaturekey.KeyResolver
	key      jose.JWK
	found    bool
}

func (resolver *retainedKeyResolver) ResolveKey(
	ctx context.Context,
	issuer string,
	discoveryDocument string,
	keyID string,
) (jose.JWK, error) {
	key, err := resolver.resolver.ResolveKey(ctx, issuer, discoveryDocument, keyID)
	if err == nil {
		resolver.key = key
		resolver.found = true
	}
	return key, err
}

type retainedRefreshingKeyResolver struct {
	*retainedKeyResolver
	refresher signaturekey.KeyRefresher
}

func newRetainedKeyCapture(resolver signaturekey.KeyResolver) (*retainedKeyResolver, signaturekey.KeyResolver) {
	capture := &retainedKeyResolver{resolver: resolver}
	if refresher, ok := resolver.(signaturekey.KeyRefresher); ok {
		return capture, &retainedRefreshingKeyResolver{
			retainedKeyResolver: capture,
			refresher:           refresher,
		}
	}
	return capture, capture
}

func (resolver *retainedKeyResolver) retainedKey() (jose.JWK, error) {
	if resolver == nil || !resolver.found {
		return jose.JWK{}, errors.New("reference: verified token key material was not retained")
	}
	return resolver.key, nil
}

func (resolver *retainedRefreshingKeyResolver) RefreshKey(
	ctx context.Context,
	issuer string,
	discoveryDocument string,
	keyID string,
) (jose.JWK, error) {
	key, err := resolver.refresher.RefreshKey(ctx, issuer, discoveryDocument, keyID)
	if err == nil {
		resolver.key = key
		resolver.found = true
	}
	return key, err
}

func (server *PersonServer) signFederationRequest(request *http.Request) error {
	nonceBytes := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, nonceBytes); err != nil {
		return fmt.Errorf("reference: generate federation proof nonce: %w", err)
	}
	return signaturekey.SignJWKSURIRequestWithOptions(
		request, server.signingKey, server.identifier, aauth.PersonDiscoveryDocument, server.clock,
		signaturekey.SignOptions{Nonce: base64.RawURLEncoding.EncodeToString(nonceBytes)},
	)
}

const personAuthorizationStateSchema = "aauth.reference.person-authorization-state"

type personAuthorizationStateRecord struct {
	Key                     string                           `json:"key"`
	Interaction             pendingInteractionRecord         `json:"interaction"`
	Context                 personAuthorizationContextRecord `json:"context"`
	Decision                aauth.AuthorizationDecision      `json:"decision"`
	Federated               *pendingFederatedRecord          `json:"federated,omitempty"`
	TerminalAuthToken       string                           `json:"terminal_auth_token,omitempty"`
	TerminalVerificationKey *jose.JWK                        `json:"terminal_verification_key,omitempty"`
	TerminalExpiresAt       int64                            `json:"terminal_expires_at,omitempty"`
	TerminalStatus          int                              `json:"terminal_status,omitempty"`
	TerminalCode            string                           `json:"terminal_code,omitempty"`
	TerminalDetail          string                           `json:"terminal_detail,omitempty"`
}

type personAuthorizationContextRecord struct {
	Request                aauth.AuthorizationRequest     `json:"request"`
	ResourceTokenCompact   string                         `json:"resource_token"`
	AgentTokenCompact      string                         `json:"agent_token"`
	SubagentTokenCompact   string                         `json:"subagent_token,omitempty"`
	UpstreamTokenCompact   string                         `json:"upstream_token,omitempty"`
	TokenVerificationKeys  retainedAuthorizationTokenKeys `json:"token_verification_keys"`
	TargetAgent            string                         `json:"target_agent"`
	TargetKey              jose.JWK                       `json:"target_key"`
	ParentAgent            string                         `json:"parent_agent,omitempty"`
	PollingAgent           string                         `json:"polling_agent"`
	PollingAgentThumbprint string                         `json:"polling_agent_thumbprint"`
	TargetTokenExpiresAt   int64                          `json:"target_token_expires_at"`
	ResourceToken          aauth.ResourceTokenClaims      `json:"resource_token_claims"`
	PersonTokenRecord      PersonTokenRecord              `json:"person_token_record"`
	RequestBody            []byte                         `json:"request_body"`
	RequestProof           *aauth.RequestProof            `json:"request_proof"`
}

type personAuthorizationTokenInput struct {
	ResourceToken string `json:"resource_token"`
	SubagentToken string `json:"subagent_token,omitempty"`
	UpstreamToken string `json:"upstream_token,omitempty"`
	Justification string `json:"justification,omitempty"`
}

type pendingFederatedRecord struct {
	AccessServer string             `json:"access_server"`
	Location     string             `json:"location"`
	RetryAfter   time.Duration      `json:"retry_after"`
	NotBefore    time.Time          `json:"not_before"`
	Status       string             `json:"status"`
	Requirement  *aauth.Requirement `json:"requirement,omitempty"`
}

var (
	ErrMissionUnknown    = errors.New("reference: mission is unknown")
	ErrMissionTerminated = errors.New("reference: mission is terminated")
	ErrMissionExpired    = errors.New("reference: mission is expired")
)

const currentResourceTokenLifetime = 5 * time.Minute

func NewPersonServer(config PersonServerConfig) (*PersonServer, error) {
	if err := aauth.ValidateServerIdentifier(config.Identifier); err != nil {
		return nil, err
	}
	if config.SigningKey.ID() == "" || config.KeyResolver == nil || config.Clock == nil ||
		config.NewID == nil || config.AuthorizationPolicy == nil {
		return nil, errors.New("reference: person server requires key, resolver, clock, id source, and authorization policy")
	}
	if (config.FederationClient == nil) != (config.AccessServerEndpoint == nil) {
		return nil, errors.New("reference: federation client and access-server endpoint resolver must be configured together")
	}
	if config.PersonTokenStore == nil || config.PersonTokenPolicy == nil ||
		config.CurrentMissionPolicy == nil || config.MissionIssuanceStore == nil {
		return nil, errors.New("reference: person server requires person-token custody and policy, current mission policy, and mission issuance custody")
	}
	if config.AuthorizationStore == nil {
		return nil, errors.New("reference: person server requires an authorization state store")
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
	server := &PersonServer{
		identifier:                    config.Identifier,
		signingKey:                    config.SigningKey,
		keyResolver:                   config.KeyResolver,
		clock:                         config.Clock,
		newID:                         config.NewID,
		currentMissionPolicy:          config.CurrentMissionPolicy,
		authorizationPolicy:           config.AuthorizationPolicy,
		permissionPolicy:              config.PermissionPolicy,
		permissionInteractionRequired: config.PermissionInteractionRequired,
		governanceStore:               config.GovernanceStore,
		personTokenStore:              config.PersonTokenStore,
		personTokenPolicy:             config.PersonTokenPolicy,
		missionIssuanceStore:          config.MissionIssuanceStore,
		completionReviewEnabled:       config.CompletionReviewEnabled,
		interactionRequired:           config.InteractionRequired,
		random:                        random,
		pendingLifetime:               pendingLifetime,
		authorizationStore:            config.AuthorizationStore,
		federationClient:              config.FederationClient,
		accessServerEndpoint:          config.AccessServerEndpoint,
		trustedUpstreamIssuer:         config.TrustedUpstreamIssuer,
		missions:                      make(map[string]storedMission),
		governanceReplays:             make(map[string]time.Time),
		pending:                       make(map[string]*pendingPersonAuthorization),
		permissionPending:             make(map[string]pendingPersonPermission),
		completionPending:             make(map[string]pendingCompletion),
		replayedProof:                 make(map[string]time.Time),
	}
	if server.governanceStore != nil {
		body, err := server.governanceStore.Load()
		if err != nil {
			return nil, fmt.Errorf("reference: load governance state: %w", err)
		}
		missions, permissions, interactions, pendingPermissions, pendingCompletions, replays, err := decodeGovernanceState(
			body,
			server.identifier,
		)
		if err != nil {
			return nil, err
		}
		server.missions = missions
		server.permissionHistory = permissions
		server.interactionHistory = interactions
		server.permissionPending = pendingPermissions
		server.completionPending = pendingCompletions
		server.governanceReplays = replays
	}
	if err := server.loadAuthorizationState(context.Background()); err != nil {
		return nil, fmt.Errorf("reference: load person authorization state: %w", err)
	}
	return server, nil
}

func (server *PersonServer) loadAuthorizationState(ctx context.Context) error {
	body, err := server.authorizationStore.Load(ctx)
	if err != nil {
		return err
	}
	if len(body) == 0 {
		server.pendingMu.Lock()
		defer server.pendingMu.Unlock()
		return server.persistAuthorizationStateLocked(ctx)
	}
	if err := server.restoreAuthorizationStateLocked(body); err != nil {
		return err
	}
	server.authorizationBody = append([]byte(nil), body...)
	return nil
}

func (server *PersonServer) restoreAuthorizationStateLocked(body []byte) error {
	rawRecords, err := decodeAuthorizationStateRecords(body, personAuthorizationStateSchema)
	if err != nil {
		return err
	}
	pending := make(map[string]*pendingPersonAuthorization, len(rawRecords))
	terminalIdentities := make(map[string]string)
	previous := ""
	for _, raw := range rawRecords {
		var record personAuthorizationStateRecord
		if err := decodeAuthorizationStateRecord(raw, &record); err != nil {
			return err
		}
		if record.Key == "" || record.Key <= previous || record.Interaction.ID != record.Key {
			return ErrAuthorizationStateIntegrity
		}
		previous = record.Key
		interaction, err := restorePendingInteraction(record.Interaction)
		if err != nil {
			return err
		}
		if err := server.validatePersonAuthorizationStateRecord(record); err != nil {
			return err
		}
		if err := retainUniqueTerminalIdentity(terminalIdentities, record.Key, record.TerminalAuthToken); err != nil {
			return err
		}
		contextValue := restorePersonAuthorizationContext(record.Context)
		var federated *pendingFederatedAuthorization
		if record.Federated != nil {
			federated = &pendingFederatedAuthorization{
				accessServer: record.Federated.AccessServer, location: record.Federated.Location,
				retryAfter: record.Federated.RetryAfter, notBefore: record.Federated.NotBefore.UTC(),
				status: record.Federated.Status, requirement: copyRequirement(record.Federated.Requirement),
			}
		}
		pending[record.Key] = &pendingPersonAuthorization{
			pendingInteraction: interaction, context: contextValue, decision: record.Decision,
			federated:               federated,
			terminalAuthToken:       record.TerminalAuthToken,
			terminalVerificationKey: copyJWK(record.TerminalVerificationKey),
			terminalExpiresAt:       record.TerminalExpiresAt,
			terminalStatus:          record.TerminalStatus, terminalCode: record.TerminalCode, terminalDetail: record.TerminalDetail,
		}
	}
	server.pending = pending
	return nil
}

func (server *PersonServer) validatePersonAuthorizationStateRecord(record personAuthorizationStateRecord) error {
	if err := validateAuthorizationTerminalState(
		record.Interaction,
		record.TerminalAuthToken,
		record.TerminalExpiresAt,
		record.TerminalStatus,
		record.TerminalCode,
		record.TerminalDetail,
	); err != nil {
		return err
	}
	if record.Federated == nil {
		if validateLocalAuthorizationInteraction(record.Interaction) != nil {
			return ErrAuthorizationStateIntegrity
		}
	} else if record.Federated.AccessServer == "" || record.Federated.Location == "" ||
		record.Federated.RetryAfter < 0 || record.Federated.NotBefore.IsZero() ||
		(record.Federated.Status != "pending" && record.Federated.Status != "interacting") ||
		record.Interaction.Code != "" || record.Interaction.NormalizedCode != "" {
		return ErrAuthorizationStateIntegrity
	}
	if !validPendingID(record.Key) ||
		(record.Federated == nil && (record.TerminalStatus != 0 || record.TerminalCode != "" || record.TerminalDetail != "")) {
		return ErrAuthorizationStateIntegrity
	}
	if record.Federated != nil {
		if aauth.ValidateServerIdentifier(record.Federated.AccessServer) != nil ||
			aauth.ValidatePollingEndpoint(record.Federated.Location) != nil {
			return ErrAuthorizationStateIntegrity
		}
		locationServer, err := endpointIdentifier(record.Federated.Location)
		federatedPendingID, pendingIDErr := pendingIDFromLocation(record.Federated.Location)
		if err != nil || pendingIDErr != nil || federatedPendingID != record.Key ||
			locationServer != record.Federated.AccessServer ||
			record.Interaction.CodeConsumed || record.Interaction.FailedCodeAttempts != 0 ||
			record.Interaction.PollingError != "" {
			return ErrAuthorizationStateIntegrity
		}
		if record.Federated.Requirement != nil {
			if _, err := aauth.FormatRequirementHeader(*record.Federated.Requirement); err != nil {
				return ErrAuthorizationStateIntegrity
			}
		}
		if (record.Interaction.State == pendingAuthorizationWaiting && record.Federated.Status != "pending") ||
			(record.Interaction.State == pendingAuthorizationInteracting && record.Federated.Status != "interacting") {
			return ErrAuthorizationStateIntegrity
		}
	}
	if record.Interaction.State == pendingAuthorizationApproved && record.Decision.Subject == "" {
		return ErrAuthorizationStateIntegrity
	}
	if err := server.validatePersonAuthorizationContext(record); err != nil {
		return ErrAuthorizationStateIntegrity
	}
	if record.Decision.Subject == "" {
		if len(record.Decision.Scope) != 0 {
			return ErrAuthorizationStateIntegrity
		}
	} else if record.Decision.Subject != record.Context.ResourceToken.Subject ||
		validateAuthorizationDecision(record.Decision, record.Context.Request.Scope) != nil {
		return ErrAuthorizationStateIntegrity
	}
	if record.Federated != nil && record.Decision.Subject == "" {
		return ErrAuthorizationStateIntegrity
	}
	if record.Federated == nil {
		if (record.Interaction.State == pendingAuthorizationApproved) != (record.Decision.Subject != "") {
			return ErrAuthorizationStateIntegrity
		}
	} else {
		if record.Interaction.State == pendingAuthorizationInvalidCode ||
			(record.Interaction.State == pendingAuthorizationApproved && record.TerminalAuthToken == "") {
			return ErrAuthorizationStateIntegrity
		}
	}
	if err := server.validatePersonTerminalToken(record); err != nil {
		return ErrAuthorizationStateIntegrity
	}
	return nil
}

func (server *PersonServer) validatePersonAuthorizationContext(record personAuthorizationStateRecord) error {
	value := record.Context
	if err := server.validatePersonAuthorizationRequestEvidence(value); err != nil {
		return ErrAuthorizationStateIntegrity
	}
	verifiedAt := value.RequestProof.VerifiedAt
	if value.ResourceTokenCompact == "" || value.AgentTokenCompact == "" {
		return ErrAuthorizationStateIntegrity
	}
	resource, err := verifyRetainedResourceTokenAt(
		value.ResourceTokenCompact,
		value.TokenVerificationKeys.Resource,
		verifiedAt,
	)
	if err != nil || !reflect.DeepEqual(resource, value.ResourceToken) {
		return ErrAuthorizationStateIntegrity
	}
	resource = value.ResourceToken
	latestInputIssuedAt := resource.IssuedAt
	if resource.PersonServer != server.identifier {
		return ErrAuthorizationStateIntegrity
	}
	if resource.ExpiresAt-resource.IssuedAt > int64(currentResourceTokenLifetime/time.Second) {
		return ErrAuthorizationStateIntegrity
	}
	personToken := value.PersonTokenRecord
	if validatePersonTokenRecord(personToken) != nil ||
		personToken.JTI != resource.PresentedJTI ||
		personToken.PersonServer != resource.PersonServer ||
		personToken.Resource != resource.Issuer ||
		personToken.Subject != resource.Subject ||
		personToken.MissionS256 != resource.MissionS256 ||
		personToken.Tenant != resource.Tenant ||
		resource.IssuedAt >= personToken.ExpiresAt.Unix() {
		return ErrAuthorizationStateIntegrity
	}
	if record.Federated == nil {
		if resource.Audience != server.identifier {
			return ErrAuthorizationStateIntegrity
		}
	} else if resource.Audience != record.Federated.AccessServer || resource.Audience == server.identifier {
		return ErrAuthorizationStateIntegrity
	}
	scopes, err := parseScopes(resource.Scope)
	if err != nil || !reflect.DeepEqual(scopes, value.Request.Scope) ||
		value.Request.PersonServer != resource.PersonServer || value.Request.Subject != resource.Subject ||
		value.Request.Resource != resource.Issuer || !reflect.DeepEqual(value.Request.Mission, resource.Mission) ||
		value.Request.MissionS256 != resource.MissionS256 || value.Request.Tenant != resource.Tenant ||
		value.Request.Account != resource.Account {
		return ErrAuthorizationStateIntegrity
	}
	agent, err := verifyRetainedAgentTokenAt(
		value.AgentTokenCompact,
		value.TokenVerificationKeys.Agent,
		verifiedAt,
	)
	if err != nil || agent.ParentAgent != "" ||
		(value.UpstreamTokenCompact == "" && agent.PersonServer != server.identifier) ||
		value.PollingAgent != agent.Subject {
		return ErrAuthorizationStateIntegrity
	}
	if agent.IssuedAt > latestInputIssuedAt {
		latestInputIssuedAt = agent.IssuedAt
	}
	pollingThumbprint, err := agent.Confirmation.JWK.Thumbprint()
	if err != nil || pollingThumbprint != value.PollingAgentThumbprint {
		return ErrAuthorizationStateIntegrity
	}
	targetAgent := agent.Subject
	targetKey := agent.Confirmation.JWK
	parentAgent := ""
	targetExpiresAt := agent.ExpiresAt
	if value.SubagentTokenCompact != "" {
		if value.TokenVerificationKeys.Subagent == nil {
			return ErrAuthorizationStateIntegrity
		}
		subagent, err := verifyRetainedAgentTokenAt(
			value.SubagentTokenCompact,
			*value.TokenVerificationKeys.Subagent,
			verifiedAt,
		)
		if err != nil ||
			subagent.ParentAgent != agent.Subject ||
			(value.UpstreamTokenCompact == "" && subagent.PersonServer != server.identifier) {
			return ErrAuthorizationStateIntegrity
		}
		targetAgent = subagent.Subject
		targetKey = subagent.Confirmation.JWK
		parentAgent = agent.Subject
		if subagent.ExpiresAt < targetExpiresAt {
			targetExpiresAt = subagent.ExpiresAt
		}
		if subagent.IssuedAt > latestInputIssuedAt {
			latestInputIssuedAt = subagent.IssuedAt
		}
	} else if value.TokenVerificationKeys.Subagent != nil {
		return ErrAuthorizationStateIntegrity
	}
	if value.UpstreamTokenCompact == "" {
		if value.Request.Upstream != nil || value.TokenVerificationKeys.Upstream != nil {
			return ErrAuthorizationStateIntegrity
		}
	} else {
		if value.TokenVerificationKeys.Upstream == nil {
			return ErrAuthorizationStateIntegrity
		}
		upstream, err := verifyRetainedAuthTokenAt(
			value.UpstreamTokenCompact,
			*value.TokenVerificationKeys.Upstream,
			verifiedAt,
		)
		if err != nil ||
			!reflect.DeepEqual(value.Request.Upstream, &upstream) || upstream.Audience != agent.Issuer ||
			upstream.PersonServer != server.identifier || !upstream.Confirmation.JWK.Equal(agent.Confirmation.JWK) ||
			upstream.MissionS256 != resource.MissionS256 {
			return ErrAuthorizationStateIntegrity
		}
		if upstream.ExpiresAt < targetExpiresAt {
			targetExpiresAt = upstream.ExpiresAt
		}
		if upstream.IssuedAt > latestInputIssuedAt {
			latestInputIssuedAt = upstream.IssuedAt
		}
	}
	targetThumbprint, err := value.TargetKey.Thumbprint()
	if err != nil || !value.TargetKey.Equal(targetKey) || targetThumbprint != resource.AgentJKT ||
		value.TargetAgent != targetAgent || value.ParentAgent != parentAgent ||
		value.Request.Agent != targetAgent || value.Request.ParentAgent != parentAgent ||
		value.TargetTokenExpiresAt != targetExpiresAt ||
		!record.Interaction.ExpiresAt.After(time.Unix(latestInputIssuedAt, 0)) ||
		record.Interaction.ExpiresAt.After(time.Unix(targetExpiresAt, 0)) ||
		record.Interaction.ExpiresAt.After(time.Unix(resource.ExpiresAt, 0)) {
		return ErrAuthorizationStateIntegrity
	}
	return nil
}

func (server *PersonServer) validatePersonAuthorizationRequestEvidence(
	value personAuthorizationContextRecord,
) error {
	if len(value.RequestBody) == 0 || len(value.RequestBody) > maxJSONBody || value.RequestProof == nil {
		return ErrAuthorizationStateIntegrity
	}
	var input personAuthorizationTokenInput
	if err := decodeJSONBytes(bytes.NewReader(value.RequestBody), &input); err != nil ||
		input.ResourceToken != value.ResourceTokenCompact ||
		input.SubagentToken != value.SubagentTokenCompact ||
		input.UpstreamToken != value.UpstreamTokenCompact ||
		input.Justification != value.Request.Justification {
		return ErrAuthorizationStateIntegrity
	}
	proof := value.RequestProof
	if proof.Method != http.MethodPost || proof.Target != "/token" || proof.Authority == "" ||
		proof.ContentDigest == "" || proof.ContentType == "" || proof.SignatureInput == "" || proof.Signature == "" ||
		proof.SignatureKey == "" || proof.SignatureKeyType != string(signaturekey.SchemeJWT) ||
		proof.CredentialType != aauth.AgentTokenType || proof.CredentialIssuer == "" ||
		proof.Authorization != "" || proof.VerifiedAt.IsZero() {
		return ErrAuthorizationStateIntegrity
	}
	identifier, err := endpointIdentifier("https://" + proof.Authority)
	if err != nil || identifier != server.identifier {
		return ErrAuthorizationStateIntegrity
	}
	request, err := http.NewRequest(
		proof.Method,
		server.identifier+proof.Target,
		bytes.NewReader(value.RequestBody),
	)
	if err != nil {
		return ErrAuthorizationStateIntegrity
	}
	request.Host = proof.Authority
	request.Header.Set("Content-Digest", proof.ContentDigest)
	request.Header.Set("Content-Type", proof.ContentType)
	request.Header.Set("Signature-Input", proof.SignatureInput)
	request.Header.Set("Signature", proof.Signature)
	request.Header.Set("Signature-Key", proof.SignatureKey)
	if proof.Authorization != "" {
		request.Header.Set("Authorization", proof.Authorization)
	}
	agent, err := decodeRetainedAgentToken(value.AgentTokenCompact)
	if err != nil || proof.CredentialIssuer != agent.Issuer {
		return ErrAuthorizationStateIntegrity
	}
	header, err := jose.PeekHeader(value.AgentTokenCompact)
	if err != nil {
		return ErrAuthorizationStateIntegrity
	}
	verified, err := aauth.VerifyRequest(
		context.Background(),
		request,
		signaturekey.StaticKeyResolver{
			agent.Issuer: {header.KeyID: value.TokenVerificationKeys.Agent},
		},
		aauth.ClockFunc(func() time.Time { return proof.VerifiedAt.UTC() }),
		aauth.VerifyRequestOptions{
			RequiredComponents:     []string{"content-type"},
			RequireExactComponents: true,
			AllowedCredentialTypes: []string{aauth.AgentTokenType},
		},
	)
	if err != nil || verified.RawCredential != value.AgentTokenCompact ||
		verified.Signer != proof.Signer || verified.Agent != proof.Agent ||
		verified.SignatureKeyType != signaturekey.Scheme(proof.SignatureKeyType) ||
		verified.CredentialType != proof.CredentialType ||
		!verified.PublicKey.Equal(proof.PublicKey) ||
		!verified.Created.Equal(proof.Created) || !verified.VerifiedAt.Equal(proof.VerifiedAt) ||
		verified.ReplayKey != proof.ReplayKey {
		return ErrAuthorizationStateIntegrity
	}
	if !reflect.DeepEqual(requestProof(request, verified), proof) {
		return ErrAuthorizationStateIntegrity
	}
	return nil
}

func (server *PersonServer) validatePersonTerminalToken(record personAuthorizationStateRecord) error {
	if record.TerminalAuthToken == "" {
		if record.TerminalVerificationKey != nil {
			return ErrAuthorizationStateIntegrity
		}
		return nil
	}
	if record.TerminalVerificationKey == nil {
		return ErrAuthorizationStateIntegrity
	}
	key := *record.TerminalVerificationKey
	expectedIssuer := server.identifier
	expectedDWK := aauth.PersonDiscoveryDocument
	if record.Federated != nil {
		expectedIssuer = record.Federated.AccessServer
		expectedDWK = aauth.AccessDiscoveryDocument
	}
	claims, err := verifyRetainedAuthToken(record.TerminalAuthToken, key)
	if err != nil {
		return ErrAuthorizationStateIntegrity
	}
	latestInputIssuedAt, err := latestRetainedAuthorizationInputIssuedAt(
		record.Context.ResourceTokenCompact,
		record.Context.AgentTokenCompact,
		record.Context.SubagentTokenCompact,
		record.Context.UpstreamTokenCompact,
	)
	if err != nil || claims.IssuedAt < latestInputIssuedAt {
		return ErrAuthorizationStateIntegrity
	}
	resource := record.Context.ResourceToken
	expectedExpiresAt := claims.IssuedAt + int64(time.Hour/time.Second)
	if record.Context.TargetTokenExpiresAt < expectedExpiresAt {
		expectedExpiresAt = record.Context.TargetTokenExpiresAt
	}
	if resource.ExpiresAt < expectedExpiresAt {
		expectedExpiresAt = resource.ExpiresAt
	}
	if record.Federated == nil && claims.JTI != record.Key {
		return ErrAuthorizationStateIntegrity
	}
	if record.Federated != nil {
		if err := validateFederatedTerminalBinding(record.Federated.Location, claims); err != nil {
			return ErrAuthorizationStateIntegrity
		}
	}
	grantedScopes, err := parseScopes(claims.Scope)
	if err != nil {
		return ErrAuthorizationStateIntegrity
	}
	scopeMatches := claims.Scope == strings.Join(record.Decision.Scope, " ")
	expiryMatches := claims.ExpiresAt == expectedExpiresAt
	if record.Federated != nil {
		scopeMatches = scopesContained(grantedScopes, record.Decision.Scope)
		expiryMatches = claims.ExpiresAt <= expectedExpiresAt
	}
	if claims.Issuer != expectedIssuer || claims.DWK != expectedDWK || claims.Audience != resource.Issuer ||
		!expiryMatches || record.TerminalExpiresAt != claims.ExpiresAt ||
		claims.Subject != resource.Subject || claims.Subject != record.Decision.Subject ||
		!scopeMatches ||
		!claims.Confirmation.JWK.Equal(record.Context.TargetKey) ||
		claims.PersonServer != resource.PersonServer || claims.Account != resource.Account ||
		claims.MissionS256 != resource.MissionS256 || claims.Tenant != resource.Tenant ||
		claims.Agent != "" || claims.Actor != nil || claims.Mission != nil {
		return ErrAuthorizationStateIntegrity
	}
	return nil
}

func copyJWK(value *jose.JWK) *jose.JWK {
	if value == nil {
		return nil
	}
	copied := *value
	return &copied
}

func (server *PersonServer) persistAuthorizationStateLocked(ctx context.Context) error {
	if server.authorizationErr != nil {
		return server.authorizationErr
	}
	if err := server.settleAuthorizationStateLocked(ctx); err != nil {
		return err
	}
	records := make([]personAuthorizationStateRecord, 0, len(server.pending))
	for key, pending := range server.pending {
		var federated *pendingFederatedRecord
		if pending.federated != nil {
			federated = &pendingFederatedRecord{
				AccessServer: pending.federated.accessServer, Location: pending.federated.location,
				RetryAfter: pending.federated.retryAfter, NotBefore: pending.federated.notBefore.UTC(),
				Status: pending.federated.status, Requirement: copyRequirement(pending.federated.requirement),
			}
		}
		records = append(records, personAuthorizationStateRecord{
			Key: key, Interaction: snapshotPendingInteraction(pending.pendingInteraction),
			Context: snapshotPersonAuthorizationContext(pending.context), Decision: pending.decision,
			Federated:               federated,
			TerminalAuthToken:       pending.terminalAuthToken,
			TerminalVerificationKey: copyJWK(pending.terminalVerificationKey),
			TerminalExpiresAt:       pending.terminalExpiresAt,
			TerminalStatus:          pending.terminalStatus, TerminalCode: pending.terminalCode, TerminalDetail: pending.terminalDetail,
		})
	}
	sort.Slice(records, func(i, j int) bool { return records[i].Key < records[j].Key })
	raw := make([]json.RawMessage, 0, len(records))
	terminalIdentities := make(map[string]string)
	for _, record := range records {
		if err := server.validatePersonAuthorizationStateRecord(record); err != nil {
			return server.reconcileAuthorizationStateLocked(ctx, nil, err)
		}
		if err := retainUniqueTerminalIdentity(terminalIdentities, record.Key, record.TerminalAuthToken); err != nil {
			return server.reconcileAuthorizationStateLocked(ctx, nil, err)
		}
		encoded, err := json.Marshal(record)
		if err != nil {
			return server.reconcileAuthorizationStateLocked(ctx, nil, err)
		}
		raw = append(raw, encoded)
	}
	body, err := marshalAuthorizationStateRecords(personAuthorizationStateSchema, raw)
	if err != nil {
		return server.reconcileAuthorizationStateLocked(ctx, nil, err)
	}
	if err := server.authorizationStore.Replace(ctx, body); err != nil {
		return server.reconcileAuthorizationStateLocked(ctx, body, err)
	}
	server.authorizationBody = append(server.authorizationBody[:0], body...)
	return nil
}

func retainUniqueTerminalIdentity(seen map[string]string, recordKey string, compact string) error {
	if compact == "" {
		return nil
	}
	claims, err := decodeRetainedAuthToken(compact)
	if err != nil {
		return ErrAuthorizationStateIntegrity
	}
	identity := claims.Issuer + "\x00" + claims.JTI
	if existing, ok := seen[identity]; ok && existing != recordKey {
		return ErrAuthorizationStateIntegrity
	}
	seen[identity] = recordKey
	return nil
}

func (server *PersonServer) reconcileAuthorizationStateLocked(ctx context.Context, candidate []byte, commitErr error) error {
	body, published, err := reconcileAuthorizationState(ctx, server.authorizationStore, server.authorizationBody, candidate)
	if err != nil || len(body) == 0 {
		server.pending = make(map[string]*pendingPersonAuthorization)
		server.authorizationErr = authorizationStateReconciliationFailure(commitErr, err)
		return server.authorizationErr
	}
	if err := server.restoreAuthorizationStateLocked(body); err != nil {
		server.pending = make(map[string]*pendingPersonAuthorization)
		server.authorizationErr = authorizationStateReconciliationFailure(commitErr, err)
		return server.authorizationErr
	}
	if published {
		server.authorizationRecovery = append(server.authorizationRecovery[:0], body...)
		return authorizationStatePublishedUncertain(commitErr)
	}
	server.authorizationBody = append(server.authorizationBody[:0], body...)
	return commitErr
}

func (server *PersonServer) settleAuthorizationStateLocked(ctx context.Context) error {
	if server.authorizationErr != nil {
		return server.authorizationErr
	}
	if len(server.authorizationRecovery) == 0 {
		return nil
	}
	candidate := append([]byte(nil), server.authorizationRecovery...)
	if err := server.authorizationStore.Replace(ctx, candidate); err != nil {
		body, published, reconcileErr := reconcileAuthorizationState(ctx, server.authorizationStore, nil, candidate)
		if reconcileErr == nil && published {
			reconcileErr = server.restoreAuthorizationStateLocked(body)
		}
		if reconcileErr != nil || !published {
			server.pending = make(map[string]*pendingPersonAuthorization)
			server.authorizationErr = authorizationStateReconciliationFailure(err, reconcileErr)
			return server.authorizationErr
		}
		return authorizationStatePublishedUncertain(err)
	}
	server.authorizationBody = append(server.authorizationBody[:0], candidate...)
	server.authorizationRecovery = nil
	return nil
}

func snapshotPersonAuthorizationContext(value personAuthorizationContext) personAuthorizationContextRecord {
	return personAuthorizationContextRecord{
		Request: copyAuthorizationRequest(value.request), ResourceTokenCompact: value.resourceTokenCompact,
		AgentTokenCompact: value.agentTokenCompact, SubagentTokenCompact: value.subagentTokenCompact,
		UpstreamTokenCompact:  value.upstreamTokenCompact,
		TokenVerificationKeys: copyRetainedAuthorizationTokenKeys(value.tokenVerificationKeys), TargetAgent: value.targetAgent,
		TargetKey: value.targetKey, ParentAgent: value.parentAgent, PollingAgent: value.pollingAgent,
		PollingAgentThumbprint: value.pollingAgentThumbprint, TargetTokenExpiresAt: value.targetTokenExpiresAt,
		ResourceToken: value.resourceToken, PersonTokenRecord: value.personTokenRecord,
		RequestBody: append([]byte(nil), value.requestBody...), RequestProof: copyRequestProof(value.requestProof),
	}
}

func restorePersonAuthorizationContext(value personAuthorizationContextRecord) personAuthorizationContext {
	return personAuthorizationContext{
		request: copyAuthorizationRequest(value.Request), resourceTokenCompact: value.ResourceTokenCompact,
		agentTokenCompact: value.AgentTokenCompact, subagentTokenCompact: value.SubagentTokenCompact,
		upstreamTokenCompact:  value.UpstreamTokenCompact,
		tokenVerificationKeys: copyRetainedAuthorizationTokenKeys(value.TokenVerificationKeys), targetAgent: value.TargetAgent,
		targetKey: value.TargetKey, parentAgent: value.ParentAgent, pollingAgent: value.PollingAgent,
		pollingAgentThumbprint: value.PollingAgentThumbprint, targetTokenExpiresAt: value.TargetTokenExpiresAt,
		resourceToken: value.ResourceToken, personTokenRecord: value.PersonTokenRecord,
		requestBody: append([]byte(nil), value.RequestBody...), requestProof: copyRequestProof(value.RequestProof),
	}
}

func (server *PersonServer) persistGovernanceLocked() error {
	if server.governanceStore == nil {
		return nil
	}
	body, err := encodeGovernanceState(
		server.identifier,
		server.missions,
		server.permissionHistory,
		server.interactionHistory,
		server.permissionPending,
		server.completionPending,
		server.governanceReplays,
	)
	if err != nil {
		return err
	}
	if err := server.governanceStore.Save(body); err != nil {
		return fmt.Errorf("reference: save governance state: %w", err)
	}
	return nil
}

func governanceSaveDefinitelyFailed(err error) bool {
	return !errors.Is(err, ErrGovernanceStateUncertain)
}

func (server *PersonServer) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /mission", server.handleMission)
	mux.HandleFunc("POST /person", server.handlePersonToken)
	mux.HandleFunc("POST /token", server.handleToken)
	if server.permissionPolicy != nil {
		mux.HandleFunc("POST /permission", server.handlePermission)
		mux.HandleFunc("GET /permission/pending/{id}", server.handlePendingPermission)
		mux.HandleFunc("GET /permission/interaction/{id}", server.handlePermissionInteraction)
	}
	mux.HandleFunc("POST /audit", server.handleAudit)
	mux.HandleFunc("GET /pending/{id}", server.handlePendingAuthorization)
	mux.HandleFunc("GET /interaction/{id}", server.handleAuthorizationInteraction)
	if server.completionReviewEnabled {
		mux.HandleFunc("POST /interaction", server.handleAgentInteraction)
		mux.HandleFunc("GET /interaction/pending/{id}", server.handlePendingAgentInteraction)
		mux.HandleFunc("POST /interaction/pending/{id}", server.handlePendingAgentInteraction)
	}
	mux.HandleFunc("GET /.well-known/aauth-person.json", server.handleMetadata)
	mux.HandleFunc("GET /jwks", server.handleJWKS)
	return mux
}

func (server *PersonServer) handleMission(response http.ResponseWriter, request *http.Request) {
	verified, err := aauth.VerifyRequest(request.Context(), request, server.keyResolver, server.clock, aauth.VerifyRequestOptions{
		RequiredComponents:     []string{"content-digest"},
		AllowedCredentialTypes: []string{aauth.AgentTokenType},
	})
	if err != nil {
		writeSignatureFailure(response, err)
		return
	}
	agentClaims, err := verified.AgentClaims()
	if err != nil {
		writeSignatureFailure(response, err)
		return
	}
	if !server.requireCurrentPersonServer(response, verified) {
		return
	}
	server.missionIssuanceMu.Lock()
	defer server.missionIssuanceMu.Unlock()
	if server.recoverCurrentMissionIssuance(
		response,
		request.Context(),
		verified.ReplayKey,
		verified.Agent,
	) {
		return
	}
	if server.governanceReplayExists(verified.ReplayKey) {
		writeSignatureFailure(response, errors.New("request proof was replayed"))
		return
	}
	var proposal aauth.MissionProposal
	if err := decodeJSON(response, request, &proposal); err != nil {
		writeProblem(response, http.StatusBadRequest, "invalid_request", err)
		return
	}
	if err := proposal.Validate(); err != nil {
		writeProblem(response, http.StatusBadRequest, "invalid_request", err)
		return
	}
	decision, err := server.currentMissionPolicy(request.Context(), aauth.MissionEvaluation{
		Agent:          verified.Agent,
		Proposal:       copyMissionProposal(proposal),
		Confirmation:   verified.PublicKey,
		AgentExpiresAt: time.Unix(agentClaims.ExpiresAt, 0).UTC(),
		PersonServer:   server.identifier,
	})
	if err != nil {
		writeHostPolicyRefusal(response, "mission_denied", "mission policy denied the request")
		return
	}
	if strings.TrimSpace(decision.Description) == "" {
		writeProblem(response, http.StatusInternalServerError, "server_error", errors.New("mission policy returned an empty description"))
		return
	}
	server.completeCurrentMission(response, request.Context(), verified, proposal, decision)
}

func copyMissionProposal(proposal aauth.MissionProposal) aauth.MissionProposal {
	return aauth.MissionProposal{
		Description: proposal.Description,
		Tools:       append([]aauth.Tool(nil), proposal.Tools...),
		Resources:   append([]string(nil), proposal.Resources...),
	}
}

func (server *PersonServer) completeCurrentMission(
	response http.ResponseWriter,
	ctx context.Context,
	verified aauth.VerifiedRequest,
	proposal aauth.MissionProposal,
	decision aauth.MissionDecision,
) {
	agentClaims, err := verified.AgentClaims()
	if err != nil {
		writeSignatureFailure(response, err)
		return
	}
	approvedResources, err := validateApprovedResources(proposal.Resources, decision.ApprovedResources)
	if err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", err)
		return
	}
	now := server.clock.Now().UTC()
	var expiresAt *time.Time
	if decision.ExpiresAt != nil {
		value := decision.ExpiresAt.UTC()
		if !value.After(now) {
			writeProblem(response, http.StatusInternalServerError, "server_error", errors.New("mission policy returned an expired mission"))
			return
		}
		expiresAt = &value
	}
	blob, err := json.Marshal(missionBlob{
		Approver:          server.identifier,
		Agent:             verified.Agent,
		ApprovedAt:        now.Format(time.RFC3339Nano),
		ExpiresAt:         formatOptionalTime(expiresAt),
		Description:       decision.Description,
		ApprovedTools:     append([]aauth.Tool(nil), decision.Tools...),
		ApprovedResources: append([]string(nil), approvedResources...),
	})
	if err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", err)
		return
	}
	reference := aauth.MissionReference{Approver: server.identifier, S256: aauth.S256(blob)}
	personTokens := make(map[string]string, len(approvedResources))
	preparedPersonTokens := make([]MissionIssuancePersonToken, 0, len(approvedResources))
	for _, resource := range approvedResources {
		prepared, _, err := server.preparePersonToken(
			ctx,
			verified.Agent,
			"",
			verified.PublicKey,
			agentClaims.ExpiresAt,
			resource,
			reference.S256,
			expiresAt,
			nil,
		)
		if err != nil {
			writePersonTokenIssuanceFailure(response, err)
			return
		}
		preparedPersonTokens = append(preparedPersonTokens, prepared)
		personTokens[resource] = prepared.Compact
	}
	approval := currentMissionApproval{
		S256:         reference.S256,
		Mission:      base64.RawURLEncoding.EncodeToString(blob),
		Capabilities: append([]string(nil), decision.Capabilities...),
		PersonTokens: personTokens,
	}
	responseBody, err := json.Marshal(approval)
	if err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", err)
		return
	}
	record := MissionIssuanceRecord{
		ReplayKey:         verified.ReplayKey,
		ReplayExpiresAt:   verified.Created.Add(signaturekey.DefaultSignatureWindow).UTC(),
		State:             MissionIssuancePrepared,
		Agent:             verified.Agent,
		Reference:         reference,
		MissionBytes:      append([]byte(nil), blob...),
		Description:       decision.Description,
		ApprovedTools:     append([]aauth.Tool(nil), decision.Tools...),
		ApprovedResources: append([]string(nil), approvedResources...),
		ExpiresAt:         copyTimePointer(expiresAt),
		Capabilities:      append([]string(nil), decision.Capabilities...),
		ResponseBody:      responseBody,
		PersonTokens:      preparedPersonTokens,
	}
	if err := server.missionIssuanceStore.Commit(ctx, record); err != nil {
		server.writeMissionRecoveryPending(response)
		return
	}
	server.advanceCurrentMissionIssuance(response, ctx, record)
}

func (server *PersonServer) recoverCurrentMissionIssuance(
	response http.ResponseWriter,
	ctx context.Context,
	replayKey string,
	agent string,
) bool {
	record, err := server.missionIssuanceStore.Load(ctx, replayKey)
	if errors.Is(err, ErrMissionIssuanceNotFound) {
		return false
	}
	if err != nil {
		server.writeMissionRecoveryPending(response)
		return true
	}
	if err := validateMissionIssuanceRecord(record); err != nil || record.Agent != agent {
		server.writeMissionRecoveryPending(response)
		return true
	}
	server.advanceCurrentMissionIssuance(response, ctx, record)
	return true
}

func (server *PersonServer) advanceCurrentMissionIssuance(
	response http.ResponseWriter,
	ctx context.Context,
	record MissionIssuanceRecord,
) {
	for _, prepared := range record.PersonTokens {
		if err := server.personTokenStore.Commit(ctx, prepared.Record); err != nil {
			server.writeMissionRecoveryPending(response)
			return
		}
	}
	if err := server.ensureCurrentMissionGovernance(record); err != nil {
		server.writeMissionRecoveryPending(response)
		return
	}
	completed := copyMissionIssuanceRecord(record)
	completed.State = MissionIssuanceComplete
	if err := server.missionIssuanceStore.Commit(ctx, completed); err != nil {
		server.writeMissionRecoveryPending(response)
		return
	}
	response.Header().Set("Content-Type", "application/json")
	response.Header().Set("Cache-Control", "no-store")
	response.WriteHeader(http.StatusOK)
	_, _ = response.Write(completed.ResponseBody)
}

func (server *PersonServer) ensureCurrentMissionGovernance(record MissionIssuanceRecord) error {
	mission := storedMission{
		reference:         record.Reference,
		agent:             record.Agent,
		bytes:             append([]byte(nil), record.MissionBytes...),
		description:       record.Description,
		approvedTools:     append([]aauth.Tool(nil), record.ApprovedTools...),
		approvedResources: append([]string(nil), record.ApprovedResources...),
		expiresAt:         copyTimePointer(record.ExpiresAt),
		status:            aauth.MissionActive,
		log:               make([]aauth.MissionLogEntry, 0),
	}
	server.mu.Lock()
	defer server.mu.Unlock()
	previousMission, hadMission := server.missions[record.Reference.S256]
	if hadMission && !reflect.DeepEqual(previousMission, mission) {
		return errors.New("reference: mission issuance conflicts with retained mission")
	}
	previousReplayExpiry, hadReplay := server.governanceReplays[record.ReplayKey]
	if hadReplay && !previousReplayExpiry.Equal(record.ReplayExpiresAt) {
		return errors.New("reference: mission issuance conflicts with retained replay")
	}
	server.missions[record.Reference.S256] = mission
	server.governanceReplays[record.ReplayKey] = record.ReplayExpiresAt
	if err := server.persistGovernanceLocked(); err != nil {
		if governanceSaveDefinitelyFailed(err) {
			if hadMission {
				server.missions[record.Reference.S256] = previousMission
			} else {
				delete(server.missions, record.Reference.S256)
			}
			if hadReplay {
				server.governanceReplays[record.ReplayKey] = previousReplayExpiry
			} else {
				delete(server.governanceReplays, record.ReplayKey)
			}
		}
		return err
	}
	return nil
}

func (server *PersonServer) writeMissionRecoveryPending(response http.ResponseWriter) {
	response.Header().Set("Retry-After", "1")
	detail := errors.New("mission issuance is retained but not durably complete; retry the exact signed request")
	writeProblem(
		response,
		http.StatusServiceUnavailable,
		"server_error",
		detail,
	)
}

func validateApprovedResources(proposed []string, approved []string) ([]string, error) {
	proposedSet := make(map[string]bool, len(proposed))
	for _, resource := range proposed {
		if err := aauth.ValidateServerIdentifier(resource); err != nil {
			return nil, fmt.Errorf("mission resource: %w", err)
		}
		if proposedSet[resource] {
			return nil, errors.New("mission resources contain a duplicate")
		}
		proposedSet[resource] = true
	}
	seen := make(map[string]bool, len(approved))
	result := make([]string, 0, len(approved))
	for _, resource := range approved {
		if !proposedSet[resource] {
			return nil, errors.New("mission policy approved a resource the proposal did not name")
		}
		if seen[resource] {
			return nil, errors.New("mission policy returned a duplicate approved resource")
		}
		seen[resource] = true
		result = append(result, resource)
	}
	return result, nil
}

func (server *PersonServer) handlePersonToken(response http.ResponseWriter, request *http.Request) {
	verified, err := aauth.VerifyRequest(request.Context(), request, server.keyResolver, server.clock, aauth.VerifyRequestOptions{
		RequiredComponents:     []string{"content-digest"},
		AllowedCredentialTypes: []string{aauth.AgentTokenType},
	})
	if err != nil {
		writeSignatureFailure(response, err)
		return
	}
	verificationClock := aauth.ClockFunc(func() time.Time { return verified.VerifiedAt })
	agentClaims, err := verified.AgentClaims()
	if err != nil {
		writeSignatureFailure(response, err)
		return
	}
	if agentClaims.ParentAgent != "" {
		writeProblem(response, http.StatusForbidden, "invalid_agent", errors.New("sub-agent cannot request a person token directly"))
		return
	}
	var input struct {
		Resource      string `json:"resource"`
		MissionS256   string `json:"mission_s256,omitempty"`
		SubagentToken string `json:"subagent_token,omitempty"`
		UpstreamToken string `json:"upstream_token,omitempty"`
	}
	if err := decodeJSON(response, request, &input); err != nil {
		writeProblem(response, http.StatusBadRequest, "invalid_request", err)
		return
	}
	if err := aauth.ValidateServerIdentifier(input.Resource); err != nil {
		writeProblem(response, http.StatusBadRequest, "invalid_request", err)
		return
	}
	targetAgent := verified.Agent
	targetKey := verified.PublicKey
	parentAgent := ""
	targetExpiresAt := agentClaims.ExpiresAt
	if input.SubagentToken != "" {
		subagentEvidence, err := aauth.VerifyAgentToken(request.Context(), input.SubagentToken, server.keyResolver, verificationClock)
		if err != nil {
			writeTokenVerificationFailure(response, http.StatusBadRequest, "invalid_subagent_token", err)
			return
		}
		subagent, err := subagentEvidence.Claims()
		if err != nil {
			writeTokenVerificationFailure(response, http.StatusBadRequest, "invalid_subagent_token", err)
			return
		}
		if subagent.ParentAgent == "" || subagent.ParentAgent != verified.Agent {
			writeProblem(response, http.StatusForbidden, "invalid_subagent_token", errors.New("sub-agent token does not name the signing parent"))
			return
		}
		if input.UpstreamToken == "" && subagent.PersonServer != server.identifier {
			writeProblem(response, http.StatusForbidden, "invalid_subagent_token", errors.New("sub-agent token names a different person server"))
			return
		}
		targetAgent = subagent.Subject
		targetKey = subagent.Confirmation.JWK
		parentAgent = verified.Agent
		if subagent.ExpiresAt < targetExpiresAt {
			targetExpiresAt = subagent.ExpiresAt
		}
	}
	var upstream *aauth.AuthTokenClaims
	if input.UpstreamToken != "" {
		if server.trustedUpstreamIssuer == nil {
			writeProblem(response, http.StatusForbidden, "invalid_upstream_token", errors.New("call chaining is not configured"))
			return
		}
		upstreamEvidence, err := aauth.VerifyAuthToken(request.Context(), input.UpstreamToken, server.keyResolver, verificationClock)
		if err != nil {
			writeTokenVerificationFailure(response, http.StatusBadRequest, "invalid_upstream_token", err)
			return
		}
		claims, err := upstreamEvidence.Claims()
		if err != nil {
			writeTokenVerificationFailure(response, http.StatusBadRequest, "invalid_upstream_token", err)
			return
		}
		if err := server.trustedUpstreamIssuer(request.Context(), claims.Issuer); err != nil {
			writeHostPolicyRefusal(response, "invalid_upstream_token", "upstream token issuer is not trusted")
			return
		}
		if claims.Audience != agentClaims.Issuer || claims.PersonServer != server.identifier {
			writeProblem(response, http.StatusForbidden, "invalid_upstream_token", errors.New("upstream auth token does not route the intermediary to this person server"))
			return
		}
		if !claims.Confirmation.JWK.Equal(verified.PublicKey) {
			writeProblem(response, http.StatusForbidden, "invalid_upstream_token", errors.New("upstream auth-token confirmation key does not match intermediary request key"))
			return
		}
		if input.MissionS256 != claims.MissionS256 {
			writeProblem(response, http.StatusBadRequest, "invalid_request", errors.New("mission_s256 does not match upstream authorization"))
			return
		}
		upstream = &claims
		if claims.ExpiresAt < targetExpiresAt {
			targetExpiresAt = claims.ExpiresAt
		}
	}
	if upstream == nil && !server.requireCurrentPersonServer(response, verified) {
		return
	}
	var missionExpiry *time.Time
	if input.MissionS256 != "" {
		reference := aauth.MissionReference{Approver: server.identifier, S256: input.MissionS256}
		mission, err := server.activeMissionForAgent(verified.Agent, reference)
		if err != nil {
			server.writeMissionError(response, err)
			return
		}
		missionExpiry = copyTimePointer(mission.ExpiresAt)
	}
	if server.seenReplay(verified.ReplayKey, verified.Created.Add(signaturekey.DefaultSignatureWindow), verified.VerifiedAt) {
		writeSignatureFailure(response, errors.New("request proof was replayed"))
		return
	}
	compact, claims, err := server.issuePersonTokenForContext(
		request.Context(),
		targetAgent,
		parentAgent,
		targetKey,
		targetExpiresAt,
		input.Resource,
		input.MissionS256,
		missionExpiry,
		upstream,
	)
	if err != nil {
		writePersonTokenIssuanceFailure(response, err)
		return
	}
	writeJSON(response, http.StatusOK, map[string]any{
		"person_token": compact,
		"expires_in":   claims.ExpiresAt - server.clock.Now().Unix(),
	})
}

func (server *PersonServer) requireCurrentPersonServer(
	response http.ResponseWriter,
	verified aauth.VerifiedRequest,
) bool {
	claims, err := verified.AgentClaims()
	if err == nil && claims.PersonServer == server.identifier {
		return true
	}
	writeProblem(
		response,
		http.StatusBadRequest,
		"invalid_agent_token",
		errors.New("agent token ps does not match person server"),
	)
	return false
}

func (server *PersonServer) issuePersonToken(
	ctx context.Context,
	agent string,
	confirmation jose.JWK,
	agentExpiresAt int64,
	resource string,
	missionS256 string,
	missionExpiresAt *time.Time,
) (string, aauth.PersonTokenClaims, error) {
	return server.issuePersonTokenForContext(ctx, agent, "", confirmation, agentExpiresAt, resource, missionS256, missionExpiresAt, nil)
}

func (server *PersonServer) issuePersonTokenForContext(
	ctx context.Context,
	agent string,
	parentAgent string,
	confirmation jose.JWK,
	agentExpiresAt int64,
	resource string,
	missionS256 string,
	missionExpiresAt *time.Time,
	upstream *aauth.AuthTokenClaims,
) (string, aauth.PersonTokenClaims, error) {
	prepared, claims, err := server.preparePersonToken(
		ctx,
		agent,
		parentAgent,
		confirmation,
		agentExpiresAt,
		resource,
		missionS256,
		missionExpiresAt,
		upstream,
	)
	if err != nil {
		return "", aauth.PersonTokenClaims{}, err
	}
	if err := server.personTokenStore.Commit(ctx, prepared.Record); err != nil {
		return "", aauth.PersonTokenClaims{}, &personTokenCustodyError{cause: err}
	}
	return prepared.Compact, claims, nil
}

func (server *PersonServer) preparePersonToken(
	ctx context.Context,
	agent string,
	parentAgent string,
	confirmation jose.JWK,
	agentExpiresAt int64,
	resource string,
	missionS256 string,
	missionExpiresAt *time.Time,
	upstream *aauth.AuthTokenClaims,
) (MissionIssuancePersonToken, aauth.PersonTokenClaims, error) {
	var prepared MissionIssuancePersonToken
	var claims aauth.PersonTokenClaims
	var policyUpstream *aauth.AuthTokenClaims
	if upstream != nil {
		policyUpstream = copyAuthorizationRequest(aauth.AuthorizationRequest{Upstream: upstream}).Upstream
	}
	decision, err := server.personTokenPolicy(ctx, aauth.PersonTokenRequest{
		Agent:          agent,
		ParentAgent:    parentAgent,
		Resource:       resource,
		MissionS256:    missionS256,
		Confirmation:   confirmation,
		AgentExpiresAt: time.Unix(agentExpiresAt, 0).UTC(),
		Upstream:       policyUpstream,
	})
	if err != nil {
		return prepared, claims, &personTokenPolicyDenialError{cause: err}
	}
	if decision.Subject == "" {
		return prepared, claims, errors.New("person-token policy returned an empty subject")
	}
	if decision.Lifetime <= 0 || decision.Lifetime > time.Hour {
		return prepared, claims, errors.New("person-token policy lifetime must be between zero and one hour")
	}
	now := server.clock.Now()
	expiresAt := now.Add(decision.Lifetime)
	if agentExpiry := time.Unix(agentExpiresAt, 0); agentExpiry.Before(expiresAt) {
		expiresAt = agentExpiry
	}
	if missionExpiresAt != nil && missionExpiresAt.Before(expiresAt) {
		expiresAt = *missionExpiresAt
	}
	if !expiresAt.After(now) {
		return prepared, claims, errors.New("person-token inputs expire before issuance")
	}
	claims = aauth.PersonTokenClaims{
		Issuer:       server.identifier,
		DWK:          aauth.PersonDiscoveryDocument,
		Audience:     resource,
		Subject:      decision.Subject,
		Confirmation: aauth.Confirmation{JWK: confirmation},
		JTI:          server.newID(),
		IssuedAt:     now.Unix(),
		ExpiresAt:    expiresAt.Unix(),
		MissionS256:  missionS256,
		Tenant:       decision.Tenant,
	}
	compact, err := aauth.MintPersonToken(server.signingKey, claims)
	if err != nil {
		return prepared, aauth.PersonTokenClaims{}, err
	}
	canonicalExpiresAt := time.Unix(claims.ExpiresAt, 0).UTC()
	prepared = MissionIssuancePersonToken{
		Resource: resource,
		Compact:  compact,
		Record: PersonTokenRecord{
			JTI:          claims.JTI,
			PersonServer: claims.Issuer,
			TokenSHA256:  aauth.S256([]byte(compact)),
			Resource:     claims.Audience,
			Subject:      claims.Subject,
			MissionS256:  claims.MissionS256,
			Tenant:       claims.Tenant,
			ExpiresAt:    canonicalExpiresAt,
			RetainUntil:  canonicalExpiresAt.Add(currentResourceTokenLifetime),
		},
	}
	return prepared, claims, nil
}

func writePersonTokenIssuanceFailure(response http.ResponseWriter, err error) {
	var policyDenial *personTokenPolicyDenialError
	if errors.As(err, &policyDenial) {
		writeHostPolicyRefusal(response, "person_token_denied", "person-token policy denied the request")
		return
	}
	var custodyFailure *personTokenCustodyError
	if errors.As(err, &custodyFailure) {
		writeProblem(response, http.StatusServiceUnavailable, "person_token_custody_unavailable", err)
		return
	}
	writeProblem(response, http.StatusInternalServerError, "server_error", err)
}

// MissionSnapshot returns a defensive copy for host policy, inspection, and
// durable-store adapters. It is not a protocol endpoint.
func (server *PersonServer) MissionSnapshot(
	reference aauth.MissionReference,
) (aauth.MissionSnapshot, error) {
	if err := reference.Validate(); err != nil {
		return aauth.MissionSnapshot{}, err
	}
	if reference.Approver != server.identifier {
		return aauth.MissionSnapshot{}, ErrMissionUnknown
	}
	server.mu.RLock()
	defer server.mu.RUnlock()
	mission, exists := server.missions[reference.S256]
	if !exists || mission.reference != reference {
		return aauth.MissionSnapshot{}, ErrMissionUnknown
	}
	return copyMissionSnapshot(mission), nil
}

// PermissionHistory returns defensive, ordered custody for every permission
// request handled by this person server, including missionless requests.
func (server *PersonServer) PermissionHistory() []aauth.PermissionRecord {
	server.mu.RLock()
	defer server.mu.RUnlock()
	return copyPermissionHistory(server.permissionHistory)
}

// TerminateMission performs the host-owned state transition defined by the
// draft's mission-management boundary. Agent-requested completion remains an
// interaction-endpoint concern.
func (server *PersonServer) TerminateMission(reference aauth.MissionReference) error {
	if err := reference.Validate(); err != nil {
		return err
	}
	if reference.Approver != server.identifier {
		return ErrMissionUnknown
	}
	server.mu.Lock()
	defer server.mu.Unlock()
	mission, exists := server.missions[reference.S256]
	if !exists || mission.reference != reference {
		return ErrMissionUnknown
	}
	if mission.status == aauth.MissionTerminated {
		return ErrMissionTerminated
	}
	previous := mission
	mission.log = append(mission.log, aauth.MissionLogEntry{
		Sequence:   uint64(len(mission.log) + 1),
		Kind:       aauth.MissionLogTermination,
		RecordedAt: server.clock.Now().UTC(),
		Agent:      mission.agent,
	})
	mission.status = aauth.MissionTerminated
	server.missions[reference.S256] = mission
	if err := server.persistGovernanceLocked(); err != nil {
		if governanceSaveDefinitelyFailed(err) {
			server.missions[reference.S256] = previous
		}
		return err
	}
	return nil
}

func (server *PersonServer) handlePermission(
	response http.ResponseWriter,
	request *http.Request,
) {
	body, err := readBoundedRequestBody(request)
	if err != nil {
		writeProblem(response, http.StatusBadRequest, "invalid_request", err)
		return
	}
	verified, err := aauth.VerifyRequest(
		request.Context(),
		request,
		server.keyResolver,
		server.clock,
		aauth.VerifyRequestOptions{
			RequiredComponents:     []string{"content-digest"},
			AllowedCredentialTypes: []string{aauth.AgentTokenType},
		},
	)
	if err != nil {
		writeSignatureFailure(response, err)
		return
	}
	agentClaims, err := verified.AgentClaims()
	if err != nil {
		writeSignatureFailure(response, err)
		return
	}
	if server.governanceReplayExists(verified.ReplayKey) {
		writeSignatureFailure(response, errors.New("request proof was replayed"))
		return
	}
	var input aauth.PermissionRequest
	if err := decodeJSONBytes(bytes.NewReader(body), &input); err != nil {
		writeProblem(response, http.StatusBadRequest, "invalid_request", err)
		return
	}
	if err := input.Validate(); err != nil {
		writeProblem(response, http.StatusBadRequest, "invalid_request", err)
		return
	}
	proof := requestProof(request, verified)

	evaluation := aauth.PermissionEvaluation{
		Agent:   verified.Agent,
		Request: input,
	}
	if input.Mission != nil {
		mission, err := server.activeMissionForAgent(verified.Agent, *input.Mission)
		if err != nil {
			server.writeMissionError(response, err)
			return
		}
		evaluation.Mission = &mission
	}
	if server.permissionInteractionRequired != nil {
		required, err := server.permissionInteractionRequired(
			request.Context(),
			copyPermissionEvaluation(evaluation),
		)
		if err != nil {
			writeProblem(response, http.StatusInternalServerError, "server_error", err)
			return
		}
		if required {
			thumbprint, err := verified.PublicKey.Thumbprint()
			if err != nil {
				writeProblem(response, http.StatusInternalServerError, "server_error", nil)
				return
			}
			if err := server.beginPendingPermission(
				response,
				verified.Agent,
				thumbprint,
				agentClaims.ExpiresAt,
				body,
				proof,
				verified.Created.Add(signaturekey.DefaultSignatureWindow),
			); err != nil {
				server.writeMissionError(response, err)
			}
			return
		}
	}
	decision, err := server.permissionPolicy(
		request.Context(),
		copyPermissionEvaluation(evaluation),
	)
	if err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", err)
		return
	}
	server.completePermission(
		response,
		verified.Agent,
		input,
		body,
		proof,
		verified.Created.Add(signaturekey.DefaultSignatureWindow),
		decision,
	)
}

func (server *PersonServer) completePermission(
	response http.ResponseWriter,
	agent string,
	input aauth.PermissionRequest,
	requestBody []byte,
	proof *aauth.RequestProof,
	replayExpiresAt time.Time,
	decision aauth.PermissionDecision,
) {
	result := aauth.PermissionResponse{
		Permission: decision.Permission,
		Reason:     decision.Reason,
	}
	if err := result.Validate(); err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", err)
		return
	}
	resultBody, err := json.Marshal(result)
	if err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", err)
		return
	}
	if err := server.commitImmediatePermission(
		agent,
		input,
		requestBody,
		proof,
		replayExpiresAt,
		decision,
		resultBody,
	); err != nil {
		server.writeMissionError(response, err)
		return
	}
	response.Header().Set("Content-Type", "application/json")
	response.Header().Set("Cache-Control", "no-store")
	response.WriteHeader(http.StatusOK)
	_, _ = response.Write(resultBody)
}

var errGovernanceReplay = errors.New("reference: request proof was replayed")

func (server *PersonServer) commitImmediatePermission(
	agent string,
	input aauth.PermissionRequest,
	requestBody []byte,
	proof *aauth.RequestProof,
	replayExpiresAt time.Time,
	decision aauth.PermissionDecision,
	responseBody []byte,
) error {
	server.mu.Lock()
	defer server.mu.Unlock()
	if _, replayed := server.governanceReplays[proof.ReplayKey]; replayed {
		return errGovernanceReplay
	}
	previousReplays := copyGovernanceReplays(server.governanceReplays)
	previousHistory := copyPermissionHistory(server.permissionHistory)
	var previousMission storedMission
	missionChanged := false
	decidedAt := server.clock.Now().UTC()

	server.permissionHistory = append(server.permissionHistory, aauth.PermissionRecord{
		Sequence:   uint64(len(server.permissionHistory) + 1),
		RecordedAt: proof.VerifiedAt,
		Agent:      agent,
		Request:    append([]byte(nil), requestBody...),
		Proof:      copyRequestProof(proof),
		DecidedAt:  decidedAt,
		DecidedBy:  decision.DecidedBy,
		Response:   append([]byte(nil), responseBody...),
	})
	if input.Mission != nil {
		mission, err := server.activeMissionForAgentLocked(agent, *input.Mission)
		if err != nil {
			server.permissionHistory = previousHistory
			return err
		}
		previousMission = mission
		mission.log = append(mission.log,
			aauth.MissionLogEntry{
				Sequence:       uint64(len(mission.log) + 1),
				Kind:           aauth.MissionLogPermissionRequest,
				RecordedAt:     proof.VerifiedAt,
				Agent:          agent,
				RequestProofID: proof.ReplayKey,
				Request:        append([]byte(nil), requestBody...),
				Proof:          copyRequestProof(proof),
			},
			aauth.MissionLogEntry{
				Sequence:       uint64(len(mission.log) + 2),
				Kind:           aauth.MissionLogPermissionDecision,
				RecordedAt:     decidedAt,
				Agent:          agent,
				DecidedBy:      decision.DecidedBy,
				RequestProofID: proof.ReplayKey,
				Response:       append([]byte(nil), responseBody...),
			},
		)
		server.missions[input.Mission.S256] = mission
		missionChanged = true
	}
	server.addGovernanceReplayLocked(proof.ReplayKey, replayExpiresAt)
	if err := server.persistGovernanceLocked(); err != nil {
		if governanceSaveDefinitelyFailed(err) {
			server.governanceReplays = previousReplays
			server.permissionHistory = previousHistory
			if missionChanged {
				server.missions[input.Mission.S256] = previousMission
			}
		}
		return err
	}
	return nil
}

func (server *PersonServer) commitPendingPermissionRequest(
	pending pendingPersonPermission,
	requestBody []byte,
	proof *aauth.RequestProof,
	replayExpiresAt time.Time,
) error {
	var input aauth.PermissionRequest
	if err := decodeJSONBytes(bytes.NewReader(requestBody), &input); err != nil {
		return err
	}
	server.mu.Lock()
	defer server.mu.Unlock()
	if _, replayed := server.governanceReplays[proof.ReplayKey]; replayed {
		return errGovernanceReplay
	}
	if _, exists := server.permissionPending[pending.id]; exists {
		return errors.New("reference: pending identifier source returned a duplicate value")
	}
	previousReplays := copyGovernanceReplays(server.governanceReplays)
	previousHistory := copyPermissionHistory(server.permissionHistory)
	var previousMission storedMission
	missionChanged := false

	server.permissionHistory = append(server.permissionHistory, aauth.PermissionRecord{
		Sequence:   uint64(len(server.permissionHistory) + 1),
		RecordedAt: proof.VerifiedAt,
		Agent:      pending.agent,
		Request:    append([]byte(nil), requestBody...),
		Proof:      copyRequestProof(proof),
		PendingID:  pending.id,
	})
	if input.Mission != nil {
		mission, err := server.activeMissionForAgentLocked(pending.agent, *input.Mission)
		if err != nil {
			server.permissionHistory = previousHistory
			return err
		}
		previousMission = mission
		mission.log = append(mission.log, aauth.MissionLogEntry{
			Sequence:       uint64(len(mission.log) + 1),
			Kind:           aauth.MissionLogPermissionRequest,
			RecordedAt:     proof.VerifiedAt,
			Agent:          pending.agent,
			RequestProofID: proof.ReplayKey,
			Request:        append([]byte(nil), requestBody...),
			Proof:          copyRequestProof(proof),
		})
		server.missions[input.Mission.S256] = mission
		missionChanged = true
	}
	server.permissionPending[pending.id] = pending
	server.addGovernanceReplayLocked(proof.ReplayKey, replayExpiresAt)
	if err := server.persistGovernanceLocked(); err != nil {
		if governanceSaveDefinitelyFailed(err) {
			server.governanceReplays = previousReplays
			server.permissionHistory = previousHistory
			delete(server.permissionPending, pending.id)
			if missionChanged {
				server.missions[input.Mission.S256] = previousMission
			}
		}
		return err
	}
	return nil
}

func (server *PersonServer) beginPendingPermission(
	response http.ResponseWriter,
	agent string,
	agentThumbprint string,
	agentTokenExpiresAt int64,
	requestBody []byte,
	proof *aauth.RequestProof,
	replayExpiresAt time.Time,
) error {
	now := server.clock.Now()
	expiresAt := now.Add(server.pendingLifetime)
	tokenExpiry := time.Unix(agentTokenExpiresAt, 0)
	if tokenExpiry.Before(expiresAt) {
		expiresAt = tokenExpiry
	}
	if !expiresAt.After(now) {
		return errors.New("reference: agent credential expires before permission interaction can begin")
	}
	server.randomMu.Lock()
	interaction, err := newPendingInteraction(server.random, expiresAt)
	server.randomMu.Unlock()
	if err != nil {
		return err
	}
	pending := pendingPersonPermission{
		pendingInteraction:     interaction,
		agent:                  agent,
		pollingAgentThumbprint: agentThumbprint,
		requestReplayKey:       proof.ReplayKey,
		requestBody:            append([]byte(nil), requestBody...),
	}
	if err := server.commitPendingPermissionRequest(
		pending,
		requestBody,
		proof,
		replayExpiresAt,
	); err != nil {
		return err
	}
	return server.writePendingPermission(
		response,
		interaction.id,
		pendingAuthorizationWaiting,
		interaction.code,
	)
}

func (server *PersonServer) writePendingPermission(
	response http.ResponseWriter,
	pendingID string,
	state pendingAuthorizationState,
	code string,
) error {
	requirement, err := aauth.FormatRequirementHeader(aauth.Requirement{
		Type:            aauth.RequirementInteraction,
		InteractionURL:  server.identifier + "/permission/interaction/" + pendingID,
		InteractionCode: code,
	})
	if err != nil {
		return err
	}
	response.Header().Set("Location", "/permission/pending/"+pendingID)
	response.Header().Set("Retry-After", "0")
	response.Header().Set("AAuth-Requirement", requirement)
	writeJSON(response, http.StatusAccepted, map[string]string{"status": string(state)})
	return nil
}

func (server *PersonServer) handlePermissionInteraction(
	response http.ResponseWriter,
	request *http.Request,
) {
	server.mu.Lock()
	pending, exists := server.permissionPending[request.PathValue("id")]
	if !exists {
		server.mu.Unlock()
		writeProblem(response, http.StatusGone, "invalid_code", errors.New("pending permission interaction is unknown"))
		return
	}
	original := pending
	status, code, err := pending.correlate(
		request.URL.Query()["code"],
		server.clock.Now(),
	)
	server.permissionPending[pending.id] = pending
	if persistErr := server.persistGovernanceLocked(); persistErr != nil {
		if governanceSaveDefinitelyFailed(persistErr) {
			server.permissionPending[pending.id] = original
		}
		server.mu.Unlock()
		writeProblem(response, http.StatusInternalServerError, "server_error", persistErr)
		return
	}
	if err != nil {
		server.mu.Unlock()
		writeProblem(response, status, code, err)
		return
	}
	body := append([]byte(nil), pending.requestBody...)
	agent := pending.agent
	server.mu.Unlock()

	var input aauth.PermissionRequest
	if err := decodeJSONBytes(bytes.NewReader(body), &input); err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", err)
		return
	}
	writeJSON(response, http.StatusOK, map[string]any{
		"status": "interacting",
		"agent":  agent,
		"action": input.Action,
	})
}

// ApprovePermission records trusted approval after interaction correlation.
// Deployment policy is evaluated here; knowledge of the code is not approval.
func (server *PersonServer) ApprovePermission(
	ctx context.Context,
	pendingID string,
) error {
	server.mu.Lock()
	pending, exists := server.permissionPending[pendingID]
	if !exists {
		server.mu.Unlock()
		return errors.New("reference: pending permission does not exist")
	}
	if !pending.expiresAt.After(server.clock.Now()) {
		original := pending
		pending.state = pendingAuthorizationExpired
		server.permissionPending[pendingID] = pending
		if err := server.persistGovernanceLocked(); err != nil {
			if governanceSaveDefinitelyFailed(err) {
				server.permissionPending[pendingID] = original
			}
			server.mu.Unlock()
			return err
		}
		server.mu.Unlock()
		return errors.New("reference: pending permission expired")
	}
	if pending.state != pendingAuthorizationInteracting {
		server.mu.Unlock()
		return errors.New("reference: pending permission is not awaiting a trusted decision")
	}
	body := append([]byte(nil), pending.requestBody...)
	agent := pending.agent
	server.mu.Unlock()

	var input aauth.PermissionRequest
	if err := decodeJSONBytes(bytes.NewReader(body), &input); err != nil {
		return err
	}
	evaluation := aauth.PermissionEvaluation{
		Agent:   agent,
		Request: input,
	}
	if input.Mission != nil {
		mission, err := server.activeMissionForAgent(agent, *input.Mission)
		if err != nil {
			return err
		}
		evaluation.Mission = &mission
	}
	decision, err := server.permissionPolicy(ctx, copyPermissionEvaluation(evaluation))
	if err != nil {
		return err
	}
	result := aauth.PermissionResponse{
		Permission: decision.Permission,
		Reason:     decision.Reason,
	}
	if err := result.Validate(); err != nil {
		return err
	}

	server.mu.Lock()
	defer server.mu.Unlock()
	pending, exists = server.permissionPending[pendingID]
	if !exists || pending.state != pendingAuthorizationInteracting {
		return errors.New("reference: pending permission changed while approval was evaluated")
	}
	if !pending.expiresAt.After(server.clock.Now()) {
		original := pending
		pending.state = pendingAuthorizationExpired
		server.permissionPending[pendingID] = pending
		if err := server.persistGovernanceLocked(); err != nil {
			if governanceSaveDefinitelyFailed(err) {
				server.permissionPending[pendingID] = original
			}
			return err
		}
		return errors.New("reference: pending permission expired")
	}
	original := pending
	pending.decision = decision
	pending.state = pendingAuthorizationApproved
	server.permissionPending[pendingID] = pending
	if err := server.persistGovernanceLocked(); err != nil {
		if governanceSaveDefinitelyFailed(err) {
			server.permissionPending[pendingID] = original
		}
		return err
	}
	return nil
}

// RejectPermission records a trusted terminal denial, abandonment, or server
// failure for a correlated permission interaction.
func (server *PersonServer) RejectPermission(
	pendingID string,
	code aauth.PollingErrorCode,
) error {
	if code != aauth.PollingDenied &&
		code != aauth.PollingAbandoned &&
		code != aauth.PollingServerError {
		return errors.New("reference: unsupported permission rejection code")
	}
	server.mu.Lock()
	defer server.mu.Unlock()
	pending, exists := server.permissionPending[pendingID]
	if !exists {
		return errors.New("reference: pending permission does not exist")
	}
	if !pending.expiresAt.After(server.clock.Now()) {
		original := pending
		pending.state = pendingAuthorizationExpired
		server.permissionPending[pendingID] = pending
		if err := server.persistGovernanceLocked(); err != nil {
			if governanceSaveDefinitelyFailed(err) {
				server.permissionPending[pendingID] = original
			}
			return err
		}
		return errors.New("reference: pending permission expired")
	}
	if pending.state != pendingAuthorizationInteracting {
		return errors.New("reference: pending permission is not awaiting a trusted decision")
	}
	original := pending
	pending.pollingError = code
	pending.state = pendingAuthorizationRejected
	server.permissionPending[pendingID] = pending
	if err := server.persistGovernanceLocked(); err != nil {
		if governanceSaveDefinitelyFailed(err) {
			server.permissionPending[pendingID] = original
		}
		return err
	}
	return nil
}

func (server *PersonServer) commitPendingPermissionTerminalLocked(
	pendingID string,
	pending pendingPersonPermission,
	responseBody []byte,
) error {
	originalPending := server.permissionPending[pendingID]
	originalHistory := copyPermissionHistory(server.permissionHistory)
	var input aauth.PermissionRequest
	if err := decodeJSONBytes(bytes.NewReader(pending.requestBody), &input); err != nil {
		return err
	}
	pending.state = pendingAuthorizationServed
	server.permissionPending[pendingID] = pending
	recordIndex := -1
	for index, record := range server.permissionHistory {
		if record.Proof != nil && record.Proof.ReplayKey == pending.requestReplayKey {
			recordIndex = index
			break
		}
	}
	if recordIndex < 0 {
		server.permissionPending[pendingID] = originalPending
		return errors.New("reference: pending permission request record is missing")
	}

	var originalMission storedMission
	missionChanged := false
	missionTerminated := false
	if input.Mission != nil {
		mission, exists := server.missions[input.Mission.S256]
		if !exists ||
			mission.reference != *input.Mission ||
			mission.agent != pending.agent ||
			aauth.S256(mission.bytes) != input.Mission.S256 {
			server.permissionPending[pendingID] = originalPending
			return ErrMissionUnknown
		}
		if mission.status == aauth.MissionTerminated {
			responseBody = problemBody(
				http.StatusForbidden,
				"mission_terminated",
				ErrMissionTerminated,
				map[string]any{"mission_status": string(aauth.MissionTerminated)},
			)
			missionTerminated = true
		} else {
			originalMission = mission
			mission.log = append(mission.log, aauth.MissionLogEntry{
				Sequence:       uint64(len(mission.log) + 1),
				Kind:           aauth.MissionLogPermissionDecision,
				RecordedAt:     server.clock.Now().UTC(),
				Agent:          pending.agent,
				DecidedBy:      pending.decision.DecidedBy,
				RequestProofID: pending.requestReplayKey,
				Response:       append([]byte(nil), responseBody...),
			})
			server.missions[input.Mission.S256] = mission
			missionChanged = true
		}
	}
	record := server.permissionHistory[recordIndex]
	record.DecidedAt = server.clock.Now().UTC()
	record.DecidedBy = pending.decision.DecidedBy
	record.Response = append([]byte(nil), responseBody...)
	server.permissionHistory[recordIndex] = record
	if err := server.persistGovernanceLocked(); err != nil {
		if governanceSaveDefinitelyFailed(err) {
			server.permissionPending[pendingID] = originalPending
			server.permissionHistory = originalHistory
			if missionChanged {
				server.missions[input.Mission.S256] = originalMission
			}
		}
		return err
	}
	if missionTerminated {
		return ErrMissionTerminated
	}
	return nil
}

func writePermissionTerminal(
	response http.ResponseWriter,
	status int,
	contentType string,
	body []byte,
) {
	response.Header().Set("Content-Type", contentType)
	response.Header().Set("Cache-Control", "no-store")
	response.WriteHeader(status)
	_, _ = response.Write(body)
}

func (server *PersonServer) handlePendingPermission(
	response http.ResponseWriter,
	request *http.Request,
) {
	verified, err := aauth.VerifyRequest(
		request.Context(),
		request,
		server.keyResolver,
		server.clock,
		aauth.VerifyRequestOptions{
			AllowedCredentialTypes: []string{aauth.AgentTokenType},
		},
	)
	if err != nil {
		writeSignatureFailure(response, err)
		return
	}
	thumbprint, err := verified.PublicKey.Thumbprint()
	if err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", nil)
		return
	}

	server.mu.Lock()
	pending, exists := server.permissionPending[request.PathValue("id")]
	if !exists {
		server.mu.Unlock()
		writeProblem(response, http.StatusGone, "gone", errors.New("pending permission is unknown"))
		return
	}
	if pending.agent != verified.Agent ||
		pending.pollingAgentThumbprint != thumbprint {
		server.mu.Unlock()
		writeProblem(response, http.StatusForbidden, "invalid_pending", errors.New("pending permission belongs to a different agent key"))
		return
	}
	if (pending.state == pendingAuthorizationWaiting ||
		pending.state == pendingAuthorizationInteracting) &&
		!pending.expiresAt.After(server.clock.Now()) {
		pending.state = pendingAuthorizationExpired
	}

	switch pending.state {
	case pendingAuthorizationWaiting, pendingAuthorizationInteracting:
		id := pending.id
		state := pending.state
		code := pending.code
		server.mu.Unlock()
		if err := server.writePendingPermission(response, id, state, code); err != nil {
			writeProblem(response, http.StatusInternalServerError, "server_error", err)
		}
	case pendingAuthorizationApproved:
		result := aauth.PermissionResponse{
			Permission: pending.decision.Permission,
			Reason:     pending.decision.Reason,
		}
		if err := result.Validate(); err != nil {
			server.mu.Unlock()
			writeProblem(response, http.StatusInternalServerError, "server_error", err)
			return
		}
		body, err := json.Marshal(result)
		if err != nil {
			server.mu.Unlock()
			writeProblem(response, http.StatusInternalServerError, "server_error", err)
			return
		}
		err = server.commitPendingPermissionTerminalLocked(pending.id, pending, body)
		server.mu.Unlock()
		if err != nil {
			server.writeMissionError(response, err)
			return
		}
		writePermissionTerminal(response, http.StatusOK, "application/json", body)
	case pendingAuthorizationExpired:
		body := problemBody(
			http.StatusRequestTimeout,
			"expired",
			errors.New("pending permission expired"),
			nil,
		)
		err := server.commitPendingPermissionTerminalLocked(pending.id, pending, body)
		server.mu.Unlock()
		if err != nil {
			server.writeMissionError(response, err)
			return
		}
		writePermissionTerminal(response, http.StatusRequestTimeout, "application/problem+json", body)
	case pendingAuthorizationRejected:
		code := pending.pollingError
		status := http.StatusForbidden
		if code == aauth.PollingServerError {
			status = http.StatusInternalServerError
		}
		body := problemBody(
			status,
			string(code),
			errors.New("pending permission was not approved"),
			nil,
		)
		err := server.commitPendingPermissionTerminalLocked(pending.id, pending, body)
		server.mu.Unlock()
		if err != nil {
			server.writeMissionError(response, err)
			return
		}
		writePermissionTerminal(response, status, "application/problem+json", body)
	case pendingAuthorizationInvalidCode:
		body := problemBody(
			http.StatusGone,
			"invalid_code",
			errors.New("permission interaction code validation failed"),
			nil,
		)
		err := server.commitPendingPermissionTerminalLocked(pending.id, pending, body)
		server.mu.Unlock()
		if err != nil {
			server.writeMissionError(response, err)
			return
		}
		writePermissionTerminal(response, http.StatusGone, "application/problem+json", body)
	default:
		server.mu.Unlock()
		writeProblem(response, http.StatusGone, "gone", errors.New("pending permission already returned a terminal response"))
	}
}

func (server *PersonServer) handleAudit(
	response http.ResponseWriter,
	request *http.Request,
) {
	body, err := readBoundedRequestBody(request)
	if err != nil {
		writeProblem(response, http.StatusBadRequest, "invalid_request", err)
		return
	}
	verified, err := aauth.VerifyRequest(
		request.Context(),
		request,
		server.keyResolver,
		server.clock,
		aauth.VerifyRequestOptions{
			RequiredComponents:     []string{"content-digest"},
			AllowedCredentialTypes: []string{aauth.AgentTokenType},
		},
	)
	if err != nil {
		writeSignatureFailure(response, err)
		return
	}
	if server.governanceReplayExists(verified.ReplayKey) {
		writeSignatureFailure(response, errors.New("request proof was replayed"))
		return
	}
	var input aauth.AuditRequest
	if err := decodeJSONBytes(bytes.NewReader(body), &input); err != nil {
		writeProblem(response, http.StatusBadRequest, "invalid_request", err)
		return
	}
	if err := input.Validate(); err != nil {
		writeProblem(response, http.StatusBadRequest, "invalid_request", err)
		return
	}
	err = server.appendMissionLogWithReplay(
		verified.Agent,
		input.Mission,
		aauth.MissionLogEntry{
			Kind:           aauth.MissionLogAudit,
			RecordedAt:     server.clock.Now().UTC(),
			Agent:          verified.Agent,
			RequestProofID: verified.ReplayKey,
			Request:        append([]byte(nil), body...),
			Proof:          requestProof(request, verified),
		},
		verified.ReplayKey,
		verified.Created.Add(signaturekey.DefaultSignatureWindow),
	)
	if err != nil {
		server.writeMissionError(response, err)
		return
	}
	response.Header().Set("Cache-Control", "no-store")
	response.WriteHeader(http.StatusCreated)
}

func (server *PersonServer) activeMissionForAgent(
	agent string,
	reference aauth.MissionReference,
) (aauth.MissionSnapshot, error) {
	if err := reference.Validate(); err != nil || reference.Approver != server.identifier {
		return aauth.MissionSnapshot{}, ErrMissionUnknown
	}
	server.mu.RLock()
	defer server.mu.RUnlock()
	mission, err := server.activeMissionForAgentLocked(agent, reference)
	if err != nil {
		return aauth.MissionSnapshot{}, err
	}
	return copyMissionSnapshot(mission), nil
}

func (server *PersonServer) activeMissionForAgentLocked(
	agent string,
	reference aauth.MissionReference,
) (storedMission, error) {
	mission, exists := server.missions[reference.S256]
	if !exists ||
		mission.reference != reference ||
		mission.agent != agent ||
		aauth.S256(mission.bytes) != reference.S256 {
		return storedMission{}, ErrMissionUnknown
	}
	if mission.status == aauth.MissionTerminated {
		return storedMission{}, ErrMissionTerminated
	}
	if mission.expiresAt != nil && !mission.expiresAt.After(server.clock.Now()) {
		return storedMission{}, ErrMissionExpired
	}
	return mission, nil
}

func (server *PersonServer) appendMissionLogWithReplay(
	agent string,
	reference aauth.MissionReference,
	entry aauth.MissionLogEntry,
	replayKey string,
	replayExpiresAt time.Time,
) error {
	if err := reference.Validate(); err != nil || reference.Approver != server.identifier {
		return ErrMissionUnknown
	}
	server.mu.Lock()
	defer server.mu.Unlock()
	if _, replayed := server.governanceReplays[replayKey]; replayed {
		return errGovernanceReplay
	}
	mission, err := server.activeMissionForAgentLocked(agent, reference)
	if err != nil {
		return err
	}
	entry.Sequence = uint64(len(mission.log) + 1)
	entry.Request = append([]byte(nil), entry.Request...)
	entry.Response = append([]byte(nil), entry.Response...)
	entry.Proof = copyRequestProof(entry.Proof)
	mission.log = append(mission.log, entry)
	previous := server.missions[reference.S256]
	previousReplays := copyGovernanceReplays(server.governanceReplays)
	server.missions[reference.S256] = mission
	server.addGovernanceReplayLocked(replayKey, replayExpiresAt)
	if err := server.persistGovernanceLocked(); err != nil {
		if governanceSaveDefinitelyFailed(err) {
			server.missions[reference.S256] = previous
			server.governanceReplays = previousReplays
		}
		return err
	}
	return nil
}

func (server *PersonServer) writeMissionError(response http.ResponseWriter, err error) {
	if errors.Is(err, errGovernanceReplay) {
		writeSignatureFailure(response, err)
		return
	}
	if errors.Is(err, ErrMissionTerminated) {
		writeMissionTerminated(response)
		return
	}
	if errors.Is(err, ErrMissionExpired) {
		writeProblem(response, http.StatusForbidden, "mission_expired", err)
		return
	}
	if errors.Is(err, ErrMissionUnknown) {
		writeProblem(response, http.StatusForbidden, "invalid_mission", err)
		return
	}
	writeProblem(response, http.StatusInternalServerError, "server_error", err)
}

func copyMissionSnapshot(mission storedMission) aauth.MissionSnapshot {
	log := make([]aauth.MissionLogEntry, len(mission.log))
	for index, entry := range mission.log {
		log[index] = entry
		log[index].Request = append([]byte(nil), entry.Request...)
		log[index].Response = append([]byte(nil), entry.Response...)
		log[index].Proof = copyRequestProof(entry.Proof)
	}
	return aauth.MissionSnapshot{
		Reference:         mission.reference,
		Bytes:             append([]byte(nil), mission.bytes...),
		Description:       mission.description,
		ApprovedTools:     append([]aauth.Tool(nil), mission.approvedTools...),
		ApprovedResources: append([]string(nil), mission.approvedResources...),
		Capabilities:      append([]string(nil), mission.capabilities...),
		ExpiresAt:         copyTimePointer(mission.expiresAt),
		Status:            mission.status,
		Log:               log,
	}
}

func copyTimePointer(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	copied := *value
	return &copied
}

func formatOptionalTime(value *time.Time) string {
	if value == nil {
		return ""
	}
	return value.UTC().Format(time.RFC3339Nano)
}

func copyPermissionEvaluation(
	evaluation aauth.PermissionEvaluation,
) aauth.PermissionEvaluation {
	copied := aauth.PermissionEvaluation{
		Agent:   evaluation.Agent,
		Request: copyPermissionRequest(evaluation.Request),
	}
	if evaluation.Mission != nil {
		mission := *evaluation.Mission
		mission.Bytes = append([]byte(nil), evaluation.Mission.Bytes...)
		mission.ApprovedTools = append([]aauth.Tool(nil), evaluation.Mission.ApprovedTools...)
		mission.ApprovedResources = append([]string(nil), evaluation.Mission.ApprovedResources...)
		mission.Capabilities = append([]string(nil), evaluation.Mission.Capabilities...)
		mission.ExpiresAt = copyTimePointer(evaluation.Mission.ExpiresAt)
		mission.Log = make([]aauth.MissionLogEntry, len(evaluation.Mission.Log))
		for index, entry := range evaluation.Mission.Log {
			mission.Log[index] = entry
			mission.Log[index].Request = append([]byte(nil), entry.Request...)
			mission.Log[index].Response = append([]byte(nil), entry.Response...)
			mission.Log[index].Proof = copyRequestProof(entry.Proof)
		}
		copied.Mission = &mission
	}
	return copied
}

func copyPermissionRequest(request aauth.PermissionRequest) aauth.PermissionRequest {
	copied := request
	if request.Mission != nil {
		mission := *request.Mission
		copied.Mission = &mission
	}
	if request.Parameters != nil {
		encoded, err := json.Marshal(request.Parameters)
		if err == nil {
			var parameters map[string]any
			if json.Unmarshal(encoded, &parameters) == nil {
				copied.Parameters = parameters
			}
		}
	}
	return copied
}

func requestProof(
	request *http.Request,
	verified aauth.VerifiedRequest,
) *aauth.RequestProof {
	credentialIssuer := ""
	switch {
	case verified.AgentToken != nil:
		claims, _ := verified.AgentClaims()
		credentialIssuer = claims.Issuer
	case verified.PersonToken != nil:
		claims, _ := verified.PersonClaims()
		credentialIssuer = claims.Issuer
	case verified.AuthToken != nil:
		claims, _ := verified.AuthClaims()
		credentialIssuer = claims.Issuer
	case verified.SubscribeToken != nil:
		credentialIssuer = verified.SubscribeToken.Issuer
	case verified.SelfJWT != nil:
		credentialIssuer = verified.SelfJWT.Issuer
	}
	authority := request.Host
	if authority == "" && request.URL != nil {
		authority = request.URL.Host
	}
	target := ""
	if request.URL != nil {
		target = request.URL.RequestURI()
	}
	return &aauth.RequestProof{
		Method:           request.Method,
		Authority:        authority,
		Target:           target,
		ContentDigest:    request.Header.Get("Content-Digest"),
		ContentType:      request.Header.Get("Content-Type"),
		SignatureInput:   request.Header.Get("Signature-Input"),
		Signature:        request.Header.Get("Signature"),
		SignatureKey:     request.Header.Get("Signature-Key"),
		Authorization:    request.Header.Get("Authorization"),
		SignatureKeyType: string(verified.SignatureKeyType),
		CredentialType:   verified.CredentialType,
		CredentialIssuer: credentialIssuer,
		Signer:           verified.Signer,
		Agent:            verified.Agent,
		PublicKey:        verified.PublicKey,
		Created:          verified.Created.UTC(),
		VerifiedAt:       verified.VerifiedAt.UTC(),
		ReplayKey:        verified.ReplayKey,
	}
}

func copyRequestProof(proof *aauth.RequestProof) *aauth.RequestProof {
	if proof == nil {
		return nil
	}
	copied := *proof
	return &copied
}

func (server *PersonServer) handleToken(response http.ResponseWriter, request *http.Request) {
	server.pendingMu.Lock()
	stateErr := server.settleAuthorizationStateLocked(request.Context())
	server.pendingMu.Unlock()
	if stateErr != nil {
		writeProblem(response, http.StatusServiceUnavailable, "authorization_state_unavailable", stateErr)
		return
	}
	agentKeyCapture, agentVerificationResolver := newRetainedKeyCapture(server.keyResolver)
	verified, err := aauth.VerifyRequest(request.Context(), request, agentVerificationResolver, server.clock, aauth.VerifyRequestOptions{
		RequiredComponents:     []string{"content-type"},
		RequireExactComponents: true,
		AllowedCredentialTypes: []string{aauth.AgentTokenType},
	})
	if err != nil {
		writeSignatureFailure(response, err)
		return
	}
	verificationClock := aauth.ClockFunc(func() time.Time { return verified.VerifiedAt })
	agentClaims, err := verified.AgentClaims()
	if err != nil {
		writeSignatureFailure(response, err)
		return
	}
	agentVerificationKey, err := agentKeyCapture.retainedKey()
	if err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", err)
		return
	}
	requestBody, err := readBoundedRequestBody(request)
	if err != nil {
		writeProblem(response, http.StatusBadRequest, "invalid_request", err)
		return
	}
	var input personAuthorizationTokenInput
	if err := decodeJSONBytes(bytes.NewReader(requestBody), &input); err != nil || input.ResourceToken == "" {
		writeProblem(response, http.StatusBadRequest, "invalid_request", err)
		return
	}
	if agentClaims.ParentAgent != "" {
		writeProblem(response, http.StatusForbidden, "invalid_agent", errors.New("sub-agent cannot request authorization directly"))
		return
	}
	targetAgent := verified.Agent
	targetKey := verified.PublicKey
	parentAgent := ""
	targetTokenExpiry := agentClaims.ExpiresAt
	var subagentVerificationKey *jose.JWK
	if input.SubagentToken != "" {
		subagentKeyCapture, subagentVerificationResolver := newRetainedKeyCapture(server.keyResolver)
		subagentEvidence, err := aauth.VerifyAgentToken(request.Context(), input.SubagentToken, subagentVerificationResolver, verificationClock)
		if err != nil {
			writeTokenVerificationFailure(response, http.StatusBadRequest, "invalid_subagent_token", err)
			return
		}
		subagent, err := subagentEvidence.Claims()
		if err != nil {
			writeTokenVerificationFailure(response, http.StatusBadRequest, "invalid_subagent_token", err)
			return
		}
		key, err := subagentKeyCapture.retainedKey()
		if err != nil {
			writeProblem(response, http.StatusInternalServerError, "server_error", err)
			return
		}
		subagentVerificationKey = &key
		if subagent.ParentAgent == "" || subagent.ParentAgent != verified.Agent {
			writeProblem(response, http.StatusForbidden, "invalid_subagent_token", errors.New("sub-agent token does not name the signing parent"))
			return
		}
		if input.UpstreamToken == "" && subagent.PersonServer != server.identifier {
			writeProblem(response, http.StatusForbidden, "invalid_subagent_token", errors.New("sub-agent token names a different person server"))
			return
		}
		targetAgent = subagent.Subject
		targetKey = subagent.Confirmation.JWK
		parentAgent = verified.Agent
		if subagent.ExpiresAt < targetTokenExpiry {
			targetTokenExpiry = subagent.ExpiresAt
		}
	}
	var upstream *aauth.AuthTokenClaims
	var upstreamVerificationKey *jose.JWK
	if input.UpstreamToken != "" {
		if server.trustedUpstreamIssuer == nil {
			writeProblem(response, http.StatusForbidden, "invalid_upstream_token", errors.New("call chaining is not configured"))
			return
		}
		upstreamKeyCapture, upstreamVerificationResolver := newRetainedKeyCapture(server.keyResolver)
		upstreamEvidence, err := aauth.VerifyAuthToken(request.Context(), input.UpstreamToken, upstreamVerificationResolver, verificationClock)
		if err != nil {
			writeTokenVerificationFailure(response, http.StatusBadRequest, "invalid_upstream_token", err)
			return
		}
		claims, err := upstreamEvidence.Claims()
		if err != nil {
			writeTokenVerificationFailure(response, http.StatusBadRequest, "invalid_upstream_token", err)
			return
		}
		key, err := upstreamKeyCapture.retainedKey()
		if err != nil {
			writeProblem(response, http.StatusInternalServerError, "server_error", err)
			return
		}
		upstreamVerificationKey = &key
		if err := server.trustedUpstreamIssuer(request.Context(), claims.Issuer); err != nil {
			writeHostPolicyRefusal(response, "invalid_upstream_token", "upstream token issuer is not trusted")
			return
		}
		if claims.Audience != agentClaims.Issuer {
			writeProblem(response, http.StatusForbidden, "invalid_upstream_token", errors.New("upstream auth-token audience does not match intermediary issuer"))
			return
		}
		if claims.PersonServer != server.identifier {
			writeProblem(response, http.StatusForbidden, "invalid_upstream_token", errors.New("upstream auth token ps does not match person server"))
			return
		}
		if !claims.Confirmation.JWK.Equal(verified.PublicKey) {
			writeProblem(response, http.StatusForbidden, "invalid_upstream_token", errors.New("upstream auth-token confirmation key does not match intermediary request key"))
			return
		}
		upstream = &claims
		if claims.ExpiresAt < targetTokenExpiry {
			targetTokenExpiry = claims.ExpiresAt
		}
	}

	resourceKeyCapture, resourceVerificationResolver := newRetainedKeyCapture(server.keyResolver)
	resourceEvidence, err := aauth.VerifyResourceToken(request.Context(), input.ResourceToken, resourceVerificationResolver, verificationClock)
	if err != nil {
		writeResourceTokenVerificationFailure(response, err)
		return
	}
	resourceToken, err := resourceEvidence.Claims()
	if err != nil {
		writeResourceTokenVerificationFailure(response, err)
		return
	}
	resourceVerificationKey, err := resourceKeyCapture.retainedKey()
	if err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", err)
		return
	}
	if server.seenReplay(verified.ReplayKey, verified.Created.Add(signaturekey.DefaultSignatureWindow), verified.VerifiedAt) {
		writeSignatureFailure(response, errors.New("request proof was replayed"))
		return
	}
	if resourceToken.Audience != server.identifier {
		if server.federationClient == nil || server.accessServerEndpoint == nil {
			writeProblem(response, http.StatusForbidden, "invalid_resource_token", errors.New("resource-token audience requires an unconfigured access server"))
			return
		}
		if err := aauth.ValidateServerIdentifier(resourceToken.Audience); err != nil {
			writeProblem(response, http.StatusForbidden, "invalid_resource_token", err)
			return
		}
	}
	if resourceToken.PersonServer == "" {
		writeProblem(response, http.StatusForbidden, "invalid_resource_token", errors.New("current resource-token ps is required"))
		return
	}
	if upstream == nil && !server.requireCurrentPersonServer(response, verified) {
		return
	}
	if server.personTokenStore == nil || resourceToken.PersonServer != server.identifier {
		writeProblem(response, http.StatusForbidden, "invalid_resource_token", errors.New("resource-token ps does not match person server"))
		return
	}
	if resourceToken.ExpiresAt-resourceToken.IssuedAt > int64(currentResourceTokenLifetime/time.Second) {
		writeProblem(response, http.StatusBadRequest, "invalid_resource_token", errors.New("resource-token lifetime exceeds the person server retention bound"))
		return
	}
	thumbprint, err := targetKey.Thumbprint()
	if err != nil || thumbprint != resourceToken.AgentJKT {
		writeProblem(response, http.StatusForbidden, "invalid_resource_token", errors.New("resource-token agent_jkt does not match authorized agent key"))
		return
	}

	scopes, err := parseScopes(resourceToken.Scope)
	if err != nil {
		writeProblem(response, http.StatusBadRequest, "invalid_resource_token", err)
		return
	}
	record, err := server.personTokenStore.Load(request.Context(), server.identifier, resourceToken.PresentedJTI)
	if errors.Is(err, ErrPersonTokenNotFound) || err == nil && !record.RetainUntil.After(server.clock.Now()) {
		writeProblem(response, http.StatusBadRequest, "unknown_person_token", errors.New("resource token names an unknown retained person token"))
		return
	}
	if err != nil {
		writeProblem(response, http.StatusServiceUnavailable, "person_token_custody_unavailable", err)
		return
	}
	if validatePersonTokenRecord(record) != nil ||
		record.JTI != resourceToken.PresentedJTI ||
		resourceToken.IssuedAt >= record.ExpiresAt.Unix() ||
		record.PersonServer != resourceToken.PersonServer ||
		record.Resource != resourceToken.Issuer ||
		record.Subject != resourceToken.Subject ||
		record.MissionS256 != resourceToken.MissionS256 ||
		record.Tenant != resourceToken.Tenant {
		writeProblem(response, http.StatusBadRequest, "invalid_resource_token", errors.New("resource token does not match the retained person-token record"))
		return
	}
	if resourceToken.MissionS256 != "" {
		reference := aauth.MissionReference{Approver: server.identifier, S256: resourceToken.MissionS256}
		if _, err := server.activeMissionForAgent(verified.Agent, reference); err != nil {
			server.writeMissionError(response, err)
			return
		}
	}
	if upstream != nil && upstream.MissionS256 != resourceToken.MissionS256 {
		writeProblem(response, http.StatusForbidden, "invalid_mission", errors.New("downstream mission_s256 does not match upstream authorization"))
		return
	}

	pollingAgentThumbprint, err := verified.PublicKey.Thumbprint()
	if err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", nil)
		return
	}
	authorizationContext := personAuthorizationContext{
		request: aauth.AuthorizationRequest{
			Agent:         targetAgent,
			ParentAgent:   parentAgent,
			Resource:      resourceToken.Issuer,
			Scope:         append([]string(nil), scopes...),
			Mission:       resourceToken.Mission,
			Justification: input.Justification,
			Upstream:      upstream,
		},
		resourceTokenCompact: input.ResourceToken,
		agentTokenCompact:    verified.RawCredential,
		subagentTokenCompact: input.SubagentToken,
		upstreamTokenCompact: input.UpstreamToken,
		tokenVerificationKeys: retainedAuthorizationTokenKeys{
			Resource: resourceVerificationKey,
			Agent:    agentVerificationKey,
			Subagent: subagentVerificationKey,
			Upstream: upstreamVerificationKey,
		},
		requestBody:            append([]byte(nil), requestBody...),
		requestProof:           requestProof(request, verified),
		targetAgent:            targetAgent,
		targetKey:              targetKey,
		parentAgent:            parentAgent,
		pollingAgent:           verified.Agent,
		pollingAgentThumbprint: pollingAgentThumbprint,
		targetTokenExpiresAt:   targetTokenExpiry,
		resourceToken:          resourceToken,
		personTokenRecord:      record,
	}
	authorizationContext.request.PersonServer = resourceToken.PersonServer
	authorizationContext.request.Subject = resourceToken.Subject
	authorizationContext.request.MissionS256 = resourceToken.MissionS256
	authorizationContext.request.Tenant = resourceToken.Tenant
	authorizationContext.request.Account = resourceToken.Account
	if server.interactionRequired != nil {
		required, err := server.interactionRequired(
			request.Context(),
			copyAuthorizationRequest(authorizationContext.request),
		)
		if err != nil {
			writeHostPolicyRefusal(response, "access_denied", "authorization policy denied the request")
			return
		}
		if required {
			if err := server.beginPendingAuthorization(response, authorizationContext); err != nil {
				if !writeAuthorizationStateFailure(response, err) {
					writeProblem(response, http.StatusInternalServerError, "server_error", err)
				}
			}
			return
		}
	}

	decision, err := server.authorizationPolicy(
		request.Context(),
		copyAuthorizationRequest(authorizationContext.request),
	)
	if err != nil {
		writeHostPolicyRefusal(response, "access_denied", "authorization policy denied the request")
		return
	}
	if err := validatePersonAuthorizationDecision(decision, scopes); err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", errors.New("authorization policy returned an invalid grant"))
		return
	}
	if decision.Subject != resourceToken.Subject {
		writeProblem(response, http.StatusInternalServerError, "server_error", errors.New("authorization policy changed the retained directed subject"))
		return
	}
	server.completeAuthorization(response, request.Context(), authorizationContext, decision)
}

func (server *PersonServer) completeAuthorization(
	response http.ResponseWriter,
	ctx context.Context,
	authorizationContext personAuthorizationContext,
	decision aauth.AuthorizationDecision,
) {
	resourceToken := authorizationContext.resourceToken
	now := server.clock.Now()
	if resourceToken.Audience != server.identifier {
		exchange, err := server.exchangeWithAccessServer(
			ctx,
			resourceToken.Audience,
			authorizationContext.resourceTokenCompact,
			authorizationContext.agentTokenCompact,
			authorizationContext.subagentTokenCompact,
			authorizationContext.upstreamTokenCompact,
			authorizationContext.targetKey,
			authorizationContext.targetTokenExpiresAt,
			resourceToken,
			decision,
		)
		if err != nil {
			writeProblem(response, http.StatusBadGateway, "federation_failed", err)
			return
		}
		if exchange.deferred != nil {
			if _, err := pendingIDFromLocation(exchange.deferred.Location); err != nil {
				writeProblem(response, http.StatusBadGateway, "federation_failed", err)
				return
			}
			if err := server.beginFederatedAuthorization(
				response,
				authorizationContext,
				decision,
				resourceToken.Audience,
				*exchange.deferred,
			); err != nil {
				if !writeAuthorizationStateFailure(response, err) {
					writeProblem(response, http.StatusInternalServerError, "server_error", err)
				}
			}
			return
		}
		writeJSON(response, http.StatusOK, map[string]any{
			"auth_token": exchange.authToken,
			"expires_in": exchange.claims.ExpiresAt - now.Unix(),
		})
		return
	}

	authToken, expiresAt, err := server.mintLocalAuthToken(authorizationContext, decision, "")
	if err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", err)
		return
	}
	writeJSON(response, http.StatusOK, map[string]any{
		"auth_token": authToken,
		"expires_in": expiresAt - now.Unix(),
	})
}

func (server *PersonServer) mintLocalAuthToken(
	authorizationContext personAuthorizationContext,
	decision aauth.AuthorizationDecision,
	tokenID string,
) (string, int64, error) {
	resourceToken := authorizationContext.resourceToken
	now := server.clock.Now()
	expiresAt := now.Add(time.Hour).Unix()
	if authorizationContext.targetTokenExpiresAt < expiresAt {
		expiresAt = authorizationContext.targetTokenExpiresAt
	}
	if resourceToken.ExpiresAt < expiresAt {
		expiresAt = resourceToken.ExpiresAt
	}
	if tokenID == "" {
		tokenID = server.newID()
	}
	claims := aauth.AuthTokenClaims{
		Issuer:       server.identifier,
		DWK:          aauth.PersonDiscoveryDocument,
		Audience:     resourceToken.Issuer,
		JTI:          tokenID,
		Confirmation: aauth.Confirmation{JWK: authorizationContext.targetKey},
		IssuedAt:     now.Unix(),
		ExpiresAt:    expiresAt,
		Subject:      resourceToken.Subject,
		Scope:        strings.Join(decision.Scope, " "),
		PersonServer: resourceToken.PersonServer,
		Account:      resourceToken.Account,
		MissionS256:  resourceToken.MissionS256,
		Tenant:       resourceToken.Tenant,
	}
	authToken, err := aauth.MintAuthToken(server.signingKey, claims)
	if err != nil {
		return "", 0, err
	}
	return authToken, expiresAt, nil
}

func (server *PersonServer) beginPendingAuthorization(
	response http.ResponseWriter,
	authorizationContext personAuthorizationContext,
) error {
	now := server.clock.Now()
	expiresAt := now.Add(server.pendingLifetime)
	for _, tokenExpiry := range []int64{
		authorizationContext.targetTokenExpiresAt,
		authorizationContext.resourceToken.ExpiresAt,
	} {
		candidate := time.Unix(tokenExpiry, 0)
		if candidate.Before(expiresAt) {
			expiresAt = candidate
		}
	}
	if !expiresAt.After(now) {
		return errors.New("reference: authorization credentials expire before interaction can begin")
	}
	server.randomMu.Lock()
	interaction, err := newPendingInteraction(server.random, expiresAt)
	server.randomMu.Unlock()
	if err != nil {
		return err
	}
	pending := &pendingPersonAuthorization{
		pendingInteraction: interaction,
		context:            copyPersonAuthorizationContext(authorizationContext),
	}
	server.pendingMu.Lock()
	if _, exists := server.pending[interaction.id]; exists {
		server.pendingMu.Unlock()
		return errors.New("reference: pending identifier source returned a duplicate value")
	}
	server.pending[interaction.id] = pending
	if err := server.persistAuthorizationStateLocked(context.Background()); err != nil {
		server.pendingMu.Unlock()
		return err
	}
	server.pendingMu.Unlock()
	return server.writePendingAuthorization(
		response,
		interaction.id,
		pendingAuthorizationWaiting,
		interaction.code,
	)
}

func (server *PersonServer) beginFederatedAuthorization(
	response http.ResponseWriter,
	authorizationContext personAuthorizationContext,
	decision aauth.AuthorizationDecision,
	accessServer string,
	deferred aauth.DeferredResponse,
) error {
	pendingID, err := pendingIDFromLocation(deferred.Location)
	if err != nil {
		return err
	}
	now := server.clock.Now()
	expiresAt := now.Add(server.pendingLifetime)
	for _, tokenExpiry := range []int64{
		authorizationContext.targetTokenExpiresAt,
		authorizationContext.resourceToken.ExpiresAt,
	} {
		candidate := time.Unix(tokenExpiry, 0)
		if candidate.Before(expiresAt) {
			expiresAt = candidate
		}
	}
	if !expiresAt.After(now) {
		return errors.New("reference: authorization credentials expire before federation can complete")
	}
	state := pendingAuthorizationWaiting
	if deferred.Status == "interacting" {
		state = pendingAuthorizationInteracting
	}
	federated := &pendingFederatedAuthorization{
		accessServer: accessServer,
		location:     deferred.Location,
		retryAfter:   deferred.RetryAfter,
		notBefore:    now.Add(deferred.RetryAfter),
		status:       deferred.Status,
		requirement:  copyRequirement(deferred.Requirement),
	}
	pending := &pendingPersonAuthorization{
		pendingInteraction: pendingInteraction{
			id:        pendingID,
			state:     state,
			expiresAt: expiresAt,
		},
		context: copyPersonAuthorizationContext(authorizationContext),
		decision: aauth.AuthorizationDecision{
			Subject: decision.Subject,
			Scope:   append([]string(nil), decision.Scope...),
		},
		federated: federated,
	}
	server.pendingMu.Lock()
	if _, exists := server.pending[pendingID]; exists {
		server.pendingMu.Unlock()
		return errors.New("reference: pending identifier source returned a duplicate value")
	}
	server.pending[pendingID] = pending
	if err := server.persistAuthorizationStateLocked(context.Background()); err != nil {
		server.pendingMu.Unlock()
		return err
	}
	server.pendingMu.Unlock()
	return server.writeFederatedPendingAuthorization(response, pendingID, federated, now)
}

func copyRequirement(requirement *aauth.Requirement) *aauth.Requirement {
	if requirement == nil {
		return nil
	}
	copied := *requirement
	return &copied
}

func (server *PersonServer) writeFederatedPendingAuthorization(
	response http.ResponseWriter,
	pendingID string,
	federated *pendingFederatedAuthorization,
	now time.Time,
) error {
	if federated == nil {
		return errors.New("reference: federated pending authorization is required")
	}
	delay := federated.retryAfter
	if federated.notBefore.After(now) {
		delay = federated.notBefore.Sub(now)
	}
	response.Header().Set("Location", "/pending/"+pendingID)
	response.Header().Set("Retry-After", fmt.Sprintf("%d", durationSecondsCeil(delay)))
	if federated.requirement != nil {
		requirement, err := aauth.FormatRequirementHeader(*federated.requirement)
		if err != nil {
			return err
		}
		response.Header().Set("AAuth-Requirement", requirement)
	}
	writeJSON(response, http.StatusAccepted, map[string]string{"status": federated.status})
	return nil
}

func durationSecondsCeil(duration time.Duration) int64 {
	if duration <= 0 {
		return 0
	}
	seconds := int64(duration / time.Second)
	if duration%time.Second != 0 {
		seconds++
	}
	return seconds
}

func copyPersonAuthorizationContext(
	authorizationContext personAuthorizationContext,
) personAuthorizationContext {
	copied := authorizationContext
	copied.request = copyAuthorizationRequest(authorizationContext.request)
	return copied
}

func (server *PersonServer) writePendingAuthorization(
	response http.ResponseWriter,
	pendingID string,
	state pendingAuthorizationState,
	code string,
) error {
	requirement, err := aauth.FormatRequirementHeader(aauth.Requirement{
		Type:            aauth.RequirementInteraction,
		InteractionURL:  server.identifier + "/interaction/" + pendingID,
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

// ApproveAuthorization records a trusted user approval after the interaction
// code has correlated a browser session. The code itself cannot call this
// method or choose the resulting subject or scope.
func (server *PersonServer) ApproveAuthorization(ctx context.Context, pendingID string) error {
	server.pendingMu.Lock()
	if err := server.settleAuthorizationStateLocked(ctx); err != nil {
		server.pendingMu.Unlock()
		return err
	}
	pending, exists := server.pending[pendingID]
	if !exists {
		server.pendingMu.Unlock()
		return errors.New("reference: pending authorization does not exist")
	}
	if pending.federated != nil {
		server.pendingMu.Unlock()
		return errors.New("reference: access-server authorization requires an access-server decision")
	}
	if pending.state != pendingAuthorizationInteracting {
		server.pendingMu.Unlock()
		return errors.New("reference: pending authorization is not awaiting a trusted decision")
	}
	now := server.clock.Now()
	if !pending.expiresAt.After(now) {
		pending.state = pendingAuthorizationExpired
		persistErr := server.persistAuthorizationStateLocked(ctx)
		server.pendingMu.Unlock()
		if persistErr != nil {
			return persistErr
		}
		return errors.New("reference: pending authorization expired")
	}
	authorizationRequest := copyAuthorizationRequest(pending.context.request)
	server.pendingMu.Unlock()

	decision, err := server.authorizationPolicy(ctx, authorizationRequest)
	if err != nil {
		return err
	}
	if err := validatePersonAuthorizationDecision(decision, authorizationRequest.Scope); err != nil {
		return err
	}
	if decision.Subject != authorizationRequest.Subject {
		return errors.New("reference: authorization decision changed the retained directed subject")
	}

	server.pendingMu.Lock()
	defer server.pendingMu.Unlock()
	current, exists := server.pending[pendingID]
	if !exists || current != pending || current.state != pendingAuthorizationInteracting {
		return errors.New("reference: pending authorization changed while approval was evaluated")
	}
	pending = current
	if !pending.expiresAt.After(server.clock.Now()) {
		pending.state = pendingAuthorizationExpired
		if err := server.persistAuthorizationStateLocked(ctx); err != nil {
			return err
		}
		return errors.New("reference: pending authorization expired")
	}
	pending.decision = aauth.AuthorizationDecision{
		Subject: decision.Subject,
		Scope:   append([]string(nil), decision.Scope...),
	}
	pending.state = pendingAuthorizationApproved
	return server.persistAuthorizationStateLocked(ctx)
}

// RejectAuthorization records a trusted terminal denial or abandonment.
func (server *PersonServer) RejectAuthorization(
	pendingID string,
	code aauth.PollingErrorCode,
) error {
	if code != aauth.PollingDenied &&
		code != aauth.PollingAbandoned &&
		code != aauth.PollingServerError {
		return errors.New("reference: unsupported authorization rejection code")
	}
	server.pendingMu.Lock()
	defer server.pendingMu.Unlock()
	if err := server.settleAuthorizationStateLocked(context.Background()); err != nil {
		return err
	}
	pending, exists := server.pending[pendingID]
	if !exists {
		return errors.New("reference: pending authorization does not exist")
	}
	if pending.federated != nil {
		return errors.New("reference: access-server authorization requires an access-server decision")
	}
	if pending.state != pendingAuthorizationInteracting {
		return errors.New("reference: pending authorization is not awaiting a trusted decision")
	}
	if !pending.expiresAt.After(server.clock.Now()) {
		pending.state = pendingAuthorizationExpired
		if err := server.persistAuthorizationStateLocked(context.Background()); err != nil {
			return err
		}
		return errors.New("reference: pending authorization expired")
	}
	pending.pollingError = code
	pending.state = pendingAuthorizationRejected
	return server.persistAuthorizationStateLocked(context.Background())
}

func (server *PersonServer) handlePendingAuthorization(
	response http.ResponseWriter,
	request *http.Request,
) {
	server.pendingMu.Lock()
	stateErr := server.settleAuthorizationStateLocked(request.Context())
	server.pendingMu.Unlock()
	if stateErr != nil {
		writeProblem(response, http.StatusServiceUnavailable, "authorization_state_unavailable", stateErr)
		return
	}
	verified, err := aauth.VerifyRequest(
		request.Context(),
		request,
		server.keyResolver,
		server.clock,
		aauth.VerifyRequestOptions{
			AllowedCredentialTypes: []string{aauth.AgentTokenType},
		},
	)
	if err != nil {
		writeSignatureFailure(response, err)
		return
	}
	thumbprint, err := verified.PublicKey.Thumbprint()
	if err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", nil)
		return
	}

	server.pendingMu.Lock()
	pending, exists := server.pending[request.PathValue("id")]
	if !exists {
		server.pendingMu.Unlock()
		writeProblem(response, http.StatusGone, "gone", errors.New("pending authorization is unknown"))
		return
	}
	if pending.context.pollingAgent != verified.Agent ||
		pending.context.pollingAgentThumbprint != thumbprint {
		server.pendingMu.Unlock()
		writeProblem(response, http.StatusForbidden, "invalid_pending", errors.New("pending authorization belongs to a different agent key"))
		return
	}
	if (pending.state == pendingAuthorizationWaiting ||
		pending.state == pendingAuthorizationInteracting) &&
		!pending.expiresAt.After(server.clock.Now()) {
		pending.state = pendingAuthorizationExpired
		if err := server.persistAuthorizationStateLocked(request.Context()); err != nil {
			server.pendingMu.Unlock()
			writeProblem(response, http.StatusServiceUnavailable, "authorization_state_unavailable", err)
			return
		}
	}

	switch pending.state {
	case pendingAuthorizationWaiting, pendingAuthorizationInteracting:
		if pending.federated != nil {
			if pending.pollingFederation ||
				server.clock.Now().Before(pending.federated.notBefore) {
				id := pending.id
				federated := copyPendingFederation(pending.federated)
				server.pendingMu.Unlock()
				if err := server.writeFederatedPendingAuthorization(
					response,
					id,
					federated,
					server.clock.Now(),
				); err != nil {
					writeProblem(response, http.StatusInternalServerError, "server_error", err)
				}
				return
			}
			pending.pollingFederation = true
			if err := server.persistAuthorizationStateLocked(request.Context()); err != nil {
				server.pendingMu.Unlock()
				writeProblem(response, http.StatusServiceUnavailable, "authorization_state_unavailable", err)
				return
			}
			id := pending.id
			federated := copyPendingFederation(pending.federated)
			authorizationContext := copyPersonAuthorizationContext(pending.context)
			decision := aauth.AuthorizationDecision{
				Subject: pending.decision.Subject,
				Scope:   append([]string(nil), pending.decision.Scope...),
			}
			server.pendingMu.Unlock()
			server.pollFederatedAuthorization(
				response,
				request.Context(),
				id,
				federated,
				authorizationContext,
				decision,
			)
			return
		}
		id := pending.id
		state := pending.state
		code := pending.code
		server.pendingMu.Unlock()
		if err := server.writePendingAuthorization(response, id, state, code); err != nil {
			writeProblem(response, http.StatusInternalServerError, "server_error", err)
		}
	case pendingAuthorizationApproved:
		if pending.terminalAuthToken != "" {
			token := pending.terminalAuthToken
			expiresAt := pending.terminalExpiresAt
			server.pendingMu.Unlock()
			writeJSON(response, http.StatusOK, map[string]any{
				"auth_token": token,
				"expires_in": expiresAt - server.clock.Now().Unix(),
			})
			return
		}
		authorizationContext := copyPersonAuthorizationContext(pending.context)
		decision := aauth.AuthorizationDecision{
			Subject: pending.decision.Subject,
			Scope:   append([]string(nil), pending.decision.Scope...),
		}
		server.pendingMu.Unlock()
		token, expiresAt, err := server.mintLocalAuthToken(authorizationContext, decision, pending.id)
		if err != nil {
			writeProblem(response, http.StatusInternalServerError, "server_error", err)
			return
		}
		server.pendingMu.Lock()
		current, exists := server.pending[pending.id]
		if !exists || current.state != pendingAuthorizationApproved {
			server.pendingMu.Unlock()
			writeProblem(response, http.StatusConflict, "authorization_changed", errors.New("pending authorization changed while token was minted"))
			return
		}
		if current.terminalAuthToken == "" {
			current.terminalAuthToken = token
			verificationKey := server.signingKey.PublicJWK()
			current.terminalVerificationKey = &verificationKey
			current.terminalExpiresAt = expiresAt
			if err := server.persistAuthorizationStateLocked(request.Context()); err != nil {
				server.pendingMu.Unlock()
				writeProblem(response, http.StatusServiceUnavailable, "authorization_state_unavailable", err)
				return
			}
		} else {
			token = current.terminalAuthToken
			expiresAt = current.terminalExpiresAt
		}
		server.pendingMu.Unlock()
		writeJSON(response, http.StatusOK, map[string]any{"auth_token": token, "expires_in": expiresAt - server.clock.Now().Unix()})
	case pendingAuthorizationExpired:
		server.pendingMu.Unlock()
		writeProblem(response, http.StatusRequestTimeout, "expired", errors.New("pending authorization expired"))
	case pendingAuthorizationRejected:
		code := pending.pollingError
		terminalStatus := pending.terminalStatus
		terminalCode := pending.terminalCode
		terminalDetail := pending.terminalDetail
		server.pendingMu.Unlock()
		if terminalStatus != 0 {
			writeProblem(response, terminalStatus, terminalCode, errors.New(terminalDetail))
			return
		}
		status := http.StatusForbidden
		if code == aauth.PollingServerError {
			status = http.StatusInternalServerError
		}
		writeProblem(response, status, string(code), errors.New("pending authorization was not approved"))
	case pendingAuthorizationInvalidCode:
		server.pendingMu.Unlock()
		writeProblem(response, http.StatusGone, "invalid_code", errors.New("interaction code validation failed"))
	default:
		server.pendingMu.Unlock()
		writeProblem(response, http.StatusGone, "gone", errors.New("pending authorization has an invalid state"))
	}
}

func copyPendingFederation(
	federated *pendingFederatedAuthorization,
) *pendingFederatedAuthorization {
	if federated == nil {
		return nil
	}
	copied := *federated
	copied.requirement = copyRequirement(federated.requirement)
	return &copied
}

func (server *PersonServer) handleAuthorizationInteraction(
	response http.ResponseWriter,
	request *http.Request,
) {
	server.pendingMu.Lock()
	stateErr := server.settleAuthorizationStateLocked(request.Context())
	server.pendingMu.Unlock()
	if stateErr != nil {
		writeProblem(response, http.StatusServiceUnavailable, "authorization_state_unavailable", stateErr)
		return
	}
	server.pendingMu.Lock()
	pending, exists := server.pending[request.PathValue("id")]
	if !exists {
		server.pendingMu.Unlock()
		writeProblem(response, http.StatusGone, "invalid_code", errors.New("pending interaction is unknown"))
		return
	}
	if pending.federated != nil {
		server.pendingMu.Unlock()
		writeProblem(response, http.StatusGone, "invalid_code", errors.New("interaction is hosted by the access server"))
		return
	}
	status, code, err := pending.correlate(
		request.URL.Query()["code"],
		server.clock.Now(),
	)
	if persistErr := server.persistAuthorizationStateLocked(request.Context()); persistErr != nil {
		server.pendingMu.Unlock()
		writeProblem(response, http.StatusServiceUnavailable, "authorization_state_unavailable", persistErr)
		return
	}
	if err != nil {
		server.pendingMu.Unlock()
		writeProblem(response, status, code, err)
		return
	}
	authorizationRequest := copyAuthorizationRequest(pending.context.request)
	server.pendingMu.Unlock()

	writeJSON(response, http.StatusOK, map[string]any{
		"status":   "interacting",
		"agent":    authorizationRequest.Agent,
		"resource": authorizationRequest.Resource,
		"scope":    strings.Join(authorizationRequest.Scope, " "),
	})
}

func (server *PersonServer) governanceReplayExists(key string) bool {
	server.mu.RLock()
	defer server.mu.RUnlock()
	_, exists := server.governanceReplays[key]
	return exists
}

func (server *PersonServer) addGovernanceReplayLocked(
	key string,
	expiresAt time.Time,
) {
	now := server.clock.Now()
	for existing, expiry := range server.governanceReplays {
		if !expiry.After(now) {
			delete(server.governanceReplays, existing)
		}
	}
	server.governanceReplays[key] = expiresAt
}

func copyGovernanceReplays(source map[string]time.Time) map[string]time.Time {
	copied := make(map[string]time.Time, len(source))
	for key, expiry := range source {
		copied[key] = expiry
	}
	return copied
}

func (server *PersonServer) seenReplay(key string, expiresAt time.Time, verifiedAt time.Time) bool {
	server.replayMu.Lock()
	defer server.replayMu.Unlock()
	for existing, expiry := range server.replayedProof {
		if expiry.Before(verifiedAt) {
			delete(server.replayedProof, existing)
		}
	}
	if _, exists := server.replayedProof[key]; exists {
		return true
	}
	server.replayedProof[key] = expiresAt
	return false
}

func validatePersonAuthorizationDecision(
	decision aauth.AuthorizationDecision,
	requestedScope []string,
) error {
	if decision.Subject == "" {
		return errors.New("authorization decision requires a subject")
	}
	return validateAuthorizationDecision(decision, requestedScope)
}

func (server *PersonServer) pollFederatedAuthorization(
	responseWriter http.ResponseWriter,
	ctx context.Context,
	pendingID string,
	federated *pendingFederatedAuthorization,
	authorizationContext personAuthorizationContext,
	personDecision aauth.AuthorizationDecision,
) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, federated.location, nil)
	if err != nil {
		server.retryFederatedAuthorization(responseWriter, pendingID, federated, 5*time.Second)
		return
	}
	request.Header.Set("Prefer", "wait=0")
	if err := server.signFederationRequest(request); err != nil {
		server.failFederatedAuthorization(responseWriter, pendingID, http.StatusInternalServerError, "server_error", err)
		return
	}
	response, err := server.federationClient.Do(request)
	if err != nil {
		server.retryFederatedAuthorization(responseWriter, pendingID, federated, 5*time.Second)
		return
	}
	defer response.Body.Close()

	switch response.StatusCode {
	case http.StatusOK:
		exchange, err := server.parseAccessServerGrant(
			ctx,
			response,
			federated.accessServer,
			authorizationContext.targetKey,
			authorizationContext.targetTokenExpiresAt,
			authorizationContext.resourceToken,
			personDecision,
		)
		if err != nil {
			server.failFederatedAuthorization(responseWriter, pendingID, http.StatusBadGateway, "federation_failed", err)
			return
		}
		if err := validateFederatedTerminalBinding(federated.location, exchange.claims); err != nil {
			server.failFederatedAuthorization(responseWriter, pendingID, http.StatusBadGateway, "federation_failed", err)
			return
		}
		retained, err := server.retainFederatedAuthorization(pendingID, exchange)
		if err != nil {
			writeProblem(responseWriter, http.StatusServiceUnavailable, "authorization_state_unavailable", err)
			return
		}
		if !retained {
			server.writeFederatedTransitionFailure(responseWriter, pendingID)
			return
		}
		writeJSON(responseWriter, http.StatusOK, map[string]any{
			"auth_token": exchange.authToken,
			"expires_in": exchange.claims.ExpiresAt - server.clock.Now().Unix(),
		})
	case http.StatusAccepted:
		deferred, err := aauth.ParseDeferredResponse(response)
		if err != nil {
			server.failFederatedAuthorization(responseWriter, pendingID, http.StatusBadGateway, "federation_failed", err)
			return
		}
		if endpoint, endpointErr := endpointIdentifier(deferred.Location); endpointErr != nil ||
			endpoint != federated.accessServer {
			server.failFederatedAuthorization(
				responseWriter,
				pendingID,
				http.StatusBadGateway,
				"federation_failed",
				errors.New("access-server pending continuation moved to another origin"),
			)
			return
		}
		continuationID, continuationErr := pendingIDFromLocation(deferred.Location)
		if continuationErr != nil || continuationID != pendingID {
			server.failFederatedAuthorization(
				responseWriter,
				pendingID,
				http.StatusBadGateway,
				"federation_failed",
				errors.New("access-server pending continuation changed its identifier"),
			)
			return
		}
		next := &pendingFederatedAuthorization{
			accessServer: federated.accessServer,
			location:     deferred.Location,
			retryAfter:   deferred.RetryAfter,
			notBefore:    server.clock.Now().Add(deferred.RetryAfter),
			status:       deferred.Status,
			requirement:  copyRequirement(deferred.Requirement),
		}
		updated, err := server.updateFederatedAuthorization(pendingID, next)
		if err != nil {
			writeProblem(responseWriter, http.StatusServiceUnavailable, "authorization_state_unavailable", err)
			return
		}
		if !updated {
			server.writeFederatedTransitionFailure(responseWriter, pendingID)
			return
		}
		if err := server.writeFederatedPendingAuthorization(
			responseWriter,
			pendingID,
			next,
			server.clock.Now(),
		); err != nil {
			server.failFederatedAuthorization(responseWriter, pendingID, http.StatusInternalServerError, "server_error", err)
		}
	case http.StatusTooManyRequests:
		delay := federated.retryAfter + 5*time.Second
		server.retryFederatedAuthorization(responseWriter, pendingID, federated, delay)
	case http.StatusInternalServerError, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		delay, err := responseRetryAfter(response.Header.Values("Retry-After"), server.clock.Now())
		if err != nil {
			delay = 5 * time.Second
		}
		server.retryFederatedAuthorization(responseWriter, pendingID, federated, delay)
	default:
		status := response.StatusCode
		code := "federation_failed"
		detail := errors.New("access server returned a terminal response")
		if status < http.StatusBadRequest {
			status = http.StatusBadGateway
		}
		if response.StatusCode == http.StatusUnauthorized {
			// The agent authenticated successfully to this person server.
			// A PS-to-AS authentication failure is an upstream federation
			// failure, not a new challenge to the agent.
			status = http.StatusBadGateway
		} else if strings.HasPrefix(
			strings.ToLower(response.Header.Get("Content-Type")),
			"application/problem+json",
		) {
			problem, decodeErr := aauth.DecodeProblemResponse(response)
			if decodeErr == nil {
				code = string(problem.Code)
				if problem.Detail != "" {
					detail = errors.New(problem.Detail)
				}
			} else {
				detail = decodeErr
			}
		}
		server.failFederatedAuthorization(responseWriter, pendingID, status, code, detail)
	}
}

func (server *PersonServer) retryFederatedAuthorization(
	response http.ResponseWriter,
	pendingID string,
	federated *pendingFederatedAuthorization,
	delay time.Duration,
) {
	next := copyPendingFederation(federated)
	next.retryAfter = delay
	next.notBefore = server.clock.Now().Add(delay)
	updated, err := server.updateFederatedAuthorization(pendingID, next)
	if err != nil {
		writeProblem(response, http.StatusServiceUnavailable, "authorization_state_unavailable", err)
		return
	}
	if !updated {
		server.writeFederatedTransitionFailure(response, pendingID)
		return
	}
	if err := server.writeFederatedPendingAuthorization(
		response,
		pendingID,
		next,
		server.clock.Now(),
	); err != nil {
		server.failFederatedAuthorization(response, pendingID, http.StatusInternalServerError, "server_error", err)
	}
}

func (server *PersonServer) updateFederatedAuthorization(
	pendingID string,
	federated *pendingFederatedAuthorization,
) (bool, error) {
	server.pendingMu.Lock()
	defer server.pendingMu.Unlock()
	pending, exists := server.pending[pendingID]
	if !exists || !pending.pollingFederation || pending.federated == nil ||
		(pending.state != pendingAuthorizationWaiting && pending.state != pendingAuthorizationInteracting) {
		return false, nil
	}
	if !pending.expiresAt.After(server.clock.Now()) {
		pending.pollingFederation = false
		pending.state = pendingAuthorizationExpired
		if err := server.persistAuthorizationStateLocked(context.Background()); err != nil {
			return false, err
		}
		return false, nil
	}
	pending.federated = copyPendingFederation(federated)
	pending.pollingFederation = false
	if federated.status == "interacting" {
		pending.state = pendingAuthorizationInteracting
	} else {
		pending.state = pendingAuthorizationWaiting
	}
	if err := server.persistAuthorizationStateLocked(context.Background()); err != nil {
		return false, err
	}
	return true, nil
}

func (server *PersonServer) retainFederatedAuthorization(
	pendingID string,
	exchange accessServerExchange,
) (bool, error) {
	server.pendingMu.Lock()
	defer server.pendingMu.Unlock()
	pending, exists := server.pending[pendingID]
	if !exists || !pending.pollingFederation || pending.federated == nil ||
		(pending.state != pendingAuthorizationWaiting && pending.state != pendingAuthorizationInteracting) {
		return false, nil
	}
	if !pending.expiresAt.After(server.clock.Now()) {
		pending.pollingFederation = false
		pending.state = pendingAuthorizationExpired
		if err := server.persistAuthorizationStateLocked(context.Background()); err != nil {
			return false, err
		}
		return false, nil
	}
	pending.pollingFederation = false
	pending.state = pendingAuthorizationApproved
	pending.terminalAuthToken = exchange.authToken
	pending.terminalVerificationKey = copyJWK(exchange.verificationKey)
	pending.terminalExpiresAt = exchange.claims.ExpiresAt
	if err := server.persistAuthorizationStateLocked(context.Background()); err != nil {
		return false, err
	}
	return true, nil
}

func validateFederatedTerminalBinding(location string, claims aauth.AuthTokenClaims) error {
	pendingID, err := pendingIDFromLocation(location)
	if err != nil || pendingID != claims.JTI {
		return errors.New("access-server auth-token jti does not match the retained pending continuation")
	}
	return nil
}

func pendingIDFromLocation(location string) (string, error) {
	parsed, err := url.Parse(location)
	if err != nil || parsed.RawPath != "" || !strings.HasPrefix(parsed.Path, "/pending/") {
		return "", errors.New("access-server pending continuation has an invalid path")
	}
	pendingID := strings.TrimPrefix(parsed.Path, "/pending/")
	if strings.Contains(pendingID, "/") || !validPendingID(pendingID) {
		return "", errors.New("access-server pending continuation has an invalid identifier")
	}
	return pendingID, nil
}

func (server *PersonServer) writeFederatedTransitionFailure(
	response http.ResponseWriter,
	pendingID string,
) {
	server.pendingMu.Lock()
	pending, exists := server.pending[pendingID]
	if exists && pending.state == pendingAuthorizationExpired {
		server.pendingMu.Unlock()
		writeProblem(response, http.StatusRequestTimeout, "expired", errors.New("pending authorization expired"))
		return
	}
	server.pendingMu.Unlock()
	writeProblem(response, http.StatusGone, "gone", errors.New("pending authorization changed during federation"))
}

func (server *PersonServer) failFederatedAuthorization(
	response http.ResponseWriter,
	pendingID string,
	status int,
	code string,
	err error,
) {
	server.pendingMu.Lock()
	pending, exists := server.pending[pendingID]
	if !exists || !pending.pollingFederation || pending.federated == nil ||
		(pending.state != pendingAuthorizationWaiting && pending.state != pendingAuthorizationInteracting) {
		server.pendingMu.Unlock()
		server.writeFederatedTransitionFailure(response, pendingID)
		return
	}
	if !pending.expiresAt.After(server.clock.Now()) {
		pending.pollingFederation = false
		pending.state = pendingAuthorizationExpired
		persistErr := server.persistAuthorizationStateLocked(context.Background())
		server.pendingMu.Unlock()
		if persistErr != nil {
			writeProblem(response, http.StatusServiceUnavailable, "authorization_state_unavailable", persistErr)
			return
		}
		server.writeFederatedTransitionFailure(response, pendingID)
		return
	}
	pending.pollingFederation = false
	pending.state = pendingAuthorizationRejected
	pending.terminalStatus = status
	pending.terminalCode = code
	pending.terminalDetail = err.Error()
	persistErr := server.persistAuthorizationStateLocked(context.Background())
	server.pendingMu.Unlock()
	if persistErr != nil {
		writeProblem(response, http.StatusServiceUnavailable, "authorization_state_unavailable", persistErr)
		return
	}
	writeProblem(response, status, code, err)
}

func (server *PersonServer) exchangeWithAccessServer(
	ctx context.Context,
	accessServerIdentifier string,
	resourceTokenCompact string,
	agentTokenCompact string,
	subagentTokenCompact string,
	upstreamTokenCompact string,
	targetKey jose.JWK,
	targetTokenExpiresAt int64,
	resourceToken aauth.ResourceTokenClaims,
	personDecision aauth.AuthorizationDecision,
) (accessServerExchange, error) {
	var exchange accessServerExchange
	endpoint, err := server.accessServerEndpoint(ctx, accessServerIdentifier)
	if err != nil {
		return exchange, fmt.Errorf("resolve access-server endpoint: %w", err)
	}
	if err := aauth.ValidateEndpoint(endpoint); err != nil {
		return exchange, err
	}
	endpointIssuer, err := endpointIdentifier(endpoint)
	if err != nil {
		return exchange, err
	}
	if endpointIssuer != accessServerIdentifier {
		return exchange, errors.New("access-server endpoint origin does not match resource-token audience")
	}
	input := map[string]string{
		"resource_token": resourceTokenCompact,
		"agent_token":    agentTokenCompact,
	}
	if subagentTokenCompact != "" {
		input["subagent_token"] = subagentTokenCompact
	}
	if upstreamTokenCompact != "" {
		input["upstream_token"] = upstreamTokenCompact
	}
	body, err := json.Marshal(input)
	if err != nil {
		return exchange, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return exchange, err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Prefer", "wait=0")
	if err := server.signFederationRequest(request); err != nil {
		return exchange, err
	}
	response, err := server.federationClient.Do(request)
	if err != nil {
		return exchange, err
	}
	defer response.Body.Close()
	switch response.StatusCode {
	case http.StatusAccepted:
		deferred, err := aauth.ParseDeferredResponse(response)
		if err != nil {
			return exchange, err
		}
		exchange.deferred = &deferred
		return exchange, nil
	case http.StatusOK:
		return server.parseAccessServerGrant(
			ctx,
			response,
			accessServerIdentifier,
			targetKey,
			targetTokenExpiresAt,
			resourceToken,
			personDecision,
		)
	default:
		body, _ := io.ReadAll(io.LimitReader(response.Body, 8<<10))
		return exchange, fmt.Errorf("access server returned %s: %s", response.Status, strings.TrimSpace(string(body)))
	}
}

func (server *PersonServer) parseAccessServerGrant(
	ctx context.Context,
	response *http.Response,
	accessServerIdentifier string,
	targetKey jose.JWK,
	targetTokenExpiresAt int64,
	resourceToken aauth.ResourceTokenClaims,
	personDecision aauth.AuthorizationDecision,
) (accessServerExchange, error) {
	var exchange accessServerExchange
	var result struct {
		AuthToken string `json:"auth_token"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, maxJSONBody)).Decode(&result); err != nil {
		return exchange, err
	}
	capturedResolver := &retainedKeyResolver{resolver: server.keyResolver}
	var verificationResolver signaturekey.KeyResolver = capturedResolver
	if refresher, ok := server.keyResolver.(signaturekey.KeyRefresher); ok {
		verificationResolver = &retainedRefreshingKeyResolver{
			retainedKeyResolver: capturedResolver,
			refresher:           refresher,
		}
	}
	evidence, err := aauth.VerifyAuthToken(ctx, result.AuthToken, verificationResolver, server.clock)
	if err != nil {
		return exchange, err
	}
	claims, err := evidence.Claims()
	if err != nil {
		return exchange, err
	}
	if claims.Issuer != accessServerIdentifier || claims.DWK != aauth.AccessDiscoveryDocument {
		return exchange, errors.New("access-server auth token has the wrong issuer or discovery document")
	}
	if claims.ExpiresAt > resourceToken.ExpiresAt {
		return exchange, errors.New("access-server auth token outlives the resource token")
	}
	if claims.ExpiresAt > targetTokenExpiresAt {
		return exchange, errors.New("access-server auth token outlives the target agent credentials")
	}
	if err := aauth.ValidateCurrentAuthTokenContext(
		claims,
		resourceToken.Issuer,
		resourceToken.PersonServer,
		resourceToken.Subject,
		targetKey,
		nil,
	); err != nil {
		return exchange, err
	}
	if claims.MissionS256 != resourceToken.MissionS256 ||
		claims.Tenant != resourceToken.Tenant ||
		claims.Account != resourceToken.Account ||
		claims.Agent != "" || claims.Actor != nil {
		return exchange, errors.New("access-server auth token changed the retained person context")
	}
	grantedScopes, err := parseScopes(claims.Scope)
	if err != nil {
		return exchange, err
	}
	if !scopesContained(grantedScopes, personDecision.Scope) {
		return exchange, errors.New("access-server auth token exceeds the person-server grant")
	}
	if !capturedResolver.found {
		return exchange, errors.New("access-server auth token verification key was not retained")
	}
	retainedClaims, err := verifyRetainedAuthToken(result.AuthToken, capturedResolver.key)
	if err != nil || !reflect.DeepEqual(retainedClaims, claims) {
		return exchange, errors.New("access-server auth token cannot be verified from retained key material")
	}
	exchange.authToken = result.AuthToken
	exchange.claims = claims
	verificationKey := capturedResolver.key
	exchange.verificationKey = &verificationKey
	return exchange, nil
}

func (server *PersonServer) handleMetadata(response http.ResponseWriter, _ *http.Request) {
	metadata := map[string]any{
		"issuer":              server.identifier,
		"jwks_uri":            server.identifier + "/jwks",
		"mission_endpoint":    server.identifier + "/mission",
		"auth_token_endpoint": server.identifier + "/token",
		"audit_endpoint":      server.identifier + "/audit",
	}
	metadata["person_token_endpoint"] = server.identifier + "/person"
	if server.permissionPolicy != nil {
		metadata["permission_endpoint"] = server.identifier + "/permission"
	}
	if server.completionReviewEnabled {
		metadata["interaction_endpoint"] = server.identifier + "/interaction"
	}
	writeJSON(response, http.StatusOK, metadata)
}

func (server *PersonServer) handleJWKS(response http.ResponseWriter, _ *http.Request) {
	writeJSON(response, http.StatusOK, map[string]any{
		"keys": []jose.JWK{server.signingKey.PublicJWK()},
	})
}
