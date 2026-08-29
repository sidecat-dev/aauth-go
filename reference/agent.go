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
	"path"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"gitlab.com/sidecat-dev/aauth-go/budgets"
	"gitlab.com/sidecat-dev/aauth-go/events"
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/r3"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"

	aauth "gitlab.com/sidecat-dev/aauth-go"
)

type AgentConfig struct {
	Identifier         string
	SigningKey         jose.SigningKey
	AgentToken         string
	KeyResolver        signaturekey.KeyResolver
	HTTPClient         *http.Client
	Clock              aauth.Clock
	AuthorizationStore AuthorizationStateStore
	Events             *AgentEventsConfig
}

// AgentEventsConfig supplies replaceable local custody and action execution
// for the Events profile.
type AgentEventsConfig struct {
	Store  AgentEventStore
	Action EventAction
}

type Agent struct {
	identifier            string
	signingKey            jose.SigningKey
	agentToken            string
	keyResolver           signaturekey.KeyResolver
	httpClient            *http.Client
	clock                 aauth.Clock
	authorizationStore    AuthorizationStateStore
	authorizationMu       sync.Mutex
	authorizationErr      error
	authorizationBody     []byte
	authorizationRecovery []byte
	pendingTokens         map[string]agentPendingTokenRecord
	pendingAccess         map[string]agentPendingAccessRecord
	pendingPersons        map[string]agentPendingPersonRecord
	personMu              sync.Mutex
	personGrants          map[string]PersonGrant
	authMu                sync.Mutex
	authGrants            map[string]Grant
	eventStore            AgentEventStore
	eventAction           EventAction
	eventMu               sync.Mutex
}

func (agent *Agent) signRequest(request *http.Request, credential string) error {
	nonceBytes := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, nonceBytes); err != nil {
		return fmt.Errorf("reference: generate request proof nonce: %w", err)
	}
	return signaturekey.SignJWTRequestWithOptions(request, agent.signingKey, credential, agent.clock, signaturekey.SignOptions{
		Nonce: base64.RawURLEncoding.EncodeToString(nonceBytes),
	})
}

type Grant struct {
	Resource  string
	AuthToken string
	Claims    aauth.AuthTokenClaims
	R3        *r3.TokenResult
	Budget    *budgets.TokenResult
}

// PersonGrant is one verified resource-directed person token obtained from a
// person server. Claims are retained beside the compact token so later client
// checks do not have to trust caller-reconstructed context.
type PersonGrant struct {
	Resource    string
	PersonToken string
	Claims      aauth.PersonTokenClaims
}

// PersonTokenAuthorization is either an immediate resource-directed person
// token or a signed-poll continuation owned by the requesting agent.
type PersonTokenAuthorization struct {
	Grant   *PersonGrant
	Pending *PendingPersonTokenAuthorization
}

// PendingPersonTokenAuthorization carries the public continuation state for a
// deferred person-token request. Private request bindings are retained by the
// agent authorization store.
type PendingPersonTokenAuthorization struct {
	ID           string
	PersonServer string
	Resource     string
	Location     string
	RetryAfter   time.Duration
	NotBefore    time.Time
	Status       string
	Requirement  *aauth.Requirement
	missionS256  string
	expectedKey  jose.JWK
}

// AuthorizedCall is the exact HTTP call an agent signs under an auth-token
// grant. Body is copied into the request; non-empty bodies require an explicit
// media type so content-type participates in the signed request semantics.
type AuthorizedCall struct {
	Method      string
	Endpoint    string
	Body        []byte
	ContentType string
}

type ResourceGrant struct {
	Resource      string                    `json:"resource"`
	ResourceToken string                    `json:"resource_token"`
	Claims        aauth.ResourceTokenClaims `json:"claims"`
	RequestedR3   *r3.OperationSet          `json:"requested_r3,omitempty"`
	Budget        *budgets.TokenResult      `json:"-"`
}

// TokenAuthorization is either an auth-token grant or a signed-poll
// continuation at a person server.
type TokenAuthorization struct {
	Grant   *Grant
	Pending *PendingTokenAuthorization
}

// PendingTokenAuthorization retains the validation context needed to verify a
// person server's eventual auth-token response.
type PendingTokenAuthorization struct {
	ID           string
	PersonServer string
	Location     string
	RetryAfter   time.Duration
	NotBefore    time.Time
	Status       string
	Requirement  *aauth.Requirement

	resourceGrant           ResourceGrant
	resourceVerificationKey jose.JWK
	expectedIssuer          string
	expectedKey             jose.JWK
}

// AccessGrant is a resource-managed authorization result. Token is opaque to
// the agent and is only presented back to Resource with a signed request.
type AccessGrant struct {
	Resource string
	Token    string
	Scope    []string
}

// AccessAuthorization is either a usable grant or a pending continuation.
type AccessAuthorization struct {
	Grant   *AccessGrant
	Pending *PendingAccessAuthorization
}

// PendingAccessAuthorization carries the same-origin signed-poll continuation
// for a resource-managed authorization.
type PendingAccessAuthorization struct {
	ID             string
	Resource       string
	Location       string
	RetryAfter     time.Duration
	NotBefore      time.Time
	Status         string
	Requirement    *aauth.Requirement
	requestedScope []string
}

const agentAuthorizationStateSchema = "aauth.reference.agent-authorization-state"

type agentAuthorizationStateRecord struct {
	Kind   string                    `json:"kind"`
	Key    string                    `json:"key"`
	Token  *agentPendingTokenRecord  `json:"token,omitempty"`
	Access *agentPendingAccessRecord `json:"access,omitempty"`
	Person *agentPendingPersonRecord `json:"person,omitempty"`
}

type agentPendingTokenRecord struct {
	ID                      string             `json:"id"`
	PersonServer            string             `json:"person_server"`
	Location                string             `json:"location"`
	RetryAfter              time.Duration      `json:"retry_after"`
	NotBefore               time.Time          `json:"not_before"`
	Status                  string             `json:"status"`
	Requirement             *aauth.Requirement `json:"requirement,omitempty"`
	ResourceGrant           ResourceGrant      `json:"resource_grant"`
	ResourceVerificationKey jose.JWK           `json:"resource_verification_key"`
	ExpectedIssuer          string             `json:"expected_issuer"`
	ExpectedKey             jose.JWK           `json:"expected_key"`
	TerminalGrant           *Grant             `json:"terminal_grant,omitempty"`
	TerminalVerificationKey *jose.JWK          `json:"terminal_verification_key,omitempty"`
}

type agentPendingAccessRecord struct {
	ID             string             `json:"id"`
	Resource       string             `json:"resource"`
	Location       string             `json:"location"`
	RetryAfter     time.Duration      `json:"retry_after"`
	NotBefore      time.Time          `json:"not_before"`
	Status         string             `json:"status"`
	Requirement    *aauth.Requirement `json:"requirement,omitempty"`
	RequestedScope []string           `json:"requested_scope"`
	TerminalGrant  *AccessGrant       `json:"terminal_grant,omitempty"`
}

// PermissionAuthorization is either a terminal permission decision or a
// signed-poll continuation at the person server.
type PermissionAuthorization struct {
	Decision *aauth.PermissionResponse
	Pending  *PendingPermissionAuthorization
}

// PendingPermissionAuthorization retains a same-origin permission continuation.
type PendingPermissionAuthorization struct {
	ID           string
	PersonServer string
	Location     string
	RetryAfter   time.Duration
	NotBefore    time.Time
	Status       string
	Requirement  *aauth.Requirement
}

// InteractionAuthorization is either a terminal person-server interaction
// result or a signed-poll continuation.
type InteractionAuthorization struct {
	Completed bool
	Status    string
	Answer    string
	Pending   *PendingInteractionAuthorization
}

// PendingInteractionAuthorization retains an ownership-bound person-server
// interaction continuation, including any clarification the agent must answer.
type PendingInteractionAuthorization struct {
	ID            string
	Type          aauth.InteractionType
	PersonServer  string
	Location      string
	RetryAfter    time.Duration
	NotBefore     time.Time
	Status        string
	Requirement   *aauth.Requirement
	Clarification string
	Timeout       time.Duration
	Options       []string
}

func NewAgent(config AgentConfig) (*Agent, error) {
	if err := aauth.ValidateAgentIdentifier(config.Identifier); err != nil {
		return nil, err
	}
	if config.SigningKey.ID() == "" || config.AgentToken == "" || config.KeyResolver == nil ||
		config.HTTPClient == nil || config.Clock == nil || config.AuthorizationStore == nil {
		return nil, errors.New("reference: agent requires key, token, resolver, HTTP client, clock, and authorization state store")
	}
	var eventStore AgentEventStore
	var eventAction EventAction
	if config.Events != nil {
		if config.Events.Store == nil || config.Events.Action == nil {
			return nil, errors.New("reference: agent Events requires store and action")
		}
		eventStore = config.Events.Store
		eventAction = config.Events.Action
	}
	agent := &Agent{
		identifier:         config.Identifier,
		signingKey:         config.SigningKey,
		agentToken:         config.AgentToken,
		keyResolver:        config.KeyResolver,
		httpClient:         config.HTTPClient,
		clock:              config.Clock,
		authorizationStore: config.AuthorizationStore,
		pendingTokens:      make(map[string]agentPendingTokenRecord),
		pendingAccess:      make(map[string]agentPendingAccessRecord),
		pendingPersons:     make(map[string]agentPendingPersonRecord),
		personGrants:       make(map[string]PersonGrant),
		authGrants:         make(map[string]Grant),
		eventStore:         eventStore,
		eventAction:        eventAction,
	}
	if err := agent.loadAuthorizationState(context.Background()); err != nil {
		return nil, fmt.Errorf("reference: load agent authorization state: %w", err)
	}
	return agent, nil
}

func (agent *Agent) loadAuthorizationState(ctx context.Context) error {
	body, err := agent.authorizationStore.Load(ctx)
	if err != nil {
		return err
	}
	if len(body) == 0 {
		agent.authorizationMu.Lock()
		defer agent.authorizationMu.Unlock()
		return agent.persistAuthorizationStateLocked(ctx)
	}
	if err := agent.restoreAuthorizationStateLocked(body); err != nil {
		return err
	}
	agent.authorizationBody = append([]byte(nil), body...)
	return nil
}

func (agent *Agent) restoreAuthorizationStateLocked(body []byte) error {
	rawRecords, err := decodeAuthorizationStateRecords(body, agentAuthorizationStateSchema)
	if err != nil {
		return err
	}
	pendingTokens := make(map[string]agentPendingTokenRecord)
	pendingAccess := make(map[string]agentPendingAccessRecord)
	pendingPersons := make(map[string]agentPendingPersonRecord)
	terminalTokenIDs := make(map[string]struct{})
	terminalAccessTokens := make(map[string]struct{})
	previous := ""
	for _, raw := range rawRecords {
		var record agentAuthorizationStateRecord
		if err := decodeAuthorizationStateRecord(raw, &record); err != nil {
			return err
		}
		sortKey := record.Kind + "\x00" + record.Key
		if record.Key == "" || sortKey <= previous {
			return ErrAuthorizationStateIntegrity
		}
		previous = sortKey
		switch record.Kind {
		case "access":
			if record.Access == nil || record.Token != nil || record.Person != nil || record.Access.ID != record.Key ||
				validateAgentPendingAccessRecord(*record.Access) != nil {
				return ErrAuthorizationStateIntegrity
			}
			if record.Access.TerminalGrant != nil {
				if _, duplicate := terminalAccessTokens[record.Access.TerminalGrant.Token]; duplicate {
					return ErrAuthorizationStateIntegrity
				}
				terminalAccessTokens[record.Access.TerminalGrant.Token] = struct{}{}
			}
			pendingAccess[record.Key] = cloneAgentPendingAccessRecord(*record.Access)
		case "token":
			if record.Token == nil || record.Access != nil || record.Person != nil || record.Token.ID != record.Key ||
				validateAgentPendingTokenRecord(*record.Token) != nil {
				return ErrAuthorizationStateIntegrity
			}
			if record.Token.TerminalGrant != nil {
				terminalID := record.Token.TerminalGrant.Claims.Issuer + "\x00" + record.Token.TerminalGrant.Claims.JTI
				if _, duplicate := terminalTokenIDs[terminalID]; duplicate {
					return ErrAuthorizationStateIntegrity
				}
				terminalTokenIDs[terminalID] = struct{}{}
			}
			pendingTokens[record.Key] = cloneAgentPendingTokenRecord(*record.Token)
		case "person":
			if record.Person == nil || record.Token != nil || record.Access != nil || record.Person.ID != record.Key ||
				validateAgentPendingPersonRecord(*record.Person) != nil {
				return ErrAuthorizationStateIntegrity
			}
			pendingPersons[record.Key] = cloneAgentPendingPersonRecord(*record.Person)
		default:
			return ErrAuthorizationStateIntegrity
		}
	}
	agent.pendingTokens = pendingTokens
	agent.pendingAccess = pendingAccess
	agent.pendingPersons = pendingPersons
	return nil
}

func validateAgentPendingAccessRecord(record agentPendingAccessRecord) error {
	if record.ID == "" || record.Resource == "" || record.Location == "" || record.NotBefore.IsZero() ||
		record.RetryAfter < 0 || (record.Status != "pending" && record.Status != "interacting") {
		return ErrAuthorizationStateIntegrity
	}
	if err := aauth.ValidateServerIdentifier(record.Resource); err != nil {
		return ErrAuthorizationStateIntegrity
	}
	if err := aauth.ValidatePollingEndpoint(record.Location); err != nil {
		return ErrAuthorizationStateIntegrity
	}
	resource, err := endpointIdentifier(record.Location)
	if err != nil || resource != record.Resource || path.Base(mustParseURLPath(record.Location)) != record.ID {
		return ErrAuthorizationStateIntegrity
	}
	if len(record.RequestedScope) != 0 {
		if scopes, err := parseScopes(strings.Join(record.RequestedScope, " ")); err != nil || len(scopes) != len(record.RequestedScope) {
			return ErrAuthorizationStateIntegrity
		}
	}
	if record.TerminalGrant != nil {
		if aauth.ValidateAccessToken(record.TerminalGrant.Token) != nil ||
			record.TerminalGrant.Resource != record.Resource {
			return ErrAuthorizationStateIntegrity
		}
		granted, err := parseScopes(strings.Join(record.TerminalGrant.Scope, " "))
		if err != nil || len(granted) != len(record.TerminalGrant.Scope) ||
			len(record.RequestedScope) != 0 && !scopesContained(granted, record.RequestedScope) {
			return ErrAuthorizationStateIntegrity
		}
	}
	return nil
}

func validateAgentPendingTokenRecord(record agentPendingTokenRecord) error {
	if record.ID == "" || record.PersonServer == "" || record.Location == "" || record.NotBefore.IsZero() ||
		record.RetryAfter < 0 || (record.Status != "pending" && record.Status != "interacting") ||
		record.ExpectedIssuer == "" {
		return ErrAuthorizationStateIntegrity
	}
	if err := aauth.ValidateServerIdentifier(record.PersonServer); err != nil {
		return ErrAuthorizationStateIntegrity
	}
	if err := aauth.ValidatePollingEndpoint(record.Location); err != nil {
		return ErrAuthorizationStateIntegrity
	}
	server, err := endpointIdentifier(record.Location)
	if err != nil || server != record.PersonServer || path.Base(mustParseURLPath(record.Location)) != record.ID {
		return ErrAuthorizationStateIntegrity
	}
	if _, err := record.ExpectedKey.PublicKey(); err != nil {
		return ErrAuthorizationStateIntegrity
	}
	if err := validateAgentRetainedResourceGrant(record); err != nil {
		return ErrAuthorizationStateIntegrity
	}
	if (record.TerminalGrant == nil) != (record.TerminalVerificationKey == nil) {
		return ErrAuthorizationStateIntegrity
	}
	if record.TerminalGrant != nil && validateAgentRetainedTerminalGrant(record) != nil {
		return ErrAuthorizationStateIntegrity
	}
	return nil
}

func validateAgentRetainedResourceGrant(record agentPendingTokenRecord) error {
	grant := record.ResourceGrant
	if aauth.ValidateServerIdentifier(grant.Resource) != nil || grant.ResourceToken == "" ||
		grant.Claims.Issuer != grant.Resource || grant.Claims.PersonServer != record.PersonServer ||
		grant.Claims.Audience != record.ExpectedIssuer || grant.Claims.Agent != "" || grant.Claims.Subject == "" {
		return ErrAuthorizationStateIntegrity
	}
	verified, err := verifyRetainedResourceToken(grant.ResourceToken, record.ResourceVerificationKey)
	if err != nil || !reflect.DeepEqual(verified, grant.Claims) {
		return ErrAuthorizationStateIntegrity
	}
	thumbprint, err := record.ExpectedKey.Thumbprint()
	if err != nil || grant.Claims.AgentJKT != thumbprint {
		return ErrAuthorizationStateIntegrity
	}
	return nil
}

func validateAgentRetainedTerminalGrant(record agentPendingTokenRecord) error {
	grant := record.TerminalGrant
	if grant == nil || record.TerminalVerificationKey == nil || grant.AuthToken == "" ||
		grant.Resource != record.ResourceGrant.Resource {
		return ErrAuthorizationStateIntegrity
	}
	claims, err := verifyRetainedAuthToken(grant.AuthToken, *record.TerminalVerificationKey)
	if err != nil || !reflect.DeepEqual(claims, grant.Claims) || claims.JTI != record.ID {
		return ErrAuthorizationStateIntegrity
	}
	resourceClaims := record.ResourceGrant.Claims
	if claims.Issuer != record.ExpectedIssuer || claims.ExpiresAt > resourceClaims.ExpiresAt ||
		claims.IssuedAt < resourceClaims.IssuedAt {
		return ErrAuthorizationStateIntegrity
	}
	expectedDiscoveryDocument := aauth.AccessDiscoveryDocument
	if record.ExpectedIssuer == resourceClaims.PersonServer {
		expectedDiscoveryDocument = aauth.PersonDiscoveryDocument
	}
	if claims.DWK != expectedDiscoveryDocument || claims.PersonServer != resourceClaims.PersonServer ||
		claims.Subject != resourceClaims.Subject || claims.MissionS256 != resourceClaims.MissionS256 ||
		claims.Tenant != resourceClaims.Tenant || claims.Account != resourceClaims.Account ||
		claims.Agent != "" || claims.Actor != nil {
		return ErrAuthorizationStateIntegrity
	}
	requiredScopes, err := parseScopes(resourceClaims.Scope)
	if err != nil || aauth.ValidateCurrentAuthTokenContext(
		claims,
		record.ResourceGrant.Resource,
		resourceClaims.PersonServer,
		resourceClaims.Subject,
		record.ExpectedKey,
		requiredScopes,
	) != nil {
		return ErrAuthorizationStateIntegrity
	}
	return nil
}

func mustParseURLPath(endpoint string) string {
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return ""
	}
	return parsed.Path
}

func (agent *Agent) persistAuthorizationStateLocked(ctx context.Context) error {
	if agent.authorizationErr != nil {
		return agent.authorizationErr
	}
	if err := agent.settleAuthorizationStateLocked(ctx); err != nil {
		return err
	}
	records := make([]agentAuthorizationStateRecord, 0, len(agent.pendingTokens)+len(agent.pendingAccess)+len(agent.pendingPersons))
	terminalTokenIDs := make(map[string]struct{})
	terminalAccessTokens := make(map[string]struct{})
	for key, pending := range agent.pendingTokens {
		if pending.ID != key || validateAgentPendingTokenRecord(pending) != nil {
			return ErrAuthorizationStateIntegrity
		}
		if pending.TerminalGrant != nil {
			terminalID := pending.TerminalGrant.Claims.Issuer + "\x00" + pending.TerminalGrant.Claims.JTI
			if _, duplicate := terminalTokenIDs[terminalID]; duplicate {
				return ErrAuthorizationStateIntegrity
			}
			terminalTokenIDs[terminalID] = struct{}{}
		}
		copied := cloneAgentPendingTokenRecord(pending)
		records = append(records, agentAuthorizationStateRecord{Kind: "token", Key: key, Token: &copied})
	}
	for key, pending := range agent.pendingAccess {
		if pending.ID != key || validateAgentPendingAccessRecord(pending) != nil {
			return ErrAuthorizationStateIntegrity
		}
		if pending.TerminalGrant != nil {
			if _, duplicate := terminalAccessTokens[pending.TerminalGrant.Token]; duplicate {
				return ErrAuthorizationStateIntegrity
			}
			terminalAccessTokens[pending.TerminalGrant.Token] = struct{}{}
		}
		copied := cloneAgentPendingAccessRecord(pending)
		records = append(records, agentAuthorizationStateRecord{Kind: "access", Key: key, Access: &copied})
	}
	for key, pending := range agent.pendingPersons {
		if pending.ID != key || validateAgentPendingPersonRecord(pending) != nil {
			return ErrAuthorizationStateIntegrity
		}
		copied := cloneAgentPendingPersonRecord(pending)
		records = append(records, agentAuthorizationStateRecord{Kind: "person", Key: key, Person: &copied})
	}
	sort.Slice(records, func(i, j int) bool {
		return records[i].Kind+"\x00"+records[i].Key < records[j].Kind+"\x00"+records[j].Key
	})
	raw := make([]json.RawMessage, 0, len(records))
	for _, record := range records {
		encoded, err := json.Marshal(record)
		if err != nil {
			return agent.reconcileAuthorizationStateLocked(ctx, nil, err)
		}
		raw = append(raw, encoded)
	}
	body, err := marshalAuthorizationStateRecords(agentAuthorizationStateSchema, raw)
	if err != nil {
		return agent.reconcileAuthorizationStateLocked(ctx, nil, err)
	}
	if err := agent.authorizationStore.Replace(ctx, body); err != nil {
		return agent.reconcileAuthorizationStateLocked(ctx, body, err)
	}
	agent.authorizationBody = append(agent.authorizationBody[:0], body...)
	return nil
}

func (agent *Agent) reconcileAuthorizationStateLocked(ctx context.Context, candidate []byte, commitErr error) error {
	body, published, err := reconcileAuthorizationState(ctx, agent.authorizationStore, agent.authorizationBody, candidate)
	if err != nil || len(body) == 0 {
		agent.pendingTokens = make(map[string]agentPendingTokenRecord)
		agent.pendingAccess = make(map[string]agentPendingAccessRecord)
		agent.pendingPersons = make(map[string]agentPendingPersonRecord)
		agent.authorizationErr = authorizationStateReconciliationFailure(commitErr, err)
		return agent.authorizationErr
	}
	if err := agent.restoreAuthorizationStateLocked(body); err != nil {
		agent.pendingTokens = make(map[string]agentPendingTokenRecord)
		agent.pendingAccess = make(map[string]agentPendingAccessRecord)
		agent.pendingPersons = make(map[string]agentPendingPersonRecord)
		agent.authorizationErr = authorizationStateReconciliationFailure(commitErr, err)
		return agent.authorizationErr
	}
	if published {
		agent.authorizationRecovery = append(agent.authorizationRecovery[:0], body...)
		return authorizationStatePublishedUncertain(commitErr)
	}
	agent.authorizationBody = append(agent.authorizationBody[:0], body...)
	return commitErr
}

func (agent *Agent) settleAuthorizationStateLocked(ctx context.Context) error {
	if agent.authorizationErr != nil {
		return agent.authorizationErr
	}
	if len(agent.authorizationRecovery) == 0 {
		return nil
	}
	candidate := append([]byte(nil), agent.authorizationRecovery...)
	if err := agent.authorizationStore.Replace(ctx, candidate); err != nil {
		body, published, reconcileErr := reconcileAuthorizationState(ctx, agent.authorizationStore, nil, candidate)
		if reconcileErr == nil && published {
			reconcileErr = agent.restoreAuthorizationStateLocked(body)
		}
		if reconcileErr != nil || !published {
			agent.pendingTokens = make(map[string]agentPendingTokenRecord)
			agent.pendingAccess = make(map[string]agentPendingAccessRecord)
			agent.pendingPersons = make(map[string]agentPendingPersonRecord)
			agent.authorizationErr = authorizationStateReconciliationFailure(err, reconcileErr)
			return agent.authorizationErr
		}
		return authorizationStatePublishedUncertain(err)
	}
	agent.authorizationBody = append(agent.authorizationBody[:0], candidate...)
	agent.authorizationRecovery = nil
	return nil
}

func (agent *Agent) ensureAuthorizationState(ctx context.Context) error {
	agent.authorizationMu.Lock()
	defer agent.authorizationMu.Unlock()
	return agent.settleAuthorizationStateLocked(ctx)
}

func cloneAgentPendingTokenRecord(value agentPendingTokenRecord) agentPendingTokenRecord {
	value.Requirement = copyRequirement(value.Requirement)
	value.TerminalVerificationKey = copyJWK(value.TerminalVerificationKey)
	if value.TerminalGrant != nil {
		grant := *value.TerminalGrant
		value.TerminalGrant = &grant
	}
	return value
}

func cloneAgentPendingAccessRecord(value agentPendingAccessRecord) agentPendingAccessRecord {
	value.Requirement = copyRequirement(value.Requirement)
	value.RequestedScope = append([]string(nil), value.RequestedScope...)
	if value.TerminalGrant != nil {
		grant := *value.TerminalGrant
		grant.Scope = append([]string(nil), value.TerminalGrant.Scope...)
		value.TerminalGrant = &grant
	}
	return value
}

// RegisterPublicEventSubscription retains the local continuation context
// before signing and sending the public subscription request.
func (agent *Agent) RegisterPublicEventSubscription(
	ctx context.Context,
	endpoint string,
	compact string,
	localContext AgentEventContext,
) error {
	return agent.registerEventSubscription(ctx, endpoint, compact, localContext)
}

// RegisterProtectedEventSubscription pins the ticket's exact AsyncAPI
// selection into local agent custody before spending the single-use URL.
func (agent *Agent) RegisterProtectedEventSubscription(
	ctx context.Context,
	grant ProtectedEventTicketGrant,
	compact string,
	localContext AgentEventContext,
) error {
	if grant.URL == "" || grant.ContractDigest == "" || grant.OperationID == "" || grant.MessageID == "" {
		return errors.New("reference: protected event ticket grant is incomplete")
	}
	if localContext.ContractDigest != grant.ContractDigest ||
		localContext.OperationID != grant.OperationID || localContext.MessageID != grant.MessageID {
		return errors.New("reference: protected event context does not match the ticket grant")
	}
	if err := validateAgentEventContext(localContext); err != nil {
		return err
	}
	return agent.registerEventSubscription(ctx, grant.URL, compact, localContext)
}

func (agent *Agent) registerEventSubscription(
	ctx context.Context,
	endpoint string,
	compact string,
	localContext AgentEventContext,
) error {
	if agent == nil || agent.eventStore == nil {
		return errors.New("reference: agent Events is not configured")
	}
	if err := aauth.ValidateEndpoint(endpoint); err != nil {
		return err
	}
	resourceIdentifier, err := endpointIdentifier(endpoint)
	if err != nil {
		return err
	}
	claims, err := aauth.VerifySubscribeToken(ctx, compact, agent.keyResolver, agent.clock)
	if err != nil {
		return err
	}
	if claims.Subject != agent.identifier {
		return errors.New("reference: event subscription agent does not match this agent")
	}
	if claims.Audience != resourceIdentifier {
		return errors.New("reference: event subscription resource does not match endpoint")
	}
	if !claims.Confirmation.JWK.Equal(agent.signingKey.PublicJWK()) {
		return errors.New("reference: event subscription confirmation key does not match this agent")
	}
	if localContext.APIssuer != claims.Issuer || localContext.EventID != claims.EventID {
		return errors.New("reference: event subscription context does not match token")
	}
	if err := validateAgentEventContext(localContext); err != nil {
		return err
	}
	if err := agent.eventStore.PutContext(ctx, localContext); err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, nil)
	if err != nil {
		return err
	}
	if err := agent.signRequest(request, compact); err != nil {
		return err
	}
	response, err := agent.httpClient.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusCreated {
		return responseError(response)
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 8<<10))
	return nil
}

// AcceptEvent independently verifies one AP-custodied compact event token and
// advances its durable local action state without trusting token claims before
// verification.
func (agent *Agent) AcceptEvent(
	ctx context.Context,
	accepted AcceptedEvent,
) (EventProcessingState, error) {
	if agent == nil || agent.eventStore == nil || agent.eventAction == nil {
		return "", errors.New("reference: agent Events is not configured")
	}
	agent.eventMu.Lock()
	defer agent.eventMu.Unlock()
	return agent.acceptEvent(ctx, accepted)
}

// ResumeEvents makes one cursor-bounded pass over durable nonterminal agent
// work. One unknown action cannot starve later action keys in the same pass.
func (agent *Agent) ResumeEvents(ctx context.Context) error {
	if agent == nil || agent.eventStore == nil || agent.eventAction == nil {
		return errors.New("reference: agent Events is not configured")
	}
	agent.eventMu.Lock()
	defer agent.eventMu.Unlock()

	var cursor *EventActionKey
	var joined error
	for {
		processing, err := agent.eventStore.NextProcessing(ctx, cursor)
		if errors.Is(err, ErrNoEventProcessing) {
			return joined
		}
		if err != nil {
			return errors.Join(joined, err)
		}
		next := processing.Action
		cursor = &next
		if _, err := agent.continueEventProcessing(ctx, processing, true); err != nil {
			joined = errors.Join(joined, err)
		}
	}
}

func (agent *Agent) acceptEvent(
	ctx context.Context,
	accepted AcceptedEvent,
) (EventProcessingState, error) {
	if err := validateAcceptedEventEnvelope(ctx, accepted); err != nil {
		return "", err
	}
	if err := validateEventPayloadEnvelope(accepted.ContentType, accepted.Payload, accepted.PayloadDigest); err != nil {
		return agent.refuseEvent(ctx, accepted.Delivery, EventRefusalInvalid)
	}
	state, err := agent.eventStore.LoadDisposition(ctx, accepted.Delivery)
	if err == nil {
		if state == EventCompleted || state == EventRefused {
			return state, nil
		}
		processing, loadErr := agent.eventStore.LoadProcessingByDelivery(ctx, accepted.Delivery)
		if loadErr != nil {
			return state, loadErr
		}
		// A pending record may belong to an Agent reconstructed with different
		// policy. Reverify it before first dispatch; dispatched work still enters
		// reconciliation above verification so an unknown consequence is retained.
		return agent.continueEventProcessing(ctx, processing, true)
	}
	if !errors.Is(err, ErrEventDispositionNotFound) {
		return "", err
	}

	claims, err := aauth.VerifyEventToken(ctx, accepted.Token, agent.keyResolver, agent.clock)
	if err != nil {
		if retryableEventVerificationError(err) {
			return "", err
		}
		reason := EventRefusalInvalid
		var validationError *aauth.TokenValidationError
		if errors.As(err, &validationError) && validationError.Code == aauth.TokenValidationExpired {
			reason = EventRefusalExpired
		}
		return agent.refuseEvent(ctx, accepted.Delivery, reason)
	}
	if !agent.acceptsEventClaims(claims) {
		return agent.refuseEvent(ctx, accepted.Delivery, EventRefusalInvalid)
	}
	localContext, err := agent.eventStore.LookupContext(ctx, accepted.APIssuer, claims.EventID)
	if errors.Is(err, ErrEventContextNotFound) {
		return agent.refuseEvent(ctx, accepted.Delivery, EventRefusalUnknownContext)
	}
	if err != nil {
		return "", err
	}
	if err := validateAgentEventPayload(localContext, accepted.ContentType, accepted.Payload, accepted.PayloadDigest); err != nil {
		return agent.refuseEvent(ctx, accepted.Delivery, EventRefusalInvalid)
	}
	action := EventActionKey{
		ResourceIssuer: claims.Issuer,
		APIssuer:       accepted.APIssuer,
		EventID:        claims.EventID,
	}
	processing := AgentEventProcessing{
		Delivery:  accepted.Delivery,
		Action:    action,
		State:     EventPending,
		ExpiresAt: time.Unix(claims.ExpiresAt, 0),
		Token:     accepted.Token, Event: claims, ContentType: accepted.ContentType,
		Payload: append([]byte(nil), accepted.Payload...), PayloadDigest: accepted.PayloadDigest,
	}
	if localContext.APIssuer != action.APIssuer || localContext.EventID != action.EventID {
		return "", errors.New("reference: stored event context does not match verified event")
	}
	if err := agent.eventStore.AdmitProcessing(ctx, processing); err != nil {
		return "", err
	}
	return agent.continueEventProcessing(ctx, processing, false)
}

func (agent *Agent) continueEventProcessing(
	ctx context.Context,
	processing AgentEventProcessing,
	reverify bool,
) (EventProcessingState, error) {
	switch processing.State {
	case EventCompleted, EventRefused:
		return processing.State, nil
	case EventDispatched:
		outcome, err := agent.eventAction.Reconcile(ctx, processing.Action)
		return agent.recordEventActionOutcome(ctx, processing, outcome, err)
	case EventPending:
	default:
		return "", fmt.Errorf("reference: unknown event processing state %q", processing.State)
	}

	if reverify {
		claims, err := aauth.VerifyEventToken(ctx, processing.Token, agent.keyResolver, agent.clock)
		if err != nil {
			var validationError *aauth.TokenValidationError
			if errors.As(err, &validationError) && validationError.Code == aauth.TokenValidationExpired {
				return agent.refuseEvent(ctx, processing.Delivery, EventRefusalExpired)
			}
			return EventPending, err
		}
		if claims != processing.Event {
			return EventPending, errors.New("reference: retained event token no longer matches verified processing")
		}
		if !agent.acceptsEventClaims(claims) {
			return agent.refuseEvent(ctx, processing.Delivery, EventRefusalInvalid)
		}
	}
	localContext, err := agent.eventStore.LookupContext(ctx, processing.Action.APIssuer, processing.Action.EventID)
	if errors.Is(err, ErrEventContextNotFound) {
		return agent.refuseEvent(ctx, processing.Delivery, EventRefusalUnknownContext)
	}
	if err != nil {
		return EventPending, err
	}
	if err := validateAgentEventPayload(localContext, processing.ContentType, processing.Payload, processing.PayloadDigest); err != nil {
		return agent.refuseEvent(ctx, processing.Delivery, EventRefusalInvalid)
	}
	claimed, err := agent.eventStore.BeginDispatch(ctx, processing.Action, agent.clock.Now())
	if errors.Is(err, ErrEventProcessingExpired) {
		return agent.refuseEvent(ctx, processing.Delivery, EventRefusalExpired)
	}
	if err != nil {
		return EventPending, err
	}
	if !claimed {
		current, loadErr := agent.eventStore.LoadProcessing(ctx, processing.Action)
		if loadErr != nil {
			return EventDispatched, loadErr
		}
		if current.State == EventCompleted || current.State == EventRefused {
			return current.State, nil
		}
		return current.State, ErrEventProcessingIncomplete
	}
	processing.State = EventDispatched
	outcome, err := agent.eventAction.Dispatch(ctx, EventActionInput{
		Key: processing.Action, Context: localContext, Event: processing.Event,
		ContentType: processing.ContentType, Payload: append([]byte(nil), processing.Payload...),
		PayloadDigest: processing.PayloadDigest,
	})
	return agent.recordEventActionOutcome(ctx, processing, outcome, err)
}

func (agent *Agent) recordEventActionOutcome(
	ctx context.Context,
	processing AgentEventProcessing,
	outcome EventActionOutcome,
	actionErr error,
) (EventProcessingState, error) {
	if actionErr != nil {
		return EventDispatched, actionErr
	}
	switch outcome {
	case EventActionCompleted:
		if err := agent.eventStore.MarkCompleted(ctx, processing.Action); err != nil {
			return EventDispatched, err
		}
		return EventCompleted, nil
	case EventActionNotApplied:
		transitioned, err := agent.eventStore.RetryNotApplied(ctx, processing.Action, agent.clock.Now())
		if errors.Is(err, ErrEventProcessingExpired) {
			return agent.refuseEvent(ctx, processing.Delivery, EventRefusalNotApplied)
		}
		if err != nil {
			return EventDispatched, err
		}
		if !transitioned {
			return EventPending, ErrEventProcessingIncomplete
		}
		return EventPending, ErrEventProcessingIncomplete
	case EventActionUnknown:
		return EventDispatched, ErrEventProcessingIncomplete
	default:
		return EventDispatched, fmt.Errorf("reference: invalid event action outcome %q", outcome)
	}
}

func (agent *Agent) acceptsEventClaims(claims aauth.EventTokenClaims) bool {
	return claims.Audience == agent.identifier &&
		claims.ExpiresAt-claims.IssuedAt <= int64(referenceEventTokenLifetime/time.Second)
}

func (agent *Agent) refuseEvent(
	ctx context.Context,
	delivery EventDeliveryKey,
	reason EventRefusalReason,
) (EventProcessingState, error) {
	if err := agent.eventStore.MarkRefused(ctx, delivery, reason); err != nil {
		return "", err
	}
	return EventRefused, nil
}

func validateAcceptedEventEnvelope(ctx context.Context, accepted AcceptedEvent) error {
	if err := eventContextError(ctx); err != nil {
		return err
	}
	if err := validateEventDeliveryKey(accepted.Delivery); err != nil {
		return err
	}
	if accepted.APIssuer != accepted.Delivery.APIssuer || accepted.Token == "" ||
		accepted.AcceptedAt.IsZero() || accepted.Delivery.TokenDigest != eventTokenDigest(accepted.Token) {
		return fmt.Errorf("%w: accepted event envelope is inconsistent", ErrEventRecordInvalid)
	}
	return nil
}

func validateAgentEventPayload(
	localContext AgentEventContext,
	contentType string,
	payload []byte,
	digest string,
) error {
	hasContract := hasEventContractBinding(localContext.ContractDigest, localContext.OperationID, localContext.MessageID)
	hasPayload := hasEventPayload(contentType, payload, digest)
	if hasContract != hasPayload {
		return errors.New("reference: agent event payload does not match local contract context")
	}
	if !hasContract {
		return nil
	}
	if err := validateEventPayloadEnvelope(contentType, payload, digest); err != nil {
		return err
	}
	contract, err := events.ParseEventsAsyncAPI(localContext.Contract)
	if err != nil || contract.Digest() != localContext.ContractDigest {
		return errors.New("reference: agent retained event contract is invalid")
	}
	message, err := contract.ProtectedMessage(localContext.OperationID, localContext.MessageID)
	if err != nil {
		return err
	}
	if contentType != message.ContentType {
		return errors.New("reference: agent event media type does not match retained contract")
	}
	return message.ValidatePayload(payload)
}

func retryableEventVerificationError(err error) bool {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var resolutionError *signaturekey.ResolutionError
	return errors.As(err, &resolutionError) &&
		(resolutionError.Code == signaturekey.ResolutionDenied ||
			resolutionError.Code == signaturekey.ResolutionUnavailable)
}

func (agent *Agent) CreateMission(ctx context.Context, endpoint string, proposal aauth.MissionProposal) (aauth.ApprovedMission, error) {
	var approved aauth.ApprovedMission
	if err := aauth.ValidateEndpoint(endpoint); err != nil {
		return approved, err
	}
	personServer, err := endpointIdentifier(endpoint)
	if err != nil {
		return approved, err
	}
	body, err := json.Marshal(proposal)
	if err != nil {
		return approved, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return approved, err
	}
	request.Header.Set("Content-Type", "application/json")
	if err := agent.signRequest(request, agent.agentToken); err != nil {
		return approved, err
	}
	response, err := agent.httpClient.Do(request)
	if err != nil {
		return approved, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return approved, responseError(response)
	}
	responseBytes, err := io.ReadAll(io.LimitReader(response.Body, maxJSONBody+1))
	if err != nil {
		return approved, err
	}
	if len(responseBytes) > maxJSONBody {
		return approved, errors.New("reference: mission response is too large")
	}
	var result struct {
		S256         string            `json:"s256"`
		Mission      string            `json:"mission"`
		Capabilities []string          `json:"capabilities,omitempty"`
		PersonTokens map[string]string `json:"person_tokens,omitempty"`
	}
	if err := json.Unmarshal(responseBytes, &result); err != nil {
		return approved, fmt.Errorf("reference: decode mission approval: %w", err)
	}
	missionBytes, err := base64.RawURLEncoding.DecodeString(result.Mission)
	if err != nil {
		return approved, fmt.Errorf("reference: decode approved mission bytes: %w", err)
	}
	approved = aauth.ApprovedMission{
		Reference:    aauth.MissionReference{Approver: personServer, S256: result.S256},
		Bytes:        append([]byte(nil), missionBytes...),
		Capabilities: append([]string(nil), result.Capabilities...),
		PersonTokens: copyStringMap(result.PersonTokens),
	}
	if err := approved.ValidateExactBytes(); err != nil {
		return approved, err
	}
	var blob struct {
		Approver string `json:"approver"`
		Agent    string `json:"agent"`
	}
	if err := json.Unmarshal(missionBytes, &blob); err != nil {
		return approved, fmt.Errorf("reference: decode approved mission: %w", err)
	}
	if blob.Approver != approved.Reference.Approver || blob.Agent != agent.identifier {
		return approved, errors.New("reference: approved mission body does not match agent or approver")
	}
	for resource, compact := range approved.PersonTokens {
		evidence, err := aauth.VerifyPersonToken(ctx, compact, agent.keyResolver, agent.clock)
		if err != nil {
			return approved, err
		}
		claims, err := claimsWithoutAuthorization(evidence)
		if err != nil {
			return approved, err
		}
		if resource != claims.Audience || claims.Issuer != approved.Reference.Approver ||
			claims.MissionS256 != approved.Reference.S256 ||
			!claims.Confirmation.JWK.Equal(agent.signingKey.PublicJWK()) {
			return approved, errors.New("reference: mission person token does not match its approval")
		}
	}
	return approved, nil
}

// UpdateMission records one current change in an approved mission. The
// mission blob remains immutable; the person server returns the digest of the
// exact update description retained in its ordered log.
func (agent *Agent) UpdateMission(
	ctx context.Context,
	endpoint string,
	mission aauth.MissionReference,
	description string,
) (aauth.MissionUpdateResult, error) {
	var result aauth.MissionUpdateResult
	if err := aauth.ValidateEndpoint(endpoint); err != nil {
		return result, err
	}
	personServer, err := endpointIdentifier(endpoint)
	if err != nil {
		return result, err
	}
	if err := mission.Validate(); err != nil {
		return result, err
	}
	if mission.Approver != personServer {
		return result, errors.New("reference: mission approver does not match person-server endpoint")
	}
	input := aauth.MissionUpdate{Action: "update", Description: description}
	if err := input.Validate(); err != nil {
		return result, err
	}
	body, err := json.Marshal(input)
	if err != nil {
		return result, err
	}
	target := strings.TrimRight(endpoint, "/") + "/" + mission.S256
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		return result, err
	}
	request.Header.Set("Content-Type", "application/json")
	if err := agent.signRequest(request, agent.agentToken); err != nil {
		return result, err
	}
	response, err := agent.httpClient.Do(request)
	if err != nil {
		return result, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return result, responseError(response)
	}
	if err := decodeJSONBytes(io.LimitReader(response.Body, maxJSONBody+1), &result); err != nil {
		return result, err
	}
	if err := result.Validate(); err != nil {
		return result, err
	}
	if result.S256 != aauth.S256([]byte(input.Description)) {
		return result, errors.New("reference: mission update response does not match the submitted description")
	}
	return result, nil
}

// RequestPersonToken obtains a current resource-directed person token. A
// mission is optional; when supplied its exact bytes and approver are checked
// before the mission digest is put on the wire.
func (agent *Agent) RequestPersonToken(
	ctx context.Context,
	endpoint string,
	resource string,
	mission *aauth.ApprovedMission,
) (PersonGrant, error) {
	authorization, err := agent.RequestPersonTokenAuthorization(ctx, endpoint, resource, mission)
	if err != nil {
		return PersonGrant{}, err
	}
	if authorization.Pending != nil {
		return PersonGrant{}, errors.New("reference: person-token request requires interaction; use RequestPersonTokenAuthorization")
	}
	if authorization.Grant == nil {
		return PersonGrant{}, errors.New("reference: person-token response has no grant")
	}
	return *authorization.Grant, nil
}

// RequestPersonTokenForSubagent lets a top-level parent obtain a current
// resource-directed person token bound to one direct sub-agent's key.
func (agent *Agent) RequestPersonTokenForSubagent(
	ctx context.Context,
	endpoint string,
	resource string,
	subagentToken string,
) (PersonGrant, error) {
	if strings.TrimSpace(subagentToken) == "" {
		return PersonGrant{}, errors.New("reference: sub-agent token is required")
	}
	authorization, err := agent.RequestPersonTokenForSubagentAuthorization(ctx, endpoint, resource, subagentToken)
	return immediatePersonGrant(authorization, err)
}

// RequestPersonTokenForUpstream obtains the downstream-directed person token
// that begins one current call-chain hop. The upstream auth token is context
// for the person server; the intermediary still signs with its own agent token.
func (agent *Agent) RequestPersonTokenForUpstream(
	ctx context.Context,
	endpoint string,
	resource string,
	upstreamToken string,
) (PersonGrant, error) {
	if strings.TrimSpace(upstreamToken) == "" {
		return PersonGrant{}, errors.New("reference: upstream auth token is required")
	}
	authorization, err := agent.RequestPersonTokenForUpstreamAuthorization(ctx, endpoint, resource, upstreamToken)
	return immediatePersonGrant(authorization, err)
}

// RequestPersonTokenForChainedSubagent obtains a downstream person token for
// one direct sub-agent while the parent's upstream authorization selects the
// person server and supplies the authorization context.
func (agent *Agent) RequestPersonTokenForChainedSubagent(
	ctx context.Context,
	endpoint string,
	resource string,
	subagentToken string,
	upstreamToken string,
) (PersonGrant, error) {
	if strings.TrimSpace(subagentToken) == "" {
		return PersonGrant{}, errors.New("reference: sub-agent token is required")
	}
	if strings.TrimSpace(upstreamToken) == "" {
		return PersonGrant{}, errors.New("reference: upstream auth token is required")
	}
	authorization, err := agent.RequestPersonTokenForChainedSubagentAuthorization(ctx, endpoint, resource, subagentToken, upstreamToken)
	return immediatePersonGrant(authorization, err)
}

func immediatePersonGrant(authorization PersonTokenAuthorization, err error) (PersonGrant, error) {
	if err != nil {
		return PersonGrant{}, err
	}
	if authorization.Pending != nil {
		return PersonGrant{}, errors.New("reference: person-token request requires interaction; use the matching PersonTokenAuthorization method")
	}
	if authorization.Grant == nil {
		return PersonGrant{}, errors.New("reference: person-token response has no grant")
	}
	return *authorization.Grant, nil
}

func copyStringMap(source map[string]string) map[string]string {
	if source == nil {
		return nil
	}
	copied := make(map[string]string, len(source))
	for key, value := range source {
		copied[key] = value
	}
	return copied
}

// RequestPermission asks a person server to govern a local action. The result
// is shaped for either an immediate decision or the draft's deferred form.
func (agent *Agent) RequestPermission(
	ctx context.Context,
	endpoint string,
	input aauth.PermissionRequest,
) (PermissionAuthorization, error) {
	var authorization PermissionAuthorization
	if err := aauth.ValidateEndpoint(endpoint); err != nil {
		return authorization, err
	}
	if err := input.Validate(); err != nil {
		return authorization, err
	}
	personServer, err := endpointIdentifier(endpoint)
	if err != nil {
		return authorization, err
	}
	if input.Mission != nil && input.Mission.Approver != personServer {
		return authorization, errors.New("reference: permission mission approver does not match person-server endpoint")
	}
	body, err := json.Marshal(input)
	if err != nil {
		return authorization, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return authorization, err
	}
	request.Header.Set("Content-Type", "application/json")
	if err := agent.signRequest(request, agent.agentToken); err != nil {
		return authorization, err
	}
	response, err := agent.httpClient.Do(request)
	if err != nil {
		return authorization, err
	}
	defer response.Body.Close()
	switch response.StatusCode {
	case http.StatusOK:
		var decision aauth.PermissionResponse
		if err := decodeJSONBytes(io.LimitReader(response.Body, maxJSONBody+1), &decision); err != nil {
			return authorization, err
		}
		if err := decision.Validate(); err != nil {
			return authorization, err
		}
		authorization.Decision = &decision
		return authorization, nil
	case http.StatusAccepted:
		deferred, err := aauth.ParseDeferredResponse(response)
		if err != nil {
			return authorization, err
		}
		pendingServer, err := endpointIdentifier(deferred.Location)
		if err != nil {
			return authorization, err
		}
		if pendingServer != personServer {
			return authorization, errors.New("reference: pending permission moved to another person server")
		}
		parsed, err := url.Parse(deferred.Location)
		if err != nil {
			return authorization, err
		}
		authorization.Pending = &PendingPermissionAuthorization{
			ID:           path.Base(parsed.Path),
			PersonServer: personServer,
			Location:     deferred.Location,
			RetryAfter:   deferred.RetryAfter,
			NotBefore:    agent.clock.Now().Add(deferred.RetryAfter),
			Status:       deferred.Status,
			Requirement:  deferred.Requirement,
		}
		return authorization, nil
	default:
		return authorization, responseError(response)
	}
}

// PollPermission makes one signed GET to a pending person-server permission
// request and returns either a refreshed continuation or a terminal decision.
func (agent *Agent) PollPermission(
	ctx context.Context,
	pending *PendingPermissionAuthorization,
) (PermissionAuthorization, error) {
	var authorization PermissionAuthorization
	if pending == nil {
		return authorization, errors.New("reference: pending permission is required")
	}
	if agent.clock.Now().Before(pending.NotBefore) {
		return authorization, errors.New("reference: pending permission is not ready to poll")
	}
	if err := aauth.ValidatePollingEndpoint(pending.Location); err != nil {
		return authorization, err
	}
	personServer, err := endpointIdentifier(pending.Location)
	if err != nil {
		return authorization, err
	}
	if personServer != pending.PersonServer {
		return authorization, errors.New("reference: pending permission does not apply to its endpoint")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, pending.Location, nil)
	if err != nil {
		return authorization, err
	}
	request.Header.Set("Prefer", "wait=0")
	if err := agent.signRequest(request, agent.agentToken); err != nil {
		return authorization, err
	}
	response, err := agent.httpClient.Do(request)
	if err != nil {
		return authorization, err
	}
	defer response.Body.Close()
	switch response.StatusCode {
	case http.StatusOK:
		var decision aauth.PermissionResponse
		if err := decodeJSONBytes(io.LimitReader(response.Body, maxJSONBody+1), &decision); err != nil {
			return authorization, err
		}
		if err := decision.Validate(); err != nil {
			return authorization, err
		}
		authorization.Decision = &decision
		return authorization, nil
	case http.StatusAccepted:
		deferred, err := aauth.ParseDeferredResponse(response)
		if err != nil {
			return authorization, err
		}
		next, err := newPendingPermissionAuthorization(
			pending.PersonServer,
			deferred,
			agent.clock.Now(),
		)
		if err != nil {
			return authorization, err
		}
		*pending = next
		authorization.Pending = pending
		return authorization, nil
	default:
		responseErr := responseError(response)
		updatePollingBackoff(
			response,
			&pending.RetryAfter,
			&pending.NotBefore,
			agent.clock.Now(),
		)
		return authorization, responseErr
	}
}

func newPendingPermissionAuthorization(
	personServer string,
	deferred aauth.DeferredResponse,
	now time.Time,
) (PendingPermissionAuthorization, error) {
	locationServer, err := endpointIdentifier(deferred.Location)
	if err != nil {
		return PendingPermissionAuthorization{}, err
	}
	if locationServer != personServer {
		return PendingPermissionAuthorization{}, errors.New("reference: pending permission moved to another person server")
	}
	parsed, err := url.Parse(deferred.Location)
	if err != nil {
		return PendingPermissionAuthorization{}, err
	}
	return PendingPermissionAuthorization{
		ID:           path.Base(parsed.Path),
		PersonServer: personServer,
		Location:     deferred.Location,
		RetryAfter:   deferred.RetryAfter,
		NotBefore:    now.Add(deferred.RetryAfter),
		Status:       deferred.Status,
		Requirement:  deferred.Requirement,
	}, nil
}

// RecordAudit submits one signed mission-bound completed-action record.
func (agent *Agent) RecordAudit(
	ctx context.Context,
	endpoint string,
	input aauth.AuditRequest,
) error {
	if err := aauth.ValidateEndpoint(endpoint); err != nil {
		return err
	}
	if err := input.Validate(); err != nil {
		return err
	}
	personServer, err := endpointIdentifier(endpoint)
	if err != nil {
		return err
	}
	if input.Mission.Approver != personServer {
		return errors.New("reference: audit mission approver does not match person-server endpoint")
	}
	body, err := json.Marshal(input)
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	if err := agent.signRequest(request, agent.agentToken); err != nil {
		return err
	}
	response, err := agent.httpClient.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusCreated {
		return responseError(response)
	}
	return nil
}

// ProposeMissionCompletion submits the current mission-endpoint completion
// action and returns the person-server review continuation.
func (agent *Agent) ProposeMissionCompletion(
	ctx context.Context,
	endpoint string,
	mission aauth.MissionReference,
	summary string,
) (InteractionAuthorization, error) {
	var authorization InteractionAuthorization
	if err := aauth.ValidateEndpoint(endpoint); err != nil {
		return authorization, err
	}
	personServer, err := endpointIdentifier(endpoint)
	if err != nil {
		return authorization, err
	}
	if err := mission.Validate(); err != nil {
		return authorization, err
	}
	if mission.Approver != personServer {
		return authorization, errors.New("reference: mission approver does not match person-server endpoint")
	}
	input := aauth.MissionCompletion{Action: "completion", Summary: summary}
	if err := input.Validate(); err != nil {
		return authorization, err
	}
	body, err := json.Marshal(input)
	if err != nil {
		return authorization, err
	}
	target := strings.TrimRight(endpoint, "/") + "/" + mission.S256
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		return authorization, err
	}
	request.Header.Set("Content-Type", "application/json")
	if err := agent.signRequest(request, agent.agentToken); err != nil {
		return authorization, err
	}
	response, err := agent.httpClient.Do(request)
	if err != nil {
		return authorization, err
	}
	defer response.Body.Close()
	return decodeInteractionAuthorization(response, personServer, agent.clock.Now(), aauth.InteractionTypeCompletion)
}

// RequestInteraction submits a signed person-server interaction request.
func (agent *Agent) RequestInteraction(
	ctx context.Context,
	endpoint string,
	input aauth.InteractionRequest,
) (InteractionAuthorization, error) {
	var authorization InteractionAuthorization
	if err := aauth.ValidateEndpoint(endpoint); err != nil {
		return authorization, err
	}
	if err := input.Validate(); err != nil {
		return authorization, err
	}
	personServer, err := endpointIdentifier(endpoint)
	if err != nil {
		return authorization, err
	}
	if input.Mission != nil && input.Mission.Approver != personServer {
		return authorization, errors.New("reference: interaction mission approver does not match person-server endpoint")
	}
	body, err := json.Marshal(input)
	if err != nil {
		return authorization, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return authorization, err
	}
	request.Header.Set("Content-Type", "application/json")
	if err := agent.signRequest(request, agent.agentToken); err != nil {
		return authorization, err
	}
	response, err := agent.httpClient.Do(request)
	if err != nil {
		return authorization, err
	}
	defer response.Body.Close()
	return decodeInteractionAuthorization(response, personServer, agent.clock.Now(), input.Type)
}

// PollInteraction makes one signed GET to a pending person-server interaction.
func (agent *Agent) PollInteraction(
	ctx context.Context,
	pending *PendingInteractionAuthorization,
) (InteractionAuthorization, error) {
	var authorization InteractionAuthorization
	if pending == nil {
		return authorization, errors.New("reference: pending interaction is required")
	}
	if agent.clock.Now().Before(pending.NotBefore) {
		return authorization, errors.New("reference: pending interaction is not ready to poll")
	}
	if err := aauth.ValidatePollingEndpoint(pending.Location); err != nil {
		return authorization, err
	}
	personServer, err := endpointIdentifier(pending.Location)
	if err != nil {
		return authorization, err
	}
	if personServer != pending.PersonServer {
		return authorization, errors.New("reference: pending interaction does not apply to its endpoint")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, pending.Location, nil)
	if err != nil {
		return authorization, err
	}
	request.Header.Set("Prefer", "wait=0")
	if err := agent.signRequest(request, agent.agentToken); err != nil {
		return authorization, err
	}
	response, err := agent.httpClient.Do(request)
	if err != nil {
		return authorization, err
	}
	defer response.Body.Close()
	authorization, err = decodeInteractionAuthorization(
		response,
		pending.PersonServer,
		agent.clock.Now(),
		pending.Type,
	)
	if authorization.Pending != nil {
		*pending = *authorization.Pending
		authorization.Pending = pending
	}
	return authorization, err
}

// RespondToClarification posts one signed Markdown answer to a pending
// interaction and updates the continuation returned by the person server.
func (agent *Agent) RespondToClarification(
	ctx context.Context,
	pending *PendingInteractionAuthorization,
	answer string,
) error {
	if pending == nil ||
		pending.Requirement == nil ||
		pending.Requirement.Type != aauth.RequirementClarification {
		return errors.New("reference: pending interaction is not awaiting clarification")
	}
	body, err := json.Marshal(aauth.ClarificationResponse{
		Action:                "clarification_response",
		ClarificationResponse: answer,
	})
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		pending.Location,
		bytes.NewReader(body),
	)
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	if err := agent.signRequest(request, agent.agentToken); err != nil {
		return err
	}
	response, err := agent.httpClient.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	authorization, err := decodeInteractionAuthorization(
		response,
		pending.PersonServer,
		agent.clock.Now(),
		pending.Type,
	)
	if err != nil {
		return err
	}
	if authorization.Pending == nil {
		return errors.New("reference: clarification response unexpectedly terminated the interaction")
	}
	*pending = *authorization.Pending
	return nil
}

func decodeInteractionAuthorization(
	response *http.Response,
	personServer string,
	now time.Time,
	interactionType aauth.InteractionType,
) (InteractionAuthorization, error) {
	var authorization InteractionAuthorization
	switch response.StatusCode {
	case http.StatusOK:
		switch interactionType {
		case aauth.InteractionTypeCompletion:
			body, err := io.ReadAll(io.LimitReader(response.Body, maxJSONBody+1))
			if err != nil {
				return authorization, err
			}
			if len(body) > maxJSONBody {
				return authorization, errors.New("reference: interaction response is too large")
			}
			if len(bytes.TrimSpace(body)) != 0 {
				var terminal struct {
					Status string `json:"status"`
				}
				if err := decodeJSONBytes(bytes.NewReader(body), &terminal); err != nil {
					return authorization, err
				}
				if terminal.Status != "completed" {
					return authorization, errors.New("reference: completion response status is invalid")
				}
			}
			authorization.Completed = true
			authorization.Status = "completed"
		case aauth.InteractionTypeQuestion:
			var terminal struct {
				Answer *string `json:"answer"`
			}
			if err := decodeJSONBytes(io.LimitReader(response.Body, maxJSONBody+1), &terminal); err != nil {
				return authorization, err
			}
			if terminal.Answer == nil {
				return authorization, errors.New("reference: question response is missing its answer")
			}
			authorization.Answer = *terminal.Answer
			authorization.Status = "answered"
		case aauth.InteractionTypeInteraction, aauth.InteractionTypePayment:
			var terminal struct {
				Status string `json:"status"`
			}
			if err := decodeJSONBytes(io.LimitReader(response.Body, maxJSONBody+1), &terminal); err != nil {
				return authorization, err
			}
			if terminal.Status == "" {
				return authorization, errors.New("reference: relay response status is missing")
			}
			authorization.Status = terminal.Status
		default:
			return authorization, errors.New("reference: interaction type is invalid")
		}
		return authorization, nil
	case http.StatusAccepted:
		deferred, err := aauth.ParseDeferredResponse(response)
		if err != nil {
			return authorization, err
		}
		pendingServer, err := endpointIdentifier(deferred.Location)
		if err != nil {
			return authorization, err
		}
		if pendingServer != personServer {
			return authorization, errors.New("reference: pending interaction moved to another person server")
		}
		parsed, err := url.Parse(deferred.Location)
		if err != nil {
			return authorization, err
		}
		authorization.Pending = &PendingInteractionAuthorization{
			ID:            path.Base(parsed.Path),
			Type:          interactionType,
			PersonServer:  personServer,
			Location:      deferred.Location,
			RetryAfter:    deferred.RetryAfter,
			NotBefore:     now.Add(deferred.RetryAfter),
			Status:        deferred.Status,
			Requirement:   deferred.Requirement,
			Clarification: deferred.Clarification,
			Timeout:       deferred.Timeout,
			Options:       append([]string(nil), deferred.Options...),
		}
		return authorization, nil
	default:
		return authorization, responseError(response)
	}
}

// AuthorizeWithPersonToken performs the current authorization-endpoint and
// person-server exchange using one resource-directed aa-person+jwt.
func (agent *Agent) AuthorizeWithPersonToken(
	ctx context.Context,
	resourceEndpoint string,
	personServerEndpoint string,
	scopes []string,
	personToken string,
) (Grant, error) {
	if err := aauth.ValidateEndpoint(personServerEndpoint); err != nil {
		return Grant{}, err
	}
	personServer, err := endpointIdentifier(personServerEndpoint)
	if err != nil {
		return Grant{}, err
	}
	personEvidence, err := aauth.VerifyPersonToken(ctx, personToken, agent.keyResolver, agent.clock)
	if err != nil {
		return Grant{}, err
	}
	personClaims, err := claimsWithoutAuthorization(personEvidence)
	if err != nil {
		return Grant{}, err
	}
	if personClaims.Issuer != personServer {
		return Grant{}, errors.New("reference: person token issuer does not match person-server endpoint")
	}
	resourceGrant, err := agent.requestCurrentResourceToken(ctx, resourceEndpoint, scopes, personToken, personClaims, nil, nil)
	if err != nil {
		return Grant{}, err
	}
	return agent.ExchangeResourceToken(ctx, personServerEndpoint, resourceGrant)
}

// AuthorizeR3WithPersonToken performs one immediate four-party initial R3
// authorization journey. Deferred and concrete per-call execution are separate
// flows.
func (agent *Agent) AuthorizeR3WithPersonToken(
	ctx context.Context,
	resourceEndpoint string,
	personServerEndpoint string,
	scopes []string,
	personToken string,
	requested r3.OperationSet,
) (Grant, error) {
	if err := aauth.ValidateEndpoint(personServerEndpoint); err != nil {
		return Grant{}, err
	}
	personServer, err := endpointIdentifier(personServerEndpoint)
	if err != nil {
		return Grant{}, err
	}
	evidence, err := aauth.VerifyPersonToken(ctx, personToken, agent.keyResolver, agent.clock)
	if err != nil {
		return Grant{}, err
	}
	claims, err := claimsWithoutAuthorization(evidence)
	if err != nil {
		return Grant{}, err
	}
	if claims.Issuer != personServer {
		return Grant{}, errors.New("reference: person token issuer does not match person-server endpoint")
	}
	resourceGrant, err := agent.RequestR3ResourceTokenWithPersonToken(
		ctx, resourceEndpoint, scopes, personToken, requested,
	)
	if err != nil {
		return Grant{}, err
	}
	return agent.ExchangeResourceToken(ctx, personServerEndpoint, resourceGrant)
}

// RequestResourceTokenWithPersonToken asks a resource to derive a current
// resource token from an exact person token. The returned grant can be
// exchanged immediately or retained by the caller across a retry boundary.
func (agent *Agent) RequestResourceTokenWithPersonToken(
	ctx context.Context,
	resourceEndpoint string,
	scopes []string,
	personToken string,
) (ResourceGrant, error) {
	evidence, err := aauth.VerifyPersonToken(ctx, personToken, agent.keyResolver, agent.clock)
	if err != nil {
		return ResourceGrant{}, err
	}
	claims, err := claimsWithoutAuthorization(evidence)
	if err != nil {
		return ResourceGrant{}, err
	}
	return agent.requestCurrentResourceToken(ctx, resourceEndpoint, scopes, personToken, claims, nil, nil)
}

// RequestR3ResourceTokenWithPersonToken requests one exact R3 operation
// set and retains that request beside the returned resource token.
func (agent *Agent) RequestR3ResourceTokenWithPersonToken(
	ctx context.Context,
	resourceEndpoint string,
	scopes []string,
	personToken string,
	requested r3.OperationSet,
) (ResourceGrant, error) {
	if err := requested.Validate(); err != nil {
		return ResourceGrant{}, err
	}
	evidence, err := aauth.VerifyPersonToken(ctx, personToken, agent.keyResolver, agent.clock)
	if err != nil {
		return ResourceGrant{}, err
	}
	claims, err := claimsWithoutAuthorization(evidence)
	if err != nil {
		return ResourceGrant{}, err
	}
	return agent.requestCurrentResourceToken(ctx, resourceEndpoint, scopes, personToken, claims, &requested, nil)
}

// RequestBudgetedResourceTokenWithPersonToken requests one resource-denominated
// Budget offer and retains its sealed companion result beside the Core token.
func (agent *Agent) RequestBudgetedResourceTokenWithPersonToken(
	ctx context.Context,
	resourceEndpoint string,
	scopes []string,
	personToken string,
	requested budgets.Budget,
) (ResourceGrant, error) {
	if err := requested.Validate(); err != nil {
		return ResourceGrant{}, err
	}
	evidence, err := aauth.VerifyPersonToken(ctx, personToken, agent.keyResolver, agent.clock)
	if err != nil {
		return ResourceGrant{}, err
	}
	claims, err := claimsWithoutAuthorization(evidence)
	if err != nil {
		return ResourceGrant{}, err
	}
	copy := requested
	return agent.requestCurrentResourceToken(ctx, resourceEndpoint, scopes, personToken, claims, nil, &copy)
}

// RequestR3PerCall presents one operation that the current auth token marks as
// per-call and validates the resource's step-up challenge. The returned
// ResourceGrant can be exchanged through the ordinary person-server token
// path; the resulting auth token applies only to the supplied operation.
func (agent *Agent) RequestR3PerCall(
	ctx context.Context,
	call AuthorizedCall,
	grant Grant,
	operation r3.OperationSet,
) (ResourceGrant, error) {
	if err := operation.Validate(); err != nil || len(operation.Operations) != 1 {
		return ResourceGrant{}, errors.New("reference: R3 per-call request requires exactly one valid operation")
	}
	if grant.R3 == nil || !grant.R3.Valid() {
		return ResourceGrant{}, errors.New("reference: R3 per-call request requires a current R3 grant")
	}
	perCall, present := grant.R3.PerCall()
	if !present || !perCall.ContainsSet(operation) {
		return ResourceGrant{}, errors.New("reference: current R3 grant does not mark this operation as per-call")
	}
	response, err := agent.DoAuthorizedRequest(ctx, call, grant)
	if err != nil {
		return ResourceGrant{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		return ResourceGrant{}, responseError(response)
	}
	requirement, err := aauth.ParseRequirementHeader(response.Header.Get("AAuth-Requirement"))
	if err != nil || requirement.Type != aauth.RequirementAuthToken {
		return ResourceGrant{}, errors.New("reference: R3 per-call response is not an auth-token challenge")
	}
	evidence, err := aauth.VerifyResourceToken(ctx, requirement.ResourceToken, agent.keyResolver, agent.clock)
	if err != nil {
		return ResourceGrant{}, err
	}
	proposalR3, err := r3.ValidateResourceToken(evidence)
	if err != nil {
		return ResourceGrant{}, err
	}
	claims, err := evidence.Claims()
	if err != nil {
		return ResourceGrant{}, err
	}
	resource, err := endpointIdentifier(call.Endpoint)
	if err != nil {
		return ResourceGrant{}, err
	}
	thumbprint, err := agent.signingKey.PublicJWK().Thumbprint()
	if err != nil {
		return ResourceGrant{}, err
	}
	if claims.Issuer != resource || claims.Audience != grant.Claims.Issuer ||
		claims.PersonServer != grant.Claims.PersonServer || claims.Subject != grant.Claims.Subject ||
		claims.AgentJKT != thumbprint || claims.Scope != grant.Claims.Scope ||
		claims.MissionS256 != grant.Claims.MissionS256 || claims.Tenant != grant.Claims.Tenant ||
		claims.Account != grant.Claims.Account || claims.Agent != "" {
		return ResourceGrant{}, errors.New("reference: R3 per-call challenge changed the current authorization context")
	}
	origin, err := endpointIdentifier(proposalR3.URI())
	if err != nil || origin != resource {
		return ResourceGrant{}, errors.New("reference: R3 per-call proposal is outside the resource")
	}
	requested := operation.Clone()
	return ResourceGrant{
		Resource: resource, ResourceToken: requirement.ResourceToken,
		Claims: claims, RequestedR3: &requested,
	}, nil
}

func (agent *Agent) requestCurrentResourceToken(
	ctx context.Context,
	resourceEndpoint string,
	scopes []string,
	personToken string,
	personClaims aauth.PersonTokenClaims,
	requestedR3 *r3.OperationSet,
	requestedBudget *budgets.Budget,
) (ResourceGrant, error) {
	var grant ResourceGrant
	if err := aauth.ValidateEndpoint(resourceEndpoint); err != nil {
		return grant, err
	}
	requestedScopes, err := parseScopes(strings.Join(scopes, " "))
	if err != nil {
		return grant, err
	}
	resourceID, err := endpointIdentifier(resourceEndpoint)
	if err != nil {
		return grant, err
	}
	if err := aauth.ValidatePersonTokenContext(personClaims, resourceID, agent.signingKey.PublicJWK()); err != nil {
		return grant, err
	}
	input := resourceAuthorizationInput{Scope: strings.Join(requestedScopes, " ")}
	if requestedR3 != nil {
		requested := requestedR3.Clone()
		input.R3Operations = &requested
	}
	if requestedBudget != nil {
		copy := *requestedBudget
		input.Budget = &copy
	}
	body, err := json.Marshal(input)
	if err != nil {
		return grant, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, resourceEndpoint, bytes.NewReader(body))
	if err != nil {
		return grant, err
	}
	request.Header.Set("Content-Type", "application/json")
	if err := agent.signRequest(request, personToken); err != nil {
		return grant, err
	}
	response, err := agent.httpClient.Do(request)
	if err != nil {
		return grant, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return grant, responseError(response)
	}
	var result struct {
		ResourceToken string `json:"resource_token"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, maxJSONBody)).Decode(&result); err != nil {
		return grant, err
	}
	resourceEvidence, err := aauth.VerifyResourceToken(ctx, result.ResourceToken, agent.keyResolver, agent.clock)
	if err != nil {
		return grant, err
	}
	var resourceR3 r3.TokenResult
	var resourceBudget budgets.TokenResult
	var resourceClaims aauth.ResourceTokenClaims
	if requestedR3 == nil && requestedBudget == nil {
		resourceClaims, err = claimsWithoutAuthorization(resourceEvidence)
	} else {
		if requestedR3 != nil {
			resourceR3, err = r3.ValidateResourceToken(resourceEvidence)
		}
		if err == nil && requestedBudget != nil {
			resourceBudget, err = budgets.ValidateResourceToken(resourceEvidence)
		}
		if err == nil {
			resourceClaims, err = resourceEvidence.Claims()
		}
	}
	if err != nil {
		return grant, err
	}
	thumbprint, err := agent.signingKey.PublicJWK().Thumbprint()
	if err != nil {
		return grant, err
	}
	if resourceClaims.Issuer != resourceID ||
		resourceClaims.PersonServer != personClaims.Issuer ||
		resourceClaims.Subject != personClaims.Subject ||
		resourceClaims.PresentedJTI != personClaims.JTI ||
		resourceClaims.AgentJKT != thumbprint ||
		resourceClaims.MissionS256 != personClaims.MissionS256 ||
		resourceClaims.Tenant != personClaims.Tenant {
		return grant, errors.New("reference: resource token does not match the presented person token")
	}
	if requestedR3 != nil {
		origin, originErr := endpointIdentifier(resourceR3.URI())
		if originErr != nil || origin != resourceID {
			return grant, errors.New("reference: R3 resource token names a document outside the resource")
		}
	}
	var retainedRequest *r3.OperationSet
	if requestedR3 != nil {
		copy := requestedR3.Clone()
		retainedRequest = &copy
	}
	return ResourceGrant{
		Resource:      resourceID,
		ResourceToken: result.ResourceToken,
		Claims:        resourceClaims,
		RequestedR3:   retainedRequest,
		Budget:        optionalBudgetResult(resourceBudget),
	}, nil
}

func optionalBudgetResult(result budgets.TokenResult) *budgets.TokenResult {
	if !result.Valid() {
		return nil
	}
	copy := result
	return &copy
}

func (agent *Agent) ExchangeResourceToken(
	ctx context.Context,
	personServerEndpoint string,
	resourceGrant ResourceGrant,
) (Grant, error) {
	authorization, err := agent.RequestTokenAuthorization(
		ctx,
		personServerEndpoint,
		resourceGrant,
	)
	if err != nil {
		return Grant{}, err
	}
	if authorization.Grant == nil {
		return Grant{}, errors.New("reference: authorization is pending; use RequestTokenAuthorization and PollTokenAuthorization")
	}
	return *authorization.Grant, nil
}

// RequestTokenAuthorization exchanges a resource token at a person server and
// returns either the immediate auth-token grant or a deferred continuation.
func (agent *Agent) RequestTokenAuthorization(
	ctx context.Context,
	personServerEndpoint string,
	resourceGrant ResourceGrant,
) (TokenAuthorization, error) {
	if _, err := preflightResourceGrantPersonServer(personServerEndpoint, resourceGrant); err != nil {
		return TokenAuthorization{}, err
	}
	agentEvidence, err := aauth.VerifyAgentToken(ctx, agent.agentToken, agent.keyResolver, agent.clock)
	if err != nil {
		return TokenAuthorization{}, err
	}
	agentClaims, err := claimsWithoutAuthorization(agentEvidence)
	if err != nil {
		return TokenAuthorization{}, err
	}
	if agentClaims.ParentAgent != "" {
		return TokenAuthorization{}, errors.New("reference: sub-agent cannot request authorization directly")
	}
	thumbprint, err := agent.signingKey.PublicJWK().Thumbprint()
	if err != nil {
		return TokenAuthorization{}, err
	}
	if resourceGrant.Claims.Agent != "" || resourceGrant.Claims.Subject == "" ||
		resourceGrant.Claims.AgentJKT != thumbprint {
		return TokenAuthorization{}, errors.New("reference: resource token is not bound to the requesting key")
	}
	return agent.requestTokenAuthorization(
		ctx,
		personServerEndpoint,
		resourceGrant,
		"",
		agent.signingKey.PublicJWK(),
		"",
	)
}

func (agent *Agent) AuthorizeSubagent(
	ctx context.Context,
	personServerEndpoint string,
	resourceGrant ResourceGrant,
	subagentToken string,
) (Grant, error) {
	authorization, err := agent.RequestSubagentTokenAuthorization(
		ctx,
		personServerEndpoint,
		resourceGrant,
		subagentToken,
	)
	if err != nil {
		return Grant{}, err
	}
	if authorization.Grant == nil {
		return Grant{}, errors.New("reference: sub-agent authorization is pending; use RequestSubagentTokenAuthorization and PollTokenAuthorization")
	}
	return *authorization.Grant, nil
}

// AuthorizeChainedSubagent lets a resource acting as a parent agent extend its
// upstream authorization to a sub-agent. The returned token is bound to the
// sub-agent and records both the parent and the upstream delegation chain.
func (agent *Agent) AuthorizeChainedSubagent(
	ctx context.Context,
	personServerEndpoint string,
	resourceGrant ResourceGrant,
	subagentToken string,
	upstreamToken string,
) (Grant, error) {
	authorization, err := agent.RequestChainedSubagentTokenAuthorization(
		ctx,
		personServerEndpoint,
		resourceGrant,
		subagentToken,
		upstreamToken,
	)
	if err != nil {
		return Grant{}, err
	}
	if authorization.Grant == nil {
		return Grant{}, errors.New("reference: chained sub-agent authorization is pending; use RequestChainedSubagentTokenAuthorization and PollTokenAuthorization")
	}
	return *authorization.Grant, nil
}

// RequestSubagentTokenAuthorization lets a parent exchange a sub-agent's
// resource token and receive either an immediate grant or a continuation the
// parent polls with its own proof.
func (agent *Agent) RequestSubagentTokenAuthorization(
	ctx context.Context,
	personServerEndpoint string,
	resourceGrant ResourceGrant,
	subagentToken string,
) (TokenAuthorization, error) {
	return agent.requestSubagentTokenAuthorization(
		ctx,
		personServerEndpoint,
		resourceGrant,
		subagentToken,
		"",
	)
}

// RequestChainedSubagentTokenAuthorization is the deferred-capable form of
// AuthorizeChainedSubagent.
func (agent *Agent) RequestChainedSubagentTokenAuthorization(
	ctx context.Context,
	personServerEndpoint string,
	resourceGrant ResourceGrant,
	subagentToken string,
	upstreamToken string,
) (TokenAuthorization, error) {
	if upstreamToken == "" {
		return TokenAuthorization{}, errors.New("reference: upstream auth token is required")
	}
	return agent.requestSubagentTokenAuthorization(
		ctx,
		personServerEndpoint,
		resourceGrant,
		subagentToken,
		upstreamToken,
	)
}

func (agent *Agent) requestSubagentTokenAuthorization(
	ctx context.Context,
	personServerEndpoint string,
	resourceGrant ResourceGrant,
	subagentToken string,
	upstreamToken string,
) (TokenAuthorization, error) {
	personServerID, err := preflightResourceGrantPersonServer(personServerEndpoint, resourceGrant)
	if err != nil {
		return TokenAuthorization{}, err
	}
	parentEvidence, err := aauth.VerifyAgentToken(ctx, agent.agentToken, agent.keyResolver, agent.clock)
	if err != nil {
		return TokenAuthorization{}, err
	}
	parentClaims, err := claimsWithoutAuthorization(parentEvidence)
	if err != nil {
		return TokenAuthorization{}, err
	}
	if parentClaims.ParentAgent != "" {
		return TokenAuthorization{}, errors.New("reference: sub-agent cannot mediate another sub-agent")
	}
	subagentEvidence, err := aauth.VerifyAgentToken(ctx, subagentToken, agent.keyResolver, agent.clock)
	if err != nil {
		return TokenAuthorization{}, err
	}
	subagentClaims, err := claimsWithoutAuthorization(subagentEvidence)
	if err != nil {
		return TokenAuthorization{}, err
	}
	if subagentClaims.ParentAgent != agent.identifier {
		return TokenAuthorization{}, errors.New("reference: sub-agent token does not name the signing parent")
	}
	if upstreamToken == "" && subagentClaims.PersonServer != personServerID {
		return TokenAuthorization{}, errors.New("reference: sub-agent token names a different person server")
	}
	subagentThumbprint, err := subagentClaims.Confirmation.JWK.Thumbprint()
	if err != nil {
		return TokenAuthorization{}, err
	}
	if resourceGrant.Claims.Agent != "" || resourceGrant.Claims.Subject == "" ||
		resourceGrant.Claims.AgentJKT != subagentThumbprint {
		return TokenAuthorization{}, errors.New("reference: resource token is not bound to the sub-agent")
	}
	if upstreamToken != "" {
		upstreamEvidence, err := aauth.VerifyAuthToken(ctx, upstreamToken, agent.keyResolver, agent.clock)
		if err != nil {
			return TokenAuthorization{}, err
		}
		upstream, err := claimsWithoutAuthorization(upstreamEvidence)
		if err != nil {
			return TokenAuthorization{}, err
		}
		if upstream.Audience != parentClaims.Issuer {
			return TokenAuthorization{}, errors.New("reference: upstream auth-token audience does not match intermediary issuer")
		}
		if upstream.PersonServer != personServerID {
			return TokenAuthorization{}, errors.New("reference: upstream auth token ps routes to a different person server")
		}
	}
	return agent.requestTokenAuthorization(
		ctx,
		personServerEndpoint,
		resourceGrant,
		subagentToken,
		subagentClaims.Confirmation.JWK,
		upstreamToken,
	)
}

func (agent *Agent) ExchangeChainedResourceToken(
	ctx context.Context,
	personServerEndpoint string,
	resourceGrant ResourceGrant,
	upstreamToken string,
) (Grant, error) {
	authorization, err := agent.RequestChainedTokenAuthorization(
		ctx,
		personServerEndpoint,
		resourceGrant,
		upstreamToken,
	)
	if err != nil {
		return Grant{}, err
	}
	if authorization.Grant == nil {
		return Grant{}, errors.New("reference: chained authorization is pending; use RequestChainedTokenAuthorization and PollTokenAuthorization")
	}
	return *authorization.Grant, nil
}

// RequestChainedTokenAuthorization exchanges a downstream resource token using
// an upstream authorization and preserves a deferred continuation when the
// person server needs more time.
func (agent *Agent) RequestChainedTokenAuthorization(
	ctx context.Context,
	personServerEndpoint string,
	resourceGrant ResourceGrant,
	upstreamToken string,
) (TokenAuthorization, error) {
	personServerID, err := preflightResourceGrantPersonServer(personServerEndpoint, resourceGrant)
	if err != nil {
		return TokenAuthorization{}, err
	}
	agentEvidence, err := aauth.VerifyAgentToken(ctx, agent.agentToken, agent.keyResolver, agent.clock)
	if err != nil {
		return TokenAuthorization{}, err
	}
	agentClaims, err := claimsWithoutAuthorization(agentEvidence)
	if err != nil {
		return TokenAuthorization{}, err
	}
	if agentClaims.ParentAgent != "" {
		return TokenAuthorization{}, errors.New("reference: sub-agent cannot perform call chaining")
	}
	upstreamEvidence, err := aauth.VerifyAuthToken(ctx, upstreamToken, agent.keyResolver, agent.clock)
	if err != nil {
		return TokenAuthorization{}, err
	}
	upstream, err := claimsWithoutAuthorization(upstreamEvidence)
	if err != nil {
		return TokenAuthorization{}, err
	}
	if upstream.Audience != agentClaims.Issuer {
		return TokenAuthorization{}, errors.New("reference: upstream auth-token audience does not match intermediary issuer")
	}
	if upstream.PersonServer != personServerID {
		return TokenAuthorization{}, errors.New("reference: upstream auth token ps routes to a different person server")
	}
	if !upstream.Confirmation.JWK.Equal(agent.signingKey.PublicJWK()) {
		return TokenAuthorization{}, errors.New("reference: upstream auth-token confirmation key does not match intermediary signing key")
	}
	thumbprint, err := agent.signingKey.PublicJWK().Thumbprint()
	if err != nil {
		return TokenAuthorization{}, err
	}
	if resourceGrant.Claims.Agent != "" || resourceGrant.Claims.Subject == "" ||
		resourceGrant.Claims.AgentJKT != thumbprint {
		return TokenAuthorization{}, errors.New("reference: downstream resource token is not bound to the intermediary")
	}
	return agent.requestTokenAuthorization(
		ctx,
		personServerEndpoint,
		resourceGrant,
		"",
		agent.signingKey.PublicJWK(),
		upstreamToken,
	)
}

func (agent *Agent) requestTokenAuthorization(
	ctx context.Context,
	personServerEndpoint string,
	resourceGrant ResourceGrant,
	subagentToken string,
	expectedKey jose.JWK,
	upstreamToken string,
) (TokenAuthorization, error) {
	var authorization TokenAuthorization
	personServerID, err := preflightResourceGrantPersonServer(personServerEndpoint, resourceGrant)
	if err != nil {
		return authorization, err
	}
	if err := agent.ensureAuthorizationState(ctx); err != nil {
		return authorization, err
	}
	resourceVerificationKey, err := agent.verifyResourceGrantForContinuation(ctx, resourceGrant)
	if err != nil {
		return authorization, err
	}
	expectedIssuer := resourceGrant.Claims.Audience
	tokenInput := map[string]string{"resource_token": resourceGrant.ResourceToken}
	if subagentToken != "" {
		tokenInput["subagent_token"] = subagentToken
	}
	if upstreamToken != "" {
		tokenInput["upstream_token"] = upstreamToken
	}
	tokenBody, err := json.Marshal(tokenInput)
	if err != nil {
		return authorization, err
	}
	tokenRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, personServerEndpoint, bytes.NewReader(tokenBody))
	if err != nil {
		return authorization, err
	}
	tokenRequest.Header.Set("Content-Type", "application/json")
	tokenRequest.Header.Set("Prefer", "wait=0")
	if err := agent.signRequest(tokenRequest, agent.agentToken); err != nil {
		return authorization, err
	}
	tokenResponse, err := agent.httpClient.Do(tokenRequest)
	if err != nil {
		return authorization, err
	}
	defer tokenResponse.Body.Close()
	switch tokenResponse.StatusCode {
	case http.StatusOK:
		grant, _, err := agent.parseTokenGrantResponse(
			ctx,
			tokenResponse,
			resourceGrant,
			expectedIssuer,
			expectedKey,
			"",
		)
		if err != nil {
			return authorization, err
		}
		authorization.Grant = &grant
		return authorization, nil
	case http.StatusAccepted:
		if resourceGrant.RequestedR3 != nil || resourceGrant.Budget != nil {
			return authorization, errors.New("reference: deferred companion authorization is not implemented")
		}
		deferred, err := aauth.ParseDeferredResponse(tokenResponse)
		if err != nil {
			return authorization, err
		}
		pending, err := newPendingTokenAuthorization(
			personServerID,
			resourceGrant,
			resourceVerificationKey,
			expectedIssuer,
			expectedKey,
			deferred,
			agent.clock.Now(),
		)
		if err != nil {
			return authorization, err
		}
		if err := agent.retainPendingTokenAuthorization(ctx, pending, nil, nil); err != nil {
			return authorization, err
		}
		authorization.Pending = &pending
		return authorization, nil
	default:
		return authorization, responseError(tokenResponse)
	}
}

func preflightResourceGrantPersonServer(
	personServerEndpoint string,
	resourceGrant ResourceGrant,
) (string, error) {
	if err := aauth.ValidateEndpoint(personServerEndpoint); err != nil {
		return "", err
	}
	personServerID, err := endpointIdentifier(personServerEndpoint)
	if err != nil {
		return "", err
	}
	if resourceGrant.Claims.PersonServer == "" {
		return "", errors.New("reference: current resource token ps is required")
	}
	if resourceGrant.Claims.PersonServer != personServerID {
		return "", errors.New("reference: resource token ps does not match selected person server")
	}
	if resourceGrant.RequestedR3 != nil {
		if err := resourceGrant.RequestedR3.Validate(); err != nil {
			return "", fmt.Errorf("reference: retained R3 request: %w", err)
		}
	}
	if resourceGrant.Budget != nil && !resourceGrant.Budget.Valid() {
		return "", errors.New("reference: retained Budget result is invalid")
	}
	return personServerID, nil
}

func (agent *Agent) verifyResourceGrantForContinuation(
	ctx context.Context,
	resourceGrant ResourceGrant,
) (jose.JWK, error) {
	capture, resolver := newRetainedKeyCapture(agent.keyResolver)
	evidence, err := aauth.VerifyResourceToken(ctx, resourceGrant.ResourceToken, resolver, agent.clock)
	if err != nil {
		return jose.JWK{}, err
	}
	var claims aauth.ResourceTokenClaims
	if resourceGrant.RequestedR3 == nil && resourceGrant.Budget == nil {
		claims, err = claimsWithoutAuthorization(evidence)
	} else {
		if resourceGrant.RequestedR3 != nil {
			result, validationErr := r3.ValidateResourceToken(evidence)
			if validationErr != nil {
				return jose.JWK{}, validationErr
			}
			origin, originErr := endpointIdentifier(result.URI())
			if originErr != nil || origin != resourceGrant.Resource {
				return jose.JWK{}, errors.New("reference: R3 document is outside the retained resource")
			}
		}
		if resourceGrant.Budget != nil {
			result, validationErr := budgets.ValidateResourceToken(evidence)
			if validationErr != nil || result.CoreEvidenceID() != resourceGrant.Budget.CoreEvidenceID() {
				return jose.JWK{}, errors.New("reference: Budget evidence does not match the retained resource token")
			}
		}
		claims, err = evidence.Claims()
	}
	if err != nil {
		return jose.JWK{}, err
	}
	if !reflect.DeepEqual(claims, resourceGrant.Claims) {
		return jose.JWK{}, errors.New("reference: resource token compact value does not match its retained claims")
	}
	if claims.Issuer != resourceGrant.Resource {
		return jose.JWK{}, errors.New("reference: resource token issuer does not match its resource grant")
	}
	return capture.retainedKey()
}

func (agent *Agent) retainPendingTokenAuthorization(
	ctx context.Context,
	pending PendingTokenAuthorization,
	terminal *Grant,
	terminalVerificationKey *jose.JWK,
) error {
	record := agentPendingTokenRecord{
		ID: pending.ID, PersonServer: pending.PersonServer, Location: pending.Location,
		RetryAfter: pending.RetryAfter, NotBefore: pending.NotBefore.UTC(), Status: pending.Status,
		Requirement: copyRequirement(pending.Requirement), ResourceGrant: pending.resourceGrant,
		ResourceVerificationKey: pending.resourceVerificationKey,
		ExpectedIssuer:          pending.expectedIssuer, ExpectedKey: pending.expectedKey,
	}
	if terminal != nil {
		if terminalVerificationKey == nil {
			return errors.New("reference: terminal auth-token verification key is required")
		}
		grant := *terminal
		record.TerminalGrant = &grant
		record.TerminalVerificationKey = copyJWK(terminalVerificationKey)
	} else if terminalVerificationKey != nil {
		return errors.New("reference: terminal auth-token verification key has no terminal grant")
	}
	if err := validateAgentPendingTokenRecord(record); err != nil {
		return ErrAuthorizationStateIntegrity
	}
	agent.authorizationMu.Lock()
	defer agent.authorizationMu.Unlock()
	if current, exists := agent.pendingTokens[pending.ID]; exists {
		if !sameAgentPendingTokenContext(current, record) {
			return ErrAuthorizationStateIntegrity
		}
		if current.TerminalGrant != nil {
			if record.TerminalGrant == nil ||
				!reflect.DeepEqual(current.TerminalGrant, record.TerminalGrant) ||
				current.TerminalVerificationKey == nil || record.TerminalVerificationKey == nil ||
				!current.TerminalVerificationKey.Equal(*record.TerminalVerificationKey) {
				return ErrAuthorizationStateIntegrity
			}
			return nil
		}
	}
	agent.pendingTokens[pending.ID] = record
	if err := agent.persistAuthorizationStateLocked(ctx); err != nil {
		return err
	}
	return nil
}

func sameAgentPendingTokenContext(first, second agentPendingTokenRecord) bool {
	return first.ID == second.ID && first.PersonServer == second.PersonServer &&
		first.Location == second.Location && reflect.DeepEqual(first.ResourceGrant, second.ResourceGrant) &&
		first.ResourceVerificationKey.Equal(second.ResourceVerificationKey) &&
		first.ExpectedIssuer == second.ExpectedIssuer && first.ExpectedKey.Equal(second.ExpectedKey)
}

func (agent *Agent) restorePendingTokenAuthorization(ctx context.Context, pending *PendingTokenAuthorization) (*Grant, error) {
	if pending.ID == "" {
		return nil, errors.New("reference: pending token authorization id is required")
	}
	agent.authorizationMu.Lock()
	defer agent.authorizationMu.Unlock()
	if err := agent.settleAuthorizationStateLocked(ctx); err != nil {
		return nil, err
	}
	record, exists := agent.pendingTokens[pending.ID]
	if !exists {
		return nil, errors.New("reference: pending token authorization is not retained")
	}
	*pending = PendingTokenAuthorization{
		ID: record.ID, PersonServer: record.PersonServer, Location: record.Location,
		RetryAfter: record.RetryAfter, NotBefore: record.NotBefore.UTC(), Status: record.Status,
		Requirement: copyRequirement(record.Requirement), resourceGrant: record.ResourceGrant,
		resourceVerificationKey: record.ResourceVerificationKey,
		expectedIssuer:          record.ExpectedIssuer, expectedKey: record.ExpectedKey,
	}
	if record.TerminalGrant == nil {
		return nil, nil
	}
	grant := *record.TerminalGrant
	return &grant, nil
}

func (agent *Agent) parseTokenGrantResponse(
	ctx context.Context,
	tokenResponse *http.Response,
	resourceGrant ResourceGrant,
	expectedIssuer string,
	expectedKey jose.JWK,
	expectedJTI string,
) (Grant, jose.JWK, error) {
	var tokenResult struct {
		AuthToken string `json:"auth_token"`
	}
	if err := json.NewDecoder(io.LimitReader(tokenResponse.Body, maxJSONBody)).Decode(&tokenResult); err != nil {
		return Grant{}, jose.JWK{}, err
	}
	capture, resolver := newRetainedKeyCapture(agent.keyResolver)
	authEvidence, err := aauth.VerifyAuthToken(ctx, tokenResult.AuthToken, resolver, agent.clock)
	if err != nil {
		return Grant{}, jose.JWK{}, err
	}
	var authR3 r3.TokenResult
	var authBudget budgets.TokenResult
	var authClaims aauth.AuthTokenClaims
	if resourceGrant.RequestedR3 == nil && resourceGrant.Budget == nil {
		authClaims, err = claimsWithoutAuthorization(authEvidence)
	} else {
		if resourceGrant.RequestedR3 != nil {
			authR3, err = r3.ValidateAuthToken(authEvidence)
		}
		if err == nil && resourceGrant.Budget != nil {
			authBudget, err = budgets.ValidateAuthToken(authEvidence)
		}
		if err == nil {
			authClaims, err = authEvidence.Claims()
		}
	}
	if err != nil {
		return Grant{}, jose.JWK{}, err
	}
	if expectedJTI != "" && authClaims.JTI != expectedJTI {
		return Grant{}, jose.JWK{}, errors.New("reference: deferred auth-token jti does not match its pending authorization")
	}
	requiredScopes, err := parseScopes(resourceGrant.Claims.Scope)
	if err != nil {
		return Grant{}, jose.JWK{}, err
	}
	if authClaims.ExpiresAt > resourceGrant.Claims.ExpiresAt {
		return Grant{}, jose.JWK{}, errors.New("reference: auth token outlives the resource token")
	}
	expectedDiscoveryDocument := aauth.AccessDiscoveryDocument
	if expectedIssuer == resourceGrant.Claims.PersonServer {
		expectedDiscoveryDocument = aauth.PersonDiscoveryDocument
	}
	if authClaims.Issuer != expectedIssuer ||
		authClaims.DWK != expectedDiscoveryDocument ||
		authClaims.PersonServer != resourceGrant.Claims.PersonServer ||
		authClaims.Subject != resourceGrant.Claims.Subject ||
		authClaims.MissionS256 != resourceGrant.Claims.MissionS256 ||
		authClaims.Tenant != resourceGrant.Claims.Tenant ||
		authClaims.Account != resourceGrant.Claims.Account ||
		authClaims.Agent != "" || authClaims.Actor != nil {
		return Grant{}, jose.JWK{}, errors.New("reference: current auth token issuer, discovery document, or person context does not match the resource token")
	}
	if err := aauth.ValidateCurrentAuthTokenContext(
		authClaims,
		resourceGrant.Resource,
		resourceGrant.Claims.PersonServer,
		resourceGrant.Claims.Subject,
		expectedKey,
		requiredScopes,
	); err != nil {
		return Grant{}, jose.JWK{}, err
	}
	if resourceGrant.RequestedR3 != nil {
		resourceCore, resourceErr := aauth.VerifyResourceToken(ctx, resourceGrant.ResourceToken, agent.keyResolver, agent.clock)
		if resourceErr != nil {
			return Grant{}, jose.JWK{}, resourceErr
		}
		resourceR3, resourceErr := r3.ValidateResourceToken(resourceCore)
		if resourceErr != nil {
			return Grant{}, jose.JWK{}, resourceErr
		}
		if resourceErr := r3.ValidateAuthorizationGrant(resourceR3, authR3, resourceGrant.RequestedR3.Clone()); resourceErr != nil {
			return Grant{}, jose.JWK{}, resourceErr
		}
	}
	if resourceGrant.Budget != nil {
		if err := budgets.ValidateGrant(*resourceGrant.Budget, authBudget); err != nil {
			return Grant{}, jose.JWK{}, err
		}
	}
	verificationKey, err := capture.retainedKey()
	if err != nil {
		return Grant{}, jose.JWK{}, err
	}
	grant := Grant{
		Resource:  resourceGrant.Resource,
		AuthToken: tokenResult.AuthToken,
		Claims:    authClaims,
	}
	if authR3.Valid() {
		copy := authR3
		grant.R3 = &copy
	}
	if authBudget.Valid() {
		copy := authBudget
		grant.Budget = &copy
	}
	return grant, verificationKey, nil
}

func newPendingTokenAuthorization(
	personServer string,
	resourceGrant ResourceGrant,
	resourceVerificationKey jose.JWK,
	expectedIssuer string,
	expectedKey jose.JWK,
	deferred aauth.DeferredResponse,
	now time.Time,
) (PendingTokenAuthorization, error) {
	parsed, err := url.Parse(deferred.Location)
	if err != nil {
		return PendingTokenAuthorization{}, err
	}
	locationServer, err := endpointIdentifier(deferred.Location)
	if err != nil {
		return PendingTokenAuthorization{}, err
	}
	if locationServer != personServer {
		return PendingTokenAuthorization{}, errors.New("reference: pending token authorization moved to another person server")
	}
	return PendingTokenAuthorization{
		ID:                      path.Base(parsed.Path),
		PersonServer:            personServer,
		Location:                deferred.Location,
		RetryAfter:              deferred.RetryAfter,
		NotBefore:               now.Add(deferred.RetryAfter),
		Status:                  deferred.Status,
		Requirement:             deferred.Requirement,
		resourceGrant:           resourceGrant,
		resourceVerificationKey: resourceVerificationKey,
		expectedIssuer:          expectedIssuer,
		expectedKey:             expectedKey,
	}, nil
}

// PollTokenAuthorization makes one signed GET to a pending person-server token
// request. It returns a refreshed continuation or the terminal auth-token
// grant.
func (agent *Agent) PollTokenAuthorization(
	ctx context.Context,
	pending *PendingTokenAuthorization,
) (TokenAuthorization, error) {
	var authorization TokenAuthorization
	if pending == nil {
		return authorization, errors.New("reference: pending token authorization is required")
	}
	terminal, err := agent.restorePendingTokenAuthorization(ctx, pending)
	if err != nil {
		return authorization, err
	}
	if terminal != nil {
		authorization.Grant = terminal
		return authorization, nil
	}
	if agent.clock.Now().Before(pending.NotBefore) {
		return authorization, errors.New("reference: pending token authorization is not ready to poll")
	}
	if err := aauth.ValidatePollingEndpoint(pending.Location); err != nil {
		return authorization, err
	}
	personServer, err := endpointIdentifier(pending.Location)
	if err != nil {
		return authorization, err
	}
	if personServer != pending.PersonServer {
		return authorization, errors.New("reference: pending token authorization does not apply to its endpoint")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, pending.Location, nil)
	if err != nil {
		return authorization, err
	}
	request.Header.Set("Prefer", "wait=0")
	if err := agent.signRequest(request, agent.agentToken); err != nil {
		return authorization, err
	}
	response, err := agent.httpClient.Do(request)
	if err != nil {
		return authorization, err
	}
	defer response.Body.Close()

	switch response.StatusCode {
	case http.StatusOK:
		grant, verificationKey, err := agent.parseTokenGrantResponse(
			ctx,
			response,
			pending.resourceGrant,
			pending.expectedIssuer,
			pending.expectedKey,
			pending.ID,
		)
		if err != nil {
			return authorization, err
		}
		if err := agent.retainPendingTokenAuthorization(ctx, *pending, &grant, &verificationKey); err != nil {
			return authorization, err
		}
		authorization.Grant = &grant
		return authorization, nil
	case http.StatusAccepted:
		deferred, err := aauth.ParseDeferredResponse(response)
		if err != nil {
			return authorization, err
		}
		next, err := newPendingTokenAuthorization(
			pending.PersonServer,
			pending.resourceGrant,
			pending.resourceVerificationKey,
			pending.expectedIssuer,
			pending.expectedKey,
			deferred,
			agent.clock.Now(),
		)
		if err != nil {
			return authorization, err
		}
		*pending = next
		if err := agent.retainPendingTokenAuthorization(ctx, *pending, nil, nil); err != nil {
			return authorization, err
		}
		authorization.Pending = pending
		return authorization, nil
	default:
		responseErr := responseError(response)
		updatePollingBackoff(
			response,
			&pending.RetryAfter,
			&pending.NotBefore,
			agent.clock.Now(),
		)
		if err := agent.retainPendingTokenAuthorization(ctx, *pending, nil, nil); err != nil {
			return authorization, err
		}
		return authorization, responseErr
	}
}

func copyActor(actor *aauth.Actor) *aauth.Actor {
	if actor == nil {
		return nil
	}
	return &aauth.Actor{
		Agent: actor.Agent,
		Actor: copyActor(actor.Actor),
	}
}

func (agent *Agent) DoAuthorized(
	ctx context.Context,
	method string,
	endpoint string,
	grant Grant,
) (*http.Response, error) {
	return agent.DoAuthorizedRequest(ctx, AuthorizedCall{
		Method:   method,
		Endpoint: endpoint,
	}, grant)
}

// DoWithPersonToken signs and sends one exact call using a resource-directed
// person token. The resource, not the person server, owns the authorization
// decision for this access mode.
func (agent *Agent) DoWithPersonToken(
	ctx context.Context,
	call AuthorizedCall,
	personToken string,
) (*http.Response, error) {
	evidence, err := aauth.VerifyPersonToken(ctx, personToken, agent.keyResolver, agent.clock)
	if err != nil {
		return nil, err
	}
	claims, err := claimsWithoutAuthorization(evidence)
	if err != nil {
		return nil, err
	}
	resource, err := endpointIdentifier(call.Endpoint)
	if err != nil {
		return nil, err
	}
	if err := aauth.ValidatePersonTokenContext(claims, resource, agent.signingKey.PublicJWK()); err != nil {
		return nil, err
	}
	request, err := agent.newAuthorizedCallRequest(ctx, call, personToken)
	if err != nil {
		return nil, err
	}
	return agent.httpClient.Do(request)
}

// DoWithPersonTokenAuthorization starts one exact protected call with a
// resource-directed person token, satisfies the resource's immediate auth-token
// challenge through the selected person server, and retries the same call under
// the resulting grant. For stateful 202 delivery it completes at the retained
// pending URL and retries one lost terminal response safely.
func (agent *Agent) DoWithPersonTokenAuthorization(
	ctx context.Context,
	call AuthorizedCall,
	personServerEndpoint string,
	personToken string,
) (*http.Response, Grant, error) {
	var zero Grant
	personServer, err := endpointIdentifier(personServerEndpoint)
	if err != nil {
		return nil, zero, err
	}
	personEvidence, err := aauth.VerifyPersonToken(ctx, personToken, agent.keyResolver, agent.clock)
	if err != nil {
		return nil, zero, err
	}
	person, err := claimsWithoutAuthorization(personEvidence)
	if err != nil {
		return nil, zero, err
	}
	if person.Issuer != personServer {
		return nil, zero, errors.New("reference: person token issuer does not match selected person server")
	}
	resource, err := endpointIdentifier(call.Endpoint)
	if err != nil {
		return nil, zero, err
	}
	if err := aauth.ValidatePersonTokenContext(person, resource, agent.signingKey.PublicJWK()); err != nil {
		return nil, zero, err
	}
	request, err := agent.newAuthorizedCallRequest(ctx, call, personToken)
	if err != nil {
		return nil, zero, err
	}
	challenge, err := agent.httpClient.Do(request)
	if err != nil {
		return nil, zero, err
	}
	var requirement aauth.Requirement
	deferredLocation := ""
	switch challenge.StatusCode {
	case http.StatusUnauthorized:
		requirement, err = aauth.ParseRequirementHeader(challenge.Header.Get("AAuth-Requirement"))
		challenge.Body.Close()
	case http.StatusAccepted:
		deferred, deferredErr := aauth.ParseDeferredResponse(challenge)
		challenge.Body.Close()
		if deferredErr != nil || deferred.Requirement == nil {
			return nil, zero, errors.New("reference: protected response is not a valid deferred auth-token challenge")
		}
		requirement = *deferred.Requirement
		deferredLocation = deferred.Location
		err = nil
	default:
		defer challenge.Body.Close()
		return nil, zero, responseError(challenge)
	}
	if err != nil || requirement.Type != aauth.RequirementAuthToken {
		return nil, zero, errors.New("reference: protected response is not an auth-token challenge")
	}
	resourceGrant, err := agent.resourceGrantFromChallenge(ctx, resource, person, requirement.ResourceToken)
	if err != nil {
		return nil, zero, err
	}
	grant, err := agent.ExchangeResourceToken(ctx, personServerEndpoint, resourceGrant)
	if err != nil {
		return nil, zero, err
	}
	completion := call
	if deferredLocation != "" {
		completion = AuthorizedCall{Method: http.MethodGet, Endpoint: deferredLocation}
	}
	response, err := agent.DoAuthorizedRequest(ctx, completion, grant)
	if err != nil && deferredLocation != "" {
		response, err = agent.DoAuthorizedRequest(ctx, completion, grant)
	}
	if err != nil {
		return nil, zero, err
	}
	return response, grant, nil
}

func (agent *Agent) resourceGrantFromChallenge(
	ctx context.Context,
	resource string,
	person aauth.PersonTokenClaims,
	compact string,
) (ResourceGrant, error) {
	evidence, err := aauth.VerifyResourceToken(ctx, compact, agent.keyResolver, agent.clock)
	if err != nil {
		return ResourceGrant{}, err
	}
	members, err := evidence.AuthorizationMembers()
	if err != nil {
		return ResourceGrant{}, err
	}
	if _, hasR3 := members["r3_uri"]; hasR3 {
		return ResourceGrant{}, errors.New("reference: protected-call R3 challenge verification is not implemented")
	}
	var budget budgets.TokenResult
	if _, hasBudget := members["budget"]; hasBudget {
		budget, err = budgets.ValidateResourceToken(evidence)
	} else {
		err = evidence.RequireNoAuthorizationMembers()
	}
	if err != nil {
		return ResourceGrant{}, err
	}
	claims, err := evidence.Claims()
	if err != nil {
		return ResourceGrant{}, err
	}
	thumbprint, err := agent.signingKey.PublicJWK().Thumbprint()
	if err != nil {
		return ResourceGrant{}, err
	}
	if claims.Issuer != resource || claims.PersonServer != person.Issuer ||
		claims.Subject != person.Subject || claims.PresentedJTI != person.JTI ||
		claims.AgentJKT != thumbprint || claims.MissionS256 != person.MissionS256 ||
		claims.Tenant != person.Tenant || claims.Account != "" || claims.Agent != "" {
		return ResourceGrant{}, errors.New("reference: resource challenge does not match the presented person token and protected call")
	}
	if _, err := parseScopes(claims.Scope); err != nil {
		return ResourceGrant{}, errors.New("reference: resource challenge carries an invalid scope")
	}
	return ResourceGrant{
		Resource: resource, ResourceToken: compact, Claims: claims,
		Budget: optionalBudgetResult(budget),
	}, nil
}

// DoAuthorizedRequest signs and sends one exact HTTP call under a grant.
func (agent *Agent) DoAuthorizedRequest(
	ctx context.Context,
	call AuthorizedCall,
	grant Grant,
) (*http.Response, error) {
	resourceID, err := endpointIdentifier(call.Endpoint)
	if err != nil {
		return nil, err
	}
	if resourceID != grant.Resource || grant.AuthToken == "" {
		return nil, errors.New("reference: grant does not apply to endpoint")
	}
	request, err := agent.newAuthorizedCallRequest(ctx, call, grant.AuthToken)
	if err != nil {
		return nil, err
	}
	return agent.httpClient.Do(request)
}

func (agent *Agent) newAuthorizedCallRequest(
	ctx context.Context,
	call AuthorizedCall,
	credential string,
) (*http.Request, error) {
	if err := validateAuthorizedCallEndpoint(call.Endpoint); err != nil {
		return nil, err
	}
	if credential == "" {
		return nil, errors.New("reference: authorized request credential is required")
	}
	if len(call.Body) != 0 && strings.TrimSpace(call.ContentType) == "" {
		return nil, errors.New("reference: authorized request body requires a content type")
	}
	var body io.Reader
	if call.Body != nil {
		body = bytes.NewReader(append([]byte(nil), call.Body...))
	}
	request, err := http.NewRequestWithContext(ctx, call.Method, call.Endpoint, body)
	if err != nil {
		return nil, err
	}
	if call.ContentType != "" {
		request.Header.Set("Content-Type", call.ContentType)
	}
	if err := agent.signRequest(request, credential); err != nil {
		return nil, err
	}
	return request, nil
}

func validateAuthorizedCallEndpoint(endpoint string) error {
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" || parsed.Opaque != "" {
		return errors.New("reference: authorized call requires an absolute HTTPS URL without userinfo or fragment")
	}
	_, err = endpointIdentifier(endpoint)
	return err
}

// RequestResourceManagedAccess starts the current resource-managed flow at the
// protected endpoint with the agent token. A successful local decision returns
// an opaque session credential; a deferred decision returns a signed-poll
// continuation. The protected consequence is retried separately with the
// resulting credential.
func (agent *Agent) RequestResourceManagedAccess(
	ctx context.Context,
	call AuthorizedCall,
) (AccessAuthorization, error) {
	var authorization AccessAuthorization
	if err := agent.ensureAuthorizationState(ctx); err != nil {
		return authorization, err
	}
	if err := aauth.ValidateEndpoint(call.Endpoint); err != nil {
		return authorization, err
	}
	if strings.TrimSpace(call.Method) == "" {
		return authorization, errors.New("reference: resource-managed authorization method is required")
	}
	if len(call.Body) != 0 && strings.TrimSpace(call.ContentType) == "" {
		return authorization, errors.New("reference: resource-managed authorization body requires a content type")
	}
	var body io.Reader
	if call.Body != nil {
		body = bytes.NewReader(append([]byte(nil), call.Body...))
	}
	request, err := http.NewRequestWithContext(ctx, call.Method, call.Endpoint, body)
	if err != nil {
		return authorization, err
	}
	if call.ContentType != "" {
		request.Header.Set("Content-Type", call.ContentType)
	}
	request.Header.Set("Prefer", "wait=0")
	if err := agent.signRequest(request, agent.agentToken); err != nil {
		return authorization, err
	}
	response, err := agent.httpClient.Do(request)
	if err != nil {
		return authorization, err
	}
	defer response.Body.Close()
	resourceID, err := endpointIdentifier(call.Endpoint)
	if err != nil {
		return authorization, err
	}
	switch response.StatusCode {
	case http.StatusOK:
		grant, err := parseAccessGrantResponse(response, resourceID, nil)
		if err != nil {
			return authorization, err
		}
		authorization.Grant = &grant
		return authorization, nil
	case http.StatusAccepted:
		deferred, err := aauth.ParseDeferredResponse(response)
		if err != nil {
			return authorization, err
		}
		pending, err := newPendingAccessAuthorization(resourceID, nil, deferred, agent.clock.Now())
		if err != nil {
			return authorization, err
		}
		if err := agent.retainPendingAccessAuthorization(ctx, pending, nil); err != nil {
			return authorization, err
		}
		authorization.Pending = &pending
		return authorization, nil
	default:
		return authorization, responseError(response)
	}
}

func parseAccessGrantResponse(
	response *http.Response,
	resourceID string,
	requestedScopes []string,
) (AccessGrant, error) {
	var grant AccessGrant
	values := response.Header.Values("AAuth-Access")
	if len(values) != 1 {
		return grant, errors.New("reference: resource did not return exactly one AAuth-Access credential")
	}
	if err := aauth.ValidateAccessToken(values[0]); err != nil {
		return grant, err
	}
	responseBody, err := io.ReadAll(io.LimitReader(response.Body, maxJSONBody+1))
	if err != nil {
		return grant, err
	}
	if len(responseBody) > maxJSONBody {
		return grant, errors.New("reference: authorization response is too large")
	}
	var result struct {
		Status string `json:"status"`
		Scope  string `json:"scope"`
	}
	if err := json.Unmarshal(responseBody, &result); err != nil {
		return grant, fmt.Errorf("reference: decode authorization response: %w", err)
	}
	grantedScopes, err := parseScopes(result.Scope)
	if err != nil {
		return grant, fmt.Errorf("reference: invalid granted scope: %w", err)
	}
	if result.Status != "authorized" || len(requestedScopes) != 0 && !scopesContained(grantedScopes, requestedScopes) {
		return grant, errors.New("reference: authorization response contains an invalid status or scope")
	}
	return AccessGrant{
		Resource: resourceID,
		Token:    values[0],
		Scope:    append([]string(nil), grantedScopes...),
	}, nil
}

func newPendingAccessAuthorization(
	resourceID string,
	requestedScope []string,
	deferred aauth.DeferredResponse,
	now time.Time,
) (PendingAccessAuthorization, error) {
	parsed, err := url.Parse(deferred.Location)
	if err != nil {
		return PendingAccessAuthorization{}, err
	}
	locationResource, err := endpointIdentifier(deferred.Location)
	if err != nil {
		return PendingAccessAuthorization{}, err
	}
	if locationResource != resourceID {
		return PendingAccessAuthorization{}, errors.New("reference: pending authorization moved to another resource")
	}
	return PendingAccessAuthorization{
		ID:             path.Base(parsed.Path),
		Resource:       resourceID,
		Location:       deferred.Location,
		RetryAfter:     deferred.RetryAfter,
		NotBefore:      now.Add(deferred.RetryAfter),
		Status:         deferred.Status,
		Requirement:    deferred.Requirement,
		requestedScope: append([]string(nil), requestedScope...),
	}, nil
}

func (agent *Agent) retainPendingAccessAuthorization(ctx context.Context, pending PendingAccessAuthorization, terminal *AccessGrant) error {
	record := agentPendingAccessRecord{
		ID: pending.ID, Resource: pending.Resource, Location: pending.Location,
		RetryAfter: pending.RetryAfter, NotBefore: pending.NotBefore.UTC(), Status: pending.Status,
		Requirement: copyRequirement(pending.Requirement), RequestedScope: append([]string(nil), pending.requestedScope...),
	}
	if terminal != nil {
		grant := *terminal
		grant.Scope = append([]string(nil), terminal.Scope...)
		record.TerminalGrant = &grant
	}
	if err := validateAgentPendingAccessRecord(record); err != nil {
		return ErrAuthorizationStateIntegrity
	}
	agent.authorizationMu.Lock()
	defer agent.authorizationMu.Unlock()
	if current, exists := agent.pendingAccess[pending.ID]; exists {
		if !sameAgentPendingAccessContext(current, record) {
			return ErrAuthorizationStateIntegrity
		}
		if current.TerminalGrant != nil {
			if record.TerminalGrant == nil || !reflect.DeepEqual(current.TerminalGrant, record.TerminalGrant) {
				return ErrAuthorizationStateIntegrity
			}
			return nil
		}
	}
	agent.pendingAccess[pending.ID] = record
	if err := agent.persistAuthorizationStateLocked(ctx); err != nil {
		return err
	}
	return nil
}

func sameAgentPendingAccessContext(first, second agentPendingAccessRecord) bool {
	return first.ID == second.ID && first.Resource == second.Resource && first.Location == second.Location &&
		reflect.DeepEqual(first.RequestedScope, second.RequestedScope)
}

func (agent *Agent) restorePendingAccessAuthorization(ctx context.Context, pending *PendingAccessAuthorization) (*AccessGrant, error) {
	if pending.ID == "" {
		return nil, errors.New("reference: pending access authorization id is required")
	}
	agent.authorizationMu.Lock()
	defer agent.authorizationMu.Unlock()
	if err := agent.settleAuthorizationStateLocked(ctx); err != nil {
		return nil, err
	}
	record, exists := agent.pendingAccess[pending.ID]
	if !exists {
		return nil, errors.New("reference: pending access authorization is not retained")
	}
	*pending = PendingAccessAuthorization{
		ID: record.ID, Resource: record.Resource, Location: record.Location,
		RetryAfter: record.RetryAfter, NotBefore: record.NotBefore.UTC(), Status: record.Status,
		Requirement: copyRequirement(record.Requirement), requestedScope: append([]string(nil), record.RequestedScope...),
	}
	if record.TerminalGrant == nil {
		return nil, nil
	}
	grant := *record.TerminalGrant
	grant.Scope = append([]string(nil), record.TerminalGrant.Scope...)
	return &grant, nil
}

// PollResourceManagedAccess makes one signed GET to a pending resource
// authorization. It returns another pending continuation or the terminal grant.
func (agent *Agent) PollResourceManagedAccess(
	ctx context.Context,
	pending *PendingAccessAuthorization,
) (AccessAuthorization, error) {
	var authorization AccessAuthorization
	if pending == nil {
		return authorization, errors.New("reference: pending access authorization is required")
	}
	terminal, err := agent.restorePendingAccessAuthorization(ctx, pending)
	if err != nil {
		return authorization, err
	}
	if terminal != nil {
		authorization.Grant = terminal
		return authorization, nil
	}
	if agent.clock.Now().Before(pending.NotBefore) {
		return authorization, errors.New("reference: pending authorization is not ready to poll")
	}
	if err := aauth.ValidatePollingEndpoint(pending.Location); err != nil {
		return authorization, err
	}
	resourceID, err := endpointIdentifier(pending.Location)
	if err != nil {
		return authorization, err
	}
	if resourceID != pending.Resource {
		return authorization, errors.New("reference: pending authorization does not apply to its endpoint")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, pending.Location, nil)
	if err != nil {
		return authorization, err
	}
	request.Header.Set("Prefer", "wait=0")
	if err := agent.signRequest(request, agent.agentToken); err != nil {
		return authorization, err
	}
	response, err := agent.httpClient.Do(request)
	if err != nil {
		return authorization, err
	}
	defer response.Body.Close()
	switch response.StatusCode {
	case http.StatusOK:
		grant, err := parseAccessGrantResponse(response, pending.Resource, pending.requestedScope)
		if err != nil {
			return authorization, err
		}
		if err := agent.retainPendingAccessAuthorization(ctx, *pending, &grant); err != nil {
			return authorization, err
		}
		authorization.Grant = &grant
		return authorization, nil
	case http.StatusAccepted:
		deferred, err := aauth.ParseDeferredResponse(response)
		if err != nil {
			return authorization, err
		}
		next, err := newPendingAccessAuthorization(
			pending.Resource,
			pending.requestedScope,
			deferred,
			agent.clock.Now(),
		)
		if err != nil {
			return authorization, err
		}
		*pending = next
		if err := agent.retainPendingAccessAuthorization(ctx, *pending, nil); err != nil {
			return authorization, err
		}
		authorization.Pending = pending
		return authorization, nil
	default:
		responseErr := responseError(response)
		updatePollingBackoff(
			response,
			&pending.RetryAfter,
			&pending.NotBefore,
			agent.clock.Now(),
		)
		if err := agent.retainPendingAccessAuthorization(ctx, *pending, nil); err != nil {
			return authorization, err
		}
		return authorization, responseErr
	}
}

func updatePollingBackoff(
	response *http.Response,
	retryAfter *time.Duration,
	notBefore *time.Time,
	now time.Time,
) {
	switch response.StatusCode {
	case http.StatusTooManyRequests:
		*retryAfter += 5 * time.Second
		*notBefore = now.Add(*retryAfter)
	case http.StatusServiceUnavailable:
		delay, err := responseRetryAfter(response.Header.Values("Retry-After"), now)
		if err != nil {
			delay = 5 * time.Second
		}
		*retryAfter = delay
		*notBefore = now.Add(delay)
	}
}

func responseRetryAfter(values []string, now time.Time) (time.Duration, error) {
	if len(values) != 1 {
		return 0, errors.New("reference: response requires exactly one Retry-After")
	}
	value := strings.TrimSpace(values[0])
	if seconds, err := strconv.ParseUint(value, 10, 31); err == nil {
		return time.Duration(seconds) * time.Second, nil
	}
	at, err := http.ParseTime(value)
	if err != nil {
		return 0, errors.New("reference: response Retry-After is invalid")
	}
	if !at.After(now) {
		return 0, nil
	}
	return at.Sub(now), nil
}

// DoWithAccess signs and sends a request using a resource-managed grant. The
// grant is updated in place when the resource rotates AAuth-Access.
func (agent *Agent) DoWithAccess(
	ctx context.Context,
	call AuthorizedCall,
	grant *AccessGrant,
) (*http.Response, error) {
	if grant == nil {
		return nil, errors.New("reference: access grant is required")
	}
	if err := aauth.ValidateEndpoint(call.Endpoint); err != nil {
		return nil, err
	}
	if len(call.Body) != 0 && strings.TrimSpace(call.ContentType) == "" {
		return nil, errors.New("reference: body-bearing authorized call requires content type")
	}
	resourceID, err := endpointIdentifier(call.Endpoint)
	if err != nil {
		return nil, err
	}
	if resourceID != grant.Resource {
		return nil, errors.New("reference: access grant does not apply to endpoint")
	}
	authorization, err := aauth.AccessAuthorization(grant.Token)
	if err != nil {
		return nil, err
	}
	request, err := http.NewRequestWithContext(ctx, call.Method, call.Endpoint, bytes.NewReader(call.Body))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Authorization", authorization)
	if call.ContentType != "" {
		request.Header.Set("Content-Type", call.ContentType)
	}
	if err := agent.signRequest(request, agent.agentToken); err != nil {
		return nil, err
	}
	response, err := agent.httpClient.Do(request)
	if err != nil {
		return nil, err
	}
	values := response.Header.Values("AAuth-Access")
	if len(values) == 0 {
		return response, nil
	}
	if len(values) != 1 {
		response.Body.Close()
		return nil, errors.New("reference: resource returned more than one AAuth-Access credential")
	}
	if err := aauth.ValidateAccessToken(values[0]); err != nil {
		response.Body.Close()
		return nil, err
	}
	grant.Token = values[0]
	return response, nil
}

func responseError(response *http.Response) error {
	if strings.HasPrefix(
		strings.ToLower(response.Header.Get("Content-Type")),
		"application/problem+json",
	) {
		problem, err := aauth.DecodeProblemResponse(response)
		if err != nil {
			return err
		}
		return problem
	}
	body, _ := io.ReadAll(io.LimitReader(response.Body, 8<<10))
	return fmt.Errorf("reference: server returned %s: %s", response.Status, strings.TrimSpace(string(body)))
}
