package reference

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/r3"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"

	aauth "gitlab.com/sidecat-dev/aauth-go"
)

type AccessServerConfig struct {
	Identifier          string
	SigningKey          jose.SigningKey
	KeyResolver         signaturekey.KeyResolver
	Clock               aauth.Clock
	NewID               func() string
	TrustedPersonServer func(context.Context, string) error
	// TrustedUpstreamIssuer admits auth-token issuers whose established
	// authorization the access server may extend through call chaining.
	TrustedUpstreamIssuer func(context.Context, string) error
	AuthorizationPolicy   aauth.AuthorizationPolicy
	InteractionRequired   func(context.Context, aauth.AuthorizationRequest) (bool, error)
	Random                io.Reader
	PendingLifetime       time.Duration
	AuthorizationStore    AuthorizationStateStore
	R3HTTPClient          *http.Client
	R3Admit               func(context.Context, string) error
	R3GrantPolicy         R3GrantPolicy
	R3FetchTimeout        time.Duration
}

type AccessServer struct {
	identifier            string
	signingKey            jose.SigningKey
	keyResolver           signaturekey.KeyResolver
	clock                 aauth.Clock
	newID                 func() string
	trustedPersonServer   func(context.Context, string) error
	trustedUpstreamIssuer func(context.Context, string) error
	authorizationPolicy   aauth.AuthorizationPolicy
	interactionRequired   func(context.Context, aauth.AuthorizationRequest) (bool, error)
	random                io.Reader
	pendingLifetime       time.Duration
	authorizationStore    AuthorizationStateStore
	r3HTTPClient          *http.Client
	r3Admit               func(context.Context, string) error
	r3GrantPolicy         R3GrantPolicy
	r3FetchTimeout        time.Duration
	replayMu              sync.Mutex
	replayedProof         map[string]time.Time
	randomMu              sync.Mutex
	pendingMu             sync.Mutex
	authorizationErr      error
	authorizationBody     []byte
	authorizationRecovery []byte
	pending               map[string]*pendingAccessServerAuthorization
}

type accessServerAuthorizationContext struct {
	request               aauth.AuthorizationRequest
	requestBody           []byte
	requestProof          *aauth.RequestProof
	resourceToken         aauth.ResourceTokenClaims
	resourceTokenCompact  string
	agentTokenCompact     string
	subagentTokenCompact  string
	upstreamTokenCompact  string
	tokenVerificationKeys retainedAuthorizationTokenKeys
	targetAgent           string
	targetKey             jose.JWK
	parentAgent           string
	targetTokenExpiresAt  int64
	pollingServer         string
	pollingKey            jose.JWK
	pollingKeyThumbprint  string
	r3Grant               *r3.DirectGrant
}

type pendingAccessServerAuthorization struct {
	pendingInteraction
	context                 accessServerAuthorizationContext
	decision                aauth.AuthorizationDecision
	terminalAuthToken       string
	terminalVerificationKey *jose.JWK
	terminalExpiresAt       int64
	terminalStatus          int
	terminalCode            string
	terminalDetail          string
}

const accessAuthorizationStateSchema = "aauth.reference.access-authorization-state"

type accessAuthorizationStateRecord struct {
	Key                     string                           `json:"key"`
	Interaction             pendingInteractionRecord         `json:"interaction"`
	Context                 accessAuthorizationContextRecord `json:"context"`
	Decision                aauth.AuthorizationDecision      `json:"decision"`
	TerminalAuthToken       string                           `json:"terminal_auth_token,omitempty"`
	TerminalVerificationKey *jose.JWK                        `json:"terminal_verification_key,omitempty"`
	TerminalExpiresAt       int64                            `json:"terminal_expires_at,omitempty"`
	TerminalStatus          int                              `json:"terminal_status,omitempty"`
	TerminalCode            string                           `json:"terminal_code,omitempty"`
	TerminalDetail          string                           `json:"terminal_detail,omitempty"`
}

type accessAuthorizationContextRecord struct {
	Request               aauth.AuthorizationRequest     `json:"request"`
	RequestBody           []byte                         `json:"request_body"`
	RequestProof          *aauth.RequestProof            `json:"request_proof"`
	ResourceToken         aauth.ResourceTokenClaims      `json:"resource_token_claims"`
	ResourceTokenCompact  string                         `json:"resource_token"`
	AgentTokenCompact     string                         `json:"agent_token"`
	SubagentTokenCompact  string                         `json:"subagent_token,omitempty"`
	UpstreamTokenCompact  string                         `json:"upstream_token,omitempty"`
	TokenVerificationKeys retainedAuthorizationTokenKeys `json:"token_verification_keys"`
	TargetAgent           string                         `json:"target_agent"`
	TargetKey             jose.JWK                       `json:"target_key"`
	ParentAgent           string                         `json:"parent_agent,omitempty"`
	TargetTokenExpiresAt  int64                          `json:"target_token_expires_at"`
	PollingServer         string                         `json:"polling_server"`
	PollingKey            jose.JWK                       `json:"polling_key"`
	PollingKeyThumbprint  string                         `json:"polling_key_thumbprint"`
}

type accessAuthorizationTokenInput struct {
	ResourceToken string `json:"resource_token"`
	AgentToken    string `json:"agent_token"`
	SubagentToken string `json:"subagent_token,omitempty"`
	UpstreamToken string `json:"upstream_token,omitempty"`
}

func NewAccessServer(config AccessServerConfig) (*AccessServer, error) {
	if err := aauth.ValidateServerIdentifier(config.Identifier); err != nil {
		return nil, err
	}
	if config.SigningKey.ID() == "" || config.KeyResolver == nil || config.Clock == nil ||
		config.NewID == nil || config.TrustedPersonServer == nil || config.AuthorizationPolicy == nil ||
		config.AuthorizationStore == nil {
		return nil, errors.New("reference: access server requires key, resolver, clock, id source, trust, policy, and authorization state store")
	}
	r3Parts := 0
	if config.R3HTTPClient != nil {
		r3Parts++
	}
	if config.R3Admit != nil {
		r3Parts++
	}
	if config.R3GrantPolicy != nil {
		r3Parts++
	}
	if r3Parts != 0 && r3Parts != 3 {
		return nil, errors.New("reference: access-server R3 requires HTTP client, egress admission, and grant policy")
	}
	if config.R3FetchTimeout < 0 {
		return nil, errors.New("reference: access-server R3 fetch timeout is invalid")
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
	server := &AccessServer{
		identifier:            config.Identifier,
		signingKey:            config.SigningKey,
		keyResolver:           config.KeyResolver,
		clock:                 config.Clock,
		newID:                 config.NewID,
		trustedPersonServer:   config.TrustedPersonServer,
		trustedUpstreamIssuer: config.TrustedUpstreamIssuer,
		authorizationPolicy:   config.AuthorizationPolicy,
		interactionRequired:   config.InteractionRequired,
		random:                random,
		pendingLifetime:       pendingLifetime,
		authorizationStore:    config.AuthorizationStore,
		r3HTTPClient:          config.R3HTTPClient,
		r3Admit:               config.R3Admit,
		r3GrantPolicy:         config.R3GrantPolicy,
		r3FetchTimeout:        config.R3FetchTimeout,
		replayedProof:         make(map[string]time.Time),
		pending:               make(map[string]*pendingAccessServerAuthorization),
	}
	if err := server.loadAuthorizationState(context.Background()); err != nil {
		return nil, fmt.Errorf("reference: load access authorization state: %w", err)
	}
	return server, nil
}

func (server *AccessServer) loadAuthorizationState(ctx context.Context) error {
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

func (server *AccessServer) restoreAuthorizationStateLocked(body []byte) error {
	rawRecords, err := decodeAuthorizationStateRecords(body, accessAuthorizationStateSchema)
	if err != nil {
		return err
	}
	pending := make(map[string]*pendingAccessServerAuthorization, len(rawRecords))
	previous := ""
	for _, raw := range rawRecords {
		var record accessAuthorizationStateRecord
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
		if err := server.validateAccessAuthorizationStateRecord(record); err != nil {
			return err
		}
		pending[record.Key] = &pendingAccessServerAuthorization{
			pendingInteraction: interaction,
			context:            restoreAccessAuthorizationContext(record.Context), decision: record.Decision,
			terminalAuthToken:       record.TerminalAuthToken,
			terminalVerificationKey: copyJWK(record.TerminalVerificationKey),
			terminalExpiresAt:       record.TerminalExpiresAt,
			terminalStatus:          record.TerminalStatus, terminalCode: record.TerminalCode, terminalDetail: record.TerminalDetail,
		}
	}
	server.pending = pending
	return nil
}

func (server *AccessServer) validateAccessAuthorizationStateRecord(record accessAuthorizationStateRecord) error {
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
	if validateLocalAuthorizationInteraction(record.Interaction) != nil {
		return ErrAuthorizationStateIntegrity
	}
	if !validPendingID(record.Key) || record.TerminalStatus != 0 ||
		record.TerminalCode != "" || record.TerminalDetail != "" {
		return ErrAuthorizationStateIntegrity
	}
	if record.Interaction.State == pendingAuthorizationApproved && record.Decision.Subject == "" {
		return ErrAuthorizationStateIntegrity
	}
	if err := server.validateAccessAuthorizationContext(record); err != nil {
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
	if (record.Interaction.State == pendingAuthorizationApproved) != (record.Decision.Subject != "") {
		return ErrAuthorizationStateIntegrity
	}
	if err := server.validateAccessTerminalToken(record); err != nil {
		return ErrAuthorizationStateIntegrity
	}
	return nil
}

func (server *AccessServer) validateAccessAuthorizationContext(record accessAuthorizationStateRecord) error {
	value := record.Context
	if err := server.validateAccessAuthorizationRequestEvidence(value); err != nil {
		return err
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
	if resource.Audience != server.identifier || resource.PersonServer == "" {
		return ErrAuthorizationStateIntegrity
	}
	scopes, err := parseScopes(resource.Scope)
	if err != nil || !slices.Equal(scopes, value.Request.Scope) ||
		value.Request.PersonServer != resource.PersonServer || value.Request.Subject != resource.Subject ||
		value.Request.Resource != resource.Issuer || !reflect.DeepEqual(value.Request.Mission, resource.Mission) ||
		value.Request.MissionS256 != resource.MissionS256 || value.Request.Tenant != resource.Tenant ||
		value.Request.Account != resource.Account || value.Request.Justification != "" ||
		value.PollingServer != resource.PersonServer {
		return ErrAuthorizationStateIntegrity
	}
	agent, err := verifyRetainedAgentTokenAt(
		value.AgentTokenCompact,
		value.TokenVerificationKeys.Agent,
		verifiedAt,
	)
	if err != nil || agent.ParentAgent != "" ||
		(value.UpstreamTokenCompact == "" && agent.PersonServer != value.PollingServer) {
		return ErrAuthorizationStateIntegrity
	}
	if agent.IssuedAt > latestInputIssuedAt {
		latestInputIssuedAt = agent.IssuedAt
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
			(value.UpstreamTokenCompact == "" && subagent.PersonServer != value.PollingServer) {
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
			upstream.PersonServer != value.PollingServer ||
			!upstream.Confirmation.JWK.Equal(agent.Confirmation.JWK) ||
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
	pollingThumbprint, pollingErr := value.PollingKey.Thumbprint()
	if err != nil || pollingErr != nil || targetThumbprint != resource.AgentJKT ||
		!value.TargetKey.Equal(targetKey) || pollingThumbprint != value.PollingKeyThumbprint ||
		value.TargetAgent != targetAgent || value.ParentAgent != parentAgent ||
		value.Request.Agent != targetAgent || value.Request.ParentAgent != parentAgent ||
		value.TargetTokenExpiresAt != targetExpiresAt ||
		!record.Interaction.ExpiresAt.After(time.Unix(latestInputIssuedAt, 0)) ||
		record.Interaction.ExpiresAt.After(time.Unix(value.TargetTokenExpiresAt, 0)) ||
		record.Interaction.ExpiresAt.After(time.Unix(resource.ExpiresAt, 0)) {
		return ErrAuthorizationStateIntegrity
	}
	return nil
}

func (server *AccessServer) validateAccessAuthorizationRequestEvidence(
	value accessAuthorizationContextRecord,
) error {
	if len(value.RequestBody) == 0 || len(value.RequestBody) > maxJSONBody || value.RequestProof == nil {
		return ErrAuthorizationStateIntegrity
	}
	var input accessAuthorizationTokenInput
	if err := decodeJSONBytes(bytes.NewReader(value.RequestBody), &input); err != nil ||
		input.ResourceToken != value.ResourceTokenCompact ||
		input.AgentToken != value.AgentTokenCompact ||
		input.SubagentToken != value.SubagentTokenCompact ||
		input.UpstreamToken != value.UpstreamTokenCompact {
		return ErrAuthorizationStateIntegrity
	}
	proof := value.RequestProof
	if proof.Method != http.MethodPost || proof.Target != "/token" || proof.Authority == "" ||
		proof.ContentDigest == "" || proof.ContentType == "" || proof.SignatureInput == "" ||
		proof.Signature == "" || proof.SignatureKey == "" ||
		proof.SignatureKeyType != string(signaturekey.SchemeJWKSURI) || proof.CredentialType != "" ||
		proof.CredentialIssuer != "" || proof.Authorization != "" ||
		proof.Signer == "" || proof.Agent != "" || proof.VerifiedAt.IsZero() ||
		proof.Signer != value.PollingServer || !proof.PublicKey.Equal(value.PollingKey) {
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
	verified, err := aauth.VerifyRequest(
		context.Background(),
		request,
		signaturekey.StaticKeyResolver{
			proof.Signer: {proof.PublicKey.Kid: proof.PublicKey},
		},
		aauth.ClockFunc(func() time.Time { return proof.VerifiedAt.UTC() }),
		aauth.VerifyRequestOptions{
			RequiredComponents:       []string{"content-type"},
			RequireExactComponents:   true,
			AllowedSignatureKeyTypes: []signaturekey.Scheme{signaturekey.SchemeJWKSURI},
		},
	)
	if err != nil || verified.Signer != proof.Signer ||
		verified.SignatureKeyType != signaturekey.Scheme(proof.SignatureKeyType) || verified.CredentialType != "" ||
		!verified.PublicKey.Equal(proof.PublicKey) || !verified.Created.Equal(proof.Created) ||
		!verified.VerifiedAt.Equal(proof.VerifiedAt) || verified.ReplayKey != proof.ReplayKey {
		return ErrAuthorizationStateIntegrity
	}
	if !reflect.DeepEqual(requestProof(request, verified), proof) {
		return ErrAuthorizationStateIntegrity
	}
	return nil
}

func (server *AccessServer) validateAccessTerminalToken(record accessAuthorizationStateRecord) error {
	if record.TerminalAuthToken == "" {
		if record.TerminalVerificationKey != nil {
			return ErrAuthorizationStateIntegrity
		}
		return nil
	}
	if record.TerminalVerificationKey == nil {
		return ErrAuthorizationStateIntegrity
	}
	claims, err := verifyRetainedAuthToken(record.TerminalAuthToken, *record.TerminalVerificationKey)
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
	if claims.Issuer != server.identifier || claims.DWK != aauth.AccessDiscoveryDocument || claims.JTI != record.Key ||
		claims.Audience != resource.Issuer || claims.ExpiresAt != expectedExpiresAt ||
		record.TerminalExpiresAt != claims.ExpiresAt || claims.Subject != resource.Subject ||
		claims.Subject != record.Decision.Subject || claims.Scope != strings.Join(record.Decision.Scope, " ") ||
		!claims.Confirmation.JWK.Equal(record.Context.TargetKey) ||
		claims.PersonServer != resource.PersonServer || claims.Account != resource.Account ||
		claims.MissionS256 != resource.MissionS256 || claims.Tenant != resource.Tenant ||
		claims.Agent != "" || claims.Actor != nil || claims.Mission != nil {
		return ErrAuthorizationStateIntegrity
	}
	return nil
}

func (server *AccessServer) persistAuthorizationStateLocked(ctx context.Context) error {
	if server.authorizationErr != nil {
		return server.authorizationErr
	}
	if err := server.settleAuthorizationStateLocked(ctx); err != nil {
		return err
	}
	records := make([]accessAuthorizationStateRecord, 0, len(server.pending))
	for key, pending := range server.pending {
		records = append(records, accessAuthorizationStateRecord{
			Key: key, Interaction: snapshotPendingInteraction(pending.pendingInteraction),
			Context: snapshotAccessAuthorizationContext(pending.context), Decision: pending.decision,
			TerminalAuthToken:       pending.terminalAuthToken,
			TerminalVerificationKey: copyJWK(pending.terminalVerificationKey),
			TerminalExpiresAt:       pending.terminalExpiresAt,
			TerminalStatus:          pending.terminalStatus, TerminalCode: pending.terminalCode, TerminalDetail: pending.terminalDetail,
		})
	}
	sort.Slice(records, func(i, j int) bool { return records[i].Key < records[j].Key })
	raw := make([]json.RawMessage, 0, len(records))
	for _, record := range records {
		if err := server.validateAccessAuthorizationStateRecord(record); err != nil {
			return server.reconcileAuthorizationStateLocked(ctx, nil, err)
		}
		encoded, err := json.Marshal(record)
		if err != nil {
			return server.reconcileAuthorizationStateLocked(ctx, nil, err)
		}
		raw = append(raw, encoded)
	}
	body, err := marshalAuthorizationStateRecords(accessAuthorizationStateSchema, raw)
	if err != nil {
		return server.reconcileAuthorizationStateLocked(ctx, nil, err)
	}
	if err := server.authorizationStore.Replace(ctx, body); err != nil {
		return server.reconcileAuthorizationStateLocked(ctx, body, err)
	}
	server.authorizationBody = append(server.authorizationBody[:0], body...)
	return nil
}

func (server *AccessServer) reconcileAuthorizationStateLocked(ctx context.Context, candidate []byte, commitErr error) error {
	body, published, err := reconcileAuthorizationState(ctx, server.authorizationStore, server.authorizationBody, candidate)
	if err != nil || len(body) == 0 {
		server.pending = make(map[string]*pendingAccessServerAuthorization)
		server.authorizationErr = authorizationStateReconciliationFailure(commitErr, err)
		return server.authorizationErr
	}
	if err := server.restoreAuthorizationStateLocked(body); err != nil {
		server.pending = make(map[string]*pendingAccessServerAuthorization)
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

func (server *AccessServer) settleAuthorizationStateLocked(ctx context.Context) error {
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
			server.pending = make(map[string]*pendingAccessServerAuthorization)
			server.authorizationErr = authorizationStateReconciliationFailure(err, reconcileErr)
			return server.authorizationErr
		}
		return authorizationStatePublishedUncertain(err)
	}
	server.authorizationBody = append(server.authorizationBody[:0], candidate...)
	server.authorizationRecovery = nil
	return nil
}

func snapshotAccessAuthorizationContext(value accessServerAuthorizationContext) accessAuthorizationContextRecord {
	return accessAuthorizationContextRecord{
		Request:     copyAuthorizationRequest(value.request),
		RequestBody: append([]byte(nil), value.requestBody...), RequestProof: copyRequestProof(value.requestProof),
		ResourceToken:        value.resourceToken,
		ResourceTokenCompact: value.resourceTokenCompact, AgentTokenCompact: value.agentTokenCompact,
		SubagentTokenCompact: value.subagentTokenCompact, UpstreamTokenCompact: value.upstreamTokenCompact,
		TokenVerificationKeys: copyRetainedAuthorizationTokenKeys(value.tokenVerificationKeys),
		TargetAgent:           value.targetAgent,
		TargetKey:             value.targetKey, ParentAgent: value.parentAgent,
		TargetTokenExpiresAt: value.targetTokenExpiresAt, PollingServer: value.pollingServer,
		PollingKey: value.pollingKey, PollingKeyThumbprint: value.pollingKeyThumbprint,
	}
}

func restoreAccessAuthorizationContext(value accessAuthorizationContextRecord) accessServerAuthorizationContext {
	return accessServerAuthorizationContext{
		request:     copyAuthorizationRequest(value.Request),
		requestBody: append([]byte(nil), value.RequestBody...), requestProof: copyRequestProof(value.RequestProof),
		resourceToken:        value.ResourceToken,
		resourceTokenCompact: value.ResourceTokenCompact, agentTokenCompact: value.AgentTokenCompact,
		subagentTokenCompact: value.SubagentTokenCompact, upstreamTokenCompact: value.UpstreamTokenCompact,
		tokenVerificationKeys: copyRetainedAuthorizationTokenKeys(value.TokenVerificationKeys),
		targetAgent:           value.TargetAgent,
		targetKey:             value.TargetKey, parentAgent: value.ParentAgent,
		targetTokenExpiresAt: value.TargetTokenExpiresAt, pollingServer: value.PollingServer,
		pollingKey: value.PollingKey, pollingKeyThumbprint: value.PollingKeyThumbprint,
	}
}

func (server *AccessServer) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /token", server.handleToken)
	mux.HandleFunc("GET /pending/{id}", server.handlePendingAuthorization)
	mux.HandleFunc("GET /interaction/{id}", server.handleInteraction)
	mux.HandleFunc("GET /.well-known/aauth-access.json", server.handleMetadata)
	mux.HandleFunc("GET /jwks", server.handleJWKS)
	return mux
}

func (server *AccessServer) handleToken(response http.ResponseWriter, request *http.Request) {
	server.pendingMu.Lock()
	stateErr := server.settleAuthorizationStateLocked(request.Context())
	server.pendingMu.Unlock()
	if stateErr != nil {
		writeProblem(response, http.StatusServiceUnavailable, "authorization_state_unavailable", stateErr)
		return
	}
	verified, err := aauth.VerifyRequest(request.Context(), request, server.keyResolver, server.clock, aauth.VerifyRequestOptions{
		RequiredComponents:       []string{"content-type"},
		RequireExactComponents:   true,
		AllowedSignatureKeyTypes: []signaturekey.Scheme{signaturekey.SchemeJWKSURI},
	})
	if err != nil {
		writeSignatureFailure(response, err)
		return
	}
	verificationClock := aauth.ClockFunc(func() time.Time { return verified.VerifiedAt })
	if err := server.trustedPersonServer(request.Context(), verified.Signer); err != nil {
		writeHostPolicyRefusal(response, "untrusted_person_server", "person server is not trusted")
		return
	}
	requestBody, err := readBoundedRequestBody(request)
	if err != nil {
		writeProblem(response, http.StatusBadRequest, "invalid_request", err)
		return
	}
	var input accessAuthorizationTokenInput
	if err := decodeJSONBytes(bytes.NewReader(requestBody), &input); err != nil ||
		input.ResourceToken == "" || input.AgentToken == "" {
		writeProblem(response, http.StatusBadRequest, "invalid_request", err)
		return
	}
	agentKeyCapture, agentVerificationResolver := newRetainedKeyCapture(server.keyResolver)
	agentTokenEvidence, err := aauth.VerifyAgentToken(request.Context(), input.AgentToken, agentVerificationResolver, verificationClock)
	if err != nil {
		writeTokenVerificationFailure(response, http.StatusBadRequest, "invalid_agent_token", err)
		return
	}
	agentToken, err := claimsWithoutAuthorization(agentTokenEvidence)
	if err != nil {
		writeTokenVerificationFailure(response, http.StatusBadRequest, "invalid_agent_token", err)
		return
	}
	agentVerificationKey, err := agentKeyCapture.retainedKey()
	if err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", err)
		return
	}
	if agentToken.ParentAgent != "" {
		writeProblem(response, http.StatusBadRequest, "invalid_agent_token", errors.New("sub-agent cannot act as a parent"))
		return
	}
	if input.UpstreamToken == "" && agentToken.PersonServer != "" && agentToken.PersonServer != verified.Signer {
		writeProblem(response, http.StatusBadRequest, "invalid_agent_token", errors.New("agent token names a different person server"))
		return
	}

	targetAgent := agentToken.Subject
	targetKey := agentToken.Confirmation.JWK
	parentAgent := ""
	targetExpiry := agentToken.ExpiresAt
	var subagentVerificationKey *jose.JWK
	if input.SubagentToken != "" {
		subagentKeyCapture, subagentVerificationResolver := newRetainedKeyCapture(server.keyResolver)
		subagentEvidence, err := aauth.VerifyAgentToken(request.Context(), input.SubagentToken, subagentVerificationResolver, verificationClock)
		if err != nil {
			writeTokenVerificationFailure(response, http.StatusBadRequest, "invalid_subagent_token", err)
			return
		}
		subagent, err := claimsWithoutAuthorization(subagentEvidence)
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
		if subagent.ParentAgent != agentToken.Subject {
			writeProblem(response, http.StatusForbidden, "invalid_subagent_token", errors.New("sub-agent token does not name the parent agent"))
			return
		}
		if input.UpstreamToken == "" && subagent.PersonServer != verified.Signer {
			writeProblem(response, http.StatusForbidden, "invalid_subagent_token", errors.New("sub-agent token names a different person server"))
			return
		}
		targetAgent = subagent.Subject
		targetKey = subagent.Confirmation.JWK
		parentAgent = agentToken.Subject
		if subagent.ExpiresAt < targetExpiry {
			targetExpiry = subagent.ExpiresAt
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
		claims, err := claimsWithoutAuthorization(upstreamEvidence)
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
		if claims.Audience != agentToken.Issuer {
			writeProblem(response, http.StatusForbidden, "invalid_upstream_token", errors.New("upstream auth-token audience does not match intermediary issuer"))
			return
		}
		if claims.PersonServer != verified.Signer {
			writeProblem(response, http.StatusForbidden, "invalid_upstream_token", errors.New("upstream auth token ps does not match sending person server"))
			return
		}
		if !claims.Confirmation.JWK.Equal(agentToken.Confirmation.JWK) {
			writeProblem(response, http.StatusForbidden, "invalid_upstream_token", errors.New("upstream auth-token confirmation key does not match intermediary agent key"))
			return
		}
		if claims.ExpiresAt < targetExpiry {
			targetExpiry = claims.ExpiresAt
		}
		upstream = &claims
	}

	resourceKeyCapture, resourceVerificationResolver := newRetainedKeyCapture(server.keyResolver)
	resourceTokenEvidence, err := aauth.VerifyResourceToken(request.Context(), input.ResourceToken, resourceVerificationResolver, verificationClock)
	if err != nil {
		writeResourceTokenVerificationFailure(response, err)
		return
	}
	var resourceR3 r3.TokenResult
	members, memberErr := resourceTokenEvidence.AuthorizationMembers()
	var resourceToken aauth.ResourceTokenClaims
	if memberErr != nil {
		err = memberErr
	} else if len(members) == 0 {
		resourceToken, err = resourceTokenEvidence.Claims()
	} else if server.r3GrantPolicy == nil {
		err = resourceTokenEvidence.RequireNoAuthorizationMembers()
	} else {
		resourceR3, err = r3.ValidateResourceToken(resourceTokenEvidence)
		if err == nil {
			resourceToken, err = resourceTokenEvidence.Claims()
		}
	}
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
		writeProblem(response, http.StatusForbidden, "invalid_resource_token", errors.New("resource-token audience does not match access server"))
		return
	}
	if resourceToken.PersonServer == "" {
		writeProblem(response, http.StatusForbidden, "invalid_resource_token", errors.New("current resource-token ps is required"))
		return
	}
	if upstream == nil && agentToken.PersonServer != verified.Signer {
		writeProblem(response, http.StatusBadRequest, "invalid_agent_token", errors.New("agent token ps does not match sending person server"))
		return
	}
	if resourceToken.PersonServer != verified.Signer {
		writeProblem(response, http.StatusForbidden, "invalid_resource_token", errors.New("resource-token ps does not match sending person server"))
		return
	}
	thumbprint, err := targetKey.Thumbprint()
	if err != nil || thumbprint != resourceToken.AgentJKT {
		writeProblem(response, http.StatusForbidden, "invalid_resource_token", errors.New("resource-token agent_jkt does not match authorized agent key"))
		return
	}
	if upstream != nil && upstream.MissionS256 != resourceToken.MissionS256 {
		writeProblem(response, http.StatusForbidden, "invalid_mission", errors.New("downstream mission_s256 does not match upstream authorization"))
		return
	}
	scopes, err := parseScopes(resourceToken.Scope)
	if err != nil {
		writeProblem(response, http.StatusBadRequest, "invalid_resource_token", err)
		return
	}
	pollingKeyThumbprint, err := verified.PublicKey.Thumbprint()
	if err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", nil)
		return
	}
	authorizationContext := accessServerAuthorizationContext{
		request: aauth.AuthorizationRequest{
			Agent:       targetAgent,
			ParentAgent: parentAgent,
			Resource:    resourceToken.Issuer,
			Scope:       append([]string(nil), scopes...),
			Mission:     resourceToken.Mission,
			Upstream:    upstream,
		},
		requestBody:          append([]byte(nil), requestBody...),
		requestProof:         requestProof(request, verified),
		resourceToken:        resourceToken,
		resourceTokenCompact: input.ResourceToken,
		agentTokenCompact:    input.AgentToken,
		subagentTokenCompact: input.SubagentToken,
		upstreamTokenCompact: input.UpstreamToken,
		tokenVerificationKeys: retainedAuthorizationTokenKeys{
			Resource: resourceVerificationKey,
			Agent:    agentVerificationKey,
			Subagent: subagentVerificationKey,
			Upstream: upstreamVerificationKey,
		},
		targetAgent:          targetAgent,
		targetKey:            targetKey,
		parentAgent:          parentAgent,
		targetTokenExpiresAt: targetExpiry,
		pollingServer:        verified.Signer,
		pollingKey:           verified.PublicKey,
		pollingKeyThumbprint: pollingKeyThumbprint,
	}
	authorizationContext.request.PersonServer = resourceToken.PersonServer
	authorizationContext.request.Subject = resourceToken.Subject
	authorizationContext.request.MissionS256 = resourceToken.MissionS256
	authorizationContext.request.Tenant = resourceToken.Tenant
	authorizationContext.request.Account = resourceToken.Account
	if resourceR3.Valid() {
		document, fetchErr := fetchR3Document(
			request.Context(),
			r3FetchConfig{
				client: server.r3HTTPClient, key: server.signingKey,
				identifier: server.identifier, discoveryDocument: aauth.AccessDiscoveryDocument,
				clock: server.clock, admit: server.r3Admit, timeout: server.r3FetchTimeout,
			},
			resourceToken.Issuer,
			resourceR3,
		)
		if fetchErr != nil {
			writeProblem(response, http.StatusBadGateway, "r3_document_verification_failed", fetchErr)
			return
		}
		granted, policyErr := server.r3GrantPolicy(
			request.Context(), copyAuthorizationRequest(authorizationContext.request), document,
		)
		if policyErr != nil {
			writeHostPolicyRefusal(response, "r3_grant_denied", "access-server R3 policy denied the request")
			return
		}
		direct, grantErr := r3.NewDirectGrant(document, granted)
		if grantErr != nil {
			writeProblem(response, http.StatusInternalServerError, "invalid_r3_grant", grantErr)
			return
		}
		authorizationContext.r3Grant = &direct
	}
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
			if resourceR3.Valid() {
				writeProblem(response, http.StatusNotImplemented, "r3_deferred_not_implemented", errors.New("direct R3 authorization does not support deferred interaction"))
				return
			}
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
	if err := validateAuthorizationDecision(decision, scopes); err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", errors.New("authorization policy returned an invalid grant"))
		return
	}
	if decision.Subject != resourceToken.Subject {
		writeProblem(response, http.StatusInternalServerError, "server_error", errors.New("authorization policy changed the person-server directed subject"))
		return
	}
	server.completeAuthorization(request.Context(), response, authorizationContext, decision)
}

func (server *AccessServer) completeAuthorization(
	ctx context.Context,
	response http.ResponseWriter,
	authorizationContext accessServerAuthorizationContext,
	decision aauth.AuthorizationDecision,
) {
	authToken, expiresAt, err := server.mintAuthorization(ctx, authorizationContext, decision, "")
	if err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", err)
		return
	}
	writeJSON(response, http.StatusOK, map[string]any{
		"auth_token": authToken,
		"expires_in": expiresAt - server.clock.Now().Unix(),
	})
}

func (server *AccessServer) mintAuthorization(
	ctx context.Context,
	authorizationContext accessServerAuthorizationContext,
	decision aauth.AuthorizationDecision,
	tokenID string,
) (string, int64, error) {
	now := server.clock.Now()
	expiresAt := now.Add(time.Hour).Unix()
	if authorizationContext.targetTokenExpiresAt < expiresAt {
		expiresAt = authorizationContext.targetTokenExpiresAt
	}
	if authorizationContext.resourceToken.ExpiresAt < expiresAt {
		expiresAt = authorizationContext.resourceToken.ExpiresAt
	}
	if tokenID == "" {
		tokenID = server.newID()
	}
	claims := aauth.AuthTokenClaims{
		Issuer:       server.identifier,
		DWK:          aauth.AccessDiscoveryDocument,
		Audience:     authorizationContext.resourceToken.Issuer,
		JTI:          tokenID,
		Confirmation: aauth.Confirmation{JWK: authorizationContext.targetKey},
		IssuedAt:     now.Unix(),
		ExpiresAt:    expiresAt,
		Subject:      authorizationContext.resourceToken.Subject,
		Scope:        strings.Join(decision.Scope, " "),
		PersonServer: authorizationContext.resourceToken.PersonServer,
		Account:      authorizationContext.resourceToken.Account,
		MissionS256:  authorizationContext.resourceToken.MissionS256,
		Tenant:       authorizationContext.resourceToken.Tenant,
	}
	var authToken string
	var err error
	if authorizationContext.r3Grant != nil {
		authToken, err = r3.MintAuthToken(server.signingKey, claims, *authorizationContext.r3Grant)
	} else {
		authToken, err = aauth.MintAuthToken(server.signingKey, claims)
	}
	if err != nil {
		return "", 0, err
	}
	return authToken, expiresAt, nil
}

func cloneMissionReference(reference *aauth.MissionReference) *aauth.MissionReference {
	if reference == nil {
		return nil
	}
	cloned := *reference
	return &cloned
}

func (server *AccessServer) beginPendingAuthorization(
	response http.ResponseWriter,
	authorizationContext accessServerAuthorizationContext,
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
	pending := &pendingAccessServerAuthorization{
		pendingInteraction: interaction,
		context:            copyAccessServerAuthorizationContext(authorizationContext),
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

func copyAccessServerAuthorizationContext(
	authorizationContext accessServerAuthorizationContext,
) accessServerAuthorizationContext {
	copied := authorizationContext
	copied.request = copyAuthorizationRequest(authorizationContext.request)
	return copied
}

func (server *AccessServer) writePendingAuthorization(
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

// ApproveAuthorization records the access authority's trusted approval after
// code correlation and reevaluates resource policy.
func (server *AccessServer) ApproveAuthorization(ctx context.Context, pendingID string) error {
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
	if pending.state != pendingAuthorizationInteracting {
		server.pendingMu.Unlock()
		return errors.New("reference: pending authorization is not awaiting a trusted decision")
	}
	if !pending.expiresAt.After(server.clock.Now()) {
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
	if err := validateAuthorizationDecision(decision, authorizationRequest.Scope); err != nil {
		return err
	}
	if decision.Subject != authorizationRequest.Subject {
		return errors.New("reference: authorization decision changed the person-server directed subject")
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

// RejectAuthorization records a trusted terminal AS decision.
func (server *AccessServer) RejectAuthorization(
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

func (server *AccessServer) handlePendingAuthorization(
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
			AllowedSignatureKeyTypes: []signaturekey.Scheme{signaturekey.SchemeJWKSURI},
		},
	)
	if err != nil {
		writeSignatureFailure(response, err)
		return
	}
	if err := server.trustedPersonServer(request.Context(), verified.Signer); err != nil {
		writeHostPolicyRefusal(response, "untrusted_person_server", "person server is not trusted")
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
	if pending.context.pollingServer != verified.Signer ||
		pending.context.pollingKeyThumbprint != thumbprint {
		server.pendingMu.Unlock()
		writeProblem(response, http.StatusForbidden, "invalid_pending", errors.New("pending authorization belongs to a different person-server key"))
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
			writeJSON(response, http.StatusOK, map[string]any{"auth_token": token, "expires_in": expiresAt - server.clock.Now().Unix()})
			return
		}
		authorizationContext := copyAccessServerAuthorizationContext(pending.context)
		decision := aauth.AuthorizationDecision{
			Subject: pending.decision.Subject,
			Scope:   append([]string(nil), pending.decision.Scope...),
		}
		server.pendingMu.Unlock()
		token, expiresAt, err := server.mintAuthorization(request.Context(), authorizationContext, decision, pending.id)
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
		server.pendingMu.Unlock()
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

func (server *AccessServer) handleInteraction(
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

func (server *AccessServer) seenReplay(key string, expiresAt time.Time, verifiedAt time.Time) bool {
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

func (server *AccessServer) handleMetadata(response http.ResponseWriter, _ *http.Request) {
	writeJSON(response, http.StatusOK, map[string]any{
		"issuer":              server.identifier,
		"jwks_uri":            server.identifier + "/jwks",
		"auth_token_endpoint": server.identifier + "/token",
	})
}

func (server *AccessServer) handleJWKS(response http.ResponseWriter, _ *http.Request) {
	writeJSON(response, http.StatusOK, map[string]any{
		"keys": []jose.JWK{server.signingKey.PublicJWK()},
	})
}
