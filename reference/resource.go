package reference

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
)

type ResourceConfig struct {
	Identifier          string
	PersonServer        string
	AccessServer        string
	SigningKey          aauth.SigningKey
	KeyResolver         aauth.KeyResolver
	Clock               aauth.Clock
	NewID               func() string
	Scopes              []string
	AuthorizationPolicy aauth.AuthorizationPolicy
	InteractionRequired func(context.Context, aauth.AuthorizationRequest) (bool, error)
	Random              io.Reader
	PendingLifetime     time.Duration
	Operation           func(context.Context, aauth.AuthorizedRequest) (any, error)
	// R3Vocabularies is the exact discovery-value map advertised by the
	// resource. R3DocumentStore owns exact-byte retention across resource
	// restarts. The selection, required-operation, and request-mapping callbacks
	// are deployment policy boundaries for the authoritative definitions.
	R3Vocabularies          map[string]json.RawMessage
	R3DocumentStore         R3DocumentStore
	R3DocumentForOperations func(context.Context, aauth.R3OperationSet) ([]byte, error)
	R3RequiredForRequest    func(context.Context, *http.Request) (bool, error)
	R3OperationForRequest   func(context.Context, *http.Request) (aauth.R3OperationSet, error)
	// R3ProposalForRequest maps one authenticated, bounded request body into
	// the complete security-relevant parameters and display of a conditional
	// call. Omitting an input leaves it unbound; deployments should include a
	// full exact-body digest when the operation consumes fields beyond a strict
	// typed mapping. The resource serializes and retains the returned proposal
	// before exposing a challenge.
	R3ProposalForRequest func(context.Context, *http.Request, []byte) (aauth.R3Proposal, error)
}

type Resource struct {
	identifier              string
	tokenAudience           string
	signingKey              aauth.SigningKey
	hasSigningKey           bool
	keyResolver             aauth.KeyResolver
	clock                   aauth.Clock
	newID                   func() string
	scopes                  []string
	authorizationPolicy     aauth.AuthorizationPolicy
	interactionRequired     func(context.Context, aauth.AuthorizationRequest) (bool, error)
	random                  io.Reader
	pendingLifetime         time.Duration
	operation               func(context.Context, aauth.AuthorizedRequest) (any, error)
	r3Vocabularies          map[string]json.RawMessage
	r3DocumentStore         R3DocumentStore
	r3ProposalDocumentStore R3ProposalDocumentStore
	r3DocumentForOperations func(context.Context, aauth.R3OperationSet) ([]byte, error)
	r3RequiredForRequest    func(context.Context, *http.Request) (bool, error)
	r3OperationForRequest   func(context.Context, *http.Request) (aauth.R3OperationSet, error)
	r3ProposalForRequest    func(context.Context, *http.Request, []byte) (aauth.R3Proposal, error)
	randomMu                sync.Mutex
	pendingMu               sync.Mutex
	pending                 map[string]*pendingAuthorization
	accessMu                sync.Mutex
	access                  map[string]localAccessGrant
	replayMu                sync.Mutex
	replayedProof           map[string]time.Time
}

type localAccessGrant struct {
	agent      string
	subject    string
	thumbprint string
	scope      []string
	mission    *aauth.MissionReference
	expiresAt  time.Time
}

type pendingAuthorization struct {
	pendingInteraction
	request         aauth.AuthorizationRequest
	decision        aauth.AuthorizationDecision
	agentThumbprint string
	agentExpiresAt  time.Time
}

func NewResource(config ResourceConfig) (*Resource, error) {
	if err := aauth.ValidateServerIdentifier(config.Identifier); err != nil {
		return nil, err
	}
	modeCount := 0
	if config.PersonServer != "" {
		modeCount++
	}
	if config.AccessServer != "" {
		modeCount++
	}
	if config.AuthorizationPolicy != nil {
		modeCount++
	}
	if modeCount != 1 {
		return nil, errors.New("reference: resource requires exactly one person server, access server, or local authorization policy")
	}
	tokenAudience := config.PersonServer
	if tokenAudience == "" {
		tokenAudience = config.AccessServer
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
	r3Parts := 0
	if len(config.R3Vocabularies) != 0 {
		r3Parts++
	}
	if config.R3DocumentStore != nil {
		r3Parts++
	}
	if config.R3DocumentForOperations != nil {
		r3Parts++
	}
	if config.R3RequiredForRequest != nil {
		r3Parts++
	}
	if config.R3OperationForRequest != nil {
		r3Parts++
	}
	if r3Parts != 0 && r3Parts != 5 {
		return nil, errors.New("reference: R3 requires vocabularies, durable document custody, document selection, required-operation policy, and request mapping")
	}
	if r3Parts != 0 && config.AccessServer == "" {
		return nil, errors.New("reference: R3 requires an access server")
	}
	if config.R3ProposalForRequest != nil && r3Parts != 5 {
		return nil, errors.New("reference: R3 proposal policy requires complete R3 configuration")
	}
	var r3ProposalDocumentStore R3ProposalDocumentStore
	if config.R3ProposalForRequest != nil {
		var ok bool
		r3ProposalDocumentStore, ok = config.R3DocumentStore.(R3ProposalDocumentStore)
		if !ok {
			return nil, errors.New("reference: R3 proposal policy requires durable proposal custody and consumption")
		}
	}
	r3Vocabularies := make(map[string]json.RawMessage, len(config.R3Vocabularies))
	for vocabulary, discovery := range config.R3Vocabularies {
		if err := aauth.ValidateR3VocabularyURI(vocabulary); err != nil {
			return nil, err
		}
		if len(discovery) == 0 || !json.Valid(discovery) {
			return nil, errors.New("reference: R3 discovery value must be valid JSON")
		}
		r3Vocabularies[vocabulary] = append(json.RawMessage(nil), discovery...)
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
	if _, err := parseScopes(strings.Join(config.Scopes, " ")); err != nil {
		return nil, err
	}
	return &Resource{
		identifier:              config.Identifier,
		tokenAudience:           tokenAudience,
		signingKey:              config.SigningKey,
		hasSigningKey:           config.SigningKey.ID() != "",
		keyResolver:             config.KeyResolver,
		clock:                   config.Clock,
		newID:                   config.NewID,
		scopes:                  append([]string(nil), config.Scopes...),
		authorizationPolicy:     config.AuthorizationPolicy,
		interactionRequired:     config.InteractionRequired,
		random:                  random,
		pendingLifetime:         pendingLifetime,
		operation:               config.Operation,
		r3Vocabularies:          r3Vocabularies,
		r3DocumentStore:         config.R3DocumentStore,
		r3ProposalDocumentStore: r3ProposalDocumentStore,
		r3DocumentForOperations: config.R3DocumentForOperations,
		r3RequiredForRequest:    config.R3RequiredForRequest,
		r3OperationForRequest:   config.R3OperationForRequest,
		r3ProposalForRequest:    config.R3ProposalForRequest,
		pending:                 make(map[string]*pendingAuthorization),
		access:                  make(map[string]localAccessGrant),
		replayedProof:           make(map[string]time.Time),
	}, nil
}

func (resource *Resource) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /authorize", resource.handleAuthorize)
	mux.HandleFunc("GET /pending/{id}", resource.handlePendingAuthorization)
	mux.HandleFunc("GET /interaction/{id}", resource.handleInteraction)
	mux.HandleFunc("GET /.well-known/aauth-resource.json", resource.handleMetadata)
	mux.HandleFunc("GET /jwks", resource.handleJWKS)
	mux.HandleFunc("GET /r3/proposals/{s256}", resource.handleR3Document)
	mux.HandleFunc("GET /r3/{s256}", resource.handleR3Document)
	mux.HandleFunc("/", resource.handleProtected)
	return mux
}

func (resource *Resource) handleAuthorize(response http.ResponseWriter, request *http.Request) {
	required := []string{"content-digest"}
	if request.Header.Get("AAuth-Mission") != "" {
		required = append(required, "aauth-mission")
	}
	verified, err := aauth.VerifyRequest(request.Context(), request, resource.keyResolver, resource.clock, aauth.VerifyRequestOptions{
		RequiredComponents:     required,
		AllowedCredentialTypes: []string{aauth.AgentTokenType},
	})
	if err != nil {
		writeSignatureFailure(response, err)
		return
	}
	if resource.seenReplay(verified.ReplayKey, verified.Created.Add(aauth.DefaultSignatureWindow)) {
		writeSignatureFailure(response, errors.New("request proof was replayed"))
		return
	}
	var input struct {
		Scope        string                `json:"scope"`
		R3Operations *aauth.R3OperationSet `json:"r3_operations,omitempty"`
	}
	if err := decodeJSON(response, request, &input); err != nil {
		writeProblem(response, http.StatusBadRequest, "invalid_request", err)
		return
	}
	scopes, err := parseScopes(input.Scope)
	if err != nil || !scopesContained(scopes, resource.scopes) {
		writeProblem(response, http.StatusBadRequest, "invalid_scope", err)
		return
	}
	var r3URI string
	var r3S256 string
	now := resource.clock.Now()
	resourceTokenExpiresAt := now.Add(5 * time.Minute)
	if input.R3Operations != nil {
		if resource.r3DocumentForOperations == nil {
			writeProblem(response, http.StatusBadRequest, "unsupported_r3_vocabulary", errors.New("resource does not advertise R3"))
			return
		}
		if err := input.R3Operations.Validate(); err != nil {
			writeProblem(response, http.StatusBadRequest, "invalid_r3_operations", err)
			return
		}
		if _, advertised := resource.r3Vocabularies[input.R3Operations.Vocabulary]; !advertised {
			writeProblem(response, http.StatusBadRequest, "unsupported_r3_vocabulary", errors.New("requested R3 vocabulary is not advertised"))
			return
		}
		exactBytes, err := resource.r3DocumentForOperations(
			request.Context(),
			input.R3Operations.Clone(),
		)
		if err != nil {
			writeProblem(response, http.StatusBadRequest, "invalid_r3_operations", err)
			return
		}
		document, err := aauth.ParseR3Document(exactBytes)
		if err != nil {
			writeProblem(response, http.StatusInternalServerError, "server_error", err)
			return
		}
		if document.Parameters != nil {
			writeProblem(response, http.StatusInternalServerError, "server_error", errors.New("R3 class document contains per-call parameters"))
			return
		}
		documentOperations := document.OperationSet()
		if documentOperations.Vocabulary != input.R3Operations.Vocabulary ||
			!documentOperations.ContainsSet(*input.R3Operations) {
			writeProblem(response, http.StatusInternalServerError, "server_error", errors.New("R3 document does not cover the requested operations"))
			return
		}
		r3S256 = aauth.R3S256(exactBytes)
		if err := resource.r3DocumentStore.Retain(
			request.Context(),
			r3S256,
			exactBytes,
			resourceTokenExpiresAt,
		); err != nil {
			writeProblem(response, http.StatusServiceUnavailable, "r3_custody_unavailable", err)
			return
		}
		r3URI = resource.identifier + "/r3/" + r3S256
	}
	var mission *aauth.MissionReference
	if header := request.Header.Get("AAuth-Mission"); header != "" {
		parsed, err := aauth.ParseMissionHeader(header)
		if err != nil {
			writeProblem(response, http.StatusBadRequest, "invalid_mission", err)
			return
		}
		mission = &parsed
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
			Mission:  mission,
		}
		if resource.interactionRequired != nil {
			required, err := resource.interactionRequired(request.Context(), authorizationRequest)
			if err != nil {
				writeProblem(response, http.StatusForbidden, "access_denied", err)
				return
			}
			if required {
				if err := resource.beginPendingAuthorization(
					response,
					authorizationRequest,
					thumbprint,
					time.Unix(verified.AgentToken.ExpiresAt, 0),
					now,
				); err != nil {
					writeProblem(response, http.StatusInternalServerError, "server_error", err)
				}
				return
			}
		}
		decision, err := resource.authorizationPolicy(request.Context(), authorizationRequest)
		if err != nil {
			writeProblem(response, http.StatusForbidden, "access_denied", err)
			return
		}
		if err := validateAuthorizationDecision(decision, scopes); err != nil {
			writeProblem(response, http.StatusInternalServerError, "server_error", errors.New("local authorization policy returned an invalid grant"))
			return
		}
		expiresAt := now.Add(time.Hour)
		if agentExpiry := time.Unix(verified.AgentToken.ExpiresAt, 0); agentExpiry.Before(expiresAt) {
			expiresAt = agentExpiry
		}
		if err := resource.writeAccessGrant(response, authorizationRequest, decision, thumbprint, expiresAt); err != nil {
			writeProblem(response, http.StatusInternalServerError, "server_error", err)
		}
		return
	}

	token, err := aauth.MintResourceToken(resource.signingKey, aauth.ResourceTokenClaims{
		Issuer:    resource.identifier,
		DWK:       aauth.ResourceDiscoveryDocument,
		Audience:  resource.tokenAudience,
		JTI:       resource.newID(),
		Agent:     verified.Agent,
		AgentJKT:  thumbprint,
		IssuedAt:  now.Unix(),
		ExpiresAt: resourceTokenExpiresAt.Unix(),
		Scope:     strings.Join(scopes, " "),
		Mission:   mission,
		R3URI:     r3URI,
		R3S256:    r3S256,
	})
	if err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", err)
		return
	}
	writeJSON(response, http.StatusOK, map[string]string{"resource_token": token})
}

func validateAuthorizationDecision(decision aauth.AuthorizationDecision, requestedScope []string) error {
	if len(decision.Scope) == 0 || !scopesContained(decision.Scope, requestedScope) {
		return errors.New("authorization decision contains an invalid scope")
	}
	return nil
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
	accessToken := resource.newID()
	if err := aauth.ValidateAccessToken(accessToken); err != nil {
		return "", err
	}
	resource.accessMu.Lock()
	defer resource.accessMu.Unlock()
	if _, exists := resource.access[accessToken]; exists {
		return "", errors.New("access token source returned a duplicate value")
	}
	resource.access[accessToken] = localAccessGrant{
		agent:      request.Agent,
		subject:    decision.Subject,
		thumbprint: thumbprint,
		scope:      append([]string(nil), decision.Scope...),
		mission:    request.Mission,
		expiresAt:  expiresAt,
	}
	return accessToken, nil
}

func (resource *Resource) beginPendingAuthorization(
	response http.ResponseWriter,
	request aauth.AuthorizationRequest,
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
		pendingInteraction: interaction,
		request:            copyAuthorizationRequest(request),
		agentThumbprint:    thumbprint,
		agentExpiresAt:     agentExpiresAt,
	}
	resource.pendingMu.Lock()
	if _, exists := resource.pending[interaction.id]; exists {
		resource.pendingMu.Unlock()
		return errors.New("pending identifier source returned a duplicate value")
	}
	resource.pending[interaction.id] = pending
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
	copied.R3 = request.R3.Clone()
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
	pending, exists := resource.pending[pendingID]
	if !exists {
		resource.pendingMu.Unlock()
		return errors.New("reference: pending authorization does not exist")
	}
	now := resource.clock.Now()
	if !pending.expiresAt.After(now) {
		pending.state = pendingAuthorizationExpired
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
	if pending.state != pendingAuthorizationInteracting {
		return errors.New("reference: pending authorization changed while approval was evaluated")
	}
	if !pending.expiresAt.After(resource.clock.Now()) {
		pending.state = pendingAuthorizationExpired
		return errors.New("reference: pending authorization expired")
	}
	pending.decision = aauth.AuthorizationDecision{
		Subject: decision.Subject,
		Scope:   append([]string(nil), decision.Scope...),
	}
	pending.state = pendingAuthorizationApproved
	return nil
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
	pending, exists := resource.pending[pendingID]
	if !exists {
		return errors.New("reference: pending authorization does not exist")
	}
	if !pending.expiresAt.After(resource.clock.Now()) {
		pending.state = pendingAuthorizationExpired
		return errors.New("reference: pending authorization expired")
	}
	if pending.state != pendingAuthorizationInteracting {
		return errors.New("reference: pending authorization is not awaiting a trusted decision")
	}
	pending.pollingError = code
	pending.state = pendingAuthorizationRejected
	return nil
}

func (resource *Resource) handlePendingAuthorization(response http.ResponseWriter, request *http.Request) {
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
	if pending.request.Agent != verified.Agent || pending.agentThumbprint != thumbprint {
		resource.pendingMu.Unlock()
		writeProblem(response, http.StatusForbidden, "invalid_pending", errors.New("pending authorization belongs to a different agent key"))
		return
	}
	if (pending.state == pendingAuthorizationWaiting ||
		pending.state == pendingAuthorizationInteracting) &&
		!pending.expiresAt.After(resource.clock.Now()) {
		pending.state = pendingAuthorizationExpired
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
		expiresAt := resource.clock.Now().Add(time.Hour)
		if pending.agentExpiresAt.Before(expiresAt) {
			expiresAt = pending.agentExpiresAt
		}
		token, err := resource.storeAccessGrant(
			pending.request,
			pending.decision,
			pending.agentThumbprint,
			expiresAt,
		)
		if err != nil {
			resource.pendingMu.Unlock()
			writeProblem(response, http.StatusInternalServerError, "server_error", err)
			return
		}
		decision := pending.decision
		pending.state = pendingAuthorizationServed
		resource.pendingMu.Unlock()
		response.Header().Set("AAuth-Access", token)
		writeJSON(response, http.StatusOK, map[string]any{
			"status": "authorized",
			"scope":  strings.Join(decision.Scope, " "),
		})
	case pendingAuthorizationExpired:
		pending.state = pendingAuthorizationServed
		resource.pendingMu.Unlock()
		writeProblem(response, http.StatusRequestTimeout, "expired", errors.New("pending authorization expired"))
	case pendingAuthorizationRejected:
		code := pending.pollingError
		pending.state = pendingAuthorizationServed
		resource.pendingMu.Unlock()
		status := http.StatusForbidden
		if code == aauth.PollingServerError {
			status = http.StatusInternalServerError
		}
		writeProblem(response, status, string(code), errors.New("pending authorization was not approved"))
	case pendingAuthorizationInvalidCode:
		pending.state = pendingAuthorizationServed
		resource.pendingMu.Unlock()
		writeProblem(response, http.StatusGone, "invalid_code", errors.New("interaction code validation failed"))
	default:
		resource.pendingMu.Unlock()
		writeProblem(response, http.StatusGone, "gone", errors.New("pending authorization already returned a terminal response"))
	}
}

func (resource *Resource) handleInteraction(response http.ResponseWriter, request *http.Request) {
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
	exactBody, err := readBoundedRequestBody(request)
	if err != nil {
		writeProblem(response, http.StatusRequestEntityTooLarge, "request_too_large", err)
		return
	}
	var requiredComponents []string
	if len(exactBody) != 0 {
		requiredComponents = append(requiredComponents, "content-type")
	}
	verified, err := aauth.VerifyRequest(request.Context(), request, resource.keyResolver, resource.clock, aauth.VerifyRequestOptions{
		RequiredComponents:     requiredComponents,
		AllowedCredentialTypes: []string{aauth.AuthTokenType},
	})
	if err != nil {
		writeSignatureFailure(response, err)
		return
	}
	claims := verified.AuthToken
	if err := aauth.ValidateAuthTokenContext(*claims, resource.identifier, verified.Agent, verified.PublicKey, resource.scopes); err != nil {
		writeProblem(response, http.StatusForbidden, "invalid_token", err)
		return
	}
	granted, err := parseScopes(claims.Scope)
	if err != nil {
		writeProblem(response, http.StatusForbidden, "insufficient_scope", err)
		return
	}
	if resource.seenReplay(verified.ReplayKey, verified.Created.Add(aauth.DefaultSignatureWindow)) {
		writeSignatureFailure(response, errors.New("request proof was replayed"))
		return
	}
	if resource.r3RequiredForRequest != nil {
		required, err := resource.r3RequiredForRequest(request.Context(), request)
		if err != nil {
			writeProblem(response, http.StatusInternalServerError, "r3_mapping_failed", err)
			return
		}
		if required && claims.R3URI == "" {
			writeProblem(response, http.StatusForbidden, "r3_required", errors.New("this resource operation requires an R3 grant"))
			return
		}
	}
	if claims.R3URI != "" {
		if claims.Issuer != resource.tokenAudience {
			writeProblem(response, http.StatusForbidden, "invalid_token", errors.New("R3 auth-token issuer is not the resource access server"))
			return
		}
		if resource.r3OperationForRequest == nil {
			writeProblem(response, http.StatusForbidden, "r3_not_configured", errors.New("resource cannot map this R3 operation"))
			return
		}
		mapped, err := resource.r3OperationForRequest(request.Context(), request)
		if err != nil {
			writeProblem(response, http.StatusForbidden, "r3_operation_unknown", err)
			return
		}
		if err := mapped.Validate(); err != nil || len(mapped.Operations) != 1 {
			writeProblem(response, http.StatusForbidden, "r3_operation_unknown", errors.New("resource request mapping must return one valid R3 operation"))
			return
		}
		proposalToken, err := classifyR3ProposalReference(resource.identifier, claims.R3URI, claims.R3S256)
		if err != nil {
			writeProblem(response, http.StatusForbidden, "invalid_per_call_token", err)
			return
		}
		if proposalToken && claims.R3Conditional != nil {
			writeProblem(response, http.StatusForbidden, "invalid_per_call_token", errors.New("per-call R3 token cannot contain conditional operations"))
			return
		}
		if claims.R3Granted != nil &&
			mapped.Vocabulary == claims.R3Granted.Vocabulary &&
			claims.R3Granted.Contains(mapped.Operations[0]) {
			if proposalToken {
				if err := resource.enforceR3Proposal(request, exactBody, *claims, mapped); err != nil {
					status := http.StatusForbidden
					code := "r3_parameter_mismatch"
					if errors.Is(err, ErrR3DocumentNotFound) || errors.Is(err, ErrR3DocumentIntegrity) {
						status = http.StatusServiceUnavailable
						code = "r3_custody_unavailable"
					}
					if errors.Is(err, ErrR3ProposalConsumed) {
						code = "r3_per_call_replayed"
					}
					writeProblem(response, status, code, err)
					return
				}
			}
		} else if claims.R3Conditional != nil &&
			mapped.Vocabulary == claims.R3Conditional.Vocabulary &&
			claims.R3Conditional.Contains(mapped.Operations[0]) {
			resource.challengeR3Conditional(response, request, exactBody, verified, *claims, mapped)
			return
		} else {
			writeProblem(response, http.StatusForbidden, "r3_operation_denied", errors.New("R3 operation is not granted or conditional"))
			return
		}
	}

	result, err := resource.operation(request.Context(), aauth.AuthorizedRequest{
		Agent:     claims.Agent,
		Subject:   claims.Subject,
		Scope:     granted,
		Mission:   claims.Mission,
		Actor:     claims.Actor,
		AuthToken: verified.RawCredential,
		Method:    request.Method,
		Path:      request.URL.Path,
		Body:      append([]byte(nil), exactBody...),
	})
	if err != nil {
		writeProblem(response, http.StatusInternalServerError, "operation_failed", err)
		return
	}
	writeJSON(response, http.StatusOK, result)
}

func classifyR3ProposalReference(resourceIdentifier, uri, s256 string) (bool, error) {
	prefix := resourceIdentifier + "/r3/proposals/"
	if !strings.HasPrefix(uri, prefix) {
		return false, nil
	}
	if uri != prefix+s256 {
		return false, errors.New("reference: R3 proposal URI does not match its digest claim")
	}
	return true, nil
}

func (resource *Resource) enforceR3Proposal(
	request *http.Request,
	exactBody []byte,
	claims aauth.AuthTokenClaims,
	operation aauth.R3OperationSet,
) error {
	if resource.r3ProposalForRequest == nil || resource.r3ProposalDocumentStore == nil {
		return errors.New("reference: R3 proposal enforcement is not configured")
	}
	exactProposal, err := resource.r3ProposalDocumentStore.LoadProposal(
		request.Context(),
		claims.R3S256,
	)
	if err != nil {
		return err
	}
	if aauth.R3S256(exactProposal) != claims.R3S256 {
		return ErrR3DocumentIntegrity
	}
	document, err := aauth.ParseR3Document(exactProposal)
	if err != nil {
		return err
	}
	actual, err := resource.r3ProposalForRequest(
		request.Context(),
		request,
		append([]byte(nil), exactBody...),
	)
	if err != nil {
		return err
	}
	if err := document.MatchR3Call(operation, actual.Parameters); err != nil {
		return err
	}
	return resource.r3ProposalDocumentStore.ConsumeProposal(
		request.Context(),
		claims.R3S256,
		claims.JTI,
		time.Unix(claims.ExpiresAt, 0),
	)
}

func (resource *Resource) challengeR3Conditional(
	response http.ResponseWriter,
	request *http.Request,
	exactBody []byte,
	verified aauth.VerifiedRequest,
	claims aauth.AuthTokenClaims,
	operation aauth.R3OperationSet,
) {
	if resource.r3ProposalForRequest == nil {
		writeProblem(response, http.StatusForbidden, "r3_conditional_not_configured", errors.New("resource has no R3 proposal policy"))
		return
	}
	if request.URL.RawQuery != "" {
		writeProblem(response, http.StatusBadRequest, "r3_conditional_query_unsupported", errors.New("conditional R3 calls must not use query parameters"))
		return
	}
	proposal, err := resource.r3ProposalForRequest(
		request.Context(),
		request,
		append([]byte(nil), exactBody...),
	)
	if err != nil {
		writeProblem(response, http.StatusBadRequest, "invalid_r3_proposal", err)
		return
	}
	exactProposal, err := aauth.BuildR3Proposal(operation, proposal)
	if err != nil {
		writeProblem(response, http.StatusInternalServerError, "invalid_r3_proposal", err)
		return
	}
	parsedProposal, err := aauth.ParseR3Document(exactProposal)
	if err != nil || parsedProposal.MatchR3Call(operation, proposal.Parameters) != nil {
		writeProblem(response, http.StatusInternalServerError, "invalid_r3_proposal", errors.New("resource proposal does not bind the authenticated call"))
		return
	}
	now := resource.clock.Now()
	expiresAt := now.Add(5 * time.Minute)
	if parentExpiry := time.Unix(claims.ExpiresAt, 0); parentExpiry.Before(expiresAt) {
		expiresAt = parentExpiry
	}
	if !expiresAt.After(now) {
		writeProblem(response, http.StatusForbidden, "invalid_token", errors.New("conditional R3 token expires before a proposal can be issued"))
		return
	}
	digest := aauth.R3S256(exactProposal)
	if err := resource.r3ProposalDocumentStore.RetainProposal(
		request.Context(),
		digest,
		exactProposal,
		expiresAt,
	); err != nil {
		writeProblem(response, http.StatusServiceUnavailable, "r3_custody_unavailable", err)
		return
	}
	thumbprint, err := verified.PublicKey.Thumbprint()
	if err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", nil)
		return
	}
	resourceToken, err := aauth.MintResourceToken(resource.signingKey, aauth.ResourceTokenClaims{
		Issuer:    resource.identifier,
		DWK:       aauth.ResourceDiscoveryDocument,
		Audience:  resource.tokenAudience,
		JTI:       resource.newID(),
		Agent:     claims.Agent,
		AgentJKT:  thumbprint,
		IssuedAt:  now.Unix(),
		ExpiresAt: expiresAt.Unix(),
		Scope:     claims.Scope,
		Mission:   claims.Mission,
		R3URI:     resource.identifier + "/r3/proposals/" + digest,
		R3S256:    digest,
	})
	if err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", err)
		return
	}
	requirement, err := aauth.FormatRequirementHeader(aauth.Requirement{
		Type:          aauth.RequirementAuthToken,
		ResourceToken: resourceToken,
	})
	if err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", err)
		return
	}
	response.Header().Set("AAuth-Requirement", requirement)
	writeProblem(response, http.StatusUnauthorized, "r3_conditional", errors.New("conditional R3 call requires per-call authorization"))
}

func usesAAuthScheme(header string) bool {
	separator := strings.IndexByte(header, ' ')
	return separator > 0 && strings.EqualFold(header[:separator], "AAuth")
}

func (resource *Resource) handleAccessProtected(response http.ResponseWriter, request *http.Request) {
	verified, err := aauth.VerifyRequest(request.Context(), request, resource.keyResolver, resource.clock, aauth.VerifyRequestOptions{
		RequiredComponents:     []string{"authorization"},
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
	resource.accessMu.Lock()
	grant, exists := resource.access[accessToken]
	if exists && !grant.expiresAt.After(resource.clock.Now()) {
		delete(resource.access, accessToken)
		exists = false
	}
	resource.accessMu.Unlock()
	if !exists {
		writeProblem(response, http.StatusForbidden, "invalid_access", errors.New("access token is unknown or expired"))
		return
	}
	thumbprint, err := verified.PublicKey.Thumbprint()
	if err != nil || grant.agent != verified.Agent || grant.thumbprint != thumbprint {
		writeProblem(response, http.StatusForbidden, "invalid_access", errors.New("access token is bound to a different agent key"))
		return
	}
	if !scopesContained(resource.scopes, grant.scope) {
		writeProblem(response, http.StatusForbidden, "insufficient_scope", errors.New("access token does not grant the operation scope"))
		return
	}
	if resource.seenReplay(verified.ReplayKey, verified.Created.Add(aauth.DefaultSignatureWindow)) {
		writeSignatureFailure(response, errors.New("request proof was replayed"))
		return
	}
	result, err := resource.operation(request.Context(), aauth.AuthorizedRequest{
		Agent:   grant.agent,
		Subject: grant.subject,
		Scope:   append([]string(nil), grant.scope...),
		Mission: grant.mission,
		Method:  request.Method,
		Path:    request.URL.Path,
	})
	if err != nil {
		writeProblem(response, http.StatusInternalServerError, "operation_failed", err)
		return
	}
	writeJSON(response, http.StatusOK, result)
}

func (resource *Resource) seenReplay(key string, expiresAt time.Time) bool {
	resource.replayMu.Lock()
	defer resource.replayMu.Unlock()
	now := resource.clock.Now()
	for existing, expiry := range resource.replayedProof {
		if !expiry.After(now) {
			delete(resource.replayedProof, existing)
		}
	}
	if _, exists := resource.replayedProof[key]; exists {
		return true
	}
	resource.replayedProof[key] = expiresAt
	return false
}

func (resource *Resource) handleMetadata(response http.ResponseWriter, _ *http.Request) {
	metadata := map[string]any{
		"issuer":                 resource.identifier,
		"authorization_endpoint": resource.identifier + "/authorize",
	}
	if resource.authorizationPolicy != nil {
		metadata["access_mode"] = "aauth-access-token"
	} else {
		metadata["access_mode"] = "auth-token"
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

func (resource *Resource) handleR3Document(response http.ResponseWriter, request *http.Request) {
	verified, err := aauth.VerifyRequest(request.Context(), request, resource.keyResolver, resource.clock, aauth.VerifyRequestOptions{
		AllowedSignatureKeyTypes: []string{aauth.SignatureKeyJWKSURI},
	})
	if err != nil {
		writeSignatureFailure(response, err)
		return
	}
	if verified.Signer != resource.tokenAudience {
		writeSignatureFailure(response, errors.New("R3 document request is not signed by the resource access server"))
		return
	}
	if resource.seenReplay(verified.ReplayKey, verified.Created.Add(aauth.DefaultSignatureWindow)) {
		writeSignatureFailure(response, errors.New("request proof was replayed"))
		return
	}
	if resource.r3DocumentStore == nil {
		writeProblem(response, http.StatusNotFound, "not_found", errors.New("R3 documents are not configured"))
		return
	}
	s256 := request.PathValue("s256")
	document, err := resource.r3DocumentStore.Load(request.Context(), s256)
	if errors.Is(err, ErrR3DocumentNotFound) {
		writeProblem(response, http.StatusNotFound, "not_found", errors.New("R3 document is unknown"))
		return
	}
	if err != nil || aauth.R3S256(document) != s256 {
		writeProblem(response, http.StatusInternalServerError, "r3_custody_failed", err)
		return
	}
	response.Header().Set("Content-Type", "application/json")
	response.Header().Set("Cache-Control", "private, immutable")
	response.Header().Set("X-Content-Type-Options", "nosniff")
	response.WriteHeader(http.StatusOK)
	_, _ = response.Write(document)
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
