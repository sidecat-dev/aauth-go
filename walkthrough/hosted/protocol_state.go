package main

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/personserver"
	"gitlab.com/sidecat-dev/aauth-go/r3"
	"gitlab.com/sidecat-dev/aauth-go/resource"
)

type connectorResultRecord struct {
	RequestKey string `json:"request_key"`
	Account    string `json:"account"`
	Result     string `json:"result"`
}

type hostedR3DocumentJSON struct {
	ReferenceURI            string                   `json:"r3_uri"`
	ReferenceDigest         string                   `json:"r3_s256"`
	ExactJSON               []byte                   `json:"exact_json"`
	PersonServer            string                   `json:"person_server"`
	AuthTokenIssuer         string                   `json:"auth_token_issuer"`
	AuthTokenIssuerDocument string                   `json:"auth_token_issuer_document"`
	ClassContext            hostedR3ClassContextJSON `json:"class_context"`
}

type hostedR3ClassContextJSON struct {
	ExactResourceToken   string                        `json:"exact_resource_token"`
	ResourceToken        hostedResourceTokenClaimsJSON `json:"resource_token"`
	PersonTokenIssuedAt  int64                         `json:"person_token_issued_at"`
	PersonTokenNotBefore int64                         `json:"person_token_not_before"`
	PersonTokenExpiresAt int64                         `json:"person_token_expires_at"`
}

type hostedResourceTokenClaimsJSON struct {
	Issuer           string                     `json:"issuer"`
	DWK              string                     `json:"dwk"`
	Audience         string                     `json:"audience"`
	JTI              string                     `json:"jti"`
	PersonServer     string                     `json:"person_server"`
	Subject          string                     `json:"subject"`
	PresentedJTI     string                     `json:"presented_jti"`
	AgentJKT         string                     `json:"agent_jkt"`
	IssuedAt         int64                      `json:"issued_at"`
	ExpiresAt        int64                      `json:"expires_at"`
	NotBefore        int64                      `json:"not_before"`
	Scope            string                     `json:"scope"`
	Account          *string                    `json:"account,omitempty"`
	MissionS256      string                     `json:"mission_s256"`
	Tenant           string                     `json:"tenant"`
	Interaction      *aauth.ResourceInteraction `json:"interaction,omitempty"`
	AdditionalClaims map[string]json.RawMessage `json:"additional_claims,omitempty"`
}

type hostedR3IssuanceJSON struct {
	AuthTokenReference aauth.TokenReference `json:"auth_token_reference"`
	Resource           string               `json:"resource"`
	ReferenceURI       string               `json:"r3_uri"`
	ReferenceDigest    string               `json:"r3_s256"`
	Vocabulary         r3.VocabularyURI     `json:"vocabulary"`
	IssuedAt           time.Time            `json:"issued_at"`
	PersonServer       string               `json:"person_server"`
	Subject            string               `json:"subject"`
	Account            *string              `json:"account,omitempty"`
	PresentedJTI       string               `json:"presented_jti"`
	AgentJKT           string               `json:"agent_jkt"`
	Agent              string               `json:"agent"`
	ParentAgent        string               `json:"parent_agent,omitempty"`
}

type hostedProtocolState struct {
	Missions       map[string]personserver.MissionRecord         `json:"missions"`
	PersonTokens   map[string]personserver.PersonTokenRecord     `json:"person_tokens"`
	AuthTokens     map[string]personserver.IssuedAuthTokenRecord `json:"auth_tokens"`
	R3Issuances    map[string]hostedR3IssuanceJSON               `json:"r3_issuances"`
	R3Documents    map[string]hostedR3DocumentJSON               `json:"r3_documents"`
	BudgetCharges  map[string]resource.BudgetCharge              `json:"budget_charges"`
	BudgetConsumed map[string]int64                              `json:"budget_consumed"`
	Lineages       map[string]resource.BudgetLineage             `json:"budget_lineages"`
	Connector      map[string]connectorResultRecord              `json:"connector_results"`
	ConnectorCalls int                                           `json:"connector_calls"`
	RevokedAgents  map[string]bool                               `json:"revoked_agents"`
}

type hostedProtocolStore struct {
	mu   sync.Mutex
	path string
}

func initializeHostedProtocolStore(path string) error {
	return writeJSONFile(path, 0o600, hostedProtocolState{
		Missions: map[string]personserver.MissionRecord{}, PersonTokens: map[string]personserver.PersonTokenRecord{},
		AuthTokens: map[string]personserver.IssuedAuthTokenRecord{}, R3Issuances: map[string]hostedR3IssuanceJSON{},
		R3Documents: map[string]hostedR3DocumentJSON{}, BudgetCharges: map[string]resource.BudgetCharge{},
		BudgetConsumed: map[string]int64{}, Lineages: map[string]resource.BudgetLineage{},
		Connector: map[string]connectorResultRecord{}, RevokedAgents: map[string]bool{},
	})
}

func newHostedProtocolStore(path string) *hostedProtocolStore {
	return &hostedProtocolStore{path: path}
}

func (store *hostedProtocolStore) load() (hostedProtocolState, error) {
	var state hostedProtocolState
	if err := readJSON(store.path, &state); err != nil {
		return state, err
	}
	if state.Missions == nil || state.PersonTokens == nil || state.AuthTokens == nil ||
		state.R3Issuances == nil || state.R3Documents == nil || state.BudgetCharges == nil ||
		state.BudgetConsumed == nil || state.Lineages == nil || state.Connector == nil || state.RevokedAgents == nil {
		return state, errors.New("hosted protocol store is incomplete")
	}
	return state, nil
}

func (store *hostedProtocolStore) save(state hostedProtocolState) error {
	return writeJSONFile(store.path, 0o600, state)
}

func tokenKey(issuer, jti string) string { return issuer + "\x1f" + jti }
func referenceKey(reference aauth.TokenReference) string {
	return tokenKey(reference.Issuer, reference.JTI)
}

func (store *hostedProtocolStore) Revoke(_ context.Context, reference aauth.TokenReference) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	state, err := store.load()
	if err != nil {
		return err
	}
	state.RevokedAgents[referenceKey(reference)] = true
	return store.save(state)
}

func (store *hostedProtocolStore) IsRevoked(_ context.Context, reference aauth.TokenReference) (bool, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	state, err := store.load()
	if err != nil {
		return false, err
	}
	return state.RevokedAgents[referenceKey(reference)], nil
}

func (store *hostedProtocolStore) connectorCallCount() (int, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	state, err := store.load()
	if err != nil {
		return 0, err
	}
	return state.ConnectorCalls, nil
}

var _ personserver.AgentTokenRevocationStore = (*hostedProtocolStore)(nil)
var _ resource.AgentTokenRevocationStore = (*hostedProtocolStore)(nil)
