package personserver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/r3"
	"gitlab.com/sidecat-dev/aauth-go/r3/vocab/mcp"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

func TestNewPSAuthorizationValidatesDirectR3Configuration(t *testing.T) {
	t.Parallel()

	validR3 := DirectR3Config{
		Registry:   newPersonServerR3Registry(t),
		HTTPClient: http.DefaultClient,
		Admit:      func(context.Context, string) error { return nil },
		AuthorizeDocument: func(context.Context, AuthorizationRequest, r3.Reference, r3.Document) (DirectR3Decision, error) {
			return DirectR3Decision{}, nil
		},
		Issuances: &directR3TestIssuanceStore{},
	}
	valid := PSAuthorizationConfig{
		Issuer: "https://person.example", SigningKey: personServerTestKey(t, "direct-R3-config"),
		KeyResolver: signaturekey.StaticKeyResolver{}, Clock: aauth.SystemClock{},
		NewID: func() string { return "token" }, Tokens: newMemoryTokenStore(),
		BindPerson: func(context.Context, PersonTokenRequest) (Person, error) { return Person{}, nil },
		Authorize: func(context.Context, AuthorizationRequest) (AuthorizationDecision, error) {
			return AuthorizationDecision{Scopes: []string{"records.read"}, Lifetime: time.Minute}, nil
		},
		R3: &validR3,
	}
	if _, err := NewPSAuthorization(valid); err != nil {
		t.Fatalf("complete direct R3 configuration: %v", err)
	}
	r3Only := valid
	r3Only.Authorize = nil
	if _, err := NewPSAuthorization(r3Only); err != nil {
		t.Fatalf("direct R3 required an unrelated Core policy: %v", err)
	}
	deferred := valid
	deferred.RequireAuthorizationInteraction = func(context.Context, AuthorizationRequest) (AuthorizationInteractionPolicy, bool, error) {
		return AuthorizationInteractionPolicy{}, false, nil
	}
	deferred.AuthorizationInteractions = newMemoryDeferredAuthorizationStore()
	if _, err := NewPSAuthorization(deferred); err == nil {
		t.Fatal("direct R3 silently bypassed configured deferred Core authorization")
	}

	for _, test := range []struct {
		name   string
		change func(*DirectR3Config)
	}{
		{name: "vocabulary registry", change: func(config *DirectR3Config) { config.Registry = r3.Registry{} }},
		{name: "HTTP client", change: func(config *DirectR3Config) { config.HTTPClient = nil }},
		{name: "egress admission", change: func(config *DirectR3Config) { config.Admit = nil }},
		{name: "document authorization policy", change: func(config *DirectR3Config) { config.AuthorizeDocument = nil }},
		{name: "issuance store", change: func(config *DirectR3Config) { config.Issuances = nil }},
		{name: "document byte limit", change: func(config *DirectR3Config) { config.MaximumDocumentBytes = -1 }},
		{name: "fetch timeout", change: func(config *DirectR3Config) { config.FetchTimeout = -1 }},
	} {
		t.Run(test.name, func(t *testing.T) {
			config := valid
			direct := validR3
			test.change(&direct)
			config.R3 = &direct
			if _, err := NewPSAuthorization(config); err == nil {
				t.Fatal("incomplete direct R3 configuration was accepted")
			}
		})
	}
}

func TestDirectR3AuthorizationRetainsExactIssuanceBeforeReturningToken(t *testing.T) {
	t.Parallel()

	protocol := newDirectR3TestProtocol(t)
	server := protocol.newServer(t, nil)
	response := protocol.exchange(t, server, protocol.resourceToken, nil)
	if response.Code != http.StatusOK || response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("direct R3 exchange = %d headers=%v body=%s", response.Code, response.Header(), response.Body.String())
	}
	var output struct {
		AuthToken string `json:"auth_token"`
		ExpiresIn int64  `json:"expires_in"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &output); err != nil || output.AuthToken == "" {
		t.Fatalf("direct R3 output = %#v, %v", output, err)
	}
	claims, reference, granted, err := r3.VerifyDirectAuthToken(
		context.Background(), protocol.registry, output.AuthToken, protocol.resolver, protocol.clock,
	)
	if err != nil {
		t.Fatal(err)
	}
	if claims.Issuer != protocol.personServerID || claims.DWK != aauth.PersonDiscoveryDocument ||
		claims.Audience != protocol.resourceID || claims.JTI != protocol.authTokenJTI ||
		claims.PersonServer != protocol.personServerID || claims.Subject != protocol.subject ||
		claims.Scope != "records.read" || claims.Tenant != protocol.tenant ||
		claims.Account == nil || *claims.Account != protocol.account ||
		!claims.Confirmation.JWK.Equal(protocol.agentKey.PublicJWK()) ||
		claims.IssuedAt != protocol.now.Unix() || claims.ExpiresAt != protocol.now.Add(30*time.Minute).Unix() ||
		output.ExpiresIn != int64((30*time.Minute)/time.Second) || reference != protocol.reference {
		t.Fatalf("direct R3 Auth token = %#v; reference=%#v expires_in=%d", claims, reference, output.ExpiresIn)
	}
	wantGranted := protocol.decision.Grant.GrantedOperations()
	equal, err := granted.Equal(wantGranted)
	if err != nil || !equal {
		t.Fatalf("direct R3 granted operations = %#v, %v", granted.Operations(), err)
	}

	records, attempts := protocol.issuances.snapshot()
	wantRecord := r3.IssuanceRecord{
		AuthTokenReference: aauth.TokenReference{Issuer: protocol.personServerID, JTI: protocol.authTokenJTI},
		Resource:           protocol.resourceID,
		R3Reference:        protocol.reference,
		Vocabulary:         mcp.URI,
		IssuedAt:           protocol.now.UTC(),
		PersonServer:       protocol.personServerID,
		Subject:            protocol.subject,
		Account:            testDirectR3StringPointer(protocol.account),
		PresentedJTI:       protocol.personTokenJTI,
		AgentJKT:           protocol.agentJKT,
		Agent:              protocol.agentID,
	}
	if attempts != 1 || !reflect.DeepEqual(records, []r3.IssuanceRecord{wantRecord}) {
		t.Fatalf("direct R3 issuance attempts/records = %d/%#v", attempts, records)
	}
	if protocol.corePolicyCalls != 0 || protocol.r3PolicyCalls != 1 || protocol.fetchCalls != 1 ||
		!reflect.DeepEqual(protocol.sequence, []string{"fetch", "policy", "commit"}) {
		t.Fatalf(
			"direct R3 core/R3/fetch/sequence = %d/%d/%d/%#v",
			protocol.corePolicyCalls, protocol.r3PolicyCalls, protocol.fetchCalls, protocol.sequence,
		)
	}
}

func TestDirectR3AuthorizationRejectsGrantOutsideDocumentBeforeCommit(t *testing.T) {
	t.Parallel()

	protocol := newDirectR3TestProtocol(t)
	deleteMCP, err := mcp.NewOperation("records.delete")
	if err != nil {
		t.Fatal(err)
	}
	deleteOperation, err := deleteMCP.ToR3()
	if err != nil {
		t.Fatal(err)
	}
	otherOperations, err := mcp.NewOperationSet(deleteMCP)
	if err != nil {
		t.Fatal(err)
	}
	otherDocument, err := r3.NewDocument(otherOperations, r3.DocumentOptions{Account: testDirectR3StringPointer(protocol.account)})
	if err != nil {
		t.Fatal(err)
	}
	outside, err := r3.NewGrantedOperations(mcp.Vocabulary(), deleteOperation)
	if err != nil {
		t.Fatal(err)
	}
	protocol.decision.Grant, err = r3.NewGrant(outside, otherDocument)
	if err != nil {
		t.Fatal(err)
	}

	response := protocol.exchange(t, protocol.newServer(t, nil), protocol.resourceToken, nil)
	assertDirectR3FailureWithoutToken(t, response, http.StatusInternalServerError, "server_error")
	records, attempts := protocol.issuances.snapshot()
	if attempts != 0 || len(records) != 0 || protocol.r3PolicyCalls != 1 || protocol.corePolicyCalls != 0 ||
		!reflect.DeepEqual(protocol.sequence, []string{"fetch", "policy"}) {
		t.Fatalf(
			"outside grant attempts/records/policy/core/sequence = %d/%d/%d/%d/%#v",
			attempts, len(records), protocol.r3PolicyCalls, protocol.corePolicyCalls, protocol.sequence,
		)
	}
}

func TestDirectR3AuthorizationCommitErrorWithholdsToken(t *testing.T) {
	t.Parallel()

	protocol := newDirectR3TestProtocol(t)
	protocol.issuances.commitErr = errors.New("direct R3 issuance retention unavailable")
	response := protocol.exchange(t, protocol.newServer(t, nil), protocol.resourceToken, nil)
	assertDirectR3FailureWithoutToken(t, response, http.StatusInternalServerError, "server_error")
	records, attempts := protocol.issuances.snapshot()
	if attempts != 1 || len(records) != 0 || protocol.r3PolicyCalls != 1 || protocol.corePolicyCalls != 0 ||
		!reflect.DeepEqual(protocol.sequence, []string{"fetch", "policy", "commit"}) {
		t.Fatalf(
			"commit failure attempts/records/policy/core/sequence = %d/%d/%d/%d/%#v",
			attempts, len(records), protocol.r3PolicyCalls, protocol.corePolicyCalls, protocol.sequence,
		)
	}
}

func TestDirectR3AuthorizationCommitThenErrorWithholdsToken(t *testing.T) {
	t.Parallel()

	protocol := newDirectR3TestProtocol(t)
	protocol.issuances.commitErr = errors.New("direct R3 issuance outcome is uncertain")
	protocol.issuances.retainOnError = true
	response := protocol.exchange(t, protocol.newServer(t, nil), protocol.resourceToken, nil)
	assertDirectR3FailureWithoutToken(t, response, http.StatusInternalServerError, "server_error")
	records, attempts := protocol.issuances.snapshot()
	if attempts != 1 || len(records) != 1 || protocol.r3PolicyCalls != 1 ||
		!reflect.DeepEqual(protocol.sequence, []string{"fetch", "policy", "commit"}) {
		t.Fatalf(
			"uncertain commit attempts/records/policy/sequence = %d/%d/%d/%#v",
			attempts, len(records), protocol.r3PolicyCalls, protocol.sequence,
		)
	}
}

func TestDirectR3AuthorizationRevocationCommitErrorWithholdsTokenAfterAudit(t *testing.T) {
	t.Parallel()

	protocol := newDirectR3TestProtocol(t)
	issued := newTestIssuedAuthTokenStore()
	issued.commitError = errors.New("revocation routing unavailable")
	server := protocol.newServer(t, func(config *PSAuthorizationConfig) {
		config.Revocation = &AuthTokenRevocationConfig{
			IssuedTokens: issued, HTTPClient: http.DefaultClient,
			Admit: func(context.Context, string) error { return nil },
		}
	})
	response := protocol.exchange(t, server, protocol.resourceToken, nil)
	assertDirectR3FailureWithoutToken(t, response, http.StatusInternalServerError, "server_error")
	records, attempts := protocol.issuances.snapshot()
	if attempts != 1 || len(records) != 1 || issued.commitCalls != 1 ||
		!reflect.DeepEqual(protocol.sequence, []string{"fetch", "policy", "commit"}) {
		t.Fatalf(
			"revocation failure audit attempts/records/revocation/sequence = %d/%d/%d/%#v",
			attempts, len(records), issued.commitCalls, protocol.sequence,
		)
	}
}

func TestDirectR3AuthorizationPolicyDenialCreatesNoAudit(t *testing.T) {
	t.Parallel()

	protocol := newDirectR3TestProtocol(t)
	protocol.policyErr = errors.Join(ErrAccessDenied, errors.New("direct R3 policy denied authorization"))
	response := protocol.exchange(t, protocol.newServer(t, nil), protocol.resourceToken, nil)
	assertDirectR3FailureWithoutToken(t, response, http.StatusForbidden, "access_denied")
	records, attempts := protocol.issuances.snapshot()
	if attempts != 0 || len(records) != 0 || protocol.r3PolicyCalls != 1 ||
		!reflect.DeepEqual(protocol.sequence, []string{"fetch", "policy"}) {
		t.Fatalf(
			"policy failure attempts/records/policy/sequence = %d/%d/%d/%#v",
			attempts, len(records), protocol.r3PolicyCalls, protocol.sequence,
		)
	}
}

func TestDirectR3ConfigurationLeavesCoreOnlyAuthorizationOnCorePath(t *testing.T) {
	t.Parallel()

	protocol := newDirectR3TestProtocol(t)
	coreClaims := protocol.resourceClaims
	coreClaims.JTI = "direct-R3-core-resource-token"
	coreClaims.Account = nil
	coreClaims.AdditionalClaims = nil
	coreToken, err := aauth.MintResourceToken(protocol.resourceKey, coreClaims)
	if err != nil {
		t.Fatal(err)
	}
	response := protocol.exchange(t, protocol.newServer(t, nil), coreToken, nil)
	if response.Code != http.StatusOK {
		t.Fatalf("Core-only exchange with direct R3 configured = %d %s", response.Code, response.Body.String())
	}
	var output struct {
		AuthToken string `json:"auth_token"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &output); err != nil || output.AuthToken == "" {
		t.Fatalf("Core-only output = %#v, %v", output, err)
	}
	claims, err := aauth.VerifyAuthToken(context.Background(), output.AuthToken, protocol.resolver, protocol.clock)
	if err != nil {
		t.Fatal(err)
	}
	if claims.Issuer != protocol.personServerID || claims.DWK != aauth.PersonDiscoveryDocument ||
		claims.Audience != protocol.resourceID || claims.Scope != "records.read" || len(claims.AdditionalClaims) != 0 {
		t.Fatalf("Core-only Auth token = %#v", claims)
	}
	records, attempts := protocol.issuances.snapshot()
	if protocol.corePolicyCalls != 1 || protocol.r3PolicyCalls != 0 || protocol.fetchCalls != 0 ||
		attempts != 0 || len(records) != 0 || len(protocol.sequence) != 0 {
		t.Fatalf(
			"Core-only core/R3/fetch/attempts/records/sequence = %d/%d/%d/%d/%d/%#v",
			protocol.corePolicyCalls, protocol.r3PolicyCalls, protocol.fetchCalls,
			attempts, len(records), protocol.sequence,
		)
	}
}

func TestDirectR3OnlyConfigurationRefusesCoreRequestAsPolicyDenial(t *testing.T) {
	t.Parallel()

	protocol := newDirectR3TestProtocol(t)
	coreClaims := protocol.resourceClaims
	coreClaims.JTI = "direct-R3-only-core-resource-token"
	coreClaims.Account = nil
	coreClaims.AdditionalClaims = nil
	coreToken, err := aauth.MintResourceToken(protocol.resourceKey, coreClaims)
	if err != nil {
		t.Fatal(err)
	}
	server := protocol.newServer(t, func(config *PSAuthorizationConfig) {
		config.Authorize = nil
	})
	response := protocol.exchange(t, server, coreToken, nil)
	assertDirectR3FailureWithoutToken(t, response, http.StatusForbidden, "access_denied")
	records, attempts := protocol.issuances.snapshot()
	if protocol.corePolicyCalls != 0 || protocol.r3PolicyCalls != 0 || protocol.fetchCalls != 0 ||
		attempts != 0 || len(records) != 0 || len(protocol.sequence) != 0 {
		t.Fatalf(
			"R3-only Core refusal core/R3/fetch/attempts/records/sequence = %d/%d/%d/%d/%d/%#v",
			protocol.corePolicyCalls, protocol.r3PolicyCalls, protocol.fetchCalls,
			attempts, len(records), protocol.sequence,
		)
	}
}

func TestDirectR3AuthorizationRejectsProposalBeforePolicyOrCommit(t *testing.T) {
	t.Parallel()

	protocol := newDirectR3TestProtocol(t)
	filter, err := r3.NewInlineParameter([]byte(`{"status":"open"}`))
	if err != nil {
		t.Fatal(err)
	}
	parameters, err := r3.NewParameters(map[string]r3.Parameter{"filter": filter})
	if err != nil {
		t.Fatal(err)
	}
	proposal, err := r3.NewProposal(protocol.read, parameters, r3.ProposalOptions{Account: testDirectR3StringPointer(protocol.account)})
	if err != nil {
		t.Fatal(err)
	}
	protocol.exactArtifact, err = json.Marshal(proposal)
	if err != nil {
		t.Fatal(err)
	}
	protocol.resourceClaims.JTI = "direct-R3-proposal-resource-token"
	protocol.resourceToken, protocol.reference, err = r3.MintProposalResourceToken(
		protocol.registry, protocol.resourceKey, protocol.resourceClaims,
		protocol.resourceID+"/r3/proposal", protocol.exactArtifact,
	)
	if err != nil {
		t.Fatal(err)
	}

	response := protocol.exchange(t, protocol.newServer(t, nil), protocol.resourceToken, nil)
	assertDirectR3FailureWithoutToken(t, response, http.StatusBadRequest, "invalid_resource_token")
	records, attempts := protocol.issuances.snapshot()
	if protocol.fetchCalls != 1 || protocol.r3PolicyCalls != 0 || protocol.corePolicyCalls != 0 ||
		attempts != 0 || len(records) != 0 || !reflect.DeepEqual(protocol.sequence, []string{"fetch"}) {
		t.Fatalf(
			"proposal fetch/R3/core/attempts/records/sequence = %d/%d/%d/%d/%d/%#v",
			protocol.fetchCalls, protocol.r3PolicyCalls, protocol.corePolicyCalls,
			attempts, len(records), protocol.sequence,
		)
	}
}

func TestDirectR3MissionRequiresAtomicStoreBeforePolicyOrCommit(t *testing.T) {
	t.Parallel()

	protocol := newDirectR3TestProtocol(t)
	store := newMemoryMissionStore()
	mission := commitCompositionMission(
		t, store, protocol.personServerID, protocol.agentID, protocol.now,
	)
	record := directPersonTokenRecord(
		protocol.personTokenJTI, protocol.personServerID, protocol.resourceID,
		protocol.subject, protocol.tenant, protocol.providerID, protocol.agentID,
		protocol.agentKey.PublicJWK(), protocol.now.Add(10*time.Minute), protocol.now.Add(15*time.Minute),
	)
	record.MissionS256 = mission.S256
	if err := store.Commit(context.Background(), record); err != nil {
		t.Fatal(err)
	}
	protocol.resourceClaims.JTI = "direct-R3-mission-resource-token"
	protocol.resourceClaims.MissionS256 = mission.S256
	var err error
	protocol.resourceToken, _, err = r3.MintResourceToken(
		protocol.registry, protocol.resourceKey, protocol.resourceClaims,
		protocol.reference.URI(), protocol.exactArtifact,
	)
	if err != nil {
		t.Fatal(err)
	}

	config := protocol.config()
	config.Tokens = store
	config.Missions = unusedCompositionMissionConfig()
	server, err := NewPSAuthorization(config)
	if err != nil {
		t.Fatal(err)
	}
	response := protocol.exchange(t, server, protocol.resourceToken, nil)
	assertDirectR3FailureWithoutToken(t, response, http.StatusInternalServerError, "server_error")
	records, attempts := protocol.issuances.snapshot()
	if protocol.fetchCalls != 0 || protocol.r3PolicyCalls != 0 || protocol.corePolicyCalls != 0 ||
		attempts != 0 || len(records) != 0 || len(protocol.sequence) != 0 {
		t.Fatalf(
			"mission fetch/R3/core/attempts/records/sequence = %d/%d/%d/%d/%d/%#v",
			protocol.fetchCalls, protocol.r3PolicyCalls, protocol.corePolicyCalls,
			attempts, len(records), protocol.sequence,
		)
	}
}

func TestDirectR3MissionNormalizesRealClockInstantForAtomicIssuance(t *testing.T) {
	t.Parallel()

	protocol := newDirectR3TestProtocol(t)
	protocol.now = protocol.now.Add(123 * time.Nanosecond)
	protocol.clock = aauth.ClockFunc(func() time.Time { return protocol.now })
	store := &directR3MissionClockStore{memoryMissionStore: newMemoryMissionStore()}
	mission := commitCompositionMission(t, store.memoryMissionStore, protocol.personServerID, protocol.agentID, protocol.now)
	record := directPersonTokenRecord(
		protocol.personTokenJTI, protocol.personServerID, protocol.resourceID,
		protocol.subject, protocol.tenant, protocol.providerID, protocol.agentID,
		protocol.agentKey.PublicJWK(), protocol.now.Add(10*time.Minute), protocol.now.Add(15*time.Minute),
	)
	record.MissionS256 = mission.S256
	if err := store.Commit(context.Background(), record); err != nil {
		t.Fatal(err)
	}
	protocol.resourceClaims.JTI = "direct-R3-real-clock-mission-resource-token"
	protocol.resourceClaims.MissionS256 = mission.S256
	var err error
	protocol.resourceToken, _, err = r3.MintResourceToken(
		protocol.registry, protocol.resourceKey, protocol.resourceClaims,
		protocol.reference.URI(), protocol.exactArtifact,
	)
	if err != nil {
		t.Fatal(err)
	}
	config := protocol.config()
	config.Tokens = store
	config.Missions = unusedCompositionMissionConfig()
	server, err := NewPSAuthorization(config)
	if err != nil {
		t.Fatal(err)
	}
	response := protocol.exchange(t, server, protocol.resourceToken, nil)
	if response.Code != http.StatusOK {
		t.Fatalf("mission-bound direct R3 with real clock = %d body=%s", response.Code, response.Body.String())
	}
}

type directR3MissionClockStore struct {
	*memoryMissionStore
}

func (store *directR3MissionClockStore) CommitMissionR3AuthToken(
	_ context.Context,
	expected MissionRecord,
	at time.Time,
	token IssuedAuthTokenRecord,
	issuance r3.IssuanceRecord,
) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.requireActiveMissionLocked(expected, at); err != nil {
		return err
	}
	if token.MissionS256 != expected.S256 || issuance.AuthTokenReference != token.Reference ||
		issuance.Resource != token.Resource || !issuance.IssuedAt.Equal(token.IssuedAt) ||
		issuance.PersonServer != token.Reference.Issuer || issuance.Agent != expected.Agent {
		return ErrMissionConflict
	}
	key := token.Reference.Issuer + "\x00" + token.Reference.JTI
	if _, exists := store.authTokens[key]; exists {
		return ErrMissionConflict
	}
	store.authTokens[key] = token
	return nil
}

func TestDirectR3UnsupportedCombinationNamesDelegationBoundaries(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name       string
		delegated  bool
		upstream   *verifiedUpstreamToken
		wantDetail string
	}{
		{name: "class-only", wantDetail: ""},
		{name: "sub-agent", delegated: true, wantDetail: "sub-agent"},
		{name: "call chain", upstream: &verifiedUpstreamToken{}, wantDetail: "call chaining"},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := directR3UnsupportedCombination(test.delegated, test.upstream)
			if test.wantDetail == "" {
				if err != nil {
					t.Fatalf("class-only combination: %v", err)
				}
				return
			}
			if err == nil || !bytes.Contains([]byte(err.Error()), []byte(test.wantDetail)) {
				t.Fatalf("combination error = %v, want detail %q", err, test.wantDetail)
			}
		})
	}
}

type directR3TestProtocol struct {
	t *testing.T

	now   time.Time
	clock aauth.Clock

	providerID       string
	personServerID   string
	resourceID       string
	agentID          string
	subject          string
	tenant           string
	account          string
	personTokenJTI   string
	resourceTokenJTI string
	authTokenJTI     string

	providerKey jose.SigningKey
	personKey   jose.SigningKey
	resourceKey jose.SigningKey
	agentKey    jose.SigningKey
	resolver    signaturekey.StaticKeyResolver
	agentToken  string
	agentJKT    string

	registry       r3.Registry
	read           r3.Operation
	export         r3.Operation
	document       r3.Document
	exactArtifact  []byte
	reference      r3.Reference
	resourceClaims aauth.ResourceTokenClaims
	resourceToken  string

	tokens    *memoryTokenStore
	issuances *directR3TestIssuanceStore
	decision  DirectR3Decision
	policyErr error

	fetchCalls      int
	r3PolicyCalls   int
	corePolicyCalls int
	sequence        []string
}

func newDirectR3TestProtocol(t *testing.T) *directR3TestProtocol {
	t.Helper()
	protocol := &directR3TestProtocol{
		t:                t,
		now:              time.Date(2026, 8, 31, 17, 0, 0, 0, time.UTC),
		providerID:       "https://provider.example",
		personServerID:   "https://person.example",
		resourceID:       "https://resource.example",
		agentID:          "aauth:planner@provider.example",
		subject:          "person-123",
		tenant:           "tenant-1",
		account:          "work-account",
		personTokenJTI:   "direct-R3-person-token",
		resourceTokenJTI: "direct-R3-resource-token",
		authTokenJTI:     "direct-R3-auth-token",
		providerKey:      personServerTestKey(t, "direct-R3-provider"),
		personKey:        personServerTestKey(t, "direct-R3-person"),
		resourceKey:      personServerTestKey(t, "direct-R3-resource"),
		agentKey:         personServerTestKey(t, "direct-R3-agent"),
		registry:         newPersonServerR3Registry(t),
		tokens:           newMemoryTokenStore(),
		issuances:        &directR3TestIssuanceStore{},
	}
	protocol.clock = aauth.ClockFunc(func() time.Time { return protocol.now })
	protocol.resolver = signaturekey.StaticKeyResolver{
		{Issuer: protocol.providerID, DiscoveryDocument: aauth.AgentDiscoveryDocument, KeyID: protocol.providerKey.ID()}:    protocol.providerKey.PublicJWK(),
		{Issuer: protocol.personServerID, DiscoveryDocument: aauth.PersonDiscoveryDocument, KeyID: protocol.personKey.ID()}: protocol.personKey.PublicJWK(),
		{Issuer: protocol.resourceID, DiscoveryDocument: aauth.ResourceDiscoveryDocument, KeyID: protocol.resourceKey.ID()}: protocol.resourceKey.PublicJWK(),
	}
	var err error
	protocol.agentToken, err = aauth.MintAgentToken(
		protocol.providerID, protocol.providerKey,
		aauth.AgentTokenRequest{
			Agent: protocol.agentID, PersonServer: protocol.personServerID,
			PublicKey: protocol.agentKey.PublicJWK(), Lifetime: time.Hour,
		},
		protocol.now, "direct-R3-agent-token",
	)
	if err != nil {
		t.Fatal(err)
	}
	protocol.agentJKT, err = protocol.agentKey.PublicJWK().Thumbprint()
	if err != nil {
		t.Fatal(err)
	}
	readMCP, err := mcp.NewOperation("records.read")
	if err != nil {
		t.Fatal(err)
	}
	exportMCP, err := mcp.NewOperation("records.export")
	if err != nil {
		t.Fatal(err)
	}
	protocol.read, err = readMCP.ToR3()
	if err != nil {
		t.Fatal(err)
	}
	protocol.export, err = exportMCP.ToR3()
	if err != nil {
		t.Fatal(err)
	}
	operations, err := mcp.NewOperationSet(readMCP, exportMCP)
	if err != nil {
		t.Fatal(err)
	}
	protocol.document, err = r3.NewDocument(
		operations, r3.DocumentOptions{Account: testDirectR3StringPointer(protocol.account)},
	)
	if err != nil {
		t.Fatal(err)
	}
	protocol.exactArtifact, err = json.Marshal(protocol.document)
	if err != nil {
		t.Fatal(err)
	}
	protocol.reference, err = r3.NewReference(
		protocol.resourceID+"/r3/class", r3.Digest(protocol.exactArtifact),
	)
	if err != nil {
		t.Fatal(err)
	}
	protocol.resourceClaims = aauth.ResourceTokenClaims{
		Issuer: protocol.resourceID, DWK: aauth.ResourceDiscoveryDocument,
		Audience: protocol.personServerID, JTI: protocol.resourceTokenJTI, AgentJKT: protocol.agentJKT,
		IssuedAt: protocol.now.Unix(), ExpiresAt: protocol.now.Add(5 * time.Minute).Unix(),
		Scope: "records.read records.export", Account: testDirectR3StringPointer(protocol.account),
		PersonServer: protocol.personServerID, Subject: protocol.subject,
		PresentedJTI: protocol.personTokenJTI, Tenant: protocol.tenant,
	}
	protocol.resourceToken, _, err = r3.MintResourceToken(
		protocol.registry, protocol.resourceKey, protocol.resourceClaims,
		protocol.reference.URI(), protocol.exactArtifact,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := protocol.tokens.Commit(context.Background(), directPersonTokenRecord(
		protocol.personTokenJTI, protocol.personServerID, protocol.resourceID,
		protocol.subject, protocol.tenant, protocol.providerID, protocol.agentID,
		protocol.agentKey.PublicJWK(), protocol.now.Add(20*time.Minute), protocol.now.Add(25*time.Minute),
	)); err != nil {
		t.Fatal(err)
	}
	granted, err := r3.NewGrantedOperations(mcp.Vocabulary(), protocol.read)
	if err != nil {
		t.Fatal(err)
	}
	grant, err := r3.NewGrant(granted, protocol.document)
	if err != nil {
		t.Fatal(err)
	}
	protocol.decision = DirectR3Decision{
		Scopes: []string{"records.read"}, Lifetime: 30 * time.Minute, Grant: grant,
	}
	protocol.issuances.onCommit = func() { protocol.sequence = append(protocol.sequence, "commit") }
	return protocol
}

func (protocol *directR3TestProtocol) config() PSAuthorizationConfig {
	return PSAuthorizationConfig{
		Issuer: protocol.personServerID, SigningKey: protocol.personKey,
		KeyResolver: protocol.resolver, Clock: protocol.clock,
		NewID: func() string { return protocol.authTokenJTI }, Tokens: protocol.tokens,
		BindPerson: func(context.Context, PersonTokenRequest) (Person, error) {
			return Person{}, errors.New("person binding is not used by this test")
		},
		Authorize: func(context.Context, AuthorizationRequest) (AuthorizationDecision, error) {
			protocol.corePolicyCalls++
			return AuthorizationDecision{Scopes: []string{"records.read"}, Lifetime: 30 * time.Minute}, nil
		},
		R3: &DirectR3Config{
			Registry: protocol.registry,
			HTTPClient: &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
				protocol.fetchCalls++
				protocol.sequence = append(protocol.sequence, "fetch")
				if request.URL.String() != protocol.reference.URI() {
					return nil, errors.New("unexpected direct R3 artifact URI: " + request.URL.String())
				}
				prepared, err := signaturekey.PrepareRequest(request, protocol.clock, signaturekey.VerifyOptions{
					RequireExactComponents: true,
					AcceptedSchemes:        []signaturekey.Scheme{signaturekey.SchemeJWKSURI},
				})
				if err != nil {
					return nil, err
				}
				issuer, document, _, ok := prepared.Credential().JWKSURI()
				if !ok || issuer != protocol.personServerID || document != aauth.PersonDiscoveryDocument {
					return nil, errors.New("direct R3 fetch did not use the Person Server role")
				}
				if _, err := prepared.Verify(protocol.personKey.PublicJWK()); err != nil {
					return nil, err
				}
				return &http.Response{
					StatusCode: http.StatusOK, Status: "200 OK", Request: request,
					Header: http.Header{"Content-Type": []string{"application/json"}},
					Body:   io.NopCloser(bytes.NewReader(protocol.exactArtifact)),
				}, nil
			})},
			Admit: func(_ context.Context, endpoint string) error {
				if endpoint != protocol.reference.URI() {
					return errors.New("unexpected direct R3 admitted URI: " + endpoint)
				}
				return nil
			},
			AuthorizeDocument: func(
				_ context.Context,
				request AuthorizationRequest,
				reference r3.Reference,
				document r3.Document,
			) (DirectR3Decision, error) {
				protocol.r3PolicyCalls++
				protocol.sequence = append(protocol.sequence, "policy")
				if request.Agent != protocol.agentID || request.Resource != protocol.resourceID ||
					request.Subject != protocol.subject || request.Tenant != protocol.tenant ||
					request.Account == nil || *request.Account != protocol.account ||
					reference != protocol.reference || !personServerOperationSetsEqual(
					protocol.t, document.OperationSet(), protocol.document.OperationSet(),
				) {
					return DirectR3Decision{}, errors.New("unexpected direct R3 policy input")
				}
				return protocol.decision, protocol.policyErr
			},
			Issuances: protocol.issuances,
		},
	}
}

func (protocol *directR3TestProtocol) newServer(t *testing.T, change func(*PSAuthorizationConfig)) *Server {
	t.Helper()
	config := protocol.config()
	if change != nil {
		change(&config)
	}
	server, err := NewPSAuthorization(config)
	if err != nil {
		t.Fatal(err)
	}
	return server
}

func (protocol *directR3TestProtocol) exchange(
	t *testing.T,
	server *Server,
	resourceToken string,
	additional map[string]any,
) *httptest.ResponseRecorder {
	t.Helper()
	body := map[string]any{"resource_token": resourceToken}
	for name, value := range additional {
		body[name] = value
	}
	exact, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(
		http.MethodPost, protocol.personServerID+"/token", bytes.NewReader(exact),
	)
	request.Header.Set("Content-Type", "application/json")
	if err := signPersonServerTestRequest(request, protocol.agentKey, protocol.agentToken, protocol.clock); err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	return response
}

type directR3TestIssuanceStore struct {
	mu            sync.Mutex
	records       []r3.IssuanceRecord
	attempts      int
	commitErr     error
	retainOnError bool
	onCommit      func()
}

func (store *directR3TestIssuanceStore) Commit(_ context.Context, record r3.IssuanceRecord) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.attempts++
	if store.onCommit != nil {
		store.onCommit()
	}
	owned := cloneDirectR3TestIssuanceRecord(record)
	for _, retained := range store.records {
		if retained.AuthTokenReference != owned.AuthTokenReference {
			continue
		}
		if !reflect.DeepEqual(retained, owned) {
			return r3.ErrIssuanceConflict
		}
		return store.commitErr
	}
	if store.retainOnError {
		store.records = append(store.records, owned)
	}
	if store.commitErr != nil {
		return store.commitErr
	}
	store.records = append(store.records, owned)
	return nil
}

func (store *directR3TestIssuanceStore) snapshot() ([]r3.IssuanceRecord, int) {
	store.mu.Lock()
	defer store.mu.Unlock()
	records := make([]r3.IssuanceRecord, len(store.records))
	for index, record := range store.records {
		records[index] = cloneDirectR3TestIssuanceRecord(record)
	}
	return records, store.attempts
}

func cloneDirectR3TestIssuanceRecord(record r3.IssuanceRecord) r3.IssuanceRecord {
	cloned := record
	if record.Account != nil {
		cloned.Account = testDirectR3StringPointer(*record.Account)
	}
	return cloned
}

func assertDirectR3FailureWithoutToken(
	t *testing.T,
	response *httptest.ResponseRecorder,
	wantStatus int,
	wantCode string,
) {
	t.Helper()
	var body map[string]json.RawMessage
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatalf("failure body = %s: %v", response.Body.String(), err)
	}
	var code string
	if err := json.Unmarshal(body["error"], &code); err != nil {
		t.Fatalf("failure error code = %s: %v", body["error"], err)
	}
	if response.Code != wantStatus || code != wantCode || body["auth_token"] != nil {
		t.Fatalf("failure = %d %s, want %d %q without token", response.Code, response.Body.String(), wantStatus, wantCode)
	}
}

func testDirectR3StringPointer(value string) *string {
	copy := value
	return &copy
}

var _ r3.IssuanceStore = (*directR3TestIssuanceStore)(nil)
