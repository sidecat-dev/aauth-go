package personserver

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
)

// An auth token issued in a call chain keeps the tie to its upstream token in
// its own issuance record, so a step-up that presents that auth token is still
// held to the same upstream token, including after the server is recomposed.
func TestCallChainingAuthTypedStepUpKeepsUpstreamTie(t *testing.T) {
	protocol := newCallChainingProtocol(t)
	compact, current := protocol.chainedAuthToken(t, protocol.newServer(t, protocol.config()))
	protocol.assertChainedIssuance(t, current)

	stepUp := protocol.stepUpResourceToken(t, compact, current, "payments.charge payments.refund")
	protocol.chainAuthorize = authorizeRequestedCallChainScopes
	_, _, beforeLoads := protocol.store.observation()
	recomposed := protocol.newServer(t, protocol.config())
	_, next := protocol.decodeAuthToken(t, protocol.tokenRequest(t, recomposed, stepUp, protocol.upstreamToken, ""))

	if next.JTI == current.JTI || next.Subject != protocol.downstreamSubject ||
		next.Audience != protocol.resourceTwoID || next.Scope != "payments.charge payments.refund" ||
		!next.Confirmation.JWK.Equal(protocol.resourceOneProofKey.PublicJWK()) {
		t.Fatalf("step-up auth token = %#v", next)
	}
	protocol.assertChainedIssuance(t, next)
	_, commits, loads := protocol.store.observation()
	if protocol.chainBindCalls != 1 || protocol.chainAuthorizeCalls != 2 ||
		protocol.ordinaryBindCalls != 0 || protocol.ordinaryAuthorizeCalls != 0 ||
		commits != 1 || loads != beforeLoads {
		t.Fatalf(
			"step-up calls/state = chain %d/%d ordinary %d/%d person commits %d loads %d (before %d)",
			protocol.chainBindCalls, protocol.chainAuthorizeCalls,
			protocol.ordinaryBindCalls, protocol.ordinaryAuthorizeCalls, commits, loads, beforeLoads,
		)
	}
}

func TestCallChainingAuthTypedStepUpRejectsOmissionSubstitutionAndByteRewrite(t *testing.T) {
	for _, test := range []struct {
		name     string
		upstream func(*testing.T, *callChainingProtocol) string
	}{
		{
			name:     "omitted upstream",
			upstream: func(*testing.T, *callChainingProtocol) string { return "" },
		},
		{
			name: "different token reference",
			upstream: func(t *testing.T, protocol *callChainingProtocol) string {
				claims := protocol.upstreamClaims
				claims.JTI = "substituted-upstream"
				return mintCallChainingAuthToken(t, protocol.personServerKey, claims)
			},
		},
		{
			name: "same reference with different exact bytes",
			upstream: func(t *testing.T, protocol *callChainingProtocol) string {
				return reserializeCallChainingToken(t, protocol.personServerKey, protocol.upstreamToken)
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			protocol := newCallChainingProtocol(t)
			server := protocol.newServer(t, protocol.config())
			compact, current := protocol.chainedAuthToken(t, server)
			stepUp := protocol.stepUpResourceToken(t, compact, current, "payments.charge payments.refund")
			protocol.chainAuthorize = authorizeRequestedCallChainScopes

			// A substitute has an issuance record of its own, so its caller is
			// identified and only the presented token's tie refuses it.
			upstream := test.upstream(t, protocol)
			agentToken := protocol.resourceOneIDToken
			if upstream == "" {
				agentToken = protocol.samePersonServerAgentToken(t)
			} else {
				protocol.identifyUpstream(t, upstream)
			}
			beforeCommits := protocol.issuedCommits()
			response := protocol.tokenRequestWithCredential(
				t, server, stepUp, upstream, "", protocol.resourceOneProofKey, agentToken,
			)
			assertCallChainingProblem(t, response, http.StatusBadRequest, "invalid_upstream_token")
			if protocol.chainAuthorizeCalls != 1 || protocol.ordinaryAuthorizeCalls != 0 ||
				protocol.issuedCommits() != beforeCommits {
				t.Fatalf(
					"refused step-up calls/state = chain authorize %d ordinary authorize %d issued commits %d (before %d)",
					protocol.chainAuthorizeCalls, protocol.ordinaryAuthorizeCalls,
					protocol.issuedCommits(), beforeCommits,
				)
			}
		})
	}
}

func TestCallChainingAuthTypedStepUpRejectsInjectedUpstream(t *testing.T) {
	protocol := newCallChainingProtocol(t)
	config := protocol.config()
	config.Authorize = func(_ context.Context, request AuthorizationRequest) (AuthorizationDecision, error) {
		protocol.ordinaryAuthorizeCalls++
		return AuthorizationDecision{Scopes: request.Scopes, Lifetime: time.Minute}, nil
	}
	server := protocol.newServer(t, config)
	agentToken := protocol.samePersonServerAgentToken(t)
	personClaims := decodeCallChainingPersonToken(
		t, protocol,
		protocol.personRequestWithCredential(t, server, "", "", protocol.resourceOneProofKey, agentToken),
	)
	resourceToken := protocol.resourceToken(t, personClaims, protocol.personServerID, "payments.charge", nil)
	compact, current := protocol.decodeAuthToken(t, protocol.tokenRequestWithCredential(
		t, server, resourceToken, "", "", protocol.resourceOneProofKey, agentToken,
	))
	direct := protocol.issuedRecord(t, aauth.TokenReference{Issuer: current.Issuer, JTI: current.JTI})
	if direct.UpstreamTokenReference != (aauth.TokenReference{}) || direct.UpstreamTokenSHA256 != ([32]byte{}) ||
		!direct.identifiesRecipient() {
		t.Fatalf("direct issuance record = %#v", direct)
	}

	stepUp := protocol.stepUpResourceToken(t, compact, current, "payments.charge payments.refund")
	beforeCommits := protocol.issuedCommits()
	response := protocol.tokenRequestWithCredential(
		t, server, stepUp, protocol.upstreamToken, "", protocol.resourceOneProofKey, agentToken,
	)
	assertCallChainingProblem(t, response, http.StatusBadRequest, "invalid_upstream_token")
	if protocol.ordinaryAuthorizeCalls != 1 || protocol.chainBindCalls != 0 || protocol.chainAuthorizeCalls != 0 ||
		protocol.issuedCommits() != beforeCommits {
		t.Fatalf(
			"injected upstream calls/state = ordinary authorize %d chain %d/%d issued commits %d (before %d)",
			protocol.ordinaryAuthorizeCalls, protocol.chainBindCalls, protocol.chainAuthorizeCalls,
			protocol.issuedCommits(), beforeCommits,
		)
	}
}

// The calling Agent of an upstream token is identified from the issuance
// record of that exact token. A verified signature is not a substitute.
func TestCallChainingIdentifiesUpstreamCallerFromIssuanceRecord(t *testing.T) {
	tests := []struct {
		name   string
		change func(*callChainingProtocol)
		status int
		code   string
	}{
		{
			name: "no issuance record",
			change: func(protocol *callChainingProtocol) {
				protocol.issued.records = make(map[aauth.TokenReference]IssuedAuthTokenRecord)
			},
		},
		{
			name: "record of other exact bytes",
			change: func(protocol *callChainingProtocol) {
				protocol.changeUpstreamRecord(func(record *IssuedAuthTokenRecord) { record.CompactSHA256[31] ^= 1 })
			},
		},
		{
			name: "record of another Resource",
			change: func(protocol *callChainingProtocol) {
				protocol.changeUpstreamRecord(func(record *IssuedAuthTokenRecord) {
					record.Resource = "https://other-resource.example"
				})
			},
		},
		{
			name: "record of another key",
			change: func(protocol *callChainingProtocol) {
				protocol.changeUpstreamRecord(func(record *IssuedAuthTokenRecord) {
					record.AgentJKT = "another-key-thumbprint"
				})
			},
		},
		{
			name: "record names no calling Agent",
			change: func(protocol *callChainingProtocol) {
				protocol.changeUpstreamRecord(func(record *IssuedAuthTokenRecord) {
					record.AgentProvider, record.Agent, record.AgentTokenJTI, record.AgentJKT = "", "", "", ""
				})
			},
		},
		{
			name: "store fault",
			change: func(protocol *callChainingProtocol) {
				protocol.issued.loadError = errors.New("issued auth-token store unavailable")
			},
			status: http.StatusInternalServerError, code: "server_error",
		},
	}
	for _, test := range tests {
		status, code := test.status, test.code
		if status == 0 {
			status, code = http.StatusBadRequest, "invalid_upstream_token"
		}
		t.Run(test.name+" at person endpoint", func(t *testing.T) {
			protocol := newCallChainingProtocol(t)
			server := protocol.newServer(t, protocol.config())
			protocol.issued.mu.Lock()
			test.change(protocol)
			protocol.issued.mu.Unlock()
			response := protocol.personRequest(t, server, protocol.upstreamToken, "")
			assertCallChainingProblem(t, response, status, code)
			_, commits, _ := protocol.store.observation()
			if protocol.chainBindCalls != 0 || protocol.ordinaryBindCalls != 0 || commits != 0 {
				t.Fatalf(
					"unidentified caller calls/state = bind %d ordinary bind %d commits %d",
					protocol.chainBindCalls, protocol.ordinaryBindCalls, commits,
				)
			}
		})
		t.Run(test.name+" at token endpoint", func(t *testing.T) {
			protocol := newCallChainingProtocol(t)
			server := protocol.newServer(t, protocol.config())
			personClaims := decodeCallChainingPersonToken(
				t, protocol, protocol.personRequest(t, server, protocol.upstreamToken, ""),
			)
			resourceToken := protocol.resourceToken(t, personClaims, protocol.personServerID, "payments.charge", nil)
			protocol.issued.mu.Lock()
			test.change(protocol)
			protocol.issued.mu.Unlock()
			beforeCommits := protocol.issuedCommits()
			response := protocol.tokenRequest(t, server, resourceToken, protocol.upstreamToken, "")
			assertCallChainingProblem(t, response, status, code)
			if protocol.chainAuthorizeCalls != 0 || protocol.ordinaryAuthorizeCalls != 0 ||
				protocol.issuedCommits() != beforeCommits {
				t.Fatalf(
					"unidentified caller calls/state = authorize %d ordinary authorize %d issued commits %d (before %d)",
					protocol.chainAuthorizeCalls, protocol.ordinaryAuthorizeCalls,
					protocol.issuedCommits(), beforeCommits,
				)
			}
		})
	}
}

// Revocation of the original calling Agent's Agent token refuses the chain
// even though the intermediary's own Agent token is not revoked. Neither the
// intermediary's Agent token nor the upstream auth token's jti stands in for
// the original caller's Agent token.
func TestCallChainingChecksRevocationOfOriginalCallerAgentToken(t *testing.T) {
	original := aauth.TokenReference{Issuer: callChainOriginalAgentProvider, JTI: callChainOriginalAgentTokenJTI}
	newProtocol := func(t *testing.T) (*callChainingProtocol, *referenceAgentTokenRevocationStore, *Server) {
		protocol := newCallChainingProtocol(t)
		revocations := newReferenceAgentTokenRevocationStore()
		config := protocol.config()
		config.AgentTokenRevocations = revocations
		return protocol, revocations, protocol.newServer(t, config)
	}

	t.Run("revoked original caller at person endpoint", func(t *testing.T) {
		protocol, revocations, server := newProtocol(t)
		revocations.revoked[original] = true
		response := protocol.personRequest(t, server, protocol.upstreamToken, "")
		assertCallChainingProblem(t, response, http.StatusBadRequest, "revoked_upstream_token")
		_, commits, _ := protocol.store.observation()
		if protocol.chainBindCalls != 0 || commits != 0 || !revocations.looked(original) {
			t.Fatalf("revoked caller calls/state = bind %d commits %d lookups %#v", protocol.chainBindCalls, commits, revocations.lookups)
		}
	})

	t.Run("revoked original caller at token endpoint", func(t *testing.T) {
		protocol, revocations, server := newProtocol(t)
		personClaims := decodeCallChainingPersonToken(
			t, protocol, protocol.personRequest(t, server, protocol.upstreamToken, ""),
		)
		resourceToken := protocol.resourceToken(t, personClaims, protocol.personServerID, "payments.charge", nil)
		revocations.revoked[original] = true
		response := protocol.tokenRequest(t, server, resourceToken, protocol.upstreamToken, "")
		assertCallChainingProblem(t, response, http.StatusBadRequest, "revoked_upstream_token")
		if protocol.chainAuthorizeCalls != 0 {
			t.Fatalf("revoked caller reached policy %d times", protocol.chainAuthorizeCalls)
		}
	})

	t.Run("other references are not substitutes", func(t *testing.T) {
		protocol, revocations, server := newProtocol(t)
		revocations.revoked[aauth.TokenReference{Issuer: protocol.personServerID, JTI: protocol.upstreamClaims.JTI}] = true
		revocations.revoked[aauth.TokenReference{Issuer: callChainOriginalAgentProvider, JTI: protocol.upstreamClaims.JTI}] = true
		revocations.revoked[aauth.TokenReference{Issuer: protocol.resourceOneID, JTI: callChainOriginalAgentTokenJTI}] = true
		protocol.chainedAuthToken(t, server)
		if !revocations.looked(original) {
			t.Fatalf("original caller was not looked up: %#v", revocations.lookups)
		}
	})

	t.Run("lookup fault", func(t *testing.T) {
		protocol, revocations, server := newProtocol(t)
		revocations.faults[original] = errors.New("revocation store unavailable")
		response := protocol.personRequest(t, server, protocol.upstreamToken, "")
		assertCallChainingProblem(t, response, http.StatusInternalServerError, "server_error")
		if protocol.chainBindCalls != 0 {
			t.Fatalf("lookup fault reached policy %d times", protocol.chainBindCalls)
		}
	})
}

// An issued auth-token store is required only when call chaining is
// configured. The revocation configuration's store is used when revocation is
// configured, and PSAuthorizationConfig.IssuedTokens otherwise.
func TestCallChainingIssuedTokenStoreConfiguration(t *testing.T) {
	revocation := func(store IssuedAuthTokenStore) *AuthTokenRevocationConfig {
		return &AuthTokenRevocationConfig{IssuedTokens: store, HTTPClient: &http.Client{}, Admit: allowRevocationEgress}
	}

	t.Run("call chaining without a store is refused", func(t *testing.T) {
		config := newCallChainingProtocol(t).config()
		config.IssuedTokens = nil
		if _, err := NewPSAuthorization(config); err == nil {
			t.Fatal("call chaining was configured without an issued auth-token store")
		}
	})

	t.Run("direct configuration needs no store", func(t *testing.T) {
		config := newCallChainingProtocol(t).config()
		config.IssuedTokens = nil
		config.CallChaining = nil
		if _, err := NewPSAuthorization(config); err != nil {
			t.Fatalf("direct configuration without an issued auth-token store: %v", err)
		}
	})

	t.Run("revocation store alone", func(t *testing.T) {
		protocol := newCallChainingProtocol(t)
		config := protocol.config()
		config.IssuedTokens = nil
		config.Revocation = revocation(protocol.issued)
		_, current := protocol.chainedAuthToken(t, protocol.newServer(t, config))
		protocol.assertChainedIssuance(t, current)
	})

	t.Run("revocation store takes precedence", func(t *testing.T) {
		protocol := newCallChainingProtocol(t)
		ignored := newTestIssuedAuthTokenStore()
		config := protocol.config()
		config.IssuedTokens = ignored
		config.Revocation = revocation(protocol.issued)
		_, current := protocol.chainedAuthToken(t, protocol.newServer(t, config))
		protocol.assertChainedIssuance(t, current)
		if ignored.commitCalls != 0 || len(ignored.records) != 0 {
			t.Fatalf("ignored store commits = %d records = %d", ignored.commitCalls, len(ignored.records))
		}
	})

	t.Run("ignored store does not identify the caller", func(t *testing.T) {
		protocol := newCallChainingProtocol(t)
		config := protocol.config()
		config.Revocation = revocation(newTestIssuedAuthTokenStore())
		response := protocol.personRequest(t, protocol.newServer(t, config), protocol.upstreamToken, "")
		assertCallChainingProblem(t, response, http.StatusBadRequest, "invalid_upstream_token")
		if protocol.chainBindCalls != 0 {
			t.Fatalf("unidentified caller reached policy %d times", protocol.chainBindCalls)
		}
	})
}

func TestIssuedAuthTokenRecordLineageMustBeComplete(t *testing.T) {
	protocol := newCallChainingProtocol(t)
	complete := protocol.issuedRecord(t, aauth.TokenReference{
		Issuer: protocol.upstreamClaims.Issuer, JTI: protocol.upstreamClaims.JTI,
	})
	complete.UpstreamTokenReference = aauth.TokenReference{Issuer: "https://person.example", JTI: "upstream-token"}
	complete.UpstreamTokenSHA256 = sha256.Sum256([]byte("upstream-token"))
	for _, test := range []struct {
		name   string
		change func(*IssuedAuthTokenRecord)
		valid  bool
	}{
		{name: "complete", change: func(*IssuedAuthTokenRecord) {}, valid: true},
		{name: "no recipient and no upstream", valid: true, change: func(record *IssuedAuthTokenRecord) {
			record.AgentProvider, record.Agent, record.AgentTokenJTI, record.AgentJKT = "", "", "", ""
			record.UpstreamTokenReference, record.UpstreamTokenSHA256 = aauth.TokenReference{}, [32]byte{}
		}},
		{name: "no agent provider", change: func(record *IssuedAuthTokenRecord) { record.AgentProvider = "" }},
		{name: "invalid agent provider", change: func(record *IssuedAuthTokenRecord) { record.AgentProvider = "not-a-server" }},
		{name: "no agent", change: func(record *IssuedAuthTokenRecord) { record.Agent = "" }},
		{name: "no agent token jti", change: func(record *IssuedAuthTokenRecord) { record.AgentTokenJTI = "" }},
		{name: "no agent key thumbprint", change: func(record *IssuedAuthTokenRecord) { record.AgentJKT = "" }},
		{name: "upstream reference only", change: func(record *IssuedAuthTokenRecord) { record.UpstreamTokenSHA256 = [32]byte{} }},
		{name: "upstream digest only", change: func(record *IssuedAuthTokenRecord) {
			record.UpstreamTokenReference = aauth.TokenReference{}
		}},
		{name: "invalid upstream reference", change: func(record *IssuedAuthTokenRecord) {
			record.UpstreamTokenReference.Issuer = "not-a-server"
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			record := complete
			test.change(&record)
			if err := validateIssuedAuthTokenRecord(record); (err == nil) != test.valid {
				t.Fatalf("validateIssuedAuthTokenRecord() error = %v, valid=%t", err, test.valid)
			}
		})
	}
}

func authorizeRequestedCallChainScopes(request AuthorizationRequest) (AuthorizationDecision, error) {
	return AuthorizationDecision{Scopes: request.Scopes, Lifetime: 20 * time.Minute}, nil
}

// chainedAuthToken runs the chained person and token requests and returns the
// downstream auth token.
func (protocol *callChainingProtocol) chainedAuthToken(t *testing.T, server *Server) (string, aauth.AuthTokenClaims) {
	t.Helper()
	personClaims := decodeCallChainingPersonToken(
		t, protocol, protocol.personRequest(t, server, protocol.upstreamToken, ""),
	)
	resourceToken := protocol.resourceToken(t, personClaims, protocol.personServerID, "payments.charge", nil)
	return protocol.decodeAuthToken(t, protocol.tokenRequest(t, server, resourceToken, protocol.upstreamToken, ""))
}

func (protocol *callChainingProtocol) decodeAuthToken(t *testing.T, response *httptest.ResponseRecorder) (string, aauth.AuthTokenClaims) {
	t.Helper()
	if response.Code != http.StatusOK {
		t.Fatalf("token response = %d %s", response.Code, response.Body.String())
	}
	var output struct {
		AuthToken string `json:"auth_token"`
	}
	if err := json.NewDecoder(response.Body).Decode(&output); err != nil {
		t.Fatal(err)
	}
	claims, err := aauth.VerifyAuthToken(context.Background(), output.AuthToken, protocol.resolver, protocol.clock)
	if err != nil {
		t.Fatal(err)
	}
	return output.AuthToken, claims
}

// stepUpResourceToken mints the resource token Resource 2 returns when it asks
// for more and names the auth token the Agent currently holds.
func (protocol *callChainingProtocol) stepUpResourceToken(
	t *testing.T, compact string, current aauth.AuthTokenClaims, scope string,
) string {
	t.Helper()
	agentJKT, err := protocol.resourceOneProofKey.PublicJWK().Thumbprint()
	if err != nil {
		t.Fatal(err)
	}
	stepUp, err := aauth.MintResourceToken(protocol.resourceTwoKey, aauth.ResourceTokenClaims{
		Issuer: protocol.resourceTwoID, DWK: aauth.ResourceDiscoveryDocument,
		Audience: protocol.personServerID, JTI: "resource-two-step-up-token", PersonServer: protocol.personServerID,
		Subject: current.Subject, PresentedJTI: current.JTI, AgentJKT: agentJKT,
		IssuedAt: protocol.now.Unix(), ExpiresAt: protocol.now.Add(4 * time.Minute).Unix(),
		Scope: scope,
	})
	if err != nil {
		t.Fatal(err)
	}
	protocol.present(stepUp, compact)
	return stepUp
}

// assertChainedIssuance checks that the issuance record of a chained auth token
// names the exact upstream token and the intermediary Agent it was issued to.
func (protocol *callChainingProtocol) assertChainedIssuance(t *testing.T, claims aauth.AuthTokenClaims) {
	t.Helper()
	intermediaryJKT, err := protocol.resourceOneProofKey.PublicJWK().Thumbprint()
	if err != nil {
		t.Fatal(err)
	}
	record := protocol.issuedRecord(t, aauth.TokenReference{Issuer: claims.Issuer, JTI: claims.JTI})
	wantReference := aauth.TokenReference{Issuer: protocol.upstreamClaims.Issuer, JTI: protocol.upstreamClaims.JTI}
	if record.UpstreamTokenReference != wantReference ||
		record.UpstreamTokenSHA256 != sha256.Sum256([]byte(protocol.upstreamToken)) ||
		record.AgentProvider != protocol.resourceOneID ||
		record.Agent != "aauth:resource-one@resource-one.example" ||
		record.AgentTokenJTI != "resource-one-agent-token" ||
		record.AgentJKT != intermediaryJKT {
		t.Fatalf("chained issuance record = %#v", record)
	}
}

func (protocol *callChainingProtocol) issuedCommits() int {
	protocol.issued.mu.Lock()
	defer protocol.issued.mu.Unlock()
	return protocol.issued.commitCalls
}

// changeUpstreamRecord edits the retained issuance record of the upstream
// token. The caller holds the store lock.
func (protocol *callChainingProtocol) changeUpstreamRecord(change func(*IssuedAuthTokenRecord)) {
	reference := aauth.TokenReference{Issuer: protocol.upstreamClaims.Issuer, JTI: protocol.upstreamClaims.JTI}
	record := protocol.issued.records[reference]
	change(&record)
	protocol.issued.records[reference] = record
}

// referenceAgentTokenRevocationStore answers each Agent-token reference on its
// own, so a test can revoke one Agent token of a chain and not another.
type referenceAgentTokenRevocationStore struct {
	revoked map[aauth.TokenReference]bool
	faults  map[aauth.TokenReference]error
	lookups []aauth.TokenReference
}

func newReferenceAgentTokenRevocationStore() *referenceAgentTokenRevocationStore {
	return &referenceAgentTokenRevocationStore{
		revoked: make(map[aauth.TokenReference]bool),
		faults:  make(map[aauth.TokenReference]error),
	}
}

func (store *referenceAgentTokenRevocationStore) Revoke(context.Context, aauth.RevocationRequest) error {
	return errors.New("unexpected Agent-token revocation request")
}

func (store *referenceAgentTokenRevocationStore) IsRevoked(_ context.Context, reference aauth.TokenReference) (bool, error) {
	store.lookups = append(store.lookups, reference)
	return store.revoked[reference], store.faults[reference]
}

func (store *referenceAgentTokenRevocationStore) looked(reference aauth.TokenReference) bool {
	for _, lookup := range store.lookups {
		if lookup == reference {
			return true
		}
	}
	return false
}

var _ AgentTokenRevocationStore = (*referenceAgentTokenRevocationStore)(nil)
