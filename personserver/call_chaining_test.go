package personserver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

func TestCallChainingPSAuthorizationSurvivesServerRecomposition(t *testing.T) {
	protocol := newCallChainingProtocol(t)

	first := protocol.newServer(t, protocol.config())
	personResponse := protocol.personRequest(t, first, protocol.upstreamToken, "")
	if personResponse.Code != http.StatusOK {
		t.Fatalf("person response = %d %s", personResponse.Code, personResponse.Body.String())
	}
	var personOutput struct {
		PersonToken string `json:"person_token"`
		ExpiresIn   int64  `json:"expires_in"`
	}
	if err := json.NewDecoder(personResponse.Body).Decode(&personOutput); err != nil {
		t.Fatal(err)
	}
	personClaims, err := aauth.VerifyPersonToken(
		context.Background(), personOutput.PersonToken, protocol.resolver, protocol.clock,
	)
	if err != nil {
		t.Fatal(err)
	}
	protocol.personTokens = map[string]string{personClaims.JTI: personOutput.PersonToken}
	if personClaims.Issuer != protocol.personServerID ||
		personClaims.Audience != protocol.resourceTwoID ||
		personClaims.Subject != protocol.downstreamSubject ||
		personClaims.Subject == protocol.upstreamClaims.Subject ||
		!personClaims.Confirmation.JWK.Equal(protocol.resourceOneProofKey.PublicJWK()) {
		t.Fatalf("downstream person token = %#v", personClaims)
	}
	// Policy allows 30 minutes, but downstream access does not outlive the
	// 10-minute upstream authorization.
	if personOutput.ExpiresIn != int64((10*time.Minute)/time.Second) ||
		personClaims.ExpiresAt != protocol.upstreamClaims.ExpiresAt {
		t.Fatalf("person expires_in = %d exp = %d, want upstream expiry %d", personOutput.ExpiresIn, personClaims.ExpiresAt, protocol.upstreamClaims.ExpiresAt)
	}

	record, commits, _ := protocol.store.observation()
	wantReference := aauth.TokenReference{Issuer: protocol.upstreamClaims.Issuer, JTI: protocol.upstreamClaims.JTI}
	wantDigest := sha256.Sum256([]byte(protocol.upstreamToken))
	if commits != 1 || record.UpstreamTokenReference != wantReference || record.UpstreamTokenSHA256 != wantDigest {
		t.Fatalf("retained call-chain record = %#v; commits = %d", record, commits)
	}

	resourceToken := protocol.resourceToken(t, personClaims, protocol.personServerID, "payments.charge", nil)
	second := protocol.newServer(t, protocol.config())
	tokenResponse := protocol.tokenRequest(t, second, resourceToken, protocol.upstreamToken, "")
	if tokenResponse.Code != http.StatusOK {
		t.Fatalf("token response = %d %s", tokenResponse.Code, tokenResponse.Body.String())
	}
	var tokenOutput struct {
		AuthToken string `json:"auth_token"`
		ExpiresIn int64  `json:"expires_in"`
	}
	if err := json.NewDecoder(tokenResponse.Body).Decode(&tokenOutput); err != nil {
		t.Fatal(err)
	}
	authClaims, err := aauth.VerifyAuthToken(
		context.Background(), tokenOutput.AuthToken, protocol.resolver, protocol.clock,
	)
	if err != nil {
		t.Fatal(err)
	}
	if authClaims.Issuer != protocol.personServerID ||
		authClaims.DWK != aauth.PersonDiscoveryDocument ||
		authClaims.Audience != protocol.resourceTwoID ||
		authClaims.PersonServer != protocol.personServerID ||
		authClaims.Subject != protocol.downstreamSubject ||
		authClaims.Subject == protocol.upstreamClaims.Subject ||
		authClaims.Scope != "payments.charge" ||
		authClaims.Scope == protocol.upstreamClaims.Scope ||
		!authClaims.Confirmation.JWK.Equal(protocol.resourceOneProofKey.PublicJWK()) {
		t.Fatalf("downstream auth token = %#v", authClaims)
	}
	// Policy allows 20 minutes; an Auth token issued on a request carrying
	// an upstream token still expires no later than that token.
	if authClaims.ExpiresAt != protocol.upstreamClaims.ExpiresAt {
		t.Fatalf("downstream expiry = %d, want upstream expiry %d", authClaims.ExpiresAt, protocol.upstreamClaims.ExpiresAt)
	}
	if tokenOutput.ExpiresIn != int64((10*time.Minute)/time.Second) {
		t.Fatalf("auth expires_in = %d", tokenOutput.ExpiresIn)
	}
	if protocol.chainBindCalls != 1 || protocol.chainAuthorizeCalls != 1 ||
		protocol.ordinaryBindCalls != 0 || protocol.ordinaryAuthorizeCalls != 0 {
		t.Fatalf(
			"policy calls: chain bind=%d authorize=%d; ordinary bind=%d authorize=%d",
			protocol.chainBindCalls, protocol.chainAuthorizeCalls,
			protocol.ordinaryBindCalls, protocol.ordinaryAuthorizeCalls,
		)
	}
}

func TestCallChainingRetainedBindingMustBeComplete(t *testing.T) {
	reference := aauth.TokenReference{Issuer: "https://person.example", JTI: "upstream-token"}
	digest := sha256.Sum256([]byte("upstream-token"))
	for _, test := range []struct {
		name   string
		record PersonTokenRecord
		valid  bool
	}{
		{name: "absent", record: PersonTokenRecord{}, valid: true},
		{name: "complete", record: PersonTokenRecord{UpstreamTokenReference: reference, UpstreamTokenSHA256: digest}, valid: true},
		{name: "reference only", record: PersonTokenRecord{UpstreamTokenReference: reference}},
		{name: "digest only", record: PersonTokenRecord{UpstreamTokenSHA256: digest}},
		{name: "invalid reference", record: PersonTokenRecord{
			UpstreamTokenReference: aauth.TokenReference{Issuer: "not-a-server", JTI: "upstream-token"},
			UpstreamTokenSHA256:    digest,
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := validateCallChainRecord(test.record)
			if (err == nil) != test.valid {
				t.Fatalf("validateCallChainRecord() error = %v, valid=%t", err, test.valid)
			}
		})
	}
}

func TestCallChainingRejectsUnacceptableUpstreamBeforePolicyOrRetention(t *testing.T) {
	tests := []struct {
		name  string
		code  string
		token func(*testing.T, *callChainingProtocol) string
	}{
		{
			name: "wrong person server",
			token: func(t *testing.T, protocol *callChainingProtocol) string {
				claims := protocol.upstreamClaims
				claims.PersonServer = "https://other-person.example"
				return signCallChainingAuthClaims(t, protocol.personServerKey, claims)
			},
		},
		{
			name: "wrong intermediary audience",
			token: func(t *testing.T, protocol *callChainingProtocol) string {
				claims := protocol.upstreamClaims
				claims.Audience = "https://other-resource.example"
				return mintCallChainingAuthToken(t, protocol.personServerKey, claims)
			},
		},
		{
			name: "different issuer",
			token: func(t *testing.T, protocol *callChainingProtocol) string {
				claims := protocol.upstreamClaims
				claims.Issuer = protocol.accessServerID
				claims.DWK = aauth.AccessDiscoveryDocument
				return mintCallChainingAuthToken(t, protocol.accessServerKey, claims)
			},
		},
		{
			// An upstream token is a person token or an auth token; an agent
			// token is neither.
			name: "wrong token type",
			token: func(t *testing.T, protocol *callChainingProtocol) string {
				return protocol.resourceOneIDToken
			},
		},
		{
			name: "expired",
			code: "expired_upstream_token",
			token: func(t *testing.T, protocol *callChainingProtocol) string {
				claims := protocol.upstreamClaims
				claims.IssuedAt = protocol.now.Add(-20 * time.Minute).Unix()
				claims.ExpiresAt = protocol.now.Add(-10 * time.Minute).Unix()
				return mintCallChainingAuthToken(t, protocol.personServerKey, claims)
			},
		},
		{
			// Beyond the default 60-second request window: a parameter-token skew.
			name: "future issued at",
			code: "clock_skew",
			token: func(t *testing.T, protocol *callChainingProtocol) string {
				claims := protocol.upstreamClaims
				claims.IssuedAt = protocol.now.Add(90 * time.Second).Unix()
				claims.ExpiresAt = protocol.now.Add(10 * time.Minute).Unix()
				return mintCallChainingAuthToken(t, protocol.personServerKey, claims)
			},
		},
		{
			name: "future not before",
			token: func(t *testing.T, protocol *callChainingProtocol) string {
				claims := protocol.upstreamClaims
				claims.NotBefore = protocol.now.Add(time.Minute).Unix()
				return mintCallChainingAuthToken(t, protocol.personServerKey, claims)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			protocol := newCallChainingProtocol(t)
			server := protocol.newServer(t, protocol.config())
			response := protocol.personRequest(t, server, test.token(t, protocol), "")
			code := test.code
			if code == "" {
				code = "invalid_upstream_token"
			}
			if got := response.Header().Get("Signature-Error"); got != "" {
				t.Fatalf("upstream token Signature-Error = %q", got)
			}
			assertCallChainingProblem(t, response, http.StatusBadRequest, code)
			_, commits, loads := protocol.store.observation()
			if protocol.chainBindCalls != 0 || protocol.chainAuthorizeCalls != 0 ||
				protocol.ordinaryBindCalls != 0 || protocol.ordinaryAuthorizeCalls != 0 ||
				commits != 0 || loads != 0 {
				t.Fatalf(
					"rejected upstream mutated state: chain=%d/%d ordinary=%d/%d commits=%d loads=%d",
					protocol.chainBindCalls, protocol.chainAuthorizeCalls,
					protocol.ordinaryBindCalls, protocol.ordinaryAuthorizeCalls, commits, loads,
				)
			}
		})
	}
}

func TestCallChainingKeepsOriginalAndIntermediaryProofKeysDistinct(t *testing.T) {
	t.Run("original Agent cannot sign intermediary person request", func(t *testing.T) {
		protocol := newCallChainingProtocol(t)
		response := protocol.personRequestWithCredential(
			t, protocol.newServer(t, protocol.config()), protocol.upstreamToken, "",
			protocol.originalAgentKey, protocol.resourceOneIDToken,
		)
		assertCallChainingProblem(t, response, http.StatusUnauthorized, "invalid_agent_token")
		_, commits, loads := protocol.store.observation()
		if protocol.chainBindCalls != 0 || protocol.chainAuthorizeCalls != 0 || commits != 0 || loads != 0 {
			t.Fatalf(
				"wrong intermediary proof mutated state: chain %d/%d commits %d loads %d",
				protocol.chainBindCalls, protocol.chainAuthorizeCalls, commits, loads,
			)
		}
	})

	t.Run("resource token must name intermediary key", func(t *testing.T) {
		protocol := newCallChainingProtocol(t)
		server := protocol.newServer(t, protocol.config())
		personClaims := decodeCallChainingPersonToken(
			t, protocol, protocol.personRequest(t, server, protocol.upstreamToken, ""),
		)
		originalAgentJKT, err := protocol.originalAgentKey.PublicJWK().Thumbprint()
		if err != nil {
			t.Fatal(err)
		}
		resourceToken, err := aauth.MintResourceToken(protocol.resourceTwoKey, aauth.ResourceTokenClaims{
			Issuer: protocol.resourceTwoID, DWK: aauth.ResourceDiscoveryDocument,
			Audience: protocol.personServerID, JTI: "wrong-agent-jkt-resource-token",
			PersonServer: protocol.personServerID, Subject: personClaims.Subject,
			PresentedJTI: personClaims.JTI, AgentJKT: originalAgentJKT,
			IssuedAt: protocol.now.Unix(), ExpiresAt: protocol.now.Add(4 * time.Minute).Unix(),
			Scope: "payments.charge",
		})
		if err != nil {
			t.Fatal(err)
		}
		protocol.present(resourceToken, protocol.personTokens[personClaims.JTI])
		response := protocol.tokenRequest(t, server, resourceToken, protocol.upstreamToken, "")
		assertCallChainingProblem(t, response, http.StatusBadRequest, "invalid_resource_token")
		_, commits, loads := protocol.store.observation()
		if protocol.chainBindCalls != 1 || protocol.chainAuthorizeCalls != 0 || commits != 1 || loads != 0 {
			t.Fatalf(
				"wrong resource-token key changed state: chain %d/%d commits %d loads %d",
				protocol.chainBindCalls, protocol.chainAuthorizeCalls, commits, loads,
			)
		}
	})
}

func TestCallChainingRetainedUpstreamRejectsSubstitutionAndByteRewrite(t *testing.T) {
	tests := []struct {
		name  string
		token func(*testing.T, *callChainingProtocol) string
	}{
		{
			name: "different token reference",
			token: func(t *testing.T, protocol *callChainingProtocol) string {
				claims := protocol.upstreamClaims
				claims.JTI = "substituted-upstream"
				return mintCallChainingAuthToken(t, protocol.personServerKey, claims)
			},
		},
		{
			name: "same reference with different exact bytes",
			token: func(t *testing.T, protocol *callChainingProtocol) string {
				return reserializeCallChainingToken(t, protocol.personServerKey, protocol.upstreamToken)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			protocol := newCallChainingProtocol(t)
			server := protocol.newServer(t, protocol.config())
			personResponse := protocol.personRequest(t, server, protocol.upstreamToken, "")
			personClaims := decodeCallChainingPersonToken(t, protocol, personResponse)
			resourceToken := protocol.resourceToken(t, personClaims, protocol.personServerID, "payments.charge", nil)
			// The substitute has an issuance record of its own, so its caller
			// is identified and only the retained tie refuses it.
			substitute := test.token(t, protocol)
			protocol.identifyUpstream(t, substitute)

			beforeRecord, beforeCommits, beforeLoads := protocol.store.observation()
			response := protocol.tokenRequest(t, server, resourceToken, substitute, "")
			assertCallChainingProblem(t, response, http.StatusBadRequest, "invalid_upstream_token")
			afterRecord, afterCommits, afterLoads := protocol.store.observation()
			if protocol.chainBindCalls != 1 || protocol.chainAuthorizeCalls != 0 ||
				protocol.ordinaryBindCalls != 0 || protocol.ordinaryAuthorizeCalls != 0 ||
				afterCommits != beforeCommits || afterRecord != beforeRecord || afterLoads < beforeLoads {
				t.Fatalf(
					"substitution changed state: chain=%d/%d ordinary=%d/%d before=%#v/%d/%d after=%#v/%d/%d",
					protocol.chainBindCalls, protocol.chainAuthorizeCalls,
					protocol.ordinaryBindCalls, protocol.ordinaryAuthorizeCalls,
					beforeRecord, beforeCommits, beforeLoads, afterRecord, afterCommits, afterLoads,
				)
			}
		})
	}
}

func TestCallChainingRetainedBindingRejectsOmissionAndInjection(t *testing.T) {
	t.Run("chained record requires upstream again", func(t *testing.T) {
		protocol := newCallChainingProtocol(t)
		server := protocol.newServer(t, protocol.config())
		personClaims := decodeCallChainingPersonToken(
			t, protocol, protocol.personRequest(t, server, protocol.upstreamToken, ""),
		)
		resourceToken := protocol.resourceToken(t, personClaims, protocol.personServerID, "payments.charge", nil)
		samePersonServerAgentToken := protocol.samePersonServerAgentToken(t)
		response := protocol.tokenRequestWithCredential(
			t, server, resourceToken, "", "",
			protocol.resourceOneProofKey, samePersonServerAgentToken,
		)
		assertCallChainingProblem(t, response, http.StatusBadRequest, "invalid_upstream_token")
		_, commits, _ := protocol.store.observation()
		if protocol.chainBindCalls != 1 || protocol.chainAuthorizeCalls != 0 ||
			protocol.ordinaryAuthorizeCalls != 0 || commits != 1 {
			t.Fatalf(
				"omitted upstream calls/commits = chain %d/%d ordinary authorize %d commits %d",
				protocol.chainBindCalls, protocol.chainAuthorizeCalls,
				protocol.ordinaryAuthorizeCalls, commits,
			)
		}
	})

	t.Run("direct record rejects injected upstream", func(t *testing.T) {
		protocol := newCallChainingProtocol(t)
		server := protocol.newServer(t, protocol.config())
		samePersonServerAgentToken := protocol.samePersonServerAgentToken(t)
		personClaims := decodeCallChainingPersonToken(
			t, protocol,
			protocol.personRequestWithCredential(
				t, server, "", "", protocol.resourceOneProofKey, samePersonServerAgentToken,
			),
		)
		resourceToken := protocol.resourceToken(t, personClaims, protocol.personServerID, "payments.charge", nil)
		response := protocol.tokenRequestWithCredential(
			t, server, resourceToken, protocol.upstreamToken, "",
			protocol.resourceOneProofKey, samePersonServerAgentToken,
		)
		assertCallChainingProblem(t, response, http.StatusBadRequest, "invalid_upstream_token")
		_, commits, _ := protocol.store.observation()
		if protocol.ordinaryBindCalls != 1 || protocol.ordinaryAuthorizeCalls != 0 ||
			protocol.chainBindCalls != 0 || protocol.chainAuthorizeCalls != 0 || commits != 1 {
			t.Fatalf(
				"injected upstream calls/commits = ordinary %d/%d chain %d/%d commits %d",
				protocol.ordinaryBindCalls, protocol.ordinaryAuthorizeCalls,
				protocol.chainBindCalls, protocol.chainAuthorizeCalls, commits,
			)
		}
	})
}

// The exact call-chain tie lives in the retained record of the presented
// token. A chained token request whose presented person token has no such
// record leaves the calling chain unidentified and is refused, never accepted
// on the upstream token alone.
func TestCallChainingRefusesUpstreamWithoutRetainedPersonToken(t *testing.T) {
	t.Run("person token record no longer retained", func(t *testing.T) {
		protocol := newCallChainingProtocol(t)
		server := protocol.newServer(t, protocol.config())
		personClaims := decodeCallChainingPersonToken(
			t, protocol, protocol.personRequest(t, server, protocol.upstreamToken, ""),
		)
		resourceToken := protocol.resourceToken(t, personClaims, protocol.personServerID, "payments.charge", nil)
		protocol.store.mu.Lock()
		protocol.store.records = make(map[string]PersonTokenRecord)
		protocol.store.mu.Unlock()
		response := protocol.tokenRequest(t, server, resourceToken, protocol.upstreamToken, "")
		assertCallChainingProblem(t, response, http.StatusBadRequest, "invalid_upstream_token")
		if protocol.chainAuthorizeCalls != 0 {
			t.Fatalf("unidentified chain reached policy %d times", protocol.chainAuthorizeCalls)
		}
	})
}

func TestCallChainingRequiresCurrentUpstreamAtBothPersonServerCalls(t *testing.T) {
	protocol := newCallChainingProtocol(t)
	server := protocol.newServer(t, protocol.config())
	personClaims := decodeCallChainingPersonToken(
		t, protocol, protocol.personRequest(t, server, protocol.upstreamToken, ""),
	)
	protocol.now = protocol.now.Add(11 * time.Minute)
	resourceToken := protocol.resourceToken(t, personClaims, protocol.personServerID, "payments.charge", nil)
	response := protocol.tokenRequest(t, server, resourceToken, protocol.upstreamToken, "")
	assertCallChainingProblem(t, response, http.StatusBadRequest, "expired_upstream_token")
	_, commits, loads := protocol.store.observation()
	if protocol.chainBindCalls != 1 || protocol.chainAuthorizeCalls != 0 || commits != 1 || loads != 0 {
		t.Fatalf(
			"expired second presentation calls/state = chain %d/%d commits %d loads %d",
			protocol.chainBindCalls, protocol.chainAuthorizeCalls, commits, loads,
		)
	}
}

func TestCallChainingKeepsShorterBoundsUnderUpstreamExpiry(t *testing.T) {
	for _, test := range []struct {
		name           string
		personLifetime time.Duration
		authLifetime   time.Duration
		agentLifetime  time.Duration
		wantPerson     time.Duration
		wantAuth       time.Duration
	}{
		{
			name:           "shorter policy",
			personLifetime: 5 * time.Minute,
			authLifetime:   3 * time.Minute,
			agentLifetime:  time.Hour,
			wantPerson:     5 * time.Minute,
			wantAuth:       3 * time.Minute,
		},
		{
			name:           "shorter intermediary Agent token",
			personLifetime: 30 * time.Minute,
			authLifetime:   20 * time.Minute,
			agentLifetime:  2 * time.Minute,
			wantPerson:     2 * time.Minute,
			wantAuth:       2 * time.Minute,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			protocol := newCallChainingProtocol(t)
			protocol.chainBind = func(PersonTokenRequest) (Person, error) {
				return Person{Subject: protocol.downstreamSubject, Lifetime: test.personLifetime}, nil
			}
			protocol.chainAuthorize = func(AuthorizationRequest) (AuthorizationDecision, error) {
				return AuthorizationDecision{Scopes: []string{"payments.charge"}, Lifetime: test.authLifetime}, nil
			}
			agentToken, err := aauth.MintAgentToken(protocol.resourceOneID, protocol.resourceOneIssuerKey, aauth.AgentTokenRequest{
				Agent:        "aauth:resource-one@resource-one.example",
				PersonServer: "https://intermediary-person.example",
				PublicKey:    protocol.resourceOneProofKey.PublicJWK(),
				Lifetime:     test.agentLifetime,
			}, protocol.now, "resource-one-bounded-agent-token")
			if err != nil {
				t.Fatal(err)
			}
			server := protocol.newServer(t, protocol.config())

			personResponse := protocol.personRequestWithCredential(
				t, server, protocol.upstreamToken, "", protocol.resourceOneProofKey, agentToken,
			)
			if personResponse.Code != http.StatusOK {
				t.Fatalf("person response = %d %s", personResponse.Code, personResponse.Body.String())
			}
			var personOutput struct {
				PersonToken string `json:"person_token"`
				ExpiresIn   int64  `json:"expires_in"`
			}
			if err := json.NewDecoder(personResponse.Body).Decode(&personOutput); err != nil {
				t.Fatal(err)
			}
			if personOutput.ExpiresIn != int64(test.wantPerson/time.Second) {
				t.Fatalf("person expires_in = %d, want %d", personOutput.ExpiresIn, int64(test.wantPerson/time.Second))
			}
			personClaims, err := aauth.VerifyPersonToken(
				context.Background(), personOutput.PersonToken, protocol.resolver, protocol.clock,
			)
			if err != nil {
				t.Fatal(err)
			}

			protocol.personTokens = map[string]string{personClaims.JTI: personOutput.PersonToken}
			resourceToken := protocol.resourceToken(t, personClaims, protocol.personServerID, "payments.charge", nil)
			tokenResponse := protocol.tokenRequestWithCredential(
				t, server, resourceToken, protocol.upstreamToken, "", protocol.resourceOneProofKey, agentToken,
			)
			if tokenResponse.Code != http.StatusOK {
				t.Fatalf("token response = %d %s", tokenResponse.Code, tokenResponse.Body.String())
			}
			var tokenOutput struct {
				AuthToken string `json:"auth_token"`
				ExpiresIn int64  `json:"expires_in"`
			}
			if err := json.NewDecoder(tokenResponse.Body).Decode(&tokenOutput); err != nil {
				t.Fatal(err)
			}
			if tokenOutput.ExpiresIn != int64(test.wantAuth/time.Second) {
				t.Fatalf("auth expires_in = %d, want %d", tokenOutput.ExpiresIn, int64(test.wantAuth/time.Second))
			}
			authClaims, err := aauth.VerifyAuthToken(
				context.Background(), tokenOutput.AuthToken, protocol.resolver, protocol.clock,
			)
			if err != nil {
				t.Fatal(err)
			}
			if authClaims.ExpiresAt != protocol.now.Add(test.wantAuth).Unix() {
				t.Fatalf("auth exp = %d, want %d", authClaims.ExpiresAt, protocol.now.Add(test.wantAuth).Unix())
			}
		})
	}
}

func TestCallChainingRefusesUnsupportedValidBranchesAndIsolatesOrdinaryInteractions(t *testing.T) {
	t.Run("upstream directed subject cannot become downstream subject", func(t *testing.T) {
		protocol := newCallChainingProtocol(t)
		protocol.chainBind = func(_ PersonTokenRequest) (Person, error) {
			return Person{Subject: protocol.upstreamClaims.Subject, Lifetime: 10 * time.Minute}, nil
		}
		response := protocol.personRequest(t, protocol.newServer(t, protocol.config()), protocol.upstreamToken, "")
		assertCallChainingProblem(t, response, http.StatusInternalServerError, "server_error")
		_, commits, _ := protocol.store.observation()
		if protocol.chainBindCalls != 1 || protocol.chainAuthorizeCalls != 0 || commits != 0 {
			t.Fatalf("copied subject calls/commits = %d/%d/%d", protocol.chainBindCalls, protocol.chainAuthorizeCalls, commits)
		}
	})

	for _, test := range []struct {
		name   string
		change func(*aauth.AuthTokenClaims)
	}{
		{
			name: "mission-bound upstream",
			change: func(claims *aauth.AuthTokenClaims) {
				claims.MissionS256 = "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU"
			},
		},
		{
			name: "account-bound upstream",
			change: func(claims *aauth.AuthTokenClaims) {
				claims.Account = testStringPointer("account-17")
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			protocol := newCallChainingProtocol(t)
			claims := protocol.upstreamClaims
			test.change(&claims)
			upstream := mintCallChainingAuthToken(t, protocol.personServerKey, claims)
			response := protocol.personRequest(t, protocol.newServer(t, protocol.config()), upstream, "")
			assertCallChainingProblem(t, response, http.StatusInternalServerError, "server_error")
			_, commits, loads := protocol.store.observation()
			if protocol.chainBindCalls != 0 || protocol.chainAuthorizeCalls != 0 || commits != 0 || loads != 0 {
				t.Fatalf("unsupported upstream mutated state: chain=%d/%d commits=%d loads=%d", protocol.chainBindCalls, protocol.chainAuthorizeCalls, commits, loads)
			}
		})
	}

	t.Run("subagent inside call chain", func(t *testing.T) {
		protocol := newCallChainingProtocol(t)
		childToken := protocol.childAgentToken(t)
		response := protocol.personRequest(t, protocol.newServer(t, protocol.config()), protocol.upstreamToken, childToken)
		assertCallChainingProblem(t, response, http.StatusInternalServerError, "server_error")
		_, commits, loads := protocol.store.observation()
		if protocol.chainBindCalls != 0 || protocol.chainAuthorizeCalls != 0 || commits != 0 || loads != 0 {
			t.Fatalf("subagent chain mutated state: chain=%d/%d commits=%d loads=%d", protocol.chainBindCalls, protocol.chainAuthorizeCalls, commits, loads)
		}
	})

	t.Run("ordinary person interaction selector", func(t *testing.T) {
		protocol := newCallChainingProtocol(t)
		store := newMemoryDeferredTokenStore()
		config := protocol.config()
		config.Tokens = store
		interactionPolicyCalls := 0
		config.RequirePersonTokenInteraction = func(_ context.Context, _ PersonTokenRequest) (PersonTokenInteractionPolicy, bool, error) {
			interactionPolicyCalls++
			return PersonTokenInteractionPolicy{
				URL: "https://person.example/interaction", Lifetime: 5 * time.Minute, RetryAfter: time.Second,
			}, true, nil
		}
		decodeCallChainingPersonToken(
			t, protocol,
			protocol.personRequest(t, protocol.newServer(t, config), protocol.upstreamToken, ""),
		)
		store.mu.Lock()
		pending := len(store.pending)
		retained := len(store.records)
		store.mu.Unlock()
		if interactionPolicyCalls != 0 || protocol.chainBindCalls != 1 || protocol.chainAuthorizeCalls != 0 || pending != 0 || retained != 1 {
			t.Fatalf("interaction calls/state = policy:%d chain:%d/%d pending:%d retained:%d", interactionPolicyCalls, protocol.chainBindCalls, protocol.chainAuthorizeCalls, pending, retained)
		}
	})

	t.Run("ordinary authorization interaction selector", func(t *testing.T) {
		protocol := newCallChainingProtocol(t)
		personServer := protocol.newServer(t, protocol.config())
		personClaims := decodeCallChainingPersonToken(
			t, protocol, protocol.personRequest(t, personServer, protocol.upstreamToken, ""),
		)
		resourceToken := protocol.resourceToken(t, personClaims, protocol.personServerID, "payments.charge", nil)
		store := newMemoryDeferredAuthorizationStore()
		config := protocol.config()
		config.AuthorizationInteractions = store
		interactionPolicyCalls := 0
		config.RequireAuthorizationInteraction = func(_ context.Context, _ AuthorizationRequest) (AuthorizationInteractionPolicy, bool, error) {
			interactionPolicyCalls++
			return AuthorizationInteractionPolicy{
				URL: "https://person.example/authorize", Lifetime: 5 * time.Minute, RetryAfter: time.Second,
			}, true, nil
		}
		response := protocol.tokenRequestWithCapabilities(
			t, protocol.newServer(t, config), resourceToken, protocol.upstreamToken, []string{"interaction"},
		)
		if response.Code != http.StatusOK {
			t.Fatalf("token response = %d %s", response.Code, response.Body.String())
		}
		store.mu.Lock()
		pending := len(store.pending)
		store.mu.Unlock()
		if interactionPolicyCalls != 0 || protocol.chainBindCalls != 1 || protocol.chainAuthorizeCalls != 1 || pending != 0 {
			t.Fatalf("authorization interaction calls/state = policy:%d authorize:%d pending:%d", interactionPolicyCalls, protocol.chainAuthorizeCalls, pending)
		}
	})

	t.Run("access-server federation", func(t *testing.T) {
		protocol := newCallChainingProtocol(t)
		server := protocol.newServer(t, protocol.config())
		personClaims := decodeCallChainingPersonToken(
			t, protocol, protocol.personRequest(t, server, protocol.upstreamToken, ""),
		)
		resourceToken := protocol.resourceToken(t, personClaims, protocol.accessServerID, "payments.charge", nil)
		response := protocol.tokenRequest(t, server, resourceToken, protocol.upstreamToken, "")
		assertCallChainingProblem(t, response, http.StatusInternalServerError, "server_error")
		_, commits, _ := protocol.store.observation()
		if protocol.chainBindCalls != 1 || protocol.chainAuthorizeCalls != 0 || commits != 1 {
			t.Fatalf("federation calls/commits = %d/%d/%d", protocol.chainBindCalls, protocol.chainAuthorizeCalls, commits)
		}
	})
}

type callChainingProtocol struct {
	t *testing.T

	now   time.Time
	clock aauth.Clock

	personServerID string
	resourceOneID  string
	resourceTwoID  string
	accessServerID string

	personServerKey      jose.SigningKey
	resourceOneIssuerKey jose.SigningKey
	resourceOneProofKey  jose.SigningKey
	originalAgentKey     jose.SigningKey
	resourceTwoKey       jose.SigningKey
	accessServerKey      jose.SigningKey
	childKey             jose.SigningKey

	resolver           signaturekey.KeyResolver
	store              *memoryTokenStore
	issued             *testIssuedAuthTokenStore
	resourceOneIDToken string
	upstreamToken      string
	upstreamClaims     aauth.AuthTokenClaims

	downstreamSubject string
	nextID            int

	// personTokens holds each issued person token by identifier, and
	// presentedTokens the token an agent presents with each resource token.
	personTokens    map[string]string
	presentedTokens map[string]string

	ordinaryBindCalls      int
	ordinaryAuthorizeCalls int
	chainBindCalls         int
	chainAuthorizeCalls    int

	chainBind      func(PersonTokenRequest) (Person, error)
	chainAuthorize func(AuthorizationRequest) (AuthorizationDecision, error)
}

func newCallChainingProtocol(t *testing.T) *callChainingProtocol {
	t.Helper()
	protocol := &callChainingProtocol{
		t:                 t,
		now:               time.Date(2026, 8, 30, 18, 0, 0, 0, time.UTC),
		personServerID:    "https://person.example",
		resourceOneID:     "https://resource-one.example",
		resourceTwoID:     "https://resource-two.example",
		accessServerID:    "https://access.example",
		downstreamSubject: "person-for-resource-two",
		store:             newMemoryTokenStore(),
		issued:            newTestIssuedAuthTokenStore(),
	}
	protocol.clock = aauth.ClockFunc(func() time.Time { return protocol.now })
	protocol.personServerKey = personServerTestKey(t, "call-chain-person")
	protocol.resourceOneIssuerKey = personServerTestKey(t, "call-chain-resource-one-issuer")
	protocol.resourceOneProofKey = personServerTestKey(t, "call-chain-resource-one-proof")
	protocol.originalAgentKey = personServerTestKey(t, "call-chain-original-agent")
	protocol.resourceTwoKey = personServerTestKey(t, "call-chain-resource-two")
	protocol.accessServerKey = personServerTestKey(t, "call-chain-access")
	protocol.childKey = personServerTestKey(t, "call-chain-child")
	protocol.resolver = signaturekey.StaticKeyResolver{
		{Issuer: protocol.personServerID, DiscoveryDocument: aauth.PersonDiscoveryDocument, KeyID: protocol.personServerKey.ID()}:    protocol.personServerKey.PublicJWK(),
		{Issuer: protocol.resourceOneID, DiscoveryDocument: aauth.AgentDiscoveryDocument, KeyID: protocol.resourceOneIssuerKey.ID()}: protocol.resourceOneIssuerKey.PublicJWK(),
		{Issuer: protocol.resourceTwoID, DiscoveryDocument: aauth.ResourceDiscoveryDocument, KeyID: protocol.resourceTwoKey.ID()}:    protocol.resourceTwoKey.PublicJWK(),
		{Issuer: protocol.accessServerID, DiscoveryDocument: aauth.AccessDiscoveryDocument, KeyID: protocol.accessServerKey.ID()}:    protocol.accessServerKey.PublicJWK(),
	}
	var err error
	protocol.resourceOneIDToken, err = aauth.MintAgentToken(
		protocol.resourceOneID, protocol.resourceOneIssuerKey,
		aauth.AgentTokenRequest{
			Agent: "aauth:resource-one@resource-one.example",
			// This is the intermediary's own PS and is deliberately not the
			// person server named by the upstream authorization.
			PersonServer: "https://intermediary-person.example",
			PublicKey:    protocol.resourceOneProofKey.PublicJWK(),
			Lifetime:     time.Hour,
		},
		protocol.now, "resource-one-agent-token",
	)
	if err != nil {
		t.Fatal(err)
	}
	protocol.upstreamClaims = aauth.AuthTokenClaims{
		Issuer: protocol.personServerID, DWK: aauth.PersonDiscoveryDocument,
		Audience: protocol.resourceOneID, JTI: "upstream-auth-token",
		PersonServer: protocol.personServerID, Subject: "person-for-resource-one",
		Confirmation: aauth.Confirmation{JWK: protocol.originalAgentKey.PublicJWK()},
		IssuedAt:     protocol.now.Unix(), ExpiresAt: protocol.now.Add(10 * time.Minute).Unix(),
		Scope: "orders.read",
		AdditionalClaims: map[string]json.RawMessage{
			"upstream_context": json.RawMessage(`{"hop":1}`),
		},
	}
	protocol.upstreamToken = mintCallChainingAuthToken(t, protocol.personServerKey, protocol.upstreamClaims)
	if protocol.upstreamClaims.Audience != protocol.resourceOneID {
		t.Fatal("test setup does not bind upstream audience to intermediary Agent-token issuer")
	}
	if protocol.upstreamClaims.Confirmation.JWK.Equal(protocol.resourceOneProofKey.PublicJWK()) {
		t.Fatal("test setup accidentally reused the intermediary proof key as the upstream confirmation key")
	}
	protocol.identifyUpstream(t, protocol.upstreamToken)
	return protocol
}

const (
	callChainOriginalAgentProvider = "https://original-agent.example"
	callChainOriginalAgent         = "aauth:original@original-agent.example"
	callChainOriginalAgentTokenJTI = "original-agent-token"
)

// identifyUpstream retains the issuance record this Person Server would hold
// for an upstream auth token it issued to the original calling Agent. It
// replaces any record already held for the same reference.
func (protocol *callChainingProtocol) identifyUpstream(t *testing.T, compact string) IssuedAuthTokenRecord {
	t.Helper()
	claims, err := aauth.VerifyAuthToken(context.Background(), compact, protocol.resolver, protocol.clock)
	if err != nil {
		t.Fatal(err)
	}
	record, err := issuedAuthTokenRecord(compact, claims)
	if err != nil {
		t.Fatal(err)
	}
	record.AgentProvider = callChainOriginalAgentProvider
	record.Agent = callChainOriginalAgent
	record.AgentTokenJTI = callChainOriginalAgentTokenJTI
	record.AgentJKT, err = claims.Confirmation.JWK.Thumbprint()
	if err != nil {
		t.Fatal(err)
	}
	if err := validateIssuedAuthTokenRecord(record); err != nil {
		t.Fatal(err)
	}
	protocol.issued.mu.Lock()
	protocol.issued.records[record.Reference] = record
	protocol.issued.mu.Unlock()
	return record
}

func (protocol *callChainingProtocol) issuedRecord(t *testing.T, reference aauth.TokenReference) IssuedAuthTokenRecord {
	t.Helper()
	record, err := protocol.issued.LoadIssuedAuthToken(context.Background(), reference)
	if err != nil {
		t.Fatalf("issued record %#v: %v", reference, err)
	}
	return record
}

func (protocol *callChainingProtocol) config() PSAuthorizationConfig {
	return PSAuthorizationConfig{
		Issuer: protocol.personServerID, SigningKey: protocol.personServerKey,
		KeyResolver: protocol.resolver, Clock: protocol.clock,
		NewID: func() string {
			protocol.nextID++
			switch protocol.nextID {
			case 1:
				return "downstream-person-token"
			case 2:
				return "downstream-auth-token"
			}
			return fmt.Sprintf("downstream-auth-token-%d", protocol.nextID)
		},
		MaximumResourceTokenLifetime: 5 * time.Minute,
		Tokens:                       protocol.store,
		IssuedTokens:                 protocol.issued,
		BindPerson: func(context.Context, PersonTokenRequest) (Person, error) {
			protocol.ordinaryBindCalls++
			return Person{Subject: "ordinary-person", Lifetime: time.Minute}, nil
		},
		Authorize: func(context.Context, AuthorizationRequest) (AuthorizationDecision, error) {
			protocol.ordinaryAuthorizeCalls++
			return AuthorizationDecision{Scopes: []string{"ordinary"}, Lifetime: time.Minute}, nil
		},
		CallChaining: &CallChainingConfig{
			BindPerson: func(_ context.Context, request PersonTokenRequest) (Person, error) {
				protocol.chainBindCalls++
				if protocol.chainBind != nil {
					return protocol.chainBind(request)
				}
				protocol.assertUpstreamPolicyClaims(request.Upstream)
				request.Upstream.Subject = "policy-local-subject-mutation"
				request.Upstream.AdditionalClaims["policy_local"] = json.RawMessage(`true`)
				request.Upstream.AdditionalClaims["upstream_context"][0] = '['
				return Person{Subject: protocol.downstreamSubject, Lifetime: 30 * time.Minute}, nil
			},
			Authorize: func(_ context.Context, request AuthorizationRequest) (AuthorizationDecision, error) {
				protocol.chainAuthorizeCalls++
				if protocol.chainAuthorize != nil {
					return protocol.chainAuthorize(request)
				}
				protocol.assertUpstreamPolicyClaims(request.Upstream)
				if request.Subject != protocol.downstreamSubject || request.Subject == request.Upstream.Subject {
					protocol.t.Fatalf("downstream authorization subject = %q; upstream = %q", request.Subject, request.Upstream.Subject)
				}
				if strings.Join(request.Scopes, " ") != "payments.charge" || strings.Join(request.Scopes, " ") == request.Upstream.Scope {
					protocol.t.Fatalf("downstream scopes = %#v; upstream = %q", request.Scopes, request.Upstream.Scope)
				}
				return AuthorizationDecision{Scopes: []string{"payments.charge"}, Lifetime: 20 * time.Minute}, nil
			},
		},
	}
}

func (protocol *callChainingProtocol) newServer(t *testing.T, config PSAuthorizationConfig) *Server {
	t.Helper()
	server, err := NewPSAuthorization(config)
	if err != nil {
		t.Fatal(err)
	}
	return server
}

func (protocol *callChainingProtocol) assertUpstreamPolicyClaims(upstream *aauth.AuthTokenClaims) {
	protocol.t.Helper()
	if upstream == nil {
		protocol.t.Fatal("call-chain policy received no verified upstream claims")
	}
	if upstream.Issuer != protocol.personServerID || upstream.DWK != aauth.PersonDiscoveryDocument ||
		upstream.PersonServer != protocol.personServerID || upstream.Audience != protocol.resourceOneID ||
		upstream.JTI != protocol.upstreamClaims.JTI || upstream.Subject != protocol.upstreamClaims.Subject ||
		upstream.Scope != protocol.upstreamClaims.Scope ||
		!upstream.Confirmation.JWK.Equal(protocol.originalAgentKey.PublicJWK()) ||
		upstream.Confirmation.JWK.Equal(protocol.resourceOneProofKey.PublicJWK()) ||
		string(upstream.AdditionalClaims["upstream_context"]) != `{"hop":1}` ||
		upstream.AdditionalClaims["policy_local"] != nil {
		protocol.t.Fatalf("call-chain policy upstream = %#v", upstream)
	}
}

func (protocol *callChainingProtocol) personRequest(t *testing.T, server *Server, upstream, subagent string) *httptest.ResponseRecorder {
	return protocol.personRequestWithCredential(
		t, server, upstream, subagent, protocol.resourceOneProofKey, protocol.resourceOneIDToken,
	)
}

func (protocol *callChainingProtocol) personRequestWithCredential(
	t *testing.T,
	server *Server,
	upstream string,
	subagent string,
	proofKey jose.SigningKey,
	agentToken string,
) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(struct {
		Resource      string `json:"resource"`
		UpstreamToken string `json:"upstream_token,omitempty"`
		SubagentToken string `json:"subagent_token,omitempty"`
	}{Resource: protocol.resourceTwoID, UpstreamToken: upstream, SubagentToken: subagent})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, protocol.personServerID+"/person", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	if err := signPersonServerTestRequest(request, proofKey, agentToken, protocol.clock); err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	return response
}

func (protocol *callChainingProtocol) tokenRequest(t *testing.T, server *Server, resourceToken, upstream, subagent string) *httptest.ResponseRecorder {
	return protocol.tokenRequestWithCredential(
		t, server, resourceToken, upstream, subagent,
		protocol.resourceOneProofKey, protocol.resourceOneIDToken,
	)
}

func (protocol *callChainingProtocol) tokenRequestWithCredential(
	t *testing.T,
	server *Server,
	resourceToken string,
	upstream string,
	subagent string,
	proofKey jose.SigningKey,
	agentToken string,
) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(struct {
		ResourceToken  string `json:"resource_token"`
		PresentedToken string `json:"presented_token,omitempty"`
		UpstreamToken  string `json:"upstream_token,omitempty"`
		SubagentToken  string `json:"subagent_token,omitempty"`
	}{
		ResourceToken: resourceToken, PresentedToken: protocol.presentedTokens[resourceToken],
		UpstreamToken: upstream, SubagentToken: subagent,
	})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, protocol.personServerID+"/token", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	if err := signPersonServerTestRequest(request, proofKey, agentToken, protocol.clock); err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	return response
}

func (protocol *callChainingProtocol) tokenRequestWithCapabilities(
	t *testing.T,
	server *Server,
	resourceToken string,
	upstream string,
	capabilities []string,
) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(struct {
		ResourceToken  string   `json:"resource_token"`
		PresentedToken string   `json:"presented_token,omitempty"`
		UpstreamToken  string   `json:"upstream_token"`
		Capabilities   []string `json:"capabilities"`
	}{
		ResourceToken: resourceToken, PresentedToken: protocol.presentedTokens[resourceToken],
		UpstreamToken: upstream, Capabilities: capabilities,
	})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, protocol.personServerID+"/token", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	if err := signPersonServerTestRequest(request, protocol.resourceOneProofKey, protocol.resourceOneIDToken, protocol.clock); err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	return response
}

func (protocol *callChainingProtocol) resourceToken(
	t *testing.T,
	person aauth.PersonTokenClaims,
	audience string,
	scope string,
	interaction *aauth.ResourceInteraction,
) string {
	t.Helper()
	agentJKT, err := protocol.resourceOneProofKey.PublicJWK().Thumbprint()
	if err != nil {
		t.Fatal(err)
	}
	compact, err := aauth.MintResourceToken(protocol.resourceTwoKey, aauth.ResourceTokenClaims{
		Issuer: protocol.resourceTwoID, DWK: aauth.ResourceDiscoveryDocument,
		Audience: audience, JTI: "resource-two-token", PersonServer: protocol.personServerID,
		Subject: person.Subject, PresentedJTI: person.JTI, AgentJKT: agentJKT,
		IssuedAt: protocol.now.Unix(), ExpiresAt: protocol.now.Add(4 * time.Minute).Unix(),
		Scope: scope, Interaction: interaction,
	})
	if err != nil {
		t.Fatal(err)
	}
	protocol.present(compact, protocol.personTokens[person.JTI])
	return compact
}

// present records the token the agent sends as presented_token with a
// resource token.
func (protocol *callChainingProtocol) present(resourceToken, presented string) {
	if protocol.presentedTokens == nil {
		protocol.presentedTokens = make(map[string]string)
	}
	protocol.presentedTokens[resourceToken] = presented
}

func (protocol *callChainingProtocol) childAgentToken(t *testing.T) string {
	t.Helper()
	compact, err := aauth.MintAgentToken(
		protocol.resourceOneID, protocol.resourceOneIssuerKey,
		aauth.AgentTokenRequest{
			Agent: "aauth:resource-one+child@resource-one.example", ParentAgent: "aauth:resource-one@resource-one.example",
			PersonServer: protocol.personServerID, PublicKey: protocol.childKey.PublicJWK(), Lifetime: time.Hour,
		},
		protocol.now, "call-chain-child-token",
	)
	if err != nil {
		t.Fatal(err)
	}
	return compact
}

func (protocol *callChainingProtocol) samePersonServerAgentToken(t *testing.T) string {
	t.Helper()
	compact, err := aauth.MintAgentToken(
		protocol.resourceOneID, protocol.resourceOneIssuerKey,
		aauth.AgentTokenRequest{
			Agent: "aauth:resource-one@resource-one.example", PersonServer: protocol.personServerID,
			PublicKey: protocol.resourceOneProofKey.PublicJWK(), Lifetime: time.Hour,
		},
		protocol.now, "resource-one-same-person-server-agent-token",
	)
	if err != nil {
		t.Fatal(err)
	}
	return compact
}

func decodeCallChainingPersonToken(t *testing.T, protocol *callChainingProtocol, response *httptest.ResponseRecorder) aauth.PersonTokenClaims {
	t.Helper()
	if response.Code != http.StatusOK {
		t.Fatalf("person response = %d %s", response.Code, response.Body.String())
	}
	var output struct {
		PersonToken string `json:"person_token"`
	}
	if err := json.NewDecoder(response.Body).Decode(&output); err != nil {
		t.Fatal(err)
	}
	claims, err := aauth.VerifyPersonToken(context.Background(), output.PersonToken, protocol.resolver, protocol.clock)
	if err != nil {
		t.Fatal(err)
	}
	if protocol.personTokens == nil {
		protocol.personTokens = make(map[string]string)
	}
	protocol.personTokens[claims.JTI] = output.PersonToken
	return claims
}

func assertCallChainingProblem(t *testing.T, response *httptest.ResponseRecorder, status int, code string) {
	t.Helper()
	var problem struct {
		Code string `json:"error"`
	}
	if err := json.NewDecoder(response.Body).Decode(&problem); err != nil {
		t.Fatalf("decode problem: %v; status=%d body=%s", err, response.Code, response.Body.String())
	}
	if response.Code != status || problem.Code != code {
		t.Fatalf("problem = %d %#v, want %d %q", response.Code, problem, status, code)
	}
}

func mintCallChainingAuthToken(t *testing.T, key jose.SigningKey, claims aauth.AuthTokenClaims) string {
	t.Helper()
	compact, err := aauth.MintAuthToken(key, claims)
	if err != nil {
		t.Fatal(err)
	}
	return compact
}

func reserializeCallChainingToken(t *testing.T, key jose.SigningKey, compact string) string {
	t.Helper()
	parts := strings.Split(compact, ".")
	if len(parts) != 3 {
		t.Fatalf("compact token has %d parts", len(parts))
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	// JSON permits trailing insignificant whitespace. Re-signing those
	// semantically identical claims changes the exact compact bytes without
	// changing any verified authorization input.
	payload = append(payload, '\n')
	reserialized, err := jose.SignCompact(key, jose.Header{
		Algorithm: jose.Ed25519Algorithm, Type: aauth.AuthTokenType, KeyID: key.ID(),
	}, payload)
	if err != nil {
		t.Fatal(err)
	}
	if reserialized == compact {
		t.Fatal("reserialized token did not change exact bytes")
	}
	return reserialized
}

func signCallChainingAuthClaims(t *testing.T, key jose.SigningKey, claims aauth.AuthTokenClaims) string {
	t.Helper()
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	compact, err := jose.SignCompact(key, jose.Header{
		Algorithm: jose.Ed25519Algorithm, Type: aauth.AuthTokenType, KeyID: key.ID(),
	}, payload)
	if err != nil {
		t.Fatal(err)
	}
	return compact
}
