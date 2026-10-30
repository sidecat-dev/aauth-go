package personserver

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

const callChainUpstreamPersonTokenJTI = "upstream-person-token"

// usePersonTokenUpstream makes the upstream token a person token this Person
// Server issued to the original calling Agent for the intermediary, as when
// the intermediary served the request on the person's identity. The retained
// person-token record identifies the calling Agent.
func (protocol *callChainingProtocol) usePersonTokenUpstream(t *testing.T) (aauth.PersonTokenClaims, PersonTokenRecord) {
	t.Helper()
	claims := aauth.PersonTokenClaims{
		Issuer: protocol.personServerID, DWK: aauth.PersonDiscoveryDocument,
		Audience: protocol.resourceOneID, Subject: "person-for-resource-one",
		Confirmation: aauth.Confirmation{JWK: protocol.originalAgentKey.PublicJWK()},
		JTI:          callChainUpstreamPersonTokenJTI,
		IssuedAt:     protocol.now.Unix(), ExpiresAt: protocol.now.Add(10 * time.Minute).Unix(),
	}
	compact, err := aauth.MintPersonToken(protocol.personServerKey, claims)
	if err != nil {
		t.Fatal(err)
	}
	record := directPersonTokenRecord(
		claims.JTI, protocol.personServerID, protocol.resourceOneID, claims.Subject, "",
		callChainOriginalAgentProvider, callChainOriginalAgent, protocol.originalAgentKey.PublicJWK(),
		time.Unix(claims.ExpiresAt, 0).UTC(), time.Unix(claims.ExpiresAt, 0).UTC().Add(time.Hour),
	)
	record.AgentTokenJTI = callChainOriginalAgentTokenJTI
	protocol.store.mu.Lock()
	protocol.store.records[record.PersonServer+"\x00"+record.JTI] = record
	protocol.store.mu.Unlock()
	protocol.upstreamToken = compact
	protocol.chainBind = func(request PersonTokenRequest) (Person, error) {
		protocol.assertUpstreamPersonPolicyClaims(request.Upstream, request.UpstreamPerson, claims)
		request.UpstreamPerson.Subject = "policy-local-subject-mutation"
		return Person{Subject: protocol.downstreamSubject, Lifetime: 30 * time.Minute}, nil
	}
	protocol.chainAuthorize = func(request AuthorizationRequest) (AuthorizationDecision, error) {
		protocol.assertUpstreamPersonPolicyClaims(request.Upstream, request.UpstreamPerson, claims)
		if request.Subject != protocol.downstreamSubject {
			protocol.t.Fatalf("downstream authorization subject = %q", request.Subject)
		}
		return AuthorizationDecision{Scopes: []string{"payments.charge"}, Lifetime: 20 * time.Minute}, nil
	}
	return claims, record
}

func (protocol *callChainingProtocol) assertUpstreamPersonPolicyClaims(
	auth *aauth.AuthTokenClaims,
	person *aauth.PersonTokenClaims,
	want aauth.PersonTokenClaims,
) {
	protocol.t.Helper()
	if auth != nil || person == nil {
		protocol.t.Fatalf("call-chain policy upstream: auth %#v, person %#v", auth, person)
	}
	if person.Issuer != want.Issuer || person.Audience != want.Audience || person.JTI != want.JTI ||
		person.Subject != want.Subject || person.ExpiresAt != want.ExpiresAt ||
		!person.Confirmation.JWK.Equal(protocol.originalAgentKey.PublicJWK()) {
		protocol.t.Fatalf("call-chain policy upstream person token = %#v", person)
	}
}

// Upstream Token Verification accepts a person token as well as an auth
// token: the intermediary served the calling Agent's request on the person's
// identity. The Person Server verifies it as a person token with the call-chain
// substitutions, requires that it issued it, identifies the calling Agent from
// its own person-token record, and issues downstream tokens that expire no
// later than it, at both the person token endpoint and the auth token endpoint.
func TestCallChainingAcceptsAnUpstreamPersonToken(t *testing.T) {
	protocol := newCallChainingProtocol(t)
	upstream, _ := protocol.usePersonTokenUpstream(t)
	server := protocol.newServer(t, protocol.config())

	personResponse := protocol.personRequest(t, server, protocol.upstreamToken, "")
	personClaims := decodeCallChainingPersonToken(t, protocol, personResponse)
	if personClaims.Audience != protocol.resourceTwoID || personClaims.Subject != protocol.downstreamSubject ||
		!personClaims.Confirmation.JWK.Equal(protocol.resourceOneProofKey.PublicJWK()) {
		t.Fatalf("downstream person token = %#v", personClaims)
	}
	// Policy allows 30 minutes, but downstream access does not outlive the
	// 10-minute upstream person token.
	if personClaims.ExpiresAt != upstream.ExpiresAt {
		t.Fatalf("downstream person token exp = %d, want upstream exp %d", personClaims.ExpiresAt, upstream.ExpiresAt)
	}
	retained, err := protocol.store.Load(context.Background(), protocol.personServerID, personClaims.JTI)
	if err != nil {
		t.Fatal(err)
	}
	wantReference := aauth.TokenReference{Issuer: protocol.personServerID, JTI: upstream.JTI}
	if retained.UpstreamTokenReference != wantReference ||
		retained.UpstreamTokenSHA256 != sha256.Sum256([]byte(protocol.upstreamToken)) ||
		retained.AgentTokenJTI != "resource-one-agent-token" {
		t.Fatalf("retained downstream record = %#v", retained)
	}

	resourceToken := protocol.resourceToken(t, personClaims, protocol.personServerID, "payments.charge", nil)
	tokenResponse := protocol.tokenRequest(t, server, resourceToken, protocol.upstreamToken, "")
	if tokenResponse.Code != http.StatusOK {
		t.Fatalf("token response = %d %s", tokenResponse.Code, tokenResponse.Body.String())
	}
	var tokenOutput struct {
		AuthToken string `json:"auth_token"`
	}
	if err := json.NewDecoder(tokenResponse.Body).Decode(&tokenOutput); err != nil {
		t.Fatal(err)
	}
	authClaims, err := aauth.VerifyAuthToken(context.Background(), tokenOutput.AuthToken, protocol.resolver, protocol.clock)
	if err != nil {
		t.Fatal(err)
	}
	if authClaims.Audience != protocol.resourceTwoID || authClaims.Subject != protocol.downstreamSubject ||
		authClaims.Scope != "payments.charge" || authClaims.ExpiresAt != upstream.ExpiresAt {
		t.Fatalf("downstream auth token = %#v, want exp %d", authClaims, upstream.ExpiresAt)
	}
	issued := protocol.issuedRecord(t, aauth.TokenReference{Issuer: authClaims.Issuer, JTI: authClaims.JTI})
	if issued.UpstreamTokenReference != wantReference {
		t.Fatalf("issued downstream auth-token record = %#v", issued)
	}
	if protocol.chainBindCalls != 1 || protocol.chainAuthorizeCalls != 1 ||
		protocol.ordinaryBindCalls != 0 || protocol.ordinaryAuthorizeCalls != 0 {
		t.Fatalf("policy calls: chain %d/%d ordinary %d/%d",
			protocol.chainBindCalls, protocol.chainAuthorizeCalls, protocol.ordinaryBindCalls, protocol.ordinaryAuthorizeCalls)
	}
}

// An upstream person token is refused, before any policy runs, when it fails
// Upstream Token Verification: another Person Server issued it, its aud is not
// the intermediary, it expired, this Person Server holds no record naming its
// calling Agent, or that Agent's Agent token is revoked.
func TestCallChainingRefusesAnUnacceptableUpstreamPersonToken(t *testing.T) {
	tests := []struct {
		name   string
		code   string
		change func(*testing.T, *callChainingProtocol, aauth.PersonTokenClaims, PersonTokenRecord)
		revoke bool
	}{
		{
			name: "other person server",
			code: "invalid_upstream_token",
			change: func(t *testing.T, protocol *callChainingProtocol, claims aauth.PersonTokenClaims, _ PersonTokenRecord) {
				// The other Person Server's key resolves, so only the issuer
				// check can refuse the token.
				const otherPersonServer = "https://other-person.example"
				otherKey := personServerTestKey(t, "call-chain-other-person")
				protocol.resolver.(signaturekey.StaticKeyResolver)[signaturekey.StaticKeyReference{
					Issuer: otherPersonServer, DiscoveryDocument: aauth.PersonDiscoveryDocument, KeyID: otherKey.ID(),
				}] = otherKey.PublicJWK()
				claims.Issuer = otherPersonServer
				protocol.upstreamToken = mintCallChainingPersonToken(t, otherKey, claims)
			},
		},
		{
			name: "audience is not the intermediary",
			code: "invalid_upstream_token",
			change: func(t *testing.T, protocol *callChainingProtocol, claims aauth.PersonTokenClaims, _ PersonTokenRecord) {
				claims.Audience = protocol.resourceTwoID
				protocol.upstreamToken = mintCallChainingPersonToken(t, protocol.personServerKey, claims)
			},
		},
		{
			name: "expired",
			code: "expired_upstream_token",
			change: func(t *testing.T, protocol *callChainingProtocol, claims aauth.PersonTokenClaims, _ PersonTokenRecord) {
				claims.IssuedAt = protocol.now.Add(-20 * time.Minute).Unix()
				claims.ExpiresAt = protocol.now.Add(-10 * time.Minute).Unix()
				protocol.upstreamToken = mintCallChainingPersonToken(t, protocol.personServerKey, claims)
			},
		},
		{
			name: "no retained record",
			code: "invalid_upstream_token",
			change: func(_ *testing.T, protocol *callChainingProtocol, _ aauth.PersonTokenClaims, record PersonTokenRecord) {
				protocol.store.mu.Lock()
				delete(protocol.store.records, record.PersonServer+"\x00"+record.JTI)
				protocol.store.mu.Unlock()
			},
		},
		{
			name: "record names no Agent token",
			code: "invalid_upstream_token",
			change: func(_ *testing.T, protocol *callChainingProtocol, _ aauth.PersonTokenClaims, record PersonTokenRecord) {
				record.AgentTokenJTI = ""
				protocol.store.mu.Lock()
				protocol.store.records[record.PersonServer+"\x00"+record.JTI] = record
				protocol.store.mu.Unlock()
			},
		},
		{
			name: "record for another person",
			code: "invalid_upstream_token",
			change: func(_ *testing.T, protocol *callChainingProtocol, _ aauth.PersonTokenClaims, record PersonTokenRecord) {
				record.Subject = "another-person"
				protocol.store.mu.Lock()
				protocol.store.records[record.PersonServer+"\x00"+record.JTI] = record
				protocol.store.mu.Unlock()
			},
		},
		{
			name:   "calling Agent's Agent token revoked",
			code:   "revoked_upstream_token",
			change: func(*testing.T, *callChainingProtocol, aauth.PersonTokenClaims, PersonTokenRecord) {},
			revoke: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			protocol := newCallChainingProtocol(t)
			claims, record := protocol.usePersonTokenUpstream(t)
			test.change(t, protocol, claims, record)
			config := protocol.config()
			revocations := newReferenceAgentTokenRevocationStore()
			original := aauth.TokenReference{Issuer: callChainOriginalAgentProvider, JTI: callChainOriginalAgentTokenJTI}
			if test.revoke {
				revocations.revoked[original] = true
			}
			config.AgentTokenRevocations = revocations
			server := protocol.newServer(t, config)
			response := protocol.personRequest(t, server, protocol.upstreamToken, "")
			assertCallChainingProblem(t, response, http.StatusBadRequest, test.code)
			_, commits, _ := protocol.store.observation()
			if protocol.chainBindCalls != 0 || protocol.ordinaryBindCalls != 0 || commits != 0 {
				t.Fatalf("refused upstream reached policy or retention: bind %d/%d commits %d",
					protocol.chainBindCalls, protocol.ordinaryBindCalls, commits)
			}
			if test.revoke && !revocations.looked(original) {
				t.Fatalf("revocation of the calling Agent's Agent token was not checked: %#v", revocations.lookups)
			}
		})
	}
}

func mintCallChainingPersonToken(t *testing.T, key jose.SigningKey, claims aauth.PersonTokenClaims) string {
	t.Helper()
	compact, err := aauth.MintPersonToken(key, claims)
	if err != nil {
		t.Fatal(err)
	}
	return compact
}
