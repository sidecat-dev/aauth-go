package signaturekey_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/dunglas/httpsfv"
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

var testFleetKey = bytes.Repeat([]byte{0x5a}, 32)

func newTestAssertionCache(t *testing.T, config signaturekey.AssertionCacheConfig) *signaturekey.AssertionCache {
	t.Helper()
	if config.Key == nil {
		config.Key = testFleetKey
	}
	cache, err := signaturekey.NewAssertionCache(config)
	if err != nil {
		t.Fatal(err)
	}
	return cache
}

// cachedDelegation is one verified jkt-jwt request that asked to be cached,
// with the Signature-Key-Cache field a verifier answered it with.
type cachedDelegation struct {
	durable   jose.SigningKey
	ephemeral jose.SigningKey
	compact   string
	full      signaturekey.Credential
	field     string
}

func issueTestDelegation(t *testing.T, cache *signaturekey.AssertionCache, now time.Time, lifetime time.Duration, jti string) cachedDelegation {
	t.Helper()
	delegation := cachedDelegation{
		durable:   testDiscoverySigningKey(t, "durable-key", 0x61),
		ephemeral: testDiscoverySigningKey(t, "ephemeral-key", 0x62),
	}
	delegation.compact = mintTestJKTJWT(t, delegation.durable, delegation.ephemeral.PublicJWK(), now, now.Add(lifetime), jti)
	full, err := signaturekey.NewJKTJWTCredential(delegation.compact)
	if err != nil {
		t.Fatal(err)
	}
	if delegation.full, err = full.WithCache(); err != nil {
		t.Fatal(err)
	}
	prepared := prepareTestJKTJWTRequestWithCredential(t, delegation.full, delegation.ephemeral, now)
	proof, _, err := prepared.VerifyJKTJWT()
	if err != nil {
		t.Fatal(err)
	}
	grant, issued, err := cache.Issue(proof)
	if err != nil || !issued {
		t.Fatalf("Issue() = %t, %v", issued, err)
	}
	if delegation.field, err = signaturekey.FormatCacheGrants(grant); err != nil {
		t.Fatal(err)
	}
	return delegation
}

// cachedCredential reads the client's credential from a Signature-Key-Cache
// field, the only way a client obtains a cache identifier.
func cachedCredential(t *testing.T, field string) signaturekey.Credential {
	t.Helper()
	grants, err := signaturekey.ParseCacheGrants([]string{field})
	if err != nil || len(grants) != 1 {
		t.Fatalf("ParseCacheGrants(%q) = %v, %v", field, grants, err)
	}
	credential, err := signaturekey.NewCachedCredential(grants[0])
	if err != nil {
		t.Fatal(err)
	}
	return credential
}

func prepareTestCachedRequest(t *testing.T, credential signaturekey.Credential, key jose.SigningKey, now time.Time) signaturekey.PreparedRequest {
	t.Helper()
	request, err := http.NewRequest(http.MethodGet, "https://ap.example/items", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := signaturekey.SignRequest(request, key, credential, fixedClock(now), signaturekey.SignOptions{}); err != nil {
		t.Fatal(err)
	}
	prepared, err := signaturekey.PrepareRequest(request, fixedClock(now), signaturekey.VerifyOptions{
		AcceptedSchemes: []signaturekey.Scheme{signaturekey.SchemeJKTJWT, signaturekey.SchemeCached},
	})
	if err != nil {
		t.Fatal(err)
	}
	return prepared
}

func TestCachedAssertionRoundTripsThroughSignatureKeyCache(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 10, 30, 15, 0, 0, 0, time.UTC)
	cache := newTestAssertionCache(t, signaturekey.AssertionCacheConfig{Retention: 10 * time.Minute})
	delegation := issueTestDelegation(t, cache, now, time.Hour, "refresh-1")

	dictionary, err := httpsfv.UnmarshalDictionary([]string{delegation.field})
	if err != nil {
		t.Fatal(err)
	}
	member, _ := dictionary.Get("sig")
	issued := member.(httpsfv.Item)
	if jti, _ := issued.Params.Get("jti"); jti != "refresh-1" {
		t.Fatalf("Signature-Key-Cache jti = %v", jti)
	}
	if expires, _ := issued.Params.Get("expires"); expires != now.Add(10*time.Minute).Unix() {
		t.Fatalf("Signature-Key-Cache expires = %v", expires)
	}

	credential := cachedCredential(t, delegation.field)
	if identifier, ok := credential.CacheIdentifier(); !ok || identifier != issued.Value {
		t.Fatalf("presented identifier %q differs from the issued %q", identifier, issued.Value)
	}
	prepared := prepareTestCachedRequest(t, credential, delegation.ephemeral, now.Add(time.Minute))
	if _, err := prepared.Verify(delegation.ephemeral.PublicJWK()); err == nil {
		t.Fatal("Verify accepted a cached proof without resolving it")
	}
	proof, assertion, err := prepared.VerifyCached(cache)
	if err != nil {
		t.Fatal(err)
	}
	identity, _ := delegation.durable.PublicJWK().ThumbprintURI()
	compact, retained := assertion.Compact()
	if proof.Scheme() != signaturekey.SchemeCached || proof.Signer() != identity ||
		assertion.Scheme() != signaturekey.SchemeJKTJWT || assertion.Issuer() != identity ||
		assertion.JTI() != "refresh-1" || !retained || compact != delegation.compact ||
		!assertion.ExpiresAt().Equal(now.Add(time.Hour)) || !assertion.CacheExpiresAt().Equal(now.Add(10*time.Minute)) ||
		!assertion.ConfirmationKey().Equal(delegation.ephemeral.PublicJWK()) {
		t.Fatalf("resolved proof %q signer %q, assertion %#v", proof.Scheme(), proof.Signer(), assertion)
	}
}

func TestCacheResolutionAndValidationStayDistinct(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 10, 30, 15, 0, 0, 0, time.UTC)
	t.Run("identifier from another verifier is a cache miss", func(t *testing.T) {
		delegation := issueTestDelegation(t, newTestAssertionCache(t, signaturekey.AssertionCacheConfig{}), now, time.Hour, "refresh-1")
		other := newTestAssertionCache(t, signaturekey.AssertionCacheConfig{Key: bytes.Repeat([]byte{0x5b}, 32), Fleet: true})
		_, _, err := prepareTestCachedRequest(t, cachedCredential(t, delegation.field), delegation.ephemeral, now).VerifyCached(other)
		assertSignatureErrorCode(t, err, signaturekey.ErrorCacheMiss)
	})
	t.Run("altered identifier is a cache miss", func(t *testing.T) {
		cache := newTestAssertionCache(t, signaturekey.AssertionCacheConfig{Fleet: true})
		delegation := issueTestDelegation(t, cache, now, time.Hour, "refresh-1")
		start := strings.Index(delegation.field, `"`) + 10
		altered := delegation.field[:start] + string('A'+(delegation.field[start]-'A'+1)%26) + delegation.field[start+1:]
		_, _, err := prepareTestCachedRequest(t, cachedCredential(t, altered), delegation.ephemeral, now).VerifyCached(cache)
		assertSignatureErrorCode(t, err, signaturekey.ErrorCacheMiss)
	})
	t.Run("evicted entry is a cache miss", func(t *testing.T) {
		cache := newTestAssertionCache(t, signaturekey.AssertionCacheConfig{})
		delegation := issueTestDelegation(t, cache, now, time.Hour, "refresh-1")
		credential := cachedCredential(t, delegation.field)
		identifier, _ := credential.CacheIdentifier()
		if !cache.Evict(identifier) {
			t.Fatal("Evict() found no entry")
		}
		_, _, err := prepareTestCachedRequest(t, credential, delegation.ephemeral, now).VerifyCached(cache)
		assertSignatureErrorCode(t, err, signaturekey.ErrorCacheMiss)
	})
	t.Run("entry past its own expiry is a cache miss", func(t *testing.T) {
		cache := newTestAssertionCache(t, signaturekey.AssertionCacheConfig{Retention: time.Minute})
		delegation := issueTestDelegation(t, cache, now, time.Hour, "refresh-1")
		later := now.Add(time.Minute + time.Second)
		_, _, err := prepareTestCachedRequest(t, cachedCredential(t, delegation.field), delegation.ephemeral, later).VerifyCached(cache)
		assertSignatureErrorCode(t, err, signaturekey.ErrorCacheMiss)
	})
	t.Run("held assertion past its exp is expired, not a miss", func(t *testing.T) {
		cache := newTestAssertionCache(t, signaturekey.AssertionCacheConfig{})
		delegation := issueTestDelegation(t, cache, now, 10*time.Minute, "refresh-1")
		atExpiry := now.Add(10 * time.Minute)
		_, _, err := prepareTestCachedRequest(t, cachedCredential(t, delegation.field), delegation.ephemeral, atExpiry).VerifyCached(cache)
		assertSignatureErrorCode(t, err, signaturekey.ErrorExpiredJWT)
	})
	t.Run("resolving does not authenticate the caller", func(t *testing.T) {
		cache := newTestAssertionCache(t, signaturekey.AssertionCacheConfig{})
		delegation := issueTestDelegation(t, cache, now, time.Hour, "refresh-1")
		_, _, err := prepareTestCachedRequest(t, cachedCredential(t, delegation.field), delegation.durable, now).VerifyCached(cache)
		assertSignatureErrorCode(t, err, signaturekey.ErrorInvalidSignature)
	})
}

func TestFleetNodesResolveSealedIdentifiers(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 10, 30, 15, 0, 0, 0, time.UTC)
	issuer := newTestAssertionCache(t, signaturekey.AssertionCacheConfig{})
	delegation := issueTestDelegation(t, issuer, now, time.Hour, "refresh-1")
	credential := cachedCredential(t, delegation.field)

	peer := newTestAssertionCache(t, signaturekey.AssertionCacheConfig{Fleet: true})
	_, assertion, err := prepareTestCachedRequest(t, credential, delegation.ephemeral, now).VerifyCached(peer)
	if err != nil {
		t.Fatal(err)
	}
	if _, retained := assertion.Compact(); retained || assertion.JTI() != "refresh-1" {
		t.Fatalf("peer resolution = %#v", assertion)
	}
	standalone := newTestAssertionCache(t, signaturekey.AssertionCacheConfig{})
	_, _, err = prepareTestCachedRequest(t, credential, delegation.ephemeral, now).VerifyCached(standalone)
	assertSignatureErrorCode(t, err, signaturekey.ErrorCacheMiss)
}

func TestAssertionCacheIssuesOnlyWhatItMay(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 10, 30, 15, 0, 0, 0, time.UTC)
	issuerKey := testDiscoverySigningKey(t, "issuer-key", 0x63)
	requestKey := testDiscoverySigningKey(t, "request-key", 0x64)
	jwtProof := func(claims map[string]any, cache bool) signaturekey.VerifiedRequest {
		t.Helper()
		payload, err := json.Marshal(claims)
		if err != nil {
			t.Fatal(err)
		}
		compact, err := jose.SignCompact(issuerKey, jose.Header{Algorithm: jose.Ed25519Algorithm, Type: "example+jwt", KeyID: issuerKey.ID()}, payload)
		if err != nil {
			t.Fatal(err)
		}
		credential, err := signaturekey.NewJWTCredential(compact)
		if err != nil {
			t.Fatal(err)
		}
		if cache {
			credential, _ = credential.WithCache()
		}
		request, _ := http.NewRequest(http.MethodGet, "https://resource.example/items", nil)
		if err := signaturekey.SignRequest(request, requestKey, credential, fixedClock(now), signaturekey.SignOptions{}); err != nil {
			t.Fatal(err)
		}
		prepared, err := signaturekey.PrepareRequest(request, fixedClock(now), signaturekey.VerifyOptions{})
		if err != nil {
			t.Fatal(err)
		}
		proof, err := prepared.Verify(requestKey.PublicJWK())
		if err != nil {
			t.Fatal(err)
		}
		return proof
	}
	claims := func(jti string, lifetime time.Duration, confirmation jose.JWK) map[string]any {
		return map[string]any{
			"iss": "https://issuer.example", "sub": "agent-1", "jti": jti,
			"exp": now.Add(lifetime).Unix(), "cnf": map[string]any{"jwk": confirmation},
		}
	}

	cache := newTestAssertionCache(t, signaturekey.AssertionCacheConfig{MaxEntriesPerKey: 1, Retention: 48 * time.Hour})
	grant, issued, err := cache.Issue(jwtProof(claims("token-1", time.Hour, requestKey.PublicJWK()), true))
	if expires, _ := grant.ExpiresAt(); err != nil || !issued || !expires.Equal(now.Add(time.Hour)) || grant.JTI() != "token-1" {
		t.Fatalf("Issue() = %t, %v, expires %s; retention must not outlive the assertion", issued, err, expires)
	}
	if _, issued, err := cache.Issue(jwtProof(claims("token-2", time.Hour, requestKey.PublicJWK()), true)); err != nil || issued {
		t.Fatalf("Issue() beyond the per-key bound = %t, %v", issued, err)
	}
	if _, issued, err := cache.Issue(jwtProof(claims("token-3", time.Hour, requestKey.PublicJWK()), false)); err != nil || issued {
		t.Fatalf("Issue() without the cache signal = %t, %v", issued, err)
	}
	fresh := newTestAssertionCache(t, signaturekey.AssertionCacheConfig{})
	if _, issued, err := fresh.Issue(jwtProof(claims("token-4", 25*time.Hour, requestKey.PublicJWK()), true)); err != nil || issued {
		t.Fatalf("Issue() for a long-lived assertion = %t, %v", issued, err)
	}
	_, _, err = fresh.Issue(jwtProof(claims("", time.Hour, requestKey.PublicJWK()), true))
	assertSignatureErrorCode(t, err, signaturekey.ErrorInvalidJWT)
	_, _, err = fresh.Issue(jwtProof(claims("token-5", time.Hour, issuerKey.PublicJWK()), true))
	assertSignatureErrorCode(t, err, signaturekey.ErrorInvalidKey)

	eventKey := testDiscoverySigningKey(t, "event-key", 0x65)
	compact := signTestSelfJWT(t, eventKey, "aa-event+jwt", map[string]any{
		"iss": "https://resource.example", "dwk": "aauth-resource.json", "jti": "event-1", "exp": now.Add(time.Minute).Unix(),
	})
	resolver := signaturekey.StaticKeyResolver{
		{Issuer: "https://resource.example", DiscoveryDocument: "aauth-resource.json", KeyID: eventKey.ID()}: eventKey.PublicJWK(),
	}
	selfProof, _, err := prepareTestSelfJWTRequest(t, eventKey, compact, now).VerifySelfJWT(context.Background(), resolver, "aa-event+jwt")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := fresh.Issue(selfProof); err == nil {
		t.Fatal("Issue() issued a cache identifier for a self-jwt")
	}
}

func TestCachingCredentialFallsBackToTheFullAssertion(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 10, 30, 15, 0, 0, 0, time.UTC)
	cache := newTestAssertionCache(t, signaturekey.AssertionCacheConfig{})
	delegation := issueTestDelegation(t, cache, now, time.Hour, "refresh-1")
	full, err := signaturekey.NewJKTJWTCredential(delegation.compact)
	if err != nil {
		t.Fatal(err)
	}
	caching, err := signaturekey.NewCachingCredential(full)
	if err != nil {
		t.Fatal(err)
	}
	if first := caching.Credential(); first.Scheme() != signaturekey.SchemeJKTJWT || !first.CacheRequested() {
		t.Fatalf("first credential = %q, cache %t", first.Scheme(), first.CacheRequested())
	}
	respond := func(name, value string) bool {
		t.Helper()
		resend, err := caching.HandleResponse(&http.Response{Header: http.Header{name: []string{value}}}, "sig")
		if err != nil {
			t.Fatal(err)
		}
		return resend
	}
	respond("Signature-Key-Cache", strings.Replace(delegation.field, `jti="refresh-1"`, `jti="refresh-2"`, 1))
	if caching.Credential().Scheme() != signaturekey.SchemeJKTJWT {
		t.Fatal("client adopted an identifier issued for another assertion")
	}
	respond("Signature-Key-Cache", delegation.field)
	if caching.Credential().Scheme() != signaturekey.SchemeCached {
		t.Fatal("client did not present the issued identifier")
	}
	if !respond("Signature-Error", "error=cache_miss") {
		t.Fatal("cache_miss did not ask for the full assertion")
	}
	if again := caching.Credential(); again.Scheme() != signaturekey.SchemeJKTJWT || !again.CacheRequested() {
		t.Fatalf("credential after cache_miss = %q", again.Scheme())
	}

	untracked := mintTestJKTJWT(t, delegation.durable, delegation.ephemeral.PublicJWK(), now, now.Add(time.Hour), "")
	withoutJTI, err := signaturekey.NewJKTJWTCredential(untracked)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := signaturekey.NewCachingCredential(withoutJTI); err == nil {
		t.Fatal("NewCachingCredential accepted an assertion without jti")
	}
}

func TestSelectSchemePresentsCachedOnlyAfterIssuance(t *testing.T) {
	t.Parallel()

	accepted := []signaturekey.Scheme{signaturekey.SchemeCached, "future", signaturekey.SchemeHWK, signaturekey.SchemeJWT}
	supported := []signaturekey.Scheme{signaturekey.SchemeJWT, signaturekey.SchemeCached}
	if scheme, ok := signaturekey.SelectScheme(accepted, supported, false); !ok || scheme != signaturekey.SchemeJWT {
		t.Fatalf("SelectScheme() before issuance = %q, %t", scheme, ok)
	}
	if scheme, ok := signaturekey.SelectScheme(accepted, supported, true); !ok || scheme != signaturekey.SchemeCached {
		t.Fatalf("SelectScheme() after issuance = %q, %t", scheme, ok)
	}
	if scheme, ok := signaturekey.SelectScheme([]signaturekey.Scheme{"future", signaturekey.SchemeCached}, supported, false); ok {
		t.Fatalf("SelectScheme() chose %q from a list it cannot satisfy", scheme)
	}
}
