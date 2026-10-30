package signaturekey

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/dunglas/httpsfv"
	"gitlab.com/sidecat-dev/aauth-go/internal/jsonstrict"
	"gitlab.com/sidecat-dev/aauth-go/jose"
)

// MaxCacheableAssertionLifetime is the longest remaining lifetime an
// assertion may have for AssertionCache to cache it. The draft requires a
// deployment to check revocation when it resolves a long-lived assertion or
// not to cache it. This cache keeps no revocation state, so it does not
// cache an assertion that has longer than this left to live.
const MaxCacheableAssertionLifetime = 24 * time.Hour

const (
	cacheIdentifierVersion    = 1
	cacheIdentifierSaltSize   = 24
	cacheIdentifierKeySize    = 32
	cacheIdentifierInfo       = "Signature-Key cache identifier v1"
	defaultCacheEntries       = 1024
	defaultCacheEntriesPerKey = 8
)

// AssertionCacheConfig configures an AssertionCache.
type AssertionCacheConfig struct {
	// Key is the 32-byte secret that seals cache identifiers. The nodes of
	// one verifier fleet share it; no other party may hold it.
	Key []byte
	// Retention bounds how long an issued identifier resolves. Zero retains
	// each entry until its assertion expires. The advertised expires is never
	// later than the assertion's own exp. A nonzero Retention is at least one
	// second.
	Retention time.Duration
	// MaxEntries bounds this node's index. Zero selects 1024.
	MaxEntries int
	// MaxEntriesPerKey bounds the entries that share one confirmation key, so
	// one caller cannot crowd out every other caller. Zero selects 8.
	MaxEntriesPerKey int
	// Fleet lets this node resolve an identifier that any node holding Key
	// issued, until its expires, without an entry in this node's own index.
	// Evict then removes only this node's entry.
	Fleet bool
}

// AssertionCache issues and resolves Signature-Key cache identifiers for
// jwt and jkt-jwt assertions that a caller asked to have cached.
//
// Each identifier is self-contained: 192 random bits and AES-256-GCM under a
// key derived from Key seal the assertion's scheme, iss, optional sub, jti,
// SHA-256, exp, confirmation key, and the identifier's own expiry. It is
// unpredictable to any party without Key, and one that fails integrity or
// decryption is a cache miss. The index additionally retains the exact
// compact assertion on the node that issued it. An AssertionCache is safe
// for concurrent use.
type AssertionCache struct {
	key        []byte
	retention  time.Duration
	maxEntries int
	maxPerKey  int
	fleet      bool

	mu      sync.Mutex
	entries map[string]assertionCacheEntry
	perKey  map[string]int
}

type assertionCacheEntry struct {
	bucket      string
	retainUntil int64
	compact     string
}

// NewAssertionCache constructs an empty assertion cache.
func NewAssertionCache(config AssertionCacheConfig) (*AssertionCache, error) {
	if len(config.Key) != cacheIdentifierKeySize {
		return nil, fmt.Errorf("aauth: assertion cache key must have %d bytes", cacheIdentifierKeySize)
	}
	if config.Retention < 0 || config.Retention > 0 && config.Retention < time.Second {
		return nil, errors.New("aauth: assertion cache retention must be zero or at least one second")
	}
	if config.MaxEntries < 0 || config.MaxEntriesPerKey < 0 {
		return nil, errors.New("aauth: assertion cache limits must not be negative")
	}
	if config.MaxEntries == 0 {
		config.MaxEntries = defaultCacheEntries
	}
	if config.MaxEntriesPerKey == 0 {
		config.MaxEntriesPerKey = defaultCacheEntriesPerKey
	}
	return &AssertionCache{
		key:        append([]byte(nil), config.Key...),
		retention:  config.Retention,
		maxEntries: config.MaxEntries,
		maxPerKey:  config.MaxEntriesPerKey,
		fleet:      config.Fleet,
		entries:    make(map[string]assertionCacheEntry),
		perKey:     make(map[string]int),
	}, nil
}

// Issue caches the assertion of a verified jwt or jkt-jwt request that
// carried the cache signal, and returns the grant to send in
// Signature-Key-Cache with FormatCacheGrants.
//
// proof must come from verifying the request with the confirmation key of
// that assertion, after the caller verified the assertion itself; a
// jkt-jwt proof from VerifyJKTJWT satisfies both. Issue refuses a proof whose
// key is not the assertion's cnf.jwk, and an assertion without iss, jti,
// exp, or cnf.jwk. A self-jwt assertion is never cached.
//
// Issuing is never obligatory. Issue returns false without an error when the
// request did not ask for caching, when the assertion has longer than
// MaxCacheableAssertionLifetime to live, or when the cache is at capacity.
func (cache *AssertionCache) Issue(proof VerifiedRequest) (CacheGrant, bool, error) {
	if cache == nil || len(cache.key) == 0 {
		return CacheGrant{}, false, errors.New("aauth: assertion cache is required")
	}
	switch proof.credential.scheme {
	case SchemeJWT, SchemeJKTJWT:
	case SchemeSelfJWT:
		return CacheGrant{}, false, errors.New("aauth: a self-jwt assertion has no cache identifier")
	default:
		return CacheGrant{}, false, fmt.Errorf("aauth: a %s proof carries no cacheable assertion", proof.credential.scheme)
	}
	if !proof.credential.cacheRequested {
		return CacheGrant{}, false, nil
	}
	compact := proof.credential.parameters["jwt"]
	claims, err := parseCacheableAssertion(compact)
	if err != nil {
		return CacheGrant{}, false, newError(ErrorInvalidJWT, err)
	}
	if !claims.confirmation.Equal(proof.publicKey) {
		return CacheGrant{}, false, newError(ErrorInvalidKey, errors.New("aauth: the assertion's confirmation key did not verify this request"))
	}
	now := proof.verifiedAt.Unix()
	if claims.expiresAt <= now {
		return CacheGrant{}, false, newError(ErrorExpiredJWT, errors.New("aauth: an expired assertion is not cached"))
	}
	if claims.expiresAt-now > int64(MaxCacheableAssertionLifetime/time.Second) {
		return CacheGrant{}, false, nil
	}
	retainUntil := claims.expiresAt
	if cache.retention > 0 {
		if candidate := proof.verifiedAt.Add(cache.retention).Unix(); candidate < retainUntil {
			retainUntil = candidate
		}
	}
	bucket, err := claims.confirmation.Thumbprint()
	if err != nil {
		return CacheGrant{}, false, newError(ErrorInvalidKey, err)
	}
	digest := sha256.Sum256([]byte(compact))
	plaintext, err := json.Marshal(sealedAssertion{
		Scheme:       proof.credential.scheme,
		Issuer:       claims.issuer,
		Subject:      claims.subject,
		JTI:          claims.jti,
		Digest:       base64.RawURLEncoding.EncodeToString(digest[:]),
		ExpiresAt:    claims.expiresAt,
		RetainUntil:  retainUntil,
		Confirmation: claims.confirmation,
	})
	if err != nil {
		return CacheGrant{}, false, fmt.Errorf("aauth: encode cached assertion: %w", err)
	}

	cache.mu.Lock()
	defer cache.mu.Unlock()
	cache.dropExpiredLocked(now)
	if len(cache.entries) >= cache.maxEntries || cache.perKey[bucket] >= cache.maxPerKey {
		return CacheGrant{}, false, nil
	}
	identifier, err := cache.seal(plaintext)
	if err != nil {
		return CacheGrant{}, false, err
	}
	cache.entries[identifier] = assertionCacheEntry{bucket: bucket, retainUntil: retainUntil, compact: compact}
	cache.perKey[bucket]++
	return CacheGrant{
		label:      proof.label,
		identifier: identifier,
		jti:        claims.jti,
		expiresAt:  time.Unix(retainUntil, 0).UTC(),
	}, true, nil
}

// Evict removes an identifier from this node's index and reports whether it
// was there. With Fleet, other nodes holding Key still resolve it until its
// expires.
func (cache *AssertionCache) Evict(identifier string) bool {
	if cache == nil {
		return false
	}
	cache.mu.Lock()
	defer cache.mu.Unlock()
	return cache.evictLocked(identifier)
}

func (cache *AssertionCache) evictLocked(identifier string) bool {
	entry, ok := cache.entries[identifier]
	if !ok {
		return false
	}
	delete(cache.entries, identifier)
	if cache.perKey[entry.bucket] <= 1 {
		delete(cache.perKey, entry.bucket)
	} else {
		cache.perKey[entry.bucket]--
	}
	return true
}

func (cache *AssertionCache) dropExpiredLocked(now int64) {
	for identifier, entry := range cache.entries {
		if entry.retainUntil < now {
			cache.evictLocked(identifier)
		}
	}
}

// resolve opens identifier and returns the assertion it names. A cache entry
// is honored through its retainUntil second.
func (cache *AssertionCache) resolve(identifier string, now time.Time) (CachedAssertion, error) {
	miss := func(cause error) error { return newError(ErrorCacheMiss, cause) }
	if cache == nil || len(cache.key) == 0 {
		return CachedAssertion{}, errors.New("aauth: assertion cache is required")
	}
	sealed, err := cache.open(identifier)
	if err != nil {
		return CachedAssertion{}, miss(err)
	}
	cache.mu.Lock()
	entry, indexed := cache.entries[identifier]
	if now.Unix() > sealed.RetainUntil {
		cache.evictLocked(identifier)
		cache.mu.Unlock()
		return CachedAssertion{}, miss(errors.New("aauth: cache entry has expired"))
	}
	cache.mu.Unlock()
	if !indexed && !cache.fleet {
		return CachedAssertion{}, miss(errors.New("aauth: cache identifier is not held by this verifier"))
	}
	digest, _ := base64.RawURLEncoding.DecodeString(sealed.Digest)
	assertion := CachedAssertion{
		scheme:          sealed.Scheme,
		issuer:          sealed.Issuer,
		subject:         sealed.Subject,
		jti:             sealed.JTI,
		digest:          digest,
		expiresAt:       time.Unix(sealed.ExpiresAt, 0).UTC(),
		retainedUntil:   time.Unix(sealed.RetainUntil, 0).UTC(),
		confirmationKey: sealed.Confirmation,
	}
	if indexed {
		assertion.compact = entry.compact
	}
	return assertion, nil
}

type sealedAssertion struct {
	Scheme       Scheme   `json:"scheme"`
	Issuer       string   `json:"iss"`
	Subject      string   `json:"sub,omitempty"`
	JTI          string   `json:"jti"`
	Digest       string   `json:"sha256"`
	ExpiresAt    int64    `json:"exp"`
	RetainUntil  int64    `json:"retain"`
	Confirmation jose.JWK `json:"cnf"`
}

// seal derives a one-time AES-256-GCM key from Key and a fresh 192-bit salt,
// so that no key and nonce pair is ever reused, and encodes the version,
// salt, and sealed payload in unpadded base64url.
func (cache *AssertionCache) seal(plaintext []byte) (string, error) {
	salt := make([]byte, cacheIdentifierSaltSize)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("aauth: generate cache identifier: %w", err)
	}
	aead, err := cache.identifierAEAD(salt)
	if err != nil {
		return "", err
	}
	header := []byte{cacheIdentifierVersion}
	sealed := aead.Seal(nil, make([]byte, aead.NonceSize()), plaintext, header)
	identifier := append(append(header, salt...), sealed...)
	return base64.RawURLEncoding.EncodeToString(identifier), nil
}

func (cache *AssertionCache) open(identifier string) (sealedAssertion, error) {
	var sealed sealedAssertion
	raw, err := base64.RawURLEncoding.Strict().DecodeString(identifier)
	if err != nil || base64.RawURLEncoding.EncodeToString(raw) != identifier {
		return sealed, errors.New("aauth: cache identifier is not canonical base64url")
	}
	if len(raw) < 1+cacheIdentifierSaltSize+16 || raw[0] != cacheIdentifierVersion {
		return sealed, errors.New("aauth: cache identifier has an unknown form")
	}
	aead, err := cache.identifierAEAD(raw[1 : 1+cacheIdentifierSaltSize])
	if err != nil {
		return sealed, err
	}
	plaintext, err := aead.Open(nil, make([]byte, aead.NonceSize()), raw[1+cacheIdentifierSaltSize:], raw[:1])
	if err != nil {
		return sealed, errors.New("aauth: cache identifier failed integrity or decryption")
	}
	if err := json.Unmarshal(plaintext, &sealed); err != nil {
		return sealedAssertion{}, fmt.Errorf("aauth: decode cache identifier: %w", err)
	}
	if sealed.Scheme != SchemeJWT && sealed.Scheme != SchemeJKTJWT || sealed.Issuer == "" || sealed.JTI == "" {
		return sealedAssertion{}, errors.New("aauth: cache identifier names no cacheable assertion")
	}
	if _, err := sealed.Confirmation.SignaturePublicKey(); err != nil {
		return sealedAssertion{}, fmt.Errorf("aauth: cache identifier confirmation key: %w", err)
	}
	return sealed, nil
}

func (cache *AssertionCache) identifierAEAD(salt []byte) (cipher.AEAD, error) {
	derived, err := hkdf.Key(sha256.New, cache.key, salt, cacheIdentifierInfo, 32)
	if err != nil {
		return nil, fmt.Errorf("aauth: derive cache identifier key: %w", err)
	}
	block, err := aes.NewCipher(derived)
	if err != nil {
		return nil, fmt.Errorf("aauth: cache identifier cipher: %w", err)
	}
	return cipher.NewGCM(block)
}

type cacheableAssertion struct {
	issuer       string
	subject      string
	jti          string
	expiresAt    int64
	confirmation jose.JWK
}

// parseCacheableAssertion reads the identity of an assertion the caller has
// already verified.
func parseCacheableAssertion(compact string) (cacheableAssertion, error) {
	var parsed cacheableAssertion
	token, err := jose.ParseCompact(compact)
	if err != nil {
		return parsed, err
	}
	payload := token.Payload()
	var claims struct {
		Issuer       string `json:"iss"`
		Subject      string `json:"sub"`
		JTI          string `json:"jti"`
		ExpiresAt    *int64 `json:"exp"`
		Confirmation *struct {
			JWK *jose.JWK `json:"jwk"`
		} `json:"cnf"`
	}
	if err := jsonstrict.RejectCaseVariants(payload, &claims); err != nil {
		return parsed, err
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return parsed, err
	}
	if claims.Issuer == "" {
		return parsed, errors.New("aauth: a cached assertion requires iss")
	}
	if claims.JTI == "" {
		return parsed, errors.New("aauth: a cached assertion requires jti")
	}
	if claims.ExpiresAt == nil {
		return parsed, errors.New("aauth: a cached assertion requires exp")
	}
	if claims.Confirmation == nil || claims.Confirmation.JWK == nil {
		return parsed, errors.New("aauth: a cached assertion requires cnf.jwk")
	}
	return cacheableAssertion{
		issuer:       claims.Issuer,
		subject:      claims.Subject,
		jti:          claims.JTI,
		expiresAt:    *claims.ExpiresAt,
		confirmation: *claims.Confirmation.JWK,
	}, nil
}

// CachedAssertion is the assertion a cache identifier resolved to. Its
// identity fields are those sealed when the identifier was issued.
type CachedAssertion struct {
	scheme          Scheme
	issuer          string
	subject         string
	jti             string
	digest          []byte
	expiresAt       time.Time
	retainedUntil   time.Time
	confirmationKey jose.JWK
	compact         string
}

// Scheme returns the scheme the assertion was presented under: jwt or
// jkt-jwt.
func (assertion CachedAssertion) Scheme() Scheme { return assertion.scheme }

// Issuer returns the assertion's iss.
func (assertion CachedAssertion) Issuer() string { return assertion.issuer }

// Subject returns the assertion's sub, or an empty string when it had none.
func (assertion CachedAssertion) Subject() string { return assertion.subject }

// JTI returns the assertion's jti.
func (assertion CachedAssertion) JTI() string { return assertion.jti }

// SHA256 returns the SHA-256 of the exact compact assertion.
func (assertion CachedAssertion) SHA256() []byte { return append([]byte(nil), assertion.digest...) }

// ExpiresAt returns the assertion's own exp.
func (assertion CachedAssertion) ExpiresAt() time.Time { return assertion.expiresAt }

// CacheExpiresAt returns the cache entry's expiry, the verifier's own
// retention decision. It is never later than ExpiresAt.
func (assertion CachedAssertion) CacheExpiresAt() time.Time { return assertion.retainedUntil }

// ConfirmationKey returns the key that verified the HTTP signature.
func (assertion CachedAssertion) ConfirmationKey() jose.JWK { return assertion.confirmationKey }

// Compact returns the exact compact assertion when this node retains it, so
// the caller can validate it as if it had been presented in full.
func (assertion CachedAssertion) Compact() (string, bool) {
	return assertion.compact, assertion.compact != ""
}

// VerifyCached resolves this request's cache identifier and verifies the
// HTTP Message Signature with the confirmation key of the assertion it names.
// Resolution and validation stay distinct.
//
// Resolution: an identifier that this cache does not hold, that was
// evicted, that is past its expires, or that fails integrity or decryption
// is cache_miss, and the caller resends the assertion in full. Resolving
// authenticates nothing: the HTTP signature must verify against the resolved
// confirmation key, or the request is invalid_signature exactly as with the
// assertion presented in full.
//
// Validation: an assertion past its own exp is expired_jwt, never
// cache_miss, while the cache still holds it. Further claim checks belong to
// the caller, which validates the returned CachedAssertion as it would the
// assertion presented in full.
func (prepared PreparedRequest) VerifyCached(cache *AssertionCache) (VerifiedRequest, CachedAssertion, error) {
	identifier, ok := prepared.credential.CacheIdentifier()
	if !ok {
		return VerifiedRequest{}, CachedAssertion{}, errors.New("aauth: prepared request does not use cached")
	}
	assertion, err := cache.resolve(identifier, prepared.verifiedAt)
	if err != nil {
		return VerifiedRequest{}, CachedAssertion{}, err
	}
	proof, err := prepared.verifyWithKey(assertion.confirmationKey)
	if err != nil {
		return VerifiedRequest{}, CachedAssertion{}, err
	}
	if !assertion.expiresAt.After(prepared.verifiedAt) {
		return VerifiedRequest{}, CachedAssertion{}, newError(ErrorExpiredJWT, errors.New("aauth: the cached assertion has expired"))
	}
	if assertion.scheme == SchemeJKTJWT {
		proof.signer = assertion.issuer
	}
	return proof, assertion, nil
}

// CacheGrant is one cache identifier a verifier issued for the assertion
// presented under one signature label. A client obtains one only from a
// Signature-Key-Cache response field, so it can present an identifier only
// after a verifier issued it. The identifier is opaque and is presented
// exactly as received.
type CacheGrant struct {
	label      string
	identifier string
	jti        string
	expiresAt  time.Time
}

// Label returns the signature label whose assertion was cached.
func (grant CacheGrant) Label() string { return grant.label }

// JTI returns the echoed jti of the cached assertion, or an empty string
// when the verifier did not send one.
func (grant CacheGrant) JTI() string { return grant.jti }

// ExpiresAt returns the advisory time after which the verifier may stop
// honoring the identifier. A verifier may answer cache_miss at any time,
// before or after it.
func (grant CacheGrant) ExpiresAt() (time.Time, bool) {
	return grant.expiresAt, !grant.expiresAt.IsZero()
}

// FormatCacheGrants serializes a Signature-Key-Cache field value. Each member
// is keyed by its signature label and carries the identifier as a String with
// its jti and expires parameters.
func FormatCacheGrants(grants ...CacheGrant) (string, error) {
	if len(grants) == 0 {
		return "", errors.New("aauth: Signature-Key-Cache requires at least one grant")
	}
	dictionary := httpsfv.NewDictionary()
	for _, grant := range grants {
		if !isStructuredFieldKey(grant.label) || grant.identifier == "" {
			return "", errors.New("aauth: Signature-Key-Cache grant requires a label and an identifier")
		}
		if _, duplicate := dictionary.Get(grant.label); duplicate {
			return "", fmt.Errorf("aauth: Signature-Key-Cache label %q is repeated", grant.label)
		}
		for _, value := range []string{grant.identifier, grant.jti} {
			if err := validateStructuredFieldString(value); err != nil {
				return "", fmt.Errorf("aauth: Signature-Key-Cache: %w", err)
			}
		}
		item := httpsfv.NewItem(grant.identifier)
		if grant.jti != "" {
			item.Params.Add("jti", grant.jti)
		}
		if !grant.expiresAt.IsZero() {
			item.Params.Add("expires", grant.expiresAt.Unix())
		}
		dictionary.Add(grant.label, item)
	}
	encoded, err := httpsfv.Marshal(dictionary)
	if err != nil {
		return "", fmt.Errorf("aauth: format Signature-Key-Cache: %w", err)
	}
	return encoded, nil
}

// ParseCacheGrants parses the Signature-Key-Cache field lines of a response.
// Unknown member parameters are ignored.
func ParseCacheGrants(values []string) ([]CacheGrant, error) {
	dictionary, err := httpsfv.UnmarshalDictionary(values)
	if err != nil {
		return nil, fmt.Errorf("aauth: parse Signature-Key-Cache: %w", err)
	}
	grants := make([]CacheGrant, 0, len(dictionary.Names()))
	for _, label := range dictionary.Names() {
		member, _ := dictionary.Get(label)
		item, ok := member.(httpsfv.Item)
		if !ok {
			return nil, fmt.Errorf("aauth: Signature-Key-Cache member %q must be an Item", label)
		}
		identifier, ok := item.Value.(string)
		if !ok || identifier == "" {
			return nil, fmt.Errorf("aauth: Signature-Key-Cache member %q must be a non-empty String", label)
		}
		grant := CacheGrant{label: label, identifier: identifier}
		if value, present := item.Params.Get("jti"); present {
			jti, ok := value.(string)
			if !ok {
				return nil, fmt.Errorf("aauth: Signature-Key-Cache member %q jti must be a String", label)
			}
			grant.jti = jti
		}
		if value, present := item.Params.Get("expires"); present {
			expires, ok := value.(int64)
			if !ok || expires < 0 {
				return nil, fmt.Errorf("aauth: Signature-Key-Cache member %q expires must be a non-negative Integer", label)
			}
			grant.expiresAt = time.Unix(expires, 0).UTC()
		}
		grants = append(grants, grant)
	}
	return grants, nil
}
