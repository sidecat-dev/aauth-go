package signaturekey

import (
	"encoding/json"
	"errors"
	"net/http"
	"sync"

	"gitlab.com/sidecat-dev/aauth-go/jose"
)

// CachingCredential presents one jwt or jkt-jwt assertion with the cache
// signal until a verifier issues a cache identifier for it, and then the
// cached reference in its place. It falls back to the full assertion
// whenever the verifier answers cache_miss, whatever the advisory expires
// said. A CachingCredential is safe for concurrent use.
type CachingCredential struct {
	full Credential
	jti  string

	mu    sync.Mutex
	grant *CacheGrant
}

// NewCachingCredential wraps a jwt or jkt-jwt credential, adding the cache
// signal when it is absent. The assertion must carry a jti, which a verifier
// requires before it caches an assertion and echoes in Signature-Key-Cache.
func NewCachingCredential(full Credential) (*CachingCredential, error) {
	if full.scheme != SchemeJWT && full.scheme != SchemeJKTJWT {
		return nil, errors.New("aauth: only a jwt or jkt-jwt assertion can be cached")
	}
	parsed, err := jose.ParseCompact(full.parameters["jwt"])
	if err != nil {
		return nil, err
	}
	var claims struct {
		JTI string `json:"jti"`
	}
	if err := json.Unmarshal(parsed.Payload(), &claims); err != nil || claims.JTI == "" {
		return nil, errors.New("aauth: an assertion presented with cache requires jti")
	}
	requested, err := full.WithCache()
	if err != nil {
		return nil, err
	}
	return &CachingCredential{full: requested.clone(), jti: claims.JTI}, nil
}

// Credential returns the credential to present next: the cached reference
// once a verifier has issued one, and otherwise the full assertion with the
// cache signal.
func (caching *CachingCredential) Credential() Credential {
	caching.mu.Lock()
	defer caching.mu.Unlock()
	if caching.grant != nil {
		if cached, err := NewCachedCredential(*caching.grant); err == nil {
			return cached
		}
	}
	return caching.full.clone()
}

// HandleResponse records the verifier's answer to a request that presented
// Credential under label. A Signature-Key-Cache member for label, whose
// echoed jti, when present, is this assertion's, becomes the identifier to
// present next. A cache_miss Signature-Error discards the identifier, so the
// next Credential is the full assertion again; resend reports that the
// request should be repeated with it.
func (caching *CachingCredential) HandleResponse(response *http.Response, label string) (resend bool, err error) {
	if response == nil {
		return false, errors.New("aauth: response is required")
	}
	if values := response.Header.Values("Signature-Error"); len(values) > 0 {
		failure, err := parseErrorValues(values)
		if err != nil {
			return false, err
		}
		if failure.Code == ErrorCacheMiss {
			caching.mu.Lock()
			resend = caching.grant != nil
			caching.grant = nil
			caching.mu.Unlock()
			return resend, nil
		}
		return false, nil
	}
	values := response.Header.Values("Signature-Key-Cache")
	if len(values) == 0 {
		return false, nil
	}
	grants, err := ParseCacheGrants(values)
	if err != nil {
		return false, err
	}
	for _, grant := range grants {
		if grant.label != label || grant.jti != "" && grant.jti != caching.jti {
			continue
		}
		issued := grant
		caching.mu.Lock()
		caching.grant = &issued
		caching.mu.Unlock()
	}
	return false, nil
}

// SelectScheme chooses the scheme a client presents from a server's
// Accept-Signature-Scheme list, in the server's order of preference. It
// skips tokens the client does not list in supported. It skips cached unless
// cacheIssued reports that a verifier has issued the client a cache
// identifier, wherever the server lists it, because cached announces a
// capability rather than a scheme to present first. ok is false when no
// listed scheme can be presented, in which case the client should not sign.
func SelectScheme(accepted, supported []Scheme, cacheIssued bool) (scheme Scheme, ok bool) {
	for _, candidate := range accepted {
		if !containsScheme(supported, candidate) {
			continue
		}
		if candidate == SchemeCached && !cacheIssued {
			continue
		}
		return candidate, true
	}
	return "", false
}
