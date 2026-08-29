package aauth

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"gitlab.com/sidecat-dev/aauth-go/jose"
)

type tokenDraftClaims interface {
	ResourceTokenClaims | AuthTokenClaims
}

// TokenDraft is invalid-zero, copy-safe issuance material for one Core
// resource or auth token. Companion packages add their complete recognized
// member sets to a draft; the deployment signs the composed payload once.
// Core checks only catalog ownership, applicability, and co-presence. It does
// not interpret companion semantics.
type TokenDraft[C tokenDraftClaims] struct {
	tokenType  string
	base       []byte
	extensions map[string]json.RawMessage
	seal       [sha256.Size]byte
}

// NewResourceTokenDraft validates Core resource claims without signing them.
func NewResourceTokenDraft(claims ResourceTokenClaims) (TokenDraft[ResourceTokenClaims], error) {
	if err := validateResourceClaims(claims, time.Unix(claims.IssuedAt, 0), false); err != nil {
		return TokenDraft[ResourceTokenClaims]{}, err
	}
	return newTokenDraft[ResourceTokenClaims](ResourceTokenType, claims)
}

// NewAuthTokenDraft validates Core auth claims without signing them.
func NewAuthTokenDraft(claims AuthTokenClaims) (TokenDraft[AuthTokenClaims], error) {
	if err := validateAuthClaims(claims, time.Unix(claims.IssuedAt, 0), false); err != nil {
		return TokenDraft[AuthTokenClaims]{}, err
	}
	return newTokenDraft[AuthTokenClaims](AuthTokenType, claims)
}

func newTokenDraft[C tokenDraftClaims](tokenType string, claims C) (TokenDraft[C], error) {
	payload, err := json.Marshal(claims)
	if err != nil {
		return TokenDraft[C]{}, fmt.Errorf("aauth: marshal token claims: %w", err)
	}
	draft := TokenDraft[C]{tokenType: tokenType, base: append([]byte(nil), payload...), extensions: make(map[string]json.RawMessage)}
	draft.seal = draft.sealValue()
	return draft, nil
}

// Valid reports whether the draft still identifies its exact composed claims.
func (draft TokenDraft[C]) Valid() bool {
	return draft.seal != [sha256.Size]byte{} && draft.seal == draft.sealValue()
}

// WithAuthorizationMembers returns a new draft containing one complete
// recognized companion member set. Existing Core or companion members cannot
// be replaced. Companion packages should expose typed wrappers around this
// low-level composition seam.
func (draft TokenDraft[C]) WithAuthorizationMembers(extension map[string]json.RawMessage) (TokenDraft[C], error) {
	if !draft.Valid() {
		return TokenDraft[C]{}, errors.New("aauth: token draft is invalid")
	}
	if len(extension) == 0 {
		return TokenDraft[C]{}, errors.New("aauth: authorization member set is empty")
	}
	var baseMembers map[string]json.RawMessage
	if err := json.Unmarshal(draft.base, &baseMembers); err != nil {
		return TokenDraft[C]{}, errors.New("aauth: token draft base claims are invalid")
	}
	next := TokenDraft[C]{
		tokenType: draft.tokenType, base: append([]byte(nil), draft.base...),
		extensions: cloneRawMembers(draft.extensions),
	}
	for name, raw := range extension {
		if !isCurrentAuthorizationMember(name) || !json.Valid(raw) {
			return TokenDraft[C]{}, errors.New("aauth: authorization member is invalid")
		}
		if _, exists := baseMembers[name]; exists {
			return TokenDraft[C]{}, fmt.Errorf("aauth: token member %q is already present", name)
		}
		if _, exists := next.extensions[name]; exists {
			return TokenDraft[C]{}, fmt.Errorf("aauth: token member %q is already present", name)
		}
		next.extensions[name] = append(json.RawMessage(nil), raw...)
	}
	payload, err := next.payload()
	if err != nil {
		return TokenDraft[C]{}, err
	}
	if err := validateAuthorizationMembers(payload, next.tokenType); err != nil {
		return TokenDraft[C]{}, err
	}
	next.seal = next.sealValue()
	return next, nil
}

func isCurrentAuthorizationMember(name string) bool {
	for _, rule := range coreAuthorizationMemberCatalog {
		if rule.name == name {
			return true
		}
	}
	return false
}

// Mint signs the exact composed payload once with the issuer's key.
func (draft TokenDraft[C]) Mint(key jose.SigningKey) (string, error) {
	if !draft.Valid() {
		return "", errors.New("aauth: token draft is invalid")
	}
	payload, err := draft.payload()
	if err != nil {
		return "", err
	}
	if err := validateAuthorizationMembers(payload, draft.tokenType); err != nil {
		return "", err
	}
	return jose.SignCompact(key, jose.Header{
		Algorithm: jose.Ed25519Algorithm, Type: draft.tokenType, KeyID: key.ID(),
	}, payload)
}

func (draft TokenDraft[C]) sealValue() [sha256.Size]byte {
	if draft.tokenType == "" || len(draft.base) == 0 || draft.extensions == nil {
		return [sha256.Size]byte{}
	}
	payload, err := draft.payload()
	if err != nil {
		return [sha256.Size]byte{}
	}
	material := append([]byte("gitlab.com/sidecat-dev/aauth-go/token-draft/v1\x00"+draft.tokenType+"\x00"), payload...)
	return sha256.Sum256(material)
}

func (draft TokenDraft[C]) payload() ([]byte, error) {
	if !json.Valid(draft.base) || len(draft.base) < 2 || draft.base[0] != '{' || draft.base[len(draft.base)-1] != '}' {
		return nil, errors.New("aauth: token draft base claims are invalid")
	}
	if len(draft.extensions) == 0 {
		return append([]byte(nil), draft.base...), nil
	}
	names := make([]string, 0, len(draft.extensions))
	for name := range draft.extensions {
		names = append(names, name)
	}
	sort.Strings(names)
	payload := append([]byte(nil), draft.base[:len(draft.base)-1]...)
	if len(draft.base) > 2 {
		payload = append(payload, ',')
	}
	for index, name := range names {
		if index != 0 {
			payload = append(payload, ',')
		}
		encodedName, _ := json.Marshal(name)
		payload = append(payload, encodedName...)
		payload = append(payload, ':')
		payload = append(payload, draft.extensions[name]...)
	}
	payload = append(payload, '}')
	if !json.Valid(payload) {
		return nil, errors.New("aauth: composed token payload is invalid")
	}
	return payload, nil
}

func cloneRawMembers(members map[string]json.RawMessage) map[string]json.RawMessage {
	cloned := make(map[string]json.RawMessage, len(members))
	for name, raw := range members {
		cloned[name] = append(json.RawMessage(nil), raw...)
	}
	return cloned
}
