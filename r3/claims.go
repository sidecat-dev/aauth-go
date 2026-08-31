package r3

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"unicode/utf8"
)

// Reference identifies exact R3 artifact bytes at an HTTPS URI.
type Reference struct {
	uri    string
	digest string
}

// NewReference constructs a validated R3 artifact reference.
func NewReference(uri, digest string) (Reference, error) {
	reference := Reference{uri: uri, digest: digest}
	if err := reference.validate(); err != nil {
		return Reference{}, err
	}
	return reference, nil
}

func (reference Reference) validate() error {
	if !utf8.ValidString(reference.uri) {
		return errors.New("r3: reference URI must be valid UTF-8")
	}
	parsed, err := url.Parse(reference.uri)
	if err != nil {
		return fmt.Errorf("r3: invalid reference URI: %w", err)
	}
	if reference.uri == "" || !parsed.IsAbs() || !strings.EqualFold(parsed.Scheme, "https") ||
		parsed.Host == "" || parsed.Hostname() == "" || parsed.Opaque != "" {
		return errors.New("r3: reference URI must be an absolute HTTPS URI")
	}
	if parsed.User != nil {
		return errors.New("r3: reference URI must not contain userinfo")
	}
	if strings.Contains(reference.uri, "#") || parsed.Fragment != "" || parsed.RawFragment != "" {
		return errors.New("r3: reference URI must not contain a fragment")
	}

	digestBytes, err := base64.RawURLEncoding.DecodeString(reference.digest)
	if err != nil {
		return fmt.Errorf("r3: invalid reference digest: %w", err)
	}
	if len(digestBytes) != 32 {
		return errors.New("r3: reference digest must encode 32 bytes")
	}
	if base64.RawURLEncoding.EncodeToString(digestBytes) != reference.digest {
		return errors.New("r3: reference digest is not canonical unpadded base64url")
	}
	return nil
}

// URI returns the absolute HTTPS artifact URI.
func (reference Reference) URI() string { return reference.uri }

// Digest returns the canonical unpadded base64url SHA-256 digest.
func (reference Reference) Digest() string { return reference.digest }

// MarshalJSON rejects a context-free nested representation. R3 carries a
// reference as sibling r3_uri and r3_s256 claims.
func (Reference) MarshalJSON() ([]byte, error) {
	return nil, errors.New("r3: Reference has no context-free JSON form; encode r3_uri and r3_s256 as sibling claims")
}

// UnmarshalJSON rejects a context-free nested representation.
func (*Reference) UnmarshalJSON([]byte) error {
	return errors.New("r3: Reference has no context-free JSON form; use NewReference with r3_uri and r3_s256")
}

// GrantedOperations is the vocabulary-tagged zero-or-more operation shape
// carried by r3_granted and r3_per_call claims.
type GrantedOperations struct{ value operationValue }

// NewGrantedOperations constructs a claim set. The explicit vocabulary keeps
// an empty grant from becoming interchangeable with another vocabulary.
func NewGrantedOperations(vocabulary Vocabulary, operations ...Operation) (GrantedOperations, error) {
	if err := vocabulary.validate(); err != nil {
		return GrantedOperations{}, err
	}
	raw := make([]json.RawMessage, len(operations))
	for index, operation := range operations {
		if operation.value.vocabulary.identity != vocabulary.identity || operation.value.vocabulary.uri != vocabulary.uri {
			return GrantedOperations{}, fmt.Errorf("r3: granted operation %d uses a different vocabulary registration", index)
		}
		if len(operation.value.raw) != 1 {
			return GrantedOperations{}, fmt.Errorf("r3: granted operation %d is not singular", index)
		}
		raw[index] = operation.value.raw[0]
	}
	value, err := newOperationValue(vocabulary, raw, setUseGrant)
	if err != nil {
		return GrantedOperations{}, err
	}
	return GrantedOperations{value: value}, nil
}

func newParsedGrantedOperations(vocabulary Vocabulary, raw []json.RawMessage) (GrantedOperations, error) {
	value, err := newOperationValue(vocabulary, raw, setUseGrant)
	if err != nil {
		return GrantedOperations{}, err
	}
	return GrantedOperations{value: value}, nil
}

func (granted GrantedOperations) clone() GrantedOperations {
	return GrantedOperations{value: granted.value.clone()}
}

// Vocabulary returns the exact vocabulary URI even for an empty grant.
func (granted GrantedOperations) Vocabulary() VocabularyURI { return granted.value.vocabulary.uri }

// Operations returns validated individual operations in retained wire order.
func (granted GrantedOperations) Operations() []Operation {
	if granted.value.validate() != nil {
		return nil
	}
	operations := make([]Operation, len(granted.value.raw))
	for index, raw := range granted.value.raw {
		operation, err := NewOperation(granted.value.vocabulary, raw)
		if err != nil {
			return nil
		}
		operations[index] = operation
	}
	return operations
}

// Equal reports vocabulary-semantic equality.
func (granted GrantedOperations) Equal(other GrantedOperations) (bool, error) {
	if err := compatibleOperations(granted.value, other.value); err != nil {
		return false, err
	}
	return granted.value.vocabulary.equal(granted.value, other.value)
}

// IsSubsetOf reports whether the claim is contained by a document set.
func (granted GrantedOperations) IsSubsetOf(operationSet OperationSet) (bool, error) {
	if err := compatibleOperations(granted.value, operationSet.value); err != nil {
		return false, err
	}
	return granted.value.vocabulary.subset(granted.value, operationSet.value)
}

// Disjoint reports whether two claim sets authorize no overlapping access.
func (granted GrantedOperations) Disjoint(other GrantedOperations) (bool, error) {
	if err := compatibleOperations(granted.value, other.value); err != nil {
		return false, err
	}
	return granted.value.vocabulary.disjoint(granted.value, other.value)
}

// Contains reports whether the claim covers one operation.
func (granted GrantedOperations) Contains(operation Operation) (bool, error) {
	if err := compatibleOperations(granted.value, operation.value); err != nil {
		return false, err
	}
	return granted.value.vocabulary.subset(operation.value, granted.value)
}

// MarshalJSON emits the shared vocabulary/operations claim shape, including
// an explicit empty array.
func (granted GrantedOperations) MarshalJSON() ([]byte, error) {
	if err := granted.value.validate(); err != nil {
		return nil, err
	}
	return marshalOperationEnvelope(granted.value)
}

// UnmarshalJSON refuses parsing without an explicit vocabulary registry.
func (*GrantedOperations) UnmarshalJSON([]byte) error {
	return errors.New("r3: GrantedOperations requires a registry; use Registry.ParseGrantedOperations")
}

// ParseGrantedOperations parses a claim through the registry named by its
// own vocabulary URI.
func (registry Registry) ParseGrantedOperations(source []byte) (GrantedOperations, error) {
	uri, raw, err := parseOperationEnvelope(source)
	if err != nil {
		return GrantedOperations{}, err
	}
	vocabulary, ok := registry.vocabularies[uri]
	if !ok {
		return GrantedOperations{}, fmt.Errorf("r3: vocabulary %q is not registered", uri)
	}
	return newParsedGrantedOperations(vocabulary, raw)
}

// Grant is a direct grant proven not to exceed one R3 document.
type Grant struct {
	granted GrantedOperations
	proven  bool
}

// Authorization is a class-document authorization split into disjoint direct
// and per-call operation sets, both proven not to exceed the document.
type Authorization struct {
	granted GrantedOperations
	perCall GrantedOperations
	proven  bool
}

// AuthTokenOperations is the validated operation-claim shape from a signed
// R3 Auth token. Artifact classification remains a separate custody fact.
type AuthTokenOperations struct {
	granted        GrantedOperations
	perCall        GrantedOperations
	perCallPresent bool
}

// OperationAccess is the authorization an R3 Auth token gives one operation.
type OperationAccess uint8

const (
	// OperationAccessDenied means the operation appears in neither claim set.
	OperationAccessDenied OperationAccess = iota
	// OperationAccessGranted means the operation may execute directly.
	OperationAccessGranted
	// OperationAccessPerCall means the operation requires an exact proposal.
	OperationAccessPerCall
)

// AccessFor classifies one registered operation against the token's disjoint
// direct and per-call claim sets.
func (operations AuthTokenOperations) AccessFor(operation Operation) (OperationAccess, error) {
	granted, err := operations.granted.Contains(operation)
	if err != nil {
		return OperationAccessDenied, err
	}
	perCall, err := operations.perCall.Contains(operation)
	if err != nil {
		return OperationAccessDenied, err
	}
	if granted && perCall {
		return OperationAccessDenied, errors.New("r3: operation appears in both direct and per-call authorization")
	}
	if granted {
		return OperationAccessGranted, nil
	}
	if perCall {
		return OperationAccessPerCall, nil
	}
	return OperationAccessDenied, nil
}

func (operations AuthTokenOperations) GrantedOperations() GrantedOperations {
	return operations.granted.clone()
}

func (operations AuthTokenOperations) PerCallOperations() GrantedOperations {
	return operations.perCall.clone()
}

func (operations AuthTokenOperations) PerCallClaimPresent() bool {
	return operations.perCallPresent
}

// NewAuthorization proves the direct and per-call sets against one class
// document and against one another.
func NewAuthorization(granted, perCall GrantedOperations, document Document) (Authorization, error) {
	if err := compatibleOperations(granted.value, document.operationSet.value); err != nil {
		return Authorization{}, fmt.Errorf("r3: direct authorization: %w", err)
	}
	if err := compatibleOperations(perCall.value, document.operationSet.value); err != nil {
		return Authorization{}, fmt.Errorf("r3: per-call authorization: %w", err)
	}
	directSubset, err := granted.IsSubsetOf(document.operationSet)
	if err != nil {
		return Authorization{}, err
	}
	if !directSubset {
		return Authorization{}, errors.New("r3: direct authorization exceeds document operation set")
	}
	perCallSubset, err := perCall.IsSubsetOf(document.operationSet)
	if err != nil {
		return Authorization{}, err
	}
	if !perCallSubset {
		return Authorization{}, errors.New("r3: per-call authorization exceeds document operation set")
	}
	disjoint, err := granted.Disjoint(perCall)
	if err != nil {
		return Authorization{}, err
	}
	if !disjoint {
		return Authorization{}, errors.New("r3: direct and per-call authorization overlap")
	}
	return Authorization{granted: granted.clone(), perCall: perCall.clone(), proven: true}, nil
}

func (authorization Authorization) GrantedOperations() GrantedOperations {
	return authorization.granted.clone()
}

func (authorization Authorization) PerCallOperations() GrantedOperations {
	return authorization.perCall.clone()
}

// NewGrant proves a direct grant against a document.
func NewGrant(granted GrantedOperations, document Document) (Grant, error) {
	if err := compatibleOperations(granted.value, document.operationSet.value); err != nil {
		return Grant{}, err
	}
	subset, err := granted.IsSubsetOf(document.operationSet)
	if err != nil {
		return Grant{}, err
	}
	if !subset {
		return Grant{}, errors.New("r3: grant exceeds document operation set")
	}
	return Grant{granted: granted.clone(), proven: true}, nil
}

// ParseGrant parses granted operations through registry and proves them
// against document.
func (registry Registry) ParseGrant(source []byte, document Document) (Grant, error) {
	granted, err := registry.ParseGrantedOperations(source)
	if err != nil {
		return Grant{}, err
	}
	return NewGrant(granted, document)
}

func (grant Grant) GrantedOperations() GrantedOperations { return grant.granted.clone() }

func (grant Grant) MarshalJSON() ([]byte, error) {
	if !grant.proven {
		return nil, errors.New("r3: cannot marshal an unproven Grant; use NewGrant or Registry.ParseGrant")
	}
	return json.Marshal(grant.granted)
}

func (*Grant) UnmarshalJSON([]byte) error {
	return errors.New("r3: Grant requires registry and document context; use Registry.ParseGrant")
}
