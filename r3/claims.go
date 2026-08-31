package r3

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"unicode/utf8"
)

// Reference identifies exact R3 document bytes at an HTTPS URI.
type Reference struct {
	uri    string
	digest string
}

// NewReference constructs a validated R3 document reference.
func NewReference(uri, digest string) (Reference, error) {
	reference := Reference{uri: uri, digest: digest}
	if err := reference.validate(); err != nil {
		return Reference{}, err
	}
	return reference, nil
}

func (r Reference) validate() error {
	if !utf8.ValidString(r.uri) {
		return fmt.Errorf("r3: reference URI must be valid UTF-8")
	}
	parsed, err := url.Parse(r.uri)
	if err != nil {
		return fmt.Errorf("r3: invalid reference URI: %w", err)
	}
	if r.uri == "" || !parsed.IsAbs() || !strings.EqualFold(parsed.Scheme, "https") || parsed.Host == "" || parsed.Hostname() == "" || parsed.Opaque != "" {
		return fmt.Errorf("r3: reference URI must be an absolute HTTPS URI")
	}
	if parsed.User != nil {
		return fmt.Errorf("r3: reference URI must not contain userinfo")
	}
	if strings.Contains(r.uri, "#") || parsed.Fragment != "" || parsed.RawFragment != "" {
		return fmt.Errorf("r3: reference URI must not contain a fragment")
	}

	digestBytes, err := base64.RawURLEncoding.DecodeString(r.digest)
	if err != nil {
		return fmt.Errorf("r3: invalid reference digest: %w", err)
	}
	if len(digestBytes) != 32 {
		return fmt.Errorf("r3: reference digest must encode 32 bytes")
	}
	if base64.RawURLEncoding.EncodeToString(digestBytes) != r.digest {
		return fmt.Errorf("r3: reference digest is not canonical unpadded base64url")
	}
	return nil
}

// URI returns the absolute HTTPS R3 document URI.
func (r Reference) URI() string { return r.uri }

// Digest returns the canonical unpadded base64url SHA-256 digest.
func (r Reference) Digest() string { return r.digest }

// ParseReferencedDocument validates reference, binds it to exactBytes by its
// digest, and only then parses the bytes as an R3 document. It performs no
// fetching.
func ParseReferencedDocument(reference Reference, exactBytes []byte) (Document, error) {
	if err := reference.validate(); err != nil {
		return Document{}, fmt.Errorf("r3: invalid reference: %w", err)
	}
	if Digest(exactBytes) != reference.digest {
		return Document{}, fmt.Errorf("r3: referenced document digest mismatch")
	}
	return ParseDocument(exactBytes)
}

// MarshalJSON rejects a context-free nested representation. R3 carries a
// Reference as the sibling claims r3_uri and r3_s256.
func (r Reference) MarshalJSON() ([]byte, error) {
	return nil, fmt.Errorf("r3: Reference has no context-free JSON form; encode r3_uri and r3_s256 as sibling claims")
}

// UnmarshalJSON rejects a context-free nested representation. Construct a
// Reference from its sibling claims with NewReference.
func (r *Reference) UnmarshalJSON(data []byte) error {
	return fmt.Errorf("r3: Reference has no context-free JSON form; use NewReference with r3_uri and r3_s256")
}

// GrantedOperations is the zero-or-more MCP operation-set shape carried by an
// r3_granted claim. Unlike request and document operation sets, an empty claim
// is valid and means that no operation was granted.
type GrantedOperations struct {
	operations []MCPOperation
}

// NewGrantedOperations constructs a validated granted-operation claim value.
func NewGrantedOperations(operations ...MCPOperation) (GrantedOperations, error) {
	granted := GrantedOperations{operations: append([]MCPOperation(nil), operations...)}
	if err := granted.validate(); err != nil {
		return GrantedOperations{}, err
	}
	return granted, nil
}

func (g GrantedOperations) validate() error {
	seen := make(map[string]struct{}, len(g.operations))
	for i, operation := range g.operations {
		if err := operation.validate(); err != nil {
			return fmt.Errorf("r3: granted operation %d: %w", i, err)
		}
		if _, duplicate := seen[operation.tool]; duplicate {
			return fmt.Errorf("r3: duplicate granted MCP tool %q", operation.tool)
		}
		seen[operation.tool] = struct{}{}
	}
	return nil
}

func (g GrantedOperations) clone() GrantedOperations {
	return GrantedOperations{operations: g.Operations()}
}

// Operations returns a copy of the retained granted-operation sequence.
func (g GrantedOperations) Operations() []MCPOperation {
	return append([]MCPOperation(nil), g.operations...)
}

// Equal reports order-insensitive semantic equality.
func (g GrantedOperations) Equal(other GrantedOperations) bool {
	if g.validate() != nil || other.validate() != nil || len(g.operations) != len(other.operations) {
		return false
	}
	return g.IsSubsetOf(other)
}

// IsSubsetOf reports whether every operation in g occurs in other.
func (g GrantedOperations) IsSubsetOf(other GrantedOperations) bool {
	if g.validate() != nil || other.validate() != nil {
		return false
	}
	available := make(map[string]struct{}, len(other.operations))
	for _, operation := range other.operations {
		available[operation.tool] = struct{}{}
	}
	for _, operation := range g.operations {
		if _, ok := available[operation.tool]; !ok {
			return false
		}
	}
	return true
}

// Contains reports whether operation is one of the granted MCP operations.
func (g GrantedOperations) Contains(operation MCPOperation) bool {
	if g.validate() != nil || operation.validate() != nil {
		return false
	}
	for _, candidate := range g.operations {
		if candidate.tool == operation.tool {
			return true
		}
	}
	return false
}

func (g GrantedOperations) isSubsetOf(operationSet MCPOperationSet) bool {
	if g.validate() != nil || operationSet.validate() != nil {
		return false
	}
	available := make(map[string]struct{}, len(operationSet.operations))
	for _, operation := range operationSet.operations {
		available[operation.tool] = struct{}{}
	}
	for _, operation := range g.operations {
		if _, ok := available[operation.tool]; !ok {
			return false
		}
	}
	return true
}

// MarshalJSON emits the shared MCP operation-set shape, including an explicit
// empty array for an empty grant.
func (g GrantedOperations) MarshalJSON() ([]byte, error) {
	if err := g.validate(); err != nil {
		return nil, err
	}
	operations := g.Operations()
	if operations == nil {
		operations = []MCPOperation{}
	}
	return json.Marshal(struct {
		Vocabulary string         `json:"vocabulary"`
		Operations []MCPOperation `json:"operations"`
	}{
		Vocabulary: MCPVocabulary,
		Operations: operations,
	})
}

// UnmarshalJSON strictly parses the shared MCP operation-set shape while
// permitting an empty operations array.
func (g *GrantedOperations) UnmarshalJSON(data []byte) error {
	granted, err := parseGrantedOperations(data)
	if err != nil {
		return err
	}
	*g = granted
	return nil
}

func parseGrantedOperations(data []byte) (GrantedOperations, error) {
	var vocabularyRaw, operationsRaw json.RawMessage
	seen, err := decodeStrictObject(data, map[string]func(json.RawMessage) error{
		"vocabulary": func(raw json.RawMessage) error {
			vocabularyRaw = append(vocabularyRaw[:0], raw...)
			return nil
		},
		"operations": func(raw json.RawMessage) error {
			operationsRaw = append(operationsRaw[:0], raw...)
			return nil
		},
	})
	if err != nil {
		return GrantedOperations{}, fmt.Errorf("r3: invalid granted operations: %w", err)
	}
	if _, ok := seen["vocabulary"]; !ok {
		return GrantedOperations{}, fmt.Errorf("r3: granted operations are missing vocabulary")
	}
	if _, ok := seen["operations"]; !ok {
		return GrantedOperations{}, fmt.Errorf("r3: granted operations are missing operations")
	}
	operations, err := parseMCPOperationsParts(vocabularyRaw, operationsRaw)
	if err != nil {
		return GrantedOperations{}, err
	}
	return NewGrantedOperations(operations...)
}

// Grant is a zero-or-more direct grant proven to be a subset of one R3
// document.
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

// AuthTokenOperations is the validated operation-claim shape from a signed R3
// Auth token. It does not classify the referenced artifact as a class document
// or a per-call proposal; callers must establish that from retained context.
type AuthTokenOperations struct {
	granted        GrantedOperations
	perCall        GrantedOperations
	perCallPresent bool
}

// GrantedOperations returns the signed r3_granted claim.
func (o AuthTokenOperations) GrantedOperations() GrantedOperations { return o.granted.clone() }

// PerCallOperations returns the signed r3_per_call claim, or an empty set when
// that optional claim was absent.
func (o AuthTokenOperations) PerCallOperations() GrantedOperations { return o.perCall.clone() }

// PerCallClaimPresent reports whether the signed token contained the optional
// r3_per_call claim, including an explicitly empty operation set.
func (o AuthTokenOperations) PerCallClaimPresent() bool { return o.perCallPresent }

// NewAuthorization proves the direct and per-call sets against one class
// document. An operation cannot occur in both sets because direct enforcement
// would otherwise silently bypass the requested per-call decision.
func NewAuthorization(granted, perCall GrantedOperations, document Document) (Authorization, error) {
	if err := granted.validate(); err != nil {
		return Authorization{}, fmt.Errorf("r3: invalid direct authorization: %w", err)
	}
	if err := perCall.validate(); err != nil {
		return Authorization{}, fmt.Errorf("r3: invalid per-call authorization: %w", err)
	}
	if err := document.operationSet.validate(); err != nil {
		return Authorization{}, fmt.Errorf("r3: invalid authorization document: %w", err)
	}
	if !granted.isSubsetOf(document.operationSet) {
		return Authorization{}, fmt.Errorf("r3: direct authorization exceeds document operation set")
	}
	if !perCall.isSubsetOf(document.operationSet) {
		return Authorization{}, fmt.Errorf("r3: per-call authorization exceeds document operation set")
	}
	for _, operation := range granted.operations {
		if perCall.Contains(operation) {
			return Authorization{}, fmt.Errorf("r3: MCP tool %q occurs in both direct and per-call authorization", operation.tool)
		}
	}
	return Authorization{granted: granted.clone(), perCall: perCall.clone(), proven: true}, nil
}

// GrantedOperations returns the proven direct-operation claim.
func (a Authorization) GrantedOperations() GrantedOperations { return a.granted.clone() }

// PerCallOperations returns the proven per-call-operation claim.
func (a Authorization) PerCallOperations() GrantedOperations { return a.perCall.clone() }

// NewGrant constructs a direct grant after proving it does not exceed the
// document's exact operation set.
func NewGrant(granted GrantedOperations, document Document) (Grant, error) {
	if err := granted.validate(); err != nil {
		return Grant{}, fmt.Errorf("r3: invalid grant: %w", err)
	}
	if err := document.operationSet.validate(); err != nil {
		return Grant{}, fmt.Errorf("r3: invalid grant document: %w", err)
	}
	if !granted.isSubsetOf(document.operationSet) {
		return Grant{}, fmt.Errorf("r3: grant exceeds document operation set")
	}
	return Grant{granted: granted.clone(), proven: true}, nil
}

// ParseGrant strictly parses granted operations and proves them against
// document.
func ParseGrant(source []byte, document Document) (Grant, error) {
	var granted GrantedOperations
	if err := json.Unmarshal(source, &granted); err != nil {
		return Grant{}, err
	}
	return NewGrant(granted, document)
}

// GrantedOperations returns a copy of the proven claim value.
func (g Grant) GrantedOperations() GrantedOperations {
	return g.granted.clone()
}

// MarshalJSON emits the grant using the shared MCP operation-set shape.
func (g Grant) MarshalJSON() ([]byte, error) {
	if !g.proven {
		return nil, fmt.Errorf("r3: cannot marshal an unproven Grant; use NewGrant or ParseGrant")
	}
	return json.Marshal(g.granted)
}

// UnmarshalJSON always rejects because a Grant cannot be validated without its
// referenced document.
func (g *Grant) UnmarshalJSON(data []byte) error {
	return fmt.Errorf("r3: Grant requires document context; use ParseGrant")
}
