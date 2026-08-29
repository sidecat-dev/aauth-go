package r3

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/jose"
)

// DocumentReference is invalid-zero, copy-safe evidence for one exact R3
// document and its content-addressed HTTPS location. When CoreEvidenceID is
// nonzero, the document was also verified against that exact token result.
type DocumentReference struct {
	uri      string
	digest   string
	exact    []byte
	document Document
	coreID   aauth.EvidenceID
	seal     [sha256.Size]byte
}

// NewDocumentReference validates exact R3 bytes and constructs the reference a
// resource may retain before issuing a resource token.
func NewDocumentReference(uri string, exact []byte) (DocumentReference, error) {
	var reference DocumentReference
	if err := validateDocumentURI(uri); err != nil {
		return reference, err
	}
	document, err := ParseDocument(exact)
	if err != nil {
		return reference, err
	}
	reference = DocumentReference{
		uri:      uri,
		digest:   S256(exact),
		exact:    append([]byte(nil), exact...),
		document: cloneDocument(document),
	}
	reference.seal = reference.sealValue()
	return reference, nil
}

// VerifyDocument binds exact fetched bytes to one previously validated R3
// token result.
func VerifyDocument(token TokenResult, exact []byte) (DocumentReference, error) {
	if !token.Valid() {
		return DocumentReference{}, errors.New("aauth: R3 token result is invalid")
	}
	reference, err := NewDocumentReference(token.URI(), exact)
	if err != nil {
		return DocumentReference{}, err
	}
	if reference.digest != token.Digest() {
		return DocumentReference{}, &ValidationError{
			Member: "r3_s256",
			Cause:  errors.New("does not match the exact fetched document"),
		}
	}
	reference.coreID = token.CoreEvidenceID()
	reference.seal = reference.sealValue()
	return reference, nil
}

// Valid reports whether the reference retains self-consistent exact bytes.
func (reference DocumentReference) Valid() bool {
	return reference.seal != [sha256.Size]byte{} && reference.seal == reference.sealValue()
}

// URI returns the exact HTTPS document location.
func (reference DocumentReference) URI() string {
	if !reference.Valid() {
		return ""
	}
	return reference.uri
}

// Digest returns the unpadded base64url SHA-256 identity.
func (reference DocumentReference) Digest() string {
	if !reference.Valid() {
		return ""
	}
	return reference.digest
}

// ExactBytes returns an independent copy of the verified serialization.
func (reference DocumentReference) ExactBytes() []byte {
	if !reference.Valid() {
		return nil
	}
	return append([]byte(nil), reference.exact...)
}

// Document returns an independent parsed projection.
func (reference DocumentReference) Document() (Document, error) {
	if !reference.Valid() {
		return Document{}, errors.New("aauth: R3 document reference is invalid")
	}
	return cloneDocument(reference.document), nil
}

// CoreEvidenceID identifies the resource token against which fetched bytes
// were verified. A resource-created pre-issuance reference returns zero.
func (reference DocumentReference) CoreEvidenceID() aauth.EvidenceID {
	if !reference.Valid() {
		return aauth.EvidenceID{}
	}
	return reference.coreID
}

// AuthorizationDecision partitions one policy result into operations granted
// directly and operations that require a proposal for each call. PerCall is
// nil when no operation requires per-call approval.
type AuthorizationDecision struct {
	Granted OperationSet  `json:"r3_granted"`
	PerCall *OperationSet `json:"r3_per_call,omitempty"`
}

// AuthorizationGrant is invalid-zero evidence that every directly granted or
// per-call operation belongs to one exact verified R3 document and that the two
// sets are disjoint.
type AuthorizationGrant struct {
	reference DocumentReference
	decision  AuthorizationDecision
	seal      [sha256.Size]byte
}

func NewAuthorizationGrant(reference DocumentReference, decision AuthorizationDecision) (AuthorizationGrant, error) {
	if !reference.Valid() {
		return AuthorizationGrant{}, errors.New("aauth: R3 document reference is invalid")
	}
	if reference.CoreEvidenceID().String() == "" {
		return AuthorizationGrant{}, errors.New("aauth: R3 authorization grant requires a document verified against Core token evidence")
	}
	if err := decision.Granted.Validate(); err != nil {
		return AuthorizationGrant{}, err
	}
	document, _ := reference.Document()
	if !document.OperationSet().ContainsSet(decision.Granted) {
		return AuthorizationGrant{}, errors.New("aauth: R3 authorization grant contains an operation outside the exact document")
	}
	cloned := AuthorizationDecision{Granted: decision.Granted.Clone()}
	if decision.PerCall != nil {
		perCall := decision.PerCall.Clone()
		if err := perCall.Validate(); err != nil {
			return AuthorizationGrant{}, err
		}
		if perCall.Vocabulary != cloned.Granted.Vocabulary {
			return AuthorizationGrant{}, errors.New("aauth: R3 direct and per-call vocabularies differ")
		}
		if !document.OperationSet().ContainsSet(perCall) {
			return AuthorizationGrant{}, errors.New("aauth: R3 per-call grant contains an operation outside the exact document")
		}
		for _, operation := range perCall.Operations {
			if cloned.Granted.Contains(operation) {
				return AuthorizationGrant{}, errors.New("aauth: R3 operation cannot be both direct and per-call")
			}
		}
		cloned.PerCall = &perCall
	}
	grant := AuthorizationGrant{reference: reference, decision: cloned}
	grant.seal = grant.sealValue()
	return grant, nil
}

// Valid reports whether the grant retains one self-consistent verified
// document and policy partition.
func (grant AuthorizationGrant) Valid() bool {
	return grant.seal != [sha256.Size]byte{} && grant.seal == grant.sealValue()
}

// Granted returns an independent operation-set projection.
func (grant AuthorizationGrant) Granted() (OperationSet, error) {
	if !grant.Valid() {
		return OperationSet{}, errors.New("aauth: R3 authorization grant is invalid")
	}
	return grant.decision.Granted.Clone(), nil
}

// PerCall returns an independent per-call set and reports whether one exists.
func (grant AuthorizationGrant) PerCall() (OperationSet, bool) {
	if !grant.Valid() || grant.decision.PerCall == nil {
		return OperationSet{}, false
	}
	return grant.decision.PerCall.Clone(), true
}

// Reference returns the exact document evidence on which the grant was based.
func (grant AuthorizationGrant) Reference() (DocumentReference, error) {
	if !grant.Valid() {
		return DocumentReference{}, errors.New("aauth: R3 authorization grant is invalid")
	}
	return grant.reference, nil
}

// MintResourceToken validates the Core claims and binds the exact R3 document
// reference into the resulting resource token.
func MintResourceToken(key jose.SigningKey, claims aauth.ResourceTokenClaims, reference DocumentReference) (string, error) {
	draft, err := aauth.NewResourceTokenDraft(claims)
	if err != nil {
		return "", err
	}
	draft, err = BindResourceToken(draft, reference)
	if err != nil {
		return "", err
	}
	return draft.Mint(key)
}

// BindResourceToken adds one exact R3 document reference to a composable Core
// resource-token draft.
func BindResourceToken(
	draft aauth.TokenDraft[aauth.ResourceTokenClaims],
	reference DocumentReference,
) (aauth.TokenDraft[aauth.ResourceTokenClaims], error) {
	if !reference.Valid() {
		return aauth.TokenDraft[aauth.ResourceTokenClaims]{}, errors.New("aauth: R3 document reference is invalid")
	}
	return draft.WithAuthorizationMembers(map[string]json.RawMessage{
		"r3_uri":  mustJSON(reference.uri),
		"r3_s256": mustJSON(reference.digest),
	})
}

// MintAuthToken validates the Core claims and carries one exact R3 policy
// partition.
func MintAuthToken(key jose.SigningKey, claims aauth.AuthTokenClaims, grant AuthorizationGrant) (string, error) {
	draft, err := aauth.NewAuthTokenDraft(claims)
	if err != nil {
		return "", err
	}
	draft, err = BindAuthToken(draft, grant)
	if err != nil {
		return "", err
	}
	return draft.Mint(key)
}

// BindAuthToken adds one exact R3 policy partition to a composable Core
// auth-token draft.
func BindAuthToken(
	draft aauth.TokenDraft[aauth.AuthTokenClaims],
	grant AuthorizationGrant,
) (aauth.TokenDraft[aauth.AuthTokenClaims], error) {
	if !grant.Valid() {
		return aauth.TokenDraft[aauth.AuthTokenClaims]{}, errors.New("aauth: R3 authorization grant is invalid")
	}
	granted, _ := grant.Granted()
	grantedJSON, err := json.Marshal(granted)
	if err != nil {
		return aauth.TokenDraft[aauth.AuthTokenClaims]{}, err
	}
	members := map[string]json.RawMessage{
		"r3_uri":     mustJSON(grant.reference.uri),
		"r3_s256":    mustJSON(grant.reference.digest),
		"r3_granted": grantedJSON,
	}
	if perCall, present := grant.PerCall(); present {
		perCallJSON, err := json.Marshal(perCall)
		if err != nil {
			return aauth.TokenDraft[aauth.AuthTokenClaims]{}, err
		}
		members["r3_per_call"] = perCallJSON
	}
	return draft.WithAuthorizationMembers(members)
}

// ValidateAuthorizationGrant binds an auth-token policy partition to the
// preceding resource token and refuses any operation outside the exact set the
// agent requested.
func ValidateAuthorizationGrant(resource TokenResult, auth TokenResult, requested OperationSet) error {
	if !resource.Valid() || !auth.Valid() {
		return errors.New("aauth: R3 token result is invalid")
	}
	if resource.URI() != auth.URI() || resource.Digest() != auth.Digest() {
		return errors.New("aauth: R3 auth-token reference does not match the resource token")
	}
	if err := requested.Validate(); err != nil {
		return fmt.Errorf("aauth: requested R3 operations: %w", err)
	}
	granted, present := auth.Granted()
	if !present || granted.Vocabulary != requested.Vocabulary || !requested.ContainsSet(granted) {
		return errors.New("aauth: R3 auth token grants an operation outside the agent request")
	}
	if perCall, present := auth.PerCall(); present {
		if perCall.Vocabulary != requested.Vocabulary || !requested.ContainsSet(perCall) {
			return errors.New("aauth: R3 auth token marks an operation outside the agent request as per-call")
		}
	}
	return nil
}

func mustJSON(value string) json.RawMessage {
	encoded, _ := json.Marshal(value)
	return encoded
}

func validateDocumentURI(value string) error {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
		return errors.New("aauth: R3 document URI must be absolute HTTPS without userinfo or fragment")
	}
	return nil
}

func cloneDocument(document Document) Document {
	cloned := document
	cloned.Operations = cloneRawMessages(document.Operations)
	if document.Parameters != nil {
		cloned.Parameters = make(map[string]json.RawMessage, len(document.Parameters))
		for name, value := range document.Parameters {
			cloned.Parameters[name] = append(json.RawMessage(nil), value...)
		}
	}
	if document.Display != nil {
		display := *document.Display
		cloned.Display = &display
	}
	return cloned
}

func (reference DocumentReference) sealValue() [sha256.Size]byte {
	if reference.uri == "" || reference.digest == "" || len(reference.exact) == 0 || S256(reference.exact) != reference.digest {
		return [sha256.Size]byte{}
	}
	material, err := json.Marshal(struct {
		Domain string `json:"domain"`
		URI    string `json:"uri"`
		Digest string `json:"digest"`
		Exact  []byte `json:"exact"`
		CoreID string `json:"core_id,omitempty"`
	}{"gitlab.com/sidecat-dev/aauth-go/r3-document-reference/v1", reference.uri, reference.digest, reference.exact, reference.coreID.String()})
	if err != nil {
		return [sha256.Size]byte{}
	}
	return sha256.Sum256(material)
}

func (grant AuthorizationGrant) sealValue() [sha256.Size]byte {
	if !grant.reference.Valid() || grant.decision.Granted.Validate() != nil {
		return [sha256.Size]byte{}
	}
	material, err := json.Marshal(struct {
		Domain    string                `json:"domain"`
		Reference string                `json:"reference"`
		Decision  AuthorizationDecision `json:"decision"`
	}{"gitlab.com/sidecat-dev/aauth-go/r3-authorization-grant/v1", grant.reference.digest, grant.decision})
	if err != nil {
		return [sha256.Size]byte{}
	}
	return sha256.Sum256(material)
}
