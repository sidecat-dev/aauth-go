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

// DirectGrant is invalid-zero evidence that every granted operation belongs to
// one exact R3 document and no operation remains per-call.
type DirectGrant struct {
	reference DocumentReference
	granted   OperationSet
	seal      [sha256.Size]byte
}

func NewDirectGrant(reference DocumentReference, granted OperationSet) (DirectGrant, error) {
	if !reference.Valid() {
		return DirectGrant{}, errors.New("aauth: R3 document reference is invalid")
	}
	if reference.CoreEvidenceID().String() == "" {
		return DirectGrant{}, errors.New("aauth: R3 direct grant requires a document verified against Core token evidence")
	}
	if err := granted.Validate(); err != nil {
		return DirectGrant{}, err
	}
	document, _ := reference.Document()
	if !document.OperationSet().ContainsSet(granted) {
		return DirectGrant{}, errors.New("aauth: R3 direct grant contains an operation outside the exact document")
	}
	grant := DirectGrant{reference: reference, granted: granted.Clone()}
	grant.seal = grant.sealValue()
	return grant, nil
}

// Valid reports whether the grant retains one self-consistent verified
// document and operation set.
func (grant DirectGrant) Valid() bool {
	return grant.seal != [sha256.Size]byte{} && grant.seal == grant.sealValue()
}

// Granted returns an independent operation-set projection.
func (grant DirectGrant) Granted() (OperationSet, error) {
	if !grant.Valid() {
		return OperationSet{}, errors.New("aauth: R3 direct grant is invalid")
	}
	return grant.granted.Clone(), nil
}

// MintResourceToken validates the Core claims and binds the exact R3 document
// reference into the resulting resource token.
func MintResourceToken(key jose.SigningKey, claims aauth.ResourceTokenClaims, reference DocumentReference) (string, error) {
	if !reference.Valid() {
		return "", errors.New("aauth: R3 document reference is invalid")
	}
	base, err := aauth.MintResourceToken(key, claims)
	if err != nil {
		return "", err
	}
	return extendToken(key, base, map[string]json.RawMessage{
		"r3_uri":  mustJSON(reference.uri),
		"r3_s256": mustJSON(reference.digest),
	})
}

// MintAuthToken validates the Core claims and carries one exact direct grant.
func MintAuthToken(key jose.SigningKey, claims aauth.AuthTokenClaims, grant DirectGrant) (string, error) {
	if !grant.Valid() {
		return "", errors.New("aauth: R3 direct grant is invalid")
	}
	base, err := aauth.MintAuthToken(key, claims)
	if err != nil {
		return "", err
	}
	granted, _ := grant.Granted()
	grantedJSON, err := json.Marshal(granted)
	if err != nil {
		return "", err
	}
	return extendToken(key, base, map[string]json.RawMessage{
		"r3_uri":     mustJSON(grant.reference.uri),
		"r3_s256":    mustJSON(grant.reference.digest),
		"r3_granted": grantedJSON,
	})
}

// ValidateDirectGrant binds an auth-token grant to the preceding resource
// token and the exact operation set the agent requested.
func ValidateDirectGrant(resource TokenResult, auth TokenResult, requested OperationSet) error {
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
	if _, perCall := auth.PerCall(); perCall {
		return errors.New("aauth: R3 auth token is not a direct-only grant")
	}
	return nil
}

func extendToken(key jose.SigningKey, compact string, members map[string]json.RawMessage) (string, error) {
	parsed, err := jose.ParseCompact(compact)
	if err != nil {
		return "", err
	}
	var payload map[string]json.RawMessage
	if err := json.Unmarshal(parsed.Payload(), &payload); err != nil {
		return "", err
	}
	for name, value := range members {
		payload[name] = append(json.RawMessage(nil), value...)
	}
	exact, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	return jose.SignCompact(key, parsed.Header(), exact)
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

func (grant DirectGrant) sealValue() [sha256.Size]byte {
	if !grant.reference.Valid() || grant.granted.Validate() != nil {
		return [sha256.Size]byte{}
	}
	material, err := json.Marshal(struct {
		Domain    string       `json:"domain"`
		Reference string       `json:"reference"`
		Granted   OperationSet `json:"granted"`
	}{"gitlab.com/sidecat-dev/aauth-go/r3-direct-grant/v1", grant.reference.digest, grant.granted})
	if err != nil {
		return [sha256.Size]byte{}
	}
	return sha256.Sum256(material)
}
