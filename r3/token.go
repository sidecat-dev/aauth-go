package r3

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"

	aauth "gitlab.com/sidecat-dev/aauth-go"
)

// ValidationError identifies the R3 member that failed validation.
type ValidationError struct {
	Member string
	Cause  error
}

func (failure *ValidationError) Error() string {
	if failure == nil || failure.Cause == nil {
		return "aauth: R3 token validation failed"
	}
	return fmt.Sprintf("aauth: R3 token member %s: %v", failure.Member, failure.Cause)
}

func (failure *ValidationError) Unwrap() error {
	if failure == nil {
		return nil
	}
	return failure.Cause
}

// TokenResult is invalid-zero sealed validation of the R3 members carried by
// one exact Core token evidence value.
type TokenResult struct {
	coreID    aauth.EvidenceID
	tokenType string
	uri       string
	digest    string
	granted   *OperationSet
	perCall   *OperationSet
	seal      [sha256.Size]byte
}

func ValidateResourceToken(core aauth.VerifiedToken[aauth.ResourceTokenClaims]) (TokenResult, error) {
	return validateToken(core, aauth.ResourceTokenType, false)
}

func ValidateAuthToken(core aauth.VerifiedToken[aauth.AuthTokenClaims]) (TokenResult, error) {
	return validateToken(core, aauth.AuthTokenType, true)
}

func validateToken[T aauth.TokenClaims](core aauth.VerifiedToken[T], tokenType string, auth bool) (TokenResult, error) {
	var result TokenResult
	actual, err := core.Type()
	if err != nil || actual != tokenType {
		if err == nil {
			err = fmt.Errorf("got %q, want %q", actual, tokenType)
		}
		return result, &ValidationError{Member: "typ", Cause: err}
	}
	coreID, err := core.EvidenceID()
	if err != nil {
		return result, err
	}
	members, err := core.AuthorizationMembers()
	if err != nil {
		return result, err
	}
	for name := range members {
		switch name {
		case "r3_uri", "r3_s256", "r3_granted", "r3_per_call":
		default:
			return result, &ValidationError{Member: name, Cause: errors.New("is not validated by R3")}
		}
	}
	uri, err := memberString(members, "r3_uri")
	if err != nil {
		return result, err
	}
	parsedURI, parseErr := url.Parse(uri)
	if parseErr != nil || parsedURI.Scheme != "https" || parsedURI.Host == "" || parsedURI.User != nil || parsedURI.Fragment != "" {
		return result, &ValidationError{Member: "r3_uri", Cause: errors.New("must be an absolute HTTPS URI without userinfo or fragment")}
	}
	digest, err := memberString(members, "r3_s256")
	if err != nil {
		return result, err
	}
	decoded, decodeErr := base64.RawURLEncoding.DecodeString(digest)
	if decodeErr != nil || len(decoded) != sha256.Size {
		return result, &ValidationError{Member: "r3_s256", Cause: errors.New("must be an unpadded base64url SHA-256 digest")}
	}
	result = TokenResult{coreID: coreID, tokenType: tokenType, uri: uri, digest: digest}
	if auth {
		granted, err := memberOperationSet(members, "r3_granted")
		if err != nil {
			return TokenResult{}, err
		}
		result.granted = &granted
		if raw, present := members["r3_per_call"]; present {
			perCall, err := ParseOperationSet(raw)
			if err != nil {
				return TokenResult{}, &ValidationError{Member: "r3_per_call", Cause: err}
			}
			if perCall.Vocabulary != granted.Vocabulary {
				return TokenResult{}, &ValidationError{Member: "r3_per_call", Cause: errors.New("vocabulary differs from r3_granted")}
			}
			for _, operation := range perCall.Operations {
				if granted.Contains(operation) {
					return TokenResult{}, &ValidationError{Member: "r3_per_call", Cause: errors.New("operation is also r3_granted")}
				}
			}
			result.perCall = &perCall
		}
	}
	result.seal = result.sealValue()
	return result, nil
}

func memberString(members map[string]json.RawMessage, name string) (string, error) {
	raw, present := members[name]
	var value string
	if !present || json.Unmarshal(raw, &value) != nil || value == "" {
		return "", &ValidationError{Member: name, Cause: errors.New("must be a non-empty string")}
	}
	return value, nil
}

func memberOperationSet(members map[string]json.RawMessage, name string) (OperationSet, error) {
	raw, present := members[name]
	if !present {
		return OperationSet{}, &ValidationError{Member: name, Cause: errors.New("is required")}
	}
	set, err := ParseOperationSet(raw)
	if err != nil {
		return OperationSet{}, &ValidationError{Member: name, Cause: err}
	}
	return set, nil
}

func (result TokenResult) Valid() bool {
	return result.seal != [sha256.Size]byte{} && result.seal == result.sealValue()
}

func (result TokenResult) CoreEvidenceID() aauth.EvidenceID {
	if !result.Valid() {
		return aauth.EvidenceID{}
	}
	return result.coreID
}
func (result TokenResult) URI() string {
	if !result.Valid() {
		return ""
	}
	return result.uri
}
func (result TokenResult) Digest() string {
	if !result.Valid() {
		return ""
	}
	return result.digest
}
func (result TokenResult) Granted() (OperationSet, bool) {
	if !result.Valid() || result.granted == nil {
		return OperationSet{}, false
	}
	return result.granted.Clone(), true
}
func (result TokenResult) PerCall() (OperationSet, bool) {
	if !result.Valid() || result.perCall == nil {
		return OperationSet{}, false
	}
	return result.perCall.Clone(), true
}

func (result TokenResult) sealValue() [sha256.Size]byte {
	if result.coreID.String() == "" || result.tokenType == "" || result.uri == "" || result.digest == "" {
		return [sha256.Size]byte{}
	}
	encoded, _ := json.Marshal(struct {
		Domain, CoreID, TokenType, URI, Digest string
		Granted, PerCall                       *OperationSet
	}{"gitlab.com/sidecat-dev/aauth-go/r3-token-result/v1", result.coreID.String(), result.tokenType, result.uri, result.digest, result.granted, result.perCall})
	return sha256.Sum256(encoded)
}
