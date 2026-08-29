package signaturekey

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strconv"

	"github.com/dunglas/httpsfv"
	"gitlab.com/sidecat-dev/aauth-go/jose"
)

var discoveryNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._~-]{0,254}$`)

// ValidateDiscoveryName validates one dot-well-known document name as a
// single safe path segment.
func ValidateDiscoveryName(name string) error {
	if !discoveryNamePattern.MatchString(name) {
		return errors.New("aauth: discovery document name is invalid")
	}
	return nil
}

// Scheme identifies one Signature-Key key-distribution scheme.
type Scheme string

const (
	SchemeJWT     Scheme = "jwt"
	SchemeJWKSURI Scheme = "jwks_uri"
	SchemeHWK     Scheme = "hwk"
	SchemeJKTJWT  Scheme = "jkt-jwt"
	SchemeSelfJWT Scheme = "self-jwt"
)

// Credential is one parsed Signature-Key member. Its parameters are copied
// and can be interpreted only through scheme-specific accessors.
type Credential struct {
	scheme     Scheme
	parameters map[string]string
	header     string
}

// NewHWKCredential constructs the selected inline Ed25519 JWK profile.
func NewHWKCredential(key jose.JWK) (Credential, error) {
	if _, err := key.PublicKey(); err != nil {
		return Credential{}, fmt.Errorf("aauth: hwk signing key: %w", err)
	}
	parameters := map[string]string{
		"kty": key.Kty,
		"crv": key.Crv,
		"x":   key.X,
		"alg": key.Alg,
	}
	header := `sig=hwk;kty=` + strconv.Quote(key.Kty) +
		`;crv=` + strconv.Quote(key.Crv) +
		`;x=` + strconv.Quote(key.X) +
		`;alg=` + strconv.Quote(key.Alg)
	return Credential{scheme: SchemeHWK, parameters: parameters, header: header}, nil
}

// NewJWTCredential carries an opaque compact JWT. The caller remains
// responsible for verifying its profile and selecting its confirmation key.
func NewJWTCredential(compact string) (Credential, error) {
	if compact == "" {
		return Credential{}, errors.New("aauth: JWT credential is required")
	}
	return Credential{
		scheme:     SchemeJWT,
		parameters: map[string]string{"jwt": compact},
		header:     `sig=jwt;jwt=` + strconv.Quote(compact),
	}, nil
}

// NewSelfJWTCredential carries one self-issued compact JWT. Verification of
// its issuer claims remains a separate stage.
func NewSelfJWTCredential(compact string) (Credential, error) {
	if compact == "" {
		return Credential{}, errors.New("aauth: self-jwt is required")
	}
	return Credential{
		scheme:     SchemeSelfJWT,
		parameters: map[string]string{"jwt": compact},
		header:     `sig=self-jwt;jwt=` + strconv.Quote(compact),
	}, nil
}

// NewJKTJWTCredential carries one self-issued durable-to-ephemeral key
// delegation.
func NewJKTJWTCredential(compact string) (Credential, error) {
	if compact == "" {
		return Credential{}, errors.New("aauth: jkt-jwt delegation is required")
	}
	return Credential{
		scheme:     SchemeJKTJWT,
		parameters: map[string]string{"jwt": compact},
		header:     `sig=jkt-jwt;jwt=` + strconv.Quote(compact),
	}, nil
}

// NewJWKSURICredential constructs a two-hop metadata and JWKS key reference.
func NewJWKSURICredential(identifier, discoveryDocument, keyID string) (Credential, error) {
	if err := validateHTTPSIdentifier(identifier); err != nil {
		return Credential{}, fmt.Errorf("aauth: jwks_uri signer: %w", err)
	}
	if err := ValidateDiscoveryName(discoveryDocument); err != nil {
		return Credential{}, errors.New("aauth: jwks_uri discovery document is invalid")
	}
	if keyID == "" {
		return Credential{}, errors.New("aauth: jwks_uri signing key is required")
	}
	return Credential{
		scheme: SchemeJWKSURI,
		parameters: map[string]string{
			"id":  identifier,
			"dwk": discoveryDocument,
			"kid": keyID,
		},
		header: `sig=jwks_uri;id=` + strconv.Quote(identifier) +
			`;dwk=` + strconv.Quote(discoveryDocument) +
			`;kid=` + strconv.Quote(keyID),
	}, nil
}

// Scheme returns the credential's selected distribution scheme.
func (credential Credential) Scheme() Scheme { return credential.scheme }

// ParseCredential parses one or more Signature-Key field lines and returns
// the selected sig member as an immutable credential.
func ParseCredential(values []string) (Credential, error) {
	return parseCredential(append([]string(nil), values...))
}

// InlineJWK returns an independent JWK for an hwk credential.
func (credential Credential) InlineJWK() (jose.JWK, bool) {
	if credential.scheme != SchemeHWK || credential.parameters == nil {
		return jose.JWK{}, false
	}
	return jose.JWK{
		Kty: credential.parameters["kty"],
		Crv: credential.parameters["crv"],
		X:   credential.parameters["x"],
		Alg: credential.parameters["alg"],
	}, true
}

// JWT returns the opaque compact value carried by jwt, jkt-jwt, or self-jwt.
func (credential Credential) JWT() (string, bool) {
	switch credential.scheme {
	case SchemeJWT, SchemeJKTJWT, SchemeSelfJWT:
		if credential.parameters == nil || credential.parameters["jwt"] == "" {
			return "", false
		}
		return credential.parameters["jwt"], true
	default:
		return "", false
	}
}

// JWKSURI returns the identifier, dot-well-known document, and key id carried
// by a jwks_uri credential.
func (credential Credential) JWKSURI() (string, string, string, bool) {
	if credential.scheme != SchemeJWKSURI || credential.parameters == nil {
		return "", "", "", false
	}
	identifier := credential.parameters["id"]
	document := credential.parameters["dwk"]
	keyID := credential.parameters["kid"]
	if identifier == "" || document == "" || keyID == "" {
		return "", "", "", false
	}
	return identifier, document, keyID, true
}

func parseCredential(values []string) (Credential, error) {
	dictionary, err := httpsfv.UnmarshalDictionary(values)
	if err != nil {
		return Credential{}, fmt.Errorf("aauth: parse Signature-Key: %w", err)
	}
	member, ok := dictionary.Get("sig")
	if !ok {
		return Credential{}, errors.New("aauth: Signature-Key must contain the sig label")
	}
	item, ok := member.(httpsfv.Item)
	if !ok {
		return Credential{}, errors.New("aauth: Signature-Key sig member must be an Item")
	}
	scheme, ok := item.Value.(httpsfv.Token)
	if !ok || scheme == "" {
		return Credential{}, errors.New("aauth: Signature-Key scheme must be a token")
	}
	parsed := Credential{scheme: Scheme(scheme), parameters: make(map[string]string)}
	required := map[Scheme][]string{
		SchemeJWT:     {"jwt"},
		SchemeJWKSURI: {"id", "dwk", "kid"},
		SchemeHWK:     {"kty", "crv", "x", "alg"},
		SchemeJKTJWT:  {"jwt"},
		SchemeSelfJWT: {"jwt"},
	}[parsed.scheme]
	if required == nil {
		return Credential{}, newError(
			ErrorUnsupportedScheme,
			fmt.Errorf("aauth: unsupported Signature-Key scheme %q", parsed.scheme),
		)
	}
	for _, name := range item.Params.Names() {
		value, _ := item.Params.Get(name)
		text, ok := value.(string)
		if !ok || text == "" {
			return Credential{}, fmt.Errorf("aauth: Signature-Key parameter %q must be a non-empty string", name)
		}
		parsed.parameters[name] = text
	}
	if parsed.scheme == SchemeHWK && parsed.parameters["alg"] == "" {
		return Credential{}, &Error{
			Code:               ErrorUnsupportedAlgorithm,
			AcceptedAlgorithms: []string{jose.Ed25519Algorithm},
			Cause:              errors.New("aauth: Signature-Key hwk requires alg"),
		}
	}
	if len(parsed.parameters) != len(required) {
		return Credential{}, fmt.Errorf("aauth: Signature-Key %s has unexpected parameters", parsed.scheme)
	}
	for _, name := range required {
		if parsed.parameters[name] == "" {
			return Credential{}, fmt.Errorf("aauth: Signature-Key %s requires %s", parsed.scheme, name)
		}
	}
	if parsed.scheme == SchemeHWK {
		key, _ := parsed.InlineJWK()
		if _, err := key.PublicKey(); err != nil {
			if key.Alg != jose.Ed25519Algorithm {
				return Credential{}, &Error{
					Code:               ErrorUnsupportedAlgorithm,
					AcceptedAlgorithms: []string{jose.Ed25519Algorithm},
					Cause:              err,
				}
			}
			return Credential{}, &Error{Code: ErrorInvalidKey, Cause: fmt.Errorf("aauth: Signature-Key hwk: %w", err)}
		}
	}
	parsed.header = values[0]
	return parsed, nil
}

func validateHTTPSIdentifier(identifier string) error {
	parsed, err := url.Parse(identifier)
	if err != nil {
		return err
	}
	if parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return errors.New("identifier must be an HTTPS URL without user information, query, or fragment")
	}
	if parsed.Path != "" && parsed.Path != "/" {
		return errors.New("identifier must not contain a path")
	}
	return nil
}
