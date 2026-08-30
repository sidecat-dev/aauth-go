package signaturekey

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"aauth-go/jose"
	"github.com/dunglas/httpsfv"
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
)

// Credential is one parsed Signature-Key member. Its parameters are copied
// and can be interpreted only through scheme-specific accessors.
type Credential struct {
	scheme         Scheme
	parameters     map[string]string
	cacheRequested bool
	header         string
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
	if err := validateStructuredFieldString(compact); err != nil {
		return Credential{}, fmt.Errorf("aauth: JWT credential: %w", err)
	}
	return Credential{
		scheme:     SchemeJWT,
		parameters: map[string]string{"jwt": compact},
		header:     `sig=jwt;jwt=` + strconv.Quote(compact),
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
	for name, value := range map[string]string{
		"signer": identifier, "discovery document": discoveryDocument, "signing key": keyID,
	} {
		if err := validateStructuredFieldString(value); err != nil {
			return Credential{}, fmt.Errorf("aauth: jwks_uri %s: %w", name, err)
		}
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

func validateStructuredFieldString(value string) error {
	for index := 0; index < len(value); index++ {
		if value[index] < 0x20 || value[index] > 0x7e {
			return errors.New("value is not representable as an RFC 8941 string")
		}
	}
	return nil
}

// Scheme returns the credential's selected distribution scheme.
func (credential Credential) Scheme() Scheme { return credential.scheme }

// CacheRequested reports whether a jwt credential asks the verifier to issue
// a Signature-Key cache identifier.
func (credential Credential) CacheRequested() bool { return credential.cacheRequested }

// ParseCredential parses one or more Signature-Key field lines containing one
// dictionary member and returns that member as an immutable credential.
func ParseCredential(values []string) (Credential, error) {
	values = append([]string(nil), values...)
	dictionary, members, err := parseDictionaryMembers(values, "Signature-Key")
	if err != nil {
		return Credential{}, err
	}
	if len(members) != 1 || len(dictionary.Names()) != 1 {
		return Credential{}, errors.New("aauth: Signature-Key must contain exactly one member")
	}
	return parseCredentialForLabel(values, dictionary.Names()[0])
}

// ParseCredentialForLabel selects one Signature-Key dictionary member by the
// application-selected HTTP Message Signature label. Other members are not
// interpreted.
func ParseCredentialForLabel(values []string, label string) (Credential, error) {
	if label == "" {
		return Credential{}, errors.New("aauth: signature label is required")
	}
	return parseCredentialForLabel(append([]string(nil), values...), label)
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

// JWT returns the opaque compact value carried by a jwt credential.
func (credential Credential) JWT() (string, bool) {
	if credential.scheme != SchemeJWT || credential.parameters == nil || credential.parameters["jwt"] == "" {
		return "", false
	}
	return credential.parameters["jwt"], true
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

func parseCredentialForLabel(values []string, label string) (Credential, error) {
	dictionary, members, err := parseDictionaryMembers(values, "Signature-Key")
	if err != nil {
		return Credential{}, err
	}
	member, ok := dictionary.Get(label)
	if !ok {
		return Credential{}, fmt.Errorf("aauth: Signature-Key has no member for signature label %q", label)
	}
	item, ok := member.(httpsfv.Item)
	if !ok {
		return Credential{}, fmt.Errorf("aauth: Signature-Key member %q must be an Item", label)
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
	}[parsed.scheme]
	if required == nil {
		return Credential{}, newError(
			ErrorUnsupportedScheme,
			fmt.Errorf("aauth: unsupported Signature-Key scheme %q", parsed.scheme),
		)
	}
	selectedMember := members[label]
	if countTopLevelDelimiters(selectedMember, ';') != len(item.Params.Names()) {
		return Credential{}, fmt.Errorf("aauth: Signature-Key member %q has duplicate parameters", label)
	}
	allowed := make(map[string]struct{}, len(required)+1)
	for _, name := range required {
		allowed[name] = struct{}{}
	}
	if parsed.scheme == SchemeJWT {
		allowed["cache"] = struct{}{}
	}
	for _, name := range item.Params.Names() {
		if _, ok := allowed[name]; !ok {
			return Credential{}, fmt.Errorf("aauth: Signature-Key %s has unexpected parameter %q", parsed.scheme, name)
		}
		value, _ := item.Params.Get(name)
		if name == "cache" {
			cache, ok := value.(bool)
			if !ok || !cache || strings.Contains(selectedMember, ";cache=") {
				return Credential{}, errors.New("aauth: Signature-Key jwt cache parameter must be bare true")
			}
			parsed.cacheRequested = true
			continue
		}
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
	parsed.header = strings.Join(values, ", ")
	return parsed, nil
}

func parseDictionaryMembers(values []string, field string) (*httpsfv.Dictionary, map[string]string, error) {
	dictionary, err := httpsfv.UnmarshalDictionary(values)
	if err != nil {
		return nil, nil, fmt.Errorf("aauth: parse %s: %w", field, err)
	}
	segments, err := splitDictionaryMembers(strings.Join(values, ","))
	if err != nil {
		return nil, nil, fmt.Errorf("aauth: parse %s: %w", field, err)
	}
	members := make(map[string]string, len(segments))
	for _, segment := range segments {
		equals := strings.IndexByte(segment, '=')
		if equals <= 0 {
			return nil, nil, fmt.Errorf("aauth: parse %s: dictionary member has no value", field)
		}
		label := strings.TrimSpace(segment[:equals])
		if _, duplicate := members[label]; duplicate {
			return nil, nil, fmt.Errorf("aauth: parse %s: duplicate member %q", field, label)
		}
		members[label] = strings.TrimSpace(segment)
	}
	return dictionary, members, nil
}

func splitDictionaryMembers(value string) ([]string, error) {
	var members []string
	start := 0
	quoted := false
	escaped := false
	binary := false
	depth := 0
	for index := 0; index < len(value); index++ {
		character := value[index]
		if quoted {
			if escaped {
				escaped = false
				continue
			}
			if character == '\\' {
				escaped = true
				continue
			}
			if character == '"' {
				quoted = false
			}
			continue
		}
		if binary {
			if character == ':' {
				binary = false
			}
			continue
		}
		switch character {
		case '"':
			quoted = true
		case ':':
			binary = true
		case '(':
			depth++
		case ')':
			depth--
			if depth < 0 {
				return nil, errors.New("dictionary member has an unmatched parenthesis")
			}
		case ',':
			if depth == 0 {
				member := strings.TrimSpace(value[start:index])
				if member == "" {
					return nil, errors.New("dictionary contains an empty member")
				}
				members = append(members, member)
				start = index + 1
			}
		}
	}
	if quoted || escaped || binary || depth != 0 {
		return nil, errors.New("dictionary member is unterminated")
	}
	member := strings.TrimSpace(value[start:])
	if member == "" {
		return nil, errors.New("dictionary contains an empty member")
	}
	members = append(members, member)
	return members, nil
}

func countTopLevelDelimiters(value string, delimiter byte) int {
	count := 0
	quoted := false
	escaped := false
	binary := false
	depth := 0
	for index := 0; index < len(value); index++ {
		character := value[index]
		if quoted {
			if escaped {
				escaped = false
				continue
			}
			if character == '\\' {
				escaped = true
				continue
			}
			if character == '"' {
				quoted = false
			}
			continue
		}
		if binary {
			if character == ':' {
				binary = false
			}
			continue
		}
		switch character {
		case '"':
			quoted = true
		case ':':
			binary = true
		case '(':
			depth++
		case ')':
			depth--
		default:
			if character == delimiter && depth == 0 {
				count++
			}
		}
	}
	return count
}

func validateHTTPSIdentifier(identifier string) error {
	if strings.Contains(identifier, "#") {
		return errors.New("identifier must not contain a fragment")
	}
	parsed, err := url.Parse(identifier)
	if err != nil {
		return err
	}
	if parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" {
		return errors.New("identifier must be an HTTPS URL without user information, query, or fragment")
	}
	if parsed.Path != "" && parsed.Path != "/" {
		return errors.New("identifier must not contain a path")
	}
	return nil
}
