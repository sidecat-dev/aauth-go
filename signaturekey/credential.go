package signaturekey

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"

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
	SchemeJKTJWT  Scheme = "jkt-jwt"
	SchemeJWKSURI Scheme = "jwks_uri"
	SchemeJWKS    Scheme = "jwks"
	SchemeHWK     Scheme = "hwk"
	SchemeSelfJWT Scheme = "self-jwt"
	SchemeX509    Scheme = "x509"
	SchemeCached  Scheme = "cached"
)

// schemeParameters lists the parameters each scheme requires. hwk is absent
// because its parameters depend on the key type.
var schemeParameters = map[Scheme][]string{
	SchemeJWT:     {"jwt"},
	SchemeJKTJWT:  {"jwt"},
	SchemeSelfJWT: {"jwt"},
	SchemeJWKSURI: {"id", "dwk", "kid"},
	SchemeJWKS:    {"url", "kid"},
	SchemeX509:    {"x5u", "x5t"},
	SchemeCached:  {"cid"},
}

// hwkParameters lists the inline JWK members an hwk member carries for each
// key type, in the order this package writes them.
var hwkParameters = map[string][]string{
	"OKP": {"kty", "crv", "x", "alg"},
	"EC":  {"kty", "crv", "x", "y", "alg"},
	"RSA": {"kty", "n", "e", "alg"},
}

// Credential is one parsed Signature-Key member. Its parameters are copied
// and can be interpreted only through scheme-specific accessors.
type Credential struct {
	scheme         Scheme
	parameters     map[string]string
	thumbprint     []byte
	cacheRequested bool
	// member is the serialized member value without its label.
	member string
}

// NewHWKCredential constructs an inline public key. The key must carry a
// fully specified alg that jose.JWK.SignaturePublicKey accepts. The member
// carries exactly the JWK members its key type requires and never a kid.
func NewHWKCredential(key jose.JWK) (Credential, error) {
	if _, err := key.SignaturePublicKey(); err != nil {
		return Credential{}, fmt.Errorf("aauth: hwk signing key: %w", err)
	}
	values := inlineJWKMembers(key)
	parameters := make(map[string]string, len(hwkParameters[key.Kty]))
	member := string(SchemeHWK)
	for _, name := range hwkParameters[key.Kty] {
		parameters[name] = values[name]
		member += ";" + name + "=" + strconv.Quote(values[name])
	}
	return Credential{scheme: SchemeHWK, parameters: parameters, member: member}, nil
}

func inlineJWKMembers(key jose.JWK) map[string]string {
	return map[string]string{
		"kty": key.Kty, "crv": key.Crv, "x": key.X, "y": key.Y,
		"n": key.N, "e": key.E, "alg": key.Alg,
	}
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
		member:     `jwt;jwt=` + strconv.Quote(compact),
	}, nil
}

// WithCache asks a verifier to retain a jwt or jkt-jwt assertion. The
// parameter is the bare boolean `;cache`. The assertion must carry a jti for
// a verifier to issue a cache identifier; AssertionCache issues one, and
// CachingCredential presents it on later requests.
func (credential Credential) WithCache() (Credential, error) {
	if credential.scheme != SchemeJWT && credential.scheme != SchemeJKTJWT {
		return Credential{}, fmt.Errorf("aauth: %s does not accept cache", credential.scheme)
	}
	if credential.cacheRequested {
		return credential, nil
	}
	credential.cacheRequested = true
	credential.member += ";cache"
	return credential, nil
}

// NewJKTJWTCredential carries one self-issued durable-to-ephemeral key
// delegation. Verification remains coupled to the outer request proof.
func NewJKTJWTCredential(compact string) (Credential, error) {
	if compact == "" {
		return Credential{}, errors.New("aauth: jkt-jwt credential is required")
	}
	if err := validateStructuredFieldString(compact); err != nil {
		return Credential{}, fmt.Errorf("aauth: jkt-jwt credential: %w", err)
	}
	return Credential{
		scheme:     SchemeJKTJWT,
		parameters: map[string]string{"jwt": compact},
		member:     `jkt-jwt;jwt=` + strconv.Quote(compact),
	}, nil
}

// NewSelfJWTCredential carries a self-issued compact JWT whose discovered
// signing key also signs the accompanying HTTP request.
func NewSelfJWTCredential(compact string) (Credential, error) {
	if compact == "" {
		return Credential{}, errors.New("aauth: self-jwt credential is required")
	}
	if err := validateStructuredFieldString(compact); err != nil {
		return Credential{}, fmt.Errorf("aauth: self-jwt credential: %w", err)
	}
	return Credential{
		scheme:     SchemeSelfJWT,
		parameters: map[string]string{"jwt": compact},
		member:     `self-jwt;jwt=` + strconv.Quote(compact),
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
		member: `jwks_uri;id=` + strconv.Quote(identifier) +
			`;dwk=` + strconv.Quote(discoveryDocument) +
			`;kid=` + strconv.Quote(keyID),
	}, nil
}

// NewJWKSCredential constructs a direct JWKS key reference. keySetURL is
// both the signer identity and the HTTPS location of its JWKS. It is carried
// byte for byte as given, so a signer must pass the same bytes wherever it
// intends the same identity.
func NewJWKSCredential(keySetURL, keyID string) (Credential, error) {
	if err := validateDiscoveryURL(keySetURL); err != nil {
		return Credential{}, fmt.Errorf("aauth: jwks url: %w", err)
	}
	if keyID == "" {
		return Credential{}, errors.New("aauth: jwks signing key is required")
	}
	for name, value := range map[string]string{"url": keySetURL, "signing key": keyID} {
		if err := validateStructuredFieldString(value); err != nil {
			return Credential{}, fmt.Errorf("aauth: jwks %s: %w", name, err)
		}
	}
	return Credential{
		scheme:     SchemeJWKS,
		parameters: map[string]string{"url": keySetURL, "kid": keyID},
		member:     `jwks;url=` + strconv.Quote(keySetURL) + `;kid=` + strconv.Quote(keyID),
	}, nil
}

// NewX509Credential references an X.509 certificate chain published as PEM
// at the HTTPS URL certificateURL. endEntity is the first certificate of
// that chain; x5t is the SHA-256 of its DER encoding.
func NewX509Credential(certificateURL string, endEntity *x509.Certificate) (Credential, error) {
	if err := validateDiscoveryURL(certificateURL); err != nil {
		return Credential{}, fmt.Errorf("aauth: x509 x5u: %w", err)
	}
	if err := validateStructuredFieldString(certificateURL); err != nil {
		return Credential{}, fmt.Errorf("aauth: x509 x5u: %w", err)
	}
	if endEntity == nil || len(endEntity.Raw) == 0 {
		return Credential{}, errors.New("aauth: x509 end-entity certificate is required")
	}
	thumbprint := sha256.Sum256(endEntity.Raw)
	return Credential{
		scheme:     SchemeX509,
		parameters: map[string]string{"x5u": certificateURL},
		thumbprint: thumbprint[:],
		member: `x509;x5u=` + strconv.Quote(certificateURL) +
			`;x5t=:` + base64.StdEncoding.EncodeToString(thumbprint[:]) + `:`,
	}, nil
}

// NewCachedCredential presents the cache identifier a verifier issued in
// Signature-Key-Cache. The identifier is carried exactly as received; there
// is deliberately no way to build one from a string.
func NewCachedCredential(grant CacheGrant) (Credential, error) {
	if grant.identifier == "" {
		return Credential{}, errors.New("aauth: cached credential requires an issued cache identifier")
	}
	if err := validateStructuredFieldString(grant.identifier); err != nil {
		return Credential{}, fmt.Errorf("aauth: cache identifier: %w", err)
	}
	return Credential{
		scheme:     SchemeCached,
		parameters: map[string]string{"cid": grant.identifier},
		member:     `cached;cid=` + strconv.Quote(grant.identifier),
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

// CacheRequested reports whether a jwt or jkt-jwt credential asks the verifier
// to issue a Signature-Key cache identifier.
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
		Y:   credential.parameters["y"],
		N:   credential.parameters["n"],
		E:   credential.parameters["e"],
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

// JKTJWT returns the opaque compact delegation carried by a jkt-jwt
// credential. Trust is established only by PreparedRequest.VerifyJKTJWT.
func (credential Credential) JKTJWT() (string, bool) {
	if credential.scheme != SchemeJKTJWT || credential.parameters == nil || credential.parameters["jwt"] == "" {
		return "", false
	}
	return credential.parameters["jwt"], true
}

// SelfJWT returns the opaque compact value carried by a self-jwt credential.
// Trust is established only by PreparedRequest.VerifySelfJWT.
func (credential Credential) SelfJWT() (string, bool) {
	if credential.scheme != SchemeSelfJWT || credential.parameters == nil || credential.parameters["jwt"] == "" {
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

// JWKS returns the exact JWKS URL and key id carried by a jwks credential.
// The URL is the signer identity as presented, without normalization.
func (credential Credential) JWKS() (string, string, bool) {
	if credential.scheme != SchemeJWKS || credential.parameters == nil {
		return "", "", false
	}
	keySetURL, keyID := credential.parameters["url"], credential.parameters["kid"]
	if keySetURL == "" || keyID == "" {
		return "", "", false
	}
	return keySetURL, keyID, true
}

// X509 returns the exact certificate URL and an independent copy of the
// SHA-256 end-entity thumbprint carried by an x509 credential. Trust is
// established only by PreparedRequest.VerifyX509.
func (credential Credential) X509() (string, []byte, bool) {
	if credential.scheme != SchemeX509 || credential.parameters == nil ||
		credential.parameters["x5u"] == "" || len(credential.thumbprint) != sha256.Size {
		return "", nil, false
	}
	return credential.parameters["x5u"], append([]byte(nil), credential.thumbprint...), true
}

// CacheIdentifier returns the opaque identifier carried by a cached
// credential, exactly as presented.
func (credential Credential) CacheIdentifier() (string, bool) {
	if credential.scheme != SchemeCached || credential.parameters == nil || credential.parameters["cid"] == "" {
		return "", false
	}
	return credential.parameters["cid"], true
}

func (credential Credential) clone() Credential {
	parameters := make(map[string]string, len(credential.parameters))
	for name, value := range credential.parameters {
		parameters[name] = value
	}
	credential.parameters = parameters
	credential.thumbprint = append([]byte(nil), credential.thumbprint...)
	return credential
}

func parseCredentialForLabel(values []string, label string) (Credential, error) {
	item, segment, err := selectCredentialMember(values, label)
	if err != nil {
		return Credential{}, err
	}
	return parseCredentialMember(item, segment)
}

// selectCredentialMember returns the Signature-Key member for label and its
// exact field text. Only its scheme token is checked, so a caller can apply
// scheme acceptance before any scheme-specific parsing.
func selectCredentialMember(values []string, label string) (httpsfv.Item, string, error) {
	dictionary, members, err := parseDictionaryMembers(values, "Signature-Key")
	if err != nil {
		return httpsfv.Item{}, "", err
	}
	member, ok := dictionary.Get(label)
	if !ok {
		return httpsfv.Item{}, "", fmt.Errorf("aauth: Signature-Key has no member for signature label %q", label)
	}
	item, ok := member.(httpsfv.Item)
	if !ok {
		return httpsfv.Item{}, "", fmt.Errorf("aauth: Signature-Key member %q must be an Item", label)
	}
	scheme, ok := item.Value.(httpsfv.Token)
	if !ok || scheme == "" {
		return httpsfv.Item{}, "", errors.New("aauth: Signature-Key scheme must be a token")
	}
	return item, members[label], nil
}

func parseCredentialMember(item httpsfv.Item, segment string) (Credential, error) {
	scheme := Scheme(item.Value.(httpsfv.Token))
	required, known := schemeParameters[scheme]
	if !known && scheme != SchemeHWK {
		return Credential{}, newError(
			ErrorUnsupportedScheme,
			fmt.Errorf("aauth: unsupported Signature-Key scheme %q", scheme),
		)
	}
	if countTopLevelDelimiters(segment, ';') != len(item.Params.Names()) {
		return Credential{}, fmt.Errorf("aauth: Signature-Key %s member has duplicate parameters", scheme)
	}
	parsed := Credential{scheme: scheme, parameters: make(map[string]string)}
	if _, value, found := strings.Cut(segment, "="); found {
		parsed.member = strings.TrimSpace(value)
	}
	if scheme == SchemeHWK {
		parameters, err := parseHWKParameters(item.Params)
		if err != nil {
			return Credential{}, err
		}
		parsed.parameters = parameters
		return parsed, nil
	}
	allowed := make(map[string]struct{}, len(required)+1)
	for _, name := range required {
		allowed[name] = struct{}{}
	}
	if scheme == SchemeJWT || scheme == SchemeJKTJWT {
		allowed["cache"] = struct{}{}
	}
	for _, name := range item.Params.Names() {
		if _, ok := allowed[name]; !ok {
			return Credential{}, fmt.Errorf("aauth: Signature-Key %s has unexpected parameter %q", scheme, name)
		}
		value, _ := item.Params.Get(name)
		switch name {
		case "cache":
			cache, ok := value.(bool)
			if !ok || !cache || strings.Contains(segment, ";cache=") {
				return Credential{}, fmt.Errorf("aauth: Signature-Key %s cache parameter must be bare true", scheme)
			}
			parsed.cacheRequested = true
		case "x5t":
			thumbprint, ok := value.([]byte)
			if !ok || len(thumbprint) != sha256.Size {
				return Credential{}, errors.New("aauth: Signature-Key x509 x5t must be a 32-byte SHA-256 byte sequence")
			}
			parsed.thumbprint = append([]byte(nil), thumbprint...)
		default:
			text, ok := value.(string)
			if !ok || text == "" {
				return Credential{}, fmt.Errorf("aauth: Signature-Key parameter %q must be a non-empty string", name)
			}
			parsed.parameters[name] = text
		}
	}
	for _, name := range required {
		present := parsed.parameters[name] != ""
		if name == "x5t" {
			present = parsed.thumbprint != nil
		}
		if !present {
			return Credential{}, fmt.Errorf("aauth: Signature-Key %s requires %s", scheme, name)
		}
	}
	switch scheme {
	case SchemeJWKS:
		if err := validateDiscoveryURL(parsed.parameters["url"]); err != nil {
			return Credential{}, fmt.Errorf("aauth: Signature-Key jwks url: %w", err)
		}
	case SchemeX509:
		if err := validateDiscoveryURL(parsed.parameters["x5u"]); err != nil {
			return Credential{}, fmt.Errorf("aauth: Signature-Key x509 x5u: %w", err)
		}
	}
	return parsed, nil
}

// parseHWKParameters reads an inline key under Algorithm Determination: alg
// selects the algorithm, kty and crv must agree with it, and the members
// required for the key type must be present. kid, private members, and
// members of another key type are refused; other parameters are ignored, as
// RFC 7517 requires of JWK members a reader does not understand. A missing
// alg, or an alg or kty this package does not implement, is
// unsupported_algorithm.
func parseHWKParameters(params *httpsfv.Params) (map[string]string, error) {
	unsupported := func(cause error) error {
		return &Error{Code: ErrorUnsupportedAlgorithm, AcceptedAlgorithms: jose.SignatureAlgorithms(), Cause: cause}
	}
	for _, name := range params.Names() {
		if name == "kid" {
			return nil, errors.New("aauth: Signature-Key hwk must not carry kid")
		}
		if jose.IsPrivateJWKMember(name) {
			return nil, fmt.Errorf("aauth: Signature-Key hwk must not carry private member %q", name)
		}
	}
	parameters := make(map[string]string)
	for _, name := range []string{"kty", "crv", "x", "y", "n", "e", "alg"} {
		value, present := params.Get(name)
		if !present {
			continue
		}
		text, ok := value.(string)
		if !ok || text == "" {
			return nil, fmt.Errorf("aauth: Signature-Key parameter %q must be a non-empty string", name)
		}
		parameters[name] = text
	}
	if parameters["alg"] == "" {
		return nil, unsupported(errors.New("aauth: Signature-Key hwk requires alg"))
	}
	keyType := parameters["kty"]
	if keyType == "" {
		return nil, errors.New("aauth: Signature-Key hwk requires kty")
	}
	expected, known := hwkParameters[keyType]
	if !known {
		return nil, unsupported(fmt.Errorf("aauth: Signature-Key hwk key type %q is not implemented", keyType))
	}
	allowed := make(map[string]struct{}, len(expected))
	for _, name := range expected {
		allowed[name] = struct{}{}
		if parameters[name] == "" {
			return nil, fmt.Errorf("aauth: Signature-Key hwk %s key requires %s", keyType, name)
		}
	}
	for name := range parameters {
		if _, ok := allowed[name]; !ok {
			return nil, fmt.Errorf("aauth: Signature-Key hwk %s key carries %q, a member of another key type", keyType, name)
		}
	}
	key := jose.JWK{
		Kty: keyType, Crv: parameters["crv"], X: parameters["x"], Y: parameters["y"],
		N: parameters["n"], E: parameters["e"], Alg: parameters["alg"],
	}
	if _, err := key.SignaturePublicKey(); err != nil {
		var unsupportedAlgorithm interface{ UnsupportedAlgorithm() string }
		if errors.As(err, &unsupportedAlgorithm) {
			return nil, unsupported(err)
		}
		return nil, &Error{Code: ErrorInvalidKey, Cause: fmt.Errorf("aauth: Signature-Key hwk: %w", err)}
	}
	return parameters, nil
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
