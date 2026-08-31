package r3

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"mime"
	"sort"
	"strings"
	"unicode/utf8"
)

// ProposalDisplay adds optional Markdown detail to the ordinary R3 display
// fields for one concrete invocation.
type ProposalDisplay struct {
	display Display
	detail  string
}

// NewProposalDisplay constructs a validated per-call display value.
func NewProposalDisplay(display Display, detail string) (ProposalDisplay, error) {
	value := ProposalDisplay{display: display, detail: detail}
	if err := value.validate(); err != nil {
		return ProposalDisplay{}, err
	}
	return value, nil
}

func (d ProposalDisplay) validate() error {
	if err := d.display.validate(); err != nil {
		return err
	}
	if !utf8.ValidString(d.detail) {
		return errors.New("r3: proposal display detail must be valid UTF-8")
	}
	return nil
}

// Summary returns the required consent-screen summary.
func (d ProposalDisplay) Summary() string { return d.display.Summary() }

// Implications returns the optional side-effect description.
func (d ProposalDisplay) Implications() string { return d.display.Implications() }

// DataAccessed returns the optional accessed-data description.
func (d ProposalDisplay) DataAccessed() string { return d.display.DataAccessed() }

// Irreversible returns the optional irreversible-action description.
func (d ProposalDisplay) Irreversible() string { return d.display.Irreversible() }

// Detail returns the optional Markdown detail.
func (d ProposalDisplay) Detail() string { return d.detail }

// MarshalJSON emits only the proposal display members.
func (d ProposalDisplay) MarshalJSON() ([]byte, error) {
	if err := d.validate(); err != nil {
		return nil, err
	}
	return json.Marshal(struct {
		Summary      string `json:"summary"`
		Implications string `json:"implications,omitempty"`
		DataAccessed string `json:"data_accessed,omitempty"`
		Irreversible string `json:"irreversible,omitempty"`
		Detail       string `json:"detail,omitempty"`
	}{
		Summary: d.Summary(), Implications: d.Implications(),
		DataAccessed: d.DataAccessed(), Irreversible: d.Irreversible(), Detail: d.detail,
	})
}

// UnmarshalJSON accepts only the exact proposal display shape.
func (d *ProposalDisplay) UnmarshalJSON(data []byte) error {
	parsed, err := parseProposalDisplay(data)
	if err != nil {
		return err
	}
	*d = parsed
	return nil
}

func parseProposalDisplay(data []byte) (ProposalDisplay, error) {
	var summary, implications, dataAccessed, irreversible, detail string
	seen, err := decodeStrictObject(data, map[string]func(json.RawMessage) error{
		"summary":       func(raw json.RawMessage) error { return decodeJSONString(raw, &summary) },
		"implications":  func(raw json.RawMessage) error { return decodeJSONString(raw, &implications) },
		"data_accessed": func(raw json.RawMessage) error { return decodeJSONString(raw, &dataAccessed) },
		"irreversible":  func(raw json.RawMessage) error { return decodeJSONString(raw, &irreversible) },
		"detail":        func(raw json.RawMessage) error { return decodeJSONString(raw, &detail) },
	})
	if err != nil {
		return ProposalDisplay{}, fmt.Errorf("r3: invalid proposal display: %w", err)
	}
	if _, ok := seen["summary"]; !ok {
		return ProposalDisplay{}, errors.New("r3: proposal display is missing summary")
	}
	display, err := NewDisplay(summary, implications, dataAccessed, irreversible)
	if err != nil {
		return ProposalDisplay{}, err
	}
	return NewProposalDisplay(display, detail)
}

// ParameterDigest identifies the exact bytes of a large or sensitive
// parameter while carrying only optional display metadata.
type ParameterDigest struct {
	s256      string
	excerpt   string
	mediaType string
}

func newParameterDigest(s256, excerpt, mediaType string) (ParameterDigest, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(s256)
	if err != nil || len(decoded) != 32 || base64.RawURLEncoding.EncodeToString(decoded) != s256 {
		return ParameterDigest{}, errors.New("r3: parameter digest s256 must be canonical unpadded base64url SHA-256")
	}
	if !utf8.ValidString(excerpt) {
		return ParameterDigest{}, errors.New("r3: parameter digest excerpt must be valid UTF-8")
	}
	if !utf8.ValidString(mediaType) || strings.TrimSpace(mediaType) != mediaType {
		return ParameterDigest{}, errors.New("r3: parameter digest media_type must be valid trimmed UTF-8")
	}
	if mediaType != "" {
		if _, _, err := mime.ParseMediaType(mediaType); err != nil {
			return ParameterDigest{}, fmt.Errorf("r3: invalid parameter digest media_type: %w", err)
		}
	}
	return ParameterDigest{s256: s256, excerpt: excerpt, mediaType: mediaType}, nil
}

// S256 returns the canonical unpadded base64url SHA-256 digest.
func (d ParameterDigest) S256() string { return d.s256 }

// Excerpt returns the optional human-readable excerpt.
func (d ParameterDigest) Excerpt() string { return d.excerpt }

// MediaType returns the optional media type.
func (d ParameterDigest) MediaType() string { return d.mediaType }

type parameterKind uint8

const (
	parameterInvalid parameterKind = iota
	parameterInline
	parameterDigest
)

// MCPParameter is either an owned inline JSON value or an exact-byte digest
// descriptor. Objects using a digest-descriptor member name are reserved for
// the descriptor shape so they cannot change interpretation after approval.
type MCPParameter struct {
	kind   parameterKind
	inline json.RawMessage
	digest ParameterDigest
}

// NewMCPInlineParameter constructs an owned, strictly parsed inline JSON
// parameter value.
func NewMCPInlineParameter(value []byte) (MCPParameter, error) {
	parsed, err := decodeStrictJSONValue(value)
	if err != nil {
		return MCPParameter{}, fmt.Errorf("r3: invalid inline parameter: %w", err)
	}
	if object, ok := parsed.(map[string]any); ok && containsDigestMember(object) {
		return MCPParameter{}, errors.New("r3: inline parameter uses a reserved digest descriptor member")
	}
	encoded, err := json.Marshal(parsed)
	if err != nil {
		return MCPParameter{}, fmt.Errorf("r3: encode inline parameter: %w", err)
	}
	return MCPParameter{kind: parameterInline, inline: append(json.RawMessage(nil), encoded...)}, nil
}

// NewMCPDigestParameter constructs an exact-byte digest parameter.
func NewMCPDigestParameter(s256, excerpt, mediaType string) (MCPParameter, error) {
	digest, err := newParameterDigest(s256, excerpt, mediaType)
	if err != nil {
		return MCPParameter{}, err
	}
	return MCPParameter{kind: parameterDigest, digest: digest}, nil
}

// NewMCPDigestParameterFromBytes constructs a digest descriptor from the
// exact bytes the Resource received for the call.
func NewMCPDigestParameterFromBytes(exact []byte, excerpt, mediaType string) (MCPParameter, error) {
	return NewMCPDigestParameter(Digest(exact), excerpt, mediaType)
}

func (p MCPParameter) validate() error {
	switch p.kind {
	case parameterInline:
		if len(p.inline) == 0 {
			return errors.New("r3: inline parameter is empty")
		}
		_, err := decodeStrictJSONValue(p.inline)
		return err
	case parameterDigest:
		_, err := newParameterDigest(p.digest.s256, p.digest.excerpt, p.digest.mediaType)
		return err
	default:
		return errors.New("r3: parameter is uninitialized")
	}
}

func (p MCPParameter) clone() MCPParameter {
	cloned := p
	cloned.inline = append(json.RawMessage(nil), p.inline...)
	return cloned
}

// InlineJSON returns an owned copy of the inline JSON value, when present.
func (p MCPParameter) InlineJSON() ([]byte, bool) {
	if p.kind != parameterInline || p.validate() != nil {
		return nil, false
	}
	return append([]byte(nil), p.inline...), true
}

// Digest returns the digest descriptor, when present.
func (p MCPParameter) Digest() (ParameterDigest, bool) {
	if p.kind != parameterDigest || p.validate() != nil {
		return ParameterDigest{}, false
	}
	return p.digest, true
}

func (p MCPParameter) matches(presented PresentedMCPParameter) (bool, error) {
	if err := p.validate(); err != nil {
		return false, err
	}
	if p.kind != presented.kind {
		return false, nil
	}
	if p.kind == parameterDigest {
		return Digest(presented.value) == p.digest.s256, nil
	}
	want, err := decodeStrictJSONValue(p.inline)
	if err != nil {
		return false, err
	}
	got, err := decodeStrictJSONValue(presented.value)
	if err != nil {
		return false, fmt.Errorf("r3: invalid presented inline parameter: %w", err)
	}
	return equalJSONValues(want, got), nil
}

// PresentedMCPParameter explicitly distinguishes JSON values, which compare
// structurally, from exact bytes used by an approved digest descriptor.
type PresentedMCPParameter struct {
	kind  parameterKind
	value []byte
}

// NewPresentedMCPInlineParameter constructs one strictly parsed call-time JSON
// value for structural comparison.
func NewPresentedMCPInlineParameter(value []byte) (PresentedMCPParameter, error) {
	if _, err := decodeStrictJSONValue(value); err != nil {
		return PresentedMCPParameter{}, fmt.Errorf("r3: invalid presented inline parameter: %w", err)
	}
	return PresentedMCPParameter{kind: parameterInline, value: append([]byte(nil), value...)}, nil
}

// NewPresentedMCPDigestBytes constructs one owned exact-byte call-time value.
func NewPresentedMCPDigestBytes(value []byte) PresentedMCPParameter {
	return PresentedMCPParameter{kind: parameterDigest, value: append([]byte(nil), value...)}
}

func (p PresentedMCPParameter) validate() error {
	switch p.kind {
	case parameterInline:
		_, err := decodeStrictJSONValue(p.value)
		return err
	case parameterDigest:
		return nil
	default:
		return errors.New("r3: presented parameter is uninitialized")
	}
}

// MarshalJSON emits the inline value or exact digest descriptor.
func (p MCPParameter) MarshalJSON() ([]byte, error) {
	if err := p.validate(); err != nil {
		return nil, err
	}
	if p.kind == parameterInline {
		return append([]byte(nil), p.inline...), nil
	}
	return json.Marshal(struct {
		S256      string `json:"s256"`
		Excerpt   string `json:"excerpt,omitempty"`
		MediaType string `json:"media_type,omitempty"`
	}{S256: p.digest.s256, Excerpt: p.digest.excerpt, MediaType: p.digest.mediaType})
}

// UnmarshalJSON accepts either an inline JSON value or the reserved digest
// descriptor shape.
func (p *MCPParameter) UnmarshalJSON(data []byte) error {
	parsed, err := parseMCPParameter(data)
	if err != nil {
		return err
	}
	*p = parsed
	return nil
}

func parseMCPParameter(data []byte) (MCPParameter, error) {
	value, err := decodeStrictJSONValue(data)
	if err != nil {
		return MCPParameter{}, err
	}
	object, isObject := value.(map[string]any)
	if !isObject || !containsDigestMember(object) {
		return NewMCPInlineParameter(data)
	}
	for name := range object {
		if name != "s256" && name != "excerpt" && name != "media_type" {
			return MCPParameter{}, fmt.Errorf("r3: digest parameter has unknown member %q", name)
		}
	}
	s256Value, ok := object["s256"]
	if !ok {
		return MCPParameter{}, errors.New("r3: digest parameter is missing s256")
	}
	s256, ok := s256Value.(string)
	if !ok {
		return MCPParameter{}, errors.New("r3: digest parameter s256 must be a string")
	}
	excerpt, err := optionalStringMember(object, "excerpt")
	if err != nil {
		return MCPParameter{}, err
	}
	mediaType, err := optionalStringMember(object, "media_type")
	if err != nil {
		return MCPParameter{}, err
	}
	return NewMCPDigestParameter(s256, excerpt, mediaType)
}

func containsDigestMember(object map[string]any) bool {
	_, ok := object["s256"]
	return ok
}

func optionalStringMember(object map[string]any, name string) (string, error) {
	value, ok := object[name]
	if !ok {
		return "", nil
	}
	text, ok := value.(string)
	if !ok {
		return "", fmt.Errorf("r3: digest parameter %s must be a string", name)
	}
	return text, nil
}

// MCPParameters is an initialized, copy-safe set of concrete MCP call
// parameters. An initialized empty set is valid for a parameterless tool.
type MCPParameters struct {
	initialized bool
	values      map[string]MCPParameter
}

// NewMCPParameters constructs a parameter set and copies every value.
func NewMCPParameters(values map[string]MCPParameter) (MCPParameters, error) {
	parameters := MCPParameters{initialized: true, values: make(map[string]MCPParameter, len(values))}
	for name, value := range values {
		if err := validateParameterName(name); err != nil {
			return MCPParameters{}, err
		}
		if err := value.validate(); err != nil {
			return MCPParameters{}, fmt.Errorf("r3: parameter %q: %w", name, err)
		}
		parameters.values[name] = value.clone()
	}
	return parameters, nil
}

func (p MCPParameters) validate() error {
	if !p.initialized || p.values == nil {
		return errors.New("r3: parameters are uninitialized")
	}
	for name, value := range p.values {
		if err := validateParameterName(name); err != nil {
			return err
		}
		if err := value.validate(); err != nil {
			return fmt.Errorf("r3: parameter %q: %w", name, err)
		}
	}
	return nil
}

func validateParameterName(name string) error {
	if !utf8.ValidString(name) {
		return fmt.Errorf("r3: parameter name %q must be valid UTF-8", name)
	}
	return nil
}

func (p MCPParameters) clone() MCPParameters {
	cloned := MCPParameters{initialized: p.initialized, values: make(map[string]MCPParameter, len(p.values))}
	for name, value := range p.values {
		cloned.values[name] = value.clone()
	}
	return cloned
}

// Get returns an owned copy of one parameter.
func (p MCPParameters) Get(name string) (MCPParameter, bool) {
	value, ok := p.values[name]
	return value.clone(), ok
}

// Names returns parameter names in lexical order.
func (p MCPParameters) Names() []string {
	names := make([]string, 0, len(p.values))
	for name := range p.values {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// Matches verifies that the presented parameter names are exact and that
// every value matches its inline or digest-backed proposal value.
func (p MCPParameters) Matches(presented map[string]PresentedMCPParameter) (bool, error) {
	if err := p.validate(); err != nil {
		return false, err
	}
	expectedNames := p.Names()
	presentedNames := make([]string, 0, len(presented))
	for name := range presented {
		presentedNames = append(presentedNames, name)
	}
	sort.Strings(presentedNames)
	for _, name := range presentedNames {
		if err := presented[name].validate(); err != nil {
			return false, fmt.Errorf("r3: presented parameter %q: %w", name, err)
		}
	}
	if len(expectedNames) != len(presentedNames) {
		return false, nil
	}
	for index, name := range expectedNames {
		if presentedNames[index] != name {
			return false, nil
		}
		matches, err := p.values[name].matches(presented[name])
		if err != nil || !matches {
			return matches, err
		}
	}
	return true, nil
}

// MarshalJSON emits one JSON object of concrete parameter values.
func (p MCPParameters) MarshalJSON() ([]byte, error) {
	if err := p.validate(); err != nil {
		return nil, err
	}
	return json.Marshal(p.values)
}

// UnmarshalJSON accepts a strict parameter object with no duplicate names.
func (p *MCPParameters) UnmarshalJSON(data []byte) error {
	value, err := decodeStrictJSONValue(data)
	if err != nil {
		return fmt.Errorf("r3: invalid parameters: %w", err)
	}
	object, ok := value.(map[string]any)
	if !ok {
		return errors.New("r3: parameters must be a JSON object")
	}
	values := make(map[string]MCPParameter, len(object))
	for name, semantic := range object {
		encoded, err := json.Marshal(semantic)
		if err != nil {
			return err
		}
		parameter, err := parseMCPParameter(encoded)
		if err != nil {
			return fmt.Errorf("r3: parameter %q: %w", name, err)
		}
		values[name] = parameter
	}
	parsed, err := NewMCPParameters(values)
	if err != nil {
		return err
	}
	*p = parsed
	return nil
}

// ProposalOptions supplies the optional account and per-call display fields.
type ProposalOptions struct {
	Account *string
	Display *ProposalDisplay
}

// MCPProposal is a validated per-call proposal for exactly one MCP operation.
type MCPProposal struct {
	operation  MCPOperation
	parameters MCPParameters
	account    *string
	display    *ProposalDisplay
}

// NewMCPProposal constructs a validated per-call proposal.
func NewMCPProposal(operation MCPOperation, parameters MCPParameters, options ProposalOptions) (MCPProposal, error) {
	if err := operation.validate(); err != nil {
		return MCPProposal{}, err
	}
	if err := parameters.validate(); err != nil {
		return MCPProposal{}, err
	}
	proposal := MCPProposal{operation: operation, parameters: parameters.clone()}
	if options.Account != nil {
		if !utf8.ValidString(*options.Account) {
			return MCPProposal{}, errors.New("r3: proposal account must be valid UTF-8")
		}
		account := *options.Account
		proposal.account = &account
	}
	if options.Display != nil {
		if err := options.Display.validate(); err != nil {
			return MCPProposal{}, err
		}
		display := *options.Display
		proposal.display = &display
	}
	return proposal, nil
}

// Operation returns the proposal's single operation.
func (p MCPProposal) Operation() MCPOperation { return p.operation }

// Parameters returns a copy of the concrete parameter set.
func (p MCPProposal) Parameters() MCPParameters { return p.parameters.clone() }

// Account returns the account and whether the optional member was present.
func (p MCPProposal) Account() (string, bool) {
	if p.account == nil {
		return "", false
	}
	return *p.account, true
}

// Display returns the per-call display and whether it was present.
func (p MCPProposal) Display() (ProposalDisplay, bool) {
	if p.display == nil {
		return ProposalDisplay{}, false
	}
	return *p.display, true
}

// MarshalJSON emits the exact MCP proposal shape.
func (p MCPProposal) MarshalJSON() ([]byte, error) {
	if err := p.operation.validate(); err != nil {
		return nil, err
	}
	if err := p.parameters.validate(); err != nil {
		return nil, err
	}
	return json.Marshal(struct {
		Vocabulary string           `json:"vocabulary"`
		Operations []MCPOperation   `json:"operations"`
		Parameters MCPParameters    `json:"parameters"`
		Account    *string          `json:"account,omitempty"`
		Display    *ProposalDisplay `json:"display,omitempty"`
	}{
		Vocabulary: MCPVocabulary, Operations: []MCPOperation{p.operation},
		Parameters: p.parameters, Account: p.account, Display: p.display,
	})
}

// UnmarshalJSON accepts only the exact MCP per-call proposal shape.
func (p *MCPProposal) UnmarshalJSON(data []byte) error {
	parsed, err := ParseMCPProposal(data)
	if err != nil {
		return err
	}
	*p = parsed
	return nil
}

// ParseMCPProposal parses a validated proposal without retaining source bytes.
func ParseMCPProposal(source []byte) (MCPProposal, error) {
	var vocabularyRaw, operationsRaw json.RawMessage
	var parameters MCPParameters
	var account string
	var display ProposalDisplay
	seen, err := decodeStrictObject(source, map[string]func(json.RawMessage) error{
		"vocabulary": func(raw json.RawMessage) error { vocabularyRaw = append(vocabularyRaw[:0], raw...); return nil },
		"operations": func(raw json.RawMessage) error { operationsRaw = append(operationsRaw[:0], raw...); return nil },
		"parameters": func(raw json.RawMessage) error { return json.Unmarshal(raw, &parameters) },
		"account":    func(raw json.RawMessage) error { return decodeJSONString(raw, &account) },
		"display":    func(raw json.RawMessage) error { return json.Unmarshal(raw, &display) },
	})
	if err != nil {
		return MCPProposal{}, fmt.Errorf("r3: invalid proposal: %w", err)
	}
	for _, required := range []string{"vocabulary", "operations", "parameters"} {
		if _, ok := seen[required]; !ok {
			return MCPProposal{}, fmt.Errorf("r3: proposal is missing %s", required)
		}
	}
	operations, err := parseMCPOperationsParts(vocabularyRaw, operationsRaw)
	if err != nil {
		return MCPProposal{}, err
	}
	if len(operations) != 1 {
		return MCPProposal{}, errors.New("r3: proposal must contain exactly one operation")
	}
	options := ProposalOptions{}
	if _, ok := seen["account"]; ok {
		options.Account = &account
	}
	if _, ok := seen["display"]; ok {
		options.Display = &display
	}
	return NewMCPProposal(operations[0], parameters, options)
}

// ParseReferencedProposal validates a reference against exact bytes before
// parsing the bytes as an MCP per-call proposal.
func ParseReferencedProposal(reference Reference, exactBytes []byte) (MCPProposal, error) {
	if err := reference.validate(); err != nil {
		return MCPProposal{}, fmt.Errorf("r3: invalid proposal reference: %w", err)
	}
	if Digest(exactBytes) != reference.digest {
		return MCPProposal{}, errors.New("r3: referenced proposal digest mismatch")
	}
	return ParseMCPProposal(exactBytes)
}

// ValidateProposalAccount requires exact presence and value parity between a
// Core token account claim and a proposal account.
func ValidateProposalAccount(proposal MCPProposal, tokenAccount *string) error {
	proposalAccount, present := proposal.Account()
	if tokenAccount == nil {
		if present {
			return errors.New("proposal contains account but token does not")
		}
		return nil
	}
	if !present {
		return errors.New("token contains account but proposal does not")
	}
	if proposalAccount != *tokenAccount {
		return errors.New("token and proposal account values differ")
	}
	return nil
}

func decodeStrictJSONValue(data []byte) (any, error) {
	if !utf8.Valid(data) {
		return nil, errors.New("JSON must be valid UTF-8")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	value, err := readJSONValue(decoder)
	if err != nil {
		return nil, err
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return nil, err
	}
	return value, nil
}

func readJSONValue(decoder *json.Decoder) (any, error) {
	token, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	delim, isDelim := token.(json.Delim)
	if !isDelim {
		switch token.(type) {
		case nil, bool, string, json.Number:
			return token, nil
		default:
			return nil, fmt.Errorf("unsupported JSON token %T", token)
		}
	}
	switch delim {
	case '{':
		object := make(map[string]any)
		for decoder.More() {
			nameToken, err := decoder.Token()
			if err != nil {
				return nil, err
			}
			name, ok := nameToken.(string)
			if !ok {
				return nil, errors.New("expected JSON object member name")
			}
			if _, duplicate := object[name]; duplicate {
				return nil, fmt.Errorf("duplicate member %q", name)
			}
			value, err := readJSONValue(decoder)
			if err != nil {
				return nil, fmt.Errorf("member %q: %w", name, err)
			}
			object[name] = value
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') {
			return nil, errors.New("invalid JSON object close")
		}
		return object, nil
	case '[':
		var array []any
		for decoder.More() {
			value, err := readJSONValue(decoder)
			if err != nil {
				return nil, err
			}
			array = append(array, value)
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim(']') {
			return nil, errors.New("invalid JSON array close")
		}
		return array, nil
	default:
		return nil, fmt.Errorf("unexpected JSON delimiter %q", delim)
	}
}

func equalJSONValues(left, right any) bool {
	switch left := left.(type) {
	case nil:
		return right == nil
	case bool:
		right, ok := right.(bool)
		return ok && left == right
	case string:
		right, ok := right.(string)
		return ok && left == right
	case json.Number:
		right, ok := right.(json.Number)
		if !ok {
			return false
		}
		leftNumber, leftOK := normalizeJSONNumber(string(left))
		rightNumber, rightOK := normalizeJSONNumber(string(right))
		return leftOK && rightOK && leftNumber.negative == rightNumber.negative &&
			leftNumber.digits == rightNumber.digits && leftNumber.exponent.Cmp(rightNumber.exponent) == 0
	case []any:
		right, ok := right.([]any)
		if !ok || len(left) != len(right) {
			return false
		}
		for index := range left {
			if !equalJSONValues(left[index], right[index]) {
				return false
			}
		}
		return true
	case map[string]any:
		right, ok := right.(map[string]any)
		if !ok || len(left) != len(right) {
			return false
		}
		for name, value := range left {
			other, ok := right[name]
			if !ok || !equalJSONValues(value, other) {
				return false
			}
		}
		return true
	default:
		return false
	}
}

type normalizedJSONNumber struct {
	negative bool
	digits   string
	exponent *big.Int
}

func normalizeJSONNumber(source string) (normalizedJSONNumber, bool) {
	coefficient := source
	exponent := new(big.Int)
	if index := strings.IndexAny(coefficient, "eE"); index >= 0 {
		parsed, ok := new(big.Int).SetString(coefficient[index+1:], 10)
		if !ok {
			return normalizedJSONNumber{}, false
		}
		exponent.Set(parsed)
		coefficient = coefficient[:index]
	}
	negative := strings.HasPrefix(coefficient, "-")
	coefficient = strings.TrimPrefix(coefficient, "-")
	fractionDigits := 0
	if index := strings.IndexByte(coefficient, '.'); index >= 0 {
		fractionDigits = len(coefficient) - index - 1
		coefficient = coefficient[:index] + coefficient[index+1:]
	}
	coefficient = strings.TrimLeft(coefficient, "0")
	if coefficient == "" {
		return normalizedJSONNumber{digits: "0", exponent: new(big.Int)}, true
	}
	exponent.Sub(exponent, big.NewInt(int64(fractionDigits)))
	trailingZeros := len(coefficient) - len(strings.TrimRight(coefficient, "0"))
	if trailingZeros != 0 {
		coefficient = coefficient[:len(coefficient)-trailingZeros]
		exponent.Add(exponent, big.NewInt(int64(trailingZeros)))
	}
	return normalizedJSONNumber{negative: negative, digits: coefficient, exponent: exponent}, true
}

var _ json.Marshaler = MCPProposal{}
var _ json.Unmarshaler = (*MCPProposal)(nil)
