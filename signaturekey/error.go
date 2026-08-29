package signaturekey

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/dunglas/httpsfv"
)

// ErrorCode is one protocol-visible Signature-Key failure class.
type ErrorCode string

const (
	ErrorInvalidRequest       ErrorCode = "invalid_request"
	ErrorInvalidInput         ErrorCode = "invalid_input"
	ErrorUnsupportedAlgorithm ErrorCode = "unsupported_algorithm"
	ErrorUnsupportedScheme    ErrorCode = "unsupported_scheme"
	ErrorInvalidSignature     ErrorCode = "invalid_signature"
	ErrorInvalidKey           ErrorCode = "invalid_key"
	ErrorUnknownKey           ErrorCode = "unknown_key"
	ErrorInvalidJWT           ErrorCode = "invalid_jwt"
	ErrorExpiredJWT           ErrorCode = "expired_jwt"
	ErrorIssuerMissing        ErrorCode = "issuer_missing"
	ErrorIssuerMismatch       ErrorCode = "issuer_mismatch"
)

// Error preserves a machine-readable failure while keeping its diagnostic
// cause local to the verifier.
type Error struct {
	Code               ErrorCode
	RequiredInput      []string
	AcceptedAlgorithms []string
	AcceptedSchemes    []Scheme
	publicDetail       string
	Cause              error
}

// NewError constructs a typed failure with a local-only diagnostic cause.
func NewError(code ErrorCode, cause error) *Error {
	return &Error{Code: code, Cause: cause}
}

// NewPublicError constructs a typed failure with a fixed detail that protocol
// adapters may safely disclose. The cause remains local-only.
func NewPublicError(code ErrorCode, detail string, cause error) *Error {
	return &Error{Code: code, publicDetail: detail, Cause: cause}
}

// PublicDetail returns the fixed detail explicitly marked safe for a remote
// response.
func (failure *Error) PublicDetail() string {
	if failure == nil {
		return ""
	}
	return failure.publicDetail
}

func (failure *Error) Error() string {
	if failure == nil {
		return "aauth: unknown signature error"
	}
	if failure.Cause != nil {
		return fmt.Sprintf("aauth: signature %s: %v", failure.Code, failure.Cause)
	}
	return fmt.Sprintf("aauth: signature %s", failure.Code)
}

func (failure *Error) Unwrap() error {
	if failure == nil {
		return nil
	}
	return failure.Cause
}

// ProblemType returns the registered Signature-Key Problem Details type.
func (failure Error) ProblemType() string {
	return "urn:ietf:params:sig-error:" + string(failure.Code)
}

func newError(code ErrorCode, cause error) error {
	return &Error{Code: code, Cause: cause}
}

// FormatError serializes the standardized members of Signature-Error. Local
// diagnostic causes are never placed on the wire.
func FormatError(value Error) (string, error) {
	if len(value.RequiredInput) > 0 && value.Code != ErrorInvalidInput {
		return "", errors.New("aauth: required_input applies only to invalid_input")
	}
	dictionary := httpsfv.NewDictionary()
	dictionary.Add("error", httpsfv.NewItem(httpsfv.Token(value.Code)))
	if len(value.RequiredInput) > 0 {
		items := make([]httpsfv.Item, 0, len(value.RequiredInput))
		for _, component := range value.RequiredInput {
			if component == "" {
				return "", errors.New("aauth: required_input contains an empty value")
			}
			items = append(items, httpsfv.NewItem(component))
		}
		dictionary.Add("required_input", httpsfv.InnerList{Items: items, Params: httpsfv.NewParams()})
	}
	encoded, err := httpsfv.Marshal(dictionary)
	if err != nil {
		return "", fmt.Errorf("aauth: format Signature-Error: %w", err)
	}
	return encoded, nil
}

// ParseError parses one Signature-Error structured-field dictionary.
func ParseError(header string) (*Error, error) {
	return parseErrorValues([]string{header})
}

func parseErrorValues(values []string) (*Error, error) {
	dictionary, err := httpsfv.UnmarshalDictionary(values)
	if err != nil {
		return nil, fmt.Errorf("aauth: parse Signature-Error: %w", err)
	}
	member, ok := dictionary.Get("error")
	if !ok {
		return nil, errors.New("aauth: Signature-Error error is required")
	}
	item, ok := member.(httpsfv.Item)
	if !ok {
		return nil, errors.New("aauth: Signature-Error error must be a token")
	}
	token, ok := item.Value.(httpsfv.Token)
	if !ok || token == "" {
		return nil, errors.New("aauth: Signature-Error error is invalid")
	}
	result := &Error{Code: ErrorCode(token)}
	if result.Code != ErrorInvalidInput {
		return result, nil
	}
	required, ok := dictionary.Get("required_input")
	if !ok {
		return result, nil
	}
	list, ok := required.(httpsfv.InnerList)
	if !ok || len(list.Items) == 0 {
		return nil, errors.New("aauth: Signature-Error required_input must be a non-empty inner list")
	}
	result.RequiredInput = make([]string, 0, len(list.Items))
	for _, item := range list.Items {
		value, ok := item.Value.(string)
		if !ok || value == "" {
			return nil, errors.New("aauth: Signature-Error required_input members must be strings")
		}
		result.RequiredInput = append(result.RequiredInput, value)
	}
	return result, nil
}

// DecodeErrorResponse decodes Signature-Error and its negotiation headers.
// The structured header is authoritative over any response body.
func DecodeErrorResponse(response *http.Response) (*Error, error) {
	if response == nil {
		return nil, errors.New("aauth: signature error response is required")
	}
	values := response.Header.Values("Signature-Error")
	if len(values) == 0 {
		return nil, errors.New("aauth: Signature-Error header is required")
	}
	decoded, err := parseErrorValues(values)
	if err != nil {
		return nil, err
	}
	decoded.AcceptedAlgorithms, err = parseTokenList("Accept-Signature-Alg", response.Header.Values("Accept-Signature-Alg"))
	if err != nil {
		return nil, err
	}
	schemeNames, err := parseTokenList("Accept-Signature-Scheme", response.Header.Values("Accept-Signature-Scheme"))
	if err != nil {
		return nil, err
	}
	for _, name := range schemeNames {
		decoded.AcceptedSchemes = append(decoded.AcceptedSchemes, Scheme(name))
	}
	return decoded, nil
}

// FormatAcceptAlgorithms serializes Accept-Signature-Alg.
func FormatAcceptAlgorithms(values []string) (string, error) {
	return formatTokenList("Accept-Signature-Alg", values)
}

// FormatAcceptSchemes serializes Accept-Signature-Scheme.
func FormatAcceptSchemes[T ~string](values []T) (string, error) {
	text := make([]string, 0, len(values))
	for _, value := range values {
		text = append(text, string(value))
	}
	return formatTokenList("Accept-Signature-Scheme", text)
}

func formatTokenList(name string, values []string) (string, error) {
	if len(values) == 0 {
		return "", fmt.Errorf("aauth: %s requires at least one value", name)
	}
	list := make(httpsfv.List, 0, len(values))
	for _, value := range values {
		if value == "" || strings.ContainsAny(value, " \t\r\n,") {
			return "", fmt.Errorf("aauth: %s contains an invalid value %q", name, value)
		}
		list = append(list, httpsfv.NewItem(httpsfv.Token(value)))
	}
	encoded, err := httpsfv.Marshal(list)
	if err != nil {
		return "", fmt.Errorf("aauth: format %s: %w", name, err)
	}
	return encoded, nil
}

func parseTokenList(name string, values []string) ([]string, error) {
	if len(values) == 0 {
		return nil, nil
	}
	list, err := httpsfv.UnmarshalList(values)
	if err != nil {
		return nil, fmt.Errorf("aauth: parse %s: %w", name, err)
	}
	result := make([]string, 0, len(list))
	for _, member := range list {
		item, ok := member.(httpsfv.Item)
		if !ok {
			return nil, fmt.Errorf("aauth: %s members must be tokens", name)
		}
		value, ok := item.Value.(httpsfv.Token)
		if !ok || value == "" {
			return nil, fmt.Errorf("aauth: %s members must be non-empty tokens", name)
		}
		result = append(result, string(value))
	}
	if len(result) == 0 {
		return nil, fmt.Errorf("aauth: %s must not be empty", name)
	}
	return result, nil
}
