package aauth

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/dunglas/httpsfv"
)

// SignatureErrorCode identifies a failure in the AAuth HTTP Message
// Signatures profile. Its values are defined by the Signature-Key draft.
type SignatureErrorCode string

const (
	SignatureErrorInvalidRequest       SignatureErrorCode = "invalid_request"
	SignatureErrorInvalidInput         SignatureErrorCode = "invalid_input"
	SignatureErrorUnsupportedAlgorithm SignatureErrorCode = "unsupported_algorithm"
	SignatureErrorUnsupportedScheme    SignatureErrorCode = "unsupported_scheme"
	SignatureErrorInvalidSignature     SignatureErrorCode = "invalid_signature"
	SignatureErrorInvalidKey           SignatureErrorCode = "invalid_key"
	SignatureErrorUnknownKey           SignatureErrorCode = "unknown_key"
	SignatureErrorInvalidJWT           SignatureErrorCode = "invalid_jwt"
	SignatureErrorExpiredJWT           SignatureErrorCode = "expired_jwt"
	SignatureErrorIssuerMissing        SignatureErrorCode = "issuer_missing"
	SignatureErrorIssuerMismatch       SignatureErrorCode = "issuer_mismatch"
)

// SignatureError preserves a machine-readable failure code while retaining
// the underlying cause for errors.Is and errors.As inspection.
type SignatureError struct {
	Code               SignatureErrorCode
	RequiredInput      []string
	AcceptedAlgorithms []string
	AcceptedSchemes    []string
	publicDetail       string
	Cause              error
}

// PublicDetail returns an optional diagnostic that is safe to include in a
// remote Problem Details response. Cause remains local-only diagnostic
// evidence and must not be exposed by protocol adapters.
func (err *SignatureError) PublicDetail() string {
	if err == nil {
		return ""
	}
	return err.publicDetail
}

func (err *SignatureError) Error() string {
	if err == nil {
		return "aauth: unknown signature error"
	}
	if err.Cause != nil {
		return fmt.Sprintf("aauth: signature %s: %v", err.Code, err.Cause)
	}
	return fmt.Sprintf("aauth: signature %s", err.Code)
}

func (err *SignatureError) Unwrap() error {
	if err == nil {
		return nil
	}
	return err.Cause
}

// ProblemType returns the Signature-Key Problem Details type URI matching
// this error code.
func (err SignatureError) ProblemType() string {
	return "urn:ietf:params:sig-error:" + string(err.Code)
}

func newSignatureError(code SignatureErrorCode, cause error) error {
	return &SignatureError{Code: code, Cause: cause}
}

func signatureErrorWithRequiredInput(cause error, required []string) error {
	unique := make([]string, 0, len(required))
	seen := make(map[string]struct{}, len(required))
	for _, component := range required {
		component = strings.ToLower(component)
		if _, exists := seen[component]; exists {
			continue
		}
		seen[component] = struct{}{}
		unique = append(unique, component)
	}
	return &SignatureError{
		Code:          SignatureErrorInvalidInput,
		RequiredInput: unique,
		Cause:         cause,
	}
}

// FormatSignatureError serializes a Signature-Error structured-field
// dictionary. It emits only standardized members and never serializes the
// diagnostic cause.
func FormatSignatureError(value SignatureError) (string, error) {
	if len(value.RequiredInput) > 0 && value.Code != SignatureErrorInvalidInput {
		return "", errors.New("aauth: required_input applies only to invalid_input")
	}
	dictionary := httpsfv.NewDictionary()
	dictionary.Add("error", httpsfv.NewItem(httpsfv.Token(value.Code)))
	if len(value.RequiredInput) > 0 {
		innerList, err := structuredStringList(value.RequiredInput)
		if err != nil {
			return "", fmt.Errorf("aauth: Signature-Error required_input: %w", err)
		}
		dictionary.Add("required_input", innerList)
	}
	encoded, err := httpsfv.Marshal(dictionary)
	if err != nil {
		return "", fmt.Errorf("aauth: format Signature-Error: %w", err)
	}
	return encoded, nil
}

func structuredStringList(values []string) (httpsfv.InnerList, error) {
	if len(values) == 0 {
		return httpsfv.InnerList{}, errors.New("list is required")
	}
	items := make([]httpsfv.Item, 0, len(values))
	for _, value := range values {
		if value == "" {
			return httpsfv.InnerList{}, errors.New("list member is empty")
		}
		item := httpsfv.NewItem(value)
		if _, err := httpsfv.Marshal(item); err != nil {
			return httpsfv.InnerList{}, fmt.Errorf("list member %q: %w", value, err)
		}
		items = append(items, item)
	}
	return httpsfv.InnerList{Items: items, Params: httpsfv.NewParams()}, nil
}

// ParseSignatureError parses the RFC 8941 Signature-Error dictionary. Unknown
// dictionary members and member parameters are ignored as required by the
// Signature-Key draft.
func ParseSignatureError(header string) (*SignatureError, error) {
	return parseSignatureErrorValues([]string{header})
}

func parseSignatureErrorValues(values []string) (*SignatureError, error) {
	dictionary, err := httpsfv.UnmarshalDictionary(values)
	if err != nil {
		return nil, fmt.Errorf("aauth: parse Signature-Error: %w", err)
	}
	errorMember, ok := dictionary.Get("error")
	if !ok {
		return nil, errors.New("aauth: Signature-Error error is required")
	}
	errorItem, ok := errorMember.(httpsfv.Item)
	if !ok {
		return nil, errors.New("aauth: Signature-Error error must be a token")
	}
	errorToken, ok := errorItem.Value.(httpsfv.Token)
	if !ok {
		return nil, errors.New("aauth: Signature-Error error is invalid")
	}

	result := SignatureError{Code: SignatureErrorCode(errorToken)}
	if result.Code == SignatureErrorInvalidInput {
		if requiredInput, ok := dictionary.Get("required_input"); ok {
			result.RequiredInput, err = parseStructuredStringList(requiredInput)
			if err != nil {
				return nil, fmt.Errorf("aauth: parse Signature-Error required_input: %w", err)
			}
		}
	}
	return &result, nil
}

// FormatAcceptSignatureAlgorithms serializes the fully specified JOSE
// algorithms accepted by a verifier as an RFC 8941 List of Tokens.
func FormatAcceptSignatureAlgorithms(values []string) (string, error) {
	return formatStructuredTokenList("Accept-Signature-Alg", values)
}

// FormatAcceptSignatureSchemes serializes the Signature-Key schemes accepted
// by a verifier as an RFC 8941 List of Tokens.
func FormatAcceptSignatureSchemes(values []string) (string, error) {
	return formatStructuredTokenList("Accept-Signature-Scheme", values)
}

func formatStructuredTokenList(name string, values []string) (string, error) {
	if len(values) == 0 {
		return "", fmt.Errorf("aauth: %s requires at least one value", name)
	}
	list := make(httpsfv.List, 0, len(values))
	for _, value := range values {
		if value == "" {
			return "", fmt.Errorf("aauth: %s contains an empty value", name)
		}
		list = append(list, httpsfv.NewItem(httpsfv.Token(value)))
	}
	encoded, err := httpsfv.Marshal(list)
	if err != nil {
		return "", fmt.Errorf("aauth: format %s: %w", name, err)
	}
	return encoded, nil
}

func parseStructuredTokenList(name string, values []string) ([]string, error) {
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

func parseStructuredStringList(member httpsfv.Member) ([]string, error) {
	innerList, ok := member.(httpsfv.InnerList)
	if !ok || len(innerList.Items) == 0 {
		return nil, errors.New("non-empty inner list is required")
	}
	values := make([]string, 0, len(innerList.Items))
	for _, item := range innerList.Items {
		value, ok := item.Value.(string)
		if !ok {
			return nil, errors.New("inner list members must be strings")
		}
		if value == "" {
			return nil, errors.New("inner list members must not be empty")
		}
		values = append(values, value)
	}
	return values, nil
}

// DecodeSignatureErrorResponse obtains machine-readable signature failure
// information from an HTTP response. Signature-Error is authoritative over a
// companion Problem Details body, so this function never lets a conflicting
// body replace the header's code or structured members.
func DecodeSignatureErrorResponse(response *http.Response) (*SignatureError, error) {
	if response == nil {
		return nil, errors.New("aauth: signature error response is required")
	}
	if values := response.Header.Values("Signature-Error"); len(values) > 0 {
		decoded, err := parseSignatureErrorValues(values)
		if err != nil {
			return nil, err
		}
		decoded.AcceptedAlgorithms, err = parseStructuredTokenList(
			"Accept-Signature-Alg",
			response.Header.Values("Accept-Signature-Alg"),
		)
		if err != nil {
			return nil, err
		}
		decoded.AcceptedSchemes, err = parseStructuredTokenList(
			"Accept-Signature-Scheme",
			response.Header.Values("Accept-Signature-Scheme"),
		)
		if err != nil {
			return nil, err
		}
		return decoded, nil
	}
	return nil, errors.New("aauth: Signature-Error header is required")
}
