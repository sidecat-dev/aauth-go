package aauth

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

// signRequestWithSignatureKey is test-only malformed-wire construction. The
// product signer accepts only parsed signaturekey.Credential values.
func signRequestWithSignatureKey(
	request *http.Request,
	key jose.SigningKey,
	signatureKeyHeader string,
	clock Clock,
	options signaturekey.SignOptions,
) error {
	if request == nil || request.URL == nil {
		return errors.New("aauth: request URL is required")
	}
	if clock == nil {
		return errors.New("aauth: clock is required")
	}
	request.Header.Set("Signature-Key", signatureKeyHeader)
	components := []string{"@method", "@authority", "@path"}
	if request.Header.Get("Authorization") != "" {
		components = append(components, "authorization")
	}
	if testHasRequestBody(request) {
		body, err := readRequestBody(request)
		if err != nil {
			return err
		}
		digest := sha256.Sum256(body)
		request.Header.Set("Content-Digest", "sha-256=:"+base64.StdEncoding.EncodeToString(digest[:])+":")
		components = append(components, "content-digest")
		if request.Header.Get("Content-Type") != "" {
			components = append(components, "content-type")
		}
	}
	components = append(components, "signature-key")
	now := clock.Now()
	params := signatureParams(components, now.Unix(), options.ExpiresAt, options.Nonce)
	base, err := signatureBase(request, components, params)
	if err != nil {
		return err
	}
	signature, err := key.Sign(rand.Reader, []byte(base), crypto.Hash(0))
	if err != nil {
		return err
	}
	request.Header.Set("Signature-Input", "sig="+params)
	request.Header.Set("Signature", "sig=:"+base64.StdEncoding.EncodeToString(signature)+":")
	return nil
}

func signatureParams(components []string, created int64, expires time.Time, nonce string) string {
	quoted := make([]string, 0, len(components))
	for _, component := range components {
		quoted = append(quoted, strconv.Quote(component))
	}
	params := "(" + strings.Join(quoted, " ") + ");created=" + strconv.FormatInt(created, 10)
	if !expires.IsZero() {
		params += ";expires=" + strconv.FormatInt(expires.Unix(), 10)
	}
	if nonce != "" {
		params += ";nonce=" + strconv.Quote(nonce)
	}
	return params
}

func signatureBase(request *http.Request, components []string, params string) (string, error) {
	lines := make([]string, 0, len(components)+1)
	for _, component := range components {
		var value string
		switch component {
		case "@method":
			value = request.Method
		case "@authority":
			var err error
			value, err = normalizedRequestAuthority(request)
			if err != nil {
				return "", err
			}
		case "@path":
			value = request.URL.EscapedPath()
			if value == "" {
				value = "/"
			}
		default:
			if strings.HasPrefix(component, "@") {
				return "", fmt.Errorf("aauth: unsupported derived signature component %q", component)
			}
			values := request.Header.Values(http.CanonicalHeaderKey(component))
			if len(values) == 0 {
				return "", fmt.Errorf("aauth: covered header %q is absent", component)
			}
			value = strings.Join(values, ", ")
		}
		lines = append(lines, strconv.Quote(component)+": "+value)
	}
	lines = append(lines, `"@signature-params": `+params)
	return strings.Join(lines, "\n"), nil
}

func normalizedRequestAuthority(request *http.Request) (string, error) {
	authority := request.Host
	if authority == "" {
		authority = request.URL.Host
	}
	if authority == "" {
		return "", errors.New("aauth: request authority is required")
	}
	host, port, err := net.SplitHostPort(authority)
	if err != nil {
		if !strings.Contains(authority, ":") || strings.HasPrefix(authority, "[") && strings.HasSuffix(authority, "]") {
			return strings.ToLower(authority), nil
		}
		return "", fmt.Errorf("aauth: request authority %q is invalid: %w", authority, err)
	}
	host = strings.ToLower(host)
	scheme := strings.ToLower(request.URL.Scheme)
	if (scheme == "https" && port == "443") || (scheme == "http" && port == "80") {
		if strings.Contains(host, ":") {
			return "[" + host + "]", nil
		}
		return host, nil
	}
	return net.JoinHostPort(host, port), nil
}

func readRequestBody(request *http.Request) ([]byte, error) {
	if !testHasRequestBody(request) {
		return nil, nil
	}
	body, err := io.ReadAll(request.Body)
	if err != nil {
		return nil, err
	}
	request.Body = io.NopCloser(bytes.NewReader(body))
	request.ContentLength = int64(len(body))
	return body, nil
}

func testHasRequestBody(request *http.Request) bool {
	return request.Body != nil && request.Body != http.NoBody && request.ContentLength != 0
}
