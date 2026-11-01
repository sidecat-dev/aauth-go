package resource

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"strings"
)

type heldRequestSnapshot struct {
	method        string
	scheme        string
	urlHost       string
	host          string
	escapedPath   string
	rawPath       string
	rawQuery      string
	forceQuery    bool
	requestURI    string
	header        http.Header
	body          []byte
	bodyKind      heldRequestBodyKind
	hadGetBody    bool
	contentLength int64
	proto         string
	protoMajor    int
	protoMinor    int
}

type heldRequestBodyKind uint8

const (
	heldRequestBodyNil heldRequestBodyKind = iota + 1
	heldRequestBodyNoBody
	heldRequestBodyBytes
)

func snapshotHeldRequest(request *http.Request, maxBodyBytes int64) (heldRequestSnapshot, error) {
	if request == nil || request.URL == nil {
		return heldRequestSnapshot{}, errors.New("aauth: held request is required")
	}
	if maxBodyBytes <= 0 {
		return heldRequestSnapshot{}, errors.New("aauth: held request maximum body size must be positive")
	}
	if err := validateHeldRequestFeatures(request); err != nil {
		return heldRequestSnapshot{}, err
	}
	escapedPath, err := validateHeldRequestTarget(request)
	if err != nil {
		return heldRequestSnapshot{}, err
	}

	body, bodyKind, hadGetBody, err := readHeldRequestBody(request, maxBodyBytes)
	if err != nil {
		return heldRequestSnapshot{}, err
	}
	return heldRequestSnapshot{
		method:        request.Method,
		scheme:        request.URL.Scheme,
		urlHost:       request.URL.Host,
		host:          request.Host,
		escapedPath:   escapedPath,
		rawPath:       request.URL.RawPath,
		rawQuery:      request.URL.RawQuery,
		forceQuery:    request.URL.ForceQuery,
		requestURI:    request.RequestURI,
		header:        heldApplicationHeaders(request.Header),
		body:          append([]byte(nil), body...),
		bodyKind:      bodyKind,
		hadGetBody:    hadGetBody,
		contentLength: request.ContentLength,
		proto:         request.Proto,
		protoMajor:    request.ProtoMajor,
		protoMinor:    request.ProtoMinor,
	}, nil
}

func validateHeldRequestFeatures(request *http.Request) error {
	if strings.EqualFold(request.Method, http.MethodConnect) {
		return errors.New("aauth: held request does not support CONNECT")
	}
	if len(request.Trailer) != 0 {
		return errors.New("aauth: held request does not support trailers")
	}
	if len(request.TransferEncoding) != 0 {
		return errors.New("aauth: held request does not support transfer encoding")
	}
	for name, values := range request.Header {
		if strings.EqualFold(name, "Connection") && onlyConnectionOptions(values) {
			continue
		}
		if isHeldRequestHopByHopHeader(name) {
			return fmt.Errorf("aauth: held request does not support hop-by-hop header %q", name)
		}
	}
	return nil
}

// onlyConnectionOptions reports whether a Connection field carries only the
// close and keep-alive options. They describe the connection the request
// arrived on, not the request, so a retained request leaves them behind (RFC
// 9110, Section 7.6.1), as it does request.Close. Any other option names a
// further hop-by-hop field, which a retained request does not support.
func onlyConnectionOptions(values []string) bool {
	for _, value := range values {
		for _, option := range strings.Split(value, ",") {
			option = strings.TrimSpace(option)
			if !strings.EqualFold(option, "close") && !strings.EqualFold(option, "keep-alive") {
				return false
			}
		}
	}
	return true
}

func isHeldRequestHopByHopHeader(name string) bool {
	switch {
	case strings.EqualFold(name, "Connection"),
		strings.EqualFold(name, "Proxy-Connection"),
		strings.EqualFold(name, "Keep-Alive"),
		strings.EqualFold(name, "Proxy-Authenticate"),
		strings.EqualFold(name, "Proxy-Authorization"),
		strings.EqualFold(name, "TE"),
		strings.EqualFold(name, "Trailer"),
		strings.EqualFold(name, "Transfer-Encoding"),
		strings.EqualFold(name, "Upgrade"):
		return true
	default:
		return false
	}
}

func validateHeldRequestTarget(request *http.Request) (string, error) {
	if request.URL.Opaque != "" || request.URL.User != nil || request.URL.Fragment != "" || request.URL.RawFragment != "" {
		return "", errors.New("aauth: held request URL contains unsupported target state")
	}
	escapedPath := request.URL.EscapedPath()
	if escapedPath == "" || !strings.HasPrefix(escapedPath, "/") {
		return "", errors.New("aauth: held request path must be absolute")
	}
	if request.URL.RawPath != "" && request.URL.RawPath != escapedPath {
		return "", errors.New("aauth: held request raw path is invalid")
	}
	path, err := url.PathUnescape(escapedPath)
	if err != nil || path != request.URL.Path {
		return "", errors.New("aauth: held request escaped path is invalid")
	}
	probe := &url.URL{Path: path, RawPath: escapedPath}
	if probe.EscapedPath() != escapedPath {
		return "", errors.New("aauth: held request escaped path cannot be reconstructed")
	}
	target := heldRequestTarget(escapedPath, request.URL.RawQuery, request.URL.ForceQuery)
	parsed, err := url.ParseRequestURI(target)
	if err != nil || parsed.EscapedPath() != escapedPath || parsed.RawQuery != request.URL.RawQuery || parsed.ForceQuery != request.URL.ForceQuery {
		return "", errors.New("aauth: held request target cannot be reconstructed")
	}
	return escapedPath, nil
}

func heldRequestTarget(escapedPath, rawQuery string, forceQuery bool) string {
	target := escapedPath
	if forceQuery || rawQuery != "" {
		target += "?" + rawQuery
	}
	return target
}

// heldApplicationHeaders returns the fields a retained request carries to
// the application: every field but the request proof and Connection.
func heldApplicationHeaders(header http.Header) http.Header {
	cloned := header.Clone()
	for name := range cloned {
		if strings.EqualFold(name, "Signature-Key") || strings.EqualFold(name, "Signature-Input") || strings.EqualFold(name, "Signature") ||
			strings.EqualFold(name, "Connection") {
			delete(cloned, name)
		}
	}
	return cloned
}

func readHeldRequestBody(request *http.Request, maxBodyBytes int64) ([]byte, heldRequestBodyKind, bool, error) {
	if request.Body == nil {
		if request.GetBody != nil {
			return nil, 0, false, errors.New("aauth: held request with nil body must not define GetBody")
		}
		return nil, heldRequestBodyNil, false, nil
	}
	if request.Body == http.NoBody {
		return nil, heldRequestBodyNoBody, request.GetBody != nil, nil
	}
	original := request.Body
	hadGetBody := request.GetBody != nil
	var source io.Reader = original
	if maxBodyBytes < math.MaxInt64 {
		source = io.LimitReader(original, maxBodyBytes+1)
	}
	body, err := io.ReadAll(source)
	if err != nil {
		request.Body = &recoveredApplicationBody{
			Reader:   io.MultiReader(bytes.NewReader(body), original),
			original: original,
		}
		return nil, 0, false, fmt.Errorf("aauth: read held request body: %w", err)
	}
	if int64(len(body)) > maxBodyBytes {
		request.Body = &recoveredApplicationBody{
			Reader:   io.MultiReader(bytes.NewReader(body), original),
			original: original,
		}
		return nil, 0, false, fmt.Errorf("aauth: held request body exceeds %d bytes", maxBodyBytes)
	}
	closeErr := original.Close()
	installHeldRequestBodyWithGetBody(request, body, hadGetBody)
	if closeErr != nil {
		return nil, 0, false, fmt.Errorf("aauth: close held request body: %w", closeErr)
	}
	return body, heldRequestBodyBytes, hadGetBody, nil
}

func installHeldRequestBody(request *http.Request, body []byte) {
	installHeldRequestBodyWithGetBody(request, body, true)
}

func installHeldRequestBodyWithGetBody(request *http.Request, body []byte, withGetBody bool) {
	owned := append([]byte(nil), body...)
	request.Body = io.NopCloser(bytes.NewReader(owned))
	request.GetBody = nil
	if withGetBody {
		request.GetBody = func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(owned)), nil
		}
	}
}

func (snapshot heldRequestSnapshot) request(ctx context.Context, principal AuthPrincipal) (*http.Request, error) {
	if ctx == nil {
		return nil, errors.New("aauth: held request context is required")
	}
	path, err := url.PathUnescape(snapshot.escapedPath)
	if err != nil {
		return nil, fmt.Errorf("aauth: decode held request path: %w", err)
	}
	body := append([]byte(nil), snapshot.body...)
	replayedURL := &url.URL{
		Scheme:     snapshot.scheme,
		Host:       snapshot.urlHost,
		Path:       path,
		RawPath:    snapshot.rawPath,
		RawQuery:   snapshot.rawQuery,
		ForceQuery: snapshot.forceQuery,
	}
	if replayedURL.EscapedPath() != snapshot.escapedPath {
		return nil, errors.New("aauth: held request escaped path no longer matches its retained representation")
	}
	bodyReader := io.ReadCloser(nil)
	if snapshot.bodyKind == heldRequestBodyNoBody {
		bodyReader = http.NoBody
	} else if snapshot.bodyKind == heldRequestBodyBytes {
		bodyReader = io.NopCloser(bytes.NewReader(body))
	} else if snapshot.bodyKind != heldRequestBodyNil {
		return nil, errors.New("aauth: held request body representation is invalid")
	}
	request := &http.Request{
		Method:        snapshot.method,
		URL:           replayedURL,
		Host:          snapshot.host,
		RequestURI:    snapshot.requestURI,
		Header:        snapshot.header.Clone(),
		Body:          bodyReader,
		ContentLength: snapshot.contentLength,
		Proto:         snapshot.proto,
		ProtoMajor:    snapshot.protoMajor,
		ProtoMinor:    snapshot.protoMinor,
	}
	if snapshot.hadGetBody {
		request.GetBody = func() (io.ReadCloser, error) {
			if snapshot.bodyKind == heldRequestBodyNoBody {
				return http.NoBody, nil
			}
			return io.NopCloser(bytes.NewReader(body)), nil
		}
	}
	if principal.Scope != nil {
		principal.Scope = append(make([]string, 0, len(principal.Scope)), principal.Scope...)
	}
	principal.AdditionalClaims = cloneAdditionalClaims(principal.AdditionalClaims)
	return request.WithContext(context.WithValue(ctx, authPrincipalContextKey{}, principal)), nil
}
