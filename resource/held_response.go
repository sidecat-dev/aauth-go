package resource

import (
	"bufio"
	"errors"
	"fmt"
	"mime"
	"net"
	"net/http"
	"net/textproto"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

var errHeldResponseFinalized = errors.New("held response capture is finalized")

type heldResponseSnapshot struct {
	statusCode int
	header     http.Header
	body       []byte
	trailer    http.Header
}

type heldResponseWriter struct {
	mu             sync.Mutex
	header         http.Header
	maxBodyBytes   int64
	maxHeaderBytes int64

	committed       bool
	statusCode      int
	committedHeader http.Header
	declaredTrailer []string
	contentLength   int64
	body            []byte
	captureErr      error

	finalized     bool
	finalSnapshot heldResponseSnapshot
	finalErr      error
}

func newHeldResponseWriter(maxBodyBytes, maxHeaderBytes int64) (*heldResponseWriter, error) {
	if maxBodyBytes <= 0 {
		return nil, fmt.Errorf("held response capture body limit must be positive: %d", maxBodyBytes)
	}
	if maxHeaderBytes <= 0 {
		return nil, fmt.Errorf("held response capture header limit must be positive: %d", maxHeaderBytes)
	}
	return &heldResponseWriter{
		header:         make(http.Header),
		maxBodyBytes:   maxBodyBytes,
		maxHeaderBytes: maxHeaderBytes,
		contentLength:  -1,
	}, nil
}

func (writer *heldResponseWriter) Header() http.Header {
	writer.mu.Lock()
	defer writer.mu.Unlock()
	// Like net/http.ResponseWriter, the returned map is handler-owned and is not
	// safe for concurrent mutation. All header use must quiesce before Write,
	// WriteHeader, or snapshot.
	return writer.header
}

func (writer *heldResponseWriter) WriteHeader(statusCode int) {
	writer.mu.Lock()
	defer writer.mu.Unlock()
	if writer.committed || writer.finalized || writer.captureErr != nil {
		return
	}
	if err := validateHeldResponseStatus(statusCode); err != nil {
		writer.failLocked(err)
		return
	}
	writer.commitLocked(statusCode)
}

func (writer *heldResponseWriter) Write(body []byte) (int, error) {
	writer.mu.Lock()
	defer writer.mu.Unlock()
	if writer.finalized {
		if writer.finalErr != nil {
			return 0, writer.finalErr
		}
		return 0, errHeldResponseFinalized
	}
	if writer.captureErr != nil {
		return 0, writer.captureErr
	}
	if !writer.committed {
		writer.commitLocked(http.StatusOK)
		if writer.captureErr != nil {
			return 0, writer.captureErr
		}
	}
	if len(body) == 0 {
		return 0, nil
	}
	if !heldResponseBodyAllowed(writer.statusCode) {
		err := fmt.Errorf("held response status %d: %w", writer.statusCode, http.ErrBodyNotAllowed)
		return 0, writer.failLocked(err)
	}
	if int64(len(body)) > writer.maxBodyBytes-int64(len(writer.body)) {
		return 0, writer.failLocked(fmt.Errorf("held response body exceeds %d bytes", writer.maxBodyBytes))
	}
	if writer.contentLength >= 0 && int64(len(body)) > writer.contentLength-int64(len(writer.body)) {
		return 0, writer.failLocked(http.ErrContentLength)
	}
	writer.body = append(writer.body, body...)
	return len(body), nil
}

func (writer *heldResponseWriter) snapshot() (heldResponseSnapshot, error) {
	writer.mu.Lock()
	defer writer.mu.Unlock()
	if writer.finalized {
		return cloneHeldResponseSnapshot(writer.finalSnapshot), writer.finalErr
	}
	writer.finalized = true
	if !writer.committed {
		writer.commitLocked(http.StatusOK)
	}
	if writer.captureErr != nil {
		return writer.finishWithErrorLocked(writer.captureErr)
	}
	if heldResponseBodyAllowed(writer.statusCode) && writer.committedHeader.Get("Content-Type") == "" &&
		writer.committedHeader.Get("Content-Encoding") == "" && len(writer.body) != 0 {
		writer.committedHeader.Set("Content-Type", http.DetectContentType(writer.body))
	}
	trailer, err := writer.collectTrailersLocked()
	if err != nil {
		return writer.finishWithErrorLocked(err)
	}
	if !heldResponseBodyAllowed(writer.statusCode) && len(trailer) != 0 {
		return writer.finishWithErrorLocked(fmt.Errorf("held response status %d does not permit trailers", writer.statusCode))
	}
	if err := validateHeldResponseHeaderLimit(writer.committedHeader, trailer, writer.maxHeaderBytes); err != nil {
		return writer.finishWithErrorLocked(err)
	}
	if writer.contentLength >= 0 && writer.contentLength != int64(len(writer.body)) {
		return writer.finishWithErrorLocked(fmt.Errorf(
			"held response Content-Length is %d, captured body is %d bytes",
			writer.contentLength,
			len(writer.body),
		))
	}
	writer.finalSnapshot = heldResponseSnapshot{
		statusCode: writer.statusCode,
		header:     writer.committedHeader.Clone(),
		body:       append([]byte(nil), writer.body...),
		trailer:    trailer.Clone(),
	}
	writer.releaseMutableStateLocked()
	return cloneHeldResponseSnapshot(writer.finalSnapshot), nil
}

func (writer *heldResponseWriter) Flush() {
	writer.markUnsupported("Flush")
}

func (writer *heldResponseWriter) FlushError() error {
	writer.markUnsupported("FlushError")
	return http.ErrNotSupported
}

func (writer *heldResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	writer.markUnsupported("Hijack")
	return nil, nil, http.ErrNotSupported
}

func (writer *heldResponseWriter) Push(string, *http.PushOptions) error {
	writer.markUnsupported("Push")
	return http.ErrNotSupported
}

func (writer *heldResponseWriter) EnableFullDuplex() error {
	writer.markUnsupported("EnableFullDuplex")
	return http.ErrNotSupported
}

func (writer *heldResponseWriter) SetReadDeadline(time.Time) error {
	writer.markUnsupported("SetReadDeadline")
	return http.ErrNotSupported
}

func (writer *heldResponseWriter) SetWriteDeadline(time.Time) error {
	writer.markUnsupported("SetWriteDeadline")
	return http.ErrNotSupported
}

func (writer *heldResponseWriter) markUnsupported(operation string) {
	writer.mu.Lock()
	defer writer.mu.Unlock()
	if writer.finalized || writer.captureErr != nil {
		return
	}
	writer.captureErr = fmt.Errorf("held response capture does not support %s: %w", operation, http.ErrNotSupported)
}

func (writer *heldResponseWriter) commitLocked(statusCode int) {
	header, declaredTrailer, contentLength, err := captureHeldResponseHeader(writer.header, writer.maxHeaderBytes)
	if err != nil {
		writer.failLocked(err)
		return
	}
	writer.committed = true
	writer.statusCode = statusCode
	writer.committedHeader = header
	writer.declaredTrailer = declaredTrailer
	writer.contentLength = contentLength

	trailer, err := writer.collectTrailersLocked()
	if err != nil {
		writer.failLocked(err)
		return
	}
	if err := validateHeldResponseHeaderLimit(header, trailer, writer.maxHeaderBytes); err != nil {
		writer.failLocked(err)
	}
}

func (writer *heldResponseWriter) collectTrailersLocked() (http.Header, error) {
	trailer := make(http.Header)
	remaining := writer.maxHeaderBytes
	if err := consumeHeldHeader(writer.committedHeader, &remaining, writer.maxHeaderBytes, "held response"); err != nil {
		return nil, err
	}
	for _, name := range writer.declaredTrailer {
		for _, key := range sortedHeldResponseHeaderKeys(writer.header) {
			if strings.HasPrefix(key, http.TrailerPrefix) || !strings.EqualFold(key, name) {
				continue
			}
			if !validHeldResponseHeaderName(key) {
				return nil, fmt.Errorf("held response trailer name %q is invalid", key)
			}
			if err := appendHeldResponseTrailerValues(trailer, name, writer.header[key], &remaining, writer.maxHeaderBytes); err != nil {
				return nil, err
			}
		}
	}

	keys := sortedHeldResponseHeaderKeys(writer.header)
	for _, key := range keys {
		if !strings.HasPrefix(key, http.TrailerPrefix) {
			continue
		}
		name, err := validateHeldResponseTrailerName(strings.TrimPrefix(key, http.TrailerPrefix))
		if err != nil {
			return nil, err
		}
		if err := appendHeldResponseTrailerValues(trailer, name, writer.header[key], &remaining, writer.maxHeaderBytes); err != nil {
			return nil, err
		}
	}
	return trailer, nil
}

func appendHeldResponseTrailerValues(
	trailer http.Header,
	name string,
	values []string,
	remaining *int64,
	maximum int64,
) error {
	if err := validateHeldResponseHeaderValues(name, values); err != nil {
		return err
	}
	for _, value := range values {
		if !consumeHeldResponseHeaderLine(remaining, name, value) {
			return fmt.Errorf("held response headers exceed %d bytes", maximum)
		}
		trailer[name] = append(trailer[name], value)
	}
	return nil
}

func (writer *heldResponseWriter) failLocked(err error) error {
	if writer.captureErr == nil {
		writer.captureErr = err
	}
	return writer.captureErr
}

func (writer *heldResponseWriter) finishWithErrorLocked(err error) (heldResponseSnapshot, error) {
	writer.finalErr = err
	writer.finalSnapshot = heldResponseSnapshot{}
	writer.releaseMutableStateLocked()
	return heldResponseSnapshot{}, err
}

func (writer *heldResponseWriter) releaseMutableStateLocked() {
	writer.header = make(http.Header)
	writer.committedHeader = nil
	writer.declaredTrailer = nil
	writer.body = nil
}

func captureHeldResponseHeader(source http.Header, maxHeaderBytes int64) (http.Header, []string, int64, error) {
	if err := validateHeldResponseHeaderLimit(source, nil, maxHeaderBytes); err != nil {
		return nil, nil, -1, err
	}

	header := make(http.Header, len(source))
	seen := make(map[string]string, len(source))
	var declaredTrailer []string
	declaredSeen := make(map[string]struct{})
	for _, key := range sortedHeldResponseHeaderKeys(source) {
		values := source[key]
		if strings.HasPrefix(key, http.TrailerPrefix) {
			name, err := validateHeldResponseTrailerName(strings.TrimPrefix(key, http.TrailerPrefix))
			if err != nil {
				return nil, nil, -1, err
			}
			if err := validateHeldResponseHeaderValues(name, values); err != nil {
				return nil, nil, -1, err
			}
			continue
		}
		if !validHeldResponseHeaderName(key) {
			return nil, nil, -1, fmt.Errorf("held response header name %q is invalid", key)
		}
		canonical := textproto.CanonicalMIMEHeaderKey(key)
		if previous, duplicate := seen[canonical]; duplicate {
			return nil, nil, -1, fmt.Errorf("held response header %q repeats with spelling %q", canonical, previous)
		}
		seen[canonical] = key
		if err := validateHeldResponseHeaderValues(canonical, values); err != nil {
			return nil, nil, -1, err
		}
		if canonical == "Trailer" {
			for _, value := range values {
				for _, element := range strings.Split(value, ",") {
					element = strings.Trim(element, " \t")
					if element == "" {
						continue
					}
					name, err := validateHeldResponseTrailerName(element)
					if err != nil {
						return nil, nil, -1, err
					}
					if _, duplicate := declaredSeen[name]; duplicate {
						continue
					}
					declaredSeen[name] = struct{}{}
					declaredTrailer = append(declaredTrailer, name)
				}
			}
			continue
		}
		if unsafeHeldResponseHeader[canonical] {
			return nil, nil, -1, fmt.Errorf("held response header %q requires unsupported connection or framing semantics", canonical)
		}
		header[canonical] = append([]string(nil), values...)
	}
	for _, name := range declaredTrailer {
		delete(header, name)
	}

	if err := rejectHeldResponseEventStream(header); err != nil {
		return nil, nil, -1, err
	}
	contentLength, err := parseHeldResponseContentLength(header)
	if err != nil {
		return nil, nil, -1, err
	}
	return header, declaredTrailer, contentLength, nil
}

func validateHeldResponseStatus(statusCode int) error {
	if statusCode < 200 || statusCode > 599 {
		return fmt.Errorf("held response status %d is invalid", statusCode)
	}
	return nil
}

func heldResponseBodyAllowed(statusCode int) bool {
	return statusCode != http.StatusNoContent && statusCode != http.StatusResetContent && statusCode != http.StatusNotModified
}

func parseHeldResponseContentLength(header http.Header) (int64, error) {
	values, present := header["Content-Length"]
	if !present {
		return -1, nil
	}
	if len(values) != 1 {
		return -1, errors.New("held response Content-Length must have exactly one value")
	}
	value := strings.Trim(values[0], " \t")
	if value == "" {
		return -1, errors.New("held response Content-Length is empty")
	}
	for index := range len(value) {
		if value[index] < '0' || value[index] > '9' {
			return -1, fmt.Errorf("held response Content-Length %q is invalid", values[0])
		}
	}
	length, err := strconv.ParseUint(value, 10, 63)
	if err != nil {
		return -1, fmt.Errorf("held response Content-Length %q is invalid: %w", values[0], err)
	}
	return int64(length), nil
}

func rejectHeldResponseEventStream(header http.Header) error {
	for _, value := range header["Content-Type"] {
		mediaType, _, err := mime.ParseMediaType(value)
		if err == nil && strings.EqualFold(mediaType, "text/event-stream") {
			return errors.New("held response capture does not support text/event-stream")
		}
		if err != nil {
			mediaType, _, _ = strings.Cut(value, ";")
			if strings.EqualFold(strings.TrimSpace(mediaType), "text/event-stream") {
				return errors.New("held response capture does not support text/event-stream")
			}
		}
	}
	return nil
}

func validateHeldResponseTrailerName(name string) (string, error) {
	if !validHeldResponseHeaderName(name) {
		return "", fmt.Errorf("held response trailer name %q is invalid", name)
	}
	canonical := textproto.CanonicalMIMEHeaderKey(name)
	if strings.HasPrefix(canonical, "If-") || forbiddenHeldResponseTrailer[canonical] {
		return "", fmt.Errorf("held response trailer %q is forbidden", canonical)
	}
	return canonical, nil
}

func validateHeldResponseHeaderValues(name string, values []string) error {
	for _, value := range values {
		for index := range len(value) {
			character := value[index]
			if (character < ' ' && character != '\t') || character == 0x7f {
				return fmt.Errorf("held response header %q contains an invalid value", name)
			}
		}
	}
	return nil
}

func validHeldResponseHeaderName(name string) bool {
	if name == "" {
		return false
	}
	for index := range len(name) {
		if !heldResponseTokenCharacter(name[index]) {
			return false
		}
	}
	return true
}

func heldResponseTokenCharacter(character byte) bool {
	if character >= 'a' && character <= 'z' ||
		character >= 'A' && character <= 'Z' ||
		character >= '0' && character <= '9' {
		return true
	}
	return strings.ContainsRune("!#$%&'*+-.^_`|~", rune(character))
}

func sortedHeldResponseHeaderKeys(header http.Header) []string {
	keys := make([]string, 0, len(header))
	for key := range header {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func validateHeldResponseHeaderLimit(header, trailer http.Header, maximum int64) error {
	return validateHeldHeaderLimit("held response", header, trailer, maximum)
}

func validateHeldRequestHeaderLimit(header http.Header, maximum int64) error {
	return validateHeldHeaderLimit("held request", header, nil, maximum)
}

func validateHeldHeaderLimit(label string, header, trailer http.Header, maximum int64) error {
	remaining := maximum
	for _, fields := range []http.Header{header, trailer} {
		if err := consumeHeldHeader(fields, &remaining, maximum, label); err != nil {
			return err
		}
	}
	return nil
}

func consumeHeldHeader(header http.Header, remaining *int64, maximum int64, label string) error {
	for name, values := range header {
		if len(values) == 0 {
			if !consumeHeldResponseHeaderLine(remaining, name, "") {
				return fmt.Errorf("%s headers exceed %d bytes", label, maximum)
			}
			continue
		}
		for _, value := range values {
			if !consumeHeldResponseHeaderLine(remaining, name, value) {
				return fmt.Errorf("%s headers exceed %d bytes", label, maximum)
			}
		}
	}
	return nil
}

func consumeHeldResponseHeaderLine(remaining *int64, name, value string) bool {
	return consumeHeldResponseHeaderBytes(remaining, int64(len(name))) &&
		consumeHeldResponseHeaderBytes(remaining, int64(len(value))) &&
		consumeHeldResponseHeaderBytes(remaining, 4)
}

func consumeHeldResponseHeaderBytes(remaining *int64, amount int64) bool {
	if amount < 0 || amount > *remaining {
		return false
	}
	*remaining -= int64(amount)
	return true
}

func cloneHeldResponseSnapshot(snapshot heldResponseSnapshot) heldResponseSnapshot {
	return heldResponseSnapshot{
		statusCode: snapshot.statusCode,
		header:     snapshot.header.Clone(),
		body:       append([]byte(nil), snapshot.body...),
		trailer:    snapshot.trailer.Clone(),
	}
}

var unsafeHeldResponseHeader = map[string]bool{
	"Connection":          true,
	"Keep-Alive":          true,
	"Proxy-Authenticate":  true,
	"Proxy-Authorization": true,
	"Proxy-Connection":    true,
	"Te":                  true,
	"Transfer-Encoding":   true,
	"Upgrade":             true,
}

var forbiddenHeldResponseTrailer = map[string]bool{
	"Authorization":       true,
	"Cache-Control":       true,
	"Connection":          true,
	"Content-Encoding":    true,
	"Content-Length":      true,
	"Content-Range":       true,
	"Content-Type":        true,
	"Expect":              true,
	"Host":                true,
	"Keep-Alive":          true,
	"Max-Forwards":        true,
	"Pragma":              true,
	"Proxy-Authenticate":  true,
	"Proxy-Authorization": true,
	"Proxy-Connection":    true,
	"Range":               true,
	"Realm":               true,
	"Te":                  true,
	"Trailer":             true,
	"Transfer-Encoding":   true,
	"Www-Authenticate":    true,
}
