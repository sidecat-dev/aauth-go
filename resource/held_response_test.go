package resource

import (
	"errors"
	"io"
	"net/http"
	"sync"
	"testing"
	"time"
)

func TestHeldResponseWriterCapturesImplicitOK(t *testing.T) {
	t.Parallel()

	response := newTestHeldResponseWriter(t, 1024, 1024)
	if _, err := response.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	snapshot := snapshotHeldResponse(t, response)
	if snapshot.statusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", snapshot.statusCode, http.StatusOK)
	}
	if got := snapshot.header.Get("Content-Type"); got != "text/plain; charset=utf-8" {
		t.Fatalf("Content-Type = %q", got)
	}
	if got := string(snapshot.body); got != "hello" {
		t.Fatalf("body = %q", got)
	}
	if got := snapshot.header.Get("Content-Length"); got != "" {
		t.Fatalf("capture invented wire Content-Length %q", got)
	}
	if got := snapshot.header.Get("Transfer-Encoding"); got != "" {
		t.Fatalf("capture invented wire Transfer-Encoding %q", got)
	}
}

func TestHeldResponseWriterCapturesExplicitResponse(t *testing.T) {
	t.Parallel()

	response := newTestHeldResponseWriter(t, 1024, 1024)
	response.Header().Add("Set-Cookie", "first=1")
	response.Header().Add("Set-Cookie", "second=2")
	response.Header().Set("X-Commit", "before")
	response.WriteHeader(http.StatusCreated)
	response.WriteHeader(http.StatusTeapot)
	response.Header().Set("X-Commit", "after")
	response.Header().Set("X-Late-Ordinary", "ignored")
	if _, err := response.Write([]byte("created")); err != nil {
		t.Fatal(err)
	}

	snapshot := snapshotHeldResponse(t, response)
	if snapshot.statusCode != http.StatusCreated {
		t.Fatalf("status = %d, want %d", snapshot.statusCode, http.StatusCreated)
	}
	if got := snapshot.header.Values("Set-Cookie"); !equalStrings(got, []string{"first=1", "second=2"}) {
		t.Fatalf("Set-Cookie = %q", got)
	}
	if got := snapshot.header.Get("X-Commit"); got != "before" {
		t.Fatalf("X-Commit = %q", got)
	}
	if got := snapshot.header.Get("X-Late-Ordinary"); got != "" {
		t.Fatalf("late ordinary header was captured: %q", got)
	}
	if got := snapshot.header.Get("Content-Type"); got != "text/plain; charset=utf-8" {
		t.Fatalf("Content-Type = %q, want automatic text/plain", got)
	}
	if got := string(snapshot.body); got != "created" {
		t.Fatalf("body = %q", got)
	}
}

func TestHeldResponseWriterSniffsCompleteInitialBodyAfterEmptyAndSplitWrites(t *testing.T) {
	t.Parallel()

	response := newTestHeldResponseWriter(t, 1024, 1024)
	response.WriteHeader(http.StatusCreated)
	if _, err := response.Write(nil); err != nil {
		t.Fatal(err)
	}
	for _, part := range []string{"<ht", "ml><body>created</body></html>"} {
		if _, err := response.Write([]byte(part)); err != nil {
			t.Fatal(err)
		}
	}
	snapshot := snapshotHeldResponse(t, response)
	if got := snapshot.header.Get("Content-Type"); got != "text/html; charset=utf-8" {
		t.Fatalf("Content-Type = %q, want text/html", got)
	}
}

func TestHeldResponseWriterCommitsHeadersAtFirstWrite(t *testing.T) {
	t.Parallel()

	response := newTestHeldResponseWriter(t, 1024, 1024)
	response.Header().Set("X-Commit", "before")
	if _, err := response.Write([]byte("body")); err != nil {
		t.Fatal(err)
	}
	response.Header().Set("X-Commit", "after")

	snapshot := snapshotHeldResponse(t, response)
	if got := snapshot.header.Get("X-Commit"); got != "before" {
		t.Fatalf("X-Commit = %q", got)
	}
}

func TestHeldResponseWriterRequiresPositiveLimits(t *testing.T) {
	t.Parallel()

	for _, limits := range []struct {
		name        string
		bodyBytes   int64
		headerBytes int64
	}{
		{name: "zero body", bodyBytes: 0, headerBytes: 1},
		{name: "negative body", bodyBytes: -1, headerBytes: 1},
		{name: "zero header", bodyBytes: 1, headerBytes: 0},
		{name: "negative header", bodyBytes: 1, headerBytes: -1},
	} {
		limits := limits
		t.Run(limits.name, func(t *testing.T) {
			if _, err := newHeldResponseWriter(limits.bodyBytes, limits.headerBytes); err == nil {
				t.Fatal("constructor accepted non-positive limit")
			}
		})
	}
}

func TestHeldResponseWriterCapturesSupportedTrailers(t *testing.T) {
	t.Parallel()

	response := newTestHeldResponseWriter(t, 1024, 2048)
	response.Header().Add("Trailer", "X-Checksum, X-Trace")
	response.Header().Add("Trailer", "X-Other")
	response.WriteHeader(http.StatusAccepted)
	response.Header().Add("X-Checksum", "sum-1")
	response.Header().Add("X-Checksum", "sum-2")
	response.Header().Set("X-Trace", "trace")
	response.Header().Set("X-Other", "other")
	response.Header().Add(http.TrailerPrefix+"X-Late", "late-1")
	response.Header().Add(http.TrailerPrefix+"X-Late", "late-2")

	snapshot := snapshotHeldResponse(t, response)
	if got := snapshot.trailer.Values("X-Checksum"); !equalStrings(got, []string{"sum-1", "sum-2"}) {
		t.Fatalf("X-Checksum trailer = %q", got)
	}
	if got := snapshot.trailer.Values("X-Trace"); !equalStrings(got, []string{"trace"}) {
		t.Fatalf("X-Trace trailer = %q", got)
	}
	if got := snapshot.trailer.Values("X-Other"); !equalStrings(got, []string{"other"}) {
		t.Fatalf("X-Other trailer = %q", got)
	}
	if got := snapshot.trailer.Values("X-Late"); !equalStrings(got, []string{"late-1", "late-2"}) {
		t.Fatalf("X-Late trailer = %q", got)
	}
	if _, present := snapshot.header["Trailer"]; present {
		t.Fatalf("Trailer declaration remained in ordinary headers: %#v", snapshot.header)
	}
	if _, present := snapshot.header[http.TrailerPrefix+"X-Late"]; present {
		t.Fatalf("TrailerPrefix field remained in ordinary headers: %#v", snapshot.header)
	}
}

func TestHeldResponseWriterRejectsInvalidOrForbiddenTrailers(t *testing.T) {
	t.Parallel()

	for _, scenario := range []struct {
		name    string
		trailer string
		prefix  bool
	}{
		{name: "invalid name", trailer: "Bad Name"},
		{name: "content length", trailer: "Content-Length"},
		{name: "transfer encoding", trailer: "Transfer-Encoding"},
		{name: "trailer", trailer: "Trailer"},
		{name: "authorization", trailer: "Authorization"},
		{name: "conditional", trailer: "If-Match"},
		{name: "prefix invalid name", trailer: "Bad Name", prefix: true},
		{name: "prefix content length", trailer: "Content-Length", prefix: true},
		{name: "prefix transfer encoding", trailer: "Transfer-Encoding", prefix: true},
		{name: "prefix trailer", trailer: "Trailer", prefix: true},
	} {
		scenario := scenario
		t.Run(scenario.name, func(t *testing.T) {
			response := newTestHeldResponseWriter(t, 1024, 1024)
			if scenario.prefix {
				response.WriteHeader(http.StatusOK)
				response.Header().Set(http.TrailerPrefix+scenario.trailer, "value")
			} else {
				response.Header().Set("Trailer", scenario.trailer)
				response.WriteHeader(http.StatusOK)
				response.Header().Set(scenario.trailer, "value")
			}
			if _, err := response.snapshot(); err == nil {
				t.Fatal("snapshot accepted invalid or forbidden trailer")
			}
		})
	}
}

func TestHeldResponseWriterRejectsBodiesForbiddenByStatus(t *testing.T) {
	t.Parallel()

	for _, statusCode := range []int{http.StatusNoContent, http.StatusResetContent, http.StatusNotModified} {
		statusCode := statusCode
		t.Run(http.StatusText(statusCode), func(t *testing.T) {
			response := newTestHeldResponseWriter(t, 1024, 1024)
			response.WriteHeader(statusCode)
			written, err := response.Write([]byte("forbidden"))
			if written != 0 || !errors.Is(err, http.ErrBodyNotAllowed) {
				t.Fatalf("Write = %d, %v; want 0, ErrBodyNotAllowed", written, err)
			}
			if _, err := response.snapshot(); err == nil {
				t.Fatal("snapshot accepted a forbidden body write")
			}
		})
	}
}

func TestHeldResponseWriterRejectsTrailersForBodylessStatus(t *testing.T) {
	t.Parallel()

	for _, statusCode := range []int{http.StatusNoContent, http.StatusResetContent, http.StatusNotModified} {
		statusCode := statusCode
		t.Run(http.StatusText(statusCode), func(t *testing.T) {
			for _, prefixed := range []bool{false, true} {
				response := newTestHeldResponseWriter(t, 1024, 1024)
				if !prefixed {
					response.Header().Set("Trailer", "X-Final")
				}
				response.WriteHeader(statusCode)
				name := "X-Final"
				if prefixed {
					name = http.TrailerPrefix + name
				}
				response.Header().Set(name, "value")
				if _, err := response.snapshot(); err == nil {
					t.Fatalf("status %d accepted trailer (prefixed=%t)", statusCode, prefixed)
				}
			}
		})
	}
}

func TestHeldResponseWriterEnforcesBodyLimitAfterIgnoredError(t *testing.T) {
	t.Parallel()

	response := newTestHeldResponseWriter(t, 3, 1024)
	if written, err := response.Write([]byte("four")); written != 0 || err == nil {
		t.Fatalf("oversized Write = %d, %v; want 0, error", written, err)
	}
	if written, err := response.Write([]byte("x")); written != 0 || err == nil {
		t.Fatalf("Write after terminal error = %d, %v; want 0, error", written, err)
	}
	if _, err := response.snapshot(); err == nil {
		t.Fatal("snapshot succeeded after ignored body-limit error")
	}
}

func TestHeldResponseWriterEnforcesHeaderLimitAfterIgnoredError(t *testing.T) {
	t.Parallel()

	response := newTestHeldResponseWriter(t, 1024, 1)
	response.Header().Set("X-Large", "value")
	if written, err := response.Write([]byte("body")); written != 0 || err == nil {
		t.Fatalf("Write with oversized headers = %d, %v; want 0, error", written, err)
	}
	if written, err := response.Write([]byte("x")); written != 0 || err == nil {
		t.Fatalf("Write after terminal error = %d, %v; want 0, error", written, err)
	}
	if _, err := response.snapshot(); err == nil {
		t.Fatal("snapshot succeeded after ignored header-limit error")
	}
}

func TestHeldResponseWriterEnforcesHeaderLimitOnLateTrailers(t *testing.T) {
	t.Parallel()

	response := newTestHeldResponseWriter(t, 1024, 32)
	response.WriteHeader(http.StatusOK)
	response.Header().Set(http.TrailerPrefix+"X-Late", "a late value too large for the limit")
	if _, err := response.snapshot(); err == nil {
		t.Fatal("snapshot accepted an oversized late trailer")
	}
	if written, err := response.Write([]byte("ignored")); written != 0 || err == nil {
		t.Fatalf("Write after terminal snapshot error = %d, %v; want 0, error", written, err)
	}
}

func TestHeldResponseWriterValidatesContentLength(t *testing.T) {
	t.Parallel()

	t.Run("exact", func(t *testing.T) {
		response := newTestHeldResponseWriter(t, 1024, 1024)
		response.Header().Set("Content-Length", "3")
		if _, err := response.Write([]byte("abc")); err != nil {
			t.Fatal(err)
		}
		snapshot := snapshotHeldResponse(t, response)
		if got := snapshot.header.Get("Content-Length"); got != "3" {
			t.Fatalf("Content-Length = %q", got)
		}
	})

	t.Run("short", func(t *testing.T) {
		response := newTestHeldResponseWriter(t, 1024, 1024)
		response.Header().Set("Content-Length", "4")
		if _, err := response.Write([]byte("abc")); err != nil {
			t.Fatal(err)
		}
		if _, err := response.snapshot(); err == nil {
			t.Fatal("snapshot accepted a short body")
		}
	})

	t.Run("long", func(t *testing.T) {
		response := newTestHeldResponseWriter(t, 1024, 1024)
		response.Header().Set("Content-Length", "2")
		if written, err := response.Write([]byte("abc")); written != 0 || !errors.Is(err, http.ErrContentLength) {
			t.Fatalf("Write = %d, %v; want 0, ErrContentLength", written, err)
		}
		if _, err := response.snapshot(); err == nil {
			t.Fatal("snapshot succeeded after ignored Content-Length error")
		}
	})

	for _, contentLength := range []struct {
		name   string
		values []string
	}{
		{name: "negative", values: []string{"-1"}},
		{name: "not decimal", values: []string{"one"}},
		{name: "comma list", values: []string{"1, 1"}},
		{name: "multiple", values: []string{"1", "1"}},
	} {
		contentLength := contentLength
		t.Run(contentLength.name, func(t *testing.T) {
			response := newTestHeldResponseWriter(t, 1024, 1024)
			response.Header()["Content-Length"] = append([]string(nil), contentLength.values...)
			if _, err := response.Write([]byte("x")); err == nil {
				t.Fatal("Write accepted invalid Content-Length")
			}
			if _, err := response.snapshot(); err == nil {
				t.Fatal("snapshot accepted invalid Content-Length")
			}
		})
	}
}

func TestHeldResponseWriterRejectsInvalidAndInformationalStatuses(t *testing.T) {
	t.Parallel()

	for _, statusCode := range []int{0, 99, 100, 101, 199, 600, 999, 1000} {
		statusCode := statusCode
		t.Run(http.StatusText(statusCode), func(t *testing.T) {
			response := newTestHeldResponseWriter(t, 1024, 1024)
			response.WriteHeader(statusCode)
			if written, err := response.Write([]byte("ignored")); written != 0 || err == nil {
				t.Fatalf("Write after invalid status = %d, %v; want 0, error", written, err)
			}
			if _, err := response.snapshot(); err == nil {
				t.Fatalf("snapshot accepted status %d", statusCode)
			}
		})
	}
	response := newTestHeldResponseWriter(t, 1024, 1024)
	response.WriteHeader(599)
	if snapshot := snapshotHeldResponse(t, response); snapshot.statusCode != 599 {
		t.Fatalf("status = %d, want 599", snapshot.statusCode)
	}
}

func TestHeldResponseWriterRejectsUnsupportedResponseControls(t *testing.T) {
	t.Parallel()

	for _, scenario := range []struct {
		name   string
		invoke func(*heldResponseWriter) error
		void   bool
	}{
		{name: "Flush", void: true, invoke: func(response *heldResponseWriter) error {
			response.Flush()
			return nil
		}},
		{name: "FlushError", invoke: func(response *heldResponseWriter) error {
			return response.FlushError()
		}},
		{name: "ResponseController Flush", invoke: func(response *heldResponseWriter) error {
			return http.NewResponseController(response).Flush()
		}},
		{name: "Hijack", invoke: func(response *heldResponseWriter) error {
			connection, readWriter, err := response.Hijack()
			if connection != nil || readWriter != nil {
				return errors.New("Hijack returned connection state")
			}
			return err
		}},
		{name: "Push", invoke: func(response *heldResponseWriter) error {
			return response.Push("/asset", nil)
		}},
		{name: "EnableFullDuplex", invoke: func(response *heldResponseWriter) error {
			return http.NewResponseController(response).EnableFullDuplex()
		}},
		{name: "SetReadDeadline", invoke: func(response *heldResponseWriter) error {
			return http.NewResponseController(response).SetReadDeadline(time.Now())
		}},
		{name: "SetWriteDeadline", invoke: func(response *heldResponseWriter) error {
			return http.NewResponseController(response).SetWriteDeadline(time.Now())
		}},
	} {
		scenario := scenario
		t.Run(scenario.name, func(t *testing.T) {
			response := newTestHeldResponseWriter(t, 1024, 1024)
			err := scenario.invoke(response)
			if !scenario.void && !errors.Is(err, http.ErrNotSupported) {
				t.Fatalf("control error = %v, want ErrNotSupported", err)
			}
			if _, err := response.snapshot(); err == nil {
				t.Fatal("snapshot succeeded after unsupported response control")
			}
		})
	}
}

func TestHeldResponseWriterRejectsUnsafeResponseFields(t *testing.T) {
	t.Parallel()

	for _, field := range []string{
		"Connection",
		"Keep-Alive",
		"Proxy-Authenticate",
		"Proxy-Authorization",
		"Proxy-Connection",
		"TE",
		"Transfer-Encoding",
		"Upgrade",
	} {
		field := field
		t.Run(field, func(t *testing.T) {
			response := newTestHeldResponseWriter(t, 1024, 1024)
			response.Header().Set(field, "unsafe")
			if _, err := response.Write([]byte("body")); err == nil {
				t.Fatalf("Write accepted %s", field)
			}
			if _, err := response.snapshot(); err == nil {
				t.Fatalf("snapshot accepted %s", field)
			}
		})
	}

	for _, contentType := range []string{"text/event-stream", "Text/Event-Stream; charset=utf-8"} {
		contentType := contentType
		t.Run(contentType, func(t *testing.T) {
			response := newTestHeldResponseWriter(t, 1024, 1024)
			response.Header().Set("Content-Type", contentType)
			if _, err := response.Write([]byte("event")); err == nil {
				t.Fatal("Write accepted an event stream")
			}
			if _, err := response.snapshot(); err == nil {
				t.Fatal("snapshot accepted an event stream")
			}
		})
	}

	for _, scenario := range []struct {
		name  string
		field string
		value string
	}{
		{name: "invalid field name", field: "Bad Name", value: "value"},
		{name: "invalid field value", field: "X-Test", value: "bad\r\nvalue"},
	} {
		scenario := scenario
		t.Run(scenario.name, func(t *testing.T) {
			response := newTestHeldResponseWriter(t, 1024, 1024)
			response.Header()[scenario.field] = []string{scenario.value}
			if _, err := response.Write([]byte("body")); err == nil {
				t.Fatal("Write accepted an invalid header")
			}
		})
	}
}

func TestHeldResponseWriterExposesOnlyDeliberateOptionalInterfaces(t *testing.T) {
	t.Parallel()

	response := newTestHeldResponseWriter(t, 1024, 1024)
	var _ http.ResponseWriter = response
	if _, ok := any(response).(http.Flusher); !ok {
		t.Fatal("writer does not expose deliberate Flusher refusal")
	}
	if _, ok := any(response).(interface{ FlushError() error }); !ok {
		t.Fatal("writer does not expose deliberate FlushError refusal")
	}
	if _, ok := any(response).(http.Hijacker); !ok {
		t.Fatal("writer does not expose deliberate Hijacker refusal")
	}
	if _, ok := any(response).(http.Pusher); !ok {
		t.Fatal("writer does not expose deliberate Pusher refusal")
	}
	if _, ok := any(response).(interface{ Unwrap() http.ResponseWriter }); ok {
		t.Fatal("writer exposes Unwrap")
	}
	if _, ok := any(response).(io.ReaderFrom); ok {
		t.Fatal("writer exposes io.ReaderFrom")
	}
	if _, ok := any(response).(io.StringWriter); ok {
		t.Fatal("writer exposes io.StringWriter")
	}
	if _, ok := any(response).(http.CloseNotifier); ok {
		t.Fatal("writer exposes CloseNotifier")
	}
}

func TestHeldResponseSnapshotIsIndependent(t *testing.T) {
	t.Parallel()

	response := newTestHeldResponseWriter(t, 1024, 2048)
	headerValues := []string{"one", "two"}
	response.Header()["X-List"] = headerValues
	response.Header().Set("Trailer", "X-Final")
	response.WriteHeader(http.StatusOK)
	headerValues[0] = "changed after commit"
	trailerValues := []string{"final"}
	response.Header()["X-Final"] = trailerValues
	body := []byte("body")
	if _, err := response.Write(body); err != nil {
		t.Fatal(err)
	}
	body[0] = 'X'

	first := snapshotHeldResponse(t, response)
	first.header["X-List"][0] = "changed snapshot"
	first.body[0] = 'Y'
	first.trailer["X-Final"][0] = "changed trailer"
	trailerValues[0] = "changed after snapshot"
	response.Header().Set("X-After-Snapshot", "ignored")

	second := snapshotHeldResponse(t, response)
	if got := second.header.Values("X-List"); !equalStrings(got, []string{"one", "two"}) {
		t.Fatalf("second header = %q", got)
	}
	if got := string(second.body); got != "body" {
		t.Fatalf("second body = %q", got)
	}
	if got := second.trailer.Values("X-Final"); !equalStrings(got, []string{"final"}) {
		t.Fatalf("second trailer = %q", got)
	}
	if got := second.header.Get("X-After-Snapshot"); got != "" {
		t.Fatalf("post-snapshot header was captured: %q", got)
	}
}

func TestHeldResponseWriterFailsWritesAfterFinalization(t *testing.T) {
	t.Parallel()

	response := newTestHeldResponseWriter(t, 1024, 1024)
	if _, err := response.Write([]byte("initial")); err != nil {
		t.Fatal(err)
	}
	snapshotHeldResponse(t, response)

	const goroutines = 32
	errorsSeen := make(chan error, goroutines)
	var wait sync.WaitGroup
	for range goroutines {
		wait.Add(1)
		go func() {
			defer wait.Done()
			_, err := response.Write([]byte("late"))
			errorsSeen <- err
		}()
	}
	wait.Wait()
	close(errorsSeen)
	for err := range errorsSeen {
		if err == nil {
			t.Fatal("write after finalization succeeded")
		}
	}
	if got := string(snapshotHeldResponse(t, response).body); got != "initial" {
		t.Fatalf("body after concurrent misuse = %q", got)
	}
}

func TestHeldResponseWriterSerializesConcurrentWrites(t *testing.T) {
	t.Parallel()

	response := newTestHeldResponseWriter(t, 1024, 1024)
	const goroutines = 64
	errorsSeen := make(chan error, goroutines)
	var wait sync.WaitGroup
	for range goroutines {
		wait.Add(1)
		go func() {
			defer wait.Done()
			_, err := response.Write([]byte{'x'})
			errorsSeen <- err
		}()
	}
	wait.Wait()
	close(errorsSeen)
	for err := range errorsSeen {
		if err != nil {
			t.Fatal(err)
		}
	}
	if got := len(snapshotHeldResponse(t, response).body); got != goroutines {
		t.Fatalf("body bytes = %d, want %d", got, goroutines)
	}
}

func newTestHeldResponseWriter(t *testing.T, maxBodyBytes, maxHeaderBytes int64) *heldResponseWriter {
	t.Helper()
	response, err := newHeldResponseWriter(maxBodyBytes, maxHeaderBytes)
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func snapshotHeldResponse(t *testing.T, response *heldResponseWriter) heldResponseSnapshot {
	t.Helper()
	snapshot, err := response.snapshot()
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
