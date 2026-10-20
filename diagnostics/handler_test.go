package diagnostics_test

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"gitlab.com/sidecat-dev/aauth-go/diagnostics"
	"gitlab.com/sidecat-dev/aauth-go/internal/httpapi"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

func TestHandlerReportsOriginalCauseAndRequestContextWithoutChangingResponse(t *testing.T) {
	type requestID struct{}
	private := errors.New("private storage diagnostic")
	cause := fmt.Errorf("retaining result: %w", private)
	for _, status := range []int{400, 401, 403, 500} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			request := httptest.NewRequest("POST", "https://resource.example/path", nil)
			request = request.WithContext(context.WithValue(request.Context(), requestID{}, "request-1"))
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { httpapi.WriteProblem(w, status, "server_error", cause) })
			baseline := httptest.NewRecorder()
			handler.ServeHTTP(baseline, request)
			calls := 0
			observed := diagnostics.Handler(handler, func(ctx context.Context, p diagnostics.Problem) {
				calls++
				if ctx != request.Context() || ctx.Value(requestID{}) != "request-1" || p.Status != status || p.Code != "server_error" || !errors.Is(p.Cause, private) {
					t.Fatalf("wrong observation: %#v", p)
				}
			})
			actual := httptest.NewRecorder()
			observed.ServeHTTP(actual, request)
			if calls != 1 {
				t.Fatalf("observations=%d", calls)
			}
			if actual.Code != baseline.Code || !reflect.DeepEqual(actual.Header(), baseline.Header()) || actual.Body.String() != baseline.Body.String() {
				t.Fatal("observer changed wire response")
			}
			if strings.Contains(actual.Body.String(), private.Error()) {
				t.Fatal("private cause leaked")
			}
		})
	}
}

func TestHandlerPreservesSignatureErrorCause(t *testing.T) {
	cause := &signaturekey.Error{Code: signaturekey.ErrorInvalidInput, RequiredInput: []string{"content-digest"}, Cause: errors.New("private verifier detail")}
	var got diagnostics.Problem
	handler := diagnostics.Handler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { httpapi.WriteProblem(w, 401, "invalid_signature", cause) }), func(_ context.Context, p diagnostics.Problem) { got = p })
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest("GET", "https://resource.example", nil))
	var typed *signaturekey.Error
	if !errors.As(got.Cause, &typed) || typed != cause || !strings.Contains(response.Header().Get("Signature-Error"), "invalid_input") {
		t.Fatalf("typed cause lost: %#v", got)
	}
}

func TestHandlerPreservesWriterCapabilitiesAndForwardsCalls(t *testing.T) {
	// Exercise bare, HTTP/1-style, HTTP/2-style and fully featured writers.
	for _, kind := range []string{"bare", "flush", "http1", "http2", "all"} {
		t.Run(kind, func(t *testing.T) {
			base := &capabilityWriter{ResponseRecorder: httptest.NewRecorder(), closed: make(chan bool)}
			var input http.ResponseWriter
			switch kind {
			case "bare":
				input = struct{ http.ResponseWriter }{base}
			case "flush":
				input = struct {
					http.ResponseWriter
					http.Flusher
				}{base, base}
			case "http1":
				input = struct {
					http.ResponseWriter
					http.Flusher
					http.Hijacker
					http.CloseNotifier
					io.ReaderFrom
				}{base, base, base, base, base}
			case "http2":
				input = struct {
					http.ResponseWriter
					http.Flusher
					http.Pusher
					http.CloseNotifier
				}{base, base, base, base}
			default:
				input = base
			}
			observerCalls := 0
			diagnostics.Handler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				interfaces := []reflect.Type{reflect.TypeFor[http.Flusher](), reflect.TypeFor[http.Hijacker](), reflect.TypeFor[http.Pusher](), reflect.TypeFor[http.CloseNotifier](), reflect.TypeFor[io.ReaderFrom]()}
				for _, iface := range interfaces {
					if reflect.TypeOf(w).Implements(iface) != reflect.TypeOf(input).Implements(iface) {
						t.Fatalf("%s capability changed", iface)
					}
				}
				if f, ok := w.(http.Flusher); ok {
					f.Flush()
					if base.flushed != 1 {
						t.Fatal("flush not forwarded")
					}
				}
				if h, ok := w.(http.Hijacker); ok {
					_, _, err := h.Hijack()
					if !errors.Is(err, errCapability) || base.hijacked != 1 {
						t.Fatal("hijack not forwarded")
					}
				}
				if p, ok := w.(http.Pusher); ok {
					if err := p.Push("/asset", nil); !errors.Is(err, errCapability) || base.pushed != 1 {
						t.Fatal("push not forwarded")
					}
				}
				if c, ok := w.(http.CloseNotifier); ok {
					if c.CloseNotify() != base.closed {
						t.Fatal("close notification changed")
					}
				}
				if r, ok := w.(io.ReaderFrom); ok {
					if n, err := r.ReadFrom(strings.NewReader("stream")); n != 6 || err != nil || base.readFrom != 1 {
						t.Fatal("ReadFrom not forwarded")
					}
				}
				deadlineErr := http.NewResponseController(w).SetWriteDeadline(time.Time{})
				if kind == "all" {
					if !errors.Is(deadlineErr, errCapability) || base.deadlines != 1 {
						t.Fatalf("ResponseController cannot unwrap: %v", deadlineErr)
					}
				} else if !errors.Is(deadlineErr, http.ErrNotSupported) {
					t.Fatalf("unexpected deadline capability: %v", deadlineErr)
				}
				w.Header().Set("X-Application", "yes")
				_, _ = w.Write([]byte("body"))
			}), func(context.Context, diagnostics.Problem) { observerCalls++ }).ServeHTTP(input, httptest.NewRequest("GET", "/", nil))
			if observerCalls != 0 || base.Header().Get("X-Application") != "yes" || !strings.HasSuffix(base.Body.String(), "body") {
				t.Fatal("normal response changed")
			}
		})
	}
}

var errCapability = errors.New("capability sentinel")

type capabilityWriter struct {
	*httptest.ResponseRecorder
	closed                                         chan bool
	flushed, hijacked, pushed, readFrom, deadlines int
}

func (w *capabilityWriter) Flush() { w.flushed++; w.ResponseRecorder.Flush() }
func (w *capabilityWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	w.hijacked++
	return nil, nil, errCapability
}
func (w *capabilityWriter) Push(string, *http.PushOptions) error { w.pushed++; return errCapability }
func (w *capabilityWriter) CloseNotify() <-chan bool             { return w.closed }
func (w *capabilityWriter) ReadFrom(r io.Reader) (int64, error) {
	w.readFrom++
	return w.Body.ReadFrom(r)
}
func (w *capabilityWriter) SetWriteDeadline(time.Time) error { w.deadlines++; return errCapability }

func TestNilObserverLeavesWriterUnwrapped(t *testing.T) {
	recorder := httptest.NewRecorder()
	handler := diagnostics.Handler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if w != recorder {
			t.Fatal("nil observer wrapped response writer")
		}
		w.WriteHeader(204)
	}), nil)
	handler.ServeHTTP(recorder, httptest.NewRequest("GET", "/", nil))
	if recorder.Code != 204 {
		t.Fatal(recorder.Code)
	}
}

// ResponseController prefers FlushError to Flusher. Middleware must preserve
// the transport error when the underlying writer implements both.
func TestHandlerPreservesResponseControllerFlushError(t *testing.T) {
	writer := &controllerWriter{ResponseRecorder: httptest.NewRecorder()}
	handler := diagnostics.Handler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if err := http.NewResponseController(w).Flush(); !errors.Is(err, errCapability) {
			t.Fatalf("flush error lost: %v", err)
		}
	}), func(context.Context, diagnostics.Problem) {})
	handler.ServeHTTP(writer, httptest.NewRequest("GET", "/", nil))
	if writer.calls != 1 {
		t.Fatalf("FlushError calls=%d", writer.calls)
	}
}

type controllerWriter struct {
	*httptest.ResponseRecorder
	calls int
}

func (w *controllerWriter) FlushError() error { w.calls++; return errCapability }
