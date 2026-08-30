package resource

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
)

func TestHeldRequestSnapshotReplaysDigestPreparedBody(t *testing.T) {
	t.Parallel()

	const body = `{"record":"alpha"}`
	request, err := http.NewRequest(http.MethodPatch, "https://resource.example/records", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Digest", "sha-256=:digest:")
	getBodyCalls := 0
	request.GetBody = func() (io.ReadCloser, error) {
		getBodyCalls++
		return io.NopCloser(strings.NewReader("stale copy")), nil
	}

	snapshot, err := snapshotHeldRequest(request, int64(len(body)))
	if err != nil {
		t.Fatal(err)
	}
	if getBodyCalls != 0 {
		t.Fatalf("GetBody called %d times, want 0", getBodyCalls)
	}
	replayed, err := snapshot.request(context.Background(), AuthPrincipal{})
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(replayed.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != body {
		t.Fatalf("body = %q, want %q", got, body)
	}
	if replayed.Header.Get("Content-Digest") != "sha-256=:digest:" {
		t.Fatalf("Content-Digest = %q", replayed.Header.Get("Content-Digest"))
	}
	copy, err := replayed.GetBody()
	if err != nil {
		t.Fatal(err)
	}
	defer copy.Close()
	got, err = io.ReadAll(copy)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != body {
		t.Fatalf("GetBody body = %q, want %q", got, body)
	}
}

func TestHeldRequestSnapshotReadsRestoredLiveBodyAfterScopePolicy(t *testing.T) {
	t.Parallel()

	const body = `{"record":"alpha","enabled":true}`
	originalBody := &heldTrackingBody{reader: strings.NewReader(body)}
	request := httptest.NewRequest(http.MethodPatch, "https://resource.example/records/a%2Fb", nil)
	request.Body = originalBody
	request.GetBody = nil
	request.ContentLength = int64(len(body))

	policyRequest, finish, err := cloneScopePolicyRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	prefix := make([]byte, 7)
	if _, err := io.ReadFull(policyRequest.Body, prefix); err != nil {
		t.Fatal(err)
	}
	if err := finish(); err != nil {
		t.Fatal(err)
	}

	snapshot, err := snapshotHeldRequest(request, int64(len(body)))
	if err != nil {
		t.Fatal(err)
	}
	if !originalBody.closed {
		t.Fatal("original body was not closed after successful snapshot")
	}
	assertHeldRequestBody(t, request.Body, body)
	replayed, err := snapshot.request(context.Background(), AuthPrincipal{})
	if err != nil {
		t.Fatal(err)
	}
	assertHeldRequestBody(t, replayed.Body, body)
}

func TestHeldRequestSnapshotIsIndependentOfRequestAndReplayMutation(t *testing.T) {
	t.Parallel()

	request, err := http.NewRequest(http.MethodPost, "https://resource.example/original", strings.NewReader("original body"))
	if err != nil {
		t.Fatal(err)
	}
	request.Header["X-Caller"] = []string{"first", "second"}
	snapshot, err := snapshotHeldRequest(request, 64)
	if err != nil {
		t.Fatal(err)
	}

	request.Method = http.MethodDelete
	request.URL.Path = "/mutated"
	request.Header["X-Caller"][0] = "mutated"
	request.Header.Set("X-Later", "not retained")
	installHeldRequestBody(request, []byte("mutated body"))

	first, err := snapshot.request(context.Background(), AuthPrincipal{})
	if err != nil {
		t.Fatal(err)
	}
	first.Method = http.MethodPut
	first.URL.Path = "/first-mutated"
	first.Header["X-Caller"][0] = "first-mutated"
	assertHeldRequestBody(t, first.Body, "original body")

	second, err := snapshot.request(context.Background(), AuthPrincipal{})
	if err != nil {
		t.Fatal(err)
	}
	if second.Method != http.MethodPost || second.URL.EscapedPath() != "/original" {
		t.Fatalf("second request = %s %s", second.Method, second.URL.EscapedPath())
	}
	if got := second.Header.Values("X-Caller"); !reflect.DeepEqual(got, []string{"first", "second"}) {
		t.Fatalf("X-Caller = %q", got)
	}
	if second.Header.Get("X-Later") != "" {
		t.Fatalf("X-Later = %q", second.Header.Get("X-Later"))
	}
	assertHeldRequestBody(t, second.Body, "original body")
}

func TestHeldRequestSnapshotReconstructsExactTargetAndProtocol(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name       string
		rawQuery   string
		forceQuery bool
		requestURI string
	}{
		{name: "explicit empty query", forceQuery: true, requestURI: "/records/a%2Fb?"},
		{name: "exact encoded query", rawQuery: "view=full%20detail&tag=a%2Fb", requestURI: "/records/a%2Fb?view=full%20detail&tag=a%2Fb"},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			request := &http.Request{
				Method: http.MethodPatch,
				URL: &url.URL{
					Scheme:     "https",
					Host:       "url-host.example:8443",
					Path:       "/records/a/b",
					RawPath:    "/records/a%2Fb",
					RawQuery:   test.rawQuery,
					ForceQuery: test.forceQuery,
				},
				Host:          "request-host.example",
				RequestURI:    test.requestURI,
				Header:        make(http.Header),
				Body:          http.NoBody,
				ContentLength: 17,
				Proto:         "HTTP/1.0",
				ProtoMajor:    1,
				ProtoMinor:    0,
			}
			snapshot, err := snapshotHeldRequest(request, 1)
			if err != nil {
				t.Fatal(err)
			}
			replayed, err := snapshot.request(context.Background(), AuthPrincipal{})
			if err != nil {
				t.Fatal(err)
			}
			if replayed.Method != request.Method || replayed.URL.Scheme != request.URL.Scheme ||
				replayed.URL.Host != request.URL.Host || replayed.Host != request.Host ||
				replayed.URL.EscapedPath() != request.URL.EscapedPath() || replayed.URL.RawQuery != test.rawQuery ||
				replayed.URL.ForceQuery != test.forceQuery || replayed.RequestURI != test.requestURI ||
				replayed.ContentLength != 17 || replayed.Proto != "HTTP/1.0" ||
				replayed.ProtoMajor != 1 || replayed.ProtoMinor != 0 {
				t.Fatalf("replayed request = %#v, URL = %#v", replayed, replayed.URL)
			}
		})
	}
}

func TestHeldRequestSnapshotPreservesRawPathAndRequestURIRepresentation(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name       string
		rawPath    string
		requestURI string
	}{
		{name: "redundant raw path and empty request URI", rawPath: "/records", requestURI: ""},
		{name: "encoded raw path and nonderived request URI", rawPath: "/records/a%2Fb", requestURI: "/synthetic-target"},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := "/records"
			if strings.Contains(test.rawPath, "%2F") {
				path = "/records/a/b"
			}
			request := &http.Request{
				Method:     http.MethodGet,
				URL:        &url.URL{Scheme: "https", Host: "resource.example", Path: path, RawPath: test.rawPath},
				RequestURI: test.requestURI,
				Header:     make(http.Header),
				Body:       nil,
			}
			snapshot, err := snapshotHeldRequest(request, 1)
			if err != nil {
				t.Fatal(err)
			}
			replayed, err := snapshot.request(context.Background(), AuthPrincipal{})
			if err != nil {
				t.Fatal(err)
			}
			if replayed.URL.RawPath != test.rawPath || replayed.RequestURI != test.requestURI {
				t.Fatalf("representation: RawPath=%q RequestURI=%q", replayed.URL.RawPath, replayed.RequestURI)
			}
		})
	}
}

func TestHeldRequestSnapshotPreservesEmptyBodyRepresentation(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name        string
		body        io.ReadCloser
		withGetBody bool
		wantNil     bool
		wantNoBody  bool
	}{
		{name: "nil body", body: nil, wantNil: true},
		{name: "NoBody", body: http.NoBody, wantNoBody: true},
		{name: "NoBody with GetBody", body: http.NoBody, withGetBody: true, wantNoBody: true},
		{name: "independent empty body", body: io.NopCloser(strings.NewReader(""))},
		{name: "replayable empty body", body: io.NopCloser(strings.NewReader("")), withGetBody: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := &http.Request{
				Method: http.MethodGet,
				URL:    &url.URL{Scheme: "https", Host: "resource.example", Path: "/records"},
				Header: make(http.Header), Body: test.body,
			}
			if test.withGetBody {
				request.GetBody = func() (io.ReadCloser, error) { return http.NoBody, nil }
			}
			originalBody := request.Body
			originalGetBodyPresent := request.GetBody != nil
			snapshot, err := snapshotHeldRequest(request, 1)
			if err != nil {
				t.Fatal(err)
			}
			if test.wantNil || test.wantNoBody {
				if request.Body != originalBody || (request.GetBody != nil) != originalGetBodyPresent {
					t.Fatal("snapshot changed the live empty-body representation")
				}
			}
			replayed, err := snapshot.request(context.Background(), AuthPrincipal{})
			if err != nil {
				t.Fatal(err)
			}
			if test.wantNil && replayed.Body != nil {
				t.Fatalf("Body = %#v, want nil", replayed.Body)
			}
			if test.wantNoBody && replayed.Body != http.NoBody {
				t.Fatalf("Body = %#v, want http.NoBody", replayed.Body)
			}
			if !test.wantNil && !test.wantNoBody && (replayed.Body == nil || replayed.Body == http.NoBody) {
				t.Fatalf("Body = %#v, want independent empty body", replayed.Body)
			}
			if (replayed.GetBody != nil) != test.withGetBody {
				t.Fatalf("GetBody present = %t, want %t", replayed.GetBody != nil, test.withGetBody)
			}
		})
	}
}

func TestHeldRequestSnapshotRejectsNilBodyWithGetBody(t *testing.T) {
	t.Parallel()

	request := &http.Request{
		Method:  http.MethodGet,
		URL:     &url.URL{Scheme: "https", Host: "resource.example", Path: "/records"},
		Header:  make(http.Header),
		GetBody: func() (io.ReadCloser, error) { return http.NoBody, nil },
	}
	if _, err := snapshotHeldRequest(request, 1); err == nil {
		t.Fatal("nil body with an unrelated GetBody was accepted")
	}
}

func TestHeldRequestSnapshotUsesFreshContextAndCopiedPrincipal(t *testing.T) {
	t.Parallel()

	type contextKey string
	const (
		originalKey contextKey = "original"
		freshKey    contextKey = "fresh"
	)
	originalContext, cancel := context.WithCancel(context.WithValue(context.Background(), originalKey, "original value"))
	cancel()
	request := httptest.NewRequest(http.MethodGet, "https://resource.example/records", nil).WithContext(originalContext)
	request.TLS = &tls.ConnectionState{ServerName: "retained.example"}
	request.RemoteAddr = "192.0.2.1:443"
	snapshot, err := snapshotHeldRequest(request, 1)
	if err != nil {
		t.Fatal(err)
	}

	principal := AuthPrincipal{
		PersonServer: "https://person.example",
		Subject:      "person-123",
		Scope:        []string{"records.read"},
		AdditionalClaims: map[string]json.RawMessage{
			"profile": json.RawMessage(`{"name":"Ada"}`),
		},
	}
	freshContext := context.WithValue(context.Background(), freshKey, "fresh value")
	replayed, err := snapshot.request(freshContext, principal)
	if err != nil {
		t.Fatal(err)
	}
	principal.Scope[0] = "mutated"
	principal.AdditionalClaims["profile"][9] = 'X'
	principal.AdditionalClaims["later"] = json.RawMessage(`true`)

	if replayed.Context().Err() != nil || replayed.Context().Value(originalKey) != nil ||
		replayed.Context().Value(freshKey) != "fresh value" {
		t.Fatalf("replayed context: err=%v original=%v fresh=%v", replayed.Context().Err(), replayed.Context().Value(originalKey), replayed.Context().Value(freshKey))
	}
	if replayed.TLS != nil || replayed.RemoteAddr != "" {
		t.Fatalf("transport state retained: TLS=%#v RemoteAddr=%q", replayed.TLS, replayed.RemoteAddr)
	}
	got, ok := AuthPrincipalFromContext(replayed.Context())
	if !ok {
		t.Fatal("AuthPrincipalFromContext did not find principal")
	}
	if !reflect.DeepEqual(got.Scope, []string{"records.read"}) || string(got.AdditionalClaims["profile"]) != `{"name":"Ada"}` || got.AdditionalClaims["later"] != nil {
		t.Fatalf("principal = %#v", got)
	}
	if _, err := snapshot.request(nil, AuthPrincipal{}); err == nil {
		t.Fatal("nil reconstruction context was accepted")
	}
	emptyScope, err := snapshot.request(context.Background(), AuthPrincipal{Scope: []string{}})
	if err != nil {
		t.Fatal(err)
	}
	storedPrincipal, ok := emptyScope.Context().Value(authPrincipalContextKey{}).(AuthPrincipal)
	if !ok || storedPrincipal.Scope == nil || len(storedPrincipal.Scope) != 0 {
		t.Fatalf("empty nonnil scope was not preserved: %#v", storedPrincipal.Scope)
	}
	publicPrincipal, ok := AuthPrincipalFromContext(emptyScope.Context())
	if !ok || publicPrincipal.Scope == nil || len(publicPrincipal.Scope) != 0 {
		t.Fatalf("public empty nonnil scope was not preserved: %#v", publicPrincipal.Scope)
	}
}

func TestHeldRequestSnapshotStripsProofHeadersAndPreservesApplicationHeaders(t *testing.T) {
	t.Parallel()

	request := httptest.NewRequest(http.MethodPost, "https://resource.example/records", strings.NewReader("body"))
	request.Header["Signature-Key"] = []string{"sig=stale"}
	request.Header["signature-input"] = []string{"sig=(\"@method\")"}
	request.Header["SIGNATURE"] = []string{"sig=:stale:"}
	request.Header["Content-Digest"] = []string{"sha-256=:digest:"}
	request.Header["Authorization"] = []string{"Bearer application-credential"}
	request.Header.Set("AAuth-Capabilities", "interaction")
	request.Header["X-Caller"] = []string{"first", "second"}
	snapshot, err := snapshotHeldRequest(request, 4)
	if err != nil {
		t.Fatal(err)
	}
	if request.Header.Get("Signature-Key") == "" {
		t.Fatal("snapshot mutated proof headers on the live request")
	}
	request.Header["X-Caller"][0] = "mutated"

	replayed, err := snapshot.request(context.Background(), AuthPrincipal{})
	if err != nil {
		t.Fatal(err)
	}
	for name := range replayed.Header {
		if strings.EqualFold(name, "Signature-Key") || strings.EqualFold(name, "Signature-Input") || strings.EqualFold(name, "Signature") {
			t.Fatalf("stale proof header retained: %q", name)
		}
	}
	want := map[string][]string{
		"Content-Digest":     {"sha-256=:digest:"},
		"Authorization":      {"Bearer application-credential"},
		"AAuth-Capabilities": {"interaction"},
		"X-Caller":           {"first", "second"},
	}
	for name, values := range want {
		if got := replayed.Header.Values(name); !reflect.DeepEqual(got, values) {
			t.Errorf("%s = %q, want %q", name, got, values)
		}
	}
}

func TestHeldRequestSnapshotRejectsUnsupportedHTTPFeaturesWithoutTakingBody(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		change func(*http.Request)
	}{
		{name: "trailers", change: func(request *http.Request) { request.Trailer = http.Header{"X-Final": {"yes"}} }},
		{name: "CONNECT", change: func(request *http.Request) { request.Method = http.MethodConnect }},
		{name: "Connection", change: func(request *http.Request) { request.Header["connection"] = []string{"X-Hop"} }},
		{name: "Proxy-Connection", change: func(request *http.Request) { request.Header.Set("Proxy-Connection", "keep-alive") }},
		{name: "Keep-Alive", change: func(request *http.Request) { request.Header.Set("Keep-Alive", "timeout=5") }},
		{name: "Proxy-Authenticate", change: func(request *http.Request) { request.Header.Set("Proxy-Authenticate", "Basic") }},
		{name: "Proxy-Authorization", change: func(request *http.Request) { request.Header.Set("Proxy-Authorization", "Basic value") }},
		{name: "TE", change: func(request *http.Request) { request.Header.Set("TE", "trailers") }},
		{name: "Trailer header", change: func(request *http.Request) { request.Header.Set("Trailer", "X-Final") }},
		{name: "Transfer-Encoding header", change: func(request *http.Request) { request.Header.Set("Transfer-Encoding", "chunked") }},
		{name: "Upgrade", change: func(request *http.Request) { request.Header.Set("Upgrade", "websocket") }},
		{name: "transfer encoding state", change: func(request *http.Request) { request.TransferEncoding = []string{"chunked"} }},
		{name: "close", change: func(request *http.Request) { request.Close = true }},
		{name: "invalid raw path", change: func(request *http.Request) { request.URL.RawPath = "/records/%zz" }},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			body := &heldTrackingBody{reader: strings.NewReader("body")}
			request := httptest.NewRequest(http.MethodPost, "https://resource.example/records", nil)
			request.Body = body
			request.ContentLength = 4
			test.change(request)
			if _, err := snapshotHeldRequest(request, 4); err == nil {
				t.Fatal("unsupported request was accepted")
			}
			if request.Body != body || request.GetBody != nil || body.read != 0 || body.closed {
				t.Fatalf("body ownership changed: read=%d closed=%v", body.read, body.closed)
			}
		})
	}
}

func TestHeldRequestSnapshotRestoresBodyAfterReadError(t *testing.T) {
	t.Parallel()

	readErr := errors.New("read failed")
	body := &heldReadErrorBody{remaining: []byte("prefix-and-suffix"), failAfter: len("prefix"), err: readErr}
	request := httptest.NewRequest(http.MethodPost, "https://resource.example/records", nil)
	request.Body = body
	request.GetBody = nil
	if _, err := snapshotHeldRequest(request, 64); !errors.Is(err, readErr) {
		t.Fatalf("error = %v, want %v", err, readErr)
	}
	if request.GetBody != nil {
		t.Fatal("read failure installed a replacement GetBody")
	}
	assertHeldRequestBody(t, request.Body, "prefix-and-suffix")
	if body.closed {
		t.Fatal("original body was closed after partial read failure")
	}
	if err := request.Body.Close(); err != nil {
		t.Fatal(err)
	}
	if !body.closed {
		t.Fatal("restored body did not retain original close ownership")
	}
}

func TestHeldRequestSnapshotRestoresBodyAndSurfacesCloseError(t *testing.T) {
	t.Parallel()

	closeErr := errors.New("close failed")
	body := &heldCloseErrorBody{reader: strings.NewReader("complete body"), err: closeErr}
	request := httptest.NewRequest(http.MethodPost, "https://resource.example/records", nil)
	request.Body = body
	request.GetBody = nil
	if _, err := snapshotHeldRequest(request, 64); !errors.Is(err, closeErr) {
		t.Fatalf("error = %v, want %v", err, closeErr)
	}
	if body.closeCalls != 1 {
		t.Fatalf("close calls = %d, want 1", body.closeCalls)
	}
	assertHeldRequestBody(t, request.Body, "complete body")
	if request.GetBody != nil {
		t.Fatal("close failure added GetBody that the original request did not have")
	}
}

func TestHeldRequestSnapshotCountsActualBodyBytesAndRestoresOversizeInput(t *testing.T) {
	t.Parallel()

	body := &heldTrackingBody{reader: strings.NewReader("123456789")}
	request := httptest.NewRequest(http.MethodPost, "https://resource.example/records", nil)
	request.Body = body
	request.ContentLength = 1
	if _, err := snapshotHeldRequest(request, 5); err == nil {
		t.Fatal("oversize body was accepted from misleading ContentLength")
	}
	if body.read != 6 || body.closed {
		t.Fatalf("body after size check: read=%d closed=%v", body.read, body.closed)
	}
	if request.GetBody != nil {
		t.Fatal("size failure installed a replacement GetBody")
	}
	assertHeldRequestBody(t, request.Body, "123456789")
}

func TestHeldRequestSnapshotAcceptsMaximumInt64BodyBound(t *testing.T) {
	t.Parallel()

	request := httptest.NewRequest(http.MethodPost, "https://resource.example/records", strings.NewReader("body"))
	snapshot, err := snapshotHeldRequest(request, math.MaxInt64)
	if err != nil {
		t.Fatal(err)
	}
	replayed, err := snapshot.request(context.Background(), AuthPrincipal{})
	if err != nil {
		t.Fatal(err)
	}
	assertHeldRequestBody(t, replayed.Body, "body")
}

func TestHeldRequestSnapshotRejectsNonpositiveLimitWithoutTakingInput(t *testing.T) {
	t.Parallel()

	for _, limit := range []int64{0, -1} {
		body := &heldTrackingBody{reader: strings.NewReader("body")}
		request := httptest.NewRequest(http.MethodPost, "https://resource.example/records", nil)
		request.Body = body
		originalGetBody := func() (io.ReadCloser, error) { return io.NopCloser(strings.NewReader("copy")), nil }
		request.GetBody = originalGetBody
		if _, err := snapshotHeldRequest(request, limit); err == nil {
			t.Fatalf("limit %d was accepted", limit)
		}
		if body.read != 0 || body.closed || reflect.ValueOf(request.GetBody).Pointer() != reflect.ValueOf(originalGetBody).Pointer() {
			t.Fatalf("limit %d changed input ownership: read=%d closed=%v", limit, body.read, body.closed)
		}
	}
}

func assertHeldRequestBody(t *testing.T, body io.Reader, want string) {
	t.Helper()
	got, err := io.ReadAll(body)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Fatalf("body = %q, want %q", got, want)
	}
}

type heldTrackingBody struct {
	reader *strings.Reader
	read   int
	closed bool
}

func (body *heldTrackingBody) Read(buffer []byte) (int, error) {
	read, err := body.reader.Read(buffer)
	body.read += read
	return read, err
}

func (body *heldTrackingBody) Close() error {
	body.closed = true
	return nil
}

type heldReadErrorBody struct {
	remaining []byte
	failAfter int
	err       error
	failed    bool
	closed    bool
}

func (body *heldReadErrorBody) Read(buffer []byte) (int, error) {
	if len(body.remaining) == 0 {
		return 0, io.EOF
	}
	readLimit := len(body.remaining)
	if !body.failed && readLimit > body.failAfter {
		readLimit = body.failAfter
	}
	if readLimit > len(buffer) {
		readLimit = len(buffer)
	}
	read := copy(buffer, body.remaining[:readLimit])
	body.remaining = body.remaining[read:]
	if !body.failed && read == body.failAfter {
		body.failed = true
		return read, body.err
	}
	return read, nil
}

func (body *heldReadErrorBody) Close() error {
	body.closed = true
	return nil
}

type heldCloseErrorBody struct {
	reader     *strings.Reader
	err        error
	closeCalls int
}

func (body *heldCloseErrorBody) Read(buffer []byte) (int, error) {
	return body.reader.Read(buffer)
}

func (body *heldCloseErrorBody) Close() error {
	body.closeCalls++
	return body.err
}
