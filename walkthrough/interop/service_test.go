package main

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

func TestAuthorizationServiceRunsBehindALoopbackTLSProxy(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	stateDir := t.TempDir()
	go func() {
		done <- serveInteropAuthorization(ctx, listener, interopAuthorizationRunConfig{
			Origin: "https://service.example", AgentIssuer: "https://interop.example",
			Agent: "aauth:go-interop@interop.example", StateDir: stateDir,
		})
	}()

	request, err := http.NewRequest(http.MethodGet, "http://"+listener.Addr().String()+"/.well-known/aauth-person.json", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Host = "service.example"
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("Person metadata = %s", response.Status)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestProtectedNoteHandlerCreatesAndReplaysOneBoundedWrite(t *testing.T) {
	store := newInteropNoteStore(t.TempDir() + "/notes.json")
	call := func(key, text string) *httptest.ResponseRecorder {
		body := `{"request_key":` + strconv.Quote(key) + `,"text":` + strconv.Quote(text) + `}`
		request := httptest.NewRequest(http.MethodPost, "https://service.example/notes", strings.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		serveInteropNote(response, request, store, "interop-person")
		return response
	}

	first := call("write-1", "hello from TypeScript")
	if first.Code != http.StatusCreated {
		t.Fatalf("first note = %d: %s", first.Code, first.Body.String())
	}
	replay := call("write-1", "hello from TypeScript")
	if replay.Code != http.StatusOK || !strings.Contains(replay.Body.String(), `"replayed":true`) ||
		!strings.Contains(replay.Body.String(), `"consequence_count":1`) {
		t.Fatalf("replayed note = %d: %s", replay.Code, replay.Body.String())
	}
	conflict := call("write-1", "changed")
	if conflict.Code != http.StatusConflict {
		t.Fatalf("changed replay = %d: %s", conflict.Code, conflict.Body.String())
	}
}

func TestProtectedNoteHandlerRejectsUnboundedOrAmbiguousInput(t *testing.T) {
	store := newInteropNoteStore(t.TempDir() + "/notes.json")
	for name, body := range map[string]string{
		"oversized request key": `{"request_key":"` + strings.Repeat("k", 129) + `","text":"hello"}`,
		"oversized note":        `{"request_key":"write-1","text":"` + strings.Repeat("x", 4097) + `"}`,
		"trailing JSON":         `{"request_key":"write-1","text":"hello"} {}`,
	} {
		t.Run(name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "https://service.example/notes", strings.NewReader(body))
			request.Header.Set("Content-Type", "application/json")
			response := httptest.NewRecorder()
			serveInteropNote(response, request, store, "interop-person")
			if response.Code != http.StatusBadRequest {
				t.Fatalf("unbounded input = %d: %s", response.Code, response.Body.String())
			}
		})
	}
}

func TestNoteStoreRetainsOneIdempotentProtectedConsequence(t *testing.T) {
	path := t.TempDir() + "/notes.json"
	store := newInteropNoteStore(path)
	first, err := store.Create("write-1", "hello from TypeScript", "interop-person")
	if err != nil {
		t.Fatal(err)
	}
	if first.NoteID != "note-1" || first.Replayed || first.ConsequenceCount != 1 {
		t.Fatalf("first note = %#v", first)
	}

	reloaded := newInteropNoteStore(path)
	replay, err := reloaded.Create("write-1", "hello from TypeScript", "interop-person")
	if err != nil {
		t.Fatal(err)
	}
	if replay.NoteID != first.NoteID || !replay.Replayed || replay.ConsequenceCount != 1 {
		t.Fatalf("replayed note = %#v, want exact retained result", replay)
	}
	if _, err := reloaded.Create("write-1", "changed", "interop-person"); !errors.Is(err, errInteropNoteConflict) {
		t.Fatalf("changed-input replay error = %v, want conflict", err)
	}
}

func TestAuthorizationServicePublishesCollocatedRoleMetadataAndKeySet(t *testing.T) {
	const origin = "https://service.example"
	service, err := newInteropAuthorizationService(interopAuthorizationServiceConfig{
		Origin:   origin,
		Agent:    "aauth:go-interop@interop.example",
		Clock:    aauth.ClockFunc(func() time.Time { return time.Date(2026, 9, 1, 22, 0, 0, 0, time.UTC) }),
		Resolver: signaturekey.StaticKeyResolver{},
		Notes:    newInteropNoteStore(t.TempDir() + "/notes.json"),
	})
	if err != nil {
		t.Fatal(err)
	}

	person := readInteropServiceJSON(t, service.Handler(), "/.well-known/aauth-person.json")
	if person["issuer"] != origin || person["person_token_endpoint"] != origin+"/person" ||
		person["auth_token_endpoint"] != origin+"/token" {
		t.Fatalf("Person Server metadata = %#v", person)
	}
	resource := readInteropServiceJSON(t, service.Handler(), "/.well-known/aauth-resource.json")
	components, _ := resource["additional_signature_components"].([]any)
	if resource["issuer"] != origin || !reflect.DeepEqual(components, []any{"content-type", "content-digest"}) {
		t.Fatalf("Resource metadata = %#v", resource)
	}
	keys := readInteropServiceJSON(t, service.Handler(), "/.well-known/jwks.json")
	keySet, ok := keys["keys"].([]any)
	if !ok || len(keySet) != 2 {
		t.Fatalf("collocated role JWKS = %#v, want two keys", keys)
	}
}

func readInteropServiceJSON(t *testing.T, handler http.Handler, path string) map[string]any {
	t.Helper()
	request := httptest.NewRequest(http.MethodGet, "https://service.example"+path, nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("GET %s = %d: %s", path, response.Code, response.Body.String())
	}
	var value map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &value); err != nil {
		t.Fatal(err)
	}
	return value
}
