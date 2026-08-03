package reference

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
)

type r3RoundTripFunc func(*http.Request) (*http.Response, error)

func (function r3RoundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func TestR3FetchCacheEvictsLeastRecentlyUsedCompletedDocument(t *testing.T) {
	t.Parallel()

	documents := map[string][]byte{
		"one":   r3TestDocument("one"),
		"two":   r3TestDocument("two"),
		"three": r3TestDocument("three"),
	}
	var mu sync.Mutex
	fetches := make(map[string]int)
	server := newR3FetchTestAccessServer(t, r3FetchTestConfig{
		cacheLimit: 2,
		transport: r3RoundTripFunc(func(request *http.Request) (*http.Response, error) {
			for name, document := range documents {
				if strings.HasSuffix(request.URL.Path, aauth.R3S256(document)) {
					mu.Lock()
					fetches[name]++
					mu.Unlock()
					return r3HTTPResponse(request, http.StatusOK, document), nil
				}
			}
			return r3HTTPResponse(request, http.StatusNotFound, nil), nil
		}),
	})
	for _, name := range []string{"one", "two", "one", "three", "two"} {
		if _, err := server.fetchR3Authorization(
			context.Background(),
			r3TestResourceToken(documents[name]),
		); err != nil {
			t.Fatalf("fetch %s: %v", name, err)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if fetches["one"] != 1 || fetches["two"] != 2 || fetches["three"] != 1 {
		t.Fatalf("fetch counts = %#v", fetches)
	}
}

func TestR3FetchRechecksAdmissionBeforeServingWarmCache(t *testing.T) {
	t.Parallel()

	document := r3TestDocument("read")
	admitted := true
	admissionChecks := 0
	transportCalls := 0
	server := newR3FetchTestAccessServer(t, r3FetchTestConfig{
		admit: func(context.Context, string) error {
			admissionChecks++
			if !admitted {
				return errors.New("endpoint was withdrawn from egress policy")
			}
			return nil
		},
		transport: r3RoundTripFunc(func(request *http.Request) (*http.Response, error) {
			transportCalls++
			return r3HTTPResponse(request, http.StatusOK, document), nil
		}),
	})
	token := r3TestResourceToken(document)
	if _, err := server.fetchR3Authorization(context.Background(), token); err != nil {
		t.Fatal(err)
	}
	admitted = false
	if _, err := server.fetchR3Authorization(context.Background(), token); err == nil ||
		!strings.Contains(err.Error(), "not admitted") {
		t.Fatalf("withdrawn warm-cache admission error = %v", err)
	}
	if admissionChecks != 2 || transportCalls != 1 {
		t.Fatalf("admission checks = %d, transport calls = %d; want 2, 1", admissionChecks, transportCalls)
	}
}

func TestR3FetchSingleFlightSurvivesLeaderAndWaiterCancellation(t *testing.T) {
	t.Parallel()

	document := r3TestDocument("read")
	started := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	var mu sync.Mutex
	fetches := 0
	server := newR3FetchTestAccessServer(t, r3FetchTestConfig{
		cacheLimit: 2,
		transport: r3RoundTripFunc(func(request *http.Request) (*http.Response, error) {
			mu.Lock()
			fetches++
			mu.Unlock()
			once.Do(func() { close(started) })
			select {
			case <-release:
				return r3HTTPResponse(request, http.StatusOK, document), nil
			case <-request.Context().Done():
				return nil, request.Context().Err()
			}
		}),
	})
	token := r3TestResourceToken(document)
	leaderContext, cancelLeader := context.WithCancel(context.Background())
	leaderResult := make(chan error, 1)
	go func() {
		_, err := server.fetchR3Authorization(leaderContext, token)
		leaderResult <- err
	}()
	<-started
	cancelLeader()

	waiterContext, cancelWaiter := context.WithCancel(context.Background())
	cancelWaiter()
	if _, err := server.fetchR3Authorization(waiterContext, token); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled waiter error = %v", err)
	}
	close(release)
	if err := <-leaderResult; err != nil {
		t.Fatalf("canceled leader ended shared fetch: %v", err)
	}
	if _, err := server.fetchR3Authorization(context.Background(), token); err != nil {
		t.Fatalf("cached result after cancellation = %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if fetches != 1 {
		t.Fatalf("transport fetches = %d, want 1", fetches)
	}
}

func TestR3FetchRefusesDeniedRedirectedOversizedAndTimedOutDocuments(t *testing.T) {
	t.Parallel()

	document := r3TestDocument("read")
	t.Run("egress denied before transport", func(t *testing.T) {
		transportCalls := 0
		server := newR3FetchTestAccessServer(t, r3FetchTestConfig{
			admit: func(context.Context, string) error {
				return errors.New("outside admitted egress")
			},
			transport: r3RoundTripFunc(func(*http.Request) (*http.Response, error) {
				transportCalls++
				return nil, errors.New("transport must not run")
			}),
		})
		if _, err := server.fetchR3Authorization(
			context.Background(),
			r3TestResourceToken(document),
		); err == nil || !strings.Contains(err.Error(), "not admitted") {
			t.Fatalf("egress-denial error = %v", err)
		}
		if transportCalls != 0 {
			t.Fatalf("transport calls = %d", transportCalls)
		}
	})

	t.Run("redirect is not followed", func(t *testing.T) {
		var paths []string
		server := newR3FetchTestAccessServer(t, r3FetchTestConfig{
			transport: r3RoundTripFunc(func(request *http.Request) (*http.Response, error) {
				paths = append(paths, request.URL.Path)
				response := r3HTTPResponse(request, http.StatusFound, nil)
				response.Header.Set("Location", "https://other.example/r3/document")
				return response, nil
			}),
		})
		if _, err := server.fetchR3Authorization(
			context.Background(),
			r3TestResourceToken(document),
		); err == nil {
			t.Fatal("redirected R3 fetch succeeded")
		}
		if len(paths) != 1 {
			t.Fatalf("redirect paths = %#v", paths)
		}
	})

	t.Run("oversized exact bytes", func(t *testing.T) {
		oversized := bytes.Repeat([]byte("x"), maxJSONBody+1)
		server := newR3FetchTestAccessServer(t, r3FetchTestConfig{
			transport: r3RoundTripFunc(func(request *http.Request) (*http.Response, error) {
				return r3HTTPResponse(request, http.StatusOK, oversized), nil
			}),
		})
		if _, err := server.fetchR3Authorization(
			context.Background(),
			r3TestResourceToken(oversized),
		); err == nil || !strings.Contains(err.Error(), "too large") {
			t.Fatalf("oversized-document error = %v", err)
		}
	})

	t.Run("admitted transport deadline", func(t *testing.T) {
		server := newR3FetchTestAccessServer(t, r3FetchTestConfig{
			fetchTimeout: 20 * time.Millisecond,
			transport: r3RoundTripFunc(func(request *http.Request) (*http.Response, error) {
				<-request.Context().Done()
				return nil, request.Context().Err()
			}),
		})
		if _, err := server.fetchR3Authorization(
			context.Background(),
			r3TestResourceToken(document),
		); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("deadline error = %v", err)
		}
	})
}

func TestR3FetchRetryUsesDistinctNonceInSameClockSecond(t *testing.T) {
	t.Parallel()

	document := r3TestDocument("read")
	var signatureInputs []string
	server := newR3FetchTestAccessServer(t, r3FetchTestConfig{
		transport: r3RoundTripFunc(func(request *http.Request) (*http.Response, error) {
			signatureInputs = append(signatureInputs, request.Header.Get("Signature-Input"))
			return r3HTTPResponse(request, http.StatusServiceUnavailable, nil), nil
		}),
	})
	for attempt := 0; attempt < 2; attempt++ {
		if _, err := server.fetchR3Authorization(
			context.Background(),
			r3TestResourceToken(document),
		); err == nil {
			t.Fatalf("failed fetch %d succeeded", attempt+1)
		}
	}
	if len(signatureInputs) != 2 || signatureInputs[0] == signatureInputs[1] ||
		!strings.Contains(signatureInputs[0], "nonce=") ||
		!strings.Contains(signatureInputs[1], "nonce=") {
		t.Fatalf("same-second signature inputs = %#v", signatureInputs)
	}
}

type r3FetchTestConfig struct {
	admit        func(context.Context, string) error
	cacheLimit   int
	fetchTimeout time.Duration
	transport    http.RoundTripper
}

func newR3FetchTestAccessServer(
	t *testing.T,
	config r3FetchTestConfig,
) *AccessServer {
	t.Helper()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signingKey, err := aauth.NewEd25519SigningKey("access-key", privateKey)
	if err != nil {
		t.Fatal(err)
	}
	clock := aauth.ClockFunc(func() time.Time {
		return time.Date(2026, 8, 2, 18, 0, 0, 0, time.UTC)
	})
	admit := config.admit
	if admit == nil {
		admit = func(context.Context, string) error { return nil }
	}
	transport := config.transport
	if transport == nil {
		transport = r3RoundTripFunc(func(request *http.Request) (*http.Response, error) {
			return nil, fmt.Errorf("unexpected R3 transport request to %s", request.URL)
		})
	}
	server, err := NewAccessServer(AccessServerConfig{
		Identifier:  "https://as.example",
		SigningKey:  signingKey,
		KeyResolver: aauth.StaticKeyResolver{},
		Clock:       clock,
		NewID:       func() string { return "auth-token" },
		TrustedPersonServer: func(context.Context, string) error {
			return nil
		},
		AuthorizationPolicy: func(_ context.Context, request aauth.AuthorizationRequest) (aauth.AuthorizationDecision, error) {
			return aauth.AuthorizationDecision{Subject: "subject", Scope: request.Scope}, nil
		},
		R3HTTPClient:   &http.Client{Transport: transport},
		R3Audit:        func(context.Context, aauth.R3AuditRecord) error { return nil },
		R3Admit:        admit,
		R3FetchTimeout: config.fetchTimeout,
		R3CacheLimit:   config.cacheLimit,
	})
	if err != nil {
		t.Fatal(err)
	}
	return server
}

func r3TestDocument(tool string) []byte {
	return []byte(fmt.Sprintf(
		`{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":%q}]}`,
		tool,
	))
}

func r3TestResourceToken(document []byte) aauth.ResourceTokenClaims {
	digest := aauth.R3S256(document)
	return aauth.ResourceTokenClaims{
		Issuer: "https://resource.example",
		R3URI:  "https://resource.example/r3/" + digest,
		R3S256: digest,
	}
}

func r3HTTPResponse(
	request *http.Request,
	status int,
	body []byte,
) *http.Response {
	return &http.Response{
		StatusCode: status,
		Status:     fmt.Sprintf("%d %s", status, http.StatusText(status)),
		Header:     make(http.Header),
		Body:       io.NopCloser(bytes.NewReader(body)),
		Request:    request,
	}
}
