package r3fetch

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"io"
	"net/http"
	"testing"
	"time"

	aauth "aauth-go"
	"aauth-go/jose"
	"aauth-go/r3"
	"aauth-go/signaturekey"
)

func TestClientFetchesOneExactSignedAndBoundedDocument(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 31, 8, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	key := r3FetchTestKey(t, "ps-key", 1)
	read, _ := r3.NewMCPOperation("records.read")
	operations, _ := r3.NewMCPOperationSet(read)
	document, _ := r3.NewDocument(operations, r3.DocumentOptions{})
	exact, _ := document.MarshalJSON()
	reference, _ := r3.NewReference("https://resource.example/r3/document", r3.Digest(exact))
	admitCalls, requestCalls := 0, 0
	transport := roundTripperFunc(func(request *http.Request) (*http.Response, error) {
		requestCalls++
		if request.Method != http.MethodGet || request.URL.String() != reference.URI() ||
			request.Header.Get("Accept") != "application/json" || request.Header.Get("Accept-Encoding") != "identity" {
			t.Fatalf("request = %s %s, accept/encoding %q/%q", request.Method, request.URL, request.Header.Get("Accept"), request.Header.Get("Accept-Encoding"))
		}
		prepared, err := signaturekey.PrepareRequest(request, clock, signaturekey.VerifyOptions{
			RequireExactComponents: true,
			AcceptedSchemes:        []signaturekey.Scheme{signaturekey.SchemeJWKSURI},
		})
		if err != nil {
			t.Fatal(err)
		}
		issuer, discovery, _, ok := prepared.Credential().JWKSURI()
		if !ok || issuer != "https://ps.example" || discovery != aauth.PersonDiscoveryDocument {
			t.Fatalf("credential = %q %q, %t", issuer, discovery, ok)
		}
		proof, err := prepared.VerifyJWKSURI(context.Background(), signaturekey.StaticKeyResolver{
			{Issuer: issuer, DiscoveryDocument: discovery, KeyID: key.ID()}: key.PublicJWK(),
		})
		if err != nil || proof.Signer() != issuer {
			t.Fatalf("proof = %#v, %v", proof, err)
		}
		return r3FetchResponse(http.StatusOK, exact, nil), nil
	})
	client, err := New(Config{
		HTTPClient: &http.Client{Transport: transport},
		SigningKey: key, Issuer: "https://ps.example",
		DiscoveryDocument: aauth.PersonDiscoveryDocument, Clock: clock,
		Admit: func(_ context.Context, endpoint string) error {
			admitCalls++
			if endpoint != reference.URI() {
				t.Fatalf("admitted endpoint = %q", endpoint)
			}
			return nil
		},
		MaximumDocumentBytes: int64(len(exact)),
	})
	if err != nil {
		t.Fatal(err)
	}
	gotDocument, gotExact, err := client.Fetch(context.Background(), reference)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotExact, exact) || !gotDocument.OperationSet().Equal(operations) || admitCalls != 1 || requestCalls != 1 {
		t.Fatalf("fetch = %q %#v, calls admit/request=%d/%d", gotExact, gotDocument, admitCalls, requestCalls)
	}
}

func TestClientRefusesUnsafeOrInexactDocumentFetches(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 31, 8, 15, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	key := r3FetchTestKey(t, "as-key", 2)
	exact := []byte(`{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"records.read"}]}`)
	reference, _ := r3.NewReference("https://resource.example/r3/document", r3.Digest(exact))

	for _, test := range []struct {
		name              string
		admitError        error
		status            int
		body              []byte
		header            http.Header
		maxBytes          int64
		wantCalls         int
		transportError    error
		wantDocumentError bool
	}{
		{name: "egress refusal", admitError: errors.New("not admitted")},
		{name: "transport failure", transportError: errors.New("network unavailable"), wantCalls: 1},
		{name: "redirect", status: http.StatusFound, header: http.Header{"Location": []string{"https://other.example/r3/document"}}, wantCalls: 1, wantDocumentError: true},
		{name: "Resource authentication failure", status: http.StatusUnauthorized, wantCalls: 1},
		{name: "Resource authorization failure", status: http.StatusForbidden, wantCalls: 1},
		{name: "Resource timeout", status: http.StatusRequestTimeout, wantCalls: 1},
		{name: "Resource throttling", status: http.StatusTooManyRequests, wantCalls: 1},
		{name: "Resource service failure", status: http.StatusServiceUnavailable, wantCalls: 1},
		{name: "wrong media type", status: http.StatusOK, body: exact, header: http.Header{"Content-Type": []string{"text/plain"}}, wantCalls: 1, wantDocumentError: true},
		{name: "content encoding", status: http.StatusOK, body: exact, header: http.Header{"Content-Encoding": []string{"gzip"}}, wantCalls: 1, wantDocumentError: true},
		{name: "ambiguous content encoding", status: http.StatusOK, body: exact, header: http.Header{"Content-Encoding": []string{"identity", "gzip"}}, wantCalls: 1, wantDocumentError: true},
		{name: "oversized", status: http.StatusOK, body: exact, maxBytes: int64(len(exact) - 1), wantCalls: 1, wantDocumentError: true},
		{name: "hash mismatch", status: http.StatusOK, body: append(append([]byte(nil), exact...), ' '), wantCalls: 1, wantDocumentError: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			calls := 0
			transport := roundTripperFunc(func(*http.Request) (*http.Response, error) {
				calls++
				if test.transportError != nil {
					return nil, test.transportError
				}
				return r3FetchResponse(test.status, test.body, test.header), nil
			})
			client, err := New(Config{
				HTTPClient: &http.Client{Transport: transport},
				SigningKey: key, Issuer: "https://as.example",
				DiscoveryDocument: aauth.AccessDiscoveryDocument, Clock: clock,
				Admit:                func(context.Context, string) error { return test.admitError },
				MaximumDocumentBytes: test.maxBytes,
			})
			if err != nil {
				t.Fatal(err)
			}
			_, _, fetchErr := client.Fetch(context.Background(), reference)
			if fetchErr == nil {
				t.Fatal("Fetch accepted unsafe or inexact response")
			}
			if IsDocumentError(fetchErr) != test.wantDocumentError {
				t.Fatalf("IsDocumentError(%v) = %t", fetchErr, IsDocumentError(fetchErr))
			}
			if calls != test.wantCalls {
				t.Fatalf("HTTP calls = %d", calls)
			}
		})
	}
}

func TestClientFetchTimeoutBoundsEgressAdmission(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 31, 8, 30, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	key := r3FetchTestKey(t, "ps-key", 3)
	exact := []byte(`{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"records.read"}]}`)
	reference, _ := r3.NewReference("https://resource.example/r3/document", r3.Digest(exact))
	client, err := New(Config{
		HTTPClient: &http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
			t.Fatal("timed-out admission reached transport")
			return nil, nil
		})},
		SigningKey: key, Issuer: "https://ps.example",
		DiscoveryDocument: aauth.PersonDiscoveryDocument, Clock: clock,
		Admit: func(ctx context.Context, _ string) error {
			<-ctx.Done()
			return ctx.Err()
		},
		Timeout: 10 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, _, err := client.Fetch(context.Background(), reference)
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("Fetch error = %v, want deadline exceeded", err)
		}
	case <-time.After(250 * time.Millisecond):
		t.Fatal("FetchTimeout did not bound egress admission")
	}
}

func r3FetchResponse(status int, body []byte, header http.Header) *http.Response {
	if header == nil {
		header = make(http.Header)
	}
	if status == http.StatusOK && header.Get("Content-Type") == "" {
		header.Set("Content-Type", "application/json")
	}
	return &http.Response{
		StatusCode: status,
		Header:     header,
		Body:       io.NopCloser(bytes.NewReader(body)),
	}
}

func r3FetchTestKey(t *testing.T, id string, fill byte) jose.SigningKey {
	t.Helper()
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{fill}, ed25519.SeedSize))
	key, err := jose.NewEd25519SigningKey(id, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (roundTrip roundTripperFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return roundTrip(request)
}
