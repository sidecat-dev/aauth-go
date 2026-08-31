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

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/r3"
	"gitlab.com/sidecat-dev/aauth-go/r3/vocab/mcp"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

func TestClientFetchesOneExactSignedAndBoundedDocument(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 31, 8, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	key := r3FetchTestKey(t, "ps-key", 1)
	registry := r3FetchRegistry(t)
	read, _ := mcp.NewOperation("records.read")
	operations, _ := mcp.NewOperationSet(read)
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
		Registry:   registry,
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
	gotDocument, gotExact, err := client.FetchDocument(context.Background(), reference)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotExact, exact) || !r3FetchOperationSetsEqual(t, gotDocument.OperationSet(), operations) ||
		admitCalls != 1 || requestCalls != 1 {
		t.Fatalf("fetch = %q %#v, calls admit/request=%d/%d", gotExact, gotDocument, admitCalls, requestCalls)
	}
}

func TestClientFetchesOneExactSignedAndBoundedProposal(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 31, 8, 5, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	key := r3FetchTestKey(t, "ps-key", 4)
	registry := r3FetchRegistry(t)
	typedOperation, err := mcp.NewOperation("records.read")
	if err != nil {
		t.Fatal(err)
	}
	operation, err := typedOperation.ToR3()
	if err != nil {
		t.Fatal(err)
	}
	parameter, err := r3.NewInlineParameter([]byte(`{"record_id":"record-1"}`))
	if err != nil {
		t.Fatal(err)
	}
	parameters, err := r3.NewParameters(map[string]r3.Parameter{"input": parameter})
	if err != nil {
		t.Fatal(err)
	}
	proposal, err := r3.NewProposal(operation, parameters, r3.ProposalOptions{})
	if err != nil {
		t.Fatal(err)
	}
	exact, err := proposal.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	reference, err := r3.NewReference("https://resource.example/r3/proposals/invocation-1", r3.Digest(exact))
	if err != nil {
		t.Fatal(err)
	}
	admitCalls, requestCalls := 0, 0
	client, err := New(Config{
		Registry: registry,
		HTTPClient: &http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
			requestCalls++
			return r3FetchResponse(http.StatusOK, exact, nil), nil
		})},
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
	gotProposal, gotExact, err := client.FetchProposal(context.Background(), reference)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotExact, exact) || !r3FetchOperationsEqual(t, gotProposal.Operation(), operation) ||
		admitCalls != 1 || requestCalls != 1 {
		t.Fatalf("fetch = %q %#v, calls admit/request=%d/%d", gotExact, gotProposal, admitCalls, requestCalls)
	}
}

func TestClientKeepsClassDocumentAndProposalParsersSeparate(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 31, 8, 10, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	key := r3FetchTestKey(t, "as-key", 5)
	registry := r3FetchRegistry(t)
	documentExact := []byte(`{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"records.read"}]}`)
	proposalExact := []byte(`{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"records.read"}],"parameters":{}}`)
	documentReference, _ := r3.NewReference("https://resource.example/r3/document", r3.Digest(documentExact))
	proposalReference, _ := r3.NewReference("https://resource.example/r3/proposals/invocation-2", r3.Digest(proposalExact))
	client, err := New(Config{
		Registry: registry,
		HTTPClient: &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
			switch request.URL.String() {
			case documentReference.URI():
				return r3FetchResponse(http.StatusOK, documentExact, nil), nil
			case proposalReference.URI():
				return r3FetchResponse(http.StatusOK, proposalExact, nil), nil
			default:
				t.Fatalf("unexpected request URI %q", request.URL)
				return nil, nil
			}
		})},
		SigningKey: key, Issuer: "https://as.example",
		DiscoveryDocument: aauth.AccessDiscoveryDocument, Clock: clock,
		Admit: func(context.Context, string) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := client.FetchDocument(context.Background(), proposalReference); err == nil || !IsDocumentError(err) {
		t.Fatalf("FetchDocument proposal error = %v", err)
	}
	if _, _, err := client.FetchProposal(context.Background(), documentReference); err == nil || !IsDocumentError(err) {
		t.Fatalf("FetchProposal class document error = %v", err)
	}
}

func TestClientFetchArtifactClassifiesOneFetchWithoutURIConventions(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 31, 8, 11, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	key := r3FetchTestKey(t, "ps-key", 7)
	registry := r3FetchRegistry(t)
	typedOperation, _ := mcp.NewOperation("records.read")
	operation, _ := typedOperation.ToR3()
	operations, _ := mcp.NewOperationSet(typedOperation)
	document, _ := r3.NewDocument(operations, r3.DocumentOptions{})
	documentExact, _ := document.MarshalJSON()
	parameters, _ := r3.NewParameters(map[string]r3.Parameter{})
	proposal, _ := r3.NewProposal(operation, parameters, r3.ProposalOptions{})
	proposalExact, _ := proposal.MarshalJSON()

	for _, test := range []struct {
		name         string
		exact        []byte
		wantDocument bool
		wantProposal bool
	}{
		{name: "class document at opaque URI", exact: documentExact, wantDocument: true},
		{name: "per-call proposal at opaque URI", exact: proposalExact, wantProposal: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			calls := 0
			client, err := New(Config{
				Registry: registry,
				HTTPClient: &http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
					calls++
					return r3FetchResponse(http.StatusOK, test.exact, nil), nil
				})},
				SigningKey: key, Issuer: "https://ps.example",
				DiscoveryDocument: aauth.PersonDiscoveryDocument, Clock: clock,
				Admit: func(context.Context, string) error { return nil },
			})
			if err != nil {
				t.Fatal(err)
			}
			reference := mustR3FetchReference(t, "https://resource.example/r3/artifacts/opaque", test.exact)
			artifact, err := client.FetchArtifact(context.Background(), reference)
			if err != nil {
				t.Fatal(err)
			}
			gotDocument, documentOK := artifact.Document()
			gotProposal, proposalOK := artifact.Proposal()
			if documentOK != test.wantDocument || proposalOK != test.wantProposal || documentOK == proposalOK {
				t.Fatalf("artifact kinds document/proposal = %t/%t", documentOK, proposalOK)
			}
			if documentOK && !r3FetchOperationSetsEqual(t, gotDocument.OperationSet(), operations) {
				t.Fatalf("document operation set = %#v", gotDocument.OperationSet())
			}
			if proposalOK && !r3FetchOperationsEqual(t, gotProposal.Operation(), operation) {
				t.Fatalf("proposal operation = %s", gotProposal.Operation().JSON())
			}
			gotExact := artifact.ExactBytes()
			if !bytes.Equal(gotExact, test.exact) || calls != 1 {
				t.Fatalf("exact = %q, calls = %d", gotExact, calls)
			}
			gotExact[0] ^= 0xff
			if !bytes.Equal(artifact.ExactBytes(), test.exact) {
				t.Fatal("returned exact bytes mutated retained artifact bytes")
			}
		})
	}
}

func TestClientFetchArtifactRefusesBytesThatAreNeitherStrictArtifact(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 31, 8, 11, 30, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	key := r3FetchTestKey(t, "as-key", 8)
	registry := r3FetchRegistry(t)
	malformed := []byte(`{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[],"parameters":{}}`)
	calls := 0
	client, err := New(Config{
		Registry: registry,
		HTTPClient: &http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
			calls++
			return r3FetchResponse(http.StatusOK, malformed, nil), nil
		})},
		SigningKey: key, Issuer: "https://as.example",
		DiscoveryDocument: aauth.AccessDiscoveryDocument, Clock: clock,
		Admit: func(context.Context, string) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	reference := mustR3FetchReference(t, "https://resource.example/r3/artifacts/opaque", malformed)
	if _, err := client.FetchArtifact(context.Background(), reference); err == nil || !IsDocumentError(err) {
		t.Fatalf("FetchArtifact error = %v", err)
	}
	if calls != 1 {
		t.Fatalf("HTTP calls = %d", calls)
	}
}

func TestClientFetchProposalBindsDigestBeforeStrictParsing(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 31, 8, 12, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	key := r3FetchTestKey(t, "as-key", 6)
	registry := r3FetchRegistry(t)
	valid := []byte(`{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"records.read"}],"parameters":{}}`)
	malformed := []byte(`{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"records.read"}],"parameters":[]}`)

	for _, test := range []struct {
		name      string
		reference r3.Reference
		body      []byte
	}{
		{name: "digest mismatch", reference: mustR3FetchReference(t, "https://resource.example/r3/proposals/digest", valid), body: append(append([]byte(nil), valid...), ' ')},
		{name: "malformed proposal", reference: mustR3FetchReference(t, "https://resource.example/r3/proposals/malformed", malformed), body: malformed},
	} {
		t.Run(test.name, func(t *testing.T) {
			client, err := New(Config{
				Registry: registry,
				HTTPClient: &http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
					return r3FetchResponse(http.StatusOK, test.body, nil), nil
				})},
				SigningKey: key, Issuer: "https://as.example",
				DiscoveryDocument: aauth.AccessDiscoveryDocument, Clock: clock,
				Admit: func(context.Context, string) error { return nil },
			})
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := client.FetchProposal(context.Background(), test.reference); err == nil || !IsDocumentError(err) {
				t.Fatalf("FetchProposal error = %v", err)
			}
		})
	}
}

func TestClientSharesUnsafeOrInexactResponseProtectionsAcrossFetchKinds(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 31, 8, 15, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	key := r3FetchTestKey(t, "as-key", 2)
	registry := r3FetchRegistry(t)
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
		for _, kind := range []string{"document", "proposal"} {
			t.Run(kind+"/"+test.name, func(t *testing.T) {
				calls := 0
				transport := roundTripperFunc(func(*http.Request) (*http.Response, error) {
					calls++
					if test.transportError != nil {
						return nil, test.transportError
					}
					return r3FetchResponse(test.status, test.body, test.header), nil
				})
				client, err := New(Config{
					Registry:   registry,
					HTTPClient: &http.Client{Transport: transport},
					SigningKey: key, Issuer: "https://as.example",
					DiscoveryDocument: aauth.AccessDiscoveryDocument, Clock: clock,
					Admit:                func(context.Context, string) error { return test.admitError },
					MaximumDocumentBytes: test.maxBytes,
				})
				if err != nil {
					t.Fatal(err)
				}
				var fetchErr error
				if kind == "document" {
					_, _, fetchErr = client.FetchDocument(context.Background(), reference)
				} else {
					_, _, fetchErr = client.FetchProposal(context.Background(), reference)
				}
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
}

func TestClientFetchTimeoutBoundsEgressAdmission(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 31, 8, 30, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	key := r3FetchTestKey(t, "ps-key", 3)
	registry := r3FetchRegistry(t)
	exact := []byte(`{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"records.read"}]}`)
	reference, _ := r3.NewReference("https://resource.example/r3/document", r3.Digest(exact))
	client, err := New(Config{
		Registry: registry,
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
		_, _, err := client.FetchDocument(context.Background(), reference)
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

func mustR3FetchReference(t *testing.T, uri string, exact []byte) r3.Reference {
	t.Helper()
	reference, err := r3.NewReference(uri, r3.Digest(exact))
	if err != nil {
		t.Fatal(err)
	}
	return reference
}

func r3FetchRegistry(t *testing.T) r3.Registry {
	t.Helper()
	registry, err := r3.NewRegistry(mcp.Vocabulary())
	if err != nil {
		t.Fatal(err)
	}
	return registry
}

func r3FetchOperationSetsEqual(t *testing.T, left, right r3.OperationSet) bool {
	t.Helper()
	equal, err := left.Equal(right)
	if err != nil {
		t.Fatal(err)
	}
	return equal
}

func r3FetchOperationsEqual(t *testing.T, left, right r3.Operation) bool {
	t.Helper()
	equal, err := left.Equal(right)
	if err != nil {
		t.Fatal(err)
	}
	return equal
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (roundTrip roundTripperFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return roundTrip(request)
}
