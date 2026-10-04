package personserver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

func TestRevokeAuthTokenUsesRetainedResourceAndOneSignedRequest(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 30, 21, 30, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	personKey := personServerTestKey(t, "revocation-person")
	const (
		personID   = "https://person.example"
		resourceID = "https://resource.example"
	)
	issued := newTestIssuedAuthTokenStore()
	record := IssuedAuthTokenRecord{
		Reference: aauth.TokenReference{Issuer: personID, JTI: "revocable-auth-token"},
		Resource:  resourceID, CompactSHA256: [32]byte{1},
		IssuedAt: now, ExpiresAt: now.Add(time.Hour),
	}
	if err := issued.CommitIssuedAuthToken(context.Background(), record); err != nil {
		t.Fatal(err)
	}
	requests := 0
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	resourceURL, err := url.Parse(resourceID)
	if err != nil {
		t.Fatal(err)
	}
	jar.SetCookies(resourceURL, []*http.Cookie{{Name: "private-session", Value: "secret"}})
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		requests++
		if request.Header.Get("Cookie") != "" {
			t.Errorf("caller cookie jar leaked: %v", request.Header)
		}
		switch {
		case request.Method == http.MethodGet && request.URL.String() == resourceID+"/.well-known/aauth-resource.json":
			body, _ := json.Marshal(map[string]any{
				"issuer": resourceID, "revocation_endpoint": resourceID + "/revoke",
				"additional_signature_components": []string{"x-revocation-context", "x-tenant-context"},
			})
			return &http.Response{
				StatusCode: http.StatusOK, Status: "200 OK", Request: request,
				Header: http.Header{"Content-Type": []string{"application/json"}},
				Body:   io.NopCloser(bytes.NewReader(body)),
			}, nil
		case request.Method == http.MethodPost && request.URL.String() == resourceID+"/revoke":
			if request.Header.Get("Authorization") != "" {
				t.Errorf("unadvertised caller headers leaked: %v", request.Header)
			}
			prepared, err := signaturekey.PrepareRequest(request, clock, signaturekey.VerifyOptions{
				RequiredComponents: []string{"content-type", "content-digest", "x-revocation-context", "x-tenant-context"},
				AcceptedSchemes:    []signaturekey.Scheme{signaturekey.SchemeJWKSURI},
			})
			if err != nil {
				t.Errorf("prepare revoke proof: %v", err)
			} else {
				issuer, document, _, ok := prepared.Credential().JWKSURI()
				proof, verifyErr := prepared.Verify(personKey.PublicJWK())
				if !ok || issuer != personID || document != aauth.PersonDiscoveryDocument || verifyErr != nil || proof.Signer() != personID {
					t.Errorf("revoke proof issuer=%q document=%q present=%t proof=%#v err=%v", issuer, document, ok, proof, verifyErr)
				}
			}
			body, _ := io.ReadAll(request.Body)
			wantBody := fmt.Sprintf(`{"jti":%q,"exp":%d}`, record.Reference.JTI, record.ExpiresAt.Unix())
			if string(body) != wantBody {
				t.Errorf("revoke body = %s, want %s", body, wantBody)
			}
			return &http.Response{
				StatusCode: http.StatusOK, Status: "200 OK", Request: request,
				Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(nil)),
			}, nil
		default:
			return nil, errors.New("unexpected revocation request: " + request.Method + " " + request.URL.String())
		}
	}), Jar: jar}
	server, err := NewPSAuthorization(PSAuthorizationConfig{
		Issuer: personID, SigningKey: personKey, KeyResolver: signaturekey.StaticKeyResolver{},
		Clock: clock, NewID: func() string { return "unused" }, Tokens: newMemoryTokenStore(),
		BindPerson: func(context.Context, PersonTokenRequest) (Person, error) { return Person{}, nil },
		Authorize: func(context.Context, AuthorizationRequest) (AuthorizationDecision, error) {
			return AuthorizationDecision{Scopes: []string{"records.read"}, Lifetime: time.Minute}, nil
		},
		Revocation: &AuthTokenRevocationConfig{IssuedTokens: issued, HTTPClient: client, Admit: allowRevocationEgress},
	})
	if err != nil {
		t.Fatal(err)
	}
	err = server.RevokeIssuedAuthToken(context.Background(), record.Reference)
	var missing *signaturekey.Error
	if !errors.As(err, &missing) || missing.Code != signaturekey.ErrorInvalidInput ||
		!slices.Equal(missing.RequiredInput, []string{"x-revocation-context", "x-tenant-context"}) {
		t.Fatalf("missing advertised headers = %#v, %v", missing, err)
	}
	if requests != 1 {
		t.Fatalf("missing advertised header made %d requests, want metadata only", requests)
	}
	if err := server.RevokeIssuedAuthTokenWithHeaders(
		context.Background(), record.Reference, http.Header{
			"X-Revocation-Context": []string{"audit-1"},
			"X-Tenant-Context":     []string{"tenant-1"},
			"Authorization":        []string{"Bearer private"},
			"Cookie":               []string{"private=true"},
		},
	); err != nil {
		t.Fatal(err)
	}
	if requests != 3 {
		t.Fatalf("revocation requests = %d, want two metadata plus one revoke", requests)
	}
	if got := jar.Cookies(resourceURL); len(got) != 1 || got[0].Name != "private-session" || got[0].Value != "secret" {
		t.Fatalf("caller cookie jar changed: %#v", got)
	}
}

func TestDeferredAuthTokenIsRetainedBeforeTerminalPublication(t *testing.T) {
	protocol := newAuthorizationInteractionProtocol(t)
	pending := newMemoryDeferredAuthorizationStore()
	issued := newTestIssuedAuthTokenStore()
	issued.commitError = errors.New("issued-token store unavailable")
	config := protocol.config(pending)
	config.Revocation = &AuthTokenRevocationConfig{
		IssuedTokens: issued,
		Admit:        allowRevocationEgress,
		HTTPClient: &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
			return nil, errors.New("unexpected revocation request: " + request.URL.String())
		})},
	}
	server, err := NewPSAuthorization(config)
	if err != nil {
		t.Fatal(err)
	}
	started := protocol.exchange(t, server, []string{"interaction"})
	requirement, err := aauth.ParseInteractionRequirement(started.Header().Values("AAuth-Requirement"))
	if err != nil {
		t.Fatal(err)
	}
	reference := requirement.URL[strings.LastIndex(requirement.URL, "/")+1:]
	interaction, err := server.ConsumeAuthorizationInteractionCode(context.Background(), reference, requirement.Code)
	if err != nil {
		t.Fatal(err)
	}
	if err := server.ApproveAuthorizationInteraction(context.Background(), interaction, AuthorizationDecision{
		Scopes: []string{"records.read"}, Lifetime: time.Minute,
	}); err != nil {
		t.Fatal(err)
	}

	failed := protocol.poll(t, server, started.Header().Get("Location"), protocol.agentKey, protocol.agentToken)
	assertAuthorizationInteractionProblem(t, failed, http.StatusInternalServerError, "server_error")
	if pending.consumeCalls != 0 || issued.commitCalls != 1 {
		t.Fatalf("failed retention: consume=%d commits=%d", pending.consumeCalls, issued.commitCalls)
	}
	approved := pending.approvedPoll(t)
	issued.commitError = nil
	pending.consumeError = errors.New("terminal consume unavailable")
	consumeFailed := protocol.poll(t, server, started.Header().Get("Location"), protocol.agentKey, protocol.agentToken)
	assertAuthorizationInteractionProblem(t, consumeFailed, http.StatusInternalServerError, "server_error")
	if pending.consumeCalls != 0 || issued.commitCalls != 2 {
		t.Fatalf("failed terminal consumption: consume=%d commits=%d", pending.consumeCalls, issued.commitCalls)
	}
	succeeded := protocol.poll(t, server, started.Header().Get("Location"), protocol.agentKey, protocol.agentToken)
	if succeeded.Code != http.StatusOK || pending.consumeCalls != 1 || issued.commitCalls != 3 {
		t.Fatalf("retained publication = %d %s; consume=%d commits=%d", succeeded.Code, succeeded.Body.String(), pending.consumeCalls, issued.commitCalls)
	}
	claims, err := aauth.VerifyAuthToken(context.Background(), approved.Token, protocol.resolver, protocol.clock)
	if err != nil {
		t.Fatal(err)
	}
	record, err := issued.LoadIssuedAuthToken(context.Background(), aauth.TokenReference{Issuer: claims.Issuer, JTI: claims.JTI})
	if err != nil || record.Resource != protocol.resourceID {
		t.Fatalf("deferred issued record = %#v, %v", record, err)
	}
}

func TestRevokeIssuedAuthTokenPreservesLocalAndRemoteOutcomes(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 30, 21, 45, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	personKey := personServerTestKey(t, "revocation-outcomes-person")
	const (
		personID   = "https://person.example"
		resourceID = "https://resource.example"
	)
	reference := aauth.TokenReference{Issuer: personID, JTI: "outcome-auth-token"}
	newServer := func(t *testing.T, issued IssuedAuthTokenStore, client *http.Client) *Server {
		t.Helper()
		server, err := NewPSAuthorization(PSAuthorizationConfig{
			Issuer: personID, SigningKey: personKey, KeyResolver: signaturekey.StaticKeyResolver{},
			Clock: clock, NewID: func() string { return "unused" }, Tokens: newMemoryTokenStore(),
			BindPerson: func(context.Context, PersonTokenRequest) (Person, error) { return Person{}, nil },
			Authorize: func(context.Context, AuthorizationRequest) (AuthorizationDecision, error) {
				return AuthorizationDecision{Scopes: []string{"records.read"}, Lifetime: time.Minute}, nil
			},
			Revocation: &AuthTokenRevocationConfig{IssuedTokens: issued, HTTPClient: client, Admit: allowRevocationEgress},
		})
		if err != nil {
			t.Fatal(err)
		}
		return server
	}

	t.Run("unknown local reference makes no request", func(t *testing.T) {
		calls := 0
		client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			calls++
			return nil, errors.New("unexpected request")
		})}
		server := newServer(t, newTestIssuedAuthTokenStore(), client)
		if err := server.RevokeIssuedAuthToken(context.Background(), reference); !errors.Is(err, ErrIssuedAuthTokenNotFound) {
			t.Fatalf("unknown reference = %v", err)
		}
		if calls != 0 {
			t.Fatalf("unknown reference made %d requests", calls)
		}
	})

	t.Run("Resource decides whether an expired token is already invalid", func(t *testing.T) {
		issued := newTestIssuedAuthTokenStore()
		if err := issued.CommitIssuedAuthToken(context.Background(), IssuedAuthTokenRecord{
			Reference: reference, Resource: resourceID,
			CompactSHA256: [32]byte{1}, IssuedAt: now.Add(-2 * time.Hour), ExpiresAt: now.Add(-time.Hour),
		}); err != nil {
			t.Fatal(err)
		}
		calls := 0
		server := newServer(t, issued, &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
			calls++
			if request.Method == http.MethodGet {
				body, _ := json.Marshal(map[string]string{
					"issuer": resourceID, "revocation_endpoint": resourceID + "/revoke",
				})
				return &http.Response{
					StatusCode: http.StatusOK, Status: "200 OK", Request: request,
					Header: http.Header{"Content-Type": []string{"application/json"}},
					Body:   io.NopCloser(bytes.NewReader(body)),
				}, nil
			}
			return &http.Response{
				StatusCode: http.StatusOK, Status: "200 OK", Request: request,
				Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(nil)),
			}, nil
		})})
		if err := server.RevokeIssuedAuthToken(context.Background(), reference); err != nil {
			t.Fatalf("expired reference = %v", err)
		}
		if calls != 2 {
			t.Fatalf("expired reference made %d requests, want metadata plus revoke", calls)
		}
	})

	t.Run("remote 404 is a failure not a recorded revocation", func(t *testing.T) {
		issued := newTestIssuedAuthTokenStore()
		if err := issued.CommitIssuedAuthToken(context.Background(), IssuedAuthTokenRecord{
			Reference: reference, Resource: resourceID,
			CompactSHA256: [32]byte{1}, IssuedAt: now, ExpiresAt: now.Add(time.Hour),
		}); err != nil {
			t.Fatal(err)
		}
		calls := 0
		client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
			calls++
			if request.Method == http.MethodGet {
				body, _ := json.Marshal(map[string]string{
					"issuer": resourceID, "revocation_endpoint": resourceID + "/revoke",
				})
				return &http.Response{
					StatusCode: http.StatusOK, Status: "200 OK", Request: request,
					Header: http.Header{"Content-Type": []string{"application/json"}},
					Body:   io.NopCloser(bytes.NewReader(body)),
				}, nil
			}
			return &http.Response{
				StatusCode: http.StatusNotFound, Status: "404 Not Found", Request: request,
				Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(nil)),
			}, nil
		})}
		server := newServer(t, issued, client)
		if err := server.RevokeIssuedAuthToken(context.Background(), reference); err == nil || !strings.Contains(err.Error(), "404") {
			t.Fatalf("remote 404 = %v", err)
		}
		if calls != 2 {
			t.Fatalf("remote unknown made %d requests", calls)
		}
	})

	t.Run("malformed nonempty 200 is revocation_unavailable", func(t *testing.T) {
		issued := newTestIssuedAuthTokenStore()
		if err := issued.CommitIssuedAuthToken(context.Background(), IssuedAuthTokenRecord{
			Reference: reference, Resource: resourceID,
			CompactSHA256: [32]byte{1}, IssuedAt: now, ExpiresAt: now.Add(time.Hour),
		}); err != nil {
			t.Fatal(err)
		}
		for name, answer := range map[string]struct {
			contentType, body string
			wantErr           bool
		}{
			"empty":      {"", "", false},
			"object":     {"application/json", `{}`, false},
			"extension":  {"application/json", `{"Downstream":{"vendor":true}}`, false},
			"null":       {"application/json", `null`, true},
			"null list":  {"application/json", `{"downstream":null}`, true},
			"text":       {"text/plain", `ok`, true},
			"json array": {"application/json", `[]`, true},
			"no type":    {"", `{}`, true},
			"bad syntax": {"application/json", `{`, true},
		} {
			client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
				header := make(http.Header)
				body := answer.body
				if request.Method == http.MethodGet {
					raw, _ := json.Marshal(map[string]string{"issuer": resourceID, "revocation_endpoint": resourceID + "/revoke"})
					header.Set("Content-Type", "application/json")
					body = string(raw)
				} else if answer.contentType != "" {
					header.Set("Content-Type", answer.contentType)
				}
				return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Request: request, Header: header, Body: io.NopCloser(strings.NewReader(body))}, nil
			})}
			err := newServer(t, issued, client).RevokeIssuedAuthToken(context.Background(), reference)
			if answer.wantErr != errors.Is(err, aauth.ErrRevocationUnavailable) || (!answer.wantErr && err != nil) {
				t.Fatalf("%s: 200 %q = %v", name, answer.body, err)
			}
		}
	})
}

func TestRevokeIssuedAuthTokenRejectsUnsafeResourceMetadataBeforePOST(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 30, 21, 50, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	personKey := personServerTestKey(t, "revocation-metadata-person")
	const (
		personID   = "https://person.example"
		resourceID = "https://resource.example"
	)
	reference := aauth.TokenReference{Issuer: personID, JTI: "metadata-auth-token"}

	tests := []struct {
		name      string
		status    int
		body      string
		location  string
		wantError string
	}{
		{
			name: "missing issuer", status: http.StatusOK,
			body:      `{"revocation_endpoint":"https://resource.example/revoke"}`,
			wantError: "issuer does not match",
		},
		{
			name: "issuer mismatch", status: http.StatusOK,
			body:      `{"issuer":"https://other.example","revocation_endpoint":"https://resource.example/revoke"}`,
			wantError: "issuer does not match",
		},
		{
			name: "missing endpoint", status: http.StatusOK,
			body:      `{"issuer":"https://resource.example"}`,
			wantError: "revocation_endpoint",
		},
		{
			name: "insecure endpoint", status: http.StatusOK,
			body:      `{"issuer":"https://resource.example","revocation_endpoint":"http://resource.example/revoke"}`,
			wantError: "revocation_endpoint",
		},
		{
			name: "invalid signature component", status: http.StatusOK,
			body:      `{"issuer":"https://resource.example","revocation_endpoint":"https://resource.example/revoke","additional_signature_components":["@method"]}`,
			wantError: "signature profile",
		},
		{
			name: "duplicate signature component", status: http.StatusOK,
			body:      `{"issuer":"https://resource.example","revocation_endpoint":"https://resource.example/revoke","additional_signature_components":["x-revocation-context","x-revocation-context"]}`,
			wantError: "duplicated",
		},
		{
			name: "case-ambiguous issuer", status: http.StatusOK,
			body:      `{"issuer":"https://resource.example","Issuer":"https://resource.example","revocation_endpoint":"https://resource.example/revoke"}`,
			wantError: "decode Resource metadata",
		},
		{
			name: "redirect", status: http.StatusFound,
			location:  "https://redirected.example/metadata",
			wantError: "metadata returned 302",
		},
		{
			name: "oversized metadata", status: http.StatusOK,
			body: `{"issuer":"https://resource.example","revocation_endpoint":"https://resource.example/revoke","padding":"` +
				strings.Repeat("x", int(maxRequestBytes)) + `"}`,
			wantError: "too large",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			issued := newTestIssuedAuthTokenStore()
			if err := issued.CommitIssuedAuthToken(context.Background(), IssuedAuthTokenRecord{
				Reference: reference, Resource: resourceID,
				CompactSHA256: [32]byte{1}, IssuedAt: now, ExpiresAt: now.Add(time.Hour),
			}); err != nil {
				t.Fatal(err)
			}
			var requests []string
			client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
				requests = append(requests, request.Method+" "+request.URL.String())
				if request.URL.String() != resourceID+"/.well-known/aauth-resource.json" {
					return nil, errors.New("unexpected request: " + request.Method + " " + request.URL.String())
				}
				header := http.Header{"Content-Type": []string{"application/json"}}
				if test.location != "" {
					header.Set("Location", test.location)
				}
				return &http.Response{
					StatusCode: test.status, Status: fmt.Sprintf("%d %s", test.status, http.StatusText(test.status)),
					Request: request, Header: header, Body: io.NopCloser(strings.NewReader(test.body)),
				}, nil
			})}
			server, err := NewPSAuthorization(PSAuthorizationConfig{
				Issuer: personID, SigningKey: personKey, KeyResolver: signaturekey.StaticKeyResolver{},
				Clock: clock, NewID: func() string { return "unused" }, Tokens: newMemoryTokenStore(),
				BindPerson: func(context.Context, PersonTokenRequest) (Person, error) { return Person{}, nil },
				Authorize: func(context.Context, AuthorizationRequest) (AuthorizationDecision, error) {
					return AuthorizationDecision{Scopes: []string{"records.read"}, Lifetime: time.Minute}, nil
				},
				Revocation: &AuthTokenRevocationConfig{IssuedTokens: issued, HTTPClient: client, Admit: allowRevocationEgress},
			})
			if err != nil {
				t.Fatal(err)
			}
			err = server.RevokeIssuedAuthToken(context.Background(), reference)
			if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("metadata error = %v, want %q", err, test.wantError)
			}
			if len(requests) != 1 || requests[0] != http.MethodGet+" "+resourceID+"/.well-known/aauth-resource.json" {
				t.Fatalf("requests = %#v, want metadata GET only", requests)
			}
		})
	}
}

func TestRevokeIssuedAuthTokenAppliesEgressPolicyBeforeEachRequest(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 30, 21, 55, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	personKey := personServerTestKey(t, "revocation-egress-person")
	const (
		personID   = "https://person.example"
		resourceID = "https://resource.example"
	)
	reference := aauth.TokenReference{Issuer: personID, JTI: "egress-auth-token"}

	for _, denyEndpoint := range []string{
		resourceID + "/.well-known/aauth-resource.json",
		resourceID + "/revoke",
	} {
		t.Run(denyEndpoint, func(t *testing.T) {
			issued := newTestIssuedAuthTokenStore()
			if err := issued.CommitIssuedAuthToken(context.Background(), IssuedAuthTokenRecord{
				Reference: reference, Resource: resourceID,
				CompactSHA256: [32]byte{1}, IssuedAt: now, ExpiresAt: now.Add(time.Hour),
			}); err != nil {
				t.Fatal(err)
			}
			var requests, admissions []string
			client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
				requests = append(requests, request.Method+" "+request.URL.String())
				body, _ := json.Marshal(map[string]string{
					"issuer": resourceID, "revocation_endpoint": resourceID + "/revoke",
				})
				return &http.Response{
					StatusCode: http.StatusOK, Status: "200 OK", Request: request,
					Header: http.Header{"Content-Type": []string{"application/json"}},
					Body:   io.NopCloser(bytes.NewReader(body)),
				}, nil
			})}
			server, err := NewPSAuthorization(PSAuthorizationConfig{
				Issuer: personID, SigningKey: personKey, KeyResolver: signaturekey.StaticKeyResolver{},
				Clock: clock, NewID: func() string { return "unused" }, Tokens: newMemoryTokenStore(),
				BindPerson: func(context.Context, PersonTokenRequest) (Person, error) { return Person{}, nil },
				Authorize: func(context.Context, AuthorizationRequest) (AuthorizationDecision, error) {
					return AuthorizationDecision{Scopes: []string{"records.read"}, Lifetime: time.Minute}, nil
				},
				Revocation: &AuthTokenRevocationConfig{
					IssuedTokens: issued, HTTPClient: client,
					Admit: func(_ context.Context, endpoint string) error {
						admissions = append(admissions, endpoint)
						if endpoint == denyEndpoint {
							return errors.New("egress denied")
						}
						return nil
					},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			err = server.RevokeIssuedAuthToken(context.Background(), reference)
			if err == nil || !strings.Contains(err.Error(), "egress admission failed") {
				t.Fatalf("egress error = %v", err)
			}
			wantAdmissions := []string{resourceID + "/.well-known/aauth-resource.json"}
			wantRequests := []string(nil)
			if denyEndpoint == resourceID+"/revoke" {
				wantAdmissions = append(wantAdmissions, resourceID+"/revoke")
				wantRequests = []string{http.MethodGet + " " + resourceID + "/.well-known/aauth-resource.json"}
			}
			if !slices.Equal(admissions, wantAdmissions) || !slices.Equal(requests, wantRequests) {
				t.Fatalf("admissions=%#v requests=%#v; want %#v %#v", admissions, requests, wantAdmissions, wantRequests)
			}
		})
	}
}

func TestRevokeIssuedAuthTokenDoesNotFollowRedirectsOrMutateCallerClient(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 30, 21, 57, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	personKey := personServerTestKey(t, "revocation-redirect-person")
	const (
		personID = "https://person.example"
		origin   = "https://resource.example"
	)

	for _, phase := range []string{"metadata", "revocation"} {
		for _, status := range []int{http.StatusFound, http.StatusTemporaryRedirect} {
			t.Run(fmt.Sprintf("%s-%d", phase, status), func(t *testing.T) {
				targetCalls, metadataCalls, revokeCalls := 0, 0, 0
				transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
					response := &http.Response{
						StatusCode: http.StatusOK, Status: "200 OK", Request: request,
						Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(nil)),
					}
					switch request.URL.Path {
					case "/.well-known/aauth-resource.json":
						metadataCalls++
						if phase == "metadata" {
							response.StatusCode = status
							response.Status = fmt.Sprintf("%d %s", status, http.StatusText(status))
							response.Header.Set("Location", origin+"/redirect-target")
							return response, nil
						}
						body, _ := json.Marshal(map[string]string{
							"issuer": origin, "revocation_endpoint": origin + "/revoke",
						})
						response.Body = io.NopCloser(bytes.NewReader(body))
					case "/revoke":
						revokeCalls++
						response.StatusCode = status
						response.Status = fmt.Sprintf("%d %s", status, http.StatusText(status))
						response.Header.Set("Location", origin+"/redirect-target")
					case "/caller-redirect":
						response.StatusCode = http.StatusFound
						response.Status = "302 Found"
						response.Header.Set("Location", origin+"/redirect-target")
					case "/redirect-target":
						targetCalls++
						response.StatusCode = http.StatusNoContent
						response.Status = "204 No Content"
					default:
						return nil, errors.New("unexpected request: " + request.URL.String())
					}
					return response, nil
				})
				reference := aauth.TokenReference{Issuer: personID, JTI: "redirect-auth-token"}
				issued := newTestIssuedAuthTokenStore()
				if err := issued.CommitIssuedAuthToken(context.Background(), IssuedAuthTokenRecord{
					Reference: reference, Resource: origin,
					CompactSHA256: [32]byte{1}, IssuedAt: now, ExpiresAt: now.Add(time.Hour),
				}); err != nil {
					t.Fatal(err)
				}
				callerClient := &http.Client{Transport: transport}
				callerRedirects := 0
				callerClient.CheckRedirect = func(*http.Request, []*http.Request) error {
					callerRedirects++
					return nil
				}
				server, err := NewPSAuthorization(PSAuthorizationConfig{
					Issuer: personID, SigningKey: personKey, KeyResolver: signaturekey.StaticKeyResolver{},
					Clock: clock, NewID: func() string { return "unused" }, Tokens: newMemoryTokenStore(),
					BindPerson: func(context.Context, PersonTokenRequest) (Person, error) { return Person{}, nil },
					Authorize: func(context.Context, AuthorizationRequest) (AuthorizationDecision, error) {
						return AuthorizationDecision{Scopes: []string{"records.read"}, Lifetime: time.Minute}, nil
					},
					Revocation: &AuthTokenRevocationConfig{
						IssuedTokens: issued, HTTPClient: callerClient, Admit: allowRevocationEgress,
					},
				})
				if err != nil {
					t.Fatal(err)
				}
				if err := server.RevokeIssuedAuthToken(context.Background(), reference); err == nil {
					t.Fatal("redirected revocation unexpectedly succeeded")
				}
				wantRevokeCalls := 0
				if phase == "revocation" {
					wantRevokeCalls = 1
				}
				if targetCalls != 0 || callerRedirects != 0 || metadataCalls != 1 || revokeCalls != wantRevokeCalls {
					t.Fatalf("server redirects: target=%d caller=%d metadata=%d revoke=%d", targetCalls, callerRedirects, metadataCalls, revokeCalls)
				}

				response, err := callerClient.Get(origin + "/caller-redirect")
				if err != nil {
					t.Fatal(err)
				}
				response.Body.Close()
				if response.StatusCode != http.StatusNoContent || callerRedirects != 1 || targetCalls != 1 {
					t.Fatalf("caller client after server construction: status=%d redirects=%d target=%d", response.StatusCode, callerRedirects, targetCalls)
				}
			})
		}
	}
}

type testIssuedAuthTokenStore struct {
	mu          sync.Mutex
	records     map[aauth.TokenReference]IssuedAuthTokenRecord
	commitError error
	commitCalls int
	loadError   error
}

func newTestIssuedAuthTokenStore() *testIssuedAuthTokenStore {
	return &testIssuedAuthTokenStore{records: make(map[aauth.TokenReference]IssuedAuthTokenRecord)}
}

func (store *testIssuedAuthTokenStore) CommitIssuedAuthToken(_ context.Context, record IssuedAuthTokenRecord) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.commitCalls++
	if store.commitError != nil {
		return store.commitError
	}
	if retained, ok := store.records[record.Reference]; ok && retained != record {
		return ErrIssuedAuthTokenConflict
	}
	store.records[record.Reference] = record
	return nil
}

func (store *testIssuedAuthTokenStore) LoadIssuedAuthToken(_ context.Context, reference aauth.TokenReference) (IssuedAuthTokenRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.loadError != nil {
		return IssuedAuthTokenRecord{}, store.loadError
	}
	record, ok := store.records[reference]
	if !ok {
		return IssuedAuthTokenRecord{}, ErrIssuedAuthTokenNotFound
	}
	return record, nil
}

var _ IssuedAuthTokenStore = (*testIssuedAuthTokenStore)(nil)

func allowRevocationEgress(context.Context, string) error { return nil }
