package signaturekey_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"sync"
	"testing"
	"time"

	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

// Signature-Key Scheme-Specific Risks: before fetching issuer metadata or a
// JWKS, the verifier rejects private, loopback, and link-local destinations
// unless deployment configuration allows them, and defends against DNS
// rebinding by pinning the resolved address for the connection. The resolver
// does both itself, through the transport it is given.
func TestHTTPKeyResolverRefusesNonPublicDiscoveryDestinations(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name      string
		addresses []string
	}{
		{name: "IPv4 loopback", addresses: []string{"127.0.0.1"}},
		{name: "IPv6 loopback", addresses: []string{"::1"}},
		{name: "RFC 1918 10/8", addresses: []string{"10.0.0.7"}},
		{name: "RFC 1918 172.16/12", addresses: []string{"172.16.4.4"}},
		{name: "RFC 1918 192.168/16", addresses: []string{"192.168.1.1"}},
		{name: "IPv4 link-local metadata service", addresses: []string{"169.254.169.254"}},
		{name: "IPv6 link-local", addresses: []string{"fe80::1"}},
		{name: "IPv6 unique local", addresses: []string{"fd00::1"}},
		{name: "unspecified", addresses: []string{"0.0.0.0"}},
		{name: "shared address space", addresses: []string{"100.64.0.1"}},
		{name: "IPv4-mapped loopback", addresses: []string{"::ffff:127.0.0.1"}},
		{name: "NAT64 private", addresses: []string{"64:ff9b::a00:7"}},
		{name: "public answer mixed with a private one", addresses: []string{"203.0.113.10", "10.0.0.7"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			var mu sync.Mutex
			dials := 0
			resolver, err := signaturekey.NewHTTPKeyResolver(signaturekey.HTTPKeyResolverConfig{
				Client: &http.Client{Transport: &http.Transport{
					DialContext: func(context.Context, string, string) (net.Conn, error) {
						mu.Lock()
						dials++
						mu.Unlock()
						return nil, errors.New("dialed a refused destination")
					},
				}},
				Clock: fixedClock(time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)),
				Admit: func(context.Context, string) error { return nil },
				LookupAddresses: func(_ context.Context, host string) ([]netip.Addr, error) {
					if host != "issuer.example" {
						return nil, fmt.Errorf("unexpected lookup %q", host)
					}
					addresses := make([]netip.Addr, 0, len(test.addresses))
					for _, value := range test.addresses {
						addresses = append(addresses, netip.MustParseAddr(value))
					}
					return addresses, nil
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			_, err = resolver.ResolveKey(context.Background(), "https://issuer.example", "aauth-agent.json", "issuer-key")
			var denied *signaturekey.ResolutionError
			if !errors.As(err, &denied) || denied.Code != signaturekey.ResolutionDenied {
				t.Fatalf("ResolveKey error = %T %v, want a denied resolution", err, err)
			}
			mu.Lock()
			defer mu.Unlock()
			if dials != 0 {
				t.Fatalf("refused destination was dialed %d times", dials)
			}
		})
	}

	t.Run("address literal", func(t *testing.T) {
		t.Parallel()
		resolver, err := signaturekey.NewHTTPKeyResolver(signaturekey.HTTPKeyResolverConfig{
			Client: &http.Client{},
			Clock:  fixedClock(time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)),
			Admit:  func(context.Context, string) error { return nil },
			LookupAddresses: func(context.Context, string) ([]netip.Addr, error) {
				return nil, errors.New("an address literal needs no lookup")
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		_, err = resolver.ResolveKey(context.Background(), "https://127.0.0.1", "aauth-agent.json", "issuer-key")
		var denied *signaturekey.ResolutionError
		if !errors.As(err, &denied) || denied.Code != signaturekey.ResolutionDenied {
			t.Fatalf("ResolveKey error = %T %v, want a denied resolution", err, err)
		}
	})
}

// A destination that deployment configuration allows is reached at exactly
// the address that was checked: the transport dials the resolved address, not
// the host name, so a later DNS answer cannot move the connection. A later
// connection resolves again and is checked again.
func TestHTTPKeyResolverPinsTheCheckedDiscoveryAddress(t *testing.T) {
	t.Parallel()

	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x5a}, ed25519.SeedSize))
	signingKey, err := jose.NewEd25519SigningKey("issuer-key", privateKey)
	if err != nil {
		t.Fatal(err)
	}
	// The httptest certificate is valid for example.com.
	const issuer = "https://example.com"
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/.well-known/aauth-agent.json":
			_, _ = fmt.Fprintf(response, `{"issuer":%q,"jwks_uri":%q}`, issuer, issuer+"/jwks")
		case "/jwks":
			_, _ = fmt.Fprintf(response, `{"keys":[{"kty":"OKP","crv":"Ed25519","alg":"Ed25519","x":%q,"kid":"issuer-key","use":"sig"}]}`, signingKey.PublicJWK().X)
		default:
			http.NotFound(response, request)
		}
	}))
	t.Cleanup(server.Close)
	tlsConfig := server.Client().Transport.(*http.Transport).TLSClientConfig.Clone()

	newResolver := func(t *testing.T, answers []string, keepAlive bool) (*signaturekey.HTTPKeyResolver, func() ([]string, int)) {
		t.Helper()
		var mu sync.Mutex
		var dialed []string
		lookups := 0
		resolver, err := signaturekey.NewHTTPKeyResolver(signaturekey.HTTPKeyResolverConfig{
			Client: &http.Client{Transport: &http.Transport{
				TLSClientConfig:   tlsConfig,
				DisableKeepAlives: !keepAlive,
				DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
					mu.Lock()
					dialed = append(dialed, address)
					mu.Unlock()
					return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
				},
			}},
			Clock: fixedClock(time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)),
			Admit: func(_ context.Context, endpoint string) error {
				if parsed, err := url.Parse(endpoint); err != nil || parsed.Host != "example.com" {
					return fmt.Errorf("endpoint %q not admitted", endpoint)
				}
				return nil
			},
			LookupAddresses: func(_ context.Context, host string) ([]netip.Addr, error) {
				mu.Lock()
				defer mu.Unlock()
				if host != "example.com" {
					return nil, fmt.Errorf("unexpected lookup %q", host)
				}
				answer := answers[min(lookups, len(answers)-1)]
				lookups++
				return []netip.Addr{netip.MustParseAddr(answer)}, nil
			},
			AllowDestination: func(address netip.Addr) bool { return address.IsLoopback() },
		})
		if err != nil {
			t.Fatal(err)
		}
		return resolver, func() ([]string, int) {
			mu.Lock()
			defer mu.Unlock()
			return append([]string(nil), dialed...), lookups
		}
	}

	t.Run("allowed destination is dialed at the checked address", func(t *testing.T) {
		t.Parallel()
		resolver, observe := newResolver(t, []string{"127.0.0.1"}, true)
		resolved, err := resolver.ResolveKey(context.Background(), issuer, "aauth-agent.json", "issuer-key")
		if err != nil {
			t.Fatal(err)
		}
		if !resolved.Equal(signingKey.PublicJWK()) {
			t.Fatal("resolved key does not match the issuer key")
		}
		dialed, lookups := observe()
		if len(dialed) == 0 || lookups != len(dialed) {
			t.Fatalf("dials %q after %d lookups", dialed, lookups)
		}
		for _, address := range dialed {
			if address != "127.0.0.1:443" {
				t.Fatalf("transport dialed %q, want the checked address 127.0.0.1:443", address)
			}
		}
	})

	t.Run("a rebinding answer for a later connection is checked again", func(t *testing.T) {
		t.Parallel()
		// Without keep-alive the JWKS fetch needs a second connection. Its
		// lookup answers a private address the configuration does not allow.
		resolver, observe := newResolver(t, []string{"127.0.0.1", "10.0.0.7"}, false)
		_, err := resolver.ResolveKey(context.Background(), issuer, "aauth-agent.json", "issuer-key")
		var denied *signaturekey.ResolutionError
		if !errors.As(err, &denied) || denied.Code != signaturekey.ResolutionDenied {
			t.Fatalf("ResolveKey error = %T %v, want a denied resolution", err, err)
		}
		dialed, lookups := observe()
		if len(dialed) != 1 || dialed[0] != "127.0.0.1:443" || lookups != 2 {
			t.Fatalf("dials %q after %d lookups, want only the checked metadata connection", dialed, lookups)
		}
	})
}

// The resolver checks destinations only through an *http.Transport it can
// dial through. Any other transport, or one that routes through a proxy, is
// refused unless the configuration states that it enforces egress itself.
func TestHTTPKeyResolverRequiresATransportItCanCheck(t *testing.T) {
	t.Parallel()

	base := signaturekey.HTTPKeyResolverConfig{
		Clock: fixedClock(time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)),
		Admit: func(context.Context, string) error { return nil },
	}
	roundTripper := discoveryRoundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("not used")
	})
	for _, test := range []struct {
		name    string
		client  *http.Client
		enforce bool
		wantErr bool
	}{
		{name: "default transport", client: &http.Client{}},
		{name: "plain transport", client: &http.Client{Transport: &http.Transport{}}},
		{name: "custom round tripper", client: &http.Client{Transport: roundTripper}, wantErr: true},
		{name: "custom round tripper that enforces egress", client: &http.Client{Transport: roundTripper}, enforce: true},
		{name: "proxied transport", client: &http.Client{Transport: &http.Transport{Proxy: http.ProxyFromEnvironment}}, wantErr: true},
		{name: "custom TLS dialer", client: &http.Client{Transport: &http.Transport{
			DialTLSContext: func(context.Context, string, string) (net.Conn, error) { return nil, errors.New("not used") },
		}}, wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			config := base
			config.Client = test.client
			config.TransportEnforcesEgress = test.enforce
			_, err := signaturekey.NewHTTPKeyResolver(config)
			if (err != nil) != test.wantErr {
				t.Fatalf("NewHTTPKeyResolver error = %v, want error %t", err, test.wantErr)
			}
		})
	}
}

func TestPublicDestination(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		address string
		public  bool
	}{
		{"203.0.113.10", true},
		{"8.8.8.8", true},
		{"2001:4860:4860::8888", true},
		{"64:ff9b::808:808", true},
		{"127.0.0.1", false},
		{"10.0.0.1", false},
		{"169.254.1.1", false},
		{"100.127.255.255", false},
		{"224.0.0.1", false},
		{"255.255.255.255", false},
		{"fe80::1", false},
		{"ff02::1", false},
		{"::", false},
		{"::ffff:192.168.0.1", false},
	} {
		if got := signaturekey.PublicDestination(netip.MustParseAddr(test.address)); got != test.public {
			t.Errorf("PublicDestination(%s) = %t, want %t", test.address, got, test.public)
		}
	}
}
