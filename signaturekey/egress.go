package signaturekey

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"time"
)

var (
	sharedAddressSpace = netip.MustParsePrefix("100.64.0.0/10")
	nat64WellKnown     = netip.MustParsePrefix("64:ff9b::/96")
)

// PublicDestination reports whether a discovery connection may reach address
// without deployment configuration: a global unicast address that is not
// private (RFC 1918, RFC 4193), loopback, link-local, unspecified, multicast,
// or in the shared address space (RFC 6598). An IPv4-mapped or well-known
// NAT64 IPv6 address is judged by the IPv4 address it carries.
func PublicDestination(address netip.Addr) bool {
	address = address.Unmap()
	if address.Is6() && nat64WellKnown.Contains(address) {
		embedded := address.As16()
		address = netip.AddrFrom4([4]byte(embedded[12:]))
	}
	return address.IsValid() && address.IsGlobalUnicast() && !address.IsPrivate() &&
		!sharedAddressSpace.Contains(address)
}

// egressDialer connects discovery requests only to destinations that pass
// egress admission. It resolves the host once, refuses the whole destination
// when any resolved address is neither public nor allowed, and then dials the
// exact addresses it checked, so a second DNS answer cannot move the
// connection (DNS rebinding).
type egressDialer struct {
	lookup func(context.Context, string) ([]netip.Addr, error)
	allow  func(netip.Addr) bool
	dial   func(context.Context, string, string) (net.Conn, error)
}

func (dialer egressDialer) dialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	var addresses []netip.Addr
	if literal, err := netip.ParseAddr(host); err == nil {
		addresses = []netip.Addr{literal}
	} else {
		addresses, err = dialer.lookup(ctx, host)
		if err != nil {
			return nil, err
		}
		if len(addresses) == 0 {
			return nil, fmt.Errorf("aauth: discovery host %q has no address", host)
		}
	}
	for _, candidate := range addresses {
		if !PublicDestination(candidate) && (dialer.allow == nil || !dialer.allow(candidate)) {
			return nil, resolutionError(
				ResolutionDenied,
				fmt.Errorf("aauth: discovery destination %s for %q is not a public address", candidate, host),
			)
		}
	}
	var failures []error
	for _, candidate := range addresses {
		conn, err := dialer.dial(ctx, network, net.JoinHostPort(candidate.Unmap().String(), port))
		if err == nil {
			return conn, nil
		}
		failures = append(failures, err)
	}
	return nil, errors.Join(failures...)
}

func lookupSystemAddresses(ctx context.Context, host string) ([]netip.Addr, error) {
	return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
}

// EgressClientConfig selects the destination policy of NewEgressClient.
type EgressClientConfig struct {
	// Client is copied; nil starts from a direct default client. Its
	// transport, if any, must be an *http.Transport without a proxy or a
	// custom dialer other than DialContext.
	Client *http.Client
	// AllowDestination admits a non-public destination address that
	// deployment configuration explicitly allows. Nil admits none.
	AllowDestination func(netip.Addr) bool
	// LookupAddresses resolves a host. Nil uses the system resolver.
	LookupAddresses func(context.Context, string) ([]netip.Addr, error)
	// Timeout bounds each request. Zero selects 10 seconds.
	Timeout time.Duration
}

// NewEgressClient returns an HTTP client for a server's own outbound calls,
// such as revocations, supervision requests and event deliveries to
// endpoints that metadata named. It applies HTTPKeyResolver's connection
// checks: it resolves each host once, refuses the destination when any
// address is not public and AllowDestination does not admit it, and connects
// to the exact address it checked. It never follows a redirect, sends no
// cookies, and gives up after Timeout. Pair it with AdmitHTTPS, or with an
// admitter that names the endpoints you trust.
func NewEgressClient(config EgressClientConfig) (*http.Client, error) {
	if config.Timeout < 0 {
		return nil, errors.New("aauth: egress client timeout must not be negative")
	}
	base := config.Client
	if base == nil {
		base = &http.Client{}
	}
	client, err := discoveryHTTPClient(HTTPKeyResolverConfig{
		Client: base, AllowDestination: config.AllowDestination, LookupAddresses: config.LookupAddresses,
	})
	if err != nil {
		return nil, err
	}
	client.Jar = nil
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	client.Timeout = config.Timeout
	if client.Timeout == 0 {
		client.Timeout = defaultDiscoveryTimeout
	}
	return client, nil
}

// discoveryHTTPClient returns the client discovery fetches through. Unless the
// configuration states that the transport enforces egress itself, discovery
// connects only through an egressDialer installed in a clone of the caller's
// *http.Transport, or of a direct default transport.
func discoveryHTTPClient(config HTTPKeyResolverConfig) (*http.Client, error) {
	client := *config.Client
	if config.TransportEnforcesEgress {
		return &client, nil
	}
	var transport *http.Transport
	switch base := client.Transport.(type) {
	case nil:
		transport = http.DefaultTransport.(*http.Transport).Clone()
		// Discovery connects directly; a proxy would hide the destination.
		transport.Proxy = nil
	case *http.Transport:
		if base.Proxy != nil || base.DialTLSContext != nil || base.DialTLS != nil || base.Dial != nil {
			return nil, errors.New("aauth: HTTP key resolver cannot check discovery destinations through a proxy or a custom dialer other than DialContext; set TransportEnforcesEgress only if the transport applies the egress controls itself")
		}
		transport = base.Clone()
	default:
		return nil, errors.New("aauth: HTTP key resolver checks discovery destinations only through an *http.Transport; set TransportEnforcesEgress only if the transport applies the egress controls itself")
	}
	dial := transport.DialContext
	if dial == nil {
		dial = (&net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}).DialContext
	}
	lookup := config.LookupAddresses
	if lookup == nil {
		lookup = lookupSystemAddresses
	}
	transport.DialContext = egressDialer{lookup: lookup, allow: config.AllowDestination, dial: dial}.dialContext
	client.Transport = transport
	return &client, nil
}
