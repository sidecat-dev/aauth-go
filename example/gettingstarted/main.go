// An Agent calls an API over TLS on this machine.
//
// Two servers run on loopback ports: an Agent Provider that issues Agent
// tokens, and an API that checks them. Each has a new self-signed
// certificate that only this program trusts.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/agent"
	"gitlab.com/sidecat-dev/aauth-go/agentprovider"
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/resource"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

func main() {
	if err := run(os.Stdout); err != nil {
		log.Fatal(err)
	}
}

func run(output io.Writer) error {
	ctx := context.Background()
	clock := aauth.SystemClock{}
	network := newLoopback()
	defer network.Close()

	// The Agent Provider signs Agent tokens and publishes the key that checks them.
	provider, err := agentprovider.New(agentprovider.Config{
		Issuer: "https://ap.example", SigningKey: newKey("ap-key-1"), Clock: clock,
		NewID: rand.Text,
	})
	if err != nil {
		return err
	}
	if err := network.Serve("ap.example", provider.Handler()); err != nil {
		return err
	}

	// The API checks every request, then runs its own policy on the verified Agent.
	apiKeys, err := trustProvider(network.Client())
	if err != nil {
		return err
	}
	hello := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		caller, _ := resource.AgentPrincipalFromContext(r.Context())
		if caller.Agent != "aauth:assistant@ap.example" {
			http.Error(w, "not admitted", http.StatusForbidden)
			return
		}
		fmt.Fprintf(w, "hello, %s", caller.Agent)
	})
	api, err := resource.NewAgentIdentity(resource.AgentIdentityConfig{
		Issuer: "https://api.example", KeyResolver: apiKeys, Clock: clock,
		Protected: hello,
	})
	if err != nil {
		return err
	}
	if err := network.Serve("api.example", api.Handler()); err != nil {
		return err
	}

	// Without a signature, the API answers 401 and says what it needs.
	response, err := network.Client().Get("https://api.example/hello")
	if err != nil {
		return err
	}
	response.Body.Close()
	fmt.Fprintln(output, "unsigned:", response.StatusCode, response.Header.Get("AAuth-Requirement"))

	// The Agent signs the request with its own key and presents its Agent token.
	agentKeys, err := trustProvider(network.Client())
	if err != nil {
		return err
	}
	assistant, err := enroll(ctx, provider, "assistant", agentKeys, network.Client())
	if err != nil {
		return err
	}
	status, body, err := get(ctx, assistant, "https://api.example/hello")
	if err != nil {
		return err
	}
	fmt.Fprintln(output, "signed:", status, body)

	// A valid signature from an Agent the API's policy does not admit gets 403.
	other, err := enroll(ctx, provider, "other", agentKeys, network.Client())
	if err != nil {
		return err
	}
	status, _, err = get(ctx, other, "https://api.example/hello")
	if err != nil {
		return err
	}
	fmt.Fprintln(output, "not admitted:", status)
	return nil
}

// trustProvider returns a key resolver that fetches the Agent Provider's
// metadata and public key over TLS, and caches them. Admit names the only
// URLs it may fetch.
func trustProvider(client *http.Client) (*signaturekey.HTTPKeyResolver, error) {
	return signaturekey.NewHTTPKeyResolver(signaturekey.HTTPKeyResolverConfig{
		Client: client, Clock: aauth.SystemClock{},
		Admit: func(_ context.Context, endpoint string) error {
			if !strings.HasPrefix(endpoint, "https://ap.example/") {
				return fmt.Errorf("not a trusted Agent Provider: %s", endpoint)
			}
			return nil
		},
		// This client reaches only this program's loopback servers, so it
		// applies the destination checks itself. On a real network, leave this
		// unset: the resolver then refuses private and loopback addresses.
		TransportEnforcesEgress: true,
	})
}

// enroll makes the Agent's own key; the provider issues a token that names it.
func enroll(ctx context.Context, provider *agentprovider.Server, name string,
	keys signaturekey.KeyResolver, client *http.Client,
) (*agent.Client, error) {
	key := newKey(name + "-key-1")
	identifier := "aauth:" + name + "@ap.example"
	token, err := provider.Issue(aauth.AgentTokenRequest{
		Agent: identifier, PublicKey: key.PublicJWK(), Lifetime: 10 * time.Minute,
	})
	if err != nil {
		return nil, err
	}
	return agent.New(ctx, agent.Config{
		Identifier: identifier, SigningKey: key, AgentToken: token,
		KeyResolver: keys, HTTPClient: client, Clock: aauth.SystemClock{},
	})
}

// get signs one GET with the Agent token and returns the status and body.
func get(ctx context.Context, caller *agent.Client, url string) (int, string, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, "", err
	}
	response, err := caller.CallAsAgent(ctx, request)
	if err != nil {
		return 0, "", err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	return response.StatusCode, string(body), err
}

func newKey(id string) jose.SigningKey {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	key, err := jose.NewEd25519SigningKey(id, private)
	if err != nil {
		log.Fatal(err)
	}
	return key
}

// loopback runs HTTPS servers on loopback ports under made-up host names.
// Its client reaches those servers and nothing else, and trusts only their
// certificates.
type loopback struct {
	roots   *x509.CertPool
	routes  map[string]string
	servers []*http.Server
	client  *http.Client
}

func newLoopback() *loopback {
	network := &loopback{roots: x509.NewCertPool(), routes: map[string]string{}}
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	network.client = &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: network.roots},
		DialContext: func(ctx context.Context, _, address string) (net.Conn, error) {
			target, ok := network.routes[address]
			if !ok {
				return nil, fmt.Errorf("no loopback server for %s", address)
			}
			return dialer.DialContext(ctx, "tcp", target)
		},
	}}
	return network
}

// Serve starts handler at https://host on a new loopback port.
func (network *loopback) Serve(host string, handler http.Handler) error {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: host},
		DNSNames: []string{host}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, public, private)
	if err != nil {
		return err
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		return err
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	server := &http.Server{Handler: handler, TLSConfig: &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: private}},
	}}
	go server.ServeTLS(listener, "", "")
	network.roots.AddCert(certificate)
	network.routes[host+":443"] = listener.Addr().String()
	network.servers = append(network.servers, server)
	return nil
}

// Client returns the HTTPS client that connects only to this network's servers.
func (network *loopback) Client() *http.Client {
	return network.client
}

func (network *loopback) Close() {
	for _, server := range network.servers {
		server.Close()
	}
}
