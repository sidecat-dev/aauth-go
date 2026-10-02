package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/agentprovider"
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

var roles = []string{"agent", "person", "orders", "inventory"}

const (
	agentOrigin      = "https://agents.test"
	personOrigin     = "https://person.test"
	ordersOrigin     = "https://orders.test"
	inventoryOrigin  = "https://inventory.test"
	agentID          = "aauth:reader@agents.test"
	relayID          = "aauth:fulfillment@orders.test"
	ordersSubject    = "person-at-orders"
	inventorySubject = "person-at-inventory"
	ordersScope      = "orders.fulfill"
	inventoryScope   = "inventory.reserve"
)

var origins = map[string]string{"agent": agentOrigin, "person": personOrigin, "orders": ordersOrigin, "inventory": inventoryOrigin}
var clock = aauth.ClockFunc(func() time.Time { return time.Now().UTC() })

type configuration struct {
	Addresses  map[string]string `json:"addresses"`
	AgentToken string            `json:"agent_token"`
	RelayToken string            `json:"relay_token"`
}

func initialize(state string, addresses map[string]string) error {
	if err := validateAddresses(addresses); err != nil {
		return err
	}
	if _, err := os.Stat(filepath.Join(state, "config.json")); err == nil {
		return errors.New("state already initialized; use a new directory")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.MkdirAll(state, 0700); err != nil {
		return err
	}
	if err := initializePKI(state); err != nil {
		return err
	}
	for _, name := range []string{"agent-provider", "agent-proof", "person", "orders-provider", "orders-resource", "orders-proof", "inventory"} {
		_, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(state, name+"-aauth.key"), private, 0600); err != nil {
			return err
		}
	}
	agentKey, err := signingKey(state, "agent-proof")
	if err != nil {
		return err
	}
	relayKey, err := signingKey(state, "orders-proof")
	if err != nil {
		return err
	}
	original, err := issueAgent(state, "agent-provider", agentOrigin, agentID, personOrigin, agentKey.PublicJWK())
	if err != nil {
		return err
	}
	// The intermediary's own PS deliberately differs: routing must use upstream ps.
	relay, err := issueAgent(state, "orders-provider", ordersOrigin, relayID, "https://relay-person.test", relayKey.PublicJWK())
	if err != nil {
		return err
	}
	encoded, err := json.Marshal(configuration{Addresses: addresses, AgentToken: original, RelayToken: relay})
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(state, "config.json"), encoded, 0600); err != nil {
		return err
	}
	thumbprint, err := relayKey.PublicJWK().Thumbprint()
	if err != nil {
		return err
	}
	return outputJSON(map[string]any{"status": "initialized", "intermediary_key": thumbprint, "agent": agentID, "intermediary": relayID})
}

func validateAddresses(addresses map[string]string) error {
	seen := make(map[string]bool)
	for _, role := range roles {
		address := addresses[role]
		host, port, err := net.SplitHostPort(address)
		if err != nil || port == "" || port == "0" || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() {
			return fmt.Errorf("%s requires a loopback IP and nonzero port", role)
		}
		if seen[address] {
			return errors.New("each role requires a distinct listener")
		}
		seen[address] = true
	}
	return nil
}

func loadConfig(state string) (configuration, error) {
	var config configuration
	encoded, err := os.ReadFile(filepath.Join(state, "config.json"))
	if err != nil {
		return config, err
	}
	if err := json.Unmarshal(encoded, &config); err != nil {
		return config, err
	}
	return config, validateAddresses(config.Addresses)
}

func signingKey(state, name string) (jose.SigningKey, error) {
	encoded, err := os.ReadFile(filepath.Join(state, name+"-aauth.key"))
	if err != nil {
		return jose.SigningKey{}, err
	}
	if len(encoded) != ed25519.PrivateKeySize {
		return jose.SigningKey{}, errors.New("invalid private key size")
	}
	return jose.NewEd25519SigningKey(name+"-key", ed25519.PrivateKey(encoded))
}

func issueAgent(state, keyName, issuer, identifier, person string, proof jose.JWK) (string, error) {
	key, err := signingKey(state, keyName)
	if err != nil {
		return "", err
	}
	provider, err := agentprovider.New(agentprovider.Config{Issuer: issuer, SigningKey: key, Clock: clock, NewID: randomID})
	if err != nil {
		return "", err
	}
	return provider.Issue(aauth.AgentTokenRequest{Agent: identifier, PersonServer: person, PublicKey: proof, Lifetime: time.Hour})
}

func randomID() string {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		panic(err)
	}
	return fmt.Sprintf("%x", value)
}

func httpClient(state string, config configuration) (*http.Client, error) {
	encoded, err := os.ReadFile(filepath.Join(state, "ca.pem"))
	if err != nil {
		return nil, err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(encoded) {
		return nil, errors.New("invalid walkthrough CA")
	}
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13},
		DialContext: func(ctx context.Context, _, address string) (net.Conn, error) {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return nil, err
			}
			for role, origin := range origins {
				parsed, _ := url.Parse(origin)
				if parsed.Hostname() == host {
					return dialer.DialContext(ctx, "tcp", config.Addresses[role])
				}
			}
			return nil, fmt.Errorf("egress host %q is outside the walkthrough", host)
		},
	}
	return &http.Client{Transport: transport, Timeout: 10 * time.Second}, nil
}

func admit(_ context.Context, endpoint string) error {
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return err
	}
	if parsed.Scheme != "https" || parsed.User != nil {
		return errors.New("discovery requires a walkthrough HTTPS origin")
	}
	for _, origin := range origins {
		if parsed.Scheme+"://"+parsed.Host == origin {
			return nil
		}
	}
	return errors.New("discovery is outside the walkthrough")
}

func resolver(client *http.Client) (signaturekey.KeyResolver, error) {
	return signaturekey.NewHTTPKeyResolver(signaturekey.HTTPKeyResolverConfig{Client: client, Clock: clock, Admit: admit})
}

func initializePKI(state string) error {
	now := time.Now().UTC()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	caTemplate := &x509.Certificate{SerialNumber: serialNumber(), Subject: pkix.Name{CommonName: "AAuth call-chain temporary CA"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	encoded, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, public, private)
	if err != nil {
		return err
	}
	ca, err := x509.ParseCertificate(encoded)
	if err != nil {
		return err
	}
	if err := writePEM(filepath.Join(state, "ca.pem"), "CERTIFICATE", encoded, 0644); err != nil {
		return err
	}
	for _, role := range roles {
		origin, _ := url.Parse(origins[role])
		leafPublic, leafPrivate, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return err
		}
		template := &x509.Certificate{SerialNumber: serialNumber(), DNSNames: []string{origin.Hostname()}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
		cert, err := x509.CreateCertificate(rand.Reader, template, ca, leafPublic, private)
		if err != nil {
			return err
		}
		key, err := x509.MarshalPKCS8PrivateKey(leafPrivate)
		if err != nil {
			return err
		}
		if err := writePEM(filepath.Join(state, role+"-tls.pem"), "CERTIFICATE", cert, 0644); err != nil {
			return err
		}
		if err := writePEM(filepath.Join(state, role+"-tls.key"), "PRIVATE KEY", key, 0600); err != nil {
			return err
		}
	}
	return nil
}

func serialNumber() *big.Int {
	number, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		panic(err)
	}
	return number
}
func writePEM(path, kind string, value []byte, mode os.FileMode) error {
	return os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: kind, Bytes: value}), mode)
}
