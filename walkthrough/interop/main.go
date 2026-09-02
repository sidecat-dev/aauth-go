package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

const interopMaxResponseBytes = 1 << 20

type initializedInterop struct {
	Issuer    string `json:"issuer"`
	Agent     string `json:"agent"`
	PublicDir string `json:"public_dir"`
}

type interopPrivateFile struct {
	Issuer             string `json:"issuer"`
	Agent              string `json:"agent"`
	PersonServer       string `json:"person_server,omitempty"`
	ProviderPrivateKey string `json:"provider_private_key"`
	AgentPrivateKey    string `json:"agent_private_key"`
	AgentToken         string `json:"agent_token"`
}

type interopPrivate struct {
	Issuer       string
	Agent        string
	PersonServer string
	ProviderKey  jose.SigningKey
	AgentKey     jose.SigningKey
	AgentPrivate ed25519.PrivateKey
	AgentToken   string
}

type interopAgentConfig struct {
	Agent        string            `json:"agent"`
	AgentToken   string            `json:"agent_token"`
	PersonServer string            `json:"person_server"`
	SigningKey   map[string]string `json:"signing_key"`
}

type interopCallResult struct {
	Status int    `json:"status"`
	Issuer string `json:"issuer"`
	Agent  string `json:"agent"`
	Target string `json:"target"`
}

func main() {
	if err := runInteropCLI(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "aauth-interop:", err)
		os.Exit(1)
	}
}

func runInteropCLI(arguments []string, output io.Writer) error {
	if len(arguments) == 0 {
		return errors.New("usage: aauth-interop init --state DIR --issuer URL [--person-server URL] | agent-config --state DIR | serve --state DIR --listen ADDRESS --origin URL --agent-issuer URL --agent ID | call --state DIR --target URL")
	}
	switch arguments[0] {
	case "init":
		flags := flag.NewFlagSet("init", flag.ContinueOnError)
		flags.SetOutput(io.Discard)
		stateDir := flags.String("state", "", "state directory")
		issuer := flags.String("issuer", "", "public Agent Provider issuer")
		personServer := flags.String("person-server", "", "Person Server bound into the Agent token")
		if err := flags.Parse(arguments[1:]); err != nil || flags.NArg() != 0 || *stateDir == "" || *issuer == "" {
			return errors.New("init requires --state DIR --issuer URL")
		}
		initialized, err := initializeInteropForAuthorization(*stateDir, *issuer, *personServer, time.Now())
		if err != nil {
			return err
		}
		return json.NewEncoder(output).Encode(initialized)
	case "agent-config":
		flags := flag.NewFlagSet("agent-config", flag.ContinueOnError)
		flags.SetOutput(io.Discard)
		stateDir := flags.String("state", "", "state directory")
		if err := flags.Parse(arguments[1:]); err != nil || flags.NArg() != 0 || *stateDir == "" {
			return errors.New("agent-config requires --state DIR")
		}
		config, err := loadInteropAgentConfig(*stateDir)
		if err != nil {
			return err
		}
		return json.NewEncoder(output).Encode(config)
	case "serve":
		flags := flag.NewFlagSet("serve", flag.ContinueOnError)
		flags.SetOutput(io.Discard)
		stateDir := flags.String("state", "", "service state directory")
		listen := flags.String("listen", "", "loopback address behind the TLS proxy")
		origin := flags.String("origin", "", "public Person Server and Resource origin")
		agentIssuer := flags.String("agent-issuer", "", "admitted independent Agent Provider issuer")
		agentID := flags.String("agent", "", "admitted independent Agent identifier")
		if err := flags.Parse(arguments[1:]); err != nil || flags.NArg() != 0 ||
			*stateDir == "" || *listen == "" || *origin == "" || *agentIssuer == "" || *agentID == "" {
			return errors.New("serve requires --state DIR --listen ADDRESS --origin URL --agent-issuer URL --agent ID")
		}
		listener, err := net.Listen("tcp", *listen)
		if err != nil {
			return err
		}
		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer cancel()
		return serveInteropAuthorization(ctx, listener, interopAuthorizationRunConfig{
			Origin: *origin, AgentIssuer: *agentIssuer, Agent: *agentID, StateDir: *stateDir,
		})
	case "call":
		flags := flag.NewFlagSet("call", flag.ContinueOnError)
		flags.SetOutput(io.Discard)
		stateDir := flags.String("state", "", "state directory")
		target := flags.String("target", "", "independent AAuth Resource URL")
		if err := flags.Parse(arguments[1:]); err != nil || flags.NArg() != 0 || *stateDir == "" || *target == "" {
			return errors.New("call requires --state DIR --target URL")
		}
		result, err := callInteropTarget(context.Background(), *stateDir, *target, http.DefaultClient, aauth.ClockFunc(time.Now))
		if err != nil {
			return err
		}
		return json.NewEncoder(output).Encode(result)
	default:
		return fmt.Errorf("unknown command %q", arguments[0])
	}
}

func initializeInterop(stateDir, issuer string, now time.Time) (initializedInterop, error) {
	return initializeInteropForAuthorization(stateDir, issuer, "", now)
}

func initializeInteropForAuthorization(stateDir, issuer, personServer string, now time.Time) (initializedInterop, error) {
	issuer = strings.TrimSuffix(issuer, "/")
	parsed, err := parseHTTPSURL(issuer)
	if err != nil {
		return initializedInterop{}, fmt.Errorf("issuer: %w", err)
	}
	if err := aauth.ValidateServerIdentifier(issuer); err != nil {
		return initializedInterop{}, fmt.Errorf("issuer: %w", err)
	}
	if personServer != "" {
		personServer = strings.TrimSuffix(personServer, "/")
		if err := aauth.ValidateServerIdentifier(personServer); err != nil {
			return initializedInterop{}, fmt.Errorf("Person Server: %w", err)
		}
	}
	if _, err := os.Stat(filepath.Join(stateDir, "private.json")); err == nil {
		return initializedInterop{}, errors.New("state is already initialized")
	} else if !errors.Is(err, os.ErrNotExist) {
		return initializedInterop{}, err
	}
	if err := os.MkdirAll(filepath.Join(stateDir, "public", ".well-known"), 0o700); err != nil {
		return initializedInterop{}, err
	}

	_, providerPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return initializedInterop{}, err
	}
	providerKey, err := jose.NewEd25519SigningKey("provider-key-1", providerPrivate)
	if err != nil {
		return initializedInterop{}, err
	}
	_, agentPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return initializedInterop{}, err
	}
	agentKey, err := jose.NewEd25519SigningKey("agent-key-1", agentPrivate)
	if err != nil {
		return initializedInterop{}, err
	}
	agentID := "aauth:go-interop@" + parsed.Hostname()
	if err := aauth.ValidateAgentIdentifier(agentID); err != nil {
		return initializedInterop{}, err
	}
	jti, err := randomInteropID()
	if err != nil {
		return initializedInterop{}, err
	}
	now = now.UTC().Truncate(time.Second)
	agentToken, err := aauth.MintAgentToken(issuer, providerKey, aauth.AgentTokenRequest{
		Agent: agentID, PersonServer: personServer,
		PublicKey: agentKey.PublicJWK(), Lifetime: 10 * time.Minute,
	}, now, jti)
	if err != nil {
		return initializedInterop{}, err
	}

	private := interopPrivateFile{
		Issuer: issuer, Agent: agentID, PersonServer: personServer,
		ProviderPrivateKey: base64.RawURLEncoding.EncodeToString(providerPrivate),
		AgentPrivateKey:    base64.RawURLEncoding.EncodeToString(agentPrivate),
		AgentToken:         agentToken,
	}
	if err := writeInteropJSON(filepath.Join(stateDir, "private.json"), 0o600, private); err != nil {
		return initializedInterop{}, err
	}
	metadata := struct {
		Issuer  string `json:"issuer"`
		JWKSURI string `json:"jwks_uri"`
	}{Issuer: issuer, JWKSURI: issuer + "/jwks.json"}
	if err := writeInteropJSON(filepath.Join(stateDir, "public", ".well-known", "aauth-agent.json"), 0o644, metadata); err != nil {
		return initializedInterop{}, err
	}
	keySet := struct {
		Keys []jose.JWK `json:"keys"`
	}{Keys: []jose.JWK{providerKey.PublicJWK()}}
	if err := writeInteropJSON(filepath.Join(stateDir, "public", "jwks.json"), 0o644, keySet); err != nil {
		return initializedInterop{}, err
	}
	return initializedInterop{Issuer: issuer, Agent: agentID, PublicDir: filepath.Join(stateDir, "public")}, nil
}

func loadInteropPrivate(stateDir string) (interopPrivate, error) {
	encoded, err := os.ReadFile(filepath.Join(stateDir, "private.json"))
	if err != nil {
		return interopPrivate{}, err
	}
	var retained interopPrivateFile
	if err := json.Unmarshal(encoded, &retained); err != nil {
		return interopPrivate{}, err
	}
	providerPrivate, err := decodeInteropPrivateKey(retained.ProviderPrivateKey)
	if err != nil {
		return interopPrivate{}, fmt.Errorf("provider key: %w", err)
	}
	agentPrivate, err := decodeInteropPrivateKey(retained.AgentPrivateKey)
	if err != nil {
		return interopPrivate{}, fmt.Errorf("Agent key: %w", err)
	}
	providerKey, err := jose.NewEd25519SigningKey("provider-key-1", providerPrivate)
	if err != nil {
		return interopPrivate{}, err
	}
	agentKey, err := jose.NewEd25519SigningKey("agent-key-1", agentPrivate)
	if err != nil {
		return interopPrivate{}, err
	}
	if retained.Issuer == "" || retained.Agent == "" || retained.AgentToken == "" {
		return interopPrivate{}, errors.New("private state is incomplete")
	}
	return interopPrivate{
		Issuer: retained.Issuer, Agent: retained.Agent, PersonServer: retained.PersonServer,
		ProviderKey: providerKey, AgentKey: agentKey, AgentPrivate: agentPrivate,
		AgentToken: retained.AgentToken,
	}, nil
}

func loadInteropAgentConfig(stateDir string) (interopAgentConfig, error) {
	private, err := loadInteropPrivate(stateDir)
	if err != nil {
		return interopAgentConfig{}, err
	}
	if private.PersonServer == "" {
		return interopAgentConfig{}, errors.New("Agent token is not bound to a Person Server")
	}
	privateKey := private.AgentPrivate
	publicKey := privateKey.Public().(ed25519.PublicKey)
	return interopAgentConfig{
		Agent: private.Agent, AgentToken: private.AgentToken, PersonServer: private.PersonServer,
		SigningKey: map[string]string{
			"alg": "Ed25519", "crv": "Ed25519", "kid": private.AgentKey.ID(), "kty": "OKP",
			"d": base64.RawURLEncoding.EncodeToString(privateKey.Seed()),
			"x": base64.RawURLEncoding.EncodeToString(publicKey),
		},
	}, nil
}

func callInteropTarget(ctx context.Context, stateDir, target string, client *http.Client, clock aauth.Clock) (interopCallResult, error) {
	if _, err := parseHTTPSURL(target); err != nil {
		return interopCallResult{}, fmt.Errorf("target: %w", err)
	}
	if client == nil || clock == nil {
		return interopCallResult{}, errors.New("HTTP client and clock are required")
	}
	private, err := loadInteropPrivate(stateDir)
	if err != nil {
		return interopCallResult{}, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return interopCallResult{}, err
	}
	if err := signaturekey.SignJWTRequest(request, private.AgentKey, private.AgentToken, clock); err != nil {
		return interopCallResult{}, err
	}
	boundedClient := *client
	boundedClient.CheckRedirect = func(*http.Request, []*http.Request) error {
		return errors.New("target redirect is not permitted")
	}
	response, err := boundedClient.Do(request)
	if err != nil {
		return interopCallResult{}, err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, interopMaxResponseBytes+1))
	if err != nil {
		return interopCallResult{}, err
	}
	if len(body) > interopMaxResponseBytes {
		return interopCallResult{}, errors.New("target response exceeds 1 MiB")
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return interopCallResult{}, fmt.Errorf("target returned %s: %s", response.Status, strings.TrimSpace(string(body)))
	}
	var identity struct {
		Issuer string `json:"iss"`
		Agent  string `json:"sub"`
	}
	if err := json.Unmarshal(body, &identity); err != nil {
		return interopCallResult{}, fmt.Errorf("decode target identity: %w", err)
	}
	if identity.Issuer != private.Issuer || identity.Agent != private.Agent {
		return interopCallResult{}, fmt.Errorf("target returned identity (%q, %q), want (%q, %q)", identity.Issuer, identity.Agent, private.Issuer, private.Agent)
	}
	return interopCallResult{Status: response.StatusCode, Issuer: identity.Issuer, Agent: identity.Agent, Target: target}, nil
}

func parseHTTPSURL(raw string) (*url.URL, error) {
	parsed, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	if parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
		return nil, errors.New("must be an absolute HTTPS URL without credentials or fragment")
	}
	return parsed, nil
}

func randomInteropID() (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}

func decodeInteropPrivateKey(encoded string) (ed25519.PrivateKey, error) {
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	if err != nil {
		return nil, err
	}
	if len(decoded) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("private key has %d bytes, want %d", len(decoded), ed25519.PrivateKeySize)
	}
	return ed25519.PrivateKey(decoded), nil
}

func writeInteropJSON(path string, mode os.FileMode, value any) error {
	encoded, err := json.Marshal(value)
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	if err := file.Chmod(mode); err != nil {
		_ = file.Close()
		return err
	}
	if _, err := file.Write(encoded); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}
