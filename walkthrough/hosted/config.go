package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"time"
)

type hostConfig struct {
	Listen         string `json:"listen"`
	Origin         string `json:"origin"`
	EnrollmentCode string `json:"enrollment_code"`
	ControlToken   string `json:"control_token"`
}

type bootstrapDocument struct {
	Origin         string `json:"origin"`
	CAPEM          string `json:"ca_pem"`
	EnrollmentCode string `json:"enrollment_code"`
	ControlToken   string `json:"control_token"`
}

type agentConfig struct {
	ServiceOrigin  string `json:"service_origin"`
	ServiceAddress string `json:"service_address,omitempty"`
	EnrollmentCode string `json:"enrollment_code"`
	ControlToken   string `json:"control_token"`
}

func hostConfigPath(stateDir string) string  { return filepath.Join(stateDir, "host-config.json") }
func agentConfigPath(stateDir string) string { return filepath.Join(stateDir, "agent-config.json") }

func loadHostConfig(stateDir string) (hostConfig, error) {
	var config hostConfig
	if err := readJSON(hostConfigPath(stateDir), &config); err != nil {
		return config, fmt.Errorf("read host configuration: %w", err)
	}
	if config.Listen == "" || config.Origin == "" || config.EnrollmentCode == "" || config.ControlToken == "" {
		return config, errors.New("host configuration is incomplete")
	}
	return config, nil
}

func loadAgentConfig(stateDir string) (agentConfig, error) {
	var config agentConfig
	if err := readJSON(agentConfigPath(stateDir), &config); err != nil {
		return config, fmt.Errorf("read Agent configuration: %w", err)
	}
	if config.ServiceOrigin == "" || config.EnrollmentCode == "" || config.ControlToken == "" {
		return config, errors.New("Agent configuration is incomplete")
	}
	return config, nil
}

func newHostedHTTPClient(stateDir string, config agentConfig) (*http.Client, error) {
	certificate, err := os.ReadFile(filepath.Join(stateDir, "ca.pem"))
	if err != nil {
		return nil, fmt.Errorf("read hosted CA: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(certificate) {
		return nil, errors.New("hosted CA certificate is invalid")
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13}}
	if config.ServiceAddress != "" {
		origin, err := url.Parse(config.ServiceOrigin)
		if err != nil {
			return nil, err
		}
		dialer := &net.Dialer{Timeout: 5 * time.Second}
		allowed := map[string]bool{
			origin.Hostname(): true,
			hostedRoleHost(origin.Hostname(), "person"):   true,
			hostedRoleHost(origin.Hostname(), "resource"): true,
		}
		transport.DialContext = func(ctx context.Context, _, address string) (net.Conn, error) {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return nil, err
			}
			if !allowed[host] {
				return nil, fmt.Errorf("egress to %q is outside the hosted walkthrough", host)
			}
			return dialer.DialContext(ctx, "tcp", config.ServiceAddress)
		}
	}
	return &http.Client{Transport: transport, Timeout: 10 * time.Second}, nil
}

// transportEnforcesEgress reports whether newHostedHTTPClient's transport
// decides every connection itself. With a service address it connects only to
// that address and refuses other hosts, so a key resolver must use it unchanged
// rather than resolve the hosted names through DNS.
func (config agentConfig) transportEnforcesEgress() bool { return config.ServiceAddress != "" }

func hostedPersonOrigin(base string) string   { return hostedRoleOrigin(base, "person") }
func hostedResourceOrigin(base string) string { return hostedRoleOrigin(base, "resource") }

func hostedRoleOrigin(base, role string) string {
	parsed, err := url.Parse(base)
	if err != nil {
		return ""
	}
	host := hostedRoleHost(parsed.Hostname(), role)
	if parsed.Port() != "" {
		host = net.JoinHostPort(host, parsed.Port())
	}
	return parsed.Scheme + "://" + host
}

func hostedRoleHost(host, role string) string {
	if net.ParseIP(host) != nil {
		return host
	}
	return role + "." + host
}

func admitHostedOrigin(origin string) func(context.Context, string) error {
	return func(_ context.Context, endpoint string) error {
		parsed, err := url.Parse(endpoint)
		if err != nil {
			return err
		}
		if parsed.Scheme+"://"+parsed.Host != origin {
			return fmt.Errorf("endpoint %q is outside the hosted walkthrough", endpoint)
		}
		return nil
	}
}

func writeJSONFile(path string, mode os.FileMode, value any) error {
	encoded, err := json.Marshal(value)
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	temporary := path + ".tmp"
	file, err := os.OpenFile(temporary, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
	if err != nil {
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
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(temporary, path)
}

func readJSON(path string, value any) error {
	encoded, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(encoded, value); err != nil {
		return err
	}
	return nil
}
