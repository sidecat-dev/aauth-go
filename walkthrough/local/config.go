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
	"os"
	"path/filepath"
	"time"
)

const (
	agentOrigin    = "https://agent.local"
	personOrigin   = "https://person.local"
	resourceOrigin = "https://resource.local"
	agentID        = "aauth:local@agent.local"
)

type walkthroughConfig struct {
	AgentAddress   string `json:"agent_address"`
	ServiceAddress string `json:"service_address"`
}

func configPath(stateDir string) string { return filepath.Join(stateDir, "config.json") }

func loadConfig(stateDir string) (walkthroughConfig, error) {
	var config walkthroughConfig
	encoded, err := os.ReadFile(configPath(stateDir))
	if err != nil {
		return config, fmt.Errorf("read configuration: %w", err)
	}
	if err := json.Unmarshal(encoded, &config); err != nil {
		return config, fmt.Errorf("decode configuration: %w", err)
	}
	if config.AgentAddress == "" || config.ServiceAddress == "" {
		return config, errors.New("configuration has empty process address")
	}
	return config, nil
}

func newHTTPClient(stateDir string, config walkthroughConfig) (*http.Client, error) {
	certificate, err := os.ReadFile(filepath.Join(stateDir, "ca.pem"))
	if err != nil {
		return nil, fmt.Errorf("read CA: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(certificate) {
		return nil, errors.New("CA certificate is invalid")
	}
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13},
		DialContext: func(ctx context.Context, _, address string) (net.Conn, error) {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return nil, err
			}
			switch host {
			case "agent.local":
				address = config.AgentAddress
			case "person.local", "resource.local":
				address = config.ServiceAddress
			default:
				return nil, fmt.Errorf("egress to %q is outside the walkthrough", host)
			}
			return dialer.DialContext(ctx, "tcp", address)
		},
	}
	return &http.Client{Transport: transport, Timeout: 10 * time.Second}, nil
}

func admitWalkthroughEndpoint(_ context.Context, endpoint string) error {
	request, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	switch request.URL.Hostname() {
	case "agent.local", "person.local", "resource.local":
		return nil
	default:
		return fmt.Errorf("endpoint %q is outside the walkthrough", endpoint)
	}
}
