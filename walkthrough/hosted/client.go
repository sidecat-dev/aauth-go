package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	clientagent "gitlab.com/sidecat-dev/aauth-go/agent"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

type connectionRequestState struct {
	EnrollmentEvidence json.RawMessage `json:"enrollment_evidence"`
	RefreshEvidence    json.RawMessage `json:"refresh_evidence"`
	DelegationJTI      string          `json:"delegation_jti"`
	IssuedAt           time.Time       `json:"issued_at"`
	ExpiresAt          time.Time       `json:"expires_at"`
}

type retainedConnection struct {
	Status      string `json:"status"`
	Agent       string `json:"agent"`
	AgentToken  string `json:"agent_token"`
	TokenSHA256 string `json:"token_sha256"`
}

type connectionOutput struct {
	Status      string `json:"status"`
	Agent       string `json:"agent"`
	TokenSHA256 string `json:"token_sha256"`
}

type hostedRemoteError struct {
	status int
	body   string
}

func (err *hostedRemoteError) Error() string {
	return fmt.Sprintf("host returned %d: %s", err.status, strings.TrimSpace(err.body))
}

func agentCommand(name string, arguments []string) error {
	stateDir, err := hostedStateFlag(name, arguments)
	if err != nil {
		return err
	}
	config, err := loadAgentConfig(stateDir)
	if err != nil {
		return err
	}
	client, err := newHostedHTTPClient(stateDir, config)
	if err != nil {
		return err
	}
	switch name {
	case "health":
		response, err := client.Get(config.ServiceOrigin + "/health")
		if err != nil {
			return err
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusOK {
			return readHostedRemoteError(response)
		}
		return nil
	case "host-status":
		request, err := http.NewRequest(http.MethodGet, config.ServiceOrigin+"/control/status", nil)
		if err != nil {
			return err
		}
		request.Header.Set("Authorization", "Bearer "+config.ControlToken)
		response, err := client.Do(request)
		if err != nil {
			return err
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusOK {
			return readHostedRemoteError(response)
		}
		_, err = io.Copy(os.Stdout, response.Body)
		return err
	case "connect":
		return connectAgent(stateDir, config, client)
	default:
		return errors.New("unknown Agent command")
	}
}

func accountCommand(name string, arguments []string) error {
	switch name {
	case "login":
		flags := flag.NewFlagSet(name, flag.ContinueOnError)
		flags.SetOutput(os.Stderr)
		stateDir := flags.String("state", "", "Agent state directory")
		email := flags.String("email", "", "account email")
		passwordFile := flags.String("password-file", "", "account password file")
		if err := flags.Parse(arguments); err != nil {
			return err
		}
		if *stateDir == "" || *email == "" || *passwordFile == "" || flags.NArg() != 0 {
			return errors.New("login requires --state DIR --email EMAIL --password-file FILE")
		}
		password, err := readSecretFile(*passwordFile)
		if err != nil {
			return err
		}
		config, client, err := loadHostedAgentHTTP(*stateDir)
		if err != nil {
			return err
		}
		var output struct {
			SessionToken string `json:"session_token"`
		}
		if err := hostedJSONCall(client, http.MethodPost, config.ServiceOrigin+"/account/login", "", map[string]string{"email": *email, "password": password}, &output); err != nil {
			return err
		}
		if output.SessionToken == "" {
			return errors.New("host returned an empty session token")
		}
		if err := os.WriteFile(filepath.Join(*stateDir, "user-session.token"), []byte(output.SessionToken+"\n"), 0o600); err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(map[string]string{"status": "authenticated"})
	case "link":
		flags := flag.NewFlagSet(name, flag.ContinueOnError)
		flags.SetOutput(os.Stderr)
		stateDir := flags.String("state", "", "Agent state directory")
		account := flags.String("account", "", "connector account identifier")
		if err := flags.Parse(arguments); err != nil {
			return err
		}
		if *stateDir == "" || *account == "" || flags.NArg() != 0 {
			return errors.New("link requires --state DIR --account ID")
		}
		token, err := readSecretFile(filepath.Join(*stateDir, "user-session.token"))
		if errors.Is(err, os.ErrNotExist) {
			return errLoginRequired
		}
		if err != nil {
			return err
		}
		config, client, err := loadHostedAgentHTTP(*stateDir)
		if err != nil {
			return err
		}
		var output map[string]string
		return hostedJSONCall(client, http.MethodPost, config.ServiceOrigin+"/account/link", token, map[string]string{"account": *account}, &output)
	case "account-status":
		stateDir, err := hostedStateFlag(name, arguments)
		if err != nil {
			return err
		}
		token, err := readSecretFile(filepath.Join(stateDir, "user-session.token"))
		if errors.Is(err, os.ErrNotExist) {
			return errLoginRequired
		}
		if err != nil {
			return err
		}
		config, client, err := loadHostedAgentHTTP(stateDir)
		if err != nil {
			return err
		}
		request, err := http.NewRequest(http.MethodGet, config.ServiceOrigin+"/account/status", nil)
		if err != nil {
			return err
		}
		request.Header.Set("Authorization", "Bearer "+token)
		response, err := client.Do(request)
		if err != nil {
			return err
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusOK {
			return readHostedRemoteError(response)
		}
		_, err = io.Copy(os.Stdout, response.Body)
		return err
	case "approve":
		stateDir, err := hostedStateFlag(name, arguments)
		if err != nil {
			return err
		}
		token, err := readSecretFile(filepath.Join(stateDir, "user-session.token"))
		if errors.Is(err, os.ErrNotExist) {
			return errLoginRequired
		}
		if err != nil {
			return err
		}
		config, client, err := loadHostedAgentHTTP(stateDir)
		if err != nil {
			return err
		}
		var output map[string]string
		if err := hostedJSONCall(client, http.MethodPost, config.ServiceOrigin+"/account/mission-approval", token, map[string]string{}, &output); err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(output)
	case "revoke":
		stateDir, err := hostedStateFlag(name, arguments)
		if err != nil {
			return err
		}
		token, err := readSecretFile(filepath.Join(stateDir, "user-session.token"))
		if errors.Is(err, os.ErrNotExist) {
			return errLoginRequired
		}
		if err != nil {
			return err
		}
		config, client, err := loadHostedAgentHTTP(stateDir)
		if err != nil {
			return err
		}
		var output map[string]string
		if err := hostedJSONCall(client, http.MethodPost, config.ServiceOrigin+"/account/revoke-agent", token, map[string]string{}, &output); err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(output)
	default:
		return errors.New("unknown account command")
	}
}

func loadHostedAgentHTTP(stateDir string) (agentConfig, *http.Client, error) {
	config, err := loadAgentConfig(stateDir)
	if err != nil {
		return config, nil, err
	}
	client, err := newHostedHTTPClient(stateDir, config)
	return config, client, err
}

func readSecretFile(path string) (string, error) {
	encoded, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	value := strings.TrimSpace(string(encoded))
	if value == "" {
		return "", errors.New("secret file is empty")
	}
	return value, nil
}

func hostedJSONCall(client *http.Client, method, endpoint, token string, input any, output any) error {
	body, err := json.Marshal(input)
	if err != nil {
		return err
	}
	request, err := http.NewRequest(method, endpoint, strings.NewReader(string(body)))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return readHostedRemoteError(response)
	}
	if output == nil {
		return nil
	}
	return json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(output)
}

func connectAgent(stateDir string, config agentConfig, httpClient *http.Client) error {
	if retained, err := loadRetainedConnection(stateDir); err == nil {
		return writeConnectionOutput(retained)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	request, err := loadOrCreateConnectionRequest(stateDir, config)
	if err != nil {
		return err
	}
	durableKey, err := loadHostedSigningKey(stateDir, "durable")
	if err != nil {
		return err
	}
	agentKey, err := loadHostedSigningKey(stateDir, "agent")
	if err != nil {
		return err
	}
	clock := aauth.ClockFunc(func() time.Time { return time.Now().UTC() })
	resolver, err := signaturekey.NewHTTPKeyResolver(signaturekey.HTTPKeyResolverConfig{
		Client: httpClient, Clock: clock, Admit: admitHostedOrigin(config.ServiceOrigin),
	})
	if err != nil {
		return err
	}
	bootstrap, err := clientagent.NewBootstrapClient(clientagent.BootstrapConfig{
		AgentProvider: config.ServiceOrigin, EnrollmentEndpoint: config.ServiceOrigin + "/internal/enrollment",
		RefreshEndpoint: config.ServiceOrigin + "/internal/refresh", DurableKey: durableKey,
		KeyResolver: resolver, HTTPClient: httpClient, Clock: clock, MaxSignedBodyBytes: 1 << 20,
	})
	if err != nil {
		return err
	}
	enrollment, err := bootstrap.Enroll(context.Background(), request.EnrollmentEvidence)
	if err != nil {
		return err
	}
	refreshed, err := bootstrap.Refresh(context.Background(), clientagent.RefreshAgentTokenInput{
		Agent: enrollment.Agent, PersonServer: hostedPersonOrigin(config.ServiceOrigin),
		Evidence: request.RefreshEvidence, SigningKey: agentKey,
		DelegationJTI: request.DelegationJTI, DelegationIssuedAt: request.IssuedAt,
		DelegationExpiresAt: request.ExpiresAt,
	})
	if err != nil {
		return err
	}
	digest := sha256.Sum256([]byte(refreshed.AgentToken))
	retained := retainedConnection{
		Status: "connected", Agent: enrollment.Agent, AgentToken: refreshed.AgentToken,
		TokenSHA256: hex.EncodeToString(digest[:]),
	}
	if err := writeJSONFile(filepath.Join(stateDir, "connection-result.json"), 0o600, retained); err != nil {
		return err
	}
	return writeConnectionOutput(retained)
}

func loadOrCreateConnectionRequest(stateDir string, config agentConfig) (connectionRequestState, error) {
	path := filepath.Join(stateDir, "connection-request.json")
	var retained connectionRequestState
	if err := readJSON(path, &retained); err == nil {
		return retained, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return retained, err
	}
	jti, err := randomSecret()
	if err != nil {
		return retained, err
	}
	now := time.Now().UTC().Truncate(time.Second)
	enrollmentEvidence, err := json.Marshal(map[string]string{"account": "person-1", "enrollment_code": config.EnrollmentCode})
	if err != nil {
		return retained, err
	}
	refreshEvidence := json.RawMessage(`{"account":"person-1"}`)
	retained = connectionRequestState{
		EnrollmentEvidence: enrollmentEvidence, RefreshEvidence: refreshEvidence,
		DelegationJTI: jti, IssuedAt: now, ExpiresAt: now.Add(20 * time.Minute),
	}
	if err := writeJSONFile(path, 0o600, retained); err != nil {
		return connectionRequestState{}, err
	}
	return retained, nil
}

func loadRetainedConnection(stateDir string) (retainedConnection, error) {
	var retained retainedConnection
	err := readJSON(filepath.Join(stateDir, "connection-result.json"), &retained)
	return retained, err
}

func writeConnectionOutput(retained retainedConnection) error {
	return json.NewEncoder(os.Stdout).Encode(connectionOutput{
		Status: retained.Status, Agent: retained.Agent, TokenSHA256: retained.TokenSHA256,
	})
}

func hostedStateFlag(name string, arguments []string) (string, error) {
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	stateDir := flags.String("state", "", "walkthrough state directory")
	if err := flags.Parse(arguments); err != nil {
		return "", err
	}
	if *stateDir == "" || flags.NArg() != 0 {
		return "", fmt.Errorf("%s requires --state DIR", name)
	}
	return *stateDir, nil
}

func readHostedRemoteError(response *http.Response) error {
	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return err
	}
	return &hostedRemoteError{status: response.StatusCode, body: string(body)}
}
