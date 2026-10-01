package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	clientagent "gitlab.com/sidecat-dev/aauth-go/agent"
	"gitlab.com/sidecat-dev/aauth-go/agentprovider"
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/personserver"
	"gitlab.com/sidecat-dev/aauth-go/resource"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

type agentCredential struct {
	Compact   string               `json:"compact"`
	Reference aauth.TokenReference `json:"reference"`
	ExpiresAt time.Time            `json:"expires_at"`
}

type agentRuntime struct {
	provider     *agentprovider.Server
	client       *clientagent.Client
	credential   agentCredential
	httpClient   *http.Client
	results      *resultStore
	controlToken string
}

func processCommand(name string, arguments []string) error {
	stateDir, err := stateFlag(name, arguments)
	if err != nil {
		return err
	}
	config, err := loadConfig(stateDir)
	if err != nil {
		return err
	}
	switch name {
	case "agent":
		return runAgentProcess(stateDir, config)
	case "service":
		return runServiceProcess(stateDir, config)
	default:
		return errors.New("unknown process")
	}
}

func runAgentProcess(stateDir string, config walkthroughConfig) error {
	runtime, err := newAgentRuntime(stateDir, config)
	if err != nil {
		return err
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusOK)
	})
	mux.Handle("POST /control/act", runtime.authorizeControl(http.HandlerFunc(runtime.handleAct)))
	mux.Handle("POST /control/revoke", runtime.authorizeControl(http.HandlerFunc(runtime.handleRevoke)))
	mux.Handle("/", runtime.provider.Handler())
	return serveTLS(config.AgentAddress, filepath.Join(stateDir, "agent-tls.pem"), filepath.Join(stateDir, "agent-tls.key"), mux)
}

func newAgentRuntime(stateDir string, config walkthroughConfig) (*agentRuntime, error) {
	clock := aauth.ClockFunc(func() time.Time { return time.Now().UTC() })
	key, err := loadSigningKey(stateDir, "agent")
	if err != nil {
		return nil, fmt.Errorf("load Agent key: %w", err)
	}
	provider, err := agentprovider.New(agentprovider.Config{
		Issuer: agentOrigin, SigningKey: key, Clock: clock,
		NewID: randomID,
	})
	if err != nil {
		return nil, err
	}
	credential, err := loadOrIssueAgentCredential(stateDir, provider, key, clock)
	if err != nil {
		return nil, err
	}
	httpClient, err := newHTTPClient(stateDir, config)
	if err != nil {
		return nil, err
	}
	resolver := signaturekey.StaticKeyResolver{
		{Issuer: agentOrigin, DiscoveryDocument: aauth.AgentDiscoveryDocument, KeyID: key.ID()}: key.PublicJWK(),
	}
	client, err := clientagent.New(context.Background(), clientagent.Config{
		Identifier: agentID, SigningKey: key, AgentToken: credential.Compact,
		KeyResolver: resolver, HTTPClient: httpClient, Clock: clock,
		MaxSignedBodyBytes: 1 << 20,
	})
	if err != nil {
		return nil, err
	}
	controlToken, err := loadControlToken(stateDir)
	if err != nil {
		return nil, err
	}
	return &agentRuntime{
		provider: provider, client: client, credential: credential, httpClient: httpClient,
		results: newResultStore(filepath.Join(stateDir, "agent-results.json")), controlToken: controlToken,
	}, nil
}

func (runtime *agentRuntime) authorizeControl(next http.Handler) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		provided := strings.TrimPrefix(request.Header.Get("Authorization"), "Bearer ")
		if len(provided) != len(runtime.controlToken) ||
			subtle.ConstantTimeCompare([]byte(provided), []byte(runtime.controlToken)) != 1 {
			response.Header().Set("WWW-Authenticate", "Bearer")
			writeJSON(response, http.StatusUnauthorized, map[string]string{"error": "control_authentication_required"})
			return
		}
		next.ServeHTTP(response, request)
	})
}

func loadControlToken(stateDir string) (string, error) {
	encoded, err := os.ReadFile(filepath.Join(stateDir, "control.token"))
	if err != nil {
		return "", fmt.Errorf("read control credential: %w", err)
	}
	token := strings.TrimSpace(string(encoded))
	if token == "" {
		return "", errors.New("control credential is empty")
	}
	return token, nil
}

func (runtime *agentRuntime) handleAct(response http.ResponseWriter, request *http.Request) {
	var input struct {
		RequestKey string `json:"request_key"`
	}
	if err := json.NewDecoder(io.LimitReader(request.Body, 1<<20)).Decode(&input); err != nil || input.RequestKey == "" {
		writeJSON(response, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	if retained, ok, err := runtime.results.load(input.RequestKey); err != nil {
		writeControlError(response, err)
		return
	} else if ok {
		retained.Replayed = true
		writeJSON(response, http.StatusOK, retained)
		return
	}
	permission, err := runtime.client.RequestPermission(request.Context(), clientagent.PermissionRequest{
		PersonServer: personOrigin,
		Action:       "notes.create",
		Description:  "Create one local note after an explicit permission decision.",
		Parameters:   json.RawMessage(`{"text":"hello"}`),
	})
	if err != nil {
		writeControlError(response, err)
		return
	}
	decision, ok := permission.Decision()
	if !ok || decision.Permission() != aauth.PermissionGranted {
		writeJSON(response, http.StatusForbidden, map[string]string{"error": "permission_denied"})
		return
	}
	applicationRequest, err := http.NewRequestWithContext(request.Context(), http.MethodPost, resourceOrigin+"/notes", strings.NewReader(`{"text":"hello"}`))
	if err != nil {
		writeControlError(response, err)
		return
	}
	applicationRequest.Header.Set("Content-Type", "application/json")
	applicationRequest.Header.Set("Idempotency-Key", input.RequestKey)
	applicationResponse, err := runtime.client.CallAsAgent(request.Context(), applicationRequest)
	if err != nil {
		writeControlError(response, err)
		return
	}
	defer applicationResponse.Body.Close()
	if applicationResponse.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(applicationResponse.Body, 1<<20))
		writeControlError(response, fmt.Errorf("Resource returned %s: %s", applicationResponse.Status, body))
		return
	}
	var output actionOutput
	if err := json.NewDecoder(io.LimitReader(applicationResponse.Body, 1<<20)).Decode(&output); err != nil {
		writeControlError(response, err)
		return
	}
	output.Status = "completed"
	output.RequestKey = input.RequestKey
	if err := runtime.results.save(input.RequestKey, output); err != nil {
		writeControlError(response, err)
		return
	}
	writeJSON(response, http.StatusOK, output)
}

func (runtime *agentRuntime) handleRevoke(response http.ResponseWriter, request *http.Request) {
	client, err := agentprovider.NewRevocationClient(agentprovider.RevocationClientConfig{
		Provider: runtime.provider, HTTPClient: runtime.httpClient, Admit: admitWalkthroughEndpoint,
	})
	if err != nil {
		writeControlError(response, err)
		return
	}
	revocation := aauth.RevocationRequest{Reference: runtime.credential.Reference, ExpiresAt: runtime.credential.ExpiresAt}
	if err := client.RevokeAgentToken(request.Context(), personOrigin, revocation); err != nil {
		writeControlError(response, err)
		return
	}
	revocationHeaders := make(http.Header)
	revocationHeaders.Set("Idempotency-Key", "revoke-"+runtime.credential.Reference.JTI)
	if err := client.RevokeAgentTokenAtResourceWithHeaders(
		request.Context(), resourceOrigin, revocation, revocationHeaders,
	); err != nil {
		writeControlError(response, err)
		return
	}
	writeJSON(response, http.StatusOK, map[string]string{"status": "revoked"})
}

func runServiceProcess(stateDir string, config walkthroughConfig) error {
	clock := aauth.ClockFunc(func() time.Time { return time.Now().UTC() })
	httpClient, err := newHTTPClient(stateDir, config)
	if err != nil {
		return err
	}
	resolver, err := signaturekey.NewHTTPKeyResolver(signaturekey.HTTPKeyResolverConfig{
		Client: httpClient, Clock: clock, Admit: admitWalkthroughEndpoint,
	})
	if err != nil {
		return err
	}
	personKey, err := loadSigningKey(stateDir, "person")
	if err != nil {
		return err
	}
	revocations := newRevocationStore(filepath.Join(stateDir, "agent-revocations.json"))
	people, err := personserver.NewPSAuthorization(personserver.PSAuthorizationConfig{
		Issuer: personOrigin, SigningKey: personKey, KeyResolver: resolver, Clock: clock,
		NewID:  randomID,
		Tokens: newTokenStore(filepath.Join(stateDir, "person-tokens.json")),
		BindPerson: func(context.Context, personserver.PersonTokenRequest) (personserver.Person, error) {
			return personserver.Person{Subject: "local-person", Lifetime: 5 * time.Minute}, nil
		},
		Authorize: func(context.Context, personserver.AuthorizationRequest) (personserver.AuthorizationDecision, error) {
			return personserver.AuthorizationDecision{Scopes: []string{"notes.write"}, Lifetime: 5 * time.Minute}, nil
		},
		Permission: &personserver.PermissionConfig{
			Store: newPermissionStore(filepath.Join(stateDir, "permissions.json")),
			Policy: func(_ context.Context, input personserver.PermissionPolicyRequest) (personserver.PermissionPolicyResult, error) {
				if input.Agent != agentID || input.Action != "notes.create" || input.Mission != nil {
					return personserver.PermissionPolicyResult{Immediate: &personserver.PermissionDecision{
						Permission: aauth.PermissionDenied, Reason: "The walkthrough grants only notes.create.",
					}}, nil
				}
				return personserver.PermissionPolicyResult{Immediate: &personserver.PermissionDecision{Permission: aauth.PermissionGranted}}, nil
			},
		},
		AgentTokenRevocations: revocations,
	})
	if err != nil {
		return err
	}
	consequences := newConsequenceStore(filepath.Join(stateDir, "consequences.json"))
	protected := http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.URL.Path != "/notes" {
			http.NotFound(response, request)
			return
		}
		principal, ok := resource.AgentPrincipalFromContext(request.Context())
		if !ok || principal.Agent != agentID {
			writeJSON(response, http.StatusForbidden, map[string]string{"error": "access_denied"})
			return
		}
		requestKey := request.Header.Get("Idempotency-Key")
		if requestKey == "" {
			writeJSON(response, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
			return
		}
		result, replayed, count, err := consequences.apply(requestKey)
		if err != nil {
			writeControlError(response, err)
			return
		}
		writeJSON(response, http.StatusOK, actionOutput{
			Status: "completed", Agent: principal.Agent, RequestKey: requestKey, Result: result,
			Replayed: replayed, ConsequenceCount: count,
		})
	})
	resourceServer, err := resource.NewAgentIdentity(resource.AgentIdentityConfig{
		Issuer: resourceOrigin, KeyResolver: resolver, Clock: clock,
		AdditionalSignatureComponents: []string{"idempotency-key"}, MaxSignedBodyBytes: 1 << 20,
		Protected: protected, AgentTokenRevocations: revocations,
	})
	if err != nil {
		return err
	}
	router := http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/health" {
			response.WriteHeader(http.StatusOK)
			return
		}
		switch request.Host {
		case "person.local":
			people.Handler().ServeHTTP(response, request)
		case "resource.local":
			if request.URL.Path == "/status" {
				count, err := consequences.count()
				if err != nil {
					writeControlError(response, err)
					return
				}
				writeJSON(response, http.StatusOK, actionOutput{Status: "ready", ConsequenceCount: count})
				return
			}
			resourceServer.Handler().ServeHTTP(response, request)
		default:
			http.NotFound(response, request)
		}
	})
	return serveTLS(config.ServiceAddress, filepath.Join(stateDir, "service-tls.pem"), filepath.Join(stateDir, "service-tls.key"), router)
}

func serveTLS(address, certificate, privateKey string, handler http.Handler) error {
	server := &http.Server{Addr: address, Handler: handler, ReadHeaderTimeout: 5 * time.Second}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	result := make(chan error, 1)
	go func() { result <- server.ListenAndServeTLS(certificate, privateKey) }()
	select {
	case err := <-result:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdown); err != nil {
			return err
		}
		return nil
	}
}

func randomID() string {
	value := make([]byte, 18)
	if _, err := rand.Read(value); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(value)
}

func writeJSON(response http.ResponseWriter, status int, value any) {
	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(value)
}

func writeControlError(response http.ResponseWriter, err error) {
	code := "internal_error"
	status := http.StatusInternalServerError
	if strings.Contains(err.Error(), "invalid_agent_token") {
		code = "invalid_agent_token"
		status = http.StatusBadRequest
	} else if strings.Contains(err.Error(), "invalid_token") || strings.Contains(strings.ToLower(err.Error()), "revoked") {
		code = "invalid_token"
		status = http.StatusUnauthorized
	}
	writeJSON(response, status, map[string]string{"error": code, "detail": err.Error()})
}

func loadOrIssueAgentCredential(stateDir string, provider *agentprovider.Server, key jose.SigningKey, clock aauth.Clock) (agentCredential, error) {
	path := filepath.Join(stateDir, "agent-credential.json")
	var retained agentCredential
	if encoded, err := os.ReadFile(path); err == nil {
		if err := json.Unmarshal(encoded, &retained); err != nil {
			return retained, err
		}
		if retained.Compact != "" && time.Now().UTC().Add(time.Minute).Before(retained.ExpiresAt) {
			return retained, nil
		}
	} else if !os.IsNotExist(err) {
		return retained, err
	}
	compact, err := provider.Issue(aauth.AgentTokenRequest{
		Agent: agentID, PersonServer: personOrigin, PublicKey: key.PublicJWK(), Lifetime: 15 * time.Minute,
	})
	if err != nil {
		return retained, err
	}
	resolver := signaturekey.StaticKeyResolver{
		{Issuer: agentOrigin, DiscoveryDocument: aauth.AgentDiscoveryDocument, KeyID: key.ID()}: key.PublicJWK(),
	}
	claims, err := aauth.VerifyAgentToken(context.Background(), compact, resolver, clock)
	if err != nil {
		return retained, err
	}
	retained = agentCredential{
		Compact:   compact,
		Reference: aauth.TokenReference{Issuer: claims.Issuer, JTI: claims.JTI},
		ExpiresAt: time.Unix(claims.ExpiresAt, 0).UTC(),
	}
	if err := writeJSONAtomic(path, retained); err != nil {
		return retained, err
	}
	return retained, nil
}

type remoteError struct{ body string }

func (failure *remoteError) Error() string { return strings.TrimSpace(failure.body) }

func requestJSON(client *http.Client, method, endpoint string, input any, bearer string) ([]byte, error) {
	var body io.Reader
	if input != nil {
		encoded, err := json.Marshal(input)
		if err != nil {
			return nil, err
		}
		body = bytes.NewReader(encoded)
	}
	request, err := http.NewRequest(method, endpoint, body)
	if err != nil {
		return nil, err
	}
	if input != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if bearer != "" {
		request.Header.Set("Authorization", "Bearer "+bearer)
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	encoded, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, &remoteError{body: string(encoded)}
	}
	return encoded, nil
}
