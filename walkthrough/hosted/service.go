package main

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/agentprovider"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

type enrollmentCodeState struct {
	CodeSHA256 string `json:"code_sha256"`
	Identity   string `json:"identity,omitempty"`
}

type enrollmentCodeAuthorizer struct {
	mu   sync.Mutex
	path string
}

func serveCommand(arguments []string) error {
	stateDir, err := hostedStateFlag("serve", arguments)
	if err != nil {
		return err
	}
	config, err := loadHostConfig(stateDir)
	if err != nil {
		return err
	}
	clock := aauth.ClockFunc(func() time.Time { return time.Now().UTC() })
	key, err := loadHostedSigningKey(stateDir, "provider")
	if err != nil {
		return fmt.Errorf("load Agent Provider key: %w", err)
	}
	provider, err := agentprovider.New(agentprovider.Config{
		Issuer: config.Origin, SigningKey: key, Clock: clock, NewID: hostedRandomID,
	})
	if err != nil {
		return err
	}
	store := newEnrollmentFileStore(filepath.Join(stateDir, "enrollment-store.json"), func() time.Time { return clock.Now() })
	accounts := newAccountFileStore(filepath.Join(stateDir, "account-store.json"), func() time.Time { return clock.Now() })
	protocol := newHostedProtocolStore(filepath.Join(stateDir, "protocol-store.json"))
	roles, err := composeHostedRoles(stateDir, config, accounts, protocol, clock)
	if err != nil {
		return err
	}
	codeAuthorizer := &enrollmentCodeAuthorizer{path: filepath.Join(stateDir, "enrollment-code.json")}
	if err := codeAuthorizer.initialize(config.EnrollmentCode); err != nil {
		return err
	}
	service, err := agentprovider.NewEnrollmentService(agentprovider.EnrollmentServiceConfig{
		Provider: provider,
		Store:    store,
		Enroll: func(_ context.Context, request agentprovider.EnrollmentRequest) (agentprovider.EnrollmentDecision, error) {
			var evidence struct {
				EnrollmentCode string `json:"enrollment_code"`
				Account        string `json:"account"`
			}
			if err := json.Unmarshal(request.Evidence, &evidence); err != nil || evidence.Account != "person-1" {
				return agentprovider.EnrollmentDecision{}, agentprovider.ErrEnrollmentDenied
			}
			if err := codeAuthorizer.authorize(evidence.EnrollmentCode, request.Identity); err != nil {
				return agentprovider.EnrollmentDecision{}, err
			}
			host, err := url.Parse(config.Origin)
			if err != nil {
				return agentprovider.EnrollmentDecision{}, err
			}
			return agentprovider.EnrollmentDecision{Agent: "aauth:agent-1@" + host.Hostname()}, nil
		},
		Refresh: func(_ context.Context, request agentprovider.RefreshRequest) (agentprovider.RefreshDecision, error) {
			var evidence struct {
				Account string `json:"account"`
			}
			if err := json.Unmarshal(request.Evidence, &evidence); err != nil || evidence.Account != "person-1" || request.RequestedPersonServer != hostedPersonOrigin(config.Origin) {
				return agentprovider.RefreshDecision{}, agentprovider.ErrRefreshDenied
			}
			return agentprovider.RefreshDecision{PersonServer: request.RequestedPersonServer, Lifetime: 10 * time.Minute}, nil
		},
	})
	if err != nil {
		return err
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusOK)
	})
	mux.Handle("POST /internal/enrollment", service.EnrollmentHandler())
	mux.Handle("POST /internal/refresh", service.RefreshHandler())
	mux.HandleFunc("POST /account/login", func(response http.ResponseWriter, request *http.Request) {
		var input struct {
			Email    string `json:"email"`
			Password string `json:"password"`
		}
		if err := decodeHostedRequest(request, &input); err != nil {
			writeHostedJSON(response, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
			return
		}
		token, err := accounts.login(input.Email, input.Password)
		if errors.Is(err, errLoginDenied) {
			writeHostedJSON(response, http.StatusUnauthorized, map[string]string{"error": "login_denied"})
			return
		}
		if err != nil {
			writeHostedJSON(response, http.StatusInternalServerError, map[string]string{"error": "state_unavailable"})
			return
		}
		writeHostedJSON(response, http.StatusOK, map[string]string{"session_token": token})
	})
	mux.HandleFunc("POST /account/link", func(response http.ResponseWriter, request *http.Request) {
		var input struct {
			Account string `json:"account"`
		}
		if err := decodeHostedRequest(request, &input); err != nil || input.Account == "" {
			writeHostedJSON(response, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
			return
		}
		err := accounts.link(bearerToken(request), input.Account)
		switch {
		case errors.Is(err, errLoginRequired):
			writeHostedJSON(response, http.StatusUnauthorized, map[string]string{"error": "login_required"})
		case errors.Is(err, errAccountConflict):
			writeHostedJSON(response, http.StatusConflict, map[string]string{"error": "account_conflict"})
		case err != nil:
			writeHostedJSON(response, http.StatusInternalServerError, map[string]string{"error": "state_unavailable"})
		default:
			writeHostedJSON(response, http.StatusOK, map[string]string{"status": "linked"})
		}
	})
	mux.HandleFunc("GET /account/status", func(response http.ResponseWriter, request *http.Request) {
		email, account, linked, err := accounts.status(bearerToken(request))
		if errors.Is(err, errLoginRequired) {
			writeHostedJSON(response, http.StatusUnauthorized, map[string]string{"error": "login_required"})
			return
		}
		if err != nil {
			writeHostedJSON(response, http.StatusInternalServerError, map[string]string{"error": "state_unavailable"})
			return
		}
		writeHostedJSON(response, http.StatusOK, map[string]any{"email": email, "account": account, "linked": linked})
	})
	mux.HandleFunc("POST /account/mission-approval", func(response http.ResponseWriter, request *http.Request) {
		err := accounts.approveMission(bearerToken(request))
		if errors.Is(err, errLoginRequired) {
			writeHostedJSON(response, http.StatusUnauthorized, map[string]string{"error": "login_required"})
			return
		}
		if err != nil {
			writeHostedJSON(response, http.StatusConflict, map[string]string{"error": "account_not_linked"})
			return
		}
		writeHostedJSON(response, http.StatusOK, map[string]string{"status": "approved"})
	})
	mux.HandleFunc("POST /account/revoke-agent", func(response http.ResponseWriter, request *http.Request) {
		if _, _, _, err := accounts.status(bearerToken(request)); errors.Is(err, errLoginRequired) {
			writeHostedJSON(response, http.StatusUnauthorized, map[string]string{"error": "login_required"})
			return
		} else if err != nil {
			writeHostedJSON(response, http.StatusInternalServerError, map[string]string{"error": "state_unavailable"})
			return
		}
		refresh, err := store.revokeOnlyEnrollment()
		if err != nil {
			writeHostedJSON(response, http.StatusConflict, map[string]string{"error": "enrollment_unavailable"})
			return
		}
		resolver := signaturekey.StaticKeyResolver{
			{Issuer: config.Origin, DiscoveryDocument: aauth.AgentDiscoveryDocument, KeyID: key.ID()}: key.PublicJWK(),
		}
		claims, err := aauth.VerifyAgentToken(request.Context(), refresh.AgentToken, resolver, clock)
		if err != nil {
			writeHostedJSON(response, http.StatusInternalServerError, map[string]string{"error": "retained_token_invalid"})
			return
		}
		httpClient, err := newHostedHTTPClient(stateDir, agentConfig{ServiceOrigin: config.Origin, ServiceAddress: config.Listen, EnrollmentCode: config.EnrollmentCode, ControlToken: config.ControlToken})
		if err != nil {
			writeHostedJSON(response, http.StatusInternalServerError, map[string]string{"error": "revocation_transport_unavailable"})
			return
		}
		revoker, err := agentprovider.NewRevocationClient(agentprovider.RevocationClientConfig{
			Provider: provider, HTTPClient: httpClient, Admit: admitHostedRoles(config.Origin),
		})
		if err != nil {
			writeHostedJSON(response, http.StatusInternalServerError, map[string]string{"error": "revocation_client_unavailable"})
			return
		}
		reference := aauth.TokenReference{Issuer: claims.Issuer, JTI: claims.JTI}
		if err := revoker.RevokeAgentToken(request.Context(), hostedPersonOrigin(config.Origin), reference); err != nil {
			writeHostedJSON(response, http.StatusBadGateway, map[string]string{"error": "person_revocation_failed"})
			return
		}
		writeHostedJSON(response, http.StatusOK, map[string]string{"status": "revoked"})
	})
	mux.Handle("GET /control/status", requireHostedControl(config.ControlToken, http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		enrollments, refreshes, err := store.counts()
		if err != nil {
			writeHostedJSON(response, http.StatusInternalServerError, map[string]string{"error": "state_unavailable"})
			return
		}
		connectorCalls, err := protocol.connectorCallCount()
		if err != nil {
			writeHostedJSON(response, http.StatusInternalServerError, map[string]string{"error": "state_unavailable"})
			return
		}
		writeHostedJSON(response, http.StatusOK, map[string]int{"enrollments": enrollments, "refreshes": refreshes, "connector_calls": connectorCalls})
	})))
	mux.Handle("/", provider.Handler())
	baseHost, _ := url.Parse(config.Origin)
	personHost, _ := url.Parse(hostedPersonOrigin(config.Origin))
	resourceHost, _ := url.Parse(hostedResourceOrigin(config.Origin))
	handler := http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		host := request.Host
		if parsed, _, err := net.SplitHostPort(host); err == nil {
			host = parsed
		}
		switch host {
		case personHost.Hostname():
			roles.people.ServeHTTP(response, request)
		case resourceHost.Hostname():
			roles.resource.ServeHTTP(response, request)
		case baseHost.Hostname():
			mux.ServeHTTP(response, request)
		default:
			writeHostedJSON(response, http.StatusMisdirectedRequest, map[string]string{"error": "unknown_host"})
		}
	})
	server := &http.Server{Addr: config.Listen, Handler: handler, ReadHeaderTimeout: 5 * time.Second}
	err = server.ListenAndServeTLS(filepath.Join(stateDir, "server-tls.pem"), filepath.Join(stateDir, "server-tls.key"))
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func (authorizer *enrollmentCodeAuthorizer) initialize(code string) error {
	authorizer.mu.Lock()
	defer authorizer.mu.Unlock()
	if _, err := os.Stat(authorizer.path); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	digest := sha256.Sum256([]byte(code))
	return writeJSONFile(authorizer.path, 0o600, enrollmentCodeState{CodeSHA256: fmt.Sprintf("%x", digest[:])})
}

func (authorizer *enrollmentCodeAuthorizer) authorize(code, identity string) error {
	authorizer.mu.Lock()
	defer authorizer.mu.Unlock()
	var state enrollmentCodeState
	if err := readJSON(authorizer.path, &state); err != nil {
		return err
	}
	digest := sha256.Sum256([]byte(code))
	encoded := fmt.Sprintf("%x", digest[:])
	if len(encoded) != len(state.CodeSHA256) || subtle.ConstantTimeCompare([]byte(encoded), []byte(state.CodeSHA256)) != 1 {
		return agentprovider.ErrEnrollmentDenied
	}
	if state.Identity != "" && state.Identity != identity {
		return agentprovider.ErrEnrollmentDenied
	}
	if state.Identity == identity {
		return nil
	}
	state.Identity = identity
	return writeJSONFile(authorizer.path, 0o600, state)
}

func requireHostedControl(token string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		provided := strings.TrimPrefix(request.Header.Get("Authorization"), "Bearer ")
		if len(provided) != len(token) || subtle.ConstantTimeCompare([]byte(provided), []byte(token)) != 1 {
			response.Header().Set("WWW-Authenticate", "Bearer")
			writeHostedJSON(response, http.StatusUnauthorized, map[string]string{"error": "control_authentication_required"})
			return
		}
		next.ServeHTTP(response, request)
	})
}

func writeHostedJSON(response http.ResponseWriter, status int, value any) {
	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(value)
}

func hostedRandomID() string {
	value, err := randomSecret()
	if err != nil {
		panic(err)
	}
	return value
}

func decodeHostedRequest(request *http.Request, value any) error {
	decoder := json.NewDecoder(io.LimitReader(request.Body, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("request body has trailing JSON")
	}
	return nil
}

func bearerToken(request *http.Request) string {
	value := request.Header.Get("Authorization")
	if !strings.HasPrefix(value, "Bearer ") {
		return ""
	}
	return strings.TrimPrefix(value, "Bearer ")
}
