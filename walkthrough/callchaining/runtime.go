package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
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

type roleCounters struct {
	metadata     atomic.Int64
	jwks         atomic.Int64
	consequences atomic.Int64
}

type chainResult struct {
	Status           string `json:"status"`
	OrdersSubject    string `json:"orders_subject"`
	InventorySubject string `json:"inventory_subject"`
	Scope            string `json:"scope"`
	IntermediaryKey  string `json:"intermediary_key"`
	UpstreamExp      int64  `json:"upstream_exp"`
	PersonExp        int64  `json:"downstream_person_exp"`
	AuthExp          int64  `json:"downstream_auth_exp"`
	ConsequenceCount int64  `json:"consequence_count"`
}

func serve(state string, config configuration, role string) error {
	if !slices.Contains(roles, role) {
		return errors.New("--role must be agent, person, orders, or inventory")
	}
	client, err := httpClient(state, config)
	if err != nil {
		return err
	}
	keys, err := resolver(client)
	if err != nil {
		return err
	}
	counters := &roleCounters{}
	handler, err := roleHandler(state, config, role, client, keys, counters)
	if err != nil {
		return err
	}
	wrapped := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/status" {
			writeJSON(w, map[string]any{"metadata_requests": counters.metadata.Load(), "jwks_requests": counters.jwks.Load(), "consequence_count": counters.consequences.Load()})
			return
		}
		if strings.HasPrefix(r.URL.Path, "/.well-known/") {
			if r.URL.Path == "/.well-known/jwks.json" {
				counters.jwks.Add(1)
			} else {
				counters.metadata.Add(1)
			}
		}
		handler.ServeHTTP(w, r)
	})
	server := &http.Server{Addr: config.Addresses[role], Handler: wrapped, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 30 * time.Second}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- server.ListenAndServeTLS(filepath.Join(state, role+"-tls.pem"), filepath.Join(state, role+"-tls.key"))
	}()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		shutdown, release := context.WithTimeout(context.Background(), 5*time.Second)
		defer release()
		if err := server.Shutdown(shutdown); err != nil {
			return err
		}
		err := <-done
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

func roleHandler(state string, config configuration, role string, client *http.Client, keys signaturekey.KeyResolver, counters *roleCounters) (http.Handler, error) {
	keyName := role
	if role == "agent" {
		keyName = "agent-provider"
	}
	if role == "orders" {
		keyName = "orders-resource"
	}
	key, err := signingKey(state, keyName)
	if err != nil {
		return nil, err
	}
	originalKey, err := signingKey(state, "agent-proof")
	if err != nil {
		return nil, err
	}
	relayKey, err := signingKey(state, "orders-proof")
	if err != nil {
		return nil, err
	}
	switch role {
	case "agent":
		provider, err := agentprovider.New(agentprovider.Config{Issuer: agentOrigin, SigningKey: key, Clock: clock, NewID: randomID})
		if err != nil {
			return nil, err
		}
		return provider.Handler(), nil
	case "person":
		store := &tokenStore{records: make(map[string][]byte)}
		people, err := personserver.NewPSAuthorization(personserver.PSAuthorizationConfig{
			Issuer: personOrigin, SigningKey: key, KeyResolver: keys, Clock: clock, NewID: randomID, Tokens: store,
			BindPerson: func(_ context.Context, r personserver.PersonTokenRequest) (personserver.Person, error) {
				if r.Agent != agentID || r.Resource != ordersOrigin || r.Upstream != nil || r.Subagent != "" || r.Mission != nil {
					return personserver.Person{}, errors.New("unknown original person request")
				}
				return personserver.Person{Subject: ordersSubject, Lifetime: 2 * time.Minute}, nil
			},
			Authorize: func(_ context.Context, r personserver.AuthorizationRequest) (personserver.AuthorizationDecision, error) {
				if r.Agent != agentID || r.Resource != ordersOrigin || r.Subject != ordersSubject || r.Upstream != nil || !slices.Equal(r.Scopes, []string{ordersScope}) {
					return personserver.AuthorizationDecision{}, errors.New("unknown original authorization")
				}
				return personserver.AuthorizationDecision{Scopes: []string{ordersScope}, Lifetime: 20 * time.Second}, nil
			},
			CallChaining: &personserver.CallChainingConfig{
				BindPerson: func(_ context.Context, r personserver.PersonTokenRequest) (personserver.Person, error) {
					if r.Agent != relayID || r.Resource != inventoryOrigin || !validUpstream(r.Upstream, originalKey.PublicJWK()) {
						return personserver.Person{}, errors.New("unknown upstream person")
					}
					return personserver.Person{Subject: inventorySubject, Lifetime: 2 * time.Minute}, nil
				},
				Authorize: func(_ context.Context, r personserver.AuthorizationRequest) (personserver.AuthorizationDecision, error) {
					if r.Agent != relayID || r.Resource != inventoryOrigin || r.Subject != inventorySubject || !slices.Equal(r.Scopes, []string{inventoryScope}) || !validUpstream(r.Upstream, originalKey.PublicJWK()) {
						return personserver.AuthorizationDecision{}, errors.New("unknown downstream authorization")
					}
					return personserver.AuthorizationDecision{Scopes: []string{inventoryScope}, Lifetime: 2 * time.Minute}, nil
				},
			},
		})
		if err != nil {
			return nil, err
		}
		return people.Handler(), nil
	case "orders", "inventory":
		subject, scope, proof := ordersSubject, ordersScope, originalKey.PublicJWK()
		if role == "inventory" {
			subject, scope, proof = inventorySubject, inventoryScope, relayKey.PublicJWK()
		}
		protected := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			expectedPath := "/orders/42/fulfill"
			if role == "inventory" {
				expectedPath = "/inventory/42/reserve"
			}
			if r.Method != http.MethodPost || r.URL.Path != expectedPath {
				http.NotFound(w, r)
				return
			}
			principal, ok := resource.AuthPrincipalFromContext(r.Context())
			if !ok || principal.PersonServer != personOrigin || principal.Subject != subject || !principal.Confirmation.Equal(proof) || !slices.Equal(principal.Scope, []string{scope}) {
				http.Error(w, "unexpected verified principal", http.StatusForbidden)
				return
			}
			compact, ok := resource.AuthTokenFromContext(r.Context())
			if !ok {
				http.Error(w, "missing verified auth token", http.StatusInternalServerError)
				return
			}
			claims, err := aauth.VerifyAuthToken(r.Context(), compact, keys, clock)
			if err != nil {
				http.Error(w, "cannot inspect verified grant", http.StatusInternalServerError)
				return
			}
			if role == "inventory" {
				thumbprint, err := principal.Confirmation.Thumbprint()
				if err != nil {
					http.Error(w, "cannot identify proof key", http.StatusInternalServerError)
					return
				}
				count := counters.consequences.Add(1)
				writeJSON(w, chainResult{Status: "completed", InventorySubject: principal.Subject, Scope: inventoryScope, IntermediaryKey: thumbprint, AuthExp: claims.ExpiresAt, ConsequenceCount: count})
				return
			}
			// Construct after the Orders listener exists: its collocated AP metadata is
			// resolved over TLS, including its own provider and Resource issuer keys.
			relay, err := clientagent.New(r.Context(), clientagent.Config{Identifier: relayID, SigningKey: relayKey, AgentToken: config.RelayToken, KeyResolver: keys, HTTPClient: client, Clock: clock})
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadGateway)
				return
			}
			result, err := callInventory(r.Context(), relay, compact, keys)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadGateway)
				return
			}
			result.OrdersSubject, result.UpstreamExp = principal.Subject, claims.ExpiresAt
			writeJSON(w, result)
		})
		protectedResource, err := resource.NewPSAuthorization(resource.PSAuthorizationConfig{
			Issuer: origins[role], SigningKey: key, KeyResolver: keys, Clock: clock, NewID: randomID,
			ScopeDescriptions: map[string]string{scope: scope}, RequiredScopes: func(*http.Request) []string { return []string{scope} },
			ResolvePerson: func(_ context.Context, identity resource.PersonIdentity, _ resource.PersonContext) error {
				if identity != (resource.PersonIdentity{Issuer: personOrigin, Subject: subject}) {
					return errors.New("unknown directed person")
				}
				return nil
			},
			Protected: protected,
		})
		if err != nil {
			return nil, err
		}
		if role == "inventory" {
			return protectedResource.Handler(), nil
		}
		providerKey, err := signingKey(state, "orders-provider")
		if err != nil {
			return nil, err
		}
		provider, err := agentprovider.New(agentprovider.Config{Issuer: ordersOrigin, SigningKey: providerKey, Clock: clock, NewID: randomID})
		if err != nil {
			return nil, err
		}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodGet && r.URL.Path == "/.well-known/aauth-agent.json" {
				provider.Handler().ServeHTTP(w, r)
				return
			}
			if r.Method == http.MethodGet && r.URL.Path == "/.well-known/jwks.json" {
				writeJSON(w, map[string]any{"keys": []jose.JWK{providerKey.PublicJWK(), key.PublicJWK()}})
				return
			}
			protectedResource.Handler().ServeHTTP(w, r)
		}), nil
	}
	return nil, fmt.Errorf("unknown role %q", role)
}

func validUpstream(claims *aauth.AuthTokenClaims, proof jose.JWK) bool {
	return claims != nil && claims.Issuer == personOrigin && claims.PersonServer == personOrigin && claims.Audience == ordersOrigin && claims.Subject == ordersSubject && claims.Scope == ordersScope && claims.Confirmation.JWK.Equal(proof) && claims.MissionS256 == "" && claims.Account == nil
}

func writeJSON(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(value); err != nil {
		fmt.Fprintln(os.Stderr, "write response:", err)
	}
}
