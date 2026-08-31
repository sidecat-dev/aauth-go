// The fourparty example runs immediate missionless Core, mission-bound Core,
// and direct MCP R3 flows entirely in process. Each role still communicates
// through ordinary HTTP handlers and a client, so the messages match a
// network deployment.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"time"

	aauth "aauth-go"
	"aauth-go/accessserver"
	clientagent "aauth-go/agent"
	"aauth-go/agentprovider"
	"aauth-go/internal/exampleutil"
	"aauth-go/jose"
	"aauth-go/personserver"
	"aauth-go/resource"
	"aauth-go/signaturekey"
)

const (
	agentProviderID = "https://agents.example"
	agentID         = "aauth:reader@agents.example"
	personServerID  = "https://person.example"
	accessServerID  = "https://access.example"
	resourceID      = "https://resource.example"
	scope           = "records.read"
)

func main() {
	run(os.Stdout)
}

func run(output io.Writer) {
	runFourParty(output, false)
	runFourParty(output, true)
	runR3Direct(output)
}

func runFourParty(output io.Writer, missionBound bool) {
	now := time.Date(2026, 8, 29, 18, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })

	providerKey := newSigningKey("agent-provider-key")
	agentKey := newSigningKey("agent-key")
	personKey := newSigningKey("person-server-key")
	accessKey := newSigningKey("access-server-key")
	resourceKey := newSigningKey("resource-key")

	network := newLogicalTransport()
	httpClient := &http.Client{Transport: network}
	resolver := must(signaturekey.NewHTTPKeyResolver(signaturekey.HTTPKeyResolverConfig{
		Client: httpClient,
		Clock:  clock,
		Admit:  network.Admit,
	}))

	provider := must(agentprovider.New(agentprovider.Config{
		Issuer: agentProviderID, SigningKey: providerKey, Clock: clock,
		NewID: func() string { return "agent-token-1" },
	}))
	agentToken := must(provider.Issue(aauth.AgentTokenRequest{
		Agent: agentID, PersonServer: personServerID,
		PublicKey: agentKey.PublicJWK(), Lifetime: time.Hour,
	}))

	access := must(accessserver.New(accessserver.Config{
		Issuer: accessServerID, SigningKey: accessKey,
		KeyResolver: resolver, Clock: clock,
		NewID: func() string { return "auth-token-1" },
		TrustPersonServer: func(_ context.Context, issuer string) error {
			if issuer != personServerID {
				return errors.Join(accessserver.ErrAccessDenied, errors.New("untrusted person server"))
			}
			return nil
		},
		Authorize: func(_ context.Context, request accessserver.AuthorizationRequest) (accessserver.Decision, error) {
			if (request.MissionS256 != "") != missionBound {
				return accessserver.Decision{}, errors.Join(accessserver.ErrAccessDenied, errors.New("unexpected mission context"))
			}
			return accessserver.Decision{Scopes: request.Scopes, Lifetime: 30 * time.Minute}, nil
		},
	}))

	protected := http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		principal, ok := resource.AuthPrincipalFromContext(request.Context())
		if !ok {
			http.Error(response, "missing AAuth principal", http.StatusInternalServerError)
			return
		}
		if (principal.MissionS256 != "") != missionBound {
			http.Error(response, "unexpected mission context", http.StatusInternalServerError)
			return
		}
		variant := "missionless"
		if missionBound {
			variant = "mission-bound"
		}
		fmt.Fprintf(response, "AAuth %s four-party flow complete: %s has %s\n", variant, principal.Subject, principal.Scope[0])
	})
	protectedResource := must(resource.NewFederatedAuthorization(resource.FederatedAuthorizationConfig{
		Issuer: resourceID, AccessServer: accessServerID,
		SigningKey: resourceKey, KeyResolver: resolver, Clock: clock,
		NewID:             func() string { return "resource-token-1" },
		ScopeDescriptions: map[string]string{scope: "Read records"},
		RequiredScopes:    func(*http.Request) []string { return []string{scope} },
		ResolvePerson: func(_ context.Context, identity resource.PersonIdentity, _ resource.PersonContext) error {
			if identity.Issuer != personServerID || identity.Subject == "" {
				return errors.New("unrecognized person identity")
			}
			return nil
		},
		Protected: protected,
	}))

	missionExpiry := now.Add(15 * time.Minute)
	personAcceptedCompletion := false
	var missions *personserver.MissionConfig
	if missionBound {
		missions = &personserver.MissionConfig{
			Approve: func(_ context.Context, request personserver.MissionApprovalRequest) (personserver.MissionDecision, error) {
				return personserver.MissionDecision{
					Description: request.Proposal.Description, ApprovedResources: request.Proposal.Resources,
					ExpiresAt: &missionExpiry,
				}, nil
			},
			AcceptUpdate: func(_ context.Context, request personserver.MissionUpdatePolicyRequest) error {
				if request.Document.Update.Description == "" {
					return errors.New("mission update description is required")
				}
				return nil
			},
			ConfirmPersonAcceptedCompletion: func(_ context.Context, request personserver.MissionCompletionPolicyRequest) error {
				if !personAcceptedCompletion {
					return fmt.Errorf("%w: person has not accepted completion", personserver.ErrMissionDenied)
				}
				return nil
			},
		}
	}
	people := must(personserver.NewFederatedAuthorization(personserver.FederatedAuthorizationConfig{
		Issuer: personServerID, SigningKey: personKey,
		KeyResolver: resolver, Clock: clock,
		NewID:      func() string { return "person-token-1" },
		HTTPClient: httpClient, Tokens: exampleutil.NewMissionStore(),
		Missions: missions,
		AccessServerEndpoint: func(_ context.Context, issuer string) (string, error) {
			if issuer != accessServerID {
				return "", errors.New("unknown access server")
			}
			return accessServerID + "/token", nil
		},
		BindPerson: func(_ context.Context, request personserver.PersonTokenRequest) (personserver.Person, error) {
			if request.Agent != agentID || request.Resource != resourceID ||
				(request.Mission != nil) != missionBound {
				return personserver.Person{}, errors.New("unexpected person-token request")
			}
			return personserver.Person{Subject: "person-123", Lifetime: time.Hour}, nil
		},
		Consent: func(_ context.Context, request personserver.AuthorizationRequest) error {
			if missionBound && (request.Mission == nil || len(request.Mission.AcceptedUpdates) != 1 ||
				request.Mission.AcceptedUpdates[0].Document.Update.Description != "Report inputs selected") {
				return errors.Join(personserver.ErrAccessDenied, errors.New("accepted mission update is required"))
			}
			if !missionBound && request.Mission != nil {
				return errors.New("mission context is unexpected")
			}
			return nil
		},
	}))

	network.Handle(agentProviderID, provider.Handler())
	network.Handle(personServerID, people.Handler())
	network.Handle(accessServerID, access.Handler())
	network.Handle(resourceID, protectedResource.Handler())

	reader := must(clientagent.New(context.Background(), clientagent.Config{
		Identifier: agentID, SigningKey: agentKey, AgentToken: agentToken,
		KeyResolver: resolver, HTTPClient: httpClient, Clock: clock,
	}))
	ctx := context.Background()
	var personToken string
	var missionS256 string
	if missionBound {
		mission := must(reader.ProposeMission(ctx, clientagent.MissionRequest{
			PersonServer: personServerID,
			Proposal: aauth.MissionProposal{
				Description: "# Read the report inputs", Resources: []string{resourceID},
			},
		}))
		missionS256 = mission.Mission().S256
		update := must(reader.UpdateMission(ctx, clientagent.MissionUpdateRequest{
			PersonServer: personServerID, MissionS256: missionS256,
			Description: "Report inputs selected",
		}))
		if update.S256() == "" {
			log.Fatal("mission update returned no digest")
		}
		var ok bool
		personToken, ok = mission.PersonToken(resourceID)
		if !ok {
			log.Fatal("mission approval omitted the Resource person token")
		}
	} else {
		result := must(reader.PersonToken(ctx, clientagent.PersonTokenRequest{
			PersonServer: personServerID, Resource: resourceID,
		}))
		var ok bool
		personToken, ok = result.Token()
		if !ok {
			log.Fatal("Person Server unexpectedly required interaction")
		}
	}
	resourceToken := must(reader.Authorize(ctx, clientagent.AuthorizeRequest{
		Resource: resourceID, PersonToken: personToken, Scopes: []string{scope},
	}))
	authToken := must(reader.Exchange(ctx, clientagent.ExchangeRequest{
		PersonServer: personServerID, ResourceToken: resourceToken,
	}))
	request := must(http.NewRequestWithContext(ctx, http.MethodGet, resourceID+"/records/42", nil))
	response := must(reader.Do(ctx, clientagent.Call{Request: request, AuthToken: authToken}))
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		log.Fatalf("protected call returned %s", response.Status)
	}
	_, _ = io.Copy(output, response.Body)
	if missionBound {
		personAcceptedCompletion = true
		if err := reader.CompleteMission(ctx, clientagent.MissionCompletionRequest{
			PersonServer: personServerID, MissionS256: missionS256,
			Summary: "Protected report read completed",
		}); err != nil {
			log.Fatal(err)
		}
		fmt.Fprintln(output, "mission completed with person acceptance")
	}
}

func newSigningKey(id string) jose.SigningKey {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	return must(jose.NewEd25519SigningKey(id, privateKey))
}

func must[T any](value T, err error) T {
	if err != nil {
		log.Fatal(err)
	}
	return value
}

type logicalTransport struct {
	mu     sync.RWMutex
	routes map[string]http.Handler
}

func newLogicalTransport() *logicalTransport {
	return &logicalTransport{routes: make(map[string]http.Handler)}
}

func (transport *logicalTransport) Handle(origin string, handler http.Handler) {
	transport.mu.Lock()
	defer transport.mu.Unlock()
	transport.routes[origin] = handler
}

func (transport *logicalTransport) Admit(_ context.Context, endpoint string) error {
	request, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	origin := request.URL.Scheme + "://" + request.URL.Host
	transport.mu.RLock()
	_, ok := transport.routes[origin]
	transport.mu.RUnlock()
	if !ok {
		return fmt.Errorf("discovery is not admitted for %s", origin)
	}
	return nil
}

func (transport *logicalTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	origin := request.URL.Scheme + "://" + request.URL.Host
	transport.mu.RLock()
	handler := transport.routes[origin]
	transport.mu.RUnlock()
	if handler == nil {
		return nil, fmt.Errorf("no handler for %s", origin)
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	response := recorder.Result()
	response.Request = request
	return response, nil
}
