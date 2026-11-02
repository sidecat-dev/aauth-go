package integration_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	clientagent "gitlab.com/sidecat-dev/aauth-go/agent"
	"gitlab.com/sidecat-dev/aauth-go/agentprovider"
	"gitlab.com/sidecat-dev/aauth-go/resource"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

// recordingTransport records every URL a client asked for.
type recordingTransport struct {
	next http.RoundTripper
	mu   sync.Mutex
	urls []string
}

func (transport *recordingTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	transport.mu.Lock()
	transport.urls = append(transport.urls, request.URL.String())
	transport.mu.Unlock()
	return transport.next.RoundTrip(request)
}

func (transport *recordingTransport) requested(prefix string) bool {
	transport.mu.Lock()
	defer transport.mu.Unlock()
	return slices.ContainsFunc(transport.urls, func(url string) bool { return strings.HasPrefix(url, prefix) })
}

// TestResourceLinkLeadsAnAgentToVerifiedMetadataOnly follows the
// aauth-resource link relation from a developer portal: the Resource emits
// it, the Agent reads it from the Link field and from the page, records where
// it found each link, fetches only admissible targets under egress
// admission, verifies issuer against the target, and never reads a link as a
// requirement.
func TestResourceLinkLeadsAnAgentToVerifiedMetadataOnly(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	now := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	const (
		resourceID      = "https://api.example"
		portalPage      = "https://portal.example/docs"
		mirrorID        = "https://mirror.example"
		blockedID       = "https://blocked.example"
		agentProviderID = "https://ap.example"
		agentID         = "aauth:reader@ap.example"
	)

	network := newLogicalTransport()
	recorder := &recordingTransport{next: network}
	httpClient := &http.Client{Transport: recorder}
	keyResolver, err := signaturekey.NewHTTPKeyResolver(signaturekey.HTTPKeyResolverConfig{
		Client: httpClient, TransportEnforcesEgress: true, Clock: clock,
		Admit: func(_ context.Context, endpoint string) error {
			if strings.HasPrefix(endpoint, blockedID+"/") {
				return errors.New("egress policy refuses " + endpoint)
			}
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	server, err := resource.NewAgentIdentity(resource.AgentIdentityConfig{
		Issuer: resourceID, KeyResolver: keyResolver, Clock: clock,
		Protected: http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(response, "records")
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	network.Handle(resourceID, server.WithResourceLink(server.Handler()))
	element, err := aauth.ResourceLinkElement(resourceID)
	if err != nil {
		t.Fatal(err)
	}
	documentation := server.WithResourceLink(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/api" {
			// An application 401 that names metadata but no AAuth requirement.
			response.WriteHeader(http.StatusUnauthorized)
			return
		}
		response.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(response, `<html><head>`+element+`
			<link rel="aauth-resource" href="https://mirror.example/.well-known/aauth-resource.json">
			<link rel="aauth-resource" href="https://blocked.example/.well-known/aauth-resource.json">
			<link rel="aauth-resource" href="https://api.example/v2/.well-known/aauth-resource.json">
			</head><body>API reference</body></html>`)
	}))
	network.Handle("https://portal.example", documentation)
	network.Handle(mirrorID, http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(response, `{"issuer":"https://api.example"}`)
	}))

	page, err := httpClient.Get(portalPage)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(page.Body)
	page.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	headerLinks := clientagent.ResourceLinksFromResponse(page)
	if len(headerLinks) != 1 || headerLinks[0].Issuer != resourceID ||
		headerLinks[0].FoundAt != portalPage || headerLinks[0].Source != clientagent.ResourceLinkFromHeader {
		t.Fatalf("Link field links = %#v", headerLinks)
	}
	htmlLinks := clientagent.ResourceLinksFromHTML(portalPage, body)
	var issuers []string
	for _, link := range htmlLinks {
		issuers = append(issuers, link.Issuer)
		if link.FoundAt != portalPage || link.Source != clientagent.ResourceLinkFromHTML {
			t.Fatalf("HTML link provenance = %#v", link)
		}
	}
	if !slices.Equal(issuers, []string{resourceID, mirrorID, blockedID}) {
		t.Fatalf("HTML link issuers = %q", issuers)
	}

	linked, err := clientagent.ResolveResourceLink(ctx, keyResolver, htmlLinks[0])
	if err != nil {
		t.Fatal(err)
	}
	if linked.Resource != resourceID || linked.Link.FoundAt != portalPage ||
		!strings.Contains(string(linked.Document), `"issuer":"https://api.example"`) {
		t.Fatalf("linked resource = %#v", linked)
	}

	_, err = clientagent.ResolveResourceLink(ctx, keyResolver, htmlLinks[1])
	var signatureFailure *signaturekey.Error
	if !errors.As(signaturekey.NormalizeError(err, signaturekey.ErrorInvalidKey), &signatureFailure) ||
		signatureFailure.Code != signaturekey.ErrorIssuerMismatch {
		t.Fatalf("metadata at another origin claiming the Resource = %v", err)
	}
	if _, err := clientagent.ResolveResourceLink(ctx, keyResolver, htmlLinks[2]); err == nil {
		t.Fatal("egress admission did not refuse the blocked target")
	}
	if recorder.requested(blockedID) {
		t.Fatal("a target refused by egress admission was fetched")
	}
	forged := clientagent.FoundResourceLink{
		ResourceLink: aauth.ResourceLink{
			Target: "https://api.example/v2/.well-known/aauth-resource.json", Issuer: resourceID,
		},
		FoundAt: portalPage, Source: clientagent.ResourceLinkFromHTML,
	}
	if _, err := clientagent.ResolveResourceLink(ctx, keyResolver, forged); err == nil {
		t.Fatal("a target of another form was resolved")
	}
	if recorder.requested(resourceID + "/v2") {
		t.Fatal("a target of another form was fetched")
	}

	// The Resource's own challenge carries both, and only AAuth-Requirement
	// states what it requires.
	challenge, err := httpClient.Get(resourceID + "/records")
	if err != nil {
		t.Fatal(err)
	}
	challenge.Body.Close()
	if challenge.StatusCode != http.StatusUnauthorized ||
		aauth.ParseAgentTokenRequirement(challenge.Header.Values("AAuth-Requirement")) != nil ||
		len(clientagent.ResourceLinksFromResponse(challenge)) != 1 {
		t.Fatalf("Resource challenge = %d %v", challenge.StatusCode, challenge.Header)
	}

	// An Agent that meets a 401 with a link and no AAuth-Requirement gets the
	// response back unchanged: the link is not a requirement to act on.
	providerKey := newSigningKey(t, "link-provider")
	agentKey := newSigningKey(t, "link-agent")
	provider, err := agentprovider.New(agentprovider.Config{
		Issuer: agentProviderID, SigningKey: providerKey, Clock: clock,
		NewID: func() string { return "link-agent-token" },
	})
	if err != nil {
		t.Fatal(err)
	}
	agentToken, err := provider.Issue(ctx, aauth.AgentTokenRequest{
		Agent: agentID, PublicKey: agentKey.PublicJWK(), Lifetime: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	reader, err := clientagent.New(ctx, clientagent.Config{
		Identifier: agentID, SigningKey: agentKey, AgentToken: agentToken,
		KeyResolver: signaturekey.StaticKeyResolver{
			{Issuer: agentProviderID, DiscoveryDocument: aauth.AgentDiscoveryDocument, KeyID: providerKey.ID()}: providerKey.PublicJWK(),
		},
		HTTPClient: httpClient, Clock: clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	call, err := http.NewRequest(http.MethodGet, "https://portal.example/api", nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := reader.CallAsAgentWithComponents(ctx, call, nil)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized || len(clientagent.ResourceLinksFromResponse(response)) != 1 {
		t.Fatalf("application response = %d %v", response.StatusCode, response.Header)
	}
}
