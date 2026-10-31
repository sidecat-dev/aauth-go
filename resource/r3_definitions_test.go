package resource

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/r3"
	"gitlab.com/sidecat-dev/aauth-go/r3/vocab/mcp"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

func TestR3RequestSpanningInternalDefinitionsGetsOneComposedDocument(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 31, 1, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	resourceKey := testSigningKey(t, "resource-key", 31)
	personKey := testSigningKey(t, "person-key", 32)
	agentKey := testSigningKey(t, "agent-key", 33)
	resolver := signaturekey.StaticKeyResolver{
		{Issuer: personIssuer, DiscoveryDocument: aauth.PersonDiscoveryDocument, KeyID: personKey.ID()}:       personKey.PublicJWK(),
		{Issuer: resourceIssuer, DiscoveryDocument: aauth.ResourceDiscoveryDocument, KeyID: resourceKey.ID()}: resourceKey.PublicJWK(),
	}
	mustDisplay := func(summary, implications, dataAccessed, irreversible string) r3.Display {
		display, err := r3.NewDisplay(summary, implications, dataAccessed, irreversible)
		if err != nil {
			t.Fatal(err)
		}
		return display
	}
	reading := R3InternalDefinition{
		Name:       "calendar.read",
		Operations: newResourceMCPOperationSet(t, "events.list", "events.get"),
		Display:    mustDisplay("Read your calendar", "", "Event titles and times", ""),
	}
	writing := R3InternalDefinition{
		Name:       "calendar.write",
		Operations: newResourceMCPOperationSet(t, "events.create"),
		Display:    mustDisplay("Create calendar events", "Invitations are sent to attendees", "Event titles and times", "Sent invitations cannot be unsent"),
	}
	store := &r3TestDocumentStore{}
	config := validConfigWithKey(resourceKey, http.NotFoundHandler())
	config.Clock = clock
	config.KeyResolver = resolver
	config.R3 = newResourceMCPConfig(
		t, store, []string{"events.list", "events.get", "events.create"},
		func(*http.Request) (string, bool, error) { return "events.list", true, nil },
	)
	config.R3.Vocabularies[0].InternalDefinitions = []R3InternalDefinition{reading, writing}
	server, err := NewFederatedAuthorization(config)
	if err != nil {
		t.Fatal(err)
	}

	authorize := func(tools ...string) r3.Document {
		t.Helper()
		operations := make([]any, len(tools))
		for index, tool := range tools {
			operations[index] = map[string]any{"tool": tool}
		}
		body, err := json.Marshal(map[string]any{
			"r3_operations": map[string]any{"vocabulary": string(mcp.URI), "operations": operations},
		})
		if err != nil {
			t.Fatal(err)
		}
		personToken := mintPersonToken(t, personKey, agentKey.PublicJWK(), now, resourceIssuer, "person-token-"+strings.Join(tools, "-"))
		request := signedRequest(t, clock, agentKey, personToken, http.MethodPost, resourceIssuer+"/authorize", string(body))
		response := httptest.NewRecorder()
		server.Handler().ServeHTTP(response, request)
		if response.Code != http.StatusOK {
			t.Fatalf("authorize %v = %d %s", tools, response.Code, response.Body.String())
		}
		var output struct {
			ResourceToken string `json:"resource_token"`
		}
		if err := json.Unmarshal(response.Body.Bytes(), &output); err != nil {
			t.Fatal(err)
		}
		_, reference, err := r3.VerifyResourceToken(context.Background(), output.ResourceToken, resolver, clock)
		if err != nil {
			t.Fatal(err)
		}
		record, err := store.Load(context.Background(), reference.URI())
		if err != nil {
			t.Fatal(err)
		}
		document, err := config.R3.Registry.ParseReferencedDocument(reference, record.ExactJSON)
		if err != nil {
			t.Fatal(err)
		}
		return document
	}

	spanning := authorize("events.get", "events.create")
	equal, err := spanning.OperationSet().Equal(newResourceMCPOperationSet(t, "events.get", "events.create"))
	if err != nil || !equal {
		t.Fatalf("composed operations = %#v, %v; want exactly the requested operations", spanning.OperationSet().Operations(), err)
	}
	display, ok := spanning.Display()
	if !ok || display.Summary() != "Read your calendar; Create calendar events" ||
		display.Implications() != "Invitations are sent to attendees" ||
		display.DataAccessed() != "Event titles and times" ||
		display.Irreversible() != "Sent invitations cannot be unsent" {
		t.Fatalf("composed display = %#v, %t", display, ok)
	}

	within := authorize("events.list")
	display, ok = within.Display()
	if !ok || display != reading.Display {
		t.Fatalf("single-definition display = %#v, %t; want that definition's display", display, ok)
	}

	config.R3.Vocabularies[0].InternalDefinitions = []R3InternalDefinition{reading}
	if _, err := NewFederatedAuthorization(config); err == nil {
		t.Fatal("internal definitions that leave an operation uncovered were accepted")
	}
}
