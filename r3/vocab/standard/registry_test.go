package standard_test

import (
	"testing"

	"gitlab.com/sidecat-dev/aauth-go/r3"
	"gitlab.com/sidecat-dev/aauth-go/r3/vocab/asyncapi"
	"gitlab.com/sidecat-dev/aauth-go/r3/vocab/graphql"
	"gitlab.com/sidecat-dev/aauth-go/r3/vocab/grpc"
	"gitlab.com/sidecat-dev/aauth-go/r3/vocab/mcp"
	"gitlab.com/sidecat-dev/aauth-go/r3/vocab/odata"
	"gitlab.com/sidecat-dev/aauth-go/r3/vocab/openapi"
	"gitlab.com/sidecat-dev/aauth-go/r3/vocab/standard"
	"gitlab.com/sidecat-dev/aauth-go/r3/vocab/wsdl"
)

func TestRegistryContainsEveryStandardVocabularyExactlyOnce(t *testing.T) {
	registry := standard.Registry()
	if registry.Len() != 7 {
		t.Fatalf("registry length = %d", registry.Len())
	}
	for _, uri := range []r3.VocabularyURI{
		mcp.URI, openapi.URI, grpc.URI, graphql.URI,
		asyncapi.URI, wsdl.URI, odata.URI,
	} {
		if _, ok := registry.Vocabulary(uri); !ok {
			t.Fatalf("registry is missing %s", uri)
		}
	}
}

func TestDefinitionRegistryContainsEveryStandardVocabularyExactlyOnce(t *testing.T) {
	registry := standard.Definitions()
	if registry.Len() != 7 {
		t.Fatalf("definition registry length = %d", registry.Len())
	}
	for _, uri := range []r3.VocabularyURI{
		mcp.URI, openapi.URI, grpc.URI, graphql.URI,
		asyncapi.URI, wsdl.URI, odata.URI,
	} {
		if !registry.Contains(uri) {
			t.Fatalf("definition registry is missing %s", uri)
		}
	}
}

func TestEveryStandardVocabularyUsesTheHTTPSDiscoveryEndpointProfile(t *testing.T) {
	t.Parallel()

	registry := standard.Registry()
	for _, uri := range []r3.VocabularyURI{
		mcp.URI, openapi.URI, grpc.URI, graphql.URI,
		asyncapi.URI, wsdl.URI, odata.URI,
	} {
		vocabulary, ok := registry.Vocabulary(uri)
		if !ok {
			t.Fatalf("registry is missing %s", uri)
		}
		t.Run(string(uri), func(t *testing.T) {
			t.Parallel()
			if err := vocabulary.ValidateDiscoveryEndpoint("https://resource.example/definition?version=current"); err != nil {
				t.Fatalf("HTTPS discovery URI with query was refused: %v", err)
			}
			if err := vocabulary.ValidateDiscoveryEndpoint("HTTPS://RESOURCE.EXAMPLE/definition"); err != nil {
				t.Fatalf("case-insensitive HTTPS scheme was refused: %v", err)
			}
			for _, endpoint := range []string{
				"",
				" https://resource.example/definition",
				"https://resource.example/definition ",
				string([]byte{'h', 't', 't', 'p', 's', ':', '/', '/', 0xff}),
				"/relative/definition",
				"http://resource.example/definition",
				"https:opaque-definition",
				"https:///definition-without-host",
				"https://user@resource.example/definition",
				"https://resource.example/definition#section",
			} {
				if err := vocabulary.ValidateDiscoveryEndpoint(endpoint); err == nil {
					t.Fatalf("invalid discovery endpoint %q was accepted", endpoint)
				}
			}
		})
	}
}
