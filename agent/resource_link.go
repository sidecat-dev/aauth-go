package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/internal/jsonstrict"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

// ResourceLinkSource says how an Agent found an aauth-resource link.
type ResourceLinkSource string

const (
	// ResourceLinkFromHeader is a Link header field of an HTTP response.
	ResourceLinkFromHeader ResourceLinkSource = "header"
	// ResourceLinkFromHTML is a link element of an HTML document.
	ResourceLinkFromHTML ResourceLinkSource = "html"
)

// FoundResourceLink is an admissible aauth-resource link together with where
// the Agent found it. A link is a statement by whoever controls the page or
// response that carried it, so keeping FoundAt lets a host tell a resource a
// third-party page introduced from one the person named.
type FoundResourceLink struct {
	aauth.ResourceLink
	// FoundAt is the URL of the response or page that carried the link, as
	// the host supplied or requested it.
	FoundAt string
	Source  ResourceLinkSource
}

// ResourceLinksFromResponse returns the admissible aauth-resource links in the
// Link fields of one response. FoundAt is the URL of the request that
// produced it. The links are discovery hints only: what the response requires
// is read from AAuth-Requirement and nothing else, and no Client method treats
// a link as a requirement.
func ResourceLinksFromResponse(response *http.Response) []FoundResourceLink {
	if response == nil {
		return nil
	}
	foundAt := ""
	if response.Request != nil && response.Request.URL != nil {
		foundAt = response.Request.URL.Redacted()
	}
	return foundResourceLinks(aauth.ResourceLinksFromHeader(response.Header.Values("Link")), foundAt, ResourceLinkFromHeader)
}

// ResourceLinksFromHTML returns the admissible aauth-resource links of the
// link elements in one HTML document fetched from pageURL. The document is
// untrusted, bounded input; see aauth.ResourceLinksFromHTML.
func ResourceLinksFromHTML(pageURL string, document []byte) []FoundResourceLink {
	return foundResourceLinks(aauth.ResourceLinksFromHTML(document), pageURL, ResourceLinkFromHTML)
}

func foundResourceLinks(links []aauth.ResourceLink, foundAt string, source ResourceLinkSource) []FoundResourceLink {
	if len(links) == 0 {
		return nil
	}
	found := make([]FoundResourceLink, len(links))
	for index, link := range links {
		found[index] = FoundResourceLink{ResourceLink: link, FoundAt: foundAt, Source: source}
	}
	return found
}

// MetadataFetcher fetches one metadata document and verifies that its issuer
// equals the URL it was fetched from minus the well-known suffix.
// *signaturekey.HTTPKeyResolver implements it with egress admission, checked
// destinations, a size bound, and no redirects.
type MetadataFetcher interface {
	FetchMetadata(ctx context.Context, issuer, document string) ([]byte, error)
}

// LinkedResource is a resource metadata document reached through an
// aauth-resource link and verified against the URL it was fetched from.
type LinkedResource struct {
	// Resource is the verified resource identifier: the document's issuer.
	Resource string
	// Link is the link that led to the document, with where it was found.
	Link FoundResourceLink
	// Document holds the exact metadata bytes.
	Document []byte
}

// ResolveResourceLink fetches the metadata document a link names and verifies
// it as any metadata document: its issuer must equal the target minus
// /.well-known/aauth-resource.json, or the result is issuer_missing or
// issuer_mismatch. A target of any other form is refused before anything is
// fetched. Reaching a resource through a link authorizes nothing: the person
// token endpoint still puts the resource to the person.
func ResolveResourceLink(ctx context.Context, fetcher MetadataFetcher, link FoundResourceLink) (LinkedResource, error) {
	const operation = "resolve resource link"
	if ctx == nil {
		return LinkedResource{}, fail(operation, errors.New("context is required"))
	}
	if fetcher == nil {
		return LinkedResource{}, fail(operation, errors.New("metadata fetcher is required"))
	}
	admitted, err := aauth.ParseResourceLinkTarget(link.Target)
	if err != nil {
		return LinkedResource{}, fail(operation, err)
	}
	if link.Issuer != "" && link.Issuer != admitted.Issuer {
		return LinkedResource{}, fail(operation, errors.New("resource link issuer does not match its target"))
	}
	link.ResourceLink = admitted
	document, err := fetcher.FetchMetadata(ctx, admitted.Issuer, aauth.ResourceDiscoveryDocument)
	if err != nil {
		return LinkedResource{}, fail(operation, signaturekey.NormalizeResolutionError(err))
	}
	// The fetcher already verified the issuer; a host-supplied fetcher may
	// not have, so the comparison is repeated on the exact bytes.
	if err := jsonstrict.RejectAmbiguousNames(document); err != nil {
		return LinkedResource{}, fail(operation, fmt.Errorf("resource metadata: %w", err))
	}
	var metadata struct {
		Issuer *string `json:"issuer"`
	}
	if err := json.Unmarshal(document, &metadata); err != nil {
		return LinkedResource{}, fail(operation, fmt.Errorf("resource metadata: %w", err))
	}
	if metadata.Issuer == nil || *metadata.Issuer == "" {
		return LinkedResource{}, fail(operation, signaturekey.NewError(
			signaturekey.ErrorIssuerMissing, errors.New("resource metadata has no issuer"),
		))
	}
	if *metadata.Issuer != admitted.Issuer {
		return LinkedResource{}, fail(operation, signaturekey.NewError(
			signaturekey.ErrorIssuerMismatch, errors.New("resource metadata issuer does not match the link target"),
		))
	}
	return LinkedResource{
		Resource: admitted.Issuer, Link: link, Document: append([]byte(nil), document...),
	}, nil
}
