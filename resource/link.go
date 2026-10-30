package resource

import (
	"net/http"

	aauth "gitlab.com/sidecat-dev/aauth-go"
)

// WithResourceLink returns a handler that adds a Link field naming this
// Resource's metadata document, with relation aauth-resource, to every
// response of next. Wrap the page at the Resource's documentation_uri, a
// developer portal, or the Resource's own Handler with it so an Agent that
// arrives there can find the metadata. The link says nothing about the
// response it rides on; requirements stay in AAuth-Requirement. For an HTML
// page, aauth.ResourceLinkElement gives the matching link element.
func (server *Server) WithResourceLink(next http.Handler) http.Handler {
	if server == nil || next == nil {
		return http.NotFoundHandler()
	}
	// Construction validated the issuer, so the value cannot fail.
	value, _ := aauth.FormatResourceLinks(server.issuer)
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Add("Link", value)
		next.ServeHTTP(response, request)
	})
}
