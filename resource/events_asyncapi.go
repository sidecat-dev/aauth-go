package resource

import (
	"errors"
	"net/http"
	"strconv"

	"gitlab.com/sidecat-dev/aauth-go/internal/httpapi"
)

// AsyncAPIHandler serves the exact AsyncAPI document configured in
// EventServiceConfig.AsyncAPIDocument, which NewEventService has checked
// declares the aauth_subscribe security scheme. The host mounts it at the
// path it advertises, such as the urn:aauth:vocabulary:asyncapi entry of its
// r3_vocabularies metadata. Without a configured document it returns a
// not-found handler.
func (service *EventService) AsyncAPIHandler() http.Handler {
	if service == nil || len(service.asyncAPIDocument) == 0 {
		return http.NotFoundHandler()
	}
	return http.HandlerFunc(service.serveAsyncAPIDocument)
}

func (service *EventService) serveAsyncAPIDocument(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet && request.Method != http.MethodHead {
		response.Header().Set("Allow", "GET, HEAD")
		httpapi.WriteProblem(response, http.StatusMethodNotAllowed, "invalid_request", errors.New("resource: AsyncAPI document requires GET"))
		return
	}
	response.Header().Set("Content-Type", "application/json")
	response.Header().Set("Content-Length", strconv.Itoa(len(service.asyncAPIDocument)))
	response.WriteHeader(http.StatusOK)
	if request.Method == http.MethodHead {
		return
	}
	_, _ = response.Write(service.asyncAPIDocument)
}
