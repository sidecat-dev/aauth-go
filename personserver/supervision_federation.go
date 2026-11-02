package personserver

import (
	"context"
	"errors"
	"net/http"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/internal/httpapi"
	"gitlab.com/sidecat-dev/aauth-go/supervision"
)

// awaitsAccessServer reports whether completing an allowed auth-token
// request left it waiting for the Access Server: the completion answered 202
// and a wait was retained under the request's own reference.
func (server *Server) awaitsAccessServer(ctx context.Context, record SupervisedRequest, retained SupervisedResponse) bool {
	if record.Kind != supervision.KindAuthToken || retained.Status != http.StatusAccepted || server.federatedDeferred == nil {
		return false
	}
	_, err := server.FederatedAuthorization(ctx, record.Reference)
	return err == nil
}

// relaySupervisedFederation serves the Agent's pending URL for a request that
// waits for the Access Server after its supervisor or the person allowed it.
// A poll and a cancellation act on the wait as at its own URL, and a pending
// answer keeps naming this URL, so the Agent polls one URL throughout. Once
// the wait answers terminally the supervised request is gone.
func (server *Server) relaySupervisedFederation(response http.ResponseWriter, request *http.Request, agent aauth.AgentTokenClaims, record SupervisedRequest) {
	if !requestBodyIsEmpty(request) {
		writeProblem(response, http.StatusBadRequest, "invalid_request", errors.New("personserver: a request waiting for the Access Server takes a bodyless GET or DELETE"))
		return
	}
	relayed := newFederatedResponseBuffer()
	switch request.Method {
	case http.MethodGet:
		server.pollFederatedAuthorization(relayed, request, agent, record.Reference)
	case http.MethodDelete:
		server.cancelFederatedAuthorization(relayed, request, agent, record.Reference)
	default:
		response.Header().Set("Allow", "GET, DELETE")
		writeProblem(response, http.StatusMethodNotAllowed, "method_not_allowed", errors.New("personserver: a request waiting for the Access Server takes GET or DELETE"))
		return
	}
	if relayed.status == http.StatusAccepted {
		relayed.header.Set("Location", supervisionPendingPath+record.Reference)
	} else {
		after := cloneSupervisedRequest(record)
		after.State = SupervisedGone
		after.Revision++
		// The wait is consumed already; a lost race leaves nothing to undo.
		_ = server.supervision.store.ReplaceSupervisedRequest(request.Context(), record, after)
	}
	relayed.send(response)
	if relayed.refusalReason != "" {
		httpapi.ReportProblem(response, relayed.status, "server_error", &DeferredCompositionError{reason: relayed.refusalReason})
	}
}

// awaitsResourceInteraction reports whether completing an allowed auth-token
// request began the Resource's own interaction: the completion answered 202,
// and a pending authorization under the request's own reference waits for
// the person under this request's decision.
func (server *Server) awaitsResourceInteraction(ctx context.Context, record SupervisedRequest) bool {
	if record.Kind != supervision.KindAuthToken || record.Response == nil || record.Response.Status != http.StatusAccepted ||
		server.authorizationInteractions == nil {
		return false
	}
	snapshot, err := server.authorizationInteractions.LoadPendingAuthorization(ctx, record.Reference, server.clock.Now().UTC())
	return err == nil && snapshot.Record.Supervision.SDI == record.SDI && snapshot.Record.Agent == record.Agent
}

// relaySupervisedResourceInteraction serves the Agent's pending URL for a
// request that waits for the Resource's own interaction after its
// supervisor or the person allowed it. Polls and a cancellation act on the
// pending authorization, which has this request's reference, as at its own
// URL, and a pending answer names this URL, so the Agent polls one URL
// throughout. Once the pending authorization is consumed the supervised
// request is gone.
func (server *Server) relaySupervisedResourceInteraction(response http.ResponseWriter, request *http.Request, record SupervisedRequest) {
	relayed := &supervisedRecorder{header: http.Header{}}
	server.handlePendingAuthorization(relayed, request)
	answer := relayed.result()
	if answer.Status != http.StatusAccepted {
		snapshot, err := server.authorizationInteractions.LoadPendingAuthorization(request.Context(), record.Reference, server.clock.Now().UTC())
		if err != nil || snapshot.State == AuthorizationPollGone {
			after := cloneSupervisedRequest(record)
			after.State = SupervisedGone
			after.Revision++
			// The pending authorization is consumed already; a lost race
			// leaves nothing to undo.
			_ = server.supervision.store.ReplaceSupervisedRequest(request.Context(), record, after)
		}
	}
	writeSupervisedResponse(response, answer)
}
