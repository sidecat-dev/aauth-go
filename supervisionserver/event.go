package supervisionserver

import (
	"context"
	"errors"
	"net/http"
	"time"

	"gitlab.com/sidecat-dev/aauth-go/supervision"
)

// Observation is one event or mission report the SS is about to
// acknowledge; exactly one of Event and Report is set. Body is the exact
// request body. A standing policy learns from it: a decision.resolved event
// carries what the person decided after an ask and the reach, apply, they
// gave their answer, which the SS then applies to later acts.
type Observation struct {
	Connection Connection
	Event      *supervision.Event
	Report     *supervision.Report
	Body       []byte
	ReceivedAt time.Time
}

func (server *Server) handleEvent(response http.ResponseWriter, request *http.Request) {
	personServer, _, body, ok := server.authenticate(response, request, true)
	if !ok || !server.admit(response, request, personServer) {
		return
	}
	event, err := supervision.DecodeEvent(body)
	if err != nil {
		writeProblem(response, supervision.ErrorInvalidRequest, err)
		return
	}
	connection, ok := server.requireConnection(response, request, personServer, event.Subject)
	if !ok {
		return
	}
	// An event about a mission needs the mission, so the Person Server
	// replays it first; and the mission must be the event's Agent's.
	if event.MissionS256 != "" {
		mission, ok := server.loadMission(response, request, personServer, event.Subject, event.MissionS256)
		if !ok {
			return
		}
		if mission.Agent != event.Agent {
			writeProblem(response, supervision.ErrorInvalidRequest, errors.New("supervisionserver: the event's mission is another agent's"))
			return
		}
	}
	server.deliver(response, request, connection, event.ID, body, nil, Observation{Event: &event})
}

// handleReport records an approved mission's exact blob, or marks a mission
// ended. A termination of a mission the SS never held records nothing about
// the mission and is still acknowledged.
func (server *Server) handleReport(response http.ResponseWriter, request *http.Request, personServer string, body []byte, report supervision.Report) {
	connection, ok := server.requireConnection(response, request, personServer, report.Subject)
	if !ok {
		return
	}
	apply := func(ctx context.Context, now time.Time) error {
		if report.Action == supervision.ReportApproved {
			return server.store.PutMission(ctx, MissionRecord{
				PersonServer: personServer, Subject: report.Subject, Agent: report.Agent,
				S256: report.MissionS256, Blob: append([]byte(nil), report.Mission...),
				SDI: report.SDI, ApprovedAt: now,
			})
		}
		err := server.store.TerminateMission(ctx, personServer, report.Subject, report.MissionS256, report.Reason, now)
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		return err
	}
	server.deliver(response, request, connection, report.ID, body, apply, Observation{Report: &report})
}

// deliver acknowledges one event or report once per (iss, id). A repeat
// answers 201 and records nothing new. A first delivery applies its effect,
// shows it to the observer, and is then recorded; any failure before the
// record answers server_error so the Person Server delivers it again.
func (server *Server) deliver(
	response http.ResponseWriter,
	request *http.Request,
	connection Connection,
	id string,
	body []byte,
	apply func(context.Context, time.Time) error,
	observation Observation,
) {
	ctx := request.Context()
	if _, err := server.store.LoadDelivery(ctx, connection.PersonServer, id); err == nil {
		writeCreated(response)
		return
	} else if !errors.Is(err, ErrNotFound) {
		writeProblem(response, supervision.ErrorServerError, err)
		return
	}
	now := server.clock.Now().UTC()
	if apply != nil {
		if err := apply(ctx, now); err != nil {
			writeProblem(response, supervision.ErrorServerError, err)
			return
		}
	}
	if server.observe != nil {
		observation.Connection = connection
		observation.Body = append([]byte(nil), body...)
		observation.ReceivedAt = now
		if err := server.observe(ctx, observation); err != nil {
			writeProblem(response, supervision.ErrorServerError, err)
			return
		}
	}
	err := server.store.RecordDelivery(ctx, Delivery{
		PersonServer: connection.PersonServer, ID: id, Body: append([]byte(nil), body...), ReceivedAt: now,
	})
	if err != nil && !errors.Is(err, ErrConflict) {
		writeProblem(response, supervision.ErrorServerError, err)
		return
	}
	writeCreated(response)
}

func writeCreated(response http.ResponseWriter) {
	response.Header().Set("Cache-Control", "no-store")
	response.WriteHeader(http.StatusCreated)
}
