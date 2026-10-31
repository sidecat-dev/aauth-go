// Package supervision implements the wire values of AAuth Supervision, the
// interface between a Person Server and a supervision server (SS) that decides
// on the person's behalf, and the Person Server's client for it.
//
// A Person Server with an SS configured for an Agent makes no supervision
// decision of its own for that Agent. It puts every mission proposal, update
// and completion, and every person-token, auth-token and permission request,
// to the Agent's deciding SS; it acts on the SS's allow, deny or ask; and it
// tells the SS what happened through events. The SS never calls the Person
// Server: everything it has to say is a response.
//
// This package owns the metadata document, the signed request envelope and
// its bodies, decisions, deferred and clarification responses, events,
// errors, and the HTTP Message Signature profile of a signed decision.
// [Client] makes the Person Server's signed requests and verifies what comes
// back. The personserver package composes it, and the supervisionserver
// package implements the SS role. Neither role imports the other.
package supervision
