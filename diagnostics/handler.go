// Package diagnostics exposes local causes of AAuth role HTTP problems without
// placing private diagnostics in protocol responses. It owns no protocol state.
package diagnostics

import (
	"context"
	"net/http"
)

// Problem describes one role-generated problem response. Code is the AAuth
// JSON error code, which may differ from the Signature-Error code. Cause is the
// original error, preserving errors.Is and errors.As and potentially containing
// private host data. The host chooses which fields to retain or redact.
type Problem struct {
	Status int
	Code   string
	Cause  error
}

// Handler observes problems emitted by an AAuth role handler. Wrap the role's
// Handler directly, including standalone enrollment or Events handlers. It does
// not observe ordinary application responses or errors returned by non-HTTP APIs.
//
// observe runs synchronously after each problem is written, with that request's
// context and original cause. It must be safe for concurrent requests and should
// return promptly. No request headers, token, body or URL are added to Problem.
// A nil observer returns next unchanged.
//
// The wrapper preserves the standard optional ResponseWriter interfaces and
// supports http.ResponseController through Unwrap. Custom writer interfaces
// are not preserved. Protocol responses are neither buffered nor changed.
func Handler(next http.Handler, observe func(context.Context, Problem)) http.Handler {
	if observe == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(wrapWriter(w, &observerWriter{ResponseWriter: w, ctx: r.Context(), observe: observe}), r)
	})
}

type observerWriter struct {
	http.ResponseWriter
	ctx     context.Context
	observe func(context.Context, Problem)
}

func (w *observerWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// FlushError lets ResponseController preserve an underlying transport error
// instead of selecting the separately preserved, errorless Flusher interface.
func (w *observerWriter) FlushError() error {
	return http.NewResponseController(w.ResponseWriter).Flush()
}

// ReportAAuthProblem is the role serializer's local diagnostic sink.
func (w *observerWriter) ReportAAuthProblem(status int, code string, cause error) {
	w.observe(w.ctx, Problem{Status: status, Code: code, Cause: cause})
}

//go:generate go run ./internal/genwriter
