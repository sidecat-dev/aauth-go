package aauth

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// InteractionCallbackError is the error query parameter an interaction host
// adds to a callback URL when the interaction cannot be completed (Core,
// Interaction Callback Errors). It implements error, so a callback recipient
// can surface it to its caller unchanged.
type InteractionCallbackError string

const (
	// InteractionCallbackAccessDenied reports that the person declined.
	InteractionCallbackAccessDenied InteractionCallbackError = "access_denied"
	// InteractionCallbackUserAbandoned reports that the person opened the
	// interaction but did not complete it.
	InteractionCallbackUserAbandoned InteractionCallbackError = "user_abandoned"
	// InteractionCallbackServerError reports an internal failure at the party
	// handling the interaction.
	InteractionCallbackServerError InteractionCallbackError = "server_error"
	// InteractionCallbackTemporarilyUnavailable reports that the interaction
	// service is temporarily unavailable. The caller may retry.
	InteractionCallbackTemporarilyUnavailable InteractionCallbackError = "temporarily_unavailable"
	// InteractionCallbackInteractionExpired reports that the interaction
	// session expired before the person completed it.
	InteractionCallbackInteractionExpired InteractionCallbackError = "interaction_expired"
)

// Error returns the registered error value.
func (value InteractionCallbackError) Error() string {
	return "aauth: interaction callback error " + string(value)
}

// Valid reports whether value is one of the five registered callback errors.
func (value InteractionCallbackError) Valid() bool {
	switch value {
	case InteractionCallbackAccessDenied, InteractionCallbackUserAbandoned, InteractionCallbackServerError,
		InteractionCallbackTemporarilyUnavailable, InteractionCallbackInteractionExpired:
		return true
	}
	return false
}

// PollingError returns the polling error a pending request ends with when
// its interaction ended with value: denied for access_denied, abandoned for
// user_abandoned, expired for interaction_expired, and server_error for
// server_error, temporarily_unavailable and any unregistered value.
func (value InteractionCallbackError) PollingError() ErrorCode {
	switch value {
	case InteractionCallbackAccessDenied:
		return "denied"
	case InteractionCallbackUserAbandoned:
		return "abandoned"
	case InteractionCallbackInteractionExpired:
		return "expired"
	default:
		return "server_error"
	}
}

// InteractionCallbackErrorFor returns the callback error that reports a
// pending request ended with the polling error code: access_denied for
// denied, user_abandoned for abandoned, interaction_expired for expired, and
// server_error for anything else.
func InteractionCallbackErrorFor(code ErrorCode) InteractionCallbackError {
	switch code {
	case "denied":
		return InteractionCallbackAccessDenied
	case "abandoned":
		return InteractionCallbackUserAbandoned
	case "expired":
		return InteractionCallbackInteractionExpired
	default:
		return InteractionCallbackServerError
	}
}

// InteractionVisit is what an interaction URL receives in its query: the
// interaction code and, when the party that sent the person has a browser
// flow of its own, the callback URL to return the person to.
type InteractionVisit struct {
	Code     string
	Callback string
}

// InteractionVisitOptions selects what ParseInteractionVisit accepts.
type InteractionVisitOptions struct {
	// AllowLoopbackCallback accepts an http://localhost or http://127.0.0.1
	// callback. An Agent may send one only when its Agent Provider metadata
	// sets localhost_callback_allowed, so leave this false unless the host
	// has checked that metadata for the requesting Agent.
	AllowLoopbackCallback bool
}

// ParseInteractionVisit reads the code and optional callback from the raw
// query of a request to an interaction URL, as sent by an Agent or by a
// Person Server: {url}?code={code}&callback={callback}. It does not judge the
// code: pass it to the role that issued it, which counts a malformed code as
// a failed attempt. A missing or repeated code, a repeated callback, or a
// callback that is not an HTTPS URL without query or fragment is refused.
// Other query members are ignored.
func ParseInteractionVisit(rawQuery string, options InteractionVisitOptions) (InteractionVisit, error) {
	values, err := url.ParseQuery(rawQuery)
	if err != nil {
		return InteractionVisit{}, fmt.Errorf("aauth: interaction query: %w", err)
	}
	codes := values["code"]
	if len(codes) != 1 || codes[0] == "" {
		return InteractionVisit{}, errors.New("aauth: interaction query requires exactly one code")
	}
	visit := InteractionVisit{Code: codes[0]}
	callbacks := values["callback"]
	switch len(callbacks) {
	case 0:
	case 1:
		if err := ValidateInteractionCallback(callbacks[0], options.AllowLoopbackCallback); err != nil {
			return InteractionVisit{}, err
		}
		visit.Callback = callbacks[0]
	default:
		return InteractionVisit{}, errors.New("aauth: interaction query repeats callback")
	}
	return visit, nil
}

// ValidateInteractionCallback checks a callback URL before an interaction
// host redirects to it. A callback is an absolute HTTPS URL with a lowercase
// host and no userinfo, query or fragment, so that an error can be appended
// as its only query. With allowLoopback, http://localhost and
// http://127.0.0.1 with any port are also accepted.
func ValidateInteractionCallback(callback string, allowLoopback bool) error {
	if callback == "" {
		return errors.New("aauth: interaction callback is empty")
	}
	if allowLoopback && isLoopbackCallback(callback) {
		return nil
	}
	if err := ValidateEndpoint(callback); err != nil {
		return fmt.Errorf("aauth: interaction callback: %w", err)
	}
	return nil
}

func isLoopbackCallback(callback string) bool {
	if strings.Contains(callback, "#") {
		return false
	}
	parsed, err := url.Parse(callback)
	if err != nil || parsed.Scheme != "http" || parsed.User != nil ||
		parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" {
		return false
	}
	host := parsed.Hostname()
	return host == "localhost" || host == "127.0.0.1"
}

// FormatInteractionVisitURL returns the user-facing URL for an interaction:
// {url}?code={code}, with &callback={callback} when callback is not empty.
// An Agent uses it to direct the person with its own callback; a Person
// Server uses it to send the person to a Resource's interaction with its
// per-flow callback. url must be HTTPS without query or fragment, code an
// emitted interaction code, and callback a URL ValidateInteractionCallback
// accepts with loopback allowed.
func FormatInteractionVisitURL(interactionURL, code, callback string) (string, error) {
	if err := validateInteractionURL(interactionURL); err != nil {
		return "", fmt.Errorf("aauth: interaction url: %w", err)
	}
	if err := validateEmittedInteractionCode(code); err != nil {
		return "", err
	}
	target := interactionURL + "?code=" + escapeInteractionComponent(code)
	if callback != "" {
		if err := ValidateInteractionCallback(callback, true); err != nil {
			return "", err
		}
		target += "&callback=" + escapeInteractionComponent(callback)
	}
	return target, nil
}

// InteractionCallbackURL returns where an interaction host sends the person
// when the interaction ends: callback itself when failure is empty, or
// {callback}?error={failure} when the interaction cannot be completed.
// failure must be empty or one of the registered callback errors.
func InteractionCallbackURL(callback string, failure InteractionCallbackError) (string, error) {
	if err := ValidateInteractionCallback(callback, true); err != nil {
		return "", err
	}
	if failure == "" {
		return callback, nil
	}
	if !failure.Valid() {
		return "", fmt.Errorf("aauth: interaction callback error %q is not registered", string(failure))
	}
	return callback + "?error=" + string(failure), nil
}

// ReadInteractionCallback reads the raw query a callback URL received. It
// returns nil when the interaction completed and an InteractionCallbackError
// when the query carries error. The recipient must then not treat the pending
// request as completable and must surface the error to its caller. An
// unregistered or repeated error value, or a query that cannot be parsed, is
// reported as server_error.
func ReadInteractionCallback(rawQuery string) error {
	if rawQuery == "" {
		return nil
	}
	values, err := url.ParseQuery(rawQuery)
	if err != nil {
		return InteractionCallbackServerError
	}
	failures, present := values["error"]
	if !present {
		return nil
	}
	if len(failures) != 1 {
		return InteractionCallbackServerError
	}
	failure := InteractionCallbackError(failures[0])
	if !failure.Valid() {
		return InteractionCallbackServerError
	}
	return failure
}

// escapeInteractionComponent percent-encodes every byte outside the RFC 3986
// unreserved set, so a space is %20 and never "+".
func escapeInteractionComponent(value string) string {
	const hex = "0123456789ABCDEF"
	var builder strings.Builder
	for index := 0; index < len(value); index++ {
		character := value[index]
		switch {
		case character >= 'A' && character <= 'Z', character >= 'a' && character <= 'z',
			character >= '0' && character <= '9', character == '-', character == '.', character == '_', character == '~':
			builder.WriteByte(character)
		default:
			builder.WriteByte('%')
			builder.WriteByte(hex[character>>4])
			builder.WriteByte(hex[character&15])
		}
	}
	return builder.String()
}
