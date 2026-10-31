package personserver

import (
	"errors"
	"fmt"

	aauth "gitlab.com/sidecat-dev/aauth-go"
)

// interactionCallbackURL returns the redirect for a correlated interaction:
// callback itself when failure is empty, callback?error={failure} otherwise,
// or an empty string when the person arrived without a callback.
func interactionCallbackURL(correlated bool, callback string, failure aauth.InteractionCallbackError) (string, error) {
	if !correlated {
		return "", errors.New("personserver: correlated interaction is required")
	}
	if failure != "" && !failure.Valid() {
		return "", fmt.Errorf("personserver: interaction callback error %q is not registered", string(failure))
	}
	if callback == "" {
		return "", nil
	}
	return aauth.InteractionCallbackURL(callback, failure)
}

// validateRetainedCallback checks a callback a store returned: one is
// retained only once a code was consumed, and it must still be a callback
// aauth.ValidateInteractionCallback accepts.
func validateRetainedCallback(callback string, codeUnconsumed bool) error {
	if callback == "" {
		return nil
	}
	if codeUnconsumed {
		return errors.New("personserver: a callback is retained before its code was consumed")
	}
	return aauth.ValidateInteractionCallback(callback, true)
}
