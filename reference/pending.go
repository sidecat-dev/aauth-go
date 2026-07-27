package reference

import (
	"crypto/subtle"
	"errors"
	"io"
	"net/http"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
)

type pendingAuthorizationState string

const (
	pendingAuthorizationWaiting     pendingAuthorizationState = "pending"
	pendingAuthorizationInteracting pendingAuthorizationState = "interacting"
	pendingAuthorizationApproved    pendingAuthorizationState = "approved"
	pendingAuthorizationRejected    pendingAuthorizationState = "rejected"
	pendingAuthorizationExpired     pendingAuthorizationState = "expired"
	pendingAuthorizationInvalidCode pendingAuthorizationState = "invalid_code"
	pendingAuthorizationServed      pendingAuthorizationState = "served"
)

const maxInteractionCodeAttempts = 3

type pendingInteraction struct {
	id                 string
	code               string
	normalizedCode     string
	codeConsumed       bool
	failedCodeAttempts int
	state              pendingAuthorizationState
	pollingError       aauth.PollingErrorCode
	expiresAt          time.Time
}

func newPendingInteraction(random io.Reader, expiresAt time.Time) (pendingInteraction, error) {
	pendingID, err := aauth.GeneratePendingID(random)
	if err != nil {
		return pendingInteraction{}, err
	}
	code, err := aauth.GenerateInteractionCode(random)
	if err != nil {
		return pendingInteraction{}, err
	}
	normalizedCode, err := aauth.NormalizeInteractionCode(code)
	if err != nil {
		return pendingInteraction{}, err
	}
	return pendingInteraction{
		id:             pendingID,
		code:           code,
		normalizedCode: normalizedCode,
		state:          pendingAuthorizationWaiting,
		expiresAt:      expiresAt,
	}, nil
}

func (pending *pendingInteraction) correlate(
	codeValues []string,
	now time.Time,
) (int, string, error) {
	if !pending.expiresAt.After(now) {
		pending.state = pendingAuthorizationExpired
		return http.StatusRequestTimeout, "expired", errors.New("pending interaction expired")
	}
	if pending.codeConsumed || pending.state != pendingAuthorizationWaiting {
		return http.StatusGone, "invalid_code", errors.New("interaction code is already consumed")
	}
	var normalizedCode string
	var err error
	if len(codeValues) != 1 {
		err = errors.New("interaction requires exactly one code")
	} else {
		normalizedCode, err = aauth.NormalizeInteractionCode(codeValues[0])
	}
	if err != nil ||
		subtle.ConstantTimeCompare([]byte(normalizedCode), []byte(pending.normalizedCode)) != 1 {
		pending.failedCodeAttempts++
		if pending.failedCodeAttempts >= maxInteractionCodeAttempts {
			pending.state = pendingAuthorizationInvalidCode
			return http.StatusGone, "invalid_code", errors.New("interaction code attempt limit reached")
		}
		return http.StatusBadRequest, "invalid_code", errors.New("interaction code is invalid")
	}
	pending.codeConsumed = true
	pending.state = pendingAuthorizationInteracting
	return http.StatusOK, "", nil
}
