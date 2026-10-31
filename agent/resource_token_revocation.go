package agent

import (
	"crypto/sha256"
	"errors"
	"net/http"
	"sync"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
)

// maximumRefusedResourceTokens bounds how many withdrawn resource tokens one
// Client remembers. Past it, the one expiring soonest is forgotten.
const maximumRefusedResourceTokens = 1024

// ErrResourceTokenRevoked reports a resource token its Resource withdrew. The
// Person Server answered revoked_resource_token, which is terminal for that
// token: the Client never submits it again. Call the Resource again to obtain
// a fresh one.
var ErrResourceTokenRevoked = errors.New("resource token was withdrawn by its Resource")

// RevokedResourceTokenError is the refusal of a withdrawn resource token. It
// matches ErrResourceTokenRevoked, and *aauth.ProblemError when the Person
// Server's answer is the cause. Problem is nil when the Client refused to
// submit a token it had already seen refused.
type RevokedResourceTokenError struct {
	Problem *aauth.ProblemError
}

func (failure *RevokedResourceTokenError) Error() string {
	if failure == nil || failure.Problem == nil {
		return "aauth agent: resource token was withdrawn by its Resource and is not submitted again"
	}
	return "aauth agent: resource token was withdrawn by its Resource: " + failure.Problem.Error()
}

// Unwrap returns ErrResourceTokenRevoked and the Person Server's problem.
func (failure *RevokedResourceTokenError) Unwrap() []error {
	if failure == nil || failure.Problem == nil {
		return []error{ErrResourceTokenRevoked}
	}
	return []error{ErrResourceTokenRevoked, failure.Problem}
}

// refusedResourceTokens remembers withdrawn resource tokens by digest until
// they expire, so none is submitted again.
type refusedResourceTokens struct {
	mu      sync.Mutex
	entries map[[32]byte]time.Time
}

func newRefusedResourceTokens() *refusedResourceTokens {
	return &refusedResourceTokens{entries: make(map[[32]byte]time.Time)}
}

func (refused *refusedResourceTokens) contains(compact string, now time.Time) bool {
	refused.mu.Lock()
	defer refused.mu.Unlock()
	expiresAt, ok := refused.entries[sha256.Sum256([]byte(compact))]
	return ok && now.Before(expiresAt)
}

func (refused *refusedResourceTokens) remember(compact string, expiresAt, now time.Time) {
	refused.mu.Lock()
	defer refused.mu.Unlock()
	for digest, until := range refused.entries {
		if !now.Before(until) {
			delete(refused.entries, digest)
		}
	}
	if len(refused.entries) >= maximumRefusedResourceTokens {
		var soonest [32]byte
		var soonestAt time.Time
		for digest, until := range refused.entries {
			if soonestAt.IsZero() || until.Before(soonestAt) {
				soonest, soonestAt = digest, until
			}
		}
		delete(refused.entries, soonest)
	}
	refused.entries[sha256.Sum256([]byte(compact))] = expiresAt
}

// refuseWithdrawnResourceToken reports a resource token this Client already
// saw refused as withdrawn.
func (client *Client) refuseWithdrawnResourceToken(compact string) error {
	if client.refusedResourceTokens.contains(compact, client.clock.Now()) {
		return &RevokedResourceTokenError{}
	}
	return nil
}

// observeWithdrawnResourceToken reads a token-endpoint answer. A
// revoked_resource_token refusal is remembered and returned as an error; any
// other response is left unread for its caller.
func (client *Client) observeWithdrawnResourceToken(response *http.Response, compact string, claims aauth.ResourceTokenClaims) error {
	if response.StatusCode != http.StatusBadRequest || !isProblemResponse(response) {
		return nil
	}
	problem, ok, err := inspectAAuthProblem(response)
	if err != nil {
		_ = response.Body.Close()
		return err
	}
	if !ok || problem.Code != "revoked_resource_token" {
		return nil
	}
	_ = response.Body.Close()
	client.refusedResourceTokens.remember(compact, time.Unix(claims.ExpiresAt, 0), client.clock.Now())
	return &RevokedResourceTokenError{Problem: problem}
}
