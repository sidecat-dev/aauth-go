package reference

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"net/http"
	"testing"

	aauth "gitlab.com/sidecat-dev/aauth-go"
)

func testResourceReplayStore(t *testing.T, clock aauth.Clock) ProofReplayStore {
	t.Helper()
	store, err := NewMemoryProofReplayStore(clock, 1024)
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func testAuthorizationStateStore(t *testing.T) AuthorizationStateStore {
	t.Helper()
	store, err := NewMemoryAuthorizationStateStore(1024, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func testRequiredResourceScopes(scopes ...string) func(context.Context, *http.Request) ([]string, error) {
	return func(context.Context, *http.Request) ([]string, error) {
		return append([]string(nil), scopes...), nil
	}
}

func testProtectedAuthorizationPolicy(context.Context, aauth.AuthorizedRequest) error {
	return nil
}

func referenceTestSigningKey(t *testing.T, id string) jose.SigningKey {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := jose.NewEd25519SigningKey(id, private)
	if err != nil {
		t.Fatal(err)
	}
	return key
}
