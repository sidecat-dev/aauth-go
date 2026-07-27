package aauth_test

import (
	"testing"

	aauth "gitlab.com/sidecat-dev/aauth-go"
)

const missionGoldenBytes = `{"approver":"https://ps.sidecat.example","agent":"aauth:planner@agent.sidecat.example","approved_at":"2026-07-23T00:00:00Z","description":"# Golden Surface 1 vector\n\nA fixed mission blob whose bytes are pinned so any AAuth implementation can check its s256 without a live PS. The bytes are authoritative: do not reformat this file.","approved_tools":[{"name":"WebSearch","description":"Search the web"},{"name":"Read","description":"Read files and web pages"}],"capabilities":["interaction"]}`

// This vector is shared with the independent Sidecat BEAM implementation and
// was also checked with openssl. It prevents two implementations from agreeing
// only because they share the same hashing mistake.
func TestMissionS256MatchesCrossImplementationGoldenVector(t *testing.T) {
	t.Parallel()

	bytes := []byte(missionGoldenBytes)
	if got, want := len(bytes), 494; got != want {
		t.Fatalf("mission vector length = %d, want %d; exact bytes changed", got, want)
	}
	if got, want := aauth.S256(bytes), "BfRh7oG2j02gOpwgQ1Vlu4NglGdJ-ZL-6vhGqXrTCpA"; got != want {
		t.Fatalf("mission s256 = %q, want %q", got, want)
	}

	tampered := append([]byte(nil), bytes...)
	tampered[len(tampered)-1] ^= 1
	if aauth.S256(tampered) == aauth.S256(bytes) {
		t.Fatal("one-bit mission mutation did not change s256")
	}
}
