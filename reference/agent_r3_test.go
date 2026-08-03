package reference

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
)

func TestAgentRefusesPerCallTokenThatDoesNotDirectlyGrantExactProposalOperation(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 2, 20, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	accessKey := agentR3TestSigningKey(t, "access-key")
	agentKey := agentR3TestSigningKey(t, "agent-key")
	approved := aauth.R3OperationSet{
		Vocabulary: aauth.R3VocabularyMCP,
		Operations: []json.RawMessage{json.RawMessage(`{"tool":"send_message"}`)},
	}
	other := aauth.R3OperationSet{
		Vocabulary: aauth.R3VocabularyMCP,
		Operations: []json.RawMessage{json.RawMessage(`{"tool":"delete_message"}`)},
	}
	empty := aauth.R3OperationSet{
		Vocabulary: aauth.R3VocabularyMCP,
		Operations: []json.RawMessage{},
	}
	mission := &aauth.MissionReference{
		Approver: "https://ps.example",
		S256:     aauth.R3S256([]byte("approved mission")),
	}
	digest := aauth.R3S256([]byte("exact proposal"))
	resourceGrant := ResourceGrant{
		Resource: "https://resource.example",
		Claims: aauth.ResourceTokenClaims{
			Issuer:   "https://resource.example",
			Audience: "https://as.example",
			JTI:      "proposal-resource-token",
			Agent:    "aauth:messenger@ap.example",
			Scope:    "messages.send",
			Mission:  mission,
			R3URI:    "https://resource.example/r3/proposals/" + digest,
			R3S256:   digest,
		},
		RequestedR3: &approved,
		R3Proposal:  true,
	}
	agent := &Agent{
		keyResolver: aauth.StaticKeyResolver{
			"https://as.example": {"access-key": accessKey.PublicJWK()},
		},
		clock: clock,
	}

	parse := func(granted, conditional *aauth.R3OperationSet) error {
		t.Helper()
		compact, err := aauth.MintAuthToken(accessKey, aauth.AuthTokenClaims{
			Issuer:        "https://as.example",
			DWK:           aauth.AccessDiscoveryDocument,
			Audience:      "https://resource.example",
			JTI:           "per-call-auth-token",
			Agent:         "aauth:messenger@ap.example",
			Confirmation:  aauth.Confirmation{JWK: agentKey.PublicJWK()},
			IssuedAt:      now.Unix(),
			ExpiresAt:     now.Add(5 * time.Minute).Unix(),
			Subject:       "pairwise-user",
			Scope:         "messages.send",
			Mission:       mission,
			R3URI:         resourceGrant.Claims.R3URI,
			R3S256:        digest,
			R3Granted:     granted,
			R3Conditional: conditional,
		})
		if err != nil {
			return err
		}
		body, err := json.Marshal(map[string]string{"auth_token": compact})
		if err != nil {
			return err
		}
		_, err = agent.parseTokenGrantResponse(
			context.Background(),
			&http.Response{Body: io.NopCloser(bytes.NewReader(body))},
			resourceGrant,
			"https://as.example",
			"aauth:messenger@ap.example",
			agentKey.PublicJWK(),
			nil,
		)
		return err
	}

	if err := parse(&approved, nil); err != nil {
		t.Fatalf("exact direct per-call token was refused: %v", err)
	}
	if err := parse(&empty, &approved); err == nil {
		t.Fatal("recursive conditional per-call token was accepted")
	}
	if err := parse(&other, nil); err == nil {
		t.Fatal("different-operation per-call token was accepted")
	}
}

func TestAgentAuthorizedCallRequiresMediaTypeForBody(t *testing.T) {
	t.Parallel()

	agent := &Agent{}
	_, err := agent.DoAuthorizedRequest(
		context.Background(),
		AuthorizedCall{
			Method:   http.MethodPost,
			Endpoint: "https://resource.example/messages",
			Body:     []byte(`{"body":"approved bytes"}`),
		},
		Grant{Resource: "https://resource.example", AuthToken: "opaque"},
	)
	if err == nil {
		t.Fatal("authorized request body without media type was accepted")
	}
}

func TestAgentRefusesProposalStageWithMismatchedDigestPath(t *testing.T) {
	t.Parallel()

	requested := aauth.R3OperationSet{
		Vocabulary: aauth.R3VocabularyMCP,
		Operations: []json.RawMessage{json.RawMessage(`{"tool":"send_message"}`)},
	}
	grant := ResourceGrant{
		Resource: "https://resource.example",
		Claims: aauth.ResourceTokenClaims{
			R3URI:  "https://resource.example/r3/proposals/other-digest",
			R3S256: "approved-digest",
		},
		RequestedR3: &requested,
		R3Proposal:  true,
	}
	if err := validateResourceGrantR3Request(grant); err == nil {
		t.Fatal("proposal stage with mismatched digest path was accepted")
	}
}

func agentR3TestSigningKey(t *testing.T, id string) aauth.SigningKey {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := aauth.NewEd25519SigningKey(id, private)
	if err != nil {
		t.Fatal(err)
	}
	return key
}
