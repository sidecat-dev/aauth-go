package reference

import (
	"context"
	"net/http"
	"testing"
)

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
