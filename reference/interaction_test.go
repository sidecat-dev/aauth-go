package reference

import (
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
)

func TestDecodeInteractionAuthorizationUsesTypeSpecificSuccessShape(t *testing.T) {
	t.Parallel()

	for name, test := range map[string]struct {
		interactionType aauth.InteractionType
		body            string
		wantCompleted   bool
		wantAnswer      string
	}{
		"completion needs no response body": {
			interactionType: aauth.InteractionTypeCompletion,
			wantCompleted:   true,
		},
		"question returns the draft answer object": {
			interactionType: aauth.InteractionTypeQuestion,
			body:            `{"answer":"Use the refundable option."}`,
			wantAnswer:      "Use the refundable option.",
		},
	} {
		t.Run(name, func(t *testing.T) {
			response := &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(test.body)),
			}
			got, err := decodeInteractionAuthorization(
				response,
				"https://ps.example",
				time.Now(),
				test.interactionType,
			)
			if err != nil {
				t.Fatal(err)
			}
			if got.Completed != test.wantCompleted || got.Answer != test.wantAnswer {
				t.Fatalf("authorization = %#v", got)
			}
		})
	}
}
