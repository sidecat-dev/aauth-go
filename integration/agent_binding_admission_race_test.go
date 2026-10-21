package integration_test

import (
	"context"
	"net/http"
	"testing"
	"time"

	"gitlab.com/sidecat-dev/aauth-go/personserver"
)

// Protocol 28e8258, Agent-Person Binding, AS Response and Pending URL
// Security: an AS response arriving after the binding was replaced cannot
// move the original request into the replacement binding's lifetime.
func TestReplacementDuringInitialASResponseDoesNotAdoptOldRequest(t *testing.T) {
	for _, advance := range []bool{false, true} {
		name := "Agent poll"
		if advance {
			name = "host advance"
		}
		t.Run(name, func(t *testing.T) {
			f := newSubagentFederation(t, 10*time.Minute)
			f.stage.Store(1)
			replace := func() {
				binding := personserver.AgentBinding{AgentProvider: "https://ap.example", Agent: subagentParentID}
				f.now.Add(1)
				if err := f.ps.RevokeAgentBinding(context.Background(), binding); err != nil {
					t.Fatal(err)
				}
				f.now.Add(1)
				if err := f.ps.ReestablishAgentBinding(context.Background(), binding); err != nil {
					t.Fatal(err)
				}
				f.now.Add(1)
			}
			f.afterAS.Store(&replace)
			pending := f.begin(t)
			f.stage.Store(2)
			if advance {
				f.now.Add(5)
				if err := f.ps.AdvanceFederation(context.Background(), deferredReference(pending)); err != nil {
					t.Fatal(err)
				}
			}
			_, err := f.parent.PollExchange(context.Background(), pending)
			requireDeferredProblem(t, err, http.StatusBadRequest, "revoked_presented_token")
			_, err = f.parent.PollExchange(context.Background(), pending)
			requireDeferredProblem(t, err, http.StatusGone, "request_consumed")
			if f.asPolls.Load() != 0 || f.asCancels.Load() != 1 {
				t.Fatalf("old request: AS polls %d, withdrawals %d; want 0 and 1", f.asPolls.Load(), f.asCancels.Load())
			}
		})
	}
}
