# M4 coverage ledger

| Scenario | Story | Iteration | Evidence | Status |
|---|---|---|---|---|
| JOURNEY-0001 | STORY-0001..0004 | ITER-0000 | `TestR3ConditionalPerCallJourney` | automated, pass |
| SCENARIO-0001 | STORY-0002 | ITER-0000 | proposal parse/binding/refusal tests | automated, pass |
| SCENARIO-0002 | STORY-0002 | ITER-0000 | real journey challenge/custody assertions | automated, pass |
| SCENARIO-0003 | STORY-0002 | ITER-0000 | journey and document-store refusal tests | automated, pass |
| SCENARIO-0004 | STORY-0001 | ITER-0000 | decision validation and real journey | automated, pass |
| SCENARIO-0005 | STORY-0003 | ITER-0000 | decision, audit, restart, and issuance-store tests | automated, pass |
| SCENARIO-0006 | STORY-0004 | ITER-0000 | real signed-HTTP parameter mutation matrix | automated, pass |
| SCENARIO-0007 | STORY-0005 | ITER-0002 | resource/AS reconstruction and custody refusal | automated, pass |
| SCENARIO-0008 | STORY-0005 | ITER-0002 | proof replay and durable token-consumption tests | automated, pass |

## Sentinel corpus

Every iteration runs the focused M4 tests plus:

- `go test ./... -count=1`
- `go test -race ./... -count=1`
- `go vet ./...`
- `go run ./cmd/aauth-reference verify coverage --source-dir /home/jgay-automate/workspaces/aauth-dev-workspace --repo .`
- `git diff --check`

M3 remains a sentinel: its direct-grant journey, AS-only fetch, exact-byte file
store, cache, audit-before-token, scope independence, and refusal tests must
remain green while conditional support is added.
