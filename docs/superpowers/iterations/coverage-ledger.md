# Coverage ledger

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
| JOURNEY-0002 | STORY-0006..0015 | ITER-0003 | public subscription through reconstructed agent | pending |
| SCENARIO-0009 | STORY-0006 | ITER-0003 | self-jwt preflight/no-discovery matrix | pending |
| SCENARIO-0010 | STORY-0006..0007,0012..0013 | ITER-0003 | same-key dual-proof exchange | pending |
| SCENARIO-0011 | STORY-0007 | ITER-0003 | admitted and bounded discovery | pending |
| SCENARIO-0012 | STORY-0008,0012 | ITER-0003 | AP metadata cache and endpoint rotation | pending |
| SCENARIO-0013 | STORY-0009,0011 | ITER-0003 | subscribe-token and proof mutation matrix | pending |
| SCENARIO-0014 | STORY-0011 | ITER-0003 | token-expiry independence and duplicate registration | pending |
| SCENARIO-0015 | STORY-0013 | ITER-0003 | failure-injected atomic inbox acceptance | pending |
| SCENARIO-0016 | STORY-0012..0013 | ITER-0003 | concurrent final use and resource cleanup | pending |
| SCENARIO-0017 | STORY-0013 | ITER-0003 | AP response-class and no-mutation matrix | pending |
| SCENARIO-0018 | STORY-0014..0016 | ITER-0003 | agent completion/refusal reconstruction | pending |
| SCENARIO-0019 | STORY-0010,0014,0016 | ITER-0003 | exact-byte and public-claim audit | pending |
| SCENARIO-0020 | STORY-0009 | ITER-0003 | AP collision/commit/restart custody | pending |
| SCENARIO-0021 | STORY-0010..0011,0015 | ITER-0003 | context/resource/dedup custody failures | pending |
| SCENARIO-0022 | STORY-0011 | ITER-0003 | two-AP same-eid federation identity | pending |
| SCENARIO-0023 | STORY-0012..0013 | ITER-0003 | lost-response exact-token retry and exhaustion | pending |
| SCENARIO-0024 | STORY-0009..0015,0017 | ITER-0003 | bounded replaceable interfaces and file adapters | pending |

## M5 source-chunk coverage

| Source chunk | Stories | Scenarios | Classification |
|---|---|---|---|
| Events 129-195, overview/terms | STORY-0009..0016 | JOURNEY-0002, SCENARIO-0019 | covered; non-normative host steps labeled |
| Events 196-208, AP metadata | STORY-0008, STORY-0012 | SCENARIO-0012 | covered |
| Events 210-290, subscribe token/context | STORY-0009..0011 | JOURNEY-0002, SCENARIO-0013..0014, SCENARIO-0020..0022 | covered |
| Events 291-295, public registration | STORY-0010..0011 | JOURNEY-0002, SCENARIO-0014, SCENARIO-0021..0022 | covered |
| Events 297-344, protected registration | STORY-0016 | SCENARIO-0019 | excluded to accepted M6 |
| Events 346-409, token/resource delivery | STORY-0012 | JOURNEY-0002, SCENARIO-0010, SCENARIO-0012 | covered for no-payload M5 profile |
| Events 410-437, AP validation | STORY-0013 | JOURNEY-0002, SCENARIO-0015..0017, SCENARIO-0023..0024 | covered |
| Events 438-456, AP-agent/agent verification | STORY-0014..0017 | JOURNEY-0002, SCENARIO-0018, SCENARIO-0021, SCENARIO-0024 | covered; transport non-normative |
| Events 582-625, security/privacy | STORY-0013..0016 | SCENARIO-0016..0019 | covered |
| Events 680-719, rationale | STORY-0009, STORY-0012..0016 | JOURNEY-0002, SCENARIO-0012, SCENARIO-0016, SCENARIO-0019..0020 | covered; multi-event ambiguity explicit |
| Signature-Key 660-721, self-jwt | STORY-0006 | SCENARIO-0009..0010 | covered |
| Signature-Key 1171-1208, validation/cache | STORY-0007 | SCENARIO-0010..0011 | covered with selected shared-cache profile |
| Signature-Key 1258-1276, SSRF/security | STORY-0006..0007 | SCENARIO-0009..0011 | covered through deployment-owned egress boundary |

## Sentinel corpus

Every iteration runs the focused impacted tests plus:

- `go test ./... -count=1`
- `go test -race ./... -count=1`
- `go vet ./...`
- `go run ./cmd/aauth-reference verify coverage --source-dir /home/jgay-automate/workspaces/aauth-dev-workspace --repo .`
- `git diff --check`

M3 and M4 remain sentinels: direct and conditional R3 journeys, AS-only fetch,
exact-byte stores, caches, audit-before-token, restart, replay, and refusal
tests must remain green while Events is added.
