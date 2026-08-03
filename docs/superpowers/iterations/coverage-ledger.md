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
| JOURNEY-0002 | STORY-0006..0015 | ITER-0003 | `TestPublicSubscriptionEventSurvivesHostReconstruction` | automated, pass |
| SCENARIO-0009 | STORY-0006 | ITER-0003 | `TestSelfJWTRejectsUnsafeClaimsBeforeDiscovery` | automated, pass |
| SCENARIO-0010 | STORY-0006..0007,0012..0013 | ITER-0003 | same-key dual-proof and strict Events-claim tests | automated, pass |
| SCENARIO-0011 | STORY-0007 | ITER-0003 | egress policy, bounded retained/inflight state, deterministic eviction, and warm-cache expiry tests | automated, pass |
| SCENARIO-0012 | STORY-0008,0012 | ITER-0003 | metadata freshness, cache prohibition, rotation, and journey tests | automated, pass |
| SCENARIO-0013 | STORY-0009,0011 | ITER-0003 | strict token claims, raw mutation endpoint, and exact proof tests | automated, pass |
| SCENARIO-0014 | STORY-0011 | ITER-0003 | registration reconstruction, expiry independence, and nonreplacement journey | automated, pass |
| SCENARIO-0015 | STORY-0013 | ITER-0003 | `TestAPEventEndpointCommitsInboxBefore202` failure/recovery path | automated, pass |
| SCENARIO-0016 | STORY-0012..0013 | ITER-0003 | race-qualified real resource/direct final-use test across AP and resource reconstruction | automated, pass |
| SCENARIO-0017 | STORY-0013 | ITER-0003 | exact HTTP refusal/problem/signature/no-mutation matrix | automated, pass |
| SCENARIO-0018 | STORY-0014..0016 | ITER-0003 | focused agent state-machine race suite | automated, pass |
| SCENARIO-0019 | STORY-0010,0014,0016 | ITER-0003 | payload mutation tests, full journey, README invariant, and verified source-coverage report | automated, pass |
| SCENARIO-0020 | STORY-0009 | ITER-0003 | exact token/record identity plus fail-before-commit, healthy retry, and collision tests | automated, pass |
| SCENARIO-0021 | STORY-0010..0011,0015 | ITER-0003 | registration authority failure and agent dedup-custody failure/retry tests | automated, pass |
| SCENARIO-0022 | STORY-0011 | ITER-0003 | two reconstructed AP authorities sharing one opaque `eid` without collision | automated, pass |
| SCENARIO-0023 | STORY-0012..0013 | ITER-0003 | exact-JWT lost-202 retry, different-JWT final-use race, 429 settlement, and reconstruction | automated, pass |
| SCENARIO-0024 | STORY-0009..0015,0017 | ITER-0003 | bounded file-adapter corpus plus reconstructed end-to-end journey | automated, pass |
| JOURNEY-0003 | STORY-0018..0021 | ITER-0004 | `TestProtectedPayloadEventSurvivesHostReconstruction` | automated, pass |
| SCENARIO-0025 | STORY-0018 | ITER-0004 | protected ticket issue/custody/reopen suite | automated, pass |
| SCENARIO-0026 | STORY-0018 | ITER-0004 | protected registration atomicity/refusal suite | automated, pass |
| SCENARIO-0027 | STORY-0019 | ITER-0004 | exact AsyncAPI discovery/profile/parser suite | automated, pass |
| SCENARIO-0028 | STORY-0020 | ITER-0004 | payload proof/custody/lost-response suite | automated, pass |
| SCENARIO-0029 | STORY-0021 | ITER-0004 | agent payload validation/recovery suite | automated, pass |
| SCENARIO-0030 | STORY-0022 | ITER-0004 | claims, source coverage, and sentinel audit | automated, pass |

## M6 source-chunk coverage

| Source chunk | Stories | Scenarios | Classification |
|---|---|---|---|
| Events 297-344, protected registration | STORY-0018 | JOURNEY-0003, SCENARIO-0025..0026 | covered; bodyless selected profile and optional deployment validator explicit |
| Events 346-456, payload delivery/agent | STORY-0020..0021 | JOURNEY-0003, SCENARIO-0028..0029 | covered; direct JSON body selected profile |
| Events 457-580, AsyncAPI discovery | STORY-0019 | JOURNEY-0003, SCENARIO-0027 | covered; exact JSON 3.0.0 local-reference profile |
| Events 582-624, security/privacy | STORY-0018..0022 | SCENARIO-0025..0030 | covered; exact payload custody and limitations explicit |
| Events 697-725, rationale | STORY-0018..0022 | JOURNEY-0003, SCENARIO-0028..0030 | covered; multi-event identity excluded |

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
