# AAuth M6 protected payload Events implementation plan

> Implement task-by-task with test-driven development. Sidecat owns live work,
> gates, checkpoints, and evidence; this file records the reviewed repository
> contract.

**Goal:** Complete one authenticated operation → protected ticket → bodyless
registration → exact JSON event payload → one independently verified agent
action across host reconstruction.

**Architecture:** Root `aauth` parses the selected portable AsyncAPI 3.0.0
document and validates a selected JSON payload. The `reference` host owns exact
document resolution/custody, ticket authority, resource subscription and
pending delivery, AP use/inbox, and agent context/processing behind replaceable
interfaces. The existing M5 token and self-jwt code remains unchanged except
where HTTP content proof is required.

**Profile authority:** `m6-profile-decision.md`

## Global constraints

- Keep this module standalone and Sidecat-free.
- Add an externally visible real-HTTP RED before production APIs.
- Retain `max_uses: 1`; do not invent a per-event token claim or protocol
  delivery identifier.
- Store only a digest of an opaque ticket. Ticket consume and resource
  subscription creation must be one transaction.
- Default protected registration is bodyless. A deployment-supplied validator
  is the only route to a non-empty registration body.
- The complete direct JSON event body is the AsyncAPI payload. The JWT remains
  payload-free in `Signature-Key`.
- No `202` before exact token, payload bytes, media type, and digest custody.
- No remote schema references or implicit network fetches during validation.
- AP-to-agent continuation stays explicitly non-normative.
- Run focused tests at each RED/GREEN cycle and full, race, vet, build, source
  coverage, artifact validation, and diff checks before closure.

## Task 1 — Lock the complete real-HTTP journey in RED

**Files:**

- Create `testdata/eventsprotected/events_journey_test.go`
- Update `behavior-corpus.md`

Write `TestProtectedPayloadEventSurvivesHostReconstruction` against the intended
public host APIs. It must perform the authenticated protected call, assert
ticket commit before URL release, register through the ticket path, retain one
exact payload attempt, lose the AP's first `202`, reconstruct every host,
settle through `429`, validate at the agent, recover one unknown action, and
prove terminal dedup.

Run:

```text
go test ./testdata/eventsprotected -run '^TestProtectedPayloadEventSurvivesHostReconstruction$' -count=1
```

Expected RED: compile failure for the absent M6 APIs. Retain exact output in
the active Sidecat work item before production changes.

## Task 2 — Parse and validate the selected AsyncAPI profile

**Files:**

- Create `events_asyncapi.go`
- Create `events_asyncapi_test.go`
- Update `go.mod` and `go.sum` only through a pinned JSON Schema dependency

Produce an immutable parsed contract carrying exact-byte SHA-256 identity and
one resolved protected operation/message selection. Accept only JSON AsyncAPI
3.0.0, local message references, matching channel address parameters,
`action: receive`, absent protected-operation security, exact
`components.securitySchemes.aauth_subscribe`, `application/json`, and an inline
compilable payload schema. Reject duplicate JSON names, remote references,
ambiguous message selection, and malformed or unsupported representations.

Expose validation that decodes one exact JSON value without trailing data and
applies the compiled schema without refetching or reserializing it.

Focused RED/GREEN:

```text
go test . -run '^TestEventsAsyncAPI' -count=1
```

## Task 3 — Add exact contract discovery and resource publication

**Files:**

- Create `events_discovery.go`
- Create `events_discovery_test.go`
- Modify `reference/resource.go`
- Create or extend resource discovery tests

Add an admitted, bounded HTTP resolver that reads resource metadata,
selects `urn:aauth:vocabulary:asyncapi`, resolves only an HTTPS same-resource
endpoint, retains exact response bytes under HTTP freshness, and returns the
parsed contract. Resource configuration publishes one exact document at its
advertised endpoint with explicit JSON media type and caching behavior.

The contract-custody interface retains exact bytes by digest through a supplied
future deadline. Ticket issuance must prove those bytes are reloadable before
releasing a URL. Existing exact-byte stores may satisfy the small interface;
the protocol API must not depend on their concrete implementation.

Focused RED/GREEN:

```text
go test ./... -run '^(TestResourceEventsAsyncAPIDiscovery|TestEventsContractResolver)' -count=1
```

## Task 4 — Add protected ticket authority and atomic registration

**Files:**

- Create `reference/events_ticket.go`
- Create `reference/events_ticket_test.go`
- Modify `reference/events.go`
- Modify `reference/events_file_store.go`
- Modify `reference/resource.go`
- Modify `reference/agent.go`

Add a resource-owned ticket service callable from an already verified
`aauth.AuthorizedRequest`. It generates at least 32 random bytes, puts only the
digest in its record, binds all STORY-0018 context, retains the selected exact
contract, commits before release, and returns URL plus contract selection.

Extend `ResourceEventStore` with ticket creation and atomic
consume-and-register. Memory and file implementations must preserve old M5
records and use one versioned transaction boundary. The ticket handler verifies
the subscribe-token JWT and confirmation-key HTTP proof before the store call.
The agent retains exact contract context before sending the bodyless request.

An optional registration validator owns bounded exact body/media-type
validation; without it, non-empty bodies fail. With it, the request requires
covered `content-type` and `content-digest` before validation or consumption.

Focused RED/GREEN:

```text
go test -race ./reference -run '^(TestProtectedEventTicketIssue|TestProtectedEventRegistration)' -count=1
```

## Task 5 — Carry exact payload custody through resource and AP

**Files:**

- Modify `reference/events.go`
- Modify `reference/events_file_store.go`
- Modify `reference/resource.go`
- Modify `reference/provider.go`
- Modify delivery/store tests

Extend resource pending and AP accepted records with bounded exact payload
bytes, media type, and digest. `DeliverEvent` accepts the selected message and
payload, validates it against the retained contract, commits one exact
token-payload pending attempt, and signs `content-type` and `content-digest`.

The AP verifies the HTTP proof and body digest before one atomic use-plus-inbox
commit. Resource retry after a lost response reloads and sends the same token
and body with a fresh proof. File snapshots enforce per-record and total-byte
limits over payload bytes and reject old/incomplete M6 records without
weakening M5 payload-free compatibility inside this unreleased Gen5 code line.

Focused RED/GREEN:

```text
go test -race ./... -run '^TestEventPayloadDelivery' -count=1
```

## Task 6 — Validate payload independently at the agent

**Files:**

- Modify `reference/events.go`
- Modify `reference/agent.go`
- Modify agent, adapter, and file-store tests

Extend the non-normative adapter envelope and `EventActionInput` with exact
payload custody. Agent context references the retained exact contract digest
and operation/message selection. Before pending action admission, independently
verify token, media type, payload digest, exact contract bytes, and JSON schema.

Invalid input records one durable terminal refusal with no action. Valid work
keeps the existing pending/dispatched/completed/reconciled state machine and
stable `(resource issuer,AP issuer,eid)` action key.

Focused RED/GREEN:

```text
go test -race ./reference -run '^(TestAgentEventPayload|TestEventAdapterPayload)' -count=1
```

## Task 7 — Promote the journey and qualify every recovery boundary

**Files:**

- Promote the complete test into `events_protected_journey_test.go`
- Extend protected ticket, payload, and file-store refusal tests
- Remove the temporary `testdata/eventsprotected` RED harness

Run JOURNEY-0003 with memory and file-backed authorities. Inject failure before
ticket commit, consume/register commit, resource pending commit, AP inbox
commit, agent pending admission, action completion, and adapter acknowledgement.
Reconstruct at every committed seam and prove exact identities/bytes survive.

Run:

```text
go test -race ./... -run '^(TestProtectedPayloadEventSurvivesHostReconstruction|TestProtectedEvent|TestEventPayload|TestAgentEventPayload|TestEventAdapterPayload)' -count=1
```

## Task 8 — Audit, document, and close M6

**Files:**

- Update README, implementation journal, source coverage, behavior artifacts,
  and generated source ledger
- Update EPIC-004, roadmap, coverage ledger, and iteration log only from fresh
  evidence

Before claiming completion run:

```text
gofmt -w <touched Go files>
go test ./... -count=1
go test -race ./... -count=1
go vet ./...
go build ./...
go run ./cmd/aauth-reference verify coverage --source-dir /home/jgay-automate/workspaces/aauth-dev-workspace --repo .
git diff --check
```

Also run every impacted scenario selector and M3/M4/M5 sentinel. Obtain an
independent claims/code review, commit the cohesive checkpoint without a
co-author trailer, publish through Sidecat governed Git, and prove fresh remote
parity before closing the work item.
