# EPIC-003 — Events public subscription lifecycle

**Summary:** Register one public subscription, durably accept one payload-free
resource event, and deliver it once to the correct agent context.
**Stories:** STORY-0008 through STORY-0017
**Primary source:** `draft-hardt-aauth-events-00`
**Accepted scope:** AAuth complete-spec-family roadmap M5
**Status:** 0/10 done

## STORY-0008

**Epic:** EPIC-003
**Title:** Advertise an Events endpoint

**As an** agent-provider deployment
**I want** metadata to advertise whether and where Events delivery is supported
**So that** resources can discover the current endpoint without token-carried
or registration-time URL authority

**Acceptance criteria:**

- AC-1: An Events-capable AP publishes an absolute HTTPS `event_endpoint` in
  `/.well-known/aauth-agent.json`; an AP without Events does not advertise it.
  · impact:`cross-surface` · seam:`integration` · scenario:`SCENARIO-0012`
- AC-2: The AP may change its endpoint; admitted HTTP cache freshness controls
  reuse and delivery after freshness expiry resolves the new metadata value.
  · impact:`cross-surface` · seam:`integration` · scenario:`SCENARIO-0012`

**Sources:** Events lines 196-208, 285, 384-409

**Status:** pending

## STORY-0009

**Epic:** EPIC-003
**Title:** Create AP subscription authority and issue its token

**As an** agent-provider deployment
**I want** one durable subscription authority and exact subscribe token
**So that** release of a registration credential never precedes the AP state
needed to authenticate later delivery

**Acceptance criteria:**

- AC-1: The selected M5 AP collision-refuses and durably records a non-empty
  opaque unique `eid`, resource, agent, AP-owned `active_until`, and
  `max_uses: 1` before releasing a token. Failure before commit releases no
  token; reconstruction recovers the exact authority. · impact:`cross-surface` ·
  seam:`process-level` · scenario:`SCENARIO-0020`
- AC-2: The AP-signed `aa-subscribe+jwt` has exact `iss`,
  `dwk=aauth-agent.json`, `sub`, resource `aud`, agent `cnf.jwk`, `eid`, `iat`,
  future `exp`, and `max_uses: 1`; `alg=none` is refused and the selected
  implementation emits EdDSA. Generic token decoding preserves absent or
  other positive values, but this single-shot host refuses them before
  authority creation. · impact:`journey` · seam:`e2e` ·
  scenario:`SCENARIO-0013`
- AC-3: Subscribe-token `exp` is only the registration window. AP
  `active_until` is a deployment-owned host input, not a protocol-negotiated
  value inferred from token expiry or synchronized with the resource over an
  invented wire. · impact:`local` · seam:`integration` ·
  scenario:`SCENARIO-0020`
- AC-4: The same `eid` correlates the AP authority, subscribe token, resource
  registration, and M5 event token; it is opaque outside the AP and unique only
  within that AP issuer. · impact:`journey` · seam:`e2e` ·
  scenario:`JOURNEY-0002`

**Sources:** Events lines 143-146, 188-235, 680-703

**Status:** pending

## STORY-0010

**Epic:** EPIC-003
**Title:** Prepare an agent public registration

**As an** agent host
**I want** to retain local context and sign one public registration request
**So that** successful event delivery can return to the exact local concern
that created the subscription

**Acceptance criteria:**

- AC-1: Before registration the reference host durably maps `(AP issuer, eid)`
  to one local context. Mapping failure prevents the signed request; host
  reconstruction recovers the same mapping. · impact:`cross-surface` ·
  seam:`process-level` · scenario:`SCENARIO-0021`
- AC-2: The agent presents the subscribe token as the sole `sig=jwt` credential
  on a signed public POST. No agent or auth token is added. · impact:`journey`
  · seam:`e2e` · scenario:`JOURNEY-0002`
- AC-3: Subscribe-token acquisition and local context mapping remain explicitly
  non-normative host behavior, not an Events wire-conformance claim. ·
  impact:`local` · seam:`integration` · scenario:`SCENARIO-0019`

**Sources:** Events lines 188-195, 253-295

**Status:** pending

## STORY-0011

**Epic:** EPIC-003
**Title:** Verify and retain a public registration

**As a** resource
**I want** to verify and durably retain one signed public registration
**So that** only the AP-authorized agent and resource establish the delivery
binding

**Acceptance criteria:**

- AC-1: Before mutation the resource verifies token type, exact discovery
  document, AP JWT signature, a present syntactically valid AAuth agent `sub`,
  non-future `iat`, future `exp`, its own resource audience, non-empty `eid`,
  selected `max_uses: 1`, and that `cnf.jwk` verifies the HTTP signature.
  Absent or other use policies are refused without mutation in this profile.
  · impact:`cross-surface` · seam:`integration` · scenario:`SCENARIO-0013`
- AC-2: A successful public request needs no credential in addition to the
  subscribe token. The resource commits `(AP issuer, eid)`, agent, and its own
  deployment-selected `active_until` before success; store failure reports no
  registration. · impact:`cross-surface` · seam:`process-level` ·
  scenario:`SCENARIO-0021`
- AC-3: Resource `active_until` is independent from subscribe-token expiry and
  AP host lifetime. The selected reference journey supplies both host policies
  explicitly but claims no negotiation or synchronization protocol. ·
  impact:`local` · seam:`integration` · scenario:`SCENARIO-0014`
- AC-4: Duplicate detection is by `(AP issuer, eid)`. A duplicate from the same
  AP cannot replace or extend the first record, while two AP issuers may use
  the same opaque `eid` without collision. · impact:`cross-surface` ·
  seam:`process-level` · scenario:`SCENARIO-0022`

**Sources:** Events lines 188-195, 210-295, 596-598, 680-695

**Status:** pending

## STORY-0012

**Epic:** EPIC-003
**Title:** Resolve and send a payload-free event

**As a** resource
**I want** to resolve the current AP endpoint and send a minimal authenticated
event
**So that** endpoint rotation and event authentication do not depend on stale
registration state

**Acceptance criteria:**

- AC-1: At delivery time the resource loads its durable `(AP issuer, eid)`
  subscription and resolves `event_endpoint` from current AP metadata using
  admitted standard cache freshness. A registration-time endpoint is not
  authority. · impact:`cross-surface` · seam:`integration` ·
  scenario:`SCENARIO-0012`
- AC-2: The resource mints `aa-event+jwt` with exact resource `iss`,
  `dwk=aauth-resource.json`, subscribed agent `aud`, the same `eid`, `iat`, and
  future `exp`; `cnf` and event-specific data are absent. · impact:`journey` ·
  seam:`e2e` · scenario:`JOURNEY-0002`
- AC-3: M5 sends a bodyless POST with `sig=self-jwt`; method, authority, path,
  and signature-key are covered and the resource key signs both the JWT and
  HTTP proof. Lookup, signing, or transport failure cannot report delivery.
  · impact:`journey` · seam:`e2e` · scenario:`SCENARIO-0010`
- AC-4: The selected one-use resource observes `remaining_uses: 0` and removes
  its local record after the AP `202`, or reconciles an unknown first outcome
  when exact retry returns the source-required exhausted `429`. ·
  impact:`local` · seam:`integration` · scenario:`SCENARIO-0023`
- AC-5: Before its first send the resource durably retains the exact event JWT
  as pending delivery. If the AP consequence is unknown, reconstruction retries
  that JWT with a fresh HTTP proof; it never mints a second event for the same
  one-use authority. · impact:`cross-surface` · seam:`process-level` ·
  scenario:`SCENARIO-0023`

**Sources:** Events lines 346-409, 423-434, 680-719

**Status:** pending

## STORY-0013

**Epic:** EPIC-003
**Title:** Durably accept and meter an event

**As an** agent provider
**I want** to authenticate and atomically retain a matching event before
acknowledging it
**So that** forged, misrouted, exhausted, or unrecorded events never enter the
agent inbox

**Acceptance criteria:**

- AC-1: The AP uses the generic self-jwt verifier, then binds `eid` to an active
  persisted subscription, exact resource `iss`, and agent `aud`. Events policy
  additionally requires exact `dwk=aauth-resource.json`, a present valid
  NumericDate `iat`, and future event `exp` before mutation. ·
  impact:`journey` · seam:`e2e` · scenario:`SCENARIO-0010`
- AC-2: One deployment-owned transaction atomically checks/increments the
  selected `max_uses: 1` and records the exact accepted token for adapter
  continuation. `202` is impossible before that durable commit. ·
  impact:`cross-surface` · seam:`process-level` · scenario:`SCENARIO-0015`
- AC-3: Concurrent different event JWTs for the final use produce one `202`
  with `remaining_uses: 0` and one `429`. A retry of the exact accepted JWT,
  including after reconstruction, returns `429` without another use or inbox
  record; the resource treats that as settled exhaustion, not proof of another
  acceptance. M5 parses absent `max_uses` but its reference authority refuses
  it and claims no ongoing delivery semantics while the source has no distinct
  per-delivery replay identity. ·
  impact:`cross-surface` · seam:`process-level` · scenario:`SCENARIO-0016`
- AC-4: The real handler returns `400` for malformed input, `401` for invalid
  resource proof, `403` for resource or agent mismatch, `404` for unknown or
  expired subscription, and `429` for exhaustion; every refusal leaves usage
  and inbox state unchanged. · impact:`local` · seam:`integration` ·
  scenario:`SCENARIO-0017`

**Sources:** Events lines 410-437, 582-603, 680-703

**Status:** pending

## STORY-0014

**Epic:** EPIC-003
**Title:** Continue accepted delivery through a deployment adapter

**As an** agent-provider deployment
**I want** accepted inbox work to survive process replacement
**So that** temporary agent absence does not erase an event already
acknowledged to its resource

**Acceptance criteria:**

- AC-1: A deployment-owned adapter reads a durable record containing trusted
  AP issuer context, a host-generated AP inbox delivery identifier, and exact
  pending token bytes from the AP inbox transaction, and resumes after AP or
  adapter reconstruction. The AP issuer and delivery identifier are host-bound
  context, not new token claims or standardized wire fields. ·
  impact:`journey` · seam:`process-level` · scenario:`JOURNEY-0002`
- AC-2: Adapter acknowledgement occurs only after the agent host reports a
  durable terminal disposition: a completed action, an already completed
  duplicate, or an independently verified terminal refusal with proof that no
  action occurred. Pending, dispatched, and outcome-unknown states are not
  terminal; failure to retain or prove the terminal disposition leaves adapter
  work pending for retry or reconciliation. ·
  impact:`cross-surface` · seam:`process-level` ·
  scenario:`SCENARIO-0018`
- AC-3: The adapter remains a replaceable reference-host contract and never
  becomes a normative AP-to-agent wire claim. · impact:`local` ·
  seam:`integration` · scenario:`SCENARIO-0019`

**Sources:** Events lines 438-442, 664-670

**Status:** pending

## STORY-0015

**Epic:** EPIC-003
**Title:** Verify and deduplicate at the agent

**As an** agent
**I want** to independently verify a durably delivered event before acting
**So that** a deployment adapter cannot weaken resource authenticity, routing,
expiry, context, or replay checks

**Acceptance criteria:**

- AC-1: Before action the agent independently verifies event `typ`, exact
  `dwk=aauth-resource.json`, a present valid NumericDate `iat`, resource
  discovery/JWT signature, its own `aud`, future `exp`, and durable local
  `(AP issuer, eid)` mapping. · impact:`journey` · seam:`e2e` ·
  scenario:`SCENARIO-0018`
- AC-2: The agent store represents valid work as `pending` (never dispatched),
  `dispatched` (outcome not yet durably known), or terminal `completed`. It
  admits `(resource iss, AP issuer, eid)` as pending and moves pending to
  dispatched before invoking the deployment action with that stable
  idempotency key. Immediately before a first dispatch it rechecks `exp`; an
  expired never-dispatched item moves transactionally to terminal refused with
  no action. An event that otherwise fails independent verification or lacks
  context is also durably refused by trusted `(AP issuer, AP inbox delivery
  identifier)` and exact-token digest, without trusting its claims. Store
  failure causes no action and leaves adapter work pending. ·
  impact:`cross-surface` ·
  seam:`process-level` ·
  scenario:`SCENARIO-0021`
- AC-3: No action occurs for wrong issuer key, type, discovery document,
  audience, expiry, or unknown context. Each such accepted-inbox delivery
  reaches a durable terminal refusal with a bounded reason class, survives
  reconstruction, and can be acknowledged without action. · impact:`local` ·
  seam:`integration` · scenario:`SCENARIO-0018`
- AC-4: Reconstruction of dispatched work reconciles through the deployment
  action's stable idempotency contract. A proven completed action becomes
  completed; a proven not-applied action may be retried while unexpired or
  refused after expiry; an unknown outcome remains dispatched and
  unacknowledged. Evidence claims no exactly-once arbitrary external
  consequence after an unobservable crash. · impact:`cross-surface` ·
  seam:`process-level` · scenario:`SCENARIO-0018`

**Sources:** Events lines 438-456, 592-598, 711-719

**Status:** pending

## STORY-0016

**Epic:** EPIC-003
**Title:** Preserve the single-shot and privacy boundary

**As an** AAuth implementer
**I want** M5 evidence to state exactly what its event profile proves
**So that** a useful single-shot path is not mistaken for protected,
payload-bearing, multi-event, or standardized adapter conformance

**Acceptance criteria:**

- AC-1: The selected journey uses `max_uses: 1`. Because the draft supplies no
  per-delivery identifier beyond `eid`, M5 does not claim independently
  deduplicable multiple events under one `eid`. · impact:`cross-surface` ·
  seam:`process-level` · scenario:`SCENARIO-0018`
- AC-2: The exact JWT, HTTP request, AP inbox record, and adapter record carry no
  event payload. Documentation states that future payloads are AP-visible and
  sensitive detail should be fetched with current authorization. ·
  impact:`cross-surface` · seam:`integration` · scenario:`SCENARIO-0019`
- AC-3: Protected tickets and AsyncAPI discovery/schema/payload handling remain
  unsupported and assigned to M6. M6 may extend deployment adapter behavior
  but cannot turn the source's non-normative AP-agent step into standardized
  protocol wire without a separate accepted specification decision. ·
  impact:`local` · seam:`integration` · scenario:`SCENARIO-0019`

**Sources:** Events lines 129-131, 297-344, 438-442, 608-624, 697-719

**Status:** pending

## STORY-0017

**Epic:** EPIC-003
**Title:** Qualify bounded replaceable host stores

**As an** AAuth deployer
**I want** each host authority behind a replaceable transaction interface and
a deliberately bounded reference file adapter
**So that** the reference implementation proves recovery without becoming an
enterprise or federated storage ceiling

**Acceptance criteria:**

- AC-1: AP subscription/inbox, resource subscription/pending delivery, adapter
  continuation, and agent context/processing services are constructed against
  deployment-owned store or transaction interfaces. In-memory qualification
  stores and file adapters are interchangeable without changing protocol or
  service APIs. · impact:`cross-surface` · seam:`process-level` ·
  scenario:`SCENARIO-0024`
- AC-2: Each file adapter uses explicit versioned record schemas and configured
  maximum record count, total bytes, and per-record bytes. It enforces those
  limits before making new authority or continuation state reachable, requires
  a private directory and files, and refuses symlinks, unexpected entries, and
  unsafe permissions. · impact:`cross-surface` · seam:`process-level` ·
  scenario:`SCENARIO-0024`
- AC-3: File mutation uses a crash-safe temporary-write, file-sync, atomic
  rename, and directory-sync boundary. Injected partial-write failure preserves
  the prior committed snapshot or reports no success; truncated, corrupt, or
  unknown-version records fail closed before authority or continuation becomes
  available. · impact:`cross-surface` · seam:`process-level` ·
  scenario:`SCENARIO-0024`
- AC-4: A file adapter owns an exclusive writer lock for its lifetime and
  refuses a concurrent writer. It makes no multi-process, distributed, or
  enterprise-capacity claim; deployments replace the interface implementation
  for those requirements. · impact:`cross-surface` · seam:`process-level` ·
  scenario:`SCENARIO-0024`

**Sources:** Events lines 188-195, 285-295, 410-456
**Architecture basis:** Accepted M5 reference-host qualification boundary;
these controls qualify host custody and do not add Events wire requirements.

**Status:** pending

## Selected-profile and host-architecture boundaries

- The draft alternates the prose name `scheme=jwt` with the actual
  Signature-Key wire grammar `sig=jwt`. M5 uses the latter and mints no alias.
- Phase-1 token acquisition, agent context mapping, and AP-to-agent delivery
  are explicitly out of protocol scope. Reference host paths prove durable
  usefulness without becoming protocol operations.
- AP and resource subscription lifetimes are independent deployment-owned
  `active_until` inputs. M5 invents no lifetime negotiation or synchronization
  message; the journey selects overlapping host lifetimes explicitly.
- Resource subscription identity is `(AP issuer, eid)`, because `eid` is unique
  only inside its AP. Agent replay identity additionally includes resource
  issuer.
- AP subscription authority and atomic usage/inbox acceptance, resource
  subscription custody, adapter continuation, and agent context/dedup custody
  are deployment-owned interfaces and transaction boundaries. Durable records
  carry explicit schema versions and authority-qualified keys. Bounded
  single-writer file stores enforce configured record and byte limits,
  crash-safe replacement, safe filesystem custody, and exclusive writer
  ownership. They are reference adapters only; enterprise, multi-process, and
  federated replacements do not change protocol APIs.
- M5 may cache metadata according to HTTP freshness, but a registration-time
  URL never becomes authority.
- `eid` is the draft's only replay key. M5 closes a single-shot journey and
  retains ongoing/unlimited delivery as unclaimed until the specification
  supplies a distinct delivery identity or otherwise clarifies deduplication.
