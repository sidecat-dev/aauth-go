# EPIC-004 — Protected payload Events lifecycle

**Summary:** Convert one authenticated resource interaction into a protected,
single-use event subscription and deliver one schema-valid JSON payload through
independently reconstructed hosts.
**Stories:** STORY-0018 through STORY-0022
**Primary source:** `draft-hardt-aauth-events-00`, profiled by
`m6-profile-decision.md`
**Accepted scope:** AAuth complete-spec-family roadmap M6
**Status:** 5/5 done

## STORY-0018

**Epic:** EPIC-004
**Title:** Issue and atomically consume a protected subscription ticket

**As a** resource deployment
**I want** a durable opaque ticket bound to one authenticated interaction
**So that** only the same authorized agent can create the selected subscription

**Acceptance criteria:**

- AC-1: Only after an auth-token protected operation has been independently
  verified may deployment code request a ticket for that exact agent,
  operation, resource-state revision, selected AsyncAPI document and message,
  future expiry, and `max_uses: 1`. The resource commits the record before
  returning its HTTPS URL. · impact:`journey` · seam:`e2e` ·
  scenario:`JOURNEY-0003`
- AC-2: The outward URL contains at least 256 bits of unpredictable random
  capability material. Durable custody stores its SHA-256 digest, never the raw
  URL capability; reconstruction preserves the exact binding and expiry. ·
  impact:`cross-surface` · seam:`process-level` · scenario:`SCENARIO-0025`
- AC-3: A signed POST to the ticket path must carry only a valid subscribe-token
  JWT proof whose `sub` and confirmation key match the authenticated agent and
  whose `aud` names this resource. Ticket validation, optional registration-body
  validation, ticket consumption, and subscription creation are one atomic
  authority transition. · impact:`journey` · seam:`process-level` ·
  scenario:`SCENARIO-0026`
- AC-4: Wrong agent/key/path, unknown, expired, or already used ticket,
  invalid subscribe token, unconfigured non-empty body, and injected store
  failure create no subscription. A failed validation or commit does not consume
  a still-valid ticket. · impact:`cross-surface` · seam:`process-level` ·
  scenario:`SCENARIO-0026`

**Sources:** Events lines 297-344, 596-607, 721-725

**Status:** done

## STORY-0019

**Epic:** EPIC-004
**Title:** Publish and pin the protected event contract

**As an** agent
**I want** an exact AsyncAPI contract bound to my ticket and local context
**So that** later payload validation cannot drift with the resource's current
document

**Acceptance criteria:**

- AC-1: Resource metadata advertises
  `urn:aauth:vocabulary:asyncapi` as a root-relative same-resource JSON
  endpoint, which serves exact immutable bytes with an explicit media type and
  bounded size. · impact:`cross-surface` · seam:`integration` ·
  scenario:`SCENARIO-0027`
- AC-2: The selected parser accepts JSON AsyncAPI 3.0.0 with one protected
  parameterized channel, matching channel parameters, one `receive` operation,
  one locally referenced message, `application/json`, and a compilable inline
  JSON Schema payload. All operation/channel/message references are local and
  resolve exactly once. · impact:`journey` · seam:`integration` ·
  scenario:`SCENARIO-0027`
- AC-3: The protected operation has no AsyncAPI operation-security entry but
  remains an authenticated subscribe-token HTTP registration. Components
  declare the AAuth HTTP security scheme; OpenAPI-style named-map security,
  `application/jwt` JSON payloads, remote references, ambiguous message matches,
  and malformed address parameters fail closed. · impact:`cross-surface` ·
  seam:`integration` · scenario:`SCENARIO-0027`
- AC-4: The ticket and resulting resource subscription bind the exact document
  digest, operation, and message. The agent retains those exact bytes with its
  local `(AP issuer,eid)` context before registration. A later current-document
  change cannot alter validation of this subscription. · impact:`journey` ·
  seam:`process-level` · scenario:`JOURNEY-0003`

**Sources:** Events lines 457-580; AsyncAPI 3.0.0 Channel, Operation, Message,
Reference, Parameter, and Security Scheme objects

**Status:** done

## STORY-0020

**Epic:** EPIC-004
**Title:** Deliver and durably accept one exact payload

**As a** resource and agent provider
**I want** token and payload custody to cross one atomic acceptance boundary
**So that** `202` proves the complete event is recoverable for the agent

**Acceptance criteria:**

- AC-1: Before first send the resource validates one bounded JSON payload
  against the subscription's retained message schema and atomically retains the
  exact event JWT, payload bytes, `application/json`, and digest as one pending
  attempt. · impact:`journey` · seam:`process-level` ·
  scenario:`SCENARIO-0028`
- AC-2: Delivery requires signed `content-type` and `content-digest` together
  with the M5 self-jwt components. Mutation, omission, mismatch, oversize,
  invalid JSON, or schema failure reaches neither AP usage nor inbox mutation. ·
  impact:`cross-surface` · seam:`integration` · scenario:`SCENARIO-0028`
- AC-3: The AP atomically meters the final use and retains the exact token,
  payload, media type, digest, and host delivery identity before `202`. Store
  failure reports no acceptance. · impact:`cross-surface` ·
  seam:`process-level` · scenario:`SCENARIO-0028`
- AC-4: A lost `202` survives resource and AP reconstruction and retries the
  exact token-payload pair with a fresh HTTP proof. Exhausted `429` settles the
  one-use unknown outcome without another inbox record or mutation. ·
  impact:`journey` · seam:`e2e` · scenario:`JOURNEY-0003`

**Sources:** Events lines 346-437, 582-607, 697-719

**Status:** done

## STORY-0021

**Epic:** EPIC-004
**Title:** Independently validate and act on the retained payload

**As an** agent
**I want** exact document, token, payload, and local-context verification
**So that** AP custody cannot weaken the event contract before action

**Acceptance criteria:**

- AC-1: The non-normative adapter passes the AP's exact retained token, payload,
  media type, digest, and trusted host delivery context without reserialization.
  It acknowledges only after durable terminal agent disposition. ·
  impact:`journey` · seam:`process-level` · scenario:`SCENARIO-0029`
- AC-2: Before action the agent independently verifies the event token,
  audience, expiry, `(AP issuer,eid)` context, retained document digest,
  content type/digest, JSON decoding, and the selected AsyncAPI message schema.
  · impact:`journey` · seam:`e2e` · scenario:`JOURNEY-0003`
- AC-3: Exact duplicates, AP/adapter/agent reconstruction, and crash after
  durable dispatch admission retain the M5 action/reconciliation semantics and
  perform at most one action under `(resource issuer,AP issuer,eid)`. ·
  impact:`cross-surface` · seam:`process-level` · scenario:`SCENARIO-0029`
- AC-4: Invalid, expired, unknown-context, wrong-document, wrong-media-type,
  digest-mismatched, or schema-invalid deliveries never dispatch an action and
  reach a durable refusal before adapter acknowledgement. ·
  impact:`cross-surface` · seam:`process-level` · scenario:`SCENARIO-0029`

**Sources:** Events lines 438-456, 592-624, 705-719

**Status:** done

## STORY-0022

**Epic:** EPIC-004
**Title:** Close M6 without broadening its evidence

**As a** maintainer
**I want** source coverage and public claims to name the exact supported profile
**So that** one complete protected payload path is not mistaken for general
Events or AsyncAPI conformance

**Acceptance criteria:**

- AC-1: README, journal, source coverage, roadmap, and executable evidence state
  that M6 proves one protected, one-use, JSON payload profile; the direct-body,
  media-type, AsyncAPI security, and bodyless registration choices are explicit.
  · impact:`local` · seam:`integration` · scenario:`SCENARIO-0030`
- AC-2: Multi-event replay identity, standardized AP-agent transport, general
  AsyncAPI/YAML/external-reference support, registration-body schema mapping,
  and lost-success protected-registration reconciliation remain visibly
  unsupported. · impact:`local` · seam:`integration` ·
  scenario:`SCENARIO-0030`
- AC-3: All impacted scenarios and the M3/M4/M5 sentinels pass under race, vet,
  build, source verification, and artifact validation before closure. ·
  impact:`journey` · seam:`e2e` · scenario:`SCENARIO-0030`

**Sources:** Events lines 297-580, 592-624, 697-725

**Status:** done
