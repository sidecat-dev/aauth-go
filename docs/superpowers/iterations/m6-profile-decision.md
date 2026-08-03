# M6 protected payload Events profile

**Status:** accepted for implementation on 2026-08-03
**Predecessor:** ITER-0003 M5 look-ahead and the accepted complete-spec-family
program
**Delta:** add one protected, `max_uses: 1`, payload-bearing Events journey;
do not broaden the public M5 profile or claim general AsyncAPI support
**Authority:** operator-delegated Codex approval under the accepted AAuth
implementation program
**Review:** independent source and architecture review completed before code

## Outcome

Qualify one complete real-HTTP path in which an authenticated resource call
creates a short-lived opaque subscription ticket, the same agent consumes that
ticket with a subscribe-token proof, and one JSON event payload survives
resource, AP, adapter, and agent reconstruction through one independently
verified action.

The M5 AP, resource, and agent authorities remain separate. M6 extends their
records and interfaces; it does not move ticket or AsyncAPI policy into token
primitives and does not make the non-normative AP-to-agent adapter a protocol.

## Accepted representation and enforcement

- A resource-owned ticket authority stores only a SHA-256 digest of a
  cryptographically random opaque ticket. Its durable record binds the exact
  authenticated agent, protected operation, deployment-supplied resource-state
  revision, AsyncAPI document digest, protected operation/message selection,
  expiry, and `max_uses: 1`.
- Ticket consumption and resource-subscription creation are one store
  transaction. Validation or commit failure leaves the ticket usable and
  creates no subscription. A successful transaction consumes it once.
- The walking skeleton's protected registration is bodyless. Non-empty
  registration bodies are rejected unless a deployment supplies a separate
  validator that owns media type, byte limit, schema/version identity, and
  exact-body validation. Such bodies require signed `content-type` and
  `content-digest` before ticket consumption.
- The resource publishes one exact JSON AsyncAPI 3.0.0 document through the
  advertised `urn:aauth:vocabulary:asyncapi` R3 value. Exact bytes are
  digest-bound to the ticket and retained through the subscription/event
  lifetime. The selected profile supports local JSON Pointer references only;
  it compiles the inline payload as JSON Schema Draft 7 and performs no
  presenter-directed schema fetch.
- A protected AsyncAPI operation has no operation-level `security` entry, but
  the HTTP registration remains authenticated by the subscribe-token JWT and
  its confirmation-key HTTP signature. The ticket URL is authorization, not
  caller authentication.
- The event token remains payload-free. The complete `application/json` POST
  body is the AsyncAPI message payload. `content-type` and `content-digest` are
  signed, and the AP atomically retains the exact token, exact payload bytes,
  media type, payload digest, and host delivery identifier before `202`.
- The resource retains one exact token-and-payload pending attempt before its
  first send. A lost `202` retries the same pair with a fresh HTTP proof; the
  M5 exhausted-`429` reconciliation remains the selected one-use behavior.
- The agent retains the exact AsyncAPI document/version selected at
  registration, independently verifies the event token, validates the exact
  payload against the selected message schema, and acts once under the existing
  `(resource issuer, AP issuer, eid)` key.

## Source conflicts and explicit profile choices

The pinned Events draft cannot be implemented literally at three points:

1. Event Delivery says the body is the AsyncAPI payload and shows a direct JSON
   object, while Event Discovery calls the schema the `payload` field in the
   POST body and the rationale calls event data a separate `payload`. This
   profile selects the complete direct JSON body shown on the wire.
2. The AsyncAPI example declares `contentType: application/jwt` around a JSON
   object. This profile uses `application/json`; the JWT remains in
   `Signature-Key`.
3. The example uses OpenAPI-style operation security
   `- aauth_subscribe: []`. AsyncAPI 3.0.0 requires Security Scheme Objects or
   references at the operation. The protected operation needs no security
   entry under the Events draft, while `components.securitySchemes` still
   declares the AAuth scheme.

These are selected implementation-profile decisions, not claims that the draft
unambiguously defines them. The registration-body mapping is deliberately not
invented from AsyncAPI channel parameters, which describe address expressions.

## Deferred boundaries

- Multiple independently deduplicable events under one `eid`. The draft
  permits multiple AP uses but tells the agent to deduplicate on `(iss,eid)` and
  defines no per-event identity.
- A standardized AP-to-agent transport.
- General AsyncAPI parsing, YAML, external references, arbitrary protocols,
  generated clients, or every AsyncAPI security scheme.
- Idempotent protected-registration response recovery after a successful
  consume-and-register commit. The source defines a single-use ticket but no
  repeat-success protocol. A lost response is reported as outcome-unknown; it
  is not silently converted into success.
- An AsyncAPI-derived schema for a protected registration body.

## Evidence basis

- Pinned Events source: protected subscriptions 297-344, payload delivery
  346-456, discovery 457-580, security 582-607, rationale 697-725.
- AsyncAPI 3.0.0: channel address parameters, operation security reference
  shape, message `payload`, and message `contentType`.
- Independent review found no need for a new token claim or AP-agent protocol,
  and required ticket digest custody, atomic consume/register, exact payload
  custody, and explicit replay limits.
