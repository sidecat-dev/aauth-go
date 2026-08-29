# AAuth Go implementation journal

This journal records executable implementation findings for the independent Go
library. It is not a conformance claim, an upstream commitment, or task
authority. Candidate protocol feedback remains separate until backed by a
reproducible behavior.

## Source basis

The current implementation is checked against the locally retained editor
sources:

| Source | Pinned identity | SHA-256 |
| --- | --- | --- |
| AAuth core | AAuth `a99d353cf18aee81d0c5445bac070164fb3b8bc5` | `c984278f21e3931f0cc272d6768b84bcc471f8ab4a1a1922dd92940a91df7e19` |
| Signature-Key | signature-key `0ff751b571e7fe51336bcc1e526954a202317cc0` | `335c6164569fc5b21aae7930c83c4088e4c02b857f9f3acee8335f16f23d66cb` |
| R3 | AAuth source above | `dd768a3b7417c45c0028f2750a50173670fd84c8f432e54ba94799ca93621760` |
| Events | AAuth source above | `6ac4f1c649172a359a6ef32380b189a4edcd9855014bbb03fefe096b74802eb0` |
| Bootstrap | AAuth source above | `ebfe4858e9511020ceb498aea997953b8b79594689ce177ba228230c3ceaf872` |
| Budgets | AAuth source above | `7a27351888d04a4d1059dd9a261243d0960bcc4d918705641b1d9e68c90d4a4d` |
| Interoperability profile | AAuth source above | `ee503da3ea6803370cffe03171f600d44bf9c81a05872b2014b01a61982fe195` |

Entries below retain the source basis and verified boundary they had when they
were written. A historical green journey is not silently promoted to current
coverage; `SOURCE-COVERAGE.md` and `INTERPRETATIONS.md` carry the current
disposition.

Earlier exercised Go implementations are implementation-experience
comparators. Unexercised BEAM source may be consulted as code archaeology, but
provides no conformance evidence. Neither defines compatibility requirements
for this library.

## 2026-08-29

### Core token evidence and authorization-member recognition

- Every Core token verifier now returns invalid-zero, copy-safe
  `VerifiedToken[T]` evidence bound to the exact compact token, selected issuer
  key, profile, and one trusted verification instant. Typed claims are
  defensive projections rather than the verification result itself.
- One source-defined catalog recognizes every current R3 and Budgets Core-token
  member, enforces token applicability and required co-presence, and rejects
  unsupported companions before key resolution or role policy. The removed
  `r3_conditional` form remains only as a negative vector.
- Exact R3 documents, operation sets, vocabularies, display values, and digests
  now have one public owner in `r3`. Events and reference stores import that
  package directly; root forwarding names are absent. Callable authorization
  enters only through the explicit companion composition below.
- Events AsyncAPI contracts and both Events discovery paths now have one public
  owner in `events`. Root Core imports neither `events` nor `r3`; reference
  composition imports the owning packages directly. Event-token ownership is a
  later dependency-ordered change, not a claim of this increment.
- Core evidence now exposes defensive exact values for structurally complete
  R3 and Budgets members. Existing endpoints explicitly reject unresolved
  companion members; Core verification alone never upgrades them into callable
  authority.
- `r3.ValidateResourceToken` and `r3.ValidateAuthToken` return invalid-zero,
  sealed results bound to the exact Core evidence. They validate the current
  R3 URI, digest, grant, per-call vocabulary, operation shape, and disjointness
  rules. They do not fetch a document, run policy, or authorize an effect.
- A clean external module performs Core verification followed by R3 validation
  using only public APIs. Malformed R3 values retain typed member-specific
  failures, while reference endpoints without an R3 consumer continue to fail
  closed before policy or consequence.

### Immediate four-party R3

- `AuthTokenCompanion` requires invalid-zero companion evidence carrying the
  same Core evidence identity. Core rejects nil and wrong-token results; the
  deployment remains responsible for selecting the correct companion
  validator rather than a permissive callback.
- A direct resource-selected document must contain exactly the agent-requested
  operation set. Exact bytes and the precise PS/AS reader identities are
  retained atomically before token release and survive resource reconstruction.
- The PS and AS fetch independently with signed `jwks_uri` server requests and
  verify the exact SHA-256 digest before review or grant policy. Changed bytes
  fail before either policy can issue authority.
- The AS partitions only operations drawn from the verified document into
  direct and per-call sets. The agent rejects either set outside its request,
  and the resource refuses an ungranted operation before replay consumption or
  host consequence.
- Direct AS issuance commits the required audit fields and exact auth-token
  response in one private record before release. Exact retry after a lost
  response and AS reconstruction returns the same token without rerunning
  trust or grant policy; a conflicting record refuses.
- One `401` per-call journey constructs and retains an exact one-operation
  proposal before challenge release. The PS and AS retrieve and evaluate that
  proposal through the same signed-reader boundary as the initial document.
- The resource recovers the exact earlier person-token JTI from its retained
  resource-token lineage. Inline JSON parameters compare structurally; digest
  parameters compare against the exact presented bytes. Changed parameters
  fail before the provider is called.
- The provider receives one deterministic execution key. The resource retains
  the successful JSON response before release, prevents a concurrent retry
  from invoking the provider, and returns the exact result after response loss
  and resource reconstruction. A pending record can be reclaimed after restart
  with the same provider key.
- Deferred `202` delivery, a same-process PS/AS topology, R3 caching, and
  three-party R3 remain unclaimed.

### Composable issuance and immediate four-party Budgets

- Core `TokenDraft` values preserve the existing Core claim bytes, accept only
  complete member sets from the closed authorization catalog, append companion
  members in canonical name order, and sign the composed payload once. Typed
  R3 and Budget binders compose on the same draft; a clean external-module test
  verifies both results against one exact resource token.
- The standalone `budgets` package owns strict integer Budget and consumption
  values, denomination-preserving narrowing, token-member validation bound to
  Core evidence, and RFC 9651 `AAuth-Budget` parsing and formatting. It does not
  own role policy, durable stores, provider execution, or Core token signing.
- One immediate four-party journey narrows a request of 10 to a resource offer
  of 5 USD, a PS grant of 3, and an AS grant of 2. Each role sees defensive
  consumption evidence, and every boundary rejects widening or a denomination
  change before issuing its token.
- The reference resource derives a stable provider key from the signed auth
  token and deployment call identity. It atomically reserves the declared
  maximum before invoking the provider, prevents concurrent oversubscription,
  settles the actual cost, and releases the difference. A conflicting retry
  cannot create a second provider identity by changing local pricing or policy.
- A successful JSON result and cost are retained before response release. An
  exact signed retry after response loss and reconstruction returns that result
  before fresh protected policy or pricing. An ambiguous provider failure keeps
  the reservation because the resource cannot prove that no consequence
  occurred.
- An insufficient maximum is refused before provider execution with the exact
  current remainder and required maximum, a fresh resource-token offer, and an
  auth-token requirement reason. Resource-token lineage custody is shared by
  R3 and Budgets rather than implemented by either companion.
- Metadata-driven Budget discovery, the general recent-consumption selection
  algorithm, usage counters, streaming trailers, billing interaction, deferred
  Budget authorization, and broader deployment topologies remain unclaimed.

### Protected-resource auth-token challenge

- An auth-token resource now admits a person-token-signed protected call as the
  current baseline challenge entry. It verifies the directed token and request,
  maps the exact required scopes, consumes the request proof, and returns a
  short-lived resource token in `requirement=auth-token` without running local
  protected policy or the host operation.
- The reference agent verifies the challenge token's resource, confirmation
  key, person-server namespace, directed subject, presented person-token JTI,
  mission, tenant, absent account, scope shape, and expiry before contacting
  its PS. It then uses the existing immediate PS/AS exchange and retries the
  same method, target, body, and media type under the resulting auth token.
- A distinct-server body-bearing journey proves that the protected consequence
  runs once, only after both PS and AS policy. Substitution tests reject every
  person and request-context binding before the token exchange.
- A configured Budget resource can place its default offer in this challenge.
  Deferred `202` challenge delivery, automatic person-token acquisition, R3
  challenge selection, and step-up from an existing auth token remain
  unclaimed.

## 2026-08-28

### Incomplete callable R3 authorization removed

- Current R3 authorization remains unclaimed. The public token, policy,
  Resource, Person Server, Access Server, and Agent APIs expose no direct-R3
  authorization path.
- Correctly signed tokens that carry unsupported R3 authorization members are
  rejected before policy, replay admission, or an operation effect. Removing
  typed fields does not turn an R3-bearing token into a scope-only token.
- The module retains current neutral R3 document values, exact-byte digests,
  and the document store used by Events. Those values do not authorize a call.
- A future R3 implementation must enter as one complete current path with
  PS-and-AS document retrieval, per-call proposal custody, grant enforcement,
  and audit-atomic issuance.

## 2026-08-03

### Protected one-use JSON Events profile

- **Status: implemented and qualified as one protected, one-use, direct-JSON
  vertical; not general Events or AsyncAPI conformance.** An authenticated
  resource operation commits a 256-bit opaque ticket before releasing its URL.
  Durable authority retains only the ticket digest plus the exact agent,
  authorized call, resource revision, contract digest, operation/message,
  expiry, and active window.
- The agent retains the exact admitted AsyncAPI 3.0.0 JSON bytes before sending
  a bodyless signed registration. Ticket validation, optional covered-body
  validation, consumption, and resource subscription creation are one atomic
  store transition. Wrong, expired, replayed, incomplete, colliding, or
  uncustodied ticket paths create no subscription.
- The selected AsyncAPI subset has one parameterized channel, one `receive`
  operation, one local message reference, `application/json`, and one inline
  compilable JSON Schema Draft 7 payload. Remote references, YAML, ambiguous selections,
  operation security, and generalized AsyncAPI modeling are not supported.
- One complete JSON body is the event payload; it is not a JWT claim. The
  resource validates against the subscription's digest-pinned document and
  commits exact token, payload bytes, media type, and digest before transport.
  The AP verifies signed content metadata and atomically commits the final use
  and exact inbox pair before `202`. A lost success survives reconstruction and
  settles through exact retry plus `429` without a second record.
- The non-normative adapter carries the AP's exact retained bytes to the agent.
  The agent independently verifies the event token, local context, exact
  contract digest and selection, media type, payload digest, JSON syntax, and
  schema before durable dispatch. Reconstruction preserves pending and unknown
  action outcomes, and terminal duplicates perform no second action.
- Protected ticket support is a separate optional authority interface. The
  included AP, resource, and agent file stores accept and write only their
  current canonical records; obsolete record versions are rejected rather
  than migrated or upgraded. Resource identity is atomically
  compared during ticket consumption, and constructor-time route validation
  prevents conflicting or templated deployment endpoints from reaching
  `ServeMux`.
- Agent contract custody uses exact byte encoding rather than JSON
  reserialization. The default per-record file bound has explicit headroom for
  the maximum admitted 1 MiB contract plus local context and its versioned
  envelope; boundary reconstruction is executable evidence.
- **Still open:** multi-event replay identity, standardized AP-agent transport,
  registration-body schema derivation, lost-success protected-registration
  reconciliation, general AsyncAPI/YAML/external-reference support, and
  distributed or multi-writer host stores.

## 2026-07-29

### HTTP signature error wire contract

- **Status: implemented for the selected Ed25519 profile.** `VerifyRequest`
  now returns a typed `SignatureError` that preserves its cause for
  `errors.Is` and `errors.As`. The selected path distinguishes malformed or
  missing proof material, missing covered components, unsupported algorithms,
  invalid or unknown keys, invalid or expired JWT credentials, and invalid
  signatures.
- Optional RFC 9421 `expires` parameters are signed and verified alongside the
  existing mandatory `created` window. A future expiry is accepted; an expiry
  at or before current time is refused.
- Reference signature-verification failures return `401` with an RFC 8941
  `Signature-Error` header and an RFC 9457 Problem Details body whose type is
  the Signature-Key draft's matching `urn:ietf:params:sig-error:` URI. The
  header is the client parser's required authoritative input. Local discovery
  denial or unavailability is a sanitized `503`, while successful
  authentication followed by policy denial remains `403` without either
  signature negotiation or Signature-Error.
- Key resolvers now return typed unknown, invalid, denied, and unavailable
  classifications. Only a successfully consulted key set that lacks the
  requested key becomes `unknown_key`; operational resolution failures are not
  mislabeled as client authentication failures or exposed in response detail.
- Initial issuer-key absence and disappearance after a same-`kid` refresh
  remain `unknown_key`. A valid JWT carrying an unusable confirmation key is
  instead `invalid_key`; malformed JWT structure or signature remains
  `invalid_jwt`.
- Concurrent discovery callers share one in-flight fetch. Genuine remote
  failures participate in the one-minute refresh floor through bounded
  negative state, while caller cancellation and local egress denial never
  poison healthy callers. A stale matching cached key remains available to an
  ordinary lookup after a remote failure, but a forced retry cannot silently
  reuse key material whose signature was already shown invalid.
- **Source ambiguity recorded:** the AAuth core profile maps missing signature
  headers to `invalid_request`, while the Signature-Key draft groups missing
  signature headers under `invalid_signature`. The reference AAuth endpoints
  follow the core profile's code and its required `401` status; malformed
  supplied signature material maps to `invalid_signature`.
- RFC 9421 derived-component construction preserves the case-sensitive HTTP
  method and normalizes authority host case and default ports. Signature-Error
  parsing and serialization use a complete RFC 8941 implementation, including
  field-line combination, strict strings, and ignorable future members and
  error-code registry entries.
- Covered HTTP fields combine all field-line values in wire order before
  signature-base construction. Required component and freshness checks finish
  before key resolution, so malformed or insufficient proof cannot trigger
  discovery effects.

## 2026-07-27

### Resource-managed `AAuth-Access`

- **Status: implemented and qualified for immediate authorization.**
- The reference resource can authorize directly without a PS, AS, or resource
  signing key and advertises `access_mode=aauth-access-token`.
- The opaque grant is retained by the resource and bound to the verified agent
  identifier, confirmation-key thumbprint, granted scope, subject, mission
  reference, and an expiry no later than the agent token.
- `Authorization: AAuth` is signed as a covered component. Unsigned use,
  credential substitution after signing, proof replay, an unknown or expired
  token, and presentation by another agent key are refused before the protected
  operation.
- The agent validates exactly one token68 credential, records the scope actually
  granted by the resource, and adopts a replacement `AAuth-Access` value on any
  later response.
- An earlier Go implementation confirmed the token68, covered-authorization,
  and replacement-token behaviors. This standalone implementation adds the
  resource-side grant and refusal path without importing another product.
- Deferred `202` interaction and polling were added in the following tranche.

### Existing complete paths

- **Status: implemented verticals, not full conformance.**
- Three-party mission authorization, parent-mediated single-level sub-agents,
  four-party PS-to-AS federation, and a two-resource three-party call chain run
  through real HTTP handlers, Ed25519 proofs, JWT verification, admitted
  metadata/JWKS discovery, policy callbacks, and protected operations.
- A retained BEAM/OpenSSL mission fixture proves exact-byte mission hash
  interoperability.
- Four-party call chaining, generic deferred responses, R3, Events, Bootstrap,
  and remaining Signature-Key schemes are still open.

### Resource-managed deferred interaction

- **Status: implemented and qualified for the resource-hosted interaction
  path.**
- The resource returns a validated Structured Field
  `requirement=interaction`, same-origin pending URL, `Retry-After`, and
  `Cache-Control: no-store`. The agent performs signed GET polling, locally
  enforces the polling interval, and adds five seconds after `429 slow_down`.
- Pending URLs carry 128 random bits. Human codes carry the required 40 random
  bits, use Crockford base32, accept case and `I`/`L`/`O` transcription aliases,
  expire with the pending request, are single-use, and terminally fail after
  three incorrect attempts.
- A valid code only enters the interaction and exposes the request context. A
  separate trusted application call approves or rejects it; approval reruns
  resource policy. Polls and delivered grants remain bound to the initiating
  agent and confirmation key.
- Terminal success, user denial, expiry, invalid-code failure, and already-gone
  continuations are one-shot. RFC 9457 responses are decoded into typed Go
  errors.
- The earlier Go implementation supplied useful requirement and
  interaction precedent but had known current-draft gaps: 32-bit hexadecimal
  codes, development-only HTTP acceptance, `200` for still-pending polls, and
  rejection of otherwise ignorable non-token extension parameters. This
  implementation does not retain those behaviors.
- Generic deferred handling at the AS, callback redirects and their terminal
  error mapping, interaction relay, clarification actions, and durable
  external pending-state custody remain open.

### Person-server deferred interaction

- **Status: implemented and qualified for the PS-hosted three-party path.**
- The agent sends `Prefer: wait=0` to the token endpoint and accepts either a
  direct auth-token grant or a same-origin pending continuation. Every poll is
  a signed GET bound at the server to the same top-level agent and confirmation
  key as the initial request.
- Before creating pending state, the PS verifies the agent proof, resource
  token, audience, scope, mission, and cross-token agent/key bindings. It
  retains those verified inputs with an expiry no later than either input
  token. Deployment authorization policy does not run until a valid
  interaction code has correlated a browser session and a separate trusted
  application call approves the request.
- The executable journey covers exact initial-proof replay refusal, another
  agent's poll refusal, early-approval refusal, code aliasing and single use,
  policy invocation only at trusted approval, terminal auth-token issuance,
  use at the protected resource, denial, expiry, three-attempt invalid-code
  failure, and one-shot terminal responses.
- Client polling now also applies `503 Retry-After` and continues to add five
  seconds after every `429`, in addition to enforcing the local not-before
  time before making another network call.
- The reconciled feedback history now lives in `SPEC-FEEDBACK.md`. This tranche
  did not produce a new protocol finding; it implements the deferred rules
  already recorded there without re-raising reconciled feedback.
- Clarification POST actions, interaction relay/callback, and durable external
  pending-state custody remain open.

### Access-server deferred interaction through the person server

- **Status: implemented and qualified for the four-party AS-hosted path.**
- The AS verifies the PS's `jwks_uri` request proof, configured PS trust, agent
  and optional sub-agent tokens, resource-token audience, agent/key binding,
  mission approver, and scope before creating pending state. Its pending URL is
  bound to the same PS identifier and signing-key thumbprint.
- The AS interaction code is correlation only. AS deployment policy runs only
  after code entry and a separate trusted AS approval; a PS approval method is
  explicitly refused for AS-owned pending work.
- The PS does not hand the AS pending URL to the agent. It creates a distinct
  random PS continuation bound to the initiating agent/key, relays the AS
  interaction requirement, and signs downstream polls with its own discovered
  identity. A terminal AS auth token is accepted only after the existing
  issuer, discovery document, audience, agent, key, scope, mission, and actor
  checks pass.
- The vertical exercises PS-to-AS `429` slowdown propagation without an early
  downstream poll, unsigned AS-poll refusal, ownership-bound approval,
  terminal success and protected use, denial, expiry, three-attempt
  invalid-code failure, and one-shot terminal responses across the proxy.
- The implementation uses the Signature-Key dependency's defined
  `id`/`dwk`/`kid` `jwks_uri` parameters. The conflicting core-draft example is
  already recorded as N2 in the reconciled workspace feedback; this is
  corroborating implementation evidence, not a new finding.
- Clarification/updated-request/cancel actions, resource-initiated callback
  chaining, PS interaction relay, durable pending storage, and four-party call
  chaining remain open.

### Deferred delegation clients

- **Status: parent-mediated sub-agent path implemented vertically; chained
  client result implemented but propagation through an intermediary resource
  remains open.**
- `RequestSubagentTokenAuthorization` returns the same immediate-or-pending
  result used by top-level agents. The parent signs both the initial PS request
  and every poll, while the retained validation context requires the terminal
  grant to remain bound to the sub-agent's identifier and key and to name the
  parent in `act.agent`.
- The executable journey covers an immediate sub-agent grant followed by a
  deferred grant in the same real AP/agent/PS/resource system. Policy does not
  run for the deferred request until trusted PS approval; the sub-agent then
  uses the terminal token at the protected resource.
- `RequestChainedTokenAuthorization` likewise preserves a `202` instead of
  collapsing it into an error. Immediate methods refuse a deferred result and
  direct callers to the continuation API.
- Full call-chaining deferral still requires the intermediary resource to
  create its own caller-facing pending URL, propagate the downstream
  interaction, finish the downstream operation, and deliver the original
  result. A client method alone is not claimed as that vertical.

### Local-action permission and mission audit

- **Status: immediate and PS-deferred permission plus mission-bound audit are
  implemented vertically.**
- The agent signs permission and audit request bodies with its agent token.
  The PS verifies the HTTP signature, content digest, agent token, proof replay,
  mission approver, exact retained mission hash, active status, and mission
  ownership before policy or custody changes.
- Permission works with or without a mission. Deployment policy receives the
  verified agent, a defensive request copy, and—when present—the exact approved
  mission bytes, approved tools, capabilities, and prior ordered mission log.
  Immediate grants and denials use the draft response shape.
- A permission policy can require user interaction. The pending URL is random,
  same-origin, signed-poll only, and bound to the initiating agent and key. The
  interaction code is correlation only; a separate trusted host call evaluates
  policy. The journey proves another agent's poll refusal, early-approval
  refusal, terminal grant and denial, one-shot delivery, and refusal when a
  mission terminates after approval but before delivery.
- Mission-bound permission requests and terminal responses are separate
  immutable ordered entries. Audit requires a mission and appends the exact
  signed request before returning `201 Created`. Snapshot callers receive
  defensive copies, so mutations cannot alter retained custody.
- The host can perform the two-state termination transition defined by the
  draft's mission-management boundary. Later permission and audit requests
  return `mission_terminated` with `mission_status=terminated`.
- The earlier Go implementation supplied useful request shapes, signed
  endpoints, and JSONL log precedent, but accepted arbitrary mission
  references without proving they were retained, active, or owned by the
  signing agent. The BEAM implementation explicitly left this area open. The
  standalone path keeps the useful shapes and closes those authorization
  gaps; neither comparator defines its package boundary.
- At this checkpoint the reference custody was in memory; the following
  tranche adds restart-safe mission/permission custody. Agent-requested
  completion through the interaction endpoint, token/interaction/clarification
  entries in the same mission log, and a general recorder for missionless
  permission requests remain open. No new protocol feedback was found;
  existing workspace feedback was not re-raised.

### Restart-safe governance custody and request proof evidence

- **Status: mission and permission governance state has an injectable durable
  contract and a qualified single-writer file adapter.**
- Mission permission/audit request entries now retain the exact body plus the
  verified HTTP signature headers, presented `Signature-Key` credential,
  request method/authority/target, content digest, verified public-key snapshot,
  signature and verification times, and replay identity. This follows the
  draft's key-rotation guidance: attribution evidence is captured while the
  issuer key is still live instead of assuming later JWKS discovery will work.
  The credential and signatures are explicitly sensitive custody.
- `reference.GovernanceStore` is an opaque snapshot boundary that a Sidecat
  store or another host can implement without introducing a Sidecat dependency.
  The included file adapter is private (`0600`), bounded, single-writer, and
  publishes with temporary-file write, file sync, rename, and directory sync.
- The snapshot envelope binds a deterministic state payload with SHA-256.
  Loading is strict and fail-closed: schema, PS identity, exact mission hash and
  blob fields, two-state lifecycle/log agreement, contiguous log sequences,
  request/body digest evidence, public keys, permission state transitions,
  pending IDs/codes/ownership, and replay expiries are validated. Empty,
  loosely-permissioned, truncated, corrupted, or cross-server snapshots are
  refused rather than treated as fresh state.
- Mission creation, log append, termination, permission code correlation,
  trusted approval/rejection, and pending terminal delivery save their state
  before success is exposed. A terminal permission response and its mission-log
  entry are one snapshot transition, so restart cannot revive a served URL or
  lose the corresponding decision. Definite save failure rolls back memory;
  publication with unproven directory-sync durability returns
  `ErrGovernanceStateUncertain` and deliberately retains the candidate state
  instead of lying by rolling back to a known-stale value.
- The restart journey creates a mission and deferred permission, reconstructs
  the PS, refuses the exact proof replay, resumes signed polling and code
  correlation, grants and audits, reconstructs again, proves the served URL
  remains gone, concurrently appends signed audits with contiguous ordering,
  injects definite and uncertain save failures, persists termination, and
  refuses post-termination work. It then rejects cross-server reuse, corrupts
  a real valid snapshot, and proves startup fails closed.
- Replay admission and its corresponding mission, permission, or audit record
  now share one durable transition. A definite save failure rolls both back, so
  the exact signed request can be retried; the test proves this for permission
  and audit. Long-term records remain valid after the short replay cache expires
  and is pruned.
- **Protocol finding earned:** a lost audit `201` cannot be reconciled. The
  executable test commits the audit, drops the response, then shows that a
  freshly signed retry creates a second indistinguishable entry. The request
  has no stable identifier, so content deduplication would also collapse
  legitimate repeated actions. This is recorded as N6 in the reconciled
  workspace feedback.
- This custody covers PS missions, permission continuations/tombstones, and
  their replay proofs. All permission requests, including missionless requests,
  now have an ordered durable request/terminal-response record. Token/AS/resource
  pending state, agent-requested mission completion, and the remaining
  mission-log event families remain open.

### Mission completion, clarification, and durable interaction custody

- **Status: the mission-completion interaction is implemented vertically and
  qualified across restart.**
- The agent signs a `type=completion` request containing a Markdown summary and
  exact mission reference. The PS admits it only for the signing agent's
  retained active mission, binds the random continuation to that agent and
  confirmation key, records the verified request proof and replay identity,
  and returns a deferred approval requirement.
- A trusted in-process host boundary can request clarification or accept
  completion. Clarification questions and signed
  `action=clarification_response` answers enter the same ordered mission log;
  the five-round recommendation is enforced. An expired continuation refuses
  both late agent answers and late host acceptance.
- Acceptance records the terminal interaction response, decision actor, and
  mission termination in one governance snapshot before it becomes visible.
  Definite store failure rolls back initial proposal admission, host
  clarification, signed clarification response, and terminal acceptance.
  Publication uncertainty retains the candidate state under the same contract
  as the other governance transitions; reconstruction proves the accepted
  completion remains deliverable.
- The snapshot now includes global interaction history and completion
  continuations as well as mission-local entries. Loading revalidates exact
  request bodies and digests, proof context, mission ownership, pending links,
  state transitions, clarification rounds, terminal response kinds, and
  cross-record relationships. A checksum-valid snapshot with a mismatched
  interaction/pending link is refused.
- The executable journey covers another agent/key being unable to poll or
  answer, exact clarification replay refusal, restart before clarification,
  restart before acceptance, a durable-save rollback, successful acceptance,
  terminal delivery, expiry during polling, expiry before a clarification
  answer, a five-round clarification limit, and fail-closed semantic
  corruption. The type-aware client accepts the draft's empty `200 OK`
  completion response and its `{"answer": ...}` question response shape.
- **Protocol finding earned:** the required pending-URL lifecycle makes a lost
  terminal response unrecoverable. The test durably accepts completion, lets
  the server return the terminal `200`, drops it in the transport, and observes
  the required `410 Gone` on the next signed poll. The agent cannot distinguish
  that case from a terminal result consumed elsewhere and never learns whether
  the mission completed. This is recorded as N7 in the reconciled workspace
  feedback; no proposal has been sent upstream.
- General interaction/payment relay, question delivery, updated-request and
  cancel actions, callback chaining, and persistence for the token/AS/resource
  pending families remain open. The completion implementation uses only the
  standalone public package and reference package; consuming applications are
  not dependencies.

### Protected host signing boundary

- **Status: the standalone library can sign through caller-owned protected key
  custody without importing or depending on a consuming application.**
- `NewSigningKey` accepts the standard `crypto.Signer` capability, verifies
  that it exposes the mandatory Ed25519 public key, and derives the public JWK
  without requesting private bytes. `NewEd25519SigningKey` remains the
  convenient in-memory constructor and delegates to the same checked path.
- An executable test signs a real AAuth HTTP request through a recording
  external signer and proves that the caller-held capability, rather than a
  copied private key, performed the signature. A host can back this seam with
  protected-value custody and access receipts.

### Runnable durable person-server process

- **Status: a standalone person-server process is implemented and qualified
  over real TLS and process restart.**
- `aauth-reference serve person --profile FILE` composes the public
  `reference.PersonServer` with an explicit trust map, deployment-owned
  action/scope policy, TLS 1.3, and the single-writer file governance store.
  It has no host-application import or runtime dependency.
- Startup refuses unknown profile fields, noncanonical custody paths,
  symlinked parents or files, multiply linked files, non-`0600` sensitive
  files, foreign ownership, an unprotected governance directory or existing
  snapshot, invalid trust keys, and a TLS leaf that does not cover the AAuth
  identifier. Diagnostics identify the invalid boundary without printing
  secret material.
- The executable journey builds and starts the binary, connects the standalone
  agent client over certificate-verified HTTPS, creates a mission, obtains a
  local-action permission, records an audit, and observes a policy denial for
  an unlisted action. It then shuts down with SIGTERM, starts a new process
  against the same snapshot, reuses the exact prior mission for another
  permission and audit, and proves the private state advanced.
- This process makes the person-server role independently operable and gives
  any host a genuine peer to consume. It does not turn the conservative static
  JSON policy into a general policy language or claim production key
  provisioning, service supervision, multi-writer state, or full AAuth
  conformance.

### Maintained source coverage

- **Status: the implementation's supported profile is bound to pinned source
  bytes, a complete source-section inventory, and executable Go evidence.**
- The manifest pins the current local core, Signature-Key, R3, Events,
  Bootstrap, Budgets, and interoperability-profile sources by exact revision,
  filename, format, and SHA-256. The generated inventory records all 600
  headings, so a
  newly added, removed, retitled, or reparented section is a review event
  instead of disappearing outside the checklist.
- Claims are deliberately section-specific. The generated report records the
  current exercised, partial, unsupported, and unclaimed totals. An exercised
  label binds only the adjacent written claim to its
  named test; it is not a full-section or full-draft conformance assertion.
- The embedded contract and `SOURCE-COVERAGE.md` are checked for exact
  agreement during `go test ./...`. Evidence verification parses the named Go
  files and rejects missing test functions. Source verification rehashes the
  maintained inputs and reconstructs their full section inventory.
- `aauth-reference verify coverage --source-dir DIR --repo DIR` exposes the
  same checks as a bounded standalone command and emits a machine-readable
  success record. The internal generator is the intentional update path; no
  source refresh or claim change can silently rewrite the pinned manifest.
- This mechanism creates an honest maintained-current-source loop without
  importing an upstream repository, making an upstream commitment, or
  treating the 557 unclaimed current sections—including the person-token
  topology, current R3, and Budgets—as implicitly supported.

### Historical Elixir interoperability fixtures

- **Status: retained historical negative evidence; no current
  bidirectional-interoperability claim.**
- At the exact historical BEAM revision
  `6fc87c6316583e94088cb7c72722d65fe5f11edc`, the two implementations exchanged
  deterministic agent-token and signed-request vectors for an earlier source
  profile. Those vectors use the removed `AAuth-Mission` request header and the
  now-prohibited polymorphic `EdDSA` identifier.
- Current Go tests retain and reject those exact bytes as
  `unsupported_algorithm`. A new cross-implementation claim requires another
  independently generated current person-token journey in both directions.
- The Go library and executable have no Elixir or host-application dependency. Elixir is
  invoked only when a maintainer deliberately regenerates or verifies an
  interoperability vector.

### Enrolled-install bootstrap and key delegation

- **Status: the informational bootstrap refresh patterns are implemented as a
  complete standalone AP/client journey.**
- The root package implements the exact selected Signature-Key profiles for
  OKP/Ed25519 `hwk` and mandatory `jkt-s256+jwt`. A JWK Thumbprint JWT carries
  the durable identity key in its protected header, binds `iss` to that key's
  RFC 7638 SHA-256 URI, validates `iat` and `exp`, and delegates HTTP signing
  only to `cnf.jwk`. Verification returns the durable identity and active
  request key as distinct trusted values.
- The reference AP accepts refresh only when an injected enrollment store maps
  the durable thumbprint to a valid stable agent identifier and allowed person
  server. An optional policy sees both verified keys and the selected scheme.
  Replay admission is also an explicit interface so a deployment can provide
  durable or distributed custody; the included memory implementation is
  process-local. The provider rejects a delegation beyond its explicit
  maximum lifetime, which defaults to the client's five-minute delegation
  lifetime.
- The two-key client mints a short-lived delegation with a caller-custodied
  durable signer, signs the request with a caller-supplied ephemeral key, and
  verifies the returned issuer, subject, person server, token signature, and
  confirmation key before returning a usable result. A fresh canonical
  client nonce is covered by the content digest on every refresh. This keeps
  rapid same-key refreshes distinct even when their signature timestamps share
  a clock second, while the provider still refuses an exact retransmission.
  The single-key client signs with the durable key under `hwk` and verifies
  that the same key carries through.
- The vertical rotates through two ephemeral keys while preserving one
  enrolled `sub`, then uses the second token to create a real mission at a
  person server. Separate controls refuse unknown enrollment, exact proof
  replay, expired and future delegations, delegation-signature mutation, and a
  durable-key HTTP proof where the delegated ephemeral key is required.
- At the historical Bootstrap and Signature-Key profile, independent Elixir
  and Go implementations generated and verified `jkt-jwt` request vectors in
  both directions, including durable thumbprint identity, delegated key
  resolution, exact request proof, and Signature-Key mutation controls. Those
  fixtures do not establish current person-token or full-family conformance.
- Source coverage now marks the selected `hwk`, `jkt-jwt`, and refresh
  behaviors exercised. Platform-specific protected key creation/storage,
  enrollment ceremonies, attestation, and identifier-strategy selection remain
  explicit deployment work; no upstream commitment or submission is implied.
