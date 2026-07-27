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
| AAuth core | AAuth `b414033d4c81224034b5b419216ae06706ede660` | `2c3650d33caf44ac6c614042edc7094a59146ce01805641eb197759de0aa01d1` |
| Signature-Key | signature-key `84f2d831e22741435660c1f160344d98c69db4d1` | `ba315a13ee30ad249a5130fb67838c23667a13c7c6d46766096a263e8e1d23c4` |
| R3 | AAuth source above, revision 01 | `752a72b44f06d457c454f2d187d43352482e2f7ce78a196d1c7fafcf66ea141c` |
| Events | AAuth source above, revision 00 | `987b4354d14c72d741e4d1d3f51ecb9724bfc57a5eb01eacc92bfd7c27644f37` |
| Bootstrap | AAuth source above, revision 01 | `27eecfd9b96de86558203684d285a1d14f135d6bd135d550ffa2d3afb1af9355` |

The Sidecat Go and BEAM implementations are implementation-experience
comparators. They do not define compatibility requirements for this library.

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
- Existing Sidecat Go work confirmed the token68, covered-authorization, and
  replacement-token behaviors. The standalone implementation adds the
  resource-side grant and refusal path; no Sidecat package is imported.
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
- The earlier Sidecat Go implementation supplied useful requirement and
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
- The prior Sidecat feedback authority is
  `/home/jgay-automate/workspaces/sidecat-workspace/aauth/`. This tranche did
  not produce a new protocol finding; it implements the deferred rules already
  recorded there without re-raising reconciled feedback.
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
  collapsing it into an error. The older immediate convenience methods remain
  source-compatible and return an explicit instruction when a caller must use
  the continuation API.
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
  standalone public package and reference package; Sidecat is an intended
  consumer, not a dependency.

### Protected host signing boundary

- **Status: the standalone library can sign through caller-owned protected key
  custody without importing or depending on Sidecat.**
- `NewSigningKey` accepts the standard `crypto.Signer` capability, verifies
  that it exposes the mandatory Ed25519 public key, and derives the public JWK
  without requesting private bytes. `NewEd25519SigningKey` remains the
  convenient in-memory constructor and delegates to the same checked path.
- An executable test signs a real AAuth HTTP request through a recording
  external signer and proves that the caller-held capability, rather than a
  copied private key, performed the signature. This is the portability seam
  Sidecat can back with its own protected-value custody and access receipts.

### Runnable durable person-server process

- **Status: a standalone person-server process is implemented and qualified
  over real TLS and process restart.**
- `aauth-reference serve person --profile FILE` composes the public
  `reference.PersonServer` with an explicit trust map, deployment-owned
  action/scope policy, TLS 1.3, and the single-writer file governance store.
  It has no Sidecat import or runtime dependency.
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
  Sidecat a genuine peer to consume. It does not turn the conservative static
  JSON policy into a general policy language or claim production key
  provisioning, service supervision, multi-writer state, or full AAuth
  conformance.

### Maintained source coverage

- **Status: the implementation's supported profile is bound to pinned source
  bytes, a complete source-section inventory, and executable Go evidence.**
- The manifest pins the current local core, Signature-Key, R3, Events,
  Bootstrap, and interoperability-profile sources by exact revision, filename,
  format, and SHA-256. The generated inventory records all 465 headings, so a
  newly added, removed, retitled, or reparented section is a review event
  instead of disappearing outside the checklist.
- Claims are deliberately section-specific. Fifty-two selected behaviors are
  exercised, eighteen broader sections are explicitly partial, twenty-six
  protocol areas are explicitly unsupported, and the remaining sections stay
  unclaimed. An exercised label binds only the adjacent written claim to its
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
  pretending unimplemented R3, Events, Bootstrap, Signature-Key schemes, or
  other core behaviors are supported.

### Independent Elixir interoperability

- **Status: the selected agent-token, mission-presentation, JWT Signature-Key,
  and RFC 9421 request profile interoperates in both directions with our
  independent Elixir AAuth implementation.**
- At exact `sidecat-beam` revision
  `6fc87c6316583e94088cb7c72722d65fe5f11edc`, the Elixir implementation mints
  a fixed `aa-agent+jwt`, builds an `AAuth-Mission` reference, and signs a real
  GET request. The Go implementation verifies issuer trust, token lifetime and
  claims, confirmation-key binding, covered components, mission syntax,
  signature freshness, and Ed25519 proof from the retained exact headers.
- The reciprocal vector is emitted solely through the public Go package. The
  Elixir implementation independently verifies the Go token, confirmation
  key, mission, and HTTP signature. Both directions change the mission and
  Signature-Key separately and prove that neither modified request verifies.
- Fixed seeds, identifiers, times, token IDs, mission bytes, and request
  targets make both generators byte-deterministic. The fixtures contain only
  public keys, tokens, and signed public request material. The deterministic
  test seeds remain visibly confined to the generators and grant no deployment
  authority.
- This proof uses the source implementations themselves rather than expected
  bytes transcribed from a draft. It is deliberately bounded: it does not
  assert cross-runtime coverage for every token, Signature-Key scheme,
  component, response, interaction, or deployed server role.
- The Go library and executable still have no Elixir or Sidecat dependency.
  Elixir is invoked only when a maintainer deliberately regenerates or
  reciprocally verifies the interoperability vectors.
