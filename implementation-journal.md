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
- AS-hosted deferral, PS pass-through of AS requirements, clarification POST
  actions, interaction relay/callback, and durable external pending-state
  custody remain open.
