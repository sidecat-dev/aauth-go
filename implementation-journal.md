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
- Deferred `202` interaction and polling are not part of this tranche and
  remain an explicit implementation gap.

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
