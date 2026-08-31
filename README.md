# AAuth for Go

`aauth-go` implements the AAuth editor revisions pinned in
[SPECIFICATIONS.md](SPECIFICATIONS.md) as ordinary Go packages. Applications
compose the protocol roles they need and supply their own policy, keys,
transport, clocks, and storage.

The implementation is incomplete. It is not an official conformance suite,
and independent interoperability has not yet been demonstrated. The exact
claim-to-test matrix is in [CONFORMANCE.md](CONFORMANCE.md).

## Run it

The module requires Go 1.24 or later. It currently uses the checkout-local
module path `aauth-go`; run it from a source checkout rather than treating the
repository as a published `go get` module.

The immediate three-party example runs an Agent Provider, Agent, Person Server,
and Resource over ordinary HTTP handlers:

```sh
go run ./example/threeparty
```

Expected output:

```text
AAuth three-party flow complete: person-123 has records.read
```

Run the standard package tests with:

```sh
go test ./... -count=1
```

## Choose an implemented path

Every example uses generated keys, fixed logical HTTPS origins, and in-memory
stores. The programs are executable documentation, not deployment templates.

| Path | What it demonstrates | Command |
| --- | --- | --- |
| [Direct Agent identity](example/agentidentity) | Agent Provider to Agent to Resource, with no Person Server or Access Server | `go run ./example/agentidentity` |
| [Resource-managed session](example/resourcesession) | Resource-owned interaction and an opaque proof-bound session | `go run ./example/resourcesession` |
| [Immediate three-party authorization](example/threeparty) | Person Server identity and authorization with no Access Server | `go run ./example/threeparty` |
| [Mission-bound three-party authorization](example/mission) | Exact approval, an ordered accepted update, one protected call, and person-accepted completion | `go run ./example/mission` |
| [Deferred Person Server consent](example/psconsent) | A verified request parked for host-authenticated consent and explicit polling | `go run ./example/psconsent` |
| [Four-party authorization variants](example/fourparty) | Missionless federation, then mission approval and update, Access Server issuance, protected use, and person-accepted completion | `go run ./example/fourparty` |
| [Parent-mediated sub-agent authorization](example/subagent) | Parent performs Person Server calls; child performs Resource calls | `go run ./example/subagent` |
| [Revocation and re-authorization](example/revocation) | Signed three-party revocation, idempotent retry after a lost response, and explicit replacement | `go run ./example/revocation` |
| [One chained Resource call](example/callchaining) | An authorized Resource acts as an Agent for one same-Person-Server downstream operation | `go run ./example/callchaining` |

The integration suite also exercises
[mission-bound four-party authorization](integration/mission_four_party_test.go),
[direct Person identity](integration/direct_identity_access_test.go),
[Person-token interaction](integration/person_token_interaction_test.go), and
both [baseline `401` and Resource-held `202` auth-token delivery](integration/core_four_party_test.go).
See [CONFORMANCE.md](CONFORMANCE.md) for their exact limits.

## Packages

| Package | Responsibility |
| --- | --- |
| `aauth` | Core identifiers, token claims, minting, verification, and context checks |
| `jose` | The focused Ed25519 JWK and compact-JWS profile used here |
| `signaturekey` | HTTP request proofs, credentials, discovery, and error negotiation |
| `agentprovider` | Agent-token issuance plus Agent Provider metadata and JWKS |
| `agent` | Explicit protocol calls; no hidden polling, browser use, or consequence retry |
| `personserver` | Person-token issuance, immediate mission lifecycle, direct authorization, interaction, revocation, call-chain policy, and Access Server federation |
| `resource` | Identity, session, authorization, protected-call, held-invocation, and revocation behavior |
| `accessserver` | Person-Server-authenticated policy and auth-token issuance |

The root protocol package and focused JOSE and Signature-Key packages do not
depend on role packages. Role packages compose them through small policy,
storage, key-resolution, clock, and transport interfaces. The complete package
graph is in [ARCHITECTURE.md](ARCHITECTURE.md); executing-path evidence is in
[CONFORMANCE.md](CONFORMANCE.md).

## Integration model

- Role servers are composable `http.Handler` values; this repository does not
  own an application's process or listener.
- The Agent API exposes protocol steps explicitly. It does not open a browser,
  sleep, poll repeatedly, or retry a consequential request on the caller's
  behalf.
- Hosts decide who may receive credentials and what scopes and lifetimes to
  grant. Verification code does not replace application policy.
- Hosts supply the store implementations required by each stateful role. The
  repository provides only in-memory examples; Agent pending handles and
  discovery caches remain process-local, so these examples do not prove
  complete process-restart recovery.
- Supported paths preserve exact bytes where a signature, digest, or retained
  store binding requires them.

Start with the runnable example closest to the topology you need. Then use its
matching [conformance entry](CONFORMANCE.md) and the exported package
documentation in the checkout—for example,
`go doc aauth-go/resource`—to replace its in-memory policies and stores with
application implementations.

## Current limits

The repository does not yet implement all of AAuth Core. Remote Agent
enrollment and credential renewal, general deferred and clarification paths,
the remaining mission log and control surfaces, and several delegation and
revocation variants remain open. Mission support currently covers immediate
top-level approval, ordered accepted updates, protected use, and
person-accepted completion through both three-party and four-party
authorization. Deferred mission actions and mission combinations with
delegation, call chaining, held delivery, or revocation remain open.

The R3, Events, Bootstrap, and Budgets companion specifications are pinned as
design inputs but do not yet have complete executing paths. HTTP Signature
Keys is implemented only to the extent required by the current role paths.

The repository does not provide durable stores, key custody, TLS listeners,
deployment infrastructure, or automatic retry policy. Applications must
review these host responsibilities before using the code outside a controlled
environment.

[CONFORMANCE.md](CONFORMANCE.md) is authoritative for implemented, partial,
and unimplemented behavior. Do not infer support from an exported type alone.

## Documentation

| Document | Use it for |
| --- | --- |
| [Protocol map](PROTOCOL.md) | How the seven pinned sources compose: roles, wire objects, state ownership, and complete journeys |
| [Architecture](ARCHITECTURE.md) | Current package boundaries and the target division of policy, state, transport, and proof |
| [Conformance](CONFORMANCE.md) | Exact implemented boundaries, exclusions, and executable evidence |
| [Specification baseline](SPECIFICATIONS.md) | Editor-source revisions and content digests used by the implementation |
| [Interpretations](INTERPRETATIONS.md) | Choices made where the source text does not determine one implementation |
| [Specification feedback](SPEC-FEEDBACK.md) | Reproducible questions and inconsistencies found while implementing the sources |
| [Contributing](CONTRIBUTING.md) | Source-grounded change and verification workflow |
| [Security policy](SECURITY.md) | Vulnerability reporting, deployment responsibilities, and supported-code status |
| [License](LICENSE) | MIT terms for using and redistributing the code |

## Verify the repository

```sh
go test ./... -count=1
go test -race ./... -count=1
go vet ./...
go build ./...
```
