# AAuth for Go

`aauth-go` implements the current AAuth editor-source family as ordinary Go
packages. Applications compose the protocol roles they need and provide their
own policy, keys, transport, clocks, and durable storage.

This is an incomplete implementation, not an official conformance suite.
[SPECIFICATIONS.md](SPECIFICATIONS.md) pins the exact source revisions;
[CONFORMANCE.md](CONFORMANCE.md) states what executes today and what does not.

## Start here

The module requires Go 1.25 or later.

```sh
go get gitlab.com/sidecat-dev/aauth-go
```

Run the smallest complete authorization journey:

```sh
go run gitlab.com/sidecat-dev/aauth-go/example/threeparty@latest
```

It carries an Agent through a Person Server to one protected Resource call.
For a standalone external module that runs an Agent and local service as
separate TLS processes, persists their application state, restarts them, and
then revokes the active Agent token, use
[`walkthrough/local`](walkthrough/local).

For a standalone laptop-to-hosted-service path with separate TLS processes,
authenticated account linking, mission approval, MCP authorization, a fixed
Budget, restart recovery, and revocation, use
[`walkthrough/hosted`](walkthrough/hosted).

For a generated AAuth Go Agent making a real signed identity call to the AAuth
project's independently implemented TypeScript Resource, use
[`walkthrough/interop`](walkthrough/interop).

For a self-hosted Agent with a local permission boundary, direct local access,
an explicit hosted account-link interaction, and one account-bound hosted
Resource call, run:

```sh
go run gitlab.com/sidecat-dev/aauth-go/example/selfhosted@latest
```

The exact application boundary is in
[LOCAL-AGENT-PROFILE.md](LOCAL-AGENT-PROFILE.md). For a composed local-Agent
and hosted-service profile, run:

```sh
go run gitlab.com/sidecat-dev/aauth-go/example/hostedservice@latest
```

To use a self-hosted Agent identity and proof key against the same reviewed
mission, R3, Budget, and connector path, run:

```sh
go run gitlab.com/sidecat-dev/aauth-go/example/hostedservice@latest --self-hosted
```

That profile adds enrollment and refresh, local permission, host-reviewed
mission approval, a Resource-validated account, an MCP operation under a fixed
Budget, application-owned
OAuth credential use, refusal of an exhausted Budget before a second connector
dispatch, and Agent-token revocation. Its exact deployment boundary is in
[HOSTED-SERVICE-PROFILE.md](HOSTED-SERVICE-PROFILE.md).

## Choose a journey

| Need | Start with |
| --- | --- |
| Direct Agent or Person identity | [`example/agentidentity`](example/agentidentity) |
| Separate local TLS processes, durable state, restart, and revocation | [`walkthrough/local`](walkthrough/local) |
| Separate laptop and hosted-service TLS processes with mission, MCP, Budget, restart, and revocation | [`walkthrough/hosted`](walkthrough/hosted) |
| AAuth Go Agent calling an independently implemented live Resource | [`walkthrough/interop`](walkthrough/interop) |
| Three-party authorization | [`example/threeparty`](example/threeparty) |
| Four-party authorization through an Access Server | [`example/fourparty`](example/fourparty) |
| Account-bound four-party fixed Budget through an Access Server | [`example/budgetfourparty`](example/budgetfourparty) |
| Self-hosted local Agent linking to a hosted account | [`LOCAL-AGENT-PROFILE.md`](LOCAL-AGENT-PROFILE.md), [`example/selfhosted`](example/selfhosted) |
| Hosted enrollment or a self-hosted Agent through the full hosted-service path | [`HOSTED-SERVICE-PROFILE.md`](HOSTED-SERVICE-PROFILE.md), [`example/hostedservice`](example/hostedservice) |
| Local permission or a mission lifecycle | [`example/permission`](example/permission), [`example/mission`](example/mission) |
| Person questions, relays, or consent clarification | [`example/interactionquestion`](example/interactionquestion), [`example/interactionrelay`](example/interactionrelay), [`example/psconsent`](example/psconsent) |
| R3 operations and fixed hard-cap Budgets | [`example/r3threeparty`](example/r3threeparty), [`example/budget`](example/budget) |
| Public or protected Event delivery | [`example/events`](example/events) |
| Revocation and explicit re-authorization | [`example/revocation`](example/revocation) |
| Parent-mediated or chained work | [`example/subagent`](example/subagent), [`example/callchaining`](example/callchaining) |

[JOURNEYS.md](JOURNEYS.md) is the full role-to-role catalog. Each entry names
the exported API, executable evidence, and missing continuations.

## Package map

| Package | Responsibility |
| --- | --- |
| `aauth` | Core identifiers, token claims, minting, verification, and context checks |
| `jose` | Focused Ed25519 JWK and compact-JWS behavior |
| `signaturekey` | HTTP request proofs, credentials, discovery, and error negotiation |
| `agentprovider` | Agent enrollment, Agent-token issuance, metadata, and Events inbox |
| `agent` | Explicit caller-side protocol steps; no hidden polling or consequence retry |
| `personserver` | Person identity, authorization, missions, permission, interaction, audit, and federation |
| `resource` | Identity, sessions, authorization, R3 enforcement, Budget charging, Events, and revocation |
| `accessserver` | Person-Server-authenticated authorization and R3 issuance |
| `r3` and `r3/vocab/*` | Vocabulary-neutral grants plus bounded MCP, OpenAPI, gRPC, GraphQL, AsyncAPI, WSDL, and OData adapters |
| `budgets` and `events` | Typed companion-protocol values and verification |
| `*/storetest` and `r3/vocabtest` | Reusable contracts for application stores and third-party R3 adapters |

The root protocol package and the JOSE and Signature-Key packages do not
depend on role packages. Role packages compose them through small policy,
storage, key-resolution, clock, and transport interfaces. See
[ARCHITECTURE.md](ARCHITECTURE.md) for the dependency graph and state owners.

## Integration boundary

- Servers are composable `http.Handler` values. The library does not own the
  application's listener or process.
- Agent methods perform one explicit protocol step. They do not open a
  browser, sleep, loop, or automatically retry a consequential request.
- Hosts decide policy and authenticate people and administrators before
  invoking host-side decisions.
- Hosts supply durable store implementations and run the applicable public
  `storetest` contracts against them. The shipped examples use in-memory
  stores and do not prove process-restart recovery.
- R3 adapters parse already-acquired native definitions. Network discovery,
  source-size limits, and dependency acquisition remain application concerns.
- Private keys and third-party service credentials stay with the application;
  AAuth values carry authority, not those credentials.

## Current boundary

The repository has executing paths for direct identity, three- and four-party
authorization, Resource-managed sessions, hosted enrollment and refresh,
missions, local permission, audit, interaction, bounded delegation and call
chaining, revocation, R3, Events, and fixed-price Budgets.

It does **not** yet implement all of AAuth Core or every companion profile.
Notable exclusions include production store adapters, key custody, TLS and
deployment infrastructure, platform attestation, general request-proof replay,
several deferred and mission combinations, automatic revocation fan-out,
complete Signature-Key schemes, variable or streaming Budgets, and independent
implementation interoperability.

Do not infer support from an exported type. Use:

- [CONFORMANCE.md](CONFORMANCE.md) for supported behavior and exclusions;
- [JOURNEYS.md](JOURNEYS.md) for caller-visible flows and evidence; and
- [LOCAL-AGENT-PROFILE.md](LOCAL-AGENT-PROFILE.md) for self-hosted local work
  plus explicit hosted account linking and Resource access;
- [HOSTED-SERVICE-PROFILE.md](HOSTED-SERVICE-PROFILE.md) for the deliberately
  narrower first hosted deployment.

## Documentation

| Document | Use it for |
| --- | --- |
| [PROTOCOL.md](PROTOCOL.md) | How the pinned specifications compose into roles, values, and journeys |
| [ARCHITECTURE.md](ARCHITECTURE.md) | Package boundaries, state ownership, transport, policy, and proof seams |
| [SPECIFICATIONS.md](SPECIFICATIONS.md) | Exact editor-source commits, digests, and R3 vocabulary baselines |
| [CONFORMANCE.md](CONFORMANCE.md) | Implemented, partial, and absent behavior with executable evidence |
| [JOURNEYS.md](JOURNEYS.md) | Runnable role-to-role paths |
| [LOCAL-AGENT-PROFILE.md](LOCAL-AGENT-PROFILE.md) | Smallest useful self-hosted local deployment |
| [INTERPRETATIONS.md](INTERPRETATIONS.md) | Deliberate choices where the source does not determine one implementation |
| [SPEC-FEEDBACK.md](SPEC-FEEDBACK.md) | Reproducible questions and inconsistencies found during implementation |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Source-grounded change and verification workflow |
| [SECURITY.md](SECURITY.md) | Vulnerability reporting and deployment responsibilities |

Package documentation is available through ordinary Go tooling, for example:

```sh
go doc gitlab.com/sidecat-dev/aauth-go/resource
```

## Verify the repository

```sh
go test ./... -count=1
go test -race ./... -count=1
go vet ./...
go build ./...
```

To verify the machine-readable protocol map against the pinned editor-source
bytes, use the command in [SPECIFICATIONS.md](SPECIFICATIONS.md).

## License

MIT. See [LICENSE](LICENSE).
