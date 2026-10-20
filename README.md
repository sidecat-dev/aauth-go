# AAuth for Go

`aauth-go` provides Go packages for AAuth. An **Agent** calls a **Resource**
(API); an **Agent Provider** signs its identity token. A **Person Server**
handles the person's identity and decisions; a separate **Access Server**
issues grants in the four-party flow. See the [glossary](GLOSSARY.md) for
abbreviations and token fields.

This is an incomplete implementation, not an official conformance suite.
[SPECIFICATIONS.md](SPECIFICATIONS.md) pins the editor sources;
[CONFORMANCE.md](CONFORMANCE.md) lists supported behavior and limits.

## Use it in your service

Requires Go 1.25 or later:

```sh
go get gitlab.com/sidecat-dev/aauth-go
```

For an HTTP endpoint accepting Agent identity, start with
`resource.NewAgentIdentity`. It verifies the token **and the request proof**
before calling your application. [Use it in your service](USE-IN-YOUR-SERVICE.md)
shows the short handler, trusted-key setup and constructor choices.
For write endpoints, [require body coverage](USE-IN-YOUR-SERVICE.md#protect-request-bodies);
the default proof does not cover body bytes.

The lower-level token check is:

```go
claims, err := aauth.VerifyAgentToken(context.Background(), token, keys, clock)
if err != nil {
	return err
}
```

Here `token` is the received JWT, `keys` resolves trusted issuer keys, and
`clock` supplies protocol time. `claims.Subject` is the verified Agent identifier.
This call does not verify an HTTP request or
decide access. The [tested example](example/verifyagent/main.go) supplies all
three inputs and then demonstrates the complete Resource check.

From a checkout, run it without a listener, network service or state directory:

```sh
go run ./example/verifyagent
```

```text
Token verified: aauth:reader@agents.example
Request verified: aauth:reader@agents.example
```

## Choose a runnable path

| Need | Start with | Setup |
| --- | --- | --- |
| Direct Agent identity | [`example/agentidentity`](example/agentidentity) | In-process; no Person or Access Server |
| Three-party or four-party authorization | [`example/threeparty`](example/threeparty), [`example/fourparty`](example/fourparty) | In-process role composition |
| Self-hosted Agent or composed hosted-service profile | [`example/selfhosted`](example/selfhosted), [`example/hostedservice`](example/hostedservice) | In-process; see [local](LOCAL-AGENT-PROFILE.md) and [hosted](HOSTED-SERVICE-PROFILE.md) profile limits |
| Permission, missions or interaction | [`example/permission`](example/permission), [`example/mission`](example/mission), [`example/psconsent`](example/psconsent) | In-process |
| R3 operations, Budgets or Events | [`example/r3threeparty`](example/r3threeparty), [`example/budget`](example/budget), [`example/events`](example/events) | In-process; terms in the [glossary](GLOSSARY.md) |
| Revocation and Person-token recovery | [`example/revocation`](example/revocation) | In-process |
| Separate services, restart and retained state | [`walkthrough/local`](walkthrough/local), [`walkthrough/hosted`](walkthrough/hosted), [`walkthrough/callchaining`](walkthrough/callchaining) | Multiple TLS processes and state directories |
| Historical Go/TypeScript qualifications (2026-09-01) | [`walkthrough/interop`](walkthrough/interop) | Live qualification needs public HTTPS and external services |

[JOURNEYS.md](JOURNEYS.md) is the full catalog, including delegation, call
chaining and the other examples. Standalone walkthroughs pin published module
versions; they do not test the current checkout. See
[versions and local development](USE-IN-YOUR-SERVICE.md#versions-and-local-development)
to point a consumer module at your checkout.

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
Person Server, Access Server, and full-profile interoperability.
The [interoperability walkthrough](walkthrough/interop#external-authorization-qualification)
records a **2026-09-01** public-TLS run: TypeScript `@aauth/agent` 3.0.2
(`packages-js` at `7bd31a5`) completed Person → Resource → Auth token issuance
and a durable note write against Go `32eab26`. Its current JavaScript unit test
stubs `fetch`; it does not call the Go roles. The walkthrough pins that older
Go revision, so neither that test nor the historical run qualifies this checkout.

After a Resource refuses an Auth token with `revoked_jwt` and a valid
`person-token` requirement, Agent calls return
`*agent.PersonTokenRequiredError`; `errors.As` also finds the original
`*signaturekey.Error`. Automatic Person-token acquisition and retry are absent.
The [revocation example](example/revocation) shows explicit recovery: obtain a
fresh Person token, retry the original request with it, and satisfy the new
Auth-token requirement returned by that Resource.

Do not infer support from an exported type. Use:

- [CONFORMANCE.md](CONFORMANCE.md) for supported behavior and exclusions;
- [JOURNEYS.md](JOURNEYS.md) for caller-visible flows and evidence; and
- [LOCAL-AGENT-PROFILE.md](LOCAL-AGENT-PROFILE.md) for self-hosted local work
  plus explicit hosted account linking and Resource access;
- [HOSTED-SERVICE-PROFILE.md](HOSTED-SERVICE-PROFILE.md) for the deliberately
  narrower first hosted deployment.

## Documentation

Start with the service guide. Use the reference pages when you need a supported
boundary, a runnable flow, or an explanation of the protocol.

| Document | Use it for |
| --- | --- |
| [USE-IN-YOUR-SERVICE.md](USE-IN-YOUR-SERVICE.md) | Minimal verification code, constructor choices and local development |
| [GLOSSARY.md](GLOSSARY.md) | Roles, token fields and terms |
| [PROTOCOL.md](PROTOCOL.md) | How the pinned specifications compose into roles, values, and journeys |
| [CONFORMANCE.md](CONFORMANCE.md) | Implemented, partial, and absent behavior with executable evidence |
| [JOURNEYS.md](JOURNEYS.md) | Runnable role-to-role paths |
| [LOCAL-AGENT-PROFILE.md](LOCAL-AGENT-PROFILE.md) | Smallest useful self-hosted local deployment |
| [SECURITY.md](SECURITY.md) | Vulnerability reporting and deployment responsibilities |

For contributors changing protocol behavior:

| Document | Use it for |
| --- | --- |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Source-grounded change and verification workflow |
| [ARCHITECTURE.md](ARCHITECTURE.md) | Package boundaries and state ownership |
| [SPECIFICATIONS.md](SPECIFICATIONS.md) | Exact editor-source commits and digests |
| [INTERPRETATIONS.md](INTERPRETATIONS.md) | Choices the source does not settle |
| [SPEC-FEEDBACK.md](SPEC-FEEDBACK.md) | Submitted specification questions and their status; not required for first use |

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
