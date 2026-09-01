# AAuth for Go

`aauth-go` implements the AAuth editor revisions pinned in
[SPECIFICATIONS.md](SPECIFICATIONS.md) as ordinary Go packages. Applications
compose the protocol roles they need and supply their own policy, keys,
transport, clocks, and storage.

The implementation is incomplete. It is not an official conformance suite,
and independent interoperability has not yet been demonstrated. Start with the
plain role-to-role catalog in [JOURNEYS.md](JOURNEYS.md); use
[CONFORMANCE.md](CONFORMANCE.md) for the denser claim-to-test matrix.

## Run it

The module requires Go 1.25 or later. Install the current module with:

```sh
go get gitlab.com/sidecat-dev/aauth-go
```

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
| [Hosted Agent bootstrap profiles](example/bootstrap) | Shared `hwk` enrollment, then either `jkt-jwt` refresh to a fresh Agent key or direct `hwk` refresh with the durable key, followed by Agent identity access | `go run ./example/bootstrap` |
| [Self-hosted Agent](example/selfhosted) | One user-controlled key publishes AP metadata/JWKS, self-issues an ordinary Agent token, and signs a protected Resource call | `go run ./example/selfhosted` |
| [Direct Agent identity](example/agentidentity) | Agent Provider to Agent to Resource, with no Person Server or Access Server | `go run ./example/agentidentity` |
| [Local-action permission](example/permission) | Missionless and mission-bound requests; the host reviews retained intent and exact mission context, and the application acts only after a typed grant | `go run ./example/permission` |
| [Resource-managed session](example/resourcesession) | Resource-owned interaction and an opaque proof-bound session | `go run ./example/resourcesession` |
| [Immediate three-party authorization](example/threeparty) | Person Server identity and authorization with no Access Server | `go run ./example/threeparty` |
| [Direct three-party R3](example/r3threeparty) | MCP operations narrowed and issued by the Person Server with no Access Server | `go run ./example/r3threeparty` |
| [Mission-bound three-party authorization](example/mission) | Exact approval, an ordered accepted update, one protected call, and person-accepted completion | `go run ./example/mission` |
| [Mission-bound action audit](example/audit) | Application performs one local action; Agent submits its exact post-action record; Person Server appends it to the active mission | `go run ./example/audit` |
| [Question through the Person Server](example/interactionquestion) | Missionless and mission-bound questions; policy answers immediately or parks the question for a host; one explicit poll returns a deferred answer | `go run ./example/interactionquestion` |
| [Resource-hosted interaction relay](example/interactionrelay) | Missionless and mission-bound relays; the PS retains the URL and code; a host marks engagement; one explicit poll returns the relay state | `go run ./example/interactionrelay` |
| [Clarification during Person Server consent](example/psconsent) | A verified request is parked; the host asks one bounded question; the Agent signs one answer; explicit polling returns the approved token | `go run ./example/psconsent` |
| [Four-party authorization variants](example/fourparty) | Missionless Core, mission lifecycle, and one runnable MCP R3 path with independent consent/policy fetches, a narrowed grant, and atomic issuance audit | `go run ./example/fourparty` |
| [Parent-mediated sub-agent authorization](example/subagent) | Parent performs Person Server calls; child performs Resource calls | `go run ./example/subagent` |
| [Revocation and re-authorization](example/revocation) | Signed three-party revocation, idempotent retry after a lost response, and explicit replacement | `go run ./example/revocation` |
| [One chained Resource call](example/callchaining) | An authorized Resource acts as an Agent for one same-Person-Server downstream operation | `go run ./example/callchaining` |
| [Public and protected event subscriptions](example/events) | Public registration plus an opaque, prior-interaction-bound, short-lived, single-use Resource ticket; both continue through `self-jwt` delivery and Agent correlation | `go run ./example/events` |
| [Fixed-price Budget](example/budget) | Resource denomination selection, Person Server amount narrowing, one atomic charge, validated feedback, and a typed over-remainder step-up | `go run ./example/budget` |

The integration suite also exercises
[mission-bound four-party authorization](integration/mission_four_party_test.go),
[direct three-party MCP R3 authorization](integration/r3_direct_three_party_test.go),
[immediate MCP, OpenAPI, and private-codec R3 four-party authorization](integration/r3_direct_four_party_test.go),
[direct Person identity](integration/direct_identity_access_test.go),
[missionless and mission-bound Person-token interaction](integration/person_token_interaction_test.go), and
both [baseline `401` and Resource-held `202` auth-token delivery](integration/core_four_party_test.go).
The [three-party clarification journey](integration/clarification_three_party_test.go)
proves a retained host question, a typed Agent view, a signed answer,
serialized continuation and value recomposition, explicit approval and
polling, one protected call, and a typed wrong-Agent refusal. No library step
polls or retries automatically.
The [missionless Permission journey](integration/permission_missionless_test.go)
proves a signed local-action request, Person Server recomposition around the
retained request, explicit host grant and denial, one caller-driven poll, one
application action after the grant, and no Resource or Access Server calls.
The [mission-bound Permission journey](integration/permission_mission_test.go)
adds the active owned mission and its accepted updates to policy and the host
view, and keeps create, decision, and delivery atomic with that exact mission
state.
The [mission Audit journey](integration/audit_mission_test.go) proves one
signed post-action record, exact retention against the still-active
owned mission, host-side read-back, and refusal after mission completion.
The [Interaction question journey](integration/interaction_question_test.go)
proves immediate and retained deferred answers, Person Server recomposition,
one explicit poll, terminal consumption, typed `user_unreachable`, and optional
exact active-mission binding without Resource or Access Server calls.
The [Interaction relay journey](integration/interaction_relay_test.go) proves
retention before `202`, Person Server recomposition, host engagement, one
terminal consumer, and typed direct fallback when the Person Server cannot
relay a Resource-hosted URL and code.
The [fixed-price Budget journey](integration/budget_three_party_test.go) proves
direct Resource offer selection, Person Server amount narrowing, and
concurrent hard-cap enforcement.
Budget Auth tokens use `Client.BeginBudgetCall`; generic `Client.Do` rejects
them before metadata or application I/O. An unverifiable post-send outcome
carries the full signed grant and is never retried automatically.
The Resource calls the host's `RetainLineage` before releasing its initial
Budget Resource token; the later challenge callback reads that host state.
The Events integrations exercise both
[public registration](integration/events_public_subscription_test.go) and a
[protected ticket](integration/events_protected_subscription_test.go). Together
they cover exact registration recovery, wrong-Agent cloaking, ticket expiry and
single use, bodyless delivery, bounded uses, delivery replay, and two distinct
payloads that share one deterministic Event token.
See [CONFORMANCE.md](CONFORMANCE.md) for their exact limits.

## Packages

| Package | Responsibility |
| --- | --- |
| `aauth` | Core identifiers, token claims, minting, verification, and context checks |
| `jose` | The focused Ed25519 JWK and compact-JWS profile used here |
| `signaturekey` | HTTP request proofs, credentials, discovery, and error negotiation |
| `budgets` | Budget values, same-denomination narrowing, token companions, fixed-price feedback, and typed challenge reasons |
| `events` | Subscribe-token and Event-token values, AP metadata, and exact delivery identity |
| `r3` | Vocabulary-neutral R3 values, registered operation algebra, atomic native-definition parsing, source receipts, advisory hints, token claims, and the shared issuance-audit contract |
| `r3/vocab/<name>` | One standard vocabulary's operation grammar, set algebra, and bounded native-definition adapter |
| `r3/vocab/standard` | Explicit registries for all seven standard operation codecs and definition parsers |
| `r3/vocabtest` | Reusable operation-codec and native-definition contracts for standard and third-party adapters |
| `agentprovider` | Agent-token and subscribe-token issuance, metadata/JWKS, and the Events inbox |
| `agent` | Explicit Core, mission Audit, missionless or mission-bound Interaction questions and relays, R3, Events, and fixed-price Budget calls; no hidden polling, browser use, or consequence retry |
| `personserver` | Person-token issuance, mission lifecycle and Audit, missionless or mission-bound local-action permission and Interaction questions or relays, direct Core/class-R3/Budget verification and narrowing, consent interaction, revocation, call-chain policy, and Access Server federation |
| `resource` | Identity, session, authorization, registered R3 documents/enforcement, Events registration/delivery, Budget metadata/offers/fixed-price accounting/step-up verification, protected-call, held-invocation, and revocation behavior |
| `accessserver` | Person-Server-authenticated Core/R3 policy, narrowing, issuance, and R3 audit |

The root protocol package and focused JOSE and Signature-Key packages do not
depend on role packages. Role packages compose them through small policy,
storage, key-resolution, clock, and transport interfaces. The complete package
graph is in [ARCHITECTURE.md](ARCHITECTURE.md); executing-path evidence is in
[CONFORMANCE.md](CONFORMANCE.md).

## Parse an R3 native definition

Definition adapters accept already-acquired native values and perform no
network I/O. For MCP, pass the JSON value inside each JSON-RPC `result`, paired
with the cursor used to request that page:

```go
source := mcp.NewToolsListSnapshot(
	mcp.NewInitialToolsListPage([]byte(
		`{"tools":[{"name":"records.read","inputSchema":{"type":"object"}}]}`,
	)),
)
snapshot, err := mcp.ParseDefinition("https://resource.example/mcp", source)
if err != nil {
	return err
}
definitions, err := r3.NewDefinitionRegistry(mcp.DefinitionRegistration())
if err != nil {
	return err
}
if err := definitions.Validate(snapshot); err != nil {
	return err
}
```

Supply that registry and snapshot through `resource.R3Config.Definitions` and
`R3VocabularyConfig.Definition`. See the direct
[`example/r3threeparty`](example/r3threeparty) or federated
[`example/fourparty/r3.go`](example/fourparty/r3.go) wiring.

A third-party vocabulary implements two separate interfaces: `r3.Codec` for
operation grammar and algebra, and `r3.DefinitionCodec` for one deterministic,
concurrency-safe, I/O-free native parse. Keep both registrations stable, then
exercise them with `vocabtest.Run` and `vocabtest.RunDefinition`. The complete
test-local extension is in
[`integration/r3_vocabulary_helpers_test.go`](integration/r3_vocabulary_helpers_test.go).

## Integration model

- Role servers are composable `http.Handler` values; this repository does not
  own an application's process or listener.
- The Agent API exposes protocol steps explicitly. It does not open a browser,
  sleep, poll repeatedly, or retry a consequential request on the caller's
  behalf.
- Hosts decide who may receive credentials and what scopes and lifetimes to
  grant. Verification code does not replace application policy.
- Hosts supply the store implementations required by each stateful role. The
  repository provides only in-memory examples. The direct clarification path
  can serialize its Agent continuation, but most other pending handles and all
  example stores remain process-local. These examples do not prove complete
  process-restart recovery.
- Supported paths preserve exact bytes where a signature, digest, or retained
  store binding requires them.

Start with the runnable example closest to the topology you need. Then use its
matching [conformance entry](CONFORMANCE.md) and the exported package
documentation in the checkout—for example,
`go doc gitlab.com/sidecat-dev/aauth-go/resource`—to replace its in-memory policies and stores with
application implementations.

## Current limits

The repository does not yet implement all of AAuth Core. Agent enrollment and
renewal cover explicit Ed25519 two-key and single-durable-key hosted profiles
with application-selected Agent Provider routes, plus the source-described
self-hosted profile. Platform-attestation and durable-key replacement remain
open. Clarification
currently covers one direct three-party question, answer, and cancellation
during host-authenticated consent. Updated requests, Access Server relay,
mission-bound clarification, and other general deferred paths remain open, as
do the remaining mission log and control
surfaces, and several delegation and revocation variants also remain open.
Permission covers top-level missionless and mission-bound actions with
immediate or deferred decisions. Mission-bound retention, host decision, and
terminal delivery compare the exact active mission; an unseen accepted update
requires the host to resume and review again. Permission records form only the
permission sublog. Automatic `approved_tools` matching, the complete
cross-event mission log, durable adapters, and recovery of an uncertain initial
submission remain open.
Audit covers one top-level Agent submitting an exact post-action record to its
active mission. The Person Server appends before acknowledging; the Agent
never retries an uncertain result. Deferred audit delivery, sub-agent and
call-chain composition, durable adapters, and the cross-event mission log and
Agent-facing read remain open.
Interaction covers top-level missionless or mission-bound questions plus
retained missionless or mission-bound `interaction` and `payment` relays. A
mission-bound request exposes the exact active mission to policy and host code;
immediate question results and every deferred transition share the mission
lifecycle transaction boundary. The Resource-hosted pending URL remains the
completion authority for a relay. The complete cross-event mission log,
durable store adapters, and stable recovery after a lost initial response
remain open.
Mission support currently covers immediate
top-level approval, ordered accepted updates, protected use, and
person-accepted completion through both three-party and four-party
authorization. Deferred mission actions and mission combinations with
delegation, call chaining, held delivery, or revocation remain open.

R3 has strict operation-object grammars and bounded native-definition adapters
for all seven standard vocabularies. One parse atomically derives copied
operations, sparse advisory hints, and a receipt over the adapter's exact
digest input. The parser performs no network or external dependency
acquisition, policy decision, or retention. Each bounded adapter resolves only
the internal relationships it needs to derive operation identities.

MCP class authorization runs through both direct three-party PS issuance and
four-party AS issuance. OpenAPI and the integration-local codec run through
four-party issuance. Per-call R3 remains four-party-only.

MCP validates complete cursor-linked `tools/list` frames and each Tool's
object-rooted `inputSchema`. OpenAPI accepts self-contained 3.0 and 3.1 Paths
operations. gRPC accepts complete binary `FileDescriptorSet` input. AsyncAPI,
WSDL, and OData each implement a documented self-contained subset. GraphQL
introspection returns a typed refusal because schema introspection does not
publish client-authored executable operation names. MCP, OpenAPI, and AsyncAPI
parse their defined sparse access hints; those hints never grant access or
select Resource enforcement.

MCP and OpenAPI have bounded immediate four-party HTTP paths for both direct
grants and per-call proposals. The same unchanged HTTP role journeys also run
against an integration-test-local codec implemented only through exported
interfaces. Complete discovery acquisition, general
dependency resolution, non-HTTP invocation bindings, durable store adapters,
and independent-implementation interoperability remain open. Callers must
bound source bytes, nesting, collection sizes, and parser work before passing
untrusted material to these parsers.
Events has complete public and protected-subscription paths. Both cover AP
retention before subscribe-token release, Agent context retention before
registration, exact Resource registration recovery, current AP endpoint
discovery with explicit egress admission, body-bearing and bodyless `self-jwt`
delivery, AP retention before `202`, bounded-use feedback, and Agent-side
context correlation and exact replay detection. The protected path also binds
an opaque Resource ticket to the prior Agent and application context and
atomically consumes it with registration. AP-to-Agent transport, automatic
AsyncAPI payload validation, and durable store adapters remain host concerns.
Bootstrap has two hosted profiles and one self-hosted profile. Budgets has
one direct fixed-price profile; four-party, variable-cost, streaming, usage,
consumption-history policy, and automatic reauthorization paths remain open.
HTTP Signature Keys is implemented only to the extent required by current role
paths.

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
