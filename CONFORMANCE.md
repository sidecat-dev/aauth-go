# Conformance status

This document gives aauth-go's per-requirement status against the pinned editor
drafts of AAuth and its companions. [SPECIFICATIONS.md](SPECIFICATIONS.md) lists
the pins.

The [aauth-conformance](https://gitlab.com/sidecat-dev/aauth-conformance) suite
measures it through the suite's Go launcher. The suite's `conformance-map.edn`
records the result for each suite clause and the draft sentences it reaches.

| `e76d864`, suite `a63c1c0` | Result |
| --- | --- |
| Roles | 24 of 24 offered, all passed |
| Assertions | 1,606 pass, 0 fail, 0 not claimed |
| Suite clauses | 338 of 338 pass |

The suite grades only the clauses its scenarios reach. Of the 1,067 keyword
sentences in the pinned drafts, 433 sit in sections no scenario reaches and are
not measured. No percentage of a draft and no official or certified status is claimed.

Below are dated blocks of what each change added, then status tables for AAuth
Core, HTTP Signature Keys, the JOSE profile, storage and the companion drafts.

Updating this document: check
- after a library change: rerun the suite, regenerate the map, update the figures and the row the change touches;
- after a suite change: the suite commit and the counts.

Changes on 2026-11-02 (not released):

- A Resource with `FurtherSchemes` can accept `self-jwt` from a client outside
  AAuth. `SelfJWTType` names the `typ` the deployment selects; the
  assertion's `iss`, `dwk` and `kid` select the key through the Resource's
  `KeyResolver`, and the same key verifies the HTTP signature.
- `jose.JWK.RFC7638Thumbprint` computes the RFC 7638 thumbprint of a key
  without `alg`, such as the RFC 8037 example key. `Thumbprint` still refuses
  such a key, so no AAuth verification path changed.
- `testutil.NewEventInboxStore` and `testutil.NewProtectedEventStore` are
  in-memory Events stores for an Agent Provider and a Resource. They pass the
  `RunEventInbox`, `RunEventInboxReader` and `RunProtectedEvents` contracts:
  the inbox compares a delivery with the subscribed Resource and Agent,
  enforces `max_uses` and retains the exact bytes it hands over, and a
  protected subscription ticket registers once. They are the stores
  `example/events` used, now exported.
- The Agent client works at a Resource that publishes no metadata. A `404` at
  `/.well-known/aauth-resource.json` means no document: the Resource is known
  by its origin, signs need only the base components, and the other members
  take their defaults. So `Begin`, `Do`, `CallAsAgent`, `BeginBudgetCall` and
  the session calls proceed, and the Agent can retry with a Person token at
  such a Resource. `Authorize` refuses, since there is no
  `authorization_endpoint`. Any other failure, and every published document,
  is checked as before.
- The revocation senders read the same `404` the same way. A Resource that
  publishes no metadata has no `revocation_endpoint`, exactly as a document
  without the member. The Person Server's cascade (`RevokePersonToken`,
  `TerminateMission`, the Access Server's cascade alike) reports it
  `revocation_unsupported`. `RevokeIssuedAuthToken` and the Agent Provider's
  `RevokeAgentTokenAtResource` return an error naming the missing endpoint,
  as they do for a document without one; the local revocation is recorded
  first. Person Server and Access Server metadata stay required, so a `404`
  there, and a `410` or any other status anywhere, is still a failure.
- The single-key refresh handler accepts Bootstrap's bare single-key refresh:
  an `hwk`-signed body with `ps` and `evidence` and no `refresh_jti` or
  `refresh_expires_at`. It used to refuse that body with `400`. Such a
  request is identified by its own verified signature and retained until
  that signature could no longer verify, so the same signed request returns
  the same token. A body that names both members keeps the caller-chosen
  identity and its recovery window of up to 24 hours. A body that names only
  one is still `400`. `agent.SingleKeyRefreshAgentTokenInput` makes both
  members optional the same way.
- The "Obtaining an agent token" and "Bootstrap enrollment and refresh"
  rows read Implemented. They had called platform attestation and key
  replacement absent. The Bootstrap draft makes attestation optional AP
  policy (line 208), which this repository leaves to the host through signed
  `evidence`, and treats a durable-key change as a new enrollment (line 337).
  The conformance suite at aauth-conformance 9286541 grades all 37 Bootstrap
  suite clauses as passing.
- `agent.BootstrapClient.NeedsRefresh` decides when an Agent token is due:
  fewer than `agent.RefreshMargin`, five minutes, remain before its `exp` at
  the client's clock (Core line 1301, applied to Agent tokens by Bootstrap
  line 291). Exactly five minutes left is outside the margin. The caller
  still performs the refresh. The conformance suite's
  `bootstrap.agent.refresh-margin` scenario can now be claimed for this
  repository.
- Both refresh handlers accept a body with no `evidence` member, such as the
  Bootstrap draft's example refresh body `{}` (line 316). They used to refuse
  it with `400`. The draft has the agent present whatever evidence the AP
  requires (line 106), so the host's `Refresh` callback now receives empty
  evidence and decides; a host that requires evidence still refuses, with
  its policy-denial status. Enrollment still requires an `evidence` member.

Changes on 2026-10-30. A review of the MUST-level rows against the pinned
drafts found these behaviors failing, and they now conform:

- `/authorize` with no person token answers the `401` person-token challenge,
  and a person token that fails verification is `401` with `Signature-Error`.
- A request missing a signature header is `invalid_signature`.
- Unrecognized `AAuth-Capabilities` parameters of any RFC 9651 type are ignored.
- On the four-party path the PS rechecks presented-token expiry after consent.
- The PS records which Access Server each person token was presented to.
- The PS ends a person-token interaction after three failed codes.
- The key resolver refuses private, loopback and link-local destinations and
  connects only to the address it checked.
- Agent polls back off on `429` and honor `Retry-After` on `503`.
  `Reauthorize` obtains a fresh resource token after a key rotation; the host
  calls it.
- Mission data no longer carries the `approver` member the draft removed.
- Call chaining accepts an upstream person token.

Changes on 2026-10-31: four-party call chaining.

- A four-party Person Server accepts as `upstream_token` an auth token an
  Access Server issued, because it keeps a receipt of each auth token it
  delivers (`FederatedAuthorizationConfig.IssuedTokens`). The receipt names the
  calling Agent and the person token the auth token was obtained with. Chains
  repeat: an intermediary's downstream auth token is the next hop's upstream
  token.
- An upstream token that carries `mission_s256` has the chain evaluated
  against that mission of the calling Agent, and the downstream person and
  auth tokens carry it and its expiry. A terminated mission ends the chain
  with `mission_terminated`.
- A chained request can wait for the Access Server. Each poll, host advance
  and delivery verifies the upstream token again; one revoked while the
  request waits ends it with `403 revoked` at the Person Server's pending URL,
  as a revoked upstream or resource token does at the Access Server's.
- A mission-bound four-party request, chained or not, can wait for the Access
  Server too. Each poll and host advance loads the mission again, a
  terminated mission ends the wait with `403 mission_terminated`, and the
  grant is committed with the mission at release. The Access Server no longer
  caps a mission-bound auth token at the Resource token's `exp`: the presented
  token carries the mission's bound, and a Resource token's lifetime is
  independent of the mission. Neither the Person Server nor the Agent refuses
  a Resource token that outlives the mission any more.
- Revoking a person token revokes the auth tokens obtained with it and the
  call chains built on any of them, hop by hop, at each Resource and Access
  Server. An Agent Provider's revocation of an Agent token does the same for
  each person token issued to that Agent, and the Person Server answers it
  `202` until that cascade is terminal.
- The Agent client accepts an Access Server's auth token and a mission-bound
  token as `upstream_token`, routes by its `ps`, and refuses downstream tokens
  that outlive it. A deferred chained exchange is a `PendingExchange`, from
  `BeginExchange` or `Exchange`'s `PendingExchangeError`, and a deferred chained
  person-token request is an `agent.Pending` (`ChainedPending`); both are polled
  at the Person Server the upstream token names.

Later on 2026-10-31: the Access Server's interaction, four-party chained
Budget, and metered release.

- A four-party Person Server relays an Access Server's
  `requirement=interaction` to the Agent, with the AS's own `url` and `code`,
  on the first answer or a later host advance, chained or not. It keeps the
  wait, and the host advances it once the person has finished at the AS. A
  request that did not declare the `interaction` capability is answered
  `403 user_unreachable`, and the PS withdraws it at the AS. The federated
  Person Server now accepts `capabilities` and ignores values it does not act
  on.
- The Access Server can ask for interaction: `PendingDecision.InteractionURL`,
  with the code it draws for each wait (`AuthorizationRequest.InteractionCode`).
- A four-party chained request may carry a Budget offer: the Person Server
  sends its ceiling to the Access Server beside the upstream token, as for an
  unchained request. `agent.BudgetCall` takes the upstream token.
- Metered release (`R3ReleaseConfig.MeterRelease`): a Resource offers the
  release cost of a held `budget: true` operation as `budget` on the per-call
  proposal's Resource token, the Person Server sends its ceiling and the
  Access Server grants it on the per-call Auth token, and the Resource draws
  the cost down once when it releases the result. A replay is not charged
  again. A per-call token whose budget is too small gets `403` with
  `AAuth-Budget`, and the result stays held. Rust refuses a budgeted proposal
  at a federated Person Server; see INTERPRETATIONS.md.
- New fields: `R3ReleaseConfig.MeterRelease`, `R3ReleaseDescription.Cost`,
  `accessserver.R3ProposalDecision.Budget` and `agent.BudgetCall.UpstreamToken`.
  Store adapters must retain `FederatedAuthorizationRecord.InteractionCapable`
  and `PendingAuthorizationRecord.InteractionCode` as immutable; the storetest
  contracts check both.
- Fixed: the Person Server and Access Server refused the proposal of any
  release-gated call (`unknown member "result"`), so a release could not
  complete across four parties.

Still open: a sub-agent as intermediary, chained R3, a four-party sub-agent
with a Budget, a three-party Person Server deferring a chained request to
PS-hosted consent, and per-call R3, metered or not, in three-party access,
which this library does not compose.

Features added on 2026-10-30:

- Resource-initiated interaction, three-party: a Resource puts its own flow in
  the challenge, a Person Server redirects the person there after checking the
  code and the URL, and callback errors end the request with the mapped polling
  error. Interaction chaining answers the original caller with its own `202`,
  code and pending URL.
- Interaction callbacks with `error` where the library hosts the page:
  Resource-initiated interaction, the Person Server returning the Agent, and
  chaining.
- The `aauth-resource` link relation is emitted and followed only for a server
  identifier's well-known metadata; a link is never read as a requirement.
- Delayed signed requests verify at their `created` time, with replay detection
  across the delay.
- Revocation: person and resource tokens are revoked at every recipient, the
  Access Server holds a cascade for `Prefer: wait`, every revocation endpoint
  answers `429 rate_limited` with `Retry-After`, and an Agent stops presenting a
  refused token.
- R3: several internal definitions compose into one document; a release-gated
  call runs once and its result goes into the proposal; a metered or
  `budget:true` operation never runs before approval.
- Budgets: held refusals reserve nothing (four-party), replays answer without
  metering, and a Resource with a key signs its usage answers.
- Events: `EventInboxReader` hands queued deliveries to the Agent with their
  exact bytes.
- A Resource that also serves clients outside AAuth can accept further
  Signature-Key schemes; such requests go to the host's own handler.

Features added on 2026-10-31:

- Every Agent request a server may defer polls its `202` through one shared
  `agent.Pending`: mission update and completion, audit, `/authorize`
  (including a Resource that authorizes by itself and issues a session), the
  sub-agent token request, event subscriptions, and bootstrap enrollment and
  refresh. Polls are signed with the original request's credential, respect
  `Retry-After` and the `429`/`503` backoff, may send `Prefer: wait`, answer a
  clarification, cancel with `DELETE`, and end on the first terminal answer.
  The immediate methods return the pending request in a `PendingError`.
- `BeginExchange` polls an R3 exchange, and `Exchange` returns any pending
  exchange in a `PendingExchangeError`. A pending mission proposal carries
  interaction and clarification requirements, with an answer and a
  cancellation.
- The Person Server's consent and person-token pages and the Resource-managed
  session page retain the visit's callback and return the person there with
  the outcome, `error` included.

Features added on 2026-10-31: AAuth Supervision.

- A Person Server routes each Agent to its deciding supervision server
  (`SupervisionConfig.Route`), and for a routed Agent makes no supervision
  decision of its own: mission proposals, updates and completions, and
  person-token, three- and four-party auth-token and permission requests go to
  the supervisor, whose allow, deny or ask the Person Server applies. An allow
  may refine a mission, narrow scope and bound `exp`. An ask, and an act the
  supervisor could not be reached for, waits for the person, whom the host
  authenticates before `ResolveSupervision` records their answer and its reach.
  The supervisor's question is relayed to the Agent and the answer back, and the
  person can question the Agent too; the chat is reported with their decision.
- Connect, with the person's confirmation at the supervisor or a tenant it
  accepts at once; reconnect after `unknown_sub`; disconnect.
- Supervision requests carry the signed envelope and an `sdi` that ties the
  request, its retries, polls and clarifications, the person's answer and the
  issued tokens together. `Prefer: wait=30`, deferred decisions polled by the
  host, idempotent repeats, and signed decisions verified on receipt and again
  later from the Person Server's log entry.
- Events, delivered in order per person and supervisor: `agent.bound`,
  `person_token.issued`, `auth_token.issued` (from the Person Server or the
  Access Server), `decision.resolved`, `audit.recorded`,
  `interaction.requested`, `revocation.received` for an Agent token, and the
  mission reports `approved` and `terminated`. Replay on an Agent's first
  route, after a routing change, and after `unknown_mission`.
- The wire choices the draft leaves open match aauth-rust's, so a Go Person
  Server can work with a Rust supervision server and a Rust Person Server with
  a Go one. No run across the two has been made yet.
- The `supervisionserver` role package: metadata and keys, connect, the three
  endpoints, host policy that allows, denies, asks, clarifies or defers,
  byte-identical repeats, signed decisions, and an observer through which a
  standing policy learns the reach of the person's answers.

Every item once listed here has closed. The last, Resource-initiated
interaction for a supervised Agent, closed on 2026-11-02 (see below).

Changes on 2026-10-31, from the shared conformance scenarios and interop QA:

- A Signature-Key header with no member for the verified label is
  `invalid_signature`, not `invalid_key`.
- A key of a type or algorithm the verifier does not implement, under any
  scheme whose key is resolved after the request is read, is
  `unsupported_algorithm`; the signature's length is judged against the key,
  not before it is resolved.
- An Agent identifier with `+` must have a non-empty part on each side of one
  `+`; `aauth:+worker@...` and `aauth:assistant+@...` are refused.
- A Resource that requires an auth token answers a mission-bound person token
  with a Resource token carrying its `mission_s256`, instead of refusing it. A
  Resource that holds requests challenges a mission-bound one without holding
  it.
- Person, Resource and auth tokens are read with `aud` as a string or as an
  array of one string, as other implementations write it; tokens are still
  minted with the string.
- A budgeted auth token is accepted as `upstream_token` by the Agent client,
  the Person Server and the Access Server, so a metered hop can chain.
- A supervision server can answer `429 rate_limited` with `Retry-After`
  through `supervisionserver.Config.RateLimit`.
- A held request or an approved R3 per-call retry sent with
  `Connection: close` or `keep-alive` runs; those options stay with the
  connection.

Changes on 2026-11-01: ES256, a default discovery client, ending a mission,
and the supervision leftovers.

- ES256. Agent, person, Resource, auth and event tokens, the jkt-jwt and
  self-jwt assertions, and the keys that sign them or that they confirm may be
  Ed25519 or ES256 (Protocol, Signature Algorithms: every party MUST support
  Ed25519 and SHOULD support ES256). A token is signed under its key's own
  `alg` and verified only with a key of that `alg`. Every endpoint accepts
  Ed25519 and ES256 request keys by default, and `unsupported_algorithm` lists
  both. Ed25519 stays the default key; an ES256 key is any `crypto.Signer` on
  P-256, so a key held in hardware works. ES384, RS256 and PS256 still sign
  HTTP requests only.
- A safe default discovery client. `signaturekey.NewHTTPKeyResolver` with a
  zero configuration uses the system clock, a direct client and
  `signaturekey.AdmitHTTPS`: it fetches the keys of any issuer at a public
  HTTPS address, follows no redirect and times out after 10 seconds.
  `signaturekey.NewEgressClient` gives a server's other outbound calls the
  same connection checks.
- Ending a mission. `personserver.Server.TerminateMission(ctx, agent, s256,
  reason)` ends a mission as `revoked`, `superseded`, `administrative` or a
  reason the deployment defines; `completed` and `expired` are refused. The
  store terminates it atomically (`MissionStore.TerminateMission`), an earlier
  end keeps its reason, and every later request under the mission is refused
  with `403 mission_terminated` and that reason. With `TokenRevocation`
  configured to send, the call revokes every unexpired token the mission store
  retained under the mission (`MissionStore.LoadMissionTokens`): each person
  token as `RevokePersonToken` revokes it, and each auth token the Person
  Server issued at its Resource; an Access Server revokes its own when the
  person token reaches it. The result reports each recipient, a pending one
  continues on the next call, and repeating the call is safe. The deciding
  supervisor gets a `terminated` report with the reason.
- Supervision. An R3 authorization from a supervised Agent, three- or
  four-party, goes to its supervisor as an `auth_token` act; an allow grants
  the document as the Resource described it, every operation outright, within
  its `exp`, and `SupervisedR3Artifact` gives the host the document's display.
  A four-party allow that narrows takes effect: the Person Server sends `scope`
  and `exp` in the PS-to-AS token request, and this Access Server issues within
  them; a broader token from an Access Server that ignores them is still
  refused. A supervised four-party request can then wait for the Access Server
  under the Agent's pending URL; the host advances it with `AdvanceFederation`,
  and the grant is checked against the allow and reported once, on release.
- Supervision reports. `revocation.received` is sent for a resource token a
  supervised Agent presented (`token_type` `resource_token`), and direct R3
  tokens are reported as `auth_token.issued`. A mission-bound
  `interaction.requested` or `audit.recorded` of an Agent no supervisor decides
  for is replayed with the mission when the Agent is first routed.
- Supervision wire, settled against the drafts. A supervised pending URL
  answers another Agent or key `403 wrong_poller`, an unknown reference
  `410 invalid_code`, and a withdrawal `200 {"status":"cancelled"}`. A denied
  mission request carries the supervisor's or the person's `reason`
  (`aauth.ProblemError.Reason` reads it); a token request's denial carries
  none. An Agent's `updated_request` answering a supervisor's clarification of
  an auth-token request is verified, relayed, and the act completes with its
  tokens. The supervision server applies the person's `mission` and `always`
  answers to later acts of the same kind before `Decide` (`Config.Kind`,
  `DefaultKind`, `ReachStore`), and its signed decisions carry `keyid`.
- Where Go and aauth-rust still differ: Go keeps its Core codes for an
  immediate denial (`person_token_denied`, `mission_denied`,
  `mission_update_denied`, `mission_completion_denied`) and `410 invalid_code`
  after a terminal answer; Go's supervision server repeats the bytes it signed
  for a request binding where aauth-rust signs each repeat afresh; and
  aauth-rust's Access Server refuses the `scope` and `exp` members a narrowing
  Go Person Server sends, which ends that request in `400 invalid_request`.
  See INTERPRETATIONS.md.
- Store adapters implement `MissionStore.TerminateMission` and
  `LoadMissionTokens`, retain `FederatedAuthorizationRecord.Supervision` and
  `SupervisedRequest.Update` as immutable, and a supervision server store
  implements `ReachStore`. `storetest.RunMission`, `RunMissionR3Issuance` and
  the federated contract check the Person Server ones.

Still open: an `updated_request` answering the person's own question, or one
that brings an R3 document, which are refused `400`; the wire endpoint for
ending a mission, which Core leaves to a companion specification
(`mission_control_endpoint`); and outbound calls other than discovery, which
still take an explicit `HTTPClient` and `Admit`. Resource-initiated
interaction for a supervised Agent, and an Agent Provider's revocation
reaching the Person Server its Agent token names, closed on 2026-11-02.

Changes on 2026-11-02: the carried gaps.

- Reading a mission. The owning Agent's signed, bodyless GET of
  `{mission_endpoint}/{mission_s256}` answers `200` with `s256`, `mission`
  (the bytes the approval returned, Core line 1437) and `updates` (each
  accepted update's `s256` and `encoded` bytes, oldest first, Core line 1481).
  Before, it answered `405`. An absent mission and another Agent's answer
  `404 mission_not_found`, and a terminated one `403 mission_terminated`.
  `agent.Client.ReadMission` reads and verifies it, through
  `aauth.DecodeMissionRead`.
- Metadata decoders. `aauth.DecodeAgentProviderMetadata`,
  `DecodePersonServerMetadata`, `DecodeAccessServerMetadata` and
  `DecodeResourceMetadata` verify one fetched document and return its parsed
  form: issuer present and equal to the fetch origin (`issuer_missing`,
  `issuer_mismatch`), required members present, `https` URLs, and endpoints
  without query or fragment (Core, Metadata Documents and Endpoint and Other
  URLs). The Agent client uses them, so it now refuses Person Server metadata
  without `jwks_uri`, which Core requires.
- Agent fan-out. With `agentprovider.Config.IssuedTokens`, the provider
  records the `jti`, `sub`, `ps` and `exp` of every Agent token it issues,
  sub-agent and refresh tokens included, before returning it, and
  `RevocationClient.RevokeAgent` revokes each unexpired token of an Agent at
  the Person Server it names (Core, Revocation Cascade). A token with no `ps`
  is reported as `ErrAgentTokenNamesNoPersonServer`.
- Supervised Resource-initiated interaction. A supervised Agent's auth-token
  request whose resource token carries an `interaction` claim goes to the
  supervisor; an allow, or the person's allow on an ask, starts the
  Resource-initiated steps, and when the Resource returns the person the
  Person Server issues within the allow and reports `auth_token.issued` under
  its `sdi`. The host makes no consent decision for it. After a later
  decision, the Agent's supervised pending URL delivers the interaction
  requirement and then relays to the pending authorization.
- An approved R3 per-call retry sent with `Connection: close` runs, as it has
  since 2026-10-31 (above); this batch checked it again.
- API changes: `agentprovider.Server.Issue` takes a context;
  `personserver.FederatedSupervision` is renamed `SupervisedAllow` and is also
  `PendingAuthorizationRecord.Supervision`, which deferred authorization
  stores retain; `SupervisionCompositionError` is gone; every interactive
  approval is reported to a supervisor or kept for replay, as an immediate one
  is.

For a first integration, start with [Use it in your service](USE-IN-YOUR-SERVICE.md)
and the [glossary](GLOSSARY.md). This matrix is a bounded reference: behavior
not stated here is not claimed.

Status terms:

- **Implemented** — an executing role path and focused negative tests cover the
  stated boundary.
- **Partial** — reusable code exists, but the stated source area is not complete
  or lacks an executing role path.
- **Not implemented** — no current supported path is claimed.

## Binding replacement boundary

A configured Agent-binding revocation store fences old requests using their
original verification time, including time spent in host policy or AS work.
After replacement, AS-issued Auth tokens are refused as presented credentials:
their issuer's clock cannot prove the PS binding generation. Obtain a fresh
PS Person token for each new authorization or step-up. A local JWT's
whole-second `iat` must be strictly later than the replacement instant.
Revocation checks and issuance commits are not one atomic transaction across
stores; a host requiring that cutoff coordinates both operations. Delivered
tokens expire normally. See [the binding interpretation](INTERPRETATIONS.md#a-revoked-agent-person-binding-ends-issuance-and-pending-delivery)
and [race regressions](personserver/agent_binding_admission_race_test.go).

## Presented-token verification

The targeted Protocol -11 overlay in [SPECIFICATIONS.md](SPECIFICATIONS.md)
requires the Agent to send the Person or Auth token previously presented to
the Resource. PS and AS use `aauth.VerifyPresentedToken` to bind its signature,
type, expiry, audience, PS, subject, Agent key, tenant, mission and `jti` to the
Resource token. Issued Auth tokens cannot outlive it; deferred PS delivery
checks expiry again. Invalid and expired tokens have distinct errors.

- A directly presented token may lack a retained record; any existing record
  must agree. Call chaining requires the PS's own upstream issuance record.
- Core verification grants no R3 or Budget authority. Companion validators
  decide those; R3 retries bind class context, not token lineage.
- PS relays terminal AS errors. Unreachable or unverifiable AS responses are
  `502 as_unreachable`; a PS store failure remains `server_error`.
- A missionless clarification accepts `updated_request`, with the limits named
  under Clarification chat.

Evidence is linked in the PS Token Endpoint, Access Server federation, and
Call chaining rows below. See [INTERPRETATIONS.md](INTERPRETATIONS.md) for
choices where the sources do not determine behavior.

## AAuth Core

`resource.Server` and `resource.ResourceManagedServer` refuse a request authority
different from their Issuer before routing or policy. This is a [local routing safeguard](INTERPRETATIONS.md#resource-handlers-admit-their-configured-authority);
the draft does not explicitly prescribe the comparison. The
[authority matrix](resource/authority_test.go) covers
Agent and Person identity plus PS- and AS-issued Auth tokens, DNS case and
default-port normalization, forwarding headers, and host/path mutations.
The [session authority regression](resource/session_authority_test.go) covers
initial authorization, session use, discovery and pending routes before state
access. A correctly signed path still needs application routing and access policy.

The bounded request profile signs and requires `content-digest` on nonempty
content, plus `content-type` when present. This is a [local default](INTERPRETATIONS.md#nonempty-request-content-is-covered-by-default),
permitted by Resource component negotiation. [Signer tests](signaturekey/body_default_test.go)
check actual bytes and limits; the [Resource matrix](resource/body_coverage_test.go)
rejects missing coverage, altered bodies and media types before policy in all
four token modes, including bodies with unspecified or unknown length.
The [service example](example/verifyagent/main.go) uses that default; its
`digestEverywhereResource` additionally requires digests on empty requests,
and [its tests](example/verifyagent/main_test.go) exercise that explicit
configuration.

| Source area | Status | Current boundary | Evidence |
| --- | --- | --- | --- |
| Agent identifiers and token structure | Implemented | Validates top-level and one-level sub-agent identifiers (the `local` part accepts `A-Za-z`, and identifiers compare exactly, never case-folded, per Protocol -11 §5.2; a `local` part with `+` has one `+` between two non-empty parts); mints and verifies an Ed25519 or ES256 agent token bound to one Ed25519 or ES256 Agent key and an optional Person Server. `VerifySubagentToken` admits a child only for its verified top-level parent: `parent_agent` names that parent, both tokens share one issuer, a child `ps` (when present) equals the parent's, and the child holds its own key (Protocol -11 Sub-Agents; Bootstrap Sub-Agent Tokens). The Agent Provider's `Issue` mints top-level tokens; `IssueSubagent` verifies the parent with the provider's own key, copies its `ps`, names the child `parent+discriminator`, and caps the child at the parent's `exp` (Bootstrap Sub-Agent Tokens). `SubagentHandler` serves the hosted request a parent signs with its own key and token, and `agent.Client.RequestSubagentToken` sends it and verifies the returned child. Additional claims remain available to Resource, PS, and AS policy. | [`core_token_api_external_test.go`](core_token_api_external_test.go), [`subagent_external_test.go`](subagent_external_test.go), [`agentprovider/server_test.go`](agentprovider/server_test.go), [`agentprovider/subagent_test.go`](agentprovider/subagent_test.go), [`agentprovider/subagent_http_test.go`](agentprovider/subagent_http_test.go), [`agent/agent_identity_test.go`](agent/agent_identity_test.go) |
| Obtaining an agent token | Implemented | Core leaves this step to Bootstrap (Core line 226), and Bootstrap is informational with no BCP 14 requirements (Bootstrap lines 90, 112, 130). Implemented against its patterns: hosted enrollment under a durable `hwk` key (lines 406–413); two-key refresh that chains a fresh ephemeral key to the durable key through `jkt-jwt`, with a `jti` in the naming JWT (lines 293–321); single-key `hwk` refresh that keeps the same `cnf.jwk` (line 325); a `sub` that stays stable across ephemeral rotation (lines 255–259); and self-hosted issuance, either with the one published key as the Agent's own key or under one published AP key for several Agents with their own keys (lines 178–196, 331). Sub-agent tokens are in the row above. The bootstrap client's Begin methods poll a deferred enrollment or refresh under the same key. `BootstrapClient.NeedsRefresh` decides when an Agent token is inside the five-minute refresh margin, `agent.RefreshMargin` (Core line 1301, applied by Bootstrap line 291). Host transitions disable, restore, or terminally revoke an enrollment, the revocation line 447 asks an AP to offer. AP token revocation reaches the recipients the host names; with `Config.IssuedTokens`, `RevokeAgent` reaches the Person Server each of an Agent's tokens names. Left to host policy: platform attestation, which the draft makes optional AP policy (lines 106, 208, 241–247). The library carries it as opaque signed `evidence`; the host callback verifies any WebAuthn, App Attest or Play Integrity result, its server nonce and its freshness (lines 319, 329, 455). A refresh body may omit `evidence`, as the draft's example body `{}` does (line 316); the host callback then receives empty evidence and decides, so a host that requires evidence still refuses (line 106). Key replacement is not a separate feature: every two-key refresh rotates the ephemeral key, and a durable-key change is a new enrollment and so a new Agent (lines 259, 337), with the old enrollment revoked by host transition. AP signing-key rollover is a Core concern; see the AP signing-key overlap row below. Not claimed: desktop and headless workload patterns, which the draft leaves TBD (lines 198–204). | [`agentprovider/enrollment_test.go`](agentprovider/enrollment_test.go), [`agentprovider/enrollment_http_test.go`](agentprovider/enrollment_http_test.go), [`agentprovider/storetest/enrollment.go`](agentprovider/storetest/enrollment.go), [`agentprovider/revocation_test.go`](agentprovider/revocation_test.go), [`personserver/agent_token_revocation_test.go`](personserver/agent_token_revocation_test.go), [`resource/agent_token_revocation_test.go`](resource/agent_token_revocation_test.go), [`agentprovider/self_hosted_test.go`](agentprovider/self_hosted_test.go), [`agent/bootstrap_test.go`](agent/bootstrap_test.go), [`integration/bootstrap_refresh_test.go`](integration/bootstrap_refresh_test.go), [`integration/bootstrap_single_key_test.go`](integration/bootstrap_single_key_test.go), [`integration/bootstrap_self_hosted_test.go`](integration/bootstrap_self_hosted_test.go), [`integration/agent_token_revocation_test.go`](integration/agent_token_revocation_test.go), [`example/bootstrap`](example/bootstrap), [`example/revocation`](example/revocation), [`example/selfhosted`](example/selfhosted) |
| AP signing-key overlap | Not implemented | The built-in AP publishes only its active signing key. The HTTP resolver selects by `kid` from multi-key JWKS and retains cached keys until refresh, but AP overlap publication and retirement timing need host implementation. Replacing the AP key can invalidate outstanding tokens after refresh. | `TestHandlerServesAgentMetadataAndJWKS` in [`agentprovider/server_test.go`](agentprovider/server_test.go); `TestAgentProviderKeyReplacementAndHostPublishedOverlap` in [`integration/agentprovider_rotation_test.go`](integration/agentprovider_rotation_test.go) |
| Agent identity Resource access | Implemented | `NewAgentIdentity` verifies a top-level or one-level child token and request proof, then supplies `AgentPrincipal`. It requires no Resource signing key or person policy. Optional AP-token revocation precedes dispatch. `CallAsAgent` discovers metadata, and a Resource that publishes none (`404`) has only the base components; `CallAsAgentWithComponents` accepts explicit components. Neither retries; an Agent without a PS surfaces a person-token requirement as unsatisfiable. | [`requirement_identity_test.go`](requirement_identity_test.go), [`resource/direct_identity_test.go`](resource/direct_identity_test.go), [`resource/agent_token_revocation_test.go`](resource/agent_token_revocation_test.go), [`agent/agent_identity_test.go`](agent/agent_identity_test.go), [`integration/direct_identity_access_test.go`](integration/direct_identity_access_test.go), [`integration/agent_token_revocation_test.go`](integration/agent_token_revocation_test.go) |
| Person token structure, usage, and verification | Implemented | Mints and verifies the current directed identity token, including issuer, Resource, subject, confirmation key, optional mission digest, and prohibition on authorization claims. Person, Resource and auth tokens are read with `aud` as a string or an array of one string, and minted with the string. Direct lifetime is capped by the requesting Agent token; a mission-bound token is also capped by the approved mission; parent-mediated lifetime is capped by the earlier parent or child token. | [`core_token_api_external_test.go`](core_token_api_external_test.go), [`personserver/server_test.go`](personserver/server_test.go), [`personserver/mission_test.go`](personserver/mission_test.go), [`agent/mission_test.go`](agent/mission_test.go), [`agent/subagent_authorization_test.go`](agent/subagent_authorization_test.go) |
| Person Token Endpoint | Partial | Immediate top-level, mission-bound, parent-mediated child, and same-PS call-chain issuance. PS-hosted interaction supports top-level requests and missionless children; the parent polls while the credential binds the child. A refused `subagent_token` is `400` `invalid_`, `expired_` or `revoked_subagent_token`. A host-revoked Agent-person binding refuses new Person tokens for the Agent and every child it mediates, from this endpoint or a mission approval (`403 person_token_denied`, with a `detail` naming the binding), and ends pending interactions; a replacement binding admits only later requests. A PS-hosted wait whose starting Agent token or sub-agent token its Agent Provider revoked ends with `403 revoked`. Mission transitions compare exact active state atomically. Call chains retain exact upstream identity and digest, and carry the upstream token's mission. The interaction page retains the visit's callback (`ConsumePersonTokenInteractionVisit`) and returns the person there with the outcome or `error` (`CompletionURL`, `FailureURL`, `PersonTokenCallbackURL`). Mission-bound parent mediation and call-chain interaction are absent. | [`personserver/subagent_profile_test.go`](personserver/subagent_profile_test.go), [`personserver/agent_binding_lifecycle_test.go`](personserver/agent_binding_lifecycle_test.go), [`agent/mission_test.go`](agent/mission_test.go), [`agent/person_token_interaction_test.go`](agent/person_token_interaction_test.go), [`agent/subagent_authorization_test.go`](agent/subagent_authorization_test.go), [`agent/call_chaining_test.go`](agent/call_chaining_test.go), [`personserver/mission_test.go`](personserver/mission_test.go), [`personserver/person_interaction_test.go`](personserver/person_interaction_test.go), [`integration/person_token_interaction_test.go`](integration/person_token_interaction_test.go), [`personserver/storetest/deferred_token.go`](personserver/storetest/deferred_token.go) |
| Person identity Resource access | Implemented | `NewPersonIdentity` advertises `person-token`, requires no Resource key, AS, or scope catalog, challenges a missing or wrong-mode credential with parameterless `requirement=person-token`, verifies directed token and proof context, resolves `(iss, sub)`, and supplies a scope-free `PersonPrincipal`. Equal subjects from distinct PS issuers remain distinct. | [`requirement_identity_test.go`](requirement_identity_test.go), [`resource/direct_identity_test.go`](resource/direct_identity_test.go), [`integration/direct_identity_access_test.go`](integration/direct_identity_access_test.go) |
| Resource token structure and verification | Implemented | Mints and verifies the immediate resource assertion, including an optional login_hint, Person Server, directed subject, the ID of the presented token (a Person token, or the earlier Auth token on step-up), agent key thumbprint, scope, and optional account and mission digest. Missionless tokens have an independent five-minute lifetime and may outlive the Person token covered by PS retention; mission-bound tokens are capped by the verified Person token and therefore the mission expiry. A protected route's challenge to a mission-bound Person token copies its `mission_s256`; a Resource that holds requests challenges such a request without holding it. | [`core_token_api_external_test.go`](core_token_api_external_test.go), [`resource/server_test.go`](resource/server_test.go), [`resource/challenge_test.go`](resource/challenge_test.go), [`agent/client_test.go`](agent/client_test.go), [`integration/three_party_authorization_test.go`](integration/three_party_authorization_test.go), [`integration/mission_three_party_test.go`](integration/mission_three_party_test.go), [`integration/mission_four_party_test.go`](integration/mission_four_party_test.go) |
| Resource authorization endpoint | Partial | PS and federated constructors issue Resource tokens from verified Person tokens, declared scopes, and an optional validated account. They preserve a mission digest without receiving its content. Either may compose class R3 with a fixed Budget. Signed JSON binds content type and digest; unconfigured companions and deferred branches fail closed. When the host supplies an AuthorizationAsk, issuance copies login_hint and fills an omitted account from the ask, and protected use rejects an auth token whose ps, sub, account, or tenant (including absence) does not match that ask. The hint string is not compared with sub. The Agent's `BeginAuthorize` polls a deferred answer and also accepts a Resource's own grant with an `AAuth-Access` session; the Resource constructors do not issue sessions from this endpoint. | [`resource/server_test.go`](resource/server_test.go), [`resource/ps_authorization_test.go`](resource/ps_authorization_test.go), [`resource/r3_test.go`](resource/r3_test.go), [`resource/budget_test.go`](resource/budget_test.go), [`integration/three_party_authorization_test.go`](integration/three_party_authorization_test.go), [`integration/budget_three_party_test.go`](integration/budget_three_party_test.go), [`integration/budget_four_party_test.go`](integration/budget_four_party_test.go), [`integration/r3_budget_three_party_test.go`](integration/r3_budget_three_party_test.go), [`integration/r3_direct_four_party_test.go`](integration/r3_direct_four_party_test.go), [`integration/mission_three_party_test.go`](integration/mission_three_party_test.go), [`integration/mission_four_party_test.go`](integration/mission_four_party_test.go) |
| PS Token Endpoint | Partial | Direct issuance and federation verify `presented_token` before policy; retained records must agree, but directly presented tokens need not have a record. Both support immediate parent mediation and top-level missions. Direct deferral supports top-level requests and missionless children, with parent polling and child credentials. Mission transitions and token retention are atomic. AS payment, approval, claims and interaction continuations, missionless or mission-bound, top-level, chained or parent-mediated, use explicit host-driven polling, and a due wait advertises `Retry-After` of at least one second; only the Agent that signed the request polls or cancels (`DELETE`), a cancellation that races a host advance still withdraws, and a child grant binds the child key. A host-revoked Agent-person binding refuses the next request and any pending delivery with `revoked_presented_token`, as does a wait from before a replacement binding. POST /person accepts optional login_hint, tenant, domain_hint, prompt, platform, device, and justification and ignores their values. An unregistered prompt or platform, or a device that is not printable UTF-8 of at most 64 characters, is invalid_request. When interaction is required and capabilities include neither interaction nor clarification, the response is 403 user_unreachable. Omitted capabilities fall back to a bound mission. A direct deferred budget approval retains the resource offer and mints the narrowed grant. The consent page retains the visit's callback (`ConsumeAuthorizationInteractionVisit`) and returns the person there with the outcome or `error` (`CompletionURL`, `FailureURL`, `AuthorizationCallbackURL`). The Agent polls a pending R3 or Budget exchange like any other. Both compositions chain calls, and a federated chained request can wait for the AS. AS clarification, mission-bound parent mediation, and lost-immediate-response recovery are absent. | [`personserver/subagent_profile_test.go`](personserver/subagent_profile_test.go), [`integration/subagent_federated_deferred_test.go`](integration/subagent_federated_deferred_test.go), [`personserver/mission_test.go`](personserver/mission_test.go), [`personserver/mission_federation_test.go`](personserver/mission_federation_test.go), [`personserver/three_party_test.go`](personserver/three_party_test.go), [`personserver/call_chaining_test.go`](personserver/call_chaining_test.go), [`personserver/authorization_interaction_test.go`](personserver/authorization_interaction_test.go), [`personserver/clarification_test.go`](personserver/clarification_test.go), [`personserver/mission_deferred_authorization_test.go`](personserver/mission_deferred_authorization_test.go), [`personserver/subagent_test.go`](personserver/subagent_test.go), [`integration/mission_three_party_test.go`](integration/mission_three_party_test.go), [`integration/mission_four_party_test.go`](integration/mission_four_party_test.go), [`integration/deferred_ps_authorization_test.go`](integration/deferred_ps_authorization_test.go), [`integration/clarification_three_party_test.go`](integration/clarification_three_party_test.go), [`integration/subagent_authorization_test.go`](integration/subagent_authorization_test.go), [`integration/federated_deferred_test.go`](integration/federated_deferred_test.go) |
| Access Server federation | Partial | Immediate top-level or parent-mediated PS-to-AS exchange verifies the PS proof, Agent tokens, Resource token, and child-key binding. A top-level mission digest stays opaque to the AS. Optional fixed Budget and account context are independently checked by PS and AS; the PS verifies the returned grant. A Core request, missionless or mission-bound, top-level, chained or parent-mediated, can wait for AS approval or a WWW-Authenticate payment challenge, then deliver a verified grant or error through separate PS/AS pending stores. The PS host advances each AS poll explicitly. The AS reverifies both Agent tokens on every poll, binds a child grant to the child key, and ends its wait by the earlier Agent expiry; the owning PS withdraws a wait with a signed `DELETE` when the Agent cancels it or the PS ends it on its own. A missionless Core claims wait returns requirement=claims with required_claims. The PS posts one JSON object of those names, never sub, and the Agent still sees approval. A chained request passes the exact `upstream_token`, which the AS verifies; it can wait like any Core request, and a wait whose upstream or resource token is revoked ends with `revoked`. A mission-bound grant is capped by the presented token, which the PS capped at the mission's expiry, not by the Resource token. An AS interaction (`PendingDecision.InteractionURL`, with the code the AS drew for the wait) reaches the Agent unchanged, chained or not, when the request declared `interaction`; otherwise the PS answers `403 user_unreachable` and withdraws the request. A chained request may carry the PS's Budget ceiling, and a per-call proposal may too when its Resource token offers a release cost; the AS grants it on the per-call token. A supervised request carries its supervisor's narrowing as `scope` and `exp`, which the AS applies, and can wait like any Core request. Clarification, other payment-header formats, and deferred R3 and Budget combinations remain absent. | [`accessserver/server_test.go`](accessserver/server_test.go), [`accessserver/narrowing_test.go`](accessserver/narrowing_test.go), [`integration/supervision_four_party_test.go`](integration/supervision_four_party_test.go), [`integration/subagent_authorization_test.go`](integration/subagent_authorization_test.go), [`integration/r3_metered_release_four_party_test.go`](integration/r3_metered_release_four_party_test.go), [`integration/subagent_federated_deferred_test.go`](integration/subagent_federated_deferred_test.go), [`integration/budget_four_party_test.go`](integration/budget_four_party_test.go), [`integration/mission_four_party_test.go`](integration/mission_four_party_test.go), [`integration/federated_deferred_test.go`](integration/federated_deferred_test.go), [`accessserver/claims_test.go`](accessserver/claims_test.go), [`example/federatedpayment`](example/federatedpayment) |
| Auth token structure, verification, and protected use | Implemented | The signed auth token's `dwk` selects a root-verified Person- or Access-Server role; the Agent separately binds `iss` to the resource-token audience. Explicit Resource constructors enforce the accepted role, including when PS and AS are collocated. Agent and Resource also verify audience, PS, subject, key, scope, optional account, context, and lifetime before one signed application call. Mission-digest continuity is verified before release; on protected use the Resource verifies the Auth token and exposes its signed digest as context without receiving mission content. | [`accessserver/server_test.go`](accessserver/server_test.go), [`personserver/three_party_test.go`](personserver/three_party_test.go), [`resource/ps_authorization_test.go`](resource/ps_authorization_test.go), [`resource/server_test.go`](resource/server_test.go), [`agent/client_test.go`](agent/client_test.go), [`integration/three_party_authorization_test.go`](integration/three_party_authorization_test.go), [`integration/mission_four_party_test.go`](integration/mission_four_party_test.go) |
| Auth-token requirement delivery | Implemented | `agent.Begin` verifies the baseline `401` requirement used by both authorization topologies and the Resource-held `202` form exposed only by `NewFederatedAuthorization`. Held delivery requires same-origin `Location`, decimal `Retry-After`, `no-store`, bounded JSON status, and a verified resource token. `PollAuthToken` performs exactly one locally bound signed `GET`; it never sleeps, exchanges, retries, or resends the application request. | [`agent/call_test.go`](agent/call_test.go), [`resource/challenge_test.go`](resource/challenge_test.go), [`resource/held_test.go`](resource/held_test.go) |
| Immediate three-party path | Partial | AP → Agent → PS → Resource → PS → Resource, with optional prior mission approval. The PS verifies the presented token and any retained record, then issues a narrowed grant. No AS participates. | [`integration/three_party_authorization_test.go`](integration/three_party_authorization_test.go), [`integration/mission_three_party_test.go`](integration/mission_three_party_test.go) |
| Federated four-party path | Partial | Missionless federation covers baseline retry and held delivery across Resource recomposition. Immediate top-level missions may compose class R3 and fixed Budget: AS audit precedes response, then PS mission comparison and exact-token retention precede release. A mission race can leave an AS audit without releasing the token. Mission-bound held delivery is absent. | [`integration/core_four_party_test.go`](integration/core_four_party_test.go), [`integration/mission_four_party_test.go`](integration/mission_four_party_test.go), [`example/fourparty`](example/fourparty) |
| Call chaining | Partial | Three- and four-party Resource-to-Resource chains over repeated hops. The upstream token is a person token or an auth token the PS issued, or delivered from an AS and kept a receipt of; that record identifies the calling Agent. An auth token carrying a Budget grant is verified with it and grants nothing downstream; one carrying R3 claims is refused. The upstream audience must match the intermediary's Agent-token `iss`, and routing follows the token's `iss` or `ps`. The exact upstream bytes repeat at both PS calls and at the AS, and bound downstream expiry. An upstream mission is evaluated and carried down the chain; an account is not. Four-party chained requests can wait for AS approval, payment, claims or interaction, reverified on every poll; a revoked upstream token ends the wait with `revoked`. An AS interaction reaches the intermediary with the AS's URL and code, for it to chain to its caller. Each hop's Budget is sized from its own Resource token's offer, at the PS in three-party access and through the PS ceiling and the AS in four-party access; nothing is drawn from the upstream token. Revoking a person token, or an Agent token, revokes the chains built on it. Sub-agent intermediaries, R3, and three-party PS-hosted consent for a chained request are absent. See [call-chain limits](#call-chain-limits). | [`agent/call_chaining_test.go`](agent/call_chaining_test.go), [`personserver/call_chaining_test.go`](personserver/call_chaining_test.go), [`personserver/call_chaining_lineage_test.go`](personserver/call_chaining_lineage_test.go), [`integration/call_chaining_test.go`](integration/call_chaining_test.go), [`integration/call_chaining_four_party_test.go`](integration/call_chaining_four_party_test.go), [`integration/call_chaining_hops_test.go`](integration/call_chaining_hops_test.go), [`accessserver/upstream_external_test.go`](accessserver/upstream_external_test.go) |
| Permission Endpoint | Partial | Top-level missionless and mission-bound local-action permission, immediate or deferred, in both PS compositions. Exact mission comparison guards release; one terminal poll consumes the decision. The caller executes any action. Automatic tool matching, cross-event mission-log ordering, durable adapters, and uncertain-initial-submission recovery are absent. | [`permission_test.go`](permission_test.go), [`agent/permission_test.go`](agent/permission_test.go), [`personserver/permission_test.go`](personserver/permission_test.go), [`personserver/storetest/permission.go`](personserver/storetest/permission.go), [`personserver/storetest/mission_permission.go`](personserver/storetest/mission_permission.go), [`internal/exampleutil/permission_store_test.go`](internal/exampleutil/permission_store_test.go), [`integration/permission_missionless_test.go`](integration/permission_missionless_test.go), [`integration/permission_mission_test.go`](integration/permission_mission_test.go), [`example/permission`](example/permission) |
| Audit Endpoint | Partial | One signed top-level, mission-bound post-action append in either PS composition. The PS checks active ownership and retains exact ordered entries before `201`; accepted updates remain valid, expiry and completion do not. The Agent polls a deferred append (`BeginAudit`); `SubmitAudit` returns it in a `PendingError`. Cross-event log ordering, PS-side deferral, delegation/chaining, durable adapters, uncertain-result recovery, and Agent log retrieval are absent. | [`audit_test.go`](audit_test.go), [`agent/audit_test.go`](agent/audit_test.go), [`agent/deferred_test.go`](agent/deferred_test.go), [`personserver/audit_test.go`](personserver/audit_test.go), [`personserver/storetest/audit.go`](personserver/storetest/audit.go), [`internal/exampleutil/mission_audit_store_test.go`](internal/exampleutil/mission_audit_store_test.go), [`integration/audit_mission_test.go`](integration/audit_mission_test.go), [`example/audit`](example/audit) |
| Interaction Endpoint | Partial | All three top-level request types, missionless or mission-bound, in either PS composition. Questions retain host answers; bounded relays retain before `202`, survive Server recomposition, and have one terminal consumer. `interaction_unavailable` preserves direct fallback. Mission transitions are atomic. Durable adapters, a complete mission log, and uncertain-initial-result recovery are absent. | [`interaction_endpoint_test.go`](interaction_endpoint_test.go), [`interaction_relay_test.go`](interaction_relay_test.go), [`agent/interaction_endpoint_test.go`](agent/interaction_endpoint_test.go), [`agent/interaction_relay_test.go`](agent/interaction_relay_test.go), [`personserver/interaction_endpoint_test.go`](personserver/interaction_endpoint_test.go), [`personserver/interaction_relay_test.go`](personserver/interaction_relay_test.go), [`integration/interaction_question_test.go`](integration/interaction_question_test.go), [`integration/interaction_relay_test.go`](integration/interaction_relay_test.go), [`example/interactionquestion`](example/interactionquestion), [`example/interactionrelay`](example/interactionrelay) |
| Error responses | Partial | RFC 9457 problems, mission reasons, and typed Signature-Key errors distinguish policy denial from server failure. Request-parameter sub-agent tokens use Protocol -11's `invalid_`, `expired_` and `revoked_subagent_token` at the PS, and `invalid_` and `expired_subagent_token` at the AS, which holds no Agent Provider revocations. Token-endpoint `access_denied` remains provisional. Future `iat` beyond the captured request time plus signature window yields `clock_skew`; verification without a request has no such check. The complete error registry and every challenge form are absent. | [`problem_test.go`](problem_test.go), [`token_issued_at_external_test.go`](token_issued_at_external_test.go), [`signaturekey/issued_at_window_external_test.go`](signaturekey/issued_at_window_external_test.go), [`resource/agent_token_skew_test.go`](resource/agent_token_skew_test.go), [`accessserver/server_test.go`](accessserver/server_test.go), [`personserver/server_test.go`](personserver/server_test.go), [`personserver/three_party_test.go`](personserver/three_party_test.go), [`personserver/mission_test.go`](personserver/mission_test.go), [`resource/budget_test.go`](resource/budget_test.go), [`internal/httpapi/httpapi_test.go`](internal/httpapi/httpapi_test.go), [`signaturekey/error_external_test.go`](signaturekey/error_external_test.go) |
| Resource-managed session-token access | Implemented | `NewResourceManaged` verifies Agent identity and proof, applies immediate or interactive Resource policy, and retains exact opaque sessions before release. Agent calls and polls are explicit, preserving capabilities, replacement sessions, and raw retryable responses. Session use signs `Authorization`; retained state binds stable Agent identity across key rotation. The interaction page retains the visit's callback (`ConsumeSessionInteractionVisit`) and returns the person there with the outcome or `error` (`CompletionURL`, `FailureURL`, `SessionCallbackURL`). Expiry, revocation, and lost-terminal recovery are not fully specified by Core. | [`resource/storetest/session.go`](resource/storetest/session.go), [`resource/session_test.go`](resource/session_test.go), [`resource/session_store_test.go`](resource/session_store_test.go), [`agent/session_test.go`](agent/session_test.go), [`integration/resource_managed_session_test.go`](integration/resource_managed_session_test.go) |
| Mixed per-operation access modes | Not implemented | Each `resource.Server` has one explicit mode. MCP, OpenAPI, and AsyncAPI definition adapters preserve sparse operation hints, and `OperationHints.Plan` gives an Agent an advisory expectation. Those values do not select Resource enforcement or replace a runtime `AAuth-Requirement`. A host can compose separate handlers, but automatic per-operation requirement negotiation is absent. | [`r3/hints_test.go`](r3/hints_test.go), [`resource/r3_test.go`](resource/r3_test.go) |
| Clarification chat and other deferred delivery | Partial | One direct PS consent round, optionally mission-bound: retained question → signed answer or cancellation → explicit host approval and Agent poll. Exact answer replay and changed-answer conflict are checked. Later rounds lack a source-defined identifier (AAG-F095). A missionless clarification accepts `updated_request`: the new resource token and `presented_token` are verified, `iss`, `ps`, `sub`, `agent_jkt`, `mission_s256`, and `tenant` must match the pending ask, a parent-mediated ask matches the child key, both replacement expiries cover the pending deadline, the resource-token lifetime stays within the configured maximum, a retained person-token record must agree, and a revoked Agent-person binding or a revoked Agent or sub-agent token that started the wait is refused. The retained scopes are replaced. Account, Budget, mission-bound, R3, and AS-relayed updated requests are absent. On the Agent, every request a server may defer returns an `agent.Pending` that polls, answers a clarification and cancels. AS clarification relay and durable adapters are absent. Claims continuations are listed under Access Server federation. The separate bounded AS approval/payment path is listed under Access Server federation. | [`agent/exchange_interaction_test.go`](agent/exchange_interaction_test.go), [`personserver/clarification_test.go`](personserver/clarification_test.go), [`personserver/mission_deferred_authorization_test.go`](personserver/mission_deferred_authorization_test.go), [`integration/clarification_three_party_test.go`](integration/clarification_three_party_test.go), [`example/psconsent`](example/psconsent), [`SPEC-FEEDBACK.md`](SPEC-FEEDBACK.md) |
| Missions | Partial | Top-level immediate or approval-only deferred missions, ordered accepted updates, and person-confirmed completion. Approval atomically retains exact mission content, returned Person tokens, and one terminal result. `approved_tools` matching is local planning, not remote enforcement. The deferred proposal retains its original proof key and Agent-token expiry. The Agent follows interaction and clarification on a pending proposal (`AnswerMissionClarification`, `CancelMissionProposal`) and polls a deferred update or completion (`BeginMissionUpdate`, `BeginMissionCompletion`), answering clarifications on it. The Person Server itself defers only proposal approval. A chain built on a mission-bound token carries the mission and ends with it. `TerminateMission` ends a mission as `revoked`, `superseded`, `administrative` or a host reason, atomically at the store and keeping an earlier reason, reports it to the deciding supervisor, and revokes the unexpired person and auth tokens retained under it. The owning Agent reads its mission, with the accepted updates, at the mission's own URL (`ReadMission`). PS-side clarification, deferred update/completion, durable adapters, uncertain-delivery recovery, complete governance/logging, delegation, direct Person identity, held delivery, and the wire endpoint for ending a mission (`mission_control_endpoint`, left to a companion specification) are absent. | [`integration/mission_termination_test.go`](integration/mission_termination_test.go), [`agent/mission_proposal_deferred_test.go`](agent/mission_proposal_deferred_test.go), [`agent/deferred_test.go`](agent/deferred_test.go), [`personserver/mission_proposal_deferred_test.go`](personserver/mission_proposal_deferred_test.go), [`integration/mission_deferred_proposal_test.go`](integration/mission_deferred_proposal_test.go), [`integration/mission_three_party_test.go`](integration/mission_three_party_test.go), [`integration/mission_four_party_test.go`](integration/mission_four_party_test.go), [`example/mission`](example/mission), [`example/fourparty`](example/fourparty), [`SPEC-FEEDBACK.md`](SPEC-FEEDBACK.md) |
| Revocation and re-authorization | Partial | AP-issued Agent-token and three-party PS-issued Auth-token revocation, with role-local retention and explicit caller recovery. An AP with `IssuedTokens` revokes an Agent at each Person Server its tokens name (`RevokeAgent`). Host-invoked Agent-person binding revocation at the PS refuses new Person tokens and missions, presented credentials, chained calls and pending deliveries under that binding, and ends the waits it reaches; `ReestablishAgentBinding` admits later requests while everything from before stays refused. It revokes nothing already delivered, which expires normally. A PS-hosted or federated wait whose starting Agent token or sub-agent token is revoked ends with `revoked`. With an `AgentPersonTokenStore`, an Agent-token revocation also revokes the Agent's person tokens and the chains built on them; the PS answers the Agent Provider `202` until that cascade is terminal. Host-invoked `TerminateMission` revokes the unexpired person and auth tokens a mission store retained under the mission, as `RevokePersonToken` does. Resource refusal preserves `revoked_jwt` and the person-token requirement. The Agent client does not obtain a Person token or retry automatically. [Revocation details](#revocation-details) separate recipient behavior, Agent error handling, and remaining gaps. | [`agentprovider/revocation_test.go`](agentprovider/revocation_test.go), [`personserver/agent_token_revocation_test.go`](personserver/agent_token_revocation_test.go), [`resource/agent_token_revocation_test.go`](resource/agent_token_revocation_test.go), [`integration/agent_token_revocation_test.go`](integration/agent_token_revocation_test.go), [`personserver/revocation_test.go`](personserver/revocation_test.go), [`resource/revocation_test.go`](resource/revocation_test.go), [`integration/revocation_reauthorization_test.go`](integration/revocation_reauthorization_test.go), [`agent/reauthorization_test.go`](agent/reauthorization_test.go), [`agent/call_test.go`](agent/call_test.go), [`integration/revocation_rate_limited_test.go`](integration/revocation_rate_limited_test.go), [`agentprovider/revocation_ratelimited_test.go`](agentprovider/revocation_ratelimited_test.go), [`personserver/revocation_ratelimited_test.go`](personserver/revocation_ratelimited_test.go), [`internal/httpapi/retryafter_test.go`](internal/httpapi/retryafter_test.go), [`integration/call_chaining_hops_test.go`](integration/call_chaining_hops_test.go), [`integration/mission_termination_test.go`](integration/mission_termination_test.go), [`example/revocation`](example/revocation) |
| Agent delegation, call chaining, and sub-agents | Partial | One-level child tokens issued by the parent's own Agent Provider (`BeginSubagentToken` polls a deferred issuance), direct Agent identity, and parent-mediated three-/four-party authorization: immediate, PS-hosted consent, and AS approval or payment. The parent owns consent, its binding, every PS call, poll and cancellation; the child holds the Person and Auth credentials and signs Resource requests, and cannot call or poll the PS. Revoking the parent's binding blocks new issuance, missions and pending delivery, and the PS withdraws any AS wait it ends; delivered Auth tokens expire normally. Call chaining is separate evidence in its own row. Mission-bound mediation, recursive delegation, combined child chaining, Agent Provider records of live sub-agents per parent, and a cascade from the parent's Agent-token revocation to its children's credentials are absent. | [`subagent_external_test.go`](subagent_external_test.go), [`agentprovider/subagent_test.go`](agentprovider/subagent_test.go), [`agentprovider/subagent_http_test.go`](agentprovider/subagent_http_test.go), [`personserver/subagent_profile_test.go`](personserver/subagent_profile_test.go), [`integration/subagent_federated_deferred_test.go`](integration/subagent_federated_deferred_test.go), [`agent/agent_identity_test.go`](agent/agent_identity_test.go), [`agent/subagent_authorization_test.go`](agent/subagent_authorization_test.go), [`agent/call_chaining_test.go`](agent/call_chaining_test.go), [`personserver/subagent_test.go`](personserver/subagent_test.go), [`personserver/call_chaining_test.go`](personserver/call_chaining_test.go), [`resource/direct_identity_test.go`](resource/direct_identity_test.go), [`integration/subagent_authorization_test.go`](integration/subagent_authorization_test.go), [`integration/person_token_interaction_test.go`](integration/person_token_interaction_test.go), [`integration/call_chaining_test.go`](integration/call_chaining_test.go), [`example/subagent`](example/subagent) |
| Third-party login | Not implemented; removed upstream | The baseline Login Flow lacked the person context required by a Resource token. Protocol -11 removed Third-Party Login and `login_endpoint` (28e8258 Core; issue #155, PR #157), resolving AAG-F103 without defining a login-only token profile. No executable login path is claimed. | [`SPEC-FEEDBACK.md`](SPEC-FEEDBACK.md) |

### Revocation details

Recipient behavior and storage:

- AP revokes Agent tokens at a configured PS or known direct Resource, or,
  with `IssuedTokens`, at the PS each of an Agent's tokens names. PS
  revokes its own Auth tokens at a configured Resource. Both send a
  `jwks_uri` proof covering `content-type` and `content-digest`; the body is
  `{jti, exp}`, with issuer identity taken only from the verified proof.
- Auth-token storage binds `(iss, jti)` to exact compact bytes. Unseen
  references can be revoked before first use. Identity conflict is
  `403 access_denied`, store failure is `500`, and an unauthorized revoker
  receives `403 unsupported_iss`.
- A revoked token in `Signature-Key` is refused before host callbacks with
  `401` and `revoked_jwt`. For a revoked Auth token the Resource adds
  `requirement=person-token`, never a Resource token naming the revoked token.

Agent behavior:

- `Do`, `BeginBudgetCall`, `PollAuthToken`, `BeginR3Call`, `RetryR3Call`, and
  `PollR3Call` preserve a valid person-token requirement as
  `*agent.PersonTokenRequiredError`, wrapping the original Signature-Key error.
  The [response matrix](agent/reauthorization_test.go) runs valid, absent,
  malformed, different-requirement, and unrelated-signature-error cases for
  every listed method. Agent- and Person-token calls do not acquire this error.
- **Automatic recovery is not implemented.** The draft's Person Token Required
  section requires obtaining a Person token and retrying the original request
  with it. Returning the error alone does not complete that procedure. The
  [signed integration test](integration/revocation_reauthorization_test.go) and
  [example](example/revocation) compose it explicitly, then exchange the new
  Resource token and use the replacement Auth token. This is distinct from
  the draft's re-authorization procedure after expiry or key rotation.

Delivery and remaining limits:

- AP/PS clients admit discovery and delivery URLs, refuse redirects, and send
  once. A `202` from a Person Server whose Agent-token cascade is not yet
  terminal is `agentprovider.RevocationPendingError`. A `200` with no body
  succeeds; a present body must be a JSON object
  with an optional `downstream` array. Invalid bodies are unavailable results;
  valid downstream reports are not exposed. A valid single `Retry-After` on
  `429 rate_limited` becomes `RateLimitedError`; retry stays caller-controlled.
- Agent, Person, Resource and Auth tokens are revoked. Person and resource
  tokens are revoked at every recipient, the Access Server holds a cascade for
  `Prefer: wait`, and every revocation endpoint answers `429 rate_limited`
  with `Retry-After`. Resource-side Agent revocation is an extension to the source's
  recipient table. A mission cascades through `TerminateMission`; session
  revocation is absent.
- Issuer-stated `exp` has no past-value or upper-bound check. Hosts own
  retention, including far-future values; entry/rate bounds are not supplied.

### Call-chain limits

The [call-chain tests](personserver/call_chaining_lineage_test.go) require
caller identity from the PS's exact issuance record, or, for an auth token an
Access Server issued, the PS's delivery receipt. Missing caller identity is
`invalid_upstream_token`; a revoked caller is `revoked_upstream_token`, and so
is an upstream auth token whose person token the PS revoked, directly or
behind a step-up. An expired upstream token is `expired_upstream_token`. A
malformed or untrusted upstream token remains `invalid_upstream_token`, as is
one carrying a mission the PS does not hold for the calling Agent. The
shortest policy/Agent/presented/mission/upstream expiry bound wins.

Auth-typed step-up repeats the retained upstream bytes, at a three-party PS
and, through the receipt, at a four-party one. The revocation configuration's
issued-token store takes precedence over the ordinary PS issuance store.
Missing directly presented records are accepted and do not prove that no
chain existed. Auth tokens issued after PS-hosted consent carry no caller
identity and cannot be upstream tokens. A revoked binding of the caller, or
of the parent that mediated the caller's upstream token, is also
`revoked_upstream_token`. The chain cascade needs the optional
`ChainedPersonTokenStore` and `AuthTokenLineageStore` extensions, and the
Agent-token cascade `AgentPersonTokenStore`; without them only the revoked
token itself, and auth tokens obtained with it, are refused.

## HTTP Signature Keys

| Source area | Status | Current boundary | Evidence |
| --- | --- | --- | --- |
| `Signature-Key` parsing and HTTP request proof | Partial | The immediate-flow profile signs and verifies an explicitly selected signature label, required request components, present or empty exact query, proof time, and one bounded SHA-256 content-digest form. Unknown noncritical JOSE members are additive; unsupported critical members fail. The complete field grammar and every digest representation are not claimed. A `jwt` or `jkt-jwt` credential may carry bare `;cache`. `Verify` refuses `x509` and `cached` proofs directly; `VerifyX509`, `VerifyCached` and `AssertionCache` implement them and `Signature-Key-Cache`. | [`signaturekey/request_external_test.go`](signaturekey/request_external_test.go), [`signaturekey/body_limit_external_test.go`](signaturekey/body_limit_external_test.go), [`jose/jose_external_test.go`](jose/jose_external_test.go) |
| `jwt` scheme | Implemented | Used for agent-, person-, and auth-token-bound requests. The caller selects the token confirmation key before proof verification. | [`signaturekey/external_module_test.go`](signaturekey/external_module_test.go), [`integration/direct_identity_access_test.go`](integration/direct_identity_access_test.go), [`integration/three_party_authorization_test.go`](integration/three_party_authorization_test.go), [`integration/core_four_party_test.go`](integration/core_four_party_test.go) |
| `jwks_uri` scheme | Implemented | Used for PS-to-AS token exchange, AP-to-PS or direct-Resource Agent-token revocation, and PS-to-Resource Auth-token revocation. Metadata and JWKS resolution are issuer-bound, time- and capacity-bounded, controlled by egress admission, and exercise same-ID rotation after the Core refresh floor. Optional `logo_uri`, `logo_dark_uri`, `documentation_uri`, `tos_uri`, and `policy_uri` values are rejected unless they are absolute `https` URLs; a query or fragment is accepted. | [`signaturekey/discovery_external_test.go`](signaturekey/discovery_external_test.go), [`accessserver/server_test.go`](accessserver/server_test.go), [`agentprovider/revocation_test.go`](agentprovider/revocation_test.go), [`personserver/agent_token_revocation_test.go`](personserver/agent_token_revocation_test.go), [`resource/agent_token_revocation_test.go`](resource/agent_token_revocation_test.go), [`personserver/revocation_test.go`](personserver/revocation_test.go), [`resource/revocation_test.go`](resource/revocation_test.go) |
| `hwk` scheme | Implemented | Ed25519, ES256, ES384, RS256 and PS256 header keys sign and verify under their fully specified `alg`; RSA names its padding and hash. Each endpoint verifies only its `VerifyOptions.AcceptedAlgorithms` (default Ed25519 and ES256). Hosted Agent Provider enrollment and single-key refresh use it. | [`signaturekey/external_module_test.go`](signaturekey/external_module_test.go), [`signaturekey/request_external_test.go`](signaturekey/request_external_test.go), [`agentprovider/enrollment_http_test.go`](agentprovider/enrollment_http_test.go), [`integration/bootstrap_refresh_test.go`](integration/bootstrap_refresh_test.go), [`integration/bootstrap_single_key_test.go`](integration/bootstrap_single_key_test.go) |
| `jkt-jwt` scheme | Partial | Implements mandatory `jkt-s256+jwt` with Ed25519 or ES256 identity and delegated keys (an ES256 durable key suits a secure enclave), thumbprint issuer binding, time and optional cache-JTI checks, and exact delegated HTTP proof. The Agent Provider's two-key refresh requires a `jti` in the naming JWT (Bootstrap line 321) and enforces AP-owned exact replay; single-key refresh uses `hwk`, not `jkt-jwt`, and needs no `refresh_jti`. The SHA-512 variant is absent. | [`signaturekey/jkt_jwt_external_test.go`](signaturekey/jkt_jwt_external_test.go), [`agentprovider/enrollment_test.go`](agentprovider/enrollment_test.go), [`integration/bootstrap_refresh_test.go`](integration/bootstrap_refresh_test.go) |
| `self-jwt` scheme | Partial | The Events path parses `self-jwt`, resolves the Resource key selected by the Event token's `iss`, `dwk`, and `kid`, verifies the Event JWT, and verifies the accompanying HTTP Message Signature with that same key. It rejects `cnf`, wrong token type, wrong discovery role, unsupported algorithms, expiry, key-resolution failure, and a mismatched outer proof. A Resource accepts it from clients outside AAuth through `FurtherSchemesConfig.SelfJWTType`. Other self-issued token profiles are not claimed. | [`signaturekey/self_jwt_external_test.go`](signaturekey/self_jwt_external_test.go), [`agentprovider/events_test.go`](agentprovider/events_test.go), [`integration/events_public_subscription_test.go`](integration/events_public_subscription_test.go) |
| `jwks` scheme | Implemented | The HTTPS JWKS `url` is the signer identity, compared byte for byte; `HTTPKeyResolver` fetches it with the same egress checks, cache and one-minute refresh floor as `jwks_uri`. No role uses it yet. | [`signaturekey`](signaturekey) |
| `x509` scheme | Implemented | The host supplies the PEM chain, trust anchors and CRLs; chain and revocation are checked before the thumbprint and signature. An RSA end-entity certificate is `unsupported_algorithm`. No role uses it yet. | [`signaturekey`](signaturekey) |
| `cached` scheme and Signature-Key-Cache | Implemented | The verifier issues sealed, unpredictable identifiers, never for a self-jwt, an assertion without `jti`, or one with more than 24 hours left; an unknown identifier is `cache_miss` and a held assertion past `exp` is `expired_jwt`. `CachingCredential` presents an identifier only after one is issued and falls back on `cache_miss`. No role uses it yet. | [`signaturekey`](signaturekey) |
| Multiple signatures | Implemented | `SignRequests` writes every Signature-Key member before signing; each signature covers `signature-key`. | [`signaturekey`](signaturekey) |
| Negotiation and `Signature-Error` | Partial | Typed errors and core negotiation headers round-trip. A signature `created` time ahead of the verifier's validity window yields `clock_skew` and an older one `invalid_signature` (Signature-Key `69f5ba2`). A header JWT `iat` beyond the captured request time plus its signature window also yields `401` `Signature-Error: error=clock_skew`; Core verification without a request does not refuse future `iat` by itself. A Signature-Key header with no member for the verified label is `invalid_signature`. A resolved key whose type or algorithm the verifier does not implement is `unsupported_algorithm`, judged before the signature's length. Full challenge and incremental-adoption behavior remain incomplete. | [`signaturekey/error_external_test.go`](signaturekey/error_external_test.go), [`signaturekey/request_external_test.go`](signaturekey/request_external_test.go), [`signaturekey/clock_skew_external_test.go`](signaturekey/clock_skew_external_test.go), [`signaturekey/issued_at_window_external_test.go`](signaturekey/issued_at_window_external_test.go), [`resource/agent_token_skew_test.go`](resource/agent_token_skew_test.go), [`token_issued_at_external_test.go`](token_issued_at_external_test.go) |
| Replay enforcement | Partial | Generic request-proof replay enforcement is absent. Hosted refresh consumes `(durable identity, refresh jti)` as one exact identity. The two-key profile binds the naming JWT and JSON body; the single-key profile binds its signed JSON body and bounded expiry, and a single-key body without `refresh_jti` takes its identity from its own signature. Both freshly sign an outer request, return the retained token on exact replay, and conflict if stable input or key profile changes. | [`agentprovider/enrollment_test.go`](agentprovider/enrollment_test.go), [`agentprovider/enrollment_http_test.go`](agentprovider/enrollment_http_test.go), [`agentprovider/storetest/enrollment.go`](agentprovider/storetest/enrollment.go), [`integration/bootstrap_refresh_test.go`](integration/bootstrap_refresh_test.go), [`integration/bootstrap_single_key_test.go`](integration/bootstrap_single_key_test.go) |

## JOSE profile

| Source area | Status | Current boundary | Evidence |
| --- | --- | --- | --- |
| Ed25519 and ES256 JWK, thumbprint, signing key, and compact JWS | Implemented | Uses caller-owned `crypto.Signer`; signs a token under its key's own `alg` and verifies it only with a key of that `alg`; rejects unsupported algorithms, ambiguous JSON, malformed compact input, and invalid signatures. The core three- and four-party journeys run with every party on Ed25519, on ES256, and mixed. | [`jose/jose_external_test.go`](jose/jose_external_test.go), [`jose/signature_algorithms_external_test.go`](jose/signature_algorithms_external_test.go), [`integration/three_party_authorization_test.go`](integration/three_party_authorization_test.go), [`integration/core_four_party_test.go`](integration/core_four_party_test.go) |
| Other JOSE algorithms and general JWT features | Not implemented | This is a bounded Ed25519 and ES256 token profile, not a general JOSE framework. ES384, RS256 and PS256 keys sign HTTP requests only. | — |

## Storage and recovery

Store contracts check observable transitions in role-specific implementations.
The shipped in-memory fixtures prove Server recomposition, not process restart.
Applications must supply production adapters and backend-failure/restart tests.
No universal store or general replay guarantee is implied.

`testutil.NewAgentTokenRevocationStore` provides a Resource-owned in-memory
fixture that passes [the public revocation contract](testutil/stores_test.go).
It retains markers until discarded, without cleanup or restart persistence.

The public `testutil` mission fixtures expose proposal, permission, audit and
R3 issuance contracts; question and relay variants share their mission
transaction boundary. Missionless permission, question and relay fixtures are
also public. [Public contract tests](testutil/mission_api_test.go) exercise
these constructors, and [external consumer tests](testutil/external_examples_test.go)
copy and run twelve examples outside the module. Public consent/clarification,
Budget, Resource R3 document, R3 issuance, PS-issued Auth-token and Resource
Auth-token status fixtures pass their [role store contracts](testutil/authorization_stores_test.go).
These constructors package in-memory behavior; they do not provide durable
storage or combine separate role transaction boundaries.

| Area | Status | Current boundary | Evidence |
| --- | --- | --- | --- |
| Person-token retention contract | Implemented | `TokenStore.Commit` precedes release. Exchange checks retained records when present; directly presented tokens may lack a record. Chained records retain upstream issuer/JTI and exact digest, requiring the same bytes at the second PS call. | [`personserver/server_test.go`](personserver/server_test.go), [`personserver/call_chaining_test.go`](personserver/call_chaining_test.go), [`integration/core_four_party_test.go`](integration/core_four_party_test.go), [`integration/call_chaining_test.go`](integration/call_chaining_test.go) |
| Mission approval retention contract | Implemented | `CommitMission` atomically retains the approved blob and returned Person tokens. Later issuance compares the exact active mission while retaining tokens; a race during AS work prevents release. `RunMission` checks lifecycle and concurrency; `RunMissionR3Issuance` checks complete cross-record pairing. | [`personserver/storetest/mission.go`](personserver/storetest/mission.go), [`personserver/storetest/mission_r3_issuance.go`](personserver/storetest/mission_r3_issuance.go), [`testutil/mission_contracts_test.go`](testutil/mission_contracts_test.go), [`testutil/external_examples_test.go`](testutil/external_examples_test.go), [`personserver/mission_test.go`](personserver/mission_test.go), [`personserver/mission_federation_test.go`](personserver/mission_federation_test.go), [`integration/mission_three_party_test.go`](integration/mission_three_party_test.go), [`integration/mission_four_party_test.go`](integration/mission_four_party_test.go) |
| Mission update and completion retention contract | Implemented | `AppendMissionUpdate` orders exact accepted updates; `CompleteMission` retains one terminal winner. Both compare policy-time state, materialize expiry, and copy mutable data before publication. `TerminateMission` terminates atomically with a host reason and keeps an earlier one; `LoadMissionTokens` lists every token retained under the mission. All are covered by `RunMission`. | [`personserver/storetest/mission.go`](personserver/storetest/mission.go), [`personserver/mission_lifecycle_test.go`](personserver/mission_lifecycle_test.go), [`personserver/mission_test.go`](personserver/mission_test.go), [`integration/mission_three_party_test.go`](integration/mission_three_party_test.go), [`integration/mission_four_party_test.go`](integration/mission_four_party_test.go), [`example/mission`](example/mission), [`example/fourparty`](example/fourparty) |
| Deferred person-token contract | Implemented | Creation precedes `202`; code correlation and terminal consumption are atomic. `RunDeferredToken` checks unique creation, copy isolation, identity cloaking, the callback retained with the consuming code, expiry, invalidation, competing decisions, and one terminal consumer. | [`personserver/storetest/deferred_token.go`](personserver/storetest/deferred_token.go), [`personserver/person_interaction_test.go`](personserver/person_interaction_test.go), [`integration/person_token_interaction_test.go`](integration/person_token_interaction_test.go), [`example/selfhosted/deferred_store_contract_test.go`](example/selfhosted/deferred_store_contract_test.go) |
| Deferred PS-authorization contract | Implemented | Verified creation precedes `202`; three wrong codes close a waiting request, and only the consuming code's callback is retained. Equivalent approvals converge. Polls reauthenticate the original Agent/key and verify approved claims; one terminal result is consumed before later `410`. `personserver/storetest.RunDeferredAuthorization` includes parent/child separation; `RunClarification` covers the optional extension. | [`personserver/storetest/deferred_authorization.go`](personserver/storetest/deferred_authorization.go), [`personserver/authorization_interaction_test.go`](personserver/authorization_interaction_test.go), [`agent/exchange_interaction_test.go`](agent/exchange_interaction_test.go), [`integration/deferred_ps_authorization_test.go`](integration/deferred_ps_authorization_test.go), [`example/psconsent/store_contract_test.go`](example/psconsent/store_contract_test.go) |
| Local problem diagnostics | Implemented (local API) | An opt-in handler wrapper passes problem status, code, request context and original error to the host after serialization. It preserves standard HTTP writer capabilities; it does not log private causes or observe ordinary application responses. | [`diagnostics/handler_test.go`](diagnostics/handler_test.go), [`diagnostics/example_test.go`](diagnostics/example_test.go), [`resource/diagnostics_test.go`](resource/diagnostics_test.go), [`personserver/diagnostics_test.go`](personserver/diagnostics_test.go), [`accessserver/diagnostics_test.go`](accessserver/diagnostics_test.go), [`agentprovider/diagnostics_test.go`](agentprovider/diagnostics_test.go) |
| Host pending-reference queues | Implemented (local API) | Optional permission and question store interfaces list bounded, issuer-scoped pending snapshots with retained expiry, stable ordering and copied records. References confer no authority; resume and decision APIs recheck state. Both examples discover work after Server recomposition. | [`personserver/pending_references_test.go`](personserver/pending_references_test.go), [`personserver/storetest/pending.go`](personserver/storetest/pending.go), [`testutil/pending_test.go`](testutil/pending_test.go), [`example/permission/main_test.go`](example/permission/main_test.go), [`example/interactionquestion/main_test.go`](example/interactionquestion/main_test.go) |
| Permission-store contracts | Implemented | `PermissionStore` retains decisions and pending requests before release, with Agent/key binding, cloaking, exact replay, conflict refusal, and one terminal consumer. `MissionPermissionStore` adds atomic active-mission comparison. Covered by `RunPermission` and `RunMissionPermission`. | [`personserver/permission_test.go`](personserver/permission_test.go), [`personserver/storetest/permission.go`](personserver/storetest/permission.go), [`personserver/storetest/mission_permission.go`](personserver/storetest/mission_permission.go), [`internal/exampleutil/permission_store_test.go`](internal/exampleutil/permission_store_test.go), [`integration/permission_missionless_test.go`](integration/permission_missionless_test.go), [`integration/permission_mission_test.go`](integration/permission_mission_test.go) |
| Mission-audit store contract | Implemented | `MissionAuditStore` checks active mission identity and lifecycle while appending exact ordered entries. Accepted updates are allowed; expiry and completion refuse append. `RunAudit` checks additive members, copy isolation, and ownership. Cross-event log ordering is absent. | [`personserver/audit_test.go`](personserver/audit_test.go), [`personserver/storetest/audit.go`](personserver/storetest/audit.go), [`internal/exampleutil/mission_audit_store_test.go`](internal/exampleutil/mission_audit_store_test.go), [`integration/audit_mission_test.go`](integration/audit_mission_test.go) |
| Interaction-question store contracts | Implemented | Question stores retain before `202`, cloak identity mismatch, expire pending work, converge one host resolution, and consume one terminal result. The mission variant shares lifecycle transactions. Covered by `RunInteractionQuestion` and `RunMissionInteractionQuestion`. | [`personserver/storetest/interaction_question.go`](personserver/storetest/interaction_question.go), [`personserver/storetest/mission_interaction_question.go`](personserver/storetest/mission_interaction_question.go), [`internal/exampleutil/interaction_question_store_test.go`](internal/exampleutil/interaction_question_store_test.go), [`integration/interaction_question_test.go`](integration/interaction_question_test.go) |
| Interaction-relay store contracts | Implemented | Relay stores retain exact URL/code before `202`, cloak mismatch, expire `max_wait` as no-progress, converge host resolution, and consume one terminal result. The mission variant shares lifecycle transactions. Covered by `RunInteractionRelay` and `RunMissionInteractionRelay`. | [`personserver/storetest/interaction_relay.go`](personserver/storetest/interaction_relay.go), [`personserver/storetest/mission_interaction_relay.go`](personserver/storetest/mission_interaction_relay.go), [`internal/exampleutil/interaction_relay_store_test.go`](internal/exampleutil/interaction_relay_store_test.go), [`integration/interaction_relay_test.go`](integration/interaction_relay_test.go) |
| Resource-session retention contracts | Implemented | Immediate and deferred grants are retained before token exposure. `RunSession` and `RunDeferredSession` check copy isolation, expiry, bounded attempts, approval replay/conflict, invalidation, and terminal consumption. Session use revalidates Resource, Agent, expiry, and route scope. | [`resource/storetest/session.go`](resource/storetest/session.go), [`example/resourcesession/store_contract_test.go`](example/resourcesession/store_contract_test.go), [`resource/session_store_test.go`](resource/session_store_test.go), [`resource/session_test.go`](resource/session_test.go), [`integration/resource_managed_session_test.go`](integration/resource_managed_session_test.go) |
| Held-invocation retention contract | Implemented | Create before pending response; atomic Claim binds the Auth token; fenced Retain precedes publication. Exact-token replay does not redispatch. `RunHeldInvocation` checks concurrency, copy isolation, expiry, fences, wrong-token refusal, and late first completion within `CompletionUntil`. Corrupt state is a server failure. | [`resource/storetest/held.go`](resource/storetest/held.go), [`integration/held_store_contract_test.go`](integration/held_store_contract_test.go), [`resource/held_store_test.go`](resource/held_store_test.go), [`resource/held_test.go`](resource/held_test.go), [`integration/core_four_party_test.go`](integration/core_four_party_test.go) |
| Three-party revocation retention contracts | Implemented | `IssuedAuthTokenStore` retains routing before immediate or deferred publication. `AuthTokenStatusStore` binds exact bytes, accepts unseen-reference revocation, and prevents resurrection. `RunIssuedAuthToken` and `RunAuthTokenStatus` check namespacing, replay/conflict, concurrent transitions, and idempotent revocation. | [`personserver/storetest/issued_auth_token.go`](personserver/storetest/issued_auth_token.go), [`resource/storetest/auth_token_status.go`](resource/storetest/auth_token_status.go), [`example/revocation/store_contract_test.go`](example/revocation/store_contract_test.go), [`personserver/revocation_test.go`](personserver/revocation_test.go), [`resource/revocation_test.go`](resource/revocation_test.go), [`integration/revocation_reauthorization_test.go`](integration/revocation_reauthorization_test.go) |
| Agent-binding revocation contract | Implemented | `AgentBindingRevocationStore` retains, per top-level Agent binding, the latest revocation and any replacement. `RunAgentBindingRevocation` checks the initial state, idempotent revocation that keeps the later instant and clears a replacement, a replacement that requires a revocation, keeps its first instant and never precedes the revocation, provider and Agent isolation, and concurrent convergence; `testutil.NewAgentBindingRevocationStore` passes it. Entries are kept: deleting one re-admits the revoked binding's unexpired credentials. | [`personserver/storetest/agent_binding_revocation.go`](personserver/storetest/agent_binding_revocation.go), [`testutil/federated_test.go`](testutil/federated_test.go), [`personserver/subagent_profile_test.go`](personserver/subagent_profile_test.go), [`personserver/agent_binding_lifecycle_test.go`](personserver/agent_binding_lifecycle_test.go) |
| Agent-token revocation contract | Implemented | Separate PS and Resource stores retain `(iss, jti)` after AP proof verification and refuse later use before policy. Issuer-stated expiry plus host skew governs retention. Both `RunAgentTokenRevocation` contracts check namespacing, exact replay, retained truth, and concurrent convergence. | [`agentprovider/revocation_test.go`](agentprovider/revocation_test.go), [`personserver/agent_token_revocation_test.go`](personserver/agent_token_revocation_test.go), [`personserver/storetest/agent_token_revocation.go`](personserver/storetest/agent_token_revocation.go), [`resource/agent_token_revocation_test.go`](resource/agent_token_revocation_test.go), [`resource/storetest/agent_token_revocation.go`](resource/storetest/agent_token_revocation.go), [`integration/agent_token_revocation_test.go`](integration/agent_token_revocation_test.go), [`example/revocation`](example/revocation), [`example/hostedservice`](example/hostedservice) |
| Agent Provider enrollment and refresh contract | Implemented | `EnrollmentStore` binds one durable-key identity to one stable Agent, retains exact refresh results, and refuses changed replay context. Expired first commits fail; retained winners recover. Host transitions preserve identity/key and expected revision, permit disable/restore, and make revocation terminal. Covered by `RunEnrollment`. | [`agentprovider/storetest/enrollment.go`](agentprovider/storetest/enrollment.go), [`internal/exampleutil/enrollment_store_contract_test.go`](internal/exampleutil/enrollment_store_contract_test.go), [`agentprovider/enrollment_test.go`](agentprovider/enrollment_test.go), [`agentprovider/enrollment_http_test.go`](agentprovider/enrollment_http_test.go), [`integration/bootstrap_refresh_test.go`](integration/bootstrap_refresh_test.go), [`integration/bootstrap_single_key_test.go`](integration/bootstrap_single_key_test.go) |
| Durable store adapters | Not implemented | Hosts supply the role-specific stores needed by their chosen paths. No production file or database adapter is provided. | — |
| Other replay and restart recovery | Not implemented | Domain-specific stores cover only their listed replay boundaries. Immediate mission issuance has no request-bound result lookup. R3 commits audit before release but has no stable retry key; a repeat may issue another audited token. An AS audit can precede PS withholding on a mission race. General request-proof replay and issuance idempotency are absent. Deferred state has role-specific logical contracts below; durable deferred recovery remains unimplemented. | [`personserver/mission_federation_test.go`](personserver/mission_federation_test.go), [`r3/issuance_test.go`](r3/issuance_test.go), [`personserver/r3_direct_test.go`](personserver/r3_direct_test.go), [`accessserver/r3_test.go`](accessserver/r3_test.go), [`integration/mission_four_party_test.go`](integration/mission_four_party_test.go) |

### Deferred federation store contracts

`accessserver/storetest.RunDeferredAuthorization` and
`personserver/storetest.RunFederatedAuthorization` check copy isolation,
immutable request identity (including the PS record's exact `SubagentToken`),
complete response retention (including `FederatedResponse.RefusalReason` in
the PS store), conditional revisions and one terminal consumption.
The optional `personserver/storetest.RunFederatedAuthorizationQueue` checks
bounded pending listing, issuer isolation, stable ordering, expiry filtering
and copy isolation without state changes.
[`testutil/federated_test.go`](testutil/federated_test.go) executes all three through
public constructors, including a PS adapter that round-trips JSON and normalizes
timestamps to UTC. [`integration/federated_deferred_test.go`](integration/federated_deferred_test.go)
checks recomposition, wrong poll identities, expiry, interval enforcement,
concurrent delivery, altered grants and failed completion persistence. It also
executes host queue recovery, Agent retry scheduling and payment/approval display
hints. Local composition refusals execute in
[`personserver/federated_deferred_test.go`](personserver/federated_deferred_test.go).
Single delivery is per continuation: `TestFederatedEquivalentGrantHasNoCrossExchangeBinding`
records acceptance of the same still-valid grant in equivalent exchanges; the
pinned draft defines no grant-to-exchange claim or required grant-JTI cache.
`TestFederatedUnsupportedRequirementIsLocalRefusal` distinguishes unsupported
requirements from AS reachability and preserves typed diagnostics through store
serialization and recomposition. `TestFederatedStoreWithoutQueueStillDelivers`
executes an exchange without optional listing. `TestFederatedConcurrentExpiredAgentPollsConsumeOnce`
checks one expiry response and a consumed refusal for the competing Agent poll.
Pending-reference error names and competing AS polls are pinned by `TestFederatedPendingErrorsDistinguishUnknownAndConsumed`
and `TestFederatedASConcurrentPollsPublishOneResult`; their names are local
extensions documented in [INTERPRETATIONS](INTERPRETATIONS.md#federation-pending-url-error-names-and-competing-polls).
These
in-memory stores do not qualify durable adapters or distributed recovery.

## Companion specifications

The R3 rows below describe supported subsets, not complete draft compliance.

| Source area | Status | Current boundary | Evidence |
| --- | --- | --- | --- |
| R3 vocabularies, metadata, and access annotations | Partial | Grammar and set algebra cover seven vocabularies. Bounded native parsers produce immutable receipt-bearing snapshots; GraphQL introspection returns typed identity-unavailable refusal. MCP, OpenAPI, and AsyncAPI hints are advisory. Invalid Budget/access-mode combinations are rejected at publication and fall back to auth-token during Agent planning. [JOURNEYS](JOURNEYS.md#native-definition-ingestion) lists parser subsets. External acquisition, parser-resource limits, automatic planning, OData annotations, and complete format coverage are absent. | [`r3/definition_test.go`](r3/definition_test.go), [`r3/hints_test.go`](r3/hints_test.go), [`r3/vocabtest/definition_contract_test.go`](r3/vocabtest/definition_contract_test.go), [`r3/vocab/standard/registry_test.go`](r3/vocab/standard/registry_test.go), [`resource/r3_test.go`](resource/r3_test.go), [`integration/r3_vocabulary_helpers_test.go`](integration/r3_vocabulary_helpers_test.go) |
| R3 documents and direct grants | Implemented | Immediate MCP three-party and MCP/OpenAPI/private-codec four-party HTTP grants cover exact documents, signed fetch, narrowed policy, atomic audit, Agent verification, and Resource enforcement. MCP class grants may compose fixed Budget, mission, and account; validation precedes charging. Per-call is four-party-only; its only Budget is a metered release. Other adapters lack role journeys/non-HTTP binding. Annotation-derived policy, delegation/chaining, and independent interop are absent. | [`r3/contract_test.go`](r3/contract_test.go), [`r3/vocabtest/definition_contract_test.go`](r3/vocabtest/definition_contract_test.go), [`token_r3_external_test.go`](token_r3_external_test.go), [`resource/r3_test.go`](resource/r3_test.go), [`personserver/r3_direct_test.go`](personserver/r3_direct_test.go), [`accessserver/r3_test.go`](accessserver/r3_test.go), [`agent/r3_test.go`](agent/r3_test.go), [`integration/r3_direct_three_party_test.go`](integration/r3_direct_three_party_test.go), [`integration/r3_budget_three_party_test.go`](integration/r3_budget_three_party_test.go), [`integration/r3_direct_four_party_test.go`](integration/r3_direct_four_party_test.go), [`integration/mission_four_party_test.go`](integration/mission_four_party_test.go), [`integration/r3_vocabulary_helpers_test.go`](integration/r3_vocabulary_helpers_test.go), [`example/r3threeparty`](example/r3threeparty), [`example/budget`](example/budget), [`example/hostedservice`](example/hostedservice) |
| R3 per-call proposals | Implemented | Four-party MCP/OpenAPI/private-codec HTTP paths cover signed proposals, baseline retry or held delivery, one-operation tokens, parameter/account binding, atomic Claim, late completion, exact replay, and permanent unresolved state after uncertain retention. A retry or held call sent with `Connection: close` or `keep-alive` runs without them. A release-gated call's proposal is fetched and approved across four parties, and its release may be metered against the per-call token. Agent sends/retries/polls are explicit. Other adapters lack role journeys/non-HTTP binding. Durable adapters, annotation-derived access, reclaim, and independent interop are absent. | [`r3/proposal_test.go`](r3/proposal_test.go), [`r3/vocabtest/definition_contract_test.go`](r3/vocabtest/definition_contract_test.go), [`agent/r3_stepup_test.go`](agent/r3_stepup_test.go), [`personserver/r3_proposal_test.go`](personserver/r3_proposal_test.go), [`accessserver/r3_proposal_test.go`](accessserver/r3_proposal_test.go), [`resource/r3_per_call_test.go`](resource/r3_per_call_test.go), [`resource/storetest/held.go`](resource/storetest/held.go), [`integration/held_store_contract_test.go`](integration/held_store_contract_test.go), [`integration/r3_per_call_four_party_test.go`](integration/r3_per_call_four_party_test.go), [`integration/r3_vocabulary_helpers_test.go`](integration/r3_vocabulary_helpers_test.go) |
| Supervision | Partial | The `supervision` package holds the metadata, envelope, request, decision, pending, event, report and error values and the Person Server's signed client; `supervisionserver` is the supervision server role; `personserver.SupervisionConfig` routes Agents to supervisors in both Person Server compositions. For a routed Agent the Person Server puts every mission proposal, update and completion, and every person-token, auth-token (R3 ones included) and permission request, to the deciding supervisor and calls none of its own decision policies. Decisions apply in place, narrowed as allowed; a four-party narrowing is sent to the Access Server as `scope` and `exp` and enforced on its token, and a supervised request can then wait for the Access Server. An ask, and an unavailable supervisor, put the act to the person through the host. Deferred decisions are polled by the host; clarification is relayed both ways within five rounds, including an Agent's verified `updated_request`, with which the act completes. Connect, reconnect on `unknown_sub`, replay on a first route, a routing change and `unknown_mission`, ordered event delivery including `revocation.received` for an Agent token or a resource token the Agent presented and `terminated` for a mission the host ends, idempotent repeats, signed decisions (required by default, with `keyid`) and their later verification all execute. The supervision server accepts a relayed `updated_request`, applies the reach of the person's `mission` and `always` answers to later acts of the same kind, and its host can answer `429 rate_limited` with `Retry-After` (`Config.RateLimit`). A Resource-initiated interaction goes to the supervisor first; after an allow the person completes the Resource's flow, the Person Server issues within the allow, and the Agent polls one pending URL throughout. Not implemented: an `updated_request` answering the person's own question, or one that brings an R3 document, refused `400`. The shipped stores are in memory, and no independent implementation has been run against these roles. | [`supervision/wire_test.go`](supervision/wire_test.go), [`supervisionserver/server_test.go`](supervisionserver/server_test.go), [`supervisionserver/reach_test.go`](supervisionserver/reach_test.go), [`integration/supervision_test.go`](integration/supervision_test.go), [`integration/supervision_wire_test.go`](integration/supervision_wire_test.go), [`integration/supervision_r3_test.go`](integration/supervision_r3_test.go), [`integration/supervision_four_party_test.go`](integration/supervision_four_party_test.go), [`integration/supervision_interaction_test.go`](integration/supervision_interaction_test.go), [`integration/supervision_resource_interaction_test.go`](integration/supervision_resource_interaction_test.go), [`integration/mission_termination_test.go`](integration/mission_termination_test.go), [`example/supervision`](example/supervision) |
| Events subscriptions and delivery | Implemented | 19 of the 22 MUST-level rows of the pinned Events draft have asserting tests. Subscribe-token verification at the Resource (L277) and Agent event verification (L462) are implemented, but no test yet presents a bad JWT signature; AP-to-Agent delivery (L456) is host-defined, as the draft leaves it. Subscribe tokens carry `jti`; event tokens carry `body_s256` when the delivery has a body, and the AP and the Agent both check it before acting. The AP validates a delivery in the draft's order and answers 401 with `Signature-Error` for token and proof failures, 403 for another Resource and 404 for an unknown, inactive or exhausted subscription. It checks `aud` before spending a `max_uses` use and answers `202` with `remaining_uses` only after the inbox store commits; `RunEventInbox` is the store contract. Protected subscription tickets are bound to the establishing key's JWK Thumbprint, expire, and are consumed atomically. The Agent polls a deferred registration with the same subscribe token (`BeginPublicSubscription`, `BeginProtectedSubscription`). `ValidateAsyncAPIDocument` requires the `aauth_subscribe` security scheme, and the Resource's Events service can serve only a document that declares it. Durability is the host store's duty under that contract; the repository ships in-memory stores only. AP-to-Agent transport is host-defined, as the draft leaves it; the AP hands the store the exact verified bytes and the Agent verifies them. Independent interop is recorded separately. | [`events/token_test.go`](events/token_test.go), [`signaturekey/self_jwt_external_test.go`](signaturekey/self_jwt_external_test.go), [`agentprovider/events_test.go`](agentprovider/events_test.go), [`resource/events_test.go`](resource/events_test.go), [`resource/events_protected_test.go`](resource/events_protected_test.go), [`resource/storetest/events_protected.go`](resource/storetest/events_protected.go), [`agent/events_test.go`](agent/events_test.go), [`integration/events_public_subscription_test.go`](integration/events_public_subscription_test.go), [`integration/events_protected_subscription_test.go`](integration/events_protected_subscription_test.go), [`example/events`](example/events) |
| Bootstrap enrollment and refresh | Implemented | Bootstrap is informational and states no requirements (lines 90, 130). "Obtaining an agent token" under AAuth Core gives each pattern and the draft lines. Repository-defined hosted profiles use delegated `jkt-jwt` or durable-key `hwk`; enrollment revocation stops refresh without rewriting issued tokens. Self-hosting publishes one key in ordinary metadata and has no refresh; that key is either the Agent's own or the AP key for several Agents with their own keys. The draft's hosted endpoints are AP-internal (lines 410, 413), so this repository's paths and envelopes are profile choices. Platform attestation is optional host policy carried in signed `evidence` (line 208); a durable-key change is a new enrollment (line 337). Desktop and workload patterns are TBD upstream. The self-hosting rationale conflict is AAG-F104. | [`agentprovider/enrollment_http_test.go`](agentprovider/enrollment_http_test.go), [`agentprovider/storetest/enrollment.go`](agentprovider/storetest/enrollment.go), [`agentprovider/self_hosted_test.go`](agentprovider/self_hosted_test.go), [`agent/bootstrap_test.go`](agent/bootstrap_test.go), [`integration/bootstrap_refresh_test.go`](integration/bootstrap_refresh_test.go), [`integration/bootstrap_single_key_test.go`](integration/bootstrap_single_key_test.go), [`integration/bootstrap_self_hosted_test.go`](integration/bootstrap_self_hosted_test.go), [`example/bootstrap`](example/bootstrap), [`example/selfhosted`](example/selfhosted) |
| Hosted-service repository profile | Implemented | One in-process composition joins enrollment/refresh, permission, mission approval, account-bound MCP class grants, fixed Budget exhaustion/recovery, mission completion, and Agent-token revocation. The connector credential stays private to the application. This is library-composition evidence, not production persistence, OAuth, administrative authentication, or deployment readiness. | [`example/hostedservice`](example/hostedservice), [`HOSTED-SERVICE-PROFILE.md`](HOSTED-SERVICE-PROFILE.md) |
| Budget grants and enforcement | Partial | Fixed-price three-party proactive/reactive and immediate four-party proactive grants. PS and AS validate denomination and independently narrow ceilings; PS omission is not a grant: the AS issues no budget claim, and a metered route treats that Auth token as carrying no Budget authorization. A step-up Resource token may carry `budget_consumed` for the presented Auth token. The PS and AS deliver that signed record to policy without retaining the prior grant. The Resource rejects a record that disagrees with committed spend or uses another scale. In-flight holds reduce `remaining` and are not part of that record. A Budget store that implements usage queries publishes `usage_endpoint` and answers a signed PS or AS `POST /usage` with UTC calendar counters and per-key figures. A Resource with a signing key signs the response under its `jwks_uri` key, covering `@status`, `content-type` and `content-digest` and bound to the request; `budgets.PostUsageChecked` verifies it ([`resource/usage_signature_test.go`](resource/usage_signature_test.go)). `budgets.AccountedSpend` and `budgets.Free` apply the unreported-allocation and settlement rules. `budgets.FormatConsentAmount` and `budgets.SanitizeDescription` are the consent-screen helpers; this library does not render that screen. Optional proactive account, mission, and class R3 bindings survive issuance and enforcement. Operation checks precede atomic charge. Explicit route selection permits free Core calls beside metered routes. Structurally valid, non-revoked tokens receive zero-cost feedback on route refusals. Invalid credentials and pricing failures never reach the Budget store. A free route remains available when its meter fails, with feedback omitted. Three- and four-party replacement-grant step-up executes through explicit exchange and retry. No automatic retry. Direct PS deferred budget approval retains the offer and mints the narrowed grant. A direct Person Server sizes a sub-agent or call-chain auth token from that token's own resource-token offer, and a federated one sends its ceiling for a chained token's offer to the AS. A second token is not reduced by the first, and there is no draw-down from a parent or upstream budget. A four-party Resource with `R3ReleaseConfig.MeterRelease` offers the release cost of a held `budget: true` operation on the per-call proposal's Resource token; the PS ceiling and the AS grant it on the per-call Auth token, and the Resource charges the cost once when it releases the result, refusing a token whose budget is short with `403` and `AAuth-Budget` before the claim, so the result stays held. Absent: same-token shrink, account-bound reactive acquisition, four-party reactive acquisition, held or R3+Budget reactive acquisition, three-party per-call R3, metered per-call execution, federated delegation, an interrupted-stream journey, and durable adapters. `BudgetConfig.Maximum` reserves that bound before dispatch. `SettleBudget` after the header is written commits a lower cost and sends a cost-only trailer. `SettleBudget` before the write, including a handler that writes nothing, sends a fixed-price header and no trailer. A handler that writes and does not settle commits the hold as the trailer. A host can send a streamed `reserved` header and a cost-only `AAuth-Budget` trailer; the Agent does not require the trailer and can apply one with `ApplyTrailer`. The header is sent whether or not the Agent declared the `budget` capability. | [`budgets`](budgets), [`r3/budget_token.go`](r3/budget_token.go), [`resource/r3_release_test.go`](resource/r3_release_test.go), [`integration/r3_metered_release_four_party_test.go`](integration/r3_metered_release_four_party_test.go), [`integration/call_chaining_hops_test.go`](integration/call_chaining_hops_test.go), [`agent/budget_test.go`](agent/budget_test.go), [`agent/budget_call_test.go`](agent/budget_call_test.go), [`resource/budget_test.go`](resource/budget_test.go), [`resource/budget_routes_test.go`](resource/budget_routes_test.go), [`resource/storetest/budget.go`](resource/storetest/budget.go), [`resource/server_test.go`](resource/server_test.go), [`personserver/budget_test.go`](personserver/budget_test.go), [`personserver/budget_delegation_test.go`](personserver/budget_delegation_test.go), [`personserver/federated_budget_test.go`](personserver/federated_budget_test.go), [`accessserver/budget_test.go`](accessserver/budget_test.go), [`token_r3_external_test.go`](token_r3_external_test.go), [`integration/budget_three_party_test.go`](integration/budget_three_party_test.go), [`integration/budget_four_party_test.go`](integration/budget_four_party_test.go), [`integration/mission_four_party_test.go`](integration/mission_four_party_test.go), [`integration/r3_budget_three_party_test.go`](integration/r3_budget_three_party_test.go), [`integration/r3_direct_four_party_test.go`](integration/r3_direct_four_party_test.go), [`example/budget`](example/budget), [`example/hostedservice`](example/hostedservice) |
| Interoperability demo profile | Partial | Internal journeys cover Surfaces 1–4 and parent-mediated Surface 5 separately. Local JavaScript tests stub `fetch`. | [`integration/mission_three_party_test.go`](integration/mission_three_party_test.go), [`integration/mission_four_party_test.go`](integration/mission_four_party_test.go), [`integration/r3_direct_three_party_test.go`](integration/r3_direct_three_party_test.go), [`integration/r3_direct_four_party_test.go`](integration/r3_direct_four_party_test.go), [`integration/r3_per_call_four_party_test.go`](integration/r3_per_call_four_party_test.go), [`example/mission`](example/mission), [`example/r3threeparty`](example/r3threeparty), [`example/fourparty`](example/fourparty), [`integration/subagent_authorization_test.go`](integration/subagent_authorization_test.go), [`walkthrough/interop`](walkthrough/interop) |
