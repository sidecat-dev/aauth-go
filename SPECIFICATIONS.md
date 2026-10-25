# Specification baseline

This repository implements a bounded part of the current AAuth editor source.
The exact commits below define the text used for implementation and review.
Rendered Internet-Draft publications may be older than these editor revisions.

SHA-256 values below are over the raw editor-source bytes at the named commit.
All eight files are the whole editor source at that commit. Notes after the
table record which behavior this library executes; they are not a second pin.

## Exact source manifest

| Document | Repository commit | Editor source | SHA-256 |
| --- | --- | --- | --- |
| AAuth Protocol | [AAuth `70d6737`](https://github.com/dickhardt/AAuth/commit/70d67375deb0bb002af7da0711fc58f6e8926e7e) | [`draft-hardt-oauth-aauth-protocol.md`](https://github.com/dickhardt/AAuth/blob/70d67375deb0bb002af7da0711fc58f6e8926e7e/draft-hardt-oauth-aauth-protocol.md) | `99ef2430c7babec7ea9cb2e9af40e3c3c57d18bce5a6e8501e9748063cfd9ab0` |
| AAuth Rich Resource Requests (R3) | [AAuth `70d6737`](https://github.com/dickhardt/AAuth/commit/70d67375deb0bb002af7da0711fc58f6e8926e7e) | [`draft-hardt-aauth-r3.md`](https://github.com/dickhardt/AAuth/blob/70d67375deb0bb002af7da0711fc58f6e8926e7e/draft-hardt-aauth-r3.md) | `39672880b054e380d39c9c997523b3320216bade2e348a8f79990f2d85e1f2aa` |
| AAuth Events | [AAuth `70d6737`](https://github.com/dickhardt/AAuth/commit/70d67375deb0bb002af7da0711fc58f6e8926e7e) | [`draft-hardt-aauth-events.md`](https://github.com/dickhardt/AAuth/blob/70d67375deb0bb002af7da0711fc58f6e8926e7e/draft-hardt-aauth-events.md) | `462b2fa2fdb10791dd976a7566cd09f5e5d64686c8d6e2966cc2e0caf87acd12` |
| AAuth Bootstrap Guidance | [AAuth `70d6737`](https://github.com/dickhardt/AAuth/commit/70d67375deb0bb002af7da0711fc58f6e8926e7e) | [`draft-hardt-aauth-bootstrap.md`](https://github.com/dickhardt/AAuth/blob/70d67375deb0bb002af7da0711fc58f6e8926e7e/draft-hardt-aauth-bootstrap.md) | `40ca9d052e942a78ef01a827a23bd0149d34a58f626e750949f3ddcd2601b82c` |
| AAuth Budgets | [AAuth `70d6737`](https://github.com/dickhardt/AAuth/commit/70d67375deb0bb002af7da0711fc58f6e8926e7e) | [`draft-hardt-aauth-budgets.md`](https://github.com/dickhardt/AAuth/blob/70d67375deb0bb002af7da0711fc58f6e8926e7e/draft-hardt-aauth-budgets.md) | `f00d34c91576476cdb30b7aa1aa13a0bc9fc1d99fc43b4f0389ccb3e8bf2e150` |
| AAuth Supervision | [AAuth `70d6737`](https://github.com/dickhardt/AAuth/commit/70d67375deb0bb002af7da0711fc58f6e8926e7e) | [`draft-hardt-aauth-supervision.md`](https://github.com/dickhardt/AAuth/blob/70d67375deb0bb002af7da0711fc58f6e8926e7e/draft-hardt-aauth-supervision.md) | `9fd44f899e06bf2a1e903459799cccdd8c6365b5eb5fa1efe2ed5b23b1a6d1a3` |
| AAuth Interoperability Demo Profile | [AAuth `70d6737`](https://github.com/dickhardt/AAuth/commit/70d67375deb0bb002af7da0711fc58f6e8926e7e) | [`interop-demo-profile.md`](https://github.com/dickhardt/AAuth/blob/70d67375deb0bb002af7da0711fc58f6e8926e7e/interop-demo-profile.md) | `596c7d2c952d8ec6cdfd66a91c2d123705f3e4ed75fa581b4e3ac20404971545` |
| HTTP Signature Keys | [Signature-Key `69f5ba2`](https://github.com/dickhardt/signature-key/commit/69f5ba2647be848feed043fb6d8b0790e43cd0b6) | [`draft-hardt-httpbis-signature-key.md`](https://github.com/dickhardt/signature-key/blob/69f5ba2647be848feed043fb6d8b0790e43cd0b6/draft-hardt-httpbis-signature-key.md) | `b2b43db67a1aa5249d1166589834d44f81e97ea2e6375a07b475115efa196b7d` |

## Executed behavior: Signature-Key `clock_skew`

The manifest pins the whole Signature-Key file. This note records the behavior
this library executes for signature `created` classification in
`signaturekey.PrepareRequest` and the `Signature-Error: error=clock_skew`
answer for a header JWT `iat`.

- Document: HTTP Signature Keys, editor source `draft-hardt-httpbis-signature-key.md`.
- Repository commit: [Signature-Key `69f5ba2`](https://github.com/dickhardt/signature-key/commit/69f5ba2647be848feed043fb6d8b0790e43cd0b6).
- Section: the `### clock_skew` heading at line 1104; the section is lines 1104-1114.
- SHA-256 of the whole file at that commit: `b2b43db67a1aa5249d1166589834d44f81e97ea2e6375a07b475115efa196b7d`.

The overlay is a list, not a table row, because the baseline manifest check
requires exactly one table row per source file.

The JWT `iat` rule itself follows the JWT `iat` note below.

## Executed behavior: Signature-Key `revoked_jwt`

The manifest pins the whole Signature-Key file. This library executes the
`revoked_jwt` code for a withdrawn JWT carried in `Signature-Key`:
`signaturekey.ErrorRevokedJWT`, returned by a Resource or Person Server only
where its own revocation store gives it notice.

- Document: HTTP Signature Keys, editor source `draft-hardt-httpbis-signature-key.md`.
- Repository commit: [Signature-Key `69f5ba2`](https://github.com/dickhardt/signature-key/commit/69f5ba2647be848feed043fb6d8b0790e43cd0b6).
- Section: the `### revoked_jwt` heading at line 1092; the section is lines 1092-1102. The registry row is line 1462.
- SHA-256 of the whole file at that commit: `b2b43db67a1aa5249d1166589834d44f81e97ea2e6375a07b475115efa196b7d`.

The overlay is a list, not a table row, because the baseline manifest check
requires exactly one table row per source file.

## Executed behavior: presenting a revoked token

The manifest pins the whole Protocol file. This library executes the first
bullet of Presenting a Revoked Token: a revoked Agent or Auth token carried in `Signature-Key` is
`401` with `Signature-Error: error=revoked_jwt`, and a Resource refusing a
revoked Auth token also sends `AAuth-Requirement: requirement=person-token`
and never `requirement=auth-token`. A token carried as a request parameter
(`revoked_<parameter>_token`, the pending-request `revoked` state) is not
adopted, and no global parameter-token remapping, cascade or automatic recovery
is added. After presenting an Auth token, the Agent preserves a valid
`person-token` requirement in `*agent.PersonTokenRequiredError`, which
unwraps to the original `*signaturekey.Error`. The referenced **Person Token
Required** section (lines 615–624) calls for obtaining a Person token for the
Resource and retrying the original request with it. The Agent client does not
automate those steps; the [revocation example](example/revocation) composes
them explicitly. This is distinct from **Re-authorization** after expiry or key
rotation (lines 1289–1305).

- Document: AAuth Protocol, editor source `draft-hardt-oauth-aauth-protocol.md`.
- Repository commit: [AAuth `70d6737`](https://github.com/dickhardt/AAuth/commit/70d67375deb0bb002af7da0711fc58f6e8926e7e).
- Section: the `### Presenting a Revoked Token` heading at line 2760; the section is lines 2760-2767.
- SHA-256 of the whole file at that commit: `99ef2430c7babec7ea9cb2e9af40e3c3c57d18bce5a6e8501e9748063cfd9ab0`.

The overlay is a list, not a table row, because the baseline manifest check
requires exactly one table row per source file.

## Executed behavior: agent identifier local part

The manifest pins the whole Protocol file. This library executes the `local`
part grammar and exact-comparison rule in `ValidateAgentIdentifier` and
`ValidateAgentRelationship`.

- Document: AAuth Protocol, editor source `draft-hardt-oauth-aauth-protocol.md`.
- Repository commit: [AAuth `70d6737`](https://github.com/dickhardt/AAuth/commit/70d67375deb0bb002af7da0711fc58f6e8926e7e).
- Section: the `## Agent Identifiers` heading at line 486; the section is lines 486-507. Document History line 3213 records the change (issue #164).
- SHA-256 of the whole file at that commit: `99ef2430c7babec7ea9cb2e9af40e3c3c57d18bce5a6e8501e9748063cfd9ab0`.

The `local` part accepts `A-Za-z`, digits, `-`, `_`, `+` and `.`, and agent
identifiers compare exactly without case folding. The overlay is a list, not a
table row, because the baseline manifest check requires exactly one table row
per source file.

## Executed behavior: revocation request

The manifest pins the whole Protocol file. This library executes the revocation
request and its `403 unsupported_iss` mapping: the `{jti, exp}` body,
the issuer taken only from the verified signature, mandatory `content-type`
and `content-digest` coverage, `(iss, jti)` state recorded whether or not the
token was seen, and the Errors table entries already adopted in
`INTERPRETATIONS.md`. The `429` `rate_limited` response is adopted for client
feedback only: the AP and PS revocation clients return additive
`aauth.RateLimitedError` with the recipient's `Retry-After`; recipient entry or
rate enforcement is not implemented. Cascade and polling of a `202` are not
adopted (`revoked_jwt` is adopted by the overlays above). The `200` Body rule is adopted for the AP and PS
clients only (`aauth.ReadRevocationResponse`): no body is a recorded revocation;
a present body that is not `application/json`, one JSON object with an optional
array `downstream`, is `aauth.ErrRevocationUnavailable`. A valid `downstream`
report is validated and not returned.

- Document: AAuth Protocol, editor source `draft-hardt-oauth-aauth-protocol.md`.
- Repository commit: [AAuth `70d6737`](https://github.com/dickhardt/AAuth/commit/70d67375deb0bb002af7da0711fc58f6e8926e7e).
- Section: the `## Token Revocation` heading at line 2666, `### Revocation Request` (lines 2670-2700) and the Errors table in `### Revocation Response` (lines 2701-2746).
- SHA-256 of the whole file at that commit: `99ef2430c7babec7ea9cb2e9af40e3c3c57d18bce5a6e8501e9748063cfd9ab0`.

## Executed behavior: JWT `iat` and `clock_skew`

The manifest pins the whole Protocol file. This library executes the JWT `iat`
rule and its `clock_skew` answers. General token verification no longer
refuses a future `iat`; `exp` and `nbf` checks are unchanged and no universal
JWT leeway is added. A verifier that has a prepared signed request refuses a
JWT whose `iat` is later than the request's captured time plus its effective
signature window (`signaturekey.PreparedRequest.CheckIssuedAt`, 60 seconds by
default). The token in the `Signature-Key` header is answered `401` with
`Signature-Error: error=clock_skew`; a token carried as a request parameter
(the Resource, upstream and sub-agent tokens at the PS and AS token endpoints)
is answered `400` with body error `clock_skew` and no `Signature-Error`. A
verifier with no request, such as a response-token consumer, applies no
future-`iat` refusal. The Events subscribe-token and event-token checks are
unchanged; both still refuse a future `iat`.

- Document: AAuth Protocol, editor source `draft-hardt-oauth-aauth-protocol.md`.
- Repository commit: [AAuth `70d6737`](https://github.com/dickhardt/AAuth/commit/70d67375deb0bb002af7da0711fc58f6e8926e7e).
- Section: the `### Common JWT Verification` heading at line 2311 (lines 2311-2322) and the `clock_skew` row at line 2597 of `### Token Endpoint Error Codes`.
- SHA-256 of the whole file at that commit: `99ef2430c7babec7ea9cb2e9af40e3c3c57d18bce5a6e8501e9748063cfd9ab0`.

The overlay is a list, not a table row, because the baseline manifest check
requires exactly one table row per source file.

[AAuth Explorer at `e6d7913`](https://github.com/aauth-dev/explorer/commit/e6d79137cda1a6a650d4394a37095393e1cc62ba)
is a non-normative diagnostic implementation, not an editor source. It is
tracked by Git commit rather than inserted into the source manifest.

## Executed behavior: call-chain expiry

The manifest pins the whole Protocol file. This library executes these rules
only on the supported call-chain path: one immediate, missionless,
accountless hop whose `upstream_token` is an auth token issued by the same
Person Server.

- A person token issued with `upstream_token` does not outlive it: the
  `upstream_token` part of the `exp` rule in `### Person Token Structure`.
- An auth token issued on a request carrying `upstream_token` does not outlive
  it: the `upstream_token` sentence of the `exp` rule in
  `### Auth Token Structure`, and "Downstream access does not outlive it" in
  `### Call Chaining`.

- Document: AAuth Protocol, editor source `draft-hardt-oauth-aauth-protocol.md`.
- Repository commit: [AAuth `70d6737`](https://github.com/dickhardt/AAuth/commit/70d67375deb0bb002af7da0711fc58f6e8926e7e).
- Section: `### Person Token Structure` at line 856 (the `exp` rule at line 863), `### Auth Token Structure` at line 1768 (the `exp` rule at line 1775), and `### Call Chaining` at line 1846 (the paragraph at line 1850).
- SHA-256 of the whole file at that commit: `99ef2430c7babec7ea9cb2e9af40e3c3c57d18bce5a6e8501e9748063cfd9ab0`.

Not adopted by this entry: `expired_upstream_token`, so an upstream token that
fails only `exp` still returns `invalid_upstream_token`; person tokens as
upstream tokens; mission- or account-bound upstream tokens; AS-issued upstream
tokens and federated downstream issuance; and repeated hops or cascade. This
overlay does not claim full call chaining.

## Executed behavior: deferred AS delivery

The manifest pins the whole Protocol file. The Core approval and payment
continuation follows **AS Response**, **Auth Token Delivery**, **PS-AS Trust
Establishment**, **Deferred Responses**, and **Pending URL Security**. This
library executes the PS's terminal-error relay and `as_unreachable` distinction
for deferred delivery alongside the immediate verifier. A missionless Core
claims wait uses `requirement=claims` and `required_claims`; the Person Server
posts one JSON object of those names, rejects `sub`, and the Agent still sees
approval. It does not execute the clarification or user-interaction branches
described in those sections.
Payment settlement remains outside AAuth; the implemented challenge carrier is
`WWW-Authenticate`.

- Document: AAuth Protocol, `draft-hardt-oauth-aauth-protocol.md`.
- Repository commit: [AAuth `70d6737`](https://github.com/dickhardt/AAuth/commit/70d67375deb0bb002af7da0711fc58f6e8926e7e).
- Sections: AS Response and Auth Token Delivery (1610–1661), PS-AS Trust
  Establishment (1686–1740), Deferred Responses (2478–2568), and Pending URL
  Security (2835–2841).
- SHA-256: `99ef2430c7babec7ea9cb2e9af40e3c3c57d18bce5a6e8501e9748063cfd9ab0`.

This note is a list, not a second manifest row.

## Executed behavior: Sub-Agents

The manifest pins the whole Protocol file. This library executes these rules
for missionless one-level parent-mediated authorization:

- **Sub-Agent Identity**: a sub-agent token's `iss` equals its parent's. The PS,
  and here also the AS, refuse a `subagent_token` that differs, does not name
  the signing parent in `parent_agent`, or reuses its key, with
  `invalid_subagent_token`.
- **Token Endpoint Error Codes**: the request-parameter sub-agent token uses
  `invalid_subagent_token` and `expired_subagent_token` at both PS and AS token
  endpoints, and `revoked_subagent_token` at the Person Server, which retains
  its Agent Provider's revocations.
- **Parent-Mediated Authorization**, final paragraph: the parent's consent for
  a child's request can be withdrawn and existing auth tokens expire normally.
  Host policy reevaluates that consent on every child request, including AS
  approval and payment waits as well as immediate and PS-hosted issuance.
- **Agent-Person Binding** and **Upstream Token Verification** step 4: a binding
  the host revoked refuses new Person tokens and missions, presented
  credentials and pending deliveries under it, and a chained request with
  `revoked_upstream_token`; a replacement binding admits only later requests.
  The binding-revocation operation and its answers are this library's reading
  ([INTERPRETATIONS.md](INTERPRETATIONS.md#a-revoked-agent-person-binding-ends-issuance-and-pending-delivery)).

- Document: AAuth Protocol, editor source `draft-hardt-oauth-aauth-protocol.md`.
- Repository commit: [AAuth `70d6737`](https://github.com/dickhardt/AAuth/commit/70d67375deb0bb002af7da0711fc58f6e8926e7e).
- Sections: `## Sub-Agents` (1888–1938), `### Upstream Token Verification`
  step 4 (1835), the three sub-agent rows of `### Token Endpoint Error Codes`
  (2594–2596), and `## Agent-Person Binding` (2912–2926).
- SHA-256: `99ef2430c7babec7ea9cb2e9af40e3c3c57d18bce5a6e8501e9748063cfd9ab0`.

Not adopted by this entry: Agent-token revocation cascades to sub-agents,
recursive delegation, mission-bound mediation, and sub-agent call chaining.
The waits' cancellation and error answers that the source does not settle are
recorded in [INTERPRETATIONS.md](INTERPRETATIONS.md#parent-mediated-federated-waits-stay-with-the-parent).

## Executed behavior: Bootstrap Sub-Agent Tokens

The manifest pins the whole Bootstrap file. This library executes Agent
Provider sub-agent issuance: `agentprovider.Server.IssueSubagent`
(same `iss`, `sub` from the parent's local part and a discriminator,
`parent_agent`, `ps` copied, the sub-agent's `cnf`, `exp` no later than the
parent's, top-level parents only), `agentprovider.Server.SubagentHandler`, and
`agent.Client.RequestSubagentToken` for the hosted request. Because the child's
`ps` is copied from its parent, `aauth.VerifySubagentToken` refuses a child
whose `ps` names another Person Server than its parent's. The request members
`jwk` and `discriminator` follow the section's illustrative example; the
`agent_token` response member and the route are this library's choice, since the
section defines no endpoint. Recording which parent requested each sub-agent
token, and how many are live per parent, remains host policy.

- Document: AAuth Bootstrap Guidance, editor source `draft-hardt-aauth-bootstrap.md`.
- Repository commit: [AAuth `70d6737`](https://github.com/dickhardt/AAuth/commit/70d67375deb0bb002af7da0711fc58f6e8926e7e).
- Section: `# Sub-Agent Tokens` at line 339 (lines 339–400), with `## Self-Hosted
  Sub-Agents` (343–367) and `## Sub-Agents Under a Hosted AP` (369–400).
- SHA-256: `40ca9d052e942a78ef01a827a23bd0149d34a58f626e750949f3ddcd2601b82c`.

The overlays are lists, not table rows, because the baseline manifest check
requires exactly one table row per source file.

## Native R3 vocabulary baselines

R3 names seven external description formats without citing exact revisions.
The table below fixes the sources used by this implementation. These are
adapter baselines, not additional AAuth normative sources, and each row states
the narrower representation this repository actually parses.

| Vocabulary | Reviewed baseline | Current parser boundary |
| --- | --- | --- |
| MCP | [MCP 2025-11-25, commit `38c84e9`](https://github.com/modelcontextprotocol/specification/tree/38c84e9f93ad191d9eb26d92b945d17bd0efcaf3/docs/specification/2025-11-25/server) | Exact JSON-encoded `tools/list` result objects with cursor continuity and required object-rooted Tool `inputSchema`; JSON-RPC transport remains outside the parser |
| OpenAPI | [OpenAPI 3.0.4](https://spec.openapis.org/oas/v3.0.4.html) and [3.1.1](https://spec.openapis.org/oas/v3.1.1.html) | Self-contained JSON or YAML Paths operations with `operationId`; callbacks, webhooks, and external reference acquisition are outside the profile |
| gRPC | [`google.golang.org/protobuf` v1.36.10](https://github.com/protocolbuffers/protobuf-go/tree/v1.36.10) | Complete binary `google.protobuf.FileDescriptorSet`; reflection and `.proto` acquisition or compilation are outside the parser |
| GraphQL | [GraphQL September 2025](https://spec.graphql.org/September2025/) | JSON response framing through object-valued `data.__schema`, followed by the typed R3 operation-identity refusal; no full introspection validator |
| AsyncAPI | [AsyncAPI JSON Schemas v6.11.1, commit `e609fc2`](https://github.com/asyncapi/spec-json-schemas/tree/e609fc2341007395d75df5756fc6fccf662c2087) | Focused self-contained 3.0.0/3.1.0 JSON operation-to-root-channel profile; no YAML conversion or general document validator |
| WSDL | [WSDL 1.1, W3C Note 15 March 2001](https://www.w3.org/TR/2001/NOTE-wsdl-20010315) | Self-contained service, binding, port-type, and message linkage needed to derive unique operations; no XML Schema or arbitrary extension validation |
| OData | [OData CSDL XML 4.01](https://docs.oasis-open.org/odata/odata-csdl-xml/v4.01/odata-csdl-xml-v4.01.html) | Self-contained Edmx 4.0 entity-container and bound-operation identity subset; method and AAuth annotation authority remain refused |

## Verify the protocol map against source bytes

[PROTOCOL.md](PROTOCOL.md) is backed by a machine-readable map of all 683
normalized Markdown headings and 1,313 uppercase normative or field-presence
occurrences in these eight files. Given a directory containing the exact
editor-source files above, verify every digest, line count, heading coordinate,
title, non-overlapping range, exact-line digest, strength, dependency, and the
owner and proof seam supplied by each occurrence's heading with:

```sh
go run ./internal/specmodel/cmd/verify -source-dir /path/to/editor-sources
```

The ordinary Go suite also verifies that each file, commit, and digest remains
bound in one row of this manifest and that the model uses controlled
classification, ownership, state-role, and proof-seam vocabularies.

## Executed behavior: Budgets

The manifest pins the whole Budgets draft. This library executes the fixed-price
narrowing chain and the consumption-record carrier:

- A resource token's `budget` is the offer. Later parties copy `unit` and
  `decimals` and may only lower `amount`.
- When that token carries `budget` and the Person Server omits the PS-to-AS
  `budget` parameter, the Access Server issues no `budget` claim. Omission is
  not the Resource offer. The Person Server rejects an auth token that carries
  a claim after that omission. A metered route then treats the auth token as
  no budget authorization.
- When the Person Server sends a ceiling, the Access Server may only lower
  `amount`, and the Person Server checks the returned claim against both
  ceilings.
- A step-up resource token may carry `budget_consumed` for `presented_jti`.
  The Person Server and Access Server verify the record and deliver it to
  policy. They do not retain the prior grant in order to admit it. The
  Resource rejects a record whose amount or scale disagrees with the metered
  grant it just charged.

A Resource whose Budget store implements usage queries publishes
`usage_endpoint` and serves signed `POST /usage`. Callers are a Person Server
or an Access Server. The response carries one unit, UTC calendar counters, and
per-key figures. It is not signed. `budgets.AccountedSpend` treats a missing
consumption record as the full grant, and `budgets.Free` applies the
settlement formula. Consent display helpers format a human amount and sanitize
a Markdown unit description; this library does not render the consent screen.

Variable-cost settlement and streaming trailers are not executed.
[CONFORMANCE.md](CONFORMANCE.md) names the evidence and the remaining gaps.

- Document: AAuth Budgets, `draft-hardt-aauth-budgets.md`.
- Repository commit: [AAuth `70d6737`](https://github.com/dickhardt/AAuth/commit/70d67375deb0bb002af7da0711fc58f6e8926e7e).
- Sections: PS-to-AS Token Request Extensions (542–572) and Auth Token
  Extensions (574–608).
- SHA-256: `f00d34c91576476cdb30b7aa1aa13a0bc9fc1d99fc43b4f0389ccb3e8bf2e150`.

This note is a list, not a second manifest row.

## Implementation relationship

### AAuth Core

Core has executing direct-identity, session, three-party, four-party,
deferred-delivery, and bounded revocation paths. It is not complete. The
source-area table in [CONFORMANCE.md](CONFORMANCE.md) is the supported-behavior
summary; it names evidence and exclusions for each path rather than inferring
support from exported types.

Core requires fully specified JOSE algorithm identifiers and requires support
for `Ed25519`. This implementation uses `Ed25519`; it does not accept the
polymorphic `EdDSA` identifier as an equivalent spelling.

### HTTP Signature Keys

The current role paths use `jwt`, `jwks_uri`, `hwk`, and the Ed25519
`jkt-s256+jwt` subset of `jkt-jwt`, plus a bounded set of shared
message-signature behavior. Other schemes, complete negotiation, and generic
replay enforcement remain explicit gaps in [CONFORMANCE.md](CONFORMANCE.md).

### Companion specifications and interoperability

R3, Events, Bootstrap, Budgets, Supervision, and the interoperability profile
are pinned as first-class inputs even where behavior is absent. Supervision is
pinned and not executed. This repository has one executing two-key repository
profile; its application-selected endpoints and JSON remain implementation
choices because the source is informational.
[CONFORMANCE.md](CONFORMANCE.md) separates reusable Core primitives from an
executing companion-spec path, and [ARCHITECTURE.md](ARCHITECTURE.md) assigns
new behavior without moving companion semantics into the Core package.

See [INTERPRETATIONS.md](INTERPRETATIONS.md) for active implementation
choices and [SPEC-FEEDBACK.md](SPEC-FEEDBACK.md) for questions to raise with the
editors.
