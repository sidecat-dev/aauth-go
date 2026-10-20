# AAuth specification feedback

Findings from implementing the AAuth family of drafts, tracked against the
current upstream editor sources. Source text and editor answers are
authoritative.

The findings below were reconciled on 2026-10-01 against these editor revisions.
The implementation baseline and its targeted overlays are recorded separately
in [SPECIFICATIONS.md](SPECIFICATIONS.md).

| Source | Revision used for these findings |
| --- | --- |
| AAuth (Core, R3, Events, Bootstrap, Budgets, interop profile) | [`dickhardt/AAuth` at `28e8258`](https://github.com/dickhardt/AAuth/tree/28e8258f8153a2a51a709c53ebc9618f941564e4) (`28e8258f8153a2a51a709c53ebc9618f941564e4`, 2026-09-28) |
| HTTP Signature Keys | [`dickhardt/signature-key` at `69f5ba2`](https://github.com/dickhardt/signature-key/tree/69f5ba2647be848feed043fb6d8b0790e43cd0b6) (`69f5ba2647be848feed043fb6d8b0790e43cd0b6`, 2026-09-13) |

Section names in this file are the headings in those commits. Line numbers in
Example blocks are lines of the Markdown draft sources at those commits: a bare
number is a line of the item's own draft, and a line of another draft carries
that draft's name (Core, R3, Bootstrap, Budgets or Signature-Key). The previous
reconcile (2026-09-01) used AAuth `a99d353` and signature-key `0ff751b`; the
implementation's pinned manifest is in [SPECIFICATIONS.md](SPECIFICATIONS.md).

Status values:

- **open:** still present upstream at the commits above, and we have not raised it
  ourselves.
- **submitted:** still present upstream, and we raised it ourselves in an upstream
  issue, comment, mailing-list post or Slack message; the item gives the date,
  channel and link or record.

The editor taking a topic from our earlier public notes (round one, June 2026)
is not a submission by us; such items are open.

This file was first committed on 2026-08-28. Our first round of feedback (June
2026) came from earlier public notes, and the drafts' Document History credits
it. Being public here is not the same as being submitted, so each item records
both the commit that first made it public here and whether we submitted it.
Resolved, rejected and withdrawn items are removed from the body and listed once
in the index at the end; their full text remains in this file's git history.

## Keeping this file current

- When we submit an item, record the date, channel and link on the item
  (**Status:** and **Submitted:**) and in its row of the tracking table.
- When upstream changes, update the commits above and recheck every unresolved
  item against the new text.
- When an item is resolved upstream, rejected with a reason we accept, or found
  wrong, delete its section and its tracking row, and add one line to the index
  at the end giving the fixing commit and section, or the reason.

## Submission status

The tracking table below identifies the findings covered by each submission.
These checks record upstream discussion status, not a change to the source
revision used for a finding.

| Submission | Upstream status | Checked |
| --- | --- | --- |
| AAuth issues [#225](https://github.com/dickhardt/AAuth/issues/225)–[#254](https://github.com/dickhardt/AAuth/issues/254), filed 2026-10-01 | Open; no editor response | 2026-10-20 |
| Signature-Key issues [#44](https://github.com/dickhardt/signature-key/issues/44) and [#45](https://github.com/dickhardt/signature-key/issues/45), filed 2026-10-01 | Open; no editor response | 2026-10-20 |
| [Comment on #108: deferral expiry](https://github.com/dickhardt/AAuth/issues/108#issuecomment-5943159708), submitted 2026-10-01 | No editor response | 2026-10-20 |
| [Comment on #108: key renewal before delivery](https://github.com/dickhardt/AAuth/issues/108#issuecomment-5943159888), submitted 2026-10-01 | No editor response | 2026-10-20 |
| [Comment on #199: delegated token verification](https://github.com/dickhardt/AAuth/issues/199#issuecomment-5943160092), submitted 2026-10-01 | No editor response | 2026-10-20 |
| [Comment on #208: self-hosted providers](https://github.com/dickhardt/AAuth/issues/208#issuecomment-5943160270), submitted 2026-10-01 | No editor response | 2026-10-20 |
| [Comment on #215: person and tenant namespaces](https://github.com/dickhardt/AAuth/issues/215#issuecomment-5943160433), submitted 2026-10-01 | No editor response | 2026-10-20 |
| [Comment on #221: upstream-token binding](https://github.com/dickhardt/AAuth/issues/221#issuecomment-5943160619), submitted 2026-10-01 | Issue author replied; no editor resolution | 2026-10-20 |
| [Comment on #222: query binding](https://github.com/dickhardt/AAuth/issues/222#issuecomment-5943160827), submitted 2026-10-01 | No editor response | 2026-10-20 |

Related discussions:

| Discussion | Status | Checked |
| --- | --- | --- |
| [AAuth #255: OpenAPI operation identifiers](https://github.com/dickhardt/AAuth/issues/255) | Open; the editor favors a stable identifier; no draft change | 2026-10-20 |
| [AAuth #261: denial reasons and alternatives](https://github.com/dickhardt/AAuth/issues/261) | Open; overlaps [#229](https://github.com/dickhardt/AAuth/issues/229) (AAG-F009, AAG-F070); no editor response | 2026-10-20 |

## Tracking

Unresolved: 47 (P1: 6, P2: 27, P3: 14; 46 submitted). Local implementation notes: 2. Removed: 62 (36 resolved, 0 rejected, 26 withdrawn).

| ID | Title | Spec | Targets | Priority | Status | First public here | Submitted | Venue |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| AAG-F010 | Four-party person identity uses the access-server namespace in one step | Core, Interop profile | MUST/SHALL/REQUIRED | P1 | submitted | bb58b20 (2026-08-28) | 2026-10-01, GitHub | Comment on [#215](https://github.com/dickhardt/AAuth/issues/215#issuecomment-5943160433) |
| AAG-F041 | Auth token delivery and response checks lack a parent-mediated branch | Core | MUST/SHALL/REQUIRED | P1 | submitted | 172bb44 (2026-08-30) | 2026-10-01, GitHub | New issue [#225](https://github.com/dickhardt/AAuth/issues/225) |
| AAG-F060 | Person token endpoint has no error for an unknown or foreign mission | Core | MUST/SHALL/REQUIRED | P1 | submitted | 076c522 (2026-08-30) | 2026-10-01, GitHub | New issue [#226](https://github.com/dickhardt/AAuth/issues/226) |
| AAG-F097 | The Permission Endpoint has no error table | Core | MUST/SHALL/REQUIRED | P1 | submitted | 288c2d5 (2026-08-31) | 2026-10-01, GitHub | New issue [#226](https://github.com/dickhardt/AAuth/issues/226) |
| AAG-F099 | The Audit Endpoint has no endpoint-specific error contract | Core | MUST/SHALL/REQUIRED | P1 | submitted | cbb4823 (2026-08-31) | 2026-10-01, GitHub | New issue [#226](https://github.com/dickhardt/AAuth/issues/226) |
| AAG-F040 | PS-to-AS token request does not require verifying agent_token and subagent_token | Core | missing-requirement | P1 | submitted | 172bb44 (2026-08-30) | 2026-10-01, GitHub | Comment on [#199](https://github.com/dickhardt/AAuth/issues/199#issuecomment-5943160092) |
| AAG-F019 | keyid has no scheme-specific equality rule | Signature-Key, Core | MUST/SHALL/REQUIRED | P2 | submitted | 0a5e37a (2026-08-30) | 2026-10-01, GitHub | New issue [signature-key#44](https://github.com/dickhardt/signature-key/issues/44) |
| AAG-F029 | Interaction decisions are described as recorded at the PS | Core | MUST/SHALL/REQUIRED | P2 | submitted | 0a5e37a (2026-08-30) | 2026-10-01, GitHub | New issue [#227](https://github.com/dickhardt/AAuth/issues/227) |
| AAG-F033 | Three-party deferral does not define the resource-token expiry boundary | Core | MUST/SHALL/REQUIRED | P2 | submitted | 0a5e37a (2026-08-30) | 2026-10-01, GitHub | Comment on [#108](https://github.com/dickhardt/AAuth/issues/108#issuecomment-5943159708) |
| AAG-F038 | Which agent token bounds exp in parent-mediated authorization | Core | MUST/SHALL/REQUIRED | P2 | submitted | 172bb44 (2026-08-30) | 2026-10-01, GitHub | New issue [#228](https://github.com/dickhardt/AAuth/issues/228) |
| AAG-F077 | GraphQL introspection cannot discover client operation names | R3 | MUST/SHALL/REQUIRED | P2 | submitted | a6b8648 (2026-08-31) | 2026-10-01, GitHub | New issue [#243](https://github.com/dickhardt/AAuth/issues/243) |
| AAG-F092 | Ambiguous failure has no interoperable maximum-cost input | Budgets | MUST/SHALL/REQUIRED | P2 | submitted | df3ccb4 (2026-08-31) | 2026-10-01, GitHub | New issue [#250](https://github.com/dickhardt/AAuth/issues/250) |
| AAG-F009 | Synchronous token-endpoint policy denial has no registered error | Core | missing-requirement | P2 | submitted | bb58b20 (2026-08-28) | 2026-10-01, GitHub | New issue [#229](https://github.com/dickhardt/AAuth/issues/229) |
| AAG-F010a | Four-party tenant changes issuer namespace | Core | missing-requirement | P2 | submitted | 0a5e37a (2026-08-30) | 2026-10-01, GitHub | Comment on [#215](https://github.com/dickhardt/AAuth/issues/215#issuecomment-5943160433) |
| AAG-F016 | The mandatory signature set does not bind a query | Core | missing-requirement | P2 | submitted | 92879d7 (2026-08-29) | 2026-10-01, GitHub | Comment on [#222](https://github.com/dickhardt/AAuth/issues/222#issuecomment-5943160827) |
| AAG-F017 | Authorization endpoint body is not required to be signed | Core, R3 | missing-requirement | P2 | submitted | 0a5e37a (2026-08-30) | 2026-10-01, GitHub | New issue [#230](https://github.com/dickhardt/AAuth/issues/230) |
| AAG-F025 | Application 202 in a deferred result is indistinguishable from "keep polling" | Core | missing-requirement | P2 | submitted | 0a5e37a (2026-08-30) | 2026-10-01, GitHub | New issue [#231](https://github.com/dickhardt/AAuth/issues/231) |
| AAG-F026 | Body signature components from resource metadata conflict with bodyless polls | Core | missing-requirement | P2 | submitted | 0a5e37a (2026-08-30) | 2026-10-01, GitHub | New issue [#232](https://github.com/dickhardt/AAuth/issues/232) |
| AAG-F039 | Retention and revocation cascade omit parent-mediated relationships | Core | missing-requirement | P2 | submitted | 172bb44 (2026-08-30) | 2026-10-01, GitHub | New issue [#233](https://github.com/dickhardt/AAuth/issues/233) |
| AAG-F044 | "Own key" does not explicitly require distinct parent and child keys | Core | missing-requirement | P2 | submitted | 172bb44 (2026-08-30) | 2026-10-01, GitHub | New issue [#234](https://github.com/dickhardt/AAuth/issues/234) |
| AAG-F045 | Direct sub-agent PS refusal has no error assignment | Core | missing-requirement | P2 | submitted | 172bb44 (2026-08-30) | 2026-10-01, GitHub | New issue [#235](https://github.com/dickhardt/AAuth/issues/235) |
| AAG-F050 | The two upstream-token presentations are not bound | Core | missing-requirement | P2 | submitted | 1e8e46a (2026-08-30) | 2026-10-01, GitHub | Comment on [#221](https://github.com/dickhardt/AAuth/issues/221#issuecomment-5943160619) |
| AAG-F059 | Mission proposal policy denial has no registered error | Core | missing-requirement | P2 | submitted | 076c522 (2026-08-30) | 2026-10-01, GitHub | New issue [#236](https://github.com/dickhardt/AAuth/issues/236) |
| AAG-F063 | Mission update does not define the exact hashed artifact | Core | missing-requirement | P2 | submitted | 972af5f (2026-08-30) | 2026-10-01, GitHub | New issue [#237](https://github.com/dickhardt/AAuth/issues/237) |
| AAG-F064 | Mission update and completion denial errors are absent | Core | missing-requirement | P2 | submitted | 972af5f (2026-08-30) | 2026-10-01, GitHub | New issue [#236](https://github.com/dickhardt/AAuth/issues/236) |
| AAG-F067 | Termination does not define outstanding credential behavior | Core | missing-requirement | P2 | submitted | 972af5f (2026-08-30) | 2026-10-01, GitHub | New issue [#238](https://github.com/dickhardt/AAuth/issues/238) |
| AAG-F070 | Immediate policy denial has no token-endpoint error | Core | missing-requirement | P2 | submitted | 7d0bab4 (2026-08-30) | 2026-10-01, GitHub | New issue [#229](https://github.com/dickhardt/AAuth/issues/229) |
| AAG-F078 | WSDL `service` plus `operation` does not identify one bound operation | R3 | missing-requirement | P2 | submitted | a6b8648 (2026-08-31) | 2026-10-01, GitHub | New issue [#244](https://github.com/dickhardt/AAuth/issues/244) |
| AAG-F079 | OData method narrowing and overload identity are undefined | R3 | missing-requirement | P2 | submitted | a6b8648 (2026-08-31) | 2026-10-01, GitHub | New issue [#245](https://github.com/dickhardt/AAuth/issues/245) |
| AAG-F080 | AsyncAPI optional `action` has no matching rule | R3 | missing-requirement | P2 | submitted | a6b8648 (2026-08-31) | 2026-10-01, GitHub | New issue [#246](https://github.com/dickhardt/AAuth/issues/246) |
| AAG-F095 | Clarification answers do not identify their question | Core | missing-requirement | P2 | open | caf7310 (2026-08-31) | no | New issue |
| AAG-F105 | Deferred mission approval does not define key renewal before token delivery | Core | missing-requirement | P2 | submitted | 4647768 (2026-08-31) | 2026-10-01, GitHub | Comment on [#108](https://github.com/dickhardt/AAuth/issues/108#issuecomment-5943159888) |
| AAG-F106 | Events requires every event to transit the AP, with no AP-authorized local delivery component | Events | missing-requirement | P2 | submitted | not public before | Slack, thread with the editor on delegated event delivery; the original Slack date is not retained (transcript supplied 2026-08-03) | None now: we deferred the follow-up until a working delegated offline/local example exists |
| AAG-F083 | Standard R3 vocabularies do not identify external specification revisions | R3 | missing-requirement | P3 | submitted | 83219c1 (2026-08-31) | 2026-10-01, GitHub | New issue [#249](https://github.com/dickhardt/AAuth/issues/249) |
| AAG-F001 | Interop Surface 3 says resource metadata holds keys, while Core uses `jwks_uri` | Interop profile, Core, Signature-Key | informative | P3 | submitted | 3afa429 (2026-08-28) | 2026-10-01, GitHub | New issue [#253](https://github.com/dickhardt/AAuth/issues/253) |
| AAG-F005 | R3 same-URI replacement can make an old content hash unverifiable | R3 | informative | P3 | submitted | 3afa429 (2026-08-28) | 2026-10-01, GitHub | New issue [#247](https://github.com/dickhardt/AAuth/issues/247) |
| AAG-F030 | Resource-managed interaction is assigned both 202 and 401 | Core | informative | P3 | submitted | 0a5e37a (2026-08-30) | 2026-10-01, GitHub | New issue [#240](https://github.com/dickhardt/AAuth/issues/240) |
| AAG-F031 | The resource authorization endpoint is not a PS-free path | Core | informative | P3 | submitted | 0a5e37a (2026-08-30) | 2026-10-01, GitHub | New issue [#241](https://github.com/dickhardt/AAuth/issues/241) |
| AAG-F042 | The interop profile asks the Resource to verify the wrong signature | Interop profile | informative | P3 | submitted | 172bb44 (2026-08-30) | 2026-10-01, GitHub | New issue [#254](https://github.com/dickhardt/AAuth/issues/254) |
| AAG-F062 | approved_at does not ensure a globally unique mission digest | Core | informative | P3 | submitted | 076c522 (2026-08-30) | 2026-10-01, GitHub | New issue [#242](https://github.com/dickhardt/AAuth/issues/242) |
| AAG-F072 | Bootstrap names `jti` replay protection without defining replay | Bootstrap | informative | P3 | submitted | 9f0c368 (2026-08-30) | 2026-10-01, GitHub | New issue [#251](https://github.com/dickhardt/AAuth/issues/251) |
| AAG-F073 | The delegated request-key algorithm is described as enclave-determined | Signature-Key | informative | P3 | submitted | 9f0c368 (2026-08-30) | 2026-10-01, GitHub | New issue [signature-key#45](https://github.com/dickhardt/signature-key/issues/45) |
| AAG-F074 | Stable Agent `sub` does not distinguish the two key rotations | Core, Bootstrap | informative | P3 | submitted | 9f0c368 (2026-08-30) | 2026-10-01, GitHub | New issue [#252](https://github.com/dickhardt/AAuth/issues/252) |
| AAG-F082 | OData annotation encoding lacks a resolvable term namespace and target | R3 | informative | P3 | submitted | 83219c1 (2026-08-31) | 2026-10-01, GitHub | New issue [#248](https://github.com/dickhardt/AAuth/issues/248) |
| AAG-F094 | Clarification actions have no success-response contract | Core | informative | P3 | submitted | caf7310 (2026-08-31) | 2026-10-01, GitHub | New issue [#239](https://github.com/dickhardt/AAuth/issues/239) |
| AAG-F104 | Core both permits and forbids a self-hosted Agent Provider | Core | informative | P3 | submitted | 2b7909b (2026-08-31) | 2026-10-01, GitHub | Comment on [#208](https://github.com/dickhardt/AAuth/issues/208#issuecomment-5943160270) |
| AAG-H003 | Recommended justification sections | Core | informative | P3 | submitted | 3afa429 (2026-08-28) | Slack, four-party implementation round with the editor, item 5 (a concrete proposal for the `justification` sections); the original Slack date is not retained (transcript supplied 2026-08-03) | None now: the editor deferred it to a later revision |

An earlier plan of "umbrella only" meant raising the item only inside one combined
issue of small editorial items. On 2026-10-01 each such item was posted as its own issue instead.

## Against MUST, SHALL or REQUIRED text

Findings against text that uses MUST, SHALL or REQUIRED.

### AAG-F010 — Four-party person identity uses the access-server namespace in one step

**Status:** submitted

**Targets:** MUST/SHALL/REQUIRED

**Priority:** P1

**First public here:** bb58b20 (2026-08-28)

**Submitted:** 2026-10-01, GitHub, comment on [#215](https://github.com/dickhardt/AAuth/issues/215#issuecomment-5943160433) (one comment together with AAG-F010a)

**Upstream evidence:** 28e8258 Core, "Auth Token Structure"; "Auth Token Verification" (Request-Context Binding step 4); "Resource Token Structure"; https://github.com/dickhardt/AAuth/issues/215

**Remaining:** Text still keys the person by (iss, sub); editor [issue #215](https://github.com/dickhardt/AAuth/issues/215) (open, 2026-09-25) proposes (ps, sub) for four-party tokens.

**Source:** AAuth Core (28e8258), "Auth Token Structure", "Auth Token Verification" (Request-Context Binding, step 4), and "Resource Token Structure"; also affected: "Directed Identifiers Across a Chain", "Trust Posture in PS Authorization Access", and the privacy section "Directed Identifiers".

In four-party mode, auth-token `iss` is the access server, while `ps` is the person server whose namespace owns `sub` ("Resource Token Structure"). "Auth Token Structure" still says `sub` is unique within `iss`, and the verification step tells the resource to match or establish the person by `(iss, sub)`. That changes the person's identity when the access server changes and can merge equal directed subjects from different person servers behind one access server.

Our implementation presents `(ps, sub)` to the protected handler; its test covers namespace separation: `resource/server_test.go:TestProtectedHandlerReceivesCurrentPrincipal`.

**Example:**

```text
PS-A and PS-B are two person servers behind access server X; each mints sub "u123" for a different person.
Resource R receives auth tokens {iss: X, ps: PS-A, sub: "u123"} and {iss: X, ps: PS-B, sub: "u123"}.
R keys its record by (iss, sub) = (X, "u123"), so both people map to one record.
Keyed by (ps, sub) the records stay distinct: (PS-A, "u123") and (PS-B, "u123").
```

**Question:** Should the auth-token structure and verification text define the person key as `(ps, sub)` in every topology, while keeping `iss` solely as the token issuer and trust anchor?

**Related upstream issues:** [#215](https://github.com/dickhardt/AAuth/issues/215) Four-party auth tokens: identify the person by (ps, sub), not (iss, sub) (open, dickhardt 2026-09-25).

**Venue:** Comment on [#215](https://github.com/dickhardt/AAuth/issues/215#issuecomment-5943160433) (one comment together with AAG-F010a), posted 2026-10-01. Earlier plan: Comment on [#215](https://github.com/dickhardt/AAuth/issues/215). That issue tracks this change; the comment adds the other affected sections.

### AAG-F041 — Auth token delivery and response checks lack a parent-mediated branch

**Status:** submitted

**Targets:** MUST/SHALL/REQUIRED

**Priority:** P1

**First public here:** 172bb44 (2026-08-30)

**Submitted:** 2026-10-01, GitHub, new issue [#225](https://github.com/dickhardt/AAuth/issues/225); earlier, the editor took this topic from our public notes in round one, June 2026

**Upstream evidence:** 28e8258 Core, "Auth Token Delivery"; "Auth Token Response Verification"; "Parent-Mediated Authorization"

**Remaining:** Delivery and response verification still require cnf to match "the agent's" signing key, with no rule for which agent's key in a parent-mediated request.

**Source:** Core "Auth Token Delivery", "Auth Token Response Verification", "Parent-Mediated Authorization" (28e8258).

Core "Auth Token Delivery" has the PS check that cnf.jwk matches the agent's signing key and requires agents to verify that aud and cnf match their own values. "Auth Token Response Verification" step 4 does the same. In "Parent-Mediated Authorization" the parent makes the request but the token is for the child, so the requester's key and the token's cnf differ and the checks as written fail or are skipped. Our implementation verifies cnf against subagent_token.cnf.jwk and the resource-token context.

**Example:** Three-party, parent-mediated: the PS issues an auth token whose cnf is K_S, the sub-agent's key (1934). The parent applies line 1660 and compares cnf with its own key K_P, finds a mismatch, and rejects a valid token. Four-party: the PS applies the check at line 1651, compares K_S with the key that signed the request (K_P), rejects the AS's token and returns as_unreachable (1658).

**Question:** Should both sections add a parent-mediated branch that checks cnf against the child's key from subagent_token, and say who checks aud?

**Venue:** New issue [#225](https://github.com/dickhardt/AAuth/issues/225), posted 2026-10-01. Earlier plan: New issue. One Core issue on parent-mediated authorization covering AAG-F038, AAG-F039 and AAG-F041, cross-linking [#199](https://github.com/dickhardt/AAuth/issues/199).

### AAG-F060 — Person token endpoint has no error for an unknown or foreign mission

**Status:** submitted

**Targets:** MUST/SHALL/REQUIRED

**Priority:** P1

**First public here:** 076c522 (2026-08-30)

**Submitted:** 2026-10-01, GitHub, new issue [#226](https://github.com/dickhardt/AAuth/issues/226) (one issue together with AAG-F097 and AAG-F099)

**Upstream evidence:** 28e8258 Core, "Person Token Endpoint"; "Mission Endpoint Errors"; "Mission Status Errors"; "Token Endpoint Error Codes"

**Remaining:** The PS MUST reject a mission that is unknown or belongs to another agent, but no code is assigned. invalid_request covers only a missing or malformed mission_s256, and mission_terminated covers only inactive missions.

**Source:** AAuth Core, `Person Token Endpoint`, `Mission Endpoint Errors`, `Mission Status Errors`, and `Token Endpoint Error Codes`.

The person token endpoint must reject a `mission_s256` that names no mission, an inactive mission, or another agent's mission. Its errors say `invalid_request` covers a missing or malformed `mission_s256`, and `Mission Status Errors` assigns `mission_terminated` to inactive missions. A well-formed reference to an unknown mission, or to another agent's mission, has no assigned result. `mission_not_found`, together with its rule that both cases look the same, is defined only for requests to the mission's own URL. Our implementation returns the same `400 invalid_request` body in both cases.

**Example:** A resource operator who also runs an agent at the same PS observes a `mission_s256` on a request it serves (1542). Its agent POSTs it to the Person Token Endpoint. For a terminated mission the PS returns 403 `mission_terminated` with `mission_status` and `termination_reason` (1550). For a live foreign mission it returns the 810 rejection. The operator learns whether the mission is live and why it ended.

**Question:** Should `mission_not_found` and its rule that both cases look the same also apply at the person token endpoint? Or should the token error registry add a mission-reference error that does not reveal ownership?

**Venue:** New issue [#226](https://github.com/dickhardt/AAuth/issues/226) (one issue together with AAG-F097 and AAG-F099), posted 2026-10-01. Earlier plan: New issue. One issue together with AAG-F097 and AAG-F099, keeping a separate line for each. Closed [issue #84](https://github.com/dickhardt/AAuth/issues/84) (2026-08-11) and [PR #85](https://github.com/dickhardt/AAuth/pull/85) defined the Mission endpoint's errors and closed its existence oracle, but did not cover this path.

### AAG-F097 — The Permission Endpoint has no error table

**Status:** submitted

**Targets:** MUST/SHALL/REQUIRED

**Priority:** P1

**First public here:** 288c2d5 (2026-08-31)

**Submitted:** 2026-10-01, GitHub, new issue [#226](https://github.com/dickhardt/AAuth/issues/226) (one issue together with AAG-F060 and AAG-F099)

**Upstream evidence:** 28e8258 Core, "Permission Endpoint" / "Permission Request" / "Permission Response"; Core, "Error Responses" ("Token Endpoint Error Codes", "Polling Error Codes")

**Remaining:** -11 added endpoint-specific tables for Interaction ("Interaction Endpoint Errors") and Mission ("Mission Endpoint Errors"), but the Permission Endpoint still names only mission status errors and no registry for the initial POST.

**Source:** AAuth Core, `Permission Endpoint`, `Permission Request`, `Permission Response`, `Mission Status Errors`, and `Error Responses` (`Token Endpoint Error Codes`, `Polling Error Codes`).

The endpoint can receive malformed input, an unknown or terminated `mission_s256`, a policy or storage failure, an expired pending request, an identity-mismatched poll, or an already consumed reference. Permission Response names only mission status errors. Core now gives the Interaction Endpoint and the Mission Endpoint their own error tables, but the Permission Endpoint has none, and the Error Responses section does not say whether the Token Endpoint Error Codes apply to the initial Permission POST.

The sharper problem is ownership. "Mission Endpoint Errors" requires the same response whether a mission does not exist or belongs to another agent, because `mission_s256` travels in auth tokens to resources and an observed value would otherwise tell a resource operator running an agent whether the mission is live. "Mission Status Errors" requires `mission_terminated` at any PS endpoint that receives the `mission_s256` of a mission that is no longer active, with no condition that the mission belongs to the caller. Read as global, the first MUST conflicts with the second; read as scoped to the Mission endpoint, it leaves the Permission, Audit and Interaction endpoints without an ownership rule, so another agent that has seen a `mission_s256` can POST it to the Permission endpoint and learn whether the mission is live or terminated and why.

Our implementation uses `invalid_request` for malformed input or an unknown mission at initial submission, the mission status error for termination, `server_error` for operational failure, and the polling errors on the pending URL. These are local choices, not a conformance claim.

**Example:** 1. Agent A's mission has expired. Agent B has seen A's `mission_s256` in a token that a resource received. 2. B POSTs a permission request carrying that `mission_s256` to the PS Permission endpoint. 3. The PS answers `403` (`application/problem+json`) with `{"error":"mission_terminated","mission_status":"terminated","termination_reason":"expired"}`, as the Mission Status Errors text requires at any PS endpoint with a `mission_s256`. 4. For a `mission_s256` value that does not exist the PS answers `404` with `mission_not_found`, so B learns that A's mission exists and why it ended.

**Question:** Must the PS verify at this endpoint that the mission belongs to the calling agent, and otherwise answer `mission_not_found` under the same indistinguishability rule? Which error table applies to the initial Permission request, and should the endpoint define any additional policy or mission-reference errors?

**Venue:** New issue [#226](https://github.com/dickhardt/AAuth/issues/226) (one issue together with AAG-F060 and AAG-F099), posted 2026-10-01. Earlier plan: New issue. One issue together with AAG-F060 and AAG-F099, keeping a separate line for each.

### AAG-F099 — The Audit Endpoint has no endpoint-specific error contract

**Status:** submitted

**Targets:** MUST/SHALL/REQUIRED

**Priority:** P1

**First public here:** cbb4823 (2026-08-31)

**Submitted:** 2026-10-01, GitHub, new issue [#226](https://github.com/dickhardt/AAuth/issues/226) (one issue together with AAG-F060 and AAG-F097)

**Upstream evidence:** 28e8258 Core, "Audit Request" / "Audit Response"; Core, "Mission Status Errors"; Core, "Error Responses"

**Remaining:** Audit Response still names only mission status errors; no mapping for malformed input, owner mismatch, or store failure.

**Source:** AAuth Core, `Audit Request`, `Audit Response`, `Mission Status Errors`, and `Error Responses`.

Audit Response names mission status errors, but not how to report malformed JSON, invalid parameter shapes, a `mission_s256` belonging to another Agent, or an audit-store failure. Core now gives the Interaction and Mission endpoints their own error tables; the Audit Endpoint has none, and the Error Responses section does not assign one. The section also does not require the PS to check that the mission belongs to the calling agent: an agent that has seen another agent's `mission_s256` can add records to that mission's log, contrary to the rationale in "Why a Mission Belongs to an Agent". The PS evaluates the owner's permission requests against that log ("Permission Request"), and MAY use audit records to alert the user or revoke the mission ("Audit Response"). A foreign caller also learns termination status through `mission_terminated`.

Our implementation uses `invalid_request` for malformed input, owner-safe mission lookup with the existing mission status errors for mission state, and `server_error` for operational failure. These are local choices, not a claim that Core assigns them.

**Example:** Agent B has seen agent A's `mission_s256`. B POSTs a signed audit record carrying that `mission_s256` to the PS `audit_endpoint`. The PS answers `201 Created` and the record joins A's mission log. A's next permission request is evaluated against a log that contains B's entries.

**Question:** Which existing error table applies to Audit, and should the endpoint define any additional owner, validation, or retention failures?

**Venue:** New issue [#226](https://github.com/dickhardt/AAuth/issues/226) (one issue together with AAG-F060 and AAG-F097), posted 2026-10-01. Earlier plan: New issue. One issue together with AAG-F060 and AAG-F097, keeping a separate line for each.

### AAG-F019 — keyid has no scheme-specific equality rule

**Status:** submitted

**Targets:** MUST/SHALL/REQUIRED

**Priority:** P2

**First public here:** 0a5e37a (2026-08-30)

**Submitted:** 2026-10-01, GitHub, new issue [signature-key#44](https://github.com/dickhardt/signature-key/issues/44)

**Upstream evidence:** 69f5ba2 signature-key, "Relationship to Accept-Signature"; 28e8258 Core, "Signature Parameters"

**Remaining:** Text unchanged since 0ff751b: keyid and Signature-Key MUST identify the same key, server SHOULD NOT send keyid, but no comparison rule per scheme.

**Source:** Signature-Key (69f5ba2), "Relationship to Accept-Signature"; AAuth Core (28e8258), "Signature Parameters", which repeats the rule.

Both texts require a `keyid` in `Signature-Input` to identify the same key as the `Signature-Key` member for that label, and the verifier takes the key from `Signature-Key`. Signature-Key now says a server SHOULD NOT send `keyid` and a client MAY ignore it, but a signer may still include it. Neither text defines how to compare `keyid` with schemes that carry an inline key or a JWT rather than one explicit key ID, so "the same key" cannot be checked uniformly.

Our implementation does not claim complete `keyid` correlation.

**Example:**

```text
Signature-Input: sig=("@method" "@authority" "@path" "signature-key");created=1000;keyid="key-1"
Signature-Key: <jwt scheme; the token's cnf.jwk is an inline key with no kid>
Verifier A looks for a kid to compare with keyid, finds none, and rejects.
Verifier B ignores keyid because the key comes from Signature-Key, and accepts.
Verifier C compares an RFC 7638 thumbprint of cnf.jwk with keyid, finds a mismatch, and rejects.
The same message gets different answers.
```

**Question:** Should `keyid` be forbidden when `Signature-Key` is present, or should each scheme define the exact value that means "the same key"?

**Venue:** New issue [signature-key#44](https://github.com/dickhardt/signature-key/issues/44), posted 2026-10-01. Earlier plan: New issue. A Signature-Key issue.

### AAG-F029 — Interaction decisions are described as recorded at the PS

**Status:** submitted

**Targets:** MUST/SHALL/REQUIRED

**Priority:** P2

**First public here:** 0a5e37a (2026-08-30)

**Submitted:** 2026-10-01, GitHub, new issue [#227](https://github.com/dickhardt/AAuth/issues/227)

**Upstream evidence:** 28e8258 Core, "Interaction Code Format"; "User Interaction"; "Resource-Managed Authorization"

**Remaining:** The interaction code rule still says the decision MUST be recorded via an authenticated channel at the PS. User Interaction now applies to a 202 interaction from any server, including a resource that runs its own consent, where no PS takes part in the decision.

**Source:** AAuth Core, `Interaction Code Format`, `User Interaction`, and `Resource-Managed Authorization`.

`Interaction Code Format` says the person's approve or deny decision must be recorded through an authenticated channel "at the PS". `User Interaction` applies the same code to an interaction from any server. In resource-managed authorization the resource runs its own login or consent page and issues the interaction requirement itself, so no PS takes part in the decision.

**Example:**

```text
Resource-managed authorization (line 575), where the resource runs its own consent:
1. The agent requests a protected resource and the resource answers 202 with an interaction requirement (lines 2351 and 575).
2. The person is sent to the resource and approves the request there.
3. Line 2394: the approve/deny decision MUST be recorded via an authenticated channel at the PS.
4. No PS takes part in steps 1 and 2, so the sentence cannot be followed as written, and different resources will record the decision in different places.
```

**Question:** Should the rule name the server that issued the interaction, with the PS and the resource as explicit examples?

**Venue:** New issue [#227](https://github.com/dickhardt/AAuth/issues/227), posted 2026-10-01. Earlier plan: New issue. A Core issue on the interaction text, or an editorial issue.

### AAG-F033 — Three-party deferral does not define the resource-token expiry boundary

**Status:** submitted

**Targets:** MUST/SHALL/REQUIRED

**Priority:** P2

**First public here:** 0a5e37a (2026-08-30)

**Submitted:** 2026-10-01, GitHub, comment on [#108](https://github.com/dickhardt/AAuth/issues/108#issuecomment-5943159708)

**Upstream evidence:** 28e8258 Core, "Resource Token Structure"; "Resource Token Verification"; "Auth Token Endpoint"; "Deferred Delivery"; https://github.com/dickhardt/AAuth/issues/108

**Remaining:** "Resource Token Structure" still only says to get a fresh token if one "expires before it is redeemed", and does not say when a pending PS request counts as redeemed. Open [issue #108](https://github.com/dickhardt/AAuth/issues/108) asks for the pending-record versus token-lifetime relation, but not this case specifically.

**Source:** AAuth Core, `Resource Token Structure`, `Resource Token Verification`, `Auth Token Endpoint`, and `Deferred Delivery`.

`Resource Token Structure` recommends resource tokens live no more than five minutes. It says that if one "expires before it is redeemed", the agent must get a fresh one and submit a new token request. It also says the PS verifies the mission is active "when it acts on the token". Consent at the PS can take much longer than five minutes. In three-party access the PS verifies the resource token when the request arrives and never presents it again. The text does not say whether the PS may issue an auth token after the original resource token has expired, or whether the pending request must end at that expiry. `Deferred Delivery` handles an expired resource token only at the resource, by allowing a fresh one in a later poll.

Our PS caps the three-party pending deadline at the original resource token's expiry. Another implementation could keep the verified request and decide it later, and both readings fit the text.

**Example:**

```text
T+0: the agent presents a resource token with exp T+5 to the PS; the PS answers 202 and the request is pending while a person decides.
T+5: the resource token's exp passes.
T+12: the person approves.
PS A reads 'expires before it is redeemed' as not yet accepted at completion, so it rejects the pending request because the token expired.
PS B reads redeemed as presented at T+0, so it completes the request.
The same sequence gives two outcomes, and line 759 does not tell the agent whether a fresh token was required.
```

**Question:** Must a three-party pending authorization expire with its original resource token, or may the PS keep the verified request and decide it later, bounded by the presented token's `exp`?

**Related upstream issues:** [#108](https://github.com/dickhardt/AAuth/issues/108) Pending grant lifetime, and key rotation across a pending grant (dickhardt, 2026-08-31; the general gap, without the resource-token case).

**Venue:** Comment on [#108](https://github.com/dickhardt/AAuth/issues/108#issuecomment-5943159708), posted 2026-10-01. Earlier plan: Comment on [#108](https://github.com/dickhardt/AAuth/issues/108). [#108](https://github.com/dickhardt/AAuth/issues/108) (pending grant lifetime) asks how pending-record lifetime relates to token lifetimes; raise it there with AAG-F105, or as a focused `Auth Token Endpoint` issue if the editors prefer.

### AAG-F038 — Which agent token bounds exp in parent-mediated authorization

**Status:** submitted

**Targets:** MUST/SHALL/REQUIRED

**Priority:** P2

**First public here:** 172bb44 (2026-08-30)

**Submitted:** 2026-10-01, GitHub, new issue [#228](https://github.com/dickhardt/AAuth/issues/228)

**Upstream evidence:** 28e8258 Core, "Person Token Structure"; "Auth Token Structure"; "Parent-Mediated Authorization"

**Remaining:** exp is still bounded by "the agent token" presented or used, but parent-mediated requests involve two agent tokens (parent in Signature-Key, child as subagent_token) and Core does not say which one.

**Source:** Core "Person Token Structure", "Auth Token Structure", "Parent-Mediated Authorization" (28e8258).

Core "Person Token Structure" caps a person token's exp at the agent token presented when it was requested, and "Auth Token Structure" caps an auth token's exp at the agent token used to obtain it. In "Parent-Mediated Authorization" the request carries the parent's agent token in Signature-Key and the child's agent token as subagent_token. Core does not say which token sets the cap, so issuers can produce tokens that outlive the child or the parent. Our implementation uses the earlier of the two expirations.

**Example:** Parent agent token exp = T+24h. Sub-agent token exp = T+10min. The PS issues one-hour person tokens. The parent signs a person token request that carries the sub-agent's token as subagent_token. A PS that applies line 863 to the Signature-Key (parent) token issues a person token with exp = T+1h, so the sub-agent can keep using it for about 50 minutes after its own agent token expired. A PS that applies the rule to subagent_token issues exp = T+10min.

**Question:** Should the cap be the earlier of the parent and child agent token expirations, or only the child's?

**Venue:** New issue [#228](https://github.com/dickhardt/AAuth/issues/228), posted 2026-10-01. Earlier plan: New issue. One Core issue on parent-mediated authorization covering AAG-F038, AAG-F039 and AAG-F041, cross-linking [#199](https://github.com/dickhardt/AAuth/issues/199).

### AAG-F077 — GraphQL introspection cannot discover client operation names

**Status:** submitted

**Targets:** MUST/SHALL/REQUIRED

**Priority:** P2

**First public here:** a6b8648 (2026-08-31)

**Submitted:** 2026-10-01, GitHub, new issue [#243](https://github.com/dickhardt/AAuth/issues/243)

**Upstream evidence:** 28e8258 R3, "GraphQL Vocabulary (`urn:aauth:vocabulary:graphql`)" and "Operation Identifier Scope"

**Remaining:** Text unchanged: identifier is "the GraphQL operation name" (client-authored in GraphQL usage), discovered "via GraphQL introspection"; Operation Identifier Scope also claims operation names are unique "within a schema".

**Source:** AAuth R3 (28e8258), `Vocabularies` > `Operation Identifier Scope` and `Standard Vocabularies` > `GraphQL Vocabulary (urn:aauth:vocabulary:graphql)`; GraphQL, `Operation Name Uniqueness` and `Schema Introspection`.

R3 identifies a GraphQL operation by a named query, mutation, or subscription plus its type, and says an agent discovers available operations through introspection. `Operation Identifier Scope` adds that GraphQL operation names are unique within a schema. GraphQL operation names belong to executable documents written by clients; introspection exposes the server schema, not a registry of client documents or their operation names. Our GraphQL adapter detects an introspection response with `data.__schema` and then refuses with `operation_identity_unavailable`. Under that meaning a Resource cannot validate the identifier against its schema, as "Operation Validation" requires, without a persisted-operation registry, and matching grants by a client-chosen name is spoofable. R3's statements that names are unique within a schema and discovered by introspection fit a second reading, in which the name is a schema root field such as `Mutation.createEvent` that a Resource can validate, so the requirement is ambiguous rather than impossible to meet.

**Example:** 1. The resource's GraphQL schema has Mutation.createEvent and Mutation.deleteAllEvents. 2. Its R3 document lists the GraphQL operation CreateCalendarEvent (urn:aauth:vocabulary:graphql) and the person approves it. 3. The agent sends the request document: mutation CreateCalendarEvent { deleteAllEvents { count } }. 4. The name CreateCalendarEvent was chosen by the client in the document; it is not in the schema and introspection does not return it, so the resource cannot validate it against its authoritative definition (R3 748). A resource that matches grants by name admits the request and deletes all events under a grant that was approved for creating one. Identifying the operation by root type and root field (Mutation.createEvent) lets the resource check the selection set.

**Question:** Which reading is meant? Should the identifier name a schema root field, require a persisted-operation registry, or define another server-owned operation catalog?

**Venue:** New issue [#243](https://github.com/dickhardt/AAuth/issues/243), posted 2026-10-01. Earlier plan: New issue. An R3 vocabulary issue, possibly one issue for AAG-F077 to AAG-F080.

### AAG-F092 — Ambiguous failure has no interoperable maximum-cost input

**Status:** submitted

**Targets:** MUST/SHALL/REQUIRED

**Priority:** P2

**First public here:** df3ccb4 (2026-08-31)

**Submitted:** 2026-10-01, GitHub, new issue [#250](https://github.com/dickhardt/AAuth/issues/250)

**Upstream evidence:** 28e8258 Budgets, "Ambiguous Failures", "The Budget Is a Hard Cap", "Refusing a Request That Does Not Fit"

**Remaining:** The gap is narrower but still there. `reserved` now covers streamed responses. For a lost non-streamed response the Agent must still assume "the request's maximum cost as the resource would have bounded it", which comes from a request bound or a "documented default". The draft still requires no Resource to publish costs, and `required` appears only on refusals.

**Source:** AAuth Budgets (28e8258), `Ambiguous Failures`, `The Budget Is a Hard Cap`, and `Refusing a Request That Does Not Fit`.

When a response is lost, the Agent MUST assume the request cost what the Resource held for it. That is `reserved` if the Agent saw one, and otherwise "the request's maximum cost as the resource would have bounded it". `The Budget Is a Hard Cap` says this maximum comes from a bound the request declares or from a documented default. `Refusing a Request That Does Not Fit` says "no part of this specification requires a resource to publish what an operation costs". `required` is sent only with an `insufficient-budget` refusal. For a non-streamed request whose response never arrives, the Agent saw no `reserved`. A generic Agent therefore cannot derive or check the figure it is required to assume.

Our implementation falls back to the full signed grant when no interoperable bound is available.

**Example:** A metered request's connection drops before any response arrives, and the agent saw no `reserved` value. Line 710 requires the agent to assume the request's maximum cost as the resource would have bounded it, but line 759 says the agent cannot compute that bound. Agent A assumes the full `remaining` and agent B assumes zero, so the two agents plan against different balances after the same failure until a later response's `remaining` corrects them.

**Question:** Should the protocol say how an Agent learns the Resource's maximum for ambiguous-failure accounting? Alternatively, should it explicitly require the full remaining grant as the conservative fallback when no `reserved` was seen and no interoperable bound exists?

**Venue:** New issue [#250](https://github.com/dickhardt/AAuth/issues/250), posted 2026-10-01. Earlier plan: New issue. A Budgets issue on ambiguous failures, with the full-grant fallback as implementation evidence.

## Missing requirements

Findings where the drafts state no requirement for a case that implementations must handle the same way to interoperate.

### AAG-F040 — PS-to-AS token request does not require verifying agent_token and subagent_token

**Status:** submitted

**Targets:** missing-requirement

**Priority:** P1

**First public here:** 172bb44 (2026-08-30)

**Submitted:** 2026-10-01, GitHub, comment on [#199](https://github.com/dickhardt/AAuth/issues/199#issuecomment-5943160092); earlier, the editor took this topic from our public notes in round one, June 2026

**Upstream evidence:** 28e8258 Core, "PS-to-AS Token Request"; https://github.com/dickhardt/AAuth/issues/199

**Remaining:** The AS-side verification steps still omit the forwarded agent_token and subagent_token; editor issue 199 (dickhardt, 2026-09-25, open) tracks the same gap.

**Source:** Core "PS-to-AS Token Request" (28e8258).

Core "PS-to-AS Token Request" has the PS forward the agent's agent_token (and, for parent-mediated requests, subagent_token) to the AS, but the AS steps do not require verifying those tokens' signatures, issuers, expiry, or binding to the PS request. An AS could issue an auth token on the strength of an unverified agent token. Our implementation verifies both tokens independently before issuing.

**Example:** Four-party. Parent agent token A_P (cnf K_P). Sub-agent token S (cnf K_S, parent_agent = A_P.sub). Resource token with agent_jkt = thumbprint(K_S). The PS sends A_P as agent_token and S as subagent_token. Under the -12 proposal the AS compares K_P with agent_jkt and rejects a valid request. Under -11 the AS has no rule for A_P, and for S only the agent_jkt match.

**Question:** Should Core list explicit AS verification steps for agent_token and subagent_token, including issuer trust, expiry, and the relationship between the two?

**Related upstream issues:** [#199](https://github.com/dickhardt/AAuth/issues/199) No error code or verification rule for the agent_token parameter at the AS (open, dickhardt 2026-09-25; agent_token only, not subagent_token).

**Venue:** Comment on [#199](https://github.com/dickhardt/AAuth/issues/199#issuecomment-5943160092), posted 2026-10-01. Earlier plan: Comment on [#199](https://github.com/dickhardt/AAuth/issues/199). That issue concerns `agent_token` at the AS only; this item adds `subagent_token` at both the PS and the AS.

### AAG-F009 — Synchronous token-endpoint policy denial has no registered error

**Status:** submitted

**Targets:** missing-requirement

**Priority:** P2

**First public here:** bb58b20 (2026-08-28)

**Submitted:** 2026-10-01, GitHub, new issue [#229](https://github.com/dickhardt/AAuth/issues/229) (one issue together with AAG-F070)

**Upstream evidence:** 28e8258 Core, "Person Token Endpoint"; "Token Endpoint Error Codes"; "Polling Error Codes"

**Remaining:** The token registry still has no policy-denial code. `denied` exists only as a polling error after a deferred response, and the text says only that AS denials are relayed.

**Source:** AAuth Core, `Person Token Endpoint`, `Token Endpoint Error Codes`, and `Polling Error Codes`.

The person token endpoint can receive a well-formed request and still refuse to issue under PS policy. `Token Endpoint Error Codes` covers malformed input, token-specific failures, `user_unreachable`, `as_unreachable` and internal failure, but not this result. `denied` (`403`) exists only in `Polling Error Codes`, for a decision reached after a `202` deferred response.

Our implementation currently returns `403` with `person_token_denied`. Reusing `user_unreachable` would claim there is no contact channel, and reusing `invalid_request` would call valid input malformed.

**Example:**

```text
POST {person_token_endpoint}
{"resource":"https://payroll.example"}
PS policy forbids this resource for this person. The token endpoint error codes (2582 to 2602) have no policy-denial code, and `denied` is defined only as a polling error after a 202 (2621 to 2627). aauth-go answers 403 `person_token_denied`. Another PS has no registered code to choose and may answer differently (for example 400 `invalid_request`), so an agent cannot tell a terminal policy refusal from a malformed request.
```

**Question:** Should Core register a terminal policy-denial error for an immediate refusal, or require the PS to report every denial through a deferred response ending in `denied`?

**Venue:** New issue [#229](https://github.com/dickhardt/AAuth/issues/229) (one issue together with AAG-F070), posted 2026-10-01. Earlier plan: New issue. A Core issue; no existing issue covers this error-code gap. It could be one policy-denial issue together with AAG-F059, AAG-F064 and AAG-F070.

### AAG-F010a — Four-party tenant changes issuer namespace

**Status:** submitted

**Targets:** missing-requirement

**Priority:** P2

**First public here:** 0a5e37a (2026-08-30)

**Submitted:** 2026-10-01, GitHub, comment on [#215](https://github.com/dickhardt/AAuth/issues/215#issuecomment-5943160433) (one comment together with AAG-F010)

**Upstream evidence:** 28e8258 Core, "Auth Token Structure"; "Person Token Structure"; "Organization Identification"; https://github.com/dickhardt/AAuth/issues/215 ; related https://github.com/dickhardt/AAuth/issues/210

**Remaining:** "(iss, tenant) identifies the organization" remains in "Auth Token Structure"; [#215](https://github.com/dickhardt/AAuth/issues/215) records the (ps, sub) decision for four-party tokens, but its body does not mention `tenant`.

**Source:** AAuth Core (28e8258), "Auth Token Structure", "Person Token Structure", and "Organization Identification".

"Auth Token Structure" says `(iss, tenant)` identifies the organization. A person server places `tenant` in the person token, but a four-party auth token copies it while changing `iss` to the access server. The same organization therefore appears to change namespace during one flow.

**Example:**

```text
Person token from PS-A: {"iss":"PS-A","sub":"u1","tenant":"acme"}
Person token from PS-B: {"iss":"PS-B","sub":"u9","tenant":"acme"}   (a different organization that also uses the string "acme")
AS X issues auth tokens for both: {"iss":"X","ps":"PS-A","tenant":"acme"} and {"iss":"X","ps":"PS-B","tenant":"acme"}.
With "(iss, tenant) identifies the organization" the resource sees (X, "acme") twice, so two organizations collapse into one.
The organization behind the first person token is (PS-A, "acme") but behind its auth token is (X, "acme"), so organization records keyed from one token do not match the other.
```

**Question:** Should organization context be keyed by `(ps, tenant)` in four-party tokens, while `iss` remains only the token issuer?

**Related upstream issues:** [#210](https://github.com/dickhardt/AAuth/issues/210) Trust Posture still treats tenant as part of the person's identifier (open, dickhardt 2026-09-25; same sentence, different point).

**Venue:** Comment on [#215](https://github.com/dickhardt/AAuth/issues/215#issuecomment-5943160433) (one comment together with AAG-F010), posted 2026-10-01. Earlier plan: Comment on [#215](https://github.com/dickhardt/AAuth/issues/215). Together with AAG-F010. [#210](https://github.com/dickhardt/AAuth/issues/210) concerns the same sentence but a different point.

### AAG-F016 — The mandatory signature set does not bind a query

**Status:** submitted

**Targets:** missing-requirement

**Priority:** P2

**First public here:** 92879d7 (2026-08-29)

**Submitted:** 2026-10-01, GitHub, comment on [#222](https://github.com/dickhardt/AAuth/issues/222#issuecomment-5943160827)

**Upstream evidence:** 28e8258 Core, "Covered Components"; "Freshness and Replay"; "Why These Covered Components"

**Remaining:** Required set is still @method, @authority, @path, signature-key with no @query; replay cache tuple omits the query.

**Source:** AAuth Core (28e8258), "Covered Components", "Why These Covered Components", and "Freshness and Replay"; RFC 9421, Sections 2.2.6 and 2.2.7.

Core requires `@path`, which RFC 9421 defines without the query. Two operations selected by different query strings can therefore share the same mandatory signature base. The replay-cache identity in "Freshness and Replay" also omits the query.

Our implementation covers `@query` when present; `signaturekey/request_external_test.go:TestRequestProofCoversAnExactQueryWhenPresent` shows that changing the query invalidates the original proof.

**Example:**

```text
Request 1 (created=1000): GET https://api.example/items?page=1
  Signature-Input covers @method @authority @path signature-key
Request 2 (same agent, created=1000): GET https://api.example/items?page=2
  Same key, method, authority and path in the same second, so a verifier that keeps the optional replay cache rejects the second request as a replay (the case issue #222 describes).
An intermediary changes ?page=1 to ?page=2 in transit: the signature still verifies, because the query is not covered.
```

**Question:** Should AAuth require `@query` for query-bearing requests and add it to replay identity, or require each query-sensitive resource to advertise it as an additional component?

**Related upstream issues:** [#222](https://github.com/dickhardt/AAuth/issues/222) Replay tuple limits an agent to one request per second per (key, method, authority, path) (open; filed by dickhardt 2026-09-30, reported by GitHub user dasiths; covers the replay half only).

**Venue:** Comment on [#222](https://github.com/dickhardt/AAuth/issues/222#issuecomment-5943160827), posted 2026-10-01. Earlier plan: Comment on [#222](https://github.com/dickhardt/AAuth/issues/222). [#222](https://github.com/dickhardt/AAuth/issues/222) covers only the replay half. Cross-link [signature-key issue 7](https://github.com/dickhardt/signature-key/issues/7), which asks where a baseline HTTP Message Signatures profile should live.

### AAG-F017 — Authorization endpoint body is not required to be signed

**Status:** submitted

**Targets:** missing-requirement

**Priority:** P2

**First public here:** 0a5e37a (2026-08-30)

**Submitted:** 2026-10-01, GitHub, new issue [#230](https://github.com/dickhardt/AAuth/issues/230)

**Upstream evidence:** 28e8258 Core, "Covered Components"; "Why These Covered Components"; "Authorization Endpoint"; "Resource Metadata"

**Remaining:** content-digest/content-type are required only for PS/AS body requests and revocation endpoints; the resource authorization endpoint (scope, account in body) is not covered, though also defined by Core.

**Source:** AAuth Core (28e8258), "Covered Components", "Why These Covered Components", "Authorization Endpoint", and "Resource Metadata".

"Covered Components" requires `content-digest` and `content-type` for body-bearing requests to PS or AS endpoints and to any revocation endpoint. The resource "Authorization Endpoint" carries `scope` and `account` in its body, and its example covers only the base components. "Why These Covered Components" exempts resources in general but makes an exception for the resource revocation endpoint because Core defines it; Core also defines the authorization endpoint, which gets no such rule. Resource metadata `additional_signature_components` is still resource-wide, so requiring body components there also forces them onto bodyless protected routes. A server MAY also require further components on a given request and name them in an `invalid_input` error with `required_input` ("Covered Components"), so the gap is the default profile, not a missing mechanism.

**Example:**

```text
POST {resource authorization endpoint}
Signature-Input covers @method @authority @path signature-key only.
Body {"scope":"data.read","account":"a1"} is changed in transit to {"scope":"data.write","account":"a1"}.
content-digest is not covered, so the signature still verifies and the resource issues a resource token for data.write. An agent that checks the returned resource token can detect the change.
```

**Question:** Should Core require `content-type` and `content-digest` at the resource authorization endpoint, as it does for the revocation endpoint, while keeping `additional_signature_components` as the resource-wide protected-request profile?

**Venue:** New issue [#230](https://github.com/dickhardt/AAuth/issues/230), posted 2026-10-01. Earlier plan: New issue. An AAuth issue referencing PR [#191](https://github.com/dickhardt/AAuth/pull/191) and issue [#165](https://github.com/dickhardt/AAuth/issues/165) (revocation-body coverage), cross-linking [signature-key issue 7](https://github.com/dickhardt/signature-key/issues/7).

### AAG-F025 — Application 202 in a deferred result is indistinguishable from "keep polling"

**Status:** submitted

**Targets:** missing-requirement

**Priority:** P2

**First public here:** 0a5e37a (2026-08-30)

**Submitted:** 2026-10-01, GitHub, new issue [#231](https://github.com/dickhardt/AAuth/issues/231)

**Upstream evidence:** 28e8258 Core, "Deferred Delivery"; "Deferred Response State Machine"

**Remaining:** Deferred Delivery answers the poll with the invocation's own response, while the state machine treats 202 as continue polling; no rule separates an application 202 from a pending 202.

**Source:** Core "Deferred Delivery" and "Deferred Response State Machine" (28e8258).

Core "Deferred Delivery" says that once the deferred call completes, the pending URL answers with the invocation's response. Core "Deferred Response State Machine" treats a 202 from the pending URL as "continue polling". If the resource's own operation legitimately returns a bare 202 with no Location, which RFC 9110 permits (for example, an ingestion endpoint that answers 202 Accepted), the agent either rejects it as a malformed pending response or keeps polling, receives the retained 202 until the auth token's `exp` ("Deferred Delivery"), then gets 410 ("Pending URL Security"), and never treats the result as final. A 202 with a same-origin Location does not loop, because "Polling with GET" sends the agent to that Location.

**Example:**

```text
POST /events (agent's request)        -> 202 Location: /pending/p1, status "pending" (resource holds the invocation)
GET /pending/p1 with the auth token   -> invocation completes; the application's own answer is 202 Accepted, no Location, no body
Agent: a 202 at an AAuth endpoint means pending (2480, 2535); no Location to switch to (2529); the body has no status (2523 treats unrecognized values as pending)
GET /pending/p1                       -> the retained 202 again (661), until the auth token's exp
GET /pending/p1                       -> 410 (2840)
The application's 202 was the final result; the agent either fails on the missing Location or polls until 410.
With a same-origin Location (POST /jobs -> 202 Location: /jobs/42) the agent follows it (2529) and no loop occurs.
```

**Question:** How should a final application 202 be distinguished from a pending 202, for example by a header, a required body shape, or a rule that the pending URL never returns the application response with 202?

**Venue:** New issue [#231](https://github.com/dickhardt/AAuth/issues/231), posted 2026-10-01. Earlier plan: New issue. A Core issue on "Deferred Delivery".

### AAG-F026 — Body signature components from resource metadata conflict with bodyless polls

**Status:** submitted

**Targets:** missing-requirement

**Priority:** P2

**First public here:** 0a5e37a (2026-08-30)

**Submitted:** 2026-10-01, GitHub, new issue [#232](https://github.com/dickhardt/AAuth/issues/232)

**Upstream evidence:** 28e8258 Core, "Resource Metadata"; "Polling with GET"; "Why These Covered Components"

**Remaining:** Metadata still says agents MUST cover every additional_signature_components member, and the example lists content-type and content-digest. Polls are still bodyless GETs, and no exception is defined.

**Source:** AAuth Core, `Resource Metadata`, `Polling with GET`, and `Why These Covered Components`.

Resource metadata says an agent must cover every `additional_signature_components` member on its requests to that resource. The metadata example lists `content-type` and `content-digest`. `Polling with GET` requires a bodyless `GET` and forbids resending the original body. `Why These Covered Components` acknowledges bodyless requests to a resource but defines no exception. Neither section says what the two fields describe on such a poll.

Our implementation covers the RFC 9530 digest of empty content, and requires the caller to supply fresh values for any other advertised fields.

**Example:**

```text
Resource metadata:  "additional_signature_components": ["content-digest", "content-type"]
Agent poll:         GET /pending/p1   (no body, so no Content-Digest or Content-Type field)
To be covered:      @method, @authority, @path, signature-key, content-digest, content-type
Result:             the last two fields are absent from the poll; the agent either cannot satisfy the profile or adds them artificially, and implementations diverge
```

**Question:** Do body-specific metadata components not apply to bodyless polls, or should a poll carry and sign an explicit zero-length representation? If they do not apply, where is that exception stated, so both peers build the same signature base?

**Venue:** New issue [#232](https://github.com/dickhardt/AAuth/issues/232), posted 2026-10-01. Earlier plan: New issue. A Core issue cross-linking Signature-Key covered-component processing; no existing issue covers this.

### AAG-F039 — Retention and revocation cascade omit parent-mediated relationships

**Status:** submitted

**Targets:** missing-requirement

**Priority:** P2

**First public here:** 172bb44 (2026-08-30)

**Submitted:** 2026-10-01, GitHub, new issue [#233](https://github.com/dickhardt/AAuth/issues/233)

**Upstream evidence:** 28e8258 Core, "Person Token Endpoint"; "Revocation Cascade"; "Parent-Mediated Authorization"

**Remaining:** The Retention paragraph and cascade Records list still have no fields for parent, child, approving party, or child key, and Parent-Mediated Authorization still assumes the PS issued both tokens.

**Source:** Core "Person Token Endpoint", "Revocation Cascade", "Parent-Mediated Authorization" (28e8258).

Core "Person Token Endpoint" (Retention paragraph) and "Revocation Cascade" (Records) list what a PS keeps so it can cascade revocation, but they have no entry for the parent agent, the child agent, the party that approved the child, or the child's key. "Parent-Mediated Authorization" still describes the PS as having issued both tokens. Without these relationships a PS cannot revoke a child's tokens when the parent is revoked, or the reverse. Our implementation retains all four relationship values.

**Example:** PS A cascades a revocation by the requester's sub (the parent). PS B also revokes tokens whose cnf is a sub-agent key of the revoked agent. After the parent is revoked, an auth token issued to the sub-agent one minute earlier stays valid under PS A for up to an hour but not under PS B. (Illustrative.)

**Question:** Should Retention and the cascade Records include the parent, child, approving party and child key, and should the cascade state whether revoking a parent revokes tokens issued for its children?

**Venue:** New issue [#233](https://github.com/dickhardt/AAuth/issues/233), posted 2026-10-01. Earlier plan: New issue. One Core issue on parent-mediated authorization covering AAG-F038, AAG-F039 and AAG-F041, cross-linking [#199](https://github.com/dickhardt/AAuth/issues/199).

### AAG-F044 — "Own key" does not explicitly require distinct parent and child keys

**Status:** submitted

**Targets:** missing-requirement

**Priority:** P2

**First public here:** 172bb44 (2026-08-30)

**Submitted:** 2026-10-01, GitHub, new issue [#234](https://github.com/dickhardt/AAuth/issues/234)

**Upstream evidence:** 28e8258 Core, "Sub-Agent Identity"; "Parent-Mediated Authorization"

**Remaining:** Sub-Agent Identity still gives the sub-agent "its own ... signing key" without requiring its `cnf.jwk` to differ from the parent's.

**Source:** AAuth Core, `Sub-Agent Identity` and `Parent-Mediated Authorization`.

Core gives a sub-agent "its own `aauth:local@domain` identifier and signing key" and, in Parent-Mediated Authorization, repeatedly contrasts the sub-agent key with the parent's signing key (for example, `agent_jkt` matches the `subagent_token`'s `cnf.jwk`, "not the signing key"). It never states that the two JWKs must differ. If they are equal, exclusive possession of the proof key is lost: whoever holds the shared key can use every credential bound to it, and the PS cannot enforce by key that a sub-agent does not request authorization on its own ("Single-Level Depth", "Parent-Mediated Authorization"). Per-token identities (`sub`, `jti`) remain. Our implementation requires distinct keys.

**Example:** The AP issues sub-agent token S for parent P with cnf = K_P, the key the parent supplied (Bootstrap 374, 376), so the sub-agent holds K_P. Instead of presenting S, which the PS must reject under Core 543 and 1917, the sub-agent presents the parent's agent token A_P and signs with K_P. The PS sees an ordinary parent request and cannot apply the sub-agent restriction. With distinct keys the sub-agent could not sign as the parent. (Illustrative.)

**Question:** Should Core explicitly require a sub-agent token's `cnf.jwk` to differ from its parent's current confirmation key, and say which party (AP at issuance, PS at use) checks it?

**Venue:** New issue [#234](https://github.com/dickhardt/AAuth/issues/234), posted 2026-10-01. Earlier plan: New issue. One focused Core sub-agent issue together with AAG-F045.

### AAG-F045 — Direct sub-agent PS refusal has no error assignment

**Status:** submitted

**Targets:** missing-requirement

**Priority:** P2

**First public here:** 172bb44 (2026-08-30)

**Submitted:** 2026-10-01, GitHub, new issue [#235](https://github.com/dickhardt/AAuth/issues/235)

**Upstream evidence:** 28e8258 Core, "Single-Level Depth"; "Token Endpoint Error Codes"; "Verification (Server)"

**Remaining:** The PS MUST reject a request signed by a sub-agent, but no status or error is assigned; the header-token rule covers verification failures, and Verification (Server) lists no error for a `parent_agent` signer.

**Source:** AAuth Core, `Single-Level Depth`, `Agent Token Verification` step 3, `Token Endpoint Error Codes`, and `Verification (Server)`.

Core requires a PS to reject a token request signed by an agent whose agent token has a `parent_agent` claim, but assigns no status or error. The error table says the token in the `Signature-Key` header has no codes there and fails with `401` and `Signature-Error`. However, a correctly signed sub-agent request has not failed signature verification, and Verification (Server) lists no `Signature-Error` value for this case. Our implementation first verifies proof of possession, then returns `400 invalid_agent_token` without `Signature-Error`; a forged proof still returns `401` with the signature failure. `invalid_agent_token` is not in the current registry.

**Example:** A sub-agent presents its own agent token in Signature-Key and signs a token request. The signature verifies, and the PS must reject the request (1917). PS-1 returns 401 with Signature-Error (2602), PS-2 returns 403 without Signature-Error (Signature-Key 976), and PS-3 returns 400 invalid_request.

**Question:** Which registered response should a correctly signed direct sub-agent request receive: a `401` with a defined `Signature-Error` value, a `403`, or a new token-endpoint error?

**Venue:** New issue [#235](https://github.com/dickhardt/AAuth/issues/235), posted 2026-10-01. Earlier plan: New issue. One focused Core sub-agent issue together with AAG-F044.

### AAG-F050 — The two upstream-token presentations are not bound

**Status:** submitted

**Targets:** missing-requirement

**Priority:** P2

**First public here:** 1e8e46a (2026-08-30)

**Submitted:** 2026-10-01, GitHub, comment on [#221](https://github.com/dickhardt/AAuth/issues/221#issuecomment-5943160619)

**Upstream evidence:** 28e8258 Core, "Call Chaining"; "Auth Token Request"; "Upstream Token Verification"; related: https://github.com/dickhardt/AAuth/issues/221

**Remaining:** Core still gives no comparison rule. This library holds the auth-token request to the exact upstream token recorded for its presented token: the retained Person-token record, or on an auth-typed step-up the issuance record of the presented auth token. A request that names an upstream token with no such record is refused; a request without one whose record is no longer retained is accepted on the verified presented token alone.

**Source:** AAuth Core, `Call Chaining`, `Person Token Endpoint`, `Auth Token Request`, `Upstream Token Verification`, and `Revocation Cascade` ("Records").

The intermediary presents `upstream_token` when it obtains the downstream person token, and presents one again with the downstream resource token and that person token as `presented_token`. Each presentation is verified independently under Upstream Token Verification. Core does not say whether the second value must be the same compact token, the same `(iss, jti)`, or a token for the same person. Call Chaining allows the same upstream token to be reused for any number of downstream requests, and the PS records the upstream `(iss, jti)` with each person token it issues from one, but only for the revocation cascade. Without a comparison rule, the second request can carry a different valid upstream token, possibly for a different person or mission, than the one the downstream identity was issued from.

**Example:** Intermediary I holds U_A (for Alice, mission M_A) and U_B (for Bob, mission M_B). (1) I obtains person token P_A with U_A. (2) I presents P_A at resource R, which issues resource token RT with presented_jti = P_A.jti, sub Alice@R and mission M_A. (3) I sends RT + P_A + U_B to the auth token endpoint. (4) The checks at 766-768 and 1832-1835 all pass. (5) The PS evaluates under Bob and M_B, but the auth token carries sub Alice@R and M_A; its exp follows U_B (1775) and its revocation follows U_A (2758). In four-party the AS records nothing about the chain (upgrade-10-to-11/access-server.md line 92). A same-person variant with two missions gives mission substitution.

**Question:** At the auth token request, must the PS check that `upstream_token` is the token (or same `(iss, jti)`) recorded for the `presented_token` person token? If a later upstream token for the same person is allowed (for example after the first expires), which fields define equivalence?

**Related upstream issues:** [#221](https://github.com/dickhardt/AAuth/issues/221) Cross-request confused deputy in AAuth call chaining (open, ngallo 2026-09-30; same class, raised independently).

**Venue:** Comment on [#221](https://github.com/dickhardt/AAuth/issues/221#issuecomment-5943160619), posted 2026-10-01. Earlier plan: Comment on [#221](https://github.com/dickhardt/AAuth/issues/221). That issue (cross-request confused deputy in call chaining) raises the related selection problem at the intermediary.

### AAG-F059 — Mission proposal policy denial has no registered error

**Status:** submitted

**Targets:** missing-requirement

**Priority:** P2

**First public here:** 076c522 (2026-08-30)

**Submitted:** 2026-10-01, GitHub, new issue [#236](https://github.com/dickhardt/AAuth/issues/236) (one issue together with AAG-F064)

**Upstream evidence:** 28e8258 Core, "Mission Creation"; "Mission Approval"; "Mission Endpoint Errors"; "Polling Error Codes"

**Remaining:** Mission Endpoint Errors still defines only invalid_request, mission_not_found and mission_terminated. An immediate denial of a valid proposal has no code. Only a deferred review can end in the polling error `denied`.

**Source:** AAuth Core, `Mission Creation`, `Mission Approval`, `Mission Endpoint Errors`, and `Polling Error Codes`.

The PS may refuse a well-formed mission proposal under its policy. `Mission Endpoint Errors` defines only `invalid_request`, `mission_not_found` and `mission_terminated`. A proposal that goes through a `202` deferred review can end in the polling error `denied`, but an immediate refusal has no defined result. Our implementation currently returns `403 mission_denied`, so that a valid proposal is not reported as malformed.

**Example:** An agent POSTs a mission proposal that policy forbids. PS-1 returns 403 `mission_denied`, PS-2 returns 400 `invalid_request`, PS-3 returns 202 and then polling `denied`. Only the third is defined (1358, 2621).

**Question:** Which registered error and status carry an immediate, terminal refusal of a mission proposal?

**Venue:** New issue [#236](https://github.com/dickhardt/AAuth/issues/236) (one issue together with AAG-F064), posted 2026-10-01. Earlier plan: New issue. A focused mission-endpoint issue, or one policy-denial issue together with AAG-F009, AAG-F064 and AAG-F070.

### AAG-F063 — Mission update does not define the exact hashed artifact

**Status:** submitted

**Targets:** missing-requirement

**Priority:** P2

**First public here:** 972af5f (2026-08-30)

**Submitted:** 2026-10-01, GitHub, new issue [#237](https://github.com/dickhardt/AAuth/issues/237)

**Upstream evidence:** 28e8258 Core, "Mission Update"; "Mission Log"; "Mission Management"

**Remaining:** Update digest still covers "the update's bytes as the PS persists them"; no retrieval representation for accepted updates; reads deferred to a companion spec at mission_control_endpoint.

**Source:** AAuth Core (28e8258), "Mission Update", "Mission Log", and "Mission Management".

An accepted update returns the digest of the update bytes as the PS persists them, but Core does not say whether those bytes are the authenticated request body, a canonical re-encoding, or a person-edited result. The mission log is meant to let auditors see accepted updates, yet Core defines no retrieval representation that supplies those bytes; "Mission Management" leaves reads to a companion specification at the `mission_control_endpoint`.

Our implementation persists and hashes the exact authenticated request body.

**Example:** The PS persists an update after re-serialising the request and returns the digest of the persisted bytes. An auditor reads the mission (1437 returns the exact bytes) but no surface returns the update bytes, so it hashes the body it saw and gets a different value.

**Question:** Which exact bytes does an accepted update digest identify, and should mission inspection return those bytes plus their acceptance order?

**Venue:** New issue [#237](https://github.com/dickhardt/AAuth/issues/237), posted 2026-10-01. Earlier plan: New issue. A Core issue on mission-update exactness. [#49](https://github.com/dickhardt/AAuth/issues/49) (mission-log completeness) is related but does not cover this.

### AAG-F064 — Mission update and completion denial errors are absent

**Status:** submitted

**Targets:** missing-requirement

**Priority:** P2

**First public here:** 972af5f (2026-08-30)

**Submitted:** 2026-10-01, GitHub, new issue [#236](https://github.com/dickhardt/AAuth/issues/236) (one issue together with AAG-F059)

**Upstream evidence:** 28e8258 Core, "Mission Endpoint Errors"; "Mission Update"; "Mission Completion"

**Remaining:** Mission Endpoint Errors still lists only invalid_request, mission_not_found, mission_terminated; no immediate refusal defined for an update.

**Source:** AAuth Core (28e8258), "Mission Update", "Mission Completion", and "Mission Endpoint Errors".

Core defines acceptance or deferred review for an update. It does not say whether an update may instead receive an immediate terminal refusal. Completion needs no such result: "Mission Completion" answers a completion proposal with acceptance or clarification follow-up, which leaves the mission active. If that is allowed, the error registry has no result for it: "Mission Endpoint Errors" lists only `invalid_request` (400), `mission_not_found` (404), and `mission_terminated` (403). `invalid_request` would misdescribe valid input, and `mission_terminated` would misdescribe a mission that remains active.

Our implementation provisionally returns `403 mission_update_denied` for a refused update and leaves the mission unchanged.

**Example:** An agent POSTs a mission update that policy refuses. The PS returns 403 `mission_terminated` to avoid inventing a code. The agent applies 1565 and stops acting on a live mission.

**Question:** May an update request end in immediate refusal? If so, should Core register a mission-update denial result, and which status should it use, or should it say that refusal is expressed only through the deferred path?

**Venue:** New issue [#236](https://github.com/dickhardt/AAuth/issues/236) (one issue together with AAG-F059), posted 2026-10-01. Earlier plan: New issue. One focused endpoint-error issue, or one policy-denial issue together with AAG-F009, AAG-F059 and AAG-F070.

### AAG-F067 — Termination does not define outstanding credential behavior

**Status:** submitted

**Targets:** missing-requirement

**Priority:** P2

**First public here:** 972af5f (2026-08-30)

**Submitted:** 2026-10-01, GitHub, new issue [#238](https://github.com/dickhardt/AAuth/issues/238)

**Upstream evidence:** 28e8258 Core, "Revocation Cascade"; "Mission Management"; "Mission Status Errors"; "Presenting a Revoked Token"

**Remaining:** Partly addressed: mission-bound person and auth tokens now expire no later than the mission, so natural expiry is covered, and Revocation Cascade says a PS revoking a mission SHOULD revoke outstanding auth tokens; outstanding person tokens, the other early termination reasons, and how a Resource learns of early termination remain undefined.

**Source:** AAuth Core (28e8258), "Mission Update", "Mission Management", "Mission Status Errors", "Revocation Cascade", and "Presenting a Revoked Token".

Core says updates leave existing mission-bound tokens valid and that a terminated mission rejects later PS requests. Natural expiry is covered: the PS caps mission-bound person and auth tokens at the mission's `expires_at` ("Person Token Structure", "Mission Approval", "Auth Token Structure"), and resource-token lifetime does not depend on the mission ("Resource Token Structure"). "Revocation Cascade" covers one early case: when the PS revokes a mission it marks the mission revoked, denies later token requests, and SHOULD revoke outstanding auth tokens issued under it. Gaps remain for termination before expiry:
- Nothing covers outstanding person tokens, which resources accept.
- Nothing covers missions that end early for other reasons (the termination reasons `completed`, `superseded` and `administrative` in "Mission Management"); those reasons say nothing about credentials.
- Per "Presenting a Revoked Token", a resource learns of revocation only through its own revocation endpoint and is otherwise bounded by token lifetime, and a Resource that sees only `mission_s256`, not mission state, has no defined way to learn that a mission ended early, so it can honour a credential for an ended mission until the credential's own expiry.

Our implementation closes later PS decisions after termination; outstanding credentials stay cryptographically usable until their own expiry, and a conforming Agent must stop using them.

**Example:** A mission is completed at T (1505, 1507). Person token P (exp T+40m) and auth token A (exp T+50m) were issued earlier. Resource R receives no revocation (2767) and honours both until they expire.

**Question:** When a mission ends before its expiry (completed, revoked, superseded or administrative), is termination intended only to close future PS decisions, or must Resources stop honouring outstanding mission-bound person and auth tokens? If the latter, how does a Resource that sees only `mission_s256` learn of it without receiving private mission state, or may it honour such a credential until its own expiry, as "Presenting a Revoked Token" describes for revocations that do not reach it?

**Venue:** New issue [#238](https://github.com/dickhardt/AAuth/issues/238), posted 2026-10-01. Earlier plan: New issue. A Core issue on propagating early mission termination.

### AAG-F070 — Immediate policy denial has no token-endpoint error

**Status:** submitted

**Targets:** missing-requirement

**Priority:** P2

**First public here:** 7d0bab4 (2026-08-30)

**Submitted:** 2026-10-01, GitHub, new issue [#229](https://github.com/dickhardt/AAuth/issues/229) (one issue together with AAG-F009)

**Upstream evidence:** 28e8258 Core, "Token Endpoint Error Codes"; "Auth Token Delivery"; "Polling Error Codes"; "Interaction Callback Errors"

**Remaining:** Registry still has no immediate policy-denial code; as_unreachable mentions an AS denial the PS relays but no code is registered; denied exists only for polling, access_denied only for callbacks.

**Source:** AAuth Core (28e8258), "Token Endpoint Error Codes", "Auth Token Delivery", "Polling Error Codes", and "Interaction Callback Errors".

"Token Endpoint Error Codes" defines `server_error` for internal failure but no immediate result for a PS consent or AS authorization policy that intentionally refuses an otherwise valid request. The `as_unreachable` entry says it is distinct from an AS denial, which the PS relays, and "Auth Token Delivery" relays the AS error value, but no denial code is registered. `denied` (403) appears only in "Polling Error Codes" for deferred requests, and `access_denied` only in "Interaction Callback Errors".

Our implementation provisionally returns `403 access_denied` only when a host callback signals an explicit denial; other callback errors return `500 server_error`.

**Example:** Three PSes refuse the same token request on policy. One returns 403 `denied`, another 400 `invalid_request`, another 500 `server_error`. An agent following 2575 decides from the `error` member and treats the first as terminal, the second as a malformed request and the third as retryable.

**Question:** May immediate PS and AS policy refuse a valid token request, and if so which registered error and status should represent that decision?

**Venue:** New issue [#229](https://github.com/dickhardt/AAuth/issues/229) (one issue together with AAG-F009), posted 2026-10-01. Earlier plan: New issue. A Core issue on token-endpoint errors, or one policy-denial issue together with AAG-F009, AAG-F059 and AAG-F064.

### AAG-F078 — WSDL `service` plus `operation` does not identify one bound operation

**Status:** submitted

**Targets:** missing-requirement

**Priority:** P2

**First public here:** a6b8648 (2026-08-31)

**Submitted:** 2026-10-01, GitHub, new issue [#244](https://github.com/dickhardt/AAuth/issues/244)

**Upstream evidence:** 28e8258 R3, "WSDL Vocabulary (`urn:aauth:vocabulary:wsdl`)"

**Remaining:** Text unchanged: only `operation` (from portType or binding) and optional `service`; no port, binding, or portType identifier.

**Source:** AAuth R3 (28e8258), `Standard Vocabularies` > `WSDL Vocabulary (urn:aauth:vocabulary:wsdl)`; WSDL 1.1, `Port Types`, `Bindings`, `Ports` and `Services`.

In WSDL a service contains ports, each port selects a binding, and each binding selects a port type. Operation names are scoped below those definitions. R3 supplies only `operation`, taken from "the WSDL `portType` or `binding`", and an optional `service`. That pair cannot distinguish several ports or bindings under one service, and it does not name the port type that WSDL's own identifiers use. Our WSDL adapter derives operations that are uniquely bound and refuses with `operation_identity_ambiguous` when the `service` and `operation` pair would cover distinct bindings.

**Example:** A WSDL 1.1 document defines port types OrderPort and ShipmentPort, and each defines an operation named Cancel. Service OrderService has one port bound to each. An R3 document lists service OrderService and operation Cancel, and the person approves it as cancelling an order. The identifier also matches Cancel on ShipmentPort, and the text does not say which bound operation the grant covers.

**Question:** Should the R3 operation entry include the binding, port, or port type needed to identify the operation the advertised WSDL actually selects?

**Venue:** New issue [#244](https://github.com/dickhardt/AAuth/issues/244), posted 2026-10-01. Earlier plan: New issue. An R3 vocabulary issue, possibly one issue for AAG-F077 to AAG-F080.

### AAG-F079 — OData method narrowing and overload identity are undefined

**Status:** submitted

**Targets:** missing-requirement

**Priority:** P2

**First public here:** a6b8648 (2026-08-31)

**Submitted:** 2026-10-01, GitHub, new issue [#245](https://github.com/dickhardt/AAuth/issues/245)

**Upstream evidence:** 28e8258 R3, "OData Vocabulary (`urn:aauth:vocabulary:odata`)", "Operations Spanning Multiple Definitions", and "Auth Token Extensions"

**Remaining:** Text unchanged: `methods` array with no set semantics, issuer MAY narrow operations without method rules, and bound operations named only `EntitySet/Name`.

**Source:** AAuth R3 (28e8258), `Standard Vocabularies` > `OData Vocabulary (urn:aauth:vocabulary:odata)`, `Authorization Endpoint Extensions` > `Operations Spanning Multiple Definitions`, and `Auth Token Extensions`; OData CSDL, function and action overloads.

R3 puts an HTTP `methods` array inside one OData operation entry, composes multiple definitions by taking the union of operations, and lets the issuer narrow a grant to fewer operations. It does not say whether method order matters, whether a grant may narrow `["GET","POST"]` to `["GET"]`, or how an entry without `methods` relates to one with them. Separately, OData functions and actions can be overloaded by binding type and parameters, while R3 names only `EntitySet/FunctionName` or `EntitySet/ActionName`. Our OData adapter refuses overloaded bound operations and derives no method-qualified authority.

**Example:** An R3 document lists the OData operation `{"operation":"Events"}` with no `methods`. The person approves it as read access to the Events entity set. The agent later sends DELETE /Events(5). One resource treats an omitted `methods` as all methods and accepts; another treats it as the read methods only and refuses. The same ambiguity applies when a per-call grant narrows `methods`: the text does not say whether equality or a subset is required.

**Question:** Should R3 define `methods` as a set with subset and union semantics, and extend bound function and action identifiers enough to name one overload?

**Venue:** New issue [#245](https://github.com/dickhardt/AAuth/issues/245), posted 2026-10-01. Earlier plan: New issue. An R3 vocabulary issue, possibly one issue for AAG-F077 to AAG-F080; method algebra and overload identity can be split if the editors prefer.

### AAG-F080 — AsyncAPI optional `action` has no matching rule

**Status:** submitted

**Targets:** missing-requirement

**Priority:** P2

**First public here:** a6b8648 (2026-08-31)

**Submitted:** 2026-10-01, GitHub, new issue [#246](https://github.com/dickhardt/AAuth/issues/246)

**Upstream evidence:** 28e8258 R3, "AsyncAPI Vocabulary (`urn:aauth:vocabulary:asyncapi`)"

**Remaining:** `action` is still OPTIONAL with no rule for how an omitted action compares with the required native action.

**Source:** AAuth R3 (28e8258), `Standard Vocabularies` > `AsyncAPI Vocabulary (urn:aauth:vocabulary:asyncapi)`; AsyncAPI 3, `Operation Object`.

R3 makes `action` OPTIONAL, while the AsyncAPI Operation Object requires `send` or `receive`. R3 does not say whether an omitted action is filled in from the discovered operation, authorizes either action, or is a distinct operation value. Each reading produces different grant and proposal matching. Our AsyncAPI adapter derives the required native `action` and refuses malformed or unresolved operations, but an R3 request that omits `action` still has no specified comparison against that definition.

**Example:** The resource's AsyncAPI 3 document lists an operation `onOrderCreated` with `action: send`, because the resource publishes the event. The agent's grant declares the same `operationId` with `action: receive`, as the text says subscribing agents do. A resource that validates `action` against its document refuses the grant; a resource that matches only on `operationId` accepts it.

**Question:** Should omission mean "resolve the required action from the `operationId`", or should R3 require `action` whenever the entry is used for authorization?

**Venue:** New issue [#246](https://github.com/dickhardt/AAuth/issues/246), posted 2026-10-01. Earlier plan: New issue. An R3 vocabulary issue, possibly one issue for AAG-F077 to AAG-F080.

### AAG-F095 — Clarification answers do not identify their question

**Status:** open

**Targets:** missing-requirement

**Priority:** P2

**First public here:** caf7310 (2026-08-31)

**Submitted:** no

**Upstream evidence:** 28e8258 Core, "Agent Response to Clarification", "Clarification Response", "Clarification Limits", "Freshness and Replay"

**Remaining:** Unchanged. The answer POST still carries only `action` and the Markdown `clarification_response`, on a pending URL shared by all rounds, with no round identifier. Clarification Limits makes a round maximum a MUST (five RECOMMENDED), so the text expects dialogues of several rounds.

**Source:** AAuth Core (28e8258), `Agent Response to Clarification`, `Clarification Response`, `Clarification Limits`, and `Freshness and Replay`.

Every round uses the same pending URL, and the answer POST carries only `action=clarification_response` and the Markdown answer. Suppose the server accepts one answer and then opens a later question. A delayed or retried POST of the first answer cannot then be told apart from an answer to the later question. `Freshness and Replay` does not close this: the replay cache is a MAY, it rejects duplicate request tuples within the validity window, and an agent's retry after a lost response is a new signed request, not a replay. Polling with `GET` before a retry shows the agent which question is open, but it does not tell the server which question a POST answers.

Our implementation sends each answer as one explicit request with no hidden retry. It allows only one round until the wire carries a binding between answer and question. It can make an exact replay idempotent while the answered round is still the latest, but it cannot recover a round identity that the request never carried.

**Question:** Should each clarification response name a round identifier or question digest supplied by the `202` response, so that a delayed or retried answer cannot bind to a different question?

**Venue:** New issue. A Core issue on clarification correlation.

### AAG-F105 — Deferred mission approval does not define key renewal before token delivery

**Status:** submitted

**Targets:** missing-requirement

**Priority:** P2

**First public here:** 4647768 (2026-08-31)

**Submitted:** 2026-10-01, GitHub, comment on [#108](https://github.com/dickhardt/AAuth/issues/108#issuecomment-5943159888)

**Upstream evidence:** 28e8258 Core, "Mission Creation", "Mission Approval", "Person Token Structure", "Pending URL Security"; https://github.com/dickhardt/AAuth/issues/108

**Remaining:** Still unspecified; editor issue 108 (open, "Pending grant lifetime, and key rotation across a pending grant") tracks the general key-rotation-across-pending case; our mission-approval case is a concrete instance.

**Source:** AAuth Core, `Mission Creation`, `Mission Approval`, `Deferred Responses`, `Person Token Structure`, and `Pending URL Security`.

Mission Creation lets the PS answer a proposal with a `202` deferred response. Pending URL Security requires the server to verify the agent's identity on every poll, but Core does not say whether the agent may renew onto a different proof key while the proposal is pending. The approval returns `person_tokens`, each bound by `cnf` to an agent key, and Person Token Structure says a person token must not outlive "the agent token presented when the token was requested", which is ambiguous between the proposal's agent token and the polling one.

Our implementation retains the proposal key, bounds the pending state by the original agent token's lifetime, and treats a poll under another key as not found. If an approval goes stale before delivery, it returns expiry instead of old credentials. Original-key continuity is our choice, not a stated Core requirement.

**Example:** 1. 09:00: the agent requests a mission with agent token T1, bound to key K1; the PS answers 202 and the approval is pending. 2. 09:30: the agent refreshes to agent token T2, bound to key K2, and keeps polling the pending URL. 3. 09:40: the person approves. 4. Outcomes diverge by PS: one refuses to deliver because the pending record is bound to K1, so the person must approve again; another returns `person_tokens` whose `cnf` is K1, which the agent no longer holds; another returns `person_tokens` with `cnf` K2. The bound on `exp` is T1's or T2's depending on the PS.

**Question:** Must a pending mission proposal stay bound to the original proof key and agent-token lifetime, or should terminal delivery mint person tokens for the currently authenticated agent key after renewal?

**Related upstream issues:** [#108](https://github.com/dickhardt/AAuth/issues/108) Pending grant lifetime, and key rotation across a pending grant (open, dickhardt 2026-08-31; the general case, without missions or person_tokens).

**Venue:** Comment on [#108](https://github.com/dickhardt/AAuth/issues/108#issuecomment-5943159888), posted 2026-10-01. Earlier plan: Comment on [#108](https://github.com/dickhardt/AAuth/issues/108). Add deferred mission approval as a concrete case, cross-linking Pending URL Security and Person Token Structure; together with AAG-F033.

### AAG-F106 — Events requires every event to transit the AP, with no AP-authorized local delivery component

**Status:** submitted

**Targets:** missing-requirement

**Priority:** P2

**First public here:** not public before

**Submitted:** Slack, thread with the editor on delegated event delivery; the original Slack date is not retained (transcript supplied 2026-08-03)

**Upstream evidence:** 28e8258 Events, "AP Metadata"; "Subscribe Token" > "Structure"; "Event Delivery: Resource to AP" > "Request" and "AP Validation"; "Security Considerations" > "AP as Delivery Intermediary"; "Privacy Considerations" > "AP Visibility"; "Design Rationale" > "Why the AP Is the Delivery Intermediary"; "Non-Normative AP-to-Agent Delivery Examples" > "Self-Hosted Agents"

Events gives an AP one AP-wide `event_endpoint`, which a resource resolves from the metadata named by the subscribe token's `iss` (AP Metadata), and assigns every acceptance duty to the AP: subscription lookup by `eid`, the `max_uses` count, and a durable record before `202` (AP Validation). No component near the agent can be authorized by the AP to accept events for a scoped set of subscriptions. The draft documents the privacy cost of this design (Privacy Considerations, AP Visibility, new since the 2026-08-29 snapshot) but not its availability cost, and its Self-Hosted Agents example offers only the two extremes: the agent is its own AP, or every event goes through the external AP.

When the agent and the resource can reach each other but the AP is remote or disconnected (a ship, a factory floor, an isolated intranet), no event can be accepted while the AP is unreachable, even though both ends of the delivery are present. A deployment that wants local delivery while keeping the remote AP as the subscription authority must either run the whole AP locally, giving up the remote AP's authority, or invent a private delegation with no interoperable binding for the delegate's identity, scope (`eid`, `aud`, agent), expiry, `max_uses` enforcement or durable-record duty. The AP-as-inbox design is deliberate (Design Rationale, Why the AP Is the Delivery Intermediary), so this is a scope question.

**Question:** Should Events define, or reserve room for, a way for the AP to authorize a scoped local delivery component for a subscription (its identity, scope, expiry, `max_uses` enforcement and durable-record duty), or else state that AP transit is mandatory and describe the availability consequence next to AP Visibility?

**Venue:** None now: we deferred the follow-up until a working delegated offline/local example exists. The editor replied in the thread that the `event_endpoint` can be hosted anywhere; we answered that this did not resolve the concern. Recheck once that example exists.

### AAG-F083 — Standard R3 vocabularies do not identify external specification revisions

**Status:** submitted

**Targets:** missing-requirement

**Priority:** P3

**First public here:** 83219c1 (2026-08-31)

**Submitted:** 2026-10-01, GitHub, new issue [#249](https://github.com/dickhardt/AAuth/issues/249)

**Upstream evidence:** 28e8258 R3, "Standard Vocabularies" and its seven subsections; R3 front-matter references

**Remaining:** R3 still cites no reference or version for MCP, OpenAPI, gRPC, GraphQL, AsyncAPI, WSDL, or OData; its references list only the AAuth drafts and the transaction-challenge draft.

**Source:** AAuth R3 (28e8258), `Vocabularies` > `Standard Vocabularies` and its seven vocabulary subsections; the document's reference list.

R3 assigns operation identities, discovery behavior, and annotation encodings to MCP, OpenAPI, gRPC, GraphQL, AsyncAPI, WSDL, and OData, but cites no version or stable reference for any of them. Its references cover only the AAuth drafts and the OAuth transaction-challenge draft. These formats change independently, so two conforming implementations can choose different Tool rules, introspection behavior, Operation Objects, or metadata grammars while following the same R3 text. Our implementation keeps its own table of exact format revisions to make its choices reproducible; a local table cannot make the R3 contract interoperable.

**Question:** Should R3 add normative references and a stated revision policy for each standard vocabulary, including how newer compatible revisions are admitted?

**Venue:** New issue [#249](https://github.com/dickhardt/AAuth/issues/249), posted 2026-10-01. Earlier plan: Umbrella only. Raise it before format-specific questions such as AAG-F078.

## Against informative text

Findings against examples, rationale, terminology and other text that uses no BCP 14 keyword.

### AAG-F001 — Interop Surface 3 says resource metadata holds keys, while Core uses `jwks_uri`

**Status:** submitted

**Targets:** informative

**Priority:** P3

**First public here:** 3afa429 (2026-08-28)

**Submitted:** 2026-10-01, GitHub, new issue [#253](https://github.com/dickhardt/AAuth/issues/253)

**Upstream evidence:** 28e8258 interop-demo-profile, "Surface 3 — Resource-token issuance and issuer discovery"; Core, "Resource Metadata"; "JWKS Discovery and Caching"; Signature-Key 69f5ba2, "JWKS URI Discovery (jwks_uri)" and "JWT Confirmation Key (jwt)"

**Remaining:** Surface 3 still says the resource publishes its JWKS at `{iss}/.well-known/aauth-resource.json` and tells verifiers to find the `kid` key in that document. In Core that document carries `jwks_uri`, which points to a separate key set.

**Source:** interop demo profile, `Surface 3 — Resource-token issuance and issuer discovery`; AAuth Core, `Resource Metadata` and `JWKS Discovery and Caching`.

Surface 3 says the resource "publishes its JWKS at" `{iss}/.well-known/aauth-resource.json`. Its verification step tells verifiers to fetch that document, check `issuer`, and find the key matching the JWT `kid` in it. In Core, `aauth-resource.json` is resource metadata. That metadata carries `jwks_uri`, which is REQUIRED when the resource issues resource tokens, and the keys are published at that URI. A verifier that follows Surface 3 literally looks for keys in the metadata document and does not find them.

Our verifier follows Core: it fetches the metadata, checks `issuer`, dereferences `jwks_uri`, and selects the key by `kid`.

**Example:**

```text
GET https://resource.example/.well-known/aauth-resource.json
-> {"issuer":"https://resource.example","jwks_uri":"https://resource.example/jwks.json", ...}
GET https://resource.example/jwks.json
-> {"keys":[{"kty":"OKP","crv":"Ed25519","kid":"resource-key-1","x":"..."}]}
A verifier that follows Surface 3 searches the first document for kid "resource-key-1" and finds no "keys" member.
```

**Question:** Should Surface 3 be reworded to "publishes resource metadata whose `jwks_uri` names its JWKS", with a verification step that dereferences `jwks_uri`?

**Venue:** New issue [#253](https://github.com/dickhardt/AAuth/issues/253), posted 2026-10-01. Earlier plan: Umbrella only. No existing issue covers this; it could also be a small pull request against the interop profile.

### AAG-F005 — R3 same-URI replacement can make an old content hash unverifiable

**Status:** submitted

**Targets:** informative

**Priority:** P3

**First public here:** 3afa429 (2026-08-28)

**Submitted:** 2026-10-01, GitHub, new issue [#247](https://github.com/dickhardt/AAuth/issues/247)

**Upstream evidence:** 28e8258 R3, "Content Addressing"; "Caching"; "Design Rationale" > "Why Not RAR"

**Remaining:** "Content Addressing" still lets a resource update the document at the same URI, while "Caching" and "Why Not RAR" still say a logged `r3_uri` plus `r3_s256` is enough to re-fetch and verify the document later.

**Source:** R3, `Content Addressing`, `Caching`, and `Design Rationale` > `Why Not RAR`.

`Content Addressing` allows a resource to update the document at the same URI: existing auth tokens keep the old hash and new resource tokens get the new one. `Caching` says the issuer need not retain R3 documents, because its audit log of `r3_uri` and `r3_s256` "is enough to re-fetch and verify the document later". `Why Not RAR` makes the same re-fetch claim. Once a resource replaces the bytes at a URI, re-fetching that URI returns the new document, and the logged hash can no longer be verified. The permanent audit record then depends on the issuer having cached the old bytes, which `Caching` says it need not do.

Our resource store treats a published R3 URI as immutable: new bytes get a new URI, and referenced bytes stay available. A conflicting write is refused with evidence.

**Example:**

```text
t0: resource serves document D1 at https://api.example/r3/orders.json; r3_s256 = H1
t1: AS issues auth token A1 that references (r3_uri, H1); the audit log records (r3_uri, H1)
t2: resource replaces the document at the same URI with D2 (line 490 allows this); new resource tokens carry H2
t3: an auditor re-fetches r3_uri to verify A1's log entry: the bytes hash to H2, not H1, so verification fails (547) and D1 is gone unless the AS kept it
```

**Question:** Should R3 say that later verification needs either a retained copy of the bytes or an unchanged document at the URI, and soften "permanent" in "Auth Token Extensions" to match? If the audit guarantee is intended as stated, should it instead require that bytes at a referenced `r3_uri` stay available and unchanged, at least for as long as an audit record may cite them, drop same-URI replacement, or require the issuer to retain the documents it relied on?

**Venue:** New issue [#247](https://github.com/dickhardt/AAuth/issues/247), posted 2026-10-01. Earlier plan: Umbrella only. No existing issue covers this.

### AAG-F030 — Resource-managed interaction is assigned both 202 and 401

**Status:** submitted

**Targets:** informative

**Priority:** P3

**First public here:** 0a5e37a (2026-08-30)

**Submitted:** 2026-10-01, GitHub, new issue [#240](https://github.com/dickhardt/AAuth/issues/240)

**Upstream evidence:** 28e8258 Core, "Resource-Managed Authorization"; "Requirement Values"; "Resource Metadata"; "Resource Adoption Path"; related https://github.com/dickhardt/AAuth/issues/209

**Remaining:** The flow and Requirement Values use 202, but Resource Metadata (intro and the authorization_endpoint field) and Adoption Path step 2 still say interaction requirements come via 401. Issue 209 covers the auth-token status, which is a different problem.

**Source:** AAuth Core, `Resource-Managed Authorization`, `Requirement Values`, `Resource Metadata`, and `Resource Adoption Path`.

The dedicated flow and the requirement table use `202 Accepted` for `requirement=interaction`. `Resource Metadata` says something different twice: its introduction, and the `authorization_endpoint` member, both say a resource issues interaction requirements through `401` responses. `Resource Adoption Path` step 2 also says resource-managed authorization works through `401` responses.

**Example:**

```text
Reading A (lines 2101 and 2130): a resource answers an interaction requirement with HTTP 401.
Reading B (lines 2351, 2360 and 575): a resource answers the same interaction requirement with HTTP 202.
An agent coded to Reading B polls on 202 and may treat 401 as a credential failure, so against a Reading A resource it does not start the interaction.
An agent coded to Reading A may not recognize a 202 from a Reading B resource as an interaction requirement.
```

**Question:** Which status is normative for a direct resource interaction, and should the other passages be corrected?

**Venue:** New issue [#240](https://github.com/dickhardt/AAuth/issues/240), posted 2026-10-01. Earlier plan: Umbrella only. Together with AAG-F031. Issue [#209](https://github.com/dickhardt/AAuth/issues/209) is related but concerns the status listed for `auth-token` in the Requirement Values table, not interaction.

### AAG-F031 — The resource authorization endpoint is not a PS-free path

**Status:** submitted

**Targets:** informative

**Priority:** P3

**First public here:** 0a5e37a (2026-08-30)

**Submitted:** 2026-10-01, GitHub, new issue [#241](https://github.com/dickhardt/AAuth/issues/241)

**Upstream evidence:** 28e8258 Core, "Authorization Endpoint"; "Response without Resource Token"; "Resource Access"; "Resource Adoption Path"; "Consuming a Resource End to End"

**Remaining:** The endpoint still requires a person token, yet Adoption Path step 2 and the session-token mode still present it as two-party, PS-less access.

**Source:** AAuth Core, `Authorization Endpoint`, `Response without Resource Token`, `Resource Access`, `Resource Adoption Path`, and `Consuming a Resource End to End`.

Every request to the authorization endpoint must carry a PS-issued person token. Even so, `Response without Resource Token` points to resource-managed authorization. `Resource Adoption Path` step 2 lists "an authorization endpoint" as a two-party mechanism. `Consuming a Resource End to End` lists a request to the `authorization_endpoint` as a session-token path. `Resource Access` says the first two modes involve no PS. An agent with no PS can use only the direct challenge path, not this endpoint.

**Question:** Should this branch be described as resource-local authorization after PS identity, rather than as a two-party flow? Or is another request shape, with no person token, intended?

**Venue:** New issue [#241](https://github.com/dickhardt/AAuth/issues/241), posted 2026-10-01. Earlier plan: Umbrella only. Together with AAG-F030.

### AAG-F042 — The interop profile asks the Resource to verify the wrong signature

**Status:** submitted

**Targets:** informative

**Priority:** P3

**First public here:** 172bb44 (2026-08-30)

**Submitted:** 2026-10-01, GitHub, new issue [#254](https://github.com/dickhardt/AAuth/issues/254)

**Upstream evidence:** 28e8258 interop-demo-profile, "Surface 5 — Parent-mediated sub-agent token handling"

**Remaining:** "What to verify" still says the auth token is "signed with the sub-agent's key"; the PS or AS signs the JWT, and the sub-agent key is in `cnf` and signs the HTTP request.

**Source:** Interoperability demo profile, `Surface 5 — Parent-mediated sub-agent token handling` ("What to verify"); AAuth Core, `Parent-Mediated Authorization` step 5.

The profile says the Resource confirms the auth token is "signed with the sub-agent's key." The PS (three-party) or AS (four-party) signs the auth token JWT. The sub-agent's key appears in the token's `cnf.jwk`, signs the HTTP request, and is what the Resource checks against `cnf.jwk`. Surface 5 step 6 already states `cnf.jwk` = the sub-agent's key, so only the verification sentence is wrong.

**Example:** Profile line 63: the auth token signature is checked against the issuer's JWKS. Line 64: cnf.jwk matches the key that signed the HTTP request. Line 77 (step 6): cnf is the sub-agent's key. Line 81: 'the resource confirms the auth token is signed with the sub-agent's key; the PS's log records the parent as the requesting agent.' Only line 81 is wrong.

**Question:** Should the profile instead say that the Resource verifies a request signed by the sub-agent whose auth-token `cnf.jwk` matches that request key, with the JWT signature verified against the issuer's JWKS?

**Venue:** New issue [#254](https://github.com/dickhardt/AAuth/issues/254), posted 2026-10-01. Earlier plan: Umbrella only. The editorial change could also be made directly in the profile.

### AAG-F062 — approved_at does not ensure a globally unique mission digest

**Status:** submitted

**Targets:** informative

**Priority:** P3

**First public here:** 076c522 (2026-08-30)

**Submitted:** 2026-10-01, GitHub, new issue [#242](https://github.com/dickhardt/AAuth/issues/242)

**Upstream evidence:** 28e8258 Core, "Mission Approval"; "Mission Identifier"

**Remaining:** The blob member list still says approved_at "Ensures the s256 is globally unique". The blob has no nonce or approver member, so identical approvals still hash to the same value.

**Source:** AAuth Core, `Mission Approval` and `Mission Identifier`.

`Mission Approval` says `approved_at` ensures that `s256` is globally unique. Two approvals with the same agent, timestamp, description and optional members have identical bytes, and therefore the same digest. This can happen with a coarse or deterministic clock. The blob has no nonce, and `Mission Identifier` says it deliberately carries no approver member. It names the mission by the pair of PS and `s256`, so two different PSes could also produce the same blob.

Our implementation adds no private mission member. Its store rejects a second identical identifier as a conflict, rather than silently treating a new approval as the old mission.

**Example:** Two approvals with the same agent, description and members, made within the resolution of `approved_at`, give an identical `s256`.

**Question:** Should the blob include a required unique value? Or should Core drop the global-uniqueness claim, scope uniqueness to the PS and `s256` pair, and define identical approvals at one PS as the same mission?

**Venue:** New issue [#242](https://github.com/dickhardt/AAuth/issues/242), posted 2026-10-01. Earlier plan: Umbrella only. No existing issue discusses uniqueness.

### AAG-F072 — Bootstrap names `jti` replay protection without defining replay

**Status:** submitted

**Targets:** informative

**Priority:** P3

**First public here:** 9f0c368 (2026-08-30)

**Submitted:** 2026-10-01, GitHub, new issue [#251](https://github.com/dickhardt/AAuth/issues/251); earlier, the editor took this topic from our public notes in round one, June 2026

**Upstream evidence:** 28e8258 Bootstrap, "Refresh Patterns" > "Two-Key Refresh"; 69f5ba2 signature-key, "JKT JWT Self-Issued Key Delegation (jkt-jwt)" and "Client Processing"

**Remaining:** Bootstrap still says the naming JWT carries "a `jti` for replay protection"; Signature-Key still requires `jti` only for caching and defines no replay contract.

**Source:** AAuth Bootstrap (28e8258), `Refresh Patterns` > `Two-Key Refresh`; HTTP Signature Keys (69f5ba2), `JKT JWT Self-Issued Key Delegation (jkt-jwt)` and `Client Processing`.

Bootstrap says the naming JWT carries a `jti` for replay protection. Signature-Key makes `jti` OPTIONAL on a `jkt-jwt`, REQUIRED only when the JWT is presented with `cache`, and its verification procedure neither consumes nor retains it. Neither document defines the replay key's namespace, its retention lifetime, what exact request it binds, what a duplicate returns, or how a client recovers a lost response.

Our implementation requires `jti`, keys it by the durable-key thumbprint, binds the exact naming JWT and JSON body, requires a freshly signed outer retry, returns the first Agent token on an exact retry, and rejects changed input. These are implementation choices, not requirements read from the text.

**Example:** An agent's durable key signs a naming JWT with exp = iat + 24h (the Signature-Key example, 393-394, carries no `jti`). An attacker holding the ephemeral key and one observed naming JWT calls POST /refresh (305-317) repeatedly until exp. Bootstrap 321 names a `jti` for replay protection, but neither 321 nor Signature-Key 347 says the AP rejects a repeated `jti`.

**Question:** Should Bootstrap define the minimum replay and lost-response contract for a two-key refresh, or state explicitly that each AP profile must define it?

**Venue:** New issue [#251](https://github.com/dickhardt/AAuth/issues/251), posted 2026-10-01. Earlier plan: Umbrella only. It touches both Bootstrap and Signature-Key.

### AAG-F073 — The delegated request-key algorithm is described as enclave-determined

**Status:** submitted

**Targets:** informative

**Priority:** P3

**First public here:** 9f0c368 (2026-08-30)

**Submitted:** 2026-10-01, GitHub, new issue [signature-key#45](https://github.com/dickhardt/signature-key/issues/45)

**Upstream evidence:** 69f5ba2 signature-key, "JKT JWT Self-Issued Key Delegation (jkt-jwt)"

**Remaining:** The paragraph after the example still ends "The `cnf.jwk` request key algorithm is likewise enclave-determined," although the same section says the ephemeral key is signed in software. The signature-key tracker was not available locally to check for an existing issue.

**Source:** HTTP Signature Keys (69f5ba2), `JKT JWT Self-Issued Key Delegation (jkt-jwt)`; AAuth Bootstrap (28e8258), `Per-Platform Key Handling` > `Mobile (iOS and Android)` and `Refresh Patterns` > `Two-Key Refresh`.

Both documents describe the fresh ephemeral request key as generated in software; the Signature-Key example explanation says the Ed25519 ephemeral key is "signed in software". The next paragraph says the stable key's algorithm is determined by the enclave hardware, then adds that the `cnf.jwk` request key algorithm is "likewise enclave-determined". That describes the durable platform key, not the delegated key. Our implementation treats both algorithms as explicit supported inputs and currently supports Ed25519 only.

**Example:** Line 406 shows a P-256 enclave key delegating to an Ed25519 software key, and the example at line 400 carries an Ed25519 `cnf.jwk`. Line 408 then says the `cnf.jwk` request key algorithm is 'likewise enclave-determined'. An implementer who follows 408 literally could reject the Ed25519 request key that the example itself uses.

**Question:** Should the text say that the durable signing algorithm is platform-determined, while the client chooses the delegated request-key algorithm from those the verifier supports?

**Venue:** New issue [signature-key#45](https://github.com/dickhardt/signature-key/issues/45), posted 2026-10-01. Earlier plan: Umbrella only. Check the Signature-Key tracker for a `jkt-jwt` clarification issue first.

### AAG-F074 — Stable Agent `sub` does not distinguish the two key rotations

**Status:** submitted

**Targets:** informative

**Priority:** P3

**First public here:** 9f0c368 (2026-08-30)

**Submitted:** 2026-10-01, GitHub, new issue [#252](https://github.com/dickhardt/AAuth/issues/252)

**Upstream evidence:** 28e8258 Core, "Agent Identifiers" and "Agent Token Structure"; Bootstrap, "Per-Install Identity" and "Key Rotation vs Token Refresh"

**Remaining:** Core still says the agent identifier and `sub` are "stable across key rotations" without qualification; Bootstrap still says a new durable key produces a new agent identity.

**Source:** AAuth Core (28e8258), `Agent Identifiers` and `Agent Token` > `Agent Token Structure`; AAuth Bootstrap (28e8258), `Agent Identifier Strategies` > `Per-Install Identity` and `Refresh Patterns` > `Key Rotation vs Token Refresh`.

Core says an agent identifier is stable across key rotations, and describes `sub` the same way. Bootstrap keeps `sub` when only the ephemeral token key changes, but treats a new durable enrollment key as a new agent with a new `sub`. Our API makes the distinction explicit: refresh rotates the ephemeral key under one enrollment, and a different durable key does not enter that enrollment.

**Example:** An agent's enrolled (durable) key is replaced. An implementer reading Core 506 and 520 keeps the same `sub` in the next agent token. One reading Bootstrap 259 and 337 issues a new `sub`, because a new durable key is a new agent.

**Question:** Should Core distinguish proof-key rotation from replacement of the key an AP enrolls against when it states that `sub` is stable?

**Venue:** New issue [#252](https://github.com/dickhardt/AAuth/issues/252), posted 2026-10-01. Earlier plan: Umbrella only. A Core and Bootstrap terminology point.

### AAG-F082 — OData annotation encoding lacks a resolvable term namespace and target

**Status:** submitted

**Targets:** informative

**Priority:** P3

**First public here:** 83219c1 (2026-08-31)

**Submitted:** 2026-10-01, GitHub, new issue [#248](https://github.com/dickhardt/AAuth/issues/248)

**Upstream evidence:** 28e8258 R3, "Operation Access Annotations" > "Vocabulary Encodings"; R3, "OData Vocabulary (`urn:aauth:vocabulary:odata`)"

**Remaining:** Still names `AAuth.AccessMode` and `AAuth.Budget` with no CSDL vocabulary namespace or reference; the annotated element is named ("the entity set or bound operation the R3 operation identifier names"), and overload identity is AAG-F079.

**Source:** AAuth R3 (28e8258), `Operation Access Annotations` > `Vocabulary Encodings` and `Standard Vocabularies` > `OData Vocabulary (urn:aauth:vocabulary:odata)`; OData CSDL, vocabulary references and bound operation overloads.

The encoding table names the terms `AAuth.AccessMode` and `AAuth.Budget`, but R3 does not define the CSDL vocabulary namespace or the reference needed to resolve them. It applies the annotation to "the entity set or bound operation the R3 operation identifier names", which names the annotated element; selecting one overload of a bound operation is AAG-F079. An implementation cannot resolve the terms without inventing a namespace or alias. Annotations are advisory and not an enforcement surface, so the effect is limited to tooling that reads them. Our OData adapter refuses AAuth annotations and overloaded bound operations instead of guessing.

**Question:** Should R3 define the OData vocabulary namespace and its reference, so that `AAuth.AccessMode` and `AAuth.Budget` resolve?

**Venue:** New issue [#248](https://github.com/dickhardt/AAuth/issues/248), posted 2026-10-01. Earlier plan: Umbrella only. It can also be the closing sentence of the AAG-F079 issue.

### AAG-F094 — Clarification actions have no success-response contract

**Status:** submitted

**Targets:** informative

**Priority:** P3

**First public here:** caf7310 (2026-08-31)

**Submitted:** 2026-10-01, GitHub, new issue [#239](https://github.com/dickhardt/AAuth/issues/239)

**Upstream evidence:** 28e8258 Core, "Clarification Response", "Cancel Request", "Deferred Response State Machine"

**Remaining:** Unchanged. The POST `clarification_response` section still says only "the agent resumes polling with GET". Cancel Request says only that later requests return 410. The state machine covers the initial request and GET polls, not the POST and DELETE actions.

**Source:** AAuth Core (28e8258), `Agent Response to Clarification`, `Clarification Response`, `Cancel Request`, and `Deferred Response State Machine`.

The draft defines the signed POST (`action=clarification_response`) and the signed DELETE to the pending URL. After the POST it says only that the Agent resumes polling with `GET`. After the DELETE it says only that later requests return `410 Gone`. The only defined error is `400` for a missing or unrecognized `action`. Neither action has a success status, response body, cache rule, or error mapping, and the `Deferred Response State Machine` covers only the initial request and `GET` polls. An implementation that requires one particular status can reject a compatible server. One that accepts any response can mistake a failed action for success.

Our Agent treats any `2xx` as acceptance of the action and takes no terminal authorization from that response; the next poll is a separate, explicit request. It refuses redirects and non-`2xx` responses, and never polls or retries without being told to.

**Example:** 1. The agent POSTs `{"action":"updated_request","presented_token":"<token>", ...}` to the pending URL. 2. The PS decides at once and returns the terminal response on the POST (for example `200` with the token requested). 3. The agent follows the `clarification_response` pattern at 1102 by analogy, treats the POST as an acknowledgement and polls with GET without keeping the POST body. 4. The GET returns `410 Gone` (2840) and the token in the discarded body cannot be fetched again. A PS that answered `202` and delivered on the next GET would have worked with the same agent.

**Question:** Which status codes and response fields are valid after `clarification_response` and after cancellation? Must successful responses carry `Cache-Control: no-store`?

**Venue:** New issue [#239](https://github.com/dickhardt/AAuth/issues/239), posted 2026-10-01. Earlier plan: New issue. A Core issue on the response to a clarification action.

### AAG-F104 — Core both permits and forbids a self-hosted Agent Provider

**Status:** submitted

**Targets:** informative

**Priority:** P3

**First public here:** 2b7909b (2026-08-31)

**Submitted:** 2026-10-01, GitHub, comment on [#208](https://github.com/dickhardt/AAuth/issues/208#issuecomment-5943160270)

**Upstream evidence:** 28e8258 Core, "Roles", "Agent Provider", "Intermediary Agent Identity", "AAuth Platform Value Registry", "Why `.json` in Well-Known URIs", "Why Agents Are Under an Agent Provider"; Bootstrap, "Self-Hosted Agents", "Self-Hosted Refresh"; https://github.com/dickhardt/AAuth/issues/208

**Remaining:** Contradiction still in the text; editor issue 208 (open, 2026-09-25) tracks the same fix (drop the "distinct AP, not self-signed" sentence).

**Source:** AAuth Core, `Roles`, `Agent Provider`, `Intermediary Agent Identity`, `AAuth Platform Value Registry`, `Why .json in Well-Known URIs`, and `Why Agents Are Under an Agent Provider`; AAuth Bootstrap, `Self-Hosted Agents` and `Self-Hosted Refresh`.

Core's Roles and Agent Provider sections say a self-hosted agent is its own AP, and Intermediary Agent Identity requires an intermediary to be its own AP. The platform registry includes `self-hosted`, and the `.json` rationale cites static hosting of self-hosted agent metadata. Bootstrap specifies the key relationship: the JWKS-published key signs the self-issued agent token and is also its `cnf` key, and fresh self-issued tokens replace a refresh ceremony.

The design rationale `Why Agents Are Under an Agent Provider` still says an agent that is its own AP weakens the protocol and concludes that "AAuth therefore requires every agent to hold a token issued by a distinct AP, not self-signed." Both statements cannot describe the same conformance model.

Our implementation follows the normative topology and the Bootstrap profile: ordinary AP metadata, JWKS, agent-token minting, agent verification, and protected Resource use with no special verifier path.

**Question:** Is the distinct-AP conclusion in the rationale stale, or should the self-hosted topology, platform value, and Bootstrap profile be narrowed?

**Related upstream issues:** [#208](https://github.com/dickhardt/AAuth/issues/208) Design rationale says an agent cannot be its own agent provider (open, dickhardt 2026-09-25).

**Venue:** Comment on [#208](https://github.com/dickhardt/AAuth/issues/208#issuecomment-5943160270), posted 2026-10-01. Earlier plan: Comment on [#208](https://github.com/dickhardt/AAuth/issues/208). A short, optional comment adding that the self-hosted path needs no special verifier handling; this item is resolved when that issue lands.

### AAG-H003 — Recommended justification sections

**Status:** submitted

**Targets:** informative

**Priority:** P3

**First public here:** 3afa429 (2026-08-28)

**Submitted:** Slack, four-party implementation round with the editor, item 5 (a concrete proposal for the `justification` sections); the original Slack date is not retained (transcript supplied 2026-08-03)

**Upstream evidence:** 28e8258 Core, "Terminology" (Markdown, Editor's note); "Auth Token Request" (`justification`)

**Remaining:** The literal TODO is gone, but the section structure is still undefined. Terminology now has an editor's note deferring section structures for all Markdown-valued parameters to a later revision, and `justification` says no structure is defined yet.

**Source:** AAuth Core, `Terminology` (Markdown entry and its editor's note) and `Auth Token Request` (`justification` parameter).

Earlier feedback proposed a small Markdown structure for `justification`, scaled to the stakes of the request: purpose; scope and magnitude; effect and reversibility; and, optionally, timing or alternatives. The current `justification` parameter says the document does not yet define a section structure for the value. The editor's note in `Terminology` defers recommended structures for every Markdown-valued parameter (mission text, justifications, clarifications, permission, audit and interaction descriptions) to a later revision, so that they stay consistent with each other.

Our consent interface renders `justification` as agent-asserted, sanitized Markdown and does not depend on any section structure.

**Question:** When the Markdown section structures are defined, should `justification` use stakes-proportional sections such as purpose, scope and magnitude, and effect and reversibility, with the same convention reused for the other Markdown parameters?

**Venue:** None now: the editor deferred it to a later revision. The editor replied in the Slack round that more real-world experience is needed, and an editor's note in 28e8258 Core defers recommended section structures for Markdown-valued parameters to a later revision. Recheck then, and offer the earlier proposal as input rather than as a new item.

## Local implementation notes (not upstream feedback)

These record choices aauth-go makes where the drafts leave the matter open;
they are not requests to the editors.

### AAG-F013 — Restored deferred state can lose the verified request authority

Core makes signature verification normative at request time and requires the agent's identity to be verified on every poll ("Pending URL Security"), but leaves to the server how a PS or AS stores and restores a pending record; archiving the signed request, `Signature-Key` value and verification result is only a SHOULD for audit ("Non-Repudiation and Audit After Key Rotation"). How a server restores its own pending state does not change what goes over the wire, so two servers that differ here still interoperate. aauth-go stores the exact request body, covered headers, signature, verification key and verification time with each pending record, and re-verifies them offline after a restart before the record can be used again.

### AAG-F027 — Resource sessions do not define agent identity across key rotation

Core says a session token in `AAuth-Access` is meaningless without a valid signature from the agent, but leaves open whether the resource binds the session to the agent identifier, to the current `cnf` key or to both, and what happens when the agent provider issues the same agent a new signing key ("AAuth-Access Response Header", "Why Session Tokens Are Opaque"). No case was identified in which two conforming implementations fail to interoperate because of this choice. aauth-go binds the session to the stable agent provider, agent and parent identity, and verifies the current agent token and signature on every request, so the agent can rotate its key without letting another agent use the session.

## Resolved, rejected and withdrawn

- **AAG-F002** AS request example used a `jwks_uri` Signature-Key parameter the scheme did not define (resolved). The examples now use `sig=jwks_uri;id=...;dwk="aauth-person.json";kid="key-1"`, matching the scheme's `id`, `dwk` and `kid` parameters (28e8258 Core, "PS-to-AS Token Request", "Keying Material"; fixed by [PR #148](https://github.com/dickhardt/AAuth/pull/148)).
- **AAG-F003** Audit delivery has no stable retry identity after a lost 201 (withdrawn). The audit endpoint is fire-and-forget (28e8258 Core, "Audit Response"), so sending once and resending are both conformant, and the editor's reply closing [PR #66](https://github.com/dickhardt/AAuth/pull/66) leaves audit-log completeness to implementations.
- **AAG-F004** Deferred terminal delivery at the PS and in resource-managed flows has no recovery path (withdrawn). A lost terminal response is recovered by a fresh request (28e8258 Core, "Deferred Response State Machine"), "Pending URL Security" already keeps a retained result for the flows that need one, and because the PS SHOULD remember consent within the mission the cost is at most a second prompt.
- **AAG-F006** R3 example hashes are not real SHA-256 values (withdrawn). The example hash values are informative placeholders (a 40-character value cannot encode a SHA-256 digest), and the normative rules are unaffected: the resource serves the exact bytes and verification rejects a mismatch (28e8258 R3, "Content Addressing", "Issuer Processing").
- **AAG-F007** Mission completion appeared in the introductory interaction-endpoint list (resolved). The finding was correct at a99d353; the -11 restructure ([PR #197](https://github.com/dickhardt/AAuth/pull/197)) removed the introductory list, and 28e8258 Core "Interaction Endpoint" says mission completion is proposed at `mission_endpoint`.
- **AAG-F008** Updated clarification requests referred to a removed agent claim (resolved). Updated Request now requires the same `iss`, `ps`, `sub`, `agent_jkt`, `mission_s256` and `tenant` and no longer mentions `agent` (28e8258 Core, "Updated Request"; [PR #129](https://github.com/dickhardt/AAuth/pull/129) and [PR #136](https://github.com/dickhardt/AAuth/pull/136)); submitted as our [comment on issue #104](https://github.com/dickhardt/AAuth/issues/104#issuecomment-5498039783) on 2026-09-01.
- **AAG-F011** Person token endpoint omitted the auth-token request parameters (resolved). Person Token Endpoint now takes `capabilities`, `login_hint`, `tenant`, `domain_hint`, `prompt`, `justification`, `platform` and `device`, and without the interaction capability a PS that must reach the person answers `user_unreachable` (28e8258 Core, "Person Token Endpoint"; [PR #186](https://github.com/dickhardt/AAuth/pull/186), [issue #175](https://github.com/dickhardt/AAuth/issues/175), [issue #177](https://github.com/dickhardt/AAuth/issues/177)); submitted as our [comment on issue #88](https://github.com/dickhardt/AAuth/issues/88#issuecomment-5498039809) on 2026-09-01.
- **AAG-F012** A lost initial 202 has no recovery identity (withdrawn). A resend is a new signed request (28e8258 Core, "Pending Response", "Polling with GET", "Freshness and Replay"), a duplicate pending record expires, nothing forbids the PS returning the pending URL it already issued, and the worst case is a second prompt.
- **AAG-F014** R3 operation selection on a protected challenge (withdrawn). The text already answered this at a99d353 and still does at 28e8258: without `r3_operations` the resource includes R3 claims "based on its own policy" (R3, "Authorization Endpoint Extensions" > "Request"; "Resource Enforcement"); the remaining part became AAG-F014a.
- **AAG-F014a** The issuer cannot tell the requested operations from a broader R3 document (withdrawn). The resource owns the mapping from request to document (28e8258 R3, "Authorization Endpoint Extensions" > "Request" and "Response"): a standing document may cover more than the request, only composed documents are an exact union ("Operations Spanning Multiple Definitions"), and the issuer MAY narrow the grant ("Auth Token Extensions").
- **AAG-F015** Per-call auth tokens did not identify the record that supplies `presented_jti` (resolved). `presented_jti` now names the token actually presented (the auth token on a per-call challenge), which the agent passes to the PS as `presented_token` (28e8258 Core, "Resource Token Structure", "Auth Token Request"; R3, "Flow"; [issue #152](https://github.com/dickhardt/AAuth/issues/152), [PR #153](https://github.com/dickhardt/AAuth/pull/153)).
- **AAG-F018** Missing proof fields have two error classifications (resolved). Core step 1 now returns `invalid_signature` for a missing `Signature`, `Signature-Input` or `Signature-Key`, matching Signature-Key's definition (28e8258 Core, "Verification (Server)" step 1; 69f5ba2 Signature-Key, "invalid_signature").
- **AAG-F020** Core JWKS stale-on-error caching conflicts with Signature-Key caching guidance (withdrawn). Core "JWKS Discovery and Caching" (28e8258) makes discarding stale keys a SHOULD with a 24-hour cap, not a requirement, and Signature-Key has no stale-on-error or 24-hour rule, so the two texts do not conflict.
- **AAG-F021** Signature-Key distinct-key MUST versus AAuth's one key across servers (withdrawn). The distinct-key MUST sits in Signature-Key's pseudonymity discussion (69f5ba2 Signature-Key, "Pseudonymity vs. Identity"), and AAuth agents use the `jwt` scheme, not `hwk` (28e8258 Core, "Keying Material"), so this is at most a question about the requirement's scope, not an established contradiction in normative text, and no interoperability or security failure follows.
- **AAG-F022** Resource-side rejection of auth tokens outliving the agent token (resolved). The conflicting resource-side rejection sentence is gone, and Core states only the issuer-side cap that an auth token's `exp` must not exceed that of the agent token used to obtain it (28e8258 Core, "Re-authorization", "Auth Token Structure").
- **AAG-F023** Deferred auth-token delivery record key and pending URL lifetime (resolved). Deferred Delivery now keys the record by the auth token's `jti`, and Pending URL Security gives deferred auth-token delivery an explicit 410 exception (28e8258 Core; [issue #92](https://github.com/dickhardt/AAuth/issues/92), [PR #99](https://github.com/dickhardt/AAuth/pull/99)).
- **AAG-F024** Deferred Delivery has no rule for the crash window (withdrawn). Durability already follows from 28e8258 Core "Deferred Delivery", where the resource keeps a retained record keyed by the auth token's `jti`, and no crash case was identified in which two conforming implementations interoperate differently.
- **AAG-F028** Opaque AAuth-Access session token conflicts with the all-JWT statement (withdrawn). Editorial only: the opaque `token68` handling of an `AAuth-Access` value is stated in 28e8258 Core "AAuth-Access Response Header", so the draft's own text corrects a reading of the all-JWT sentence in "Protocol Overview".
- **AAG-F032** Resource sessions have no standardized lifecycle or errors (withdrawn). The session token is opaque to the agent and resource-local, so its lifecycle can stay with the resource (28e8258 Core, "AAuth-Access Response Header"), and a resource can answer with the ordinary requirement responses ("Resource Access").
- **AAG-F034** Signing scheme for PS-to-resource revocation requests (resolved). Keying Material now requires `scheme=jwks_uri` with the server's issuer and `dwk` for a server's own requests, including revocation, and the Revocation Request example shows a PS signing to a resource that way (28e8258 Core; [PR #148](https://github.com/dickhardt/AAuth/pull/148)).
- **AAG-F035** Signature coverage for JSON revocation requests to resources (resolved). Submitted as our [issue #165](https://github.com/dickhardt/AAuth/issues/165) on 2026-09-13; Covered Components now requires `content-digest` and `content-type` at every revocation endpoint, including a resource's (28e8258 Core, "Covered Components", "Revocation Request"; [PR #191](https://github.com/dickhardt/AAuth/pull/191), 2026-09-20).
- **AAG-F036** Response when a revoked token is presented (resolved). Core now specifies 401 with `Signature-Error` `error=revoked_jwt` and, as a SHOULD, `AAuth-Requirement` `requirement=person-token`, and server verification checks revocation (28e8258 Core, "Presenting a Revoked Token", "Verification (Server)"; [PR #149](https://github.com/dickhardt/AAuth/pull/149) and [PR #150](https://github.com/dickhardt/AAuth/pull/150)).
- **AAG-F037** Revocation request contents, retention, and unknown-token handling (resolved). The request now carries `jti` and `exp` (REQUIRED), retention is bounded by `exp` plus clock skew, there is no "not found" response, and unseen tokens are recorded (28e8258 Core, "Revocation Request", "Revocation Response", "Revocation Cascade"; [PR #147](https://github.com/dickhardt/AAuth/pull/147), [PR #149](https://github.com/dickhardt/AAuth/pull/149), [PR #190](https://github.com/dickhardt/AAuth/pull/190), [PR #192](https://github.com/dickhardt/AAuth/pull/192)); Core "Who Revokes What" explicitly excludes revoking an Agent token at a Resource (the agent provider revokes an agent token at the PS only, and a resource that accepts one directly has no revocation path), so aauth-go's Agent-token revocation at a Resource endpoint is an extension.
- **AAG-F043** Parent attenuation has no request parameter (withdrawn). The Auth Token Endpoint has no scope parameter by design: the Resource sets scope through the resource token and can adjust it on re-authorization (28e8258 Core, "Auth Token Request", "Re-authorization"), and a parent attenuates by refusing or delaying the request it forwards ("Sub-Agents" > "Parent-Mediated Authorization").
- **AAG-F046** Generic auth-token verification has no call-chain context (resolved). Upstream Token Verification step 1 now lists the substitutions to Person and Auth Token Verification: `aud` is the intermediary, `cnf.jwk` is not compared with the request signer, and the resource `sub` record check does not apply (28e8258 Core; [PR #162](https://github.com/dickhardt/AAuth/pull/162) item 2).
- **AAG-F047** The upstream `cnf` description names the wrong key (resolved). Call Chaining now says the upstream token's `cnf` is the calling agent's key, not the intermediary's, and step 1 says it is not compared with the request signer (28e8258 Core, "Call Chaining", "Upstream Token Verification"; [PR #162](https://github.com/dickhardt/AAuth/pull/162) item 2).
- **AAG-F048** The audience rule implies Resource/AP collocation (resolved). Core now states that an intermediary MUST be its own agent provider, with agent metadata `issuer` equal to its resource `issuer`, and Roles lists Resource + Agent + AP as a collocation (28e8258 Core, "Intermediary Agent Identity", "Roles"; [PR #176](https://github.com/dickhardt/AAuth/pull/176)); the substance was raised in our Slack four-party implementation round (question 4).
- **AAG-F049** Person remapping has no host contract (resolved). The PS now resolves the person from its own record for the upstream token's `aud` and `sub`, must reject when it holds none, and mints the downstream `sub` from the downstream resource token (28e8258 Core, "Person Token Endpoint", "Directed Identifiers Across a Chain"; [PR #162](https://github.com/dickhardt/AAuth/pull/162) item 3).
- **AAG-F051** Downstream credential lifetime is not derived (resolved). Person and auth tokens issued with `upstream_token` MUST NOT expire later than the upstream token, and Call Chaining says downstream access does not outlive it (28e8258 Core, "Person Token Structure", "Auth Token Structure", "Call Chaining"; [PR #176](https://github.com/dickhardt/AAuth/pull/176)).
- **AAG-F052** Mission ownership and propagation conflict in a chain (resolved). The intermediary sends no `mission_s256`; the PS evaluates the upstream token's mission and copies its `mission_s256` into the downstream person token (28e8258 Core, "Person Token Endpoint", "Call Chaining"; [PR #162](https://github.com/dickhardt/AAuth/pull/162) item 3 and [PR #176](https://github.com/dickhardt/AAuth/pull/176)).
- **AAG-F053** An AS cannot literally verify the forwarded upstream token (resolved). Step 1 no longer compares the upstream `cnf.jwk` with the request signer, step 2 has the AS check the issuer against the signing PS, and step 3 uses the `agent_token` parameter at the AS (28e8258 Core, "Upstream Token Verification"; [PR #162](https://github.com/dickhardt/AAuth/pull/162)); open [issue #199](https://github.com/dickhardt/AAuth/issues/199) tracks verifying `agent_token` itself at the AS (AAG-F040).
- **AAG-F054** "Trusted issuer" has no evidence model (resolved). The vague "previously brokered or is authorized to extend" test is replaced by concrete checks backed by the PS's retained presentation records (28e8258 Core, "Upstream Token Verification" step 2, "Revocation Cascade").
- **AAG-F055** No error code covers an invalid upstream token (resolved). `invalid_upstream_token`, `expired_upstream_token` and `revoked_upstream_token` are now registered and assigned (28e8258 Core, "Token Endpoint Error Codes", "Upstream Token Verification"; [PR #162](https://github.com/dickhardt/AAuth/pull/162) item 2).
- **AAG-F056** Person-token retention omits upstream-chain custody (resolved). A person token issued with `upstream_token` is now recorded with the upstream token's `(iss, jti)` until `exp` plus clock skew (28e8258 Core, "Revocation Cascade", "Person Token Endpoint"; [PR #174](https://github.com/dickhardt/AAuth/pull/174)); checking the second presentation remains under AAG-F050.
- **AAG-F057** One-Agent/one-person conflicts with intermediary Resources (resolved). A request carrying `upstream_token` now neither uses nor establishes a binding, and the intermediary's agent token is explicitly not bound to one person (28e8258 Core, "Agent-Person Binding", "Intermediary Agent Identity"; [PR #176](https://github.com/dickhardt/AAuth/pull/176)).
- **AAG-F058** Events uses a subscription identifier as the delivery deduplication key (resolved). Event tokens now carry a per-event `jti`, and the AP and agent deduplicate on `(iss, jti)` (28e8258 Events, "Event Token" > "Structure", "Agent Verification"; [PR #168](https://github.com/dickhardt/AAuth/pull/168) item G1).
- **AAG-F061** Resource and access server could not read the mission expiry they had to enforce (resolved). A resource token's lifetime no longer depends on the mission; the PS caps person and auth tokens at `expires_at`, and an AS's auth token may not outlive the presented person token (28e8258 Core, "Mission Approval", "Person Token Structure", "Auth Token Structure"; [PR #131](https://github.com/dickhardt/AAuth/pull/131), which closed our [issue #121](https://github.com/dickhardt/AAuth/issues/121)).
- **AAG-F065** Mission action uncertain success has no recovery identity (withdrawn). A retry after completion gets 403 `mission_terminated` with reason `completed` (28e8258 Core, "Mission Endpoint Errors", "Mission Status Errors"), and a duplicate update is ordinary POST behaviour ("Mission Update").
- **AAG-F066** Core contradicts itself on update acceptance authority (withdrawn). There is no contradiction: the "Mission" introduction is informative and qualified ("whenever the person must be asked") and is consistent with "Mission Creation", "Mission Update" and "Mission Completion" (28e8258 Core).
- **AAG-F068** Retry-After is required but also has an absence default (withdrawn). `Retry-After` is REQUIRED of the sender (28e8258 Core, "Pending Response"), and the 5-second default is the receiver's fallback when it is missing ("Polling with GET"), an ordinary robustness pattern.
- **AAG-F069** Immediate auth-token issuance has no exact-result recovery identity (withdrawn). Resource tokens deliberately need no replay detection (28e8258 Core, "Resource Token Structure", "Freshness and Replay"), and recovery after an uncertain issuance is a fresh resource token ("Re-authorization"). A repeated issuance is not harmless: each auth token carries its own budget, and a PS that issues *n* concurrent tokens of *X* has authorized up to *nX* (28e8258 Budgets, "Concurrency", "Over-Issuance Through Concurrency"). Keeping that cross-token sum within the person's ceiling is assigned to the issuer (a PS SHOULD size per-token budgets so their sum stays within its standing ceiling), and that duty applies to a repeat as to any concurrent token; it does not require idempotent issuance. Whether a requester can learn the outcome of an issuance whose response was lost is a separate recovery question, left open in the text and not raised here.
- **AAG-F071** The `jkt-jwt` example omitted the required `alg` in both JWKs (resolved). The example now carries `"alg": "ES256"` on the header JWK and `"alg": "Ed25519"` on `cnf.jwk` (69f5ba2 Signature-Key, "JKT JWT Self-Issued Key Delegation (jkt-jwt)"; [signature-key PR #42](https://github.com/dickhardt/signature-key/pull/42)).
- **AAG-F075** Bootstrap examples use AP-internal endpoints after removing discovery (withdrawn). Bootstrap is informational, uses no BCP 14 keywords and labels its paths and member names as illustrative (28e8258 Bootstrap, "What Bootstrapping Is Not", "Conventions and Definitions", "Sub-Agents Under a Hosted AP"), so implementers are not asked to interoperate at those AP-internal endpoints.
- **AAG-F076** R3 rationale contradicted the normative dual-role fetch rule (resolved). [PR #128](https://github.com/dickhardt/AAuth/pull/128) rewrote Why Not RAR: the "restricted to AS-only access" sentence is gone, and the content is said to reach the PS and the AS and never the agent (28e8258 R3, "Design Rationale" > "Why Not RAR").
- **AAG-F081** Per-call parameter projection is not defined by vocabulary (withdrawn). The resource that builds and persists the per-call proposal is the one that verifies the retried call against it (28e8258 R3, "Per-Call Proposals" > "Flow"), so the projection is internal to one resource.
- **AAG-F084** Events leaves subscription-registration parameters outside the signed content digest (withdrawn). The registration body is defined by the resource's own AsyncAPI channel schema (28e8258 Events, "Protected Subscriptions"), only delivery is fixed to cover `content-digest` ("Event Delivery: Resource to AP"), and Core's body-coverage MUST ("Covered Components") names PS, AS and revocation requests, not Events registration.
- **AAG-F085** Events gave two incompatible event-endpoint retention rules (resolved). [PR #207](https://github.com/dickhardt/AAuth/pull/207) changed the overview to say the Resource stores the `eid` and AP issuer and resolves `event_endpoint` at delivery time, matching Verification and Event Delivery (28e8258 Events, "Protocol Overview", "Subscribe Token" > "Verification").
- **AAG-F086** Direct R3 leaves Auth-token-issuer duties assigned only to an AS (resolved). R3 now names the issuer as the AS in four-party and the PS in three-party access, renames AS Processing to Issuer Processing, and has both the AS and the PS fetch `r3_uri` (28e8258 R3, "Issuer Processing", "Auth Token Extensions", "R3 Document Access Restriction"; [PR #204](https://github.com/dickhardt/AAuth/pull/204) item 4).
- **AAG-F087** `AAuth-Budget` examples are not RFC 9651 Dictionaries (resolved). Every `AAuth-Budget` example now separates members with commas (28e8258 Budgets; [PR #128](https://github.com/dickhardt/AAuth/pull/128)).
- **AAG-F088** First-hop denomination selection contradicts numeric narrowing (withdrawn). Read together, the two passages of Budgets "The Narrowing Chain" (28e8258) are consistent: after the first hop the denomination is fixed, because the PS MUST NOT change `unit` or `decimals`.
- **AAG-F089** Omitted PS-to-AS Budget ceiling is indistinguishable from extension non-participation (resolved). Our [issue #122](https://github.com/dickhardt/AAuth/issues/122) was closed 2026-09-06 by [PR #141](https://github.com/dickhardt/AAuth/pull/141): when the PS omits `budget` the AS MUST NOT issue a `budget` claim, omission "MUST NOT be read as a grant", and the PS MUST check the AS token's budget against what it sent (28e8258 Budgets, "PS-to-AS Token Request Extensions", "Auth Token Extensions").
- **AAG-F090** The exhausted example charges a refused request (resolved). Budget Exhaustion now says a refusal carries no `cost`, and every exhausted example reads `remaining=0, unit="USD", decimals=6` with no `cost` (28e8258 Budgets, "Budget Exhaustion", "The `reason` Parameter", "Sending Rules"; no fixing PR was identified).
- **AAG-F091** Core names retained lineage but not its Auth-token lookup binding (resolved). `presented_jti` is now the `jti` of the token the request carried, which the agent passes to the PS as `presented_token`, so lineage is bound on the wire with no retained mapping (28e8258 Core, "Resource Token Structure", "Resource Token Verification"; [issue #152](https://github.com/dickhardt/AAuth/issues/152), [PR #153](https://github.com/dickhardt/AAuth/pull/153); Budgets aligned in [PR #206](https://github.com/dickhardt/AAuth/pull/206)).
- **AAG-F093** Clarification timeout has no recipient reference instant (withdrawn). `timeout` is a relative number of seconds, like `Retry-After` (28e8258 Core, "Pending Response"), so counting from receipt is the natural reading and differs from the sender's clock only by network latency.
- **AAG-F096** Permission denial has two terminal wire representations (withdrawn). Both representations are defined, one for the Permission 200 forms and one for deferred terminal states (28e8258 Core, "Permission Response", "Polling Error Codes"), and both mean do not proceed.
- **AAG-F098** An uncertain initial Permission submission cannot be recovered (withdrawn). The only effect of a lost response is a duplicate permission prompt to the person; no grant is issued twice and no state is damaged.
- **AAG-F100** "Fire-and-forget" does not define the Audit response behavior (withdrawn). The SHOULD NOT in 28e8258 Core "Audit Response" constrains only whether the agent waits; the bytes on the wire are identical either way.
- **AAG-F101** An uncertain Interaction question submission cannot be recovered (withdrawn). As with AAG-F098, the only effect of a lost response is a repeated question to the person; nothing is granted twice.
- **AAG-F102** Resource-hosted relay resolution has no terminal success shape (withdrawn). Completion is signalled by the resource's own pending URL, which the agent keeps polling after the relay resolves (28e8258 Core, "Interaction Response"), and the `interacting` state is defined ("Pending Response").
- **AAG-F103** Third-party login requires person context it has not obtained (resolved). [issue #155](https://github.com/dickhardt/AAuth/issues/155) and [PR #157](https://github.com/dickhardt/AAuth/pull/157) deleted Third-Party Login and `login_endpoint`, so the flow this finding questioned no longer exists (28e8258 Core).
- **AAG-H001** Draft-05 through draft-08 implementation feedback (resolved). The feedback was incorporated: 28e8258 Core "Document History" records "Interoperability clarifications from Joshua Gay's feedback" for -06 and "Added Joshua Gay to Acknowledgments" for -07, and "Acknowledgments" lists Joshua Gay.
- **AAG-H002** Callback authority and issuer-role discovery (resolved). The editors answered it in the Slack four-party implementation round (items 2 and 3), and 28e8258 Core reflects the answer: the callback URL has no security role ("Design Rationale" > "In Brief"; "Why No Authorization Code"), and issuer roles are distinguished by the well-known document named in `dwk` ("Auth Token Verification").
