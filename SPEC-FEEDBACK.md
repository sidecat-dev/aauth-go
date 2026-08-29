# AAuth specification feedback journal

This journal tracks evidence-backed questions and feedback for the AAuth
authors. Its purpose is to improve shared specification and interoperability
work. It is not a scorecard for the specification or another implementation.

## Status vocabulary

- **submitted / incorporated** — the feedback reached the authors and the
  current editor source carries the disposition.
- **submitted / answered** — the authors answered directly; the answer may not
  have a public issue URL.
- **submitted / still open** — the feedback reached the authors and the current
  source still leaves the question open.
- **new / evidence pending** — current source inspection supports a question,
  but the executable test or wire capture needed before submission does not yet
  exist.
- **ready / unsubmitted** — current executable evidence supports a question
  that has not been sent.
- **withdrawn** — later source or implementation evidence resolved or disproved
  the concern before submission.

## Already submitted

### AAG-H001 — Draft-05 through draft-08 implementation feedback

**Status:** submitted / incorporated

The earlier implementation supplied feedback on mission-reference dereference
and `approver`/`s256` syntax, agent keying material, `AAuth-Requirement`
parameters, `AAuth-Access` token grammar, capability forward compatibility,
same-`kid` refresh, egress admission, auth-token verification ordering,
approval-endpoint authentication, freshness and replay, interaction codes,
callback errors, and call-chaining identity.

The current core source records these contributions in its changelog and names
Joshua Gay in the acknowledgments. Several individual discussions were direct
with the authors; their public thread URLs were not retained in this repository.
The source itself is therefore the durable disposition evidence:

- AAuth Protocol, current editor source, changelog entries for revisions 6
  through 9;
- `Interaction Codes`, `Interaction Callback Errors`, `Call Chaining`,
  `Auth Token Verification`, and the security considerations;
- AAuth issue 47 for the `act.agent` direction correction.

This history must not be re-filed as new feedback merely because a new
implementation independently encounters the same issue.

### AAG-H002 — Callback authority and issuer-role discovery

**Status:** submitted / answered

Two questions received direct author answers during the June 2026 feedback
cycle:

- the interaction callback is a user-experience return, not authority to record
  approval or denial;
- an auth token's `dwk` selects the issuer-role metadata document, while issuer
  trust remains an independent verifier decision.

The historical journal recorded those answers and the corresponding local
changes. No durable public discussion URL was retained. Current implementations
must follow the current editor text rather than treat this summary as normative.

### AAG-H003 — Recommended `justification` sections

**Status:** submitted / still open

The earlier feedback proposed stakes-proportional Markdown sections for
purpose, scope and magnitude, effect and reversibility, and optional timing or
alternatives. The current `PS Token Endpoint` text still contains `TODO: Define
recommended sections` under `justification`.

Before re-raising it, prepare a short current-source note that links the prior
delivery context and supplies examples from an executing consent interface.
Do not submit the old text as if it were a new observation.

## Earlier candidates reconciled against the current source

The July 2026 implementation pass drafted thirteen candidates but explicitly
marked them unsubmitted. The current editor family now resolves or removes many
of them:

| Earlier candidate | Current disposition |
| --- | --- |
| golden vectors, unpadded mission hashes, exact mission bytes, and mission-header parsing | previously delivered or superseded by the current person-token mission envelope |
| PS and AS R3 retrieval contradiction | withdrawn: current `R3 Endpoint Access Control` admits the exact PS and AS roles |
| R3 token `typ` mismatch | withdrawn: current R3 uses `aa-resource+jwt` and `aa-auth+jwt` |
| R3 grant not bounded by the requested operations | reopened as AAG-F014: current composition requires coverage but does not bind the AS to only the requested set |
| `AAuth-Mission` Structured Fields question | withdrawn: the current protocol removed the header |
| auth-token agent self-comparison | withdrawn: the current resource-facing topology uses person identity and no agent claim |
| `act.agent` direction and chaining prose | incorporated: current source and issue 47 name the immediate upstream delegator |

The unresolved candidates below are re-stated against the current source. They
remain evidence-pending until their current tests or wire captures exist; after
that evidence is reviewed, they may become ready and unsubmitted.

## Ready, unsubmitted

### AAG-F014 — The AS cannot distinguish requested operations from a broader R3 document

**Status:** ready / unsubmitted

**Source:** current R3 `Authorization Endpoint Extensions / Request`,
`Operations Spanning Multiple Definitions`, `R3 Processing / AS Processing`,
and `Auth Token Extensions` at AAuth `a99d353cf18aee81d0c5445bac070164fb3b8bc5`.

**Question:** Must the R3 document selected or composed for an authorization
request contain exactly the operations in `r3_operations`, or should the
original requested set be carried separately and integrity-bound for AS policy?
If a document may contain additional operations, what prevents the AS from
placing an unrequested document member in `r3_granted`?

**Why this is ambiguous:** The request gives `r3_operations` to the resource.
The resource token sent onward carries only `r3_uri` and `r3_s256`. Composition
must cover the requested operations, but the text does not say that the
document's `operations` set is equal to them. The AS therefore receives the
document but not an independent representation of what the agent requested.

**Observed implementation effect:** The direct reference profile must require
the selected document's operation set to equal the agent request. Without that
rule, a conforming AS policy can grant a broader document member. A cooperative
agent can reject the excess grant, but the auth token remains usable by a caller
that does not perform that client-side check.

**Evidence:**

- `reference/r3_direct_test.go:TestR3DocumentSelectionIsExactlyTheAgentRequest`
- `r3/token_external_test.go:TestR3AuthorizationGrantPartitionsTheExactAgentRequest`
- `r3_direct_journey_test.go:TestCurrentFourPartyR3JourneySurvivesReconstruction`

**Suggested disposition:** State that a selected/composed initial R3 document
contains exactly the requested operation set, or add an integrity-bound
requested-operation set that the AS must use to bound `r3_granted` and
`r3_per_call`.

### AAG-F015 — A per-call auth token does not identify the resource-token record that supplies `presented_jti`

**Status:** ready / unsubmitted

**Source:** current Protocol `Resource Token Structure`, `Resource Token
Verification`, and `Why presented_jti exists`; current R3 `Per-Call Proposals /
Flow` at AAuth `a99d353cf18aee81d0c5445bac070164fb3b8bc5`.

**Question:** How must a resource select the earlier person-token record when a
per-call request presents an auth token? The new resource token must carry the
earlier `presented_jti`, but the auth token carries neither that claim nor the
identifier of the resource token from which it was issued.

**Why this is ambiguous:** A resource can retain several active resource tokens
with the same access server, person server, subject, proof key, scope, mission,
tenant, account, and R3 document. Those are all the relevant values available
from the later auth token. Claim equality therefore need not identify one
person-token JTI.

**Observed implementation effect:** The reference resource retains each exact
resource token that supplies later authorization context and resolves the latest
active generation no later than the auth token's trusted issuance instant. It
converges only repeated issuance for the same person-token JTI, requested scope,
and companion variant; different bindings in the same otherwise
indistinguishable generation make later resolution fail closed. The same gap is
observable in both the R3 per-call challenge and the Budget reauthorization
challenge.
This is deterministic, but it is an implementation choice rather than a rule
stated by the draft.

**Evidence:**

- `reference/resource_token_lineage_store_test.go:TestFileResourceTokenLineageStoreRecoversOneExactAuthorizationLineage`
- `r3_direct_journey_test.go:TestCurrentFourPartyR3JourneySurvivesReconstruction`
- `budget_journey_test.go:TestCurrentFourPartyBudgetJourneyNarrowsEveryIssuanceBoundary`

**Suggested disposition:** Bind the auth token to the resource-token JTI whose
authorization it represents, or define the exact resource-side lineage rule
that recovers `presented_jti` during step-up and per-call challenges.

## New, evidence pending

### AAG-F001 — Interoperability Surface 3 and metadata discovery disagree

**Status:** new / evidence pending

**Source:** current interoperability profile, `Surface 3`; current AAuth
Protocol and Signature-Key metadata discovery sections.

**Question:** Is `/.well-known/aauth-resource.json` itself intended to contain
the signing keys, as Surface 3 says, or is it metadata whose `jwks_uri` points
to a separate JWKS, as the main protocol and Signature-Key flow require?

**Evidence needed before submission:** one black-box verifier test showing that
the same resource cannot satisfy both literal discovery procedures with one
document shape.

**Consequence:** two conforming-looking implementations can perform different
numbers of fetches and parse incompatible documents at the same URL.

### AAG-F002 — The AS request example uses an undefined Signature-Key parameter

**Status:** new / evidence pending

**Source:** current AAuth Protocol, `AS Token Endpoint`, example request;
Signature-Key, `jwks_uri` scheme.

**Question:** Should the example use the scheme's `id`, `dwk`, and `kid`
parameters instead of a `jwks_uri` header parameter?

**Evidence needed before submission:** a strict parser test demonstrating that
the current example cannot be resolved under the current Signature-Key grammar.

**Consequence:** an implementer copying the example produces a request that a
strict Signature-Key implementation cannot authenticate.

### AAG-F003 — Audit delivery has no stable retry identity

**Status:** new / evidence pending

**Source:** current AAuth Protocol, `Audit Endpoint`, `Freshness and Replay`.

**Question:** After the PS commits an audit entry but the client loses the
`201 Created`, how does the agent retry without either replay refusal or a
second indistinguishable audit record?

**Evidence needed before submission:** a transport-loss test that commits the
record, drops the response, and shows the absence of a stable request identity.

**Provisional alternative:** a client-generated audit request identifier with
same-body duplicate acknowledgment and different-body conflict.

**Consequence:** the current wire shape cannot distinguish a retry from a
legitimate repeated action.

### AAG-F004 — A lost terminal deferred response may be unrecoverable

**Status:** new / evidence pending

**Source:** current AAuth Protocol, `Deferred Responses` and pending URL
security; current R3, per-call retained-result language.

**Question:** Does the general deferred-response contract require bounded
repeat retrieval of a committed terminal result, as current R3 does for a
per-call effect, or may a lost first terminal response leave the caller unable
to learn the outcome?

**Evidence needed before submission:** one current-profile test that commits a
terminal result, loses the response, and observes the next legal poll.

**Consequence:** a caller may repeat a consequence or remain permanently
uncertain after an ordinary transport failure.

### AAG-F005 — R3 same-URI updates conflict with permanent verification

**Status:** new / evidence pending

**Source:** current R3, `Content Addressing`, `AS Processing`, and auth-token
audit-provenance text.

**Question:** If a resource serves new bytes at the same `r3_uri`, how can a
fresh verifier later retrieve the old bytes named by an old `r3_s256` after an
AS cache entry is gone?

**Evidence needed before submission:** a cache-eviction or fresh-verifier test
using an old token after same-URI document replacement.

**Provisional alternative:** require immutable content-addressed URIs, or
define historical retrieval by hash.

**Consequence:** an old token may name exact semantics by hash while providing
no way to obtain the bytes, contradicting the permanent-verification claim.

### AAG-F006 — R3 example hashes are not executable vectors

**Status:** new / evidence pending

**Source:** current R3 resource-token and auth-token examples.

**Question:** Should the 40-character illustrative `r3_s256` values be replaced
with 43-character unpadded base64url SHA-256 values over exact example bytes, or
explicitly labeled as shortened placeholders at each use site?

**Evidence needed before submission:** an example-validation test that checks
decoded hash length and, when exact document bytes are supplied, digest parity.

**Consequence:** readers cannot copy the examples into a strict parser or use
them as cross-implementation fixtures.

### AAG-F007 — Mission completion still appears in the interaction list

**Status:** new / evidence pending

**Source:** current AAuth Protocol, the introductory `Interaction Endpoint`
summary, the normative `Interaction Endpoint` section, and the current document
history entry that moves mission completion to the mission endpoint.

**Question:** Should the introductory endpoint summary remove mission
completion so that it agrees with the normative interaction section and the
documented completion move?

**Evidence needed before submission:** a routing test or endpoint matrix that
shows the two literal readings and identifies which endpoint a client would
call for the same completion intent.

**Consequence:** a client following the summary can send a terminal mission
transition to an endpoint whose normative operation set no longer accepts it.

### AAG-F008 — Clarification still requires an agent claim absent from current resource tokens

**Status:** ready / unsubmitted

**Source:** current AAuth Protocol, `Clarification`, `Resource Token Claims`,
and the current document history entry that removes the agent identifier from
resource-facing tokens.

**Question:** When a clarification response produces an updated resource
token, which retained binding should remain stable in place of the text's
requirement that the token contain the same `agent`?

**Executable and source evidence:** the current four-party implementation
constructs and verifies resource tokens without an `agent` claim, matching the
current `Resource Token Structure`. A literal implementation of the updated
request rule can therefore only compare two absent values; it cannot enforce
the anti-substitution check the sentence appears intended to express.

**Provisional alternative:** bind the update to the retained person-token
reference and the current `ps`, directed `sub`, `presented_jti`, resource, and
mission digest values.

**Consequence:** implementations must otherwise either invent a removed claim
or omit an intended anti-substitution check during clarification.

**Submission placement:** add the missing site to open AAuth issue 104, which
is already collecting lingering agent-token references. Keep the editorial
correction in that comment; treat any proposal to add new stable `ps` or `sub`
bindings as a separate normative question if implementation evidence later
shows it is needed.

### AAG-F009 — Person-token policy denial has no registered error

**Status:** ready / unsubmitted

**Source:** current AAuth Protocol, `Person Token Endpoint` and `Token Endpoint
Error Codes`.

**Question:** Which error should a PS return when the AgentToken, signed request,
resource, and mission are valid, but person-binding policy declines to issue a
person token?

**Executable evidence:**

- `current_person_token_journey_test.go:TestCurrentFourPartyPersonTokenJourneySurvivesPersonServerRestart`
  distinguishes missing or wrong `ps` as registered `400 invalid_agent_token`
  from a valid policy refusal.

**Provisional choice:** This implementation uses the explicit extension
`403 person_token_denied`. `user_unreachable` describes a different condition,
and `invalid_request` would misclassify valid input.

**Consequence:** implementations otherwise invent different codes or overload a
registered code, making terminal denial handling non-interoperable.

### AAG-F010 — Four-party resource identity should be namespaced by the PS

**Status:** new / evidence pending

**Source:** current AAuth Protocol, `Person Token`, `Resource Token Structure`,
`Auth Token Structure`, and `Auth Token Verification`.

**Question:** In four-party mode, should a resource match or establish the
directed person as `(ps, sub)`, while separately trusting the authorization
issuer as `(iss, dwk)`? The verification text currently says `(iss, sub)`, even
though `iss` is the AS and the directed subject originated in the PS namespace.

**Evidence needed before submission:** a resource identity adapter test in which
one AS presents the same `sub` under two different admitted person servers and
the records remain distinct.

**Provisional choice:** Pass verified `ps` and `sub` to host policy, but do not
claim identity matching or establishment until that adapter and test exist.

**Consequence:** keying the person by AS issuer can merge unrelated PS namespaces
or change identity when the same PS moves between access servers.

### AAG-F011 — The closed person-token endpoint resolution is absent from the current editor source

**Status:** ready / unsubmitted

**Source:** current AAuth Protocol at
`a99d353cf18aee81d0c5445bac070164fb3b8bc5`, `Person Token Endpoint`;
AAuth issues 88 and 89 and their author comments of August 11, 2026.

**Question:** Were issues 88 and 89 closed before their shared resolution was
applied to the editor source, or was the resolution later withdrawn?

**Evidence:** both issue threads record the document author's resolution that
the person-token endpoint accepts the auth-token endpoint's request parameters,
except `resource_token`. The current repository HEAD is still `a99d353` and its
person-token endpoint still lists only `resource`, `mission_s256`,
`subagent_token`, and `upstream_token`. It therefore still lacks the eight
resolved parameters: `justification`, `login_hint`, `tenant`, `domain_hint`,
`prompt`, `platform`, `device`, and `capabilities`.

**Consequence:** the two closed defects remain in the normative text. A literal
implementation still cannot select tenant context or tell the PS that it can
complete deferred interaction on first person-token issuance.

**Submission placement:** comment once on issue 88 and cross-link issue 89.
This is follow-through on the existing shared resolution, not a new issue.

### AAG-F012 — A lost initial deferred response has no recovery identity

**Status:** new / evidence pending

**Source:** current AAuth Protocol, `Deferred Responses`, `Initial Request`,
`Polling with GET`, and pending URL security.

**Question:** When the server has accepted and retained a deferred operation but
the caller loses the initial `202 Accepted` response and its random pending URL,
which proof-covered request identity lets a fresh-proof retry recover that exact
operation without creating a duplicate or orphan?

**Evidence needed before submission:** an end-to-end transport-loss test that
commits the initial deferred operation, drops the `202` response, reconstructs
the caller, and demonstrates that the current request fields cannot identify
the retained operation. This is distinct from terminal-response recovery after
the caller already owns the pending URL.

**Provisional clean-current design:** require a client-generated
`AAuth-Request-ID` covered by the request proof and retained before the first
send. A retry with a fresh proof and the same identifier recovers the exact
retained operation; reuse of that identifier for different authenticated
semantics returns `409 Conflict`.

**Implementation disposition:** accepted as the next interaction and recovery
slice, outside the current authorization-state repair. The extension is not yet
implemented or submitted upstream.

**Consequence:** without a stable recovery identity, a caller that loses the
initial `202` cannot distinguish recovery from a new operation, while an exact
wire retransmission conflicts with proof replay protection.

### AAG-F013 — Restored deferred state can lose the verified request authority

**Status:** ready / unsubmitted

**Source:** current AAuth Protocol, `Covered Components`, `Verification`,
`Deferred Responses`, and `Non-Repudiation and Audit After Key Rotation`.

**Question:** When a PS or AS retains a pending authorization, should restart
recovery be required to re-establish every policy- and continuation-bearing
field from the verified signed request or from an authenticated receipt that
binds the same fields?

**Executable evidence:**

- `reference/authorization_state_reconciliation_test.go:TestPersonAndAccessServersRejectSemanticallyCorruptCanonicalStateAfterReopen`
  mutates the PS's signed `justification`, and separately replaces both the
  AS polling key and its self-consistent thumbprint. Without retained request
  evidence, those canonical mutations survive restart even though neither
  value was authorized by the original signer.
- The current repair retains a bounded exact request body, covered headers,
  signature, exact verification key, and original verification instant. It
  re-verifies offline without network discovery, current policy, or current
  wall-clock authorization.

**Source gap:** request-time signature verification is normative. Archiving
the verified artifacts is only a `SHOULD`, is framed as durable audit guidance,
and is not connected to the semantics of restored pending state.

**Provisional choice:** a durable deferred record must contain either the exact
verified request evidence or a locally authenticated receipt binding every
authority-bearing projection. Recovery must validate that evidence before the
record becomes callable.

**Consequence:** otherwise an implementation can authenticate the live request
correctly but transfer policy input or polling authority through a rewritten
canonical state record after restart.

**Submission placement:** check the current issue tracker for an existing
deferred-recovery or audit-evidence issue. If none covers restored authority,
open a focused new issue rather than attaching it to the lost-initial-response
question in AAG-F012.

## Adding and submitting an item

1. Pin the exact source commit, document, section, and shortest relevant
   excerpt or faithful paraphrase.
2. Add a reproducible wire example, failing test, or interoperability capture.
3. Reconcile the observation against the submitted history above.
4. Ask one neutral question and name the provisional choice plus a plausible
   alternative.
5. Explain the security or interoperability consequence.
6. Submit under the responsible human maintainer's identity and link the
   upstream issue or discussion here.
7. Record the authors' answer and update implementation and coverage separately.

If later evidence disproves a concern, mark it withdrawn. Do not erase it or
quietly turn it into implementation policy.
