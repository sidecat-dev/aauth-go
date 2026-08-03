# EPIC-001 — R3 conditional per-call authorization

**Summary:** Authorize one conditional operation only after its concrete call
parameters have been proposed, approved, and verified on retry.
**Stories:** STORY-0001 through STORY-0005
**Primary source:** `draft-hardt-aauth-r3-01`
**Accepted scope:** AAuth complete-spec-family roadmap M4
**Status:** 5/5 done

## STORY-0001

**Epic:** EPIC-001
**Title:** Issue a conditional initial grant

**As an** access-server deployment
**I want** to distinguish operations granted outright from operations approved
only in principle
**So that** parameter-sensitive calls cannot execute under the initial token

**Acceptance criteria:**

- AC-1: A verified R3 document may produce disjoint `r3_granted` and
  `r3_conditional` subsets in one auth token. The union cannot exceed the
  document, and the agent refuses any part of the union outside its retained
  request. · impact:`journey` · seam:`e2e` · scenario:`JOURNEY-0001`
- AC-2: An operation present in neither set is refused. · impact:`local` ·
  seam:`integration` · scenario:`SCENARIO-0004`
- AC-3: The initial auth token retains the exact verified `r3_uri` and
  `r3_s256` pair and remains independently bound to resource, agent, key,
  mission, scope, issuer, and lifetime. · impact:`journey` · seam:`e2e` ·
  scenario:`JOURNEY-0001`

**Status:** done:ITER-0000

**Sources:** R3 lines 464-530, 532-542, 616-618

## STORY-0002

**Epic:** EPIC-001
**Title:** Challenge without executing and retain one exact proposal

**As a** protected resource
**I want** a conditional call to produce a content-addressed per-call proposal
before any operation runs
**So that** approval refers to the concrete pending call rather than a class of
future calls

**Acceptance criteria:**

- AC-1: A call matching `r3_conditional` does not invoke the protected
  operation. It returns `AAuth-Requirement` with an auth-token requirement and
  a signed resource token. · impact:`journey` · seam:`e2e` ·
  scenario:`JOURNEY-0001`
- AC-2: The proposal is a valid R3 document with exactly one operation and a
  required `parameters` object; optional proposal display may include
  `detail`. · impact:`local` · seam:`unit` · scenario:`SCENARIO-0001`
- AC-3: The resource persists the proposal's exact serialized bytes before
  exposing its URI/hash. The token contains only `r3_uri`/`r3_s256`, never the
  parameters. · impact:`cross-surface` · seam:`integration` ·
  scenario:`SCENARIO-0002`
- AC-4: A proposal that does not describe the mapped conditional operation or
  cannot be retained fails closed without a challenge token. ·
  impact:`local` · seam:`integration` · scenario:`SCENARIO-0003`

**Status:** done:ITER-0000

**Sources:** R3 lines 530-538, 544-562, 580-585

## STORY-0003

**Epic:** EPIC-001
**Title:** Approve the exact proposal and audit before token release

**As an** access server
**I want** to authenticate, fetch, hash, parse, evaluate, and audit the proposal
**So that** the per-call token names the exact reviewed authorization semantics

**Acceptance criteria:**

- AC-1: The AS-only signed, admitted, same-resource, no-redirect, bounded fetch
  path verifies the proposal's exact hash before policy receives it. ·
  impact:`journey` · seam:`e2e` · scenario:`JOURNEY-0001`
- AC-2: A proposal decision must directly grant its one operation; another
  conditional result, a half claim, an absent operation, or an operation beyond
  the proposal fails closed. · impact:`local` · seam:`integration` ·
  scenario:`SCENARIO-0005`
- AC-3: The per-call auth token echoes the proposal URI/hash and lists the
  approved operation in `r3_granted`. A successful issuance audit is recorded
  before the token is released. · impact:`journey` · seam:`e2e` ·
  scenario:`JOURNEY-0001`

**Status:** done:ITER-0000

**Sources:** R3 lines 448-461, 580-585, 604-610

## STORY-0004

**Epic:** EPIC-001
**Title:** Bind the enforced retry to every approved parameter

**As a** protected resource
**I want** to recover the approved proposal and compare it with the actual
retry
**So that** a token for one concrete call cannot authorize a different call

**Acceptance criteria:**

- AC-1: The resource loads the exact proposal by the per-call token's
  `r3_s256`, validates the single mapped operation, and compares every actual
  parameter with the approved `parameters` object before execution. ·
  impact:`journey` · seam:`e2e` · scenario:`JOURNEY-0001`
- AC-2: Inline parameters compare as JSON values. Digest parameters compare
  `BASE64URL(SHA-256(presented-value-bytes))` with the stored `s256`; optional
  excerpt and media type are not substitutes for the digest. · impact:`local` ·
  seam:`integration` · scenario:`SCENARIO-0006`
- AC-3: Added, removed, or changed parameters, a changed HTTP method or
  recipient, changed body bytes, another operation, or another proposal
  URI/hash is refused before operation execution. · impact:`journey` · seam:`e2e` ·
  scenario:`SCENARIO-0006`

**Status:** done:ITER-0000

**Sources:** R3 lines 548-562, 580-590

## STORY-0005

**Epic:** EPIC-001
**Title:** Preserve restart and replay refusal boundaries

**As a** resource operator
**I want** conditional authorization to remain safe across process replacement
and repeated requests
**So that** recovery does not turn an exact per-call approval into ambient
authority

**Acceptance criteria:**

- AC-1: Reconstructing the resource after the challenge can load the retained
  exact proposal and complete only the matching retry. ·
  impact:`cross-surface` · seam:`integration` · scenario:`SCENARIO-0007`
- AC-2: Reusing the same signed request proof is refused and cannot invoke the
  operation again. · impact:`local` · seam:`integration` ·
  scenario:`SCENARIO-0008`
- AC-3: Losing, corrupting, expiring, or substituting proposal custody fails
  closed. · impact:`cross-surface` · seam:`integration` ·
  scenario:`SCENARIO-0007`
- AC-4: For one per-call auth-token JTI, at most one freshly signed matching
  request crosses the durable operation-admission boundary, including across
  resource reconstruction and concurrent attempts. · impact:`cross-surface` ·
  seam:`integration` · scenario:`SCENARIO-0008`

**Sources:** R3 lines 384-393, 580-585, 594-618
**Profile guarantee:** AC-4 is an AAuth-Go one-shot rule; the draft does not
define token consumption or exactly-once consequence delivery.

**Status:** done:ITER-0002

## Preserved source boundary

R3 requires the PS to fetch proposals for consent while separately requiring
the resource to accept only signatures from its one AS. M4 retains the
accepted AS-only endpoint security rule. It does not implement PS wire fetch,
invent AS-to-PS transfer, or treat a PS as the AS. The deployment policy can
receive the AS-verified proposal; PS display retrieval remains unsupported
pending specification clarification.

## AAuth-Go profile decisions

The draft leaves several enforcement details undefined. This M4 profile makes
the following implementation choices without presenting them as R3
requirements:

- The selected MCP request-mapping boundary supplies both a machine-readable
  JSON value and the exact presented bytes used for a digest parameter. No
  cross-vocabulary or JSON canonicalization rule is inferred.
- Proposal custody is restart-safe and retained long enough for the maximum
  auth-token lifetime; missing, expired, corrupt, or substituted custody fails
  closed.
- Replay refusal has two distinct layers: the existing HTTP Message Signature
  rule rejects the same signed proof, and the AAuth-Go profile durably consumes
  a per-call token JTI immediately before operation admission so a fresh proof
  cannot reuse it. This is at-most-once admission, not exactly-once external
  effect: a crash after consumption can lose the opportunity to perform the
  consequence.
- Identical operation and parameter proposals may share a content hash, as the
  draft's content-addressing rule permits. The implementation does not invent
  an invocation identifier inside the proposal.
