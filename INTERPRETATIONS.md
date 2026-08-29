# AAuth Go implementation interpretations

This register explains choices that affect observable protocol behavior. It is
not a substitute for the AAuth specifications. The exact author editor sources
and revisions below are authoritative; this file records how this Go
implementation applies them where a choice, transition, or ambiguity matters.

Current source family:

| Source | Author revision |
| --- | --- |
| AAuth Protocol, R3, Events, Bootstrap, Budgets, interoperability profile | `dickhardt/AAuth@a99d353cf18aee81d0c5445bac070164fb3b8bc5` |
| HTTP Signature Keys | `dickhardt/signature-key@0ff751b571e7fe51336bcc1e526954a202317cc0` |

Each adopted interpretation must name the exact source section, the selected
behavior, a materially plausible alternative, the reason for the choice, and
executable evidence. An unresolved question stays open; it does not silently
become implementation policy or a conformance claim.

## AAG-I001 — Author editor sources are the implementation authority

**Status:** adopted

**Source:** the complete current source family listed above; exact bytes and
SHA-256 digests are in `internal/sourcecoverage/source-coverage.json`.

**Question:** Which text controls when an editor source and a rendered or
published snapshot differ?

**Chosen behavior:** Pin and implement the authors' exact editor-source bytes at
one named commit per repository. Retain rendered documents only as publication
artifacts, never as stronger implementation authority.

**Alternative considered:** Implement the latest IETF-hosted snapshot until a
new numbered draft is published. That gives a stable citation, but it omits
accepted editor changes and can make interoperability work knowingly stale.

**Why:** The editor repositories contain the protocol family as it is being
developed together. One exact commit and byte digest make that moving authority
reviewable and reproducible.

**Evidence:**

- `internal/sourcecoverage/sourcecoverage_test.go:TestCoveragePinsOneCompleteCurrentEditorFamily`
- `go run ./cmd/aauth-reference verify coverage`

**Current-product effect:** A source refresh may deliberately expose
implemented behavior as obsolete or unclaimed. A green negative-vector test
against an old wire shape is not relabeled as current conformance.

## AAG-I002 — Emit and accept fully specified `Ed25519`, not `EdDSA`

**Status:** adopted

**Source:** AAuth Protocol, `Signature Algorithms`; HTTP Signature Keys,
`Algorithm Determination` and `Unsupported Algorithm`.

**Question:** Should Ed25519 keys and JWTs accept the polymorphic JOSE name
`EdDSA` used by retained historical peers?

**Chosen behavior:** Emit `alg: Ed25519`. Reject missing algorithms,
polymorphic `EdDSA`, `none`, symmetric algorithms, and structurally invalid
Ed25519 keys on the applicable current paths. Return the specified negotiable
unsupported-algorithm response where the HTTP protocol permits it.

**Alternative considered:** Accept `EdDSA` while emitting `Ed25519`. That would
admit historical peer input, but it weakens the current algorithm-determination
rule and makes the accepted cryptographic operation depend on key shape outside
the declared algorithm.

**Why:** A fully specified algorithm makes the cryptographic operation explicit
and follows both current author sources.

**Evidence:**

- `draft11_wire_test.go:TestDraft11Ed25519WireJourney`
- `draft08_discovery_test.go:TestDraft08SelectedUnsupportedJWKSAlgorithmUsesNegotiableEnvelope`
- `elixir_interop_test.go:TestHistoricalElixirFixturesUseUnsupportedPolymorphicEdDSA`

**Current-product effect:** Historical `EdDSA` fixtures remain retained only as
negative evidence. They are not current interoperability vectors.

## AAG-I003 — Only the current person-token topology is supported

**Status:** adopted current boundary

**Source:** AAuth Protocol, `Person Token`, `Resource Access and Resource
Tokens`, `Person Server`, `Auth Tokens`, and `Sub-Agents`; interoperability
profile surfaces 1 through 5.

**Question:** Can an agent/resource/auth-token journey that omits the current
person-token claims remain as an alternate runtime path because several
endpoints and JWT type names are unchanged?

**Chosen behavior:** No. Resource and auth tokens structurally require the
current person topology. The implementation issues and retains an
`aa-person+jwt`, derives `ps`, `sub`, `presented_jti`, and `mission_s256` into
the resource token, resolves the retained person-token record at the PS, and
issues and presents only the current auth-token shape.

**Alternative considered:** Keep the old journey marked exercised and describe
the new claims as a later enhancement. That would hide a security-relevant
topology change: the retained `presented_jti` lookup is what detects subject or
mission substitution, and current resource-facing tokens no longer identify
the agent.

**Why:** Similar endpoint names do not make the authorization evidence
equivalent. The current person-token chain changes what each party may assert
and what the PS must retain and compare.

**Evidence:**

- `internal/sourcecoverage/sourcecoverage_test.go:TestCurrentClaimsUseCurrentEvidenceOnly`
- `token_identity_internal_test.go:TestCurrentResourceAndAuthTokensRequirePersonTopology`
- `current_person_token_journey_test.go:TestCurrentFourPartyPersonTokenJourneySurvivesPersonServerRestart`

**Current-product effect:** Obsolete issuance methods and conditional runtime
branches are removed. Old wire forms may remain only as raw rejection vectors.

## AAG-I004 — Current R3 proposal retrieval must admit both the PS and AS

**Status:** adopted source correction; implementation pending

**Source:** R3, `Per-Call Proposals`, `R3 Document`, and `R3 Processing` at the
current AAuth revision above.

**Question:** May a resource expose an exact proposal only to its access server,
leaving the person server unable to retrieve it?

**Chosen behavior:** No current-conformance claim is made until resource policy
admits the current PS and AS retrieval roles and the rebuilt person-token flow
binds the resulting proposal and token evidence.

**Alternative considered:** Preserve the earlier AS-only endpoint rule because
an older draft combined PS display language with AS-only retrieval text. The
current source resolves that conflict by granting both roles access.

**Why:** Continuing the old restriction would prevent the PS from evaluating
the exact proposal it is asked to authorize and would contradict the current
retrieval contract.

**Evidence:**

- `internal/sourcecoverage/sourcecoverage_test.go:TestCurrentClaimsUseCurrentEvidenceOnly`
- current R3 sections remain unclaimed in `SOURCE-COVERAGE.md`

**Current-product effect:** Current R3 remains unclaimed, and no callable R3
authorization path remains. Neutral current-source document values and digests
remain for Events. A future implementation must add PS-and-AS retrieval,
per-call proposal custody, grant enforcement, and audit-atomic issuance as one
complete path before any R3 conformance claim.

## AAG-I005 — Person-token policy denial is an explicit extension

**Status:** adopted extension pending editor disposition

**Source:** AAuth Protocol, `Person Token Endpoint` and `Token Endpoint Error
Codes` at the current AAuth revision above.

**Question:** Which wire error represents a valid person-token request that a
deployment refuses for person-binding policy?

**Chosen behavior:** Return `403` with `error: person_token_denied` only after
the AgentToken, request proof, resource, and optional mission are valid. Missing,
expired, or mismatched tokens continue to use the registered `400` errors.

**Alternative considered:** Use `user_unreachable`. That code says the PS has no
way to reach the user, which is different from a reached policy decision. Using
`invalid_request` would incorrectly describe valid protocol input as malformed.

**Why:** The current registry does not name policy denial. An explicit extension
preserves the distinction without silently assigning another code new meaning.

**Evidence:**

- `current_person_token_journey_test.go:TestCurrentFourPartyPersonTokenJourneySurvivesPersonServerRestart`
- `SPEC-FEEDBACK.md`, AAG-F009

**Current-product effect:** Clients must treat an unrecognized terminal `403` as
denial. The code may change if the editors add or select a registered result.

## AAG-I006 — Mission approval is released only after recoverable cross-store custody

**Status:** adopted

**Source:** AAuth Protocol, `Mission Approval`, `Person Token Endpoint`, and
`Freshness and Replay` at the current AAuth revision above.

**Question:** When approval spans a mission store and several person-token
records, what survives a partial write, uncertain commit, restart, or lost
response?

**Chosen behavior:** Before any child commit, retain one private issuance record
keyed by the signed request proof. It contains the exact response and every
exact person-token record. Partial and uncertain writes return retryable
`503 server_error`; replaying that exact signed request resumes idempotently and
returns the byte-identical approval only after all stores confirm it.

**Alternative considered:** Commit person tokens first and retain only their
hashes. That can orphan the first token when a later write fails and cannot
reconstruct the compact response after an uncertain commit.

**Why:** The mission bytes returned to the agent and each person-token retention
record are one authorization decision. The journal makes their separate durable
stores a recoverable state machine without pretending they share a transaction.

**Evidence:**

- `current_mission_recovery_test.go:TestCurrentMissionIssuanceRecoversExactResponseAcrossStoreBoundaries`

**Current-product effect:** Current person-token server compositions must supply a
`MissionIssuanceStore`. Exact recovery requires the original signed request
within its accepted signature window; a newly signed request is a new proposal.

## AAG-I007 — Defined authorization extensions fail closed until implemented

**Status:** adopted current boundary

**Source:** AAuth Protocol, `Resource Token Structure`; R3, `Resource Token
Extensions` and `Auth Token Extensions`; Budgets, `Resource Token Extensions`
and `Auth Token Extensions`.

**Question:** May a receiver ignore a signed R3 or Budget claim merely because
this implementation does not yet support that companion specification?

**Chosen behavior:** No. Resource and auth tokens containing any defined R3 or
Budget member are rejected by name before ordinary claims decoding, request-
proof replay admission, authorization-decision policy, new authorization-state
retention, or protected consequence. Signer authentication, trusted-peer
policy, and recovery of already-retained state remain earlier independent
boundaries. Support begins only with the companion extension's complete
validation and enforcement path.

**Alternative considered:** Treat the members as unknown optional JWT claims.
That would silently discard signed grants or limits. In particular, accepting a
Budget-bearing auth token without enforcing its hard cap changes the authority
the issuer expressed.

**Why:** Cryptographic validity does not authorize a receiver to ignore known
authorization semantics. A named refusal is safer and interoperable with a
future complete extension implementation; partial parsing would create a
second, weaker profile.

**Evidence:**

- `r3_test.go:TestVerifyTokensRejectRawUnsupportedExtensionMembersBeforeClaimsDecode`
- `reference/resource_replay_store_test.go:TestCurrentProtectedResourceRejectsRawUnsupportedExtensionTokensBeforePolicyReplayAndOperation`
- `reference/resource_token_preflight_replay_test.go:TestTokenAuthoritiesRejectUnsupportedResourceTokenClaimBeforeProofReplay`
- `reference/resource_token_preflight_replay_test.go:TestPersonTokenAuthorityRejectsUnsupportedUpstreamClaimBeforeProofReplay`

**Current-product effect:** R3 and Budgets remain unclaimed. Their defined
claims cannot be downgraded into the current Core scope-only path.

## Adding or changing an interpretation

1. Pin the exact source revision and section.
2. Add an externally observable failing test or interoperability capture.
3. Record the chosen behavior and at least one plausible alternative.
4. Explain the security and interoperability effect in plain language.
5. Update source coverage only after the evidence passes.
6. Preserve a superseded entry with its disposition instead of rewriting
   history to make the old choice look current.
