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

**Compatibility effect:** A source refresh may deliberately expose previously
implemented behavior as legacy or unclaimed. A green test against an older
wire shape is not relabeled as current conformance.

## AAG-I002 — Emit and accept fully specified `Ed25519`, not `EdDSA`

**Status:** adopted

**Source:** AAuth Protocol, `Signature Algorithms`; HTTP Signature Keys,
`Algorithm Determination` and `Unsupported Algorithm`.

**Question:** Should Ed25519 keys and JWTs use the polymorphic JOSE name
`EdDSA` for compatibility with older implementations?

**Chosen behavior:** Emit `alg: Ed25519`. Reject missing algorithms,
polymorphic `EdDSA`, `none`, symmetric algorithms, and structurally invalid
Ed25519 keys on the applicable current paths. Return the specified negotiable
unsupported-algorithm response where the HTTP protocol permits it.

**Alternative considered:** Accept `EdDSA` while emitting `Ed25519`. That can
ease a transition, but it weakens the current algorithm-determination rule and
makes the accepted cryptographic operation depend on key shape outside the
declared algorithm.

**Why:** A fully specified algorithm makes the cryptographic operation explicit
and follows both current author sources.

**Evidence:**

- `draft11_wire_test.go:TestDraft11Ed25519WireJourney`
- `draft08_discovery_test.go:TestDraft08SelectedUnsupportedJWKSAlgorithmUsesNegotiableEnvelope`
- `elixir_interop_test.go:TestHistoricalElixirFixturesUseUnsupportedPolymorphicEdDSA`

**Compatibility effect:** Historical `EdDSA` fixtures remain retained as
negative compatibility evidence. They are not current interoperability vectors.

## AAG-I003 — Legacy token journeys do not count as current person-token coverage

**Status:** adopted migration boundary

**Source:** AAuth Protocol, `Person Token`, `Resource Access and Resource
Tokens`, `Person Server`, `Auth Tokens`, and `Sub-Agents`; interoperability
profile surfaces 1 through 5.

**Question:** Can the earlier agent/resource/auth-token journey be treated as a
partial implementation of the current topology because several endpoints and
JWT type names are unchanged?

**Chosen behavior:** No. Current coverage stays unclaimed until a real journey
issues and retains an `aa-person+jwt`, derives `ps`, `sub`, `presented_jti`, and
`mission_s256` into the resource token, resolves the retained person-token
record at the PS, and issues and presents the current auth-token shape.

**Alternative considered:** Keep the old journey marked exercised and describe
the new claims as a later enhancement. That would hide a security-relevant
topology change: the retained `presented_jti` lookup is what detects subject or
mission substitution, and current resource-facing tokens no longer identify
the agent.

**Why:** Similar endpoint names do not make the authorization evidence
equivalent. The current person-token chain changes what each party may assert
and what the PS must retain and compare.

**Evidence:**

- `internal/sourcecoverage/sourcecoverage_test.go:TestLegacyEvidenceDoesNotClaimTheCurrentPersonTokenTopology`
- `SOURCE-COVERAGE.md` leaves the affected current sections unclaimed

**Compatibility effect:** Existing APIs and tests remain regression evidence
while the migration is in progress, but they are not advertised as current
protocol coverage. Compatibility policy for legacy public types will be decided
before the current journey replaces them.

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

- `internal/sourcecoverage/sourcecoverage_test.go:TestLegacyEvidenceDoesNotClaimTheCurrentPersonTokenTopology`
- current R3 sections remain unclaimed in `SOURCE-COVERAGE.md`

**Compatibility effect:** The existing AS-only reference handler and
`r3_conditional` token fields remain legacy behavior during migration. They are
not described as current R3 support.

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

**Compatibility effect:** Clients must treat an unrecognized terminal `403` as
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

**Compatibility effect:** Current person-token server compositions must supply a
`MissionIssuanceStore`. Exact recovery requires the original signed request
within its accepted signature window; a newly signed request is a new proposal.

## Adding or changing an interpretation

1. Pin the exact source revision and section.
2. Add an externally observable failing test or interoperability capture.
3. Record the chosen behavior and at least one plausible alternative.
4. Explain the security and compatibility effect in plain language.
5. Update source coverage only after the evidence passes.
6. Preserve a superseded entry with its disposition instead of rewriting
   history to make the old choice look current.
