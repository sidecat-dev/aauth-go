# M4 behavior scenarios

## JOURNEY-0001 — A concrete conditional call is approved and executed

**Kind:** journey
**Proof seam:** real HTTP handlers and cryptographic verification
**Owning stories:** STORY-0001 through STORY-0004

**Preconditions:**

- Two MCP operations are in an exact class R3 document.
- The AS policy grants one directly and marks the other conditional in the
  same initial auth token.
- The resource can build and durably retain an exact proposal from the signed
  call, and only the AS can fetch proposal bytes.

**Steps:**

1. The agent obtains the ordinary class resource token and exchanges it.
   → The verified initial auth token contains disjoint `r3_granted` and
   `r3_conditional` subsets whose union stays inside the retained request.
2. The agent signs and sends the directly granted operation.
   → The resource invokes that operation once without proposal construction.
3. The agent signs and sends a conditional protected call with inline and
   digested parameters.
   → The operation is not invoked; the resource persists one exact proposal
   and returns an auth-token requirement whose resource token contains only its
   URI/hash.
4. The agent exchanges that challenge token through the PS.
   → The AS alone fetches and hash-verifies the exact proposal, policy sees its
   parameters, issuance audit succeeds, and the returned per-call token grants
   its one operation.
5. The agent signs a fresh retry with the same actual parameters.
   → The resource loads the exact approved proposal, verifies inline and digest
   bindings, and invokes the protected operation once.

**Final observables:**

- The directly granted operation executes once under the mixed class token.
- There is no conditional protected-operation call before approval.
- The challenge and per-call token name the same proposal URI/hash.
- The policy and resource observe the same exact proposal identity.
- Exactly one matching retry reaches the conditional operation during the
  journey.

**Automation status:** automated
**Execution command:** `go test ./... -run '^(TestR3ConditionalPerCallJourney|TestR3FetchRefusesDeniedRedirectedOversizedAndTimedOutDocuments)$' -count=1`

**Sources:**

- `draft-hardt-aauth-r3.md:448-618`

## SCENARIO-0001 — Proposal structure is strict

**Kind:** contract
**Proof seam:** unit
**Owning stories:** STORY-0002

**Preconditions:**

- An R3 document is presented as a concrete-call proposal.

**Action:**

- Decode and validate valid and malformed proposal variants.

**Expected observables:**

- Valid proposals have exactly one operation and one parameters object.
- Duplicate or ambiguous names, missing or non-object parameters, zero or
  multiple operations, operation mismatch, malformed digests, and empty digest
  values are refused before custody or issuance.

**Automation status:** automated
**Execution command:** `go test . -run '^(TestR3ProposalBindsInlineAndDigestParameters|TestR3ProposalRejectsMalformedParameterDocuments|TestR3DocumentRejectsDuplicateNamesAtEveryDepth)$' -count=1`

**Sources:**

- `draft-hardt-aauth-r3.md:544-562`

## SCENARIO-0002 — Challenge token carries only the proposal reference

**Kind:** contract
**Proof seam:** integration
**Owning stories:** STORY-0002

**Preconditions:**

- A signed call matches an operation granted only in `r3_conditional`.

**Action:**

- Send the call to the real protected-resource handler.

**Expected observables:**

- The resource retains exact proposal bytes before responding.
- The operation does not run.
- `AAuth-Requirement` contains a signed resource token with only the proposal
  URI/hash; neither token nor header contains proposal parameters.

**Automation status:** automated
**Execution command:** `go test . -run '^TestR3ConditionalPerCallJourney$' -count=1`

**Sources:**

- `draft-hardt-aauth-r3.md:530-538,580-585`

## SCENARIO-0003 — Proposal construction and custody fail closed

**Kind:** failure-recovery
**Proof seam:** integration
**Owning stories:** STORY-0002

**Preconditions:**

- A conditional call reaches proposal construction or retention.

**Action:**

- Inject mapping, unsafe-directory, exact-byte custody, and capacity failures.

**Expected observables:**

- No challenge token or proposal parameters escape.
- The protected operation is never invoked.

**Automation status:** automated
**Execution command:** `go test ./... -run '^(TestR3ConditionalPerCallJourney|TestFileR3DocumentStoreRejectsUnsafeDirectoryPermissions|TestFileR3PerCallIssuanceStoreRejectsUnsafeDirectoryPermissions|TestFileR3DocumentStoreRefusesOversizedOrInvalidRetention|TestFileR3DocumentStoreCountsProposalStateAgainstTotalByteLimit|TestFileR3DocumentStoreRollsBackNewDocumentWhenProposalStateCannotFit)$' -count=1`

**Sources:**

- `draft-hardt-aauth-r3.md:530-562`

## SCENARIO-0004 — Ungranted operations never execute

**Kind:** contract
**Proof seam:** integration
**Owning stories:** STORY-0001

**Preconditions:**

- Policy returns disjoint direct and conditional operation subsets.

**Action:**

- Validate the decision and call direct, conditional, and absent operations.

**Expected observables:**

- A direct operation executes under the class token.
- A conditional operation challenges without execution.
- An operation in neither set is denied.

**Automation status:** automated
**Execution command:** `go test ./... -run '^(TestR3ConditionalPerCallJourney|TestR3DirectGrantJourney|TestValidateR3AuthorizationDecisionAcceptsOnlyDisjointDocumentSubsets)$' -count=1`

**Sources:**

- `draft-hardt-aauth-r3.md:464-542,616-618`

## SCENARIO-0005 — Proposal authorization cannot be partial or recursive

**Kind:** contract
**Proof seam:** integration
**Owning stories:** STORY-0003

**Preconditions:**

- The AS has authenticated, fetched, and hash-verified an exact proposal.

**Action:**

- Return valid and invalid proposal policy decisions; inject recovery-store
  and durable-audit failures.

**Expected observables:**

- Only an exact direct grant of the proposal's one operation is accepted.
- Missing or half claims, empty grant, recursive conditional, vocabulary or
  operation mismatch, and overgrant fail closed.
- Recovery commit and durable audit both precede token release; after restart,
  the audit is retried and the exact committed token is recovered.

**Automation status:** automated
**Execution command:** `go test ./... -run '^(TestR3ConditionalPerCallJourney|TestR3TokenClaimsRequireCompleteConsistentClaims|TestValidateR3AuthorizationDecisionRequiresExactDirectProposalGrant|TestFileR3PerCallIssuanceStoreCommitsOneExactTokenAcrossRestart)$' -count=1`

**Sources:**

- `draft-hardt-aauth-r3.md:448-461,580-610`

## SCENARIO-0006 — Every actual parameter remains bound

**Kind:** contract
**Proof seam:** e2e
**Owning stories:** STORY-0004

**Preconditions:**

- A per-call token directly grants one exact retained proposal.

**Action:**

- Retry through the signed HTTP path with matching and mutated calls.

**Expected observables:**

- Matching inline JSON and full digest bytes execute once.
- Added, removed, or changed parameters, changed HTTP method, body byte or
  media type, recipient, operation, proposal, and malformed digest metadata
  are refused before execution and do not consume the matching grant.

**Automation status:** automated
**Execution command:** `go test ./... -run '^(TestR3ConditionalPerCallJourney|TestR3ProposalBindsInlineAndDigestParameters|TestR3ProposalRejectsMalformedParameterDocuments|TestClassifyR3ProposalReferenceRefusesDigestPathMismatch|TestAgentRefusesProposalStageWithMismatchedDigestPath)$' -count=1`

**Sources:**

- `draft-hardt-aauth-r3.md:548-562,580-590`

## SCENARIO-0007 — Resource reconstruction retains enforcement

**Kind:** failure-recovery
**Proof seam:** integration
**Owning stories:** STORY-0005

**Preconditions:**

- A challenge and its exact proposal are durably retained.

**Action:**

- Reconstruct the resource and access server; also present missing, expired,
  corrupt, and substituted custody.

**Expected observables:**

- Reconstruction loads the exact proposal and issuance candidate.
- Only a matching retry can complete.
- Missing, expired, corrupt, or substituted state fails closed.

**Automation status:** automated
**Execution command:** `go test ./... -run '^(TestR3ConditionalPerCallJourney|TestFileR3DocumentStoreFailsClosedForMissingExpiredOrCorruptProposalCustody|TestFileR3PerCallIssuanceStoreCommitsOneExactTokenAcrossRestart)$' -count=1`

**Sources:**

- `draft-hardt-aauth-r3.md:384-393,580-618`

## SCENARIO-0008 — Replayed proof and per-call token reuse are refused

**Kind:** failure-recovery
**Proof seam:** integration
**Owning stories:** STORY-0005

**Preconditions:**

- One valid per-call token and exact proposal exist.

**Action:**

- Reuse the identical signed proof, then use fresh proofs with the same token,
  including across reconstruction and concurrent attempts.

**Expected observables:**

- Identical-proof replay is refused.
- Durable consume-before-effect admission gives one winner for fresh proofs
  using the same token, including after restart.
- Changed parameters are refused without consuming the matching call.
- The evidence supports at-most-once admission, not exactly-once consequence.

**Automation status:** automated
**Execution command:** `go test ./... -run '^(TestR3ConditionalPerCallJourney|TestFileR3DocumentStoreConsumesProposalOnceAcrossRestart)$' -count=1`

**Sources:**

- `draft-hardt-aauth-r3.md:384-393,580-618`
