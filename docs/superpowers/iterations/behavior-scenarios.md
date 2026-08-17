# Behavior scenarios

> **Historical iteration overlay (2026-08-17):** This file preserves the
> scenarios and evidence language accepted for the draft-09/06/01 iteration.
> It is not the active wire-contract projection. Every `EdDSA` acceptance or
> emission statement below is historical and superseded: the active Phase-1
> implementation emits and accepts only fully specified `Ed25519`, requires
> JWK and `hwk` `alg`, and deliberately rejects retained draft-06 fixtures.
> Current evidence is `draft11_wire_test.go`, `draft08_discovery_test.go`, and
> `signature_key_structured_internal_test.go`; draft-11 token topology remains
> a later phase.

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

## JOURNEY-0002 — One public subscription delivers one verified event

**Kind:** journey
**Proof seam:** e2e
**Owning stories:** STORY-0006, STORY-0007, STORY-0008, STORY-0009,
STORY-0010, STORY-0011, STORY-0012, STORY-0013, STORY-0014, STORY-0015

**Preconditions:**

- An Events-capable AP, resource, and agent have distinct durable host stores
  and admitted discovery clients.
- The AP selects `max_uses: 1`; AP and resource hosts select independent,
  overlapping active lifetimes; the agent has a durable local context to bind
  to `(AP issuer, eid)`.

**Steps:**

1. The AP creates a subscription record and issues a subscribe token.
   → The record is durable before release, the token names the same opaque
   `eid`, resource, agent, and one-use policy, and AP metadata advertises its
   HTTPS event endpoint.
2. The reference agent retains its local `eid` context and signs a public
   registration POST using only the subscribe token.
   → The resource verifies the AP JWT and agent HTTP proof and durably retains
   the exact authority-qualified subscription binding without treating token
   expiry or the AP host lifetime as its own lifetime.
3. The registration token expires while both host subscription lifetimes
   remain active.
   → Existing subscription authority remains usable; the expired token cannot
   create another registration.
4. The AP changes its advertised endpoint after the earlier metadata response
   becomes stale.
   → The resource's delivery-time resolution selects the current endpoint,
   not a registration-time URL.
5. The resource durably retains a payload-free event token as pending and sends
   a bodyless self-jwt-signed POST.
   → One discovered resource key verifies the JWT and HTTP proof; token `eid`,
   resource, and agent match the durable subscription.
6. The AP atomically records the exact token and consumes the subscription use
   before returning `202` with `remaining_uses: 0`, but the first response is
   lost.
   → Reconstructed AP and resource state let the resource retry the same JWT
   with a fresh HTTP proof; the AP returns the source-required exhausted `429`
   without another use or inbox record, and the resource resolves the unknown
   first outcome by removing its exhausted subscription.
7. The adapter delivers trusted AP context and the exact pending token; the
   agent verifies and records pending action state, then is reconstructed
   before action completion while the event remains unexpired.
   → Reconstruction rechecks expiry, resumes the stable idempotent action,
   records completion, and only then acknowledges adapter work. Later
   duplicates do not act again.

**Final observables:**

- No protocol surface claims the non-normative token-acquisition or AP-agent
  adapter as standardized wire.
- No success precedes durable subscription, resource pending-delivery, AP
  inbox, or agent processing state.
- The exact journey contains no event payload and exhausts one use once.

**Automation status:** automated
**Execution command:** `go test ./... -run '^TestPublicSubscriptionEventSurvivesHostReconstruction$' -count=1`

**Sources:**

- `draft-hardt-aauth-events.md:143-295,346-456,582-624,680-719`
- `http-signature-keys.txt:660-721`

## SCENARIO-0009 — Invalid self-jwt fails before discovery

**Kind:** contract
**Proof seam:** integration
**Owning stories:** STORY-0006

**Preconditions:**

- A counting resolver records every attempted metadata or JWKS lookup.

**Action:**

- Verify requests with absent, non-string, empty, malformed, expired,
  wrong-type, missing-locator, unsafe-locator, and `cnf`-bearing self-jwts.

**Expected observables:**

- Every request is refused before discovery or HTTP-signature verification.
- The counting resolver remains at zero and stable typed errors distinguish
  malformed JWT, expired JWT, and invalid key input.

**Automation status:** automated
**Execution command:** `go test . -run '^TestSelfJWTRejectsUnsafeClaimsBeforeDiscovery$' -count=1`

**Sources:**

- `http-signature-keys.txt:668-710,1269-1276`

## SCENARIO-0010 — One discovered key must verify both proof layers

**Kind:** contract
**Proof seam:** e2e
**Owning stories:** STORY-0006, STORY-0007, STORY-0012, STORY-0013

**Preconditions:**

- Admitted resource metadata publishes two valid signing keys.

**Action:**

- Send a real self-jwt request, then independently substitute the JWT key,
  HTTP key, `kid`, Events `dwk`, required `iat` (absent and malformed), other
  application claims, and maximum lifetime.

**Expected observables:**

- Only the request whose selected key verifies both layers, whose `dwk` is the
  exact Events discovery document, and whose required claims satisfy caller
  policy reaches the operation.
- A missing JWKS key reports `unknown_key`; excessive lifetime and claim
  mismatch are refused after JWT proof but before application mutation.

**Automation status:** automated
**Execution command:** `go test . -run '^(TestSelfJWTUsesOneDiscoveredKeyForBothProofs|TestSelfJWTAppliesDeploymentPolicyBeforeHTTPProof|TestSelfJWTUsesAdmittedHTTPKeyForBothProofs|TestSubscribeAndEventClaimsRejectRequiredFieldMutations)$' -count=1`

**Sources:**

- `http-signature-keys.txt:660-721,1171-1182`
- `draft-hardt-aauth-events.md:346-437`

## SCENARIO-0011 — Presenter-directed discovery stays inside host policy

**Kind:** contract
**Proof seam:** integration
**Owning stories:** STORY-0007

**Preconditions:**

- A reference egress policy and logical HTTP gateway expose public, private,
  loopback, link-local, rebound, and cross-origin destinations.

**Action:**

- Resolve repeated valid and adversarial self-jwt issuer/document/key tuples,
  including after token expiration and beyond negative-cache capacity.

**Expected observables:**

- Every metadata and JWKS connection is separately admitted; disallowed or
  rebound targets never reach the gateway.
- Cached key material cannot make an expired JWT usable, and retained resolver
  state remains bounded.

**Automation status:** automated
**Execution command:** `go test . -run '^(TestHTTPKeyResolverPresenterDirectedEgressPolicy|TestSelfJWTExpiryCannotUseWarmDiscoveryCache|TestHTTPKeyResolverRetainedStateIsBounded|TestHTTPKeyResolverEvictsTiedRetainedStateDeterministically|TestHTTPKeyResolverBoundsConcurrentUniqueInflight|TestHTTPKeyResolverUsesAdmittedTwoHopDiscoveryAndCache|TestHTTPKeyResolverAppliesUnknownKeyRefreshFloor|TestHTTPKeyResolverDoesNotFetchBeforeAdmission)$' -count=1`

**Sources:**

- `http-signature-keys.txt:1171-1215,1248-1276`

## SCENARIO-0012 — Current AP metadata controls delivery endpoint

**Kind:** contract
**Proof seam:** integration
**Owning stories:** STORY-0008, STORY-0012

**Preconditions:**

- An Events-capable AP first advertises endpoint A and later endpoint B.

**Action:**

- Resolve during fresh cache state, advance beyond freshness, rotate metadata,
  and deliver the event.

**Expected observables:**

- The AP metadata document contains an absolute HTTPS `event_endpoint` only
  when Events is enabled.
- Fresh cache state avoids an extra fetch; delivery after expiry targets B and
  no registration-time endpoint overrides it.

**Automation status:** automated
**Execution command:** `go test ./... -run '^(TestAgentEventMetadataUsesAdmittedHTTPFreshness|TestAgentEventMetadataDoesNotCacheWhenCacheControlForbidsIt|TestAgentProviderEventsMetadataRotatesWithHTTPFreshness|TestPublicSubscriptionEventSurvivesHostReconstruction)$' -count=1`

**Sources:**

- `draft-hardt-aauth-events.md:196-208,285,384-409`

## SCENARIO-0013 — Subscribe-token mutations cannot register

**Kind:** contract
**Proof seam:** integration
**Owning stories:** STORY-0009, STORY-0011

**Preconditions:**

- A valid AP record and subscribe token exist for one agent and resource.

**Action:**

- Mutate type, algorithm, discovery document, issuer key, `sub` (absent and
  malformed), `iat`, `exp`, audience, confirmation key, `eid`, and `max_uses`
  (including absent, zero, and values above one), then send each through the
  real resource endpoint.

**Expected observables:**

- **Historical draft-06 expectation, superseded:** Only the exact EdDSA
  selected-profile token with `max_uses: 1` plus matching
  agent proof registers; `alg=none`, absent or other use policies, and every
  binding mutation fail.
- No refusal creates or replaces durable resource subscription state.

**Automation status:** automated
**Execution command:** `go test ./... -run '^(TestSubscribeAndEventClaimsRejectRequiredFieldMutations|TestPublicEventRegistrationRequiresExactSubscribeTokenAndAgentProof|TestPublicEventRegistrationRejectsRawSubscribeMutationsWithoutCustody)$' -count=1`

**Sources:**

- `draft-hardt-aauth-events.md:210-285`

## SCENARIO-0014 — Duplicate public registration cannot replace custody

**Kind:** failure-recovery
**Proof seam:** process-level
**Owning stories:** STORY-0011

**Preconditions:**

- One public subscription has been accepted and durably retained under
  `(AP issuer, eid)`; its registration token has expired but resource host
  `active_until` remains in the future.

**Action:**

- Reconstruct the resource, deliver under the existing record, then replay the
  expired registration token and a different valid token that names the same
  `(AP issuer, eid)`.

**Expected observables:**

- The first resource/AP/agent/host-lifetime binding remains authoritative and
  the live subscription remains usable after registration-token expiry.
- Both duplicate registrations are refused without replacing or extending it.

**Automation status:** automated
**Execution command:** `go test ./... -run '^(TestPublicEventRegistrationCustodySurvivesReconstruction|TestPublicSubscriptionEventSurvivesHostReconstruction)$' -count=1`

**Sources:**

- `draft-hardt-aauth-events.md:285-295,596-598,689-695`

## SCENARIO-0015 — Durable-inbox failure prevents 202

**Kind:** failure-recovery
**Proof seam:** process-level
**Owning stories:** STORY-0013

**Preconditions:**

- A cryptographically valid event matches one live one-use subscription.

**Action:**

- Inject failure before the AP can atomically commit inbox record and use
  count, then retry after store recovery.

**Expected observables:**

- The failed attempt never returns `202`, consumes a use, or creates adapter
  work.
- The later healthy retry commits one recoverable event and one use together.

**Automation status:** automated
**Execution command:** `go test ./reference -run '^TestAPEventEndpointCommitsInboxBefore202$' -count=1`

**Sources:**

- `draft-hardt-aauth-events.md:410-434`

## SCENARIO-0016 — Concurrent final use has one durable winner

**Kind:** failure-recovery
**Proof seam:** process-level
**Owning stories:** STORY-0012, STORY-0013

**Preconditions:**

- A subscription has one use remaining and no accepted event.

**Action:**

- Race two valid deliveries, reconstruct the AP, and inspect the resource's
  response handling.

**Expected observables:**

- Exactly one different event JWT returns `202` with `remaining_uses: 0`; the
  other returns `429`. Retrying the winning exact JWT also returns `429` without
  another state transition.
- Reconstructed state remains exhausted with one exact inbox record, and the
  resource removes its exhausted local subscription.

**Automation status:** automated
**Execution command:** `go test -race ./... -run '^(TestAPEventEndpointSerializesConcurrentFinalUseAcrossReconstruction|TestPublicSubscriptionEventSurvivesHostReconstruction)$' -count=1`

**Sources:**

- `draft-hardt-aauth-events.md:233-235,410-434,697-703`

## SCENARIO-0017 — AP refusal classes leave state unchanged

**Kind:** contract
**Proof seam:** integration
**Owning stories:** STORY-0013

**Preconditions:**

- The AP holds one active subscription and a snapshot of usage/inbox state.

**Action:**

- Send malformed input, invalid resource proof, wrong resource, wrong agent,
  unknown and expired `eid`, expired token, and exhausted delivery.

**Expected observables:**

- Responses use the specified `400`, `401`, `403`, `404`, and `429` classes.
- Every refusal leaves the snapshot unchanged and queues no adapter work.

**Automation status:** automated
**Execution command:** `go test ./reference -run '^TestAPEventEndpointRefusalMatrixLeavesAuthorityUnchanged$' -count=1`

**Sources:**

- `draft-hardt-aauth-events.md:410-437,582-603`

## SCENARIO-0018 — Agent verification and dedup survive reconstruction

**Kind:** failure-recovery
**Proof seam:** process-level
**Owning stories:** STORY-0014, STORY-0015, STORY-0016

**Preconditions:**

- The AP inbox contains one accepted token with trusted AP issuer context and
  a host-generated delivery identifier, and the agent durably maps
  `(AP issuer, eid)` to local context.

**Action:**

- Deliver the valid token, crash after durable pending admission but before
  action completion, reconstruct the adapter and agent, and resume while it is
  unexpired, then repeat after completion. Exercise three separate expiry and
  crash boundaries: expire never-dispatched pending work; crash after the
  durable dispatched transition when the action contract can prove either
  completed or not applied; and crash after dispatch with an outcome the
  action contract cannot prove. Also deliver accepted-inbox records whose exact
  tokens have wrong type, wrong key, wrong Events `dwk`, absent or malformed
  `iat`, wrong audience, expiry before initial agent processing, or unknown
  context; reconstruct after recording each refusal.

**Expected observables:**

- Unexpired pending work resumes through the stable idempotent action key and
  produces one completed action before adapter acknowledgement.
- Never-dispatched expired work and dispatched work reconciled as not applied
  become terminal refused without action and survive reconstruction. A
  previously completed dispatch is reconciled to completed without another
  action even if expiry passed before the completion mark. An outcome-unknown
  dispatch remains dispatched and unacknowledged after expiry and restart.
- Completed dedup survives reconstruction. Every invalid variant produces no
  action, reaches one durable terminal refusal keyed by trusted AP delivery
  context rather than unverified claims, and is acknowledged only after that
  refusal survives reconstruction.

**Automation status:** automated
**Execution command:** `go test -race ./reference -run '^(TestAgentEventProcessing|TestAgentEventRefusalMatrixSurvivesStoreReconstruction|TestEventAdapter)' -count=1`

**Sources:**

- `draft-hardt-aauth-events.md:438-456,592-598,711-719`

## SCENARIO-0019 — M5 remains payload-free and claim-honest

**Kind:** contract
**Proof seam:** integration
**Owning stories:** STORY-0010, STORY-0014, STORY-0016

**Preconditions:**

- The full M5 public single-shot journey has completed.

**Action:**

- Inspect exact JWT claims, HTTP request, AP inbox bytes, adapter record,
  public API, source-coverage annotations, and README claims.

**Expected observables:**

- No event-specific payload appears at any M5 boundary.
- Documentation states AP token retention, future AP payload visibility,
  current-auth detail retrieval, the single-shot replay boundary, and the M6
  ownership of protected tickets and AsyncAPI, while AP-agent transport stays
  explicitly non-normative.

**Automation status:** automated
**Execution command:** `go test ./... -run '^(TestEventsPublicClaimsMatchQualifiedProfile|TestSubscribeAndEventClaimsRejectRequiredFieldMutations|TestPublicSubscriptionEventSurvivesHostReconstruction)$' -count=1`

**Sources:**

- `draft-hardt-aauth-events.md:129-131,297-344,438-442,608-624,697-719`

## SCENARIO-0020 — AP issuance cannot outrun subscription custody

**Kind:** failure-recovery
**Proof seam:** process-level
**Owning stories:** STORY-0009

**Preconditions:**

- The AP uses a collision-capable identifier source and a failure-injected
  subscription authority store.

**Action:**

- Produce a duplicate `eid`, fail the durable commit, then issue successfully
  and reconstruct the AP after the subscribe token is returned.

**Expected observables:**

- Collision and commit failure release no token and leave no partial authority.
- Successful release has one exact recoverable `(AP issuer, eid)` record whose
  host `active_until` is independent from token `exp`.

**Automation status:** automated
**Execution command:** `go test ./reference -run '^TestAgentProviderIssuesOnlyAfterDurableSubscriptionCommit$' -count=1`

**Sources:**

- `draft-hardt-aauth-events.md:143-146,188-235,689-703`

## SCENARIO-0021 — Host custody failure prevents outward success

**Kind:** failure-recovery
**Proof seam:** process-level
**Owning stories:** STORY-0010, STORY-0011, STORY-0015

**Preconditions:**

- Failure-injected agent-context, resource-subscription, and agent-dedup stores
  back an otherwise valid single-shot journey.

**Action:**

- Fail each store immediately before its durable boundary, then retry after
  reopening a healthy adapter.

**Expected observables:**

- Context failure sends no registration; resource-store failure reports no
  registration success; dedup-store failure performs no agent action and
  leaves adapter work pending.
- Healthy retries recover exact authority-qualified state and advance once.

**Automation status:** automated
**Execution command:** `go test ./reference -run '^(TestPublicEventRegistrationRequiresExactSubscribeTokenAndAgentProof|TestEventAdapterRecoversAfterDedupCustodyFailure)$' -count=1`

**Sources:**

- `draft-hardt-aauth-events.md:188-195,285-295,423-456`

## SCENARIO-0022 — Two APs may reuse one opaque eid

**Kind:** contract
**Proof seam:** process-level
**Owning stories:** STORY-0011

**Preconditions:**

- Two trusted AP issuers independently generate the same opaque `eid` for the
  same resource.

**Action:**

- Register both valid subscriptions, reconstruct the resource, then attempt to
  replace each with a same-AP duplicate.

**Expected observables:**

- Both `(AP issuer, eid)` records coexist and remain independently loadable.
- A duplicate from its own AP cannot replace or extend either record.

**Automation status:** automated
**Execution command:** `go test ./reference -run '^TestPublicEventRegistrationsKeyOpaqueEventIDByAPIssuer$' -count=1`

**Sources:**

- `draft-hardt-aauth-events.md:143-145,224-235,285,596-598`

## SCENARIO-0023 — Unknown delivery outcome retries one exact token

**Kind:** failure-recovery
**Proof seam:** process-level
**Owning stories:** STORY-0012, STORY-0013

**Preconditions:**

- The resource durably retains one pending event JWT and the AP has one
  remaining subscription use.

**Action:**

- Let the AP atomically accept the token but lose the `202` response;
  reconstruct both hosts and retry the exact JWT with a fresh HTTP proof. Also
  submit a different valid event JWT for the exhausted subscription.

**Expected observables:**

- The exact retry returns exhausted `429` without a second use or inbox record,
  allowing deterministic resource cleanup while making no second-acceptance
  claim.
- A different JWT also returns `429`; reconstruction preserves exhaustion and
  the single accepted inbox record.

**Automation status:** automated
**Execution command:** `go test -race ./... -run '^(TestEventDeliveryRetainsExactJWTAndReconcilesLost202With429|TestAPEventEndpointSerializesConcurrentFinalUseAcrossReconstruction|TestPublicSubscriptionEventSurvivesHostReconstruction)$' -count=1`

**Sources:**

- `draft-hardt-aauth-events.md:410-437,592-598,697-703`

## SCENARIO-0024 — Host stores are versioned replaceable authorities

**Kind:** contract
**Proof seam:** process-level
**Owning stories:** STORY-0009, STORY-0010, STORY-0011, STORY-0012,
STORY-0013, STORY-0014, STORY-0015, STORY-0017

**Preconditions:**

- AP authority/inbox, resource subscription/delivery, adapter continuation,
  and agent context/processing are supplied through public host interfaces.
- File adapters are configured with small record-count, total-byte, and
  per-record-byte limits and private filesystem custody.

**Action:**

- Run the lifecycle with in-memory qualification stores and bounded
  single-writer file adapters. Reopen valid files; exceed every configured
  capacity; present truncated, corrupt, and unknown-version records; weaken
  permissions; substitute a symlink or unexpected entry; inject failure during
  replacement; and try to open a concurrent writer for the same store.

**Expected observables:**

- Service and protocol APIs do not change when store implementations are
  replaced.
- Valid versioned state reopens exactly. Count and byte limits are enforced
  before state becomes reachable. Truncated, corrupt, unknown-version,
  symlinked, unexpected, or unsafely permissioned custody fails closed.
- Partial-write injection never exposes a partial successor and leaves the
  prior committed snapshot usable or reports no mutation success. A second
  writer is refused while the first owns the store.
- These are reference-host qualification results, not new Events protocol or
  enterprise-storage conformance claims.

**Automation status:** automated
**Execution command:** `go test -race ./... -run '^(TestFileEventStores|TestPublicSubscriptionEventSurvivesHostReconstruction)$' -count=1`

**Sources:**

- `draft-hardt-aauth-events.md:188-195,285-295,410-456`

## JOURNEY-0003 — One protected subscription delivers one validated payload

**Kind:** journey
**Proof seam:** e2e
**Owning stories:** STORY-0018, STORY-0019, STORY-0020, STORY-0021

**Preconditions:**

- An agent has a valid auth token and subscribe-token confirmation key.
- A resource publishes one exact admitted AsyncAPI 3.0.0 JSON document with
  one protected parameterized channel, one receive operation, and one JSON
  message schema.
- AP, resource-ticket/subscription, resource-pending, and agent-context/action
  authorities use independently reopenable stores.

**Action:**

1. Send one signed auth-token request to the protected resource operation.
2. During the verified operation, durably issue an opaque ticket bound to the
   agent, operation, resource-state revision, exact AsyncAPI digest, operation,
   message, future expiry, and one AP use; return its HTTPS URL.
3. Discover and retain the exact AsyncAPI document, obtain the AP subscribe
   token, map local context, and send one bodyless signed registration to the
   ticket path.
4. Reconstruct the resource, validate one JSON event payload, durably retain
   its exact token and body, and send it with signed content metadata. Let the
   AP commit the token and payload but lose the first `202`.
5. Reconstruct resource and AP, retry the exact pair with a fresh proof, and
   settle the unknown result through exhausted `429` without another inbox
   record.
6. Reconstruct AP adapter and agent, independently verify the token and exact
   retained AsyncAPI document, validate the payload, dispatch once, record the
   terminal disposition, acknowledge, and repeat the delivery.

**Expected observables:**

- No ticket URL is released before digest-only durable ticket custody.
- Ticket consumption and subscription creation are one committed transition.
- No `202` precedes exact token-plus-payload AP custody.
- The exact JSON body reaches one action without reserialization; every host
  reconstruction preserves its selected authority and document version.
- The duplicate performs no second action and the AP-agent adapter remains a
  deployment contract, not a standardized wire.

**Automation status:** automated
**Execution command:** `go test -race ./reference -run '^TestProtectedPayloadEventSurvivesHostReconstruction$' -count=1`

**Sources:**

- `draft-hardt-aauth-events.md:297-456,457-580,582-607,697-725`
- AsyncAPI 3.0.0 Channel, Operation, Message, Parameter, Reference, and Security
  Scheme objects

## SCENARIO-0025 — Ticket issue custody is opaque, exact, and restart-safe

**Kind:** failure-recovery
**Proof seam:** process-level
**Owning stories:** STORY-0018

**Preconditions:**

- A ticket issuer has an authenticated agent context, a cryptographic random
  source, a bounded ticket store, and an injected clock.

**Action:**

- Issue successfully, fail before commit, force identifier collision, weaken
  every required binding, inspect durable bytes, and reopen the ticket store.

**Expected observables:**

- Success releases one HTTPS URL with at least 256 random bits only after the
  exact record is committed; custody contains its SHA-256 digest but not the raw
  capability.
- Failure releases no URL. Collision cannot replace a live record.
- Reconstruction recovers agent, operation, resource revision, document
  digest, operation/message selection, expiry, and one-use policy exactly.

**Automation status:** automated
**Execution command:** `go test -race ./reference -run '^TestProtectedEventTicketIssue' -count=1`

**Sources:** `draft-hardt-aauth-events.md:301-310,600-607,721-725`

## SCENARIO-0026 — Protected registration consumes one exact authority

**Kind:** contract
**Proof seam:** process-level
**Owning stories:** STORY-0018

**Preconditions:**

- One valid ticket and matching subscribe token exist in independent durable
  authorities.

**Action:**

- Register correctly, then vary the ticket path, agent, key, resource audience,
  document/message binding, expiry, use state, request body policy, signature,
  and commit outcome. Repeat after resource reconstruction.

**Expected observables:**

- The correct bodyless request atomically consumes the ticket and creates the
  subscription before success.
- Every refusal creates no subscription. Validation and commit failures leave
  a still-valid ticket usable; a successful ticket cannot be used again.
- Non-empty bodies are rejected by default. With an explicit validator, media
  type and content digest are proof-covered before validation and consumption.

**Automation status:** automated
**Execution command:** `go test -race ./reference -run '^TestProtectedEventRegistration' -count=1`

**Sources:** `draft-hardt-aauth-events.md:303-344,596-607`

## SCENARIO-0027 — AsyncAPI contract is exact, local, and unambiguous

**Kind:** contract
**Proof seam:** integration
**Owning stories:** STORY-0019

**Preconditions:**

- A resource advertises one AsyncAPI R3 vocabulary endpoint and a ticket names
  one operation/message selection.

**Action:**

- Fetch and parse the exact document, then vary version, media type, size,
  duplicate names, channel parameter mapping, action, references, message
  cardinality, content type, schema, security representation, and selected
  identifiers. Rotate the current document after ticket issuance.

**Expected observables:**

- The admitted JSON 3.0.0 profile resolves exactly one protected receive
  operation and one `application/json` message with a compilable inline schema.
- Invalid or remote/ambiguous variants fail before ticket release or
  consumption. No network schema reference is followed.
- Rotation does not alter the digest-bound document used by an existing
  ticket, subscription, pending delivery, or agent context.

**Automation status:** automated
**Execution command:** `go test ./... -run '^(TestEventsAsyncAPI|TestResourceEventsAsyncAPIDiscovery)' -count=1`

**Sources:** `draft-hardt-aauth-events.md:457-580`; AsyncAPI 3.0.0

## SCENARIO-0028 — Payload proof and AP custody are one acceptance boundary

**Kind:** failure-recovery
**Proof seam:** process-level
**Owning stories:** STORY-0020

**Preconditions:**

- One protected one-use subscription is active and selects one retained JSON
  message schema.

**Action:**

- Send a valid payload; omit or mutate content metadata; send malformed,
  schema-invalid, wrong-type, or oversized input; fail resource pending custody
  and AP inbox custody; lose the successful response; reconstruct and retry.

**Expected observables:**

- Resource validation and pending custody precede transport. AP signature and
  digest verification precede its atomic use-plus-inbox commit.
- Every refusal leaves use and inbox state unchanged. No `202` is returned
  unless exact token, payload bytes, media type, and digest are reloadable.
- Lost-response retry uses the same token and payload with a new HTTP proof and
  creates no duplicate acceptance.

**Automation status:** automated
**Execution command:** `go test -race ./... -run '^(TestEventPayloadDelivery|TestProtectedPayloadEventSurvivesHostReconstruction)$' -count=1`

**Sources:** `draft-hardt-aauth-events.md:346-437,592-607,697-719`

## SCENARIO-0029 — Agent payload verification survives reconstruction

**Kind:** failure-recovery
**Proof seam:** process-level
**Owning stories:** STORY-0021

**Preconditions:**

- AP custody contains one trusted delivery envelope and agent context retains
  the selected exact AsyncAPI document.

**Action:**

- Reconstruct before admission, after pending admission, after dispatch, and
  after completion. Vary token, payload bytes, media type, digest, document,
  schema validity, audience, expiry, and local context, then duplicate terminal
  work.

**Expected observables:**

- Only an independently verified, digest-matching, schema-valid delivery
  reaches the action. Its exact body is available to the action input.
- Invalid variants reach one durable terminal refusal and no action.
- Pending and dispatched work retains M5 continuation/reconciliation behavior;
  one terminal duplicate performs no second action and is safely acknowledged.

**Automation status:** automated
**Execution command:** `go test -race ./reference -run '^(TestAgentEventPayload|TestEventAdapterPayload)' -count=1`

**Sources:** `draft-hardt-aauth-events.md:438-456,592-624,705-719`

## SCENARIO-0030 — M6 claims remain narrow and source-honest

**Kind:** contract
**Proof seam:** integration
**Owning stories:** STORY-0022

**Preconditions:**

- The protected payload journey and all impacted behavior are automated.

**Action:**

- Inspect public APIs, README, journal, roadmap, source coverage, generated
  source ledger, exact test selectors, and dependency/build output.

**Expected observables:**

- Claims name one protected, one-use, direct-JSON payload profile and its exact
  AsyncAPI subset and host-authority boundaries.
- Body shape, media type, security syntax, bodyless registration, lost ticket
  response, multi-event identity, AP-agent transport, general AsyncAPI, and
  storage limitations remain explicit.
- Full, race, vet, build, source coverage, artifact validators, and every
  M3/M4/M5 sentinel pass before M6 closure.

**Automation status:** automated
**Execution command:** `go test ./... -run '^(TestProtectedPayloadEventSurvivesHostReconstruction|TestEventsM6ClaimsMatchQualifiedProfile)$' -count=1`

**Sources:** `draft-hardt-aauth-events.md:297-580,592-624,697-725`
