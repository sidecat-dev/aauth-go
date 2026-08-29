# AAuth Go source coverage

This generated source coverage is not a full-conformance claim. It binds the implementation's explicit claims and omissions to pinned source bytes and executable Go evidence.

Profile: AAuth Go bounded current-editor profile: draft-hardt-oauth-aauth-protocol-latest, draft-hardt-httpbis-signature-key-latest, draft-hardt-aauth-r3-latest, draft-hardt-aauth-events-latest, draft-hardt-aauth-bootstrap-latest, draft-hardt-aauth-budgets-latest, and interop-demo-profile at AAuth a99d353cf18aee81d0c5445bac070164fb3b8bc5 and HTTP Signature Keys 0ff751b571e7fe51336bcc1e526954a202317cc0; every unsupported current behavior remains explicit or unclaimed

## Summary

| Status | Sections |
| --- | ---: |
| Exercised | 47 |
| Partial | 59 |
| Unsupported | 5 |
| Informational | 0 |
| Unclaimed | 489 |

`Unclaimed` means this module makes no section-level implementation claim. It is visible work, not implicit support. `Exercised` names the supported behavior claimed for that section and binds it to a runnable test; it does not silently claim behavior outside the written claim. `Partial` names an intentionally incomplete implementation, and `Unsupported` names an explicit omission.

## Pinned sources

| Source | Revision | SHA-256 | Exercised | Partial | Unsupported | Informational | Unclaimed |
| --- | --- | --- | ---: | ---: | ---: | ---: | ---: |
| `core` | draft-hardt-oauth-aauth-protocol-latest at AAuth a99d353cf18aee81d0c5445bac070164fb3b8bc5 | `c984278f21e3931f0cc272d6768b84bcc471f8ab4a1a1922dd92940a91df7e19` | 28 | 22 | 2 | 0 | 204 |
| `signature-key` | draft-hardt-httpbis-signature-key-latest at signature-key 0ff751b571e7fe51336bcc1e526954a202317cc0 | `335c6164569fc5b21aae7930c83c4088e4c02b857f9f3acee8335f16f23d66cb` | 8 | 2 | 1 | 0 | 71 |
| `r3` | draft-hardt-aauth-r3-latest at AAuth a99d353cf18aee81d0c5445bac070164fb3b8bc5 | `dd768a3b7417c45c0028f2750a50173670fd84c8f432e54ba94799ca93621760` | 2 | 15 | 0 | 0 | 39 |
| `events` | draft-hardt-aauth-events-latest at AAuth a99d353cf18aee81d0c5445bac070164fb3b8bc5 | `6ac4f1c649172a359a6ef32380b189a4edcd9855014bbb03fefe096b74802eb0` | 0 | 7 | 0 | 0 | 57 |
| `bootstrap` | draft-hardt-aauth-bootstrap-latest at AAuth a99d353cf18aee81d0c5445bac070164fb3b8bc5 | `ebfe4858e9511020ceb498aea997953b8b79594689ce177ba228230c3ceaf872` | 1 | 2 | 2 | 0 | 38 |
| `budgets` | draft-hardt-aauth-budgets-latest at AAuth a99d353cf18aee81d0c5445bac070164fb3b8bc5 | `7a27351888d04a4d1059dd9a261243d0960bcc4d918705641b1d9e68c90d4a4d` | 8 | 11 | 0 | 0 | 72 |
| `interop-profile` | interop-demo-profile at AAuth a99d353cf18aee81d0c5445bac070164fb3b8bc5 | `ee503da3ea6803370cffe03171f600d44bf9c81a05872b2014b01a61982fe195` | 0 | 0 | 0 | 0 | 8 |

## Explicit section dispositions

### `bootstrap/identifier-strategies` — Partial

A caller-owned enrollment store binds each durable-key thumbprint to a stable opaque agent identifier, and ephemeral rotation preserves it; enrollment ceremonies and strategy selection remain deployment-specific.

Evidence:

- `bootstrap_journey_test.go:TestTwoKeyBootstrapIssuesAUsableAgentTokenWithStableInstallIdentity`

### `bootstrap/optional-attestation` — Unsupported

Platform attestation is not implemented.

### `bootstrap/per-platform-enrollment-sketches` — Unsupported

Per-platform enrollment flows are not implemented.

### `bootstrap/per-platform-keys` — Partial

Two-key durable-to-ephemeral rotation and the simpler single-durable-key pattern are executable through caller-custodied Ed25519 signers; platform-specific key generation, protected storage, and attestation remain deployment work.

Evidence:

- `bootstrap_journey_test.go:TestTwoKeyBootstrapIssuesAUsableAgentTokenWithStableInstallIdentity`
- `bootstrap_journey_test.go:TestSingleKeyBootstrapCarriesTheDurableKeyIntoTheAgentToken`

### `bootstrap/refresh-patterns` — Exercised

The reference AP and client execute two-key jkt-jwt refresh and single-key hwk refresh, enforce enrollment and person-server policy, reject replay, and issue verified agent tokens bound to the active request key.

Evidence:

- `bootstrap_journey_test.go:TestTwoKeyBootstrapIssuesAUsableAgentTokenWithStableInstallIdentity`
- `bootstrap_journey_test.go:TestBootstrapRefusesUnknownInstallAndExactRequestReplay`
- `bootstrap_journey_test.go:TestSingleKeyBootstrapCarriesTheDurableKeyIntoTheAgentToken`

### `budgets/aauth-budget-header` — Partial

The public parser and formatter implement remaining, cost, reserved, required, and the optional unit-plus-decimals pair as an RFC 9651 Dictionary, ignore unknown members, and reject negative or contradictory known values. Streaming trailers remain unclaimed.

Evidence:

- `budgets/external_module_test.go:TestBudgetHeaderRoundTripsCurrentResponseSemantics`
- `budget_journey_test.go:TestCurrentFourPartyBudgetJourneyNarrowsEveryIssuanceBoundary`

### `budgets/ambiguous-failure` — Partial

The reference resource retains a reservation across an ambiguous provider failure. For an applied call whose response is lost, reconstruction returns the exact retained JSON result before fresh policy or changed pricing can run. Agent-side conservative accounting when no response or header arrives remains unclaimed.

Evidence:

- `budget_journey_test.go:TestCurrentFourPartyBudgetJourneyNarrowsEveryIssuanceBoundary`

### `budgets/as-token-endpoint` — Partial

In the four-party profile the PS may send its narrowed Budget object to the AS. The AS verifies it against the resource offer and can only narrow it again before issuance; when the PS omits the parameter, the resource offer is its ceiling.

Evidence:

- `budget_journey_test.go:TestCurrentFourPartyBudgetJourneyNarrowsEveryIssuanceBoundary`
- `reference/budgets_test.go:TestAccessServerUsesResourceBudgetWhenPersonServerOmitsNarrowing`

### `budgets/auth-token` — Partial

The Budget companion binds the final grant to exact Core auth-token evidence. The PS and agent reject amount widening or unit and scale substitution against the preceding resource and PS offers.

Evidence:

- `budgets/external_module_test.go:TestBudgetCompanionBindsNarrowedTokenEvidence`
- `budget_journey_test.go:TestCurrentFourPartyBudgetJourneyNarrowsEveryIssuanceBoundary`

### `budgets/authorization-endpoint` — Partial

The reference agent can request one Budget beside scope, and the resource policy may change denomination and lower amount before issuing its resource token. Metadata-driven proactive discovery remains unclaimed.

Evidence:

- `budget_journey_test.go:TestCurrentFourPartyBudgetJourneyNarrowsEveryIssuanceBoundary`

### `budgets/budget-consumed` — Partial

Consumption records are strictly parsed as JTI plus non-negative consumed amount and are exposed to PS and AS Budget policy as defensive evidence. The bounded recent-record selection algorithm remains unclaimed.

Evidence:

- `budgets/external_module_test.go:TestBudgetCompanionBindsNarrowedTokenEvidence`

### `budgets/budget-model` — Partial

The standalone Budgets package owns one exact allocation value and validates a resource-to-PS-to-AS narrowing chain without moving unit or scale. Mission-wide totals, pricing, payment, and usage-counter policy remain unclaimed.

Evidence:

- `budgets/external_module_test.go:TestBudgetValuesNarrowWithoutChangingDenomination`
- `budget_journey_test.go:TestCurrentFourPartyBudgetJourneyNarrowsEveryIssuanceBoundary`

### `budgets/budget-object` — Exercised

The public Budget value strictly requires amount, nonempty unit, and decimals and preserves the resource-selected denomination through narrowing and token projections.

Evidence:

- `budgets/external_module_test.go:TestBudgetValuesNarrowWithoutChangingDenomination`

### `budgets/concurrency` — Exercised

Two concurrent presentations of one metered call cannot both acquire provider execution; a second distinct reservation that would exceed the same auth token's remainder is refused atomically.

Evidence:

- `reference/budget_store_test.go:TestFileBudgetStoreReservesCommitsAndRecoversExactResult`
- `budget_journey_test.go:TestCurrentFourPartyBudgetJourneyNarrowsEveryIssuanceBoundary`

### `budgets/exhaustion` — Partial

A request whose declared maximum exceeds the net remainder is refused before provider execution with 401, a fresh resource-token offer, and an auth-token requirement reason. Zero-remainder and standing reauthorization loops remain unclaimed.

Evidence:

- `budget_journey_test.go:TestCurrentFourPartyBudgetJourneyNarrowsEveryIssuanceBoundary`

### `budgets/narrowing-chain` — Exercised

In one immediate four-party journey the agent requests 10 in its own denomination, the resource settles a 5-unit USD offer, the PS narrows to 3, and the AS narrows to 2. Every boundary rejects amount widening or denomination changes.

Evidence:

- `budget_journey_test.go:TestCurrentFourPartyBudgetJourneyNarrowsEveryIssuanceBoundary`
- `budgets/external_module_test.go:TestBudgetCompanionBindsNarrowedTokenEvidence`

### `budgets/overshoot` — Exercised

The file store maintains committed cost plus outstanding maximum reservations at or below the auth token amount. It reserves before provider invocation, commits actual cost, releases the difference, and rejects over-bound settlement.

Evidence:

- `reference/budget_store_test.go:TestFileBudgetStoreReservesCommitsAndRecoversExactResult`

### `budgets/ps-token-endpoint` — Partial

The PS validates the exact resource Budget and recent consumption before applying a deployment policy that can only narrow the offer. Clarification, interaction, usage-counter lookup, and suggested-budget refusal remain unclaimed.

Evidence:

- `budget_journey_test.go:TestCurrentFourPartyBudgetJourneyNarrowsEveryIssuanceBoundary`

### `budgets/reason-parameter` — Partial

The Core requirement value round-trips an optional auth-token reason token, and the bounded Budget path emits insufficient-budget with its fresh resource token. budget-exhausted is formatted by the same branch but not separately exercised.

Evidence:

- `requirement_test.go:TestAuthTokenRequirementCarriesBudgetReason`
- `budget_journey_test.go:TestCurrentFourPartyBudgetJourneyNarrowsEveryIssuanceBoundary`

### `budgets/required-member` — Exercised

An insufficient-budget refusal reports the exact request maximum as required and the current net remainder in AAuth-Budget before any provider consequence.

Evidence:

- `budget_journey_test.go:TestCurrentFourPartyBudgetJourneyNarrowsEveryIssuanceBoundary`

### `budgets/requires-auth-token` — Exercised

Reference Budget composition is admitted only for an auth-token resource and requires an exact Budget companion on every metered protected request.

Evidence:

- `budget_journey_test.go:TestCurrentFourPartyBudgetJourneyNarrowsEveryIssuanceBoundary`

### `budgets/resource-enforces` — Exercised

The resource, not the PS or AS, atomically reserves and settles the exact Budget carried by the presented auth token and returns the retained cost and remainder.

Evidence:

- `reference/budget_store_test.go:TestFileBudgetStoreReservesCommitsAndRecoversExactResult`
- `budget_journey_test.go:TestCurrentFourPartyBudgetJourneyNarrowsEveryIssuanceBoundary`

### `budgets/resource-token` — Partial

A typed companion binds budget and optional budget_consumed to exact Core resource-token evidence. The exact token and person-token JTI are retained in shared resource-token lineage before release. Usage-window production remains unclaimed.

Evidence:

- `budgets/external_module_test.go:TestBudgetCompanionBindsNarrowedTokenEvidence`
- `reference/resource_token_lineage_store_test.go:TestFileResourceTokenLineageStoreRecoversOneExactAuthorizationLineage`

### `budgets/value-representation` — Exercised

Budget amount and decimals are exact non-negative JSON integers. Floating-point, negative, missing, unknown, case-fold-colliding, and over-15-digit forms are rejected.

Evidence:

- `budgets/external_module_test.go:TestBudgetValuesNarrowWithoutChangingDenomination`

### `core/access-server-federation` — Partial

The four-party path carries one PS-retained person binding through an independently authenticated AS policy decision for immediate, deferred, and upstream-auth-token call-chain authorization. Dynamic trust establishment and richer requirement composition remain open.

Evidence:

- `current_person_token_journey_test.go:TestCurrentFourPartyPersonTokenJourneySurvivesPersonServerRestart`
- `deferred_four_party_journey_test.go:TestCurrentFourPartyDeferredAuthorizationJourney`
- `call_chaining_journey_test.go:TestCurrentCallChainThroughAccessServer`

### `core/agent-tokens/agent-token-usage` — Exercised

Agent tokens are presented through Signature-Key and bound to the signing key during live authorization requests.

Evidence:

- `current_person_token_journey_test.go:TestCurrentFourPartyPersonTokenJourneySurvivesPersonServerRestart`

### `core/agent-tokens/agent-token-verification` — Exercised

Issuer trust, JWT validity, issuer-domain identity binding, confirmation-key binding, and request proof are verified before the supported endpoints proceed.

Evidence:

- `request_security_test.go:TestSignedRequestRejectsConfirmationKeySubstitution`
- `token_identity_internal_test.go:TestAgentTokenRefusesAnIdentifierOutsideTheIssuerDomain`

### `core/as-token-endpoint/as-response` — Partial

The AS returns a current auth token after verifying the sending PS, resource token, agent token, proof key, optional upstream auth token, and policy result. Immediate and deferred results are exercised; payment responses remain open.

Evidence:

- `current_person_token_journey_test.go:TestCurrentFourPartyPersonTokenJourneySurvivesPersonServerRestart`
- `deferred_four_party_journey_test.go:TestCurrentFourPartyDeferredAuthorizationJourney`
- `call_chaining_journey_test.go:TestCurrentCallChainThroughAccessServer`

### `core/as-token-endpoint/auth-token-delivery` — Partial

The PS verifies the AS issuer, audience, confirmation key, directed person, scope, mission, tenant, account, and resource-token expiry ceiling before delivering immediate or deferred grants.

Evidence:

- `current_person_token_journey_test.go:TestCurrentFourPartyPersonTokenJourneySurvivesPersonServerRestart`
- `deferred_four_party_journey_test.go:TestCurrentFourPartyDeferredAuthorizationJourney`

### `core/as-token-endpoint/ps-to-as-token-request` — Partial

The PS signs the AS request under its discovered server key and sends the verified current resource and agent tokens. The exercised federated call-chain adds a separately verified upstream auth token; richer optional request parameters remain open.

Evidence:

- `current_person_token_journey_test.go:TestCurrentFourPartyPersonTokenJourneySurvivesPersonServerRestart`
- `call_chaining_journey_test.go:TestCurrentCallChainThroughAccessServer`

### `core/auth-token-response-verification` — Exercised

The client verifies issuer, audience, confirmation key, sub, ps, mission, tenant, account, requested scope, and the resource-token expiry ceiling before retaining the auth token.

Evidence:

- `current_person_token_journey_test.go:TestCurrentFourPartyPersonTokenJourneySurvivesPersonServerRestart`

### `core/auth-tokens/auth-token-structure` — Exercised

The selected current auth token requires ps and sub, carries the copied mission and tenant context, and omits agent, act, and the removed mission object.

Evidence:

- `current_person_token_journey_test.go:TestCurrentFourPartyPersonTokenJourneySurvivesPersonServerRestart`

### `core/auth-tokens/auth-token-usage` — Exercised

The agent presents the auth token through Signature-Key and signs the protected request with the token's confirmation key; exact proof replay is refused. The automatic missionless path reuses one verified companion-free grant for subsequent calls to the same resource until trusted expiry, then re-enters the person-token and auth-token requirement chain.

Evidence:

- `current_person_token_journey_test.go:TestCurrentFourPartyPersonTokenJourneySurvivesPersonServerRestart`
- `protected_challenge_journey_test.go:TestCurrentProtectedResourceChallengeCompletesOneExactFourPartyCall`

### `core/auth-tokens/auth-token-verification/jwt-trust-verification` — Exercised

The resource verifies current auth-token type, issuer-role discovery, admitted issuer key, signature, time, and HTTPS issuer before policy context is used.

Evidence:

- `current_person_token_journey_test.go:TestCurrentFourPartyPersonTokenJourneySurvivesPersonServerRestart`

### `core/auth-tokens/auth-token-verification/request-context-binding` — Partial

The reference resource verifies audience, configured issuer, confirmation key, and required scope, then passes the verified ps and sub to the host operation. It does not match or establish those values against a resource-owned identity record; that host adapter remains open.

Evidence:

- `current_person_token_journey_test.go:TestCurrentFourPartyPersonTokenJourneySurvivesPersonServerRestart`

### `core/call-chaining` — Exercised

An intermediary presents a current upstream auth token to obtain a new directed person token, then carries that exact upstream authorization through either the person server or a federated access server while the downstream resource receives only current ps/sub authority and the proof key. Every PS and AS receive boundary requires the upstream token confirmation key to equal the verified intermediary key.

Evidence:

- `call_chaining_journey_test.go:TestCurrentCallChainThroughPersonServer`
- `call_chaining_journey_test.go:TestCurrentCallChainThroughAccessServer`
- `call_chaining_journey_test.go:TestCurrentCallChainThroughPersonServerRejectsSubstitutedUpstreamKey`
- `call_chaining_journey_test.go:TestCurrentCallChainThroughAccessServerRejectsSubstitutedUpstreamKey`

### `core/covered-components` — Partial

Current reference requests always cover method, normalized authority, escaped path, the exact query when one is present, and Signature-Key. Body-bearing calls also cover Content-Digest and present Content-Type; endpoint-specific additional-component coverage remains partial.

Evidence:

- `signaturekey/request_external_test.go:TestRequestProofCoversAnExactQueryWhenPresent`
- `protected_challenge_journey_test.go:TestCurrentProtectedResourceChallengeCompletesOneExactFourPartyCall`

### `core/deferred-auth-token` — Partial

One four-party 202 delivery retains the exact body-bearing invocation and its verified person-token request proof before releasing its same-origin pending URL. Store reopen re-verifies that proof, so a canonical request rewrite fails. The first auth token to satisfy the held scope claims a stable consequence key; the exact status, media type, and body are retained before release and replay after terminal-response loss and resource reconstruction without rerunning policy or consequence. Companion-bearing calls, refreshed resource tokens, and deferred PS or AS authorization remain unclaimed.

Evidence:

- `deferred_protected_journey_test.go:TestCurrentDeferredProtectedCallRecoversAfterLostResultAndResourceRestart`
- `reference/deferred_protected_store_test.go:TestFileDeferredProtectedCallStoreRetainsOneExactTerminalResponse`
- `reference/deferred_protected_store_test.go:TestFileDeferredProtectedCallStoreRefusesCanonicalRequestRewrite`

### `core/deferred-responses/deferred-response-state-machine` — Partial

After the caller receives and retains the pending URL, pending, success, denial, expiry, polling refusal, reconstructed server/client continuations, transient issuance and federation retry, and exact terminal-response recovery are exercised for protected-first session authorization and current person-server/access-server authorization. Recovery from loss of the initial 202 response is not implemented because the current wire request carries no stable recovery identity.

Evidence:

- `deferred_access_journey_test.go:TestCurrentResourceManagedDeferredAccessStartsAtProtectedEndpoint`
- `deferred_person_server_journey_test.go:TestCurrentPersonServerDeferredAuthorizationJourney`
- `deferred_four_party_journey_test.go:TestCurrentFourPartyDeferredAuthorizationJourney`

### `core/deferred-responses/initial-request` — Exercised

A protected request signed with an agent token can enter the resource-managed deferred state machine; current person-server and federated access-server token requests can also return signed pending continuations.

Evidence:

- `deferred_access_journey_test.go:TestCurrentResourceManagedDeferredAccessStartsAtProtectedEndpoint`
- `deferred_person_server_journey_test.go:TestCurrentPersonServerDeferredAuthorizationJourney`
- `deferred_four_party_journey_test.go:TestCurrentFourPartyDeferredAuthorizationJourney`

### `core/deferred-responses/pending-response` — Exercised

Pending and slowdown responses carry validated retry information and do not expose terminal authority.

Evidence:

- `deferred_client_test.go:TestAgentEnforcesRetryAfterAndSlowDown`

### `core/deferred-responses/polling-with-get` — Exercised

The supported client performs same-origin signed GET polling with the initiating identity and proof key.

Evidence:

- `deferred_test.go:TestParseDeferredResponseAllowsSameOriginPollingQuery`

### `core/error-response-format` — Partial

Problem Details are implemented, and reference signature-verification failures use the matching 401 Signature-Error header and sig-error URN; endpoint-specific coverage beyond that profile remains incomplete.

Evidence:

- `problem_test.go:TestDecodeProblemResponseRejectsInvalidWireValue`
- `reference/signature_error_test.go:TestResourceReportsSignatureFailuresAsSignatureError`

### `core/freshness-and-replay` — Exercised

The verifier enforces a bounded signature window. Public Agent signing gives independently initiated same-second calls distinct proof identifiers while captured retransmission remains replayable only as the exact same proof. Governance endpoints retain applicable replay decisions across restart, and current protected resources atomically consume exact proof keys in an explicitly supplied replay store whose file adapter refuses the same proof after reopen.

Evidence:

- `http_signature_inline_internal_test.go:TestVerifyRequestRejectsPreflightFailuresBeforeKeyResolution`
- `reference/resource_replay_store_test.go:TestCurrentProtectedResourceDurablyConsumesExactProof`
- `access_client_test.go:TestPublicAgentUsesUniqueProofsForIndependentSameSecondProtectedCalls`
- `governance_restart_test.go:TestPersonServerGovernanceSurvivesRestart`

### `core/identifiers-and-discovery` — Partial

Canonical HTTPS server identifiers and selected metadata discovery documents are implemented; the complete identifier and metadata surface is not.

Evidence:

- `discovery_test.go:TestHTTPKeyResolverUsesAdmittedTwoHopDiscoveryAndCache`

### `core/interaction-chaining` — Unsupported

General chained interaction relay is not implemented.

### `core/mission-approval` — Partial

Immediate approval returns s256, base64url exact mission bytes, approved resources, and resource-keyed person tokens. One pre-release journal makes the exact response recoverable across partial and uncertain child commits; broader lifecycle and deferred approval remains open.

Evidence:

- `current_person_token_journey_test.go:TestCurrentFourPartyPersonTokenJourneySurvivesPersonServerRestart`
- `current_mission_recovery_test.go:TestCurrentMissionIssuanceRecoversExactResponseAcrossStoreBoundaries`

### `core/mission-completion` — Partial

An owning agent can submit the current mission completion action at POST /mission/{mission_s256}; the person server validates the exact summary and active mission, retains a proof-bound approval continuation, and keeps the existing clarification, acceptance, termination, restart, replay, expiry, and rollback behavior. The generic interaction surface and other mission actions remain separate gaps.

Evidence:

- `mission_completion_journey_test.go:TestMissionCompletionClarificationAndAcceptanceSurviveRestart`
- `mission_test.go:TestMissionCompletionValidation`

### `core/mission-creation` — Partial

A current mission proposal is validated before policy, and policy receives the authenticated agent, proof key, token expiry, and person-server binding. The resulting exact digest-bound approval can be recovered after restart. Mission control and broader mission-log behavior remain open; current update and completion actions are covered by their own partial annotations.

Evidence:

- `current_person_token_journey_test.go:TestCurrentFourPartyPersonTokenJourneySurvivesPersonServerRestart`
- `current_mission_recovery_test.go:TestCurrentMissionIssuanceRecoversExactResponseAcrossStoreBoundaries`

### `core/mission-update` — Exercised

An owning agent can submit one current mission update at POST /mission/{mission_s256}; the person server validates the exact Markdown request, evaluates deployment policy with the current defensive mission snapshot, appends an ordered proof-bearing log entry, and returns the update's exact s256. The immutable mission blob and mission s256 do not change. Exact signed replay after person-server restart returns the retained result without a duplicate log entry, while unknown, non-owning, malformed, and terminated requests fail closed.

Evidence:

- `mission_update_journey_test.go:TestCurrentMissionUpdateRoundTripsAndRecoversAfterRestart`
- `mission_test.go:TestMissionUpdateValidationAndResult`

### `core/overview-person-identity` — Exercised

A person-token resource verifies one directed person token and exact request proof, maps the operation's required local policy scope, consumes replay, and runs one host consequence from ps, sub, mission, and tenant continuity without issuing a resource token or auth token.

Evidence:

- `person_token_access_journey_test.go:TestCurrentPersonTokenAccessUsesDirectedIdentityWithoutAuthToken`

### `core/overview-resource-managed` — Exercised

A protected request signed with the agent token enters the resource-managed authorization state machine. An immediate or deferred result returns an opaque proof-bound AAuth-Access credential, and the protected retry presents that credential with an agent-token proof before the operation runs.

Evidence:

- `access_journey_test.go:TestCurrentResourceManagedAccessStartsAtProtectedEndpoint`

### `core/person-token-endpoint` — Partial

Direct issuance retains exact verification records across person-server restart. Mission-bundled issuance recovers one exact response across partial or uncertain journal, person-token, and mission commits. Parent-mediated sub-agent, upstream-auth-token, and chained-sub-agent requests share one typed immediate-or-pending client path. Deferred issuance retains the exact interaction, polling caller and key, target key, resource, parent, upstream and mission context, decision, and precommitted terminal token across PS and agent reconstruction; signed polling returns the same token without rerunning policy or minting. A configured HTTP resolver verifies bounded, unambiguous resource metadata and supplies exact name, description, and access mode to interaction and policy; deferred restart and replay retain that presentation without refetch. A configured resource limiter keys distinct-resource admission by the verified signing agent, admits repeats, and returns typed `429 resource_limit_exceeded` for a new resource beyond its bound. The automatic path discovers issuer-matched person-server metadata, caches missionless tokens until expiry, and reacquires lazily. Durable limiter continuity across restart and processes remains deployment-owned.

Evidence:

- `current_person_token_journey_test.go:TestCurrentFourPartyPersonTokenJourneySurvivesPersonServerRestart`
- `current_mission_recovery_test.go:TestCurrentMissionIssuanceRecoversExactResponseAcrossStoreBoundaries`
- `subagent_journey_test.go:TestCurrentParentMediatedSubagentAuthorization`
- `call_chaining_journey_test.go:TestCurrentCallChainThroughPersonServer`
- `person_token_access_journey_test.go:TestAgentFollowsPersonTokenRequirementThroughDiscoveredPersonServer`
- `deferred_person_server_journey_test.go:TestCurrentPersonServerDeferredAuthorizationJourney`
- `call_chaining_journey_test.go:TestCurrentCallChainThroughAccessServer`
- `reference/resource_metadata_test.go:TestHTTPResourceMetadataResolverReturnsVerifiedPresentation`
- `reference/resource_metadata_test.go:TestHTTPResourceMetadataResolverClassifiesRefusals`
- `reference/resource_metadata_test.go:TestResourceMetadataFailuresUseTokenEndpointProblemCodes`
- `reference/person_token_resource_limit_test.go:TestMemoryPersonTokenResourceLimiterAllowsRepeatsAndSeparatesAgents`
- `reference/person_token_resource_limit_test.go:TestMemoryPersonTokenResourceLimiterRejectsInvalidConfigurationAndInput`

### `core/person-token-structure` — Exercised

The selected Ed25519 profile emits every required person-token claim, supports mission_s256 and tenant, caps lifetime at one hour, and refuses scope or account.

Evidence:

- `current_person_token_journey_test.go:TestCurrentFourPartyPersonTokenJourneySurvivesPersonServerRestart`
- `person_token_internal_test.go:TestVerifyPersonTokenRejectsAuthorizationClaims`

### `core/person-token-usage` — Exercised

An agent presents aa-person+jwt through Signature-Key and signs either an authorization request or one exact person-identity protected call with the token's confirmation key.

Evidence:

- `current_person_token_journey_test.go:TestCurrentFourPartyPersonTokenJourneySurvivesPersonServerRestart`
- `person_token_access_journey_test.go:TestCurrentPersonTokenAccessUsesDirectedIdentityWithoutAuthToken`

### `core/person-token-verification` — Exercised

Verification covers type, discovery role, admitted issuer key, signature, time, resource audience, and request confirmation key, with negative controls for each context boundary.

Evidence:

- `current_person_token_journey_test.go:TestCurrentFourPartyPersonTokenJourneySurvivesPersonServerRestart`
- `person_token_access_journey_test.go:TestCurrentPersonTokenAccessUsesDirectedIdentityWithoutAuthToken`

### `core/ps-token-endpoint/agent-token-request` — Partial

The current request is agent-token signed, key-bound to the resource token, and verified against retained person-token custody. Direct, parent-mediated sub-agent, and upstream-auth-token forms are exercised; claims, clarification, and payment composition remain open.

Evidence:

- `current_person_token_journey_test.go:TestCurrentFourPartyPersonTokenJourneySurvivesPersonServerRestart`
- `subagent_journey_test.go:TestCurrentParentMediatedSubagentAuthorization`
- `call_chaining_journey_test.go:TestCurrentCallChainThroughPersonServer`

### `core/ps-token-endpoint/ps-response` — Partial

The direct and federated paths return a current auth token after PS and optional AS policy, including immediate and deferred decisions. Current claims, clarification, payment, and broader interaction composition remain open.

Evidence:

- `current_person_token_journey_test.go:TestCurrentFourPartyPersonTokenJourneySurvivesPersonServerRestart`
- `deferred_person_server_journey_test.go:TestCurrentPersonServerDeferredAuthorizationJourney`
- `deferred_four_party_journey_test.go:TestCurrentFourPartyDeferredAuthorizationJourney`

### `core/requirement-auth-token` — Partial

An auth-token resource accepts either a person-token-signed protected call or an agent-token-signed entry that first receives requirement=person-token. After the directed person token is presented, it maps the required scope and performs no protected consequence before returning either the baseline 401 or stateful 202 with a verified resource token. The reference agent exchanges it through the ordinary PS and AS path and completes the exact invocation. Existing-auth-token step-up remains unclaimed.

Evidence:

- `protected_challenge_journey_test.go:TestCurrentProtectedResourceChallengeCompletesOneExactFourPartyCall`
- `deferred_protected_journey_test.go:TestCurrentDeferredProtectedCallRecoversAfterLostResultAndResourceRestart`

### `core/requirement-person-token` — Exercised

A person-token or auth-token resource accepts an agent-token-signed call only far enough to return requirement=person-token without running policy or consequence. The reference agent verifies its own token, discovers the named person server's current endpoints, obtains a resource-directed person token, and retries the exact call. An agent with no person server refuses before contacting one.

Evidence:

- `person_token_access_journey_test.go:TestAgentFollowsPersonTokenRequirementThroughDiscoveredPersonServer`
- `protected_challenge_journey_test.go:TestCurrentProtectedResourceChallengeCompletesOneExactFourPartyCall`

### `core/requirement-responses/aauth-requirement-header-structure` — Exercised

The supported requirement header is parsed and serialized as a structured field with strict wire-value validation.

Evidence:

- `requirement_test.go:TestInteractionRequirementStructuredFieldRoundTrip`

### `core/requirement-responses/approval-pending` — Exercised

Approval-pending requirements drive signed polling with enforced retry cadence in the supported flows.

Evidence:

- `deferred_client_test.go:TestAgentEnforcesRetryAfterAndSlowDown`

### `core/requirement-responses/interaction-required` — Partial

The supported session-token resource authorization continuation represents an interaction requirement; the current interaction family remains incomplete.

Evidence:

- `deferred_access_journey_test.go:TestCurrentResourceManagedDeferredAccessStartsAtProtectedEndpoint`

### `core/resource-tokens/authorization-endpoint-request` — Exercised

The current client signs a scope request with a resource-directed person token, and the resource verifies that token before issuing a resource token.

Evidence:

- `current_person_token_journey_test.go:TestCurrentFourPartyPersonTokenJourneySurvivesPersonServerRestart`

### `core/resource-tokens/authorization-endpoint-responses/response-with-resource-token` — Exercised

A four-party resource returns a verified resource token whose audience is its AS and whose person and mission context comes from the presented person token.

Evidence:

- `current_person_token_journey_test.go:TestCurrentFourPartyPersonTokenJourneySurvivesPersonServerRestart`

### `core/resource-tokens/resource-token/resource-challenge-verification` — Partial

The client verifies resource issuer, proof key, ps, sub, presented_jti, mission_s256, tenant, account, scope shape, and expiry on proactive, protected-resource 401, and held-invocation 202 resource tokens before contacting the PS. Distinct-server journeys complete the exact protected call under the resulting grant. R3 challenge selection and step-up from an existing auth token remain open.

Evidence:

- `current_person_token_journey_test.go:TestCurrentFourPartyPersonTokenJourneySurvivesPersonServerRestart`
- `protected_challenge_journey_test.go:TestCurrentProtectedResourceChallengeCompletesOneExactFourPartyCall`
- `reference/protected_challenge_test.go:TestAgentRejectsSubstitutedProtectedResourceChallengeContext`
- `deferred_protected_journey_test.go:TestCurrentDeferredProtectedCallRecoversAfterLostResultAndResourceRestart`

### `core/resource-tokens/resource-token/resource-token-structure` — Exercised

The current resource token carries ps, sub, presented_jti, agent_jkt, scope, mission_s256, and tenant while omitting agent and the removed mission object.

Evidence:

- `current_person_token_journey_test.go:TestCurrentFourPartyPersonTokenJourneySurvivesPersonServerRestart`

### `core/resource-tokens/resource-token/resource-token-verification` — Partial

The PS resolves presented_jti from durable custody and compares ps, resource, sub, mission_s256, and tenant; the AS verifies that ps is the signing PS. Parent-mediated sub-agent and upstream-auth-token call-chain journeys exercise the same current resource-token checks without restoring agent or actor claims.

Evidence:

- `current_person_token_journey_test.go:TestCurrentFourPartyPersonTokenJourneySurvivesPersonServerRestart`
- `subagent_journey_test.go:TestCurrentParentMediatedSubagentAuthorization`
- `call_chaining_journey_test.go:TestCurrentCallChainThroughAccessServer`

### `core/security-considerations/tls-requirements` — Exercised

The runnable person-server profile enforces TLS 1.3 and a certificate covering its HTTPS identifier.

Evidence:

- `cmd/aauth-reference/main_test.go:TestPersonProcessServesDurableGovernanceOverTLS`

### `core/signature-algorithms` — Exercised

Phase 1 emits and validates fully specified Ed25519 on active JWT and JWK surfaces and rejects polymorphic EdDSA; current editor token topology remains unclaimed.

Evidence:

- `draft11_wire_test.go:TestDraft11Ed25519WireJourney`

### `core/sub-agents/parent-mediated-authorization` — Exercised

The verified parent requests the sub-agent's resource-directed person token and mediates immediate or deferred authorization, while the resulting auth token and protected request are bound to the sub-agent confirmation key and current ps/sub authority.

Evidence:

- `subagent_journey_test.go:TestCurrentParentMediatedSubagentAuthorization`

### `core/sub-agents/single-level-depth` — Exercised

The exercised profile admits one direct parent/sub-agent relationship and refuses the sub-agent's attempt to exchange its resource token without parent mediation.

Evidence:

- `subagent_journey_test.go:TestCurrentParentMediatedSubagentAuthorization`

### `core/sub-agents/sub-agent-identity` — Exercised

A sub-agent has its own current agent token, identifier, and confirmation key, with the direct parent bound by the verified token rather than inferred from auth-token subject claims.

Evidence:

- `subagent_journey_test.go:TestCurrentParentMediatedSubagentAuthorization`

### `core/third-party-login` — Unsupported

Third-party login is not implemented.

### `core/token-revocation` — Partial

The reference Person Server, auth-token Resource, and Access Server implement the current signed (iss, jti) revocation request for observed credentials. Person Server accepts its existing agent-token caller and a server-signed issuer caller; a checksum-bound file store retains observations, revocation state, and proof replay keys; issuer-or-deployment policy authorizes each request; repeated new proofs are idempotent; restart preserves refusal before the protected consequence for revoked agent and auth tokens, and Access Server issuance records each auth token before release. Mission-wide propagation and provider fan-out remain open.

Evidence:

- `revocation_journey_test.go:TestCurrentAgentTokenRevocationSurvivesPersonServerRestart`
- `resource_revocation_journey_test.go:TestCurrentAuthTokenRevocationSurvivesResourceRestart`
- `access_server_revocation_journey_test.go:TestCurrentAccessServerAuthTokenRevocationSurvivesRestart`
- `reference/token_revocation_test.go:TestFileTokenRevocationStoreSurvivesRestart`
- `revocation_test.go:TestTokenRevocationRequestValidation`

### `core/verification` — Partial

Phase 1 maps unsupported algorithms, unsupported schemes, and issuer metadata failures to the current editor typed authentication envelope; Phase-2 credential topology is unclaimed.

Evidence:

- `draft11_wire_test.go:TestDraft08SignatureKeyFailuresAreTypedAndNegotiable`

### `events/ap-to-agent` — Partial

A non-normative host adapter advances one exact AP inbox event through durable agent pending, dispatched, completed, or refused states. The agent independently validates token, context, digest-pinned contract, media type, payload digest, JSON, and schema before action; terminal custody precedes AP acknowledgement and unknown outcomes remain dispatched for reconciliation. No AP-to-agent wire protocol is claimed.

Evidence:

- `reference/events_agent_test.go:TestAgentEventProcessingReconcilesDispatchedUnknownHonestly`
- `reference/events_agent_test.go:TestEventAdapterAcknowledgesOnlyDurableTerminalDisposition`
- `reference/events_agent_test.go:TestAgentEventRefusalMatrixSurvivesStoreReconstruction`
- `reference/events_agent_payload_test.go:TestAgentEventPayloadIndependentlyValidatesAndReachesExactAction`
- `reference/events_agent_payload_test.go:TestEventAdapterPayloadAcknowledgesOnlyAfterTerminalAgentValidation`

### `events/event-delivery` — Partial

Resource-to-AP delivery retains one exact event token and payload pair before send, covers content type and digest in fresh HTTP proof, atomically commits one use and exact inbox custody before 202, and treats an exact-pair 429 retry after an unknown outcome as deterministic settlement. Invalid or different input after exhaustion cannot create a second acceptance or state mutation.

Evidence:

- `reference/events_delivery_test.go:TestAPEventEndpointCommitsInboxBefore202`
- `reference/events_delivery_test.go:TestAPEventEndpointSerializesConcurrentFinalUseAcrossReconstruction`
- `events_journey_test.go:TestPublicSubscriptionEventSurvivesHostReconstruction`
- `reference/events_payload_delivery_test.go:TestEventPayloadDeliveryAPProofRefusalsLeaveUseAndInboxUnchanged`
- `reference/events_protected_journey_test.go:TestProtectedPayloadEventSurvivesHostReconstruction`

### `events/event-discovery` — Partial

Agent-provider event endpoint discovery is exercised through admitted agent metadata with HTTP freshness, cache prohibition, rotation, and strict endpoint validation. The protected profile adds admitted exact AsyncAPI 3.0.0 JSON discovery with one local receive-operation/message/schema subset; general AsyncAPI and a standardized AP-to-agent delivery description remain open.

Evidence:

- `discovery_events_test.go:TestAgentEventMetadataUsesAdmittedHTTPFreshness`
- `reference/events_provider_test.go:TestAgentProviderEventsMetadataRotatesWithHTTPFreshness`
- `events_discovery_test.go:TestEventsContractResolverUsesAdmittedExactHTTPFreshness`
- `events/asyncapi_external_test.go:TestEventsAsyncAPIRejectsUnsupportedOrAmbiguousDocuments`

### `events/event-token` — Partial

The strict aa-event+jwt remains payload-free and carries resource issuer, resource discovery document, agent audience, event id, issued-at, and expiry claims. The selected protected profile carries one exact JSON payload as the direct HTTP body rather than a token claim.

Evidence:

- `events_test.go:TestSubscribeAndEventClaimsRejectRequiredFieldMutations`
- `events_journey_test.go:TestPublicSubscriptionEventSurvivesHostReconstruction`
- `reference/events_payload_delivery_test.go:TestEventPayloadDeliveryRetainsExactPairAndReconcilesLost202`

### `events/protocol-overview` — Partial

The selected public single-use payload-free profile and one protected one-use direct JSON profile are qualified across independently reconstructed AP, resource, and agent hosts. Multi-event replay identity and complete Events conformance remain open.

Evidence:

- `events_journey_test.go:TestPublicSubscriptionEventSurvivesHostReconstruction`
- `reference/events_protected_journey_test.go:TestProtectedPayloadEventSurvivesHostReconstruction`

### `events/subscribe-token` — Partial

Strict subscribe-token issue and verification are exercised with the required issuer, aa-subscribe+jwt type, agent discovery document, subject, audience, embedded agent key, event id, issued-at and expiry claims; the selected public profile requires max_uses:1.

Evidence:

- `events_test.go:TestSubscribeAndEventClaimsRejectRequiredFieldMutations`
- `reference/events_provider_test.go:TestAgentProviderIssuesOnlyAfterDurableSubscriptionCommit`

### `events/subscription-registration` — Partial

Public registration requires the exact subscribe token, embedded agent proof key, max_uses:1, and a future active window. The selected protected profile adds a digest-only opaque ticket bound to authenticated operation and contract context; bodyless signed validation, ticket consumption, and subscription creation are one atomic transition. Agent-local context remains agent-host custody.

Evidence:

- `reference/events_registration_test.go:TestPublicEventRegistrationRequiresExactSubscribeTokenAndAgentProof`
- `reference/events_registration_test.go:TestPublicEventRegistrationRejectsRawSubscribeMutationsWithoutCustody`
- `reference/events_registration_test.go:TestPublicEventRegistrationCustodySurvivesReconstruction`
- `reference/events_ticket_test.go:TestProtectedEventRegistrationConsumesTicketAndCreatesSubscriptionAtomically`
- `reference/events_ticket_test.go:TestProtectedEventTicketIssueRejectsIncompleteOrCollidingAuthority`

### `r3/auth-token-extensions` — Partial

R3 validation binds r3_uri, r3_s256, r3_granted, and optional r3_per_call to exact Core auth-token evidence; it validates one shared vocabulary, semantic operation shapes, and disjoint granted and per-call sets. One bounded direct and 401 per-call resource-enforcement path is claimed separately.

Evidence:

- `r3/token_external_test.go:TestR3TokenResultsBindExactCoreEvidence`
- `r3/token_external_test.go:TestR3AuthTokenValidationRefusesMalformedMembers`
- `r3/external_module_test.go:TestCleanExternalModuleValidatesR3DocumentsAndTokenEvidence`

### `r3/authorization-endpoint-extensions/request` — Partial

The reference agent submits one validated r3_operations set with the current authorization request. The four-party profile requires the resource-selected document to contain exactly that set; account selection and multiple-definition composition are not exercised.

Evidence:

- `r3_direct_journey_test.go:TestCurrentFourPartyR3JourneySurvivesReconstruction`
- `reference/r3_direct_test.go:TestR3DocumentSelectionIsExactlyTheAgentRequest`

### `r3/authorization-endpoint-extensions/response` — Partial

The direct four-party profile returns a resource token carrying the exact HTTPS r3_uri and unpadded exact-byte r3_s256 selected for the requested operations. Non-R3 and multiple-definition response behavior remains outside this claim.

Evidence:

- `r3_direct_journey_test.go:TestCurrentFourPartyR3JourneySurvivesReconstruction`

### `r3/content-addressing` — Partial

R3 S256 computes unpadded base64url SHA-256 over the exact document bytes without canonicalization. Durable byte serving and hash-keyed cache custody are not implemented by this value layer.

Evidence:

- `r3/document_internal_test.go:TestR3DocumentRetainsExactIdentityAndCurrentNeutralShape`

### `r3/per-call-proposals/flow` — Partial

One immediate four-party 401 flow retains the exact proposal for PS and AS retrieval, issues an exact one-operation approval, verifies the retried parameters, admits only one in-process provider call, retains its JSON result before response, and recovers the result after loss and resource reconstruction. Deferred 202 delivery remains unclaimed.

Evidence:

- `r3_direct_journey_test.go:TestCurrentFourPartyR3JourneySurvivesReconstruction`
- `reference/r3_per_call_store_test.go:TestFileR3PerCallStoreRecoversPendingAndCompleteExecution`

### `r3/per-call-proposals/large-and-sensitive-payloads` — Partial

A proposal may replace one exact parameter value with an s256 digest plus bounded display metadata. The retry hashes the exact presented bytes and rejects substitution before provider execution. Deployment policy decides which fields remain inline and how excerpts are produced.

Evidence:

- `r3/per_call_external_test.go:TestPerCallProposalMatchesInlineAndDigestParameters`
- `r3_direct_journey_test.go:TestCurrentFourPartyR3JourneySurvivesReconstruction`

### `r3/per-call-proposals/proposal-document` — Partial

The public R3 package validates one-operation per-call proposals with a required parameters object. Inline JSON values compare structurally; digest objects require an unpadded SHA-256 value and admit an optional excerpt and valid media type. Broader vocabulary-specific parameter projection remains deployment-owned.

Evidence:

- `r3/per_call_external_test.go:TestPerCallProposalMatchesInlineAndDigestParameters`
- `r3/per_call_external_test.go:TestPerCallProposalRejectsAmbiguousParameterForms`

### `r3/r3-document-access-restriction` — Partial

Before releasing an initial or per-call resource token, the resource atomically retains the exact document bytes with the precise PS and AS reader identities. The reconstructed resource serves them only after a fresh verified jwks_uri request from a retained reader. Three-party reader composition remains unclaimed.

Evidence:

- `reference/r3_document_store_test.go:TestFileR3DocumentStoreRetainsAuthorizedReadersAcrossRestart`
- `r3_direct_journey_test.go:TestCurrentFourPartyR3JourneySurvivesReconstruction`

### `r3/r3-document/fields` — Partial

The public R3 package strictly parses the current vocabulary, operations, account, parameters, and display fields and returns defensive operation-set projections. Serving and policy remain separate role compositions; one bounded reference path is claimed below.

Evidence:

- `r3/document_internal_test.go:TestR3DocumentRetainsExactIdentityAndCurrentNeutralShape`
- `r3/document_internal_test.go:TestParseR3DocumentRejectsRemovedAndMalformedMembers`

### `r3/r3-document/resource-token-extensions` — Partial

Core verification retains applicable r3_uri and r3_s256 members only as exact sealed token evidence; R3 validation then requires an absolute HTTPS document URI and an unpadded SHA-256 digest bound to that evidence. The bounded direct retrieval and policy composition is claimed separately below.

Evidence:

- `r3/token_external_test.go:TestR3TokenResultsBindExactCoreEvidence`
- `r3/token_external_test.go:TestR3AuthTokenValidationRefusesMalformedMembers`

### `r3/r3-processing` — Partial

In one immediate four-party profile, the PS and AS independently fetch the exact document with signed server identities and verify its hash before review or grant policy. Direct AS audit and response retention are atomic; caching, deferred authorization, and three-party deployment remain unclaimed.

Evidence:

- `r3_direct_journey_test.go:TestCurrentFourPartyR3JourneySurvivesReconstruction`

### `r3/r3-processing/as-processing` — Partial

The AS verifies the resource token, signed document retrieval, exact document hash, deployment grant policy, and grant membership before atomically retaining the required audit fields with the exact r3_granted token response. Exact retry after a lost response and AS reconstruction returns the same record without rerunning trust or grant policy. Caching and deferred R3 remain unclaimed.

Evidence:

- `r3_direct_journey_test.go:TestCurrentFourPartyR3JourneySurvivesReconstruction`

### `r3/resource-enforcement` — Partial

A configured R3 resource maps each protected request to exactly one operation. It serves r3_granted directly, challenges r3_per_call before consequence, and refuses ungranted operations. The bounded 401 per-call path verifies exact approved parameters, executes once, and replays its retained result; deferred 202 delivery remains unclaimed.

Evidence:

- `r3_direct_journey_test.go:TestCurrentFourPartyR3JourneySurvivesReconstruction`

### `r3/security-considerations/audit-log-integrity` — Exercised

For immediate four-party issuance, the AS atomically commits the exact auth-token response with r3_uri, r3_s256, PS, subject, agent key thumbprint, agent identity, resource and token identifiers, and issuance instant before release. Exact replay after a lost response and server reconstruction returns that record without policy re-execution; a conflicting record refuses.

Evidence:

- `r3_direct_journey_test.go:TestCurrentFourPartyR3JourneySurvivesReconstruction`

### `r3/security-considerations/grant-enforcement` — Partial

The four-party profile validates that every AS direct or per-call classification belongs to the verified document and stays within the agent's exact request. The resource serves direct operations, challenges per-call operations, and executes an approved concrete call once before replaying its retained result.

Evidence:

- `r3_direct_journey_test.go:TestCurrentFourPartyR3JourneySurvivesReconstruction`
- `r3/token_external_test.go:TestR3AuthorizationGrantPartitionsTheExactAgentRequest`

### `r3/security-considerations/hash-verification` — Exercised

Both four-party policy roles verify SHA-256 over the exact fetched bytes against r3_s256 and refuse changed bytes before review, grant issuance, or protected consequence.

Evidence:

- `r3_direct_journey_test.go:TestCurrentFourPartyR3JourneySurvivesReconstruction`
- `r3/token_external_test.go:TestR3AuthorizationGrantPartitionsTheExactAgentRequest`

### `r3/vocabularies` — Partial

The public R3 package validates semantic operation sets for all seven standard vocabulary identifiers and admits structurally valid third-party vocabulary URIs. It does not discover authoritative service definitions or prove that a declared operation exists there.

Evidence:

- `r3/document_internal_test.go:TestR3StandardVocabularyOperationShapes`
- `r3/document_internal_test.go:TestR3OperationSetUsesSemanticSetEquality`

### `signature-key/accept-signature-scheme-and-accept-signature-alg-response-headers` — Exercised

Signature failures carry accepted algorithms and schemes in separate Accept-Signature-Alg and Accept-Signature-Scheme headers, never in supported_algorithms.

Evidence:

- `draft11_wire_test.go:TestDraft08SignatureKeyFailuresAreTypedAndNegotiable`
- `reference/draft11_wire_internal_test.go:TestSignatureFailureEmitsDraft08NegotiationHeaders`

### `signature-key/algorithm-determination` — Exercised

Every active conveyed Ed25519 JWK requires alg=Ed25519; missing, polymorphic, or structurally inconsistent keys are rejected.

Evidence:

- `draft11_wire_test.go:TestDraft11Ed25519WireJourney`

### `signature-key/issuer_mismatch` — Exercised

Metadata whose issuer differs from its discovery identity is rejected with issuer_mismatch from discovery through request verification.

Evidence:

- `draft11_wire_test.go:TestDraft08HTTPDiscoveryClassifiesMissingAndMismatchedIssuer`

### `signature-key/issuer_missing` — Exercised

Metadata without issuer is rejected with issuer_missing from discovery through request verification.

Evidence:

- `draft11_wire_test.go:TestDraft08HTTPDiscoveryClassifiesMissingAndMismatchedIssuer`

### `signature-key/jwks-uri-scheme` — Exercised

JWKS URI resolution selects the exact requested kid before validating only that JWK, so unrelated future or malformed siblings do not deny a valid selected Ed25519 key; selected unsupported algorithms retain the negotiable unsupported_algorithm envelope.

Evidence:

- `draft08_discovery_test.go:TestDraft08JWKSValidatesOnlyTheExactRequestedKid`
- `draft08_discovery_test.go:TestDraft08SelectedUnsupportedJWKSAlgorithmUsesNegotiableEnvelope`

### `signature-key/signature-key-http-request-header` — Partial

The active verifier parses Signature-Key as an RFC 8941 Dictionary, selects the sig Item and Token before dispatch, combines field lines, ignores unselected members, rejects non-string known-scheme parameters and non-RFC string escapes, and supports the selected single-signature schemes; general multiple-signature verification remains unclaimed.

Evidence:

- `signature_key_structured_internal_test.go:TestSignatureKeyUsesRFC8941DictionarySelection`
- `signature_key_structured_internal_test.go:TestSignatureKeyAcceptsOnlyRFC8941StringEscapes`
- `signature_key_structured_internal_test.go:TestSignatureKeyRejectsMalformedStructuredMembers`
- `signature_key_structured_internal_test.go:TestSignatureKeySplitFieldLinesAreAllCoveredByTheSignature`

### `signature-key/signature-key-http-request-header/header-web-key-hwk` — Exercised

The active hwk serializer and verifier carry and require the fully specified Ed25519 alg parameter.

Evidence:

- `draft11_wire_test.go:TestDraft11Ed25519WireJourney`

### `signature-key/signature-key-http-request-header/self-issued-jwt-self-jwt` — Partial

The selected self-jwt profile verifies the compact JWT and its HTTP Message Signature with the same discovered key (Ed25519); broader algorithm and multi-signature profiles remain unclaimed.

Evidence:

- `http_signature_self_jwt_test.go:TestSelfJWTUsesOneDiscoveredKeyForBothProofs`
- `events_journey_test.go:TestPublicSubscriptionEventSurvivesHostReconstruction`

### `signature-key/signature-key-http-request-header/x-509-certificates-x509` — Unsupported

The x509 scheme is not implemented.

### `signature-key/unsupported-scheme` — Exercised

A selected unknown or disallowed Signature-Key scheme is rejected as unsupported_scheme with the accepted scheme set available for HTTP negotiation.

Evidence:

- `draft11_wire_test.go:TestDraft08SignatureKeyFailuresAreTypedAndNegotiable`

### `signature-key/unsupported_algorithm` — Exercised

A selected JWK with missing, polymorphic, or unsupported alg is rejected as unsupported_algorithm with Accept-Signature-Alg naming Ed25519; malformed Ed25519 material remains invalid_key.

Evidence:

- `draft08_discovery_test.go:TestDraft08SelectedUnsupportedJWKSAlgorithmUsesNegotiableEnvelope`
- `draft11_wire_test.go:TestDraft08SignatureKeyFailuresAreTypedAndNegotiable`
