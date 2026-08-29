# AAuth Go source coverage

This generated source coverage is not a full-conformance claim. It binds the implementation's explicit claims and omissions to pinned source bytes and executable Go evidence.

Profile: AAuth Go bounded current-editor profile: draft-hardt-oauth-aauth-protocol-latest, draft-hardt-httpbis-signature-key-latest, draft-hardt-aauth-r3-latest, draft-hardt-aauth-events-latest, draft-hardt-aauth-bootstrap-latest, draft-hardt-aauth-budgets-latest, and interop-demo-profile at AAuth a99d353cf18aee81d0c5445bac070164fb3b8bc5 and HTTP Signature Keys 0ff751b571e7fe51336bcc1e526954a202317cc0; every unsupported current behavior remains explicit or unclaimed

## Summary

| Status | Sections |
| --- | ---: |
| Exercised | 34 |
| Partial | 28 |
| Unsupported | 6 |
| Informational | 0 |
| Unclaimed | 532 |

`Unclaimed` means this module makes no section-level implementation claim. It is visible work, not implicit support. `Exercised` names the supported behavior claimed for that section and binds it to a runnable test; it does not silently claim behavior outside the written claim. `Partial` names an intentionally incomplete implementation, and `Unsupported` names an explicit omission.

## Pinned sources

| Source | Revision | SHA-256 | Exercised | Partial | Unsupported | Informational | Unclaimed |
| --- | --- | --- | ---: | ---: | ---: | ---: | ---: |
| `core` | draft-hardt-oauth-aauth-protocol-latest at AAuth a99d353cf18aee81d0c5445bac070164fb3b8bc5 | `c984278f21e3931f0cc272d6768b84bcc471f8ab4a1a1922dd92940a91df7e19` | 25 | 17 | 3 | 0 | 211 |
| `signature-key` | draft-hardt-httpbis-signature-key-latest at signature-key 0ff751b571e7fe51336bcc1e526954a202317cc0 | `335c6164569fc5b21aae7930c83c4088e4c02b857f9f3acee8335f16f23d66cb` | 8 | 2 | 1 | 0 | 71 |
| `r3` | draft-hardt-aauth-r3-latest at AAuth a99d353cf18aee81d0c5445bac070164fb3b8bc5 | `dd768a3b7417c45c0028f2750a50173670fd84c8f432e54ba94799ca93621760` | 0 | 0 | 0 | 0 | 56 |
| `events` | draft-hardt-aauth-events-latest at AAuth a99d353cf18aee81d0c5445bac070164fb3b8bc5 | `6ac4f1c649172a359a6ef32380b189a4edcd9855014bbb03fefe096b74802eb0` | 0 | 7 | 0 | 0 | 57 |
| `bootstrap` | draft-hardt-aauth-bootstrap-latest at AAuth a99d353cf18aee81d0c5445bac070164fb3b8bc5 | `ebfe4858e9511020ceb498aea997953b8b79594689ce177ba228230c3ceaf872` | 1 | 2 | 2 | 0 | 38 |
| `budgets` | draft-hardt-aauth-budgets-latest at AAuth a99d353cf18aee81d0c5445bac070164fb3b8bc5 | `7a27351888d04a4d1059dd9a261243d0960bcc4d918705641b1d9e68c90d4a4d` | 0 | 0 | 0 | 0 | 91 |
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

The agent presents the auth token through Signature-Key and signs the protected request with the token's confirmation key; exact proof replay is refused.

Evidence:

- `current_person_token_journey_test.go:TestCurrentFourPartyPersonTokenJourneySurvivesPersonServerRestart`

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

### `core/mission-creation` — Partial

A current mission proposal is validated before policy, and policy receives the authenticated agent, proof key, token expiry, and person-server binding. The resulting exact digest-bound approval can be recovered after restart. Current mission update, completion, control, and log behavior remains open.

Evidence:

- `current_person_token_journey_test.go:TestCurrentFourPartyPersonTokenJourneySurvivesPersonServerRestart`
- `current_mission_recovery_test.go:TestCurrentMissionIssuanceRecoversExactResponseAcrossStoreBoundaries`

### `core/overview-resource-managed` — Exercised

A protected request signed with the agent token enters the resource-managed authorization state machine. An immediate or deferred result returns an opaque proof-bound AAuth-Access credential, and the protected retry presents that credential with an agent-token proof before the operation runs.

Evidence:

- `access_journey_test.go:TestCurrentResourceManagedAccessStartsAtProtectedEndpoint`

### `core/person-token-endpoint` — Partial

Direct issuance retains exact verification records across person-server restart. Mission-bundled issuance recovers one exact response across partial or uncertain journal, person-token, and mission commits. The endpoint also verifies parent-mediated sub-agent and upstream-auth-token requests before issuing a resource-directed current person token. Deferred person-token issuance and metadata-fetch behavior remain open.

Evidence:

- `current_person_token_journey_test.go:TestCurrentFourPartyPersonTokenJourneySurvivesPersonServerRestart`
- `current_mission_recovery_test.go:TestCurrentMissionIssuanceRecoversExactResponseAcrossStoreBoundaries`
- `subagent_journey_test.go:TestCurrentParentMediatedSubagentAuthorization`
- `call_chaining_journey_test.go:TestCurrentCallChainThroughPersonServer`

### `core/person-token-structure` — Exercised

The selected Ed25519 profile emits every required person-token claim, supports mission_s256 and tenant, caps lifetime at one hour, and refuses scope or account.

Evidence:

- `current_person_token_journey_test.go:TestCurrentFourPartyPersonTokenJourneySurvivesPersonServerRestart`
- `person_token_internal_test.go:TestVerifyPersonTokenRejectsAuthorizationClaims`

### `core/person-token-usage` — Exercised

An agent presents aa-person+jwt through Signature-Key and signs the authorization request with the token's confirmation key.

Evidence:

- `current_person_token_journey_test.go:TestCurrentFourPartyPersonTokenJourneySurvivesPersonServerRestart`

### `core/person-token-verification` — Exercised

Verification covers type, discovery role, admitted issuer key, signature, time, resource audience, and request confirmation key, with negative controls for each context boundary.

Evidence:

- `current_person_token_journey_test.go:TestCurrentFourPartyPersonTokenJourneySurvivesPersonServerRestart`

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

The client checks a proactive authorization response's resource issuer, proof key, ps, sub, presented_jti, mission_s256, and tenant against the person token it presented, including a cross-session substitution control. Extracting and verifying a resource token from a protected-resource 401 challenge remains open.

Evidence:

- `current_person_token_journey_test.go:TestCurrentFourPartyPersonTokenJourneySurvivesPersonServerRestart`

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

### `core/token-revocation` — Unsupported

Token revocation is not implemented.

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
