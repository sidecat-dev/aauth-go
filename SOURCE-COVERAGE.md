# AAuth Go source coverage

This generated source coverage is not a full-conformance claim. It binds the implementation's explicit claims and omissions to pinned source bytes and executable Go evidence.

Profile: AAuth Go maintained supported profile

## Summary

| Status | Sections |
| --- | ---: |
| Exercised | 54 |
| Partial | 35 |
| Unsupported | 7 |
| Informational | 0 |
| Unclaimed | 369 |

`Unclaimed` means this module makes no section-level implementation claim. It is visible work, not implicit support. `Exercised` names the supported behavior claimed for that section and binds it to a runnable test; it does not silently claim behavior outside the written claim. `Partial` names an intentionally incomplete implementation, and `Unsupported` names an explicit omission.

## Pinned sources

| Source | Revision | SHA-256 | Exercised | Partial | Unsupported | Informational | Unclaimed |
| --- | --- | --- | ---: | ---: | ---: | ---: | ---: |
| `core` | draft-hardt-oauth-aauth-protocol-09 at AAuth b414033d4c81224034b5b419216ae06706ede660 | `2c3650d33caf44ac6c614042edc7094a59146ce01805641eb197759de0aa01d1` | 43 | 17 | 3 | 0 | 165 |
| `signature-key` | draft-hardt-httpbis-signature-key-06 at signature-key 84f2d831e22741435660c1f160344d98c69db4d1 | `e049f5509806db9a9f93da0965e99d84415527634ca8b019f6c697a7743e17bf` | 5 | 4 | 2 | 0 | 62 |
| `r3` | draft-hardt-aauth-r3-01 at AAuth b414033d4c81224034b5b419216ae06706ede660 | `752a72b44f06d457c454f2d187d43352482e2f7ce78a196d1c7fafcf66ea141c` | 0 | 5 | 0 | 0 | 44 |
| `events` | draft-hardt-aauth-events-00 at AAuth b414033d4c81224034b5b419216ae06706ede660 | `987b4354d14c72d741e4d1d3f51ecb9724bfc57a5eb01eacc92bfd7c27644f37` | 0 | 7 | 0 | 0 | 57 |
| `bootstrap` | draft-hardt-aauth-bootstrap-01 at AAuth b414033d4c81224034b5b419216ae06706ede660 | `27eecfd9b96de86558203684d285a1d14f135d6bd135d550ffa2d3afb1af9355` | 1 | 2 | 2 | 0 | 38 |
| `interop-profile` | interop-demo-profile at AAuth b414033d4c81224034b5b419216ae06706ede660 | `a9eb24420b2c0a4176833a67e1ce8c55c007e65d567bcd3f076426cba8643cca` | 5 | 0 | 0 | 0 | 3 |

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

### `core/access-server-federation` — Exercised

The resource, person server, and access server execute the supported federation path across distinct trust and policy boundaries.

Evidence:

- `four_party_journey_test.go:TestFourPartyPersonServerAccessServerJourney`

### `core/agent-tokens/agent-token-structure` — Exercised

The selected Ed25519-bound agent-token claim profile is minted and consumed on the three-party path.

Evidence:

- `journey_test.go:TestThreePartyMissionAuthorizationJourney`

### `core/agent-tokens/agent-token-usage` — Exercised

Agent tokens are presented through Signature-Key and bound to the signing key during live authorization requests.

Evidence:

- `journey_test.go:TestThreePartyMissionAuthorizationJourney`

### `core/agent-tokens/agent-token-verification` — Exercised

Issuer trust, JWT validity, issuer-domain identity binding, confirmation-key binding, and request proof are verified before the supported endpoints proceed.

Evidence:

- `request_security_test.go:TestSignedRequestRejectsConfirmationKeySubstitution`
- `elixir_interop_test.go:TestElixirSignedAgentRequestVerifiesInGo`
- `token_identity_internal_test.go:TestAgentTokenRefusesAnIdentifierOutsideTheIssuerDomain`

### `core/as-token-endpoint/as-response` — Partial

Immediate and deferred access-server outcomes are relayed and verified; the complete draft response surface is not implemented.

Evidence:

- `deferred_four_party_journey_test.go:TestAccessServerDeferredAuthorizationThroughPersonServer`

### `core/as-token-endpoint/auth-token-delivery` — Exercised

The person server verifies the access-server result before delivering the auth token to the agent.

Evidence:

- `four_party_journey_test.go:TestFourPartyPersonServerAccessServerJourney`

### `core/as-token-endpoint/ps-to-as-token-request` — Exercised

The person server signs a supported access-server token request with its discoverable server identity.

Evidence:

- `four_party_journey_test.go:TestFourPartyPersonServerAccessServerJourney`

### `core/audit-endpoint/audit-request` — Exercised

Signed audit requests are validated against mission ownership and action history before append.

Evidence:

- `governance_journey_test.go:TestMissionPermissionAndAuditVertical`

### `core/audit-endpoint/audit-response` — Exercised

Successful audit acceptance is durably committed before the supported response is exposed.

Evidence:

- `governance_restart_test.go:TestPersonServerGovernanceSurvivesRestart`

### `core/auth-token-response-verification` — Exercised

The supported client verifies a returned auth token before presenting it to the resource.

Evidence:

- `four_party_journey_test.go:TestFourPartyPersonServerAccessServerJourney`

### `core/auth-tokens/auth-token-structure` — Exercised

The selected auth-token profile carries issuer, audience, agent, key, mission, scope, and lifetime bindings.

Evidence:

- `journey_test.go:TestThreePartyMissionAuthorizationJourney`

### `core/auth-tokens/auth-token-usage` — Exercised

The auth token is presented in Signature-Key and authorizes only the proof-bound protected request.

Evidence:

- `journey_test.go:TestThreePartyMissionAuthorizationJourney`

### `core/auth-tokens/auth-token-verification/jwt-trust-verification` — Exercised

The resource verifies admitted issuer trust and the supported JWT claims before applying authorization.

Evidence:

- `request_security_test.go:TestAuthTokenRejectsWrongAudienceAtResourceBoundary`

### `core/auth-tokens/auth-token-verification/request-context-binding` — Exercised

Audience, request authority, confirmation key, and signed HTTP context are enforced at the resource boundary.

Evidence:

- `request_security_test.go:TestAuthTokenRejectsWrongAudienceAtResourceBoundary`

### `core/call-chaining` — Partial

Mission-governed multi-hop call chaining crosses three- and four-party authorization, composes with parent-mediated sub-agents, preserves nested delegation, and supports immediate and deferred access-server issuance. Missionless direct-AS routing and resource-owned interaction chaining remain open.

Evidence:

- `call_chaining_journey_test.go:TestResourceExtendsAuthorizationToDownstreamResource`
- `call_chaining_journey_test.go:TestResourceExtendsAuthorizationThroughDownstreamAccessServer`

### `core/covered-components` — Exercised

Method, authority, path, Signature-Key, applicable authorization and mission fields, and body digest are required in the supported profile.

Evidence:

- `request_security_test.go:TestSignedRequestRejectsMissionAddedOutsideCoveredComponents`

### `core/deferred-responses/deferred-response-state-machine` — Partial

Pending, slowdown, success, denial, expiry, one-shot terminal delivery, and replay refusal are exercised; not every endpoint persists this state across restart.

Evidence:

- `deferred_person_server_journey_test.go:TestPersonServerDeferredAuthorizationVertical`
- `governance_restart_test.go:TestPersonServerGovernanceSurvivesRestart`

### `core/deferred-responses/initial-request` — Exercised

A supported initial request can return a protected continuation and interaction requirement.

Evidence:

- `deferred_person_server_journey_test.go:TestPersonServerDeferredAuthorizationVertical`

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

The supported endpoints enforce a bounded signature window and reject exact proof replay within one live process. Governance endpoints backed by GovernanceStore retain applicable replay decisions across restart; token, access-server, and resource replay caches remain process-local.

Evidence:

- `journey_test.go:TestThreePartyMissionAuthorizationJourney`
- `deferred_person_server_journey_test.go:TestPersonServerDeferredAuthorizationVertical`
- `governance_restart_test.go:TestPersonServerGovernanceSurvivesRestart`

### `core/http-message-signatures-profile` — Partial

The selected Ed25519 request-signing profile enforces created freshness, optional RFC 9421 expires freshness, required components, and typed verification failures; algorithms and schemes outside that profile remain open.

Evidence:

- `request_security_test.go:TestSignedRequestRejectsBodyMutation`
- `http_signature_jwks_test.go:TestJWKSURIRequestIdentitySignsAndVerifies`
- `signature_error_test.go:TestVerifyRequestClassifiesExpiresAndRequiredInputs`

### `core/identifiers-and-discovery` — Partial

Canonical HTTPS server identifiers and selected metadata discovery documents are implemented; the complete identifier and metadata surface is not.

Evidence:

- `discovery_test.go:TestHTTPKeyResolverUsesAdmittedTwoHopDiscoveryAndCache`

### `core/interaction-chaining` — Unsupported

General chained interaction relay is not implemented.

### `core/interaction-endpoint/interaction-request` — Partial

Completion and clarification-response interaction requests are signed, ownership-bound, and durable; other draft actions are open.

Evidence:

- `mission_completion_journey_test.go:TestMissionCompletionClarificationAndAcceptanceSurviveRestart`

### `core/interaction-response-poll-authority` — Partial

Type-specific completion and question response shapes plus durable polling are implemented for the selected interaction profile.

Evidence:

- `reference/interaction_test.go:TestDecodeInteractionAuthorizationUsesTypeSpecificSuccessShape`
- `mission_completion_journey_test.go:TestMissionCompletionClarificationAndAcceptanceSurviveRestart`

### `core/jwks-discovery` — Exercised

Admitted metadata-to-JWKS discovery, bounded caching, refresh throttling, and same-key-id rotation recovery are executable.

Evidence:

- `discovery_test.go:TestHTTPKeyResolverUsesAdmittedTwoHopDiscoveryAndCache`
- `discovery_test.go:TestTokenVerificationRefreshesSameKidAfterSignatureFailure`

### `core/metadata-documents` — Partial

The reference provider, person server, resource, and access server publish the metadata needed by supported journeys.

Evidence:

- `four_party_journey_test.go:TestFourPartyPersonServerAccessServerJourney`

### `core/mission-approval` — Exercised

The supported person-server policy approves or rejects mission content and retains the approved mission as authorization context.

Evidence:

- `journey_test.go:TestThreePartyMissionAuthorizationJourney`

### `core/mission-completion` — Partial

The selected completion path supports clarification and atomic acceptance plus termination, but not every interaction action.

Evidence:

- `mission_completion_journey_test.go:TestMissionCompletionClarificationAndAcceptanceSurviveRestart`

### `core/mission-completion-overview` — Partial

Completion proposal, clarification, acceptance, termination, restart, and replay handling are implemented; other interaction actions remain open.

Evidence:

- `mission_completion_journey_test.go:TestMissionCompletionClarificationAndAcceptanceSurviveRestart`

### `core/mission-creation` — Exercised

A proposed mission is signed, policy-evaluated, assigned a durable identifier, and returned with exact approved bytes.

Evidence:

- `journey_test.go:TestThreePartyMissionAuthorizationJourney`

### `core/mission-creation-overview` — Exercised

Mission proposal, approval, exact approved-byte retention, and mission digest agreement are executable.

Evidence:

- `journey_test.go:TestThreePartyMissionAuthorizationJourney`
- `mission_test.go:TestMissionS256MatchesCrossImplementationGoldenVector`

### `core/mission-log` — Partial

Permission, audit, clarification, completion, termination, proofs, and terminal responses are ordered and durable; other draft event families are open.

Evidence:

- `governance_restart_test.go:TestPersonServerGovernanceSurvivesRestart`
- `mission_completion_journey_test.go:TestMissionCompletionClarificationAndAcceptanceSurviveRestart`

### `core/missions/aauth-mission-request-header` — Exercised

The mission header is encoded, presented, covered by the request signature, and rejected if added outside that proof.

Evidence:

- `request_security_test.go:TestSignedRequestRejectsMissionAddedOutsideCoveredComponents`

### `core/overview-resource-managed` — Exercised

The supported profile implements proof-bound resource-managed access, opaque credential rotation, and protected operation enforcement.

Evidence:

- `access_journey_test.go:TestResourceManagedAAuthAccessIsProofBound`

### `core/permission-endpoint/permission-request` — Exercised

Signed mission-bound and missionless permission requests reach host policy with exact structured input.

Evidence:

- `governance_journey_test.go:TestMissionPermissionAndAuditVertical`

### `core/permission-endpoint/permission-response` — Exercised

Immediate and deferred permission decisions are validated, retained, and returned through the supported person-server profile.

Evidence:

- `governance_restart_test.go:TestPersonServerGovernanceSurvivesRestart`

### `core/person-server/user-interaction` — Partial

The person server supports trusted approval, rejection, clarification, expiry, and durable terminal delivery for selected interaction types.

Evidence:

- `mission_completion_journey_test.go:TestMissionCompletionClarificationAndAcceptanceSurviveRestart`

### `core/protocol-overview/resource-access-modes/federated-access-four-party` — Exercised

The supported profile executes person-server to access-server federation with independent trust and policy boundaries.

Evidence:

- `four_party_journey_test.go:TestFourPartyPersonServerAccessServerJourney`

### `core/protocol-overview/resource-access-modes/ps-asserted-access-three-party` — Exercised

The supported profile executes agent-provider identity, mission approval, resource-token exchange, person-server authorization, and protected resource access.

Evidence:

- `journey_test.go:TestThreePartyMissionAuthorizationJourney`

### `core/ps-token-endpoint/agent-token-request` — Exercised

A signed supported agent-token request reaches the person-server token endpoint with resource and mission context.

Evidence:

- `journey_test.go:TestThreePartyMissionAuthorizationJourney`

### `core/ps-token-endpoint/ps-response` — Partial

Immediate success, denial, and deferred person-server responses are handled; the full draft response family is not implemented.

Evidence:

- `deferred_person_server_journey_test.go:TestPersonServerDeferredAuthorizationVertical`

### `core/requirement-agent-token` — Exercised

The supported client parses an agent-token requirement and obtains a token before retrying authorization.

Evidence:

- `journey_test.go:TestThreePartyMissionAuthorizationJourney`

### `core/requirement-auth-token` — Exercised

The supported client follows an auth-token requirement through the person server before protected access.

Evidence:

- `journey_test.go:TestThreePartyMissionAuthorizationJourney`

### `core/requirement-responses/aauth-requirement-header-structure` — Exercised

The supported requirement header is parsed and serialized as a structured field with strict wire-value validation.

Evidence:

- `requirement_test.go:TestInteractionRequirementStructuredFieldRoundTrip`

### `core/requirement-responses/approval-pending` — Exercised

Approval-pending requirements drive signed polling with enforced retry cadence in the supported flows.

Evidence:

- `deferred_client_test.go:TestAgentEnforcesRetryAfterAndSlowDown`

### `core/requirement-responses/interaction-required` — Partial

Interaction requirements are represented for resource, person-server, access-server, and completion continuations; not every type is implemented.

Evidence:

- `deferred_person_server_journey_test.go:TestPersonServerDeferredAuthorizationVertical`

### `core/resource-initiated-interaction` — Partial

Resource-hosted deferred approval is implemented with separate trusted decision authority; the broader interaction family remains incomplete.

Evidence:

- `deferred_access_journey_test.go:TestResourceManagedDeferredInteractionVertical`

### `core/resource-tokens/authorization-endpoint-request` — Exercised

The supported resource authorization request is signed, mission-bound when applicable, and handled by a real resource endpoint.

Evidence:

- `journey_test.go:TestThreePartyMissionAuthorizationJourney`

### `core/resource-tokens/authorization-endpoint-responses/response-with-resource-token` — Exercised

A successful supported authorization response returns a proof-bound resource token used in the next protocol step.

Evidence:

- `journey_test.go:TestThreePartyMissionAuthorizationJourney`

### `core/resource-tokens/resource-token/resource-challenge-verification` — Exercised

The client verifies the resource challenge and issuer relationship before adopting the resource token.

Evidence:

- `journey_test.go:TestThreePartyMissionAuthorizationJourney`

### `core/resource-tokens/resource-token/resource-token-structure` — Exercised

The selected resource-token claim profile is minted and carried across the person-server exchange.

Evidence:

- `journey_test.go:TestThreePartyMissionAuthorizationJourney`

### `core/resource-tokens/resource-token/resource-token-verification` — Exercised

Resource-token issuer, audience, mission, agent, request-key, lifetime, and scope bindings are verified in the supported flow.

Evidence:

- `four_party_journey_test.go:TestFourPartyPersonServerAccessServerJourney`

### `core/security-considerations/tls-requirements` — Exercised

The runnable person-server profile enforces TLS 1.3 and a certificate covering its HTTPS identifier.

Evidence:

- `cmd/aauth-reference/main_test.go:TestPersonProcessServesDurableGovernanceOverTLS`

### `core/sub-agents/parent-mediated-authorization` — Exercised

The parent obtains and polls authority for a sub-agent, while the sub-agent cannot call the person server directly.

Evidence:

- `subagent_journey_test.go:TestParentMediatesSubagentAuthorization`

### `core/sub-agents/single-level-depth` — Exercised

The person server permits one delegation level and refuses deeper sub-agent chains.

Evidence:

- `subagent_journey_test.go:TestParentMediatesSubagentAuthorization`

### `core/sub-agents/sub-agent-identity` — Exercised

The supported parent-mediated flow binds a sub-agent identity and confirmation key while retaining the parent actor.

Evidence:

- `subagent_journey_test.go:TestParentMediatesSubagentAuthorization`

### `core/third-party-login` — Unsupported

Third-party login is not implemented.

### `core/token-revocation` — Unsupported

Token revocation is not implemented.

### `core/upstream-token-verification` — Partial

Person and access servers verify upstream JWT trust, issuer admission, mission continuity, and the draft step-3 audience-to-intermediary-agent-token-issuer binding before policy. The person server forwards the compact token unchanged. Actor construction follows the coherent delegation-chain semantics recorded in feedback N5 rather than contradictory step 4, so the source section remains partial pending draft resolution.

Evidence:

- `call_chaining_journey_test.go:TestResourceExtendsAuthorizationToDownstreamResource`
- `call_chaining_journey_test.go:TestResourceExtendsAuthorizationThroughDownstreamAccessServer`

### `core/verification` — Exercised

Server verification checks component coverage, digest, freshness, credential and key binding, signature, and replay identity.

Evidence:

- `request_security_test.go:TestSignedRequestRejectsBodyMutation`

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
- `events_asyncapi_test.go:TestEventsAsyncAPIRejectsUnsupportedOrAmbiguousDocuments`

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

### `interop-profile/aauth-interoperability-demo-profile/surface-1-ps-mission-approval-and-blob-response` — Exercised

Mission approval and exact approved-mission response behavior execute through the reference person server.

Evidence:

- `journey_test.go:TestThreePartyMissionAuthorizationJourney`

### `interop-profile/aauth-interoperability-demo-profile/surface-2-aauth-mission-presentation-and-resource-token-echo` — Exercised

The mission presentation, signed resource authorization request, and resource-token continuity surface is executable.

Evidence:

- `journey_test.go:TestThreePartyMissionAuthorizationJourney`
- `elixir_interop_test.go:TestElixirSignedAgentRequestVerifiesInGo`

### `interop-profile/aauth-interoperability-demo-profile/surface-3-resource-token-issuance-and-issuer-discovery` — Exercised

Resource-token issuance and admitted issuer metadata plus JWKS discovery are executable.

Evidence:

- `journey_test.go:TestThreePartyMissionAuthorizationJourney`
- `discovery_test.go:TestHTTPKeyResolverUsesAdmittedTwoHopDiscoveryAndCache`

### `interop-profile/aauth-interoperability-demo-profile/surface-4-auth-token-issuance-and-presentation` — Exercised

Auth-token issuance, person-server verification, agent adoption, presentation, and resource enforcement are executable.

Evidence:

- `four_party_journey_test.go:TestFourPartyPersonServerAccessServerJourney`

### `interop-profile/aauth-interoperability-demo-profile/surface-5-parent-mediated-sub-agent-token-handling` — Exercised

Parent-mediated sub-agent token handling executes through authorization and protected resource access.

Evidence:

- `subagent_journey_test.go:TestParentMediatesSubagentAuthorization`

### `r3/auth-token-extensions` — Partial

Resource and auth tokens enforce complete URI/hash claim pairs and reject exact or case-fold-ambiguous claim names. Class auth tokens may carry disjoint direct and conditional operation subsets. A proposal auth token must echo the proposal reference, directly grant exactly its one operation, carry no recursive conditional result, retain the resource, agent, key, mission, scope, issuer and lifetime bindings, and pass agent validation before use. The resource independently enforces ordinary scope and the mapped R3 operation. Deferred R3 authorization remains unsupported.

Evidence:

- `r3_journey_test.go:TestR3DirectGrantJourney`
- `r3_test.go:TestR3TokenClaimsRequireCompleteConsistentClaims`
- `r3_test.go:TestVerifyAuthTokenRejectsDuplicateR3Claims`
- `r3_conditional_journey_test.go:TestR3ConditionalPerCallJourney`
- `reference/agent_r3_test.go:TestAgentRefusesPerCallTokenThatDoesNotDirectlyGrantExactProposalOperation`
- `reference/access_server_r3_test.go:TestValidateR3AuthorizationDecisionRequiresExactDirectProposalGrant`

### `r3/authorization-endpoint-extensions` — Partial

The supported four-party path carries signed r3_operations for one advertised MCP vocabulary, validates the requested operation through a deployment-owned authoritative-definition boundary, preserves that requested set in serializable agent state, and returns one R3 reference alongside independently enforced scope. Access policy may split verified document operations into disjoint direct and conditional subsets; their union cannot exceed either the document or retained agent request. Exact and case-fold-ambiguous request names are refused before decoding. Scope-free R3 and live authoritative discovery adapters for every vocabulary remain open.

Evidence:

- `r3_journey_test.go:TestR3DirectGrantJourney`
- `r3_conditional_journey_test.go:TestR3ConditionalPerCallJourney`
- `reference/access_server_r3_test.go:TestValidateR3AuthorizationDecisionAcceptsOnlyDisjointDocumentSubsets`

### `r3/per-call-proposals` — Partial

For one MCP conditional operation alongside a disjoint direct class operation with ordinary scope, the mixed class token executes the direct operation and produces a non-executing auth-token challenge for the conditional call. The signed challenge token references one durably retained exact proposal. The AS alone fetches and hash-verifies it, policy directly approves its single operation, and atomic issuance custody precedes token release. A signed retry must match the selected HTTP operation and every inline and full-byte digest parameter before durable consume-before-effect admission; changed calls and repeated per-call-token use are refused across resource restart. This is at-most-once operation admission, not exactly-once external consequence. Query-bearing conditional calls are unsupported, content type is signed for bodies, and PS proposal retrieval/display remains unresolved because the draft's PS-fetch text conflicts with its AS-only endpoint rule.

Evidence:

- `r3_conditional_journey_test.go:TestR3ConditionalPerCallJourney`
- `r3_test.go:TestR3ProposalBindsInlineAndDigestParameters`
- `reference/r3_document_store_test.go:TestFileR3DocumentStoreConsumesProposalOnceAcrossRestart`
- `reference/r3_issuance_store_test.go:TestFileR3PerCallIssuanceStoreCommitsOneExactTokenAcrossRestart`

### `r3/r3-document` — Partial

The reference resource rejects exact and case-fold duplicate-name ambiguity, validates standard operation-entry shapes and strict one-operation proposal parameters, preserves selected bytes without reserialization, and requires deployment-owned exact-byte custody before issuing a hash-derived class or proposal URI. The included atomic mode-0600 file store survives resource reconstruction, durably classifies proposals and their per-token consumption, bounds per-document, total-byte, and count retention, rejects non-canonical digest paths, and evicts only expired custody. Missing, corrupt, substituted, or expired proposal bytes fail closed. It does not promise permanent historical retention after token expiry. Exact bytes are served only to the resource's signed access server. Multi-process store coordination and multi-definition composition remain open.

Evidence:

- `r3_journey_test.go:TestR3DirectGrantJourney`
- `r3_test.go:TestR3DocumentHashRetainsExactWireIdentity`
- `r3_test.go:TestR3StandardVocabularyOperationShapes`
- `r3_test.go:TestR3DocumentRejectsDuplicateNamesAtEveryDepth`
- `r3_test.go:TestR3ProposalBindsInlineAndDigestParameters`
- `r3_test.go:TestR3ProposalRejectsMalformedParameterDocuments`
- `reference/r3_document_store_test.go:TestFileR3DocumentStoreRetainsExactBytesAcrossRestart`
- `reference/r3_document_store_test.go:TestFileR3DocumentStoreRefusesOversizedOrInvalidRetention`
- `reference/r3_document_store_test.go:TestFileR3DocumentStoreRemovesExpiredDocumentsBeforeStartupCapacityCheck`
- `reference/r3_document_store_test.go:TestFileR3DocumentStoreRejectsNonCanonicalDigestPaths`
- `reference/r3_document_store_test.go:TestFileR3DocumentStoreConsumesProposalOnceAcrossRestart`
- `reference/r3_document_store_test.go:TestFileR3DocumentStoreFailsClosedForMissingExpiredOrCorruptProposalCustody`

### `r3/r3-processing` — Partial

The access server performs an admitted, deadline-bounded, no-redirect same-resource signed fetch with a fresh nonce, verifies bounded exact bytes before parsing or policy, rechecks admission before warm-cache reads, coalesces concurrent requests with cancellation isolation, and uses recoverable least-recently-used eviction for its re-hashed cache. Direct issuance remains gated by the deployment audit callback. Proposal issuance in a private custody directory atomically commits the exact auth token and a candidate semantic audit, then requires an independent deployment-owned durable idempotent audit before release. Its token lifetime is capped to proposal custody, and access-server restart retries the audit before recovering that same token. Person-server proposal fetching remains unsupported under the selected AS-only access rule.

Evidence:

- `r3_journey_test.go:TestR3DirectGrantJourney`
- `reference/r3_fetch_test.go:TestR3FetchCacheEvictsLeastRecentlyUsedCompletedDocument`
- `reference/r3_fetch_test.go:TestR3FetchSingleFlightSurvivesLeaderAndWaiterCancellation`
- `reference/r3_fetch_test.go:TestR3FetchRefusesDeniedRedirectedOversizedAndTimedOutDocuments`
- `reference/r3_fetch_test.go:TestR3FetchRetryUsesDistinctNonceInSameClockSecond`
- `reference/r3_fetch_test.go:TestR3FetchRechecksAdmissionBeforeServingWarmCache`
- `r3_conditional_journey_test.go:TestR3ConditionalPerCallJourney`
- `reference/r3_issuance_store_test.go:TestFileR3PerCallIssuanceStoreCommitsOneExactTokenAcrossRestart`

### `signature-key/name-accept-signature-sigkey-par` — Unsupported

Accept-Signature sigkey negotiation is not implemented.

### `signature-key/name-header-web-key-hwk` — Exercised

The selected OKP/Ed25519 hwk profile carries the exact inline public-key parameters, covers them in the request signature, and verifies without discovery.

Evidence:

- `http_signature_inline_test.go:TestHWKRequestCarriesAndProvesItsInlineEd25519Key`
- `bootstrap_journey_test.go:TestSingleKeyBootstrapCarriesTheDurableKeyIntoTheAgentToken`

### `signature-key/name-jkt-jwt-self-issued-key-del` — Exercised

The mandatory jkt-s256+jwt Ed25519 profile verifies the durable-key thumbprint identity, self-signature, time, delegated key, and ephemeral-key HTTP proof in both Go and Elixir.

Evidence:

- `http_signature_inline_test.go:TestJKTJWTRequestProvesDurableIdentityAndDelegatedRequestKey`
- `http_signature_inline_internal_test.go:TestJKTJWTRequestRefusesAnHTTPProofMadeByTheDurableKey`
- `elixir_interop_test.go:TestElixirJKTJWTRequestVerifiesInGo`
- `internal/interop/cmd/generate/main_test.go:TestGenerateProducesVerifiableGoJKTJWTRequest`

### `signature-key/name-jwks-uri-discovery-jwks_uri` — Exercised

The supported server identity uses id, discovery-document, and key-id parameters with admitted two-hop metadata and JWKS resolution.

Evidence:

- `http_signature_jwks_test.go:TestJWKSURIRequestIdentitySignsAndVerifies`
- `discovery_test.go:TestHTTPKeyResolverUsesAdmittedTwoHopDiscoveryAndCache`

### `signature-key/name-jwt-confirmation-key-jwt` — Partial

AAuth agent and auth JWTs supply the confirmation key for the supported signed-request profile; arbitrary JWT profiles are not accepted.

Evidence:

- `request_security_test.go:TestSignedRequestRejectsConfirmationKeySubstitution`
- `elixir_interop_test.go:TestElixirSignedAgentRequestVerifiesInGo`

### `signature-key/name-label-consistency` — Exercised

The supported single sig label is bound consistently across Signature-Key, Signature-Input, and Signature.

Evidence:

- `http_signature_jwks_test.go:TestJWKSURIRequestRejectsKeyReferenceSubstitution`

### `signature-key/name-self-issued-jwt-self-jwt` — Partial

The selected portable self-jwt profile uses the same discovered key to verify both the compact JWT and its HTTP Message Signature, rejects unsafe issuer, discovery, and time claims before application use, and runs under deployment-owned presenter-directed egress policy. Other self-issued JWT profiles are unclaimed.

Evidence:

- `http_signature_self_jwt_test.go:TestSelfJWTRejectsUnsafeClaimsBeforeDiscovery`
- `http_signature_self_jwt_test.go:TestSelfJWTUsesOneDiscoveredKeyForBothProofs`
- `discovery_policy_test.go:TestSelfJWTUsesAdmittedHTTPKeyForBothProofs`

### `signature-key/name-signature-error-http-respon` — Partial

The RFC 8941 codec and AAuth reference response path are exercised, including unknown-member tolerance, authoritative header decoding, operational resolution failures, and post-authentication policy denial. The AAuth core and Signature-Key drafts assign different codes to missing proof headers; the AAuth profile follows core invalid_request, so generic Signature-Key response conformance is not claimed.

Evidence:

- `signature_error_test.go:TestSignatureErrorWireContract`
- `signature_error_test.go:TestSignatureErrorIgnoresRFC8941UnknownMembers`
- `reference/signature_error_test.go:TestResourceReportsSignatureFailuresAsSignatureError`
- `reference/signature_error_test.go:TestResourcePolicyDenialIsNotASignatureFailure`

### `signature-key/name-signature-key-http-request-` — Partial

Signature-Key parsing, signing, and proof binding are implemented for the selected Ed25519 jwt, jwks_uri, hwk, and jkt-jwt profiles; other schemes and multiple signatures are not.

Evidence:

- `http_signature_jwks_test.go:TestJWKSURIRequestIdentitySignsAndVerifies`
- `request_security_test.go:TestSignedRequestRejectsConfirmationKeySubstitution`
- `http_signature_inline_test.go:TestJKTJWTRequestProvesDurableIdentityAndDelegatedRequestKey`

### `signature-key/name-signature-key-integrity` — Exercised

Signature-Key is a mandatory covered component, so changing the selected key reference invalidates the HTTP signature.

Evidence:

- `http_signature_jwks_test.go:TestJWKSURIRequestRejectsKeyReferenceSubstitution`

### `signature-key/name-x509-certificates-x509` — Unsupported

The x509 scheme is not implemented.
