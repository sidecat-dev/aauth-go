# AAuth conformance journeys

This catalog describes what a caller can run through the exported Go API at
the source revision pinned in [SPECIFICATIONS.md](SPECIFICATIONS.md). It is a
reader's map, not an official conformance claim. A type or parser alone does
not make a journey implemented.

Status means:

- **Implemented**: the complete stated path runs through exported APIs and has
  executable role-to-role evidence.
- **Partial**: a useful path runs, but the named continuation or deployment
  profile is missing.
- **Not implemented**: the repository does not provide the path.

Every flow uses protocol roles: Agent Provider (AP), Agent, Person Server (PS),
Access Server (AS), and Resource. Applications still supply policy, keys,
transport, clocks, and durable stores. An unqualified `Client` method below is
a method on `agent.Client`.

Specifications:

- [Repository deployment profiles](#repository-deployment-profiles)
- [AAuth Protocol](#aauth-protocol)
- [HTTP Signature Keys](#http-signature-keys)
- [AAuth Rich Resource Requests (R3)](#aauth-rich-resource-requests-r3)
- [AAuth Events](#aauth-events)
- [AAuth Bootstrap Guidance](#aauth-bootstrap-guidance)
- [AAuth Budgets](#aauth-budgets)
- [AAuth interoperability demo profile](#aauth-interoperability-demo-profile)

## Repository deployment profiles

- [x] **Hosted-service launch composition — Implemented**
  - Flow: durable-key enrollment → delegated Agent-token refresh → local
    permission → separately host-reviewed mission approval → MCP operation and
    fixed Budget → one connector application call → verified exhausted-Budget
    step-up before a second dispatch → AP revocation at the PS and local direct
    Resource.
  - Start with: [`HOSTED-SERVICE-PROFILE.md`](HOSTED-SERVICE-PROFILE.md) and
    `go run ./example/hostedservice`.
  - Boundary: this proves exported-library composition with real signed HTTP
    exchanges. Its operation-and-Budget reference stores pass the public R3
    document, R3 issuance, and Budget contracts. It does not prove production
    persistence, account login, OAuth, administrative authentication, or
    deployment.

## AAuth Protocol

Pinned source: [AAuth Protocol editor source](https://github.com/dickhardt/AAuth/blob/a99d353cf18aee81d0c5445bac070164fb3b8bc5/draft-hardt-oauth-aauth-protocol.md).

### Runnable journeys

- [x] **Direct Agent and Person identity — Implemented**
  - Flow: AP → Agent token → signed Resource request → `AgentPrincipal`.
    Alternatively, Agent → PS → directed Person token → signed Resource
    request → `PersonPrincipal`.
  - Start with: `agent.New`, `Client.CallAsAgent`, `Client.PersonToken`,
    `resource.NewAgentIdentity`, or `resource.NewPersonIdentity`.
  - Evidence: [`integration/direct_identity_access_test.go`](integration/direct_identity_access_test.go)
    and `go run ./example/agentidentity`.

- [x] **Immediate three-party authorization — Implemented**
  - Flow: Agent → PS for a Person token → Resource for a Resource token → PS
    for a narrowed Auth token → protected Resource call.
  - Start with: `personserver.NewPSAuthorization`,
    `resource.NewPSAuthorization`, and `Client.PersonToken`, `Authorize`,
    `Exchange`, and `Do`.
  - Evidence: [`integration/three_party_authorization_test.go`](integration/three_party_authorization_test.go)
    and `go run ./example/threeparty`.

- [x] **Resource-managed session — Implemented**
  - Flow: Agent → Resource → optional Resource-owned person interaction →
    explicit poll → opaque proof-bound session → protected call.
  - Start with: `resource.NewResourceManaged`,
    `Client.BeginResourceSession`, `PollResourceSession`,
    `RestoreResourceSession`, and `DoWithResourceSession`.
  - Evidence: [`resource/storetest/session.go`](resource/storetest/session.go),
    [`integration/resource_managed_session_test.go`](integration/resource_managed_session_test.go),
    and `go run ./example/resourcesession`.

- [x] **Immediate four-party federation — Implemented**
  - Flow: Agent → PS → Resource → PS → AS → PS → Agent → protected
    Resource call. The Resource-held variant retains the invocation, executes
    it once after explicit polling, and replays the retained result.
  - Start with: `personserver.NewFederatedAuthorization`, `accessserver.New`,
    `resource.NewFederatedAuthorization`, `Client.Begin`, and
    `Client.PollAuthToken`.
  - Evidence: [`integration/core_four_party_test.go`](integration/core_four_party_test.go)
    and `go run ./example/fourparty`.

### Bounded journeys

- [ ] **Agent enrollment and refresh — Partial**
  - Flow: Agent → AP with a durable inline key → retained Agent identity →
    Agent token → either delegated-key or direct durable-key refresh → exact
    replay returns the retained token → host disables, restores, or permanently
    revokes the enrollment → new refresh is refused while already-issued tokens
    remain bounded by their signed expiry.
  - Start with: `agent.NewBootstrapClient`, `BootstrapClient.Enroll`,
    `BootstrapClient.Refresh`, `BootstrapClient.RefreshSingleKey`,
    `agentprovider.NewEnrollmentService`, and
    `agentprovider.EnrollmentStore.TransitionEnrollment`.
  - Evidence: [`integration/bootstrap_refresh_test.go`](integration/bootstrap_refresh_test.go),
    [`integration/bootstrap_single_key_test.go`](integration/bootstrap_single_key_test.go),
    and `go run ./example/bootstrap`.
  - Missing: platform-attestation profiles and durable-key replacement.

- [ ] **Interactive Person-token issuance — Partial**
  - Flow: Agent → PS with an optional active mission → pending URL and
    interaction code → separately authenticated person decision over the exact
    mission context when named → explicit Agent poll → Person token or terminal
    error only while that mission remains active.
  - Start with: `Client.PersonToken`, `Client.PollPersonToken`,
    `personserver.DeferredTokenStore`, `MissionDeferredTokenStore`, and the PS
    interaction methods.
  - Evidence: [`integration/person_token_interaction_test.go`](integration/person_token_interaction_test.go).
  - Missing: parent-mediated composition and durable adapters.

- [ ] **Deferred three-party consent and clarification — Partial**
  - Flow: Agent → PS → pending interaction, optionally bound to one mission →
    one host question → explicit Agent poll → one signed answer or terminal
    cancellation → host decision → explicit poll → Auth token → protected
    call. Missionless and mission-bound requests use the same Agent methods.
  - Start with: `Client.BeginExchange`, `PollExchange`,
    `AnswerClarification`, `CancelClarification`, `PendingExchange.Snapshot`,
    `RestorePendingExchange`, `personserver.DeferredAuthorizationStore`,
    `personserver.MissionDeferredAuthorizationStore`, and the two focused
    clarification store extensions.
  - Evidence: [`integration/deferred_ps_authorization_test.go`](integration/deferred_ps_authorization_test.go),
    [`integration/clarification_three_party_test.go`](integration/clarification_three_party_test.go),
    [`personserver/mission_deferred_authorization_test.go`](personserver/mission_deferred_authorization_test.go),
    and `go run ./example/psconsent`.
  - Boundary: omitted capabilities on a mission-bound request use the exact
    values retained at mission approval; an explicit empty array remains
    empty. Durable adapters, AS relay, `claims`, `payment`, and
    `updated_request` remain missing. The safe limit is one question because
    Core gives an answer no round identifier; see `AAG-F095` in
    [SPEC-FEEDBACK.md](SPEC-FEEDBACK.md).

- [ ] **Mission-governed authorization — Partial**
  - Flow: Agent → PS mission proposal → immediate approval or retained pending
    URL → store-derived host queue and separately authenticated decision → one
    Agent poll → optional ordered updates → three- or four-party authorization
    → protected call → person-accepted completion.
  - Start with: `Client.ProposeMission` for immediate-only deployments;
    `Client.BeginMission`, `PollMissionProposal`,
    `PendingMissionProposal.Snapshot`, `RestorePendingMissionProposal`,
    `Server.PendingMissionProposals`,
    `ApproveMissionProposal`, `DenyMissionProposal`, `UpdateMission`, and
    `CompleteMission`.
  - Evidence: [`integration/mission_three_party_test.go`](integration/mission_three_party_test.go),
    [`integration/mission_four_party_test.go`](integration/mission_four_party_test.go),
    [`integration/mission_deferred_proposal_test.go`](integration/mission_deferred_proposal_test.go),
    `go run ./example/mission`, and `go run ./example/fourparty`.
  - Missing: mission clarification and POST-on-pending; deferred mission update
    or completion; a helper that waits between polls; a durable production
    adapter; recovery after an uncertain initial or terminal response;
    delegation; call chaining; held delivery; and revocation.

- [ ] **Parent-mediated sub-agents and one Resource call chain — Partial**
  - Flow: parent → PS on behalf of one child → credential bound to the child
    key → child → Resource. Alternatively, Resource 1 receives an authorized
    call → acts as its own Agent → PS → Resource 2.
  - Start with: `PersonTokenRequest.SubagentToken`,
    `ExchangeRequest.SubagentToken`, `PersonTokenRequest.UpstreamToken`,
    `ExchangeRequest.UpstreamToken`, and `personserver.CallChainingConfig`.
  - Evidence: [`integration/subagent_authorization_test.go`](integration/subagent_authorization_test.go),
    [`integration/call_chaining_test.go`](integration/call_chaining_test.go),
    `go run ./example/subagent`, and `go run ./example/callchaining`.
  - Missing: recursive or remote delegation, delegated interaction, repeated
    chain depth, federated downstream chaining, and mission composition.

- [ ] **Agent- and three-party Auth-token revocation — Partial**
  - Flow: AP signs an exact Agent-token reference → PS or a known direct
    Agent-identity Resource retains it and refuses later requests before policy
    or application dispatch. Separately, PS retains issued-token routing →
    signed revocation → Resource marks the exact Auth token revoked → later use
    fails → Agent explicitly performs a fresh authorization.
  - Start with: `personserver.AuthTokenRevocationConfig`,
    `personserver.IssuedAuthTokenStore`,
    `personserver.Server.RevokeIssuedAuthToken`, and
    `resource.AuthTokenStatusStore`; for Agent tokens, start with
    `agentprovider.RevocationClient`,
    `personserver.AgentTokenRevocationStore`, and
    `resource.AgentTokenRevocationStore`.
  - Evidence: [`integration/revocation_reauthorization_test.go`](integration/revocation_reauthorization_test.go),
    [`integration/agent_token_revocation_test.go`](integration/agent_token_revocation_test.go),
    and `go run ./example/revocation`.
  - Missing: automatic Agent-token fan-out, Auth-token pre-use and four-party
    propagation, mission cascade, and session revocation.

- [x] **Missionless local-action permission — Implemented**
  - Flow: Agent → PS with one signed local-action request → immediate decision
    or retained pending URL → independently authenticated host decision → one
    explicit Agent poll → application acts only after a typed grant.
  - Start with: `Client.RequestPermission`, `Client.PollPermission`,
    `personserver.PermissionConfig`, `personserver.PermissionStore`,
    `Server.ResumePermission`, `GrantPermission`, and `DenyPermission`.
  - Evidence: [`integration/permission_missionless_test.go`](integration/permission_missionless_test.go),
    [`personserver/storetest/permission.go`](personserver/storetest/permission.go),
    and `go run ./example/permission`.
  - Missing from the wider Permission Endpoint: `approved_tools` matching,
    complete cross-event mission-log recording, durable adapters, and
    recovery of an uncertain initial submission.

- [x] **Mission-bound local-action permission — Implemented**
  - Flow: Agent names one active mission → PS gives policy the approved blob
    and accepted updates → immediate decision or retained pending URL → host
    resumes the exact mission context and records a decision → one explicit
    Agent poll consumes the result only while the mission remains active.
  - Start with: `agent.PermissionRequest.MissionS256`,
    `personserver.PermissionPolicyRequest.Mission`,
    `personserver.MissionPermissionStore`, and
    `personserver.PermissionRequest.Mission`.
  - Evidence: [`integration/permission_mission_test.go`](integration/permission_mission_test.go),
    [`personserver/storetest/mission_permission.go`](personserver/storetest/mission_permission.go),
    [`internal/exampleutil/permission_store_test.go`](internal/exampleutil/permission_store_test.go),
    and `go run ./example/permission`.
  - Boundary: retained permission state is the permission sublog. Cross-event
    ordering with tokens, updates, Audit, Interaction, and clarification
    remains part of the incomplete mission log.

- [x] **Mission-bound action audit — Implemented**
  - Flow: application performs one action → Agent sends one exact signed
    post-action record → PS verifies the active owned mission → the mission
    store appends before `201 Created` → the host can read the ordered
    Audit-entry sublog.
  - Start with: `aauth.AuditEntry`, `agent.Client.SubmitAudit`,
    `personserver.AuditConfig`, and `personserver.MissionAuditStore`.
  - Evidence: [`integration/audit_mission_test.go`](integration/audit_mission_test.go),
    [`personserver/storetest/audit.go`](personserver/storetest/audit.go), and
    `go run ./example/audit`.
  - Missing from the wider Audit and mission-log surface: cross-event ordering
    with token, update, permission, interaction, and clarification activity;
    deferred delivery; sub-agent and call-chain composition; durable adapters;
    stable recovery after an uncertain acknowledgment; and Agent-facing log
    retrieval.

- [x] **Missionless or mission-bound Interaction question — Implemented**
  - Flow: Agent → PS with one exact signed raw-Markdown question and optional
    mission digest → PS supplies the exact active mission to policy when named
    → policy returns an atomically retained immediate answer or a bounded
    pending question → an independently authenticated host resumes the same
    mission view and answers → one explicit Agent poll consumes the result only
    while the mission remains active.
  - Start with: `aauth.InteractionQuestion`,
    `agent.Client.AskPersonQuestion`, and
    `personserver.InteractionQuestionConfig`. Mission-aware applications set
    `InteractionQuestionRequest.MissionS256`, read
    `InteractionQuestionPolicyRequest.Mission` and
    `InteractionQuestionHandle.Mission`, and implement
    `MissionInteractionQuestionStore`.
  - Evidence: [`integration/interaction_question_test.go`](integration/interaction_question_test.go),
    [`personserver/storetest/mission_interaction_question.go`](personserver/storetest/mission_interaction_question.go),
    and `go run ./example/interactionquestion`.
  - Missing from the wider Interaction Endpoint: durable adapters, complete
    cross-event mission-log recording, and stable uncertain-initial-submission
    recovery.

- [x] **Interaction and payment relay — Implemented**
  - Flow: Agent → PS with one exact signed URL/code relay and optional mission
    digest → PS verifies the exact active mission when present and retains
    before `202` → independently authenticated host sees that same mission view
    and marks engagement or no progress → one explicit Agent poll consumes the
    terminal relay state. A configured `max_wait` resolves the relay without
    replacing a Resource-hosted pending URL as the authority for completing the
    underlying work.
  - Start with: `aauth.InteractionRelay`,
    `agent.Client.RequestInteractionRelay`, and
    `personserver.InteractionRelayConfig`. Mission-aware applications set
    `InteractionRelay.MissionS256`, read `InteractionRelayPolicyRequest.Mission`
    and `InteractionRelayHandle.Mission`, and implement
    `MissionInteractionRelayStore`.
  - Evidence: [`integration/interaction_relay_test.go`](integration/interaction_relay_test.go),
    [`personserver/storetest/interaction_relay.go`](personserver/storetest/interaction_relay.go),
    [`personserver/storetest/mission_interaction_relay.go`](personserver/storetest/mission_interaction_relay.go),
    and `go run ./example/interactionrelay`.
  - Missing: durable adapters, complete cross-event mission-log recording, and
    stable uncertain-initial-submission recovery.

### Not implemented

- [ ] **Complete PS governance and mission log — Not implemented.** The
  bounded stores retain approval, accepted updates, mission-bound permission,
  Audit, and completion, but there is no single ordered log across all required
  PS interactions or complete governance-policy history.
- [ ] **Third-party login — Blocked by the current Core flow.** The Login Flow
  tells the recipient to create a Resource token and post it directly to the
  Person Server, but a current Resource token requires person-derived `sub` and
  `presented_jti`. The user has not yet authenticated and no Person-token step
  appears in the flow, so the repository does not invent a login-only token
  profile. See `AAG-F103`.
- [ ] **General deferred composition — Not implemented.** Existing pending
  paths do not yet compose AS deferral, mission deferral, correlated
  multi-round clarification, updated requests, claims, and payment through one
  caller-driven model.

## HTTP Signature Keys

Pinned source: [HTTP Signature Keys editor source](https://github.com/dickhardt/signature-key/blob/0ff751b571e7fe51336bcc1e526954a202317cc0/draft-hardt-httpbis-signature-key.md).

### Runnable journeys

- [x] **Token-selected `jwt` proof — Implemented**
  - Flow: caller presents an Agent, Person, or Auth token in `Signature-Key` →
    recipient validates the token → recipient uses its confirmation key to
    verify the HTTP Message Signature.
  - Start with: `signaturekey.SignJWTRequest`, `NewJWTCredential`,
    `PrepareRequest`, and `PreparedRequest.Verify`.
  - Evidence: [`signaturekey/request_external_test.go`](signaturekey/request_external_test.go)
    plus the Core integration journeys above.

- [x] **HTTPS-identified `jwks_uri` proof — Implemented**
  - Flow: HTTPS role signs with a discovery-named key → recipient admits and
    fetches metadata and JWKS → verifies issuer and key → verifies the request.
  - Start with: `signaturekey.SignJWKSURIRequest`, `NewJWKSURICredential`, and
    `NewHTTPKeyResolver`.
  - Evidence: [`signaturekey/discovery_external_test.go`](signaturekey/discovery_external_test.go),
    `go run ./example/fourparty`, and `go run ./example/revocation`.

### Bounded journeys

- [ ] **Common request signing and verification — Partial**
  - Flow: caller selects a credential scheme and covered components → signs
    method, target, selected headers, and optional body digest → recipient
    parses one label, resolves the proof key, and returns `VerifiedRequest`.
  - Start with: `signaturekey.SignRequest`, `PrepareRequest`,
    `PreparedRequest.Verify`, `SignOptions`, and `VerifyOptions`.
  - Evidence: [`signaturekey/request_external_test.go`](signaturekey/request_external_test.go)
    and [`signaturekey/body_limit_external_test.go`](signaturekey/body_limit_external_test.go).
  - Missing: the complete field and digest representation space.

- [ ] **Inline `hwk` enrollment and delegated `jkt-jwt` refresh — Partial**
  - Flow: Agent signs enrollment with a durable inline key → AP retains the
    Agent identity → delegated assertion binds the durable key to a current
    proof key → AP verifies both layers and issues the Agent token.
  - Start with: `signaturekey.SignHWKRequest`, `NewHWKCredential`,
    `MintJKTJWT`, `NewJKTJWTCredential`, and
    `PreparedRequest.VerifyJKTJWT`.
  - Evidence: [`signaturekey/jkt_jwt_external_test.go`](signaturekey/jkt_jwt_external_test.go)
    and `go run ./example/bootstrap`.
  - Missing: SHA-512 and non-Ed25519 delegated-key profiles.

- [ ] **Self-issued `self-jwt` Event delivery — Partial**
  - Flow: Resource creates an Event token → signs delivery with the same key →
    AP resolves the Resource key → verifies both token and HTTP proof.
  - Start with: `signaturekey.SignSelfJWTRequest`,
    `NewSelfJWTCredential`, and `PreparedRequest.VerifySelfJWT`.
  - Evidence: [`signaturekey/self_jwt_external_test.go`](signaturekey/self_jwt_external_test.go)
    and `go run ./example/events`.
  - Missing: other self-issued token profiles.

- [ ] **Typed errors and negotiation — Partial**
  - Flow: recipient returns `Signature-Error` and accepted schemes or
    algorithms → caller decodes the failure → caller decides whether to make a
    new request.
  - Start with: `signaturekey.NewError`, `FormatError`, `ParseError`,
    `FormatAcceptSchemes`, `FormatAcceptAlgorithms`, and `DecodeErrorResponse`.
  - Evidence: [`signaturekey/error_external_test.go`](signaturekey/error_external_test.go).
  - Missing: consistent negotiation behavior across every role path.

- [ ] **Exact-proof fingerprint — Partial helper coverage**
  - `VerifiedRequest.ReplayKey` identifies one exact signed proof. A fresh
    signature over the same logical operation has a different value.
  - Evidence: [`signaturekey/request_external_test.go`](signaturekey/request_external_test.go)
    checks that verified proofs expose the fingerprint.
  - Missing: no role store consumes `ReplayKey`, and there is no generic
    operation-level replay contract. Focused journeys such as Agent-token
    refresh derive their own stable request identity instead.

### Not implemented

- [ ] **`jwks`, `x509`, and provisional `cached` schemes — Not implemented.**
  No complete signing-and-verification journey exists for these schemes.

## AAuth Rich Resource Requests (R3)

Pinned source: [R3 editor source](https://github.com/dickhardt/AAuth/blob/a99d353cf18aee81d0c5445bac070164fb3b8bc5/draft-hardt-aauth-r3.md).

### Native definition ingestion

The shared flow is: application acquires exact native material → one
vocabulary parser derives operations → `r3.AuthoritativeSnapshot` retains the
source receipt and copied operations → `resource.R3Config` binds that snapshot
to one advertised Resource definition. Parsing does not fetch dependencies,
decide policy, retain grants, or prove a role journey.

| Vocabulary | Current status | Executable evidence | Missing continuation |
| --- | --- | --- | --- |
| MCP | **Implemented for the bounded profile** | [`r3/vocab/mcp/definition_test.go`](r3/vocab/mcp/definition_test.go), direct and federated journeys below | JSON-RPC transport, live `tools/list` acquisition, and external schema resolution remain with the application. |
| OpenAPI | **Partial** | [`r3/vocab/openapi/definition_test.go`](r3/vocab/openapi/definition_test.go), federated journeys below | No direct three-party journey; callbacks, webhooks, and external references are outside the parser. |
| gRPC | **Partial** | [`r3/vocab/grpc/definition_test.go`](r3/vocab/grpc/definition_test.go) | No role journey; reflection and `.proto` acquisition or compilation are absent. |
| GraphQL | **Not implemented as an authoritative journey** | [`r3/vocab/graphql/definition_test.go`](r3/vocab/graphql/definition_test.go) proves typed refusal | Introspection does not identify client-authored executable operations, so no authoritative snapshot is claimed. |
| AsyncAPI | **Partial** | [`r3/vocab/asyncapi/definition_test.go`](r3/vocab/asyncapi/definition_test.go) | No role journey; YAML conversion and general validation are outside the parser. |
| WSDL | **Partial** | [`r3/vocab/wsdl/definition_test.go`](r3/vocab/wsdl/definition_test.go) | No role journey; imports, includes, XML Schema, and arbitrary extensions are absent. |
| OData | **Partial** | [`r3/vocab/odata/definition_test.go`](r3/vocab/odata/definition_test.go) | No role journey; the bounded CSDL subset does not claim HTTP-method or AAuth-annotation authority. |

Start definition work with `r3.NewDefinitionRegistry`,
`r3/vocab/standard.Definitions`, the vocabulary's `ParseDefinition`, and
`resource.R3VocabularyConfig`. A third-party adapter uses `r3.Codec` and
`r3.DefinitionCodec`, then runs the reusable contracts in `r3/vocabtest`.

### Runnable journeys

- [x] **Direct three-party class authorization — Implemented for MCP**
  - Flow: Agent → Resource for an exact retained class document and R3
    Resource token → PS fetches and verifies the document → PS narrows the
    grant, retains issuance audit, and signs the Auth token → Resource enforces
    granted and ungranted operations.
  - Start with: `resource.NewPSAuthorization`, `resource.R3Config`,
    `personserver.DirectR3Config`, `r3.IssuanceStore`, `agent.R3Config`, and
    the ordinary Agent token methods.
  - Evidence: [`integration/r3_direct_three_party_test.go`](integration/r3_direct_three_party_test.go)
    and `go run ./example/r3threeparty`.
  - Missing: direct three-party per-call authorization and composition with
    missions, sub-agents, call chaining, or deferral.

- [x] **Direct MCP class authorization with a fixed Budget — Implemented**
  - Flow: Agent requests exact MCP operations and a Budget → Resource retains
    one R3 document and Budget lineage → PS independently verifies both and
    narrows the operation set and amount → Resource verifies both companions,
    checks the operation, atomically charges, then dispatches → an over-cap
    call returns a typed step-up with the same R3 reference and no dispatch.
  - Start with: `r3.MintBudgetResourceToken`,
    `r3.MintDirectBudgetAuthToken`, the ordinary direct-R3 configurations, and
    the ordinary fixed-price Budget configurations and Agent calls.
  - Evidence: [`integration/r3_budget_three_party_test.go`](integration/r3_budget_three_party_test.go),
    [`token_r3_external_test.go`](token_r3_external_test.go), and
    `go run ./example/budget`.
  - Boundary: direct three-party class authorization only. R3-only and
    Budget-only verifiers continue to reject mixed tokens. Per-call,
    four-party, mission, delegation, call-chain, account, and variable-price
    combinations remain unsupported.

- [x] **Federated four-party class authorization — Implemented for MCP and OpenAPI**
  - Flow: Resource retains and publishes the exact class document → PS and AS
    fetch it independently → PS consents → AS narrows and audits the grant →
    Agent receives the Auth token → Resource enforces Core scope and R3
    operations.
  - Start with: `resource.NewFederatedAuthorization`,
    `personserver.R3Config.ConsentDocument`,
    `accessserver.R3Config.AuthorizeDocument`, and `accessserver.R3DocumentDecision`.
  - Evidence: [`integration/r3_direct_four_party_test.go`](integration/r3_direct_four_party_test.go)
    and the MCP path in `go run ./example/fourparty`.
  - Missing: role-composed gRPC, AsyncAPI, WSDL, and OData journeys. GraphQL
    first needs an executable-operation identity.

- [x] **Federated four-party per-call authorization — Implemented for MCP and OpenAPI**
  - Flow: Agent makes one concrete request → Resource retains an exact
    proposal → Agent follows a baseline `401` or held `202` continuation → PS
    and AS fetch and approve the proposal → Resource matches exact operation
    and parameters, executes once, and replays the retained result.
  - Start with: `resource.R3PerCallConfig`, `resource.R3ProposalStore`,
    `resource.R3RetryStore`, `personserver.R3Config.ConsentProposal`,
    `accessserver.R3Config.AuthorizeProposal`, and `Client.BeginR3Call`,
    `RetryR3Call`, or `PollR3Call`.
  - Evidence: [`integration/r3_per_call_four_party_test.go`](integration/r3_per_call_four_party_test.go).
  - Missing: a direct three-party issuer, a runnable per-call example, and
    role journeys for the remaining standard vocabularies.

## AAuth Events

Pinned source: [Events editor source](https://github.com/dickhardt/AAuth/blob/a99d353cf18aee81d0c5445bac070164fb3b8bc5/draft-hardt-aauth-events.md).

### Runnable journeys

- [x] **Public subscription and event delivery — Implemented**
  - Flow: Agent → AP for a retained subscribe token → Agent retains context
    and registers with Resource → Resource resolves and admits the AP event
    endpoint → Resource sends a `self-jwt` event → AP retains before `202` →
    host transport gives the delivery to Agent → Agent verifies context and
    exact replay.
  - Start with: `agentprovider.EventsConfig`,
    `agentprovider.Server.IssueSubscribeToken`, `agent.EventsConfig`,
    `Client.RegisterPublicSubscription`, `Client.AcceptEvent`,
    `resource.NewEventService`, `resource.EventService.PublicSubscriptionHandler`,
    `resource.EventService.PrepareEvent`, `resource.EventService.DeliverEvent`,
    and `resource.NewHTTPEventEndpointResolver`.
  - Evidence: [`integration/events_public_subscription_test.go`](integration/events_public_subscription_test.go)
    and `go run ./example/events`.
  - Host boundary: the specification leaves AP-to-Agent transport
    platform-defined; the host supplies the queue, push channel, or other
    durable delivery adapter.

- [x] **Protected subscription ticket and event delivery — Implemented**
  - Flow: authenticated Agent interaction → Resource retains an opaque ticket
    bound to the verified Agent and application context → AP issues a subscribe
    token → Agent signs one POST to the ticket URL → Resource verifies the
    Agent, expiry, and single use and atomically commits registration → ordinary
    Events delivery continues.
  - Start with: `resource.ProtectedSubscriptionConfig`,
    `EventService.IssueProtectedSubscriptionTicket`,
    `EventService.ProtectedSubscriptionHandler`,
    `resource.ProtectedSubscriptionStore`, and
    `Client.RegisterProtectedSubscription`.
  - Evidence: [`integration/events_protected_subscription_test.go`](integration/events_protected_subscription_test.go),
    [`resource/storetest/events_protected.go`](resource/storetest/events_protected.go),
    and `go run ./example/events`.
  - Host boundary: the Resource application decides which prior authenticated
    interaction may issue a ticket and what opaque context the registration
    policy receives. The specification does not define ticket encoding.

### Bounded and missing journeys

- [ ] **AsyncAPI event discovery — Partial helper coverage**
  - `asyncapi.ParseDefinition` derives bounded R3 operations and sparse hints.
    It does not acquire the document, choose a subscription endpoint, register
    a subscription, or validate event payloads.
  - Evidence: [`r3/vocab/asyncapi/definition_test.go`](r3/vocab/asyncapi/definition_test.go).

## AAuth Bootstrap Guidance

Pinned source: [Bootstrap editor source](https://github.com/dickhardt/AAuth/blob/a99d353cf18aee81d0c5445bac070164fb3b8bc5/draft-hardt-aauth-bootstrap.md).

Bootstrap is informational. The source does not standardize enrollment routes,
JSON envelopes, evidence formats, or policy decisions, so the executing path
below is explicitly a repository profile.

### Runnable journey

- [x] **Hosted two-key and single-key enrollment, refresh, and Agent use — Implemented repository profiles**
  - Flow: Agent → AP enrollment handler with an `hwk` durable key → AP retains
    a stable Agent identity → Agent creates a fresh proof key → durable key
    delegates through `jkt-jwt` while the fresh key signs refresh → AP returns
    an exact retained Agent token → Agent uses it on a Resource request → an
    authenticated host atomically revokes the enrollment → a fresh refresh is
    refused. Already-issued Agent tokens remain valid only until their signed
    expiry.
    In the single-key variant, the durable key signs refresh directly through
    `hwk` and remains the Agent-token confirmation key.
  - Start with: `agentprovider.NewEnrollmentService`,
    `agentprovider.EnrollmentService.EnrollmentHandler`,
    `agentprovider.EnrollmentService.RefreshHandler`,
    `agentprovider.EnrollmentService.SingleKeyRefreshHandler`,
    `agent.NewBootstrapClient`, `BootstrapClient.Enroll`,
    `BootstrapClient.Refresh`, `BootstrapClient.RefreshSingleKey`,
    `EnrollmentStore.TransitionEnrollment`, `agent.New`, `Client.CallAsAgent`, and
    `resource.NewAgentIdentity`.
  - Evidence: [`integration/bootstrap_refresh_test.go`](integration/bootstrap_refresh_test.go),
    [`integration/bootstrap_single_key_test.go`](integration/bootstrap_single_key_test.go),
    and `go run ./example/bootstrap`.
  - Host boundary: applications supply attestation/evidence policy and a
    durable `agentprovider.EnrollmentStore`; the repository supplies no
    database adapter.

- [x] **Self-hosted Agent issuance and use — Implemented source profile**
  - Flow: user-controlled Agent origin → ordinary AP metadata and JWKS → Agent
    self-issues a current token with the same signing and confirmation key →
    ordinary Agent client → protected Resource call. Reissuance creates another
    short-lived token; there is no separate refresh endpoint.
  - Start with: `agentprovider.NewSelfHostedAgent`,
    `SelfHostedAgent.Issue`, `SelfHostedAgent.Handler`, `agent.New`, and
    `resource.NewAgentIdentity`.
  - Evidence: [`integration/bootstrap_self_hosted_test.go`](integration/bootstrap_self_hosted_test.go)
    and `go run ./example/selfhosted`.
  - Source note: Core's functional sections explicitly support this profile,
    while one later rationale paragraph says APs must always be distinct.
    `AAG-F104` records the contradiction.

### Not implemented

- [ ] **Concrete platform attestation — Not implemented.** The repository
  profile hands opaque evidence to host policy; it does not verify WebAuthn,
  App Attest, Play Integrity, or another platform trust chain.

## AAuth Budgets

Pinned source: [Budgets editor source](https://github.com/dickhardt/AAuth/blob/a99d353cf18aee81d0c5445bac070164fb3b8bc5/draft-hardt-aauth-budgets.md).

### Runnable journey

- [x] **Proactive direct three-party fixed-price Budget — Implemented alone or with an MCP class grant**
  - Flow: Agent → PS for a Person token → Resource selects one declared
    denomination and retains lineage → PS preserves the denomination and
    narrows the amount → Agent calls `BeginBudgetCall` → Resource verifies an
    optional MCP class grant, atomically charges the known cost, then dispatches
    → Agent receives validated cost and remaining feedback.
  - Start with: `budgets.NewUnit`, `budgets.NewValue`,
    `budgets.NewBoundedUnitDeclaration`, `resource.NewPSAuthorization`,
    `resource.BudgetConfig`, `personserver.NewPSAuthorization`,
    `personserver.BudgetConfig`, `Client.PersonToken`, `Client.Authorize`,
    `Client.Exchange`, and `Client.BeginBudgetCall`.
  - Evidence: [`integration/budget_three_party_test.go`](integration/budget_three_party_test.go),
    [`integration/r3_budget_three_party_test.go`](integration/r3_budget_three_party_test.go),
    and `go run ./example/budget`.
  - Boundary: this is proactive, direct, fixed-price, non-streaming,
    missionless, non-delegated, non-chained, and has no account binding. The
    combined path is direct MCP class authorization only.

### Bounded journey

- [ ] **Exhaustion or insufficiency step-up — Partial**
  - Flow: Resource refuses without charging → returns `401`, typed Budget
    reason, validated feedback, and a host-selected replacement Resource token
    → Agent returns `BudgetAuthorization` without exchanging or retrying it.
  - Start with: `resource.BudgetConfig.RetainLineage`,
    `resource.BudgetConfig.Challenge`, `Client.BeginBudgetCall`, and
    `BudgetCallResult.AuthorizationRequired`, `BudgetCallResult.Feedback`,
    `BudgetAuthorization.ResourceToken`, and `BudgetAuthorization.Reason`.
  - Evidence: [`agent/budget_call_test.go`](agent/budget_call_test.go),
    [`resource/budget_test.go`](resource/budget_test.go), and the fixed-price
    integration journeys. A combined challenge preserves the R3 reference.
  - Missing: exhaustion has no composed replacement-token exchange, new
    narrowed Auth token, or protected-call retry. Insufficiency exposes
    `remaining` and `required` for an explicit same-token shrink-and-retry, but
    no executable journey proves that branch. After an unverifiable post-send
    result, `BudgetCallUncertainError` carries the full signed grant and never
    retries.

### Not implemented

- [ ] **Reactive first-call Budget acquisition — Not implemented.** The
  baseline Person-token `401` challenge does not mint a default-sized Budget
  Resource token. Only proactive `AuthorizeRequest.Budget` requests enter the
  Budget offer path.
- [ ] **Four-party Budget authorization — Not implemented.** No PS-to-AS
  Budget ceiling, AS narrowing, or AS-issued Budget protected-call journey
  exists.
- [ ] **Variable-cost and streaming calls — Not implemented.** There is no
  reservation/settlement store contract, trailer reconciliation, or safe
  interrupted-stream journey.
- [ ] **Consumption history and usage queries — Not implemented as role journeys.**
  `budgets.NewConsumptionRecord` and token helpers cover the carrier, while the
  direct PS refuses nonempty history until retained prior-grant resolution
  exists. There is no usage endpoint or counter-response journey.
- [ ] **Delegation, call chaining, missions, and account-bound Budgets — Not implemented.**
  The Agent, PS, and Resource fail closed rather than carrying a Budget through
  these otherwise-supported Core compositions.

## AAuth interoperability demo profile

Pinned source: [interoperability profile editor source](https://github.com/dickhardt/AAuth/blob/a99d353cf18aee81d0c5445bac070164fb3b8bc5/interop-demo-profile.md).

This profile is informational. Passing its five surfaces within this
repository would not by itself demonstrate interoperability with an
independent implementation.

Two profile sentences diverge from Core. Surface 3 places keys directly in
Resource metadata, while Core and this implementation use metadata →
`jwks_uri` → JWKS (`AAG-F001`). Surface 5 says the child signs the Auth token;
Core instead has the PS or AS sign it and binds the child's key through
`cnf.jwk` and the HTTP proof (`AAG-F042`). See
[SPEC-FEEDBACK.md](SPEC-FEEDBACK.md). The entries below implement the
functional surfaces through Core; they do not claim those two literal
sentences.

### Runnable within this repository

- [ ] **Surfaces 1–4, mission-bound three-party — Implemented internally; partial against the literal profile**
  - Flow: Agent → PS mission approval and exact blob response → mission-bound
    Person token → Resource token with person and mission continuity →
    PS-issued Auth token → protected Resource call.
  - Start with: `Client.ProposeMission`, `agent.MissionResult.PersonToken`,
    `personserver.MissionConfig`, `resource.NewPSAuthorization`, and the
    ordinary Agent authorization methods.
  - Evidence: [`integration/mission_three_party_test.go`](integration/mission_three_party_test.go)
    and `go run ./example/mission`.

- [ ] **Surfaces 1–4, mission-bound four-party — Implemented internally; partial against the literal profile**
  - Flow: mission approval and Person token → Resource token → PS federation →
    AS-issued Auth token preserving mission digest → PS verification →
    protected Resource call.
  - Start with: `personserver.NewFederatedAuthorization`, `accessserver.New`,
    `resource.NewFederatedAuthorization`, and the mission Agent APIs.
  - Evidence: [`integration/mission_four_party_test.go`](integration/mission_four_party_test.go)
    and `go run ./example/fourparty`.

### Bounded and missing surfaces

- [ ] **Surface 5, parent-mediated sub-agent — Partial**
  - Flow: parent → PS with child Agent token → Person token bound to child key
    → child → Resource → parent → PS with child Resource and Agent tokens →
    Auth token bound to child key → child → Resource.
  - Evidence: [`integration/subagent_authorization_test.go`](integration/subagent_authorization_test.go)
    and `go run ./example/subagent`.
  - Missing: one journey that prepends mission-bound Surfaces 1–4 to Surface 5.

- [ ] **Independent-implementation interoperability — Not implemented**
  - No journey crosses from a Go role to an independently implemented role and
    back. The Explorer pin is comparator material, not bidirectional evidence.
  - Next proof: select one black-box external role and run a complete profile
    surface across that boundary with independent parsing, keys, and policy.

## How to verify the catalog

Run all repository evidence:

```sh
go test ./... -count=1
```

Then run the examples named by the journey you want to compose. Use
[CONFORMANCE.md](CONFORMANCE.md) for the denser claim-to-test matrix and
[SPEC-FEEDBACK.md](SPEC-FEEDBACK.md) for version-pinned questions raised by
implementation.
