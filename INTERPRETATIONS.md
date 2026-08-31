# Implementation interpretations

This file records choices needed where the pinned editor text is ambiguous or
internally inconsistent. Explicit requirements need no interpretation and do
not appear here; [CONFORMANCE.md](CONFORMANCE.md) says whether they are
implemented. See [SPECIFICATIONS.md](SPECIFICATIONS.md) for the exact source
revisions.

Companion-source text alone does not create an implementation interpretation.
This file gains a companion entry only when an accepted implementation path
requires a choice; source-only questions without such a path remain in
[SPEC-FEEDBACK.md](SPEC-FEEDBACK.md).

## Resource-token scope is optional when a companion claim replaces it

**Source:** AAuth Core, `Resource Token Structure`; R3, `Resource Token
Extensions`.

Core lists `scope` in the Resource-token payload without marking it REQUIRED
and permits a companion authorization claim to replace it. R3 expressly treats
Core scope as optional and requires independent enforcement when both are
present.

The target implementation accepts a Resource token with no Core scope when a
configured companion supplies the authorization claim. A token with neither
Core nor configured companion authorization remains invalid for an
authorization flow. When both are present, the accepting role validates and
enforces both; neither is projected into or treated as a substitute for the
other.

## R3 documents use immutable URIs and exact requested operation sets

**Source:** R3, `Authorization Endpoint Extensions`, `Operations Spanning
Multiple Definitions`, `Content Addressing`, `Caching`, and `AS Processing`.

R3 requires one URI to serve identical bytes but also permits later replacement
at that URI, while treating URI plus hash as a permanently refetchable record.
Those statements cannot all hold after an old body is evicted. The target
implementation never replaces bytes at a published R3 URI. Changed bytes
receive a new URI. The Resource document-store interface exposes no pruning
operation: once a URI becomes observable, its exact bytes remain loadable.

The general request mapping also allows a document that merely covers the
requested operations. Because the AS receives no separate authenticated copy
of the Agent's requested set, a broader reused document would prevent the AS
from knowing what was actually requested. The target implementation creates a
document whose operation set equals the validated requested set. Equal sets may
reuse one document; different sets do not. Every AS grant must be a subset of
that exact set.

These choices use the existing wire format. They do not add a request-set claim
or change the R3 hash algorithm.

## R3 document URIs bind bytes and fetch entitlement

**Source:** R3, `Content Addressing`, `Resource Enforcement`, and `R3 Document
Access Restriction`.

The source makes the document hash its identity, restricts fetches to the PS
and AS named by the Resource token, and says protected enforcement uses the
trusted issuer's `r3_granted` claim without fetching the document. It does not
define how a Resource recovers the entitled pair from a bare document URI.

This implementation derives an immutable URI from the Resource issuer, exact
document hash, and the PS/AS entitlement pair. The signed fetch handler checks
that derivation before serving exact bytes. At protected use, the Resource
recomputes the same URI from the verified Auth token and enforces the AS-signed
grant directly; it does not turn every protected call into a document-store
read. The Auth-token minting API separately proves the grant and account
against the fetched exact document before the AS can sign them.

The entitlement digest is a local URI construction, not a wire claim or a new
trusting party. Other conforming Resources may use a different immutable URI
scheme if they can recover and enforce the same PS/AS-only fetch boundary.

## Event replay identity is distinct from subscription identity

**Source:** Events, `Subscribe Token`, `Event Token`, and `Agent
Verification`.

The draft uses `eid` as the subscription identifier and permits multiple or
unlimited deliveries, then tells the Agent to deduplicate events by `(iss,
eid)`. Applying that literally discards every legitimate delivery after the
first.

The target implementation keeps `(iss, eid)` as subscription and routing
context. It derives a local delivery fingerprint as SHA-256 over the exact
compact Event token bytes, one zero byte, and the exact payload bytes. An exact
replay is ignored; a different authenticated token or payload on the same
subscription is a different delivery. The fingerprint is local state, not a
new wire claim.

## Events normative expiry and algorithm rules control conflicting text

**Source:** Events, `Subscribe Token`, `Event Token`, and `Agent
Verification`.

The draft says both `MUST NOT` and `SHOULD NOT` act after Event-token expiry.
The target implementation applies `MUST NOT`. It also rejects polymorphic
`EdDSA` as the normative token rule requires; examples using `EdDSA` are not
acceptance vectors. Both inconsistencies remain recorded for editor feedback.

## Mission-bound Resource and federated Auth tokens inherit upstream expiry ceilings

**Source:** AAuth Core, `Mission Approval`, `Resource Token Structure`, and
`Why presented_jti Exists`.

Core requires a mission-bound Resource token not to outlive the mission while
keeping mission content private to the Person Server. A Resource therefore
cannot read `expires_at` directly. This implementation caps the Resource token
at the verified Person token's `exp`; the Person Server already capped that
token at mission expiry.

Core also requires an AS-issued mission-bound Auth token not to outlive the
mission, but the AS likewise receives only `mission_s256` and the verified
Resource token. This implementation's Access Server conservatively caps the
Auth token at the Resource token's `exp`. The Person Server does not require an
independent AS to use that stricter ceiling: it verifies the returned Auth
token against the retained mission expiry, then atomically rechecks the
complete active mission before release. A conforming returned Auth token may
therefore outlive the Resource token, but never the mission.

## Unknown mission references at the Person Token Endpoint use `invalid_request`

**Source:** AAuth Core, `Person Token Endpoint`, `Mission Endpoint Errors`, and
`Token Endpoint Error Codes`.

Core requires the Person Token Endpoint to reject an absent or wrong-owner
mission but assigns `mission_not_found` only to a mission's own URL. Until the
registry says otherwise, this implementation returns the same `400
invalid_request` response for absent and wrong-owner references. It uses
`mission_terminated` only after the authenticated Agent's ownership is known.

Mission proposal policy denial is likewise unregistered. The immediate
approval endpoint provisionally returns `403 mission_denied`; the gap is
recorded in [SPEC-FEEDBACK.md](SPEC-FEEDBACK.md).

## Immediate authorization refusal uses provisional `access_denied`

**Source:** AAuth Core, `Token Endpoint Error Codes` and `AS Token Endpoint`.

Core distinguishes internal `server_error` but does not register an immediate
PS- or AS-policy denial result for these token endpoints. This implementation
uses explicit `ErrAccessDenied` sentinels for intentional policy refusals and
returns provisional `403 access_denied`; every other callback error is an
operational `500 server_error`. This keeps outages retryable without treating a
valid request as approved. The missing registered result is recorded in
[SPEC-FEEDBACK.md](SPEC-FEEDBACK.md).

## An accepted mission update identifies the authenticated request body

**Source:** AAuth Core, `Mission Log` and `Mission Update`.

Core defines an update digest over the update bytes “as the PS persists them”
but does not say whether the PS may rewrite the submitted document. This
implementation persists and hashes the exact authenticated JSON request body.
Its parsed fields drive policy; unknown additive members remain in the retained
bytes. This gives the Agent's returned digest one stable object without adding
a private canonicalization format.

## Immediate mission completion requires actual person acceptance

**Source:** AAuth Core, `Mission Completion` and `Mission Management`.

The immediate composition exposes ordinary PS update policy and a distinctly
named person-confirmation callback for completion. This follows the
update-specific rule that the PS may accept an update on its own, despite the
mission overview's conflicting person-decides statement. A successful
completion callback means the host obtained acceptance from the responsible
person; it is not an autonomous policy judgment that the summary looks
reasonable. The callback and exact completion record are followed by one
atomic transition to `terminated/completed`. Deployments that need interaction,
clarification, or deferred review cannot use this immediate path for those
outcomes.

Update and completion policy denial use provisional `403
mission_update_denied` and `403 mission_completion_denied`. Core registers no
denial result for either valid request—or clearly say immediate refusal is an
allowed outcome. Mission actions are sent once and have no lost-success
recovery identity. These gaps are recorded in
[SPEC-FEEDBACK.md](SPEC-FEEDBACK.md).

## Mission termination closes PS decisions, not outstanding tokens

**Source:** AAuth Core, `Mission Management`, `Mission Status Errors`, and `Why
Missions Are Not a Policy Language`.

After completion, the implementation rejects later mission actions, Person
token issuance, and Auth-token exchange at the PS. It does not revoke already
issued credentials: the Resource receives only `mission_s256`, has no mission
state channel, and continues to apply the credential's own expiry. The Agent
must stop using a terminated mission. Core does not define a stronger
termination-propagation mechanism.

## Missing deferred `Retry-After` uses the stated five-second fallback

**Source:** AAuth Core, `Pending Response` and `Polling with GET`.

Core both marks `Retry-After` required and defines a five-second default when
it is absent. The receiver implements the explicit fallback. A present header
must still contain one valid nonnegative delay. The contradiction remains in
[SPEC-FEEDBACK.md](SPEC-FEEDBACK.md).

## Parent-mediated credentials use the child key and the earlier expiry

**Source:** AAuth Core, `Person Token Endpoint`, `Resource Token
Verification`, `AS Token Endpoint`, and `Sub-Agents`.

The parent signs both Person Server requests, but the child uses every issued
credential. The person and auth token are therefore verified and issued
against the child token's `cnf.jwk`; the resource token's `agent_jkt` must name
that same key. Each issued token is capped by the earlier of the parent and
child Agent-token expirations.

The child token's optional `ps` claim does not select this flow; the parent
selects and authenticates to its Person Server. The Person Server retains the
child's Agent Provider, child, parent, and child key with the person-token
record. A later token request must match that record before policy runs. The
parent and child keys must be distinct, and the Resource receives none of the
relationship fields.

The record binds the stable relationship, not one compact child token. A later
valid child token may rotate `jti`, expiry, or additional policy claims when
issuer, child, parent, and key remain unchanged; policy receives the current
claims.

The Person Server verifies the HTTP proof before applying the top-level-only
request rule. A correctly signed direct request from a child returns
`400 invalid_agent_token` without `Signature-Error`; a forged proof returns
`401` with its Signature-Key failure. Core requires the direct-child refusal
but does not assign it an error code.

**Executable examples:**
`personserver/subagent_test.go:TestServerIssuesImmediatePersonAndAuthTokensForSubagent`
and
`integration/subagent_authorization_test.go:TestCurrentCoreParentMediatedSubagentImmediatePSAuthorization`.

## Immediate call chaining uses token trust plus explicit chain bindings

**Source:** AAuth Core, `Auth Token Verification`, `Upstream Token
Verification`, and `Call Chaining`.

Generic auth-token verification includes Resource request-context checks that
do not apply when a Person Server receives an upstream token in a request
signed by an intermediary. This implementation verifies the upstream JWT's
type, issuer key, and time first. It then requires a Person-role token with
`iss == ps` equal to the receiving Person Server and `aud` equal to the
intermediary Agent token's `iss`.

The upstream token remains bound to the original Agent's key. It is not
required to match the intermediary's request key. The intermediary proves its
own identity separately with its Agent token and HTTP signature. Because Core
compares upstream `aud` with Agent-token `iss`, this path composes Resource 1
and its Agent Provider at one identifier. The intermediary Agent token's own
`ps` does not route or authorize the chain.

The same-PS restriction is the complete trusted-issuer policy for this first
path. It does not claim the general “previously brokered or authorized to
extend” relationship.

**Executable examples:**
`agent/call_chaining_test.go:TestCallChainingRoutesFromUpstreamTokenAndCarriesItExactly`
and
`integration/call_chaining_test.go:TestCurrentCoreImmediateTwoResourceCallChain`.

## Both Person Server calls bind the same exact upstream token

**Source:** AAuth Core, `Person Token Endpoint`, `PS Token Endpoint`, and
`Call Chaining`.

Core places `upstream_token` on both Person Server requests but does not define
how the two presentations relate. This implementation commits the upstream
token's `(iss, jti)` and SHA-256 of its exact compact serialization with the
downstream person-token record. The later `/token` request must repeat both the
same reference and the same bytes. A separately signed token with equal claims
does not match.

The store retains the reference and digest, not the compact token. Direct and
parent-mediated person-token records leave both fields empty. A half-populated
record is invalid.

**Executable example:**
`personserver/call_chaining_test.go:TestCallChainingRetainedUpstreamRejectsSubstitutionAndByteRewrite`.

## Call-chain policy derives a new person context and independent grant

**Source:** AAuth Core, `Person Token Endpoint`, `Directed Identifiers Across
a Chain`, `Call Chaining`, and `Agent-Person Binding`.

`CallChaining.BindPerson` receives copy-safe verified upstream claims and maps
the upstream directed subject to the person context used for Resource 2. It
must return a different directed subject; the server refuses a copied value.
This host policy is the missing person-directory boundary. The ordinary
`BindPerson` callback is not used for a chained request.

`CallChaining.Authorize` receives another independent copy and decides the
downstream scope and lifetime. The scope need not be a subset of the upstream
scope. The upstream token must be current at each Person Server request, but
the downstream person or auth token is not capped by the upstream expiration;
Core does not state such a derived-token ceiling.

The special person selection applies only when a Resource intermediary
presents a verified upstream token. Requests without one keep the ordinary
one-Agent/one-person binding.

**Executable example:**
`integration/call_chaining_test.go:TestCurrentCoreImmediateTwoResourceCallChain`.

## Unsupported valid call-chain branches fail as server errors

**Source:** AAuth Core, `Call Chaining`, `Interaction Chaining`, `Sub-Agents`,
and `Token Endpoint Error Codes`.

The first evidenced call-chain path is immediate, missionless, accountless,
and PS-authorized. Missions, accounts, sub-agents, and Access Server federation
are not partially processed. Once their otherwise valid context is recognized,
the Person Server returns `500 server_error` before chain policy,
pending-state creation, or issuance. Ordinary interaction selectors are never
called for a chained request; `CallChaining` is an explicitly immediate policy
pair.

The public seam has no depth marker. A Resource can compose it again for
another same-PS hop, but repeated-hop behavior is untested and unclaimed; it is
not classified as an unsupported branch.

An invalid verified upstream token provisionally returns
`400 invalid_upstream_token`; Core has no registered upstream-token error. A
malformed parameter or a configuration without explicit `CallChaining`
support returns `400 invalid_request`. These names can change when Core defines
the missing error contract.

**Executable example:**
`personserver/call_chaining_test.go:TestCallChainingRefusesUnsupportedValidBranchesAndIsolatesOrdinaryInteractions`.

## A federated Access Server verifies both Agent tokens

**Source:** AAuth Core, `PS-to-AS Token Request`, `Auth Token Delivery`, and
`Parent-Mediated Authorization`.

The source sends both tokens to the Access Server but does not explicitly say
whether the AS verifies them itself. This implementation does. The AS verifies
the parent and child tokens at the Person Server proof's fixed instant,
confirms their relationship, and requires the parent token to name the signing
Person Server. The child's optional `ps` claim does not select the flow. Policy
receives both identities, and issuance uses only the child key. The Person
Server then verifies the returned auth token against the child key before
returning it to the parent.

**Executable example:**
`integration/subagent_authorization_test.go:TestCurrentCoreParentMediatedSubagentImmediateASAuthorization`.

## Four-party person identity uses `(ps, sub)`

**Source:** AAuth Core, `Auth Token Structure` and `Auth Token Verification`.

An auth token's `iss` names its issuer. In a four-party exchange that issuer is
the access server, while `ps` names the person server that owns the `sub`
namespace. The verification text nevertheless says that `(iss, sub)` identifies
the person.

The Resource exposes person identity to its protected handler as `(ps, sub)`.
A change of Access Server therefore does not change the identity pair, and the
same `sub` under two Person Servers still names two people. `tenant` is context,
not part of this pair. This library does not retain a person directory.

This choice follows the resource-token chain, where the resource copies `ps`
and `sub` from the verified person token. It also keeps the identity namespace
anchored at the server that created the directed identifier.

**Executable example:**
`resource/server_test.go:TestProtectedHandlerReceivesCurrentPrincipal`.

## Person-token policy denial uses `person_token_denied`

**Source:** AAuth Core, `Person Token Endpoint` and `Token Endpoint Error
Codes`.

The registered errors distinguish malformed or expired credentials from an
unreachable person, but do not name a valid request denied by person-server
policy.

The implementation returns HTTP `403` with
`error: "person_token_denied"` for that case. It does not reuse
`user_unreachable` or describe valid input as `invalid_request`.

This is a provisional extension, not a registered AAuth error. Clients must
treat an unknown terminal `403` as denial. The name can change when the Core
specification defines this result.

## Query-bearing requests cover `@query`

**Source:** AAuth Core, `Covered Components` and `Verification`; RFC 9421,
Section 2.2.7.

The mandatory Core set includes `@path`, which excludes the query. A signature
over only that set can therefore be replayed with another query on an endpoint
where query parameters select behavior.

The implementation adds `@query` whenever the request target has a query and
requires the verifier to cover the same value. A request without a query keeps
the four-component Core baseline. Changing the query after signing invalidates
the proof.

**Executable example:**
`signaturekey/request_external_test.go:TestRequestProofCoversAnExactQueryWhenPresent`
and `TestRequestProofCoversAnExplicitEmptyQuery`.

## Resource-managed sessions bind the stable Agent identity

**Source:** AAuth Core, `AAuth-Access` and `Agent Token Verification`.

Core says an opaque session token names a relationship with “this agent” and
must be accompanied by a valid Agent signature, but it does not say whether a
session survives rotation of the Agent token's `cnf` key.

The Resource binds a session to the Agent Provider, Agent identifier, and
optional parent Agent. Every request must still carry a current AP-issued
agent token and a matching HTTP proof. A new agent token for the same stable
identity may therefore poll and use the session with a new proof key; a token
for another Agent cannot. Reassigning the same Agent identifier at the AP also
preserves the session unless the Resource revokes it.

**Executable examples:**
`resource/session_test.go:TestResourceManagedInteractionApprovesAcrossRecompositionAndBindsStableAgent`
and `resource/session_test.go:TestSessionUseVerifiesProofBeforeLoadAndRejectsEveryBindingFailure`.

## `AAuth-Access` is an opaque credential, not a JWT profile

**Source:** AAuth Core, `Overview` and `AAuth-Access`.

The overview says all AAuth tokens are JWTs. The more specific
`AAuth-Access` section defines a Resource-owned opaque `token68`, permits it to
wrap an existing OAuth or session credential, and defines no JWT claims.

The library applies the specific `AAuth-Access` rules. It validates only the
`token68` wire form and never parses the credential as a JWT. Proof of
possession comes from the Agent signature covering `Authorization`, not from a
session-token `cnf` claim.

**Executable example:**
`integration/resource_managed_session_test.go:TestCurrentCoreResourceManagedSessionAcrossResourceRecomposition`.

## Four-party tenant context remains in the Person Server namespace

**Source:** AAuth Core, `Auth Token Structure` and `Person Token Structure`.

Core says `(iss, tenant)` identifies an organization, but four-party auth-token
`iss` names the Access Server while `tenant` is copied from the Person Server.
Changing Access Servers must not silently rename the organization.

The Resource therefore presents tenant beside `PersonIdentity{Issuer: ps,
Subject: sub}` in a separate `PersonContext`. Hosts that use tenant as an
organization hint interpret it in the Person Server namespace. Tenant does not
participate in stable person matching.

## Authorization requests always bind their JSON body

**Source:** AAuth Core, `Authorization Endpoint Request`, `Covered Components`,
and `Resource Metadata`.

The authorization request carries `scope`, which decides what the Resource
may issue. Applying `additional_signature_components` globally cannot safely
solve this for Resources that also have bodyless protected routes.

This implementation always signs and requires `content-type` and
`content-digest` at `/authorize`, then adds the Resource's advertised
components. Advertised components alone govern ordinary protected routes. A
transport-mutation test proves that changing `scope` after signing is refused.

**Executable example:**
`integration/core_four_party_test.go:TestCurrentCoreFourParty`.

## A bodyless poll can cover the digest of empty content

**Source:** AAuth Core, `Resource Metadata` and `Polling with GET`; RFC 9530,
Sections 2 and 6.3.

Core requires every Resource-advertised signature component on Resource
requests, while polling switches to `GET` without resending the original body.
RFC 9530 permits `Content-Digest` over empty content to prove that no content
was added.

When a poll profile includes `content-digest`, the signer emits the SHA-256
digest of empty content and leaves the request body absent. The caller supplies
fresh values for any other advertised header fields through
`PollResourceSessionWithComponents`.

**Executable example:**
`integration/resource_managed_session_test.go:TestCurrentCoreResourceManagedSessionAcrossResourceRecomposition`.

## The first two-key Bootstrap path is an explicit Agent Provider profile

**Source:** AAuth Bootstrap, `Per-Platform Key Handling`, `Two-Key Refresh`,
`Web App Enrollment`, and `Mobile App Enrollment`; Signature-Key, `Header Web
Key (hwk)`, `JKT JWT Self-Issued Key Delegation (jkt-jwt)`, `Signature-Key
Integrity`, and `Signature-Error HTTP Response Header`; AAuth Core, `Covered
Components` and `Freshness and Replay`.

Bootstrap describes a preferred durable-to-ephemeral key pattern but says its
mechanisms are informational. It defines no discoverable endpoint, request or
response envelope, status table, or replay-store contract. The implementation
therefore exposes two path-agnostic handlers that a host mounts at configured
Agent-Provider-origin URLs. The explicit Agent caller receives those URLs; AP
metadata is unchanged.

Both operations use signed `application/json` with exact `content-type` and
`content-digest` coverage. Enrollment presents the durable key through `hwk`
and carries one opaque `evidence` value. Refresh carries optional `ps` plus one
opaque `evidence` value, presents a durable-signed Ed25519
`jkt-s256+jwt`, and signs the HTTP request with its delegated ephemeral key.
The AP callbacks interpret evidence, assign the Agent identity, approve the
requested PS, and decide token lifetime and additive claims. Evidence is
opaque authenticated input, not proof of account state or attestation; the
host callback validates any session, server nonce, and platform trust chain.
These field names and statuses are repository profile choices, not additions
to AAuth.

The first profile has one exact signed-component set: the Core method,
authority, path, and `signature-key` fields plus `content-type` and
`content-digest`. Host login, nonce, or attestation material belongs inside
the signed `evidence` value. Additional application-specific signed headers
are not supported by this first profile. The profile adopts Core's covered
components and the `signaturekey.DefaultSignatureWindow` 60-second outer
request-proof window. Generic replay enforcement remains separate.

The profile uses one explicit response table:

| Result | HTTP response |
| --- | --- |
| Enrollment retained | `201` JSON plus `Cache-Control: no-store` |
| Refresh retained or exactly replayed | `200` JSON plus `Cache-Control: no-store` |
| Method other than `POST` | `405 invalid_request` plus `Allow: POST` |
| Media type other than `application/json` | `415 invalid_request` |
| Signature-Key proof failure | `401`; `Signature-Error`, problem `type`, and body `error` carry the same Signature-Key code |
| Delegation expires before a first result commits | `401 expired_jwt`; no result is retained |
| Invalid profile body or semantic input | `400 invalid_request` |
| Policy denial or inactive enrollment | `403` with the profile-specific denial code and no Signature-Key challenge |
| Missing enrollment | `404 enrollment_not_found` |
| Conflicting enrollment or refresh identity | `409` with the corresponding profile conflict code |
| Policy, store, or signing failure | `500 server_error` |

The refresh profile requires `jti` even though generic Signature-Key requires
it only for assertion caching. The AP treats `(durable identity, jti)` as one
request identity. It binds the exact naming JWT and JSON body. Recovery reuses
the full `RefreshAgentTokenInput`: Agent, requested PS, exact evidence bytes,
delegated key, JTI, issued time, and expiry. The client reconstructs that
stable input but freshly signs the outer HTTP request. An exact retry returns
the retained first Agent token; a different naming JWT or JSON body conflicts.
The store returns any existing winner first, then atomically refuses a first
commit when its trusted clock reaches the delegation expiry. A host may
therefore prune at expiry without allowing an already-verified request to
recreate the result. Generic HTTP-proof replay enforcement remains separate
and unimplemented.

An exact retained result remains available from the host-supplied
`EnrollmentStore` while that record is retained, even after the enrollment
becomes disabled or revoked. This completes an issuance that was already
committed; it does not authorize a new token. This repository supplies no
durable EnrollmentStore adapter or process-restart proof. Disabling issuance
does not invalidate an already-issued token under Core, so a host that needs
active invalidation must apply its separate Agent-token revocation policy. A
new JTI still loads the current enrollment and is refused unless it is active.

This first profile supports Ed25519 durable and ephemeral keys only. Rotating
the ephemeral key preserves the assigned Agent identifier. Replacing the
durable key is a new enrollment; continuity for that case is not implemented.
The Agent caller is responsible for generating a new ephemeral key for each
new JTI. The AP proves that the delegated key differs from the durable key but
does not keep an unbounded history to prove that key material was never used
before.

**Executable examples:**
`signaturekey/jkt_jwt_external_test.go`,
`agentprovider/enrollment_http_test.go`,
`agent/bootstrap_test.go`,
`integration/bootstrap_refresh_test.go`, and `example/bootstrap`.

## Failed JWKS refresh may use the bounded cached entry

**Source:** AAuth Core, `JWKS Discovery and Caching`; Signature-Key, `Caching
and Performance`.

Signature-Key says to respect HTTP freshness. Core adds the AAuth-specific
outage rule: after a fetch failure, use an available cached JWKS and discard it
after at most 24 hours.

The resolver attempts refresh when HTTP freshness expires. If that attempt
fails, it follows Core and may use the previously cached key until the fixed
24-hour discard bound. It never extends that bound from a failed request.

**Executable example:**
`signaturekey/discovery_external_test.go:TestHTTPKeyResolverUsesStaleCacheOnlyWithinCoreDiscardBound`.

## An R3 proposal URI identifies one invocation, not only its content

**Source:** R3, `per-call` authorization.

Two calls with identical proposal JSON have the same `r3_s256`, but approval
and execution are single-use. The Resource therefore gives each invocation a
fresh Resource-token `jti` and full proposal URI. `R3ProposalStore.Commit` is
create-only by that URI; any identifier collision fails before a `401` or
`202` becomes observable. The content digest remains the exact-byte identity,
while the URI is the invocation identity.

**Executable example:**
`resource/r3_per_call_test.go:TestMCPR3PerCallClassOperationCommitsProposalAndRetryBeforeChallenge`.

## Resource-token expiry closes Auth issuance, not an issued Auth token

**Source:** AAuth Core, `Auth Token Delivery`, `Deferred Delivery`, and R3
`per-call` authorization.

A class or proposal Auth token must have `iat` inside the Resource token's
issuance window. Its own valid `exp` may be later. A first retry or poll may
therefore occur after Resource-token expiry. The Resource retains execution
custody through `CompletionUntil`, exactly one maximum Auth-token lifetime
after Resource-token expiry; completed results remain exact-token replayable.

For delayed per-call consent, the Person Server retains the original person
record through the maximum Resource-token plus Auth-token lifetime. Only a
verified proposal artifact may reuse that retained identity after the original
Person token expires; a new class authorization may not.

**Executable examples:**
`resource/held_test.go:TestHeldAuthTokenIssuedBeforeResourceExpiryCanFirstExecuteLater`,
`resource/r3_per_call_test.go:TestMCPR3PerCallClassOperationCommitsProposalAndRetryBeforeChallenge`,
and
`personserver/r3_proposal_test.go:TestFederatedMCPR3ProposalUsesDistinctConsentAndVerifiesExactResult`.

## Held and per-call replay bind the exact compact Auth token

**Source:** AAuth Core, `Deferred Delivery`.

Core requires a repeated presentation of “the same auth token” to replay a
held invocation, but it does not define whether sameness means claims, `jti`,
signature, or compact serialization. Its general Pending URL Security section
also says every poll after a terminal response must return `410 Gone`, which
contradicts the held-delivery replay requirement.

`HeldInvocationStore.Claim` and `R3RetryStore.Claim` receive the SHA-256 digest
of the exact compact token bytes. Only that exact token can replay the retained
result. A separately signed token with identical claims cannot consume the
record. The replay rule is treated as the specific exception to the general
`410 Gone` rule.

**Executable example:**
`resource/held_test.go:TestHeldAuthTokenInvocationCompletesOnceAndReplays` and
`resource/r3_per_call_test.go:TestMCPR3PerCallClassOperationCommitsProposalAndRetryBeforeChallenge`.

## A lost held or per-call execution is never reclaimed automatically

**Source:** AAuth Core, `Deferred Delivery`.

Core prohibits re-executing a completed held invocation, but it does not define
a recovery protocol for a Resource process that stops after an atomic claim and
before durable result retention. Reclaiming after a timeout could execute an
application consequence twice.

This implementation has no lease or reclaim transition. After an indeterminate
claim or retention result, the held store exposes either a committed replay or
`ErrHeldExecutionUnresolved`; the baseline R3 retry store does the same with
`ErrR3RetryUnresolved`. A caller can start a new application request, but the
original record never becomes executable again.

An unresolved poll returns the registered `500 server_error`. It does not use
`503`: the implementation has no retry schedule or condition under which that
record becomes executable again.

The test below injects an uncertain `Retain` result into the store contract.
This repository has no durable adapter or process-restart proof.

**Executable example:**
`resource/held_test.go:TestHeldAuthTokenRetainFailureWithholdsResultAndNeverReexecutes` and
`resource/r3_per_call_test.go:TestMCPR3PerCallClassOperationCommitsProposalAndRetryBeforeChallenge`.

## An application `202` starts a nested deferred response

**Source:** AAuth Core, `Deferred Delivery` and `Deferred Responses`.

Core says the held poll returns the invocation's response and separately says
every `202` is a deferred response whose polling ends only on a non-`202`.

When the protected application returns `202`, the Resource treats it as the
retained result only if it contains a same-origin `Location`, decimal
`Retry-After`, `Cache-Control: no-store`, and an unambiguous
`application/json` body with `status`. The original held record then replays
that response. `PollAuthToken` returns it without following the new location;
the caller can continue that separate deferred operation explicitly.

**Executable example:**
`resource/held_test.go:TestHeldAuthTokenRetainsWellFormedApplicationPendingResponse`.

## Deferred PS consent expires with the original resource token

**Source:** AAuth Core, `Resource Token Structure`, `PS Token Endpoint`, and
`Deferred Responses`.

Core tells an Agent to obtain a fresh resource token when an AS exchange is
delayed past expiry, but does not say whether a three-party PS may decide after
the resource token used to create its pending request expires.

The three-party pending deadline is the earliest of the host policy lifetime,
the initial Agent-token expiry, and the original resource-token expiry. This
keeps a later approval inside every credential bound that justified creating
the pending request.

After the first terminal response, the store marks the pending URL gone. Core
does not register a separate error name for that state, so the implementation
uses `410 invalid_code`, the registered result for a consumed or unrecognized
interaction code.

**Executable examples:**
`personserver/authorization_interaction_test.go:TestDeferredAuthorizationDecisionRacesAndDeadlineAreTerminal`
and
`integration/deferred_ps_authorization_test.go:TestCurrentCoreDeferredPSAuthorizationAcrossRecomposition`.

## Three choices for bounded three-party revocation

**Source:** AAuth Core, `Token Revocation`, `Keying Material`, `Covered
Components`, `Authentication Errors`, and `Verification (Server)`.

### Server identity and body binding

The revocation example uses `scheme=jwt`, but a three-party auth token binds
the Agent's key, not the issuing Person Server's key. The example also signs no
body component even though `(iss, jti)` selects the token to terminate.

The Person Server therefore signs `/revoke` with its existing `jwks_uri`
server identity. Both sides require `content-type`, `content-digest`, and the
Resource's advertised components. The Resource accepts only the PS that equals
the token issuer in this three-party path.

### Refusal after revocation

A revoked token still has a valid signature and request proof. Because Core
does not define the protected-use response, this implementation provisionally
returns `403 access_denied` rather than a misleading `401 Signature-Error`.
This check stops a request only when the store reports revocation before host
callbacks; it does not cancel an already-admitted in-flight request.

### No pre-use tombstone

The Resource returns `404` when it has not yet observed `(iss, jti)`; it does
not invent a pre-use tombstone from an underspecified request.

**Executable examples:**
`resource/revocation_test.go:TestRevocationEndpointRequiresBoundPersonServerProof`
and
`integration/revocation_reauthorization_test.go:TestThreePartyRevocationAndExplicitReauthorizationAcrossResourceRecomposition`.
