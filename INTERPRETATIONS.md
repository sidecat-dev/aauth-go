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

The implementation keeps `(iss, eid)` as subscription and routing
context. It derives a local delivery fingerprint as SHA-256 over the exact
compact Event token bytes, a separator, the signed content type, another
separator, and the exact payload bytes. An exact replay is ignored; a different
authenticated token, content type, or payload on the same subscription is a
different delivery. The fingerprint is local state, not a new wire claim.

## Events uses the stricter normative expiry rule

**Source:** Events, `Subscribe Token`, `Event Token`, and `Agent
Verification`.

The draft says both `MUST NOT` and `SHOULD NOT` act after Event-token expiry.
The implementation applies `MUST NOT`. The inconsistency remains recorded for
editor feedback.

## Events registration has exact retry and delivery-time endpoint resolution

**Source:** Events, `Overview`, `Subscribe Token Verification`, `Event
Delivery`, and `Subscribe Token Replay at Registration`.

The overview says the Resource stores the AP event endpoint at registration,
while both detailed delivery sections require resolving the current endpoint
at delivery time. This implementation retains only the AP issuer and resolves
current metadata for every explicit delivery attempt. Both the metadata URL
and the discovered delivery endpoint pass host egress admission.

The replay section recommends rejecting a repeated `eid`, but does not define
the response to an exact retry after a lost registration result. This
implementation hashes the compact subscribe token, content type, and exact
parameter bytes. The same registration recovers the first retained Resource
record; changed bytes under that `eid` conflict.

## Protected Events tickets keep Resource policy opaque

**Source:** Events, `Protected Subscriptions` and `Subscription Ticket
Replay`.

Events defines the protected ticket as an opaque, short-lived, single-use URL
bound to the Agent and context of a prior authenticated interaction. It leaves
the ticket representation, lifetime, and Resource policy undefined. This
implementation therefore retains a host-generated path segment and opaque
context rather than defining another token. The Resource host chooses a
same-origin URL prefix, an explicit maximum lifetime, and the policy that
interprets the retained context.

Ticket consumption and subscription registration share one store operation.
While the original subscribe token remains valid, an exact retry returns the
retained registration even after the unused-ticket deadline and does not rerun
host policy; a changed retry conflicts. An unused ticket still expires at its
deadline.
A request whose subscribe-token `sub` does not match the retained Agent is
cloaked as a missing ticket, and an expired ticket returns a distinct terminal
refusal. These are repository storage and HTTP-response choices around the
source-defined binding, not new Events wire fields.

## Bodyless Events deliveries sign the exact empty body

**Source:** Events, `Event Delivery: Resource to AP`; HTTP Signature Keys,
`Covered Components`.

Events makes the payload optional but shows only a body-bearing signature. The
bodyless profile here omits `content-type` and still covers a
`content-digest` for zero bytes. That preserves the distinction between an
intentional empty payload and bytes injected after signing without inventing a
wire field. The same profile requires both `content-type` and
`content-digest` when registration parameters or an event payload are present;
that body-binding requirement is an implementation hardening recorded as
`AAG-F084` (since withdrawn), not a claim that the current Events text already requires it.

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
a Chain`, `Call Chaining`, and `Agent-Person Binding`; for the expiry ceiling
only, AAuth Protocol -11 `Person Token Structure`, `Auth Token Structure`, and
`Call Chaining`.

`CallChaining.BindPerson` receives copy-safe verified upstream claims and maps
the upstream directed subject to the person context used for Resource 2. It
must return a different directed subject; the server refuses a copied value.
This host policy is the missing person-directory boundary. The ordinary
`BindPerson` callback is not used for a chained request.

`CallChaining.Authorize` receives another independent copy and decides the
downstream scope and lifetime. The scope need not be a subset of the upstream
scope. The upstream token must be current at each Person Server request. Under
the targeted Protocol -11 overlay in `SPECIFICATIONS.md`, the downstream person
and auth tokens expire no later than the verified upstream token. The policy
lifetime, the Agent-token bound, the presented-token bound and any mission
bound still apply, so the shortest bound wins. The ceiling comes from the
upstream claims already verified for the request; no separate expiry record is
kept.

The special person selection applies only when a Resource intermediary
presents a verified upstream token. Requests without one keep the ordinary
one-Agent/one-person binding.

**Executable examples:**
`integration/call_chaining_test.go:TestCurrentCoreImmediateTwoResourceCallChain`
and
`personserver/call_chaining_test.go:TestCallChainingKeepsShorterBoundsUnderUpstreamExpiry`.

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

## Resource handlers admit their configured authority

**Source:** AAuth Core `a99d353` and `28e8258`, `Covered Components` and
`Verification (Server)`; RFC 9421 Section 2.2.3;
[RFC 9110 Sections 7.4 and 15.5.20](https://www.rfc-editor.org/rfc/rfc9110.html#name-421-misdirected-request).

The draft requires coverage and verification of the received request's
authority. It does not explicitly compare that authority with the Resource's
configured identifier. Its cross-host replay rationale assumes correct HTTP
routing. This check is a local routing safeguard, not a claim that the draft
already specifies this comparison or its error response. AAG-F107 in
[SPEC-FEEDBACK.md](SPEC-FEEDBACK.md) asks where that responsibility belongs.

A valid signature binds the request's target host, but does not prove that the
receiving handler serves that host. An Auth token's audience check is also
insufficient: its audience can match the Resource while the signed request
names another host.

`resource.Server.Handler` and `resource.ResourceManagedServer.Handler` therefore
admit only their configured Issuer's authority before routing or authentication.
The check uses `Request.Host`, falling back to `URL.Host`, accepts DNS case differences and the default HTTPS port
443, and ignores forwarding headers. A foreign authority receives HTTP 421
with `no-store`, without `Signature-Error`: the request is misdirected, not
necessarily incorrectly signed. This also makes foreign-host R3 document
fetches return 421 before their document-access checks.

The issuer has no path. Application routing and authorization decide which
correctly signed paths it serves; changing a path after signing still fails
signature verification. Reverse proxies must preserve the public authority
and signed target. The Resource-managed session service applies the same check
to initial authorization, session use, discovery and pending routes. Event
services have their own endpoint binding checks.

**Evidence:** `resource/authority_test.go:TestResourceBindsRequestAuthorityToIssuer`
covers Agent identity, Person identity, PS-issued Auth tokens and AS-issued
Auth tokens, including host/path mutations and forwarding-header controls.
`resource/session_authority_test.go:TestResourceManagedRejectsForeignAuthorityBeforeSessionAccess`
checks the session service before authorization policy, store access or dispatch.

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

Person Server continuation GETs and authorization cancellation DELETEs test
whether request content is empty, not whether Go represents the body as
`http.NoBody`. In particular, an empty HTTP/2 request can carry a non-nil empty
reader. The check reads at most one byte and rejects payloads and read errors;
route-specific credential and continuation validation remains unchanged.
`personserver/permission_http2_test.go` exercises a real HTTP/2 permission poll,
payload rejection, and one-shot consumption. The sibling handler checks in
`personserver/bodyless_request_test.go` verify empty-reader handling and
credential rejection, not complete transport journeys for those routes.

## Hosted Bootstrap key patterns share one explicit Agent Provider profile

**Source:** AAuth Bootstrap, `Per-Platform Key Handling`, `Refresh Patterns`,
`Web App Enrollment`, and `Mobile App Enrollment`; Signature-Key, `Header Web
Key (hwk)`, `JKT JWT Self-Issued Key Delegation (jkt-jwt)`, `Signature-Key
Integrity`, and `Signature-Error HTTP Response Header`; AAuth Core, `Covered
Components` and `Freshness and Replay`.

Bootstrap describes a preferred durable-to-ephemeral key pattern and an
optional simpler single-durable-key pattern, but says its
mechanisms are informational. It defines no discoverable endpoint, request or
response envelope, status table, or replay-store contract. The implementation
therefore exposes one shared enrollment handler and separate path-agnostic
two-key and single-key refresh handlers that a host mounts at configured
Agent-Provider-origin URLs. The explicit Agent caller receives those URLs; AP
metadata is unchanged.

Both operations use signed `application/json` with exact `content-type` and
`content-digest` coverage. Enrollment presents the durable key through `hwk`
and carries one opaque `evidence` value. Refresh carries optional `ps` plus one
opaque `evidence` value, presents a durable-signed Ed25519
`jkt-s256+jwt`, and signs the HTTP request with its delegated ephemeral key.
Single-key refresh presents the same durable key through `hwk`, signs the HTTP
request with it directly, and carries a signed `refresh_jti` plus
`refresh_expires_at` for bounded exact-result recovery.
The AP callbacks interpret evidence, assign the Agent identity, approve the
requested PS, and decide token lifetime and additive claims. Evidence is
opaque authenticated input, not proof of account state or attestation; the
host callback validates any session, server nonce, and platform trust chain.
These field names and statuses are repository profile choices, not additions
to AAuth.

Both profiles have one exact signed-component set: the Core method,
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
| Signed refresh identity expires before a first result commits | `401 expired_jwt`; no result is retained |
| Invalid profile body or semantic input | `400 invalid_request` |
| Policy denial or inactive enrollment | `403` with the profile-specific denial code and no Signature-Key challenge |
| Missing enrollment | `404 enrollment_not_found` |
| Conflicting enrollment or refresh identity | `409` with the corresponding profile conflict code |
| Policy, store, or signing failure | `500 server_error` |

The AP treats `(durable identity, refresh jti)` as one request identity. In the
two-key profile it binds the exact naming JWT and JSON body; recovery reuses the
full `RefreshAgentTokenInput`, including delegated key and delegation times. In
the single-key profile it binds the exact signed JSON body; recovery reuses
`SingleKeyRefreshAgentTokenInput`, including the unchanged durable key, JTI,
and expiry. The single-key recovery window is at most 24 hours so caller input
cannot impose unbounded retention. Both clients freshly sign the outer HTTP
request. An exact retry returns the retained first Agent token; a changed key
profile, proof material, or JSON body conflicts. The store returns any existing
winner first, then atomically refuses a first commit when its trusted clock
reaches the signed request expiry.

An exact retained result remains available from the host-supplied
`EnrollmentStore` while that record is retained, even after the enrollment
becomes disabled or revoked. This completes an issuance that was already
committed; it does not authorize a new token. This repository supplies no
durable EnrollmentStore adapter or process-restart proof. Disabling issuance
does not invalidate an already-issued token under Core, so a host that needs
active invalidation must apply its separate Agent-token revocation policy. A
new JTI still loads the current enrollment and is refused unless it is active.

These profiles support Ed25519 keys only. Rotating
the ephemeral key preserves the assigned Agent identifier. Replacing the
durable key is a new enrollment; continuity for that case is not implemented.
The Agent caller is responsible for generating a new ephemeral key for each
new JTI. The AP proves that the delegated key differs from the durable key but
does not keep an unbounded history to prove that key material was never used
before.

**Executable examples:**
`signaturekey/jkt_jwt_external_test.go`,
`agentprovider/enrollment_http_test.go`,
`agentprovider/storetest/enrollment.go`,
`agent/bootstrap_test.go`,
`integration/bootstrap_refresh_test.go`,
`integration/bootstrap_single_key_test.go`, and `example/bootstrap`.

## Self-hosted issuance uses the ordinary Agent-token trust path

**Sources:** AAuth Core, `Agent + AP`, `AAuth Platform Value Registry`, and
`Why Agents Are Under an Agent Provider`; AAuth Bootstrap, `Self-Hosted Agents`
and `Refresh Patterns`.

Core's functional topology and Bootstrap both define a self-hosted Agent as its
own AP. One user-controlled Ed25519 key signs the AP's ordinary Agent token and
is copied into that token's `cnf.jwk`; ordinary AP metadata and JWKS publish the
same public key. There is no enrollment or refresh endpoint. The host issues a
fresh short-lived token when needed, and every receiver follows the unchanged
Agent-token discovery and request-proof rules.

`NewSelfHostedAgent` is therefore a small composition around the existing
Agent Provider, not a new token issuer or verifier mode. It fixes one issuer,
one top-level Agent identifier in that issuer's namespace, and one key. `Issue`
accepts only the claims that can vary between tokens. The resulting compact
token is passed to the ordinary immutable Agent client and protected Resource
path.

One later Core rationale paragraph says the opposite: every Agent must have a
distinct AP and self-signed tokens are forbidden. Because the executable
protocol sections, platform registry, static-metadata rationale, and Bootstrap
all explicitly describe self-hosting, this implementation follows those
functional sections and records the contradiction as `AAG-F104` rather than
adding a hidden verifier exception.

**Executable examples:** `agentprovider/self_hosted_test.go`,
`integration/bootstrap_self_hosted_test.go`, and `example/selfhosted`.

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

## R3 operation algebra belongs to the registered vocabulary

**Source:** R3, `Standard Vocabularies`, `Operations Spanning Multiple
Definitions`, `Auth Token Extensions`, and `Resource Enforcement`.

R3 uses one common `vocabulary` plus `operations` envelope, but the entries do
not share one identifier or containment rule. The implementation therefore
does not reduce operations to strings or compare their JSON generically. Each
explicitly registered codec owns strict parsing, stable union, equality,
subset, and disjointness. The root R3 model owns request, document, grant, and
single-operation proposal cardinality. Documents, grants, proposals, and all
four roles use that same algebra. Values from different
vocabularies—or from independently registered implementations of the same
URI—cannot be compared.

For underspecified optional members, the current interpretations are:

- AsyncAPI preserves `action` presence and value; omitted and explicit values
  are distinct.
- WSDL treats an omitted `service` as overlapping every same-named qualified
  operation and refuses such an ambiguous set. Different explicit services
  remain distinct.
- OData preserves `methods` presence, treats methods as an order-insensitive
  set, permits method-level narrowing and union, and refuses a same-named
  mixture of absent and present `methods`.

The standard annotation-location mechanisms use named constants. A
third-party codec identifies its own mechanism with an absolute URI so two
independent extensions cannot silently reuse one local label.

`AnnotationEncoding` is only a capability declaration. Separately, the MCP,
OpenAPI, and focused AsyncAPI definition adapters parse the encodings defined
by the draft into sparse `OperationHints`. Those hints preserve independent
member presence and produce an advisory `ExpectedAccess`; they are never
enforcement input or grant evidence. Resource configuration rejects the
publisher-forbidden combination of `budget:true` with explicit `agent-token`
or `person-token`; Agent planning still applies the draft's required
`auth-token` fallback when reading a conflicting remote definition. The OData adapter refuses AAuth
annotations until the draft defines a usable term namespace and an unambiguous
target. gRPC, GraphQL, and WSDL expose no annotation parser because the draft
defines no encoding for them.

These rules make authorization algebra deterministic; they do not claim that
the draft's GraphQL, WSDL, or OData discovery identifiers are sufficient to
build an authoritative catalog. Those source questions remain in
`SPEC-FEEDBACK.md`.

**Executable examples:**
`r3/vocabtest/standard_contract_test.go`, the tests under `r3/vocab/`, and
`r3/vocabulary_test.go`.

## Authoritative-definition parsing is atomic, not authoritative custody

**Source:** R3, `Resource Metadata Extensions`, `Operation Identifier Scope`,
`Standard Vocabularies`, `Operation Access Annotations`, and `Operation
Validation`.

Each definition adapter parses one already-acquired native source in one call
and emits its operations and hints together. The receipt hashes the adapter's
exact named digest input, so changed source cannot silently reuse a snapshot
identity. The snapshot owns copied operations and hints; it retains no source
bytes, parser AST, resolver, transport, policy, or lifecycle state.

The receipt is not an `r3_s256`, a trust decision, retained evidence, or proof
that the advertised endpoint was fetched correctly. Parser registration
prevents an accidental adapter substitution, not a malicious or mistaken host
choice. The caller still owns acquisition, egress policy, external import and
reference acquisition, freshness, and parser-resource bounds.

The native adapters deliberately have different complete boundaries:

- MCP binds every JSON-encoded `tools/list` result object to the cursor used to
  request it, after the caller removes the JSON-RPC envelope, and requires each
  Tool's object-rooted `inputSchema`.
- OpenAPI accepts self-contained 3.0 and 3.1 Paths operations with explicit
  `operationId` values; callbacks and webhooks are outside this profile.
- gRPC accepts a complete linked binary `FileDescriptorSet`; live reflection
  and hosted `.proto` text must be acquired and compiled first.
- GraphQL checks for JSON containing object-valued `data.__schema` and then
  refuses with `operation_identity_unavailable`, because schema introspection
  does not contain client-authored operation names.
- AsyncAPI requires native `action`, validates the direct operation-to-root-
  channel pointer, and refuses external references and traits. Other nested
  local references are outside this focused operation-identity profile.
- WSDL derives only uniquely resolved service, binding, and port-type
  operations from a self-contained WSDL 1.1 document.
- OData derives only the unambiguous structural subset and refuses overloads,
  multiple containers, external references, and AAuth annotations.

These boundaries preserve the open specification questions recorded as
`AAG-F077` through `AAG-F080`; successful parsing does not answer them.

**Executable examples:** `r3/definition_test.go`,
`r3/vocabtest/definition_contract_test.go`, the definition tests under
`r3/vocab/`, and `resource/r3_test.go`.

## Standard R3 discovery endpoints use a bounded HTTPS URL profile

**Source:** R3, `Vocabularies` and `Standard Vocabularies`.

R3 makes discovery endpoints vocabulary-specific but defines no common URI
grammar. Each registered codec therefore validates its own endpoint. The seven
standard codecs currently require a trimmed absolute HTTPS URI with an
authority and no userinfo or fragment; query strings are allowed. Third-party
codecs may define another syntax.

This is an implementation restriction, not complete discovery support. In
particular, the gRPC operation codec accepts hosted HTTPS reflection or
`.proto` URLs, but the definition adapter performs no network or compilation
work and accepts only a complete binary `FileDescriptorSet`. The draft permits
a reflection endpoint but does not define a portable target grammar. Endpoint
validation alone does not fetch or validate a native definition.

**Executable examples:**
`r3/vocabulary_test.go:TestVocabularyDelegatesDiscoveryEndpointValidationToCodec`,
`r3/vocab/standard/registry_test.go:TestEveryStandardVocabularyUsesTheHTTPSDiscoveryEndpointProfile`,
and `r3/vocab/grpc/codec_test.go:TestDiscoveryEndpointUsesTheCurrentHTTPSURLProfile`.

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

## Bounded three-party revocation

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

A revoked token still has a valid signature and request proof. Protocol -11
(AAuth 28e8258f, Presenting a Revoked Token) answers a revoked token in
`Signature-Key` with `401` and `Signature-Error: error=revoked_jwt`. A revoked
Auth token also carries `AAuth-Requirement: requirement=person-token`, never
`auth-token`. A token carried as a request parameter would use
`revoked_<parameter>_token`; that is not adopted, so request-body tokens such
as a sub-agent token get no revocation lookup. An Auth-token identity conflict
stays `403 access_denied`. This check stops a request only when the store reports revocation before host
callbacks; it does not cancel an already-admitted in-flight request.

The Agent returns `*agent.PersonTokenRequiredError` when an Auth-token
call receives that `401 revoked_jwt` with a valid `person-token` requirement.
This includes ordinary, Budget, pending-poll and R3 calls. The error preserves
the original `*signaturekey.Error` through `errors.As`; the response body is
closed and no automatic retry or exchange occurs. A missing, malformed or
different requirement leaves the original signature error intact. The same
hint on a call presenting an Agent or Person token does not acquire Auth-token
recovery semantics.

The referenced **Person Token Required** section (Protocol -11, lines
615–624) calls for obtaining a Person token and retrying the original request
with it. The client methods leave those steps explicit; returning the error
does not complete the draft's Agent procedure. The example obtains a fresh
Person token, retries the original GET, then exchanges the Resource token
returned by that retry. It never exchanges a Resource token naming the revoked
Auth token. This differs from **Re-authorization** after expiry or key rotation
(lines 1289–1305).

**Executable evidence:** `agent/reauthorization_test.go`,
`agent/call_test.go:TestPollAuthTokenPreservesSignatureErrorAndAAuthProblem`,
and `integration/revocation_reauthorization_test.go`.

### Refused revocation caller uses `unsupported_iss`

Protocol -11 (AAuth 28e8258f, Token Revocation, Errors table) answers `403
unsupported_iss` when the recipient does not accept revocations from the
caller. The Resource returns it when the matching status store is not
configured. The body no longer names an issuer, so there is no body-issuer
mismatch refusal. The refusal after revocation above is
a different, protected-use response and is unchanged.

### Pre-use revocation is recorded

Protocol -11 requires the recipient to record whether the token was seen, not
to answer `404`. `RevocationRequest` carries a `TokenReference` plus the
issuer-stated expiration, and the Resource records an unseen `(iss, jti)` and
answers `200`; the store refuses the token at its first use. The wire body is
`{jti, exp}`; the issuer comes only from the verified signature and a body
`iss` is ignored. Token kinds without a configured store still receive
`403 unsupported_iss`.

The Person Server and a direct Agent-identity Resource cannot make the same
choice for Agent tokens: Core says that an AP revocation makes subsequent use
fail, even when the recipient has not seen the token. A configured
`AgentTokenRevocationStore` therefore accepts the AP-signed reference before
first use and retains it until the host can prove no matching token remains
valid. This is intentionally a host retention contract, not a guessed fixed
duration in the protocol library.

**Executable examples:**
`resource/revocation_test.go:TestRevocationEndpointRequiresBoundPersonServerProof`
`integration/revocation_reauthorization_test.go:TestThreePartyRevocationAndPersonTokenRecoveryAcrossResourceRecomposition`,
`personserver/agent_token_revocation_test.go`,
`resource/agent_token_revocation_test.go`, and
`integration/agent_token_revocation_test.go`.

### A rate-limited revocation is reported, not retried

Protocol -11 (AAuth 28e8258f, Token Revocation) lets a recipient answer `429`
`rate_limited` with a required `Retry-After`; this differs from the polling
`slow_down` code. The AP and PS revocation clients make one exchange. When it
returns that problem with exactly one valid `Retry-After` (non-negative
delay-seconds, or an HTTP-date whose delay is representable), the error is a
`*aauth.RateLimitedError` whose `Problem` is the decoded `*aauth.ProblemError`
and whose `RetryAfter` is the delay. Zero is valid: it is either a supplied `0`
or a date that is not in the future. A missing, empty, repeated or malformed
header, or an unrepresentable date, leaves the plain `*aauth.ProblemError`; the
library supplies no default delay and never retries. `errors.As` finds both
types. Agent polling is a separate path and is unchanged.

This reports what the recipient said. It does not bound or rate-limit the
revocations a host accepts; that remains a host policy this library does not
implement.

**Executable examples:**
`integration/revocation_rate_limited_test.go:TestRevocationClientsReturnRateLimitedFeedbackOverSignedExchange`,
`agentprovider/revocation_ratelimited_test.go`,
`personserver/revocation_ratelimited_test.go`, and
`internal/httpapi/retryafter_test.go`.

## Budget fields follow their declared RFC 9651 Dictionary shape

**Source:** AAuth Budgets, `AAuth-Budget Response Header` and “The `reason`
Parameter”.

The draft declares `AAuth-Budget` to be an RFC 9651 Dictionary, but its
examples separate apparent dictionary members with semicolons. Semicolons
introduce parameters on one member; commas separate dictionary members. This
implementation follows the declared Dictionary contract and emits canonical
comma-separated members.

## The Resource selects a declared denomination; later issuers preserve it

**Source:** AAuth Budgets, `The Narrowing Chain`.

The draft explicitly lets the Resource change the Agent's requested
denomination because only the Resource knows its pricing. The Agent therefore
accepts the Resource token's value when it uses one current `budget_units`
declaration. From that point, the Person Server preserves the exact unit and
scale and may only lower the amount. The library defines no conversion
algorithm: an optional Resource offer policy owns any request-to-offer
conversion. This is not a claim that cross-denomination output is a
protocol-verifiable numeric lowering; that source question is `AAG-F088` (since withdrawn).

## A metered route treats a missing signed Budget as no grant

**Source:** AAuth Budgets, `Auth Token Extensions` and `The Resource Enforces`.

The draft permits an Auth-token issuer to omit an offered Budget and then asks
the Resource to apply a default. A positive default would bypass Person Server
narrowing. The fixed-price profiles therefore treat omission from the Auth
token as no metering authorization and refuse the operation; they do not
construct a synthetic zero-valued grant. In four-party Core, the distinct
PS-to-AS omission rule is implemented exactly as written: the AS uses the
verified Resource offer as the PS ceiling. It must still issue an explicit
equal-or-lower Budget for metered protected use. `BudgetConfig.Metered` lets
host routing policy distinguish priced operations from free ones. Its absence
meters every protected route, preserving the existing default. A free route
accepts an otherwise valid Core Auth token without consulting pricing or the
Budget store; a Budget token receives zero-cost feedback, even when exhausted.
This selector governs protected Auth-token use, not initial-offer policy.
Evidence: `TestBudgetResourceSelectsMeteredRoutes`.

## Fixed-price calls charge atomically before application execution

**Source:** AAuth Budgets, `Concurrency`, `The Budget Is a Hard Cap`, and
`Failed Calls`.

For the first non-streaming profile, the Resource knows the exact charge
before dispatch. One atomic store operation binds the signed grant and context,
increments token consumption, and posts the same amount to person accounting.
The application runs only after that operation succeeds. Application failures
are chargeable in this profile, as permitted by the Resource-owned failed-call
policy. Variable-cost and streaming work require a later reservation and
settlement profile.

## Budget step-up refusals omit current-request cost

**Source:** AAuth Budgets, `Budget Exhaustion` and `AAuth-Budget Response
Header`.

The draft says an insufficient or exhausted request consumes nothing, while
one example reports a nonzero `cost`. This implementation omits `cost` on both
refusals. Exhaustion reports `remaining=0` and may report the denomination;
insufficiency reports the remainder and may also report `required`.

## Uncharged Resource errors report the actual Budget remainder

**Source:** AAuth Budgets at `a99d353`, `Sending Rules` and `AAuth-Budget Response Header`.

After verifying the Budget token, request proof, issuer role, Resource context,
account/scope structure and revocation status, a Resource-generated route refusal
carries `cost=0` and the current remainder when its meter is available. This differs from the step-up challenge above:
an ordinary error is a completed request with no charge. Application failures
after an atomic charge retain the charged cost.

The Resource observes its own store through `Charge` with zero cost, which may
establish the token binding but must not increase either consumption ledger.
An exhausted result supplies a zero remainder. A failed or inconsistent meter
result supplies no feedback; the implementation never substitutes the signed
cap for an unknown balance. Invalid or revoked credentials never reach the
Budget store. Pricing failures also omit feedback without observing the
ledger; pricing is part of metering. No second observation follows a failed
charge. A free route still dispatches when its zero-cost observation fails.
The Agent continues to classify missing feedback as uncertain, even on a
problem response, because that body does not establish consumption.
Evidence: `TestBudgetScopeRefusalReportsUnchargedBalance`,
`TestBudgetRefusalDoesNotInventBalance`, `TestBudgetFeedbackRequiresVerifiedRequestAndResourceContext`,
`TestBudgetFeedbackRejectsInvalidCredentialBeforeMetering`,
`TestBudgetCostPolicyFailureDoesNotObserveBalance`,
`TestUnmeteredBudgetCallSurvivesMeterFailure` and `storetest.RunBudget`.

## The host selects retained lineage for a Budget step-up token

**Source:** AAuth Budgets, `Budget Exhaustion`; AAuth Core, `Resource Token
Structure`.

A Budget refusal must carry a fresh Resource token. The presented Auth token
does not identify the earlier Resource token or its `presented_jti`, so the
Resource library cannot select that lineage without guessing. A metered
Resource therefore requires a host callback that owns retained Person-token
state and returns the fresh token. Before releasing the initial Resource token,
the Resource passes its exact `BudgetLineage` to a required host retention
callback; the example no longer obtains this state from the Agent side. The
Resource and Agent verify every context field they can observe, including a
nonempty `presented_jti`; neither library claims to prove that the host selected
the exact prior Person-token record. The Agent returns the verified step-up and
performs no automatic exchange or retry. For three-party access the fresh
Resource token names the PS as audience; for four-party access it names the
Resource's AS, matching the issuer of the refused Auth token. The independent
`ps` claim still identifies the Person Server. Both role checks and the full
four-party replacement exchange execute in `TestBudgetStepUpBindsAudienceToAuthTokenIssuer`,
`TestFederatedBudgetStepUpRejectsWrongAudience` and
`TestBudgetImmediateFourPartyFixedPriceJourney`.

On a step-up, the fresh Resource token's `presented_jti` names the Auth token
the Agent presented, and the Agent sends that Auth token as `presented_token`.
The Agent refuses a step-up whose `presented_jti` is not the `jti` of the Auth
token it presented. The Person-token record the host retains remains host
state that neither library proves.

## An R3 retry is tied to its class record by reference and context, not by token lineage

**Source:** AAuth R3, per-call operation flow; AAuth Core, `Resource Token
Structure`.

A proposal Resource token's `presented_jti` is the `jti` of the class Auth
token the Agent presented. The class record is written before that Auth token
exists, so it cannot hold that `jti`, and the Resource compares no token
identifier with the class record on retry. What the retry check does prove is
that the retained proposal token carries a nonempty `presented_jti` and the
same class reference, Person Server, subject, agent key, tenant, mission and
account as the class record, inside the class validity interval. The Agent
separately requires the proposal's `presented_jti` to equal the `jti` of the
class Auth token it holds. The remaining distinction is Person-token lineage:
nothing at the Resource ties the retry to the Person token the class
authorization began from. No extra claim or store field was added for it.

## An ambiguous Budget call carries the full signed grant, never a retry

**Source:** AAuth Budgets, `Ambiguous Failures` and `The Budget Is a Hard Cap`.

The draft requires an Agent to assume that a lost response cost the request's
maximum as the Resource would have bounded it, but defines no generic pricing
carrier from which the Agent library can verify that figure. After the
protected request is handed to HTTP, an unverifiable result therefore returns
`BudgetCallUncertainError` carrying the complete signed grant—the only local
upper bound the Agent can prove—and is never retried. The implementation
ignores feedback on any response carrying a valid `Age` field, including
`Age: 0`. This is a conservative observable approximation of the draft's
positive-`current_age` rule; HTTP exposes integer Age, not subsecond cache age.

## Clarification extends the retained consent request

**Sources:** AAuth Core, `Clarification Chat`, `Clarification Required`,
`Agent Response to Clarification`, and `Clarification Limits`.

One direct three-party profile lets the host ask a question only after the
ordinary interaction code has correlated the pending authorization. The
question, options, deadline, and signed Agent answer remain attached to that
same pending request. They do not create another authorization or a generic
workflow record.

The source recommends at most five rounds but gives an answer no round
identifier. This implementation therefore fixes one as the safe maximum until
`AAG-F095` is resolved. One question or answer is bounded at 64 KiB and one
question may carry at most 32 distinct options of at most 4 KiB each. Those
are local resource bounds, not wire-format extensions. The strings remain
untrusted Markdown. The library validates and retains them but never renders
or sanitizes them on a host's behalf.

The wire `timeout` is relative but does not identify its reference instant.
The Agent starts a conservative local answer window when it finishes
validating the response and refuses an answer at or after that local deadline.
The Person Server independently enforces the canonical retained deadline.
This implementation choice does not claim the two clocks or instants are
identical; `AAG-F093` (since withdrawn) asked the editors to define the binding.

While an answered round remains latest and no later question is active, an
exact answer replay is idempotent and a changed replay conflicts. Once another
question opens, Core carries no round identifier that can distinguish a late
replay from a new answer; `AAG-F095` records that gap and the current profile
therefore stops after one round. A signed cancellation makes every later
request to the pending URL return `410 Gone`, including a repeat cancellation.
Agent APIs perform one answer, cancellation, or poll request and never continue
automatically.

Core assigns no success response to the answer POST or cancellation DELETE.
The Agent therefore accepts any `2xx` as action acceptance and requires the
caller to poll explicitly for authorization state. Redirects and non-`2xx`
responses remain failures. `AAG-F094` asks the editors to define this response
contract.

`updated_request` remains unsupported. Its current equality rule requires an
`agent` claim that current Resource tokens do not carry; choosing a replacement
binding here would hide the source problem recorded as `AAG-F008` (since resolved).

### A mission adds context, not another continuation API

The direct deferred authorization path uses the same Agent begin, answer or
cancel, snapshot or restore, and poll methods whether the Resource token names
a mission or not. The signed Resource token already carries `mission_s256`, so
serializing that exact token is sufficient to reconstruct the verified
continuation; a second mission field in the Agent snapshot would create two
sources of truth.

At the Person Server, the host sees a copied exact active mission through the
ordinary authorization handle. Mission-aware store methods compare that
snapshot in the transaction that creates or changes pending state. Approval
also retains the issued token in that transaction. A later accepted update
does not invalidate the token or prevent its delivery: Core keeps
`mission_s256` stable specifically so the Agent can continue while the log
catches up. Termination still prevents poll or terminal consume. An update
before the host decides makes that host handle stale; resuming exposes the new
context before a decision is made.

Core permits omitted request capabilities to fall back to the capabilities
captured when the mission was approved. `MissionRecord` retains those exact
values, and the Person Server uses them only when the request member is
absent. An explicitly supplied empty array is preserved as an explicit refresh
to no capabilities. The Agent's Go request keeps that distinction: a nil slice
omits the member, while a nonnil empty slice emits `[]`.

## Permission decisions stay specific to the Permission Endpoint

**Sources:** AAuth Core, `Permission Endpoint`, `Permission Response`, and
`Deferred Response State Machine`.

The Permission Endpoint explicitly defines both immediate grant and denial as
`200` responses carrying `permission`. The generic deferred state machine
instead shows terminal denial as `403 denied`. This implementation keeps the
endpoint-specific representation for both immediate and deferred host
decisions. The Agent also accepts a generic `403 denied` while polling so it
can interoperate with a server that follows the generic state machine. It does
not treat any other `403` problem as a permission decision. `AAG-F096` (since withdrawn) asked the
editors to choose one terminal wire representation.

The executing profiles are top-level and either missionless or associated with
one active mission. A nonempty `mission_s256` is validated and owner-scoped;
JSON `null` remains an explicit `invalid_request` rather than silently becoming
missionless. Mission policy and a resumed host decision receive the approved
blob plus accepted updates. The host handle retains the exact mission state it
displayed, so a later accepted update conflicts and requires another resume.
Expiry or termination before create, decision, or terminal consume prevents a
grant from reaching the Agent.

The mission-bound store retains permission request and response state in the
same atomic backing-store boundary as mission lifecycle and mission-bound
tokens. This is the Permission sublog required by the source, not an invented
cross-protocol history object. Core still requires one ordered mission log
across token requests, updates, permission, Audit, Interaction, and
clarification; that wider log remains unimplemented. The Agent does not infer
whether `action` matches `approved_tools`: Core tells the Agent when it may skip
the endpoint but defines no matching algorithm.

An application may defer policy while it authenticates and consults the
person through its own channel. `ResumePermission` reconstructs the verified
intent from retained state, but the resulting handle is not person authority.
The host must authenticate the person independently and sanitize the raw
Markdown description before display. The library never executes the named
action. It returns a typed decision, and the application decides what that
action means.

The source defines no stable identity for the initial POST. A transport error,
malformed success, or non-retryable server failure after handoff therefore
returns `PermissionSubmissionUncertainError` and is never retried
automatically (`AAG-F098`, since withdrawn). A definite `4xx` rejection remains an ordinary
failure; `429` and `503` remain caller-owned responses under the source's
explicit backoff rules. Once a terminal poll response is consumed, the source
requires later polls to return `410`; the implementation follows that rule and
therefore inherits the lost-terminal-response gap already recorded as
`AAG-F004` (since withdrawn).

The Agent can persist a `PendingPermissionSnapshot` and restore it with a
fresh client. Restoration checks the current Agent token, the retained issuer,
Agent, Person Server, proof key, and pending URL against current permission
endpoint metadata. Token renewal with the same identity and key is supported;
key rotation remains refused. The snapshot is application-owned continuation
state, not signed evidence of the original response, so its storage must
preserve confidentiality and integrity. Restoration does not repeat the POST,
poll, or execute the action. The source's Permission and Pending URL Security
rules are unchanged; this is an application persistence API.

`PollPermission` reports `PermissionPollNotStartedError` when validation,
metadata discovery, or signing fails before its GET reaches the HTTP client.
The caller can retain and retry that same continuation. After HTTP handoff,
an error may mean a terminal result was consumed; it carries no such retry
guarantee. This distinction does not permit replaying the initial POST.

## Audit is one exact post-action append, not action execution

**Sources:** AAuth Core, `Audit Endpoint`, `Audit Request`, and `Audit
Response`.

An audit request reports an action that the application has already performed.
The library validates and carries the report; it does not interpret the action,
execute it, render its Markdown description, or treat the record as permission.
The description is untrusted raw Markdown and must be sanitized before display.
The action, parameters, result, and additive members remain untrusted Agent
input and need host-specific validation before processing or rendering.

The Person Server retains the exact signed JSON request before returning `201
Created`. This preserves unknown additive members and gives the host log the
same artifact the Agent authenticated. An audit append compares stable mission
identity and lifecycle state inside the mission store's atomic boundary, so
completion or expiry cannot race into a successful later append. An accepted
update does not invalidate the action's audit because it does not change the
mission. Identical requests are distinct Audit-sublog entries because Core
defines no audit identity or replay key. This slice does not claim ordering
against the other event classes in Core's complete mission log.

`SubmitAudit` performs one request and waits for its protocol status. Any `201`
acknowledges the append; an optional representation is ignored. It does not
retry, poll, or hide the call in background work. A transport failure or server
failure after handoff is an uncertain outcome because the record may already
exist (`AAG-F003`, since withdrawn). The source's simultaneous `201` contract and
“fire-and-forget” guidance leave the meaning of “SHOULD NOT block” unclear;
`AAG-F100` (since withdrawn) asked whether it describes application control flow or the HTTP
exchange itself.

## Interaction questions are a focused exact-document path

**Sources:** AAuth Core, `Interaction Endpoint`, `Interaction Request`,
`Interaction Response`, and `Deferred Responses`.

The root question document fixes `type` to `question`, preserves the exact
signed JSON and additive members, and rejects relay-only `url`, `code`, and
`max_wait` members. Description and question are untrusted raw Markdown. The
Person Server host must sanitize them before display and chooses how to reach
the person; the protocol library performs neither action.

The question role journey is top-level and may optionally name one active
mission. Policy returns one immediate answer or a bounded deferred policy. For
a mission-bound request, policy and a resumed host receive the same exact
mission view; immediate answer or unreachable retention and every deferred
transition compare mission lifecycle state atomically. A separately
authenticated host reconstructs a non-authoritative handle, records one answer
or unreachable result, and the Agent makes one explicit poll. These records
are an Interaction sublog, not the undefined complete cross-event mission log.
Relay requests remain a separate purpose-specific state machine.

Core recommends recording every Interaction request and response and requires
mission interactions in the mission log. The mission-bound path retains exact
immediate and deferred question documents and results. Missionless immediate
recording remains host policy, and the complete cross-event mission log remains
an explicit conformance gap because Core defines neither its representation nor
retrieval surface.

`AskPersonQuestion` makes one request and never retries. A valid immediate
answer returns its exact bytes; a valid `202` returns a verified pending handle.
A transport failure or malformed initial result remains uncertain because the
question may already have reached the person. `AAG-F101` (since withdrawn) recorded the missing
uncertain-initial-submission identity. Once the pending URL is received, the
ordinary deferred state machine applies, including its separate lost-terminal
response gap.

## Resource-hosted relays report delivery progress, not operation completion

**Sources:** AAuth Core, `Interaction Request`, `Interaction Response`,
`Interaction Relay`, and `Deferred Responses`.

The relay path may be top-level missionless or name one active mission.
`interaction` and `payment` documents preserve the exact signed JSON while
exposing a validated HTTPS URL, code, optional untrusted Markdown description,
whole-second `max_wait`, and optional `mission_s256`. When a mission is named,
policy and the resumed host receive the same exact active mission view, and
create, resolution, poll, and consume share its lifecycle boundary. This is a
focused relay sublog, not the complete cross-event mission log.

The Person Server retains the relay record before `202`. Host policy chooses
whether it has a person channel; `interaction_unavailable` is the defined
non-terminal refusal and returns the original document to the Agent application
for direct presentation.

An accepted relay creates only Person Server delivery-progress authority. A
separately authenticated host marks that the person engaged or that the server
can make no further progress. The requested `max_wait`, when present, can only
shorten the host policy's lifetime. One signed poll consumes the terminal relay
state. The library does not open the URL, render the description, contact the
person, sleep, loop, or poll the Resource.

Core says the Person Server returns `status: interacting` once the user engages
and a terminal response when engagement, timeout, or no-progress occurs, but it
does not assign a terminal HTTP status or body. This implementation uses `200`
with `{"status":"interacting"}` for engagement and
`{"status":"pending"}` for timeout or no progress. These reuse only Core's
defined status values and are explicitly local profile choices (`AAG-F102`, since withdrawn).
The Resource's original pending URL remains authoritative for whether the
underlying operation completed.

## Deferred mission approval stays on the proposal key

**Sources:** AAuth Core, `Mission Creation`, `Mission Approval`, `Deferred
Responses`, `Pending URL Security`, and `Person Token`.

Core authenticates every pending poll as the same Agent identity, defined by
Agent Provider and Agent identifier. It does not say whether that Agent may
renew onto a different proof key while approval is pending. Mission approval,
however, returns Person tokens bound to an Agent key, and the host can approve
before the next Agent poll supplies a current key.

This implementation therefore retains the proposal key and bounds the pending
deadline by the original Agent token. Approval-time Person tokens use that key;
a poll under another key is cloaked as an invalid pending reference. Renewal
with the same key remains valid until the original token's expiry. This is a
local consistency choice, not a claim that Core defines key continuity.
`AAG-F105` asks the editors to choose between original-key continuity and
decision-time token issuance for a renewed Agent.

## Third-party login cannot yet construct its first protocol message

**Sources:** AAuth Core, `Third-Party Login`, `Login Endpoint`, `Login Flow`,
`Person Token`, and `Resource Token Structure`.

The Login Flow tells an Agent or Resource to create a Resource token and POST
it directly to the selected Person Server's token endpoint. At that point the
user has not authenticated. A current Resource token nevertheless requires
`sub` and `presented_jti`, both derived from a Person token issued for that
user. The flow contains no Person-token request and its diagram begins with the
Resource-token POST.

This is not a choice between two equivalent Go compositions: the first
required message cannot satisfy the current token grammar. The implementation
therefore does not mint placeholder person claims, omit required claims, or
define a login-only Resource-token dialect. `AAG-F103` (since resolved) asked whether the flow
must first obtain a Person token through an additional browser-correlated step
or whether Login intends a different signed request object.

## Signature `created` ahead of the window is `clock_skew`

Source: Signature-Key `69f5ba2`, section `clock_skew` (heading `### clock_skew` at line 1104, section lines 1104-1114, see
`SPECIFICATIONS.md`). The text applies `clock_skew` when a signature `created`
is further ahead of the verifier clock than the validity window, and leaves a
`created` older than the window as `invalid_signature`.

`PrepareRequest` reuses its existing validity window (`SignatureWindow`,
default `DefaultSignatureWindow`, 60 seconds) for both directions. A `created`
exactly one window ahead or behind is accepted; one second further ahead is
`clock_skew`, one second further behind is `invalid_signature`. `created` is a
whole number of seconds, and the tests step by one second. The window and expiry
semantics are unchanged. The source does not fix the window length; this
choice is the library's existing one.

JWT `iat` skew uses the same window, and the policy belongs to the request
rather than to general token verification. Core `validateTimes` no longer
refuses a future `iat`; `exp`, `nbf` and the positive-lifetime rule are
unchanged, and no leeway is added. A verifier holding a prepared or verified
signed request calls `CheckIssuedAt`, which answers `clock_skew` for an `iat`
later than the request's captured time plus its effective `SignatureWindow`.
`VerifyJKTJWT` uses this check in place of its former `invalid_jwt` refusal.
The `Signature-Key` header token is answered `401` with
`Signature-Error: error=clock_skew`; a token carried as a request parameter is
answered `400` with body error `clock_skew` (see the Protocol -11 JWT `iat`
section of `SPECIFICATIONS.md`). A verifier with no request applies no
future-`iat` refusal.

Events is excluded. Subscribe-token and event-token validation keep their own
`validateTimes` in `events/token.go`, which still refuses any future `iat`;
neither was changed.
