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

## `aud` names one audience, written as a string or an array of one

**Source:** Protocol `70d6737`, Resource Token Structure (line 742), Person
Token Structure (line 867), Auth Token Structure (line 1778) and Common JWT
Verification (line 2313).

Each of these tokens names one audience URL, and Common JWT Verification
verifies "per RFC 7515 and RFC 7519". RFC 7519, Section 4.1.3, lets a single
audience be written as a string or as an array of one string, and the drafts
do not exclude the array; some implementations write it. Person, Resource and
auth tokens are read in either form. An empty array, or one of two or more
members, is refused as a malformed token, since it does not name the one
audience the drafts require. Tokens are minted with the string. Only the
decoded claims are affected: the signed bytes and the members a host sees
stay as presented. Agent tokens carry no `aud`.

**Evidence:** `core_token_api_external_test.go:TestCoreTokenVerificationReadsAudAsAStringOrAnArrayOfOne`.

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

**Source:** Events, `Structure` and `Agent Verification` at the pinned
`70d67375` text.

`eid` identifies the subscription. Each event token carries a required `jti`,
and `(iss, jti)` is the deduplication key at the Agent Provider and the Agent.
The earlier `(iss, eid)` reading would discard later events on the same
subscription; that sentence is not in this pin.

The implementation keeps `eid` as subscription and routing context. It derives
a local delivery fingerprint as SHA-256 over the exact compact Event token
bytes, a separator, the signed content type, another separator, and the exact
payload bytes. An exact replay is ignored; a different authenticated token,
content type, or payload on the same subscription is a different delivery.
The fingerprint is local state, not a new wire claim. Minting and verifying
an event token requires `jti`; the fingerprint still distinguishes a changed
body under a reused identifier.

## Event-token expiry is MUST NOT in both sections

**Source:** Events, `Structure` (the `exp` claim) and `Agent Verification`.

Both sections say the Agent MUST NOT act on an event token whose `exp` has
passed. There is no MUST versus SHOULD NOT conflict in the pinned text.
Verification rejects an expired event token.

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
bound to the signing key of a prior authenticated interaction: the Resource
records the JWK Thumbprint of the `cnf` key it verified and compares it with
the thumbprint of the subscribe token's `cnf.jwk`. No token the Resource
verified then carries an Agent identifier, so the subscribe token's `sub` does
not bind the ticket. Events leaves the ticket representation, lifetime, and
Resource policy undefined. This implementation therefore retains a
host-generated path segment, the RFC 7638 SHA-256 thumbprint, and opaque
context rather than defining another token. The Resource host chooses a
same-origin URL prefix, an explicit maximum lifetime, and the policy that
interprets the retained context.

Ticket consumption and subscription registration share one store operation.
While the original subscribe token remains valid, an exact retry returns the
retained registration even after the unused-ticket deadline and does not rerun
host policy; a changed retry conflicts. An unused ticket still expires at its
deadline.
A request whose subscribe-token `cnf.jwk` has another thumbprint is cloaked as
a missing ticket, and an expired ticket returns a distinct terminal refusal.
The handler repeats both checks on the ticket the store returns, so a store
that loaded by ID alone could not weaken them. These are repository storage and HTTP-response choices around the
source-defined binding, not new Events wire fields.

## Events requests cover body components only when a body is present

**Source:** Events, `Event Delivery: Resource to AP` (`Request` and `AP
Validation`); Protocol, `Covered Components`.

An event delivery with a body covers `content-digest` and `content-type`, as
Events requires; a bodyless delivery covers only the base components. The
Event token's `body_s256` binds the body: it is present exactly when there is
a body, so the AP and the Agent both refuse bytes added to a bodyless delivery
or removed from a body-bearing one. Registration requests follow the same
rule. `signaturekey.PrepareRequest` already requires `content-digest` for any
request with content, and these handlers additionally require a signed
`content-type` whenever one is sent. The Events registration example covers
`content-type` without `content-digest`; this library's verifier, like its
other Resource endpoints, still requires `content-digest` on a request with a
body, which the Core lets a server require.

## Events delivery failures follow the AP Validation status codes

**Source:** Events, `AP Validation`.

Every Event-token and HTTP-proof failure is `401` with `Signature-Error`:
`expired_jwt` for an expired token, `invalid_jwt` for a token of the wrong
type, discovery document, or claim shape, a `body_s256` mismatch, or an `aud`
that is not the subscribed Agent, and `clock_skew` for an `iat` beyond the
signature window. A Resource other than the subscribed one is `403` without
`Signature-Error`. An unknown, inactive, or exhausted subscription is `404`.
Only a request for another delivery target or a body without `Content-Type`
is `400`. The inbox store checks the subscribed Agent before it consumes a
use, although Events lists that check after the use-count increment, so a
refused delivery never spends the subscription.

## Mission-bound Auth tokens take the mission's bound from the presented token

**Source:** Protocol `70d6737`, Resource Token Structure (line 759), Mission
Approval (`expires_at`, line 1425), Person Token Structure, Auth Token
Structure and PS-to-AS Token Request.

The pinned draft makes a Resource token's lifetime "independent of any
mission it names: the PS verifies that the mission is active when it acts on
the token", and says the Person Server caps the person tokens and auth tokens
it issues at the mission's `expires_at`, "and the presented token carries that
bound to an AS". An Access Server receives only `mission_s256`, so it caps a
mission-bound Auth token at the presented token's `exp`, as it caps every
Auth token, and not at the Resource token's. The Person Server checks the
returned Auth token against the mission's expiry and commits it with the
mission atomically before release. Neither the Person Server nor the Agent
refuses a Resource token that outlives the mission. A Resource built with
this library still issues a mission-bound Resource token no later than the
person token it verified; that is shorter than the draft requires, not a
refusal of anyone else's token.

**Evidence:** `integration/mission_four_party_test.go`,
`integration/call_chaining_hops_test.go:TestCallChainCarriesTheCallingAgentsMission`
and `agent/mission_test.go:TestClientAcceptsResourceTokenThatOutlivesMissionBoundPersonToken`.

## A mission-bound person token is challenged with its mission

**Source:** Protocol `70d6737`, the Resource's auth-token challenge (line
704), Resource Token Structure (`mission_s256`, line 755; lifetime, line 759)
and Deferred Delivery (line 645).

A Resource that requires an auth token answers a mission-bound person token
as it answers any other: with a Resource token whose `mission_s256` is copied
unchanged, REQUIRED "when the presented token carried one". The Resource does
not check the mission; "the PS verifies that the mission is active when it
acts on the token". Held delivery retains missionless requests only, so a
Resource configured with `HeldInvocations` answers a mission-bound request
with the ordinary `401` challenge rather than holding it; the draft lets a
Resource choose either form. Before, the Resource refused a mission-bound
person token with `401 invalid_token`.

**Evidence:** `resource/challenge_test.go:TestAuthTokenRequirementCopiesTheMissionOfAMissionBoundPersonToken`.

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

## A `429` poll answer honors both the backoff and its own `Retry-After`

**Source:** AAuth Core, `Polling with GET` and `Deferred Response State
Machine`.

Core requires the agent to respect `Retry-After` values and to increase its
polling interval by five seconds on a `429`. When a `429` also carries a
`Retry-After` longer than the increased interval, both cannot hold with an
increase of exactly five seconds. Every agent poll keeps the larger of the
two, so it never polls sooner than the server asked and never backs off by
less than five seconds. A `429` whose `Retry-After` cannot be read still backs
off by five seconds rather than ending the poll. A `503` takes its
`Retry-After`, or five seconds when absent. Each poll method returns the continuation carrying that interval
alongside the caller-owned `429` or `503` response.

**Executable example:**
`agent/poll_interval_test.go:TestEveryAgentPollAppliesTheDefaultIntervalAndLinearBackoff`.

## Parent-mediated credentials use the child key and the earlier expiry

**Source:** AAuth Core, `Person Token Endpoint`, `Resource Token
Verification`, `AS Token Endpoint`, and `Sub-Agents`.

The parent signs both Person Server requests, but the child uses every issued
credential. The person and auth token are therefore verified and issued
against the child token's `cnf.jwk`; the resource token's `agent_jkt` must name
that same key. Each issued token is capped by the earlier of the parent and
child Agent-token expirations.

The child token's optional `ps` claim does not select this flow; the parent
selects and authenticates to its Person Server. When present it must equal the
parent's `ps`, because Bootstrap issues the child with its parent's value;
another value is `invalid_subagent_token` at the PS and AS, as in aauth-rust.
The Person Server retains the child's Agent Provider, child, parent, and child
key with the person-token record. A later token request must match that record
before policy runs. The parent and child keys must be distinct, and the
Resource receives none of the relationship fields.

The record binds the stable relationship, not one compact child token. A later
valid child token may rotate `jti`, expiry, or additional policy claims when
issuer, child, parent, and key remain unchanged; policy receives the current
claims.

The Person Server verifies the HTTP proof before applying the top-level-only
request rule. A correctly signed direct request from a child returns
`400 invalid_agent_token` without `Signature-Error`; a forged proof returns
`401` with its Signature-Key failure. Core requires the direct-child refusal
but does not assign it an error code (AAG-F045). A refused `subagent_token`
parameter instead uses Protocol -11's `invalid_subagent_token`,
`expired_subagent_token` or `revoked_subagent_token`.

**Executable examples:**
`personserver/subagent_test.go:TestServerIssuesImmediatePersonAndAuthTokensForSubagent`
and
`integration/subagent_authorization_test.go:TestCurrentCoreParentMediatedSubagentImmediatePSAuthorization`.

## Immediate call chaining uses token trust plus explicit chain bindings

**Source:** AAuth Core, `Auth Token Verification`, `Upstream Token
Verification`, and `Call Chaining`.

Generic auth-token verification includes Resource request-context checks that
do not apply when a Person Server receives an upstream token in a request
signed by an intermediary. The upstream token is a person token or an auth
token, told apart by `typ`; any other `typ` is refused. This implementation
verifies the upstream JWT's type, issuer key, and time first. It then requires
a person token whose `iss` is the receiving Person Server, or an auth token
whose `ps` is the receiving Person Server and whose `iss` is that Person Server
(a Person-role token) or an Access Server (an Access-role token), and in every
case `aud` equal to the intermediary Agent token's `iss`. The calling Agent is
identified from this Person Server's own record of that exact token: the
person-token record, which names the Agent token the token was issued
against, the auth-token issuance record, or, for an Access Server's token, the
receipt the Person Server kept when it delivered it.

Step 2 accepts an Access Server's auth token when the Person Server presented
a person token to that server "for that token's `aud` and `sub`". The receipt
is the evidence: the Person Server writes it only after checking, on
delivery, the token's `iss`, `aud`, `sub` and `cnf` against the request it sent
that server, and the receipt binds the exact token digest. An Access Server's
auth token without a receipt, such as one a three-party Person Server never
delivered, is `invalid_upstream_token`. Since step 4 identifies the caller
through the person token the auth token was obtained with, an upstream auth
token whose person token this Person Server revoked, directly or behind a
step-up, is `revoked_upstream_token` even when no cascade reached the auth
token itself. After a binding is replaced, an Access Server's token cannot
show which binding generation authorized it, so it is refused as upstream
evidence as it is as a presented token.

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
`agent/call_chaining_test.go:TestCallChainingRoutesFromUpstreamTokenAndCarriesItExactly`,
`integration/call_chaining_test.go:TestCurrentCoreImmediateTwoResourceCallChain`,
`personserver/call_chaining_person_token_test.go:TestCallChainingAcceptsAnUpstreamPersonToken`,
`personserver/call_chaining_lineage_test.go:TestCallChainingRefusesAnUpstreamAuthTokenWhosePersonTokenWasRevoked`
and
`integration/call_chaining_hops_test.go:TestFourPartyCallChainRepeatsOnAccessServerAuthTokens`.

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

Missions are carried down a chain, and an account in an upstream auth token
stays with the upstream Resource: policy sees it in the upstream claims and no
downstream token carries it. A sub-agent intermediary, or a sub-agent token
combined with an upstream token, is not partially processed. Once its
otherwise valid context is recognized, the Person Server returns
`500 server_error` before chain policy, pending-state creation, or issuance.
Ordinary interaction selectors are never called for a chained request;
`CallChaining` and `FederatedCallChainingConfig` decide it immediately, and
only an Access Server can make a four-party chained request wait.

The public seam has no depth marker. Each hop is verified on its own: the
intermediary's downstream token becomes the next hop's upstream token, and its
record names that intermediary as the calling Agent.

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
confirms their relationship (one issuer, and a child `ps` equal to the
parent's when present), and requires the parent token to name the signing
Person Server. A deferred request repeats all of this on every Person Server
poll from the retained request bytes. The child's optional `ps` claim does not
select the flow. Policy receives both identities, and issuance uses only the
child key. The Person Server then verifies the returned auth token against the
child key before returning it to the parent.

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
components. Ordinary protected routes use the nonempty-content default below
alongside their advertised components. A
transport-mutation test proves that changing `scope` after signing is refused.

**Executable example:**
`integration/core_four_party_test.go:TestCurrentCoreFourParty`.

## Nonempty request content is covered by default

**Source:** AAuth Core `a99d353`, `Covered Components` and `Verification`,
step 2; RFC 9530, `Content-Digest`.

Core mandates body digest and media-type coverage at PS/AS endpoints but
explicitly lets Resources declare their requirements for arbitrary APIs,
including large and streamed payloads. It permits further component
requirements through metadata and `invalid_input` / `required_input`.
It does not impose a universal Resource-body digest requirement.

This library chooses a bounded profile: signing nonempty content computes and
covers SHA-256 `content-digest`, and covers `content-type` when that field is
present. Verification requires the same coverage and checks the actual content
before role policy. An uncovered body or media type returns `invalid_input`
with the required components; a covered digest or field that no longer matches
returns `invalid_signature`. Body detection inspects bytes, not Content-Length.

Before signing, a positive Go `Request.ContentLength` must match the buffered
content size. A mismatch is a local input error: no proof headers are attached
and the body remains readable. Zero and `-1` with nonempty content are allowed.
This prevents HTTP framing from sending fewer bytes than the digest covers;
the verifier still checks actual content rather than trusting Content-Length.

Empty content retains the existing component profile, including non-nil empty
transport readers. Explicitly requiring `content-digest` still covers the
SHA-256 digest of zero bytes. Advertised components remain unconditional;
metadata does not imply that the conditional default applies to empty content.

This changes the default for body-bearing Resource calls. Signing and
verification buffer within their configured bound (1 MiB by default); larger
payloads require explicit limits. Unchecked body pass-through and streaming
digest trailers are not supported. The proof does not prevent replay within
its freshness window.

**Evidence:** `signaturekey/body_default_test.go`,
`signaturekey/body_limit_external_test.go` and
`resource/body_coverage_test.go` execute bounded signing, preserved content,
unspecified and unknown lengths, and rejection of added/changed/removed bodies
and changed media types before Agent/Person identity or PS/AS Auth policy.
The signing tests also exercise HTTP serialization, mismatched positive
lengths, and the maximum `int64` body limit without overflow or content loss.
`agent/body_default_test.go` checks the client's configured bound before
transport in Agent-identity, initial Person-token, Auth-token and Budget calls,
even when Resource metadata declares no additional components.

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

## A retained request leaves its connection options behind

**Source:** Protocol `70d6737`, Deferred Delivery (line 659); R3 `70d6737`,
Per-Call Proposals, enforced completion (line 677); RFC 9110, Section 7.6.1.

A Resource that holds a request, or runs an approved per-call retry, executes
a copy of the request apart from the exchange that carried it. The `close`
and `keep-alive` options of `Connection` describe that connection, not the
request, and RFC 9110 does not let them travel past it. A retained request
leaves the `Connection` field and `http.Request.Close` behind, and the
application sees neither. Before, a per-call retry sent with
`Connection: close` was refused with `400 invalid_request` before it ran, and
a held request with `500`. A `Connection` field naming any other option names
a further hop-by-hop field, which a retained request still refuses, as it
refuses trailers, transfer codings and the other hop-by-hop fields.

**Evidence:** `resource/held_request_test.go:TestHeldRequestSnapshotLeavesConnectionOptionsBehind`
and `resource/r3_per_call_test.go:TestMCPR3PerCallClassOperationCommitsProposalAndRetryBeforeChallenge`.

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

### Re-authorization verifies the prior auth token as of its issuance

**Source:** AAuth Core, `Re-authorization`.

`agent.Client.Reauthorize` replaces one Core auth token after the Agent's key
rotated or the token expired. Either way the prior token no longer verifies
for the current key and clock, yet it is what says which authorization to
renew. The client therefore verifies its signature and claims as of its own
`iat`, then asks the Resource's authorization endpoint for a fresh resource
token for the same scope and account, presenting a person token bound to the
current key, and submits that resource token to the Person Server the prior
token named. It refuses a person token for another Resource, Person Server,
person, or mission. The Resource and Person Server decide again on current
policy, so the new scope may differ.

**Executable evidence:**
`integration/key_rotation_reauthorization_test.go:TestKeyRotationReauthorizesWithFreshResourceTokensAtThePersonServer`.

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
construct a synthetic zero-valued grant. In four-party Core, PS-to-AS omission
is not a grant: the AS does not substitute the Resource offer, and it must not
issue a `budget` claim. A metered route then refuses that Auth token. When the
PS does send a ceiling, the AS may only lower its amount. `BudgetConfig.Metered` lets
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
policy. `BudgetConfig.Maximum` reserves a finite bound before dispatch.
`SettleBudget` after the header is written commits the spent part as a
cost-only trailer. `SettleBudget` before the handler writes sends a fixed-price
header and drops the trailer declaration. An unsettled written response
commits the hold as the trailer.

## Budget step-up refusals omit current-request cost

**Source:** AAuth Budgets, `Budget Exhaustion` and `AAuth-Budget Response
Header`.

The draft says an insufficient or exhausted request consumes nothing, while
one example reports a nonzero `cost`. This implementation omits `cost` on both
refusals. Exhaustion reports `remaining=0` and may report the denomination;
insufficiency reports the remainder and may also report `required`.

## Uncharged Resource errors report the actual Budget remainder

**Source:** AAuth Budgets at `70d6737`, `Sending Rules` and `AAuth-Budget Response Header`.

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

A missionless clarification accepts `updated_request`. The replacement resource
token and `presented_token` are verified. `iss`, `ps`, `sub`, `agent_jkt`,
`mission_s256`, and `tenant` must match the pending ask. A parent-mediated ask
matches the child key. Both replacement expiries cover the pending deadline,
and the resource-token lifetime stays within the configured maximum. A retained
person-token record must agree. A revoked Agent-person binding, or a revoked
Agent or sub-agent token that started the wait, is refused. The retained
scopes are replaced. Account, Budget, mission-bound, R3, and AS-relayed
updated requests are not accepted. `AAG-F008` (since resolved) had required an
`agent` claim current Resource tokens do not carry; the executed checks use
the claims above.

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

Events follows the same rule. `validateTimes` in `events/token.go` checks the
positive lifetime and expiry only. The Resource registration handlers and the
AP event endpoint call `CheckIssuedAt`, answering `clock_skew`; an Agent
verifying a forwarded Event token has no request and applies no bound.

## Deferred federation keeps payment and progress with the PS host

**Source:** Protocol `28e8258`, AS Response, Auth Token Delivery, PS-AS Trust
Establishment, Deferred Responses and Pending URL Security.

The AS retains the exact verified token request before publishing a pending
URL. The PS retains a separate continuation before returning its own pending
URL to the Agent. Both URLs use 256-bit random references. PS polls use the
server's `jwks_uri` identity; Agent polls remain bound to the original Agent
issuer, identifier and key. No payment credentials or AS payment challenge are
forwarded to the Agent.

`AdvanceFederation` performs one explicit AS GET. The host calls it after
settling the indicated payment or when approval polling is due. Hosts own
payment-protocol interpretation, settlement and billing-relationship caches
per AS/PS; policy callbacks inspect that state without charging on a poll.
The library currently carries one `WWW-Authenticate` challenge with optional
opaque content. It does not implement a payment protocol or other payment
header formats. AS claims and interaction are described below; clarification
forwarding remains a separate unimplemented branch.

Each pending deadline is the earliest of its configured lifetime, the original
Resource-token expiry, Agent-token expiry and presented-token expiry. A wait
cannot extend any credential that justified it. An expired request returns one
`408 expired`, then `410 request_consumed`. The continuation error choices are
recorded below. A retained grant is reverified at actual Agent
delivery, and `expires_in` is recomputed then.

The PS conditionally marks an AS call in progress before sending it. If the
process or completion write fails after handoff, the call remains fenced until
expiry. It is not automatically retried: the AS may already have consumed its
terminal response. This bounds ambiguous delivery without pretending that two
servers share a transaction. Hosts must monitor pending records and store
errors. The lifetime bounds processing, not store retention or queue capacity.

**Evidence:** `integration/federated_deferred_test.go`, the two role-specific
federation `storetest` contracts, and `example/federatedpayment`.

## Deferred federation host visibility and Agent hints

**Source:** Protocol `28e8258`, AS Response, Pending Response Format, Polling
with GET, Error Response Format and Token Endpoint Error Codes.

A local request-composition refusal uses `500 server_error` with a bounded
public explanation; `DeferredCompositionError` identifies the reason to the
host through diagnostics. A valid pending envelope asking for clarification,
or for an unsupported extension, uses the same typed refusal, both on the
initial response and a later AS poll. Its reason identifies that branch.
On a later AS poll, the PS retains the bounded reason with the terminal response;
`AdvanceFederation` reports successful retention, and Agent delivery reconstructs
the typed diagnostic. The store carries neither a Go error nor an arbitrary AS
cause. The reason survives serialization and server recomposition.
`as_unreachable` is reserved for the federation failures described by Auth Token
Delivery, rather than local missing support.

Host queue listing is a library API, not a new endpoint. It is scoped to one
PS, ordered by next poll time then ID, and includes in-flight records for
monitoring. It neither reserves nor advances requests. The optional
`FederatedAuthorizationQueueStore` extends the base continuation store, matching
the permission and question listing pattern; adapters without it can still
complete exchanges. Agent `Retry-After` is
the remaining interval until the retained AS poll time, rounded up to whole
seconds, and at least one second. Once the AS poll is due only the host can
advance it, so advertising zero would invite an Agent that follows the hint to
poll in a busy loop until the host's next pass.

The optional `pending_reason` response field is a library display extension,
not a draft-defined requirement. The PS maps AS `402` to `awaiting_payment` and
approval `202` to `awaiting_approval`, while keeping `status: pending` and
`requirement=approval`. Other retained statuses omit the hint. The Agent
exposes recognized values through `PendingExchange.WaitReason()` and ignores
unknown values; absence clears an earlier hint. No AS challenge, payment body
or credentials are copied to the Agent. The hint grants no payment authority.

**Evidence:** `TestDeferredCompositionRefusalHasLocalReason`,
`TestDeferredCompositionRefusesR3AndBudget`,
`TestFederatedStoreWithoutQueueStillDelivers`,
`TestPendingFederatedReferencesValidateStoreResults`,
`TestFederatedPendingReferencesAcrossRecomposition`,
`TestFederatedAgentRetryAfterTracksASSchedule`,
`TestFederatedWaitingRoundsUpRemainingRetryAfter`,
`TestFederatedWaitingExposesOnlySafeHint`,
`TestPendingExchangeWaitReasonIsOptionalDisplayHint`,
`TestFederatedAgentWaitReasonPaymentThenApproval`,
`TestFederatedUnsupportedRequirementIsLocalRefusal`, and the PS federation store
contracts in `personserver/storetest/federated.go`.

## An Access Server's interaction reaches the Agent that declared it

**Source:** Protocol `70d6737`, AS Response (lines 1610-1625), PS Response
(969-977), Person Token Endpoint (`capabilities`, line 814), AAuth-Capabilities
(2456-2476), Interaction Required (2358-2400) and Interaction Chaining
(1882-1886).

A federated Person Server passes an Access Server's `202` with
`requirement=interaction` back to the Agent: the Agent's `202` carries the
AS's own `url` and `code` in a fresh `AAuth-Requirement`, the PS's own
`Location`, and `{"status":"pending"}`. The code is the AS's, so the person
completes the interaction on the AS's page, which compares it; the PS keeps
its wait and the host advances it, as for approval, until the AS answers. A
chained request is relayed the same way, and the intermediary chains it to
its caller with its own code and pending URL. The relay happens on the first
AS answer and on a later host advance alike.

The Agent declares what it can handle. A request whose `capabilities`, or
whose mission's captured capabilities when the request omits them, do not
include `interaction` cannot send the person to the AS, and this Person
Server has no page of its own for an AS interaction. It answers
`403 user_unreachable`, as the Person Token Endpoint says a PS that must reach
the person does without the capability, and sends the AS one signed `DELETE`.
On a later advance the wait ends with that answer. The federated Person
Server therefore accepts `capabilities` now and, as AAuth-Capabilities
requires, ignores values it does not act on.

The PS reads the interaction requirement as an Agent would. A `url` that is
not HTTPS or carries a query or fragment, or a `code` outside upper-case
Crockford base32, is a malformed AS continuation and the request ends with
`502 as_unreachable`. aauth-rust relays an AS interaction whatever the
request's capabilities and upper-cases a code the AS wrote in lower case. Go
answers `user_unreachable` because its Agent refuses an interaction it did
not declare, and the draft names that answer for a person the PS cannot
reach. It refuses a lower-case code because Interaction Code Format forbids a
server to emit one.

The Access Server draws a 40-bit code for each wait it may defer and keeps it
for every poll of that wait (`AuthorizationRequest.InteractionCode`,
`PendingAuthorizationRecord.InteractionCode`). A policy that asks for
interaction names only the page (`PendingDecision.InteractionURL`); the host
serves that page, compares a presented code with `aauth.MatchInteractionCode`,
and its policy grants or refuses on a later poll once the person has finished.

**Evidence:** `TestFederatedInteractionReachesTheAgentThatDeclaredIt`,
`TestChainedExchangeRelaysTheAccessServersInteraction` and
`TestAccessServerClaimsContinuation`.

## Federated grants have no exchange identifier

**Source:** Protocol `28e8258`, Auth Token Delivery, Auth Token Structure,
Common JWT Claims and HTTP Message Signatures Profile / Verification (Server).

Auth Token Delivery specifies signature, issuer, audience, confirmation key,
subject, scope and expiry checks. Auth Token Structure carries no Resource-token
ID, presented-token ID or pending-request ID. Common JWT Claims describes `jti`
as a unique token identifier for replay detection, audit and revocation; it
neither makes each delivery a new token nor requires a PS cache of previously
delivered grant JTIs. Verification (Server) also explicitly does not require
PS or AS replay caches for Resource tokens.

The PS therefore accepts an identical, still-valid AS grant in separate Core
exchanges when it satisfies each exchange's full authorization context and
expiry bounds. This does not prove that the AS made a fresh approval or billing
decision for the second exchange. Single terminal delivery is scoped to each
retained continuation, not to a token across all continuations. The library
adds no cross-exchange JTI cache or private request-binding claim. An AS remains
the authority that can issue an equivalent fresh grant in any event.

**Evidence:** `TestFederatedEquivalentGrantHasNoCrossExchangeBinding` in
`integration/federated_deferred_test.go` creates distinct pending, Resource and
presented-token references, delivers the same grant bytes for both, and refuses
another delivery from either consumed continuation. The adjacent altered-grant
tests execute signature and scope refusals.

## Federation pending-URL error names and competing polls

**Source:** Protocol `28e8258`, Pending URL Security, Polling Error Codes and
Error Response Format.

The draft requires authentication at pending URLs and `410` after terminal
delivery. Its `invalid_code` names an interaction code; `denied` names an
approver's decision. Neither describes these opaque federation references or
a different authenticated poller. The AS and PS federation endpoints use these
library error-code extensions, without claiming that the draft registers them:

| Status and error | Meaning |
| --- | --- |
| `410 unknown_request` | No retained continuation for that reference. |
| `410 request_consumed` | The retained continuation has already delivered its terminal result. |
| `403 wrong_poller` | The authenticated PS, Agent identity or Agent key does not own the continuation. |
| `409 request_conflict` | Another AS poll changed a still-pending record before this poll could publish. |

An explicit AS policy denial remains `403 denied`; expiry remains one
`408 expired` before consumption. These choices apply only to AS and federated
PS token continuations. Interaction-code endpoints retain their own mappings.

An AS record has no in-flight policy lock. Concurrent polls may each run policy
and sign a Core token before one conditional store replacement wins. Only that
winner publishes its buffered result; losing signed tokens are discarded. A
loser reloads the record to distinguish consumption from a nonterminal update.
Hosts must not rely on exactly-once policy execution or charge on a poll. The
PS's separate in-flight fence normally prevents overlapping AS polls from that
host, but is not an AS-wide lock.

**Evidence:** `TestFederatedPendingErrorsDistinguishUnknownAndConsumed`,
`TestFederatedDeferredPollIdentityAndSingleDelivery`,
`TestFederatedDeferredDenialRetainsPollingError`, and
`TestFederatedASConcurrentPollsPublishOneResult` in
`integration/federated_deferred_test.go`. The last test overlaps native AS
polls at store replacement, asserting one published wait or grant and the
corresponding conflict or consumed response from its competitor.

## Parent-mediated federated waits stay with the parent

**Source:** Protocol `28e8258`, Sub-Agents (Parent-Mediated Authorization),
AS Response, Deferred Responses, Polling Error Codes, Agent Response to
Clarification (Cancel Request) and Pending URL Security.

Parent-Mediated Authorization has the parent make every Person Server call
and says consent surfaces for the parent; it does not describe an AS that
defers a sub-agent's request. This implementation treats the wait as the
parent's request. The PS retains the exact sub-agent token beside the parent's
token, and only the parent's identity and key may poll or cancel. A child that
signs a poll or cancellation receives `403 wrong_poller` and changes nothing,
before or after the AS completes. Both waits end at the earliest of their
configured lifetime and the Resource, parent, sub-agent and presented-token
expiries, using the sub-agent token actually presented. Both Agent tokens and
their relationship are verified again before each AS poll and before release,
and the released grant must be bound to the child key.

The polling error `revoked` names the Agent token of the Agent that started the
request. A sub-agent token its Agent Provider revoked while the request waits
also ends it with `403 revoked`; the public `detail` says which token was
revoked. Neither token is presented to the AS again.

DELETE on a pending URL is defined as an answer to a clarification. A parent
may also withdraw an approval or payment wait with a bodyless signed DELETE.
The PS consumes its own record first, so nothing retained can be released
later, answers `200` with `{"status":"cancelled"}`, and sends the AS one signed
DELETE. A withdrawal that loses its compare-and-swap to a host advance reloads
and consumes again, so it still wins and any grant the advance retained is
withheld; only a request another poll or cancellation consumed first is
answered `410 request_consumed`. The AS consumes its record for its owning PS
with the same answer (another PS receives `403 wrong_poller`), and later polls
receive `410 request_consumed`. A withdrawal after the deadline consumes the
record and answers `408 expired`. The PS-hosted consent wait answers its own
cancellation the same way. These answers match aauth-rust, whose PS accepts
only `200` or `410` from an AS DELETE, so either PS can withdraw at either AS.

The two deadlines are configured separately, so a wait the PS ends on its own,
because of its deadline, a revocation or an AS answer that arrives after the
PS deadline, may still be live at the AS, where an unattended payment request
could still be paid. The PS therefore sends the AS the same best-effort DELETE
whenever it ends a wait the AS has not finished. A missed AS DELETE leaves the
AS record only until its deadline; the PS does not retry it (AAG-F109).

**Evidence:** `integration/subagent_federated_deferred_test.go`, including
`TestSubagentFederatedWaitsEndWithThePresentedChildToken`,
`TestSubagentFederatedCancellationClosesBothContinuations`,
`TestSubagentFederatedCancellationWinsAConcurrentAdvance`,
`TestSubagentFederatedLateASAnswerIsWithdrawn`,
`TestSubagentFederatedCancellationAfterExpiryIsExpired`,
`TestAccessServerCancellationBelongsToTheRequestingPersonServer` and
`TestSubagentFederatedRevokedChildTokenEndsTheWait`; the shared harness
`authorization.subagent` slice exercises the same answers against aauth-rust.

## A revoked Agent-person binding ends issuance and pending delivery

**Source:** Protocol `28e8258`, Agent-Person Binding, Upstream Token
Verification step 4, Revocation Cascade, Presenting a Revoked Token, Polling
Error Codes and Pending URL Security.

Agent-Person Binding says a changed association is handled by revoking the
existing binding and establishing a new one, and that revocation immediately
prevents the agent from obtaining new auth tokens. It defines no operation or
answers for it outside call chaining. Here the host revokes a binding through
`Server.RevokeAgentBinding`, keyed by the top-level Agent's provider and
identifier, after authenticating its administrator. The binding belongs to the
Agent that signs Person Server requests, so a parent's revocation also covers
every child it mediates. This is distinct from the parent's per-scope consent
that Parent-Mediated Authorization says the parent can withdraw: host policy
already reevaluates that consent on every child request.

While the binding is revoked, the PS answers as the synchronous request would
be answered: a Person-token request, a mission proposal (whose approval issues
Person tokens) and a pending Person-token interaction or mission proposal
receive `403 person_token_denied`; a token request and a pending consent or
federated wait receive `400 revoked_presented_token`; a chained request whose
caller, or the caller's mediating parent, holds the binding receives
`400 revoked_upstream_token`. Each refusal carries a public `detail` naming
the revoked binding, so a caller can tell it from a denial. The pending answer
is not the polling code `revoked`, whose table names only the Resource,
upstream and Agent tokens (AAG-F108). It is terminal: the PS ends the wait
first, so its pending URL answers `410` afterwards, as Pending URL Security
requires. A federated wait is consumed and withdrawn at the AS; a PS-hosted
wait is failed, cancelled or consumed through its store's own transitions,
and an undelivered mission approval is withheld. Host approval and mission
approval are refused with `ErrAgentBindingRevoked`. Delivered Person and Auth
tokens are not revoked at Resources or ASes; they expire normally. The
permission, audit and interaction endpoints issue no credential and are not
gated by this state.

`Server.ReestablishAgentBinding` records that the host has established the new
binding. Requests made after it are admitted under the host's `BindPerson`
policy, while every pending request created, and every presented or upstream
token issued, at or before that instant stays refused. The revocation entry is
the fence, so the host keeps it, and the replacement needs no waiting period
for the old binding's credentials to expire. The comparison uses the Person
Server's clock. Distinct lifecycle changes use strictly increasing instants;
store retries retain their original instant. A stale revocation leaves a later
replacement alone, and a replacement at or before the latest revocation is
refused with `ErrAgentBindingStale`. Hosts coordinate this clock and binding
policy across instances.

A pending record retains the original verified request time, before any host
policy or Access Server round trip. Those operations cannot move an old
request past a replacement fence. The same binding is checked again after
host policy before immediate credential issuance, and before federated
delivery. An Agent poll checks retained Agent-token revocations even when no
host has advanced the Access Server wait.

An AS-issued presented Auth token has no retained binding generation in this
profile, and its `iat` belongs to the AS's clock. After replacement the PS
therefore refuses that presentation with `revoked_presented_token`, including
new AS tokens, and requires a fresh PS Person token for the next authorization
or step-up. A never-revoked binding still accepts AS Auth-token step-up.
Locally issued JWTs use whole-second `iat`, which must be strictly later than
the replacement instant; a request in that same second can be refused safely.
`TestReplacementDoesNotAdmitOldASAuthTokenWithAheadClock` reproduces the old
credential being admitted without this rule.

**Evidence:** `personserver/subagent_profile_test.go`
(`TestRevokedAgentBindingRefusesNewPersonTokens`,
`TestRevokedAgentBindingRefusesTokenRequests`,
`TestCallChainingRefusesARevokedCallerBinding`),
`personserver/agent_binding_lifecycle_test.go`
(`TestRevokedAgentBindingEndsPSHostedConsentInEveryState`,
`TestRevokedAgentBindingEndsPersonTokenInteractionsInEveryState`,
`TestReestablishedAgentBindingAdmitsOnlyLaterRequests`,
`TestRevokedAgentBindingRefusesMissionApproval`),
`TestSubagentFederatedBindingRevocationEndsTheWait`, the
`storetest.RunAgentBindingRevocation` contract, and the shared harness's
`revoked-binding` and `revoked-pending` scenarios, which aauth-rust answers the
same way.

## A PS-hosted wait ends when an Agent token it depends on is revoked

**Source:** Protocol `28e8258`, Presenting a Revoked Token and Polling Error
Codes.

Presenting a Revoked Token says a pending request whose agent's agent token is
revoked while it waits terminates with `revoked`, `detail` saying which. A
PS-hosted consent or Person-token wait retains the identifiers of the Agent
token that started it and, for a parent-mediated request, of the sub-agent
token. The parent re-authenticates on every poll, but the child never calls the
Person Server, so only the Person Server can refuse to bind a credential to a
child key its Agent Provider withdrew. A revocation of either token, recorded
through the Person Server's Agent-token revocation store, ends the wait with
`403 revoked` and a `detail` naming the token, and later polls receive `410`;
host approval is refused with an error matching `ErrAgentTokenRevoked`. The
federated wait applies the same rule before each AS poll and before release.

**Evidence:** `TestRevokedAgentTokenEndsPSHostedWaits` in
`personserver/agent_binding_lifecycle_test.go` and
`TestSubagentFederatedRevokedChildTokenEndsTheWait`.

## A sub-agent token comes from the parent's own provider

**Source:** Bootstrap `28e8258`, Sub-Agent Tokens; Protocol `28e8258`,
Sub-Agent Identity.

`IssueSubagent` authenticates the parent token with only the provider's own
signing key, not a general resolver, because a sub-agent's `iss` must equal its
parent's. Bootstrap says a sub-agent's `exp` should not exceed, or is no later
than, the parent's; the provider caps a longer requested lifetime at the
parent's `exp` rather than refusing it. The host supplies the discriminator and
owns its uniqueness. The hosted handler accepts the draft's illustrative `jwk`
and `discriminator` members, ignores other members rather than letting them
reach the token, and answers a sub-agent signer or policy refusal with
`403 subagent_denied`; Bootstrap defines no error codes for this request.
Bootstrap has the provider record which parent requested each live
sub-agent, which only host policy can do, so the handler refuses a request it
could not issue, the parent's own key or a malformed suggested discriminator,
with `400 invalid_request` before policy sees it. It keeps no replay cache: an exact replay inside the signature window yields
another token for the same sub-agent key, which only that key's holder can use.

**Evidence:** `agentprovider/subagent_test.go` and
`agentprovider/subagent_http_test.go`.

## An Agent identifier's `+` separates two non-empty parts

**Source:** Protocol `70d6737`, Agent Identifiers (lines 488 and 490) and
Sub-Agents (line 1915).

`+` is reserved as the sub-agent delimiter. A top-level Agent's local part
has none; a sub-agent's is its parent's local part, `+`, and a non-empty
discriminator; and delegation is one level deep, so a parent's local part has
no `+`. `ValidateAgentIdentifier` checks an identifier on its own, without the
token that carries it: it accepts a local part with no `+`, or with one `+`
between two non-empty parts, and refuses `+worker`, `assistant+` and
`a+b+c`. The draft does not say whether a discriminator may contain `+`;
refusing it follows from the reservation. Whether an Agent is a sub-agent is
still decided by `parent_agent` (`ValidateAgentRelationship`), never by this
shape: line 490 forbids parsing the local part for protocol decisions, and
this check refuses only identifiers no Agent Provider may assign.

**Evidence:** `identity_test.go:TestAgentIdentifierPlacesTheSubAgentDelimiterBetweenTwoParts`.

## Request-key algorithms are an endpoint choice

**Source:** Signature-Key `69f5ba2`, Algorithm Determination, Header Web Key
(hwk), Algorithm Selection, and `unsupported_algorithm`.

The draft requires a verifier to refuse an `alg` it does not support with
`unsupported_algorithm`, and `Accept-Signature-Alg` to state exactly the set
it accepts. It does not say whether that set belongs to the library or to
each endpoint. `VerifyOptions.AcceptedAlgorithms` makes it the endpoint's
choice and defaults to Ed25519, so existing roles keep their Ed25519 profile.
An `hwk` or `x509` key may use `ES256`, `ES384`, `RS256` or `PS256` when the
endpoint lists it, and every `unsupported_algorithm` from a prepared request
names exactly that list. The `jwt`, `jkt-jwt`, `self-jwt`, `jwks` and
`jwks_uri` keys, AAuth tokens, and compact JWS remain Ed25519. `RS256` and
`PS256` keys need a 2048- to 8192-bit modulus and an odd exponent no larger
than 2^31-1. `PS256` uses a salt as long as the hash. An `hwk` member refuses
`kid`, private members and members of another key type, checking them before
`alg`, and ignores other parameters as RFC 7517 requires of JWK members.

**Evidence:** `signaturekey/hwk_algorithms_external_test.go` and
`jose/signature_algorithms_external_test.go`.

## A Signature-Key header without the label's member is a missing Signature-Key

**Source:** Signature-Key `69f5ba2`, Label Correlation step 4 (line 179),
Label Consistency (line 187), `invalid_signature` (line 1018) and
`invalid_key` (line 1046); Protocol `70d6737`, Verification (Server) steps 1
and 5 (lines 2244 and 2248).

When Signature-Key is present but has no member for the label being verified,
verification "MUST fail"; neither draft names the code. `invalid_signature`
covers a missing `Signature-Key` header, and `invalid_key` a key that is
present but cannot be parsed. A missing member is the missing header for that
one signature, so request preparation, `ParseCredentialForLabel` and response
verification answer `invalid_signature`, as aauth-rust does. A member that is
present but malformed (not an Item, or a scheme that is not a token), and a
header that is not a Dictionary, stay `invalid_key`, following step 5's "cannot
be parsed", although the `invalid_signature` text also says "malformed".

**Evidence:** `signaturekey/request_external_test.go:TestPrepareRequestClassifiesAMissingLabelMemberAsInvalidSignature`.

## A request signature's length is judged against its key

**Source:** Signature-Key `69f5ba2`, Algorithm Determination (lines 225 and
233); Protocol `70d6737`, Verification (Server) steps 5 to 7 (lines 2248 to
2250).

The verifier obtains the key, then determines its algorithm, refusing an
`alg` or key type it does not implement with `unsupported_algorithm`, and only
then verifies the signature. A request whose key is resolved after
preparation (`jwt`, `jkt-jwt`, `self-jwt`, `jwks`, `jwks_uri` and `cached`) is
therefore prepared with any nonempty signature, and its length is compared
with what the resolved key produces. A key of a type the verifier does not
implement, such as ML-DSA's `AKP`, is `unsupported_algorithm` whatever the
signature's length; a wrong length for a key it implements is
`invalid_signature`, and for a `jwks_uri` key it lets a `KeyRefresher` check
the key once more, as any other `invalid_signature` does. An `hwk` key is in
the header, so its algorithm and length are checked while preparing, in the
same order. An `x509` proof admits every length a supported certificate key
can produce until the certificate is checked.

**Evidence:** `signaturekey/request_external_test.go:TestJWKSURIKeyOfAnUnimplementedTypeIsUnsupportedAlgorithm`.

## An x509 proof needs a host-supplied chain, anchors and CRLs

**Source:** Signature-Key `69f5ba2`, X.509 Certificates (x509), Key
Validation, and Scheme-Specific Risks.

The draft lists fetching `x5u` and checking revocation as verification steps
but defines neither egress rules for `x5u` nor a revocation mechanism.
`VerifyX509` does not fetch: the host supplies the PEM chain it fetched, its
trust anchors, and CRLs. Every certificate on the path below the anchor must
be covered by a current CRL that its issuer signed. A certificate that a CRL
lists, or that no usable CRL covers, is refused. Delta CRLs, CRLs with an
issuing distribution point, and CRLs with other critical extensions are not
used, so a partitioned CRL leaves its certificates uncovered. Chain and
revocation failures, and an `x5t` that does not match, are `invalid_key`.
The end-entity key selects Ed25519, ES256 (P-256) or ES384 (P-384). An RSA
subject public key names neither padding nor hash, so choosing `RS256` or
`PS256` for it would be the polymorphic selection the draft forbids: it is
`unsupported_algorithm`. Certificate signatures in the chain are checked with
the Go standard library's algorithms.

**Evidence:** `signaturekey/x509_external_test.go`.

## Assertion caching seals its identifiers and refuses long-lived assertions

**Source:** Signature-Key `69f5ba2`, Cached Assertion (cached),
Signature-Key-Cache Response Header, Presenting and Resolving a Cached
Assertion, `cache_miss`, and Cache Identifiers.

The draft leaves the identifier's form, the retention policy, and the meaning
of "long-lived" to the verifier. `AssertionCache` seals each identifier with
AES-256-GCM under a key derived by HKDF-SHA-256 from the fleet key and a fresh
192-bit salt, so no key and nonce pair repeats. The seal carries the scheme,
`iss`, `sub`, `jti`, the assertion's SHA-256, its `exp`, its confirmation key
and the entry's own expiry. An identifier that does not open is `cache_miss`.
The issuing node also retains the exact assertion, and only an identifier in
its index resolves unless `Fleet` is set. An entry is honored through its
`expires` second, which is never later than the assertion's `exp`. A
configured retention longer than the assertion is shortened to it rather than
refused. An assertion with more than 24 hours left is not cached, since the
cache keeps no revocation state. `VerifyCached` checks the HTTP signature
against the resolved confirmation key before the assertion's expiry, so a
held but expired assertion is `expired_jwt`. A caller without the private key
gets `invalid_signature`, never `cache_miss`. Caching requires `iss`, `jti`,
`exp` and `cnf.jwk`.

**Evidence:** `signaturekey/cache_external_test.go`.

## An `aauth-resource` link is read leniently and admitted strictly

**Source:** Protocol `70d6737`, Resource Metadata Link Relation (lines
2136-2158), Link Relation Security (2858-2862), and Link Relation Type
Registration (3012-3019).

The draft fixes the admissible target, a server identifier followed by
`/.well-known/aauth-resource.json`, and says the HTML relation is carried in
`head`. It does not say how an Agent reads the relation. `ResourceLinksFromHTML`
reads every `link` element, in `head` or not, decodes attribute entities as
HTML does, and does not resolve a relative `href` against the page, so only an
absolute target can be admitted. A relation token is matched case-insensitively
among the space-separated values of `rel`. An `anchor` parameter is ignored. A
Link field longer than 8 KiB in total, or a page larger than 1 MiB, is not
scanned. Duplicate targets are reported once. Whatever is read, only the one
target form is admitted, and `ResolveResourceLink` checks that form again
before it fetches anything. A document reached through a link is verified like
any metadata document, with `issuer` compared byte for byte against the target
minus the suffix. The library never follows a link on its own: an Agent passes
the links it found, with where it found them, to `ResolveResourceLink`.

**Evidence:** `resource_link_test.go` and
`integration/resource_link_test.go`.

## A delayed verifier's bound and replay span come from its own options

**Source:** Protocol `70d6737`, Freshness and Replay (lines 2268-2274) and
Verification (Server), step 3 (lines 2240-2254).

The draft lets a verifier that first sees a signed artifact after a delay
anchor on `created`, verify the presented token at `created`, and choose how
much delay it accepts, and it requires such a verifier's replay cache to span
that delay. It does not say how the delay relates to the signature window or to
`expires`. `VerifyOptions.MaxDelay` is the accepted delay. A request may then be
up to the larger of `MaxDelay` and the window old; `created` further ahead than
the window is still `clock_skew`; and `expires` is judged at the time of
verification, because the draft's rule to reject a past `expires` has no
exception. `ValidAt` is `created` for a delayed verifier, and `CheckIssuedAt`
judges a token's `iat` against it. `ReplayCache` keys entries by the tuple the
draft names, `(signing-key thumbprint, created, @method, @authority, @path)`,
and holds each until `created` plus the request's own `MaxAge`, so its span
follows the verifier's options rather than a separate setting. A replay is
`invalid_signature`, the code the Signature-Key draft gives a replayed
`created`. A full cache refuses with `ErrReplayCacheFull` rather than evict an
entry whose span has not ended.

**Evidence:** `signaturekey/freshness_external_test.go` and
`freshness_external_test.go`.

## An Access Server verifies the upstream token of a chained request itself

**Source:** Protocol `70d6737`, PS-to-AS Token Request (lines 1577-1608),
Call Chaining (1846-1858), Intermediary Agent Identity (1860-1866), Directed
Identifiers Across a Chain (1868-1880), and Upstream Token Verification
(1826-1836).

A four-party Person Server with `FederatedCallChainingConfig` passes the
Agent's exact `upstream_token` to the Access Server, with the intermediary's
Agent token as `agent_token`. The Access Server applies steps 1 to 3 of
Upstream Token Verification before policy: `typ` selects the person-token or
auth-token verifier and any other is `invalid_upstream_token`; `aud` must equal
the `iss` of the intermediary's Agent token; `cnf` is not compared; a person
token's `iss`, or an auth token's `ps`, must be the Person Server that signed
the request, and an auth token's `iss` is not checked beyond its signature. An
expired token is `expired_upstream_token`, and an `iat` beyond the signature
window is `clock_skew`. The intermediary's own Agent token is not required to
name the signing Person Server, since its `ps` names the intermediary's own.
The issued auth token takes `sub` from the Resource token and expires no later
than the upstream token, and a deferred wait for it ends with `expired` by
then. Once a person token's revocation reaches the Access Server, it answers
`revoked_upstream_token`; see "A Person Server's revocation names a person
token or an auth token" below.

The four-party Person Server accepts upstream person tokens it issued and
auth tokens an Access Server issued that it delivered and kept a receipt of,
as "Immediate call chaining uses token trust plus explicit chain bindings"
describes. It refuses chained R3 requests. A chained request whose Resource
token offers a Budget carries the Person Server's ceiling to the Access Server
beside the upstream token, sized from that Resource token's own offer as for
an unchained request; nothing is drawn from the upstream token, which carries
no Budget of its own here. A `202` or `402` from the Access Server for a
chained request starts an ordinary federated wait, which retains the exact
upstream token. A three-party Person Server refuses a
Resource token naming an Access Server with `invalid_resource_token`, chained
or not.

**Evidence:** `accessserver/upstream_external_test.go`,
`integration/call_chaining_four_party_test.go` and
`integration/call_chaining_hops_test.go`.

## Further Signature-Key schemes are for a Resource's clients outside AAuth

**Source:** Protocol `70d6737`, Keying Material (lines 2177-2196) and
Signature-Key Scheme Rejection (2256-2266); Signature-Key `69f5ba2`,
Accept-Signature-Scheme and Cached Assertion (cached).

Keying Material requires `jwt` of Agents and `jwks_uri` of servers, and step 4
of Verification refuses any scheme the profile does not use. The one place a
draft expects more is a Resource that also serves clients outside AAuth: it
may accept further schemes and must then list all of them. No AAuth role
accepts `jwks`, `x509` or `cached` for an AAuth request. A Resource with
`FurtherSchemes` prepares its protected routes with `jwt` plus the listed
schemes and with Ed25519 plus the listed algorithms, so every
`unsupported_scheme` and `unsupported_algorithm` there names the full lists,
and it states them on the unsigned challenge too. A request under a further
scheme goes to a separate handler with a `SignerPrincipal`, so no AAuth policy
or principal sees a signer that is not an Agent. `cached` resolves only
`jkt-jwt` assertions, since the Resource does not cache AAuth tokens, and a
resolved assertion of another scheme is `invalid_jwt`. The authorization,
revocation, R3 and usage endpoints keep their AAuth schemes, because they
serve only AAuth parties. A Resource-managed session Resource has no further
schemes.

**Evidence:** `resource/further_schemes_test.go`.

## A signed usage response covers what Budgets lists

**Source:** Budgets `70d6737`, The Signed Response (lines 1039–1061);
Signature-Key `69f5ba2`, Signature-Key Integrity.

Budgets lists the components a signed usage response covers: `@status`,
`content-type`, `content-digest`, and the request's `@authority` and `@path`
under `req`. Signature-Key requires every request signature to cover
`signature-key`, and says nothing about responses. The Resource covers exactly
the five listed components, in that order, under the label `sig`, so any
verifier that rebuilds the base from the Budgets list accepts it. Leaving
`signature-key` uncovered does not let a third party re-attribute the
response, because `VerifyUsageResponse` does not take the signer from the
header: it requires the jwks_uri `id` to be the Resource the caller asked and
`dwk` to be `aauth-resource.json`, and it applies the request signature window
to `created`. A response with a signature that does not verify is refused even
when the caller does not require one; an unsigned response is reported as
unsigned. See AAG-F132.

**Evidence:** `resource/usage_signature_test.go` and
`signaturekey/response_external_test.go`.

## Internal R3 definitions compose by merging their displays

**Source:** R3 `70d6737`, Operations Spanning Multiple Definitions (lines
431–442).

The draft leaves the organization of a Resource's definitions to the Resource
and lets it merge their displays or write one for the combination. A
definition is involved when the requested operations are not disjoint from its
operations under the vocabulary's own semantics. `r3.MergeDisplays` joins
summaries with "; ", implications and irreversible text with a blank line, and
takes the union of the distinct `data_accessed` values, so no stated
consequence is lost. The composed document's operations are always exactly the
requested ones, never the whole of each involved definition. The internal
definitions must together cover the vocabulary's authoritative operations, so
no requested operation falls outside every definition. Each document stays
bound to its Resource token's lineage in its URI, so an identical combination
yields identical bytes and the same `r3_s256` but is not served at a shared
URI.

**Evidence:** `resource/r3_definitions_test.go` and `r3/release_test.go`.

## Release gating runs only held calls and writes the release statement

**Source:** R3 `70d6737`, Proposal Document (`result`) and Approving Release
Rather Than Execution (lines 686–723).

The Resource runs a call before approval only under `202` delivery, where the
agent never re-sends it: under `401` the agent's retry would ask for a result
computed from a call it no longer controls. `NewReleaseProposalDisplay` opens
the detail with a fixed `## Action` section stating that the operation has run
and that what is approved is release of its result, and `NewProposal` refuses a
`result` without that display; a received proposal is not judged by this
wording. A route the Budget profile meters, and an operation annotated
`budget: true`, never run first. Whether running is audited or billed, or calls
another party, only the host knows, so `Eligible` decides. Unless
`MeterRelease` is set, the library meters nothing for a release-gated call, so
a declined release leaves no Budget posting and the held record keeps the
unreleased response until its pending lifetime ends: what the library meters
and what its records show cannot diverge. With `MeterRelease` the release is
the metered event; see "A per-call token's budget meters the release of a
held result" below. A re-requested
call runs again rather than inheriting the earlier result; by the eligibility
rule that has no outside effect.

**Evidence:** `resource/r3_release_test.go` and `r3/release_test.go`.

## A held Budget refusal stays at one pending URL

**Source:** Budgets `70d6737`, Deferred Delivery (lines 769–802).

Rule 3 says the Resource "continues to hold the invocation" after a completing
token that does not fit, without saying whether the pending URL changes. The
Resource keeps the same `Location` and swaps the held Resource token with
`HeldBudgetStore.Rechallenge`, a compare-and-swap on the previous token, so one
invocation is never pending under two tokens. The reservation for the
completing token is taken before the store claims the invocation and released
on a replay, a conflict or a mismatch, so a replay meters nothing and a token
that does not fit leaves the invocation pending. A hold needs a reserving
Budget store for that order. With a Budget profile the Resource holds nothing
else but a metered release, because a held Core or per-call completion carries
no meter. A refused
token that carries R3 claims is answered `401`, as before.

**Evidence:** `resource/held_budget_test.go`.

## A per-call token's budget meters the release of a held result

**Source:** R3 `70d6737`, Approving Release Rather Than Execution (lines
688-723), Budget Annotation (316-322) and Flow (674-679); Budgets, Resource
Token Extensions (425-452), PS-to-AS Token Request Extensions (542-572), Auth
Token Extensions (574-608), Budget Exhaustion (716-727) and Deferred Delivery
(769-797).

A Resource may meter the release of a result rather than its execution; R3
leaves what that draws down to the Resource's metering policy. With
`R3ReleaseConfig.MeterRelease` the library meters it against the per-call
Auth token, the token presented on the poll that completes the held
invocation. The drafts do not say whether a per-call proposal's Resource
token or the per-call Auth token may carry `budget`; this library's reading,
as aauth-rust's, is that they may:

- Only an operation annotated `budget: true` is metered at release, and it
  may then run before approval; an unannotated release states no cost. A
  route the Budget profile meters still never runs first.
- The proposal's Resource token offers exactly the release cost, in a
  denomination the Resource declares, and carries no `budget_consumed`: the
  token presented on the call is a class Auth token, which carries no Budget
  here.
- The per-call Auth token carries the issuer's grant beside `r3_granted`. The
  Person Server sends its ceiling to the Access Server, and the Access
  Server's proposal policy grants it, under the same rules as any Budget
  offer.
- A per-call token without a budget, or whose grant is above the offer or in
  another denomination, is `403 access_denied`. One whose grant is below the
  cost is `403` with `AAuth-Budget` stating its `remaining` and the cost as
  `required`, before the held store claims the invocation, so the result
  stays held for a token that fits. A per-call token authorizes only this
  release, so its grant alone decides whether it fits.
- The release charges the cost once. The released response carries
  `AAuth-Budget` with that cost; a replay answers from the stored result with
  the token's current `remaining` and meters nothing again. If the charge
  fails after the claim, the release is retained as a `500` and the call is
  never run again. A declined release meters nothing.

Deferred Delivery's third rule answers a completing token that does not fit
with another `202` and a fresh Resource token naming that token. For a held
release that token would have to be a new per-call proposal token presented
with a per-call Auth token, which R3's flow does not describe, so this
library answers `403` as aauth-rust does. aauth-rust also lets a three-party
Person Server grant the release budget and refuses a budgeted proposal at a
federated one. This library's per-call R3 is four-party only, and the
PS-to-AS budget parameter applies to any Resource token that offers a budget,
so its federated Person Server relays the ceiling and its Access Server
grants the release budget. The relay has no precedent in the drafts or in
aauth-rust, so each step is stated here for another implementation to match:

1. The Agent sends the proposal's Resource token to its Person Server with
   the class Auth token it presented on the call as `presented_token`, and
   `capabilities` including `budget`.
2. The Person Server verifies the Resource token's `r3_uri`, `r3_s256` and
   `budget`, and checks the offer against the Resource's declared
   `budget_units` (`invalid_budget` otherwise). It fetches the proposal, and
   proposal consent sees the offer in `AuthorizationRequest.Budget`.
3. The Person Server's ceiling policy (`FederatedBudgetConfig.Ceiling`)
   returns the ceiling, which keeps the offer's `unit` and `decimals` and an
   `amount` no higher, or nothing. Anything else is `500 server_error`.
4. The PS-to-AS token request carries `resource_token`, `presented_token`,
   `agent_token` and, when there is a ceiling, `budget` with it. Without a
   ceiling `budget` is omitted, and omission is not a grant.
5. The Access Server checks the offer against its own view of the
   Resource's `budget_units`. Its proposal policy returns
   `R3ProposalDecision.Budget`: required when the request carried `budget`,
   forbidden when it did not, and narrowing it without changing `unit` or
   `decimals`. Anything else is `500 server_error`.
6. The Access Server mints the per-call Auth token with `r3_uri` and
   `r3_s256` of the proposal, `r3_granted` of its one operation, no
   `r3_per_call`, and `budget` set to the grant. It expires no later than the
   presented class token.
7. The Person Server verifies the per-call token as for any per-call result
   and also its budget. The token carries `budget` exactly when the Person
   Server sent one, in the same `unit` and `decimals`, with an `amount` no
   higher than the ceiling or the offer. Otherwise it answers
   `502 as_unreachable`. The Person Server keeps no allocation ledger across
   tokens.
8. An Access Server `202` or `402` for a budgeted proposal is refused at the
   Person Server with `500 server_error` (`DeferredCompositionError` reason
   `r3`), as for any deferred R3 exchange.
9. The Agent checks that the per-call token's budget narrows the offer, at
   the exchange and again before it polls. When the Person Server omitted its
   ceiling, the per-call token it delivers has no budget: this library's
   Agent refuses it at the exchange, and a Resource presented with it answers
   the release `403`.

**Evidence:** `TestR3MeteredReleaseDrawsTheCostDownOnceFromThePerCallToken`,
`TestR3MeteredReleaseFourPartyJourney`,
`TestMCPR3PerCallBudgetTokensCarryTheReleaseOffer` and
`TestR3ReleaseGatingRefusesMeteredAndBudgetAnnotatedCalls`.

## A revocation hold that ends before a downstream answers is pending

**Source:** Protocol `70d6737`, Revocation Response.

The draft answers `202` when the cascade takes longer than the recipient will
hold the connection, and makes a downstream that did not respond or timed out
`revocation_unavailable`. It does not say which applies when the recipient's
own hold ends first. Here the hold is the caller's `Prefer: wait`, capped at
20 seconds by default. A downstream still unanswered when it ends stays
pending: the recipient answers `202` and attempts it again on the next poll,
which is safe because a repeated revocation records nothing new. A downstream
whose own request fails or times out under the HTTP client is
`revocation_unavailable`. A downstream that answers `429 rate_limited` has not
reached either terminal outcome the draft names, so it stays pending and is not
attempted again before its `Retry-After`, nor is anything else sent to that
recipient in the same step; a pending downstream URL is likewise not polled
before its `Retry-After`. The cascade's progress is process memory, bounded,
while the revocation itself is in the host store before anyone is called; a
pending URL the recipient no longer holds is `404`, and the caller revokes
again. After the terminal response a poll is `410` with `invalid_code`, the code
this library uses for every consumed pending URL. Repeated revocations
re-attempt both `revocation_unavailable` and `revocation_unsupported`
recipients, since neither succeeded.

**Evidence:** `TestRevocationCascadeIsDeferredAndPolledByItsCaller` and
`TestFourPartyRevocationCascadesFromPersonServerThroughAccessServer` in
`integration/revocation_cascade_test.go`.

## A Person Server's revocation names a person token or an auth token

**Source:** Protocol `70d6737`, Revocation Request, Who Revokes What and
Revocation Cascade.

A revocation carries only `jti` and `exp`, and a Person Server issues both
person tokens and, in three-party access, auth tokens under one `iss`. A
Resource cannot tell which one a revocation names, so it records the pair as a
revoked person token and, in three-party access, as a revoked auth token. An
Access Server accepts person-token revocations only from Person Servers its
`TrustPersonServer` policy admits and answers others `unsupported_iss`; a
four-party Resource accepts auth-token revocations only from its configured
Access Server. A Person Server counts an Access Server it passed a person token
to as `upstream_token` among those it presented the token to, so a revocation
reaches it and it can answer `revoked_upstream_token`
([AAG-F128](SPEC-FEEDBACK.md#aag-f140--no-revocation-reaches-an-access-server-that-received-a-person-token-as-upstream_token)). When a person token is revoked the Access Server revokes every
unexpired auth token issued against it and, on a step-up, against those auth
tokens in turn, and records each as revoked itself so a later step-up presenting
one is refused.

**Evidence:** `TestFourPartyRevocationCascadesFromPersonServerThroughAccessServer`.

## A revoked request-parameter token is reported revoked even when expired

**Source:** Protocol `70d6737`, Presenting a Revoked Token and Verification
(Server).

Presenting a Revoked Token requires a recipient to say a revoked token was
revoked, not that it is expired, while step 5 of Verification gives
`revoked_jwt` only to a JWT that is unexpired. This library follows step 5 for a
token in `Signature-Key`, which is `expired_jwt` once expired. For a
`resource_token` or `presented_token`, whose signature was verified before its
lifetime, a revocation still on record is reported as
`revoked_resource_token` or `revoked_presented_token`. A pending request is
answered `403 revoked` instead, with a `detail` naming the token.

**Evidence:** `TestWithdrawnResourceTokenEndsPSHostedConsent` in
`personserver/resource_token_revocation_test.go`.

## The Agent keeps refused resource tokens until they expire

**Source:** Protocol `70d6737`, Token Endpoint Error Codes.

`revoked_resource_token` is terminal for that token, and the Agent must not
resubmit it. `agent.Client` does not otherwise retain state, but it remembers
the digest of each resource token a Person Server refused this way, up to 1024
tokens, until the token's `exp`, and refuses to send it again with a
`*RevokedResourceTokenError` whose `Problem` is nil. After `exp` the Client's
own verification refuses the token. The memory is per process; a host that
recreates the Client after a restart relies on the Person Server refusing the
token again.

**Evidence:** `TestThreePartyWithdrawnResourceTokenAndRateLimitedRevocation`.

## Revocation endpoints bound each caller by rate and lifetime

**Source:** Protocol `70d6737`, Revocation Request and Revocation Response.

A recipient that accepts revocations from any verified issuer should bound what
one issuer can hold, in entries and in rate, and may reject an `exp` beyond the
longest lifetime it accepts. Every revocation endpoint here admits 600 requests a
minute from one verified caller by default, polls excluded, and answers
`429 rate_limited` with `Retry-After` beyond that. A cascade sends one
revocation per token, so the default of 600 a minute is high enough that a
legitimate cascade meets it only rarely, and when it does the sender keeps the
revocation pending rather than failing it. An `exp` more than 24 hours
ahead, the longest lifetime of an Agent token, is `invalid_request`. The entry
bound belongs to the store, which returns `aauth.ErrRevocationLimitReached`;
the endpoint then answers `rate_limited` and records nothing. A revocation from
a caller whose metadata document names no role the endpoint accepts
revocations from is `403 unsupported_iss`.

**Evidence:** `TestThreePartyWithdrawnResourceTokenAndRateLimitedRevocation`.

## Interaction callbacks are honored only after the code correlates

**Source:** AAuth Core `70d6737`, User Interaction, Interaction Callback
Errors, Endpoint and Other URLs, and Agent Provider Metadata.

Core makes the callback a user-experience aid with no security role, and says
an Agent builds it from its `callback_endpoint`. It does not say whether a
host compares the callback with that metadata, or whether a host redirects
for a visit whose code does not correlate. The library helpers accept a
callback only as an HTTPS URL with a lowercase host and no userinfo, query or
fragment, so `?error=` is always its only query; a loopback `http` callback is
accepted only when the host opts in after checking
`localhost_callback_allowed`. Roles hand a callback back only through a
correlated interaction: an unknown, used or rate-limited code produces an
error and no redirect, so an interaction page cannot become an open
redirector for an arbitrary link. Comparing the callback with the Agent's
`callback_endpoint` is left to the host (`AAG-F125`). A callback whose `error`
is unregistered, repeated or unreadable is read as `server_error`, never as
completion.

**Evidence:** `interaction_callback_test.go`,
`integration/resource_initiated_interaction_test.go` and
`integration/interaction_chaining_test.go`.

## Resource-initiated interaction is three-party, missionless and deferred

**Source:** AAuth Core `70d6737`, Resource Token Structure, Resource-Initiated
Interaction, Interaction Callback Errors, and Polling Error Codes.

The section has the Person Server issue the Auth token after its own consent,
which describes three-party access; it does not say what a federated Person
Server or an Access Server does with the claim (`AAG-F124`). A Resource puts
the claim only in Core Resource tokens it issues against a Person token, and
retains only the code's digest, until the Resource token expires. A Person
Server accepts the claim only with `ResourceInteractionConfig`, only on the
three-party path, and refuses it for call chaining, R3 and mission-bound
requests. A request that carries it always takes the deferred path, because
the person must visit the Resource, and an Agent that did not declare
`interaction` receives `user_unreachable`. The person is sent to the Resource
once, after the host's interstitial, to `{interaction.url}?code=...&callback=...`
where the callback ends in a fresh 128-bit flow value; only its digest is
retained, and a callback with any other value is refused. The interaction URL
is checked for HTTPS and passed to the host's egress admission before the
redirect, although the person's browser, not the Person Server, makes that
request (`AAG-F127`). Consent cannot be approved until the Resource returned
the person without an error. An error callback ends the request in the mapped
terminal state, which the next poll delivers once. When the Resource withdraws
the Resource token, the person is not sent on, the Resource's callback is
refused, and the next poll ends the request with `revoked`.

**Evidence:** `integration/resource_initiated_interaction_test.go`.

## Interaction chaining binds polls to the caller's key

**Source:** AAuth Core `70d6737`, Interaction Chaining, Interaction Chaining
(detailed flow), Deferred Responses, and Pending URL Security.

The section requires the intermediary to answer with its own code and
`Location` and to complete the original request there, but does not say which
credential the original Agent presents on that pending URL (`AAG-F126`). The
Agent polls with the Auth token it made the call with, and the Resource
answers only a poll whose verified key has the thumbprint retained when the
interaction was chained and whose person matches; any other caller receives
an empty `404`. The deadline never passes that Auth token's expiry, so only
Core Auth tokens are chained, and a revoked one is refused with
`revoked_jwt` like any other request. A downstream request that ends with a
polling error, `revoked` included, is relayed to the caller with that error. The result, a final status other than `202` with
its body and media type, is delivered once and the pending URL is `410`
afterwards. The detailed flow shows the intermediary sending the person on to
the downstream interaction with its own callback; the library builds that
link with a per-flow callback value, as for Resource-initiated interaction,
and an error that comes back ends the chained request with the mapped polling
error. The library's own Person Servers ask the person nothing about a
call-chaining request, so a chained `requirement=interaction` comes from
another server; the Agent keeps polling the Person Server the upstream token
names, as it does for a chained Access Server wait.

**Evidence:** `integration/interaction_chaining_test.go` and
`agent/call_chaining_test.go`.

## A chain carries the calling Agent's mission

**Source:** Protocol `70d6737`, Person Token Endpoint ("Which person" and the
`mission_s256` parameter), Call Chaining, Upstream Token Verification step 5,
Person Token Structure, Auth Token Structure and Mission Status Errors.

When the upstream token carries `mission_s256`, the Person Server "evaluates
the request against that mission". A mission belongs to an Agent, and the
draft does not say whose this is. It is the calling Agent's, as the Person
Server's record of the upstream token names it, or that Agent's parent when
it was a mediated sub-agent. The mission is loaded for that Agent and passed
to the chain policy, the downstream person token copies `mission_s256` and
expires no later than the mission, and so does the downstream auth token. The
Resource token for the downstream call must carry the same `mission_s256`,
since the Resource copied it from that person token; another is
`invalid_resource_token`.

Mission Status Errors is phrased for a request "with a `mission_s256`
parameter", which a chained request does not have. A terminated or expired
mission still ends the chain with `403 mission_terminated` and its
`termination_reason`, because the Person Token Endpoint says the mission's
expiry and termination "reach the chain". A mission the Person Server does not
hold for the calling Agent is `invalid_upstream_token`: the intermediary did
not name it, so the fault is in the upstream token. An intermediary that sends
`mission_s256` with `upstream_token` is `invalid_request`. A chained record
names the intermediary as its Agent, so a mission store's issuance commit
accepts a chained record whose Agent differs from the mission's.

A mission-bound request that waits for the Access Server, chained or not,
loads its mission again on every poll and host advance. Polling Error Codes
has no `mission_terminated`, but a terminated mission ends the wait with
`403 mission_terminated` and its `termination_reason`, as it ends a new
request for it, and the pending URL then answers `410`. The grant is
committed with the mission when it is released. A wait also ends no later
than its presented token, which the Person Server capped at the mission's
expiry, so expiry ends it with `expired` at the same instant.

**Evidence:** `integration/call_chaining_hops_test.go:TestCallChainCarriesTheCallingAgentsMission`
and `personserver/mission_composition_test.go`.

## A budgeted auth token chains like any other upstream token

**Source:** Protocol `70d6737`, Upstream Token Verification steps 1 and 2
(lines 1832 and 1833) and Call Chaining (line 1848); Budgets `70d6737`,
Delegation (line 923).

An auth token presented as `upstream_token` is verified "per Auth Token
Verification", and an auth token may carry a Budget grant. The intermediary's
Agent client, the Person Server and the Access Server verify a budgeted
upstream token with the complete Budget companion and then set its grant
aside: the upstream token "grants nothing by itself", and "a budget is not
delegable", so each downstream hop is sized from its own Resource token's
offer and nothing is drawn from the upstream grant. An upstream token without
Budget claims is verified as a Core auth token, as before. One that carries
R3 claims is still refused, because verifying them needs the R3 document,
which a chained request does not carry. aauth-rust's core verifier keeps
companion claims without checking them, so it accepts both.

**Evidence:** `integration/call_chaining_hops_test.go:TestFourPartyBudgetedAuthTokenChainsAsAnUpstreamToken`.

## A revoked upstream token ends a waiting chained request with revoked

**Source:** Protocol `70d6737`, Call Chaining, Presenting a Revoked Token,
Polling Error Codes and Upstream Token Verification step 4.

Call Chaining names only `expired`, for a pending downstream request whose
upstream token expires. Presenting a Revoked Token says a pending request
"whose upstream token or agent's agent token is revoked while it waits,
terminates with `revoked`", with `detail` saying which. Both Person Server and
Access Server verify a waiting chained request's upstream token again and
answer `403 revoked` on their pending URLs. At the Person Server, step 4 makes
a revoked Agent token or binding of the calling Agent refuse the chain as the
token itself does, so the `detail` is "The upstream token of this chained
request, or its calling agent's agent token or binding, was revoked." At the
Access Server it is "The upstream token of this chained request was revoked."
and, for a withdrawn resource token, "The resource token this request was
started for was revoked." A new request naming the revoked token is still
answered `revoked_upstream_token`. The Person Server's wait ends no later than
the upstream token, but that bound never binds earlier than the presented
token's, which already expires no later than the upstream token.

**Evidence:** `integration/call_chaining_hops_test.go:TestChainedExchangeWaitsForTheAccessServerUntilItsUpstreamIsRevoked`
and `accessserver/upstream_external_test.go:TestAccessServerEndsAChainedWaitWhenItsUpstreamOrResourceTokenIsRevoked`.

## Revocation follows the tokens obtained with a person token

**Source:** Protocol `70d6737`, Revocation Cascade (the person-token and
Agent-token items, and Records), Who Revokes What and Revocation Response.

The chain clause reaches person tokens issued with the revoked person token,
"or an auth token issued against it", as `upstream_token`. A Person Server
records each auth token it issues, and each it delivers from an Access Server,
with the token it was issued against, and the walk follows those records from
the person token through step-ups to every auth token obtained with it. Each
enters the Person Server's own revocation store, so it is refused as a
presented or upstream token. One the Person Server issued itself is revoked at
its Resource, as an Access Server does with its own; one an Access Server
issued is left to that server, which revokes it when the person token reaches
it. The person tokens chained from any of them are revoked the same way, at
their Resources and Access Servers, hop by hop.

The chain clause sits under "PS revokes a person token it issued". An Agent
Provider's revocation of an Agent token also revokes person tokens, so the
cascade applies the clause there too. The cascade is by Agent identity, and
the revocation names only an Agent token's `jti`. The Person Server finds the
Agent from the person-token records that name that Agent token, then revokes
every unexpired person token issued to that Agent, each at its Resource and
once at every Access Server it was presented to. It holds the Agent Provider's
request while the cascade runs, answers `202` with a pending URL if a
recipient has not reached a terminal outcome, and answers the empty `200` once
each has. Repeating the revocation records nothing new and continues the
cascade.

**Evidence:** `integration/call_chaining_hops_test.go:TestFourPartyCallChainRepeatsOnAccessServerAuthTokens`,
`integration/call_chaining_hops_test.go:TestAgentTokenRevocationReachesEachPersonTokenAndItsChain`
and `accessserver/upstream_external_test.go:TestAccessServerRevokesStepUpsWithTheirPersonToken`.

## A deferred Agent request is polled with the credential that started it

**Source:** AAuth Core `70d6737`, Deferred Responses (Pending Response,
Polling with GET, Deferred Response State Machine), Authorization Endpoint,
Mission Update, Mission Completion, Audit Response, and Agent Response to
Clarification.

"Agents MUST handle `202` responses regardless of the nature of the original
request." The section says the Agent switches to `GET` on the `Location` URL
and never resends the body, but not which credential signs the poll
(`AAG-F133`). Every Agent request that the library sends and a server may
defer returns an `agent.Pending`, whose polls, clarification answers and
cancellations are signed with the credential that signed the original
request: the Agent token at a Person Server or Agent Provider, the person
token at a Resource's authorization endpoint, the subscribe token at an event
endpoint, and the durable `hwk` key or the `jkt-jwt` delegation for bootstrap.
That is the identity a server already bound the pending request to.

"The agent MUST respect `Retry-After` values": `Poll` refuses to send before
the interval elapsed, measured on the Agent's clock from the answer that set
it. The older per-flow poll methods leave scheduling to the caller, as their
documentation says; their intervals are computed the same way. A `429` adds
five seconds, or takes its own `Retry-After` when longer; a `503` takes its
`Retry-After` or five seconds. `Prefer: wait` is sent on a poll only when the
caller asks, rounded up to whole seconds; the requests that start these flows
send none, as the Rust implementation's do. An unrecognized `status` counts as pending, and
`interacting` once seen is kept. Approval, interaction and clarification are
the requirements an Agent can act on here; any other is refused as
unsupported. A `402` is not treated as pending on these requests, because none
of them has a payment branch; it is a terminal failure.

A non-`202` answer ends the request for every copy of the `Pending`, as does a
`202` with a malformed body or a different `Location`, because the server can
no longer be followed. A successful `DELETE` ends it too. A transport failure
does not, because the server may or may not have answered; the next poll
either delivers the result or reads `410`. A clarification answer is accepted
on any `2xx` and the Agent polls for the outcome (`AAG-F094`). A mission
completion the person does not accept has no terminal answer in the draft
(`AAG-F134`); the Agent reports whatever terminal error the Person Server
sends and the mission stays active. A `Pending` holds its signing credential
and cannot be snapshotted; the pending exchange and mission proposal types
keep their snapshots, except that an R3 or Budget pending exchange cannot be
snapshotted, because its restoration would lose the companion context.

**Evidence:** `agent/deferred_test.go`, `agent/r3_test.go`,
`agent/mission_proposal_deferred_test.go` and
`agent/mission_lifecycle_test.go`.

## The library's own interaction pages keep the visit's callback

**Source:** AAuth Core `70d6737`, User Interaction and Interaction Callback
Errors.

"When present, the server redirects the user's browser to the `callback` URL
after the user completes the action", and "When an interaction cannot be
completed, the server MUST redirect to the `callback` URL with an `error`
query parameter." The Person Server's consent and person-token pages and a
Resource-managed session page therefore retain the callback with the pending
request when the visit's code is consumed. The code presentation carries it to
the store, so the callback is recorded in the same transition that consumes
the code, and a visit whose code does not correlate retains nothing. The
library checks the callback's shape again, accepting a loopback callback,
because whether one is allowed depends on the Agent Provider's metadata, which
the host checked when it parsed the visit.

After its own decision the host redirects with the interaction's
`CompletionURL` or `FailureURL`, which need no store read. For a request that
ended otherwise, such as by expiring, `AuthorizationCallbackURL`,
`PersonTokenCallbackURL` and `SessionCallbackURL` map the retained state:
approval to the bare callback, denial to `access_denied`, abandonment to
`user_abandoned`, expiry to `interaction_expired`, and failure, cancellation
and a request already gone to `server_error`. The stores keep no outcome once
the Agent has collected it, so a request gone after an approval also reads as
`server_error`; the host avoids this by redirecting right after its decision.
The person-token and session stores do not materialize expiry when they load a
record, so a record past its deadline reads as expired there.

**Evidence:** `integration/deferred_ps_authorization_test.go`,
`integration/person_token_interaction_test.go`,
`integration/resource_managed_session_test.go`,
`personserver/authorization_interaction_test.go`, `resource/session_test.go`,
and the storetests `RunDeferredAuthorization`, `RunDeferredToken` and
`resource/storetest` (deferred session).

## A supervised Agent's acts go to its supervisor and nowhere else

**Source:** AAuth Supervision, `What This Document Defines`, `Supervision
Decisions` and `Why the PS Never Decides`.

A Person Server with a supervision server configured for an Agent makes no
supervision decision of its own for that Agent. For an Agent that
`SupervisionConfig.Route` routes, the Person Server calls none of `Authorize`,
`Consent`, `CallChaining` policies, `Missions.Approve`, `DeferProposal`,
`AcceptUpdate`, `ConfirmPersonAcceptedCompletion`, `Permission.Policy`, the
interaction selectors or the four-party Budget `Ceiling`. `BindPerson` still
runs after an allow, because it resolves the person's directed identity for a
Resource, which is the Person Server's job; it must not apply consent. An
allow without narrowing grants a Resource's Budget offer as offered: the
supervisor saw it in the resource token. An R3 authorization and a
Resource-initiated interaction are refused with `SupervisionCompositionError`
(500 `server_error`) rather than decided locally, because this implementation
cannot put them to a supervisor.

**Evidence:** every test in `integration/supervision_test.go` fails if a
Person Server policy decides for a routed Agent.

## The person decides through the supervised request's own pending URL

**Source:** AAuth Supervision, `Supervision Decisions` (`ask`), `Unavailable
Supervisor`; Core, `Deferred Responses`.

After an `ask`, and when the supervisor is unavailable, the Person Server
answers the Agent `202` with `requirement=approval` at `/pending/{id}`, a path
that does not name supervision because nothing the Agent sees changes with who
supervises, and keeps the request for the person. It reaches
the person through its own channel: `PendingSupervision` and
`ReviewSupervision` give the host what to show, and `ResolveSupervision`
records the authenticated person's answer, its reach and an optional reason.
It does not hand the Agent an interaction URL, because the draft leaves the
channel to the Person Server and no other Agent-facing requirement is needed.
A supervisor that defers is polled by the host with `AdvanceSupervision`, as
an Access Server continuation is; the Agent's polls only observe retained
state.

**Evidence:** `TestSupervisorDecidesForSupervisedAgentAndAsksOnlyForExceptions`,
`TestUnavailableSupervisorLeavesTheDecisionToThePerson`.

## A supervised request allowed later is served again as it was made

**Source:** AAuth Supervision, `Deferred Decisions`; Core, `Deferred
Responses`.

A decision that arrives after the Agent received `202` must still issue what
the Agent asked for. The Person Server keeps the Agent's exact signed request
and, once the request is allowed, serves it again through the same handler:
the HTTP signature and the request's tokens are verified as at the instant
they were first verified, and every lifetime, revocation, binding and mission
check runs again at the time of issuance. Tokens are issued at that time. The
response the Agent would have received is kept for its next poll. A deny ends
the request with the polling error `denied`, except a permission request,
whose answer is the denial with the supervisor's reason. A four-party request
that already waited for its supervisor cannot then wait for the Access Server:
the Agent polls one pending URL, so that combination ends with
`DeferredCompositionError` reason `supervision`.

**Evidence:** `TestUnavailableSupervisorLeavesTheDecisionToThePerson`,
`TestSupervisorClarifiesThroughThePersonServer`.

## An unreachable supervisor is not retried within the act

**Source:** AAuth Supervision, `Delivery` and `Unavailable Supervisor`.

`Delivery` says the Person Server retries a request until it receives a
terminal response, and `Unavailable Supervisor` says a connection failure
makes the supervisor unavailable for the decision, which then goes to the
person. The Person Server does not retry a supervision request it could not
deliver: it puts the act to the person at once and logs that the supervisor
was not consulted. Events and mission reports are queued in order per
`(sub, supervisor)` and delivered before the next request to that supervisor,
after each host step, and whenever the host calls `DeliverSupervisionEvents`;
delivery stops at the first one not accepted, so none is delivered out of
order. An event the supervisor answers `invalid_request` is dropped, since the
draft says retrying cannot help and keeping it would hold back every later
one.

**Evidence:** `TestUnavailableSupervisorLeavesTheDecisionToThePerson`.

## A deferral that outlives the Agent's wait ends the request

**Source:** AAuth Supervision, `Deferred Decisions`.

The Person Server polls a deferring supervisor "until the agent's own pending
request at the PS would expire", and then treats it as unavailable, which
would put the act to the person when no time is left. The Person Server ends
the request with `408 expired` at that point. The person was never asked, so
no `decision.resolved` is sent. A request that was with the person when it
expired, or that the Agent cancelled, is reported `abandoned`. The pending
request lasts `SupervisionConfig.PendingLifetime`, ten minutes by default, and
never longer than the tokens it depends on.

**Evidence:** `TestUnavailableSupervisorLeavesTheDecisionToThePerson`.

## A signed decision is verified for coverage and signer, not age

**Source:** AAuth Supervision, `Signed Decisions` and `Idempotence`.

The Person Server requires the components the draft makes MUST: `@status`,
`content-type` and `content-digest`, and checks every covered `req` component
against its own request. It sends `Accept-Signature` on every supervision
request and poll, naming the request's `content-digest`, `@authority` and
`@path`; the supervision server in this repository covers what it names that
it can produce, but the Person Server does not refuse a decision without
them, since they are SHOULD. A repeated request is answered with the same
signed response, and a decision reached at a pending URL may be signed when
it is polled, so a signature's `created` time has no lower bound; one more
than sixty seconds ahead of the clock is refused. `supervision.VerifyExchange`
applies the same rule at the recorded receipt time.

**Evidence:** `TestSignedSupervisorDecisionsAreAVerifiableRecord`,
`supervisionserver/server_test.go`.

## A four-party narrowing is enforced when the token is delivered

**Source:** AAuth Supervision, `Auth Token`.

An allow may narrow `scope` and bound `exp`, and "how a PS narrows a federated
request is the AS's business". The PS-to-AS request in this implementation
carries no scope, so the Person Server checks the Access Server's token on
delivery and refuses one broader than the supervisor allowed with
`403 access_denied`.

**Evidence:** `TestFourPartySupervisorDecidesAndThePersonServerEnforcesIt`.

## Which supervisor origins a Person Server contacts is egress policy

**Source:** AAuth Supervision, `Supervisor Metadata` and `Egress`.

Endpoint URLs "MUST be on the `issuer`'s origin or one the SS controls". A
Person Server cannot establish from the document which other origins an SS
controls, so `supervision.Metadata.Validate` requires HTTPS endpoints and
leaves origins to `SupervisionConfig.Admit`, which already decides every
destination. A pending URL must still be on the origin that answered with it,
as Core requires. The supervision server in this repository publishes its
endpoints on its own origin.

**Evidence:** `TestMetadataNamesHTTPSEndpoints`.

## Replay copies what the Person Server reported

**Source:** AAuth Supervision, `Replay and Recovery`.

Replay gives a new supervisor "the mission's log entries in order, each as the
event or report it would have been". The Person Server keeps every event and
report it queued for an Agent and replays from that history, keeping each
one's `id` and rewriting only `sub`: `agent.bound`, then for each mission not
reported terminated its `approved` report and events, and the issued events
of tokens still outstanding. While supervision is configured, the Person
Server also records the approvals, terminations and issued tokens of Agents
no supervisor decides for, under an `sdi` it mints, so the first time such an
Agent is routed its active state is replayed the same way. An accepted mission
update has no event or report form, so it is not replayed. A mission approved
before supervision was configured has no record; after `unknown_mission`, to
a request or to an event, the Person Server builds its `approved` report from
the mission store under a fresh `sdi` and sends it before trying again.
`agent.bound` is sent the first time an Agent is routed, since this Person
Server binds an Agent implicitly rather than at one approval. An Agent token
an Agent Provider revokes is reported as `revocation.received` to the
supervisor that decides for the Agent that presented it.

**Evidence:** `TestAgentsOfOnePersonGoToTheirOwnSupervisors`,
`TestUnknownMissionIsReplayedBeforeTheSupervisorDecides`.

## A mission's end is reported once, when the Person Server finds it

**Source:** AAuth Supervision, `Terminated`; Core, `Mission Management`.

Missions expire lazily in this implementation: the store materializes expiry
when it loads one. The Person Server reports `terminated` to the Agent's last
deciding supervisor when it finds a mission terminated for any reason, and
after a completion it allowed, under the completion's `sdi`. It checks its
record first, so a mission found ended more than once is reported once.

**Evidence:** `TestSupervisorDecidesForSupervisedAgentAndAsksOnlyForExceptions`.

## Agent-asserted content reaches a supervisor in the members the Agent wrote

**Source:** Core, `Consent Presentation`.

Where the Supervisor is a supervision server, the Person Server must convey
the distinction between resource-asserted and agent-asserted content. A
supervision request carries agent-asserted content only in the members the
Agent authored (`description`, `summary`, `justification`, `action`,
`parameters`) and resource-asserted content only in the forwarded resource
token, so the distinction is carried by member, and `SupervisionReview`
keeps it for the host's own presentation.

**Evidence:** `supervision.Request`, `TestRequestsRoundTripThroughTheirEndpoints`.

## Supervised clarification allows five rounds and no replacement request

**Source:** AAuth Supervision, `Clarification`; Core, `Clarification Limits`
and `Agent Response to Clarification`.

The Person Server enforces one limit of five rounds per supervised request,
counting the supervisor's questions and the person's own, as the draft
recommends. Beyond it the supervisor is treated as unavailable and the person
decides. Core carries no round identifier in an answer (AAG-F095), so a
delayed repeat of an earlier answer is taken as the answer to the question
open when it arrives. The Person Server refuses the Agent's `updated_request`
with `400`: it completes the Agent's retained signed request, whose tokens a
replacement cannot change, so a different request is made afresh. The
supervision server accepts an `updated_request` from a Person Server that
relays one, and decides again on its tokens.

**Evidence:** `TestSupervisorClarifiesThroughThePersonServer`.

## A supervision server repeats each terminal answer byte for byte

**Source:** AAuth Supervision, `Idempotence`; Core, `Deferred Response State
Machine`.

A repeated request under an answered `sdi` gets "the same signed response",
and Core makes a pending URL gone after its terminal response. The
supervision server keeps every terminal response for an `sdi` and repeats it
exactly for the same request: the original POST, or a poll of its pending URL.
If the first answer went out on a poll and the POST is repeated later, it
signs that decision once as a response to the POST and repeats that. Polls of
a decided pending URL keep returning the decision rather than `410`, because
the Person Server may not have received the first. A repeat under an `sdi`
whose request differs is `invalid_request`.

**Evidence:** `supervisionserver/server_test.go`.

## A supervision server sheds load with `rate_limited` through a host hook

**Source:** Supervision `70d6737`, Errors (line 636) and Unavailable
Supervisor (line 609).

The draft gives the supervision server `429 rate_limited`, with `Retry-After`
REQUIRED, for "will not take more from this PS for now", and leaves when to
the server. `Config.RateLimit` is that decision. The host is asked once a
connect, mission, decision or event request's signature verifies, before its
body is decoded, and a wait answers `rate_limited` with that wait as
`Retry-After`. Nothing is recorded, so the Person Server's later resend is
handled as a first request. The wait is whole seconds from one second to an
hour, the bound the server applies to a deferral's `Retry-After`; anything
else is a host defect, answered `server_error`. Polls, clarification answers
and cancellations of a pending URL are not limited by the hook: polling uses
the Core polling codes, in which `429` is `slow_down`. aauth-rust exports a
`rate_limited` response for its host to send; the two answer the same on the
wire.

**Evidence:** `supervisionserver/server_test.go:TestRateLimitAnswersRateLimitedWithRetryAfter`.
