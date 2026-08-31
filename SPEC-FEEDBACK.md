# AAuth specification feedback

This register separates feedback already delivered to the editors from current
implementation questions against the exact manifest in
[SPECIFICATIONS.md](SPECIFICATIONS.md). It is not a scorecard. Source text and
editor answers remain authoritative.

## Status vocabulary

- **submitted / incorporated** — delivered feedback appears in the current
  editor source.
- **submitted / answered** — an editor answered directly, although a public
  thread may not exist.
- **submitted / still open** — delivered feedback remains unresolved in the
  current source.
- **ready / unsubmitted** — current source and executable evidence support the
  question, but it has not been sent.
- **evidence pending** — the source suggests a question, but the repository
  does not yet contain the executable evidence needed before submission.
- **withdrawn** — later source or implementation evidence resolved the concern.

## Source review boundary

The source family is synchronized as one manifest, but review depth follows
executing behavior. “Mapped” means the source and intended package boundary
were read; it is not an implementation or conformance claim.

| Source | Review state | Feedback boundary |
| --- | --- | --- |
| AAuth Core | implementation-reviewed for current paths | Submitted history and executable current questions appear below; unimplemented Core areas remain evidence-pending |
| HTTP Signature Keys | implementation-reviewed for the schemes and proof profile currently used | Current parser, proof, discovery, and negotiation questions appear below; unused schemes are not claimed reviewed through execution |
| R3 | implementation-reviewed for immediate four-party MCP direct-grant and per-call paths | Executing Agent, Resource, PS, and AS evidence supports `AAG-F005`, `AAG-F014`, `AAG-F014a`, `AAG-F015`, `AAG-F069`, and `AAG-F076`; example vectors, annotations, other vocabularies, and independent interop remain evidence-pending |
| Events | source-synchronized and architecture-mapped | No implementation-backed question yet |
| Bootstrap | implementation-reviewed for the explicit Ed25519 two-key profile | `AAG-F071` through `AAG-F075` record the source and replay questions exposed by the executing enrollment and refresh path |
| Budgets | source-synchronized through the current `a99d353` revision and architecture-mapped | No implementation-backed question yet |
| Interoperability demo profile | source-reviewed against current internal paths | `AAG-F001` remains evidence-pending; no independent implementation has been exercised |

## Submitted history

### AAG-H001 — Draft-05 through draft-08 implementation feedback

**Status:** submitted / incorporated

Earlier implementation work supplied feedback on mission references and
hashes, agent keying material, requirement parameters, capability extensions,
same-`kid` key refresh, egress admission, auth-token verification, approval
authentication, proof freshness, interaction codes, callback errors, and
call-chaining identity. Current Core revisions 6 through 9 incorporate those
dispositions and acknowledge Joshua Gay. Do not re-file them as new findings.

### AAG-H002 — Callback authority and issuer-role discovery

**Status:** submitted / answered

The editors answered that an interaction callback is a user-experience return,
not authority to approve or deny, and that auth-token `dwk` selects issuer-role
metadata while issuer trust remains a separate verifier decision. No durable
public discussion URL was retained.

### AAG-H003 — Recommended `justification` sections

**Status:** submitted / still open

Earlier feedback proposed a small Markdown structure for `justification`. The
current PS Token Endpoint still contains `TODO: Define recommended sections`.
Any follow-up should cite the earlier delivery rather than present it as new.

## Earlier unsubmitted candidates

This compact index preserves the prior register without carrying obsolete
implementation journals into the library. Detailed current questions appear
below where evidence is ready.

| ID | Question | Current status |
| --- | --- | --- |
| AAG-F001 | Interoperability Surface 3 says Resource metadata contains keys, while Core uses its `jwks_uri` | evidence pending |
| AAG-F002 | The AS request example uses a `jwks_uri` Signature-Key parameter not defined by that scheme | evidence pending |
| AAG-F003 | Audit delivery has no stable retry identity after a lost `201` | evidence pending |
| AAG-F004 | General deferred endpoints do not define recovery of a lost terminal response | ready below with Resource-session and PS-consent evidence |
| AAG-F005 | R3 same-URI replacement can make an old content hash unverifiable | immutable Resource store, conflict evidence, and complete direct-grant journey implemented |
| AAG-F006 | R3 example hashes are not executable SHA-256 vectors | evidence pending until a source-example vector test is added |
| AAG-F007 | Mission completion still appears in the introductory interaction list after moving endpoints | evidence pending |
| AAG-F008 | Clarification requires an `agent` claim removed from resource tokens | ready below |
| AAG-F009 | Person-token policy denial has no registered error | ready below |
| AAG-F010 | Four-party person and tenant context use the wrong issuer namespace | ready below |
| AAG-F011 | Closed issues 88 and 89 are not reflected in the person-token endpoint text | ready below |
| AAG-F012 | A lost initial deferred `202` has no stable recovery identity | evidence pending |
| AAG-F013 | Restored deferred state can lose the verified request authority | held-store boundary implemented; generic deferred rule remains open |
| AAG-F014 | R3 protected challenges do not define who selects the exact operation | exact-request Resource mapping covers direct and per-call enforcement |
| AAG-F014a | An AS cannot distinguish requested operations from a broader R3 document carried only by URI and digest | exact-request document construction and independent AS fetch/policy evidence implemented |
| AAG-F015 | Per-call auth tokens do not identify the resource-token record that supplies `presented_jti` | implementation bridge evidenced: exact class/proposal token lineage at the Resource plus bounded original Person-token retention at the PS; editor clarification remains useful |
| AAG-F016 | The mandatory signature set does not bind the query | ready below |
| AAG-F033 | Three-party deferral does not define whether the original resource-token expiry is terminal | ready below with PS-consent evidence |
| AAG-F058 | Events uses a subscription identifier as the Agent's event deduplication key | exact-delivery interpretation recorded; evidence pending until Events implementation |
| AAG-F059 | Mission proposal policy denial has no registered error | ready below with immediate mission evidence |
| AAG-F060 | Unknown mission references at the Person Token Endpoint have no assigned error | ready below with ownership-safe refusal evidence |
| AAG-F061 | A Resource and Access Server cannot directly enforce mission expiry without receiving mission content | implementation bridges recorded; ready below |
| AAG-F062 | `approved_at` alone does not make a mission digest globally unique | ready below with immediate mission evidence |
| AAG-F063 | The exact byte object identified by a mission-update digest is underspecified | ready below with exact-body implementation evidence |
| AAG-F064 | Immediate mission-action refusal is undefined, including its error if allowed | ready below with typed provisional refusal evidence |
| AAG-F065 | Mission update and completion uncertain success have no recovery identity | ready below with one-shot transport evidence; no recovery claim |
| AAG-F066 | Core contradicts itself on who may accept a mission update | ready below; implementation follows the update-specific rule |
| AAG-F067 | Mission termination does not define the fate of outstanding credentials | ready below with explicit implementation boundary |
| AAG-F068 | Deferred `Retry-After` is both required and assigned an absent-header default | ready below; implementation honors the receiver fallback |
| AAG-F069 | Immediate Auth-token issuance has no exact-result recovery identity | ready below with retained-but-unreplayable issuance evidence |
| AAG-F070 | Immediate PS and AS policy denial has no registered token-endpoint error | ready below with denial-versus-failure evidence |
| AAG-F071 | The `jkt-jwt` example omits the required `alg` in both JWKs | ready below |
| AAG-F072 | Bootstrap names `jti` replay protection without defining replay | ready below |
| AAG-F073 | The delegated software key is described as enclave-determined | ready below |
| AAG-F074 | Stable Agent `sub` does not distinguish the two key rotations | ready below |
| AAG-F075 | Bootstrap examples use AP-internal endpoints after removing discovery | ready below |
| AAG-F076 | R3 rationale says AS-only while the normative fetch rule requires both PS and AS | ready below with dual-role fetch evidence |

## Current unsubmitted questions

The questions below come from the pinned editor sources in
[SPECIFICATIONS.md](SPECIFICATIONS.md). Their placement notes avoid duplicating
existing discussions.

### AAG-F004 — Deferred terminal delivery has no recovery path

**Source:** AAuth Core, `Pending URL Security` and `AAuth-Access`.

After returning one terminal response, a pending URL must return `410 Gone`.
If a terminal response carrying `AAuth-Access` or an auth token is lost, the
Agent cannot recover that credential and must not poll again. The source
defines neither an idempotency key for restarting the interaction nor a replay
window for the terminal result.

The Resource-managed and deferred PS-consent integration tests follow the
specified one-terminal-then-`410` behavior. They therefore demonstrate the
loss window rather than solving it.

**Question:** Should a pending URL replay its exact terminal response for a
bounded period, or should Core define another stable recovery key for a lost
terminal `AAuth-Access` response?

**Placement:** Open a Core deferred-response issue and cross-link the held
delivery replay exception.

### AAG-F033 — Three-party deferral does not define the resource-token expiry boundary

**Source:** AAuth Core, `Resource Token Structure`, `PS Token Endpoint`, and
`Deferred Responses`.

Core tells an Agent to obtain a fresh resource token when delayed interaction
prevents the PS from presenting it to an AS before expiry. It does not say
whether a three-party PS, which does not present the token again, may approve a
request after the original resource token expires.

The implementation caps the three-party pending deadline at the original
resource-token expiry. This is safe and executable, but another implementation
could retain the verified request and permit a later decision.

**Question:** Must a three-party pending authorization expire with its original
resource token, or may the PS retain the verified request and decide it later?

**Placement:** Open a focused Core PS Token Endpoint question.

### AAG-F026 — Global body signature components conflict with bodyless polls

**Source:** AAuth Core, `Resource Metadata` and `Polling with GET`.

Resource metadata says every listed `additional_signature_components` member
must be covered on requests to that Resource. The metadata example lists
`content-type` and `content-digest`. Polling then requires a bodyless `GET` and
forbids resending the original body. The text does not say what content those
two fields describe on that poll.

The implementation covers the RFC 9530 digest of empty content and requires
the caller to supply fresh values for other advertised fields.

**Question:** Are body-specific metadata components inapplicable to bodyless
polls, or should a poll carry and sign an explicit zero-length representation?
If the former, where is the exception declared so both peers choose the same
signature base?

**Placement:** Open a Core issue and cross-link Signature-Key covered-component
processing.

### AAG-F027 — Resource sessions do not define Agent identity across key rotation

**Source:** AAuth Core, `AAuth-Access` and `Agent Token Verification`.

The session is a relationship with “this agent” and each use requires a valid
Agent signature. The source does not say whether the Resource binds the Agent
identifier, the current `cnf` key, or both, nor what happens when the AP issues
the same Agent a new proof key.

The implementation binds the stable AP/Agent/parent identity and verifies the
current AP-issued token and proof on every request. This permits key rotation
without allowing another Agent to use the session.

**Question:** Should Core define that stable binding, require a key-bound
session, or make the choice an explicit Resource policy advertised to Agents?

**Placement:** Open a Core `AAuth-Access` issue.

### AAG-F028 — Opaque `AAuth-Access` conflicts with the all-JWT statement

**Source:** AAuth Core, `Overview`, `AAuth-Access`, and `Security
Considerations`.

The overview says all AAuth tokens are JWTs and the security text describes
proof through a token `cnf` claim. `AAuth-Access` instead defines an opaque
`token68`, permits wrapping an existing credential, and defines no JWT claims.
Its proof binding is the Agent signature covering `Authorization`.

**Question:** Should the overview and proof-of-possession text explicitly
exclude Resource-owned session tokens?

**Placement:** Open a focused editorial Core issue.

### AAG-F029 — Resource interaction decisions are described as PS records

**Source:** AAuth Core, `Interaction Requirement` and `Resource-Managed
Authorization`.

The generic interaction rules say approve or deny must be recorded through an
authenticated channel “at the PS.” A two-party Resource-managed interaction
has no PS; the Resource runs its own login or consent interface.

**Question:** Should the rule name the server that issued the interaction, with
the PS and Resource as explicit examples?

**Placement:** Add to a Core interaction issue or open an editorial issue.

### AAG-F030 — Resource-managed interaction is assigned both `202` and `401`

**Source:** AAuth Core, `Resource-Managed Authorization`, `Requirement
Responses`, `Resource Metadata`, and `Incremental Adoption`.

The dedicated flow and requirement registry use `202 Accepted` for
`requirement=interaction`. Resource metadata and adoption prose say a Resource
without an authorization endpoint issues interaction requirements through
`401` responses.

**Question:** Which status is normative for a direct Resource interaction, and
should the other passages be corrected?

**Placement:** Open one Core Resource-managed-flow issue.

### AAG-F031 — The Resource authorization endpoint is not a PS-free path

**Source:** AAuth Core, `Authorization Endpoint Request` and
`Response without Resource Token`.

The latter section is described as Resource-managed authorization, but every
authorization-endpoint request must carry a PS-issued person token. A PS-less
Agent can use the direct Resource challenge path, not this endpoint.

**Question:** Should this branch be described as Resource-local authorization
after PS identity rather than as a two-party flow, or is another no-person-token
request shape intended?

**Placement:** Add to the same Resource-managed-flow issue as AAG-F030.

### AAG-F032 — Resource sessions have no standardized lifecycle errors

**Source:** AAuth Core, `AAuth-Access`, `Token Revocation`, and `Error
Responses`.

Session tokens have no defined lifetime, `iss`, or `jti`, so the token
revocation endpoint does not identify them. Core also assigns no status,
challenge, or problem code for an unknown, expired, or revoked session.

**Question:** Is the complete session lifecycle intentionally Resource-local?
If so, should Core state the minimum Agent behavior for an invalid session; if
not, which identifier and error shape apply?

**Placement:** Open a Core `AAuth-Access` lifecycle issue.

### AAG-F008 — Updated clarification requests refer to a removed `agent` claim

**Source:** AAuth Core, `Updated Request` and `Resource Token Structure`.

`Updated Request` requires the replacement resource token to retain the same
`iss`, `agent`, and `agent_jkt`. `Resource Token Structure` says that a resource
token carries no agent identifier, so a conforming token has no `agent` claim
to compare. A literal absent-to-absent comparison cannot detect substitution.

**Question:** Which surviving claims must remain stable when an agent replaces a
resource token during clarification? At minimum, the text needs to remove
`agent` and state the intended person, resource, key, and mission bindings.

**Placement:** Add this instance to
[AAuth issue 104](https://github.com/dickhardt/AAuth/issues/104), which collects
remaining agent-token references after the person-token change.

### AAG-F011 — The person-token endpoint omits eight resolved request parameters

**Source:** AAuth Core, `Person Token Endpoint` and `Agent Token Request`.

The person-token endpoint lists four parameters. The auth-token endpoint also
accepts eight parameters needed by the same person-selection and interaction
flow: `justification`, `login_hint`, `tenant`, `domain_hint`, `prompt`,
`platform`, `device`, and `capabilities`.

The authors' recorded resolution on
[issue 88](https://github.com/dickhardt/AAuth/issues/88) and
[issue 89](https://github.com/dickhardt/AAuth/issues/89) says that the
person-token endpoint accepts those eight parameters. The pinned editor source
does not yet contain that edit.

**Question:** Should the editor source now copy the eight parameters and their
semantics into `Person Token Endpoint`, including the rule that a PS should not
return an interaction requirement when `capabilities` excludes interaction?

**Placement:** Comment on issue 88 and cross-link issue 89. Both issues are
closed with the same recorded resolution, so a new issue would duplicate it.

### AAG-F009 — Person-token policy denial has no registered error

**Source:** AAuth Core, `Person Token Endpoint` and `Token Endpoint Error
Codes`.

The endpoint can receive a structurally valid request and still deny issuance
under person-server policy. The registry names invalid credentials,
`user_unreachable`, and internal failure, but not this result.

The implementation provisionally returns HTTP `403` with
`person_token_denied`. Reusing `user_unreachable` would say that no contact
channel exists; reusing `invalid_request` would say that valid input is
malformed.

**Question:** Should Core register a terminal policy-denial error, or assign
this case to an existing error with clarified semantics?

**Placement:** Open a new AAuth issue. No existing issue records this error-code
gap.

### AAG-F059 — Mission proposal policy denial has no registered error

**Source:** AAuth Core, `Mission Creation`, `Mission Approval`, and `Mission
Endpoint Errors`.

A valid proposal may be denied by Person Server policy, but the endpoint error
table names only malformed requests, unknown ownership, and terminated
missions. The implementation provisionally returns `403 mission_denied` rather
than describe a valid proposal as malformed.

**Question:** Which registered error and status should carry a terminal mission
proposal denial?

**Placement:** Combine with AAG-F009 if Core adopts one policy-denial code across
Person Server endpoints; otherwise open a focused mission-endpoint issue.

### AAG-F060 — The Person Token Endpoint has no error for an unknown mission

**Source:** AAuth Core, `Person Token Endpoint`, `Mission Endpoint Errors`, and
`Token Endpoint Error Codes`.

The Person Token Endpoint must reject a mission that does not exist or belongs
to another Agent. `mission_not_found` is defined only for a mission's own URL,
while the token error registry assigns no equivalent result. The implementation
uses the same `400 invalid_request` body for absent and wrong-owner references.

**Question:** Should `mission_not_found` apply at the Person Token Endpoint, or
should the token error registry add an ownership-safe mission-reference error?

**Placement:** Add to the mission endpoint/error registry discussion.

### AAG-F061 — A Resource and Access Server cannot read the mission expiry they must enforce

**Source:** AAuth Core, `Mission Approval`, `Resource Token Structure`, and
`Why Mission Content Stays at the PS`.

Core requires both a mission-bound Resource token and a mission-bound Auth
token to expire no later than the mission, but deliberately sends the Resource
and AS only `mission_s256`, not the blob or `expires_at`. The implementation
caps the Resource token at the verified Person token's `exp`. Its Access Server
caps the Auth token at the verified Resource token's `exp`. The PS, which owns
the mission, separately verifies a returned AS token against the retained
mission expiry before release.

**Question:** Should Core state explicitly that non-PS issuers inherit the
preceding mission-bound token's authenticated expiry ceiling, or expose another
authenticated mission-expiry value?

**Placement:** Open a focused Core mission-lifetime clarification.

### AAG-F062 — `approved_at` does not ensure a globally unique mission digest

**Source:** AAuth Core, `Mission Approval`.

Core says that `approved_at` ensures `s256` is globally unique. Two approvals
with the same approver, Agent, timestamp, description, and optional members
have identical bytes and therefore the same digest. This can occur with a
coarse or deterministic clock, and the wire shape has no nonce or distinct
mission identifier to separate them.

The implementation does not add a private mission member. Its store rejects
the second exact identifier as a conflict rather than silently treating a new
approval as the old mission.

**Question:** Should the blob include a required unique value, or should Core
drop the global-uniqueness claim and define identical approvals as the same
mission?

**Placement:** Open a focused Core mission-identity clarification after
checking the current issue tracker for an existing uniqueness discussion.

### AAG-F063 — Mission update does not define the exact hashed artifact

**Source:** AAuth Core, `Mission Log` and `Mission Update`.

An accepted update returns the digest of the update bytes “as the PS persists
them,” but Core does not say whether those bytes are the authenticated request,
a canonical re-encoding, or a person-edited result. It also requires auditors
to read accepted updates without defining the retrieval representation that
supplies those bytes.

The implementation persists and hashes the exact authenticated request body.
This keeps unknown additive members and gives the returned digest one
unambiguous object without inventing a canonicalization format.

**Question:** Which exact bytes does an accepted update digest identify, and
should mission inspection return those bytes plus their acceptance order?

**Placement:** Open a focused Core mission-update exactness issue after checking
for a current mission-log retrieval discussion.

### AAG-F064 — Mission update and completion denial errors are absent

**Source:** AAuth Core, `Mission Update`, `Mission Completion`, and `Mission
Endpoint Errors`.

Core defines acceptance or deferred review for an update, and acceptance or
clarification follow-up for completion. It does not say whether either action
may instead receive an immediate terminal refusal. If that outcome is allowed,
the error registry has no result for it. `invalid_request` would misdescribe
valid input, and `mission_terminated` would misdescribe a mission that remains
active.

The immediate implementation provisionally returns `403
mission_update_denied` and `403 mission_completion_denied` and leaves the
mission unchanged.

**Question:** May an update or completion request end in immediate refusal? If
so, should Core register one mission-action denial result or distinct update
and completion results, and which statuses should they use?

**Placement:** Combine with AAG-F059 if Core adopts one policy-denial family for
mission actions; otherwise open one focused endpoint-error issue.

### AAG-F065 — Mission action uncertain success has no recovery identity

**Source:** AAuth Core, `Mission Update`, `Mission Completion`, and `Deferred
Response State Machine`.

An update request has no request identifier and the endpoint defines no lookup
or replay rule. If its `200` response is lost, resending the same body may
append the same update twice. Completion has the same uncertainty after the
person has accepted: storage or response delivery can fail, while a retry may
ask the person again or encounter the already terminated mission.

The implementation performs one mission-action POST and never retries it
automatically. Its store serializes concurrent transitions, but it makes no
claim that a lost update or completion success can be recovered or safely
repeated.

**Question:** How may an Agent recover an accepted update or person-accepted
completion after an uncertain response without repeating either consequence?

**Placement:** Open a focused Core mission-action recovery issue after checking
for an existing deferred/replay discussion.

### AAG-F066 — Core contradicts itself on update acceptance authority

**Source:** AAuth Core, `Mission` and `Mission Update`.

The mission overview says all three Agent operations have one shape: the Agent
proposes and the person decides. The update section later says the PS may
accept an update on its own or defer while the person reviews it. These assign
different decision-makers to the same operation.

The implementation follows the update-specific rule: `AcceptUpdate` may apply
Person Server policy autonomously. Completion remains separate and requires a
host callback that confirms actual person acceptance.

**Question:** May the PS autonomously accept an update, or must every accepted
update represent a person decision?

**Placement:** Open a focused editorial issue for the conflicting mission
overview and update-specific rule.

### AAG-F067 — Termination does not define outstanding credential behavior

**Source:** AAuth Core, `Mission Update`, `Mission Management`, `Mission Status
Errors`, and `Why Missions Are Not a Policy Language`.

Core says updates leave all existing mission-bound tokens valid and that a
terminated mission rejects later PS requests. It does not say whether
termination revokes already-issued Person, Resource, or Auth tokens, nor define
a signal by which a Resource could learn the new state. Resources intentionally
receive only the digest and do not evaluate mission content.

This implementation closes later Person Server decisions after termination.
It does not revoke or remotely invalidate outstanding credentials; they remain
cryptographically usable until their own expiry, and a conforming Agent must
stop using them.

**Question:** Is mission termination intended only to close future PS
decisions, or must it invalidate outstanding credentials? If invalidation is
required, how does a Resource learn it without receiving private mission state?

**Placement:** Open a focused Core mission-termination propagation issue.

### AAG-F068 — `Retry-After` is required but also has an absence default

**Source:** AAuth Core, `Pending Response` and `Polling with GET`.

The pending-response header list marks `Retry-After` REQUIRED. The following
polling rule says that when it is absent the default interval is five seconds.
Both cannot describe the same receiver requirement.

The implementation accepts an absent header and applies the explicit
five-second receiver fallback. Present values still require one valid
nonnegative delay.

**Question:** Should `Retry-After` be optional with a five-second default, or
required with absence treated as a malformed deferred response?

**Placement:** Add to the deferred-response clarification discussion.

### AAG-F069 — Immediate Auth-token issuance has no exact-result recovery identity

**Source:** AAuth Core, `Resource Token Structure`, `PS Token Endpoint`, and
`Auth Token Delivery`.

The Resource token has a unique `jti`, but Core does not say that an immediate
PS exchange is idempotent for that token or define a lookup for its result. A
PS can retain an issuance and still lose the store result or client response.
Retaining only audit claims and a compact-token digest cannot reproduce the
credential, while repeating the exchange may cause the AS to issue another
valid token.

The implementation commits the mission-bound issuance record before release,
never retries internally, and exposes this recovery limit. It does not invent
an exact-result store or silently treat the Resource-token `jti` as a replay
key. The immediate R3 path strengthens the retained record to include the
exact compact token and mandatory audit facts, but reaches the same limit: a
store error withholds the token, and an explicit repeat may produce another
independently audited token.

**Question:** Should an immediate Auth-token request be idempotent for one
Resource-token identity, with bounded exact-result replay after uncertain
success, or is issuing another token on explicit retry intended?

**Placement:** Open a focused Core token-issuance recovery issue.

### AAG-F070 — Immediate policy denial has no token-endpoint error

**Source:** AAuth Core, `Token Endpoint Error Codes` and `AS Token Endpoint`.

The registry defines `server_error` for internal failure but no immediate
result for a PS consent or AS authorization policy that intentionally refuses
an otherwise valid request. `access_denied` appears in an interaction callback,
not as a registered result for these token endpoints.

The implementation provisionally returns `403 access_denied` only when a host
callback wraps an explicit denial sentinel. Other callback errors return `500
server_error`, so a policy-service outage is not mislabeled as a refusal.

**Question:** May immediate PS and AS policy refuse a valid token request, and
if so which registered error and status should represent that decision?

**Placement:** Add to the Core token-endpoint error registry discussion.

### AAG-F010 — Four-party person identity uses the access-server namespace in one step

**Source:** AAuth Core, `Auth Token Structure`, `Auth Token Verification`, and
`Resource Token Structure`.

In four-party mode, auth-token `iss` is the access server, while `ps` is the
person server whose namespace owns `sub`. `Auth Token Verification` step 7
nevertheless tells the resource to match or establish the person by
`(iss, sub)`. That changes the person's identity when the access server changes
and can merge equal directed subjects from different person servers behind one
access server.

The implementation presents `(ps, sub)` to the protected handler without
retaining its own person directory. Its test covers namespace separation:
`resource/server_test.go:TestProtectedHandlerReceivesCurrentPrincipal`.

**Question:** Should the auth-token structure and verification text define the
person key as `(ps, sub)` in every topology, while keeping `iss` solely as the
token issuer and trust anchor?

**Placement:** Open a new AAuth issue.

### AAG-F010a — Four-party tenant changes issuer namespace

**Source:** AAuth Core, `Auth Token Structure` and `Person Token Structure`.

Core says `(iss, tenant)` identifies the organization. A Person Server places
`tenant` in the person token, but a four-party auth token copies it while
changing `iss` to the Access Server. The same organization therefore appears
to change namespace during one flow.

**Question:** Should organization context be keyed by `(ps, tenant)` in
four-party tokens, while `iss` remains only the token issuer?

**Placement:** Add to the same new issue as the parallel `(ps, sub)` identity
question.

### AAG-F017 — Authorization endpoint examples leave authorization input unsigned

**Source:** AAuth Core, `Authorization Endpoint Request`, `Covered Components`,
and `Resource Metadata`.

The authorization body carries `scope`, but the endpoint example covers only
the base signature components. Resource metadata can require content type and
digest globally, but doing so also makes bodyless protected routes require
body-only components.

**Question:** Should Core require `content-type` and `content-digest` at the
authorization endpoint specifically, while keeping
`additional_signature_components` as the Resource-wide protected-request
profile?

**Placement:** Open a new AAuth issue and cross-link Signature-Key issue 7.

### AAG-F016 — The mandatory signature set does not bind a query

**Source:** AAuth Core, `Covered Components` and `Freshness and Replay`; RFC
9421, Sections 2.2.6 and 2.2.7.

Core requires `@path`, but RFC 9421 defines it without the query. Two operations
selected by different query strings can therefore share the same mandatory
signature base. The replay guidance also omits the query.

The implementation covers `@query` only when present. Its executable example
shows that changing the query invalidates the original proof:
`signaturekey/request_external_test.go:TestRequestProofCoversAnExactQueryWhenPresent`.

**Question:** Should AAuth require `@query` for query-bearing requests and add
it to replay identity, or require each query-sensitive resource to advertise it
as an additional component?

**Placement:** Open a new AAuth issue and cross-link
[Signature-Key issue 7](https://github.com/dickhardt/signature-key/issues/7),
which asks where a baseline HTTP Message Signatures profile should live.

### AAG-F018 — Missing proof fields have two error classifications

**Source:** AAuth Core, `Verification (Server)`, step 1; Signature-Key,
`invalid_signature` and the Signature Error Code Registry.

Core says that a missing `Signature`, `Signature-Input`, or `Signature-Key`
field returns `invalid_request`. Signature-Key defines `invalid_signature` as
including a missing signature and lists missing proof fields under that code.
The implementation follows the more specific AAuth Core profile for AAuth
endpoints.

**Question:** Is Core intentionally overriding Signature-Key for these missing
fields, or should the two sources use one error code?

**Placement:** Open an AAuth issue and cross-link the corresponding
Signature-Key text so both editors can disposition the profile relationship.

### AAG-F019 — `keyid` has no scheme-specific equality rule

**Source:** Signature-Key, `Relationship to Accept-Signature`.

The source requires a `keyid` in `Signature-Input` to identify the same key as
the selected `Signature-Key` member. It does not define how to compare `keyid`
with schemes that carry an inline key or a JWT rather than one explicit key ID.
The implementation therefore does not claim complete `keyid` correlation.

**Question:** Should `keyid` be forbidden when `Signature-Key` is present, or
should each scheme define the exact value that means “the same key”?

**Placement:** Open a new Signature-Key issue.

### AAG-F020 — Core and Signature-Key differ on stale JWKS after refresh failure

**Source:** AAuth Core, `JWKS Discovery and Caching`; Signature-Key, `Caching
and Performance`.

Signature-Key requires appropriate cache expiration and respecting HTTP cache
headers. Core says that when refresh fails an implementation should use an
available cached JWKS, retry with backoff, and discard the entry after at most
24 hours.

**Question:** Is Core intentionally defining a stale-on-error exception for
AAuth token verification? If so, should Signature-Key state that profile hook
or define the same bounded behavior directly?

**Placement:** Open a Signature-Key issue and cross-link the Core caching
section.

### AAG-F021 — Core appears to reuse one proof key across servers

**Source:** AAuth Core, the immediate authorization journey; Signature-Key,
`Security Considerations`.

The immediate Core journey binds the agent token to one confirmation key and
uses that key when the agent calls the Person Server, Resource, and protected
endpoint. Signature-Key says that clients must use distinct keys with distinct
servers to reduce linkability. A straightforward implementation cannot satisfy
both instructions without another key-derivation or token-rebinding step.

**Question:** Does AAuth intentionally profile or override the distinct-server
key rule for this journey? If not, where should the journey derive and bind a
server-specific proof key?

**Placement:** Open a Signature-Key issue and cross-link the immediate AAuth
journey.

### AAG-F022 — A Resource cannot independently apply the agent-token expiry rule

**Source:** AAuth Core, `Re-authorization`, `Auth Token Structure`, and `Auth
Token Verification`.

`Re-authorization` says an auth token must not outlive the agent token used to
obtain it and that a Resource must reject an auth token whose associated agent
token has expired. The auth token deliberately carries no agent identifier,
and the Resource receives neither the agent token nor its expiration during an
auth-token request. The Resource can validate only the auth token's own `exp`
and proof key.

The immediate implementation caps `exp` at issuance and rechecks that ceiling
at the Person Server and Agent. The Resource trusts the resulting auth-token
expiration because it cannot reconstruct the predecessor relation itself.

**Question:** Is issuer-side capping the intended way to satisfy this rule, or
does the Resource need another claim or lookup that binds an auth token to the
agent-token expiration?

**Placement:** Open a new AAuth issue and cross-link the removal of agent
identity from auth tokens.

### AAG-F023 — Held replay does not define auth-token sameness

**Source:** AAuth Core, `Deferred Delivery`.

The Resource must replay a held result when the agent presents “the same auth
token.” Compact JWTs with identical claims can have different signatures or
serializations, and two tokens can reuse a `jti` incorrectly. Those choices
produce different replay and theft boundaries. The general Pending URL
Security section also says every request after one terminal response must
return `410 Gone`, directly conflicting with held delivery's required replay.

The implementation binds replay to the SHA-256 digest of the exact compact
token bytes first presented at the pending URL.

**Question:** Should Core define “the same auth token” as the exact compact JWT,
the same `jti` under one issuer, or another explicit identity, and state that
held-result replay is an exception to the general terminal-then-`410` rule?

**Placement:** Open a new AAuth issue for the held-delivery section.

### AAG-F024 — Held execution has no crash-recovery rule

**Source:** AAuth Core, `Deferred Delivery`.

Core requires the Resource to execute once and replay the result, but it does
not say what to do when the Resource durably claims the invocation and stops
before retaining a result. A lease permits progress but can execute a
consequence twice; permanent unresolved state avoids duplication but can lose
an execution.

**Question:** Is held delivery intentionally at-most-once across this crash
window, or should Core define an operation-specific idempotency or recovery
contract?

**Placement:** Open a new AAuth issue for the held-delivery section.

### AAG-F025 — A held application response can itself be `202`

**Source:** AAuth Core, `Deferred Delivery` and `Deferred Responses`.

The held-delivery text says the poll returns the invocation's response. The
generic deferred rules say every `202` remains pending until a non-`202`
response. The text does not say whether an application `202` consumes the
original held record and starts a new pending URL, or keeps the original record
active.

The implementation retains and replays the application `202` only when it is a
complete, same-origin deferred response. It returns that response to the caller
without following either pending URL.

**Question:** Should Core state that a valid application `202` is the held
invocation's retained result, that the original URL remains its replay URL, and
that the application `Location` identifies a separate deferred operation?

**Placement:** Add to the held-delivery issue or open a focused deferred-state
issue if the editors prefer to separate result identity from crash recovery.

### AAG-F034 — The three-party revocation example cannot authenticate the PS as written

**Source:** AAuth Core, `Token Revocation` and `Keying Material`.

The prose says a PS calls the Resource, but the example targets `ps.example`
and uses `scheme=jwt`. A three-party auth token is bound to the Agent key, so
the PS cannot use it to prove its own identity. The implementation uses the
PS's existing `jwks_uri` server identity.

**Question:** Should the example target the Resource and use the issuing
server's `jwks_uri` credential, or is another PS credential intended?

**Placement:** Open a focused AAuth Core revocation issue.

### AAG-F035 — The revocation example does not bind the token reference body

**Source:** AAuth Core, `Token Revocation` and `Covered Components`.

The signed example omits `content-type` and `content-digest`. The general body
rule names PS and AS endpoints, not a Resource `/revoke` endpoint. A captured
proof can therefore be paired with a different `(iss, jti)` body. The
implementation requires both body fields plus the Resource's advertised
components.

**Question:** Should Core require `content-type` and `content-digest` for every
JSON revocation request?

**Placement:** Add to the focused AAuth Core revocation issue and cross-link
the Signature-Key covered-components discussion.

### AAG-F036 — Protected use after revocation has no response contract

**Source:** AAuth Core, `Token Revocation`, `Authentication Errors`, and
`Verification (Server)`.

Core defines `/revoke` responses but not the later protected Resource response.
It also reserves every `401` for a `Signature-Error`, although the revoked
token and request proof may both verify. The implementation returns
`403 access_denied` before route policy or application callbacks.

**Question:** What status and machine-readable error should a Resource return
when a valid proof presents a revoked auth token?

**Placement:** Add to the focused AAuth Core revocation issue.

### AAG-F037 — Core does not define the lifetime or race semantics of a pre-use tombstone

**Source:** AAuth Core, `Token Revocation`.

The `(iss, jti)` request can identify a pre-use tombstone, but the Resource has
not seen the token's expiry or exact bytes. Core requires `404` when the pair is
not recognized and does not say whether that response may still retain state,
how long such state lasts, how later token bytes are checked, or which side of
a concurrent first-use/revoke race wins.

**Question:** Must `404` be non-mutating, or should the Resource retain a
pre-use tombstone? If it retains one, what bounds its lifetime and how should a
concurrent first use be resolved?

**Placement:** Add to the focused AAuth Core revocation issue.

### AAG-F038 — Parent-mediated person-token expiry has two Agent-token ceilings

**Source:** AAuth Core, `Person Token Structure` and `Parent-Mediated
Authorization`.

The person token may not outlive “the agent token presented.” The parent token
is presented in `Signature-Key`, while `subagent_token` supplies the child key
bound into the result. The implementation uses the earlier expiration.

**Question:** Should parent-mediated person and auth tokens be capped by the
earlier of the parent and sub-agent token expirations?

**Placement:** Open one focused Core sub-agent issue containing F038–F045.

### AAG-F039 — Required parent/sub-agent retention fields are unspecified

**Source:** AAuth Core, `Person Token Endpoint` retention and `Sub-Agents`.

The retention list omits parent, child, Agent Provider, and child key, while
the later text says the PS records the relationship for audit and revocation.
It also says the PS “issued both tokens,” although the AP issues the child
token and an AS may issue the auth token. The implementation retains the four
relationship values with the person-token record.

**Question:** Which exact relationship fields must the PS retain, and which
token pair does “both tokens” mean?

**Placement:** Add to the focused Core sub-agent issue.

### AAG-F040 — AS verification of forwarded Agent tokens is implicit

**Source:** AAuth Core, `PS-to-AS Token Request` and `Parent-Mediated
Authorization`.

The AS receives parent and child Agent tokens and is said to record the parent
authoritatively, but the endpoint steps do not explicitly require verifying
both signatures, expirations, and the `parent_agent` link. The parent token
names the signing Person Server; the child's `ps` claim is optional. The
implementation independently verifies both tokens.

**Question:** Must the AS verify both Agent tokens, or treat the signed PS
request as an attestation of their already-verified contents?

**Placement:** Add to the focused Core sub-agent issue.

### AAG-F041 — Generic auth-token delivery compares against the wrong key

**Source:** AAuth Core, `Auth Token Delivery` and `Parent-Mediated
Authorization`.

Generic delivery tells the receiving Agent to compare `cnf.jwk` with its own
key. In this flow the parent receives a token intentionally bound to the child.
The implementation verifies it against `subagent_token.cnf.jwk` and the exact
resource-token context before forwarding it.

**Question:** Should the delivery checks define this parent-mediated branch
explicitly?

**Placement:** Add to the focused Core sub-agent issue.

### AAG-F042 — The interop profile asks the Resource to verify the wrong signature

**Source:** Interoperability demo profile, Surface 5.

The profile says the auth token is “signed with the sub-agent's key.” The PS or
AS signs the JWT; the child key appears in `cnf`, signs the HTTP request, and
is checked by the Resource.

**Question:** Should the profile instead say that the Resource verifies a
child-signed request whose auth-token `cnf.jwk` matches that request key?

**Placement:** Add to the focused Core sub-agent issue or make the matching
editorial change directly in the profile.

### AAG-F043 — Parent attenuation has no request parameter

**Source:** AAuth Core, `Parent-Mediated Authorization`.

The text says the parent can attenuate a child request, but the Resource-signed
resource token fixes the requested scope and the PS request has no narrower
scope parameter. The parent can refuse or delay forwarding, but cannot express
attenuation on the wire.

**Question:** Is attenuation intended to require a fresh narrower resource
token, or should the parent-to-PS request gain an explicit narrowing input?

**Placement:** Add to the focused Core sub-agent issue.

### AAG-F044 — “Own key” does not explicitly require distinct parent and child keys

**Source:** AAuth Core, `Sub-Agent Identity` and `Parent-Mediated
Authorization`.

The text gives a sub-agent its “own” signing key and repeatedly contrasts that
key with the parent request key, but never states that the two JWKs must differ.
If they are equal, the parent can use every child-bound credential. The
implementation requires distinct keys.

**Question:** Should Core explicitly require a sub-agent token's `cnf.jwk` to
differ from its parent's current confirmation key?

**Placement:** Add to the focused Core sub-agent issue.

### AAG-F045 — Direct sub-agent PS refusal has no error assignment

**Source:** AAuth Core, `Delegation Depth` and `Token Endpoint Error Codes`.

Core requires a PS to reject a request signed by a sub-agent but assigns no
status or error. The implementation first verifies proof possession, then
returns `400 invalid_agent_token` without `Signature-Error`; a forged proof
still returns `401` with the signature failure.

**Question:** Which registered response should a correctly signed direct
sub-agent request receive?

**Placement:** Add to the focused Core sub-agent issue.

### AAG-F046 — Generic auth-token verification has no call-chain context

**Source:** AAuth Core, [Auth Token Verification][core-auth-verification] and
[Upstream Token Verification][core-upstream-verification].

The upstream rule says to perform Auth Token Verification. Its request-context
steps assume the verifier is the upstream Resource: `aud` must name that
Resource, `cnf` must match the current request signer, and `(iss, sub)` matches
that Resource's person record. A PS or AS processing a downstream request is
none of those parties, so literal verification rejects a valid chain.

**Question:** Should upstream verification explicitly use JWT Trust
Verification, followed by its own `iss`, `aud`, person, and intermediary
bindings, rather than importing Resource Request-Context Binding?

**Placement:** Open one focused Core call-chaining issue containing F046–F057.

### AAG-F047 — The upstream `cnf` description names the wrong key

**Source:** AAuth Core, [Call Chaining][core-call-chaining] and
[Auth Token Usage][core-auth-verification].

Call Chaining says the upstream token's `cnf` is the intermediary's key. The
upstream Resource received that token on a request signed by the original
Agent, so Auth Token Usage requires `cnf` to be the original Agent's key. The
intermediary later signs with its own Agent-token key; changing `cnf` would
change the already-issued upstream token.

**Question:** Should the call-chaining text say that upstream `cnf` remains the
original caller's key and is not compared with the intermediary proof key?

**Placement:** Add to the focused Core call-chaining issue.

### AAG-F048 — The audience rule implies Resource/AP collocation

**Source:** AAuth Core, [Upstream Token Verification][core-upstream-verification]
and [Call Chaining Identity][core-agent-person-binding].

The upstream token's `aud` is Resource 1's identifier. Requiring it to equal
the intermediary Agent token's `iss` also requires Resource 1's Agent Provider
to use that same identifier. Publishing Agent metadata at the Resource origin
supports this arrangement, but the text does not state the resulting role
collocation requirement.

**Question:** Is Resource-1/Agent-Provider identifier collocation required for
call chaining? If so, should the topology state it directly?

**Placement:** Add to the focused Core call-chaining issue.

### AAG-F049 — Person remapping has no host contract

**Source:** AAuth Core, [Person Token Endpoint][core-person-endpoint] and
[Directed Identifiers Across a Chain][core-call-chaining].

The PS must determine the person from an upstream Resource-1-directed `sub`,
then mint a different Resource-2-directed `sub`. The required person-token
retention fields preserve the directed value but do not identify the PS's
internal person record or define the lookup and derivation contract.

**Question:** What stable mapping must a PS retain or expose so an upstream
directed subject can be resolved to the same person and re-derived for a new
Resource?

**Placement:** Add to the focused Core call-chaining issue.

### AAG-F050 — The two upstream-token presentations are not bound

**Source:** AAuth Core, [Person Token Endpoint][core-person-endpoint],
[PS Token Endpoint][core-ps-token-endpoint], and
[Call Chaining][core-call-chaining].

The intermediary presents `upstream_token` when obtaining the downstream
person token and presents one again with the downstream resource token. Core
does not say whether the second value must be the same compact token, the same
issuer/JTI, or merely equivalent claims. Without a binding, the second request
can substitute another authorization after the downstream identity was issued.

**Question:** Must the second request repeat the exact compact upstream token?
If semantic replacement is allowed, which fields define equivalence?

**Placement:** Add to the focused Core call-chaining issue.

### AAG-F051 — Downstream credential lifetime is not derived

**Source:** AAuth Core, [Call Chaining][core-call-chaining],
[Person Token Structure][core-person-lifetime], and
[Auth Token Structure][core-auth-token-lifetime].

Core requires the upstream token to be valid when presented but does not say
whether a downstream person or auth token may outlive it. The ordinary token
ceilings refer to the intermediary Agent token and an optional mission, not
the upstream authorization being extended.

**Question:** Must either downstream credential expire no later than the
upstream auth token, or is validating the upstream token independently at each
issuance step sufficient?

**Placement:** Add to the focused Core call-chaining issue.

### AAG-F052 — Mission ownership and propagation conflict in a chain

**Source:** AAuth Core, [Person Token Endpoint][core-person-endpoint],
[Upstream Token Verification][core-upstream-verification], and
[Call Chaining][core-call-chaining].

The person-token endpoint says a requested mission belongs to “this agent,”
which is the intermediary. Call Chaining instead tells the PS to evaluate the
mission carried by the upstream token, which belongs to the original Agent.
It does not say whether that digest enters the downstream person token and
resource-token lineage or remains policy input only.

**Question:** Whose mission governs a chained request, how does the
intermediary present it, and which downstream tokens must carry its digest?

**Placement:** Add to the focused Core call-chaining issue.

### AAG-F053 — An AS cannot literally verify the forwarded upstream token

**Source:** AAuth Core, [PS-to-AS Token Request][core-ps-as-request],
[Auth Token Verification][core-auth-verification], and
[Upstream Token Verification][core-upstream-verification].

In four-party chaining the PS forwards `upstream_token` and the intermediary
Agent token in a request signed by the PS. Literal Auth Token Verification
would compare upstream `cnf` with the PS request key. That key belongs to
neither the original Agent nor the intermediary, so every valid request fails.

**Question:** Which upstream checks must the AS perform itself, which key does
it compare, and which facts may it accept from the authenticated PS?

**Placement:** Add to the focused Core call-chaining issue.

### AAG-F054 — “Trusted issuer” has no evidence model

**Source:** AAuth Core,
[Upstream Token Verification step 2][core-upstream-verification].

The recipient must trust a PS or AS whose token it “previously brokered or is
authorized to extend.” Core defines no retained record, trust callback, token
reference, or proof that establishes either condition. Two conforming
implementations can therefore admit different issuers for the same request.

**Question:** What evidence establishes that an upstream issuer may be
extended, and which party retains it for PS and AS verification?

**Placement:** Add to the focused Core call-chaining issue.

### AAG-F055 — No error code covers an invalid upstream token

**Source:** AAuth Core, [Upstream Token Verification][core-upstream-verification]
and [Token Endpoint Error Codes][core-token-errors].

The registry distinguishes invalid Agent and Resource tokens but has no result
for a malformed, expired, untrusted, misdirected, or substituted
`upstream_token`. Reusing `invalid_request` hides a verified-token failure;
reusing `invalid_resource_token` names the wrong token.

**Question:** Should Core register `invalid_upstream_token`, with a distinct
expired form or one code for every upstream-token validation failure?

**Placement:** Add to the focused Core call-chaining issue.

### AAG-F056 — Person-token retention omits upstream-chain custody

**Source:** AAuth Core, [Person-token retention][core-person-endpoint] and
[Call Chaining][core-call-chaining].

The required record contains only the downstream person-token fields. It does
not retain the upstream issuer/JTI, exact token digest, upstream person, or
trust decision. The later PS request therefore has no specified durable fact
against which to compare its second `upstream_token` presentation.

**Question:** Which upstream reference and integrity fields must be retained
with a chained person-token record, and for how long?

**Placement:** Add to the focused Core call-chaining issue.

### AAG-F057 — One-Agent/one-person conflicts with intermediary Resources

**Source:** AAuth Core, [Agent-Person Binding][core-agent-person-binding] and
[Call Chaining][core-call-chaining].

Core requires every Agent to be associated with exactly one person. A Resource
acting as one stable Agent can receive authorized calls for many people and
uses each caller's upstream token to select the downstream person. Applying
the general invariant literally would let that intermediary serve only one
upstream person.

**Question:** Should Core define a narrow exception for a Resource acting as an
Agent only when a valid upstream token supplies the person, while preserving
the one-person rule for that Agent's direct requests?

**Placement:** Add to the focused Core call-chaining issue.

### AAG-F058 — Events uses a subscription identifier as the delivery deduplication key

**Status:** evidence pending

**Source:** AAuth Events, `Subscribe Token`, `Event Token`, and `Agent
Verification`.

The AP creates one `eid` for a subscription. A subscription may permit several
or unlimited deliveries, and every Event token repeats that same `eid`. The
Agent is nevertheless told to deduplicate events by `(iss, eid)`. A literal
implementation accepts the first delivery and discards every later legitimate
delivery on the same subscription.

The target implementation keeps `eid` as subscription context and uses an
exact token-and-payload fingerprint as a local replay key. That avoids data
loss but cannot establish whether two differently encoded deliveries represent
the same logical event.

**Question:** Should the Event token carry a Resource-issued per-delivery `jti`
or another event identifier, and should Agent deduplication use that value
instead of the subscription `eid`?

**Placement:** Open an Events issue after the executing delivery path provides
an interoperability vector.

### AAG-F071 — The `jkt-jwt` example omits the required `alg` in both JWKs

**Status:** ready / unsubmitted

**Source:** HTTP Signature Keys, `Header Web Key (hwk)` and `JKT JWT
Self-Issued Key Delegation (jkt-jwt)`.

The text requires a fully specified algorithm on the durable protected-header
JWK and the delegated `cnf.jwk`. Its example omits `alg` from both. The
executing Ed25519 profile rejects either omission, so copying the example does
not produce a valid assertion.

**Question:** Should the example add `"alg":"ES256"` to the durable P-256
protected-header JWK and `"alg":"Ed25519"` to the delegated Ed25519
`cnf.jwk`?

**Placement:** Open or add to a Signature-Key examples issue after checking
the current tracker for the same vector defect.

### AAG-F072 — Bootstrap names `jti` replay protection without defining replay

**Status:** ready / unsubmitted

**Source:** AAuth Bootstrap, `Two-Key Refresh`; HTTP Signature Keys, `JKT JWT
Self-Issued Key Delegation (jkt-jwt)` and `Client Processing`.

Bootstrap says the naming JWT includes `jti` for replay protection.
Signature-Key requires `jti` only when assertion caching is requested and its
verification procedure does not consume or retain it. Neither source defines
the replay key's namespace, lifetime, exact-request binding, duplicate result,
or lost-response recovery.

The executing profile requires `jti`, keys it with the durable thumbprint,
binds the exact naming JWT and JSON body, freshly signs the outer retry,
returns the retained first Agent token for an exact retry, and rejects changed
stable input. Those are implementation choices rather than inferred
requirements.

**Question:** Should Bootstrap define the minimum replay and lost-response
contract for a two-key refresh, or state explicitly that every AP profile must
define it?

**Placement:** Open a focused Bootstrap/Signature-Key cross-spec issue.

### AAG-F073 — The delegated software key is described as enclave-determined

**Status:** ready / unsubmitted

**Source:** HTTP Signature Keys, `JKT JWT Self-Issued Key Delegation
(jkt-jwt)`; AAuth Bootstrap, `Mobile App Enrollment` and `Two-Key Refresh`.

Both sources describe software generating the fresh ephemeral request key.
The Signature-Key algorithm step later says that key's algorithm is
“enclave-determined,” which instead describes the durable platform key. The
executing profile treats both algorithms as explicit supported inputs and
currently supports Ed25519 only.

**Question:** Should the algorithm text say that the durable signing
algorithm is platform-determined while the delegated request-key algorithm is
chosen by the client within peer support?

**Placement:** Add to a Signature-Key `jkt-jwt` clarification issue.

### AAG-F074 — Stable Agent `sub` does not distinguish the two key rotations

**Status:** ready / unsubmitted

**Source:** AAuth Core, `Agent Token Structure`; AAuth Bootstrap, `Agent
Identifier Strategies`, `Per-Install Identity`, and `Key Rotation vs Token
Refresh`.

Core says Agent `sub` is stable across key rotations. Bootstrap preserves it
when only the ephemeral token key changes, but treats a replacement durable
enrollment key as a new Agent identity. The executing API makes that
distinction explicit: refresh rotates the ephemeral key under one enrollment;
a different durable key does not enter that enrollment.

**Question:** Should Core distinguish proof-key rotation from durable
enrollment-key replacement when describing `sub` stability?

**Placement:** Open a focused Core/Bootstrap terminology issue.

### AAG-F075 — Bootstrap examples use AP-internal endpoints after removing discovery

**Status:** ready / unsubmitted

**Source:** AAuth Bootstrap, `Per-Platform Enrollment Sketches` and `Document
History`.

The document deliberately removes `bootstrap_endpoint`, `refresh_endpoint`,
and `webauthn_endpoint` from AP metadata while its examples continue to use
unnamed AP-internal endpoints and one sample `/refresh` request. Because the
document is informational, independent implementations can follow the same
key pattern while exposing incompatible routes, envelopes, statuses, and
errors. The executing Go profile therefore requires application-selected AP
URLs and labels its JSON as an implementation choice.

**Question:** Should Bootstrap include one explicitly non-normative reference
HTTP profile for interoperability, or state more directly that it defines
only the key and role pattern and intentionally provides no portable wire?

**Placement:** Open a Bootstrap scope question rather than presenting the Go
profile as source-defined.

### AAG-F076 — R3 rationale contradicts the normative dual-role fetch rule

**Status:** ready / unsubmitted

**Source:** AAuth R3, `R3 Document Access Restriction` and `Design Rationale`.

The normative rule entitles both the PS and AS to fetch an R3 document and
explains their distinct consent and policy uses. The later rationale still
calls document retrieval “restricted to AS-only access.” A literal
implementation of that rationale prevents the PS from rendering the document's
human-readable consent material. The executing four-party journey observes
independent PS and AS fetches, while the Resource role test accepts the same
collocated issuer separately as `aauth-person.json` and `aauth-access.json`.
Together they prove that the role distinction is not redundant.

**Question:** Should the rationale say that R3 documents are restricted to the
entitled PS and AS, and that the Agent remains unable to fetch them?

**Placement:** Add to an R3 editorial-consistency issue after checking the
current tracker for the same stale “AS-only” sentence.

[core-person-endpoint]: https://github.com/dickhardt/AAuth/blob/a99d353cf18aee81d0c5445bac070164fb3b8bc5/draft-hardt-oauth-aauth-protocol.md#L651-L700
[core-person-lifetime]: https://github.com/dickhardt/AAuth/blob/a99d353cf18aee81d0c5445bac070164fb3b8bc5/draft-hardt-oauth-aauth-protocol.md#L714-L726
[core-ps-token-endpoint]: https://github.com/dickhardt/AAuth/blob/a99d353cf18aee81d0c5445bac070164fb3b8bc5/draft-hardt-oauth-aauth-protocol.md#L1062-L1086
[core-ps-as-request]: https://github.com/dickhardt/AAuth/blob/a99d353cf18aee81d0c5445bac070164fb3b8bc5/draft-hardt-oauth-aauth-protocol.md#L1781-L1796
[core-auth-token-lifetime]: https://github.com/dickhardt/AAuth/blob/a99d353cf18aee81d0c5445bac070164fb3b8bc5/draft-hardt-oauth-aauth-protocol.md#L1984-L2001
[core-auth-verification]: https://github.com/dickhardt/AAuth/blob/a99d353cf18aee81d0c5445bac070164fb3b8bc5/draft-hardt-oauth-aauth-protocol.md#L2005-L2031
[core-upstream-verification]: https://github.com/dickhardt/AAuth/blob/a99d353cf18aee81d0c5445bac070164fb3b8bc5/draft-hardt-oauth-aauth-protocol.md#L2043-L2050
[core-call-chaining]: https://github.com/dickhardt/AAuth/blob/a99d353cf18aee81d0c5445bac070164fb3b8bc5/draft-hardt-oauth-aauth-protocol.md#L2060-L2085
[core-token-errors]: https://github.com/dickhardt/AAuth/blob/a99d353cf18aee81d0c5445bac070164fb3b8bc5/draft-hardt-oauth-aauth-protocol.md#L2537-L2548
[core-agent-person-binding]: https://github.com/dickhardt/AAuth/blob/a99d353cf18aee81d0c5445bac070164fb3b8bc5/draft-hardt-oauth-aauth-protocol.md#L3143-L3164
