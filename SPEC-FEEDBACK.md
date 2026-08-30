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
| R3 | source-reviewed and architecture-mapped | `AAG-F005`, `AAG-F006`, `AAG-F014`, `AAG-F014a`, and `AAG-F015` remain evidence-pending until an R3 path executes |
| Events | source-synchronized and architecture-mapped | No implementation-backed question yet |
| Bootstrap | source-synchronized and architecture-mapped | The document is informational; no enrollment or refresh path has produced implementation feedback yet |
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
| AAG-F005 | R3 same-URI replacement can make an old content hash unverifiable | evidence pending until R3 implementation |
| AAG-F006 | R3 example hashes are not executable SHA-256 vectors | evidence pending until R3 implementation |
| AAG-F007 | Mission completion still appears in the introductory interaction list after moving endpoints | evidence pending |
| AAG-F008 | Clarification requires an `agent` claim removed from resource tokens | ready below |
| AAG-F009 | Person-token policy denial has no registered error | ready below |
| AAG-F010 | Four-party person and tenant context use the wrong issuer namespace | ready below |
| AAG-F011 | Closed issues 88 and 89 are not reflected in the person-token endpoint text | ready below |
| AAG-F012 | A lost initial deferred `202` has no stable recovery identity | evidence pending |
| AAG-F013 | Restored deferred state can lose the verified request authority | held-store boundary implemented; generic deferred rule remains open |
| AAG-F014 | R3 protected challenges do not define who selects the exact operation | evidence pending until R3 implementation |
| AAG-F014a | An AS cannot distinguish requested operations from a broader R3 document carried only by URI and digest | evidence pending until R3 implementation |
| AAG-F015 | Per-call auth tokens do not identify the resource-token record that supplies `presented_jti` | evidence pending until R3 or step-up implementation |
| AAG-F016 | The mandatory signature set does not bind the query | ready below |
| AAG-F033 | Three-party deferral does not define whether the original resource-token expiry is terminal | ready below with PS-consent evidence |

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
