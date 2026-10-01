# AAuth specification feedback

Findings from implementing the AAuth family of drafts, tracked against the
current upstream editor sources. Source text and editor answers are
authoritative.

**Last reconciled:** 2026-10-01

| Source | Upstream commit |
| --- | --- |
| AAuth (Core, R3, Events, Bootstrap, Budgets, interop profile) | [`dickhardt/AAuth` at `28e8258`](https://github.com/dickhardt/AAuth/tree/28e8258f8153a2a51a709c53ebc9618f941564e4) (`28e8258f8153a2a51a709c53ebc9618f941564e4`, 2026-09-28) |
| HTTP Signature Keys | [`dickhardt/signature-key` at `69f5ba2`](https://github.com/dickhardt/signature-key/tree/69f5ba2647be848feed043fb6d8b0790e43cd0b6) (`69f5ba2647be848feed043fb6d8b0790e43cd0b6`, 2026-09-13) |

Section names in this file are the headings in those commits. The previous
reconcile (2026-09-01) used AAuth `a99d353` and signature-key `0ff751b`; the
implementation's pinned manifest is in [SPECIFICATIONS.md](SPECIFICATIONS.md).

Status values:

- **open:** still present upstream and not submitted by us.
- **submitted:** we posted a public issue or comment; the item gives the date
  and URL.
- **resolved:** the current upstream text fixes it, or removed the feature.
- **withdrawn:** our finding was wrong.
- **unverified:** could not be decided from the current text; the line says
  why.

## Keeping this file current

When you submit a finding, add the date and the public URL to its table row
and move its section from Open to Submitted. When upstream changes, update the
commits above, recheck every open and submitted item against the new text, and
move fixed items to Resolved as one line citing the commit and section. Git
history keeps the full text of resolved and withdrawn items.

A finding we submitted that upstream has since fixed is listed as resolved;
its Submitted column still gives the date and URL.


## Summary

open: 72, resolved: 36, submitted: 1, withdrawn: 1 (total 110).


| ID | Title | Status | Upstream evidence | Submitted |
| --- | --- | --- | --- | --- |
| AAG-H001 | Draft-05 through draft-08 implementation feedback | resolved | 28e8258 Core, "Acknowledgments"; "Document History" | date not retained, record not retained |
| AAG-H002 | Callback authority and issuer-role discovery | resolved | 28e8258 Core, "Design Rationale" > "In Brief"; "Why No Authorization Code"; "Auth Token Verification" | date not retained, record not retained |
| AAG-H003 | Recommended justification sections | submitted | 28e8258 Core, "Terminology" (Markdown, Editor's note); "Auth Token Request" (`justification`) | date not retained, record not retained |
| AAG-F001 | Interop Surface 3 says resource metadata holds keys, while Core uses `jwks_uri` | open | 28e8258 interop-demo-profile, "Surface 3 — Resource-token issuance and issuer discovery"; Core, "Resource Metadata"; "JWKS Discovery and Caching" | no |
| AAG-F002 | AS request example used a `jwks_uri` Signature-Key parameter the scheme did not define | resolved | 28e8258 Core, "PS-to-AS Token Request"; "Keying Material"; 69f5ba2 signature-key, "JWKS URI Discovery (jwks_uri)"; https://github.com/dickhardt/AAuth/pull/148 | no |
| AAG-F003 | Audit delivery has no stable retry identity after a lost 201 | open | 28e8258 Core, "Audit Request"; "Audit Response" | no |
| AAG-F004 | Deferred terminal delivery at the PS and in resource-managed flows has no recovery path | open | 28e8258 Core, "Pending URL Security"; "Deferred Delivery"; "PS Response"; "AAuth-Access Response Header"; "Deferred Response State Machine" | no |
| AAG-F005 | R3 same-URI replacement can make an old content hash unverifiable | open | 28e8258 R3, "Content Addressing"; "Caching"; "Design Rationale" > "Why Not RAR" | no |
| AAG-F006 | R3 example hashes are not real SHA-256 values | open | 28e8258 R3, "Resource Token Extensions"; "Auth Token Extensions" | no |
| AAG-F007 | Mission completion appeared in the introductory interaction-endpoint list | resolved | 28e8258 Core, "Interaction Endpoint"; https://github.com/dickhardt/AAuth/pull/197 | no |
| AAG-F008 | Updated clarification requests referred to a removed agent claim | resolved | 28e8258 Core, "Updated Request"; https://github.com/dickhardt/AAuth/issues/104 (PR 129/136) | 2026-09-01 https://github.com/dickhardt/AAuth/issues/104#issuecomment-5498039783 |
| AAG-F009 | Synchronous token-endpoint policy denial has no registered error | open | 28e8258 Core, "Person Token Endpoint"; "Token Endpoint Error Codes"; "Polling Error Codes" | no |
| AAG-F010 | Four-party person identity uses the access-server namespace in one step | open | 28e8258 Core, "Auth Token Structure"; "Auth Token Verification" (Request-Context Binding step 4); "Resource Token Structure"; https://github.com/dickhardt/AAuth/issues/215 | no |
| AAG-F010a | Four-party tenant changes issuer namespace | open | 28e8258 Core, "Auth Token Structure"; "Person Token Structure"; "Organization Identification"; https://github.com/dickhardt/AAuth/issues/215 ; related https://github.com/dickhardt/AAuth/issues/210 | no |
| AAG-F011 | Person token endpoint omitted the auth-token request parameters | resolved | 28e8258 Core, "Person Token Endpoint"; https://github.com/dickhardt/AAuth/pull/186 (issues 175/177) | 2026-09-01 https://github.com/dickhardt/AAuth/issues/88#issuecomment-5498039809 |
| AAG-F012 | A lost initial 202 has no recovery identity | open | 28e8258 Core, "Deferred Responses" > "Initial Request"; "Pending Response"; "Polling with GET"; "Pending URL Security" | no |
| AAG-F013 | Restored deferred state can lose the verified request authority | open | 28e8258 Core, "Deferred Responses"; "Pending URL Security"; "Non-Repudiation and Audit After Key Rotation" | no |
| AAG-F014 | R3 operation selection on a protected challenge | withdrawn | 28e8258 R3, "Authorization Endpoint Extensions" > "Request"; "Resource Enforcement" | no |
| AAG-F014a | The issuer cannot tell the requested operations from a broader R3 document | open | 28e8258 R3, "Authorization Endpoint Extensions" > "Request"/"Response"; "Operations Spanning Multiple Definitions"; "Issuer Processing"; "Auth Token Delivery" | no |
| AAG-F015 | Per-call auth tokens did not identify the record that supplies `presented_jti` | resolved | 28e8258 Core, "Resource Token Structure"; "Auth Token Request"; R3, "Flow"; https://github.com/dickhardt/AAuth/issues/152; https://github.com/dickhardt/AAuth/pull/153 | no |
| AAG-F016 | The mandatory signature set does not bind a query | open | 28e8258 Core, "Covered Components"; "Freshness and Replay"; "Why These Covered Components" | no |
| AAG-F017 | Authorization endpoint body is not required to be signed | open | 28e8258 Core, "Covered Components"; "Why These Covered Components"; "Authorization Endpoint"; "Resource Metadata" | no |
| AAG-F018 | Missing proof fields have two error classifications | resolved | 28e8258 Core, "Verification (Server)" step 1; 69f5ba2 signature-key, "invalid_signature" | no |
| AAG-F019 | keyid has no scheme-specific equality rule | open | 69f5ba2 signature-key, "Relationship to Accept-Signature"; 28e8258 Core, "Signature Parameters" | no |
| AAG-F020 | Core JWKS stale-on-error caching conflicts with Signature-Key caching guidance | open | 28e8258 Core, "JWKS Discovery and Caching"; 69f5ba2 Signature-Key, "Caching and Performance" | no |
| AAG-F021 | Signature-Key distinct-key MUST versus AAuth's one key across servers | open | 69f5ba2 Signature-Key, "Pseudonymity vs. Identity"; 28e8258 Core, "Keying Material", "Directed Identifiers" | no |
| AAG-F022 | Resource-side rejection of auth tokens outliving the agent token | resolved | 28e8258 Core, "Re-authorization"; "Auth Token Structure" | no |
| AAG-F023 | Deferred auth-token delivery record key and pending URL lifetime | resolved | 28e8258 Core, "Deferred Delivery"; "Pending URL Security"; https://github.com/dickhardt/AAuth/issues/92 | no |
| AAG-F024 | Deferred Delivery has no rule for the crash window | open | 28e8258 Core, "Deferred Delivery"; "Deferred Response State Machine" | no |
| AAG-F025 | Application 202 in a deferred result is indistinguishable from "keep polling" | open | 28e8258 Core, "Deferred Delivery"; "Deferred Response State Machine" | no |
| AAG-F026 | Body signature components from resource metadata conflict with bodyless polls | open | 28e8258 Core, "Resource Metadata"; "Polling with GET"; "Why These Covered Components" | no |
| AAG-F027 | Resource sessions do not define agent identity across key rotation | open | 28e8258 Core, "AAuth-Access Response Header"; "Why Session Tokens Are Opaque" | no |
| AAG-F028 | Opaque AAuth-Access session token conflicts with the all-JWT statement | open | 28e8258 Core, "Protocol Overview"; "AAuth Tokens"; "AAuth-Access Response Header"; "Proof-of-Possession" | no |
| AAG-F029 | Interaction decisions are described as recorded at the PS | open | 28e8258 Core, "Interaction Code Format"; "User Interaction"; "Resource-Managed Authorization" | no |
| AAG-F030 | Resource-managed interaction is assigned both 202 and 401 | open | 28e8258 Core, "Resource-Managed Authorization"; "Requirement Values"; "Resource Metadata"; "Resource Adoption Path"; related https://github.com/dickhardt/AAuth/issues/209 | no |
| AAG-F031 | The resource authorization endpoint is not a PS-free path | open | 28e8258 Core, "Authorization Endpoint"; "Response without Resource Token"; "Resource Access"; "Resource Adoption Path"; "Consuming a Resource End to End" | no |
| AAG-F032 | Resource sessions have no standardized lifecycle or errors | open | 28e8258 Core, "AAuth-Access Response Header"; "Token Revocation"; "Who Revokes What"; "Presenting a Revoked Token"; "Error Responses" | no |
| AAG-F033 | Three-party deferral does not define the resource-token expiry boundary | open | 28e8258 Core, "Resource Token Structure"; "Resource Token Verification"; "Auth Token Endpoint"; "Deferred Delivery"; https://github.com/dickhardt/AAuth/issues/108 | no |
| AAG-F034 | Signing scheme for PS-to-resource revocation requests | resolved | 28e8258 Core, "Revocation Request"; "Keying Material"; https://github.com/dickhardt/AAuth/pull/148 | no |
| AAG-F035 | Signature coverage for JSON revocation requests to resources | resolved | 28e8258 Core, "Covered Components"; "Revocation Request"; https://github.com/dickhardt/AAuth/pull/191 | 2026-09-13 https://github.com/dickhardt/AAuth/issues/165 |
| AAG-F036 | Response when a revoked token is presented | resolved | 28e8258 Core, "Presenting a Revoked Token"; "Verification (Server)"; https://github.com/dickhardt/AAuth/pull/149 | no |
| AAG-F037 | Revocation request contents, retention, and unknown-token handling | resolved | 28e8258 Core, "Revocation Request"; "Revocation Response"; "Who Revokes What"; "Revocation Cascade"; https://github.com/dickhardt/AAuth/pull/147 | no |
| AAG-F038 | Which agent token bounds exp in parent-mediated authorization | open | 28e8258 Core, "Person Token Structure"; "Auth Token Structure"; "Parent-Mediated Authorization" | no |
| AAG-F039 | Retention and revocation cascade omit parent-mediated relationships | open | 28e8258 Core, "Person Token Endpoint"; "Revocation Cascade"; "Parent-Mediated Authorization" | no |
| AAG-F040 | PS-to-AS token request does not require verifying agent_token and subagent_token | open | 28e8258 Core, "PS-to-AS Token Request"; https://github.com/dickhardt/AAuth/issues/199 | no |
| AAG-F041 | Auth token delivery and response checks lack a parent-mediated branch | open | 28e8258 Core, "Auth Token Delivery"; "Auth Token Response Verification"; "Parent-Mediated Authorization" | no |
| AAG-F042 | The interop profile asks the Resource to verify the wrong signature | open | 28e8258 interop-demo-profile, "Surface 5 — Parent-mediated sub-agent token handling" | no |
| AAG-F043 | Parent attenuation has no request parameter | open | 28e8258 Core, "Parent-Mediated Authorization"; "Auth Token Request" | no |
| AAG-F044 | "Own key" does not explicitly require distinct parent and child keys | open | 28e8258 Core, "Sub-Agent Identity"; "Parent-Mediated Authorization" | no |
| AAG-F045 | Direct sub-agent PS refusal has no error assignment | open | 28e8258 Core, "Single-Level Depth"; "Token Endpoint Error Codes"; "Verification (Server)" | no |
| AAG-F046 | Generic auth-token verification has no call-chain context | resolved | 28e8258 Core, "Upstream Token Verification" step 1; https://github.com/dickhardt/AAuth/pull/162 | no |
| AAG-F047 | The upstream `cnf` description names the wrong key | resolved | 28e8258 Core, "Call Chaining"; "Upstream Token Verification" step 1; https://github.com/dickhardt/AAuth/pull/162 | no |
| AAG-F048 | The audience rule implies Resource/AP collocation | resolved | 28e8258 Core, "Intermediary Agent Identity"; "Roles"; https://github.com/dickhardt/AAuth/pull/176 | no |
| AAG-F049 | Person remapping has no host contract | resolved | 28e8258 Core, "Person Token Endpoint" ("Which person"); "Directed Identifiers Across a Chain"; https://github.com/dickhardt/AAuth/pull/162 | no |
| AAG-F050 | The two upstream-token presentations are not bound | open | 28e8258 Core, "Call Chaining"; "Auth Token Request"; "Upstream Token Verification"; related: https://github.com/dickhardt/AAuth/issues/221 | no |
| AAG-F051 | Downstream credential lifetime is not derived | resolved | 28e8258 Core, "Person Token Structure"; "Auth Token Structure"; "Call Chaining"; https://github.com/dickhardt/AAuth/pull/176 | no |
| AAG-F052 | Mission ownership and propagation conflict in a chain | resolved | 28e8258 Core, "Person Token Endpoint" (`mission_s256` parameter and "Which person"); "Call Chaining"; https://github.com/dickhardt/AAuth/pull/162 | no |
| AAG-F053 | An AS cannot literally verify the forwarded upstream token | resolved | 28e8258 Core, "Upstream Token Verification" steps 1-3; "PS-to-AS Token Request"; https://github.com/dickhardt/AAuth/pull/162 | no |
| AAG-F054 | "Trusted issuer" has no evidence model | resolved | 28e8258 Core, "Upstream Token Verification" step 2; "Revocation Cascade" ("Records") | no |
| AAG-F055 | No error code covers an invalid upstream token | resolved | 28e8258 Core, "Token Endpoint Error Codes"; "Upstream Token Verification" step 1; https://github.com/dickhardt/AAuth/pull/162 | no |
| AAG-F056 | Person-token retention omits upstream-chain custody | resolved | 28e8258 Core, "Revocation Cascade" ("Records"); "Person Token Endpoint" ("Retention"); https://github.com/dickhardt/AAuth/pull/174 | no |
| AAG-F057 | One-Agent/one-person conflicts with intermediary Resources | resolved | 28e8258 Core, "Agent-Person Binding"; "Intermediary Agent Identity"; https://github.com/dickhardt/AAuth/pull/176 | no |
| AAG-F058 | Events uses a subscription identifier as the delivery deduplication key | resolved | 28e8258 Events, "Event Token" > "Structure"; "Agent Verification"; https://github.com/dickhardt/AAuth/pull/168 | no |
| AAG-F059 | Mission proposal policy denial has no registered error | open | 28e8258 Core, "Mission Creation"; "Mission Approval"; "Mission Endpoint Errors"; "Polling Error Codes" | no |
| AAG-F060 | Person token endpoint has no error for an unknown or foreign mission | open | 28e8258 Core, "Person Token Endpoint"; "Mission Endpoint Errors"; "Mission Status Errors"; "Token Endpoint Error Codes" | no |
| AAG-F061 | Resource and access server could not read the mission expiry they had to enforce | resolved | 28e8258 Core, "Mission Approval"; "Person Token Structure"; "Auth Token Structure"; https://github.com/dickhardt/AAuth/pull/131 | 2026-09-01 https://github.com/dickhardt/AAuth/issues/121 |
| AAG-F062 | approved_at does not ensure a globally unique mission digest | open | 28e8258 Core, "Mission Approval"; "Mission Identifier" | no |
| AAG-F063 | Mission update does not define the exact hashed artifact | open | 28e8258 Core, "Mission Update"; "Mission Log"; "Mission Management" | no |
| AAG-F064 | Mission update and completion denial errors are absent | open | 28e8258 Core, "Mission Endpoint Errors"; "Mission Update"; "Mission Completion" | no |
| AAG-F065 | Mission action uncertain success has no recovery identity | open | 28e8258 Core, "Mission Update"; "Mission Completion"; "Deferred Response State Machine" | no |
| AAG-F066 | Core contradicts itself on update acceptance authority | open | 28e8258 Core, "Mission"; "Mission Update" | no |
| AAG-F067 | Termination does not define outstanding credential behavior | open | 28e8258 Core, "Revocation Cascade"; "Mission Management"; "Mission Status Errors"; "Presenting a Revoked Token" | no |
| AAG-F068 | Retry-After is required but also has an absence default | open | 28e8258 Core, "Pending Response"; "Polling with GET" | no |
| AAG-F069 | Immediate auth-token issuance has no exact-result recovery identity | open | 28e8258 Core, "Resource Token Structure"; "Freshness and Replay"; "Auth Token Request"; "PS Response"; "Auth Token Delivery" | no |
| AAG-F070 | Immediate policy denial has no token-endpoint error | open | 28e8258 Core, "Token Endpoint Error Codes"; "Auth Token Delivery"; "Polling Error Codes"; "Interaction Callback Errors" | no |
| AAG-F071 | The `jkt-jwt` example omitted the required `alg` in both JWKs | resolved | 69f5ba2 signature-key, "JKT JWT Self-Issued Key Delegation (jkt-jwt)"; https://github.com/dickhardt/signature-key/pull/42 | no |
| AAG-F072 | Bootstrap names `jti` replay protection without defining replay | open | 28e8258 Bootstrap, "Refresh Patterns" > "Two-Key Refresh"; 69f5ba2 signature-key, "JKT JWT Self-Issued Key Delegation (jkt-jwt)" and "Client Processing" | no |
| AAG-F073 | The delegated request-key algorithm is described as enclave-determined | open | 69f5ba2 signature-key, "JKT JWT Self-Issued Key Delegation (jkt-jwt)" | no |
| AAG-F074 | Stable Agent `sub` does not distinguish the two key rotations | open | 28e8258 Core, "Agent Identifiers" and "Agent Token Structure"; Bootstrap, "Per-Install Identity" and "Key Rotation vs Token Refresh" | no |
| AAG-F075 | Bootstrap examples use AP-internal endpoints after removing discovery | open | 28e8258 Bootstrap, "Per-Platform Enrollment Sketches", "Refresh Patterns" > "Two-Key Refresh", and "Document History" | no |
| AAG-F076 | R3 rationale contradicted the normative dual-role fetch rule | resolved | 28e8258 R3, "Design Rationale" > "Why Not RAR"; R3, "Security Considerations" > "R3 Document Access Restriction"; https://github.com/dickhardt/AAuth/pull/128 | no |
| AAG-F077 | GraphQL introspection cannot discover client operation names | open | 28e8258 R3, "GraphQL Vocabulary (`urn:aauth:vocabulary:graphql`)" and "Operation Identifier Scope" | no |
| AAG-F078 | WSDL `service` plus `operation` does not identify one bound operation | open | 28e8258 R3, "WSDL Vocabulary (`urn:aauth:vocabulary:wsdl`)" | no |
| AAG-F079 | OData method narrowing and overload identity are undefined | open | 28e8258 R3, "OData Vocabulary (`urn:aauth:vocabulary:odata`)", "Operations Spanning Multiple Definitions", and "Auth Token Extensions" | no |
| AAG-F080 | AsyncAPI optional `action` has no matching rule | open | 28e8258 R3, "AsyncAPI Vocabulary (`urn:aauth:vocabulary:asyncapi`)" | no |
| AAG-F081 | Per-call parameter projection is not defined by vocabulary | open | 28e8258 R3, "Per-Call Proposals" > "Proposal Document" and "Flow" | no |
| AAG-F082 | OData annotation encoding lacks a resolvable term namespace and target | open | 28e8258 R3, "Operation Access Annotations" > "Vocabulary Encodings"; R3, "OData Vocabulary (`urn:aauth:vocabulary:odata`)" | no |
| AAG-F083 | Standard R3 vocabularies do not identify external specification revisions | open | 28e8258 R3, "Standard Vocabularies" and its seven subsections; R3 front-matter references | no |
| AAG-F084 | Events leaves subscription-registration parameters outside the signed content digest | open | 28e8258 Events, "Subscribe Token" > "Presentation"; Events, "Subscription Registration" > "Public Subscriptions"; Core, "Covered Components" | no |
| AAG-F085 | Events gave two incompatible event-endpoint retention rules | resolved | 28e8258 Events, "Protocol Overview" (step 2); Events, "Subscribe Token" > "Verification"; https://github.com/dickhardt/AAuth/pull/207 | no |
| AAG-F086 | Direct R3 leaves Auth-token-issuer duties assigned only to an AS | resolved | 28e8258 R3, "R3 Processing" / "Issuer Processing" (was AS Processing), "Auth Token Extensions", "R3 Document Access Restriction"; https://github.com/dickhardt/AAuth/pull/204 | no |
| AAG-F087 | `AAuth-Budget` examples are not RFC 9651 Dictionaries | resolved | 28e8258 Budgets, "AAuth-Budget Response Header", "Sending Rules", "Streaming", "The `reason` Parameter", "Deferred Delivery"; https://github.com/dickhardt/AAuth/pull/128 | no |
| AAG-F088 | First-hop denomination selection contradicts numeric narrowing | open | 28e8258 Budgets, "The Narrowing Chain" | no |
| AAG-F089 | Omitted PS-to-AS Budget ceiling is indistinguishable from extension non-participation | resolved | 28e8258 Budgets, "PS-to-AS Token Request Extensions", "Auth Token Extensions"; https://github.com/dickhardt/AAuth/pull/141 | 2026-09-01 https://github.com/dickhardt/AAuth/issues/122 |
| AAG-F090 | The exhausted example charges a refused request | resolved | 28e8258 Budgets, "Budget Exhaustion", "The `reason` Parameter", "Sending Rules" | no |
| AAG-F091 | Core names retained lineage but not its Auth-token lookup binding | resolved | 28e8258 Core, "Resource Token Structure", "Resource Token Verification"; Budgets, "Budget Exhaustion", "The Consumption Record"; https://github.com/dickhardt/AAuth/issues/152 (PR 153), https://github.com/dickhardt/AAuth/pull/206 | no |
| AAG-F092 | Ambiguous failure has no interoperable maximum-cost input | open | 28e8258 Budgets, "Ambiguous Failures", "The Budget Is a Hard Cap", "Refusing a Request That Does Not Fit" | no |
| AAG-F093 | Clarification timeout has no recipient reference instant | open | 28e8258 Core, "Clarification Required" | no |
| AAG-F094 | Clarification actions have no success-response contract | open | 28e8258 Core, "Clarification Response", "Cancel Request", "Deferred Response State Machine" | no |
| AAG-F095 | Clarification answers do not identify their question | open | 28e8258 Core, "Agent Response to Clarification", "Clarification Response", "Clarification Limits" | no |
| AAG-F096 | Permission denial has two terminal wire representations | open | 28e8258 Core, "Permission Response"; Core, "Deferred Response State Machine"; Core, "Polling Error Codes" | no |
| AAG-F097 | The Permission Endpoint has no error table | open | 28e8258 Core, "Permission Endpoint" / "Permission Request" / "Permission Response"; Core, "Error Responses" ("Token Endpoint Error Codes", "Polling Error Codes") | no |
| AAG-F098 | An uncertain initial Permission submission cannot be recovered | open | 28e8258 Core, "Permission Request"; Core, "Deferred Responses" ("Initial Request", "Polling with GET") | no |
| AAG-F099 | The Audit Endpoint has no endpoint-specific error contract | open | 28e8258 Core, "Audit Request" / "Audit Response"; Core, "Mission Status Errors"; Core, "Error Responses" | no |
| AAG-F100 | "Fire-and-forget" does not define the Audit response behavior | open | 28e8258 Core, "Audit Response" | no |
| AAG-F101 | An uncertain Interaction question submission cannot be recovered | open | 28e8258 Core, "Interaction Request" / "Interaction Response"; Core, "Deferred Responses" | no |
| AAG-F102 | Resource-hosted relay resolution has no terminal success shape | open | 28e8258 Core, "Interaction Response"; Core, "Relaying Through the Person Server"; Core, "Deferred Response State Machine" | no |
| AAG-F103 | Third-party login requires person context it has not obtained | resolved | 28e8258 Core (no Third-Party Login, Login Endpoint, or login_endpoint remains); https://github.com/dickhardt/AAuth/issues/155 ; https://github.com/dickhardt/AAuth/pull/157 | no |
| AAG-F104 | Core both permits and forbids a self-hosted Agent Provider | open | 28e8258 Core, "Roles", "Agent Provider", "Intermediary Agent Identity", "AAuth Platform Value Registry", "Why `.json` in Well-Known URIs", "Why Agents Are Under an Agent Provider"; Bootstrap, "Self-Hosted Agents", "Self-Hosted Refresh"; https://github.com/dickhardt/AAuth/issues/208 | no |
| AAG-F105 | Deferred mission approval does not define key renewal before token delivery | open | 28e8258 Core, "Mission Creation", "Mission Approval", "Person Token Structure", "Pending URL Security"; https://github.com/dickhardt/AAuth/issues/108 | no |

## Open

### AAG-F001 — Interop Surface 3 says resource metadata holds keys, while Core uses `jwks_uri`

**Upstream evidence:** 28e8258 interop-demo-profile, "Surface 3 — Resource-token issuance and issuer discovery"; Core, "Resource Metadata"; "JWKS Discovery and Caching"

**Submitted:** no

**Remaining:** Surface 3 still says the resource publishes its JWKS at `{iss}/.well-known/aauth-resource.json` and tells verifiers to find the `kid` key in that document. In Core that document carries `jwks_uri`, which points to a separate key set.

**Source:** interop demo profile, `Surface 3 — Resource-token issuance and issuer discovery`; AAuth Core, `Resource Metadata` and `JWKS Discovery and Caching`.

Surface 3 says the resource "publishes its JWKS at" `{iss}/.well-known/aauth-resource.json`. Its verification step tells verifiers to fetch that document, check `issuer`, and find the key matching the JWT `kid` in it. In Core, `aauth-resource.json` is resource metadata. That metadata carries `jwks_uri`, which is REQUIRED when the resource issues resource tokens, and the keys are published at that URI. A verifier that follows Surface 3 literally looks for keys in the metadata document and does not find them.

Our verifier follows Core: it fetches the metadata, checks `issuer`, dereferences `jwks_uri`, and selects the key by `kid`.

**Question:** Should Surface 3 be reworded to "publishes resource metadata whose `jwks_uri` names its JWKS", with a verification step that dereferences `jwks_uri`?

**Placement:** Open a small interop-profile issue or PR. No existing issue covers this.

### AAG-F003 — Audit delivery has no stable retry identity after a lost 201

**Upstream evidence:** 28e8258 Core, "Audit Request"; "Audit Response"

**Submitted:** no

**Remaining:** Unchanged. The request still has no event identifier or idempotency key. The response is a bare 201, and the endpoint is described as fire-and-forget.

**Source:** AAuth Core, `Audit Request` and `Audit Response`.

An audit request carries `mission_s256`, `action` and optional description, parameters and result. It has no request identifier, idempotency key or lookup reference. If the PS records the entry but the `201 Created` is lost, the agent cannot tell acceptance from non-delivery. `Audit Response` calls the endpoint fire-and-forget and says the agent SHOULD NOT block on the response. Resending the signed request creates a second valid log entry, while treating equal content as a retry would wrongly merge two identical actions.

Our PS appends the exact request bytes before acknowledging and keeps identical appends distinct. Our agent submits once and returns a typed uncertain outcome; it does not retry.

**Question:** Should an audit request carry a stable event identity chosen by the caller? Or should the PS define exact-request replay and lookup semantics after uncertain delivery?

**Placement:** Open a focused Core `Audit Endpoint` issue and cross-link AAG-F012. No existing issue covers this.

### AAG-F004 — Deferred terminal delivery at the PS and in resource-managed flows has no recovery path

**Upstream evidence:** 28e8258 Core, "Pending URL Security"; "Deferred Delivery"; "PS Response"; "AAuth-Access Response Header"; "Deferred Response State Machine"

**Submitted:** no

**Remaining:** Partly addressed. "Pending URL Security" now exempts resource-side deferred auth-token delivery and per-call grants from 410. The PS token endpoint's deferred `auth_token` and a resource-managed terminal `AAuth-Access` still get 410 after one terminal response.

**Source:** AAuth Core, `Pending URL Security`, `Deferred Delivery`, `PS Response`, `AAuth-Access Response Header`, and `Deferred Response State Machine`.

`Pending URL Security` says a pending URL must return `410 Gone` once it has returned a terminal response. The state machine says the agent MUST NOT retry after `410`. There is now one exception: deferred auth-token delivery at a resource and per-call grants, where a repeated presentation of the same auth token is answered from a retained result. `Deferred Delivery` gives the reason: a response can be lost in transit, and the agent cannot otherwise tell "not executed" from "executed, response lost". The same loss can happen in two other places: the `200` carrying `auth_token` from a pending PS token request, and the terminal `200` carrying `AAuth-Access` after resource-managed interaction. Neither has a replay window or a recovery key, so the credential is lost and the user may have to consent again.

Our deferred PS-consent and resource-managed tests follow the specified one-terminal-then-`410` behavior, so they show the loss window rather than closing it.

**Question:** Should the retained-result exception extend to the PS token endpoint's pending URL and to resource-managed terminal responses for a bounded period? Or should Core define another stable recovery key for a lost terminal auth token or `AAuth-Access` response?

**Placement:** Open a Core deferred-response issue citing the existing exception in `Pending URL Security` and `Deferred Delivery`. No existing issue covers this.

### AAG-F005 — R3 same-URI replacement can make an old content hash unverifiable

**Upstream evidence:** 28e8258 R3, "Content Addressing"; "Caching"; "Design Rationale" > "Why Not RAR"

**Submitted:** no

**Remaining:** "Content Addressing" still lets a resource update the document at the same URI, while "Caching" and "Why Not RAR" still say a logged `r3_uri` plus `r3_s256` is enough to re-fetch and verify the document later.

**Source:** R3, `Content Addressing`, `Caching`, and `Design Rationale` > `Why Not RAR`.

`Content Addressing` allows a resource to update the document at the same URI: existing auth tokens keep the old hash and new resource tokens get the new one. `Caching` says the issuer need not retain R3 documents, because its audit log of `r3_uri` and `r3_s256` "is enough to re-fetch and verify the document later". `Why Not RAR` makes the same re-fetch claim. Once a resource replaces the bytes at a URI, re-fetching that URI returns the new document, and the logged hash can no longer be verified. The permanent audit record then depends on the issuer having cached the old bytes, which `Caching` says it need not do.

Our resource store treats a published R3 URI as immutable: new bytes get a new URI, and referenced bytes stay available. A conflicting write is refused with evidence.

**Question:** Should R3 require that bytes at a referenced `r3_uri` stay available and unchanged, at least for as long as an audit record may cite them? Or should it drop same-URI replacement, or require the issuer to retain the documents it relied on?

**Placement:** Open an R3 issue. No existing issue covers this.

### AAG-F006 — R3 example hashes are not real SHA-256 values

**Upstream evidence:** 28e8258 R3, "Resource Token Extensions"; "Auth Token Extensions"

**Submitted:** no

**Remaining:** Both examples still show `r3_s256` as "aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789abcd", which is 40 characters. An unpadded base64url SHA-256 is 43 characters, and the value is not marked as a placeholder.

**Source:** R3, `Resource Token Extensions` and `Auth Token Extensions`.

`Content Addressing` defines `r3_s256` as the unpadded base64url SHA-256 of the served bytes, which is always 43 characters. The resource-token and auth-token examples both use `aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789abcd`, which is 40 characters, so it cannot be a SHA-256 value of any document. The examples also give no document bytes to hash and do not mark the value as illustrative. An implementer building test vectors from the draft cannot use these examples, and a strict length check would reject them.

Our implementation checks `r3_s256` against the exact served bytes and has no source vector it can check against these examples.

**Question:** Could the examples include a short R3 document and its real `r3_s256`, or else mark the value clearly as a placeholder?

**Placement:** Open a small R3 editorial issue or PR. No existing issue covers this.

### AAG-F009 — Synchronous token-endpoint policy denial has no registered error

**Upstream evidence:** 28e8258 Core, "Person Token Endpoint"; "Token Endpoint Error Codes"; "Polling Error Codes"

**Submitted:** no

**Remaining:** The token registry still has no policy-denial code. `denied` exists only as a polling error after a deferred response, and the text says only that AS denials are relayed.

**Source:** AAuth Core, `Person Token Endpoint`, `Token Endpoint Error Codes`, and `Polling Error Codes`.

The person token endpoint can receive a well-formed request and still refuse to issue under PS policy. `Token Endpoint Error Codes` covers malformed input, token-specific failures, `user_unreachable`, `as_unreachable` and internal failure, but not this result. `denied` (`403`) exists only in `Polling Error Codes`, for a decision reached after a `202` deferred response.

Our implementation currently returns `403` with `person_token_denied`. Reusing `user_unreachable` would claim there is no contact channel, and reusing `invalid_request` would call valid input malformed.

**Question:** Should Core register a terminal policy-denial error for an immediate refusal, or require the PS to report every denial through a deferred response ending in `denied`?

**Placement:** Open a new Core issue. No existing issue covers this error-code gap.

### AAG-F010 — Four-party person identity uses the access-server namespace in one step

**Upstream evidence:** 28e8258 Core, "Auth Token Structure"; "Auth Token Verification" (Request-Context Binding step 4); "Resource Token Structure"; https://github.com/dickhardt/AAuth/issues/215

**Submitted:** no

**Remaining:** Text still keys the person by (iss, sub); editor issue #215 (open, 2026-09-25) proposes (ps, sub) for four-party tokens.

**Source:** AAuth Core (28e8258), "Auth Token Structure", "Auth Token Verification" (Request-Context Binding, step 4), and "Resource Token Structure"; also affected: "Directed Identifiers Across a Chain", "Trust Posture in PS Authorization Access", and the privacy section "Directed Identifiers".

In four-party mode, auth-token `iss` is the access server, while `ps` is the person server whose namespace owns `sub` ("Resource Token Structure"). "Auth Token Structure" still says `sub` is unique within `iss`, and the verification step tells the resource to match or establish the person by `(iss, sub)`. That changes the person's identity when the access server changes and can merge equal directed subjects from different person servers behind one access server.

Our implementation presents `(ps, sub)` to the protected handler; its test covers namespace separation: `resource/server_test.go:TestProtectedHandlerReceivesCurrentPrincipal`.

**Question:** Should the auth-token structure and verification text define the person key as `(ps, sub)` in every topology, while keeping `iss` solely as the token issuer and trust anchor?

**Placement:** Comment on https://github.com/dickhardt/AAuth/issues/215, which tracks this change, with the additional affected sections.

### AAG-F010a — Four-party tenant changes issuer namespace

**Upstream evidence:** 28e8258 Core, "Auth Token Structure"; "Person Token Structure"; "Organization Identification"; https://github.com/dickhardt/AAuth/issues/215 ; related https://github.com/dickhardt/AAuth/issues/210

**Submitted:** no

**Remaining:** "(iss, tenant) identifies the organization" remains; #215 proposes (ps, tenant).

**Source:** AAuth Core (28e8258), "Auth Token Structure", "Person Token Structure", and "Organization Identification".

"Auth Token Structure" says `(iss, tenant)` identifies the organization. A person server places `tenant` in the person token, but a four-party auth token copies it while changing `iss` to the access server. The same organization therefore appears to change namespace during one flow.

**Question:** Should organization context be keyed by `(ps, tenant)` in four-party tokens, while `iss` remains only the token issuer?

**Placement:** Comment on https://github.com/dickhardt/AAuth/issues/215 together with AAG-F010; related wording in https://github.com/dickhardt/AAuth/issues/210.

### AAG-F012 — A lost initial 202 has no recovery identity

**Upstream evidence:** 28e8258 Core, "Deferred Responses" > "Initial Request"; "Pending Response"; "Polling with GET"; "Pending URL Security"

**Submitted:** no

**Remaining:** Unchanged. The initial request still has no caller-chosen idempotency or lookup key, and the pending URL appears only in the 202 `Location`.

**Source:** AAuth Core, `Deferred Responses` (`Initial Request`, `Pending Response`, `Polling with GET`) and `Pending URL Security`.

The initial request carries no idempotency or lookup key chosen by the caller. The pending URL exists only in the `Location` header of the `202`. If the server keeps the request and returns `202` but the response is lost, the agent never learns the pending URL. Sending the request again may start a second operation, such as a second consent prompt or a second mission proposal. A short HTTP-signature replay cache does not offer a later lookup.

Our mission-proposal client submits once and returns a typed uncertain outcome after a transport failure, a server failure, or a success response it cannot verify. It does not create a second proposal on its own.

**Question:** Should a deferred request carry a stable identity, chosen by the caller, that recovers its pending URL? Or should an exact replay return the original pending response for a bounded period?

**Placement:** Open a general Core deferred-response issue and cross-link AAG-F004. No existing issue covers this. Issue #222 (replay tuple) concerns signature replay windows, not recovery.

### AAG-F013 — Restored deferred state can lose the verified request authority

**Upstream evidence:** 28e8258 Core, "Deferred Responses"; "Pending URL Security"; "Non-Repudiation and Audit After Key Rotation"

**Submitted:** no

**Remaining:** Unchanged. Archiving verified artifacts is still a SHOULD framed as audit guidance and is not tied to pending state. Editors may consider server-internal storage integrity out of protocol scope.

**Source:** AAuth Core, `Deferred Responses`, `Pending URL Security`, and `Non-Repudiation and Audit After Key Rotation`.

A PS or AS that answers `202` keeps the pending request and acts on it later, possibly after a restart. Core makes signature verification normative at request time. `Pending URL Security` requires the agent's identity to be verified on every poll, but says nothing about the request fields the server stored. `Non-Repudiation and Audit After Key Rotation` recommends archiving the signed request, `Signature-Key` value and verification result, but only as a SHOULD for durable audit, not as a condition on restored pending state. Policy fields such as `justification`, and continuation fields such as the polling key, can therefore come back from a stored record that nothing ties back to the signed request.

Our implementation stores the exact request body, covered headers, signature, verification key and verification time with each pending record. On restart it re-verifies them offline before the record can be used again.

**Question:** When a PS or AS restores a pending authorization, should it be required to rebuild every field that carries policy or continuation authority from the verified signed request, or from an authenticated receipt that binds those same fields?

**Placement:** Open a focused Core deferred-response issue, separate from the lost-initial-response question in AAG-F012. Issue https://github.com/dickhardt/AAuth/issues/108 covers related pending-state binding across key rotation but not this point.

### AAG-F014a — The issuer cannot tell the requested operations from a broader R3 document

**Upstream evidence:** 28e8258 R3, "Authorization Endpoint Extensions" > "Request"/"Response"; "Operations Spanning Multiple Definitions"; "Issuer Processing"; "Auth Token Delivery"

**Submitted:** no

**Remaining:** The new "Auth Token Delivery" check limits grants to the document's `operations`, not to the requested ones. A single-definition request may still map to an "appropriate" document that only covers the request; only composed documents are defined as the exact union.

**Source:** R3, `Authorization Endpoint Extensions` (`Request` and `Response`), `Operations Spanning Multiple Definitions`, `Issuer Processing`, and `Auth Token Delivery`.

The agent sends `r3_operations` only to the resource. The resource maps them to "an appropriate R3 document", which must cover the requested operations, and puts only `r3_uri` and `r3_s256` in the resource token. When the request spans several internal definitions, the composed document's `operations` is the union of the requested operations. A request that maps to a single existing definition can get that whole definition, which may contain more operations. The issuer evaluates the document's `operations` and never sees the requested set. `Auth Token Delivery` now has the four-party PS check that `r3_granted` and `r3_per_call` fall within the document's `operations`. That check does not stop the issuer from granting a document member the agent never asked for.

Our resource always issues an exact-request document whose `operations` equals the agent's request, and our issuer constrains every grant to that set.

**Question:** Must the document chosen for an authorization-endpoint request contain exactly the operations in `r3_operations`? Or should the requested set be carried separately, bound for integrity, so issuer policy can see it?

**Placement:** Open an R3 issue. No existing issue covers this; issue #91 (operation access annotations) is unrelated.

### AAG-F016 — The mandatory signature set does not bind a query

**Upstream evidence:** 28e8258 Core, "Covered Components"; "Freshness and Replay"; "Why These Covered Components"

**Submitted:** no

**Remaining:** Required set is still @method, @authority, @path, signature-key with no @query; replay cache tuple omits the query.

**Source:** AAuth Core (28e8258), "Covered Components", "Why These Covered Components", and "Freshness and Replay"; RFC 9421, Sections 2.2.6 and 2.2.7.

Core requires `@path`, which RFC 9421 defines without the query. Two operations selected by different query strings can therefore share the same mandatory signature base. The replay-cache identity in "Freshness and Replay" also omits the query.

Our implementation covers `@query` when present; `signaturekey/request_external_test.go:TestRequestProofCoversAnExactQueryWhenPresent` shows that changing the query invalidates the original proof.

**Question:** Should AAuth require `@query` for query-bearing requests and add it to replay identity, or require each query-sensitive resource to advertise it as an additional component?

**Placement:** Open a new AAuth issue and cross-link https://github.com/dickhardt/signature-key/issues/7, which asks where a baseline HTTP Message Signatures profile should live.

### AAG-F017 — Authorization endpoint body is not required to be signed

**Upstream evidence:** 28e8258 Core, "Covered Components"; "Why These Covered Components"; "Authorization Endpoint"; "Resource Metadata"

**Submitted:** no

**Remaining:** content-digest/content-type are required only for PS/AS body requests and revocation endpoints; the resource authorization endpoint (scope, account in body) is not covered, though also defined by Core.

**Source:** AAuth Core (28e8258), "Covered Components", "Why These Covered Components", "Authorization Endpoint", and "Resource Metadata".

"Covered Components" requires `content-digest` and `content-type` for body-bearing requests to PS or AS endpoints and to any revocation endpoint. The resource "Authorization Endpoint" carries `scope` and `account` in its body, and its example covers only the base components. "Why These Covered Components" exempts resources in general but makes an exception for the resource revocation endpoint because Core defines it; Core also defines the authorization endpoint, which gets no such rule. Resource metadata `additional_signature_components` is still resource-wide, so requiring body components there also forces them onto bodyless protected routes.

**Question:** Should Core require `content-type` and `content-digest` at the resource authorization endpoint, as it does for the revocation endpoint, while keeping `additional_signature_components` as the resource-wide protected-request profile?

**Placement:** Open a new AAuth issue; reference PR #191 and issue #165 (revocation-body coverage) and cross-link Signature-Key issue 7.

### AAG-F019 — keyid has no scheme-specific equality rule

**Upstream evidence:** 69f5ba2 signature-key, "Relationship to Accept-Signature"; 28e8258 Core, "Signature Parameters"

**Submitted:** no

**Remaining:** Text unchanged since 0ff751b: keyid and Signature-Key MUST identify the same key, server SHOULD NOT send keyid, but no comparison rule per scheme.

**Source:** Signature-Key (69f5ba2), "Relationship to Accept-Signature"; AAuth Core (28e8258), "Signature Parameters", which repeats the rule.

Both texts require a `keyid` in `Signature-Input` to identify the same key as the `Signature-Key` member for that label, and the verifier takes the key from `Signature-Key`. Signature-Key now says a server SHOULD NOT send `keyid` and a client MAY ignore it, but a signer may still include it. Neither text defines how to compare `keyid` with schemes that carry an inline key or a JWT rather than one explicit key ID, so "the same key" cannot be checked uniformly.

Our implementation does not claim complete `keyid` correlation.

**Question:** Should `keyid` be forbidden when `Signature-Key` is present, or should each scheme define the exact value that means "the same key"?

**Placement:** Open a new Signature-Key issue.

### AAG-F020 — Core JWKS stale-on-error caching conflicts with Signature-Key caching guidance

**Upstream evidence:** 28e8258 Core, "JWKS Discovery and Caching"; 69f5ba2 Signature-Key, "Caching and Performance"

**Submitted:** no

**Remaining:** Core still allows cached keys on fetch failure with a 24-hour hard discard regardless of headers; Signature-Key still says only to honor cache-control and use appropriate expiration.

Core "JWKS Discovery and Caching" lets a verifier keep using cached keys when a refresh fails, with backoff, and requires discarding cached keys after at most 24 hours regardless of HTTP cache headers. Signature-Key "Caching and Performance" tells verifiers to use appropriate cache expiration and respect cache-control, with a once-per-minute refetch floor, and says nothing about stale use on error or a hard ceiling. An implementation that follows only Signature-Key will behave differently from one following Core when a JWKS endpoint is down or sends long max-age values.

**Source:** Core "JWKS Discovery and Caching" (28e8258); Signature-Key "Caching and Performance" (69f5ba2).

**Question:** Should Signature-Key carry the stale-on-error and maximum-age rules, or should Core state that its rules are an AAuth profile that tightens Signature-Key's general guidance?

**Placement:** New Signature-Key issue, cross-linking Core "JWKS Discovery and Caching".

### AAG-F021 — Signature-Key distinct-key MUST versus AAuth's one key across servers

**Upstream evidence:** 69f5ba2 Signature-Key, "Pseudonymity vs. Identity"; 28e8258 Core, "Keying Material", "Directed Identifiers"

**Submitted:** no

**Remaining:** The distinct-keys-per-server MUST is unchanged; Core still binds one cnf key into agent, person and auth tokens used at every server, and only Core's privacy section acknowledges it.

Signature-Key "Pseudonymity vs. Identity" says clients MUST use distinct keys for distinct servers to prevent cross-server correlation. The section is written about pseudonymous schemes (hwk, jkt-jwt). Core "Keying Material" has the agent token, person token and auth token all carry the same cnf key, so an AAuth agent presents one signing key to its PS, AS and every resource. Core "Directed Identifiers" acknowledges that the key itself correlates the agent across servers. A reader cannot tell from Signature-Key whether the MUST applies to the jwt scheme as AAuth uses it.

**Source:** Signature-Key "Pseudonymity vs. Identity" (69f5ba2); Core "Keying Material" and "Directed Identifiers" (28e8258).

**Question:** Is the distinct-key MUST scoped only to pseudonymous schemes? If so, can Signature-Key say so; if not, should Core state explicitly that AAuth's single-key design departs from it and why?

**Placement:** New Signature-Key issue, cross-linking Core "Directed Identifiers".

### AAG-F024 — Deferred Delivery has no rule for the crash window

**Upstream evidence:** 28e8258 Core, "Deferred Delivery"; "Deferred Response State Machine"

**Submitted:** no

**Remaining:** Current Deferred Delivery text still does not say what happens if the server fails after executing the call but before recording the result for later delivery.

Core "Deferred Delivery" has the server record the result of a deferred invocation and hand it back when the agent polls. It does not cover a server that fails after the invocation has taken effect but before the result is durably recorded. On restart the server cannot tell whether to re-run the call, report failure, or report an unknown outcome, and the agent cannot tell whether a retry is safe.

**Source:** Core "Deferred Delivery" and "Deferred Response State Machine" (28e8258).

**Question:** Should Core require the server to record the pending state before executing, and define what a poll returns when the outcome is unknown after a restart?

**Placement:** New AAuth issue on Core "Deferred Delivery" (together with AAG-F025).

### AAG-F025 — Application 202 in a deferred result is indistinguishable from "keep polling"

**Upstream evidence:** 28e8258 Core, "Deferred Delivery"; "Deferred Response State Machine"

**Submitted:** no

**Remaining:** Deferred Delivery answers the poll with the invocation's own response, while the state machine treats 202 as continue polling; no rule separates an application 202 from a pending 202.

Core "Deferred Delivery" says that once the deferred call completes, the pending URL answers with the invocation's response. Core "Deferred Response State Machine" treats a 202 from the pending URL as "continue polling". If the resource's own operation legitimately returns 202 (for example, an accepted asynchronous job), the agent will keep polling forever or misread the final result.

**Source:** Core "Deferred Delivery" and "Deferred Response State Machine" (28e8258).

**Question:** How should a final application 202 be distinguished from a pending 202, for example by a header, a required body shape, or a rule that the pending URL never returns the application response with 202?

**Placement:** New AAuth issue on Core "Deferred Delivery" (together with AAG-F024).

### AAG-F026 — Body signature components from resource metadata conflict with bodyless polls

**Upstream evidence:** 28e8258 Core, "Resource Metadata"; "Polling with GET"; "Why These Covered Components"

**Submitted:** no

**Remaining:** Metadata still says agents MUST cover every additional_signature_components member, and the example lists content-type and content-digest. Polls are still bodyless GETs, and no exception is defined.

**Source:** AAuth Core, `Resource Metadata`, `Polling with GET`, and `Why These Covered Components`.

Resource metadata says an agent must cover every `additional_signature_components` member on its requests to that resource. The metadata example lists `content-type` and `content-digest`. `Polling with GET` requires a bodyless `GET` and forbids resending the original body. `Why These Covered Components` acknowledges bodyless requests to a resource but defines no exception. Neither section says what the two fields describe on such a poll.

Our implementation covers the RFC 9530 digest of empty content, and requires the caller to supply fresh values for any other advertised fields.

**Question:** Do body-specific metadata components not apply to bodyless polls, or should a poll carry and sign an explicit zero-length representation? If they do not apply, where is that exception stated, so both peers build the same signature base?

**Placement:** Open a Core issue and cross-link Signature-Key covered-component processing. No existing issue covers this.

### AAG-F027 — Resource sessions do not define agent identity across key rotation

**Upstream evidence:** 28e8258 Core, "AAuth-Access Response Header"; "Why Session Tokens Are Opaque"

**Submitted:** no

**Remaining:** The text now says only that the token is meaningless without a valid agent signature. Identifier binding versus key binding, and key rotation, are still undefined.

**Source:** AAuth Core, `AAuth-Access Response Header` and `Why Session Tokens Are Opaque`.

The session token is meaningless without a valid signature from the agent. The text does not say whether the resource binds the session to the agent identifier, to the current `cnf` key, or to both. It also does not say what happens when the agent provider issues the same agent a new signing key.

Our implementation binds the session to the stable agent provider, agent and parent identity, and verifies the current agent token and signature on every request. This allows key rotation without letting another agent use the session.

**Question:** Should Core define this stable binding, require a key-bound session, or make the choice an explicit resource policy advertised to agents?

**Placement:** Open a Core `AAuth-Access` issue. No existing issue covers this.

### AAG-F028 — Opaque AAuth-Access session token conflicts with the all-JWT statement

**Upstream evidence:** 28e8258 Core, "Protocol Overview"; "AAuth Tokens"; "AAuth-Access Response Header"; "Proof-of-Possession"

**Submitted:** no

**Remaining:** The AAuth Tokens list now names only the four JWT types. The Overview still says all AAuth tokens are JWTs, and Proof-of-Possession still says all AAuth tokens bind a key through cnf.

**Source:** AAuth Core, `Protocol Overview`, `AAuth-Access Response Header`, and `Proof-of-Possession`.

`Protocol Overview` says all AAuth tokens are JWTs. `Proof-of-Possession` says every AAuth token proves possession of the key in its `cnf` claim. `AAuth-Access Response Header` calls the session token the one AAuth credential a resource issues, and defines it as an opaque `token68` with no JWT claims. Its proof binding is the agent's signature covering `Authorization`. `AAuth Tokens` lists only the four JWT types, which helps, but the two general statements are unchanged.

**Question:** Should the Overview and the proof-of-possession text explicitly exclude resource-issued session tokens?

**Placement:** Open a focused editorial Core issue.

### AAG-F029 — Interaction decisions are described as recorded at the PS

**Upstream evidence:** 28e8258 Core, "Interaction Code Format"; "User Interaction"; "Resource-Managed Authorization"

**Submitted:** no

**Remaining:** The interaction code rule still says the decision MUST be recorded via an authenticated channel at the PS. User Interaction now applies to a 202 interaction from any server, including a resource with no PS.

**Source:** AAuth Core, `Interaction Code Format`, `User Interaction`, and `Resource-Managed Authorization`.

`Interaction Code Format` says the person's approve or deny decision must be recorded through an authenticated channel "at the PS". `User Interaction` applies the same code to an interaction from any server. In two-party resource-managed authorization there is no PS, and the resource runs its own login or consent page.

**Question:** Should the rule name the server that issued the interaction, with the PS and the resource as explicit examples?

**Placement:** Add to a Core interaction issue, or open an editorial issue.

### AAG-F030 — Resource-managed interaction is assigned both 202 and 401

**Upstream evidence:** 28e8258 Core, "Resource-Managed Authorization"; "Requirement Values"; "Resource Metadata"; "Resource Adoption Path"; related https://github.com/dickhardt/AAuth/issues/209

**Submitted:** no

**Remaining:** The flow and Requirement Values use 202, but Resource Metadata (intro and the authorization_endpoint field) and Adoption Path step 2 still say interaction requirements come via 401. Issue 209 covers the auth-token status, which is a different problem.

**Source:** AAuth Core, `Resource-Managed Authorization`, `Requirement Values`, `Resource Metadata`, and `Resource Adoption Path`.

The dedicated flow and the requirement table use `202 Accepted` for `requirement=interaction`. `Resource Metadata` says something different twice: its introduction, and the `authorization_endpoint` member, both say a resource issues interaction requirements through `401` responses. `Resource Adoption Path` step 2 also says resource-managed authorization works through `401` responses.

**Question:** Which status is normative for a direct resource interaction, and should the other passages be corrected?

**Placement:** Open one Core resource-managed-flow issue. Issue 209 is related: it concerns the status listed for `auth-token` in the Requirement Values table, not interaction.

### AAG-F031 — The resource authorization endpoint is not a PS-free path

**Upstream evidence:** 28e8258 Core, "Authorization Endpoint"; "Response without Resource Token"; "Resource Access"; "Resource Adoption Path"; "Consuming a Resource End to End"

**Submitted:** no

**Remaining:** The endpoint still requires a person token, yet Adoption Path step 2 and the session-token mode still present it as two-party, PS-less access.

**Source:** AAuth Core, `Authorization Endpoint`, `Response without Resource Token`, `Resource Access`, `Resource Adoption Path`, and `Consuming a Resource End to End`.

Every request to the authorization endpoint must carry a PS-issued person token. Even so, `Response without Resource Token` points to resource-managed authorization. `Resource Adoption Path` step 2 lists "an authorization endpoint" as a two-party mechanism. `Consuming a Resource End to End` lists a request to the `authorization_endpoint` as a session-token path. `Resource Access` says the first two modes involve no PS. An agent with no PS can use only the direct challenge path, not this endpoint.

**Question:** Should this branch be described as resource-local authorization after PS identity, rather than as a two-party flow? Or is another request shape, with no person token, intended?

**Placement:** Add to the same resource-managed-flow issue as AAG-F030.

### AAG-F032 — Resource sessions have no standardized lifecycle or errors

**Upstream evidence:** 28e8258 Core, "AAuth-Access Response Header"; "Token Revocation"; "Who Revokes What"; "Presenting a Revoked Token"; "Error Responses"

**Submitted:** no

**Remaining:** The session token is absent from Who Revokes What and Presenting a Revoked Token, and no status or error is defined for an unknown, expired or revoked session.

**Source:** AAuth Core, `AAuth-Access Response Header`, `Token Revocation`, `Who Revokes What`, `Presenting a Revoked Token`, and `Error Responses`.

Session tokens have no defined lifetime, `iss` or `jti`. `Who Revokes What` lists agent, person, auth and resource tokens but not session tokens, and `Presenting a Revoked Token` does not cover them. Core also assigns no status, challenge or problem code for an unknown, expired or revoked session.

**Question:** Is the whole session lifecycle intentionally resource-local? If so, should Core state the minimum agent behavior when a session is invalid? If not, which identifier and error shape apply?

**Placement:** Open a Core `AAuth-Access` lifecycle issue.

### AAG-F033 — Three-party deferral does not define the resource-token expiry boundary

**Upstream evidence:** 28e8258 Core, "Resource Token Structure"; "Resource Token Verification"; "Auth Token Endpoint"; "Deferred Delivery"; https://github.com/dickhardt/AAuth/issues/108

**Submitted:** no

**Remaining:** "Resource Token Structure" still only says to get a fresh token if one "expires before it is redeemed", and does not say when a pending PS request counts as redeemed. Open issue #108 asks for the pending-record versus token-lifetime relation, but not this case specifically.

**Source:** AAuth Core, `Resource Token Structure`, `Resource Token Verification`, `Auth Token Endpoint`, and `Deferred Delivery`.

`Resource Token Structure` recommends resource tokens live no more than five minutes. It says that if one "expires before it is redeemed", the agent must get a fresh one and submit a new token request. It also says the PS verifies the mission is active "when it acts on the token". Consent at the PS can take much longer than five minutes. In three-party access the PS verifies the resource token when the request arrives and never presents it again. The text does not say whether the PS may issue an auth token after the original resource token has expired, or whether the pending request must end at that expiry. `Deferred Delivery` handles an expired resource token only at the resource, by allowing a fresh one in a later poll.

Our PS caps the three-party pending deadline at the original resource token's expiry. Another implementation could keep the verified request and decide it later, and both readings fit the text.

**Question:** Must a three-party pending authorization expire with its original resource token, or may the PS keep the verified request and decide it later, bounded by the presented token's `exp`?

**Placement:** Comment on https://github.com/dickhardt/AAuth/issues/108 (pending grant lifetime), which asks for the relationship between pending-record lifetime and token lifetimes. Open a focused `Auth Token Endpoint` issue if the editors prefer to keep it separate.

### AAG-F038 — Which agent token bounds exp in parent-mediated authorization

**Upstream evidence:** 28e8258 Core, "Person Token Structure"; "Auth Token Structure"; "Parent-Mediated Authorization"

**Submitted:** no

**Remaining:** exp is still bounded by "the agent token" presented or used, but parent-mediated requests involve two agent tokens (parent in Signature-Key, child as subagent_token) and Core does not say which one.

Core "Person Token Structure" caps a person token's exp at the agent token presented when it was requested, and "Auth Token Structure" caps an auth token's exp at the agent token used to obtain it. In "Parent-Mediated Authorization" the request carries the parent's agent token in Signature-Key and the child's agent token as subagent_token. Core does not say which token sets the cap, so issuers can produce tokens that outlive the child or the parent. Our implementation uses the earlier of the two expirations.

**Source:** Core "Person Token Structure", "Auth Token Structure", "Parent-Mediated Authorization" (28e8258).

**Question:** Should the cap be the earlier of the parent and child agent token expirations, or only the child's?

**Placement:** One focused Core issue on parent-mediated authorization covering AAG-F038, F039 and F041, cross-linking https://github.com/dickhardt/AAuth/issues/199.

### AAG-F039 — Retention and revocation cascade omit parent-mediated relationships

**Upstream evidence:** 28e8258 Core, "Person Token Endpoint"; "Revocation Cascade"; "Parent-Mediated Authorization"

**Submitted:** no

**Remaining:** The Retention paragraph and cascade Records list still have no fields for parent, child, approving party, or child key, and Parent-Mediated Authorization still assumes the PS issued both tokens.

Core "Person Token Endpoint" (Retention paragraph) and "Revocation Cascade" (Records) list what a PS keeps so it can cascade revocation, but they have no entry for the parent agent, the child agent, the party that approved the child, or the child's key. "Parent-Mediated Authorization" still describes the PS as having issued both tokens. Without these relationships a PS cannot revoke a child's tokens when the parent is revoked, or the reverse. Our implementation retains all four relationship values.

**Source:** Core "Person Token Endpoint", "Revocation Cascade", "Parent-Mediated Authorization" (28e8258).

**Question:** Should Retention and the cascade Records include the parent, child, approving party and child key, and should the cascade state whether revoking a parent revokes tokens issued for its children?

**Placement:** One focused Core issue on parent-mediated authorization covering AAG-F038, F039 and F041, cross-linking https://github.com/dickhardt/AAuth/issues/199.

### AAG-F040 — PS-to-AS token request does not require verifying agent_token and subagent_token

**Upstream evidence:** 28e8258 Core, "PS-to-AS Token Request"; https://github.com/dickhardt/AAuth/issues/199

**Submitted:** no

**Remaining:** The AS-side verification steps still omit the forwarded agent_token and subagent_token; editor issue 199 (dickhardt, 2026-09-25, open) tracks the same gap.

Core "PS-to-AS Token Request" has the PS forward the agent's agent_token (and, for parent-mediated requests, subagent_token) to the AS, but the AS steps do not require verifying those tokens' signatures, issuers, expiry, or binding to the PS request. An AS could issue an auth token on the strength of an unverified agent token. Our implementation verifies both tokens independently before issuing.

**Source:** Core "PS-to-AS Token Request" (28e8258).

**Question:** Should Core list explicit AS verification steps for agent_token and subagent_token, including issuer trust, expiry, and the relationship between the two?

**Placement:** Comment on https://github.com/dickhardt/AAuth/issues/199.

### AAG-F041 — Auth token delivery and response checks lack a parent-mediated branch

**Upstream evidence:** 28e8258 Core, "Auth Token Delivery"; "Auth Token Response Verification"; "Parent-Mediated Authorization"

**Submitted:** no

**Remaining:** Delivery and response verification still require cnf to match "the agent's" signing key, with no rule for which agent's key in a parent-mediated request.

Core "Auth Token Delivery" has the PS check that cnf.jwk matches the agent's signing key and requires agents to verify that aud and cnf match their own values. "Auth Token Response Verification" step 4 does the same. In "Parent-Mediated Authorization" the parent makes the request but the token is for the child, so the requester's key and the token's cnf differ and the checks as written fail or are skipped. Our implementation verifies cnf against subagent_token.cnf.jwk and the resource-token context.

**Source:** Core "Auth Token Delivery", "Auth Token Response Verification", "Parent-Mediated Authorization" (28e8258).

**Question:** Should both sections add a parent-mediated branch that checks cnf against the child's key from subagent_token, and say who checks aud?

**Placement:** One focused Core issue on parent-mediated authorization covering AAG-F038, F039 and F041, cross-linking https://github.com/dickhardt/AAuth/issues/199.

### AAG-F042 — The interop profile asks the Resource to verify the wrong signature

**Upstream evidence:** 28e8258 interop-demo-profile, "Surface 5 — Parent-mediated sub-agent token handling"

**Submitted:** no

**Remaining:** "What to verify" still says the auth token is "signed with the sub-agent's key"; the PS or AS signs the JWT, and the sub-agent key is in `cnf` and signs the HTTP request.

**Source:** Interoperability demo profile, `Surface 5 — Parent-mediated sub-agent token handling` ("What to verify"); AAuth Core, `Parent-Mediated Authorization` step 5.

The profile says the Resource confirms the auth token is "signed with the sub-agent's key." The PS (three-party) or AS (four-party) signs the auth token JWT. The sub-agent's key appears in the token's `cnf.jwk`, signs the HTTP request, and is what the Resource checks against `cnf.jwk`. Surface 5 step 6 already states `cnf.jwk` = the sub-agent's key, so only the verification sentence is wrong.

**Question:** Should the profile instead say that the Resource verifies a request signed by the sub-agent whose auth-token `cnf.jwk` matches that request key, with the JWT signature verified against the issuer's JWKS?

**Placement:** Make the editorial change directly in the profile, or add it to a focused Core sub-agent issue with F043–F045.

### AAG-F043 — Parent attenuation has no request parameter

**Upstream evidence:** 28e8258 Core, "Parent-Mediated Authorization"; "Auth Token Request"

**Submitted:** no

**Remaining:** Core still says the parent "can refuse, attenuate, or rate-limit", but the auth token request has no narrowing parameter and the resource token fixes the requested scope.

**Source:** AAuth Core, `Parent-Mediated Authorization` (closing paragraph) and `Auth Token Request` (request parameters).

Core says that because every sub-agent authorization passes through the parent, the parent "can refuse, attenuate, or rate-limit." The sub-agent's resource token is signed by the Resource and fixes the requested scope. The parent's auth token request carries `resource_token`, `presented_token`, and `subagent_token`, and has no parameter that narrows scope. The parent can refuse or delay forwarding, but cannot express attenuation on the wire.

**Question:** Is attenuation meant to require a fresh, narrower resource token from the Resource, or should the parent's auth token request gain an explicit narrowing input?

**Placement:** Open one focused Core sub-agent issue containing F042–F045.

### AAG-F044 — "Own key" does not explicitly require distinct parent and child keys

**Upstream evidence:** 28e8258 Core, "Sub-Agent Identity"; "Parent-Mediated Authorization"

**Submitted:** no

**Remaining:** Sub-Agent Identity still gives the sub-agent "its own ... signing key" without requiring its `cnf.jwk` to differ from the parent's.

**Source:** AAuth Core, `Sub-Agent Identity` and `Parent-Mediated Authorization`.

Core gives a sub-agent "its own `aauth:local@domain` identifier and signing key" and, in Parent-Mediated Authorization, repeatedly contrasts the sub-agent key with the parent's signing key (for example, `agent_jkt` matches the `subagent_token`'s `cnf.jwk`, "not the signing key"). It never states that the two JWKs must differ. If they are equal, the parent can use every credential bound to the sub-agent, and the parent/sub-agent distinction used for audit and revocation is lost. Our implementation requires distinct keys.

**Question:** Should Core explicitly require a sub-agent token's `cnf.jwk` to differ from its parent's current confirmation key, and say which party (AP at issuance, PS at use) checks it?

**Placement:** Add to the focused Core sub-agent issue.

### AAG-F045 — Direct sub-agent PS refusal has no error assignment

**Upstream evidence:** 28e8258 Core, "Single-Level Depth"; "Token Endpoint Error Codes"; "Verification (Server)"

**Submitted:** no

**Remaining:** The PS MUST reject a request signed by a sub-agent, but no status or error is assigned; the header-token rule covers verification failures, and Verification (Server) lists no error for a `parent_agent` signer.

**Source:** AAuth Core, `Single-Level Depth`, `Agent Token Verification` step 3, `Token Endpoint Error Codes`, and `Verification (Server)`.

Core requires a PS to reject a token request signed by an agent whose agent token has a `parent_agent` claim, but assigns no status or error. The error table says the token in the `Signature-Key` header has no codes there and fails with `401` and `Signature-Error`. However, a correctly signed sub-agent request has not failed signature verification, and Verification (Server) lists no `Signature-Error` value for this case. Our implementation first verifies proof of possession, then returns `400 invalid_agent_token` without `Signature-Error`; a forged proof still returns `401` with the signature failure. `invalid_agent_token` is not in the current registry.

**Question:** Which registered response should a correctly signed direct sub-agent request receive: a `401` with a defined `Signature-Error` value, a `403`, or a new token-endpoint error?

**Placement:** Add to the focused Core sub-agent issue.

### AAG-F050 — The two upstream-token presentations are not bound

**Upstream evidence:** 28e8258 Core, "Call Chaining"; "Auth Token Request"; "Upstream Token Verification"; related: https://github.com/dickhardt/AAuth/issues/221

**Submitted:** no

**Remaining:** Each presentation is verified independently, and nothing ties the auth-token request's `upstream_token` to the one the downstream person token was issued from, although the PS now records that token's `(iss, jti)`.

**Source:** AAuth Core, `Call Chaining`, `Person Token Endpoint`, `Auth Token Request`, `Upstream Token Verification`, and `Revocation Cascade` ("Records").

The intermediary presents `upstream_token` when it obtains the downstream person token, and presents one again with the downstream resource token and that person token as `presented_token`. Each presentation is verified independently under Upstream Token Verification. Core does not say whether the second value must be the same compact token, the same `(iss, jti)`, or a token for the same person. Call Chaining allows the same upstream token to be reused for any number of downstream requests, and the PS records the upstream `(iss, jti)` with each person token it issues from one, but only for the revocation cascade. Without a comparison rule, the second request can carry a different valid upstream token, possibly for a different person or mission, than the one the downstream identity was issued from.

**Question:** At the auth token request, must the PS check that `upstream_token` is the token (or same `(iss, jti)`) recorded for the `presented_token` person token? If a later upstream token for the same person is allowed (for example after the first expires), which fields define equivalence?

**Placement:** Comment on issue 221 (cross-request confused deputy in call chaining), which raises the related selection problem at the intermediary, or open a focused Core call-chaining issue.

### AAG-F059 — Mission proposal policy denial has no registered error

**Upstream evidence:** 28e8258 Core, "Mission Creation"; "Mission Approval"; "Mission Endpoint Errors"; "Polling Error Codes"

**Submitted:** no

**Remaining:** Mission Endpoint Errors still defines only invalid_request, mission_not_found and mission_terminated. An immediate denial of a valid proposal has no code. Only a deferred review can end in the polling error `denied`.

**Source:** AAuth Core, `Mission Creation`, `Mission Approval`, `Mission Endpoint Errors`, and `Polling Error Codes`.

The PS may refuse a well-formed mission proposal under its policy. `Mission Endpoint Errors` defines only `invalid_request`, `mission_not_found` and `mission_terminated`. A proposal that goes through a `202` deferred review can end in the polling error `denied`, but an immediate refusal has no defined result. Our implementation currently returns `403 mission_denied`, so that a valid proposal is not reported as malformed.

**Question:** Which registered error and status carry an immediate, terminal refusal of a mission proposal?

**Placement:** Combine with AAG-F009 if Core adopts one policy-denial code for all PS endpoints. Otherwise open a focused mission-endpoint issue.

### AAG-F060 — Person token endpoint has no error for an unknown or foreign mission

**Upstream evidence:** 28e8258 Core, "Person Token Endpoint"; "Mission Endpoint Errors"; "Mission Status Errors"; "Token Endpoint Error Codes"

**Submitted:** no

**Remaining:** The PS MUST reject a mission that is unknown or belongs to another agent, but no code is assigned. invalid_request covers only a missing or malformed mission_s256, and mission_terminated covers only inactive missions.

**Source:** AAuth Core, `Person Token Endpoint`, `Mission Endpoint Errors`, `Mission Status Errors`, and `Token Endpoint Error Codes`.

The person token endpoint must reject a `mission_s256` that names no mission, an inactive mission, or another agent's mission. Its errors say `invalid_request` covers a missing or malformed `mission_s256`, and `Mission Status Errors` assigns `mission_terminated` to inactive missions. A well-formed reference to an unknown mission, or to another agent's mission, has no assigned result. `mission_not_found`, together with its rule that both cases look the same, is defined only for requests to the mission's own URL. Our implementation returns the same `400 invalid_request` body in both cases.

**Question:** Should `mission_not_found` and its rule that both cases look the same also apply at the person token endpoint? Or should the token error registry add a mission-reference error that does not reveal ownership?

**Placement:** Add to the mission-endpoint and error-registry discussion. Issues 84 and 85, both closed, defined the mission endpoint errors but did not cover this.

### AAG-F062 — approved_at does not ensure a globally unique mission digest

**Upstream evidence:** 28e8258 Core, "Mission Approval"; "Mission Identifier"

**Submitted:** no

**Remaining:** The blob member list still says approved_at "Ensures the s256 is globally unique". The blob has no nonce or approver member, so identical approvals still hash to the same value.

**Source:** AAuth Core, `Mission Approval` and `Mission Identifier`.

`Mission Approval` says `approved_at` ensures that `s256` is globally unique. Two approvals with the same agent, timestamp, description and optional members have identical bytes, and therefore the same digest. This can happen with a coarse or deterministic clock. The blob has no nonce, and `Mission Identifier` says it deliberately carries no approver member. It names the mission by the pair of PS and `s256`, so two different PSes could also produce the same blob.

Our implementation adds no private mission member. Its store rejects a second identical identifier as a conflict, rather than silently treating a new approval as the old mission.

**Question:** Should the blob include a required unique value? Or should Core drop the global-uniqueness claim, scope uniqueness to the PS and `s256` pair, and define identical approvals at one PS as the same mission?

**Placement:** Open a focused Core mission-identity issue. No existing issue discusses uniqueness.

### AAG-F063 — Mission update does not define the exact hashed artifact

**Upstream evidence:** 28e8258 Core, "Mission Update"; "Mission Log"; "Mission Management"

**Submitted:** no

**Remaining:** Update digest still covers "the update's bytes as the PS persists them"; no retrieval representation for accepted updates; reads deferred to a companion spec at mission_control_endpoint.

**Source:** AAuth Core (28e8258), "Mission Update", "Mission Log", and "Mission Management".

An accepted update returns the digest of the update bytes as the PS persists them, but Core does not say whether those bytes are the authenticated request body, a canonical re-encoding, or a person-edited result. The mission log is meant to let auditors see accepted updates, yet Core defines no retrieval representation that supplies those bytes; "Mission Management" leaves reads to a companion specification at the `mission_control_endpoint`.

Our implementation persists and hashes the exact authenticated request body.

**Question:** Which exact bytes does an accepted update digest identify, and should mission inspection return those bytes plus their acceptance order?

**Placement:** Open a focused Core mission-update exactness issue. Issue #49 (mission-log completeness) is related but does not cover this.

### AAG-F064 — Mission update and completion denial errors are absent

**Upstream evidence:** 28e8258 Core, "Mission Endpoint Errors"; "Mission Update"; "Mission Completion"

**Submitted:** no

**Remaining:** Mission Endpoint Errors still lists only invalid_request, mission_not_found, mission_terminated; no immediate refusal defined for update or completion.

**Source:** AAuth Core (28e8258), "Mission Update", "Mission Completion", and "Mission Endpoint Errors".

Core defines acceptance or deferred review for an update, and acceptance or clarification follow-up for completion. It does not say whether either action may instead receive an immediate terminal refusal. If that is allowed, the error registry has no result for it: "Mission Endpoint Errors" lists only `invalid_request` (400), `mission_not_found` (404), and `mission_terminated` (403). `invalid_request` would misdescribe valid input, and `mission_terminated` would misdescribe a mission that remains active.

Our implementation provisionally returns `403 mission_update_denied` or `403 mission_completion_denied` and leaves the mission unchanged.

**Question:** May an update or completion request end in immediate refusal? If so, should Core register one mission-action denial result or distinct update and completion results, and which statuses should they use?

**Placement:** Combine with AAG-F059 if Core adopts one policy-denial family for mission actions; otherwise open one focused endpoint-error issue.

### AAG-F065 — Mission action uncertain success has no recovery identity

**Upstream evidence:** 28e8258 Core, "Mission Update"; "Mission Completion"; "Deferred Response State Machine"

**Submitted:** no

**Remaining:** No request identifier, lookup, or replay rule for update or completion; a lost 200 still cannot be recovered safely.

**Source:** AAuth Core (28e8258), "Mission Update", "Mission Completion", and "Deferred Response State Machine".

An update request has no request identifier, and the endpoint defines no lookup or replay rule. If its `200` response is lost, resending the same body may append the same update twice. Completion has the same uncertainty after the person has accepted: storage or response delivery can fail, and a retry may ask the person again or hit the already terminated mission.

Our implementation sends one mission-action POST and never retries it automatically; it does not claim that a lost success can be recovered or safely repeated.

**Question:** How may an Agent recover an accepted update or person-accepted completion after an uncertain response without repeating either consequence?

**Placement:** Open a focused Core mission-action recovery issue.

### AAG-F066 — Core contradicts itself on update acceptance authority

**Upstream evidence:** 28e8258 Core, "Mission"; "Mission Update"

**Submitted:** no

**Remaining:** Mission intro still says for all three operations the agent proposes and the person decides; Mission Update still says the PS MAY accept the update on its own.

**Source:** AAuth Core (28e8258), "Mission" and "Mission Update"; related: Security Considerations, "Incremental Consent".

The "Mission" overview says all three Agent operations have one shape: the Agent proposes and the person decides. "Mission Update" says the PS may accept an update on its own or defer while the person reviews it. These assign different decision-makers to the same operation.

Our implementation follows the update-specific rule: the PS may accept an update by its own policy, while completion requires a host callback confirming actual person acceptance.

**Question:** May the PS autonomously accept an update, or must every accepted update represent a person decision?

**Placement:** Open a focused editorial issue for the conflicting mission overview and update-specific rule.

### AAG-F067 — Termination does not define outstanding credential behavior

**Upstream evidence:** 28e8258 Core, "Revocation Cascade"; "Mission Management"; "Mission Status Errors"; "Presenting a Revoked Token"

**Submitted:** no

**Remaining:** Partly addressed: Revocation Cascade now says a PS revoking a mission SHOULD revoke outstanding auth tokens; person/resource tokens, non-revoked terminal states, and resource signaling remain undefined.

**Source:** AAuth Core (28e8258), "Mission Update", "Mission Management", "Mission Status Errors", "Revocation Cascade", and "Presenting a Revoked Token".

Core says updates leave existing mission-bound tokens valid and that a terminated mission rejects later PS requests. "Revocation Cascade" now covers one case: when the PS revokes a mission it marks the mission revoked, denies later token requests, and SHOULD revoke outstanding auth tokens issued under it. Gaps remain:
- Nothing covers outstanding person tokens or resource tokens.
- Nothing covers missions that end for other reasons (completed, expired, or other terminal states in "Mission Management"); those states say nothing about credentials.
- Auth-token revocation is only SHOULD.
- Per "Presenting a Revoked Token", a resource learns of revocation only through its own revocation endpoint, and resources receive only the mission digest, not mission state.

Our implementation closes later PS decisions after termination; outstanding credentials stay cryptographically usable until their own expiry, and a conforming Agent must stop using them.

**Question:** Is mission termination, for every terminal reason, intended only to close future PS decisions, or must it invalidate all outstanding mission-bound credentials? If invalidation is required, how does a resource learn it without receiving private mission state?

**Placement:** Open a focused Core mission-termination propagation issue.

### AAG-F068 — Retry-After is required but also has an absence default

**Upstream evidence:** 28e8258 Core, "Pending Response"; "Polling with GET"

**Submitted:** no

**Remaining:** Pending Response still marks Retry-After REQUIRED while Polling with GET still gives a 5-second default when absent.

**Source:** AAuth Core (28e8258), "Pending Response" and "Polling with GET".

"Pending Response" marks `Retry-After` REQUIRED. "Polling with GET" says that when it is absent the default interval is five seconds. Both cannot describe the same receiver requirement.

Our implementation accepts an absent header and applies the five-second fallback; present values must be one valid nonnegative delay.

**Question:** Should `Retry-After` be optional with a five-second default, or required with absence treated as a malformed deferred response?

**Placement:** Open a focused deferred-response clarification issue.

### AAG-F069 — Immediate auth-token issuance has no exact-result recovery identity

**Upstream evidence:** 28e8258 Core, "Resource Token Structure"; "Freshness and Replay"; "Auth Token Request"; "PS Response"; "Auth Token Delivery"

**Submitted:** no

**Remaining:** Resource tokens are "consumed in a single token request" with no replay cache required; no idempotency or result lookup for an issued auth token after a lost response.

**Source:** AAuth Core (28e8258), "Resource Token Structure", "Freshness and Replay", "Auth Token Request", "PS Response", and "Auth Token Delivery".

The resource token has a unique `jti`, and "Freshness and Replay" says resource tokens are consumed in a single token request, while "Resource Token Structure" says ASes need no replay detection for them. Core does not say that an immediate exchange is idempotent for one resource token or define a lookup for its result. A PS can retain an issuance and still lose the store result or client response. Retaining only audit claims cannot reproduce the credential, and repeating the exchange may cause the AS to issue another valid token.

Our implementation commits the issuance record before releasing the token and never retries internally; an explicit repeat may produce another independently audited token.

**Question:** Should an immediate auth-token request be idempotent for one resource-token identity, with bounded exact-result replay after uncertain success, or is issuing another token on explicit retry intended?

**Placement:** Open a focused Core token-issuance recovery issue.

### AAG-F070 — Immediate policy denial has no token-endpoint error

**Upstream evidence:** 28e8258 Core, "Token Endpoint Error Codes"; "Auth Token Delivery"; "Polling Error Codes"; "Interaction Callback Errors"

**Submitted:** no

**Remaining:** Registry still has no immediate policy-denial code; as_unreachable mentions an AS denial the PS relays but no code is registered; denied exists only for polling, access_denied only for callbacks.

**Source:** AAuth Core (28e8258), "Token Endpoint Error Codes", "Auth Token Delivery", "Polling Error Codes", and "Interaction Callback Errors".

"Token Endpoint Error Codes" defines `server_error` for internal failure but no immediate result for a PS consent or AS authorization policy that intentionally refuses an otherwise valid request. The `as_unreachable` entry says it is distinct from an AS denial, which the PS relays, and "Auth Token Delivery" relays the AS error value, but no denial code is registered. `denied` (403) appears only in "Polling Error Codes" for deferred requests, and `access_denied` only in "Interaction Callback Errors".

Our implementation provisionally returns `403 access_denied` only when a host callback signals an explicit denial; other callback errors return `500 server_error`.

**Question:** May immediate PS and AS policy refuse a valid token request, and if so which registered error and status should represent that decision?

**Placement:** Open a focused Core token-endpoint error registry issue, or combine with AAG-F009 and AAG-F059 as one policy-denial family.

### AAG-F072 — Bootstrap names `jti` replay protection without defining replay

**Upstream evidence:** 28e8258 Bootstrap, "Refresh Patterns" > "Two-Key Refresh"; 69f5ba2 signature-key, "JKT JWT Self-Issued Key Delegation (jkt-jwt)" and "Client Processing"

**Submitted:** no

**Remaining:** Bootstrap still says the naming JWT carries "a `jti` for replay protection"; Signature-Key still requires `jti` only for caching and defines no replay contract.

**Source:** AAuth Bootstrap (28e8258), `Refresh Patterns` > `Two-Key Refresh`; HTTP Signature Keys (69f5ba2), `JKT JWT Self-Issued Key Delegation (jkt-jwt)` and `Client Processing`.

Bootstrap says the naming JWT carries a `jti` for replay protection. Signature-Key makes `jti` OPTIONAL on a `jkt-jwt`, REQUIRED only when the JWT is presented with `cache`, and its verification procedure neither consumes nor retains it. Neither document defines the replay key's namespace, its retention lifetime, what exact request it binds, what a duplicate returns, or how a client recovers a lost response.

Our implementation requires `jti`, keys it by the durable-key thumbprint, binds the exact naming JWT and JSON body, requires a freshly signed outer retry, returns the first Agent token on an exact retry, and rejects changed input. These are implementation choices, not requirements read from the text.

**Question:** Should Bootstrap define the minimum replay and lost-response contract for a two-key refresh, or state explicitly that each AP profile must define it?

**Placement:** Open a focused Bootstrap/Signature-Key cross-spec issue.

### AAG-F073 — The delegated request-key algorithm is described as enclave-determined

**Upstream evidence:** 69f5ba2 signature-key, "JKT JWT Self-Issued Key Delegation (jkt-jwt)"

**Submitted:** no

**Remaining:** The paragraph after the example still ends "The `cnf.jwk` request key algorithm is likewise enclave-determined," although the same section says the ephemeral key is signed in software. The signature-key tracker was not available locally to check for an existing issue.

**Source:** HTTP Signature Keys (69f5ba2), `JKT JWT Self-Issued Key Delegation (jkt-jwt)`; AAuth Bootstrap (28e8258), `Per-Platform Key Handling` > `Mobile (iOS and Android)` and `Refresh Patterns` > `Two-Key Refresh`.

Both documents describe the fresh ephemeral request key as generated in software; the Signature-Key example explanation says the Ed25519 ephemeral key is "signed in software". The next paragraph says the stable key's algorithm is determined by the enclave hardware, then adds that the `cnf.jwk` request key algorithm is "likewise enclave-determined". That describes the durable platform key, not the delegated key. Our implementation treats both algorithms as explicit supported inputs and currently supports Ed25519 only.

**Question:** Should the text say that the durable signing algorithm is platform-determined, while the client chooses the delegated request-key algorithm from those the verifier supports?

**Placement:** Open or add to a Signature-Key `jkt-jwt` clarification issue after checking that tracker.

### AAG-F074 — Stable Agent `sub` does not distinguish the two key rotations

**Upstream evidence:** 28e8258 Core, "Agent Identifiers" and "Agent Token Structure"; Bootstrap, "Per-Install Identity" and "Key Rotation vs Token Refresh"

**Submitted:** no

**Remaining:** Core still says the agent identifier and `sub` are "stable across key rotations" without qualification; Bootstrap still says a new durable key produces a new agent identity.

**Source:** AAuth Core (28e8258), `Agent Identifiers` and `Agent Token` > `Agent Token Structure`; AAuth Bootstrap (28e8258), `Agent Identifier Strategies` > `Per-Install Identity` and `Refresh Patterns` > `Key Rotation vs Token Refresh`.

Core says an agent identifier is stable across key rotations, and describes `sub` the same way. Bootstrap keeps `sub` when only the ephemeral token key changes, but treats a new durable enrollment key as a new agent with a new `sub`. Our API makes the distinction explicit: refresh rotates the ephemeral key under one enrollment, and a different durable key does not enter that enrollment.

**Question:** Should Core distinguish proof-key rotation from replacement of the key an AP enrolls against when it states that `sub` is stable?

**Placement:** Open a focused Core/Bootstrap terminology issue.

### AAG-F075 — Bootstrap examples use AP-internal endpoints after removing discovery

**Upstream evidence:** 28e8258 Bootstrap, "Per-Platform Enrollment Sketches", "Refresh Patterns" > "Two-Key Refresh", and "Document History"

**Submitted:** no

**Remaining:** The sketches still name unnamed "AP-internal" enrollment and token-issuance endpoints and the refresh example still posts to `/refresh`; no portable wire format or explicit no-wire statement was added.

**Source:** AAuth Bootstrap (28e8258), `Introduction` > `What Bootstrapping Is Not`, `Refresh Patterns` > `Two-Key Refresh`, `Per-Platform Enrollment Sketches`, and `Document History`.

Bootstrap -01 removed `bootstrap_endpoint`, `refresh_endpoint`, and `webauthn_endpoint` from AP metadata. The enrollment sketches still use unnamed AP-internal enrollment and token-issuance endpoints, and the refresh example posts to `/refresh`. The document is informational and says the sketches are illustrative, so independent implementations can follow the same key pattern while exposing incompatible routes, bodies, status codes, and errors. Our implementation therefore requires the application to supply AP URLs and labels its JSON as an implementation choice.

**Question:** Should Bootstrap include one explicitly non-normative reference HTTP profile for interoperability, or state directly that it defines only the key and role pattern and intentionally provides no portable wire format?

**Placement:** Open a Bootstrap scope question; do not present our profile as defined by the source.

### AAG-F077 — GraphQL introspection cannot discover client operation names

**Upstream evidence:** 28e8258 R3, "GraphQL Vocabulary (`urn:aauth:vocabulary:graphql`)" and "Operation Identifier Scope"

**Submitted:** no

**Remaining:** Text unchanged: identifier is a client-authored operation name discovered "via GraphQL introspection"; Operation Identifier Scope also claims operation names are unique "within a schema".

**Source:** AAuth R3 (28e8258), `Vocabularies` > `Operation Identifier Scope` and `Standard Vocabularies` > `GraphQL Vocabulary (urn:aauth:vocabulary:graphql)`; GraphQL, `Operation Name Uniqueness` and `Schema Introspection`.

R3 identifies a GraphQL operation by a named query, mutation, or subscription plus its type, and says an agent discovers available operations through introspection. `Operation Identifier Scope` adds that GraphQL operation names are unique within a schema. GraphQL operation names belong to executable documents written by clients; introspection exposes the server schema, not a registry of client documents or their operation names. Our GraphQL adapter detects an introspection response with `data.__schema` and then refuses with `operation_identity_unavailable`. A Resource therefore cannot check an R3 identifier against ordinary schema introspection.

**Question:** Should the identifier name a schema root field, require a persisted-operation registry, or define another server-owned operation catalog?

**Placement:** Open a focused R3 vocabulary issue with a counterexample showing introspection output that lacks any operation names.

### AAG-F078 — WSDL `service` plus `operation` does not identify one bound operation

**Upstream evidence:** 28e8258 R3, "WSDL Vocabulary (`urn:aauth:vocabulary:wsdl`)"

**Submitted:** no

**Remaining:** Text unchanged: only `operation` (from portType or binding) and optional `service`; no port, binding, or portType identifier.

**Source:** AAuth R3 (28e8258), `Standard Vocabularies` > `WSDL Vocabulary (urn:aauth:vocabulary:wsdl)`; WSDL 1.1, `Services, Ports, and Bindings` and `Port Types`.

In WSDL a service contains ports, each port selects a binding, and each binding selects a port type. Operation names are scoped below those definitions. R3 supplies only `operation`, taken from "the WSDL `portType` or `binding`", and an optional `service`. That pair cannot distinguish several ports or bindings under one service, and it does not name the port type that WSDL's own identifiers use. Our WSDL adapter derives operations that are uniquely bound and refuses with `operation_identity_ambiguous` when the `service` and `operation` pair would cover distinct bindings.

**Question:** Should the R3 operation entry include the binding, port, or port type needed to identify the operation the advertised WSDL actually selects?

**Placement:** Open a focused R3 vocabulary issue.

### AAG-F079 — OData method narrowing and overload identity are undefined

**Upstream evidence:** 28e8258 R3, "OData Vocabulary (`urn:aauth:vocabulary:odata`)", "Operations Spanning Multiple Definitions", and "Auth Token Extensions"

**Submitted:** no

**Remaining:** Text unchanged: `methods` array with no set semantics, issuer MAY narrow operations without method rules, and bound operations named only `EntitySet/Name`.

**Source:** AAuth R3 (28e8258), `Standard Vocabularies` > `OData Vocabulary (urn:aauth:vocabulary:odata)`, `Authorization Endpoint Extensions` > `Operations Spanning Multiple Definitions`, and `Auth Token Extensions`; OData CSDL, function and action overloads.

R3 puts an HTTP `methods` array inside one OData operation entry, composes multiple definitions by taking the union of operations, and lets the issuer narrow a grant to fewer operations. It does not say whether method order matters, whether a grant may narrow `["GET","POST"]` to `["GET"]`, or how an entry without `methods` relates to one with them. Separately, OData functions and actions can be overloaded by binding type and parameters, while R3 names only `EntitySet/FunctionName` or `EntitySet/ActionName`. Our OData adapter refuses overloaded bound operations and derives no method-qualified authority.

**Question:** Should R3 define `methods` as a set with subset and union semantics, and extend bound function and action identifiers enough to name one overload?

**Placement:** Open a focused R3 vocabulary issue; split method algebra from overload identity if the editor prefers.

### AAG-F080 — AsyncAPI optional `action` has no matching rule

**Upstream evidence:** 28e8258 R3, "AsyncAPI Vocabulary (`urn:aauth:vocabulary:asyncapi`)"

**Submitted:** no

**Remaining:** `action` is still OPTIONAL with no rule for how an omitted action compares with the required native action.

**Source:** AAuth R3 (28e8258), `Standard Vocabularies` > `AsyncAPI Vocabulary (urn:aauth:vocabulary:asyncapi)`; AsyncAPI 3, `Operation Object`.

R3 makes `action` OPTIONAL, while the AsyncAPI Operation Object requires `send` or `receive`. R3 does not say whether an omitted action is filled in from the discovered operation, authorizes either action, or is a distinct operation value. Each reading produces different grant and proposal matching. Our AsyncAPI adapter derives the required native `action` and refuses malformed or unresolved operations, but an R3 request that omits `action` still has no specified comparison against that definition.

**Question:** Should omission mean "resolve the required action from the `operationId`", or should R3 require `action` whenever the entry is used for authorization?

**Placement:** Add to the R3 vocabulary issue set.

### AAG-F081 — Per-call parameter projection is not defined by vocabulary

**Upstream evidence:** 28e8258 R3, "Per-Call Proposals" > "Proposal Document" and "Flow"

**Submitted:** no

**Remaining:** `parameters` is still one JSON object with structural and digest comparison but no vocabulary-specific mapping; the new SHOULD-use-202 advice avoids the retry comparison but does not define projection or say which streaming calls cannot use 401 replay.

**Source:** AAuth R3 (28e8258), `Per-Call Proposals` > `Proposal Document` and `Flow`, and the seven subsections of `Standard Vocabularies`.

A proposal carries a JSON `parameters` object, and on a `401` retry the Resource compares inline values structurally and digest values by `s256`. Only MCP maps naturally to one argument object. OpenAPI can have same-named path, query, header, and cookie parameters plus a body; gRPC and AsyncAPI may stream messages; GraphQL has a document, an operation selection, variables, and fragments; WSDL has XML/SOAP bindings and attachments. R3 now recommends `202` deferred delivery, which avoids the retry comparison, but a Resource that uses `401` still has no vocabulary-specific projection. Two conforming Resources can describe and verify the same call differently.

**Question:** Should each vocabulary define a canonical parameter projection and retry comparison boundary, and state which streaming calls cannot use `401` replay?

**Placement:** Open a focused R3 per-call interoperability issue after the operation-identity questions are settled.

### AAG-F082 — OData annotation encoding lacks a resolvable term namespace and target

**Upstream evidence:** 28e8258 R3, "Operation Access Annotations" > "Vocabulary Encodings"; R3, "OData Vocabulary (`urn:aauth:vocabulary:odata`)"

**Submitted:** no

**Remaining:** Still names `AAuth.AccessMode` and `AAuth.Budget` with no CSDL vocabulary namespace or reference, and targets "the entity set or bound operation the R3 operation identifier names" with no overload form.

**Source:** AAuth R3 (28e8258), `Operation Access Annotations` > `Vocabulary Encodings` and `Standard Vocabularies` > `OData Vocabulary (urn:aauth:vocabulary:odata)`; OData CSDL, vocabulary references and bound operation overloads.

The encoding table names the terms `AAuth.AccessMode` and `AAuth.Budget`, but R3 does not define the CSDL vocabulary namespace or the reference needed to resolve them. It applies the annotation to "the entity set or bound operation the R3 operation identifier names", and that identifier cannot pick one overload of a bound operation. An implementation cannot validate the annotation or attach it to one R3 operation without inventing both. Our OData adapter refuses AAuth annotations and overloaded bound operations instead of guessing.

**Question:** Should R3 define the OData vocabulary namespace and its reference, plus an annotation target form that identifies one bound operation overload?

**Placement:** Open a focused R3 OData annotation issue and cross-link AAG-F079.

### AAG-F083 — Standard R3 vocabularies do not identify external specification revisions

**Upstream evidence:** 28e8258 R3, "Standard Vocabularies" and its seven subsections; R3 front-matter references

**Submitted:** no

**Remaining:** R3 still cites no reference or version for MCP, OpenAPI, gRPC, GraphQL, AsyncAPI, WSDL, or OData; its references list only the AAuth drafts and the transaction-challenge draft.

**Source:** AAuth R3 (28e8258), `Vocabularies` > `Standard Vocabularies` and its seven vocabulary subsections; the document's reference list.

R3 assigns operation identities, discovery behavior, and annotation encodings to MCP, OpenAPI, gRPC, GraphQL, AsyncAPI, WSDL, and OData, but cites no version or stable reference for any of them. Its references cover only the AAuth drafts and the OAuth transaction-challenge draft. These formats change independently, so two conforming implementations can choose different Tool rules, introspection behavior, Operation Objects, or metadata grammars while following the same R3 text. Our implementation keeps its own table of exact format revisions to make its choices reproducible; a local table cannot make the R3 contract interoperable.

**Question:** Should R3 add normative references and a stated revision policy for each standard vocabulary, including how newer compatible revisions are admitted?

**Placement:** Open one cross-vocabulary source-reference issue before filing format-specific interpretation questions.

### AAG-F084 — Events leaves subscription-registration parameters outside the signed content digest

**Upstream evidence:** 28e8258 Events, "Subscribe Token" > "Presentation"; Events, "Subscription Registration" > "Public Subscriptions"; Core, "Covered Components"

**Submitted:** no

**Remaining:** Registration example still covers content-type but not content-digest, and Core mandates the digest only at PS/AS and revocation endpoints; Events added the MUST for event delivery bodies (PR 207) but not for registration.

**Source:** AAuth Events (28e8258), `Subscribe Token` > `Presentation` and `Subscription Registration` > `Public Subscriptions`; AAuth Core (28e8258), `HTTP Message Signatures Profile` > `Covered Components`.

The subscription registration request body selects event types and other parameters the Resource defines. The `Presentation` example covers `content-type` but not `content-digest`, and neither `Verification` nor `Public Subscriptions` adds a body-binding requirement. Core requires `content-digest` and `content-type` only on bodies sent to a PS or AS endpoint or to a revocation endpoint; other Resource endpoints declare their needs through `additional_signature_components`. The subscription endpoint, like the revocation endpoint and the AP event endpoint, is defined by a specification rather than by the Resource's own API. Events now requires both components on event delivery bodies (`Event Delivery: Resource to AP` > `Request`), but not on registration.

Our implementation requires both components whenever registration parameters are present. Its bodyless form signs the digest of zero bytes.

**Question:** Should Events require `content-digest` on subscription registration requests, with `content-type` also required when the body is nonempty, as it now does for event delivery?

**Placement:** Open a focused Events issue that cites the Core `Covered Components` rule for revocation endpoints and the event-delivery rule added in PR 207.

### AAG-F088 — First-hop denomination selection contradicts numeric narrowing

**Upstream evidence:** 28e8258 Budgets, "The Narrowing Chain"

**Submitted:** no

**Remaining:** Text is unchanged in substance. It still says "Each stage MUST NOT exceed the previous stage" and calls the resource token figure "the minimum of the two, exactly as scope is", while letting the resource change `unit`. It defines no comparison across units.

**Source:** AAuth Budgets (28e8258), `The Narrowing Chain`.

The section opens with "Each stage MUST NOT exceed the previous stage." It later says the resource token's single figure is "the minimum of the two" (the Agent request and the Resource maximum), "exactly as `scope` is". The same section lets the Resource change `unit`, for example from tokens to a currency amount. It fixes `unit` and `decimals` only for the later stages, and it tells the Agent that the granted budget may not be directly comparable to its request. Neither a numeric no-increase rule nor "minimum" means anything across that first change of denomination.

Our implementation treats a cross-unit Resource offer as a Resource policy decision. It does not compare the offer numerically with the Agent's request.

**Question:** Is the Resource's choice of denomination an explicit exception to the first-hop no-increase rule and the "minimum" wording? If it is not, what conversion or ordering proves that an offer in a different denomination does not exceed the request?

**Placement:** Open a focused Budgets narrowing issue, with the cross-unit Resource offer policy as implementation evidence.

### AAG-F092 — Ambiguous failure has no interoperable maximum-cost input

**Upstream evidence:** 28e8258 Budgets, "Ambiguous Failures", "The Budget Is a Hard Cap", "Refusing a Request That Does Not Fit"

**Submitted:** no

**Remaining:** The gap is narrower but still there. `reserved` now covers streamed responses. For a lost non-streamed response the Agent must still assume "the request's maximum cost as the resource would have bounded it", which comes from a request bound or a "documented default". The draft still requires no Resource to publish costs, and `required` appears only on refusals.

**Source:** AAuth Budgets (28e8258), `Ambiguous Failures`, `The Budget Is a Hard Cap`, and `Refusing a Request That Does Not Fit`.

When a response is lost, the Agent MUST assume the request cost what the Resource held for it. That is `reserved` if the Agent saw one, and otherwise "the request's maximum cost as the resource would have bounded it". `The Budget Is a Hard Cap` says this maximum comes from a bound the request declares or from a documented default. `Refusing a Request That Does Not Fit` says "no part of this specification requires a resource to publish what an operation costs". `required` is sent only with an `insufficient-budget` refusal. For a non-streamed request whose response never arrives, the Agent saw no `reserved`. A generic Agent therefore cannot derive or check the figure it is required to assume.

Our implementation falls back to the full signed grant when no interoperable bound is available.

**Question:** Should the protocol say how an Agent learns the Resource's maximum for ambiguous-failure accounting? Alternatively, should it explicitly require the full remaining grant as the conservative fallback when no `reserved` was seen and no interoperable bound exists?

**Placement:** Open a focused Budgets ambiguous-failure issue, with the full-grant fallback as implementation evidence.

### AAG-F093 — Clarification timeout has no recipient reference instant

**Upstream evidence:** 28e8258 Core, "Clarification Required"

**Submitted:** no

**Remaining:** Unchanged. `timeout` is still "Seconds until the server times out the request. The recipient MUST respond before this deadline." The text does not say when the interval starts and carries no absolute deadline.

**Source:** AAuth Core (28e8258), `Clarification Required` (under `Clarification Chat`).

The `202` clarification body carries `timeout` as "Seconds until the server times out the request", and the recipient MUST respond before that deadline. The text does not say whether the interval starts when the server creates the response, when it sends it, or when the recipient receives it. Because of network delay, a recipient cannot work out the server's exact deadline from the wire value alone.

Our Agent uses the moment it finishes validating the response as its local reference, and refuses a locally late answer before any network I/O. The Person Server separately enforces its own retained deadline. The Agent's local check therefore does not prove where the server's clock boundary falls.

**Question:** What instant starts `timeout`? Should the response carry an absolute deadline or a signed response time, so recipients can meet the MUST without guessing across transport delay and clock skew?

**Placement:** Open a focused Core clarification-timing issue.

### AAG-F094 — Clarification actions have no success-response contract

**Upstream evidence:** 28e8258 Core, "Clarification Response", "Cancel Request", "Deferred Response State Machine"

**Submitted:** no

**Remaining:** Unchanged. The POST `clarification_response` section still says only "the agent resumes polling with GET". Cancel Request says only that later requests return 410. The state machine covers the initial request and GET polls, not the POST and DELETE actions.

**Source:** AAuth Core (28e8258), `Agent Response to Clarification`, `Clarification Response`, `Cancel Request`, and `Deferred Response State Machine`.

The draft defines the signed POST (`action=clarification_response`) and the signed DELETE to the pending URL. After the POST it says only that the Agent resumes polling with `GET`. After the DELETE it says only that later requests return `410 Gone`. The only defined error is `400` for a missing or unrecognized `action`. Neither action has a success status, response body, cache rule, or error mapping, and the `Deferred Response State Machine` covers only the initial request and `GET` polls. An implementation that requires one particular status can reject a compatible server. One that accepts any response can mistake a failed action for success.

Our Agent treats any `2xx` as acceptance of the action and takes no terminal authorization from that response; the next poll is a separate, explicit request. It refuses redirects and non-`2xx` responses, and never polls or retries without being told to.

**Question:** Which status codes and response fields are valid after `clarification_response` and after cancellation? Must successful responses carry `Cache-Control: no-store`?

**Placement:** Open a focused Core clarification-action response issue.

### AAG-F095 — Clarification answers do not identify their question

**Upstream evidence:** 28e8258 Core, "Agent Response to Clarification", "Clarification Response", "Clarification Limits"

**Submitted:** no

**Remaining:** Unchanged. The answer POST still carries only `action` and the Markdown `clarification_response` on a pending URL shared by all rounds. Clarification Limits now makes a round maximum a MUST (five RECOMMENDED), so the text expects dialogues of several rounds.

**Source:** AAuth Core (28e8258), `Agent Response to Clarification`, `Clarification Response`, and `Clarification Limits`.

Every round uses the same pending URL, and the answer POST carries only `action=clarification_response` and the Markdown answer. Suppose the server accepts one answer and then opens a later question. A delayed replay of the first POST cannot then be told apart from an answer to the later question. PSes MUST enforce a maximum number of rounds and five is RECOMMENDED, so dialogues of several rounds are expected and this is not a rare edge case.

Our implementation sends each answer as one explicit request with no hidden retry. It allows only one round until the wire carries a binding between answer and question. It can make an exact replay idempotent while the answered round is still the latest, but it cannot recover a round identity that the request never carried.

**Question:** Should each clarification response name a stable round identifier or question digest supplied by the `202` response, so that retries and delayed delivery cannot bind an answer to a different question?

**Placement:** Open a focused Core clarification-correlation issue.

### AAG-F096 — Permission denial has two terminal wire representations

**Upstream evidence:** 28e8258 Core, "Permission Response"; Core, "Deferred Response State Machine"; Core, "Polling Error Codes"

**Submitted:** no

**Remaining:** Unchanged since a99d353; Permission Response still defines 200 permission=denied while the deferred state machine and polling errors define 403 denied, and nothing says which a deferred Permission decision uses.

**Source:** AAuth Core, `Permission Response`, `Deferred Response State Machine`, and `Polling Error Codes`.

The Permission Endpoint says an immediate grant or denial returns `200` with a `permission` field. If the PS needs user input it returns a deferred response and the agent "polls until a final response". The generic deferred state machine and the Polling Error Codes table say a terminal denial on the pending URL returns `403` with `error=denied`. The Permission text does not say whether a deferred permission decision returns the endpoint-specific body or the generic polling problem.

Our Person Server returns the endpoint-specific `200` decision for both immediate and deferred results. Our Agent accepts that and also recognizes `403 denied` while polling, but no implementation can tell from the current text which form another server will emit.

**Question:** Should a deferred Permission denial return the same `200 permission=denied` body as an immediate decision, or the generic `403 denied` polling problem?

**Placement:** Open a focused Core Permission Endpoint issue.

### AAG-F097 — The Permission Endpoint has no error table

**Upstream evidence:** 28e8258 Core, "Permission Endpoint" / "Permission Request" / "Permission Response"; Core, "Error Responses" ("Token Endpoint Error Codes", "Polling Error Codes")

**Submitted:** no

**Remaining:** -11 added endpoint-specific tables for Interaction ("Interaction Endpoint Errors") and Mission ("Mission Endpoint Errors"), but the Permission Endpoint still names only mission status errors and no registry for the initial POST.

**Source:** AAuth Core, `Permission Endpoint`, `Permission Request`, `Permission Response`, `Mission Status Errors`, and `Error Responses` (`Token Endpoint Error Codes`, `Polling Error Codes`).

The endpoint can receive malformed input, an unknown or terminated `mission_s256`, a policy or storage failure, an expired pending request, an identity-mismatched poll, or an already consumed reference. Permission Response names only mission status errors. Core now gives the Interaction Endpoint and the Mission Endpoint their own error tables, but the Permission Endpoint has none, and the Error Responses section does not say whether the Token Endpoint Error Codes apply to the initial Permission POST.

Our implementation uses `invalid_request` for malformed input or an unknown mission at initial submission, the mission status error for termination, `server_error` for operational failure, and the polling errors on the pending URL. These are local choices, not a conformance claim.

**Question:** Which error table applies to the initial Permission request, and should the endpoint define any additional policy or mission-reference errors?

**Placement:** Combine with the Permission response issue (AAG-F096) if the editors prefer one endpoint-contract pass.

### AAG-F098 — An uncertain initial Permission submission cannot be recovered

**Upstream evidence:** 28e8258 Core, "Permission Request"; Core, "Deferred Responses" ("Initial Request", "Polling with GET")

**Submitted:** no

**Remaining:** Permission Request still has no request identifier or idempotency key; the only retained-result rule in Core covers deferred auth-token delivery and R3 per-call grants, not Permission.

**Source:** AAuth Core, `Permission Request`, `Deferred Responses` (`Initial Request`, `Polling with GET`), and `Pending URL Security`.

The initial signed POST carries `action`, `description`, `parameters`, and `mission_s256`, but no request identifier, idempotency key, or lookup reference. If transport fails after the Person Server accepts and retains the request, the Agent cannot discover whether a decision exists or recover its pending URL. Repeating the POST may create a second person-visible request and a second decision. Core defines retained-result replay only for deferred auth-token delivery and R3 per-call grants.

Our Agent performs the POST exactly once and returns a typed uncertain-outcome error after a transport failure, malformed success, or non-retryable server failure. A definite `4xx` rejection stays ordinary; `429` and `503` stay with the caller under the backoff rules. The Agent does not retry or claim recovery.

**Question:** Should Permission requests carry a stable caller-selected identity, or should the Person Server define exact-request replay and lookup semantics for uncertain initial submissions?

**Placement:** Cross-link a general deferred initial-request recovery discussion (with AAG-F101) rather than treating this as a Permission-only transport issue.

### AAG-F099 — The Audit Endpoint has no endpoint-specific error contract

**Upstream evidence:** 28e8258 Core, "Audit Request" / "Audit Response"; Core, "Mission Status Errors"; Core, "Error Responses"

**Submitted:** no

**Remaining:** Audit Response still names only mission status errors; no mapping for malformed input, owner mismatch, or store failure.

**Source:** AAuth Core, `Audit Request`, `Audit Response`, `Mission Status Errors`, and `Error Responses`.

Audit Response names mission status errors, but not how to report malformed JSON, invalid parameter shapes, a `mission_s256` belonging to another Agent, or an audit-store failure. Core now gives the Interaction and Mission endpoints their own error tables; the Audit Endpoint has none, and the Error Responses section does not assign one.

Our implementation uses `invalid_request` for malformed input, owner-safe mission lookup with the existing mission status errors for mission state, and `server_error` for operational failure. These are local choices, not a claim that Core assigns them.

**Question:** Which existing error table applies to Audit, and should the endpoint define any additional owner, validation, or retention failures?

**Placement:** Combine with an Audit Endpoint contract pass (with AAG-F100) if the editors prefer one issue for request, response, and error behavior.

### AAG-F100 — "Fire-and-forget" does not define the Audit response behavior

**Upstream evidence:** 28e8258 Core, "Audit Response"

**Submitted:** no

**Remaining:** Text unchanged in substance: still requires 201 Created and permits a mission status error, then says the agent SHOULD NOT block on the response. Issue 49 cites the same sentence for a different (log-completeness) problem.

**Source:** AAuth Core, `Audit Response`.

Core requires the Person Server to return `201 Created`, permits a mission status error, and says the audit endpoint is "fire-and-forget; the agent SHOULD NOT block on the response." An ordinary HTTP request cannot learn either result without waiting for the response. Dispatching it as background work hides delivery failure and leaves process-lifetime and cancellation behavior undefined.

Our implementation exposes one synchronous request. It waits for the response, returns a definite typed rejection when possible, returns an uncertain outcome after an ambiguous handoff, and leaves concurrency to the calling application.

**Question:** Does "SHOULD NOT block" mean the action must not wait for audit because audit happens afterward, that the application should dispatch the request asynchronously, or that the Agent may ignore the response entirely?

**Placement:** Combine with AAG-F003 in a focused Core Audit Endpoint issue; issue 49 (https://github.com/dickhardt/AAuth/issues/49) touches the same sentence from the log-completeness side and can be cross-linked.

### AAG-F101 — An uncertain Interaction question submission cannot be recovered

**Upstream evidence:** 28e8258 Core, "Interaction Request" / "Interaction Response"; Core, "Deferred Responses"

**Submitted:** no

**Remaining:** Interaction Request still has no request identifier or idempotency key; a lost response to a question leaves the answer unrecoverable and a retry asks the person twice.

**Source:** AAuth Core, `Interaction Request`, `Interaction Response`, and `Deferred Responses`.

The initial signed `question` POST carries no request identifier, idempotency key, or lookup reference. If the Person Server delivers the question or obtains an answer but the response is lost or malformed, the Agent cannot discover the result. Repeating the request may show the person the same question twice and produce two unrelated answers.

Our Agent submits exactly once. A valid `202` supplies a pending URL, but a transport failure or malformed initial result loses that continuation even though the Person Server kept the question. The Agent returns a typed uncertain outcome and does not retry or claim recovery.

**Question:** Should Interaction requests carry a stable caller-selected identity, or should the Person Server define exact-request replay and lookup semantics after an uncertain submission?

**Placement:** Cross-link a general initial-request recovery discussion together with the Permission (AAG-F098) and Audit (AAG-F100) delivery gaps.

### AAG-F102 — Resource-hosted relay resolution has no terminal success shape

**Upstream evidence:** 28e8258 Core, "Interaction Response"; Core, "Relaying Through the Person Server"; Core, "Deferred Response State Machine"

**Submitted:** no

**Remaining:** Text condensed in -11 but the gap remains: the relay returns "a terminal response when the PS has done all it can" with no HTTP status or body assigned.

**Source:** AAuth Core, `Interaction Request` (`max_wait`), `Interaction Response`, `Relaying Through the Person Server`, and `Deferred Response State Machine`.

For a resource-hosted interaction, Core says the Person Server's relay returns `status: "interacting"` once the user has engaged and "a terminal response when the PS has done all it can"; `max_wait` says the PS resolves once the user has engaged, the window elapses, or it can make no further progress. No HTTP status or body is assigned to that terminal response. The deferred state machine defines `200` only as "done — process response body", and its other terminal outcomes are errors. None represents successful relay delivery without implying that the Resource operation completed.

Our implementation retains the exact relay before `202`, bounds it by `max_wait`, and gives one terminal poll consumer. Its provisional profile uses `200 {"status":"interacting"}` after engagement and `200 {"status":"pending"}` after timeout or no progress. The Agent treats the Resource's original pending URL as authoritative for completion.

**Question:** What HTTP status and response body should terminate a resource-hosted relay after engagement, timeout, or no progress, without claiming that the underlying Resource interaction completed?

**Placement:** Open a focused Core Interaction Endpoint question and cross-link the Deferred Response State Machine.

### AAG-F104 — Core both permits and forbids a self-hosted Agent Provider

**Upstream evidence:** 28e8258 Core, "Roles", "Agent Provider", "Intermediary Agent Identity", "AAuth Platform Value Registry", "Why `.json` in Well-Known URIs", "Why Agents Are Under an Agent Provider"; Bootstrap, "Self-Hosted Agents", "Self-Hosted Refresh"; https://github.com/dickhardt/AAuth/issues/208

**Submitted:** no

**Remaining:** Contradiction still in the text; editor issue 208 (open, 2026-09-25) tracks the same fix (drop the "distinct AP, not self-signed" sentence).

**Source:** AAuth Core, `Roles`, `Agent Provider`, `Intermediary Agent Identity`, `AAuth Platform Value Registry`, `Why .json in Well-Known URIs`, and `Why Agents Are Under an Agent Provider`; AAuth Bootstrap, `Self-Hosted Agents` and `Self-Hosted Refresh`.

Core's Roles and Agent Provider sections say a self-hosted agent is its own AP, and Intermediary Agent Identity requires an intermediary to be its own AP. The platform registry includes `self-hosted`, and the `.json` rationale cites static hosting of self-hosted agent metadata. Bootstrap specifies the key relationship: the JWKS-published key signs the self-issued agent token and is also its `cnf` key, and fresh self-issued tokens replace a refresh ceremony.

The design rationale `Why Agents Are Under an Agent Provider` still says an agent that is its own AP weakens the protocol and concludes that "AAuth therefore requires every agent to hold a token issued by a distinct AP, not self-signed." Both statements cannot describe the same conformance model.

Our implementation follows the normative topology and the Bootstrap profile: ordinary AP metadata, JWKS, agent-token minting, agent verification, and protected Resource use with no special verifier path.

**Question:** Is the distinct-AP conclusion in the rationale stale, or should the self-hosted topology, platform value, and Bootstrap profile be narrowed?

**Placement:** Comment on editor issue 208 (https://github.com/dickhardt/AAuth/issues/208), which proposes dropping the distinct-AP sentence; add implementation evidence that the self-hosted path needs no special verifier handling.

### AAG-F105 — Deferred mission approval does not define key renewal before token delivery

**Upstream evidence:** 28e8258 Core, "Mission Creation", "Mission Approval", "Person Token Structure", "Pending URL Security"; https://github.com/dickhardt/AAuth/issues/108

**Submitted:** no

**Remaining:** Still unspecified; editor issue 108 (open, "Pending grant lifetime, and key rotation across a pending grant") tracks the general key-rotation-across-pending case; our mission-approval case is a concrete instance.

**Source:** AAuth Core, `Mission Creation`, `Mission Approval`, `Deferred Responses`, `Person Token Structure`, and `Pending URL Security`.

Mission Creation lets the PS answer a proposal with a `202` deferred response. Pending URL Security requires the server to verify the agent's identity on every poll, but Core does not say whether the agent may renew onto a different proof key while the proposal is pending. The approval returns `person_tokens`, each bound by `cnf` to an agent key, and Person Token Structure says a person token must not outlive "the agent token presented when the token was requested", which is ambiguous between the proposal's agent token and the polling one.

Our implementation retains the proposal key, bounds the pending state by the original agent token's lifetime, and treats a poll under another key as not found. If an approval goes stale before delivery, it returns expiry instead of old credentials. Original-key continuity is our choice, not a stated Core requirement.

**Question:** Must a pending mission proposal stay bound to the original proof key and agent-token lifetime, or should terminal delivery mint person tokens for the currently authenticated agent key after renewal?

**Placement:** Comment on editor issue 108 (https://github.com/dickhardt/AAuth/issues/108) with deferred mission approval as a concrete case, cross-linking Pending URL Security and Person Token Structure.


## Submitted

### AAG-H003 — Recommended justification sections

**Upstream evidence:** 28e8258 Core, "Terminology" (Markdown, Editor's note); "Auth Token Request" (`justification`)

**Submitted:** date not retained, record not retained

**Remaining:** The literal TODO is gone, but the section structure is still undefined. Terminology now has an editor's note deferring section structures for all Markdown-valued parameters to a later revision, and `justification` says no structure is defined yet.

**Source:** AAuth Core, `Terminology` (Markdown entry and its editor's note) and `Auth Token Request` (`justification` parameter).

Earlier feedback proposed a small Markdown structure for `justification`, scaled to the stakes of the request: purpose; scope and magnitude; effect and reversibility; and, optionally, timing or alternatives. The current `justification` parameter says the document does not yet define a section structure for the value. The editor's note in `Terminology` defers recommended structures for every Markdown-valued parameter (mission text, justifications, clarifications, permission, audit and interaction descriptions) to a later revision, so that they stay consistent with each other.

Our consent interface renders `justification` as agent-asserted, sanitized Markdown and does not depend on any section structure.

**Question:** When the Markdown section structures are defined, should `justification` use stakes-proportional sections such as purpose, scope and magnitude, and effect and reversibility, with the same convention reused for the other Markdown parameters?

**Placement:** Raise this as input to the deferred Markdown-structure work named in the `Terminology` editor's note. Cite the earlier delivery rather than presenting it as new. No existing issue covers this.


## Resolved and withdrawn

- **AAG-H001** Draft-05 through draft-08 implementation feedback (resolved). The feedback was incorporated. Core "Acknowledgments" lists Joshua Gay. Document History -06 records "Interoperability clarifications from Joshua Gay's feedback", and -07 records adding him to Acknowledgments. Evidence: 28e8258 Core, "Acknowledgments"; "Document History".
- **AAG-H002** Callback authority and issuer-role discovery (resolved). The editors answered it and the text reflects the answer: the callback URL has no security role (UX only), and issuer roles are distinguished by the well-known document named in `dwk`. The answer itself was not kept as a public record. Evidence: 28e8258 Core, "Design Rationale" > "In Brief"; "Why No Authorization Code"; "Auth Token Verification".
- **AAG-F002** AS request example used a `jwks_uri` Signature-Key parameter the scheme did not define (resolved). The examples now use `sig=jwks_uri;id=...;dwk="aauth-person.json";kid="key-1"`, which matches the scheme's `id`, `dwk` and `kid` parameters. Fixed by PR #148; the -10 to -11 upgrade guide notes the old form. Evidence: 28e8258 Core, "PS-to-AS Token Request"; "Keying Material"; 69f5ba2 signature-key, "JWKS URI Discovery (jwks_uri)"; https://github.com/dickhardt/AAuth/pull/148.
- **AAG-F007** Mission completion appeared in the introductory interaction-endpoint list (resolved). The finding was correct at a99d353, so the old "withdrawn" record was wrong. The -11 restructure (PR #197) removed that introductory list, and "Interaction Endpoint" now says mission completion is proposed at `mission_endpoint`. Evidence: 28e8258 Core, "Interaction Endpoint"; https://github.com/dickhardt/AAuth/pull/197.
- **AAG-F008** Updated clarification requests referred to a removed agent claim (resolved). Updated Request now requires the same iss, ps, sub, agent_jkt, mission_s256 and tenant, and no longer mentions agent. Our comment on issue 104 is the submission. Evidence: 28e8258 Core, "Updated Request"; https://github.com/dickhardt/AAuth/issues/104 (PR 129/136).
- **AAG-F011** Person token endpoint omitted the auth-token request parameters (resolved). Person Token Endpoint now takes capabilities, login_hint, tenant, domain_hint, prompt, justification, platform and device. Without the interaction capability, a PS that must reach the person answers user_unreachable. Our issue 88 comment is the submission. Evidence: 28e8258 Core, "Person Token Endpoint"; https://github.com/dickhardt/AAuth/pull/186 (issues 175/177).
- **AAG-F014** R3 operation selection on a protected challenge (withdrawn). The text already answered this at a99d353 and still does. Without `r3_operations`, the resource includes R3 claims "based on its own policy", and the issuer decides grants from the document; no agent-supplied operation set is needed. What remains (a document broader than the call) is AAG-F014a. Evidence: 28e8258 R3, "Authorization Endpoint Extensions" > "Request"; "Resource Enforcement".
- **AAG-F015** Per-call auth tokens did not identify the record that supplies `presented_jti` (resolved). `presented_jti` now names the token actually presented (the auth token on a per-call challenge), and the agent passes that token to the PS as `presented_token`. The resource no longer has to look up an earlier person-token record. Evidence: 28e8258 Core, "Resource Token Structure"; "Auth Token Request"; R3, "Flow"; https://github.com/dickhardt/AAuth/issues/152; https://github.com/dickhardt/AAuth/pull/153.
- **AAG-F018** Missing proof fields have two error classifications (resolved). Core step 1 now returns invalid_signature for missing Signature, Signature-Input, or Signature-Key, matching signature-key's invalid_signature definition (Core keeps 401 for all signature failures, stated explicitly). Evidence: 28e8258 Core, "Verification (Server)" step 1; 69f5ba2 signature-key, "invalid_signature".
- **AAG-F022** Resource-side rejection of auth tokens outliving the agent token (resolved). The conflicting resource-rejection sentence is gone; Core now states only the issuer-side cap that an auth token's exp must not exceed the agent token used to obtain it. Evidence: 28e8258 Core, "Re-authorization"; "Auth Token Structure".
- **AAG-F023** Deferred auth-token delivery record key and pending URL lifetime (resolved). Deferred Delivery now keys the record by the auth token's jti, and Pending URL Security gives deferred auth-token delivery an explicit 410 exception (issue 92, PR 99). Evidence: 28e8258 Core, "Deferred Delivery"; "Pending URL Security"; https://github.com/dickhardt/AAuth/issues/92.
- **AAG-F034** Signing scheme for PS-to-resource revocation requests (resolved). Keying Material now requires scheme=jwks_uri with the server's issuer and dwk for server-own requests including revocation, and the Revocation Request example shows a PS signing to a resource that way (PR 148). Evidence: 28e8258 Core, "Revocation Request"; "Keying Material"; https://github.com/dickhardt/AAuth/pull/148.
- **AAG-F035** Signature coverage for JSON revocation requests to resources (resolved). Submitted as issue 165 (closed 2026-09-20); Covered Components now requires content-digest and content-type at any revocation endpoint, including a resource's (PR 191). Evidence: 28e8258 Core, "Covered Components"; "Revocation Request"; https://github.com/dickhardt/AAuth/pull/191.
- **AAG-F036** Response when a revoked token is presented (resolved). Core now specifies 401 with Signature-Error error=revoked_jwt and SHOULD AAuth-Requirement requirement=person-token, and server verification checks revocation (PRs 149/150). Evidence: 28e8258 Core, "Presenting a Revoked Token"; "Verification (Server)"; https://github.com/dickhardt/AAuth/pull/149.
- **AAG-F037** Revocation request contents, retention, and unknown-token handling (resolved). Request now carries jti and exp (REQUIRED) with retention bounded by exp plus skew, there is no "not found" response, unseen tokens are recorded, and Who Revokes What covers resources that accept agent tokens directly (PRs 147, 149, 190, 192). Evidence: 28e8258 Core, "Revocation Request"; "Revocation Response"; "Who Revokes What"; "Revocation Cascade"; https://github.com/dickhardt/AAuth/pull/147.
- **AAG-F046** Generic auth-token verification has no call-chain context (resolved). Step 1 now lists substitutions to Person/Auth Token Verification: `aud` is the intermediary, `cnf.jwk` is not compared with the request signer, and the resource `sub` record check does not apply (PR 162 item 2). Evidence: 28e8258 Core, "Upstream Token Verification" step 1; https://github.com/dickhardt/AAuth/pull/162.
- **AAG-F047** The upstream `cnf` description names the wrong key (resolved). Call Chaining now says the upstream token's `cnf` is the calling agent's key, not the intermediary's, and step 1 says it is not compared with the request signer (PR 162 item 2). Evidence: 28e8258 Core, "Call Chaining"; "Upstream Token Verification" step 1; https://github.com/dickhardt/AAuth/pull/162.
- **AAG-F048** The audience rule implies Resource/AP collocation (resolved). Core now states an intermediary MUST be its own agent provider with agent metadata `issuer` equal to its resource `issuer`, and Roles lists Resource + Agent + AP as a collocation (PR 176). Evidence: 28e8258 Core, "Intermediary Agent Identity"; "Roles"; https://github.com/dickhardt/AAuth/pull/176.
- **AAG-F049** Person remapping has no host contract (resolved). The PS now resolves the person from its own record for the upstream token's `aud` and `sub` (the directed identifier it minted), must reject when it holds no such record, and mints the downstream `sub` from the downstream resource token (PR 162 item 3). Evidence: 28e8258 Core, "Person Token Endpoint" ("Which person"); "Directed Identifiers Across a Chain"; https://github.com/dickhardt/AAuth/pull/162.
- **AAG-F051** Downstream credential lifetime is not derived (resolved). Person and auth tokens issued with `upstream_token` now MUST NOT expire later than the upstream token; Call Chaining says downstream access does not outlive it (Document History -11 entry with PR 176). Evidence: 28e8258 Core, "Person Token Structure"; "Auth Token Structure"; "Call Chaining"; https://github.com/dickhardt/AAuth/pull/176.
- **AAG-F052** Mission ownership and propagation conflict in a chain (resolved). The intermediary sends no `mission_s256`; the PS evaluates the upstream token's mission and copies its `mission_s256` into the downstream person token, so resource and auth tokens carry it (PR 162 item 3, PR 176). Evidence: 28e8258 Core, "Person Token Endpoint" (`mission_s256` parameter and "Which person"); "Call Chaining"; https://github.com/dickhardt/AAuth/pull/162.
- **AAG-F053** An AS cannot literally verify the forwarded upstream token (resolved). Step 1 no longer compares upstream `cnf.jwk` with the request signer, step 2 says the AS checks the issuer against the signing PS and relies on the PS for an auth token's `iss`, and step 3 uses the `agent_token` parameter at the AS. Open issue 199 tracks the separate gap of verifying `agent_token` itself at the AS. Evidence: 28e8258 Core, "Upstream Token Verification" steps 1-3; "PS-to-AS Token Request"; https://github.com/dickhardt/AAuth/pull/162.
- **AAG-F054** "Trusted issuer" has no evidence model (resolved). The vague "previously brokered or is authorized to extend" test is replaced by concrete checks (this PS, or an AS this PS presented a person token to for that `aud` and `sub`; at the AS, the signing PS), backed by the PS's retained presentation records. Evidence: 28e8258 Core, "Upstream Token Verification" step 2; "Revocation Cascade" ("Records").
- **AAG-F055** No error code covers an invalid upstream token (resolved). `invalid_upstream_token`, `expired_upstream_token`, and `revoked_upstream_token` are now registered and assigned in Upstream Token Verification (PR 162 item 2). Evidence: 28e8258 Core, "Token Endpoint Error Codes"; "Upstream Token Verification" step 1; https://github.com/dickhardt/AAuth/pull/162.
- **AAG-F056** Person-token retention omits upstream-chain custody (resolved). A person token issued with `upstream_token` is now recorded with the upstream token's `(iss, jti)` until `exp` plus clock skew. Using that record to check the second presentation remains under F050. Evidence: 28e8258 Core, "Revocation Cascade" ("Records"); "Person Token Endpoint" ("Retention"); https://github.com/dickhardt/AAuth/pull/174.
- **AAG-F057** One-Agent/one-person conflicts with intermediary Resources (resolved). A request carrying `upstream_token` now neither uses nor establishes a binding, and the intermediary's agent token is explicitly not bound to one person (PR 176). Evidence: 28e8258 Core, "Agent-Person Binding"; "Intermediary Agent Identity"; https://github.com/dickhardt/AAuth/pull/176.
- **AAG-F058** Events uses a subscription identifier as the delivery deduplication key (resolved). Event tokens now carry a per-event `jti`, and the AP and agent deduplicate on `(iss, jti)`; the text says `eid` cannot serve because every event on a subscription shares it (PR 168 item G1). Evidence: 28e8258 Events, "Event Token" > "Structure"; "Agent Verification"; https://github.com/dickhardt/AAuth/pull/168.
- **AAG-F061** Resource and access server could not read the mission expiry they had to enforce (resolved). A resource token's lifetime no longer depends on the mission. The PS caps person tokens and auth tokens at expires_at, and an AS's auth token may not outlive the presented person token, which carries that limit. Fixed by PR 131 (closes our issue 121). Evidence: 28e8258 Core, "Mission Approval"; "Person Token Structure"; "Auth Token Structure"; https://github.com/dickhardt/AAuth/pull/131.
- **AAG-F071** The `jkt-jwt` example omitted the required `alg` in both JWKs (resolved). The example now carries `"alg": "ES256"` on the header JWK and `"alg": "Ed25519"` on `cnf.jwk` (added in signature-key PR 42, consistency-review). Evidence: 69f5ba2 signature-key, "JKT JWT Self-Issued Key Delegation (jkt-jwt)"; https://github.com/dickhardt/signature-key/pull/42.
- **AAG-F076** R3 rationale contradicted the normative dual-role fetch rule (resolved). PR 128 rewrote Why Not RAR; the "restricted to AS-only access" sentence is gone and the agent-opacity paragraph now says the content reaches the PS and the AS and never the agent. Evidence: 28e8258 R3, "Design Rationale" > "Why Not RAR"; R3, "Security Considerations" > "R3 Document Access Restriction"; https://github.com/dickhardt/AAuth/pull/128.
- **AAG-F085** Events gave two incompatible event-endpoint retention rules (resolved). PR 207 changed the overview to say the Resource stores the `eid` and AP issuer and resolves `event_endpoint` at delivery time, matching Verification and Event Delivery. Evidence: 28e8258 Events, "Protocol Overview" (step 2); Events, "Subscribe Token" > "Verification"; https://github.com/dickhardt/AAuth/pull/207.
- **AAG-F086** Direct R3 leaves Auth-token-issuer duties assigned only to an AS (resolved). R3 now says the issuer is the AS in four-party and the PS in three-party access, renames AS Processing to Issuer Processing, has r3_uri fetched by "the AS and the PS", and makes Audit Log Integrity bind "the issuer" (PR 204, item 4 "Three-party issuance"). Evidence: 28e8258 R3, "R3 Processing" / "Issuer Processing" (was AS Processing), "Auth Token Extensions", "R3 Document Access Restriction"; https://github.com/dickhardt/AAuth/pull/204.
- **AAG-F087** `AAuth-Budget` examples are not RFC 9651 Dictionaries (resolved). Every AAuth-Budget example now separates members with commas (PR 128: "comma-separated AAuth-Budget examples"). No semicolon-separated AAuth-Budget example remains. Evidence: 28e8258 Budgets, "AAuth-Budget Response Header", "Sending Rules", "Streaming", "The `reason` Parameter", "Deferred Delivery"; https://github.com/dickhardt/AAuth/pull/128.
- **AAG-F089** Omitted PS-to-AS Budget ceiling is indistinguishable from extension non-participation (resolved). Issue 122 was closed 2026-09-06 by PR 141. When the PS omits `budget`, the AS MUST NOT issue a `budget` claim. Omission "MUST NOT be read as a grant". The PS MUST verify that the AS token's budget matches what it sent, or is absent when it sent none, and otherwise fail delivery with as_unreachable. A token with no budget falls back to the Resource's own default; the text states this as deliberate non-participation semantics. Evidence: 28e8258 Budgets, "PS-to-AS Token Request Extensions", "Auth Token Extensions"; https://github.com/dickhardt/AAuth/pull/141.
- **AAG-F090** The exhausted example charges a refused request (resolved). Budget Exhaustion now says "A refusal therefore carries no `cost`; `required` ... is the figure a refusal reports". Every exhausted example now reads `remaining=0, unit="USD", decimals=6` with no `cost`. No PR could be identified in the shallow history; PR 102 introduced `required`. Evidence: 28e8258 Budgets, "Budget Exhaustion", "The `reason` Parameter", "Sending Rules".
- **AAG-F091** Core names retained lineage but not its Auth-token lookup binding (resolved). `presented_jti` is now the `jti` of the token the request carried, which is the Auth token on a step-up. The Agent passes that token to the PS as `presented_token` and the PS checks it against `presented_jti`. Lineage is therefore bound on the wire with no retained Auth-token-to-Person-token mapping (issue 152 / PR 153). Budgets aligned its example and record in PR 206. Evidence: 28e8258 Core, "Resource Token Structure", "Resource Token Verification"; Budgets, "Budget Exhaustion", "The Consumption Record"; https://github.com/dickhardt/AAuth/issues/152 (PR 153), https://github.com/dickhardt/AAuth/pull/206.
- **AAG-F103** Third-party login requires person context it has not obtained (resolved). Feature removed upstream: issue 155 / PR 157 deleted Third-Party Login and login_endpoint, so the flow this finding questioned no longer exists. Evidence: 28e8258 Core (no Third-Party Login, Login Endpoint, or login_endpoint remains); https://github.com/dickhardt/AAuth/issues/155 ; https://github.com/dickhardt/AAuth/pull/157.
