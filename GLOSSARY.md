# Terms used in this library

Start with [Use it in your service](USE-IN-YOUR-SERVICE.md). These definitions
explain names; [CONFORMANCE.md](CONFORMANCE.md) defines implemented limits.

| Name | Meaning |
| --- | --- |
| Agent | A caller with an AAuth identifier and a key used to sign requests. |
| Agent Provider (AP) | The issuer of an Agent token. It vouches for the Agent identifier and public key. |
| Resource | The service receiving and verifying the Agent's requests. |
| Person Server (PS) | The role that binds person identity and applies the person's authorization and interaction policy. |
| Access Server (AS) | A separate authorization issuer used in the four-party flow. In the three-party flow, the PS issues Auth tokens directly. |
| Agent identifier | `aauth:<local>@<provider-domain>`. The local part permits ASCII letters, digits, `-`, `_` and `.`; `+` separates a child Agent from its parent. Comparison is case-sensitive. The domain must match the Agent-token issuer's domain. See `ValidateAgentIdentifier` and `ValidateAgentRelationship` for the one-level child form. |
| Agent / Person / Resource / Auth token | Respectively: Agent identity and key; person identity directed to a Resource; the Resource's request for authorization; the resulting authorization grant. Their distinct types are not interchangeable. |
| JWT / JWS / JWK / JWKS | JSON Web Token / JSON Web Signature / JSON Web Key / a set of JWKs. This library uses compact signed JWTs and the bounded Ed25519 profile described in [SPECIFICATIONS.md](SPECIFICATIONS.md). |
| `iss`, `sub`, `aud`, `jti`, `exp` | Token issuer, subject, audience, unique token identifier and expiration time. The token type determines the subject and audience's roles. |
| `dwk` and `kid` | The discovery document name and key ID used with `iss` to select the issuer's signing key. For an Agent token, `dwk` is `aauth-agent.json`. |
| `cnf.jwk` / `agent_jkt` | A confirmation public key / a key thumbprint. They bind the credential to the Agent key; a verified HTTP signature proves possession of its private part. |
| `StaticKeyResolver` | An exact in-memory map from `(Issuer, DiscoveryDocument, KeyID)` to a trusted public JWK. `HTTPKeyResolver` obtains keys through admitted metadata and JWKS endpoints. |
| `Clock` / `ClockFunc` | A required source of protocol time / an adapter for a function returning `time.Time`. Use `SystemClock{}` in a service or a fixed function in a test. |
| `Signature-Key` | The HTTP field describing which credential and key authenticate an HTTP Message Signature. JWT verification alone does not verify that request signature. |
| `jwt`, `hwk`, `jkt-jwt`, `jwks_uri`, `self-jwt` | Signature-Key schemes: a token-bound key; an inline public key; a JWT delegating from an identity-key thumbprint; a key discovered via issuer metadata; a self-issued JWT whose issuer key also signs the request. “`hwk`” does not imply hardware attestation. Support varies by scheme; see [the matrix](CONFORMANCE.md#http-signature-keys). |
| Sub-agent / `parent_agent` / `subagent_token` | A one-level child Agent with its own key, issued by its parent's Agent Provider / the child-token claim naming its parent / the request member a parent uses to obtain the child's Person and Auth tokens. The parent makes every PS request; the child alone calls the Resource. |
| Agent-person binding | The PS's association of a top-level Agent with one person. A sub-agent uses its parent's binding. `RevokeAgentBinding` records a host's revocation; issuance and pending delivery under it are refused. `ReestablishAgentBinding` records a replacement, which admits only later requests. |
| `presented_token` | The Person or Auth token the Agent previously showed to the Resource. Sending it with the Resource token lets the issuer verify the identity, key and context behind that request. |
| `AAuth-Requirement` / step-up | The Resource's requested credential type / a request for additional authorization, such as a fresh Auth token after a fixed Budget is exhausted. Callers choose subsequent exchanges explicitly. |
| R3 | Rich Resource Requests: operation-level authorization described by a vocabulary, such as MCP tool names or OpenAPI operation IDs. |
| Budget / `AAuth-Budget` | A grant's metering allowance / the HTTP response field carrying Budget feedback. The implemented fixed-price paths and missing variable/streaming behavior are listed in the matrix. |
| Mission / `mission_s256` | A person-approved task description retained by the PS / the digest binding tokens and requests to its exact approved bytes. Other roles need the digest, not the mission text. |
| Clarification | A pending authorization question that the caller explicitly answers or cancels. The implemented path is bounded to one round; a supervised request allows five. |
| Supervisor / supervision server (SS) | The party that decides each act an Agent asks its PS to authorize: the person by default, or a supervision server the person connects to their PS. For an Agent routed to an SS, the PS decides nothing itself; it relays, records and enforces. |
| Deciding SS / `sdi` | The one SS the PS consults for an Agent / the supervision decision identifier the PS mints for each request, tying the request, its retries, polls and clarifications, the person's answer and the issued tokens together. |
| `ask` / reach (`apply`) | The SS's answer that the person decides / how far the person's answer reaches (`once`, `mission`, `always`, or a value the SS offered), which the SS remembers and applies; the PS applies none. |
| `storetest` | Reusable contract suites for host-supplied, role-specific stores. Passing them checks observable storage behavior; production restart and backend-failure tests remain the application's responsibility. |
