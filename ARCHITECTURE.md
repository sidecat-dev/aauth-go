# Architecture

AAuth Go separates cryptographic evidence, HTTP request proof, AAuth protocol
semantics, companion specifications, deployable roles, and process setup. A
valid signature proves integrity and key possession. It does not, by itself,
authorize an operation.

This document has two deliberately separate parts:

- **Observed architecture** describes published source at one exact revision.
- **Target architecture** describes the package and evidence boundaries toward
  which the current implementation is being rewritten.

[Source coverage](SOURCE-COVERAGE.md) remains the authority for which
specification sections have executable evidence. This document is not a
coverage or release claim.

## Observed architecture

At source revision `13bf46f0586ba139bd9948ad02c1a46b7b3eed60`, the
module has three public library packages:

```text
jose        bounded Ed25519 JWK, signing, compact JWS, and sealed evidence
aauth       Signature-Key, discovery, protocol values, and token logic
reference   role handlers, policy seams, durable custody, and recovery
```

`cmd/aauth-reference` composes those packages into a runnable process.
`internal/sourcecoverage`, `internal/jsonstrict`, and `internal/snapshotfile`
provide private source, validation, and storage support.

The first extraction is complete: every role uses the public `jose` package
directly, with no root aliases or second key model, and seven frozen token
vectors remain byte-identical. The root `aauth` package still owns too many
remaining layers. For example, `VerifyRequest` combines Signature-Key parsing,
HTTP Message Signature verification, issuer-key discovery, AAuth token
dispatch, claim validation, identity projection, and replay-key generation.
The target architecture separates those concerns rather than preserving the
current shape behind aliases.

---

> **Target architecture — not a current-state claim.** Everything below this
> banner describes the complete target graph. Individual slices, including
> `jose`, may already appear in the observed architecture above, but the graph
> as a whole is not present at revision `13bf46f`.
> [Source coverage](SOURCE-COVERAGE.md) remains the authority for executable
> behavior. “Core” below means the module-root Go package `aauth`, not a new
> `/core` package.

## Target package graph

Arrows mean “imports.” Every edge points toward a lower-level dependency.

```text
cmd/aauth-reference
        |
        v
    reference ---------------------------------------------------+
        |                                                        |
        +--> bootstrap                                           |
        +--> events -----> r3 <----- budgets                     |
        +------|-----------|----------|--------------------------+
               v           v          v
                         aauth
                          |  \
                          v   v
                    signaturekey ---> jose
```

The complete intended edges are:

- `signaturekey` imports `jose`;
- root `aauth` imports `signaturekey` and `jose`;
- `r3` imports root `aauth`;
- `events` imports root `aauth` for protected flows and the R3 operation
  vocabulary it uses;
- `budgets` imports root `aauth` and consumes the typed Budget-required
  annotation owned by R3;
- `bootstrap` imports the portable role helpers it needs from `aauth`,
  `signaturekey`, and `jose`;
- `reference` imports the packages required by each endpoint profile; and
- the command imports `reference`.

R3 preserves exact authorization-document bytes without importing Events or
Budgets. Its operation-vocabulary model keeps unknown third-party members
byte-for-byte as `json.RawMessage` beside the exact source bytes. Events and
Budgets consume R3-owned typed vocabulary through one-way seams. This avoids
Go import cycles, parse-and-reserialize drift, and an untyped runtime extension
registry.

## Target package ownership

### `jose`

`jose` will own the selected Ed25519 JOSE profile:

- JWK validation and RFC 7638 thumbprints;
- caller-custodied signing keys over `crypto.Signer`;
- exact compact-JWS parsing, signing, and verification; and
- sealed, copy-safe evidence that one exact compact JWS verified under one
  exact public key.

It will not own AAuth claims, HTTP, discovery, role policy, deployment policy,
or an algorithm registry. It is a bounded Go implementation, not a general JWT
framework.

### `signaturekey`

`signaturekey` will own the shared HTTP proof and key-discovery layer:

- RFC 8941 Signature-Key fields and the closed implemented scheme set;
- RFC 9421 request signing and verification;
- covered-component and content-digest validation;
- proof freshness, optional expiry and nonce, and replay identity;
- issuer, `dwk`, `kid`, metadata, and JWKS resolution;
- admitted network egress, bounded refresh, and typed discovery failures; and
- Signature-Key negotiation and refusal fields.

The package will treat credentials as semantically opaque. It may expose parsed
credential bytes and verified request-proof facts, but it will not select an
AAuth token profile, return AAuth claims, establish a principal, or decide
authorization policy.

Events routing and arbitrary R3 document retrieval are not key discovery and
remain with their owning companion or endpoint composition.

### Root `aauth`

Core will own portable protocol values and the current Core token profiles:

- agent, person, resource, and auth token claims;
- identifiers, mission references, requirements, and context checks;
- token-type, issuer-role, time, confirmation-key, and request-context rules;
- a compile-time recognized-member catalog for every pinned authorization
  companion; and
- sealed Core token evidence bound to exact compact bytes, selected key,
  verification instant, and an opaque `EvidenceID`.

The recognized-member catalog is independent of configured companion
validators. It includes per-token applicability and co-presence rules. A known
authorization member cannot become “unknown and ignorable” merely because an
optional package is absent. Truly unrecognized members are handled only as
their governing source permits.

Core will import `signaturekey` for canonical issuer-key discovery contracts.
It will not import R3, Events, Budgets, Bootstrap, or `reference`.

### `r3`

`r3` will own R3 authorization documents, proposal and grant values, parameter
binding, retained-result replay, and effect-time enforcement. It will also own
the agent-readable operation-vocabulary rules defined by R3: access modes,
Budget annotation syntax and validation, its typed `BudgetRequired` value, and
the rule that `budget=true` implies auth-token planning.

The Budget annotation lives in MCP, OpenAPI, AsyncAPI, or OData operation
vocabulary, not in an R3 authorization document. R3 preserves an authorization
document’s exact source serialization; it never canonicalizes that document by
parsing and reserializing it.

### `events`

`events` will own subscribe and event token profiles, subscription and
delivery state, endpoint vocabulary, use-count enforcement, and the relevant
R3 AsyncAPI interpretation. An Events token is not a Core token extension.
Events will accept sealed JOSE evidence for its own token profile and mint its
own sealed token evidence and `EvidenceID`. A protected flow that also carries
a Core auth token will retain both independent evidences.

### `budgets`

`budgets` will own Budget token members, metadata, narrowing, reservation
state, metering, and settlement. It will consume R3’s typed
`BudgetRequired` operation value rather than redefine the annotation. It will
return its own sealed token result bound to the Core `EvidenceID`; it will not
mint Core evidence.

### `bootstrap`

Bootstrap is informational role support, not an authorization companion. Its
package may provide the source’s hardware-key, `jkt-jwt`, refresh, and setup
examples. It does not participate in companion admission and does not claim a
normative extension registry.

### `reference`

`reference` will own deployable composition:

- endpoint routing and the exact scheme, credential, and body-token forms each
  endpoint accepts;
- endpoint-local trusted-peer and deployment policy;
- explicit typed admission bundles for each endpoint profile;
- replay admission, durable custody, recovery, and consequence settlement;
- typed HTTP refusal mapping; and
- protected consequence invocation.

It will not define another JOSE, token, Signature-Key, or companion
implementation.

### `cmd/aauth-reference`

The command will own deployment files, TLS and listener setup, process
lifecycle, protected-key adapters, and runnable examples. It is not a second
protocol implementation.

## Target evidence composition

Evidence has two token roots and one independent HTTP-proof root. It is
composed without a global registry or a generic success object:

```text
Core compact token                    Events compact token
        |                                      |
        v                                      v
jose.VerifiedCompact                   jose.VerifiedCompact
        |                                      |
        v                                      v
aauth.VerifiedToken                    events.VerifiedToken
 + Core EvidenceID                     + Events EvidenceID
        |             |                        |
        v             v                        |
 r3.TokenResult  budgets.TokenResult            |
        \             /                         /
         +-----------+-------------------------+
                     |
signaturekey.VerifiedRequest
                     |
                     v
       reference endpoint admission bundle
```

Core will mint only sealed Core-token evidence. R3 and Budgets will accept
sealed Core evidence and return their own sealed concrete results. Events will
mint separate sealed evidence for its own subscribe and event profiles. A
protected Events flow may carry both an Events evidence value and an unrelated
Core auth-token evidence value.

`signaturekey.VerifiedRequest` will seal the exact HTTP proof: the
`Signature-Key` field or its digest, selected proof key, required covered
components, method, authority, target, applicable authorization and content
digests, and one trusted verification instant. A staged verifier may accept a
profile-selected key from Core or Events, but the resulting proof will retain
the exact credential reference and selected key used by that stage.

A `reference` endpoint will construct an explicitly typed admission bundle
only after it has verified that every required token or companion result binds
the appropriate:

- Core or Events `EvidenceID` and exact input digest;
- HTTP-proof evidence ID and exact signed request;
- selected proof key and required covered components;
- trusted verification instant;
- endpoint profile.

The constructor will additionally enforce each profile’s relationship:

- `jwt`: the covered `Signature-Key` credential is the exact Core token and
  its `cnf.jwk` verified the HTTP signature;
- `self-jwt`: the covered credential is the exact Events token and the same
  selected issuer key verified both the token and HTTP signature;
- `jwks_uri`: the trusted server proof covers the exact `Content-Digest` and
  body bytes from which every secondary token was extracted.

Pending recovery will retain this admission bundle or an authenticated receipt
that preserves the same relationships. Token evidence cannot be combined with
a different request target, body, proof, or caller after restart.

The admission constructor remains private to the owning endpoint composition.
No `any`, open validator list, install-time registry, or Core-owned “all
extensions admitted” seal is involved.

Cross-package evidence types have unexported state, no public constructor or
setter, an invalid zero value, and copy-returning accessors. These evidence
stages are distinct:

1. **cryptographically verified** — the exact compact object verified under
   one exact key;
2. **token-profile verified** — the owning Core or Events token profile
   passed;
3. **companion token verified** — an applicable side-effect-free R3 or Budget
   token rule passed for the same Core evidence;
4. **HTTP proof verified** — one exact signed request verified under the key
   selected by its credential profile;
5. **endpoint admitted** — the endpoint assembled and cross-checked the exact
   token, companion, and request-proof evidence its profile requires; and
6. **authorized** — local policy permitted one consequence.

None of stages 1–5 is authorization.

## Target endpoint verification profiles

There is no universal verification sequence. Every endpoint will name its
profile and use only that profile’s ordered stages.

<details>
<summary>JWT-credential protected-resource request</summary>

1. Perform key-independent request preflight.
2. Parse and cryptographically verify the compact credential through Core and
   the canonical discovery layer.
3. Run side-effect-free companion token validation required for a valid JWT:
   recognized-member applicability and co-presence, exact claim parsing,
   shape, and bounds.
4. Obtain the proof key from the fully validated credential.
5. Verify the HTTP Message Signature and signed request body.
6. Apply the issuer-role, audience, endpoint-profile, and trusted-peer checks
   that require only sealed token and request-proof facts.
7. Only after that trust admission, run companion document retrieval and
   store-backed processing.
8. Apply operation, mission, proposal, and policy-context checks that depend on
   the companion results.
9. Cross-check and seal the token-plus-request admission bundle.
10. Admit replay state and recover any retained terminal result.
11. Apply local authorization.
12. Run pre-consequence reservation or grant enforcement, invoke the
    consequence once, and settle retained state.

</details>

<details>
<summary>Server-to-server <code>jwks_uri</code> request with body tokens</summary>

1. Perform key-independent request preflight.
2. Resolve the server credential through `signaturekey` discovery.
3. Verify the HTTP Message Signature and signed body before trusting any body
   member.
4. Apply trusted-server policy.
5. Parse and verify the secondary Core tokens carried in the body.
6. Run the companions required by those exact tokens and this endpoint.
7. Apply routing, identity, mission, and endpoint-context checks.
8. Cross-check and seal the trusted-server-proof-plus-body-token admission
   bundle, proving that the proof covered the exact body bytes and every
   secondary token and companion result came from those bytes.
9. Admit replay state only after all retryable preconditions have passed.
10. Authorize, retain, and settle the endpoint consequence.

</details>

<details>
<summary>Events <code>self-jwt</code> delivery</summary>

1. Perform key-independent request preflight.
2. Verify the event credential and derive its proof key.
3. Verify the HTTP Message Signature and body.
4. Validate the Events token profile and mint separate sealed Events evidence.
5. Recover and validate the subscription, audience, and delivery context.
6. Cross-check and seal the Events-token-plus-request admission bundle. If the
   endpoint also carries a Core auth token, retain and bind both evidences
   through the signed request.
7. Admit replay and use-count state atomically.
8. Apply local delivery policy and retain the delivery outcome.

</details>

<details>
<summary>Bootstrap hardware-key and <code>jkt-jwt</code> ceremonies</summary>

1. Use the scheme-specific Signature-Key proof profile.
2. Apply the role’s setup or refresh ceremony.
3. Retain only the authority and recovery material that ceremony requires.

Bootstrap supplies role support and examples; it does not add a companion
admission stage.

</details>

R3 and Budgets also have consequence-time stages that occur after endpoint
admission:

- R3 retrieves and binds the exact proposal, checks parameters and single-use
  authority, and returns a retained result rather than repeating an effect.
- Budgets atomically reserves before the consequence, then commits actual
  consumption or releases the reservation. Committed consumption plus
  outstanding reservations must never exceed the token’s amount.

## Target recovery contracts

Recovery is purpose-specific. A small replay record must not be mistaken for
authority evidence, and a cryptographic proof must not be mistaken for a
terminal consequence.

| Recovery class | Minimum retained custody | Recovery behavior |
|---|---|---|
| Replay rejection | Replay key and expiry | Reject the duplicate. Do not reconstruct a decision or response. |
| Source correlation | The exact fields the governing source declares sufficient | Compare or resolve only that relationship, such as `presented_jti`. Do not invent broader authority. |
| Pending authority | Exact signed request or authenticated receipt, covered components, selected key, profile, original trusted instant, and retained mutable-policy decision when applicable | Reverify cryptography offline at the original instant. Do not use current discovery or rerun mutable policy as a substitute for retained authority. |
| Issuance or terminal settlement | Exact response or result, consequence identity, and settlement state | Return or finish the retained outcome. Never mint again or repeat the protected consequence. |

Each store will state which class it implements. An endpoint may use several
stores with different classes in one journey.

## Target invariants

1. One exported concept has one canonical package. Root aliases and forwarding
   compatibility façades are not retained.
2. Moving a Go type does not change JSON names, compact bytes, digests,
   signature inputs, replay identities, or retained schemas.
3. No global algorithm, scheme, credential, companion, or policy registry can
   change process behavior.
4. Each endpoint explicitly selects its accepted schemes, credential forms,
   body tokens, companion results, and signed components.
5. Core recognizes every pinned Core-token authorization member at compile
   time. A known
   but unsupported member fails before replay admission, authorization policy,
   new retention, or protected consequence.
6. Signature-Key returns proof and discovery facts, never AAuth claims or
   deployment principals.
7. Core and companion validation use exact compact bytes, not reconstructed
   claim structs.
8. A valid person token is not authorization, and a discoverable server is not
   trusted solely because its signature verifies.
9. Every endpoint admission bundle binds sealed token-profile evidence to
   sealed HTTP request-proof evidence through explicit profile-specific checks.
10. Replay identity is consumed only at the endpoint profile’s documented
   admission boundary.
11. Replay admission and consequence custody remain endpoint and store
    responsibilities.
12. Recovery uses the contract of its specific recovery class; it does not
    silently promote reduced state into broader authority.
13. Diagnostic causes remain local unless a typed error explicitly marks a
    fixed detail safe for the wire.
14. Adding an algorithm, scheme, or companion requires ordinary source code,
    endpoint opt-in, tests, and source-coverage evidence. Installation alone
    cannot activate behavior.

## Required qualification

The target will require:

- package tests for local parsing, copy isolation, canonical bytes, and
  cryptography;
- root tests for Core token profiles and compile-time claim recognition;
- companion tests for each sealed result and effect-time invariant;
- reference journey tests for every endpoint profile, refusal order, replay,
  restart recovery, policy, and consequence settlement;
- frozen wire vectors that prove package moves preserve bytes and digests;
- clean external modules that prove the public import graph; and
- source-coverage changes only after current externally observable behavior
  passes.
