# EPIC-002 — Portable Signature-Key self-jwt

**Summary:** Verify a self-issued JWT and its HTTP Message Signature with one
admitted issuer key, and produce the same portable proof without an
Events-specific verifier.
**Stories:** STORY-0006 through STORY-0007
**Primary source:** `draft-hardt-httpbis-signature-key-06`
**Accepted scope:** AAuth complete-spec-family roadmap M5 prerequisite
**Status:** 0/2 done

## STORY-0006

**Epic:** EPIC-002
**Title:** Sign and verify one self-jwt dual proof

**As a** portable AAuth application implementer
**I want** one generic self-jwt producer and verifier
**So that** application profiles can authenticate a JWT and HTTP request with
the same discoverable issuer key

**Acceptance criteria:**

- AC-1: The signer carries the caller-supplied compact JWT as the exact required
  `jwt` parameter in `sig=self-jwt` and signs the HTTP request with the key that
  signed that JWT. JWT acquisition remains outside this API. · impact:`journey`
  · seam:`e2e` · scenario:`JOURNEY-0002`
  - Proof: parse the exact header and complete a real producer-consumer HTTP
    exchange; a substituted HTTP signing key is refused.
- AC-2: Before discovery the verifier rejects an absent, non-string, empty, or
  malformed JWT parameter, an unexpected deployment-selected `typ`, expired
  `exp`, absent or unsafe `iss`, invalid `dwk`, absent `kid`, or any `cnf` claim.
  · impact:`local` · seam:`integration` · scenario:`SCENARIO-0009`
  - Proof: a counting resolver observes zero calls for every preflight failure.
- AC-3: After preflight the verifier resolves `kid` through
  `{iss}/.well-known/{dwk}`, reports a missing key as `unknown_key`, verifies the
  JWT, applies caller claim policy, and only then verifies the HTTP signature
  with that exact resolved key. · impact:`journey` · seam:`e2e` ·
  scenario:`SCENARIO-0010`
  - Proof: independently corrupt each proof layer and use two valid issuer
    keys to prove that success at one layer cannot substitute for the other.
- AC-4: The portable verifier exposes deployment-selected type, claim, and
  maximum-lifetime policy. The M5 Events profile requires `aud`, `iat`, `exp`,
  and a finite lifetime but does not invent `sub` or a universal lifetime for
  every self-jwt application. · impact:`cross-surface` · seam:`integration` ·
  scenario:`SCENARIO-0010`
  - Proof: accepted and excessive-lifetime tokens traverse the same verifier;
    public documentation distinguishes scheme requirements, Events
    requirements, and the selected EdDSA implementation profile.

**Sources:** Signature-Key lines 660-721, 1271-1276

**Status:** pending

## STORY-0007

**Epic:** EPIC-002
**Title:** Keep presenter-directed discovery admitted and bounded

**As a** verifier deployment operator
**I want** issuer metadata and JWKS retrieval to remain inside explicit egress
and cache policy
**So that** self-jwt does not turn presenter claims into ambient network access
or unbounded trust state

**Acceptance criteria:**

- AC-1: `iss` is an absolute HTTPS issuer and `dwk` is a safe well-known
  document name. Metadata and JWKS are separately admitted; invalid issuer
  metadata, invalid or duplicate-key JWKS, redirects, and unknown `kid` fail
  closed. · impact:`cross-surface` · seam:`integration` ·
  scenario:`SCENARIO-0010`
  - Proof: the real HTTP resolver records both endpoint admissions and the
    complete invalid-discovery matrix.
- AC-2: The library keeps address-class refusal, DNS pinning, and cross-origin
  JWKS approval in the deployment-supplied egress/client boundary and invokes
  that boundary before each connection. It does not claim a default network
  policy it does not own. · impact:`cross-surface` · seam:`integration` ·
  scenario:`SCENARIO-0011`
  - Proof: a reference policy refuses private, loopback, link-local, rebound,
    and unapproved cross-origin targets before the logical gateway observes a
    request.
- AC-3: An expired JWT is unusable even when its discovered key remains in the
  shared bounded HTTP-discovery cache. Metadata and JWKS freshness, negative
  refresh state, and cache cardinality remain bounded by the existing resolver
  contract. · impact:`local` · seam:`integration` ·
  scenario:`SCENARIO-0011`
  - Proof: warm-cache expiry cannot bypass token validation, repeated unknown
    issuers cannot grow retained failure state without bound, and existing
    discovery sentinel tests stay green.

**Sources:** Signature-Key lines 1171-1215, 1248-1276

**Status:** pending

## Selected-profile boundaries

- The draft recommends `sub`, `aud`, `exp`, and `iat` for generic self-jwts.
  The signer consumes an already-issued JWT and therefore cannot manufacture
  missing application claims. Each application policy owns their presence;
  Events requires `aud`, `exp`, and `iat` but defines no `sub` claim.
- The source says cache by `iss+kid` until JWT expiration while discovery is
  selected by `iss+dwk` and supplies no same-`kid` refresh procedure for this
  scheme. AAuth-Go validates every JWT lifetime before discovery and reuses its
  already bounded HTTP metadata/JWKS resolver; it does not create a second
  self-jwt trust cache or claim a source-defined rotation algorithm.
- Ed25519/EdDSA is the portable implemented algorithm. The draft recommends
  EdDSA but does not make it the only permitted algorithm.
