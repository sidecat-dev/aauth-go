# AAuth for Go

This is an independent, community-oriented Go implementation of AAuth. The
root package supplies portable protocol types and verification. The `reference`
package supplies deployable role handlers and an agent client over that public
library. Host applications consume the module through explicit interfaces;
the module has no dependency on a particular product or deployment.

The repository pins the complete current Dick Hardt editor-source family at
AAuth `a99d353cf18aee81d0c5445bac070164fb3b8bc5` and Signature-Key
`0ff751b571e7fe51336bcc1e526954a202317cc0`. The implementation is bounded:
its fully specified `Ed25519`, selected Signature-Key behavior, and bounded
distinct-server person-token, R3, and Budget journeys use the current topology.
[The source coverage report](SOURCE-COVERAGE.md) names the exact current claims;
sections without current executable evidence remain unclaimed. This is a
community-oriented standalone Go implementation; it does not claim an official
AAuth designation.

## Install

```sh
go get gitlab.com/sidecat-dev/aauth-go
```

The focused `jose` package owns the current Ed25519 JWK, caller-custodied
signing key, and compact-JWS parse, sign, and sealed-verification API. The
`signaturekey` package owns the selected Signature-Key schemes, exact HTTP
request proofs, admitted issuer-key discovery, and typed negotiation failures;
it leaves JWT credentials opaque. The root `aauth` package owns portable
protocol values, token semantics, and policy-aware verification.
Core verification returns `VerifiedToken[T]`: invalid-zero, copy-safe evidence
bound to the exact compact token, selected issuer key, token profile, and one
trusted verification instant. `Claims()` returns a defensive typed projection;
`EvidenceID()` identifies the exact retained verification without exposing a
constructor or mutable evidence fields.
The `r3` package owns exact-byte R3 documents, semantic operation sets, the
seven current standard vocabularies, third-party vocabulary admission, and
content digests. It also validates the R3 members retained in exact Core token
evidence and returns a sealed result bound to that evidence. These values do
not themselves authorize an operation. The reference package composes the
bounded four-party journey: deployment-owned review and grant policy creates a
sealed authorization partition, while signed retrieval and resource enforcement remain
role-specific responsibilities.
The `budgets` package owns exact Budget values, token-member validation,
narrowing, and `AAuth-Budget` parsing. Core `TokenDraft` values let R3 and
Budgets add their typed member sets to one resource or auth token before the
issuer signs the composed payload once. The reference roles exercise one
immediate four-party metered call with durable reservation, settlement, and
exact result recovery.
The `events` package owns exact AsyncAPI contract parsing and payload
validation plus admitted resource-contract and agent-endpoint discovery. Event
and subscribe token profiles remain in root Core for now; their package move is
not implied by the contract/discovery boundary.
Deployable reference role handlers, host-owned storage interfaces, and an
agent client are in `reference`. [Architecture](ARCHITECTURE.md) maps the
observed package structure, target import graph, endpoint-specific evidence
flows, and recovery contracts. The
[implementation interpretation register](INTERPRETATIONS.md) records observable
choices, alternatives, reasons, and evidence in one
place. [Retained-source provenance](PROVENANCE.md) makes every current input
reproducible, and the [specification feedback journal](SPEC-FEEDBACK.md) tracks
evidence-backed questions and their upstream dispositions. Runnable package
examples exercise the current person-token path.

## Implemented current behavior

The current walking skeleton is a real four-party path. A person server
validates a mission proposal before policy and gives policy the authenticated
agent, proof key, AgentToken expiry, and PS binding. Immediate approval retains
one exact recovery record before committing the mission and its resource-keyed
person tokens. Partial writes, uncertain commits, restart, and an exact replay
recover the same response without rerunning policy or minting new tokens.

The agent presents a directed `aa-person+jwt` to a resource. The resource issues
a current `aa-resource+jwt`; the PS resolves its `presented_jti` against durable
person-token custody; an independently authenticated AS issues the current
`aa-auth+jwt`; both the PS and agent reject an auth token that outlives the
resource token; and the resource verifies the token and signed call before
invoking its host operation. The included person-token and mission-issuance file
stores are private, single-writer reference adapters. They do not coordinate
multiple processes or compact expired records; long-running or high-volume
deployments should supply their own store implementations.

The same current path can begin at an ordinary protected operation. The agent
signs the exact call with its resource-directed person token. The resource maps
the required scope, performs no host consequence, and returns an auth-token
challenge carrying its resource token. The agent verifies that token against
the resource, its own key, and the person token's exact namespace and context;
exchanges it through the ordinary PS and AS path; then retries the same method,
target, body, and media type once under the resulting auth token.

A resource may instead select the current stateful `202 Accepted` form. It
retains the exact invocation before releasing a same-origin pending URL. The
agent obtains the auth token through the same exchange and completes with a
signed `GET`. The first valid token claims a stable host consequence key; the
resource retains the exact terminal status, media type, and body before release.
A lost terminal response and reconstructed resource return that retained result
without rerunning protected policy or the host consequence. Store reopen also
re-verifies the original person-token request proof, so rewriting a canonical
snapshot cannot change the held invocation.

This slice is deliberately bounded. `reference.Resource` implements explicit
`person-token`, `auth-token`, and `session-token` modes, not every registered
access mode.
Companion-bearing deferred calls, refreshed resource tokens during a pending
call, deferred PS or AS authorization, resource-owned person identity matching,
collocated PS/AS roles, and dynamic three-party PS
selection, and account ownership remain open. The exercised current profile
includes immediate and deferred PS/AS authorization, one-level parent-mediated
sub-agents, and upstream-auth-token call chaining through either a PS or AS. Exact
mission recovery requires replay of the original signed request inside its
signature window. See [AAG-I005 and AAG-I006](INTERPRETATIONS.md) for the
person-token denial extension and cross-store recovery contract.

In `person-token` mode, the agent signs the protected call directly with its
resource-directed person token. The resource verifies the directed identity and
exact request proof, maps the operation's required local policy scope, consumes
replay, and gives its policy and host operation the separate person-server,
subject, mission, and tenant context. No resource token or auth token is minted;
the resource alone decides what that identity may do.

`reference.Resource` requires an explicit current `access_mode`. Its
`auth-token` mode accepts only current auth tokens carrying `ps` and `sub` and
omitting `agent`, `act`, and `mission`. Its `session-token` mode applies a
caller-owned local authorization policy, issues an opaque `AAuth-Access`
credential, and binds the retained grant to the verified agent identity and
confirmation key. The initial protected request is signed with the agent token
and enters that local policy directly; `/authorize` remains person-token-only.
The protected retry presents `Authorization: AAuth` with another agent-token
proof. The agent adopts downscoped grants and rotated credentials, and the
resource refuses unsigned, substituted, replayed, expired, or differently-keyed
use before invoking the protected operation.

Resource configuration supplies one canonical issuance allowlist in `Scopes`,
one human-readable `ScopeDescriptions` entry for each advertised auth-token
scope, and a `RequiredScopesForRequest` callback that maps each protected path
to the exact nonempty subset it needs. Auth-token mode also requires a
`ProtectedAuthorizationPolicy` that decides the fully verified person and
token context before any protected response or Operation consequence. A policy
denial returns a fixed non-leaking 403 response. Resource configuration also
supplies a `ProofReplayStore`; there is no in-process fallback. The memory
adapter is bounded and explicitly non-durable. The bounded file adapter retains
canonical exact replay state under private single-writer custody, refuses
corrupt or unsafe state, and rejects the same proof after close and reopen.

After verification and durable proof consumption, the protected Operation
receives `ps` and `sub` separately from the exact confirmation JWK. It also
receives the proof replay key and creation time plus normalized auth-token
issuer, issuer role (`dwk`), token ID, issued-at time, and expiry. The required
protected policy receives a defensive copy of that same context. Current auth
tokens do not name the agent; a host resolves its separately enrolled local
principal from the verified confirmation key. The raw auth token remains
available for exact authorization-evidence custody.

That path can also defer for resource-hosted user interaction. Pending
continuations use 128-bit random URLs, 40-bit Crockford codes, same-origin
signed polling, enforced `Retry-After`/`slow_down`, bounded code attempts,
single-use interaction entry, a separate trusted approval or rejection
boundary, and expiry. After the caller receives and retains the pending URL,
approved terminal artifacts are committed before release and remain exactly
recoverable after a lost terminal response or process restart. Loss of the
initial `202 Accepted` and its pending URL is not recoverable in the current
wire shape; AAG-F012 in `SPEC-FEEDBACK.md` records the accepted next
interaction/recovery slice. Merely presenting the interaction code cannot
approve a grant.

Every deferred-capable reference role requires an explicit
`AuthorizationStateStore`: each Agent, PersonServer, AccessServer, and
session-token Resource receives a distinct store instance for its own canonical
current schema. `NewMemoryAuthorizationStateStore` is bounded ephemeral
custody. `OpenFileAuthorizationStateStore` provides bounded private
single-writer custody with canonical decoding and atomic fsync-backed replace;
corrupt, ambiguous, oversized, or unsafe state fails closed. There is no
implicit in-process store.

Body-bearing resource-managed consequences use one call shape. The Agent signs
the exact body and media type, and the Resource passes defensive copies to the
Operation callback:

```go
response, err := agent.DoWithAccess(ctx, reference.AuthorizedCall{
	Method:      http.MethodPost,
	Endpoint:    "https://resource.example/documents",
	Body:        []byte(`{"query":"current"}`),
	ContentType: "application/json",
}, &grant)
```

HTTP request bodies use `Content-Digest`, all AAuth requests use the mandatory
RFC 9421 components, query-bearing calls additionally cover the exact `@query`,
and protected operations durably consume an exact proof
before their host callback.
Issuer keys use admitted two-hop metadata/JWKS discovery with bounded reads,
cache lifetimes, unknown-key refresh throttling, and same-`kid` rotation
recovery.
Token JSON and reference endpoint request JSON reject exact duplicate member
names and names that Go would case-fold onto the same struct field before
decoding.

One bounded immediate four-party R3 path is callable. The AS partitions one
exact requested operation set into direct and per-call operations. Direct
operations run under `r3_granted`. A `401` per-call operation produces an exact
content-addressed proposal for one call, admits only the PS and AS as readers,
and goes through both policies again. The retry must match inline JSON
structurally and digest parameters byte-for-byte before a provider-keyed
operation runs once. A dropped response, resource reconstruction, or exact
retry returns the retained result; a concurrent retry cannot run the provider
again.

This is not complete R3 conformance. Deferred `202` per-call delivery,
three-party R3, and document caching remain open. Direct and per-call AS
issuance retains the required audit fields and exact token response atomically
before release; exact retry after a lost response or AS reconstruction returns
that record without rerunning policy.

One bounded immediate four-party Budget path is also callable. The agent's
requested value is narrowed independently by the resource, PS, and AS without
changing its denomination. The resource atomically reserves the declared
maximum before provider execution, prevents concurrent oversubscription,
settles actual cost, and returns the current remainder. A committed result is
retained before release: a dropped response and reconstructed resource return
the same JSON result without rerunning policy, pricing, or the provider. An
insufficient maximum is refused before the provider with a fresh resource
token, `AAuth-Requirement` reason, and `AAuth-Budget` remainder and required
values.

This is not complete Budgets conformance. Metadata-driven discovery, general
recent-consumption selection, usage counters, streaming trailers, billing
integration, deferred Budget authorization, and broader deployment topologies
remain unclaimed. Core verification
retains structurally complete companion members only as exact evidence; an
endpoint must return matching invalid-zero companion evidence or reject those
members. Existing non-companion endpoints reject them, and the removed
`r3_conditional` name remains only as a rejected negative vector.
Bounded current
sub-agent and call-chain behavior is claimed only for the exact runnable
journeys listed in the source coverage report; broader delegation and
interaction chaining remain explicit gaps.

### Governance surfaces

Permission, audit, and mission-completion APIs remain separate from the current
Resource auth-token boundary. Their exact current claims and runnable evidence
are listed section by section in `SOURCE-COVERAGE.md`.

The person server also implements a host-integrated local-action governance
path. An agent can make a signed permission request with or without
a mission and receive an immediate grant/denial or an ownership-bound deferred
interaction. Mission-bound permission requests, terminal decisions, and signed
audit submissions enter an ordered append-only mission log. Host policy sees
the exact approved mission bytes, approved tools, and a defensive copy of the
prior log. A host-owned termination transition permanently refuses later
permission and audit use, including a deferred grant approved before
termination but not yet delivered.

An agent can also propose mission completion through the person server's
published interaction endpoint. The proposal is signed, bound to the exact
active mission and initiating key, and placed into a durable approval
continuation. A trusted host may ask up to five clarification questions; the
agent posts signed, self-describing Markdown answers and resumes polling. Host
acceptance records the terminal interaction response and mission termination
atomically before returning success. Pending review, clarification, expiry,
acceptance, terminal delivery, replay proofs, and the complete ordered
interaction/clarification log survive restart. The client accepts the draft's
empty `200 OK` completion response as well as the reference server's optional
`{"status":"completed"}` body.

Governance custody can be injected through the small `GovernanceStore`
interface. The included single-writer file adapter writes private `0600`
checksum-bound snapshots by synced temporary-file replacement and refuses
empty, malformed, cross-server, loosely-permissioned, or semantically
inconsistent state. Approved missions, ordered logs, permission and completion
continuations, terminal tombstones, every governed request and terminal
response, and active governance replay proofs survive restart. Mission-log
request entries archive the verified signature headers, presented credential,
public-key snapshot, request target, timestamps, replay identity, and exact
body. That material is sensitive evidence custody, not display data.

Signing keys can likewise remain host-custodied. `jose.NewSigningKey` accepts a
standard `crypto.Signer` and retains only that signing capability plus its
Ed25519 public identity. A host can therefore sign through an operating-system
key store, HSM, encrypted value service, or another protected adapter without
giving the AAuth package private-key bytes.

## Bootstrapping an enrolled agent

The standalone library implements the source-backed agent-token refresh
patterns that turn an enrolled installation into a usable agent. The mandatory
Ed25519 profile supports both inline `hwk` requests and
`jkt-s256+jwt` delegation: a durable installation key self-signs a short-lived
JWT naming a fresh ephemeral key, and that ephemeral key signs the refresh
request. Verification exposes the durable thumbprint identity separately from
the request key and refuses expiry, issuer/key mismatch, signature mutation,
and a request signed by the durable key instead of the delegated key.

`reference.AgentProvider` serves `POST /refresh` when configured with an
`EnrollmentStore`. The store maps the durable RFC 7638 thumbprint to a stable
opaque agent identifier and allowed person server. Provider policy, token IDs,
token lifetime, enrollment lookup, and replay custody are caller-owned
boundaries. Delegations are limited to five minutes by default, with an
explicit provider setting required to change that ceiling. The included static
enrollment map and memory replay store are useful for embedding and
qualification; a durable or horizontally scaled deployment supplies its own
implementations.

`reference.BootstrapClient.Refresh` performs the two-key exchange and returns a
verified `BootstrapResult` containing the stable identifier, active ephemeral
signing key, agent token, and verified claims. That result can be passed
directly to `reference.NewAgent`. Every refresh includes a fresh
content-digest-covered client nonce, so two refreshes made with the same keys
inside one clock second remain distinct while an exact retransmission is still
refused. `RefreshSingleKey` implements the simpler profile in which the
durable key signs with `hwk` and remains the token's confirmation key.

The complete journey rotates the ephemeral key across two refreshes while
preserving the enrolled identity, then uses the second token for a real mission
request. Separate controls refuse an unknown durable key and an exact refresh
proof replay. Platform enrollment ceremonies, hardware attestation, and
platform-specific key stores remain deployment concerns; both durable and
ephemeral keys can use caller-custodied `crypto.Signer` implementations.

## Installing and proving the reference program

Install the standalone program with the ordinary Go toolchain:

```sh
go install gitlab.com/sidecat-dev/aauth-go/cmd/aauth-reference@latest
```

The program has no dependency on another application runtime. Immediately
prove the installed
binary's protected profile, TLS process boundary, mission approval,
mission-bound permission, outcome audit, default denial, durable governance,
and process-restart recovery with:

```sh
aauth-reference demo person
```

The demonstration creates an ephemeral `0700` workspace, launches
`aauth-reference serve person` as a separate process twice against the same
protected governance file, and removes the workspace when it finishes. Success
is one bounded `aauth.reference.person-demo.v0` JSON record. It never prints
the ephemeral keys or custody paths.

## Running a person server

The module includes one deliberately small deployment program:

```sh
go run ./cmd/aauth-reference serve person --profile /absolute/path/person.json
```

It serves the standalone `reference.PersonServer` over TLS 1.3 and persists
mission governance through `reference.FileGovernanceStore`. It is a real
process boundary, not an application wrapper: the command imports only this
module and can run as an independent AAuth peer.

The profile is strict JSON with this shape:

```json
{
  "format": "aauth.reference.person-profile.v0",
  "identifier": "https://person.example",
  "listen": "127.0.0.1:8443",
  "key_id": "person-key-1",
  "signing_key": "<base64 encoding of a 64-byte Ed25519 private key>",
  "tls_certificate": "/absolute/path/person-chain.pem",
  "tls_private_key": "/absolute/path/person-tls-key.pem",
  "governance_file": "/absolute/path/state/person-governance.json",
  "trusted_keys": {
    "https://ap.example": [
      {
        "kty": "OKP",
        "crv": "Ed25519",
        "x": "<base64url public key>",
        "alg": "Ed25519",
        "kid": "ap-key-1"
      }
    ]
  },
  "allowed_actions": ["store.backup.create"],
  "allowed_scopes": []
}
```

Go JSON encodes the `signing_key` byte slice with standard padded base64.
The profile, TLS chain, and TLS private key must be canonical absolute paths
to owned, regular, single-link `0600` files below non-symlinked directories.
The TLS leaf must cover the profile identifier's host. The governance
directory is created as `0700`, and an existing snapshot must satisfy the same
private-file custody checks. These checks currently express POSIX host
custody; the protocol and reference packages remain independent of the
executable's deployment adapter.

`trusted_keys` is an explicit issuer-to-JWK trust map. Mission tools and local
permission actions are default-deny against `allowed_actions`; authorization
scopes are default-deny against `allowed_scopes`. Startup emits one bounded
JSON readiness line containing the schema, AAuth identifier, and bound address.
SIGINT or SIGTERM performs a bounded graceful shutdown. Errors do not echo
profile contents or private keys.

Before startup, compose and validate the exact same protected signer, current
TLS identity, trust map, policy, and governance snapshot without binding the
listener:

```sh
aauth-reference diagnose person --profile /absolute/path/person.json
```

Success emits one bounded `aauth.reference.person-diagnostic.v0` JSON record
with public identity, certificate validity, policy counts, and whether durable
governance is new or loaded. It omits private keys and all custody paths.
Corrupt retained governance, an expired certificate, an unsafe file, or an
invalid trust or policy boundary fails before the server can run.

The process qualification builds the actual binary, connects a real agent over
certificate-verified HTTPS, creates and uses a mission, records audit evidence,
refuses an unlisted action, restarts the process, and proves the same mission
and durable governance remain usable.

## Verifying maintained source coverage

The repository carries a generated [source coverage report](SOURCE-COVERAGE.md)
and the machine-readable manifest and section inventory that produce it. The
manifest pins the exact bytes and revisions of seven current maintained source
documents—core, Signature-Key, R3, Events, Bootstrap, Budgets, and the
interoperability profile—and the pinned bytes themselves are retained in
`internal/sourcecoverage/sources/`, so every digest resolves from a fresh
clone. Each positive claim names a Go test; explicit omissions remain
unsupported or unclaimed instead of being inferred from nearby work.

The implemented profile is bounded and is named precisely in the report.
Active JWT, JWK, HTTP-signature algorithm, negotiation, and selected discovery
surfaces use fully specified `Ed25519`, require the same fully specified
algorithm on applicable JWKs, and return `Accept-Signature-Alg` and
`Accept-Signature-Scheme` negotiation. The report claims only behavior tied to
current executable evidence. Every other unevidenced current section remains
partial or unclaimed.

Verify the source digests, complete heading inventory, evidence test names,
and embedded coverage contract with:

```sh
go run ./cmd/aauth-reference verify coverage
```

The command verifies the retained repository sources by default; pass
`--source-dir` to verify against an external directory of the same pinned
filenames. It succeeds with one bounded JSON record and fails closed if source
bytes or section structure drift, if a named test disappears, or if the
embedded manifest and inventory are invalid. To intentionally update the
coverage data after reviewing newer sources or changing claims, regenerate the
inventory and report:

```sh
go run ./internal/sourcecoverage/cmd/generate
```

`go test ./...` independently proves that the checked-in report exactly
matches the embedded contract and that every named evidence test still exists.
This is maintained implementation coverage, not a full-conformance
certification and not an upstream submission.

## Retained Elixir-origin interoperability fixtures

The repository retains [historical wire fixtures](interop/README.md) attributed
to an earlier Elixir prototype. Those exact compact JWS bytes use the now
prohibited polymorphic `EdDSA` identifier. Go tests retain and deliberately
reject them with `unsupported_algorithm`; they are retained historical
rejection vectors, not current evidence of a running peer implementation.
The active Go-origin fixtures are regenerated with fully specified `Ed25519`
and execute through the public verifier.

Ordinary Go builds, tests, embedding, and the runnable person server require no
BEAM installation. Re-running both generators and both independent verifiers
from pinned clean checkouts is an explicit future qualification gate before
any bidirectional-interoperability claim is restored.

Run the current qualification:

```sh
go test -race ./...
go vet ./...
```

Current scope is deliberately stated as a vertical, not full AAuth conformance.
The selected HTTP-message-signature profile supports mandatory `created` and
optional RFC 9421 `expires` parameters, returns typed library errors, and has
the reference handlers emit RFC 8941 `Signature-Error` dictionaries with a
Problem Details body whose type is the Signature-Key draft's matching
`urn:ietf:params:sig-error:` URI. Clients use the header as the authoritative
machine-readable failure record; operational key-resolution failures remain
local `503` failures, and a policy denial after successful authentication
remains an ordinary `403` without signature negotiation.

The selected public Events profile is implemented and qualified as one narrow
vertical. Its `self-jwt` proof requires that the same admitted, discovered key
verifies both the compact JWT and its HTTP Message Signature. An agent provider
issues a strict subscribe token with `max_uses: 1`; the agent retains its local
context and registers that exact token at the resource; and the resource may
deliver one payload-free event through the provider to the agent. The AP can
see the event token. Any future token-carried payload would therefore be
AP-visible. This profile does not put event data in that token: the agent
retrieves current details from the resource under its current authorization.

The resource retains the exact event token before sending it. Lost `202
Accepted` delivery is reconciled by retrying that exact JWT with a fresh HTTP
proof. A resulting `429 Too Many Requests` settles the retained attempt without
a second acceptance. The AP-to-agent adapter is a non-normative host-integration
adapter, not a standardized wire protocol. Protected subscription tickets and
AsyncAPI remain outside this public profile; the separate protected profile
below implements one bounded ticket and direct-JSON AsyncAPI path.
Token-carried payloads and multi-event replay remain outside both profiles.
The bounded file stores provide single-writer reference-host qualification;
they are not enterprise or distributed storage conformance.

The selected protected Events profile is implemented and qualified as a
separate one-use vertical. An authenticated resource operation commits an
opaque ticket capability after the host resolves the verified confirmation key
to its separately enrolled local agent. The resource retains only its SHA-256
digest and the exact agent, operation, resource-revision, contract, message,
expiry, and use bindings. A bodyless signed registration atomically consumes
that ticket and
creates the subscription. A deployment may opt into a bounded registration
body validator, but no registration-body schema mapping is inferred from the
AsyncAPI document.

The protected event is the complete direct `application/json` HTTP body; the
event JWT remains payload-free. The resource validates and retains the exact
token, body, media type, and digest before sending signed `content-type` and
`content-digest`. The AP commits that exact pair before `202 Accepted`, and a
lost `202 Accepted` is settled by an exact retry and exhausted `429 Too Many
Requests` without a second inbox record. The agent independently validates the
same body against the digest-pinned contract before one durable action.

The selected contract is one exact AsyncAPI 3.0.0 JSON document with one
parameterized channel, one `receive` operation, one locally referenced message,
`application/json`, and an inline JSON Schema Draft 7 payload. Multi-event replay identity, a
standardized AP-to-agent transport, general AsyncAPI/YAML/external-reference
support, registration-body schema mapping, and lost-success
protected-registration reconciliation remain unsupported. The provided memory
and bounded single-writer file stores qualify replaceable host boundaries; they
do not claim distributed, multi-writer, federated, or enterprise storage.

Resource-owned interaction chaining, interaction/payment relay and callbacks,
question delivery, updated-request/cancel clarification actions,
existing-token step-up, deferred `202` and three-party
R3, R3 challenge selection, R3 caching and multiple-definition composition,
platform enrollment/attestation, x509, and additional Signature-Key schemes
still require implementation and qualification.
The Phase-1 `Accept-Signature-Alg` and
`Accept-Signature-Scheme` failure envelopes are implemented and qualified.
Without a configured
`GovernanceStore`, an embedded reference person server deliberately remains
process-local. The runnable person profile always configures the file adapter,
which has a single-writer contract; a host embedding the package may implement
the same standalone interface with its own durable store.

This repository is maintained as a community-oriented standalone Go
implementation. No official designation, repository transfer, or upstream
acceptance is claimed.
