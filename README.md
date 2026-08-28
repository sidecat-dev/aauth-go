# AAuth for Go

This is an independent, community-oriented Go implementation of AAuth. The
root package supplies portable protocol types and verification. The `reference`
package supplies deployable role handlers and an agent client over that public
library. Host applications consume the module through explicit interfaces;
the module has no dependency on a particular product or deployment.

The repository pins the complete current Dick Hardt editor-source family at
AAuth `a99d353cf18aee81d0c5445bac070164fb3b8bc5` and Signature-Key
`0ff751b571e7fe51336bcc1e526954a202317cc0`. The implementation is transitional:
its fully specified `Ed25519`, selected Signature-Key behavior, and one
distinct-server immediate person-token journey use the current topology. Older
resource, governance, delegation, and R3 journeys remain useful regression
evidence, but [the source coverage report](SOURCE-COVERAGE.md) does not count
them as current-protocol conformance. This is a community-oriented standalone
Go implementation; it does not claim an official AAuth designation.

## Install

```sh
go get gitlab.com/sidecat-dev/aauth-go
```

The public API is the root `aauth` package. Deployable reference role handlers,
host-owned storage interfaces, and an agent client are in `reference`. The
[implementation interpretation register](INTERPRETATIONS.md) records observable
choices, alternatives, reasons, evidence, and compatibility effects in one
place. [Retained-source provenance](PROVENANCE.md) makes every current input
reproducible, and the [specification feedback journal](SPEC-FEEDBACK.md) tracks
evidence-backed questions and their upstream dispositions. Runnable package
examples are part of the current person-token migration.

## Implemented behavior during the current migration

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

This slice is deliberately bounded. `reference.Resource` implements explicit
`auth-token` mode, not every registered access mode. Protected-resource 401
challenge handling, resource-owned person identity matching, current deferred
approval, current sub-agent and call-chain behavior, collocated PS/AS roles,
general three-party PS selection, and account ownership remain open. Exact
mission recovery requires replay of the original signed request inside its
signature window. See [AAG-I005 and AAG-I006](INTERPRETATIONS.md) for the
person-token denial extension and cross-store recovery contract.

Unless a paragraph explicitly says otherwise, the journeys in this section are
implemented behavior from the preceding profile and are retained as migration
and regression evidence. `SOURCE-COVERAGE.md` is the authority for current
section claims.

Resource-managed access is implemented as a complete legacy two-party path. A
resource can apply caller-owned authorization policy without a signing key or
another AAuth server, advertise the earlier
`access_mode=aauth-access-token`, issue an opaque `AAuth-Access` credential,
and bind its retained grant to the verified agent identity and confirmation
key. The current editor source renames that metadata value to `session-token`;
the reference resource has not migrated that advertisement and does not claim
current resource-metadata conformance. The agent signs `Authorization: AAuth`
as a covered component, adopts downscoped grants and rotated credentials, and
the resource refuses unsigned, substituted, replayed, expired, or
differently-keyed use before invoking the protected operation.

That path can also defer for resource-hosted user interaction. Pending
continuations use 128-bit random URLs, 40-bit Crockford codes, same-origin
signed polling, enforced `Retry-After`/`slow_down`, bounded code attempts,
single-use interaction entry, a separate trusted approval or rejection
boundary, expiry, and one-shot terminal delivery. Merely presenting the
interaction code cannot approve a grant.

The three-party mission flow is also implemented end to end:

1. an agent provider issues an Ed25519-bound `aa-agent+jwt`;
2. the agent signs a mission proposal to a person server;
3. the person server returns and retains exact approved mission bytes;
4. a resource verifies the agent proof and issues a mission-bound
   `aa-resource+jwt`;
5. the person server verifies the resource token, mission, agent, request key,
   audience, and scope before issuing an `aa-auth+jwt`;
6. the resource verifies the JWT trust and request-context proof before calling
   the protected operation.

The person server can defer that token exchange for its own user interaction.
Its pending state is bound to the initiating agent and key, retains the
already-verified resource and mission context, and invokes deployment policy
only after a separate trusted approval. Success, denial, expiry, invalid-code
failure, replay refusal, and one-shot terminal delivery run through the actual
person-server, agent, and resource handlers. Polling clients honor both
`429` linear slowdown and `503 Retry-After`.

HTTP request bodies use `Content-Digest`, all AAuth requests use the mandatory
RFC 9421 components, and protected operations reject an exact proof replay.
Issuer keys use admitted two-hop metadata/JWKS discovery with bounded reads,
cache lifetimes, unknown-key refresh throttling, and same-`kid` rotation
recovery.

Parent-mediated sub-agents also run through the complete resource-token,
person-server, auth-token, and protected-operation path. The person server
enforces single-level delegation and emits an auth token bound to the
sub-agent's key with the parent in `act.agent`. The parent can retain and poll
a deferred PS continuation on the sub-agent's behalf; the sub-agent never gains
authority to call or poll the PS directly.

The four-party path is live as well: resources can target an access server,
the person server applies user policy and signs the federated request with its
discoverable `jwks_uri` identity, the access server applies independent trust
and resource policy, and both the person server and agent verify the returned
proof-bound auth token before it reaches the resource.

The access server may also defer for resource-owner interaction. It binds its
pending state and signed polls to the initiating person-server identity and
key. The person server retains a distinct agent-facing pending URL, relays the
AS interaction requirement without exposing AS polling authority, polls the AS
with its own key, and validates the terminal AS token before returning it to
the agent. Slowdown, denial, expiry, invalid-code failure, and one-shot terminal
delivery cross both continuation boundaries.

One R3 direct-grant path and one conditional per-call path are implemented
through that real four-party flow. A
resource advertises an MCP vocabulary, validates an agent's `r3_operations`
through a deployment-owned authoritative-definition boundary, serializes and
durably retains one exact R3 document through a deployment-owned store, and
issues its URI plus unpadded SHA-256 hash in the resource token only after that
retention succeeds. The included bounded file store preserves exact bytes
across resource reconstruction, requires a private custody directory, and
never evicts a document while its resource token is live. The AS alone performs a signed, admitted, deadline-bounded,
no-redirect fetch; verifies the exact bytes before parsing or policy;
coalesces a hash-keyed cache with recoverable least-recently-used eviction; and
requires a successful issuance-audit write before releasing an auth token.
The resource independently enforces both ordinary scope and semantic
membership in `r3_granted`, without fetching class R3 at call time. The agent retains
its requested operation set in the persistable resource-grant value and fails
closed if that binding is absent after reconstruction.

Access policy may instead place a verified operation in `r3_conditional`. The
first signed call then executes nothing: the resource captures the bounded
exact body, builds and durably retains a strict one-operation proposal, and
returns an auth-token requirement containing a signed resource token with only
the proposal URI/hash. Query-bearing conditional calls are refused, and
`Content-Type` is signed whenever a protected body is present. The AS alone
fetches and hash-verifies the proposal, policy must directly grant exactly its
one operation, and a bounded file issuance store in a private custody
directory atomically commits the exact auth token plus proposal, operation, agent, resource, mission, challenge-token,
and issued-token audit identities. A deployment-owned audit callback must then
durably and idempotently record that stable issuance identity before release;
its retention is independent of the short-lived recovery store. If either
step fails, no token is released. Repeating the exchange after AS
reconstruction retries the audit and returns the same committed token.

On retry, the resource reloads the exact proposal and compares every actual
parameter. Inline parameters compare as JSON values; digest parameters compare
the full presented bytes and media type, never the display excerpt. Durable
consumption keyed by proposal digest and per-call token JTI happens immediately
before the operation, survives resource reconstruction, and admits only one
use. This is at-most-once operation admission: a crash after consumption but
before the external consequence can lose the opportunity, so the library does
not claim exactly-once effects.

The included store guarantees exact-byte availability through the resource
token's expiry; it is not permanent historical custody after that expiry.
Token JSON and reference endpoint request JSON reject exact duplicate member
names and names that Go would case-fold onto the same struct field before
decoding.

These R3 journeys implement an earlier profile and remain regression evidence,
not current R3 coverage. The current source uses `r3_per_call`, builds on the
person-token topology, and permits both the PS and AS to retrieve the exact R3
document. The existing `r3_conditional` and AS-only handler behavior must
migrate before the repository claims any current R3 section. Scope-free R3,
multi-definition composition, live discovery adapters for every standard
vocabulary, multi-process file-store coordination, and deferred R3 also remain
open. The [source coverage report](SOURCE-COVERAGE.md) keeps that boundary
explicit, and [AAG-I004](INTERPRETATIONS.md#aag-i004--current-r3-proposal-retrieval-must-admit-both-the-ps-and-as)
records why the older endpoint interpretation was withdrawn.

### Legacy governance and delegation evidence

The following governance, completion, call-chaining, and sub-agent journeys
exercise an earlier protocol profile. They remain valuable regression evidence,
but they do not establish coverage of the corresponding current-editor
sections. The current profile uses `mission_s256`, completes missions at the
mission endpoint, and depends on the person-token topology described above.

Three-party call chaining is exercised through two real protected resources.
The intermediary signs as its own agent, carries the upstream auth token only
as evidence, obtains a downstream token bound to its own key, and the person
server verifies issuer trust, upstream audience, mission continuity, and the
delegation chain before issuing the downstream grant.

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

Signing keys can likewise remain host-custodied. `NewSigningKey` accepts a
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

The implemented profile is transitional and is named precisely in the report.
Active JWT, JWK, HTTP-signature algorithm, negotiation, and selected discovery
surfaces use fully specified `Ed25519`, require the same fully specified
algorithm on applicable JWKs, and return `Accept-Signature-Alg` and
`Accept-Signature-Scheme` negotiation. The report claims only the exercised
parts of the immediate current person-token journey. Challenge handling,
resource identity continuity, current delegation and deferred paths, and every
other unevidenced current section remain partial or unclaimed.

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
reject them with `unsupported_algorithm`; they are historical compatibility
boundary evidence, not current evidence of a running peer implementation.
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
opaque ticket capability while retaining only its SHA-256 digest and exact
agent, operation, resource-revision, contract, message, expiry, and use
bindings. A bodyless signed registration atomically consumes that ticket and
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

Missionless direct-AS call chaining, resource-owned interaction chaining,
interaction/payment relay and callbacks, question delivery,
updated-request/cancel clarification actions, restart custody for
token/AS/resource continuations, broader R3 vocabularies and PS proposal use,
platform enrollment/attestation, x509, additional Signature-Key schemes, and
broader challenge-selection behavior still require implementation and
qualification. The Phase-1 `Accept-Signature-Alg` and
`Accept-Signature-Scheme` failure envelopes are implemented and qualified.
Without a configured
`GovernanceStore`, an embedded reference person server deliberately remains
process-local. The runnable person profile always configures the file adapter,
which has a single-writer contract; a host embedding the package may implement
the same standalone interface with its own durable store.

This repository is maintained as a community-oriented standalone Go
implementation. No official designation, repository transfer, or upstream
acceptance is claimed.
