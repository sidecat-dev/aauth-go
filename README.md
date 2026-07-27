# AAuth for Go

This is an independent Go implementation of AAuth maintained for use by
Sidecat. The protocol library has no Sidecat dependency. The `reference`
package supplies deployable role handlers and an agent client over the public
library. Sidecat is an intended consumer of this module; independence means the
dependency points from Sidecat to this library, never that Sidecat is excluded
from using it.

Resource-managed access is implemented as a complete two-party path. A
resource can apply caller-owned authorization policy without a signing key or
another AAuth server, advertise `access_mode=aauth-access-token`, issue an
opaque `AAuth-Access` credential, and bind its retained grant to the verified
agent identity and confirmation key. The agent signs `Authorization: AAuth`
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

Three-party call chaining is exercised through two real protected resources.
The intermediary signs as its own agent, carries the upstream auth token only
as evidence, obtains a downstream token bound to its own key, and the person
server verifies issuer trust, upstream audience, mission continuity, and the
delegation chain before issuing the downstream grant.

The person server also implements the local-action governance path intended
for Sidecat use. An agent can make a signed permission request with or without
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
Ed25519 public identity. Hosts such as Sidecat can therefore sign through an
operating-system key store, HSM, encrypted value service, or another protected
adapter without giving the AAuth package private-key bytes.

## Installing and proving the reference program

Install the standalone program with the ordinary Go toolchain:

```sh
go install gitlab.com/sidecat-dev/aauth-go/cmd/aauth-reference@latest
```

The program has no Sidecat or BEAM dependency. Immediately prove the installed
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
process boundary, not a Sidecat wrapper: the command imports only this module,
and Sidecat can run it as an independent AAuth peer.

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
        "alg": "EdDSA",
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
manifest pins the exact bytes and revisions of the six maintained source
documents. Each positive claim names a Go test; explicit omissions remain
unsupported or unclaimed instead of being inferred from nearby work.

Given a directory containing the pinned source filenames, verify the source
digests, complete heading inventory, evidence test names, and embedded coverage
contract with:

```sh
go run ./cmd/aauth-reference verify coverage \
  --source-dir /absolute/path/to/pinned-aauth-sources \
  --repo .
```

The command succeeds with one bounded JSON record. It fails closed if source
bytes or section structure drift, if a named test disappears, or if the
embedded manifest and inventory are invalid. To intentionally update the
coverage data after reviewing newer sources or changing claims, regenerate the
inventory and report:

```sh
go run ./internal/sourcecoverage/cmd/generate \
  --source-dir /absolute/path/to/pinned-aauth-sources \
  --repo .
```

`go test ./...` independently proves that the checked-in report exactly
matches the embedded contract and that every named evidence test still exists.
This is maintained implementation coverage, not a full-conformance
certification and not an upstream submission.

## Independent Elixir interoperability

The [interoperability evidence](interop/README.md) exercises the supported
agent-request profile in both directions against our separate Elixir AAuth
implementation. The Elixir implementation mints an agent token and signs a
mission-bearing request which Go verifies from exact retained wire values. Go
then generates the reciprocal token and signed request, which the Elixir
implementation verifies. Both directions include mutation controls for the
mission and Signature-Key bindings, and both generators are deterministic.

The Elixir implementation is comparator and peer evidence, not a runtime or
module dependency. Ordinary Go builds, tests, embedding, and the runnable
person server require no BEAM installation. The retained vectors make the Go
side continuously testable; rerunning the reciprocal Elixir check is an
explicit maintainer qualification.

Run the current qualification:

```sh
go test -race ./...
go vet ./...
```

Current scope is deliberately stated as a vertical, not full AAuth conformance.
Four-party call chaining, interaction/payment relay and callbacks, question
delivery, updated-request/cancel clarification actions, restart custody for
token/AS/resource continuations, R3, Events, Bootstrap, and the remaining
Signature-Key schemes still require implementation and qualification. Without
a configured `GovernanceStore`, an embedded reference person server
deliberately remains process-local. The runnable person profile always
configures the file adapter, which has a single-writer contract; a Sidecat or
other host embedding the package may implement the same standalone interface
with its own durable store.

No upstream contribution or repository is implied by this local project.
