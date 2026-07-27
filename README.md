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
a configured `GovernanceStore`, the reference person server deliberately
remains process-local. The file adapter has a single-writer contract; a Sidecat
or other host may implement the same standalone interface with its own durable
store.

No upstream contribution or repository is implied by this local project.
