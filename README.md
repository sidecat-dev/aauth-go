# AAuth for Go

This is an independent Go implementation of AAuth maintained for use by
Sidecat. The protocol library has no Sidecat dependency. The `reference`
package supplies deployable role handlers and an agent client over the public
library.

The implemented live vertical is the three-party mission flow:

1. an agent provider issues an Ed25519-bound `aa-agent+jwt`;
2. the agent signs a mission proposal to a person server;
3. the person server returns and retains exact approved mission bytes;
4. a resource verifies the agent proof and issues a mission-bound
   `aa-resource+jwt`;
5. the person server verifies the resource token, mission, agent, request key,
   audience, and scope before issuing an `aa-auth+jwt`;
6. the resource verifies the JWT trust and request-context proof before calling
   the protected operation.

HTTP request bodies use `Content-Digest`, all AAuth requests use the mandatory
RFC 9421 components, and protected operations reject an exact proof replay.
Issuer keys use admitted two-hop metadata/JWKS discovery with bounded reads,
cache lifetimes, unknown-key refresh throttling, and same-`kid` rotation
recovery.

Parent-mediated sub-agents also run through the complete resource-token,
person-server, auth-token, and protected-operation path. The person server
enforces single-level delegation and emits an auth token bound to the
sub-agent's key with the parent in `act.agent`.

The four-party path is live as well: resources can target an access server,
the person server applies user policy and signs the federated request with its
discoverable `jwks_uri` identity, the access server applies independent trust
and resource policy, and both the person server and agent verify the returned
proof-bound auth token before it reaches the resource.

Three-party call chaining is exercised through two real protected resources.
The intermediary signs as its own agent, carries the upstream auth token only
as evidence, obtains a downstream token bound to its own key, and the person
server verifies issuer trust, upstream audience, mission continuity, and the
delegation chain before issuing the downstream grant.

Run the current qualification:

```sh
go test -race ./...
go vet ./...
```

Current scope is deliberately stated as a vertical, not full AAuth conformance.
Four-party call chaining, deferred interactions, R3, Events, Bootstrap, and
the remaining Signature-Key schemes still require implementation and
qualification.

No upstream contribution or repository is implied by this local project.
