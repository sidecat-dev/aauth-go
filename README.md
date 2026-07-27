# AAuth for Go

This is an independent Go implementation of AAuth maintained for use by
Sidecat. The protocol library has no Sidecat dependency. The `reference`
package supplies deployable role handlers and an agent client over the public
library.

The first implemented vertical is the three-party mission flow:

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

Run the current qualification:

```sh
go test -race ./...
go vet ./...
```

Current scope is deliberately stated as a vertical, not full AAuth conformance.
Four-party access servers, sub-agents, call chaining, deferred interactions,
R3, Events, Bootstrap, HTTP key discovery/caching, and the remaining
Signature-Key schemes still require implementation and qualification.

No upstream contribution or repository is implied by this local project.
