# Specification baseline

This repository implements a bounded part of the current AAuth editor source.
The exact commits below define the text used for implementation and review.
Rendered Internet-Draft publications may be older than these editor revisions.

## Implemented sources

### AAuth Core

- Repository: [dickhardt/AAuth](https://github.com/dickhardt/AAuth)
- Commit:
  [`a99d353cf18aee81d0c5445bac070164fb3b8bc5`](https://github.com/dickhardt/AAuth/commit/a99d353cf18aee81d0c5445bac070164fb3b8bc5)
- Editor source:
  [`draft-hardt-oauth-aauth-protocol.md`](https://github.com/dickhardt/AAuth/blob/a99d353cf18aee81d0c5445bac070164fb3b8bc5/draft-hardt-oauth-aauth-protocol.md)
- Editor-source SHA-256 at that commit:
  `c984278f21e3931f0cc272d6768b84bcc471f8ab4a1a1922dd92940a91df7e19`

The current implementation covers direct Agent identity, direct Person
identity, Resource-managed opaque sessions, immediate and deferred three-party
PS authorization, bounded three-party auth-token revocation and explicit
re-authorization, and the four-party Core path. A direct Resource verifies the
selected agent or person token and matching request proof without requiring an
Access Server. A Resource-managed session similarly needs no Person Server or
Access Server: the Resource applies immediate policy and may run its own
interaction, retains its opaque credential, and requires the Agent to cover
`Authorization` in every session request proof. Direct Agent
identity includes a one-level sub-agent using its own token and key; the
parent-mediated authorization journey remains outside this cut. For direct
Agent identity, Resource metadata is optional when the caller supplies the
exact additional signature components. In three-party authorization, the
Resource issues a resource token to the verified Person Server, which verifies
retained person-token lineage and either directly issues a narrowed auth token
with `dwk: aauth-person.json` or parks that verified request for explicit
host-authenticated consent. In the four-party path, the resource token names an
Access Server and the Person Server federates the exchange. The resulting auth
token protects an HTTP request in both paths. If PS and AS share one origin,
the explicit federated composition still requires `dwk: aauth-access.json`;
URL equality does not turn that flow into three-party authorization.
Each interaction poll is one explicit signed `GET`. Three-party PS consent is
domain-specific and does not claim deferred AS federation. Both authorization
topologies support a baseline `401` retry. The federated Resource can instead
hold the request and return `202`, completed through explicit signed `GET`
polls. Each `PollAuthToken` call makes exactly one poll.
For three-party revocation, the PS retains issued-token routing before release,
the Resource recognizes an otherwise-valid token on first protected use, and
the PS admits each remote URL before making one body-bound signed revocation
request. A caller explicitly
retries an uncertain outcome or runs the ordinary authorization sequence for a
fresh token. This does not claim pre-use, four-party, Agent-token, mission, or
session revocation.

Core requires fully specified JOSE algorithm identifiers and requires support
for `Ed25519`. This implementation uses `Ed25519`; it does not accept the
polymorphic `EdDSA` identifier as an equivalent spelling.

### HTTP Signature Keys

- Repository:
  [dickhardt/signature-key](https://github.com/dickhardt/signature-key)
- Commit:
  [`0ff751b571e7fe51336bcc1e526954a202317cc0`](https://github.com/dickhardt/signature-key/commit/0ff751b571e7fe51336bcc1e526954a202317cc0)
- Editor source:
  [`draft-hardt-httpbis-signature-key.md`](https://github.com/dickhardt/signature-key/blob/0ff751b571e7fe51336bcc1e526954a202317cc0/draft-hardt-httpbis-signature-key.md)
- Editor-source SHA-256 at that commit:
  `335c6164569fc5b21aae7930c83c4088e4c02b857f9f3acee8335f16f23d66cb`

The current implementation uses `jwt` for direct, three-party, and four-party
protected requests and `jwks_uri` for the Person Server to Access Server
exchange and the Person Server to Resource revocation request, plus a small set
of supporting key operations. It is not a complete
implementation of every Signature-Key scheme or optional mechanism.

## Companion sources not implemented

The same AAuth commit contains these companion editor sources:

- [Rich Resource Requests (R3)](https://github.com/dickhardt/AAuth/blob/a99d353cf18aee81d0c5445bac070164fb3b8bc5/draft-hardt-aauth-r3.md)
- [AAuth Events](https://github.com/dickhardt/AAuth/blob/a99d353cf18aee81d0c5445bac070164fb3b8bc5/draft-hardt-aauth-events.md)
- [AAuth Bootstrap](https://github.com/dickhardt/AAuth/blob/a99d353cf18aee81d0c5445bac070164fb3b8bc5/draft-hardt-aauth-bootstrap.md)
- [AAuth Budgets](https://github.com/dickhardt/AAuth/blob/a99d353cf18aee81d0c5445bac070164fb3b8bc5/draft-hardt-aauth-budgets.md)

Those companions are not implemented. The
[interoperability demo profile](https://github.com/dickhardt/AAuth/blob/a99d353cf18aee81d0c5445bac070164fb3b8bc5/interop-demo-profile.md)
is also not a conformance target yet.

See [INTERPRETATIONS.md](INTERPRETATIONS.md) for active implementation
choices and [SPEC-FEEDBACK.md](SPEC-FEEDBACK.md) for questions to raise with the
editors.
