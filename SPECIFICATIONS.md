# Specification baseline

This repository implements a bounded part of the current AAuth editor source.
The exact commits below define the text used for implementation and review.
Rendered Internet-Draft publications may be older than these editor revisions.

SHA-256 values below are over the raw editor-source bytes at the named commit.
All seven files match the retained local source mirror used for review.

## Exact source manifest

| Document | Repository commit | Editor source | SHA-256 |
| --- | --- | --- | --- |
| AAuth Core | [AAuth `a99d353`](https://github.com/dickhardt/AAuth/commit/a99d353cf18aee81d0c5445bac070164fb3b8bc5) | [`draft-hardt-oauth-aauth-protocol.md`](https://github.com/dickhardt/AAuth/blob/a99d353cf18aee81d0c5445bac070164fb3b8bc5/draft-hardt-oauth-aauth-protocol.md) | `c984278f21e3931f0cc272d6768b84bcc471f8ab4a1a1922dd92940a91df7e19` |
| Rich Resource Requests (R3) | [AAuth `a99d353`](https://github.com/dickhardt/AAuth/commit/a99d353cf18aee81d0c5445bac070164fb3b8bc5) | [`draft-hardt-aauth-r3.md`](https://github.com/dickhardt/AAuth/blob/a99d353cf18aee81d0c5445bac070164fb3b8bc5/draft-hardt-aauth-r3.md) | `dd768a3b7417c45c0028f2750a50173670fd84c8f432e54ba94799ca93621760` |
| AAuth Events | [AAuth `a99d353`](https://github.com/dickhardt/AAuth/commit/a99d353cf18aee81d0c5445bac070164fb3b8bc5) | [`draft-hardt-aauth-events.md`](https://github.com/dickhardt/AAuth/blob/a99d353cf18aee81d0c5445bac070164fb3b8bc5/draft-hardt-aauth-events.md) | `6ac4f1c649172a359a6ef32380b189a4edcd9855014bbb03fefe096b74802eb0` |
| AAuth Bootstrap | [AAuth `a99d353`](https://github.com/dickhardt/AAuth/commit/a99d353cf18aee81d0c5445bac070164fb3b8bc5) | [`draft-hardt-aauth-bootstrap.md`](https://github.com/dickhardt/AAuth/blob/a99d353cf18aee81d0c5445bac070164fb3b8bc5/draft-hardt-aauth-bootstrap.md) | `ebfe4858e9511020ceb498aea997953b8b79594689ce177ba228230c3ceaf872` |
| AAuth Budgets | [AAuth `a99d353`](https://github.com/dickhardt/AAuth/commit/a99d353cf18aee81d0c5445bac070164fb3b8bc5) | [`draft-hardt-aauth-budgets.md`](https://github.com/dickhardt/AAuth/blob/a99d353cf18aee81d0c5445bac070164fb3b8bc5/draft-hardt-aauth-budgets.md) | `7a27351888d04a4d1059dd9a261243d0960bcc4d918705641b1d9e68c90d4a4d` |
| Interoperability demo profile | [AAuth `a99d353`](https://github.com/dickhardt/AAuth/commit/a99d353cf18aee81d0c5445bac070164fb3b8bc5) | [`interop-demo-profile.md`](https://github.com/dickhardt/AAuth/blob/a99d353cf18aee81d0c5445bac070164fb3b8bc5/interop-demo-profile.md) | `ee503da3ea6803370cffe03171f600d44bf9c81a05872b2014b01a61982fe195` |
| HTTP Signature Keys | [Signature-Key `0ff751b`](https://github.com/dickhardt/signature-key/commit/0ff751b571e7fe51336bcc1e526954a202317cc0) | [`draft-hardt-httpbis-signature-key.md`](https://github.com/dickhardt/signature-key/blob/0ff751b571e7fe51336bcc1e526954a202317cc0/draft-hardt-httpbis-signature-key.md) | `335c6164569fc5b21aae7930c83c4088e4c02b857f9f3acee8335f16f23d66cb` |

[AAuth Explorer at `e6d7913`](https://github.com/aauth-dev/explorer/commit/e6d79137cda1a6a650d4394a37095393e1cc62ba)
is a non-normative diagnostic implementation, not an editor source. It is
tracked by Git commit rather than inserted into the source manifest.

## Verify the protocol map against source bytes

[PROTOCOL.md](PROTOCOL.md) is backed by a machine-readable map of all 612
normalized Markdown headings and 1,200 uppercase normative or field-presence
occurrences in these seven files. Given a directory containing the exact
editor-source files above, verify every digest, line count, heading coordinate,
title, non-overlapping range, exact-line digest, strength, dependency, and the
owner and proof seam supplied by each occurrence's heading with:

```sh
go run ./internal/specmodel/cmd/verify -source-dir /path/to/editor-sources
```

The ordinary Go suite also verifies that each file, commit, and digest remains
bound in one row of this manifest and that the model uses controlled
classification, ownership, state-role, and proof-seam vocabularies.

## Implementation relationship

### AAuth Core

Core has executing direct-identity, session, three-party, four-party,
deferred-delivery, and bounded revocation paths. It is not complete. The
source-area table in [CONFORMANCE.md](CONFORMANCE.md) is the supported-behavior
summary; it names evidence and exclusions for each path rather than inferring
support from exported types.

Core requires fully specified JOSE algorithm identifiers and requires support
for `Ed25519`. This implementation uses `Ed25519`; it does not accept the
polymorphic `EdDSA` identifier as an equivalent spelling.

### HTTP Signature Keys

The current role paths use `jwt` and `jwks_uri` plus a bounded set of shared
message-signature behavior. Other schemes, complete negotiation, and replay
enforcement remain explicit gaps in [CONFORMANCE.md](CONFORMANCE.md).

### Companion specifications and interoperability

R3, Events, Bootstrap, Budgets, and the interoperability profile are pinned as
first-class inputs even where behavior is absent. [CONFORMANCE.md](CONFORMANCE.md)
separates reusable Core primitives from an executing companion-spec path, and
[ARCHITECTURE.md](ARCHITECTURE.md) assigns new behavior without moving
companion semantics into the Core package.

See [INTERPRETATIONS.md](INTERPRETATIONS.md) for active implementation
choices and [SPEC-FEEDBACK.md](SPEC-FEEDBACK.md) for questions to raise with the
editors.
