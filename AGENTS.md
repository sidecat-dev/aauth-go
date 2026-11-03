# Working on AAuth Go

This repository is a standalone Go implementation of the AAuth specification
family. It does not claim official status.

## Orient

Read these files before changing protocol behavior:

1. `README.md` and `docs/` — what the library offers a user, and how to start.
2. `ARCHITECTURE.md` — package boundaries and dependency direction.
3. `SPECIFICATIONS.md` — exact source documents and revisions.
4. `INTERPRETATIONS.md` — choices not settled by the source text.
5. `SPEC-FEEDBACK.md` — questions already identified for the authors.

Use `CONFORMANCE.md` for what the conformance suite measures, and the guides
under `docs/features/` for each feature's limits.
Treat the source revision named in `SPECIFICATIONS.md` as the protocol input.

## Keep the package graph clear

- The root `aauth` package owns Core protocol values and verification.
- `jose` owns the focused JOSE primitives used by the protocol.
- `signaturekey` owns Signature-Key request proofs, credentials, discovery, and
  error negotiation.
- Agent and server role packages compose Core through small policy, storage,
  key-resolution, clock, and transport interfaces.
- Companion packages may import Core packages. Core packages must not import
  companions.

Preserve exact bytes when a signature, digest, token, or replay identity binds
them. Keep application policy outside protocol parsing and verification.

## Change behavior from a source section

1. Name the source document, revision, and section.
2. Write an externally observable failing test.
3. Implement the smallest complete behavior that makes the test pass.
4. Add negative tests for each security-relevant binding.
5. Record a material interpretation in `INTERPRETATIONS.md`.
6. Record an evidence-backed specification question in `SPEC-FEEDBACK.md`.

Do not describe a section as implemented because its types compile. A claim
needs an executing path through the roles that issue, verify, or consume it.

## Verify

Run focused tests while developing:

```sh
go test ./path/to/package -count=1
```

Before proposing a change, run:

```sh
gofmt -w path/to/changed.go
go test ./... -count=1
go test -race ./... -count=1
go vet ./...
git diff --check
```

Report what passed and what remains unverified.
