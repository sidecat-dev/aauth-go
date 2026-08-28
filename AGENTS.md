# Working on AAuth Go

This repository is a standalone, community-oriented Go implementation of the
AAuth protocol family. These instructions orient human and automated
contributors. They do not confer an official status on the implementation.

## Start in three reads

1. Read `README.md` for the supported product shape and current exclusions.
2. Read `SOURCE-COVERAGE.md` for section-level implementation evidence.
3. Read `INTERPRETATIONS.md` and `SPEC-FEEDBACK.md` before making a new
   protocol judgment or reporting a specification problem.

The current source identities and exact retained-byte hashes are in
`PROVENANCE.md`. Do not infer the implemented protocol version from old tests,
type names, Git history, or a rendered IETF snapshot.

## Source authority

- The pinned author editor sources under `internal/sourcecoverage/sources/`
  are the implementation inputs.
- One refresh pins one exact commit per upstream repository and updates
  `PROVENANCE.md`, the retained files, and the generated coverage manifest
  together.
- Existing behavior remains regression evidence, but it does not count as
  current coverage when the source changed its wire topology or trust model.
- Never turn an unclaimed section into partial or exercised coverage without an
  executable test that demonstrates the current section's observable behavior.

## Architecture boundaries

- The root `aauth` package owns portable protocol values, verification, and
  client-side behavior.
- The `reference` package owns deployable reference role handlers, agent
  clients, and host-supplied storage or policy seams.
- `cmd/aauth-reference` is a runnable composition of those public packages. It
  is an example and qualification target, not a second protocol implementation.
- Deployment policy belongs behind explicit interfaces: clocks, randomness,
  key resolution, egress, replay custody, mission decisions, authorization
  decisions, storage, audit, and protected operations.
- Keep the module independent of any consuming product, private store, command
  surface, or organization-specific policy.
- Preserve exact bytes wherever a digest, signature, replay identity, or
  retained record binds them.

## Current migration boundary

The retained source family uses directed person tokens as the center of its
three- and four-party authorization topology. Older resource-token and
auth-token journeys in this repository do not establish current conformance.
The active walking skeleton must include:

1. mission approval;
2. `aa-person+jwt` issuance and retained lookup by issuer plus JTI;
3. person-token verification by the resource;
4. current resource-token claims;
5. person-server retained-record cross-check and mission-stripping detection;
6. current auth-token issuance and protected presentation;
7. durable replay and restart behavior.

R3, Events, Bootstrap, Budgets, call chaining, sub-agents, and federation are
claimed only section by section as their current-source journeys pass.

## Implementation method

For each behavior:

1. Name the exact source document and section.
2. Add an externally visible failing test first. Prefer a real HTTP and
   cryptographic journey over a helper-only unit test.
3. Implement the smallest complete path through every role that owns trust,
   policy, retention, or consequence.
4. Add typed negative cases for every security-relevant binding.
5. Exercise restart, retry, replay, and lost-response behavior where the
   protocol retains state or permits recovery.
6. Regenerate coverage and inspect the claim; passing tests do not update
   coverage automatically.
7. Record a non-obvious observable choice in `INTERPRETATIONS.md`.
8. Record an evidence-backed question for the authors in `SPEC-FEEDBACK.md`.

Narrow work is welcome; shallow work is not. A token struct without issuance,
verification, retention, refusal, and a real consumer journey is not a complete
protocol increment.

## Specification feedback

- Separate already-submitted feedback from new observations.
- Preserve new/evidence-pending, ready/unsubmitted, submitted/resolved, and
  submitted/still-open state.
- Cite the exact source commit and section plus a reproducible test or wire
  capture.
- Ask one neutral question and explain the interoperability or security effect.
- Link the upstream discussion and record the authors' disposition.
- If later evidence disproves a concern, mark it withdrawn; do not erase it.
- Treat other implementations as community peers and useful interoperability
  evidence. Do not use the journal to rank or disparage them.

## Verification

Run from the repository root:

```sh
go run ./internal/sourcecoverage/cmd/generate
go run ./cmd/aauth-reference verify coverage
go test ./... -count=1
go test -race ./... -count=1
go vet ./...
git diff --check
```

Run focused tests while developing, then run the complete commands before a
publication or release claim. Inspect generated coverage changes rather than
accepting them mechanically.

## Completion and release claims

State the exact source revision, roles, journey, stores, and exclusions. Do not
describe a feature as supported because types compile or one role accepts a
message. A release-quality claim requires deterministic source provenance,
full and race suites, clean-consumer examples, compatibility notes, and
independent interoperability evidence appropriate to the claim.
